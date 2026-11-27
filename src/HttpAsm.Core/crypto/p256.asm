; =============================================================================
; crypto/p256.asm - NIST P-256 (SP 800-186 3.2.1.3; TLS's secp256r1): the C ABI's
; httpasm_p256_public_key (d G), httpasm_p256_ecdh (the shared secret TLS 1.3's secp256r1 key
; share and RFC 10024's SecP256r1MLKEM768 need), httpasm_p256_sign and httpasm_p256_verify
; (ECDSA, FIPS 186-5 6.4, as TLS 1.3's ecdsa_secp256r1_sha256 and X.509 certificates use it).
;
; The arithmetic. Field elements in Montgomery form, four 64-bit limbs, fully reduced
; (include/crypto/p256.inc, in two versions: v3 with mulx and adcx/adox, v1 with mul; one is
; chosen per call). Points in Jacobian coordinates (X, Y, Z), x = X / Z^2, y = Y / Z^3, the
; point at infinity as Z = 0 (exactly 0: the identity is written as all zeros, and every
; operation on zeros gives zeros):
;   - doubling: OpenSSL's arrangement for a = -3 (4M + 4S, ten small operations, one halving),
;     level with dbl-2001-b's 3M + 5S at v3 and 7% faster at v1 (measured, below);
;   - addition: add-2007-bl (11M + 5S) with Jacobian inputs, mixed addition madd-2007-bl (7M +
;     4S) with an affine one; both select the result by mask when either input is infinity
;     (no branch), and neither handles equal inputs (doubling): the scalar multiplications below
;     never meet them, and verification, whose inputs are public, checks for them after.
;
; The scalar multiplications, constant time (every digit read by mask over all the table, no
; branch or address on the scalar):
;   - variable base (ECDH, verification's u2 Q): Booth's signed digits of 5 bits (OpenSSL's
;     ecp_nistz256 recoding: digit i from bits 5i - 1 .. 5i + 4, magnitudes 0..16, the sign
;     applied by negating y), 52 windows from the top: a table of 1P..16P in Jacobian
;     coordinates (even multiples by doubling, odd ones by adding P), then 5 doublings and one
;     addition a window;
;   - fixed base (public keys, signatures, verification's u1 G): the same recoding with 7 bits,
;     37 windows, each with its own table of m 2^(7i) G (m = 1..64, affine: 151.5 KB, generated
;     and proven by specs/p256.cs), one mixed addition a window and no doubling.
; No addition meets the doubling case for a scalar k in [1, n - 1] (proof in docs/DESIGN.md's
; P-256 entry: a window's addend is +-d 2^(w i) and what came before is below 2^(w i - 1) in
; magnitude, so they could only meet modulo n in the top window, where both differences work
; out to k or to a value the digits rule out); the generator's model checked it on the edge
; scalars too. The accumulator is infinity exactly until the first nonzero digit.
;
; The inversion (to affine, and ECDSA's k^-1 and s^-1): Bernstein and Yang's divsteps in
; libsecp256k1's arrangement (ha_modinv256, crypto/inverse.asm: written here first, now shared
; with Curve25519's field), constant time, one routine for p and n: 2.16 us against Fermat's
; 4.1 us (a chain of 255 squarings, each waiting for the last).
;
; ECDSA. Signing draws k from RFC 6979's HMAC-DRBG (HMAC-SHA256 always: RFC 6979's own k
; whenever the digest is SHA-256's), with the caller's entropy as RFC 6979 3.6's extra input when
; given (hedged signatures: a fault or a weak generator alone no longer leaks the key), and
; draws again, as RFC 6979 says, in the cases no one will meet (k >= n, r = 0, s = 0).
; Verification (every input public, so variable time) takes u1 G + u2 Q in one pass from the top
; (Straus): wNAF digits, u1's by 7 bits over G's odd multiples (the fixed-base table's window 0
; holds 1G..64G), u2's by 5 bits over 1Q, 3Q, ..15Q (built per call), the doublings shared (about
; 247 doublings, 42 additions and 28 mixed additions a verification, against 258 + 57 + 37 for
; the two constant-time multiplications); its additions branch on infinity and on equal and
; opposite points, which a crafted key or signature can bring about. Then x(R) is compared with
; r without leaving Jacobian coordinates: X = r Z^2, or X = (r + n) Z^2 when r + n < p.
;
; Validation: a public key must be 65 octets of SEC 1's uncompressed form (04, x, y), x and y
; below p, on the curve (RFC 9846 4.2.8.2 requires the check of a peer's key share; it also
; rules out the invalid-curve attack); a private key must be in [1, n - 1]; r and s too.
;
; Measured (2026-11-27, i9-13900K P-core, WSL; against OpenSSL 3.0.13's EVP, which runs its
; ecp_nistz256 assembly): see benchmarks/README.md.
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "crypto/p256.inc"

extern httpasm_hmac_sha256                  ; crypto/hmac.asm: RFC 6979's HMAC (one-shot)

section .rodata
%include "generated/p256_table.inc"

section .text

; -----------------------------------------------------------------------------
; The frame every routine of a call shares, addressed off rbp (the field macros take every
; register but rbp and rsp). 64-aligned: the table scans move 32-octet rows. Everything below
; PF_END is wiped before a function returns (keys, nonces, every intermediate point).
; -----------------------------------------------------------------------------
PF_AX       equ 0                           ; the accumulator, Jacobian (X, Y, Z)
PF_AY       equ 32
PF_AZ       equ 64
PF_IX       equ 96                          ; the addend: Jacobian, or affine with IZ = 1
PF_IY       equ 128
PF_IZ       equ 160
PF_RX       equ 192                         ; an addition's result before the selection
PF_RY       equ 224
PF_RZ       equ 256
PF_T0       equ 288                         ; twelve temporaries
PF_T1       equ 320
PF_T2       equ 352
PF_T3       equ 384                         ; (the addition leaves H here)
PF_T4       equ 416
PF_T5       equ 448                         ; (and r here)
PF_T6       equ 480
PF_T7       equ 512
PF_T8       equ 544
PF_T9       equ 576
PF_T10      equ 608
PF_T11      equ 640
PF_TAB      equ 672                         ; the variable base's table: 16 points of 96 octets
PF_PX       equ 2208                        ; an input point (affine, Montgomery), later the
PF_PY       equ 2240                        ; output's coordinates (affine, plain)
PF_ZI       equ 2272                        ; the value being inverted
PF_K2       equ 2304                        ; the scalar shifted up one bit: five qwords
PF_K        equ 2344                        ; the scalar: four qwords
PF_WIN      equ 2376                        ; the window number
PF_SIGN     equ 2392                        ; the digit's sign as a mask
PF_OUT      equ 2400                        ; the output's address
PF_ARG      equ 2408                        ; inputs' addresses and lengths
PF_RES      equ 2416                        ; the result to return
PF_ARG2     equ 2424
PF_ARG3     equ 2432
PF_ARG4     equ 2440
PF_SEEDN    equ 2448                        ; RFC 6979's seeding length: 97, or 129 with entropy
PF_LEN1     equ 2456                        ; verification: u1's wNAF digits (how many)
PF_E        equ 2464                        ; ECDSA's scalars, plain limbs: e = digest mod n
PF_D        equ 2496                        ; the private key
PF_R        equ 2528                        ; r
PF_S        equ 2560                        ; s (verification: then w = s^-1)
PF_KINV     equ 2592                        ; k^-1
PF_U1       equ 2624                        ; u1 = e w, u2 = r w
PF_U2       equ 2656
PF_KEY      equ 2688                        ; RFC 6979's K
PF_SEED     equ 2720                        ; V || separator || x || h1 || entropy (129 of 136)
PF_LEN2     equ 2856                        ; verification: u2's wNAF digits (how many)
PF_DIG1     equ 2864                        ; u1's wNAF digits, signed octets (260)
PF_DIG2     equ 3124                        ; u2's (260)
PF_END      equ 3384                        ; (wiped up to here)
PF_OLDSP    equ 3384                        ; the caller's rsp (after the six pushes)
PF_FRAME    equ 3392                        ; a multiple of 64

%define S_AX rbp + PF_AX
%define S_AY rbp + PF_AY
%define S_AZ rbp + PF_AZ
%define S_IX rbp + PF_IX
%define S_IY rbp + PF_IY
%define S_IZ rbp + PF_IZ
%define S_RX rbp + PF_RX
%define S_RY rbp + PF_RY
%define S_RZ rbp + PF_RZ
%define S_T0 rbp + PF_T0
%define S_T1 rbp + PF_T1
%define S_T2 rbp + PF_T2
%define S_T3 rbp + PF_T3
%define S_T4 rbp + PF_T4
%define S_T5 rbp + PF_T5
%define S_T6 rbp + PF_T6
%define S_T7 rbp + PF_T7
%define S_T8 rbp + PF_T8
%define S_T9 rbp + PF_T9
%define S_T10 rbp + PF_T10
%define S_PX rbp + PF_PX
%define S_PY rbp + PF_PY
%define S_ZI rbp + PF_ZI

; P256_COPY dst, src, qwords: memory to memory through rax (no flags).
%macro P256_COPY 3
  %assign c_q 0
  %rep %3
    mov         rax, [%2 + c_q]
    mov         [%1 + c_q], rax
    %assign c_q c_q + 8
  %endrep
%endmacro

; P256_ENTER / P256_LEAVE: the six kept registers pushed, the 64-aligned frame at rbp (the
; caller's rsp kept above PF_END, so the wipe leaves it); keeps rdi, rsi, rdx, rcx, r8, r9.
%macro P256_ENTER 0
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    and         rsp, -64
    sub         rsp, PF_FRAME
    mov         rbp, rsp
    mov         [rbp + PF_OLDSP], rax
%endmacro
%macro P256_LEAVE 0
    mov         rsp, [rbp + PF_OLDSP]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
%endmacro

; P256_FINISH: the return: eax = PF_RES's low dword after the frame below PF_END is wiped (it
; held the key or the nonce, the table, every intermediate point), then P256_LEAVE and ret.
%macro P256_FINISH 0
    mov         r8, [rbp + PF_RES]
    xor         eax, eax
    mov         ecx, PF_END / 8
    mov         rdi, rbp
    rep         stosq
    mov         eax, r8d
    P256_LEAVE
    ret
%endmacro

; P256_IS_ZERO reg, slot: reg = all ones when the slot's four qwords are 0, else 0 (no branch).
%macro P256_IS_ZERO 2
    mov         %1, [%2]
    or          %1, [%2 + 8]
    or          %1, [%2 + 16]
    or          %1, [%2 + 24]
    neg         %1                          ; CF = nonzero
    sbb         %1, %1
    not         %1
%endmacro

; P256_DIFFER a, b: ZF clear when the four qwords at a and b differ (an OR of their XORs; for
; public values only: the caller branches on it). Clobbers rax, rcx.
%macro P256_DIFFER 2
    mov         rax, [%1]
    xor         rax, [%2]
    mov         rcx, [%1 + 8]
    xor         rcx, [%2 + 8]
    or          rax, rcx
    mov         rcx, [%1 + 16]
    xor         rcx, [%2 + 16]
    or          rax, rcx
    mov         rcx, [%1 + 24]
    xor         rcx, [%2 + 24]
    or          rax, rcx
%endmacro

; P256_DIGIT w: ecx = window number i (public) -> edx = the magnitude of the window's Booth digit
; (0..2^(w - 1)), r12 = its sign as a mask (all ones when negative). The window is bits
; w i - 1 .. w i + w - 1 of the scalar, read as bits w i .. w i + w of PF_K2 (the scalar shifted up
; one bit: bit -1 is 0); the qword and the shift follow i alone. Booth (OpenSSL's
; booth_recode_w5/w7): s = -(v >> w); d = s ? 2^(w + 1) - 1 - v : v; magnitude (d >> 1) + (d & 1),
; negative when s. Clobbers rax, rcx, the flags.
%macro P256_DIGIT 1
    imul        eax, ecx, %1                ; w i
    mov         ecx, eax
    shr         eax, 6                      ; its qword
    and         ecx, 63                     ; its shift
    mov         rdx, [rbp + PF_K2 + rax * 8]
    mov         rax, [rbp + PF_K2 + rax * 8 + 8]
    shrd        rdx, rax, cl
    and         edx, (2 << %1) - 1          ; the window's w + 1 bits, v
    mov         eax, edx
    shr         eax, %1
    neg         rax                         ; s: 0 or all ones
    mov         r12, rax
    mov         ecx, (2 << %1) - 1
    sub         ecx, edx
    xor         ecx, edx
    and         ecx, eax
    xor         edx, ecx                    ; d
    mov         eax, edx
    shr         edx, 1
    and         eax, 1
    add         edx, eax
%endmacro

; P256_SELECT_RESULT inf_acc, inf_in: ACC = inf_in ? ACC : (inf_acc ? IN : R) over the twelve
; qwords, the masks in registers (all ones = that input is infinity). No branch.
%macro P256_SELECT_RESULT 2
  %assign s_q 0
  %rep 12
    mov         rax, [rbp + PF_RX + s_q]
    mov         rcx, [rbp + PF_IX + s_q]
    xor         rcx, rax
    and         rcx, %1
    xor         rax, rcx
    mov         rcx, [rbp + PF_AX + s_q]
    xor         rcx, rax
    and         rcx, %2
    xor         rax, rcx
    mov         [rbp + PF_AX + s_q], rax
    %assign s_q s_q + 8
  %endrep
%endmacro

; P256_ON_CURVE F: the input point (PX, PY, plain limbs below p) into Montgomery form, then
; jumps to the caller's .invalid unless y^2 = x^3 - 3x + b. A public key's check: the branch is
; on public data.
%macro P256_ON_CURVE 1
    %1_MUL      S_PX, S_PX, rel p256_r2
    %1_MUL      S_PY, S_PY, rel p256_r2
    %1_SQR      S_T0, S_PX
    %1_MUL      S_T0, S_T0, S_PX            ; x^3
    %1_ADD      S_T1, S_PX, S_PX
    %1_ADD      S_T1, S_T1, S_PX            ; 3x
    %1_SUB      S_T0, S_T0, S_T1
    %1_ADD      S_T0, S_T0, rel p256_b      ; x^3 - 3x + b
    %1_SQR      S_T1, S_PY                  ; y^2
    P256_DIFFER S_T0, S_T1
    jnz         .invalid
%endmacro

; -----------------------------------------------------------------------------
; The point formulas over field version F (frame slots in, frame slots out).
; -----------------------------------------------------------------------------

; P256_DBL F: ACC = 2 ACC, OpenSSL's ecp_nistz256_point_double arrangement for a = -3: with
; S = (2Y)^2 = 4Y^2, 4 beta = 4 X Y^2 is S X, 8 Y^4 is S^2 / 2, Z3 = 2Y Z. 4M + 4S and ten small
; operations; measured against dbl-2001-b (3M + 5S, sixteen small ones): 360 against 364 cycles
; at v3 (level), 364 against 391 at v1. Infinity (zeros) stays zeros. Every input slot is read
; before it is written.
%macro P256_DBL 1
    %1_ADD      S_T0, S_AY, S_AY            ; 2Y
    %1_SQR      S_T1, S_AZ                  ; delta = Z^2
    %1_SQR      S_T2, S_T0                  ; S = 4Y^2
    %1_MUL      S_AZ, S_T0, S_AZ            ; Z3 = 2Y Z
    %1_SUB      S_T4, S_AX, S_T1            ; X - delta
    %1_ADD      S_T5, S_AX, S_T1            ; X + delta
    %1_SQR      S_T6, S_T2                  ; 16 Y^4
    %1_MUL      S_T2, S_T2, S_AX            ; 4 beta = 4 X Y^2
    %1_MUL      S_T4, S_T4, S_T5            ; (X - delta)(X + delta)
    %1_HALF     S_T6, S_T6                  ; 8 Y^4
    %1_ADD      S_T5, S_T4, S_T4
    %1_ADD      S_T4, S_T5, S_T4            ; alpha = 3 (X - delta)(X + delta)
    %1_ADD      S_T5, S_T2, S_T2            ; 8 beta
    %1_SQR      S_T7, S_T4                  ; alpha^2
    %1_SUB      S_AX, S_T7, S_T5            ; X3 = alpha^2 - 8 beta
    %1_SUB      S_T2, S_T2, S_AX            ; 4 beta - X3
    %1_MUL      S_T2, S_T2, S_T4            ; alpha (4 beta - X3)
    %1_SUB      S_AY, S_T2, S_T6            ; Y3 = alpha (4 beta - X3) - 8 Y^4
%endmacro

; P256_ADD F: R = ACC + IN, both Jacobian, add-2007-bl (11M + 5S), independent operations side
; by side. Leaves H = U2 - U1 in T3 and r = 2 (S2 - S1) in T5: the doubling case is H = r = 0,
; the cancelling case H = 0 with r not 0 (p256_vadd looks). Wrong for either case and for an
; input at infinity: the caller's selection replaces the latter.
%macro P256_ADD 1
    %1_SQR      S_T0, S_AZ                  ; Z1Z1 = Z1^2
    %1_SQR      S_T1, S_IZ                  ; Z2Z2 = Z2^2
    %1_MUL      S_T2, S_AX, S_T1            ; U1 = X1 Z2Z2
    %1_MUL      S_T3, S_IX, S_T0            ; U2 = X2 Z1Z1
    %1_MUL      S_T4, S_IZ, S_T1            ; Z2^3
    %1_MUL      S_T5, S_AZ, S_T0            ; Z1^3
    %1_ADD      S_T8, S_AZ, S_IZ            ; Z1 + Z2
    %1_MUL      S_T4, S_AY, S_T4            ; S1 = Y1 Z2^3
    %1_MUL      S_T5, S_IY, S_T5            ; S2 = Y2 Z1^3
    %1_SUB      S_T3, S_T3, S_T2            ; H = U2 - U1
    %1_SQR      S_T8, S_T8                  ; (Z1 + Z2)^2
    %1_SUB      S_T5, S_T5, S_T4            ; S2 - S1
    %1_ADD      S_T6, S_T3, S_T3            ; 2H
    %1_ADD      S_T5, S_T5, S_T5            ; r = 2 (S2 - S1)
    %1_SQR      S_T6, S_T6                  ; I = (2H)^2
    %1_SUB      S_T8, S_T8, S_T0            ; (Z1 + Z2)^2 - Z1Z1
    %1_SQR      S_T9, S_T5                  ; r^2
    %1_MUL      S_T7, S_T3, S_T6            ; J = H I
    %1_MUL      S_T2, S_T2, S_T6            ; V = U1 I
    %1_SUB      S_T8, S_T8, S_T1            ; (Z1 + Z2)^2 - Z1Z1 - Z2Z2
    %1_MUL      S_RZ, S_T8, S_T3            ; Z3 = that H
    %1_SUB      S_T9, S_T9, S_T7            ; r^2 - J
    %1_ADD      S_T10, S_T2, S_T2           ; 2V
    %1_MUL      S_T4, S_T4, S_T7            ; S1 J
    %1_SUB      S_RX, S_T9, S_T10           ; X3 = r^2 - J - 2V
    %1_SUB      S_T2, S_T2, S_RX            ; V - X3
    %1_ADD      S_T4, S_T4, S_T4            ; 2 S1 J
    %1_MUL      S_T2, S_T5, S_T2            ; r (V - X3)
    %1_SUB      S_RY, S_T2, S_T4            ; Y3 = r (V - X3) - 2 S1 J
%endmacro

; P256_MADD F: R = ACC + IN with IN affine (IX, IY), madd-2007-bl (7M + 4S). The same cases as
; P256_ADD are the caller's.
%macro P256_MADD 1
    %1_SQR      S_T0, S_AZ                  ; Z1Z1 = Z1^2
    %1_MUL      S_T1, S_IX, S_T0            ; U2 = X2 Z1Z1
    %1_MUL      S_T2, S_AZ, S_T0            ; Z1^3
    %1_SUB      S_T1, S_T1, S_AX            ; H = U2 - X1
    %1_MUL      S_T2, S_IY, S_T2            ; S2 = Y2 Z1^3
    %1_SQR      S_T3, S_T1                  ; HH = H^2
    %1_ADD      S_T7, S_AZ, S_T1            ; Z1 + H
    %1_SUB      S_T2, S_T2, S_AY            ; S2 - Y1
    %1_ADD      S_T4, S_T3, S_T3            ; 2 HH
    %1_SQR      S_T7, S_T7                  ; (Z1 + H)^2
    %1_ADD      S_T2, S_T2, S_T2            ; r = 2 (S2 - Y1)
    %1_ADD      S_T4, S_T4, S_T4            ; I = 4 HH
    %1_MUL      S_T5, S_T1, S_T4            ; J = H I
    %1_MUL      S_T6, S_AX, S_T4            ; V = X1 I
    %1_SQR      S_T8, S_T2                  ; r^2
    %1_SUB      S_T7, S_T7, S_T0            ; (Z1 + H)^2 - Z1Z1
    %1_MUL      S_T9, S_AY, S_T5            ; Y1 J
    %1_SUB      S_T8, S_T8, S_T5            ; r^2 - J
    %1_ADD      S_T10, S_T6, S_T6           ; 2V
    %1_SUB      S_RZ, S_T7, S_T3            ; Z3 = (Z1 + H)^2 - Z1Z1 - HH
    %1_SUB      S_RX, S_T8, S_T10           ; X3 = r^2 - J - 2V
    %1_ADD      S_T9, S_T9, S_T9            ; 2 Y1 J
    %1_SUB      S_T6, S_T6, S_RX            ; V - X3
    %1_MUL      S_T6, S_T2, S_T6            ; r (V - X3)
    %1_SUB      S_RY, S_T6, S_T9            ; Y3 = r (V - X3) - 2 Y1 J
%endmacro

; -----------------------------------------------------------------------------
; The table scans: edx = a digit's magnitude. Every entry is read and masked by (its number =
; the digit): no address depends on the digit; digit 0 matches none and gives zeros (infinity).
;   P256_SCAN_TAB_v3 / _v1: TAB (16 Jacobian points, 96 octets each) into IN.
;   P256_SCAN_BASE_v3 / _v1: the fixed-base window at rsi (2^(P256_W - 1) affine points, 64
;     octets each) into IX, IY.
; v3 with AVX2 (and vzeroupper after: the field code and the C ABI's callees run legacy SSE);
; v1 with SSE2. Clobber rax, rcx, rsi, xmm0-xmm10 (ymm at v3), the flags.
; -----------------------------------------------------------------------------
%macro P256_SCAN_TAB_v3 0
    vmovd       xmm0, edx
    vpbroadcastd ymm0, xmm0
    vpcmpeqd    ymm5, ymm5, ymm5
    vpsrld      ymm5, ymm5, 31              ; 1 in every dword: the step
    vmovdqa     ymm4, ymm5                  ; the entry number, from 1
    vpxor       xmm1, xmm1, xmm1
    vpxor       xmm2, xmm2, xmm2
    vpxor       xmm3, xmm3, xmm3
    lea         rax, [rbp + PF_TAB]
    mov         ecx, 16
%%scan:
    vpcmpeqd    ymm6, ymm4, ymm0
    vpaddd      ymm4, ymm4, ymm5
    vpand       ymm7, ymm6, [rax]
    vpor        ymm1, ymm1, ymm7
    vpand       ymm7, ymm6, [rax + 32]
    vpor        ymm2, ymm2, ymm7
    vpand       ymm7, ymm6, [rax + 64]
    vpor        ymm3, ymm3, ymm7
    add         rax, 96
    dec         ecx
    jnz         %%scan
    vmovdqa     [rbp + PF_IX], ymm1
    vmovdqa     [rbp + PF_IY], ymm2
    vmovdqa     [rbp + PF_IZ], ymm3
    vzeroupper
%endmacro

%macro P256_SCAN_TAB_v1 0
    movd        xmm0, edx
    pshufd      xmm0, xmm0, 0
    pcmpeqd     xmm7, xmm7
    psrld       xmm7, 31
    movdqa      xmm8, xmm7
    pxor        xmm1, xmm1
    pxor        xmm2, xmm2
    pxor        xmm3, xmm3
    pxor        xmm4, xmm4
    pxor        xmm5, xmm5
    pxor        xmm6, xmm6
    lea         rax, [rbp + PF_TAB]
    mov         ecx, 16
%%scan:
    movdqa      xmm9, xmm8
    pcmpeqd     xmm9, xmm0
    paddd       xmm8, xmm7
    movdqa      xmm10, [rax]
    pand        xmm10, xmm9
    por         xmm1, xmm10
    movdqa      xmm10, [rax + 16]
    pand        xmm10, xmm9
    por         xmm2, xmm10
    movdqa      xmm10, [rax + 32]
    pand        xmm10, xmm9
    por         xmm3, xmm10
    movdqa      xmm10, [rax + 48]
    pand        xmm10, xmm9
    por         xmm4, xmm10
    movdqa      xmm10, [rax + 64]
    pand        xmm10, xmm9
    por         xmm5, xmm10
    movdqa      xmm10, [rax + 80]
    pand        xmm10, xmm9
    por         xmm6, xmm10
    add         rax, 96
    dec         ecx
    jnz         %%scan
    movdqa      [rbp + PF_IX], xmm1
    movdqa      [rbp + PF_IX + 16], xmm2
    movdqa      [rbp + PF_IX + 32], xmm3
    movdqa      [rbp + PF_IX + 48], xmm4
    movdqa      [rbp + PF_IX + 64], xmm5
    movdqa      [rbp + PF_IX + 80], xmm6
%endmacro

%macro P256_SCAN_BASE_v3 0
    vmovd       xmm0, edx
    vpbroadcastd ymm0, xmm0
    vpcmpeqd    ymm5, ymm5, ymm5
    vpsrld      ymm5, ymm5, 31
    vmovdqa     ymm4, ymm5
    vpxor       xmm1, xmm1, xmm1
    vpxor       xmm2, xmm2, xmm2
    mov         ecx, 1 << (P256_W - 1)
%%scan:
    vpcmpeqd    ymm6, ymm4, ymm0
    vpaddd      ymm4, ymm4, ymm5
    vpand       ymm7, ymm6, [rsi]
    vpor        ymm1, ymm1, ymm7
    vpand       ymm7, ymm6, [rsi + 32]
    vpor        ymm2, ymm2, ymm7
    add         rsi, 64
    dec         ecx
    jnz         %%scan
    vmovdqa     [rbp + PF_IX], ymm1
    vmovdqa     [rbp + PF_IY], ymm2
    vzeroupper
%endmacro

%macro P256_SCAN_BASE_v1 0
    movd        xmm0, edx
    pshufd      xmm0, xmm0, 0
    pcmpeqd     xmm7, xmm7
    psrld       xmm7, 31
    movdqa      xmm8, xmm7
    pxor        xmm1, xmm1
    pxor        xmm2, xmm2
    pxor        xmm3, xmm3
    pxor        xmm4, xmm4
    mov         ecx, 1 << (P256_W - 1)
%%scan:
    movdqa      xmm9, xmm8
    pcmpeqd     xmm9, xmm0
    paddd       xmm8, xmm7
    movdqa      xmm10, [rsi]
    pand        xmm10, xmm9
    por         xmm1, xmm10
    movdqa      xmm10, [rsi + 16]
    pand        xmm10, xmm9
    por         xmm2, xmm10
    movdqa      xmm10, [rsi + 32]
    pand        xmm10, xmm9
    por         xmm3, xmm10
    movdqa      xmm10, [rsi + 48]
    pand        xmm10, xmm9
    por         xmm4, xmm10
    add         rsi, 64
    dec         ecx
    jnz         %%scan
    movdqa      [rbp + PF_IX], xmm1
    movdqa      [rbp + PF_IX + 16], xmm2
    movdqa      [rbp + PF_IY], xmm3
    movdqa      [rbp + PF_IY + 16], xmm4
%endmacro

; =============================================================================
; The inversion (Z to affine, and ECDSA's k^-1 and s^-1) is ha_modinv256 in crypto/inverse.asm,
; shared with Curve25519's field: rdi = four qwords x, replaced by x^-1 mod M; rsi = the
; modulus' record (p256_mod_p or p256_mod_n, generated with the tables by specs/p256.cs).
; =============================================================================
extern ha_modinv256

; =============================================================================
; Shared helpers (no field products): they work in the caller's frame (rbp) and keep rbp.
; =============================================================================

; -----------------------------------------------------------------------------
; p256_load_scalar: rsi = 32 big-endian octets -> PF_K (limbs) and PF_K2 (shifted up a bit).
; eax = 0 when 1 <= k < n, else -1 (both computed without a branch; the caller's branch on the
; answer shows only whether a key or a candidate nonce was in range). Clobbers rax, rcx, rdx,
; r8-r11, the flags.
; -----------------------------------------------------------------------------
align 16
p256_load_scalar:
    mov         r8, [rsi + 24]
    bswap       r8
    mov         r9, [rsi + 16]
    bswap       r9
    mov         r10, [rsi + 8]
    bswap       r10
    mov         r11, [rsi]
    bswap       r11
    mov         [rbp + PF_K], r8
    mov         [rbp + PF_K + 8], r9
    mov         [rbp + PF_K + 16], r10
    mov         [rbp + PF_K + 24], r11
    mov         rax, r8
    sub         rax, [rel p256_n]
    mov         rax, r9
    sbb         rax, [rel p256_n + 8]
    mov         rax, r10
    sbb         rax, [rel p256_n + 16]
    mov         rax, r11
    sbb         rax, [rel p256_n + 24]
    sbb         ecx, ecx                    ; all ones when k < n
    mov         rax, r8
    or          rax, r9
    or          rax, r10
    or          rax, r11
    neg         rax
    sbb         edx, edx                    ; all ones when k != 0
    and         ecx, edx
    call        p256_set_k2
    mov         eax, ecx
    not         eax
    ret

; -----------------------------------------------------------------------------
; p256_set_k2: PF_K2 = the scalar in r8..r11 shifted up one bit (five qwords): what P256_DIGIT
; reads, Booth's bit -1 a zero below it. Keeps rcx; clobbers rax, r8-r11, the flags.
; -----------------------------------------------------------------------------
align 16
p256_set_k2:
    mov         rax, r11
    shr         rax, 63
    mov         [rbp + PF_K2 + 32], rax
    shld        r11, r10, 1
    mov         [rbp + PF_K2 + 24], r11
    shld        r10, r9, 1
    mov         [rbp + PF_K2 + 16], r10
    shld        r9, r8, 1
    mov         [rbp + PF_K2 + 8], r9
    shl         r8, 1
    mov         [rbp + PF_K2], r8
    ret

; -----------------------------------------------------------------------------
; p256_wnaf: rsi = a scalar's four limbs (public), rdi = 260 octets, ecx = w (5 or 7) -> the
; scalar's width-w NAF, least significant digit first, as signed octets: every digit 0 or odd with
; |d| < 2^(w - 1), at most one nonzero among any w in a row, zeros past the last; rax = how many
; (the last one nonzero; 0 for a zero scalar; at most 257, as k - d can pass 2^256). The classic
; recoding (an odd k gives d = k mods 2^w and k -= d, leaving a multiple of 2^w), with each run of
; zero digits passed at once (bsf, or a whole zero limb). Variable time: for verification's public
; scalars only. Clobbers rax, rbx, rcx, rdx, rsi, r8-r15, the flags.
; -----------------------------------------------------------------------------
align 16
p256_wnaf:
    push        rdi
    push        rcx
    xor         eax, eax
    mov         ecx, 260
    rep         stosb
    pop         rcx
    pop         rdi
    mov         r8, [rsi]
    mov         r9, [rsi + 8]
    mov         r10, [rsi + 16]
    mov         r11, [rsi + 24]
    xor         r12d, r12d                  ; a fifth limb: k - d passes 2^256 for d < 0
    mov         r13d, 1
    shl         r13, cl                     ; 2^w
    lea         r14, [r13 - 1]              ; 2^w - 1
    mov         r15, r13
    shr         r15, 1                      ; 2^(w - 1)
    xor         ebx, ebx                    ; the position k's bit 0 stands for
    xor         esi, esi                    ; the count: the last digit's position + 1
.next:
    mov         rax, r8
    or          rax, r9
    or          rax, r10
    or          rax, r11
    or          rax, r12
    jz          .done
    test        r8, r8
    jnz         .zeros
    mov         r8, r9                      ; a zero limb: 64 zero digits at once
    mov         r9, r10
    mov         r10, r11
    mov         r11, r12
    xor         r12d, r12d
    add         ebx, 64
    jmp         .next
.zeros:
    bsf         rcx, r8                     ; the run of zero digits below the next odd bit
    shrd        r8, r9, cl                  ; (bsf, not tzcnt: v1 runs this too)
    shrd        r9, r10, cl
    shrd        r10, r11, cl
    shrd        r11, r12, cl
    shr         r12, cl
    add         ebx, ecx
    mov         rax, r8
    and         rax, r14                    ; k mod 2^w (k is odd now)
    cmp         rax, r15
    jb          .digit
    sub         rax, r13                    ; 2^(w - 1) or more: the negative digit
.digit:
    mov         [rdi + rbx], al
    lea         esi, [rbx + 1]
    cqo                                     ; d's sign for the higher limbs
    sub         r8, rax
    sbb         r9, rdx
    sbb         r10, rdx
    sbb         r11, rdx
    sbb         r12, rdx                    ; k -= d: a multiple of 2^w now
    jmp         .next
.done:
    mov         eax, esi
    ret

; -----------------------------------------------------------------------------
; p256_load_point: rsi = 65 octets, SEC 1's uncompressed form 04 || x || y -> PX, PY (plain
; limbs). eax = 0 when the form is uncompressed and x, y are below p, else -1 (the curve
; equation is the caller's: P256_ON_CURVE). Clobbers rax, rsi, rdi, r8-r11, the flags.
; -----------------------------------------------------------------------------
align 16
p256_load_point:
    cmp         byte [rsi], 4
    jne         .bad
    lea         rdi, [rbp + PF_PX]
    inc         rsi
    call        p256_load_be_p
    jc          .bad
    lea         rdi, [rbp + PF_PY]
    call        p256_load_be_p
    jc          .bad
    xor         eax, eax
    ret
.bad:
    mov         eax, -1
    ret

; -----------------------------------------------------------------------------
; p256_load_be_p: 32 big-endian octets at rsi -> limbs at rdi; rsi += 32. CF set when the value is
; p or more (the subtraction of p does not borrow). Clobbers rax, r8-r11, the flags.
; -----------------------------------------------------------------------------
align 16
p256_load_be_p:
    mov         r8, [rsi + 24]
    bswap       r8
    mov         r9, [rsi + 16]
    bswap       r9
    mov         r10, [rsi + 8]
    bswap       r10
    mov         r11, [rsi]
    bswap       r11
    add         rsi, 32
    mov         [rdi], r8
    mov         [rdi + 8], r9
    mov         [rdi + 16], r10
    mov         [rdi + 24], r11
    sub         r8, -1
    mov         rax, FP_P1
    sbb         r9, rax
    sbb         r10, 0
    mov         rax, FP_P3
    sbb         r11, rax
    cmc
    ret

; -----------------------------------------------------------------------------
; p256_store_be: the limbs at rsi -> 32 big-endian octets at rdi. Clobbers rax.
; -----------------------------------------------------------------------------
align 16
p256_store_be:
    mov         rax, [rsi]
    bswap       rax
    mov         [rdi + 24], rax
    mov         rax, [rsi + 8]
    bswap       rax
    mov         [rdi + 16], rax
    mov         rax, [rsi + 16]
    bswap       rax
    mov         [rdi + 8], rax
    mov         rax, [rsi + 24]
    bswap       rax
    mov         [rdi], rax
    ret

; -----------------------------------------------------------------------------
; p256_load_digest: rsi = a digest, rdx = its length (public) -> PF_E = bits2int(digest) mod n
; (RFC 6979 2.3.2, FIPS 186-5 6.4.1: its leftmost 256 bits, or all of a shorter one, as a
; big-endian integer; then one subtraction of n, as e < 2^256 < 2n). Uses PF_T0. Clobbers rax,
; rbx, rcx, rdx, rsi, rdi, r8-r12, the flags.
; -----------------------------------------------------------------------------
align 16
p256_load_digest:
    xor         eax, eax
    mov         [rbp + PF_T0], rax
    mov         [rbp + PF_T0 + 8], rax
    mov         [rbp + PF_T0 + 16], rax
    mov         [rbp + PF_T0 + 24], rax
    mov         rcx, rdx
    cmp         rcx, 32
    jb          .short
    mov         ecx, 32
    lea         rdi, [rbp + PF_T0]
    jmp         .copy
.short:
    lea         rdi, [rbp + PF_T0 + 32]     ; right-aligned: zeros before it
    sub         rdi, rcx
.copy:
    rep         movsb
    lea         rsi, [rbp + PF_T0]
    lea         rdi, [rbp + PF_E]
    call        p256_load_be_p              ; (its CF, the comparison with p, is not wanted)
    FN_REDUCE   rbp + PF_E
    ret

; -----------------------------------------------------------------------------
; RFC 6979 3.2's HMAC_DRBG, HMAC-SHA256 always (RFC 6979's exactly when the digest is SHA-256's;
; any other digest still gets a sound deterministic nonce), over PF_KEY (K) and PF_SEED: V at
; +0, then the separator octet, x (the key's octets), h1 = bits2octets(digest) and the entropy.
; The calls into the C ABI need rsp 16-aligned: so p256_drbg_hmac is called only from the three
; routines below, and they only from a function's frame body (rsp = rbp, 64-aligned).
; -----------------------------------------------------------------------------

; p256_drbg_hmac: rcx = octets of PF_SEED, r8 = where the MAC goes: HMAC(K, SEED[0..rcx]).
; (httpasm_hmac_sha256 reads its key and data before it writes the MAC: K and V update in place.)
align 16
p256_drbg_hmac:
    lea         rdi, [rbp + PF_KEY]
    mov         esi, 32
    lea         rdx, [rbp + PF_SEED]
    call        httpasm_hmac_sha256
    ret

; p256_drbg_init: steps b-g: V = 0x01..., K = 0x00..., K = HMAC_K(V || 0x00 || x || h1 [|| k']),
; V = HMAC_K(V), K = HMAC_K(V || 0x01 || ...), V = HMAC_K(V).
align 16
p256_drbg_init:
    mov         rax, 0x0101010101010101
    mov         [rbp + PF_SEED], rax
    mov         [rbp + PF_SEED + 8], rax
    mov         [rbp + PF_SEED + 16], rax
    mov         [rbp + PF_SEED + 24], rax
    xor         eax, eax
    mov         [rbp + PF_KEY], rax
    mov         [rbp + PF_KEY + 8], rax
    mov         [rbp + PF_KEY + 16], rax
    mov         [rbp + PF_KEY + 24], rax
    mov         byte [rbp + PF_SEED + 32], 0
    mov         rcx, [rbp + PF_SEEDN]
    lea         r8, [rbp + PF_KEY]
    call        p256_drbg_hmac
    mov         ecx, 32
    lea         r8, [rbp + PF_SEED]
    call        p256_drbg_hmac
    mov         byte [rbp + PF_SEED + 32], 1
    mov         rcx, [rbp + PF_SEEDN]
    lea         r8, [rbp + PF_KEY]
    call        p256_drbg_hmac
    mov         ecx, 32
    lea         r8, [rbp + PF_SEED]
    call        p256_drbg_hmac
    ret

; p256_drbg_next: step h: V = HMAC_K(V), the candidate k (its 32 octets at PF_SEED; qlen = 256 =
; the HMAC's output, so one block).
align 16
p256_drbg_next:
    mov         ecx, 32
    lea         r8, [rbp + PF_SEED]
    call        p256_drbg_hmac
    ret

; p256_drbg_reject: step h.3, after a candidate out of range or a zero r or s: K = HMAC_K(V ||
; 0x00), V = HMAC_K(V).
align 16
p256_drbg_reject:
    mov         byte [rbp + PF_SEED + 32], 0
    mov         ecx, 33
    lea         r8, [rbp + PF_KEY]
    call        p256_drbg_hmac
    mov         ecx, 32
    lea         r8, [rbp + PF_SEED]
    call        p256_drbg_hmac
    ret

; =============================================================================
; P256_ROUTINES F, v: every routine of one version (F = FPX or FPQ, v = v3 or v1). The point
; routines work on the frame of the function that calls them (rbp) and clobber every register but
; rbp and rsp.
; =============================================================================
%macro P256_ROUTINES 2

; p256_dbl_v: ACC = 2 ACC.
align 16
p256_dbl_%2:
    P256_DBL    %1
    ret

; p256_add_raw_v, p256_madd_raw_v: the formulas alone, R = ACC + IN (P256_ADD, P256_MADD), for
; callers that settle infinity and the equal points themselves: the constant-time additions below
; by mask, the verification's variable-time ones by branch.
align 16
p256_add_raw_%2:
    P256_ADD    %1
    ret

align 16
p256_madd_raw_%2:
    P256_MADD   %1
    ret

; p256_add_v: ACC = ACC + IN (Jacobian), either input infinity handled by the selection; H and r
; left in T3 and T5.
align 16
p256_add_%2:
    call        p256_add_raw_%2
    P256_IS_ZERO r13, S_AZ
    P256_IS_ZERO r14, S_IZ
    P256_SELECT_RESULT r13, r14
    ret

; p256_madd_v: ACC = ACC + IN (affine, IZ = 1 set by the caller for the selection); IN is
; infinity when x = y = 0 (no curve point has them: the scan's zeros, which a negative digit
; leaves zeros, FP_CNEG mapping 0 to 0).
align 16
p256_madd_%2:
    call        p256_madd_raw_%2
    P256_IS_ZERO r13, S_AZ
    mov         r14, [rbp + PF_IX]
    or          r14, [rbp + PF_IX + 8]
    or          r14, [rbp + PF_IX + 16]
    or          r14, [rbp + PF_IX + 24]
    or          r14, [rbp + PF_IY]
    or          r14, [rbp + PF_IY + 8]
    or          r14, [rbp + PF_IY + 16]
    or          r14, [rbp + PF_IY + 24]
    neg         r14
    sbb         r14, r14
    not         r14
    P256_SELECT_RESULT r13, r14
    ret

; p256_vadd_v: ACC = ACC + IN, IN Jacobian and never infinity, in variable time (verification's
; public points only): ACC at infinity takes IN; after the addition, H = 0 means the same x: the
; same point (r = 0 too) doubles IN, the opposite one gives infinity. The constant-time addition
; above handles neither, as the scalar multiplications never meet them; Straus's pass can.
align 16
p256_vadd_%2:
    P256_IS_ZERO rax, S_AZ
    test        rax, rax
    jnz         .take
    call        p256_add_raw_%2
    P256_IS_ZERO rax, S_T3                  ; H = 0?
    test        rax, rax
    jz          .sum
    P256_IS_ZERO rax, S_T5                  ; r = 0?
    test        rax, rax
    jz          .cancel
    P256_COPY   S_AX, S_IX, 12
    jmp         p256_dbl_%2                 ; (a tail call: it returns to our caller)
.cancel:
    xor         eax, eax
    mov         ecx, 12
    lea         rdi, [rbp + PF_AX]
    rep         stosq
    ret
.sum:
    P256_COPY   S_AX, S_RX, 12
    ret
.take:
    P256_COPY   S_AX, S_IX, 12
    ret

; p256_vmadd_v: p256_vadd_v's cases with IN affine (IX, IY; IZ = 1 set by the caller): the mixed
; addition leaves H in T1 and r in T2.
align 16
p256_vmadd_%2:
    P256_IS_ZERO rax, S_AZ
    test        rax, rax
    jnz         .take
    call        p256_madd_raw_%2
    P256_IS_ZERO rax, S_T1                  ; H = 0?
    test        rax, rax
    jz          .sum
    P256_IS_ZERO rax, S_T2                  ; r = 0?
    test        rax, rax
    jz          .cancel
    P256_COPY   S_AX, S_IX, 12
    jmp         p256_dbl_%2
.cancel:
    xor         eax, eax
    mov         ecx, 12
    lea         rdi, [rbp + PF_AX]
    rep         stosq
    ret
.sum:
    P256_COPY   S_AX, S_RX, 12
    ret
.take:
    P256_COPY   S_AX, S_IX, 12
    ret

; p256_affine_v: PX, PY = ACC in affine coordinates, plain (out of Montgomery form), ACC not
; infinity. Z's inverse comes plain from ha_modinv256 ((Z R)^-1 = Z^-1 R^-1), and a product by
; R^3 mod p takes it to Z^-1 R, its Montgomery form.
align 16
p256_affine_%2:
    P256_COPY   S_ZI, S_AZ, 4
    lea         rdi, [rbp + PF_ZI]
    lea         rsi, [rel p256_mod_p]
    call        ha_modinv256
    %1_MUL      S_ZI, S_ZI, rel p256_r3
    %1_SQR      S_T0, S_ZI                  ; Z^-2
    %1_MUL      S_PX, S_AX, S_T0
    %1_MUL      S_T0, S_T0, S_ZI            ; Z^-3
    %1_MUL      S_PY, S_AY, S_T0
    %1_MUL      S_PX, S_PX, rel p256_int1   ; out of the form
    %1_MUL      S_PY, S_PY, rel p256_int1
    ret

; p256_mul_var_v: ACC = k P, k from PF_K2 (1 <= k < n), P affine (Montgomery form) in PX, PY.
; The table TAB[j] = (j + 1) P: (2j + 2) P by doubling (j + 1) P, (2j + 3) P by adding P to it.
; Then the top window (51: bits 254 and 255, a digit b255 + b254, never negative) selects the
; start, and each window below doubles five times and adds its digit's point.
align 16
p256_mul_var_%2:
    P256_COPY   rbp + PF_TAB, S_PX, 4
    P256_COPY   rbp + PF_TAB + 32, S_PY, 4
    P256_COPY   rbp + PF_TAB + 64, rel p256_one, 4
    P256_COPY   S_IX, rbp + PF_TAB, 12      ; IN = P for the odd multiples
    mov         qword [rbp + PF_WIN], 0
.table:
    imul        rdx, [rbp + PF_WIN], 96
    P256_COPY   S_AX, rbp + PF_TAB + rdx, 12        ; (j + 1) P
    call        p256_dbl_%2
    imul        rdx, [rbp + PF_WIN], 192
    P256_COPY   rbp + PF_TAB + 96 + rdx, S_AX, 12   ; (2j + 2) P
    cmp         qword [rbp + PF_WIN], 7
    je          .table_done
    call        p256_add_%2
    imul        rdx, [rbp + PF_WIN], 192
    P256_COPY   rbp + PF_TAB + 192 + rdx, S_AX, 12  ; (2j + 3) P
    inc         qword [rbp + PF_WIN]
    jmp         .table
.table_done:
    mov         ecx, 51
    P256_DIGIT  5
    P256_SCAN_TAB_%2
    P256_COPY   S_AX, S_IX, 12              ; the start (zeros, infinity, for digit 0)
    mov         dword [rbp + PF_WIN], 50
.window:
    call        p256_dbl_%2
    call        p256_dbl_%2
    call        p256_dbl_%2
    call        p256_dbl_%2
    call        p256_dbl_%2
    mov         ecx, [rbp + PF_WIN]
    P256_DIGIT  5
    mov         [rbp + PF_SIGN], r12
    P256_SCAN_TAB_%2
    mov         r12, [rbp + PF_SIGN]
    FP_CNEG     r12, S_IY
    call        p256_add_%2
    dec         dword [rbp + PF_WIN]
    jns         .window
    ret

; p256_mul_base_v: ACC = k G, k from PF_K2 (0 <= k < n: 0 gives infinity). Window i's digit
; selects from its own table, the sign negates y, and one mixed addition joins it.
align 16
p256_mul_base_%2:
    xor         eax, eax
    mov         ecx, 12
    lea         rdi, [rbp + PF_AX]
    rep         stosq                       ; ACC = infinity
    P256_COPY   S_IZ, rel p256_one, 4       ; the affine addend's Z for the selection
    mov         dword [rbp + PF_WIN], 0
.window:
    mov         ecx, [rbp + PF_WIN]
    P256_DIGIT  P256_W
    mov         [rbp + PF_SIGN], r12
    mov         eax, [rbp + PF_WIN]
    shl         eax, P256_W + 5             ; 2^(W - 1) points of 64 octets a window
    lea         rsi, [rel p256_base_table]
    add         rsi, rax
    P256_SCAN_BASE_%2
    mov         r12, [rbp + PF_SIGN]
    FP_CNEG     r12, S_IY
    call        p256_madd_%2
    inc         dword [rbp + PF_WIN]
    cmp         dword [rbp + PF_WIN], P256_WINDOWS
    jne         .window
    ret

; -----------------------------------------------------------------------------
; int p256_public_key_v(uint8_t out[65], const uint8_t key[32]): httpasm_p256_public_key.
; -----------------------------------------------------------------------------
align 16
p256_public_key_%2:
    P256_ENTER
    mov         [rbp + PF_OUT], rdi
    call        p256_load_scalar
    test        eax, eax
    jnz         .invalid
    call        p256_mul_base_%2
    call        p256_affine_%2
    mov         rdi, [rbp + PF_OUT]
    mov         byte [rdi], 4               ; SEC 1's uncompressed form
    inc         rdi
    lea         rsi, [S_PX]
    call        p256_store_be
    mov         rdi, [rbp + PF_OUT]
    add         rdi, 33
    lea         rsi, [S_PY]
    call        p256_store_be
    mov         qword [rbp + PF_RES], 0
    jmp         .done
.invalid:
    mov         rdi, [rbp + PF_OUT]
    xor         eax, eax
    mov         ecx, HTTPASM_P256_POINT
    rep         stosb
    mov         qword [rbp + PF_RES], -1
.done:
    P256_FINISH

; -----------------------------------------------------------------------------
; int p256_ecdh_v(uint8_t out[32], const uint8_t key[32], const uint8_t point[65]):
; httpasm_p256_ecdh.
; -----------------------------------------------------------------------------
align 16
p256_ecdh_%2:
    P256_ENTER
    mov         [rbp + PF_OUT], rdi
    mov         [rbp + PF_ARG], rdx
    call        p256_load_scalar
    test        eax, eax
    jnz         .invalid
    mov         rsi, [rbp + PF_ARG]
    call        p256_load_point
    test        eax, eax
    jnz         .invalid
    P256_ON_CURVE %1
    call        p256_mul_var_%2
    call        p256_affine_%2              ; (never infinity: k in [1, n), the point's order n)
    mov         rdi, [rbp + PF_OUT]
    lea         rsi, [S_PX]
    call        p256_store_be
    mov         qword [rbp + PF_RES], 0
    jmp         .done
.invalid:
    mov         rdi, [rbp + PF_OUT]
    xor         eax, eax
    mov         ecx, HTTPASM_P256_SCALAR
    rep         stosb
    mov         qword [rbp + PF_RES], -1
.done:
    P256_FINISH

; -----------------------------------------------------------------------------
; int p256_sign_v(uint8_t signature[64], const uint8_t key[32], const uint8_t *digest,
;                 size_t length, const uint8_t *entropy): httpasm_p256_sign.
; -----------------------------------------------------------------------------
align 16
p256_sign_%2:
    P256_ENTER
    mov         [rbp + PF_OUT], rdi
    mov         [rbp + PF_ARG], rsi
    mov         [rbp + PF_ARG2], rdx
    mov         [rbp + PF_ARG3], rcx
    mov         [rbp + PF_ARG4], r8
    call        p256_load_scalar
    test        eax, eax
    jnz         .invalid
    P256_COPY   rbp + PF_D, rbp + PF_K, 4
    mov         rsi, [rbp + PF_ARG]
    P256_COPY   rbp + PF_SEED + 33, rsi, 4  ; x = int2octets(d): the key's own octets
    mov         rsi, [rbp + PF_ARG2]
    mov         rdx, [rbp + PF_ARG3]
    call        p256_load_digest
    lea         rdi, [rbp + PF_SEED + 65]
    lea         rsi, [rbp + PF_E]
    call        p256_store_be               ; h1 = bits2octets(digest) = int2octets(e)
    mov         qword [rbp + PF_SEEDN], 97
    mov         rsi, [rbp + PF_ARG4]
    test        rsi, rsi
    jz          .seeded
    P256_COPY   rbp + PF_SEED + 97, rsi, 4  ; RFC 6979 3.6's k': the caller's entropy
    mov         qword [rbp + PF_SEEDN], 129
.seeded:
    call        p256_drbg_init
.candidate:
    call        p256_drbg_next
    lea         rsi, [rbp + PF_SEED]
    call        p256_load_scalar            ; k, when 1 <= k < n
    test        eax, eax
    jnz         .retry
    call        p256_mul_base_%2
    call        p256_affine_%2
    P256_COPY   rbp + PF_R, S_PX, 4
    FN_REDUCE   rbp + PF_R                  ; r = x mod n
    P256_IS_ZERO rax, rbp + PF_R
    test        rax, rax
    jnz         .retry
    P256_COPY   rbp + PF_KINV, rbp + PF_K, 4
    lea         rdi, [rbp + PF_KINV]
    lea         rsi, [rel p256_mod_n]
    call        ha_modinv256                ; k^-1, plain
    ; s = k^-1 (e + r d): Montgomery products modulo n, each followed by one by R^2 (a b R^-1,
    ; then times R^2 R^-1: the plain product)
    FN_MUL      rbp + PF_S, rbp + PF_R, rbp + PF_D
    FN_MUL      rbp + PF_S, rbp + PF_S, rel p256_n_r2      ; r d
    FN_ADD      rbp + PF_S, rbp + PF_S, rbp + PF_E          ; e + r d
    FN_MUL      rbp + PF_S, rbp + PF_S, rbp + PF_KINV
    FN_MUL      rbp + PF_S, rbp + PF_S, rel p256_n_r2      ; s
    P256_IS_ZERO rax, rbp + PF_S
    test        rax, rax
    jnz         .retry
    mov         rdi, [rbp + PF_OUT]
    lea         rsi, [rbp + PF_R]
    call        p256_store_be
    mov         rdi, [rbp + PF_OUT]
    add         rdi, 32
    lea         rsi, [rbp + PF_S]
    call        p256_store_be
    mov         qword [rbp + PF_RES], 0
    jmp         .done
.retry:
    call        p256_drbg_reject
    jmp         .candidate
.invalid:
    mov         rdi, [rbp + PF_OUT]
    xor         eax, eax
    mov         ecx, HTTPASM_P256_SIGNATURE
    rep         stosb
    mov         qword [rbp + PF_RES], -1
.done:
    P256_FINISH

; -----------------------------------------------------------------------------
; int p256_verify_v(const uint8_t key[65], const uint8_t *digest, size_t length,
;                   const uint8_t signature[64]): httpasm_p256_verify. Every input is public:
; the branches below may follow them.
; -----------------------------------------------------------------------------
align 16
p256_verify_%2:
    P256_ENTER
    mov         [rbp + PF_ARG], rdi
    mov         [rbp + PF_ARG2], rsi
    mov         [rbp + PF_ARG3], rdx
    mov         [rbp + PF_ARG4], rcx
    mov         rsi, rcx
    call        p256_load_scalar            ; r in [1, n)
    test        eax, eax
    jnz         .invalid
    P256_COPY   rbp + PF_R, rbp + PF_K, 4
    mov         rsi, [rbp + PF_ARG4]
    add         rsi, 32
    call        p256_load_scalar            ; s in [1, n)
    test        eax, eax
    jnz         .invalid
    P256_COPY   rbp + PF_S, rbp + PF_K, 4
    mov         rsi, [rbp + PF_ARG]
    call        p256_load_point
    test        eax, eax
    jnz         .invalid
    P256_ON_CURVE %1
    mov         rsi, [rbp + PF_ARG2]
    mov         rdx, [rbp + PF_ARG3]
    call        p256_load_digest
    lea         rdi, [rbp + PF_S]
    lea         rsi, [rel p256_mod_n]
    call        ha_modinv256                ; w = s^-1
    FN_MUL      rbp + PF_U1, rbp + PF_E, rbp + PF_S
    FN_MUL      rbp + PF_U1, rbp + PF_U1, rel p256_n_r2    ; u1 = e w
    FN_MUL      rbp + PF_U2, rbp + PF_R, rbp + PF_S
    FN_MUL      rbp + PF_U2, rbp + PF_U2, rel p256_n_r2    ; u2 = r w
    ; R = u1 G + u2 Q in one pass from the top (Straus): wNAF digits (u1 by 7 bits: G's odd
    ; multiples are in the fixed-base table's window 0, 1G..64G; u2 by 5 bits over Q's odd
    ; multiples 1Q..15Q, built here), the doublings shared; variable time, as every input is
    ; public, so the additions branch on the doubling and cancelling cases
    lea         rsi, [rbp + PF_U1]
    lea         rdi, [rbp + PF_DIG1]
    mov         ecx, 7
    call        p256_wnaf
    mov         [rbp + PF_LEN1], rax
    lea         rsi, [rbp + PF_U2]
    lea         rdi, [rbp + PF_DIG2]
    mov         ecx, 5
    call        p256_wnaf
    mov         [rbp + PF_LEN2], rax
    ; Q's odd multiples into TAB: Q, then 2Q into IN, then Q + 2Q, 3Q + 2Q, ... 13Q + 2Q (none of
    ; these additions meets equal or opposite points: (2j + 1) Q = +-2Q has no solution mod n)
    P256_COPY   S_AX, S_PX, 8
    P256_COPY   S_AZ, rel p256_one, 4
    P256_COPY   rbp + PF_TAB, S_AX, 12
    call        p256_dbl_%2
    P256_COPY   S_IX, S_AX, 12              ; IN = 2Q
    P256_COPY   S_AX, rbp + PF_TAB, 12      ; ACC = Q
    mov         qword [rbp + PF_WIN], 1
.odd:
    call        p256_add_%2                 ; (2j + 1) Q
    imul        rdx, [rbp + PF_WIN], 96
    P256_COPY   rbp + PF_TAB + rdx, S_AX, 12
    inc         qword [rbp + PF_WIN]
    cmp         qword [rbp + PF_WIN], 8
    jne         .odd
    ; the pass: from the longer wNAF's top digit (nonzero by its length) down; the accumulator
    ; starts at infinity, so its first doubling is skipped
    xor         eax, eax
    mov         ecx, 12
    lea         rdi, [rbp + PF_AX]
    rep         stosq
    mov         rax, [rbp + PF_LEN1]
    cmp         rax, [rbp + PF_LEN2]
    cmovb       rax, [rbp + PF_LEN2]
    dec         rax
    mov         [rbp + PF_WIN], rax
    jmp         .digits                     ; (u2 is not 0: its wNAF has at least one digit)
.pass:
    call        p256_dbl_%2
.digits:
    mov         rcx, [rbp + PF_WIN]
    movsx       rax, byte [rbp + PF_DIG1 + rcx]
    test        eax, eax
    jz          .u2
    ; IN = |d| G from window 0 (affine; IZ = 1 for the selection), negated for d < 0
    mov         [rbp + PF_SIGN], rax
    mov         edx, eax
    neg         edx
    cmovs       edx, eax                    ; |d|
    dec         edx
    shl         edx, 6
    lea         rsi, [rel p256_base_table]
    add         rsi, rdx
    P256_COPY   S_IX, rsi, 8
    P256_COPY   S_IZ, rel p256_one, 4
    mov         r12, [rbp + PF_SIGN]
    sar         r12, 63                     ; all ones for a negative digit
    FP_CNEG     r12, S_IY
    call        p256_vmadd_%2
.u2:
    mov         rcx, [rbp + PF_WIN]
    movsx       rax, byte [rbp + PF_DIG2 + rcx]
    test        eax, eax
    jz          .next
    ; IN = |d| Q from TAB[(|d| - 1) / 2] (Jacobian), negated for d < 0
    mov         [rbp + PF_SIGN], rax
    mov         edx, eax
    neg         edx
    cmovs       edx, eax
    shr         edx, 1                      ; (|d| - 1) / 2 for odd |d|
    imul        edx, edx, 96
    P256_COPY   S_IX, rbp + PF_TAB + rdx, 12
    mov         r12, [rbp + PF_SIGN]
    sar         r12, 63
    FP_CNEG     r12, S_IY
    call        p256_vadd_%2
.next:
    dec         qword [rbp + PF_WIN]
    jns         .pass
    ; R at infinity (u1 G = -u2 Q, or a cancellation the pass met and never left): no x to
    ; compare, and (0, 0, 0) would pass X = r Z^2 below and accept a forgery
    P256_IS_ZERO rax, S_AZ
    test        rax, rax
    jnz         .invalid
    ; x(R) mod n = r without the inversion: X = r Z^2, or X = (r + n) Z^2 when r + n < p (x < p
    ; < 2n: those are the only x with x mod n = r)
    %1_SQR      S_T0, S_AZ
    %1_MUL      S_T1, rbp + PF_R, rel p256_r2
    %1_MUL      S_T2, S_T1, S_T0
    P256_DIFFER S_T2, S_AX
    jz          .valid
    mov         r8, [rbp + PF_R]
    mov         r9, [rbp + PF_R + 8]
    mov         r10, [rbp + PF_R + 16]
    mov         r11, [rbp + PF_R + 24]
    mov         rax, r8
    sub         rax, [rel p256_n_p]
    mov         rax, r9
    sbb         rax, [rel p256_n_p + 8]
    mov         rax, r10
    sbb         rax, [rel p256_n_p + 16]
    mov         rax, r11
    sbb         rax, [rel p256_n_p + 24]
    jnc         .invalid                    ; r >= p - n: r + n is no field element
    add         r8, [rel p256_n]
    adc         r9, [rel p256_n + 8]
    adc         r10, [rel p256_n + 16]
    adc         r11, [rel p256_n + 24]
    mov         [rbp + PF_T1], r8
    mov         [rbp + PF_T1 + 8], r9
    mov         [rbp + PF_T1 + 16], r10
    mov         [rbp + PF_T1 + 24], r11
    %1_MUL      S_T1, S_T1, rel p256_r2
    %1_MUL      S_T2, S_T1, S_T0
    P256_DIFFER S_T2, S_AX
    jnz         .invalid
.valid:
    mov         qword [rbp + PF_RES], 0
    jmp         .done
.invalid:
    mov         qword [rbp + PF_RES], -1
.done:
    P256_FINISH
%endmacro

P256_ROUTINES FPX, v3
P256_ROUTINES FPQ, v1

; =============================================================================
; The C ABI: each picks v3 (BMI2, ADX and AVX2) or v1 and jumps there (tail calls: the version
; returns to our caller). httpasm.h says what each does.
; =============================================================================

; -----------------------------------------------------------------------------
; int httpasm_p256_public_key(uint8_t public_key[65], const uint8_t private_key[32])
; -----------------------------------------------------------------------------
global httpasm_p256_public_key:function (httpasm_p256_public_key.end - httpasm_p256_public_key)
align 16
httpasm_p256_public_key:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         p256_public_key_v1
.v3:
    jmp         p256_public_key_v3
.end:

; -----------------------------------------------------------------------------
; int httpasm_p256_ecdh(uint8_t shared[32], const uint8_t private_key[32],
;                       const uint8_t peer_key[65])
; -----------------------------------------------------------------------------
global httpasm_p256_ecdh:function (httpasm_p256_ecdh.end - httpasm_p256_ecdh)
align 16
httpasm_p256_ecdh:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         p256_ecdh_v1
.v3:
    jmp         p256_ecdh_v3
.end:

; -----------------------------------------------------------------------------
; int httpasm_p256_sign(uint8_t signature[64], const uint8_t private_key[32],
;                       const uint8_t *digest, size_t digest_length, const uint8_t *entropy)
; -----------------------------------------------------------------------------
global httpasm_p256_sign:function (httpasm_p256_sign.end - httpasm_p256_sign)
align 16
httpasm_p256_sign:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         p256_sign_v1
.v3:
    jmp         p256_sign_v3
.end:

; -----------------------------------------------------------------------------
; int httpasm_p256_verify(const uint8_t public_key[65], const uint8_t *digest,
;                         size_t digest_length, const uint8_t signature[64])
; -----------------------------------------------------------------------------
global httpasm_p256_verify:function (httpasm_p256_verify.end - httpasm_p256_verify)
align 16
httpasm_p256_verify:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         p256_verify_v1
.v3:
    jmp         p256_verify_v3
.end:
