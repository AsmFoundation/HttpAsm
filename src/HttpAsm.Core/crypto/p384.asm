; =============================================================================
; crypto/p384.asm - NIST P-384 (SP 800-186 3.2.1.4; TLS's secp384r1): the C ABI's
; httpasm_p384_public_key (d G), httpasm_p384_ecdh (the shared secret of TLS 1.3's secp384r1
; key share and RFC 10024's SecP384r1MLKEM1024), httpasm_p384_sign and httpasm_p384_verify
; (ECDSA, FIPS 186-5 6.4: TLS 1.3's ecdsa_secp384r1_sha384, and the certificates of the WebPKI's
; P-384 roots and intermediates, Let's Encrypt's E5-E9 and ISRG Root X2 among them, whose
; signatures every TLS client of an ECDSA chain verifies).
;
; crypto/p256.asm's twin at six limbs: the same formulas, recodings, scans, selections and
; checks (its header has each one's reasoning and measurements), over include/crypto/p384.inc's
; field (six 64-bit limbs in Montgomery form, fully reduced; v3 with mulx and adcx/adox, v1 with
; mul; one is chosen per call). Points in Jacobian coordinates (X, Y, Z), the point at infinity as
; Z = 0 (all zeros):
;   - doubling: OpenSSL's arrangement for a = -3 (4M + 4S, one halving);
;   - addition add-2007-bl (11M + 5S), mixed addition madd-2007-bl (7M + 4S); infinity handled by
;     selection masks, equal inputs never met by the constant-time multiplications, checked by
;     verification's variable-time pass.
; The scalar multiplications, constant time (every digit read by mask over all the table):
;   - variable base (ECDH, verification's u2 Q): Booth digits of 5 bits, 77 windows from the top
;     (bits 5i - 1 .. 5i + 4; the top window, bits 379..383, is never negative), a table of 1P..16P
;     in Jacobian coordinates, then 5 doublings and one addition a window;
;   - fixed base (public keys, signatures): Booth digits of 7 bits, 55 windows, each with its own
;     table of m 2^(7i) G (m = 1..64, affine: 337,920 octets, generated and proven by
;     specs/p384.cs), one mixed addition a window, no doubling.
; No addition meets the doubling case for k in [1, n - 1]: crypto/p256.asm's argument holds word
; for word (a window's addend is +-d 2^(w i), what came before is below 2^(w i - 1) in magnitude).
;
; The inversion (to affine, and ECDSA's k^-1 and s^-1): Bernstein and Yang's divsteps in
; libsecp256k1's modinv64 arrangement, constant time, one routine for p and n, as crypto/p256.asm's
; but with ORIGINAL divsteps (delta from 1, eta = -delta): their paper's Theorem 11.2 bounds the
; steps for any input below 2^384 by floor((49 384 + 57) / 17) = 1110, so 18 batches of 62 (1116),
; numbers in seven signed 62-bit limbs. (The half-delta divsteps crypto/p256.asm runs converge
; faster, but their bound, 590 for 256 bits, comes from a computation libsecp256k1 made for 256
; bits only; the theorem's bound is proven for every size.)
;
; ECDSA. Signing draws k from RFC 6979's HMAC-DRBG with HMAC-SHA384 always (RFC 6979's own k
; whenever the digest is SHA-384's: qlen = hlen = 384, one HMAC block a candidate), the caller's
; entropy as RFC 6979 3.6's extra input when given, and draws again in the cases no one will meet
; (k >= n, r = 0, s = 0). Verification (every input public, so variable time): u1 G + u2 Q in one
; pass from the top (Straus), wNAF digits, u1's by 7 bits over the fixed-base table's window 0
; (1G..64G), u2's by 5 bits over 1Q, 3Q, ..15Q built per call; the additions branch on infinity
; and on equal and opposite points. Then x(R) against r without an inversion: X = r Z^2, or
; X = (r + n) Z^2 when r + n < p.
;
; Validation: a public key must be 97 octets of SEC 1's uncompressed form (04, x, y), x and y
; below p, on the curve (RFC 9846 4.2.8.2; it also rules out the invalid-curve attack); a private
; key, r and s must be in [1, n - 1].
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "crypto/p384.inc"

extern httpasm_hmac_sha384                  ; crypto/hmac.asm: RFC 6979's HMAC (one-shot)

section .rodata
%include "generated/p384_table.inc"

section .text

; -----------------------------------------------------------------------------
; The frame every routine of a call shares, addressed off rbp (the field macros take every
; register but rbp and rsp). 64-aligned; field values are 48 octets (16-aligned: the v1 scans
; move 16-octet rows). Everything below PF_END is wiped before a function returns (keys, nonces,
; every intermediate point).
; -----------------------------------------------------------------------------
PF_AX       equ 0                           ; the accumulator, Jacobian (X, Y, Z)
PF_AY       equ 48
PF_AZ       equ 96
PF_IX       equ 144                         ; the addend: Jacobian, or affine with IZ = 1
PF_IY       equ 192
PF_IZ       equ 240
PF_RX       equ 288                         ; an addition's result before the selection
PF_RY       equ 336
PF_RZ       equ 384
PF_T0       equ 432                         ; twelve temporaries
PF_T1       equ 480
PF_T2       equ 528
PF_T3       equ 576                         ; (the addition leaves H here)
PF_T4       equ 624
PF_T5       equ 672                         ; (and r here)
PF_T6       equ 720
PF_T7       equ 768
PF_T8       equ 816
PF_T9       equ 864
PF_T10      equ 912
PF_T11      equ 960
PF_TAB      equ 1024                        ; the variable base's table: 16 points of 144 octets
PF_PX       equ 3328                        ; an input point (affine, Montgomery), later the
PF_PY       equ 3376                        ; output's coordinates (affine, plain)
PF_ZI       equ 3424                        ; the value being inverted
PF_K2       equ 3472                        ; the scalar shifted up one bit: seven qwords (and one
                                            ; zero above, which the digits' reads may touch)
PF_K        equ 3536                        ; the scalar: six qwords
PF_WIN      equ 3584                        ; the window number
PF_SIGN     equ 3592                        ; the digit's sign as a mask
PF_OUT      equ 3600                        ; the output's address
PF_ARG      equ 3608                        ; inputs' addresses and lengths
PF_RES      equ 3616                        ; the result to return
PF_ARG2     equ 3624
PF_ARG3     equ 3632
PF_ARG4     equ 3640
PF_SEEDN    equ 3648                        ; RFC 6979's seeding length: 145, or 193 with entropy
PF_LEN1     equ 3656                        ; verification: u1's wNAF digits (how many)
PF_LEN2     equ 3664                        ; verification: u2's wNAF digits (how many)
PF_E        equ 3672                        ; ECDSA's scalars, plain limbs: e = digest mod n
PF_D        equ 3720                        ; the private key
PF_R        equ 3768                        ; r
PF_S        equ 3816                        ; s (verification: then w = s^-1)
PF_KINV     equ 3864                        ; k^-1
PF_U1       equ 3912                        ; u1 = e w, u2 = r w
PF_U2       equ 3960
PF_KEY      equ 4008                        ; RFC 6979's K (48 octets)
PF_SEED     equ 4056                        ; V || separator || x || h1 || entropy (193 of 200)
PF_DIG1     equ 4256                        ; u1's wNAF digits, signed octets (392)
PF_DIG2     equ 4648                        ; u2's (392)
PF_END      equ 5040                        ; (wiped up to here)
PF_OLDSP    equ 5040                        ; the caller's rsp (after the six pushes)
PF_FRAME    equ 5056                        ; a multiple of 64

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

; P384_COPY dst, src, qwords: memory to memory through rax (no flags).
%macro P384_COPY 3
  %assign c_q 0
  %rep %3
    mov         rax, [%2 + c_q]
    mov         [%1 + c_q], rax
    %assign c_q c_q + 8
  %endrep
%endmacro

; P384_ENTER / P384_LEAVE: the six kept registers pushed, the 64-aligned frame at rbp (the
; caller's rsp kept above PF_END, so the wipe leaves it); keeps rdi, rsi, rdx, rcx, r8, r9, r10.
; The frame passes a page, so it is taken a page at a time (HA_STACK_DOWN, counting in r11: no
; stack clash).
%macro P384_ENTER 0
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    and         rsp, -64
    HA_STACK_DOWN PF_FRAME, r11d
    mov         rbp, rsp
    mov         [rbp + PF_OLDSP], rax
%endmacro
%macro P384_LEAVE 0
    mov         rsp, [rbp + PF_OLDSP]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
%endmacro

; P384_FINISH: the return: eax = PF_RES's low dword after the frame below PF_END is wiped (it
; held the key or the nonce, the table, every intermediate point), then P384_LEAVE and ret.
%macro P384_FINISH 0
    mov         r8, [rbp + PF_RES]
    xor         eax, eax
    mov         ecx, PF_END / 8
    mov         rdi, rbp
    rep         stosq
    mov         eax, r8d
    P384_LEAVE
    ret
%endmacro

; P384_IS_ZERO reg, slot: reg = all ones when the slot's six qwords are 0, else 0 (no branch).
%macro P384_IS_ZERO 2
    mov         %1, [%2]
    or          %1, [%2 + 8]
    or          %1, [%2 + 16]
    or          %1, [%2 + 24]
    or          %1, [%2 + 32]
    or          %1, [%2 + 40]
    neg         %1                          ; CF = nonzero
    sbb         %1, %1
    not         %1
%endmacro

; P384_DIFFER a, b: ZF clear when the six qwords at a and b differ (an OR of their XORs; for public
; values only: the caller branches on it). Clobbers rax, rcx.
%macro P384_DIFFER 2
    mov         rax, [%1]
    xor         rax, [%2]
  %assign d_q 8
  %rep 5
    mov         rcx, [%1 + d_q]
    xor         rcx, [%2 + d_q]
    or          rax, rcx
    %assign d_q d_q + 8
  %endrep
%endmacro

; P384_NREDUCE slot: slot = slot mod n for any value below 2^384 (below 2n: one subtraction,
; selected by cmov). Clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r14, the flags.
%macro P384_NREDUCE 1
    F6_LOAD     %1
    xor         r14d, r14d
    F6_SUBM     rel p384_n
    F6_STORE    %1
%endmacro

; P384_DIGIT w: ecx = window number i (public) -> edx = the magnitude of the window's Booth digit
; (0..2^(w - 1)), r12 = its sign as a mask (all ones when negative). The window is bits
; w i - 1 .. w i + w - 1 of the scalar, read as bits w i .. w i + w of PF_K2 (the scalar shifted up
; one bit); the qword and the shift follow i alone. Booth (OpenSSL's booth_recode_w5/w7): s =
; -(v >> w); d = s ? 2^(w + 1) - 1 - v : v; magnitude (d >> 1) + (d & 1), negative when s.
; Clobbers rax, rcx, the flags.
%macro P384_DIGIT 1
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

; P384_SELECT_RESULT inf_acc, inf_in: ACC = inf_in ? ACC : (inf_acc ? IN : R) over the eighteen
; qwords, the masks in registers (all ones = that input is infinity). No branch.
%macro P384_SELECT_RESULT 2
  %assign s_q 0
  %rep 18
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

; P384_ON_CURVE F: the input point (PX, PY, plain limbs below p) into Montgomery form, then
; jumps to the caller's .invalid unless y^2 = x^3 - 3x + b. A public key's check: the branch is
; on public data.
%macro P384_ON_CURVE 1
    %1_FMUL     S_PX, S_PX, rel p384_r2
    %1_FMUL     S_PY, S_PY, rel p384_r2
    %1_FSQR     S_T0, S_PX
    %1_FMUL     S_T0, S_T0, S_PX            ; x^3
    %1_FADD     S_T1, S_PX, S_PX
    %1_FADD     S_T1, S_T1, S_PX            ; 3x
    %1_FSUB     S_T0, S_T0, S_T1
    %1_FADD     S_T0, S_T0, rel p384_b      ; x^3 - 3x + b
    %1_FSQR     S_T1, S_PY                  ; y^2
    P384_DIFFER S_T0, S_T1
    jnz         .invalid
%endmacro

; -----------------------------------------------------------------------------
; The point formulas over field version F (frame slots in, frame slots out): crypto/p256.asm's,
; operation for operation.
; -----------------------------------------------------------------------------

; P384_DBL F: ACC = 2 ACC, OpenSSL's ecp_nistz256_point_double arrangement for a = -3: with
; S = (2Y)^2 = 4Y^2, 4 beta = 4 X Y^2 is S X, 8 Y^4 is S^2 / 2, Z3 = 2Y Z. 4M + 4S and ten small
; operations. Infinity (zeros) stays zeros. Every input slot is read before it is written.
%macro P384_DBL 1
    %1_FADD     S_T0, S_AY, S_AY            ; 2Y
    %1_FSQR     S_T1, S_AZ                  ; delta = Z^2
    %1_FSQR     S_T2, S_T0                  ; S = 4Y^2
    %1_FMUL     S_AZ, S_T0, S_AZ            ; Z3 = 2Y Z
    %1_FSUB     S_T4, S_AX, S_T1            ; X - delta
    %1_FADD     S_T5, S_AX, S_T1            ; X + delta
    %1_FSQR     S_T6, S_T2                  ; 16 Y^4
    %1_FMUL     S_T2, S_T2, S_AX            ; 4 beta = 4 X Y^2
    %1_FMUL     S_T4, S_T4, S_T5            ; (X - delta)(X + delta)
    %1_FHALF    S_T6, S_T6                  ; 8 Y^4
    %1_FADD     S_T5, S_T4, S_T4
    %1_FADD     S_T4, S_T5, S_T4            ; alpha = 3 (X - delta)(X + delta)
    %1_FADD     S_T5, S_T2, S_T2            ; 8 beta
    %1_FSQR     S_T7, S_T4                  ; alpha^2
    %1_FSUB     S_AX, S_T7, S_T5            ; X3 = alpha^2 - 8 beta
    %1_FSUB     S_T2, S_T2, S_AX            ; 4 beta - X3
    %1_FMUL     S_T2, S_T2, S_T4            ; alpha (4 beta - X3)
    %1_FSUB     S_AY, S_T2, S_T6            ; Y3 = alpha (4 beta - X3) - 8 Y^4
%endmacro

; P384_ADD F: R = ACC + IN, both Jacobian, add-2007-bl (11M + 5S). Leaves H = U2 - U1 in T3 and
; r = 2 (S2 - S1) in T5: the doubling case is H = r = 0, the cancelling case H = 0 with r not 0
; (p384_vadd looks). Wrong for either case and for an input at infinity: the caller's selection
; replaces the latter.
%macro P384_ADD 1
    %1_FSQR     S_T0, S_AZ                  ; Z1Z1 = Z1^2
    %1_FSQR     S_T1, S_IZ                  ; Z2Z2 = Z2^2
    %1_FMUL     S_T2, S_AX, S_T1            ; U1 = X1 Z2Z2
    %1_FMUL     S_T3, S_IX, S_T0            ; U2 = X2 Z1Z1
    %1_FMUL     S_T4, S_IZ, S_T1            ; Z2^3
    %1_FMUL     S_T5, S_AZ, S_T0            ; Z1^3
    %1_FADD     S_T8, S_AZ, S_IZ            ; Z1 + Z2
    %1_FMUL     S_T4, S_AY, S_T4            ; S1 = Y1 Z2^3
    %1_FMUL     S_T5, S_IY, S_T5            ; S2 = Y2 Z1^3
    %1_FSUB     S_T3, S_T3, S_T2            ; H = U2 - U1
    %1_FSQR     S_T8, S_T8                  ; (Z1 + Z2)^2
    %1_FSUB     S_T5, S_T5, S_T4            ; S2 - S1
    %1_FADD     S_T6, S_T3, S_T3            ; 2H
    %1_FADD     S_T5, S_T5, S_T5            ; r = 2 (S2 - S1)
    %1_FSQR     S_T6, S_T6                  ; I = (2H)^2
    %1_FSUB     S_T8, S_T8, S_T0            ; (Z1 + Z2)^2 - Z1Z1
    %1_FSQR     S_T9, S_T5                  ; r^2
    %1_FMUL     S_T7, S_T3, S_T6            ; J = H I
    %1_FMUL     S_T2, S_T2, S_T6            ; V = U1 I
    %1_FSUB     S_T8, S_T8, S_T1            ; (Z1 + Z2)^2 - Z1Z1 - Z2Z2
    %1_FMUL     S_RZ, S_T8, S_T3            ; Z3 = that H
    %1_FSUB     S_T9, S_T9, S_T7            ; r^2 - J
    %1_FADD     S_T10, S_T2, S_T2           ; 2V
    %1_FMUL     S_T4, S_T4, S_T7            ; S1 J
    %1_FSUB     S_RX, S_T9, S_T10           ; X3 = r^2 - J - 2V
    %1_FSUB     S_T2, S_T2, S_RX            ; V - X3
    %1_FADD     S_T4, S_T4, S_T4            ; 2 S1 J
    %1_FMUL     S_T2, S_T5, S_T2            ; r (V - X3)
    %1_FSUB     S_RY, S_T2, S_T4            ; Y3 = r (V - X3) - 2 S1 J
%endmacro

; P384_MADD F: R = ACC + IN with IN affine (IX, IY), madd-2007-bl (7M + 4S); leaves H in T1 and r
; in T2. The same cases as P384_ADD are the caller's.
%macro P384_MADD 1
    %1_FSQR     S_T0, S_AZ                  ; Z1Z1 = Z1^2
    %1_FMUL     S_T1, S_IX, S_T0            ; U2 = X2 Z1Z1
    %1_FMUL     S_T2, S_AZ, S_T0            ; Z1^3
    %1_FSUB     S_T1, S_T1, S_AX            ; H = U2 - X1
    %1_FMUL     S_T2, S_IY, S_T2            ; S2 = Y2 Z1^3
    %1_FSQR     S_T3, S_T1                  ; HH = H^2
    %1_FADD     S_T7, S_AZ, S_T1            ; Z1 + H
    %1_FSUB     S_T2, S_T2, S_AY            ; S2 - Y1
    %1_FADD     S_T4, S_T3, S_T3            ; 2 HH
    %1_FSQR     S_T7, S_T7                  ; (Z1 + H)^2
    %1_FADD     S_T2, S_T2, S_T2            ; r = 2 (S2 - Y1)
    %1_FADD     S_T4, S_T4, S_T4            ; I = 4 HH
    %1_FMUL     S_T5, S_T1, S_T4            ; J = H I
    %1_FMUL     S_T6, S_AX, S_T4            ; V = X1 I
    %1_FSQR     S_T8, S_T2                  ; r^2
    %1_FSUB     S_T7, S_T7, S_T0            ; (Z1 + H)^2 - Z1Z1
    %1_FMUL     S_T9, S_AY, S_T5            ; Y1 J
    %1_FSUB     S_T8, S_T8, S_T5            ; r^2 - J
    %1_FADD     S_T10, S_T6, S_T6           ; 2V
    %1_FSUB     S_RZ, S_T7, S_T3            ; Z3 = (Z1 + H)^2 - Z1Z1 - HH
    %1_FSUB     S_RX, S_T8, S_T10           ; X3 = r^2 - J - 2V
    %1_FADD     S_T9, S_T9, S_T9            ; 2 Y1 J
    %1_FSUB     S_T6, S_T6, S_RX            ; V - X3
    %1_FMUL     S_T6, S_T2, S_T6            ; r (V - X3)
    %1_FSUB     S_RY, S_T6, S_T9            ; Y3 = r (V - X3) - 2 Y1 J
%endmacro

; -----------------------------------------------------------------------------
; The table scans: edx = a digit's magnitude. Every entry is read and masked by (its number =
; the digit): no address depends on the digit; digit 0 matches none and gives zeros (infinity).
;   P384_SCAN_TAB_v3 / _v1: TAB (16 Jacobian points, 144 octets each) into IN.
;   P384_SCAN_BASE_v3 / _v1: the fixed-base window at rsi (2^(P384_W - 1) affine points, 96
;     octets each) into IX, IY.
; v3 with AVX2 (and vzeroupper after: the field code and the C ABI's callees run legacy SSE);
; v1 with SSE2 (its loads aligned: every entry starts on 16 octets). Clobber rax, rcx, rsi,
; xmm0-xmm13 (ymm at v3), the flags.
; -----------------------------------------------------------------------------
%macro P384_SCAN_TAB_v3 0
    vmovd       xmm0, edx
    vpbroadcastd ymm0, xmm0
    vpcmpeqd    ymm6, ymm6, ymm6
    vpsrld      ymm6, ymm6, 31              ; 1 in every dword: the step
    vmovdqa     ymm7, ymm6                  ; the entry number, from 1
    vpxor       xmm1, xmm1, xmm1
    vpxor       xmm2, xmm2, xmm2
    vpxor       xmm3, xmm3, xmm3
    vpxor       xmm4, xmm4, xmm4
    vpxor       xmm5, xmm5, xmm5
    lea         rax, [rbp + PF_TAB]
    mov         ecx, 16
%%scan:
    vpcmpeqd    ymm8, ymm7, ymm0
    vpaddd      ymm7, ymm7, ymm6
    vpand       ymm9, ymm8, [rax]
    vpor        ymm1, ymm1, ymm9
    vpand       ymm9, ymm8, [rax + 32]
    vpor        ymm2, ymm2, ymm9
    vpand       ymm9, ymm8, [rax + 64]
    vpor        ymm3, ymm3, ymm9
    vpand       ymm9, ymm8, [rax + 96]
    vpor        ymm4, ymm4, ymm9
    vpand       xmm9, xmm8, [rax + 128]
    vpor        xmm5, xmm5, xmm9
    add         rax, 144
    dec         ecx
    jnz         %%scan
    vmovdqu     [rbp + PF_IX], ymm1
    vmovdqu     [rbp + PF_IX + 32], ymm2
    vmovdqu     [rbp + PF_IX + 64], ymm3
    vmovdqu     [rbp + PF_IX + 96], ymm4
    vmovdqu     [rbp + PF_IX + 128], xmm5
    vzeroupper
%endmacro

%macro P384_SCAN_TAB_v1 0
    movd        xmm0, edx
    pshufd      xmm0, xmm0, 0
    pcmpeqd     xmm10, xmm10
    psrld       xmm10, 31                   ; 1 in every dword: the step
    movdqa      xmm11, xmm10                ; the entry number, from 1
    pxor        xmm1, xmm1
    pxor        xmm2, xmm2
    pxor        xmm3, xmm3
    pxor        xmm4, xmm4
    pxor        xmm5, xmm5
    pxor        xmm6, xmm6
    pxor        xmm7, xmm7
    pxor        xmm8, xmm8
    pxor        xmm9, xmm9
    lea         rax, [rbp + PF_TAB]
    mov         ecx, 16
%%scan:
    movdqa      xmm12, xmm11
    pcmpeqd     xmm12, xmm0
    paddd       xmm11, xmm10
    P384_SCAN_ROW xmm1, rax
    P384_SCAN_ROW xmm2, rax + 16
    P384_SCAN_ROW xmm3, rax + 32
    P384_SCAN_ROW xmm4, rax + 48
    P384_SCAN_ROW xmm5, rax + 64
    P384_SCAN_ROW xmm6, rax + 80
    P384_SCAN_ROW xmm7, rax + 96
    P384_SCAN_ROW xmm8, rax + 112
    P384_SCAN_ROW xmm9, rax + 128
    add         rax, 144
    dec         ecx
    jnz         %%scan
    movdqa      [rbp + PF_IX], xmm1
    movdqa      [rbp + PF_IX + 16], xmm2
    movdqa      [rbp + PF_IX + 32], xmm3
    movdqa      [rbp + PF_IX + 48], xmm4
    movdqa      [rbp + PF_IX + 64], xmm5
    movdqa      [rbp + PF_IX + 80], xmm6
    movdqa      [rbp + PF_IX + 96], xmm7
    movdqa      [rbp + PF_IX + 112], xmm8
    movdqa      [rbp + PF_IX + 128], xmm9
%endmacro

; P384_SCAN_ROW acc, address: acc |= the 16 octets at address ANDed with xmm12 (the entry's mask);
; xmm13 the temporary (SSE2's pand needs the row in a register: aligned rows). No flags.
%macro P384_SCAN_ROW 2
    movdqa      xmm13, [%2]
    pand        xmm13, xmm12
    por         %1, xmm13
%endmacro

%macro P384_SCAN_BASE_v3 0
    vmovd       xmm0, edx
    vpbroadcastd ymm0, xmm0
    vpcmpeqd    ymm6, ymm6, ymm6
    vpsrld      ymm6, ymm6, 31
    vmovdqa     ymm7, ymm6
    vpxor       xmm1, xmm1, xmm1
    vpxor       xmm2, xmm2, xmm2
    vpxor       xmm3, xmm3, xmm3
    mov         ecx, 1 << (P384_W - 1)
%%scan:
    vpcmpeqd    ymm8, ymm7, ymm0
    vpaddd      ymm7, ymm7, ymm6
    vpand       ymm9, ymm8, [rsi]
    vpor        ymm1, ymm1, ymm9
    vpand       ymm9, ymm8, [rsi + 32]
    vpor        ymm2, ymm2, ymm9
    vpand       ymm9, ymm8, [rsi + 64]
    vpor        ymm3, ymm3, ymm9
    add         rsi, 96
    dec         ecx
    jnz         %%scan
    vmovdqu     [rbp + PF_IX], ymm1
    vmovdqu     [rbp + PF_IX + 32], ymm2    ; (x is 48 octets: ymm2's upper half is y's first 16)
    vmovdqu     [rbp + PF_IX + 64], ymm3
    vzeroupper
%endmacro

%macro P384_SCAN_BASE_v1 0
    movd        xmm0, edx
    pshufd      xmm0, xmm0, 0
    pcmpeqd     xmm10, xmm10
    psrld       xmm10, 31
    movdqa      xmm11, xmm10
    pxor        xmm1, xmm1
    pxor        xmm2, xmm2
    pxor        xmm3, xmm3
    pxor        xmm4, xmm4
    pxor        xmm5, xmm5
    pxor        xmm6, xmm6
    mov         ecx, 1 << (P384_W - 1)
%%scan:
    movdqa      xmm12, xmm11
    pcmpeqd     xmm12, xmm0
    paddd       xmm11, xmm10
    P384_SCAN_ROW xmm1, rsi
    P384_SCAN_ROW xmm2, rsi + 16
    P384_SCAN_ROW xmm3, rsi + 32
    P384_SCAN_ROW xmm4, rsi + 48
    P384_SCAN_ROW xmm5, rsi + 64
    P384_SCAN_ROW xmm6, rsi + 80
    add         rsi, 96
    dec         ecx
    jnz         %%scan
    movdqa      [rbp + PF_IX], xmm1
    movdqa      [rbp + PF_IX + 16], xmm2
    movdqa      [rbp + PF_IX + 32], xmm3
    movdqa      [rbp + PF_IX + 48], xmm4
    movdqa      [rbp + PF_IX + 64], xmm5
    movdqa      [rbp + PF_IX + 80], xmm6
%endmacro

; =============================================================================
; p384_inverse: x^-1 modulo p or n, constant time, by Bernstein and Yang's divsteps ("Fast
; constant-time gcd computation and modular inversion", 2019) in the arrangement of
; libsecp256k1's modinv64 (MIT; its doc/safegcd_implementation.md derives every step used here):
;   - original divsteps (delta from 1, kept as eta = -delta: the swap when eta < 0 and g odd,
;     then eta = -eta - 1, else eta - 1): 1116 of them, 18 batches of 62, always - the paper's
;     Theorem 11.2 bound for inputs below 2^384 is floor((49 384 + 57) / 17) = 1110;
;   - a batch works on f's and g's low 62-bit limbs only and builds the 2x2 transition matrix
;     (u, v, q, r) scaled by 2^62 (u and r start at 1; u and v double each step while g halves),
;     which is then applied to the whole numbers: f, g = (u f + v g, q f + r g) / 2^62, and to the
;     Bezout coefficients d, e modulo M, a multiple of M chosen through M^-1 mod 2^62 making each
;     division exact;
;   - numbers in seven signed 62-bit limbs (six of 62 bits, the top one signed), so each product
;     of a limb by a matrix entry (|entry| <= 2^62) fits a signed 128-bit sum.
; Every batch runs the same instructions whatever the values: no branch and no address depends
; on x (the counts are constants), which is why it can invert a secret nonce.
; =============================================================================

M62 equ 0x3FFFFFFFFFFFFFFF

; The local frame (rsp-based).
IV_F        equ 0                           ; f: seven signed 62-bit limbs
IV_G        equ 56                          ; g
IV_D        equ 112                         ; d (the inverse's coefficient, modulo M)
IV_E        equ 168                         ; e
IV_X        equ 224                         ; the caller's x
IV_MOD      equ 232                         ; the modulus' record
IV_CNT      equ 240                         ; the batch counter
IV_ETA      equ 248                         ; eta between batches
IV_SIZE     equ 264                         ; (rsp 16-aligned is not needed: no call inside)

; IV_UPDATE a, b: the matrix applied to the two numbers held as seven limbs at [rsp + a] and
; [rsp + b] (f and g): a, b = (u a + v b) / 2^62, (q a + r b) / 2^62, with r11 = u, r12 = v,
; r13 = q, r14 = r. Each limb's products are summed in a signed 128-bit pair (rbx:rcx for a,
; r8:r9 for b) and shifted down 62 bits (arithmetically) for the next limb; the low 62 bits of
; the first limb's sums are zero (the batch made them so). Limb i - 1 of the results is written
; after limb i of the inputs is read. Clobbers rax, rbx, rcx, rdx, r8, r9, r10, the flags.
%macro IV_UPDATE 2
    mov         r10, M62
    mov         rax, [rsp + %1]
    imul        r11                         ; u a0
    mov         rbx, rax
    mov         rcx, rdx
    mov         rax, [rsp + %2]
    imul        r12                         ; v b0
    add         rbx, rax
    adc         rcx, rdx
    mov         rax, [rsp + %1]
    imul        r13                         ; q a0
    mov         r8, rax
    mov         r9, rdx
    mov         rax, [rsp + %2]
    imul        r14                         ; r b0
    add         r8, rax
    adc         r9, rdx
    shrd        rbx, rcx, 62
    sar         rcx, 62
    shrd        r8, r9, 62
    sar         r9, 62
  %assign iv_i 1
  %rep 6
    mov         rax, [rsp + %1 + 8 * iv_i]
    imul        r11
    add         rbx, rax
    adc         rcx, rdx
    mov         rax, [rsp + %2 + 8 * iv_i]
    imul        r12
    add         rbx, rax
    adc         rcx, rdx
    mov         rax, [rsp + %1 + 8 * iv_i]
    imul        r13
    add         r8, rax
    adc         r9, rdx
    mov         rax, [rsp + %2 + 8 * iv_i]
    imul        r14
    add         r8, rax
    adc         r9, rdx
    mov         rax, rbx
    and         rax, r10
    mov         [rsp + %1 + 8 * iv_i - 8], rax
    mov         rax, r8
    and         rax, r10
    mov         [rsp + %2 + 8 * iv_i - 8], rax
    shrd        rbx, rcx, 62
    sar         rcx, 62
    shrd        r8, r9, 62
    sar         r9, 62
    %assign iv_i iv_i + 1
  %endrep
    mov         [rsp + %1 + 48], rbx        ; the top limbs, signed
    mov         [rsp + %2 + 48], r8
%endmacro

; -----------------------------------------------------------------------------
; p384_inverse: rdi = six qwords x (plain, below M), replaced by x^-1 mod M (0 stays 0); rsi =
; the modulus' record (p384_mod_p or p384_mod_n: M in seven signed 62-bit limbs, then M^-1 mod
; 2^62). System V: keeps rbx, rbp, r12-r15. Its frame is wiped before it returns.
; -----------------------------------------------------------------------------
align 16
p384_inverse:
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    sub         rsp, IV_SIZE
    mov         [rsp + IV_X], rdi
    mov         [rsp + IV_MOD], rsi
    ; f = M; g = x in signed 62-bit limbs; d = 0; e = 1
  %assign iv_q 0
  %rep 7
    mov         rax, [rsi + iv_q]
    mov         [rsp + IV_F + iv_q], rax
    mov         qword [rsp + IV_D + iv_q], 0
    mov         qword [rsp + IV_E + iv_q], 0
    %assign iv_q iv_q + 8
  %endrep
    mov         qword [rsp + IV_E], 1
    mov         r10, M62
    mov         r8, [rdi]                   ; limb i = bits 62i .. 62i + 61 of x
    mov         rax, r8
    and         rax, r10
    mov         [rsp + IV_G], rax
    mov         r9, [rdi + 8]
    mov         rax, r8
    shrd        rax, r9, 62
    and         rax, r10
    mov         [rsp + IV_G + 8], rax
    mov         r8, [rdi + 16]
    mov         rax, r9
    shrd        rax, r8, 60
    and         rax, r10
    mov         [rsp + IV_G + 16], rax
    mov         r9, [rdi + 24]
    mov         rax, r8
    shrd        rax, r9, 58
    and         rax, r10
    mov         [rsp + IV_G + 24], rax
    mov         r8, [rdi + 32]
    mov         rax, r9
    shrd        rax, r8, 56
    and         rax, r10
    mov         [rsp + IV_G + 32], rax
    mov         r9, [rdi + 40]
    mov         rax, r8
    shrd        rax, r9, 54
    and         rax, r10
    mov         [rsp + IV_G + 40], rax
    shr         r9, 52
    mov         [rsp + IV_G + 48], r9
    mov         qword [rsp + IV_ETA], -1
    mov         dword [rsp + IV_CNT], 18
.batch:
    ; 62 divsteps on the low limbs: eta r8, f r9, g r10, u r11, v r12, q r13, r r14
    mov         r8, [rsp + IV_ETA]
    mov         r9, [rsp + IV_F]
    mov         r10, [rsp + IV_G]
    mov         r11d, 1
    xor         r12d, r12d
    xor         r13d, r13d
    mov         r14d, 1
    mov         ecx, 62
.step:
    mov         rax, r8
    sar         rax, 63                     ; c1: all ones when eta < 0 (delta > 0)
    mov         edx, 1
    and         rdx, r10
    neg         rdx                         ; c2: all ones when g is odd
    mov         rsi, r9                     ; x, y, z = f, u, v negated under c1
    xor         rsi, rax
    sub         rsi, rax
    mov         rdi, r11
    xor         rdi, rax
    sub         rdi, rax
    mov         rbx, r12
    xor         rbx, rax
    sub         rbx, rax
    and         rax, rdx                    ; c1 &= c2: the swap (ZF clear)
    cmovnz      r9, r10                     ; f, u, v = g, q, r under the swap (the old ones)
    cmovnz      r11, r13
    cmovnz      r12, r14
    and         rsi, rdx                    ; g, q, r += x, y, z under c2
    add         r10, rsi
    and         rdi, rdx
    add         r13, rdi
    and         rbx, rdx
    add         r14, rbx
    xor         r8, rax                     ; eta = -eta - 1 (= ~eta) under the swap, else eta - 1
    dec         r8
    sub         r8, rax                     ; (+1 back under the swap: ~eta - 1 + 1)
    shr         r10, 1                      ; g /= 2 (its low bit is 0 now); u, v *= 2
    add         r11, r11
    add         r12, r12
    dec         ecx
    jnz         .step
    mov         [rsp + IV_ETA], r8
    ; d, e = (u d + v e, q d + r e) / 2^62 modulo M: md, me multiples of M make the low 62 bits
    ; vanish (and start at u or v, q or r for a negative d or e, keeping the range (-2M, M))
    mov         r15, [rsp + IV_MOD]
    mov         rax, [rsp + IV_D + 48]
    sar         rax, 63                     ; sd: d < 0
    mov         rdx, [rsp + IV_E + 48]
    sar         rdx, 63                     ; se: e < 0
    mov         rdi, r11                    ; md = (u & sd) + (v & se)
    and         rdi, rax
    mov         rsi, r12
    and         rsi, rdx
    add         rdi, rsi
    mov         rsi, r13                    ; me = (q & sd) + (r & se)
    and         rsi, rax
    mov         rbx, r14
    and         rbx, rdx
    add         rsi, rbx
    mov         rax, [rsp + IV_D]
    imul        r11                         ; cd = u d0 + v e0
    mov         rbx, rax
    mov         rcx, rdx
    mov         rax, [rsp + IV_E]
    imul        r12
    add         rbx, rax
    adc         rcx, rdx
    mov         rax, [rsp + IV_D]
    imul        r13                         ; ce = q d0 + r e0
    mov         r8, rax
    mov         r9, rdx
    mov         rax, [rsp + IV_E]
    imul        r14
    add         r8, rax
    adc         r9, rdx
    mov         r10, M62
    mov         rax, [r15 + 56]             ; md -= (M^-1 cd + md) mod 2^62
    imul        rax, rbx
    add         rax, rdi
    and         rax, r10
    sub         rdi, rax
    mov         rax, [r15 + 56]             ; me -= (M^-1 ce + me) mod 2^62
    imul        rax, r8
    add         rax, rsi
    and         rax, r10
    sub         rsi, rax
    mov         rax, [r15]                  ; cd += M0 md, ce += M0 me: low 62 bits now 0
    imul        rdi
    add         rbx, rax
    adc         rcx, rdx
    mov         rax, [r15]
    imul        rsi
    add         r8, rax
    adc         r9, rdx
    shrd        rbx, rcx, 62
    sar         rcx, 62
    shrd        r8, r9, 62
    sar         r9, 62
  %assign iv_i 1
  %rep 6
    mov         rax, [rsp + IV_D + 8 * iv_i]
    imul        r11
    add         rbx, rax
    adc         rcx, rdx
    mov         rax, [rsp + IV_E + 8 * iv_i]
    imul        r12
    add         rbx, rax
    adc         rcx, rdx
    mov         rax, [r15 + 8 * iv_i]
    imul        rdi
    add         rbx, rax
    adc         rcx, rdx
    mov         rax, [rsp + IV_D + 8 * iv_i]
    imul        r13
    add         r8, rax
    adc         r9, rdx
    mov         rax, [rsp + IV_E + 8 * iv_i]
    imul        r14
    add         r8, rax
    adc         r9, rdx
    mov         rax, [r15 + 8 * iv_i]
    imul        rsi
    add         r8, rax
    adc         r9, rdx
    mov         rax, rbx
    and         rax, r10
    mov         [rsp + IV_D + 8 * iv_i - 8], rax
    mov         rax, r8
    and         rax, r10
    mov         [rsp + IV_E + 8 * iv_i - 8], rax
    shrd        rbx, rcx, 62
    sar         rcx, 62
    shrd        r8, r9, 62
    sar         r9, 62
    %assign iv_i iv_i + 1
  %endrep
    mov         [rsp + IV_D + 48], rbx
    mov         [rsp + IV_E + 48], r8
    ; f, g = (u f + v g, q f + r g) / 2^62
    IV_UPDATE   IV_F, IV_G
    dec         dword [rsp + IV_CNT]
    jnz         .batch
    ; g is 0 and f is +1 or -1 (x and M coprime; f = M and d = 0 when x = 0): d, negated when
    ; f < 0, from (-2M, M) into [0, M), each conditional step a mask
    mov         r15, [rsp + IV_MOD]
    mov         r10, M62
    mov         rax, [rsp + IV_D + 48]
    sar         rax, 63                     ; d < 0: add M
    mov         rdx, [rsp + IV_F + 48]
    sar         rdx, 63                     ; f < 0: negate
  %assign iv_q 0
  %rep 7
    mov         rbx, [r15 + iv_q]
    and         rbx, rax
    add         rbx, [rsp + IV_D + iv_q]
    xor         rbx, rdx
    sub         rbx, rdx
    mov         [rsp + IV_D + iv_q], rbx
    %assign iv_q iv_q + 8
  %endrep
  %rep 2
    ; carries up through the limbs, then M added again when still negative (the second round
    ; adds nothing: it only leaves every limb in range)
    %assign iv_q 0
    %rep 6
    mov         rax, [rsp + IV_D + iv_q]
    mov         rbx, rax
    sar         rax, 62
    add         [rsp + IV_D + iv_q + 8], rax
    and         rbx, r10
    mov         [rsp + IV_D + iv_q], rbx
      %assign iv_q iv_q + 8
    %endrep
    mov         rax, [rsp + IV_D + 48]
    sar         rax, 63
    %assign iv_q 0
    %rep 7
    mov         rbx, [r15 + iv_q]
    and         rbx, rax
    add         [rsp + IV_D + iv_q], rbx
      %assign iv_q iv_q + 8
    %endrep
  %endrep
    ; d's seven limbs back into six qwords: qword j = limb j >> 2j | limb j+1 << (62 - 2j)
    mov         rdi, [rsp + IV_X]
  %assign iv_j 0
  %rep 6
    mov         rax, [rsp + IV_D + 8 * iv_j]
    %if iv_j > 0
    shr         rax, 2 * iv_j
    %endif
    mov         rdx, [rsp + IV_D + 8 * iv_j + 8]
    shl         rdx, 62 - 2 * iv_j
    or          rax, rdx
    mov         [rdi + 8 * iv_j], rax
    %assign iv_j iv_j + 1
  %endrep
    ; the frame wiped: d, e, f, g (they derive from x)
    xor         eax, eax
    mov         ecx, IV_SIZE / 8
    mov         rdi, rsp
    rep         stosq
    add         rsp, IV_SIZE
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret

; =============================================================================
; Shared helpers (no field products): they work in the caller's frame (rbp) and keep rbp.
; =============================================================================

; -----------------------------------------------------------------------------
; p384_load_scalar: rsi = 48 big-endian octets -> PF_K (limbs) and PF_K2 (shifted up a bit).
; eax = 0 when 1 <= k < n, else -1 (both computed without a branch; the caller's branch on the
; answer shows only whether a key or a candidate nonce was in range). Clobbers rax, rcx, rdx,
; r8-r13, the flags.
; -----------------------------------------------------------------------------
align 16
p384_load_scalar:
    mov         r8, [rsi + 40]
    bswap       r8
    mov         r9, [rsi + 32]
    bswap       r9
    mov         r10, [rsi + 24]
    bswap       r10
    mov         r11, [rsi + 16]
    bswap       r11
    mov         r12, [rsi + 8]
    bswap       r12
    mov         r13, [rsi]
    bswap       r13
    mov         [rbp + PF_K], r8
    mov         [rbp + PF_K + 8], r9
    mov         [rbp + PF_K + 16], r10
    mov         [rbp + PF_K + 24], r11
    mov         [rbp + PF_K + 32], r12
    mov         [rbp + PF_K + 40], r13
    mov         rax, r8
    sub         rax, [rel p384_n]
    mov         rax, r9
    sbb         rax, [rel p384_n + 8]
    mov         rax, r10
    sbb         rax, [rel p384_n + 16]
    mov         rax, r11
    sbb         rax, [rel p384_n + 24]
    mov         rax, r12
    sbb         rax, [rel p384_n + 32]
    mov         rax, r13
    sbb         rax, [rel p384_n + 40]
    sbb         ecx, ecx                    ; all ones when k < n
    mov         rax, r8
    or          rax, r9
    or          rax, r10
    or          rax, r11
    or          rax, r12
    or          rax, r13
    neg         rax
    sbb         edx, edx                    ; all ones when k != 0
    and         ecx, edx
    call        p384_set_k2
    mov         eax, ecx
    not         eax
    HA_DECLASSIFY rax                       ; (public by design: a key or a candidate refused)
    ret

; -----------------------------------------------------------------------------
; p384_set_k2: PF_K2 = the scalar in r8..r13 shifted up one bit (seven qwords, and an eighth of
; zeros): what P384_DIGIT reads, Booth's bit -1 a zero below it. Keeps rcx; clobbers rax,
; r8-r13, the flags.
; -----------------------------------------------------------------------------
align 16
p384_set_k2:
    mov         qword [rbp + PF_K2 + 56], 0
    mov         rax, r13
    shr         rax, 63
    mov         [rbp + PF_K2 + 48], rax
    shld        r13, r12, 1
    mov         [rbp + PF_K2 + 40], r13
    shld        r12, r11, 1
    mov         [rbp + PF_K2 + 32], r12
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
; p384_wnaf: rsi = a scalar's six limbs (public), rdi = 392 octets, ecx = w (5 or 7) -> the
; scalar's width-w NAF, least significant digit first, as signed octets: every digit 0 or odd with
; |d| < 2^(w - 1), at most one nonzero among any w in a row, zeros past the last; rax = how many
; (the last one nonzero; 0 for a zero scalar; at most 385, as k - d can pass 2^384). The classic
; recoding (an odd k gives d = k mods 2^w and k -= d, leaving a multiple of 2^w), with each run of
; zero digits passed at once (bsf, or a whole zero limb). Variable time: for verification's public
; scalars only. Clobbers rax, rbx, rcx, rdx, rsi, r8-r15, the flags.
; -----------------------------------------------------------------------------
align 16
p384_wnaf:
    push        rdi
    push        rcx
    xor         eax, eax
    mov         ecx, 392
    rep         stosb
    pop         rcx
    pop         rdi
    mov         r8, [rsi]
    mov         r9, [rsi + 8]
    mov         r10, [rsi + 16]
    mov         r11, [rsi + 24]
    mov         r12, [rsi + 32]
    mov         r13, [rsi + 40]
    xor         r14d, r14d                  ; a seventh limb: k - d passes 2^384 for d < 0
    mov         r15d, 1
    shl         r15, cl                     ; 2^w
    xor         ebx, ebx                    ; the position k's bit 0 stands for
    xor         esi, esi                    ; the count: the last digit's position + 1
.next:
    mov         rax, r8
    or          rax, r9
    or          rax, r10
    or          rax, r11
    or          rax, r12
    or          rax, r13
    or          rax, r14
    jz          .done
    test        r8, r8
    jnz         .zeros
    mov         r8, r9                      ; a zero limb: 64 zero digits at once
    mov         r9, r10
    mov         r10, r11
    mov         r11, r12
    mov         r12, r13
    mov         r13, r14
    xor         r14d, r14d
    add         ebx, 64
    jmp         .next
.zeros:
    bsf         rcx, r8                     ; the run of zero digits below the next odd bit
    shrd        r8, r9, cl                  ; (bsf, not tzcnt: v1 runs this too)
    shrd        r9, r10, cl
    shrd        r10, r11, cl
    shrd        r11, r12, cl
    shrd        r12, r13, cl
    shrd        r13, r14, cl
    shr         r14, cl
    add         ebx, ecx
    lea         rax, [r15 - 1]
    and         rax, r8                     ; k mod 2^w (k is odd now)
    mov         rdx, r15
    shr         rdx, 1                      ; 2^(w - 1)
    cmp         rax, rdx
    jb          .digit
    sub         rax, r15                    ; 2^(w - 1) or more: the negative digit
.digit:
    mov         [rdi + rbx], al
    lea         esi, [rbx + 1]
    cqo                                     ; d's sign for the higher limbs
    sub         r8, rax
    sbb         r9, rdx
    sbb         r10, rdx
    sbb         r11, rdx
    sbb         r12, rdx
    sbb         r13, rdx
    sbb         r14, rdx                    ; k -= d: a multiple of 2^w now
    jmp         .next
.done:
    mov         eax, esi
    ret

; -----------------------------------------------------------------------------
; p384_load_point: rsi = 97 octets, SEC 1's uncompressed form 04 || x || y -> PX, PY (plain
; limbs). eax = 0 when the form is uncompressed and x, y are below p, else -1 (the curve
; equation is the caller's: P384_ON_CURVE). Clobbers rax, rsi, rdi, r8-r13, the flags.
; -----------------------------------------------------------------------------
align 16
p384_load_point:
    cmp         byte [rsi], 4
    jne         .bad
    lea         rdi, [rbp + PF_PX]
    inc         rsi
    call        p384_load_be_p
    jc          .bad
    lea         rdi, [rbp + PF_PY]
    call        p384_load_be_p
    jc          .bad
    xor         eax, eax
    ret
.bad:
    mov         eax, -1
    ret

; -----------------------------------------------------------------------------
; p384_load_be_p: 48 big-endian octets at rsi -> limbs at rdi; rsi += 48. CF set when the value is
; p or more (the subtraction of p does not borrow). Clobbers rax, r8-r13, the flags.
; -----------------------------------------------------------------------------
align 16
p384_load_be_p:
    mov         r8, [rsi + 40]
    bswap       r8
    mov         r9, [rsi + 32]
    bswap       r9
    mov         r10, [rsi + 24]
    bswap       r10
    mov         r11, [rsi + 16]
    bswap       r11
    mov         r12, [rsi + 8]
    bswap       r12
    mov         r13, [rsi]
    bswap       r13
    add         rsi, 48
    mov         [rdi], r8
    mov         [rdi + 8], r9
    mov         [rdi + 16], r10
    mov         [rdi + 24], r11
    mov         [rdi + 32], r12
    mov         [rdi + 40], r13
    sub         r8, [rel p384_p]
    sbb         r9, [rel p384_p + 8]
    sbb         r10, [rel p384_p + 16]
    sbb         r11, [rel p384_p + 24]
    sbb         r12, [rel p384_p + 32]
    sbb         r13, [rel p384_p + 40]
    cmc
    ret

; -----------------------------------------------------------------------------
; p384_store_be: the limbs at rsi -> 48 big-endian octets at rdi. Clobbers rax.
; -----------------------------------------------------------------------------
align 16
p384_store_be:
  %assign sb_q 0
  %rep 6
    mov         rax, [rsi + sb_q]
    bswap       rax
    mov         [rdi + 40 - sb_q], rax
    %assign sb_q sb_q + 8
  %endrep
    ret

; -----------------------------------------------------------------------------
; p384_load_digest: rsi = a digest, rdx = its length (public) -> PF_E = bits2int(digest) mod n
; (RFC 6979 2.3.2, FIPS 186-5 6.4.1: its leftmost 384 bits, or all of a shorter one, as a
; big-endian integer; then one subtraction of n, as e < 2^384 < 2n). Uses PF_T0. Clobbers rax,
; rbx, rcx, rdx, rsi, rdi, r8-r14, the flags.
; -----------------------------------------------------------------------------
align 16
p384_load_digest:
    xor         eax, eax
  %assign ld_q 0
  %rep 6
    mov         [rbp + PF_T0 + ld_q], rax
    %assign ld_q ld_q + 8
  %endrep
    mov         rcx, rdx
    cmp         rcx, 48
    jb          .short
    mov         ecx, 48
    lea         rdi, [rbp + PF_T0]
    jmp         .copy
.short:
    lea         rdi, [rbp + PF_T0 + 48]     ; right-aligned: zeros before it
    sub         rdi, rcx
.copy:
    rep         movsb
    lea         rsi, [rbp + PF_T0]
    lea         rdi, [rbp + PF_E]
    call        p384_load_be_p              ; (its CF, the comparison with p, is not wanted)
    P384_NREDUCE rbp + PF_E
    ret

; -----------------------------------------------------------------------------
; RFC 6979 3.2's HMAC_DRBG, HMAC-SHA384 always (RFC 6979's exactly when the digest is SHA-384's;
; any other digest still gets a sound deterministic nonce), over PF_KEY (K, 48 octets) and
; PF_SEED: V (48) at +0, then the separator octet (+48), x (the key's octets, +49), h1 =
; bits2octets(digest) (+97) and the entropy (+145). The calls into the C ABI need rsp 16-aligned:
; so p384_drbg_hmac is called only from the three routines below, and they only from a function's
; frame body (rsp = rbp, 64-aligned).
; -----------------------------------------------------------------------------

; p384_drbg_hmac: rcx = octets of PF_SEED, r8 = where the MAC goes: HMAC(K, SEED[0..rcx]).
; (httpasm_hmac_sha384 reads its key and data before it writes the MAC: K and V update in place.)
align 16
p384_drbg_hmac:
    lea         rdi, [rbp + PF_KEY]
    mov         esi, 48
    lea         rdx, [rbp + PF_SEED]
    call        httpasm_hmac_sha384
    ret

; p384_drbg_init: steps b-g: V = 0x01..., K = 0x00..., K = HMAC_K(V || 0x00 || x || h1 [|| k']),
; V = HMAC_K(V), K = HMAC_K(V || 0x01 || ...), V = HMAC_K(V).
align 16
p384_drbg_init:
    mov         rax, 0x0101010101010101
    xor         ecx, ecx
  %assign di_q 0
  %rep 6
    mov         [rbp + PF_SEED + di_q], rax
    mov         [rbp + PF_KEY + di_q], rcx
    %assign di_q di_q + 8
  %endrep
    mov         byte [rbp + PF_SEED + 48], 0
    mov         rcx, [rbp + PF_SEEDN]
    lea         r8, [rbp + PF_KEY]
    call        p384_drbg_hmac
    mov         ecx, 48
    lea         r8, [rbp + PF_SEED]
    call        p384_drbg_hmac
    mov         byte [rbp + PF_SEED + 48], 1
    mov         rcx, [rbp + PF_SEEDN]
    lea         r8, [rbp + PF_KEY]
    call        p384_drbg_hmac
    mov         ecx, 48
    lea         r8, [rbp + PF_SEED]
    call        p384_drbg_hmac
    ret

; p384_drbg_next: step h: V = HMAC_K(V), the candidate k (its 48 octets at PF_SEED; qlen = 384 =
; the HMAC's output, so one block).
align 16
p384_drbg_next:
    mov         ecx, 48
    lea         r8, [rbp + PF_SEED]
    call        p384_drbg_hmac
    ret

; p384_drbg_reject: step h.3, after a candidate out of range or a zero r or s: K = HMAC_K(V ||
; 0x00), V = HMAC_K(V).
align 16
p384_drbg_reject:
    mov         byte [rbp + PF_SEED + 48], 0
    mov         ecx, 49
    lea         r8, [rbp + PF_KEY]
    call        p384_drbg_hmac
    mov         ecx, 48
    lea         r8, [rbp + PF_SEED]
    call        p384_drbg_hmac
    ret

; =============================================================================
; P384_ROUTINES F, v: every routine of one version (F = F6X or F6Q, v = v3 or v1). The point
; routines work on the frame of the function that calls them (rbp) and clobber every register but
; rbp and rsp.
; =============================================================================
%macro P384_ROUTINES 2

; p384_dbl_v: ACC = 2 ACC.
align 16
p384_dbl_%2:
    P384_DBL    %1
    ret

; p384_add_raw_v, p384_madd_raw_v: the formulas alone, R = ACC + IN (P384_ADD, P384_MADD), for
; callers that settle infinity and the equal points themselves: the constant-time additions below
; by mask, the verification's variable-time ones by branch.
align 16
p384_add_raw_%2:
    P384_ADD    %1
    ret

align 16
p384_madd_raw_%2:
    P384_MADD   %1
    ret

; p384_add_v: ACC = ACC + IN (Jacobian), either input infinity handled by the selection; H and r
; left in T3 and T5.
align 16
p384_add_%2:
    call        p384_add_raw_%2
    P384_IS_ZERO r13, S_AZ
    P384_IS_ZERO r14, S_IZ
    P384_SELECT_RESULT r13, r14
    ret

; p384_madd_v: ACC = ACC + IN (affine, IZ = 1 set by the caller for the selection); IN is
; infinity when x = y = 0 (no curve point has them: the scan's zeros, which a negative digit
; leaves zeros, F6_CNEG mapping 0 to 0).
align 16
p384_madd_%2:
    call        p384_madd_raw_%2
    P384_IS_ZERO r13, S_AZ
    mov         r14, [rbp + PF_IX]
  %assign mz_q 8
  %rep 11
    or          r14, [rbp + PF_IX + mz_q]   ; x's and y's twelve qwords
    %assign mz_q mz_q + 8
  %endrep
    neg         r14
    sbb         r14, r14
    not         r14
    P384_SELECT_RESULT r13, r14
    ret

; p384_vadd_v: ACC = ACC + IN, IN Jacobian and never infinity, in variable time (verification's
; public points only): ACC at infinity takes IN; after the addition, H = 0 means the same x: the
; same point (r = 0 too) doubles IN, the opposite one gives infinity. The constant-time addition
; above handles neither, as the scalar multiplications never meet them; Straus's pass can.
align 16
p384_vadd_%2:
    P384_IS_ZERO rax, S_AZ
    test        rax, rax
    jnz         .take
    call        p384_add_raw_%2
    P384_IS_ZERO rax, S_T3                  ; H = 0?
    test        rax, rax
    jz          .sum
    P384_IS_ZERO rax, S_T5                  ; r = 0?
    test        rax, rax
    jz          .cancel
    P384_COPY   S_AX, S_IX, 18
    jmp         p384_dbl_%2                 ; (a tail call: it returns to our caller)
.cancel:
    xor         eax, eax
    mov         ecx, 18
    lea         rdi, [rbp + PF_AX]
    rep         stosq
    ret
.sum:
    P384_COPY   S_AX, S_RX, 18
    ret
.take:
    P384_COPY   S_AX, S_IX, 18
    ret

; p384_vmadd_v: p384_vadd_v's cases with IN affine (IX, IY; IZ = 1 set by the caller): the mixed
; addition leaves H in T1 and r in T2.
align 16
p384_vmadd_%2:
    P384_IS_ZERO rax, S_AZ
    test        rax, rax
    jnz         .take
    call        p384_madd_raw_%2
    P384_IS_ZERO rax, S_T1                  ; H = 0?
    test        rax, rax
    jz          .sum
    P384_IS_ZERO rax, S_T2                  ; r = 0?
    test        rax, rax
    jz          .cancel
    P384_COPY   S_AX, S_IX, 18
    jmp         p384_dbl_%2
.cancel:
    xor         eax, eax
    mov         ecx, 18
    lea         rdi, [rbp + PF_AX]
    rep         stosq
    ret
.sum:
    P384_COPY   S_AX, S_RX, 18
    ret
.take:
    P384_COPY   S_AX, S_IX, 18
    ret

; p384_affine_v: PX, PY = ACC in affine coordinates, plain (out of Montgomery form), ACC not
; infinity. Z's inverse comes plain from p384_inverse ((Z R)^-1 = Z^-1 R^-1), and a product by
; R^3 mod p takes it to Z^-1 R, its Montgomery form.
align 16
p384_affine_%2:
    P384_COPY   S_ZI, S_AZ, 6
    lea         rdi, [rbp + PF_ZI]
    lea         rsi, [rel p384_mod_p]
    call        p384_inverse
    %1_FMUL     S_ZI, S_ZI, rel p384_r3
    %1_FSQR     S_T0, S_ZI                  ; Z^-2
    %1_FMUL     S_PX, S_AX, S_T0
    %1_FMUL     S_T0, S_T0, S_ZI            ; Z^-3
    %1_FMUL     S_PY, S_AY, S_T0
    %1_FMUL     S_PX, S_PX, rel p384_int1   ; out of the form
    %1_FMUL     S_PY, S_PY, rel p384_int1
    ret

; p384_mul_var_v: ACC = k P, k from PF_K2 (1 <= k < n), P affine (Montgomery form) in PX, PY.
; The table TAB[j] = (j + 1) P: (2j + 2) P by doubling (j + 1) P, (2j + 3) P by adding P to it.
; Then the top window (76: bits 379..383, a digit never negative) selects the start, and each
; window below doubles five times and adds its digit's point.
align 16
p384_mul_var_%2:
    P384_COPY   rbp + PF_TAB, S_PX, 6
    P384_COPY   rbp + PF_TAB + 48, S_PY, 6
    P384_COPY   rbp + PF_TAB + 96, rel p384_one, 6
    P384_COPY   S_IX, rbp + PF_TAB, 18      ; IN = P for the odd multiples
    mov         qword [rbp + PF_WIN], 0
.table:
    imul        rdx, [rbp + PF_WIN], 144
    P384_COPY   S_AX, rbp + PF_TAB + rdx, 18        ; (j + 1) P
    call        p384_dbl_%2
    imul        rdx, [rbp + PF_WIN], 288
    P384_COPY   rbp + PF_TAB + 144 + rdx, S_AX, 18  ; (2j + 2) P
    cmp         qword [rbp + PF_WIN], 7
    je          .table_done
    call        p384_add_%2
    imul        rdx, [rbp + PF_WIN], 288
    P384_COPY   rbp + PF_TAB + 288 + rdx, S_AX, 18  ; (2j + 3) P
    inc         qword [rbp + PF_WIN]
    jmp         .table
.table_done:
    mov         ecx, 76
    P384_DIGIT  5
    P384_SCAN_TAB_%2
    P384_COPY   S_AX, S_IX, 18              ; the start (zeros, infinity, for digit 0)
    mov         dword [rbp + PF_WIN], 75
.window:
    call        p384_dbl_%2
    call        p384_dbl_%2
    call        p384_dbl_%2
    call        p384_dbl_%2
    call        p384_dbl_%2
    mov         ecx, [rbp + PF_WIN]
    P384_DIGIT  5
    mov         [rbp + PF_SIGN], r12
    P384_SCAN_TAB_%2
    mov         r15, [rbp + PF_SIGN]
    F6_CNEG     r15, S_IY, rel p384_p
    call        p384_add_%2
    dec         dword [rbp + PF_WIN]
    jns         .window
    ret

; p384_mul_base_v: ACC = k G, k from PF_K2 (0 <= k < n: 0 gives infinity). Window i's digit
; selects from its own table, the sign negates y, and one mixed addition joins it.
align 16
p384_mul_base_%2:
    xor         eax, eax
    mov         ecx, 18
    lea         rdi, [rbp + PF_AX]
    rep         stosq                       ; ACC = infinity
    P384_COPY   S_IZ, rel p384_one, 6       ; the affine addend's Z for the selection
    mov         dword [rbp + PF_WIN], 0
.window:
    mov         ecx, [rbp + PF_WIN]
    P384_DIGIT  P384_W
    mov         [rbp + PF_SIGN], r12
    imul        eax, [rbp + PF_WIN], 96 << (P384_W - 1)   ; 2^(W - 1) points of 96 octets a window
    lea         rsi, [rel p384_base_table]
    add         rsi, rax
    P384_SCAN_BASE_%2
    mov         r15, [rbp + PF_SIGN]
    F6_CNEG     r15, S_IY, rel p384_p
    call        p384_madd_%2
    inc         dword [rbp + PF_WIN]
    cmp         dword [rbp + PF_WIN], P384_WINDOWS
    jne         .window
    ret

; -----------------------------------------------------------------------------
; int p384_public_key_v(uint8_t out[97], const uint8_t key[48]): httpasm_p384_public_key.
; -----------------------------------------------------------------------------
align 16
p384_public_key_%2:
    P384_ENTER
    mov         [rbp + PF_OUT], rdi
    call        p384_load_scalar
    test        eax, eax
    jnz         .invalid
    call        p384_mul_base_%2
    call        p384_affine_%2
    mov         rdi, [rbp + PF_OUT]
    mov         byte [rdi], 4               ; SEC 1's uncompressed form
    inc         rdi
    lea         rsi, [S_PX]
    call        p384_store_be
    mov         rdi, [rbp + PF_OUT]
    add         rdi, 49
    lea         rsi, [S_PY]
    call        p384_store_be
    mov         qword [rbp + PF_RES], 0
    jmp         .done
.invalid:
    mov         rdi, [rbp + PF_OUT]
    xor         eax, eax
    mov         ecx, HTTPASM_P384_POINT
    rep         stosb
    mov         qword [rbp + PF_RES], -1
.done:
    P384_FINISH

; -----------------------------------------------------------------------------
; int p384_ecdh_v(uint8_t out[48], const uint8_t key[48], const uint8_t point[97]):
; httpasm_p384_ecdh.
; -----------------------------------------------------------------------------
align 16
p384_ecdh_%2:
    P384_ENTER
    mov         [rbp + PF_OUT], rdi
    mov         [rbp + PF_ARG], rdx
    call        p384_load_scalar
    test        eax, eax
    jnz         .invalid
    mov         rsi, [rbp + PF_ARG]
    call        p384_load_point
    test        eax, eax
    jnz         .invalid
    P384_ON_CURVE %1
    call        p384_mul_var_%2
    call        p384_affine_%2              ; (never infinity: k in [1, n), the point's order n)
    mov         rdi, [rbp + PF_OUT]
    lea         rsi, [S_PX]
    call        p384_store_be
    mov         qword [rbp + PF_RES], 0
    jmp         .done
.invalid:
    mov         rdi, [rbp + PF_OUT]
    xor         eax, eax
    mov         ecx, HTTPASM_P384_SCALAR
    rep         stosb
    mov         qword [rbp + PF_RES], -1
.done:
    P384_FINISH

; -----------------------------------------------------------------------------
; int p384_sign_v(uint8_t signature[96], const uint8_t key[48], const uint8_t *digest,
;                 size_t length, const uint8_t *entropy): httpasm_p384_sign.
; -----------------------------------------------------------------------------
align 16
p384_sign_%2:
    P384_ENTER
    mov         [rbp + PF_OUT], rdi
    mov         [rbp + PF_ARG], rsi
    mov         [rbp + PF_ARG2], rdx
    mov         [rbp + PF_ARG3], rcx
    mov         [rbp + PF_ARG4], r8
    call        p384_load_scalar
    test        eax, eax
    jnz         .invalid
    P384_COPY   rbp + PF_D, rbp + PF_K, 6
    mov         rsi, [rbp + PF_ARG]
    P384_COPY   rbp + PF_SEED + 49, rsi, 6  ; x = int2octets(d): the key's own octets
    mov         rsi, [rbp + PF_ARG2]
    mov         rdx, [rbp + PF_ARG3]
    call        p384_load_digest
    lea         rdi, [rbp + PF_SEED + 97]
    lea         rsi, [rbp + PF_E]
    call        p384_store_be               ; h1 = bits2octets(digest) = int2octets(e)
    mov         qword [rbp + PF_SEEDN], 145
    mov         rsi, [rbp + PF_ARG4]
    test        rsi, rsi
    jz          .seeded
    P384_COPY   rbp + PF_SEED + 145, rsi, 6 ; RFC 6979 3.6's k': the caller's entropy
    mov         qword [rbp + PF_SEEDN], 193
.seeded:
    call        p384_drbg_init
.candidate:
    call        p384_drbg_next
    lea         rsi, [rbp + PF_SEED]
    call        p384_load_scalar            ; k, when 1 <= k < n
    test        eax, eax
    jnz         .retry
    call        p384_mul_base_%2
    call        p384_affine_%2
    P384_COPY   rbp + PF_R, S_PX, 6
    P384_NREDUCE rbp + PF_R                 ; r = x mod n
    P384_IS_ZERO rax, rbp + PF_R
    HA_DECLASSIFY rax                       ; (public by design: r = 0 draws again)
    test        rax, rax
    jnz         .retry
    P384_COPY   rbp + PF_KINV, rbp + PF_K, 6
    lea         rdi, [rbp + PF_KINV]
    lea         rsi, [rel p384_mod_n]
    call        p384_inverse                ; k^-1, plain
    ; s = k^-1 (e + r d): Montgomery products modulo n, each followed by one by R^2 (a b R^-1,
    ; then times R^2 R^-1: the plain product)
    F6_NMUL     rbp + PF_S, rbp + PF_R, rbp + PF_D
    F6_NMUL     rbp + PF_S, rbp + PF_S, rel p384_n_r2      ; r d
    F6_NADD     rbp + PF_S, rbp + PF_S, rbp + PF_E          ; e + r d
    F6_NMUL     rbp + PF_S, rbp + PF_S, rbp + PF_KINV
    F6_NMUL     rbp + PF_S, rbp + PF_S, rel p384_n_r2      ; s
    P384_IS_ZERO rax, rbp + PF_S
    HA_DECLASSIFY rax                       ; (public by design: s = 0 draws again)
    test        rax, rax
    jnz         .retry
    mov         rdi, [rbp + PF_OUT]
    lea         rsi, [rbp + PF_R]
    call        p384_store_be
    mov         rdi, [rbp + PF_OUT]
    add         rdi, 48
    lea         rsi, [rbp + PF_S]
    call        p384_store_be
    mov         qword [rbp + PF_RES], 0
    jmp         .done
.retry:
    call        p384_drbg_reject
    jmp         .candidate
.invalid:
    mov         rdi, [rbp + PF_OUT]
    xor         eax, eax
    mov         ecx, HTTPASM_P384_SIGNATURE
    rep         stosb
    mov         qword [rbp + PF_RES], -1
.done:
    P384_FINISH

; -----------------------------------------------------------------------------
; int p384_verify_v(const uint8_t key[97], const uint8_t *digest, size_t length,
;                   const uint8_t signature[96]): httpasm_p384_verify. Every input is public:
; the branches below may follow them.
; -----------------------------------------------------------------------------
align 16
p384_verify_%2:
    P384_ENTER
    mov         [rbp + PF_ARG], rdi
    mov         [rbp + PF_ARG2], rsi
    mov         [rbp + PF_ARG3], rdx
    mov         [rbp + PF_ARG4], rcx
    mov         rsi, rcx
    call        p384_load_scalar            ; r in [1, n)
    test        eax, eax
    jnz         .invalid
    P384_COPY   rbp + PF_R, rbp + PF_K, 6
    mov         rsi, [rbp + PF_ARG4]
    add         rsi, 48
    call        p384_load_scalar            ; s in [1, n)
    test        eax, eax
    jnz         .invalid
    P384_COPY   rbp + PF_S, rbp + PF_K, 6
    mov         rsi, [rbp + PF_ARG]
    call        p384_load_point
    test        eax, eax
    jnz         .invalid
    P384_ON_CURVE %1
    mov         rsi, [rbp + PF_ARG2]
    mov         rdx, [rbp + PF_ARG3]
    call        p384_load_digest
    lea         rdi, [rbp + PF_S]
    lea         rsi, [rel p384_mod_n]
    call        p384_inverse                ; w = s^-1
    F6_NMUL     rbp + PF_U1, rbp + PF_E, rbp + PF_S
    F6_NMUL     rbp + PF_U1, rbp + PF_U1, rel p384_n_r2    ; u1 = e w
    F6_NMUL     rbp + PF_U2, rbp + PF_R, rbp + PF_S
    F6_NMUL     rbp + PF_U2, rbp + PF_U2, rel p384_n_r2    ; u2 = r w
    ; R = u1 G + u2 Q in one pass from the top (Straus): wNAF digits (u1 by 7 bits: G's odd
    ; multiples are in the fixed-base table's window 0, 1G..64G; u2 by 5 bits over Q's odd
    ; multiples 1Q..15Q, built here), the doublings shared; variable time, as every input is
    ; public, so the additions branch on the doubling and cancelling cases
    lea         rsi, [rbp + PF_U1]
    lea         rdi, [rbp + PF_DIG1]
    mov         ecx, 7
    call        p384_wnaf
    mov         [rbp + PF_LEN1], rax
    lea         rsi, [rbp + PF_U2]
    lea         rdi, [rbp + PF_DIG2]
    mov         ecx, 5
    call        p384_wnaf
    mov         [rbp + PF_LEN2], rax
    ; Q's odd multiples into TAB: Q, then 2Q into IN, then Q + 2Q, 3Q + 2Q, ... 13Q + 2Q (none of
    ; these additions meets equal or opposite points: (2j + 1) Q = +-2Q has no solution mod n)
    P384_COPY   S_AX, S_PX, 12
    P384_COPY   S_AZ, rel p384_one, 6
    P384_COPY   rbp + PF_TAB, S_AX, 18
    call        p384_dbl_%2
    P384_COPY   S_IX, S_AX, 18              ; IN = 2Q
    P384_COPY   S_AX, rbp + PF_TAB, 18      ; ACC = Q
    mov         qword [rbp + PF_WIN], 1
.odd:
    call        p384_add_%2                 ; (2j + 1) Q
    imul        rdx, [rbp + PF_WIN], 144
    P384_COPY   rbp + PF_TAB + rdx, S_AX, 18
    inc         qword [rbp + PF_WIN]
    cmp         qword [rbp + PF_WIN], 8
    jne         .odd
    ; the pass: from the longer wNAF's top digit (nonzero by its length) down; the accumulator
    ; starts at infinity, so its first doubling is skipped
    xor         eax, eax
    mov         ecx, 18
    lea         rdi, [rbp + PF_AX]
    rep         stosq
    mov         rax, [rbp + PF_LEN1]
    cmp         rax, [rbp + PF_LEN2]
    cmovb       rax, [rbp + PF_LEN2]
    dec         rax
    mov         [rbp + PF_WIN], rax
    jmp         .digits                     ; (u2 is not 0: its wNAF has at least one digit)
.pass:
    call        p384_dbl_%2
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
    imul        edx, edx, 96
    lea         rsi, [rel p384_base_table]
    add         rsi, rdx
    P384_COPY   S_IX, rsi, 12
    P384_COPY   S_IZ, rel p384_one, 6
    mov         r15, [rbp + PF_SIGN]
    sar         r15, 63                     ; all ones for a negative digit
    F6_CNEG     r15, S_IY, rel p384_p
    call        p384_vmadd_%2
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
    imul        edx, edx, 144
    P384_COPY   S_IX, rbp + PF_TAB + rdx, 18
    mov         r15, [rbp + PF_SIGN]
    sar         r15, 63
    F6_CNEG     r15, S_IY, rel p384_p
    call        p384_vadd_%2
.next:
    dec         qword [rbp + PF_WIN]
    jns         .pass
    ; R at infinity (u1 G = -u2 Q, or a cancellation the pass met and never left): no x to
    ; compare, and (0, 0, 0) would pass X = r Z^2 below and accept a forgery
    P384_IS_ZERO rax, S_AZ
    test        rax, rax
    jnz         .invalid
    ; x(R) mod n = r without the inversion: X = r Z^2, or X = (r + n) Z^2 when r + n < p (x < p
    ; < 2n: those are the only x with x mod n = r)
    %1_FSQR     S_T0, S_AZ
    %1_FMUL     S_T1, rbp + PF_R, rel p384_r2
    %1_FMUL     S_T2, S_T1, S_T0
    P384_DIFFER S_T2, S_AX
    jz          .valid
    F6_LOAD     rbp + PF_R
    mov         rax, r8
    sub         rax, [rel p384_n_p]
    mov         rax, r9
    sbb         rax, [rel p384_n_p + 8]
    mov         rax, r10
    sbb         rax, [rel p384_n_p + 16]
    mov         rax, r11
    sbb         rax, [rel p384_n_p + 24]
    mov         rax, r12
    sbb         rax, [rel p384_n_p + 32]
    mov         rax, r13
    sbb         rax, [rel p384_n_p + 40]
    jnc         .invalid                    ; r >= p - n: r + n is no field element
    add         r8, [rel p384_n]
    adc         r9, [rel p384_n + 8]
    adc         r10, [rel p384_n + 16]
    adc         r11, [rel p384_n + 24]
    adc         r12, [rel p384_n + 32]
    adc         r13, [rel p384_n + 40]
    F6_STORE    S_T1
    %1_FMUL     S_T1, S_T1, rel p384_r2
    %1_FMUL     S_T2, S_T1, S_T0
    P384_DIFFER S_T2, S_AX
    jnz         .invalid
.valid:
    mov         qword [rbp + PF_RES], 0
    jmp         .done
.invalid:
    mov         qword [rbp + PF_RES], -1
.done:
    P384_FINISH
%endmacro

P384_ROUTINES F6X, v3
P384_ROUTINES F6Q, v1

; =============================================================================
; The C ABI: each picks v3 (BMI2, ADX and AVX2) or v1 and jumps there (tail calls: the version
; returns to our caller). httpasm.h says what each does.
; =============================================================================

; -----------------------------------------------------------------------------
; int httpasm_p384_public_key(uint8_t public_key[97], const uint8_t private_key[48])
; -----------------------------------------------------------------------------
global httpasm_p384_public_key:function (httpasm_p384_public_key.end - httpasm_p384_public_key)
align 16
httpasm_p384_public_key:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         p384_public_key_v1
.v3:
    jmp         p384_public_key_v3
.end:

; -----------------------------------------------------------------------------
; int httpasm_p384_ecdh(uint8_t shared[48], const uint8_t private_key[48],
;                       const uint8_t peer_key[97])
; -----------------------------------------------------------------------------
global httpasm_p384_ecdh:function (httpasm_p384_ecdh.end - httpasm_p384_ecdh)
align 16
httpasm_p384_ecdh:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         p384_ecdh_v1
.v3:
    jmp         p384_ecdh_v3
.end:

; -----------------------------------------------------------------------------
; int httpasm_p384_sign(uint8_t signature[96], const uint8_t private_key[48],
;                       const uint8_t *digest, size_t digest_length, const uint8_t *entropy)
; -----------------------------------------------------------------------------
global httpasm_p384_sign:function (httpasm_p384_sign.end - httpasm_p384_sign)
align 16
httpasm_p384_sign:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         p384_sign_v1
.v3:
    jmp         p384_sign_v3
.end:

; -----------------------------------------------------------------------------
; int httpasm_p384_verify(const uint8_t public_key[97], const uint8_t *digest,
;                         size_t digest_length, const uint8_t signature[96])
; -----------------------------------------------------------------------------
global httpasm_p384_verify:function (httpasm_p384_verify.end - httpasm_p384_verify)
align 16
httpasm_p384_verify:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         p384_verify_v1
.v3:
    jmp         p384_verify_v3
.end:
