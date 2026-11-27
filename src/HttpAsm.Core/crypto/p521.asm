; =============================================================================
; crypto/p521.asm - NIST P-521 (SP 800-186 3.2.1.5; TLS's secp521r1): the C ABI's
; httpasm_p521_public_key (d G), httpasm_p521_ecdh (the shared secret of TLS 1.3's secp521r1 key
; share), httpasm_p521_sign and httpasm_p521_verify (ECDSA, FIPS 186-5 6.4: TLS 1.3's
; ecdsa_secp521r1_sha512, the last group and signature scheme of RFC 9846's lists that M2 needed).
;
; crypto/p384.asm's twin: the same formulas, recodings, scans, selections and checks (its header
; and crypto/p256.asm's have each one's reasoning), over include/crypto/p521.inc's field: nine
; 64-bit limbs, PLAIN values (p = 2^521 - 1 reduces a product by its form, not by Montgomery),
; fully reduced; the products are called routines (p521_fmul_v3 and the others below), v3 with
; mulx and adcx/adox, v1 with mul; one version is chosen per call. Points in Jacobian
; coordinates (X, Y, Z), the point at infinity as Z = 0 (all zeros); a point's slot is 224 octets
; (three 72-octet values and 8 of padding, so table rows stay 16- and 32-aligned for the scans):
;   - doubling: OpenSSL's arrangement for a = -3 (4M + 4S, one halving: a rotation here);
;   - addition add-2007-bl (11M + 5S), mixed addition madd-2007-bl (7M + 4S); infinity handled by
;     selection masks; the doublings by 2, 4 and 8 inside them are rotations of the 521-bit
;     string (p521.inc's F9_ROTL), not additions.
; The scalar multiplications, constant time (every digit read by mask over all the table):
;   - variable base (ECDH): Booth digits of 5 bits, 105 windows from the top (bits 5i - 1 ..
;     5i + 4; the top window, bits 519..524, is never negative), a table of 1P..16P in Jacobian
;     coordinates, then 5 doublings and one addition a window;
;   - fixed base (public keys, signatures): Booth digits of 6 bits (not P-384's 7: that table
;     would be 691,200 octets), 87 windows, each with its own table of m 2^(6i) G (m = 1..32,
;     affine: 400,896 octets, generated and proven by specs/p521.cs), one mixed addition a window,
;     no doubling.
;
; The doubling case. P-256's argument (no addition of a constant-time multiplication meets equal
; points for k in [1, n - 1]) holds for the fixed base here (the partial sums of the windows
; below window i are below 2^(6i - 1) in magnitude, the addend at least 2^(6i); at the top window
; only k >= 2^521 + 2^260 could meet it, and k < n). It does NOT hold for the variable base's
; LAST addition: there the accumulator is (k - d0) P and the addend d0 P, equal when
; k = 2 d0 (mod n) with k - d0 a multiple of 32; for d0 < 0 that is k = n + 2 d0 with d0 = -n
; (mod 32), and P-521's n is 9 (mod 32), so d0 = -9 and k = n - 18 meets it (P-256's and P-384's
; n give d0 = -17 and -19, outside Booth's [-16, 16], which is why their code needs nothing).
; The add-2007-bl formulas give garbage there (H = r = 0, Z3 = 0), so the last addition is
; p521_add_last: it also doubles the addend and takes that by mask when H and r are both 0 and
; neither input is at infinity (scratchpad model p521/model.py found n - 18 as the only such k,
; and the tests run it). No other window can meet it: there the accumulator is a multiple of 32
; below n, the addend of magnitude 16 or less.
;
; The inversion (to affine, and ECDSA's k^-1 and s^-1): crypto/p384.asm's divsteps (Bernstein and
; Yang, original divsteps from delta = 1, libsecp256k1's modinv64 arrangement), constant time, one
; routine for p and n, at nine signed 62-bit limbs (558 bits) and 25 batches of 62: Theorem 11.2's
; bound for inputs below 2^521 is floor((49 521 + 57) / 17) = 1505 divsteps (25 62 = 1550).
;
; ECDSA. Signing draws k from RFC 6979's HMAC-DRBG with HMAC-SHA512 always (RFC 6979's own k
; whenever the digest is SHA-512's, as ecdsa_secp521r1_sha512's is: qlen = 521, hlen = 512, so a
; candidate is two HMAC blocks, k their first 66 octets shifted right 7), the caller's entropy as
; RFC 6979 3.6's extra input when given, and draws again in the cases no one will meet (k >= n,
; r = 0, s = 0). Verification (every input public, so variable time): u1 G + u2 Q in one pass from
; the top (Straus), wNAF digits, u1's by 6 bits over the fixed-base table's window 0 (1G..32G),
; u2's by 5 bits over 1Q, 3Q, ..15Q built per call; the additions branch on infinity and on equal
; and opposite points. Then x(R) against r without an inversion: X = r Z^2, or X = (r + n) Z^2
; when r + n < p. A digest of 66 octets or more gives its leftmost 521 bits (bits2int), a shorter
; one all of its bits.
;
; Validation: a public key must be 133 octets of SEC 1's uncompressed form (04, x, y), x and y
; below p, on the curve (RFC 9846 4.2.8.2; it also rules out the invalid-curve attack); a private
; key, r and s must be in [1, n - 1] (66 big-endian octets: anything with bits above 520 is n or
; more).
; =============================================================================
default rel
%include "httpasm_core.inc"

extern httpasm_hmac_sha512                  ; crypto/hmac.asm: RFC 6979's HMAC (one-shot)

section .rodata
%include "generated/p521_table.inc"

section .text

; -----------------------------------------------------------------------------
; The frame every routine of a call shares, addressed off rbp (the products take every register
; but rbp and rsp, and keep their scratch here: F9_SCR, F9_NT). 64-aligned; field values are 72
; octets; points are 224-octet slots (X, Y, Z and 8 octets of padding), so TAB's rows start on 32
; octets. Everything below PF_END is wiped before a function returns (keys, nonces, every
; intermediate point and every product's scratch).
; -----------------------------------------------------------------------------
PF_AX       equ 0                           ; the accumulator, Jacobian (X, Y, Z)
PF_AY       equ 72
PF_AZ       equ 144
PF_IX       equ 224                         ; the addend: Jacobian, or affine with IZ = 1
PF_IY       equ 296
PF_IZ       equ 368
PF_RX       equ 448                         ; an addition's result before the selection
PF_RY       equ 520
PF_RZ       equ 592
PF_T0       equ 672                         ; eleven temporaries
PF_T1       equ 744
PF_T2       equ 816
PF_T3       equ 888                         ; (the addition leaves H here)
PF_T4       equ 960
PF_T5       equ 1032                        ; (and r here)
PF_T6       equ 1104
PF_T7       equ 1176
PF_T8       equ 1248
PF_T9       equ 1320
PF_T10      equ 1392
PF_TAB      equ 1472                        ; the variable base's table: 16 points of 224 octets
PF_PX       equ 5056                        ; an input point (affine), later the output's
PF_PY       equ 5128                        ; coordinates (affine)
PF_ZI       equ 5200                        ; the value being inverted
PF_K2       equ 5272                        ; the scalar shifted up one bit: nine qwords, and a
                                            ; tenth of zeros, which the digits' reads may touch
PF_K        equ 5352                        ; the scalar: nine qwords
PF_WIN      equ 5424                        ; the window number
PF_SIGN     equ 5432                        ; the digit's sign as a mask
PF_OUT      equ 5440                        ; the output's address
PF_ARG      equ 5448                        ; inputs' addresses and lengths
PF_RES      equ 5456                        ; the result to return
PF_ARG2     equ 5464
PF_ARG3     equ 5472
PF_ARG4     equ 5480
PF_SEEDN    equ 5488                        ; RFC 6979's seeding length: 197, or 263 with entropy
PF_LEN1     equ 5496                        ; verification: u1's wNAF digits (how many)
PF_LEN2     equ 5504                        ; verification: u2's wNAF digits (how many)
PF_DBLM     equ 5512                        ; p521_add_last: the doubling case, as a mask
PF_E        equ 5520                        ; ECDSA's scalars, nine limbs: e = bits2int mod n
PF_D        equ 5592                        ; the private key
PF_R        equ 5664                        ; r
PF_S        equ 5736                        ; s (verification: then w = s^-1)
PF_KINV     equ 5808                        ; k^-1
PF_U1       equ 5880                        ; u1 = e w, u2 = r w
PF_U2       equ 5952
PF_KEY      equ 6024                        ; RFC 6979's K (64 octets)
PF_SEED     equ 6088                        ; V || separator || x || h1 || entropy (263 of 272)
PF_TT       equ 6360                        ; a candidate's 66 octets (two HMAC blocks' first)
PF_SCR      equ 6432                        ; the products' scratch (88 octets: p521.inc)
PF_NT       equ 6520                        ; the scalars' Montgomery window (160 octets)
PF_DIG1     equ 6680                        ; u1's wNAF digits, signed octets (528)
PF_DIG2     equ 7208                        ; u2's (528)
PF_END      equ 7736                        ; (wiped up to here)
PF_OLDSP    equ 7736                        ; the caller's rsp (after the six pushes)
PF_FRAME    equ 7744                        ; a multiple of 64

%define F9_SCR rbp + PF_SCR
%define F9_NT rbp + PF_NT
%include "crypto/p521.inc"

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

; P521_COPY dst, src, qwords: memory to memory through rax (no flags).
%macro P521_COPY 3
  %assign c_q 0
  %rep %3
    mov         rax, [%2 + c_q]
    mov         [%1 + c_q], rax
    %assign c_q c_q + 8
  %endrep
%endmacro

; P521_ENTER / P521_LEAVE: the six kept registers pushed, the 64-aligned frame at rbp (the
; caller's rsp kept above PF_END, so the wipe leaves it); keeps rdi, rsi, rdx, rcx, r8, r9, r10.
; The frame passes a page, so it is taken a page at a time (HA_STACK_DOWN, counting in r11: no
; stack clash).
%macro P521_ENTER 0
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
%macro P521_LEAVE 0
    mov         rsp, [rbp + PF_OLDSP]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
%endmacro

; P521_FINISH: the return: eax = PF_RES's low dword after the frame below PF_END is wiped (it
; held the key or the nonce, the tables, every intermediate point, the products' scratch), then
; P521_LEAVE and ret.
%macro P521_FINISH 0
    mov         r8, [rbp + PF_RES]
    xor         eax, eax
    mov         ecx, PF_END / 8
    mov         rdi, rbp
    rep         stosq
    mov         eax, r8d
    P521_LEAVE
    ret
%endmacro

; P521_IS_ZERO reg, slot: reg = all ones when the slot's nine qwords are 0, else 0 (no branch).
%macro P521_IS_ZERO 2
    mov         %1, [%2]
    or          %1, [%2 + 8]
    or          %1, [%2 + 16]
    or          %1, [%2 + 24]
    or          %1, [%2 + 32]
    or          %1, [%2 + 40]
    or          %1, [%2 + 48]
    or          %1, [%2 + 56]
    or          %1, [%2 + 64]
    neg         %1                          ; CF = nonzero
    sbb         %1, %1
    not         %1
%endmacro

; P521_DIFFER a, b: ZF clear when the nine qwords at a and b differ (an OR of their XORs: one
; decision; for public values only, as the caller branches on it). Clobbers rax, rcx.
%macro P521_DIFFER 2
    mov         rax, [%1]
    xor         rax, [%2]
  %assign d_q 8
  %rep 8
    mov         rcx, [%1 + d_q]
    xor         rcx, [%2 + d_q]
    or          rax, rcx
    %assign d_q d_q + 8
  %endrep
%endmacro

; P521_DIGIT w: ecx = window number i (public) -> edx = the magnitude of the window's Booth digit
; (0..2^(w - 1)), r12 = its sign as a mask (all ones when negative). The window is bits
; w i - 1 .. w i + w - 1 of the scalar, read as bits w i .. w i + w of PF_K2 (the scalar shifted up
; one bit); the qword and the shift follow i alone. Booth (OpenSSL's booth_recode_w5/w7): s =
; -(v >> w); d = s ? 2^(w + 1) - 1 - v : v; magnitude (d >> 1) + (d & 1), negative when s.
; Clobbers rax, rcx, the flags.
%macro P521_DIGIT 1
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

; P521_SELECT_RESULT inf_acc, inf_in: ACC = inf_in ? ACC : (inf_acc ? IN : R) over the 27 qwords
; of a point, the masks in registers (all ones = that input is infinity). No branch.
%macro P521_SELECT_RESULT 2
  %assign s_q 0
  %rep 27
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

; P521_ON_CURVE v: jumps to the caller's .invalid unless the input point (PX, PY, below p)
; satisfies y^2 = x^3 - 3x + b. A public key's check: the branch is on public data.
%macro P521_ON_CURVE 1
    F9_FSQR     %1, S_T0, S_PX
    F9_FMUL     %1, S_T0, S_T0, S_PX        ; x^3
    F9_ROTL     S_T1, S_PX, 1
    F9_ADD      S_T1, S_T1, S_PX            ; 3x
    F9_SUB      S_T0, S_T0, S_T1
    F9_ADD      S_T0, S_T0, rel p521_b      ; x^3 - 3x + b
    F9_FSQR     %1, S_T1, S_PY              ; y^2
    P521_DIFFER S_T0, S_T1
    jnz         .invalid
%endmacro

; -----------------------------------------------------------------------------
; The point formulas over version v's products (frame slots in, frame slots out): crypto/p384.asm's,
; operation for operation, with each a + a a rotation (F9_ROTL) and 4 HH one rotation by 2.
; -----------------------------------------------------------------------------

; P521_DBL v: ACC = 2 ACC, OpenSSL's ecp_nistz256_point_double arrangement for a = -3: with
; S = (2Y)^2 = 4Y^2, 4 beta = 4 X Y^2 is S X, 8 Y^4 is S^2 / 2, Z3 = 2Y Z. 4M + 4S and ten small
; operations. Infinity (zeros) stays zeros. Every input slot is read before it is written.
%macro P521_DBL 1
    F9_ROTL     S_T0, S_AY, 1               ; 2Y
    F9_FSQR     %1, S_T1, S_AZ              ; delta = Z^2
    F9_FSQR     %1, S_T2, S_T0              ; S = 4Y^2
    F9_FMUL     %1, S_AZ, S_T0, S_AZ        ; Z3 = 2Y Z
    F9_SUB      S_T4, S_AX, S_T1            ; X - delta
    F9_ADD      S_T5, S_AX, S_T1            ; X + delta
    F9_FSQR     %1, S_T6, S_T2              ; 16 Y^4
    F9_FMUL     %1, S_T2, S_T2, S_AX        ; 4 beta = 4 X Y^2
    F9_FMUL     %1, S_T4, S_T4, S_T5        ; (X - delta)(X + delta)
    F9_HALF     S_T6, S_T6                  ; 8 Y^4
    F9_ROTL     S_T5, S_T4, 1
    F9_ADD      S_T4, S_T5, S_T4            ; alpha = 3 (X - delta)(X + delta)
    F9_ROTL     S_T5, S_T2, 1               ; 8 beta
    F9_FSQR     %1, S_T7, S_T4              ; alpha^2
    F9_SUB      S_AX, S_T7, S_T5            ; X3 = alpha^2 - 8 beta
    F9_SUB      S_T2, S_T2, S_AX            ; 4 beta - X3
    F9_FMUL     %1, S_T2, S_T2, S_T4        ; alpha (4 beta - X3)
    F9_SUB      S_AY, S_T2, S_T6            ; Y3 = alpha (4 beta - X3) - 8 Y^4
%endmacro

; P521_ADD v: R = ACC + IN, both Jacobian, add-2007-bl (11M + 5S). Leaves H = U2 - U1 in T3 and
; r = 2 (S2 - S1) in T5: the doubling case is H = r = 0, the cancelling case H = 0 with r not 0
; (p521_vadd and p521_add_last look). Wrong for either case and for an input at infinity: the
; caller's selection replaces the latter.
%macro P521_ADD 1
    F9_FSQR     %1, S_T0, S_AZ              ; Z1Z1 = Z1^2
    F9_FSQR     %1, S_T1, S_IZ              ; Z2Z2 = Z2^2
    F9_FMUL     %1, S_T2, S_AX, S_T1        ; U1 = X1 Z2Z2
    F9_FMUL     %1, S_T3, S_IX, S_T0        ; U2 = X2 Z1Z1
    F9_FMUL     %1, S_T4, S_IZ, S_T1        ; Z2^3
    F9_FMUL     %1, S_T5, S_AZ, S_T0        ; Z1^3
    F9_ADD      S_T8, S_AZ, S_IZ            ; Z1 + Z2
    F9_FMUL     %1, S_T4, S_AY, S_T4        ; S1 = Y1 Z2^3
    F9_FMUL     %1, S_T5, S_IY, S_T5        ; S2 = Y2 Z1^3
    F9_SUB      S_T3, S_T3, S_T2            ; H = U2 - U1
    F9_FSQR     %1, S_T8, S_T8              ; (Z1 + Z2)^2
    F9_SUB      S_T5, S_T5, S_T4            ; S2 - S1
    F9_ROTL     S_T6, S_T3, 1               ; 2H
    F9_ROTL     S_T5, S_T5, 1               ; r = 2 (S2 - S1)
    F9_FSQR     %1, S_T6, S_T6              ; I = (2H)^2
    F9_SUB      S_T8, S_T8, S_T0            ; (Z1 + Z2)^2 - Z1Z1
    F9_FSQR     %1, S_T9, S_T5              ; r^2
    F9_FMUL     %1, S_T7, S_T3, S_T6        ; J = H I
    F9_FMUL     %1, S_T2, S_T2, S_T6        ; V = U1 I
    F9_SUB      S_T8, S_T8, S_T1            ; (Z1 + Z2)^2 - Z1Z1 - Z2Z2
    F9_FMUL     %1, S_RZ, S_T8, S_T3        ; Z3 = that H
    F9_SUB      S_T9, S_T9, S_T7            ; r^2 - J
    F9_ROTL     S_T10, S_T2, 1              ; 2V
    F9_FMUL     %1, S_T4, S_T4, S_T7        ; S1 J
    F9_SUB      S_RX, S_T9, S_T10           ; X3 = r^2 - J - 2V
    F9_SUB      S_T2, S_T2, S_RX            ; V - X3
    F9_ROTL     S_T4, S_T4, 1               ; 2 S1 J
    F9_FMUL     %1, S_T2, S_T5, S_T2        ; r (V - X3)
    F9_SUB      S_RY, S_T2, S_T4            ; Y3 = r (V - X3) - 2 S1 J
%endmacro

; P521_MADD v: R = ACC + IN with IN affine (IX, IY), madd-2007-bl (7M + 4S); leaves H in T1 and r
; in T2. The same cases as P521_ADD are the caller's.
%macro P521_MADD 1
    F9_FSQR     %1, S_T0, S_AZ              ; Z1Z1 = Z1^2
    F9_FMUL     %1, S_T1, S_IX, S_T0        ; U2 = X2 Z1Z1
    F9_FMUL     %1, S_T2, S_AZ, S_T0        ; Z1^3
    F9_SUB      S_T1, S_T1, S_AX            ; H = U2 - X1
    F9_FMUL     %1, S_T2, S_IY, S_T2        ; S2 = Y2 Z1^3
    F9_FSQR     %1, S_T3, S_T1              ; HH = H^2
    F9_ADD      S_T7, S_AZ, S_T1            ; Z1 + H
    F9_SUB      S_T2, S_T2, S_AY            ; S2 - Y1
    F9_ROTL     S_T4, S_T3, 2               ; I = 4 HH
    F9_FSQR     %1, S_T7, S_T7              ; (Z1 + H)^2
    F9_ROTL     S_T2, S_T2, 1               ; r = 2 (S2 - Y1)
    F9_FMUL     %1, S_T5, S_T1, S_T4        ; J = H I
    F9_FMUL     %1, S_T6, S_AX, S_T4        ; V = X1 I
    F9_FSQR     %1, S_T8, S_T2              ; r^2
    F9_SUB      S_T7, S_T7, S_T0            ; (Z1 + H)^2 - Z1Z1
    F9_FMUL     %1, S_T9, S_AY, S_T5        ; Y1 J
    F9_SUB      S_T8, S_T8, S_T5            ; r^2 - J
    F9_ROTL     S_T10, S_T6, 1              ; 2V
    F9_SUB      S_RZ, S_T7, S_T3            ; Z3 = (Z1 + H)^2 - Z1Z1 - HH
    F9_SUB      S_RX, S_T8, S_T10           ; X3 = r^2 - J - 2V
    F9_ROTL     S_T9, S_T9, 1               ; 2 Y1 J
    F9_SUB      S_T6, S_T6, S_RX            ; V - X3
    F9_FMUL     %1, S_T6, S_T2, S_T6        ; r (V - X3)
    F9_SUB      S_RY, S_T6, S_T9            ; Y3 = r (V - X3) - 2 Y1 J
%endmacro

; -----------------------------------------------------------------------------
; The table scans: edx = a digit's magnitude. Every entry is read and masked by (its number =
; the digit): no address depends on the digit; digit 0 matches none and gives zeros (infinity).
;   P521_SCAN_TAB_v3 / _v1: TAB (16 Jacobian points, 224-octet slots) into IN (its 224 octets).
;   P521_SCAN_BASE_v3 / _v1: the fixed-base window at rsi (32 affine points, 144 octets each)
;     into IX, IY.
; v3 with AVX2 (and vzeroupper after: the products and the C ABI's callees run legacy SSE); v1
; with SSE2 (its loads aligned: every entry starts on 16 octets), TAB's rows in two passes of
; seven (fourteen accumulators and the scan's own five would pass SSE2's sixteen registers).
; Clobber rax, rcx, rsi, xmm0-xmm13 (ymm at v3), the flags.
; -----------------------------------------------------------------------------
%macro P521_SCAN_TAB_v3 0
    vmovd       xmm0, edx
    vpbroadcastd ymm0, xmm0
    vpcmpeqd    ymm8, ymm8, ymm8
    vpsrld      ymm8, ymm8, 31              ; 1 in every dword: the step
    vmovdqa     ymm9, ymm8                  ; the entry number, from 1
    vpxor       xmm1, xmm1, xmm1
    vpxor       xmm2, xmm2, xmm2
    vpxor       xmm3, xmm3, xmm3
    vpxor       xmm4, xmm4, xmm4
    vpxor       xmm5, xmm5, xmm5
    vpxor       xmm6, xmm6, xmm6
    vpxor       xmm7, xmm7, xmm7
    lea         rax, [rbp + PF_TAB]
    mov         ecx, 16
%%scan:
    vpcmpeqd    ymm10, ymm9, ymm0
    vpaddd      ymm9, ymm9, ymm8
    vpand       ymm11, ymm10, [rax]
    vpor        ymm1, ymm1, ymm11
    vpand       ymm11, ymm10, [rax + 32]
    vpor        ymm2, ymm2, ymm11
    vpand       ymm11, ymm10, [rax + 64]
    vpor        ymm3, ymm3, ymm11
    vpand       ymm11, ymm10, [rax + 96]
    vpor        ymm4, ymm4, ymm11
    vpand       ymm11, ymm10, [rax + 128]
    vpor        ymm5, ymm5, ymm11
    vpand       ymm11, ymm10, [rax + 160]
    vpor        ymm6, ymm6, ymm11
    vpand       ymm11, ymm10, [rax + 192]
    vpor        ymm7, ymm7, ymm11
    add         rax, 224
    dec         ecx
    jnz         %%scan
    vmovdqu     [rbp + PF_IX], ymm1
    vmovdqu     [rbp + PF_IX + 32], ymm2
    vmovdqu     [rbp + PF_IX + 64], ymm3
    vmovdqu     [rbp + PF_IX + 96], ymm4
    vmovdqu     [rbp + PF_IX + 128], ymm5
    vmovdqu     [rbp + PF_IX + 160], ymm6
    vmovdqu     [rbp + PF_IX + 192], ymm7
    vzeroupper
%endmacro

%macro P521_SCAN_TAB_v1 0
    P521_SCAN_HALF_v1 0
    P521_SCAN_HALF_v1 112
%endmacro

; P521_SCAN_HALF_v1 offset: TAB's rows at offset .. offset + 111 of every entry into IN's same
; octets: seven 16-octet rows, sixteen entries.
%macro P521_SCAN_HALF_v1 1
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
    lea         rax, [rbp + PF_TAB + %1]
    mov         ecx, 16
%%scan:
    movdqa      xmm12, xmm11
    pcmpeqd     xmm12, xmm0
    paddd       xmm11, xmm10
    P521_SCAN_ROW xmm1, rax
    P521_SCAN_ROW xmm2, rax + 16
    P521_SCAN_ROW xmm3, rax + 32
    P521_SCAN_ROW xmm4, rax + 48
    P521_SCAN_ROW xmm5, rax + 64
    P521_SCAN_ROW xmm6, rax + 80
    P521_SCAN_ROW xmm7, rax + 96
    add         rax, 224
    dec         ecx
    jnz         %%scan
    movdqa      [rbp + PF_IX + %1], xmm1
    movdqa      [rbp + PF_IX + %1 + 16], xmm2
    movdqa      [rbp + PF_IX + %1 + 32], xmm3
    movdqa      [rbp + PF_IX + %1 + 48], xmm4
    movdqa      [rbp + PF_IX + %1 + 64], xmm5
    movdqa      [rbp + PF_IX + %1 + 80], xmm6
    movdqa      [rbp + PF_IX + %1 + 96], xmm7
%endmacro

; P521_SCAN_ROW acc, address: acc |= the 16 octets at address ANDed with xmm12 (the entry's mask);
; xmm13 the temporary (SSE2's pand needs the row in a register: aligned rows). No flags.
%macro P521_SCAN_ROW 2
    movdqa      xmm13, [%2]
    pand        xmm13, xmm12
    por         %1, xmm13
%endmacro

%macro P521_SCAN_BASE_v3 0
    vmovd       xmm0, edx
    vpbroadcastd ymm0, xmm0
    vpcmpeqd    ymm6, ymm6, ymm6
    vpsrld      ymm6, ymm6, 31
    vmovdqa     ymm7, ymm6
    vpxor       xmm1, xmm1, xmm1
    vpxor       xmm2, xmm2, xmm2
    vpxor       xmm3, xmm3, xmm3
    vpxor       xmm4, xmm4, xmm4
    vpxor       xmm5, xmm5, xmm5
    mov         ecx, P521_ENTRIES
%%scan:
    vpcmpeqd    ymm8, ymm7, ymm0
    vpaddd      ymm7, ymm7, ymm6
    vpand       ymm9, ymm8, [rsi]
    vpor        ymm1, ymm1, ymm9
    vpand       ymm9, ymm8, [rsi + 32]
    vpor        ymm2, ymm2, ymm9
    vpand       ymm9, ymm8, [rsi + 64]      ; (x is 72 octets: this row is x's last and y's first)
    vpor        ymm3, ymm3, ymm9
    vpand       ymm9, ymm8, [rsi + 96]
    vpor        ymm4, ymm4, ymm9
    vpand       xmm9, xmm8, [rsi + 128]
    vpor        xmm5, xmm5, xmm9
    add         rsi, 144
    dec         ecx
    jnz         %%scan
    vmovdqu     [rbp + PF_IX], ymm1
    vmovdqu     [rbp + PF_IX + 32], ymm2
    vmovdqu     [rbp + PF_IX + 64], ymm3
    vmovdqu     [rbp + PF_IX + 96], ymm4
    vmovdqu     [rbp + PF_IX + 128], xmm5
    vzeroupper
%endmacro

%macro P521_SCAN_BASE_v1 0
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
    pxor        xmm7, xmm7
    pxor        xmm8, xmm8
    pxor        xmm9, xmm9
    mov         ecx, P521_ENTRIES
%%scan:
    movdqa      xmm12, xmm11
    pcmpeqd     xmm12, xmm0
    paddd       xmm11, xmm10
    P521_SCAN_ROW xmm1, rsi
    P521_SCAN_ROW xmm2, rsi + 16
    P521_SCAN_ROW xmm3, rsi + 32
    P521_SCAN_ROW xmm4, rsi + 48
    P521_SCAN_ROW xmm5, rsi + 64
    P521_SCAN_ROW xmm6, rsi + 80
    P521_SCAN_ROW xmm7, rsi + 96
    P521_SCAN_ROW xmm8, rsi + 112
    P521_SCAN_ROW xmm9, rsi + 128
    add         rsi, 144
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

; =============================================================================
; The field's products and the scalars' (include/crypto/p521.inc has their bodies and contracts):
; rdi = out, rsi = a, rdx = b (the squares take no b), all inside a P-521 frame (rbp). Global
; and hidden: callable from inside the library (and from a scratch harness linked against this
; object), not exported.
; =============================================================================
global p521_fmul_v3:function hidden
align 16
p521_fmul_v3:
    F9X_MUL_BODY
    ret

global p521_fsqr_v3:function hidden
align 16
p521_fsqr_v3:
    F9X_SQR_BODY
    ret

global p521_fmul_v1:function hidden
align 16
p521_fmul_v1:
    F9Q_MUL_BODY
    ret

; p521_fsqr_v1: through the product (mul overwrites the flags a doubling chain and the squares'
; additions would share, so v1 has no triangle of its own).
global p521_fsqr_v1:function hidden
align 16
p521_fsqr_v1:
    mov         rdx, rsi
    jmp         p521_fmul_v1

global p521_nmul:function hidden
align 16
p521_nmul:
    F9_NMUL_BODY
    ret

; =============================================================================
; p521_inverse: x^-1 modulo p or n, constant time, by Bernstein and Yang's divsteps ("Fast
; constant-time gcd computation and modular inversion", 2019) in the arrangement of
; libsecp256k1's modinv64 (MIT; its doc/safegcd_implementation.md derives every step used here):
;   - original divsteps (delta from 1, kept as eta = -delta: the swap when eta < 0 and g odd,
;     then eta = -eta - 1, else eta - 1): 1550 of them, 25 batches of 62, always - the paper's
;     Theorem 11.2 bound for inputs below 2^521 is floor((49 521 + 57) / 17) = 1505;
;   - a batch works on f's and g's low 62-bit limbs only and builds the 2x2 transition matrix
;     (u, v, q, r) scaled by 2^62 (u and r start at 1; u and v double each step while g halves),
;     which is then applied to the whole numbers: f, g = (u f + v g, q f + r g) / 2^62, and to the
;     Bezout coefficients d, e modulo M, a multiple of M chosen through M^-1 mod 2^62 making each
;     division exact;
;   - numbers in nine signed 62-bit limbs (eight of 62 bits, the top one signed), so each product
;     of a limb by a matrix entry (|entry| <= 2^62) fits a signed 128-bit sum.
; crypto/p384.asm's routine at nine limbs (the scratchpad model p521/model.py ran this exact
; arrangement against pow(x, -1) for both moduli first). Every batch runs the same instructions
; whatever the values: no branch and no address depends on x (the counts are constants), which
; is why it can invert a secret nonce.
; =============================================================================

M62 equ 0x3FFFFFFFFFFFFFFF

; The local frame (rsp-based).
IV_F        equ 0                           ; f: nine signed 62-bit limbs
IV_G        equ 72                          ; g
IV_D        equ 144                         ; d (the inverse's coefficient, modulo M)
IV_E        equ 216                         ; e
IV_X        equ 288                         ; the caller's x
IV_MOD      equ 296                         ; the modulus' record
IV_CNT      equ 304                         ; the batch counter
IV_ETA      equ 312                         ; eta between batches
IV_SIZE     equ 320                         ; (rsp 16-aligned is not needed: no call inside)

; IV_UPDATE a, b: the matrix applied to the two numbers held as nine limbs at [rsp + a] and
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
  %rep 8
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
    mov         [rsp + %1 + 64], rbx        ; the top limbs, signed
    mov         [rsp + %2 + 64], r8
%endmacro

; -----------------------------------------------------------------------------
; p521_inverse: rdi = nine qwords x (plain, below M), replaced by x^-1 mod M (0 stays 0); rsi =
; the modulus' record (p521_mod_p or p521_mod_n: M in nine signed 62-bit limbs, then M^-1 mod
; 2^62). System V: keeps rbx, rbp, r12-r15. Its frame is wiped before it returns.
; -----------------------------------------------------------------------------
align 16
p521_inverse:
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
  %rep 9
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
    mov         r8, [rdi + 48]
    mov         rax, r9
    shrd        rax, r8, 52
    and         rax, r10
    mov         [rsp + IV_G + 48], rax
    mov         r9, [rdi + 56]
    mov         rax, r8
    shrd        rax, r9, 50
    and         rax, r10
    mov         [rsp + IV_G + 56], rax
    mov         r8, [rdi + 64]
    shrd        r9, r8, 48                  ; limb 8: bits 496 .. 520 (x < 2^521: no mask)
    mov         [rsp + IV_G + 64], r9
    mov         qword [rsp + IV_ETA], -1
    mov         dword [rsp + IV_CNT], 25
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
    mov         rax, [rsp + IV_D + 64]
    sar         rax, 63                     ; sd: d < 0
    mov         rdx, [rsp + IV_E + 64]
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
    mov         rax, [r15 + 72]             ; md -= (M^-1 cd + md) mod 2^62
    imul        rax, rbx
    add         rax, rdi
    and         rax, r10
    sub         rdi, rax
    mov         rax, [r15 + 72]             ; me -= (M^-1 ce + me) mod 2^62
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
  %rep 8
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
    mov         [rsp + IV_D + 64], rbx
    mov         [rsp + IV_E + 64], r8
    ; f, g = (u f + v g, q f + r g) / 2^62
    IV_UPDATE   IV_F, IV_G
    dec         dword [rsp + IV_CNT]
    jnz         .batch
    ; g is 0 and f is +1 or -1 (x and M coprime; f = M and d = 0 when x = 0): d, negated when
    ; f < 0, from (-2M, M) into [0, M), each conditional step a mask
    mov         r15, [rsp + IV_MOD]
    mov         r10, M62
    mov         rax, [rsp + IV_D + 64]
    sar         rax, 63                     ; d < 0: add M
    mov         rdx, [rsp + IV_F + 64]
    sar         rdx, 63                     ; f < 0: negate
  %assign iv_q 0
  %rep 9
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
    %rep 8
    mov         rax, [rsp + IV_D + iv_q]
    mov         rbx, rax
    sar         rax, 62
    add         [rsp + IV_D + iv_q + 8], rax
    and         rbx, r10
    mov         [rsp + IV_D + iv_q], rbx
      %assign iv_q iv_q + 8
    %endrep
    mov         rax, [rsp + IV_D + 64]
    sar         rax, 63
    %assign iv_q 0
    %rep 9
    mov         rbx, [r15 + iv_q]
    and         rbx, rax
    add         [rsp + IV_D + iv_q], rbx
      %assign iv_q iv_q + 8
    %endrep
  %endrep
    ; d's nine limbs back into nine qwords: qword j = limb j >> 2j | limb j+1 << (62 - 2j) for
    ; j < 8, and qword 8 = limb 8 >> 16 (limb 8 holds bits 496 .. 520)
    mov         rdi, [rsp + IV_X]
  %assign iv_j 0
  %rep 8
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
    mov         rax, [rsp + IV_D + 64]
    shr         rax, 16
    mov         [rdi + 64], rax
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
; p521_load_be66: rsi = 66 big-endian octets -> their value's limbs (528 bits at most) in r8,
; r9, r10, r11, r12, r13, r14, r15, rbx (the top one below 2^16). Reads exactly the 66 octets.
; Clobbers the flags (rol's).
; -----------------------------------------------------------------------------
align 16
p521_load_be66:
    mov         r8, [rsi + 58]
    bswap       r8
    mov         r9, [rsi + 50]
    bswap       r9
    mov         r10, [rsi + 42]
    bswap       r10
    mov         r11, [rsi + 34]
    bswap       r11
    mov         r12, [rsi + 26]
    bswap       r12
    mov         r13, [rsi + 18]
    bswap       r13
    mov         r14, [rsi + 10]
    bswap       r14
    mov         r15, [rsi + 2]
    bswap       r15
    movzx       ebx, word [rsi]
    rol         bx, 8                       ; octets 0 and 1, big-endian
    ret

; -----------------------------------------------------------------------------
; p521_load_scalar: rsi = 66 big-endian octets -> PF_K (limbs) and PF_K2 (shifted up a bit).
; eax = 0 when 1 <= k < n, else -1 (both computed without a branch; the caller's branch on the
; answer shows only whether a key or a candidate nonce was in range). Clobbers rax, rbx, rcx,
; rdx, r8-r15, the flags.
; p521_load_candidate: the same for RFC 6979's candidate: the 66 octets at rsi are the first of
; two HMAC blocks, and bits2int takes their leftmost 521 bits: the 528-bit value shifted right 7.
; -----------------------------------------------------------------------------
align 16
p521_load_candidate:
    call        p521_load_be66
    shrd        r8, r9, 7
    shrd        r9, r10, 7
    shrd        r10, r11, 7
    shrd        r11, r12, 7
    shrd        r12, r13, 7
    shrd        r13, r14, 7
    shrd        r14, r15, 7
    shrd        r15, rbx, 7
    shr         rbx, 7
    jmp         p521_check_scalar

align 16
p521_load_scalar:
    call        p521_load_be66
    ; (falls through)
p521_check_scalar:
    F9_STORE    rbp + PF_K
    mov         rax, r8
    sub         rax, [rel p521_n]
    mov         rax, r9
    sbb         rax, [rel p521_n + 8]
    mov         rax, r10
    sbb         rax, [rel p521_n + 16]
    mov         rax, r11
    sbb         rax, [rel p521_n + 24]
    mov         rax, r12
    sbb         rax, [rel p521_n + 32]
    mov         rax, r13
    sbb         rax, [rel p521_n + 40]
    mov         rax, r14
    sbb         rax, [rel p521_n + 48]
    mov         rax, r15
    sbb         rax, [rel p521_n + 56]
    mov         rax, rbx
    sbb         rax, [rel p521_n + 64]
    sbb         ecx, ecx                    ; all ones when k < n
    mov         rax, r8
    or          rax, r9
    or          rax, r10
    or          rax, r11
    or          rax, r12
    or          rax, r13
    or          rax, r14
    or          rax, r15
    or          rax, rbx
    neg         rax
    sbb         edx, edx                    ; all ones when k != 0
    and         ecx, edx
    call        p521_set_k2
    mov         eax, ecx
    not         eax
    ret

; -----------------------------------------------------------------------------
; p521_set_k2: PF_K2 = the scalar in r8..r15, rbx shifted up one bit (nine qwords, and a tenth of
; zeros): what P521_DIGIT reads, Booth's bit -1 a zero below it. A scalar of n or more (refused
; by the caller) loses its bits past 575; nothing reads them. Keeps rcx; clobbers r8-r15, rbx,
; the flags.
; -----------------------------------------------------------------------------
align 16
p521_set_k2:
    mov         qword [rbp + PF_K2 + 72], 0
    shld        rbx, r15, 1
    mov         [rbp + PF_K2 + 64], rbx
    shld        r15, r14, 1
    mov         [rbp + PF_K2 + 56], r15
    shld        r14, r13, 1
    mov         [rbp + PF_K2 + 48], r14
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
; p521_wnaf: rsi = a scalar's nine limbs (public, below n), rdi = 528 octets, ecx = w (5 or 6)
; -> the scalar's width-w NAF, least significant digit first, as signed octets: every digit 0 or
; odd with |d| < 2^(w - 1), at most one nonzero among any w in a row, zeros past the last; rax =
; how many (the last one nonzero; 0 for a zero scalar; at most 522, as k - d can pass 2^521). The
; classic recoding (an odd k gives d = k mods 2^w and k -= d, leaving a multiple of 2^w), with
; each run of zero digits passed at once (bsf, or a whole zero limb). The nine limbs take nine of
; the fourteen registers, so the position is the output's address itself (rdi moves along), and
; the base and w wait on the stack. Variable time: for verification's public scalars only.
; Clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r15, the flags.
; -----------------------------------------------------------------------------
align 16
p521_wnaf:
    push        rdi                         ; [rsp + 8]: the digits' base
    push        rcx                         ; [rsp]: w
    xor         eax, eax
    mov         ecx, 528 / 8
    rep         stosq
    mov         rdi, [rsp + 8]              ; the position k's bit 0 stands for
    mov         r8, [rsi]
    mov         r9, [rsi + 8]
    mov         r10, [rsi + 16]
    mov         r11, [rsi + 24]
    mov         r12, [rsi + 32]
    mov         r13, [rsi + 40]
    mov         r14, [rsi + 48]
    mov         r15, [rsi + 56]
    mov         rbx, [rsi + 64]
    xor         esi, esi                    ; past the last digit written (0: none yet)
.next:
    mov         rax, r8
    or          rax, r9
    or          rax, r10
    or          rax, r11
    or          rax, r12
    or          rax, r13
    or          rax, r14
    or          rax, r15
    or          rax, rbx
    jz          .done
    test        r8, r8
    jnz         .zeros
    mov         r8, r9                      ; a zero limb: 64 zero digits at once
    mov         r9, r10
    mov         r10, r11
    mov         r11, r12
    mov         r12, r13
    mov         r13, r14
    mov         r14, r15
    mov         r15, rbx
    xor         ebx, ebx
    add         rdi, 64
    jmp         .next
.zeros:
    bsf         rcx, r8                     ; the run of zero digits below the next odd bit
    shrd        r8, r9, cl                  ; (bsf, not tzcnt: v1 runs this too)
    shrd        r9, r10, cl
    shrd        r10, r11, cl
    shrd        r11, r12, cl
    shrd        r12, r13, cl
    shrd        r13, r14, cl
    shrd        r14, r15, cl
    shrd        r15, rbx, cl
    shr         rbx, cl
    add         rdi, rcx
    mov         ecx, [rsp]                  ; w
    mov         edx, 1
    shl         rdx, cl                     ; 2^w
    lea         rax, [rdx - 1]
    and         rax, r8                     ; k mod 2^w (k is odd now)
    shr         rdx, 1                      ; 2^(w - 1)
    cmp         rax, rdx
    jb          .digit
    sub         rax, rdx                    ; 2^(w - 1) or more: the negative digit, k mod 2^w - 2^w
    sub         rax, rdx
.digit:
    mov         [rdi], al
    lea         rsi, [rdi + 1]
    cqo                                     ; d's sign for the higher limbs
    sub         r8, rax
    sbb         r9, rdx
    sbb         r10, rdx
    sbb         r11, rdx
    sbb         r12, rdx
    sbb         r13, rdx
    sbb         r14, rdx
    sbb         r15, rdx
    sbb         rbx, rdx                    ; k -= d: a multiple of 2^w now
    jmp         .next
.done:
    pop         rcx
    pop         rdi
    mov         rax, rsi
    sub         rax, rdi                    ; the count, when a digit was written
    test        rsi, rsi
    cmovz       rax, rsi                    ; none: 0 (a zero scalar)
    ret

; -----------------------------------------------------------------------------
; p521_load_point: rsi = 133 octets, SEC 1's uncompressed form 04 || x || y -> PX, PY (limbs).
; eax = 0 when the form is uncompressed and x, y are below p, else -1 (the curve equation is the
; caller's: P521_ON_CURVE). Clobbers rax, rbx, rsi, rdi, r8-r15, the flags.
; -----------------------------------------------------------------------------
align 16
p521_load_point:
    cmp         byte [rsi], 4
    jne         .bad
    lea         rdi, [rbp + PF_PX]
    inc         rsi
    call        p521_load_be_p
    jc          .bad
    lea         rdi, [rbp + PF_PY]
    call        p521_load_be_p
    jc          .bad
    xor         eax, eax
    ret
.bad:
    mov         eax, -1
    ret

; -----------------------------------------------------------------------------
; p521_load_be_p: 66 big-endian octets at rsi -> limbs at rdi; rsi += 66. CF set when the value
; is p or more (the subtraction of p does not borrow: a value of 2^521 or more, or p itself).
; Clobbers rax, rbx, r8-r15, the flags.
; -----------------------------------------------------------------------------
align 16
p521_load_be_p:
    call        p521_load_be66
    add         rsi, 66
    mov         [rdi], r8
    mov         [rdi + 8], r9
    mov         [rdi + 16], r10
    mov         [rdi + 24], r11
    mov         [rdi + 32], r12
    mov         [rdi + 40], r13
    mov         [rdi + 48], r14
    mov         [rdi + 56], r15
    mov         [rdi + 64], rbx
    sub         r8, [rel p521_p]
    sbb         r9, [rel p521_p + 8]
    sbb         r10, [rel p521_p + 16]
    sbb         r11, [rel p521_p + 24]
    sbb         r12, [rel p521_p + 32]
    sbb         r13, [rel p521_p + 40]
    sbb         r14, [rel p521_p + 48]
    sbb         r15, [rel p521_p + 56]
    sbb         rbx, [rel p521_p + 64]
    cmc
    ret

; -----------------------------------------------------------------------------
; p521_store_be66: the limbs at rsi (a value below 2^521) -> 66 big-endian octets at rdi.
; Clobbers rax.
; -----------------------------------------------------------------------------
align 16
p521_store_be66:
  %assign sb_q 0
  %rep 8
    mov         rax, [rsi + sb_q]
    bswap       rax
    mov         [rdi + 58 - sb_q], rax
    %assign sb_q sb_q + 8
  %endrep
    mov         eax, [rsi + 64]             ; (below 2^9: octets 0 and 1)
    rol         ax, 8
    mov         [rdi], ax
    ret

; -----------------------------------------------------------------------------
; p521_load_digest: rsi = a digest, rdx = its length (public) -> PF_E = bits2int(digest) mod n
; (RFC 6979 2.3.2, FIPS 186-5 6.4.1): a digest of 66 octets or more gives its first 66 octets'
; 528 bits shifted right 7 (its leftmost 521 bits); a shorter one is all of its bits (right-
; aligned in 66 octets of zeros, no shift); then one subtraction of n (e < 2^521 < 2n). Uses
; PF_T0. Clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r15, the flags.
; -----------------------------------------------------------------------------
align 16
p521_load_digest:
    xor         eax, eax
  %assign ld_q 0
  %rep 9
    mov         [rbp + PF_T0 + ld_q], rax
    %assign ld_q ld_q + 8
  %endrep
    mov         rcx, rdx
    cmp         rcx, 66
    jb          .short
    mov         ecx, 66
    lea         rdi, [rbp + PF_T0]
    mov         edx, 7                      ; the shift: 528 - 521
    jmp         .copy
.short:
    lea         rdi, [rbp + PF_T0 + 66]     ; right-aligned: zeros before it
    sub         rdi, rcx
    xor         edx, edx                    ; no shift
.copy:
    rep         movsb
    lea         rsi, [rbp + PF_T0]
    call        p521_load_be66
    mov         ecx, edx
    shrd        r8, r9, cl                  ; (a shift by 0 changes nothing)
    shrd        r9, r10, cl
    shrd        r10, r11, cl
    shrd        r11, r12, cl
    shrd        r12, r13, cl
    shrd        r13, r14, cl
    shrd        r14, r15, cl
    shrd        r15, rbx, cl
    shr         rbx, cl
    F9_STORE    rbp + PF_E
    F9_NSUBN    rbp + PF_E
    ret

; -----------------------------------------------------------------------------
; RFC 6979 3.2's HMAC_DRBG, HMAC-SHA512 always (RFC 6979's exactly when the digest is SHA-512's;
; any other digest still gets a sound deterministic nonce), over PF_KEY (K, 64 octets) and
; PF_SEED: V (64) at +0, then the separator octet (+64), x (the key's 66 octets, +65), h1 =
; bits2octets(digest) (+131) and the entropy (+197). qlen = 521 > hlen = 512: a candidate is
; two HMAC blocks (V = HMAC_K(V) twice), the first 66 octets of their concatenation going to
; PF_TT. The calls into the C ABI need rsp 16-aligned: so p521_drbg_hmac is called only from the
; three routines below, and they only from a function's frame body (rsp = rbp, 64-aligned).
; -----------------------------------------------------------------------------

; p521_drbg_hmac: rcx = octets of PF_SEED, r8 = where the MAC goes: HMAC(K, SEED[0..rcx]).
; (httpasm_hmac_sha512 reads its key and data before it writes the MAC: K and V update in place.)
align 16
p521_drbg_hmac:
    lea         rdi, [rbp + PF_KEY]
    mov         esi, 64
    lea         rdx, [rbp + PF_SEED]
    call        httpasm_hmac_sha512
    ret

; p521_drbg_init: steps b-g: V = 0x01..., K = 0x00..., K = HMAC_K(V || 0x00 || x || h1 [|| k']),
; V = HMAC_K(V), K = HMAC_K(V || 0x01 || ...), V = HMAC_K(V).
align 16
p521_drbg_init:
    mov         rax, 0x0101010101010101
    xor         ecx, ecx
  %assign di_q 0
  %rep 8
    mov         [rbp + PF_SEED + di_q], rax
    mov         [rbp + PF_KEY + di_q], rcx
    %assign di_q di_q + 8
  %endrep
    mov         byte [rbp + PF_SEED + 64], 0
    mov         rcx, [rbp + PF_SEEDN]
    lea         r8, [rbp + PF_KEY]
    call        p521_drbg_hmac
    mov         ecx, 64
    lea         r8, [rbp + PF_SEED]
    call        p521_drbg_hmac
    mov         byte [rbp + PF_SEED + 64], 1
    mov         rcx, [rbp + PF_SEEDN]
    lea         r8, [rbp + PF_KEY]
    call        p521_drbg_hmac
    mov         ecx, 64
    lea         r8, [rbp + PF_SEED]
    call        p521_drbg_hmac
    ret

; p521_drbg_next: step h: T = V1 || V2 with V = HMAC_K(V) each time; PF_TT = T's first 66
; octets (the candidate's: bits2int keeps 521 of T's 1024 bits, all within them).
align 16
p521_drbg_next:
    mov         ecx, 64
    lea         r8, [rbp + PF_SEED]
    call        p521_drbg_hmac
  %assign dn_q 0
  %rep 8
    mov         rax, [rbp + PF_SEED + dn_q]
    mov         [rbp + PF_TT + dn_q], rax
    %assign dn_q dn_q + 8
  %endrep
    mov         ecx, 64
    lea         r8, [rbp + PF_SEED]
    call        p521_drbg_hmac
    movzx       eax, word [rbp + PF_SEED]
    mov         [rbp + PF_TT + 64], ax
    ret

; p521_drbg_reject: step h.3, after a candidate out of range or a zero r or s: K = HMAC_K(V ||
; 0x00), V = HMAC_K(V).
align 16
p521_drbg_reject:
    mov         byte [rbp + PF_SEED + 64], 0
    mov         ecx, 65
    lea         r8, [rbp + PF_KEY]
    call        p521_drbg_hmac
    mov         ecx, 64
    lea         r8, [rbp + PF_SEED]
    call        p521_drbg_hmac
    ret

; =============================================================================
; P521_ROUTINES v: every routine of one version (v3 or v1). The point routines work on the frame
; of the function that calls them (rbp) and clobber every register but rbp and rsp.
; =============================================================================
%macro P521_ROUTINES 1

; p521_dbl_v: ACC = 2 ACC.
align 16
p521_dbl_%1:
    P521_DBL    %1
    ret

; p521_add_raw_v, p521_madd_raw_v: the formulas alone, R = ACC + IN (P521_ADD, P521_MADD), for
; callers that settle infinity and the equal points themselves: the constant-time additions below
; by mask, the verification's variable-time ones by branch.
align 16
p521_add_raw_%1:
    P521_ADD    %1
    ret

align 16
p521_madd_raw_%1:
    P521_MADD   %1
    ret

; p521_add_v: ACC = ACC + IN (Jacobian), either input infinity handled by the selection; H and r
; left in T3 and T5.
align 16
p521_add_%1:
    call        p521_add_raw_%1
    P521_IS_ZERO r13, S_AZ
    P521_IS_ZERO r14, S_IZ
    P521_SELECT_RESULT r13, r14
    ret

; p521_add_last_v: p521_add_v for the variable base's last window, where the doubling case can
; occur (the header: k = n - 18): the sum by selection as above, then 2 IN (the addend doubled in
; ACC, the sum kept in R meanwhile), and ACC = 2 IN where H = r = 0 with neither input at
; infinity, else the sum; every step a mask, so the time does not show which.
align 16
p521_add_last_%1:
    call        p521_add_raw_%1
    P521_IS_ZERO r13, S_AZ                  ; ACC at infinity
    P521_IS_ZERO r14, S_IZ                  ; IN at infinity
    P521_IS_ZERO rax, S_T3                  ; H = 0
    P521_IS_ZERO rcx, S_T5                  ; r = 0
    and         rax, rcx
    mov         rcx, r13
    or          rcx, r14
    not         rcx                         ; neither at infinity
    and         rax, rcx
    mov         [rbp + PF_DBLM], rax        ; the doubling case
    P521_SELECT_RESULT r13, r14
    P521_COPY   S_RX, S_AX, 27              ; the sum, kept
    P521_COPY   S_AX, S_IX, 27
    call        p521_dbl_%1                 ; ACC = 2 IN
    mov         rdx, [rbp + PF_DBLM]
  %assign al_q 0
  %rep 27
    mov         rax, [rbp + PF_RX + al_q]
    mov         rcx, [rbp + PF_AX + al_q]
    xor         rcx, rax
    and         rcx, rdx
    xor         rax, rcx                    ; the doubling case ? 2 IN : the sum
    mov         [rbp + PF_AX + al_q], rax
    %assign al_q al_q + 8
  %endrep
    ret

; p521_madd_v: ACC = ACC + IN (affine, IZ = 1 set by the caller for the selection); IN is
; infinity when x = y = 0 (no curve point has them: the scan's zeros, which a negative digit
; leaves zeros, F9_CNEG keeping 0 as 0).
align 16
p521_madd_%1:
    call        p521_madd_raw_%1
    P521_IS_ZERO r13, S_AZ
    mov         r14, [rbp + PF_IX]
  %assign mz_q 8
  %rep 17
    or          r14, [rbp + PF_IX + mz_q]   ; x's and y's eighteen qwords
    %assign mz_q mz_q + 8
  %endrep
    neg         r14
    sbb         r14, r14
    not         r14
    P521_SELECT_RESULT r13, r14
    ret

; p521_vadd_v: ACC = ACC + IN, IN Jacobian and never infinity, in variable time (verification's
; public points only): ACC at infinity takes IN; after the addition, H = 0 means the same x: the
; same point (r = 0 too) doubles IN, the opposite one gives infinity.
align 16
p521_vadd_%1:
    P521_IS_ZERO rax, S_AZ
    test        rax, rax
    jnz         .take
    call        p521_add_raw_%1
    P521_IS_ZERO rax, S_T3                  ; H = 0?
    test        rax, rax
    jz          .sum
    P521_IS_ZERO rax, S_T5                  ; r = 0?
    test        rax, rax
    jz          .cancel
    P521_COPY   S_AX, S_IX, 27
    jmp         p521_dbl_%1                 ; (a tail call: it returns to our caller)
.cancel:
    xor         eax, eax
    mov         ecx, 27
    lea         rdi, [rbp + PF_AX]
    rep         stosq
    ret
.sum:
    P521_COPY   S_AX, S_RX, 27
    ret
.take:
    P521_COPY   S_AX, S_IX, 27
    ret

; p521_vmadd_v: p521_vadd_v's cases with IN affine (IX, IY; IZ = 1 set by the caller): the mixed
; addition leaves H in T1 and r in T2.
align 16
p521_vmadd_%1:
    P521_IS_ZERO rax, S_AZ
    test        rax, rax
    jnz         .take
    call        p521_madd_raw_%1
    P521_IS_ZERO rax, S_T1                  ; H = 0?
    test        rax, rax
    jz          .sum
    P521_IS_ZERO rax, S_T2                  ; r = 0?
    test        rax, rax
    jz          .cancel
    P521_COPY   S_AX, S_IX, 27
    jmp         p521_dbl_%1
.cancel:
    xor         eax, eax
    mov         ecx, 27
    lea         rdi, [rbp + PF_AX]
    rep         stosq
    ret
.sum:
    P521_COPY   S_AX, S_RX, 27
    ret
.take:
    P521_COPY   S_AX, S_IX, 27
    ret

; p521_affine_v: PX, PY = ACC in affine coordinates, ACC not infinity (Z's inverse, then X Z^-2
; and Y Z^-3: no form to leave, as the field's values are plain).
align 16
p521_affine_%1:
    P521_COPY   S_ZI, S_AZ, 9
    lea         rdi, [rbp + PF_ZI]
    lea         rsi, [rel p521_mod_p]
    call        p521_inverse
    F9_FSQR     %1, S_T0, S_ZI              ; Z^-2
    F9_FMUL     %1, S_PX, S_AX, S_T0
    F9_FMUL     %1, S_T0, S_T0, S_ZI        ; Z^-3
    F9_FMUL     %1, S_PY, S_AY, S_T0
    ret

; p521_mul_var_v: ACC = k P, k from PF_K2 (1 <= k < n), P affine in PX, PY. The table TAB[j] =
; (j + 1) P: (2j + 2) P by doubling (j + 1) P, (2j + 3) P by adding P to it. Then the top window
; (104: bits 519..524, a digit never negative) selects the start, and each window below doubles
; five times and adds its digit's point; window 0's addition is p521_add_last (the header's
; doubling case: the branch on the window number is on public data).
align 16
p521_mul_var_%1:
    P521_COPY   rbp + PF_TAB, S_PX, 18      ; x, y (PX and PY are adjacent)
    P521_COPY   rbp + PF_TAB + 144, rel p521_one, 9
    P521_COPY   S_IX, rbp + PF_TAB, 27      ; IN = P for the odd multiples
    mov         qword [rbp + PF_WIN], 0
.table:
    imul        rdx, [rbp + PF_WIN], 224
    P521_COPY   S_AX, rbp + PF_TAB + rdx, 27            ; (j + 1) P
    call        p521_dbl_%1
    imul        rdx, [rbp + PF_WIN], 448
    P521_COPY   rbp + PF_TAB + 224 + rdx, S_AX, 27      ; (2j + 2) P
    cmp         qword [rbp + PF_WIN], 7
    je          .table_done
    call        p521_add_%1
    imul        rdx, [rbp + PF_WIN], 448
    P521_COPY   rbp + PF_TAB + 448 + rdx, S_AX, 27      ; (2j + 3) P
    inc         qword [rbp + PF_WIN]
    jmp         .table
.table_done:
    mov         ecx, 104
    P521_DIGIT  5
    P521_SCAN_TAB_%1
    P521_COPY   S_AX, S_IX, 27              ; the start (zeros, infinity, for digit 0)
    mov         dword [rbp + PF_WIN], 103
.window:
    call        p521_dbl_%1
    call        p521_dbl_%1
    call        p521_dbl_%1
    call        p521_dbl_%1
    call        p521_dbl_%1
    mov         ecx, [rbp + PF_WIN]
    P521_DIGIT  5
    mov         [rbp + PF_SIGN], r12
    P521_SCAN_TAB_%1
    mov         r15, [rbp + PF_SIGN]
    F9_CNEG     r15, S_IY
    cmp         dword [rbp + PF_WIN], 0
    je          .last
    call        p521_add_%1
    dec         dword [rbp + PF_WIN]
    jmp         .window
.last:
    jmp         p521_add_last_%1            ; (a tail call: it returns to our caller)

; p521_mul_base_v: ACC = k G, k from PF_K2 (0 <= k < n: 0 gives infinity). Window i's digit
; selects from its own table, the sign negates y, and one mixed addition joins it.
align 16
p521_mul_base_%1:
    xor         eax, eax
    mov         ecx, 27
    lea         rdi, [rbp + PF_AX]
    rep         stosq                       ; ACC = infinity
    P521_COPY   S_IZ, rel p521_one, 9       ; the affine addend's Z for the selection
    mov         dword [rbp + PF_WIN], 0
.window:
    mov         ecx, [rbp + PF_WIN]
    P521_DIGIT  P521_W
    mov         [rbp + PF_SIGN], r12
    imul        eax, [rbp + PF_WIN], 144 << (P521_W - 1)  ; 2^(W - 1) points of 144 octets a window
    lea         rsi, [rel p521_base_table]
    add         rsi, rax
    P521_SCAN_BASE_%1
    mov         r15, [rbp + PF_SIGN]
    F9_CNEG     r15, S_IY
    call        p521_madd_%1
    inc         dword [rbp + PF_WIN]
    cmp         dword [rbp + PF_WIN], P521_WINDOWS
    jne         .window
    ret

; -----------------------------------------------------------------------------
; int p521_public_key_v(uint8_t out[133], const uint8_t key[66]): httpasm_p521_public_key.
; -----------------------------------------------------------------------------
align 16
p521_public_key_%1:
    P521_ENTER
    mov         [rbp + PF_OUT], rdi
    call        p521_load_scalar
    test        eax, eax
    jnz         .invalid
    call        p521_mul_base_%1
    call        p521_affine_%1
    mov         rdi, [rbp + PF_OUT]
    mov         byte [rdi], 4               ; SEC 1's uncompressed form
    inc         rdi
    lea         rsi, [S_PX]
    call        p521_store_be66
    mov         rdi, [rbp + PF_OUT]
    add         rdi, 67
    lea         rsi, [S_PY]
    call        p521_store_be66
    mov         qword [rbp + PF_RES], 0
    jmp         .done
.invalid:
    mov         rdi, [rbp + PF_OUT]
    xor         eax, eax
    mov         ecx, HTTPASM_P521_POINT
    rep         stosb
    mov         qword [rbp + PF_RES], -1
.done:
    P521_FINISH

; -----------------------------------------------------------------------------
; int p521_ecdh_v(uint8_t out[66], const uint8_t key[66], const uint8_t point[133]):
; httpasm_p521_ecdh.
; -----------------------------------------------------------------------------
align 16
p521_ecdh_%1:
    P521_ENTER
    mov         [rbp + PF_OUT], rdi
    mov         [rbp + PF_ARG], rdx
    call        p521_load_scalar
    test        eax, eax
    jnz         .invalid
    mov         rsi, [rbp + PF_ARG]
    call        p521_load_point
    test        eax, eax
    jnz         .invalid
    P521_ON_CURVE %1
    call        p521_mul_var_%1
    call        p521_affine_%1              ; (never infinity: k in [1, n), the point's order n)
    mov         rdi, [rbp + PF_OUT]
    lea         rsi, [S_PX]
    call        p521_store_be66
    mov         qword [rbp + PF_RES], 0
    jmp         .done
.invalid:
    mov         rdi, [rbp + PF_OUT]
    xor         eax, eax
    mov         ecx, HTTPASM_P521_SCALAR
    rep         stosb
    mov         qword [rbp + PF_RES], -1
.done:
    P521_FINISH

; -----------------------------------------------------------------------------
; int p521_sign_v(uint8_t signature[132], const uint8_t key[66], const uint8_t *digest,
;                 size_t length, const uint8_t *entropy): httpasm_p521_sign.
; -----------------------------------------------------------------------------
align 16
p521_sign_%1:
    P521_ENTER
    mov         [rbp + PF_OUT], rdi
    mov         [rbp + PF_ARG], rsi
    mov         [rbp + PF_ARG2], rdx
    mov         [rbp + PF_ARG3], rcx
    mov         [rbp + PF_ARG4], r8
    call        p521_load_scalar
    test        eax, eax
    jnz         .invalid
    P521_COPY   rbp + PF_D, rbp + PF_K, 9
    mov         rsi, [rbp + PF_ARG]
    lea         rdi, [rbp + PF_SEED + 65]   ; x = int2octets(d): the key's own 66 octets
    mov         ecx, 66
    rep         movsb
    mov         rsi, [rbp + PF_ARG2]
    mov         rdx, [rbp + PF_ARG3]
    call        p521_load_digest
    lea         rdi, [rbp + PF_SEED + 131]
    lea         rsi, [rbp + PF_E]
    call        p521_store_be66             ; h1 = bits2octets(digest) = int2octets(e)
    mov         qword [rbp + PF_SEEDN], 197
    mov         rsi, [rbp + PF_ARG4]
    test        rsi, rsi
    jz          .seeded
    lea         rdi, [rbp + PF_SEED + 197]  ; RFC 6979 3.6's k': the caller's entropy
    mov         ecx, 66
    rep         movsb
    mov         qword [rbp + PF_SEEDN], 263
.seeded:
    call        p521_drbg_init
.candidate:
    call        p521_drbg_next
    lea         rsi, [rbp + PF_TT]
    call        p521_load_candidate         ; k, when 1 <= k < n
    test        eax, eax
    jnz         .retry
    call        p521_mul_base_%1
    call        p521_affine_%1
    P521_COPY   rbp + PF_R, S_PX, 9
    F9_NREDUCE  rbp + PF_R                  ; r = x mod n
    P521_IS_ZERO rax, rbp + PF_R
    test        rax, rax
    jnz         .retry
    P521_COPY   rbp + PF_KINV, rbp + PF_K, 9
    lea         rdi, [rbp + PF_KINV]
    lea         rsi, [rel p521_mod_n]
    call        p521_inverse                ; k^-1
    ; s = k^-1 (e + r d): Montgomery products modulo n, each followed by one by R^2 (a b R^-1,
    ; then times R^2 R^-1: the plain product)
    F9_NMUL     rbp + PF_S, rbp + PF_R, rbp + PF_D
    F9_NMUL     rbp + PF_S, rbp + PF_S, rel p521_n_r2      ; r d
    F9_NADD     rbp + PF_S, rbp + PF_S, rbp + PF_E          ; e + r d
    F9_NMUL     rbp + PF_S, rbp + PF_S, rbp + PF_KINV
    F9_NMUL     rbp + PF_S, rbp + PF_S, rel p521_n_r2      ; s
    P521_IS_ZERO rax, rbp + PF_S
    test        rax, rax
    jnz         .retry
    mov         rdi, [rbp + PF_OUT]
    lea         rsi, [rbp + PF_R]
    call        p521_store_be66
    mov         rdi, [rbp + PF_OUT]
    add         rdi, 66
    lea         rsi, [rbp + PF_S]
    call        p521_store_be66
    mov         qword [rbp + PF_RES], 0
    jmp         .done
.retry:
    call        p521_drbg_reject
    jmp         .candidate
.invalid:
    mov         rdi, [rbp + PF_OUT]
    xor         eax, eax
    mov         ecx, HTTPASM_P521_SIGNATURE
    rep         stosb
    mov         qword [rbp + PF_RES], -1
.done:
    P521_FINISH

; -----------------------------------------------------------------------------
; int p521_verify_v(const uint8_t key[133], const uint8_t *digest, size_t length,
;                   const uint8_t signature[132]): httpasm_p521_verify. Every input is public:
; the branches below may follow them.
; -----------------------------------------------------------------------------
align 16
p521_verify_%1:
    P521_ENTER
    mov         [rbp + PF_ARG], rdi
    mov         [rbp + PF_ARG2], rsi
    mov         [rbp + PF_ARG3], rdx
    mov         [rbp + PF_ARG4], rcx
    mov         rsi, rcx
    call        p521_load_scalar            ; r in [1, n)
    test        eax, eax
    jnz         .invalid
    P521_COPY   rbp + PF_R, rbp + PF_K, 9
    mov         rsi, [rbp + PF_ARG4]
    add         rsi, 66
    call        p521_load_scalar            ; s in [1, n)
    test        eax, eax
    jnz         .invalid
    P521_COPY   rbp + PF_S, rbp + PF_K, 9
    mov         rsi, [rbp + PF_ARG]
    call        p521_load_point
    test        eax, eax
    jnz         .invalid
    P521_ON_CURVE %1
    mov         rsi, [rbp + PF_ARG2]
    mov         rdx, [rbp + PF_ARG3]
    call        p521_load_digest
    lea         rdi, [rbp + PF_S]
    lea         rsi, [rel p521_mod_n]
    call        p521_inverse                ; w = s^-1
    F9_NMUL     rbp + PF_U1, rbp + PF_E, rbp + PF_S
    F9_NMUL     rbp + PF_U1, rbp + PF_U1, rel p521_n_r2    ; u1 = e w
    F9_NMUL     rbp + PF_U2, rbp + PF_R, rbp + PF_S
    F9_NMUL     rbp + PF_U2, rbp + PF_U2, rel p521_n_r2    ; u2 = r w
    ; R = u1 G + u2 Q in one pass from the top (Straus): wNAF digits (u1 by 6 bits: G's odd
    ; multiples are in the fixed-base table's window 0, 1G..32G; u2 by 5 bits over Q's odd
    ; multiples 1Q..15Q, built here), the doublings shared; variable time, as every input is
    ; public, so the additions branch on the doubling and cancelling cases
    lea         rsi, [rbp + PF_U1]
    lea         rdi, [rbp + PF_DIG1]
    mov         ecx, 6
    call        p521_wnaf
    mov         [rbp + PF_LEN1], rax
    lea         rsi, [rbp + PF_U2]
    lea         rdi, [rbp + PF_DIG2]
    mov         ecx, 5
    call        p521_wnaf
    mov         [rbp + PF_LEN2], rax
    ; Q's odd multiples into TAB: Q, then 2Q into IN, then Q + 2Q, 3Q + 2Q, ... 13Q + 2Q (none of
    ; these additions meets equal or opposite points: (2j + 1) Q = +-2Q has no solution mod n)
    P521_COPY   S_AX, S_PX, 9
    P521_COPY   S_AY, S_PY, 9
    P521_COPY   S_AZ, rel p521_one, 9
    P521_COPY   rbp + PF_TAB, S_AX, 27
    call        p521_dbl_%1
    P521_COPY   S_IX, S_AX, 27              ; IN = 2Q
    P521_COPY   S_AX, rbp + PF_TAB, 27      ; ACC = Q
    mov         qword [rbp + PF_WIN], 1
.odd:
    call        p521_add_%1                 ; (2j + 1) Q
    imul        rdx, [rbp + PF_WIN], 224
    P521_COPY   rbp + PF_TAB + rdx, S_AX, 27
    inc         qword [rbp + PF_WIN]
    cmp         qword [rbp + PF_WIN], 8
    jne         .odd
    ; the pass: from the longer wNAF's top digit (nonzero by its length) down; the accumulator
    ; starts at infinity, so its first doubling is skipped
    xor         eax, eax
    mov         ecx, 27
    lea         rdi, [rbp + PF_AX]
    rep         stosq
    mov         rax, [rbp + PF_LEN1]
    cmp         rax, [rbp + PF_LEN2]
    cmovb       rax, [rbp + PF_LEN2]
    dec         rax
    mov         [rbp + PF_WIN], rax
    jmp         .digits                     ; (u2 is not 0: its wNAF has at least one digit)
.pass:
    call        p521_dbl_%1
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
    imul        edx, edx, 144
    lea         rsi, [rel p521_base_table]
    add         rsi, rdx
    P521_COPY   S_IX, rsi, 18
    P521_COPY   S_IZ, rel p521_one, 9
    mov         r15, [rbp + PF_SIGN]
    sar         r15, 63                     ; all ones for a negative digit
    F9_CNEG     r15, S_IY
    call        p521_vmadd_%1
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
    imul        edx, edx, 224
    P521_COPY   S_IX, rbp + PF_TAB + rdx, 27
    mov         r15, [rbp + PF_SIGN]
    sar         r15, 63
    F9_CNEG     r15, S_IY
    call        p521_vadd_%1
.next:
    dec         qword [rbp + PF_WIN]
    jns         .pass
    ; R at infinity (u1 G = -u2 Q, or a cancellation the pass met and never left): no x to
    ; compare, and (0, 0, 0) would pass X = r Z^2 below and accept a forgery
    P521_IS_ZERO rax, S_AZ
    test        rax, rax
    jnz         .invalid
    ; x(R) mod n = r without the inversion: X = r Z^2, or X = (r + n) Z^2 when r + n < p (x < p
    ; < 2n: those are the only x with x mod n = r)
    F9_FSQR     %1, S_T0, S_AZ
    F9_FMUL     %1, S_T2, rbp + PF_R, S_T0  ; (r < n < p: a field value as it is)
    P521_DIFFER S_T2, S_AX
    jz          .valid
    F9_LOAD     rbp + PF_R
    mov         rax, r8
    sub         rax, [rel p521_n_p]
    mov         rax, r9
    sbb         rax, [rel p521_n_p + 8]
    mov         rax, r10
    sbb         rax, [rel p521_n_p + 16]
    mov         rax, r11
    sbb         rax, [rel p521_n_p + 24]
    mov         rax, r12
    sbb         rax, [rel p521_n_p + 32]
    mov         rax, r13
    sbb         rax, [rel p521_n_p + 40]
    mov         rax, r14
    sbb         rax, [rel p521_n_p + 48]
    mov         rax, r15
    sbb         rax, [rel p521_n_p + 56]
    mov         rax, rbx
    sbb         rax, [rel p521_n_p + 64]
    jnc         .invalid                    ; r >= p - n: r + n is no field element
    add         r8, [rel p521_n]
    adc         r9, [rel p521_n + 8]
    adc         r10, [rel p521_n + 16]
    adc         r11, [rel p521_n + 24]
    adc         r12, [rel p521_n + 32]
    adc         r13, [rel p521_n + 40]
    adc         r14, [rel p521_n + 48]
    adc         r15, [rel p521_n + 56]
    adc         rbx, [rel p521_n + 64]
    F9_STORE    S_T1
    F9_FMUL     %1, S_T2, S_T1, S_T0
    P521_DIFFER S_T2, S_AX
    jnz         .invalid
.valid:
    mov         qword [rbp + PF_RES], 0
    jmp         .done
.invalid:
    mov         qword [rbp + PF_RES], -1
.done:
    P521_FINISH
%endmacro

P521_ROUTINES v3
P521_ROUTINES v1

; =============================================================================
; The C ABI: each picks v3 (BMI2, ADX and AVX2) or v1 and jumps there (tail calls: the version
; returns to our caller). httpasm.h says what each does.
; =============================================================================

; -----------------------------------------------------------------------------
; int httpasm_p521_public_key(uint8_t public_key[133], const uint8_t private_key[66])
; -----------------------------------------------------------------------------
global httpasm_p521_public_key:function (httpasm_p521_public_key.end - httpasm_p521_public_key)
align 16
httpasm_p521_public_key:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         p521_public_key_v1
.v3:
    jmp         p521_public_key_v3
.end:

; -----------------------------------------------------------------------------
; int httpasm_p521_ecdh(uint8_t shared[66], const uint8_t private_key[66],
;                       const uint8_t peer_key[133])
; -----------------------------------------------------------------------------
global httpasm_p521_ecdh:function (httpasm_p521_ecdh.end - httpasm_p521_ecdh)
align 16
httpasm_p521_ecdh:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         p521_ecdh_v1
.v3:
    jmp         p521_ecdh_v3
.end:

; -----------------------------------------------------------------------------
; int httpasm_p521_sign(uint8_t signature[132], const uint8_t private_key[66],
;                       const uint8_t *digest, size_t digest_length, const uint8_t *entropy)
; -----------------------------------------------------------------------------
global httpasm_p521_sign:function (httpasm_p521_sign.end - httpasm_p521_sign)
align 16
httpasm_p521_sign:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         p521_sign_v1
.v3:
    jmp         p521_sign_v3
.end:

; -----------------------------------------------------------------------------
; int httpasm_p521_verify(const uint8_t public_key[133], const uint8_t *digest,
;                         size_t digest_length, const uint8_t signature[132])
; -----------------------------------------------------------------------------
global httpasm_p521_verify:function (httpasm_p521_verify.end - httpasm_p521_verify)
align 16
httpasm_p521_verify:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         p521_verify_v1
.v3:
    jmp         p521_verify_v3
.end:
