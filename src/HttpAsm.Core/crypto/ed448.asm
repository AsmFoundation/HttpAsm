; =============================================================================
; crypto/ed448.asm - Ed448 (RFC 8032 5.2, pure EdDSA over edwards448 with SHAKE256 and dom4),
; for TLS 1.3's ed448 signature scheme (RFC 9846 4.2.3) and Ed448 certificates (RFC 8410): the C
; ABI's httpasm_ed448_public_key, httpasm_ed448_private_key_init, httpasm_ed448_sign and
; httpasm_ed448_verify; and X448's public keys from the same fixed base (ha_x448_base_v3 and
; _v1, which crypto/x448.asm's httpasm_x448_public_key calls).
;
; The field is include/crypto/fe448.inc's (X448's): eight 56-bit limbs at both versions, v3
; multiplying with mulx and scanning tables with AVX2, v1 with mul and SSE2. Every routine that
; touches the field is written once as a macro over the version (ED448_ROUTINES).
;
; The group: points in extended coordinates (X : Y : Z : T), x = X / Z, y = Y / Z, x y = T / Z
; (Hisil, Wong, Carter and Dawson), the formulas for a = 1 (edwards448 is untwisted): doubling
; dbl-2008-hwcd (4S + 4M), addition add-2008-hwcd (H = B - A: 9M and the product by d = -39081,
; a carry chain), and the mixed addition with a table point (x, y, d x y), Z = 1 (8M). They are
; COMPLETE on edwards448 (a = 1 is a square, d is not, modulo p): no input is exceptional, the
; neutral point (0 : 1 : 1 : 0) and doubling included, so no selection masks are needed. Their
; products come in pairs (fe448.inc's FE448_MUL2 / FE448_SQR2, interleaved: see x448.asm's
; measurements): a mixed addition is four pairs, a doubling two pairs of squares and two of
; products. Their sums run uncarried; the largest product input is a doubling's F = A + B - 2 Z^2
; (limbs below 6 2^56), far inside the 2^61 the products take (fe448.inc's bounds).
;
; The scalar multiplications:
;   - fixed base (public keys, R = r B, X448's public keys), constant time: signed 5-bit digits
;     (Booth), 90 windows covering 450 bits (any scalar below 2^448: Ed448's clamped s and X448's
;     k go in unreduced, since s B = (s mod L) B), each window with its own table of m 32^i B
;     (m = 1..16) as (x, y, d x y): 276,480 octets in include/generated/ed448_table.inc, written
;     and proven by specs/ed448.cs. A window's digit selects its entry by a scan that reads all
;     16 (AVX2 at v3, SSE2 at v1), a negative digit takes 2p - x and 2p - d x y, digit 0 gives
;     the neutral (0, 1, 0); one mixed addition a window, no doubling;
;   - verification, variable time (every input public): [S]B + [k](-A) in one pass from the top
;     (Straus), wNAF digits of width 5 for both: S's over window 0 of the table (its odd entries
;     1B..15B), k's over -A's odd multiples 1..15 (extended, built per call), the doublings shared.
;
; X448's public key: RFC 7748 4.2's 4-isogeny takes edwards448's B to curve448's base point,
; u = y^2 / x^2 = 5 (specs/ed448.cs proves it), and maps k B to X448(k, 5) for every k: so the
; public key is (Y / X)^2 of k B from this table: one fixed-base multiplication and an inversion
; instead of the 448-step ladder. k = 4q (the one clamped scalar with a zero key) gives the
; neutral point, X = 0, whose inverse the chain makes 0: u = 0 and -1, as the ladder gives.
;
; Signing with a prepared key (httpasm_ed448_private_key_init: s = clamp(SHAKE256(seed,
; 114)[0..57]) (the two low bits cleared, the 57th octet dropped, bit 447 set), the prefix the
; hash's last 57 octets, A = s B computed here): RFC 8032 5.2.6's r = SHAKE256(dom4(0, C) ||
; prefix || M, 114) mod L, R = r B, k = SHAKE256(dom4(0, C) || R || A || M, 114) mod L, S = r +
; k s mod L. The key carries its own A: an API that took the public key from the caller would let
; a mismatched one leak the private key (r does not depend on A).
;
; Verification (RFC 8032 5.2.7, cofactorless, as httpasm_ed25519_verify): the signature is 114
; octets; S must be below L (non-malleable; its 57th octet zero); A must decode (RFC 8032 5.2.3:
; the last octet's low seven bits zero, y below p, x recovered, x = 0 with the sign bit set
; refused); then the encoding of [S]B - [k]A must equal R's octets (a non-canonical R never
; matches).
;
; The context C: any 0 to 255 octets (RFC 8032's dom4); TLS 1.3 signs with an empty one. A longer
; one is refused (-1, nothing written).
;
; Scalars modulo L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
; by Montgomery products over seven limbs (R = 2^448), with mul at both versions (a signature
; takes ten): a 912-bit hash h = h2 R^2 + h1 R + h0 reduces as REDC(REDC(h2 R^4) + REDC(h1 R^3) +
; REDC(h0 R^2)), S as REDC(REDC(k s) R^2) + r, one conditional subtraction each.
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "crypto/fe448.inc"

extern ha_fe448_2p                          ; crypto/x448.asm: 2p, limb by limb (fe448.inc's sums)
extern ha_fe448_mul_v3                      ; crypto/x448.asm: the field functions, per version
extern ha_fe448_mul_v1
extern ha_fe448_sqr_v3
extern ha_fe448_sqr_v1
extern ha_fe448_invert_v3
extern ha_fe448_invert_v1
extern ha_fe448_pow_p34_v3
extern ha_fe448_pow_p34_v1
extern httpasm_shake256                     ; crypto/sha3.asm: the one-shot XOF, and the running one
extern httpasm_shake256_init
extern httpasm_sha3_update
extern httpasm_shake_squeeze

section .rodata
%include "generated/ed448_table.inc"
align 64
ed448_one:  dq 1, 0, 0, 0, 0, 0, 0, 0       ; 1 (a field element; a scalar too: seven qwords and 0)
ed448_zero: dq 0, 0, 0, 0, 0, 0, 0, 0       ; 0 (0 - a = 2p - a, fe448.inc's negation)
; The neutral point's table form (x, y, d x y) = (0, 1, 0): the digit 0's entry.
ed448_neutral_entry:
    dq 0, 0, 0, 0, 0, 0, 0, 0
    dq 1, 0, 0, 0, 0, 0, 0, 0
    dq 0, 0, 0, 0, 0, 0, 0, 0
align 16
ed448_dw_one: dd 1, 1, 1, 1                 ; v1's scan: the entry counter's step, in every dword
ed448_dom4: db "SigEd448"                   ; dom4's first eight octets (RFC 8032 2)

section .text

; -----------------------------------------------------------------------------
; The frame (rbp, 64-aligned), the same at both versions. Everything below EF_END is wiped before
; a function returns (the private scalar, r, the hashes, every intermediate point).
; -----------------------------------------------------------------------------
EF_PX       equ FT_SIZE                     ; the accumulator (X : Y : Z : T), after the products' scratch
EF_PY       equ EF_PX + 64
EF_PZ       equ EF_PY + 64
EF_PT       equ EF_PZ + 64
EF_QX       equ EF_PT + 64                  ; the point added: a table entry (x, y, -, d x y), or (X : Y : Z : T)
EF_QY       equ EF_QX + 64
EF_QZ       equ EF_QY + 64
EF_QT       equ EF_QZ + 64
EF_TA       equ EF_QT + 64                  ; the formulas' values
EF_TB       equ EF_TA + 64
EF_TC       equ EF_TB + 64
EF_TD       equ EF_TC + 64
EF_TE       equ EF_TD + 64
EF_TF       equ EF_TE + 64
EF_TG       equ EF_TF + 64
EF_TH       equ EF_TG + 64
EF_TS       equ EF_TH + 64
EF_TS2      equ EF_TS + 64
EF_ODD      equ EF_TS2 + 64                 ; verification: -A's odd multiples 1, 3, .., 15 (8 points, 256 octets each)
EF_SS       equ EF_ODD + 2048               ; scalars, eight qwords each (the eighth 0): s, or X448's k
EF_SR       equ EF_SS + 64                  ; r
EF_SK       equ EF_SR + 64                  ; k
EF_ST       equ EF_SK + 64                  ; scalar temporaries
EF_SU       equ EF_ST + 64
EF_SV       equ EF_SU + 64
EF_SP       equ EF_SV + 64                  ; a Montgomery product's 15 qwords (128 kept)
EF_DIG      equ EF_SP + 128                 ; the fixed base's 90 signed digits; S's wNAF (verification: up to 449)
EF_DIG2     equ EF_DIG + 456                ; k's wNAF
EF_HASH     equ EF_DIG2 + 456               ; SHAKE256's 114 octets (128 kept)
EF_SHA3     equ EF_HASH + 128               ; the running SHAKE256 (httpasm_sha3_ctx: 216 octets, 256 kept)
EF_RENC     equ EF_SHA3 + 256               ; R's encoding (57 octets, 64 kept)
EF_AENC     equ EF_RENC + 64                ; A's encoding
EF_DOM      equ EF_AENC + 64                ; dom4's first ten octets: "SigEd448", 0, the context's length
EF_OUT      equ EF_DOM + 16                 ; the output's address
EF_KEY      equ EF_OUT + 8                  ; the key's address
EF_MSG      equ EF_KEY + 8                  ; the message's address
EF_LEN      equ EF_MSG + 8                  ; its length
EF_CTX      equ EF_LEN + 8                  ; the context's address
EF_CTXLEN   equ EF_CTX + 8                  ; its length
EF_SIG      equ EF_CTXLEN + 8               ; the signature's address (verification)
EF_P1       equ EF_SIG + 8                  ; ed448_hash's first part and its length
EF_P1LEN    equ EF_P1 + 8
EF_P2       equ EF_P1LEN + 8                ; its second part and length
EF_P2LEN    equ EF_P2 + 8
EF_IDX      equ EF_P2LEN + 8                ; a loop's index
EF_TOP      equ EF_IDX + 8                  ; verification: the top digit's index
EF_PAR      equ EF_TOP + 8                  ; a parity / sign bit kept across calls
EF_RES      equ EF_PAR + 8                  ; the result
EF_END      equ EF_RES + 8
EF_OLDSP    equ EF_END                      ; rsp before the frame (read last: not wiped)
EF_FRAME    equ EF_OLDSP + 8

; ED_ENTER: the callee-saved registers pushed, then the frame taken a page at a time
; (HA_STACK_DOWN: it passes 4 KiB, and a stack nearly spent must fault on its guard), aligned
; to 64. Keeps rdi, rsi, rdx, rcx, r8, r9 (the arguments).
%macro ED_ENTER 0
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    and         rsp, -64
    HA_STACK_DOWN EF_FRAME, r11d
    mov         rbp, rsp
    mov         [rbp + EF_OLDSP], rax
%endmacro

; ED_FINISH v: eax = EF_RES's low dword after the frame below EF_END is wiped, the upper halves
; of the vector registers cleared at v3, the registers restored; returns.
%macro ED_FINISH 1
    mov         r8, [rbp + EF_RES]
    xor         eax, eax
    mov         ecx, EF_END / 8
    mov         rdi, rbp
    rep         stosq
  %ifidn %1, v3
    vzeroupper
  %endif
    mov         eax, r8d
    mov         rsp, [rbp + EF_OLDSP]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret
%endmacro

; ED_COPY dst, src: one element (64 octets) by qwords (fe448.inc's rule: elements move as qwords).
; Clobbers rax.
%macro ED_COPY 2
  %assign q 0
  %rep 8
    mov         rax, [%2 + q]
    mov         [%1 + q], rax
    %assign q q + 8
  %endrep
%endmacro

; ED_DIFFER slot: ZF set when the limbs in r8-r15 (FE448_STRONG's) equal the eight qwords at
; slot, clear otherwise: the OR of their XORs, for one branch on the whole comparison. Clobbers
; rax, rdx and the flags.
%macro ED_DIFFER 1
    xor         eax, eax
  %assign q 0
  %rep 8
    mov         rdx, [%1 + q]
    xor         rdx, r %+ %eval(8 + q / 8)
    or          rax, rdx
    %assign q q + 8
  %endrep
%endmacro

; ED_SET_NEUTRAL: the accumulator = (0 : 1 : 1 : 0). Clobbers rax.
%macro ED_SET_NEUTRAL 0
    xor         eax, eax
  %assign q 0
  %rep 8
    mov         [rbp + EF_PX + q], rax
    mov         [rbp + EF_PY + q], rax
    mov         [rbp + EF_PZ + q], rax
    mov         [rbp + EF_PT + q], rax
    %assign q q + 8
  %endrep
    mov         qword [rbp + EF_PY], 1
    mov         qword [rbp + EF_PZ], 1
%endmacro

; =============================================================================
; Version-independent routines: the digits, the scalars, the hashes. rbp = a function's frame.
; =============================================================================

; -----------------------------------------------------------------------------
; ed448_recode: EF_DIG = the 90 signed digits of the scalar at [rsi] (eight qwords, the eighth
; 0, the value below 2^448): window i's five bits plus the window below's carry v (0..32), digit
; v - 32 [v > 16], carry [v > 16] (Booth), so that the scalar = sum d_i 32^i with d_i in -16..16.
; Constant time: every address follows i, never the scalar. Clobbers rax, rcx, rdx, r8-r10 and
; the flags.
; -----------------------------------------------------------------------------
align 16
ed448_recode:
    xor         r9d, r9d                    ; the carry
    xor         r10d, r10d                  ; i
.digit:
    lea         eax, [r10 + r10 * 4]        ; 5 i: the window's lowest bit
    mov         ecx, eax
    shr         eax, 6                      ; its qword (6 at most: the eighth qword is read, 0)
    and         ecx, 63
    mov         r8, [rsi + rax * 8]
    mov         rdx, [rsi + rax * 8 + 8]
    shrd        r8, rdx, cl                 ; (a count of 0 leaves r8 as it is)
    and         r8d, 31
    add         r8d, r9d                    ; v = the bits + the carry
    lea         r9d, [r8 + 15]
    shr         r9d, 5                      ; carry = v > 16
    mov         eax, r9d
    shl         eax, 5
    sub         r8d, eax                    ; d = v - 32 carry
    mov         [rbp + EF_DIG + r10], r8b
    inc         r10d
    cmp         r10d, ED448_WINDOWS
    jb          .digit
    ret

; -----------------------------------------------------------------------------
; sc_mont: [rdi] = [rsi] [rcx] R^-1 mod L (R = 2^448), fully reduced, as eight qwords (the eighth
; 0); [rsi] and [rcx] seven qwords each (an eighth ignored) whose product is below L R (one below
; 2^448, the other below L, as every call here has it). Schoolbook into EF_SP's 15 qwords, then
; seven Montgomery steps (m = t_i (-L^-1) mod 2^64, t += m L 2^(64 i)), which leave t / R below
; 2L, then L subtracted when that does not borrow (by mask). Constant time. rdi may be rsi or
; rcx (the output is written last). Clobbers rax, rbx, rdx, r8-r11 and the flags.
; -----------------------------------------------------------------------------
align 16
sc_mont:
    xor         eax, eax
  %assign q 0
  %rep 15
    mov         [rbp + EF_SP + q], rax
    %assign q q + 8
  %endrep
    ; The product, row by row: t[i .. i + 7] += a b_i.
    xor         r10d, r10d                  ; i
.row:
    xor         r9d, r9d                    ; the carry
    xor         r11d, r11d                  ; j
.column:
    mov         rax, [rsi + r11 * 8]
    mul         qword [rcx + r10 * 8]
    lea         r8, [r10 + r11]
    add         rax, [rbp + EF_SP + r8 * 8]
    adc         rdx, 0
    add         rax, r9
    adc         rdx, 0
    mov         [rbp + EF_SP + r8 * 8], rax
    mov         r9, rdx
    inc         r11d
    cmp         r11d, 7
    jb          .column
    mov         [rbp + EF_SP + r10 * 8 + 56], r9
    inc         r10d
    cmp         r10d, 7
    jb          .row
    ; The reduction: for each i, m = t_i L0, t[i ..] += m L, the carry run to the top (every
    ; word, whatever the carry: constant time). L's address in rbx (a rip-relative operand
    ; takes no index register).
    lea         rbx, [rel ed448_l]
    xor         r10d, r10d
.reduce:
    mov         rax, [rbp + EF_SP + r10 * 8]
    imul        rax, [rel ed448_l0]
    mov         [rbp + EF_SP + 120], rax    ; m (EF_SP's sixteenth qword)
    xor         r9d, r9d
    xor         r11d, r11d
.reduce_column:
    mov         rax, [rbx + r11 * 8]
    mul         qword [rbp + EF_SP + 120]
    lea         r8, [r10 + r11]
    add         rax, [rbp + EF_SP + r8 * 8]
    adc         rdx, 0
    add         rax, r9
    adc         rdx, 0
    mov         [rbp + EF_SP + r8 * 8], rax
    mov         r9, rdx
    inc         r11d
    cmp         r11d, 7
    jb          .reduce_column
    lea         r8, [r10 + 7]               ; the carry into t[i + 7], then up through t[14]
.carry:
    add         [rbp + EF_SP + r8 * 8], r9
    mov         r9d, 0
    adc         r9d, 0
    inc         r8d
    cmp         r8d, 15
    jb          .carry
    inc         r10d
    cmp         r10d, 7
    jb          .reduce
    ; t[7 .. 13] (below 2L; t[14] is 0): minus L, kept when it did not borrow.
  %assign q 0
  %rep 7
    mov         rax, [rbp + EF_SP + 56 + q]
    %if q == 0
    sub         rax, [rel ed448_l + q]
    %else
    sbb         rax, [rel ed448_l + q]
    %endif
    mov         [rbp + EF_SP + q], rax      ; (t[0 .. 6] are spent: the difference goes there)
    %assign q q + 8
  %endrep
    sbb         r9, r9                      ; all ones when it borrowed: keep t
  %assign q 0
  %rep 7
    mov         rax, [rbp + EF_SP + 56 + q]
    mov         rdx, [rbp + EF_SP + q]
    xor         rax, rdx
    and         rax, r9
    xor         rax, rdx                    ; borrowed ? t : t - L
    mov         [rdi + q], rax
    %assign q q + 8
  %endrep
    mov         qword [rdi + 56], 0
    ret

; -----------------------------------------------------------------------------
; sc_reduce912: [rdi] = the 114-octet little-endian hash at [rsi] modulo L, eight qwords (the
; eighth 0): h = h2 R^2 + h1 R + h0 (h0, h1 the first two 56-octet parts, h2 the last two
; octets) as REDC(REDC(h2 R^4) + REDC(h1 R^3) + REDC(h0 R^2)): each REDC below L, their sum
; below 3L, then R^-1 times it is h. Uses EF_ST, EF_SU, EF_SV and EF_SP; rdi must not be one of
; them. Clobbers rax, rcx, rdx, rsi, r8-r11 and the flags; keeps rdi.
; -----------------------------------------------------------------------------
align 16
sc_reduce912:
    ; h0 into EF_ST, h1 into EF_SU, h2 into EF_SV (eight qwords each, zero-extended).
  %assign q 0
  %rep 7
    mov         rax, [rsi + q]
    mov         [rbp + EF_ST + q], rax
    mov         rax, [rsi + 56 + q]
    mov         [rbp + EF_SU + q], rax
    %assign q q + 8
  %endrep
    movzx       eax, word [rsi + 112]
    mov         [rbp + EF_SV], rax
    xor         eax, eax
    mov         [rbp + EF_ST + 56], rax
    mov         [rbp + EF_SU + 56], rax
  %assign q 8
  %rep 7
    mov         [rbp + EF_SV + q], rax
    %assign q q + 8
  %endrep
    push        rdi
    lea         rdi, [rbp + EF_SV]
    lea         rsi, [rbp + EF_SV]
    lea         rcx, [rel ed448_r4]
    call        sc_mont                     ; h2 R^3
    lea         rdi, [rbp + EF_SU]
    lea         rsi, [rbp + EF_SU]
    lea         rcx, [rel ed448_r3]
    call        sc_mont                     ; h1 R^2
    lea         rdi, [rbp + EF_ST]
    lea         rsi, [rbp + EF_ST]
    lea         rcx, [rel ed448_r2]
    call        sc_mont                     ; h0 R
    ; The sum (below 3L < 2^448: seven qwords hold it) into EF_ST.
    mov         rax, [rbp + EF_ST]
    add         rax, [rbp + EF_SU]
    mov         [rbp + EF_ST], rax
  %assign q 8
  %rep 6
    mov         rax, [rbp + EF_ST + q]
    adc         rax, [rbp + EF_SU + q]
    mov         [rbp + EF_ST + q], rax
    %assign q q + 8
  %endrep
    mov         rax, [rbp + EF_ST]
    add         rax, [rbp + EF_SV]
    mov         [rbp + EF_ST], rax
  %assign q 8
  %rep 6
    mov         rax, [rbp + EF_ST + q]
    adc         rax, [rbp + EF_SV + q]
    mov         [rbp + EF_ST + q], rax
    %assign q q + 8
  %endrep
    pop         rdi
    lea         rsi, [rbp + EF_ST]
    lea         rcx, [rel ed448_one]
    jmp         sc_mont                     ; (its ret returns for us) h = R^-1 (R h)

; -----------------------------------------------------------------------------
; ed448_hash: EF_HASH = SHAKE256(dom4(0, context) || part 1 || part 2 || message, 114) (RFC 8032
; 5.2's H with dom4), part 1 at EF_P1 (EF_P1LEN octets), part 2 at EF_P2 (EF_P2LEN, 0 for none),
; the context and the message at EF_CTX/EF_CTXLEN and EF_MSG/EF_LEN; EF_DOM holds dom4's first
; ten octets. C calls: clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
ed448_hash:
    sub         rsp, 8                      ; (called from a 16-aligned frame: the C calls need it again)
    lea         rdi, [rbp + EF_SHA3]
    call        httpasm_shake256_init
    lea         rdi, [rbp + EF_SHA3]
    lea         rsi, [rbp + EF_DOM]
    mov         edx, 10
    call        httpasm_sha3_update
    lea         rdi, [rbp + EF_SHA3]
    mov         rsi, [rbp + EF_CTX]
    mov         rdx, [rbp + EF_CTXLEN]
    call        httpasm_sha3_update         ; (a length of 0 reads nothing)
    lea         rdi, [rbp + EF_SHA3]
    mov         rsi, [rbp + EF_P1]
    mov         rdx, [rbp + EF_P1LEN]
    call        httpasm_sha3_update
    lea         rdi, [rbp + EF_SHA3]
    mov         rsi, [rbp + EF_P2]
    mov         rdx, [rbp + EF_P2LEN]
    call        httpasm_sha3_update
    lea         rdi, [rbp + EF_SHA3]
    mov         rsi, [rbp + EF_MSG]
    mov         rdx, [rbp + EF_LEN]
    call        httpasm_sha3_update
    lea         rdi, [rbp + EF_SHA3]
    lea         rsi, [rbp + EF_HASH]
    mov         edx, 114
    add         rsp, 8
    jmp         httpasm_shake_squeeze       ; (its ret returns for us)

; -----------------------------------------------------------------------------
; ed448_dom: EF_DOM = "SigEd448" || 0 || the context's length (EF_CTXLEN, at most 255: checked
; by the caller). Clobbers rax.
; -----------------------------------------------------------------------------
align 16
ed448_dom:
    mov         rax, [rel ed448_dom4]
    mov         [rbp + EF_DOM], rax
    mov         byte [rbp + EF_DOM + 8], 0
    mov         rax, [rbp + EF_CTXLEN]
    mov         [rbp + EF_DOM + 9], al
    ret

; -----------------------------------------------------------------------------
; ed448_clamp: EF_SS = the scalar from the 56 octets at [rsi], clamped (RFC 8032 5.2.5 and
; RFC 7748 5: the two low bits cleared, bit 447 set), eight qwords (the eighth 0). Clobbers rax.
; -----------------------------------------------------------------------------
align 16
ed448_clamp:
  %assign q 0
  %rep 7
    mov         rax, [rsi + q]
    %if q == 0
    and         rax, -4
    %elif q == 48
    bts         rax, 63
    %endif
    mov         [rbp + EF_SS + q], rax
    %assign q q + 8
  %endrep
    mov         qword [rbp + EF_SS + 56], 0
    ret

; -----------------------------------------------------------------------------
; ed448_wnaf: the width-5 NAF of the scalar at [rsi] (seven qwords, below 2^447) as signed bytes
; at [rdi] (450 of them, from the lowest bit; each nonzero digit odd in -15..15 with four zeros
; above it). Variable time (verification's public scalars). Uses EF_SP as the running value.
; Returns eax = the index of the highest nonzero digit + 1 (0 for a zero scalar). Clobbers rax,
; rcx, rdx, r8-r11 and the flags.
; -----------------------------------------------------------------------------
align 16
ed448_wnaf:
  %assign q 0
  %rep 7
    mov         rax, [rsi + q]
    mov         [rbp + EF_SP + q], rax
    %assign q q + 8
  %endrep
    mov         qword [rbp + EF_SP + 56], 0
    xor         r10d, r10d                  ; the bit index
    xor         r11d, r11d                  ; the top + 1
.bit:
    mov         rax, [rbp + EF_SP]
    xor         edx, edx                    ; the digit: 0 unless this bit is set
    test        al, 1
    jz          .store
    mov         edx, eax
    and         edx, 31
    cmp         edx, 16
    jb          .positive
    sub         edx, 32                     ; -15 .. -1
.positive:
    ; value -= digit (a small signed number), across the eight qwords
    movsx       rcx, edx
    mov         r8, rcx
    sar         r8, 63                      ; the digit's sign, extended (before the borrow chain:
    sub         [rbp + EF_SP], rcx          ; sar writes CF)
  %assign q 8
  %rep 7
    sbb         [rbp + EF_SP + q], r8
    %assign q q + 8
  %endrep
    lea         r11d, [r10 + 1]
.store:
    mov         [rdi + r10], dl
    ; value >>= 1
  %assign q 0
  %rep 7
    mov         rax, [rbp + EF_SP + q + 8]
    shrd        [rbp + EF_SP + q], rax, 1
    %assign q q + 8
  %endrep
    shr         qword [rbp + EF_SP + 56], 1
    inc         r10d
    cmp         r10d, 450
    jb          .bit
    mov         eax, r11d
    ret

; =============================================================================
; ED448_ROUTINES v: the field-dependent routines at version v (v3 or v1).
; =============================================================================
%macro ED448_ROUTINES 1
  %ifidn %1, v3
    %xdefine EP FE448_PROD_V3
    %xdefine EP2 FE448_PROD2_V3
  %else
    %xdefine EP FE448_PROD_V1
    %xdefine EP2 FE448_PROD2_V1
  %endif

; ed448_add_mixed_v: the accumulator += the table entry in EF_QX (x), EF_QY (y), EF_QT (d x y),
; Z = 1: A = X1 x, B = Y1 y, C = T1 d x y, E = (X1 + Y1)(x + y) - A - B, F = Z1 - C, G = Z1 + C,
; H = B - A, then (E F : G H : F G : E H). Clobbers every register but rbp and rsp.
align 32
ed448_add_mixed_%1:
    FE448_MUL2  EP, rbp + EF_TA, rbp + EF_PX, rbp + EF_QX, rbp + EF_TB, rbp + EF_PY, rbp + EF_QY
    FE448_ADD   rbp + EF_TS, rbp + EF_PX, rbp + EF_PY
    FE448_ADD   rbp + EF_TS2, rbp + EF_QX, rbp + EF_QY
    FE448_MUL2  EP, rbp + EF_TC, rbp + EF_PT, rbp + EF_QT, rbp + EF_TE, rbp + EF_TS, rbp + EF_TS2
    FE448_SUB   rbp + EF_TE, rbp + EF_TE, rbp + EF_TA
    FE448_SUB   rbp + EF_TE, rbp + EF_TE, rbp + EF_TB
    FE448_SUB   rbp + EF_TF, rbp + EF_PZ, rbp + EF_TC
    FE448_ADD   rbp + EF_TG, rbp + EF_PZ, rbp + EF_TC
    FE448_SUB   rbp + EF_TH, rbp + EF_TB, rbp + EF_TA
    FE448_MUL2  EP, rbp + EF_PX, rbp + EF_TE, rbp + EF_TF, rbp + EF_PY, rbp + EF_TG, rbp + EF_TH
    FE448_MUL2  EP, rbp + EF_PT, rbp + EF_TE, rbp + EF_TH, rbp + EF_PZ, rbp + EF_TF, rbp + EF_TG
    ret

; ed448_add_full_v: the accumulator += the point (X : Y : Z : T) in EF_QX .. EF_QT:
; add-2008-hwcd with a = 1, C = d T1 T2 taken as -39081 (T1 T2) by a carry chain.
align 32
ed448_add_full_%1:
    FE448_MUL2  EP, rbp + EF_TA, rbp + EF_PX, rbp + EF_QX, rbp + EF_TB, rbp + EF_PY, rbp + EF_QY
    FE448_ADD   rbp + EF_TS, rbp + EF_PX, rbp + EF_PY
    FE448_ADD   rbp + EF_TS2, rbp + EF_QX, rbp + EF_QY
    FE448_MUL2  EP, rbp + EF_TC, rbp + EF_PT, rbp + EF_QT, rbp + EF_TD, rbp + EF_PZ, rbp + EF_QZ
    FE448_MUL1  EP, rbp + EF_TE, rbp + EF_TS, rbp + EF_TS2
    FE448_MULW  rbp + EF_TC, rbp + EF_TC, 39081         ; 39081 T1 T2 = -d T1 T2 = -C
    ; With C' = -C: F = D - C = D + C', G = D + C = D - C'; then the shared ending with Z1 Z2 = D.
    FE448_SUB   rbp + EF_TE, rbp + EF_TE, rbp + EF_TA
    FE448_SUB   rbp + EF_TE, rbp + EF_TE, rbp + EF_TB
    FE448_ADD   rbp + EF_TF, rbp + EF_TD, rbp + EF_TC
    FE448_SUB   rbp + EF_TG, rbp + EF_TD, rbp + EF_TC
    FE448_SUB   rbp + EF_TH, rbp + EF_TB, rbp + EF_TA
    FE448_MUL2  EP, rbp + EF_PX, rbp + EF_TE, rbp + EF_TF, rbp + EF_PY, rbp + EF_TG, rbp + EF_TH
    FE448_MUL2  EP, rbp + EF_PT, rbp + EF_TE, rbp + EF_TH, rbp + EF_PZ, rbp + EF_TF, rbp + EF_TG
    ret

; ed448_dbl_v: the accumulator doubled (dbl-2008-hwcd, a = 1): A = X1^2, B = Y1^2, C = 2 Z1^2,
; E = (X1 + Y1)^2 - A - B, G = A + B, F = G - C, H = A - B, then (E F : G H : F G : E H).
align 32
ed448_dbl_%1:
    FE448_SQR2  EP, EP2, rbp + EF_TA, rbp + EF_PX, rbp + EF_TB, rbp + EF_PY
    FE448_ADD   rbp + EF_TS, rbp + EF_PX, rbp + EF_PY
    FE448_SQR2  EP, EP2, rbp + EF_TC, rbp + EF_PZ, rbp + EF_TE, rbp + EF_TS
    FE448_SUB   rbp + EF_TE, rbp + EF_TE, rbp + EF_TA
    FE448_SUB   rbp + EF_TE, rbp + EF_TE, rbp + EF_TB
    FE448_ADD   rbp + EF_TG, rbp + EF_TA, rbp + EF_TB
    FE448_SUB   rbp + EF_TF, rbp + EF_TG, rbp + EF_TC   ; F = G - Z1^2 - Z1^2 (each subtrahend a
    FE448_SUB   rbp + EF_TF, rbp + EF_TF, rbp + EF_TC   ; product's output, as SUB requires)
    FE448_SUB   rbp + EF_TH, rbp + EF_TA, rbp + EF_TB
    FE448_MUL2  EP, rbp + EF_PX, rbp + EF_TE, rbp + EF_TF, rbp + EF_PY, rbp + EF_TG, rbp + EF_TH
    FE448_MUL2  EP, rbp + EF_PT, rbp + EF_TE, rbp + EF_TH, rbp + EF_PZ, rbp + EF_TF, rbp + EF_TG
    ret

; ed448_fixed_base_v: the accumulator = k B for the digits in EF_DIG (ed448_recode's): from the
; neutral point, each window's entry selected (ed448_select_v) and added. Clobbers every register
; but rbp and rsp.
align 32
ed448_fixed_base_%1:
    ED_SET_NEUTRAL
    mov         dword [rbp + EF_IDX], 0
.window:
    mov         ecx, [rbp + EF_IDX]
    movsx       edx, byte [rbp + EF_DIG + rcx]
    call        ed448_select_%1
    call        ed448_add_mixed_%1
    inc         dword [rbp + EF_IDX]
    cmp         dword [rbp + EF_IDX], ED448_WINDOWS
    jb          .window
    ret

; ed448_encode_v: the accumulator's encoding (RFC 8032 5.2.2) at [rdi], 57 octets: y fully
; reduced, little-endian, then the octet holding x's parity in its top bit. One inversion of Z
; (fe448's chain: constant time). Clobbers every register but rbp and rsp.
align 32
ed448_encode_%1:
    mov         [rbp + EF_P1], rdi
    lea         rdi, [rbp + EF_TA]
    lea         rsi, [rbp + EF_PZ]
    call        ha_fe448_invert_%1          ; 1 / Z
    FE448_MUL2  EP, rbp + EF_TB, rbp + EF_PX, rbp + EF_TA, rbp + EF_TC, rbp + EF_PY, rbp + EF_TA
    FE448_STRONG rbp + EF_TB                ; x, fully reduced: its parity
    and         r8d, 1
    mov         [rbp + EF_PAR], r8
    FE448_STRONG rbp + EF_TC
    mov         rdi, [rbp + EF_P1]
    FE448_STORE56 rdi
    mov         rax, [rbp + EF_PAR]
    shl         eax, 7
    mov         [rdi + 56], al
    ret

; ed448_x448_u_v: u = (Y / X)^2 of the accumulator (the 4-isogeny's image of k B: X448(k, 5)),
; fully reduced, 56 octets at [rdi]; rax = the OR of its limbs (0 only for u = 0: X = 0, the
; neutral point, inverted to 0). Clobbers every register but rbp and rsp.
align 32
ed448_x448_u_%1:
    mov         [rbp + EF_P1], rdi
    lea         rdi, [rbp + EF_TA]
    lea         rsi, [rbp + EF_PX]
    call        ha_fe448_invert_%1          ; 1 / X
    FE448_MUL1  EP, rbp + EF_TB, rbp + EF_PY, rbp + EF_TA
    FE448_SQR1  EP, EP2, rbp + EF_TC, rbp + EF_TB
    mov         rdi, [rbp + EF_P1]
    FE448_ENCODE rdi, rbp + EF_TC
    ret

; ed448_decode_v: the point encoded at [rsi] (57 octets, RFC 8032 5.2.3) into EF_QX .. EF_QT as
; (x : y : 1 : x y); eax = 0, or -1 when the octets encode no point: the last octet's low seven
; bits set, y not below p, no square root for x^2 = (y^2 - 1) / (d y^2 - 1), or x = 0 with the
; sign bit set. x = u^3 v (u^5 v^3)^((p - 3) / 4) with u = y^2 - 1, v = d y^2 - 1, checked by
; v x^2 = u. Variable time (public keys only). Clobbers every register but rbp and rsp.
align 32
ed448_decode_%1:
    movzx       eax, byte [rsi + 56]
    test        al, 0x7F
    jnz         .refused
    shr         eax, 7
    mov         [rbp + EF_PAR], rax         ; x's sign bit
    FE448_DECODE rbp + EF_QY, rsi
    ; y below p: the full reduction must leave every limb as decoded (one decision on the OR of
    ; the limbs' differences: a branch per limb would have edges no input reaches, since a y of p
    ; or more always differs in its lowest limb).
    FE448_STRONG rbp + EF_QY
    ED_DIFFER   rbp + EF_QY
    jnz         .refused
    ; u = y^2 - 1 (EF_TB), v = -(39081 y^2 + 1) (EF_TC).
    FE448_SQR1  EP, EP2, rbp + EF_TA, rbp + EF_QY
    FE448_SUB   rbp + EF_TB, rbp + EF_TA, rel ed448_one
    FE448_MULW  rbp + EF_TC, rbp + EF_TA, 39081
    FE448_ADD   rbp + EF_TC, rbp + EF_TC, rel ed448_one
    FE448_SUB   rbp + EF_TC, rel ed448_zero, rbp + EF_TC
    ; u^2, v^2; u^3, v^3; u^5, u^3 v; u^5 v^3; its power (p - 3) / 4; x = u^3 v times that.
    FE448_SQR2  EP, EP2, rbp + EF_TD, rbp + EF_TB, rbp + EF_TE, rbp + EF_TC
    FE448_MUL2  EP, rbp + EF_TF, rbp + EF_TD, rbp + EF_TB, rbp + EF_TG, rbp + EF_TE, rbp + EF_TC
    FE448_MUL2  EP, rbp + EF_TH, rbp + EF_TF, rbp + EF_TD, rbp + EF_TS, rbp + EF_TF, rbp + EF_TC
    FE448_MUL1  EP, rbp + EF_TS2, rbp + EF_TH, rbp + EF_TG
    lea         rdi, [rbp + EF_TA]
    lea         rsi, [rbp + EF_TS2]
    call        ha_fe448_pow_p34_%1
    FE448_MUL1  EP, rbp + EF_QX, rbp + EF_TS, rbp + EF_TA
    ; v x^2 = u, both sides fully reduced and compared.
    FE448_SQR1  EP, EP2, rbp + EF_TD, rbp + EF_QX
    FE448_MUL1  EP, rbp + EF_TE, rbp + EF_TC, rbp + EF_TD
    FE448_STRONG rbp + EF_TB
    FE448_STORE_LIMBS rbp + EF_TB           ; u, fully reduced
    FE448_STRONG rbp + EF_TE
    ED_DIFFER   rbp + EF_TB
    jnz         .refused
    ; x fully reduced: 0 with the sign bit set is refused; another parity than the bit's, p - x.
    FE448_STRONG rbp + EF_QX
    FE448_STORE_LIMBS rbp + EF_QX
    mov         rax, r8
    or          rax, r9
    or          rax, r10
    or          rax, r11
    or          rax, r12
    or          rax, r13
    or          rax, r14
    or          rax, r15
    jnz         .nonzero
    cmp         qword [rbp + EF_PAR], 0
    jne         .refused
.nonzero:
    mov         eax, r8d
    and         eax, 1
    cmp         rax, [rbp + EF_PAR]
    je          .parity
    FE448_SUB   rbp + EF_QX, rel ed448_zero, rbp + EF_QX
.parity:
    ; Z = 1, T = x y.
    ED_COPY     rbp + EF_QZ, rel ed448_one
    FE448_MUL1  EP, rbp + EF_QT, rbp + EF_QX, rbp + EF_QY
    xor         eax, eax
    ret
.refused:
    mov         eax, -1
    ret
%endmacro

; =============================================================================
; The scans (constant time): ed448_select_v3 and _v1.
; =============================================================================

; -----------------------------------------------------------------------------
; ed448_select_v3: EF_QX, EF_QY, EF_QT = window ecx's entry for the signed digit edx (-16..16):
; |d|'s point read by a scan of all 16 entries (each masked by |d| = m, ORed in), the neutral
; (0, 1, 0) for d = 0; x and d x y taken as 2p - them when d < 0 (vpblendvb on the sign).
; AVX2. Clobbers rax, rcx, rsi, r8, ymm0-ymm15 and the flags.
; -----------------------------------------------------------------------------
align 32
ed448_select_v3:
    mov         eax, edx
    sar         eax, 31                     ; the sign: 0 or -1
    mov         r8d, edx
    xor         r8d, eax
    sub         r8d, eax                    ; |d|
    vmovq       xmm15, r8
    vpbroadcastq ymm15, xmm15               ; |d| in every lane
    vpxor       xmm14, xmm14, xmm14         ; m = 0 in every lane
    vpcmpeqq    ymm13, ymm15, ymm14         ; |d| = 0: the neutral entry
    vpand       ymm0, ymm13, [rel ed448_neutral_entry]
    vpand       ymm1, ymm13, [rel ed448_neutral_entry + 32]
    vpand       ymm2, ymm13, [rel ed448_neutral_entry + 64]
    vpand       ymm3, ymm13, [rel ed448_neutral_entry + 96]
    vpand       ymm4, ymm13, [rel ed448_neutral_entry + 128]
    vpand       ymm5, ymm13, [rel ed448_neutral_entry + 160]
    imul        ecx, ecx, ED448_ENTRIES * 192
    lea         rsi, [rel ed448_base_table]
    add         rsi, rcx
    vpcmpeqq    ymm12, ymm12, ymm12
    vpsrlq      ymm12, ymm12, 63            ; 1 in every lane: m's step
    mov         ecx, ED448_ENTRIES
.entry:
    vpaddq      ymm14, ymm14, ymm12
    vpcmpeqq    ymm13, ymm15, ymm14         ; |d| = m
  %assign q 0
  %rep 6
    vpand       ymm6, ymm13, [rsi + q]
    vpor        ymm %+ %eval(q / 32), ymm %+ %eval(q / 32), ymm6
    %assign q q + 32
  %endrep
    add         rsi, 192
    dec         ecx
    jnz         .entry
    ; d < 0: 2p - x, 2p - d x y.
    vmovd       xmm13, eax
    vpbroadcastd ymm13, xmm13
    vmovdqu     ymm6, [rel ha_fe448_2p]
    vmovdqu     ymm7, [rel ha_fe448_2p + 32]
    vpsubq      ymm8, ymm6, ymm0
    vpsubq      ymm9, ymm7, ymm1
    vpsubq      ymm10, ymm6, ymm4
    vpsubq      ymm11, ymm7, ymm5
    vpblendvb   ymm0, ymm0, ymm8, ymm13
    vpblendvb   ymm1, ymm1, ymm9, ymm13
    vpblendvb   ymm4, ymm4, ymm10, ymm13
    vpblendvb   ymm5, ymm5, ymm11, ymm13
    vmovdqu     [rbp + EF_QX], ymm0
    vmovdqu     [rbp + EF_QX + 32], ymm1
    vmovdqu     [rbp + EF_QY], ymm2
    vmovdqu     [rbp + EF_QY + 32], ymm3
    vmovdqu     [rbp + EF_QT], ymm4
    vmovdqu     [rbp + EF_QT + 32], ymm5
    ret

; -----------------------------------------------------------------------------
; ed448_select_v1: the same in SSE2 (the entry in xmm0-xmm11: x, y, d x y four registers each;
; |d| = m by pcmpeqd on dwords, every dword of both sides broadcast; the negation by and/andn/or).
; Clobbers rax, rcx, rsi, r8, xmm0-xmm15 and the flags.
; -----------------------------------------------------------------------------
align 32
ed448_select_v1:
    mov         eax, edx
    sar         eax, 31
    mov         r8d, edx
    xor         r8d, eax
    sub         r8d, eax
    movd        xmm15, r8d
    pshufd      xmm15, xmm15, 0             ; |d| in every dword
    pxor        xmm14, xmm14                ; m = 0
    movdqa      xmm13, xmm15
    pcmpeqd     xmm13, xmm14                ; |d| = 0
  %assign q 0
  %rep 12
    movdqu      xmm %+ %eval(q / 16), [rel ed448_neutral_entry + q]
    pand        xmm %+ %eval(q / 16), xmm13
    %assign q q + 16
  %endrep
    imul        ecx, ecx, ED448_ENTRIES * 192
    lea         rsi, [rel ed448_base_table]
    add         rsi, rcx
    mov         ecx, ED448_ENTRIES
.entry:
    paddd       xmm14, [rel ed448_dw_one]
    movdqa      xmm13, xmm15
    pcmpeqd     xmm13, xmm14
  %assign q 0
  %rep 12
    movdqu      xmm12, [rsi + q]
    pand        xmm12, xmm13
    por         xmm %+ %eval(q / 16), xmm12
    %assign q q + 16
  %endrep
    add         rsi, 192
    dec         ecx
    jnz         .entry
    ; y stored now, its registers then free for the negation of x (xmm0-xmm3) and d x y (xmm8-xmm11).
    movdqu      [rbp + EF_QY], xmm4
    movdqu      [rbp + EF_QY + 16], xmm5
    movdqu      [rbp + EF_QY + 32], xmm6
    movdqu      [rbp + EF_QY + 48], xmm7
    movd        xmm13, eax
    pshufd      xmm13, xmm13, 0             ; the sign in every dword
  %assign q 0
  %rep 4
    movdqu      xmm4, [rel ha_fe448_2p + q]
    movdqa      xmm5, xmm4
    psubq       xmm4, xmm %+ %eval(q / 16)          ; 2p - x
    psubq       xmm5, xmm %+ %eval(8 + q / 16)      ; 2p - d x y
    pand        xmm4, xmm13
    pand        xmm5, xmm13
    movdqa      xmm6, xmm13
    movdqa      xmm7, xmm13
    pandn       xmm6, xmm %+ %eval(q / 16)
    pandn       xmm7, xmm %+ %eval(8 + q / 16)
    por         xmm4, xmm6
    por         xmm5, xmm7
    movdqu      [rbp + EF_QX + q], xmm4
    movdqu      [rbp + EF_QT + q], xmm5
    %assign q q + 16
  %endrep
    ret

ED448_ROUTINES v3
ED448_ROUTINES v1

; =============================================================================
; The functions, per version: ED448_FUNCTIONS v.
; =============================================================================
%macro ED448_FUNCTIONS 1

; -----------------------------------------------------------------------------
; ed448_keys_v: from the seed at [rsi] (57 octets): EF_HASH = SHAKE256(seed, 114) (RFC 8032
; 5.2.5: no dom4 here), EF_SS = the clamped s, the accumulator = s B, EF_AENC = its encoding.
; Clobbers every register but rbp and rsp.
; -----------------------------------------------------------------------------
align 32
ed448_keys_%1:
    sub         rsp, 8                      ; (the C call needs the 16-aligned stack back)
    mov         rdi, rsi
    mov         esi, 57
    lea         rdx, [rbp + EF_HASH]
    mov         ecx, 114
    call        httpasm_shake256
    add         rsp, 8
    lea         rsi, [rbp + EF_HASH]
    call        ed448_clamp                 ; (the 57th octet is not read: RFC 8032 clears it)
    lea         rsi, [rbp + EF_SS]
    call        ed448_recode
    call        ed448_fixed_base_%1
    lea         rdi, [rbp + EF_AENC]
    jmp         ed448_encode_%1             ; (its ret returns for us)

; void ed448_public_key_v(public_key[57], seed[57])
align 32
ed448_public_key_%1:
    ED_ENTER
    mov         [rbp + EF_OUT], rdi
    call        ed448_keys_%1
    mov         rdi, [rbp + EF_OUT]
  %assign q 0
  %rep 7
    mov         rax, [rbp + EF_AENC + q]
    mov         [rdi + q], rax
    %assign q q + 8
  %endrep
    mov         al, [rbp + EF_AENC + 56]
    mov         [rdi + 56], al
    mov         qword [rbp + EF_RES], 0
    ED_FINISH   %1

; void ed448_private_key_init_v(key, seed[57]): the key's s (seven qwords), prefix (the hash's
; octets 57..113) and A, written after the seed is read (the hash reads it first).
align 32
ed448_private_key_init_%1:
    ED_ENTER
    mov         [rbp + EF_OUT], rdi
    call        ed448_keys_%1
    mov         rdi, [rbp + EF_OUT]
  %assign q 0
  %rep 7
    mov         rax, [rbp + EF_SS + q]
    mov         [rdi + httpasm_ed448_private_key.scalar + q], rax
    mov         rax, [rbp + EF_HASH + 57 + q]
    mov         [rdi + httpasm_ed448_private_key.prefix + q], rax
    mov         rax, [rbp + EF_AENC + q]
    mov         [rdi + httpasm_ed448_private_key.public + q], rax
    %assign q q + 8
  %endrep
    mov         al, [rbp + EF_HASH + 57 + 56]
    mov         [rdi + httpasm_ed448_private_key.prefix + 56], al
    mov         al, [rbp + EF_AENC + 56]
    mov         [rdi + httpasm_ed448_private_key.public + 56], al
    xor         eax, eax
    mov         [rdi + httpasm_ed448_private_key.pad], eax
    mov         [rdi + httpasm_ed448_private_key.pad + 2], eax
    mov         qword [rbp + EF_RES], 0
    ED_FINISH   %1

; int ed448_sign_v(signature[114], key, message, length, context, context_length)
align 32
ed448_sign_%1:
    ED_ENTER
    mov         qword [rbp + EF_RES], -1
    cmp         r9, 255
    ja          .done                       ; a context over 255 octets: refused, nothing written
    mov         [rbp + EF_OUT], rdi
    mov         [rbp + EF_KEY], rsi
    mov         [rbp + EF_MSG], rdx
    mov         [rbp + EF_LEN], rcx
    mov         [rbp + EF_CTX], r8
    mov         [rbp + EF_CTXLEN], r9
    call        ed448_dom
    ; r = SHAKE256(dom4 || prefix || M, 114) mod L.
    mov         rax, [rbp + EF_KEY]
    add         rax, httpasm_ed448_private_key.prefix
    mov         [rbp + EF_P1], rax
    mov         qword [rbp + EF_P1LEN], 57
    mov         qword [rbp + EF_P2LEN], 0
    call        ed448_hash
    lea         rdi, [rbp + EF_SR]
    lea         rsi, [rbp + EF_HASH]
    call        sc_reduce912
    ; R = r B, encoded.
    lea         rsi, [rbp + EF_SR]
    call        ed448_recode
    call        ed448_fixed_base_%1
    lea         rdi, [rbp + EF_RENC]
    call        ed448_encode_%1
    ; k = SHAKE256(dom4 || R || A || M, 114) mod L.
    lea         rax, [rbp + EF_RENC]
    mov         [rbp + EF_P1], rax
    mov         qword [rbp + EF_P1LEN], 57
    mov         rax, [rbp + EF_KEY]
    add         rax, httpasm_ed448_private_key.public
    mov         [rbp + EF_P2], rax
    mov         qword [rbp + EF_P2LEN], 57
    call        ed448_hash
    lea         rdi, [rbp + EF_SK]
    lea         rsi, [rbp + EF_HASH]
    call        sc_reduce912
    ; S = r + k s mod L: REDC(REDC(k s) R^2) + r, less L when that does not borrow.
    mov         rsi, [rbp + EF_KEY]
  %assign q 0
  %rep 7
    mov         rax, [rsi + httpasm_ed448_private_key.scalar + q]
    mov         [rbp + EF_SS + q], rax
    %assign q q + 8
  %endrep
    mov         qword [rbp + EF_SS + 56], 0
    lea         rdi, [rbp + EF_ST]
    lea         rsi, [rbp + EF_SS]
    lea         rcx, [rbp + EF_SK]
    call        sc_mont                     ; k s R^-1
    lea         rdi, [rbp + EF_ST]
    lea         rsi, [rbp + EF_ST]
    lea         rcx, [rel ed448_r2]
    call        sc_mont                     ; k s
    mov         rax, [rbp + EF_ST]
    add         rax, [rbp + EF_SR]
    mov         [rbp + EF_ST], rax
  %assign q 8
  %rep 6
    mov         rax, [rbp + EF_ST + q]
    adc         rax, [rbp + EF_SR + q]
    mov         [rbp + EF_ST + q], rax
    %assign q q + 8
  %endrep
  %assign q 0
  %rep 7
    mov         rax, [rbp + EF_ST + q]
    %if q == 0
    sub         rax, [rel ed448_l + q]
    %else
    sbb         rax, [rel ed448_l + q]
    %endif
    mov         [rbp + EF_SU + q], rax
    %assign q q + 8
  %endrep
    sbb         rcx, rcx                    ; all ones when it borrowed: keep the sum
    ; The signature: R, then S (57 octets, the last 0); written only now, after every read of
    ; the message (the signature may overlap it).
    mov         rdi, [rbp + EF_OUT]
  %assign q 0
  %rep 7
    mov         rax, [rbp + EF_RENC + q]
    mov         [rdi + q], rax
    %assign q q + 8
  %endrep
    mov         al, [rbp + EF_RENC + 56]
    mov         [rdi + 56], al
  %assign q 0
  %rep 7
    mov         rax, [rbp + EF_ST + q]
    mov         rdx, [rbp + EF_SU + q]
    xor         rax, rdx
    and         rax, rcx
    xor         rax, rdx                    ; borrowed ? the sum : the sum - L
    mov         [rdi + 57 + q], rax
    %assign q q + 8
  %endrep
    mov         byte [rdi + 113], 0
    mov         qword [rbp + EF_RES], 0
.done:
    ED_FINISH   %1

; int ed448_verify_v(public_key[57], message, length, context, context_length, signature[114])
align 32
ed448_verify_%1:
    ED_ENTER
    mov         qword [rbp + EF_RES], -1
    cmp         r8, 255
    ja          .done
    mov         [rbp + EF_KEY], rdi
    mov         [rbp + EF_MSG], rsi
    mov         [rbp + EF_LEN], rdx
    mov         [rbp + EF_CTX], rcx
    mov         [rbp + EF_CTXLEN], r8
    mov         [rbp + EF_SIG], r9
    ; S below L: its 57th octet 0, and S - L borrowing (one decision on the borrow of a
    ; sub/sbb chain: compared from the top, a qword of L's all ones could never be exceeded and
    ; its branch would never run).
    cmp         byte [r9 + 113], 0
    jne         .done
    mov         rax, [r9 + 57]
    sub         rax, [rel ed448_l]
  %assign q 8
  %rep 6
    mov         rax, [r9 + 57 + q]
    sbb         rax, [rel ed448_l + q]
    %assign q q + 8
  %endrep
    jnc         .done                       ; no borrow: S is L or more
  %assign q 0
  %rep 7
    mov         rax, [r9 + 57 + q]
    mov         [rbp + EF_SS + q], rax       ; S (EF_SS: sc_reduce912 below uses EF_ST .. EF_SV)
    %assign q q + 8
  %endrep
    ; A decoded, then negated: -A = (-x : y : 1 : -x y).
    mov         rsi, [rbp + EF_KEY]
    call        ed448_decode_%1
    test        eax, eax
    jnz         .done
    FE448_SUB   rbp + EF_QX, rel ed448_zero, rbp + EF_QX
    FE448_SUB   rbp + EF_QT, rel ed448_zero, rbp + EF_QT
    ; k = SHAKE256(dom4 || R || A || M, 114) mod L.
    call        ed448_dom
    mov         rax, [rbp + EF_SIG]
    mov         [rbp + EF_P1], rax
    mov         qword [rbp + EF_P1LEN], 57
    mov         rax, [rbp + EF_KEY]
    mov         [rbp + EF_P2], rax
    mov         qword [rbp + EF_P2LEN], 57
    call        ed448_hash
    lea         rdi, [rbp + EF_SK]
    lea         rsi, [rbp + EF_HASH]
    call        sc_reduce912
    ; -A's odd multiples: ODD[0] = -A, then ODD[i] = ODD[i - 1] + 2 (-A). (The loops count in
    ; vq, vm: ED_COPY's own %assign q would take an argument's q, which NASM resolves late.)
  %assign vq 0
  %rep 4
    ED_COPY     rbp + EF_ODD + vq, rbp + EF_QX + vq
    ED_COPY     rbp + EF_PX + vq, rbp + EF_QX + vq
    %assign vq vq + 64
  %endrep
    call        ed448_dbl_%1                ; the accumulator = 2 (-A)
  %assign vq 0
  %rep 4
    ED_COPY     rbp + EF_QX + vq, rbp + EF_PX + vq
    %assign vq vq + 64
  %endrep
  %assign vm 1
  %rep 7
    %assign vq 0
    %rep 4
    ED_COPY     rbp + EF_PX + vq, rbp + EF_ODD + 256 * (vm - 1) + vq
      %assign vq vq + 64
    %endrep
    call        ed448_add_full_%1
    %assign vq 0
    %rep 4
    ED_COPY     rbp + EF_ODD + 256 * vm + vq, rbp + EF_PX + vq
      %assign vq vq + 64
    %endrep
    %assign vm vm + 1
  %endrep
    ; The digits: S's and k's width-5 NAFs; the top is the higher of their tops.
    lea         rdi, [rbp + EF_DIG]
    lea         rsi, [rbp + EF_SS]
    call        ed448_wnaf
    mov         [rbp + EF_TOP], rax
    lea         rdi, [rbp + EF_DIG2]
    lea         rsi, [rbp + EF_SK]
    call        ed448_wnaf
    cmp         rax, [rbp + EF_TOP]
    jbe         .top
    mov         [rbp + EF_TOP], rax
.top:
    ED_SET_NEUTRAL
    mov         rax, [rbp + EF_TOP]
    mov         [rbp + EF_IDX], rax
.step:
    cmp         qword [rbp + EF_IDX], 0
    je          .compare
    dec         qword [rbp + EF_IDX]
    call        ed448_dbl_%1
    ; S's digit: window 0's entry |d| (x, y, d x y), negated for d < 0.
    mov         rcx, [rbp + EF_IDX]
    movsx       rax, byte [rbp + EF_DIG + rcx]
    test        rax, rax
    jz          .k_digit
    mov         [rbp + EF_PAR], rax
    mov         ecx, eax
    sar         ecx, 31
    xor         eax, ecx
    sub         eax, ecx                    ; |d|
    dec         eax
    imul        eax, eax, 192
    lea         rsi, [rel ed448_base_table]
    add         rsi, rax
    ED_COPY     rbp + EF_QX, rsi
    ED_COPY     rbp + EF_QY, rsi + 64
    ED_COPY     rbp + EF_QT, rsi + 128
    cmp         qword [rbp + EF_PAR], 0
    jg          .s_add
    FE448_SUB   rbp + EF_QX, rel ed448_zero, rbp + EF_QX
    FE448_SUB   rbp + EF_QT, rel ed448_zero, rbp + EF_QT
.s_add:
    call        ed448_add_mixed_%1
.k_digit:
    ; k's digit: -A's multiple |d| (ODD[(|d| - 1) / 2]), negated (X and T) for d < 0.
    mov         rcx, [rbp + EF_IDX]
    movsx       rax, byte [rbp + EF_DIG2 + rcx]
    test        rax, rax
    jz          .step
    mov         [rbp + EF_PAR], rax
    mov         ecx, eax
    sar         ecx, 31
    xor         eax, ecx
    sub         eax, ecx
    shr         eax, 1                      ; (|d| - 1) / 2 for odd |d|
    shl         eax, 8                      ; 256 octets a point
    lea         rsi, [rbp + EF_ODD]
    add         rsi, rax
  %assign vq 0
  %rep 4
    ED_COPY     rbp + EF_QX + vq, rsi + vq
    %assign vq vq + 64
  %endrep
    cmp         qword [rbp + EF_PAR], 0
    jg          .k_add
    FE448_SUB   rbp + EF_QX, rel ed448_zero, rbp + EF_QX
    FE448_SUB   rbp + EF_QT, rel ed448_zero, rbp + EF_QT
.k_add:
    call        ed448_add_full_%1
    jmp         .step
.compare:
    ; [S]B - [k]A's encoding against R's octets.
    lea         rdi, [rbp + EF_RENC]
    call        ed448_encode_%1
    mov         rsi, [rbp + EF_SIG]
    xor         eax, eax                    ; the OR of every octet's difference: one decision
  %assign q 0
  %rep 7
    mov         rdx, [rbp + EF_RENC + q]
    xor         rdx, [rsi + q]
    or          rax, rdx
    %assign q q + 8
  %endrep
    movzx       edx, byte [rbp + EF_RENC + 56]
    xor         dl, [rsi + 56]
    or          rax, rdx
    jnz         .done
    mov         qword [rbp + EF_RES], 0
.done:
    ED_FINISH   %1

; -----------------------------------------------------------------------------
; int ha_x448_base_v(uint8_t out[56], const uint8_t scalar[56]): X448(scalar, 5), the public key
; of an X448 scalar, from this fixed base (see the header): 0, or -1 when out is all zeros (the
; scalar 4q). Hidden: crypto/x448.asm's httpasm_x448_public_key calls it.
; -----------------------------------------------------------------------------
global ha_x448_base_%1:function hidden (ha_x448_base_%1.end - ha_x448_base_%1)
align 32
ha_x448_base_%1:
    ED_ENTER
    mov         [rbp + EF_OUT], rdi
    call        ed448_clamp
    lea         rsi, [rbp + EF_SS]
    call        ed448_recode
    call        ed448_fixed_base_%1
    mov         rdi, [rbp + EF_OUT]
    call        ed448_x448_u_%1
    neg         rax                         ; -1 when u is 0, else 0
    sbb         rax, rax
    not         rax
    HA_DECLASSIFY rax                       ; (public by design: the key is all zeros, 4q's)
    mov         [rbp + EF_RES], rax
    ED_FINISH   %1
.end:
%endmacro

ED448_FUNCTIONS v3
ED448_FUNCTIONS v1

; =============================================================================
; The C ABI: each picks v3 (AVX2 and BMI2: x86-64-v3) or v1 once.
; =============================================================================

; -----------------------------------------------------------------------------
; void httpasm_ed448_public_key(uint8_t public_key[57], const uint8_t private_key[57])
;   A = s B, encoded: s = clamp(SHAKE256(private_key, 114)[0..57]) (RFC 8032 5.2.5).
; -----------------------------------------------------------------------------
global httpasm_ed448_public_key:function (httpasm_ed448_public_key.end - httpasm_ed448_public_key)
align 16
httpasm_ed448_public_key:
    HA_CPU_PICK HTTPASM_CPU_V3, .v3
    jmp         ed448_public_key_v1         ; (tail calls: the version returns to our caller)
.v3:
    jmp         ed448_public_key_v3
.end:

; -----------------------------------------------------------------------------
; void httpasm_ed448_private_key_init(httpasm_ed448_private_key *key, const uint8_t seed[57])
;   The key ready to sign: s, the nonce prefix, A (see httpasm_abi.inc's struc).
; -----------------------------------------------------------------------------
global httpasm_ed448_private_key_init:function (httpasm_ed448_private_key_init.end - httpasm_ed448_private_key_init)
align 16
httpasm_ed448_private_key_init:
    HA_CPU_PICK HTTPASM_CPU_V3, .v3
    jmp         ed448_private_key_init_v1
.v3:
    jmp         ed448_private_key_init_v3
.end:

; -----------------------------------------------------------------------------
; int httpasm_ed448_sign(uint8_t signature[114], const httpasm_ed448_private_key *key,
;                        const uint8_t *message, size_t length, const uint8_t *context,
;                        size_t context_length)
;   RFC 8032 5.2.6 (pure Ed448, dom4(0, context)). 0; -1 (nothing written) for a context over
;   255 octets.
; -----------------------------------------------------------------------------
global httpasm_ed448_sign:function (httpasm_ed448_sign.end - httpasm_ed448_sign)
align 16
httpasm_ed448_sign:
    HA_CPU_PICK HTTPASM_CPU_V3, .v3
    jmp         ed448_sign_v1
.v3:
    jmp         ed448_sign_v3
.end:

; -----------------------------------------------------------------------------
; int httpasm_ed448_verify(const uint8_t public_key[57], const uint8_t *message, size_t length,
;                          const uint8_t *context, size_t context_length,
;                          const uint8_t signature[114])
;   RFC 8032 5.2.7, cofactorless. 0 when valid; -1 otherwise (see the header).
; -----------------------------------------------------------------------------
global httpasm_ed448_verify:function (httpasm_ed448_verify.end - httpasm_ed448_verify)
align 16
httpasm_ed448_verify:
    HA_CPU_PICK HTTPASM_CPU_V3, .v3
    jmp         ed448_verify_v1
.v3:
    jmp         ed448_verify_v3
.end:
