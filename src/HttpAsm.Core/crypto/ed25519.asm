; =============================================================================
; crypto/ed25519.asm - Ed25519 (RFC 8032 5.1, pure EdDSA over edwards25519), for TLS 1.3's
; ed25519 signature scheme (RFC 9846 4.2.3) and Ed25519 certificates (RFC 8410): the C ABI's
; httpasm_ed25519_public_key, httpasm_ed25519_private_key_init, httpasm_ed25519_sign and
; httpasm_ed25519_verify.
;
; The field is include/crypto/fe25519.inc's (X25519's), in its two versions, one chosen per call:
; v3 FE64 (four 64-bit limbs, mulx with adcx/adox), v1 FE51 (five 51-bit limbs, mul). Every
; routine below is written once as a macro over the version's prefix and element size
; (ED_ROUTINES), as crypto/x25519.asm's ladder is.
;
; The group: points in extended coordinates (X : Y : Z : T), x = X / Z, y = Y / Z, x y = T / Z
; (Hisil, Wong, Carter and Dawson), the formulas for a = -1: doubling dbl-2008-hwcd (4M + 4S),
; addition add-2008-hwcd-3 with 2d T precomputed on one side (8M; 7M against a table point in
; the "niels" form (y + x, y - x, 2d x y), Z = 1). They are COMPLETE on edwards25519 (a = -1 is a
; square and d is not, modulo p): no input is exceptional, the neutral point (0 : 1 : 1 : 0) and
; doubling included, so no selection masks are needed (crypto/p256.asm needs them for its
; Weierstrass formulas). At v1, FE51_ADD does not carry, and two values here are sums of three
; carried values where X25519's ladder never has more than two: G = 2 Z + C in an addition and
; F' = 2 Z^2 + G' in a doubling, limbs below 3 (2^51 + 2^13). Both stay inside FE51's limits:
; every product they enter (G H the largest, a three-sum by a two-sum) keeps its 128-bit sums
; below 77 * 3 * 2^103 < 2^111, which FE51_CARRY takes, and no subtraction takes one as its
; subtrahend (FE51_SUB's 4p bias, limbs from 2^53 - 76, would cover even that).
;
; The scalar multiplications:
;   - fixed base (public keys, R = r B), constant time: signed 6-bit digits (the Booth recoding
;     of crypto/p256.asm), 43 windows, each with its own table of m 2^(6i) B (m = 1..32) in niels
;     form: 132,096 octets in include/generated/ed25519_table.inc, written and proven by
;     specs/ed25519.cs. A window's digit selects its entry by a scan that reads all 32 (AVX2 at
;     v3, SSE2 at v1), a negative digit swaps y + x with y - x and negates 2d x y, digit 0 gives
;     the neutral (1, 1, 0); one mixed addition a window, no doubling;
;   - verification, variable time (every input public): [S]B + [k](-A) in one pass from the top
;     (Straus), wNAF digits, S's by 6 bits over the table's window 0 (1B..32B: its odd ones), k's
;     by 5 bits over -A's odd multiples 1..15 (cached form, built per call), the doublings shared.
;
; Signing with a prepared key (httpasm_ed25519_private_key_init: a = clamp(SHA-512(seed)[0..32])
; mod L, the prefix SHA-512(seed)[32..64], A = a B computed here): RFC 8032 5.1.6's r =
; SHA-512(prefix || M) mod L, R = r B, k = SHA-512(R || A || M) mod L, S = r + k a mod L. The key
; carries its own A: an API that took the public key from the caller would let a mismatched one
; leak the private key (r does not depend on A, so two signatures of one message under two A
; give a = (S1 - S2) / (k1 - k2)).
;
; Verification (RFC 8032 5.1.7, cofactorless): the signature is 64 octets; S must be below L
; (non-malleable); A must decode (RFC 8032 5.1.3: y below p, x recovered, x = 0 with the sign bit
; set refused); then the encoding of [S]B - [k]A must equal R's octets (a non-canonical R can
; never match). Small-order and mixed-order public keys are not refused by policy: their
; signatures pass when the cofactorless equation holds (Wycheproof marks them acceptable either
; way).
;
; Scalars modulo L = 2^252 + 27742317777372353535851937790883648493 by Montgomery products over
; four limbs (R = 2^256), with mul in both versions (a signature takes a handful): a 512-bit hash
; h = h1 R + h0 reduces as REDC(REDC(h1, R^3) + REDC(h0, R^2)), S as REDC(REDC(k, a), R^2) + r.
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "crypto/fe25519.inc"

extern httpasm_sha512                       ; crypto/sha512.asm: the one-shot hash, and the running
extern httpasm_sha512_init                  ; one's start and end (httpasm_core.inc declares its
extern httpasm_sha512_final                 ; update, which SHA-384 shares)

extern ha_modinv256                         ; crypto/inverse.asm: x^-1 mod M (safegcd)

section .rodata
%include "generated/ed25519_table.inc"
FE25519_INVERSE_RECORD                      ; fe25519_mod_p, for ha_modinv256
align 16
ed_zero: times 48 db 0                      ; a zero field element at either version (0 - a)

section .text

; -----------------------------------------------------------------------------
; The frame (rbp, 64-aligned). The version-independent part first, at fixed offsets (the scalar
; routines and the hashing use it at either version); then the field slots, whose size S (32 at
; v3, 40 at v1) each ED_ROUTINES expansion sets (%xdefine'd there). Everything below its end is
; wiped before a function returns (the private scalar, r, every intermediate point).
; -----------------------------------------------------------------------------
EF_K2       equ 0                           ; a scalar shifted up one bit (five qwords, a sixth 0)
EF_SA       equ 48                          ; scalars, four little-endian qwords: a (mod L)
EF_SR       equ 80                          ; r
EF_SK       equ 112                         ; k
EF_SS       equ 144                         ; S
EF_ST       equ 176                         ; scalar temporaries
EF_ST2      equ 208
EF_HASH     equ 240                         ; a SHA-512 digest (64)
EF_CTX      equ 304                         ; a httpasm_sha512_ctx (208)
EF_ENC      equ 512                         ; an encoding (32)
EF_DIG1     equ 544                         ; verification: S's wNAF digits (264)
EF_DIG2     equ 808                         ; k's (264)
EF_SCAN     equ 1072                        ; a scanned table entry, canonical (96)
EF_CMP      equ 1168                        ; canonical values to compare (64)
EF_OUT      equ 1232                        ; the output's address
EF_ARG      equ 1240                        ; inputs' addresses and lengths
EF_ARG2     equ 1248
EF_ARG3     equ 1256
EF_RES      equ 1264                        ; the result to return
EF_WIN      equ 1272                        ; a window or position number
EF_SIGN     equ 1280                        ; a digit's sign as a mask; a parity bit
EF_DIGIT    equ 1288                        ; a digit's magnitude
EF_SQRN     equ 1296                        ; ED_SQR_N's counter
EF_LEN1     equ 1304                        ; verification: the wNAFs' lengths
EF_LEN2     equ 1312
FE51_T19    equ 1320                        ; FE51's scratch (40)
EF_INV      equ 1360                        ; ed_invert's value, canonical (32)
EF_FIELD    equ 1408                        ; the field slots from here (64-aligned)

; ED_COPY dst, src, qwords: memory to memory through rax (no flags).
%macro ED_COPY 3
  %assign c_q 0
  %rep %3
    mov         rax, [%2 + c_q]
    mov         [%1 + c_q], rax
    %assign c_q c_q + 8
  %endrep
%endmacro

; ED_ZERO dst, qwords: zeros (no flags).
%macro ED_ZERO 2
  %assign z_q 0
  %rep %2
    mov         qword [%1 + z_q], 0
    %assign z_q z_q + 8
  %endrep
%endmacro

; =============================================================================
; Scalars modulo L (version-independent: mul). Montgomery products over four limbs, R = 2^256.
; =============================================================================

; ED_LMAC a, bi, t0, t1, t2, t3, t4, t5: t0..t4 += a bi (four mul, one carry chain through the high
; words in rdi); t5 = the carry word out. bi is a memory operand. Clobbers rax, rcx, rdx, rdi.
%macro ED_LMAC 8
    mov         rcx, %2
    mov         rax, [%1]
    mul         rcx
    add         %3, rax
    adc         rdx, 0
    mov         rdi, rdx
  %assign lm_q 8
  %rep 3
    mov         rax, [%1 + lm_q]
    mul         rcx
    add         rax, rdi
    adc         rdx, 0
    %if lm_q == 8
    add         %4, rax
    %elif lm_q == 16
    add         %5, rax
    %else
    add         %6, rax
    %endif
    adc         rdx, 0
    mov         rdi, rdx
    %assign lm_q lm_q + 8
  %endrep
    xor         %8, %8
    add         %7, rdi
    adc         %8, 0
%endmacro

; ED_LRED t0, t1, t2, t3, t4, t5: t += m L with m = t0 L0 (t0 then 0); the carry out of t4 into t5
; (added). Clobbers rax, rcx, rdx, rdi.
%macro ED_LRED 6
    mov         rcx, %1
    imul        rcx, [rel ed25519_l0]
    mov         rax, [rel ed25519_l]
    mul         rcx
    add         %1, rax
    adc         rdx, 0
    mov         rdi, rdx
  %assign lr_q 8
  %rep 3
    mov         rax, [rel ed25519_l + lr_q]
    mul         rcx
    add         rax, rdi
    adc         rdx, 0
    %if lr_q == 8
    add         %2, rax
    %elif lr_q == 16
    add         %3, rax
    %else
    add         %4, rax
    %endif
    adc         rdx, 0
    mov         rdi, rdx
    %assign lr_q lr_q + 8
  %endrep
    add         %5, rdi
    adc         %6, 0
%endmacro

; -----------------------------------------------------------------------------
; ed_lmul: rdi = out, rsi = a, rdx = b (four qwords each; a below R, b below L: then a b < R L and
; the result is below L) -> out = a b R^-1 mod L. CIOS, the six limbs of t turning through
; r8..r13; out may be a or b. Clobbers rax, rbx, rcx, rdx, rdi, rsi, r8-r15, the flags.
; -----------------------------------------------------------------------------
align 16
ed_lmul:
    mov         r14, rdi                    ; out
    mov         r15, rdx                    ; b
    mov         rcx, [r15]                  ; round 0: t = a b0
    mov         rax, [rsi]
    mul         rcx
    mov         r8, rax
    mov         r9, rdx
    mov         rax, [rsi + 8]
    mul         rcx
    add         r9, rax
    adc         rdx, 0
    mov         r10, rdx
    mov         rax, [rsi + 16]
    mul         rcx
    add         r10, rax
    adc         rdx, 0
    mov         r11, rdx
    mov         rax, [rsi + 24]
    mul         rcx
    add         r11, rax
    adc         rdx, 0
    mov         r12, rdx
    xor         r13d, r13d
    ED_LRED     r8, r9, r10, r11, r12, r13
    ED_LMAC     rsi, [r15 + 8], r9, r10, r11, r12, r13, r8
    ED_LRED     r9, r10, r11, r12, r13, r8
    ED_LMAC     rsi, [r15 + 16], r10, r11, r12, r13, r8, r9
    ED_LRED     r10, r11, r12, r13, r8, r9
    ED_LMAC     rsi, [r15 + 24], r11, r12, r13, r8, r9, r10
    ED_LRED     r11, r12, r13, r8, r9, r10
    ; t = r12 r13 r8 r9 with the carry word r10, below 2L: minus L when that does not borrow
    mov         rax, r12
    sub         rax, [rel ed25519_l]
    mov         rbx, r13
    sbb         rbx, [rel ed25519_l + 8]
    mov         rcx, r8
    sbb         rcx, [rel ed25519_l + 16]
    mov         rdx, r9
    sbb         rdx, [rel ed25519_l + 24]
    sbb         r10, 0
    cmovnc      r12, rax
    cmovnc      r13, rbx
    cmovnc      r8, rcx
    cmovnc      r9, rdx
    mov         [r14], r12
    mov         [r14 + 8], r13
    mov         [r14 + 16], r8
    mov         [r14 + 24], r9
    ret

; -----------------------------------------------------------------------------
; ed_ladd: rdi = out, rsi = a, rdx = b (each below L) -> out = a + b mod L (one subtraction of L,
; selected by cmov). Clobbers rax, rbx, rcx, r8-r12, the flags.
; -----------------------------------------------------------------------------
align 16
ed_ladd:
    mov         r8, [rsi]
    mov         r9, [rsi + 8]
    mov         r10, [rsi + 16]
    mov         r11, [rsi + 24]
    add         r8, [rdx]
    adc         r9, [rdx + 8]
    adc         r10, [rdx + 16]
    adc         r11, [rdx + 24]                 ; (below 2L < 2^254: no carry out)
    mov         rax, r8
    sub         rax, [rel ed25519_l]
    mov         rbx, r9
    sbb         rbx, [rel ed25519_l + 8]
    mov         rcx, r10
    sbb         rcx, [rel ed25519_l + 16]
    mov         r12, r11
    sbb         r12, [rel ed25519_l + 24]
    cmovnc      r8, rax
    cmovnc      r9, rbx
    cmovnc      r10, rcx
    cmovnc      r11, r12
    mov         [rdi], r8
    mov         [rdi + 8], r9
    mov         [rdi + 16], r10
    mov         [rdi + 24], r11
    ret

; -----------------------------------------------------------------------------
; ed_reduce64: rsi = 64 octets (a SHA-512 digest, little-endian: RFC 8032 reads it so), rdi = out
; (four qwords) -> out = the 512-bit value mod L: h1 R^2 (REDC of h1 and R^3) plus h0 R (REDC of
; h0 and R^2) is h R, and a REDC by 1 takes it to h. Works in the frame's EF_ST, EF_ST2 (rbp).
; Clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r15, the flags.
; -----------------------------------------------------------------------------
align 16
ed_reduce64:
    push        rdi
    push        rsi
    lea         rdi, [rbp + EF_ST]
    lea         rsi, [rsi + 32]             ; h1
    lea         rdx, [rel ed25519_l_r3]
    call        ed_lmul                     ; h1 R^2
    mov         rsi, [rsp]
    lea         rdi, [rbp + EF_ST2]         ; h0 (rsi) times R^2: h0 R
    lea         rdx, [rel ed25519_l_r2]
    call        ed_lmul
    lea         rdi, [rbp + EF_ST]
    lea         rsi, [rbp + EF_ST]
    lea         rdx, [rbp + EF_ST2]
    call        ed_ladd                     ; h R
    mov         qword [rbp + EF_ST2], 1     ; the integer 1
    mov         qword [rbp + EF_ST2 + 8], 0
    mov         qword [rbp + EF_ST2 + 16], 0
    mov         qword [rbp + EF_ST2 + 24], 0
    pop         rsi
    pop         rdi
    lea         rsi, [rbp + EF_ST]
    lea         rdx, [rbp + EF_ST2]
    call        ed_lmul                     ; h
    ret

; -----------------------------------------------------------------------------
; ed_set_k2: rsi = a scalar's four qwords -> EF_K2 = it shifted up one bit (five qwords, a sixth
; of zeros): what ED_DIGIT reads, the recoding's bit -1 a zero below it. Clobbers rax, r8-r11.
; -----------------------------------------------------------------------------
align 16
ed_set_k2:
    mov         r8, [rsi]
    mov         r9, [rsi + 8]
    mov         r10, [rsi + 16]
    mov         r11, [rsi + 24]
    mov         qword [rbp + EF_K2 + 40], 0
    mov         rax, r11
    shr         rax, 63
    mov         [rbp + EF_K2 + 32], rax
    shld        r11, r10, 1
    mov         [rbp + EF_K2 + 24], r11
    shld        r10, r9, 1
    mov         [rbp + EF_K2 + 16], r10
    shld        r9, r8, 1
    mov         [rbp + EF_K2 + 8], r9
    shl         r8, 1
    mov         [rbp + EF_K2], r8
    ret

; ED_DIGIT: ecx = window number i (public) -> edx = the magnitude of the window's signed 6-bit
; digit (0..32), r12 = its sign as a mask: crypto/p256.asm's P256_DIGIT (OpenSSL's Booth
; recoding) at w = 6 over EF_K2. Clobbers rax, rcx, the flags.
%macro ED_DIGIT 0
    imul        eax, ecx, 6
    mov         ecx, eax
    shr         eax, 6
    and         ecx, 63
    mov         rdx, [rbp + EF_K2 + rax * 8]
    mov         rax, [rbp + EF_K2 + rax * 8 + 8]
    shrd        rdx, rax, cl
    and         edx, (2 << 6) - 1           ; the window's 7 bits, v
    mov         eax, edx
    shr         eax, 6
    neg         rax                         ; s: 0 or all ones
    mov         r12, rax
    mov         ecx, (2 << 6) - 1
    sub         ecx, edx
    xor         ecx, edx
    and         ecx, eax
    xor         edx, ecx                    ; d
    mov         eax, edx
    shr         edx, 1
    and         eax, 1
    add         edx, eax
%endmacro

; -----------------------------------------------------------------------------
; ed_wnaf: rsi = a scalar's four limbs (public, below 2^253), rdi = 264 octets, ecx = w (5 or 6)
; -> its width-w NAF, least significant digit first, as signed octets (odd digits below 2^(w - 1)
; in magnitude, zeros past the last); rax = how many (0 for zero). crypto/p256.asm's p256_wnaf
; at four limbs. Variable time: verification's public scalars only. Clobbers rax, rbx, rcx, rdx,
; rsi, r8-r15, the flags.
; -----------------------------------------------------------------------------
align 16
ed_wnaf:
    push        rdi
    push        rcx
    xor         eax, eax
    mov         ecx, 264
    rep         stosb
    pop         rcx
    pop         rdi
    mov         r8, [rsi]
    mov         r9, [rsi + 8]
    mov         r10, [rsi + 16]
    mov         r11, [rsi + 24]
    xor         r12d, r12d                  ; a fifth limb for k - d
    mov         r15d, 1
    shl         r15, cl                     ; 2^w
    xor         ebx, ebx                    ; the position k's bit 0 stands for
    xor         esi, esi                    ; the count
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
    bsf         rcx, r8
    shrd        r8, r9, cl
    shrd        r9, r10, cl
    shrd        r10, r11, cl
    shrd        r11, r12, cl
    shr         r12, cl
    add         ebx, ecx
    lea         rax, [r15 - 1]
    and         rax, r8                     ; k mod 2^w (odd)
    mov         rdx, r15
    shr         rdx, 1
    cmp         rax, rdx
    jb          .digit
    sub         rax, r15                    ; the negative digit
.digit:
    mov         [rdi + rbx], al
    lea         esi, [rbx + 1]
    cqo
    sub         r8, rax
    sbb         r9, rdx
    sbb         r10, rdx
    sbb         r11, rdx
    sbb         r12, rdx                    ; k -= d: a multiple of 2^w now
    jmp         .next
.done:
    mov         eax, esi
    ret

; ED_ENTER frame / ED_FINISH frame, end: a C ABI function's prologue and epilogue. ENTER pushes
; the six kept registers and makes the 64-aligned frame at rbp (rsp 16-aligned for the calls to
; SHA-512), the entry rsp in its last qword (above end, which the wipe leaves); FINISH returns
; EF_RES's low dword after wiping [rbp, rbp + end): the private scalar, r, the hashes and every
; point. frame = the frame's size (a multiple of 64), end = the wiped part's (a multiple of 8).
%macro ED_ENTER 1
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    and         rsp, -64
    sub         rsp, %1
    mov         rbp, rsp
    mov         [rbp + %1 - 8], rax
%endmacro
%macro ED_FINISH 2
    mov         r8, [rbp + EF_RES]
    xor         eax, eax
    mov         ecx, %2 / 8
    mov         rdi, rbp
    rep         stosq
    mov         eax, r8d
    mov         rsp, [rbp + %1 - 8]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret
%endmacro

; =============================================================================
; ED_ROUTINES F, S, v: every routine of one field version (F = FE64 or FE51, S its element's
; octets, v = v3 or v1). The routines work on the frame of the function that calls them (rbp)
; and clobber every register but rbp and rsp.
; =============================================================================
%macro ED_ROUTINES 3
  %xdefine ES %2
  %xdefine E_AX (EF_FIELD + 0 * ES)          ; the accumulator (X : Y : Z : T)
  %xdefine E_AY (EF_FIELD + 1 * ES)
  %xdefine E_AZ (EF_FIELD + 2 * ES)
  %xdefine E_AT (EF_FIELD + 3 * ES)
  %xdefine E_NP (EF_FIELD + 4 * ES)          ; a niels addend: y + x, y - x, 2d x y
  %xdefine E_NM (EF_FIELD + 5 * ES)
  %xdefine E_NT (EF_FIELD + 6 * ES)
  %xdefine E_CP (EF_FIELD + 7 * ES)          ; a cached addend: Y + X, Y - X, Z, 2d T
  %xdefine E_CM (EF_FIELD + 8 * ES)
  %xdefine E_CZ (EF_FIELD + 9 * ES)
  %xdefine E_CT (EF_FIELD + 10 * ES)
  %xdefine E_T0 (EF_FIELD + 11 * ES)         ; eight temporaries
  %xdefine E_T1 (EF_FIELD + 12 * ES)
  %xdefine E_T2 (EF_FIELD + 13 * ES)
  %xdefine E_T3 (EF_FIELD + 14 * ES)
  %xdefine E_T4 (EF_FIELD + 15 * ES)
  %xdefine E_T5 (EF_FIELD + 16 * ES)
  %xdefine E_T6 (EF_FIELD + 17 * ES)
  %xdefine E_T7 (EF_FIELD + 18 * ES)
  %xdefine E_C2D (EF_FIELD + 19 * ES)        ; the constants in this version's form
  %xdefine E_CSM1 (EF_FIELD + 20 * ES)
  %xdefine E_CD (EF_FIELD + 21 * ES)
  %xdefine E_C1 (EF_FIELD + 22 * ES)
  %xdefine E_PX (EF_FIELD + 23 * ES)         ; a decoded point (X : Y : Z : T)
  %xdefine E_PY (EF_FIELD + 24 * ES)
  %xdefine E_PZ (EF_FIELD + 25 * ES)
  %xdefine E_PT (EF_FIELD + 26 * ES)
  %xdefine E_C2 (EF_FIELD + 27 * ES)         ; a cached point, 4 slots (2 (-A))
  %xdefine E_TAB (EF_FIELD + 31 * ES)        ; -A's odd multiples, cached: 8 points of 4 slots
  %xdefine E_END (EF_FIELD + 63 * ES)
  %xdefine E_FRAME (((E_END + 8 + 63) & -64))

; ed_const_v: the constants (2d, sqrt(-1), d, 1) into the frame in this version's form.
align 16
ed_const_%3:
    ED_CONST    %1, E_C2D, ed25519_2d
    ED_CONST    %1, E_CSM1, ed25519_sqrtm1
    ED_CONST    %1, E_CD, ed25519_d
    ED_CONST    %1, E_C1, ed25519_one
    ret

; ed_dbl_v: ACC = 2 ACC (dbl-2008-hwcd, a = -1, every sign flipped: E' = -E, G' = -G, F' = -F,
; H' = -H, whose products are the same; ref10's ge_p2_dbl arrangement), T3 included: what an
; addition needs next. ed_dbl_xyz_v: the same without T3 (one product fewer), for a doubling
; that another doubling follows (the formula never reads T: verification's positions without a
; digit take it).
align 16
ed_dbl_%3:
    ED_DBL      %1, 1
    ret
align 16
ed_dbl_xyz_%3:
    ED_DBL      %1, 0
    ret

; ed_madd_v: ACC = ACC + N, N in niels form (add-2008-hwcd-3 with Z2 = 1: 7M).
align 16
ed_madd_%3:
    %1_ADD      rbp + E_T0, rbp + E_AY, rbp + E_AX          ; Y + X
    %1_SUB      rbp + E_T1, rbp + E_AY, rbp + E_AX          ; Y - X
    %1_MUL      rbp + E_T0, rbp + E_T0, rbp + E_NP          ; B = (Y + X)(y + x)
    %1_MUL      rbp + E_T1, rbp + E_T1, rbp + E_NM          ; A = (Y - X)(y - x)
    %1_MUL      rbp + E_T2, rbp + E_AT, rbp + E_NT          ; C = T 2d x y
    %1_ADD      rbp + E_T3, rbp + E_AZ, rbp + E_AZ          ; D = 2 Z
    ED_FINISH_ADD %1
    ret

; ed_add_v: ACC = ACC + C, C cached (add-2008-hwcd-3: 8M).
align 16
ed_add_%3:
    %1_ADD      rbp + E_T0, rbp + E_AY, rbp + E_AX
    %1_SUB      rbp + E_T1, rbp + E_AY, rbp + E_AX
    %1_MUL      rbp + E_T0, rbp + E_T0, rbp + E_CP          ; B
    %1_MUL      rbp + E_T1, rbp + E_T1, rbp + E_CM          ; A
    %1_MUL      rbp + E_T2, rbp + E_AT, rbp + E_CT          ; C = T 2d T'
    %1_MUL      rbp + E_T3, rbp + E_AZ, rbp + E_CZ
    %1_ADD      rbp + E_T3, rbp + E_T3, rbp + E_T3          ; D = 2 Z Z'
    ED_FINISH_ADD %1
    ret

; ed_cached_v: ACC in cached form into CP, CM, CZ, CT.
align 16
ed_cached_%3:
    %1_ADD      rbp + E_CP, rbp + E_AY, rbp + E_AX
    %1_SUB      rbp + E_CM, rbp + E_AY, rbp + E_AX
    ED_COPY     rbp + E_CZ, rbp + E_AZ, ES / 8
    %1_MUL      rbp + E_CT, rbp + E_AT, rbp + E_C2D
    ret

; ed_niels_v: the canonical entry at EF_SCAN (96 octets) into NP, NM, NT; then negated when
; EF_SIGN is all ones (y + x and y - x swapped, 2d x y negated).
align 16
ed_niels_%3:
    ED_LOADE    %1, E_NP, EF_SCAN
    ED_LOADE    %1, E_NM, EF_SCAN + 32
    ED_LOADE    %1, E_NT, EF_SCAN + 64
    mov         r8, [rbp + EF_SIGN]
    %1_CSWAP    r8, rbp + E_NP, rbp + E_NM
    %1_SUB      rbp + E_T0, rel ed_zero, rbp + E_NT
    mov         r8, [rbp + EF_SIGN]
    %1_CSWAP    r8, rbp + E_NT, rbp + E_T0
    ret

; ed_mul_base_v: ACC = k B for the scalar in EF_K2 (below 2^255), constant time: 43 windows, each
; digit's entry scanned from its window's table, the neutral entry (1, 1, 0) for digit 0, negated
; for a negative digit, one mixed addition.
align 16
ed_mul_base_%3:
    ED_ZERO     rbp + E_AX, ES / 8
    ED_ZERO     rbp + E_AT, ES / 8
    ED_COPY     rbp + E_AY, rbp + E_C1, ES / 8
    ED_COPY     rbp + E_AZ, rbp + E_C1, ES / 8
    mov         dword [rbp + EF_WIN], 0
.window:
    mov         ecx, [rbp + EF_WIN]
    ED_DIGIT
    mov         [rbp + EF_SIGN], r12
    mov         [rbp + EF_DIGIT], rdx
    imul        eax, [rbp + EF_WIN], 96 << (ED25519_W - 1)
    lea         rsi, [rel ed25519_base_table]
    add         rsi, rax
    ED_SCAN_%3
    mov         rax, [rbp + EF_DIGIT]       ; digit 0: (1, 1, 0), the neutral point in niels form
    neg         rax
    sbb         rax, rax                    ; all ones unless the digit is 0
    inc         rax                         ; 1 when it is 0, else 0
    or          [rbp + EF_SCAN], rax
    or          [rbp + EF_SCAN + 32], rax
    call        ed_niels_%3
    call        ed_madd_%3
    inc         dword [rbp + EF_WIN]
    cmp         dword [rbp + EF_WIN], ED25519_WINDOWS
    jne         .window
    ret

; ed_invert_v: T0 = AZ^-1, by ha_modinv256 (crypto/inverse.asm: safegcd, constant time) on AZ
; fully reduced in EF_INV: 2.11 us where this field's Fermat chains (AZ^(p - 2): 254 squarings,
; each waiting for the last, and 11 products) take 3.76 us at v3 and 4.03 us at v1. AZ is never
; 0 (the formulas are complete: Z stays nonzero), so the inverse always exists.
align 16
ed_invert_%3:
    lea         rax, [rbp + E_AZ]
    %1_PACK     rax                         ; (FE51's reads every limb before it reuses rax)
    FE_CANON
    FE64_STORE  rbp + EF_INV
    lea         rdi, [rbp + EF_INV]
    lea         rsi, [rel fe25519_mod_p]
    call        ha_modinv256                ; (keeps rbp; wipes its own frame)
    ED_LOADE    %1, E_T0, EF_INV
    ret

; ed_pow22523_v: T6 = T5^((p - 5) / 8) = T5^(2^252 - 3) (ref10's fe_pow22523 chain): the
; decompression's square root (RFC 8032 5.1.3). T5 is kept; T0, T3 and T4 are its temporaries
; (T1, T2 and T7 survive it: the decoder keeps u and v there).
align 16
ed_pow22523_%3:
    %1_SQR      rbp + E_T0, rbp + E_T5                      ; z^2
    ED_SQR_N    %1, E_T3, E_T0, 2                           ; z^8
    %1_MUL      rbp + E_T3, rbp + E_T5, rbp + E_T3          ; z^9
    %1_MUL      rbp + E_T0, rbp + E_T0, rbp + E_T3          ; z^11
    %1_SQR      rbp + E_T0, rbp + E_T0                      ; z^22
    %1_MUL      rbp + E_T0, rbp + E_T3, rbp + E_T0          ; z^(2^5 - 1)
    ED_SQR_N    %1, E_T3, E_T0, 5
    %1_MUL      rbp + E_T0, rbp + E_T3, rbp + E_T0          ; z^(2^10 - 1)
    ED_SQR_N    %1, E_T3, E_T0, 10
    %1_MUL      rbp + E_T3, rbp + E_T3, rbp + E_T0          ; z^(2^20 - 1)
    ED_SQR_N    %1, E_T4, E_T3, 20
    %1_MUL      rbp + E_T3, rbp + E_T4, rbp + E_T3          ; z^(2^40 - 1)
    ED_SQR_N    %1, E_T3, E_T3, 10
    %1_MUL      rbp + E_T0, rbp + E_T3, rbp + E_T0          ; z^(2^50 - 1)
    ED_SQR_N    %1, E_T3, E_T0, 50
    %1_MUL      rbp + E_T3, rbp + E_T3, rbp + E_T0          ; z^(2^100 - 1)
    ED_SQR_N    %1, E_T4, E_T3, 100
    %1_MUL      rbp + E_T3, rbp + E_T4, rbp + E_T3          ; z^(2^200 - 1)
    ED_SQR_N    %1, E_T3, E_T3, 50
    %1_MUL      rbp + E_T0, rbp + E_T3, rbp + E_T0          ; z^(2^250 - 1)
    ED_SQR_N    %1, E_T0, E_T0, 2                           ; z^(2^252 - 4)
    %1_MUL      rbp + E_T6, rbp + E_T0, rbp + E_T5          ; z^(2^252 - 3)
    ret

; ed_canon_v: rsi = a slot's offset from rbp, rdi = where (an rbp offset) its canonical value goes
; (four qwords); rax = that value's bit 0 (x's sign in an encoding).
align 16
ed_canon_%3:
    push        rdi
    lea         rax, [rbp + rsi]
    %1_PACK     rax
    FE_CANON
    pop         rdi
    mov         [rbp + rdi], r8
    mov         [rbp + rdi + 8], r9
    mov         [rbp + rdi + 16], r10
    mov         [rbp + rdi + 24], r11
    mov         eax, 1
    and         rax, r8
    ret

; ed_encode_v: rdi = 32 octets <- the encoding of ACC (RFC 8032 5.1.2: y, with x's parity in bit
; 255). Uses T0..T7, EF_CMP.
align 16
ed_encode_%3:
    push        rdi
    sub         rsp, 8                      ; (16-aligned at the calls below)
    call        ed_invert_%3                ; T0 = 1/Z
    %1_MUL      rbp + E_T1, rbp + E_AX, rbp + E_T0          ; x
    %1_MUL      rbp + E_T2, rbp + E_AY, rbp + E_T0          ; y
    mov         esi, E_T1
    mov         edi, EF_CMP
    call        ed_canon_%3
    mov         [rbp + EF_SIGN], rax        ; x's parity
    mov         esi, E_T2
    mov         edi, EF_CMP
    call        ed_canon_%3
    add         rsp, 8
    pop         rdi
    ED_COPY     rdi, rbp + EF_CMP, 3        ; (through rax: the sign is read after)
    mov         rax, [rbp + EF_SIGN]
    shl         rax, 63
    or          rax, [rbp + EF_CMP + 24]
    mov         [rdi + 24], rax
    ret

; ed_decode_v: rsi = 32 octets, an encoded point -> P (X : Y : 1 : X Y); eax = 0, or -1 when
; RFC 8032 5.1.3 refuses it: y not below p, no square root for x, or x = 0 with the sign bit set.
; Public data (a public key): the branches may follow it. Uses T0..T7, EF_SCAN, EF_CMP.
align 16
ed_decode_%3:
    mov         r8, [rsi]
    mov         r9, [rsi + 8]
    mov         r10, [rsi + 16]
    mov         r11, [rsi + 24]
    mov         rax, r11
    shr         rax, 63
    mov         [rbp + EF_SIGN], rax        ; x's sign
    btr         r11, 63
    mov         [rbp + EF_SCAN], r8         ; y, canonical or not
    mov         [rbp + EF_SCAN + 8], r9
    mov         [rbp + EF_SCAN + 16], r10
    mov         [rbp + EF_SCAN + 24], r11
    add         r8, 19                      ; y >= p exactly when y + 19 reaches 2^255
    adc         r9, 0
    adc         r10, 0
    adc         r11, 0
    bt          r11, 63
    jc          .invalid
    ED_LOADE    %1, E_PY, EF_SCAN
    ED_COPY     rbp + E_PZ, rbp + E_C1, ES / 8
    %1_SQR      rbp + E_T1, rbp + E_PY                      ; y^2
    %1_MUL      rbp + E_T2, rbp + E_T1, rbp + E_CD          ; d y^2
    %1_SUB      rbp + E_T1, rbp + E_T1, rbp + E_C1          ; u = y^2 - 1
    %1_ADD      rbp + E_T2, rbp + E_T2, rbp + E_C1          ; v = d y^2 + 1
    %1_SQR      rbp + E_T3, rbp + E_T2                      ; v^2
    %1_MUL      rbp + E_T3, rbp + E_T3, rbp + E_T2          ; v^3
    %1_MUL      rbp + E_PX, rbp + E_T1, rbp + E_T3          ; u v^3 (PX: the chain leaves it)
    %1_SQR      rbp + E_T5, rbp + E_T3                      ; v^6
    %1_MUL      rbp + E_T5, rbp + E_T5, rbp + E_T2          ; v^7
    %1_MUL      rbp + E_T5, rbp + E_T5, rbp + E_T1          ; u v^7
    call        ed_pow22523_%3                              ; T6 = (u v^7)^((p - 5) / 8)
    %1_MUL      rbp + E_PX, rbp + E_PX, rbp + E_T6          ; x = u v^3 (u v^7)^((p - 5) / 8)
    %1_SQR      rbp + E_T7, rbp + E_PX
    %1_MUL      rbp + E_T7, rbp + E_T7, rbp + E_T2          ; v x^2
    mov         esi, E_T7
    mov         edi, EF_CMP
    call        ed_canon_%3
    mov         esi, E_T1
    mov         edi, EF_CMP + 32
    call        ed_canon_%3
    mov         rax, [rbp + EF_CMP]
    xor         rax, [rbp + EF_CMP + 32]
    mov         rcx, [rbp + EF_CMP + 8]
    xor         rcx, [rbp + EF_CMP + 40]
    or          rax, rcx
    mov         rcx, [rbp + EF_CMP + 16]
    xor         rcx, [rbp + EF_CMP + 48]
    or          rax, rcx
    mov         rcx, [rbp + EF_CMP + 24]
    xor         rcx, [rbp + EF_CMP + 56]
    or          rax, rcx
    jz          .root                       ; v x^2 = u: x is a root
    %1_SUB      rbp + E_T0, rel ed_zero, rbp + E_T1         ; -u
    mov         esi, E_T0
    mov         edi, EF_CMP + 32
    call        ed_canon_%3
    mov         rax, [rbp + EF_CMP]
    xor         rax, [rbp + EF_CMP + 32]
    mov         rcx, [rbp + EF_CMP + 8]
    xor         rcx, [rbp + EF_CMP + 40]
    or          rax, rcx
    mov         rcx, [rbp + EF_CMP + 16]
    xor         rcx, [rbp + EF_CMP + 48]
    or          rax, rcx
    mov         rcx, [rbp + EF_CMP + 24]
    xor         rcx, [rbp + EF_CMP + 56]
    or          rax, rcx
    jnz         .invalid                    ; neither: no square root, no point
    %1_MUL      rbp + E_PX, rbp + E_PX, rbp + E_CSM1        ; v x^2 = -u: x sqrt(-1)
.root:
    mov         esi, E_PX
    mov         edi, EF_CMP
    call        ed_canon_%3                 ; rax = x's parity
    mov         rcx, [rbp + EF_CMP]
    or          rcx, [rbp + EF_CMP + 8]
    or          rcx, [rbp + EF_CMP + 16]
    or          rcx, [rbp + EF_CMP + 24]
    jnz         .nonzero
    cmp         qword [rbp + EF_SIGN], 0
    jne         .invalid                    ; x = 0 with the sign bit set
.nonzero:
    cmp         rax, [rbp + EF_SIGN]
    je          .signed
    %1_SUB      rbp + E_PX, rel ed_zero, rbp + E_PX         ; the other root, -x
.signed:
    %1_MUL      rbp + E_PT, rbp + E_PX, rbp + E_PY
    xor         eax, eax
    ret
.invalid:
    mov         eax, -1
    ret

; -----------------------------------------------------------------------------
; void ed_public_key_v(uint8_t out[32], const uint8_t seed[32]): httpasm_ed25519_public_key.
; -----------------------------------------------------------------------------
align 16
ed_public_key_%3:
    ED_ENTER    E_FRAME
    mov         [rbp + EF_OUT], rdi
    lea         rdx, [rbp + EF_HASH]        ; h = SHA-512(seed)
    mov         rdi, rsi
    mov         esi, 32
    call        httpasm_sha512
    call        ed_clamp                    ; a, clamped, into EF_ST
    call        ed_const_%3
    lea         rsi, [rbp + EF_ST]
    call        ed_set_k2
    call        ed_mul_base_%3
    mov         rdi, [rbp + EF_OUT]
    call        ed_encode_%3
    mov         qword [rbp + EF_RES], 0
    ED_FINISH   E_FRAME, E_END

; -----------------------------------------------------------------------------
; void ed_key_init_v(httpasm_ed25519_private_key *key, const uint8_t seed[32]):
; httpasm_ed25519_private_key_init: a mod L, the prefix, A.
; -----------------------------------------------------------------------------
align 16
ed_key_init_%3:
    ED_ENTER    E_FRAME
    mov         [rbp + EF_OUT], rdi
    lea         rdx, [rbp + EF_HASH]
    mov         rdi, rsi
    mov         esi, 32
    call        httpasm_sha512
    mov         rdi, [rbp + EF_OUT]
    ED_COPY     rdi + httpasm_ed25519_private_key.prefix, rbp + EF_HASH + 32, 4
    call        ed_clamp
    call        ed_const_%3
    lea         rsi, [rbp + EF_ST]
    call        ed_set_k2
    call        ed_mul_base_%3              ; A = a B
    mov         rdi, [rbp + EF_OUT]
    add         rdi, httpasm_ed25519_private_key.public
    call        ed_encode_%3
    ; a mod L: the clamped a as a 512-bit value with a zero high half
    ED_COPY     rbp + EF_HASH, rbp + EF_ST, 4
    ED_ZERO     rbp + EF_HASH + 32, 4
    mov         rdi, [rbp + EF_OUT]
    add         rdi, httpasm_ed25519_private_key.scalar
    lea         rsi, [rbp + EF_HASH]
    call        ed_reduce64
    mov         qword [rbp + EF_RES], 0
    ED_FINISH   E_FRAME, E_END

; -----------------------------------------------------------------------------
; void ed_sign_v(uint8_t signature[64], const httpasm_ed25519_private_key *key,
;                const uint8_t *message, size_t length): httpasm_ed25519_sign.
; -----------------------------------------------------------------------------
align 16
ed_sign_%3:
    ED_ENTER    E_FRAME
    mov         [rbp + EF_OUT], rdi
    mov         [rbp + EF_ARG], rsi
    mov         [rbp + EF_ARG2], rdx
    mov         [rbp + EF_ARG3], rcx
    ; r = SHA-512(prefix || M) mod L
    lea         rdi, [rbp + EF_CTX]
    call        httpasm_sha512_init
    lea         rdi, [rbp + EF_CTX]
    mov         rsi, [rbp + EF_ARG]
    add         rsi, httpasm_ed25519_private_key.prefix
    mov         edx, 32
    call        httpasm_sha512_update
    lea         rdi, [rbp + EF_CTX]
    mov         rsi, [rbp + EF_ARG2]
    mov         rdx, [rbp + EF_ARG3]
    call        httpasm_sha512_update
    lea         rdi, [rbp + EF_CTX]
    lea         rsi, [rbp + EF_HASH]
    call        httpasm_sha512_final
    lea         rdi, [rbp + EF_SR]
    lea         rsi, [rbp + EF_HASH]
    call        ed_reduce64
    ; R = r B, kept in the frame (EF_ENC) until the end: written out now, it would change the
    ; message before k hashes it when the caller's signature buffer overlaps the message
    call        ed_const_%3
    lea         rsi, [rbp + EF_SR]
    call        ed_set_k2
    call        ed_mul_base_%3
    lea         rdi, [rbp + EF_ENC]
    call        ed_encode_%3
    ; k = SHA-512(R || A || M) mod L
    lea         rdi, [rbp + EF_CTX]
    call        httpasm_sha512_init
    lea         rdi, [rbp + EF_CTX]
    lea         rsi, [rbp + EF_ENC]
    mov         edx, 32
    call        httpasm_sha512_update
    lea         rdi, [rbp + EF_CTX]
    mov         rsi, [rbp + EF_ARG]
    add         rsi, httpasm_ed25519_private_key.public
    mov         edx, 32
    call        httpasm_sha512_update
    lea         rdi, [rbp + EF_CTX]
    mov         rsi, [rbp + EF_ARG2]
    mov         rdx, [rbp + EF_ARG3]
    call        httpasm_sha512_update
    lea         rdi, [rbp + EF_CTX]
    lea         rsi, [rbp + EF_HASH]
    call        httpasm_sha512_final
    lea         rdi, [rbp + EF_SK]
    lea         rsi, [rbp + EF_HASH]
    call        ed_reduce64
    ; S = r + k a mod L: REDC(k, a) is k a R^-1, a REDC with R^2 makes it k a
    lea         rdi, [rbp + EF_SS]
    lea         rsi, [rbp + EF_SK]
    mov         rdx, [rbp + EF_ARG]
    add         rdx, httpasm_ed25519_private_key.scalar
    call        ed_lmul
    lea         rdi, [rbp + EF_SS]
    lea         rsi, [rbp + EF_SS]
    lea         rdx, [rel ed25519_l_r2]
    call        ed_lmul
    lea         rdi, [rbp + EF_SS]
    lea         rsi, [rbp + EF_SS]
    lea         rdx, [rbp + EF_SR]
    call        ed_ladd
    mov         rdi, [rbp + EF_OUT]         ; the signature: R || S (S little-endian, below L)
    ED_COPY     rdi, rbp + EF_ENC, 4
    ED_COPY     rdi + 32, rbp + EF_SS, 4
    mov         qword [rbp + EF_RES], 0
    ED_FINISH   E_FRAME, E_END

; -----------------------------------------------------------------------------
; int ed_verify_v(const uint8_t public_key[32], const uint8_t *message, size_t length,
;                 const uint8_t signature[64]): httpasm_ed25519_verify. Every input is public.
; -----------------------------------------------------------------------------
align 16
ed_verify_%3:
    ED_ENTER    E_FRAME
    mov         [rbp + EF_ARG], rdi
    mov         [rbp + EF_ARG2], rsi
    mov         [rbp + EF_ARG3], rdx
    mov         [rbp + EF_OUT], rcx         ; (the signature)
    ; S below L (RFC 8032 5.1.7: the non-malleability check)
    mov         rax, [rcx + 32]
    sub         rax, [rel ed25519_l]
    mov         rax, [rcx + 40]
    sbb         rax, [rel ed25519_l + 8]
    mov         rax, [rcx + 48]
    sbb         rax, [rel ed25519_l + 16]
    mov         rax, [rcx + 56]
    sbb         rax, [rel ed25519_l + 24]
    jnc         .invalid
    ED_COPY     rbp + EF_SS, rcx + 32, 4
    call        ed_const_%3
    mov         rsi, [rbp + EF_ARG]
    call        ed_decode_%3                ; A
    test        eax, eax
    jnz         .invalid
    ; k = SHA-512(R || A || M) mod L
    lea         rdi, [rbp + EF_CTX]
    call        httpasm_sha512_init
    lea         rdi, [rbp + EF_CTX]
    mov         rsi, [rbp + EF_OUT]
    mov         edx, 32
    call        httpasm_sha512_update
    lea         rdi, [rbp + EF_CTX]
    mov         rsi, [rbp + EF_ARG]
    mov         edx, 32
    call        httpasm_sha512_update
    lea         rdi, [rbp + EF_CTX]
    mov         rsi, [rbp + EF_ARG2]
    mov         rdx, [rbp + EF_ARG3]
    call        httpasm_sha512_update
    lea         rdi, [rbp + EF_CTX]
    lea         rsi, [rbp + EF_HASH]
    call        httpasm_sha512_final
    lea         rdi, [rbp + EF_SK]
    lea         rsi, [rbp + EF_HASH]
    call        ed_reduce64
    ; -A: X and T negated; its odd multiples, cached, into TAB: -A, then 2(-A) as the addend
    %1_SUB      rbp + E_PX, rel ed_zero, rbp + E_PX
    %1_SUB      rbp + E_PT, rel ed_zero, rbp + E_PT
    ED_COPY     rbp + E_AX, rbp + E_PX, ES / 2
    call        ed_cached_%3
    ED_COPY     rbp + E_TAB, rbp + E_CP, ES / 2             ; TAB[0] = -A
    call        ed_dbl_%3
    call        ed_cached_%3
    ED_COPY     rbp + E_C2, rbp + E_CP, ES / 2              ; 2 (-A)
    ED_COPY     rbp + E_AX, rbp + E_PX, ES / 2
    mov         qword [rbp + EF_WIN], 1
.odd:
    ED_COPY     rbp + E_CP, rbp + E_C2, ES / 2
    call        ed_add_%3                   ; (2j + 1)(-A)
    call        ed_cached_%3
    imul        rdi, [rbp + EF_WIN], 4 * ES
    ED_COPY     rbp + E_TAB + rdi, rbp + E_CP, ES / 2
    inc         qword [rbp + EF_WIN]
    cmp         qword [rbp + EF_WIN], 8
    jne         .odd
    ; the wNAF digits: S by 6 bits (the table's window 0 holds 1B..32B), k by 5 (TAB: 1..15)
    lea         rsi, [rbp + EF_SS]
    lea         rdi, [rbp + EF_DIG1]
    mov         ecx, 6
    call        ed_wnaf
    mov         [rbp + EF_LEN1], rax
    lea         rsi, [rbp + EF_SK]
    lea         rdi, [rbp + EF_DIG2]
    mov         ecx, 5
    call        ed_wnaf
    mov         [rbp + EF_LEN2], rax
    ; the pass from the top: ACC = the neutral point, doubled at each position (complete
    ; formulas: the neutral's doubling needs no case)
    ED_ZERO     rbp + E_AX, ES / 8
    ED_ZERO     rbp + E_AT, ES / 8
    ED_COPY     rbp + E_AY, rbp + E_C1, ES / 8
    ED_COPY     rbp + E_AZ, rbp + E_C1, ES / 8
    mov         rax, [rbp + EF_LEN1]
    cmp         rax, [rbp + EF_LEN2]
    cmovb       rax, [rbp + EF_LEN2]
    mov         [rbp + EF_WIN], rax
    jmp         .next
.pass:
    mov         rcx, [rbp + EF_WIN]         ; a digit at this position: the addition needs T
    mov         al, [rbp + EF_DIG1 + rcx]
    or          al, [rbp + EF_DIG2 + rcx]
    jz          .bare
    call        ed_dbl_%3
    jmp         .s
.bare:
    call        ed_dbl_xyz_%3               ; (another doubling follows: T is never read)
    jmp         .next
.s:
    mov         rcx, [rbp + EF_WIN]
    movsx       rax, byte [rbp + EF_DIG1 + rcx]
    test        eax, eax
    jz          .k
    mov         rdx, rax
    sar         rdx, 63
    mov         [rbp + EF_SIGN], rdx        ; negative digit: negate
    mov         edx, eax
    neg         edx
    cmovs       edx, eax                    ; |d|
    dec         edx
    imul        edx, edx, 96
    lea         rsi, [rel ed25519_base_table]
    add         rsi, rdx
    ED_COPY     rbp + EF_SCAN, rsi, 12
    call        ed_niels_%3
    call        ed_madd_%3
.k:
    mov         rcx, [rbp + EF_WIN]
    movsx       rax, byte [rbp + EF_DIG2 + rcx]
    test        eax, eax
    jz          .next
    mov         rdx, rax
    sar         rdx, 63
    mov         [rbp + EF_SIGN], rdx
    mov         edx, eax
    neg         edx
    cmovs       edx, eax
    shr         edx, 1                      ; (|d| - 1) / 2
    imul        edx, edx, 4 * ES
    ED_COPY     rbp + E_CP, rbp + E_TAB + rdx, ES / 2
    mov         r8, [rbp + EF_SIGN]
    %1_CSWAP    r8, rbp + E_CP, rbp + E_CM
    %1_SUB      rbp + E_T0, rel ed_zero, rbp + E_CT
    mov         r8, [rbp + EF_SIGN]
    %1_CSWAP    r8, rbp + E_CT, rbp + E_T0
    call        ed_add_%3
.next:
    dec         qword [rbp + EF_WIN]
    jns         .pass
    ; the encoding of [S]B + [k](-A) against R's octets
    lea         rdi, [rbp + EF_ENC]
    call        ed_encode_%3
    mov         rsi, [rbp + EF_OUT]
    mov         rax, [rbp + EF_ENC]
    xor         rax, [rsi]
    mov         rcx, [rbp + EF_ENC + 8]
    xor         rcx, [rsi + 8]
    or          rax, rcx
    mov         rcx, [rbp + EF_ENC + 16]
    xor         rcx, [rsi + 16]
    or          rax, rcx
    mov         rcx, [rbp + EF_ENC + 24]
    xor         rcx, [rsi + 24]
    or          rax, rcx
    jnz         .invalid
    mov         qword [rbp + EF_RES], 0
    jmp         .done
.invalid:
    mov         qword [rbp + EF_RES], -1
.done:
    ED_FINISH   E_FRAME, E_END
%endmacro

; ED_CONST F, slot, label: a constant (four canonical qwords) into a frame slot in F's form.
%macro ED_CONST 3
  %ifidn %1, FE64
    ED_COPY     rbp + %2, rel %3, 4
  %else
    lea         rdx, [rel %3]
    FE51_LOAD_U rbp + %2
  %endif
%endmacro

; ED_LOADE F, slot, canonical: four canonical qwords at rbp + canonical into a slot in F's form.
%macro ED_LOADE 3
  %ifidn %1, FE64
    ED_COPY     rbp + %2, rbp + %3, 4
  %else
    lea         rdx, [rbp + %3]
    FE51_LOAD_U rbp + %2
  %endif
%endmacro

; ED_SQR_N F, out, a, n: out = a^(2^n) (frame offsets), n >= 2 (crypto/x25519.asm's X25519_SQR_N).
%macro ED_SQR_N 4
    %1_SQR      rbp + %2, rbp + %3
  %if %4 == 2
    %1_SQR      rbp + %2, rbp + %2
  %else
    mov         dword [rbp + EF_SQRN], %4 - 1
%%again:
    %1_SQR      rbp + %2, rbp + %2
    dec         dword [rbp + EF_SQRN]
    jnz         %%again
  %endif
%endmacro

; ED_DBL F, t: ed_dbl's body (see there), T3 = E' H' too when t is 1. The last products stand
; together: they are independent, and only adjacent operations overlap (crypto/x25519.asm's
; measured lesson).
%macro ED_DBL 2
    %1_SQR      rbp + E_T0, rbp + E_AX                      ; A = X^2
    %1_SQR      rbp + E_T1, rbp + E_AY                      ; B = Y^2
    %1_SQR      rbp + E_T2, rbp + E_AZ
    %1_ADD      rbp + E_T2, rbp + E_T2, rbp + E_T2          ; C = 2 Z^2
    %1_ADD      rbp + E_T3, rbp + E_T0, rbp + E_T1          ; H' = A + B
    %1_ADD      rbp + E_T4, rbp + E_AX, rbp + E_AY
    %1_SQR      rbp + E_T4, rbp + E_T4                      ; (X + Y)^2
    %1_SUB      rbp + E_T4, rbp + E_T3, rbp + E_T4          ; E' = H' - (X + Y)^2
    %1_SUB      rbp + E_T5, rbp + E_T0, rbp + E_T1          ; G' = A - B
    %1_ADD      rbp + E_T6, rbp + E_T2, rbp + E_T5          ; F' = C + G'
    %1_MUL      rbp + E_AX, rbp + E_T4, rbp + E_T6          ; X3 = E' F'
    %1_MUL      rbp + E_AY, rbp + E_T5, rbp + E_T3          ; Y3 = G' H'
  %if %2
    %1_MUL      rbp + E_AT, rbp + E_T4, rbp + E_T3          ; T3 = E' H'
  %endif
    %1_MUL      rbp + E_AZ, rbp + E_T6, rbp + E_T5          ; Z3 = F' G'
%endmacro

; ED_FINISH_ADD F: the additions' common end, from B (T0), A (T1), C (T2), D (T3): E = B - A,
; H = B + A, F = D - C, G = D + C; X3 = E F, Y3 = G H, T3 = E H, Z3 = F G.
%macro ED_FINISH_ADD 1
    %1_SUB      rbp + E_T4, rbp + E_T0, rbp + E_T1          ; E
    %1_ADD      rbp + E_T5, rbp + E_T0, rbp + E_T1          ; H
    %1_SUB      rbp + E_T6, rbp + E_T3, rbp + E_T2          ; F
    %1_ADD      rbp + E_T7, rbp + E_T3, rbp + E_T2          ; G
    %1_MUL      rbp + E_AX, rbp + E_T4, rbp + E_T6
    %1_MUL      rbp + E_AY, rbp + E_T7, rbp + E_T5
    %1_MUL      rbp + E_AT, rbp + E_T4, rbp + E_T5
    %1_MUL      rbp + E_AZ, rbp + E_T6, rbp + E_T7
%endmacro

; The fixed-base table scans: edx = a digit's magnitude (0..32), rsi = its window's table (32
; entries of 96 octets) -> EF_SCAN = the entry numbered edx (zeros for 0); every entry read and
; masked (no address depends on the digit). v3 with AVX2 (vzeroupper after), v1 with SSE2.
; Clobber rax, rcx, rsi, xmm0-xmm13 (ymm at v3), the flags.
%macro ED_SCAN_v3 0
    vmovd       xmm0, edx
    vpbroadcastd ymm0, xmm0
    vpcmpeqd    ymm6, ymm6, ymm6
    vpsrld      ymm6, ymm6, 31
    vmovdqa     ymm7, ymm6
    vpxor       xmm1, xmm1, xmm1
    vpxor       xmm2, xmm2, xmm2
    vpxor       xmm3, xmm3, xmm3
    mov         ecx, 1 << (ED25519_W - 1)
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
    vmovdqu     [rbp + EF_SCAN], ymm1
    vmovdqu     [rbp + EF_SCAN + 32], ymm2
    vmovdqu     [rbp + EF_SCAN + 64], ymm3
    vzeroupper
%endmacro

%macro ED_SCAN_v1 0
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
    mov         ecx, 1 << (ED25519_W - 1)
%%scan:
    movdqa      xmm12, xmm11
    pcmpeqd     xmm12, xmm0
    paddd       xmm11, xmm10
    ED_SCAN_ROW xmm1, rsi
    ED_SCAN_ROW xmm2, rsi + 16
    ED_SCAN_ROW xmm3, rsi + 32
    ED_SCAN_ROW xmm4, rsi + 48
    ED_SCAN_ROW xmm5, rsi + 64
    ED_SCAN_ROW xmm6, rsi + 80
    add         rsi, 96
    dec         ecx
    jnz         %%scan
    movdqu      [rbp + EF_SCAN], xmm1
    movdqu      [rbp + EF_SCAN + 16], xmm2
    movdqu      [rbp + EF_SCAN + 32], xmm3
    movdqu      [rbp + EF_SCAN + 48], xmm4
    movdqu      [rbp + EF_SCAN + 64], xmm5
    movdqu      [rbp + EF_SCAN + 80], xmm6
%endmacro

; ED_SCAN_ROW acc, address: acc |= the 16 octets at address ANDed with xmm12 (aligned rows).
%macro ED_SCAN_ROW 2
    movdqa      xmm13, [%2]
    pand        xmm13, xmm12
    por         %1, xmm13
%endmacro

; -----------------------------------------------------------------------------
; ed_clamp: EF_HASH's first 32 octets (SHA-512(seed)) -> EF_ST = a, clamped (RFC 8032 5.1.5: the
; low 3 bits and bit 255 cleared, bit 254 set). Clobbers rax.
; -----------------------------------------------------------------------------
align 16
ed_clamp:
    mov         rax, [rbp + EF_HASH]
    and         rax, -8
    mov         [rbp + EF_ST], rax
    mov         rax, [rbp + EF_HASH + 8]
    mov         [rbp + EF_ST + 8], rax
    mov         rax, [rbp + EF_HASH + 16]
    mov         [rbp + EF_ST + 16], rax
    mov         rax, [rbp + EF_HASH + 24]
    btr         rax, 63
    bts         rax, 62
    mov         [rbp + EF_ST + 24], rax
    ret

ED_ROUTINES FE64, 32, v3
ED_ROUTINES FE51, 40, v1

; =============================================================================
; The C ABI: each picks v3 (BMI2, ADX and AVX2) or v1 and jumps there (tail calls).
; =============================================================================

; void httpasm_ed25519_public_key(uint8_t public_key[32], const uint8_t private_key[32])
global httpasm_ed25519_public_key:function (httpasm_ed25519_public_key.end - httpasm_ed25519_public_key)
align 16
httpasm_ed25519_public_key:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         ed_public_key_v1
.v3:
    jmp         ed_public_key_v3
.end:

; void httpasm_ed25519_private_key_init(httpasm_ed25519_private_key *key, const uint8_t private_key[32])
global httpasm_ed25519_private_key_init:function (httpasm_ed25519_private_key_init.end - httpasm_ed25519_private_key_init)
align 16
httpasm_ed25519_private_key_init:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         ed_key_init_v1
.v3:
    jmp         ed_key_init_v3
.end:

; void httpasm_ed25519_sign(uint8_t signature[64], const httpasm_ed25519_private_key *key,
;                           const uint8_t *message, size_t length)
global httpasm_ed25519_sign:function (httpasm_ed25519_sign.end - httpasm_ed25519_sign)
align 16
httpasm_ed25519_sign:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         ed_sign_v1
.v3:
    jmp         ed_sign_v3
.end:

; int httpasm_ed25519_verify(const uint8_t public_key[32], const uint8_t *message, size_t length,
;                            const uint8_t signature[64])
global httpasm_ed25519_verify:function (httpasm_ed25519_verify.end - httpasm_ed25519_verify)
align 16
httpasm_ed25519_verify:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         ed_verify_v1
.v3:
    jmp         ed_verify_v3
.end:
