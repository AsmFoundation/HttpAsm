; =============================================================================
; include/crypto/p521.inc - arithmetic modulo the prime p = 2^521 - 1 of the NIST curve P-521
; (SP 800-186 3.2.1.5, the curve TLS calls secp521r1) and modulo its group order n (ECDSA's
; scalars), for crypto/p521.asm.
;
; Field values are nine 64-bit limbs, little-endian, PLAIN (no Montgomery form) and FULLY reduced
; (below p) between operations: 72 octets in memory, the top limb below 2^9. Full reduction lets
; the caller compare values limb by limb (the curve equation, verification's x-coordinate, the
; point at infinity's Z = 0) and select them by mask, as P-384's code does.
;
; Why not P-384's generic Montgomery product (include/crypto/p384.inc): at nine limbs its
; reduction is 81 more multiplications, while p's Mersenne form reduces a product with a shift
; and an add. The 1042-bit product t splits at bit 521: t = hi 2^521 + lo = hi + lo (mod p), so
;   hi = t >> 521   (nine shrd by 9 over t's limbs 8..16), lo = t mod 2^521;
;   w = hi + lo + 1 (one stc and nine adc), below 2^522;
;   when w reaches 2^521 (its bit 521, c, is 1), hi + lo is p or more and the value is w - 2^521
;   (= hi + lo - p); otherwise it is w - 1 (= hi + lo). Both in one pass: the top limb masked to
;   9 bits and d = c - 1 (0, or all ones: -1) added over the nine limbs. Never p itself: hi + lo
;   = 2p would need t = p 2^521 + p, above any product of two values below p.
; Sums take the same tail (a + b + 1, below 2^522). A difference adds p back on a borrow, which
; is the top limb masked to 9 bits (the wrapped value modulo 2^521 is a - b + 2^521) and 1
; subtracted. Halving and doubling are rotations of the 521-bit string (2^521 = 1 modulo p, so
; a / 2 = (a >> 1) + (a & 1) 2^520, and 2a = (a << 1) mod 2^521 + a's bit 520), which keep a
; value below p below p (the rotations move p, all ones, only onto itself). Negation is the
; complement within 521 bits (p - a), masked so that 0 stays 0.
;
; The products are called routines, not macros (crypto/p521.asm instantiates F9X_MUL_BODY and
; the others as p521_fmul_v3 and so on): a product is about 300 instructions, and a doubling
; with all its products written out would be about 10 KB of code and an addition 20 KB, past the
; L1 instruction cache and the decoded-micro-op cache together: the call costs a few cycles of
; the product's ~110. Sums, differences, halves, rotations and negations (about 25 instructions)
; stay macros.
;
; Two versions of the products, everything else shared:
;   F9X_* (v3: BMI2 and ADX): mulx with two carry chains (adcx on CF, adox on OF); squares by the
;     triangle (36 products above the diagonal, then doubled with the nine squares added: 45 mulx
;     against the product's 81);
;   F9Q_* (v1: any x86-64): mul, one carry chain; squares through the product.
; Each product keeps a window of ten accumulator limbs in registers, retiring the lowest to the
; scratch each row; the reduction then reads the low eight limbs back from the scratch.
;
; The products' scratch, F9_SCR, is an rbp-addressed slot of 88 octets in the caller's frame
; (crypto/p521.asm defines it before including this file): the products keep there the low eight
; limbs of t, the output's and b's addresses, and v1's multiplier, so nothing secret lands below
; the frame, which its function wipes before returning. F9_NT (160 octets) is the scalars'
; Montgomery product's window. Both mean every product needs rbp at a P-521 frame.
;
; Scalars modulo n are Montgomery products (CIOS, R = 2^576) with mul at both versions (a
; signature takes a handful): F9_NMUL_BODY; sums and the reduction below 2n by a subtraction
; undone by cmov.
;
; Constant time: no branch and no address depends on an operand; every conditional step is a
; mask, an adc of a mask, or a cmov. The macros clobber the flags and the registers each lists,
; never rbp or rsp.
; =============================================================================
%ifndef HTTPASM_P521_INC
%define HTTPASM_P521_INC

; -----------------------------------------------------------------------------
; F9_LOAD a: a's nine limbs into r8, r9, r10, r11, r12, r13, r14, r15, rbx (in that order: the
; registers every sum, difference and rotation works in). No flags.
; -----------------------------------------------------------------------------
%macro F9_LOAD 1
    mov         r8, [%1]
    mov         r9, [%1 + 8]
    mov         r10, [%1 + 16]
    mov         r11, [%1 + 24]
    mov         r12, [%1 + 32]
    mov         r13, [%1 + 40]
    mov         r14, [%1 + 48]
    mov         r15, [%1 + 56]
    mov         rbx, [%1 + 64]
%endmacro

; -----------------------------------------------------------------------------
; F9_STORE out: r8, r9, r10, r11, r12, r13, r14, r15, rbx to out's nine limbs. No flags.
; -----------------------------------------------------------------------------
%macro F9_STORE 1
    mov         [%1], r8
    mov         [%1 + 8], r9
    mov         [%1 + 16], r10
    mov         [%1 + 24], r11
    mov         [%1 + 32], r12
    mov         [%1 + 40], r13
    mov         [%1 + 48], r14
    mov         [%1 + 56], r15
    mov         [%1 + 64], rbx
%endmacro

; -----------------------------------------------------------------------------
; F9_FOLD l0, l1, l2, l3, l4, l5, l6, l7, l8: the reductions' common tail. In: the nine registers
; hold w = v + 1 for a value v in [0, 2p) (below 2^522; w at least 1). Out: v mod p, below p, in
; the same registers: when w's bit 521 is set (v >= p), w - 2^521 = v - p; otherwise w - 1 = v.
; Both by masking l8 to its 9 bits (w mod 2^521: no change when the bit is clear) and adding
; d = c - 1 (0 when it was set, all ones = -1 when not) over the nine limbs: the -1 cannot
; borrow past the top, as w is at least 1. Clobbers rax, the flags.
; -----------------------------------------------------------------------------
%macro F9_FOLD 9
    mov         rax, %9
    shr         rax, 9                      ; c: w's bit 521 (w < 2^522: nothing above it)
    sub         rax, 1                      ; d = c - 1: 0, or all ones
    and         %9, 0x1FF                   ; w mod 2^521 (64-bit form, as a parameter cannot
                                            ; name its 32-bit half: 0x1FF sign-extends to itself)
    add         %1, rax
    adc         %2, rax
    adc         %3, rax
    adc         %4, rax
    adc         %5, rax
    adc         %6, rax
    adc         %7, rax
    adc         %8, rax
    adc         %9, rax
%endmacro

; -----------------------------------------------------------------------------
; F9_ADD out, a, b: out = a + b mod p (a, b below p; out may be a or b). w = a + b + 1 (stc,
; then nine adc: below 2p + 1 < 2^522), then F9_FOLD. Clobbers rax, rbx, r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro F9_ADD 3
    F9_LOAD     %2
    stc                                     ; the +1 F9_FOLD's test needs
    adc         r8, [%3]
    adc         r9, [%3 + 8]
    adc         r10, [%3 + 16]
    adc         r11, [%3 + 24]
    adc         r12, [%3 + 32]
    adc         r13, [%3 + 40]
    adc         r14, [%3 + 48]
    adc         r15, [%3 + 56]
    adc         rbx, [%3 + 64]
    F9_FOLD     r8, r9, r10, r11, r12, r13, r14, r15, rbx
    F9_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; F9_SUB out, a, b: out = a - b mod p (a, b below p; out may be a or b). The nine-limb
; difference; when it borrows (a < b), the wrapped value a - b + 2^576 reduced modulo 2^521 (the
; top limb masked to 9 bits) is a - b + 2^521, and adding the borrow's mask (all ones: -1) gives
; a - b + p, in [1, p - 1]. Without a borrow the mask is 0 and the top limb, below 2^9 already,
; keeps its bits. Clobbers rax, rbx, r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro F9_SUB 3
    F9_LOAD     %2
    sub         r8, [%3]
    sbb         r9, [%3 + 8]
    sbb         r10, [%3 + 16]
    sbb         r11, [%3 + 24]
    sbb         r12, [%3 + 32]
    sbb         r13, [%3 + 40]
    sbb         r14, [%3 + 48]
    sbb         r15, [%3 + 56]
    sbb         rbx, [%3 + 64]
    sbb         rax, rax                    ; all ones when it borrowed
    and         ebx, 0x1FF                  ; modulo 2^521 (ebx: the and zero-extends)
    add         r8, rax
    adc         r9, rax
    adc         r10, rax
    adc         r11, rax
    adc         r12, rax
    adc         r13, rax
    adc         r14, rax
    adc         r15, rax
    adc         rbx, rax
    F9_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; F9_HALF out, a: out = a / 2 mod p (a below p; out may be a): the 521-bit string rotated right
; one bit (a's bit 0 becomes bit 520: 2^520 is 2's inverse modulo p). Clobbers rax, rbx, r8-r15,
; the flags.
; -----------------------------------------------------------------------------
%macro F9_HALF 2
    F9_LOAD     %2
    mov         eax, r8d
    and         eax, 1
    shl         eax, 8                      ; bit 0 -> bit 520 (the top limb's bit 8)
    shrd        r8, r9, 1                   ; each limb reads the next one's old value: they
    shrd        r9, r10, 1                  ; go up in order
    shrd        r10, r11, 1
    shrd        r11, r12, 1
    shrd        r12, r13, 1
    shrd        r13, r14, 1
    shrd        r14, r15, 1
    shrd        r15, rbx, 1
    shr         rbx, 1
    or          rbx, rax
    F9_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; F9_ROTL out, a, k: out = 2^k a mod p for k = 1, 2 or 3 (a below p; out may be a): the 521-bit
; string rotated left k bits (bits 521 - k .. 520 come round to bits 0 .. k - 1). Doubling (k =
; 1) replaces a + a, and P-521's doubling and additions double often. Clobbers rax, rbx, r8-r15,
; the flags.
; -----------------------------------------------------------------------------
%macro F9_ROTL 3
    F9_LOAD     %2
    mov         rax, rbx
    shr         rax, 9 - %3                 ; the top k bits -> bits 0 .. k - 1
    shld        rbx, r15, %3                ; each limb reads the one below's old value: they
    shld        r15, r14, %3                ; go down in order
    shld        r14, r13, %3
    shld        r13, r12, %3
    shld        r12, r11, %3
    shld        r11, r10, %3
    shld        r10, r9, %3
    shld        r9, r8, %3
    shl         r8, %3
    or          r8, rax
    and         ebx, 0x1FF                  ; the bits rotated out of the top
    F9_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; F9_CNEG mask, a: a = -a mod p where the 64-bit register mask is all ones, a unchanged where it
; is 0 (Booth's negative digits). -a = p - a is a's complement within 521 bits, except that -0
; must stay 0 (p would be no reduced value, and a table scan's "no point", (0, 0), must stay
; (0, 0) whatever the digit's sign): the mask is ANDed with "a is not 0" first. mask may be any
; register but rax and rcx. Clobbers rax, rcx, the flags.
; -----------------------------------------------------------------------------
%macro F9_CNEG 2
    mov         rax, [%2]
    or          rax, [%2 + 8]
    or          rax, [%2 + 16]
    or          rax, [%2 + 24]
    or          rax, [%2 + 32]
    or          rax, [%2 + 40]
    or          rax, [%2 + 48]
    or          rax, [%2 + 56]
    or          rax, [%2 + 64]
    neg         rax                         ; CF = a is not 0
    sbb         rax, rax
    and         rax, %1                     ; the complement's mask
    mov         ecx, eax
    and         ecx, 0x1FF                  ; the top limb's 9 bits of it
    xor         [%2], rax
    xor         [%2 + 8], rax
    xor         [%2 + 16], rax
    xor         [%2 + 24], rax
    xor         [%2 + 32], rax
    xor         [%2 + 40], rax
    xor         [%2 + 48], rax
    xor         [%2 + 56], rax
    xor         [%2 + 64], rcx
%endmacro

; =============================================================================
; The products' common reduction. F9_SCR's layout (88 octets, rbp-addressed; the includer
; defines F9_SCR): +0 .. +56 t's limbs 0..7 (the rows retire them there), +64 the output's
; address, +72 b's address, +80 v1's multiplier b_i.
; =============================================================================

; -----------------------------------------------------------------------------
; F9_REDUCE: the product's t (below p^2 < 2^1042: t[0..7] at F9_SCR, t[8..16] in rbx, rdi, r8,
; r9, r10, r11, r12, r13, r14; t[17] is 0 and not read) reduced modulo p and stored at the
; output's address (F9_SCR + 64). hi = t >> 521 by shrd (each limb reads the next one's old
; value, so they go up in order; hi's top limb is t[16] >> 9), lo's top limb t[8] mod 2^9 kept
; first; w = hi + lo + 1; F9_FOLD. Clobbers rax, rbx, rdi, r8-r14, the flags.
; -----------------------------------------------------------------------------
%macro F9_REDUCE 0
    mov         rax, rbx
    and         eax, 0x1FF                  ; lo's top limb: t[8] mod 2^9
    shrd        rbx, rdi, 9                 ; hi[0] = t[8] >> 9 | t[9] << 55
    shrd        rdi, r8, 9
    shrd        r8, r9, 9
    shrd        r9, r10, 9
    shrd        r10, r11, 9
    shrd        r11, r12, 9
    shrd        r12, r13, 9
    shrd        r13, r14, 9                 ; hi[7]
    shr         r14, 9                      ; hi[8] = t[16] >> 9 (t[17] = 0)
    stc                                     ; w = hi + lo + 1
    adc         rbx, [F9_SCR]
    adc         rdi, [F9_SCR + 8]
    adc         r8, [F9_SCR + 16]
    adc         r9, [F9_SCR + 24]
    adc         r10, [F9_SCR + 32]
    adc         r11, [F9_SCR + 40]
    adc         r12, [F9_SCR + 48]
    adc         r13, [F9_SCR + 56]
    adc         r14, rax
    F9_FOLD     rbx, rdi, r8, r9, r10, r11, r12, r13, r14
    mov         rax, [F9_SCR + 64]          ; the output: written last (it may be an input)
    mov         [rax], rbx
    mov         [rax + 8], rdi
    mov         [rax + 16], r8
    mov         [rax + 24], r9
    mov         [rax + 32], r10
    mov         [rax + 40], r11
    mov         [rax + 48], r12
    mov         [rax + 56], r13
    mov         [rax + 64], r14
%endmacro

; =============================================================================
; v3: mulx, adcx, adox (BMI2 and ADX). a's address in rsi throughout; rdx the multiplier.
; =============================================================================

; -----------------------------------------------------------------------------
; F9X_TERM offset, lo, hi: one product of a's limb at [rsi + offset] by rdx, its low half added
; into lo on the CF chain, its high half into hi on the OF chain. Clobbers rax, rcx.
; -----------------------------------------------------------------------------
%macro F9X_TERM 3
    mulx        rcx, rax, [rsi + %1]
    adcx        %2, rax
    adox        %3, rcx
%endmacro

; -----------------------------------------------------------------------------
; F9X_ROW boffset, t0, t1, t2, t3, t4, t5, t6, t7, t8, t9: one row of the product, t0..t9 +=
; a b_i, with b_i at [b + boffset] (b's address at F9_SCR + 72). t0..t8 hold the running sum's
; limbs i .. i + 8; t9 is the row's new limb, zeroed here (the xor also clears CF and OF for the
; chains). Each a_j b_i adds its low half to t_j (CF) and its high half to t_(j+1) (OF); the OF
; chain ends in t9, which was 0, so it cannot carry out; the CF chain's last carry goes into t9
; (the running sum fits ten limbs from i: no carry passes t9). Clobbers rax, rcx, rdx.
; -----------------------------------------------------------------------------
%macro F9X_ROW 11
    mov         rdx, [F9_SCR + 72]
    mov         rdx, [rdx + %1]             ; b_i
    xor         %11, %11                    ; t9 = 0; CF = OF = 0
    F9X_TERM    0, %2, %3
    F9X_TERM    8, %3, %4
    F9X_TERM    16, %4, %5
    F9X_TERM    24, %5, %6
    F9X_TERM    32, %6, %7
    F9X_TERM    40, %7, %8
    F9X_TERM    48, %8, %9
    F9X_TERM    56, %9, %10
    F9X_TERM    64, %10, %11
    mov         eax, 0                      ; a zero that keeps CF (mov, not xor)
    adcx        %11, rax
%endmacro

; -----------------------------------------------------------------------------
; F9X_MUL_BODY: the body of p521_fmul_v3: rdi = out, rsi = a, rdx = b (each below p; out may be
; a or b: both are read before out is written) -> out = a b mod p. Row 0 makes t = a b0 with one
; chain; rows 1..8 add a b_i over a window of ten limbs that turns through r8, r9, r10, r11, r12,
; r13, r14, r15, rbx, rdi (limb k of t in the (k mod 10)th), each row's lowest limb retired to
; F9_SCR; after row 8, t[8..17] are in rbx, rdi, r8..r15 (t[17] = 0), and F9_REDUCE finishes.
; Clobbers rax, rbx, rcx, rdx, rdi, r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro F9X_MUL_BODY 0
    mov         [F9_SCR + 64], rdi          ; the output's address
    mov         [F9_SCR + 72], rdx          ; b's
    mov         rdx, [rdx]                  ; row 0: t0..t9 = a b0
    mulx        r9, r8, [rsi]
    mulx        r10, rax, [rsi + 8]
    add         r9, rax
    mulx        r11, rax, [rsi + 16]
    adc         r10, rax
    mulx        r12, rax, [rsi + 24]
    adc         r11, rax
    mulx        r13, rax, [rsi + 32]
    adc         r12, rax
    mulx        r14, rax, [rsi + 40]
    adc         r13, rax
    mulx        r15, rax, [rsi + 48]
    adc         r14, rax
    mulx        rbx, rax, [rsi + 56]
    adc         r15, rax
    mulx        rdi, rax, [rsi + 64]
    adc         rbx, rax
    adc         rdi, 0                      ; t9 (mulx keeps the flags: one chain from add)
    mov         [F9_SCR], r8                ; t0: final
    F9X_ROW     8, r9, r10, r11, r12, r13, r14, r15, rbx, rdi, r8
    mov         [F9_SCR + 8], r9
    F9X_ROW     16, r10, r11, r12, r13, r14, r15, rbx, rdi, r8, r9
    mov         [F9_SCR + 16], r10
    F9X_ROW     24, r11, r12, r13, r14, r15, rbx, rdi, r8, r9, r10
    mov         [F9_SCR + 24], r11
    F9X_ROW     32, r12, r13, r14, r15, rbx, rdi, r8, r9, r10, r11
    mov         [F9_SCR + 32], r12
    F9X_ROW     40, r13, r14, r15, rbx, rdi, r8, r9, r10, r11, r12
    mov         [F9_SCR + 40], r13
    F9X_ROW     48, r14, r15, rbx, rdi, r8, r9, r10, r11, r12, r13
    mov         [F9_SCR + 48], r14
    F9X_ROW     56, r15, rbx, rdi, r8, r9, r10, r11, r12, r13, r14
    mov         [F9_SCR + 56], r15
    F9X_ROW     64, rbx, rdi, r8, r9, r10, r11, r12, r13, r14, r15
    F9_REDUCE                               ; t[8..16] = rbx, rdi, r8 .. r14
%endmacro

; -----------------------------------------------------------------------------
; F9X_SQR_BODY: the body of p521_fsqr_v3: rdi = out, rsi = a (below p; out may be a) -> out =
; a^2 mod p. The 36 products above the diagonal once, row i adding a_i a[i+1..8] at positions
; 2i + 1 .. i + 9: t_k and t_(k+9) share a register for k = 1..7 (r8 .. r14: limb k retires
; before limb k + 9 first appears), t8 is rbx and t9 rdi; t1..t7 retire to F9_SCR after the row
; that finishes them. Then one pass from limb 0 up doubles every limb (adcx on CF) and adds the
; nine squares' halves (adox on OF): t0 = 0 takes a0^2's low half alone; t1..t7 go through r15
; from and back to F9_SCR; t8..t16 stay in their registers. a < 2^521 keeps both chains' last
; carries 0 (a^2 < 2^1042), and a8^2's high half is 0. Then F9_REDUCE (t[8..16] in rbx, rdi,
; r8..r14, as the product leaves them). Clobbers rax, rbx, rcx, rdx, rdi, r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro F9X_SQR_BODY 0
    mov         [F9_SCR + 64], rdi          ; the output's address
    ; row 0: t1..t9 = a0 a[1..8] (one chain)
    mov         rdx, [rsi]
    mulx        r9, r8, [rsi + 8]           ; a0 a1: t1, t2
    mulx        r10, rax, [rsi + 16]
    add         r9, rax
    mulx        r11, rax, [rsi + 24]
    adc         r10, rax
    mulx        r12, rax, [rsi + 32]
    adc         r11, rax
    mulx        r13, rax, [rsi + 40]
    adc         r12, rax
    mulx        r14, rax, [rsi + 48]
    adc         r13, rax
    mulx        rbx, rax, [rsi + 56]        ; a0 a7: t7, t8
    adc         r14, rax
    mulx        rdi, rax, [rsi + 64]        ; a0 a8: t8, t9
    adc         rbx, rax
    adc         rdi, 0
    mov         [F9_SCR + 8], r8            ; t1, t2: no later row reaches them
    mov         [F9_SCR + 16], r9
    ; row 1: t3..t10 += a1 a[2..8] (t10 = r8, new)
    mov         rdx, [rsi + 8]
    xor         r8d, r8d                    ; t10 = 0; CF = OF = 0
    F9X_TERM    16, r10, r11                ; a1 a2: t3, t4
    F9X_TERM    24, r11, r12
    F9X_TERM    32, r12, r13
    F9X_TERM    40, r13, r14
    F9X_TERM    48, r14, rbx
    F9X_TERM    56, rbx, rdi
    F9X_TERM    64, rdi, r8                 ; a1 a8: t9, t10
    mov         eax, 0
    adcx        r8, rax
    mov         [F9_SCR + 24], r10          ; t3, t4
    mov         [F9_SCR + 32], r11
    ; row 2: t5..t11 += a2 a[3..8] (t11 = r9, new)
    mov         rdx, [rsi + 16]
    xor         r9d, r9d
    F9X_TERM    24, r12, r13                ; a2 a3: t5, t6
    F9X_TERM    32, r13, r14
    F9X_TERM    40, r14, rbx
    F9X_TERM    48, rbx, rdi
    F9X_TERM    56, rdi, r8
    F9X_TERM    64, r8, r9                  ; a2 a8: t10, t11
    mov         eax, 0
    adcx        r9, rax
    mov         [F9_SCR + 40], r12          ; t5, t6
    mov         [F9_SCR + 48], r13
    ; row 3: t7..t12 += a3 a[4..8] (t12 = r10, new)
    mov         rdx, [rsi + 24]
    xor         r10d, r10d
    F9X_TERM    32, r14, rbx                ; a3 a4: t7, t8
    F9X_TERM    40, rbx, rdi
    F9X_TERM    48, rdi, r8
    F9X_TERM    56, r8, r9
    F9X_TERM    64, r9, r10                 ; a3 a8: t11, t12
    mov         eax, 0
    adcx        r10, rax
    mov         [F9_SCR + 56], r14          ; t7 (t8 stays in rbx)
    ; row 4: t9..t13 += a4 a[5..8] (t13 = r11, new)
    mov         rdx, [rsi + 32]
    xor         r11d, r11d
    F9X_TERM    40, rdi, r8                 ; a4 a5: t9, t10
    F9X_TERM    48, r8, r9
    F9X_TERM    56, r9, r10
    F9X_TERM    64, r10, r11                ; a4 a8: t12, t13
    mov         eax, 0
    adcx        r11, rax
    ; row 5: t11..t14 += a5 a[6..8] (t14 = r12, new)
    mov         rdx, [rsi + 40]
    xor         r12d, r12d
    F9X_TERM    48, r9, r10                 ; a5 a6: t11, t12
    F9X_TERM    56, r10, r11
    F9X_TERM    64, r11, r12                ; a5 a8: t13, t14
    mov         eax, 0
    adcx        r12, rax
    ; row 6: t13..t15 += a6 a[7..8] (t15 = r13, new)
    mov         rdx, [rsi + 48]
    xor         r13d, r13d
    F9X_TERM    56, r11, r12                ; a6 a7: t13, t14
    F9X_TERM    64, r12, r13                ; a6 a8: t14, t15
    mov         eax, 0
    adcx        r13, rax
    ; row 7: t15..t16 += a7 a8 (t16 = r14, new: its high half alone)
    mov         rdx, [rsi + 56]
    mulx        r14, rax, [rsi + 64]
    add         r13, rax
    adc         r14, 0
    ; the pass: T_k = 2 t_k + the squares' halves (a_i^2 at limbs 2i, 2i + 1)
    mov         rdx, [rsi]
    mulx        rcx, rax, rdx               ; a0^2
    mov         [F9_SCR], rax               ; T0 (t0 = 0)
    xor         eax, eax                    ; CF = OF = 0
    mov         r15, [F9_SCR + 8]
    adcx        r15, r15
    adox        r15, rcx
    mov         [F9_SCR + 8], r15           ; T1
    F9X_SQ_LOW  8, 16, 24                   ; a1^2: T2, T3
    F9X_SQ_LOW  16, 32, 40                  ; a2^2: T4, T5
    F9X_SQ_LOW  24, 48, 56                  ; a3^2: T6, T7
    F9X_SQ_HIGH 32, rbx, rdi                ; a4^2: T8, T9
    F9X_SQ_HIGH 40, r8, r9                  ; a5^2: T10, T11
    F9X_SQ_HIGH 48, r10, r11                ; a6^2: T12, T13
    F9X_SQ_HIGH 56, r12, r13                ; a7^2: T14, T15
    mov         rdx, [rsi + 64]
    mulx        rcx, rax, rdx               ; a8^2 (below 2^18: rcx = 0)
    adcx        r14, r14
    adox        r14, rax                    ; T16
    F9_REDUCE
%endmacro

; F9X_SQ_LOW aoffset, k, k1: the pass over limbs k and k1 (byte offsets into F9_SCR) with the
; square of a's limb at [rsi + aoffset]: each limb from the scratch into r15, doubled (CF), its
; half added (OF), and back. Clobbers rax, rcx, rdx, r15 (no flags but the two chains').
%macro F9X_SQ_LOW 3
    mov         rdx, [rsi + %1]
    mulx        rcx, rax, rdx
    mov         r15, [F9_SCR + %2]
    adcx        r15, r15
    adox        r15, rax
    mov         [F9_SCR + %2], r15
    mov         r15, [F9_SCR + %3]
    adcx        r15, r15
    adox        r15, rcx
    mov         [F9_SCR + %3], r15
%endmacro

; F9X_SQ_HIGH aoffset, lo, hi: the same for two limbs held in registers. Clobbers rax, rcx, rdx.
%macro F9X_SQ_HIGH 3
    mov         rdx, [rsi + %1]
    mulx        rcx, rax, rdx
    adcx        %2, %2
    adox        %2, rax
    adcx        %3, %3
    adox        %3, rcx
%endmacro

; =============================================================================
; v1: mul (any x86-64). a's address in rsi throughout; the row's multiplier b_i at F9_SCR + 80
; (mul's memory operand: every register is taken by the window, rax and rdx, and the carry).
; =============================================================================

; -----------------------------------------------------------------------------
; F9Q_ROW boffset, t0, t1, t2, t3, t4, t5, t6, t7, t8, t9: t0..t8 += a b_i with b_i at
; [b + boffset], the carries through rcx; t9 (new) = the last carry. Each term: a_j b_i plus the
; carry in (rcx) plus t_j, below 2^128: the high word, with both adds' carries, is the carry out.
; Clobbers rax, rcx, rdx, the flags.
; -----------------------------------------------------------------------------
%macro F9Q_ROW 11
    mov         rax, [F9_SCR + 72]
    mov         rax, [rax + %1]
    mov         [F9_SCR + 80], rax          ; b_i
    mov         rax, [rsi]
    mul         qword [F9_SCR + 80]
    add         %2, rax
    adc         rdx, 0
    mov         rcx, rdx
    F9Q_LIMB    8, %3
    F9Q_LIMB    16, %4
    F9Q_LIMB    24, %5
    F9Q_LIMB    32, %6
    F9Q_LIMB    40, %7
    F9Q_LIMB    48, %8
    F9Q_LIMB    56, %9
    F9Q_LIMB    64, %10
    mov         %11, rcx                    ; the new limb is the row's carry
%endmacro

; F9Q_LIMB aoffset, t: t += a's limb at [rsi + aoffset] times b_i, plus the carry in rcx; rcx =
; the carry out. Clobbers rax, rdx, the flags.
%macro F9Q_LIMB 2
    mov         rax, [rsi + %1]
    mul         qword [F9_SCR + 80]
    add         rax, rcx
    adc         rdx, 0
    add         %2, rax
    adc         rdx, 0
    mov         rcx, rdx
%endmacro

; F9Q_FIRST aoffset, lo, hi: row 0's term: lo += a's limb times b0 (low half), hi = the high half
; plus the carry. Clobbers rax, rdx, the flags.
%macro F9Q_FIRST 3
    mov         rax, [rsi + %1]
    mul         qword [F9_SCR + 80]
    add         %2, rax
    adc         rdx, 0
    mov         %3, rdx
%endmacro

; -----------------------------------------------------------------------------
; F9Q_MUL_BODY: the body of p521_fmul_v1: rdi = out, rsi = a, rdx = b (each below p; out may be
; a or b) -> out = a b mod p: F9X_MUL_BODY's rows and window with mul and one carry chain, then
; F9_REDUCE. Clobbers rax, rbx, rcx, rdx, rdi, r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro F9Q_MUL_BODY 0
    mov         [F9_SCR + 64], rdi          ; the output's address
    mov         [F9_SCR + 72], rdx          ; b's
    mov         rax, [rdx]
    mov         [F9_SCR + 80], rax          ; b0
    mov         rax, [rsi]                  ; row 0: t0..t9 = a b0
    mul         qword [F9_SCR + 80]
    mov         r8, rax
    mov         r9, rdx
    F9Q_FIRST   8, r9, r10
    F9Q_FIRST   16, r10, r11
    F9Q_FIRST   24, r11, r12
    F9Q_FIRST   32, r12, r13
    F9Q_FIRST   40, r13, r14
    F9Q_FIRST   48, r14, r15
    F9Q_FIRST   56, r15, rbx
    F9Q_FIRST   64, rbx, rdi
    mov         [F9_SCR], r8                ; t0
    F9Q_ROW     8, r9, r10, r11, r12, r13, r14, r15, rbx, rdi, r8
    mov         [F9_SCR + 8], r9
    F9Q_ROW     16, r10, r11, r12, r13, r14, r15, rbx, rdi, r8, r9
    mov         [F9_SCR + 16], r10
    F9Q_ROW     24, r11, r12, r13, r14, r15, rbx, rdi, r8, r9, r10
    mov         [F9_SCR + 24], r11
    F9Q_ROW     32, r12, r13, r14, r15, rbx, rdi, r8, r9, r10, r11
    mov         [F9_SCR + 32], r12
    F9Q_ROW     40, r13, r14, r15, rbx, rdi, r8, r9, r10, r11, r12
    mov         [F9_SCR + 40], r13
    F9Q_ROW     48, r14, r15, rbx, rdi, r8, r9, r10, r11, r12, r13
    mov         [F9_SCR + 48], r14
    F9Q_ROW     56, r15, rbx, rdi, r8, r9, r10, r11, r12, r13, r14
    mov         [F9_SCR + 56], r15
    F9Q_ROW     64, rbx, rdi, r8, r9, r10, r11, r12, r13, r14, r15
    F9_REDUCE
%endmacro

; =============================================================================
; Scalars modulo n (nine limbs, below n).
; =============================================================================

; -----------------------------------------------------------------------------
; F9_NMUL_BODY: the body of p521_nmul: rdi = out, rsi = a, rdx = b (each below n; out may be a or
; b) -> out = a b R^-1 mod n, R = 2^576 (a Montgomery product by R^2 mod n after it gives the
; plain product). CIOS (Koc, Acar and Kaliski) with t in memory: F9_NT holds 20 qwords, zeroed,
; and round i works on t[i .. i + 9]: t += a b_i, then t += m n with m = t[i] n0, which makes
; t[i] zero (so the window moves up one qword instead of shifting t). t stays below 2n between
; rounds and below 2^587 within one, so nothing carries past t[i + 9]. The last window, t[9..17],
; is below 2n: n is subtracted, and the difference undone limb by limb by cmov from memory when
; it borrowed. Rounds by a loop (nine, the counter public). Clobbers rax, rbx, rcx, rdx, rsi, rdi,
; r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro F9_NMUL_BODY 0
    mov         r11, rdi                    ; the output's address
    mov         r9, rdx                     ; b's next limb
    xor         eax, eax
  %assign nm_q 0
  %rep 20
    mov         [F9_NT + nm_q], rax
    %assign nm_q nm_q + 8
  %endrep
    lea         r8, [F9_NT]                 ; the window: t[i]
    mov         r10d, 9
%%round:
    mov         rcx, [r9]                   ; b_i
    xor         edi, edi                    ; the carry
  %assign nm_j 0
  %rep 9
    mov         rax, [rsi + nm_j]
    mul         rcx
    add         rax, rdi
    adc         rdx, 0
    add         [r8 + nm_j], rax
    adc         rdx, 0
    mov         rdi, rdx
    %assign nm_j nm_j + 8
  %endrep
    add         [r8 + 72], rdi              ; t[i + 9] (no carry past it)
    mov         rcx, [r8]
    imul        rcx, [rel p521_n0]          ; m: t[i] + m n0's low half is 0 mod 2^64
    xor         edi, edi
  %assign nm_j 0
  %rep 9
    mov         rax, [rel p521_n + nm_j]
    mul         rcx
    add         rax, rdi
    adc         rdx, 0
    add         [r8 + nm_j], rax
    adc         rdx, 0
    mov         rdi, rdx
    %assign nm_j nm_j + 8
  %endrep
    add         [r8 + 72], rdi
    add         r8, 8                       ; t[i] is 0 now: the window moves up
    add         r9, 8
    dec         r10d
    jnz         %%round
    ; r8 = t[9]: the result below 2n, less n unless that borrows
    mov         r12, [r8]
    mov         r13, [r8 + 8]
    mov         r14, [r8 + 16]
    mov         r15, [r8 + 24]
    mov         rbx, [r8 + 32]
    mov         rsi, [r8 + 40]
    mov         rdi, [r8 + 48]
    mov         r9, [r8 + 56]
    mov         r10, [r8 + 64]
    sub         r12, [rel p521_n]
    sbb         r13, [rel p521_n + 8]
    sbb         r14, [rel p521_n + 16]
    sbb         r15, [rel p521_n + 24]
    sbb         rbx, [rel p521_n + 32]
    sbb         rsi, [rel p521_n + 40]
    sbb         rdi, [rel p521_n + 48]
    sbb         r9, [rel p521_n + 56]
    sbb         r10, [rel p521_n + 64]
    cmovc       r12, [r8]                   ; it borrowed: the value was below n already
    cmovc       r13, [r8 + 8]
    cmovc       r14, [r8 + 16]
    cmovc       r15, [r8 + 24]
    cmovc       rbx, [r8 + 32]
    cmovc       rsi, [r8 + 40]
    cmovc       rdi, [r8 + 48]
    cmovc       r9, [r8 + 56]
    cmovc       r10, [r8 + 64]
    mov         [r11], r12
    mov         [r11 + 8], r13
    mov         [r11 + 16], r14
    mov         [r11 + 24], r15
    mov         [r11 + 32], rbx
    mov         [r11 + 40], rsi
    mov         [r11 + 48], rdi
    mov         [r11 + 56], r9
    mov         [r11 + 64], r10
%endmacro

; -----------------------------------------------------------------------------
; F9_NSUBN slot: r8, r9, r10, r11, r12, r13, r14, r15, rbx (a value below 2n, also stored at
; slot) less n unless that borrows, restored from slot by cmov when it does; stored back to slot.
; Clobbers r8-r15, rbx, the flags.
; -----------------------------------------------------------------------------
%macro F9_NSUBN 1
    sub         r8, [rel p521_n]
    sbb         r9, [rel p521_n + 8]
    sbb         r10, [rel p521_n + 16]
    sbb         r11, [rel p521_n + 24]
    sbb         r12, [rel p521_n + 32]
    sbb         r13, [rel p521_n + 40]
    sbb         r14, [rel p521_n + 48]
    sbb         r15, [rel p521_n + 56]
    sbb         rbx, [rel p521_n + 64]
    cmovc       r8, [%1]
    cmovc       r9, [%1 + 8]
    cmovc       r10, [%1 + 16]
    cmovc       r11, [%1 + 24]
    cmovc       r12, [%1 + 32]
    cmovc       r13, [%1 + 40]
    cmovc       r14, [%1 + 48]
    cmovc       r15, [%1 + 56]
    cmovc       rbx, [%1 + 64]
    F9_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; F9_NADD out, a, b: out = a + b mod n (a, b below n; out may be a or b): the sum (below 2n <
; 2^522: no carry out of nine limbs), stored, then F9_NSUBN. Clobbers rbx, r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro F9_NADD 3
    F9_LOAD     %2
    add         r8, [%3]
    adc         r9, [%3 + 8]
    adc         r10, [%3 + 16]
    adc         r11, [%3 + 24]
    adc         r12, [%3 + 32]
    adc         r13, [%3 + 40]
    adc         r14, [%3 + 48]
    adc         r15, [%3 + 56]
    adc         rbx, [%3 + 64]
    F9_STORE    %1
    F9_NSUBN    %1
%endmacro

; -----------------------------------------------------------------------------
; F9_NREDUCE slot: slot = slot mod n for any value below 2^521 (below 2n: one subtraction).
; Clobbers rbx, r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro F9_NREDUCE 1
    F9_LOAD     %1
    F9_NSUBN    %1
%endmacro

; =============================================================================
; The call sites (crypto/p521.asm's routines are p521_fmul_v3, p521_fsqr_v3, p521_fmul_v1,
; p521_fsqr_v1 and p521_nmul). Operands are addresses: frame slots ("rbp + PF_T0") or constants
; ("rel p521_b"). Each clobbers every register but rbp and rsp.
; =============================================================================

; F9_FMUL v, out, a, b: out = a b mod p, version v.
%macro F9_FMUL 4
    lea         rdi, [%2]
    lea         rsi, [%3]
    lea         rdx, [%4]
    call        p521_fmul_%1
%endmacro

; F9_FSQR v, out, a: out = a^2 mod p, version v.
%macro F9_FSQR 3
    lea         rdi, [%2]
    lea         rsi, [%3]
    call        p521_fsqr_%1
%endmacro

; F9_NMUL out, a, b: out = a b R^-1 mod n (every version: mul).
%macro F9_NMUL 3
    lea         rdi, [%1]
    lea         rsi, [%2]
    lea         rdx, [%3]
    call        p521_nmul
%endmacro

%endif
