; =============================================================================
; include/crypto/p384.inc - arithmetic modulo the prime p = 2^384 - 2^128 - 2^96 + 2^32 - 1 of
; the NIST curve P-384 (SP 800-186 3.2.1.4, the curve TLS calls secp384r1) and modulo its group
; order n (ECDSA's scalars), for crypto/p384.asm. include/crypto/p256.inc's twin at six limbs.
;
; Values are six 64-bit limbs, little-endian, FULLY reduced (below the modulus) between
; operations; every macro takes and leaves reduced values (48 octets in memory: operands are
; addresses, normally frame slots off rbp, or constants as "rel p384_..."). Field values are in
; Montgomery form, a R mod p with R = 2^384: a product of two is a b R^-1 mod p, the form of the
; product, so a whole scalar multiplication runs inside the form. Full reduction is what lets
; the caller compare values limb by limb (the curve equation, verification's x-coordinate, the
; point at infinity's Z = 0).
;
; One Montgomery product serves both moduli: CIOS (Koc, Acar and Kaliski) over a modulus M in
; memory with its n0 = -M^-1 mod 2^64 (p384_p and p384_p0 = 2^32 + 1 for p, p384_n and p384_n0
; for n): six rounds of t += a b_i, then t += m M with m = t0 n0, the eight limbs of t turning
; through r8..r15 so that nothing moves between rounds; one subtraction of M by cmov at the end.
; Why generic for p too (measured, scratchpad p384/f6.asm, cycles on the i9-13900K's P-core):
; 130 a product chained, 114 at throughput; m by shl and add (p0 = 2^32 + 1) instead of imul,
; 131: no gain. p's special form (m p = m 2^384 - m (2^128 + 2^96 - 2^32 + 1)) would trade the
; reduction's six mulx for about fourteen add, adc, sub and sbb a step, and every carry
; instruction runs on ports 0 and 6 only, which the twelve adcx/adox of the generic step already
; keep busy (include/crypto/p256.inc's header has the measurement of those ports).
;
; Two versions of the products, the rest shared:
;   F6X_* (v3: BMI2 and ADX): mulx with two carry chains, adcx on CF and adox on OF;
;   F6Q_* (v1: any x86-64): mul, one carry chain.
; Each version's macros have the same names after the prefix (F6X_MUL / F6Q_MUL, and F6X_ADD /
; F6Q_ADD for the shared F6_ADD), so crypto/p384.asm's point routines take the prefix as a
; parameter and are written once. v3 squares with its own F6X_SQR (the products above the
; diagonal once: 21 mulx and the reduction's 36 against the product's 72); v1 squares through
; F6Q_MUL, as mul overwrites the flags that a doubling chain and the squares' additions would
; share.
;
; Constant time: no branch and no address depends on an operand; the final subtractions are
; cmov or masks. The macros clobber the flags and the registers each lists, never rbp or rsp
; (operands are addressed off them).
; =============================================================================
%ifndef HTTPASM_P384_INC
%define HTTPASM_P384_INC

; -----------------------------------------------------------------------------
; F6_STORE out: the six limbs r8..r13 to out. No flags.
; -----------------------------------------------------------------------------
%macro F6_STORE 1
    mov         [%1], r8
    mov         [%1 + 8], r9
    mov         [%1 + 16], r10
    mov         [%1 + 24], r11
    mov         [%1 + 32], r12
    mov         [%1 + 40], r13
%endmacro

; -----------------------------------------------------------------------------
; F6_LOAD a: a's six limbs into r8..r13. No flags.
; -----------------------------------------------------------------------------
%macro F6_LOAD 1
    mov         r8, [%1]
    mov         r9, [%1 + 8]
    mov         r10, [%1 + 16]
    mov         r11, [%1 + 24]
    mov         r12, [%1 + 32]
    mov         r13, [%1 + 40]
%endmacro

; -----------------------------------------------------------------------------
; F6_SUBM m: the final reduction of a sum. In: r14:r13..r8, a value below 2M (r14, the carry
; word, 0 or 1). Out: r8..r13 = the value modulo M, below M: M subtracted when that does not
; borrow, selected by cmov (no branch on the value). Clobbers rax, rbx, rcx, rdx, rsi, rdi, r14,
; the flags.
; -----------------------------------------------------------------------------
%macro F6_SUBM 1
    mov         rax, r8
    sub         rax, [%1]
    mov         rbx, r9
    sbb         rbx, [%1 + 8]
    mov         rcx, r10
    sbb         rcx, [%1 + 16]
    mov         rdx, r11
    sbb         rdx, [%1 + 24]
    mov         rsi, r12
    sbb         rsi, [%1 + 32]
    mov         rdi, r13
    sbb         rdi, [%1 + 40]
    sbb         r14, 0                      ; borrow out of the carry word: the value was below M
    cmovnc      r8, rax
    cmovnc      r9, rbx
    cmovnc      r10, rcx
    cmovnc      r11, rdx
    cmovnc      r12, rsi
    cmovnc      r13, rdi
%endmacro

; -----------------------------------------------------------------------------
; F6_MASKED m, mask: M's six limbs ANDed with the 64-bit register mask (all ones or 0) into rax,
; rbx, rcx, rdx, rsi, rdi: what a subtraction adds back, or a halving adds, by mask. The ands
; clear the flags: no carry chain may be open across it. Clobbers those six registers.
; -----------------------------------------------------------------------------
%macro F6_MASKED 2
    mov         rax, [%1]
    and         rax, %2
    mov         rbx, [%1 + 8]
    and         rbx, %2
    mov         rcx, [%1 + 16]
    and         rcx, %2
    mov         rdx, [%1 + 24]
    and         rdx, %2
    mov         rsi, [%1 + 32]
    and         rsi, %2
    mov         rdi, [%1 + 40]
    and         rdi, %2
%endmacro

; -----------------------------------------------------------------------------
; F6_ADD out, a, b, m: out = a + b mod M. The 385-bit sum, then F6_SUBM (a + b < 2M). out may
; be a or b. Clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r14, the flags.
; -----------------------------------------------------------------------------
%macro F6_ADD 4
    xor         r14d, r14d
    F6_LOAD     %2
    add         r8, [%3]
    adc         r9, [%3 + 8]
    adc         r10, [%3 + 16]
    adc         r11, [%3 + 24]
    adc         r12, [%3 + 32]
    adc         r13, [%3 + 40]
    adc         r14, 0
    F6_SUBM     %4
    F6_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; F6_SUB out, a, b, m: out = a - b mod M. The difference, then M added back when it borrowed (M
; masked by the borrow: no branch). out may be a or b. Clobbers rax, rbx, rcx, rdx, rsi, rdi,
; r8-r14, the flags.
; -----------------------------------------------------------------------------
%macro F6_SUB 4
    F6_LOAD     %2
    sub         r8, [%3]
    sbb         r9, [%3 + 8]
    sbb         r10, [%3 + 16]
    sbb         r11, [%3 + 24]
    sbb         r12, [%3 + 32]
    sbb         r13, [%3 + 40]
    sbb         r14, r14                    ; all ones when it borrowed, else 0
    F6_MASKED   %4, r14
    add         r8, rax
    adc         r9, rbx
    adc         r10, rcx
    adc         r11, rdx
    adc         r12, rsi
    adc         r13, rdi
    F6_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; F6_CNEG mask, a, m: a = -a mod M where the 64-bit register mask is all ones, a unchanged where
; it is 0 (Booth's negative digits). 0 - a, with M added back when that borrows (so -0 is 0, not
; M: a table scan's "no point", (0, 0), stays (0, 0) whatever the digit's sign), then each limb
; chosen by the mask: no branch. The mask must be r15 (every other register but rbp and rsp is
; used). Clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r14, the flags.
; -----------------------------------------------------------------------------
%macro F6_CNEG 3
    xor         r8d, r8d
    xor         r9d, r9d
    xor         r10d, r10d
    xor         r11d, r11d
    xor         r12d, r12d
    xor         r13d, r13d
    sub         r8, [%2]
    sbb         r9, [%2 + 8]
    sbb         r10, [%2 + 16]
    sbb         r11, [%2 + 24]
    sbb         r12, [%2 + 32]
    sbb         r13, [%2 + 40]
    sbb         r14, r14                    ; all ones unless a = 0
    F6_MASKED   %3, r14
    add         r8, rax
    adc         r9, rbx
    adc         r10, rcx
    adc         r11, rdx
    adc         r12, rsi
    adc         r13, rdi                    ; -a mod M, below M
    F6_PICK     r8, %2, %1                  ; each limb = a ^ ((a ^ -a) & mask)
    F6_PICK     r9, %2 + 8, %1
    F6_PICK     r10, %2 + 16, %1
    F6_PICK     r11, %2 + 24, %1
    F6_PICK     r12, %2 + 32, %1
    F6_PICK     r13, %2 + 40, %1
    F6_STORE    %2
%endmacro

; F6_PICK reg, a, mask: reg = a's limb where mask is 0, reg kept where mask is all ones (a ^ ((a ^
; reg) & mask)). Clobbers rax, the flags.
%macro F6_PICK 3
    mov         rax, [%2]
    xor         %1, rax
    and         %1, %3
    xor         %1, rax
%endmacro

; -----------------------------------------------------------------------------
; F6_HALF out, a, m: out = a / 2 mod M: (a + M) / 2 when a is odd, else a / 2 (M added under a
; mask, then the 385-bit sum shifted down one bit). Clobbers rax, rbx, rcx, rdx, rsi, rdi,
; r8-r14, the flags.
; -----------------------------------------------------------------------------
%macro F6_HALF 3
    F6_LOAD     %2
    mov         r14d, 1
    and         r14, r8
    neg         r14                         ; all ones when a is odd
    F6_MASKED   %3, r14
    add         r8, rax
    adc         r9, rbx
    adc         r10, rcx
    adc         r11, rdx
    adc         r12, rsi
    adc         r13, rdi
    mov         r14d, 0                     ; (mov keeps CF)
    adc         r14, 0                      ; the sum's bit 384
    shrd        r8, r9, 1
    shrd        r9, r10, 1
    shrd        r10, r11, 1
    shrd        r11, r12, 1
    shrd        r12, r13, 1
    shrd        r13, r14, 1
    F6_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; F6_FINAL out, t0, t1, t2, t3, t4, t5, carry: out = the product's t (six limbs in the registers
; named, below 2M with the carry word) minus M when that does not borrow, by cmov, stored. M is
; F6_M_ (the macro's caller defines it). The temporaries are the registers the products leave
; free at their end: rax, rbx, rcx, rdx, rsi, rdi. Clobbers them, the carry word, the flags.
; -----------------------------------------------------------------------------
%macro F6_FINAL 8
    mov         rax, %2
    sub         rax, [F6_M_]
    mov         rbx, %3
    sbb         rbx, [F6_M_ + 8]
    mov         rcx, %4
    sbb         rcx, [F6_M_ + 16]
    mov         rdx, %5
    sbb         rdx, [F6_M_ + 24]
    mov         rsi, %6
    sbb         rsi, [F6_M_ + 32]
    mov         rdi, %7
    sbb         rdi, [F6_M_ + 40]
    sbb         %8, 0                       ; borrow out of the carry word: t was below M
    cmovnc      %2, rax
    cmovnc      %3, rbx
    cmovnc      %4, rcx
    cmovnc      %5, rdx
    cmovnc      %6, rsi
    cmovnc      %7, rdi
    mov         [%1], %2
    mov         [%1 + 8], %3
    mov         [%1 + 16], %4
    mov         [%1 + 24], %5
    mov         [%1 + 32], %6
    mov         [%1 + 40], %7
%endmacro

; =============================================================================
; v3: mulx, adcx, adox (BMI2 and ADX).
; =============================================================================

; -----------------------------------------------------------------------------
; F6X_MAC a, t0, t1, t2, t3, t4, t5, t6, t7: t0..t6 += a rdx (rdx: the multiplier), the six
; products a_j rdx in two carry chains (low halves on CF, high halves on OF); t7 = the carry word
; out (CF + OF, at most 1: the running t stays below 2^449). Clobbers rax, rcx, the flags.
; -----------------------------------------------------------------------------
%macro F6X_MAC 9
    xor         %9, %9                      ; t7 = 0, and CF = OF = 0 for the chains
    mulx        rcx, rax, [%1]              ; a0 rdx
    adcx        %2, rax
    adox        %3, rcx
    mulx        rcx, rax, [%1 + 8]          ; a1 rdx
    adcx        %3, rax
    adox        %4, rcx
    mulx        rcx, rax, [%1 + 16]         ; a2 rdx
    adcx        %4, rax
    adox        %5, rcx
    mulx        rcx, rax, [%1 + 24]         ; a3 rdx
    adcx        %5, rax
    adox        %6, rcx
    mulx        rcx, rax, [%1 + 32]         ; a4 rdx
    adcx        %6, rax
    adox        %7, rcx
    mulx        rcx, rax, [%1 + 40]         ; a5 rdx
    adcx        %7, rax
    adox        %8, rcx                     ; OF: the high chain's carry out of t6
    mov         eax, 0                      ; a zero that keeps the flags (mov, not xor)
    adcx        %8, rax                     ; CF: the low chain's carry out of t5, into t6
    adcx        %9, rax                     ; t7 = CF
    adox        %9, rax                     ; t7 += OF
%endmacro

; -----------------------------------------------------------------------------
; F6X_RED m, n0, t0, t1, t2, t3, t4, t5, t6, t7: one Montgomery step: t += q M with q = t0 n0
; mod 2^64 (t0 then holds 0, and the caller drops it by renaming the registers down one limb);
; the carries out of t6 into t7 (added). Clobbers rax, rcx, rdx, the flags.
; -----------------------------------------------------------------------------
%macro F6X_RED 10
    mov         rdx, %3
    imul        rdx, %2                     ; q
    xor         eax, eax                    ; CF = OF = 0
    mulx        rcx, rax, [%1]              ; q m0: t0 + its low half is 0 (q's choice)
    adcx        %3, rax
    adox        %4, rcx
    mulx        rcx, rax, [%1 + 8]
    adcx        %4, rax
    adox        %5, rcx
    mulx        rcx, rax, [%1 + 16]
    adcx        %5, rax
    adox        %6, rcx
    mulx        rcx, rax, [%1 + 24]
    adcx        %6, rax
    adox        %7, rcx
    mulx        rcx, rax, [%1 + 32]
    adcx        %7, rax
    adox        %8, rcx
    mulx        rcx, rax, [%1 + 40]
    adcx        %8, rax
    adox        %9, rcx
    mov         eax, 0
    adcx        %9, rax
    adcx        %10, rax
    adox        %10, rax
%endmacro

; -----------------------------------------------------------------------------
; F6X_MUL out, a, b, m, n0: out = a b R^-1 mod M (a, b below M; out may be a or b: both are
; read before out is written). Round 0 makes t = a b0 with one chain; then each round t += a b_i
; (F6X_MAC) after the previous reduction step (F6X_RED), the eight limbs of t turning through
; r8..r15; then F6_FINAL. Clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro F6X_MUL 5
  %define F6_M_ %4
    mov         rdx, [%3]                   ; round 0: t = a b0
    mulx        r9, r8, [%2]
    mulx        r10, rax, [%2 + 8]
    add         r9, rax
    mulx        r11, rax, [%2 + 16]
    adc         r10, rax
    mulx        r12, rax, [%2 + 24]
    adc         r11, rax
    mulx        r13, rax, [%2 + 32]
    adc         r12, rax
    mulx        r14, rax, [%2 + 40]
    adc         r13, rax
    adc         r14, 0
    mov         r15d, 0                     ; t7, the carry word
    F6X_RED     %4, %5, r8, r9, r10, r11, r12, r13, r14, r15
    mov         rdx, [%3 + 8]               ; t = r9..r15 (r8 is 0: the next carry word)
    F6X_MAC     %2, r9, r10, r11, r12, r13, r14, r15, r8
    F6X_RED     %4, %5, r9, r10, r11, r12, r13, r14, r15, r8
    mov         rdx, [%3 + 16]
    F6X_MAC     %2, r10, r11, r12, r13, r14, r15, r8, r9
    F6X_RED     %4, %5, r10, r11, r12, r13, r14, r15, r8, r9
    mov         rdx, [%3 + 24]
    F6X_MAC     %2, r11, r12, r13, r14, r15, r8, r9, r10
    F6X_RED     %4, %5, r11, r12, r13, r14, r15, r8, r9, r10
    mov         rdx, [%3 + 32]
    F6X_MAC     %2, r12, r13, r14, r15, r8, r9, r10, r11
    F6X_RED     %4, %5, r12, r13, r14, r15, r8, r9, r10, r11
    mov         rdx, [%3 + 40]
    F6X_MAC     %2, r13, r14, r15, r8, r9, r10, r11, r12
    F6X_RED     %4, %5, r13, r14, r15, r8, r9, r10, r11, r12
    ; t = r14 r15 r8 r9 r10 r11 with the carry word r12, below 2M
    F6_FINAL    %1, r14, r15, r8, r9, r10, r11, r12
  %undef F6_M_
%endmacro

; -----------------------------------------------------------------------------
; F6X_SQR out, a, m, n0: out = a^2 R^-1 mod M (a below M; out may be a). The 768-bit square
; with each product above the diagonal once (15 mulx in five rows, t1..t10 in registers), then
; doubled on CF while the six squares join on OF (6 mulx); the high half t6..t11 parked in out
; (a is read no more), the low half reduced by six Montgomery steps (F6X_RED, the turning
; registers of F6X_MUL), the high half added (below 2M: the reduced low half is at most M, the
; high half below M), F6_FINAL. Clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro F6X_SQR 4
  %define F6_M_ %3
    ; row 0: t1..t6 = a0 a[1..5] (one chain)
    mov         rdx, [%2]
    mulx        r10, r9, [%2 + 8]           ; a0 a1: t1, and t2's start
    mulx        r11, rax, [%2 + 16]         ; a0 a2
    add         r10, rax
    mulx        r12, rax, [%2 + 24]         ; a0 a3
    adc         r11, rax
    mulx        r13, rax, [%2 + 32]         ; a0 a4
    adc         r12, rax
    mulx        r14, rax, [%2 + 40]         ; a0 a5
    adc         r13, rax
    adc         r14, 0                      ; t6
    ; row 1: t3..t7 += a1 a[2..5] (two chains; t7 = r15 starts at 0)
    mov         rdx, [%2 + 8]
    xor         r15d, r15d
    mulx        rcx, rax, [%2 + 16]
    adcx        r11, rax
    adox        r12, rcx
    mulx        rcx, rax, [%2 + 24]
    adcx        r12, rax
    adox        r13, rcx
    mulx        rcx, rax, [%2 + 32]
    adcx        r13, rax
    adox        r14, rcx
    mulx        rcx, rax, [%2 + 40]
    adcx        r14, rax
    adox        r15, rcx
    mov         eax, 0
    adcx        r15, rax                    ; (the rows' sum fits t1..t10: no carry passes t10)
    ; row 2: t5..t8 += a2 a[3..5] (t8 = rbx)
    mov         rdx, [%2 + 16]
    xor         ebx, ebx
    mulx        rcx, rax, [%2 + 24]
    adcx        r13, rax
    adox        r14, rcx
    mulx        rcx, rax, [%2 + 32]
    adcx        r14, rax
    adox        r15, rcx
    mulx        rcx, rax, [%2 + 40]
    adcx        r15, rax
    adox        rbx, rcx
    mov         eax, 0
    adcx        rbx, rax
    ; row 3: t7..t9 += a3 a[4..5] (t9 = rsi)
    mov         rdx, [%2 + 24]
    xor         esi, esi
    mulx        rcx, rax, [%2 + 32]
    adcx        r15, rax
    adox        rbx, rcx
    mulx        rcx, rax, [%2 + 40]
    adcx        rbx, rax
    adox        rsi, rcx
    mov         eax, 0
    adcx        rsi, rax
    ; row 4: t9..t10 += a4 a5 (t10 = rdi)
    mov         rdx, [%2 + 32]
    mulx        rdi, rax, [%2 + 40]
    add         rsi, rax
    adc         rdi, 0
    ; t = 2t + the squares a_i^2 at t[2i], t[2i+1]: CF doubles t1..t10, OF adds the squares
    mov         rdx, [%2]
    mulx        rcx, r8, rdx                ; a0^2: t0, and its high word for t1
    xor         eax, eax                    ; CF = OF = 0
    adcx        r9, r9
    adox        r9, rcx
    mov         rdx, [%2 + 8]
    mulx        rcx, rax, rdx               ; a1^2
    adcx        r10, r10
    adox        r10, rax
    adcx        r11, r11
    adox        r11, rcx
    mov         rdx, [%2 + 16]
    mulx        rcx, rax, rdx               ; a2^2
    adcx        r12, r12
    adox        r12, rax
    adcx        r13, r13
    adox        r13, rcx
    mov         rdx, [%2 + 24]
    mulx        rcx, rax, rdx               ; a3^2
    adcx        r14, r14
    adox        r14, rax
    adcx        r15, r15
    adox        r15, rcx
    mov         rdx, [%2 + 32]
    mulx        rcx, rax, rdx               ; a4^2
    adcx        rbx, rbx
    adox        rbx, rax
    adcx        rsi, rsi
    adox        rsi, rcx
    mov         rdx, [%2 + 40]
    mulx        rcx, rax, rdx               ; a5^2
    adcx        rdi, rdi
    adox        rdi, rax
    mov         eax, 0
    adcx        rcx, rax                    ; t11 (a^2 < 2^768: nothing carries out of it)
    adox        rcx, rax
    ; the high half t6..t11 parked in out (every read of a is done)
    mov         [%1], r14
    mov         [%1 + 8], r15
    mov         [%1 + 16], rbx
    mov         [%1 + 24], rsi
    mov         [%1 + 32], rdi
    mov         [%1 + 40], rcx
    ; the low half r8..r13 reduced: six steps over the turning registers, the limbs above start 0
    xor         r14d, r14d
    xor         r15d, r15d
    F6X_RED     %3, %4, r8, r9, r10, r11, r12, r13, r14, r15
    F6X_RED     %3, %4, r9, r10, r11, r12, r13, r14, r15, r8
    F6X_RED     %3, %4, r10, r11, r12, r13, r14, r15, r8, r9
    F6X_RED     %3, %4, r11, r12, r13, r14, r15, r8, r9, r10
    F6X_RED     %3, %4, r12, r13, r14, r15, r8, r9, r10, r11
    F6X_RED     %3, %4, r13, r14, r15, r8, r9, r10, r11, r12
    ; (low + q M) / R = r14 r15 r8 r9 r10 r11 + r12 2^384, at most M; plus the high half
    add         r14, [%1]
    adc         r15, [%1 + 8]
    adc         r8, [%1 + 16]
    adc         r9, [%1 + 24]
    adc         r10, [%1 + 32]
    adc         r11, [%1 + 40]
    adc         r12, 0
    F6_FINAL    %1, r14, r15, r8, r9, r10, r11, r12
  %undef F6_M_
%endmacro

; =============================================================================
; v1: mul (any x86-64).
; =============================================================================

; -----------------------------------------------------------------------------
; F6Q_MAC a, bi, t0, t1, t2, t3, t4, t5, t6, t7: t0..t6 += a bi (six mul, one carry chain through
; the high words in rdi); t7 = the carry word out (0 or 1). bi is a memory operand. Clobbers rax,
; rcx, rdx, rdi, the flags.
; -----------------------------------------------------------------------------
; F6Q_MACLIMB a, offset, t: t += a[offset] rcx + rdi (the carry in), rdi = the carry out (the
; product's high word plus both adds' carries: below 2^64). Clobbers rax, rdx, the flags.
%macro F6Q_MACLIMB 3
    mov         rax, [%1 + %2]
    mul         rcx
    add         rax, rdi
    adc         rdx, 0
    add         %3, rax
    adc         rdx, 0
    mov         rdi, rdx
%endmacro

%macro F6Q_MAC 10
    mov         rcx, %2
    mov         rax, [%1]
    mul         rcx                         ; a0 bi
    add         %3, rax
    adc         rdx, 0
    mov         rdi, rdx                    ; carried into the next limb
    F6Q_MACLIMB %1, 8, %4
    F6Q_MACLIMB %1, 16, %5
    F6Q_MACLIMB %1, 24, %6
    F6Q_MACLIMB %1, 32, %7
    F6Q_MACLIMB %1, 40, %8
    xor         %10, %10                    ; t7 = 0 (no chain is open across it)
    add         %9, rdi
    adc         %10, 0
%endmacro

; -----------------------------------------------------------------------------
; F6Q_RED m, n0, t0, t1, t2, t3, t4, t5, t6, t7: F6X_RED's step with mul: t += q M with q = t0 n0
; (t0 then 0, dropped by the caller's renaming); the carry out of t6 added into t7. Clobbers rax,
; rcx, rdx, rdi, the flags.
; -----------------------------------------------------------------------------
%macro F6Q_RED 10
    mov         rcx, %3
    imul        rcx, %2                     ; q
    mov         rax, [%1]
    mul         rcx                         ; q m0: t0 + its low half is 0
    add         %3, rax
    adc         rdx, 0
    mov         rdi, rdx
    F6Q_MACLIMB %1, 8, %4
    F6Q_MACLIMB %1, 16, %5
    F6Q_MACLIMB %1, 24, %6
    F6Q_MACLIMB %1, 32, %7
    F6Q_MACLIMB %1, 40, %8
    add         %9, rdi
    adc         %10, 0
%endmacro

; -----------------------------------------------------------------------------
; F6Q_MUL out, a, b, m, n0: out = a b R^-1 mod M, F6X_MUL's rounds with mul (a, b below M; out
; may be a or b). Clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro F6Q_MUL 5
  %define F6_M_ %4
    mov         rcx, [%3]                   ; round 0: t = a b0
    mov         rax, [%2]
    mul         rcx
    mov         r8, rax
    mov         r9, rdx
    mov         rax, [%2 + 8]
    mul         rcx
    add         r9, rax
    adc         rdx, 0
    mov         r10, rdx
    mov         rax, [%2 + 16]
    mul         rcx
    add         r10, rax
    adc         rdx, 0
    mov         r11, rdx
    mov         rax, [%2 + 24]
    mul         rcx
    add         r11, rax
    adc         rdx, 0
    mov         r12, rdx
    mov         rax, [%2 + 32]
    mul         rcx
    add         r12, rax
    adc         rdx, 0
    mov         r13, rdx
    mov         rax, [%2 + 40]
    mul         rcx
    add         r13, rax
    adc         rdx, 0
    mov         r14, rdx
    xor         r15d, r15d                  ; t7, the carry word
    F6Q_RED     %4, %5, r8, r9, r10, r11, r12, r13, r14, r15
    F6Q_MAC     %2, [%3 + 8], r9, r10, r11, r12, r13, r14, r15, r8
    F6Q_RED     %4, %5, r9, r10, r11, r12, r13, r14, r15, r8
    F6Q_MAC     %2, [%3 + 16], r10, r11, r12, r13, r14, r15, r8, r9
    F6Q_RED     %4, %5, r10, r11, r12, r13, r14, r15, r8, r9
    F6Q_MAC     %2, [%3 + 24], r11, r12, r13, r14, r15, r8, r9, r10
    F6Q_RED     %4, %5, r11, r12, r13, r14, r15, r8, r9, r10
    F6Q_MAC     %2, [%3 + 32], r12, r13, r14, r15, r8, r9, r10, r11
    F6Q_RED     %4, %5, r12, r13, r14, r15, r8, r9, r10, r11
    F6Q_MAC     %2, [%3 + 40], r13, r14, r15, r8, r9, r10, r11, r12
    F6Q_RED     %4, %5, r13, r14, r15, r8, r9, r10, r11, r12
    F6_FINAL    %1, r14, r15, r8, r9, r10, r11, r12
  %undef F6_M_
%endmacro

; F6Q_SQR out, a, m, n0: out = a^2 R^-1 mod M with mul (a below M; out may be a).
%macro F6Q_SQR 4
    F6Q_MUL     %1, %2, %2, %3, %4
%endmacro

; =============================================================================
; The point routines' names: the field's operations under each prefix (FIELD p), the scalars'
; (modulo n) through v1's product: a signature takes a handful.
; =============================================================================
%macro F6X_FMUL 3
    F6X_MUL     %1, %2, %3, rel p384_p, [rel p384_p0]
%endmacro
%macro F6Q_FMUL 3
    F6Q_MUL     %1, %2, %3, rel p384_p, [rel p384_p0]
%endmacro
%macro F6X_FSQR 2
    F6X_SQR     %1, %2, rel p384_p, [rel p384_p0]
%endmacro
%macro F6Q_FSQR 2
    F6Q_MUL     %1, %2, %2, rel p384_p, [rel p384_p0]
%endmacro
%macro F6X_FADD 3
    F6_ADD      %1, %2, %3, rel p384_p
%endmacro
%macro F6Q_FADD 3
    F6_ADD      %1, %2, %3, rel p384_p
%endmacro
%macro F6X_FSUB 3
    F6_SUB      %1, %2, %3, rel p384_p
%endmacro
%macro F6Q_FSUB 3
    F6_SUB      %1, %2, %3, rel p384_p
%endmacro
%macro F6X_FHALF 2
    F6_HALF     %1, %2, rel p384_p
%endmacro
%macro F6Q_FHALF 2
    F6_HALF     %1, %2, rel p384_p
%endmacro
%macro F6_NMUL 3                            ; modulo n, v1 everywhere (any CPU)
    F6Q_MUL     %1, %2, %3, rel p384_n, [rel p384_n0]
%endmacro
%macro F6_NADD 3
    F6_ADD      %1, %2, %3, rel p384_n
%endmacro

%endif
