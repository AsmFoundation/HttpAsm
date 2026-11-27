; =============================================================================
; include/crypto/p256.inc - arithmetic in GF(p), p = 2^256 - 2^224 + 2^192 + 2^96 - 1, the
; field of the NIST curve P-256 (SP 800-186 3.2.1.3, the curve TLS calls secp256r1), and
; modulo its group order n (ECDSA's scalars), for crypto/p256.asm.
;
; Elements are in Montgomery form: a stands as a R mod p, R = 2^256, in four 64-bit limbs,
; little-endian, FULLY reduced (below p) between operations; every macro takes and leaves
; reduced values (32 octets in memory: operands are addresses, normally frame slots off rbp).
; A product of two such values is a b R^-1 mod p, which is again the Montgomery form of the
; product, so a whole scalar multiplication runs without leaving the form. Full reduction is
; what lets the caller compare values limb by limb (the curve equation, verification's
; x-coordinate, the point at infinity's Z = 0).
;
; Montgomery's reduction is cheap for this p (Gueron and Krasnov, "Fast prime field
; elliptic-curve cryptography with 256-bit primes", OpenSSL's ecp_nistz256): p's low limb is all
; ones, so -p^-1 = 1 modulo 2^64 and the quotient of a reduction step is the low limb itself,
; m = t0; and m p needs one multiplication only:
;   t + m p = (t0 - m) + (t1 + (m << 32)) 2^64 + (t2 + (m >> 32)) 2^128 + (t3 + m p3) 2^192
; where p3 = 2^64 - 2^32 + 1 is p's top limb (m p = m 2^256 - m 2^224 + m 2^192 + m 2^96 - m,
; and t0 - m = 0 drops off the bottom).
;
; Two versions of the products, the rest shared:
;   FPX_* (v3: BMI2 and ADX): mulx with two carry chains, adcx on CF and adox on OF (OpenSSL's
;         "montx" arrangement);
;   FPQ_* (v1: any x86-64): mul, one carry chain (OpenSSL's "montq").
; Every version's macro has the same name after its prefix (FPX_MUL / FPQ_MUL, and FPX_ADD /
; FPQ_ADD as the shared FP_ADD), so the point routines of crypto/p256.asm take the prefix as a
; parameter and are written once.
;
; What the measurements decided (2026-11-27, i9-13900K P-core; crypto/p256.asm's header has the
; whole account): every carry instruction (adc, adcx, adox, sbb), every cmov and every shift runs
; on ports 0 and 6 only, and a product holds about 69 of them: llvm-mca's Alder Lake model puts
; those two ports at 94% busy, and products run about 37 cycles apart where the multiplier would
; allow 20. So v3's reduction takes m << 32 and m >> 32 from one mulx by 2^32 (the multiplier's
; ports 1 and 5) instead of two shifts: doubling 378 to 356 cycles, product throughput 37.7 to
; 36.0. The final subtraction stays a cmov selection: masks instead (xor, and, xor: any port)
; were measured 14 cycles slower in a product's latency.
;
; Constant time: no branch and no address depends on an operand; the final subtractions are
; cmov or masks. The macros clobber the flags and the registers each lists, never rbp or rsp
; (operands are addressed off them).
; =============================================================================
%ifndef HTTPASM_P256_INC
%define HTTPASM_P256_INC

; p's limbs that are not 0 or all ones, as immediates (64-bit immediates go through a register).
%define FP_P1 0x00000000FFFFFFFF            ; p's limb 1 (limb 0 is 2^64 - 1, limb 2 is 0)
%define FP_P3 0xFFFFFFFF00000001            ; p's limb 3

; -----------------------------------------------------------------------------
; FP_STORE out: the four limbs r8, r9, r10, r11 to out. No flags.
; -----------------------------------------------------------------------------
%macro FP_STORE 1
    mov         [%1], r8
    mov         [%1 + 8], r9
    mov         [%1 + 16], r10
    mov         [%1 + 24], r11
%endmacro

; -----------------------------------------------------------------------------
; FP_SUBP: the final reduction of every product and sum. In: r12:r11:r10:r9:r8, a value below
; 2p (r12, the carry word, 0 or 1). Out: r8..r11 = the value modulo p, below p: p subtracted when
; that does not borrow, selected by cmov (no branch on the value; cmov's timing does not depend
; on its condition). cmov, not masks: the masked selection (sbb into a mask, then xor, and, xor
; per limb, off ports 0 and 6) measured 14 cycles longer in a product's latency. Clobbers rax,
; rbx, rcx, rdx, rsi, r12 and the flags.
; -----------------------------------------------------------------------------
%macro FP_SUBP 0
    mov         rax, r8
    mov         rbx, r9
    mov         rcx, r10
    mov         rdx, r11
    sub         rax, -1                     ; limb 0 of p: 2^64 - 1
    mov         rsi, FP_P1
    sbb         rbx, rsi
    sbb         rcx, 0                      ; limb 2 of p: 0
    mov         rsi, FP_P3
    sbb         rdx, rsi
    sbb         r12, 0                      ; borrow out of the carry word: the value was below p
    cmovnc      r8, rax
    cmovnc      r9, rbx
    cmovnc      r10, rcx
    cmovnc      r11, rdx
%endmacro

; -----------------------------------------------------------------------------
; FP_ADD out, a, b: out = a + b mod p. The 257-bit sum, then FP_SUBP (a + b < 2p). out may be a
; or b. Clobbers rax, rbx, rcx, rdx, rsi, r8-r12, the flags.
; -----------------------------------------------------------------------------
%macro FP_ADD 3
    xor         r12d, r12d
    mov         r8, [%2]
    mov         r9, [%2 + 8]
    mov         r10, [%2 + 16]
    mov         r11, [%2 + 24]
    add         r8, [%3]
    adc         r9, [%3 + 8]
    adc         r10, [%3 + 16]
    adc         r11, [%3 + 24]
    adc         r12, 0
    FP_SUBP
    FP_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; FP_SUB out, a, b: out = a - b mod p. The difference, then p added back when it borrowed (p
; masked by the borrow: no branch). out may be a or b. Clobbers rax, rbx, rdx, rsi, r8-r11, the
; flags.
; -----------------------------------------------------------------------------
%macro FP_SUB 3
    mov         r8, [%2]
    mov         r9, [%2 + 8]
    mov         r10, [%2 + 16]
    mov         r11, [%2 + 24]
    sub         r8, [%3]
    sbb         r9, [%3 + 8]
    sbb         r10, [%3 + 16]
    sbb         r11, [%3 + 24]
    sbb         rsi, rsi                    ; all ones when it borrowed, else 0
    mov         rax, rsi                    ; p's limb 0, masked
    mov         ebx, 0xFFFFFFFF
    and         rbx, rsi                    ; limb 1, masked
    mov         rdx, FP_P3
    and         rdx, rsi                    ; limb 3, masked
    add         r8, rax
    adc         r9, rbx
    adc         r10, 0                      ; limb 2 is 0
    adc         r11, rdx
    FP_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; FP_CNEG mask, a: a = -a mod p where the 64-bit register mask is all ones, a unchanged where it
; is 0 (Booth's negative digits, crypto/p256.asm). 0 - a, with p added back when that borrows
; (so -0 is 0, not p: a table scan's "no point", (0, 0), stays (0, 0) whatever the digit's sign,
; and the mixed addition still sees it as the point at infinity), then each limb chosen by the
; mask: no branch. Clobbers rax, rbx, rcx, rdx, rsi, r8-r11, the flags; keeps the mask register
; (it must not be one of those).
; -----------------------------------------------------------------------------
%macro FP_CNEG 2
    xor         r8d, r8d
    xor         r9d, r9d
    xor         r10d, r10d
    xor         r11d, r11d
    sub         r8, [%2]
    sbb         r9, [%2 + 8]
    sbb         r10, [%2 + 16]
    sbb         r11, [%2 + 24]
    sbb         rsi, rsi                    ; all ones unless a = 0
    mov         rax, rsi                    ; p's limb 0, masked
    mov         ebx, 0xFFFFFFFF
    and         rbx, rsi                    ; limb 1, masked
    mov         rdx, FP_P3
    and         rdx, rsi                    ; limb 3, masked
    add         r8, rax
    adc         r9, rbx
    adc         r10, 0                      ; limb 2 is 0
    adc         r11, rdx                    ; -a mod p, below p
    ; each limb = a ^ ((a ^ -a) & mask)
    mov         rcx, [%2]
    xor         r8, rcx
    and         r8, %1
    xor         r8, rcx
    mov         rcx, [%2 + 8]
    xor         r9, rcx
    and         r9, %1
    xor         r9, rcx
    mov         rcx, [%2 + 16]
    xor         r10, rcx
    and         r10, %1
    xor         r10, rcx
    mov         rcx, [%2 + 24]
    xor         r11, rcx
    and         r11, %1
    xor         r11, rcx
    FP_STORE    %2
%endmacro

; =============================================================================
; v3: mulx, adcx, adox (BMI2 and ADX).
; =============================================================================

; -----------------------------------------------------------------------------
; FPX_REDUCE t0, t1, t2, t3, t4, t5: one Montgomery step of a product in progress: t += m p with
; m = t0 (t0 then holds 0, and the caller drops it by renaming the registers down one limb); t5
; receives the carry out of t4 (added to it: the caller zeroes or carries it). r13 must hold p3
; and r14 2^32: m << 32 and m >> 32 are the two halves of m 2^32, one mulx on the multiplier's
; ports where two shifts would take ports 0 and 6 from the carries (measured: the header).
; Clobbers rax, rcx, rdx, the flags.
; -----------------------------------------------------------------------------
%macro FPX_REDUCE 6
    mov         rdx, %1
    mulx        rcx, rax, r14               ; m 2^32: rax = m << 32, rcx = m >> 32 (the multiplier's
    add         %2, rax                     ; ports, not the shifts' 0 and 6, which the carries need)
    adc         %3, rcx
    mulx        rcx, rax, r13               ; m p3 (mulx leaves the flags as they are)
    adc         %4, rax
    adc         %5, rcx
    adc         %6, 0
%endmacro

; -----------------------------------------------------------------------------
; FPX_MAC a, bi, t0, t1, t2, t3, t4, t5: t0..t4 += a bi, the four products a_j bi in two carry
; chains (low halves on CF, high halves on OF); t5 = the carry word out (CF + OF, at most 1 since
; the running value stays below 2^321). bi is a memory operand. Clobbers rax, rcx, rdx, the flags.
; -----------------------------------------------------------------------------
%macro FPX_MAC 8
    mov         rdx, %2
    xor         %8, %8                      ; t5 = 0, and CF = OF = 0 for the chains
    mulx        rcx, rax, [%1]              ; a0 bi
    adcx        %3, rax
    adox        %4, rcx
    mulx        rcx, rax, [%1 + 8]          ; a1 bi
    adcx        %4, rax
    adox        %5, rcx
    mulx        rcx, rax, [%1 + 16]         ; a2 bi
    adcx        %5, rax
    adox        %6, rcx
    mulx        rcx, rax, [%1 + 24]         ; a3 bi
    adcx        %6, rax
    adox        %7, rcx                     ; OF: the high chain's carry out of t4
    mov         eax, 0                      ; a zero that keeps the flags (mov, not xor)
    adcx        %7, rax                     ; CF: the low chain's carry out of t4
    adcx        %8, rax                     ; t5 = CF
    adox        %8, rax                     ; t5 += OF
%endmacro

; -----------------------------------------------------------------------------
; FPX_MUL out, a, b: out = a b R^-1 mod p (a, b below p; out may be a or b: both are read before
; out is written). Four rounds of t += a b_i and one reduction step each (the running t stays
; below 2p in five limbs that turn through r8, r9, r10, r11, rbx, r12), then FP_SUBP.
; Clobbers rax, rbx, rcx, rdx, rsi, r8-r14, the flags.
; -----------------------------------------------------------------------------
%macro FPX_MUL 3
    mov         r13, FP_P3
    mov         r14, 1 << 32
    ; round 0: t = a b0, then its reduction
    mov         rdx, [%3]
    mulx        r9, r8, [%2]                ; a0 b0
    mulx        r10, rax, [%2 + 8]          ; a1 b0
    xor         r12d, r12d                  ; CF = 0; r12 = 0 (the carry word to come)
    adcx        r9, rax
    mulx        r11, rax, [%2 + 16]         ; a2 b0
    adcx        r10, rax
    mulx        rbx, rax, [%2 + 24]         ; a3 b0: rbx = t4
    adcx        r11, rax
    adcx        rbx, r12
    FPX_REDUCE  r8, r9, r10, r11, rbx, r12
    ; t = r9 r10 r11 rbx r12 (r8 is 0 and becomes the next carry word)
    FPX_MAC     %2, [%3 + 8], r9, r10, r11, rbx, r12, r8
    FPX_REDUCE  r9, r10, r11, rbx, r12, r8
    ; t = r10 r11 rbx r12 r8
    FPX_MAC     %2, [%3 + 16], r10, r11, rbx, r12, r8, r9
    FPX_REDUCE  r10, r11, rbx, r12, r8, r9
    ; t = r11 rbx r12 r8 r9
    FPX_MAC     %2, [%3 + 24], r11, rbx, r12, r8, r9, r10
    FPX_REDUCE  r11, rbx, r12, r8, r9, r10
    ; t = rbx r12 r8 r9 r10, below 2p: into r8..r11 and the carry word r12 for FP_SUBP
    mov         r11, r9
    mov         r9, r12
    mov         r12, r10
    mov         r10, r8
    mov         r8, rbx
    FP_SUBP
    FP_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; FPX_SQR_STEP w0, w1, w2, w3: one reduction step over a square's low half held in a turning
; window of four registers: m = w0; w1 += m << 32, w2 += m >> 32, w3 += low(m p3) with carries;
; then w0 = high(m p3) + the carry, the window's new top limb (the window turns: w1 w2 w3 w0).
; No carry is lost: high(m p3) is below 2^64 - 2^32 + 1. rdi must hold p3 and rsi 2^32 (the
; shifts as one mulx, as FPX_REDUCE's; r12-r15 hold the square's high half meanwhile). Clobbers
; rax, rcx, rdx, the flags.
; -----------------------------------------------------------------------------
%macro FPX_SQR_STEP 4
    mov         rdx, %1
    mulx        rcx, rax, rsi               ; m 2^32: m << 32 and m >> 32
    add         %2, rax
    adc         %3, rcx
    mulx        rcx, rax, rdi               ; m p3 (mulx leaves the flags)
    adc         %4, rax
    adc         rcx, 0
    mov         %1, rcx
%endmacro

; -----------------------------------------------------------------------------
; FPX_SQR out, a: out = a^2 R^-1 mod p (a below p; out may be a). The 512-bit square (the six
; cross products once, doubled on CF while the four squares join on OF), then four reduction
; steps over the low half (FPX_SQR_STEP; the half after them is at most p), plus the high half
; (below p, as a^2 < p^2), then FP_SUBP. Clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro FPX_SQR 2
    mov         rdx, [%2]                   ; a0
    mov         rcx, [%2 + 8]               ; a1
    mov         rsi, [%2 + 24]              ; a3
    mulx        r15, r8, rdx                ; a0 a0 (its high word waits in r15)
    mulx        rax, r9, rcx                ; a0 a1
    xor         edi, edi                    ; rdi = 0; CF = OF = 0
    mulx        rbx, r10, [%2 + 16]         ; a0 a2
    adcx        r10, rax
    mulx        r12, r11, rsi               ; a0 a3
    adcx        r11, rbx
    mov         rdx, rcx                    ; a1
    adcx        r12, rdi
    mulx        rbx, rax, [%2 + 16]         ; a1 a2
    adox        r11, rax
    adcx        r12, rbx
    mulx        r13, rax, rsi               ; a1 a3
    adox        r12, rax
    mov         rdx, [%2 + 16]              ; a2
    adcx        r13, rdi
    mulx        r14, rax, rsi               ; a2 a3
    mov         rdx, rcx                    ; a1
    adox        r13, rax
    adcx        r14, rdi
    adox        r14, rdi
    ; the cross products doubled (CF) while the squares are added (OF)
    adcx        r9, r9
    adox        r9, r15
    adcx        r10, r10
    mulx        rbx, rax, rdx               ; a1 a1
    mov         rdx, [%2 + 16]              ; a2
    adcx        r11, r11
    adox        r10, rax
    adcx        r12, r12
    adox        r11, rbx
    mulx        rbx, rax, rdx               ; a2 a2
    mov         rdx, rsi                    ; a3
    adcx        r13, r13
    adox        r12, rax
    adcx        r14, r14
    adox        r13, rbx
    mulx        r15, rax, rdx               ; a3 a3
    adox        r14, rax
    adcx        r15, rdi
    adox        r15, rdi
    ; the low half r8..r11 reduced (the window turns back to r8..r11), plus the high half
    ; r12..r15; the carry word into r12 for FP_SUBP
    mov         rdi, FP_P3
    mov         rsi, 1 << 32
    FPX_SQR_STEP r8, r9, r10, r11
    FPX_SQR_STEP r9, r10, r11, r8
    FPX_SQR_STEP r10, r11, r8, r9
    FPX_SQR_STEP r11, r8, r9, r10
    add         r8, r12
    adc         r9, r13
    adc         r10, r14
    adc         r11, r15
    mov         r12d, 0                     ; (mov keeps CF for the next adc)
    adc         r12, 0
    FP_SUBP
    FP_STORE    %1
%endmacro

; =============================================================================
; v1: mul (any x86-64).
; =============================================================================

; -----------------------------------------------------------------------------
; FPQ_REDUCE t0, t1, t2, t3, t4, t5: FPX_REDUCE's step with mul for m p3: t += m p with m = t0
; (t0 then 0, dropped by the caller's renaming); t5 receives the carry out of t4 (added). r13 must
; hold p3. Clobbers rax, rcx, rdx, rsi, the flags.
; -----------------------------------------------------------------------------
%macro FPQ_REDUCE 6
    mov         rax, %1
    mul         r13                         ; rdx:rax = m p3
    mov         rsi, %1
    shl         rsi, 32                     ; m << 32, into limb 1
    mov         rcx, %1
    shr         rcx, 32                     ; m >> 32, into limb 2
    add         %2, rsi
    adc         %3, rcx
    adc         %4, rax
    adc         %5, rdx
    adc         %6, 0
%endmacro

; -----------------------------------------------------------------------------
; FPQ_MAC a, bi, t0, t1, t2, t3, t4, t5: t0..t4 += a bi (four mul, one carry chain through the
; high words); t5 = the carry word out (0 or 1). bi is a memory operand. Clobbers rax, rcx, rdx,
; rdi, the flags.
; -----------------------------------------------------------------------------
%macro FPQ_MAC 8
    mov         rcx, %2
    mov         rax, [%1]
    mul         rcx                         ; a0 bi
    add         %3, rax
    adc         rdx, 0
    mov         rdi, rdx                    ; carried into the next limb
    mov         rax, [%1 + 8]
    mul         rcx                         ; a1 bi
    add         rax, rdi
    adc         rdx, 0
    add         %4, rax
    adc         rdx, 0
    mov         rdi, rdx
    mov         rax, [%1 + 16]
    mul         rcx                         ; a2 bi
    add         rax, rdi
    adc         rdx, 0
    add         %5, rax
    adc         rdx, 0
    mov         rdi, rdx
    mov         rax, [%1 + 24]
    mul         rcx                         ; a3 bi
    add         rax, rdi
    adc         rdx, 0
    add         %6, rax
    adc         rdx, 0
    xor         %8, %8                      ; t5 = 0 (no chain is open across it)
    add         %7, rdx
    adc         %8, 0
%endmacro

; -----------------------------------------------------------------------------
; FPQ_MUL out, a, b: out = a b R^-1 mod p, FPX_MUL's rounds with mul (a, b below p; out may be a
; or b). Clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r13, the flags.
; -----------------------------------------------------------------------------
%macro FPQ_MUL 3
    mov         r13, FP_P3
    ; round 0: t = a b0, then its reduction
    mov         rcx, [%3]
    mov         rax, [%2]
    mul         rcx                         ; a0 b0
    mov         r8, rax
    mov         r9, rdx
    mov         rax, [%2 + 8]
    mul         rcx                         ; a1 b0
    add         r9, rax
    adc         rdx, 0
    mov         r10, rdx
    mov         rax, [%2 + 16]
    mul         rcx                         ; a2 b0
    add         r10, rax
    adc         rdx, 0
    mov         r11, rdx
    mov         rax, [%2 + 24]
    mul         rcx                         ; a3 b0
    add         r11, rax
    adc         rdx, 0
    mov         rbx, rdx                    ; t4
    xor         r12d, r12d                  ; the carry word to come
    FPQ_REDUCE  r8, r9, r10, r11, rbx, r12
    ; t = r9 r10 r11 rbx r12 (r8 is 0 and becomes the next carry word)
    FPQ_MAC     %2, [%3 + 8], r9, r10, r11, rbx, r12, r8
    FPQ_REDUCE  r9, r10, r11, rbx, r12, r8
    ; t = r10 r11 rbx r12 r8
    FPQ_MAC     %2, [%3 + 16], r10, r11, rbx, r12, r8, r9
    FPQ_REDUCE  r10, r11, rbx, r12, r8, r9
    ; t = r11 rbx r12 r8 r9
    FPQ_MAC     %2, [%3 + 24], r11, rbx, r12, r8, r9, r10
    FPQ_REDUCE  r11, rbx, r12, r8, r9, r10
    ; t = rbx r12 r8 r9 r10, below 2p: into r8..r11 and the carry word r12 for FP_SUBP
    mov         r11, r9
    mov         r9, r12
    mov         r12, r10
    mov         r10, r8
    mov         r8, rbx
    FP_SUBP
    FP_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; FPQ_SQR_STEP w0, w1, w2, w3: FPX_SQR_STEP with mul: m = w0; w1 += m << 32, w2 += m >> 32,
; w3 += low(m p3); w0 = high(m p3) + the carry. rdi must hold p3. Clobbers rax, rbx, rcx, rdx,
; the flags.
; -----------------------------------------------------------------------------
%macro FPQ_SQR_STEP 4
    mov         rax, %1
    mul         rdi                         ; rdx:rax = m p3
    mov         rbx, %1
    shl         rbx, 32
    mov         rcx, %1
    shr         rcx, 32
    add         %2, rbx
    adc         %3, rcx
    adc         %4, rax
    adc         rdx, 0
    mov         %1, rdx
%endmacro

; -----------------------------------------------------------------------------
; FPQ_SQR out, a: out = a^2 R^-1 mod p with mul: the six cross products once, doubled, the four
; squares added, then FPX_SQR's reduction (a below p; out may be a). Clobbers rax, rbx, rcx, rdx,
; rsi, rdi, r8-r15, the flags.
; -----------------------------------------------------------------------------
%macro FPQ_SQR 2
    mov         rsi, [%2]                   ; a0
    mov         rax, [%2 + 8]
    mul         rsi                         ; a0 a1
    mov         r9, rax
    mov         r10, rdx
    mov         rax, [%2 + 16]
    mul         rsi                         ; a0 a2
    add         r10, rax
    adc         rdx, 0
    mov         r11, rdx
    mov         rax, [%2 + 24]
    mul         rsi                         ; a0 a3
    add         r11, rax
    adc         rdx, 0
    mov         r12, rdx
    mov         rsi, [%2 + 8]               ; a1
    mov         rax, [%2 + 16]
    mul         rsi                         ; a1 a2
    add         r11, rax
    adc         rdx, 0
    mov         rbx, rdx
    mov         rax, [%2 + 24]
    mul         rsi                         ; a1 a3
    add         rax, rbx
    adc         rdx, 0
    add         r12, rax
    adc         rdx, 0
    mov         r13, rdx
    mov         rax, [%2 + 24]
    mul         qword [%2 + 16]             ; a2 a3
    add         r13, rax
    adc         rdx, 0
    mov         r14, rdx
    ; the cross products doubled: r9..r14 shifted up one bit, the bit out into r15
    xor         r15d, r15d
    add         r9, r9
    adc         r10, r10
    adc         r11, r11
    adc         r12, r12
    adc         r13, r13
    adc         r14, r14
    adc         r15, 0
    ; plus the squares a_i^2 at limbs 2i and 2i + 1
    mov         rax, [%2]
    mul         rax                         ; a0 a0
    mov         r8, rax
    mov         rbx, rdx
    mov         rax, [%2 + 8]
    mul         rax                         ; a1 a1
    add         r9, rbx
    adc         r10, rax
    adc         rdx, 0
    mov         rbx, rdx
    mov         rax, [%2 + 16]
    mul         rax                         ; a2 a2
    add         r11, rbx
    adc         r12, rax
    adc         rdx, 0
    mov         rbx, rdx
    mov         rax, [%2 + 24]
    mul         rax                         ; a3 a3
    add         r13, rbx
    adc         r14, rax
    adc         r15, rdx                    ; no carry out: a^2 < 2^512
    ; the low half reduced, plus the high half, then FP_SUBP
    mov         rdi, FP_P3
    FPQ_SQR_STEP r8, r9, r10, r11
    FPQ_SQR_STEP r9, r10, r11, r8
    FPQ_SQR_STEP r10, r11, r8, r9
    FPQ_SQR_STEP r11, r8, r9, r10
    add         r8, r12
    adc         r9, r13
    adc         r10, r14
    adc         r11, r15
    mov         r12d, 0
    adc         r12, 0
    FP_SUBP
    FP_STORE    %1
%endmacro

; -----------------------------------------------------------------------------
; FP_HALF out, a: out = a / 2 mod p: (a + p) / 2 when a is odd, else a / 2 (p added under a mask:
; no branch), the 257-bit sum shifted down one bit (shrd: port 1, not the carries' 0 and 6). The
; point doubling's 8 Y^4 comes from (16 Y^4) / 2, one of these where 8 gamma^2 took three
; additions. out may be a. Clobbers rax, rbx, rdx, rsi, r8-r12, the flags.
; -----------------------------------------------------------------------------
%macro FP_HALF 2
    mov         r8, [%2]
    mov         r9, [%2 + 8]
    mov         r10, [%2 + 16]
    mov         r11, [%2 + 24]
    mov         esi, 1
    and         rsi, r8
    neg         rsi                         ; all ones when a is odd
    mov         ebx, 0xFFFFFFFF
    and         rbx, rsi                    ; p's limb 1, masked
    mov         rdx, FP_P3
    and         rdx, rsi                    ; limb 3, masked
    xor         r12d, r12d
    add         r8, rsi                     ; limb 0 (all ones), masked
    adc         r9, rbx
    adc         r10, 0
    adc         r11, rdx
    adc         r12, 0
    shrd        r8, r9, 1
    shrd        r9, r10, 1
    shrd        r10, r11, 1
    shrd        r11, r12, 1
    FP_STORE    %1
%endmacro

; =============================================================================
; Arithmetic modulo n, the group order (ECDSA's scalars), shared by every version: a signature
; or a verification takes a handful of these products (the inversions go through p256_inverse),
; so one plain version with mul serves. Montgomery form with R = 2^256 again; n has no special
; shape, so a reduction step's quotient is m = t0 n' (n' = -n^-1 mod 2^64, p256_n0) and m n takes
; four products.
; =============================================================================

; FN_ROW x, y, t0, t1, t2, t3, t4, t5: t0..t4 += x y (x four limbs in memory, y a register or
; memory qword other than rcx), the carry out of t4 ADDED to t5. Clobbers rax, rcx, rdx, rdi,
; the flags.
%macro FN_ROW 8
    mov         rcx, %2
    mov         rax, [%1]
    mul         rcx
    add         %3, rax
    adc         rdx, 0
    mov         rdi, rdx
    mov         rax, [%1 + 8]
    mul         rcx
    add         rax, rdi
    adc         rdx, 0
    add         %4, rax
    adc         rdx, 0
    mov         rdi, rdx
    mov         rax, [%1 + 16]
    mul         rcx
    add         rax, rdi
    adc         rdx, 0
    add         %5, rax
    adc         rdx, 0
    mov         rdi, rdx
    mov         rax, [%1 + 24]
    mul         rcx
    add         rax, rdi
    adc         rdx, 0
    add         %6, rax
    adc         rdx, 0
    add         %7, rdx
    adc         %8, 0
%endmacro

; FN_ROUND a, bi, t0, t1, t2, t3, t4, t5: one Montgomery round modulo n: t += a bi, then t += m n
; with m = t0 n' (t0 becomes 0; the caller renames the registers down a limb). t5 must hold 0.
; Clobbers rax, rcx, rdx, rsi, rdi, the flags.
%macro FN_ROUND 8
    FN_ROW      %1, %2, %3, %4, %5, %6, %7, %8
    mov         rsi, %3
    imul        rsi, [rel p256_n0]          ; m = t0 n' mod 2^64
    FN_ROW      rel p256_n, rsi, %3, %4, %5, %6, %7, %8
%endmacro

; FN_SUBN: r8..r11 (and the carry word r12, 0 or 1), a value below 2n, minus n when that does not
; borrow (cmov). Clobbers rax, rbx, rcx, rdx, r12, the flags.
%macro FN_SUBN 0
    mov         rax, r8
    mov         rbx, r9
    mov         rcx, r10
    mov         rdx, r11
    sub         rax, [rel p256_n]
    sbb         rbx, [rel p256_n + 8]
    sbb         rcx, [rel p256_n + 16]
    sbb         rdx, [rel p256_n + 24]
    sbb         r12, 0
    cmovnc      r8, rax
    cmovnc      r9, rbx
    cmovnc      r10, rcx
    cmovnc      r11, rdx
%endmacro

; FN_MUL out, a, b: out = a b R^-1 mod n (a, b below n; out may be a or b). Clobbers rax, rbx,
; rcx, rdx, rsi, rdi, r8-r13, the flags.
%macro FN_MUL 3
    xor         r8d, r8d
    xor         r9d, r9d
    xor         r10d, r10d
    xor         r11d, r11d
    xor         ebx, ebx
    xor         r12d, r12d
    FN_ROUND    %2, [%3], r8, r9, r10, r11, rbx, r12
    xor         r8d, r8d                    ; t = r9 r10 r11 rbx r12; r8 the next carry word
    FN_ROUND    %2, [%3 + 8], r9, r10, r11, rbx, r12, r8
    xor         r9d, r9d
    FN_ROUND    %2, [%3 + 16], r10, r11, rbx, r12, r8, r9
    xor         r10d, r10d
    FN_ROUND    %2, [%3 + 24], r11, rbx, r12, r8, r9, r10
    ; t = rbx r12 r8 r9 r10, below 2n
    mov         r11, r9
    mov         r9, r12
    mov         r12, r10
    mov         r10, r8
    mov         r8, rbx
    FN_SUBN
    FP_STORE    %1
%endmacro

; FN_ADD out, a, b: out = a + b mod n (a, b below n). Clobbers rax, rbx, rcx, rdx, r8-r12, the
; flags.
%macro FN_ADD 3
    xor         r12d, r12d
    mov         r8, [%2]
    mov         r9, [%2 + 8]
    mov         r10, [%2 + 16]
    mov         r11, [%2 + 24]
    add         r8, [%3]
    adc         r9, [%3 + 8]
    adc         r10, [%3 + 16]
    adc         r11, [%3 + 24]
    adc         r12, 0
    FN_SUBN
    FP_STORE    %1
%endmacro

; FN_REDUCE a: a = a mod n for any a below 2^256 (below 2n: one subtraction). Clobbers rax, rbx,
; rcx, rdx, r8-r12, the flags.
%macro FN_REDUCE 1
    xor         r12d, r12d
    mov         r8, [%1]
    mov         r9, [%1 + 8]
    mov         r10, [%1 + 16]
    mov         r11, [%1 + 24]
    FN_SUBN
    FP_STORE    %1
%endmacro

; The shared macros under each version's prefix, so a point routine takes the prefix alone.
%macro FPX_ADD 3
    FP_ADD      %1, %2, %3
%endmacro
%macro FPX_SUB 3
    FP_SUB      %1, %2, %3
%endmacro
%macro FPQ_ADD 3
    FP_ADD      %1, %2, %3
%endmacro
%macro FPQ_SUB 3
    FP_SUB      %1, %2, %3
%endmacro
%macro FPX_HALF 2
    FP_HALF     %1, %2
%endmacro
%macro FPQ_HALF 2
    FP_HALF     %1, %2
%endmacro

%endif
