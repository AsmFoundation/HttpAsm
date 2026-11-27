; =============================================================================
; include/crypto/fe25519.inc - arithmetic in GF(2^255 - 19), the field of Curve25519 and
; edwards25519 (RFC 7748, RFC 8032), as macros the curve code expands in place: X25519's ladder
; now, Ed25519's point formulas next. Two representations, one per version:
;
;   FE64 (v3: BMI2 and ADX): four 64-bit limbs, a value below 2^256 kept reduced modulo
;     2^256 - 38 = 2p only (2^256 = 38 modulo p), fully reduced once, at the end. Products by
;     mulx (BMI2: no flags written, any destination registers) with two carry chains at once
;     (adcx on CF, adox on OF), the arrangement of OpenSSL's x25519-x86_64 "fe64" code (Andy
;     Polyakov) and of Oliveira, Lopez, Hisil, Faz-Hernandez and Rodriguez-Henriquez, "How to
;     (pre-)compute a ladder" (SAC 2017).
;   FE51 (v1: any x86-64): five 51-bit limbs in qwords (a = a0 + 2^51 a1 + ... + 2^204 a4), the
;     "donna-c64" arrangement (Adam Langley's curve25519-donna): each output limb a sum of
;     mul's 128-bit products, with b1..b4 taken times 19 once so the products past 2^255 fold
;     back (2^255 = 19 modulo p). Limbs stay below 2^52 + 2^14 between operations, which bounds
;     every sum below 2^111.
;
; Every macro is constant time: no branch and no address depends on an operand's value. Operands
; are memory (frame slots addressed from rbp, or any address); the macros take rax, rbx, rcx,
; rdx, rdi, rsi and r8-r15 as they say, never rbp (the frame) or rsp. FE51's macros also use
; 40 octets of scratch at rbp + FE51_T19, which the including file defines.
; =============================================================================
%ifndef HTTPASM_FE25519_INC
%define HTTPASM_FE25519_INC

; =============================================================================
; FE64: four limbs, values below 2^256.
; =============================================================================

; FE64_STORE out: out = r8..r11 (four limbs, low first).
%macro FE64_STORE 1
    mov         [%1], r8
    mov         [%1 + 8], r9
    mov         [%1 + 16], r10
    mov         [%1 + 24], r11
%endmacro

; FE64_REDUCE out: the 512-bit product in r8..r15 (low first) folded below 2^256 into out: the
; high half times 38 onto the low half (2^256 = 38), then that sum's carry word times 38 (below
; 40 * 38), then 38 once more if that addition wrapped past 2^256 (after a wrap the low limb is
; small, so the last addition cannot carry). Clobbers rax, rbx, rcx, rdx, r8-r15 and the flags.
%macro FE64_REDUCE 1
    mov         edx, 38
    mulx        r12, rcx, r12               ; 38 t4
    xor         ebx, ebx                    ; rbx = 0; CF = OF = 0
    adcx        r8, rcx
    adox        r9, r12
    mulx        r13, rcx, r13               ; 38 t5
    adcx        r9, rcx
    adox        r10, r13
    mulx        r14, rcx, r14               ; 38 t6
    adcx        r10, rcx
    adox        r11, r14
    mulx        r15, rcx, r15               ; 38 t7
    adcx        r11, rcx
    adox        r15, rbx
    adcx        r15, rbx                    ; the carry word (at most 39)
    imul        r15, r15, 38
    add         r8, r15
    adc         r9, rbx
    adc         r10, rbx
    adc         r11, rbx
    sbb         rax, rax                    ; all ones when that wrapped past 2^256
    and         eax, 38
    add         r8, rax
    FE64_STORE  %1
%endmacro

; FE64_MUL out, a, b: out = a b modulo 2^256 - 38 (out may be a or b: both are read before out
; is written). Sixteen mulx in four rows of four, each row's low words joining one carry chain
; (CF) and its high words the other (OF); the rows' last carries cannot overflow, since a row's
; partial product with what came before stays below 2^(64 (row + 5)).
; Clobbers rax, rbx, rcx, rdx, r8-r15 and the flags.
%macro FE64_MUL 3
    xor         eax, eax                    ; rax = 0; CF = OF = 0
    mov         rdx, [%3]                   ; b0
    mulx        r9, r8, [%2]                ; a0 b0
    mulx        r10, rcx, [%2 + 8]          ; a1 b0
    adcx        r9, rcx
    mulx        r11, rcx, [%2 + 16]         ; a2 b0
    adcx        r10, rcx
    mulx        r12, rcx, [%2 + 24]         ; a3 b0
    adcx        r11, rcx
    adcx        r12, rax
    mov         rdx, [%3 + 8]               ; b1
    xor         r13d, r13d
    mulx        rbx, rcx, [%2]
    adcx        r9, rcx
    adox        r10, rbx
    mulx        rbx, rcx, [%2 + 8]
    adcx        r10, rcx
    adox        r11, rbx
    mulx        rbx, rcx, [%2 + 16]
    adcx        r11, rcx
    adox        r12, rbx
    mulx        rbx, rcx, [%2 + 24]
    adcx        r12, rcx
    adox        r13, rbx
    adcx        r13, rax
    mov         rdx, [%3 + 16]              ; b2
    xor         r14d, r14d
    mulx        rbx, rcx, [%2]
    adcx        r10, rcx
    adox        r11, rbx
    mulx        rbx, rcx, [%2 + 8]
    adcx        r11, rcx
    adox        r12, rbx
    mulx        rbx, rcx, [%2 + 16]
    adcx        r12, rcx
    adox        r13, rbx
    mulx        rbx, rcx, [%2 + 24]
    adcx        r13, rcx
    adox        r14, rbx
    adcx        r14, rax
    mov         rdx, [%3 + 24]              ; b3
    xor         r15d, r15d
    mulx        rbx, rcx, [%2]
    adcx        r11, rcx
    adox        r12, rbx
    mulx        rbx, rcx, [%2 + 8]
    adcx        r12, rcx
    adox        r13, rbx
    mulx        rbx, rcx, [%2 + 16]
    adcx        r13, rcx
    adox        r14, rbx
    mulx        rbx, rcx, [%2 + 24]
    adcx        r14, rcx
    adox        r15, rbx
    adcx        r15, rax
    FE64_REDUCE %1
%endmacro

; FE64_SQR out, a: out = a^2 modulo 2^256 - 38 (out may be a): the six cross products once (CF
; and OF chains), then doubled in one chain while the four squares join in the other: ten mulx
; where a product takes sixteen. Clobbers rax, rbx, rcx, rdx, rdi, rsi, r8-r15 and the flags.
%macro FE64_SQR 2
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
    adcx        r9, r9                      ; the cross products doubled (CF) ...
    adox        r9, r15                     ; ... and the squares added (OF)
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
    FE64_REDUCE %1
%endmacro

; FE64_ADD out, a, b: out = a + b modulo 2^256 - 38 (a carry past 2^256 comes back as 38, twice
; at most). Clobbers rax, r8-r11 and the flags.
%macro FE64_ADD 3
    mov         r8, [%2]
    mov         r9, [%2 + 8]
    mov         r10, [%2 + 16]
    mov         r11, [%2 + 24]
    add         r8, [%3]
    adc         r9, [%3 + 8]
    adc         r10, [%3 + 16]
    adc         r11, [%3 + 24]
    sbb         rax, rax
    and         eax, 38
    add         r8, rax
    adc         r9, 0
    adc         r10, 0
    adc         r11, 0
    sbb         rax, rax
    and         eax, 38
    add         r8, rax
    FE64_STORE  %1
%endmacro

; FE64_SUB out, a, b: out = a - b modulo 2^256 - 38 (a borrow below 0 comes back as -38, twice
; at most). Clobbers rax, r8-r11 and the flags.
%macro FE64_SUB 3
    mov         r8, [%2]
    mov         r9, [%2 + 8]
    mov         r10, [%2 + 16]
    mov         r11, [%2 + 24]
    sub         r8, [%3]
    sbb         r9, [%3 + 8]
    sbb         r10, [%3 + 16]
    sbb         r11, [%3 + 24]
    sbb         rax, rax
    and         eax, 38
    sub         r8, rax
    sbb         r9, 0
    sbb         r10, 0
    sbb         r11, 0
    sbb         rax, rax
    and         eax, 38
    sub         r8, rax
    FE64_STORE  %1
%endmacro

; FE64_MUL_A24 out, a: out = 121666 a, the ladder's (A + 2) / 4 (RFC 7748 5 computes
; z2 = E (AA + 121665 E), the same as E (BB + 121666 E) since AA = BB + E). The top word, below
; 121666, comes back times 38. Clobbers rax, rcx, rdx, r8-r11 and the flags.
%macro FE64_MUL_A24 2
    mov         edx, 121666
    mulx        rax, r8, [%2]
    mulx        rcx, r9, [%2 + 8]
    add         r9, rax
    mulx        rax, r10, [%2 + 16]
    adc         r10, rcx
    mulx        rcx, r11, [%2 + 24]
    adc         r11, rax
    adc         rcx, 0
    imul        rcx, rcx, 38
    add         r8, rcx
    adc         r9, 0
    adc         r10, 0
    adc         r11, 0
    sbb         rax, rax
    and         eax, 38
    add         r8, rax
    FE64_STORE  %1
%endmacro

; FE64_CSWAP mask, a, b: a and b exchanged when mask (a register) is all ones, kept when it is 0:
; t = (a ^ b) & mask, a ^= t, b ^= t, limb by limb (no branch, no address depends on mask).
; Clobbers rax, rcx, rdx and the flags.
%macro FE64_CSWAP 3
  %assign fe_q 0
  %rep 4
    mov         rax, [%2 + fe_q]
    mov         rcx, [%3 + fe_q]
    mov         rdx, rax
    xor         rdx, rcx
    and         rdx, %1
    xor         rax, rdx
    xor         rcx, rdx
    mov         [%2 + fe_q], rax
    mov         [%3 + fe_q], rcx
    %assign fe_q fe_q + 8
  %endrep
%endmacro

; FE64_LOAD_U out: a u-coordinate's 32 octets at rdx (little-endian), bit 255 cleared (RFC 7748
; 5: masked, not rejected), into out. Clobbers r8-r11 and the flags.
%macro FE64_LOAD_U 1
    mov         r8, [rdx]
    mov         r9, [rdx + 8]
    mov         r10, [rdx + 16]
    mov         r11, [rdx + 24]
    btr         r11, 63
    FE64_STORE  %1
%endmacro

; FE64_PACK a: a's value (below 2^256) into r8..r11, for the final reduction (FE_CANON).
%macro FE64_PACK 1
    mov         r8, [%1]
    mov         r9, [%1 + 8]
    mov         r10, [%1 + 16]
    mov         r11, [%1 + 24]
%endmacro

; =============================================================================
; FE51: five 51-bit limbs, each below 2^52 + 2^14 between operations.
; =============================================================================

FE51_MASK   equ 0x7FFFFFFFFFFFF             ; 2^51 - 1

; FE51_MAC lo, hi, x, y: hi:lo += x y (x moved to rax, mul by the memory operand y).
; Clobbers rax, rdx and the flags.
%macro FE51_MAC 4
    mov         rax, %3
    mul         qword %4
    add         %1, rax
    adc         %2, rdx
%endmacro

; FE51_CARRY out: five 128-bit sums, r8:r9 (limb 0), r10:r11, r12:r13, r14:r15, rbx:rcx (limb 4),
; carried into five limbs and stored at out: each limb's bits from 51 up (shld of its high word,
; below 2^60) join the next limb; limb 4's come back to limb 0 times 19 (limb 4 holds no folded
; products, so its carry is below 2^56 and times 19 fits); limb 0 then carries once more into
; limb 1. Result: limbs below 2^51, limb 1 below 2^51 + 2^13. Clobbers rax, rdi, r8-r15, rbx,
; rcx and the flags.
%macro FE51_CARRY 1
    mov         rdi, FE51_MASK
    shld        r9, r8, 13
    and         r8, rdi
    add         r10, r9
    adc         r11, 0
    shld        r11, r10, 13
    and         r10, rdi
    add         r12, r11
    adc         r13, 0
    shld        r13, r12, 13
    and         r12, rdi
    add         r14, r13
    adc         r15, 0
    shld        r15, r14, 13
    and         r14, rdi
    add         rbx, r15
    adc         rcx, 0
    shld        rcx, rbx, 13
    and         rbx, rdi
    imul        rcx, rcx, 19
    add         r8, rcx
    mov         rax, r8
    shr         rax, 51
    and         r8, rdi
    add         r10, rax
    mov         [%1], r8
    mov         [%1 + 8], r10
    mov         [%1 + 16], r12
    mov         [%1 + 24], r14
    mov         [%1 + 32], rbx
%endmacro

; FE51_MUL out, a, b: out = a b (out may be a or b): 19 b1..19 b4 to the scratch first, then
; each limb's five products (twenty-five mul), then FE51_CARRY.
; Clobbers rax, rbx, rcx, rdx, rdi, r8-r15 and the flags.
%macro FE51_MUL 3
  %assign fe_q 1
  %rep 4
    imul        rax, [%3 + 8 * fe_q], 19
    mov         [rbp + FE51_T19 + 8 * fe_q], rax
    %assign fe_q fe_q + 1
  %endrep
    ; limb 0: a0 b0 + 19 (a1 b4 + a2 b3 + a3 b2 + a4 b1)
    mov         rax, [%2]
    mul         qword [%3]
    mov         r8, rax
    mov         r9, rdx
    FE51_MAC    r8, r9, [%2 + 8], [rbp + FE51_T19 + 32]
    FE51_MAC    r8, r9, [%2 + 16], [rbp + FE51_T19 + 24]
    FE51_MAC    r8, r9, [%2 + 24], [rbp + FE51_T19 + 16]
    FE51_MAC    r8, r9, [%2 + 32], [rbp + FE51_T19 + 8]
    ; limb 1: a0 b1 + a1 b0 + 19 (a2 b4 + a3 b3 + a4 b2)
    mov         rax, [%2]
    mul         qword [%3 + 8]
    mov         r10, rax
    mov         r11, rdx
    FE51_MAC    r10, r11, [%2 + 8], [%3]
    FE51_MAC    r10, r11, [%2 + 16], [rbp + FE51_T19 + 32]
    FE51_MAC    r10, r11, [%2 + 24], [rbp + FE51_T19 + 24]
    FE51_MAC    r10, r11, [%2 + 32], [rbp + FE51_T19 + 16]
    ; limb 2: a0 b2 + a1 b1 + a2 b0 + 19 (a3 b4 + a4 b3)
    mov         rax, [%2]
    mul         qword [%3 + 16]
    mov         r12, rax
    mov         r13, rdx
    FE51_MAC    r12, r13, [%2 + 8], [%3 + 8]
    FE51_MAC    r12, r13, [%2 + 16], [%3]
    FE51_MAC    r12, r13, [%2 + 24], [rbp + FE51_T19 + 32]
    FE51_MAC    r12, r13, [%2 + 32], [rbp + FE51_T19 + 24]
    ; limb 3: a0 b3 + a1 b2 + a2 b1 + a3 b0 + 19 a4 b4
    mov         rax, [%2]
    mul         qword [%3 + 24]
    mov         r14, rax
    mov         r15, rdx
    FE51_MAC    r14, r15, [%2 + 8], [%3 + 16]
    FE51_MAC    r14, r15, [%2 + 16], [%3 + 8]
    FE51_MAC    r14, r15, [%2 + 24], [%3]
    FE51_MAC    r14, r15, [%2 + 32], [rbp + FE51_T19 + 32]
    ; limb 4: a0 b4 + a1 b3 + a2 b2 + a3 b1 + a4 b0
    mov         rax, [%2]
    mul         qword [%3 + 32]
    mov         rbx, rax
    mov         rcx, rdx
    FE51_MAC    rbx, rcx, [%2 + 8], [%3 + 24]
    FE51_MAC    rbx, rcx, [%2 + 16], [%3 + 16]
    FE51_MAC    rbx, rcx, [%2 + 24], [%3 + 8]
    FE51_MAC    rbx, rcx, [%2 + 32], [%3]
    FE51_CARRY  %1
%endmacro

; FE51_SQR out, a: out = a^2 (out may be a) with each cross product once (fifteen mul): the
; scratch holds 2 a0, 2 a1, 38 a2, 38 a3 and 19 a4, the factors the squared limbs need:
;   limb 0 = a0^2 + 38 a1 a4 + 38 a2 a3     limb 1 = 2 a0 a1 + 38 a2 a4 + 19 a3^2
;   limb 2 = 2 a0 a2 + a1^2 + 38 a3 a4      limb 3 = 2 a0 a3 + 2 a1 a2 + 19 a4^2
;   limb 4 = 2 a0 a4 + 2 a1 a3 + a2^2
; Clobbers rax, rbx, rcx, rdx, rdi, r8-r15 and the flags.
%macro FE51_SQR 2
    mov         rax, [%2]
    add         rax, rax
    mov         [rbp + FE51_T19], rax           ; 2 a0
    mov         rax, [%2 + 8]
    add         rax, rax
    mov         [rbp + FE51_T19 + 8], rax       ; 2 a1
    imul        rax, [%2 + 16], 38
    mov         [rbp + FE51_T19 + 16], rax      ; 38 a2
    imul        rax, [%2 + 24], 38
    mov         [rbp + FE51_T19 + 24], rax      ; 38 a3
    imul        rax, [%2 + 32], 19
    mov         [rbp + FE51_T19 + 32], rax      ; 19 a4
    mov         rax, [%2]
    mul         qword [%2]
    mov         r8, rax
    mov         r9, rdx
    imul        rax, [%2 + 8], 38               ; 38 a1
    mul         qword [%2 + 32]
    add         r8, rax
    adc         r9, rdx
    FE51_MAC    r8, r9, [%2 + 24], [rbp + FE51_T19 + 16]
    mov         rax, [rbp + FE51_T19]
    mul         qword [%2 + 8]
    mov         r10, rax
    mov         r11, rdx
    FE51_MAC    r10, r11, [%2 + 32], [rbp + FE51_T19 + 16]
    imul        rax, [%2 + 24], 19              ; 19 a3
    mul         qword [%2 + 24]
    add         r10, rax
    adc         r11, rdx
    mov         rax, [rbp + FE51_T19]
    mul         qword [%2 + 16]
    mov         r12, rax
    mov         r13, rdx
    FE51_MAC    r12, r13, [%2 + 8], [%2 + 8]
    FE51_MAC    r12, r13, [%2 + 32], [rbp + FE51_T19 + 24]
    mov         rax, [rbp + FE51_T19]
    mul         qword [%2 + 24]
    mov         r14, rax
    mov         r15, rdx
    FE51_MAC    r14, r15, [%2 + 16], [rbp + FE51_T19 + 8]
    FE51_MAC    r14, r15, [%2 + 32], [rbp + FE51_T19 + 32]
    mov         rax, [rbp + FE51_T19]
    mul         qword [%2 + 32]
    mov         rbx, rax
    mov         rcx, rdx
    FE51_MAC    rbx, rcx, [%2 + 24], [rbp + FE51_T19 + 8]
    FE51_MAC    rbx, rcx, [%2 + 16], [%2 + 16]
    FE51_CARRY  %1
%endmacro

; FE51_ADD out, a, b: out = a + b limb by limb, without carries: the sum's limbs stay below
; 2^52 + 2^14, which FE51_MUL and FE51_SQR take (an addition's result only ever feeds a product
; in the ladder, never another addition). Clobbers rax and the flags.
%macro FE51_ADD 3
  %assign fe_q 0
  %rep 5
    mov         rax, [%2 + fe_q]
    add         rax, [%3 + fe_q]
    mov         [%1 + fe_q], rax
    %assign fe_q fe_q + 8
  %endrep
%endmacro

; FE51_SUB out, a, b: out = a - b + 4p limb by limb (4p's limbs, 2^53 - 76 then 2^53 - 4, exceed
; any carried limb, so no limb goes negative), then carried as a product's sums are, so the
; result's limbs are carried limbs again. Clobbers rax, rbx, rcx, rdi, r8-r15 and the flags.
%macro FE51_SUB 3
    mov         r8, 0x1FFFFFFFFFFFB4        ; 4 (2^51 - 19)
    mov         rdi, 0x1FFFFFFFFFFFFC       ; 4 (2^51 - 1)
    add         r8, [%2]
    sub         r8, [%3]
    mov         r10, rdi
    add         r10, [%2 + 8]
    sub         r10, [%3 + 8]
    mov         r12, rdi
    add         r12, [%2 + 16]
    sub         r12, [%3 + 16]
    mov         r14, rdi
    add         r14, [%2 + 24]
    sub         r14, [%3 + 24]
    mov         rbx, rdi
    add         rbx, [%2 + 32]
    sub         rbx, [%3 + 32]
    xor         r9d, r9d                    ; the sums' high words: none
    xor         r11d, r11d
    xor         r13d, r13d
    xor         r15d, r15d
    xor         ecx, ecx
    FE51_CARRY  %1
%endmacro

; FE51_MUL_A24 out, a: out = 121666 a (as FE64_MUL_A24), each limb's product carried.
; Clobbers rax, rbx, rcx, rdx, rdi, rsi, r8-r15 and the flags.
%macro FE51_MUL_A24 2
    mov         esi, 121666
    mov         rax, [%2]
    mul         rsi
    mov         r8, rax
    mov         r9, rdx
    mov         rax, [%2 + 8]
    mul         rsi
    mov         r10, rax
    mov         r11, rdx
    mov         rax, [%2 + 16]
    mul         rsi
    mov         r12, rax
    mov         r13, rdx
    mov         rax, [%2 + 24]
    mul         rsi
    mov         r14, rax
    mov         r15, rdx
    mov         rax, [%2 + 32]
    mul         rsi
    mov         rbx, rax
    mov         rcx, rdx
    FE51_CARRY  %1
%endmacro

; FE51_CSWAP mask, a, b: as FE64_CSWAP, over five limbs. Clobbers rax, rcx, rdx and the flags.
%macro FE51_CSWAP 3
  %assign fe_q 0
  %rep 5
    mov         rax, [%2 + fe_q]
    mov         rcx, [%3 + fe_q]
    mov         rdx, rax
    xor         rdx, rcx
    and         rdx, %1
    xor         rax, rdx
    xor         rcx, rdx
    mov         [%2 + fe_q], rax
    mov         [%3 + fe_q], rcx
    %assign fe_q fe_q + 8
  %endrep
%endmacro

; FE51_LOAD_U out: a u-coordinate's 32 octets at rdx, bit 255 cleared, as five 51-bit limbs (the
; four qwords split at bits 51, 102, 153 and 204 by shrd). Clobbers rax, rdi, r8-r11.
%macro FE51_LOAD_U 1
    mov         r8, [rdx]
    mov         r9, [rdx + 8]
    mov         r10, [rdx + 16]
    mov         r11, [rdx + 24]
    btr         r11, 63
    mov         rdi, FE51_MASK
    mov         rax, r8
    and         rax, rdi
    mov         [%1], rax                   ; bits 0-50
    shrd        r8, r9, 51
    and         r8, rdi
    mov         [%1 + 8], r8                ; bits 51-101
    shrd        r9, r10, 38
    and         r9, rdi
    mov         [%1 + 16], r9               ; bits 102-152
    shrd        r10, r11, 25
    and         r10, rdi
    mov         [%1 + 24], r10              ; bits 153-203
    shr         r11, 12
    mov         [%1 + 32], r11              ; bits 204-254
%endmacro

; FE51_PACK a: a's limbs carried to 51 bits each (limb 4's overflow back times 19, twice: after
; the second pass only limb 0 can exceed 51 bits, by a few) and packed into four qwords r8..r11,
; a value below 2^255 + 2^51, for the final reduction (FE_CANON). The shifts come before the
; add/adc chain (shifts write CF); the packed pieces' bits do not overlap, so only limb 0's few
; extra bits can carry, and the chain takes that carry up.
; Clobbers rax, rcx, rdx, rsi, rdi, r8-r11 and the flags.
%macro FE51_PACK 1
    mov         rdi, FE51_MASK
    mov         r8, [%1]
    mov         r9, [%1 + 8]
    mov         r10, [%1 + 16]
    mov         r11, [%1 + 24]
    mov         rcx, [%1 + 32]
  %rep 2
    mov         rax, r8
    shr         rax, 51
    and         r8, rdi
    add         r9, rax
    mov         rax, r9
    shr         rax, 51
    and         r9, rdi
    add         r10, rax
    mov         rax, r10
    shr         rax, 51
    and         r10, rdi
    add         r11, rax
    mov         rax, r11
    shr         rax, 51
    and         r11, rdi
    add         rcx, rax
    mov         rax, rcx
    shr         rax, 51
    and         rcx, rdi
    imul        rax, rax, 19
    add         r8, rax
  %endrep
    mov         rax, r9
    shl         rax, 51                     ; l1 << 51
    shr         r9, 13                      ; l1 >> 13
    mov         rdx, r10
    shl         rdx, 38                     ; l2 << 38
    shr         r10, 26                     ; l2 >> 26
    mov         rsi, r11
    shl         rsi, 25                     ; l3 << 25
    shr         r11, 39                     ; l3 >> 39
    shl         rcx, 12                     ; l4 << 12
    add         r8, rax
    adc         r9, rdx
    adc         r10, rsi
    adc         r11, rcx
%endmacro

; =============================================================================
; Shared.
; =============================================================================

; FE_CANON: the value in r8..r11 (below 2^256) fully reduced modulo p in place: bit 255 comes
; back as 19 (leaving a value below 2^255 + 19), then p is subtracted when that value + 19
; reaches 2^255 (x >= p exactly then), selected with cmov.
; Clobbers rax, rbx, rcx, rdx and the flags.
%macro FE_CANON 0
    mov         rax, r11
    shr         rax, 63
    imul        rax, rax, 19
    btr         r11, 63
    add         r8, rax
    adc         r9, 0
    adc         r10, 0
    adc         r11, 0
    mov         rax, r8
    add         rax, 19
    mov         rbx, r9
    adc         rbx, 0
    mov         rcx, r10
    adc         rcx, 0
    mov         rdx, r11
    adc         rdx, 0
    btr         rdx, 63                     ; CF = bit 255 of x + 19
    cmovc       r8, rax
    cmovc       r9, rbx
    cmovc       r10, rcx
    cmovc       r11, rdx
%endmacro

%endif
