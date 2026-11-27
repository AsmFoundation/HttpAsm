; =============================================================================
; include/crypto/fe448.inc - arithmetic in GF(2^448 - 2^224 - 1), the field of curve448 and
; edwards448 (RFC 7748, RFC 8032), as macros the curve code expands in place: X448's ladder
; (crypto/x448.asm, which also holds the field's functions and its 2p constant, ha_fe448_2p) and
; Ed448's point formulas (crypto/ed448.asm, which also makes X448's public keys).
;
; The representation, at both versions: eight 56-bit limbs in qwords (a = a0 + 2^56 a1 + ... +
; 2^392 a7), so phi = 2^224 is limb 4 exactly and phi^2 = phi + 1 (mod p) folds whole limbs: a
; product is (A0 + A1 phi)(B0 + B1 phi) = (A0 B0 + A1 B1) + ((A0 + A1)(B0 + B1) - A0 B0) phi
; (mod p), three 4-limb products (Karatsuba: 48 multiplications), each output column a 128-bit
; sum (OpenSSL's arch_64 gf_mul from Mike Hamburg's libdecaf, column for column); a square is
; three 4-limb squares, A0^2, A1^2 and (A0 + A1)^2 (30 multiplications). The versions differ in
; the multiplication only: FE448_PROD_V3 (mulx) and FE448_PROD_V1 (mul).
;
; Bounds (scratchpad models x448/model.py and its Ed448 extension ran this arithmetic over every
; vector and random inputs, checking every sum; the worst cases by hand agree): a product takes
; limbs up to 2^61 (its column sums stay below 2^128: 127 bits at 2^61 - 1 in every limb), X448's
; inputs stay below 3 2^56 (sums below 2^120) and Ed448's below 6 2^56; outputs come back below
; 2^56 except limbs 1 and 5 (a few units over) and, after a product by a small constant, limbs 0
; and 4 (below 2^56 + 2^20). Sums are not carried (lazy); a - b is a + 2p - b, limb by limb, which
; keeps every limb positive while b's limbs are below 2^57 - 4 (b must be a product's output, or
; a constant: never a sum or a difference).
;
; Elements move through memory as qwords only, every store read back by loads of its own size:
; a vector load over several qword stores waits for them to reach the cache (crypto/x448.asm's
; header has the measurements). Every macro is constant time: no branch and no address depends
; on an operand's value.
; =============================================================================
%ifndef HTTPASM_FE448_INC
%define HTTPASM_FE448_INC

FE448_MASK equ 0x00FFFFFFFFFFFFFF          ; a limb's 56 bits

; =============================================================================
; The products' scratch. Every frame that runs field products starts with FT_SIZE octets of
; scratch at rbp: the precomputed sums and doubled limbs of the operands (secrets, which the
; frame's wipe then covers), the first product's at rbp, a paired product's at rbp + 128.
; =============================================================================
FT_AA equ 0                                 ; mul and sqr: a0 + a4 .. a3 + a7 (4 qwords)
FT_BB equ 32                                ; mul: b0 + b4 .. b3 + b7
FT_BBB equ 64                               ; mul: (b0 + b4) + b4 .. (b3 + b7) + b7
FT_D equ 32                                 ; sqr: 2 a0 .. 2 a7 (8 qwords)
FT_DAA equ 96                               ; sqr: 2 (a0 + a4) .. 2 (a3 + a7)
FT_PAIR equ 128                             ; the second product's scratch
FT_SIZE equ 256

; FE448_PROD_V3 lo, hi, x, y, op, opc: (hi:lo) op= [x] [y] by mulx, op / opc being add / adc
; or sub / sbb. Clobbers rax, rbx, rdx and the flags.
%macro FE448_PROD_V3 6
    mov         rdx, [%3]
    mulx        rbx, rax, [%4]
    %5          %1, rax
    %6          %2, rbx
%endmacro

; FE448_PROD_V1 lo, hi, x, y, op, opc: the same by mul. Clobbers rax, rdx and the flags.
%macro FE448_PROD_V1 6
    mov         rax, [%3]
    mul         qword [%4]
    %5          %1, rax
    %6          %2, rdx
%endmacro

; FE448_PROD2_V3 lo, hi, lo2, hi2, x, y: (hi:lo) += [x] [y] and (hi2:lo2) -= the same product,
; one mulx. Clobbers rax, rbx, rdx and the flags.
%macro FE448_PROD2_V3 6
    mov         rdx, [%5]
    mulx        rbx, rax, [%6]
    add         %1, rax
    adc         %2, rbx
    sub         %3, rax
    sbb         %4, rbx
%endmacro

; FE448_PROD2_V1 lo, hi, lo2, hi2, x, y: the same by mul. Clobbers rax, rdx and the flags.
%macro FE448_PROD2_V1 6
    mov         rax, [%5]
    mul         qword [%6]
    add         %1, rax
    adc         %2, rdx
    sub         %3, rax
    sbb         %4, rdx
%endmacro

; FE448_PRE_MUL a, b, s: a product's sums into the scratch at s: aa = a0..3 + a4..7,
; bb = b0..3 + b4..7, bbb = bb + b4..7. Clobbers rax, rdx.
%macro FE448_PRE_MUL 3
  %assign c_j 0
  %rep 4
    mov         rax, [%1 + 8 * c_j]
    add         rax, [%1 + 8 * c_j + 32]
    mov         [%3 + FT_AA + 8 * c_j], rax
    mov         rax, [%2 + 8 * c_j]
    mov         rdx, [%2 + 8 * c_j + 32]
    add         rax, rdx
    mov         [%3 + FT_BB + 8 * c_j], rax
    add         rax, rdx
    mov         [%3 + FT_BBB + 8 * c_j], rax
    %assign c_j c_j + 1
  %endrep
%endmacro

; FE448_PRE_SQR a, s: a square's sums into the scratch at s: aa = a0..3 + a4..7, the eight
; limbs doubled, aa doubled. Clobbers rax, rbx, rdx.
%macro FE448_PRE_SQR 2
  %assign c_j 0
  %rep 4
    mov         rax, [%1 + 8 * c_j]
    mov         rdx, [%1 + 8 * c_j + 32]
    lea         rbx, [rax + rdx]
    mov         [%2 + FT_AA + 8 * c_j], rbx
    add         rbx, rbx
    mov         [%2 + FT_DAA + 8 * c_j], rbx
    add         rax, rax
    mov         [%2 + FT_D + 8 * c_j], rax
    add         rdx, rdx
    mov         [%2 + FT_D + 32 + 8 * c_j], rdx
    %assign c_j c_j + 1
  %endrep
%endmacro

; FE448_MULCOL prod, i, a, b, s, a0l, a0h, a1l, a1h, tl, th: a product's column pair (i, i + 4)
; added to acc0 = (a0h:a0l) and acc1 = (a1h:a1l), OpenSSL's gf_mul: acc2 = (tl:th) =
; (A0 B0)_i + (A0 B1)_(i+4); acc1 += (AA BB)_i + (AA BBB)_(i+4) - acc2; acc0 += (A1 B1)_i +
; (A1 BB)_(i+4) + acc2 (AA, BB, BBB the precomputed sums at s). acc1 never goes below acc2:
; each of its products dominates one of acc2's (aa >= a, bb >= b, bbb >= b limb by limb).
%macro FE448_MULCOL 11
    xor         %10, %10
    xor         %11, %11
  %assign c_j 0
  %rep 4
    %if c_j <= (%2)
    %1          %10, %11, %3 + 8 * c_j, %4 + 8 * ((%2) - c_j), add, adc
    %1          %8, %9, %5 + FT_AA + 8 * c_j, %5 + FT_BB + 8 * ((%2) - c_j), add, adc
    %1          %6, %7, %3 + 8 * (c_j + 4), %4 + 8 * ((%2) - c_j + 4), add, adc
    %else
    %1          %10, %11, %3 + 8 * c_j, %4 + 8 * ((%2) - c_j + 8), add, adc
    %1          %8, %9, %5 + FT_AA + 8 * c_j, %5 + FT_BBB + 8 * ((%2) - c_j + 4), add, adc
    %1          %6, %7, %3 + 8 * (c_j + 4), %5 + FT_BB + 8 * ((%2) - c_j + 4), add, adc
    %endif
    %assign c_j c_j + 1
  %endrep
    sub         %8, %10                     ; acc1 -= acc2
    sbb         %9, %11
    add         %6, %10                     ; acc0 += acc2
    adc         %7, %11
%endmacro

; FE448_SQCOL prod, lo, hi, x, d, k, op, opc: (hi:lo) op= column k of the 4-limb square of x
; (x = 4 qwords at address x, d = the same doubled): k = 0: x0^2; 1: 2x0 x1; 2: 2x0 x2 + x1^2;
; 3: 2x0 x3 + 2x1 x2; 4: 2x1 x3 + x2^2; 5: 2x2 x3; 6: x3^2.
%macro FE448_SQCOL 8
  %if (%6) == 0
    %1          %2, %3, %4, %4, %7, %8
  %elif (%6) == 1
    %1          %2, %3, %5, %4 + 8, %7, %8
  %elif (%6) == 2
    %1          %2, %3, %5, %4 + 16, %7, %8
    %1          %2, %3, %4 + 8, %4 + 8, %7, %8
  %elif (%6) == 3
    %1          %2, %3, %5, %4 + 24, %7, %8
    %1          %2, %3, %5 + 8, %4 + 16, %7, %8
  %elif (%6) == 4
    %1          %2, %3, %5 + 8, %4 + 24, %7, %8
    %1          %2, %3, %4 + 16, %4 + 16, %7, %8
  %elif (%6) == 5
    %1          %2, %3, %5 + 16, %4 + 24, %7, %8
  %elif (%6) == 6
    %1          %2, %3, %4 + 24, %4 + 24, %7, %8
  %endif
%endmacro

; FE448_SQCOL2 prod2, lo, hi, lo2, hi2, x, d, k: column k (0 to 3) of the 4-limb square of x
; added to (hi:lo) and subtracted from (hi2:lo2), each product once.
%macro FE448_SQCOL2 8
  %if (%8) == 0
    %1          %2, %3, %4, %5, %6, %6
  %elif (%8) == 1
    %1          %2, %3, %4, %5, %7, %6 + 8
  %elif (%8) == 2
    %1          %2, %3, %4, %5, %7, %6 + 16
    %1          %2, %3, %4, %5, %6 + 8, %6 + 8
  %elif (%8) == 3
    %1          %2, %3, %4, %5, %7, %6 + 24
    %1          %2, %3, %4, %5, %7 + 8, %6 + 16
  %endif
%endmacro

; FE448_SQRCOL prod, prod2, i, a, s, a0l, a0h, a1l, a1h, tl, th: a square's column pair
; (i, i + 4). With S0 = A0^2, S1 = A1^2, SA = (A0 + A1)^2 (7 columns each, 0 past 6), the low
; limb takes S0_i + S1_i + SA_(i+4) - S0_(i+4) and the high one S1_(i+4) + SA_i - S0_i +
; SA_(i+4): S0_i's products go to both at once (FE448_PROD2), SA_(i+4) is summed in (th:tl)
; and added to both. Each limb's sum is at least 0 (SA dominates S0 column by column) however
; its terms come in: the accumulators wrap modulo 2^128 on the way.
%macro FE448_SQRCOL 11
    FE448_SQCOL2 %2, %6, %7, %8, %9, %4, %5 + FT_D, %3                          ; +-S0_i
    FE448_SQCOL %1, %6, %7, %4 + 32, %5 + FT_D + 32, %3, add, adc               ; acc0 += S1_i
    FE448_SQCOL %1, %8, %9, %5 + FT_AA, %5 + FT_DAA, %3, add, adc               ; acc1 += SA_i
  %if (%3) < 3
    xor         %10, %10
    xor         %11, %11
    FE448_SQCOL %1, %10, %11, %5 + FT_AA, %5 + FT_DAA, (%3) + 4, add, adc       ; SA_(i+4)
    FE448_SQCOL %1, %6, %7, %4, %5 + FT_D, (%3) + 4, sub, sbb                   ; acc0 -= S0_(i+4)
    FE448_SQCOL %1, %8, %9, %4 + 32, %5 + FT_D + 32, (%3) + 4, add, adc         ; acc1 += S1_(i+4)
    add         %6, %10                     ; both take SA_(i+4)
    adc         %7, %11
    add         %8, %10
    adc         %9, %11
  %endif
%endmacro

; FE448_OUT a0l, a0h, a1l, a1h, mask, o, i: the column pair (i, i + 4) done: limb i = acc0 mod
; 2^56 and limb i + 4 = acc1 mod 2^56 stored at o (qword stores: see the header); both
; accumulators shifted down 56 bits, the carries into columns i + 1 and i + 5.
%macro FE448_OUT 7
    mov         rax, %1
    and         rax, %5
    mov         [%6 + 8 * (%7)], rax
    mov         rax, %3
    and         rax, %5
    mov         [%6 + 8 * (%7) + 32], rax
    shrd        %1, %2, 56
    shr         %2, 56
    shrd        %3, %4, 56
    shr         %4, 56
%endmacro

; FE448_FIN a0l, a0h, a1l, a1h, mask, o: the last carries (OpenSSL's ending): acc0 (out of
; column 3) belongs to column 4; acc1 (out of column 7) is 2^448 times itself = (phi + 1) times
; it, columns 0 and 4. Limbs 0 and 4 are rewritten below 2^56 and their own carries go to limbs
; 1 and 5 (which end a few units above 2^56). Every sum here is below 2^66, so the shifted
; carries fit a qword. Clobbers rax and the flags.
%macro FE448_FIN 6
    add         %1, %3
    adc         %2, %4
    add         %1, [%6 + 32]
    adc         %2, 0
    add         %3, [%6]
    adc         %4, 0
    mov         rax, %1
    and         rax, %5
    mov         [%6 + 32], rax
    mov         rax, %3
    and         rax, %5
    mov         [%6], rax
    shrd        %1, %2, 56
    add         [%6 + 40], %1
    shrd        %3, %4, 56
    add         [%6 + 8], %3
%endmacro

; FE448_MUL1 prod, o, a, b: [o] = [a] [b] (mod p), a, b and o any address expressions (o must
; not overlap a or b: the columns store o while a and b are still read), the scratch at rbp.
; Clobbers rax, rbx, rdx, r8-r14 and the flags.
%macro FE448_MUL1 4
    FE448_PRE_MUL %3, %4, rbp
    mov         r14, FE448_MASK
    xor         r8d, r8d                    ; acc0 = r8:r9, acc1 = r10:r11
    xor         r9d, r9d
    xor         r10d, r10d
    xor         r11d, r11d
  %assign m_i 0
  %rep 4
    FE448_MULCOL %1, m_i, %3, %4, rbp, r8, r9, r10, r11, r12, r13
    FE448_OUT   r8, r9, r10, r11, r14, %2, m_i
    %assign m_i m_i + 1
  %endrep
    FE448_FIN   r8, r9, r10, r11, r14, %2
%endmacro

; FE448_SQR1 prod, prod2, o, a: [o] = [a]^2 (mod p), o not overlapping a, the scratch at rbp.
; Clobbers rax, rbx, rcx, rdx, r8-r13 and the flags.
%macro FE448_SQR1 4
    FE448_PRE_SQR %4, rbp
    mov         rcx, FE448_MASK
    xor         r8d, r8d                    ; acc0 = r8:r9, acc1 = r10:r11
    xor         r9d, r9d
    xor         r10d, r10d
    xor         r11d, r11d
  %assign s_i 0
  %rep 4
    FE448_SQRCOL %1, %2, s_i, %4, rbp, r8, r9, r10, r11, r12, r13
    FE448_OUT   r8, r9, r10, r11, rcx, %3, s_i
    %assign s_i s_i + 1
  %endrep
    FE448_FIN   r8, r9, r10, r11, rcx, %3
%endmacro

; FE448_MUL2 prod, o1, a1, b1, o2, a2, b2: [o1] = [a1] [b1] and [o2] = [a2] [b2] (mod p), the
; two products' column pairs interleaved (first's acc0/acc1 in r8-r11, second's in r12-r15,
; acc2 in rsi:rdi for each in turn, the mask in rcx), so the reorder buffer always holds both.
; Operands are address expressions on rbp (no register holds a pointer); no output may overlap
; an input of either product. Scratch at rbp and rbp + FT_PAIR. Clobbers rax, rbx, rcx, rdx,
; rsi, rdi, r8-r15 and the flags.
%macro FE448_MUL2 7
    FE448_PRE_MUL %3, %4, rbp
    FE448_PRE_MUL %6, %7, rbp + FT_PAIR
    mov         rcx, FE448_MASK
    xor         r8d, r8d
    xor         r9d, r9d
    xor         r10d, r10d
    xor         r11d, r11d
    xor         r12d, r12d
    xor         r13d, r13d
    xor         r14d, r14d
    xor         r15d, r15d
  %assign m_i 0
  %rep 4
    FE448_MULCOL %1, m_i, %3, %4, rbp, r8, r9, r10, r11, rsi, rdi
    FE448_OUT   r8, r9, r10, r11, rcx, %2, m_i
    FE448_MULCOL %1, m_i, %6, %7, rbp + FT_PAIR, r12, r13, r14, r15, rsi, rdi
    FE448_OUT   r12, r13, r14, r15, rcx, %5, m_i
    %assign m_i m_i + 1
  %endrep
    FE448_FIN   r8, r9, r10, r11, rcx, %2
    FE448_FIN   r12, r13, r14, r15, rcx, %5
%endmacro

; FE448_SQR2 prod, prod2, o1, a1, o2, a2: [o1] = [a1]^2 and [o2] = [a2]^2 (mod p), interleaved
; as FE448_MUL2 is. Clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r15 and the flags.
%macro FE448_SQR2 6
    FE448_PRE_SQR %4, rbp
    FE448_PRE_SQR %6, rbp + FT_PAIR
    mov         rcx, FE448_MASK
    xor         r8d, r8d
    xor         r9d, r9d
    xor         r10d, r10d
    xor         r11d, r11d
    xor         r12d, r12d
    xor         r13d, r13d
    xor         r14d, r14d
    xor         r15d, r15d
  %assign s_i 0
  %rep 4
    FE448_SQRCOL %1, %2, s_i, %4, rbp, r8, r9, r10, r11, rsi, rdi
    FE448_OUT   r8, r9, r10, r11, rcx, %3, s_i
    FE448_SQRCOL %1, %2, s_i, %6, rbp + FT_PAIR, r12, r13, r14, r15, rsi, rdi
    FE448_OUT   r12, r13, r14, r15, rcx, %5, s_i
    %assign s_i s_i + 1
  %endrep
    FE448_FIN   r8, r9, r10, r11, rcx, %3
    FE448_FIN   r12, r13, r14, r15, rcx, %5
%endmacro

; =============================================================================
; Inline element operations of the ladder: sums, differences, the conditional swap, products by
; a small constant, and the encodings. Operands are element addresses (64 octets), moved as
; qwords (see the header).
; =============================================================================

; FE448_ADD out, a, b: out = a + b, limb by limb (no carry: lazy). out may be a or b.
; Clobbers rax.
%macro FE448_ADD 3
  %assign q 0
  %rep 8
    mov         rax, [%2 + q]
    add         rax, [%3 + q]
    mov         [%1 + q], rax
    %assign q q + 8
  %endrep
%endmacro

; FE448_SUB out, a, b: out = a + 2p - b, limb by limb (b's limbs below 2^57 - 4). out may be a
; or b. Clobbers rax.
%macro FE448_SUB 3
  %assign q 0
  %rep 8
    mov         rax, [%2 + q]
    add         rax, [rel ha_fe448_2p + q]
    sub         rax, [%3 + q]
    mov         [%1 + q], rax
    %assign q q + 8
  %endrep
%endmacro

; FE448_CSWAP mask, x, y: swaps the elements at x and y when the register mask is nonzero,
; keeps them when it is 0: the same loads, cmovs and stores either way (cmov's timing does not
; depend on its condition). Clobbers rax, rbx, rdx and the flags.
%macro FE448_CSWAP 3
    test        %1, %1
  %assign q 0
  %rep 8
    mov         rax, [%2 + q]
    mov         rdx, [%3 + q]
    mov         rbx, rax
    cmovnz      rax, rdx
    cmovnz      rdx, rbx
    mov         [%2 + q], rax
    mov         [%3 + q], rdx
    %assign q q + 8
  %endrep
%endmacro

; FE448_MULW out, a, w: out = w a for a constant w below 2^32 (39081, or 5), limb by limb with
; a carry chain (each product below 2^76, so its carry stays below 2^20); the last carry is
; 2^448 times itself = (phi + 1) times it: added to limbs 0 and 4, which stay just over 2^56.
; out may be a (each limb is read before it is written). Clobbers rax, rdx, r8-r11, the flags.
%macro FE448_MULW 3
    mov         r9d, %3
    mov         r10, FE448_MASK
    xor         r8d, r8d                    ; the carry
  %assign q 0
  %rep 8
    mov         rax, [%2 + q]
    mul         r9
    add         rax, r8
    adc         rdx, 0
    mov         r11, rax
    and         r11, r10
    mov         [%1 + q], r11
    shrd        rax, rdx, 56
    mov         r8, rax
    %assign q q + 8
  %endrep
    add         [%1], r8
    add         [%1 + 32], r8
%endmacro

; FE448_DECODE out, octets: the 56 octets at the address in register `octets` as eight 56-bit
; limbs (7 octets each, little-endian): qwords at 7i masked, the last from octet 48 shifted
; down, so nothing past the 56th octet is read. No reduction: a value at or above p is a valid
; operand. Clobbers rax, rcx.
%macro FE448_DECODE 2
    mov         rcx, FE448_MASK
  %assign q 0
  %rep 7
    mov         rax, [%2 + 7 * q]
    and         rax, rcx
    mov         [%1 + 8 * q], rax
    %assign q q + 1
  %endrep
    mov         rax, [%2 + 48]
    shr         rax, 8
    mov         [%1 + 56], rax
%endmacro

; FE448_STRONG a: the element at a fully reduced, its limbs left in r8-r15 (each below 2^56,
; the value below p): OpenSSL's gf_strong_reduce - one carry pass with limb 7's carry wrapped
; into limbs 0 and 4, which leaves a value below 2p for any limbs below 2^61; p subtracted with
; a signed carry, then added back, masked, when that went below zero. Clobbers rax, rbx, rcx,
; rdx and the flags.
%macro FE448_STRONG 1
    mov         r8, [%1]
    mov         r9, [%1 + 8]
    mov         r10, [%1 + 16]
    mov         r11, [%1 + 24]
    mov         r12, [%1 + 32]
    mov         r13, [%1 + 40]
    mov         r14, [%1 + 48]
    mov         r15, [%1 + 56]
    mov         rcx, FE448_MASK
    ; The weak reduction, top down: limb i keeps its 56 bits plus limb i - 1's carry; limb 7's
    ; carry (rax) goes to limb 4 first (so limb 5 takes it with limb 4's) and to limb 0 last.
    mov         rax, r15
    shr         rax, 56
    add         r12, rax
  %assign q 15
  %rep 7
    and         r %+ q, rcx
    mov         rdx, r %+ %eval(q - 1)
    shr         rdx, 56
    add         r %+ q, rdx
    %assign q q - 1
  %endrep
    and         r8, rcx
    add         r8, rax
    ; Minus p, the carry signed in rax (0 or -1 out of each limb): p's limbs are 2^56 - 1, and
    ; 2^56 - 2 at limb 4 (one more added back there).
    mov         rax, r8
    sub         rax, rcx
    mov         r8, rax
    and         r8, rcx
    sar         rax, 56
  %assign q 9
  %rep 7
    add         rax, r %+ q
    sub         rax, rcx
    %if q == 12
    inc         rax
    %endif
    mov         r %+ q, rax
    and         r %+ q, rcx
    sar         rax, 56
    %assign q q + 1
  %endrep
    ; rax = 0: the value was p or more, and this is it minus p. rax = -1: it was below p, and
    ; this is it minus p plus 2^448: p added back (masked by rax), the last carry dropped (the
    ; 2^448). rbx = p's limb or 0, rdx = limb 4's (2^56 - 2) or 0.
    mov         rbx, rax
    and         rbx, rcx
    lea         rdx, [rbx + rax]
    add         r8, rbx
    mov         rax, r8
    shr         rax, 56
    and         r8, rcx
  %assign q 9
  %rep 7
    %if q == 12
    add         r %+ q, rdx
    %else
    add         r %+ q, rbx
    %endif
    add         r %+ q, rax
    mov         rax, r %+ q
    shr         rax, 56
    and         r %+ q, rcx
    %assign q q + 1
  %endrep
%endmacro

; FE448_STORE56 octets: the fully reduced limbs in r8-r15 as 56 octets at the address in
; register `octets` (not rax, rdx, r8-r15): seven qword stores at 7i in rising order (each
; one's eighth octet is the next limb's first, rewritten by the next store), then limb 6's top
; octet and limb 7 as the qword at octet 48, so nothing past the 56th octet is written. Leaves
; rax = the OR of the limbs (0 for a zero value). Clobbers rdx and the flags.
%macro FE448_STORE56 1
    mov         [%1], r8
    mov         [%1 + 7], r9
    mov         [%1 + 14], r10
    mov         [%1 + 21], r11
    mov         [%1 + 28], r12
    mov         [%1 + 35], r13
    mov         [%1 + 42], r14
    mov         rax, r15
    shl         rax, 8
    mov         rdx, r14
    shr         rdx, 48
    or          rax, rdx
    mov         [%1 + 48], rax
    mov         rax, r8
    or          rax, r9
    or          rax, r10
    or          rax, r11
    or          rax, r12
    or          rax, r13
    or          rax, r14
    or          rax, r15
%endmacro

; FE448_STORE_LIMBS out: the limbs in r8-r15 stored as the element at out (eight qwords).
%macro FE448_STORE_LIMBS 1
  %assign q 0
  %rep 8
    mov         [%1 + q], r %+ %eval(8 + q / 8)
    %assign q q + 8
  %endrep
%endmacro

; FE448_ENCODE octets, a: the element at a fully reduced (FE448_STRONG) and written as 56
; octets at the address in register `octets` (not rax, rbx, rcx, rdx, r8-r15; FE448_STORE56).
; Leaves rax = the OR of the limbs (0 for a zero result). Clobbers rbx, rcx, rdx, r8-r15 and
; the flags.
%macro FE448_ENCODE 2
    FE448_STRONG %2
    FE448_STORE56 %1
%endmacro

; FE448_CALL_MUL v, out, a, b / FE448_CALL_SQR v, out, a: one field function of version v on
; frame slots (offsets from rbp). Clobber what the functions do, and rdi, rsi, rcx.
%macro FE448_CALL_MUL 4
    lea         rdi, [rbp + %2]
    lea         rsi, [rbp + %3]
    lea         rcx, [rbp + %4]
    call        ha_fe448_mul_%1
%endmacro

%macro FE448_CALL_SQR 3
    lea         rdi, [rbp + %2]
    lea         rsi, [rbp + %3]
    call        ha_fe448_sqr_%1
%endmacro

%endif
