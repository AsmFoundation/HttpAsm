; =============================================================================
; crypto/x448.asm - X448 (RFC 7748 5), the Diffie-Hellman function of TLS 1.3's x448 group
; (RFC 9846 4.2.7): the C ABI's httpasm_x448 (the shared secret from a scalar and a peer's
; u-coordinate) and httpasm_x448_public_key (the scalar times the base point, u = 5); and the
; arithmetic of GF(p), p = 2^448 - 2^224 - 1, as hidden functions (ha_fe448_mul, _sqr, _invert,
; one per version) that Ed448 is to share.
;
; The field, at both versions: eight 56-bit limbs in qwords (a = a0 + 2^56 a1 + ... + 2^392 a7),
; so phi = 2^224 is limb 4 exactly and phi^2 = phi + 1 (mod p) folds whole limbs: a product is
; (A0 + A1 phi)(B0 + B1 phi) = (A0 B0 + A1 B1) + ((A0 + A1)(B0 + B1) - A0 B0) phi (mod p), three
; 4-limb products (Karatsuba: 48 multiplications), each output column a 128-bit sum (OpenSSL's
; arch_64 gf_mul from Mike Hamburg's libdecaf, column for column); a square is three 4-limb
; squares, A0^2, A1^2 and (A0 + A1)^2 (30 multiplications). Weighed against seven 64-bit limbs
; (49 mulx with adcx/adox): the same count of products, but 2^224 falls mid-limb there (every
; reduction shifts by 32) and every sum needs carries, while 56-bit limbs leave sums and
; differences carry-free; and the column form can run two products interleaved (below), which
; adcx/adox's register-hungry rows cannot. The versions differ in the multiplication only:
;   v3 (AVX2 and BMI2: chosen with x86-64-v3): mulx (any multiplier register, flags untouched);
;   v1 (any x86-64): mul.
; Bounds (scratchpad model x448/model.py ran this arithmetic step for step over RFC 7748's
; vectors and iterations, Wycheproof's tests and random cases, checking every sum; the worst
; case bounds by hand): product inputs have limbs below 3 2^56 (a sum of two outputs, or a
; difference biased by 2p); every column sum stays below 2^120, so a column's carry fits a
; qword; outputs come back below 2^56 except limbs 1 and 5 (a few units over) and, after a
; product by a small constant, limbs 0 and 4 (below 2^56 + 2^20). Sums are not carried (lazy);
; a - b is a + 2p - b, limb by limb, which keeps every limb positive while b's limbs are below
; 2^57 - 4 (b is always an output of a product here).
;
; Speed, measured on the i9-13900K (TSC ticks; see the commit for the whole story):
; - Elements move through memory as qwords only, every store read back by loads of its own
;   size: a vector load over several qword stores cannot take their data from the store buffer
;   and waits for them to reach the cache (a chain of products took 105 ticks each when the
;   products' sums were vector loads of qword-stored outputs, 89 with qword loads), and making
;   the outputs vectors instead costs port 5, which mulx already fills (113 ticks).
; - One product is about 350 micro-operations, so the reorder buffer never holds two: alone, a
;   step's nine products run nearly one after the other at their latency (about 100 ticks),
;   twice their throughput. The ladder therefore computes its products in pairs, the two
;   interleaved column by column (FE448_MUL2, FE448_SQR2: 14 registers, no pointers, the
;   operands frame offsets), so one product's chains fill the other's waits.
;
; The ladder is RFC 7748 5's, step for step: the scalar clamped (the low two bits cleared,
; bit 447 set), u's 56 octets taken as they are (a non-canonical u, at or above p, is reduced by
; the arithmetic, as RFC 7748 5 requires), 448 steps from bit 447 down, each a conditional swap
; by cmov (swap = k_t XOR the previous bit) and the differential addition and doubling with
; a24 = 39081, then x2 z2^(p - 2): z2^(p - 2) by a chain of 453 squarings and 13 products,
; fully reduced and written as 56 octets. Constant time: the bits steer cmov's condition only;
; the one address that moves, the scalar's qword, follows the public bit number.
;
; An all-zero result means the peer's point had small order (it carries no secret of ours):
; TLS 1.3 aborts then (RFC 9846 7.4.2), so httpasm_x448 says so with -1, the zeros still
; written. The public key (u = 5, the base point of prime order q) is all zeros for one clamped
; scalar only, 4q itself (unlike X25519's, X448's clamped range [2^447, 2^448) holds a multiple
; of q): httpasm_x448_public_key returns -1 for it too. Its ladder multiplies by u = 5 with a
; carry chain instead of a product (z3 = 5 (DA - CB)^2), one product fewer a step.
; =============================================================================
default rel
%include "httpasm_core.inc"

FE448_MASK equ 0x00FFFFFFFFFFFFFF          ; a limb's 56 bits

section .rodata
; 2p, limb by limb (2^57 - 2, limb 4 2^57 - 4): a - b + 2p keeps every limb of a - b positive.
align 64
fe448_2p:
    dq 2 * FE448_MASK, 2 * FE448_MASK, 2 * FE448_MASK, 2 * FE448_MASK
    dq 2 * (FE448_MASK - 1), 2 * FE448_MASK, 2 * FE448_MASK, 2 * FE448_MASK

section .text

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
; The field functions: ha_fe448_mul_v{3,1}(rdi = out, rsi = a, rcx = b) and
; ha_fe448_sqr_v{3,1}(rdi = out, rsi = a), eight-limb elements of 64 octets, out never
; overlapping an operand. They read their scratch at [rbp, rbp + 128): the caller's frame must
; start there (see the products' scratch). Both keep rdi, rsi, rbp (mul also rcx, r15; sqr
; r14, r15) and clobber rax, rbx, rdx, r8-r13, the flags, and mul r14, sqr rcx.
; =============================================================================

global ha_fe448_mul_v3:function hidden (ha_fe448_mul_v3.end - ha_fe448_mul_v3)
align 32
ha_fe448_mul_v3:
    FE448_MUL1  FE448_PROD_V3, rdi, rsi, rcx
    ret
.end:

global ha_fe448_sqr_v3:function hidden (ha_fe448_sqr_v3.end - ha_fe448_sqr_v3)
align 32
ha_fe448_sqr_v3:
    FE448_SQR1  FE448_PROD_V3, FE448_PROD2_V3, rdi, rsi
    ret
.end:

global ha_fe448_mul_v1:function hidden (ha_fe448_mul_v1.end - ha_fe448_mul_v1)
align 32
ha_fe448_mul_v1:
    FE448_MUL1  FE448_PROD_V1, rdi, rsi, rcx
    ret
.end:

global ha_fe448_sqr_v1:function hidden (ha_fe448_sqr_v1.end - ha_fe448_sqr_v1)
align 32
ha_fe448_sqr_v1:
    FE448_SQR1  FE448_PROD_V1, FE448_PROD2_V1, rdi, rsi
    ret
.end:

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
    add         rax, [rel fe448_2p + q]
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

; FE448_ENCODE octets, a: the element at a fully reduced (OpenSSL's gf_strong_reduce: one carry
; pass with limb 7's carry wrapped into limbs 0 and 4, which leaves a value below 2p; p
; subtracted with a signed carry, then added back, masked, when that went below zero) and
; written as 56 octets at the address in register `octets` (not rax, rbx, rcx, rdx, r8-r15):
; seven qword stores at 7i in rising order (each one's eighth octet is the next limb's first,
; rewritten by the next store), then limb 6's top octet and limb 7 as the qword at octet 48, so
; nothing past the 56th octet is written. Leaves rax = the OR of the limbs (0 for a zero
; result). Clobbers rbx, rcx, rdx, r8-r15 and the flags.
%macro FE448_ENCODE 2
    mov         r8, [%2]
    mov         r9, [%2 + 8]
    mov         r10, [%2 + 16]
    mov         r11, [%2 + 24]
    mov         r12, [%2 + 32]
    mov         r13, [%2 + 40]
    mov         r14, [%2 + 48]
    mov         r15, [%2 + 56]
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

; =============================================================================
; The inverse.
; =============================================================================

; -----------------------------------------------------------------------------
; FE448_INVERT_ROUTINE v: ha_fe448_invert_v(rdi = out, rsi = z): out = z^(p - 2) = z^-1 (mod p),
; and 0 for z = 0 in any form, by
;   p - 2 = (2^223 - 1) 2^225 + (2^222 - 1) 4 + 1:
;   x_n = z^(2^n - 1) for n = 2, 3, 6, 12, 24, 30, 48, 96, 192, 222, 223 (each from smaller ones:
;   x_(m+n) = x_m^(2^n) x_n), then ((x_223^(2^223) x_222)^4) z: 453 squarings and 13 products,
;   the same for every z (constant time). out may be z (z is copied first). Keeps rbp
;   (pushed; its own frame comes from it); clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r15 and
;   the flags. Its frame, every power of z, is wiped before returning.
; The squarings ping-pong between IF_P and IF_Q: n of them from a slot end in IF_P for odd n,
; IF_Q for even n (SQRN's caller knows which), the address toggled by XOR with IF_TOGGLE. The
; chain is one dependence after another, so these are the one-at-a-time functions.
; -----------------------------------------------------------------------------
%macro FE448_INVERT_ROUTINE 1
  %xdefine IF_Z FT_SIZE                     ; z (after the products' scratch)
  %xdefine IF_A (IF_Z + 64)                 ; the powers kept: see the chain below
  %xdefine IF_B (IF_A + 64)
  %xdefine IF_C (IF_B + 64)
  %xdefine IF_D (IF_C + 64)
  %xdefine IF_P (IF_D + 64)                 ; the squarings' two slots
  %xdefine IF_Q (IF_P + 64)
  %xdefine IF_OUT (IF_Q + 64)               ; where the inverse goes
  %xdefine IF_N (IF_OUT + 8)                ; squarings left
  %xdefine IF_TOGGLE (IF_N + 8)             ; (rbp + IF_P) XOR (rbp + IF_Q)
  %xdefine IF_RSP (IF_TOGGLE + 8)           ; rsp before the frame's alignment
  %xdefine IF_END (IF_RSP + 8)

global ha_fe448_invert_%1:function hidden (ha_fe448_invert_%1.end - ha_fe448_invert_%1)
align 32
ha_fe448_invert_%1:
    push        rbp
    mov         rax, rsp
    sub         rsp, IF_END
    and         rsp, -64                    ; slots on cache lines: no element splits two
    mov         rbp, rsp
    mov         [rbp + IF_RSP], rax
    mov         [rbp + IF_OUT], rdi
  %assign q 0
  %rep 8
    mov         rax, [rsi + q]
    mov         [rbp + IF_Z + q], rax
    %assign q q + 8
  %endrep
    lea         rax, [rbp + IF_P]
    lea         rdx, [rbp + IF_Q]
    xor         rax, rdx
    mov         [rbp + IF_TOGGLE], rax
    SQRN_%1     IF_Z, 1                     ; z^2
    FE448_CALL_MUL %1, IF_A, IF_P, IF_Z     ; A = x2
    SQRN_%1     IF_A, 1
    FE448_CALL_MUL %1, IF_B, IF_P, IF_Z     ; B = x3
    SQRN_%1     IF_B, 3
    FE448_CALL_MUL %1, IF_C, IF_P, IF_B     ; C = x6
    SQRN_%1     IF_C, 6
    FE448_CALL_MUL %1, IF_D, IF_Q, IF_C     ; D = x12
    SQRN_%1     IF_D, 12
    FE448_CALL_MUL %1, IF_A, IF_Q, IF_D     ; A = x24
    SQRN_%1     IF_A, 6
    FE448_CALL_MUL %1, IF_B, IF_Q, IF_C     ; B = x30 (x24^(2^6) x6)
    SQRN_%1     IF_A, 24
    FE448_CALL_MUL %1, IF_C, IF_Q, IF_A     ; C = x48
    SQRN_%1     IF_C, 48
    FE448_CALL_MUL %1, IF_D, IF_Q, IF_C     ; D = x96
    SQRN_%1     IF_D, 96
    FE448_CALL_MUL %1, IF_A, IF_Q, IF_D     ; A = x192
    SQRN_%1     IF_A, 30
    FE448_CALL_MUL %1, IF_C, IF_Q, IF_B     ; C = x222 (x192^(2^30) x30)
    SQRN_%1     IF_C, 1
    FE448_CALL_MUL %1, IF_D, IF_P, IF_Z     ; D = x223
    SQRN_%1     IF_D, 223
    FE448_CALL_MUL %1, IF_A, IF_P, IF_C     ; A = x223^(2^223) x222
    SQRN_%1     IF_A, 2
    mov         rdi, [rbp + IF_OUT]         ; out = A^4 z (out is not a slot of this frame)
    lea         rsi, [rbp + IF_Q]
    lea         rcx, [rbp + IF_Z]
    call        ha_fe448_mul_%1
    xor         eax, eax
    mov         ecx, IF_RSP / 8
    mov         rdi, rbp
    rep         stosq                       ; the frame wiped (not IF_RSP, read next)
    mov         rsp, [rbp + IF_RSP]
    pop         rbp
    ret
.end:
%endmacro

; SQRN_v slot, n: n squarings of the element at rbp + slot (n a constant, 1 or more), the first
; into IF_P, then alternating (the result in IF_P for odd n, IF_Q for even n). The count lives
; in the frame: the field functions clobber most free registers. n = 2 is written out: a loop
; run once would leave its back edge never taken (the coverage gate counts every edge).
%macro SQRN_v3 2
    SQRN_ANY    v3, %1, %2
%endmacro

%macro SQRN_v1 2
    SQRN_ANY    v1, %1, %2
%endmacro

%macro SQRN_ANY 3
    lea         rdi, [rbp + IF_P]
    lea         rsi, [rbp + %2]
    call        ha_fe448_sqr_%1
  %if (%3) == 2
    mov         rsi, rdi                    ; the square is the second one's input
    xor         rdi, [rbp + IF_TOGGLE]      ; and IF_Q its output
    call        ha_fe448_sqr_%1
  %elif (%3) > 2
    mov         dword [rbp + IF_N], (%3) - 1
%%more:
    mov         rsi, rdi                    ; the last square is the next one's input
    xor         rdi, [rbp + IF_TOGGLE]      ; and the other slot its output
    call        ha_fe448_sqr_%1
    dec         dword [rbp + IF_N]
    jnz         %%more
  %endif
%endmacro

FE448_INVERT_ROUTINE v3
FE448_INVERT_ROUTINE v1

; =============================================================================
; The ladder.
; =============================================================================

; -----------------------------------------------------------------------------
; X448_ROUTINE name, v, base: int name(uint8_t out[56], const uint8_t scalar[56],
; const uint8_t u[56]) at version v (v3: FE448_PROD_V3, or v1); with base = 1, int name(uint8_t
; out[56], const uint8_t scalar[56]) at u = 5, z3 taken as 5 (DA - CB)^2 by FE448_MULW.
;   Returns 0, or -1 when out is all zeros. Keeps rbx, rbp, r12-r15 (pushed). The frame (the
;   clamped scalar, every ladder value) is wiped before returning; out is written last, so it
;   may be the scalar or u.
; The frame's offsets are %xdefine'd: each expansion redefines them. Its slots are 64-aligned
; (the frame is aligned to a cache line), so no element straddles two lines.
; -----------------------------------------------------------------------------
%macro X448_ROUTINE 3
  %xdefine XF_X1 FT_SIZE                    ; u (after the products' scratch)
  %xdefine XF_X2 (XF_X1 + 64)               ; the ladder's (x2 : z2) and (x3 : z3)
  %xdefine XF_Z2 (XF_X2 + 64)
  %xdefine XF_X3 (XF_Z2 + 64)
  %xdefine XF_Z3 (XF_X3 + 64)
  %xdefine XF_A (XF_Z3 + 64)                ; the step's values (RFC 7748 5's names)
  %xdefine XF_AA (XF_A + 64)
  %xdefine XF_B (XF_AA + 64)
  %xdefine XF_BB (XF_B + 64)
  %xdefine XF_E (XF_BB + 64)
  %xdefine XF_C (XF_E + 64)
  %xdefine XF_D (XF_C + 64)
  %xdefine XF_DA (XF_D + 64)
  %xdefine XF_CB (XF_DA + 64)
  %xdefine XF_T (XF_CB + 64)                ; DA + CB, then z2^-1
  %xdefine XF_U (XF_T + 64)                 ; (DA - CB)^2, then the result
  %xdefine XF_K (XF_U + 64)                 ; the clamped scalar (56 octets; 64 kept)
  %xdefine XF_OUT (XF_K + 64)               ; where the result goes
  %xdefine XF_BIT (XF_OUT + 8)              ; the ladder's bit number, 447 down to 0
  %xdefine XF_SWAP (XF_BIT + 8)             ; the previous bit as a mask
  %xdefine XF_RSP (XF_SWAP + 8)             ; rsp before the frame's alignment
  %xdefine XF_END (XF_RSP + 8)
  %ifidn %2, v3
    %xdefine XP FE448_PROD_V3
    %xdefine XP2 FE448_PROD2_V3
  %else
    %xdefine XP FE448_PROD_V1
    %xdefine XP2 FE448_PROD2_V1
  %endif

align 32
%1:
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    sub         rsp, XF_END
    and         rsp, -64
    mov         rbp, rsp
    mov         [rbp + XF_RSP], rax
    mov         [rbp + XF_OUT], rdi
    ; The scalar, clamped (RFC 7748 5: decodeScalar448: the low two bits cleared, bit 447 set).
  %assign q 0
  %rep 7
    mov         rax, [rsi + q]
    %if q == 0
    and         rax, -4
    %elif q == 48
    bts         rax, 63
    %endif
    mov         [rbp + XF_K + q], rax
    %assign q q + 8
  %endrep
    ; u (the base point's 5, or the peer's octets as they are: RFC 7748 5's decodeUCoordinate,
    ; no bit masked for X448); x2 = 1, z2 = 0, x3 = u, z3 = 1.
    xor         eax, eax
  %assign q 0
  %rep 8
    mov         [rbp + XF_X2 + q], rax
    mov         [rbp + XF_Z2 + q], rax
    mov         [rbp + XF_Z3 + q], rax
    %if %3
    mov         [rbp + XF_X1 + q], rax
    %endif
    %assign q q + 8
  %endrep
  %if %3
    mov         qword [rbp + XF_X1], 5
  %else
    FE448_DECODE rbp + XF_X1, rdx
  %endif
    mov         qword [rbp + XF_X2], 1
    mov         qword [rbp + XF_Z3], 1
  %assign q 0
  %rep 8
    mov         rax, [rbp + XF_X1 + q]
    mov         [rbp + XF_X3 + q], rax
    %assign q q + 8
  %endrep
    mov         qword [rbp + XF_SWAP], 0
    mov         dword [rbp + XF_BIT], 447
%%ladder:
    ; k_t as a mask; the swap by k_t XOR the previous bit; then remember k_t.
    mov         ecx, [rbp + XF_BIT]
    mov         eax, ecx
    shr         eax, 6
    mov         rax, [rbp + XF_K + rax * 8]  ; (the qword follows the public bit number)
    shr         rax, cl
    and         eax, 1
    neg         rax
    mov         r8, rax
    xor         r8, [rbp + XF_SWAP]
    mov         [rbp + XF_SWAP], rax
    FE448_CSWAP r8, rbp + XF_X2, rbp + XF_X3
    FE448_CSWAP r8, rbp + XF_Z2, rbp + XF_Z3
    ; The step (RFC 7748 5): its products in pairs (DA and CB, AA and BB, x3 and (DA - CB)^2,
    ; x2 and z2), then z3; dead slots take later values (D, then C).
    FE448_SUB   rbp + XF_B, rbp + XF_X2, rbp + XF_Z2           ; B = x2 - z2
    FE448_ADD   rbp + XF_A, rbp + XF_X2, rbp + XF_Z2           ; A = x2 + z2
    FE448_SUB   rbp + XF_D, rbp + XF_X3, rbp + XF_Z3           ; D = x3 - z3
    FE448_ADD   rbp + XF_C, rbp + XF_X3, rbp + XF_Z3           ; C = x3 + z3
    FE448_MUL2  XP, rbp + XF_DA, rbp + XF_D, rbp + XF_A, rbp + XF_CB, rbp + XF_C, rbp + XF_B
    FE448_SQR2  XP, XP2, rbp + XF_AA, rbp + XF_A, rbp + XF_BB, rbp + XF_B
    FE448_ADD   rbp + XF_T, rbp + XF_DA, rbp + XF_CB           ; DA + CB
    FE448_SUB   rbp + XF_D, rbp + XF_DA, rbp + XF_CB           ; DA - CB
    FE448_SUB   rbp + XF_E, rbp + XF_AA, rbp + XF_BB           ; E = AA - BB
    FE448_MULW  rbp + XF_C, rbp + XF_E, 39081                  ; a24 E
    FE448_ADD   rbp + XF_C, rbp + XF_AA, rbp + XF_C            ; AA + a24 E
    FE448_SQR2  XP, XP2, rbp + XF_X3, rbp + XF_T, rbp + XF_U, rbp + XF_D
    FE448_MUL2  XP, rbp + XF_X2, rbp + XF_AA, rbp + XF_BB, rbp + XF_Z2, rbp + XF_E, rbp + XF_C
  %if %3
    FE448_MULW  rbp + XF_Z3, rbp + XF_U, 5                     ; z3 = 5 (DA - CB)^2
  %else
    FE448_CALL_MUL %2, XF_Z3, XF_X1, XF_U                      ; z3 = x1 (DA - CB)^2
  %endif
    dec         dword [rbp + XF_BIT]
    jns         %%ladder
    mov         r8, [rbp + XF_SWAP]
    FE448_CSWAP r8, rbp + XF_X2, rbp + XF_X3
    FE448_CSWAP r8, rbp + XF_Z2, rbp + XF_Z3
    ; x2 / z2, fully reduced, written out.
    lea         rdi, [rbp + XF_T]
    lea         rsi, [rbp + XF_Z2]
    call        ha_fe448_invert_%2          ; (keeps rbp; wipes its own frame)
    FE448_CALL_MUL %2, XF_U, XF_X2, XF_T
    mov         rdi, [rbp + XF_OUT]
    FE448_ENCODE rdi, rbp + XF_U
    ; -1 when the result is zero (a small-order point, or the base point times 4q), else 0:
    ; the OR of the limbs, then neg's CF.
    neg         rax
    sbb         r9d, r9d                    ; -1 unless zero
    not         r9d
    xor         eax, eax
    mov         ecx, XF_RSP / 8
    mov         rdi, rbp
    rep         stosq                       ; the frame wiped (not XF_RSP, read next)
    mov         eax, r9d
    mov         rsp, [rbp + XF_RSP]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret
%endmacro

X448_ROUTINE x448_v3, v3, 0
X448_ROUTINE x448_v1, v1, 0
X448_ROUTINE x448_base_v3, v3, 1
X448_ROUTINE x448_base_v1, v1, 1

; =============================================================================
; The C ABI.
; =============================================================================

; -----------------------------------------------------------------------------
; int httpasm_x448(uint8_t out[56], const uint8_t scalar[56], const uint8_t point[56])
;   out = X448(scalar, point) (RFC 7748 5). Returns 0, or -1 when out is all zeros: the peer's
;   point had small order (TLS 1.3 aborts then, RFC 9846 7.4.2); the zeros are written anyway.
;   v3 (mulx: x86-64-v3) or v1, chosen by the CPU.
; -----------------------------------------------------------------------------
global httpasm_x448:function (httpasm_x448.end - httpasm_x448)
align 16
httpasm_x448:
    HA_CPU_PICK HTTPASM_CPU_V3, .v3
    jmp         x448_v1                     ; (tail calls: the version returns to our caller)
.v3:
    jmp         x448_v3
.end:

; -----------------------------------------------------------------------------
; int httpasm_x448_public_key(uint8_t out[56], const uint8_t scalar[56])
;   out = X448(scalar, 5), the public key of a private scalar. Returns 0, or -1 when out is all
;   zeros, which happens for one clamped scalar only: 4q, q the base point's prime order
;   (unreachable by a random scalar, but a key share of zeros would make every peer abort).
; -----------------------------------------------------------------------------
global httpasm_x448_public_key:function (httpasm_x448_public_key.end - httpasm_x448_public_key)
align 16
httpasm_x448_public_key:
    HA_CPU_PICK HTTPASM_CPU_V3, .v3
    jmp         x448_base_v1                ; (tail calls: the version returns to our caller)
.v3:
    jmp         x448_base_v3
.end:
