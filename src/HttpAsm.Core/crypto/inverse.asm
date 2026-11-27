; =============================================================================
; crypto/inverse.asm - modular inversion for moduli below 2^256, constant time: ha_modinv256,
; the internal routine P-256 (its p and n: affine coordinates, ECDSA's k^-1 and s^-1) and
; Curve25519's field (2^255 - 19: Ed25519's encodings, X25519's result) call. Written in
; crypto/p256.asm first and moved here unchanged when Ed25519 needed it.
;
; Bernstein and Yang's divsteps ("Fast constant-time gcd computation and modular inversion",
; 2019) in the arrangement of libsecp256k1's modinv64 (MIT; its doc/safegcd_implementation.md
; derives every step and bound used here):
;   - half-delta divsteps (zeta = -(delta + 1/2), from -1): 590 of them, 10 batches of 59,
;     always: that document's bound for any input below 2^256;
;   - a batch works on f's and g's low 62-bit limbs only and builds the 2x2 transition matrix
;     (u, v, q, r), scaled by 2^62 (it starts at 8 = 2^3 and doubles 59 times), which is then
;     applied to the whole numbers: f, g = (u f + v g, q f + r g) / 2^62, and to the Bezout
;     coefficients d, e modulo M, a multiple of M chosen through M^-1 mod 2^62 making each
;     division exact;
;   - numbers in five signed 62-bit limbs (four of 62 bits, the top one signed), so each product
;     of a limb by a matrix entry fits a signed 128-bit sum.
; Every batch runs the same instructions whatever the values: no branch and no address depends
; on x (the counts are constants), which is why it can invert a secret nonce. A step selects the
; new f, u, v as the old g, q, r under the swap (f + (g - f) is g) with cmov: f no longer waits
; for the new g (2,226 to 2,158 ns, measured with the masked additions first).
;
; Against Fermat (x^(M - 2): a chain of about 255 squarings, each waiting for the last): P-256's
; 4.1 us against 2.16 us; at 2^255 - 19, measured with fe25519.inc's chains (ref10's: 254
; squarings, 11 products), 3.76 us at v3 (mulx) and 4.03 us at v1 (51-bit limbs, mul) against
; 2.11 us here, the same inverses on 20,000 random inputs. One version for every tier (v1 runs
; it too, so its gain there is the larger one): its products are imul's signed ones, which the
; matrix's negative entries need.
; =============================================================================
default rel

section .text

M62 equ 0x3FFFFFFFFFFFFFFF

; The local frame (rsp-based).
IV_F        equ 0                           ; f: five signed 62-bit limbs
IV_G        equ 40                          ; g
IV_D        equ 80                          ; d (the inverse's coefficient, modulo M)
IV_E        equ 120                         ; e
IV_X        equ 160                         ; the caller's x
IV_MOD      equ 168                         ; the modulus' record
IV_CNT      equ 176                         ; the batch counter
IV_ZETA     equ 184                         ; zeta between batches
IV_SIZE     equ 200

; IV_UPDATE a, b: the matrix applied to the two numbers held as five limbs at [rsp + a] and
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
  %rep 4
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
    mov         [rsp + %1 + 32], rbx        ; the top limbs, signed
    mov         [rsp + %2 + 32], r8
%endmacro

; -----------------------------------------------------------------------------
; ha_modinv256: x^-1 modulo M, constant time, for any odd M below 2^256 given by its record.
;   In: rdi = four qwords x (plain, little-endian, below M: a value that is only congruent to
;   one, such as a field element not fully reduced, must be reduced first - x = M itself would
;   not come back as 0), rsi = the modulus' record: M in five signed 62-bit limbs, then
;   M^-1 mod 2^62 (P-256's p256_mod_p and p256_mod_n, generated and proven by specs/p256.cs;
;   2^255 - 19's FE25519_INVERSE_RECORD, include/crypto/fe25519.inc).
;   Out: x replaced by x^-1 mod M, in [0, M); 0 stays 0 (no inverse: the callers' points at
;   infinity and small-order results rely on that). x and M must be coprime otherwise (M prime).
;   System V: keeps rbx, rbp, r12-r15; clobbers rax, rcx, rdx, rsi, rdi, r8-r11 and the flags.
;   Its frame (d, e, f, g: they derive from x, a secret nonce or point) is wiped before it
;   returns. No alignment asked of rsp.
; -----------------------------------------------------------------------------
global ha_modinv256:function hidden (ha_modinv256.end - ha_modinv256)
align 16
ha_modinv256:
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
  %rep 5
    mov         rax, [rsi + iv_q]
    mov         [rsp + IV_F + iv_q], rax
    mov         qword [rsp + IV_D + iv_q], 0
    mov         qword [rsp + IV_E + iv_q], 0
    %assign iv_q iv_q + 8
  %endrep
    mov         qword [rsp + IV_E], 1
    mov         r10, M62
    mov         r8, [rdi]
    mov         r9, [rdi + 8]
    mov         rax, r8
    and         rax, r10
    mov         [rsp + IV_G], rax
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
    shr         r9, 56
    mov         [rsp + IV_G + 32], r9
    mov         qword [rsp + IV_ZETA], -1
    mov         dword [rsp + IV_CNT], 10
.batch:
    ; 59 divsteps on the low limbs: zeta r8, f r9, g r10, u r11, v r12, q r13, r r14
    mov         r8, [rsp + IV_ZETA]
    mov         r9, [rsp + IV_F]
    mov         r10, [rsp + IV_G]
    mov         r11d, 8
    xor         r12d, r12d
    xor         r13d, r13d
    mov         r14d, 8
    mov         ecx, 59
.step:
    mov         rax, r8
    sar         rax, 63                     ; c1: all ones when zeta < 0
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
    and         rax, rdx                    ; c1 &= c2: zeta < 0 and g odd, the swap (ZF clear)
    cmovnz      r9, r10                     ; f, u, v = g, q, r under the swap (the old ones)
    cmovnz      r11, r13
    cmovnz      r12, r14
    and         rsi, rdx                    ; g, q, r += x, y, z under c2
    add         r10, rsi
    and         rdi, rdx
    add         r13, rdi
    and         rbx, rdx
    add         r14, rbx
    xor         r8, rax                     ; zeta = -zeta - 2 under the swap, else zeta - 1
    dec         r8
    shr         r10, 1                      ; g /= 2 (its low bit is 0 now); u, v *= 2
    add         r11, r11
    add         r12, r12
    dec         ecx
    jnz         .step
    mov         [rsp + IV_ZETA], r8
    ; d, e = (u d + v e, q d + r e) / 2^62 modulo M: md, me multiples of M make the low 62 bits
    ; vanish (and start at u or v, q or r for a negative d or e, keeping the range (-2M, M))
    mov         r15, [rsp + IV_MOD]
    mov         rax, [rsp + IV_D + 32]
    sar         rax, 63                     ; sd: d < 0
    mov         rdx, [rsp + IV_E + 32]
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
    mov         rax, [r15 + 40]             ; md -= (M^-1 cd + md) mod 2^62
    imul        rax, rbx
    add         rax, rdi
    and         rax, r10
    sub         rdi, rax
    mov         rax, [r15 + 40]             ; me -= (M^-1 ce + me) mod 2^62
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
  %rep 4
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
    mov         [rsp + IV_D + 32], rbx
    mov         [rsp + IV_E + 32], r8
    ; f, g = (u f + v g, q f + r g) / 2^62
    IV_UPDATE   IV_F, IV_G
    dec         dword [rsp + IV_CNT]
    jnz         .batch
    ; g is 0 and f is +1 or -1 (x and M coprime; f = M and d = 0 when x = 0): d, negated when
    ; f < 0, from (-2M, M) into [0, M), each conditional step a mask
    mov         r15, [rsp + IV_MOD]
    mov         r10, M62
    mov         rax, [rsp + IV_D + 32]
    sar         rax, 63                     ; d < 0: add M
    mov         rdx, [rsp + IV_F + 32]
    sar         rdx, 63                     ; f < 0: negate
  %assign iv_q 0
  %rep 5
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
    mov         rbx, [rsp + IV_D]
    mov         rcx, [rsp + IV_D + 8]
    mov         r8, [rsp + IV_D + 16]
    mov         r9, [rsp + IV_D + 24]
    mov         r11, [rsp + IV_D + 32]
    mov         rax, rbx
    sar         rax, 62
    add         rcx, rax
    and         rbx, r10
    mov         rax, rcx
    sar         rax, 62
    add         r8, rax
    and         rcx, r10
    mov         rax, r8
    sar         rax, 62
    add         r9, rax
    and         r8, r10
    mov         rax, r9
    sar         rax, 62
    add         r11, rax
    and         r9, r10
    mov         [rsp + IV_D], rbx
    mov         [rsp + IV_D + 8], rcx
    mov         [rsp + IV_D + 16], r8
    mov         [rsp + IV_D + 24], r9
    mov         [rsp + IV_D + 32], r11
    mov         rax, r11
    sar         rax, 63
    %assign iv_q 0
    %rep 5
    mov         rbx, [r15 + iv_q]
    and         rbx, rax
    add         [rsp + IV_D + iv_q], rbx
      %assign iv_q iv_q + 8
    %endrep
  %endrep
    ; d's five limbs back into four qwords
    mov         rdi, [rsp + IV_X]
    mov         rax, [rsp + IV_D]
    mov         rcx, [rsp + IV_D + 8]
    mov         rdx, rcx
    shl         rdx, 62
    or          rax, rdx
    mov         [rdi], rax
    mov         r8, [rsp + IV_D + 16]
    shr         rcx, 2
    mov         rdx, r8
    shl         rdx, 60
    or          rcx, rdx
    mov         [rdi + 8], rcx
    mov         r9, [rsp + IV_D + 24]
    shr         r8, 4
    mov         rdx, r9
    shl         rdx, 58
    or          r8, rdx
    mov         [rdi + 16], r8
    mov         rax, [rsp + IV_D + 32]
    shr         r9, 6
    shl         rax, 56
    or          r9, rax
    mov         [rdi + 24], r9
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
.end:
