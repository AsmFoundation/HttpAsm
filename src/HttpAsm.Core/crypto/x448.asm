; =============================================================================
; crypto/x448.asm - X448 (RFC 7748 5), the Diffie-Hellman function of TLS 1.3's x448 group
; (RFC 9846 4.2.7): the C ABI's httpasm_x448 (the shared secret from a scalar and a peer's
; u-coordinate) and httpasm_x448_public_key (the scalar times the base point, u = 5); and the
; field functions of GF(p), p = 2^448 - 2^224 - 1, that Ed448 shares (ha_fe448_mul, _sqr, _invert,
; _pow_p34, one per version, and the constant ha_fe448_2p).
;
; The field is include/crypto/fe448.inc's: eight 56-bit limbs at both versions (mulx at v3, mul
; at v1), Karatsuba over 2^224, sums uncarried; its header has the representation and the bounds.
; Weighed against seven 64-bit limbs (49 mulx with adcx/adox): the same count of products, but
; 2^224 falls mid-limb there (every reduction shifts by 32) and every sum needs carries, while
; 56-bit limbs leave sums and differences carry-free; and the column form can run two products
; interleaved (below), which adcx/adox's register-hungry rows cannot.
;
; Speed, measured on the i9-13900K (TSC ticks; the commits have the whole story):
; - Elements move through memory as qwords only, every store read back by loads of its own
;   size: a vector load over several qword stores cannot take their data from the store buffer
;   and waits for them to reach the cache (a chain of products took 105 ticks each when the
;   products' sums were vector loads of qword-stored outputs, 89 with qword loads), and making
;   the outputs vectors instead costs port 5, which mulx already fills (113 ticks).
; - One product is about 350 micro-operations, so the reorder buffer never holds two: alone, a
;   step's nine products run nearly one after the other. The ladder therefore computes its
;   products in pairs, the two interleaved column by column (FE448_MUL2, FE448_SQR2: 14
;   registers, no pointers, the operands frame offsets), so one product's chains fill the other's
;   waits (405k ticks a shared secret alone, 372k paired).
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
; written. The public key (u = 5, the base point of prime order q) does not take the ladder: RFC
; 7748 4.2's 4-isogeny takes edwards448's base point to u = 5 and k B to X448(k, 5), so
; crypto/ed448.asm's ha_x448_base_v computes k B from Ed448's precomputed table and returns
; (y / x)^2 (the same octets as the ladder at u = 5, which X448Tests and tests/native/tiers
; compare on every case). It is all zeros for one clamped scalar only, 4q itself (unlike X25519's,
; X448's clamped range [2^447, 2^448) holds a multiple of q): -1 for it too.
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "crypto/fe448.inc"

extern ha_x448_base_v3                      ; crypto/ed448.asm: X448(k, 5) by edwards448's fixed
extern ha_x448_base_v1                      ; base, per version

section .rodata
; 2p, limb by limb (2^57 - 2, limb 4 2^57 - 4): a - b + 2p keeps every limb of a - b positive.
align 64
global ha_fe448_2p:data hidden (ha_fe448_2p.end - ha_fe448_2p)
ha_fe448_2p:
    dq 2 * FE448_MASK, 2 * FE448_MASK, 2 * FE448_MASK, 2 * FE448_MASK
    dq 2 * (FE448_MASK - 1), 2 * FE448_MASK, 2 * FE448_MASK, 2 * FE448_MASK
.end:

section .text

; =============================================================================
; The field functions: ha_fe448_mul_v{3,1}(rdi = out, rsi = a, rcx = b) and
; ha_fe448_sqr_v{3,1}(rdi = out, rsi = a), eight-limb elements of 64 octets, out never
; overlapping an operand. They read their scratch at [rbp, rbp + 128): the caller's frame must
; start there (see fe448.inc's products' scratch). Both keep rdi, rsi, rbp (mul also rcx, r15;
; sqr r14, r15) and clobber rax, rbx, rdx, r8-r13, the flags, and mul r14, sqr rcx.
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
; The inverse, and the square root's power.
; =============================================================================

; -----------------------------------------------------------------------------
; FE448_POWER_ROUTINE v: two functions over one chain (rdi = out, rsi = z; out may be z, which
; is copied first):
;   ha_fe448_pow_p34_v: out = z^((p - 3) / 4), Ed448's decoding (RFC 8032 5.2.3: x = u^3 v
;     (u^5 v^3)^((p - 3) / 4));
;   ha_fe448_invert_v: out = z^(p - 2) = z^-1 (mod p), and 0 for z = 0 in any form.
; (p - 3) / 4 = 2^446 - 2^222 - 1 = (2^223 - 1) 2^223 + (2^222 - 1): x_n = z^(2^n - 1) for n = 2,
; 3, 6, 12, 24, 30, 48, 96, 192, 222, 223 (each from smaller ones: x_(m+n) = x_m^(2^n) x_n), then
; x_223^(2^223) x_222: 451 squarings and 12 products. p - 2 = 4 ((p - 3) / 4) + 1: the inverse
; squares that twice more and multiplies by z. The same steps for every z (constant time); the
; one branch is on which function was called. Keeps rbp (pushed; its own frame comes from it);
; clobbers rax, rbx, rcx, rdx, rsi, rdi, r8-r15 and the flags. Its frame, every power of z, is
; wiped before returning.
; The squarings ping-pong between IF_P and IF_Q: n of them from a slot end in IF_P for odd n,
; IF_Q for even n (SQRN's caller knows which), the address toggled by XOR with IF_TOGGLE. The
; chain is one dependence after another, so these are the one-at-a-time functions.
; -----------------------------------------------------------------------------
%macro FE448_POWER_ROUTINE 1
  %xdefine IF_Z FT_SIZE                     ; z (after the products' scratch)
  %xdefine IF_A (IF_Z + 64)                 ; the powers kept: see the chain below
  %xdefine IF_B (IF_A + 64)
  %xdefine IF_C (IF_B + 64)
  %xdefine IF_D (IF_C + 64)
  %xdefine IF_P (IF_D + 64)                 ; the squarings' two slots
  %xdefine IF_Q (IF_P + 64)
  %xdefine IF_OUT (IF_Q + 64)               ; where the result goes
  %xdefine IF_N (IF_OUT + 8)                ; squarings left
  %xdefine IF_TOGGLE (IF_N + 8)             ; (rbp + IF_P) XOR (rbp + IF_Q)
  %xdefine IF_INVERT (IF_TOGGLE + 8)        ; 1 for the inverse, 0 for the power (p - 3) / 4
  %xdefine IF_RSP (IF_INVERT + 8)           ; rsp before the frame's alignment
  %xdefine IF_END (IF_RSP + 8)

global ha_fe448_invert_%1:function hidden (ha_fe448_invert_%1.end - ha_fe448_invert_%1)
align 32
ha_fe448_invert_%1:
    mov         eax, 1
    jmp         fe448_power_%1
.end:

global ha_fe448_pow_p34_%1:function hidden (ha_fe448_pow_p34_%1.end - ha_fe448_pow_p34_%1)
align 32
ha_fe448_pow_p34_%1:
    xor         eax, eax
    jmp         fe448_power_%1
.end:

align 32
fe448_power_%1:
    push        rbp
    mov         rdx, rsp
    sub         rsp, IF_END
    and         rsp, -64                    ; slots on cache lines: no element splits two
    mov         rbp, rsp
    mov         [rbp + IF_RSP], rdx
    mov         [rbp + IF_OUT], rdi
    mov         [rbp + IF_INVERT], rax
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
    cmp         qword [rbp + IF_INVERT], 0
    je          .power
    FE448_CALL_MUL %1, IF_A, IF_P, IF_C     ; A = x223^(2^223) x222 = z^((p - 3) / 4)
    SQRN_%1     IF_A, 2
    mov         rdi, [rbp + IF_OUT]         ; out = A^4 z (out is not a slot of this frame)
    lea         rsi, [rbp + IF_Q]
    lea         rcx, [rbp + IF_Z]
    call        ha_fe448_mul_%1
    jmp         .wipe
.power:
    mov         rdi, [rbp + IF_OUT]         ; out = x223^(2^223) x222
    lea         rsi, [rbp + IF_P]
    lea         rcx, [rbp + IF_C]
    call        ha_fe448_mul_%1
.wipe:
    xor         eax, eax
    mov         ecx, IF_RSP / 8
    mov         rdi, rbp
    rep         stosq                       ; the frame wiped (not IF_RSP, read next)
    mov         rsp, [rbp + IF_RSP]
    pop         rbp
    ret
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

FE448_POWER_ROUTINE v3
FE448_POWER_ROUTINE v1

; =============================================================================
; The ladder.
; =============================================================================

; -----------------------------------------------------------------------------
; X448_ROUTINE name, v: int name(uint8_t out[56], const uint8_t scalar[56], const uint8_t u[56])
; at version v (v3: FE448_PROD_V3, or v1).
;   Returns 0, or -1 when out is all zeros. Keeps rbx, rbp, r12-r15 (pushed). The frame (the
;   clamped scalar, every ladder value) is wiped before returning; out is written last, so it
;   may be the scalar or u.
; The frame's offsets are %xdefine'd: each expansion redefines them. Its slots are 64-aligned
; (the frame is aligned to a cache line), so no element straddles two lines.
; -----------------------------------------------------------------------------
%macro X448_ROUTINE 2
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
    ; u (the peer's octets as they are: RFC 7748 5's decodeUCoordinate, no bit masked for X448);
    ; x2 = 1, z2 = 0, x3 = u, z3 = 1.
    xor         eax, eax
  %assign q 0
  %rep 8
    mov         [rbp + XF_X2 + q], rax
    mov         [rbp + XF_Z2 + q], rax
    mov         [rbp + XF_Z3 + q], rax
    %assign q q + 8
  %endrep
    FE448_DECODE rbp + XF_X1, rdx
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
    FE448_CALL_MUL %2, XF_Z3, XF_X1, XF_U                      ; z3 = x1 (DA - CB)^2
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
    ; -1 when the result is zero (a point of small order), else 0: the OR of the limbs, then
    ; neg's CF.
    neg         rax
    sbb         r9d, r9d                    ; -1 unless zero
    not         r9d
    HA_DECLASSIFY r9                        ; (public by design: the peer's point had small order)
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

X448_ROUTINE x448_v3, v3
X448_ROUTINE x448_v1, v1

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
;   out = X448(scalar, 5), the public key of a private scalar, by edwards448's fixed base
;   (crypto/ed448.asm's ha_x448_base_v: see this file's header). Returns 0, or -1 when out is all
;   zeros, which happens for one clamped scalar only: 4q, q the base point's prime order
;   (unreachable by a random scalar, but a key share of zeros would make every peer abort). The
;   same version choice (v3 with x86-64-v3: the table scans use AVX2 there).
; -----------------------------------------------------------------------------
global httpasm_x448_public_key:function (httpasm_x448_public_key.end - httpasm_x448_public_key)
align 16
httpasm_x448_public_key:
    HA_CPU_PICK HTTPASM_CPU_V3, .v3
    jmp         ha_x448_base_v1             ; (tail calls: the version returns to our caller)
.v3:
    jmp         ha_x448_base_v3
.end:
