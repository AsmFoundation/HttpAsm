; =============================================================================
; crypto/x25519.asm - X25519 (RFC 7748 5), the Diffie-Hellman function TLS 1.3 offers first
; (x25519, RFC 9846 4.2.7) and the base of RFC 10024's X25519MLKEM768: the C ABI's
; httpasm_x25519 (the shared secret from a scalar and a peer's u-coordinate) and
; httpasm_x25519_public_key (the scalar times the base point, u = 9).
;
; One Montgomery ladder (X25519_ROUTINE), expanded over the two field versions of
; include/crypto/fe25519.inc, chosen once per call:
;   v3 (BMI2 + ADX: mulx, adcx/adox): four 64-bit limbs (FE64);
;   v1 (any x86-64): five 51-bit limbs with mul (FE51).
; The ladder is RFC 7748 5's, step for step: the scalar clamped (low three bits and bit 255
; cleared, bit 254 set), u's bit 255 masked and non-canonical u accepted as they are (the
; arithmetic is modulo p), 255 steps from bit 254 down, each a conditional swap by mask (swap =
; k_t XOR the previous bit) and the differential addition and doubling, then x2 / z2, fully
; reduced. z2 is inverted by ha_modinv256 (crypto/inverse.asm: safegcd, constant time) on z2
; fully reduced: 2.11 us where RFC 7748's z2^(p - 2) by ref10's addition chain (254 squarings,
; each waiting for the last, and 11 multiplications: this file's until Ed25519 brought the
; routine here) takes 3.76 us at v3 and 4.03 us at v1. A z2 of 0 (a small-order point's) comes
; back 0, as z2^(p - 2) did, so the result is still all zeros then.
; Constant time: the bits steer masks only; the one address that moves, the scalar's qword,
; follows the public bit number.
;
; An all-zero result means the peer's point had small order (it carries no secret of ours):
; TLS 1.3 aborts then (RFC 9846 7.4.2), so httpasm_x25519 says so with -1, the zeros still
; written for callers that want them (RFC 7748 6.1: "MAY check").
;
; The public key, X25519(k, 9), does not take the ladder: the base point is fixed, so
; crypto/ed25519.asm's ha_x25519_base_v computes k B on edwards25519 from its precomputed table
; (43 signed 6-bit windows, one mixed addition each, constant time) and maps it to u = (1 + y) /
; (1 - y) (RFC 7748 4.1's birational map, which takes edwards25519's B to u = 9): the same
; octets as the ladder at u = 9 (X25519Tests compares the two on every case), in about a quarter
; of its time (see the httpasm_x25519_public_key dispatcher below).
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "crypto/fe25519.inc"

extern ha_modinv256                         ; crypto/inverse.asm: x^-1 mod M (safegcd)
extern ha_x25519_base_v3                    ; crypto/ed25519.asm: X25519(k, 9) by edwards25519's
extern ha_x25519_base_v1                    ; fixed base, per field version

section .rodata
FE25519_INVERSE_RECORD                      ; fe25519_mod_p, for ha_modinv256

section .text

; -----------------------------------------------------------------------------
; X25519_ROUTINE name, F, S: int name(uint8_t out[32], const uint8_t scalar[32],
; const uint8_t u[32]) over the field F (FE64 or FE51), whose elements take S octets.
;   Returns 0, or -1 when out is all zeros. Keeps rbx, rbp, r12-r15 (pushed). The frame (the
;   clamped scalar, every ladder value) is wiped before returning.
; The frame's offsets are %xdefine'd, not equ'd: each expansion redefines them.
; -----------------------------------------------------------------------------
%macro X25519_ROUTINE 3
  %xdefine XS %3
  %xdefine XF_X1 (0)                        ; u
  %xdefine XF_X2 (XS)                       ; the ladder's (x2 : z2) and (x3 : z3)
  %xdefine XF_Z2 (2 * XS)
  %xdefine XF_X3 (3 * XS)
  %xdefine XF_Z3 (4 * XS)
  %xdefine XF_A (5 * XS)                    ; the step's values (RFC 7748 5's names)
  %xdefine XF_AA (6 * XS)
  %xdefine XF_B (7 * XS)
  %xdefine XF_BB (8 * XS)
  %xdefine XF_E (9 * XS)
  %xdefine XF_C (10 * XS)
  %xdefine XF_D (11 * XS)
  %xdefine XF_DA (12 * XS)
  %xdefine XF_CB (13 * XS)
  %xdefine XF_T (14 * XS)
  %xdefine XF_K (15 * XS)                   ; the clamped scalar (32 octets)
  %xdefine XF_OUT (XF_K + 32)               ; where the result goes
  %xdefine XF_BIT (XF_OUT + 8)              ; the ladder's bit number, 254 down to 0
  %xdefine XF_SWAP (XF_BIT + 8)             ; the previous bit as a mask
  %xdefine FE51_T19 (XF_SWAP + 8)           ; FE51's scratch: 40 octets
  %xdefine XF_END (FE51_T19 + 40)
  %xdefine XF_FRAME (((XF_END + 15) & -16) + 8)    ; six pushes + this: rsp 16-aligned

align 16
%1:
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    sub         rsp, XF_FRAME
    mov         rbp, rsp
    mov         [rbp + XF_OUT], rdi
    ; The scalar, clamped (RFC 7748 5: decodeScalar25519).
    mov         rax, [rsi]
    and         rax, -8
    mov         [rbp + XF_K], rax
    mov         rax, [rsi + 8]
    mov         [rbp + XF_K + 8], rax
    mov         rax, [rsi + 16]
    mov         [rbp + XF_K + 16], rax
    mov         rax, [rsi + 24]
    btr         rax, 63
    bts         rax, 62
    mov         [rbp + XF_K + 24], rax
    %2_LOAD_U   rbp + XF_X1
    ; x2 = 1, z2 = 0, x3 = u, z3 = 1.
    xor         eax, eax
    mov         ecx, XS / 8
    lea         rdi, [rbp + XF_X2]
    rep         stosq
    mov         ecx, XS / 8
    lea         rdi, [rbp + XF_Z2]
    rep         stosq
    mov         ecx, XS / 8
    lea         rdi, [rbp + XF_Z3]
    rep         stosq
    mov         qword [rbp + XF_X2], 1
    mov         qword [rbp + XF_Z3], 1
  %assign x_q 0
  %rep XS / 8
    mov         rax, [rbp + XF_X1 + x_q]
    mov         [rbp + XF_X3 + x_q], rax
    %assign x_q x_q + 8
  %endrep
    mov         qword [rbp + XF_SWAP], 0
    mov         dword [rbp + XF_BIT], 254
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
    %2_CSWAP    r8, rbp + XF_X2, rbp + XF_X3
    %2_CSWAP    r8, rbp + XF_Z2, rbp + XF_Z3
    ; The ladder step (RFC 7748 5), its operations ordered so independent ones stand together:
    ; the reorder buffer holds about five of these operations, and only what is adjacent
    ; overlaps (measured: the RFC's own order took 128k cycles a call at either version, this
    ; one 97.5k at v3 and 111k at v1). Dead slots take the step's later values (D, then C).
    %2_SUB      rbp + XF_B, rbp + XF_X2, rbp + XF_Z2        ; B = x2 - z2
    %2_ADD      rbp + XF_A, rbp + XF_X2, rbp + XF_Z2        ; A = x2 + z2
    %2_SUB      rbp + XF_D, rbp + XF_X3, rbp + XF_Z3        ; D = x3 - z3
    %2_ADD      rbp + XF_C, rbp + XF_X3, rbp + XF_Z3        ; C = x3 + z3
    %2_MUL      rbp + XF_DA, rbp + XF_D, rbp + XF_A         ; DA = D A
    %2_MUL      rbp + XF_CB, rbp + XF_C, rbp + XF_B         ; CB = C B
    %2_SQR      rbp + XF_BB, rbp + XF_B                     ; BB = B^2
    %2_SQR      rbp + XF_AA, rbp + XF_A                     ; AA = A^2
    %2_ADD      rbp + XF_T, rbp + XF_DA, rbp + XF_CB        ; DA + CB
    %2_SUB      rbp + XF_D, rbp + XF_DA, rbp + XF_CB        ; DA - CB
    %2_MUL      rbp + XF_X2, rbp + XF_AA, rbp + XF_BB       ; x2 = AA BB
    %2_SUB      rbp + XF_E, rbp + XF_AA, rbp + XF_BB        ; E = AA - BB
    %2_SQR      rbp + XF_D, rbp + XF_D                      ; (DA - CB)^2
    %2_MUL_A24  rbp + XF_C, rbp + XF_E                      ; 121666 E
    %2_SQR      rbp + XF_X3, rbp + XF_T                     ; x3 = (DA + CB)^2
    %2_ADD      rbp + XF_C, rbp + XF_BB, rbp + XF_C         ; BB + 121666 E
    %2_MUL      rbp + XF_Z3, rbp + XF_X1, rbp + XF_D        ; z3 = x1 (DA - CB)^2
    %2_MUL      rbp + XF_Z2, rbp + XF_E, rbp + XF_C         ; z2 = E (BB + 121666 E)
    dec         dword [rbp + XF_BIT]
    jns         %%ladder
    mov         r8, [rbp + XF_SWAP]
    %2_CSWAP    r8, rbp + XF_X2, rbp + XF_X3
    %2_CSWAP    r8, rbp + XF_Z2, rbp + XF_Z3
    ; z2^-1: z2 fully reduced (ha_modinv256 takes values below p, and a z2 of 0 in any form must
    ; come back 0) into XF_A as four qwords, inverted in place, loaded back as XF_C.
    %2_PACK     rbp + XF_Z2
    FE_CANON
    FE64_STORE  rbp + XF_A
    lea         rdi, [rbp + XF_A]
    lea         rsi, [rel fe25519_mod_p]
    call        ha_modinv256                ; (keeps rbp; wipes its own frame)
    lea         rdx, [rbp + XF_A]
    %2_LOAD_U   rbp + XF_C
    %2_MUL      rbp + XF_T, rbp + XF_X2, rbp + XF_C         ; x2 / z2
    %2_PACK     rbp + XF_T
    FE_CANON
    mov         rdi, [rbp + XF_OUT]
    FE64_STORE  rdi
    ; -1 when the result is zero (a small-order point), else 0: OR of the limbs, then neg's CF.
    or          r8, r9
    or          r10, r11
    or          r8, r10
    neg         r8
    sbb         r9d, r9d                    ; -1 unless zero
    not         r9d
    HA_DECLASSIFY r9                        ; (public by design: the peer's point had small order)
    xor         eax, eax
    mov         ecx, XF_END / 8
    mov         rdi, rbp
    rep         stosq                       ; the frame wiped
    mov         eax, r9d
    add         rsp, XF_FRAME
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret
%endmacro

X25519_ROUTINE x25519_v3, FE64, 32
X25519_ROUTINE x25519_v1, FE51, 40

; =============================================================================
; The C ABI.
; =============================================================================

; -----------------------------------------------------------------------------
; int httpasm_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
;   out = X25519(scalar, point) (RFC 7748 5). Returns 0, or -1 when out is all zeros: the peer's
;   point had small order (TLS 1.3 aborts then, RFC 9846 7.4.2); the zeros are written anyway.
; -----------------------------------------------------------------------------
global httpasm_x25519:function (httpasm_x25519.end - httpasm_x25519)
align 16
httpasm_x25519:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         x25519_v1                   ; (tail calls: the version returns to our caller)
.v3:
    jmp         x25519_v3
.end:

; -----------------------------------------------------------------------------
; void httpasm_x25519_public_key(uint8_t out[32], const uint8_t scalar[32])
;   out = X25519(scalar, 9), the public key of a private scalar. Never zero: the base point's
;   order is the large prime, and a clamped scalar is below eight times it. Computed by
;   edwards25519's fixed base (crypto/ed25519.asm's ha_x25519_base_v, see this file's header),
;   not the ladder: the same octets, the same version choice (v3 with BMI2 and ADX; the table
;   scans use AVX2 there, which v3 implies).
; -----------------------------------------------------------------------------
global httpasm_x25519_public_key:function (httpasm_x25519_public_key.end - httpasm_x25519_public_key)
align 16
httpasm_x25519_public_key:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    jmp         ha_x25519_base_v1           ; (tail calls: the version returns to our caller)
.v3:
    jmp         ha_x25519_base_v3
.end:
