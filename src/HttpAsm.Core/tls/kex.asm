; =============================================================================
; tls/kex.asm - TLS 1.3's key exchange, the server's side (RFC 9846 4.3.8, 7.4; RFC 7919; RFC
; 10024): the answer to a client's key share in each group the engine negotiates, and the
; shared secret the key schedule takes as its (EC)DHE input.
;
;   group               client share                 our share                    secret
;   x25519              32                           32                           32
;   x448                56                           56                           56
;   secp256r1           65 (04 || x || y)            65                           32 (x of dQ)
;   secp384r1           97                           97                           48
;   secp521r1           133                          133                          66
;   ffdhe2048..8192     p's size, left-padded        p's size                     p's size (7.4.1)
;   X25519MLKEM768      ek 1184 || x25519 32         ct 1088 || x25519 32         ML-KEM || X25519 (64)
;   SecP256r1MLKEM768   P-256 65 || ek 1184          P-256 65 || ct 1088          ECDH || ML-KEM (64)
;   SecP384r1MLKEM1024  P-384 97 || ek 1568          P-384 97 || ct 1568          ECDH || ML-KEM (80)
;
; Every check of the peer's share is the primitive's own: X25519 and X448 refuse an all-zero
; secret (7.4.2: a small-order point), the NIST curves' ECDH a point not on the curve or not
; uncompressed (4.3.8.2), FFDHE a value outside 1 < Y < p - 1 (RFC 7919 5.1), ML-KEM an
; encapsulation key failing FIPS 203 7.2's modulus check (RFC 10024 4.2): each is
; illegal_parameter, as is a share of the wrong length. The private parts are drawn from the
; configuration's random source in the order our share carries them (an ECDH scalar drawn again
; while it is out of range, which happens about once in 2^32 draws at P-256), live in this
; frame only, and are wiped before the return, whatever the outcome.
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "tls/engine.inc"

extern ha_tls_draw
extern httpasm_x25519
extern httpasm_x25519_public_key
extern httpasm_x448
extern httpasm_x448_public_key
extern httpasm_p256_public_key
extern httpasm_p256_ecdh
extern httpasm_p384_public_key
extern httpasm_p384_ecdh
extern httpasm_p521_public_key
extern httpasm_p521_ecdh
extern httpasm_ffdhe_size
extern httpasm_ffdhe_public_key
extern httpasm_ffdhe_shared
extern httpasm_mlkem768_encaps
extern httpasm_mlkem1024_encaps

KX_PRIVATE      equ 0                       ; the ECDH scalar, or FFDHE's exponent (66 at most)
KX_MESSAGE      equ 80                      ; ML-KEM's m (32)
KX_WIPE         equ 112                     ; the octets wiped: the private parts' slots
KX_FRAME        equ 128                     ; (five pushes + 128: rsp 16-aligned at the calls);
                                            ; its last 8 octets hold the group (public)
KX_TRIES        equ 8                       ; ECDH scalars drawn at most (a failure: 2^-256 at P-256)

section .text

; KX_ECDH public_fn, ecdh_fn, scalar, point, share_at, secret_at, top_mask: our ECDH half: a
; scalar drawn (its first octet masked by top_mask: P-521's 66 octets carry 521 bits) until
; public_fn takes it, our point written at r14 + share_at, the secret (ecdh_fn against the
; client's point at r12) at r15 + secret_at. Jumps to .internal or .illegal; rbp counts the tries.
%macro KX_ECDH 7
    mov     ebp, KX_TRIES
%%draw:
    lea     rdi, [rsp + KX_PRIVATE]
    mov     esi, %3
    call    ha_tls_draw
    test    eax, eax
    jnz     .done
%if %7 != 0xFF
    and     byte [rsp + KX_PRIVATE], %7
%endif
    lea     rdi, [r14 + %5]
    lea     rsi, [rsp + KX_PRIVATE]
    call    %1
    test    eax, eax
    jz      %%drawn
    dec     ebp
    jnz     %%draw
    jmp     .internal                       ; (never: KX_TRIES scalars out of range)
%%drawn:
    lea     rdi, [r15 + %6]
    lea     rsi, [rsp + KX_PRIVATE]
    mov     rdx, r12
    call    %2
    test    eax, eax
    jnz     .illegal                        ; not a point of the curve (4.3.8.2)
%endmacro

; KX_KEM encaps_fn, ek_at, ct_at, secret_at: ML-KEM's half: m drawn, encapsulated to the client's
; key at r12 + ek_at, the ciphertext written at r14 + ct_at and the secret at r15 + secret_at.
%macro KX_KEM 4
    lea     rdi, [rsp + KX_MESSAGE]
    mov     esi, 32
    call    ha_tls_draw
    test    eax, eax
    jnz     .done
    lea     rdi, [r14 + %3]
    lea     rsi, [r15 + %4]
    lea     rdx, [r12 + %2]
    lea     rcx, [rsp + KX_MESSAGE]
    call    %1
    test    eax, eax
    jnz     .illegal                        ; the modulus check failed (RFC 10024 4.2)
%endmacro

; -----------------------------------------------------------------------------
; ha_tls_kex_server: rbx = the connection (its random source), edi = the group, rsi = the
;   client's key_exchange, rdx = its octets, rcx = where our key_exchange goes (1665 octets at
;   most: SecP384r1MLKEM1024's), r8 = where the shared secret goes (1024 at most: ffdhe8192's)
;   -> rax = our share's octets | the secret's octets << 32; or minus an alert: illegal_parameter
;   for a share the group refuses, internal_error when the random source fails (or for a group
;   the engine lacks, which the configuration never offers). Clobbers the caller-saved
;   registers; rbx kept.
; -----------------------------------------------------------------------------
global ha_tls_kex_server:function hidden (ha_tls_kex_server.end - ha_tls_kex_server)
align 16
ha_tls_kex_server:
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, KX_FRAME
    mov     r12, rsi                        ; the client's share
    mov     r13, rdx
    mov     r14, rcx                        ; ours
    mov     r15, r8                         ; the secret
    mov     [rsp + KX_FRAME - 8], edi       ; the group (kept for FFDHE's calls)
    cmp     edi, HTTPASM_TLS_GROUP_X25519
    je      .x25519
    cmp     edi, HTTPASM_TLS_GROUP_X25519MLKEM768
    je      .x25519mlkem768
    cmp     edi, HTTPASM_TLS_GROUP_SECP256R1
    je      .p256
    cmp     edi, HTTPASM_TLS_GROUP_X448
    je      .x448
    cmp     edi, HTTPASM_TLS_GROUP_SECP384R1
    je      .p384
    cmp     edi, HTTPASM_TLS_GROUP_SECP521R1
    je      .p521
    cmp     edi, HTTPASM_TLS_GROUP_SECP256R1MLKEM768
    je      .p256mlkem768
    cmp     edi, HTTPASM_TLS_GROUP_SECP384R1MLKEM1024
    je      .p384mlkem1024
    lea     eax, [rdi - HTTPASM_TLS_GROUP_FFDHE2048]
    cmp     eax, HTTPASM_TLS_GROUP_FFDHE8192 - HTTPASM_TLS_GROUP_FFDHE2048
    jbe     .ffdhe
    jmp     .internal

.x25519:
    cmp     r13, 32
    jne     .illegal
    lea     rdi, [rsp + KX_PRIVATE]
    mov     esi, 32
    call    ha_tls_draw                     ; (any 32 octets: X25519 clamps them)
    test    eax, eax
    jnz     .done
    mov     rdi, r14
    lea     rsi, [rsp + KX_PRIVATE]
    call    httpasm_x25519_public_key
    mov     rdi, r15
    lea     rsi, [rsp + KX_PRIVATE]
    mov     rdx, r12
    call    httpasm_x25519
    test    eax, eax
    jnz     .illegal                        ; an all-zero secret (7.4.2)
    mov     rax, (32 << 32) | 32
    jmp     .done

.x448:
    cmp     r13, 56
    jne     .illegal
    lea     rdi, [rsp + KX_PRIVATE]
    mov     esi, 56
    call    ha_tls_draw
    test    eax, eax
    jnz     .done
    mov     rdi, r14
    lea     rsi, [rsp + KX_PRIVATE]
    call    httpasm_x448_public_key
    mov     rdi, r15
    lea     rsi, [rsp + KX_PRIVATE]
    mov     rdx, r12
    call    httpasm_x448
    test    eax, eax
    jnz     .illegal
    mov     rax, (56 << 32) | 56
    jmp     .done

.p256:
    cmp     r13, 65
    jne     .illegal
    KX_ECDH httpasm_p256_public_key, httpasm_p256_ecdh, 32, 65, 0, 0, 0xFF
    mov     rax, (32 << 32) | 65
    jmp     .done

.p384:
    cmp     r13, 97
    jne     .illegal
    KX_ECDH httpasm_p384_public_key, httpasm_p384_ecdh, 48, 97, 0, 0, 0xFF
    mov     rax, (48 << 32) | 97
    jmp     .done

.p521:
    cmp     r13, 133
    jne     .illegal
    KX_ECDH httpasm_p521_public_key, httpasm_p521_ecdh, 66, 133, 0, 0, 0x01
    mov     rax, (66 << 32) | 133
    jmp     .done

.ffdhe:
    ; the share is p's size exactly (4.3.8.1: left-padded); the exponent RFC 7919 Appendix A's
    ; advised length: 29, 35, 41, 47, 50 octets for the five groups
    call    httpasm_ffdhe_size              ; (edi = the group)
    cmp     r13, rax
    jne     .illegal
    mov     r13, rax                        ; p's size: our share's and the secret's
    mov     edi, [rsp + KX_FRAME - 8]
    lea     ecx, [rdi - HTTPASM_TLS_GROUP_FFDHE2048]
    lea     rdx, [rel kx_ffdhe_exponent]
    movzx   ebp, byte [rdx + rcx]
    lea     rdi, [rsp + KX_PRIVATE]
    mov     esi, ebp
    call    ha_tls_draw
    test    eax, eax
    jnz     .done
    mov     edi, [rsp + KX_FRAME - 8]       ; public_key(group, out, x, x_length)
    mov     rsi, r14
    lea     rdx, [rsp + KX_PRIVATE]
    mov     ecx, ebp
    call    httpasm_ffdhe_public_key
    test    eax, eax
    jnz     .internal
    mov     edi, [rsp + KX_FRAME - 8]       ; shared(group, out, x, x_length, peer)
    mov     rsi, r15
    lea     rdx, [rsp + KX_PRIVATE]
    mov     ecx, ebp
    mov     r8, r12
    call    httpasm_ffdhe_shared
    test    eax, eax
    jnz     .illegal                        ; Y outside 1 < Y < p - 1 (RFC 7919 5.1)
    mov     rax, r13
    shl     rax, 32
    or      rax, r13
    jmp     .done

.x25519mlkem768:
    ; ML-KEM first in this group's shares and secret (RFC 10024 4.1, 4.3: its historical order)
    cmp     r13, 1184 + 32
    jne     .illegal
    KX_KEM  httpasm_mlkem768_encaps, 0, 0, 0
    lea     rdi, [rsp + KX_PRIVATE]
    mov     esi, 32
    call    ha_tls_draw
    test    eax, eax
    jnz     .done
    lea     rdi, [r14 + 1088]
    lea     rsi, [rsp + KX_PRIVATE]
    call    httpasm_x25519_public_key
    lea     rdi, [r15 + 32]
    lea     rsi, [rsp + KX_PRIVATE]
    lea     rdx, [r12 + 1184]
    call    httpasm_x25519
    test    eax, eax
    jnz     .illegal
    mov     rax, (64 << 32) | (1088 + 32)
    jmp     .done

.p256mlkem768:
    cmp     r13, 65 + 1184
    jne     .illegal
    KX_ECDH httpasm_p256_public_key, httpasm_p256_ecdh, 32, 65, 0, 0, 0xFF
    KX_KEM  httpasm_mlkem768_encaps, 65, 65, 32
    mov     rax, (64 << 32) | (65 + 1088)
    jmp     .done

.p384mlkem1024:
    cmp     r13, 97 + 1568
    jne     .illegal
    KX_ECDH httpasm_p384_public_key, httpasm_p384_ecdh, 48, 97, 0, 0, 0xFF
    KX_KEM  httpasm_mlkem1024_encaps, 97, 97, 48
    mov     rax, (80 << 32) | (97 + 1568)
    jmp     .done

.illegal:
    mov     rax, -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER
    jmp     .done
.internal:
    mov     rax, -HTTPASM_TLS_ALERT_INTERNAL_ERROR
.done:
    ; the private parts wiped, whatever the outcome (rax kept)
    mov     r8, rax
    lea     rdi, [rsp + KX_PRIVATE]
    xor     eax, eax
    mov     ecx, KX_WIPE
    rep     stosb
    mov     rax, r8
    add     rsp, KX_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    ret
.end:

; -----------------------------------------------------------------------------
; ha_tls_kex_share_length: edi = a group -> eax = the octets of our key_exchange in it (the
;   file's header's table), 0 for a group the engine lacks. The one table the ServerHello's room
;   (tls/server.asm) and a configuration's output_min (tls/config.asm) are sized from, so the two
;   cannot disagree. A leaf: clobbers rax, rcx.
; -----------------------------------------------------------------------------
global ha_tls_kex_share_length:function hidden (ha_tls_kex_share_length.end - ha_tls_kex_share_length)
align 16
ha_tls_kex_share_length:
    lea     rcx, [rel kx_shares]
.next:
    movzx   eax, word [rcx]
    test    eax, eax
    jz      .none
    cmp     eax, edi
    je      .found
    add     rcx, 4
    jmp     .next
.found:
    movzx   eax, word [rcx + 2]
    ret
.none:
    xor     eax, eax
    ret
.end:

section .rodata
; RFC 7919 Appendix A's advised exponent lengths, in octets, for ffdhe2048 .. ffdhe8192 (225,
; 275, 325, 375 and 400 bits, rounded up): the least httpasm_ffdhe_* take, and its cost follows it.
kx_ffdhe_exponent:  db 29, 35, 41, 47, 50
align 2
; (group, our key_exchange's octets) for every group, then 0
kx_shares:
    dw HTTPASM_TLS_GROUP_X25519, 32
    dw HTTPASM_TLS_GROUP_X448, 56
    dw HTTPASM_TLS_GROUP_SECP256R1, 65
    dw HTTPASM_TLS_GROUP_SECP384R1, 97
    dw HTTPASM_TLS_GROUP_SECP521R1, 133
    dw HTTPASM_TLS_GROUP_FFDHE2048, 256
    dw HTTPASM_TLS_GROUP_FFDHE3072, 384
    dw HTTPASM_TLS_GROUP_FFDHE4096, 512
    dw HTTPASM_TLS_GROUP_FFDHE6144, 768
    dw HTTPASM_TLS_GROUP_FFDHE8192, 1024
    dw HTTPASM_TLS_GROUP_X25519MLKEM768, 1088 + 32
    dw HTTPASM_TLS_GROUP_SECP256R1MLKEM768, 65 + 1088
    dw HTTPASM_TLS_GROUP_SECP384R1MLKEM1024, 97 + 1568
    dw 0, 0
