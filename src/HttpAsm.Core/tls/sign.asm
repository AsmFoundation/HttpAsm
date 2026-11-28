; =============================================================================
; tls/sign.asm - the server's CertificateVerify signature (RFC 9846 4.5.2) in each scheme a
; server's key makes: over 64 octets of 0x20, the context string "TLS 1.3, server
; CertificateVerify", one 0 octet and the transcript's hash (Transcript-Hash(ClientHello ..
; Certificate)), under .scheme, which the handshake chose from the client's list among the key's
; (httpasm_tls13_server_config.schemes).
;
;   rsa_pss_rsae_sha256/384/512, rsa_pss_pss_*   RSASSA-PSS over the content's hash, MGF1 of
;                                                the same hash, a salt of the hash's length
;                                                (4.3.3), the modulus' octets long
;   ecdsa_secp256r1_sha256 .. secp521r1_sha512   ECDSA over the content's hash, hedged with
;                                                random octets (RFC 6979 3.6), sent as DER's
;                                                ECDSA-Sig-Value { r INTEGER, s INTEGER }
;   ed25519, ed448                               EdDSA over the content itself (pure EdDSA,
;                                                Ed448's context empty: RFC 8032, 4.3.3)
;
; The private key is the configuration's (httpasm_private_key: the prepared key of its kind in
; .secret); the signers are constant time in it. The randomness (the salt, the hedge) is drawn
; from the configuration's source after the key share's (httpasm_tls13_receive's order). The
; frame's copies (digest, salt, hedge, the raw ECDSA signature) are wiped before the return.
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "tls/engine.inc"

extern ha_tls_draw
extern httpasm_sha512
extern httpasm_rsa_sign_pss
extern httpasm_p256_sign
extern httpasm_p384_sign
extern httpasm_p521_sign
extern httpasm_ed25519_sign
extern httpasm_ed448_sign

SG_CONTENT      equ 0                       ; 64 spaces, the context string, 0, the hash: 146 at most
SG_DIGEST       equ 160                     ; the content's hash (64 at most)
SG_RANDOM       equ 224                     ; the salt or the hedge (66 at most)
SG_RAW          equ 304                     ; ECDSA's r || s (132 at most)
SG_DER          equ 448                     ; the two INTEGERs before their SEQUENCE (138 at most)
SG_WIPE         equ 592                     ; the octets wiped
SG_FRAME        equ 608                     ; (five pushes + 608: rsp 16-aligned at the calls)
SG_FIXED        equ 98                      ; the content before the hash: 64 + 33 + 1

section .rodata
sg_context:     db "TLS 1.3, server CertificateVerify", 0

section .text

; -----------------------------------------------------------------------------
; ha_tls_sign: rbx = the connection, rdi = out (1024 octets at most: an 8192-bit modulus), rsi =
;   the transcript's hash (.hash_length octets) -> rax = the signature's octets, or minus an
;   alert: internal_error when the random source or the signer fails. Clobbers the caller-saved
;   registers; rbx kept.
; -----------------------------------------------------------------------------
global ha_tls_sign:function hidden (ha_tls_sign.end - ha_tls_sign)
align 16
ha_tls_sign:
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, SG_FRAME
    mov     r12, rdi                        ; out
    mov     rax, [rbx + httpasm_tls13_connection.config]
    mov     r13, [rax + httpasm_tls13_server_config.key]
    ; the content (4.5.2)
    mov     rdx, rsi
    lea     rdi, [rsp + SG_CONTENT]
    mov     al, 0x20
    mov     ecx, 64
    rep     stosb
    lea     rsi, [rel sg_context]
    mov     ecx, 34                         ; the string and its 0 octet
    rep     movsb
    mov     rsi, rdx
    movzx   ecx, byte [rbx + httpasm_tls13_connection.hash_length]
    rep     movsb
    movzx   r14d, byte [rbx + httpasm_tls13_connection.hash_length]
    add     r14d, SG_FIXED                  ; the content's octets
    movzx   eax, word [rbx + httpasm_tls13_connection.scheme]
    cmp     eax, HTTPASM_TLS_SCHEME_ED25519
    je      .ed25519
    cmp     eax, HTTPASM_TLS_SCHEME_ED448
    je      .ed448
    cmp     eax, HTTPASM_TLS_SCHEME_ECDSA_SECP256R1_SHA256
    je      .p256
    cmp     eax, HTTPASM_TLS_SCHEME_ECDSA_SECP384R1_SHA384
    je      .p384
    cmp     eax, HTTPASM_TLS_SCHEME_ECDSA_SECP521R1_SHA512
    je      .p521
    ; RSASSA-PSS: rsae 0x0804-0x0806 and pss 0x0809-0x080B take their hash by the last digit
    mov     ebp, HTTPASM_HASH_SHA256
    mov     r15d, 32
    cmp     eax, HTTPASM_TLS_SCHEME_RSA_PSS_RSAE_SHA256
    je      .pss
    cmp     eax, HTTPASM_TLS_SCHEME_RSA_PSS_PSS_SHA256
    je      .pss
    mov     ebp, HTTPASM_HASH_SHA384
    mov     r15d, 48
    cmp     eax, HTTPASM_TLS_SCHEME_RSA_PSS_RSAE_SHA384
    je      .pss
    cmp     eax, HTTPASM_TLS_SCHEME_RSA_PSS_PSS_SHA384
    je      .pss
    mov     ebp, HTTPASM_HASH_SHA512
    mov     r15d, 64
    cmp     eax, HTTPASM_TLS_SCHEME_RSA_PSS_RSAE_SHA512
    je      .pss
    cmp     eax, HTTPASM_TLS_SCHEME_RSA_PSS_PSS_SHA512
    je      .pss
    jmp     .internal                       ; (never: the scheme came from the key's own)

.pss:
    ; ebp = the hash, r15 = its octets (the salt's too)
    lea     rdi, [rsp + SG_CONTENT]
    mov     rsi, r14
    lea     rdx, [rsp + SG_DIGEST]
    call    .hash
    lea     rdi, [rsp + SG_RANDOM]
    mov     esi, r15d
    call    ha_tls_draw
    test    eax, eax
    jnz     .answer
    ; sign_pss(key, hash, digest, salt, salt_length, out, the modulus' octets)
    mov     eax, [r13 + httpasm_private_key.bits]
    add     eax, 7
    shr     eax, 3
    mov     r14d, eax                       ; the signature's octets: the modulus'
    sub     rsp, 16                         ; the 7th argument's slot (alignment kept)
    mov     [rsp], r14
    lea     rdi, [r13 + httpasm_private_key.secret]
    mov     esi, ebp
    lea     rdx, [rsp + 16 + SG_DIGEST]
    lea     rcx, [rsp + 16 + SG_RANDOM]
    mov     r8d, r15d
    mov     r9, r12
    call    httpasm_rsa_sign_pss
    add     rsp, 16
    test    eax, eax
    jnz     .internal
    mov     eax, r14d
    jmp     .answer

.p256:
    lea     rdi, [rsp + SG_CONTENT]
    mov     rsi, r14
    lea     rdx, [rsp + SG_DIGEST]
    call    httpasm_sha256
    mov     r15d, 32                        ; the hedge's octets, and the scalar's
    lea     rdi, [rsp + SG_RANDOM]
    mov     esi, r15d
    call    ha_tls_draw
    test    eax, eax
    jnz     .answer
    lea     rdi, [rsp + SG_RAW]             ; sign(raw, scalar, digest, 32, hedge)
    lea     rsi, [r13 + httpasm_private_key.secret]
    lea     rdx, [rsp + SG_DIGEST]
    mov     ecx, 32
    lea     r8, [rsp + SG_RANDOM]
    call    httpasm_p256_sign
    jmp     .ecdsa

.p384:
    lea     rdi, [rsp + SG_CONTENT]
    mov     rsi, r14
    lea     rdx, [rsp + SG_DIGEST]
    call    httpasm_sha384
    mov     r15d, 48
    lea     rdi, [rsp + SG_RANDOM]
    mov     esi, r15d
    call    ha_tls_draw
    test    eax, eax
    jnz     .answer
    lea     rdi, [rsp + SG_RAW]
    lea     rsi, [r13 + httpasm_private_key.secret]
    lea     rdx, [rsp + SG_DIGEST]
    mov     ecx, 48
    lea     r8, [rsp + SG_RANDOM]
    call    httpasm_p384_sign
    jmp     .ecdsa

.p521:
    lea     rdi, [rsp + SG_CONTENT]
    mov     rsi, r14
    lea     rdx, [rsp + SG_DIGEST]
    call    httpasm_sha512
    mov     r15d, 66
    lea     rdi, [rsp + SG_RANDOM]
    mov     esi, r15d
    call    ha_tls_draw
    test    eax, eax
    jnz     .answer
    lea     rdi, [rsp + SG_RAW]
    lea     rsi, [r13 + httpasm_private_key.secret]
    lea     rdx, [rsp + SG_DIGEST]
    mov     ecx, 64                         ; SHA-512's whole digest (521 bits taken: all of it)
    lea     r8, [rsp + SG_RANDOM]
    call    httpasm_p521_sign

.ecdsa:
    ; eax = the signer's answer; r15 = the scalar's octets (r's and s's); the raw r || s as DER
    test    eax, eax
    jnz     .internal
    lea     rdi, [rsp + SG_DER]
    lea     rsi, [rsp + SG_RAW]
    mov     ecx, r15d
    call    .integer
    mov     rbp, rax                        ; r's INTEGER
    lea     rdi, [rsp + SG_DER + rbp]
    lea     rsi, [rsp + SG_RAW + r15]
    mov     ecx, r15d
    call    .integer
    add     rbp, rax                        ; the SEQUENCE's content
    mov     rdi, r12
    mov     byte [rdi], 0x30
    cmp     ebp, 128
    jae     .long
    mov     [rdi + 1], bpl
    add     rdi, 2
    lea     r14, [rbp + 2]
    jmp     .der
.long:
    mov     byte [rdi + 1], 0x81            ; (138 at most: one length octet)
    mov     [rdi + 2], bpl
    add     rdi, 3
    lea     r14, [rbp + 3]
.der:
    lea     rsi, [rsp + SG_DER]
    mov     rcx, rbp
    rep     movsb
    mov     rax, r14
    jmp     .answer

.ed25519:
    mov     rdi, r12                        ; sign(out, key, content, length)
    lea     rsi, [r13 + httpasm_private_key.secret]
    lea     rdx, [rsp + SG_CONTENT]
    mov     rcx, r14
    call    httpasm_ed25519_sign
    mov     eax, 64
    jmp     .answer

.ed448:
    mov     rdi, r12                        ; sign(out, key, content, length, no context)
    lea     rsi, [r13 + httpasm_private_key.secret]
    lea     rdx, [rsp + SG_CONTENT]
    mov     rcx, r14
    xor     r8d, r8d
    xor     r9d, r9d
    call    httpasm_ed448_sign
    test    eax, eax
    jnz     .internal
    mov     eax, 114
    jmp     .answer

.internal:
    mov     rax, -HTTPASM_TLS_ALERT_INTERNAL_ERROR
.answer:
    movsxd  rax, eax                        ; (lengths are positive and fit; alerts negative)
    mov     r8, rax
    lea     rdi, [rsp]                      ; the frame's copies wiped
    xor     eax, eax
    mov     ecx, SG_WIPE
    rep     stosb
    mov     rax, r8
    add     rsp, SG_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    ret

; .hash: rdi = data, rsi = octets, rdx = out, ebp = HTTPASM_HASH_SHA256/384/512: the digest.
; (Called from the aligned body, it jumps on: the hash is entered as if called from there.)
.hash:
    cmp     ebp, HTTPASM_HASH_SHA384
    je      .sha384
    cmp     ebp, HTTPASM_HASH_SHA512
    je      .sha512
    jmp     httpasm_sha256
.sha384:
    jmp     httpasm_sha384
.sha512:
    jmp     httpasm_sha512

; .integer: rdi = out, rsi = a big-endian value, ecx = its octets: DER's INTEGER of it (02, the
; length, the octets without leading zeros, one kept, and a 0 first when the top bit is set: a
; non-negative INTEGER, X.690 8.3) -> rax = the octets written. r and s are public (they are
; the signature): branching on them is fine. A leaf: clobbers rcx, rdx, rsi, rdi, r8.
.integer:
    mov     edx, ecx
.skip:
    cmp     edx, 1
    jbe     .kept
    cmp     byte [rsi], 0
    jne     .kept
    inc     rsi
    dec     edx
    jmp     .skip
.kept:
    mov     byte [rdi], 0x02
    xor     r8d, r8d
    cmp     byte [rsi], 0x80
    setae   r8b                             ; a 0 octet first when the top bit is set
    lea     eax, [rdx + r8]
    mov     [rdi + 1], al
    add     rdi, 2
    test    r8d, r8d
    jz      .value
    mov     byte [rdi], 0
    inc     rdi
.value:
    mov     ecx, edx
    rep     movsb
    add     eax, 2
    ret
.end:
