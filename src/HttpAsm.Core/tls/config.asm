; =============================================================================
; tls/config.asm - a TLS 1.3 server's configuration (httpasm_tls13_server_config): checked once,
; and what every connection would otherwise work out again made once: the Certificate message
; (RFC 9846 4.5.1) built from the chain, the signature schemes the key makes (4.3.3), the
; library's default groups and suites, and the sizes a connection needs.
;
; The key's schemes:
;   rsaEncryption   rsa_pss_rsae_sha256/384/512, each when the modulus holds RSASSA-PSS's
;                   encoding with a salt of the hash's length (emLen >= 2 hLen + 2, RFC 8017
;                   9.1.1): all three from 1040 bits up
;   id-RSASSA-PSS   rsa_pss_pss_* likewise, only for the hash its parameters bind (any when they
;                   are absent) and only when their salt length, a minimum for a key (RFC 4055
;                   3.1), is at most the hash's length (TLS's salt, 4.3.3)
;   P-256/384/521   ecdsa_secp256r1_sha256 / secp384r1_sha384 / secp521r1_sha512 (4.3.3 binds
;                   each curve to its hash)
;   Ed25519, Ed448  ed25519, ed448
;
; The sizes (output_min): what the largest exchange queues before the caller takes any of it: a
; HelloRetryRequest and its change_cipher_spec, then the ServerHello with the largest share the
; groups make, then the flight (EncryptedExtensions and a CertificateRequest with room for the
; extensions 4c4 and 4f add, the Certificate, a CertificateVerify of the key's largest
; signature, Finished) in records as small as a client's record_size_limit may make them (64:
; 63 octets of content each), with their overhead, and the alert reserve.
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "tls/engine.inc"

extern httpasm_certificate_read
extern httpasm_public_key_read
extern httpasm_private_key_matches
extern ha_tls_kex_share_length

CF_CERT         equ 0                               ; an httpasm_certificate
CF_PUBLIC       equ httpasm_certificate_size        ; the leaf's httpasm_public_key
CF_BUFFER       equ (CF_PUBLIC + httpasm_public_key_size + 15) / 16 * 16   ; the caller's buffer
CF_LENGTH       equ CF_BUFFER + 8                   ; the Certificate message's octets so far
CF_FRAME        equ CF_BUFFER + 16 + 8              ; (six pushes + this: rsp 16-aligned)

CF_EXTENSIONS   equ 64                              ; EncryptedExtensions' and CertificateRequest's
                                                    ; room each (4c4, 4f)

section .rodata
align 2
; The library's group order: post-quantum hybrid first where the client sent its share (Chrome
; and Firefox do), then the classical curves by cost, then the hybrids NIST's curves make, then
; the finite fields (slowest: offered last).
cf_groups:
    dw HTTPASM_TLS_GROUP_X25519MLKEM768, HTTPASM_TLS_GROUP_X25519, HTTPASM_TLS_GROUP_SECP256R1
    dw HTTPASM_TLS_GROUP_X448, HTTPASM_TLS_GROUP_SECP384R1, HTTPASM_TLS_GROUP_SECP521R1
    dw HTTPASM_TLS_GROUP_SECP256R1MLKEM768, HTTPASM_TLS_GROUP_SECP384R1MLKEM1024
    dw HTTPASM_TLS_GROUP_FFDHE2048, HTTPASM_TLS_GROUP_FFDHE3072, HTTPASM_TLS_GROUP_FFDHE4096
    dw HTTPASM_TLS_GROUP_FFDHE6144, HTTPASM_TLS_GROUP_FFDHE8192
CF_GROUPS       equ ($ - cf_groups) / 2
cf_suites:
    dw HTTPASM_TLS_AES_128_GCM_SHA256, HTTPASM_TLS_AES_256_GCM_SHA384
    dw HTTPASM_TLS_CHACHA20_POLY1305_SHA256
CF_SUITES       equ ($ - cf_suites) / 2

section .text

; -----------------------------------------------------------------------------
; int httpasm_tls13_server_config_init(httpasm_tls13_server_config *config,
;                                      const uint8_t *const *chain, const size_t *lengths,
;                                      size_t count, uint8_t *buffer, size_t capacity)
;   Checks a server's configuration and fills its "out" fields (the C header says what each
;   holds). Returns 0; -1 for no key or random source, no chain, a list over its bound, a group
;   or suite the engine lacks, a max_message under 512, or a key that makes no TLS 1.3 signature;
;   -2 for a certificate that does not parse, one over 2^24 - 1 octets, or a leaf whose key is
;   not config->key's; -3 when buffer is too small (config->certificate_length then holds the
;   octets needed). Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_server_config_init:function (httpasm_tls13_server_config_init.end - httpasm_tls13_server_config_init)
align 16
httpasm_tls13_server_config_init:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, CF_FRAME
    mov     rbx, rdi                        ; the configuration
    mov     r12, rsi                        ; the chain
    mov     r13, rdx                        ; its lengths
    mov     r14, rcx                        ; its count
    mov     [rsp + CF_BUFFER], r8        ; (the buffer and its capacity, kept for the end)
    mov     rbp, r9
    mov     eax, -1
    cmp     qword [rbx + httpasm_tls13_server_config.key], 0
    je      .done
    cmp     qword [rbx + httpasm_tls13_server_config.random], 0
    je      .done
    test    r14, r14
    jz      .done
    ; ---- groups: the library's order when none are given; each one the engine has
    mov     ecx, [rbx + httpasm_tls13_server_config.group_count]
    test    ecx, ecx
    jnz     .groups_given
    lea     rsi, [rel cf_groups]
    lea     rdi, [rbx + httpasm_tls13_server_config.groups]
    mov     ecx, CF_GROUPS
    rep     movsw
    mov     dword [rbx + httpasm_tls13_server_config.group_count], CF_GROUPS
    jmp     .suites
.groups_given:
    cmp     ecx, HTTPASM_TLS_GROUPS_MAX
    ja      .done
    xor     edx, edx
.group_check:
    movzx   eax, word [rbx + httpasm_tls13_server_config.groups + rdx * 2]
    call    .group_index                    ; -> rax = its index in cf_groups, or -1
    test    rax, rax
    js      .refused
    inc     edx
    cmp     edx, [rbx + httpasm_tls13_server_config.group_count]
    jb      .group_check
.suites:
    ; ---- suites: likewise
    mov     ecx, [rbx + httpasm_tls13_server_config.suite_count]
    test    ecx, ecx
    jnz     .suites_given
    lea     rsi, [rel cf_suites]
    lea     rdi, [rbx + httpasm_tls13_server_config.suites]
    mov     ecx, CF_SUITES
    rep     movsw
    mov     dword [rbx + httpasm_tls13_server_config.suite_count], CF_SUITES
    jmp     .message
.suites_given:
    cmp     ecx, 4
    ja      .refused
    xor     edx, edx
.suite_check:
    movzx   eax, word [rbx + httpasm_tls13_server_config.suites + rdx * 2]
    sub     eax, HTTPASM_TLS_AES_128_GCM_SHA256
    cmp     eax, HTTPASM_TLS_CHACHA20_POLY1305_SHA256 - HTTPASM_TLS_AES_128_GCM_SHA256
    ja      .refused                        ; (0x1301-0x1303: RFC 9846 9.1's three AEAD suites)
    inc     edx
    cmp     edx, [rbx + httpasm_tls13_server_config.suite_count]
    jb      .suite_check
.message:
    mov     eax, [rbx + httpasm_tls13_server_config.max_message]
    test    eax, eax
    jnz     .message_given
    mov     dword [rbx + httpasm_tls13_server_config.max_message], HTTPASM_TLS_MESSAGE_DEFAULT
    jmp     .chain
.message_given:
    cmp     eax, 512
    jb      .refused
.chain:
    ; ---- the flags: only the ones the engine knows (a caller asking for a behavior this
    ; library lacks is told so, not served without it)
    test    dword [rbx + httpasm_tls13_server_config.flags], ~(HTTPASM_TLS_CLIENT_AUTH_REQUEST | HTTPASM_TLS_CLIENT_AUTH_REQUIRE | HTTPASM_TLS_SERVER_GROUP_ORDER)
    jnz     .refused
    ; ---- the chain: each certificate read; the leaf's key the configuration's
    xor     r15d, r15d                      ; the certificate
    mov     qword [rsp + CF_LENGTH], 4 + 1 + 3      ; the message's octets: header, context, list
.certificate:
    mov     rdx, [r13 + r15 * 8]
    cmp     rdx, 0x00FFFFFF
    ja      .bad_chain                      ; cert_data<1..2^24-1> (4.5.1)
    lea     rdi, [rsp + CF_CERT]
    mov     rsi, [r12 + r15 * 8]
    call    httpasm_certificate_read
    test    eax, eax
    jnz     .bad_chain
    mov     rax, [r13 + r15 * 8]
    add     rax, 3 + 2                      ; the entry: its length, the DER, no extensions
    add     [rsp + CF_LENGTH], rax
    test    r15, r15
    jnz     .next_certificate
    lea     rdi, [rsp + CF_PUBLIC]          ; the leaf: its public key, the private key's half
    mov     rsi, [rsp + CF_CERT + httpasm_certificate.spki]
    mov     rdx, [rsp + CF_CERT + httpasm_certificate.spki_length]
    call    httpasm_public_key_read
    test    eax, eax
    js      .bad_chain
    mov     rdi, [rbx + httpasm_tls13_server_config.key]
    lea     rsi, [rsp + CF_PUBLIC]
    call    httpasm_private_key_matches
    test    eax, eax
    jnz     .bad_chain
.next_certificate:
    inc     r15
    cmp     r15, r14
    jb      .certificate
    ; ---- the Certificate message, built into the buffer
    mov     rax, [rsp + CF_LENGTH]
    lea     rcx, [rax - 4]
    cmp     rcx, 0x00FFFFFF
    ja      .bad_chain                      ; the message's body over a uint24
    mov     [rbx + httpasm_tls13_server_config.certificate_length], rax
    cmp     rax, rbp
    ja      .small                          ; the buffer cannot hold it
    mov     rdi, [rsp + CF_BUFFER]
    mov     [rbx + httpasm_tls13_server_config.certificate], rdi
    mov     edx, ecx                        ; the body's length
    bswap   edx
    mov     dl, HTTPASM_TLS_CERTIFICATE     ; (bswap put the uint24 in octets 1-3: octet 0 the type)
    mov     [rdi], edx
    mov     byte [rdi + 4], 0               ; certificate_request_context: empty (4.5.1)
    lea     edx, [rcx - 4]                  ; certificate_list's length
    bswap   edx
    shr     edx, 8
    mov     [rdi + 5], dx                   ; its three octets, big-endian
    shr     edx, 16
    mov     [rdi + 7], dl
    add     rdi, 8
    xor     r15d, r15d
.entry:
    mov     rcx, [r13 + r15 * 8]
    mov     edx, ecx
    bswap   edx
    shr     edx, 8                          ; cert_data's length: three octets, big-endian
    mov     [rdi], dx
    shr     edx, 16
    mov     [rdi + 2], dl
    add     rdi, 3
    mov     rsi, [r12 + r15 * 8]
    rep     movsb
    mov     word [rdi], 0                   ; extensions: none (4c; status_request and SCTs: 4f)
    add     rdi, 2
    inc     r15
    cmp     r15, r14
    jb      .entry
    ; ---- the schemes the key makes
    mov     rsi, [rbx + httpasm_tls13_server_config.key]
    call    .schemes
    test    rax, rax
    jz      .refused                        ; none: the key cannot sign a TLS 1.3 handshake
    mov     [rbx + httpasm_tls13_server_config.schemes], rax
    ; ---- the sizes a connection needs
    call    .sizes
    xor     eax, eax
    jmp     .done
.small:
    mov     eax, -3
    jmp     .done
.bad_chain:
    mov     eax, -2
    jmp     .done
.refused:
    mov     eax, -1
.done:
    add     rsp, CF_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; .group_index: eax = a NamedGroup -> rax = its index in cf_groups, or -1. A leaf: clobbers rcx,
; rsi, rdi.
.group_index:
    lea     rsi, [rel cf_groups]
    xor     ecx, ecx
.group_scan:
    cmp     ax, [rsi + rcx * 2]
    je      .group_found
    inc     ecx
    cmp     ecx, CF_GROUPS
    jb      .group_scan
    mov     rax, -1
    ret
.group_found:
    mov     eax, ecx
    ret

; .schemes: rsi = the private key -> rax = its HTTPASM_TLS_SCHEME_BIT_* (the file's header has
; the rules). A leaf: clobbers rcx, rdx, rdi, r8, r9.
.schemes:
    xor     eax, eax
    mov     ecx, [rsi + httpasm_private_key.kind]
    cmp     ecx, HTTPASM_KEY_P256
    je      .p256
    cmp     ecx, HTTPASM_KEY_P384
    je      .p384
    cmp     ecx, HTTPASM_KEY_P521
    je      .p521
    cmp     ecx, HTTPASM_KEY_ED25519
    je      .ed25519
    cmp     ecx, HTTPASM_KEY_ED448
    je      .ed448
    xor     r9d, r9d                        ; the first bit: rsae's 0, pss's 3
    cmp     ecx, HTTPASM_KEY_RSA
    je      .rsa
    cmp     ecx, HTTPASM_KEY_RSA_PSS
    jne     .schemes_done
    mov     r9d, HTTPASM_TLS_SCHEME_BIT_RSA_PSS_PSS_SHA256
.rsa:
    ; emLen = ceil((modBits - 1) / 8) octets must hold 2 hLen + 2 (a salt of hLen)
    mov     edx, [rsi + httpasm_private_key.bits]
    add     edx, 6
    shr     edx, 3                          ; emLen
    xor     edi, edi                        ; the hash's place: 0, 1, 2
.rsa_hash:
    mov     r8d, edi
    shl     r8d, 4
    add     r8d, 32                         ; hLen: 32, 48, 64 (SHA-256, -384, -512)
    lea     ecx, [r8 * 2 + 2]
    cmp     edx, ecx
    jb      .rsa_next                       ; too short for this hash's encoding
    cmp     dword [rsi + httpasm_private_key.kind], HTTPASM_KEY_RSA_PSS
    jne     .rsa_take
    mov     ecx, [rsi + httpasm_private_key.pss_hash]
    test    ecx, ecx
    jz      .pss_salt                       ; any hash
    lea     ecx, [rcx - HTTPASM_HASH_SHA256]
    cmp     ecx, edi
    jne     .rsa_next                       ; bound to another hash
.pss_salt:
    mov     ecx, [rsi + httpasm_private_key.pss_salt]
    cmp     ecx, r8d
    ja      .rsa_next                       ; a minimum salt over TLS's
.rsa_take:
    lea     ecx, [r9 + rdi]
    bts     rax, rcx
.rsa_next:
    inc     edi
    cmp     edi, 3
    jb      .rsa_hash
    ret
.p256:
    mov     eax, 1 << HTTPASM_TLS_SCHEME_BIT_ECDSA_SECP256R1_SHA256
    ret
.p384:
    mov     eax, 1 << HTTPASM_TLS_SCHEME_BIT_ECDSA_SECP384R1_SHA384
    ret
.p521:
    mov     eax, 1 << HTTPASM_TLS_SCHEME_BIT_ECDSA_SECP521R1_SHA512
    ret
.ed25519:
    mov     eax, 1 << HTTPASM_TLS_SCHEME_BIT_ED25519
    ret
.ed448:
    mov     eax, 1 << HTTPASM_TLS_SCHEME_BIT_ED448
.schemes_done:
    ret

; .sizes: the configuration's output_min and memory (the file's header says what output_min
; holds). Calls leaves only: clobbers rax, rcx, rdx, rsi, rdi, r8, r9, r10.
.sizes:
    ; the largest share the groups make
    xor     r8d, r8d
    xor     edx, edx
.share:
    movzx   edi, word [rbx + httpasm_tls13_server_config.groups + rdx * 2]
    call    ha_tls_kex_share_length         ; (the table tls/server.asm sizes a ServerHello from)
    cmp     r8d, eax
    cmovb   r8d, eax
    inc     edx
    cmp     edx, [rbx + httpasm_tls13_server_config.group_count]
    jb      .share
    ; the key's largest signature: an RSA modulus' octets, or the curves' DER and EdDSA's
    mov     rsi, [rbx + httpasm_tls13_server_config.key]
    mov     ecx, [rsi + httpasm_private_key.kind]
    mov     r9d, 72                         ; P-256: 30 46 (02 21 00 r) (02 21 00 s)
    cmp     ecx, HTTPASM_KEY_P256
    je      .signature
    mov     r9d, 104                        ; P-384
    cmp     ecx, HTTPASM_KEY_P384
    je      .signature
    mov     r9d, 141                        ; P-521: 30 81 8a ...
    cmp     ecx, HTTPASM_KEY_P521
    je      .signature
    mov     r9d, 64
    cmp     ecx, HTTPASM_KEY_ED25519
    je      .signature
    mov     r9d, 114
    cmp     ecx, HTTPASM_KEY_ED448
    je      .signature
    mov     r9d, [rsi + httpasm_private_key.bits]
    add     r9d, 7
    shr     r9d, 3
.signature:
    ; the flight's plaintext: EncryptedExtensions, CertificateRequest, Certificate,
    ; CertificateVerify, Finished
    mov     rax, [rbx + httpasm_tls13_server_config.certificate_length]
    add     rax, 4 + 2 + CF_EXTENSIONS      ; EncryptedExtensions
    add     rax, 4 + 1 + 2 + CF_EXTENSIONS  ; CertificateRequest
    lea     rax, [rax + r9 + 4 + 2 + 2]     ; CertificateVerify
    add     rax, 4 + 48                     ; Finished
    ; its records' overhead (header, type, tag) at the smallest records a client may ask for: a
    ; record_size_limit of 64 (RFC 8449 4) leaves 63 octets of content to a record, so any valid
    ; client's flight fits
    mov     r10, rax
    lea     rax, [rax + 62]
    xor     edx, edx
    mov     ecx, 63
    div     rcx                             ; the records
    imul    rax, rax, HTTPASM_TLS_RECORD_HEADER + 1 + HTTPASM_TLS_TAG
    add     rax, r10
    ; then the HelloRetryRequest's record (93) and change_cipher_spec's (6), the ServerHello's
    ; (95 and the share), the alert reserve and a KeyUpdate's record (27), rounded up
    lea     rax, [rax + r8 + 93 + 6 + 95 + TE_ALERT_RESERVE + 27 + 63]
    and     rax, -64
    mov     [rbx + httpasm_tls13_server_config.output_min], rax
    ; memory: the reassembly span (max_message), with client authentication the peer-chain span
    ; (max_message again: server_init's split), and output_min, rounded to 16
    mov     ecx, [rbx + httpasm_tls13_server_config.max_message]
    add     rax, rcx
    test    dword [rbx + httpasm_tls13_server_config.flags], HTTPASM_TLS_CLIENT_AUTH_REQUEST | HTTPASM_TLS_CLIENT_AUTH_REQUIRE
    jz      .rounded
    add     rax, rcx
.rounded:
    add     rax, 15
    and     rax, -16
    mov     [rbx + httpasm_tls13_server_config.memory], rax
    ret
.end:
