; =============================================================================
; tls/sign.asm - the CertificateVerify (RFC 9846 4.5.2) both ways: the server's signature in each
; scheme a server's key makes, and the client's verified against its certificate (client
; authentication, 4c4: ha_tls_peer_leaf, ha_tls_verify, and the CertificateRequest they answer,
; ha_tls_request). The server signs over 64 octets of 0x20, the context string "TLS 1.3, server
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
extern ha_tls_transcript_hash
extern httpasm_sha512
extern httpasm_rsa_sign_pss
extern httpasm_p256_sign
extern httpasm_p384_sign
extern httpasm_p521_sign
extern httpasm_ed25519_sign
extern httpasm_ed448_sign
extern httpasm_rsa_verify_pss
extern httpasm_p256_verify
extern httpasm_p384_verify
extern httpasm_p521_verify
extern httpasm_ed25519_verify
extern httpasm_ed448_verify
extern httpasm_certificate_read
extern httpasm_public_key_read
extern httpasm_tls13_certificate_entry
extern httpasm_tls13_certificate_verify_read

SG_CONTENT      equ 0                       ; 64 spaces, the context string, 0, the hash: 146 at most
SG_DIGEST       equ 160                     ; the content's hash (64 at most)
SG_RANDOM       equ 224                     ; the salt or the hedge (66 at most)
SG_RAW          equ 304                     ; ECDSA's r || s (132 at most)
SG_DER          equ 448                     ; the two INTEGERs before their SEQUENCE (138 at most)
SG_WIPE         equ 592                     ; the octets wiped
SG_FRAME        equ 608                     ; (five pushes + 608: rsp 16-aligned at the calls)
SG_FIXED        equ 98                      ; the content before the hash: 64 + 33 + 1

; ha_tls_peer_leaf's frame
PL_EXT          equ 0                       ; an entry's extensions (httpasm_tls_extensions)
PL_CERT         equ PL_EXT + httpasm_tls_extensions_size      ; an entry's certificate
PL_KEY          equ (PL_CERT + httpasm_certificate_size + 15) / 16 * 16   ; the leaf's key
PL_DATA         equ PL_KEY + httpasm_public_key_size          ; the entry's cert_data
PL_DATA_LENGTH  equ PL_DATA + 8
PL_FRAME        equ (PL_DATA_LENGTH + 8 + 15) / 16 * 16       ; (five pushes + this: 16-aligned)

; ha_tls_verify's frame (under a page: one subtraction, touched from its bottom up)
VF_EXT          equ 0                       ; the leaf's entry's extensions (walked again)
VF_CERT         equ VF_EXT + httpasm_tls_extensions_size      ; the leaf
VF_KEY          equ (VF_CERT + httpasm_certificate_size + 15) / 16 * 16   ; its key
VF_CONTENT      equ VF_KEY + httpasm_public_key_size          ; what was signed: 146 at most
VF_DIGEST       equ VF_CONTENT + 160        ; its hash (64 at most)
VF_RAW          equ VF_DIGEST + 64          ; ECDSA's r || s from the DER (132 at most)
VF_SIGNATURE    equ VF_RAW + 144            ; the signature: its pointer, its octets
VF_SIGNATURE_LENGTH equ VF_SIGNATURE + 8
VF_DATA         equ VF_SIGNATURE_LENGTH + 8 ; the leaf's cert_data, its octets
VF_DATA_LENGTH  equ VF_DATA + 8
VF_SCHEME       equ VF_DATA_LENGTH + 8      ; the scheme (uint32)
VF_FRAME        equ (VF_SCHEME + 8 + 15) / 16 * 16            ; (five pushes + this: 16-aligned)

section .rodata
sg_context:     db "TLS 1.3, server CertificateVerify", 0
sg_client:      db "TLS 1.3, client CertificateVerify", 0

; The CertificateRequest the server sends (4.4.2), whole: an empty certificate_request_context
; (the main handshake's, 4.4.2-4.2.1#2) and signature_algorithms (4.4.2-4.4.1#1) listing every
; scheme ha_tls_verify verifies, the elliptic curves and EdDSA before RSA (smaller, faster to
; verify): ecdsa_secp256r1_sha256, ed25519, ecdsa_secp384r1_sha384, ed448, ecdsa_secp521r1_
; sha512, rsa_pss_rsae_sha256/384/512, rsa_pss_pss_sha256/384/512. No PKCS#1 v1.5 and no SHA-1
; (4.5.2-16#2: a CertificateVerify never takes them). The client's scheme must be one of these
; (ha_tls_verify reads the list here, so the request and the check cannot disagree).
global ha_tls_request:data hidden (ha_tls_request.end - ha_tls_request)
ha_tls_request:
    db HTTPASM_TLS_CERTIFICATE_REQUEST, 0, 0, TE_REQUEST_LENGTH - 4
    db 0                                    ; certificate_request_context: empty
    db 0, 28                                ; extensions: 28 octets
    db 0, 13, 0, 24                         ; signature_algorithms, 24 octets
    db 0, 22                                ; supported_signature_algorithms: 11 schemes
.schemes:
    db 0x04, 0x03, 0x08, 0x07, 0x05, 0x03, 0x08, 0x08, 0x06, 0x03
    db 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x08, 0x09, 0x08, 0x0A, 0x08, 0x0B
.end:
; static checks (a TIMES of -1 stops the assembly; of 0 emits nothing): the message is the
; TE_REQUEST_LENGTH octets tls/server.asm puts, and both frames below stay under a page's
; probe distance, so one subtraction takes them (HA_STACK_DOWN's rule: 4032)
    times -((ha_tls_request.end - ha_tls_request) != TE_REQUEST_LENGTH) db 0
    times -(VF_FRAME > 4032) db 0
    times -(PL_FRAME > 4032) db 0

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

; -----------------------------------------------------------------------------
; ha_tls_peer_leaf: rbx = the connection, rsi = the client's certificate_list (of a Certificate
;   message httpasm_tls13_certificate_read accepted), rdx = its octets: each entry judged as a
;   client's answer to our CertificateRequest -> eax = 0, or minus an alert:
;     unsupported_extension    an entry carries an extension (4.5.1-6.6.1#2: a client's must
;                              answer one the request asked for, and ours asks for none);
;     bad_certificate          a cert_data that is no certificate (httpasm_certificate_read);
;     unsupported_certificate  the leaf's key is none the engine verifies (httpasm_public_key_read
;                              reads exactly the kinds the request's schemes name).
;   The chain's trust, names, dates and order past the leaf are the caller's to judge (M3's
;   validation): this proves the entries are certificates and the leaf's key one a
;   CertificateVerify can be checked against. The frame holds only what the client sent (public):
;   no wipe. Clobbers the caller-saved registers; rbx kept.
; -----------------------------------------------------------------------------
global ha_tls_peer_leaf:function hidden (ha_tls_peer_leaf.end - ha_tls_peer_leaf)
align 16
ha_tls_peer_leaf:
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, PL_FRAME
    mov     r12, rsi                        ; the list
    mov     r13, rdx                        ; its octets
    xor     r14d, r14d                      ; the next entry's offset
    xor     ebp, ebp                        ; the entry's place (0: the leaf)
.entry:
    mov     rdi, r12                        ; entry(list, length, offset, &cert, &length, &ext)
    mov     rsi, r13
    mov     rdx, r14
    lea     rcx, [rsp + PL_DATA]
    lea     r8, [rsp + PL_DATA_LENGTH]
    lea     r9, [rsp + PL_EXT]
    call    httpasm_tls13_certificate_entry
    test    rax, rax
    js      .done                           ; (never: the reader accepted this list; eax its alert)
    mov     r14, rax
    cmp     dword [rsp + PL_EXT + httpasm_tls_extensions.count], 0
    jne     .unsupported_extension          ; (any type, known or not: we asked for none)
    lea     rdi, [rsp + PL_CERT]
    mov     rsi, [rsp + PL_DATA]
    mov     rdx, [rsp + PL_DATA_LENGTH]
    call    httpasm_certificate_read
    test    eax, eax
    jnz     .bad_certificate
    test    ebp, ebp
    jnz     .next
    lea     rdi, [rsp + PL_KEY]             ; the leaf: its key
    mov     rsi, [rsp + PL_CERT + httpasm_certificate.spki]
    mov     rdx, [rsp + PL_CERT + httpasm_certificate.spki_length]
    call    httpasm_public_key_read
    test    eax, eax
    js      .unsupported_certificate
.next:
    inc     ebp
    cmp     r14, r13
    jb      .entry
    xor     eax, eax
.done:
    add     rsp, PL_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    ret
.unsupported_extension:
    mov     eax, -HTTPASM_TLS_ALERT_UNSUPPORTED_EXTENSION
    jmp     .done
.bad_certificate:
    mov     eax, -HTTPASM_TLS_ALERT_BAD_CERTIFICATE
    jmp     .done
.unsupported_certificate:
    mov     eax, -HTTPASM_TLS_ALERT_UNSUPPORTED_CERTIFICATE
    jmp     .done
.end:

; -----------------------------------------------------------------------------
; ha_tls_verify: rbx = the connection (its client's chain kept in .peer, the leaf first), rsi =
;   the client's CertificateVerify (header and body), rdx = its octets: verified (4.5.2) ->
;   eax = 0, or minus an alert:
;     decode_error       the message does not parse (httpasm_tls13_certificate_verify_read);
;     illegal_parameter  a scheme our CertificateRequest did not list (4.5.2-15), or one the
;                        leaf's key does not make (4.5.2-16#1: an ECDSA scheme of the key's own
;                        curve; rsae for an rsaEncryption key; pss for an RSASSA-PSS key whose
;                        parameters allow that hash and a salt of its length, as tls/config.asm
;                        holds our own keys to; ed25519 and ed448 for theirs);
;     decrypt_error      the signature does not verify (4.5.2-19), counting an ECDSA signature
;                        whose DER is not strict (.der_raw) and an EdDSA one of the wrong length.
;   What was signed: 64 octets of 0x20, "TLS 1.3, client CertificateVerify", 0, and Transcript-
;   Hash(ClientHello .. the client's Certificate), the transcript as it stands (the caller adds
;   this message after). The leaf is read again from .peer (ha_tls_peer_leaf judged it when the
;   Certificate came: those reads cannot fail now). All of it is public - the peer's key and
;   signature, the transcript's hash - so nothing is wiped and nothing needs constant time.
;   Clobbers the caller-saved registers; rbx kept.
; -----------------------------------------------------------------------------
global ha_tls_verify:function hidden (ha_tls_verify.end - ha_tls_verify)
align 16
ha_tls_verify:
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, VF_FRAME
    ; the message: its scheme and signature
    lea     rdi, [rsi + 4]                  ; read(body, length, &scheme, &signature, &length)
    lea     rsi, [rdx - 4]
    lea     rdx, [rsp + VF_SCHEME]
    lea     rcx, [rsp + VF_SIGNATURE]
    lea     r8, [rsp + VF_SIGNATURE_LENGTH]
    call    httpasm_tls13_certificate_verify_read
    test    eax, eax
    jnz     .done                           ; decode_error
    ; the scheme: one our CertificateRequest listed (the list as the request carries it)
    mov     eax, [rsp + VF_SCHEME]
    xchg    al, ah                          ; big-endian, as the list stores it
    lea     rsi, [rel ha_tls_request.schemes]
    mov     ecx, (ha_tls_request.end - ha_tls_request.schemes) / 2
.offered:
    cmp     [rsi], ax
    je      .listed
    add     rsi, 2
    dec     ecx
    jnz     .offered
    jmp     .illegal
.listed:
    ; the leaf again, from the chain kept: its entry, its certificate, its key
    mov     rdi, [rbx + httpasm_tls13_connection.peer]
    mov     rsi, [rbx + httpasm_tls13_connection.peer_length]
    xor     edx, edx                        ; the first entry
    lea     rcx, [rsp + VF_DATA]
    lea     r8, [rsp + VF_DATA_LENGTH]
    lea     r9, [rsp + VF_EXT]
    call    httpasm_tls13_certificate_entry
    test    rax, rax
    js      .internal                       ; (never: ha_tls_peer_leaf read it from these octets)
    lea     rdi, [rsp + VF_CERT]
    mov     rsi, [rsp + VF_DATA]
    mov     rdx, [rsp + VF_DATA_LENGTH]
    call    httpasm_certificate_read
    test    eax, eax
    jnz     .internal                       ; (never, likewise)
    lea     rdi, [rsp + VF_KEY]
    mov     rsi, [rsp + VF_CERT + httpasm_certificate.spki]
    mov     rdx, [rsp + VF_CERT + httpasm_certificate.spki_length]
    call    httpasm_public_key_read
    test    eax, eax
    js      .internal                       ; (never, likewise)
    mov     r15d, eax                       ; the key's kind
    ; what the client signed
    lea     rdi, [rsp + VF_CONTENT]
    mov     al, 0x20
    mov     ecx, 64
    rep     stosb
    lea     rsi, [rel sg_client]
    mov     ecx, 34                         ; the string and its 0 octet
    rep     movsb
    call    ha_tls_transcript_hash          ; (rdi: right after them)
    movzx   r14d, byte [rbx + httpasm_tls13_connection.hash_length]
    add     r14d, SG_FIXED                  ; the content's octets
    mov     r12, [rsp + VF_SIGNATURE]
    mov     r13, [rsp + VF_SIGNATURE_LENGTH]
    ; the scheme against the key's kind, then the verification
    mov     eax, [rsp + VF_SCHEME]
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
    ; RSASSA-PSS (listed: rsae 0x0804-0x0806 or pss 0x0809-0x080B are what is left), the hash by
    ; the scheme's last digit
    mov     ecx, HTTPASM_KEY_RSA
    lea     edx, [rax - HTTPASM_TLS_SCHEME_RSA_PSS_RSAE_SHA256]
    cmp     edx, 2
    jbe     .rsa
    mov     ecx, HTTPASM_KEY_RSA_PSS
    lea     edx, [rax - HTTPASM_TLS_SCHEME_RSA_PSS_PSS_SHA256]
.rsa:
    cmp     r15d, ecx
    jne     .illegal                        ; rsae for rsaEncryption, pss for RSASSA-PSS
    lea     ebp, [rdx + HTTPASM_HASH_SHA256] ; SHA-256, -384, -512 (consecutive codes)
    shl     edx, 4
    add     edx, 32
    mov     r14d, edx                       ; hLen: the digest's octets and the salt's
    cmp     r15d, HTTPASM_KEY_RSA_PSS
    jne     .rsa_hash
    mov     eax, [rsp + VF_KEY + httpasm_public_key.pss_hash]
    test    eax, eax
    jz      .rsa_salt                       ; any hash
    cmp     eax, ebp
    jne     .illegal                        ; the key's parameters bind another hash
.rsa_salt:
    cmp     [rsp + VF_KEY + httpasm_public_key.pss_salt], r14d
    ja      .illegal                        ; a minimum salt over TLS's (the hash's length)
.rsa_hash:
    lea     rdi, [rsp + VF_CONTENT]
    movzx   esi, byte [rbx + httpasm_tls13_connection.hash_length]
    add     esi, SG_FIXED
    lea     rdx, [rsp + VF_DIGEST]
    call    ha_tls_sign.hash                ; (ebp: the hash)
    lea     rdi, [rsp + VF_KEY + httpasm_public_key.rsa]   ; verify_pss(key, hash, digest, salt, s, n)
    mov     esi, ebp
    lea     rdx, [rsp + VF_DIGEST]
    mov     ecx, r14d
    mov     r8, r12
    mov     r9, r13
    call    httpasm_rsa_verify_pss
    jmp     .verdict

.p256:
    cmp     r15d, HTTPASM_KEY_P256
    jne     .illegal
    mov     ebp, HTTPASM_HASH_SHA256
    mov     r14d, 32                        ; the scalars' octets
    jmp     .ecdsa
.p384:
    cmp     r15d, HTTPASM_KEY_P384
    jne     .illegal
    mov     ebp, HTTPASM_HASH_SHA384
    mov     r14d, 48
    jmp     .ecdsa
.p521:
    cmp     r15d, HTTPASM_KEY_P521
    jne     .illegal
    mov     ebp, HTTPASM_HASH_SHA512
    mov     r14d, 66
.ecdsa:
    ; the DER (ECDSA-Sig-Value) to r || s, then the digest of what was signed, then the curve's
    ; verification (which checks 0 < r, s < n itself)
    call    .der_raw
    test    eax, eax
    jnz     .decrypt
    lea     rdi, [rsp + VF_CONTENT]
    movzx   esi, byte [rbx + httpasm_tls13_connection.hash_length]
    add     esi, SG_FIXED
    lea     rdx, [rsp + VF_DIGEST]
    call    ha_tls_sign.hash
    lea     rdi, [rsp + VF_KEY + httpasm_public_key.point]   ; verify(point, digest, n, r || s)
    lea     rsi, [rsp + VF_DIGEST]
    mov     edx, 32                         ; (SHA-256's 32, -384's 48, -512's 64: the scheme's)
    cmp     ebp, HTTPASM_HASH_SHA384
    jb      .ecdsa_call
    mov     edx, 48
    je      .ecdsa_call
    mov     edx, 64
.ecdsa_call:
    lea     rcx, [rsp + VF_RAW]
    cmp     r15d, HTTPASM_KEY_P384
    je      .verify_p384
    cmp     r15d, HTTPASM_KEY_P521
    je      .verify_p521
    call    httpasm_p256_verify
    jmp     .verdict
.verify_p384:
    call    httpasm_p384_verify
    jmp     .verdict
.verify_p521:
    call    httpasm_p521_verify
    jmp     .verdict

.ed25519:
    cmp     r15d, HTTPASM_KEY_ED25519
    jne     .illegal
    cmp     r13, 64
    jne     .decrypt                        ; (not a signature of this scheme: it does not verify)
    lea     rdi, [rsp + VF_KEY + httpasm_public_key.point]   ; verify(key, message, n, signature)
    lea     rsi, [rsp + VF_CONTENT]
    mov     edx, r14d
    mov     rcx, r12
    call    httpasm_ed25519_verify
    jmp     .verdict
.ed448:
    cmp     r15d, HTTPASM_KEY_ED448
    jne     .illegal
    cmp     r13, 114
    jne     .decrypt
    lea     rdi, [rsp + VF_KEY + httpasm_public_key.point]   ; verify(key, message, n, no context, s)
    lea     rsi, [rsp + VF_CONTENT]
    mov     edx, r14d
    xor     ecx, ecx
    xor     r8d, r8d
    mov     r9, r12
    call    httpasm_ed448_verify

.verdict:
    test    eax, eax
    jnz     .decrypt
    xor     eax, eax
.done:
    add     rsp, VF_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    ret
.illegal:
    mov     eax, -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER
    jmp     .done
.decrypt:
    mov     eax, -HTTPASM_TLS_ALERT_DECRYPT_ERROR
    jmp     .done
.internal:
    mov     eax, -HTTPASM_TLS_ALERT_INTERNAL_ERROR
    jmp     .done

; .der_raw: r12 = the signature, r13 = its octets, r14d = the curve's scalar octets: DER's
; ECDSA-Sig-Value { r INTEGER, s INTEGER } (RFC 3279 2.2.3) read strictly into r || s at VF_RAW
; (each left-padded to r14d octets) -> eax = 0, or -1 when it is not exactly that: the tag
; 30, a minimal length (short, or 81 and 128 or more), the content all of the signature; each
; INTEGER tag 02 with a short length, minimal (no 00 before an octet under 80), non-negative (no
; first octet of 80 or more), its value r14d octets at most; nothing after s. Called from
; ha_tls_verify's body (rsp then 8 below its frame: VF_ offsets move by 8). A leaf: clobbers
; rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11.
.der_raw:
    mov     rsi, r12
    lea     r8, [r12 + r13]                 ; the end
    cmp     r13, 2
    jb      .der_bad
    cmp     byte [rsi], 0x30
    jne     .der_bad
    movzx   ecx, byte [rsi + 1]
    add     rsi, 2
    cmp     ecx, 0x80
    jb      .der_length
    cmp     ecx, 0x81
    jne     .der_bad                        ; (two scalars of 66 octets take 138 at most)
    cmp     rsi, r8
    jae     .der_bad
    movzx   ecx, byte [rsi]
    inc     rsi
    cmp     ecx, 0x80
    jb      .der_bad                        ; 81 before a length under 128: not minimal
.der_length:
    lea     rax, [rsi + rcx]
    cmp     rax, r8
    jne     .der_bad                        ; the SEQUENCE is the whole signature, exactly
    lea     rdi, [rsp + 8 + VF_RAW]         ; r, then s
    call    .der_integer
    test    eax, eax
    jnz     .der_bad
    lea     rdi, [rsp + 8 + VF_RAW + r14]
    call    .der_integer
    test    eax, eax
    jnz     .der_bad
    cmp     rsi, r8
    jne     .der_bad                        ; something after s
    xor     eax, eax
    ret
.der_bad:
    mov     eax, -1
    ret

; .der_integer: rsi = an INTEGER's tag, r8 = the end, rdi = where its value goes (r14d octets,
; left-padded with zeros) -> eax = 0 with rsi past it, or -1. A leaf (of .der_raw): clobbers
; rax, rcx, rdx, rdi, and moves rsi.
.der_integer:
    lea     rax, [rsi + 2]
    cmp     rax, r8
    ja      .integer_bad                    ; no room for the tag and the length
    cmp     byte [rsi], 0x02
    jne     .integer_bad
    movzx   ecx, byte [rsi + 1]             ; its length (short form only: 67 octets at most)
    add     rsi, 2
    test    ecx, ecx
    jz      .integer_bad                    ; an INTEGER has one octet at least (X.690 8.3.1)
    cmp     ecx, 0x80
    jae     .integer_bad
    lea     rax, [rsi + rcx]
    cmp     rax, r8
    ja      .integer_bad                    ; past the signature
    test    byte [rsi], 0x80
    jnz     .integer_bad                    ; negative
    cmp     ecx, 1
    je      .integer_value
    cmp     byte [rsi], 0
    jne     .integer_value
    test    byte [rsi + 1], 0x80
    jz      .integer_bad                    ; a 00 not needed for the sign: not minimal (8.3.2)
    inc     rsi                             ; the sign's 00 is not the value's
    dec     ecx
.integer_value:
    cmp     ecx, r14d
    ja      .integer_bad                    ; longer than the curve's scalars
    mov     edx, r14d
    sub     edx, ecx                        ; the zeros before it
    xor     eax, eax
.integer_pad:
    test    edx, edx
    jz      .integer_copy
    mov     byte [rdi], 0
    inc     rdi
    dec     edx
    jmp     .integer_pad
.integer_copy:
    rep     movsb                           ; (rsi past the value: the next element)
    xor     eax, eax
    ret
.integer_bad:
    mov     eax, -1
    ret
.end:
