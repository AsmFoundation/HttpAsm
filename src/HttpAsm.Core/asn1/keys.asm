; =============================================================================
; asn1/keys.asm - a private key from its file, for the server to sign its handshakes with: PEM
; (RFC 7468) or DER, in PKCS#8's OneAsymmetricKey (RFC 5958), PKCS#1's RSAPrivateKey (RFC 8017
; A.1.2) or SEC1's ECPrivateKey (RFC 5915); RSA (rsaEncryption, and RSASSA-PSS with RFC 4055's
; parameters), P-256, P-384 and P-521 (RFC 5480's named curves), Ed25519 and Ed448 (RFC 8410).
;
; What is read, and why:
;   - BER throughout (RFC 5958 2: receivers MUST support it; RFC 5915 4: SHOULD), through the
;     reader of asn1/asn1.asm; a BER-constructed privateKey is gathered (httpasm_asn1_octets's
;     way) into this frame's own room first.
;   - OneAsymmetricKey: version v1 (0) or v2 (1); privateKeyAlgorithm; privateKey; attributes
;     [0] (read, not interpreted); publicKey [1], v2 only, which must then be the private key's
;     own. Nothing after them: the ASN.1's extension marker allows later versions' fields, but a
;     key this reader cannot fully read is refused, not half-read.
;   - rsaEncryption: parameters NULL or absent (OpenSSL writes NULL; RFC 8017 A.1 says NULL,
;     and absent ones are seen too); RSAPrivateKey version 0 (two primes: multi-prime keys,
;     version 1, are refused), every number positive, n and e as httpasm_rsa_private_key_init
;     takes them, d read but not used (the init's test signature proves the numbers agree).
;   - id-RSASSA-PSS (RFC 4055 3.1): parameters absent (any of SHA-256, -384, -512 may be
;     used), or naming SHA-256, SHA-384 or SHA-512 with MGF1 over the same hash (RFC 9846 4.2.3
;     signs PSS no other way, so a key bound to SHA-1 is refused: no TLS 1.3 signature could
;     use it), the salt length kept, the trailer field 1.
;   - id-ecPublicKey: a named curve (RFC 5480 2.1.1: implicitCurve and specifiedCurve MUST NOT
;     be used) among P-256, P-384, P-521; ECPrivateKey version 1; privateKey of the curve's
;     length or shorter (OpenSSL before 1.1.0 dropped leading zero octets: such keys exist, so
;     they are padded); parameters [0] when present the curve's (and the algorithm's, both
;     present); publicKey [1] when present d G's, uncompressed or compressed. d outside 1..n-1
;     is refused (the curve's public key function says so).
;   - id-Ed25519, id-Ed448 (RFC 8410 3): parameters absent; CurvePrivateKey, an OCTET STRING of
;     32 or 57 octets, prepared as httpasm_ed25519/ed448_private_key_init prepares it.
;   - X25519 and X448 keys sign nothing and are refused; so is every other algorithm.
;   - PEM: the first "PRIVATE KEY", "RSA PRIVATE KEY" or "EC PRIVATE KEY" block; any other
;     block (a certificate in a combined file, "EC PARAMETERS" before a key) is skipped;
;     "ENCRYPTED PRIVATE KEY" makes the answer -2 when no plain key follows (decryption: PBES2,
;     is M3's).
;
; Constant time: a key's numbers, scalar and seed are secrets, read in constant time (the
; reader's INTEGER and OCTET STRING paths, the RSA and curve code, the Edwards preparation);
; the rest (the structure, the algorithm's identifiers, the version, n and e, the public key
; given) is public by design, and the ConstantTime build marks it so where it is loaded. Every
; buffer that held key material in this frame is wiped before the function returns, and a key
; refused is left all zeros.
; =============================================================================
default rel
%include "httpasm_core.inc"

extern ha_asn1_read
extern ha_asn1_type
extern ha_asn1_gather
extern httpasm_pem_read
extern httpasm_rsa_private_key_init
extern httpasm_p256_public_key
extern httpasm_p384_public_key
extern httpasm_p521_public_key
extern httpasm_ed25519_private_key_init
extern httpasm_ed448_private_key_init

KL_DEPTH        equ 32                      ; the reader's nesting levels (asn1.asm's HA_ASN1_DEPTH)
KL_ED448_KEY    equ 57
AG_BITS         equ 0x200                   ; asn1.asm's ha_asn1_gather flag: a BIT STRING's bits

; KL_CALL target: calls target with rsp 16-aligned (the System V ABI's rule, which the crypto
; functions' own frames rely on) from any depth of this file's local helpers, whose calls leave
; rsp at either alignment. Keeps every register the ABI keeps (rbx, pushed, holds the old rsp).
%macro KL_CALL 1
    push    rbx
    mov     rbx, rsp
    and     rsp, -16
    call    %1
    mov     rsp, rbx
    pop     rbx
%endmacro

; The frame (rbp = rsp after it is taken).
KF_DER          equ 0                       ; a PEM block's octets
KF_DER_SIZE     equ 16384                   ; (RSA-8192's PKCS#8 takes under 5 KiB)
KF_INNER        equ KF_DER + KF_DER_SIZE    ; a BER-constructed string's octets, gathered
KF_INNER_SIZE   equ 16384
KF_NUMBERS      equ KF_INNER + KF_INNER_SIZE    ; httpasm_rsa_private_numbers, then d's slot (16)
KF_OUTER        equ KF_NUMBERS + 128        ; httpasm_asn1: the outer SEQUENCE
KF_E1           equ KF_OUTER + 32           ; httpasm_asn1 scratch elements
KF_E2           equ KF_E1 + 32
KF_E3           equ KF_E2 + 32
KF_E4           equ KF_E3 + 32
KF_PEM          equ KF_E4 + 32              ; httpasm_pem
KF_POINT        equ KF_PEM + 32             ; a public key given (gathered bits), 136 octets
KF_COMPUTED     equ KF_POINT + 136          ; the public key computed from d, 136 octets
KF_SEED         equ KF_COMPUTED + 136       ; d padded, or a seed, 72 octets
KF_DATA         equ KF_SEED + 72
KF_LENGTH       equ KF_DATA + 8
KF_VALUE        equ KF_LENGTH + 8           ; a privateKey's value: pointer and length
KF_VALUE_LENGTH equ KF_VALUE + 8
KF_SAVE13       equ KF_VALUE_LENGTH + 8     ; a cursor kept across a nested structure
KF_SAVE14       equ KF_SAVE13 + 8
KF_DER_USED     equ KF_SAVE14 + 8           ; KF_DER's octets written (to wipe)
KF_INNER_USED   equ KF_DER_USED + 8         ; KF_INNER's
KF_POINT_LENGTH equ KF_INNER_USED + 8       ; KF_POINT's (0: no public key given)
KF_VERSION      equ KF_POINT_LENGTH + 8     ; OneAsymmetricKey's version
KF_CURVE        equ KF_VERSION + 4          ; the curve the algorithm names (HTTPASM_KEY_P*), or 0
KF_ENCRYPTED    equ KF_CURVE + 4            ; 1 once an ENCRYPTED PRIVATE KEY block was seen
KF_FORMAT       equ KF_ENCRYPTED + 4        ; 0 by its shape, 1 PKCS#8, 2 PKCS#1, 3 SEC1
KF_DER_START    equ KF_FORMAT + 4           ; the DER's start and length (the outer SEQUENCE's)
KF_DER_LENGTH   equ KF_DER_START + 8
KF_END          equ KF_DER_LENGTH + 8
KF_FRAME        equ (KF_END + 15) / 16 * 16 + 8     ; (6 pushes + KF_FRAME: rsp 16-aligned at calls)

section .rodata
oid_rsa:        db 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01    ; rsaEncryption
oid_pss:        db 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A    ; id-RSASSA-PSS
oid_mgf1:       db 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08    ; id-mgf1
oid_ec:         db 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01                ; id-ecPublicKey
oid_p256:       db 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07          ; prime256v1
oid_p384:       db 0x2B, 0x81, 0x04, 0x00, 0x22                            ; secp384r1
oid_p521:       db 0x2B, 0x81, 0x04, 0x00, 0x23                            ; secp521r1
oid_ed25519:    db 0x2B, 0x65, 0x70
oid_ed448:      db 0x2B, 0x65, 0x71
oid_sha256:     db 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
oid_sha384:     db 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
oid_sha512:     db 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
label_pkcs8:    db "PRIVATE KEY"            ; 11
label_pkcs1:    db "RSA PRIVATE KEY"        ; 15
label_sec1:     db "EC PRIVATE KEY"         ; 14
label_crypt:    db "ENCRYPTED PRIVATE KEY"  ; 21

section .text

; -----------------------------------------------------------------------------
; int httpasm_private_key_load(httpasm_private_key *key, const uint8_t *data, size_t length)
;   The private key in data[0..length): DER when its first octet is a SEQUENCE's (0x30), else
;   PEM text. See the header above for every format and rule. Returns the key's kind
;   (HTTPASM_KEY_RSA ... HTTPASM_KEY_ED448) with key filled; -2 when the text's only private key
;   is encrypted; -1 otherwise (key then all zeros). Needs about 90 KiB of stack (this frame,
;   33 KiB, touched a page at a time, and an RSA key's preparation under it); every octet of
;   key material in the frame is wiped before it returns. Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_private_key_load:function (httpasm_private_key_load.end - httpasm_private_key_load)
align 16
httpasm_private_key_load:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    HA_STACK_DOWN KF_FRAME, eax             ; (over a page: a page at a time, no stack clash)
    mov     rbp, rsp
    mov     r12, rdi                        ; the key
    mov     [rbp + KF_DATA], rsi
    mov     [rbp + KF_LENGTH], rdx
    xor     eax, eax
    mov     [rbp + KF_DER_USED], rax
    mov     [rbp + KF_INNER_USED], rax
    mov     [rbp + KF_POINT_LENGTH], rax
    mov     [rbp + KF_VERSION], eax
    mov     [rbp + KF_CURVE], eax
    mov     [rbp + KF_ENCRYPTED], eax
    mov     [rbp + KF_FORMAT], eax
    mov     rdi, r12                        ; the key starts all zeros (and stays so if refused)
    mov     ecx, httpasm_private_key_size / 8
    rep     stosq
    mov     rsi, [rbp + KF_DATA]
    mov     rdx, [rbp + KF_LENGTH]
    test    rdx, rdx
    jz      .refused
    HA_DECLASSIFY_MEM rsi, 1                ; (public by design: the file's format)
    cmp     byte [rsi], 0x30
    je      .der                            ; DER (a SEQUENCE's identifier)

    ; ---- PEM: the first block labeled as a private key
    xor     ebx, ebx                        ; the offset of the text left
.pem_block:
    lea     rdi, [rbp + KF_PEM]
    mov     rsi, [rbp + KF_DATA]
    add     rsi, rbx
    mov     rdx, [rbp + KF_LENGTH]
    sub     rdx, rbx
    lea     rcx, [rbp + KF_DER]
    mov     r8d, KF_DER_SIZE
    KL_CALL httpasm_pem_read
    cmp     eax, 1
    je      .pem_none
    test    eax, eax
    jnz     .refused                        ; a malformed block, or one past 16 KiB
    mov     rax, [rbp + KF_PEM + httpasm_pem.der_length]
    cmp     rax, [rbp + KF_DER_USED]
    jbe     .pem_used
    mov     [rbp + KF_DER_USED], rax        ; the most octets any block wrote (wiped at the end)
.pem_used:
    mov     rsi, [rbp + KF_PEM + httpasm_pem.label]
    mov     rcx, [rbp + KF_PEM + httpasm_pem.label_length]
    mov     edx, 1
    lea     rdi, [rel label_pkcs8]
    cmp     rcx, 11
    je      .pem_label
    mov     edx, 2
    lea     rdi, [rel label_pkcs1]
    cmp     rcx, 15
    je      .pem_label
    mov     edx, 3
    lea     rdi, [rel label_sec1]
    cmp     rcx, 14
    je      .pem_label
    mov     edx, 4
    lea     rdi, [rel label_crypt]
    cmp     rcx, 21
    jne     .pem_next
.pem_label:
    repe    cmpsb                           ; (public: a label)
    jne     .pem_next
    cmp     edx, 4
    jne     .pem_found
    mov     dword [rbp + KF_ENCRYPTED], 1   ; encrypted: a plain key may still follow
.pem_next:
    add     rbx, [rbp + KF_PEM + httpasm_pem.end]
    jmp     .pem_block
.pem_none:
    mov     eax, -1
    cmp     dword [rbp + KF_ENCRYPTED], 0
    je      .finish
    mov     eax, -2
    jmp     .finish
.pem_found:
    mov     [rbp + KF_FORMAT], edx
    lea     rsi, [rbp + KF_DER]
    mov     rdx, [rbp + KF_PEM + httpasm_pem.der_length]

    ; ---- the DER (rsi, rdx): its shape, by its second element's tag
.der:
    mov     [rbp + KF_DER_START], rsi
    mov     [rbp + KF_DER_LENGTH], rdx
    mov     r13, rsi                        ; the cursor
    lea     r14, [rsi + rdx]                ; the end
    lea     rdi, [rbp + KF_OUTER]
    call    .next
    test    eax, eax
    jnz     .refused
    cmp     r13, r14
    jne     .refused                        ; one element, the whole input
    cmp     dword [rbp + KF_OUTER + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .refused
    lea     rdi, [rbp + KF_OUTER]
    call    .enter
    lea     rdi, [rbp + KF_E1]              ; a version, in all three
    call    .next
    test    eax, eax
    jnz     .refused
    cmp     dword [rbp + KF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_INTEGER
    jne     .refused
    lea     rdi, [rbp + KF_E2]
    call    .next
    test    eax, eax
    jnz     .refused
    mov     eax, [rbp + KF_E2 + httpasm_asn1.tag]
    mov     ecx, [rbp + KF_FORMAT]
    cmp     eax, HTTPASM_ASN1_SEQUENCE      ; OneAsymmetricKey: the privateKeyAlgorithm
    je      .is_pkcs8
    cmp     eax, HTTPASM_ASN1_INTEGER       ; RSAPrivateKey: the modulus
    je      .is_pkcs1
    cmp     eax, HTTPASM_ASN1_OCTET_STRING  ; ECPrivateKey: the privateKey
    je      .is_sec1
    test    eax, HTTPASM_ASN1_CONSTRUCTED   ; (BER: a constructed OCTET STRING too)
    jz      .refused
    cmp     eax, HTTPASM_ASN1_OCTET_STRING | HTTPASM_ASN1_CONSTRUCTED
    je      .is_sec1
    jmp     .refused
.is_pkcs1:
    test    ecx, ecx
    jz      .pkcs1
    cmp     ecx, 2
    jne     .refused                        ; a PEM label naming another format
.pkcs1:
    mov     rsi, [rbp + KF_DER_START]       ; RSAPrivateKey: the whole DER
    mov     rdx, [rbp + KF_DER_LENGTH]
    mov     dword [r12 + httpasm_private_key.kind], HTTPASM_KEY_RSA
    call    .rsa_key
    jmp     .finish
.is_sec1:
    test    ecx, ecx
    jz      .sec1
    cmp     ecx, 3
    jne     .refused
.sec1:
    mov     rsi, [rbp + KF_DER_START]       ; ECPrivateKey: the whole DER
    mov     rdx, [rbp + KF_DER_LENGTH]
    call    .ec_key
    jmp     .finish
.is_pkcs8:
    test    ecx, ecx
    jz      .pkcs8
    cmp     ecx, 1
    jne     .refused

    ; ---- OneAsymmetricKey (RFC 5958 2)
.pkcs8:
    lea     rdi, [rbp + KF_E1]
    call    .small                          ; version: v1 (0) or v2 (1)
    cmp     eax, 1
    ja      .refused
    mov     [rbp + KF_VERSION], eax
    ; privateKeyAlgorithm: SEQUENCE { algorithm, parameters OPTIONAL }
    mov     [rbp + KF_SAVE13], r13
    mov     [rbp + KF_SAVE14], r14
    lea     rdi, [rbp + KF_E2]
    call    .enter
    lea     rdi, [rbp + KF_E3]
    call    .next
    test    eax, eax
    jnz     .refused
    cmp     dword [rbp + KF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_OID
    jne     .refused
    xor     ebx, ebx                        ; 1: a parameters element follows
    cmp     r13, r14
    je      .algorithm
    lea     rdi, [rbp + KF_E4]
    call    .next
    test    eax, eax
    jnz     .refused
    cmp     r13, r14
    jne     .refused                        ; nothing after the parameters
    mov     ebx, 1
.algorithm:
    lea     rdi, [rbp + KF_E3]
    lea     rsi, [rel oid_rsa]
    mov     ecx, 9
    call    .oid_is
    je      .alg_rsa
    lea     rdi, [rbp + KF_E3]
    lea     rsi, [rel oid_pss]
    mov     ecx, 9
    call    .oid_is
    je      .alg_pss
    lea     rdi, [rbp + KF_E3]
    lea     rsi, [rel oid_ec]
    mov     ecx, 7
    call    .oid_is
    je      .alg_ec
    test    ebx, ebx
    jnz     .refused                        ; RFC 8410 3: the Edwards keys' parameters MUST be absent
    mov     dword [r12 + httpasm_private_key.kind], HTTPASM_KEY_ED25519
    lea     rdi, [rbp + KF_E3]
    lea     rsi, [rel oid_ed25519]
    mov     ecx, 3
    call    .oid_is
    je      .alg_done
    mov     dword [r12 + httpasm_private_key.kind], HTTPASM_KEY_ED448
    lea     rdi, [rbp + KF_E3]
    lea     rsi, [rel oid_ed448]
    mov     ecx, 3
    call    .oid_is
    je      .alg_done
    jmp     .refused                        ; X25519, X448, and every other algorithm
.alg_rsa:
    mov     dword [r12 + httpasm_private_key.kind], HTTPASM_KEY_RSA
    test    ebx, ebx
    jz      .alg_done                       ; parameters absent
    cmp     dword [rbp + KF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_NULL
    jne     .refused                        ; (the reader checked NULL's form)
    jmp     .alg_done
.alg_pss:
    mov     dword [r12 + httpasm_private_key.kind], HTTPASM_KEY_RSA_PSS
    test    ebx, ebx
    jz      .alg_done                       ; absent: any hash (RFC 4055 3.1)
    call    .pss_params
    test    eax, eax
    jnz     .refused
    jmp     .alg_done
.alg_ec:
    test    ebx, ebx
    jz      .refused                        ; RFC 5480 2.1.1: the curve is named
    cmp     dword [rbp + KF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_OID
    jne     .refused                        ; implicitCurve (NULL), specifiedCurve: MUST NOT
    lea     rdi, [rbp + KF_E4]
    call    .curve
    test    eax, eax
    jz      .refused
    mov     [rbp + KF_CURVE], eax
    mov     [r12 + httpasm_private_key.kind], eax
.alg_done:
    mov     r13, [rbp + KF_SAVE13]
    mov     r14, [rbp + KF_SAVE14]
    ; privateKey: OCTET STRING, its value gathered when BER made it constructed
    lea     rdi, [rbp + KF_E3]
    call    .next
    test    eax, eax
    jnz     .refused
    mov     eax, [rbp + KF_E3 + httpasm_asn1.tag]
    and     eax, ~HTTPASM_ASN1_CONSTRUCTED
    cmp     eax, HTTPASM_ASN1_OCTET_STRING
    jne     .refused
    lea     rdi, [rbp + KF_E3]
    call    .value
    test    eax, eax
    jnz     .refused
    ; attributes [0] (read, not interpreted), then publicKey [1] (v2 only), then nothing
    cmp     r13, r14
    je      .pkcs8_parsed
    lea     rdi, [rbp + KF_E4]
    call    .next
    test    eax, eax
    jnz     .refused
    cmp     dword [rbp + KF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 0
    jne     .pkcs8_public                   ; no attributes: perhaps the public key
    cmp     r13, r14
    je      .pkcs8_parsed
    lea     rdi, [rbp + KF_E4]
    call    .next
    test    eax, eax
    jnz     .refused
.pkcs8_public:
    mov     eax, [rbp + KF_E4 + httpasm_asn1.tag]
    and     eax, ~HTTPASM_ASN1_CONSTRUCTED
    cmp     eax, HTTPASM_ASN1_CONTEXT | 1
    jne     .refused
    cmp     dword [rbp + KF_VERSION], 1
    jne     .refused                        ; RFC 5958 2: publicKey makes the version v2
    lea     rdi, [rbp + KF_E4]
    call    .given_public                   ; [1] IMPLICIT BIT STRING
    test    eax, eax
    jnz     .refused
    cmp     r13, r14
    jne     .refused                        ; nothing after the public key
.pkcs8_parsed:
    mov     eax, [r12 + httpasm_private_key.kind]
    mov     rsi, [rbp + KF_VALUE]
    mov     rdx, [rbp + KF_VALUE_LENGTH]
    cmp     eax, HTTPASM_KEY_RSA_PSS
    jbe     .pkcs8_rsa
    cmp     eax, HTTPASM_KEY_P521
    jbe     .pkcs8_ec
    call    .ed_key
    jmp     .finish
.pkcs8_rsa:
    call    .rsa_key
    jmp     .finish
.pkcs8_ec:
    call    .ec_key
    jmp     .finish

.refused:
    mov     eax, -1
.finish:                                    ; eax = the answer; every buffer of key material wiped
    mov     ebx, eax
    lea     rdi, [rbp + KF_DER]
    mov     rcx, [rbp + KF_DER_USED]
    xor     eax, eax
    rep     stosb
    lea     rdi, [rbp + KF_INNER]
    mov     rcx, [rbp + KF_INNER_USED]
    rep     stosb
    lea     rdi, [rbp + KF_SEED]
    mov     ecx, 72 / 8
    rep     stosq
    test    ebx, ebx
    jns     .done
    mov     rdi, r12                        ; refused: the key all zeros again
    mov     ecx, httpasm_private_key_size / 8
    rep     stosq
.done:
    mov     eax, ebx
    lea     rsp, [rbp + KF_FRAME]
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- the helpers (local: they share the frame at rbp and the cursor r13..r14) ---------------

; .next: rdi = an element slot -> the element at the cursor read into it under BER (the reader's
; every check), the cursor past it; eax = 0, or -1 (also at the end of the contents).
.next:
    push    rdi                             ; (the slot: the reader clobbers rdi)
    mov     rsi, r13
    mov     rdx, r14
    sub     rdx, r13
    mov     ecx, HTTPASM_ASN1_BER
    mov     r8d, KL_DEPTH
    KL_CALL ha_asn1_read
    pop     rdi
    test    eax, eax
    jnz     .next_end
    add     r13, [rdi + httpasm_asn1.length]
.next_end:
    ret

; .enter: rdi = a constructed element -> the cursor over its contents.
.enter:
    mov     r13, [rdi + httpasm_asn1.content]
    mov     r14, [rdi + httpasm_asn1.content_length]
    add     r14, r13
    ret

; .oid_is: rdi = an OBJECT IDENTIFIER, rsi = an encoding's contents, ecx = its length -> ZF set
; when they are the same (the reader made the identifier's octets public).
.oid_is:
    cmp     [rdi + httpasm_asn1.content_length], rcx
    jne     .oid_no
    mov     rdi, [rdi + httpasm_asn1.content]
    repe    cmpsb
.oid_no:
    ret

; .small: rdi = an INTEGER (public by design: a version, a salt length, a trailer field) ->
; eax = its value when 0 to 2^31 - 1, else -1. Marks its contents public first.
.small:
    mov     rsi, [rdi + httpasm_asn1.content]
    mov     rcx, [rdi + httpasm_asn1.content_length]
    HA_DECLASSIFY_MEM rsi, rcx              ; (public by design: a format's numbers)
    cmp     dword [rdi + httpasm_asn1.tag], HTTPASM_ASN1_INTEGER
    jne     .small_no
    cmp     rcx, 4
    ja      .small_no
    test    byte [rsi], 0x80
    jnz     .small_no                       ; negative
    xor     eax, eax
.small_octet:
    shl     eax, 8
    movzx   edx, byte [rsi]
    or      eax, edx
    inc     rsi
    dec     rcx
    jnz     .small_octet
    test    eax, eax
    js      .small_no
    ret
.small_no:
    mov     eax, -1
    ret

; .curve: rdi = a named curve's OBJECT IDENTIFIER -> eax = HTTPASM_KEY_P256, _P384, _P521, or 0.
.curve:
    push    rdi
    lea     rsi, [rel oid_p256]
    mov     ecx, 8
    call    .oid_is
    pop     rdi
    mov     eax, HTTPASM_KEY_P256
    je      .curve_done
    push    rdi
    lea     rsi, [rel oid_p384]
    mov     ecx, 5
    call    .oid_is
    pop     rdi
    mov     eax, HTTPASM_KEY_P384
    je      .curve_done
    lea     rsi, [rel oid_p521]
    mov     ecx, 5
    call    .oid_is
    mov     eax, HTTPASM_KEY_P521
    je      .curve_done
    xor     eax, eax
.curve_done:
    ret

; .value: rdi = an OCTET STRING (its own tag or an implicit one, primitive or BER-constructed)
; -> KF_VALUE and KF_VALUE_LENGTH: its contents, or its segments' gathered into KF_INNER; eax =
; 0, or -1 when they do not fit there. Constant time in the octets.
.value:
    test    dword [rdi + httpasm_asn1.tag], HTTPASM_ASN1_CONSTRUCTED
    jnz     .value_gather
    mov     rax, [rdi + httpasm_asn1.content]
    mov     [rbp + KF_VALUE], rax
    mov     rax, [rdi + httpasm_asn1.content_length]
    mov     [rbp + KF_VALUE_LENGTH], rax
    xor     eax, eax
    ret
.value_gather:
    push    rdi
    lea     rsi, [rbp + KF_INNER]
    mov     edx, KF_INNER_SIZE
    mov     ecx, HTTPASM_ASN1_BER
    mov     r8d, KL_DEPTH
    KL_CALL ha_asn1_gather
    pop     rdi
    test    rax, rax
    js      .value_no
    mov     [rbp + KF_INNER_USED], rax      ; (wiped at the end; a later gather writes no more)
    mov     [rbp + KF_VALUE_LENGTH], rax
    lea     rax, [rbp + KF_INNER]
    mov     [rbp + KF_VALUE], rax
    xor     eax, eax
    ret
.value_no:
    mov     eax, -1
    ret

; .given_public: rdi = a public key's BIT STRING (its own tag or an implicit one) -> its bits in
; KF_POINT, their count in KF_POINT_LENGTH (136 at most); eax = 0, or -1 when they are no
; whole octets, do not fit, or a public key was given already that differs.
.given_public:
    push    rdi
    mov     esi, HTTPASM_ASN1_BIT_STRING
    mov     edx, HTTPASM_ASN1_BER
    mov     ecx, KL_DEPTH
    KL_CALL ha_asn1_type                    ; a BIT STRING's rules, under an implicit tag too
    pop     rdi
    test    eax, eax
    jnz     .given_no
    push    rdi
    lea     rsi, [rbp + KF_COMPUTED]        ; (as scratch: compared, then the copy kept)
    mov     edx, 136
    mov     ecx, HTTPASM_ASN1_BER | AG_BITS
    mov     r8d, KL_DEPTH
    KL_CALL ha_asn1_gather
    pop     rdi
    test    rax, rax
    js      .given_no
    test    edx, edx
    jnz     .given_no                       ; whole octets only
    mov     rcx, [rbp + KF_POINT_LENGTH]
    test    rcx, rcx
    jz      .given_keep
    cmp     rcx, rax                        ; given twice (PKCS#8's and ECPrivateKey's): equal
    jne     .given_no
    lea     rsi, [rbp + KF_COMPUTED]
    lea     rdi, [rbp + KF_POINT]
    repe    cmpsb
    jne     .given_no
    xor     eax, eax
    ret
.given_keep:
    mov     [rbp + KF_POINT_LENGTH], rax
    mov     rcx, rax
    lea     rsi, [rbp + KF_COMPUTED]
    lea     rdi, [rbp + KF_POINT]
    rep     movsb
    xor     eax, eax
    ret
.given_no:
    mov     eax, -1
    ret

; .pss_params: KF_E4 = RSASSA-PSS-params (RFC 4055 3.1) -> pss_hash and pss_salt in the key;
; eax = 0, or -1 for a hash other than SHA-256/384/512, MGF1 over another hash, or a trailer
; field other than 1. [0] to [3] are EXPLICIT (RFC 4055's module), each optional, in order.
.pss_params:
    cmp     dword [rbp + KF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .pss_no
    push    r13
    push    r14
    lea     rdi, [rbp + KF_E4]
    call    .enter
    xor     ebx, ebx                        ; the hash (HTTPASM_HASH_*): absent is SHA-1
    mov     r15d, -1                        ; MGF1's hash: absent is SHA-1 (-1: not seen)
    mov     dword [r12 + httpasm_private_key.pss_salt], 20  ; saltLength's DEFAULT
    cmp     r13, r14
    je      .pss_checked
    lea     rdi, [rbp + KF_E1]
    call    .next
    test    eax, eax
    jnz     .pss_bad
    cmp     dword [rbp + KF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 0
    jne     .pss_mgf
    lea     rdi, [rbp + KF_E1]
    call    .hash_in                        ; [0] HashAlgorithm
    test    eax, eax
    jz      .pss_bad
    mov     ebx, eax
    call    .pss_more
    jc      .pss_checked
.pss_mgf:
    cmp     dword [rbp + KF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 1
    jne     .pss_salt
    ; [1] MaskGenAlgorithm: SEQUENCE { id-mgf1, HashAlgorithm }
    push    r13
    push    r14
    lea     rdi, [rbp + KF_E1]
    call    .enter
    lea     rdi, [rbp + KF_E2]
    call    .next
    test    eax, eax
    jnz     .pss_mgf_bad
    cmp     r13, r14
    jne     .pss_mgf_bad                    ; [1]'s contents: the one AlgorithmIdentifier
    cmp     dword [rbp + KF_E2 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .pss_mgf_bad
    lea     rdi, [rbp + KF_E2]
    call    .enter
    lea     rdi, [rbp + KF_E3]
    call    .next
    test    eax, eax
    jnz     .pss_mgf_bad
    cmp     dword [rbp + KF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_OID
    jne     .pss_mgf_bad
    lea     rdi, [rbp + KF_E3]
    lea     rsi, [rel oid_mgf1]
    mov     ecx, 9
    call    .oid_is
    jne     .pss_mgf_bad
    lea     rdi, [rbp + KF_E3]              ; MGF1's parameter: the hash's AlgorithmIdentifier
    call    .next
    test    eax, eax
    jnz     .pss_mgf_bad
    cmp     r13, r14
    jne     .pss_mgf_bad
    call    .hash_id                        ; KF_E3 = AlgorithmIdentifier
    test    eax, eax
    jz      .pss_mgf_bad
    mov     r15d, eax
    pop     r14
    pop     r13
    call    .pss_more
    jc      .pss_checked
    jmp     .pss_salt
.pss_mgf_bad:
    pop     r14
    pop     r13
    jmp     .pss_bad
.pss_salt:
    cmp     dword [rbp + KF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 2
    jne     .pss_trailer
    call    .explicit_small                 ; [2] INTEGER
    test    eax, eax
    js      .pss_bad
    mov     [r12 + httpasm_private_key.pss_salt], eax
    call    .pss_more
    jc      .pss_checked
.pss_trailer:
    cmp     dword [rbp + KF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 3
    jne     .pss_bad                        ; out of order, or unknown
    call    .explicit_small                 ; [3] INTEGER: 1 (RFC 4055 3.1: MUST)
    cmp     eax, 1
    jne     .pss_bad
    cmp     r13, r14
    jne     .pss_bad
.pss_checked:
    ; SHA-256, -384 or -512, and MGF1 over the same one (absent MGF: MGF1 with SHA-1)
    test    ebx, ebx
    jz      .pss_bad                        ; SHA-1, the default: TLS 1.3 never signs with it
    cmp     r15d, ebx
    jne     .pss_bad
    mov     [r12 + httpasm_private_key.pss_hash], ebx
    pop     r14
    pop     r13
    xor     eax, eax
    ret
.pss_bad:
    pop     r14
    pop     r13
.pss_no:
    mov     eax, -1
    ret

; .pss_more: the next element of the parameters into KF_E1 -> CF set when there is none; on a
; malformed one, the parameters are refused (the return address is dropped: .pss_bad pops the
; cursor .pss_params saved).
.pss_more:
    cmp     r13, r14
    je      .pss_more_none
    lea     rdi, [rbp + KF_E1]
    call    .next
    test    eax, eax
    jnz     .pss_more_bad
    clc
    ret
.pss_more_none:
    stc
    ret
.pss_more_bad:
    add     rsp, 8                          ; (the call from .pss_params)
    jmp     .pss_bad

; .hash_in: rdi = an EXPLICIT [n] holding a HashAlgorithm -> eax = its HTTPASM_HASH_* among
; SHA-256/384/512 (0 for anything else). Keeps r13, r14.
.hash_in:
    push    r13
    push    r14
    call    .enter
    lea     rdi, [rbp + KF_E3]
    call    .next
    test    eax, eax
    jnz     .hash_in_no
    cmp     r13, r14
    jne     .hash_in_no
    call    .hash_id
    jmp     .hash_in_done
.hash_in_no:
    xor     eax, eax
.hash_in_done:
    pop     r14
    pop     r13
    ret

; .hash_id: KF_E3 = an AlgorithmIdentifier of a hash -> eax = HTTPASM_HASH_SHA256/384/512, or 0
; (another hash, or parameters other than NULL or absent). Keeps r13, r14.
.hash_id:
    cmp     dword [rbp + KF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .hash_id_no
    push    r13
    push    r14
    lea     rdi, [rbp + KF_E3]
    call    .enter
    lea     rdi, [rbp + KF_E4]
    call    .next
    test    eax, eax
    jnz     .hash_id_pop
    cmp     dword [rbp + KF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_OID
    jne     .hash_id_pop
    cmp     r13, r14
    je      .hash_id_which                  ; parameters absent
    lea     rdi, [rbp + KF_E2]              ; (scratch: KF_E4 keeps the identifier)
    call    .next
    test    eax, eax
    jnz     .hash_id_pop
    cmp     dword [rbp + KF_E2 + httpasm_asn1.tag], HTTPASM_ASN1_NULL
    jne     .hash_id_pop
    cmp     r13, r14
    jne     .hash_id_pop
.hash_id_which:
    lea     rdi, [rbp + KF_E4]
    lea     rsi, [rel oid_sha256]
    mov     ecx, 9
    call    .oid_is
    mov     eax, HTTPASM_HASH_SHA256
    je      .hash_id_done
    lea     rdi, [rbp + KF_E4]
    lea     rsi, [rel oid_sha384]
    mov     ecx, 9
    call    .oid_is
    mov     eax, HTTPASM_HASH_SHA384
    je      .hash_id_done
    lea     rdi, [rbp + KF_E4]
    lea     rsi, [rel oid_sha512]
    mov     ecx, 9
    call    .oid_is
    mov     eax, HTTPASM_HASH_SHA512
    je      .hash_id_done
.hash_id_pop:
    xor     eax, eax
.hash_id_done:
    pop     r14
    pop     r13
    ret
.hash_id_no:
    xor     eax, eax
    ret

; .explicit_small: KF_E1 = an EXPLICIT [n] holding one INTEGER -> eax = its value (.small's), or
; -1. Keeps r13, r14.
.explicit_small:
    push    r13
    push    r14
    lea     rdi, [rbp + KF_E1]
    call    .enter
    lea     rdi, [rbp + KF_E2]
    call    .next
    test    eax, eax
    jnz     .explicit_no
    cmp     r13, r14
    jne     .explicit_no
    lea     rdi, [rbp + KF_E2]
    call    .small
    jmp     .explicit_done
.explicit_no:
    mov     eax, -1
.explicit_done:
    pop     r14
    pop     r13
    ret

; .integer_into: rdi = an INTEGER read, rsi = where its pointer and length go (in the numbers),
; edx = 1 when it is public (n, e: marked so) -> eax = 0, or -1 when it is negative. The sign
; is checked without a branch on a secret's octet: only the verdict is made public.
.integer_into:
    cmp     dword [rdi + httpasm_asn1.tag], HTTPASM_ASN1_INTEGER
    jne     .integer_no
    mov     rax, [rdi + httpasm_asn1.content]
    mov     rcx, [rdi + httpasm_asn1.content_length]
    mov     [rsi], rax
    mov     [rsi + 8], rcx
    test    edx, edx
    jz      .integer_sign
    HA_DECLASSIFY_MEM rax, rcx              ; (public by design: n and e are the public key)
.integer_sign:
    movzx   eax, byte [rax]
    shr     eax, 7                          ; 1: negative (the reader made it at least one octet)
    HA_DECLASSIFY rax                       ; (public by design: a negative number is refused)
    test    eax, eax
    jnz     .integer_no
    ret
.integer_no:
    mov     eax, -1
    ret

; .rsa_key: rsi, rdx = an RSAPrivateKey's encoding (RFC 8017 A.1.2), the key's kind set (RSA or
; RSA_PSS) -> the key prepared; eax = the kind, or -1.
.rsa_key:
    mov     r13, rsi
    lea     r14, [rsi + rdx]
    lea     rdi, [rbp + KF_E1]
    call    .next
    test    eax, eax
    jnz     .rsa_no
    cmp     r13, r14
    jne     .rsa_no                         ; one element, the whole value
    cmp     dword [rbp + KF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .rsa_no
    lea     rdi, [rbp + KF_E1]
    call    .enter
    lea     rdi, [rbp + KF_E2]
    call    .next
    test    eax, eax
    jnz     .rsa_no
    lea     rdi, [rbp + KF_E2]
    call    .small                          ; version 0: two primes (1: multi-prime, refused)
    test    eax, eax
    jnz     .rsa_no
    ; n, e, d, p, q, dp, dq, qinv: n and e public, the rest secret; d checked and dropped
    xor     ebx, ebx                        ; which number
.rsa_number:
    lea     rdi, [rbp + KF_E2]
    call    .next
    test    eax, eax
    jnz     .rsa_no
    lea     rdi, [rbp + KF_E2]
    lea     rax, [rel .rsa_slots]
    movzx   esi, byte [rax + rbx]
    lea     rsi, [rbp + KF_NUMBERS + rsi]
    xor     edx, edx
    cmp     ebx, 2
    setb    dl                              ; n and e: public
    call    .integer_into
    test    eax, eax
    jnz     .rsa_no
    inc     ebx
    cmp     ebx, 8
    jb      .rsa_number
    cmp     r13, r14
    jne     .rsa_no                         ; nothing after the coefficient
    lea     rdi, [r12 + httpasm_private_key.secret]
    lea     rsi, [rbp + KF_NUMBERS]
    KL_CALL httpasm_rsa_private_key_init
    test    eax, eax
    jnz     .rsa_no
    ; the modulus' bits (n is public): its octets past leading zeros, less the first's zero bits
    mov     rsi, [rbp + KF_NUMBERS + httpasm_rsa_private_numbers.n]
    mov     rcx, [rbp + KF_NUMBERS + httpasm_rsa_private_numbers.n_length]
.rsa_lead:
    movzx   eax, byte [rsi]
    test    eax, eax
    jnz     .rsa_bits
    inc     rsi
    dec     rcx
    jmp     .rsa_lead                       ; (the init refused a zero modulus)
.rsa_bits:
    bsr     eax, eax
    lea     rcx, [rcx * 8 - 8]
    lea     eax, [rcx + rax + 1]
    mov     [r12 + httpasm_private_key.bits], eax
    mov     eax, [r12 + httpasm_private_key.kind]
    ret
.rsa_no:
    mov     eax, -1
    ret
; Where each number goes in httpasm_rsa_private_numbers (d: into its own slot after them).
.rsa_slots:
    db httpasm_rsa_private_numbers.n, httpasm_rsa_private_numbers.e, httpasm_rsa_private_numbers_size
    db httpasm_rsa_private_numbers.p, httpasm_rsa_private_numbers.q, httpasm_rsa_private_numbers.dp
    db httpasm_rsa_private_numbers.dq, httpasm_rsa_private_numbers.qinv

; .ec_key: rsi, rdx = an ECPrivateKey's encoding (RFC 5915 3), KF_CURVE = the algorithm's curve
; or 0 -> the key's scalar and public key; eax = the kind, or -1.
.ec_key:
    mov     r13, rsi
    lea     r14, [rsi + rdx]
    lea     rdi, [rbp + KF_E1]
    call    .next
    test    eax, eax
    jnz     .ec_no
    cmp     r13, r14
    jne     .ec_no
    cmp     dword [rbp + KF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .ec_no
    lea     rdi, [rbp + KF_E1]
    call    .enter
    lea     rdi, [rbp + KF_E2]
    call    .next
    test    eax, eax
    jnz     .ec_no
    lea     rdi, [rbp + KF_E2]
    call    .small
    cmp     eax, 1                          ; ecPrivkeyVer1
    jne     .ec_no
    lea     rdi, [rbp + KF_E2]              ; privateKey
    call    .next
    test    eax, eax
    jnz     .ec_no
    mov     eax, [rbp + KF_E2 + httpasm_asn1.tag]
    and     eax, ~HTTPASM_ASN1_CONSTRUCTED
    cmp     eax, HTTPASM_ASN1_OCTET_STRING
    jne     .ec_no
    lea     rdi, [rbp + KF_E2]
    call    .value
    test    eax, eax
    jnz     .ec_no
    xor     ebx, ebx                        ; the curve [0] names (0: absent)
    cmp     r13, r14
    je      .ec_parsed
    lea     rdi, [rbp + KF_E3]
    call    .next
    test    eax, eax
    jnz     .ec_no
    cmp     dword [rbp + KF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 0
    jne     .ec_public
    ; parameters [0] EXPLICIT ECParameters: the namedCurve choice only
    push    r13
    push    r14
    lea     rdi, [rbp + KF_E3]
    call    .enter
    lea     rdi, [rbp + KF_E4]
    call    .next
    mov     ecx, eax
    xor     eax, eax
    test    ecx, ecx
    jnz     .ec_curve_done
    cmp     r13, r14
    jne     .ec_curve_done
    cmp     dword [rbp + KF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_OID
    jne     .ec_curve_done
    lea     rdi, [rbp + KF_E4]
    call    .curve
.ec_curve_done:
    pop     r14
    pop     r13
    test    eax, eax
    jz      .ec_no
    mov     ebx, eax
    cmp     r13, r14
    je      .ec_parsed
    lea     rdi, [rbp + KF_E3]
    call    .next
    test    eax, eax
    jnz     .ec_no
.ec_public:
    cmp     dword [rbp + KF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 1
    jne     .ec_no
    ; publicKey [1] EXPLICIT BIT STRING
    push    r13
    push    r14
    lea     rdi, [rbp + KF_E3]
    call    .enter
    lea     rdi, [rbp + KF_E4]
    call    .next
    mov     ecx, eax
    mov     eax, -1
    test    ecx, ecx
    jnz     .ec_public_done
    cmp     r13, r14
    jne     .ec_public_done
    mov     eax, [rbp + KF_E4 + httpasm_asn1.tag]
    and     eax, ~HTTPASM_ASN1_CONSTRUCTED
    cmp     eax, HTTPASM_ASN1_BIT_STRING
    mov     eax, -1
    jne     .ec_public_done
    lea     rdi, [rbp + KF_E4]
    call    .given_public
.ec_public_done:
    pop     r14
    pop     r13
    test    eax, eax
    jnz     .ec_no
    cmp     r13, r14
    jne     .ec_no                          ; nothing after the public key
.ec_parsed:
    ; the curve: [0]'s, the algorithm's, both equal; one of them at least
    mov     eax, [rbp + KF_CURVE]
    test    ebx, ebx
    jz      .ec_curve_known
    test    eax, eax
    jz      .ec_curve_own
    cmp     eax, ebx
    jne     .ec_no
.ec_curve_own:
    mov     eax, ebx
.ec_curve_known:
    test    eax, eax
    jz      .ec_no                          ; no curve named anywhere
    mov     [r12 + httpasm_private_key.kind], eax
    ; d: 1 to the curve's octets, left-padded with zeros (the length is public)
    mov     ecx, 32
    mov     edx, 256
    cmp     eax, HTTPASM_KEY_P256
    je      .ec_size
    mov     ecx, 48
    mov     edx, 384
    cmp     eax, HTTPASM_KEY_P384
    je      .ec_size
    mov     ecx, 66
    mov     edx, 521
.ec_size:
    mov     [r12 + httpasm_private_key.bits], edx
    mov     rdx, [rbp + KF_VALUE_LENGTH]
    test    rdx, rdx
    jz      .ec_no
    cmp     rdx, rcx
    ja      .ec_no
    push    rcx
    lea     rdi, [rbp + KF_SEED]
    mov     r8, rcx
    xor     eax, eax
    rep     stosb                           ; zeros first
    lea     rdi, [rbp + KF_SEED + r8]
    sub     rdi, rdx
    mov     rsi, [rbp + KF_VALUE]
    mov     rcx, rdx
    rep     movsb                           ; then d by position (constant time)
    pop     rcx
    ; the public key d G (d outside 1..n-1: refused)
    mov     [r12 + httpasm_private_key.public_length], ecx
    shl     dword [r12 + httpasm_private_key.public_length], 1
    inc     dword [r12 + httpasm_private_key.public_length]
    push    rcx
    lea     rdi, [r12 + httpasm_private_key.public]
    lea     rsi, [rbp + KF_SEED]
    mov     eax, [r12 + httpasm_private_key.kind]
    cmp     eax, HTTPASM_KEY_P256
    je      .ec_p256
    cmp     eax, HTTPASM_KEY_P384
    je      .ec_p384
    KL_CALL httpasm_p521_public_key
    jmp     .ec_derived
.ec_p256:
    KL_CALL httpasm_p256_public_key
    jmp     .ec_derived
.ec_p384:
    KL_CALL httpasm_p384_public_key
.ec_derived:
    pop     rcx
    test    eax, eax
    jnz     .ec_no
    ; d G is the key's public half: computed from the secret d, published by every certificate
    ; of the key and compared below with the file's copy and later with a certificate's
    ; (httpasm_private_key_matches); the whole field (its octets past the point are zeros)
    HA_DECLASSIFY_MEM r12 + httpasm_private_key.public, 136   ; (public by design: the public key)
    lea     rdi, [r12 + httpasm_private_key.secret]   ; the scalar kept
    lea     rsi, [rbp + KF_SEED]
    push    rcx
    rep     movsb
    pop     rcx
    ; a public key given: the same point, uncompressed (04 x y) or compressed (02/03 x)
    mov     rdx, [rbp + KF_POINT_LENGTH]
    test    rdx, rdx
    jz      .ec_done
    movzx   eax, byte [rbp + KF_POINT]
    cmp     eax, 4
    je      .ec_uncompressed
    cmp     eax, 3
    ja      .ec_no
    cmp     eax, 2
    jb      .ec_no
    lea     r8, [rcx + 1]
    cmp     rdx, r8
    jne     .ec_no
    ; compressed: x equal, and y's parity the prefix's (02 even, 03 odd)
    movzx   r8d, byte [r12 + httpasm_private_key.public + rcx * 2]  ; y's last octet
    and     r8d, 1
    add     r8d, 2
    cmp     eax, r8d
    jne     .ec_no
    lea     rsi, [rbp + KF_POINT + 1]
    lea     rdi, [r12 + httpasm_private_key.public + 1]
    repe    cmpsb                           ; (public: points)
    jne     .ec_no
    jmp     .ec_done
.ec_uncompressed:
    lea     r8, [rcx * 2 + 1]
    cmp     rdx, r8
    jne     .ec_no
    mov     rcx, rdx
    lea     rsi, [rbp + KF_POINT]
    lea     rdi, [r12 + httpasm_private_key.public]
    repe    cmpsb                           ; (public: points)
    jne     .ec_no
.ec_done:
    mov     eax, [r12 + httpasm_private_key.kind]
    ret
.ec_no:
    mov     eax, -1
    ret

; .ed_key: rsi, rdx = a CurvePrivateKey's encoding (RFC 8410 7: an OCTET STRING of 32 or 57
; octets), the kind set -> the key prepared; eax = the kind, or -1.
.ed_key:
    mov     r13, rsi
    lea     r14, [rsi + rdx]
    lea     rdi, [rbp + KF_E1]
    call    .next
    test    eax, eax
    jnz     .ed_no
    cmp     r13, r14
    jne     .ed_no
    mov     eax, [rbp + KF_E1 + httpasm_asn1.tag]
    and     eax, ~HTTPASM_ASN1_CONSTRUCTED
    cmp     eax, HTTPASM_ASN1_OCTET_STRING
    jne     .ed_no
    test    dword [rbp + KF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_CONSTRUCTED
    jz      .ed_primitive
    ; BER-constructed: its segments into KF_SEED (57 octets of room is enough for either key)
    lea     rdi, [rbp + KF_E1]
    lea     rsi, [rbp + KF_SEED]
    mov     edx, KL_ED448_KEY
    mov     ecx, HTTPASM_ASN1_BER
    mov     r8d, KL_DEPTH
    KL_CALL ha_asn1_gather
    test    rax, rax
    js      .ed_no
    mov     rcx, rax
    lea     rsi, [rbp + KF_SEED]
    jmp     .ed_seed
.ed_primitive:
    mov     rsi, [rbp + KF_E1 + httpasm_asn1.content]
    mov     rcx, [rbp + KF_E1 + httpasm_asn1.content_length]
.ed_seed:
    mov     eax, [r12 + httpasm_private_key.kind]
    cmp     eax, HTTPASM_KEY_ED25519
    jne     .ed448
    cmp     rcx, HTTPASM_ED25519_KEY
    jne     .ed_no
    mov     dword [r12 + httpasm_private_key.bits], 256
    mov     dword [r12 + httpasm_private_key.public_length], HTTPASM_ED25519_KEY
    lea     rdi, [r12 + httpasm_private_key.secret]
    KL_CALL httpasm_ed25519_private_key_init
    lea     rsi, [r12 + httpasm_private_key.secret + httpasm_ed25519_private_key.public]
    mov     ecx, HTTPASM_ED25519_KEY
    jmp     .ed_public
.ed448:
    cmp     rcx, KL_ED448_KEY
    jne     .ed_no
    mov     dword [r12 + httpasm_private_key.bits], 448
    mov     dword [r12 + httpasm_private_key.public_length], KL_ED448_KEY
    lea     rdi, [r12 + httpasm_private_key.secret]
    KL_CALL httpasm_ed448_private_key_init
    lea     rsi, [r12 + httpasm_private_key.secret + httpasm_ed448_private_key.public]
    mov     ecx, KL_ED448_KEY
.ed_public:
    lea     rdi, [r12 + httpasm_private_key.public]
    push    rsi
    push    rcx
    rep     movsb                           ; the public key, the prepared key's own
    pop     rcx
    pop     rsi
    ; the public key A, derived from the secret seed (the prepared key's copy stays as the signer
    ; left it), is published by every certificate of the key: compared below with the file's and
    ; later with a certificate's (httpasm_private_key_matches)
    HA_DECLASSIFY_MEM r12 + httpasm_private_key.public, 136   ; (public by design: the public key)
    ; a public key given (PKCS#8 v2): the same, compared with the copy just made public (the
    ; prepared key's own octets are equal but still marked secret in the ConstantTime build)
    mov     rdx, [rbp + KF_POINT_LENGTH]
    test    rdx, rdx
    jz      .ed_done
    cmp     rdx, rcx
    jne     .ed_no
    lea     rsi, [r12 + httpasm_private_key.public]
    lea     rdi, [rbp + KF_POINT]
    repe    cmpsb                           ; (public: keys)
    jne     .ed_no
.ed_done:
    mov     eax, [r12 + httpasm_private_key.kind]
    ret
.ed_no:
    mov     eax, -1
    ret
.end:
