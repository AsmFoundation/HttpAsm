; =============================================================================
; asn1/x509.asm - an X.509 certificate's structure (RFC 5280 4.1) and its subject's public key
; (RFC 5280 4.1.2.7 with RFC 4055, 5480 and 8410): what a server reads of its own chain, to
; know its key's kind and that the key it was given is the certificate's, and what a TLS client
; reads of the peer's leaf to verify its CertificateVerify. Validation of a chain (names,
; constraints, extensions' meanings, revocation, time) is M3's: this reads, and checks the DER
; and the shape, nothing more.
;
; What is checked, in DER (RFC 5280 4.1: the signed part is DER, so the certificate is read as
; DER through the reader of asn1/asn1.asm):
;   - Certificate: tbsCertificate, signatureAlgorithm, signatureValue (whole octets), nothing
;     after; the input one element exactly.
;   - TBSCertificate, in order: version [0] (present: v2 or v3, since DER omits v1, the default:
;     X.690 11.5), serialNumber, signature (the same AlgorithmIdentifier as the outer one, octet
;     for octet: RFC 5280 4.1.1.2), issuer, validity, subject, subjectPublicKeyInfo,
;     issuerUniqueID [1] and subjectUniqueID [2] (v2 and v3 only), extensions [3] (v3 only, one
;     extension at least), nothing after.
;   - Names: SEQUENCE OF RelativeDistinguishedName, each a non-empty SET OF (DER's order)
;     AttributeTypeAndValue: an OBJECT IDENTIFIER and one value of any type.
;   - Validity: two times, UTCTime or GeneralizedTime, the latter without fractions (RFC 5280
;     4.1.2.5.2: MUST NOT); kept as seconds since 1970-01-01T00:00:00Z (UTCTime's YY as
;     1950-2049, RFC 5280 4.1.2.5.1).
;   - Extensions: each SEQUENCE { extnID, critical BOOLEAN (DER: absent when FALSE), extnValue
;     OCTET STRING }; their values are not read (M3).
;   - subjectPublicKeyInfo, by httpasm_public_key_read: rsaEncryption (parameters NULL: RFC 4055
;     1.2's MUST) with RSAPublicKey { n, e } prepared by httpasm_rsa_public_key_init;
;     id-RSASSA-PSS with its parameters (the private keys' rules); id-ecPublicKey on a named
;     curve with an uncompressed point of the curve's length (RFC 5480 2.2: compressed points
;     MAY be supported; ECDSA's verification takes the uncompressed form, so these are not); the
;     Edwards keys of 32 and 57 octets, parameters absent. The point is checked when used (the
;     curves' verification refuses one off its curve).
; =============================================================================
default rel
%include "httpasm_core.inc"

extern ha_asn1_read
extern ha_asn1_type
extern httpasm_asn1_check_set_of
extern httpasm_rsa_public_key_init

XK_DEPTH        equ 32
KL_ED448_KEY    equ 57

; KC_CALL target: target called with rsp 16-aligned whatever this file's local helpers' depth
; (keys.asm's KL_CALL). Keeps the ABI's callee-saved registers.
%macro KC_CALL 1
    push    rbx
    mov     rbx, rsp
    and     rsp, -16
    call    %1
    mov     rsp, rbx
    pop     rbx
%endmacro

section .rodata
xo_rsa:         db 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01    ; rsaEncryption
xo_pss:         db 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A    ; id-RSASSA-PSS
xo_mgf1:        db 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08
xo_ec:          db 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
xo_p256:        db 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
xo_p384:        db 0x2B, 0x81, 0x04, 0x00, 0x22
xo_p521:        db 0x2B, 0x81, 0x04, 0x00, 0x23
xo_ed25519:     db 0x2B, 0x65, 0x70
xo_ed448:       db 0x2B, 0x65, 0x71
xo_sha256:      db 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
xo_sha384:      db 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
xo_sha512:      db 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
; days before each month in a common year
xo_days:        dw 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334

section .text

; The frame both functions share (rbp = rsp after it is taken).
XF_E1           equ 0                       ; httpasm_asn1 scratch elements
XF_E2           equ 32
XF_E3           equ 64
XF_E4           equ 96
XF_E5           equ 128
XF_KEY          equ 160                     ; httpasm_asn1: a public key info's BIT STRING
XF_FRAME        equ 200                     ; (6 pushes + 200: rsp 16-aligned at calls)

; -----------------------------------------------------------------------------
; int httpasm_certificate_read(httpasm_certificate *c, const uint8_t *der, size_t length)
;   A certificate's DER: see the header above. Fills c with pointers into der (the whole TBS,
;   the serial number's contents, the issuer's, subject's and public key info's encodings, the
;   extensions' SEQUENCE or NULL, the outer signature algorithm's encoding, the signature's
;   octets), the validity's two times and the version. Returns 0, or -1 (c's fields then
;   unspecified). Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_certificate_read:function (httpasm_certificate_read.end - httpasm_certificate_read)
align 16
httpasm_certificate_read:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, XF_FRAME
    mov     rbp, rsp
    mov     r12, rdi                        ; c
    mov     r13, rsi                        ; the cursor
    lea     r14, [rsi + rdx]                ; the end
    mov     rdi, r12                        ; c starts all zeros
    mov     ecx, httpasm_certificate_size / 8
    xor     eax, eax
    rep     stosq
    ; Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    lea     rdi, [rbp + XF_E1]
    call    .next
    jnz     .bad
    cmp     r13, r14
    jne     .bad                            ; one element, the whole input
    cmp     dword [rbp + XF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .bad
    lea     rdi, [rbp + XF_E1]
    call    .enter
    lea     rdi, [rbp + XF_E2]              ; tbsCertificate
    call    .next
    jnz     .bad
    cmp     dword [rbp + XF_E2 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .bad
    mov     rax, [rbp + XF_E2 + httpasm_asn1.content]
    sub     rax, [rbp + XF_E2 + httpasm_asn1.length]
    add     rax, [rbp + XF_E2 + httpasm_asn1.content_length]
    mov     [r12 + httpasm_certificate.tbs], rax        ; (DER: header + contents)
    mov     rax, [rbp + XF_E2 + httpasm_asn1.length]
    mov     [r12 + httpasm_certificate.tbs_length], rax
    lea     rdi, [rbp + XF_E3]              ; signatureAlgorithm
    call    .next
    jnz     .bad
    cmp     dword [rbp + XF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .bad
    lea     rdi, [rbp + XF_E3]
    call    .whole
    mov     [r12 + httpasm_certificate.signature_algorithm], rax
    mov     [r12 + httpasm_certificate.signature_algorithm_length], rdx
    lea     rdi, [rbp + XF_E4]              ; signatureValue
    call    .next
    jnz     .bad
    cmp     dword [rbp + XF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_BIT_STRING
    jne     .bad
    mov     rsi, [rbp + XF_E4 + httpasm_asn1.content]
    cmp     byte [rsi], 0
    jne     .bad                            ; a signature is whole octets
    inc     rsi
    mov     [r12 + httpasm_certificate.signature], rsi
    mov     rax, [rbp + XF_E4 + httpasm_asn1.content_length]
    dec     rax
    mov     [r12 + httpasm_certificate.signature_length], rax
    cmp     r13, r14
    jne     .bad                            ; nothing after the signature

    ; ---- TBSCertificate (RFC 5280 4.1)
    lea     rdi, [rbp + XF_E2]
    call    .enter
    mov     dword [r12 + httpasm_certificate.version], 1
    lea     rdi, [rbp + XF_E4]
    call    .next
    jnz     .bad
    cmp     dword [rbp + XF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 0
    jne     .serial
    ; version [0] EXPLICIT Version: v2 (1) or v3 (2); v1 (0) is the DEFAULT, absent in DER
    push    r13
    push    r14
    lea     rdi, [rbp + XF_E4]
    call    .enter
    lea     rdi, [rbp + XF_E5]
    call    .next
    mov     ecx, -1
    jnz     .version_done
    cmp     r13, r14
    jne     .version_done
    cmp     dword [rbp + XF_E5 + httpasm_asn1.tag], HTTPASM_ASN1_INTEGER
    jne     .version_done
    cmp     qword [rbp + XF_E5 + httpasm_asn1.content_length], 1
    jne     .version_done
    mov     rax, [rbp + XF_E5 + httpasm_asn1.content]
    movzx   ecx, byte [rax]
.version_done:
    pop     r14
    pop     r13
    dec     ecx
    cmp     ecx, 1                          ; (1, 2) - 1 = 0, 1: v2, v3
    ja      .bad
    add     ecx, 2
    mov     [r12 + httpasm_certificate.version], ecx
    lea     rdi, [rbp + XF_E4]
    call    .next
    jnz     .bad
.serial:
    cmp     dword [rbp + XF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_INTEGER
    jne     .bad
    mov     rax, [rbp + XF_E4 + httpasm_asn1.content]
    mov     [r12 + httpasm_certificate.serial], rax
    mov     rax, [rbp + XF_E4 + httpasm_asn1.content_length]
    mov     [r12 + httpasm_certificate.serial_length], rax
    ; signature: the outer signatureAlgorithm, octet for octet
    lea     rdi, [rbp + XF_E4]
    call    .next
    jnz     .bad
    lea     rdi, [rbp + XF_E4]
    call    .whole
    cmp     rdx, [r12 + httpasm_certificate.signature_algorithm_length]
    jne     .bad
    mov     rsi, rax
    mov     rdi, [r12 + httpasm_certificate.signature_algorithm]
    mov     rcx, rdx
    repe    cmpsb
    jne     .bad
    ; issuer
    lea     rdi, [rbp + XF_E4]
    call    .next
    jnz     .bad
    lea     rdi, [rbp + XF_E4]
    call    .name
    jnz     .bad
    lea     rdi, [rbp + XF_E4]
    call    .whole
    mov     [r12 + httpasm_certificate.issuer], rax
    mov     [r12 + httpasm_certificate.issuer_length], rdx
    ; validity ::= SEQUENCE { notBefore Time, notAfter Time }
    lea     rdi, [rbp + XF_E4]
    call    .next
    jnz     .bad
    cmp     dword [rbp + XF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .bad
    push    r13
    push    r14
    lea     rdi, [rbp + XF_E4]
    call    .enter
    lea     rdi, [rbp + XF_E5]
    call    .next
    jnz     .validity_bad
    call    .time
    jc      .validity_bad
    mov     [r12 + httpasm_certificate.not_before], rax
    lea     rdi, [rbp + XF_E5]
    call    .next
    jnz     .validity_bad
    call    .time
    jc      .validity_bad
    mov     [r12 + httpasm_certificate.not_after], rax
    cmp     r13, r14
    jne     .validity_bad
    pop     r14
    pop     r13
    ; subject
    lea     rdi, [rbp + XF_E4]
    call    .next
    jnz     .bad
    lea     rdi, [rbp + XF_E4]
    call    .name
    jnz     .bad
    lea     rdi, [rbp + XF_E4]
    call    .whole
    mov     [r12 + httpasm_certificate.subject], rax
    mov     [r12 + httpasm_certificate.subject_length], rdx
    ; subjectPublicKeyInfo: its shape here (SEQUENCE { AlgorithmIdentifier, BIT STRING });
    ; its key by httpasm_public_key_read
    lea     rdi, [rbp + XF_E4]
    call    .next
    jnz     .bad
    cmp     dword [rbp + XF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .bad
    lea     rdi, [rbp + XF_E4]
    call    .whole
    mov     [r12 + httpasm_certificate.spki], rax
    mov     [r12 + httpasm_certificate.spki_length], rdx
    ; the unique identifiers [1], [2] (v2, v3) and the extensions [3] (v3), in order
    xor     ebx, ebx                        ; the last of them seen: 0 none, 1, 2, 3
.optional:
    cmp     r13, r14
    je      .read
    lea     rdi, [rbp + XF_E4]
    call    .next
    jnz     .bad
    mov     eax, [rbp + XF_E4 + httpasm_asn1.tag]
    cmp     eax, HTTPASM_ASN1_CONTEXT | 1   ; issuerUniqueID [1] IMPLICIT BIT STRING
    je      .unique
    cmp     eax, HTTPASM_ASN1_CONTEXT | 2   ; subjectUniqueID [2]
    je      .unique
    cmp     eax, HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 3
    jne     .bad
    cmp     ebx, 3
    jae     .bad
    mov     ebx, 3
    cmp     dword [r12 + httpasm_certificate.version], 3
    jne     .bad                            ; extensions: v3 only
    call    .extensions
    jnz     .bad
    jmp     .optional
.unique:
    and     eax, HTTPASM_ASN1_NUMBER
    cmp     eax, ebx
    jbe     .bad                            ; out of order, or twice
    mov     ebx, eax
    cmp     dword [r12 + httpasm_certificate.version], 2
    jb      .bad                            ; v2 and v3 only
    lea     rdi, [rbp + XF_E4]
    mov     esi, HTTPASM_ASN1_BIT_STRING
    mov     edx, HTTPASM_ASN1_DER
    mov     ecx, XK_DEPTH
    KC_CALL ha_asn1_type
    test    eax, eax
    jnz     .bad
    jmp     .optional
.read:
    xor     eax, eax
.done:
    add     rsp, XF_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.validity_bad:
    pop     r14
    pop     r13
.bad:
    mov     eax, -1
    jmp     .done

; ---- the certificate's helpers (local: rbp's frame, the cursor r13..r14) --------------------

; .next: rdi = a slot -> the element at the cursor read into it under DER, the cursor past it;
; ZF set (eax 0) when it read, clear (eax -1) otherwise (also at the end).
.next:
    push    rdi
    mov     rsi, r13
    mov     rdx, r14
    sub     rdx, r13
    mov     ecx, HTTPASM_ASN1_DER
    mov     r8d, XK_DEPTH
    KC_CALL ha_asn1_read
    pop     rdi
    test    eax, eax
    jnz     .next_end
    add     r13, [rdi + httpasm_asn1.length]
    xor     eax, eax
.next_end:
    ret

; .enter: rdi = a constructed element -> the cursor over its contents.
.enter:
    mov     r13, [rdi + httpasm_asn1.content]
    mov     r14, [rdi + httpasm_asn1.content_length]
    add     r14, r13
    ret

; .whole: rdi = a DER element -> rax = its encoding's start, rdx = its length (DER's lengths are
; definite: the header is the length less the contents).
.whole:
    mov     rdx, [rdi + httpasm_asn1.length]
    mov     rax, [rdi + httpasm_asn1.content]
    sub     rax, rdx
    add     rax, [rdi + httpasm_asn1.content_length]
    ret

; .name: rdi = a Name -> ZF set when it is RDNSequence's shape: a SEQUENCE OF non-empty SET OF
; (in DER's order) SEQUENCE { OBJECT IDENTIFIER, a value }. Keeps r13, r14.
.name:
    cmp     dword [rdi + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .name_no
    push    r13
    push    r14
    call    .enter
.name_rdn:
    cmp     r13, r14
    je      .name_yes
    lea     rdi, [rbp + XF_E5]
    call    .next
    jnz     .name_pop
    cmp     dword [rbp + XF_E5 + httpasm_asn1.tag], HTTPASM_ASN1_SET
    jne     .name_pop
    cmp     qword [rbp + XF_E5 + httpasm_asn1.content_length], 0
    je      .name_pop                       ; SET SIZE (1..MAX)
    lea     rdi, [rbp + XF_E5]
    mov     esi, HTTPASM_ASN1_DER
    KC_CALL httpasm_asn1_check_set_of       ; DER's order (X.690 11.6), each component read
    test    eax, eax
    jnz     .name_pop
    ; each AttributeTypeAndValue: SEQUENCE { type OBJECT IDENTIFIER, value ANY }
    push    r13
    push    r14
    lea     rdi, [rbp + XF_E5]
    call    .enter
.name_atv:
    cmp     r13, r14
    je      .name_atv_done
    lea     rdi, [rbp + XF_E1]              ; (the Certificate's slot: no longer needed)
    call    .next
    jnz     .name_atv_bad
    cmp     dword [rbp + XF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .name_atv_bad
    push    r13
    push    r14
    lea     rdi, [rbp + XF_E1]
    call    .enter
    lea     rdi, [rbp + XF_E3]
    call    .next
    jnz     .name_pair_bad
    cmp     dword [rbp + XF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_OID
    jne     .name_pair_bad
    lea     rdi, [rbp + XF_E3]
    call    .next
    jnz     .name_pair_bad
    cmp     r13, r14
    jne     .name_pair_bad
    pop     r14
    pop     r13
    jmp     .name_atv
.name_pair_bad:
    pop     r14
    pop     r13
.name_atv_bad:
    pop     r14
    pop     r13
    jmp     .name_pop
.name_atv_done:
    pop     r14
    pop     r13
    jmp     .name_rdn
.name_yes:
    pop     r14
    pop     r13
    xor     eax, eax
    ret
.name_pop:
    pop     r14
    pop     r13
.name_no:
    or      eax, -1                         ; ZF clear
    ret

; .extensions: XF_E4 = [3] EXPLICIT Extensions -> ZF set when it holds one SEQUENCE OF one
; Extension at least, each SEQUENCE { extnID, critical BOOLEAN (absent when FALSE: X.690 11.5),
; extnValue OCTET STRING }. The SEQUENCE is kept in the certificate. Keeps r13, r14.
.extensions:
    push    r13
    push    r14
    lea     rdi, [rbp + XF_E4]
    call    .enter
    lea     rdi, [rbp + XF_E4]
    call    .next
    jnz     .ext_bad
    cmp     r13, r14
    jne     .ext_bad                        ; [3] holds the one SEQUENCE
    cmp     dword [rbp + XF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .ext_bad
    cmp     qword [rbp + XF_E4 + httpasm_asn1.content_length], 0
    je      .ext_bad                        ; SIZE (1..MAX)
    lea     rdi, [rbp + XF_E4]
    call    .whole
    mov     [r12 + httpasm_certificate.extensions], rax
    mov     [r12 + httpasm_certificate.extensions_length], rdx
    lea     rdi, [rbp + XF_E4]
    call    .enter
.ext_one:
    cmp     r13, r14
    je      .ext_good
    lea     rdi, [rbp + XF_E5]
    call    .next
    jnz     .ext_bad
    cmp     dword [rbp + XF_E5 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .ext_bad
    push    r13
    push    r14
    lea     rdi, [rbp + XF_E5]
    call    .enter
    lea     rdi, [rbp + XF_E3]
    call    .next
    jnz     .ext_pair_bad
    cmp     dword [rbp + XF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_OID
    jne     .ext_pair_bad
    lea     rdi, [rbp + XF_E3]
    call    .next
    jnz     .ext_pair_bad
    cmp     dword [rbp + XF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_BOOLEAN
    jne     .ext_value
    mov     rax, [rbp + XF_E3 + httpasm_asn1.content]
    cmp     byte [rax], 0
    je      .ext_pair_bad                   ; FALSE, the DEFAULT, encoded: not DER
    lea     rdi, [rbp + XF_E3]
    call    .next
    jnz     .ext_pair_bad
.ext_value:
    cmp     dword [rbp + XF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_OCTET_STRING
    jne     .ext_pair_bad
    cmp     r13, r14
    jne     .ext_pair_bad
    pop     r14
    pop     r13
    jmp     .ext_one
.ext_pair_bad:
    pop     r14
    pop     r13
.ext_bad:
    pop     r14
    pop     r13
    or      eax, -1
    ret
.ext_good:
    pop     r14
    pop     r13
    xor     eax, eax
    ret

; .time: XF_E5 = a Time (UTCTime or GeneralizedTime, the reader checked its DER form) -> rax =
; its seconds since 1970-01-01T00:00:00Z, CF clear; CF set for another type, or a
; GeneralizedTime with a fraction (RFC 5280 4.1.2.5.2: MUST NOT). UTCTime's YY is 1950-2049
; (RFC 5280 4.1.2.5.1). Days from the civil date by the proleptic Gregorian calendar.
.time:
    mov     rsi, [rbp + XF_E5 + httpasm_asn1.content]
    mov     eax, [rbp + XF_E5 + httpasm_asn1.tag]
    cmp     eax, HTTPASM_ASN1_UTC_TIME
    je      .time_utc
    cmp     eax, HTTPASM_ASN1_GENERALIZED_TIME
    jne     .time_no
    cmp     qword [rbp + XF_E5 + httpasm_asn1.content_length], 15
    jne     .time_no                        ; YYYYMMDDHHMMSSZ: no fraction
    call    .two
    imul    r8d, eax, 100
    add     rsi, 2
    call    .two
    add     r8d, eax                        ; the year
    add     rsi, 2
    jmp     .time_date
.time_utc:
    call    .two                            ; YY: 1950-2049
    lea     r8d, [rax + 1900]
    lea     ecx, [rax + 2000]
    cmp     eax, 50
    cmovb   r8d, ecx
    add     rsi, 2
.time_date:                                 ; r8d = the year, rsi = MMDDHHMMSS
    call    .two
    mov     r9d, eax                        ; month 1-12
    call    .two_at2
    mov     r10d, eax                       ; day
    ; days since 1970: 365 y + the leap days before the year + the month's and the day's
    mov     eax, r8d
    sub     eax, 1970
    imul    rcx, rax, 365                   ; (signed: years before 1970 give negative days)
    movsxd  rcx, ecx
    ; leap days in [1970, year): floor((y-1)/4) - floor((y-1)/100) + floor((y-1)/400) - 477
    ; (477 = those before 1970); the floors of a positive y - 1 (y >= 1, y = 0 gives -1)
    lea     eax, [r8 - 1]
    movsxd  rax, eax
    mov     r11, rax
    sar     r11, 2                          ; floor((y-1)/4) for y - 1 >= -1
    add     rcx, r11
    mov     rax, r11                        ; (y-1) / 100 and / 400 by division (y - 1 >= -1)
    lea     eax, [r8 - 1]
    movsxd  rax, eax
    cqo
    mov     r11, 100
    idiv    r11
    sub     rcx, rax
    lea     eax, [r8 - 1]
    movsxd  rax, eax
    cqo
    mov     r11, 400
    idiv    r11
    add     rcx, rax
    sub     rcx, 477
    ; the months before this one, and February's 29th of this year once past it
    lea     rax, [rel xo_days]
    movzx   eax, word [rax + r9 * 2 - 2]
    add     rcx, rax
    cmp     r9d, 2
    jbe     .time_day
    mov     eax, r8d                        ; this year leap: divisible by 4, not 100 unless 400
    test    eax, 3
    jnz     .time_day
    xor     edx, edx
    mov     r11d, 100
    div     r11d
    test    edx, edx
    jnz     .time_leap
    test    eax, 3
    jnz     .time_day
.time_leap:
    inc     rcx
.time_day:
    lea     rcx, [rcx + r10 - 1]
    imul    rcx, rcx, 86400
    add     rsi, 4
    call    .two                            ; hour
    imul    eax, eax, 3600
    add     rcx, rax
    call    .two_at2                        ; minute
    imul    eax, eax, 60
    add     rcx, rax
    add     rsi, 2
    call    .two_at2                        ; second
    add     rcx, rax
    mov     rax, rcx
    clc
    ret
.time_no:
    stc
    ret
; .two: eax = the two digits at rsi (checked by the reader); .two_at2: the two at rsi + 2.
; Clobbers edx.
.two_at2:
    movzx   eax, byte [rsi + 2]
    movzx   edx, byte [rsi + 3]
    jmp     .two_digits
.two:
    movzx   eax, byte [rsi]
    movzx   edx, byte [rsi + 1]
.two_digits:
    lea     eax, [rax + rax * 4]
    lea     eax, [rdx + rax * 2 - 528]      ; d0 * 10 + d1, less '0' * 11
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_public_key_read(httpasm_public_key *key, const uint8_t *spki, size_t length)
;   A SubjectPublicKeyInfo's DER (a certificate's spki): see the header above. Fills key: its
;   kind (HTTPASM_KEY_*), size in bits, the PSS parameters (as the private keys' rules read
;   them), the EC point or Edwards key, or the RSA key prepared. Returns the kind, or -1 (key
;   then all zeros). Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_public_key_read:function (httpasm_public_key_read.end - httpasm_public_key_read)
align 16
httpasm_public_key_read:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, XF_FRAME
    mov     rbp, rsp
    mov     r12, rdi                        ; key
    mov     r13, rsi
    lea     r14, [rsi + rdx]
    mov     rdi, r12
    mov     ecx, httpasm_public_key_size / 8
    xor     eax, eax
    rep     stosq
    lea     rdi, [rbp + XF_E1]
    call    .next
    jnz     .bad
    cmp     r13, r14
    jne     .bad
    cmp     dword [rbp + XF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .bad
    lea     rdi, [rbp + XF_E1]
    call    .enter
    lea     rdi, [rbp + XF_E2]              ; algorithm
    call    .next
    jnz     .bad
    cmp     dword [rbp + XF_E2 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .bad
    lea     rdi, [rbp + XF_E3]              ; subjectPublicKey
    call    .next
    jnz     .bad
    cmp     r13, r14
    jne     .bad
    cmp     dword [rbp + XF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_BIT_STRING
    jne     .bad
    mov     rsi, [rbp + XF_E3 + httpasm_asn1.content]
    cmp     byte [rsi], 0
    jne     .bad                            ; whole octets
    lea     rsi, [rbp + XF_E3]              ; kept apart: the parameters' parsing reuses XF_E3
    lea     rdi, [rbp + XF_KEY]
    mov     ecx, httpasm_asn1_size
    rep     movsb
    ; the algorithm and its parameters
    lea     rdi, [rbp + XF_E2]
    call    .enter
    lea     rdi, [rbp + XF_E4]
    call    .next
    jnz     .bad
    cmp     dword [rbp + XF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_OID
    jne     .bad
    xor     ebx, ebx                        ; 1: parameters present (in XF_E5)
    cmp     r13, r14
    je      .algorithm
    lea     rdi, [rbp + XF_E5]
    call    .next
    jnz     .bad
    cmp     r13, r14
    jne     .bad
    mov     ebx, 1
.algorithm:
    lea     rsi, [rel xo_rsa]
    mov     ecx, 9
    call    .oid_is
    je      .rsa
    lea     rsi, [rel xo_pss]
    mov     ecx, 9
    call    .oid_is
    je      .pss
    lea     rsi, [rel xo_ec]
    mov     ecx, 7
    call    .oid_is
    je      .ec
    test    ebx, ebx
    jnz     .bad                            ; RFC 8410 3: absent for the Edwards keys
    mov     dword [r12 + httpasm_public_key.kind], HTTPASM_KEY_ED25519
    mov     dword [r12 + httpasm_public_key.bits], 256
    mov     r15d, HTTPASM_ED25519_KEY
    lea     rsi, [rel xo_ed25519]
    mov     ecx, 3
    call    .oid_is
    je      .edwards
    mov     dword [r12 + httpasm_public_key.kind], HTTPASM_KEY_ED448
    mov     dword [r12 + httpasm_public_key.bits], 448
    mov     r15d, KL_ED448_KEY
    lea     rsi, [rel xo_ed448]
    mov     ecx, 3
    call    .oid_is
    je      .edwards
    jmp     .bad
.edwards:
    mov     rcx, [rbp + XF_KEY + httpasm_asn1.content_length]
    dec     rcx
    cmp     rcx, r15
    jne     .bad
    mov     [r12 + httpasm_public_key.point_length], ecx
    mov     rsi, [rbp + XF_KEY + httpasm_asn1.content]
    inc     rsi
    lea     rdi, [r12 + httpasm_public_key.point]
    rep     movsb
    jmp     .kind
.ec:
    test    ebx, ebx
    jz      .bad                            ; RFC 5480 2.1.1: the curve, always
    cmp     dword [rbp + XF_E5 + httpasm_asn1.tag], HTTPASM_ASN1_OID
    jne     .bad                            ; implicitCurve, specifiedCurve: MUST NOT
    mov     edx, HTTPASM_KEY_P256
    mov     r15d, 32
    mov     dword [r12 + httpasm_public_key.bits], 256
    lea     rdi, [rbp + XF_E5]
    lea     rsi, [rel xo_p256]
    mov     ecx, 8
    call    .oid_of
    je      .ec_curve
    mov     edx, HTTPASM_KEY_P384
    mov     r15d, 48
    mov     dword [r12 + httpasm_public_key.bits], 384
    lea     rdi, [rbp + XF_E5]
    lea     rsi, [rel xo_p384]
    mov     ecx, 5
    call    .oid_of
    je      .ec_curve
    mov     edx, HTTPASM_KEY_P521
    mov     r15d, 66
    mov     dword [r12 + httpasm_public_key.bits], 521
    lea     rdi, [rbp + XF_E5]
    lea     rsi, [rel xo_p521]
    mov     ecx, 5
    call    .oid_of
    jne     .bad
.ec_curve:
    mov     [r12 + httpasm_public_key.kind], edx
    ; the point: 04 || x || y (the uncompressed form only)
    mov     rcx, [rbp + XF_KEY + httpasm_asn1.content_length]
    dec     rcx
    lea     rax, [r15 * 2 + 1]
    cmp     rcx, rax
    jne     .bad
    mov     rsi, [rbp + XF_KEY + httpasm_asn1.content]
    inc     rsi
    cmp     byte [rsi], 4
    jne     .bad
    mov     [r12 + httpasm_public_key.point_length], ecx
    lea     rdi, [r12 + httpasm_public_key.point]
    rep     movsb
    jmp     .kind
.pss:
    mov     dword [r12 + httpasm_public_key.kind], HTTPASM_KEY_RSA_PSS
    test    ebx, ebx
    jz      .rsa_key                        ; absent: unbound
    call    .pss_params
    jnz     .bad
    jmp     .rsa_key
.rsa:
    mov     dword [r12 + httpasm_public_key.kind], HTTPASM_KEY_RSA
    test    ebx, ebx
    jz      .bad                            ; RFC 4055 1.2: NULL, present
    cmp     dword [rbp + XF_E5 + httpasm_asn1.tag], HTTPASM_ASN1_NULL
    jne     .bad
.rsa_key:
    ; RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }, in the BIT STRING
    mov     r13, [rbp + XF_KEY + httpasm_asn1.content]
    mov     r14, [rbp + XF_KEY + httpasm_asn1.content_length]
    add     r14, r13
    inc     r13
    lea     rdi, [rbp + XF_E1]
    call    .next
    jnz     .bad
    cmp     r13, r14
    jne     .bad
    cmp     dword [rbp + XF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .bad
    lea     rdi, [rbp + XF_E1]
    call    .enter
    lea     rdi, [rbp + XF_E2]
    call    .next
    jnz     .bad
    lea     rdi, [rbp + XF_E4]
    call    .next
    jnz     .bad
    cmp     r13, r14
    jne     .bad
    cmp     dword [rbp + XF_E2 + httpasm_asn1.tag], HTTPASM_ASN1_INTEGER
    jne     .bad
    cmp     dword [rbp + XF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_INTEGER
    jne     .bad
    mov     rax, [rbp + XF_E2 + httpasm_asn1.content]
    test    byte [rax], 0x80
    jnz     .bad                            ; negative
    mov     rax, [rbp + XF_E4 + httpasm_asn1.content]
    test    byte [rax], 0x80
    jnz     .bad
    lea     rdi, [r12 + httpasm_public_key.rsa]
    mov     rsi, [rbp + XF_E2 + httpasm_asn1.content]
    mov     rdx, [rbp + XF_E2 + httpasm_asn1.content_length]
    mov     rcx, [rbp + XF_E4 + httpasm_asn1.content]
    mov     r8, [rbp + XF_E4 + httpasm_asn1.content_length]
    KC_CALL httpasm_rsa_public_key_init
    test    eax, eax
    jnz     .bad
    ; the modulus' bits: its octets past leading zeros, less the first's zero bits
    mov     rsi, [rbp + XF_E2 + httpasm_asn1.content]
    mov     rcx, [rbp + XF_E2 + httpasm_asn1.content_length]
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
    mov     [r12 + httpasm_public_key.bits], eax
.kind:
    mov     eax, [r12 + httpasm_public_key.kind]
.done:
    add     rsp, XF_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.bad:
    mov     rdi, r12
    mov     ecx, httpasm_public_key_size / 8
    xor     eax, eax
    rep     stosq
    mov     eax, -1
    jmp     .done

; ---- the key's helpers -----------------------------------------------------------------------

; .next, .enter: as the certificate's (DER).
.next:
    push    rdi
    mov     rsi, r13
    mov     rdx, r14
    sub     rdx, r13
    mov     ecx, HTTPASM_ASN1_DER
    mov     r8d, XK_DEPTH
    KC_CALL ha_asn1_read
    pop     rdi
    test    eax, eax
    jnz     .next_end
    add     r13, [rdi + httpasm_asn1.length]
    xor     eax, eax
.next_end:
    ret
.enter:
    mov     r13, [rdi + httpasm_asn1.content]
    mov     r14, [rdi + httpasm_asn1.content_length]
    add     r14, r13
    ret

; .oid_is: XF_E4 (the algorithm), rsi = an identifier's contents, ecx = their length -> ZF set
; when equal. .oid_of: the same for the element at rdi. Keep rdx.
.oid_is:
    lea     rdi, [rbp + XF_E4]
.oid_of:
    cmp     [rdi + httpasm_asn1.content_length], rcx
    jne     .oid_no
    mov     rdi, [rdi + httpasm_asn1.content]
    repe    cmpsb
.oid_no:
    ret

; .pss_params: XF_E5 = RSASSA-PSS-params under DER -> the hash and salt in key; ZF set when
; they name SHA-256/384/512 and MGF1 over the same hash (the trailer field 1), else clear.
; Keeps r13, r14.
.pss_params:
    cmp     dword [rbp + XF_E5 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .pss_no
    push    r13
    push    r14
    lea     rdi, [rbp + XF_E5]
    call    .enter
    xor     ebx, ebx                        ; the hash
    mov     r15d, -1                        ; MGF1's hash (-1: absent, SHA-1)
    mov     dword [r12 + httpasm_public_key.pss_salt], 20
    call    .pss_field
    jc      .pss_checked
    cmp     dword [rbp + XF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 0
    jne     .pss_mgf
    lea     rdi, [rbp + XF_E1]
    call    .inner_hash
    test    eax, eax
    jz      .pss_bad
    mov     ebx, eax
    call    .pss_field
    jc      .pss_checked
.pss_mgf:
    cmp     dword [rbp + XF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 1
    jne     .pss_salt
    lea     rdi, [rbp + XF_E1]
    call    .inner_mgf
    test    eax, eax
    jz      .pss_bad
    mov     r15d, eax
    call    .pss_field
    jc      .pss_checked
.pss_salt:
    cmp     dword [rbp + XF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 2
    jne     .pss_trailer
    lea     rdi, [rbp + XF_E1]
    call    .inner_small
    test    eax, eax
    js      .pss_bad
    mov     [r12 + httpasm_public_key.pss_salt], eax
    call    .pss_field
    jc      .pss_checked
.pss_trailer:
    cmp     dword [rbp + XF_E1 + httpasm_asn1.tag], HTTPASM_ASN1_CONTEXT | HTTPASM_ASN1_CONSTRUCTED | 3
    jne     .pss_bad
    lea     rdi, [rbp + XF_E1]
    call    .inner_small
    cmp     eax, 1
    jne     .pss_bad
    cmp     r13, r14
    jne     .pss_bad
.pss_checked:
    test    ebx, ebx
    jz      .pss_bad                        ; SHA-1 (the default): no TLS 1.3 signature uses it
    cmp     r15d, ebx
    jne     .pss_bad
    mov     [r12 + httpasm_public_key.pss_hash], ebx
    pop     r14
    pop     r13
    xor     eax, eax
    ret
.pss_bad:
    pop     r14
    pop     r13
.pss_no:
    or      eax, -1
    ret
; .pss_field: the next parameter into XF_E1 -> CF set at the end; on an element that does not
; read, the parameters are refused (this call's return address dropped, .pss_bad's way).
.pss_field:
    cmp     r13, r14
    je      .pss_field_end
    lea     rdi, [rbp + XF_E1]
    call    .next
    jnz     .pss_field_bad
    clc
    ret
.pss_field_end:
    stc
    ret
.pss_field_bad:
    add     rsp, 8
    jmp     .pss_bad

; .inner: rdi = an EXPLICIT [n] -> ZF set with its one element in XF_E2 (the cursor kept).
.inner:
    push    r13
    push    r14
    call    .enter
    lea     rdi, [rbp + XF_E2]
    call    .next
    jnz     .inner_done
    cmp     r13, r14                        ; (ZF: the one element)
.inner_done:
    pop     r14
    pop     r13
    ret
; .inner_hash: rdi = [n] { AlgorithmIdentifier of a hash } -> eax = its HTTPASM_HASH_*, or 0.
.inner_hash:
    call    .inner
    jnz     .hash_none
    lea     rdi, [rbp + XF_E2]
    jmp     .hash_of
; .inner_mgf: rdi = [1] { AlgorithmIdentifier { id-mgf1, AlgorithmIdentifier of a hash } } ->
; eax = the hash's HTTPASM_HASH_*, or 0.
.inner_mgf:
    call    .inner
    jnz     .hash_none
    cmp     dword [rbp + XF_E2 + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .hash_none
    push    r13
    push    r14
    lea     rdi, [rbp + XF_E2]
    call    .enter
    lea     rdi, [rbp + XF_E3]
    call    .next
    jnz     .mgf_none
    cmp     dword [rbp + XF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_OID
    jne     .mgf_none
    lea     rdi, [rbp + XF_E3]
    lea     rsi, [rel xo_mgf1]
    mov     ecx, 9
    call    .oid_of
    jne     .mgf_none
    lea     rdi, [rbp + XF_E2]
    call    .next
    jnz     .mgf_none
    cmp     r13, r14
    jne     .mgf_none
    pop     r14
    pop     r13
    lea     rdi, [rbp + XF_E2]
    jmp     .hash_of
.mgf_none:
    pop     r14
    pop     r13
.hash_none:
    xor     eax, eax
    ret
; .hash_of: rdi = an AlgorithmIdentifier of a hash -> eax = HTTPASM_HASH_SHA256/384/512, or 0
; (another hash; parameters other than NULL or absent). Keeps r13, r14.
.hash_of:
    cmp     dword [rdi + httpasm_asn1.tag], HTTPASM_ASN1_SEQUENCE
    jne     .hash_none
    push    r13
    push    r14
    call    .enter
    lea     rdi, [rbp + XF_E3]
    call    .next
    jnz     .hash_pop
    cmp     dword [rbp + XF_E3 + httpasm_asn1.tag], HTTPASM_ASN1_OID
    jne     .hash_pop
    cmp     r13, r14
    je      .hash_which
    lea     rdi, [rbp + XF_E4]              ; (the algorithm's slot: compared already)
    call    .next
    jnz     .hash_pop
    cmp     dword [rbp + XF_E4 + httpasm_asn1.tag], HTTPASM_ASN1_NULL
    jne     .hash_pop
    cmp     r13, r14
    jne     .hash_pop
.hash_which:
    lea     rdi, [rbp + XF_E3]
    lea     rsi, [rel xo_sha256]
    mov     ecx, 9
    call    .oid_of
    mov     eax, HTTPASM_HASH_SHA256
    je      .hash_done
    lea     rdi, [rbp + XF_E3]
    lea     rsi, [rel xo_sha384]
    mov     ecx, 9
    call    .oid_of
    mov     eax, HTTPASM_HASH_SHA384
    je      .hash_done
    lea     rdi, [rbp + XF_E3]
    lea     rsi, [rel xo_sha512]
    mov     ecx, 9
    call    .oid_of
    mov     eax, HTTPASM_HASH_SHA512
    je      .hash_done
.hash_pop:
    xor     eax, eax
.hash_done:
    pop     r14
    pop     r13
    ret
; .inner_small: rdi = [n] { INTEGER } -> eax = its value when 0 to 2^31 - 1, else -1.
.inner_small:
    call    .inner
    jnz     .small_no
    cmp     dword [rbp + XF_E2 + httpasm_asn1.tag], HTTPASM_ASN1_INTEGER
    jne     .small_no
    mov     rsi, [rbp + XF_E2 + httpasm_asn1.content]
    mov     rcx, [rbp + XF_E2 + httpasm_asn1.content_length]
    cmp     rcx, 4
    ja      .small_no
    test    byte [rsi], 0x80
    jnz     .small_no
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
.end:

; -----------------------------------------------------------------------------
; int httpasm_private_key_matches(const httpasm_private_key *key, const httpasm_public_key *pub)
;   Whether the public key (a certificate's) is the private key's: an RSA key's modulus and
;   exponent (either RSA kind with either: the TLS layer picks schemes by the certificate's
;   kind), a curve's kind and point, an Edwards key's kind and octets. Returns 0 when they are
;   one key pair, else -1. Variable time: both keys' compared parts are public.
;   Clobbers rax, rcx, rsi, rdi, the flags.
; -----------------------------------------------------------------------------
global httpasm_private_key_matches:function (httpasm_private_key_matches.end - httpasm_private_key_matches)
align 16
httpasm_private_key_matches:
    mov     eax, [rdi + httpasm_private_key.kind]
    mov     ecx, [rsi + httpasm_public_key.kind]
    test    eax, eax
    jz      .no
    cmp     eax, HTTPASM_KEY_RSA_PSS
    ja      .other
    cmp     ecx, HTTPASM_KEY_RSA_PSS
    ja      .no
    test    ecx, ecx
    jz      .no
    ; RSA: the private key begins with its prepared public key, which httpasm_rsa_public_key_init
    ; computes from n and e alone: the same octets exactly when n and e are the same
    lea     rdi, [rdi + httpasm_private_key.secret]
    lea     rsi, [rsi + httpasm_public_key.rsa]
    mov     ecx, httpasm_rsa_public_key_size
    repe    cmpsb
    jne     .no
    xor     eax, eax
    ret
.other:
    cmp     eax, ecx
    jne     .no
    mov     ecx, [rdi + httpasm_private_key.public_length]
    cmp     ecx, [rsi + httpasm_public_key.point_length]
    jne     .no
    lea     rdi, [rdi + httpasm_private_key.public]
    lea     rsi, [rsi + httpasm_public_key.point]
    repe    cmpsb
    jne     .no
    xor     eax, eax
    ret
.no:
    mov     eax, -1
    ret
.end:
