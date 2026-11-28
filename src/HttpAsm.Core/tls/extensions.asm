; =============================================================================
; tls/extensions.asm - TLS 1.3's extension blocks (RFC 9846 4.3): the walk over a block, which
; finds each extension the library knows by its index, and the syntax of the ones the engine
; reads.
;
; The walk (httpasm_tls_extensions_read): every extension's header and data within the block;
; no type twice in a block (4.3's MUST NOT), for all 65,536 types, by a bitmap on the stack, so a
; block of thousands of extensions costs linear time and not their square; a type 4.3's table
; knows only in the messages it names (anywhere else: illegal_parameter, the MUST of 4.3), the
; table extended with the extensions of the IANA registry's TLS 1.3 column the library meets and
; with TLS 1.2's own, which a TLS 1.3 ClientHello carries for servers of either version and which
; therefore stand in a ClientHello only; pre_shared_key last in a ClientHello (4.3.11:
; illegal_parameter). Types the table does not know are counted and passed over: a ClientHello
; may carry anything (GREASE among them), and whether an answer may is the engine's to judge
; (an extension it did not offer: unsupported_extension).
;
; The syntax (ha_tls_check_extensions): each present extension the engine reads, by the message
; it is in: its structure whole, nothing after it (4.3: decode_error), its lengths in their
; ranges, and the value rules the documents attach to them (a key_share group twice, a
; record_size_limit below 64, a binder count other than the identities': illegal_parameter).
; Extensions the library knows but does not implement are not looked into (4.3: the
; trailing-data rule "does not apply if the receiver does not implement ... an extension").
;
; Nothing here is secret: a handshake's extensions are public (the encrypted ones are the
; peer's, read after decryption, and none is a key). Answers are 0 or minus an alert.
; =============================================================================
default rel
%include "httpasm_core.inc"

section .rodata
; The index + 1 of each type below 256 that the table knows (0: unknown); the three above, by
; compare (ech_outer_extensions, encrypted_client_hello, renegotiation_info).
et_index:
    db 1, 2, 0, 0, 0, 3, 0, 0, 0, 0, 4, 5, 0, 6, 7, 8         ; 0-15
    db 9, 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 16, 17, 0, 0, 0 ; 16-31
    db 0, 0, 18, 19, 0, 0, 0, 20, 0, 21, 22, 23, 24, 25, 0, 26 ; 32-47
    db 27, 28, 29, 30, 31, 0, 0, 32, 33, 34, 35, 0, 0, 0, 0, 0 ; 48-63
    times 192 db 0                                             ; 64-255
; The messages each known extension may be in (HTTPASM_TLS_IN_* bits), by index (4.3's table and
; the IANA registry's TLS 1.3 column; TLS 1.2's extensions a ClientHello's only). The short names
; carry a T_ (CH alone is a register's name to NASM).
T_CH equ HTTPASM_TLS_IN_CH
T_SH equ HTTPASM_TLS_IN_SH
T_EE equ HTTPASM_TLS_IN_EE
T_CT equ HTTPASM_TLS_IN_CT
T_CR equ HTTPASM_TLS_IN_CR
T_NST equ HTTPASM_TLS_IN_NST
T_HRR equ HTTPASM_TLS_IN_HRR
et_allowed:
    db T_CH|T_EE|T_CR        ; 0 server_name
    db T_CH|T_EE             ; 1 max_fragment_length
    db T_CH|T_CR|T_CT        ; 2 status_request
    db T_CH|T_EE             ; 3 supported_groups
    db T_CH                  ; 4 ec_point_formats (TLS 1.2)
    db T_CH|T_CR             ; 5 signature_algorithms
    db T_CH|T_EE             ; 6 use_srtp
    db T_CH|T_EE             ; 7 heartbeat
    db T_CH|T_EE             ; 8 application_layer_protocol_negotiation
    db T_CH|T_CR|T_CT        ; 9 signed_certificate_timestamp
    db T_CH|T_EE             ; 10 client_certificate_type
    db T_CH|T_EE             ; 11 server_certificate_type
    db T_CH                  ; 12 padding
    db T_CH                  ; 13 encrypt_then_mac (TLS 1.2)
    db T_CH                  ; 14 extended_master_secret (TLS 1.2)
    db T_CH|T_CR             ; 15 compress_certificate
    db T_CH|T_EE             ; 16 record_size_limit
    db T_CH|T_CR|T_CT        ; 17 delegated_credential
    db T_CH                  ; 18 session_ticket (TLS 1.2)
    db T_CH|T_EE             ; 19 supported_ekt_ciphers
    db T_CH|T_SH             ; 20 pre_shared_key
    db T_CH|T_EE|T_NST       ; 21 early_data
    db T_CH|T_SH|T_HRR       ; 22 supported_versions
    db T_CH|T_HRR            ; 23 cookie
    db T_CH                  ; 24 psk_key_exchange_modes
    db T_CH|T_CR             ; 25 certificate_authorities
    db T_CR                  ; 26 oid_filters
    db T_CH                  ; 27 post_handshake_auth
    db T_CH|T_CR             ; 28 signature_algorithms_cert
    db T_CH|T_SH|T_HRR       ; 29 key_share
    db T_CH|T_CR|T_CT        ; 30 transparency_info
    db T_CH|T_EE             ; 31 external_id_hash
    db T_CH|T_EE             ; 32 external_session_id
    db T_CH|T_EE             ; 33 quic_transport_parameters
    db T_CH|T_EE             ; 34 ticket_request
    db T_CH                  ; 35 ech_outer_extensions
    db T_CH|T_HRR|T_EE       ; 36 encrypted_client_hello
    db T_CH                  ; 37 renegotiation_info (TLS 1.2)

section .text

; XC_U16 reg, address: reg (a 32-bit register) = the big-endian uint16 at address.
%macro XC_U16 2
    movzx   %1, word [%2]
    bswap   %1
    shr     %1, 16
%endmacro

; -----------------------------------------------------------------------------
; int httpasm_tls_extensions_read(httpasm_tls_extensions *ext, int message, const uint8_t *block,
;                                 size_t length)
;   Walks the extensions in block[0..length) (an extension block's octets, after its uint16
;   length) as found in `message` (one HTTPASM_TLS_IN_* bit): fills ext (each known extension's
;   data and length by index, the present bits, the count, the last type) and checks 4.3's rules
;   (see the header above). The data is not looked into: the message readers do that with
;   ha_tls_check_extensions. Returns 0; or -HTTPASM_TLS_ALERT_DECODE_ERROR for an extension
;   running past the block, -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER for a type twice, a known type
;   the message may not carry, or a ClientHello's pre_shared_key not last (ext's fields are then
;   unspecified). Clobbers the caller-saved registers.
;   Frame: the types seen, a 65,536-bit bitmap (8 KiB, taken a page at a time).
; -----------------------------------------------------------------------------
EW_SEEN         equ 0                       ; the bitmap
EW_FRAME        equ 8192 + 8                ; (six pushes + the frame: rsp 16-aligned)

global httpasm_tls_extensions_read:function (httpasm_tls_extensions_read.end - httpasm_tls_extensions_read)
align 16
httpasm_tls_extensions_read:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    HA_STACK_DOWN EW_FRAME, eax             ; (over a page: a page at a time, no stack clash)
    mov     rbx, rdi                        ; ext
    mov     ebp, esi                        ; the message's bit
    mov     r12, rdx                        ; the cursor
    lea     r13, [rdx + rcx]                ; the end
    xor     eax, eax
    mov     ecx, httpasm_tls_extensions_size / 8
    rep     stosq                           ; ext all zeros: nothing present
    lea     rdi, [rsp + EW_SEEN]
    mov     ecx, 8192 / 8
    rep     stosq                           ; no type seen
    lea     r14, [rel et_index]
    lea     r15, [rel et_allowed]
.next:
    cmp     r12, r13
    je      .walked
    mov     rax, r13
    sub     rax, r12
    cmp     rax, 4
    jb      .decode                         ; not even a type and a length
    XC_U16  ecx, r12                        ; the type
    XC_U16  edx, r12 + 2                    ; its data's length
    sub     rax, 4
    cmp     rdx, rax
    ja      .decode                         ; its data runs past the block
    bts     dword [rsp + EW_SEEN], ecx      ; (a bit string: the type's bit, tested then set)
    jc      .illegal                        ; twice in one block (4.3)
    inc     dword [rbx + httpasm_tls_extensions.count]
    mov     [rbx + httpasm_tls_extensions.last], ecx
    ; known? its index from the table, or the three types above 255
    mov     eax, HTTPASM_TLS_EXT_ECH_OUTER_EXTENSIONS
    cmp     ecx, 0xFD00
    je      .known
    mov     eax, HTTPASM_TLS_EXT_ENCRYPTED_CLIENT_HELLO
    cmp     ecx, 0xFE0D
    je      .known
    mov     eax, HTTPASM_TLS_EXT_RENEGOTIATION_INFO
    cmp     ecx, 0xFF01
    je      .known
    cmp     ecx, 255
    ja      .skip                           ; unknown: passed over
    movzx   eax, byte [r14 + rcx]
    dec     eax
    js      .skip                           ; (0 in the table: unknown)
.known:
    test    [r15 + rax], bpl
    jz      .illegal                        ; known, but not in this message (4.3's table)
    bts     [rbx + httpasm_tls_extensions.present], rax
    lea     rsi, [r12 + 4]
    mov     [rbx + httpasm_tls_extensions.data + rax * 8], rsi
    mov     [rbx + httpasm_tls_extensions.length + rax * 2], dx
.skip:
    lea     r12, [r12 + rdx + 4]
    jmp     .next
.walked:
    ; a ClientHello's pre_shared_key: the last extension (4.3.11)
    cmp     ebp, HTTPASM_TLS_IN_CH
    jne     .good
    bt      qword [rbx + httpasm_tls_extensions.present], HTTPASM_TLS_EXT_PRE_SHARED_KEY
    jnc     .good
    cmp     dword [rbx + httpasm_tls_extensions.last], 41
    jne     .illegal
.good:
    xor     eax, eax
.done:
    add     rsp, EW_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.decode:
    mov     eax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    jmp     .done
.illegal:
    mov     eax, -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER
    jmp     .done
.end:

; -----------------------------------------------------------------------------
; ha_tls_check_extensions: rdi = an httpasm_tls_extensions that httpasm_tls_extensions_read
;   filled, esi = the message's bit -> eax = 0, or minus the alert of the first present
;   extension (by index) whose syntax breaks its rules (see the header above). Clobbers the
;   caller-saved registers.
; -----------------------------------------------------------------------------
; XC_CHECK index, checker: when the extension of index is present, its data through checker
; (rsi = the data, rdx = its length, ebp = the message's bit), a refusal ending the walk.
%macro XC_CHECK 2
    bt      qword [rbx + httpasm_tls_extensions.present], %1
    jnc     %%absent
    mov     rsi, [rbx + httpasm_tls_extensions.data + %1 * 8]
    movzx   edx, word [rbx + httpasm_tls_extensions.length + %1 * 2]
    call    %2
    test    eax, eax
    jnz     .done
%%absent:
%endmacro

global ha_tls_check_extensions:function hidden (ha_tls_check_extensions.end - ha_tls_check_extensions)
align 16
ha_tls_check_extensions:
    push    rbx
    push    rbp
    sub     rsp, 8                          ; (two pushes + 8: rsp 16-aligned at the calls)
    mov     rbx, rdi
    mov     ebp, esi
    XC_CHECK HTTPASM_TLS_EXT_SERVER_NAME, xc_server_name
    XC_CHECK HTTPASM_TLS_EXT_SUPPORTED_GROUPS, xc_pairs16
    XC_CHECK HTTPASM_TLS_EXT_SIGNATURE_ALGORITHMS, xc_pairs16
    XC_CHECK HTTPASM_TLS_EXT_ALPN, xc_alpn
    XC_CHECK HTTPASM_TLS_EXT_COMPRESS_CERTIFICATE, xc_compression
    XC_CHECK HTTPASM_TLS_EXT_RECORD_SIZE_LIMIT, xc_record_size_limit
    XC_CHECK HTTPASM_TLS_EXT_PRE_SHARED_KEY, xc_pre_shared_key
    XC_CHECK HTTPASM_TLS_EXT_EARLY_DATA, xc_early_data
    XC_CHECK HTTPASM_TLS_EXT_SUPPORTED_VERSIONS, xc_versions
    XC_CHECK HTTPASM_TLS_EXT_COOKIE, xc_cookie
    XC_CHECK HTTPASM_TLS_EXT_PSK_KEY_EXCHANGE_MODES, xc_psk_modes
    XC_CHECK HTTPASM_TLS_EXT_CERTIFICATE_AUTHORITIES, xc_authorities
    XC_CHECK HTTPASM_TLS_EXT_OID_FILTERS, xc_oid_filters
    XC_CHECK HTTPASM_TLS_EXT_POST_HANDSHAKE_AUTH, xc_empty
    XC_CHECK HTTPASM_TLS_EXT_SIGNATURE_ALGORITHMS_CERT, xc_pairs16
    XC_CHECK HTTPASM_TLS_EXT_KEY_SHARE, xc_key_share
    XC_CHECK HTTPASM_TLS_EXT_TICKET_REQUEST, xc_ticket_request
    xor     eax, eax
.done:
    add     rsp, 8
    pop     rbp
    pop     rbx
    ret
.end:

; ---- the checkers -------------------------------------------------------------------------
;
; Each: rsi = the extension's data, rdx = its length, ebp = the message's bit -> eax = 0, or minus
; an alert. Leaves (xc_key_share's ClientHello walk aside, with a frame of its own): they clobber
; rax, rcx, rdx, rsi, rdi, r8-r11.

; xc_vector16: rsi, rdx = data -> a uint16-length vector that fills the data exactly: rcx = its
; length, rsi past the length octets, CF clear; CF set when it is not one (shorter than 2, or a
; length other than the rest). xc_vector8 the same with a uint8 length.
align 16
xc_vector16:
    cmp     rdx, 2
    jb      .no
    XC_U16  ecx, rsi
    add     rsi, 2
    sub     rdx, 2
    cmp     rcx, rdx
    jne     .no
    clc
    ret
.no:
    stc
    ret
align 16
xc_vector8:
    test    rdx, rdx
    jz      .no
    movzx   ecx, byte [rsi]
    inc     rsi
    dec     rdx
    cmp     rcx, rdx
    jne     .no
    clc
    ret
.no:
    stc
    ret

; The answers (tail-jumped to).
align 16
xc_good:
    xor     eax, eax
    ret
xc_decode:
    mov     eax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    ret
xc_illegal:
    mov     eax, -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER
    ret

; xc_empty: no data at all (post_handshake_auth, 4.3.6; early_data's in a ClientHello or
; EncryptedExtensions, 4.3.10; server_name's in EncryptedExtensions).
align 16
xc_empty:
    test    rdx, rdx
    jnz     xc_decode
    jmp     xc_good

; xc_server_name (RFC 6066 3): a ClientHello's ServerNameList<1..2^16-1>, each ServerName a
; NameType and, for host_name (0), a HostName<1..2^16-1>; one name of each type at most (its
; MUST NOT: illegal_parameter); a name type no document defines cannot be measured, so it ends
; the list (decode_error). EncryptedExtensions' (the server's acknowledgment): no data. A
; CertificateRequest's (RFC 9261's exported authenticators) is not looked into.
align 16
xc_server_name:
    cmp     ebp, HTTPASM_TLS_IN_CR
    je      xc_good
    cmp     ebp, HTTPASM_TLS_IN_CH
    jne     xc_empty
    call    xc_vector16
    jc      xc_decode
    test    rcx, rcx
    jz      xc_decode                       ; the list: one name at least
    lea     rdi, [rsi + rcx]
    xor     r8d, r8d                        ; a host_name seen
.name:
    cmp     rsi, rdi
    je      xc_good
    movzx   eax, byte [rsi]
    test    eax, eax
    jnz     xc_decode                       ; a type no document defines
    test    r8d, r8d
    jnz     xc_illegal                      ; host_name twice
    inc     r8d
    mov     rax, rdi
    sub     rax, rsi
    cmp     rax, 3
    jb      xc_decode
    XC_U16  ecx, rsi + 1
    test    ecx, ecx
    jz      xc_decode                       ; HostName<1..2^16-1>
    sub     rax, 3
    cmp     rcx, rax
    ja      xc_decode
    lea     rsi, [rsi + rcx + 3]
    jmp     .name

; xc_pairs16: a uint16-length vector of two-octet values, one at least: NamedGroup
; named_group_list<2..2^16-1> (4.3.7), SignatureScheme supported_signature_algorithms
; <2..2^16-2> (4.3.3: signature_algorithms and signature_algorithms_cert). (An even length of at
; most 2^16 - 1 octets is at most 2^16 - 2: one rule for both.)
align 16
xc_pairs16:
    call    xc_vector16
    jc      xc_decode
    cmp     rcx, 2
    jb      xc_decode
    test    ecx, 1
    jnz     xc_decode
    jmp     xc_good

; xc_alpn (RFC 7301 3.1): ProtocolNameList<2..2^16-1> of ProtocolName<1..2^8-1>; the server's
; (EncryptedExtensions) "MUST contain exactly one" name (one more or fewer: decode_error).
align 16
xc_alpn:
    call    xc_vector16
    jc      xc_decode
    cmp     rcx, 2
    jb      xc_decode
    lea     rdi, [rsi + rcx]
    xor     r8d, r8d                        ; names
.name:
    cmp     rsi, rdi
    je      .counted
    movzx   ecx, byte [rsi]
    test    ecx, ecx
    jz      xc_decode                       ; an empty name
    mov     rax, rdi
    sub     rax, rsi
    dec     rax
    cmp     rcx, rax
    ja      xc_decode
    lea     rsi, [rsi + rcx + 1]
    inc     r8d
    jmp     .name
.counted:
    cmp     ebp, HTTPASM_TLS_IN_EE
    jne     xc_good
    cmp     r8d, 1
    jne     xc_decode                       ; the server's answer: exactly one
    jmp     xc_good

; xc_compression (RFC 8879 3): CertificateCompressionAlgorithm algorithms<2..2^8-2>: pairs, one
; at least.
align 16
xc_compression:
    call    xc_vector8
    jc      xc_decode
    cmp     rcx, 2
    jb      xc_decode
    test    ecx, 1
    jnz     xc_decode
    jmp     xc_good

; xc_record_size_limit (RFC 8449 4): a uint16, 64 at least (a smaller one: illegal_parameter).
align 16
xc_record_size_limit:
    cmp     rdx, 2
    jne     xc_decode
    XC_U16  eax, rsi
    cmp     eax, 64
    jb      xc_illegal
    jmp     xc_good

; xc_pre_shared_key (4.3.11): a ClientHello's OfferedPsks: identities<7..2^16-1> of {
; identity<1..2^16-1>, uint32 obfuscated_ticket_age }, then binders<33..2^16-1> of
; PskBinderEntry<32..255> filling the rest, one binder for each identity (else
; illegal_parameter: the two lists disagree); a ServerHello's selected_identity, a uint16.
align 16
xc_pre_shared_key:
    cmp     ebp, HTTPASM_TLS_IN_CH
    je      .offered
    cmp     rdx, 2
    jne     xc_decode
    jmp     xc_good
.offered:
    lea     r9, [rsi + rdx]                 ; the data's end
    cmp     rdx, 2
    jb      xc_decode
    XC_U16  ecx, rsi
    add     rsi, 2
    cmp     rcx, 7
    jb      xc_decode
    mov     rax, r9
    sub     rax, rsi
    cmp     rcx, rax
    ja      xc_decode
    lea     rdi, [rsi + rcx]                ; the identities' end
    xor     r8d, r8d                        ; identities
.identity:
    cmp     rsi, rdi
    je      .binders
    mov     rax, rdi
    sub     rax, rsi
    cmp     rax, 2
    jb      xc_decode
    XC_U16  ecx, rsi
    test    ecx, ecx
    jz      xc_decode                       ; identity<1..2^16-1>
    sub     rax, 2
    add     rcx, 4                          ; and its obfuscated_ticket_age
    cmp     rcx, rax
    ja      xc_decode
    lea     rsi, [rsi + rcx + 2]
    inc     r8d
    jmp     .identity
.binders:
    mov     rax, r9
    sub     rax, rsi
    cmp     rax, 2
    jb      xc_decode
    XC_U16  ecx, rsi
    add     rsi, 2
    sub     rax, 2
    cmp     rcx, rax
    jne     xc_decode                       ; the binders fill the rest exactly
    cmp     rcx, 33
    jb      xc_decode
.binder:
    cmp     rsi, r9
    je      .counted
    movzx   ecx, byte [rsi]
    cmp     ecx, 32
    jb      xc_decode                       ; PskBinderEntry<32..255>
    mov     rax, r9
    sub     rax, rsi
    dec     rax
    cmp     rcx, rax
    ja      xc_decode
    lea     rsi, [rsi + rcx + 1]
    dec     r8d
    jmp     .binder
.counted:
    test    r8d, r8d
    jnz     xc_illegal                      ; a binder for each identity, no more, no fewer
    jmp     xc_good

; xc_early_data (4.3.10): no data in a ClientHello or EncryptedExtensions; a NewSessionTicket's
; uint32 max_early_data_size.
align 16
xc_early_data:
    cmp     ebp, HTTPASM_TLS_IN_NST
    jne     xc_empty
    cmp     rdx, 4
    jne     xc_decode
    jmp     xc_good

; xc_versions (4.3.1): a ClientHello's ProtocolVersion versions<2..254>; a ServerHello's and a
; HelloRetryRequest's selected_version, a uint16.
align 16
xc_versions:
    cmp     ebp, HTTPASM_TLS_IN_CH
    je      .list
    cmp     rdx, 2
    jne     xc_decode
    jmp     xc_good
.list:
    call    xc_vector8
    jc      xc_decode
    cmp     rcx, 2
    jb      xc_decode
    test    ecx, 1
    jnz     xc_decode
    jmp     xc_good

; xc_cookie (4.3.2): opaque cookie<1..2^16-1>.
align 16
xc_cookie:
    call    xc_vector16
    jc      xc_decode
    test    rcx, rcx
    jz      xc_decode
    jmp     xc_good

; xc_psk_modes (4.3.9): PskKeyExchangeMode ke_modes<1..255>.
align 16
xc_psk_modes:
    call    xc_vector8
    jc      xc_decode
    test    rcx, rcx
    jz      xc_decode
    jmp     xc_good

; xc_authorities (4.3.4): DistinguishedName authorities<3..2^16-1>, each
; DistinguishedName<1..2^16-1> (its DER is the engine's to read, or not).
align 16
xc_authorities:
    call    xc_vector16
    jc      xc_decode
    cmp     rcx, 3
    jb      xc_decode
    lea     rdi, [rsi + rcx]
.name:
    cmp     rsi, rdi
    je      xc_good
    mov     rax, rdi
    sub     rax, rsi
    cmp     rax, 2
    jb      xc_decode
    XC_U16  ecx, rsi
    test    ecx, ecx
    jz      xc_decode
    sub     rax, 2
    cmp     rcx, rax
    ja      xc_decode
    lea     rsi, [rsi + rcx + 2]
    jmp     .name

; xc_oid_filters (4.3.5): OIDFilter filters<0..2^16-1>, each { certificate_extension_oid<1..2^8-1>,
; certificate_extension_values<0..2^16-1> }.
align 16
xc_oid_filters:
    call    xc_vector16
    jc      xc_decode
    lea     rdi, [rsi + rcx]
.filter:
    cmp     rsi, rdi
    je      xc_good
    movzx   ecx, byte [rsi]
    test    ecx, ecx
    jz      xc_decode                       ; an empty OID
    mov     rax, rdi
    sub     rax, rsi
    dec     rax
    cmp     rcx, rax
    ja      xc_decode
    lea     rsi, [rsi + rcx + 1]
    sub     rax, rcx
    cmp     rax, 2
    jb      xc_decode
    XC_U16  ecx, rsi
    sub     rax, 2
    cmp     rcx, rax
    ja      xc_decode
    lea     rsi, [rsi + rcx + 2]
    jmp     .filter

; xc_key_share (4.3.8): a ClientHello's KeyShareEntry client_shares<0..2^16-1>, each { NamedGroup
; group, key_exchange<1..2^16-1> }, no group twice (a client's MUST NOT, which servers MAY check;
; this one does: illegal_parameter); a ServerHello's one KeyShareEntry, exactly; a
; HelloRetryRequest's NamedGroup selected_group.
align 16
xc_key_share:
    cmp     ebp, HTTPASM_TLS_IN_HRR
    jne     .not_retry
    cmp     rdx, 2
    jne     xc_decode
    jmp     xc_good
.not_retry:
    cmp     ebp, HTTPASM_TLS_IN_CH
    je      xc_shares
    ; a ServerHello's one entry: group, key_exchange<1..2^16-1>, nothing after
    cmp     rdx, 4
    jb      xc_decode
    XC_U16  ecx, rsi + 2
    test    ecx, ecx
    jz      xc_decode
    lea     rcx, [rcx + 4]
    cmp     rcx, rdx
    jne     xc_decode
    jmp     xc_good

; xc_shares: a ClientHello's client_shares (as xc_key_share says). The groups seen are a
; 65,536-bit bitmap on the stack (8 KiB, a page at a time): a list of up to 13,107 entries (the
; most 2^16 octets hold) is checked in linear time, where comparing each with those before it
; would cost their square, a ClientHello's worth of CPU for an attacker's one message.
XS_FRAME        equ 8192
align 16
xc_shares:
    push    rbx
    mov     rbx, rsp
    HA_STACK_DOWN XS_FRAME, eax
    mov     r8, rsi                         ; (the data: rep stosq takes rdi and rcx)
    mov     r9, rdx
    mov     rdi, rsp
    mov     ecx, XS_FRAME / 8
    xor     eax, eax
    rep     stosq                           ; no group seen
    mov     rsi, r8
    mov     rdx, r9
    call    xc_vector16
    jc      .decode
    lea     rdi, [rsi + rcx]                ; the shares' end
.share:
    cmp     rsi, rdi
    je      .good
    mov     rax, rdi
    sub     rax, rsi
    cmp     rax, 4
    jb      .decode
    XC_U16  ecx, rsi + 2
    test    ecx, ecx
    jz      .decode                         ; key_exchange<1..2^16-1>
    sub     rax, 4
    cmp     rcx, rax
    ja      .decode
    XC_U16  edx, rsi
    bts     dword [rsp], edx
    jc      .illegal                        ; a group twice
    lea     rsi, [rsi + rcx + 4]
    jmp     .share
.good:
    xor     eax, eax
.done:
    mov     rsp, rbx
    pop     rbx
    ret
.decode:
    mov     eax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    jmp     .done
.illegal:
    mov     eax, -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER
    jmp     .done

; xc_ticket_request (RFC 9149 3): a ClientHello's ClientTicketRequest { uint8 new_session_count;
; uint8 resumption_count; }; EncryptedExtensions' ServerTicketRequestHint { uint8
; expected_count; }.
align 16
xc_ticket_request:
    mov     eax, 2
    cmp     ebp, HTTPASM_TLS_IN_CH
    je      .size
    mov     eax, 1
.size:
    cmp     rdx, rax
    jne     xc_decode
    jmp     xc_good
