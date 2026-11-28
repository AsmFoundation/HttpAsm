; =============================================================================
; tls/server.asm - TLS 1.3's server (RFC 9846 Appendix A.2, 4.1-4.5): a connection's start, the
; ClientHello's negotiation (4.2.1), the HelloRetryRequest (4.2.4), the ServerHello (4.2.3) and
; the server's flight (EncryptedExtensions, Certificate, CertificateVerify, Finished), the key
; schedule through the master secret (7.1), and the client's Finished (4.5.3).
;
; Negotiation (docs/DESIGN.md M2 4c):
;   - the version: TLS 1.3 only until M3 (0x0304 not in supported_versions: protocol_version);
;   - the suite: the configuration's order among the client's (none: handshake_failure);
;   - the signature scheme: the client's order (signature_algorithms) among the key's (none:
;     handshake_failure); the extension is required without a PSK (missing_extension);
;   - the group: by default the configuration's first group the client sent a share for, so no
;     round trip is spent; with HTTPASM_TLS_SERVER_GROUP_ORDER, the configuration's first group
;     the client supports even when that takes a HelloRetryRequest (RFC 8448's server does so).
;     With no share to take, a HelloRetryRequest names the configuration's first group the
;     client supports (none: handshake_failure). A share for a group outside the client's own
;     supported_groups is refused (illegal_parameter: 4.3.8's MAY, as OpenSSL does);
;     supported_groups and key_share are both required without a PSK (missing_extension);
;   - the second ClientHello (4.2.2) keeps the legacy_session_id and offers the suite chosen,
;     carries exactly one share, of the group the retry named, and no early_data
;     (illegal_parameter for each);
;   - PSKs offered before 4e are passed over (a full handshake) and early data is skipped
;     (tls/engine.asm, TF_SKIP_EARLY); a client's legacy_session_id is echoed, and when it is not
;     empty one change_cipher_spec follows our first handshake message (Appendix E.4).
;
; What our messages carry: the ServerHello, key_share then supported_versions (RFC 8448's
; server's order); the HelloRetryRequest, the same with key_share's selected_group (no cookie:
; the server keeps its state); EncryptedExtensions, supported_groups (the configuration's list:
; 4.3.7's SHOULD, sent always, as RFC 8448's server does), record_size_limit when the client sent
; one (2^14 + 1: we take whole records, and the client's own limit then bounds every record we
; protect, RFC 8449), server_name empty when the client named one (RFC 6066's acknowledgment;
; choosing among names is 4f's).
;
; Constant time: the secrets go through the key schedule, the exchange and the signer, constant
; time in them; the Finished check is an OR of XORs over the whole MAC with only its verdict
; declassified. The frame (the exchange's secret, the server's handshake secret, the early and
; derived secrets, the MACs) is wiped before every return.
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "tls/engine.inc"

extern httpasm_tls13_hello_read
extern httpasm_tls13_extract
extern httpasm_tls13_derive_secret
extern httpasm_tls13_finished
extern ha_tls_draw
extern ha_tls_transcript_init
extern ha_tls_transcript_add
extern ha_tls_transcript_hash
extern ha_tls_out_free
extern ha_tls_out_plain
extern ha_tls_out_record
extern ha_tls_flight_begin
extern ha_tls_flight_put
extern ha_tls_flight_end
extern ha_tls_set_read
extern ha_tls_set_write
extern ha_tls_kex_server
extern ha_tls_kex_share_length
extern ha_tls_sign
extern ha_tls_peer_leaf
extern ha_tls_verify
extern ha_tls_request
extern httpasm_tls13_certificate_read

; The frame (rbp-based: the local subroutines below are leaves but .put, which realigns)
SV_HELLO        equ 0                               ; the ClientHello read (httpasm_tls13_hello)
SV_EXT          equ SV_HELLO + httpasm_tls13_hello.extensions
SV_PRESENT      equ SV_EXT + httpasm_tls_extensions.present
SV_DATA         equ SV_EXT + httpasm_tls_extensions.data
SV_HASH         equ (SV_HELLO + httpasm_tls13_hello_size + 15) / 16 * 16   ; a transcript hash (48)
SV_EARLY        equ SV_HASH + 48                    ; the early secret
SV_DERIVED      equ SV_EARLY + 48                   ; Derive-Secret(., "derived", "")
SV_SERVER_HS    equ SV_DERIVED + 48                 ; server_handshake_traffic_secret
SV_VERIFY       equ SV_SERVER_HS + 48               ; a Finished's verify_data
SV_MESSAGE      equ SV_VERIFY + 48                  ; a short message built: the HelloRetryRequest
                                                    ; (88 at most), EE (54), CV's header, Finished
SV_SHARE        equ SV_MESSAGE + 128                ; the client's share taken: its key_exchange
SV_SHARE_LENGTH equ SV_SHARE + 8
SV_RANK         equ SV_SHARE_LENGTH + 8             ; its group's place in our order (16: none)
SV_SH           equ SV_RANK + 8                     ; the ServerHello's first octet, in the output
SV_EXTENSIONS   equ SV_SH + 8                       ; its extensions' length field
SV_CONTEXT      equ SV_SHARE                        ; the client's Certificate (4c4): its context,
SV_CONTEXT_LENGTH equ SV_SHARE_LENGTH               ; its length, its certificate_list and its
SV_LIST         equ SV_RANK                         ; length, in the hello's slots (a call reads a
SV_LIST_LENGTH  equ SV_SH                           ; hello or a Certificate, never both)
SV_EXPECT       equ SV_SIGNATURE                    ; .take_certificate: the context the request
SV_EXPECT_LENGTH equ SV_SIGNATURE + 8               ; carried, its octets (a Certificate's call
                                                    ; signs nothing: the slots are free)
SV_SECRET       equ SV_EXTENSIONS + 8               ; the exchange's secret (1024: ffdhe8192's)
SV_SIGNATURE    equ SV_SECRET + 1024                ; the CertificateVerify's signature (1024)
SV_FRAME        equ (SV_SIGNATURE + 1024 + 15) / 16 * 16   ; (five pushes + this: aligned)
SV_SH_FIXED     equ HTTPASM_TLS_RECORD_HEADER + 4 + 2 + 32 + 1 + 32 + 2 + 1 + 2 + 8 + 6 + 6
                                                    ; a ServerHello's record but its share (the
                                                    ; longest session id echoed, key_share's and
                                                    ; supported_versions' headers), and a
                                                    ; change_cipher_spec's record after it

section .rodata
; SHA-256("HelloRetryRequest"): a HelloRetryRequest's random (4.2.3)
sv_retry_random:
    db 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91
    db 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
sv_derived:     db "derived"                ; the key schedule's labels (7.1), "tls13 " added by
sv_c_hs:        db "c hs traffic"           ; httpasm_tls13_expand_label
sv_s_hs:        db "s hs traffic"
sv_c_ap:        db "c ap traffic"
sv_s_ap:        db "s ap traffic"
sv_exp:         db "exp master"
sv_res:         db "res master"
sv_ccs:         db 1                        ; change_cipher_spec's one octet

section .text

; -----------------------------------------------------------------------------
; int httpasm_tls13_server_init(httpasm_tls13_connection *c, const httpasm_tls13_server_config *config,
;                               uint8_t *memory, size_t length)
;   Starts a server connection: zeroed, the configuration kept, memory[0..length) split into the
;   reassembly span (config->max_message octets), with client authentication configured the
;   peer-chain span (max_message again: the client's Certificate message, which is gathered
;   whole, kept for the CertificateVerify and the caller), and the output span (the rest,
;   config->output_min at least). Returns 0, or -1 when length is under config->memory, or when
;   the configuration no longer holds the bounds init gave it (nothing written). A leaf:
;   clobbers rax, rcx, rdx, rdi, r8-r11.
;   The configuration is the caller's memory, read live by every connection, and init checked it
;   once: one edited since (a caller that changed max_message, the flags, the lists' counts or
;   output_min without calling init again) is checked again here where it bounds memory, so the
;   split never passes memory's end (the spans' sum, carried out of 64 bits too, within length)
;   and the lists stay within the arrays the frames copy them into (1 to 16 groups, 1 to 4
;   suites: the EncryptedExtensions built in the server's frame holds 16 groups). A smaller
;   output_min than the flight needs is not caught (nothing here can measure a flight): the
;   engine's own room checks then fail the handshake with internal_error, inside the spans. A
;   connection started without the peer-chain span never asks for a certificate, whatever the
;   flags say later (tls/server.asm's flight).
; -----------------------------------------------------------------------------
global httpasm_tls13_server_init:function (httpasm_tls13_server_init.end - httpasm_tls13_server_init)
align 16
httpasm_tls13_server_init:
    mov     eax, -1
    cmp     rcx, [rsi + httpasm_tls13_server_config.memory]
    jb      .done
    mov     r8d, [rsi + httpasm_tls13_server_config.group_count]
    dec     r8d
    cmp     r8d, HTTPASM_TLS_GROUPS_MAX - 1
    ja      .done                           ; 0, or more than the array holds
    mov     r8d, [rsi + httpasm_tls13_server_config.suite_count]
    dec     r8d
    cmp     r8d, 4 - 1
    ja      .done
    mov     r8d, [rsi + httpasm_tls13_server_config.max_message]
    xor     r9d, r9d                        ; the peer-chain span: none without client authentication
    test    dword [rsi + httpasm_tls13_server_config.flags], HTTPASM_TLS_CLIENT_AUTH_REQUEST | HTTPASM_TLS_CLIENT_AUTH_REQUIRE
    jz      .spans
    mov     r9, r8                          ; a Certificate message's most: max_message
.spans:
    lea     r10, [r8 + r9]                  ; (two uint32s: no carry)
    add     r10, [rsi + httpasm_tls13_server_config.output_min]
    jc      .done                           ; (an output_min near 2^64: no length holds it)
    cmp     rcx, r10
    jb      .done
    mov     r10, rdx                        ; memory
    mov     r11, rcx                        ; its length
    mov     rdx, rdi                        ; the connection (rdi goes to the zeroing)
    xor     eax, eax
    mov     ecx, httpasm_tls13_connection_size / 8
    rep     stosq                           ; TS_START, no flags, no keys, no peer span
    mov     [rdx + httpasm_tls13_connection.config], rsi
    mov     [rdx + httpasm_tls13_connection.message], r10
    mov     [rdx + httpasm_tls13_connection.message_capacity], r8
    add     r10, r8                         ; past the reassembly span
    test    r9, r9
    jz      .output
    mov     [rdx + httpasm_tls13_connection.peer], r10
    mov     [rdx + httpasm_tls13_connection.peer_capacity], r9
    add     r10, r9
.output:
    mov     [rdx + httpasm_tls13_connection.output], r10
    sub     r11, r8
    sub     r11, r9
    mov     [rdx + httpasm_tls13_connection.output_capacity], r11
    xor     eax, eax
.done:
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_request_certificate(httpasm_tls13_connection *c)
;   Post-handshake authentication (4.7.2): queues a CertificateRequest - a context of TA_CONTEXT
;   random octets (unpredictable, 4.4.2-4.2.1#3: the configuration's source draws them) and the
;   handshake's signature_algorithms - in one record under our application key. The client's
;   answer (Certificate, CertificateVerify for one with certificates, Finished) is then taken by
;   httpasm_tls13_receive, application data and KeyUpdates allowed before it begins (4.7.2-3#1)
;   and refused between its messages (4.7.2-1#5); its end is the event AUTHENTICATED, and the
;   chain httpasm_tls13_peer_certificates' (0 entries: declined; the engine refuses nothing for
;   that: the caller decides). Returns 0; or -1 with nothing sent or changed: the handshake not
;   completed, the connection failed or our close_notify sent, the client not having offered
;   post_handshake_auth (4.3.6-1#1), no peer-chain span (client authentication not configured
;   when the connection started), a request already outstanding (one at a time), the random
;   source failing, or no room in the output (drain it and call again).
;   Frame: the message (51 octets). Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
RQ_MESSAGE      equ 0                       ; the CertificateRequest built
RQ_LENGTH       equ 4 + 1 + TA_CONTEXT + 2 + (TE_REQUEST_LENGTH - 7)  ; 51: the handshake's
                                            ; request with our context in its empty one's place
global httpasm_tls13_request_certificate:function (httpasm_tls13_request_certificate.end - httpasm_tls13_request_certificate)
align 16
httpasm_tls13_request_certificate:
    push    rbx
    sub     rsp, 64                         ; (one push + 64: rsp 16-aligned at the calls)
    mov     rbx, rdi
    mov     eax, -1
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_CONNECTED
    jne     .done                           ; (FAILED included)
    test    dword [rbx + httpasm_tls13_connection.flags], TF_CLOSED
    jnz     .done
    test    dword [rbx + httpasm_tls13_connection.flags], TF_POST_AUTH
    jz      .done                           ; the client did not offer it (4.3.6-1#1)
    cmp     qword [rbx + httpasm_tls13_connection.peer], 0
    je      .done                           ; nowhere to keep its chain
    cmp     dword [rbx + httpasm_tls13_connection.auth_state], TA_NONE
    jne     .done                           ; one outstanding already
    ; the message: 13, its length; the context; signature_algorithms as the handshake's request
    ; carries it (ha_tls_request: its extensions' length and block after its empty context)
    mov     dword [rsp + RQ_MESSAGE], ((RQ_LENGTH - 4) << 24) | HTTPASM_TLS_CERTIFICATE_REQUEST
    mov     byte [rsp + RQ_MESSAGE + 4], TA_CONTEXT
    lea     rdi, [rsp + RQ_MESSAGE + 5]
    mov     esi, TA_CONTEXT
    call    ha_tls_draw
    test    rax, rax
    jnz     .refused
    lea     rdi, [rsp + RQ_MESSAGE + 5 + TA_CONTEXT]
    lea     rsi, [rel ha_tls_request + 5]
    mov     ecx, TE_REQUEST_LENGTH - 5
    rep     movsb
    ; one record (52 octets of content: within the smallest record_size_limit, 64)
    mov     esi, HTTPASM_TLS_CONTENT_HANDSHAKE
    lea     rdx, [rsp + RQ_MESSAGE]
    mov     ecx, RQ_LENGTH
    xor     r8d, r8d                        ; (the alert reserve stays)
    call    ha_tls_out_record
    test    eax, eax
    jnz     .refused
    ; the exchange's transcript: the handshake's kept aside, the request after it (4.4's
    ; Handshake Context: ClientHello .. client Finished + CertificateRequest)
    lea     rdi, [rbx + httpasm_tls13_connection.auth_base]
    lea     rsi, [rbx + httpasm_tls13_connection.transcript]
    mov     ecx, httpasm_sha512_ctx_size
    rep     movsb
    lea     rdi, [rbx + httpasm_tls13_connection.auth_context]
    lea     rsi, [rsp + RQ_MESSAGE + 5]
    mov     ecx, TA_CONTEXT
    rep     movsb
    lea     rsi, [rsp + RQ_MESSAGE]
    mov     edx, RQ_LENGTH
    call    ha_tls_transcript_add
    mov     dword [rbx + httpasm_tls13_connection.auth_state], TA_CERT
    xor     eax, eax
    jmp     .done
.refused:
    mov     eax, -1
.done:
    add     rsp, 64
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_tls_server_message: rbx = the connection (before TS_CONNECTED), rsi = a whole handshake
;   message (header and body), rdx = its octets -> eax = TM_* flags, or minus an alert (the
;   connection is failed by the caller). START and WAIT_CH2 take a ClientHello, WAIT_CERT the
;   client's Certificate, WAIT_CV its CertificateVerify, WAIT_FINISHED its Finished; anything
;   else is unexpected_message. Clobbers the caller-saved registers; rbx kept.
; -----------------------------------------------------------------------------
global ha_tls_server_message:function hidden (ha_tls_server_message.end - ha_tls_server_message)
align 16
ha_tls_server_message:
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, SV_FRAME
    mov     rbp, rsp                        ; the frame's base
    mov     r12, rsi                        ; the message
    mov     r13, rdx
    movzx   eax, byte [r12]
    mov     ecx, [rbx + httpasm_tls13_connection.state]
    cmp     ecx, TS_WAIT_FINISHED
    je      .wait_finished
    cmp     ecx, TS_WAIT_CERT
    je      .wait_cert
    cmp     ecx, TS_WAIT_CV
    je      .wait_cv
    cmp     ecx, TS_CONNECTED
    je      .post_auth                      ; (tls/engine.asm took a KeyUpdate itself)
    cmp     ecx, TS_WAIT_CH2
    ja      .unexpected                     ; (never: FAILED does not call in)
    cmp     eax, HTTPASM_TLS_CLIENT_HELLO
    jne     .unexpected

    ; ---- the ClientHello's own rules (tls/messages.asm)
    lea     rdi, [rbp + SV_HELLO]
    mov     esi, HTTPASM_TLS_CLIENT_HELLO
    lea     rdx, [r12 + 4]
    lea     rcx, [r13 - 4]
    call    httpasm_tls13_hello_read
    test    eax, eax
    jnz     .answer
    ; legacy_version 0x0303 (4.2.2: a server receiving another value MUST abort with
    ; protocol_version; TLS 1.2 and older clients, M3's, send it too), then TLS 1.3 offered
    ; (4.3.1): the one version spoken until M3
    cmp     word [rbp + SV_HELLO + httpasm_tls13_hello.legacy_version], 0x0303
    jne     .protocol_version
    bt      qword [rbp + SV_PRESENT], HTTPASM_TLS_EXT_SUPPORTED_VERSIONS
    jnc     .protocol_version
    mov     rsi, [rbp + SV_DATA + HTTPASM_TLS_EXT_SUPPORTED_VERSIONS * 8]
    movzx   ecx, byte [rsi]                 ; the list's octets (its syntax checked: pairs)
    inc     rsi
    mov     edx, 0x0304
    call    .find_pair
    jnc     .protocol_version
    ; the client's record_size_limit (RFC 8449), 2^14 + 1 at most, bounds what we protect
    xor     eax, eax
    bt      qword [rbp + SV_PRESENT], HTTPASM_TLS_EXT_RECORD_SIZE_LIMIT
    jnc     .limited
    mov     rsi, [rbp + SV_DATA + HTTPASM_TLS_EXT_RECORD_SIZE_LIMIT * 8]
    movzx   eax, word [rsi]                 ; (checked: two octets, 64 at least)
    xchg    al, ah
    mov     ecx, HTTPASM_TLS_INNER_MAX
    cmp     eax, ecx
    cmova   eax, ecx
.limited:
    mov     [rbx + httpasm_tls13_connection.peer_limit], ax
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_WAIT_CH2
    je      .second

    ; ---- the first ClientHello: the suite, by our order among the client's
    mov     r8, [rbx + httpasm_tls13_connection.config]
    xor     r9d, r9d
.suite_next:
    cmp     r9d, [r8 + httpasm_tls13_server_config.suite_count]
    jae     .handshake_failure
    movzx   edx, word [r8 + httpasm_tls13_server_config.suites + r9 * 2]
    mov     rsi, [rbp + SV_HELLO + httpasm_tls13_hello.cipher_suites]
    mov     ecx, [rbp + SV_HELLO + httpasm_tls13_hello.cipher_suites_length]
    call    .find_pair
    jc      .suite_found
    inc     r9d
    jmp     .suite_next
.suite_found:
    mov     [rbx + httpasm_tls13_connection.suite], dx
    mov     byte [rbx + httpasm_tls13_connection.hash], HTTPASM_HASH_SHA256
    mov     byte [rbx + httpasm_tls13_connection.hash_length], 32
    cmp     edx, HTTPASM_TLS_AES_256_GCM_SHA384
    jne     .suite_hashed
    mov     byte [rbx + httpasm_tls13_connection.hash], HTTPASM_HASH_SHA384
    mov     byte [rbx + httpasm_tls13_connection.hash_length], 48
.suite_hashed:
    ; the legacy_session_id, kept to echo (and for the second hello to repeat); not empty:
    ; middlebox compatibility (Appendix E.4)
    movzx   ecx, byte [rbp + SV_HELLO + httpasm_tls13_hello.session_id_length]
    mov     [rbx + httpasm_tls13_connection.session_id_length], cl
    lea     rdi, [rbx + httpasm_tls13_connection.session_id]
    mov     rsi, [rbp + SV_HELLO + httpasm_tls13_hello.session_id]
    rep     movsb
    cmp     byte [rbx + httpasm_tls13_connection.session_id_length], 0
    je      .compat_known
    or      dword [rbx + httpasm_tls13_connection.flags], TF_COMPAT
.compat_known:
    ; early data offered: not taken (no PSK before 4e), so its records are skipped (4.3.10)
    bt      qword [rbp + SV_PRESENT], HTTPASM_TLS_EXT_EARLY_DATA
    jnc     .early_known
    or      dword [rbx + httpasm_tls13_connection.flags], TF_SKIP_EARLY
.early_known:
    bt      qword [rbp + SV_PRESENT], HTTPASM_TLS_EXT_POST_HANDSHAKE_AUTH
    jnc     .negotiate
    or      dword [rbx + httpasm_tls13_connection.flags], TF_POST_AUTH
    jmp     .negotiate

.second:
    ; ---- the second ClientHello (4.2.2): what the retry asked for changed, and nothing else:
    ; the same legacy_session_id
    movzx   ecx, byte [rbp + SV_HELLO + httpasm_tls13_hello.session_id_length]
    cmp     cl, [rbx + httpasm_tls13_connection.session_id_length]
    jne     .illegal
    mov     rsi, [rbp + SV_HELLO + httpasm_tls13_hello.session_id]
    lea     rdi, [rbx + httpasm_tls13_connection.session_id]
    repe    cmpsb                           ; (no octets: ZF still the length compare's)
    jne     .illegal
    ; the suite the retry chose, offered still
    movzx   edx, word [rbx + httpasm_tls13_connection.suite]
    mov     rsi, [rbp + SV_HELLO + httpasm_tls13_hello.cipher_suites]
    mov     ecx, [rbp + SV_HELLO + httpasm_tls13_hello.cipher_suites_length]
    call    .find_pair
    jnc     .illegal
    ; no early data after a HelloRetryRequest (4.3.10)
    bt      qword [rbp + SV_PRESENT], HTTPASM_TLS_EXT_EARLY_DATA
    jc      .illegal

.negotiate:
    ; ---- the signature scheme: the client's order among the key's (4.3.3)
    bt      qword [rbp + SV_PRESENT], HTTPASM_TLS_EXT_SIGNATURE_ALGORITHMS
    jnc     .missing
    mov     rsi, [rbp + SV_DATA + HTTPASM_TLS_EXT_SIGNATURE_ALGORITHMS * 8]
    movzx   ecx, word [rsi]
    xchg    cl, ch                          ; the list's octets (checked: pairs, one at least)
    add     rsi, 2
    mov     r8, [rbx + httpasm_tls13_connection.config]
    mov     r9, [r8 + httpasm_tls13_server_config.schemes]
.scheme_next:
    test    ecx, ecx
    jz      .handshake_failure
    movzx   eax, word [rsi]
    xchg    al, ah
    call    .scheme_bit
    test    eax, eax
    js      .scheme_skip
    bt      r9, rax
    jc      .scheme_found
.scheme_skip:
    add     rsi, 2
    sub     ecx, 2
    jmp     .scheme_next
.scheme_found:
    movzx   eax, word [rsi]
    xchg    al, ah
    mov     [rbx + httpasm_tls13_connection.scheme], ax

    ; ---- the groups (9.2: both lists required without a PSK)
    bt      qword [rbp + SV_PRESENT], HTTPASM_TLS_EXT_SUPPORTED_GROUPS
    jnc     .missing
    bt      qword [rbp + SV_PRESENT], HTTPASM_TLS_EXT_KEY_SHARE
    jnc     .missing
    mov     r14, [rbp + SV_DATA + HTTPASM_TLS_EXT_SUPPORTED_GROUPS * 8]
    movzx   r15d, word [r14]
    rol     r15w, 8                         ; the list's octets
    add     r14, 2                          ; the client's supported_groups
    ; every share's group the client's own (4.3.8's MAY); the best share: its group's place in
    ; our order the lowest
    mov     qword [rbp + SV_RANK], HTTPASM_TLS_GROUPS_MAX
    mov     r8, [rbp + SV_DATA + HTTPASM_TLS_EXT_KEY_SHARE * 8]
    movzx   r9d, word [r8]
    rol     r9w, 8
    add     r8, 2
    add     r9, r8                          ; the shares' end (checked: whole entries)
.share_next:
    cmp     r8, r9
    jae     .shares_done
    movzx   r11d, word [r8]
    rol     r11w, 8                         ; the share's group
    mov     edx, r11d
    mov     rsi, r14
    mov     ecx, r15d
    call    .find_pair
    jnc     .illegal                        ; a share for a group the client does not support
    mov     rax, [rbx + httpasm_tls13_connection.config]
    xor     ecx, ecx
.rank_next:
    cmp     ecx, [rax + httpasm_tls13_server_config.group_count]
    jae     .share_skip                     ; not one of ours
    cmp     r11w, [rax + httpasm_tls13_server_config.groups + rcx * 2]
    je      .ranked
    inc     ecx
    jmp     .rank_next
.ranked:
    cmp     rcx, [rbp + SV_RANK]
    jae     .share_skip
    mov     [rbp + SV_RANK], rcx
    lea     rax, [r8 + 4]
    mov     [rbp + SV_SHARE], rax
    movzx   eax, word [r8 + 2]
    rol     ax, 8
    mov     [rbp + SV_SHARE_LENGTH], rax
.share_skip:
    movzx   eax, word [r8 + 2]
    rol     ax, 8
    lea     r8, [r8 + rax + 4]
    jmp     .share_next
.shares_done:
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_WAIT_CH2
    je      .second_share
    ; the group: our first one the client supports, when our order rules (it may cost a retry)
    mov     rax, [rbx + httpasm_tls13_connection.config]
    test    dword [rax + httpasm_tls13_server_config.flags], HTTPASM_TLS_SERVER_GROUP_ORDER
    jz      .by_share
    call    .first_supported                ; -> r9d = its place, CF set when there is one
    jnc     .handshake_failure
    cmp     r9, [rbp + SV_RANK]
    jne     .retry_group                    ; no share for it: a retry asks for one
    jmp     .chosen
.by_share:
    cmp     qword [rbp + SV_RANK], HTTPASM_TLS_GROUPS_MAX
    jb      .chosen
    ; no share we take: a HelloRetryRequest for our first group the client supports (4.2.4)
    call    .first_supported
    jnc     .handshake_failure
.retry_group:
    mov     rax, [rbx + httpasm_tls13_connection.config]
    movzx   edx, word [rax + httpasm_tls13_server_config.groups + r9 * 2]
    jmp     .retry
.second_share:
    ; one share exactly, of the group the retry named (4.2.2)
    mov     r8, [rbp + SV_DATA + HTTPASM_TLS_EXT_KEY_SHARE * 8]
    movzx   eax, word [r8]
    rol     ax, 8                           ; the shares' octets
    movzx   ecx, word [r8 + 4]
    rol     cx, 8                           ; the first share's key_exchange
    add     ecx, 4
    cmp     eax, ecx
    jne     .illegal
    movzx   eax, word [r8 + 2]
    rol     ax, 8
    cmp     ax, [rbx + httpasm_tls13_connection.group]
    jne     .illegal
    cmp     qword [rbp + SV_RANK], HTTPASM_TLS_GROUPS_MAX
    jae     .illegal                        ; (never: the retry named one of ours)
    mov     rsi, r12                        ; after message_hash and the retry: this hello
    mov     rdx, r13
    call    ha_tls_transcript_add
    jmp     .exchange
.chosen:
    mov     rax, [rbp + SV_RANK]
    mov     rcx, [rbx + httpasm_tls13_connection.config]
    movzx   eax, word [rcx + httpasm_tls13_server_config.groups + rax * 2]
    mov     [rbx + httpasm_tls13_connection.group], ax
    call    ha_tls_transcript_init          ; the transcript starts with this hello (4.1)
    mov     rsi, r12
    mov     rdx, r13
    call    ha_tls_transcript_add
    jmp     .exchange

.retry:
    ; ---- the HelloRetryRequest (4.2.4), dx = the group it names. The transcript turns into
    ; message_hash: Hash(ClientHello1) in a message of its own (4.1)
    mov     [rbx + httpasm_tls13_connection.group], dx
    or      dword [rbx + httpasm_tls13_connection.flags], TF_RETRIED
    call    ha_tls_transcript_init
    mov     rsi, r12
    mov     rdx, r13
    call    ha_tls_transcript_add
    lea     rdi, [rbp + SV_HASH]
    call    ha_tls_transcript_hash
    call    ha_tls_transcript_init
    movzx   eax, byte [rbx + httpasm_tls13_connection.hash_length]
    shl     eax, 24
    or      eax, HTTPASM_TLS_MESSAGE_HASH   ; FE 00 00 Hash.length
    mov     [rbp + SV_MESSAGE], eax
    lea     rsi, [rbp + SV_MESSAGE]
    mov     edx, 4
    call    ha_tls_transcript_add
    lea     rsi, [rbp + SV_HASH]
    movzx   edx, byte [rbx + httpasm_tls13_connection.hash_length]
    call    ha_tls_transcript_add
    ; the message: a ServerHello with SHA-256("HelloRetryRequest") as random, the session id
    ; echoed, the suite, then key_share's selected_group and supported_versions
    lea     rdi, [rbp + SV_MESSAGE]
    mov     word [rdi + 4], 0x0303          ; legacy_version
    lea     rsi, [rel sv_retry_random]
    add     rdi, 6
    mov     ecx, 32
    rep     movsb
    movzx   ecx, byte [rbx + httpasm_tls13_connection.session_id_length]
    mov     [rdi], cl
    inc     rdi
    lea     rsi, [rbx + httpasm_tls13_connection.session_id]
    rep     movsb
    movzx   eax, word [rbx + httpasm_tls13_connection.suite]
    xchg    al, ah
    mov     [rdi], ax
    mov     byte [rdi + 2], 0               ; legacy_compression_method
    mov     word [rdi + 3], 0x0C00          ; extensions: 12 octets
    mov     dword [rdi + 5], 0x02003300     ; key_share: 00 33 00 02
    movzx   eax, word [rbx + httpasm_tls13_connection.group]
    xchg    al, ah
    mov     [rdi + 9], ax                   ; selected_group
    mov     dword [rdi + 11], 0x02002B00    ; supported_versions: 00 2b 00 02
    mov     word [rdi + 15], 0x0403         ; 03 04
    add     rdi, 17
    lea     rax, [rbp + SV_MESSAGE]
    sub     rdi, rax
    mov     r12, rdi                        ; the message's octets
    lea     eax, [rdi - 4]
    bswap   eax
    mov     al, HTTPASM_TLS_SERVER_HELLO
    mov     [rbp + SV_MESSAGE], eax
    lea     rsi, [rbp + SV_MESSAGE]
    mov     rdx, r12
    call    ha_tls_transcript_add
    mov     esi, HTTPASM_TLS_CONTENT_HANDSHAKE
    lea     rdx, [rbp + SV_MESSAGE]
    mov     rcx, r12
    xor     r8d, r8d
    call    ha_tls_out_plain
    test    eax, eax
    jnz     .answer
    test    dword [rbx + httpasm_tls13_connection.flags], TF_COMPAT
    jz      .retried
    call    .ccs
    test    eax, eax
    jnz     .answer
.retried:
    mov     dword [rbx + httpasm_tls13_connection.state], TS_WAIT_CH2
    mov     eax, TM_BOUNDARY                ; nothing may follow the first hello in its record
    jmp     .answer

.exchange:
    ; ---- the ServerHello, built where its record goes: the room first (the queued output moved
    ; to the front), then the random (the first draw), then our share, made in place
    xor     edx, edx
    call    ha_tls_out_free
    mov     r14, rax
    movzx   edi, word [rbx + httpasm_tls13_connection.group]
    call    ha_tls_kex_share_length         ; our share in this group (the configuration's table)
    add     eax, SV_SH_FIXED
    cmp     r14, rax
    jb      .internal                       ; (the configuration's output_min holds it: only a
                                            ; caller that left output untaken meets this)
    mov     rdi, [rbx + httpasm_tls13_connection.output]
    add     rdi, [rbx + httpasm_tls13_connection.output_end]
    add     rdi, HTTPASM_TLS_RECORD_HEADER
    mov     [rbp + SV_SH], rdi
    mov     word [rdi + 4], 0x0303          ; legacy_version (4.2.3)
    add     rdi, 6
    mov     esi, 32
    call    ha_tls_draw                     ; the random
    test    eax, eax
    jnz     .answer
    mov     rdi, [rbp + SV_SH]
    add     rdi, 38
    movzx   ecx, byte [rbx + httpasm_tls13_connection.session_id_length]
    mov     [rdi], cl                       ; legacy_session_id_echo
    inc     rdi
    lea     rsi, [rbx + httpasm_tls13_connection.session_id]
    rep     movsb
    movzx   eax, word [rbx + httpasm_tls13_connection.suite]
    xchg    al, ah
    mov     [rdi], ax                       ; cipher_suite
    mov     byte [rdi + 2], 0               ; legacy_compression_method
    mov     [rbp + SV_EXTENSIONS], rdi      ; (+3: the extensions' length, set below)
    mov     word [rdi + 5], 0x3300          ; key_share: 00 33, its length below
    movzx   eax, word [rbx + httpasm_tls13_connection.group]
    xchg    al, ah
    mov     [rdi + 9], ax                   ; KeyShareEntry.group
    movzx   edi, word [rbx + httpasm_tls13_connection.group]
    mov     rsi, [rbp + SV_SHARE]
    mov     rdx, [rbp + SV_SHARE_LENGTH]
    mov     rcx, [rbp + SV_EXTENSIONS]
    add     rcx, 13                         ; key_exchange: made in place
    lea     r8, [rbp + SV_SECRET]
    call    ha_tls_kex_server
    test    rax, rax
    js      .answer
    mov     r14d, eax                       ; our share's octets
    shr     rax, 32
    mov     r15d, eax                       ; the secret's
    mov     rdi, [rbp + SV_EXTENSIONS]
    mov     eax, r14d
    xchg    al, ah
    mov     [rdi + 11], ax                  ; key_exchange's length
    lea     eax, [r14 + 4]
    xchg    al, ah
    mov     [rdi + 7], ax                   ; key_share's extension_data
    lea     rsi, [rdi + 13 + r14]
    mov     dword [rsi], 0x02002B00         ; supported_versions: 00 2b 00 02
    mov     word [rsi + 4], 0x0403          ; selected_version 03 04
    lea     eax, [r14 + 8 + 6]
    xchg    al, ah
    mov     [rdi + 3], ax                   ; the extensions' length
    add     rsi, 6
    mov     rdi, [rbp + SV_SH]
    sub     rsi, rdi
    mov     r12, rsi                        ; the message's octets
    lea     eax, [rsi - 4]
    bswap   eax
    mov     al, HTTPASM_TLS_SERVER_HELLO
    mov     [rdi], eax
    mov     rsi, rdi
    mov     rdx, r12
    call    ha_tls_transcript_add
    mov     esi, HTTPASM_TLS_CONTENT_HANDSHAKE
    mov     rdx, [rbp + SV_SH]
    mov     rcx, r12
    xor     r8d, r8d
    call    ha_tls_out_plain                ; (in place: the header written, the record queued)
    test    eax, eax
    jnz     .answer
    ; one change_cipher_spec after our first handshake message (E.4), unless that was a retry
    test    dword [rbx + httpasm_tls13_connection.flags], TF_COMPAT
    jz      .secrets
    test    dword [rbx + httpasm_tls13_connection.flags], TF_RETRIED
    jnz     .secrets
    call    .ccs
    test    eax, eax
    jnz     .answer

.secrets:
    ; ---- the handshake secret: Extract(Derive-Secret(Extract(0, 0), "derived", ""), (EC)DHE)
    movzx   edi, byte [rbx + httpasm_tls13_connection.hash]
    xor     esi, esi                        ; no salt (HKDF's zeros)
    xor     edx, edx
    xor     ecx, ecx                        ; no IKM: TLS's "0" (no PSK)
    xor     r8d, r8d
    lea     r9, [rbp + SV_EARLY]
    call    httpasm_tls13_extract
    movzx   edi, byte [rbx + httpasm_tls13_connection.hash]
    lea     rsi, [rbp + SV_EARLY]
    lea     rdx, [rel sv_derived]
    mov     ecx, 7
    xor     r8d, r8d                        ; Hash("")
    lea     r9, [rbp + SV_DERIVED]
    call    httpasm_tls13_derive_secret
    movzx   edi, byte [rbx + httpasm_tls13_connection.hash]
    lea     rsi, [rbp + SV_DERIVED]
    movzx   edx, byte [rbx + httpasm_tls13_connection.hash_length]
    lea     rcx, [rbp + SV_SECRET]
    mov     r8d, r15d
    lea     r9, [rbx + httpasm_tls13_connection.secret]
    call    httpasm_tls13_extract
    ; the handshake traffic secrets, over ClientHello .. ServerHello
    lea     rdi, [rbp + SV_HASH]
    call    ha_tls_transcript_hash
    lea     rdx, [rel sv_c_hs]
    lea     r9, [rbx + httpasm_tls13_connection.client_handshake]
    call    .derive
    lea     rdx, [rel sv_s_hs]
    lea     r9, [rbp + SV_SERVER_HS]
    call    .derive
    lea     rsi, [rbx + httpasm_tls13_connection.client_handshake]
    call    ha_tls_set_read
    lea     rsi, [rbp + SV_SERVER_HS]
    call    ha_tls_set_write

    ; ---- the flight
    call    ha_tls_flight_begin
    call    .encrypted_extensions
    lea     rsi, [rbp + SV_MESSAGE]
    mov     rdx, rax
    call    .put
    test    eax, eax
    jnz     .answer
    ; CertificateRequest (4.4.2), right after EncryptedExtensions (4.4.2-1#2), when the
    ; configuration asks for the client's certificate (tls/sign.asm's ha_tls_request: an empty
    ; context, the schemes the engine verifies). A connection without the peer-chain span
    ; (a configuration edited after server_init to ask) asks nothing: it could keep no chain.
    mov     rax, [rbx + httpasm_tls13_connection.config]
    test    dword [rax + httpasm_tls13_server_config.flags], HTTPASM_TLS_CLIENT_AUTH_REQUEST | HTTPASM_TLS_CLIENT_AUTH_REQUIRE
    jz      .server_certificate
    cmp     qword [rbx + httpasm_tls13_connection.peer], 0
    je      .server_certificate
    lea     rsi, [rel ha_tls_request]
    mov     edx, TE_REQUEST_LENGTH
    call    .put
    test    eax, eax
    jnz     .answer
    or      dword [rbx + httpasm_tls13_connection.flags], TF_ASKED
.server_certificate:
    mov     rax, [rbx + httpasm_tls13_connection.config]
    mov     rsi, [rax + httpasm_tls13_server_config.certificate]
    mov     rdx, [rax + httpasm_tls13_server_config.certificate_length]
    call    .put
    test    eax, eax
    jnz     .answer
    ; CertificateVerify (4.5.2) over ClientHello .. Certificate
    lea     rdi, [rbp + SV_HASH]
    call    ha_tls_transcript_hash
    lea     rdi, [rbp + SV_SIGNATURE]
    lea     rsi, [rbp + SV_HASH]
    call    ha_tls_sign
    test    rax, rax
    js      .answer
    mov     r14d, eax                       ; the signature's octets
    lea     eax, [r14 + 4]
    bswap   eax
    mov     al, HTTPASM_TLS_CERTIFICATE_VERIFY
    mov     [rbp + SV_MESSAGE], eax
    movzx   eax, word [rbx + httpasm_tls13_connection.scheme]
    xchg    al, ah
    mov     [rbp + SV_MESSAGE + 4], ax
    mov     eax, r14d
    xchg    al, ah
    mov     [rbp + SV_MESSAGE + 6], ax
    lea     rsi, [rbp + SV_MESSAGE]
    mov     edx, 8
    call    .put
    test    eax, eax
    jnz     .answer
    lea     rsi, [rbp + SV_SIGNATURE]
    mov     edx, r14d
    call    .put
    test    eax, eax
    jnz     .answer
    ; Finished (4.5.3) over ClientHello .. CertificateVerify, under the server's handshake secret
    lea     rdi, [rbp + SV_HASH]
    call    ha_tls_transcript_hash
    movzx   edi, byte [rbx + httpasm_tls13_connection.hash]
    lea     rsi, [rbp + SV_SERVER_HS]
    lea     rdx, [rbp + SV_HASH]
    lea     rcx, [rbp + SV_MESSAGE + 4]
    call    httpasm_tls13_finished
    movzx   eax, byte [rbx + httpasm_tls13_connection.hash_length]
    shl     eax, 24
    or      eax, HTTPASM_TLS_FINISHED       ; 14 00 00 Hash.length
    mov     [rbp + SV_MESSAGE], eax
    lea     rsi, [rbp + SV_MESSAGE]
    movzx   edx, byte [rbx + httpasm_tls13_connection.hash_length]
    add     edx, 4
    call    .put
    test    eax, eax
    jnz     .answer
    call    ha_tls_flight_end
    test    eax, eax
    jnz     .answer

    ; ---- the master secret: Extract(Derive-Secret(handshake secret, "derived", ""), 0), and
    ; the application traffic and exporter secrets over ClientHello .. server Finished
    movzx   edi, byte [rbx + httpasm_tls13_connection.hash]
    lea     rsi, [rbx + httpasm_tls13_connection.secret]
    lea     rdx, [rel sv_derived]
    mov     ecx, 7
    xor     r8d, r8d
    lea     r9, [rbp + SV_DERIVED]
    call    httpasm_tls13_derive_secret
    movzx   edi, byte [rbx + httpasm_tls13_connection.hash]
    lea     rsi, [rbp + SV_DERIVED]
    movzx   edx, byte [rbx + httpasm_tls13_connection.hash_length]
    xor     ecx, ecx                        ; IKM "0"
    xor     r8d, r8d
    lea     r9, [rbx + httpasm_tls13_connection.secret]   ; the master secret, in its place
    call    httpasm_tls13_extract
    lea     rdi, [rbp + SV_HASH]
    call    ha_tls_transcript_hash
    lea     rdx, [rel sv_c_ap]
    lea     r9, [rbx + httpasm_tls13_connection.client_secret]
    call    .derive
    lea     rdx, [rel sv_s_ap]
    lea     r9, [rbx + httpasm_tls13_connection.server_secret]
    call    .derive
    lea     rdx, [rel sv_exp]
    mov     ecx, 10
    lea     r9, [rbx + httpasm_tls13_connection.exporter]
    call    .derive_n
    lea     rsi, [rbx + httpasm_tls13_connection.server_secret]
    call    ha_tls_set_write                ; our application data may go now (0.5-RTT)
    or      dword [rbx + httpasm_tls13_connection.flags], TF_SENT_FINISHED
    mov     dword [rbx + httpasm_tls13_connection.state], TS_WAIT_FINISHED
    test    dword [rbx + httpasm_tls13_connection.flags], TF_ASKED
    jz      .flight_done
    mov     dword [rbx + httpasm_tls13_connection.state], TS_WAIT_CERT   ; its Certificate first
.flight_done:
    mov     eax, TM_BOUNDARY                ; the read key changed: the hello ends its record
    jmp     .answer

.wait_cert:
    ; ---- the client's Certificate (4.5.1) answering our CertificateRequest: our request's
    ; context (empty: illegal_parameter otherwise), every entry a certificate answering only what
    ; we asked (tls/sign.asm's ha_tls_peer_leaf), the leaf's key one the engine verifies. An
    ; empty list is the client declining: taken, or certificate_required when the configuration
    ; requires a certificate (4.5.1.3-3#1). The list is kept in the peer-chain span (the message
    ; lies in the caller's record or the reassembly span, neither of which lasts) for the
    ; CertificateVerify and for the caller (httpasm_tls13_peer_certificates).
    cmp     eax, HTTPASM_TLS_CERTIFICATE
    jne     .unexpected
    xor     esi, esi                        ; the main handshake's request: an empty context
    xor     edx, edx
    call    .take_certificate               ; -> 1 (certificates), 0 (none), or minus an alert
    test    eax, eax
    js      .answer
    jnz     .main_chain
    mov     rax, [rbx + httpasm_tls13_connection.config]
    test    dword [rax + httpasm_tls13_server_config.flags], HTTPASM_TLS_CLIENT_AUTH_REQUIRE
    jnz     .certificate_required
    mov     dword [rbx + httpasm_tls13_connection.state], TS_WAIT_FINISHED   ; no CertificateVerify
    jmp     .client_message
.main_chain:
    mov     dword [rbx + httpasm_tls13_connection.state], TS_WAIT_CV
.client_message:
    ; the client's Certificate or CertificateVerify into the transcript, after it was judged
    ; (the CertificateVerify's content is over the transcript before itself)
    mov     rsi, r12
    mov     rdx, r13
    call    ha_tls_transcript_add
    xor     eax, eax
    jmp     .answer

.wait_cv:
    ; ---- its CertificateVerify (4.5.2), which must come right after a Certificate with
    ; certificates (4.5.2-1#2, -1#3): over ClientHello .. the client's Certificate, by the leaf's
    ; key (tls/sign.asm's ha_tls_verify)
    cmp     eax, HTTPASM_TLS_CERTIFICATE_VERIFY
    jne     .unexpected
    mov     rsi, r12
    mov     rdx, r13
    call    ha_tls_verify
    test    eax, eax
    jnz     .answer
    mov     dword [rbx + httpasm_tls13_connection.state], TS_WAIT_FINISHED
    jmp     .client_message

.post_auth:
    ; ---- after the handshake (4.7.2): the client's answer to our post-handshake CertificateRequest
    ; (httpasm_tls13_request_certificate), its messages in their order - Certificate (our
    ; request's context), CertificateVerify for one with certificates, Finished - each judged as
    ; the handshake's are, over ClientHello .. client Finished + the request (.transcript; the
    ; handshake's own is kept in .auth_base). Any other message, or one out of its turn, is
    ; unexpected_message (KeyUpdates and application data between the messages are refused
    ; where they arrive: tls/engine.asm).
    mov     ecx, [rbx + httpasm_tls13_connection.auth_state]
    cmp     eax, HTTPASM_TLS_CERTIFICATE
    je      .post_certificate
    cmp     eax, HTTPASM_TLS_CERTIFICATE_VERIFY
    je      .post_verify
    cmp     eax, HTTPASM_TLS_FINISHED
    jne     .unexpected
    cmp     ecx, TA_FINISHED
    jne     .unexpected
    ; the Finished (4.4): its MAC under the client's current application traffic secret (the
    ; Base Key of 4.4's table for post-handshake authentication), compared whole in constant
    ; time as the handshake's is
    movzx   ecx, byte [rbx + httpasm_tls13_connection.hash_length]
    lea     rax, [rcx + 4]
    cmp     r13, rax
    jne     .decode
    lea     rdi, [rbp + SV_HASH]
    call    ha_tls_transcript_hash
    movzx   edi, byte [rbx + httpasm_tls13_connection.hash]
    lea     rsi, [rbx + httpasm_tls13_connection.client_secret]
    lea     rdx, [rbp + SV_HASH]
    lea     rcx, [rbp + SV_VERIFY]
    call    httpasm_tls13_finished
    movzx   ecx, byte [rbx + httpasm_tls13_connection.hash_length]
    xor     eax, eax
    xor     edx, edx
.post_compare:
    movzx   esi, byte [r12 + 4 + rdx]
    xor     sil, [rbp + SV_VERIFY + rdx]
    or      eax, esi
    inc     edx
    cmp     edx, ecx
    jb      .post_compare
    HA_DECLASSIFY rax
    test    eax, eax
    jnz     .decrypt_error
    ; the exchange is over: the transcript back to the handshake's (each request's context
    ; starts from ClientHello .. client Finished), no request outstanding
    lea     rdi, [rbx + httpasm_tls13_connection.transcript]
    lea     rsi, [rbx + httpasm_tls13_connection.auth_base]
    mov     ecx, httpasm_sha512_ctx_size
    rep     movsb
    mov     dword [rbx + httpasm_tls13_connection.auth_state], TA_NONE
    mov     eax, TM_AUTHENTICATED
    jmp     .answer
.post_certificate:
    cmp     ecx, TA_CERT
    jne     .unexpected
    lea     rsi, [rbx + httpasm_tls13_connection.auth_context]
    mov     edx, TA_CONTEXT
    call    .take_certificate
    test    eax, eax
    js      .answer
    mov     ecx, TA_FINISHED                ; declined: its Finished next, no CertificateVerify
    mov     edx, TA_CV
    test    eax, eax
    cmovnz  ecx, edx
    mov     [rbx + httpasm_tls13_connection.auth_state], ecx
    jmp     .client_message
.post_verify:
    cmp     ecx, TA_CV
    jne     .unexpected
    mov     rsi, r12
    mov     rdx, r13
    call    ha_tls_verify
    test    eax, eax
    jnz     .answer
    mov     dword [rbx + httpasm_tls13_connection.auth_state], TA_FINISHED
    jmp     .client_message

.wait_finished:
    ; ---- the client's Finished (4.5.3) over ClientHello .. server Finished
    cmp     eax, HTTPASM_TLS_FINISHED
    jne     .unexpected
    movzx   ecx, byte [rbx + httpasm_tls13_connection.hash_length]
    lea     rax, [rcx + 4]
    cmp     r13, rax
    jne     .decode                         ; verify_data is Hash.length octets
    lea     rdi, [rbp + SV_HASH]
    call    ha_tls_transcript_hash
    movzx   edi, byte [rbx + httpasm_tls13_connection.hash]
    lea     rsi, [rbx + httpasm_tls13_connection.client_handshake]
    lea     rdx, [rbp + SV_HASH]
    lea     rcx, [rbp + SV_VERIFY]
    call    httpasm_tls13_finished
    ; compared whole in constant time: only the verdict is public
    movzx   ecx, byte [rbx + httpasm_tls13_connection.hash_length]
    xor     eax, eax
    xor     edx, edx
.compare:
    movzx   esi, byte [r12 + 4 + rdx]
    xor     sil, [rbp + SV_VERIFY + rdx]
    or      eax, esi
    inc     edx
    cmp     edx, ecx
    jb      .compare
    HA_DECLASSIFY rax
    test    eax, eax
    jnz     .decrypt_error
    mov     rsi, r12
    mov     rdx, r13
    call    ha_tls_transcript_add
    lea     rdi, [rbp + SV_HASH]
    call    ha_tls_transcript_hash          ; .. client Finished
    lea     rdx, [rel sv_res]
    mov     ecx, 10
    lea     r9, [rbx + httpasm_tls13_connection.resumption]
    call    .derive_n
    lea     rsi, [rbx + httpasm_tls13_connection.client_secret]
    call    ha_tls_set_read
    ; the handshake's own secrets are done with (the master secret too: what 4e needs of it is
    ; the resumption secret now made)
    lea     rdi, [rbx + httpasm_tls13_connection.client_handshake]
    xor     eax, eax
    mov     ecx, 48
    rep     stosb
    lea     rdi, [rbx + httpasm_tls13_connection.secret]
    mov     ecx, 48
    rep     stosb
    or      dword [rbx + httpasm_tls13_connection.flags], TF_PEER_FINISHED
    mov     dword [rbx + httpasm_tls13_connection.state], TS_CONNECTED
    mov     eax, TM_BOUNDARY | TM_CONNECTED
    jmp     .answer

.unexpected:
    mov     eax, -HTTPASM_TLS_ALERT_UNEXPECTED_MESSAGE
    jmp     .answer
.protocol_version:
    mov     eax, -HTTPASM_TLS_ALERT_PROTOCOL_VERSION
    jmp     .answer
.handshake_failure:
    mov     eax, -HTTPASM_TLS_ALERT_HANDSHAKE_FAILURE
    jmp     .answer
.missing:
    mov     eax, -HTTPASM_TLS_ALERT_MISSING_EXTENSION
    jmp     .answer
.illegal:
    mov     eax, -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER
    jmp     .answer
.decode:
    mov     eax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    jmp     .answer
.decrypt_error:
    mov     eax, -HTTPASM_TLS_ALERT_DECRYPT_ERROR
    jmp     .answer
.certificate_required:
    mov     eax, -HTTPASM_TLS_ALERT_CERTIFICATE_REQUIRED
    jmp     .answer
.internal:
    mov     eax, -HTTPASM_TLS_ALERT_INTERNAL_ERROR
.answer:
    ; the frame wiped (eax kept): every secret of the step lived there
    mov     r12d, eax
    mov     rdi, rbp
    xor     eax, eax
    mov     ecx, SV_FRAME
    rep     stosb
    mov     eax, r12d
    add     rsp, SV_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    ret

; .find_pair: edx = a 16-bit value, rsi = a list of big-endian pairs, ecx = its octets (even)
; -> CF set when the value is in it. A leaf: clobbers rcx, rsi, r10.
.find_pair:
    mov     r10d, edx
    rol     r10w, 8                         ; as the list stores it
.pair:
    test    ecx, ecx
    jz      .pair_none
    cmp     [rsi], r10w
    je      .pair_found
    add     rsi, 2
    sub     ecx, 2
    jmp     .pair
.pair_found:
    stc
    ret
.pair_none:
    clc
    ret

; .scheme_bit: eax = a SignatureScheme -> eax = its HTTPASM_TLS_SCHEME_BIT_*, or -1 for a
; scheme no server key makes. A leaf: eax only.
.scheme_bit:
    cmp     eax, HTTPASM_TLS_SCHEME_ECDSA_SECP256R1_SHA256
    je      .bit_p256
    cmp     eax, HTTPASM_TLS_SCHEME_ECDSA_SECP384R1_SHA384
    je      .bit_p384
    cmp     eax, HTTPASM_TLS_SCHEME_ECDSA_SECP521R1_SHA512
    je      .bit_p521
    sub     eax, HTTPASM_TLS_SCHEME_RSA_PSS_RSAE_SHA256
    cmp     eax, HTTPASM_TLS_SCHEME_RSA_PSS_PSS_SHA512 - HTTPASM_TLS_SCHEME_RSA_PSS_RSAE_SHA256
    ja      .bit_none
    ; 0x0804-0x080B: rsae 0-2, ed25519 3, ed448 4, pss 5-7 by code; the bits: rsae 0-2, pss 3-5,
    ; ed25519 9, ed448 10
    cmp     eax, 3
    jb      .bit_done                       ; rsae: the code's place is its bit
    je      .bit_ed25519
    cmp     eax, 4
    je      .bit_ed448
    sub     eax, 2                          ; pss: 5-7 -> 3-5
.bit_done:
    ret
.bit_ed25519:
    mov     eax, HTTPASM_TLS_SCHEME_BIT_ED25519
    ret
.bit_ed448:
    mov     eax, HTTPASM_TLS_SCHEME_BIT_ED448
    ret
.bit_p256:
    mov     eax, HTTPASM_TLS_SCHEME_BIT_ECDSA_SECP256R1_SHA256
    ret
.bit_p384:
    mov     eax, HTTPASM_TLS_SCHEME_BIT_ECDSA_SECP384R1_SHA384
    ret
.bit_p521:
    mov     eax, HTTPASM_TLS_SCHEME_BIT_ECDSA_SECP521R1_SHA512
    ret
.bit_none:
    mov     eax, -1
    ret

; .first_supported: r14 = the client's supported_groups, r15 = their octets -> r9 = the place
; in our order of our first group among them, CF set; CF clear when there is none. A leaf:
; clobbers rax, rcx, rdx, rsi, r10.
.first_supported:
    mov     rax, [rbx + httpasm_tls13_connection.config]
    xor     r9d, r9d
.supported_next:
    cmp     r9d, [rax + httpasm_tls13_server_config.group_count]
    jae     .supported_none
    movzx   edx, word [rax + httpasm_tls13_server_config.groups + r9 * 2]
    mov     rsi, r14
    mov     ecx, r15d
    call    .find_pair
    jc      .supported_found
    inc     r9d
    jmp     .supported_next
.supported_found:
    stc
    ret
.supported_none:
    clc
    ret

; .encrypted_extensions: EncryptedExtensions (4.4.1) built at SV_MESSAGE -> rax = its octets:
; supported_groups (the configuration's list, 4.3.7), record_size_limit (2^14 + 1) when the
; client sent one, server_name empty when the client named one. A leaf: clobbers rax, rcx, rdx,
; rsi, rdi.
.encrypted_extensions:
    lea     rdi, [rbp + SV_MESSAGE + 6]     ; past the header and the extensions' length
    mov     word [rdi], 0x0A00              ; supported_groups: 00 0a
    mov     rsi, [rbx + httpasm_tls13_connection.config]
    mov     ecx, [rsi + httpasm_tls13_server_config.group_count]
    lea     eax, [rcx * 2]                  ; named_group_list's octets
    lea     edx, [rax + 2]
    xchg    dl, dh
    mov     [rdi + 2], dx                   ; extension_data's length
    xchg    al, ah
    mov     [rdi + 4], ax
    add     rdi, 6
    xor     edx, edx
.ee_group:
    movzx   eax, word [rsi + httpasm_tls13_server_config.groups + rdx * 2]
    xchg    al, ah
    mov     [rdi], ax
    add     rdi, 2
    inc     edx
    cmp     edx, ecx
    jb      .ee_group
    bt      qword [rbp + SV_PRESENT], HTTPASM_TLS_EXT_RECORD_SIZE_LIMIT
    jnc     .ee_name
    mov     dword [rdi], 0x02001C00         ; record_size_limit: 00 1c 00 02
    mov     word [rdi + 2 + 2], 0x0140      ; 40 01: 2^14 + 1, the most TLS 1.3 allows
    add     rdi, 6
.ee_name:
    bt      qword [rbp + SV_PRESENT], HTTPASM_TLS_EXT_SERVER_NAME
    jnc     .ee_done
    mov     dword [rdi], 0                  ; server_name: 00 00 00 00
    add     rdi, 4
.ee_done:
    lea     rax, [rbp + SV_MESSAGE]
    sub     rdi, rax                        ; the message's octets
    lea     edx, [rdi - 6]
    xchg    dl, dh
    mov     [rax + 4], dx                   ; the extensions' length
    lea     edx, [rdi - 4]
    bswap   edx
    mov     dl, HTTPASM_TLS_ENCRYPTED_EXTENSIONS
    mov     [rax], edx
    mov     rax, rdi
    ret

; .take_certificate: r12 = the client's Certificate message (header and body), r13 = its octets,
; rsi = the context our request carried, rdx = its octets (0 for the main handshake's): the
; message read (httpasm_tls13_certificate_read), its context the request's exactly (4.5.1:
; illegal_parameter otherwise), each entry judged (tls/sign.asm's ha_tls_peer_leaf), and its
; certificate_list kept in the peer-chain span with .peer_length, .peer_count and TF_PEER_CHAIN
; (a later answer replaces an earlier chain) -> eax = 1 with certificates, 0 for an empty list
; (the client declined), or minus an alert. The state and the transcript are the caller's. Called
; from the body (one push with the return address: rsp 16-aligned for the calls); keeps r12, r13,
; r14 and r15.
.take_certificate:
    push    r14
    mov     [rbp + SV_EXPECT], rsi
    mov     [rbp + SV_EXPECT_LENGTH], rdx
    lea     rdi, [r12 + 4]                  ; read(body, length, &context, &n, &list, &n)
    lea     rsi, [r13 - 4]
    lea     rdx, [rbp + SV_CONTEXT]
    lea     rcx, [rbp + SV_CONTEXT_LENGTH]
    lea     r8, [rbp + SV_LIST]
    lea     r9, [rbp + SV_LIST_LENGTH]
    call    httpasm_tls13_certificate_read
    test    rax, rax
    js      .take_done                      ; (eax: minus its alert)
    mov     r14, rax                        ; the entries
    mov     rcx, [rbp + SV_CONTEXT_LENGTH]
    cmp     rcx, [rbp + SV_EXPECT_LENGTH]
    jne     .take_illegal
    mov     rsi, [rbp + SV_CONTEXT]
    mov     rdi, [rbp + SV_EXPECT]
    repe    cmpsb                           ; (no octets: ZF still the length compare's)
    jne     .take_illegal
    test    r14, r14
    jz      .take_empty
    mov     rsi, [rbp + SV_LIST]
    mov     rdx, [rbp + SV_LIST_LENGTH]
    call    ha_tls_peer_leaf
    test    eax, eax
    jnz     .take_done
    ; kept: the message lies in the caller's record or the reassembly span, neither of which lasts
    mov     rcx, [rbp + SV_LIST_LENGTH]
    cmp     rcx, [rbx + httpasm_tls13_connection.peer_capacity]
    ja      .take_internal                  ; (never: the message was within max_message, the
                                            ; span's size, both server_init's)
    mov     [rbx + httpasm_tls13_connection.peer_length], rcx
    mov     [rbx + httpasm_tls13_connection.peer_count], r14d
    mov     rdi, [rbx + httpasm_tls13_connection.peer]
    mov     rsi, [rbp + SV_LIST]
    rep     movsb
    or      dword [rbx + httpasm_tls13_connection.flags], TF_PEER_CHAIN
    mov     eax, 1
    jmp     .take_done
.take_empty:
    mov     qword [rbx + httpasm_tls13_connection.peer_length], 0
    mov     dword [rbx + httpasm_tls13_connection.peer_count], 0
    or      dword [rbx + httpasm_tls13_connection.flags], TF_PEER_CHAIN
    xor     eax, eax
    jmp     .take_done
.take_illegal:
    mov     eax, -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER
    jmp     .take_done
.take_internal:
    mov     eax, -HTTPASM_TLS_ALERT_INTERNAL_ERROR
.take_done:
    pop     r14
    ret

; .put: rsi = octets, rdx = their count: into the transcript and the flight -> eax = 0 or minus
; an alert. Called from the body (rsp then 8 below 16-aligned: realigned here); keeps r12-r15.
.put:
    push    r12
    push    r13
    sub     rsp, 8
    mov     r12, rsi
    mov     r13, rdx
    call    ha_tls_transcript_add
    mov     rsi, r12
    mov     rdx, r13
    call    ha_tls_flight_put
    add     rsp, 8
    pop     r13
    pop     r12
    ret

; .ccs: the one change_cipher_spec record (Appendix E.4) queued -> eax = 0 or minus an alert.
; Realigns as .put does.
.ccs:
    sub     rsp, 8
    mov     esi, HTTPASM_TLS_CONTENT_CHANGE_CIPHER_SPEC
    lea     rdx, [rel sv_ccs]
    mov     ecx, 1
    xor     r8d, r8d
    call    ha_tls_out_plain
    add     rsp, 8
    ret

; .derive / .derive_n: rdx = a label (12 octets; .derive_n: ecx octets), r9 = out: Derive-Secret
; (the connection's .secret, the label, the transcript hash at SV_HASH). Realigns as .put does.
.derive:
    mov     ecx, 12
.derive_n:
    sub     rsp, 8
    movzx   edi, byte [rbx + httpasm_tls13_connection.hash]
    lea     rsi, [rbx + httpasm_tls13_connection.secret]
    lea     r8, [rbp + SV_HASH]
    call    httpasm_tls13_derive_secret
    add     rsp, 8
    ret
.end:
