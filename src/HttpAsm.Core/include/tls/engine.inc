; =============================================================================
; include/tls/engine.inc - what the TLS 1.3 engine's files share (tls/engine.asm: the connection
; and its records; tls/server.asm: the server's handshake; tls/kex.asm: key shares;
; tls/sign.asm: CertificateVerify; tls/config.asm: a server's configuration): the connection's
; states and flags, the engine's bounds, and the internal routines' contracts.
;
; The connection (httpasm_tls13_connection, httpasm_abi.inc) is one block of the caller's memory;
; every internal routine takes it in rbx and keeps rbx: the connection is the one object each
; step needs, so it stays in a callee-saved register the whole way down. Internal routines that
; can fail answer minus an alert (TLS's AlertDescription) without failing the connection
; themselves: httpasm_tls13_receive turns the first such answer into the failure (ha_tls_fail),
; so a failure is handled, sent and recorded in one place.
; =============================================================================
%ifndef HTTPASM_TLS_ENGINE_INC
%define HTTPASM_TLS_ENGINE_INC

; httpasm_tls13_connection.state: the server's places in RFC 9846 Appendix A.2 (the client's,
; 4d, will follow from 16). START and WAIT_CH2 read plaintext records, the others protected ones.
TS_START            equ 0       ; waiting for the ClientHello
TS_WAIT_CH2         equ 1       ; a HelloRetryRequest sent: waiting for the second ClientHello
TS_WAIT_CERT        equ 2       ; a CertificateRequest sent: the client's Certificate (4c4)
TS_WAIT_CV          equ 3       ; its CertificateVerify (4c4)
TS_WAIT_FINISHED    equ 4       ; the client's Finished
TS_CONNECTED        equ 5       ; the handshake completed
TS_FAILED           equ 6       ; ended by an alert (.alert): every call answers it again

; httpasm_tls13_connection.flags
TF_CLIENT           equ 0x0001  ; the client's side (4d); clear: the server's
TF_COMPAT           equ 0x0002  ; the client's legacy_session_id was not empty: middlebox
                                ; compatibility (Appendix E.4: one change_cipher_spec record after
                                ; our first handshake message)
TF_SKIP_EARLY       equ 0x0004  ; early data offered and not taken: records that fail to open
                                ; under the handshake key are dropped (4.3.10)
TF_RETRIED          equ 0x0008  ; a HelloRetryRequest was sent
TF_READ_KEY         equ 0x0010  ; the peer's records are protected (.read is live)
TF_WRITE_KEY        equ 0x0020  ; ours are (.write is live)
TF_PEER_CLOSED      equ 0x0040  ; the peer's close_notify arrived
TF_CLOSED           equ 0x0080  ; ours was sent
TF_PEER_FINISHED    equ 0x0100  ; the peer's Finished arrived: no change_cipher_spec from now
TF_SENT_FINISHED    equ 0x0200  ; our Finished is out: application data may be sent (0.5-RTT)
TF_POST_AUTH        equ 0x0400  ; the client offered post_handshake_auth (4c5)
TF_PEER_ALERT       equ 0x0800  ; FAILED by the peer's alert, not ours
TF_UPDATE_OWED      equ 0x1000  ; the peer asked for a KeyUpdate: ours goes before our next data

; The engine's bounds
TE_IGNORED_MAX      equ 32      ; records that bring nothing (change_cipher_spec, empty data,
                                ; KeyUpdate, user_canceled) taken in a row at most: then
                                ; unexpected_message (BoringSSL's bound against such floods)
TE_EARLY_MAX        equ 16384   ; octets of rejected early data dropped at most (4.3.10's
                                ; "configured max_early_data_size"; BoringSSL's bound)
TE_ALERT_RESERVE    equ 64      ; output octets every write but an alert's leaves free, so a
                                ; failure's alert always fits
TE_FRAGMENT         equ 16384   ; the content we put in one record at most (2^14, 5.1)

; The internal routines (rbx = the connection, kept):
;   tls/engine.asm:
;     ha_tls_draw              rdi = out, rsi = octets: the configuration's random source ->
;                              eax = 0, or -HTTPASM_TLS_ALERT_INTERNAL_ERROR when it failed
;     ha_tls_transcript_init   starts the transcript's hash (.hash's)
;     ha_tls_transcript_add    rsi = octets, rdx = their count: into the transcript
;     ha_tls_transcript_hash   rdi = out: the transcript's hash so far (.hash_length octets)
;     ha_tls_out_plain         esi = content type, rdx = content, rcx = its length (2^14 at
;                              most): a plaintext record at the output's end -> eax = 0, or
;                              -INTERNAL_ERROR when it does not fit
;     ha_tls_flight_begin      opens a flight: protected handshake records under .write, built
;                              in place in the output
;     ha_tls_flight_put        rsi = octets, rdx = their count: appended to the flight (records
;                              sealed as they fill) -> eax = 0, or -INTERNAL_ERROR (no room)
;     ha_tls_flight_end        seals the flight's last record -> eax = 0 or -INTERNAL_ERROR
;     ha_tls_set_read          rsi = a traffic secret: .read under the suite, TF_READ_KEY
;     ha_tls_set_write         rsi = a traffic secret: .write likewise, TF_WRITE_KEY
;   tls/server.asm:
;     ha_tls_server_message    rsi = a whole handshake message, rdx = its octets (header and
;                              body), in a state before CONNECTED -> eax = TM_* flags, or
;                              minus an alert
;   tls/kex.asm:
;     ha_tls_kex_server        edi = group, rsi = the client's share, rdx = its octets,
;                              rcx = our share's out, r8 = the shared secret's out -> rax =
;                              our share's octets | the secret's octets << 32, or minus an alert
;   tls/sign.asm:
;     ha_tls_sign              rdi = out, rsi = the transcript's hash: the server's
;                              CertificateVerify signature under .scheme -> rax = its octets,
;                              or minus an alert
TM_BOUNDARY         equ 1       ; the message must end its record (a key change, 5.1; or a
                                ; HelloRetryRequest sent: nothing may follow a ClientHello)
TM_CONNECTED        equ 2       ; the handshake completed with this message

%endif
