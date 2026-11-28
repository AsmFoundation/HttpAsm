; =============================================================================
; tls/engine.asm - the TLS 1.3 engine's connection (RFC 9846 5, 6, 4.7.3, Appendix E.4): records
; in (one a call, opened in place in the caller's buffer) and out (sealed into the caller's
; output span), the handshake messages' reassembly across records and their transcript, the
; alerts, application data, close_notify and KeyUpdate. What a handshake says is the role's
; (tls/server.asm; the client's is 4d's): the engine hands it whole messages and sends what it
; answers.
;
; The caller's memory (httpasm_tls13_server_init) holds two spans beside the connection:
;   - the reassembly span (.message): a handshake message that goes on past its record is
;     gathered there, the configuration's max_message octets at most (illegal_parameter past
;     that, also for a message whole in one record, so that what is accepted does not depend
;     on how the peer cut its records); a message whole in its record is read in place;
;   - the output span (.output): every record we send, queued from .output_start to .output_end
;     and taken by the caller (httpasm_tls13_output, _output_done), moved back to the span's
;     front when the caller has taken some and room is wanted. A handshake flight is built in
;     place there: its messages are written where their record's content goes and each record
;     is sealed in place as it fills (httpasm_tls13_seal takes its content at out + 5), so a
;     flight is never copied. TE_ALERT_RESERVE octets stay free at all times for a failure's
;     alert.
;
; Records in (httpasm_tls13_receive), by RFC 9846 5:
;   - plaintext before the peer's handshake key (TF_READ_KEY): handshake and alert records;
;   - protected after it: application_data records whose inner type is handshake, alert or
;     application_data (a protected change_cipher_spec, or any other type: unexpected_message);
;     a plaintext alert is still taken until the handshake completes (a peer that failed before
;     it had keys sends one in the clear, Appendix A.1's note), and refused after;
;   - change_cipher_spec, plaintext, the one octet 0x01, after the first ClientHello and before
;     the peer's Finished: dropped (Appendix E.4); any other: unexpected_message;
;   - no handshake record is empty, and no record of another type may come while a handshake
;     message is being gathered (5.1: unexpected_message); a message that changes a key must end
;     its record (5.1: unexpected_message otherwise);
;   - records that bring nothing (change_cipher_spec, empty application data, KeyUpdate,
;     user_canceled) are taken TE_IGNORED_MAX in a row at most;
;   - rejected early data (TF_SKIP_EARLY): records that fail to open under the handshake key are
;     dropped, TE_EARLY_MAX octets at most, until one opens (4.3.10);
;   - an alert: close_notify after the handshake ends the peer's side (EVENT_CLOSED; what follows
;     is ignored, 6.1); before it, it is a failure; user_canceled is a warning; every other
;     alert, unknown ones too, ends the connection (6: error alerts, whatever their level).
;
; Constant time: the secrets (traffic secrets, keys) only pass through the key schedule and the
; record layer, constant time in them; this file branches on lengths, types and states, all
; public. The one secret comparison of a handshake, Finished's, is the role's.
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "tls/engine.inc"

extern httpasm_tls_record_length
extern httpasm_tls13_open
extern httpasm_tls13_seal
extern httpasm_tls13_record_key_init
extern httpasm_tls13_update_secret
extern httpasm_tls13_key_update_read
extern ha_tls_server_message

section .text

; -----------------------------------------------------------------------------
; ha_tls_draw: rbx = the connection, rdi = out, rsi = octets: out filled from the
;   configuration's random source -> rax = 0, or -HTTPASM_TLS_ALERT_INTERNAL_ERROR when the
;   source failed (the handshake cannot go on: 6.2's internal_error). The whole of rax: a caller
;   may hand it on as a 64-bit answer (ha_tls_kex_server does, whose caller tests rax's sign;
;   an eax-only -80, zero-extended, once read there as a share 2^32 - 80 octets long, written
;   past the output span: tests/HttpAsm.Tests/TlsServerEdgeTests.FailsAtEachDraw). Clobbers the
;   caller-saved registers (the source is the caller's C function).
; -----------------------------------------------------------------------------
global ha_tls_draw:function hidden (ha_tls_draw.end - ha_tls_draw)
align 16
ha_tls_draw:
    sub     rsp, 8                          ; (rsp 16-aligned at the call)
    mov     rax, [rbx + httpasm_tls13_connection.config]
    mov     rdx, rsi                        ; random(context, out, length)
    mov     rsi, rdi
    mov     rdi, [rax + httpasm_tls13_server_config.random_context]
    call    [rax + httpasm_tls13_server_config.random]
    add     rsp, 8
    test    eax, eax                        ; (the callback's int: its upper half is not its)
    jnz     .failed
    xor     eax, eax
    ret
.failed:
    mov     rax, -HTTPASM_TLS_ALERT_INTERNAL_ERROR   ; (sign-extended: all of rax)
    ret
.end:

; -----------------------------------------------------------------------------
; The transcript (4.1): the running hash of the handshake's messages, under the suite's hash
; (.hash). Its snapshots are what the key schedule and the Finished MACs take.
;   ha_tls_transcript_init   starts it empty
;   ha_tls_transcript_add    rsi = octets, rdx = their count: appended
;   ha_tls_transcript_hash   rdi = out: the hash so far, .hash_length octets (a copy of the
;                            running context finalized: the transcript goes on)
; Each takes rbx = the connection and clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global ha_tls_transcript_init:function hidden (ha_tls_transcript_init.end - ha_tls_transcript_init)
align 16
ha_tls_transcript_init:
    sub     rsp, 8
    lea     rdi, [rbx + httpasm_tls13_connection.transcript]
    cmp     byte [rbx + httpasm_tls13_connection.hash], HTTPASM_HASH_SHA384
    je      .sha384
    call    httpasm_sha256_init
    add     rsp, 8
    ret
.sha384:
    call    httpasm_sha384_init
    add     rsp, 8
    ret
.end:

global ha_tls_transcript_add:function hidden (ha_tls_transcript_add.end - ha_tls_transcript_add)
align 16
ha_tls_transcript_add:
    sub     rsp, 8
    lea     rdi, [rbx + httpasm_tls13_connection.transcript]
    cmp     byte [rbx + httpasm_tls13_connection.hash], HTTPASM_HASH_SHA384
    je      .sha384
    call    httpasm_sha256_update
    add     rsp, 8
    ret
.sha384:
    call    httpasm_sha512_update           ; (SHA-384's update is SHA-512's)
    add     rsp, 8
    ret
.end:

global ha_tls_transcript_hash:function hidden (ha_tls_transcript_hash.end - ha_tls_transcript_hash)
align 16
ha_tls_transcript_hash:
    push    r12
    sub     rsp, httpasm_sha512_ctx_size    ; a copy of the context (one push + 208: aligned)
    mov     r12, rdi
    lea     rsi, [rbx + httpasm_tls13_connection.transcript]
    mov     rdi, rsp
    mov     ecx, httpasm_sha512_ctx_size / 8
    rep     movsq
    mov     rdi, rsp
    mov     rsi, r12
    cmp     byte [rbx + httpasm_tls13_connection.hash], HTTPASM_HASH_SHA384
    je      .sha384
    call    httpasm_sha256_final
    jmp     .done
.sha384:
    call    httpasm_sha384_final
.done:
    add     rsp, httpasm_sha512_ctx_size    ; (a transcript's hash is public: no wipe)
    pop     r12
    ret
.end:

; -----------------------------------------------------------------------------
; ha_tls_out_free: rbx = the connection, edx = 1 when the alert reserve may be used -> rax = the
;   octets free at the output's end. The octets the caller has taken make room: the queued ones
;   move to the span's front first (not while a flight's record is open: its content sits past
;   .output_end, where the move would leave it behind). A leaf: clobbers rcx, rsi, rdi, r8. A
;   caller building a record in place calls it first: the octets stay put until it commits them.
; -----------------------------------------------------------------------------
global ha_tls_out_free:function hidden (ha_tls_out_free.end - ha_tls_out_free)
align 16
ha_tls_out_free:
    mov     r8, [rbx + httpasm_tls13_connection.output_start]
    test    r8, r8
    jz      .measure
    cmp     qword [rbx + httpasm_tls13_connection.flight], 0
    jne     .measure
    mov     rsi, [rbx + httpasm_tls13_connection.output]
    mov     rdi, rsi
    add     rsi, r8
    mov     rcx, [rbx + httpasm_tls13_connection.output_end]
    sub     rcx, r8
    rep     movsb                           ; (the destination below the source: a forward copy
                                            ; of overlapping octets is exact)
    sub     [rbx + httpasm_tls13_connection.output_end], r8
    mov     qword [rbx + httpasm_tls13_connection.output_start], 0
.measure:
    mov     rax, [rbx + httpasm_tls13_connection.output_capacity]
    sub     rax, [rbx + httpasm_tls13_connection.output_end]
    test    edx, edx
    jnz     .done
    sub     rax, TE_ALERT_RESERVE
    jae     .done
    xor     eax, eax                        ; less than the reserve left: nothing for others
.done:
    ret
.end:

; -----------------------------------------------------------------------------
; ha_tls_out_plain: rbx = the connection, esi = the content type, rdx = the content, rcx = its
;   octets (2^14 at most), r8d = 1 when the alert reserve may be used: one plaintext record
;   (TLSPlaintext, 5.1: legacy_record_version 0x0303) at the output's end. The content may
;   already lie where the record's content goes (a message built in place: left there) or
;   anywhere else (copied). -> eax = 0, or -HTTPASM_TLS_ALERT_INTERNAL_ERROR when it does not
;   fit. A caller building in place takes the room first (ha_tls_out_free), which also moves the
;   queued octets, so this call's own measure moves nothing.
; -----------------------------------------------------------------------------
global ha_tls_out_plain:function hidden (ha_tls_out_plain.end - ha_tls_out_plain)
align 16
ha_tls_out_plain:
    push    r12
    push    r13
    push    r14
    mov     r12d, esi
    mov     r13, rdx
    mov     r14, rcx
    mov     edx, r8d
    call    ha_tls_out_free
    lea     rcx, [r14 + HTTPASM_TLS_RECORD_HEADER]
    cmp     rax, rcx
    jb      .no_room
    mov     rdi, [rbx + httpasm_tls13_connection.output]
    add     rdi, [rbx + httpasm_tls13_connection.output_end]
    mov     [rdi], r12b
    mov     word [rdi + 1], 0x0303
    mov     eax, r14d
    xchg    al, ah                          ; the length, big-endian
    mov     [rdi + 3], ax
    add     rdi, HTTPASM_TLS_RECORD_HEADER
    cmp     rdi, r13
    je      .placed                         ; built where it goes
    mov     rsi, r13
    mov     rcx, r14
    rep     movsb
.placed:
    lea     rax, [r14 + HTTPASM_TLS_RECORD_HEADER]
    add     [rbx + httpasm_tls13_connection.output_end], rax
    xor     eax, eax
    jmp     .done
.no_room:
    mov     eax, -HTTPASM_TLS_ALERT_INTERNAL_ERROR
.done:
    pop     r14
    pop     r13
    pop     r12
    ret
.end:

; -----------------------------------------------------------------------------
; ha_tls_out_record: rbx = the connection, esi = the content type, rdx = the content, rcx = its
;   octets (a few: an alert, a KeyUpdate, a post-handshake CertificateRequest), r8d = 1 when the
;   alert reserve may be used: one record, sealed under .write once TF_WRITE_KEY is set (6.2:
;   alerts are protected once keys are in use), plaintext before. -> eax = 0, or nonzero when it
;   does not fit or the key refuses (its record limit, or a content over the peer's
;   record_size_limit). Nothing is queued then.
; -----------------------------------------------------------------------------
global ha_tls_out_record:function hidden (ha_tls_out_record.end - ha_tls_out_record)
align 16
ha_tls_out_record:
    test    dword [rbx + httpasm_tls13_connection.flags], TF_WRITE_KEY
    jz      ha_tls_out_plain
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 24                         ; [rsp]: seal's 7th argument (four pushes + 24: aligned)
    mov     r12d, esi
    mov     r13, rdx
    mov     r14, rcx
    mov     edx, r8d
    call    ha_tls_out_free
    lea     r15, [r14 + HTTPASM_TLS_RECORD_HEADER + 1 + HTTPASM_TLS_TAG]
    cmp     rax, r15
    jb      .refused
    mov     [rsp], r15                      ; seal(key, type, content, length, 0, out, capacity)
    lea     rdi, [rbx + httpasm_tls13_connection.write]
    mov     esi, r12d
    mov     rdx, r13
    mov     rcx, r14
    xor     r8d, r8d
    mov     r9, [rbx + httpasm_tls13_connection.output]
    add     r9, [rbx + httpasm_tls13_connection.output_end]
    call    httpasm_tls13_seal
    test    rax, rax
    js      .refused
    add     [rbx + httpasm_tls13_connection.output_end], rax
    xor     eax, eax
    jmp     .done
.refused:
    mov     eax, -1
.done:
    add     rsp, 24
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    ret
.end:

; -----------------------------------------------------------------------------
; A flight: handshake messages in protected records under .write, built in place in the output.
;   ha_tls_flight_begin   opens the first record at the output's end (queued octets moved to
;                         the front first: a flight wants all the room there is)
;   ha_tls_flight_put     rsi = octets, rdx = their count: appended; each record sealed when it
;                         holds what one may (.write's limit less the type octet) -> eax = 0,
;                         or -INTERNAL_ERROR when the output cannot hold it (the configuration's
;                         output_min is what a flight needs: only a caller that left output
;                         untaken meets this)
;   ha_tls_flight_end     seals the last record -> eax = 0 or -INTERNAL_ERROR
; The open record's content is .flight octets at .output + .output_end + 5. A failure drops an
; open record (ha_tls_fail): what is past .output_end is never sent. Each takes rbx and
; clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global ha_tls_flight_begin:function hidden (ha_tls_flight_begin.end - ha_tls_flight_begin)
align 16
ha_tls_flight_begin:
    mov     qword [rbx + httpasm_tls13_connection.flight], 0
    xor     edx, edx
    jmp     ha_tls_out_free                 ; (for its move only)
.end:

global ha_tls_flight_put:function hidden (ha_tls_flight_put.end - ha_tls_flight_put)
align 16
ha_tls_flight_put:
    push    r12
    push    r13
    push    r14                             ; (three pushes: rsp 16-aligned at the call)
    mov     r12, rsi
    mov     r13, rdx
.next:
    test    r13, r13
    jz      .done
    mov     r14d, [rbx + httpasm_tls13_connection.write + httpasm_tls13_record_key.limit]
    dec     r14                             ; one record's content at most
    sub     r14, [rbx + httpasm_tls13_connection.flight]
    cmp     r14, r13
    cmova   r14, r13                        ; what goes into the open record now
    ; the output must hold the open record whole once sealed (header, content, type, tag) and
    ; keep the reserve
    mov     rax, [rbx + httpasm_tls13_connection.output_end]
    add     rax, [rbx + httpasm_tls13_connection.flight]
    lea     rax, [rax + r14 + HTTPASM_TLS_RECORD_HEADER + 1 + HTTPASM_TLS_TAG + TE_ALERT_RESERVE]
    cmp     rax, [rbx + httpasm_tls13_connection.output_capacity]
    ja      .no_room
    mov     rdi, [rbx + httpasm_tls13_connection.output]
    add     rdi, [rbx + httpasm_tls13_connection.output_end]
    add     rdi, [rbx + httpasm_tls13_connection.flight]
    add     rdi, HTTPASM_TLS_RECORD_HEADER
    mov     rsi, r12
    mov     rcx, r14
    rep     movsb
    add     r12, r14
    sub     r13, r14
    add     [rbx + httpasm_tls13_connection.flight], r14
    mov     eax, [rbx + httpasm_tls13_connection.write + httpasm_tls13_record_key.limit]
    dec     eax
    cmp     [rbx + httpasm_tls13_connection.flight], rax
    jb      .next                           ; room left in it: the next octets go there too
    call    ha_tls_flight_seal              ; full: sealed, and the next record opens
    test    eax, eax
    jz      .next
    jmp     .out
.done:
    xor     eax, eax
.out:
    pop     r14
    pop     r13
    pop     r12
    ret
.no_room:
    mov     eax, -HTTPASM_TLS_ALERT_INTERNAL_ERROR
    jmp     .out
.end:

global ha_tls_flight_end:function hidden (ha_tls_flight_end.end - ha_tls_flight_end)
align 16
ha_tls_flight_end:
    cmp     qword [rbx + httpasm_tls13_connection.flight], 0
    jne     ha_tls_flight_seal              ; (a tail call)
    xor     eax, eax
    ret
.end:

; ha_tls_flight_seal: the open record (.flight octets of content at .output_end + 5) sealed in
; place under .write as a handshake record -> eax = 0, or -INTERNAL_ERROR when the key refuses
; (its record limit, which no handshake reaches).
align 16
ha_tls_flight_seal:
    sub     rsp, 24                         ; [rsp]: seal's 7th argument (8 + 24: aligned)
    mov     r9, [rbx + httpasm_tls13_connection.output]
    add     r9, [rbx + httpasm_tls13_connection.output_end]
    mov     rax, [rbx + httpasm_tls13_connection.output_capacity]
    sub     rax, [rbx + httpasm_tls13_connection.output_end]
    mov     [rsp], rax
    lea     rdi, [rbx + httpasm_tls13_connection.write]
    mov     esi, HTTPASM_TLS_CONTENT_HANDSHAKE
    lea     rdx, [r9 + HTTPASM_TLS_RECORD_HEADER]   ; the content, where the record carries it
    mov     rcx, [rbx + httpasm_tls13_connection.flight]
    xor     r8d, r8d                        ; no padding
    call    httpasm_tls13_seal
    test    rax, rax
    js      .refused
    add     [rbx + httpasm_tls13_connection.output_end], rax
    mov     qword [rbx + httpasm_tls13_connection.flight], 0
    xor     eax, eax
    add     rsp, 24
    ret
.refused:
    mov     eax, -HTTPASM_TLS_ALERT_INTERNAL_ERROR
    add     rsp, 24
    ret

; -----------------------------------------------------------------------------
; ha_tls_set_read / ha_tls_set_write: rbx = the connection, rsi = a traffic secret
;   (.hash_length octets): the peer's (read) or our (write) records protected from now under its
;   key and IV (7.3), sequence 0, with TF_READ_KEY / TF_WRITE_KEY set. Every write key takes the
;   peer's record_size_limit (RFC 8449 4: TLSInnerPlaintext's octets at most, protected records
;   only), so each later key (the application's, a KeyUpdate's) keeps it. Clobbers the
;   caller-saved registers.
; -----------------------------------------------------------------------------
global ha_tls_set_read:function hidden (ha_tls_set_read.end - ha_tls_set_read)
align 16
ha_tls_set_read:
    sub     rsp, 8
    mov     rdx, rsi                        ; record_key_init(key, suite, secret)
    movzx   esi, word [rbx + httpasm_tls13_connection.suite]
    lea     rdi, [rbx + httpasm_tls13_connection.read]
    call    httpasm_tls13_record_key_init
    or      dword [rbx + httpasm_tls13_connection.flags], TF_READ_KEY
    add     rsp, 8
    ret
.end:

global ha_tls_set_write:function hidden (ha_tls_set_write.end - ha_tls_set_write)
align 16
ha_tls_set_write:
    sub     rsp, 8
    mov     rdx, rsi
    movzx   esi, word [rbx + httpasm_tls13_connection.suite]
    lea     rdi, [rbx + httpasm_tls13_connection.write]
    call    httpasm_tls13_record_key_init
    or      dword [rbx + httpasm_tls13_connection.flags], TF_WRITE_KEY
    movzx   eax, word [rbx + httpasm_tls13_connection.peer_limit]
    test    eax, eax
    jz      .unlimited
    mov     [rbx + httpasm_tls13_connection.write + httpasm_tls13_record_key.limit], eax
.unlimited:
    add     rsp, 8
    ret
.end:

; -----------------------------------------------------------------------------
; ha_tls_fail: rbx = the connection, esi = an alert: the connection fails with it. The alert goes
;   out fatal (6: every error alert), sealed under .write when there is one and plaintext before,
;   into the output's reserve; an open flight record is dropped unsent. A connection already
;   failed stays as it was (its first alert is the one reported). Clobbers the caller-saved
;   registers.
; -----------------------------------------------------------------------------
align 16
ha_tls_fail:
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_FAILED
    je      .already
    sub     rsp, 24                         ; [rsp]: the alert's two octets (8 + 24: aligned)
    mov     dword [rbx + httpasm_tls13_connection.state], TS_FAILED
    mov     [rbx + httpasm_tls13_connection.alert], esi
    mov     qword [rbx + httpasm_tls13_connection.flight], 0
    mov     byte [rsp], 2                   ; AlertLevel fatal
    mov     [rsp + 1], sil
    mov     esi, HTTPASM_TLS_CONTENT_ALERT
    mov     rdx, rsp
    mov     ecx, 2
    mov     r8d, 1                          ; the reserve is the alert's
    call    ha_tls_out_record               ; (no room or no key that can seal: nothing goes;
                                            ; the connection ends all the same)
    add     rsp, 24
.already:
    ret

; -----------------------------------------------------------------------------
; ha_tls_key_update_send: rbx = the connection, esi = request_update (0 or 1): our KeyUpdate
;   (4.7.3), sealed under the current write key, then our next application traffic secret and
;   key (7.2: "traffic upd"); the old secret is overwritten. -> eax = 0, or -1 when the record did
;   not fit (nothing changed). Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
align 16
ha_tls_key_update_send:
    push    r12
    sub     rsp, 64                         ; [rsp]: the message; [rsp + 16]: the next secret
    mov     dword [rsp], 0x01000018         ; KeyUpdate (24), length 1: 18 00 00 01
    mov     [rsp + 4], sil
    mov     esi, HTTPASM_TLS_CONTENT_HANDSHAKE
    mov     rdx, rsp
    mov     ecx, 5
    xor     r8d, r8d
    call    ha_tls_out_record
    test    eax, eax
    jnz     .refused
    lea     r12, [rbx + httpasm_tls13_connection.server_secret]  ; ours, by role
    test    dword [rbx + httpasm_tls13_connection.flags], TF_CLIENT
    jz      .ours
    lea     r12, [rbx + httpasm_tls13_connection.client_secret]
.ours:
    movzx   edi, byte [rbx + httpasm_tls13_connection.hash]
    mov     rsi, r12
    lea     rdx, [rsp + 16]
    call    httpasm_tls13_update_secret
    lea     rsi, [rsp + 16]
    mov     rdi, r12
    movzx   ecx, byte [rbx + httpasm_tls13_connection.hash_length]
    rep     movsb
    lea     rdi, [rsp + 16]                 ; the copy wiped
    xor     eax, eax
    mov     ecx, 48
    rep     stosb
    mov     rsi, r12
    call    ha_tls_set_write
    and     dword [rbx + httpasm_tls13_connection.flags], ~TF_UPDATE_OWED
    xor     eax, eax
    jmp     .done
.refused:
    mov     eax, -1
.done:
    add     rsp, 64
    pop     r12
    ret

; -----------------------------------------------------------------------------
; ha_tls_message: rbx = the connection, rsi = a whole handshake message (header and body), rdx =
;   its octets -> eax = TM_* flags, or minus an alert. Before the handshake completes, the role
;   reads it (tls/server.asm; the client's machine is 4d's); after, the messages either side may
;   get: KeyUpdate (4.7.3) here, and the server's post-handshake authentication's (the client's
;   answer to our CertificateRequest: tls/server.asm, which refuses whatever else comes); the
;   client's NewSessionTicket with 4d.
; -----------------------------------------------------------------------------
align 16
ha_tls_message:
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_CONNECTED
    je      .post
    mov     dword [rbx + httpasm_tls13_connection.ignored], 0  ; a handshake message is progress
    test    dword [rbx + httpasm_tls13_connection.flags], TF_CLIENT
    jnz     .unexpected
    jmp     ha_tls_server_message           ; (a tail call)
.post:
    cmp     byte [rsi], HTTPASM_TLS_KEY_UPDATE
    je      .key_update
    test    dword [rbx + httpasm_tls13_connection.flags], TF_CLIENT
    jnz     .unexpected
    mov     dword [rbx + httpasm_tls13_connection.ignored], 0  ; (an answer's message is progress)
    jmp     ha_tls_server_message           ; (a tail call: CONNECTED's messages, 4.7.2)
.key_update:
    ; inside the client's answer to our request a KeyUpdate is a message of another type, which
    ; may not come between its Certificate, CertificateVerify and Finished (4.7.2-1#5)
    cmp     dword [rbx + httpasm_tls13_connection.auth_state], TA_CV
    jae     .unexpected
    push    r12
    push    r13
    sub     rsp, 56                         ; [rsp]: the next secret (two pushes + 56: aligned)
    lea     rdi, [rsi + 4]
    lea     rsi, [rdx - 4]
    call    httpasm_tls13_key_update_read
    test    eax, eax
    js      .key_done
    mov     r12d, eax                       ; request_update
    inc     dword [rbx + httpasm_tls13_connection.ignored]  ; KeyUpdates bring the caller nothing:
    cmp     dword [rbx + httpasm_tls13_connection.ignored], TE_IGNORED_MAX  ; a flood is refused
    ja      .key_unexpected
    ; the peer's application traffic secret moves on (7.2): the client's, to a server
    lea     r13, [rbx + httpasm_tls13_connection.client_secret]
    test    dword [rbx + httpasm_tls13_connection.flags], TF_CLIENT
    jz      .peer
    lea     r13, [rbx + httpasm_tls13_connection.server_secret]
.peer:
    movzx   edi, byte [rbx + httpasm_tls13_connection.hash]
    mov     rsi, r13
    mov     rdx, rsp
    call    httpasm_tls13_update_secret
    mov     rdi, r13
    mov     rsi, rsp
    movzx   ecx, byte [rbx + httpasm_tls13_connection.hash_length]
    rep     movsb
    mov     rdi, rsp                        ; the copy wiped
    xor     eax, eax
    mov     ecx, 48
    rep     stosb
    mov     rsi, r13
    call    ha_tls_set_read
    test    r12d, r12d
    jz      .key_changed
    or      dword [rbx + httpasm_tls13_connection.flags], TF_UPDATE_OWED  ; ours goes before our
                                            ; next application data (4.7.3), one for any number
.key_changed:
    mov     eax, TM_BOUNDARY                ; the key changed: the KeyUpdate ends its record (5.1)
.key_done:
    add     rsp, 56
    pop     r13
    pop     r12
    ret
.key_unexpected:
    mov     eax, -HTTPASM_TLS_ALERT_UNEXPECTED_MESSAGE
    jmp     .key_done
.unexpected:
    mov     eax, -HTTPASM_TLS_ALERT_UNEXPECTED_MESSAGE
    ret

; -----------------------------------------------------------------------------
; ha_tls_handshake: rbx = the connection, rsi = a record's handshake octets, rdx = their count
;   (> 0) -> eax = the TM_* flags of the messages they completed, or minus an alert. A message
;   whole in the record is read in place; one that goes on past it is gathered into the
;   reassembly span, its length checked against the span as soon as its header is whole (and
;   checked for whole ones too, so a message's fate does not depend on the peer's record cuts).
;   Nothing may follow, in the same record, a message that must end its record (TM_BOUNDARY:
;   5.1's key change). Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
align 16
ha_tls_handshake:
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15                             ; (five pushes: rsp 16-aligned at the calls)
    mov     r12, rsi                        ; the octets left
    mov     r13, rdx
    xor     r14d, r14d                      ; the flags so far
.next:
    test    r13, r13
    jz      .flags
    test    r14d, TM_BOUNDARY
    jnz     .unexpected                     ; octets after a key change, in its record (5.1)
    mov     rbp, [rbx + httpasm_tls13_connection.message_length]
    test    rbp, rbp
    jnz     .gather
    cmp     r13, 4
    jb      .begin                          ; not even the header here: gathered
    mov     eax, [r12]
    bswap   eax
    and     eax, 0x00FFFFFF                 ; the body's length (uint24)
    lea     r15, [rax + 4]                  ; the message's octets
    cmp     r15, [rbx + httpasm_tls13_connection.message_capacity]
    ja      .too_long
    cmp     r15, r13
    ja      .begin                          ; it goes on in a later record
    mov     rsi, r12                        ; whole here: read in place
    mov     rdx, r15
    call    ha_tls_message
    test    eax, eax
    js      .done
    or      r14d, eax
    add     r12, r15
    sub     r13, r15
    jmp     .next
.begin:
    ; the start of a message that goes on past this record (its length, when its header is here,
    ; checked above): gathered
    mov     rdi, [rbx + httpasm_tls13_connection.message]
    mov     rsi, r12
    mov     rcx, r13
    rep     movsb
    mov     [rbx + httpasm_tls13_connection.message_length], r13
    jmp     .flags
.gather:
    ; rbp = octets gathered so far: first the header's four, then the rest of the message
    mov     rdi, [rbx + httpasm_tls13_connection.message]
    cmp     rbp, 4
    jae     .header
.header_octet:
    mov     al, [r12]
    mov     [rdi + rbp], al
    inc     rbp
    inc     r12
    dec     r13
    cmp     rbp, 4
    jae     .header
    test    r13, r13
    jnz     .header_octet
    mov     [rbx + httpasm_tls13_connection.message_length], rbp
    jmp     .flags
.header:
    mov     eax, [rdi]
    bswap   eax
    and     eax, 0x00FFFFFF
    lea     r15, [rax + 4]
    cmp     r15, [rbx + httpasm_tls13_connection.message_capacity]
    ja      .too_long
    mov     rcx, r15
    sub     rcx, rbp                        ; still wanted
    cmp     rcx, r13
    cmova   rcx, r13                        ; what this record has of it
    lea     rdi, [rdi + rbp]
    mov     rsi, r12
    add     r12, rcx
    sub     r13, rcx
    add     rbp, rcx
    rep     movsb
    cmp     rbp, r15
    jb      .partial
    mov     qword [rbx + httpasm_tls13_connection.message_length], 0
    mov     rsi, [rbx + httpasm_tls13_connection.message]
    mov     rdx, r15
    call    ha_tls_message
    test    eax, eax
    js      .done
    or      r14d, eax
    jmp     .next
.partial:
    mov     [rbx + httpasm_tls13_connection.message_length], rbp
.flags:
    mov     eax, r14d
.done:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    ret
.too_long:
    mov     eax, -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER   ; (OpenSSL's and BoringSSL's answer to an
    jmp     .done                                       ; excessive message size)
.unexpected:
    mov     eax, -HTTPASM_TLS_ALERT_UNEXPECTED_MESSAGE
    jmp     .done

; -----------------------------------------------------------------------------
; int64_t httpasm_tls13_receive(httpasm_tls13_connection *c, uint8_t *in, size_t length,
;                               httpasm_tls13_event *event)
;   Takes the record at the start of in[0..length) (the file's header has the rules): returns its
;   octets, consumed, with *event saying what it brought (NONE, CONNECTED, DATA with the
;   plaintext in place in `in`, CLOSED); 0 when no whole record is there yet (nothing consumed,
;   *event NONE); or -1 when the connection failed (*event FAILED with the alert and, when the
;   peer sent it, HTTPASM_TLS_EVENT_PEER; ours is queued in the output). After a failure every
;   call answers -1 and the same event. Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_receive:function (httpasm_tls13_receive.end - httpasm_tls13_receive)
align 16
httpasm_tls13_receive:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 24                         ; [rsp]: the inner content type (six pushes + 24: aligned)
    mov     rbx, rdi
    mov     r12, rsi                        ; the record
    mov     r13, rdx
    mov     r14, rcx                        ; the event
    xor     eax, eax
    mov     [r14], rax                      ; NONE, until a record says otherwise
    mov     [r14 + 8], rax
    mov     [r14 + 16], rax
    mov     [r14 + 24], rax
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_FAILED
    je      .failed
    mov     rdi, r12
    mov     rsi, r13
    call    httpasm_tls_record_length
    test    rax, rax
    jz      .done                           ; not whole yet (rax 0)
    js      .alert_answer                   ; record_overflow
    mov     r13, rax                        ; the record's octets: what is consumed
    test    dword [rbx + httpasm_tls13_connection.flags], TF_PEER_CLOSED
    jnz     .consumed                       ; after the peer's close_notify: ignored (6.1)
    movzx   eax, byte [r12]
    cmp     eax, HTTPASM_TLS_CONTENT_CHANGE_CIPHER_SPEC
    je      .ccs
    test    dword [rbx + httpasm_tls13_connection.flags], TF_READ_KEY
    jnz     .protected
    lea     rsi, [r12 + HTTPASM_TLS_RECORD_HEADER]
    lea     rdx, [r13 - HTTPASM_TLS_RECORD_HEADER]
    cmp     eax, HTTPASM_TLS_CONTENT_ALERT
    je      .alert
    cmp     eax, HTTPASM_TLS_CONTENT_HANDSHAKE
    je      .plain_handshake
    cmp     eax, HTTPASM_TLS_CONTENT_APPLICATION_DATA
    jne     .unexpected                     ; an unknown type
    ; a protected record while we read plaintext: early data the client sent before our
    ; HelloRetryRequest reached it, rejected and skipped by its outer type (4.3.10), up to the
    ; bound; any other is unexpected
    test    dword [rbx + httpasm_tls13_connection.flags], TF_SKIP_EARLY
    jz      .unexpected
    add     [rbx + httpasm_tls13_connection.skipped], r13
    cmp     qword [rbx + httpasm_tls13_connection.skipped], TE_EARLY_MAX
    ja      .unexpected                     ; (4.3.10: more than the bound, unexpected_message)
    jmp     .consumed
.plain_handshake:
    test    rdx, rdx
    jz      .unexpected                     ; no handshake record is empty (5.1)
    jmp     .handshake
.protected:
    cmp     eax, HTTPASM_TLS_CONTENT_ALERT
    jne     .open
    ; a plaintext alert under the peer's keys: a peer that failed before it had its keys, until
    ; the handshake completes (Appendix A.1's note); none after
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_CONNECTED
    jae     .unexpected
    lea     rsi, [r12 + HTTPASM_TLS_RECORD_HEADER]
    lea     rdx, [r13 - HTTPASM_TLS_RECORD_HEADER]
    jmp     .alert
.open:
    cmp     eax, HTTPASM_TLS_CONTENT_APPLICATION_DATA
    jne     .unexpected                     ; a plaintext record of any other type (5.2)
    lea     rdi, [rbx + httpasm_tls13_connection.read]
    mov     rsi, r12
    mov     rdx, r13
    mov     rcx, rsp
    call    httpasm_tls13_open
    test    rax, rax
    js      .open_failed
    and     dword [rbx + httpasm_tls13_connection.flags], ~TF_SKIP_EARLY  ; one opened: the early
                                            ; data, if any, is behind us (4.3.10)
    lea     rsi, [r12 + HTTPASM_TLS_RECORD_HEADER]
    mov     rdx, rax                        ; the content's octets
    movzx   eax, byte [rsp]
    cmp     eax, HTTPASM_TLS_CONTENT_APPLICATION_DATA
    je      .data
    ; a handshake message's octets or an alert, opened under a secret key: the protocol's own
    ; messages, which the peer wrote and both ends hash into the transcript, and which the
    ; engine parses and acts on. Application data (above) stays secret: it is the caller's, and
    ; the engine only hands it over, never branching on it.
    HA_DECLASSIFY_MEM rsi, rdx              ; (public by design: the peer's messages)
    cmp     eax, HTTPASM_TLS_CONTENT_ALERT
    je      .alert
    cmp     eax, HTTPASM_TLS_CONTENT_HANDSHAKE
    jne     .unexpected                     ; a protected change_cipher_spec, or another type (5)
    test    rdx, rdx
    jz      .unexpected
    jmp     .handshake
.open_failed:
    ; rejected early data: records the handshake key cannot open are dropped, up to a bound
    cmp     rax, -HTTPASM_TLS_ALERT_BAD_RECORD_MAC
    jne     .alert_answer
    test    dword [rbx + httpasm_tls13_connection.flags], TF_SKIP_EARLY
    jz      .alert_answer
    add     [rbx + httpasm_tls13_connection.skipped], r13
    cmp     qword [rbx + httpasm_tls13_connection.skipped], TE_EARLY_MAX
    ja      .unexpected                     ; (4.3.10: more than the bound, unexpected_message)
    jmp     .consumed
.data:
    ; application data: once the handshake completed only (no 0-RTT is taken)
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_CONNECTED
    jne     .unexpected
    cmp     qword [rbx + httpasm_tls13_connection.message_length], 0
    jne     .unexpected                     ; inside a handshake message (5.1: no interleaving)
    cmp     dword [rbx + httpasm_tls13_connection.auth_state], TA_CV
    jae     .unexpected                     ; inside the client's answer to our post-handshake
                                            ; request, between its messages (4.7.2-1#5)
    test    rdx, rdx
    jz      .nothing                        ; an empty record (5.4 allows it): counted
    mov     dword [rbx + httpasm_tls13_connection.ignored], 0
    mov     dword [r14 + httpasm_tls13_event.kind], HTTPASM_TLS_EVENT_DATA
    mov     [r14 + httpasm_tls13_event.data], rsi
    mov     [r14 + httpasm_tls13_event.length], rdx
    jmp     .consumed
.ccs:
    ; change_cipher_spec (Appendix E.4): plaintext, the one octet 0x01, after the first
    ; ClientHello and before the peer's Finished, between messages; dropped
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_START
    je      .unexpected
    test    dword [rbx + httpasm_tls13_connection.flags], TF_PEER_FINISHED
    jnz     .unexpected
    cmp     r13, HTTPASM_TLS_RECORD_HEADER + 1
    jne     .unexpected
    cmp     byte [r12 + HTTPASM_TLS_RECORD_HEADER], 1
    jne     .unexpected
    cmp     qword [rbx + httpasm_tls13_connection.message_length], 0
    jne     .unexpected
.nothing:
    inc     dword [rbx + httpasm_tls13_connection.ignored]
    cmp     dword [rbx + httpasm_tls13_connection.ignored], TE_IGNORED_MAX
    ja      .unexpected
    jmp     .consumed
.handshake:
    ; (after our close_notify the peer's messages are still read: a KeyUpdate keeps its side's
    ; key moving, 6.1 closes one direction only)
    call    ha_tls_handshake
    test    eax, eax
    js      .alert_answer
    test    eax, TM_AUTHENTICATED
    jnz     .authenticated
    test    eax, TM_CONNECTED
    jz      .consumed
    mov     dword [r14 + httpasm_tls13_event.kind], HTTPASM_TLS_EVENT_CONNECTED
    jmp     .consumed
.authenticated:
    mov     dword [r14 + httpasm_tls13_event.kind], HTTPASM_TLS_EVENT_AUTHENTICATED
    jmp     .consumed
.alert:
    ; rsi, rdx = an alert's octets: exactly two (6: one alert to a record, whole)
    cmp     rdx, 2
    jne     .decode
    movzx   eax, byte [rsi + 1]
    test    eax, eax
    jz      .close_notify
    cmp     eax, HTTPASM_TLS_ALERT_USER_CANCELED
    je      .nothing                        ; a warning: close_notify follows it (6.1)
.peer_failed:
    ; any other alert, unknown ones too, is an error alert whatever its level (6)
    mov     dword [rbx + httpasm_tls13_connection.state], TS_FAILED
    mov     [rbx + httpasm_tls13_connection.alert], eax
    or      dword [rbx + httpasm_tls13_connection.flags], TF_PEER_ALERT
    jmp     .failed
.close_notify:
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_CONNECTED
    jne     .peer_failed                    ; before the handshake completed: it failed
    or      dword [rbx + httpasm_tls13_connection.flags], TF_PEER_CLOSED
    mov     dword [r14 + httpasm_tls13_event.kind], HTTPASM_TLS_EVENT_CLOSED
    jmp     .consumed
.decode:
    mov     esi, HTTPASM_TLS_ALERT_DECODE_ERROR
    jmp     .fail
.unexpected:
    mov     esi, HTTPASM_TLS_ALERT_UNEXPECTED_MESSAGE
    jmp     .fail
.alert_answer:
    mov     esi, eax                        ; rax = minus an alert
    neg     esi
.fail:
    call    ha_tls_fail
.failed:
    mov     dword [r14 + httpasm_tls13_event.kind], HTTPASM_TLS_EVENT_FAILED
    mov     eax, [rbx + httpasm_tls13_connection.alert]
    mov     [r14 + httpasm_tls13_event.alert], eax
    test    dword [rbx + httpasm_tls13_connection.flags], TF_PEER_ALERT
    jz      .ours
    mov     dword [r14 + httpasm_tls13_event.flags], HTTPASM_TLS_EVENT_PEER
.ours:
    mov     rax, -1
    jmp     .done
.consumed:
    mov     rax, r13
.done:
    add     rsp, 24
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; size_t httpasm_tls13_output(const httpasm_tls13_connection *c, const uint8_t **out)
;   The octets queued to send: *out and their count (0: none). They stay until _output_done.
;   A leaf: clobbers rax.
; -----------------------------------------------------------------------------
global httpasm_tls13_output:function (httpasm_tls13_output.end - httpasm_tls13_output)
align 16
httpasm_tls13_output:
    mov     rax, [rdi + httpasm_tls13_connection.output]
    add     rax, [rdi + httpasm_tls13_connection.output_start]
    mov     [rsi], rax
    mov     rax, [rdi + httpasm_tls13_connection.output_end]
    sub     rax, [rdi + httpasm_tls13_connection.output_start]
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_tls13_output_done(httpasm_tls13_connection *c, size_t n)
;   Takes n octets (what is queued at most) off the output's front; all of it taken, the span
;   starts over at its front. A leaf: clobbers rax, rsi.
; -----------------------------------------------------------------------------
global httpasm_tls13_output_done:function (httpasm_tls13_output_done.end - httpasm_tls13_output_done)
align 16
httpasm_tls13_output_done:
    mov     rax, [rdi + httpasm_tls13_connection.output_end]
    sub     rax, [rdi + httpasm_tls13_connection.output_start]
    cmp     rsi, rax
    cmova   rsi, rax                        ; no more than is queued
    add     rsi, [rdi + httpasm_tls13_connection.output_start]
    mov     [rdi + httpasm_tls13_connection.output_start], rsi
    cmp     rsi, [rdi + httpasm_tls13_connection.output_end]
    jne     .done
    cmp     qword [rdi + httpasm_tls13_connection.flight], 0
    jne     .done
    xor     eax, eax
    mov     [rdi + httpasm_tls13_connection.output_start], rax
    mov     [rdi + httpasm_tls13_connection.output_end], rax
.done:
    ret
.end:

; -----------------------------------------------------------------------------
; int64_t httpasm_tls13_send(httpasm_tls13_connection *c, const uint8_t *data, size_t length)
;   Seals application data into the output, records of up to a record's content each, as many
;   octets as fit: returns how many it took (0 when the output is full); or -1 before our
;   Finished is out, after our close_notify, or after a failure. A KeyUpdate the peer asked for
;   goes first (4.7.3); under AES-GCM a KeyUpdate of ours goes before the write key's 2^24.5
;   records run out (5.5), so the key never refuses. Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_send:function (httpasm_tls13_send.end - httpasm_tls13_send)
align 16
httpasm_tls13_send:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 16                         ; [rsp]: seal's 7th argument (five pushes + 16: aligned)
    mov     rbx, rdi
    mov     r12, rsi
    mov     r13, rdx
    xor     r14d, r14d                      ; taken
    mov     rax, -1
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_FAILED
    je      .done
    test    dword [rbx + httpasm_tls13_connection.flags], TF_CLOSED
    jnz     .done
    test    dword [rbx + httpasm_tls13_connection.flags], TF_SENT_FINISHED
    jz      .done
    test    dword [rbx + httpasm_tls13_connection.flags], TF_UPDATE_OWED
    jz      .next
    xor     esi, esi                        ; update_not_requested
    call    ha_tls_key_update_send
    test    eax, eax
    jnz     .taken                          ; no room for it: nothing sent (call again)
.next:
    cmp     r14, r13
    jae     .taken
    cmp     word [rbx + httpasm_tls13_connection.suite], HTTPASM_TLS_CHACHA20_POLY1305_SHA256
    je      .room
    cmp     qword [rbx + httpasm_tls13_connection.write + httpasm_tls13_record_key.sequence], HTTPASM_TLS_GCM_RECORDS - 2
    jb      .room
    xor     esi, esi                        ; two records short of the limit: a new key first
    call    ha_tls_key_update_send
    test    eax, eax
    jnz     .taken
.room:
    xor     edx, edx
    call    ha_tls_out_free
    sub     rax, HTTPASM_TLS_RECORD_HEADER + 1 + HTTPASM_TLS_TAG
    jbe     .taken                          ; not even a one-octet record fits
    mov     r15, r13
    sub     r15, r14                        ; what is left
    cmp     r15, rax
    cmova   r15, rax                        ; what fits
    mov     ecx, [rbx + httpasm_tls13_connection.write + httpasm_tls13_record_key.limit]
    dec     rcx
    cmp     r15, rcx
    cmova   r15, rcx                        ; one record's content at most
    lea     rax, [r15 + HTTPASM_TLS_RECORD_HEADER + 1 + HTTPASM_TLS_TAG]
    mov     [rsp], rax
    lea     rdi, [rbx + httpasm_tls13_connection.write]
    mov     esi, HTTPASM_TLS_CONTENT_APPLICATION_DATA
    lea     rdx, [r12 + r14]
    mov     rcx, r15
    xor     r8d, r8d
    mov     r9, [rbx + httpasm_tls13_connection.output]
    add     r9, [rbx + httpasm_tls13_connection.output_end]
    call    httpasm_tls13_seal
    test    rax, rax
    js      .taken                          ; (unreachable: sizes measured, the limit kept)
    add     [rbx + httpasm_tls13_connection.output_end], rax
    add     r14, r15
    jmp     .next
.taken:
    mov     rax, r14
.done:
    add     rsp, 16
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_close(httpasm_tls13_connection *c)
;   Queues close_notify (6.1; AlertLevel warning, as implementations send it): we send nothing
;   more; the peer may go on. Returns 0, or -1 when the connection failed, was closed already, or
;   the record does not fit. Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_close:function (httpasm_tls13_close.end - httpasm_tls13_close)
align 16
httpasm_tls13_close:
    push    rbx
    sub     rsp, 16                         ; [rsp]: the alert (one push + 16: aligned)
    mov     rbx, rdi
    mov     eax, -1
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_FAILED
    je      .done
    test    dword [rbx + httpasm_tls13_connection.flags], TF_CLOSED
    jnz     .done
    mov     word [rsp], 0x0001              ; warning (1), close_notify (0)
    mov     esi, HTTPASM_TLS_CONTENT_ALERT
    mov     rdx, rsp
    mov     ecx, 2
    xor     r8d, r8d
    call    ha_tls_out_record
    test    eax, eax
    jnz     .refused
    or      dword [rbx + httpasm_tls13_connection.flags], TF_CLOSED
    xor     eax, eax
    jmp     .done
.refused:
    mov     eax, -1
.done:
    add     rsp, 16
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_key_update(httpasm_tls13_connection *c, int request)
;   Queues our KeyUpdate (request nonzero: update_requested) and moves to our next write key.
;   Returns 0, or -1 before the handshake completed, after a failure or our close_notify, or when
;   the record does not fit. Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_key_update:function (httpasm_tls13_key_update.end - httpasm_tls13_key_update)
align 16
httpasm_tls13_key_update:
    push    rbx                             ; (one push: rsp 16-aligned at the call)
    mov     rbx, rdi
    mov     eax, -1
    cmp     dword [rbx + httpasm_tls13_connection.state], TS_CONNECTED
    jne     .done
    test    dword [rbx + httpasm_tls13_connection.flags], TF_CLOSED
    jnz     .done
    xor     eax, eax
    test    esi, esi
    setnz   al
    mov     esi, eax
    call    ha_tls_key_update_send
.done:
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_negotiated(const httpasm_tls13_connection *c, uint32_t *suite, uint32_t *group,
;                              uint32_t *scheme)
;   What the handshake chose so far (0 for what is not chosen; any pointer may be NULL). Returns
;   0 before a ServerHello or HelloRetryRequest, 1 while the handshake goes on, 2 once connected,
;   -1 after a failure. A leaf: clobbers rax.
; -----------------------------------------------------------------------------
global httpasm_tls13_negotiated:function (httpasm_tls13_negotiated.end - httpasm_tls13_negotiated)
align 16
httpasm_tls13_negotiated:
    movzx   eax, word [rdi + httpasm_tls13_connection.suite]
    test    rsi, rsi
    jz      .group
    mov     [rsi], eax
.group:
    movzx   eax, word [rdi + httpasm_tls13_connection.group]
    test    rdx, rdx
    jz      .scheme
    mov     [rdx], eax
.scheme:
    movzx   eax, word [rdi + httpasm_tls13_connection.scheme]
    test    rcx, rcx
    jz      .state
    mov     [rcx], eax
.state:
    mov     eax, [rdi + httpasm_tls13_connection.state]
    cmp     eax, TS_FAILED
    je      .failed
    cmp     eax, TS_CONNECTED
    je      .connected
    test    eax, eax
    jz      .start
    mov     eax, 1
    ret
.connected:
    mov     eax, 2
    ret
.failed:
    mov     eax, -1
    ret
.start:
    xor     eax, eax                        ; TS_START: no answer sent yet
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_peer_certificates(const httpasm_tls13_connection *c, const uint8_t **list,
;                                     size_t *length)
;   The client's certificate_list as it sent it (CertificateEntry { cert_data, extensions }, the
;   leaf first: httpasm_tls13_certificate_entry walks it), kept in the connection's peer-chain
;   span: *list and *length (any pointer may be NULL). Returns its entries' count (0: the client
;   declined, an empty Certificate), or -1 before the client's Certificate came (no client
;   authentication configured, or not that far yet). The engine proved the client holds the
;   leaf's key (its CertificateVerify); whether the chain is to be trusted (issuers, names, dates)
;   is the caller's to judge (M3 brings validation). Valid until the connection is wiped. A leaf:
;   clobbers rax, rcx.
; -----------------------------------------------------------------------------
global httpasm_tls13_peer_certificates:function (httpasm_tls13_peer_certificates.end - httpasm_tls13_peer_certificates)
align 16
httpasm_tls13_peer_certificates:
    mov     eax, -1
    test    dword [rdi + httpasm_tls13_connection.flags], TF_PEER_CHAIN
    jz      .done
    test    rsi, rsi
    jz      .length
    mov     rcx, [rdi + httpasm_tls13_connection.peer]
    mov     [rsi], rcx
.length:
    test    rdx, rdx
    jz      .count
    mov     rcx, [rdi + httpasm_tls13_connection.peer_length]
    mov     [rdx], rcx
.count:
    mov     eax, [rdi + httpasm_tls13_connection.peer_count]
.done:
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_tls13_wipe(httpasm_tls13_connection *c)
;   Zeroes the connection's spans and then the connection itself: its secrets, keys and state
;   (the peer chain too: what a client sent is the connection's to forget with it). A leaf:
;   clobbers rax, rcx, rdi, rsi.
; -----------------------------------------------------------------------------
global httpasm_tls13_wipe:function (httpasm_tls13_wipe.end - httpasm_tls13_wipe)
align 16
httpasm_tls13_wipe:
    mov     rsi, rdi
    xor     eax, eax
    mov     rdi, [rsi + httpasm_tls13_connection.message]
    test    rdi, rdi
    jz      .peer
    mov     rcx, [rsi + httpasm_tls13_connection.message_capacity]
    rep     stosb
.peer:
    mov     rdi, [rsi + httpasm_tls13_connection.peer]
    test    rdi, rdi
    jz      .output
    mov     rcx, [rsi + httpasm_tls13_connection.peer_capacity]
    rep     stosb
.output:
    mov     rdi, [rsi + httpasm_tls13_connection.output]
    test    rdi, rdi
    jz      .self
    mov     rcx, [rsi + httpasm_tls13_connection.output_capacity]
    rep     stosb
.self:
    mov     rdi, rsi
    mov     ecx, httpasm_tls13_connection_size
    rep     stosb
    ret
.end:
