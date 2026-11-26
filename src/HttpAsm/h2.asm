; =============================================================================
; h2.asm - the driver's HTTP/2 engine (RFC 9113): h2c with prior knowledge on a connection whose
; first octets are the client preface. Frames are parsed in place from the connection's input;
; responses are framed into its output; the handler sees the same exchange as with HTTP/1.1.
;
; Streams are independent: each has its own request, body, exchange and flow-control windows,
; and a deferred stream holds up nothing else. A request goes to the handler once it ended
; (END_STREAM), with its whole body (and trailers); the body is bounded by max_body (413).
;
; The protocol's rules, by section (h2spec's 146 cases exercise them):
;   3.4    the client preface, then a SETTINGS frame first;
;   4.1/2  frame header, sizes (FRAME_SIZE_ERROR past SETTINGS_MAX_FRAME_SIZE), unknown types
;          ignored, the reserved bit masked;
;   4.3    field blocks: HEADERS then CONTINUATIONs of the same stream and nothing in between;
;          every block decoded, even a refused stream's, so HPACK stays in step;
;   5.1    stream states: idle, open, half-closed, closed; a closed stream is remembered with
;          how it closed (normal end: connection error STREAM_CLOSED; peer reset: stream error;
;          this side's reset: frames in flight ignored); 5.1.1 ids odd and increasing; 5.1.2
;          SETTINGS_MAX_CONCURRENT_STREAMS (REFUSED_STREAM beyond);
;   5.3    a stream depending on itself is a stream error;
;   5.4    connection errors write GOAWAY and close; stream errors write RST_STREAM;
;   6.8    every close is preceded by a GOAWAY: an error's, or NO_ERROR with the last stream the
;          peer opened (ha_h2_goodbye: the idle timeout, a stop, the peer's own GOAWAY); a
;          graceful stop first says GOAWAY with 2^31 - 1 while streams finish (ha_h2_notice);
;   6.x    every frame type's fields, lengths, stream-0 rules and padding;
;   6.9    flow control both ways, windows signed (a SETTINGS change can make them negative),
;          2^31 - 1 the most; a response's body waits for window and resumes on WINDOW_UPDATE and
;          on SETTINGS_INITIAL_WINDOW_SIZE changes;
;   8.1    a request ends with END_STREAM; trailers end it too; content-length must equal the
;          DATA; a response before the request's end is followed by RST_STREAM(NO_ERROR);
;   8.2/8.3 field and pseudo-field rules (the core's httpasm_h2_request), cookies joined
;          (8.2.3), connection-specific fields refused in responses as well; a malformed
;          request head gets 400 and then RST_STREAM(PROTOCOL_ERROR) (h2_bad_request);
;   8.4    a client's PUSH_PROMISE is a PROTOCOL_ERROR.
; Hardening (the published floods, RFC 9113 10.5):
;   - resets: past HA_H2_RESET_FLOOR, more than one reset for every two streams opened is
;     ENHANCE_YOUR_CALM (h2_count_reset), whether the peer sends them (CVE-2023-44487, rapid
;     reset) or provokes this side's (CVE-2025-8671, "MadeYouReset": h2_peer_stream_error);
;   - glitches: PRIORITY, empty DATA without END_STREAM, unknown frame types, refusals and
;     every stream error the peer causes spend a token bucket (h2_glitch: 10,000 at once, 330
;     a second, nghttp2's defaults); spent, ENHANCE_YOUR_CALM (CVE-2019-9513, 9514, 9518);
;   - field blocks are bounded in octets and CONTINUATION frames (CVE-2024-27316), and HPACK
;     past the limits only measures (the core's decoder: no HPACK bomb);
;   - no frame costs more than its size and the active streams once: SETTINGS applies a frame's
;     net window change in one walk (h2_settings), a WINDOW_UPDATE on stream 0 walks the
;     streams only when a body waits for that window (H2F_CONN_BLOCKED), and a stream is found
;     by four ids per compare (h2_slot);
;   - output past HA_OUTPUT_HIGH stops the input (the same back-pressure as HTTP/1.1), so a
;     peer that does not read cannot make PING, SETTINGS or reset answers pile up
;     (CVE-2019-9512, 9514, 9515).
;
; Memory: the connection's state (this file's h2, with both HPACK tables) is one block; each
; stream is one block plus its request's fields (one block), trailers, body and pending output.
; Field blocks decode into the worker's scratch first and are copied to the stream before any
; handler runs, because the decoder's output must outlive the input buffer.
;
; Registers in the frame handlers: rbx = conn, r12 = its h2 state. Every function keeps rbx,
; rbp and r12-r15 (System V), so the handlers and the handler's calls back (respond) can nest.
; =============================================================================
default rel
%include "httpasm.inc"
%include "h2/h2.inc"
%include "internal/driver.inc"


section .rodata
s_preface:          db "PRI * HTTP/2.0", 13, 10, 13, 10, "SM", 13, 10, 13, 10
s_stop_ping:        db "HAstop!", 0 ; the graceful stop's PING payload (8 octets): its ACK
                                    ; is the round trip ha_h2_notice waits for
s_status:           db ":status"
s_date:             db "date"
s_content_length:   db "content-length"
s_content_type:     db "content-type"   ; the server's own answers explain themselves in
s_text_plain:       db "text/plain"     ; plain text (h2_error_response)

section .text

; -----------------------------------------------------------------------------
; ha_h2_detect: whether a connection's first octets are HTTP/2's client preface (RFC 9113 3.4).
;   In: rdi = conn (input non-empty). Out: eax = 1 (the whole preface), 0 (not HTTP/2), -1 (a
;   prefix of it so far: wait), 2 (an invalid preface: its first line "PRI * HTTP/2.0" came
;   whole, so the client speaks HTTP/2, but what follows is not the preface's end; a
;   connection error PROTOCOL_ERROR whose GOAWAY may be omitted, RFC9113-3.4-9: the caller
;   closes without a word, where HTTP/1.1 would have answered its 505).
;   Clobbers rcx, rdx, rsi, r8 and the flags.
; -----------------------------------------------------------------------------
global ha_h2_detect:function hidden (ha_h2_detect.end - ha_h2_detect)
align 16
ha_h2_detect:
    mov     rsi, [rdi + conn.rbuf]
    mov     rcx, [rdi + conn.rlen]
    mov     r8d, H2_PREFACE_LENGTH
    cmp     rcx, r8
    cmova   rcx, r8                         ; compare what has arrived, up to 24 octets
    lea     rdx, [rel s_preface]
    xor     r8d, r8d
.octet:
    movzx   eax, byte [rsi + r8]
    cmp     al, [rdx + r8]
    jne     .not_h2
    inc     r8
    cmp     r8, rcx
    jb      .octet
    mov     eax, -1
    cmp     rcx, H2_PREFACE_LENGTH
    jb      .out
    mov     eax, 1
.out:
    ret
.not_h2:
    xor     eax, eax
    cmp     r8, H2_PREFACE_LINE             ; the mismatch's offset: past "PRI * HTTP/2.0\r\n"?
    jb      .other
    mov     eax, 2                          ; an HTTP/2 client with a broken preface
.other:
    ret
.end:

; -----------------------------------------------------------------------------
; h2_frame_header: writes a frame header (RFC 9113 4.1) at rdi.
;   In: rdi = where, esi = payload length, edx = type, ecx = flags, r8d = stream id.
;   Clobbers rax and the flags.
; -----------------------------------------------------------------------------
align 16
h2_frame_header:
    mov     eax, esi
    shr     eax, 16
    mov     [rdi], al
    mov     eax, esi
    shr     eax, 8
    mov     [rdi + 1], al
    mov     [rdi + 2], sil
    mov     [rdi + 3], dl
    mov     [rdi + 4], cl
    mov     eax, r8d
    bswap   eax
    mov     [rdi + 5], eax
    ret

; -----------------------------------------------------------------------------
; h2_frame: appends one whole frame (header and payload) to the connection's output.
;   In: rbx = conn, edi = type, esi = flags, edx = stream id, rcx = payload, r8 = its length.
;   Out: eax = 0, or -ENOMEM. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
F_TYPE      equ 0
F_FLAGS     equ 4
F_STREAM    equ 8
F_PAYLOAD   equ 16
F_LENGTH    equ 24
F_FRAME     equ 40      ; entered at 8 past 16: 40 more leaves rsp aligned

align 16
h2_frame:
    sub     rsp, F_FRAME
    mov     [rsp + F_TYPE], edi
    mov     [rsp + F_FLAGS], esi
    mov     [rsp + F_STREAM], edx
    mov     [rsp + F_PAYLOAD], rcx
    mov     [rsp + F_LENGTH], r8
    mov     rdi, rbx
    lea     rsi, [r8 + H2_FRAME_HEADER]
    call    ha_output_reserve               ; the whole frame first: pointers into the output
    test    eax, eax                        ; are stale after a reserve
    jnz     .out
    mov     rdi, [rbx + conn.wbuf]
    add     rdi, [rbx + conn.wlen]
    mov     esi, [rsp + F_LENGTH]
    mov     edx, [rsp + F_TYPE]
    mov     ecx, [rsp + F_FLAGS]
    mov     r8d, [rsp + F_STREAM]
    call    h2_frame_header
    add     rdi, H2_FRAME_HEADER
    mov     rsi, [rsp + F_PAYLOAD]
    mov     rcx, [rsp + F_LENGTH]
    COPY_OCTETS                             ; empty for every SETTINGS ACK
    mov     rax, [rsp + F_LENGTH]
    add     rax, H2_FRAME_HEADER
    add     [rbx + conn.wlen], rax
    xor     eax, eax
.out:
    add     rsp, F_FRAME
    ret

; -----------------------------------------------------------------------------
; h2_u32_frame: a frame whose payload is one big-endian 32-bit value (RST_STREAM, WINDOW_UPDATE).
;   In: rbx = conn, edi = type, edx = stream id, esi = the value. Out: eax = 0 or -ENOMEM.
;   Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_u32_frame:
    sub     rsp, 24
    bswap   esi
    mov     [rsp], esi
    xor     esi, esi
    mov     rcx, rsp
    mov     r8d, 4
    call    h2_frame
    add     rsp, 24
    ret

; -----------------------------------------------------------------------------
; h2_connection_error: GOAWAY with the error and the last stream the peer opened, then the
; connection closes once the output is sent (RFC 9113 5.4.1). Input is ignored from now on.
;   In: rbx = conn, r12 = h2, edi = the error code. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_connection_error:
    test    dword [r12 + h2.flags], H2F_CLOSING
    jnz     .out                            ; one GOAWAY is enough
    or      dword [r12 + h2.flags], H2F_CLOSING
    sub     rsp, 24
    mov     eax, [r12 + h2.last_stream]
    bswap   eax
    mov     [rsp], eax
    bswap   edi
    mov     [rsp + 4], edi
    mov     edi, H2_GOAWAY
    xor     esi, esi
    xor     edx, edx
    mov     rcx, rsp
    mov     r8d, 8
    call    h2_frame
    add     rsp, 24
    or      dword [rbx + conn.flags], C_CLOSE_AFTER
.out:
    ret

; -----------------------------------------------------------------------------
; h2_goaway_frame: appends a GOAWAY (RFC 9113 6.8) with a last stream id and an error code, and
; no debug data (RFC9113-6.8-21#1 allows some; this side has nothing to say in it). Used by the
; closing paths that are not connection errors: the goodbye before a close, a graceful stop's
; notice.
;   In: rbx = conn, edi = the last stream id, esi = the error code. Out: eax = 0, or -ENOMEM
;   (nothing written). Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_goaway_frame:
    sub     rsp, 24                         ; entered at 8 past 16: 24 more leaves rsp aligned
    bswap   edi
    mov     [rsp], edi                      ; Last-Stream-ID (the reserved bit is 0: ids < 2^31)
    bswap   esi
    mov     [rsp + 4], esi                  ; Error Code
    mov     edi, H2_GOAWAY
    xor     esi, esi                        ; GOAWAY defines no flags
    xor     edx, edx                        ; and always goes on stream 0
    mov     rcx, rsp
    mov     r8d, 8
    call    h2_frame
    add     rsp, 24
    ret

; -----------------------------------------------------------------------------
; ha_h2_goodbye: the connection is about to close. Unless its final GOAWAY went out already (a
; connection error, or an earlier goodbye), GOAWAY(NO_ERROR) with the last stream the peer
; opened is appended, so the client learns which of its requests this side may have acted on
; and which it can safely retry elsewhere (RFC9113-6.8-5, 9.1-5, 5.4.1-4#2: a GOAWAY before
; every close). Then one non-blocking send of whatever the output still holds, the GOAWAY last.
; Best effort, on purpose: the descriptor closes right after this returns, whatever the send
; did; a full socket or a peer already gone loses the GOAWAY, which costs the client nothing a
; bare close would not have.
;   Footgun: call it while the descriptor is still open and before ha_h2_free (it reads the
;   state's last stream); after a shutdown(SHUT_WR) the send just fails, harmlessly.
;   In: rdi = conn (conn.h2 may be 0: nothing happens). Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
global ha_h2_goodbye:function hidden (ha_h2_goodbye.end - ha_h2_goodbye)
align 16
ha_h2_goodbye:
    push    rbx
    push    r12
    sub     rsp, 8                          ; two pushes + 8: aligned for the calls below
    mov     rbx, rdi
    mov     r12, [rbx + conn.h2]
    test    r12, r12
    jz      .out
    test    dword [r12 + h2.flags], H2F_CLOSING
    jnz     .out                            ; the final GOAWAY was written before (and flushed)
    or      dword [r12 + h2.flags], H2F_CLOSING
    mov     edi, [r12 + h2.last_stream]
    mov     esi, H2_NO_ERROR
    call    h2_goaway_frame
    test    eax, eax
    jnz     .out                            ; no memory for it: the close goes ahead without
    ; io_uring: a SEND submitted in this batch, whose completion is not handled yet, has sent
    ; octets this side still counts as unsent; sending from wsent would repeat them, so the
    ; GOAWAY is given up instead (a SEND only queued is fine: closing drops it unsubmitted).
    test    dword [rbx + conn.uflags], U_SEND
    jnz     .out
    mov     edi, [rbx + conn.fd]
    mov     rsi, [rbx + conn.wbuf]
    add     rsi, [rbx + conn.wsent]         ; the unsent output, the GOAWAY at its end
    mov     rdx, [rbx + conn.wlen]
    sub     rdx, [rbx + conn.wsent]
    mov     r10d, MSG_NOSIGNAL              ; a gone peer is an error code, not a SIGPIPE
    xor     r8d, r8d
    xor     r9d, r9d
    mov     eax, SYS_sendto                 ; the socket is non-blocking: a full one returns at once
    syscall                                 ; whatever it returns: the descriptor closes next
.out:
    add     rsp, 8
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_h2_notice: a graceful stop began. GOAWAY(NO_ERROR) with the last stream id 2^31 - 1 tells
; the client to open no more streams, while every stream already on its way is still served
; (RFC9113-6.8-18#1); a PING follows it, and its ACK (h2_ping: H2F_NOTICE_ACKED) proves the
; client has seen the notice, so everything it sent before has arrived: RFC 9113 6.8's "at
; least one round-trip time" for in-flight streams, measured instead of guessed. The final
; GOAWAY, with the real last stream id, goes out when the connection closes once idle and
; acknowledged (close_idle, ha_h2_goodbye; RFC9113-6.8-18#2), so no request is lost between the
; two. Every HTTP/2 connection gets it, idle ones included: closing an idle one at once lost a
; request already on its way (Http2FrameTests.ShutsDownGracefully failed that way under the
; slower coverage build, 2026-11-26). Once per connection; nothing after a connection error. The
; output is flushed at once (the stop has no other reason to write).
;   In: rdi = conn (conn.h2 may be 0: nothing happens). Out: eax = 0, or 1 when the flush closed
;   the connection (a failed send). Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
global ha_h2_notice:function hidden (ha_h2_notice.end - ha_h2_notice)
align 16
ha_h2_notice:
    push    rbx
    push    r12
    sub     rsp, 8                          ; two pushes + 8: aligned for the calls below
    mov     rbx, rdi
    xor     eax, eax
    mov     r12, [rbx + conn.h2]
    test    r12, r12
    jz      .out
    test    dword [r12 + h2.flags], H2F_CLOSING | H2F_NOTICE
    jnz     .out                            ; said already, or closing anyway
    or      dword [r12 + h2.flags], H2F_NOTICE
    mov     edi, 0x7FFFFFFF                 ; 2^31 - 1: every stream id is still "may be served"
    mov     esi, H2_NO_ERROR
    call    h2_goaway_frame
    test    eax, eax
    jnz     .unsent                         ; no memory: the stop goes on without the notice
    mov     edi, H2_PING                    ; the round trip's probe, after the GOAWAY
    xor     esi, esi
    xor     edx, edx
    lea     rcx, [rel s_stop_ping]
    mov     r8d, 8
    call    h2_frame
    test    eax, eax
    jnz     .no_ping                        ; no memory: idle closes without the round trip
    mov     rdi, rbx
    call    ha_conn_flush                   ; eax = 1 when it closed the connection
    jmp     .out
.no_ping:
    or      dword [r12 + h2.flags], H2F_NOTICE_ACKED  ; nothing to wait for: close when idle
    mov     rdi, rbx
    call    ha_conn_flush
    jmp     .out
.unsent:
    or      dword [r12 + h2.flags], H2F_NOTICE_ACKED  ; no notice went out: none to wait on
    xor     eax, eax
.out:
    add     rsp, 8
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; h2_slot: the slot of the active stream with an id, by four ids per compare from h2.ids (SSE2,
; the x86-64 baseline: no tier needed for at most HA_H2_MAX_STREAMS ids). Every frame that names
; a stream looks it up, so the cost is per frame: the scan it replaced followed each active
; stream's pointer to read its id, up to 100 dependent loads even for a stream long gone. A
; slot past stream_count holds a stale id (a removed stream's, or 0), so a match there means
; none; ids are never reused (they only increase), so no active stream shares a stale id.
;   In: r12 = h2, edi = id. Out: eax = the slot, or -1 (rax's upper half 0 either way with a
;   slot; -1 sign-extended otherwise). Clobbers rcx, rdx, xmm0, xmm1 and the flags.
; -----------------------------------------------------------------------------
align 16
h2_slot:
    mov     ecx, [r12 + h2.stream_count]
    movd    xmm0, edi
    pshufd  xmm0, xmm0, 0                   ; the id in all four lanes
    xor     edx, edx
.block:
    cmp     edx, ecx
    jae     .none
    movdqu  xmm1, [r12 + h2.ids + rdx * 4]  ; the padding keeps the last load inside h2
    pcmpeqd xmm1, xmm0
    pmovmskb eax, xmm1
    test    eax, eax
    jnz     .match
    add     edx, 4
    jmp     .block
.match:
    bsf     eax, eax                        ; the first matching lane: an active one comes
    shr     eax, 2                          ; before any stale one of this block
    add     eax, edx
    cmp     eax, ecx
    jae     .none                           ; a stale id past the active ones
    ret
.none:
    mov     rax, -1
    ret

; -----------------------------------------------------------------------------
; h2_find: the active stream with an id (h2_slot).
;   In: r12 = h2, edi = id. Out: rax = the stream, or 0. Clobbers rcx, rdx, xmm0, xmm1 and the
;   flags (callers rely on it calling nothing: it touches no other register).
; -----------------------------------------------------------------------------
align 16
h2_find:
    call    h2_slot
    test    eax, eax
    js      .none
    mov     rax, [r12 + h2.streams + rax * 8]
    ret
.none:
    xor     eax, eax
    ret

; -----------------------------------------------------------------------------
; h2_remember: records how a stream closed, in the ring of recent ones.
;   In: r12 = h2, edi = id, esi = H2C_*. Clobbers rax, rcx and the flags.
; -----------------------------------------------------------------------------
align 16
h2_remember:
    mov     eax, esi
    shl     rax, 32
    or      rax, rdi                        ; edi's upper half is 0
    mov     ecx, [r12 + h2.closed_next]
    mov     [r12 + h2.closed + rcx * 8], rax
    inc     ecx
    cmp     ecx, HA_H2_CLOSED_RING
    jb      .stored
    xor     ecx, ecx
.stored:
    mov     [r12 + h2.closed_next], ecx
    ret

; -----------------------------------------------------------------------------
; h2_closed_how: how a stream not active any more closed, if it is still remembered.
;   In: r12 = h2, edi = id. Out: eax = H2C_*, or 0 (never opened, or forgotten).
;   Clobbers rcx, rdx and the flags.
; -----------------------------------------------------------------------------
align 16
h2_closed_how:
    xor     ecx, ecx
.next:
    mov     rdx, [r12 + h2.closed + rcx * 8]
    cmp     edx, edi
    je      .found
    inc     ecx
    cmp     ecx, HA_H2_CLOSED_RING
    jb      .next
    xor     eax, eax
    ret
.found:
    shr     rdx, 32
    mov     eax, edx
    test    edi, edi
    jnz     .out
    xor     eax, eax                        ; id 0 is never a stream (empty slots hold 0)
.out:
    ret

; -----------------------------------------------------------------------------
; h2_free_stream: frees a stream and everything it owns. In: rdi = stream.
;   Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_free_stream:
    push    rbx
    mov     rbx, rdi
    mov     rdi, [rbx + h2stream.body]
    call    free wrt ..plt
    mov     rdi, [rbx + h2stream.out]
    call    free wrt ..plt
    mov     rdi, [rbx + h2stream.head]
    call    free wrt ..plt
    mov     rdi, [rbx + h2stream.tail]
    call    free wrt ..plt
    mov     rdi, rbx
    call    free wrt ..plt
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; h2_close: a stream leaves the active set, and is remembered with how it closed. A stream
; whose handler still holds its exchange (deferred, or running now) is detached instead of
; freed (HSF_CANCELLED): its owner frees it when the handler returns or the answer comes.
;   In: rbx = conn, r12 = h2, rdi = stream, esi = H2C_*. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_close:
    push    r13
    mov     r13, rdi
    mov     edi, [r13 + h2stream.id]
    call    h2_remember
    mov     edi, [r13 + h2stream.id]        ; out of the active set: the last one takes its
    call    h2_slot                         ; slot, in both arrays
    test    eax, eax
    js      .removed                        ; not active (closed before): nothing to move
    mov     ecx, [r12 + h2.stream_count]
    dec     ecx
    mov     rdx, [r12 + h2.streams + rcx * 8]
    mov     [r12 + h2.streams + rax * 8], rdx
    mov     edx, [r12 + h2.ids + rcx * 4]
    mov     [r12 + h2.ids + rax * 4], edx
    mov     [r12 + h2.stream_count], ecx
.removed:
    test    dword [r13 + h2stream.flags], HSF_DEFERRED | HSF_IN_HANDLER
    jz      .free
    or      dword [r13 + h2stream.flags], HSF_CANCELLED
    jmp     .out
.free:
    mov     rdi, r13
    call    h2_free_stream
.out:
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_touch: a request head was accepted: activity, so the connection starts a new window
; (ha_lru_touch). A connection kept busy this way never reaches its deadline, where its streams
; would be judged (ha_conn_expire), so they are judged here as well, once a window
; (ha_h2_sweep, when the last sweep is an idle timeout old). Otherwise a client could hold up
; to 100 streams of half-sent uploads behind a trickle of real requests.
;   The stream whose head was just accepted is not touched by the sweep: its window began when
;   it opened (h2_new_stream), moments ago.
;   In: rbx = conn, r12 = h2. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_touch:
    sub     rsp, 8
    mov     rax, [rbx + conn.worker]
    mov     rcx, [rax + worker.now_ms]
    sub     rcx, [r12 + h2.swept]           ; how long ago the streams were last judged
    mov     rax, [rax + worker.server]
    cmp     rcx, [rax + server.idle_ms]
    jb      .touch
    mov     rdi, rbx
    call    ha_h2_sweep
.touch:
    mov     rdi, rbx
    call    ha_lru_touch
    add     rsp, 8
    ret

; -----------------------------------------------------------------------------
; ha_h2_sweep: every active stream judged on its own progress, as ha_conn_expire judges the
; connection: h2stream.moved counts the stream's DATA in either direction (its request's body
; arriving, its answer leaving as its window opens) since .moved_since. A stream whose window
; is an idle timeout old starts a new one if it moved at least min_rate octets a second over
; it; one below that is stuck:
;   - its request stopped arriving (RUDY over HTTP/2): no answer has begun, so it is answered
;     408 (Request Timeout, RFC 9110 15.5.9), and reset with NO_ERROR since its request never
;     ended (an early answer, h2_error_response);
;   - its answer stopped leaving (the client never opens its window: a slow read holding the
;     answer's memory): reset with CANCEL.
; Streams a handler holds (deferred, or its handler running) are the handler's to finish.
;   In: rdi = conn (HTTP/2). Clobbers every caller-saved register. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global ha_h2_sweep:function hidden (ha_h2_sweep.end - ha_h2_sweep)
align 16
ha_h2_sweep:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15                             ; five pushes: rsp aligned for the calls
    mov     rbx, rdi
    mov     r12, [rbx + conn.h2]
    test    dword [r12 + h2.flags], H2F_CLOSING
    jnz     .out
    mov     rax, [rbx + conn.worker]
    mov     r15, [rax + worker.now_ms]
    mov     [r12 + h2.swept], r15
    xor     r13d, r13d                      ; the slot
.stream:
    cmp     r13d, [r12 + h2.stream_count]
    jae     .out
    mov     r14, [r12 + h2.streams + r13 * 8]
    test    dword [r14 + h2stream.flags], HSF_DEFERRED | HSF_IN_HANDLER
    jnz     .next
    mov     rcx, r15
    sub     rcx, [r14 + h2stream.moved_since]   ; its window's age
    mov     rax, [rbx + conn.worker]
    mov     rax, [rax + worker.server]
    cmp     rcx, [rax + server.idle_ms]
    jb      .next                           ; younger than a window: not judged yet
    mov     eax, [rax + server.min_rate]
    imul    rax, rcx                        ; what its window needed, in thousandths of octets
    imul    rdx, [r14 + h2stream.moved], 1000
    cmp     rdx, rax
    jb      .stuck
    mov     qword [r14 + h2stream.moved], 0 ; it kept the pace: a new window
    mov     [r14 + h2stream.moved_since], r15
.next:
    inc     r13d
    jmp     .stream
.stuck:
    test    dword [r14 + h2stream.flags], HSF_ANSWERED
    jnz     .cancel
    mov     rdi, r14
    mov     esi, 408
    call    h2_error_response
    jmp     .judged
.cancel:
    mov     edi, [r14 + h2stream.id]
    mov     esi, H2_CANCEL
    call    h2_stream_error
.judged:
    ; The stream may have left the active set, the last one taking its slot: the slot is
    ; judged again unless it still holds this stream (a 408 whose DATA waits for window: its
    ; window starts over, so it is not judged twice).
    test    dword [r12 + h2.flags], H2F_CLOSING
    jnz     .out
    cmp     r13d, [r12 + h2.stream_count]
    jae     .out
    cmp     [r12 + h2.streams + r13 * 8], r14
    jne     .stream
    mov     qword [r14 + h2stream.moved], 0
    mov     [r14 + h2stream.moved_since], r15
    inc     r13d
    jmp     .stream
.out:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; h2_glitch: spends one glitch of the connection's budget (RFC9113-10.5-6: "track the use of
; these features and set limits on their use"). A glitch is a frame that costs this side work
; and moves no request forward: PRIORITY, an empty DATA frame without END_STREAM, a frame of an
; unknown type, or any frame that makes this side reset a stream (h2_peer_stream_error). Each
; is legal and cheap alone; floods of them are CVE-2019-9513 (PRIORITY), CVE-2019-9518 (empty
; frames), CVE-2019-9514 and CVE-2025-8671 (resets the peer provokes). The budget is a token
; bucket in thousandths of a glitch: it refills by HA_H2_GLITCH_RATE a second, by the worker's
; clock (refreshed after every wait), and holds at most HA_H2_GLITCH_BURST. Spent, the
; connection ends with ENHANCE_YOUR_CALM (RFC9113-10.5-6#2).
;   In: rbx = conn, r12 = h2. Out: eax = 1 when the connection is closing now (the caller acts
;   on the frame no further), else 0. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_glitch:
    mov     rax, [rbx + conn.worker]
    mov     rax, [rax + worker.now_ms]
    mov     rcx, rax
    sub     rcx, [r12 + h2.glitch_time]     ; the ms since the last refill (never negative:
    mov     [r12 + h2.glitch_time], rax     ; the clock is monotonic)
    imul    rcx, rcx, HA_H2_GLITCH_RATE     ; thousandths earned: rate per second = per 1000 ms
    add     rcx, [r12 + h2.glitch_tokens]
    mov     edx, HA_H2_GLITCH_BURST * 1000
    cmp     rcx, rdx
    cmova   rcx, rdx                        ; a full bucket holds the burst, no more
    sub     rcx, 1000                       ; this glitch
    jb      .spent
    mov     [r12 + h2.glitch_tokens], rcx
    xor     eax, eax
    ret
.spent:
    mov     qword [r12 + h2.glitch_tokens], 0
    sub     rsp, 8
    mov     edi, H2_ENHANCE_YOUR_CALM
    call    h2_connection_error
    add     rsp, 8
    mov     eax, 1
    ret

; -----------------------------------------------------------------------------
; h2_count_reset: one more active stream ended by a reset - the peer's RST_STREAM, or one this
; side sent because of the peer's frames (h2_peer_stream_error). Either frees a stream slot
; while the request's handler may still be at work: CVE-2023-44487 (rapid reset) does it with
; the client's own RST_STREAM, CVE-2025-8671 ("MadeYouReset") by provoking the server's. Past
; HA_H2_RESET_FLOOR resets, more than one reset for every two streams opened is
; ENHANCE_YOUR_CALM (RFC9113-10.5-6#2).
;   In: rbx = conn, r12 = h2. Out: eax = 1 when the connection is closing now, else 0.
;   Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_count_reset:
    inc     dword [r12 + h2.resets]
    mov     eax, [r12 + h2.resets]
    cmp     eax, HA_H2_RESET_FLOOR
    jbe     .fine
    shl     rax, 1
    cmp     rax, [r12 + h2.opened]
    jbe     .fine
    sub     rsp, 8
    mov     edi, H2_ENHANCE_YOUR_CALM
    call    h2_connection_error
    add     rsp, 8
    mov     eax, 1
    ret
.fine:
    xor     eax, eax
    ret

; -----------------------------------------------------------------------------
; h2_peer_stream_error: a stream error the peer's frames caused (a malformed request, a frame
; on a closed stream, a WINDOW_UPDATE of 0, a window past 2^31 - 1, ...): RST_STREAM with the
; error, as h2_stream_error. It is also a glitch (h2_glitch), and when the stream was active,
; one more reset for the rapid-reset rule (h2_count_reset): a client that makes this side reset
; its streams frees their slots as surely as one that resets them itself (CVE-2025-8671). When
; either ends the connection, the RST_STREAM is not sent: the GOAWAY says it all. Stream errors
; of this side's own making (no memory, an early answer's NO_ERROR) use h2_stream_error.
;   In: rbx = conn, r12 = h2, edi = id, esi = the error code. Clobbers every caller-saved
;   register.
; -----------------------------------------------------------------------------
align 16
h2_peer_stream_error:
    push    r13
    push    r14
    sub     rsp, 8
    mov     r13d, edi
    mov     r14d, esi
    call    h2_glitch
    test    eax, eax
    jnz     .out
    mov     edi, r13d
    call    h2_find
    test    rax, rax
    jz      .reset                          ; not active: no slot freed, nothing to count
    call    h2_count_reset
    test    eax, eax
    jnz     .out
.reset:
    mov     edi, r13d
    mov     esi, r14d
    call    h2_stream_error
.out:
    add     rsp, 8
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_stream_error: RST_STREAM with the error (RFC 9113 5.4.2); the stream, if active, closes as
; reset by this side (later frames already in flight are ignored), else is remembered so.
;   In: rbx = conn, r12 = h2, edi = id, esi = the error code. Clobbers caller-saved registers.
; -----------------------------------------------------------------------------
align 16
h2_stream_error:
    push    r13
    push    r14
    sub     rsp, 8
    mov     r13d, edi
    mov     edx, edi
    mov     edi, H2_RST_STREAM
    call    h2_u32_frame
    mov     edi, r13d
    call    h2_find
    test    rax, rax
    jz      .remember
    mov     rdi, rax
    mov     esi, H2C_RESET
    call    h2_close
    jmp     .out
.remember:
    ; Not active: a frame on a stream that closed before (a peer's reset, say) or never opened.
    ; A stream the ring holds already has its entry turned into this side's reset, so the
    ; peer's frames still in flight are ignored from now on instead of drawing one more
    ; RST_STREAM each (RFC9113-5.4.2-4#1: normally one per stream). Appending instead would
    ; leave the older entry first in h2_closed_how's search. The scan costs only on this error
    ; path; a normal close (h2_close) appends without one.
    test    r13d, r13d
    jz      .append                         ; id 0 is no stream (empty slots hold 0)
    xor     ecx, ecx
.scan:
    mov     rax, [r12 + h2.closed + rcx * 8]
    cmp     eax, r13d
    je      .update
    inc     ecx
    cmp     ecx, HA_H2_CLOSED_RING
    jb      .scan
.append:
    mov     edi, r13d
    mov     esi, H2C_RESET
    call    h2_remember
    jmp     .out
.update:
    mov     eax, H2C_RESET
    shl     rax, 32
    or      rax, r13                        ; r13's upper half is 0 (mov r13d above)
    mov     [r12 + h2.closed + rcx * 8], rax
.out:
    add     rsp, 8
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_window_update: gives received octets back to the peer (RFC 9113 6.9).
;   In: rbx = conn, edi = stream id (0: the connection), esi = the increment.
;   Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_window_update:
    mov     edx, edi
    mov     edi, H2_WINDOW_UPDATE
    jmp     h2_u32_frame

; -----------------------------------------------------------------------------
; ha_h2_start: a connection speaks HTTP/2 from now on. Its state (with both HPACK tables) is
; allocated, the worker's decoding scratch on its first HTTP/2 connection, and this side's
; preface is written: SETTINGS (MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE,
; MAX_HEADER_LIST_SIZE; the table and frame sizes stay at their defaults, so they are not
; sent; ENABLE_PUSH is a client's setting) and a WINDOW_UPDATE raising the connection's
; receive window to HA_H2_CONNECTION_WINDOW.
;   In: rdi = conn. Out: eax = 0, or -ENOMEM. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
global ha_h2_start:function hidden (ha_h2_start.end - ha_h2_start)
align 16
ha_h2_start:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 32                         ; five pushes + 32: aligned; the SETTINGS payload
    mov     rbx, rdi
    mov     r13, [rbx + conn.worker]
    mov     r14, [r13 + worker.server]
    ; The limits: max_head (the decoded field section) and max_fields, defaults for 0.
    mov     r15d, [r14 + server.limits + httpasm_h1_limits.max_head]
    mov     eax, HA_H1_DEFAULT_MAX_HEAD
    test    r15d, r15d
    cmovz   r15d, eax
    ; The worker's decoding scratch, made at its first HTTP/2 connection: both buffers or
    ; neither. The space is allocated last, so it alone says the scratch is whole, and when its
    ; allocation fails the fields array goes too. Until 2026-11-26 the fields alone were
    ; checked: after the space's allocation failed, the next HTTP/2 connection found the fields,
    ; took the scratch as ready, and decoded its first field block into a NULL space - a crash
    ; in hp_string (tests/native/faults, the 26th allocation failing).
    cmp     qword [r13 + worker.h2_space], 0
    jne     .scratch_ready
    mov     eax, [r14 + server.limits + httpasm_h1_limits.max_fields]
    mov     ecx, HA_H1_DEFAULT_MAX_FIELDS
    test    eax, eax
    cmovz   eax, ecx
    shl     eax, 5
    mov     edi, eax
    call    malloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     [r13 + worker.h2_fields], rax
    mov     edi, r15d
    call    malloc wrt ..plt
    test    rax, rax
    jz      .no_scratch_space
    mov     [r13 + worker.h2_space], rax
.scratch_ready:
    ; One block: the state, then the decoder's and the encoder's HPACK tables.
    mov     edi, HA_H2_TABLE
    call    httpasm_hpack_size
    mov     r12, rax                        ; one table's octets
    lea     rsi, [h2_size + rax * 2 + 64]
    mov     edi, 1
    call    calloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    xchg    rax, r12                        ; r12 = the state, rax = one table's octets
    mov     [rbx + conn.h2], r12
    mov     r13, rax
    lea     rdi, [r12 + h2_size + 63]
    and     rdi, -64                        ; tables 64-octet aligned
    mov     [r12 + h2.decoder], rdi
    lea     rax, [rdi + r13]
    mov     [r12 + h2.encoder], rax
    mov     rsi, r13
    mov     edx, HA_H2_TABLE
    xor     ecx, ecx
    call    httpasm_hpack_init              ; the decoder: size updates up to 4096
    mov     rdi, [r12 + h2.encoder]
    mov     rsi, r13
    mov     edx, HA_H2_TABLE
    xor     ecx, ecx                        ; raw strings: cheaper to make and to read than
    call    httpasm_hpack_init              ; Huffman, and loopback bandwidth is not scarce
    mov     qword [r12 + h2.send_window], H2_DEFAULT_WINDOW
    mov     qword [r12 + h2.recv_window], HA_H2_CONNECTION_WINDOW
    mov     dword [r12 + h2.peer_window], H2_DEFAULT_WINDOW
    mov     dword [r12 + h2.peer_frame], H2_MIN_FRAME_SIZE
    mov     dword [r12 + h2.state], H2S_PREFACE
    mov     qword [r12 + h2.glitch_tokens], HA_H2_GLITCH_BURST * 1000  ; the whole burst
    mov     rax, [rbx + conn.worker]
    mov     rax, [rax + worker.now_ms]
    mov     [r12 + h2.glitch_time], rax
    mov     [r12 + h2.swept], rax           ; no stream to judge for a window

    ; SETTINGS: three 6-octet entries, big-endian.
    mov     word [rsp], 0x0300              ; MAX_CONCURRENT_STREAMS (3)
    mov     eax, HA_H2_MAX_STREAMS
    bswap   eax
    mov     [rsp + 2], eax
    mov     word [rsp + 6], 0x0400          ; INITIAL_WINDOW_SIZE (4)
    mov     eax, HA_H2_WINDOW
    bswap   eax
    mov     [rsp + 8], eax
    mov     word [rsp + 12], 0x0600         ; MAX_HEADER_LIST_SIZE (6): max_head
    mov     eax, r15d
    bswap   eax
    mov     [rsp + 14], eax
    mov     edi, H2_SETTINGS
    xor     esi, esi
    xor     edx, edx
    mov     rcx, rsp
    mov     r8d, 18
    call    h2_frame
    test    eax, eax
    jnz     .no_memory
    xor     edi, edi
    mov     esi, HA_H2_CONNECTION_WINDOW - H2_DEFAULT_WINDOW
    call    h2_window_update
    test    eax, eax
    jnz     .no_memory
    xor     eax, eax
    jmp     .out
.no_scratch_space:
    ; The fields array without its space is no scratch: freed, so the next connection makes
    ; both again (r13 = the worker; the frame keeps rsp aligned for the call).
    mov     rdi, [r13 + worker.h2_fields]
    call    free wrt ..plt
    mov     qword [r13 + worker.h2_fields], 0
.no_memory:
    mov     eax, -ENOMEM
.out:
    add     rsp, 32
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_h2_free: the connection is closing. Every stream is freed but those a handler still
; holds (deferred): they are detached, each freed when its answer arrives. Then the state.
;   In: rdi = conn. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
global ha_h2_free:function hidden (ha_h2_free.end - ha_h2_free)
align 16
ha_h2_free:
    push    rbx
    push    r12
    push    r13
    mov     rbx, rdi
    mov     r12, [rbx + conn.h2]
    test    r12, r12
    jz      .out
.stream:
    mov     ecx, [r12 + h2.stream_count]
    test    ecx, ecx
    jz      .streams_done
    dec     ecx
    mov     [r12 + h2.stream_count], ecx
    mov     r13, [r12 + h2.streams + rcx * 8]
    test    dword [r13 + h2stream.flags], HSF_DEFERRED
    jz      .free_stream
    or      dword [r13 + h2stream.flags], HSF_CANCELLED
    jmp     .stream
.free_stream:
    mov     rdi, r13
    call    h2_free_stream
    jmp     .stream
.streams_done:
    mov     rdi, [r12 + h2.block]
    call    free wrt ..plt
    mov     rdi, r12
    call    free wrt ..plt
    mov     qword [rbx + conn.h2], 0
.out:
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_h2_process: the frames the input holds (see this file's header).
;   In: rdi = conn (HTTP/2). Out: eax = 1 when back-pressure stopped it (frames may wait in the
;   input: process again once the output drained), 0 otherwise. The consumed octets leave the
;   input; a partial frame stays, and the input grows to hold it. Clobbers every caller-saved
;   register.
; -----------------------------------------------------------------------------
global ha_h2_process:function hidden (ha_h2_process.end - ha_h2_process)
align 16
ha_h2_process:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 8
    mov     rbx, rdi
    mov     r12, [rbx + conn.h2]
    xor     r13d, r13d                      ; the offset of the next frame
    xor     r15d, r15d                      ; the result: 1 for back-pressure
.frame:
    test    dword [r12 + h2.flags], H2F_CLOSING
    jnz     .consumed
    mov     rax, [rbx + conn.wlen]
    sub     rax, [rbx + conn.wsent]
    cmp     rax, HA_OUTPUT_HIGH
    ja      .pressure
    mov     rax, [rbx + conn.rlen]
    sub     rax, r13                        ; octets not consumed yet
    cmp     dword [r12 + h2.state], H2S_PREFACE
    jne     .header
    cmp     rax, H2_PREFACE_LENGTH          ; ha_h2_detect checked the 24 octets
    jb      .consumed
    add     r13, H2_PREFACE_LENGTH
    mov     dword [r12 + h2.state], H2S_SETTINGS
    jmp     .frame
.header:
    cmp     rax, H2_FRAME_HEADER
    jb      .consumed
    mov     rsi, [rbx + conn.rbuf]
    add     rsi, r13                        ; the frame
    movzx   ecx, byte [rsi]                 ; length: 24 bits, big-endian
    shl     ecx, 16
    movzx   edx, byte [rsi + 1]
    shl     edx, 8
    or      ecx, edx
    movzx   edx, byte [rsi + 2]
    or      ecx, edx
    cmp     ecx, HA_H2_FRAME
    ja      .too_large
    lea     r14, [rcx + H2_FRAME_HEADER]    ; the whole frame's octets
    cmp     rax, r14
    jb      .partial
    mov     [r12 + h2.frame_length], ecx
    movzx   eax, byte [rsi + 3]
    mov     [r12 + h2.frame_type], eax
    movzx   eax, byte [rsi + 4]
    mov     [r12 + h2.frame_flags], eax
    mov     eax, [rsi + 5]
    bswap   eax
    and     eax, 0x7FFFFFFF                 ; the reserved bit means nothing (RFC 9113 4.1)
    mov     [r12 + h2.frame_stream], eax
    add     rsi, H2_FRAME_HEADER
    mov     [r12 + h2.frame_payload], rsi

    ; While a field block is open, only its CONTINUATIONs may come (RFC 9113 6.2, 6.10).
    mov     edx, [r12 + h2.frame_type]
    cmp     dword [r12 + h2.block_stream], 0
    je      .no_block
    cmp     edx, H2_CONTINUATION
    jne     .protocol_error
    cmp     eax, [r12 + h2.block_stream]
    jne     .protocol_error
.no_block:
    cmp     dword [r12 + h2.state], H2S_SETTINGS
    jne     .dispatch
    cmp     edx, H2_SETTINGS                ; the preface's SETTINGS comes first (RFC 9113 3.4)
    jne     .protocol_error
.dispatch:
    cmp     edx, H2_DATA
    je      .data
    cmp     edx, H2_HEADERS
    je      .headers
    cmp     edx, H2_PRIORITY
    je      .priority
    cmp     edx, H2_RST_STREAM
    je      .rst_stream
    cmp     edx, H2_SETTINGS
    je      .settings
    cmp     edx, H2_PUSH_PROMISE
    je      .protocol_error                 ; a client never pushes (RFC 9113 8.4)
    cmp     edx, H2_PING
    je      .ping
    cmp     edx, H2_GOAWAY
    je      .goaway
    cmp     edx, H2_WINDOW_UPDATE
    je      .window_update
    cmp     edx, H2_CONTINUATION
    je      .continuation
    ; An extension frame (a type this side does not know: RFC 9218's PRIORITY_UPDATE, say) is
    ; ignored (RFC 9113 5.5), and is a glitch (h2_glitch): a flood of them is pure overhead.
    call    h2_glitch
    jmp     .next
.data:
    call    h2_data
    jmp     .next
.headers:
    call    h2_headers
    jmp     .next
.priority:
    call    h2_priority
    jmp     .next
.rst_stream:
    call    h2_rst_stream
    jmp     .next
.settings:
    call    h2_settings
    jmp     .next
.ping:
    call    h2_ping
    jmp     .next
.goaway:
    call    h2_goaway
    jmp     .next
.window_update:
    call    h2_window_update_frame
    jmp     .next
.continuation:
    call    h2_continuation
.next:
    add     r13, r14
    jmp     .frame

.protocol_error:
    mov     edi, H2_PROTOCOL_ERROR
    call    h2_connection_error
    jmp     .consumed
.too_large:
    mov     edi, H2_FRAME_SIZE_ERROR        ; past SETTINGS_MAX_FRAME_SIZE (RFC 9113 4.2)
    call    h2_connection_error
    jmp     .consumed
.pressure:
    mov     r15d, 1
    jmp     .consumed
.partial:
    ; A frame not whole yet: the input must hold it from its start once the consumed octets
    ; leave (at most 16393 octets: the frame size this side allows).
    call    .compact
    mov     rdi, rbx
    mov     rsi, r14
    call    ha_input_reserve
    test    eax, eax
    jz      .finish
    mov     edi, H2_INTERNAL_ERROR
    call    h2_connection_error
    jmp     .finish
.consumed:
    call    .compact
.finish:
    ; Frames arriving are not activity by themselves: PING, SETTINGS, WINDOW_UPDATE and PRIORITY
    ; would keep an idle connection forever. A request head accepted and an answer queued start
    ; a new window (h2_touch, ha_h2_respond); DATA counts as progress (h2_data); the window's
    ; end judges the rest (ha_conn_expire).
    ; The peer said GOAWAY: once no stream is active, the connection closes, with a GOAWAY of
    ; this side's first (RFC9113-6.8-7: a receiver done with the connection still says GOAWAY).
    ; It goes into the output here, before the flush half-closes the socket after it: written
    ; later, at the close itself, it could no longer be sent. NO_ERROR, so nothing is wrong;
    ; the function's other effects (input ignored, C_CLOSE_AFTER) are what a goodbye needs too.
    test    dword [r12 + h2.flags], H2F_GOAWAY_RECEIVED
    jz      .out
    cmp     dword [r12 + h2.stream_count], 0
    jne     .out
    mov     edi, H2_NO_ERROR
    call    h2_connection_error             ; once: it does nothing when closing already
.out:
    mov     eax, r15d
    add     rsp, 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
; .compact: the consumed octets leave the input (a local routine: called with rsp 8 below the
; aligned frame, it makes no call itself).
.compact:
    test    r13, r13
    jz      .compacted
    mov     rdi, [rbx + conn.rbuf]
    lea     rsi, [rdi + r13]
    mov     rcx, [rbx + conn.rlen]
    sub     rcx, r13
    mov     [rbx + conn.rlen], rcx
    COPY_OCTETS                             ; nothing left when the input was all whole frames
    xor     r13d, r13d
.compacted:
    ret
.end:

; -----------------------------------------------------------------------------
; h2_payload: a frame's payload without its padding (RFC 9113 6.1, 6.2).
;   In: r12 = h2 (the current frame). Out: rsi = the payload after the Pad Length octet,
;   ecx = its length without the padding; CF set when the padding is the payload's length or
;   more (a connection error PROTOCOL_ERROR). Clobbers rax and the flags.
; -----------------------------------------------------------------------------
align 16
h2_payload:
    mov     rsi, [r12 + h2.frame_payload]
    mov     ecx, [r12 + h2.frame_length]
    test    dword [r12 + h2.frame_flags], H2_FLAG_PADDED
    jz      .ok
    test    ecx, ecx
    jz      .bad                            ; no room even for the Pad Length octet
    movzx   eax, byte [rsi]
    inc     rsi
    dec     ecx
    cmp     eax, ecx
    ja      .bad
    sub     ecx, eax
.ok:
    clc
    ret
.bad:
    stc
    ret

; -----------------------------------------------------------------------------
; h2_settings: a SETTINGS frame (RFC 9113 6.5): the peer's parameters, then an ACK.
;   SETTINGS_INITIAL_WINDOW_SIZE changes every active stream's send window by the change
;   (RFC 9113 6.9.2). A frame may repeat it (up to 2,730 times in 16 KiB), and applying each one
;   to every stream cost 2,730 x 100 window updates for one frame: the abuse RFC 9113 10.5
;   names ("changing the same setting multiple times in the same frame"). The parameters are
;   still processed in order, with the same outcome as applying them one by one: each value is
;   checked at once against the largest stream window before the frame plus the change so far
;   (a window past 2^31 - 1 at any step is a FLOW_CONTROL_ERROR, RFC9113-6.9.2-3.1#2, ahead of
;   any later parameter's error). Only the frame's net change is applied, once per stream. The
;   waiting bodies resume (h2_resume) only when the windows grew. The cost is linear in the
;   frame and the streams.
;   In: rbx = conn, r12 = h2. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
S_OLD       equ 0       ; the peer's INITIAL_WINDOW_SIZE before the frame (zero-extended)
S_MAX       equ 8       ; the largest active stream's send window before the frame (signed)
S_SEEN      equ 16      ; 1 once the frame had an INITIAL_WINDOW_SIZE (S_MAX computed)
S_FRAME     equ 32      ; three pushes + 32: rsp stays 16-byte aligned for the calls

align 16
h2_settings:
    push    r13
    push    r14
    push    r15
    sub     rsp, S_FRAME
    cmp     dword [r12 + h2.frame_stream], 0
    jne     .protocol_error
    mov     eax, [r12 + h2.frame_length]
    test    dword [r12 + h2.frame_flags], H2_FLAG_ACK
    jz      .parameters
    test    eax, eax                        ; an ACK carries nothing (RFC9113-6.5-3.2.1)
    jnz     .frame_size_error
    jmp     .out
.parameters:
    xor     edx, edx
    mov     ecx, 6
    div     ecx
    test    edx, edx
    jnz     .frame_size_error               ; not whole 6-octet parameters
    mov     r13, [r12 + h2.frame_payload]
    mov     r14d, eax                       ; parameters left
    mov     eax, [r12 + h2.peer_window]
    mov     [rsp + S_OLD], rax
    mov     qword [rsp + S_SEEN], 0
.parameter:
    test    r14d, r14d
    jz      .acknowledge
    movzx   eax, word [r13]
    xchg    al, ah                          ; the identifier
    mov     r15d, [r13 + 2]
    bswap   r15d                            ; the value
    add     r13, 6
    dec     r14d
    cmp     eax, H2_SETTINGS_HEADER_TABLE_SIZE
    je      .table_size
    cmp     eax, H2_SETTINGS_ENABLE_PUSH
    je      .enable_push
    cmp     eax, H2_SETTINGS_INITIAL_WINDOW_SIZE
    je      .initial_window
    cmp     eax, H2_SETTINGS_MAX_FRAME_SIZE
    je      .max_frame
    jmp     .parameter                      ; others (and unknown ones) need nothing here
.table_size:
    mov     rdi, [r12 + h2.encoder]         ; the encoder follows, and signals it next block
    mov     esi, r15d
    call    httpasm_hpack_encoder_limit
    jmp     .parameter
.enable_push:
    cmp     r15d, 1
    ja      .protocol_error                 ; 0 or 1 only (RFC9113-6.5.2-2.4.1)
    jmp     .parameter
.initial_window:
    cmp     r15d, H2_MAX_WINDOW
    ja      .flow_control_error             ; past 2^31 - 1 (RFC9113-6.5.2-2.8.1)
    cmp     qword [rsp + S_SEEN], 0
    jne     .largest_known
    ; The frame's first one: the largest active stream window, once. With no stream, a value
    ; far below any window: the check below then never fails, and cannot overflow.
    mov     rax, -(1 << 62)
    mov     ecx, [r12 + h2.stream_count]
    xor     edx, edx
.largest:
    cmp     edx, ecx
    jae     .largest_found
    mov     rsi, [r12 + h2.streams + rdx * 8]
    mov     rdi, [rsi + h2stream.send_window]
    cmp     rdi, rax
    cmovg   rax, rdi
    inc     edx
    jmp     .largest
.largest_found:
    mov     [rsp + S_MAX], rax
    mov     qword [rsp + S_SEEN], 1
.largest_known:
    ; Applied one by one, after this value every window would be its own plus (value - old),
    ; and may go negative (RFC 9113 6.9.2); the largest must not pass 2^31 - 1.
    mov     eax, r15d
    sub     rax, [rsp + S_OLD]              ; the change so far, signed (both below 2^31)
    add     rax, [rsp + S_MAX]
    cmp     rax, H2_MAX_WINDOW
    jg      .flow_control_error
    mov     [r12 + h2.peer_window], r15d    ; new streams start from it (h2_new_stream)
    jmp     .parameter
.max_frame:
    cmp     r15d, H2_MIN_FRAME_SIZE
    jb      .protocol_error                 ; 16384 to 2^24 - 1 (RFC9113-6.5.2-2.10.1)
    cmp     r15d, H2_MAX_FRAME_SIZE
    ja      .protocol_error
    mov     [r12 + h2.peer_frame], r15d
    jmp     .parameter
.acknowledge:
    ; The frame's net change to INITIAL_WINDOW_SIZE, once to every active stream (the checks
    ; above proved no window passes 2^31 - 1 at any step).
    xor     r15d, r15d                      ; 1 when the windows grew: bodies may resume
    cmp     qword [rsp + S_SEEN], 0
    je      .windows_done
    mov     eax, [r12 + h2.peer_window]
    sub     rax, [rsp + S_OLD]              ; the net change, signed
    jz      .windows_done
    setg    r15b
    mov     ecx, [r12 + h2.stream_count]
    xor     edx, edx
.stream_window:
    cmp     edx, ecx
    jae     .windows_done
    mov     rsi, [r12 + h2.streams + rdx * 8]
    add     [rsi + h2stream.send_window], rax
    inc     edx
    jmp     .stream_window
.windows_done:
    mov     edi, H2_SETTINGS
    mov     esi, H2_FLAG_ACK
    xor     edx, edx
    xor     ecx, ecx
    xor     r8d, r8d
    call    h2_frame
    cmp     dword [r12 + h2.state], H2S_SETTINGS
    jne     .resume
    mov     dword [r12 + h2.state], H2S_OPEN
.resume:
    test    r15d, r15d
    jz      .out                            ; no window grew: nothing waiting can move
    call    h2_resume
    jmp     .out
.protocol_error:
    mov     edi, H2_PROTOCOL_ERROR
    call    h2_connection_error
    jmp     .out
.frame_size_error:
    mov     edi, H2_FRAME_SIZE_ERROR
    call    h2_connection_error
    jmp     .out
.flow_control_error:
    mov     edi, H2_FLOW_CONTROL_ERROR
    call    h2_connection_error
.out:
    add     rsp, S_FRAME
    pop     r15
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_ping: PING (RFC 9113 6.7): answered with an ACK carrying the same 8 octets. An ACK of the
; graceful stop's own PING marks the notice acknowledged (H2F_NOTICE_ACKED).
;   In: rbx = conn, r12 = h2. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_ping:
    sub     rsp, 8
    cmp     dword [r12 + h2.frame_stream], 0
    jne     .protocol_error
    cmp     dword [r12 + h2.frame_length], 8
    jne     .frame_size_error
    test    dword [r12 + h2.frame_flags], H2_FLAG_ACK
    jnz     .ack
    mov     edi, H2_PING
    mov     esi, H2_FLAG_ACK
    xor     edx, edx
    mov     rcx, [r12 + h2.frame_payload]
    mov     r8d, 8
    call    h2_frame
    jmp     .out
.ack:
    ; The only PING this side sends is a graceful stop's (ha_h2_notice). Its ACK, after the
    ; notice, is the round trip the stop waits for; any other ACK is ignored (RFC 9113 6.7
    ; leaves unsolicited ACKs without effect).
    test    dword [r12 + h2.flags], H2F_NOTICE
    jz      .out
    mov     rax, [r12 + h2.frame_payload]
    mov     rax, [rax]
    cmp     rax, [rel s_stop_ping]
    jne     .out
    or      dword [r12 + h2.flags], H2F_NOTICE_ACKED
    jmp     .out
.protocol_error:
    mov     edi, H2_PROTOCOL_ERROR
    call    h2_connection_error
    jmp     .out
.frame_size_error:
    mov     edi, H2_FRAME_SIZE_ERROR
    call    h2_connection_error
.out:
    add     rsp, 8
    ret

; -----------------------------------------------------------------------------
; h2_goaway: GOAWAY (RFC 9113 6.8): the peer opens no more streams; the connection closes once
; the active ones are done (ha_h2_process checks after each batch).
;   In: rbx = conn, r12 = h2. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_goaway:
    sub     rsp, 8
    cmp     dword [r12 + h2.frame_stream], 0
    jne     .protocol_error
    cmp     dword [r12 + h2.frame_length], 8
    jb      .frame_size_error               ; last-stream-id and error code at least
    or      dword [r12 + h2.flags], H2F_GOAWAY_RECEIVED
    jmp     .out
.protocol_error:
    mov     edi, H2_PROTOCOL_ERROR
    call    h2_connection_error
    jmp     .out
.frame_size_error:
    mov     edi, H2_FRAME_SIZE_ERROR
    call    h2_connection_error
.out:
    add     rsp, 8
    ret

; -----------------------------------------------------------------------------
; h2_priority: PRIORITY (RFC 9113 6.3). The priority scheme is deprecated and not acted on, but
; the frame is checked; it never opens a stream (RFC 9113 5.1.1: only HEADERS does). Every
; PRIORITY frame is a glitch (h2_glitch): it costs work and moves nothing (CVE-2019-9513
; shuffled priorities endlessly; nghttp2 counts each frame too).
;   In: rbx = conn, r12 = h2. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_priority:
    sub     rsp, 8
    mov     edi, [r12 + h2.frame_stream]
    test    edi, edi
    jz      .protocol_error
    cmp     dword [r12 + h2.frame_length], 5
    jne     .frame_size_error
    mov     rax, [r12 + h2.frame_payload]
    mov     eax, [rax]
    bswap   eax
    and     eax, 0x7FFFFFFF
    cmp     eax, edi
    je      .self                           ; a stream cannot depend on itself (RFC 9113 5.3.1)
    call    h2_glitch                       ; a valid one: the budget's (an invalid one's error
    jmp     .out                            ; below is a glitch of its own)
.self:
    mov     esi, H2_PROTOCOL_ERROR
    call    h2_peer_stream_error
    jmp     .out
.frame_size_error:
    mov     esi, H2_FRAME_SIZE_ERROR        ; a stream error (RFC9113-6.3-6.2)
    call    h2_peer_stream_error
    jmp     .out
.protocol_error:
    mov     edi, H2_PROTOCOL_ERROR
    call    h2_connection_error
.out:
    add     rsp, 8
    ret

; -----------------------------------------------------------------------------
; h2_rst_stream: RST_STREAM (RFC 9113 6.4): the stream closes, as reset by the peer. Reset
; storms are refused (CVE-2023-44487): h2_count_reset's rule, shared with the resets the peer
; provokes (h2_peer_stream_error).
;   In: rbx = conn, r12 = h2. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_rst_stream:
    sub     rsp, 8
    mov     edi, [r12 + h2.frame_stream]
    test    edi, edi
    jz      .protocol_error
    cmp     dword [r12 + h2.frame_length], 4
    jne     .frame_size_error
    call    h2_find
    test    rax, rax
    jnz     .active
    mov     edi, [r12 + h2.frame_stream]
    cmp     edi, [r12 + h2.last_stream]
    ja      .protocol_error                 ; idle: never opened (RFC 9113 5.1)
    jmp     .out                            ; closed already: nothing to do
.active:
    mov     rdi, rax
    mov     esi, H2C_PEER_RESET
    call    h2_close
    call    h2_count_reset                  ; ENHANCE_YOUR_CALM past the rule: nothing follows
    jmp     .out
.protocol_error:
    mov     edi, H2_PROTOCOL_ERROR
    call    h2_connection_error
    jmp     .out
.frame_size_error:
    mov     edi, H2_FRAME_SIZE_ERROR
    call    h2_connection_error
.out:
    add     rsp, 8
    ret

; -----------------------------------------------------------------------------
; h2_window_update_frame: WINDOW_UPDATE (RFC 9113 6.9): this side may send more, on the
; connection (stream 0) or one stream; waiting response bodies resume.
;   In: rbx = conn, r12 = h2. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_window_update_frame:
    sub     rsp, 8
    cmp     dword [r12 + h2.frame_length], 4
    jne     .frame_size_error
    mov     rax, [r12 + h2.frame_payload]
    mov     esi, [rax]
    bswap   esi
    and     esi, 0x7FFFFFFF                 ; the increment
    mov     edi, [r12 + h2.frame_stream]
    test    edi, edi
    jnz     .stream
    test    esi, esi
    jz      .protocol_error                 ; 0 on the connection: a connection error
    add     [r12 + h2.send_window], rsi
    cmp     qword [r12 + h2.send_window], H2_MAX_WINDOW
    jg      .flow_control_error
    ; Only a body that waits for the connection's window can move now (H2F_CONN_BLOCKED, set
    ; by h2_send_out). Clients send these as they read, most of the time with nothing waiting;
    ; walking every stream for each would make a stream of them cost O(streams) per frame.
    test    dword [r12 + h2.flags], H2F_CONN_BLOCKED
    jz      .out
    call    h2_resume
    jmp     .out
.stream:
    push    rsi                             ; the increment, across h2_find (which calls nothing)
    call    h2_find
    pop     rsi
    test    rax, rax
    jnz     .active
    mov     edi, [r12 + h2.frame_stream]
    cmp     edi, [r12 + h2.last_stream]
    ja      .protocol_error                 ; idle (RFC 9113 5.1)
    jmp     .out                            ; closed: frames in flight are fine
.active:
    mov     edi, [rax + h2stream.id]
    test    esi, esi
    jz      .stream_protocol_error          ; 0 on a stream: a stream error
    add     [rax + h2stream.send_window], rsi
    cmp     qword [rax + h2stream.send_window], H2_MAX_WINDOW
    jg      .stream_flow_control_error
    mov     rdi, rax
    call    h2_send_data
    jmp     .out
.stream_protocol_error:
    mov     esi, H2_PROTOCOL_ERROR          ; CVE-2025-8671's favorite: a reset the server
    call    h2_peer_stream_error            ; sends on a stream whose answer may be in progress
    jmp     .out
.stream_flow_control_error:
    mov     esi, H2_FLOW_CONTROL_ERROR
    call    h2_peer_stream_error
    jmp     .out
.protocol_error:
    mov     edi, H2_PROTOCOL_ERROR
    call    h2_connection_error
    jmp     .out
.frame_size_error:
    mov     edi, H2_FRAME_SIZE_ERROR
    call    h2_connection_error
    jmp     .out
.flow_control_error:
    mov     edi, H2_FLOW_CONTROL_ERROR
    call    h2_connection_error
.out:
    add     rsp, 8
    ret

; -----------------------------------------------------------------------------
; h2_headers: HEADERS (RFC 9113 6.2): a new stream's request head, or an open stream's trailers.
; The field block is classified here, decoded when whole (here, or after its CONTINUATIONs).
;   In: rbx = conn, r12 = h2. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_headers:
    push    r13
    push    r14
    push    r15
    mov     r13d, [r12 + h2.frame_stream]
    test    r13d, r13d
    jz      .protocol_error
    call    h2_payload                      ; rsi, ecx: without padding
    jc      .protocol_error
    mov     r15d, [r12 + h2.frame_flags]    ; END_STREAM, and H2B_* below
    test    r15d, H2_FLAG_PRIORITY
    jz      .no_priority
    cmp     ecx, 5
    jb      .frame_size_error
    mov     eax, [rsi]
    bswap   eax
    and     eax, 0x7FFFFFFF
    cmp     eax, r13d
    jne     .priority_done
    or      r15d, H2B_SELF_DEPENDENT        ; a stream error, after the block is decoded
.priority_done:
    add     rsi, 5
    sub     ecx, 5
.no_priority:
    mov     [r12 + h2.frame_payload], rsi   ; the fragment, from here on
    mov     [r12 + h2.frame_length], ecx

    ; What the block will be.
    test    r13d, 1
    jz      .protocol_error                 ; a client's streams are odd (RFC 9113 5.1.1)
    mov     edi, r13d
    call    h2_find
    test    rax, rax
    jz      .not_active
    mov     r14d, H2K_CLOSED                ; half-closed (remote): STREAM_CLOSED (RFC 9113 5.1)
    test    dword [rax + h2stream.flags], HSF_END_RECEIVED
    jnz     .classified
    mov     r14d, H2K_TRAILERS              ; trailers: they must end the stream (RFC9113-8.1-2.4)
    jmp     .classified
.not_active:
    cmp     r13d, [r12 + h2.last_stream]
    ja      .new_stream
    mov     edi, r13d
    call    h2_closed_how
    cmp     eax, H2C_NORMAL
    je      .stream_closed                  ; a connection error STREAM_CLOSED (RFC 9113 5.1)
    mov     r14d, H2K_CLOSED                ; reset by the peer: a stream error
    cmp     eax, H2C_PEER_RESET
    je      .classified
    mov     r14d, H2K_DISCARD               ; reset by this side: in flight, ignored
    cmp     eax, H2C_RESET
    je      .classified
    jmp     .protocol_error                 ; lower than one opened before (RFC9113-5.1.1-2)
.new_stream:
    mov     [r12 + h2.last_stream], r13d
    inc     qword [r12 + h2.opened]
    mov     r14d, H2K_DISCARD               ; this side is leaving: new streams are not served
    test    dword [r12 + h2.flags], H2F_GOAWAY_RECEIVED
    jnz     .classified
    mov     r14d, H2K_REFUSE
    cmp     dword [r12 + h2.stream_count], HA_H2_MAX_STREAMS
    jae     .classified                     ; past MAX_CONCURRENT_STREAMS (RFC 9113 5.1.2)
    mov     edi, r13d
    call    h2_new_stream
    test    rax, rax
    jz      .internal_error
    mov     r14d, H2K_REQUEST
.classified:
    test    dword [r12 + h2.frame_flags], H2_FLAG_END_HEADERS
    jz      .open_block
    ; The whole block is here: decode it in place.
    mov     edi, r14d
    mov     esi, r15d
    mov     edx, r13d
    mov     rcx, [r12 + h2.frame_payload]
    mov     r8d, [r12 + h2.frame_length]
    call    h2_block_done
    jmp     .out
.open_block:
    ; CONTINUATIONs follow: keep the fragment.
    mov     [r12 + h2.block_stream], r13d
    mov     [r12 + h2.block_kind], r14d
    mov     [r12 + h2.block_flags], r15d
    mov     dword [r12 + h2.block_frames], 0
    mov     qword [r12 + h2.block_length], 0
    call    h2_block_append
    jmp     .out
.stream_closed:
    mov     edi, H2_STREAM_CLOSED
    call    h2_connection_error
    jmp     .out
.internal_error:
    mov     edi, H2_INTERNAL_ERROR
    call    h2_connection_error
    jmp     .out
.frame_size_error:
    mov     edi, H2_FRAME_SIZE_ERROR
    call    h2_connection_error
    jmp     .out
.protocol_error:
    mov     edi, H2_PROTOCOL_ERROR
    call    h2_connection_error
.out:
    pop     r15
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_continuation: CONTINUATION (RFC 9113 6.10): the next fragment of the open field block
; (ha_h2_process already refused any other frame, or another stream, while a block is open).
;   In: rbx = conn, r12 = h2. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_continuation:
    sub     rsp, 8
    cmp     dword [r12 + h2.block_stream], 0
    je      .protocol_error                 ; no HEADERS before it (RFC 9113 6.10)
    inc     dword [r12 + h2.block_frames]
    cmp     dword [r12 + h2.block_frames], HA_H2_MAX_CONTINUATIONS
    ja      .calm                           ; a CONTINUATION flood (CVE-2024-27316)
    call    h2_block_append
    test    dword [r12 + h2.flags], H2F_CLOSING
    jnz     .out
    test    dword [r12 + h2.frame_flags], H2_FLAG_END_HEADERS
    jz      .out
    ; The block is whole.
    mov     edx, [r12 + h2.block_stream]
    mov     dword [r12 + h2.block_stream], 0
    mov     edi, [r12 + h2.block_kind]
    mov     esi, [r12 + h2.block_flags]
    mov     rcx, [r12 + h2.block]
    mov     r8, [r12 + h2.block_length]
    call    h2_block_done
    jmp     .out
.calm:
    mov     edi, H2_ENHANCE_YOUR_CALM
    call    h2_connection_error
    jmp     .out
.protocol_error:
    mov     edi, H2_PROTOCOL_ERROR
    call    h2_connection_error
.out:
    add     rsp, 8
    ret

; -----------------------------------------------------------------------------
; h2_block_append: the current frame's fragment onto the open field block. A block past twice
; max_head octets cannot be kept, and must not be skipped (HPACK would fall out of step): the
; connection closes with ENHANCE_YOUR_CALM.
;   In: rbx = conn, r12 = h2 (frame_payload/length: the fragment). Clobbers caller-saved registers.
; -----------------------------------------------------------------------------
align 16
h2_block_append:
    push    r13
    push    r14
    sub     rsp, 8
    mov     r13d, [r12 + h2.frame_length]
    mov     r14, [r12 + h2.block_length]
    add     r14, r13                        ; the block's octets after this fragment
    mov     rax, [rbx + conn.worker]
    mov     rax, [rax + worker.server]
    mov     eax, [rax + server.limits + httpasm_h1_limits.max_head]
    mov     ecx, HA_H1_DEFAULT_MAX_HEAD
    test    eax, eax
    cmovz   eax, ecx
    shl     rax, 1
    cmp     r14, rax
    ja      .calm
    cmp     r14, [r12 + h2.block_cap]
    jbe     .room
    lea     rsi, [r14 + 4096]
    mov     [r12 + h2.block_cap], rsi
    mov     rdi, [r12 + h2.block]
    call    realloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     [r12 + h2.block], rax
.room:
    mov     rdi, [r12 + h2.block]
    add     rdi, [r12 + h2.block_length]
    mov     rsi, [r12 + h2.frame_payload]
    mov     ecx, r13d
    COPY_OCTETS                             ; an empty fragment (a CONTINUATION flood's)
    mov     [r12 + h2.block_length], r14
    jmp     .out
.no_memory:
    mov     qword [r12 + h2.block_cap], 0
    mov     edi, H2_INTERNAL_ERROR
    call    h2_connection_error
    jmp     .out
.calm:
    mov     edi, H2_ENHANCE_YOUR_CALM
    call    h2_connection_error
.out:
    add     rsp, 8
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_new_stream: a new active stream, its windows set from both sides' settings.
;   In: rbx = conn, r12 = h2, edi = id. Out: rax = the stream, or 0 (no memory).
;   Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_new_stream:
    push    r13
    mov     r13d, edi
    mov     edi, 1
    mov     esi, h2stream_size
    call    calloc wrt ..plt
    test    rax, rax
    jz      .out
    mov     [rax + h2stream.id], r13d
    mov     [rax + h2stream.conn], rbx
    mov     rcx, [rbx + conn.worker]
    mov     rcx, [rcx + worker.now_ms]
    mov     [rax + h2stream.moved_since], rcx   ; its first window starts now (ha_h2_sweep)
    mov     ecx, [r12 + h2.peer_window]
    mov     [rax + h2stream.send_window], rcx
    mov     qword [rax + h2stream.recv_window], HA_H2_WINDOW
    mov     ecx, [r12 + h2.stream_count]
    mov     [r12 + h2.streams + rcx * 8], rax
    mov     [r12 + h2.ids + rcx * 4], r13d  ; h2_slot finds it by this
    inc     ecx
    mov     [r12 + h2.stream_count], ecx
.out:
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_block_done: a whole field block. It is decoded whatever it is (HPACK stays in step with
; the peer's encoder: RFC 9113 4.3), then acted on by kind.
;   In: rbx = conn, r12 = h2, edi = H2K_*, esi = the HEADERS' flags and H2B_*, edx = stream id,
;   rcx = the block, r8 = its length. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
B_OUTPUT    equ 0       ; httpasm_hpack_output (48 octets)
B_KIND      equ 48
B_FLAGS     equ 52
B_ID        equ 56
B_FRAME     equ 72      ; four pushes + 72: aligned

align 16
h2_block_done:
    push    r13
    push    r14
    push    r15
    push    rbp
    sub     rsp, B_FRAME
    mov     [rsp + B_KIND], edi
    mov     [rsp + B_FLAGS], esi
    mov     [rsp + B_ID], edx
    mov     r14, rcx
    mov     r15, r8
    ; Decode into the worker's scratch.
    mov     rax, [rbx + conn.worker]
    mov     rdx, [rax + worker.h2_fields]
    mov     [rsp + B_OUTPUT + httpasm_hpack_output.fields], rdx
    mov     rdx, [rax + worker.h2_space]
    mov     [rsp + B_OUTPUT + httpasm_hpack_output.space], rdx
    mov     rax, [rax + worker.server]
    mov     edx, [rax + server.limits + httpasm_h1_limits.max_head]
    mov     ecx, HA_H1_DEFAULT_MAX_HEAD
    test    edx, edx
    cmovz   edx, ecx
    mov     [rsp + B_OUTPUT + httpasm_hpack_output.space_size], rdx
    mov     edx, [rax + server.limits + httpasm_h1_limits.max_fields]
    mov     ecx, HA_H1_DEFAULT_MAX_FIELDS
    test    edx, edx
    cmovz   edx, ecx
    mov     [rsp + B_OUTPUT + httpasm_hpack_output.max_fields], edx
    mov     rdi, [r12 + h2.decoder]
    mov     rsi, r14
    mov     rdx, r15
    lea     rcx, [rsp + B_OUTPUT]
    call    httpasm_hpack_decode
    test    rax, rax
    js      .compression_error              ; the decoder's table cannot be trusted any more
    mov     rbp, rax                        ; 1: it did not fit the scratch

    mov     eax, [rsp + B_KIND]
    cmp     eax, H2K_DISCARD
    je      .out
    cmp     eax, H2K_REFUSE
    je      .refuse
    cmp     eax, H2K_CLOSED
    je      .closed
    mov     edi, [rsp + B_ID]
    call    h2_find
    test    rax, rax
    jz      .out                            ; gone meanwhile
    mov     r13, rax
    cmp     dword [rsp + B_KIND], H2K_TRAILERS
    je      .trailers

    ; A request head.
    test    dword [rsp + B_FLAGS], H2B_SELF_DEPENDENT
    jnz     .malformed                      ; a priority error (RFC 9113 5.3.1), not a bad message: reset only
    test    rbp, rbp
    jnz     .too_large
    mov     rdi, [rsp + B_OUTPUT + httpasm_hpack_output.fields]
    mov     esi, [rsp + B_OUTPUT + httpasm_hpack_output.count]
    lea     rdx, [r13 + h2stream.request]
    call    httpasm_h2_request
    cmp     eax, -HTTPASM_ERROR_EXPECT
    je      .expectation_failed
    test    eax, eax
    jnz     .bad_request                    ; 400, then the reset (h2_bad_request)
    lea     rdi, [rsp + B_OUTPUT]
    mov     rsi, r13
    call    h2_keep_head                    ; into the stream's own memory, cookies joined
    test    eax, eax
    jnz     .internal_error
    call    h2_touch                        ; a request: activity, a new window (and a sweep)
    test    dword [rsp + B_FLAGS], H2_FLAG_END_STREAM
    jz      .body_follows
    or      dword [r13 + h2stream.flags], HSF_END_RECEIVED
    test    dword [r13 + h2stream.request + httpasm_request.flags], HTTPASM_REQUEST_CONTENT_LENGTH
    jz      .dispatch
    cmp     qword [r13 + h2stream.request + httpasm_request.content_length], 0
    jne     .bad_request                    ; content-length promised DATA that never comes
.dispatch:
    mov     rdi, r13
    call    h2_dispatch
    jmp     .out
.body_follows:
    ; A declared body past max_body: 413 now, then RST_STREAM(NO_ERROR) (RFC 9113 8.1).
    test    dword [r13 + h2stream.request + httpasm_request.flags], HTTPASM_REQUEST_CONTENT_LENGTH
    jz      .continue_check
    mov     rax, [rbx + conn.worker]
    mov     rax, [rax + worker.server]
    mov     rax, [rax + server.max_body]
    cmp     [r13 + h2stream.request + httpasm_request.content_length], rax
    ja      .body_too_large
.continue_check:
    test    dword [r13 + h2stream.request + httpasm_request.flags], HTTPASM_REQUEST_EXPECT_CONTINUE
    jz      .out
    mov     rdi, r13
    call    h2_continue                     ; 100 (Continue): the client may send the body
    jmp     .out

.trailers:
    test    rbp, rbp
    jnz     .too_large
    test    dword [rsp + B_FLAGS], H2_FLAG_END_STREAM
    jz      .malformed                      ; a second HEADERS must end the stream
    mov     rdi, [rsp + B_OUTPUT + httpasm_hpack_output.fields]
    mov     esi, [rsp + B_OUTPUT + httpasm_hpack_output.count]
    call    httpasm_h2_trailers
    test    eax, eax
    jnz     .malformed
    lea     rdi, [rsp + B_OUTPUT]
    mov     rsi, r13
    call    h2_keep_tail
    test    eax, eax
    jnz     .internal_error
    or      dword [r13 + h2stream.flags], HSF_END_RECEIVED
    mov     rdi, r13
    call    h2_body_ended
    jmp     .out

.too_large:
    mov     esi, 431                        ; the field section past max_head (RFC9113-10.5.1-4)
    jmp     .refusal
.body_too_large:
    mov     esi, 413
    jmp     .refusal
.expectation_failed:
    mov     esi, 417
.refusal:
    ; A refusal the peer earned is a glitch (h2_glitch): a stream of oversized heads costs
    ; their decoding and an answer each, and moves nothing.
    mov     [rsp + B_KIND], esi             ; the status, across the call (the kind is used up)
    call    h2_glitch
    test    eax, eax
    jnz     .out
    mov     rdi, r13
    mov     esi, [rsp + B_KIND]
    call    h2_error_response
    jmp     .out
.bad_request:
    mov     rdi, r13                        ; a malformed request head: 400, then RST_STREAM(PROTOCOL_ERROR)
    call    h2_bad_request
    jmp     .out
.malformed:
    mov     edi, [rsp + B_ID]               ; RFC9113-8.1.1-3: a stream error PROTOCOL_ERROR
    mov     esi, H2_PROTOCOL_ERROR
    call    h2_peer_stream_error
    jmp     .out
.refuse:
    mov     edi, [rsp + B_ID]               ; past SETTINGS_MAX_CONCURRENT_STREAMS
    mov     esi, H2_REFUSED_STREAM
    call    h2_peer_stream_error
    jmp     .out
.closed:
    mov     edi, [rsp + B_ID]
    mov     esi, H2_STREAM_CLOSED
    call    h2_peer_stream_error
    jmp     .out
.internal_error:
    mov     edi, [rsp + B_ID]
    mov     esi, H2_INTERNAL_ERROR
    call    h2_stream_error
    jmp     .out
.compression_error:
    mov     edi, H2_COMPRESSION_ERROR
    call    h2_connection_error
.out:
    add     rsp, B_FRAME
    pop     rbp
    pop     r15
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_keep_head: a decoded request head into its stream's own block: the records, then the
; strings that are not the static table's, every pointer moved with them (the request's
; method, target, authority, scheme and fields too). Several cookie fields become one, joined
; with "; " (RFC9113-8.2.3-4: a generic application sees one).
;   In: rdi = the httpasm_hpack_output (scratch), rsi = stream. Out: eax = 0 or -ENOMEM.
;   Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
K_COOKIES   equ 0       ; how many cookie fields
K_JOINED    equ 8       ; their values' octets joined, separators included
K_FRAME     equ 24

align 16
h2_keep_head:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, K_FRAME
    mov     rbx, rdi                        ; the decoder's output
    mov     r12, rsi                        ; the stream
    ; Cookies among the regular fields.
    xor     eax, eax
    mov     [rsp + K_COOKIES], rax
    mov     [rsp + K_JOINED], rax
    mov     r13, [r12 + h2stream.request + httpasm_request.fields]
    mov     ecx, [r12 + h2stream.request + httpasm_request.field_count]
.count_cookie:
    test    ecx, ecx
    jz      .counted
    cmp     word [r13 + httpasm_field.id], HA_FIELD_COOKIE
    jne     .not_cookie
    inc     qword [rsp + K_COOKIES]
    mov     eax, [r13 + httpasm_field.value_length]
    add     [rsp + K_JOINED], rax
    add     qword [rsp + K_JOINED], 2       ; "; " (one too many: harmless room)
.not_cookie:
    add     r13, httpasm_field_size
    dec     ecx
    jmp     .count_cookie
.counted:
    ; One block: the records, the strings, and room for the joined cookie.
    mov     eax, [rbx + httpasm_hpack_output.count]
    shl     rax, 5
    mov     r14, rax                        ; the records' octets
    add     rax, [rbx + httpasm_hpack_output.space_used]
    add     rax, [rsp + K_JOINED]
    mov     rdi, rax
    call    malloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     [r12 + h2stream.head], rax
    mov     r15, rax                        ; the records go here
    lea     rbp, [rax + r14]                ; and the strings here
    mov     rdi, r15
    mov     rsi, [rbx + httpasm_hpack_output.fields]
    mov     rcx, r14
    rep     movsb
    mov     rdi, rbp
    mov     rsi, [rbx + httpasm_hpack_output.space]
    mov     rcx, [rbx + httpasm_hpack_output.space_used]
    rep     movsb
    ; Every pointer into the scratch moves by the same distance.
    mov     ecx, [rbx + httpasm_hpack_output.count]
    mov     rdx, r15
.rebase_field:
    test    ecx, ecx
    jz      .rebase_request
    mov     rdi, [rdx + httpasm_field.name]
    call    .rebase
    mov     [rdx + httpasm_field.name], rdi
    mov     rdi, [rdx + httpasm_field.value]
    call    .rebase
    mov     [rdx + httpasm_field.value], rdi
    add     rdx, httpasm_field_size
    dec     ecx
    jmp     .rebase_field
.rebase_request:
    lea     r13, [r12 + h2stream.request]
%macro REBASE_REQUEST 1
    mov     rdi, [r13 + %1]
    test    rdi, rdi
    jz      %%skip
    call    .rebase
    mov     [r13 + %1], rdi
%%skip:
%endmacro
    REBASE_REQUEST httpasm_request.method
    REBASE_REQUEST httpasm_request.target
    REBASE_REQUEST httpasm_request.authority
    REBASE_REQUEST httpasm_request.scheme
    mov     rax, [r13 + httpasm_request.fields]
    sub     rax, [rbx + httpasm_hpack_output.fields]
    add     rax, r15
    mov     [r13 + httpasm_request.fields], rax

    ; Cookies: the first one's value becomes all of them, joined; the others leave the array.
    cmp     qword [rsp + K_COOKIES], 2
    jb      .done
    mov     rdi, rbp
    add     rdi, [rbx + httpasm_hpack_output.space_used]  ; the joined value goes here
    mov     r8, rdi                         ; its start
    xor     r9d, r9d                        ; the first cookie's record, once found
    mov     rsi, [r13 + httpasm_request.fields]
    mov     rdx, rsi                        ; where the next kept record goes
    mov     ecx, [r13 + httpasm_request.field_count]
.cookie:
    test    ecx, ecx
    jz      .cookies_joined
    cmp     word [rsi + httpasm_field.id], HA_FIELD_COOKIE
    je      .cookie_value
    ; Not a cookie: kept, moved down over the cookies removed.
    movdqu  xmm0, [rsi]
    movdqu  xmm1, [rsi + 16]
    movdqu  [rdx], xmm0
    movdqu  [rdx + 16], xmm1
    add     rdx, httpasm_field_size
    jmp     .cookie_next
.cookie_value:
    test    r9, r9
    jnz     .separator
    mov     r9, rdx                         ; the first cookie keeps its place
    movdqu  xmm0, [rsi]
    movdqu  xmm1, [rsi + 16]
    movdqu  [rdx], xmm0
    movdqu  [rdx + 16], xmm1
    add     rdx, httpasm_field_size
    jmp     .append
.separator:
    mov     word [rdi], 0x203B              ; "; "
    add     rdi, 2
.append:
    push    rsi
    push    rcx
    mov     rax, rsi
    mov     rsi, [rax + httpasm_field.value]
    mov     ecx, [rax + httpasm_field.value_length]
    rep     movsb
    pop     rcx
    pop     rsi
.cookie_next:
    add     rsi, httpasm_field_size
    dec     ecx
    jmp     .cookie
.cookies_joined:
    mov     [r9 + httpasm_field.value], r8
    mov     rax, rdi
    sub     rax, r8
    mov     [r9 + httpasm_field.value_length], eax
    mov     rax, rdx
    sub     rax, [r13 + httpasm_request.fields]
    shr     rax, 5
    mov     [r13 + httpasm_request.field_count], eax
.done:
    xor     eax, eax
    jmp     .out
.no_memory:
    mov     eax, -ENOMEM
.out:
    add     rsp, K_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
; .rebase: rdi = a pointer; if it points into the scratch's strings, the same place in the
; copy. Uses rbx (the output) and rbp (the copy's strings). Clobbers rax.
.rebase:
    mov     rax, rdi
    sub     rax, [rbx + httpasm_hpack_output.space]
    jb      .rebase_out                     ; below the scratch: the static table's text
    cmp     rax, [rbx + httpasm_hpack_output.space_used]
    jae     .rebase_out
    lea     rdi, [rbp + rax]
.rebase_out:
    ret

; -----------------------------------------------------------------------------
; h2_keep_tail: decoded trailers into the stream's own block (as h2_keep_head, no cookies).
;   In: rdi = the httpasm_hpack_output, rsi = stream. Out: eax = 0 or -ENOMEM.
;   Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_keep_tail:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    mov     rbx, rdi
    mov     r12, rsi
    mov     eax, [rbx + httpasm_hpack_output.count]
    mov     [r12 + h2stream.trailer_count], eax
    shl     rax, 5
    mov     r14, rax
    lea     rdi, [rax + 1]                  ; at least one octet: an empty section still gets a block
    add     rdi, [rbx + httpasm_hpack_output.space_used]
    call    malloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     [r12 + h2stream.tail], rax
    mov     r13, rax
    lea     rbp, [rax + r14]
    mov     rdi, r13
    mov     rsi, [rbx + httpasm_hpack_output.fields]
    mov     rcx, r14
    rep     movsb
    mov     rdi, rbp
    mov     rsi, [rbx + httpasm_hpack_output.space]
    mov     rcx, [rbx + httpasm_hpack_output.space_used]
    rep     movsb
    mov     ecx, [r12 + h2stream.trailer_count]
    mov     rdx, r13
.field:
    test    ecx, ecx
    jz      .done
%macro REBASE_TAIL 1
    mov     rax, [rdx + %1]
    sub     rax, [rbx + httpasm_hpack_output.space]
    jb      %%keep
    cmp     rax, [rbx + httpasm_hpack_output.space_used]
    jae     %%keep
    add     rax, rbp
    mov     [rdx + %1], rax
%%keep:
%endmacro
    REBASE_TAIL httpasm_field.name
    REBASE_TAIL httpasm_field.value
    add     rdx, httpasm_field_size
    dec     ecx
    jmp     .field
.done:
    xor     eax, eax
    jmp     .out
.no_memory:
    mov     eax, -ENOMEM
.out:
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; h2_data: DATA (RFC 9113 6.1): a request's body. The whole frame, padding included, counts
; against both receive windows; the octets go back with WINDOW_UPDATE once half a window was
; consumed. A frame on a stream that cannot take it is still counted on the connection.
;   In: rbx = conn, r12 = h2. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_data:
    push    r13
    push    r14
    push    r15
    mov     edi, [r12 + h2.frame_stream]
    test    edi, edi
    jz      .protocol_error
    call    h2_payload
    jc      .protocol_error
    mov     r14, rsi                        ; the data
    mov     r15d, ecx                       ; its octets
    ; A DATA frame with no data that ends nothing is a glitch (h2_glitch): legal, and useless
    ; (CVE-2019-9518 floods them; an empty one with END_STREAM ends a request, and is not).
    test    r15d, r15d
    jnz     .not_empty
    test    dword [r12 + h2.frame_flags], H2_FLAG_END_STREAM
    jnz     .not_empty
    call    h2_glitch
    test    eax, eax
    jnz     .out                            ; the budget is spent: the connection is ending
.not_empty:
    ; The connection's window.
    mov     eax, [r12 + h2.frame_length]
    cmp     rax, [r12 + h2.recv_window]
    ja      .flow_control_error
    sub     [r12 + h2.recv_window], rax
    add     [r12 + h2.recv_unacked], rax
    cmp     qword [r12 + h2.recv_unacked], HA_H2_CONNECTION_WINDOW / 2
    jb      .connection_window_ok
    mov     rsi, [r12 + h2.recv_unacked]
    add     [r12 + h2.recv_window], rsi
    mov     qword [r12 + h2.recv_unacked], 0
    xor     edi, edi
    call    h2_window_update
.connection_window_ok:
    mov     edi, [r12 + h2.frame_stream]
    call    h2_find
    test    rax, rax
    jz      .not_active
    mov     r13, rax
    test    dword [r13 + h2stream.flags], HSF_END_RECEIVED
    jnz     .stream_closed                  ; half-closed (remote): STREAM_CLOSED (RFC 9113 5.1)
    mov     eax, [r12 + h2.frame_length]
    cmp     rax, [r13 + h2stream.recv_window]
    ja      .stream_flow_control_error
    sub     [r13 + h2stream.recv_window], rax
    add     [r13 + h2stream.recv_unacked], rax
    add     [rbx + conn.progress], rax      ; a body arriving: the connection's progress
    add     [r13 + h2stream.moved], rax     ; and the stream's own (ha_h2_sweep)
    ; Onto the body, within max_body (413 beyond, RFC 9110 15.5.14).
    mov     rax, [r13 + h2stream.body_length]
    add     rax, r15
    mov     rcx, [rbx + conn.worker]
    mov     rcx, [rcx + worker.server]
    cmp     rax, [rcx + server.max_body]
    ja      .too_large
    test    dword [r13 + h2stream.request + httpasm_request.flags], HTTPASM_REQUEST_CONTENT_LENGTH
    jz      .length_ok
    cmp     rax, [r13 + h2stream.request + httpasm_request.content_length]
    ja      .malformed                      ; more DATA than content-length (RFC9113-8.1.1-3)
.length_ok:
    cmp     rax, [r13 + h2stream.body_cap]
    jbe     .room
    mov     rsi, [r13 + h2stream.body_cap]  ; grow: twice, or what is needed, or the declared
    shl     rsi, 1                          ; length when it is known
    cmp     rsi, rax
    cmovb   rsi, rax
    test    dword [r13 + h2stream.request + httpasm_request.flags], HTTPASM_REQUEST_CONTENT_LENGTH
    jz      .grow
    mov     rcx, [r13 + h2stream.request + httpasm_request.content_length]
    cmp     rsi, rcx
    cmovb   rsi, rcx
.grow:
    mov     [r13 + h2stream.body_cap], rsi
    mov     rdi, [r13 + h2stream.body]
    call    realloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     [r13 + h2stream.body], rax
.room:
    mov     rdi, [r13 + h2stream.body]
    add     rdi, [r13 + h2stream.body_length]
    mov     rsi, r14
    mov     ecx, r15d
    COPY_OCTETS                             ; an empty DATA frame (END_STREAM, or a glitch)
    add     [r13 + h2stream.body_length], r15
    test    dword [r12 + h2.frame_flags], H2_FLAG_END_STREAM
    jz      .more_to_come
    or      dword [r13 + h2stream.flags], HSF_END_RECEIVED
    mov     rdi, r13
    call    h2_body_ended
    jmp     .out
.more_to_come:
    cmp     qword [r13 + h2stream.recv_unacked], HA_H2_WINDOW / 2
    jb      .out
    mov     rsi, [r13 + h2stream.recv_unacked]
    add     [r13 + h2stream.recv_window], rsi
    mov     qword [r13 + h2stream.recv_unacked], 0
    mov     edi, [r13 + h2stream.id]
    call    h2_window_update
    jmp     .out
.not_active:
    mov     edi, [r12 + h2.frame_stream]
    cmp     edi, [r12 + h2.last_stream]
    ja      .protocol_error                 ; idle (RFC 9113 5.1)
    call    h2_closed_how
    cmp     eax, H2C_RESET
    je      .out                            ; this side reset it: in flight, ignored
    cmp     eax, H2C_PEER_RESET
    je      .stream_closed_id
    mov     edi, H2_STREAM_CLOSED           ; ended, or never used: a connection error
    call    h2_connection_error
    jmp     .out
.stream_closed_id:
    mov     edi, [r12 + h2.frame_stream]
    mov     esi, H2_STREAM_CLOSED
    call    h2_peer_stream_error
    jmp     .out
.stream_closed:
    mov     edi, [r13 + h2stream.id]        ; DATA after END_STREAM: the stream may be at its
    mov     esi, H2_STREAM_CLOSED           ; handler (CVE-2025-8671 provokes exactly this)
    call    h2_peer_stream_error
    jmp     .out
.stream_flow_control_error:
    mov     edi, [r13 + h2stream.id]
    mov     esi, H2_FLOW_CONTROL_ERROR
    call    h2_peer_stream_error
    jmp     .out
.malformed:
    mov     edi, [r13 + h2stream.id]
    mov     esi, H2_PROTOCOL_ERROR
    call    h2_peer_stream_error
    jmp     .out
.too_large:
    call    h2_glitch                       ; a refusal the peer earned
    test    eax, eax
    jnz     .out
    mov     rdi, r13
    mov     esi, 413
    call    h2_error_response
    jmp     .out
.no_memory:
    mov     edi, [r13 + h2stream.id]
    mov     esi, H2_INTERNAL_ERROR
    call    h2_stream_error
    jmp     .out
.flow_control_error:
    mov     edi, H2_FLOW_CONTROL_ERROR
    call    h2_connection_error
    jmp     .out
.protocol_error:
    mov     edi, H2_PROTOCOL_ERROR
    call    h2_connection_error
.out:
    pop     r15
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_body_ended: the request ended (END_STREAM on DATA or trailers): its content-length must
; equal the DATA received (RFC9113-8.1.1-3), then the handler gets it.
;   In: rbx = conn, r12 = h2, rdi = stream. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_body_ended:
    sub     rsp, 8
    test    dword [rdi + h2stream.flags], HSF_ANSWERED
    jnz     .answered                       ; an early answer (413, 417) already went out
    test    dword [rdi + h2stream.request + httpasm_request.flags], HTTPASM_REQUEST_CONTENT_LENGTH
    jz      .dispatch
    mov     rax, [rdi + h2stream.body_length]
    cmp     rax, [rdi + h2stream.request + httpasm_request.content_length]
    jne     .malformed
.dispatch:
    call    h2_dispatch
    jmp     .out
.answered:
    ; Both sides are done once the early answer's body is out too.
    test    dword [rdi + h2stream.flags], HSF_END_SENT
    jz      .out
    mov     esi, H2C_NORMAL
    call    h2_close
    jmp     .out
.malformed:
    mov     edi, [rdi + h2stream.id]        ; content-length and the DATA disagree
    mov     esi, H2_PROTOCOL_ERROR
    call    h2_peer_stream_error
.out:
    add     rsp, 8
    ret

; -----------------------------------------------------------------------------
; h2_dispatch: a whole request goes to the handler, as an exchange with the stream's request,
; body and trailers. A deferral counts on the connection (it stays allocated while any is
; outstanding); a handler that returns without an answer gets 500 for its stream only.
;   In: rbx = conn, r12 = h2, rdi = stream. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_dispatch:
    push    r13
    push    r14
    push    r15
    mov     r13, rdi
    lea     r14, [r13 + h2stream.exchange]
    mov     [r14 + exchange.conn], rbx
    mov     [r14 + exchange.stream], r13
    lea     rax, [r13 + h2stream.request]
    mov     [r14 + exchange.request], rax
    mov     rax, [r13 + h2stream.body]
    test    rax, rax
    jnz     .body
    lea     rax, [r13 + h2stream.body]      ; an empty body is still a valid pointer
.body:
    mov     [r14 + exchange.body], rax
    mov     rax, [r13 + h2stream.body_length]
    mov     [r14 + exchange.body_length], rax
    mov     rax, [r13 + h2stream.tail]
    test    rax, rax
    jnz     .trailers
    lea     rax, [r13 + h2stream.tail]      ; no trailers: a valid pointer, count 0
.trailers:
    mov     [r14 + exchange.trailers], rax
    mov     eax, [r13 + h2stream.trailer_count]
    mov     [r14 + exchange.trailer_count], eax
    mov     dword [r14 + exchange.state], X_IN_HANDLER
    or      dword [r13 + h2stream.flags], HSF_DISPATCHED | HSF_IN_HANDLER
    mov     r15, [rbx + conn.worker]
    mov     r15, [r15 + worker.server]
    mov     rdi, [r15 + server.context]
    mov     rsi, r14
    call    [r15 + server.handler]
    mov     eax, [r14 + exchange.state]
    cmp     eax, X_DEFERRED
    je      .deferred
    cmp     eax, X_POSTED                   ; answered from another thread before returning
    je      .deferred
    cmp     eax, X_RESPONDED
    je      .answered
    ; No answer: 500, for this stream only. HSF_IN_HANDLER is still set, so a stream this
    ; finishes is only detached, not freed under this function.
    mov     rdi, r13
    mov     esi, 500
    call    h2_error_response
    mov     dword [r14 + exchange.state], X_RESPONDED
.answered:
    and     dword [r13 + h2stream.flags], ~HSF_IN_HANDLER
    ; Finished while the handler ran: the stream left the active set then; free it now.
    test    dword [r13 + h2stream.flags], HSF_CANCELLED
    jz      .out
    mov     rdi, r13
    call    h2_free_stream
    jmp     .out
.deferred:
    and     dword [r13 + h2stream.flags], ~HSF_IN_HANDLER
    or      dword [r13 + h2stream.flags], HSF_DEFERRED
    inc     dword [rbx + conn.deferred]
.out:
    pop     r15
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_error_response: the server's own answer (413, 417, 431, 500), before or after the request
; ended, explaining itself in one line of text/plain: the status's reason phrase
; (RFC9110-15.5-1#1, 15.6-1#1; HEAD drops it, as ha_h2_respond does for every HEAD). Done
; before the request's end, the stream is then reset with NO_ERROR (RFC 9113 8.1: the client
; should stop sending).
;   In: rbx = conn, r12 = h2, rdi = stream, esi = status. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
HE_LENGTH   equ 0       ; the body's length (the 7th argument), at [rsp] when called
HE_FIELD    equ 8       ; httpasm_field: content-type: text/plain (32)
HE_STREAM   equ 40
HE_STATUS   equ 48
HE_FRAME    equ 56      ; entered at 8 past 16: 56 more leaves rsp aligned for the calls

align 16
h2_error_response:
    sub     rsp, HE_FRAME
    mov     [rsp + HE_STREAM], rdi
    mov     [rsp + HE_STATUS], esi
    mov     edi, esi
    call    ha_status_reason                ; rax = the phrase, edx = its length (0: none)
    mov     r9, rax                         ; the body
    mov     [rsp + HE_LENGTH], rdx          ; edx's write zero-extended rdx
    xor     r8d, r8d                        ; no content-type without content
    test    edx, edx
    jz      .respond
    lea     rax, [rel s_content_type]
    mov     [rsp + HE_FIELD + httpasm_field.name], rax
    lea     rax, [rel s_text_plain]
    mov     [rsp + HE_FIELD + httpasm_field.value], rax
    mov     dword [rsp + HE_FIELD + httpasm_field.name_length], 12
    mov     dword [rsp + HE_FIELD + httpasm_field.value_length], 10
    mov     dword [rsp + HE_FIELD + httpasm_field.id], 0    ; id and flags: none
    mov     dword [rsp + HE_FIELD + httpasm_field.reserved], 0
    mov     r8d, 1
.respond:
    lea     rcx, [rsp + HE_FIELD]
    mov     edx, [rsp + HE_STATUS]
    mov     rsi, [rsp + HE_STREAM]
    mov     rdi, rbx
    call    ha_h2_respond
    add     rsp, HE_FRAME
    ret

; -----------------------------------------------------------------------------
; h2_continue: 100 (Continue) on a stream whose request expects it and whose body has not
; begun (RFC 9110 10.1.1): HEADERS with :status 100, neither ending the stream nor final. The
; block comes from the connection's encoder like every other, so a table size update it owes
; still starts the first block after the change (RFC 7541 4.2).
;   In: rbx = conn, r12 = h2, rdi = stream. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
C_FIELD     equ 0       ; one httpasm_field: ":status: 100"
C_DIGITS    equ 32      ; "100"
C_BLOCK     equ 40      ; the block: at most 12 + 18 + 7 + 3 octets
C_FRAME     equ 96      ; one push + 96: aligned

align 16
h2_continue:
    push    r13
    sub     rsp, C_FRAME
    mov     r13, rdi
    test    dword [r13 + h2stream.flags], HSF_CONTINUE_SENT
    jnz     .out
    or      dword [r13 + h2stream.flags], HSF_CONTINUE_SENT
    mov     dword [rsp + C_DIGITS], '100'
    lea     rax, [rel s_status]
    mov     [rsp + C_FIELD + httpasm_field.name], rax
    lea     rax, [rsp + C_DIGITS]
    mov     [rsp + C_FIELD + httpasm_field.value], rax
    mov     dword [rsp + C_FIELD + httpasm_field.name_length], 7
    mov     dword [rsp + C_FIELD + httpasm_field.value_length], 3
    mov     dword [rsp + C_FIELD + httpasm_field.id], 0
    mov     dword [rsp + C_FIELD + httpasm_field.reserved], 0
    mov     rdi, [r12 + h2.encoder]
    lea     rsi, [rsp + C_FIELD]
    mov     edx, 1
    lea     rcx, [rsp + C_BLOCK]
    mov     r8d, C_FRAME - C_BLOCK
    call    httpasm_hpack_encode
    test    rax, rax
    jz      .out
    mov     edi, H2_HEADERS
    mov     esi, H2_FLAG_END_HEADERS
    mov     edx, [r13 + h2stream.id]
    lea     rcx, [rsp + C_BLOCK]
    mov     r8, rax
    call    h2_frame
.out:
    add     rsp, C_FRAME
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_bad_request: a request head that breaks HTTP/2's message rules (a field or pseudo-field the
; core's httpasm_h2_request refused, or a content-length that END_STREAM contradicts) gets
; 400 (Bad Request), then RST_STREAM(PROTOCOL_ERROR). Both, because both apply: the SHOULD of
; RFC9113-8.2.1-6 (a 400 where one can be sent; RFC9113-8.1.1-4#1 allows a response before the
; reset) and the MUST of RFC9113-8.1.1-3 (a malformed request is a stream error, which is a
; RST_STREAM, RFC 9113 5.4.2).
;   The 400's HEADERS does not end the stream: when the request ended already, END_STREAM
;   would close the stream, and a closed stream can carry no RST_STREAM (RFC9113-5.1-7.14.3);
;   the reset is what tells the client its request was malformed, and it comes last. The
;   response holds :status and the worker's date (RFC 9110 6.6.1: a 4xx carries Date), encoded
;   by the connection's encoder like every block, so the HPACK tables stay in step.
;   Not for trailers or DATA (there the 400 may contradict an answer in progress, and
;   RFC9113-8.2.1-6 itself exempts trailers): those get the reset alone (h2_peer_stream_error).
;   The reset is h2_peer_stream_error's: a glitch, and one more reset for the rapid-reset
;   rule, so a stream of malformed requests ends the connection like any other reset storm;
;   when it does, the 400 is followed by the GOAWAY instead of the RST_STREAM.
;   In: rbx = conn, r12 = h2, rdi = stream (active, not dispatched). Clobbers every caller-saved
;   register; the stream is closed (reset) afterwards, and freed unless a handler holds it.
; -----------------------------------------------------------------------------
BR_STATUS   equ 0       ; httpasm_field: ":status: 400"
BR_DATE     equ 32      ; httpasm_field: "date: <the worker's IMF-fixdate>"
BR_DIGITS   equ 64      ; "400"
BR_BLOCK    equ 72      ; the block: a size update (3), :status (1), date (1 + 1 + 29) at most
BR_FRAME    equ 176     ; one push + 176: aligned; the block's room is 104 octets

align 16
h2_bad_request:
    push    r13
    sub     rsp, BR_FRAME
    mov     r13, rdi
    mov     dword [rsp + BR_DIGITS], '400'
    lea     rax, [rel s_status]
    mov     [rsp + BR_STATUS + httpasm_field.name], rax
    lea     rax, [rsp + BR_DIGITS]
    mov     [rsp + BR_STATUS + httpasm_field.value], rax
    mov     dword [rsp + BR_STATUS + httpasm_field.name_length], 7
    mov     dword [rsp + BR_STATUS + httpasm_field.value_length], 3
    mov     dword [rsp + BR_STATUS + httpasm_field.id], 0
    mov     dword [rsp + BR_STATUS + httpasm_field.reserved], 0
    lea     rax, [rel s_date]
    mov     [rsp + BR_DATE + httpasm_field.name], rax
    mov     rax, [rbx + conn.worker]
    lea     rax, [rax + worker.date]        ; refreshed every second by the worker's loop
    mov     [rsp + BR_DATE + httpasm_field.value], rax
    mov     dword [rsp + BR_DATE + httpasm_field.name_length], 4
    mov     dword [rsp + BR_DATE + httpasm_field.value_length], 29
    mov     dword [rsp + BR_DATE + httpasm_field.id], 0
    mov     dword [rsp + BR_DATE + httpasm_field.reserved], 0
    mov     rdi, [r12 + h2.encoder]
    lea     rsi, [rsp + BR_STATUS]
    mov     edx, 2
    lea     rcx, [rsp + BR_BLOCK]
    mov     r8d, BR_FRAME - BR_BLOCK
    call    httpasm_hpack_encode
    test    rax, rax
    jle     .reset                          ; cannot happen in this room; the reset must come anyway
    mov     edi, H2_HEADERS
    mov     esi, H2_FLAG_END_HEADERS        ; no END_STREAM: the reset is the stream's last frame
    mov     edx, [r13 + h2stream.id]
    lea     rcx, [rsp + BR_BLOCK]
    mov     r8, rax
    call    h2_frame
.reset:
    mov     edi, [r13 + h2stream.id]        ; closes the stream as reset by this side; the
    mov     esi, H2_PROTOCOL_ERROR          ; peer's doing, so a glitch and a reset counted
    call    h2_peer_stream_error
    add     rsp, BR_FRAME
    pop     r13
    ret

; -----------------------------------------------------------------------------
; ha_h2_respond: a final response on a stream: HEADERS (and CONTINUATIONs when the block is
; larger than the peer's frame size), then the body as DATA frames as far as the windows allow;
; the rest waits on the stream (a copy) for WINDOW_UPDATE or a SETTINGS change.
;   The fields are checked with HTTP/1.1's response rules plus Upgrade (the core's
;   ha_check_fields): one set of rules for every version. Names go out lower-cased (RFC
;   9113 8.2). The library adds :status, date (unless given) and content-length (except for
;   1xx, 204 and 304). HEAD and the bodiless statuses end the stream on HEADERS.
;   In: rdi = conn, rsi = stream, edx = status (200-599), rcx = fields, r8d = count, r9 = body,
;   [rsp + 8] = the body's length. Out: eax = 0 (also when the stream is gone: the answer is
;   dropped), -HTTPASM_ERROR_* (nothing sent; _STATUS also for a 205 with a body, which must
;   carry none), or -ENOMEM.
;   Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
R_STATUS    equ 0
R_COUNT     equ 4
R_FIELDS    equ 8
R_BODY      equ 16
R_LENGTH    equ 24
R_LIST      equ 32      ; the field list (in the worker's h2_out)
R_ITEMS     equ 40      ; its records
R_NOBODY    equ 44      ; 1: the stream ends with the HEADERS
R_DIGITS    equ 48      ; ":status" and content-length's digits (24 octets)
R_FRAME     equ 88      ; six pushes + 88: aligned

global ha_h2_respond:function hidden (ha_h2_respond.end - ha_h2_respond)
align 16
ha_h2_respond:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, R_FRAME
    mov     rbx, rdi
    mov     r13, rsi
    mov     [rsp + R_STATUS], edx
    mov     [rsp + R_FIELDS], rcx
    mov     [rsp + R_COUNT], r8d
    mov     [rsp + R_BODY], r9
    mov     rax, [rsp + R_FRAME + 6 * 8 + 8]
    mov     [rsp + R_LENGTH], rax
    mov     r12, [rbx + conn.h2]
    xor     eax, eax
    test    dword [r13 + h2stream.flags], HSF_CANCELLED
    jnz     .out                            ; the stream is gone: the answer is dropped
    test    r12, r12
    jz      .out
    mov     eax, -HTTPASM_ERROR_STATUS
    cmp     dword [rsp + R_STATUS], 200
    jb      .out
    cmp     dword [rsp + R_STATUS], 599
    ja      .out
    cmp     dword [rsp + R_STATUS], 205
    jne     .status_allowed
    cmp     qword [rsp + R_LENGTH], 0       ; 205 carries no content (RFC9110-15.3.6-3): refused
    jne     .out                            ; with a body, as HTTP/1.1's writer refuses it
.status_allowed:
    mov     rdi, [rsp + R_FIELDS]
    mov     esi, [rsp + R_COUNT]
    mov     edx, HA_CHECK_H2_RESPONSE
    call    ha_check_fields
    test    eax, eax
    jz      .fields_ok
    neg     eax
    jmp     .out
.fields_ok:
    mov     r15d, ecx                       ; 1: the caller gave a Date

    ; Room in the worker's h2_out: the list (count + 3 records), lower-cased names, the block.
    mov     eax, [rsp + R_COUNT]
    add     eax, 3
    shl     rax, 5
    mov     r14, rax                        ; the list's octets
    mov     rdi, [rsp + R_FIELDS]
    mov     esi, [rsp + R_COUNT]
    call    httpasm_hpack_encode_bound
    ; The block's bound with the three added fields (each 18 + its strings: :status 7 + 3,
    ; date 4 + 29, content-length 14 + 20 = 131), rounded up.
    lea     rbp, [rax + 160]
    mov     ecx, [rsp + R_COUNT]
    mov     rdx, [rsp + R_FIELDS]
.name_room:
    test    ecx, ecx
    jz      .room_known
    mov     eax, [rdx + httpasm_field.name_length]
    add     rbp, rax
    add     rdx, httpasm_field_size
    dec     ecx
    jmp     .name_room
.room_known:
    lea     rsi, [rbp + r14]                ; list + names + block (names counted in rbp too)
    mov     rdi, [rbx + conn.worker]
    cmp     rsi, [rdi + worker.h2_out_cap]
    jbe     .out_ready
    mov     [rdi + worker.h2_out_cap], rsi
    mov     rdi, [rdi + worker.h2_out]
    call    realloc wrt ..plt
    test    rax, rax
    jz      .no_out
    mov     rdi, [rbx + conn.worker]
    mov     [rdi + worker.h2_out], rax
.out_ready:
    mov     rdi, [rbx + conn.worker]
    mov     rax, [rdi + worker.h2_out]
    mov     [rsp + R_LIST], rax
    lea     rbp, [rax + r14]                ; lower-cased names, then the block, go here
    mov     dword [rsp + R_ITEMS], 0
    mov     dword [rsp + R_NOBODY], 0

    ; :status, three digits.
    mov     eax, [rsp + R_STATUS]
    xor     edx, edx
    mov     ecx, 100
    div     ecx
    add     al, '0'
    mov     [rsp + R_DIGITS], al
    mov     eax, edx
    xor     edx, edx
    mov     ecx, 10
    div     ecx
    add     al, '0'
    mov     [rsp + R_DIGITS + 1], al
    add     dl, '0'
    mov     [rsp + R_DIGITS + 2], dl
    lea     rsi, [rel s_status]
    mov     ecx, 7
    lea     rdx, [rsp + R_DIGITS]
    mov     r8d, 3
    call    .item
    ; date, the worker's (unless the caller gave one).
    test    r15d, r15d
    jnz     .dated
    lea     rsi, [rel s_date]
    mov     ecx, 4
    mov     rdx, [rbx + conn.worker]
    lea     rdx, [rdx + worker.date]
    mov     r8d, 29
    call    .item
.dated:
    ; Bodiless statuses, and HEAD (which keeps content-length: what GET would send).
    mov     eax, [rsp + R_STATUS]
    cmp     eax, 204
    je      .bodiless
    cmp     eax, 304
    je      .bodiless
    cmp     word [r13 + h2stream.request + httpasm_request.method_id], HTTPASM_METHOD_HEAD
    jne     .length
    mov     dword [rsp + R_NOBODY], 1
.length:
    ; content-length: the body's decimal digits.
    mov     rax, [rsp + R_LENGTH]
    lea     rdi, [rsp + R_DIGITS + 24]      ; written backwards
    mov     ecx, 10
.digit:
    xor     edx, edx
    div     rcx
    add     dl, '0'
    dec     rdi
    mov     [rdi], dl
    test    rax, rax
    jnz     .digit
    lea     r8, [rsp + R_DIGITS + 24]
    sub     r8, rdi
    mov     rdx, rdi
    lea     rsi, [rel s_content_length]
    mov     ecx, 14
    call    .item
    jmp     .caller_fields
.bodiless:
    mov     dword [rsp + R_NOBODY], 1
.caller_fields:
    ; The caller's fields, names lower-cased (they were checked to be tokens).
    mov     r14d, [rsp + R_COUNT]
    mov     r15, [rsp + R_FIELDS]
.caller_field:
    test    r14d, r14d
    jz      .encode
    mov     rsi, [r15 + httpasm_field.name]
    mov     ecx, [r15 + httpasm_field.name_length]
    mov     rdi, rbp                        ; the lower-cased copy
    push    rcx
    push    rdi
.lower:
    test    ecx, ecx
    jz      .lowered
    movzx   eax, byte [rsi]
    lea     edx, [rax - 'A']
    cmp     edx, 'Z' - 'A'
    ja      .as_is
    or      eax, 0x20
.as_is:
    mov     [rdi], al
    inc     rsi
    inc     rdi
    dec     ecx
    jmp     .lower
.lowered:
    pop     rsi                             ; the copy
    pop     rcx                             ; its length
    add     rbp, rcx
    mov     rdx, [r15 + httpasm_field.value]
    mov     r8d, [r15 + httpasm_field.value_length]
    call    .item
    add     r15, httpasm_field_size
    dec     r14d
    jmp     .caller_field

.encode:
    ; The HPACK block, after the names.
    mov     rdi, [r12 + h2.encoder]
    mov     rsi, [rsp + R_LIST]
    mov     edx, [rsp + R_ITEMS]
    mov     rcx, rbp
    mov     rax, [rbx + conn.worker]
    mov     r8, [rax + worker.h2_out]
    add     r8, [rax + worker.h2_out_cap]
    sub     r8, rbp                         ; the room left for it
    call    httpasm_hpack_encode
    test    rax, rax
    jz      .no_out                         ; cannot happen: the room was sized from the bound
    mov     r14, rax                        ; the block's length
    ; END_STREAM on the HEADERS when nothing follows.
    xor     r15d, r15d
    cmp     dword [rsp + R_NOBODY], 0
    jne     .ends_here
    cmp     qword [rsp + R_LENGTH], 0
    jne     .frames
.ends_here:
    mov     r15d, H2_FLAG_END_STREAM
.frames:
    ; HEADERS, then CONTINUATIONs, each at most the peer's frame size.
    mov     ecx, [r12 + h2.peer_frame]
    mov     r8, r14
    cmp     r8, rcx
    cmova   r8, rcx                         ; this frame's fragment
    mov     esi, r15d
    cmp     r8, r14
    jne     .first_fragment
    or      esi, H2_FLAG_END_HEADERS
.first_fragment:
    push    r8
    sub     rsp, 8
    mov     edi, H2_HEADERS
    mov     edx, [r13 + h2stream.id]
    mov     rcx, rbp
    call    h2_frame
    add     rsp, 8
    pop     r8
    test    eax, eax
    jnz     .no_memory
    add     rbp, r8
    sub     r14, r8
.continuation:
    test    r14, r14
    jz      .headers_sent
    mov     ecx, [r12 + h2.peer_frame]
    mov     r8, r14
    cmp     r8, rcx
    cmova   r8, rcx
    xor     esi, esi
    cmp     r8, r14
    jne     .middle
    mov     esi, H2_FLAG_END_HEADERS
.middle:
    push    r8
    sub     rsp, 8
    mov     edi, H2_CONTINUATION
    mov     edx, [r13 + h2stream.id]
    mov     rcx, rbp
    call    h2_frame
    add     rsp, 8
    pop     r8
    test    eax, eax
    jnz     .no_memory
    add     rbp, r8
    sub     r14, r8
    jmp     .continuation
.headers_sent:
    or      dword [r13 + h2stream.flags], HSF_HEADERS_SENT | HSF_ANSWERED
    ; An answer queued starts a new window for the connection, as HTTP/1.1's ha_conn_finish
    ; does: however late in the last window it came, a slow client has a whole one to take it.
    mov     rdi, rbx
    call    ha_lru_touch                    ; keeps r13-r15
    test    r15d, r15d
    jz      .body
    or      dword [r13 + h2stream.flags], HSF_END_SENT
    mov     rdi, r13
    call    h2_stream_done
    xor     eax, eax
    jmp     .out
.body:
    ; As much as the windows allow from the caller's body itself; a copy of the rest waits.
    mov     rax, [rsp + R_BODY]
    mov     [r13 + h2stream.out], rax
    mov     rax, [rsp + R_LENGTH]
    mov     [r13 + h2stream.out_length], rax
    mov     qword [r13 + h2stream.out_sent], 0
    mov     rdi, r13
    mov     esi, 1                          ; borrowed: not this stream's to free
    call    h2_send_out
    test    eax, eax
    jnz     .no_memory
    xor     eax, eax
    jmp     .out
.no_out:
    mov     rdi, [rbx + conn.worker]
    mov     qword [rdi + worker.h2_out_cap], 0
.no_memory:
    mov     eax, -ENOMEM
.out:
    add     rsp, R_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
; .item: one more record in the list: rsi = name, ecx = its length, rdx = value, r8d = its
; length (a local routine of ha_h2_respond: rsp is 8 below its frame). Clobbers rax, rdi.
.item:
    mov     eax, [rsp + 8 + R_ITEMS]
    mov     rdi, rax
    shl     rdi, 5
    add     rdi, [rsp + 8 + R_LIST]
    mov     [rdi + httpasm_field.name], rsi
    mov     [rdi + httpasm_field.value], rdx
    mov     [rdi + httpasm_field.name_length], ecx
    mov     [rdi + httpasm_field.value_length], r8d
    mov     dword [rdi + httpasm_field.id], 0
    mov     dword [rdi + httpasm_field.reserved], 0
    inc     dword [rsp + 8 + R_ITEMS]
    ret
.end:

; -----------------------------------------------------------------------------
; h2_send_out: a stream's waiting body as DATA frames, as far as both send windows allow, each
; at most the peer's frame size; END_STREAM on the last. What a borrowed body (the caller's,
; esi = 1) still has to send is copied, so the caller may free its own.
;   In: rbx = conn, r12 = h2, rdi = stream (with .out set), esi = 1 when .out is borrowed.
;   Out: eax = 0 or -ENOMEM. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_send_out:
    push    r13
    push    r14
    push    r15
    mov     r13, rdi
    mov     r15d, esi
.frame:
    mov     r14, [r13 + h2stream.out_length]
    sub     r14, [r13 + h2stream.out_sent]  ; left to send
    jz      .ended
    mov     rax, [r12 + h2.send_window]
    cmp     rax, [r13 + h2stream.send_window]
    cmovg   rax, [r13 + h2stream.send_window]
    test    rax, rax
    jle     .waiting                        ; no window: WINDOW_UPDATE or SETTINGS resumes it
    cmp     r14, rax
    cmova   r14, rax
    mov     eax, [r12 + h2.peer_frame]
    cmp     r14, rax
    cmova   r14, rax                        ; this frame's octets
    xor     esi, esi
    mov     rax, [r13 + h2stream.out_length]
    sub     rax, [r13 + h2stream.out_sent]
    cmp     r14, rax
    jne     .not_last
    mov     esi, H2_FLAG_END_STREAM
.not_last:
    mov     edi, H2_DATA
    mov     edx, [r13 + h2stream.id]
    mov     rcx, [r13 + h2stream.out]
    add     rcx, [r13 + h2stream.out_sent]
    mov     r8, r14
    call    h2_frame
    test    eax, eax
    jnz     .no_memory
    sub     [r12 + h2.send_window], r14
    sub     [r13 + h2stream.send_window], r14
    add     [r13 + h2stream.out_sent], r14
    add     [r13 + h2stream.moved], r14     ; the answer moving: the stream's progress (its
    jmp     .frame                          ; window opening; the socket's pace is the conn's)
.ended:
    test    r15d, r15d
    jnz     .borrowed_done
    mov     rdi, [r13 + h2stream.out]
    call    free wrt ..plt
.borrowed_done:
    mov     qword [r13 + h2stream.out], 0
    or      dword [r13 + h2stream.flags], HSF_END_SENT
    mov     rdi, r13
    call    h2_stream_done
    xor     eax, eax
    jmp     .out
.waiting:
    ; Held back by the connection's window (spent, or both are): a WINDOW_UPDATE on stream 0
    ; must walk the streams again (H2F_CONN_BLOCKED). By its own window alone, only its own
    ; WINDOW_UPDATE or a SETTINGS change can move it.
    cmp     qword [r12 + h2.send_window], 0
    jg      .own_window
    or      dword [r12 + h2.flags], H2F_CONN_BLOCKED
.own_window:
    test    r15d, r15d
    jz      .kept
    ; The caller's body: copy what is left.
    mov     rdi, r14
    call    malloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     rdi, rax
    mov     rsi, [r13 + h2stream.out]
    add     rsi, [r13 + h2stream.out_sent]
    mov     rcx, r14
    mov     [r13 + h2stream.out], rax
    rep     movsb
    mov     [r13 + h2stream.out_length], r14
    mov     qword [r13 + h2stream.out_sent], 0
.kept:
    xor     eax, eax
    jmp     .out
.no_memory:
    mov     qword [r13 + h2stream.out], 0   ; nothing of the caller's is kept
    mov     eax, -ENOMEM
.out:
    pop     r15
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_send_data: resumes a stream's waiting body (h2_send_out on its own copy).
;   In: rbx = conn, r12 = h2, rdi = stream. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_send_data:
    cmp     qword [rdi + h2stream.out], 0
    je      .none
    xor     esi, esi
    jmp     h2_send_out
.none:
    ret

; -----------------------------------------------------------------------------
; h2_resume: every active stream with a waiting body sends what the windows now allow. A stream
; that finishes leaves the active set (its slot taken by the last one), so the index advances
; only past streams that stay. H2F_CONN_BLOCKED starts over: h2_send_out sets it again for a
; body the connection's window holds back, and so does a walk cut short by that window (the
; streams it did not reach may wait too).
;   In: rbx = conn, r12 = h2. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_resume:
    push    r13
    push    r14
    sub     rsp, 8
    and     dword [r12 + h2.flags], ~H2F_CONN_BLOCKED
    xor     r13d, r13d
.stream:
    cmp     r13d, [r12 + h2.stream_count]
    jae     .out
    cmp     qword [r12 + h2.send_window], 0
    jle     .spent                          ; the connection's window is spent
    mov     r14, [r12 + h2.streams + r13 * 8]
    mov     rdi, r14
    call    h2_send_data
    cmp     r13d, [r12 + h2.stream_count]
    jae     .out
    cmp     [r12 + h2.streams + r13 * 8], r14
    jne     .stream                         ; it finished: another stream has this slot now
    inc     r13d
    jmp     .stream
.spent:
    or      dword [r12 + h2.flags], H2F_CONN_BLOCKED
.out:
    add     rsp, 8
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; h2_stream_done: the response ended (END_STREAM sent). If the request ended too, the stream
; closes normally; if not (an early answer), it is reset with NO_ERROR so the client stops
; sending (RFC9113-8.1-3).
;   In: rbx = conn, r12 = h2, rdi = stream. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
h2_stream_done:
    sub     rsp, 8
    test    dword [rdi + h2stream.flags], HSF_END_RECEIVED
    jz      .early
    mov     esi, H2C_NORMAL
    call    h2_close
    jmp     .out
.early:
    mov     edi, [rdi + h2stream.id]
    mov     esi, H2_NO_ERROR
    call    h2_stream_error
.out:
    add     rsp, 8
    ret

; -----------------------------------------------------------------------------
; ha_h2_completion: a deferred stream's answer, posted by another thread, on the worker. A
; stream detached meanwhile (reset, or its connection closed) is freed and the answer dropped.
;   In: rdi = conn, rsi = the completion (fields and body inside it). The caller frees the
;   completion and adjusts conn.deferred. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
global ha_h2_completion:function hidden (ha_h2_completion.end - ha_h2_completion)
align 16
ha_h2_completion:
    push    rbx
    push    r12
    push    r13
    mov     rbx, rdi
    mov     r12, rsi
    mov     r13, [r12 + completion.stream]
    test    dword [r13 + h2stream.flags], HSF_CANCELLED
    jz      .live
    mov     rdi, r13
    call    h2_free_stream
    jmp     .out
.live:
    and     dword [r13 + h2stream.flags], ~HSF_DEFERRED
    mov     dword [r13 + h2stream.exchange + exchange.state], X_RESPONDED
    sub     rsp, 16
    mov     rax, [r12 + completion.body_length]
    mov     [rsp], rax
    mov     rdi, rbx
    mov     rsi, r13
    mov     edx, [r12 + completion.status]
    mov     rcx, [r12 + completion.fields]
    mov     r8d, [r12 + completion.field_count]
    mov     r9, [r12 + completion.body]
    call    ha_h2_respond
    add     rsp, 16
    test    eax, eax
    jz      .out
    mov     r12, [rbx + conn.h2]            ; no memory for it: the stream is reset
    test    r12, r12
    jz      .out
    mov     edi, [r13 + h2stream.id]
    mov     esi, H2_INTERNAL_ERROR
    call    h2_stream_error
.out:
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:
