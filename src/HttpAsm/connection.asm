; =============================================================================
; connection.asm - one HTTP/1.1 connection on a worker: the request loop (head, body, trailers,
; the handler), responses into the output buffer, flushing with back-pressure, and closing.
;
; The input buffer always starts with the current message. The sans-I/O codec parses it in
; place (h1/request.asm, h1/chunked.asm); when a message is answered, the bytes after it
; (pipelined requests) move to the front. Responses are appended to the output buffer and leave
; in one send per batch: every request a read brought is answered before the flush, so
; pipelined requests cost one system call, not one each (RFC9112-9.3.2-1#2: responses go out in
; request order).
;
; Back-pressure: while more than HA_OUTPUT_HIGH octets wait to be sent, the connection is not
; read. A client that sends requests but never reads the responses cannot make the server
; buffer without bound.
;
; A request's pointers (httpasm_request, the field records) point into the input buffer. When
; the buffer must grow (a body larger than it), realloc may move it, and conn_rebase moves every
; such pointer by the same distance.
; =============================================================================
default rel
%include "httpasm.inc"
%include "internal/driver.inc"

section .rodata
s_continue:     db "HTTP/1.1 100 Continue", 13, 10, 13, 10     ; RFC 9110 10.1.1
s_continue_len  equ $ - s_continue
s_content_type: db "Content-Type"                               ; the refusals' explanations are
s_text_plain:   db "text/plain"                                 ; plain text (RFC9110-8.3-5#1)
; A 505 says which versions this server speaks (RFC9110-15.6.6-1), not only that it refused one.
s_505_body:     db "HTTP Version Not Supported: this server speaks HTTP/1.1, and HTTP/2 with prior knowledge", 10
s_505_body_len  equ $ - s_505_body

section .text

; -----------------------------------------------------------------------------
; ha_interest_mask: the events a connection should wait for, from its flags; the one rule set
; for both backends (epoll's ha_set_interest, io_uring's poll in uring.asm; EPOLL* and POLL*
; share their values). Closed connections and zombies wait for nothing (their descriptor is
; gone). Otherwise: RDHUP until the peer's end was seen (a peer's close is noticed even while
; deferred; once seen, asking again would wake the worker in a loop, since it stays raised),
; OUT while output waits for the socket, IN unless output waits, an exchange is deferred, or
; reading is paused. A deferred connection whose peer is done waits for nothing at all (0:
; only errors and hang-ups, which are always reported).
;   In: rdi = conn. Out: esi = the events. Clobbers ecx and the flags; keeps the rest.
; -----------------------------------------------------------------------------
global ha_interest_mask:function hidden (ha_interest_mask.end - ha_interest_mask)
align 16
ha_interest_mask:
    xor     esi, esi
    mov     ecx, [rdi + conn.flags]
    test    ecx, C_ZOMBIE | C_CLOSED
    jnz     .out
    test    ecx, C_PEER_DONE
    jnz     .rdhup_set
    mov     esi, EPOLLRDHUP
.rdhup_set:
    test    ecx, C_WANT_WRITE
    jz      .no_write
    or      esi, EPOLLOUT
    jmp     .out
.no_write:
    test    ecx, C_DEFERRED | C_READ_PAUSED
    jnz     .out
    or      esi, EPOLLIN
.out:
    ret
.end:

; -----------------------------------------------------------------------------
; ha_set_interest: the events a connection waits for follow its flags (ha_interest_mask).
;   epoll: one epoll_ctl, only when the set changes. io_uring: the connection goes on the
;   pending list, and the next submission arms, updates or removes its poll (uring.asm) from
;   its state then; closed connections and zombies included, whose poll must go.
;   In: rdi = conn. Clobbers rax, rcx, rdx, rsi, rdi, r8-r11. Keeps the rest.
; -----------------------------------------------------------------------------
global ha_set_interest:function hidden (ha_set_interest.end - ha_set_interest)
align 16
ha_set_interest:
    mov     rax, [rdi + conn.worker]
    cmp     dword [rax + worker.uring], 0
    jne     ha_uring_pending                ; a tail call: it keeps to this contract
    sub     rsp, 24                         ; struct epoll_event (12) + alignment
    mov     ecx, [rdi + conn.flags]
    test    ecx, C_ZOMBIE | C_CLOSED
    jnz     .done
    call    ha_interest_mask                ; esi = the events (rsp is aligned: 8 + 24)
.events_set:
    cmp     esi, [rdi + conn.pad]           ; conn.pad holds the events epoll has now
    je      .done
    mov     [rdi + conn.pad], esi
    mov     [rsp], esi
    mov     [rsp + 4], rdi                  ; the event's data: the connection
    mov     rax, [rdi + conn.worker]
    mov     edx, [rdi + conn.fd]
    mov     edi, [rax + worker.epfd]
    mov     esi, EPOLL_CTL_MOD
    mov     r10, rsp
    mov     eax, SYS_epoll_ctl
    syscall
.done:
    add     rsp, 24
    ret
.end:

; -----------------------------------------------------------------------------
; ha_lru_touch: a new window: the connection's deadline becomes now + the idle timeout, its
; progress starts over from 0 (ha_conn_expire judges the window by it), and it moves to the
; worker's list's tail (the list stays ordered by deadline: every touch uses the same timeout).
;   In: rdi = conn. Clobbers rax, rcx, rdx, rsi.
; -----------------------------------------------------------------------------
global ha_lru_touch:function hidden (ha_lru_touch.end - ha_lru_touch)
align 16
ha_lru_touch:
    mov     rsi, [rdi + conn.worker]
    mov     rax, [rsi + worker.server]
    mov     rax, [rax + server.idle_ms]
    add     rax, [rsi + worker.now_ms]
    mov     [rdi + conn.deadline], rax
    mov     qword [rdi + conn.progress], 0
    call    lru_unlink
    mov     rax, [rsi + worker.lru_tail]    ; append
    mov     [rdi + conn.lru_prev], rax
    mov     qword [rdi + conn.lru_next], 0
    test    rax, rax
    jz      .first
    mov     [rax + conn.lru_next], rdi
    jmp     .tail
.first:
    mov     [rsi + worker.lru_head], rdi
.tail:
    mov     [rsi + worker.lru_tail], rdi
    ret
.end:

; lru_unlink: takes rdi (conn) out of rsi's (worker) list, if it is in it. Clobbers rax, rcx.
align 16
lru_unlink:
    mov     rax, [rdi + conn.lru_prev]
    mov     rcx, [rdi + conn.lru_next]
    test    rax, rax
    jz      .no_prev
    mov     [rax + conn.lru_next], rcx
    jmp     .prev_done
.no_prev:
    cmp     [rsi + worker.lru_head], rdi
    jne     .prev_done                      ; not in the list at all
    mov     [rsi + worker.lru_head], rcx
.prev_done:
    test    rcx, rcx
    jz      .no_next
    mov     [rcx + conn.lru_prev], rax
    jmp     .next_done
.no_next:
    cmp     [rsi + worker.lru_tail], rdi
    jne     .next_done
    mov     [rsi + worker.lru_tail], rax
.next_done:
    mov     qword [rdi + conn.lru_prev], 0
    mov     qword [rdi + conn.lru_next], 0
    ret

; -----------------------------------------------------------------------------
; ha_conn_expire: the connection's window ended (its deadline passed); this judges it. The idle
; timeout is a window, not a limit on how long a transfer may take:
;   - lingering after a closing response (C_DRAINING): the linger is over, close;
;   - a deferred exchange holds the connection: a new window (the handler decides);
;   - nothing in progress is idleness, and closes. That means no output waiting, and HTTP/1.1
;     between requests or within a head, or HTTP/2 with no active stream. Octets do not matter
;     here: a head's trickle (slowloris) and HTTP/2's control frames (PING) are not progress;
;   - a transfer in progress (output waiting, an HTTP/1.1 body arriving, an HTTP/2 stream
;     active) gets a new window when it moved at least min_rate octets a second over the window
;     that ended: conn.progress x 1000 >= idle_ms x min_rate. Below that it closes (RUDY, slow
;     reads). At or above it, a transfer outlives any number of windows (RFC9112-9.5-4);
;   - an HTTP/2 connection that is kept has every stream judged on its own (ha_h2_sweep
;     answers 408 or resets the stuck ones), so other streams' traffic cannot hide one.
;   The verdict is reached before the streams are judged: the sweep may queue a 408, and an
;   answer queued starts a new window (ha_h2_respond touches), zeroing the progress the verdict
;   needs. Only a connection that is kept is swept; one that closes takes its streams with it.
;   In: rdi = conn (its deadline passed). Out: eax = 1 when it gets a new window (ha_lru_touch:
;   a future deadline, the list's tail), 0 when the caller should close it.
;   Clobbers every caller-saved register. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global ha_conn_expire:function hidden (ha_conn_expire.end - ha_conn_expire)
align 16
ha_conn_expire:
    push    rbx                             ; also aligns rsp for the calls below
    mov     rbx, rdi
    test    dword [rbx + conn.flags], C_DRAINING
    jnz     .close
    cmp     dword [rbx + conn.deferred], 0
    jne     .keep
    mov     rax, [rbx + conn.wlen]
    cmp     rax, [rbx + conn.wsent]
    jne     .transfer                       ; output waiting: its pace decides
    mov     rax, [rbx + conn.h2]
    test    rax, rax
    jz      .http1
    cmp     dword [rax + h2.stream_count], 0
    jne     .transfer
    jmp     .close                          ; HTTP/2 with no active stream: idle
.http1:
    mov     ecx, [rbx + conn.state]
    sub     ecx, CS_BODY_LENGTH
    cmp     ecx, CS_TRAILERS - CS_BODY_LENGTH
    ja      .close                          ; between requests, or within a head
.transfer:
    mov     rsi, [rbx + conn.worker]
    mov     rsi, [rsi + worker.server]
    mov     eax, [rsi + server.min_rate]
    imul    rax, [rsi + server.idle_ms]     ; what the window needed, in thousandths of octets
    imul    rcx, [rbx + conn.progress], 1000
    cmp     rcx, rax
    jb      .close
.keep:
%ifndef HTTPASM_H1_ONLY
    cmp     qword [rbx + conn.h2], 0
    je      .new_window
    mov     rdi, rbx
    call    ha_h2_sweep                     ; each stream on its own, now the verdict is in
    mov     rax, [rbx + conn.h2]
    test    dword [rax + h2.flags], H2F_CLOSING
    jnz     .close                          ; a connection error meanwhile: it is ending anyway
.new_window:
%endif
    mov     rdi, rbx
    call    ha_lru_touch
    mov     eax, 1
    pop     rbx
    ret
.close:
    xor     eax, eax
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_conn_close: closes a connection's descriptor. Its memory is not freed here:
;   - With an exchange still deferred (conn.deferred above 0), the memory must outlive the
;     descriptor (the handler's code holds the exchange, and another thread reads the request
;     and the connection's worker when it answers): the connection becomes a zombie, released
;     by the worker when the last deferred answer arrives (ha_conn_release).
;   - An HTTP/2 connection says GOAWAY first (ha_h2_goodbye: NO_ERROR and the last stream the
;     peer opened, one best-effort send, unless an error's GOAWAY went out already); then its
;     state is freed here in either case (ha_h2_free); its deferred streams are detached, each
;     freed when its answer arrives.
;   - Otherwise it goes on the worker's closed list, freed by ha_conn_reap once the current
;     event batch is done: an event later in the same batch (epoll_wait's events, io_uring's
;     completions) may still carry this connection's pointer (handle_completions or close_idle
;     can close a connection whose own event comes after theirs), and that event must find
;     valid memory marked closed, not a freed block.
;   Closing twice is harmless (the second call sees C_CLOSED or C_ZOMBIE and returns).
;   In: rdi = conn. Clobbers every caller-saved register. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global ha_conn_close:function hidden (ha_conn_close.end - ha_conn_close)
align 16
ha_conn_close:
    push    rbx
    mov     rbx, rdi
    test    dword [rbx + conn.flags], C_ZOMBIE | C_CLOSED
    jnz     .out                            ; already closed
    mov     rsi, [rbx + conn.worker]
    mov     rdi, rbx
    call    lru_unlink
    mov     rsi, [rbx + conn.worker]
    dec     qword [rsi + worker.conn_count]
    ; HTTP/2: a GOAWAY before the close (RFC 9113 6.8), whoever closes and why: the idle
    ; timeout, a stop, the end of a stop's grace, the peer's own end. A connection error
    ; wrote and flushed its GOAWAY already, and then this sends nothing.
    mov     rdi, rbx
    call    ha_h2_goodbye                   ; nothing for HTTP/1.1 (conn.h2 = 0)
    mov     edi, [rbx + conn.fd]
    mov     eax, SYS_close                  ; under epoll, the close removes it from the interest list
    syscall
    mov     dword [rbx + conn.fd], -1
    ; io_uring: the connection's poll, armed in the kernel, holds the socket and is not ended by
    ; the close: the next submission removes it (uring.asm sees C_CLOSED or C_ZOMBIE by then),
    ; and the memory waits for its last operation's completion (conn.uops, ha_conn_reap).
    mov     rax, [rbx + conn.worker]
    cmp     dword [rax + worker.uring], 0
    je      .no_ring
    mov     rdi, rbx
    call    ha_uring_pending
.no_ring:
    cmp     qword [rbx + conn.h2], 0
    je      .state_freed
    mov     rdi, rbx                        ; HTTP/2: its streams go; deferred ones are detached
    call    ha_h2_free                      ; and wait for their answers
.state_freed:
    cmp     dword [rbx + conn.deferred], 0  ; a handler still holds an exchange: the memory stays
    je      .closed
    or      dword [rbx + conn.flags], C_ZOMBIE
    mov     rsi, [rbx + conn.worker]
    inc     qword [rsi + worker.zombies]
    jmp     .out
.closed:
    mov     rdi, rbx
    call    ha_conn_release
.out:
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_conn_release: puts a connection whose descriptor is closed on its worker's closed list
; (C_CLOSED), for ha_conn_reap to free after the event batch. Used by ha_conn_close, and for a
; zombie once its deferred response arrived (nothing else will reference it then).
;   In: rdi = conn (out of the deadline list already). Clobbers rax, rsi.
; -----------------------------------------------------------------------------
global ha_conn_release:function hidden (ha_conn_release.end - ha_conn_release)
align 16
ha_conn_release:
    or      dword [rdi + conn.flags], C_CLOSED
    mov     rsi, [rdi + conn.worker]
    mov     rax, [rsi + worker.closed]      ; the list reuses lru_next: the connection left the
    mov     [rdi + conn.lru_next], rax      ; deadline list when it closed
    mov     [rsi + worker.closed], rdi
    ret
.end:

; -----------------------------------------------------------------------------
; ha_conn_reap: frees every connection on the worker's closed list. Called by the worker
; between event batches only, when no event can name them any more. Under io_uring a
; connection that an operation still names (conn.uops: its poll's removal not completed yet,
; or the pending list) stays on the list for a later reap: that completion arrives in a later
; batch and reads the memory. Counts kept for an earlier ring (the worker stopped and started
; again, or now runs on epoll) mean nothing any more: such a connection is freed.
;   In: rdi = worker. Clobbers every caller-saved register. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global ha_conn_reap:function hidden (ha_conn_reap.end - ha_conn_reap)
align 16
ha_conn_reap:
    push    rbx
    push    r12
    push    r13                             ; three pushes: aligned for the calls below
    mov     r12, rdi
    xor     r13d, r13d                      ; the connections kept for a later reap
.next:
    mov     rbx, [r12 + worker.closed]
    test    rbx, rbx
    jz      .done
    mov     rax, [rbx + conn.lru_next]
    mov     [r12 + worker.closed], rax
    cmp     dword [r12 + worker.uring], 0
    je      .free
    mov     eax, [rbx + conn.ring_gen]
    cmp     eax, [r12 + worker.ring_gen]
    jne     .free                           ; counted for a ring that is gone
    cmp     dword [rbx + conn.uops], 0
    je      .free
    mov     [rbx + conn.lru_next], r13      ; still named by the ring: kept
    mov     r13, rbx
    jmp     .next
.free:
    mov     rdi, rbx
    call    ha_conn_free
    jmp     .next
.done:
    mov     [r12 + worker.closed], r13
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; ha_conn_free: frees a closed connection's memory. In: rdi = conn. Keeps rbx, rbp, r12-r15.
global ha_conn_free:function hidden (ha_conn_free.end - ha_conn_free)
align 16
ha_conn_free:
    push    rbx
    mov     rbx, rdi
    mov     rdi, [rbx + conn.rbuf]
    call    free wrt ..plt
    mov     rdi, [rbx + conn.wbuf]
    call    free wrt ..plt
    mov     rdi, [rbx + conn.fields]
    call    free wrt ..plt
    mov     rdi, rbx
    call    free wrt ..plt
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_conn_flush: sends what the output buffer holds, until done or the socket is full.
;   Under io_uring it only hands the output to the next submission (C_SEND_QUEUED; see .queue)
;   and returns 0; with nothing left to send it does the same work under both backends.
;   In: rdi = conn. Out: eax = 0 (still open), 1 (closed: a send failed, or the last answer
;   went out after the peer's end).
;   When everything is sent after a closing response, the connection half-closes (FIN) and
;   reads and discards until the peer closes or the linger ends (RFC 9112 9.6: closing at once
;   could turn the unread request bytes into a reset that destroys the response in flight).
;   When the peer's end was already read (C_PEER_DONE), no request byte can be left unread, so
;   it closes at once instead.
;   Clobbers every caller-saved register. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global ha_conn_flush:function hidden (ha_conn_flush.end - ha_conn_flush)
align 16
ha_conn_flush:
    push    rbx
    mov     rbx, rdi
.send:
    mov     rdx, [rbx + conn.wlen]
    mov     rsi, [rbx + conn.wsent]
    sub     rdx, rsi
    jz      .sent
    mov     rax, [rbx + conn.worker]
    cmp     dword [rax + worker.uring], 0
    jne     .queue
    add     rsi, [rbx + conn.wbuf]
    mov     edi, [rbx + conn.fd]
    mov     r10d, MSG_NOSIGNAL              ; a closed peer is an error code, not a SIGPIPE
    xor     r8d, r8d
    xor     r9d, r9d
    mov     eax, SYS_sendto
    syscall
    test    rax, rax
    js      .send_error
    add     [rbx + conn.wsent], rax
    add     [rbx + conn.progress], rax      ; octets that left: a transfer's progress
    jmp     .send
.send_error:
    cmp     rax, -EINTR
    je      .send
    cmp     rax, -EAGAIN
    jne     .failed
    or      dword [rbx + conn.flags], C_WANT_WRITE
    mov     rdi, rbx
    call    ha_set_interest
    xor     eax, eax
    jmp     .out
.sent:
    xor     eax, eax
    mov     [rbx + conn.wlen], rax
    mov     [rbx + conn.wsent], rax
    and     dword [rbx + conn.flags], ~C_WANT_WRITE
    test    dword [rbx + conn.flags], C_CLOSE_AFTER
    jz      .interest
    test    dword [rbx + conn.flags], C_PEER_DONE
    jnz     .failed                         ; nothing left to drain: close now
    and     dword [rbx + conn.flags], ~C_CLOSE_AFTER
    or      dword [rbx + conn.flags], C_DRAINING
    mov     edi, [rbx + conn.fd]
    mov     esi, SHUT_WR
    mov     eax, SYS_shutdown
    syscall
    ; The linger: the deadline moves up to now + HA_LINGER_MS (the list may hold it a little
    ; longer than that, behind older deadlines; the peer's close usually comes first).
    mov     rsi, [rbx + conn.worker]
    mov     rax, [rsi + worker.now_ms]
    add     rax, HA_LINGER_MS
    mov     [rbx + conn.deadline], rax
.interest:
    mov     rdi, rbx
    call    ha_set_interest
    xor     eax, eax
    jmp     .out
.queue:
    ; io_uring: the output goes with the next submission, one SEND for all of it then; its
    ; completion (uring.asm, ha_uring_conn) does the rest of this function's work, calling it
    ; again once nothing is left. Until then the connection counts as writing (C_SEND_QUEUED).
    or      dword [rbx + conn.flags], C_SEND_QUEUED
    mov     rdi, rbx
    call    ha_uring_pending
    xor     eax, eax
    jmp     .out
.failed:
    mov     rdi, rbx
    call    ha_conn_close
    mov     eax, 1
.out:
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; output_reserve: makes room for rsi more octets after the output's end.
;   In: rdi = conn, rsi = octets. Out: eax = 0, or -ENOMEM. Sent octets at the front are
;   dropped first; the buffer doubles (or more) only when that is not enough.
;   Clobbers every caller-saved register. Keeps rbx, rbp, r12-r15.
;   Also ha_output_reserve, for h2.asm. Any pointer into the output is stale afterwards (the
;   octets may move, or the buffer): callers reserve a whole frame first, then write it.
; -----------------------------------------------------------------------------
global ha_output_reserve:function hidden
align 16
ha_output_reserve:
output_reserve:
    push    rbx
    push    r12
    push    r13
    mov     rbx, rdi
    mov     r12, rsi
    mov     rax, [rbx + conn.wcap]
    sub     rax, [rbx + conn.wlen]
    cmp     rax, r12
    jae     .ok
    mov     rdx, [rbx + conn.wsent]         ; drop what was sent
    test    rdx, rdx
    jz      .grow
    mov     rdi, [rbx + conn.wbuf]
    lea     rsi, [rdi + rdx]
    mov     rcx, [rbx + conn.wlen]
    sub     rcx, rdx
    rep     movsb
    mov     rax, [rbx + conn.wlen]
    sub     rax, [rbx + conn.wsent]
    mov     [rbx + conn.wlen], rax
    mov     qword [rbx + conn.wsent], 0
    mov     rax, [rbx + conn.wcap]
    sub     rax, [rbx + conn.wlen]
    cmp     rax, r12
    jae     .ok
.grow:
    mov     r13, [rbx + conn.wcap]
    shl     r13, 1
    mov     rax, [rbx + conn.wlen]
    add     rax, r12
    cmp     r13, rax
    cmovb   r13, rax                        ; at least what is needed
    mov     rdi, [rbx + conn.wbuf]
    mov     rsi, r13
    call    realloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     [rbx + conn.wbuf], rax
    mov     [rbx + conn.wcap], r13
.ok:
    xor     eax, eax
    jmp     .out
.no_memory:
    mov     eax, -ENOMEM
.out:
    pop     r13
    pop     r12
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; input_reserve: makes the input buffer hold at least rsi octets in all, moving the request's
; pointers if realloc moved the buffer.
;   In: rdi = conn, rsi = the capacity needed. Out: eax = 0, or -ENOMEM.
;   Clobbers every caller-saved register. Keeps rbx, rbp, r12-r15.
;   Also ha_input_reserve, for h2.asm (whose frames keep no pointer into the input: the
;   rebase finds nothing to move for an HTTP/2 connection, whose conn.state stays CS_HEAD).
; -----------------------------------------------------------------------------
global ha_input_reserve:function hidden
align 16
ha_input_reserve:
input_reserve:
    push    rbx
    push    r12
    push    r13
    mov     rbx, rdi
    mov     r12, rsi
    cmp     r12, [rbx + conn.rcap]
    jbe     .ok
    mov     r13, [rbx + conn.rcap]
    shl     r13, 1
    cmp     r13, r12
    cmovb   r13, r12
    mov     rdi, [rbx + conn.rbuf]
    mov     rsi, r13
    call    realloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     rsi, rax
    sub     rsi, [rbx + conn.rbuf]          ; how far the buffer moved
    mov     [rbx + conn.rbuf], rax
    mov     [rbx + conn.rcap], r13
    test    rsi, rsi
    jz      .ok
    mov     rdi, rbx
    call    conn_rebase
.ok:
    xor     eax, eax
    jmp     .out
.no_memory:
    mov     eax, -ENOMEM
.out:
    pop     r13
    pop     r12
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; conn_rebase: moves every pointer of the current request into the input buffer by rsi octets:
; the request's method, target, authority and scheme, and each header and trailer field's name
; and value. Only a parsed head has such pointers (state past CS_HEAD).
;   In: rdi = conn, rsi = the distance. Clobbers rax, rcx, rdx, r8.
; -----------------------------------------------------------------------------
align 16
conn_rebase:
    cmp     dword [rdi + conn.state], CS_HEAD
    je      .done
    lea     r8, [rdi + conn.request]
%macro REBASE 1
    cmp     qword [r8 + %1], 0
    je      %%skip
    add     [r8 + %1], rsi
%%skip:
%endmacro
    REBASE  httpasm_request.method
    REBASE  httpasm_request.target
    REBASE  httpasm_request.authority
    REBASE  httpasm_request.scheme
    mov     ecx, [r8 + httpasm_request.field_count]
    add     ecx, [rdi + conn.exchange + exchange.trailer_count]
    mov     rdx, [rdi + conn.fields]
.field:
    test    ecx, ecx
    jz      .done
    add     [rdx + httpasm_field.name], rsi
    add     [rdx + httpasm_field.value], rsi
    add     rdx, httpasm_field_size
    dec     ecx
    jmp     .field
.done:
    ret

; -----------------------------------------------------------------------------
; ha_conn_respond: appends a response to the connection's output.
;   In: rdi = conn, esi = status, rdx = fields, ecx = count, r8 = body, r9 = its length,
;   [rsp + 8] = 1 to close the connection after this response, 0 otherwise.
;   The request's version and method (the current one, or HTTP/1.1 GET when the head could not
;   be parsed) decide the framing. Date is the worker's cached value. A connection that does not
;   persist (RFC 9112 9.3) is closed after the response, which says so.
;   Out: eax = 0, -HTTPASM_ERROR_* (the writer refused the fields; nothing was written), or
;   -ENOMEM. Clobbers every caller-saved register. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global ha_conn_respond:function hidden (ha_conn_respond.end - ha_conn_respond)
align 16
ha_conn_respond:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, httpasm_response_size + 8  ; the response record; 6 pushes + 56 keep alignment
    mov     rbx, rdi
    mov     r12, r8                         ; body
    mov     r13, r9                         ; its length
    mov     r14d, [rsp + httpasm_response_size + 8 + 6 * 8 + 8]   ; the close argument
    mov     [rsp + httpasm_response.fields], rdx
    mov     [rsp + httpasm_response.field_count], ecx
    mov     [rsp + httpasm_response.status], si
    mov     [rsp + httpasm_response.content_length], r9
    mov     rax, [rbx + conn.worker]
    lea     rax, [rax + worker.date]
    mov     [rsp + httpasm_response.date], rax
    xor     eax, eax
    mov     [rsp + httpasm_response.reserved], eax
    mov     [rsp + httpasm_response.reserved2], rax
    ; The request's version and method; an unparsed head answers as HTTP/1.1.
    movzx   eax, byte [rbx + conn.request + httpasm_request.version]
    mov     ecx, 11
    test    eax, eax
    cmovz   eax, ecx
    mov     [rsp + httpasm_response.request_version], al
    movzx   eax, word [rbx + conn.request + httpasm_request.method_id]
    mov     [rsp + httpasm_response.request_method], al
    mov     eax, HTTPASM_RESPONSE_LENGTH
    test    r14d, r14d
    jnz     .closing
    test    dword [rbx + conn.request + httpasm_request.flags], HTTPASM_REQUEST_KEEP_ALIVE
    jnz     .flags_set
.closing:
    or      eax, HTTPASM_RESPONSE_CLOSE
.flags_set:
    mov     [rsp + httpasm_response.flags], eax

    ; The head, into the output; on 0 (no room), make room and try again.
    mov     r15d, 512
.write_head:
    mov     rdi, rbx
    mov     rsi, r15
    call    output_reserve
    test    eax, eax
    jnz     .out
    mov     rdi, [rbx + conn.wbuf]
    add     rdi, [rbx + conn.wlen]
    mov     rsi, [rbx + conn.wcap]
    sub     rsi, [rbx + conn.wlen]
    mov     rdx, rsp
    call    httpasm_h1_write_response
    test    rax, rax
    js      .out                            ; refused: eax = -HTTPASM_ERROR_*
    jnz     .head_written
    shl     r15, 1                          ; the head did not fit: twice the room
    jmp     .write_head
.head_written:
    add     [rbx + conn.wlen], rax
    test    dword [rsp + httpasm_response.flags], HTTPASM_RESPONSE_CLOSE
    jz      .body
    or      dword [rbx + conn.flags], C_CLOSE_AFTER
.body:
    test    dword [rsp + httpasm_response.flags], HTTPASM_RESPONSE_NO_BODY
    jnz     .done
    test    r13, r13
    jz      .done
    mov     rdi, rbx
    mov     rsi, r13
    call    output_reserve
    test    eax, eax
    jnz     .out
    mov     rdi, [rbx + conn.wbuf]
    add     rdi, [rbx + conn.wlen]
    mov     rsi, r12
    mov     rcx, r13
    rep     movsb
    add     [rbx + conn.wlen], r13
.done:
    xor     eax, eax
.out:
    add     rsp, httpasm_response_size + 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_conn_append: appends rsi[0..rdx) to the connection's output (a response another thread
; serialized for a deferred exchange).
;   In: rdi = conn, rsi = octets, rdx = their count. Out: eax = 0, or -ENOMEM.
;   Clobbers every caller-saved register. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global ha_conn_append:function hidden (ha_conn_append.end - ha_conn_append)
align 16
ha_conn_append:
    push    rbx
    push    r12
    push    r13
    mov     rbx, rdi
    mov     r12, rsi
    mov     r13, rdx
    mov     rsi, rdx
    call    output_reserve
    test    eax, eax
    jnz     .out
    mov     rdi, [rbx + conn.wbuf]
    add     rdi, [rbx + conn.wlen]
    mov     rsi, r12
    mov     rcx, r13
    rep     movsb
    add     [rbx + conn.wlen], r13
    xor     eax, eax
.out:
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; error_response: answers the server's own refusal (400, 413, 414, 417, 431, 501, 505, the
; 500 for a handler that did not answer) with status esi, and closes after it. Its body is a
; one-line explanation as text/plain (RFC9110-15.5-1#1, 15.6-1#1: a 4xx or 5xx explains
; itself): the status's reason phrase, or for 505 the versions this server speaks
; (RFC9110-15.6.6-1). A HEAD request's answer drops the body, as the writer does for every
; HEAD; a status with no registered phrase goes out empty.
;   In: rdi = conn, esi = status. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
E_CLOSE     equ 0       ; the close argument (the 7th), at [rsp] when ha_conn_respond is called
E_FIELD     equ 8       ; httpasm_field: Content-Type: text/plain (32)
E_CONN      equ 40
E_STATUS    equ 48
E_FRAME     equ 56      ; entered at 8 past 16: 56 more leaves rsp aligned for the calls

align 16
error_response:
    sub     rsp, E_FRAME
    mov     [rsp + E_CONN], rdi
    mov     [rsp + E_STATUS], esi
    cmp     esi, 505
    je      .version
    mov     edi, esi
    call    ha_status_reason                ; rax = the phrase, edx = its length (0: none)
    mov     r8, rax
    mov     r9d, edx                        ; zero-extended into r9
    xor     ecx, ecx                        ; no Content-Type without content
    test    edx, edx
    jz      .respond
    jmp     .typed
.version:
    lea     r8, [rel s_505_body]
    mov     r9d, s_505_body_len
.typed:
    lea     rax, [rel s_content_type]
    mov     [rsp + E_FIELD + httpasm_field.name], rax
    lea     rax, [rel s_text_plain]
    mov     [rsp + E_FIELD + httpasm_field.value], rax
    mov     dword [rsp + E_FIELD + httpasm_field.name_length], 12
    mov     dword [rsp + E_FIELD + httpasm_field.value_length], 10
    mov     dword [rsp + E_FIELD + httpasm_field.id], 0     ; id and flags: none
    mov     dword [rsp + E_FIELD + httpasm_field.reserved], 0
    mov     ecx, 1
.respond:
    lea     rdx, [rsp + E_FIELD]
    mov     rdi, [rsp + E_CONN]
    mov     esi, [rsp + E_STATUS]
    mov     qword [rsp + E_CLOSE], 1
    call    ha_conn_respond
    add     rsp, E_FRAME
    ret

; -----------------------------------------------------------------------------
; send_continue: 100 Continue, once per request, when the client expects it and its body has
; not all arrived (RFC 9110 10.1.1; HTTP/1.0 never gets a 1xx: RFC9110-15.2-1). In: rdi = conn.
; Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
send_continue:
    push    rbx
    mov     rbx, rdi
    test    dword [rbx + conn.request + httpasm_request.flags], HTTPASM_REQUEST_EXPECT_CONTINUE
    jz      .out
    test    dword [rbx + conn.flags], C_CONTINUE_SENT
    jnz     .out
    cmp     byte [rbx + conn.request + httpasm_request.version], 11
    jb      .out
    or      dword [rbx + conn.flags], C_CONTINUE_SENT
    mov     rdi, rbx
    mov     esi, s_continue_len
    call    output_reserve
    test    eax, eax
    jnz     .out
    mov     rdi, [rbx + conn.wbuf]
    add     rdi, [rbx + conn.wlen]
    lea     rsi, [rel s_continue]
    mov     ecx, s_continue_len
    rep     movsb
    add     qword [rbx + conn.wlen], s_continue_len
.out:
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; ha_conn_drive: answers what the input holds and sends it. Process, flush, and again while
; the processing stopped only for back-pressure and the flush emptied the output: pipelined
; requests held back that way are already read, so no event would ever bring them back. Once
; the peer's end was seen (C_PEER_DONE) and no complete request is left, nothing more can come:
; the connection closes after its last answer (an incomplete message is dropped, RFC9112-6.3-2.6).
;   In: rdi = conn (open: neither closed nor a zombie). Clobbers every caller-saved register.
;   Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global ha_conn_drive:function hidden (ha_conn_drive.end - ha_conn_drive)
align 16
ha_conn_drive:
    push    rbx
    push    r12
    sub     rsp, 8                          ; two pushes + 8: aligned for the calls below
    mov     rbx, rdi
.again:
    mov     rdi, rbx
    call    ha_conn_process
    mov     r12d, eax                       ; 1: stopped for back-pressure, requests wait
    test    r12d, r12d
    jnz     .flush
    mov     eax, [rbx + conn.flags]
    test    eax, C_PEER_DONE
    jz      .flush
    test    eax, C_DEFERRED | C_DRAINING
    jnz     .flush                          ; the deferred answer comes first; draining closes anyway
    or      dword [rbx + conn.flags], C_CLOSE_AFTER
.flush:
    mov     rdi, rbx
    call    ha_conn_flush
    test    eax, eax
    jnz     .out                            ; closed
    test    r12d, r12d
    jz      .out                            ; it needs input, waits for an answer, or closes
    test    dword [rbx + conn.flags], C_WANT_WRITE | C_SEND_QUEUED
    jnz     .out                            ; the socket is full (EPOLLOUT resumes it), or the
                                            ; output is with io_uring (its SEND's completion does)
    jmp     .again
.out:
    add     rsp, 8
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_conn_process: everything the input holds, until it needs more bytes, waits for a deferred
; exchange, must close, or has more output waiting than HA_OUTPUT_HIGH.
;   In: rdi = conn (not a zombie). Out: eax = 1 when it stopped for back-pressure (complete
;   requests may wait in the input: process again once the output drained), 0 otherwise.
;   Clobbers every caller-saved register. Keeps rbx, rbp, r12-r15. May close the connection
;   only through a closing response (C_CLOSE_AFTER): the caller flushes, and the flush closes.
;   Callers use ha_conn_drive, which handles both.
; -----------------------------------------------------------------------------
; The frame: [rsp] the chunked decoder's produced count, [rsp + 8] the trailer count, [rsp + 16]
; a limits record (16), then:
P_NO_ROOM       equ 32      ; 1 while the trailers parse into P_SPARE_FIELD (the array is full)
P_SPARE_FIELD   equ 40      ; one httpasm_field (32): a trailer section's destination when the
                            ; array has no room left (.trailers says why)
P_FRAME         equ 72      ; six pushes + 72 + the return address: rsp 16-byte aligned for calls

global ha_conn_process:function hidden (ha_conn_process.end - ha_conn_process)
align 16
ha_conn_process:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, P_FRAME
    mov     rbx, rdi
    mov     r12, [rbx + conn.worker]
    mov     r13, [r12 + worker.server]

.loop:
    test    dword [rbx + conn.flags], C_DEFERRED | C_CLOSE_AFTER | C_DRAINING | C_ZOMBIE
    jnz     .out
    mov     rax, [rbx + conn.wlen]
    sub     rax, [rbx + conn.wsent]
    cmp     rax, HA_OUTPUT_HIGH
    ja      .pressure                       ; back-pressure: answer more only after a flush
%ifndef HTTPASM_H1_ONLY                     ; the isolation measurement's control assembles HTTP/2 out
    cmp     dword [rbx + conn.proto], HA_PROTO_H2
    je      .h2
%endif
    mov     eax, [rbx + conn.state]
    cmp     eax, CS_HEAD
    je      .head
    cmp     eax, CS_BODY_LENGTH
    je      .body_length
    cmp     eax, CS_BODY_CHUNKED
    je      .body_chunked
    cmp     eax, CS_TRAILERS
    je      .trailers
    jmp     .ready

.head:
    cmp     qword [rbx + conn.rlen], 0
    je      .out
%ifdef HTTPASM_H1_ONLY
    mov     dword [rbx + conn.proto], HA_PROTO_H1
    jmp     .parse_head
%endif
    cmp     dword [rbx + conn.proto], HA_PROTO_UNKNOWN
    jne     .parse_head
    ; The connection's first octets decide its protocol, once: HTTP/2's preface (h2c with prior
    ; knowledge, RFC 9113 3.3), or anything else as HTTP/1.1. A preface whose first line came
    ; whole but whose end is wrong is an HTTP/2 client's connection error (RFC9113-3.4-9): the
    ; connection closes without a GOAWAY (allowed: the peer is not speaking HTTP/2 after all)
    ; rather than get HTTP/1.1's 505 for a request it never meant to send.
    mov     rdi, rbx
    call    ha_h2_detect
    test    eax, eax
    js      .out                            ; a prefix of the preface: wait for more
    jz      .is_h1
    cmp     eax, 2
    je      .not_http                       ; an invalid preface: close, nothing said
    mov     rdi, rbx
    call    ha_h2_start
    test    eax, eax
    jnz     .no_memory
    mov     dword [rbx + conn.proto], HA_PROTO_H2
    jmp     .h2
.is_h1:
    mov     dword [rbx + conn.proto], HA_PROTO_H1
.parse_head:
    mov     rdi, [rbx + conn.rbuf]
    mov     rsi, [rbx + conn.rlen]
    lea     rdx, [rbx + conn.scan_from]
    lea     rcx, [r13 + server.limits]
    lea     r8, [rbx + conn.request]
    mov     r9, [rbx + conn.fields]
    call    httpasm_h1_parse_request
    test    rax, rax
    jz      .need_more
    js      .head_refused
    or      dword [rbx + conn.flags], C_SPOKE
    mov     [rbx + conn.head_length], rax
    xor     ecx, ecx
    mov     [rbx + conn.exchange + exchange.state], ecx
    mov     [rbx + conn.exchange + exchange.trailer_count], ecx
    and     dword [rbx + conn.flags], ~C_CONTINUE_SENT
    mov     edx, [rbx + conn.request + httpasm_request.flags]
    test    edx, HTTPASM_REQUEST_CHUNKED
    jnz     .start_chunked
    test    edx, HTTPASM_REQUEST_CONTENT_LENGTH
    jnz     .start_length
    mov     [rbx + conn.body_end], rax      ; no body
    mov     [rbx + conn.message_end], rax
    mov     dword [rbx + conn.state], CS_READY
    jmp     .loop
.start_length:
    mov     rcx, [rbx + conn.request + httpasm_request.content_length]
    cmp     rcx, [r13 + server.max_body]
    ja      .too_large
    add     rcx, rax
    mov     [rbx + conn.body_end], rcx
    mov     dword [rbx + conn.state], CS_BODY_LENGTH
    jmp     .body_window
.start_chunked:
    mov     [rbx + conn.body_end], rax
    pxor    xmm0, xmm0
    movdqu  [rbx + conn.chunked], xmm0
    movdqu  [rbx + conn.chunked + 16], xmm0
    mov     dword [rbx + conn.state], CS_BODY_CHUNKED
.body_window:
    ; The head is whole: its body gets a window of its own (ha_lru_touch), so a body that
    ; starts late in the head's window is judged on its own pace (ha_conn_expire), not on
    ; whatever was left of the head's.
    mov     rdi, rbx
    call    ha_lru_touch
    jmp     .loop
.head_refused:
    neg     rax                             ; the status to answer
    ; A connection's first message whose request-line is broken and carries no HTTP-version is
    ; not an HTTP/1.x request at all (an HTTP/2 client's invalid preface, another protocol).
    ; RFC 9112 2.2's 400 is for what "appears from the start-line to be an HTTP request
    ; message" (RFC9112-2.2-9); with no protocol to answer in, the connection just closes
    ; (h2spec 3.5/2 expects exactly that of an HTTP/2 server).
    test    dword [rbx + conn.flags], C_SPOKE
    jnz     .answer_refusal
    movzx   ecx, word [rbx + conn.request + httpasm_request.error]
    cmp     ecx, HTTPASM_ERROR_METHOD
    je      .is_it_http
    cmp     ecx, HTTPASM_ERROR_REQUEST_LINE
    je      .is_it_http
    cmp     ecx, HTTPASM_ERROR_TARGET
    je      .is_it_http
    cmp     ecx, HTTPASM_ERROR_TARGET_FORM
    je      .is_it_http
    cmp     ecx, HTTPASM_ERROR_VERSION
    jne     .answer_refusal
.is_it_http:
    ; "HTTP/" before the first line's end (or the first 8 KiB) says it is.
    mov     rsi, [rbx + conn.rbuf]
    mov     rcx, [rbx + conn.rlen]
    mov     edx, 8192
    cmp     rcx, rdx
    cmova   rcx, rdx
    sub     rcx, 4                          ; the last place "HTTP/" can start
    jbe     .not_http
    xor     edx, edx
.empty_line:
    cmp     rdx, rcx                        ; the empty lines the parser skips (RFC 9112 2.2)
    jae     .not_http
    cmp     word [rsi + rdx], 0x0A0D
    jne     .scan
    add     rdx, 2
    jmp     .empty_line
.scan:
    cmp     byte [rsi + rdx], 10
    je      .not_http
    cmp     dword [rsi + rdx], 'HTTP'
    jne     .scan_next
    cmp     byte [rsi + rdx + 4], '/'
    je      .answer_refusal
.scan_next:
    inc     rdx
    cmp     rdx, rcx
    jb      .scan
.not_http:
    or      dword [rbx + conn.flags], C_CLOSE_AFTER
    jmp     .out
.answer_refusal:
    mov     rdi, rbx
    mov     esi, eax
    call    error_response
    jmp     .out

.body_length:
    mov     rax, [rbx + conn.body_end]
    cmp     [rbx + conn.rlen], rax
    jb      .length_short
    mov     [rbx + conn.message_end], rax
    mov     dword [rbx + conn.state], CS_READY
    jmp     .loop
.length_short:
    mov     rdi, rbx
    call    send_continue
    mov     rdi, rbx
    mov     rsi, [rbx + conn.body_end]
    call    input_reserve                   ; room for the whole body
    test    eax, eax
    jnz     .no_memory
    jmp     .out

.body_chunked:
    mov     rdx, [rbx + conn.rlen]
    sub     rdx, [rbx + conn.body_end]
    jz      .chunked_short
    lea     rdi, [rbx + conn.chunked]
    mov     rsi, [rbx + conn.rbuf]
    add     rsi, [rbx + conn.body_end]
    lea     rcx, [rsp]                      ; produced
    call    httpasm_h1_chunked_decode
    test    rax, rax
    js      .bad_request
    ; Decoded data now sits at [body_end, body_end + produced); the octets not consumed yet are
    ; at [body_end + consumed, rlen). Close the gap so the input stays contiguous.
    mov     r14, rax                        ; consumed
    mov     r15, [rsp]                      ; produced
    mov     rcx, [rbx + conn.rlen]
    sub     rcx, [rbx + conn.body_end]
    sub     rcx, r14                        ; the octets after the consumed ones
    cmp     r14, r15
    je      .chunked_moved
    test    rcx, rcx
    jz      .chunked_moved
    mov     rdi, [rbx + conn.rbuf]
    add     rdi, [rbx + conn.body_end]
    lea     rsi, [rdi + r14]
    add     rdi, r15
    rep     movsb
.chunked_moved:
    mov     rax, r14
    sub     rax, r15
    sub     [rbx + conn.rlen], rax
    add     [rbx + conn.body_end], r15
    mov     rax, [rbx + conn.chunked + httpasm_h1_chunked.total]
    cmp     rax, [r13 + server.max_body]
    ja      .too_large
    cmp     dword [rbx + conn.chunked + httpasm_h1_chunked.state], HTTPASM_CHUNKED_TRAILERS
    jne     .chunked_short
    mov     qword [rbx + conn.scan_from], 0
    mov     dword [rbx + conn.state], CS_TRAILERS
    jmp     .loop
.chunked_short:
    mov     rdi, rbx
    call    send_continue
    jmp     .need_more

.trailers:
    ; Trailer fields go after the header fields, in the room the array has left. With none
    ; left they go to the frame's one record instead (P_SPARE_FIELD), and a section that holds
    ; a field is refused with 431 once parsed. The limit cannot say "no field" (0 asks for the
    ; default), and the limit 1 with the array's end as the destination - what this did until
    ; 2026-11-26 - wrote a record 32 octets past the array's allocation: a request with
    ; max_fields header fields, a chunked body and one trailer corrupted the heap ("free():
    ; invalid next size", an abort; found by the coverage gate's walk of the unrun markers).
    mov     eax, [r13 + server.limits + httpasm_h1_limits.max_head]
    mov     [rsp + 16 + httpasm_h1_limits.max_head], eax
    mov     dword [rsp + 16 + httpasm_h1_limits.max_target], 0
    mov     dword [rsp + 16 + httpasm_h1_limits.reserved], 0
    mov     eax, [r13 + server.limits + httpasm_h1_limits.max_fields]
    test    eax, eax
    jnz     .capacity
    mov     eax, HA_H1_DEFAULT_MAX_FIELDS
.capacity:
    mov     r8d, [rbx + conn.request + httpasm_request.field_count]
    shl     r8, 5
    add     r8, [rbx + conn.fields]         ; the records after the header's
    mov     dword [rsp + P_NO_ROOM], 0
    sub     eax, [rbx + conn.request + httpasm_request.field_count]
    jnz     .room
    lea     r8, [rsp + P_SPARE_FIELD]       ; none left: the frame's record, never the array's end
    mov     dword [rsp + P_NO_ROOM], 1
    mov     eax, 1
.room:
    mov     [rsp + 16 + httpasm_h1_limits.max_fields], eax
    mov     rdi, [rbx + conn.rbuf]
    add     rdi, [rbx + conn.body_end]
    mov     rsi, [rbx + conn.rlen]
    sub     rsi, [rbx + conn.body_end]
    lea     rdx, [rbx + conn.scan_from]
    lea     rcx, [rsp + 16]
    lea     r9, [rsp + 8]                   ; count
    call    httpasm_h1_parse_trailers
    test    rax, rax
    jz      .need_more
    js      .head_refused
    mov     ecx, [rsp + 8]
    test    ecx, ecx
    jz      .trailers_fit                   ; an empty section fits whatever the room
    cmp     dword [rsp + P_NO_ROOM], 0
    je      .trailers_fit
    mov     rax, -431                       ; a field the array has no room for (RFC 6585 5)
    jmp     .head_refused
.trailers_fit:
    mov     [rbx + conn.exchange + exchange.trailer_count], ecx
    add     rax, [rbx + conn.body_end]
    mov     [rbx + conn.message_end], rax
    mov     dword [rbx + conn.state], CS_READY
    jmp     .loop

.ready:
    ; The exchange the handler sees.
    lea     r14, [rbx + conn.exchange]
    mov     [r14 + exchange.conn], rbx
    mov     rax, [rbx + conn.rbuf]
    add     rax, [rbx + conn.head_length]
    mov     [r14 + exchange.body], rax
    mov     rax, [rbx + conn.body_end]
    sub     rax, [rbx + conn.head_length]
    mov     [r14 + exchange.body_length], rax
    mov     eax, [rbx + conn.request + httpasm_request.field_count]
    shl     rax, 5
    add     rax, [rbx + conn.fields]
    mov     [r14 + exchange.trailers], rax
    lea     rax, [rbx + conn.request]
    mov     [r14 + exchange.request], rax
    mov     qword [r14 + exchange.stream], 0
    mov     dword [r14 + exchange.state], X_IN_HANDLER
    mov     rdi, [r13 + server.context]
    mov     rsi, r14
    call    [r13 + server.handler]
    mov     eax, [r14 + exchange.state]
    cmp     eax, X_DEFERRED
    je      .deferred
    ; Deferred and already answered: another thread responded before the handler returned. The
    ; response waits on the worker's queue (its eventfd rang), so this is still a deferral.
    cmp     eax, X_POSTED
    je      .deferred
    cmp     eax, X_RESPONDED
    je      .answered
    ; The handler returned without answering: 500, and the connection closes (its state after
    ; a broken handler is not to be trusted).
    mov     rdi, rbx
    mov     esi, 500
    call    error_response
    mov     dword [r14 + exchange.state], X_RESPONDED
.answered:
    mov     rdi, rbx
    call    ha_conn_finish
    jmp     .loop
.deferred:
    or      dword [rbx + conn.flags], C_DEFERRED
    inc     dword [rbx + conn.deferred]
    mov     rdi, rbx
    call    ha_set_interest                 ; stop reading until the response comes
    jmp     .out

.h2:
    ; An HTTP/2 connection: the engine takes the input (h2.asm), with the same contract.
    mov     rdi, rbx
    call    ha_h2_process
    jmp     .return

.need_more:
    ; The input is full and the message is not complete: grow it (the parsers refuse heads over
    ; their limit with 431 before this grows without end).
    mov     rax, [rbx + conn.rlen]
    cmp     rax, [rbx + conn.rcap]
    jb      .out
    mov     rdi, rbx
    lea     rsi, [rax + rax]
    call    input_reserve
    test    eax, eax
    jnz     .no_memory
    jmp     .out
.too_large:
    mov     rdi, rbx
    mov     esi, 413
    call    error_response
    jmp     .out
.bad_request:
    mov     rdi, rbx
    mov     esi, 400
    call    error_response
    jmp     .out
.no_memory:
    mov     rdi, rbx
    mov     esi, 503
    call    error_response
.out:
    xor     eax, eax
    jmp     .return
.pressure:
    mov     eax, 1
.return:
    add     rsp, P_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_conn_finish: the current message is answered. Its octets leave the input (what follows
; moves to the front), the head parser starts over, and the deadline moves on: the next request
; gets a full timeout. A request that does not persist the connection was answered with a
; closing response (C_CLOSE_AFTER), so nothing more is parsed.
;   In: rdi = conn. Clobbers every caller-saved register. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global ha_conn_finish:function hidden (ha_conn_finish.end - ha_conn_finish)
align 16
ha_conn_finish:
    push    rbx
    mov     rbx, rdi
    mov     rdx, [rbx + conn.message_end]
    mov     rcx, [rbx + conn.rlen]
    sub     rcx, rdx                        ; the octets after the message
    mov     [rbx + conn.rlen], rcx
    jz      .moved
    mov     rdi, [rbx + conn.rbuf]
    lea     rsi, [rdi + rdx]
    rep     movsb
.moved:
    xor     eax, eax
    mov     [rbx + conn.scan_from], rax
    mov     [rbx + conn.head_length], rax
    mov     [rbx + conn.body_end], rax
    mov     [rbx + conn.message_end], rax
    mov     dword [rbx + conn.state], CS_HEAD
    mov     dword [rbx + conn.exchange + exchange.state], X_IDLE
    mov     dword [rbx + conn.exchange + exchange.trailer_count], 0
    mov     rdi, rbx
    call    ha_lru_touch
    pop     rbx
    ret
.end:
