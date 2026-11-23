; =============================================================================
; exchange.asm - the C ABI a handler uses: the request, its body and trailers, and the answer,
; either at once (inside the handler) or later from any thread (after httpasm_exchange_defer).
;
; At once: the response is written straight into the connection's output buffer, on the
; worker's thread. Later: the caller's thread serializes the response itself (the writer is
; pure: no worker state is touched), posts it to the connection's worker on a lock-free stack,
; and rings the worker's eventfd. The worker appends the octets and resumes the connection.
; Pipelined requests behind a deferred one wait for it: responses leave in request order.
; =============================================================================
default rel
%include "httpasm.inc"
%include "internal/driver.inc"

extern ha_wake_worker

section .text

; -----------------------------------------------------------------------------
; const httpasm_request *httpasm_exchange_request(const httpasm_exchange *exchange)
;   The request: its pointers stay valid until the exchange is answered (they point into the
;   connection's input buffer).
; -----------------------------------------------------------------------------
global httpasm_exchange_request:function (httpasm_exchange_request.end - httpasm_exchange_request)
align 16
httpasm_exchange_request:
    mov     rax, [rdi + exchange.conn]
    add     rax, conn.request
    ret
.end:

; -----------------------------------------------------------------------------
; const uint8_t *httpasm_exchange_body(const httpasm_exchange *exchange, size_t *length)
;   The request's body, decoded (chunked framing removed), and its length in *length; valid
;   until the exchange is answered. An empty body is a valid pointer with length 0.
; -----------------------------------------------------------------------------
global httpasm_exchange_body:function (httpasm_exchange_body.end - httpasm_exchange_body)
align 16
httpasm_exchange_body:
    mov     rax, [rdi + exchange.body_length]
    test    rsi, rsi
    jz      .no_length
    mov     [rsi], rax
.no_length:
    mov     rax, [rdi + exchange.body]
    ret
.end:

; -----------------------------------------------------------------------------
; const httpasm_field *httpasm_exchange_trailers(const httpasm_exchange *exchange,
;                                                uint32_t *count)
;   The trailer fields of a chunked request (HTTPASM_FIELD_FLAG_TRAILER), *count of them; 0
;   when there were none. Kept apart from the header fields (RFC 9110 6.5.1).
; -----------------------------------------------------------------------------
global httpasm_exchange_trailers:function (httpasm_exchange_trailers.end - httpasm_exchange_trailers)
align 16
httpasm_exchange_trailers:
    mov     eax, [rdi + exchange.trailer_count]
    test    rsi, rsi
    jz      .no_count
    mov     [rsi], eax
.no_count:
    mov     rax, [rdi + exchange.trailers]
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_exchange_defer(httpasm_exchange *exchange)
;   Called inside the handler: the handler returns without answering, and answers later with
;   httpasm_exchange_respond from any thread. The connection waits (later requests on it
;   included). Returns 0, or -EINVAL outside the handler.
; -----------------------------------------------------------------------------
global httpasm_exchange_defer:function (httpasm_exchange_defer.end - httpasm_exchange_defer)
align 16
httpasm_exchange_defer:
    mov     eax, -EINVAL
    cmp     dword [rdi + exchange.state], X_IN_HANDLER
    jne     .out
    mov     dword [rdi + exchange.state], X_DEFERRED
    xor     eax, eax
.out:
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_exchange_respond(httpasm_exchange *exchange, uint16_t status,
;                              const httpasm_field *fields, uint32_t count,
;                              const uint8_t *body, size_t length)
;   Answers the exchange: the status, the caller's fields (the library adds Date, the framing
;   and Connection), and the body (none for HEAD, 1xx, 204, 304). Inside the handler, or after
;   httpasm_exchange_defer from any thread; once.
;   Returns 0; -HTTPASM_ERROR_* when the writer refused the status or a field (nothing is sent,
;   and the exchange may be answered again); -EINVAL when it was already answered, or never
;   deferred outside its handler; -ENOMEM.
;   The fields and body are copied before this returns: the caller may free them.
; -----------------------------------------------------------------------------
global httpasm_exchange_respond:function (httpasm_exchange_respond.end - httpasm_exchange_respond)
align 16
httpasm_exchange_respond:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, httpasm_response_size + 40 ; response (48) + date (32) + 8: rsp aligned
    mov     rbx, rdi                        ; the exchange
    mov     r12d, esi                       ; status
    mov     r13, rdx                        ; fields
    mov     r14d, ecx                       ; count
    mov     r15, r8                         ; body
    mov     rbp, r9                         ; length
    mov     eax, [rbx + exchange.state]
    cmp     eax, X_IN_HANDLER
    je      .now
    cmp     eax, X_DEFERRED
    je      .later
    mov     eax, -EINVAL
    jmp     .out

.now:
    ; Inside the handler, on the worker's thread: straight into the output.
    mov     rdi, [rbx + exchange.conn]
    movzx   esi, r12w
    mov     rdx, r13
    mov     ecx, r14d
    mov     r8, r15
    mov     r9, rbp
    sub     rsp, 16
    mov     qword [rsp], 0                  ; close: only as the request decides
    call    ha_conn_respond
    add     rsp, 16
    test    eax, eax
    jnz     .out
    mov     dword [rbx + exchange.state], X_RESPONDED
    jmp     .out

.later:
    ; Any thread. Claim the exchange first, so two calls cannot both post.
    mov     eax, X_DEFERRED
    mov     ecx, X_POSTED
    lock cmpxchg [rbx + exchange.state], ecx
    jz      .claimed
    mov     eax, -EINVAL
    jmp     .out
.claimed:
    ; The response record. The Date is formatted on this thread: the worker's cached value
    ; belongs to the worker.
    lea     rdi, [rsp + httpasm_response_size]
    call    ha_date_format
    lea     rax, [rsp + httpasm_response_size]
    mov     [rsp + httpasm_response.date], rax
    mov     [rsp + httpasm_response.fields], r13
    mov     [rsp + httpasm_response.field_count], r14d
    mov     [rsp + httpasm_response.status], r12w
    mov     [rsp + httpasm_response.content_length], rbp
    mov     rcx, [rbx + exchange.conn]
    mov     al, [rcx + conn.request + httpasm_request.version]
    mov     [rsp + httpasm_response.request_version], al
    mov     ax, [rcx + conn.request + httpasm_request.method_id]
    mov     [rsp + httpasm_response.request_method], al
    mov     eax, HTTPASM_RESPONSE_LENGTH
    test    dword [rcx + conn.request + httpasm_request.flags], HTTPASM_REQUEST_KEEP_ALIVE
    jnz     .persists
    or      eax, HTTPASM_RESPONSE_CLOSE
.persists:
    mov     [rsp + httpasm_response.flags], eax
    xor     eax, eax
    mov     [rsp + httpasm_response.reserved], eax
    mov     [rsp + httpasm_response.reserved2], rax

    ; Serialize into a completion: its header, the response head, the body. The head's size is
    ; not known before writing it: start with 1 KiB and double until it fits.
    mov     r12d, 1024                      ; the room for the head (the status is in the record now)
.allocate:
    lea     rdi, [r12 + rbp + completion_size]
    call    malloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     r13, rax                        ; the completion (the fields are in the record)
    lea     rdi, [r13 + completion_size]
    mov     rsi, r12
    mov     rdx, rsp
    call    httpasm_h1_write_response
    test    rax, rax
    jnz     .written
    mov     rdi, r13                        ; too small: twice the room
    call    free wrt ..plt
    shl     r12, 1
    jmp     .allocate
.written:
    js      .refused
    mov     r14, rax                        ; the head's length
    test    dword [rsp + httpasm_response.flags], HTTPASM_RESPONSE_NO_BODY
    jnz     .no_body
    lea     rdi, [r13 + completion_size + r14]
    mov     rsi, r15
    mov     rcx, rbp
    rep     movsb
    add     r14, rbp
.no_body:
    mov     [r13 + completion.length], r14
    mov     rax, [rbx + exchange.conn]
    mov     [r13 + completion.conn], rax
    xor     ecx, ecx
    test    dword [rsp + httpasm_response.flags], HTTPASM_RESPONSE_CLOSE
    setnz   cl
    mov     [r13 + completion.close], ecx
    ; Post it: push onto the worker's lock-free stack, then ring the worker.
    mov     rdi, [rax + conn.worker]
.push:
    mov     rax, [rdi + worker.queue]
    mov     [r13 + completion.next], rax
    lock cmpxchg [rdi + worker.queue], r13
    jnz     .push
    call    ha_wake_worker
    xor     eax, eax
    jmp     .out
.refused:
    mov     r12, rax                        ; -HTTPASM_ERROR_*
    mov     rdi, r13
    call    free wrt ..plt
    mov     dword [rbx + exchange.state], X_DEFERRED   ; the caller may answer again, correctly
    mov     rax, r12
    jmp     .out
.no_memory:
    mov     dword [rbx + exchange.state], X_DEFERRED
    mov     eax, -ENOMEM
.out:
    add     rsp, httpasm_response_size + 40
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:
