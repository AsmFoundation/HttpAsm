; =============================================================================
; client.asm - the C ABI's client: one blocking HTTP/1.1 connection (RFC 9112), requests answered
; in order, built on the same codec the server uses (the request writer, the response parser,
; the chunked decoder and the trailer parser of HttpAsm.Core).
;
; A response is read whole before httpasm_client_send returns: its head (1xx interim responses
; skipped: RFC 9110 15.2), and its body framed as RFC 9112 6.3 says (no body for HEAD, 1xx, 204,
; 304; Content-Length; chunked, decoded in place, its trailers kept apart from the header fields
; (RFC 9110 6.5.1); or until the server closes). Every pointer the caller gets points into the
; client's own input buffer and stays valid until the next call on the client.
;
; The input buffer may grow, and move, while a body arrives. The head's octets never move inside
; it (they stay at its start), so instead of rebasing every pointer the head is parsed again once
; the body is complete, if the buffer moved: cheap, and no pointer can be missed.
;
; Persistence (RFC 9112 9.3): after a response that does not keep the connection (Connection:
; close, HTTP/1.0 without keep-alive, a body delimited by the close, a CONNECT tunnel), or a
; request that asked to close, the socket is closed and later calls return -ENOTCONN. An I/O
; error or an invalid response closes it too: its framing can no longer be trusted.
;
; Not thread-safe: one thread at a time per client. Timeouts (SO_RCVTIMEO, SO_SNDTIMEO) bound
; the connect and every read and write.
; =============================================================================
default rel
%include "httpasm.inc"
%include "internal/driver.inc"

extern ha_method_lookup

SYS_connect         equ 42
SYS_sendmsg         equ 46
SO_RCVTIMEO         equ 20
SO_SNDTIMEO         equ 21
MSG_PEEK            equ 0x02        ; look without taking (MSG_DONTWAIT: driver.inc)
ENOTCONN            equ 107
ECONNRESET          equ 104
ETIMEDOUT           equ 110
EPROTO              equ 71          ; the server sent octets no request asked for

HA_CLIENT_BUFFER    equ 16384   ; the input to start with (it grows as a response needs)
HA_CLIENT_OUTPUT    equ 4096    ; the request head's buffer to start with
HA_CLIENT_FIELDS    equ 256     ; response field records: the head's, then the trailers'

struc client
    .rbuf:              resq 1
    .rcap:              resq 1
    .rlen:              resq 1
    .consumed:          resq 1  ; the last response's octets: they leave the input next call
    .wbuf:              resq 1
    .wcap:              resq 1
    .fields:            resq 1  ; httpasm_field[HA_CLIENT_FIELDS]
    .fd:                resd 1
    .open:              resd 1  ; 1 while the connection may carry another request
    .chunked:           resb httpasm_h1_chunked_size
endstruc

section .text

; -----------------------------------------------------------------------------
; httpasm_client *httpasm_client_connect(uint32_t address, uint16_t port, uint32_t timeout_ms,
;                                        int *error)
;   Connects to an IPv4 address (network byte order) and port. timeout_ms bounds the connect
;   and each later read and write (0: no limit). NULL on failure with *error = -errno (error may
;   be NULL): ECONNREFUSED, ETIMEDOUT (EINPROGRESS when the connect timed out), ENOMEM, ...
; -----------------------------------------------------------------------------
CC_ADDRESS  equ 0       ; sockaddr_in (16)
CC_TIME     equ 16      ; struct timeval (16)
CC_OPTION   equ 32      ; an int option
CC_FRAME    equ 40      ; five pushes + 40: aligned for the calls

global httpasm_client_connect:function (httpasm_client_connect.end - httpasm_client_connect)
align 16
httpasm_client_connect:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, CC_FRAME
    mov     r13d, edi                       ; address
    mov     r14d, esi                       ; port
    mov     r15d, edx                       ; timeout
    mov     rbx, rcx                        ; error
    mov     r12d, -1                        ; no socket yet
    mov     edi, AF_INET
    mov     esi, SOCK_STREAM | SOCK_CLOEXEC
    xor     edx, edx
    mov     eax, SYS_socket
    syscall
    test    eax, eax
    js      .fail
    mov     r12d, eax
    test    r15d, r15d
    jz      .no_timeout
    ; Both timeouts: the connect obeys SO_SNDTIMEO on Linux, reads SO_RCVTIMEO.
    mov     eax, r15d
    xor     edx, edx
    mov     ecx, 1000
    div     ecx
    mov     [rsp + CC_TIME], rax            ; seconds
    imul    rdx, rdx, 1000
    mov     [rsp + CC_TIME + 8], rdx        ; microseconds
    mov     edi, r12d
    mov     esi, SOL_SOCKET
    mov     edx, SO_SNDTIMEO
    lea     r10, [rsp + CC_TIME]
    mov     r8d, 16
    mov     eax, SYS_setsockopt
    syscall
    mov     edi, r12d
    mov     esi, SOL_SOCKET
    mov     edx, SO_RCVTIMEO
    lea     r10, [rsp + CC_TIME]
    mov     r8d, 16
    mov     eax, SYS_setsockopt
    syscall
.no_timeout:
    mov     dword [rsp + CC_OPTION], 1      ; TCP_NODELAY: a request leaves when it is written
    mov     edi, r12d
    mov     esi, IPPROTO_TCP
    mov     edx, TCP_NODELAY
    lea     r10, [rsp + CC_OPTION]
    mov     r8d, 4
    mov     eax, SYS_setsockopt
    syscall
    mov     word [rsp + CC_ADDRESS], AF_INET
    mov     eax, r14d
    xchg    al, ah
    mov     [rsp + CC_ADDRESS + 2], ax
    mov     [rsp + CC_ADDRESS + 4], r13d
    mov     qword [rsp + CC_ADDRESS + 8], 0
    mov     edi, r12d
    lea     rsi, [rsp + CC_ADDRESS]
    mov     edx, 16
    mov     eax, SYS_connect
    syscall
    test    eax, eax
    js      .fail
    ; The client and its buffers.
    mov     edi, 1
    mov     esi, client_size
    call    calloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     r13, rax
    mov     [r13 + client.fd], r12d
    mov     dword [r13 + client.open], 1
    mov     edi, HA_CLIENT_BUFFER
    call    malloc wrt ..plt
    mov     [r13 + client.rbuf], rax
    mov     qword [r13 + client.rcap], HA_CLIENT_BUFFER
    test    rax, rax
    jz      .no_memory_client
    mov     edi, HA_CLIENT_OUTPUT
    call    malloc wrt ..plt
    mov     [r13 + client.wbuf], rax
    mov     qword [r13 + client.wcap], HA_CLIENT_OUTPUT
    test    rax, rax
    jz      .no_memory_client
    mov     edi, HA_CLIENT_FIELDS * httpasm_field_size
    call    malloc wrt ..plt
    mov     [r13 + client.fields], rax
    test    rax, rax
    jz      .no_memory_client
    mov     rax, r13
    jmp     .out
.no_memory_client:
    mov     dword [r13 + client.fd], -1     ; the socket is closed below, once
    mov     rdi, r13
    call    free_client
.no_memory:
    mov     eax, -ENOMEM
.fail:
    mov     r13d, eax                       ; -errno
    test    r12d, r12d
    js      .report
    mov     edi, r12d
    mov     eax, SYS_close
    syscall
.report:
    test    rbx, rbx
    jz      .null
    mov     [rbx], r13d
.null:
    xor     eax, eax
.out:
    add     rsp, CC_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; free_client: closes the socket if it is open and frees the client's memory.
;   In: rdi = client. Clobbers every caller-saved register.
align 16
free_client:
    push    rbx
    mov     rbx, rdi
    mov     edi, [rbx + client.fd]
    test    edi, edi
    js      .closed
    mov     eax, SYS_close
    syscall
.closed:
    mov     rdi, [rbx + client.rbuf]
    call    free wrt ..plt
    mov     rdi, [rbx + client.wbuf]
    call    free wrt ..plt
    mov     rdi, [rbx + client.fields]
    call    free wrt ..plt
    mov     rdi, rbx
    call    free wrt ..plt
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; void httpasm_client_close(httpasm_client *client)
;   Closes the connection and frees the client; its last response's pointers become invalid.
;   NULL does nothing.
; -----------------------------------------------------------------------------
global httpasm_client_close:function (httpasm_client_close.end - httpasm_client_close)
align 16
httpasm_client_close:
    test    rdi, rdi
    jz      .out
    jmp     free_client
.out:
    ret
.end:

; -----------------------------------------------------------------------------
; client_hangup: the connection carries no more requests: the socket closes (the input stays,
; so the last response remains readable). In: rbx = client. Clobbers rax, rcx, rdi, r11.
; -----------------------------------------------------------------------------
align 16
client_hangup:
    mov     dword [rbx + client.open], 0
    mov     edi, [rbx + client.fd]
    test    edi, edi
    js      .out
    mov     eax, SYS_close
    syscall
    mov     dword [rbx + client.fd], -1
.out:
    ret

; -----------------------------------------------------------------------------
; client_receive: reads what the socket has into the input, growing it when full.
;   In: rbx = client. Out: rax = octets read (> 0), 0 at the end of the stream, or -errno
;   (-ETIMEDOUT when the read timed out). Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
client_receive:
    sub     rsp, 8
    mov     rax, [rbx + client.rlen]
    cmp     rax, [rbx + client.rcap]
    jb      .read
    mov     rsi, [rbx + client.rcap]        ; full: twice the room
    shl     rsi, 1
    mov     rdi, [rbx + client.rbuf]
    push    rsi
    sub     rsp, 8
    call    realloc wrt ..plt
    add     rsp, 8
    pop     rsi
    test    rax, rax
    jz      .no_memory
    mov     [rbx + client.rbuf], rax
    mov     [rbx + client.rcap], rsi
.read:
    mov     edi, [rbx + client.fd]
    mov     rsi, [rbx + client.rbuf]
    add     rsi, [rbx + client.rlen]
    mov     rdx, [rbx + client.rcap]
    sub     rdx, [rbx + client.rlen]
    xor     r10d, r10d
    xor     r8d, r8d
    xor     r9d, r9d
    mov     eax, SYS_recvfrom
    syscall
    cmp     rax, -EINTR
    je      .read
    cmp     rax, -EAGAIN
    je      .timed_out
    test    rax, rax
    jle     .out
    add     [rbx + client.rlen], rax
    jmp     .out
.timed_out:
    mov     rax, -ETIMEDOUT
    jmp     .out
.no_memory:
    mov     rax, -ENOMEM
.out:
    add     rsp, 8
    ret

; -----------------------------------------------------------------------------
; int httpasm_client_send(httpasm_client *client, const httpasm_request *request,
;                         const uint8_t *body, size_t length, httpasm_client_response *response)
;   Sends a request and reads its final response (see this file's header). request gives the
;   method, target, authority (sent as Host), fields, and in flags HTTPASM_REQUEST_CLOSE (ask to
;   close after) or _EXPECT_CONTINUE; the framing is the client's: Content-Length when there is
;   a body or the method defines one (POST, PUT, PATCH). Returns 0; -HTTPASM_ERROR_* for a
;   request the writer refuses (nothing sent, the connection unchanged) or an invalid response
;   (the connection closed); -errno for I/O (ETIMEDOUT, ECONNRESET when the server closed before
;   a whole response, ENOMEM) with the connection closed; -ENOTCONN once it is.
;   Before sending, the connection must be quiet: -ECONNRESET when the server closed it while
;   idle (the request was not sent: safe to retry on a new connection), -EPROTO when it sent
;   octets no request asked for (the connection closes; they are never read as a response).
;   Octets that follow a response close the connection the same way, after that response is
;   returned (RFC 9112 9.2).
; -----------------------------------------------------------------------------
S_REQUEST   equ 0       ; a copy of the request, with the client's framing (96)
S_IOV       equ 96      ; two iovecs: the head, the body (32)
S_MSG       equ 128     ; struct msghdr (56)
S_SCAN      equ 184     ; the parsers' resume point
S_PRODUCED  equ 192
S_HEAD      equ 200     ; the head's length
S_BASE      equ 208     ; the input buffer when the head was parsed
S_COUNT     equ 216     ; trailer fields
S_LIMITS    equ 224     ; httpasm_h1_limits for the trailers (16)
S_BODY_END  equ 240     ; the end of the body decoded so far
S_PEEK      equ 248     ; one octet for the peek that finds unsolicited octets before a send
S_FRAME     equ 264     ; six pushes + 264: aligned

global httpasm_client_send:function (httpasm_client_send.end - httpasm_client_send)
align 16
httpasm_client_send:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, S_FRAME
    mov     rbx, rdi                        ; client
    mov     r12, rsi                        ; request
    mov     r13, rdx                        ; body
    mov     r14, rcx                        ; length
    mov     r15, r8                         ; response
    mov     eax, -ENOTCONN
    cmp     dword [rbx + client.open], 0
    je      .out

    ; The last response leaves the input (whatever followed it closed the connection already,
    ; at .persistence, so an open client moves nothing here and only resets the marks).
    mov     rcx, [rbx + client.rlen]
    sub     rcx, [rbx + client.consumed]
    mov     rdi, [rbx + client.rbuf]
    mov     rsi, rdi
    add     rsi, [rbx + client.consumed]
    mov     [rbx + client.rlen], rcx
    mov     qword [rbx + client.consumed], 0
    rep     movsb

    ; Nothing may be waiting in the socket either: octets the server sent since its last
    ; response answer no request (RFC9112-9.2-3#1), so the connection closes rather than read
    ; them as this request's response (-EPROTO; RFC9112-9.2-3#2). A server that closed the idle
    ; connection shows here as well, before this request goes out: -ECONNRESET then tells the
    ; caller it was never sent, so retrying it on a new connection is safe. One non-blocking
    ; peek; the usual answer is EAGAIN.
    mov     edi, [rbx + client.fd]
    lea     rsi, [rsp + S_PEEK]
    mov     edx, 1
    mov     r10d, MSG_PEEK | MSG_DONTWAIT
    xor     r8d, r8d
    xor     r9d, r9d
    mov     eax, SYS_recvfrom
    syscall
    cmp     rax, -EAGAIN
    je      .quiet                          ; nothing there: the usual case
    cmp     rax, -EINTR
    je      .quiet                          ; a signal, not the socket: nothing learned, go on
    test    rax, rax
    js      .io_error_rax                   ; a socket error: the connection closes with it
    jz      .reset                          ; the server closed: nothing was sent
    mov     rax, -EPROTO                    ; octets no request asked for
    jmp     .broken
.quiet:

    ; The request, with the client's framing.
    lea     rdi, [rsp + S_REQUEST]
    mov     rsi, r12
    mov     ecx, httpasm_request_size
    rep     movsb
    mov     rdi, [rsp + S_REQUEST + httpasm_request.method]
    mov     esi, [rsp + S_REQUEST + httpasm_request.method_length]
    call    ha_method_lookup
    mov     [rsp + S_REQUEST + httpasm_request.method_id], ax
    and     dword [rsp + S_REQUEST + httpasm_request.flags], HTTPASM_REQUEST_CLOSE | HTTPASM_REQUEST_EXPECT_CONTINUE
    test    r14, r14
    jnz     .with_length
    cmp     eax, HTTPASM_METHOD_POST        ; methods that define content get Content-Length: 0
    je      .with_length                    ; (RFC9110-8.6-5#1); others send none (8.6-5#2)
    cmp     eax, HTTPASM_METHOD_PUT
    je      .with_length
    cmp     eax, HTTPASM_METHOD_PATCH
    jne     .framed
.with_length:
    or      dword [rsp + S_REQUEST + httpasm_request.flags], HTTPASM_REQUEST_CONTENT_LENGTH
    mov     [rsp + S_REQUEST + httpasm_request.content_length], r14
.framed:
.write_head:
    mov     rdi, [rbx + client.wbuf]
    mov     rsi, [rbx + client.wcap]
    lea     rdx, [rsp + S_REQUEST]
    call    httpasm_h1_write_request
    test    rax, rax
    js      .out                            ; refused: nothing sent
    jnz     .head_written
    mov     rsi, [rbx + client.wcap]        ; no room: twice as much
    shl     rsi, 1
    mov     [rbx + client.wcap], rsi
    mov     rdi, [rbx + client.wbuf]
    call    realloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     [rbx + client.wbuf], rax
    jmp     .write_head
.head_written:
    ; Head and body in one sendmsg (MSG_NOSIGNAL: a vanished server is an error, not SIGPIPE).
    mov     rcx, [rbx + client.wbuf]
    mov     [rsp + S_IOV], rcx
    mov     [rsp + S_IOV + 8], rax
    mov     [rsp + S_IOV + 16], r13
    mov     [rsp + S_IOV + 24], r14
    xor     eax, eax
    mov     [rsp + S_MSG], rax              ; msg_name
    mov     [rsp + S_MSG + 8], rax          ; msg_namelen (and padding)
    lea     rcx, [rsp + S_IOV]
    mov     [rsp + S_MSG + 16], rcx         ; msg_iov
    mov     qword [rsp + S_MSG + 24], 2     ; msg_iovlen
    mov     [rsp + S_MSG + 32], rax         ; msg_control
    mov     [rsp + S_MSG + 40], rax         ; msg_controllen
    mov     [rsp + S_MSG + 48], rax         ; msg_flags
.send:
    mov     rax, [rsp + S_IOV + 8]
    or      rax, [rsp + S_IOV + 24]
    jz      .sent
    mov     edi, [rbx + client.fd]
    lea     rsi, [rsp + S_MSG]
    mov     edx, MSG_NOSIGNAL
    mov     eax, SYS_sendmsg
    syscall
    cmp     rax, -EINTR
    je      .send
    cmp     rax, -EAGAIN
    je      .timed_out
    test    rax, rax
    js      .io_error
    ; Advance the iovecs past what was sent.
    mov     rcx, [rsp + S_IOV + 8]
    cmp     rax, rcx
    jb      .partial_head
    sub     rax, rcx
    mov     qword [rsp + S_IOV + 8], 0
    add     [rsp + S_IOV + 16], rax
    sub     [rsp + S_IOV + 24], rax
    jmp     .send
.partial_head:
    add     [rsp + S_IOV], rax
    sub     [rsp + S_IOV + 8], rax
    jmp     .send
.sent:

    ; The response head; interim (1xx) responses are dropped (RFC 9110 15.2).
.head:
    mov     qword [rsp + S_SCAN], 0
.parse_head:
    mov     rdi, [rbx + client.rbuf]
    mov     [rsp + S_BASE], rdi
    mov     rsi, [rbx + client.rlen]
    lea     rdx, [rsp + S_SCAN]
    xor     ecx, ecx                        ; the default limits
    movzx   r8d, word [rsp + S_REQUEST + httpasm_request.method_id]
    lea     r9, [r15 + httpasm_client_response.head]
    mov     rax, [rbx + client.fields]
    sub     rsp, 16
    mov     [rsp], rax                      ; the 7th argument: the fields
    call    httpasm_h1_parse_response
    add     rsp, 16
    test    rax, rax
    js      .bad_response
    jnz     .head_parsed
    call    client_receive
    test    rax, rax
    jg      .parse_head
    jz      .reset                          ; the server closed before a whole head
    jmp     .io_error_rax
.head_parsed:
    mov     [rsp + S_HEAD], rax
    movzx   ecx, word [r15 + httpasm_client_response.head + httpasm_response_head.status]
    cmp     ecx, 200
    jae     .final
    cmp     ecx, 100
    jb      .final                          ; 000-099: invalid, a final answer like a 5xx (RFC9110-15-6)
    cmp     ecx, 101
    je      .bad_status                     ; a protocol switch this client never asked for
    ; An interim response: out of the input, then the next head.
    mov     rcx, [rbx + client.rlen]
    sub     rcx, rax
    mov     [rbx + client.rlen], rcx
    mov     rdi, [rbx + client.rbuf]
    lea     rsi, [rdi + rax]
    rep     movsb
    jmp     .head
.final:
    mov     qword [r15 + httpasm_client_response.trailers], 0
    mov     dword [r15 + httpasm_client_response.trailer_count], 0
    mov     dword [r15 + httpasm_client_response.reserved], 0
    mov     eax, [r15 + httpasm_client_response.head + httpasm_response_head.flags]
    test    eax, HTTPASM_RESPONSE_HEAD_NO_BODY
    jnz     .no_body
    test    eax, HTTPASM_RESPONSE_HEAD_TUNNEL
    jnz     .tunnel
    test    eax, HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH
    jnz     .length
    test    eax, HTTPASM_RESPONSE_HEAD_CHUNKED
    jnz     .chunked

    ; Delimited by the close: everything until the end of the stream (RFC 9112 6.3, 8).
.until_close:
    call    client_receive
    test    rax, rax
    jg      .until_close
    js      .io_error_rax
    mov     rax, [rsp + S_HEAD]
    mov     rcx, [rbx + client.rlen]
    sub     rcx, rax
    mov     [rsp + S_BODY_END], rcx         ; (the body's length)
    mov     rdx, [rbx + client.rlen]
    mov     [rbx + client.consumed], rdx
    call    client_hangup
    mov     rcx, [rsp + S_BODY_END]
    jmp     .body_found

.no_body:
    mov     rax, [rsp + S_HEAD]
    mov     [rbx + client.consumed], rax
    xor     ecx, ecx
    jmp     .body_found
.tunnel:
    ; A 2xx to CONNECT: the connection is a tunnel now, no longer this client's to use for HTTP.
    mov     rax, [rsp + S_HEAD]
    mov     [rbx + client.consumed], rax
    call    client_hangup
    xor     ecx, ecx
    jmp     .body_found

.length:
    mov     rax, [rsp + S_HEAD]
    add     rax, [r15 + httpasm_client_response.head + httpasm_response_head.content_length]
    jc      .bad_response_length
    mov     [rsp + S_BODY_END], rax         ; the message's end
.length_read:
    mov     rax, [rsp + S_BODY_END]
    cmp     [rbx + client.rlen], rax
    jae     .length_whole
    ; Room for the whole body at once, then read.
    cmp     rax, [rbx + client.rcap]
    jbe     .length_receive
    mov     rsi, rax
    mov     [rbx + client.rcap], rsi
    mov     rdi, [rbx + client.rbuf]
    call    realloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     [rbx + client.rbuf], rax
.length_receive:
    call    client_receive
    test    rax, rax
    jg      .length_read
    jz      .reset                          ; closed before the body's end (RFC9112-6.3-2.6)
    jmp     .io_error_rax
.length_whole:
    mov     rax, [rsp + S_BODY_END]
    mov     [rbx + client.consumed], rax
    mov     rcx, [r15 + httpasm_client_response.head + httpasm_response_head.content_length]
    jmp     .body_found

.chunked:
    ; Decoded in place behind the head, the framing's octets closed up as the server does it.
    pxor    xmm0, xmm0
    movdqu  [rbx + client.chunked], xmm0
    movdqu  [rbx + client.chunked + 16], xmm0
    mov     rax, [rsp + S_HEAD]
    mov     [rsp + S_BODY_END], rax
.chunk:
    mov     rdx, [rbx + client.rlen]
    sub     rdx, [rsp + S_BODY_END]
    jz      .chunk_more
    lea     rdi, [rbx + client.chunked]
    mov     rsi, [rbx + client.rbuf]
    add     rsi, [rsp + S_BODY_END]
    lea     rcx, [rsp + S_PRODUCED]
    call    httpasm_h1_chunked_decode
    test    rax, rax
    js      .bad_response_chunk
    mov     rdx, [rsp + S_PRODUCED]         ; data now at [body_end, body_end + produced); the
    mov     rcx, [rbx + client.rlen]        ; unconsumed octets at [body_end + consumed, rlen)
    sub     rcx, [rsp + S_BODY_END]
    sub     rcx, rax                        ; the octets after the consumed ones
    cmp     rax, rdx
    je      .chunk_moved
    test    rcx, rcx
    jz      .chunk_moved
    mov     rdi, [rbx + client.rbuf]
    add     rdi, [rsp + S_BODY_END]
    lea     rsi, [rdi + rax]
    add     rdi, rdx
    push    rax
    push    rdx
    rep     movsb
    pop     rdx
    pop     rax
.chunk_moved:
    sub     rax, rdx                        ; framing octets removed
    sub     [rbx + client.rlen], rax
    add     [rsp + S_BODY_END], rdx
    cmp     dword [rbx + client.chunked + httpasm_h1_chunked.state], HTTPASM_CHUNKED_TRAILERS
    je      .trailers
.chunk_more:
    call    client_receive
    test    rax, rax
    jg      .chunk
    jz      .reset
    jmp     .io_error_rax
.trailers:
    ; The trailer section, into the records after the head's fields.
    mov     qword [rsp + S_SCAN], 0
    mov     dword [rsp + S_LIMITS + httpasm_h1_limits.max_head], 0
    mov     dword [rsp + S_LIMITS + httpasm_h1_limits.max_target], 0
    mov     dword [rsp + S_LIMITS + httpasm_h1_limits.reserved], 0
    mov     eax, HA_CLIENT_FIELDS
    sub     eax, [r15 + httpasm_client_response.head + httpasm_response_head.field_count]
    jnz     .trailer_room
    mov     eax, 1                          ; none left: a section with a field fails (431)
.trailer_room:
    mov     [rsp + S_LIMITS + httpasm_h1_limits.max_fields], eax
.trailer_parse:
    mov     rdi, [rbx + client.rbuf]
    add     rdi, [rsp + S_BODY_END]
    mov     rsi, [rbx + client.rlen]
    sub     rsi, [rsp + S_BODY_END]
    lea     rdx, [rsp + S_SCAN]
    lea     rcx, [rsp + S_LIMITS]
    mov     r8d, [r15 + httpasm_client_response.head + httpasm_response_head.field_count]
    shl     r8, 5
    add     r8, [rbx + client.fields]
    lea     r9, [rsp + S_COUNT]
    call    httpasm_h1_parse_trailers
    test    rax, rax
    js      .bad_response
    jnz     .trailers_parsed
    call    client_receive
    test    rax, rax
    jg      .trailer_parse
    jz      .reset
    jmp     .io_error_rax
.trailers_parsed:
    add     rax, [rsp + S_BODY_END]
    mov     [rbx + client.consumed], rax
    mov     eax, [rsp + S_COUNT]
    mov     [r15 + httpasm_client_response.trailer_count], eax
    mov     rcx, [rsp + S_BODY_END]
    sub     rcx, [rsp + S_HEAD]             ; the decoded body's length

.body_found:
    ; rcx = the body's length; it starts right after the head.
    mov     [r15 + httpasm_client_response.body_length], rcx
    mov     rax, [rbx + client.rbuf]
    cmp     rax, [rsp + S_BASE]
    je      .pointers_good
    ; The input moved while the body arrived: the head's pointers follow it (parsed again).
    push    rcx
    sub     rsp, 8                          ; the frame is 16 octets up from here on
    mov     qword [rsp + 16 + S_SCAN], 0
    mov     rdi, [rbx + client.rbuf]
    mov     rsi, [rsp + 16 + S_HEAD]
    lea     rdx, [rsp + 16 + S_SCAN]
    xor     ecx, ecx
    movzx   r8d, word [rsp + 16 + S_REQUEST + httpasm_request.method_id]
    lea     r9, [r15 + httpasm_client_response.head]
    mov     rax, [rbx + client.fields]
    sub     rsp, 16
    mov     [rsp], rax
    call    httpasm_h1_parse_response
    add     rsp, 16
    ; The trailers' pointers moved by the same distance.
    mov     ecx, [r15 + httpasm_client_response.trailer_count]
    test    ecx, ecx
    jz      .reparsed
    mov     rdx, [rbx + client.rbuf]
    sub     rdx, [rsp + 16 + S_BASE]        ; the distance
    mov     eax, [r15 + httpasm_client_response.head + httpasm_response_head.field_count]
    shl     rax, 5
    add     rax, [rbx + client.fields]
.trailer_rebase:
    add     [rax + httpasm_field.name], rdx
    add     [rax + httpasm_field.value], rdx
    add     rax, httpasm_field_size
    dec     ecx
    jnz     .trailer_rebase
.reparsed:
    add     rsp, 8
    pop     rcx
.pointers_good:
    mov     rax, [rbx + client.rbuf]
    add     rax, [rsp + S_HEAD]
    mov     [r15 + httpasm_client_response.body], rax
    cmp     dword [r15 + httpasm_client_response.trailer_count], 0
    je      .persistence
    mov     eax, [r15 + httpasm_client_response.head + httpasm_response_head.field_count]
    shl     rax, 5
    add     rax, [rbx + client.fields]
    mov     [r15 + httpasm_client_response.trailers], rax
.persistence:
    ; Octets past this response are not part of it, and answer no request either (one is
    ; outstanding at a time): they are never read as a response (RFC9112-9.2-3#1, 6.3-8#2).
    ; They are dropped with the connection, which can no longer be trusted (RFC9112-9.2-3#2;
    ; 6.3-8#1 allows discarding them); this response itself was whole, and is returned.
    mov     rax, [rbx + client.rlen]
    cmp     rax, [rbx + client.consumed]
    ja      .hang_up
    ; Another request may follow only if the response keeps the connection and the request
    ; did not ask to close it (RFC9112-9.6-5#2: the client closes after such a response).
    test    dword [r15 + httpasm_client_response.head + httpasm_response_head.flags], HTTPASM_RESPONSE_HEAD_KEEP_ALIVE
    jz      .hang_up
    test    dword [rsp + S_REQUEST + httpasm_request.flags], HTTPASM_REQUEST_CLOSE
    jz      .done
.hang_up:
    call    client_hangup
.done:
    xor     eax, eax
    jmp     .out

.bad_status:
    mov     rax, -HTTPASM_ERROR_STATUS
    jmp     .broken
.bad_response_length:
    mov     rax, -HTTPASM_ERROR_CONTENT_LENGTH
    jmp     .broken
.bad_response_chunk:
    mov     rax, -HTTPASM_ERROR_CHUNK
    jmp     .broken
.bad_response:
    ; -400 or -431 from a parser: the head says which rule, when it knows.
    movzx   ecx, word [r15 + httpasm_client_response.head + httpasm_response_head.error]
    test    ecx, ecx
    jz      .broken
    mov     eax, ecx
    neg     rax
    jmp     .broken
.reset:
    mov     rax, -ECONNRESET
    jmp     .broken
.timed_out:
    mov     rax, -ETIMEDOUT
    jmp     .broken
.no_memory:
    mov     rax, -ENOMEM
    jmp     .broken
.io_error:
.io_error_rax:
.broken:
    ; Its framing cannot be trusted any more: the connection closes.
    push    rax
    sub     rsp, 8
    call    client_hangup
    add     rsp, 8
    pop     rax
.out:
    add     rsp, S_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:
