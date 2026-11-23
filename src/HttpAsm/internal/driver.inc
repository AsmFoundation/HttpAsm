; =============================================================================
; internal/driver.inc - the Linux driver's internal structures and constants: the server, its
; workers, their connections, and the exchange a handler sees. Not part of the C ABI: callers
; hold only opaque pointers (httpasm_server *, httpasm_exchange *).
;
; The driver (docs/DESIGN.md, "Architecture") runs one worker thread per core. Each worker owns
; an epoll instance, its own listening socket (SO_REUSEPORT: the kernel spreads connections, so
; no accept lock and no hand-off), an eventfd that wakes it, and every connection it accepted.
; Nothing is shared between workers but the server's read-only settings, so no request takes a
; lock. Workers sleep in epoll_wait until an event arrives or the nearest idle deadline is due:
; no tick, no spin.
; =============================================================================
%ifndef HTTPASM_DRIVER_INC
%define HTTPASM_DRIVER_INC

; ---- Linux x86-64 system calls the driver makes directly (they return -errno) ----
SYS_read            equ 0
SYS_write           equ 1
SYS_close           equ 3
SYS_socket          equ 41
SYS_accept4         equ 288
SYS_sendto          equ 44
SYS_recvfrom        equ 45
SYS_shutdown        equ 48
SYS_bind            equ 49
SYS_listen          equ 50
SYS_getsockname     equ 51
SYS_setsockopt      equ 54
SYS_sched_getaffinity equ 204
SYS_epoll_wait      equ 232
SYS_epoll_ctl       equ 233
SYS_eventfd2        equ 290
SYS_epoll_create1   equ 291

AF_INET             equ 2
SOCK_STREAM         equ 1
SOCK_NONBLOCK       equ 0x800
SOCK_CLOEXEC        equ 0x80000
SOL_SOCKET          equ 1
SO_REUSEADDR        equ 2
SO_REUSEPORT        equ 15
IPPROTO_TCP         equ 6
TCP_NODELAY         equ 1
EPOLLIN             equ 0x001
EPOLLOUT            equ 0x004
EPOLLERR            equ 0x008
EPOLLHUP            equ 0x010
EPOLLRDHUP          equ 0x2000
EPOLL_CTL_ADD       equ 1
EPOLL_CTL_DEL       equ 2
EPOLL_CTL_MOD       equ 3
EPOLL_CLOEXEC       equ 0x80000
EFD_NONBLOCK        equ 0x800
EFD_CLOEXEC         equ 0x80000
MSG_NOSIGNAL        equ 0x4000
SHUT_WR             equ 1
EAGAIN              equ 11
EINTR               equ 4
EINVAL              equ 22
ENOMEM              equ 12
CLOCK_REALTIME_COARSE  equ 5
CLOCK_MONOTONIC_COARSE equ 6

; ---- Tunables ----
HA_EVENTS           equ 64          ; epoll events per wait
HA_BUFFER_INITIAL   equ 16384       ; a connection's input and output buffers to start with
HA_OUTPUT_HIGH      equ 1048576     ; output pending past this: stop reading the connection
HA_DEFAULT_MAX_BODY equ 1048576     ; request body limit: 413 beyond
HA_DEFAULT_IDLE_MS  equ 60000       ; idle and request-head timeout
HA_LINGER_MS        equ 2000        ; after a closing response: read and discard this long, then close
HA_STOP_GRACE_MS    equ 5000        ; httpasm_server_stop waits this long for in-flight exchanges
HA_LISTEN_BACKLOG   equ 4096

; epoll_event is packed on x86-64: a u32 of events and a u64 of data, 12 octets.
EPOLL_EVENT_SIZE    equ 12

; The epoll data of the two descriptors that are not connections.
HA_TAG_LISTENER     equ 1
HA_TAG_WAKE         equ 2

; -----------------------------------------------------------------------------
; The server: the options it was created with, and its workers.
; -----------------------------------------------------------------------------
struc server
    .handler:           resq 1
    .context:           resq 1
    .max_body:          resq 1
    .idle_ms:           resq 1
    .workers:           resq 1  ; worker[worker_count]
    .worker_count:      resd 1
    .bind_address:      resd 1
    .port:              resd 1  ; the bound port, host order
    .started:           resd 1
    .stop:              resd 1  ; set by httpasm_server_stop; workers read it when woken
    .pad:               resd 1
    .limits:            resb httpasm_h1_limits_size
endstruc

; -----------------------------------------------------------------------------
; The exchange: one request and its response, as the handler sees it (embedded in its
; connection, so a pointer to it leads back to the connection).
; -----------------------------------------------------------------------------
struc exchange
    .conn:              resq 1
    .state:             resd 1  ; X_*
    .trailer_count:     resd 1
    .body:              resq 1  ; the decoded body, in the connection's input buffer
    .body_length:       resq 1
    .trailers:          resq 1  ; httpasm_field[trailer_count], after the header fields
endstruc

X_IDLE              equ 0       ; no request
X_IN_HANDLER        equ 1       ; the handler runs: respond writes straight into the output
X_DEFERRED          equ 2       ; the handler deferred: respond posts the response to the worker
X_RESPONDED         equ 3       ; answered
X_POSTED            equ 4       ; a deferred response was posted; the worker has not taken it yet

; -----------------------------------------------------------------------------
; A connection.
; -----------------------------------------------------------------------------
struc conn
    .fd:                resd 1
    .flags:             resd 1  ; C_*
    .state:             resd 1  ; CS_*
    .pad:               resd 1
    .worker:            resq 1
    .rbuf:              resq 1  ; input: the current message starts at offset 0
    .rcap:              resq 1
    .rlen:              resq 1
    .wbuf:              resq 1  ; output: wbuf[wsent..wlen) is waiting to be sent
    .wcap:              resq 1
    .wlen:              resq 1
    .wsent:             resq 1
    .scan_from:         resq 1  ; the head parser's resume point
    .head_length:       resq 1
    .body_end:          resq 1  ; the end of the body decoded so far (chunked), or of the body
    .message_end:       resq 1  ; the end of the whole message, once complete
    .deadline:          resq 1  ; monotonic ms when the idle or head timeout closes it
    .lru_prev:          resq 1  ; the worker's list, oldest deadline first
    .lru_next:          resq 1
    .fields:            resq 1  ; httpasm_field[max_fields]
    .chunked:           resb httpasm_h1_chunked_size
    .request:           resb httpasm_request_size
    .exchange:          resb exchange_size
endstruc

; conn.flags
C_CLOSE_AFTER       equ 0x0001  ; close once the output is flushed (a closing response was written)
C_DRAINING          equ 0x0002  ; half-closed: reading and discarding until EOF or the linger ends
C_WANT_WRITE        equ 0x0004  ; output is waiting for EPOLLOUT
C_DEFERRED          equ 0x0008  ; an exchange is deferred: the connection waits for its response
C_ZOMBIE            equ 0x0010  ; closed while deferred: freed when the response arrives
C_CONTINUE_SENT     equ 0x0020  ; 100 Continue went out for the current request
C_READ_PAUSED       equ 0x0040  ; EPOLLIN is off (deferred, or output past HA_OUTPUT_HIGH)
; The peer finished sending (its FIN was read, or EPOLLRDHUP came while deferred). EPOLLRDHUP is
; level-triggered and stays raised from then on: asking for it again would wake the worker in a
; loop while the connection cannot act (deferred, or waiting for EPOLLOUT). The connection
; answers what it holds and closes; nothing more can arrive, so it closes without lingering.
C_PEER_DONE         equ 0x0080
; Closed and on its worker's closed list: the memory stays until the end of the event batch,
; because a later event of the same epoll_wait may still name the connection. Events for a
; closed (or zombie) connection are skipped.
C_CLOSED            equ 0x0100

; conn.state
CS_HEAD             equ 0       ; waiting for a request head
CS_BODY_LENGTH      equ 1       ; reading a Content-Length body
CS_BODY_CHUNKED     equ 2       ; decoding a chunked body
CS_TRAILERS         equ 3       ; reading the chunked body's trailer section
CS_READY            equ 4       ; the message is complete: the handler may run

; -----------------------------------------------------------------------------
; A worker.
; -----------------------------------------------------------------------------
struc worker
    .server:            resq 1
    .thread:            resq 1  ; pthread_t
    .queue:             resq 1  ; completions posted by other threads (a lock-free stack)
    .lru_head:          resq 1  ; the connection whose deadline comes first
    .lru_tail:          resq 1
    .conn_count:        resq 1
    .now_ms:            resq 1  ; monotonic, refreshed after every wait
    .date_second:       resq 1  ; the realtime second .date was formatted for
    .stop_deadline:     resq 1  ; monotonic ms when stopping forces the remaining connections closed
    .closed:            resq 1  ; connections closed during this batch, linked by conn.lru_next
    .zombies:           resq 1  ; closed connections whose deferred answer has not come yet: a
                                ; stopping worker waits for them too (within the grace)
    .epfd:              resd 1
    .listen_fd:         resd 1
    .wake_fd:           resd 1
    .stopping:          resd 1
    .date:              resb 32 ; IMF-fixdate, 29 octets
    .events:            resb HA_EVENTS * EPOLL_EVENT_SIZE
    .pad:               resd 1
endstruc

; -----------------------------------------------------------------------------
; A response posted from another thread to a deferred exchange's worker.
; -----------------------------------------------------------------------------
struc completion
    .next:              resq 1
    .conn:              resq 1
    .length:            resq 1  ; the serialized response's octets, which follow this header
    .close:             resd 1  ; the response closes the connection
    .pad:               resd 1
endstruc

; ---- functions shared between the driver's files ----
extern ha_date_format       ; (rdi = 32-octet buffer) -> the current IMF-fixdate, rax = its second
extern ha_conn_process      ; (rdi = conn) -> eax 1 when back-pressure stopped it: parse, dispatch, answer
extern ha_conn_drive        ; (rdi = conn): process and flush until no more can be done now
extern ha_conn_flush        ; (rdi = conn) -> eax 0 ok, 1 the connection was closed
extern ha_conn_close        ; (rdi = conn): close (or turn into a zombie while deferred); freed by ha_conn_reap
extern ha_conn_reap         ; (rdi = worker): frees the connections closed since the last reap
extern ha_conn_release      ; (rdi = conn): a zombie whose answer came: onto the closed list
extern ha_conn_respond      ; (rdi = conn, esi = status, rdx = fields, ecx = count, r8 = body, r9 = len, [rsp+8] = flags)
extern ha_lru_touch         ; (rdi = conn): the deadline moves to now + idle, to the list's tail
extern ha_set_interest      ; (rdi = conn): epoll's events follow the connection's flags
extern ha_conn_append       ; (rdi = conn, rsi = octets, rdx = count) -> eax 0 or -ENOMEM
extern ha_conn_finish       ; (rdi = conn): the answered message leaves the input
extern ha_conn_free         ; (rdi = conn): frees a closed connection's memory

; ---- the C library ----
extern malloc
extern calloc
extern realloc
extern free
extern pthread_create
extern pthread_join
extern clock_gettime

%endif
