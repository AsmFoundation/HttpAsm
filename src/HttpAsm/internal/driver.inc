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
; The exchange: one request and its response, as the handler sees it. HTTP/1.1 embeds it in
; its connection; HTTP/2 in each stream (h2stream), with .stream set, so a pointer to it leads
; back to both.
; -----------------------------------------------------------------------------
struc exchange
    .conn:              resq 1
    .state:             resd 1  ; X_*
    .trailer_count:     resd 1
    .body:              resq 1  ; the decoded body (HTTP/1.1: in the input buffer; HTTP/2: the stream's)
    .body_length:       resq 1
    .trailers:          resq 1  ; httpasm_field[trailer_count]
    .request:           resq 1  ; httpasm_request * (the connection's, or the stream's)
    .stream:            resq 1  ; HTTP/2: the h2stream; 0 for HTTP/1.1
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
    .h2:                resq 1  ; HTTP/2: the connection's h2 state (h2.asm); 0 otherwise
    .proto:             resd 1  ; HA_PROTO_*: decided by the connection's first octets
    .deferred:          resd 1  ; exchanges deferred and not answered yet (HTTP/1.1: 0 or 1;
                                ; HTTP/2: any number of streams): while above 0, a closed
                                ; connection stays allocated as a zombie
    .chunked:           resb httpasm_h1_chunked_size
    .request:           resb httpasm_request_size
    .exchange:          resb exchange_size
endstruc

HA_PROTO_UNKNOWN    equ 0       ; nothing read yet, or a prefix of HTTP/2's preface
HA_PROTO_H1         equ 1
HA_PROTO_H2         equ 2       ; h2c with prior knowledge (RFC 9113 3.3)

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
; A request head parsed on this connection: its peer speaks HTTP/1.x. Until then, a refused head
; whose request-line carries no HTTP-version is not HTTP at all (an HTTP/2 client's broken
; preface, another protocol), and the connection closes without an answer.
C_SPOKE             equ 0x0200

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
    ; HTTP/2 scratch, allocated on the worker's first HTTP/2 connection and shared by all of
    ; them (a worker handles one connection at a time): a field block decodes here, and the
    ; result is copied into its stream's own memory before any handler runs.
    .h2_fields:         resq 1  ; httpasm_field[max_fields]
    .h2_space:          resq 1  ; the decoded strings: max_head octets
    .h2_out:            resq 1  ; a response's field list, lower-cased names and HPACK block
    .h2_out_cap:        resq 1
    .epfd:              resd 1
    .listen_fd:         resd 1
    .wake_fd:           resd 1
    .stopping:          resd 1
    .date:              resb 32 ; IMF-fixdate, 29 octets
    .events:            resb HA_EVENTS * EPOLL_EVENT_SIZE
    .pad:               resd 1
endstruc

; -----------------------------------------------------------------------------
; A response posted from another thread to a deferred exchange's worker. HTTP/1.1's is
; serialized by the answering thread (the writer is pure). HTTP/2's cannot be: its HPACK
; encoder belongs to the connection, so the completion carries copies of the fields and the
; body, and the worker encodes them.
; -----------------------------------------------------------------------------
struc completion
    .next:              resq 1
    .conn:              resq 1
    .length:            resq 1  ; HTTP/1.1: the serialized response's octets, after this header
    .stream:            resq 1  ; HTTP/2: the h2stream; 0 for HTTP/1.1
    .fields:            resq 1  ; HTTP/2: httpasm_field[field_count], in this block
    .body:              resq 1  ; HTTP/2: the body, in this block
    .body_length:       resq 1
    .close:             resd 1  ; HTTP/1.1: the response closes the connection
    .status:            resd 1  ; HTTP/2: the status
    .field_count:       resd 1
    .pad:               resd 1
endstruc

; -----------------------------------------------------------------------------
; HTTP/2 (h2.asm): what this side advertises, and the engine's state.
; -----------------------------------------------------------------------------
HA_H2_MAX_STREAMS       equ 100         ; SETTINGS_MAX_CONCURRENT_STREAMS
HA_H2_WINDOW            equ 262144      ; SETTINGS_INITIAL_WINDOW_SIZE: each stream's receive window
HA_H2_CONNECTION_WINDOW equ 16777216    ; the connection's receive window (a WINDOW_UPDATE at start)
HA_H2_TABLE             equ 4096        ; SETTINGS_HEADER_TABLE_SIZE: the default, so not sent
HA_H2_FRAME             equ 16384       ; SETTINGS_MAX_FRAME_SIZE: the default, so not sent
HA_H2_CLOSED_RING       equ 64          ; recently closed streams remembered, with how they closed
HA_H2_MAX_CONTINUATIONS equ 128         ; CONTINUATION frames in one field block (a flood beyond)
HA_H2_RESET_FLOOR       equ 128         ; peer resets tolerated before the rapid-reset rule applies

struc h2
    .decoder:           resq 1  ; the HPACK decoder's table (in this block, after the stream table)
    .encoder:           resq 1  ; the encoder's
    .block:             resq 1  ; a field block assembled from HEADERS and CONTINUATION, or 0
    .block_length:      resq 1
    .block_cap:         resq 1
    .send_window:       resq 1  ; signed: what this side may still send on the connection
    .recv_window:       resq 1  ; what the peer may still send on it
    .recv_unacked:      resq 1  ; received DATA octets not given back with WINDOW_UPDATE yet
    .opened:            resq 1  ; streams the peer opened (rapid-reset accounting)
    .frame_payload:     resq 1  ; the frame being handled: its payload
    .frame_length:      resd 1  ;   its length
    .frame_stream:      resd 1  ;   its stream id (the reserved bit cleared)
    .frame_type:        resd 1
    .frame_flags:       resd 1
    .state:             resd 1  ; H2S_*
    .flags:             resd 1  ; H2F_*
    .last_stream:       resd 1  ; the highest stream id the peer opened
    .stream_count:      resd 1  ; streams in .streams
    .block_stream:      resd 1  ; the stream whose field block is being assembled; 0 when none
    .block_kind:        resd 1  ; H2K_*: what the block will be once whole
    .block_flags:       resd 1  ; the HEADERS frame's flags (END_STREAM) and H2B_*
    .block_frames:      resd 1  ; CONTINUATION frames so far
    .peer_window:       resd 1  ; the peer's SETTINGS_INITIAL_WINDOW_SIZE
    .peer_frame:        resd 1  ; the peer's SETTINGS_MAX_FRAME_SIZE
    .resets:            resd 1  ; streams the peer reset
    .closed_next:       resd 1  ; the ring's next slot
    .closed:            resq HA_H2_CLOSED_RING  ; id | H2C_* << 32
    .streams:           resq HA_H2_MAX_STREAMS  ; the active streams, unordered
endstruc

H2S_PREFACE         equ 0       ; the client's preface is next
H2S_SETTINGS        equ 1       ; its first frame must be SETTINGS
H2S_OPEN            equ 2

H2F_CLOSING         equ 0x01    ; the final GOAWAY is written (an error, or a goodbye): input ignored, close after it
H2F_GOAWAY_RECEIVED equ 0x02    ; the peer is leaving: close once no stream is active
H2F_NOTICE          equ 0x04    ; a graceful stop's first GOAWAY (last stream 2^31 - 1) went out:
                                ; streams already on their way are still served, none should follow

; How a remembered stream closed: what a later frame on it means (RFC 9113 5.1).
H2C_NORMAL          equ 1       ; both sides ended it: DATA or HEADERS are a connection error STREAM_CLOSED
H2C_PEER_RESET      equ 2       ; the peer reset it: a stream error STREAM_CLOSED
H2C_RESET           equ 3       ; this side reset it: frames already in flight are ignored

; What a field block is (block_kind)
H2K_REQUEST         equ 1       ; a new stream's request head
H2K_TRAILERS        equ 2       ; an open stream's trailer section
H2K_DISCARD         equ 3       ; decoded only to keep HPACK in step, then dropped
H2K_REFUSE          equ 4       ; a new stream over the concurrency limit: RST_STREAM REFUSED_STREAM
H2K_CLOSED          equ 5       ; a half-closed or reset stream: RST_STREAM STREAM_CLOSED after decoding
H2B_SELF_DEPENDENT  equ 0x100   ; block_flags: the HEADERS' priority named the stream itself

struc h2stream
    .send_window:       resq 1  ; signed: what this side may still send on the stream
    .recv_window:       resq 1  ; what the peer may still send on it
    .recv_unacked:      resq 1  ; received octets not given back with WINDOW_UPDATE yet
    .body:              resq 1  ; the request's body (grows), or 0
    .body_length:       resq 1
    .body_cap:          resq 1
    .out:               resq 1  ; the response body not sent yet (a copy), or 0
    .out_length:        resq 1
    .out_sent:          resq 1
    .head:              resq 1  ; the request's fields and their strings, one block
    .tail:              resq 1  ; the trailers' fields and strings, one block, or 0
    .conn:              resq 1
    .id:                resd 1
    .flags:             resd 1  ; HSF_*
    .trailer_count:     resd 1
    .pad:               resd 1
    .request:           resb httpasm_request_size
    .exchange:          resb exchange_size
endstruc

HSF_END_RECEIVED    equ 0x0001  ; the request ended (END_STREAM): half-closed (remote)
HSF_HEADERS_SENT    equ 0x0002  ; the final response's HEADERS went out
HSF_END_SENT        equ 0x0004  ; the response ended (END_STREAM): half-closed (local)
HSF_DISPATCHED      equ 0x0008  ; the handler has the exchange (or had it)
HSF_DEFERRED        equ 0x0010  ; the handler deferred: an answer from another thread will come
HSF_CANCELLED       equ 0x0020  ; detached while deferred (reset, or the connection closed):
                                ; freed when the answer comes, which is then dropped
HSF_IN_HANDLER      equ 0x0040  ; the handler runs: a finished stream is freed after it returns
HSF_ANSWERED        equ 0x0080  ; a final response was given (also an early error response)
HSF_CONTINUE_SENT   equ 0x0100  ; 100 (Continue) went out

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
extern ha_output_reserve    ; (rdi = conn, rsi = octets) -> eax 0 or -ENOMEM: room after the output's end
extern ha_input_reserve     ; (rdi = conn, rsi = capacity) -> eax 0 or -ENOMEM: the input holds this much
extern ha_h2_detect         ; (rdi = conn) -> eax 1 HTTP/2's preface, 0 HTTP/1.1, -1 too few octets to tell,
                            ;   2 an HTTP/2 preface broken after its first line (close silently)
extern ha_h2_start          ; (rdi = conn) -> eax 0 or -ENOMEM: the connection speaks HTTP/2 from now on
extern ha_h2_process        ; (rdi = conn) -> eax 1 when back-pressure stopped it: frames in the input
extern ha_h2_respond        ; (rdi = conn, rsi = stream, edx = status, rcx = fields, r8d = count, r9 = body, [rsp+8] = length)
extern ha_h2_completion     ; (rdi = conn, rsi = completion): a deferred stream's answer arrived
extern ha_h2_free           ; (rdi = conn): frees the HTTP/2 state; deferred streams are detached
extern ha_h2_goodbye        ; (rdi = conn): GOAWAY(NO_ERROR) and one best-effort send, before a close
extern ha_h2_notice         ; (rdi = conn) -> eax 1 if closed: a graceful stop's GOAWAY(2^31 - 1), flushed
extern ha_check_fields      ; (rdi = fields, esi = count, edx = HA_CHECK_*) -> eax 0 or HTTPASM_ERROR_*
extern ha_status_reason     ; (edi = status) -> rax = its reason phrase, edx = its length (0: none)

; ha_check_fields' modes (the core's h1/write.asm WR_*)
HA_CHECK_RESPONSE       equ 0
HA_CHECK_H2_RESPONSE    equ 3

; ---- the C library ----
extern malloc
extern calloc
extern realloc
extern free
extern pthread_create
extern pthread_join
extern clock_gettime

%endif
