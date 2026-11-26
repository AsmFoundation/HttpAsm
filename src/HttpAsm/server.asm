; =============================================================================
; server.asm - the server's life (create, start, stop, destroy) and its workers' event loop:
; accepting, reading, flushing, idle deadlines, completions of deferred exchanges, and a
; graceful stop.
;
; One worker per core (the CPUs this process may run on, unless told otherwise). Each worker
; binds its own listening socket to the same port with SO_REUSEPORT, so the kernel spreads new
; connections across workers: no accept lock, no hand-off, and a connection never changes
; thread. A worker sleeps until an event arrives or the earliest idle deadline is due; with no
; connection it waits without a timeout at all. Nothing ticks.
;
; Waiting and I/O, per worker: through epoll by default (epoll_wait, then recv and send per
; ready connection), or through the worker's own io_uring when the options ask for it with
; HTTPASM_SERVER_URING (uring.asm: one io_uring_enter per loop turn submits the turn's receives,
; sends and polls, and waits for the next completions). epoll is the default because it
; measured as cheap or cheaper on Linux 5.15 (benchmarks/README.md). A kernel or a seccomp
; profile that refuses io_uring_setup leaves the asking worker on epoll, worker by worker
; (httpasm_server_io tells whether all, none or some have rings). Both drive the same
; connection code (connection.asm): only the waiting, and who issues the receives and sends,
; differ.
;
; Stopping: httpasm_server_stop sets the server's stop flag and wakes every worker through its
; eventfd. A worker then closes its listener and the connections that are between requests,
; lets in-flight exchanges finish (deferred ones included, even when their client is gone), and
; after HA_STOP_GRACE_MS closes whatever remains. stop returns when every worker has exited.
;
; Each worker's eventfd and completion queue live as long as the server, not only while it
; runs: a deferred exchange may be answered by another thread at any time, also after a stop.
; Its response then waits on the queue (the eventfd stays valid to ring) until the next start
; handles it, or httpasm_server_destroy frees it.
; =============================================================================
default rel
%include "httpasm.inc"
%include "internal/driver.inc"

section .text

; -----------------------------------------------------------------------------
; monotonic_ms: the coarse monotonic clock in milliseconds (vDSO, no system call).
;   Out: rax. Clobbers every caller-saved register. Called with rsp 16-byte aligned; the
;   24-octet frame keeps it aligned for clock_gettime.
; -----------------------------------------------------------------------------
align 16
monotonic_ms:
    sub     rsp, 24
    mov     edi, CLOCK_MONOTONIC_COARSE
    mov     rsi, rsp
    call    clock_gettime wrt ..plt
    mov     rax, [rsp + 8]                  ; nanoseconds
    xor     edx, edx
    mov     ecx, 1000000
    div     rcx
    mov     rcx, rax
    imul    rax, [rsp], 1000
    add     rax, rcx
    add     rsp, 24
    ret

; -----------------------------------------------------------------------------
; cpu_count: the CPUs this process may run on (its affinity mask), at least 1.
;   Out: eax. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
cpu_count:
    sub     rsp, 136                        ; a 1024-bit CPU mask, aligned
    xor     edi, edi                        ; this thread
    mov     esi, 128
    mov     rdx, rsp
    mov     eax, SYS_sched_getaffinity
    syscall
    test    rax, rax
    jle     .one
    mov     rcx, rax                        ; the octets the kernel wrote
    xor     eax, eax
    xor     edx, edx
.octet:
    movzx   r8d, byte [rsp + rdx]
.bit:
    test    r8d, r8d
    jz      .next
    mov     r9d, r8d
    and     r9d, 1
    add     eax, r9d
    shr     r8d, 1
    jmp     .bit
.next:
    inc     rdx
    cmp     rdx, rcx
    jb      .octet
    test    eax, eax
    jnz     .out
.one:
    mov     eax, 1
.out:
    add     rsp, 136
    ret

; -----------------------------------------------------------------------------
; httpasm_server *httpasm_server_create(const httpasm_server_options *options, int *error)
;   A server with these options, not started. NULL on failure with *error = -errno (EINVAL: no
;   handler; ENOMEM; EMFILE/ENFILE: no descriptor for a worker's eventfd). error may be NULL.
;   See httpasm.h for the options' defaults.
; -----------------------------------------------------------------------------
global httpasm_server_create:function (httpasm_server_create.end - httpasm_server_create)
align 16
httpasm_server_create:
    push    rbx
    push    r12
    push    r13
    mov     r12, rdi                        ; options
    mov     r13, rsi                        ; error
    mov     eax, -EINVAL
    test    r12, r12
    jz      .fail
    cmp     qword [r12 + httpasm_server_options.handler], 0
    je      .fail
    mov     edi, 1
    mov     esi, server_size
    call    calloc wrt ..plt
    test    rax, rax
    jz      .no_memory
    mov     rbx, rax
    mov     rax, [r12 + httpasm_server_options.handler]
    mov     [rbx + server.handler], rax
    mov     rax, [r12 + httpasm_server_options.context]
    mov     [rbx + server.context], rax
    mov     rax, [r12 + httpasm_server_options.max_body]
    mov     rcx, HA_DEFAULT_MAX_BODY
    test    rax, rax
    cmovz   rax, rcx
    mov     [rbx + server.max_body], rax
    mov     eax, [r12 + httpasm_server_options.idle_timeout_ms]
    mov     ecx, HA_DEFAULT_IDLE_MS
    test    eax, eax
    cmovz   eax, ecx
    mov     [rbx + server.idle_ms], rax
    mov     eax, [r12 + httpasm_server_options.min_data_rate]
    mov     ecx, HA_DEFAULT_MIN_RATE
    test    eax, eax
    cmovz   eax, ecx
    mov     [rbx + server.min_rate], eax
    mov     eax, [r12 + httpasm_server_options.bind_address]
    mov     [rbx + server.bind_address], eax
    movzx   eax, word [r12 + httpasm_server_options.port]
    mov     [rbx + server.port], eax
    movzx   eax, word [r12 + httpasm_server_options.flags]
    mov     [rbx + server.flags], eax
    mov     rax, [r12 + httpasm_server_options.limits]
    mov     [rbx + server.limits], rax
    mov     rax, [r12 + httpasm_server_options.limits + 8]
    mov     [rbx + server.limits + 8], rax
    mov     eax, [r12 + httpasm_server_options.workers]
    test    eax, eax
    jnz     .count_set
    call    cpu_count
.count_set:
    mov     [rbx + server.worker_count], eax
    mov     edi, eax
    mov     esi, worker_size
    call    calloc wrt ..plt
    test    rax, rax
    jz      .no_memory_free
    mov     [rbx + server.workers], rax
    mov     ecx, [rbx + server.worker_count]
.worker:
    mov     [rax + worker.server], rbx
    mov     dword [rax + worker.epfd], -1
    mov     dword [rax + worker.listen_fd], -1
    mov     dword [rax + worker.wake_fd], -1
    ; A second no realtime clock reads, so the worker's first refresh_clock formats the Date
    ; whatever the clock says. calloc's 0 here matched a clock at 1970-01-01T00:00:00Z (a
    ; machine without an RTC, just booted): that second's responses carried .date's 29 zero
    ; octets as their Date (tests/native/dates.c, 2026-11-26).
    mov     qword [rax + worker.date_second], -1
    add     rax, worker_size
    dec     ecx
    jnz     .worker
    ; Each worker's eventfd, for the server's whole life (this file's header says why).
    xor     r12d, r12d                      ; the options are copied: r12 counts workers now
.eventfd:
    cmp     r12d, [rbx + server.worker_count]
    jae     .created
    xor     edi, edi
    mov     esi, EFD_NONBLOCK | EFD_CLOEXEC
    mov     eax, SYS_eventfd2
    syscall
    test    eax, eax
    js      .eventfd_failed
    imul    rcx, r12, worker_size
    add     rcx, [rbx + server.workers]
    mov     [rcx + worker.wake_fd], eax
    inc     r12d
    jmp     .eventfd
.eventfd_failed:
    mov     r12d, eax                       ; -errno, kept across the cleanup
    mov     rdi, rbx
    call    free_server                     ; closes the eventfds made so far, frees the rest
    mov     eax, r12d
    jmp     .fail
.created:
    mov     rax, rbx
    jmp     .out
.no_memory_free:
    mov     rdi, rbx
    call    free wrt ..plt
.no_memory:
    mov     eax, -ENOMEM
.fail:
    test    r13, r13
    jz      .null
    mov     [r13], eax
.null:
    xor     eax, eax
.out:
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; worker_open: a worker's epoll instance or, when the options ask for it (HTTPASM_SERVER_URING)
; and the kernel gives one, its io_uring ring (uring.asm); and its listening socket, bound and
; listening. Under epoll the listener and the worker's eventfd (made by httpasm_server_create)
; join the epoll instance here; under io_uring worker_main arms a poll for each instead.
;   In: rdi = worker. Out: eax = 0, or -errno (what is already open stays for close_worker).
;   The first worker of a server with port 0 learns the port the kernel chose, and the others
;   bind that one. The worker's run state starts over (a server may be started again).
; -----------------------------------------------------------------------------
align 16
worker_open:
    push    rbx
    push    r12
    sub     rsp, 24                         ; sockaddr_in (16) + an int option value
    mov     rbx, rdi
    mov     r12, [rbx + worker.server]
    mov     dword [rbx + worker.stopping], 0
    mov     qword [rbx + worker.stop_deadline], 0
    mov     qword [rbx + worker.accept_resume], 0   ; a new listener is watched from the start
    ; io_uring only when the options ask for it; a kernel without it (or a seccomp profile
    ; refusing it, or a user past RLIMIT_MEMLOCK where the kernel charges rings to it) leaves
    ; the worker on epoll,
    ; which needs no setting at all.
    test    dword [r12 + server.flags], HTTPASM_SERVER_URING
    jz      .epoll
    mov     rdi, rbx
    call    ha_uring_open
    test    eax, eax
    jnz     .epoll                          ; -errno: epoll serves instead
    mov     dword [rbx + worker.epfd], -1   ; no epoll instance (close_worker skips it)
    jmp     .socket
.epoll:
    mov     edi, EPOLL_CLOEXEC
    mov     eax, SYS_epoll_create1
    syscall
    test    eax, eax
    js      .out
    mov     [rbx + worker.epfd], eax
.socket:
    mov     edi, AF_INET
    mov     esi, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC
    xor     edx, edx
    mov     eax, SYS_socket
    syscall
    test    eax, eax
    js      .out
    mov     [rbx + worker.listen_fd], eax
    mov     dword [rsp + 16], 1
    mov     edi, eax
    mov     esi, SOL_SOCKET
    mov     edx, SO_REUSEADDR
    lea     r10, [rsp + 16]
    mov     r8d, 4
    mov     eax, SYS_setsockopt
    syscall
    test    eax, eax
    js      .out
    mov     edi, [rbx + worker.listen_fd]
    mov     esi, SOL_SOCKET
    mov     edx, SO_REUSEPORT
    lea     r10, [rsp + 16]
    mov     r8d, 4
    mov     eax, SYS_setsockopt
    syscall
    test    eax, eax
    js      .out
    ; sockaddr_in: family, port (network order), address (already network order), zero.
    mov     word [rsp], AF_INET
    mov     eax, [r12 + server.port]
    xchg    al, ah
    mov     [rsp + 2], ax
    mov     eax, [r12 + server.bind_address]
    mov     [rsp + 4], eax
    mov     qword [rsp + 8], 0
    mov     edi, [rbx + worker.listen_fd]
    mov     rsi, rsp
    mov     edx, 16
    mov     eax, SYS_bind
    syscall
    test    eax, eax
    js      .out
    mov     edi, [rbx + worker.listen_fd]
    mov     esi, HA_LISTEN_BACKLOG
    mov     eax, SYS_listen
    syscall
    test    eax, eax
    js      .out
    cmp     dword [r12 + server.port], 0
    jne     .port_known
    mov     dword [rsp + 16], 16            ; socklen_t
    mov     edi, [rbx + worker.listen_fd]
    mov     rsi, rsp
    lea     rdx, [rsp + 16]
    mov     eax, SYS_getsockname
    syscall
    test    eax, eax
    js      .out
    movzx   eax, word [rsp + 2]
    xchg    al, ah
    mov     [r12 + server.port], eax
.port_known:
    ; The listener and the eventfd join epoll under their tags (io_uring: their polls are
    ; armed when the worker's loop starts, under the same tags).
    xor     eax, eax
    cmp     dword [rbx + worker.uring], 0
    jne     .out
    mov     dword [rsp], EPOLLIN
    mov     qword [rsp + 4], HA_TAG_LISTENER
    mov     edi, [rbx + worker.epfd]
    mov     esi, EPOLL_CTL_ADD
    mov     edx, [rbx + worker.listen_fd]
    mov     r10, rsp
    mov     eax, SYS_epoll_ctl
    syscall
    test    eax, eax
    js      .out
    mov     dword [rsp], EPOLLIN
    mov     qword [rsp + 4], HA_TAG_WAKE
    mov     edi, [rbx + worker.epfd]
    mov     esi, EPOLL_CTL_ADD
    mov     edx, [rbx + worker.wake_fd]
    mov     r10, rsp
    mov     eax, SYS_epoll_ctl
    syscall
.out:
    add     rsp, 24
    pop     r12
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; close_worker: closes the descriptors a worker opened to run (its listener, and its epoll
; instance or its ring). The eventfd stays: it is the server's, until free_server.
;   In: rdi = worker. Clobbers rax, rcx, rdx, rsi, rdi, r11.
; -----------------------------------------------------------------------------
align 16
close_worker:
    push    rbx
    mov     rbx, rdi
    call    ha_uring_close                  ; nothing when the worker ran on epoll (rsp aligned)
%macro CLOSE_FD 1
    mov     edi, [rbx + %1]
    test    edi, edi
    js      %%skip
    mov     eax, SYS_close
    syscall
    mov     dword [rbx + %1], -1
%%skip:
%endmacro
    CLOSE_FD worker.listen_fd
    CLOSE_FD worker.epfd
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; free_server: closes every worker's eventfd and frees the workers and the server. The server
; must not run, and no completion may wait on a queue (drain_queues).
;   In: rdi = server (its workers array may be NULL). Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
free_server:
    push    rbx
    push    r12
    push    r13                             ; three pushes: rsp aligned for the calls below
    mov     rbx, rdi
    mov     r12, [rbx + server.workers]
    test    r12, r12
    jz      .server
    xor     r13d, r13d
.worker:
    cmp     r13d, [rbx + server.worker_count]
    jae     .workers
    imul    rcx, r13, worker_size
    mov     edi, [r12 + rcx + worker.wake_fd]
    test    edi, edi
    js      .scratch                        ; never made (a failed create)
    mov     eax, SYS_close
    syscall
.scratch:
    ; The worker's HTTP/2 scratch, if it ever served HTTP/2 (free(NULL) is a no-op).
    imul    rcx, r13, worker_size
    mov     rdi, [r12 + rcx + worker.h2_fields]
    call    free wrt ..plt
    imul    rcx, r13, worker_size
    mov     rdi, [r12 + rcx + worker.h2_space]
    call    free wrt ..plt
    imul    rcx, r13, worker_size
    mov     rdi, [r12 + rcx + worker.h2_out]
    call    free wrt ..plt
.next:
    inc     r13d
    jmp     .worker
.workers:
    mov     rdi, r12
    call    free wrt ..plt
.server:
    mov     rdi, rbx
    call    free wrt ..plt
    pop     r13
    pop     r12
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; drain_queues: frees the responses that wait on the workers' queues after the workers
; stopped (deferred exchanges answered after a stop), and the zombie connections they were for
; (every deferred connection a stopping worker closed is a zombie; nothing else references it).
;   In: rdi = server (stopped). Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
align 16
drain_queues:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 16                         ; five pushes + 16: aligned for the calls below
    mov     rbx, rdi
    mov     r12, [rbx + server.workers]
    xor     r13d, r13d
.worker:
    cmp     r13d, [rbx + server.worker_count]
    jae     .out
    imul    rcx, r13, worker_size
    xor     eax, eax
    xchg    rax, [r12 + rcx + worker.queue] ; atomic: a late answer may still be pushing
    mov     r14, rax
.completion:
    test    r14, r14
    jz      .next_worker
    mov     r15, r14
    mov     r14, [r15 + completion.next]
    mov     rdi, [r15 + completion.conn]
    test    dword [rdi + conn.flags], C_ZOMBIE
    jz      .free_completion
    call    ha_conn_free
.free_completion:
    mov     rdi, r15
    call    free wrt ..plt
    jmp     .completion
.next_worker:
    inc     r13d
    jmp     .worker
.out:
    add     rsp, 16
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; int httpasm_server_start(httpasm_server *server)
;   Opens every worker's sockets and starts its thread. Returns 0, or -errno (EADDRINUSE, ...);
;   on failure nothing is left running or open. Starting twice returns -EINVAL.
; -----------------------------------------------------------------------------
global httpasm_server_start:function (httpasm_server_start.end - httpasm_server_start)
align 16
httpasm_server_start:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    mov     rbx, rdi
    mov     eax, -EINVAL
    cmp     dword [rbx + server.started], 0
    jne     .out
    mov     dword [rbx + server.stop], 0
    mov     r12, [rbx + server.workers]
    mov     r13d, [rbx + server.worker_count]
    xor     r14d, r14d
.open:
    cmp     r14d, r13d
    jae     .threads
    imul    rdi, r14, worker_size
    add     rdi, r12
    call    worker_open
    test    eax, eax
    js      .open_failed
    inc     r14d
    jmp     .open
.open_failed:
    mov     r15d, eax
    xor     r14d, r14d
.close_all:
    cmp     r14d, r13d
    jae     .failed
    imul    rdi, r14, worker_size
    add     rdi, r12
    call    close_worker
    inc     r14d
    jmp     .close_all
.threads:
    xor     r14d, r14d
.thread:
    cmp     r14d, r13d
    jae     .started
    imul    rcx, r14, worker_size
    add     rcx, r12                        ; the worker: worker_main's argument
    lea     rdi, [rcx + worker.thread]
    xor     esi, esi
    lea     rdx, [rel worker_main]
    call    pthread_create wrt ..plt
    test    eax, eax
    jnz     .thread_failed
    inc     r14d
    jmp     .thread
.thread_failed:
    neg     eax                             ; pthread_create returns the error number itself
    mov     r15d, eax
    ; Stop the threads already running, then close every worker.
    mov     dword [rbx + server.stop], 1
    mov     r13d, r14d                      ; only these started
    xor     r14d, r14d
.wake_started:
    cmp     r14d, r13d
    jae     .join_started
    imul    rdi, r14, worker_size
    add     rdi, r12
    call    ha_wake_worker
    inc     r14d
    jmp     .wake_started
.join_started:
    xor     r14d, r14d
.join:
    cmp     r14d, r13d
    jae     .close_after_join
    imul    rcx, r14, worker_size
    mov     rdi, [r12 + rcx + worker.thread]
    xor     esi, esi
    call    pthread_join wrt ..plt
    inc     r14d
    jmp     .join
.close_after_join:
    mov     r13d, [rbx + server.worker_count]
    xor     r14d, r14d
    jmp     .close_all
.failed:
    mov     eax, r15d
    jmp     .out
.started:
    mov     dword [rbx + server.started], 1
    xor     eax, eax
.out:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; wake_worker: rings a worker's eventfd. In: rdi = worker. Clobbers caller-saved registers.
; -----------------------------------------------------------------------------
global ha_wake_worker:function hidden (ha_wake_worker.end - ha_wake_worker)
ha_wake_worker:
    sub     rsp, 24
    mov     qword [rsp], 1
    mov     rax, rdi
    mov     edi, [rax + worker.wake_fd]
    mov     rsi, rsp
    mov     edx, 8
    mov     eax, SYS_write
    syscall
    add     rsp, 24
    ret
.end:

; -----------------------------------------------------------------------------
; uint16_t httpasm_server_port(const httpasm_server *server)
;   The port the server listens on: the one asked for, or the one the kernel chose for port 0
;   (known once started).
; -----------------------------------------------------------------------------
global httpasm_server_port:function (httpasm_server_port.end - httpasm_server_port)
align 16
httpasm_server_port:
    movzx   eax, word [rdi + server.port]
    ret
.end:

; -----------------------------------------------------------------------------
; uint32_t httpasm_server_io(const httpasm_server *server)
;   What the running server's workers wait and do their I/O with: HTTPASM_SERVER_IO_URING when
;   every worker has its ring, _EPOLL when none has, _MIXED when some have and some do not, or
;   _NONE when the server is not running. Each worker makes its ring on its own when it opens,
;   so the kernel can refuse some and not others: Linux 6.14 to 7.2 without upstream commit
;   b59cabf9b4ac charge rings to the user's RLIMIT_MEMLOCK, and a user past it gets epoll for
;   the remaining workers (uring.asm, HA_RING_ENTRIES). For tests, measurements and operators that must know what really runs.
;   Every worker's flag is set before httpasm_server_start returns; a stop clears them as the
;   workers exit, so a call racing a stop may see a mix.
;   In: rdi = server. Out: eax. Clobbers rcx, rdx, rsi.
; -----------------------------------------------------------------------------
global httpasm_server_io:function (httpasm_server_io.end - httpasm_server_io)
align 16
httpasm_server_io:
    mov     eax, HTTPASM_SERVER_IO_NONE
    cmp     dword [rdi + server.started], 0
    je      .out
    mov     rcx, [rdi + server.workers]
    mov     edx, [rdi + server.worker_count] ; at least 1: create gives every server a worker
    xor     esi, esi                        ; the workers with a ring
.count:
    cmp     dword [rcx + worker.uring], 0
    je      .next
    inc     esi
.next:
    add     rcx, worker_size
    dec     edx
    jnz     .count
    mov     eax, HTTPASM_SERVER_IO_EPOLL
    test    esi, esi
    jz      .out                            ; none
    mov     eax, HTTPASM_SERVER_IO_URING
    cmp     esi, [rdi + server.worker_count]
    je      .out                            ; all
    mov     eax, HTTPASM_SERVER_IO_MIXED
.out:
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_server_stop(httpasm_server *server)
;   Stops accepting, lets in-flight exchanges finish for up to HA_STOP_GRACE_MS, closes every
;   connection, and returns when every worker thread has exited. A deferred exchange still
;   unanswered after the grace period must not be answered afterwards. Stopping a server that
;   is not running does nothing. The server can be started again.
; -----------------------------------------------------------------------------
global httpasm_server_stop:function (httpasm_server_stop.end - httpasm_server_stop)
align 16
httpasm_server_stop:
    push    rbx
    push    r12
    push    r13
    mov     rbx, rdi
    cmp     dword [rbx + server.started], 0
    je      .out
    mov     dword [rbx + server.stop], 1    ; read by the workers once woken (the eventfd's write orders it)
    mov     r12, [rbx + server.workers]
    xor     r13d, r13d
.wake:
    cmp     r13d, [rbx + server.worker_count]
    jae     .joined_start
    imul    rdi, r13, worker_size
    add     rdi, r12
    call    ha_wake_worker
    inc     r13d
    jmp     .wake
.joined_start:
    xor     r13d, r13d
.join:
    cmp     r13d, [rbx + server.worker_count]
    jae     .closed_start
    imul    rcx, r13, worker_size
    mov     rdi, [r12 + rcx + worker.thread]
    xor     esi, esi
    call    pthread_join wrt ..plt
    inc     r13d
    jmp     .join
.closed_start:
    xor     r13d, r13d
.close:
    cmp     r13d, [rbx + server.worker_count]
    jae     .stopped
    imul    rdi, r13, worker_size
    add     rdi, r12
    call    close_worker
    inc     r13d
    jmp     .close
.stopped:
    mov     dword [rbx + server.started], 0
.out:
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_server_destroy(httpasm_server *server)
;   Stops the server if it runs, frees the responses still waiting for a worker (deferred
;   exchanges answered after the stop) with their connections, and frees the server. NULL does
;   nothing. Every deferred exchange must have been answered before this: an answer after it
;   would use freed memory. (A deferred exchange never answered leaks its connection.)
; -----------------------------------------------------------------------------
global httpasm_server_destroy:function (httpasm_server_destroy.end - httpasm_server_destroy)
align 16
httpasm_server_destroy:
    push    rbx
    mov     rbx, rdi
    test    rbx, rbx
    jz      .out
    call    httpasm_server_stop
    mov     rdi, rbx
    call    drain_queues
    mov     rdi, rbx
    call    free_server
.out:
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; pause_accept: the listener rests for HA_ACCEPT_PAUSE_MS: accept4 ran out of descriptors or
; memory (EMFILE, ENFILE, ENOBUFS, ENOMEM). The connection it could not take stays in the
; backlog, so the listener stays readable: watched again at once (epoll's level-triggered
; interest, or io_uring's poll, level-checked when armed), it would wake the worker again
; and again, a core at full CPU for as long as the descriptors stay exhausted. It is watched
; again (resume_accept) once the pause is over, and the backlog is taken then. nginx does the
; same (it rests 500 ms).
;   epoll: the listener's interest becomes 0 (EPOLL_CTL_MOD; a listening socket reports no
;   error or hang-up). io_uring: its poll is simply not armed again (worker_main's listener
;   completion checks worker.accept_resume).
;   In: rbx = worker (its now_ms current). Clobbers rax, rcx, rdx, rsi, rdi, r8-r11.
; -----------------------------------------------------------------------------
align 16
pause_accept:
    mov     rax, [rbx + worker.now_ms]
    add     rax, HA_ACCEPT_PAUSE_MS
    mov     [rbx + worker.accept_resume], rax
    cmp     dword [rbx + worker.uring], 0
    jne     .out
    sub     rsp, 24                         ; an epoll_event (no call is made: alignment moot)
    mov     dword [rsp], 0
    mov     qword [rsp + 4], HA_TAG_LISTENER
    mov     edi, [rbx + worker.epfd]
    mov     esi, EPOLL_CTL_MOD
    mov     edx, [rbx + worker.listen_fd]
    mov     r10, rsp
    mov     eax, SYS_epoll_ctl
    syscall
    add     rsp, 24
.out:
    ret

; -----------------------------------------------------------------------------
; resume_accept: a resting listener (pause_accept) is watched again: epoll's interest is EPOLLIN
; again, or io_uring's poll is armed. The backlog that waited is reported at once (a level
; check), and accept_all takes it; if descriptors are still short, it rests again. A listener
; closed meanwhile (a stop) is not watched: only the pause ends.
;   In: rbx = worker. Clobbers every caller-saved register. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
align 16
resume_accept:
    sub     rsp, 24                         ; an epoll_event; rsp aligned for the call below
    mov     qword [rbx + worker.accept_resume], 0
    cmp     dword [rbx + worker.listen_fd], 0
    jl      .out
    cmp     dword [rbx + worker.uring], 0
    jne     .ring
    mov     dword [rsp], EPOLLIN
    mov     qword [rsp + 4], HA_TAG_LISTENER
    mov     edi, [rbx + worker.epfd]
    mov     esi, EPOLL_CTL_MOD
    mov     edx, [rbx + worker.listen_fd]
    mov     r10, rsp
    mov     eax, SYS_epoll_ctl
    syscall
    jmp     .out
.ring:
    mov     rdi, rbx
    mov     esi, [rbx + worker.listen_fd]
    mov     edx, HA_TAG_LISTENER
    call    ha_uring_poll
.out:
    add     rsp, 24
    ret

; -----------------------------------------------------------------------------
; accept_all: accepts every pending connection (a new connection per accept4 until EAGAIN).
; When accept4 runs out of descriptors or memory, the listener rests (pause_accept).
;   In: rbx = worker, r12 = server. Keeps rbx, rbp, r12-r15 (r13, r14 saved here). Clobbers
;   the caller-saved registers.
; -----------------------------------------------------------------------------
align 16
accept_all:
    push    r13
    push    r14
    sub     rsp, 24                         ; an epoll_event / an option value; rsp aligned
.next:
    mov     edi, [rbx + worker.listen_fd]
    xor     esi, esi
    xor     edx, edx
    mov     r10d, SOCK_NONBLOCK | SOCK_CLOEXEC
    mov     eax, SYS_accept4
    syscall
    cmp     rax, -EINTR
    je      .next
    test    eax, eax
    js      .failed
    mov     r13d, eax                       ; the descriptor
    cmp     dword [rbx + worker.stopping], 0
    jne     .refuse
    mov     edi, 1
    mov     esi, conn_size
    call    calloc wrt ..plt
    test    rax, rax
    jz      .refuse
    mov     r14, rax
    mov     [r14 + conn.fd], r13d
    mov     [r14 + conn.worker], rbx
    mov     edi, HA_BUFFER_INITIAL
    call    malloc wrt ..plt
    mov     [r14 + conn.rbuf], rax
    test    rax, rax
    jz      .free_conn
    mov     qword [r14 + conn.rcap], HA_BUFFER_INITIAL
    mov     edi, HA_BUFFER_INITIAL
    call    malloc wrt ..plt
    mov     [r14 + conn.wbuf], rax
    test    rax, rax
    jz      .free_conn
    mov     qword [r14 + conn.wcap], HA_BUFFER_INITIAL
    mov     eax, [r12 + server.limits + httpasm_h1_limits.max_fields]
    mov     ecx, HA_H1_DEFAULT_MAX_FIELDS
    test    eax, eax
    cmovz   eax, ecx
    shl     eax, 5
    mov     edi, eax
    call    malloc wrt ..plt
    mov     [r14 + conn.fields], rax
    test    rax, rax
    jz      .free_conn
    ; TCP_NODELAY: responses leave as soon as they are written (each flush is one whole batch).
    mov     dword [rsp + 16], 1
    mov     edi, r13d
    mov     esi, IPPROTO_TCP
    mov     edx, TCP_NODELAY
    lea     r10, [rsp + 16]
    mov     r8d, 4
    mov     eax, SYS_setsockopt
    syscall
    ; The worker's wait: epoll registers it now; io_uring arms its poll at the next
    ; submission (it is pending; its counts belong to this ring).
    cmp     dword [rbx + worker.uring], 0
    jne     .ring
    mov     dword [rsp], EPOLLIN | EPOLLRDHUP
    mov     [rsp + 4], r14
    mov     edi, [rbx + worker.epfd]
    mov     esi, EPOLL_CTL_ADD
    mov     edx, r13d
    mov     r10, rsp
    mov     eax, SYS_epoll_ctl
    syscall
    test    eax, eax
    js      .free_conn
    mov     dword [r14 + conn.pad], EPOLLIN | EPOLLRDHUP
    jmp     .joined
.ring:
    mov     eax, [rbx + worker.ring_gen]
    mov     [r14 + conn.ring_gen], eax
    mov     rdi, r14
    call    ha_uring_pending                ; conn.pad stays 0: nothing armed yet
.joined:
    inc     qword [rbx + worker.conn_count]
    mov     rdi, r14
    call    ha_lru_touch
    jmp     .next
.free_conn:
    mov     rdi, r14
    call    ha_conn_free
.refuse:
    mov     edi, r13d
    mov     eax, SYS_close
    syscall
    jmp     .next
.failed:
    ; EAGAIN: no more. A failure of one connection's own (ECONNABORTED, and the network errors
    ; accept4 passes on) used that connection up: if more wait, the listener is still readable
    ; and the next wait reports it. Out of descriptors or memory, the connection stays queued
    ; and nothing changes until a descriptor frees: the listener rests (pause_accept).
    cmp     eax, -EMFILE
    je      .pause
    cmp     eax, -ENFILE
    je      .pause
    cmp     eax, -ENOBUFS
    je      .pause
    cmp     eax, -ENOMEM
    jne     .done
.pause:
    call    pause_accept
.done:
    add     rsp, 24
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; read_ready: a connection's socket is readable (or its peer half-closed).
;   In: rdi = conn, esi = the epoll events. Keeps rbx, rbp, r12-r15 (r13 saved here). Clobbers
;   the caller-saved registers.
; -----------------------------------------------------------------------------
align 16
read_ready:
    push    r13                             ; also aligns rsp for the calls below
    mov     r13, rdi
    test    dword [r13 + conn.flags], C_DRAINING
    jnz     .drain
    test    dword [r13 + conn.flags], C_DEFERRED
    jnz     .deferred_event
    mov     rax, [r13 + conn.rlen]
    cmp     rax, [r13 + conn.rcap]
    jb      .read
    ; The input is full: the processing will make room or answer 413/431.
    mov     rdi, r13
    call    ha_conn_drive
    jmp     .out
.read:
    mov     edi, [r13 + conn.fd]
    mov     rsi, [r13 + conn.rbuf]
    add     rsi, [r13 + conn.rlen]
    mov     rdx, [r13 + conn.rcap]
    sub     rdx, [r13 + conn.rlen]
    xor     r10d, r10d
    xor     r8d, r8d
    xor     r9d, r9d
    mov     eax, SYS_recvfrom
    syscall
    cmp     rax, -EINTR
    je      .read
    cmp     rax, -EAGAIN
    je      .out
    test    rax, rax
    jz      .eof
    js      .close
    add     [r13 + conn.rlen], rax
    INPUT_PROGRESS r13, rax                 ; a body's octets keep it alive, a head's do not
    mov     rdi, r13
    call    ha_conn_drive
    jmp     .out
.eof:
    ; The peer finished sending (it may have half-closed after its last request and still
    ; read the answer): whatever it sent is answered first, then the connection closes
    ; (ha_conn_drive sees C_PEER_DONE). A deferred answer is waited for; nothing more can
    ; arrive, so EPOLLRDHUP is not asked again (every interest update now leaves it out).
    or      dword [r13 + conn.flags], C_PEER_DONE
    mov     rdi, r13
    call    ha_conn_drive
    jmp     .out
.close:
    mov     rdi, r13
    call    ha_conn_close
    jmp     .out
.drain:
    ; After a closing response: read and discard until the peer closes.
    mov     edi, [r13 + conn.fd]
    mov     rsi, [r13 + conn.rbuf]
    mov     rdx, [r13 + conn.rcap]
    xor     r10d, r10d
    xor     r8d, r8d
    xor     r9d, r9d
    mov     eax, SYS_recvfrom
    syscall
    test    rax, rax
    jg      .drain
    cmp     rax, -EAGAIN
    je      .out
    cmp     rax, -EINTR
    je      .drain
    jmp     .close
.deferred_event:
    ; Deferred: only EPOLLRDHUP was asked for. The peer finished sending, but may still read
    ; the answer (a half-close after the request): keep the connection, stop asking. A reset
    ; peer comes as EPOLLERR/EPOLLHUP instead, and closes it (a zombie until the answer).
    test    esi, EPOLLRDHUP
    jz      .out                            ; anything else is stale: nothing to do while deferred
    or      dword [r13 + conn.flags], C_PEER_DONE
    mov     rdi, r13
    call    ha_set_interest
.out:
    pop     r13
    ret

; -----------------------------------------------------------------------------
; handle_completions: takes every response other threads posted for deferred exchanges, in
; posting order, and answers with each.
;   In: rbx = worker. Keeps rbx, rbp, r12-r15 (r13-r15 saved here). Clobbers the caller-saved
;   registers.
; -----------------------------------------------------------------------------
align 16
handle_completions:
    push    r13
    push    r14
    push    r15                             ; three pushes: rsp is 16-byte aligned for the calls
    xor     eax, eax
    xchg    rax, [rbx + worker.queue]       ; take the whole stack at once (xchg is atomic)
    ; The stack is newest first: reverse it.
    xor     r14d, r14d
.reverse:
    test    rax, rax
    jz      .reversed
    mov     rcx, [rax + completion.next]
    mov     [rax + completion.next], r14
    mov     r14, rax
    mov     rax, rcx
    jmp     .reverse
.reversed:
    test    r14, r14
    jz      .out
    mov     r15, r14
    mov     r14, [r15 + completion.next]
    mov     r13, [r15 + completion.conn]
    dec     dword [r13 + conn.deferred]     ; one answer fewer outstanding on its connection
    cmp     qword [r15 + completion.stream], 0
    jne     .h2
    test    dword [r13 + conn.flags], C_ZOMBIE
    jz      .live
    mov     rdi, r15                        ; its client is gone: drop the response, and the
    call    free wrt ..plt                  ; connection after this batch
.zombie_answered:
    cmp     dword [r13 + conn.deferred], 0
    jne     .reversed                       ; HTTP/2: other streams' answers still to come
    dec     qword [rbx + worker.zombies]
    mov     rdi, r13
    call    ha_conn_release
    jmp     .reversed
.h2:
    ; An HTTP/2 stream's answer: the worker encodes and frames it (a stream detached meanwhile
    ; is freed and the answer dropped), then the output goes.
    mov     rdi, r13
    mov     rsi, r15
    call    ha_h2_completion
    mov     rdi, r15
    call    free wrt ..plt
    test    dword [r13 + conn.flags], C_ZOMBIE
    jnz     .zombie_answered
    mov     rdi, r13
    call    ha_conn_drive
    jmp     .reversed
.live:
    and     dword [r13 + conn.flags], ~C_DEFERRED
    mov     dword [r13 + conn.exchange + exchange.state], X_RESPONDED
    mov     rdi, r13
    lea     rsi, [r15 + completion_size]
    mov     rdx, [r15 + completion.length]
    call    ha_conn_append
    test    eax, eax
    jnz     .append_failed
    cmp     dword [r15 + completion.close], 0
    je      .appended
    or      dword [r13 + conn.flags], C_CLOSE_AFTER
.appended:
    mov     rdi, r15
    call    free wrt ..plt
    mov     rdi, r13
    call    ha_conn_finish
    mov     rdi, r13
    call    ha_set_interest                 ; reading resumes
    mov     rdi, r13
    call    ha_conn_drive                   ; the answer, and pipelined requests already here
    jmp     .reversed
.append_failed:
    ; No memory for the response: the client can never get it, so the connection closes
    ; rather than leave it waiting (no longer deferred: closed outright, not a zombie).
    mov     rdi, r15
    call    free wrt ..plt
    mov     rdi, r13
    call    ha_conn_close
    jmp     .reversed
.out:
    pop     r15
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; refresh_clock: the worker's monotonic now, and its Date value when the second changed.
;   In: rbx = worker. Clobbers caller-saved registers. The 24-octet frame aligns rsp for the
;   calls (entered with rsp 8 past a 16-octet boundary).
; -----------------------------------------------------------------------------
align 16
refresh_clock:
    sub     rsp, 24
    call    monotonic_ms
    mov     [rbx + worker.now_ms], rax
    mov     edi, CLOCK_REALTIME_COARSE
    mov     rsi, rsp
    call    clock_gettime wrt ..plt
    mov     rax, [rsp]
    cmp     rax, [rbx + worker.date_second]
    je      .out
    lea     rdi, [rbx + worker.date]
    call    ha_date_format
    mov     [rbx + worker.date_second], rax
.out:
    add     rsp, 24
    ret

; -----------------------------------------------------------------------------
; begin_stop: closes the listener and every connection between requests; the rest finish.
;   In: rbx = worker. Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
align 16
begin_stop:
    sub     rsp, 8                          ; aligned for the call below
    mov     dword [rbx + worker.stopping], 1
    mov     rax, [rbx + worker.now_ms]
    add     rax, HA_STOP_GRACE_MS
    mov     [rbx + worker.stop_deadline], rax
    cmp     dword [rbx + worker.uring], 0
    je      .close_listener
    ; io_uring: the listener's poll holds its file, so the socket would outlive its descriptor
    ; (and keep taking connections into its queue through SO_REUSEPORT). The poll goes first,
    ; submitted at once; its removal completes inside that call.
    mov     rdi, rbx
    mov     esi, HA_TAG_LISTENER
    call    ha_uring_unpoll
    mov     rdi, rbx
    call    ha_uring_submit
.close_listener:
    mov     edi, [rbx + worker.listen_fd]
    mov     eax, SYS_close
    syscall
    mov     dword [rbx + worker.listen_fd], -1
    call    close_idle
    add     rsp, 8
    ret

; close_idle: closes every connection with no request in progress and nothing to send (an
; HTTP/2 one says GOAWAY as it closes: ha_conn_close). An HTTP/2 connection gets a graceful
; stop's notice first, once (ha_h2_notice: GOAWAY with the last stream 2^31 - 1, then a PING,
; RFC9113-6.8-18), so its client opens nothing new; a later call closes it once its streams are
; done and the PING has come back, the round trip after which no request of the client's can
; still be on its way. Called only while the worker is stopping.
;   In: rbx = worker. Keeps rbx, rbp, r12-r15 (r13, r14 saved here).
align 16
close_idle:
    push    r13
    push    r14
    sub     rsp, 8                          ; aligned for the calls below
    mov     r13, [rbx + worker.lru_head]
.next:
    test    r13, r13
    jz      .out
    mov     r14, [r13 + conn.lru_next]      ; the close unlinks r13
    cmp     dword [r13 + conn.state], CS_HEAD
    jne     .skip
    cmp     qword [r13 + conn.rlen], 0
    jne     .skip
    test    dword [r13 + conn.flags], C_DEFERRED | C_WANT_WRITE | C_SEND_QUEUED
    jnz     .skip                           ; output waits: the socket's (epoll) or the ring's
    cmp     dword [r13 + conn.deferred], 0
    jne     .skip                           ; HTTP/2: a stream's answer is still to come
    mov     rax, [r13 + conn.h2]
    test    rax, rax
    jz      .idle
    cmp     dword [rax + h2.stream_count], 0
    jne     .skip                           ; HTTP/2: requests in progress
    ; Idle HTTP/2: it closes only once the notice's PING came back (ha_h2_notice), or when the
    ; client is leaving or the connection is closing anyway; until then a request may still be
    ; on its way, and it would be refused. A client that never answers is closed at the stop's
    ; deadline (.force in worker_main), like any connection still open then.
    test    dword [rax + h2.flags], H2F_NOTICE_ACKED | H2F_CLOSING | H2F_GOAWAY_RECEIVED
    jz      .skip
.idle:
    mov     rdi, r13
    call    ha_conn_close
    jmp     .advance
.skip:
    ; Kept open for its requests: an HTTP/2 client is told the stop has begun (once; the
    ; notice may close the connection when its flush fails, which r14 already stepped past).
    mov     rdi, r13
    call    ha_h2_notice                    ; nothing for HTTP/1.1 (conn.h2 = 0)
.advance:
    mov     r13, r14
    jmp     .next
.out:
    add     rsp, 8
    pop     r14
    pop     r13
    ret

; -----------------------------------------------------------------------------
; worker_main: a worker thread's loop (see this file's header).
;   In: rdi = worker (pthread's argument). Out: rax = NULL.
; -----------------------------------------------------------------------------
align 16
worker_main:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 8
    mov     rbx, rdi
    mov     r12, [rbx + worker.server]
    call    refresh_clock
    cmp     dword [rbx + worker.uring], 0
    je      .wait
    ; io_uring: the listener's and the eventfd's polls, armed once here and again after each
    ; completion (one-shot, as every poll of the ring; level-checked when armed).
    mov     rdi, rbx
    mov     esi, [rbx + worker.listen_fd]
    mov     edx, HA_TAG_LISTENER
    call    ha_uring_poll
    mov     rdi, rbx
    mov     esi, [rbx + worker.wake_fd]
    mov     edx, HA_TAG_WAKE
    call    ha_uring_poll

.wait:
    ; The timeout: the earliest deadline, or none at all; a resting listener's return
    ; (pause_accept); while stopping, the grace's end too.
    mov     rdx, -1
    mov     rax, [rbx + worker.lru_head]
    test    rax, rax
    jz      .no_deadline
    mov     rdx, [rax + conn.deadline]
    sub     rdx, [rbx + worker.now_ms]
    jns     .no_deadline
    xor     edx, edx
.no_deadline:
    mov     rax, [rbx + worker.accept_resume]
    test    rax, rax
    jz      .accepting
    sub     rax, [rbx + worker.now_ms]
    jns     .pause_left
    xor     eax, eax
.pause_left:
    cmp     rdx, -1
    je      .take_pause
    cmp     rax, rdx
    jae     .accepting
.take_pause:
    mov     rdx, rax
.accepting:
    cmp     dword [rbx + worker.stopping], 0
    je      .timeout_set
    mov     rax, [rbx + worker.stop_deadline]
    sub     rax, [rbx + worker.now_ms]
    jns     .grace_left
    xor     eax, eax
.grace_left:
    cmp     rdx, -1
    je      .take_grace
    cmp     rax, rdx
    jae     .timeout_set
.take_grace:
    mov     rdx, rax
.timeout_set:
    cmp     rdx, 0x7FFFFFFF
    jbe     .timeout_ok
    cmp     rdx, -1
    je      .timeout_ok
    mov     edx, 0x7FFFFFFF
.timeout_ok:
    cmp     dword [rbx + worker.uring], 0
    jne     .uring_wait
    mov     edi, [rbx + worker.epfd]
    lea     rsi, [rbx + worker.events]
    mov     r10d, edx
    mov     edx, HA_EVENTS
    mov     eax, SYS_epoll_wait
    syscall
    mov     ebp, eax
    test    ebp, ebp
    jns     .woken
    xor     ebp, ebp                        ; EINTR: no events
.woken:
    call    refresh_clock
    xor     r15d, r15d
.event:
    cmp     r15d, ebp
    jae     .events_done
    imul    rcx, r15, EPOLL_EVENT_SIZE
    lea     rcx, [rbx + worker.events + rcx]
    mov     eax, [rcx]                      ; the events
    mov     rdi, [rcx + 4]                  ; the data
    inc     r15d
    cmp     rdi, HA_TAG_LISTENER
    je      .listener
    cmp     rdi, HA_TAG_WAKE
    je      .wake
    ; A connection closed earlier in this batch (its memory waits for the reap): skip it.
    test    dword [rdi + conn.flags], C_CLOSED | C_ZOMBIE
    jnz     .event
    test    eax, EPOLLERR | EPOLLHUP
    jnz     .error_event
    test    eax, EPOLLOUT
    jz      .readable
    mov     r14, rdi                        ; the connection (every helper keeps r14)
    call    ha_conn_flush                   ; the socket drained: send the rest
    test    eax, eax
    jnz     .event                          ; closed
    test    dword [r14 + conn.flags], C_WANT_WRITE
    jnz     .event                          ; still full
    mov     rdi, r14
    call    ha_conn_drive                   ; answer what waited behind the back-pressure
    jmp     .event
.readable:
    mov     esi, eax                        ; the events
    call    read_ready
    jmp     .event
.error_event:
    call    ha_conn_close
    jmp     .event
.listener:
    call    accept_all
    jmp     .event
.wake:
    sub     rsp, 8                          ; drain the eventfd's counter
    mov     edi, [rbx + worker.wake_fd]
    mov     rsi, rsp
    mov     edx, 8
    mov     eax, SYS_read
    syscall
    add     rsp, 8
    call    handle_completions
    cmp     dword [r12 + server.stop], 0
    je      .event
    cmp     dword [rbx + worker.stopping], 0
    jne     .event
    call    begin_stop
    jmp     .event

.uring_wait:
    ; io_uring (uring.asm): the pending connections' work is submitted and the worker waits, in
    ; one io_uring_enter; then every completion is handled in order. The eventfd's only notes
    ; that the deferred answers are due: they are taken after all of the batch's completions,
    ; so no buffer moves between an operation and the handling of its completion.
    mov     rdi, rbx
    mov     rsi, rdx                        ; the timeout: ms, or -1 for none
    call    ha_uring_enter
    call    refresh_clock
.completion:
    mov     rdi, rbx
    call    ha_uring_cqe                    ; rax = user_data (0: none left), edx = res, ecx = flags
    test    rax, rax
    jz      .completions_done
    cmp     rax, 16
    jb      .own                            ; below 16: never a connection's (driver.inc)
    mov     esi, eax
    and     esi, UT_MASK                    ; the operation
    and     rax, ~UT_MASK                   ; the connection
    mov     rdi, rax
    call    ha_uring_conn                   ; edx = res and ecx = flags, as ha_uring_cqe left them
    jmp     .completion
.own:
    cmp     rax, HA_TAG_LISTENER
    je      .uring_listener
    cmp     rax, HA_TAG_WAKE
    jne     .completion                     ; UD_IGNORE: a poll update's or removal's
    mov     dword [rbx + worker.wake_due], 1
    jmp     .completion
.uring_listener:
    test    edx, edx
    js      .completion                     ; removed by the stop (or failed): not armed again
    call    accept_all
    cmp     dword [rbx + worker.listen_fd], 0
    jl      .completion                     ; closed meanwhile: nothing to arm
    cmp     qword [rbx + worker.accept_resume], 0
    jne     .completion                     ; resting (pause_accept): resume_accept arms it
    mov     rdi, rbx
    mov     esi, [rbx + worker.listen_fd]
    mov     edx, HA_TAG_LISTENER
    call    ha_uring_poll
    jmp     .completion
.completions_done:
    cmp     dword [rbx + worker.wake_due], 0
    je      .events_done
    mov     dword [rbx + worker.wake_due], 0
    mov     rdi, rbx                        ; armed again before the drain: a write after the
    mov     esi, [rbx + worker.wake_fd]     ; drain still finds it armed (level-checked when the
    mov     edx, HA_TAG_WAKE                ; next submission arms it)
    call    ha_uring_poll
    sub     rsp, 8                          ; drain the eventfd's counter
    mov     edi, [rbx + worker.wake_fd]
    mov     rsi, rsp
    mov     edx, 8
    mov     eax, SYS_read
    syscall
    add     rsp, 8
    call    handle_completions
    cmp     dword [r12 + server.stop], 0
    je      .events_done
    cmp     dword [rbx + worker.stopping], 0
    jne     .events_done
    call    begin_stop

.events_done:
    ; A resting listener (pause_accept) whose pause is over is watched again; its backlog is
    ; reported by the next wait.
    mov     rax, [rbx + worker.accept_resume]
    test    rax, rax
    jz      .expire
    cmp     rax, [rbx + worker.now_ms]
    ja      .expire
    call    resume_accept
    ; Deadlines: each connection whose window ended is judged (ha_conn_expire): a deferred
    ; exchange, or a transfer that kept min_data_rate, gets another window (to the list's tail
    ; with a future deadline, so the loop ends at it at the latest); anything else closes.
.expire:
    mov     r13, [rbx + worker.lru_head]
    test    r13, r13
    jz      .expired
    mov     rax, [r13 + conn.deadline]
    cmp     rax, [rbx + worker.now_ms]
    ja      .expired
    mov     rdi, r13
    call    ha_conn_expire
    test    eax, eax
    jnz     .expire                         ; kept: a new window
    mov     rdi, r13
    call    ha_conn_close
    jmp     .expire
.expired:
    cmp     dword [rbx + worker.stopping], 0
    je      .reap
    call    close_idle
    cmp     qword [rbx + worker.conn_count], 0
    jne     .grace
    cmp     qword [rbx + worker.zombies], 0
    je      .exit                           ; nothing in flight: done
.grace:
    mov     rax, [rbx + worker.now_ms]
    cmp     rax, [rbx + worker.stop_deadline]
    jb      .reap
.force:                                     ; the grace is over: close everything left
    mov     rdi, [rbx + worker.lru_head]
    test    rdi, rdi
    jz      .exit
    call    ha_conn_close
    jmp     .force
.reap:
    ; The batch is done: no event can name the connections closed in it any more.
    mov     rdi, rbx
    call    ha_conn_reap
    jmp     .wait
.exit:
    ; Answers that came meanwhile release their zombies; then everything closed is freed.
    ; Zombies still unanswered stay: their answers find the queue later (the next start, or
    ; httpasm_server_destroy, frees them). The ring goes before the reap: closing it cancels
    ; the polls still armed, no completion can name a connection after that, and the reap
    ; frees every closed connection whatever its counts (worker.uring is 0 then).
    call    handle_completions
    mov     rdi, rbx
    call    ha_uring_close                  ; nothing under epoll
    mov     rdi, rbx
    call    ha_conn_reap
    xor     eax, eax
    add     rsp, 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
