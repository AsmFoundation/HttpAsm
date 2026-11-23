; =============================================================================
; uring.asm - the driver's io_uring backend: each worker's ring, used in place of epoll when the
; server's options ask for it (HTTPASM_SERVER_URING) and the kernel offers it (Linux 5.13 or
; later; built and tested on 5.15: a wait with a timeout, SEND and RECV that honor
; MSG_DONTWAIT). Where io_uring is refused (seccomp in Docker's default profile, an older
; kernel, a user past RLIMIT_MEMLOCK on 6.14+), the worker falls back to epoll by itself.
;
; Not the default: on Linux 5.15 this design measured 5.10-5.46 us of server CPU per HTTP/1.1
; keep-alive request against epoll's 4.99, and never cheaper than epoll in any of five
; interleaved rounds; the same as epoll pipelined and over HTTP/2 (benchmarks/README.md). The likely cost is the
; one-shot poll armed again for every request, which epoll's lasting registration does not
; pay; multishot polls, registered descriptors, and on newer kernels DEFER_TASKRUN, multishot
; RECV into provided buffers and zero-copy SEND are the levers to measure next.
;
; How it works. Readiness stays level-triggered, as under epoll: one POLL_ADD per connection,
; one-shot, armed with the events ha_interest_mask gives; when they change while it is armed,
; it is removed and armed anew on its completion. The I/O is batched: the RECVs and SENDs of
; every connection that became ready, and every poll to arm or remove, reach the kernel in the
; one io_uring_enter that then waits for the next events, instead of one system call each.
;
; Safety, by construction:
;   - Every RECV and SEND carries MSG_DONTWAIT, so it completes (or fails with EAGAIN) inside
;     the io_uring_enter that submits it: the kernel never keeps a pointer into a connection's
;     buffers past that call, and the buffers move and compact as they do under epoll.
;   - A connection's SQEs are written only by the submission walk (ha_uring_enter), right
;     before io_uring_enter, from the connection's state at that moment. A connection closed in
;     between is skipped, so no SQE can name a descriptor number the kernel has since given to
;     a new connection. (Only the listener's and the eventfd's polls are queued directly: those
;     descriptors outlive every SQE that names them.)
;   - A connection's operations are counted (conn.uops) until their completions are handled; a
;     closed connection is freed only at 0 (ha_conn_reap): the walk removes its armed poll, and
;     that poll's completion is its last reference.
;   - Completions are handled in submission order (a connection's SEND before its RECV, queued
;     so), and deferred answers only after all of a batch's completions (the eventfd's poll only
;     sets .wake_due), so nothing moves a buffer between an operation and its completion's
;     handling.
; =============================================================================
default rel
%include "httpasm.inc"
%include "internal/driver.inc"

SYS_mmap                equ 9
SYS_munmap              equ 11
SYS_io_uring_setup      equ 425
SYS_io_uring_enter      equ 426
PROT_READ_WRITE         equ 3
MAP_SHARED_POPULATE     equ 0x8001      ; MAP_SHARED | MAP_POPULATE: no page faults on first use
IORING_OFF_SQES         equ 0x10000000  ; the SQE array's mmap offset (the rings' is 0)
IORING_SETUP_CQSIZE     equ 0x08
IORING_SETUP_CLAMP      equ 0x10
IORING_FEAT_SINGLE_MMAP equ 0x001
IORING_FEAT_NODROP      equ 0x002       ; completions are never lost to a full CQ ring
IORING_FEAT_EXT_ARG     equ 0x100       ; io_uring_enter waits with a timeout (5.11)
IORING_FEAT_RSRC_TAGS   equ 0x400       ; 5.13: the oldest release accepted (tested on 5.15)
URING_FEATURES          equ IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP | IORING_FEAT_EXT_ARG | IORING_FEAT_RSRC_TAGS
IORING_ENTER_GETEVENTS  equ 1
IORING_ENTER_EXT_ARG    equ 8
IORING_OP_POLL_ADD      equ 6
IORING_OP_POLL_REMOVE   equ 7
IORING_OP_SEND          equ 26
IORING_OP_RECV          equ 27
ENOSYS                  equ 38
; The ring's size is a budget. Linux 6.14 and later charge every page of a ring (the SQ and CQ
; rings, the SQE array) to the user's RLIMIT_MEMLOCK, shared by all of that user's processes
; (8 MiB by default on Ubuntu 24.04): 4096 SQEs and 16384 CQEs took 132 pages a worker, so ten
; to fifteen workers exhausted it and the rest fell back to epoll (the CI runner's kernel 7.0
; showed it). These sizes take 21 pages (84 KiB), or 36 while the kernel can also charge the
; rounding of its allocation to a power of two: 57 to 97 workers per 8 MiB. Neither size limits
; correctness:
;   - SQEs: a walk that queues more submits them in parts (ha_uring_sqe), 256 per system call,
;     already ~1/256 of a call per operation;
;   - CQEs: a worker has one poll per connection and the RECVs and SENDs of the turn in flight;
;     past 4096 at once (more than ~1300 connections active in one turn), the kernel keeps the
;     rest in its overflow list (IORING_FEAT_NODROP) and hands them over, in order, as the ring
;     is drained: slower, never lost (unless that list's own allocation fails, under memory
;     pressure, when a connection may wait for its idle timeout instead).
HA_RING_ENTRIES         equ 256         ; SQEs (16 KiB)
HA_RING_CQ_ENTRIES      equ 4096        ; CQEs (64 KiB, with the SQ ring's index array beside them)

; struct io_uring_params (120 octets) and its two offset records.
P_SQ_ENTRIES    equ 0
P_CQ_ENTRIES    equ 4
P_FLAGS         equ 8
P_FEATURES      equ 20
P_SQ_OFF        equ 40
P_CQ_OFF        equ 80
P_SIZE          equ 120
SQO_HEAD        equ 0
SQO_TAIL        equ 4
SQO_MASK        equ 8
SQO_ARRAY       equ 24
CQO_HEAD        equ 0
CQO_TAIL        equ 4
CQO_MASK        equ 8
CQO_CQES        equ 20
; struct io_uring_sqe (64 octets).
SQE_OPCODE      equ 0
SQE_FD          equ 4
SQE_ADDR        equ 16
SQE_LEN         equ 24
SQE_OPFLAGS     equ 28      ; msg_flags (SEND, RECV), poll32_events (POLL_ADD)
; conn.pad under io_uring: the events of the armed poll, or this while its removal is on its way
; (a bit no event uses): the walk sends one removal and waits for the poll's completion.
POLL_REMOVING   equ 0x80000000
SQE_USER_DATA   equ 32

section .text

; -----------------------------------------------------------------------------
; ha_uring_open: the worker's ring: io_uring_setup, then its rings and SQEs mapped. It is used
; only when the kernel has every feature this backend relies on (URING_FEATURES); otherwise the
; ring is closed again and the worker uses epoll.
;   In: rdi = worker. Out: eax = 0 (worker.uring = 1, a new ring_gen), or -errno: -ENOSYS for a
;   kernel without the features, -EPERM where seccomp refuses io_uring (nothing stays open).
;   Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
O_PARAMS    equ 0       ; struct io_uring_params
O_FRAME     equ 128     ; three pushes + 128: aligned

global ha_uring_open:function hidden (ha_uring_open.end - ha_uring_open)
align 16
ha_uring_open:
    push    rbx
    push    r12
    push    r13
    sub     rsp, O_FRAME
    mov     rbx, rdi
    lea     rdi, [rsp + O_PARAMS]
    xor     eax, eax
    mov     ecx, P_SIZE / 8
    rep     stosq                           ; params zeroed: every field not set is a default
    mov     dword [rsp + O_PARAMS + P_FLAGS], IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP
    mov     dword [rsp + O_PARAMS + P_CQ_ENTRIES], HA_RING_CQ_ENTRIES
    mov     edi, HA_RING_ENTRIES
    lea     rsi, [rsp + O_PARAMS]
    mov     eax, SYS_io_uring_setup
    syscall
    test    eax, eax
    js      .out                            ; -ENOSYS (no io_uring), -EPERM (seccomp), ...
    mov     r12d, eax                       ; the ring's descriptor
    mov     eax, [rsp + O_PARAMS + P_FEATURES]
    and     eax, URING_FEATURES
    cmp     eax, URING_FEATURES
    jne     .unsupported

    ; The SQ and CQ rings share one mapping, as large as the larger of the two.
    mov     eax, [rsp + O_PARAMS + P_SQ_ENTRIES]
    shl     eax, 2
    add     eax, [rsp + O_PARAMS + P_SQ_OFF + SQO_ARRAY]
    mov     ecx, [rsp + O_PARAMS + P_CQ_ENTRIES]
    shl     ecx, 4
    add     ecx, [rsp + O_PARAMS + P_CQ_OFF + CQO_CQES]
    cmp     eax, ecx
    cmovb   eax, ecx
    mov     r13d, eax                       ; the mapping's size
    xor     edi, edi
    mov     esi, eax
    mov     edx, PROT_READ_WRITE
    mov     r10d, MAP_SHARED_POPULATE
    mov     r8d, r12d
    xor     r9d, r9d                        ; IORING_OFF_SQ_RING
    mov     eax, SYS_mmap
    syscall
    cmp     rax, -4096
    ja      .close_ring                     ; -errno
    mov     [rbx + worker.ring_map], rax
    mov     [rbx + worker.ring_map_size], r13
    mov     ecx, [rsp + O_PARAMS + P_SQ_OFF + SQO_HEAD]
    lea     rdx, [rax + rcx]
    mov     [rbx + worker.sq_khead], rdx
    mov     ecx, [rsp + O_PARAMS + P_SQ_OFF + SQO_TAIL]
    lea     rdx, [rax + rcx]
    mov     [rbx + worker.sq_ktail], rdx
    mov     ecx, [rsp + O_PARAMS + P_SQ_OFF + SQO_MASK]
    mov     ecx, [rax + rcx]
    mov     [rbx + worker.sq_mask], ecx
    mov     ecx, [rsp + O_PARAMS + P_SQ_ENTRIES]
    mov     [rbx + worker.sq_entries], ecx
    mov     ecx, [rsp + O_PARAMS + P_CQ_OFF + CQO_HEAD]
    lea     rdx, [rax + rcx]
    mov     [rbx + worker.cq_khead], rdx
    mov     ecx, [rsp + O_PARAMS + P_CQ_OFF + CQO_TAIL]
    lea     rdx, [rax + rcx]
    mov     [rbx + worker.cq_ktail], rdx
    mov     ecx, [rsp + O_PARAMS + P_CQ_OFF + CQO_MASK]
    mov     ecx, [rax + rcx]
    mov     [rbx + worker.cq_mask], ecx
    mov     ecx, [rsp + O_PARAMS + P_CQ_OFF + CQO_CQES]
    lea     rdx, [rax + rcx]
    mov     [rbx + worker.cqes], rdx
    ; The SQ array maps ring slot i to SQE i, once and for good: SQEs are then simply written
    ; in ring order, and publishing the tail is all a submission needs.
    mov     ecx, [rsp + O_PARAMS + P_SQ_OFF + SQO_ARRAY]
    lea     rdx, [rax + rcx]
    xor     ecx, ecx
.identity:
    mov     [rdx + rcx * 4], ecx
    inc     ecx
    cmp     ecx, [rbx + worker.sq_entries]
    jb      .identity

    ; The SQE array, mapped on its own.
    mov     eax, [rsp + O_PARAMS + P_SQ_ENTRIES]
    shl     eax, 6
    mov     r13d, eax
    xor     edi, edi
    mov     esi, eax
    mov     edx, PROT_READ_WRITE
    mov     r10d, MAP_SHARED_POPULATE
    mov     r8d, r12d
    mov     r9d, IORING_OFF_SQES
    mov     eax, SYS_mmap
    syscall
    cmp     rax, -4096
    ja      .unmap_rings                    ; -errno
    mov     [rbx + worker.sqes], rax
    mov     [rbx + worker.sqes_size], r13
    mov     [rbx + worker.ring_fd], r12d
    mov     rax, [rbx + worker.sq_ktail]
    mov     eax, [rax]
    mov     [rbx + worker.sq_tail], eax     ; where the kernel expects the next SQE (0)
    mov     qword [rbx + worker.pending], 0
    mov     dword [rbx + worker.wake_due], 0
    inc     dword [rbx + worker.ring_gen]   ; connections' counts belong to this ring from now
    mov     dword [rbx + worker.uring], 1
    xor     eax, eax
    jmp     .out

.unmap_rings:
    mov     r13, rax                        ; -errno, kept across the cleanup
    mov     rdi, [rbx + worker.ring_map]
    mov     rsi, [rbx + worker.ring_map_size]
    mov     eax, SYS_munmap
    syscall
    mov     rax, r13
    jmp     .close_ring
.unsupported:
    mov     rax, -ENOSYS                    ; too old for this backend: epoll serves instead
.close_ring:
    mov     r13, rax
    mov     edi, r12d
    mov     eax, SYS_close
    syscall
    mov     rax, r13
.out:
    add     rsp, O_FRAME
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_uring_close: the worker's ring goes: its mappings are unmapped and its descriptor closed,
; which cancels every operation still armed (the polls). Nothing of the ring is touched again:
; worker.uring becomes 0 and the pending list is dropped (its connections are freed by the
; reaps that follow, which stop counting references once the ring is gone).
;   In: rdi = worker. Nothing happens for a worker without a ring. Clobbers rax, rcx, rdx, rsi,
;   rdi, r11.
; -----------------------------------------------------------------------------
global ha_uring_close:function hidden (ha_uring_close.end - ha_uring_close)
align 16
ha_uring_close:
    push    rbx
    mov     rbx, rdi
    cmp     dword [rbx + worker.uring], 0
    je      .out
    mov     dword [rbx + worker.uring], 0
    mov     qword [rbx + worker.pending], 0
    mov     rdi, [rbx + worker.sqes]
    mov     rsi, [rbx + worker.sqes_size]
    mov     eax, SYS_munmap
    syscall
    mov     rdi, [rbx + worker.ring_map]
    mov     rsi, [rbx + worker.ring_map_size]
    mov     eax, SYS_munmap
    syscall
    mov     edi, [rbx + worker.ring_fd]
    mov     eax, SYS_close
    syscall
    mov     dword [rbx + worker.ring_fd], -1
.out:
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; uring_publish: the SQEs written so far become the kernel's to take (the tail it reads moves).
; On x86 stores are seen in order, so the SQEs' contents are visible before the tail is.
;   In: rdi = worker. Out: esi = how many SQEs the kernel has not taken yet. Clobbers rax, rcx.
; -----------------------------------------------------------------------------
align 16
uring_publish:
    mov     rax, [rdi + worker.sq_ktail]
    mov     ecx, [rdi + worker.sq_tail]
    mov     [rax], ecx
    mov     rax, [rdi + worker.sq_khead]
    sub     ecx, [rax]
    mov     esi, ecx
    ret

; -----------------------------------------------------------------------------
; ha_uring_sqe: the next SQE of the worker's ring, zeroed, to fill in; it goes to the kernel
; with the next io_uring_enter. When the SQ ring is full, what it holds is submitted first (no
; wait), so a walk may queue any number of SQEs.
;   In: rdi = worker (with a ring). Out: rax = the SQE. Clobbers every caller-saved register
;   (the submission is a system call) and xmm0.
; -----------------------------------------------------------------------------
global ha_uring_sqe:function hidden (ha_uring_sqe.end - ha_uring_sqe)
align 16
ha_uring_sqe:
    push    rbx
    mov     rbx, rdi
.again:
    mov     rax, [rbx + worker.sq_khead]
    mov     ecx, [rbx + worker.sq_tail]
    sub     ecx, [rax]                      ; SQEs the kernel has not taken
    cmp     ecx, [rbx + worker.sq_entries]
    jb      .room
    mov     rdi, rbx
    call    uring_publish
    mov     edi, [rbx + worker.ring_fd]
    xor     edx, edx                        ; wait for nothing: just take them
    xor     r10d, r10d
    xor     r8d, r8d
    xor     r9d, r9d
    mov     eax, SYS_io_uring_enter
    syscall
    jmp     .again
.room:
    mov     eax, [rbx + worker.sq_tail]
    mov     ecx, eax
    and     ecx, [rbx + worker.sq_mask]
    inc     eax
    mov     [rbx + worker.sq_tail], eax
    shl     rcx, 6
    add     rcx, [rbx + worker.sqes]
    pxor    xmm0, xmm0
    movdqu  [rcx], xmm0
    movdqu  [rcx + 16], xmm0
    movdqu  [rcx + 32], xmm0
    movdqu  [rcx + 48], xmm0
    mov     rax, rcx
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_uring_submit: the SQEs written so far go to the kernel now, without waiting for anything
; (begin_stop: the listener's poll must be gone before its descriptor closes).
;   In: rdi = worker (with a ring). Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
global ha_uring_submit:function hidden (ha_uring_submit.end - ha_uring_submit)
align 16
ha_uring_submit:
    push    rbx
    mov     rbx, rdi
    call    uring_publish                   ; esi = the SQEs to submit (rsp aligned)
    mov     edi, [rbx + worker.ring_fd]
    xor     edx, edx
    xor     r10d, r10d
    xor     r8d, r8d
    xor     r9d, r9d
    mov     eax, SYS_io_uring_enter
    syscall
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_uring_poll: a one-shot POLL_ADD (readable) for one of the worker's own descriptors, the
; listener or the eventfd, queued at once: they outlive any SQE naming them (this file's
; header), so the walk's care is not needed. Its completion comes under the tag.
;   In: rdi = worker, esi = the descriptor, edx = the tag (HA_TAG_LISTENER, HA_TAG_WAKE).
;   Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
global ha_uring_poll:function hidden (ha_uring_poll.end - ha_uring_poll)
align 16
ha_uring_poll:
    push    r12
    push    r13
    sub     rsp, 8                          ; two pushes + 8: aligned
    mov     r12d, esi
    mov     r13d, edx
    call    ha_uring_sqe                    ; rdi = worker still
    mov     byte [rax + SQE_OPCODE], IORING_OP_POLL_ADD
    mov     [rax + SQE_FD], r12d
    mov     dword [rax + SQE_OPFLAGS], EPOLLIN
    mov     [rax + SQE_USER_DATA], r13      ; the tag, zero-extended
    add     rsp, 8
    pop     r13
    pop     r12
    ret
.end:

; -----------------------------------------------------------------------------
; ha_uring_unpoll: removes the poll armed under a tag (the listener's, when the worker stops
; accepting): the poll holds the descriptor's file, which closes only once the poll is gone.
; The armed poll then completes with -ECANCELED; the removal's own completion means nothing.
;   In: rdi = worker, esi = the tag. Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
global ha_uring_unpoll:function hidden (ha_uring_unpoll.end - ha_uring_unpoll)
align 16
ha_uring_unpoll:
    push    r12                             ; one push: aligned
    mov     r12d, esi
    call    ha_uring_sqe
    mov     byte [rax + SQE_OPCODE], IORING_OP_POLL_REMOVE
    mov     dword [rax + SQE_FD], -1
    mov     [rax + SQE_ADDR], r12           ; the poll, by its user_data (the tag)
    mov     qword [rax + SQE_USER_DATA], UD_IGNORE
    pop     r12
    ret
.end:

; -----------------------------------------------------------------------------
; ha_uring_cqe: the next completion of the worker's ring, taken off it: its slot is free again
; when this returns (what it held is in registers).
;   In: rdi = worker (with a ring). Out: rax = its user_data, edx = its res (signed); rax = 0
;   when none is left (no operation is ever submitted with user_data 0). Clobbers rcx, r8.
; -----------------------------------------------------------------------------
global ha_uring_cqe:function hidden (ha_uring_cqe.end - ha_uring_cqe)
align 16
ha_uring_cqe:
    mov     r8, [rdi + worker.cq_khead]
    mov     ecx, [r8]
    mov     rax, [rdi + worker.cq_ktail]
    cmp     ecx, [rax]                      ; the kernel's tail: a plain load is an acquire on x86
    je      .none
    mov     eax, ecx
    and     eax, [rdi + worker.cq_mask]
    shl     rax, 4                          ; 16 octets a CQE
    add     rax, [rdi + worker.cqes]
    mov     edx, [rax + 8]                  ; res
    mov     rax, [rax]                      ; user_data
    inc     ecx
    mov     [r8], ecx                       ; the head moves: the kernel may reuse the slot
    ret
.none:
    xor     eax, eax
    ret
.end:

; -----------------------------------------------------------------------------
; ha_uring_pending: a connection has work for the next submission (a poll to arm or change, a
; RECV, a SEND, or, once closed, a poll to remove): onto its worker's pending list, once. The
; list holds a reference (conn.uops) until the walk takes the connection off.
;   In: rdi = conn. Clobbers rax, rcx (only: ha_set_interest jumps here).
; -----------------------------------------------------------------------------
global ha_uring_pending:function hidden (ha_uring_pending.end - ha_uring_pending)
align 16
ha_uring_pending:
    test    dword [rdi + conn.uflags], U_PENDING
    jnz     .out
    or      dword [rdi + conn.uflags], U_PENDING
    inc     dword [rdi + conn.uops]
    mov     rax, [rdi + conn.worker]
    mov     rcx, [rax + worker.pending]
    mov     [rdi + conn.u_next], rcx
    mov     [rax + worker.pending], rdi
.out:
    ret
.end:

; -----------------------------------------------------------------------------
; uring_conn_work: what one pending connection needs from the kernel now, as SQEs, from its
; state at this moment (see this file's header for why only now):
;   - closed (or a zombie): its armed poll is removed, nothing else;
;   - its waiting output (C_SEND_QUEUED): one SEND for all of it, MSG_DONTWAIT;
;   - readable (U_WANT_RECV): one RECV into the input's free room (a draining connection's
;     discards into the buffer's start), MSG_DONTWAIT; its completion then decides the poll;
;   - otherwise its poll, to the events ha_interest_mask gives: armed when none is; removed
;     when they changed or nothing is wanted (its completion then arms it anew from the state).
; A SEND goes before a RECV, so their completions come in that order.
;   In: rdi = conn (just taken off the pending list). Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
W_EVENTS    equ 0       ; the events wanted, kept across ha_uring_sqe
W_FRAME     equ 8       ; two pushes + 8: aligned

align 16
uring_conn_work:
    push    rbx
    push    r12
    sub     rsp, W_FRAME
    mov     rbx, rdi
    mov     r12, [rbx + conn.worker]
    test    dword [rbx + conn.flags], C_CLOSED | C_ZOMBIE
    jnz     .closed

    ; The output.
    test    dword [rbx + conn.flags], C_SEND_QUEUED
    jz      .recv
    test    dword [rbx + conn.uflags], U_SEND
    jnz     .recv                           ; submitted already: its completion is coming
    mov     rax, [rbx + conn.wlen]
    cmp     rax, [rbx + conn.wsent]
    jne     .send
    and     dword [rbx + conn.flags], ~C_SEND_QUEUED    ; nothing waits after all
    jmp     .recv
.send:
    mov     rdi, r12
    call    ha_uring_sqe
    mov     byte [rax + SQE_OPCODE], IORING_OP_SEND
    mov     ecx, [rbx + conn.fd]
    mov     [rax + SQE_FD], ecx
    mov     rcx, [rbx + conn.wbuf]
    add     rcx, [rbx + conn.wsent]
    mov     [rax + SQE_ADDR], rcx
    mov     rcx, [rbx + conn.wlen]
    sub     rcx, [rbx + conn.wsent]
    mov     [rax + SQE_LEN], ecx            ; far below 4 GiB: reading stops at HA_OUTPUT_HIGH
    mov     dword [rax + SQE_OPFLAGS], MSG_DONTWAIT | MSG_NOSIGNAL
    lea     rcx, [rbx + UT_SEND]
    mov     [rax + SQE_USER_DATA], rcx
    or      dword [rbx + conn.uflags], U_SEND
    inc     dword [rbx + conn.uops]

.recv:
    test    dword [rbx + conn.uflags], U_WANT_RECV
    jz      .poll
    and     dword [rbx + conn.uflags], ~U_WANT_RECV
    test    dword [rbx + conn.uflags], U_RECV
    jnz     .out                            ; one at a time: its completion decides the rest
    mov     rdi, r12
    call    ha_uring_sqe
    mov     byte [rax + SQE_OPCODE], IORING_OP_RECV
    mov     ecx, [rbx + conn.fd]
    mov     [rax + SQE_FD], ecx
    mov     rcx, [rbx + conn.rbuf]
    test    dword [rbx + conn.flags], C_DRAINING
    jnz     .discard
    add     rcx, [rbx + conn.rlen]          ; after what is held
    mov     [rax + SQE_ADDR], rcx
    mov     rcx, [rbx + conn.rcap]
    sub     rcx, [rbx + conn.rlen]          ; > 0: a full input is processed, never received into
    jmp     .recv_length
.discard:
    mov     [rax + SQE_ADDR], rcx           ; draining: whatever comes is thrown away
    mov     rcx, [rbx + conn.rcap]
.recv_length:
    mov     [rax + SQE_LEN], ecx
    mov     dword [rax + SQE_OPFLAGS], MSG_DONTWAIT
    lea     rcx, [rbx + UT_RECV]
    mov     [rax + SQE_USER_DATA], rcx
    or      dword [rbx + conn.uflags], U_RECV
    inc     dword [rbx + conn.uops]
    jmp     .out

.poll:
    mov     rdi, rbx
    call    ha_interest_mask                ; esi = the events wanted
    mov     [rsp + W_EVENTS], esi
    test    dword [rbx + conn.uflags], U_POLL
    jnz     .armed
    test    esi, esi
    jz      .out                            ; nothing to wait for
    mov     [rbx + conn.pad], esi           ; the events armed
    mov     rdi, r12
    call    ha_uring_sqe
    mov     byte [rax + SQE_OPCODE], IORING_OP_POLL_ADD
    mov     ecx, [rbx + conn.fd]
    mov     [rax + SQE_FD], ecx
    mov     ecx, [rsp + W_EVENTS]
    mov     [rax + SQE_OPFLAGS], ecx        ; poll32_events; one-shot (no IORING_POLL_ADD_MULTI)
    lea     rcx, [rbx + UT_POLL]
    mov     [rax + SQE_USER_DATA], rcx
    or      dword [rbx + conn.uflags], U_POLL
    inc     dword [rbx + conn.uops]
    jmp     .out
.armed:
    ; Armed with other events: removed, and armed anew from the state then, when the removal's
    ; poll completes (-ECANCELED, or ready, if it fired first: ha_uring_conn arms again either
    ; way). Not updated in place (IORING_POLL_UPDATE_EVENTS): an update that does not take
    ; (5.15 refuses some, racing a completion) would leave a connection waiting for readability
    ; while its client only reads, and a removal's outcome is certain. The changes are on the
    ; slow paths only (a full socket, a deferral): a poll that fires is armed anew anyway.
    cmp     esi, [rbx + conn.pad]
    je      .out                            ; armed as wanted
.remove:
    cmp     dword [rbx + conn.pad], POLL_REMOVING
    je      .out                            ; its removal is on its way already
    mov     dword [rbx + conn.pad], POLL_REMOVING
    mov     rdi, r12
    call    ha_uring_sqe
    mov     byte [rax + SQE_OPCODE], IORING_OP_POLL_REMOVE
    mov     dword [rax + SQE_FD], -1
    lea     rcx, [rbx + UT_POLL]
    mov     [rax + SQE_ADDR], rcx           ; the poll, by its user_data
    mov     qword [rax + SQE_USER_DATA], UD_IGNORE
    jmp     .out

.closed:
    ; The poll holds the socket open in the kernel, and its completion is the connection's
    ; last reference: it must go.
    test    dword [rbx + conn.uflags], U_POLL
    jnz     .remove
.out:
    add     rsp, W_FRAME
    pop     r12
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; ha_uring_enter: one turn of a worker's ring: every pending connection's work becomes SQEs
; (the walk), they go to the kernel, and the worker waits until something completes or the
; timeout passes, all in one io_uring_enter. The RECVs and SENDs just submitted complete in
; that same call (MSG_DONTWAIT), so their completions are there when it returns.
;   In: rdi = worker (with a ring), rsi = the timeout in ms, or -1 for none.
;   Out: nothing; -ETIME, -EINTR and -EBUSY (completions waiting) all mean "handle what came".
;   Clobbers every caller-saved register.
; -----------------------------------------------------------------------------
E_TS        equ 0       ; struct __kernel_timespec
E_ARG       equ 16      ; struct io_uring_getevents_arg: sigmask, sigmask_sz + pad, ts
E_TIMEOUT   equ 40
E_FRAME     equ 56      ; two pushes + 56: aligned

global ha_uring_enter:function hidden (ha_uring_enter.end - ha_uring_enter)
align 16
ha_uring_enter:
    push    rbx
    push    r12
    sub     rsp, E_FRAME
    mov     rbx, rdi
    mov     [rsp + E_TIMEOUT], rsi
.walk:
    ; A connection on the list has a reference (uops) that keeps it allocated until here.
    mov     r12, [rbx + worker.pending]
    test    r12, r12
    jz      .walked
    mov     rax, [r12 + conn.u_next]
    mov     [rbx + worker.pending], rax
    and     dword [r12 + conn.uflags], ~U_PENDING
    dec     dword [r12 + conn.uops]
    mov     rdi, r12
    call    uring_conn_work
    jmp     .walk
.walked:
    xor     eax, eax
    mov     [rsp + E_ARG], rax              ; no signal mask of its own
    mov     [rsp + E_ARG + 8], rax          ; sigmask_sz, pad
    mov     [rsp + E_ARG + 16], rax         ; no timespec: wait until something completes
    mov     rax, [rsp + E_TIMEOUT]
    cmp     rax, -1
    je      .no_timeout
    xor     edx, edx
    mov     ecx, 1000
    div     rcx                             ; rax = seconds, rdx = the ms left
    mov     [rsp + E_TS], rax
    imul    rdx, rdx, 1000000
    mov     [rsp + E_TS + 8], rdx
    lea     rax, [rsp + E_TS]
    mov     [rsp + E_ARG + 16], rax
.no_timeout:
    mov     rdi, rbx
    call    uring_publish                   ; esi = the SQEs to submit
    mov     edi, [rbx + worker.ring_fd]
    mov     edx, 1                          ; wait for one completion at least
    mov     r10d, IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG
    lea     r8, [rsp + E_ARG]
    mov     r9d, 24
    mov     eax, SYS_io_uring_enter
    syscall
    add     rsp, E_FRAME
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_uring_conn: one completion of a connection's operation. Its reference (uops) is dropped
; first; a closed connection's completions do nothing more (the reap frees it at 0).
;   POLL: an error or a hang-up closes, as under epoll. Writable: the output goes on (a SEND).
;     Readable, or the peer's end: a RECV is queued; on a deferred connection only the peer's
;     end is noted, as under epoll; a full input is processed first. A poll its removal
;     cancelled (res < 0) is armed again from the state now.
;   RECV: what read_ready does under epoll with its recvfrom's result: the octets are added and
;     processed, the peer's end noted (0), EAGAIN waits for readability again; a draining
;     connection discards and reads on until EAGAIN, closing at the peer's end.
;   SEND: what ha_conn_flush does under epoll with its sendto's result: part of the output
;     went (the socket is full): wait until writable; all of it: ha_conn_flush, finding nothing
;     left, closes after a closing response or sets the interest, and the processing resumes
;     (pipelined requests, input held back by back-pressure), unless a RECV of the same batch
;     is still to be handled (it drives then: its octets are in the input, the length not yet).
;   In: rdi = conn, esi = UT_*, edx = res (the CQE's, signed). Clobbers every caller-saved
;   register; keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global ha_uring_conn:function hidden (ha_uring_conn.end - ha_uring_conn)
align 16
ha_uring_conn:
    push    rbx
    push    r12
    push    r13                             ; three pushes: aligned for the calls below
    mov     rbx, rdi
    mov     r12d, esi
    movsxd  r13, edx                        ; res, sign-extended: < 0 is -errno
    dec     dword [rbx + conn.uops]
    cmp     r12d, UT_POLL
    je      .poll
    cmp     r12d, UT_RECV
    je      .recv

    ; ---- SEND
    and     dword [rbx + conn.uflags], ~U_SEND
    and     dword [rbx + conn.flags], ~C_SEND_QUEUED
    test    dword [rbx + conn.flags], C_CLOSED | C_ZOMBIE
    jnz     .out
    test    r13, r13
    js      .send_error
    add     [rbx + conn.wsent], r13
    mov     rax, [rbx + conn.wlen]
    cmp     [rbx + conn.wsent], rax
    jb      .send_full                      ; the socket took part: wait until writable
    mov     rdi, rbx
    call    ha_conn_flush                   ; nothing left: the rest of a flush's work
    test    eax, eax
    jnz     .out                            ; closed
    test    dword [rbx + conn.uflags], U_RECV
    jnz     .out                            ; this batch's RECV will drive
    test    dword [rbx + conn.flags], C_WANT_WRITE | C_SEND_QUEUED
    jnz     .out
    mov     rdi, rbx
    call    ha_conn_drive
    jmp     .out
.send_error:
    cmp     r13, -EAGAIN
    je      .send_full
    cmp     r13, -EINTR
    je      .send_again
    mov     rdi, rbx                        ; the peer is gone (EPIPE, ECONNRESET, ...)
    call    ha_conn_close
    jmp     .out
.send_again:
    mov     rdi, rbx
    call    ha_conn_flush                   ; queues the SEND again
    jmp     .out
.send_full:
    or      dword [rbx + conn.flags], C_WANT_WRITE
    jmp     .rearm                          ; ha_interest_mask: writable, not readable

    ; ---- RECV
.recv:
    and     dword [rbx + conn.uflags], ~U_RECV
    test    dword [rbx + conn.flags], C_CLOSED | C_ZOMBIE
    jnz     .out
    test    dword [rbx + conn.flags], C_DRAINING
    jnz     .draining
    test    r13, r13
    jz      .eof
    js      .recv_error
    add     [rbx + conn.rlen], r13
    mov     rdi, rbx
    call    ha_conn_drive
    jmp     .rearm
.eof:
    ; The peer finished sending: what it sent is answered first, then the connection closes
    ; (ha_conn_drive sees C_PEER_DONE), as under epoll.
    or      dword [rbx + conn.flags], C_PEER_DONE
    mov     rdi, rbx
    call    ha_conn_drive
    jmp     .rearm
.recv_error:
    cmp     r13, -EAGAIN
    je      .rearm                          ; nothing after all: wait until readable
    cmp     r13, -EINTR
    je      .rearm
    mov     rdi, rbx
    call    ha_conn_close
    jmp     .out
.draining:
    ; After a closing response: read and discard until the peer closes (or the linger ends).
    test    r13, r13
    jg      .read_on
    cmp     r13, -EAGAIN
    je      .rearm
    cmp     r13, -EINTR
    je      .read_on
    mov     rdi, rbx                        ; the peer's end (0), or an error
    call    ha_conn_close
    jmp     .out
.read_on:
    or      dword [rbx + conn.uflags], U_WANT_RECV
    mov     rdi, rbx
    call    ha_uring_pending
    jmp     .out

    ; ---- POLL
.poll:
    and     dword [rbx + conn.uflags], ~U_POLL
    mov     dword [rbx + conn.pad], 0       ; nothing is armed now
    test    dword [rbx + conn.flags], C_CLOSED | C_ZOMBIE
    jnz     .out
    test    r13, r13
    js      .rearm                          ; cancelled by a removal (or failed): arm again
    test    r13d, EPOLLERR | EPOLLHUP
    jnz     .error
    test    r13d, EPOLLOUT
    jz      .readable
    and     dword [rbx + conn.flags], ~C_WANT_WRITE
    mov     rdi, rbx
    call    ha_conn_flush                   ; queues the SEND; its completion goes on
    jmp     .out
.readable:
    test    r13d, EPOLLIN | EPOLLRDHUP
    jz      .rearm
    test    dword [rbx + conn.flags], C_DEFERRED
    jnz     .deferred
    test    dword [rbx + conn.flags], C_DRAINING
    jnz     .want_recv
    mov     rax, [rbx + conn.rlen]
    cmp     rax, [rbx + conn.rcap]
    jb      .want_recv
    mov     rdi, rbx                        ; the input is full: processing makes room (or
    call    ha_conn_drive                   ; answers 413/431) before anything more is read
    jmp     .rearm
.want_recv:
    or      dword [rbx + conn.uflags], U_WANT_RECV
    mov     rdi, rbx
    call    ha_uring_pending
    jmp     .out
.deferred:
    ; Deferred: only the peer's end was asked for. It finished sending, but may still read the
    ; answer: noted, and not asked again (ha_interest_mask leaves it out from now on).
    test    r13d, EPOLLRDHUP
    jz      .rearm
    or      dword [rbx + conn.flags], C_PEER_DONE
    jmp     .rearm
.error:
    mov     rdi, rbx
    call    ha_conn_close
    jmp     .out
.rearm:
    mov     rdi, rbx
    call    ha_set_interest                 ; pending: the walk arms what the state wants
.out:
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:
