/*
 * faults.c - the drivers' error paths (docs/DESIGN.md phase H step 3: "memory and connection
 * exhaustion"): allocations and system calls that fail, one at a time, at every point a whole
 * server's life reaches. No other test can reach these paths: on a healthy machine nothing fails.
 *
 * The scenario: a server created and started (one worker, loopback), an HTTP/1.1 request and an
 * HTTP/2 one answered, the httpasm client's own request, then the stop and the destroy.
 *
 *   1. Allocation failures. This program defines malloc, calloc and realloc (they interpose on
 *      the C library's for the whole process, libhttpasm.so included) and counts the calls; the
 *      scenario runs once to count them, then once per allocation N in a child process where
 *      allocation N returns NULL. Every child must end by itself - the scenario succeeding, or
 *      an API call reporting the failure - never by a signal, and within 20 s.
 *   2. System-call failures. For each system call the server and the client make, a child
 *      installs a seccomp filter that fails it with an errno (EMFILE, ENOMEM, ENOBUFS, ...),
 *      then runs the scenario; again it must end by itself.
 * A child's exit status says how far its scenario got. A signal, a hang, or a child that spun
 * (more than CHILD_CPU_LIMIT seconds of CPU: a worker woken again and again by something it
 * cannot act on, such as a listener whose accept4 keeps failing) fails the test.
 *   3. Descriptor exhaustion, on each backend: a server whose process can open only 4 more
 *      descriptors, and 12 connections from another process. Accepting stops at the limit:
 *      the server must rest (its CPU over a second stays near zero, where a spinning worker
 *      uses the whole second), then take the waiting connections once descriptors free, and
 *      answer the request that waited in the backlog.
 *
 * Exit status: 0 when every child ended by itself and the exhaustion checks held; 1 with the
 * failing ones listed.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "httpasm.h"

/* ---- 1. The allocator: glibc's own entry points, with a countdown. */
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);

static long allocations;     /* every allocation so far */
static long fail_at = -1;    /* the allocation that fails (1-based), -1: none */

/* fails: counts an allocation; whether this one is to fail. */
static int fails(void)
{
    return ++allocations == fail_at;
}

void *malloc(size_t n)
{
    return fails() ? NULL : __libc_malloc(n);
}

void *calloc(size_t count, size_t n)
{
    return fails() ? NULL : __libc_calloc(count, n);
}

void *realloc(void *p, size_t n)
{
    return fails() ? NULL : __libc_realloc(p, n);
}

/* ---- The scenario. */

static void handler(void *context, httpasm_exchange *exchange)
{
    (void)context;
    httpasm_exchange_respond(exchange, 200, NULL, 0, (const uint8_t *)"ok", 2);
}

/* exchange_raw: one connection to the port: sends the octets, half-closes, reads to the close
 * (within 3 s). Returns the octets read, or -1 when the connection failed. */
static ssize_t exchange_raw(uint16_t port, const void *octets, size_t n)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0 || send(fd, octets, n, MSG_NOSIGNAL) != (ssize_t)n) {
        close(fd);
        return -1;
    }
    shutdown(fd, SHUT_WR);
    char buf[4096];
    ssize_t total = 0;
    for (;;) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, 3000) <= 0)
            break;
        ssize_t r = recv(fd, buf, sizeof buf, 0);
        if (r <= 0)
            break;
        total += r;
    }
    close(fd);
    return total;
}

/* scenario: a server's whole life. Returns how far it got: 0 all of it, 1-4 the step that
 * reported a failure (an API's failure, which is an acceptable outcome under injection). */
static int scenario(void)
{
    static const char h1[] = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    static const unsigned char h2[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                                      "\x00\x00\x00\x04\x00\x00\x00\x00\x00"                              /* SETTINGS */
                                      "\x00\x00\x06\x01\x05\x00\x00\x00\x01\x82\x86\x84\x41\x01\x61";    /* HEADERS: GET / a */
    httpasm_server_options o;
    memset(&o, 0, sizeof o);
    o.handler = handler;
    o.workers = 1;
    o.bind_address = htonl(INADDR_LOOPBACK);
    int error = 0;
    httpasm_server *s = httpasm_server_create(&o, &error);
    if (s == NULL)
        return 1;
    if (httpasm_server_start(s) != 0) {
        httpasm_server_destroy(s);
        return 2;
    }
    uint16_t port = httpasm_server_port(s);
    exchange_raw(port, h1, sizeof h1 - 1);
    exchange_raw(port, h2, sizeof h2 - 1);
    int result = 0;
    httpasm_client *c = httpasm_client_connect(htonl(INADDR_LOOPBACK), port, 3000, &error);
    if (c == NULL) {
        result = 3;
    } else {
        httpasm_request q;
        memset(&q, 0, sizeof q);
        q.method = (const uint8_t *)"GET";
        q.method_length = 3;
        q.target = (const uint8_t *)"/";
        q.target_length = 1;
        q.authority = (const uint8_t *)"a";
        q.authority_length = 1;
        httpasm_client_response r;
        if (httpasm_client_send(c, &q, NULL, 0, &r) != 0)
            result = 4;
        httpasm_client_close(c);
    }
    httpasm_server_stop(s);
    httpasm_server_destroy(s);
    return result;
}

/* ---- 2. System calls: a seccomp filter failing one, with an errno. */

/* fail_syscall: installs a filter on this process that fails syscall nr with err. Returns 0, or
 * -1 when the kernel refuses the filter. */
static int fail_syscall(int nr, int err)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ((unsigned)err & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = sizeof filter / sizeof filter[0], .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &program);
}

/* outcomes[k]: how many children ended with scenario() returning k (0: the whole scenario,
 * 1-4: the step whose API reported the failure, 100: the filter could not be installed) - the
 * evidence that the injected failures reach the library rather than passing unnoticed. */
static long outcomes[101];

/* CHILD_CPU_LIMIT: the most CPU seconds a child may use. A whole scenario takes tens of
 * milliseconds; one whose waits time out (a server that never accepts, say) lives about ten
 * seconds, nearly all of them asleep. A worker that spins instead - woken again and again by
 * a listener or a connection it cannot act on - uses a core for all of them. */
#define CHILD_CPU_LIMIT 1.5

/* child_cpu_most: the most CPU seconds any child used, reported as the margin under the limit. */
static double child_cpu_most;

/* in_child: runs the scenario in a child process, after setup(arg) there, with a 20 s alarm.
 * Returns 0 when the child ended by itself (any exit status, counted in outcomes) within the
 * CPU limit, else -1 with *how describing it. */
static int in_child(void (*setup)(long), long arg, char *how, size_t how_size)
{
    pid_t pid = fork();
    if (pid == 0) {
        alarm(20);
        setup(arg);
        _exit(scenario());
    }
    int status = 0;
    struct rusage usage;
    if (pid < 0 || wait4(pid, &status, 0, &usage) != pid) {
        snprintf(how, how_size, "fork/wait failed");
        return -1;
    }
    if (WIFSIGNALED(status)) {
        snprintf(how, how_size, WTERMSIG(status) == SIGALRM ? "hung (20 s)" : "killed by signal %d", WTERMSIG(status));
        return -1;
    }
    double cpu = (double)(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1e6;
    if (cpu > child_cpu_most)
        child_cpu_most = cpu;
    if (cpu > CHILD_CPU_LIMIT) {
        snprintf(how, how_size, "spun: %.2f s of CPU (the limit is %.1f s)", cpu, CHILD_CPU_LIMIT);
        return -1;
    }
    if (WEXITSTATUS(status) <= 100)
        outcomes[WEXITSTATUS(status)]++;
    return 0;
}

/* ---- 3. Descriptor exhaustion. */

/* EXHAUST_ROOM: the descriptors the server's process may still open once the limit is set,
 * and EXHAUST_CONNECTIONS: the connections the other process makes, three times as many. */
#define EXHAUST_ROOM 4
#define EXHAUST_CONNECTIONS 12

/* exhaustion_server: the server's process. It starts a server on the backend `flags` asks
 * for, lowers RLIMIT_NOFILE so only EXHAUST_ROOM more descriptors can be opened, writes the
 * port to `out`, then answers commands read from `in`: 'c' writes the process's CPU time so far
 * (microseconds, a uint64_t); anything else, or the parent's end, stops and destroys the server
 * and exits 0. Exits 2 when the server cannot start, 3 when the limit cannot be set. */
static void exhaustion_server(int in, int out, uint16_t flags)
{
    httpasm_server_options o;
    memset(&o, 0, sizeof o);
    o.handler = handler;
    o.workers = 1;
    o.bind_address = htonl(INADDR_LOOPBACK);
    o.flags = flags;
    int error = 0;
    httpasm_server *s = httpasm_server_create(&o, &error);
    if (s == NULL || httpasm_server_start(s) != 0)
        _exit(2);
    uint16_t port = httpasm_server_port(s);
    /* The highest open descriptor, the server's own included. The holes below it (the pipe
     * ends this process closed) would add to the room, so they are filled first: the kernel
     * always hands out the lowest free descriptor, and once one lands above the top, every
     * descriptor up to the top is open. A limit of top + 1 + EXHAUST_ROOM then leaves exactly
     * EXHAUST_ROOM for the connections the worker accepts. */
    int top = -1;
    for (int fd = 0; fd < 4096; fd++) {
        if (fcntl(fd, F_GETFD) != -1)
            top = fd;
    }
    for (;;) {
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            _exit(3);
        if (fd > top) {
            close(fd);
            break;
        }
    }
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
        _exit(3);
    limit.rlim_cur = (rlim_t)top + 1 + EXHAUST_ROOM;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
        _exit(3);
    if (write(out, &port, sizeof port) != sizeof port)
        _exit(3);
    char command;
    while (read(in, &command, 1) == 1 && command == 'c') {
        struct rusage u;
        getrusage(RUSAGE_SELF, &u);
        uint64_t us = (uint64_t)(u.ru_utime.tv_sec + u.ru_stime.tv_sec) * 1000000u + (uint64_t)(u.ru_utime.tv_usec + u.ru_stime.tv_usec);
        if (write(out, &us, sizeof us) != sizeof us)
            break;
    }
    httpasm_server_stop(s);
    httpasm_server_destroy(s);
    _exit(0);
}

/* server_cpu: the server process's CPU time so far, in microseconds (or UINT64_MAX when it
 * does not answer). */
static uint64_t server_cpu(int to, int from)
{
    uint64_t us;
    if (write(to, "c", 1) != 1 || read(from, &us, sizeof us) != sizeof us)
        return UINT64_MAX;
    return us;
}

/* exhaustion: the descriptor-exhaustion check on one backend (see this file's header).
 * Returns 0 when it held, else 1 with the failure printed. */
static int exhaustion(uint16_t flags, const char *backend)
{
    int down[2], up[2];
    if (pipe(down) != 0 || pipe(up) != 0)
        return fprintf(stderr, "faults: exhaustion (%s): no pipe\n", backend), 1;
    pid_t pid = fork();
    if (pid == 0) {
        alarm(30);
        close(down[1]);
        close(up[0]);
        exhaustion_server(down[0], up[1], flags);
    }
    close(down[0]);
    close(up[1]);
    int failed = 0;
    int fds[EXHAUST_CONNECTIONS];
    int made = 0;
    uint16_t port = 0;
    if (pid < 0 || read(up[0], &port, sizeof port) != sizeof port) {
        fprintf(stderr, "faults: exhaustion (%s): the server did not start\n", backend);
        failed = 1;
        goto done;
    }
    /* Every connect completes (the kernel finishes the handshake into the backlog); the server
     * takes EXHAUST_ROOM of them, and its next accept4 fails with EMFILE. */
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    for (; made < EXHAUST_CONNECTIONS; made++) {
        fds[made] = socket(AF_INET, SOCK_STREAM, 0);
        if (fds[made] < 0 || connect(fds[made], (struct sockaddr *)&to, sizeof to) != 0) {
            fprintf(stderr, "faults: exhaustion (%s): connection %d failed: %s\n", backend, made, strerror(errno));
            if (fds[made] >= 0)
                close(fds[made]);
            failed = 1;
            goto done;
        }
    }
    static const char request[] = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    int last = fds[EXHAUST_CONNECTIONS - 1];
    if (send(last, request, sizeof request - 1, MSG_NOSIGNAL) != (ssize_t)(sizeof request - 1)) {
        fprintf(stderr, "faults: exhaustion (%s): the request was not sent\n", backend);
        failed = 1;
        goto done;
    }
    usleep(200000);                         /* the worker has met EMFILE by now */
    uint64_t before = server_cpu(down[1], up[0]);
    usleep(1000000);
    uint64_t after = server_cpu(down[1], up[0]);
    struct pollfd p = { .fd = last, .events = POLLIN };
    int answered_early = poll(&p, 1, 0);
    printf("faults: exhaustion (%s): %d connections against %d descriptors; the server used %.1f ms of CPU in the second after\n",
           backend, EXHAUST_CONNECTIONS, EXHAUST_ROOM, (double)(after - before) / 1000.0);
    if (before == UINT64_MAX || after == UINT64_MAX || after - before > 150000) {
        fprintf(stderr, "faults: exhaustion (%s): the server spun while out of descriptors (%.1f ms of CPU in 1 s)\n", backend,
                (double)(after - before) / 1000.0);
        failed = 1;
    }
    if (answered_early != 0) {
        fprintf(stderr, "faults: exhaustion (%s): the last connection was answered while the descriptors were short\n", backend);
        failed = 1;
    }
    /* Recovery: the first 8 connections close; the server reads their end and frees its
     * descriptors, takes the waiting connections once its pause is over, and answers. */
    for (int i = 0; i < 8; i++)
        close(fds[i]);
    char reply[64] = { 0 };
    if (poll(&p, 1, 3000) != 1 || recv(last, reply, sizeof reply - 1, 0) < 12 || memcmp(reply, "HTTP/1.1 200", 12) != 0) {
        fprintf(stderr, "faults: exhaustion (%s): the request that waited was not answered after descriptors freed\n", backend);
        failed = 1;
    }
    for (int i = 8; i < made; i++)
        close(fds[i]);
    made = 0;
done:
    for (int i = 0; i < made; i++)
        close(fds[i]);
    close(down[1]);                         /* the server's process stops and exits */
    int status = 0;
    if (pid > 0 && (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)) {
        fprintf(stderr, "faults: exhaustion (%s): the server's process ended badly (status 0x%x)\n", backend, status);
        failed = 1;
    }
    close(up[0]);
    return failed;
}

static void set_fail_at(long n)
{
    fail_at = n;
}

static void set_syscall(long packed)
{
    if (fail_syscall((int)(packed >> 16), (int)(packed & 0xFFFF)) != 0)
        _exit(100);
}

/* main: counts the scenario's allocations, fails each, then each system call. */
int main(void)
{
    int failures = 0;
    char how[128];
    /* The count, in a child too: the parent's own allocations stay out of it. */
    long before = allocations;
    int r = scenario();
    long count = allocations - before;
    printf("faults: the scenario runs whole (%d) with %ld allocations\n", r, count);
    if (r != 0)
        return 1;
    for (long n = 1; n <= count + 8; n++) {
        if (in_child(set_fail_at, allocations + n, how, sizeof how) != 0) {
            fprintf(stderr, "faults: allocation %ld of %ld failing: %s\n", n, count, how);
            failures++;
        }
    }
    printf("faults: each of %ld allocations failed in turn: %d children did not end by themselves\n", count + 8, failures);

    static const struct { int nr; int err; const char *name; } calls[] = {
        { SYS_socket, EMFILE, "socket EMFILE" },         { SYS_bind, EADDRINUSE, "bind EADDRINUSE" },
        { SYS_listen, ENOBUFS, "listen ENOBUFS" },       { SYS_setsockopt, ENOMEM, "setsockopt ENOMEM" },
        { SYS_epoll_create1, EMFILE, "epoll_create1 EMFILE" }, { SYS_epoll_ctl, ENOMEM, "epoll_ctl ENOMEM" },
        { SYS_eventfd2, EMFILE, "eventfd2 EMFILE" },     { SYS_accept4, EMFILE, "accept4 EMFILE" },
        { SYS_recvfrom, ENOMEM, "recvfrom ENOMEM" },     { SYS_sendto, ENOBUFS, "sendto ENOBUFS" },
        { SYS_sendmsg, ENOBUFS, "sendmsg ENOBUFS" },     { SYS_connect, ECONNREFUSED, "connect ECONNREFUSED" },
        { SYS_clone3, EAGAIN, "clone3 EAGAIN" },         { SYS_clone, EAGAIN, "clone EAGAIN" },
        { SYS_shutdown, ENOTCONN, "shutdown ENOTCONN" }, { SYS_timerfd_create, EMFILE, "timerfd_create EMFILE" },
    };
    int syscall_failures = 0;
    for (size_t i = 0; i < sizeof calls / sizeof calls[0]; i++) {
        if (in_child(set_syscall, (long)calls[i].nr << 16 | calls[i].err, how, sizeof how) != 0) {
            fprintf(stderr, "faults: %s: %s\n", calls[i].name, how);
            syscall_failures++;
        }
    }
    printf("faults: %zu system calls failed in turn: %d children did not end by themselves\n", sizeof calls / sizeof calls[0],
           syscall_failures);
    printf("faults: the children's scenarios: %ld whole, %ld refused at create, %ld at start, %ld at the client's connect, "
           "%ld at its send, %ld without a filter; the most CPU a child used: %.2f s (the limit is %.1f s)\n",
           outcomes[0], outcomes[1], outcomes[2], outcomes[3], outcomes[4], outcomes[100], child_cpu_most, CHILD_CPU_LIMIT);

    int exhausted = exhaustion(0, "epoll") + exhaustion(HTTPASM_SERVER_URING, "io_uring");
    return failures + syscall_failures + exhausted == 0 ? 0 : 1;
}
