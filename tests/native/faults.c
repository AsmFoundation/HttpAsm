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
 * A child's exit status says how far its scenario got; only a signal or a hang fails the test.
 *
 * Exit status: 0 when every child ended by itself; 1 with the failing ones listed.
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
#include <sys/prctl.h>
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

/* in_child: runs the scenario in a child process, after setup(arg) there, with a 20 s alarm.
 * Returns 0 when the child ended by itself (any exit status, counted in outcomes), else -1 with
 * *how describing it. */
static int in_child(void (*setup)(long), long arg, char *how, size_t how_size)
{
    pid_t pid = fork();
    if (pid == 0) {
        alarm(20);
        setup(arg);
        _exit(scenario());
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid) {
        snprintf(how, how_size, "fork/wait failed");
        return -1;
    }
    if (WIFSIGNALED(status)) {
        snprintf(how, how_size, WTERMSIG(status) == SIGALRM ? "hung (20 s)" : "killed by signal %d", WTERMSIG(status));
        return -1;
    }
    if (WEXITSTATUS(status) <= 100)
        outcomes[WEXITSTATUS(status)]++;
    return 0;
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
           "%ld at its send, %ld without a filter\n",
           outcomes[0], outcomes[1], outcomes[2], outcomes[3], outcomes[4], outcomes[100]);
    return failures + syscall_failures == 0 ? 0 : 1;
}
