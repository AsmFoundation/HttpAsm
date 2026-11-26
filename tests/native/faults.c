/*
 * faults.c - the drivers' error paths (docs/DESIGN.md phase H step 3: "memory and connection
 * exhaustion"): allocations and system calls that fail, one at a time, at every point a whole
 * server's life reaches. No other test can reach these paths: on a healthy machine nothing fails.
 *
 * The scenario: a server created and started (one worker by default, loopback), then on it:
 * an HTTP/1.1 request; a deferred one (answered from another thread); a chunked 40 KB upload
 * with a trailer, echoed (the input and the output grow); an HTTP/2 request; and an HTTP/2
 * connection carrying a deferred request and an upload whose head continues in a CONTINUATION
 * frame, whose 20 KB body comes in two DATA frames and which ends with trailers; then the
 * httpasm client's own requests (a small answer and a 256 KiB one), the stop and the destroy.
 *
 *   1. Allocation failures. This program defines malloc, calloc and realloc (they interpose on
 *      the C library's for the whole process, libhttpasm.so included) and counts the calls; the
 *      scenario runs once to count them, then once per allocation N in a child process where
 *      allocation N returns NULL. Every child must end by itself - the scenario succeeding, or
 *      an API call reporting the failure - never by a signal, and within 20 s.
 *   2. System-call failures, lasting. For each system call the server and the client make, a
 *      child installs a seccomp filter that fails every call of it with an errno (EMFILE,
 *      ENOMEM, ENOBUFS, ...), then runs the scenario; again it must end by itself.
 *   4. System-call failures, one at a time. A filter that fails every call reaches only the
 *      first site that makes it. Here a seccomp user-notification filter (SECCOMP_RET_USER_NOTIF)
 *      hands each call of one system call to a supervisor thread of the child, which lets every
 *      call go on (SECCOMP_USER_NOTIF_FLAG_CONTINUE) but the k-th, which it fails with an errno;
 *      a first run counts the calls, then k takes every value. So each call site meets its own
 *      failure, transient ones (EINTR, EAGAIN, ECONNABORTED) included, which a lasting filter
 *      could only turn into a spin.
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
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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

static _Atomic long allocations;     /* every allocation so far */
static long fail_at = -1;            /* the allocation that fails (1-based), -1: none */

/* fails: counts an allocation; whether this one is to fail (errno is then ENOMEM, as a real
 * allocator's failure leaves it: glibc's pthread_create asserts that it does). Atomic: the
 * scenario allocates on its worker, its own thread and the threads that answer deferred
 * requests at once, and a lost increment would make two allocations fail, or none. */
static int fails(void)
{
    if (atomic_fetch_add(&allocations, 1) + 1 != fail_at)
        return 0;
    errno = ENOMEM;
    return 1;
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

/* The scenario's server options, set before a run (a child inherits them from the parent,
 * which sets them for each pass): its workers (0: one per CPU, which reads the affinity mask)
 * and HTTPASM_SERVER_* flags. */
static uint32_t scenario_workers = 1;
static uint16_t scenario_flags;

/* /big's answer: large enough that the output grows and the client's input does too. */
static uint8_t big_body[256 << 10];

/* answer_later: answers a deferred exchange from this thread, with a field, as a handler's
 * worker pool would. Its result is ignored: under injection the answer may be refused, and the
 * connection then ends with the server. Returns NULL. */
static void *answer_later(void *exchange)
{
    static const httpasm_field field = { (const uint8_t *)"x-later", (const uint8_t *)"yes", 7, 3, 0, 0, 0 };
    httpasm_exchange_respond(exchange, 200, &field, 1, (const uint8_t *)"later", 5);
    return NULL;
}

/* answer_big_later: as answer_later, with big_body: the answer outgrows the connection's
 * output when the worker appends it. Returns NULL. */
static void *answer_big_later(void *exchange)
{
    httpasm_exchange_respond(exchange, 200, NULL, 0, big_body, sizeof big_body);
    return NULL;
}

/* target_is: whether the request-target (or :path) is exactly path. */
static int target_is(const httpasm_request *r, const char *path)
{
    size_t n = strlen(path);
    return r->target_length == n && memcmp(r->target, path, n) == 0;
}

/* handler: "/echo" answers the body it got, "/big" big_body, "/defer" and "/defer-big" defer
 * and answer from a thread of their own, small or big_body (inline when no thread can be made:
 * under injection pthread_create fails, and a deferred exchange nobody answers would hold its
 * connection until the stop); anything else "ok". */
static void handler(void *context, httpasm_exchange *exchange)
{
    (void)context;
    const httpasm_request *r = httpasm_exchange_request(exchange);
    void *(*later)(void *) = target_is(r, "/defer") ? answer_later : target_is(r, "/defer-big") ? answer_big_later : NULL;
    if (target_is(r, "/echo")) {
        size_t length = 0;
        const uint8_t *body = httpasm_exchange_body(exchange, &length);
        httpasm_exchange_respond(exchange, 200, NULL, 0, body, length);
    } else if (target_is(r, "/big")) {
        httpasm_exchange_respond(exchange, 200, NULL, 0, big_body, sizeof big_body);
    } else if (later != NULL && httpasm_exchange_defer(exchange) == 0) {
        pthread_t t;
        if (pthread_create(&t, NULL, later, exchange) == 0)
            pthread_detach(t);
        else
            later(exchange);
    } else {
        httpasm_exchange_respond(exchange, 200, NULL, 0, (const uint8_t *)"ok", 2);
    }
}

/* exchange_raw: one connection to the port: sends the octets, half-closes, reads to the close
 * (each wait 1 s at most: a loopback exchange takes milliseconds, and under a lasting failure -
 * every accept4 failing, say - each of the scenario's ten connections waits its full time, which
 * must stay within the child's 20 s alarm). Returns the octets read, or -1 when the connection
 * failed. */
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
        if (poll(&p, 1, 1000) <= 0)
            break;
        ssize_t r = recv(fd, buf, sizeof buf, 0);
        if (r <= 0)
            break;
        total += r;
    }
    close(fd);
    return total;
}

/* The scenario's larger messages, built once by build_messages before any run (static, so
 * building them allocates nothing a count could see; children inherit them). */
static char chunked_upload[41 << 10];
static size_t chunked_upload_length;
static char length_upload[41 << 10];        /* Content-Length: 40000: the input grows to the body */
static size_t length_upload_length;
static char too_large[101 << 10];           /* a body past max_body: 413, then the rest is drained */
static size_t too_large_length;
static unsigned char h2_more[21 << 10];
static size_t h2_more_length;

/* put_frame: appends an HTTP/2 frame (RFC 9113 4.1) to h2_more.
 *   type, flags, stream  its header's fields; payload, length  its payload (NULL: length
 *   octets of 'y'). */
static void put_frame(int type, int flags, int stream, const void *payload, size_t length)
{
    unsigned char *at = h2_more + h2_more_length;
    at[0] = (unsigned char)(length >> 16);
    at[1] = (unsigned char)(length >> 8);
    at[2] = (unsigned char)length;
    at[3] = (unsigned char)type;
    at[4] = (unsigned char)flags;
    at[5] = 0;
    at[6] = 0;
    at[7] = 0;
    at[8] = (unsigned char)stream;
    if (payload != NULL)
        memcpy(at + 9, payload, length);
    else
        memset(at + 9, 'y', length);
    h2_more_length += 9 + length;
}

/* build_messages: big_body's octets; the chunked upload (40,000 octets in one chunk, then the
 * trailer X-T); and the HTTP/2 connection's frames: the preface, SETTINGS, stream 1 GET /defer
 * (its :authority added to the dynamic table), stream 3 POST /echo whose head is split between
 * HEADERS and a CONTINUATION (:authority from the dynamic table), 16,384 + 3,616 octets of
 * DATA, and the trailers "x-t: 1" with END_STREAM. Field blocks are written by hand, from
 * RFC 7541's static table (2 GET, 3 POST, 4 :path, 6 http; 1 :authority as a name). */
static void build_messages(void)
{
    for (size_t i = 0; i < sizeof big_body; i++)
        big_body[i] = (uint8_t)('a' + i % 26);

    int head = snprintf(chunked_upload, sizeof chunked_upload,
                        "POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%x\r\n", 40000);
    chunked_upload_length = (size_t)head;
    memset(chunked_upload + chunked_upload_length, 'x', 40000);
    chunked_upload_length += 40000;
    static const char tail[] = "\r\n0\r\nX-T: 1\r\n\r\n";
    memcpy(chunked_upload + chunked_upload_length, tail, sizeof tail - 1);
    chunked_upload_length += sizeof tail - 1;

    head = snprintf(length_upload, sizeof length_upload,
                    "POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 40000\r\nConnection: close\r\n\r\n");
    length_upload_length = (size_t)head;
    memset(length_upload + length_upload_length, 'z', 40000);
    length_upload_length += 40000;

    /* 2 MB announced against the scenario's max_body (1 MiB, the default): 413 at once, then
     * the server drains the 100,000 octets that follow before it closes. */
    head = snprintf(too_large, sizeof too_large, "POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 2000000\r\n\r\n");
    too_large_length = (size_t)head;
    memset(too_large + too_large_length, 'q', 100000);
    too_large_length += 100000;

    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    memcpy(h2_more, preface, sizeof preface - 1);
    h2_more_length = sizeof preface - 1;
    put_frame(4, 0, 0, "", 0);                                                      /* SETTINGS */
    static const unsigned char defer[] = { 0x82, 0x86, 0x04, 6, '/', 'd', 'e', 'f', 'e', 'r', 0x41, 1, 'a' };
    put_frame(1, 0x05, 1, defer, sizeof defer);                                     /* HEADERS, END_STREAM */
    static const unsigned char echo[] = { 0x83, 0x86, 0x04, 5, '/', 'e', 'c', 'h', 'o', 0xbe };
    put_frame(1, 0x00, 3, echo, 5);                                                 /* HEADERS, the head goes on */
    put_frame(9, 0x04, 3, echo + 5, sizeof echo - 5);                               /* CONTINUATION, END_HEADERS */
    put_frame(0, 0, 3, NULL, 16384);                                                /* DATA */
    put_frame(0, 0, 3, NULL, 3616);                                                 /* DATA */
    static const unsigned char trailers[] = { 0x00, 3, 'x', '-', 't', 1, '1' };
    put_frame(1, 0x05, 3, trailers, sizeof trailers);                               /* HEADERS: trailers, END_STREAM */
}

/* client_get: one GET by the httpasm client. Returns httpasm_client_send's result. */
static int client_get(httpasm_client *c, const char *target)
{
    httpasm_request q;
    memset(&q, 0, sizeof q);
    q.method = (const uint8_t *)"GET";
    q.method_length = 3;
    q.target = (const uint8_t *)target;
    q.target_length = (uint32_t)strlen(target);
    q.authority = (const uint8_t *)"a";
    q.authority_length = 1;
    httpasm_client_response r;
    return httpasm_client_send(c, &q, NULL, 0, &r);
}

/* scenario: a server's whole life (this file's header lists its steps). Returns how far it
 * got: 0 all of it, 1-4 the step that reported a failure (an API's failure, which is an
 * acceptable outcome under injection). The raw connections' own failures are not counted:
 * they are this program's, and the steps after them go on. */
static int scenario(void)
{
    static const char h1[] = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    static const char h1_defer[] = "GET /defer HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    static const char h1_defer_big[] = "GET /defer-big HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    /* Two answers of 256 KiB asked for at once: the second is written while the first still
     * fills the output. */
    static const char h1_pipelined[] = "GET /big HTTP/1.1\r\nHost: a\r\n\r\nGET /big HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    static const unsigned char h2[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                                      "\x00\x00\x00\x04\x00\x00\x00\x00\x00"                              /* SETTINGS */
                                      "\x00\x00\x06\x01\x05\x00\x00\x00\x01\x82\x86\x84\x41\x01\x61";    /* HEADERS: GET / a */
    httpasm_server_options o;
    memset(&o, 0, sizeof o);
    o.handler = handler;
    o.workers = scenario_workers;
    o.flags = scenario_flags;
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
    (void)httpasm_server_io(s);                     /* what the workers run on: MIXED under some failures */
    exchange_raw(port, h1, sizeof h1 - 1);
    exchange_raw(port, h1_defer, sizeof h1_defer - 1);
    exchange_raw(port, h1_defer_big, sizeof h1_defer_big - 1);
    exchange_raw(port, h1_pipelined, sizeof h1_pipelined - 1);
    exchange_raw(port, length_upload, length_upload_length);
    exchange_raw(port, too_large, too_large_length);
    exchange_raw(port, chunked_upload, chunked_upload_length);
    exchange_raw(port, h2, sizeof h2 - 1);
    exchange_raw(port, h2_more, h2_more_length);
    int result = 0;
    httpasm_client *c = httpasm_client_connect(htonl(INADDR_LOOPBACK), port, 3000, &error);
    if (c == NULL) {
        result = 3;
    } else {
        if (client_get(c, "/") != 0 || client_get(c, "/big") != 0)
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

/* judge: a child's end, from wait4. Returns 0 when it ended by itself (any exit status,
 * counted in outcomes) within the CPU limit, else -1 with *how describing it. */
static int judge(int status, const struct rusage *usage, char *how, size_t how_size)
{
    if (WIFSIGNALED(status)) {
        snprintf(how, how_size, WTERMSIG(status) == SIGALRM ? "hung (20 s)" : "killed by signal %d", WTERMSIG(status));
        return -1;
    }
    double cpu = (double)(usage->ru_utime.tv_sec + usage->ru_stime.tv_sec) + (usage->ru_utime.tv_usec + usage->ru_stime.tv_usec) / 1e6;
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

/* spawn: forks a child that runs the scenario after setup(arg), with a 20 s alarm. Returns its
 * pid, or -1. The parent's stdio is flushed first, so a child's exit() cannot print it again.
 * The child ends with exit(), not _exit(): the coverage build's library writes the markers it
 * ran from its .fini_array (tests/coverage/coverage_rt.asm), which _exit skips, and with _exit
 * every error path this program exists to reach was missing from the coverage report. */
static pid_t spawn(void (*setup)(long), long arg)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(20);
        setup(arg);
        exit(scenario());
    }
    return pid;
}

/* in_child: runs the scenario in one child process (spawn) and waits for it. Returns 0 when it
 * ended by itself within the CPU limit, else -1 with *how describing it (judge). */
static int in_child(void (*setup)(long), long arg, char *how, size_t how_size)
{
    pid_t pid = spawn(setup, arg);
    int status = 0;
    struct rusage usage;
    if (pid < 0 || wait4(pid, &status, 0, &usage) != pid) {
        snprintf(how, how_size, "fork/wait failed");
        return -1;
    }
    return judge(status, &usage, how, how_size);
}

/* PARALLEL: the children run_parallel keeps running at once. Their scenarios are independent
 * (each server on a port of its own), mostly asleep (waiting on loopback), and the judgment
 * is per child (its own CPU time from wait4), so running them side by side changes no verdict
 * and divides the time: run one by one, the sweeps took most of an hour. */
#define PARALLEL 8

/* run_parallel: runs `total` children, PARALLEL at a time. Child i is configured in this
 * process by configure(i) just before its fork (it inherits that state), then runs setup(i) and
 * the scenario. Each child that did not end by itself is reported with report(i, how).
 * Returns how many those were. */
static int run_parallel(long total, void (*configure)(long), void (*setup)(long), void (*report)(long, const char *))
{
    struct { pid_t pid; long index; } running[PARALLEL];
    int active = 0;
    int failed = 0;
    long next = 0;
    while (next < total || active > 0) {
        while (active < PARALLEL && next < total) {
            configure(next);
            pid_t pid = spawn(setup, next);
            if (pid < 0) {
                report(next, "fork failed");
                failed++;
            } else {
                running[active].pid = pid;
                running[active].index = next;
                active++;
            }
            next++;
        }
        if (active == 0)
            continue;
        int status = 0;
        struct rusage usage;
        pid_t done = wait4(-1, &status, 0, &usage);
        if (done < 0) {
            perror("faults: wait4");
            return failed + active;
        }
        for (int i = 0; i < active; i++) {
            if (running[i].pid != done)
                continue;
            char how[128];
            if (judge(status, &usage, how, sizeof how) != 0) {
                report(running[i].index, how);
                failed++;
            }
            running[i] = running[--active];
            break;
        }
    }
    return failed;
}

/* ---- 3. Descriptor exhaustion. */

/* EXHAUST_ROOM: the descriptors the server's process may still open once the limit is set,
 * and EXHAUST_CONNECTIONS: the connections the other process makes, three times as many. */
#define EXHAUST_ROOM 4
#define EXHAUST_CONNECTIONS 12

/* exhaustion_server: the server's process. It starts a server on the backend `flags` asks
 * for (idle_ms: its idle timeout, 0 the default), lowers RLIMIT_NOFILE so only EXHAUST_ROOM more descriptors can be opened, writes the
 * port to `out`, then answers commands read from `in`: 'c' writes the process's CPU time so far
 * (microseconds, a uint64_t); anything else, or the parent's end, stops and destroys the server
 * and exits 0. Exits 2 when the server cannot start, 3 when the limit cannot be set. */
static void exhaustion_server(int in, int out, uint16_t flags, uint32_t idle_ms)
{
    httpasm_server_options o;
    memset(&o, 0, sizeof o);
    o.handler = handler;
    o.workers = 1;
    o.bind_address = htonl(INADDR_LOOPBACK);
    o.flags = flags;
    o.idle_timeout_ms = idle_ms;
    int error = 0;
    httpasm_server *s = httpasm_server_create(&o, &error);
    if (s == NULL || httpasm_server_start(s) != 0)
        exit(2);
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
            exit(3);
        if (fd > top) {
            close(fd);
            break;
        }
    }
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
        exit(3);
    limit.rlim_cur = (rlim_t)top + 1 + EXHAUST_ROOM;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
        exit(3);
    if (write(out, &port, sizeof port) != sizeof port)
        exit(3);
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
    exit(0);
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
 * idle_ms 0 keeps the default idle timeout, so the accepted connections hold their descriptors
 * through the check and the waiting request must not be answered early. A short one (50 ms)
 * closes them while the listener rests: the earliest deadline then comes before the pause's
 * end (100 ms), which the worker's wait must take first; the waiting request may then be
 * answered at any time, so only the rest (no spin) and the answer are checked.
 * Returns 0 when it held, else 1 with the failure printed. */
static int exhaustion(uint16_t flags, const char *backend, uint32_t idle_ms)
{
    int down[2], up[2];
    if (pipe(down) != 0 || pipe(up) != 0)
        return fprintf(stderr, "faults: exhaustion (%s): no pipe\n", backend), 1;
    fflush(NULL);                               /* the child ends with exit(): see in_child */
    pid_t pid = fork();
    if (pid == 0) {
        alarm(30);
        close(down[1]);
        close(up[0]);
        exhaustion_server(down[0], up[1], flags, idle_ms);
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
    if (answered_early != 0 && idle_ms == 0) {
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

static void set_syscall(long packed)
{
    if (fail_syscall((int)(packed >> 16), (int)(packed & 0xFFFF)) != 0)
        exit(100);
}

/* ---- 4. System calls: the k-th call failing, through a supervisor thread.
 *
 * A seccomp filter returning SECCOMP_RET_USER_NOTIF hands each call of one system call to the
 * listener the filter returned (SECCOMP_FILTER_FLAG_NEW_LISTENER); the supervisor thread reads
 * each (SECCOMP_IOCTL_NOTIF_RECV) and answers it (SECCOMP_IOCTL_NOTIF_SEND): the k-th with an
 * errno, every other with SECCOMP_USER_NOTIF_FLAG_CONTINUE, which lets the kernel run it as if
 * no filter were there (Linux 5.5). The supervisor is created before the filter is installed,
 * and the filter goes on the scenario's thread alone (no TSYNC): the threads that thread makes
 * afterwards - the server's workers, the threads that answer deferred requests - inherit it,
 * while the supervisor never meets it. So it can answer calls of any system call, thread
 * creation (clone3) and write included, without calling them in the middle of its own work. */

static int notify_nr = -1;                  /* the system call handed to the supervisor */
static int notify_err;                      /* the errno of the call that fails */
static long notify_fail_at;                 /* that call (1-based); 0: none fails, they are counted */
static _Atomic int notify_fd = -1;          /* the filter's listener, once installed */
static _Atomic long notify_calls;           /* calls seen by this process's supervisor */
static _Atomic long *notify_seen;           /* a counting run's calls, in memory shared with the
                                               parent (failing runs run side by side, so each
                                               counts in its own notify_calls) */

/* supervise: the supervisor's loop: waits for the listener (installing the filter takes
 * nothing from this thread), then answers every notification until the listener ends with the
 * process. Its two records are static: an allocation here would be counted with the
 * scenario's, and the notification sizes are the kernel's (SECCOMP_GET_NOTIF_SIZES).
 *   unused  pthread's argument. Returns NULL. */
static void *supervise(void *unused)
{
    (void)unused;
    int fd;
    while ((fd = atomic_load(&notify_fd)) < 0)
        usleep(50);
    struct seccomp_notif_sizes sizes;
    static _Alignas(16) unsigned char request_space[512], response_space[128];
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0 || sizes.seccomp_notif > sizeof request_space
        || sizes.seccomp_notif_resp > sizeof response_space) {
        fprintf(stderr, "faults: the kernel's notification records do not fit\n");
        exit(100);
    }
    struct seccomp_notif *request = (struct seccomp_notif *)request_space;
    struct seccomp_notif_resp *response = (struct seccomp_notif_resp *)response_space;
    for (;;) {
        memset(request, 0, sizes.seccomp_notif);    /* RECV requires a zeroed record */
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, request) != 0) {
            if (errno == EINTR)
                continue;
            return NULL;                            /* the listener is gone: the process ends */
        }
        long k = atomic_fetch_add(&notify_calls, 1) + 1;
        if (notify_fail_at == 0)
            atomic_store(notify_seen, k);           /* counting: the parent reads it */
        memset(response, 0, sizes.seccomp_notif_resp);
        response->id = request->id;
        if (k == notify_fail_at)
            response->error = -notify_err;
        else
            response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        /* ENOENT when the caller was interrupted meanwhile: its call is gone, nothing to do. */
        ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, response);
    }
}

/* start_supervised: a child's setup for the sweep: the supervisor thread, then the filter on
 * this thread, handing notify_nr's calls to it. Exits with 100 (counted apart) when the kernel
 * refuses either. */
static void start_supervised(long unused)
{
    (void)unused;
    pthread_t t;
    atomic_store(&notify_fd, -1);
    if (pthread_create(&t, NULL, supervise, NULL) != 0)
        exit(100);
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)notify_nr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = sizeof filter / sizeof filter[0], .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        exit(100);
    int fd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    if (fd < 0)
        exit(100);
    atomic_store(&notify_fd, fd);
}

/* SWEEP_LIMIT: the most calls of one system call failed in turn. A scenario makes some calls
 * hundreds of times (recvfrom, sendto); their sites are all among the first ones, and every
 * child costs a whole scenario. */
#define SWEEP_LIMIT 48

/* sweep_entry: one system call, the errno its failing call returns, and the scenario's server
 * options for it (thread creation is swept with two workers, so the second one's failure
 * leaves a server partly started; the CPU count with workers 0; io_uring's calls on a server
 * asking for io_uring). */
struct sweep_entry {
    int nr;
    int err;
    uint32_t workers;
    uint16_t flags;
    const char *name;
};

/* The entry sweep() is running, and its count: for configure_call and report_call. */
static const struct sweep_entry *sweep_entry_now;
static long sweep_count_now;

/* configure_call: before failing run i's fork: its call to fail is the (i + 1)-th. */
static void configure_call(long i)
{
    notify_fail_at = i + 1;
}

/* report_call: prints failing run i of the current entry, which did not end by itself. */
static void report_call(long i, const char *how)
{
    fprintf(stderr, "faults: %s, call %ld of %ld failing: %s\n", sweep_entry_now->name, i + 1, sweep_count_now, how);
}

/* sweep: counts entry's calls in one supervised run, then fails each of the first
 * SWEEP_LIMIT in a run of its own (run_parallel). Returns the runs whose child did not end by
 * itself (each printed), and adds the runs made to *runs. */
static int sweep(const struct sweep_entry *entry, long *runs)
{
    char how[128];
    scenario_workers = entry->workers;
    scenario_flags = entry->flags;
    notify_nr = entry->nr;
    notify_err = entry->err;
    notify_fail_at = 0;
    atomic_store(notify_seen, 0);
    int failed = 0;
    if (in_child(start_supervised, 0, how, sizeof how) != 0) {
        fprintf(stderr, "faults: %s, counting: %s\n", entry->name, how);
        failed++;
    }
    long count = atomic_load(notify_seen);
    long last = count < SWEEP_LIMIT ? count : SWEEP_LIMIT;
    sweep_entry_now = entry;
    sweep_count_now = count;
    failed += run_parallel(last, configure_call, start_supervised, report_call);
    *runs += 1 + last;
    scenario_workers = 1;
    scenario_flags = 0;
    return failed;
}

/* set_fail_index: a failing allocation run's setup in the child: the (i + 1)-th allocation of
 * its scenario fails (the child's count, at its fork, is the parent's). */
static void set_fail_index(long i)
{
    fail_at = atomic_load(&allocations) + i + 1;
}

/* configure_nothing: the allocation runs need no state set before their fork. */
static void configure_nothing(long i)
{
    (void)i;
}

/* The allocation runs' count, for report_allocation. */
static long allocation_count;

/* report_allocation: prints failing allocation run i, which did not end by itself. */
static void report_allocation(long i, const char *how)
{
    fprintf(stderr, "faults: allocation %ld of %ld failing: %s\n", i + 1, allocation_count, how);
}

/* main: counts the scenario's allocations, fails each, then each system call for good, then
 * each call of each system call in turn, then exhausts the descriptors.
 * "faults alloc N" runs the scenario once in this process with allocation N failing (no
 * child): for a debugger, when a child ended by a signal. */
int main(int argc, char **argv)
{
    int failures = 0;
    char how[128];
    build_messages();
    if (argc == 3 && strcmp(argv[1], "alloc") == 0) {
        fail_at = atol(argv[2]);
        int r = scenario();
        printf("faults: the scenario with allocation %ld failing returned %d\n", fail_at, r);
        return 0;
    }
    /* The count, in a child too: the parent's own allocations stay out of it. */
    long before = allocations;
    int r = scenario();
    long count = allocations - before;
    printf("faults: the scenario runs whole (%d) with %ld allocations\n", r, count);
    if (r != 0)
        return 1;
    /* Eight more than counted: the threads' order moves some allocations between runs. */
    allocation_count = count + 8;
    failures += run_parallel(allocation_count, configure_nothing, set_fail_index, report_allocation);
    printf("faults: each of %ld allocations failed in turn: %d children did not end by themselves\n", allocation_count, failures);

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
    /* 4. The k-th call of each system call the server, the client and the scenario make, with
     * the errnos those calls can see: the transient ones (EINTR, EAGAIN, a peer gone) as well
     * as the lasting ones section 2 tries. */
    static const struct sweep_entry entries[] = {
        { SYS_socket, EMFILE, 1, 0, "socket EMFILE" },
        { SYS_setsockopt, ENOMEM, 1, 0, "setsockopt ENOMEM" },
        { SYS_bind, EADDRINUSE, 1, 0, "bind EADDRINUSE" },
        { SYS_listen, ENOBUFS, 1, 0, "listen ENOBUFS" },
        { SYS_getsockname, ENOBUFS, 1, 0, "getsockname ENOBUFS" },
        { SYS_epoll_create1, EMFILE, 1, 0, "epoll_create1 EMFILE" },
        { SYS_epoll_ctl, ENOMEM, 1, 0, "epoll_ctl ENOMEM" },
        { SYS_epoll_wait, EINTR, 1, 0, "epoll_wait EINTR" },
        { SYS_eventfd2, EMFILE, 1, 0, "eventfd2 EMFILE" },
        { SYS_accept4, ECONNABORTED, 1, 0, "accept4 ECONNABORTED" },
        { SYS_accept4, EINTR, 1, 0, "accept4 EINTR" },
        { SYS_accept4, ENFILE, 1, 0, "accept4 ENFILE" },
        { SYS_accept4, ENOBUFS, 1, 0, "accept4 ENOBUFS" },
        { SYS_accept4, ENOMEM, 1, 0, "accept4 ENOMEM" },
        { SYS_recvfrom, EINTR, 1, 0, "recvfrom EINTR" },
        { SYS_recvfrom, EAGAIN, 1, 0, "recvfrom EAGAIN" },
        { SYS_recvfrom, ECONNRESET, 1, 0, "recvfrom ECONNRESET" },
        { SYS_sendto, EINTR, 1, 0, "sendto EINTR" },
        { SYS_sendto, EAGAIN, 1, 0, "sendto EAGAIN" },
        { SYS_sendto, EPIPE, 1, 0, "sendto EPIPE" },
        { SYS_sendmsg, EINTR, 1, 0, "sendmsg EINTR" },
        { SYS_sendmsg, EAGAIN, 1, 0, "sendmsg EAGAIN" },
        { SYS_sendmsg, EPIPE, 1, 0, "sendmsg EPIPE" },
        { SYS_connect, ECONNREFUSED, 1, 0, "connect ECONNREFUSED" },
        { SYS_poll, EINTR, 1, 0, "poll EINTR" },
        { SYS_getsockopt, ENOBUFS, 1, 0, "getsockopt ENOBUFS" },
        { SYS_shutdown, ENOTCONN, 1, 0, "shutdown ENOTCONN" },
        { SYS_read, EAGAIN, 1, 0, "read EAGAIN" },
        { SYS_clone3, EAGAIN, 2, 0, "clone3 EAGAIN (two workers)" },
        { SYS_sched_getaffinity, EINVAL, 0, 0, "sched_getaffinity EINVAL (one worker per CPU)" },
        { SYS_io_uring_setup, ENOMEM, 1, HTTPASM_SERVER_URING, "io_uring_setup ENOMEM" },
        { SYS_io_uring_setup, ENOMEM, 2, HTTPASM_SERVER_URING, "io_uring_setup ENOMEM (two workers: one on epoll)" },
        { SYS_mmap, ENOMEM, 1, HTTPASM_SERVER_URING, "mmap ENOMEM (io_uring)" },
    };
    /* Not swept, measured 2026-11-26: io_uring_enter, whose completions run as the caller's
     * task work, which the notification's wait holds back - even a counting run, failing
     * nothing, hung; and the eventfd's write, which no kernel fails with EAGAIN below its
     * counter's 2^64 - 2 (a failing wake hung the stop, which waits for the woken worker). */
    /* The supervisor's count lives in memory the children share with this process. */
    notify_seen = mmap(NULL, sizeof *notify_seen, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (notify_seen == MAP_FAILED) {
        perror("faults: mmap");
        return 1;
    }
    long sweep_runs = 0;
    long before_sweep = outcomes[100];
    int sweep_failures = 0;
    for (size_t i = 0; i < sizeof entries / sizeof entries[0]; i++)
        sweep_failures += sweep(&entries[i], &sweep_runs);
    printf("faults: %zu system calls failed one call at a time (%ld runs): %d children did not end by themselves\n",
           sizeof entries / sizeof entries[0], sweep_runs, sweep_failures);
    if (outcomes[100] != before_sweep) {
        fprintf(stderr, "faults: %ld supervised children could not install the filter\n", outcomes[100] - before_sweep);
        sweep_failures++;
    }

    printf("faults: the children's scenarios: %ld whole, %ld refused at create, %ld at start, %ld at the client's connect, "
           "%ld at its send, %ld without a filter; the most CPU a child used: %.2f s (the limit is %.1f s)\n",
           outcomes[0], outcomes[1], outcomes[2], outcomes[3], outcomes[4], outcomes[100], child_cpu_most, CHILD_CPU_LIMIT);

    int exhausted = exhaustion(0, "epoll", 0) + exhaustion(HTTPASM_SERVER_URING, "io_uring", 0)
                    + exhaustion(0, "epoll, 50 ms idle", 50) + exhaustion(HTTPASM_SERVER_URING, "io_uring, 50 ms idle", 50);
    return failures + syscall_failures + sweep_failures + exhausted == 0 ? 0 : 1;
}
