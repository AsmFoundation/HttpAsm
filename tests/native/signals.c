/*
 * signals.c - the client and the server survive signals (tests/native; run by
 * tests/run-linux.sh).
 *
 * A host process gets signals: SIGCHLD, a profiler's SIGPROF, alarm timers. A signal arriving
 * during a blocking call interrupts it with EINTR when its handler was installed without
 * SA_RESTART, and some calls are never restarted anyway (connect, epoll_wait, poll).
 * tests/fuzz/client found httpasm_client_connect returning -EINTR there (2026-11-26:
 * libFuzzer's timer signal). Every handler here does nothing and has no SA_RESTART, so every
 * interrupted call sees EINTR. Three parts:
 *
 *   1. 2,000 connects to a local listener under a 100-microsecond interval timer (SIGALRM, to
 *      this thread alone). Every connect must succeed; a thread drains the backlog.
 *   2. Connects that have to wait, under the same timer: to a listener whose backlog is full
 *      (listen backlog 0 and one connection already waiting), so the SYN is dropped and the
 *      connect waits in the kernel, interrupted again and again. With a 200 ms timeout it must
 *      end in -ETIMEDOUT (the deadline passes inside the poll loop); with no timeout it must
 *      connect once the listener accepts (the client's retransmitted SYN, about a second
 *      later); and when the listener closes meanwhile, it must report the refusal its socket
 *      learned (SO_ERROR: -ECONNREFUSED), not success.
 *   3. A server and the client under a storm: a thread sends SIGUSR1 to every other thread of
 *      the process every 100 microseconds (tgkill, so the server's workers get their share: a
 *      process-directed signal goes to the main thread first). The workers' waits (epoll_wait,
 *      io_uring_enter) and the client's blocking send and receive are interrupted throughout.
 *      200 GETs and 20 POSTs of 1 MiB echoed, and one request whose head carries a 1 MiB field
 *      (the client's sendmsg cut inside the head), on epoll and on io_uring: every answer must
 *      come whole.
 *
 * Exit status: 0 when every check held; 1 with the first failure printed; 2 when the setup
 * failed.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "httpasm.h"

enum { CONNECTS = 2000 };

static int listener;

/* tick: the signals' handler: nothing, so the only effect is the interrupted call. */
static void tick(int sig)
{
    (void)sig;
}

/* drain: accepts and closes every connection, so the backlog never fills. */
static void *drain(void *unused)
{
    (void)unused;
    for (;;) {
        int fd = accept(listener, NULL, NULL);
        if (fd >= 0)
            close(fd);
    }
    return NULL;
}

/* timer: arms (or, with 0, stops) the SIGALRM interval timer, in microseconds. */
static void timer(long us)
{
    struct itimerval every = { .it_interval = { 0, us }, .it_value = { 0, us } };
    setitimer(ITIMER_REAL, &every, NULL);
}

/* full_listener: a listener on 127.0.0.1 whose accept queue is full: backlog 0 admits one
 * waiting connection, made here (*waiting, never accepted), so a further SYN is dropped and
 * its connect waits. Returns the listener (its port in *port), or -1. */
static int full_listener(uint16_t *port, int *waiting)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in at = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t len = sizeof at;
    if (fd < 0 || bind(fd, (struct sockaddr *)&at, sizeof at) != 0 || listen(fd, 0) != 0
        || getsockname(fd, (struct sockaddr *)&at, &len) != 0)
        return -1;
    *port = ntohs(at.sin_port);
    *waiting = socket(AF_INET, SOCK_STREAM, 0);
    if (*waiting < 0 || connect(*waiting, (struct sockaddr *)&at, sizeof at) != 0)
        return -1;
    return fd;
}

/* The listener a helper thread acts on after a delay, and what it does: accept the waiting
 * connections (1) or close the listener (0). */
static int delayed_fd;
static int delayed_accepts;

/* act_later: 100 ms later, accepts every waiting connection (keeping them open until the
 * process ends) or closes the listener. SIGALRM is blocked here (the creating thread blocked
 * it), so the timer's ticks keep landing on the connecting thread. */
static void *act_later(void *unused)
{
    (void)unused;
    usleep(100000);
    if (!delayed_accepts) {
        close(delayed_fd);
        return NULL;
    }
    for (int i = 0; i < 2; i++)
        accept(delayed_fd, NULL, NULL);
    return NULL;
}

/* waiting_connects: part 2. Returns 0, or 1 with the failure printed. */
static int waiting_connects(void)
{
    sigset_t alarm_only;
    sigemptyset(&alarm_only);
    sigaddset(&alarm_only, SIGALRM);
    for (int variant = 0; variant < 3; variant++) {
        uint16_t port;
        int waiting;
        int fd = full_listener(&port, &waiting);
        if (fd < 0) {
            perror("signals: a full listener");
            return 1;
        }
        pthread_t helper;
        if (variant > 0) {
            delayed_fd = fd;
            delayed_accepts = variant == 1;
            pthread_sigmask(SIG_BLOCK, &alarm_only, NULL);
            int made = pthread_create(&helper, NULL, act_later, NULL);
            pthread_sigmask(SIG_UNBLOCK, &alarm_only, NULL);
            if (made != 0)
                return 1;
        }
        timer(100);
        int error = 0;
        uint32_t timeout = variant == 0 ? 200 : variant == 1 ? 0 : 3000;
        httpasm_client *c = httpasm_client_connect(htonl(INADDR_LOOPBACK), port, timeout, &error);
        timer(0);
        const char *what = variant == 0 ? "a 200 ms timeout" : variant == 1 ? "no timeout" : "the listener closing";
        int expected = variant == 0 ? -ETIMEDOUT : variant == 1 ? 0 : -ECONNREFUSED;
        int got = c != NULL ? 0 : error;
        if (c != NULL)
            httpasm_client_close(c);
        if (variant > 0)
            pthread_join(helper, NULL);
        close(waiting);
        if (variant != 2)
            close(fd);
        if (got != expected) {
            fprintf(stderr, "signals: a waiting connect with %s returned %d, not %d\n", what, got, expected);
            return 1;
        }
    }
    printf("signals: waiting connects under the timer: -ETIMEDOUT at the deadline, connected with no timeout, "
           "-ECONNREFUSED when the listener closed\n");
    return 0;
}

/* ---- 3. The storm. */

static _Atomic int storming;            /* 1 while the storm thread sends */
static _Atomic long storm_signals;      /* signals it sent */

/* storm: every 100 microseconds, SIGUSR1 to every other thread of the process (tgkill), until
 * storming is 0. It reads /proc/self/task each round, so threads made meanwhile (the
 * server's workers) get theirs too. */
static void *storm(void *unused)
{
    (void)unused;
    pid_t self = (pid_t)syscall(SYS_gettid);
    pid_t pid = getpid();
    while (atomic_load(&storming)) {
        DIR *tasks = opendir("/proc/self/task");
        if (tasks == NULL)
            break;
        struct dirent *entry;
        while ((entry = readdir(tasks)) != NULL) {
            pid_t tid = (pid_t)atol(entry->d_name);
            if (tid > 0 && tid != self && syscall(SYS_tgkill, pid, tid, SIGUSR1) == 0)
                atomic_fetch_add(&storm_signals, 1);
        }
        closedir(tasks);
        struct timespec pause = { 0, 100000 };
        nanosleep(&pause, NULL);
    }
    return NULL;
}

/* echo: answers a request with its body (a POST) or "ok". */
static void echo(void *context, httpasm_exchange *exchange)
{
    (void)context;
    size_t length = 0;
    const uint8_t *body = httpasm_exchange_body(exchange, &length);
    if (length > 0)
        httpasm_exchange_respond(exchange, 200, NULL, 0, body, length);
    else
        httpasm_exchange_respond(exchange, 200, NULL, 0, (const uint8_t *)"ok", 2);
}

/* send_request: one request by the client; checks the answer: 200 and the expected body.
 *   method, field  (field: NULL, or a field to send), body/length  the body.
 * Returns 0, or 1 with the failure printed. */
static int send_request(httpasm_client *c, const char *method, const httpasm_field *field, const uint8_t *body, size_t length,
                        const uint8_t *expected, size_t expected_length)
{
    httpasm_request q;
    memset(&q, 0, sizeof q);
    q.method = (const uint8_t *)method;
    q.method_length = (uint32_t)strlen(method);
    q.target = (const uint8_t *)"/";
    q.target_length = 1;
    q.authority = (const uint8_t *)"t";
    q.authority_length = 1;
    q.fields = (httpasm_field *)field;
    q.field_count = field != NULL ? 1 : 0;
    httpasm_client_response r;
    int result = httpasm_client_send(c, &q, body, length, &r);
    if (result != 0 || r.head.status != 200 || r.body_length != expected_length || memcmp(r.body, expected, expected_length) != 0) {
        fprintf(stderr, "signals: a %s under the storm: result %d, status %u, %zu octets of %zu\n", method, result,
                result == 0 ? r.head.status : 0, result == 0 ? (size_t)r.body_length : 0, expected_length);
        return 1;
    }
    return 0;
}

/* storm_server: part 3 on one backend (flags 0: epoll, HTTPASM_SERVER_URING). Returns 0, or 1
 * with the failure printed. */
static int storm_server(uint16_t flags)
{
    static uint8_t upload[1 << 20];
    for (size_t i = 0; i < sizeof upload; i++)
        upload[i] = (uint8_t)(i * 7 + 1);
    static char huge[1 << 20];
    memset(huge, 'h', sizeof huge);
    const httpasm_field field = { (const uint8_t *)"X-Huge", (const uint8_t *)huge, 6, sizeof huge, 0, 0, 0 };

    httpasm_server_options o;
    memset(&o, 0, sizeof o);
    o.handler = echo;
    o.workers = 2;
    o.flags = flags;
    o.bind_address = htonl(INADDR_LOOPBACK);
    o.max_body = 2 << 20;
    o.limits.max_head = 4 << 20;
    int error = 0;
    httpasm_server *s = httpasm_server_create(&o, &error);
    if (s == NULL || httpasm_server_start(s) != 0) {
        fprintf(stderr, "signals: the storm's server did not start (%d)\n", error);
        return 2;
    }
    atomic_store(&storming, 1);
    pthread_t t;
    if (pthread_create(&t, NULL, storm, NULL) != 0)
        return 2;
    int failed = 0;
    httpasm_client *c = httpasm_client_connect(htonl(INADDR_LOOPBACK), httpasm_server_port(s), 10000, &error);
    if (c == NULL) {
        fprintf(stderr, "signals: the storm's connect failed (%d)\n", error);
        failed = 1;
    }
    for (int i = 0; i < 200 && failed == 0; i++)
        failed = send_request(c, "GET", NULL, NULL, 0, (const uint8_t *)"ok", 2);
    for (int i = 0; i < 20 && failed == 0; i++)
        failed = send_request(c, "POST", NULL, upload, sizeof upload, upload, sizeof upload);
    if (failed == 0)
        failed = send_request(c, "GET", &field, NULL, 0, (const uint8_t *)"ok", 2);
    if (c != NULL)
        httpasm_client_close(c);
    atomic_store(&storming, 0);
    pthread_join(t, NULL);
    long sent = atomic_load(&storm_signals);
    httpasm_server_stop(s);
    httpasm_server_destroy(s);
    if (failed == 0)
        printf("signals: the storm (%s): 221 requests answered whole under %ld signals\n", flags ? "io_uring" : "epoll", sent);
    return failed;
}

/* main: the three parts. Returns 0 when all held, 1 at the first failure, 2 when the setup
 * failed. */
int main(void)
{
    listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in at = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t len = sizeof at;
    if (listener < 0 || bind(listener, (struct sockaddr *)&at, sizeof at) != 0 || listen(listener, 512) != 0
        || getsockname(listener, (struct sockaddr *)&at, &len) != 0) {
        perror("signals: listener");
        return 2;
    }
    /* The drain thread blocks the timer's signal, so every tick lands on this thread, the one
     * that connects. */
    sigset_t alarm_only;
    sigemptyset(&alarm_only);
    sigaddset(&alarm_only, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &alarm_only, NULL);
    pthread_t t;
    if (pthread_create(&t, NULL, drain, NULL) != 0)
        return 2;
    pthread_sigmask(SIG_UNBLOCK, &alarm_only, NULL);

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = tick;                /* no SA_RESTART: interrupted calls see EINTR */
    sigaction(SIGALRM, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
    timer(100);

    for (int i = 0; i < CONNECTS; i++) {
        int error = 0;
        httpasm_client *c = httpasm_client_connect(htonl(INADDR_LOOPBACK), ntohs(at.sin_port), 2000, &error);
        if (c == NULL) {
            timer(0);
            fprintf(stderr, "signals: connect %d of %d failed with %d\n", i + 1, CONNECTS, error);
            return 1;
        }
        httpasm_client_close(c);
    }
    timer(0);
    printf("signals: %d connects under a 100-microsecond timer signal, all connected\n", CONNECTS);

    if (waiting_connects() != 0)
        return 1;
    int stormed = storm_server(0);
    if (stormed == 0)
        stormed = storm_server(HTTPASM_SERVER_URING);
    return stormed;
}
