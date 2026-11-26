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
 *   2. Connects that have to wait: to a listener whose backlog is full (listen backlog 0 and
 *      one connection already waiting), so the SYN is dropped and the connect waits in the
 *      kernel. Under the same timer, interrupted again and again: with a 200 ms timeout it must
 *      end in -ETIMEDOUT (the deadline passes inside the poll loop); with no timeout it must
 *      connect once the listener accepts (the client's retransmitted SYN, about a second
 *      later); and when the listener closes meanwhile, it must report the refusal its socket
 *      learned (SO_ERROR: -ECONNREFUSED), not success. Then the other ends of that wait: with
 *      no signal at all, the connect's own timeout (SO_SNDTIMEO, which Linux reports as
 *      EINPROGRESS) must read -ETIMEDOUT too; after one signal and no more, the poll's own
 *      timeout must; a poll the kernel refuses (RLIMIT_NOFILE dropped to 0 meanwhile: EINVAL)
 *      must be reported, as must an outcome that cannot be read (getsockopt failing, under a
 *      seccomp filter in a child process, after the attempt ended).
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
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
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

/* timer_once: arms the SIGALRM timer to fire once, in microseconds: a single interruption. */
static void timer_once(long us)
{
    struct itimerval once = { .it_interval = { 0, 0 }, .it_value = { 0, us } };
    setitimer(ITIMER_REAL, &once, NULL);
}

/* What a waiting connect's helper thread does, after its delay. */
enum action {
    NOTHING,            /* no helper */
    ACCEPT,             /* accept the waiting connections (kept open until the process ends) */
    CLOSE_LISTENER,     /* close the listener: the client's retransmitted SYN is refused */
    NO_DESCRIPTORS,     /* RLIMIT_NOFILE to 0: the client's poll of its one socket is refused
                           (EINVAL: more descriptors than the limit); the connect returns first */
    SHUT_CONNECTING,    /* shutdown() of the client's socket while it connects: the attempt ends
                           (ECONNRESET in SO_ERROR), so the poll returns at once */
};

/* The helper's orders: its action, its delay, the listener (CLOSE_LISTENER, ACCEPT) and the
 * client's socket (SHUT_CONNECTING: the lowest free descriptor when the connect began, which
 * socket() gives it; nothing else opens one meanwhile). */
static enum action delayed_action;
static long delayed_us;
static int delayed_fd;
static int connecting_fd;

/* act_later: after delayed_us, carries out delayed_action. SIGALRM is blocked here (the
 * creating thread blocked it), so the timer's ticks keep landing on the connecting thread. */
static void *act_later(void *unused)
{
    (void)unused;
    usleep((useconds_t)delayed_us);
    struct rlimit none = { 0, 0 };
    switch (delayed_action) {
    case ACCEPT:
        for (int i = 0; i < 2; i++)
            accept(delayed_fd, NULL, NULL);
        break;
    case CLOSE_LISTENER:
        close(delayed_fd);
        break;
    case NO_DESCRIPTORS:
        getrlimit(RLIMIT_NOFILE, &none);
        none.rlim_cur = 0;
        setrlimit(RLIMIT_NOFILE, &none);
        break;
    case SHUT_CONNECTING:
        shutdown(connecting_fd, SHUT_RDWR);
        break;
    case NOTHING:
        break;
    }
    return NULL;
}

/* fail_getsockopt: a seccomp filter on this process making every getsockopt fail with ENOBUFS,
 * for the waiting connect whose outcome cannot be read (SO_ERROR). Returns 0, or -1. Only in a
 * child process: a filter cannot be taken back. */
static int fail_getsockopt(void)
{
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getsockopt, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOBUFS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = sizeof code / sizeof code[0], .filter = code };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
}

/* One waiting connect: how it is interrupted, what happens meanwhile, and its outcome. */
struct waiting_case {
    const char *what;
    long interval_us;           /* the timer: every this many microseconds, */
    long once_us;               /* or once, this long after the connect began (0: neither) */
    enum action action;
    long action_us;
    uint32_t timeout_ms;
    int in_child;               /* 1: in a child process whose getsockopt fails (seccomp) */
    int expected;               /* 0: connected; else -errno */
};

/* waiting_connect: runs one case. Returns 0, or 1 with the failure printed. */
static int waiting_connect(const struct waiting_case *w)
{
    sigset_t alarm_only;
    sigemptyset(&alarm_only);
    sigaddset(&alarm_only, SIGALRM);
    uint16_t port;
    int waiting;
    int fd = full_listener(&port, &waiting);
    if (fd < 0) {
        perror("signals: a full listener");
        return 1;
    }
    struct rlimit descriptors;
    getrlimit(RLIMIT_NOFILE, &descriptors);
    connecting_fd = dup(0);                         /* the lowest free descriptor: the client's next */
    close(connecting_fd);
    pthread_t helper;
    if (w->action != NOTHING) {
        delayed_action = w->action;
        delayed_us = w->action_us;
        delayed_fd = fd;
        pthread_sigmask(SIG_BLOCK, &alarm_only, NULL);
        int made = pthread_create(&helper, NULL, act_later, NULL);
        pthread_sigmask(SIG_UNBLOCK, &alarm_only, NULL);
        if (made != 0)
            return 1;
    }
    if (w->interval_us > 0)
        timer(w->interval_us);
    else if (w->once_us > 0)
        timer_once(w->once_us);
    int error = 0;
    httpasm_client *c = httpasm_client_connect(htonl(INADDR_LOOPBACK), port, w->timeout_ms, &error);
    timer(0);
    int got = c != NULL ? 0 : error;
    if (c != NULL)
        httpasm_client_close(c);
    if (w->action != NOTHING)
        pthread_join(helper, NULL);
    setrlimit(RLIMIT_NOFILE, &descriptors);         /* back, after NO_DESCRIPTORS */
    close(waiting);
    if (w->action != CLOSE_LISTENER)
        close(fd);
    if (got != w->expected) {
        fprintf(stderr, "signals: a waiting connect (%s) returned %d, not %d\n", w->what, got, w->expected);
        return 1;
    }
    return 0;
}

/* waiting_connects: part 2. Returns 0, or 1 with the failure printed. */
static int waiting_connects(void)
{
    static const struct waiting_case cases[] = {
        /* Under the 100-microsecond timer: the poll loop's own deadline; no timeout, connected
         * once the listener accepts (the retransmitted SYN, about a second later); the refusal
         * the socket learned when the listener closed. */
        { "a 200 ms timeout under the timer", 100, 0, NOTHING, 0, 200, 0, -ETIMEDOUT },
        { "no timeout under the timer", 100, 0, ACCEPT, 100000, 0, 0, 0 },
        { "the listener closing under the timer", 100, 0, CLOSE_LISTENER, 100000, 3000, 0, -ECONNREFUSED },
        /* No signal at all: the connect's own SO_SNDTIMEO passes (Linux: EINPROGRESS), and the
         * client reports the timeout as it does every other one. */
        { "a 200 ms timeout, no signal", 0, 0, NOTHING, 0, 200, 0, -ETIMEDOUT },
        /* One signal 20 ms in, then none: the poll that waits for the rest times out itself. */
        { "one signal, then the poll's own timeout", 0, 20000, NOTHING, 0, 300, 0, -ETIMEDOUT },
        /* The descriptor limit drops to 0 while the connect waits; the signal then sends the
         * client to poll, which refuses one descriptor past the limit: reported, the socket
         * closed. */
        { "the poll refused", 0, 30000, NO_DESCRIPTORS, 10000, 300, 0, -EINVAL },
        /* The attempt ends while the client polls (its socket shut down), and the outcome
         * cannot be read: getsockopt fails (seccomp, in a child process). */
        { "SO_ERROR unreadable", 0, 20000, SHUT_CONNECTING, 50000, 3000, 1, -ENOBUFS },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        if (!cases[i].in_child) {
            if (waiting_connect(&cases[i]) != 0)
                return 1;
            continue;
        }
        fflush(NULL);                               /* the child's exit() must not print it again */
        pid_t pid = fork();
        if (pid == 0)                               /* exit(), not _exit(): the coverage build writes its */
            exit(fail_getsockopt() != 0 ? 2 : waiting_connect(&cases[i]));     /* markers at exit */
        int status = 0;
        if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "signals: the child for a waiting connect (%s) failed (status %d)\n", cases[i].what, status);
            return 1;
        }
    }
    printf("signals: waiting connects: -ETIMEDOUT at the deadline under the timer, with no signal, and at the "
           "poll's own end; connected with no timeout; -ECONNREFUSED when the listener closed; -EINVAL when the "
           "poll was refused; -ENOBUFS when SO_ERROR could not be read\n");
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
