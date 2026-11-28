/*
 * forks.c - proves that the server's event registrations end with its own descriptors, whatever
 * other processes hold: a connection the server closed gets no more events, and a stopping
 * server's listener stops reporting, while a child holds copies of the server's descriptors.
 * Every fork() makes such a child for a while (the server's descriptors are CLOEXEC, so an exec
 * drops them, but between the fork and the exec the child holds every one of them), and a child
 * that never execs holds them for its whole life. A process that embeds the server and starts
 * other programs - a .NET application calling Process.Start, a test suite running tools - forks
 * at moments the server cannot know.
 *
 * Why it matters: epoll's interest list holds (descriptor, open file description) pairs, and a
 * close() takes a pair off only once every descriptor of the description is closed (epoll(7),
 * "Will closing a file descriptor cause it to be removed from all epoll interest lists?"). A
 * server that counts on close() keeps the registration while a child holds a copy: the closed
 * connection's events go on coming, level-triggered, carrying the pointer of memory the server
 * freed. The worker spins on them, reads the freed memory, and once that memory is the next
 * connection's, treats that connection by the dead one's events and closes it. The .NET suite
 * met it as h2spec's "Error: EOF" (connections closed mid-handshake) and a "double free or
 * corruption (out)" abort, whenever tests that start processes ran beside the HTTP/2 ones.
 * libuv removes each descriptor from its epoll set before closing it for the same reason.
 *
 * Each scenario runs one worker on the backend HTTPASM_TEST_IO names (uring: io_uring; anything
 * else: epoll), and holds a child (forked, blocked on a pipe) across the part that matters:
 *   1. connection: connection A answered; the child forked (it holds the server's end of A); A
 *      closed by the client and the server's end seen closed (/proc/self/fd); three new
 *      connections answered twice each and kept open (the first is the likeliest to get A's
 *      freed memory); then the process' CPU time over a quiet window: a worker spinning on A's
 *      events takes all of it, an idle one next to none. After the child is released, one more
 *      connection is answered (the server still serves).
 *   2. listener: a request deferred (the stop then waits for its answer); the child forked (it
 *      holds the listener); httpasm_server_stop on a thread, and the listener seen closed; a
 *      client connects (the child's copy keeps the socket listening, so the kernel queues the
 *      connection on it); the CPU time over a quiet window again; then the deferred answer,
 *      which its client must get whole, and the stop must finish.
 *
 * Usage: forks            (HTTPASM_TEST_IO=uring: the server on io_uring)
 * Exit status: 0 when every check held; 1 when one did not (printed); 2 when the setup failed.
 * Build: tests/native/build.sh.
 */
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "httpasm.h"

/* The handler's one answer body: read_answer expects exactly these octets after each head. */
static const char body[] = "forked";

/* The quiet window (ms) and the CPU time the whole process may take over it (ms). A worker
 * spinning on stale events takes the window whole (or its share of a CPU under load, which on
 * any machine this runs on is far above the bound); an idle process takes well under 1 ms. */
#define QUIET_MS 300
#define QUIET_CPU_MS 60

/* How long a client waits for an answer, and the setup waits for the server, in ms: a server
 * that broke must fail the run, not hang it. */
#define ANSWER_TIMEOUT_MS 5000
#define WAIT_MS 2000

/* The exchange the handler deferred (scenario 2), answered by main once the window is over. */
static _Atomic(httpasm_exchange *) deferred;

/* handler: answers every request 200 with `body` at once, except a request for /defer, which it
 * defers and leaves in `deferred` for main to answer.
 *   context  unused; exchange  the request. */
static void handler(void *context, httpasm_exchange *exchange)
{
    (void)context;
    const httpasm_request *request = httpasm_exchange_request(exchange);
    if (request->target_length == 6 && memcmp(request->target, "/defer", 6) == 0
        && httpasm_exchange_defer(exchange) == 0) {
        atomic_store(&deferred, exchange);
        return;
    }
    httpasm_exchange_respond(exchange, 200, NULL, 0, (const uint8_t *)body, sizeof body - 1);
}

/* monotonic_ms: CLOCK_MONOTONIC in milliseconds (deadlines). */
static double monotonic_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

/* cpu_ms: the CPU time of the whole process in milliseconds - every thread, so the server's
 * worker too (this program's own threads sleep or block while it is measured). */
static double cpu_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

/* sleep_ms: sleeps `ms` milliseconds, resumed after a signal.
 *   ms  the time, 0 to 999,999. */
static void sleep_ms(long ms)
{
    struct timespec t = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    while (nanosleep(&t, &t) != 0 && errno == EINTR) {
    }
}

/* descriptors: how many descriptors the process has open (/proc/self/fd's entries, the listing's
 * own descriptor left out). Returns the count, or -1 when /proc cannot be read. */
static int descriptors(void)
{
    DIR *listing = opendir("/proc/self/fd");
    if (listing == NULL)
        return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(listing)) != NULL)
        if (entry->d_name[0] != '.')
            count++;
    closedir(listing);
    return count - 1;                               /* the listing's own */
}

/* wait_descriptors: waits up to WAIT_MS for the process to have `most` descriptors open or
 * fewer - how this program sees the server close one of its own (the child's copies are the
 * child's: they do not count here).
 *   most  the count to reach.
 * Returns 1 when it was reached, 0 at the deadline. */
static int wait_descriptors(int most)
{
    double deadline = monotonic_ms() + WAIT_MS;
    for (;;) {
        int open = descriptors();
        if (open >= 0 && open <= most)
            return 1;
        if (monotonic_ms() > deadline)
            return 0;
        sleep_ms(1);
    }
}

/* dial: a client socket connected to 127.0.0.1:port, its reads timed out after
 * ANSWER_TIMEOUT_MS (a read that times out fails the check it serves).
 *   port  the server's.
 * Returns the socket, or -1 (printed). */
static int dial(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("forks: socket");
        return -1;
    }
    struct timeval timeout = { .tv_sec = ANSWER_TIMEOUT_MS / 1000, .tv_usec = 0 };
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) != 0
        || connect(fd, (struct sockaddr *)&to, sizeof to) != 0) {
        perror("forks: connect");
        close(fd);
        return -1;
    }
    return fd;
}

/* send_request: sends one keep-alive GET.
 *   fd  a connected socket; target  the request-target ("/" or "/defer").
 * Returns 0, or -1 (printed). */
static int send_request(int fd, const char *target)
{
    char request[128];
    int length = snprintf(request, sizeof request, "GET %s HTTP/1.1\r\nHost: t\r\n\r\n", target);
    if (write(fd, request, (size_t)length) != length) {
        perror("forks: write");
        return -1;
    }
    return 0;
}

/* read_answer: reads one answer - its head, then the body's octets (the handler's only body, so
 * a keep-alive answer ends right there) - and checks it is a 200 carrying `body`.
 *   fd  the socket; what  the check's name, for the message.
 * Returns 0 when a whole 200 came; -1 (printed) when the connection ended, failed or timed out
 * first, or the answer is another. */
static int read_answer(int fd, const char *what)
{
    char answer[2048];
    size_t used = 0;
    for (;;) {
        answer[used] = 0;
        const char *end = strstr(answer, "\r\n\r\n");
        if (end != NULL && used >= (size_t)(end - answer) + 4 + sizeof body - 1)
            break;
        if (used == sizeof answer - 1) {
            fprintf(stderr, "forks: %s: an answer longer than %zu octets\n", what, sizeof answer - 1);
            return -1;
        }
        ssize_t n = read(fd, answer + used, sizeof answer - 1 - used);
        if (n <= 0) {
            fprintf(stderr, "forks: %s: %s after %zu octets of the answer\n", what,
                    n == 0 ? "the server closed the connection" : strerror(errno), used);
            return -1;
        }
        used += (size_t)n;
    }
    const char *end = strstr(answer, "\r\n\r\n");
    if (strncmp(answer, "HTTP/1.1 200 ", 13) != 0 || memcmp(end + 4, body, sizeof body - 1) != 0) {
        fprintf(stderr, "forks: %s: not a 200 with the body: %s\n", what, answer);
        return -1;
    }
    return 0;
}

/* ask: one request and its answer on a keep-alive connection.
 *   fd  the socket; what  the check's name.
 * Returns 0, or -1 (printed). */
static int ask(int fd, const char *what)
{
    return send_request(fd, "/") != 0 ? -1 : read_answer(fd, what);
}

/* hold: forks a child that holds a copy of every descriptor the process has until released. The
 * child closes its copy of the gate's write end, blocks reading the read end, and _exits: only
 * async-signal-safe calls, as a fork of a process with threads must (the server's worker runs).
 *   gate  receives the gate's write end: closing it releases the child.
 * Returns the child's pid, or -1 (printed). */
static pid_t hold(int *gate)
{
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) {
        perror("forks: pipe");
        return -1;
    }
    pid_t child = fork();
    if (child < 0) {
        perror("forks: fork");
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }
    if (child == 0) {
        char octet;
        close(pipe_fds[1]);
        while (read(pipe_fds[0], &octet, 1) < 0 && errno == EINTR) {
        }
        _exit(0);
    }
    close(pipe_fds[0]);
    *gate = pipe_fds[1];
    return child;
}

/* release: lets the child go (its gate closed: its read sees the end) and reaps it.
 *   child  hold's pid; gate  hold's write end.
 * Returns 0, or -1 (printed) when the child could not be reaped or did not exit with 0. */
static int release(pid_t child, int gate)
{
    close(gate);
    int status = 0;
    pid_t reaped;
    while ((reaped = waitpid(child, &status, 0)) < 0 && errno == EINTR) {
    }
    if (reaped != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "forks: the child did not end as it should (status %d)\n", status);
        return -1;
    }
    return 0;
}

/* start_server: a server of one worker (every connection on the one epoll instance or ring the
 * scenario looks at) on 127.0.0.1, any port, on HTTPASM_TEST_IO's backend.
 *   uring  nonzero: io_uring, checked to be what the server runs on.
 * Returns the started server, or NULL (printed). */
static httpasm_server *start_server(int uring)
{
    httpasm_server_options options;
    memset(&options, 0, sizeof options);
    options.handler = handler;
    options.workers = 1;
    options.bind_address = htonl(INADDR_LOOPBACK);
    options.flags = uring ? HTTPASM_SERVER_URING : 0;
    int error = 0;
    httpasm_server *server = httpasm_server_create(&options, &error);
    if (server == NULL || httpasm_server_start(server) != 0) {
        fprintf(stderr, "forks: the server did not start (error %d)\n", error);
        if (server != NULL)
            httpasm_server_destroy(server);
        return NULL;
    }
    if (httpasm_server_io(server) != (uring ? HTTPASM_SERVER_IO_URING : HTTPASM_SERVER_IO_EPOLL)) {
        fprintf(stderr, "forks: the server runs on another backend than asked (io %u)\n", httpasm_server_io(server));
        httpasm_server_destroy(server);
        return NULL;
    }
    return server;
}

/* quiet_cpu: the process' CPU time over QUIET_MS of sleep, against QUIET_CPU_MS.
 *   what  the moment measured, for the message.
 * Returns 0 when under the bound; 1 (printed) when over: a worker spinning. */
static int quiet_cpu(const char *what)
{
    double before = cpu_ms();
    sleep_ms(QUIET_MS);
    double used = cpu_ms() - before;
    if (used > QUIET_CPU_MS) {
        fprintf(stderr, "forks: %s: the process ran %.1f ms of a %d ms quiet window (a worker spinning on events "
                "for a descriptor it closed)\n", what, used, QUIET_MS);
        return 1;
    }
    return 0;
}

/* A stop on its own thread (scenario 2): httpasm_server_stop blocks until the deferred answer
 * leaves, and main must answer it meanwhile. */
typedef struct stopper {
    httpasm_server *server;     /* in */
    atomic_int done;            /* set when httpasm_server_stop returned */
} stopper;

/* stop_thread: stops the server and says so.
 *   argument  the stopper. Returns NULL. */
static void *stop_thread(void *argument)
{
    stopper *s = argument;
    httpasm_server_stop(s->server);
    atomic_store(&s->done, 1);
    return NULL;
}

/* scenario_connection: scenario 1 (the file's header).
 *   uring  the backend.
 * Returns 0, 1 when a check failed (printed), 2 when the setup failed. */
static int scenario_connection(int uring)
{
    httpasm_server *server = start_server(uring);
    if (server == NULL)
        return 2;
    uint16_t port = httpasm_server_port(server);
    int a = dial(port);
    if (a < 0 || ask(a, "connection A's request") != 0) {
        httpasm_server_destroy(server);
        return 2;
    }
    int gate = -1;
    pid_t child = hold(&gate);
    int before = descriptors();                     /* (the gate's write end counted) */
    if (before < 0 || child < 0) {
        httpasm_server_destroy(server);
        return 2;
    }

    int failed = 0;
    /* the child holds our end of A too, so a close alone would send nothing: shutdown ends the
       socket itself (its FIN goes whoever holds copies), then our descriptor goes */
    shutdown(a, SHUT_WR);
    close(a);
    /* our end of A, then the server's (it reads the end and closes its descriptor; the child's
       copy keeps the file description, and with it any registration close() left behind) */
    if (!wait_descriptors(before - 2)) {
        fprintf(stderr, "forks: connection: the server never closed its end of connection A (%d descriptors open, "
                "%d before A closed)\n", descriptors(), before);
        failed = 1;
    }
    int kept[3] = { -1, -1, -1 };
    for (int i = 0; i < 3; i++) {
        char what[64];
        snprintf(what, sizeof what, "connection %d after A closed", i + 1);
        kept[i] = dial(port);
        if (kept[i] < 0 || ask(kept[i], what) != 0 || ask(kept[i], what) != 0)
            failed = 1;
    }
    failed |= quiet_cpu("connection: after A closed, a child holding the server's end of it");
    if (release(child, gate) != 0)
        failed = 1;
    for (int i = 0; i < 3; i++)
        if (kept[i] >= 0)
            close(kept[i]);
    int last = dial(port);
    if (last < 0 || ask(last, "a connection after the child ended") != 0)
        failed = 1;
    if (last >= 0)
        close(last);
    httpasm_server_destroy(server);
    if (!failed)
        printf("forks: connection (%s): a closed connection's end held by a child: no more events, the next connections served\n",
               uring ? "io_uring" : "epoll");
    return failed;
}

/* scenario_listener: scenario 2 (the file's header).
 *   uring  the backend.
 * Returns 0, 1 when a check failed (printed), 2 when the setup failed. */
static int scenario_listener(int uring)
{
    httpasm_server *server = start_server(uring);
    if (server == NULL)
        return 2;
    uint16_t port = httpasm_server_port(server);
    atomic_store(&deferred, NULL);
    int d = dial(port);
    if (d < 0 || send_request(d, "/defer") != 0) {
        httpasm_server_destroy(server);
        return 2;
    }
    double deadline = monotonic_ms() + WAIT_MS;
    while (atomic_load(&deferred) == NULL && monotonic_ms() < deadline)
        sleep_ms(1);
    if (atomic_load(&deferred) == NULL) {
        fprintf(stderr, "forks: listener: the request was never deferred\n");
        httpasm_server_destroy(server);
        return 2;
    }
    int gate = -1;
    pid_t child = hold(&gate);
    int before = descriptors();                     /* (the gate's write end counted) */
    if (before < 0 || child < 0) {
        httpasm_exchange_respond(atomic_load(&deferred), 200, NULL, 0, (const uint8_t *)body, sizeof body - 1);
        httpasm_server_destroy(server);
        return 2;
    }

    int failed = 0;
    stopper s = { .server = server };
    atomic_init(&s.done, 0);
    pthread_t thread;
    if (pthread_create(&thread, NULL, stop_thread, &s) != 0) {
        fprintf(stderr, "forks: listener: no thread for the stop\n");
        httpasm_exchange_respond(atomic_load(&deferred), 200, NULL, 0, (const uint8_t *)body, sizeof body - 1);
        release(child, gate);
        httpasm_server_destroy(server);
        return 2;
    }
    /* the stop closes the listener (the deferred connection is busy: it stays) */
    if (!wait_descriptors(before - 1)) {
        fprintf(stderr, "forks: listener: the stopping server never closed its listener (%d descriptors open, "
                "%d before the stop)\n", descriptors(), before);
        failed = 1;
    }
    /* the child's copy keeps the socket listening: this connection waits in its queue (a refusal
       would mean no copy was held, which is not this program's concern: only the worker is) */
    int c = dial(port);
    failed |= quiet_cpu("listener: a stopping server's listener held by a child, a connection queued on it");
    httpasm_exchange_respond(atomic_load(&deferred), 200, NULL, 0, (const uint8_t *)body, sizeof body - 1);
    if (read_answer(d, "listener: the deferred answer") != 0)
        failed = 1;
    deadline = monotonic_ms() + 10000;              /* the stop's grace is 5 s */
    while (!atomic_load(&s.done) && monotonic_ms() < deadline)
        sleep_ms(1);
    if (!atomic_load(&s.done)) {
        /* a stuck worker would keep the thread forever: report and leave without joining */
        fprintf(stderr, "forks: listener: the stop never finished\n");
        return 1;
    }
    pthread_join(thread, NULL);
    if (release(child, gate) != 0)
        failed = 1;
    if (c >= 0)
        close(c);
    close(d);
    httpasm_server_destroy(server);
    if (!failed)
        printf("forks: listener (%s): a stopping server's listener held by a child: no more events, the stop finished\n",
               uring ? "io_uring" : "epoll");
    return failed;
}

/* main: both scenarios on HTTPASM_TEST_IO's backend. Returns 0, 1 when a check failed, 2 when
 * the setup failed (the worst of the two). */
int main(void)
{
    const char *io = getenv("HTTPASM_TEST_IO");
    int uring = io != NULL && strcmp(io, "uring") == 0;
    int first = scenario_connection(uring);
    int second = scenario_listener(uring);
    return first > second ? first : second;
}
