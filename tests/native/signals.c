/*
 * signals.c - the client's connect survives signals (tests/native; run by tests/run-linux.sh).
 *
 * A host process gets signals: SIGCHLD, a profiler's SIGPROF, alarm timers. A signal arriving
 * during a blocking connect interrupts it with EINTR, and nothing restarts connect (SA_RESTART
 * never does for it); the attempt goes on in the kernel. tests/fuzz/client found
 * httpasm_client_connect returning -EINTR there (2026-11-26: libFuzzer's timer signal).
 *
 * This program arms a 100-microsecond interval timer whose handler does nothing, installed
 * without SA_RESTART so every interrupted call sees EINTR, and connects to a local listener
 * 2,000 times. Every connect must succeed; the listener's backlog is drained by a thread.
 *
 * Exit status: 0 when every connect succeeded; 1 with the first failure's -errno printed.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "httpasm.h"

enum { CONNECTS = 2000 };

static int listener;

/* tick: the timer's handler: nothing, so the only effect is the interrupted call. */
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

/* main: the listener, the timer, the connects. Returns 0 when all succeeded, 1 otherwise, 2 when
 * the setup failed. */
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
    struct itimerval every = { .it_interval = { 0, 100 }, .it_value = { 0, 100 } };
    setitimer(ITIMER_REAL, &every, NULL);

    for (int i = 0; i < CONNECTS; i++) {
        int error = 0;
        httpasm_client *c = httpasm_client_connect(htonl(INADDR_LOOPBACK), ntohs(at.sin_port), 2000, &error);
        if (c == NULL) {
            struct itimerval off = { 0 };
            setitimer(ITIMER_REAL, &off, NULL);
            fprintf(stderr, "signals: connect %d of %d failed with %d\n", i + 1, CONNECTS, error);
            return 1;
        }
        httpasm_client_close(c);
    }
    struct itimerval off = { 0 };
    setitimer(ITIMER_REAL, &off, NULL);
    printf("signals: %d connects under a 100-microsecond timer signal, all connected\n", CONNECTS);
    return 0;
}
