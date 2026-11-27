/*
 * random.c - proves httpasm_random (src/HttpAsm/random.asm) on every path getrandom(2) can take:
 *   - fills: lengths 0 to 4 KiB, 1 MiB (its octet histogram against a chi-square bound), and
 *     64 MiB, which the kernel serves in two short reads (it caps a call at 32 MiB - 1); every
 *     buffer pre-filled with a pattern no 64-octet stretch of random output keeps;
 *   - signals: 64 MiB requests under a 50-microsecond interval timer whose handler does not
 *     restart system calls, so calls come back short (a signal after some octets) or with EINTR
 *     (a signal before any): the buffer must still come back full;
 *   - refusals, each in a forked child (a seccomp filter can never be removed): getrandom
 *     answered EPERM (a sandbox) and ENOSYS (an old kernel) must come back as those errors, and
 *     "error 0" (a filter that returns no octets and no error) as -EIO, not a spin;
 *   - EINTR made certain: in a forked child, a supervisor thread answers getrandom's first call
 *     with -EINTR through seccomp's user notification and lets every later one through (the
 *     timer above meets EINTR only when a signal is pending just as a call starts, which no run
 *     can promise): the buffer must come back full.
 * The children leave with exit(), not _exit(): the coverage build writes its marks at exit, from
 * .fini_array, which _exit skips.
 * Usage: random
 * Exit status: 0 when every check holds; 1 when one fails (printed); 2 on a setup error.
 * Build: tests/native/build.sh.
 */
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "httpasm.h"

/* full: 1 when no 64-octet stretch of buf[0..n) still holds the pattern 0xA5 it was given
 * before the call (random output keeps one with probability 2^-512 a stretch). */
static int full(const uint8_t *buf, size_t n)
{
    for (size_t at = 0; at + 64 <= n; at += 64) {
        size_t k = 0;
        while (k < 64 && buf[at + k] == 0xA5)
            k++;
        if (k == 64) {
            fprintf(stderr, "random: 64 octets at %zu of %zu never filled\n", at, n);
            return 0;
        }
    }
    return 1;
}

/* fill: one call into a buffer of n octets pre-filled with 0xA5. Returns 0 when it returned 0
 * and filled everything, 1 otherwise (printed). */
static int fill(uint8_t *buf, size_t n)
{
    memset(buf, 0xA5, n);
    int result = httpasm_random(buf, n);
    if (result != 0) {
        fprintf(stderr, "random: %zu octets: httpasm_random returned %d\n", n, result);
        return 1;
    }
    return full(buf, n) ? 0 : 1;
}

/* histogram: chi-square of 1 MiB's octet counts against the uniform 4096 each; 255 degrees of
 * freedom put 99.99% of honest draws below 360. Returns 0 below the bound. */
static int histogram(uint8_t *buf)
{
    enum { N = 1 << 20 };
    long counts[256] = { 0 };
    if (httpasm_random(buf, N) != 0)
        return 1;
    for (size_t i = 0; i < N; i++)
        counts[buf[i]]++;
    double chi = 0;
    for (int v = 0; v < 256; v++) {
        double d = counts[v] - N / 256.0;
        chi += d * d / (N / 256.0);
    }
    if (chi > 360) {
        fprintf(stderr, "random: chi-square %.1f over 1 MiB (bound 360)\n", chi);
        return 1;
    }
    printf("random: 1 MiB, chi-square %.1f (255 degrees of freedom)\n", chi);
    return 0;
}

static volatile sig_atomic_t ticks;
static void on_tick(int sig) { (void)sig; ticks++; }

/* under_signals: ten 64 MiB requests under a 50 us interval timer (SA_RESTART off). Returns 0
 * when every buffer came back full. */
static int under_signals(uint8_t *buf, size_t n)
{
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_tick;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, NULL) != 0)
        return 2;
    struct itimerval timer = { { 0, 50 }, { 0, 50 } };
    if (setitimer(ITIMER_REAL, &timer, NULL) != 0)
        return 2;
    int failed = 0;
    for (int i = 0; i < 10 && !failed; i++)
        failed = fill(buf, n);
    struct itimerval off = { { 0, 0 }, { 0, 0 } };
    setitimer(ITIMER_REAL, &off, NULL);
    if (!failed)
        printf("random: 10 x %zu MiB under %d timer signals, every buffer full\n", n >> 20, (int)ticks);
    return failed;
}

/* refused: in a forked child, getrandom answered with the seccomp action `action` (ERRNO with
 * the given errno in its data): httpasm_random must return `expected`. Returns 0 when it did. */
static int refused(uint32_t action, int expected, const char *what)
{
    fflush(stdout);                                 /* exit() in the child flushes its copy */
    fflush(stderr);
    pid_t child = fork();
    if (child < 0)
        return 2;
    if (child == 0) {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getrandom, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, action),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog program = { (unsigned short)(sizeof filter / sizeof filter[0]), filter };
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0)
            exit(2);
        uint8_t buf[64];
        signal(SIGALRM, SIG_DFL);                   /* (the parent's timer handler came along) */
        alarm(10);                                  /* a spin would end here, as a failure */
        exit(httpasm_random(buf, sizeof buf) == expected ? 0 : 1);
    }
    int status;
    if (waitpid(child, &status, 0) != child)
        return 2;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "random: getrandom %s: httpasm_random did not return %d (status %#x)\n", what, expected, status);
        return WIFEXITED(status) && WEXITSTATUS(status) == 2 ? 2 : 1;
    }
    printf("random: getrandom %s: httpasm_random returned %d\n", what, expected);
    return 0;
}

/* The interrupted_once child's notification descriptor, passed to its supervisor through a pipe
 * (the supervisor exists before the filter, so the filter does not apply to it). */
static int notify_pipe[2];

/* supervise: the supervisor thread: reads the notification descriptor from the pipe, then answers
 * getrandom's first call with -EINTR and lets every later call run (CONTINUE). Ends when the
 * descriptor goes away (the process exits). */
static void *supervise(void *unused)
{
    (void)unused;
    int fd;
    if (read(notify_pipe[0], &fd, sizeof fd) != (ssize_t)sizeof fd)
        return NULL;
    for (int call = 0;; call++) {
        struct seccomp_notif request;
        struct seccomp_notif_resp response;
        memset(&request, 0, sizeof request);
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &request) != 0)
            return NULL;
        memset(&response, 0, sizeof response);
        response.id = request.id;
        if (call == 0)
            response.error = -EINTR;                /* interrupted before any octet */
        else
            response.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &response) != 0)
            return NULL;
    }
}

/* interrupted_once: in a forked child, getrandom's first call answered -EINTR (see supervise):
 * httpasm_random must ask again and fill the buffer. Returns 0 when it did. */
static int interrupted_once(void)
{
    fflush(stdout);
    fflush(stderr);
    pid_t child = fork();
    if (child < 0)
        return 2;
    if (child == 0) {
        pthread_t supervisor;
        if (pipe(notify_pipe) != 0 || pthread_create(&supervisor, NULL, supervise, NULL) != 0)
            exit(2);
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getrandom, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog program = { (unsigned short)(sizeof filter / sizeof filter[0]), filter };
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
            exit(2);
        int fd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
        if (fd < 0 || write(notify_pipe[1], &fd, sizeof fd) != (ssize_t)sizeof fd)
            exit(2);
        uint8_t buf[256];
        memset(buf, 0xA5, sizeof buf);
        signal(SIGALRM, SIG_DFL);                   /* (the parent's timer handler came along) */
        alarm(10);                                  /* a spin or a lost answer ends here, failing */
        int result = httpasm_random(buf, sizeof buf);
        exit(result == 0 && full(buf, sizeof buf) ? 0 : 1);
    }
    int status;
    if (waitpid(child, &status, 0) != child)
        return 2;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "random: getrandom interrupted once (EINTR): httpasm_random did not fill the buffer (status %#x)\n", status);
        return WIFEXITED(status) && WEXITSTATUS(status) == 2 ? 2 : 1;
    }
    printf("random: getrandom interrupted once (EINTR): httpasm_random asked again and filled 256 octets\n");
    return 0;
}

int main(void)
{
    size_t big = 64u << 20;
    uint8_t *buf = malloc(big);
    if (buf == NULL)
        return 2;
    static const size_t lengths[] = { 0, 1, 15, 16, 17, 255, 256, 257, 4095, 4096 };
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
        memset(buf, 0xA5, 4096 + 64);
        if (httpasm_random(buf, lengths[i]) != 0 || !full(buf, lengths[i]) || buf[lengths[i]] != 0xA5) {
            fprintf(stderr, "random: %zu octets: wrong (or wrote past the end)\n", lengths[i]);
            return 1;
        }
    }
    if (fill(buf, big) != 0)
        return 1;
    printf("random: lengths 0 to 4 KiB and 64 MiB (two short reads) filled\n");
    int failed = histogram(buf);
    if (!failed)
        failed = under_signals(buf, big);
    if (!failed)
        failed = refused(SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA), -EPERM, "refused with EPERM");
    if (!failed)
        failed = refused(SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA), -ENOSYS, "refused with ENOSYS");
    if (!failed)
        failed = refused(SECCOMP_RET_ERRNO | 0, -EIO, "answered with no octets and no error");
    if (!failed)
        failed = interrupted_once();
    free(buf);
    return failed;
}
