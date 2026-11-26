/*
 * fallback.c - proves that a server asking for io_uring (HTTPASM_SERVER_URING) runs every worker
 * on epoll, and serves, when the kernel refuses io_uring_setup: what Docker's default seccomp
 * profile does, and what an old kernel, io_uring_disabled, or a memlock limit on a kernel that
 * charges rings to it can do.
 *
 * Deterministic on every kernel: before starting the server, this program refuses the call
 * itself with a seccomp filter (EPERM for io_uring_setup, for every thread), checks that the
 * filter holds, then requires httpasm_server_io to say EPOLL and a request over TCP to be
 * answered. The .NET suite cannot do this in its own process (a seccomp filter can never be
 * removed, and the suite's io_uring run needs rings afterwards), hence a program of its own.
 *
 * Usage: fallback
 * Exit status: 0 when the server came up on epoll and answered 200 with its body; 1 when not
 * (printed); 2 when the filter could not be installed or did not hold.
 * Build: tests/native/build.sh.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "httpasm.h"

static const char body[] = "served on epoll";

/* handler: answers every request 200 with `body`, at once.
 *   context  unused; exchange  the request. */
static void handler(void *context, httpasm_exchange *exchange)
{
    (void)context;
    httpasm_exchange_respond(exchange, 200, NULL, 0, (const uint8_t *)body, sizeof body - 1);
}

/* refuse_io_uring: installs a seccomp filter, on every thread of the process (TSYNC), that
 * makes io_uring_setup fail with EPERM and allows everything else. Returns 0, or -1 (errno set)
 * when the kernel refused the filter. Needs no privilege: PR_SET_NO_NEW_PRIVS comes first. */
static int refuse_io_uring(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),                  /* another ABI: untouched */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = sizeof filter / sizeof filter[0], .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &program);
}

/* ask: sends one request to 127.0.0.1:port and reads the answer until the server closes.
 *   port  the server's; answer, size  where the answer goes (NUL-terminated).
 * Returns the answer's length, or -1 on a socket error (printed). */
static ssize_t ask(uint16_t port, char *answer, size_t size)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (fd < 0 || connect(fd, (struct sockaddr *)&to, sizeof to) != 0) {
        perror("fallback: connect");
        return -1;
    }
    static const char request[] = "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
    if (write(fd, request, sizeof request - 1) != (ssize_t)(sizeof request - 1)) {
        perror("fallback: write");
        close(fd);
        return -1;
    }
    size_t used = 0;
    for (;;) {
        ssize_t n = read(fd, answer + used, size - 1 - used);
        if (n < 0) {
            perror("fallback: read");
            close(fd);
            return -1;
        }
        if (n == 0 || (used += (size_t)n) == size - 1)
            break;
    }
    answer[used] = 0;
    close(fd);
    return (ssize_t)used;
}

/* main: refuses io_uring, starts a server that asks for it, and checks it fell back and serves.
 * Returns 0, 1 on a failed check, 2 when the filter could not be installed or did not hold. */
int main(void)
{
    if (refuse_io_uring() != 0) {
        perror("fallback: seccomp");
        return 2;
    }
    uint8_t params[120] = { 0 };
    long probe = syscall(__NR_io_uring_setup, 1, params);
    if (probe >= 0 || errno != EPERM) {
        fprintf(stderr, "fallback: the filter did not hold (io_uring_setup returned %ld, errno %d)\n", probe, errno);
        return 2;
    }

    httpasm_server_options options;
    memset(&options, 0, sizeof options);
    options.handler = handler;
    options.workers = 2;
    options.bind_address = htonl(INADDR_LOOPBACK);
    options.flags = HTTPASM_SERVER_URING;
    int error = 0;
    httpasm_server *server = httpasm_server_create(&options, &error);
    if (server == NULL || httpasm_server_start(server) != 0) {
        fprintf(stderr, "fallback: the server did not start (create error %d)\n", error);
        return 1;
    }
    int failed = 0;
    uint32_t io = httpasm_server_io(server);
    if (io != HTTPASM_SERVER_IO_EPOLL) {
        fprintf(stderr, "fallback: httpasm_server_io says %u, not HTTPASM_SERVER_IO_EPOLL (%d)\n", io, HTTPASM_SERVER_IO_EPOLL);
        failed = 1;
    }
    char answer[4096];
    ssize_t length = ask(httpasm_server_port(server), answer, sizeof answer);
    if (length < 0 || strncmp(answer, "HTTP/1.1 200 ", 13) != 0 || strstr(answer, body) == NULL) {
        fprintf(stderr, "fallback: no 200 with the body; the answer was: %s\n", length < 0 ? "(none)" : answer);
        failed = 1;
    }
    httpasm_server_destroy(server);
    if (!failed)
        printf("fallback: io_uring refused by seccomp; the server ran on epoll and answered 200\n");
    return failed;
}
