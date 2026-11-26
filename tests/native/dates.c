/*
 * dates.c - the Date field's value (src/HttpAsm/date.asm) on every day the realtime clock can
 * hold, against glibc's gmtime_r: an IMF-fixdate (RFC 9110 5.6.7), "Sun, 06 Nov 1994 08:49:37
 * GMT", English names whatever the locale.
 *
 * The server reads the clock through the PLT (clock_gettime), so this program defines
 * clock_gettime itself: an executable's definition comes first in the lookup of every shared
 * library's references, as faults.c's malloc does. CLOCK_REALTIME and CLOCK_REALTIME_COARSE
 * return the second this program sets; every other clock (the server's monotonic ones) goes
 * to the kernel. A worker reformats its Date when the realtime second changes (server.asm's
 * refresh_clock, after each wait), so setting the second before each request sets the Date of
 * its response.
 *
 * Checked, over one keep-alive connection:
 *   1. a clock at 1970-01-01T00:00:00Z from the server's start: the worker's first Date is the
 *      epoch's, not the zeroed buffer it starts with (found here: its cached second started at
 *      0, the same second, so the Date was never formatted);
 *   2. every day from 1970-01-01 to 2262-04-11, the last day the kernel's CLOCK_REALTIME can
 *      hold (it refuses times past KTIME_SEC_MAX, 2^63 ns), each at another second of its day:
 *      day d at second (d * 7919) mod 86400, which visits all 86,400 seconds of a day (7919 is
 *      prime to 86,400) - every year, leap rule, month length, weekday and HH:MM:SS;
 *   3. the last second the kernel can hold.
 *
 * Usage: dates            (HTTPASM_TEST_IO=uring: the server on io_uring)
 * Exit status: 0 when every Date matched; 1 on a mismatch or an I/O failure (printed).
 * Build: tests/native/build.sh.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "httpasm.h"

/* The last second the kernel's CLOCK_REALTIME may be set to: KTIME_SEC_MAX = (2^63 - 1) ns
 * in seconds, 2262-04-11T23:47:16Z (timespec64_valid_settod refuses it and later ones). */
#define KTIME_SEC_MAX 9223372036LL

/* The second the realtime clocks report, or -1 for the kernel's own. */
static _Atomic long long fake_second = -1;

/* clock_gettime: the program's own, found before libc's by libhttpasm.so's PLT. The realtime
 * clocks report fake_second when one is set; every clock else is the kernel's, through the
 * system call (libc's vDSO path would be this function again). Returns 0, or -1 with errno. */
int clock_gettime(clockid_t clock, struct timespec *ts)
{
    long long fake = atomic_load(&fake_second);
    if (fake >= 0 && (clock == CLOCK_REALTIME || clock == CLOCK_REALTIME_COARSE)) {
        ts->tv_sec = (time_t)fake;
        ts->tv_nsec = 0;
        return 0;
    }
    return (int)syscall(SYS_clock_gettime, clock, ts);
}

/* handler: answers every request 200 with no content, at once.
 *   context  unused; exchange  the request. */
static void handler(void *context, httpasm_exchange *exchange)
{
    (void)context;
    httpasm_exchange_respond(exchange, 200, NULL, 0, NULL, 0);
}

/* expected: the IMF-fixdate of second t, from glibc's calendar (gmtime_r) and the English names
 * RFC 9110 5.6.7 fixes. out holds 64 octets (the compiler cannot bound gmtime_r's fields to two
 * digits, so the room is its worst case); the date is 29 octets and a NUL for every second the
 * kernel's clock can hold, which check() verifies. */
static void expected(long long t, char out[64])
{
    static const char days[7][4] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    static const char months[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    time_t when = (time_t)t;
    struct tm tm;
    gmtime_r(&when, &tm);
    snprintf(out, 64, "%s, %02d %s %04d %02d:%02d:%02d GMT", days[tm.tm_wday], tm.tm_mday, months[tm.tm_mon],
             tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* date_of: sends one request on fd and reads its response's head, then copies its Date value.
 *   fd  a connected keep-alive socket; date  receives the 29 octets and a NUL.
 * Returns 0, or -1 when the response did not come or had no Date (printed). The responses have
 * no content (Content-Length: 0), so the head is the whole response. */
static int date_of(int fd, char date[30])
{
    static const char request[] = "GET / HTTP/1.1\r\nHost: t\r\n\r\n";
    if (write(fd, request, sizeof request - 1) != (ssize_t)(sizeof request - 1)) {
        perror("dates: write");
        return -1;
    }
    char head[512];
    size_t used = 0;
    for (;;) {
        ssize_t n = read(fd, head + used, sizeof head - 1 - used);
        if (n <= 0) {
            fprintf(stderr, "dates: the response did not come (read returned %zd)\n", n);
            return -1;
        }
        used += (size_t)n;
        head[used] = 0;
        if (strstr(head, "\r\n\r\n") != NULL)
            break;
        if (used == sizeof head - 1) {
            fprintf(stderr, "dates: a head longer than %zu octets\n", sizeof head - 1);
            return -1;
        }
    }
    const char *field = strstr(head, "\r\nDate: ");
    if (field == NULL || strlen(field + 8) < 29) {
        fprintf(stderr, "dates: no Date in: %s\n", head);
        return -1;
    }
    memcpy(date, field + 8, 29);
    date[29] = 0;
    return 0;
}

/* check: sets the clock to t, asks, and compares the Date with expected(t).
 *   fd  the connection; t  the second. Returns 0, or 1 on a mismatch or failure (printed). */
static int check(int fd, long long t)
{
    atomic_store(&fake_second, t);
    char want[64], got[30];
    expected(t, want);
    if (strlen(want) != 29) {
        fprintf(stderr, "dates: the oracle's date for %lld is not 29 octets: \"%s\"\n", t, want);
        return 1;
    }
    if (date_of(fd, got) != 0)
        return 1;
    if (memcmp(want, got, 29) != 0) {
        /* A NUL inside got would end %s early: print the octets in hex as well. */
        fprintf(stderr, "dates: at %lld the Date was \"%.29s\", not \"%s\"; octets:", t, got, want);
        for (int i = 0; i < 29; i++)
            fprintf(stderr, " %02x", (unsigned char)got[i]);
        fputc('\n', stderr);
        return 1;
    }
    return 0;
}

/* main: starts a server with the clock at the epoch, then checks the Date on every day the
 * clock can hold. Returns 0, or 1 at the first mismatch or failure. */
int main(void)
{
    const char *io = getenv("HTTPASM_TEST_IO");
    int uring = io != NULL && strcmp(io, "uring") == 0;
    atomic_store(&fake_second, 0);                  /* the server starts at the epoch's first second */

    httpasm_server_options options;
    memset(&options, 0, sizeof options);
    options.handler = handler;
    options.workers = 1;
    options.bind_address = htonl(INADDR_LOOPBACK);
    options.flags = uring ? HTTPASM_SERVER_URING : 0;
    int error = 0;
    httpasm_server *server = httpasm_server_create(&options, &error);
    if (server == NULL || httpasm_server_start(server) != 0) {
        fprintf(stderr, "dates: the server did not start (error %d)\n", error);
        return 1;
    }
    if (uring && httpasm_server_io(server) != HTTPASM_SERVER_IO_URING) {
        fprintf(stderr, "dates: io_uring was asked for and the server runs on epoll\n");
        return 1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(httpasm_server_port(server)),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    int one = 1;
    if (fd < 0 || setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) != 0
        || connect(fd, (struct sockaddr *)&to, sizeof to) != 0) {
        perror("dates: connect");
        return 1;
    }

    /* 1. The epoch's first second, read by the worker's first refresh at its start. */
    int failed = check(fd, 0);
    /* 2. Every day the kernel's clock can hold, each at another second of its day. */
    long long days = 0;
    for (long long day = 0; failed == 0; day++) {
        long long t = day * 86400 + (day * 7919) % 86400;
        if (t >= KTIME_SEC_MAX)
            break;
        failed = check(fd, t);
        days++;
    }
    /* 3. The last second the kernel can hold. */
    if (failed == 0)
        failed = check(fd, KTIME_SEC_MAX - 1);

    close(fd);
    httpasm_server_stop(server);
    httpasm_server_destroy(server);
    if (failed != 0)
        return 1;
    printf("dates (%s): the Date matched gmtime_r on %lld days, 1970-01-01 to 2262-04-11, at every second of a day\n",
           uring ? "io_uring" : "epoll", days);
    return 0;
}
