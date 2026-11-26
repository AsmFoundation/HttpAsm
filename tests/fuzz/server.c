/*
 * server.c - fuzzes the server end to end: whole connections, HTTP/1.1 or HTTP/2, against a
 * running httpasm_server on loopback, with its drivers (connection.asm, h2.asm, server.asm) in
 * the loop. The parser fuzzers prove each codec alone; this one proves what a peer reaches
 * through a socket: buffering across reads, pipelining, bodies, the HTTP/2 engine, and that no
 * input stops the server.
 *
 * The servers (LLVMFuzzerInitialize): two, one worker each, one on epoll and one asking for
 * io_uring (the input's bit 1 picks), loopback, a 4 KiB body limit (413 is
 * reachable), a handler that answers 200 with "<method> <target> <body octets>". Its code is
 * linked into this program from the Fuzz objects, so its blocks steer the fuzzer like the core's.
 *
 * The input: its first octet's bit 0 chooses HTTP/1.1 (0: the rest is sent as is) or HTTP/2 (1:
 * the client preface goes first, then the rest, as frames). Each input is one connection: sent
 * whole while the answer is read (both at once, so neither side can stall the other), then the
 * write side shut, then read to the server's close, within a time limit.
 *
 * For every input it requires:
 *   - the server closes the connection after the client's FIN, within 5 s;
 *   - HTTP/1.1: the answer to the first request agrees with what httpasm_h1_parse_request says
 *     of that request: a refusal is answered with that status (400, 414, 417, 431, 501, 505),
 *     then the close - except a broken request-line with no "HTTP/" in it, which is no HTTP/1.x
 *     request and gets the close alone (speaks_http); a complete head with a complete body (none, Content-Length, or chunked
 *     decoded by httpasm_h1_chunked_decode) is answered 200 with the handler's text naming the
 *     same method, target and body length (a 413 when the body passes 4 KiB; 1xx interim
 *     answers first are allowed); every answer is a well-formed response head
 *     (httpasm_h1_parse_response);
 *   - HTTP/2: the answer is a sequence of whole frames, SETTINGS first;
 *   - the server still serves: a plain GET on a new connection is answered 200, after every
 *     input, so a finding names the input that broke it.
 */
#include "fuzz.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum { ANSWER_MAX = 4 << 20, MAX_BODY = 4096, TIMEOUT_MS = 5000, MAX_FIELDS = 128 };

/* Two servers: [0] on epoll (the default), [1] asking for io_uring (HTTPASM_SERVER_URING), so
 * uring.asm's paths meet the same inputs; where the kernel refuses a ring, [1] runs on epoll
 * all the same (httpasm.h), which still serves. port is the one the current input talks to. */
static httpasm_server *servers[2];
static uint16_t ports[2];
static uint16_t port;

/* handler: answers every request 200 with "<method> <target> <body octets>", at once. The
 * server refuses to send a 2xx to CONNECT (it would open a tunnel it cannot carry yet:
 * ServerTests.RefusesToStartATunnel), so a refused answer is followed by a 501, as an
 * exchange left unanswered would hold its connection until the idle timeout. */
static void handler(void *context, httpasm_exchange *exchange)
{
    (void)context;
    char text[16384];
    const httpasm_request *q = httpasm_exchange_request(exchange);
    size_t length = 0;
    httpasm_exchange_body(exchange, &length);
    int n = snprintf(text, sizeof text, "%.*s %.*s %zu", (int)q->method_length, (const char *)q->method,
                     (int)(q->target_length < 8192 ? q->target_length : 8192), (const char *)q->target, length);
    if (httpasm_exchange_respond(exchange, 200, NULL, 0, (const uint8_t *)text, (size_t)n) != 0)
        httpasm_exchange_respond(exchange, 501, NULL, 0, NULL, 0);
}

/* LLVMFuzzerInitialize: starts both servers once for the whole run. Aborts if one cannot. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    httpasm_server_options options;
    memset(&options, 0, sizeof options);
    options.handler = handler;
    options.workers = 1;
    options.max_body = MAX_BODY;
    options.idle_timeout_ms = 2000;
    options.bind_address = htonl(INADDR_LOOPBACK);
    for (int i = 0; i < 2; i++) {
        int error = 0;
        options.flags = i == 1 ? HTTPASM_SERVER_URING : 0;
        servers[i] = httpasm_server_create(&options, &error);
        FUZZ_CHECK(servers[i] != NULL && httpasm_server_start(servers[i]) == 0, "server %d did not start (%d)", i, error);
        ports[i] = httpasm_server_port(servers[i]);
    }
    return 0;
}

/* now_ms: a monotonic clock in milliseconds. */
static int64_t now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* talk: one connection: sends a then b (either may be empty) while reading, shuts the write
 * side, reads to the close. Returns the octets read (at most cap kept in answer); *closed is 1
 * when the server closed within TIMEOUT_MS. A server that resets the connection after its
 * answer (as it may after a refusal) counts as closed. */
static size_t talk(const uint8_t *a, size_t an, const uint8_t *b, size_t bn, uint8_t *answer, size_t cap, int *closed)
{
    *closed = 0;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    FUZZ_CHECK(fd >= 0, "socket: %d", errno);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0)
        FUZZ_CHECK(errno == EINPROGRESS, "connect: %d", errno);
    size_t sent = 0, total = an + bn, got = 0;
    int shut = 0;
    int64_t deadline = now_ms() + TIMEOUT_MS;
    for (;;) {
        if (sent == total && !shut) {
            shutdown(fd, SHUT_WR);
            shut = 1;
        }
        struct pollfd p = { .fd = fd, .events = POLLIN | (shut ? 0 : POLLOUT) };
        int64_t left = deadline - now_ms();
        if (left <= 0)
            break;
        if (poll(&p, 1, (int)left) <= 0)
            continue;
        if (p.revents & (POLLIN | POLLHUP | POLLERR)) {
            uint8_t scratch[65536];
            uint8_t *into = got < cap ? answer + got : scratch;
            size_t room = got < cap ? cap - got : sizeof scratch;
            ssize_t r = recv(fd, into, room, 0);
            if (r == 0 || (r < 0 && (errno == ECONNRESET || errno == EPIPE))) {
                *closed = 1;
                break;
            }
            if (r > 0)
                got += (size_t)r;
        }
        if (!shut && (p.revents & POLLOUT)) {
            const uint8_t *from = sent < an ? a + sent : b + (sent - an);
            size_t chunk = sent < an ? an - sent : total - sent;
            ssize_t w = send(fd, from, chunk, MSG_NOSIGNAL);
            if (w > 0)
                sent += (size_t)w;
            else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                sent = total;                /* the server closed its side: stop sending */
            }
        }
    }
    close(fd);
    return got < cap ? got : cap;
}

/* body_complete: whether the body the head at in[0..head) announces is whole in in[head..n),
 * and its length (decoded, for chunked); -1 when the chunked framing is malformed. */
static int body_complete(const httpasm_request *q, uint8_t *in, size_t head, size_t n, uint64_t *length)
{
    *length = 0;
    if (q->flags & HTTPASM_REQUEST_CONTENT_LENGTH) {
        *length = q->content_length;
        return q->content_length <= n - head;
    }
    if (!(q->flags & HTTPASM_REQUEST_CHUNKED))
        return 1;
    static uint8_t copy[FUZZ_MAX];
    memcpy(copy, in + head, n - head);
    httpasm_h1_chunked state;
    memset(&state, 0, sizeof state);
    size_t produced = 0;
    int64_t used = httpasm_h1_chunked_decode(&state, copy, n - head, &produced);
    if (used < 0)
        return -1;
    *length = state.total;
    if (state.state != HTTPASM_CHUNKED_TRAILERS)
        return 0;
    /* The trailer section must be whole too. */
    static httpasm_field fields[MAX_FIELDS];
    uint32_t count = 0;
    size_t scan = 0;
    int64_t t = httpasm_h1_parse_trailers(copy + used, n - head - (size_t)used, &scan, NULL, fields, &count);
    return t > 0 ? 1 : t == 0 ? 0 : -1;
}

/* speaks_http: whether a connection's first octets say HTTP/1.x: "HTTP/" before the first
 * line's end (after the empty lines a server skips), within the first 8 KiB. The server answers
 * a broken first request-line only then: one with no HTTP-version is no HTTP/1.x request at
 * all (an HTTP/2 client's invalid preface, another protocol; RFC9112-2.2-9 keeps its 400 for
 * what "appears from the start-line to be an HTTP request message"), and gets the close
 * (connection.asm, .head_refused). Written here apart from the server's own scan. */
static int speaks_http(const uint8_t *in, size_t n)
{
    size_t window = n < 8192 ? n : 8192, i = 0;
    while (i + 1 < window && in[i] == '\r' && in[i + 1] == '\n')
        i += 2;
    for (; i + 5 <= window && in[i] != '\n'; i++)
        if (memcmp(in + i, "HTTP/", 5) == 0)
            return 1;
    return 0;
}

/* check_h1: the HTTP/1.1 rules of this file's header, for the input in[0..n) and the answer. */
static void check_h1(uint8_t *in, size_t n, uint8_t *answer, size_t got)
{
    static httpasm_field fields[MAX_FIELDS], rfields[MAX_FIELDS];
    httpasm_request q;
    memset(&q, 0, sizeof q);
    size_t scan = 0;
    int64_t r = httpasm_h1_parse_request(in, n, &scan, NULL, &q, fields);

    /* The answers' heads, in order, up to the first final one (1xx are interim). */
    httpasm_response_head h;
    size_t at = 0;
    int64_t hr = 0;
    while (at < got) {
        memset(&h, 0, sizeof h);
        size_t rscan = 0;
        hr = httpasm_h1_parse_response(answer + at, got - at, &rscan, NULL, q.method_id, &h, rfields);
        FUZZ_CHECK(hr > 0, "the answer at %zu is no response head (%lld, error %u)", at, (long long)hr, h.error);
        at += (size_t)hr;
        if (h.status >= 200)
            break;
    }

    if (r < 0) {
        int line = q.error == HTTPASM_ERROR_METHOD || q.error == HTTPASM_ERROR_REQUEST_LINE || q.error == HTTPASM_ERROR_TARGET
                || q.error == HTTPASM_ERROR_TARGET_FORM || q.error == HTTPASM_ERROR_VERSION;
        if (line && !speaks_http(in, n)) {
            FUZZ_CHECK(got == 0, "no HTTP/1.x request (error %u), yet the server answered %zu octets", q.error, got);
            return;
        }
        FUZZ_CHECK(got > 0 && hr > 0 && h.status == (uint16_t)-r, "the parser refuses with %lld (error %u), the server answered %u",
                   (long long)-r, q.error, got > 0 ? h.status : 0);
        return;
    }
    if (r == 0)
        return;                              /* the head never ended: the server may say nothing */
    uint64_t length = 0;
    int complete = body_complete(&q, in, (size_t)r, n, &length);
    if (complete < 0) {
        /* Malformed chunked framing: 400 once the server reaches it, after the head. */
        FUZZ_CHECK(got == 0 || h.status == 400, "a malformed chunked body answered %u", h.status);
        return;
    }
    if (length > MAX_BODY) {
        FUZZ_CHECK(got > 0 && h.status == 413, "a %llu-octet body answered %u", (unsigned long long)length, got > 0 ? h.status : 0);
        return;
    }
    if (!complete)
        return;                              /* the body never ended: no answer is owed */
    if (q.method_id == HTTPASM_METHOD_CONNECT) {
        FUZZ_CHECK(got > 0 && h.status == 501, "CONNECT answered %u, not the handler's 501", got > 0 ? h.status : 0);
        return;
    }
    FUZZ_CHECK(got > 0 && h.status == 200, "a complete request answered %u (got %zu octets)", got > 0 ? h.status : 0, got);
    if (q.method_id == HTTPASM_METHOD_HEAD)
        return;                              /* no body to compare */
    char expected[16384];
    int en = snprintf(expected, sizeof expected, "%.*s %.*s %llu", (int)q.method_length, (const char *)q.method,
                      (int)(q.target_length < 8192 ? q.target_length : 8192), (const char *)q.target, (unsigned long long)length);
    FUZZ_CHECK((h.flags & HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH) && h.content_length == (uint64_t)en && at + (size_t)en <= got
                   && memcmp(answer + at, expected, (size_t)en) == 0,
               "the handler saw another request than the parser: expected \"%s\"", expected);
}

/* check_h2: the answer is whole frames, SETTINGS first. */
static void check_h2(const uint8_t *answer, size_t got)
{
    size_t at = 0;
    int first = 1;
    while (at < got) {
        FUZZ_CHECK(got - at >= 9, "a frame header cut at %zu of %zu", at, got);
        size_t length = (size_t)answer[at] << 16 | (size_t)answer[at + 1] << 8 | answer[at + 2];
        FUZZ_CHECK(length <= 16384, "a frame of %zu octets, past the default SETTINGS_MAX_FRAME_SIZE", length);
        FUZZ_CHECK(got - at - 9 >= length, "a frame cut at %zu of %zu", at, got);
        if (first)
            FUZZ_CHECK(answer[at + 3] == 0x4, "the server's first frame is type %u, not SETTINGS", answer[at + 3]);
        first = 0;
        at += 9 + length;
    }
}

/* LLVMFuzzerTestOneInput: libFuzzer's entry, once per input. Always returns 0. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t answer[ANSWER_MAX], input[FUZZ_MAX];
    static const uint8_t preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (size < 1 || size > FUZZ_MAX)
        return 0;
    int h2 = data[0] & 1;
    port = ports[(data[0] >> 1) & 1];        /* bit 1: the io_uring server */
    size_t n = size - 1;
    memcpy(input, data + 1, n);
    int closed = 0;
    size_t got = talk(h2 ? preface : NULL, h2 ? sizeof preface - 1 : 0, input, n, answer, sizeof answer, &closed);
    FUZZ_CHECK(closed, "the server did not close the connection within %d ms of the client's FIN (%zu octets read)", TIMEOUT_MS, got);
    if (h2)
        check_h2(answer, got);
    else
        check_h1(input, n, answer, got);

    /* Still serving. */
    static const uint8_t ping[] = "GET /alive HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    got = talk(ping, sizeof ping - 1, NULL, 0, answer, sizeof answer, &closed);
    FUZZ_CHECK(closed && got >= 12 && memcmp(answer, "HTTP/1.1 200", 12) == 0, "the server stopped serving after this input (%zu octets)", got);
    return 0;
}
