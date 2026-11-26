/*
 * client.c - fuzzes the HTTP/1.1 client (client.asm) end to end: a server thread in this process
 * answers the real client's request with the input's octets, then closes; httpasm_client_send
 * must read them exactly as HttpAsm's own parsers read them. A client that frames a response
 * differently from its parser, or hangs or crashes on a hostile server, is a client a server
 * can attack.
 *
 * The input: its first octet's bit 0 chooses the request's method (GET, or HEAD, which changes
 * the framing); the rest is the server's whole answer. The server thread reads the request's
 * head, sends the answer, half-closes, and reads until the client closes (so its close is a FIN,
 * never a reset that could destroy the answer in flight).
 *
 * For every input it requires:
 *   - the client returns within its timeout (2 s), with 0, -HTTPASM_ERROR_* (an invalid response)
 *     or -errno; then the connection is closed or reusable as documented;
 *   - a 0 agrees with the parsers: the first final head of the answer (1xx skipped) read by
 *     httpasm_h1_parse_response has the client's status, fields and flags; the body is what the
 *     framing says - Content-Length octets, the chunked body decoded by httpasm_h1_chunked_decode
 *     with its trailers by httpasm_h1_parse_trailers, the rest to the close, or none;
 *   - a refusal agrees with them too: the answer holds no complete, valid final response.
 */
#include "fuzz.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

enum { MAX_FIELDS = 128 };

static int listener;
static uint16_t port;
/* The handshake between an input and the server thread. answer is the harness's own copy of
 * the input's answer: libFuzzer frees an input when its call returns, and the server may still
 * be sending the answer's end after the client stopped reading (ASan caught exactly that). An
 * input waits for its connection to be served to the end (served) before it returns, so the
 * copy is never overwritten while in use and a connection never takes the next input's answer. */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER, done = PTHREAD_COND_INITIALIZER;
static uint8_t answer[FUZZ_MAX];
static size_t answer_length;
static int answer_pending, served;

/* serve: the server thread: per connection, reads the request head, sends the current answer,
 * half-closes, and drains until the client closes. */
static void *serve(void *unused)
{
    (void)unused;
    for (;;) {
        int fd = accept(listener, NULL, NULL);
        if (fd < 0)
            continue;
        pthread_mutex_lock(&lock);
        while (!answer_pending)
            pthread_cond_wait(&ready, &lock);
        size_t n = answer_length;
        answer_pending = 0;
        pthread_mutex_unlock(&lock);
        const uint8_t *a = answer;
        char head[8192];
        size_t got = 0;
        while (got < sizeof head) {
            ssize_t r = recv(fd, head + got, sizeof head - got, 0);
            if (r <= 0)
                break;
            got += (size_t)r;
            if (got >= 4 && memmem(head, got, "\r\n\r\n", 4) != NULL)
                break;
        }
        for (size_t sent = 0; sent < n;) {
            ssize_t w = send(fd, a + sent, n - sent, MSG_NOSIGNAL);
            if (w <= 0)
                break;
            sent += (size_t)w;
        }
        shutdown(fd, SHUT_WR);
        char drain[4096];
        while (recv(fd, drain, sizeof drain, 0) > 0)
            ;
        close(fd);
        pthread_mutex_lock(&lock);
        served = 1;
        pthread_cond_signal(&done);
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

/* LLVMFuzzerInitialize: the listening socket and the server thread. Aborts if they fail. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in at = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t len = sizeof at;
    FUZZ_CHECK(listener >= 0 && bind(listener, (struct sockaddr *)&at, sizeof at) == 0 && listen(listener, 16) == 0
                   && getsockname(listener, (struct sockaddr *)&at, &len) == 0,
               "the listener: %d", errno);
    port = ntohs(at.sin_port);
    pthread_t t;
    FUZZ_CHECK(pthread_create(&t, NULL, serve, NULL) == 0, "the server thread");
    return 0;
}

/* same_field: two fields with the same name and value octets. */
static int same_field(const httpasm_field *a, const httpasm_field *b)
{
    return a->name_length == b->name_length && a->value_length == b->value_length && memcmp(a->name, b->name, a->name_length) == 0
        && memcmp(a->value, b->value, a->value_length) == 0;
}

/* expected: what the parsers say the answer is, for a request of this method: 1 with the
 * final head, its fields and the body's octets (decoded) and trailers when the answer holds a
 * complete valid final response; 0 when it does not. buf is writable (obs-fold is rewritten). */
static int expected(uint8_t *buf, size_t n, uint32_t method, httpasm_response_head *h, httpasm_field *fields, uint8_t **body,
                    size_t *body_length, httpasm_field *trailers, uint32_t *trailer_count)
{
    size_t at = 0;
    httpasm_h1_limits limits = { .max_fields = MAX_FIELDS };
    for (;;) {
        memset(h, 0, sizeof *h);
        size_t scan = 0;
        int64_t r = httpasm_h1_parse_response(buf + at, n - at, &scan, &limits, method, h, fields);
        if (r <= 0)
            return 0;
        at += (size_t)r;
        /* Interim answers are 1xx only: 000-099 are invalid final ones, framed as a 5xx's
         * (RFC 9110 15; h1/response.asm), which the client returns. */
        if (h->status < 100 || h->status >= 200)
            break;
        /* 101 (Switching Protocols) is no interim answer to skip: after it the connection
         * speaks another protocol (RFC 9110 15.2.2), one this client never asked for (it sends
         * no Upgrade; RFC 9110 7.8: a server must not switch to a protocol the request did not
         * name). The client refuses it (-HTTPASM_ERROR_STATUS), and so does this oracle: CI's
         * fuzzing found the oracle skipping "101 Continue" as an interim answer (2026-11-26). */
        if (h->status == 101)
            return 0;
    }
    *body = buf + at;
    *body_length = 0;
    *trailer_count = 0;
    if (h->flags & HTTPASM_RESPONSE_HEAD_NO_BODY)
        return 1;
    if (h->flags & HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH) {
        if (h->content_length > n - at)
            return 0;
        *body_length = (size_t)h->content_length;
        return 1;
    }
    if (h->flags & HTTPASM_RESPONSE_HEAD_UNTIL_CLOSE) {
        *body_length = n - at;
        return 1;
    }
    httpasm_h1_chunked state;
    memset(&state, 0, sizeof state);
    size_t produced = 0;
    int64_t used = httpasm_h1_chunked_decode(&state, buf + at, n - at, &produced);
    if (used < 0 || state.state != HTTPASM_CHUNKED_TRAILERS)
        return 0;
    *body_length = produced;
    size_t scan = 0;
    int64_t t = httpasm_h1_parse_trailers(buf + at + used, n - at - (size_t)used, &scan, &limits, trailers, trailer_count);
    return t > 0;
}

/* LLVMFuzzerTestOneInput: libFuzzer's entry, once per input. Always returns 0. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t copy[FUZZ_MAX];
    static httpasm_field fields[MAX_FIELDS], trailers[MAX_FIELDS];
    if (size < 1 || size > FUZZ_MAX)
        return 0;
    uint32_t method = data[0] & 1 ? HTTPASM_METHOD_HEAD : HTTPASM_METHOD_GET;

    pthread_mutex_lock(&lock);
    memcpy(answer, data + 1, size - 1);
    answer_length = size - 1;
    answer_pending = 1;
    served = 0;
    pthread_cond_signal(&ready);
    pthread_mutex_unlock(&lock);

    int error = 0;
    httpasm_client *client = httpasm_client_connect(htonl(INADDR_LOOPBACK), port, 2000, &error);
    FUZZ_CHECK(client != NULL, "connect: %d", error);
    httpasm_request q;
    memset(&q, 0, sizeof q);
    q.method = (const uint8_t *)(method == HTTPASM_METHOD_HEAD ? "HEAD" : "GET");
    q.method_length = method == HTTPASM_METHOD_HEAD ? 4 : 3;
    q.target = (const uint8_t *)"/";
    q.target_length = 1;
    q.authority = (const uint8_t *)"fuzz";
    q.authority_length = 4;
    httpasm_client_response resp;
    memset(&resp, 0, sizeof resp);
    int r = httpasm_client_send(client, &q, NULL, 0, &resp);

    memcpy(copy, data + 1, size - 1);
    httpasm_response_head h;
    uint8_t *body = NULL;
    size_t body_length = 0;
    uint32_t trailer_count = 0;
    int valid = expected(copy, size - 1, method, &h, fields, &body, &body_length, trailers, &trailer_count);
    if (r == 0) {
        FUZZ_CHECK(valid, "the client took an answer the parsers find incomplete or invalid");
        FUZZ_CHECK(resp.head.status == h.status && resp.head.field_count == h.field_count && resp.head.flags == h.flags,
                   "status %u/%u, fields %u/%u, flags 0x%x/0x%x (client/parsers)", resp.head.status, h.status, resp.head.field_count,
                   h.field_count, resp.head.flags, h.flags);
        for (uint32_t i = 0; i < h.field_count; i++)
            FUZZ_CHECK(same_field(&resp.head.fields[i], &fields[i]), "field %u differs", i);
        FUZZ_CHECK(resp.body_length == body_length && (body_length == 0 || memcmp(resp.body, body, body_length) == 0),
                   "the body: %zu octets from the client, %zu by the framing", resp.body_length, body_length);
        FUZZ_CHECK(resp.trailer_count == trailer_count, "%u trailers from the client, %u parsed", resp.trailer_count, trailer_count);
        for (uint32_t i = 0; i < trailer_count; i++)
            FUZZ_CHECK(same_field(&resp.trailers[i], &trailers[i]), "trailer %u differs", i);
    } else {
        FUZZ_CHECK(r < 0, "result %d", r);
        FUZZ_CHECK(r != -ETIMEDOUT, "the client timed out on an answer the server had finished");
        /* A refusal of the response itself (-HTTPASM_ERROR_*, 1 to 37): the parsers must find
         * no valid complete one. -errno codes are I/O, the server's doing, not a verdict; the
         * ranges overlap only for ENOMEM (12), which a loopback answer of at most 64 KiB does
         * not cause. */
        if (r >= -37)
            FUZZ_CHECK(!valid, "the client refused (%d) what the parsers read as a valid response", r);
    }
    httpasm_client_close(client);
    /* The connection served to its end (the server saw the client's close) before the next
     * input may touch the answer. */
    pthread_mutex_lock(&lock);
    while (!served)
        pthread_cond_wait(&done, &lock);
    pthread_mutex_unlock(&lock);
    return 0;
}
