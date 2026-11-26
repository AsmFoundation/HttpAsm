/*
 * rivals.c - single-thread measurements of HttpAsm's parsers beside the parsers others run
 * (docs/DESIGN.md phase H step 2, "a single-thread benchmark harness ... against
 * picohttpparser, llhttp and nghttp2"): the same inputs, the same process, the same core.
 *
 *   HTTP/1.1 request heads: httpasm_h1_parse_request; picohttpparser's phr_parse_request (h2o);
 *   llhttp (Node.js), with callbacks that keep every span, which is what a server needs and
 *   what the other two hand back anyway.
 *   HPACK header blocks: httpasm_hpack_decode; nghttp2's nghttp2_hd_inflate_hd3.
 *
 * Method (as benchmarks/micro): every contender measured in turn, round after round, so drift
 * hits all alike; a sample times a batch of about 0.5 ms; the fastest sample is the estimate
 * (interference on this host only adds time; medians swing 2x under WSL2), and HttpAsm runs a
 * second time as the A/A control: a difference counts only past the gap between the two.
 * HttpAsm runs at its best tier and at v1 (the baseline every CPU has). The rivals are
 * compiled with -O3 -march=native by run.sh: their best (picohttpparser and llhttp both have
 * SSE4.2 paths that need it).
 *
 * Usage: rivals [rounds, default 41]. Output: a Markdown table on stdout.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <llhttp.h>
#include <nghttp2/nghttp2.h>
#include <picohttpparser.h>

#include "httpasm.h"

#define MAX_ROUNDS 101
#define MAX_FIELDS 64

static volatile size_t sink;

/* now_ns: CLOCK_MONOTONIC_RAW in nanoseconds. */
static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* compare_doubles: qsort's ascending comparison. */
static int compare_doubles(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* ---- HTTP/1.1 contenders: each parses input[0..length) `calls` times. */

static void httpasm_h1(const uint8_t *input, size_t length, long calls)
{
    static httpasm_field fields[MAX_FIELDS];
    httpasm_h1_limits limits = { .max_fields = MAX_FIELDS };
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        httpasm_request q;
        size_t scan = 0;
        total += (size_t)httpasm_h1_parse_request(input, length, &scan, &limits, &q, fields);
    }
    sink = total;
}

static void pico_h1(const uint8_t *input, size_t length, long calls)
{
    struct phr_header headers[MAX_FIELDS];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        const char *method, *path;
        size_t method_length, path_length, count = MAX_FIELDS;
        int minor;
        total += (size_t)phr_parse_request((const char *)input, length, &method, &method_length, &path, &path_length, &minor, headers,
                                           &count, 0);
    }
    sink = total;
}

/* llhttp's spans, kept as a server would keep them. */
static struct {
    const char *at[2 * MAX_FIELDS + 2];
    size_t length[2 * MAX_FIELDS + 2];
    size_t count;
} spans;

static int keep(llhttp_t *p, const char *at, size_t n)
{
    (void)p;
    if (spans.count < sizeof spans.at / sizeof spans.at[0]) {
        spans.at[spans.count] = at;
        spans.length[spans.count++] = n;
    }
    return 0;
}

static int headers_done(llhttp_t *p)
{
    (void)p;
    return HPE_PAUSED;                       /* the head is what is measured, as for the others */
}

static void llhttp_h1(const uint8_t *input, size_t length, long calls)
{
    static llhttp_settings_t settings;
    static int ready;
    if (!ready) {
        llhttp_settings_init(&settings);
        settings.on_method = keep;
        settings.on_url = keep;
        settings.on_header_field = keep;
        settings.on_header_value = keep;
        settings.on_headers_complete = headers_done;
        ready = 1;
    }
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        llhttp_t parser;
        spans.count = 0;
        llhttp_init(&parser, HTTP_REQUEST, &settings);
        total += (size_t)llhttp_execute(&parser, (const char *)input, length) + spans.count;
    }
    sink = total;
}

/* ---- HPACK contenders: each decodes the block `calls` times; the block indexes nothing, so the
 * tables never change and every call does the same work. */

static httpasm_hpack *ours;
static nghttp2_hd_inflater *theirs;

static void httpasm_hpack_decoder(const uint8_t *input, size_t length, long calls)
{
    static httpasm_field fields[MAX_FIELDS];
    static uint8_t space[16384];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        httpasm_hpack_output o = { .fields = fields, .space = space, .space_size = sizeof space, .max_fields = MAX_FIELDS };
        total += (size_t)httpasm_hpack_decode(ours, input, length, &o) + o.count;
    }
    sink = total;
}

static void nghttp2_hpack_decoder(const uint8_t *input, size_t length, long calls)
{
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        const uint8_t *in = input;
        size_t left = length;
        for (;;) {
            nghttp2_nv nv;
            int flags = 0;
            nghttp2_ssize used = nghttp2_hd_inflate_hd3(theirs, &nv, &flags, in, left, 1);
            if (used < 0)
                abort();
            in += used;
            left -= (size_t)used;
            if (flags & NGHTTP2_HD_INFLATE_EMIT)
                total += nv.namelen + nv.valuelen;
            if (flags & NGHTTP2_HD_INFLATE_FINAL) {
                nghttp2_hd_inflate_end_headers(theirs);
                break;
            }
        }
    }
    sink = total;
}

typedef void (*batch_fn)(const uint8_t *input, size_t length, long calls);

/* One contender: its name, the routine, and the tier it runs at (0: no tier, a rival). */
typedef struct contender {
    const char *name;
    batch_fn run;
    uint64_t cap;
} contender;

/* measure: the contenders on one input, interleaved for `rounds`; prints a row each, with the
 * first contender (HttpAsm at its best tier) as the reference. */
static void measure(const char *input_name, const uint8_t *input, size_t length, const contender *c, size_t n, int rounds)
{
    double samples[8][MAX_ROUNDS];
    long calls = 256;
    httpasm_cpu_limit(HTTPASM_CPU_CAP_V1);
    for (;;) {                               /* the batch: about 0.5 ms for the slowest-known case */
        double t0 = now_ns();
        for (size_t k = 0; k < n; k++)
            c[k].run(input, length, calls);
        if (now_ns() - t0 > 5e5 * (double)n || calls > (1L << 28))
            break;
        calls *= 2;
    }
    for (int r = 0; r < rounds; r++) {
        for (size_t k = 0; k < n; k++) {
            httpasm_cpu_limit(c[k].cap);
            c[k].run(input, length, calls / 16);
            double t0 = now_ns();
            c[k].run(input, length, calls);
            samples[k][r] = (now_ns() - t0) / (double)calls;
        }
    }
    double reference = 0;
    for (size_t k = 0; k < n; k++) {
        qsort(samples[k], (size_t)rounds, sizeof(double), compare_doubles);
        double best = samples[k][0], median = samples[k][rounds / 2];
        if (k == 0)
            reference = best;
        printf("| %s | %zu | %s | %.1f | %.1f | %.2f | %.2fx |\n", input_name, length, c[k].name, best, median,
               best > 0 ? (double)length / best : 0.0, reference > 0 ? best / reference : 0.0);
    }
}

/* The inputs: a minimal request, a browser's navigation request, an API call with a bearer
 * token. Realistic shapes, fixed octets. */
static const char small_request[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
static const char browser_request[] =
    "GET /articles/2026/11/assembly-http-parsers?ref=home&utm_source=feed HTTP/1.1\r\n"
    "Host: www.example.com\r\n"
    "Connection: keep-alive\r\n"
    "sec-ch-ua: \"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\", \"Not_A Brand\";v=\"99\"\r\n"
    "sec-ch-ua-mobile: ?0\r\n"
    "sec-ch-ua-platform: \"Windows\"\r\n"
    "Upgrade-Insecure-Requests: 1\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n"
    "Sec-Fetch-Site: same-origin\r\n"
    "Sec-Fetch-Mode: navigate\r\n"
    "Sec-Fetch-User: ?1\r\n"
    "Sec-Fetch-Dest: document\r\n"
    "Referer: https://www.example.com/\r\n"
    "Accept-Encoding: gzip, deflate, br, zstd\r\n"
    "Accept-Language: en-US,en;q=0.9,he;q=0.8\r\n"
    "Cookie: session=7f3a9c2e8b1d4f6a0e5c9b2d7a4f1e8c; theme=dark; consent=1; _ga=GA1.1.1234567890.1764115200\r\n"
    "\r\n";
static const char api_request[] =
    "POST /api/v2/orders/12345/items HTTP/1.1\r\n"
    "Host: api.example.com\r\n"
    "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzY0MTE1MjAw"
    "LCJleHAiOjE3NjQxMTg4MDAsInNjb3BlIjoib3JkZXJzOndyaXRlIn0.c2lnbmF0dXJlLXBsYWNlaG9sZGVyLWZvci1iZW5jaG1hcmstb25seQ\r\n"
    "Content-Type: application/json; charset=utf-8\r\n"
    "Content-Length: 128\r\n"
    "Accept: application/json\r\n"
    "X-Request-Id: 4b8e2c6a-91f3-4d7e-b5a0-2f6c8d1e9a37\r\n"
    "Idempotency-Key: 0f9c1b2a-3d4e-5f60-7182-93a4b5c6d7e8\r\n"
    "\r\n";

/* main: pins the process, prepares the decoders and the HPACK block, measures. Returns 0, or 2
 * on a usage error. */
int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 41;
    if (rounds < 1 || rounds > MAX_ROUNDS) {
        fprintf(stderr, "usage: rivals [rounds 1-%d]\n", MAX_ROUNDS);
        return 2;
    }
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(sched_getcpu(), &one);
    if (sched_setaffinity(0, sizeof one, &one) != 0)
        perror("rivals: sched_setaffinity (continuing unpinned)");

    /* The HPACK block: the browser request's fields as HTTP/2 sends them, encoded once by
     * HttpAsm's encoder with Huffman, every field flagged NO_INDEX, so decoding it never
     * changes a table. */
    static uint8_t table_ours[16384], table_enc[16384], block[4096];
    size_t need = httpasm_hpack_size(4096);
    if (need > sizeof table_ours || httpasm_hpack_init(table_ours, need, 4096, 0) != 0
        || httpasm_hpack_init(table_enc, need, 4096, HTTPASM_HPACK_HUFFMAN) != 0)
        return 1;
    ours = (httpasm_hpack *)table_ours;
    static const char *pairs[][2] = {
        { ":method", "GET" }, { ":scheme", "https" }, { ":authority", "www.example.com" },
        { ":path", "/articles/2026/11/assembly-http-parsers?ref=home&utm_source=feed" },
        { "sec-ch-ua", "\"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\", \"Not_A Brand\";v=\"99\"" },
        { "sec-ch-ua-mobile", "?0" }, { "sec-ch-ua-platform", "\"Windows\"" }, { "upgrade-insecure-requests", "1" },
        { "user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36" },
        { "accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" },
        { "sec-fetch-site", "same-origin" }, { "sec-fetch-mode", "navigate" }, { "sec-fetch-user", "?1" },
        { "sec-fetch-dest", "document" }, { "referer", "https://www.example.com/" }, { "accept-encoding", "gzip, deflate, br, zstd" },
        { "accept-language", "en-US,en;q=0.9,he;q=0.8" },
        { "cookie", "session=7f3a9c2e8b1d4f6a0e5c9b2d7a4f1e8c; theme=dark; consent=1; _ga=GA1.1.1234567890.1764115200" },
    };
    httpasm_field fields[sizeof pairs / sizeof pairs[0]];
    for (size_t i = 0; i < sizeof pairs / sizeof pairs[0]; i++)
        fields[i] = (httpasm_field){ .name = (const uint8_t *)pairs[i][0], .name_length = (uint32_t)strlen(pairs[i][0]),
                                     .value = (const uint8_t *)pairs[i][1], .value_length = (uint32_t)strlen(pairs[i][1]),
                                     .flags = HTTPASM_FIELD_FLAG_NO_INDEX };
    int64_t block_length = httpasm_hpack_encode((httpasm_hpack *)table_enc, fields, (uint32_t)(sizeof pairs / sizeof pairs[0]), block,
                                                sizeof block);
    if (block_length <= 0 || nghttp2_hd_inflate_new(&theirs) != 0)
        return 1;

    printf("found %#llx; %d rounds; ns per call (fastest, median), octets per ns (fastest), and each\n"
           "contender's fastest over HttpAsm's best tier's (below 1.00x is faster than HttpAsm)\n\n",
           (unsigned long long)httpasm_cpu_found(), rounds);
    printf("| input | octets | contender | fastest ns | median ns | octets/ns | vs HttpAsm |\n");
    printf("|---|---:|---|---:|---:|---:|---:|\n");
    const contender h1[] = {
        { "HttpAsm (best tier)", httpasm_h1, HTTPASM_CPU_ALL },
        { "HttpAsm v1", httpasm_h1, HTTPASM_CPU_CAP_V1 },
        { "picohttpparser dd573d8", pico_h1, HTTPASM_CPU_ALL },
        { "llhttp 9.4.4", llhttp_h1, HTTPASM_CPU_ALL },
        { "HttpAsm (best, A/A)", httpasm_h1, HTTPASM_CPU_ALL },
    };
    measure("small GET", (const uint8_t *)small_request, sizeof small_request - 1, h1, 5, rounds);
    measure("browser GET", (const uint8_t *)browser_request, sizeof browser_request - 1, h1, 5, rounds);
    measure("API POST", (const uint8_t *)api_request, sizeof api_request - 1, h1, 5, rounds);
    const contender hpack[] = {
        { "HttpAsm (best tier)", httpasm_hpack_decoder, HTTPASM_CPU_ALL },
        { "HttpAsm v1", httpasm_hpack_decoder, HTTPASM_CPU_CAP_V1 },
        { "nghttp2 1.71.0", nghttp2_hpack_decoder, HTTPASM_CPU_ALL },
        { "HttpAsm (best, A/A)", httpasm_hpack_decoder, HTTPASM_CPU_ALL },
    };
    measure("HPACK browser block", block, (size_t)block_length, hpack, 4, rounds);
    nghttp2_hd_inflate_del(theirs);
    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    return 0;
}
