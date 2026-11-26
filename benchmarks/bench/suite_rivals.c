/*
 * suite_rivals.c - the rivals suite: HttpAsm's parsers beside the ones others run, on the same
 * inputs, in the same process, on the same core (docs/DESIGN.md phase H step 2: "a
 * single-thread benchmark harness ... against picohttpparser, llhttp and nghttp2").
 *
 *   HTTP/1.1 request heads: httpasm_h1_parse_request; picohttpparser's phr_parse_request (h2o);
 *   llhttp (Node.js), with callbacks that keep every span, which is what a server needs and
 *   what the other two hand back anyway.
 *   HPACK header blocks: httpasm_hpack_decode; nghttp2's nghttp2_hd_inflate_hd3.
 *
 * HttpAsm runs at its best tier and at v1; the rivals are the sources tests/tools.sh pins (the
 * differential fuzzers' references), compiled by benchmarks/bench.sh with -O3 -march=native,
 * their best: picohttpparser's and llhttp's SSE4.2 paths need it. Mind what each one does:
 * picohttpparser splits a head into lines and checks almost nothing else; llhttp checks the
 * grammar; HttpAsm also applies RFC 9112's semantics (target and Host grammar, field names and
 * values, every framing rule, known-field ids).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <llhttp.h>
#include <nghttp2/nghttp2.h>
#include <picohttpparser.h>

#include "bench.h"

#define MAX_FIELDS 64

/* ---- HTTP/1.1 request heads. */

/* bench_h1_request: httpasm_h1_parse_request on the case's head, `calls` times (bench.h: the
 * tiers suite runs it too). */
void bench_h1_request(const bench_build *b, const bench_case *c, long calls)
{
    static httpasm_field fields[MAX_FIELDS];
    httpasm_h1_limits limits = { .max_fields = MAX_FIELDS };
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        httpasm_request q;
        size_t scan = 0;
        total += (size_t)b->api.httpasm_h1_parse_request(c->data, c->length, &scan, &limits, &q, fields);
    }
    bench_sink = total;
}

/* pico_h1: picohttpparser's phr_parse_request on the case's head, `calls` times. */
static void pico_h1(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    struct phr_header headers[MAX_FIELDS];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        const char *method, *path;
        size_t method_length, path_length, count = MAX_FIELDS;
        int minor;
        total += (size_t)phr_parse_request((const char *)c->data, c->length, &method, &method_length, &path, &path_length, &minor, headers,
                                           &count, 0);
    }
    bench_sink = total;
}

/* llhttp's spans, kept as a server would keep them. */
static struct {
    const char *at[2 * MAX_FIELDS + 2];
    size_t length[2 * MAX_FIELDS + 2];
    size_t count;
} spans;

/* keep: llhttp's span callback: records the span. Returns 0 (go on). */
static int keep(llhttp_t *p, const char *at, size_t n)
{
    (void)p;
    if (spans.count < sizeof spans.at / sizeof spans.at[0]) {
        spans.at[spans.count] = at;
        spans.length[spans.count++] = n;
    }
    return 0;
}

/* headers_done: llhttp's end-of-head callback: pauses, so the head is what is measured, as for
 * the others. Returns HPE_PAUSED. */
static int headers_done(llhttp_t *p)
{
    (void)p;
    return HPE_PAUSED;
}

/* llhttp_h1: llhttp on the case's head, `calls` times, every span kept. */
static void llhttp_h1(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
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
        total += (size_t)llhttp_execute(&parser, (const char *)c->data, c->length) + spans.count;
    }
    bench_sink = total;
}

static const bench_rival h1_rivals[] = {
    { "picohttpparser dd573d8", pico_h1 },
    { "llhttp 9.4.4", llhttp_h1 },
};

/* The inputs: a minimal request, a browser's navigation request, an API call with a bearer
 * token. Realistic shapes, fixed octets. */
const char bench_small_request[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
const char bench_browser_request[] =
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
const char bench_api_request[] =
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

/* ---- HPACK header blocks: each contender decodes the block `calls` times; the block indexes
 * nothing, so no table ever changes and every call does the same work. */

static uint8_t block[4096];
static size_t block_length;
static nghttp2_hd_inflater *theirs;

/* decoder_key: the per-build decoder table's key for bench_state (its address, nothing more). */
static const char decoder_key;

/* decoder_init: an HPACK decoder table through build b's own functions. Returns 0, or nonzero
 * when the build refuses it. */
static int decoder_init(const bench_build *b, void *memory, size_t size)
{
    return b->api.httpasm_hpack_init(memory, size, 4096, 0);
}

/* httpasm_hpack_decoder: httpasm_hpack_decode of the block, `calls` times, with the build's own
 * decoder table. */
static void httpasm_hpack_decoder(const bench_build *b, const bench_case *c, long calls)
{
    static httpasm_field fields[MAX_FIELDS];
    static uint8_t space[16384];
    httpasm_hpack *table = bench_state(b, &decoder_key, b->api.httpasm_hpack_size(4096), decoder_init);
    if (table == NULL)
        return;
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        httpasm_hpack_output o = { .fields = fields, .space = space, .space_size = sizeof space, .max_fields = MAX_FIELDS };
        total += (size_t)b->api.httpasm_hpack_decode(table, c->data, c->length, &o) + o.count;
    }
    bench_sink = total;
}

/* nghttp2_hpack_decoder: nghttp2_hd_inflate_hd3 over the block, `calls` times, every field
 * emitted counted. Aborts on a decoding error (the block is HttpAsm's encoding of valid fields:
 * an error would mean the comparison is void). */
static void nghttp2_hpack_decoder(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        const uint8_t *in = c->data;
        size_t left = c->length;
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
    bench_sink = total;
}

static const bench_rival hpack_rivals[] = {
    { "nghttp2 1.71.0", nghttp2_hpack_decoder },
};

/* make_block: the HPACK block: the browser request's fields as HTTP/2 sends them, encoded once by
 * the first build's encoder with Huffman, every field flagged NO_INDEX (so decoding it never
 * changes a table). Returns 0, or -1 when there is no build or encoding fails. */
static int make_block(void)
{
    const bench_build *b = bench_first_build();
    if (b == NULL)
        return -1;
    static const char *const pairs[][2] = {
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
    for (size_t i = 0; i < sizeof pairs / sizeof pairs[0]; i++) {
        memset(&fields[i], 0, sizeof fields[i]);
        fields[i].name = (const uint8_t *)pairs[i][0];
        fields[i].name_length = (uint32_t)strlen(pairs[i][0]);
        fields[i].value = (const uint8_t *)pairs[i][1];
        fields[i].value_length = (uint32_t)strlen(pairs[i][1]);
        fields[i].flags = HTTPASM_FIELD_FLAG_NO_INDEX;
    }
    size_t need = b->api.httpasm_hpack_size(4096);
    void *encoder = calloc(1, need);
    if (encoder == NULL || b->api.httpasm_hpack_init(encoder, need, 4096, HTTPASM_HPACK_HUFFMAN) != 0) {
        free(encoder);
        return -1;
    }
    int64_t n = b->api.httpasm_hpack_encode(encoder, fields, (uint32_t)(sizeof pairs / sizeof pairs[0]), block, sizeof block);
    free(encoder);
    if (n <= 0)
        return -1;
    block_length = (size_t)n;
    return 0;
}

/* add: registers one rivals case. name, input, data, length: as bench_case's (the octets are the
 * length); run: HttpAsm's batch; rivals, count: the rivals beside it. */
static void add(const char *name, const char *input, const void *data, size_t length, bench_batch run, const bench_rival *rivals,
                size_t count)
{
    bench_case c;
    memset(&c, 0, sizeof c);
    c.suite = "rivals";
    c.name = name;
    c.input = input;
    c.data = data;
    c.length = length;
    c.octets = length;
    c.ours = run;
    c.tiers = BENCH_TIERS_BEST_V1;
    c.rivals = rivals;
    c.rival_count = count;
    bench_add(&c);
}

/* bench_suite_rivals: registers the suite's cases (bench.h); the HPACK case only when the block
 * and nghttp2's decoder could be made (it says why on stderr when not). */
void bench_suite_rivals(void)
{
    size_t n = sizeof h1_rivals / sizeof h1_rivals[0];
    add("h1_request", "small GET", bench_small_request, sizeof bench_small_request - 1, bench_h1_request, h1_rivals, n);
    add("h1_request", "browser GET", bench_browser_request, sizeof bench_browser_request - 1, bench_h1_request, h1_rivals, n);
    add("h1_request", "API POST", bench_api_request, sizeof bench_api_request - 1, bench_h1_request, h1_rivals, n);
    if (make_block() != 0 || nghttp2_hd_inflate_new(&theirs) != 0) {
        fprintf(stderr, "bench: rivals: no HPACK block or nghttp2 decoder: the HPACK case is left out\n");
        return;
    }
    add("hpack_decode", "browser request's block", block, block_length, httpasm_hpack_decoder, hpack_rivals,
        sizeof hpack_rivals / sizeof hpack_rivals[0]);
}
