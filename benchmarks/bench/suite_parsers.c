/*
 * suite_parsers.c - the parsers suite: libhttpasm.so's whole routines on realistic inputs, each
 * at the best tier the CPU has and at v1 (BENCH_TIERS_BEST_V1): what one request, response,
 * chunked body or header block costs, and what the vector versions add to it. These are the
 * hot paths docs/DESIGN.md phase H step 4 accelerates (line scanning, token and value
 * validation, field-name lookup, chunk-size parsing, HPACK, response writing); a routine that
 * gains a version above v1 also joins the tiers suite.
 *
 * The HTTP/1.1 request heads are the rivals suite's (suite_rivals.c measures them beside
 * picohttpparser and llhttp), so they are not repeated here. Every input is fixed text, so two
 * runs, two builds or two machines measure the same octets.
 */
#include <stdio.h>
#include <string.h>

#include "bench.h"

#define MAX_FIELDS 64

/* ---- HTTP/1.1 response heads (the client's side). */

static const char response_head[] =
    "HTTP/1.1 200 OK\r\n"
    "Date: Thu, 26 Nov 2026 16:30:00 GMT\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Content-Length: 48213\r\n"
    "Cache-Control: private, max-age=0, must-revalidate\r\n"
    "ETag: \"5f3a9c2e8b1d4f6a0e5c9b2d7a4f1e8c\"\r\n"
    "Last-Modified: Wed, 25 Nov 2026 09:12:44 GMT\r\n"
    "Vary: Accept-Encoding, Cookie\r\n"
    "Set-Cookie: session=7f3a9c2e8b1d4f6a0e5c9b2d7a4f1e8c; Path=/; Secure; HttpOnly; SameSite=Lax\r\n"
    "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "Server: example\r\n"
    "\r\n";
static uint8_t response_buffer[sizeof response_head];

/* parse_response: httpasm_h1_parse_response on the response head, `calls` times. The buffer is
 * writable (an obs-fold would be blanked in place); this head has none, so every call parses
 * the same octets. */
static void parse_response(const bench_build *b, const bench_case *c, long calls)
{
    static httpasm_field fields[MAX_FIELDS];
    httpasm_h1_limits limits = { .max_fields = MAX_FIELDS };
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        httpasm_response_head head;
        size_t scan = 0;
        total += (size_t)b->api.httpasm_h1_parse_response((uint8_t *)c->data, c->length, &scan, &limits, HTTPASM_METHOD_GET, &head,
                                                          fields);
    }
    bench_sink = total;
}

/* ---- Chunked bodies: decoded in place, so each call first restores the pristine encoding (the
 * copy is part of every contender's sample alike: it dilutes a ratio, never biases one). */

static uint8_t chunked_pristine[20000], chunked_work[20000];
static char chunked_labels[2][40];

/* encode_chunked: writes `count` chunks of `size` octets of 'a'-'z' (hex size lines, CRLFs, then
 * "0" CRLF CRLF) into chunked_pristine. Returns the encoding's length. The callers size it to
 * fit the buffer. */
static size_t encode_chunked(size_t count, size_t size)
{
    size_t n = 0;
    for (size_t k = 0; k < count; k++) {
        n += (size_t)snprintf((char *)chunked_pristine + n, sizeof chunked_pristine - n, "%zx\r\n", size);
        for (size_t i = 0; i < size; i++)
            chunked_pristine[n++] = (uint8_t)('a' + (k + i) % 26);
        chunked_pristine[n++] = '\r';
        chunked_pristine[n++] = '\n';
    }
    memcpy(chunked_pristine + n, "0\r\n\r\n", 5);
    return n + 5;
}

/* chunked_decode: restores the body, then httpasm_h1_chunked_decode on it, `calls` times. The
 * case's data points into chunked_pristine (its length is the encoding's). */
static void chunked_decode(const bench_build *b, const bench_case *c, long calls)
{
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        memcpy(chunked_work, c->data, c->length);
        httpasm_h1_chunked state;
        memset(&state, 0, sizeof state);
        size_t produced = 0;
        total += (size_t)b->api.httpasm_h1_chunked_decode(&state, chunked_work, c->length, &produced) + produced;
    }
    bench_sink = total;
}

/* ---- Field-name lookup and token validation. */

/* The names a server meets: the common known ones, a long known one, and two it does not know
 * (a custom header, a CDN's), so the lookup's miss is measured too. */
static const char *const lookup_names[] = {
    "host", "user-agent", "accept", "accept-encoding", "accept-language", "cookie", "content-type",
    "content-length", "sec-fetch-mode", "upgrade-insecure-requests", "x-request-id", "cf-connecting-ip",
};

/* field_id: httpasm_field_id on each of the twelve names in turn, `calls` passes (a call here is
 * the twelve lookups, so ns per call is per twelve names). */
static void field_id(const bench_build *b, const bench_case *c, long calls)
{
    (void)c;
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        for (size_t k = 0; k < sizeof lookup_names / sizeof lookup_names[0]; k++)
            total += b->api.httpasm_field_id((const uint8_t *)lookup_names[k], strlen(lookup_names[k]));
    }
    bench_sink = total;
}

/* token_length: httpasm_token_length on the case's octets (a field name's or a method's
 * characters), `calls` times. */
static void token_length(const bench_build *b, const bench_case *c, long calls)
{
    size_t total = 0;
    for (long i = 0; i < calls; i++)
        total += b->api.httpasm_token_length(c->data, c->length);
    bench_sink = total;
}

static const char token_long[] = "x-amz-server-side-encryption-customer-key-MD5";

/* ---- HTTP/1.1 response heads written by the server. */

/* write_response: httpasm_h1_write_response of a 200 with a length, a date and six fields into a
 * 4 KiB buffer, `calls` times. */
static void write_response(const bench_build *b, const bench_case *c, long calls)
{
    (void)c;
    static const httpasm_field fields[] = {
        { (const uint8_t *)"content-type", (const uint8_t *)"text/html; charset=utf-8", 12, 24, 0, 0, 0 },
        { (const uint8_t *)"cache-control", (const uint8_t *)"private, max-age=0, must-revalidate", 13, 35, 0, 0, 0 },
        { (const uint8_t *)"etag", (const uint8_t *)"\"5f3a9c2e8b1d4f6a0e5c9b2d7a4f1e8c\"", 4, 34, 0, 0, 0 },
        { (const uint8_t *)"vary", (const uint8_t *)"Accept-Encoding, Cookie", 4, 23, 0, 0, 0 },
        { (const uint8_t *)"strict-transport-security", (const uint8_t *)"max-age=63072000; includeSubDomains; preload", 25, 44, 0, 0, 0 },
        { (const uint8_t *)"x-content-type-options", (const uint8_t *)"nosniff", 22, 7, 0, 0, 0 },
    };
    static uint8_t out[4096];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        httpasm_response r;
        memset(&r, 0, sizeof r);
        r.fields = fields;
        r.field_count = sizeof fields / sizeof fields[0];
        r.date = (const uint8_t *)"Thu, 26 Nov 2026 16:30:00 GMT";
        r.content_length = 48213;
        r.flags = HTTPASM_RESPONSE_LENGTH;
        r.status = 200;
        r.request_version = 11;
        r.request_method = HTTPASM_METHOD_GET;
        total += (size_t)b->api.httpasm_h1_write_response(out, sizeof out, &r);
    }
    bench_sink = total;
}

/* ---- HPACK encoding and HTTP/2's request rules, over the browser request's fields. */

/* The browser request's fields as HTTP/2 carries them (suite_rivals.c decodes the same list),
 * every one flagged NO_INDEX so an encoder's table never changes between calls. */
static const char *const browser_pairs[][2] = {
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
#define BROWSER_FIELDS (sizeof browser_pairs / sizeof browser_pairs[0])
static httpasm_field browser_fields[BROWSER_FIELDS];

/* encoder_key: the per-build encoder table's key for bench_state (its address, nothing more). */
static const char encoder_key;

/* encoder_init: an HPACK encoder table through build b's own functions, Huffman on.
 * Returns 0, or nonzero when the build refuses it. */
static int encoder_init(const bench_build *b, void *memory, size_t size)
{
    return b->api.httpasm_hpack_init(memory, size, 4096, HTTPASM_HPACK_HUFFMAN);
}

/* hpack_encode: httpasm_hpack_encode of the eighteen browser fields into a 4 KiB block, `calls`
 * times, with the build's own encoder table (NO_INDEX: the table never changes). */
static void hpack_encode(const bench_build *b, const bench_case *c, long calls)
{
    (void)c;
    static uint8_t block[4096];
    httpasm_hpack *table = bench_state(b, &encoder_key, b->api.httpasm_hpack_size(4096), encoder_init);
    if (table == NULL)
        return;
    size_t total = 0;
    for (long i = 0; i < calls; i++)
        total += (size_t)b->api.httpasm_hpack_encode(table, browser_fields, (uint32_t)BROWSER_FIELDS, block, sizeof block);
    bench_sink = total;
}

/* h2_request: httpasm_h2_request on the browser fields, `calls` times. It may write into the
 * field records (their ids and flags), so each call starts from a copy of the pristine list
 * (18 records: the copy is part of every contender's sample alike). */
static void h2_request(const bench_build *b, const bench_case *c, long calls)
{
    (void)c;
    static httpasm_field work[BROWSER_FIELDS];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        memcpy(work, browser_fields, sizeof work);
        httpasm_request q;
        memset(&q, 0, sizeof q);
        total += (size_t)b->api.httpasm_h2_request(work, (uint32_t)BROWSER_FIELDS, &q) + q.field_count;
    }
    bench_sink = total;
}

/* add: registers one parsers case. name, input, data, length, octets: as bench_case's; run:
 * the batch. */
static void add(const char *name, const char *input, const void *data, size_t length, size_t octets, bench_batch run)
{
    bench_case c;
    memset(&c, 0, sizeof c);
    c.suite = "parsers";
    c.name = name;
    c.input = input;
    c.data = data;
    c.length = length;
    c.octets = octets;
    c.ours = run;
    c.tiers = BENCH_TIERS_BEST_V1;
    bench_add(&c);
}

/* bench_suite_parsers: registers the suite's cases (bench.h). */
void bench_suite_parsers(void)
{
    memcpy(response_buffer, response_head, sizeof response_head - 1);
    add("h1_parse_response", "typical response head", response_buffer, sizeof response_head - 1, sizeof response_head - 1, parse_response);

    size_t small = encode_chunked(256, 16), large = 0;
    snprintf(chunked_labels[0], sizeof chunked_labels[0], "256 chunks of 16 octets");
    /* Two bodies share chunked_pristine: the small-chunk one (chunk-size lines dominate) is
     * copied aside first, then the large-chunk one (the data copy dominates) is encoded. */
    static uint8_t small_body[sizeof chunked_pristine];
    memcpy(small_body, chunked_pristine, small);
    large = encode_chunked(16, 1024);
    snprintf(chunked_labels[1], sizeof chunked_labels[1], "16 chunks of 1024 octets");
    add("h1_chunked_decode", chunked_labels[0], small_body, small, small, chunked_decode);
    add("h1_chunked_decode", chunked_labels[1], chunked_pristine, large, large, chunked_decode);

    add("field_id", "12 names (10 known, 2 not)", NULL, 0, 0, field_id);
    add("token_length", "method GET", "GET", 3, 3, token_length);
    add("token_length", "a 45-octet field name", token_long, sizeof token_long - 1, sizeof token_long - 1, token_length);
    add("h1_write_response", "200 with 6 fields", NULL, 0, 0, write_response);

    for (size_t i = 0; i < BROWSER_FIELDS; i++) {
        memset(&browser_fields[i], 0, sizeof browser_fields[i]);
        browser_fields[i].name = (const uint8_t *)browser_pairs[i][0];
        browser_fields[i].name_length = (uint32_t)strlen(browser_pairs[i][0]);
        browser_fields[i].value = (const uint8_t *)browser_pairs[i][1];
        browser_fields[i].value_length = (uint32_t)strlen(browser_pairs[i][1]);
        browser_fields[i].flags = HTTPASM_FIELD_FLAG_NO_INDEX;
    }
    add("hpack_encode", "browser request's 18 fields", NULL, 0, 0, hpack_encode);
    add("h2_request", "browser request's 18 fields", NULL, 0, 0, h2_request);
}
