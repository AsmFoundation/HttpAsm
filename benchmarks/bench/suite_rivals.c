/*
 * suite_rivals.c - the rivals suite: HttpAsm's parsers beside the ones others run, on the same
 * inputs, in the same process, on the same core (docs/DESIGN.md phase H step 2: "a
 * single-thread benchmark harness ... against picohttpparser, llhttp and nghttp2").
 *
 *   HTTP/1.1 request heads: httpasm_h1_parse_request; picohttpparser's phr_parse_request (h2o);
 *   llhttp (Node.js), with callbacks that keep every span, which is what a server needs and
 *   what the other two hand back anyway.
 *   HTTP/1.1 response heads (the client's side): httpasm_h1_parse_response; picohttpparser's
 *   phr_parse_response; llhttp in its response mode, every span kept the same way.
 *   HPACK header blocks: httpasm_hpack_decode; nghttp2's nghttp2_hd_inflate_hd3.
 *
 * HttpAsm runs at its best tier and at v1; the rivals are the sources tests/tools.sh pins (the
 * differential fuzzers' references), compiled by benchmarks/bench.sh with -O3 -march=native,
 * their best: picohttpparser's and llhttp's SSE4.2 paths need it. Mind what each one does:
 * picohttpparser splits a head into lines and checks almost nothing else; llhttp checks the
 * grammar; HttpAsm also applies RFC 9112's semantics (target and Host grammar, field names and
 * values, every framing rule, known-field ids).
 */
#include <dlfcn.h>
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

/* ---- HTTP/1.1 response heads (the client's side). */

/* The response head (bench.h): a typical 200 for a page, twelve fields. Fixed octets. */
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

/* bench_response: the writable copy of the response head (bench.h), made on the first call: the
 * parser may write its buffer, and a string literal may sit in read-only memory.
 *   length  out: the head's length. Returns the copy. */
uint8_t *bench_response(size_t *length)
{
    static uint8_t copy[sizeof response_head];
    static int made;
    if (!made) {
        memcpy(copy, response_head, sizeof response_head);
        made = 1;
    }
    *length = sizeof response_head - 1;
    return copy;
}

/* bench_h1_response: httpasm_h1_parse_response on the case's head, `calls` times (bench.h: the
 * parsers and tiers suites run it too). The head holds no obs-fold, so no call writes it and
 * every call parses the same octets. */
void bench_h1_response(const bench_build *b, const bench_case *c, long calls)
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

/* pico_h1_response: picohttpparser's phr_parse_response on the case's head, `calls` times. */
static void pico_h1_response(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    struct phr_header headers[MAX_FIELDS];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        const char *reason;
        size_t reason_length, count = MAX_FIELDS;
        int minor, status;
        total += (size_t)phr_parse_response((const char *)c->data, c->length, &minor, &status, &reason, &reason_length, headers, &count,
                                            0);
    }
    bench_sink = total;
}

/* llhttp_h1_response: llhttp in its response mode on the case's head, `calls` times, every span
 * (the reason, each name and value) kept; it pauses at the head's end (headers_done), before the
 * body the head announces. */
static void llhttp_h1_response(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    static llhttp_settings_t settings;
    static int ready;
    if (!ready) {
        llhttp_settings_init(&settings);
        settings.on_status = keep;
        settings.on_header_field = keep;
        settings.on_header_value = keep;
        settings.on_headers_complete = headers_done;
        ready = 1;
    }
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        llhttp_t parser;
        spans.count = 0;
        llhttp_init(&parser, HTTP_RESPONSE, &settings);
        total += (size_t)llhttp_execute(&parser, (const char *)c->data, c->length) + spans.count;
    }
    bench_sink = total;
}

static const bench_rival h1_response_rivals[] = {
    { "picohttpparser dd573d8", pico_h1_response },
    { "llhttp 9.4.4", llhttp_h1_response },
};

/* ---- Hashes: SHA-256, SHA-512 and SHA-384 against OpenSSL's, the reference M2 measures every
 * primitive by. */

/* bench_sha_input: the hash cases' octets (bench.h): 16 KiB from a fixed xorshift, made once. */
const uint8_t *bench_sha_input(void)
{
    static uint8_t input[16384];
    static int made;
    if (!made) {
        uint64_t x = 0x243F6A8885A308D3u;
        for (size_t i = 0; i < sizeof input; i++) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            input[i] = (uint8_t)x;
        }
        made = 1;
    }
    return input;
}

/* bench_sha256: httpasm_sha256 of the case's message, `calls` times (bench.h). */
void bench_sha256(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t digest[32];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        b->api.httpasm_sha256(c->data, c->length, digest);
        total += digest[0];
    }
    bench_sink = total;
}

/* OpenSSL's libcrypto, loaded at run time (the machine's own: the benchmark needs no headers
 * and builds no OpenSSL), and its one-shot SHA256, which picks the SHA extensions or its
 * AVX2/SSSE3 code by OPENSSL_ia32cap as it does for any application. */
typedef unsigned char *(*openssl_sha256_fn)(const unsigned char *data, size_t length, unsigned char *digest);
static openssl_sha256_fn openssl_sha256_call;
static char openssl_name[64];

/* openssl_load: loads libcrypto.so.3 and finds SHA256 and the version text, once. Returns 0, or
 * -1 (with the reason on stderr) when the machine has no OpenSSL 3: the cases then run without
 * this rival. */
static int openssl_load(void)
{
    static int state;                       /* 0 not tried, 1 loaded, -1 absent */
    if (state != 0)
        return state > 0 ? 0 : -1;
    state = -1;
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL);
    if (crypto == NULL) {
        fprintf(stderr, "bench: rivals: no libcrypto.so.3 (%s): the hash cases run without OpenSSL\n", dlerror());
        return -1;
    }
    openssl_sha256_call = (openssl_sha256_fn)dlsym(crypto, "SHA256");
    const char *(*version)(int) = (const char *(*)(int))dlsym(crypto, "OpenSSL_version");
    if (openssl_sha256_call == NULL || version == NULL) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks SHA256 or OpenSSL_version\n");
        return -1;
    }
    /* "OpenSSL 3.0.13 30 Jan 2024": the name and version, the date left out. */
    snprintf(openssl_name, sizeof openssl_name, "%s", version(0));
    char *space = strchr(openssl_name, ' ');
    if (space != NULL && (space = strchr(space + 1, ' ')) != NULL)
        *space = '\0';
    state = 1;
    return 0;
}

/* openssl_sha256: OpenSSL's SHA256 of the case's message, `calls` times. */
static void openssl_sha256(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char digest[32];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        openssl_sha256_call(c->data, c->length, digest);
        total += digest[0];
    }
    bench_sink = total;
}

static bench_rival sha256_rivals[] = {
    { openssl_name, openssl_sha256 },
};

/* bench_sha512: httpasm_sha512 of the case's message, `calls` times (bench.h). */
void bench_sha512(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t digest[64];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        b->api.httpasm_sha512(c->data, c->length, digest);
        total += digest[0];
    }
    bench_sink = total;
}

/* bench_sha384: httpasm_sha384 of the case's message, `calls` times (bench.h). */
void bench_sha384(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t digest[48];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        b->api.httpasm_sha384(c->data, c->length, digest);
        total += digest[0];
    }
    bench_sink = total;
}

/* OpenSSL's one-shot SHA512 and SHA384 (the same signature as SHA256's), found by
 * openssl_load_sha512: its compression picks AVX2 with BMI2, AVX or the scalar code by
 * OPENSSL_ia32cap, as for any application. */
static openssl_sha256_fn openssl_sha512_call;
static openssl_sha256_fn openssl_sha384_call;

/* openssl_load_sha512: SHA512 and SHA384 from the libcrypto openssl_load found. Returns 0, or -1
 * (with the reason on stderr) when either is missing: the cases then run without this rival. */
static int openssl_load_sha512(void)
{
    if (openssl_load() != 0)
        return -1;
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
    openssl_sha512_call = crypto ? (openssl_sha256_fn)dlsym(crypto, "SHA512") : NULL;
    openssl_sha384_call = crypto ? (openssl_sha256_fn)dlsym(crypto, "SHA384") : NULL;
    if (openssl_sha512_call == NULL || openssl_sha384_call == NULL) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks SHA512 or SHA384\n");
        return -1;
    }
    return 0;
}

/* bench_sha3_256: see bench.h. */
void bench_sha3_256(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t digest[32];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        b->api.httpasm_sha3_256(c->data, c->length, digest);
        total += digest[0];
    }
    bench_sink = total;
}

/* bench_shake128: see bench.h. */
void bench_shake128(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t out[32];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        b->api.httpasm_shake128(c->data, c->length, out, sizeof out);
        total += out[0];
    }
    bench_sink = total;
}

/* OpenSSL's SHA-3 (3.0.13: keccak1600-x86_64, its scalar code, on this CPU) has no one-call
 * function like SHA512: EVP with the algorithm fetched once (EVP_MD_fetch) and one EVP_MD_CTX
 * reused, so each call is EVP_DigestInit_ex, EVP_DigestUpdate and EVP_DigestFinal_ex (or
 * EVP_DigestFinalXOF): what a careful caller does, without the per-call fetch EVP_Digest makes. */
typedef void *(*openssl_md_fetch_fn)(void *libctx, const char *name, const char *properties);
typedef void *(*openssl_md_ctx_new_fn0)(void);
typedef int (*openssl_digest_init_ex_fn)(void *ctx, const void *md, void *engine);
typedef int (*openssl_digest_update_fn)(void *ctx, const void *data, size_t n);
typedef int (*openssl_digest_final_ex_fn)(void *ctx, unsigned char *md, unsigned int *size);
typedef int (*openssl_digest_final_xof_fn)(void *ctx, unsigned char *md, size_t size);
static openssl_digest_init_ex_fn openssl_sha3_init;
static openssl_digest_update_fn openssl_sha3_update;
static openssl_digest_final_ex_fn openssl_sha3_final;
static openssl_digest_final_xof_fn openssl_sha3_final_xof;
static void *openssl_sha3_ctx, *openssl_sha3_256_md, *openssl_shake128_md;

/* openssl_load_sha3: the EVP calls, SHA3-256 and SHAKE128 fetched, one context made (kept for
 * the process). Returns 0, or -1 (the cases then run without this rival). */
static int openssl_load_sha3(void)
{
    if (openssl_load() != 0)
        return -1;
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
    if (crypto == NULL)
        return -1;
    openssl_md_fetch_fn fetch = (openssl_md_fetch_fn)dlsym(crypto, "EVP_MD_fetch");
    openssl_md_ctx_new_fn0 ctx_new = (openssl_md_ctx_new_fn0)dlsym(crypto, "EVP_MD_CTX_new");
    openssl_sha3_init = (openssl_digest_init_ex_fn)dlsym(crypto, "EVP_DigestInit_ex");
    openssl_sha3_update = (openssl_digest_update_fn)dlsym(crypto, "EVP_DigestUpdate");
    openssl_sha3_final = (openssl_digest_final_ex_fn)dlsym(crypto, "EVP_DigestFinal_ex");
    openssl_sha3_final_xof = (openssl_digest_final_xof_fn)dlsym(crypto, "EVP_DigestFinalXOF");
    if (!fetch || !ctx_new || !openssl_sha3_init || !openssl_sha3_update || !openssl_sha3_final || !openssl_sha3_final_xof) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks the EVP digest functions\n");
        return -1;
    }
    openssl_sha3_256_md = fetch(NULL, "SHA3-256", NULL);
    openssl_shake128_md = fetch(NULL, "SHAKE128", NULL);
    openssl_sha3_ctx = ctx_new();
    if (!openssl_sha3_256_md || !openssl_shake128_md || !openssl_sha3_ctx) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 did not fetch SHA3-256 and SHAKE128\n");
        return -1;
    }
    return 0;
}

/* openssl_sha3_256: OpenSSL's SHA3-256 of the case's message, `calls` times. */
static void openssl_sha3_256(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char digest[32];
    unsigned int size = 0;
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        openssl_sha3_init(openssl_sha3_ctx, openssl_sha3_256_md, NULL);
        openssl_sha3_update(openssl_sha3_ctx, c->data, c->length);
        openssl_sha3_final(openssl_sha3_ctx, digest, &size);
        total += digest[0];
    }
    bench_sink = total;
}

/* openssl_shake128: 32 octets of OpenSSL's SHAKE128 of the case's message, `calls` times. */
static void openssl_shake128(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char out[32];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        openssl_sha3_init(openssl_sha3_ctx, openssl_shake128_md, NULL);
        openssl_sha3_update(openssl_sha3_ctx, c->data, c->length);
        openssl_sha3_final_xof(openssl_sha3_ctx, out, sizeof out);
        total += out[0];
    }
    bench_sink = total;
}

static bench_rival sha3_256_rivals[] = {
    { openssl_name, openssl_sha3_256 },
};

static bench_rival shake128_rivals[] = {
    { openssl_name, openssl_shake128 },
};

/* openssl_sha512: OpenSSL's SHA512 of the case's message, `calls` times. */
static void openssl_sha512(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char digest[64];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        openssl_sha512_call(c->data, c->length, digest);
        total += digest[0];
    }
    bench_sink = total;
}

/* openssl_sha384: OpenSSL's SHA384 of the case's message, `calls` times. */
static void openssl_sha384(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char digest[48];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        openssl_sha384_call(c->data, c->length, digest);
        total += digest[0];
    }
    bench_sink = total;
}

static bench_rival sha512_rivals[] = {
    { openssl_name, openssl_sha512 },
};

static bench_rival sha384_rivals[] = {
    { openssl_name, openssl_sha384 },
};

/* The MAC cases' key: 32 octets, a TLS 1.3 traffic secret's size. */
static const uint8_t mac_key[32] = { 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x94, 0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa,
                                     0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x94, 0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa };

/* bench_hmac_sha256: httpasm_hmac_sha256 of the case's message under mac_key (bench.h). */
void bench_hmac_sha256(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t mac[32];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        b->api.httpasm_hmac_sha256(mac_key, sizeof mac_key, c->data, c->length, mac);
        total += mac[0];
    }
    bench_sink = total;
}

/* bench_hkdf_expand: httpasm_hkdf_sha256_expand of c->octets octets, info = the case's data
 * (bench.h). */
void bench_hkdf_expand(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t okm[64];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        total += (size_t)b->api.httpasm_hkdf_sha256_expand(mac_key, sizeof mac_key, c->data, c->length, okm, c->octets);
        total += okm[0];
    }
    bench_sink = total;
}

/* OpenSSL's one-shot HMAC() with EVP_sha256(), found by openssl_load_hmac. */
typedef const void *(*openssl_md_fn)(void);
typedef unsigned char *(*openssl_hmac_fn)(const void *md, const void *key, int key_length, const unsigned char *data, size_t n,
                                          unsigned char *mac, unsigned int *mac_length);
static openssl_hmac_fn openssl_hmac_call;
static const void *openssl_sha256_md;

/* openssl_load_hmac: HMAC and EVP_sha256 from the libcrypto openssl_load found. Returns 0, or -1
 * (the HMAC case then runs without this rival). */
static int openssl_load_hmac(void)
{
    if (openssl_load() != 0)
        return -1;
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
    openssl_hmac_call = crypto ? (openssl_hmac_fn)dlsym(crypto, "HMAC") : NULL;
    openssl_md_fn md = crypto ? (openssl_md_fn)dlsym(crypto, "EVP_sha256") : NULL;
    if (openssl_hmac_call == NULL || md == NULL) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks HMAC or EVP_sha256\n");
        return -1;
    }
    openssl_sha256_md = md();
    return 0;
}

/* openssl_hmac_sha256: OpenSSL's HMAC-SHA256 of the case's message under mac_key, `calls` times. */
static void openssl_hmac_sha256(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char mac[32];
    unsigned int length = 0;
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        openssl_hmac_call(openssl_sha256_md, mac_key, (int)sizeof mac_key, c->data, c->length, mac, &length);
        total += mac[0];
    }
    bench_sink = total;
}

static bench_rival hmac_rivals[] = {
    { openssl_name, openssl_hmac_sha256 },
};

/* ---- The block cipher: one AES block, as QUIC's header protection asks for it. */

/* bench_aes_block: httpasm_aes_encrypt_block, `calls` times, the key made first (bench.h). */
void bench_aes_block(const bench_build *b, const bench_case *c, long calls)
{
    httpasm_aes_key key;
    uint8_t block[16];
    if (b->api.httpasm_aes_init(&key, c->data, c->length) != 0)
        return;
    memcpy(block, c->data, 16);
    for (long i = 0; i < calls; i++)
        b->api.httpasm_aes_encrypt_block(&key, block, block);   /* chained: each block the last one's output */
    bench_sink = block[0];
}

/* OpenSSL's EVP for one ECB block: a context set up once per batch (AES-NI on this CPU, as any
 * application gets it), then EVP_EncryptUpdate of 16 octets per call. */
typedef void *(*openssl_ctx_new_fn)(void);
typedef void (*openssl_ctx_free_fn)(void *ctx);
typedef int (*openssl_init_fn)(void *ctx, const void *cipher, void *engine, const unsigned char *key, const unsigned char *iv);
typedef int (*openssl_padding_fn)(void *ctx, int pad);
typedef int (*openssl_update_fn)(void *ctx, unsigned char *out, int *out_length, const unsigned char *in, int in_length);
static openssl_ctx_new_fn openssl_ctx_new;
static openssl_ctx_free_fn openssl_ctx_free;
static openssl_init_fn openssl_encrypt_init;
static openssl_padding_fn openssl_set_padding;
static openssl_update_fn openssl_encrypt_update;
static const void *openssl_aes128_ecb;
static const void *openssl_aes256_ecb;

/* openssl_load_aes: the EVP functions and the two ECB ciphers. Returns 0, or -1 (with the reason
 * on stderr): the AES cases then run without this rival. */
static int openssl_load_aes(void)
{
    if (openssl_load() != 0)
        return -1;
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
    if (crypto == NULL)
        return -1;
    openssl_ctx_new = (openssl_ctx_new_fn)dlsym(crypto, "EVP_CIPHER_CTX_new");
    openssl_ctx_free = (openssl_ctx_free_fn)dlsym(crypto, "EVP_CIPHER_CTX_free");
    openssl_encrypt_init = (openssl_init_fn)dlsym(crypto, "EVP_EncryptInit_ex");
    openssl_set_padding = (openssl_padding_fn)dlsym(crypto, "EVP_CIPHER_CTX_set_padding");
    openssl_encrypt_update = (openssl_update_fn)dlsym(crypto, "EVP_EncryptUpdate");
    openssl_md_fn ecb128 = (openssl_md_fn)dlsym(crypto, "EVP_aes_128_ecb");
    openssl_md_fn ecb256 = (openssl_md_fn)dlsym(crypto, "EVP_aes_256_ecb");
    if (openssl_ctx_new == NULL || openssl_ctx_free == NULL || openssl_encrypt_init == NULL || openssl_set_padding == NULL ||
        openssl_encrypt_update == NULL || ecb128 == NULL || ecb256 == NULL) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks the EVP cipher functions\n");
        return -1;
    }
    openssl_aes128_ecb = ecb128();
    openssl_aes256_ecb = ecb256();
    return 0;
}

/* openssl_aes_block: OpenSSL's one ECB block, `calls` times, chained like bench_aes_block. */
static void openssl_aes_block(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *ctx = openssl_ctx_new();
    unsigned char block[16];
    int length = 0;
    if (ctx == NULL || openssl_encrypt_init(ctx, c->length == 16 ? openssl_aes128_ecb : openssl_aes256_ecb, NULL, c->data, NULL) != 1) {
        openssl_ctx_free(ctx);
        return;
    }
    openssl_set_padding(ctx, 0);
    memcpy(block, c->data, 16);
    for (long i = 0; i < calls; i++)
        openssl_encrypt_update(ctx, block, &length, block, 16);
    openssl_ctx_free(ctx);
    bench_sink = block[0];
}

static bench_rival aes_rivals[] = {
    { openssl_name, openssl_aes_block },
};

/* ---- AES-GCM: seals the size of TLS records, the AAD a TLS 1.3 record header. */

static uint8_t gcm_out[16384 + 64];         /* the ciphertext (contenders run one at a time) */

/* gcm_seal: httpasm_aes_gcm_seal of the case's message `calls` times under a key of key_length
 * octets (the case's first octets), each call's nonce the last one's with its final word bumped. */
static void gcm_seal(const bench_build *b, const bench_case *c, long calls, size_t key_length)
{
    static httpasm_aes_gcm_key key;
    uint8_t nonce[12] = { 0 }, tag[16];
    static const uint8_t aad[5] = { 0x17, 0x03, 0x03, 0x40, 0x11 };
    if (b->api.httpasm_aes_gcm_init(&key, c->data, key_length) != 0)
        return;
    uint32_t sequence = 0;
    for (long i = 0; i < calls; i++) {
        sequence++;
        memcpy(nonce + 8, &sequence, 4);
        b->api.httpasm_aes_gcm_seal(&key, nonce, aad, sizeof aad, c->data, c->length, gcm_out, tag);
    }
    bench_sink = tag[0] + gcm_out[0];
}

/* bench_gcm128_seal, bench_gcm256_seal: gcm_seal under AES-128 and AES-256 keys (bench.h). */
void bench_gcm128_seal(const bench_build *b, const bench_case *c, long calls) { gcm_seal(b, c, calls, 16); }
void bench_gcm256_seal(const bench_build *b, const bench_case *c, long calls) { gcm_seal(b, c, calls, 32); }

/* OpenSSL's EVP AES-GCM as a TLS library drives it per record: the key set once per batch, then
 * per call a new IV (EVP_EncryptInit_ex with only the IV), the AAD, the text, the final, the tag. */
typedef int (*openssl_final_fn)(void *ctx, unsigned char *out, int *out_length);
typedef int (*openssl_ctrl_fn)(void *ctx, int type, int arg, void *ptr);
static openssl_final_fn openssl_encrypt_final;
static openssl_ctrl_fn openssl_cipher_ctrl;
static const void *openssl_aes128_gcm;
static const void *openssl_aes256_gcm;

/* openssl_load_gcm: the GCM ciphers and functions beside openssl_load_aes's. Returns 0, or -1
 * (the GCM cases then run without this rival). */
static int openssl_load_gcm(void)
{
    if (openssl_load_aes() != 0)
        return -1;
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
    openssl_encrypt_final = crypto ? (openssl_final_fn)dlsym(crypto, "EVP_EncryptFinal_ex") : NULL;
    openssl_cipher_ctrl = crypto ? (openssl_ctrl_fn)dlsym(crypto, "EVP_CIPHER_CTX_ctrl") : NULL;
    openssl_md_fn gcm128 = crypto ? (openssl_md_fn)dlsym(crypto, "EVP_aes_128_gcm") : NULL;
    openssl_md_fn gcm256 = crypto ? (openssl_md_fn)dlsym(crypto, "EVP_aes_256_gcm") : NULL;
    if (openssl_encrypt_final == NULL || openssl_cipher_ctrl == NULL || gcm128 == NULL || gcm256 == NULL) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks the EVP GCM functions\n");
        return -1;
    }
    openssl_aes128_gcm = gcm128();
    openssl_aes256_gcm = gcm256();
    return 0;
}

/* openssl_gcm_seal: OpenSSL's seal of the case's message, `calls` times, as gcm_seal. */
static void openssl_gcm_seal(const bench_build *b, const bench_case *c, long calls, int aes256)
{
    (void)b;
    void *ctx = openssl_ctx_new();
    unsigned char nonce[12] = { 0 }, tag[16];
    static const unsigned char aad[5] = { 0x17, 0x03, 0x03, 0x40, 0x11 };
    int length = 0;
    if (ctx == NULL || openssl_encrypt_init(ctx, aes256 ? openssl_aes256_gcm : openssl_aes128_gcm, NULL, c->data, NULL) != 1) {
        openssl_ctx_free(ctx);
        return;
    }
    uint32_t sequence = 0;
    for (long i = 0; i < calls; i++) {
        sequence++;
        memcpy(nonce + 8, &sequence, 4);
        openssl_encrypt_init(ctx, NULL, NULL, NULL, nonce);
        openssl_encrypt_update(ctx, NULL, &length, aad, (int)sizeof aad);
        openssl_encrypt_update(ctx, gcm_out, &length, c->data, (int)c->length);
        openssl_encrypt_final(ctx, gcm_out + length, &length);
        openssl_cipher_ctrl(ctx, 0x10, 16, tag);            /* EVP_CTRL_AEAD_GET_TAG */
    }
    openssl_ctx_free(ctx);
    bench_sink = tag[0] + gcm_out[0];
}

static void openssl_gcm128_seal(const bench_build *b, const bench_case *c, long calls) { openssl_gcm_seal(b, c, calls, 0); }
static void openssl_gcm256_seal(const bench_build *b, const bench_case *c, long calls) { openssl_gcm_seal(b, c, calls, 1); }

static bench_rival gcm128_rivals[] = {
    { openssl_name, openssl_gcm128_seal },
};

static bench_rival gcm256_rivals[] = {
    { openssl_name, openssl_gcm256_seal },
};

/* ---- ChaCha20-Poly1305: seals the size of TLS records, as AES-GCM's above. */

/* bench_chacha_seal: httpasm_chacha20_poly1305_seal of the case's message `calls` times under
 * the case's first 32 octets as the key, each call's nonce the last one's with its final word
 * bumped (bench.h). The key is raw octets: ChaCha20 has no schedule to make before the loop. */
void bench_chacha_seal(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t nonce[12] = { 0 }, tag[16];
    static const uint8_t aad[5] = { 0x17, 0x03, 0x03, 0x40, 0x11 };
    uint32_t sequence = 0;
    for (long i = 0; i < calls; i++) {
        sequence++;
        memcpy(nonce + 8, &sequence, 4);
        b->api.httpasm_chacha20_poly1305_seal(c->data, nonce, aad, sizeof aad, c->data, c->length, gcm_out, tag);
    }
    bench_sink = tag[0] + gcm_out[0];
}

static const void *openssl_chacha_poly;

/* openssl_load_chacha: EVP_chacha20_poly1305 beside openssl_load_gcm's functions (the same
 * init, update, final and ctrl drive it). Returns 0, or -1 (the case then runs without this
 * rival). */
static int openssl_load_chacha(void)
{
    if (openssl_load_gcm() != 0)
        return -1;
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
    openssl_md_fn chacha = crypto ? (openssl_md_fn)dlsym(crypto, "EVP_chacha20_poly1305") : NULL;
    if (chacha == NULL) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks EVP_chacha20_poly1305\n");
        return -1;
    }
    openssl_chacha_poly = chacha();
    return 0;
}

/* openssl_chacha_seal: OpenSSL's seal of the case's message, `calls` times, as a TLS library
 * drives EVP per record: the key set once, then per call a new nonce, the AAD, the text, the
 * final and the tag (as bench_chacha_seal, the case's first 32 octets the key). */
static void openssl_chacha_seal(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *ctx = openssl_ctx_new();
    unsigned char nonce[12] = { 0 }, tag[16];
    static const unsigned char aad[5] = { 0x17, 0x03, 0x03, 0x40, 0x11 };
    int length = 0;
    if (ctx == NULL || openssl_encrypt_init(ctx, openssl_chacha_poly, NULL, c->data, NULL) != 1) {
        openssl_ctx_free(ctx);
        return;
    }
    uint32_t sequence = 0;
    for (long i = 0; i < calls; i++) {
        sequence++;
        memcpy(nonce + 8, &sequence, 4);
        openssl_encrypt_init(ctx, NULL, NULL, NULL, nonce);
        openssl_encrypt_update(ctx, NULL, &length, aad, (int)sizeof aad);
        openssl_encrypt_update(ctx, gcm_out, &length, c->data, (int)c->length);
        openssl_encrypt_final(ctx, gcm_out + length, &length);
        openssl_cipher_ctrl(ctx, 0x10, 16, tag);            /* EVP_CTRL_AEAD_GET_TAG */
    }
    openssl_ctx_free(ctx);
    bench_sink = tag[0] + gcm_out[0];
}

static bench_rival chacha_rivals[] = {
    { openssl_name, openssl_chacha_seal },
};

/* ---- X25519: the ladder alone, and a key share's whole X25519 work. */

/* bench_x25519: see bench.h. */
void bench_x25519(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t out[32];
    for (long i = 0; i < calls; i++)
        b->api.httpasm_x25519(out, c->data, c->data + 32);
    bench_sink = out[0];
}

/* bench_x25519_public_key: see bench.h. */
void bench_x25519_public_key(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t public_key[32];
    for (long i = 0; i < calls; i++)
        b->api.httpasm_x25519_public_key(public_key, c->data);
    bench_sink = public_key[0];
}

/* bench_x25519_share: see bench.h. */
void bench_x25519_share(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t public_key[32], out[32];
    for (long i = 0; i < calls; i++) {
        b->api.httpasm_x25519_public_key(public_key, c->data);
        b->api.httpasm_x25519(out, c->data, c->data + 32);
    }
    bench_sink = out[0] + public_key[0];
}

typedef void *(*openssl_new_raw_fn)(int type, void *engine, const unsigned char *key, size_t length);
typedef void *(*openssl_pkey_ctx_new_fn)(void *pkey, void *engine);
typedef int (*openssl_pkey_ctx_fn)(void *ctx);
typedef int (*openssl_set_peer_fn)(void *ctx, void *peer);
typedef int (*openssl_derive_fn)(void *ctx, unsigned char *key, size_t *length);
typedef void (*openssl_free_fn)(void *object);
typedef int (*openssl_get_raw_fn)(const void *pkey, unsigned char *out, size_t *length);
static openssl_new_raw_fn openssl_new_private, openssl_new_public;
static openssl_get_raw_fn openssl_get_raw_public;  /* (the X25519 and Ed25519 public keys) */
static openssl_pkey_ctx_new_fn openssl_pkey_ctx_new;
static openssl_pkey_ctx_fn openssl_derive_init;
static openssl_set_peer_fn openssl_set_peer;
static openssl_derive_fn openssl_derive;
static openssl_free_fn openssl_pkey_ctx_free, openssl_pkey_free;
enum { OPENSSL_PKEY_X25519 = 1034 };        /* EVP_PKEY_X25519 (NID_X25519) */

/* openssl_load_x25519: OpenSSL's EVP_PKEY functions for X25519. Returns 0, or -1 (the cases then
 * run without this rival). */
static int openssl_load_x25519(void)
{
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL);
    if (crypto == NULL)
        return -1;
    openssl_new_private = (openssl_new_raw_fn)dlsym(crypto, "EVP_PKEY_new_raw_private_key");
    openssl_new_public = (openssl_new_raw_fn)dlsym(crypto, "EVP_PKEY_new_raw_public_key");
    openssl_pkey_ctx_new = (openssl_pkey_ctx_new_fn)dlsym(crypto, "EVP_PKEY_CTX_new");
    openssl_derive_init = (openssl_pkey_ctx_fn)dlsym(crypto, "EVP_PKEY_derive_init");
    openssl_set_peer = (openssl_set_peer_fn)dlsym(crypto, "EVP_PKEY_derive_set_peer");
    openssl_derive = (openssl_derive_fn)dlsym(crypto, "EVP_PKEY_derive");
    openssl_pkey_ctx_free = (openssl_free_fn)dlsym(crypto, "EVP_PKEY_CTX_free");
    openssl_pkey_free = (openssl_free_fn)dlsym(crypto, "EVP_PKEY_free");
    openssl_get_raw_public = (openssl_get_raw_fn)dlsym(crypto, "EVP_PKEY_get_raw_public_key");
    if (!openssl_new_private || !openssl_new_public || !openssl_pkey_ctx_new || !openssl_derive_init || !openssl_set_peer ||
        !openssl_derive || !openssl_pkey_ctx_free || !openssl_pkey_free || !openssl_get_raw_public) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks the EVP_PKEY X25519 functions\n");
        return -1;
    }
    return 0;
}

/* openssl_x25519: OpenSSL's derive alone: the keys and the context made once, EVP_PKEY_derive
 * `calls` times (the ladder plus EVP's per-call cost). */
static void openssl_x25519(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *private_key = openssl_new_private(OPENSSL_PKEY_X25519, NULL, c->data, 32);
    void *peer = openssl_new_public(OPENSSL_PKEY_X25519, NULL, c->data + 32, 32);
    void *ctx = private_key && peer ? openssl_pkey_ctx_new(private_key, NULL) : NULL;
    unsigned char out[32] = { 0 };
    if (ctx != NULL && openssl_derive_init(ctx) == 1 && openssl_set_peer(ctx, peer) == 1) {
        for (long i = 0; i < calls; i++) {
            size_t length = 32;
            openssl_derive(ctx, out, &length);
        }
    }
    openssl_pkey_ctx_free(ctx);
    openssl_pkey_free(peer);
    openssl_pkey_free(private_key);
    bench_sink = out[0];
}

/* openssl_x25519_share: a key share as a TLS stack drives OpenSSL per handshake: the private key
 * from raw octets (which computes its public key), the peer's key, a context, the derive. */
static void openssl_x25519_share(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char out[32] = { 0 };
    for (long i = 0; i < calls; i++) {
        void *private_key = openssl_new_private(OPENSSL_PKEY_X25519, NULL, c->data, 32);
        void *peer = openssl_new_public(OPENSSL_PKEY_X25519, NULL, c->data + 32, 32);
        void *ctx = openssl_pkey_ctx_new(private_key, NULL);
        size_t length = 32;
        if (openssl_derive_init(ctx) == 1 && openssl_set_peer(ctx, peer) == 1)
            openssl_derive(ctx, out, &length);
        openssl_pkey_ctx_free(ctx);
        openssl_pkey_free(peer);
        openssl_pkey_free(private_key);
    }
    bench_sink = out[0];
}

/* openssl_x25519_public_key: the private key from raw octets (OpenSSL derives its public key
 * then: the fixed-base work of a key share) and the public key taken, each call. */
static void openssl_x25519_public_key(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char out[32] = { 0 };
    for (long i = 0; i < calls; i++) {
        void *private_key = openssl_new_private(OPENSSL_PKEY_X25519, NULL, c->data, 32);
        size_t length = sizeof out;
        openssl_get_raw_public(private_key, out, &length);
        openssl_pkey_free(private_key);
    }
    bench_sink = out[0];
}

static bench_rival x25519_rivals[] = {
    { openssl_name, openssl_x25519 },
};

static bench_rival x25519_public_key_rivals[] = {
    { openssl_name, openssl_x25519_public_key },
};

static bench_rival x25519_share_rivals[] = {
    { openssl_name, openssl_x25519_share },
};

/* ---- X448: the ladder alone, the public key, and a key share's whole X448 work. OpenSSL's
 * rivals go through the same EVP_PKEY functions as X25519's (openssl_load_x25519 loads them),
 * with EVP_PKEY_X448: its derive is curve448's own ladder (libdecaf's 56-bit limbs in C), its
 * public key (from EVP_PKEY_new_raw_private_key) the precomputed fixed-base comb. */

enum { OPENSSL_PKEY_X448 = 1035 };          /* EVP_PKEY_X448 (NID_X448) */

/* bench_x448: see bench.h. */
void bench_x448(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t out[56];
    for (long i = 0; i < calls; i++)
        b->api.httpasm_x448(out, c->data, c->data + 56);
    bench_sink = out[0];
}

/* bench_x448_public_key: see bench.h. */
void bench_x448_public_key(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t public_key[56];
    for (long i = 0; i < calls; i++)
        b->api.httpasm_x448_public_key(public_key, c->data);
    bench_sink = public_key[0];
}

/* bench_x448_share: see bench.h. */
void bench_x448_share(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t public_key[56], out[56];
    for (long i = 0; i < calls; i++) {
        b->api.httpasm_x448_public_key(public_key, c->data);
        b->api.httpasm_x448(out, c->data, c->data + 56);
    }
    bench_sink = out[0] + public_key[0];
}

/* openssl_x448: OpenSSL's derive alone: the keys and the context made once, EVP_PKEY_derive
 * `calls` times (the ladder plus EVP's per-call cost). */
static void openssl_x448(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *private_key = openssl_new_private(OPENSSL_PKEY_X448, NULL, c->data, 56);
    void *peer = openssl_new_public(OPENSSL_PKEY_X448, NULL, c->data + 56, 56);
    void *ctx = private_key && peer ? openssl_pkey_ctx_new(private_key, NULL) : NULL;
    unsigned char out[56] = { 0 };
    if (ctx != NULL && openssl_derive_init(ctx) == 1 && openssl_set_peer(ctx, peer) == 1) {
        for (long i = 0; i < calls; i++) {
            size_t length = 56;
            openssl_derive(ctx, out, &length);
        }
    }
    openssl_pkey_ctx_free(ctx);
    openssl_pkey_free(peer);
    openssl_pkey_free(private_key);
    bench_sink = out[0];
}

/* openssl_x448_share: a key share as a TLS stack drives OpenSSL per handshake: the private key
 * from raw octets (which computes its public key), the peer's key, a context, the derive. */
static void openssl_x448_share(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char out[56] = { 0 };
    for (long i = 0; i < calls; i++) {
        void *private_key = openssl_new_private(OPENSSL_PKEY_X448, NULL, c->data, 56);
        void *peer = openssl_new_public(OPENSSL_PKEY_X448, NULL, c->data + 56, 56);
        void *ctx = openssl_pkey_ctx_new(private_key, NULL);
        size_t length = 56;
        if (openssl_derive_init(ctx) == 1 && openssl_set_peer(ctx, peer) == 1)
            openssl_derive(ctx, out, &length);
        openssl_pkey_ctx_free(ctx);
        openssl_pkey_free(peer);
        openssl_pkey_free(private_key);
    }
    bench_sink = out[0];
}

/* openssl_x448_public_key: the private key from raw octets (OpenSSL derives its public key then,
 * by its fixed-base comb) and the public key taken, each call. */
static void openssl_x448_public_key(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char out[56] = { 0 };
    for (long i = 0; i < calls; i++) {
        void *private_key = openssl_new_private(OPENSSL_PKEY_X448, NULL, c->data, 56);
        size_t length = sizeof out;
        openssl_get_raw_public(private_key, out, &length);
        openssl_pkey_free(private_key);
    }
    bench_sink = out[0];
}

static bench_rival x448_rivals[] = {
    { openssl_name, openssl_x448 },
};

static bench_rival x448_public_key_rivals[] = {
    { openssl_name, openssl_x448_public_key },
};

static bench_rival x448_share_rivals[] = {
    { openssl_name, openssl_x448_share },
};

/* ---- P-256: ECDH, the public key, a key share, ECDSA's signature and verification. */

/* The P-256 cases' input: a private key, RFC 6979 A.2.5's public key as the peer's, a digest,
 * entropy (see bench.h). */
static const uint8_t p256_input[32 + 65 + 32 + 32] = {
    0x5A, 0x31, 0x08, 0xC2, 0x77, 0x19, 0x4E, 0x63, 0xA0, 0x2B, 0xD5, 0x6E, 0x91, 0x3C, 0x47, 0xF8,
    0x0D, 0xB6, 0x29, 0x84, 0x53, 0xE1, 0x7A, 0x9F, 0x36, 0xC4, 0x12, 0x5D, 0xE8, 0x70, 0xAB, 0x45,
    0x04,
    0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31, 0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
    0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C, 0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
    0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99, 0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
    0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51, 0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99,
    0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1, 0xE2, 0xAD, 0xE1, 0xD6, 0x94, 0xF4, 0x1F, 0xC7,
    0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15, 0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF,
    0x13, 0x57, 0x9B, 0xDF, 0x24, 0x68, 0xAC, 0xE0, 0x35, 0x79, 0xBD, 0xF1, 0x46, 0x8A, 0xCE, 0x02,
    0x57, 0x9B, 0xDF, 0x13, 0x68, 0xAC, 0xE0, 0x24, 0x79, 0xBD, 0xF1, 0x35, 0x8A, 0xCE, 0x02, 0x46,
};

/* bench_p256_input: see bench.h. */
const uint8_t *bench_p256_input(void)
{
    return p256_input;
}

/* bench_p256_ecdh: see bench.h. */
void bench_p256_ecdh(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t out[32];
    for (long i = 0; i < calls; i++)
        b->api.httpasm_p256_ecdh(out, c->data, c->data + 32);
    bench_sink = out[0];
}

/* bench_p256_public_key: see bench.h. */
void bench_p256_public_key(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t out[65];
    for (long i = 0; i < calls; i++)
        b->api.httpasm_p256_public_key(out, c->data);
    bench_sink = out[1];
}

/* bench_p256_share: see bench.h. */
void bench_p256_share(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t key[32], public_key[65], out[32];
    for (long i = 0; i < calls; i++) {
        do
            b->api.httpasm_random(key, sizeof key);
        while (b->api.httpasm_p256_public_key(public_key, key) != 0);
        b->api.httpasm_p256_ecdh(out, key, c->data + 32);
    }
    bench_sink = out[0] + public_key[1];
}

/* bench_p256_sign: see bench.h. */
void bench_p256_sign(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t signature[64];
    for (long i = 0; i < calls; i++)
        b->api.httpasm_p256_sign(signature, c->data, c->data + 97, 32, c->data + 129);
    bench_sink = signature[0];
}

/* bench_p256_verify: see bench.h. */
void bench_p256_verify(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t public_key[65], signature[64];
    b->api.httpasm_p256_public_key(public_key, c->data);
    b->api.httpasm_p256_sign(signature, c->data, c->data + 97, 32, NULL);
    int sum = 0;
    for (long i = 0; i < calls; i++)
        sum += b->api.httpasm_p256_verify(public_key, c->data + 97, 32, signature);
    bench_sink = (uint8_t)sum;
}

typedef void *(*openssl_q_keygen_fn)(void *libctx, const char *propq, const char *type, ...);
typedef void *(*openssl_pkey_new_fn)(void);
typedef int (*openssl_copy_parameters_fn)(void *to, const void *from);
typedef int (*openssl_set1_encoded_fn)(void *pkey, const unsigned char *pub, size_t length);
typedef size_t (*openssl_get1_encoded_fn)(void *pkey, unsigned char **pub);
typedef void (*openssl_crypto_free_fn)(void *pointer, const char *file, int line);
typedef int (*openssl_sign_fn)(void *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
typedef int (*openssl_verify_fn)(void *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
static openssl_q_keygen_fn openssl_q_keygen;
static openssl_pkey_new_fn openssl_pkey_new;
static openssl_copy_parameters_fn openssl_copy_parameters;
static openssl_set1_encoded_fn openssl_set1_encoded;
static openssl_get1_encoded_fn openssl_get1_encoded;
static openssl_crypto_free_fn openssl_crypto_free;
static openssl_pkey_ctx_fn openssl_sign_init, openssl_verify_init;
static openssl_sign_fn openssl_sign;
static openssl_verify_fn openssl_verify;

/* openssl_load_p256: OpenSSL's EVP_PKEY functions for EC keys on P-256 (the X25519 set loaded
 * first: the derive functions are shared). Returns 0, or -1 (the cases then run without this
 * rival). */
static int openssl_load_p256(void)
{
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL);
    if (crypto == NULL || openssl_load_x25519() != 0)
        return -1;
    openssl_q_keygen = (openssl_q_keygen_fn)dlsym(crypto, "EVP_PKEY_Q_keygen");
    openssl_pkey_new = (openssl_pkey_new_fn)dlsym(crypto, "EVP_PKEY_new");
    openssl_copy_parameters = (openssl_copy_parameters_fn)dlsym(crypto, "EVP_PKEY_copy_parameters");
    openssl_set1_encoded = (openssl_set1_encoded_fn)dlsym(crypto, "EVP_PKEY_set1_encoded_public_key");
    openssl_get1_encoded = (openssl_get1_encoded_fn)dlsym(crypto, "EVP_PKEY_get1_encoded_public_key");
    openssl_crypto_free = (openssl_crypto_free_fn)dlsym(crypto, "CRYPTO_free");
    openssl_sign_init = (openssl_pkey_ctx_fn)dlsym(crypto, "EVP_PKEY_sign_init");
    openssl_sign = (openssl_sign_fn)dlsym(crypto, "EVP_PKEY_sign");
    openssl_verify_init = (openssl_pkey_ctx_fn)dlsym(crypto, "EVP_PKEY_verify_init");
    openssl_verify = (openssl_verify_fn)dlsym(crypto, "EVP_PKEY_verify");
    if (!openssl_q_keygen || !openssl_pkey_new || !openssl_copy_parameters || !openssl_set1_encoded || !openssl_get1_encoded ||
        !openssl_crypto_free || !openssl_sign_init || !openssl_sign || !openssl_verify_init || !openssl_verify) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks the EVP_PKEY EC functions\n");
        return -1;
    }
    return 0;
}

/* openssl_p256_peer: an EVP_PKEY of the input's peer point, through the encoded form (the call a
 * TLS stack makes for a key share), on the parameters of `like`. */
static void *openssl_p256_peer(void *like, const uint8_t *point)
{
    void *peer = openssl_pkey_new();
    if (peer != NULL && (openssl_copy_parameters(peer, like) != 1 || openssl_set1_encoded(peer, point, 65) != 1)) {
        openssl_pkey_free(peer);
        return NULL;
    }
    return peer;
}

/* openssl_p256_ecdh: OpenSSL's derive alone: a key made once, the peer's key and the context
 * once, EVP_PKEY_derive `calls` times (the multiplication plus EVP's per-call cost; the peer's
 * point checked once, where ours checks it every call). */
static void openssl_p256_ecdh(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *key = openssl_q_keygen(NULL, NULL, "EC", "P-256");
    void *peer = key ? openssl_p256_peer(key, c->data + 32) : NULL;
    void *ctx = peer ? openssl_pkey_ctx_new(key, NULL) : NULL;
    unsigned char out[32] = { 0 };
    if (ctx != NULL && openssl_derive_init(ctx) == 1 && openssl_set_peer(ctx, peer) == 1) {
        for (long i = 0; i < calls; i++) {
            size_t length = 32;
            openssl_derive(ctx, out, &length);
        }
    }
    openssl_pkey_ctx_free(ctx);
    openssl_pkey_free(peer);
    openssl_pkey_free(key);
    bench_sink = out[0];
}

/* openssl_p256_public_key: a key generated and its encoded public key taken, `calls` times (the
 * fixed-base work OpenSSL does per handshake, with its random draw). */
static void openssl_p256_public_key(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    (void)c;
    unsigned char first = 0;
    for (long i = 0; i < calls; i++) {
        void *key = openssl_q_keygen(NULL, NULL, "EC", "P-256");
        unsigned char *encoded = NULL;
        if (key != NULL && openssl_get1_encoded(key, &encoded) == 65)
            first = encoded[1];
        openssl_crypto_free(encoded, "", 0);
        openssl_pkey_free(key);
    }
    bench_sink = first;
}

/* openssl_p256_share: a key share as OpenSSL's TLS 1.3 code makes one per handshake: a key
 * generated, its encoded public key, the peer's key from its encoding, a context, the derive. */
static void openssl_p256_share(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char out[32] = { 0 };
    for (long i = 0; i < calls; i++) {
        void *key = openssl_q_keygen(NULL, NULL, "EC", "P-256");
        unsigned char *encoded = NULL;
        openssl_get1_encoded(key, &encoded);
        void *peer = openssl_p256_peer(key, c->data + 32);
        void *ctx = openssl_pkey_ctx_new(key, NULL);
        size_t length = 32;
        if (openssl_derive_init(ctx) == 1 && openssl_set_peer(ctx, peer) == 1)
            openssl_derive(ctx, out, &length);
        openssl_pkey_ctx_free(ctx);
        openssl_pkey_free(peer);
        openssl_crypto_free(encoded, "", 0);
        openssl_pkey_free(key);
    }
    bench_sink = out[0];
}

/* openssl_p256_sign: EVP_PKEY_sign of the input's digest under a key made once, the context
 * once (a random nonce from OpenSSL's generator each call, DER out). */
static void openssl_p256_sign(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *key = openssl_q_keygen(NULL, NULL, "EC", "P-256");
    void *ctx = key ? openssl_pkey_ctx_new(key, NULL) : NULL;
    unsigned char signature[80] = { 0 };
    if (ctx != NULL && openssl_sign_init(ctx) == 1) {
        for (long i = 0; i < calls; i++) {
            size_t length = sizeof signature;
            openssl_sign(ctx, signature, &length, c->data + 97, 32);
        }
    }
    openssl_pkey_ctx_free(ctx);
    openssl_pkey_free(key);
    bench_sink = signature[4];
}

/* openssl_p256_verify: EVP_PKEY_verify of a valid signature (made before the loop), the
 * context made once. */
static void openssl_p256_verify(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *key = openssl_q_keygen(NULL, NULL, "EC", "P-256");
    void *ctx = key ? openssl_pkey_ctx_new(key, NULL) : NULL;
    unsigned char signature[80] = { 0 };
    size_t length = sizeof signature;
    int sum = 0;
    if (ctx != NULL && openssl_sign_init(ctx) == 1 && openssl_sign(ctx, signature, &length, c->data + 97, 32) == 1 &&
        openssl_verify_init(ctx) == 1) {
        for (long i = 0; i < calls; i++)
            sum += openssl_verify(ctx, signature, length, c->data + 97, 32);
    }
    openssl_pkey_ctx_free(ctx);
    openssl_pkey_free(key);
    bench_sink = (uint8_t)sum;
}

static bench_rival p256_ecdh_rivals[] = { { openssl_name, openssl_p256_ecdh } };
static bench_rival p256_public_key_rivals[] = { { openssl_name, openssl_p256_public_key } };
static bench_rival p256_share_rivals[] = { { openssl_name, openssl_p256_share } };
static bench_rival p256_sign_rivals[] = { { openssl_name, openssl_p256_sign } };
static bench_rival p256_verify_rivals[] = { { openssl_name, openssl_p256_verify } };

/* ---- P-384: ECDH, the public key, a key share, ECDSA's signature and verification. */

/* The P-384 cases' input: a private key, RFC 6979 A.2.6's public key as the peer's, a SHA-384
 * digest (of "sample"), entropy (see bench.h). */
static const uint8_t p384_input[48 + 97 + 48 + 48] = {
    0x3A, 0x8C, 0x51, 0xF9, 0xD2, 0x7E, 0x60, 0x4B, 0x19, 0xC5, 0xEE, 0x73, 0x2A, 0xB4, 0x8D, 0x01,
    0xF7, 0x65, 0x3C, 0x9A, 0xE2, 0x14, 0x8B, 0xD6, 0x0F, 0x7A, 0x2C, 0x95, 0xE4, 0x31, 0x8B, 0x6D,
    0x72, 0xC0, 0x54, 0x9E, 0xA3, 0xB6, 0x1F, 0x78, 0xD2, 0x05, 0x4C, 0x93, 0xE1, 0xA8, 0x7B, 0x26,
    0x04, 0xEC, 0x3A, 0x4E, 0x41, 0x5B, 0x4E, 0x19, 0xA4, 0x56, 0x86, 0x18, 0x02, 0x9F, 0x42, 0x7F,
    0xA5, 0xDA, 0x9A, 0x8B, 0xC4, 0xAE, 0x92, 0xE0, 0x2E, 0x06, 0xAA, 0xE5, 0x28, 0x6B, 0x30, 0x0C,
    0x64, 0xDE, 0xF8, 0xF0, 0xEA, 0x90, 0x55, 0x86, 0x60, 0x64, 0xA2, 0x54, 0x51, 0x54, 0x80, 0xBC,
    0x13, 0x80, 0x15, 0xD9, 0xB7, 0x2D, 0x7D, 0x57, 0x24, 0x4E, 0xA8, 0xEF, 0x9A, 0xC0, 0xC6, 0x21,
    0x89, 0x67, 0x08, 0xA5, 0x93, 0x67, 0xF9, 0xDF, 0xB9, 0xF5, 0x4C, 0xA8, 0x4B, 0x3F, 0x1C, 0x9D,
    0xB1, 0x28, 0x8B, 0x23, 0x1C, 0x3A, 0xE0, 0xD4, 0xFE, 0x73, 0x44, 0xFD, 0x25, 0x33, 0x26, 0x47,
    0x20, 0x9A, 0x90, 0x83, 0x50, 0x5B, 0xC9, 0x22, 0x76, 0xAE, 0xC4, 0xBE, 0x31, 0x26, 0x96, 0xEF,
    0x7B, 0xF3, 0xBF, 0x60, 0x3F, 0x4B, 0xBD, 0x38, 0x11, 0x96, 0xA0, 0x29, 0xF3, 0x40, 0x58, 0x53,
    0x12, 0x31, 0x3B, 0xCA, 0x4A, 0x9B, 0x5B, 0x89, 0x0E, 0xFE, 0xE4, 0x2C, 0x77, 0xB1, 0xEE, 0x25,
    0xFE, 0x13, 0x37, 0x5B, 0x7F, 0xA3, 0xC7, 0xEB, 0x0F, 0x33, 0x57, 0x7B, 0x9F, 0xC3, 0xE7, 0x0B,
    0x2F, 0x53, 0x77, 0x9B, 0xBF, 0xE3, 0x07, 0x2B, 0x4F, 0x73, 0x97, 0xBB, 0xDF, 0x03, 0x27, 0x4B,
    0x6F, 0x93, 0xB7, 0xDB, 0xFF, 0x23, 0x47, 0x6B, 0x8F, 0xB3, 0xD7, 0xFB, 0x1F, 0x43, 0x67, 0x8B,
    0xAF,
};

/* bench_p384_input: see bench.h. */
const uint8_t *bench_p384_input(void)
{
    return p384_input;
}

/* bench_p384_ecdh: see bench.h. */
void bench_p384_ecdh(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t out[48];
    for (long i = 0; i < calls; i++)
        b->api.httpasm_p384_ecdh(out, c->data, c->data + 48);
    bench_sink = out[0];
}

/* bench_p384_public_key: see bench.h. */
void bench_p384_public_key(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t out[97];
    for (long i = 0; i < calls; i++)
        b->api.httpasm_p384_public_key(out, c->data);
    bench_sink = out[1];
}

/* bench_p384_share: see bench.h. */
void bench_p384_share(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t key[48], public_key[97], out[48];
    for (long i = 0; i < calls; i++) {
        do
            b->api.httpasm_random(key, sizeof key);
        while (b->api.httpasm_p384_public_key(public_key, key) != 0);
        b->api.httpasm_p384_ecdh(out, key, c->data + 48);
    }
    bench_sink = out[0] + public_key[1];
}

/* bench_p384_sign: see bench.h. */
void bench_p384_sign(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t signature[96];
    for (long i = 0; i < calls; i++)
        b->api.httpasm_p384_sign(signature, c->data, c->data + 145, 48, c->data + 193);
    bench_sink = signature[0];
}

/* bench_p384_verify: see bench.h. */
void bench_p384_verify(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t public_key[97], signature[96];
    b->api.httpasm_p384_public_key(public_key, c->data);
    b->api.httpasm_p384_sign(signature, c->data, c->data + 145, 48, NULL);
    int sum = 0;
    for (long i = 0; i < calls; i++)
        sum += b->api.httpasm_p384_verify(public_key, c->data + 145, 48, signature);
    bench_sink = (uint8_t)sum;
}

/* OpenSSL at P-384 (3.0.13 runs its generic EC_GFp_mont_method there: no assembly for this curve,
 * where P-256 has ecp_nistz256): the same calls as the P-256 rivals, the curve "P-384". */

/* openssl_p384_peer: an EVP_PKEY of the input's peer point, through the encoded form, on the
 * parameters of `like`. */
static void *openssl_p384_peer(void *like, const uint8_t *point)
{
    void *peer = openssl_pkey_new();
    if (peer != NULL && (openssl_copy_parameters(peer, like) != 1 || openssl_set1_encoded(peer, point, 97) != 1)) {
        openssl_pkey_free(peer);
        return NULL;
    }
    return peer;
}

/* openssl_p384_ecdh: the derive alone (key, peer and context made once). */
static void openssl_p384_ecdh(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *key = openssl_q_keygen(NULL, NULL, "EC", "P-384");
    void *peer = key ? openssl_p384_peer(key, c->data + 48) : NULL;
    void *ctx = peer ? openssl_pkey_ctx_new(key, NULL) : NULL;
    unsigned char out[48] = { 0 };
    if (ctx != NULL && openssl_derive_init(ctx) == 1 && openssl_set_peer(ctx, peer) == 1) {
        for (long i = 0; i < calls; i++) {
            size_t length = 48;
            openssl_derive(ctx, out, &length);
        }
    }
    openssl_pkey_ctx_free(ctx);
    openssl_pkey_free(peer);
    openssl_pkey_free(key);
    bench_sink = out[0];
}

/* openssl_p384_public_key: a key generated and its encoded public key taken, each call. */
static void openssl_p384_public_key(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    (void)c;
    unsigned char first = 0;
    for (long i = 0; i < calls; i++) {
        void *key = openssl_q_keygen(NULL, NULL, "EC", "P-384");
        unsigned char *encoded = NULL;
        if (key != NULL && openssl_get1_encoded(key, &encoded) == 97)
            first = encoded[1];
        openssl_crypto_free(encoded, "", 0);
        openssl_pkey_free(key);
    }
    bench_sink = first;
}

/* openssl_p384_share: a key share as OpenSSL's TLS 1.3 code makes one per handshake. */
static void openssl_p384_share(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char out[48] = { 0 };
    for (long i = 0; i < calls; i++) {
        void *key = openssl_q_keygen(NULL, NULL, "EC", "P-384");
        unsigned char *encoded = NULL;
        openssl_get1_encoded(key, &encoded);
        void *peer = openssl_p384_peer(key, c->data + 48);
        void *ctx = openssl_pkey_ctx_new(key, NULL);
        size_t length = 48;
        if (openssl_derive_init(ctx) == 1 && openssl_set_peer(ctx, peer) == 1)
            openssl_derive(ctx, out, &length);
        openssl_pkey_ctx_free(ctx);
        openssl_pkey_free(peer);
        openssl_crypto_free(encoded, "", 0);
        openssl_pkey_free(key);
    }
    bench_sink = out[0];
}

/* openssl_p384_sign: EVP_PKEY_sign of the input's digest under a key made once (a random nonce
 * from OpenSSL's generator each call, DER out). */
static void openssl_p384_sign(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *key = openssl_q_keygen(NULL, NULL, "EC", "P-384");
    void *ctx = key ? openssl_pkey_ctx_new(key, NULL) : NULL;
    unsigned char signature[112] = { 0 };
    if (ctx != NULL && openssl_sign_init(ctx) == 1) {
        for (long i = 0; i < calls; i++) {
            size_t length = sizeof signature;
            openssl_sign(ctx, signature, &length, c->data + 145, 48);
        }
    }
    openssl_pkey_ctx_free(ctx);
    openssl_pkey_free(key);
    bench_sink = signature[4];
}

/* openssl_p384_verify: EVP_PKEY_verify of a valid signature (made before the loop). */
static void openssl_p384_verify(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *key = openssl_q_keygen(NULL, NULL, "EC", "P-384");
    void *ctx = key ? openssl_pkey_ctx_new(key, NULL) : NULL;
    unsigned char signature[112] = { 0 };
    size_t length = sizeof signature;
    int sum = 0;
    if (ctx != NULL && openssl_sign_init(ctx) == 1 && openssl_sign(ctx, signature, &length, c->data + 145, 48) == 1 &&
        openssl_verify_init(ctx) == 1) {
        for (long i = 0; i < calls; i++)
            sum += openssl_verify(ctx, signature, length, c->data + 145, 48);
    }
    openssl_pkey_ctx_free(ctx);
    openssl_pkey_free(key);
    bench_sink = (uint8_t)sum;
}

static bench_rival p384_ecdh_rivals[] = { { openssl_name, openssl_p384_ecdh } };
static bench_rival p384_public_key_rivals[] = { { openssl_name, openssl_p384_public_key } };
static bench_rival p384_share_rivals[] = { { openssl_name, openssl_p384_share } };
static bench_rival p384_sign_rivals[] = { { openssl_name, openssl_p384_sign } };
static bench_rival p384_verify_rivals[] = { { openssl_name, openssl_p384_verify } };

/* ---- Ed25519: the public key, a signature, a verification. */

/* The Ed25519 cases' input (see bench.h): the seed, then the CertificateVerify content, built on
 * first use (the bench is single-threaded). */
static uint8_t ed25519_input[32 + BENCH_ED25519_MESSAGE];

/* bench_ed25519_input: see bench.h. */
const uint8_t *bench_ed25519_input(void)
{
    static const char context[] = "TLS 1.3, server CertificateVerify";
    if (ed25519_input[32] == 0) {
        for (size_t i = 0; i < 32; i++)
            ed25519_input[i] = (uint8_t)(0x9D + 37 * i);    /* the seed: any 32 octets are a key */
        memset(ed25519_input + 32, 0x20, 64);
        memcpy(ed25519_input + 32 + 64, context, sizeof context);    /* (its NUL is the separator) */
        for (size_t i = 0; i < 32; i++)
            ed25519_input[32 + 64 + sizeof context + i] = (uint8_t)(0x5A ^ (13 * i));   /* the hash */
    }
    return ed25519_input;
}

/* bench_ed25519_public_key: see bench.h. */
void bench_ed25519_public_key(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t out[32];
    for (long i = 0; i < calls; i++)
        b->api.httpasm_ed25519_public_key(out, c->data);
    bench_sink = out[0];
}

/* bench_ed25519_sign: see bench.h. */
void bench_ed25519_sign(const bench_build *b, const bench_case *c, long calls)
{
    httpasm_ed25519_private_key key;
    uint8_t signature[64];
    b->api.httpasm_ed25519_private_key_init(&key, c->data);
    for (long i = 0; i < calls; i++)
        b->api.httpasm_ed25519_sign(signature, &key, c->data + 32, BENCH_ED25519_MESSAGE);
    memset(&key, 0, sizeof key);
    bench_sink = signature[0];
}

/* bench_ed25519_verify: see bench.h. */
void bench_ed25519_verify(const bench_build *b, const bench_case *c, long calls)
{
    httpasm_ed25519_private_key key;
    uint8_t public_key[32], signature[64];
    b->api.httpasm_ed25519_public_key(public_key, c->data);
    b->api.httpasm_ed25519_private_key_init(&key, c->data);
    b->api.httpasm_ed25519_sign(signature, &key, c->data + 32, BENCH_ED25519_MESSAGE);
    int sum = 0;
    for (long i = 0; i < calls; i++)
        sum += b->api.httpasm_ed25519_verify(public_key, c->data + 32, BENCH_ED25519_MESSAGE, signature);
    bench_sink = (uint8_t)sum;
}

/* OpenSSL's Ed25519 (3.0.13: its own curve25519.c, 51-bit limbs in C on x86-64, with the
 * fixed-base table) through EVP: the key from raw octets (which derives the public key), the
 * message signed and verified whole with EVP_DigestSign and EVP_DigestVerify. OpenSSL 3.0.13
 * takes repeated one-shot calls on one context (checked: the same signature each time), so the
 * contexts are made before the loops and only the calls are timed - the strictest rival. */
typedef void *(*openssl_md_ctx_new_fn)(void);
typedef int (*openssl_digest_sign_init_fn)(void *ctx, void **pctx, const void *md, void *engine, void *pkey);
typedef int (*openssl_digest_sign_fn)(void *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
typedef int (*openssl_digest_verify_fn)(void *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
static openssl_md_ctx_new_fn openssl_md_ctx_new;
static openssl_free_fn openssl_md_ctx_free;
static openssl_digest_sign_init_fn openssl_digest_sign_init, openssl_digest_verify_init;
static openssl_digest_sign_fn openssl_digest_sign;
static openssl_digest_verify_fn openssl_digest_verify;
enum { OPENSSL_PKEY_ED25519 = 1087 };       /* EVP_PKEY_ED25519 (NID_ED25519) */

/* openssl_load_ed25519: OpenSSL's EVP functions for Ed25519 (the raw-key ones, the public key's
 * getter among them, come with X25519's). Returns 0, or -1 (the cases then run without this
 * rival). */
static int openssl_load_ed25519(void)
{
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL);
    if (crypto == NULL || openssl_load_x25519() != 0)
        return -1;
    openssl_md_ctx_new = (openssl_md_ctx_new_fn)dlsym(crypto, "EVP_MD_CTX_new");
    openssl_md_ctx_free = (openssl_free_fn)dlsym(crypto, "EVP_MD_CTX_free");
    openssl_digest_sign_init = (openssl_digest_sign_init_fn)dlsym(crypto, "EVP_DigestSignInit");
    openssl_digest_sign = (openssl_digest_sign_fn)dlsym(crypto, "EVP_DigestSign");
    openssl_digest_verify_init = (openssl_digest_sign_init_fn)dlsym(crypto, "EVP_DigestVerifyInit");
    openssl_digest_verify = (openssl_digest_verify_fn)dlsym(crypto, "EVP_DigestVerify");
    if (!openssl_md_ctx_new || !openssl_md_ctx_free || !openssl_digest_sign_init || !openssl_digest_sign ||
        !openssl_digest_verify_init || !openssl_digest_verify) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks the EVP Ed25519 functions\n");
        return -1;
    }
    return 0;
}

/* openssl_ed25519_public_key: the key made from the seed (OpenSSL derives its public key then)
 * and the public key taken, each call. */
static void openssl_ed25519_public_key(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char out[32] = { 0 };
    for (long i = 0; i < calls; i++) {
        void *key = openssl_new_private(OPENSSL_PKEY_ED25519, NULL, c->data, 32);
        size_t length = sizeof out;
        openssl_get_raw_public(key, out, &length);
        openssl_pkey_free(key);
    }
    bench_sink = out[0];
}

/* openssl_ed25519_sign: EVP_DigestSign of the message, the key and the context made once. */
static void openssl_ed25519_sign(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *key = openssl_new_private(OPENSSL_PKEY_ED25519, NULL, c->data, 32);
    void *ctx = key ? openssl_md_ctx_new() : NULL;
    unsigned char signature[64] = { 0 };
    if (ctx != NULL && openssl_digest_sign_init(ctx, NULL, NULL, NULL, key) == 1) {
        for (long i = 0; i < calls; i++) {
            size_t length = sizeof signature;
            openssl_digest_sign(ctx, signature, &length, c->data + 32, BENCH_ED25519_MESSAGE);
        }
    }
    openssl_md_ctx_free(ctx);
    openssl_pkey_free(key);
    bench_sink = signature[0];
}

/* openssl_ed25519_verify: EVP_DigestVerify of a valid signature (made before the loop), the
 * public key and the context made once. */
static void openssl_ed25519_verify(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *key = openssl_new_private(OPENSSL_PKEY_ED25519, NULL, c->data, 32);
    unsigned char public_key[32], signature[64] = { 0 };
    size_t length = sizeof public_key;
    void *sign = key ? openssl_md_ctx_new() : NULL;
    void *verify = key ? openssl_md_ctx_new() : NULL;
    void *peer = NULL;
    int sum = 0;
    if (sign != NULL && verify != NULL && openssl_get_raw_public(key, public_key, &length) == 1 &&
        (peer = openssl_new_public(OPENSSL_PKEY_ED25519, NULL, public_key, 32)) != NULL &&
        openssl_digest_sign_init(sign, NULL, NULL, NULL, key) == 1) {
        length = sizeof signature;
        if (openssl_digest_sign(sign, signature, &length, c->data + 32, BENCH_ED25519_MESSAGE) == 1 &&
            openssl_digest_verify_init(verify, NULL, NULL, NULL, peer) == 1) {
            for (long i = 0; i < calls; i++)
                sum += openssl_digest_verify(verify, signature, 64, c->data + 32, BENCH_ED25519_MESSAGE);
        }
    }
    openssl_md_ctx_free(verify);
    openssl_md_ctx_free(sign);
    openssl_pkey_free(peer);
    openssl_pkey_free(key);
    bench_sink = (uint8_t)sum;
}

static bench_rival ed25519_public_key_rivals[] = { { openssl_name, openssl_ed25519_public_key } };
static bench_rival ed25519_sign_rivals[] = { { openssl_name, openssl_ed25519_sign } };
static bench_rival ed25519_verify_rivals[] = { { openssl_name, openssl_ed25519_verify } };

/* ---- Ed448: the public key, a signature, a verification. OpenSSL's rival goes through the same
 * EVP functions as Ed25519's (openssl_load_ed25519 loads them) with EVP_PKEY_ED448: its curve448
 * code (libdecaf's 56-bit limbs in C, a fixed-base comb), pure Ed448 with an empty context. */

enum { OPENSSL_PKEY_ED448 = 1088 };         /* EVP_PKEY_ED448 (NID_ED448) */

/* The Ed448 cases' input (see bench.h): the seed, then Ed25519's CertificateVerify content. */
static uint8_t ed448_input[57 + BENCH_ED25519_MESSAGE];

/* bench_ed448_input: see bench.h. */
const uint8_t *bench_ed448_input(void)
{
    if (ed448_input[57] == 0) {
        for (size_t i = 0; i < 57; i++)
            ed448_input[i] = (uint8_t)(0x4F + 41 * i);      /* the seed: any 57 octets are a key */
        memcpy(ed448_input + 57, bench_ed25519_input() + 32, BENCH_ED25519_MESSAGE);
    }
    return ed448_input;
}

/* bench_ed448_public_key: see bench.h. */
void bench_ed448_public_key(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t out[57];
    for (long i = 0; i < calls; i++)
        b->api.httpasm_ed448_public_key(out, c->data);
    bench_sink = out[0];
}

/* bench_ed448_sign: see bench.h. */
void bench_ed448_sign(const bench_build *b, const bench_case *c, long calls)
{
    httpasm_ed448_private_key key;
    uint8_t signature[114];
    b->api.httpasm_ed448_private_key_init(&key, c->data);
    for (long i = 0; i < calls; i++)
        b->api.httpasm_ed448_sign(signature, &key, c->data + 57, BENCH_ED25519_MESSAGE, NULL, 0);
    memset(&key, 0, sizeof key);
    bench_sink = signature[0];
}

/* bench_ed448_verify: see bench.h. */
void bench_ed448_verify(const bench_build *b, const bench_case *c, long calls)
{
    httpasm_ed448_private_key key;
    uint8_t public_key[57], signature[114];
    b->api.httpasm_ed448_public_key(public_key, c->data);
    b->api.httpasm_ed448_private_key_init(&key, c->data);
    b->api.httpasm_ed448_sign(signature, &key, c->data + 57, BENCH_ED25519_MESSAGE, NULL, 0);
    int sum = 0;
    for (long i = 0; i < calls; i++)
        sum += b->api.httpasm_ed448_verify(public_key, c->data + 57, BENCH_ED25519_MESSAGE, NULL, 0, signature);
    bench_sink = (uint8_t)sum;
}

/* openssl_ed448_public_key: the key made from the seed (OpenSSL derives its public key then) and
 * the public key taken, each call. */
static void openssl_ed448_public_key(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char out[57] = { 0 };
    for (long i = 0; i < calls; i++) {
        void *key = openssl_new_private(OPENSSL_PKEY_ED448, NULL, c->data, 57);
        size_t length = sizeof out;
        openssl_get_raw_public(key, out, &length);
        openssl_pkey_free(key);
    }
    bench_sink = out[0];
}

/* openssl_ed448_sign: EVP_DigestSign of the message, the key and the context made once. */
static void openssl_ed448_sign(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *key = openssl_new_private(OPENSSL_PKEY_ED448, NULL, c->data, 57);
    void *ctx = key ? openssl_md_ctx_new() : NULL;
    unsigned char signature[114] = { 0 };
    if (ctx != NULL && openssl_digest_sign_init(ctx, NULL, NULL, NULL, key) == 1) {
        for (long i = 0; i < calls; i++) {
            size_t length = sizeof signature;
            openssl_digest_sign(ctx, signature, &length, c->data + 57, BENCH_ED25519_MESSAGE);
        }
    }
    openssl_md_ctx_free(ctx);
    openssl_pkey_free(key);
    bench_sink = signature[0];
}

/* openssl_ed448_verify: EVP_DigestVerify of a valid signature (made before the loop), the public
 * key and the context made once. */
static void openssl_ed448_verify(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *key = openssl_new_private(OPENSSL_PKEY_ED448, NULL, c->data, 57);
    unsigned char public_key[57], signature[114] = { 0 };
    size_t length = sizeof public_key;
    void *sign = key ? openssl_md_ctx_new() : NULL;
    void *verify = key ? openssl_md_ctx_new() : NULL;
    void *peer = NULL;
    int sum = 0;
    if (sign != NULL && verify != NULL && openssl_get_raw_public(key, public_key, &length) == 1 &&
        (peer = openssl_new_public(OPENSSL_PKEY_ED448, NULL, public_key, 57)) != NULL &&
        openssl_digest_sign_init(sign, NULL, NULL, NULL, key) == 1) {
        length = sizeof signature;
        if (openssl_digest_sign(sign, signature, &length, c->data + 57, BENCH_ED25519_MESSAGE) == 1 &&
            openssl_digest_verify_init(verify, NULL, NULL, NULL, peer) == 1) {
            for (long i = 0; i < calls; i++)
                sum += openssl_digest_verify(verify, signature, 114, c->data + 57, BENCH_ED25519_MESSAGE);
        }
    }
    openssl_md_ctx_free(verify);
    openssl_md_ctx_free(sign);
    openssl_pkey_free(peer);
    openssl_pkey_free(key);
    bench_sink = (uint8_t)sum;
}

static bench_rival ed448_public_key_rivals[] = { { openssl_name, openssl_ed448_public_key } };
static bench_rival ed448_sign_rivals[] = { { openssl_name, openssl_ed448_sign } };
static bench_rival ed448_verify_rivals[] = { { openssl_name, openssl_ed448_verify } };

/* ---- ML-KEM: a key pair, an encapsulation, a decapsulation, at 768 and 1024. OpenSSL 3.0.13 has
 * no ML-KEM (3.5 brought it): the rival is mlkem-native 2.1.0 (rival_mlkem.c), its AVX2 backend. */

/* The cases' 96 octets: the seed d || z, then m (fixed, made on first use: single-threaded). */
static uint8_t mlkem_input[96];
static int mlkem_input_made;

/* bench_mlkem_input: the cases' data (see bench.h). */
static const uint8_t *bench_mlkem_input(void)
{
    if (!mlkem_input_made) {
        for (size_t i = 0; i < sizeof mlkem_input; i++)
            mlkem_input[i] = (uint8_t)(0xA7 ^ (53 * i));
        mlkem_input_made = 1;
    }
    return mlkem_input;
}

/* The keys and ciphertexts the loops reuse (the largest set's sizes; the bench is single-threaded). */
static uint8_t mlkem_ek[1568], mlkem_dk[3168], mlkem_ct[1568], mlkem_ss[32];

/* mlkem_ours: one of HttpAsm's three functions of a case's set (op 0 key pair, 1 encapsulation,
 * 2 decapsulation) on the shared buffers. */
static void mlkem_ours(const bench_build *b, size_t set, int op, const uint8_t *data)
{
    if (op == 0) {
        if (set == 768)
            b->api.httpasm_mlkem768_keypair(mlkem_ek, mlkem_dk, data);
        else
            b->api.httpasm_mlkem1024_keypair(mlkem_ek, mlkem_dk, data);
    } else if (op == 1) {
        if (set == 768)
            b->api.httpasm_mlkem768_encaps(mlkem_ct, mlkem_ss, mlkem_ek, data + 64);
        else
            b->api.httpasm_mlkem1024_encaps(mlkem_ct, mlkem_ss, mlkem_ek, data + 64);
    } else {
        if (set == 768)
            b->api.httpasm_mlkem768_decaps(mlkem_ss, mlkem_dk, mlkem_ct);
        else
            b->api.httpasm_mlkem1024_decaps(mlkem_ss, mlkem_dk, mlkem_ct);
    }
}

/* bench_mlkem_keypair, bench_mlkem_encaps, bench_mlkem_decaps: see bench.h (each prepares what its
 * operation takes with HttpAsm's own functions, then times the operation alone). */
void bench_mlkem_keypair(const bench_build *b, const bench_case *c, long calls)
{
    for (long i = 0; i < calls; i++)
        mlkem_ours(b, c->length, 0, c->data);
    bench_sink = mlkem_ek[0];
}

void bench_mlkem_encaps(const bench_build *b, const bench_case *c, long calls)
{
    mlkem_ours(b, c->length, 0, c->data);
    for (long i = 0; i < calls; i++)
        mlkem_ours(b, c->length, 1, c->data);
    bench_sink = mlkem_ss[0];
}

void bench_mlkem_decaps(const bench_build *b, const bench_case *c, long calls)
{
    mlkem_ours(b, c->length, 0, c->data);
    mlkem_ours(b, c->length, 1, c->data);
    for (long i = 0; i < calls; i++)
        mlkem_ours(b, c->length, 2, c->data);
    bench_sink = mlkem_ss[0];
}

/* mlkem_rival: mlkem-native's function of the same operation on the same buffers. */
static void mlkem_rival(size_t set, int op, const uint8_t *data)
{
    if (op == 0) {
        if (set == 768)
            rival_mlkem768_keypair(mlkem_ek, mlkem_dk, data);
        else
            rival_mlkem1024_keypair(mlkem_ek, mlkem_dk, data);
    } else if (op == 1) {
        if (set == 768)
            rival_mlkem768_encaps(mlkem_ct, mlkem_ss, mlkem_ek, data + 64);
        else
            rival_mlkem1024_encaps(mlkem_ct, mlkem_ss, mlkem_ek, data + 64);
    } else {
        if (set == 768)
            rival_mlkem768_decaps(mlkem_ss, mlkem_ct, mlkem_dk);
        else
            rival_mlkem1024_decaps(mlkem_ss, mlkem_ct, mlkem_dk);
    }
}

/* rival_mlkem_keypair, rival_mlkem_encaps, rival_mlkem_decaps: the cases' mlkem-native contenders,
 * prepared and timed as ours are. */
static void rival_mlkem_keypair(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    for (long i = 0; i < calls; i++)
        mlkem_rival(c->length, 0, c->data);
    bench_sink = mlkem_ek[0];
}

static void rival_mlkem_encaps(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    mlkem_rival(c->length, 0, c->data);
    for (long i = 0; i < calls; i++)
        mlkem_rival(c->length, 1, c->data);
    bench_sink = mlkem_ss[0];
}

static void rival_mlkem_decaps(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    mlkem_rival(c->length, 0, c->data);
    mlkem_rival(c->length, 1, c->data);
    for (long i = 0; i < calls; i++)
        mlkem_rival(c->length, 2, c->data);
    bench_sink = mlkem_ss[0];
}

static const char mlkem_native_name[] = "mlkem-native 2.1.0";
static bench_rival mlkem_keypair_rivals[] = { { mlkem_native_name, rival_mlkem_keypair } };
static bench_rival mlkem_encaps_rivals[] = { { mlkem_native_name, rival_mlkem_encaps } };
static bench_rival mlkem_decaps_rivals[] = { { mlkem_native_name, rival_mlkem_decaps } };

/* ---- FFDHE: a public key and a shared secret at ffdhe2048, ffdhe3072 and ffdhe4096 (RFC 7919),
 * with exponents of the group's advised minimum length. OpenSSL 3.0.13's own path for these
 * groups: DH_new_by_nid (the named group, its Montgomery context cached on first use), our
 * exponent installed as the private key (DH_set0_key), then DH_generate_key (which, a private key
 * being set, computes the public key from it) or DH_compute_key_padded (the peer's key checked,
 * the secret left-padded to p's size: what TLS 1.3 takes). */

/* The cases' exponents: two of 50 octets (the largest advised minimum), fixed; a case uses each
 * one's first minimum-length octets. */
static uint8_t ffdhe_input[2 * 50];
static int ffdhe_input_made;

/* ffdhe_data: the cases' data (see bench.h). */
static const uint8_t *ffdhe_data(void)
{
    if (!ffdhe_input_made) {
        for (size_t i = 0; i < sizeof ffdhe_input; i++)
            ffdhe_input[i] = (uint8_t)(0x5C ^ (61 * i));
        ffdhe_input_made = 1;
    }
    return ffdhe_input;
}

/* ffdhe_case: a case's group code, p's size in octets and the exponents' length (the advised
 * minimum), from its length in bits. */
static void ffdhe_case(const bench_case *c, int *group, size_t *size, size_t *length)
{
    *group = c->length == 2048 ? 0x0100 : c->length == 3072 ? 0x0101 : 0x0102;
    *size = c->length / 8;
    *length = c->length == 2048 ? 29 : c->length == 3072 ? 35 : 41;
}

/* The outputs and the peer's key the loops reuse (ffdhe4096's sizes at most). */
static uint8_t ffdhe_out[512], ffdhe_peer[512];

/* bench_ffdhe_public_key, bench_ffdhe_shared: see bench.h. */
void bench_ffdhe_public_key(const bench_build *b, const bench_case *c, long calls)
{
    int group;
    size_t size, length;
    ffdhe_case(c, &group, &size, &length);
    for (long i = 0; i < calls; i++)
        b->api.httpasm_ffdhe_public_key(group, ffdhe_out, c->data, length);
    bench_sink = ffdhe_out[size - 1];
}

void bench_ffdhe_shared(const bench_build *b, const bench_case *c, long calls)
{
    int group;
    size_t size, length;
    ffdhe_case(c, &group, &size, &length);
    b->api.httpasm_ffdhe_public_key(group, ffdhe_peer, c->data + 50, length);
    for (long i = 0; i < calls; i++)
        b->api.httpasm_ffdhe_shared(group, ffdhe_out, c->data, length, ffdhe_peer);
    bench_sink = ffdhe_out[size - 1];
}

/* OpenSSL's DH and BIGNUM functions (the DH_* ones deprecated in 3.0, still exported: TLS's
 * named-group path runs them). */
typedef void *(*openssl_dh_new_by_nid_fn)(int);
typedef int (*openssl_dh_set0_key_fn)(void *, void *, void *);
typedef int (*openssl_dh_generate_key_fn)(void *);
typedef const void *(*openssl_dh_get0_pub_key_fn)(const void *);
typedef int (*openssl_dh_compute_key_padded_fn)(unsigned char *, const void *, void *);
typedef void *(*openssl_bn_bin2bn_fn)(const unsigned char *, int, void *);
typedef int (*openssl_bn_bn2binpad_fn)(const void *, unsigned char *, int);
static openssl_dh_new_by_nid_fn openssl_dh_new_by_nid;
static openssl_dh_set0_key_fn openssl_dh_set0_key;
static openssl_dh_generate_key_fn openssl_dh_generate_key;
static openssl_dh_get0_pub_key_fn openssl_dh_get0_pub_key;
static openssl_dh_compute_key_padded_fn openssl_dh_compute_key_padded;
static openssl_bn_bin2bn_fn openssl_bn_bin2bn;
static openssl_bn_bn2binpad_fn openssl_bn_bn2binpad;
static openssl_free_fn openssl_dh_free, openssl_bn_free;
enum { OPENSSL_NID_FFDHE2048 = 1126 };      /* NID_ffdhe2048; 3072, 4096 follow it */

/* openssl_load_ffdhe: those functions. Returns 0, or -1 (the cases then run without this rival). */
static int openssl_load_ffdhe(void)
{
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL);
    if (crypto == NULL)
        return -1;
    openssl_dh_new_by_nid = (openssl_dh_new_by_nid_fn)dlsym(crypto, "DH_new_by_nid");
    openssl_dh_set0_key = (openssl_dh_set0_key_fn)dlsym(crypto, "DH_set0_key");
    openssl_dh_generate_key = (openssl_dh_generate_key_fn)dlsym(crypto, "DH_generate_key");
    openssl_dh_get0_pub_key = (openssl_dh_get0_pub_key_fn)dlsym(crypto, "DH_get0_pub_key");
    openssl_dh_compute_key_padded = (openssl_dh_compute_key_padded_fn)dlsym(crypto, "DH_compute_key_padded");
    openssl_bn_bin2bn = (openssl_bn_bin2bn_fn)dlsym(crypto, "BN_bin2bn");
    openssl_bn_bn2binpad = (openssl_bn_bn2binpad_fn)dlsym(crypto, "BN_bn2binpad");
    openssl_dh_free = (openssl_free_fn)dlsym(crypto, "DH_free");
    openssl_bn_free = (openssl_free_fn)dlsym(crypto, "BN_free");
    if (!openssl_dh_new_by_nid || !openssl_dh_set0_key || !openssl_dh_generate_key || !openssl_dh_get0_pub_key ||
        !openssl_dh_compute_key_padded || !openssl_bn_bin2bn || !openssl_bn_bn2binpad || !openssl_dh_free || !openssl_bn_free) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks the DH functions\n");
        return -1;
    }
    return 0;
}

/* openssl_ffdhe_key: the case's named group with an exponent installed as its private key
 * (the first exponent, or the second's when `second`), or NULL. */
static void *openssl_ffdhe_key(const bench_case *c, int second)
{
    int group;
    size_t size, length;
    ffdhe_case(c, &group, &size, &length);
    void *dh = openssl_dh_new_by_nid(OPENSSL_NID_FFDHE2048 + (group - 0x0100));
    void *private_key = dh ? openssl_bn_bin2bn(c->data + (second ? 50 : 0), (int)length, NULL) : NULL;
    if (private_key == NULL || openssl_dh_set0_key(dh, NULL, private_key) != 1) {
        openssl_bn_free(private_key);
        openssl_dh_free(dh);
        return NULL;
    }
    return dh;
}

/* openssl_ffdhe_public_key: DH_generate_key on the key (its public key from the installed
 * exponent) and the public key's octets, each call. */
static void openssl_ffdhe_public_key(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *dh = openssl_ffdhe_key(c, 0);
    if (dh != NULL) {
        for (long i = 0; i < calls; i++) {
            openssl_dh_generate_key(dh);
            openssl_bn_bn2binpad(openssl_dh_get0_pub_key(dh), ffdhe_out, (int)(c->length / 8));
        }
    }
    openssl_dh_free(dh);
    bench_sink = ffdhe_out[0];
}

/* openssl_ffdhe_shared: the peer's key from its octets and DH_compute_key_padded, each call (the
 * key with its exponent made before the loop). */
static void openssl_ffdhe_shared(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    void *dh = openssl_ffdhe_key(c, 0), *peer_dh = openssl_ffdhe_key(c, 1);
    if (dh != NULL && peer_dh != NULL && openssl_dh_generate_key(peer_dh) == 1) {
        unsigned char peer_octets[512];
        int size = (int)(c->length / 8);
        openssl_bn_bn2binpad(openssl_dh_get0_pub_key(peer_dh), peer_octets, size);
        for (long i = 0; i < calls; i++) {
            void *peer = openssl_bn_bin2bn(peer_octets, size, NULL);
            openssl_dh_compute_key_padded(ffdhe_out, peer, dh);
            openssl_bn_free(peer);
        }
    }
    openssl_dh_free(peer_dh);
    openssl_dh_free(dh);
    bench_sink = ffdhe_out[0];
}

static bench_rival ffdhe_public_key_rivals[] = { { openssl_name, openssl_ffdhe_public_key } };
static bench_rival ffdhe_shared_rivals[] = { { openssl_name, openssl_ffdhe_shared } };

/* ---- RSA verification ------------------------------------------------------------------------
 * The vectors: a public key, a SHA-256 digest and its valid PKCS#1 v1.5 signature at each size,
 * Project Wycheproof's rsa_signature_{2048,3072,4096}_sha256_test.json, each one's first valid
 * test under e = 65537 (the exponent nearly every key has: 16 squares and one product; FIPS
 * 186-3's records have random exponents of 20-odd bits, half again the work). Hex, decoded on
 * first use. */
static const struct {
    const char *n, *e, *digest, *signature;
} rsa_hex[] = {
    {   /* 2048 bits: tcId 2 */
        "a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a"
        "1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e"
        "254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c0"
        "21d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a19"
        "69816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e77306"
        "6f453d1f5b4c2e9cf7820283f742b9d5",
        "010001",
        "de47c9b27eb8d300dbb5f2c353e632c393262cf06340c4fa7f1b40c4cbd36f90",
        "8a1b220cb2ab415dc760eb7f5bb10335a3cca269d7dbbf7d0962ba79f9cf7b43a5fc09c99a1584f07403473d6c189a83"
        "6897a5b6f8ea9fa22d601e6ba5f7411fe27c638b81b1a22363583a80fce8c7df3e40fb51bd0e60d0a6653f79f3bcb7ec"
        "3e9dc14cfb5b31ab1735bca692d50ac03f979dda92747c6430f8045efa3513ba6e0ce3e9e35570e1c30c8ebe589b4419"
        "2e1344ca83dfa576fc6fdc7bf1cd7cee875b001c8c02ce8d602769e4bd9d241c4857182a0089a8b67644e73eef105c55"
        "0efa47a40874289395ac0c4e02fd4ba98e130a4c2d1b95521c6af4a002ac3bdc6e52122ae4c08cc3da1c896e059acbdd"
        "ec574ac0432f6103dd97273d8803c102",
    },
    {   /* 3072 bits: tcId 2 */
        "c6fe23792566023c265287c5ac6f71541c0994d11d059ee6403986efa21c24b51bd91d8862f9df79a4e328e3e27c83df"
        "260b25a9b43420affc44b51e8d7525b6f29c372a405104732007527a62ed82fac73f4892a80e09682a41a58cd347017f"
        "3be7d801334f92d9321aafd53b51bffabfc752cfccae0b1ee03bdaff9e428cc1c117f1ac96b4fe23f8c23e6381186a66"
        "fd59289339ae55c4bcdadbff84abdaa532240d4e1d28b2d0481dadd3b246557ca8fe18092817730b39e6ee378ffcc85b"
        "19ffdc916a9b991a6b66d4a9c7bab5f5e7a3722101142e7a4108c15d573b15289e07e46eaea07b42c2abcba330e99554"
        "b4656165bb4c0db2b6393a07eca575c51a93c4e15bdb0f747909447e3efe34c67ca8954b530e56a20a1b6d84d45ed1bc"
        "d3aa58ec06f184ee5857aaa819e1cca9a26f4e28d6b977d33916db9896d252d1afa762e287cb0d384cc75bfe53f4e922"
        "d02dd0a481c042e2d306b4b3c189371e575b25e0005a164cf69dd0976e4d5be476806ea6be6084e71ab4f5ac5c1b1203",
        "010001",
        "de47c9b27eb8d300dbb5f2c353e632c393262cf06340c4fa7f1b40c4cbd36f90",
        "631cb4bed6b79dcd3827879f6d64de3ae17e0fdb022be013e733bbfe0031cf204f0508ab87a2e2bbdfaa16cf24acc96b"
        "3fd2e72bc4a224428e515d6f1e0ea6927eba6ed7282a959e5df5e52eb3be9a39cfe139ea2fa45c21eb81b3197eff655b"
        "918f7c5fff6abab33945557a922063f9600a372ae7701db686f7e1fe4a6e804a0f624331fbb59536733bed3710dcacd2"
        "2ec74b1a1386d045372853cac91130703ecafad7f6f42ec1aade5cb865339743c83e882f248b0db0855f487a6d3b5544"
        "2f67773611a11813ff46a58c762b1bd70b5e870c3095507f23758e90b3c84526f47a825f0ae787acfd3ed349ca6786a2"
        "e84ec500c6042a9027a994c328c7a6868e6a81481b294383edda62773fd224af46e782ea3f00468515f6100486d94e81"
        "8afca1bdb81851e62b3bf4f9236f061afafb3e399b93e6f6a295ae200c9bba5ff5aabcac8361c84f2e69aff8a8a21720"
        "b900d52ea4bddcfbaba3a231bb9b0dd48f0a4ef1cdd255b3524ca0633d04907ab672314c5e3173108313ff4a97df3772",
    },
    {   /* 4096 bits: tcId 2 */
        "956353ecb7561945dc5544e4602466078c93f28507701ffd39e2a9813c8ac8740e6ad61c955d484e513b3dcea527e001"
        "a018ee2c207c1806a96763280236cd3c820dff79837c9b709cb4b522d3ddbc9192242259c43be75ea244d37ccfa8a4c7"
        "5024a2cf7cc76e842ea69cc7ca1227405b070047387a5068e4976e4b8ed5f9aadd7b4db024fbb8d7bd8a040d8f6610c1"
        "c6eb1d4b606dfd182235d0360880304d5a750603af0c424b8c8e6dbc12c3697d2d609c97547e774e2e362ea96d1690dc"
        "9432112c535258b3db2c4c32ad510d6c07ad0788357883869efb8b629298724847925cf42b34386be700f02903db5852"
        "276bee2370941f397bdc3905e30964a0b5e73602703340960c3ed6078263b611f197955fecce4b9a32e43cd1d2e5e87c"
        "4ceb65edc8853a7ee31d28e16e5adffb8ac7b760fbfc63d5f174f4d0936461dbb12c964a6b6d6cee752e5fca1ab4a9fd"
        "238dd3e8860a1d763d2019f9e7b99ed7666d4e038710f90e0093bc566987d6c0092f571376e705b342d066c54e6e2578"
        "927b92c1f0928de44e9a6e1f49b907c6aa4f605ec9c398d55df81c67373b03cc8110162fb417f96fd321048647dfcbb3"
        "92455115cd912ea83351853e6a185284648842adcbd25e67174a3b93b8a64ce2ce9de0e8577b8b662ce32e2565782665"
        "dd38e5bb5fcc4fe12e4320dab7773b545a09c6d39d9dbad459f21f3e624ee6ed",
        "010001",
        "de47c9b27eb8d300dbb5f2c353e632c393262cf06340c4fa7f1b40c4cbd36f90",
        "46a6c9cd78e38d5567795dbea71872ac16da06725975cee7d8839d2de665ec3b8411277f3e026fd2f9b836d788b48539"
        "755858bc8be0804147b59c09354b372713145e5a000ac15744ccd2db5795727e2f4d5f67bcab5e7cb1290824963ae885"
        "28aba0e6785989c8adb86084d26dd1faea3ae2a6175739fe978b576eff673832e513419806d206e0984d1ef0e1c8d898"
        "1084ee2ee569806b003fb7f08e775998eba1771f1efa070c00a769363c6101d5c5fc6140f102469574cd09746130ed80"
        "d14eabcd0a0418a752d5595b5f40ee0fb05f5f9860e600d75fbdd53461f5ea18be5bd807281f9e8fd6cf7eb31985206c"
        "9a5033cdea631512bffdd977fee5e692b3153a2ce9c7708a9c7d665d84762740cc9ea374bd32c18c2d76320e4893a2fa"
        "c374ca7122e01e08011c351bd33725a6adad96becd44e4ec1032fbfb0c8dcf13cae9556eaf419211d0149c574b8d12ff"
        "e5bc59468c7c549283be541697258af847e52a9aa8063557dfa40404adbaa95e38ad28eba053aec3c123e98ab1b947bb"
        "774841e9040dd5409068a2c8a84c530fc4273897ed845d76dbafbf45af1a8fd2767234fac1e852453d8b7eede02af228"
        "d8b5821238a50a321490dab74d687a3400c34f215b85823424c9d966b516cccac38fc7f08769f47d66c57b9b75ea67be"
        "82508a513946bcbc809436efc4ee85f139b143c5bc15ff69ad1f3667c3f69bcf",
    },
};

static bench_rsa_vector rsa_vectors[3];

/* rsa_hex_decode: the octets of a hex string into out (room for `room`); returns how many, or 0
 * when the string is odd, too long or not hex. */
static size_t rsa_hex_decode(const char *hex, uint8_t *out, size_t room)
{
    size_t length = strlen(hex);
    if (length % 2 != 0 || length / 2 > room)
        return 0;
    for (size_t i = 0; i < length / 2; i++) {
        unsigned value;
        if (sscanf(hex + 2 * i, "%2x", &value) != 1)
            return 0;
        out[i] = (uint8_t)value;
    }
    return length / 2;
}

/* bench_rsa_input: see bench.h. */
const bench_rsa_vector *bench_rsa_input(size_t which)
{
    if (which >= sizeof rsa_vectors / sizeof rsa_vectors[0])
        return NULL;
    bench_rsa_vector *v = &rsa_vectors[which];
    if (v->octets == 0) {
        v->octets = rsa_hex_decode(rsa_hex[which].n, v->n, sizeof v->n);
        v->e_length = rsa_hex_decode(rsa_hex[which].e, v->e, sizeof v->e);
        if (v->octets == 0 || v->e_length == 0 || rsa_hex_decode(rsa_hex[which].digest, v->digest, sizeof v->digest) != 32
            || rsa_hex_decode(rsa_hex[which].signature, v->signature, sizeof v->signature) != v->octets) {
            fprintf(stderr, "bench: the RSA vector %zu does not decode\n", which);
            exit(2);
        }
    }
    return v;
}

/* bench_rsa_verify: see bench.h. */
void bench_rsa_verify(const bench_build *b, const bench_case *c, long calls)
{
    const bench_rsa_vector *v = (const bench_rsa_vector *)c->data;
    httpasm_rsa_public_key key;
    b->api.httpasm_rsa_public_key_init(&key, v->n, v->octets, v->e, v->e_length);
    int sum = 0;
    for (long i = 0; i < calls; i++)
        sum += b->api.httpasm_rsa_verify_pkcs1(&key, HTTPASM_HASH_SHA256, v->digest, v->signature, v->octets);
    bench_sink = (uint8_t)sum;
}

/* bench_rsa_init_verify: see bench.h. */
void bench_rsa_init_verify(const bench_build *b, const bench_case *c, long calls)
{
    const bench_rsa_vector *v = (const bench_rsa_vector *)c->data;
    httpasm_rsa_public_key key;
    int sum = 0;
    for (long i = 0; i < calls; i++) {
        b->api.httpasm_rsa_public_key_init(&key, v->n, v->octets, v->e, v->e_length);
        sum += b->api.httpasm_rsa_verify_pkcs1(&key, HTTPASM_HASH_SHA256, v->digest, v->signature, v->octets);
    }
    bench_sink = (uint8_t)sum;
}

/* bench_rsa_init: see bench.h. */
void bench_rsa_init(const bench_build *b, const bench_case *c, long calls)
{
    const bench_rsa_vector *v = (const bench_rsa_vector *)c->data;
    httpasm_rsa_public_key key;
    int sum = 0;
    for (long i = 0; i < calls; i++)
        sum += b->api.httpasm_rsa_public_key_init(&key, v->n, v->octets, v->e, v->e_length);
    bench_sink = (uint8_t)(sum + (int)key.opaque[0]);
}

/* ---- RSA signing -----------------------------------------------------------------------------
 * The keys: Project Wycheproof's rsa_pkcs1_{2048,3072,4096}_sig_gen_test.json, at each size the
 * first SHA-256 group with e = 65537 (its PKCS#8 key's numbers: n, e, d, p, q, dp, dq, q^-1; the
 * 2048-bit n is the verification vector's) and the digest of its first valid test's message,
 * whose PKCS#1 v1.5 signature the vector holds (checked when the hex was made). Hex, decoded on
 * first use. */
static const struct {
    const char *n, *e, *d, *p, *q, *dp, *dq, *qinv, *digest;
} rsa_private_hex[] = {
    {   /* 2048 bits: tcId 81, the 0-octet message's digest */
        "a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a"
        "1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e"
        "254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c0"
        "21d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a19"
        "69816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e77306"
        "6f453d1f5b4c2e9cf7820283f742b9d5",
        "010001",
        "7627eef3567b2a27268e52053ecd31c3a7172ccb9ddcee819b306a5b3c66b7573ca4fa88efc6f3c4a00bfa0ae7139f64"
        "543a4dac3d05823f6ff477cfcec84fe2ac7a68b17204b390232e110310c4e899c4e7c10967db4acde042dbbf19dbe00b"
        "4b4741de1020aaaaffb5054c797c9f136f7d93ac3fc8caff6654242d7821ebee517bf537f44366a0fdd45ae05b9909c2"
        "e6cc1ed9281eff4399f76c96b96233ec29ae0bbf0d752b234fc197389f51050aa1acd01c074c3ac8fbdb9ea8b651a959"
        "95e8db4ad5c43b6c8673e5a126e7ee94b8dff4c5afc01259bc8da76950bae6f8bae715f50985b0d6f66d04c6fef3b700"
        "720eecdcdf171bb7b1ecbe7289c467c1",
        "dc431050f782e894fb5248247d98cb7d58b8d1e24f3b55d041c56e4de086b0d5bb028bda42eeb5d234d5681e5809d415"
        "e6a289ad4cfbf78f978f6c35814f50eebff1c5b80a69f788e81e6bab5ddaa78369d659d143ec6f17e79813a575cfad9c"
        "569156b90113e2e9110ad9e7b48a1c9348a6e653321191290ea36cfb3a5b18f1",
        "bd1a81e7977f9898122273ae3222b598ea5fb19eb4eabc38308a5e32196603b2e500ffb79f5b886816611debc472fac4"
        "5544070beb057c941378a6868af3b7a03d3f9880ec47d5e089b94fbde542aba9ae8d72c57088d7abf5b131f39098f7bc"
        "160f90536abc9492fd4e06f3ed7299d4b97bb03677207d95669f140cfbc20f25",
        "a94b528b28f291599121d91952ffd1c7f21d7c1479d99d478885fb161870ee1218bf08472612dbe5497e8d9c650688e0"
        "9c786961ae3e2c354dc48ae34514759c4c23c4588488961dc06b414e61c0e1e7fbbd2923d31532fe289f96da220711e5"
        "8c14019808e00414276933bb07e4efb9b4a9b37656917205209f33f09515d7c1",
        "3af0e72a933aef09ff2503df78bafed531c02ff1a2bc437c540cdcbd4ad35435cf511763596543480629b114ca7f780f"
        "f7efa32ea0cb6e000d6d9ea1f2ef71fd9cf9948422a165557e37e755edfe70d90b920502eb478bc98a63f788ce3a0f85"
        "6d6ede7251a383bfa8fa480a81a925af7b3cc538c4bab8c9f7597ffb68011d8d",
        "2640fbfbcfefb163ee7a87b6483a66ee41f956d90fa8a7939bfc042ee0924b1b7993d0445f758d51933e85179c0320b0"
        "c968b48a91c38b5be923e1097c0c562f88d42294b6a2759bafa5428a74f1270874e45f6fcc60f21602de5eccd143cf31"
        "241f5921b5ad3983fb54ef17be3b285367e50c999c67247b552fe4bfce945f7b",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    {   /* 3072 bits: tcId 105, the 0-octet message's digest */
        "c6fe23792566023c265287c5ac6f71541c0994d11d059ee6403986efa21c24b51bd91d8862f9df79a4e328e3e27c83df"
        "260b25a9b43420affc44b51e8d7525b6f29c372a405104732007527a62ed82fac73f4892a80e09682a41a58cd347017f"
        "3be7d801334f92d9321aafd53b51bffabfc752cfccae0b1ee03bdaff9e428cc1c117f1ac96b4fe23f8c23e6381186a66"
        "fd59289339ae55c4bcdadbff84abdaa532240d4e1d28b2d0481dadd3b246557ca8fe18092817730b39e6ee378ffcc85b"
        "19ffdc916a9b991a6b66d4a9c7bab5f5e7a3722101142e7a4108c15d573b15289e07e46eaea07b42c2abcba330e99554"
        "b4656165bb4c0db2b6393a07eca575c51a93c4e15bdb0f747909447e3efe34c67ca8954b530e56a20a1b6d84d45ed1bc"
        "d3aa58ec06f184ee5857aaa819e1cca9a26f4e28d6b977d33916db9896d252d1afa762e287cb0d384cc75bfe53f4e922"
        "d02dd0a481c042e2d306b4b3c189371e575b25e0005a164cf69dd0976e4d5be476806ea6be6084e71ab4f5ac5c1b1203",
        "010001",
        "72ac6bb6d9a5726e454b5430c71125c6e9ad5fd42e1c5a18a8343e9d83d72214386b2308c0b8ec5ec6759dcfcd6a21f8"
        "8b8ceaf46403923eb86ac3d14a8592e95de0462e14085c3f17db005dc4fac87b4a2d1ede5cf851d5745c8651a4438c0a"
        "4d746ad72e419207964728c301bf379a01c094e9693376f721137d3dc76ee47c9790fbd590b7d6a8d626e21b277ef17a"
        "4e4f7e0171c1146e1ec324fa97f30d3a1bae08f8d5f6e92cfc121665239c429167359e9650434b29d2015190356adfee"
        "12f25b341b08f12b7fec6379598af7d5cc24fe7f00de1d47133ce3ad8b6be1c9a854e33fb952e164ac6dd2a9052186ee"
        "144ee7dd986a8f03891d0da21ed78516dcdc2ac89cdddc8b544731d66f9d89bf17a50c6d987a598b02c938dc36521b88"
        "1ea994e4c8fb2ba8fd001f73335d4dd1bdbe177d3093cf3883657c9ff944e8f5c9cde548b7c1b0741929b0d74977ecda"
        "694d940aefd9d2fc75323e0b3a114b99feaf3e2518f5158d1fd9d953aa20af158e67d27e2ce2f18d97fd02f369981979",
        "f5eca16e0e83696b0ed9ac8a812545daba55f20a964c4e6343604a7f2be2860fce9fa16a1cc92120939deb88dff68550"
        "383ead851fac07ad1b2e8a9b2bb69525d96ceabb7ee83ce50f08d649107f449a14521a6893f3f3c5c5a703b2fc28bfcf"
        "e261a4f7f450558080deaeaab651c7a9ae586c1e7f5c52cda93e40aac908e4e3357984fc116af9cbe9539bc7a8d3b351"
        "a73ea5c2413d1da2e0b448b454670aca89ffe73b1401e9b8554fc3f23d6c904623251a1d29962ca9b26d973345bc4c5f",
        "cf25446f59cf512919ddbfcfa2d9670495ad92b6f295d61032057f9da6dbefc4510a623c2b47a5220082a3bc42af1a14"
        "4f98c9ee4fdae41be0ec501ccc94b2b0640191099b355611160deb327e8ace018b898025ef470e4373ec1d97f669e298"
        "e1d845c6553c0a546ccb168d5b510dbe6018fd4ed9a3545f9bdb81968f4a6d7c790e5c34729a8efb496086fa1300249a"
        "b8b28f38951d7bee1c127ac3c4d0bd596edee1e9d17781dbb8227d7b5d76ce8b8bce03c5d339b9757981610848c55cdd",
        "6357a59679d26801514c6940c20eb67b370e84e9f5f0f9316c0437d3cb7c843f5a6e6d9c19e8bdb3152e93f904cfe6e6"
        "92f1eed27a0ada46f95601b3d122be793dad9bdd05d4f6d469105ecfc11448381dc154ddadf6bc20c649435b483585d6"
        "8a527b7b967be52e35e0be9a437021c1cfa5f4771567cc233c1ce3ae99eb37daf8bd10156b4bd580a3ce9c7d391bdbb2"
        "3e67363a947405c6c812cbd3dccc8b356a2dafd0d3b23a21b684b458e4ab3854bcd9be04cdc9d65ceeb10a8531c470ed",
        "0004dadabfc15b1a8bdc0f566f876191088a7986f6c2b8c04ba0e0801d31cbf5d2a4139a39cec9df14ecee22e846a7d3"
        "f4a5e8eed2a70c7a4c2cf95ce74fe42c4bf60c135a264919bb4cc906ba283d1896f0ae48529b490f0c85ab03068cbfee"
        "8fa6bb6ae73b182d25cd66f5205b038b4eeaf1aafe2e1ba5de97c88d40fa1ac47626602fc90ae694734f44f3e4e88d18"
        "4e8805a755ac2904be8fe9def6b7a62cc9ebcf4d7c2d6c9f9e86b2483e9bf22ce51861bbb4e73e731a4dbeba87772d29",
        "214a1f73130e48b336fe01b950885ecdb3443d93e7e8ca62fb0da96bd423759d8be552c8be44f139fbee6ec24b75fbf0"
        "744fac4daabf5488fe6c3600d9b8e9a922481fc74a7a3d622662db8c85318de48ee8b716f19429fb594990da705ebdf7"
        "ef6613dd6bf885c16ad65e9fe6c280386bee976c25dbaff8fbf69baed9510be5eded3f90e0ba4a97e5c81a2189f11467"
        "0745ab95edda215bd05fdc78929fa0cfe8b01c83f2aec93e3ad1a334fd85aa8794eacf955ae5dacd45b268741fca195c",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    {   /* 4096 bits: tcId 129, the 0-octet message's digest */
        "956353ecb7561945dc5544e4602466078c93f28507701ffd39e2a9813c8ac8740e6ad61c955d484e513b3dcea527e001"
        "a018ee2c207c1806a96763280236cd3c820dff79837c9b709cb4b522d3ddbc9192242259c43be75ea244d37ccfa8a4c7"
        "5024a2cf7cc76e842ea69cc7ca1227405b070047387a5068e4976e4b8ed5f9aadd7b4db024fbb8d7bd8a040d8f6610c1"
        "c6eb1d4b606dfd182235d0360880304d5a750603af0c424b8c8e6dbc12c3697d2d609c97547e774e2e362ea96d1690dc"
        "9432112c535258b3db2c4c32ad510d6c07ad0788357883869efb8b629298724847925cf42b34386be700f02903db5852"
        "276bee2370941f397bdc3905e30964a0b5e73602703340960c3ed6078263b611f197955fecce4b9a32e43cd1d2e5e87c"
        "4ceb65edc8853a7ee31d28e16e5adffb8ac7b760fbfc63d5f174f4d0936461dbb12c964a6b6d6cee752e5fca1ab4a9fd"
        "238dd3e8860a1d763d2019f9e7b99ed7666d4e038710f90e0093bc566987d6c0092f571376e705b342d066c54e6e2578"
        "927b92c1f0928de44e9a6e1f49b907c6aa4f605ec9c398d55df81c67373b03cc8110162fb417f96fd321048647dfcbb3"
        "92455115cd912ea83351853e6a185284648842adcbd25e67174a3b93b8a64ce2ce9de0e8577b8b662ce32e2565782665"
        "dd38e5bb5fcc4fe12e4320dab7773b545a09c6d39d9dbad459f21f3e624ee6ed",
        "010001",
        "097a59d2c4f70377793937bbbd95d19b5d01edfb1eb3b073e27e4cfed416820d4af4e04cc3f53d272ae43551ad0cd09b"
        "89cacb21a595f9f8423b3b0148d2ad46cf818fd9e7cbba18f4f84a1dc18f69ed5a764c6fa191a3664fa94a39bafb1a29"
        "431e6fedf61eb9164dd7684f0cb506248121fa948a32c8733f3d9453dae61c8708b2500582f32d91128775265f18bcab"
        "6eb170145e33dc40f1bab451194cf8c38f9fa91806bd225fa4b54ca50813b9d7a54f61e0000e5e0769cb2a3eb99b1ae9"
        "c3c5416dac83a6f91248c734d7e63291ce12de4d780703614128f878f29015801c7a5ec7670e531e1573ebc8ce63d640"
        "b01b9aea48b43d1eea8ad85b55423d4e142bcf73315f3e9e978b65f0556246066596013fad97b83ba552140c6957ef44"
        "3ccec4051b2a8c9cd9f25c4cf6bdc2e904f46063e319643283462a4047d49c38bdbb0ee3d87980ec08410d5d2dee8e53"
        "49958e4178aba065a55d79d89080570fd4af5678b1573e42f2e0f863b31bb4e19ba232c02ae5b8f948d1ce8145c4968d"
        "24b56ac930b4f67047257f3c0b86bce7a77b8d0d87124c4a4141409ac11377fb9fc805d60012386becc2ba8478e663be"
        "cc3d73239ce3036c2d2fc9e6e2e370c2c78053ee1bcef7a87872ef92b784638b84713a5d78ba8c3a868e3466f2275b25"
        "2e19766d2104ec60537bc1589b1558b76643751f6a60fd8a5102b6c788e0f049",
        "c3c677495c2bd56619e44e26140d2ede0037409b81f3a5b3886a0904eb486140f43b8626af13d14a33918eb72b786b3c"
        "9114f39017871528953c09104e1fd2d36b725388f54ffea30373077895a6934ab174e55ca6a12c21923a7b775b5ffaff"
        "bd813f9fb752805b016a5735b883c639fedd55ba2e233a6dc1673063d8487390d1676123544d3def177a91caeef98b13"
        "f38860474e44993d4c6060926d878a2059855d0de1c794ac8dbdad655fbbad20f152f15c73b95ac544cbb87b8bec8fd3"
        "c007ad09d76ae22a5e993302aa72f11deb265a7f28b88976af5d0c912d97b7284b1783c5bc91a6dcb7a9b97fe5371396"
        "5857742b7e4032dc5141acd4afd4771f",
        "c357cf685f9b8d4e59e96686f7b8752f0a982efbe6658e6bcdb615d921f5e7056882825347455782d7bc78d637e17e0e"
        "6810c2136ad81b16cc1c81750785924616f2bdf5964b26c7fc50fa98fb67b746b50812705b379f5deadbd11dcd2fec7b"
        "724d042aef25cea2eb37f85b7554d7ad49fe5f47737ff436bded418507f2f175c695e324fbb11beb0544a7a7cb3f0792"
        "4e291b5c8ddaa6a7dbb07e23bce1960cb52b9000d3a7aab1f58e3c750b6d978adf3d085ae7693b7e6a46cf6dbb6d2ad9"
        "81f4bca5d15e0962c39066a9fc27985b9ba1f51132355792796a5dd847400804f98671ee4899050bdc2e7872ce6fb2b7"
        "8b1050436d882425ee0745546a6a1c73",
        "a6bbb5460638d2b2f5242aa6657760cdf3731b1415d5f2ee77248f6fe00e31bdc70396da054ba47844791809c9fcf19f"
        "90943e671e928e23950d9f4e82aab9bc138b37b7b1ed2219a54b67367c8574762db237d0f39cda5ff110dbac286712f6"
        "9167ad4f122b3263cf4dc8de58b9e9ade4f08e1d5543ed74223e06c9521f4a45310291892c37e8a262e5a19b2a71decf"
        "ec1dde997c00125e5158d7867dbfec9466899d59c04b60c4a0a6c5314c1a2375a5f194dbbf37422635d426d719b12c41"
        "140fb5806735814ec268493861002977e8982e8493a2ae78251be32315a85b75f6961d44dfb7505c34135987a2288907"
        "074fdc015ab1c45f3cd8e91fee6bcdd3",
        "178cd58f72bf5118da141e6d351e42da69ff90e2839348c94c62a05dae0f744b9d9ee6515ded4930980bbbd1afa8fac6"
        "87db455a8bee03ce0acb80fbf7ed2d864fabf224d27abaf12f45200123860c7d74c3c55d5051f35fa239e00b24ba9b5b"
        "029bb05df0b8f12189141558095c32284d1c62a63d917682c700fc7e2a482abe1533eacf819c878e1cf37af6eab4ed97"
        "c0de89d2edb327966310f31421e85c6ba9c7d7b391d0cbee6a793c66abfb09630fa8cf020e960c3b205aeb15029c95a6"
        "e558f90950a572a23a8b852507264ae2f86f5d1936a161ae61fee5d3763b8cfbf48d35dd1159895735b350881ec52e99"
        "9c255a57d6b3ac0ffa935bd36284ea6b",
        "484ad86e79415ea3c78af5f6c807cc99decfb14ca1e80c8e6a1ef00ee582d3d180774236a54ec9dc8dbcca51f4da4379"
        "cf634f3a07cea4b7748d7b5d94cacd4d474111f92d19f3ab5eb4def8dba57b990844efd28d85344666e283f5d5fb0e6e"
        "8d96f07411c882bf280446e49b3b9b15218fc24da34ce8f01e02735920ef48a343b4de11f99b26547a251afa7aaa6908"
        "3c421e2447b1a989d50712bf8fc35882b63517c7c39843cf67b92645b68c6d8f90331600142e6cb97032a5af6ef7c20f"
        "87630c6b25dddeb57f2cc0cd8c8a0661b5f40ed6632989f5d40f33bbfd9be09374483606c2cd7ed8b5fcb8bf3df1f936"
        "8a13922b1240c0d25792505b857d3e8d",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
};

static bench_rsa_private_vector rsa_private_vectors[3];

/* bench_rsa_private_input: see bench.h. */
const bench_rsa_private_vector *bench_rsa_private_input(size_t which)
{
    if (which >= sizeof rsa_private_vectors / sizeof rsa_private_vectors[0])
        return NULL;
    bench_rsa_private_vector *v = &rsa_private_vectors[which];
    if (v->octets == 0) {
        v->octets = rsa_hex_decode(rsa_private_hex[which].n, v->n, sizeof v->n);
        v->half = rsa_hex_decode(rsa_private_hex[which].p, v->p, sizeof v->p);
        /* every number at its own size: e three octets, d n's, the CRT numbers the primes' */
        if (v->octets == 0 || v->half == 0 || rsa_hex_decode(rsa_private_hex[which].e, v->e, sizeof v->e) != sizeof v->e
            || rsa_hex_decode(rsa_private_hex[which].d, v->d, sizeof v->d) != v->octets
            || rsa_hex_decode(rsa_private_hex[which].q, v->q, sizeof v->q) != v->half
            || rsa_hex_decode(rsa_private_hex[which].dp, v->dp, sizeof v->dp) != v->half
            || rsa_hex_decode(rsa_private_hex[which].dq, v->dq, sizeof v->dq) != v->half
            || rsa_hex_decode(rsa_private_hex[which].qinv, v->qinv, sizeof v->qinv) != v->half
            || rsa_hex_decode(rsa_private_hex[which].digest, v->digest, sizeof v->digest) != 32) {
            fprintf(stderr, "bench: the RSA signing key %zu does not decode\n", which);
            exit(2);
        }
    }
    return v;
}

/* rsa_private_numbers: the vector's numbers as httpasm_rsa_private_key_init takes them (pointers
 * into the vector, which outlives every call). */
static httpasm_rsa_private_numbers rsa_private_numbers(const bench_rsa_private_vector *v)
{
    httpasm_rsa_private_numbers numbers = {
        v->n, v->octets, v->e, sizeof v->e, v->p, v->half, v->q, v->half, v->dp, v->half, v->dq, v->half, v->qinv, v->half,
    };
    return numbers;
}

/* rsa_private_key: the vector's key prepared by build b into key; a key the build refuses ends
 * the process (a case that signed with a zeroed key would time a refusal). */
static void rsa_private_key(const bench_build *b, const bench_rsa_private_vector *v, httpasm_rsa_private_key *key)
{
    httpasm_rsa_private_numbers numbers = rsa_private_numbers(v);
    if (b->api.httpasm_rsa_private_key_init(key, &numbers) != 0) {
        fprintf(stderr, "bench: build %s refuses the %zu-bit RSA signing key\n", b->name, v->octets * 8);
        exit(2);
    }
}

/* bench_rsa_sign_pkcs1: see bench.h. */
void bench_rsa_sign_pkcs1(const bench_build *b, const bench_case *c, long calls)
{
    const bench_rsa_private_vector *v = (const bench_rsa_private_vector *)c->data;
    static httpasm_rsa_private_key key;     /* (6.7 KB: static, off the stack the signing uses) */
    uint8_t signature[512];
    rsa_private_key(b, v, &key);
    int sum = 0;
    for (long i = 0; i < calls; i++)
        sum += b->api.httpasm_rsa_sign_pkcs1(&key, HTTPASM_HASH_SHA256, v->digest, signature, v->octets);
    bench_sink = (uint8_t)(sum + signature[0]);
}

/* bench_rsa_sign_pss: see bench.h. */
void bench_rsa_sign_pss(const bench_build *b, const bench_case *c, long calls)
{
    const bench_rsa_private_vector *v = (const bench_rsa_private_vector *)c->data;
    static httpasm_rsa_private_key key;
    uint8_t signature[512], salt[32];
    rsa_private_key(b, v, &key);
    int sum = 0;
    for (long i = 0; i < calls; i++) {
        sum += b->api.httpasm_random(salt, sizeof salt);
        sum += b->api.httpasm_rsa_sign_pss(&key, HTTPASM_HASH_SHA256, v->digest, salt, sizeof salt, signature, v->octets);
    }
    bench_sink = (uint8_t)(sum + signature[0]);
}

/* bench_rsa_private_init: see bench.h. */
void bench_rsa_private_init(const bench_build *b, const bench_case *c, long calls)
{
    const bench_rsa_private_vector *v = (const bench_rsa_private_vector *)c->data;
    static httpasm_rsa_private_key key;
    httpasm_rsa_private_numbers numbers = rsa_private_numbers(v);
    int sum = 0;
    for (long i = 0; i < calls; i++)
        sum += b->api.httpasm_rsa_private_key_init(&key, &numbers);
    bench_sink = (uint8_t)(sum + (int)key.opaque[0]);
}

typedef void *(*openssl_bld_new_fn)(void);
typedef int (*openssl_bld_push_bn_fn)(void *bld, const char *key, const void *bn);
typedef void *(*openssl_bld_to_param_fn)(void *bld);
typedef void *(*openssl_bin2bn_fn)(const unsigned char *s, int length, void *ret);
typedef void *(*openssl_ctx_new_from_name_fn)(void *libctx, const char *name, const char *propquery);
typedef int (*openssl_fromdata_fn)(void *ctx, void **pkey, int selection, void *params);
typedef int (*openssl_set_md_fn)(void *ctx, const void *md);
static openssl_bld_new_fn openssl_bld_new;
static openssl_bld_push_bn_fn openssl_bld_push_bn;
static openssl_bld_to_param_fn openssl_bld_to_param;
static openssl_bin2bn_fn openssl_bin2bn;
static openssl_ctx_new_from_name_fn openssl_ctx_new_from_name;
static openssl_pkey_ctx_fn openssl_fromdata_init;
static openssl_fromdata_fn openssl_fromdata;
static openssl_set_md_fn openssl_set_signature_md;
static const void *openssl_rsa_md;        /* EVP_sha256() */
static void *rsa_params[3];
static void *rsa_fromdata_ctx;

enum { OPENSSL_PUBLIC_KEY = 0x86 };         /* EVP_PKEY_PUBLIC_KEY: all parameters + the public key */

/* openssl_load_rsa: OpenSSL's functions for an RSA public key from n and e (OSSL_PARAM_BLD, BN,
 * EVP_PKEY_fromdata) and for a verification with SHA-256 (the P-256 set loaded first: it holds
 * the verify functions), then each vector's parameters, made once. Returns 0, or -1 (the cases
 * then run without this rival). */
static int openssl_load_rsa(void)
{
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL);
    if (crypto == NULL || openssl_load_p256() != 0)
        return -1;
    openssl_bld_new = (openssl_bld_new_fn)dlsym(crypto, "OSSL_PARAM_BLD_new");
    openssl_bld_push_bn = (openssl_bld_push_bn_fn)dlsym(crypto, "OSSL_PARAM_BLD_push_BN");
    openssl_bld_to_param = (openssl_bld_to_param_fn)dlsym(crypto, "OSSL_PARAM_BLD_to_param");
    openssl_bin2bn = (openssl_bin2bn_fn)dlsym(crypto, "BN_bin2bn");
    openssl_ctx_new_from_name = (openssl_ctx_new_from_name_fn)dlsym(crypto, "EVP_PKEY_CTX_new_from_name");
    openssl_fromdata_init = (openssl_pkey_ctx_fn)dlsym(crypto, "EVP_PKEY_fromdata_init");
    openssl_fromdata = (openssl_fromdata_fn)dlsym(crypto, "EVP_PKEY_fromdata");
    openssl_set_signature_md = (openssl_set_md_fn)dlsym(crypto, "EVP_PKEY_CTX_set_signature_md");
    openssl_md_fn sha256 = (openssl_md_fn)dlsym(crypto, "EVP_sha256");
    if (!openssl_bld_new || !openssl_bld_push_bn || !openssl_bld_to_param || !openssl_bin2bn || !openssl_ctx_new_from_name
        || !openssl_fromdata_init || !openssl_fromdata || !openssl_set_signature_md || !sha256) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks the RSA key functions\n");
        return -1;
    }
    openssl_rsa_md = sha256();
    rsa_fromdata_ctx = openssl_ctx_new_from_name(NULL, "RSA", NULL);
    for (size_t i = 0; i < sizeof rsa_params / sizeof rsa_params[0]; i++) {
        const bench_rsa_vector *v = bench_rsa_input(i);
        void *bld = openssl_bld_new();
        void *n = openssl_bin2bn(v->n, (int)v->octets, NULL), *e = openssl_bin2bn(v->e, (int)v->e_length, NULL);
        if (bld == NULL || n == NULL || e == NULL || openssl_bld_push_bn(bld, "n", n) != 1 || openssl_bld_push_bn(bld, "e", e) != 1
            || (rsa_params[i] = openssl_bld_to_param(bld)) == NULL || rsa_fromdata_ctx == NULL) {
            fprintf(stderr, "bench: rivals: OpenSSL refused an RSA vector's parameters\n");
            return -1;
        }
        /* (the builder and the numbers stay: a few hundred octets, once per process) */
    }
    return 0;
}

/* openssl_rsa_key: an EVP_PKEY of a vector's n and e through EVP_PKEY_fromdata (OpenSSL's way to
 * a key from its numbers, as a TLS stack gets one from a certificate's), or NULL. */
static void *openssl_rsa_key(const bench_case *c)
{
    size_t which = (size_t)((const bench_rsa_vector *)c->data - rsa_vectors);
    void *key = NULL;
    if (openssl_fromdata_init(rsa_fromdata_ctx) != 1 || openssl_fromdata(rsa_fromdata_ctx, &key, OPENSSL_PUBLIC_KEY, rsa_params[which]) != 1)
        return NULL;
    return key;
}

/* openssl_rsa_verify: EVP_PKEY_verify of the vector's signature, the key and the context made once
 * (OpenSSL caches the key's Montgomery constants on its first verification). */
static void openssl_rsa_verify(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    const bench_rsa_vector *v = (const bench_rsa_vector *)c->data;
    void *key = openssl_rsa_key(c);
    void *ctx = key ? openssl_pkey_ctx_new(key, NULL) : NULL;
    int sum = 0;
    if (ctx != NULL && openssl_verify_init(ctx) == 1 && openssl_set_signature_md(ctx, openssl_rsa_md) == 1) {
        for (long i = 0; i < calls; i++)
            sum += openssl_verify(ctx, v->signature, v->octets, v->digest, 32);
    }
    openssl_pkey_ctx_free(ctx);
    openssl_pkey_free(key);
    bench_sink = (uint8_t)sum;
}

/* openssl_rsa_fresh: OpenSSL's verification with the key made from n and e each call (fromdata, a
 * context, the digest set, verify, both freed): its work per certificate. */
static void openssl_rsa_fresh(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    const bench_rsa_vector *v = (const bench_rsa_vector *)c->data;
    int sum = 0;
    for (long i = 0; i < calls; i++) {
        void *key = openssl_rsa_key(c);
        void *ctx = key ? openssl_pkey_ctx_new(key, NULL) : NULL;
        if (ctx != NULL && openssl_verify_init(ctx) == 1 && openssl_set_signature_md(ctx, openssl_rsa_md) == 1)
            sum += openssl_verify(ctx, v->signature, v->octets, v->digest, 32);
        openssl_pkey_ctx_free(ctx);
        openssl_pkey_free(key);
    }
    bench_sink = (uint8_t)sum;
}

static bench_rival rsa_verify_rivals[] = { { openssl_name, openssl_rsa_verify } };
static bench_rival rsa_init_verify_rivals[] = { { openssl_name, openssl_rsa_fresh } };

typedef int (*openssl_set_int_fn)(void *ctx, int value);
static openssl_set_int_fn openssl_set_rsa_padding, openssl_set_rsa_pss_saltlen;
static void *rsa_private_params[3];

enum {
    OPENSSL_KEYPAIR = 0x87,                 /* EVP_PKEY_KEYPAIR: all parameters + both keys */
    OPENSSL_PKCS1_PSS_PADDING = 6,          /* RSA_PKCS1_PSS_PADDING */
};

/* openssl_load_rsa_sign: OpenSSL's functions for RSA signing (the padding and the PSS salt's
 * length; the rest come with openssl_load_rsa, which must have succeeded first) and each signing
 * key's parameters (n, e, d and the CRT's five numbers, OpenSSL's names), made once. Returns 0, or
 * -1 (the signing cases then run without this rival). */
static int openssl_load_rsa_sign(void)
{
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL);
    if (crypto == NULL)
        return -1;
    openssl_set_rsa_padding = (openssl_set_int_fn)dlsym(crypto, "EVP_PKEY_CTX_set_rsa_padding");
    openssl_set_rsa_pss_saltlen = (openssl_set_int_fn)dlsym(crypto, "EVP_PKEY_CTX_set_rsa_pss_saltlen");
    if (!openssl_set_rsa_padding || !openssl_set_rsa_pss_saltlen) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks the RSA padding functions\n");
        return -1;
    }
    for (size_t i = 0; i < sizeof rsa_private_params / sizeof rsa_private_params[0]; i++) {
        const bench_rsa_private_vector *v = bench_rsa_private_input(i);
        const struct {
            const char *name;
            const uint8_t *octets;
            size_t length;
        } numbers[] = {
            { "n", v->n, v->octets },           { "e", v->e, sizeof v->e },           { "d", v->d, v->octets },
            { "rsa-factor1", v->p, v->half },   { "rsa-factor2", v->q, v->half },     { "rsa-exponent1", v->dp, v->half },
            { "rsa-exponent2", v->dq, v->half }, { "rsa-coefficient1", v->qinv, v->half },
        };
        void *bld = openssl_bld_new();
        if (bld == NULL)
            return -1;
        for (size_t k = 0; k < sizeof numbers / sizeof numbers[0]; k++) {
            void *bn = openssl_bin2bn(numbers[k].octets, (int)numbers[k].length, NULL);
            if (bn == NULL || openssl_bld_push_bn(bld, numbers[k].name, bn) != 1) {
                fprintf(stderr, "bench: rivals: OpenSSL refused an RSA signing key's %s\n", numbers[k].name);
                return -1;
            }
        }
        if ((rsa_private_params[i] = openssl_bld_to_param(bld)) == NULL) {
            fprintf(stderr, "bench: rivals: OpenSSL refused an RSA signing key's parameters\n");
            return -1;
        }
        /* (the builder and the numbers stay, as openssl_load_rsa's: a few KB, once per process) */
    }
    return 0;
}

/* openssl_rsa_private_key: an EVP_PKEY of a signing vector's numbers through EVP_PKEY_fromdata
 * (as a server gets its key from a PKCS#8 file), or NULL. */
static void *openssl_rsa_private_key(const bench_case *c)
{
    size_t which = (size_t)((const bench_rsa_private_vector *)c->data - rsa_private_vectors);
    void *key = NULL;
    if (openssl_fromdata_init(rsa_fromdata_ctx) != 1 || openssl_fromdata(rsa_fromdata_ctx, &key, OPENSSL_KEYPAIR, rsa_private_params[which]) != 1)
        return NULL;
    return key;
}

/* openssl_rsa_signing: EVP_PKEY_sign of the vector's digest with SHA-256, `calls` times, the key
 * and the context made once (OpenSSL computes the key's Montgomery constants and its blinding on
 * the first signature, then keeps them); pss selects RSASSA-PSS with a 32-octet salt (drawn from
 * OpenSSL's DRBG each call; MGF1 takes the signature's digest), else PKCS#1 v1.5 (RSA's default).
 * Like ours, OpenSSL checks every CRT result under e against faults (rsa_ossl_mod_exp); unlike
 * ours, it blinds the base, where ours runs in constant time without. */
static void openssl_rsa_signing(const bench_case *c, long calls, int pss)
{
    const bench_rsa_private_vector *v = (const bench_rsa_private_vector *)c->data;
    void *key = openssl_rsa_private_key(c);
    void *ctx = key ? openssl_pkey_ctx_new(key, NULL) : NULL;
    uint8_t signature[512] = { 0 };
    int sum = 0;
    if (ctx != NULL && openssl_sign_init(ctx) == 1 && openssl_set_signature_md(ctx, openssl_rsa_md) == 1
        && (!pss || (openssl_set_rsa_padding(ctx, OPENSSL_PKCS1_PSS_PADDING) == 1 && openssl_set_rsa_pss_saltlen(ctx, 32) == 1))) {
        for (long i = 0; i < calls; i++) {
            size_t length = sizeof signature;
            sum += openssl_sign(ctx, signature, &length, v->digest, 32);
        }
    }
    openssl_pkey_ctx_free(ctx);
    openssl_pkey_free(key);
    bench_sink = (uint8_t)(sum + signature[0]);
}

/* openssl_rsa_sign: OpenSSL's PKCS#1 v1.5 signature (openssl_rsa_signing). */
static void openssl_rsa_sign(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    openssl_rsa_signing(c, calls, 0);
}

/* openssl_rsa_sign_pss: OpenSSL's PSS signature (openssl_rsa_signing). */
static void openssl_rsa_sign_pss(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    openssl_rsa_signing(c, calls, 1);
}

static bench_rival rsa_sign_rivals[] = { { openssl_name, openssl_rsa_sign } };
static bench_rival rsa_sign_pss_rivals[] = { { openssl_name, openssl_rsa_sign_pss } };

/* The SHA-384 MAC cases' key: 48 octets, a TLS_AES_256_GCM_SHA384 secret's size. */
static const uint8_t mac_key48[48] = { 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x94, 0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa,
                                       0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x94, 0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa,
                                       0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x94, 0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa };

/* bench_hmac_sha384: httpasm_hmac_sha384 of the case's message under mac_key48 (bench.h). */
void bench_hmac_sha384(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t mac[48];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        b->api.httpasm_hmac_sha384(mac_key48, sizeof mac_key48, c->data, c->length, mac);
        total += mac[0];
    }
    bench_sink = total;
}

/* bench_hkdf384_expand: httpasm_hkdf_sha384_expand of c->octets octets from mac_key48, info =
 * the case's data (bench.h). */
void bench_hkdf384_expand(const bench_build *b, const bench_case *c, long calls)
{
    uint8_t okm[96];
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        total += (size_t)b->api.httpasm_hkdf_sha384_expand(mac_key48, sizeof mac_key48, c->data, c->length, okm, c->octets);
        total += okm[0];
    }
    bench_sink = total;
}

/* OpenSSL's EVP_sha384(), for its HMAC() over SHA-384; found by openssl_load_hmac384. */
static const void *openssl_sha384_md;

/* openssl_load_hmac384: EVP_sha384 beside the HMAC that openssl_load_hmac found. Returns 0, or
 * -1 (the SHA-384 MAC cases then run without this rival). */
static int openssl_load_hmac384(void)
{
    if (openssl_load_hmac() != 0)
        return -1;
    void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
    openssl_md_fn md = crypto ? (openssl_md_fn)dlsym(crypto, "EVP_sha384") : NULL;
    if (md == NULL) {
        fprintf(stderr, "bench: rivals: libcrypto.so.3 lacks EVP_sha384\n");
        return -1;
    }
    openssl_sha384_md = md();
    return 0;
}

/* openssl_hmac_sha384: OpenSSL's HMAC-SHA384 of the case's message under mac_key48, `calls` times. */
static void openssl_hmac_sha384(const bench_build *b, const bench_case *c, long calls)
{
    (void)b;
    unsigned char mac[48];
    unsigned int length = 0;
    size_t total = 0;
    for (long i = 0; i < calls; i++) {
        openssl_hmac_call(openssl_sha384_md, mac_key48, (int)sizeof mac_key48, c->data, c->length, mac, &length);
        total += mac[0];
    }
    bench_sink = total;
}

static bench_rival hmac384_rivals[] = {
    { openssl_name, openssl_hmac_sha384 },
};

/* The hash cases' message lengths and their labels. */
static const size_t sha_lengths[] = { 64, 1024, 16384 };
static const char *const sha_labels[] = { "64 octets", "1 KiB", "16 KiB" };

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

/* bench_hpack_decode: httpasm_hpack_decode of the case's block, `calls` times, with the build's
 * own decoder table (bench.h: the tiers suite runs it too, with bench_hpack_block's block). */
void bench_hpack_decode(const bench_build *b, const bench_case *c, long calls)
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

/* bench_hpack_block: the HPACK block (bench.h): the browser request's fields as HTTP/2 sends
 * them, encoded by the first build's encoder with Huffman, every field flagged NO_INDEX (so
 * decoding it never changes a table). Built on the first call; every suite shares it.
 *   data, length  out: the block. Returns 0, or -1 when there is no build or encoding fails. */
int bench_hpack_block(const uint8_t **data, size_t *length)
{
    if (block_length > 0) {
        *data = block;
        *length = block_length;
        return 0;
    }
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
    *data = block;
    *length = block_length;
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
    size_t response_length;
    const uint8_t *response = bench_response(&response_length);
    add("h1_response", "typical response head", response, response_length, bench_h1_response, h1_response_rivals,
        sizeof h1_response_rivals / sizeof h1_response_rivals[0]);
    const uint8_t *sha = bench_sha_input();
    int openssl = openssl_load() == 0;      /* without libcrypto the cases run with no rival */
    for (size_t i = 0; i < sizeof sha_lengths / sizeof sha_lengths[0]; i++)
        add("sha256", sha_labels[i], sha, sha_lengths[i], bench_sha256, openssl ? sha256_rivals : NULL,
            openssl ? sizeof sha256_rivals / sizeof sha256_rivals[0] : 0);
    int sha3 = openssl_load_sha3() == 0;
    for (size_t i = 0; i < sizeof sha_lengths / sizeof sha_lengths[0]; i++) {
        add("sha3_256", sha_labels[i], sha, sha_lengths[i], bench_sha3_256, sha3 ? sha3_256_rivals : NULL, sha3 ? 1 : 0);
        add("shake128", sha_labels[i], sha, sha_lengths[i], bench_shake128, sha3 ? shake128_rivals : NULL, sha3 ? 1 : 0);
    }
    int sha512 = openssl_load_sha512() == 0;
    for (size_t i = 0; i < sizeof sha_lengths / sizeof sha_lengths[0]; i++)
        add("sha512", sha_labels[i], sha, sha_lengths[i], bench_sha512, sha512 ? sha512_rivals : NULL,
            sha512 ? sizeof sha512_rivals / sizeof sha512_rivals[0] : 0);
    for (size_t i = 0; i < 2; i++)          /* 64 octets and 1 KiB: a transcript's and a record's sizes */
        add("sha384", sha_labels[i], sha, sha_lengths[i], bench_sha384, sha512 ? sha384_rivals : NULL,
            sha512 ? sizeof sha384_rivals / sizeof sha384_rivals[0] : 0);
    int hmac = openssl_load_hmac() == 0;
    for (size_t i = 0; i < 2; i++)          /* 64 octets and 1 KiB: a record's MAC-sized inputs */
        add("hmac_sha256", sha_labels[i], sha, sha_lengths[i], bench_hmac_sha256, hmac ? hmac_rivals : NULL,
            hmac ? sizeof hmac_rivals / sizeof hmac_rivals[0] : 0);
    int aes = openssl_load_aes() == 0;
    for (size_t key = 16; key <= 32; key += 16) {
        bench_case c;                       /* by hand: the key's length is c.length, a call's octets 16 */
        memset(&c, 0, sizeof c);
        c.suite = "rivals";
        c.name = "aes_encrypt_block";
        c.input = key == 16 ? "AES-128 block" : "AES-256 block";
        c.data = sha;
        c.length = key;
        c.octets = 16;
        c.ours = bench_aes_block;
        c.tiers = BENCH_TIERS_BEST_V1;
        c.rivals = aes ? aes_rivals : NULL;
        c.rival_count = aes ? sizeof aes_rivals / sizeof aes_rivals[0] : 0;
        bench_add(&c);
    }
    int gcm = openssl_load_gcm() == 0;
    for (size_t i = 0; i < sizeof sha_lengths / sizeof sha_lengths[0]; i++)
        add("aes_128_gcm_seal", sha_labels[i], sha, sha_lengths[i], bench_gcm128_seal, gcm ? gcm128_rivals : NULL,
            gcm ? sizeof gcm128_rivals / sizeof gcm128_rivals[0] : 0);
    for (size_t i = 1; i < sizeof sha_lengths / sizeof sha_lengths[0]; i++)
        add("aes_256_gcm_seal", sha_labels[i], sha, sha_lengths[i], bench_gcm256_seal, gcm ? gcm256_rivals : NULL,
            gcm ? sizeof gcm256_rivals / sizeof gcm256_rivals[0] : 0);
    int chacha = openssl_load_chacha() == 0;
    for (size_t i = 0; i < sizeof sha_lengths / sizeof sha_lengths[0]; i++)
        add("chacha20_poly1305_seal", sha_labels[i], sha, sha_lengths[i], bench_chacha_seal, chacha ? chacha_rivals : NULL,
            chacha ? sizeof chacha_rivals / sizeof chacha_rivals[0] : 0);
    int x25519 = openssl_load_x25519() == 0;
    static const struct {
        const char *name, *input;
        bench_batch ours;
        const bench_rival *rivals;
    } x25519_cases[] = {
        { "x25519", "shared secret", bench_x25519, x25519_rivals },
        { "x25519_public_key", "public key", bench_x25519_public_key, x25519_public_key_rivals },
        { "x25519_key_share", "public key + shared secret", bench_x25519_share, x25519_share_rivals },
    };
    for (size_t i = 0; i < sizeof x25519_cases / sizeof x25519_cases[0]; i++) {
        bench_case c;                       /* by hand: one operation a call, no octets to rate */
        memset(&c, 0, sizeof c);
        c.suite = "rivals";
        c.name = x25519_cases[i].name;
        c.input = x25519_cases[i].input;
        c.data = sha;
        c.length = 64;
        c.octets = 0;
        c.ours = x25519_cases[i].ours;
        c.tiers = BENCH_TIERS_BEST_V1;
        c.rivals = x25519 ? x25519_cases[i].rivals : NULL;
        c.rival_count = x25519 ? 1 : 0;
        bench_add(&c);
    }
    static const struct {
        const char *name, *input;
        bench_batch ours;
        const bench_rival *rivals;
    } x448_cases[] = {
        { "x448", "shared secret", bench_x448, x448_rivals },
        { "x448_public_key", "public key", bench_x448_public_key, x448_public_key_rivals },
        { "x448_key_share", "public key + shared secret", bench_x448_share, x448_share_rivals },
    };
    for (size_t i = 0; i < sizeof x448_cases / sizeof x448_cases[0]; i++) {
        bench_case c;                       /* by hand: one operation a call, no octets to rate */
        memset(&c, 0, sizeof c);
        c.suite = "rivals";
        c.name = x448_cases[i].name;
        c.input = x448_cases[i].input;
        c.data = sha;                       /* the scalar (56 octets), then the peer's u (any 56 are one) */
        c.length = 112;
        c.octets = 0;
        c.ours = x448_cases[i].ours;
        c.tiers = BENCH_TIERS_BEST_V1;
        c.rivals = x25519 ? x448_cases[i].rivals : NULL;   /* (openssl_load_x25519 loaded the EVP functions) */
        c.rival_count = x25519 ? 1 : 0;
        bench_add(&c);
    }
    int p256 = openssl_load_p256() == 0;
    static const struct {
        const char *name, *input;
        bench_batch ours;
        const bench_rival *rivals;
    } p256_cases[] = {
        { "p256_ecdh", "shared secret", bench_p256_ecdh, p256_ecdh_rivals },
        { "p256_public_key", "public key", bench_p256_public_key, p256_public_key_rivals },
        { "p256_key_share", "key drawn + public key + shared secret", bench_p256_share, p256_share_rivals },
        { "p256_sign", "ECDSA signature (SHA-256 digest)", bench_p256_sign, p256_sign_rivals },
        { "p256_verify", "ECDSA verification", bench_p256_verify, p256_verify_rivals },
    };
    for (size_t i = 0; i < sizeof p256_cases / sizeof p256_cases[0]; i++) {
        bench_case c;                       /* by hand: one operation a call, no octets to rate */
        memset(&c, 0, sizeof c);
        c.suite = "rivals";
        c.name = p256_cases[i].name;
        c.input = p256_cases[i].input;
        c.data = p256_input;
        c.length = sizeof p256_input;
        c.octets = 0;
        c.ours = p256_cases[i].ours;
        c.tiers = BENCH_TIERS_BEST_V1;
        c.rivals = p256 ? p256_cases[i].rivals : NULL;
        c.rival_count = p256 ? 1 : 0;
        bench_add(&c);
    }
    static const struct {
        const char *name, *input;
        bench_batch ours;
        const bench_rival *rivals;
    } p384_cases[] = {
        { "p384_ecdh", "shared secret", bench_p384_ecdh, p384_ecdh_rivals },
        { "p384_public_key", "public key", bench_p384_public_key, p384_public_key_rivals },
        { "p384_key_share", "key drawn + public key + shared secret", bench_p384_share, p384_share_rivals },
        { "p384_sign", "ECDSA signature (SHA-384 digest)", bench_p384_sign, p384_sign_rivals },
        { "p384_verify", "ECDSA verification", bench_p384_verify, p384_verify_rivals },
    };
    for (size_t i = 0; i < sizeof p384_cases / sizeof p384_cases[0]; i++) {
        bench_case c;                       /* by hand: one operation a call, no octets to rate */
        memset(&c, 0, sizeof c);
        c.suite = "rivals";
        c.name = p384_cases[i].name;
        c.input = p384_cases[i].input;
        c.data = p384_input;
        c.length = sizeof p384_input;
        c.octets = 0;
        c.ours = p384_cases[i].ours;
        c.tiers = BENCH_TIERS_BEST_V1;
        c.rivals = p256 ? p384_cases[i].rivals : NULL;  /* (P-256's loading brought the functions) */
        c.rival_count = p256 ? 1 : 0;
        bench_add(&c);
    }
    static const struct {
        const char *name, *input;
        size_t set;
        bench_batch ours;
        const bench_rival *rivals;
    } mlkem_cases[] = {
        { "mlkem768_keypair", "key pair from a seed", 768, bench_mlkem_keypair, mlkem_keypair_rivals },
        { "mlkem768_encaps", "encapsulation", 768, bench_mlkem_encaps, mlkem_encaps_rivals },
        { "mlkem768_decaps", "decapsulation", 768, bench_mlkem_decaps, mlkem_decaps_rivals },
        { "mlkem1024_keypair", "key pair from a seed", 1024, bench_mlkem_keypair, mlkem_keypair_rivals },
        { "mlkem1024_encaps", "encapsulation", 1024, bench_mlkem_encaps, mlkem_encaps_rivals },
        { "mlkem1024_decaps", "decapsulation", 1024, bench_mlkem_decaps, mlkem_decaps_rivals },
    };
    for (size_t i = 0; i < sizeof mlkem_cases / sizeof mlkem_cases[0]; i++) {
        bench_case c;                       /* by hand: one operation a call; the length is the set */
        memset(&c, 0, sizeof c);
        c.suite = "rivals";
        c.name = mlkem_cases[i].name;
        c.input = mlkem_cases[i].input;
        c.data = bench_mlkem_input();
        c.length = mlkem_cases[i].set;
        c.octets = 0;
        c.ours = mlkem_cases[i].ours;
        c.tiers = BENCH_TIERS_BEST_V1;
        c.rivals = mlkem_cases[i].rivals;
        c.rival_count = 1;
        bench_add(&c);
    }
    int ffdhe = openssl_load_ffdhe() == 0;
    static const struct {
        const char *name, *input;
        size_t bits;
        bench_batch ours;
        const bench_rival *rivals;
    } ffdhe_cases[] = {
        { "ffdhe2048_public_key", "public key (225-bit exponent)", 2048, bench_ffdhe_public_key, ffdhe_public_key_rivals },
        { "ffdhe2048_shared", "shared secret (225-bit exponent)", 2048, bench_ffdhe_shared, ffdhe_shared_rivals },
        { "ffdhe3072_public_key", "public key (275-bit exponent)", 3072, bench_ffdhe_public_key, ffdhe_public_key_rivals },
        { "ffdhe3072_shared", "shared secret (275-bit exponent)", 3072, bench_ffdhe_shared, ffdhe_shared_rivals },
        { "ffdhe4096_public_key", "public key (325-bit exponent)", 4096, bench_ffdhe_public_key, ffdhe_public_key_rivals },
        { "ffdhe4096_shared", "shared secret (325-bit exponent)", 4096, bench_ffdhe_shared, ffdhe_shared_rivals },
    };
    for (size_t i = 0; i < sizeof ffdhe_cases / sizeof ffdhe_cases[0]; i++) {
        bench_case c;                       /* by hand: one operation a call; the length is the group */
        memset(&c, 0, sizeof c);
        c.suite = "rivals";
        c.name = ffdhe_cases[i].name;
        c.input = ffdhe_cases[i].input;
        c.data = ffdhe_data();
        c.length = ffdhe_cases[i].bits;
        c.octets = 0;
        c.ours = ffdhe_cases[i].ours;
        c.tiers = BENCH_TIERS_BEST_V1;
        c.rivals = ffdhe ? ffdhe_cases[i].rivals : NULL;
        c.rival_count = ffdhe ? 1 : 0;
        bench_add(&c);
    }
    int ed25519 = openssl_load_ed25519() == 0;
    static const struct {
        const char *name, *input;
        bench_batch ours;
        const bench_rival *rivals;
    } ed25519_cases[] = {
        { "ed25519_public_key", "public key", bench_ed25519_public_key, ed25519_public_key_rivals },
        { "ed25519_sign", "signature (130-octet CertificateVerify content)", bench_ed25519_sign, ed25519_sign_rivals },
        { "ed25519_verify", "verification (130-octet CertificateVerify content)", bench_ed25519_verify, ed25519_verify_rivals },
    };
    for (size_t i = 0; i < sizeof ed25519_cases / sizeof ed25519_cases[0]; i++) {
        bench_case c;                       /* by hand: one operation a call, no octets to rate */
        memset(&c, 0, sizeof c);
        c.suite = "rivals";
        c.name = ed25519_cases[i].name;
        c.input = ed25519_cases[i].input;
        c.data = bench_ed25519_input();
        c.length = 32 + BENCH_ED25519_MESSAGE;
        c.octets = 0;
        c.ours = ed25519_cases[i].ours;
        c.tiers = BENCH_TIERS_BEST_V1;
        c.rivals = ed25519 ? ed25519_cases[i].rivals : NULL;
        c.rival_count = ed25519 ? 1 : 0;
        bench_add(&c);
    }
    static const struct {
        const char *name, *input;
        bench_batch ours;
        const bench_rival *rivals;
    } ed448_cases[] = {
        { "ed448_public_key", "public key", bench_ed448_public_key, ed448_public_key_rivals },
        { "ed448_sign", "signature (130-octet CertificateVerify content)", bench_ed448_sign, ed448_sign_rivals },
        { "ed448_verify", "verification (130-octet CertificateVerify content)", bench_ed448_verify, ed448_verify_rivals },
    };
    for (size_t i = 0; i < sizeof ed448_cases / sizeof ed448_cases[0]; i++) {
        bench_case c;                       /* by hand: one operation a call, no octets to rate */
        memset(&c, 0, sizeof c);
        c.suite = "rivals";
        c.name = ed448_cases[i].name;
        c.input = ed448_cases[i].input;
        c.data = bench_ed448_input();
        c.length = 57 + BENCH_ED25519_MESSAGE;
        c.octets = 0;
        c.ours = ed448_cases[i].ours;
        c.tiers = BENCH_TIERS_BEST_V1;
        c.rivals = ed25519 ? ed448_cases[i].rivals : NULL;   /* (openssl_load_ed25519 loaded the EVP functions) */
        c.rival_count = ed25519 ? 1 : 0;
        bench_add(&c);
    }
    int rsa = openssl_load_rsa() == 0;
    static const char *const rsa_labels[] = { "2048-bit, PKCS#1 v1.5 SHA-256", "3072-bit, PKCS#1 v1.5 SHA-256",
                                              "4096-bit, PKCS#1 v1.5 SHA-256" };
    static const struct {
        const char *name;
        bench_batch ours;
        const bench_rival *rivals;
    } rsa_cases[] = {
        { "rsa_verify", bench_rsa_verify, rsa_verify_rivals },
        { "rsa_init_verify", bench_rsa_init_verify, rsa_init_verify_rivals },
        { "rsa_key_init", bench_rsa_init, NULL },
    };
    for (size_t i = 0; i < sizeof rsa_cases / sizeof rsa_cases[0]; i++) {
        for (size_t size = 0; size < 3; size++) {
            bench_case c;                   /* by hand: one operation a call, no octets to rate */
            memset(&c, 0, sizeof c);
            c.suite = "rivals";
            c.name = rsa_cases[i].name;
            c.input = rsa_labels[size];
            c.data = (const uint8_t *)bench_rsa_input(size);
            c.length = sizeof(bench_rsa_vector);
            c.octets = 0;
            c.ours = rsa_cases[i].ours;
            c.tiers = BENCH_TIERS_BEST_V1;
            c.rivals = rsa && rsa_cases[i].rivals ? rsa_cases[i].rivals : NULL;
            c.rival_count = c.rivals ? 1 : 0;
            bench_add(&c);
        }
    }
    int rsa_sign = rsa && openssl_load_rsa_sign() == 0;
    static const char *const rsa_pss_labels[] = { "2048-bit, PSS SHA-256, 32-octet salt", "3072-bit, PSS SHA-256, 32-octet salt",
                                                  "4096-bit, PSS SHA-256, 32-octet salt" };
    static const char *const rsa_key_labels[] = { "2048-bit key (CRT numbers)", "3072-bit key (CRT numbers)",
                                                  "4096-bit key (CRT numbers)" };
    static const struct {
        const char *name;
        bench_batch ours;
        const bench_rival *rivals;
        const char *const *labels;
    } rsa_sign_cases[] = {
        { "rsa_sign", bench_rsa_sign_pkcs1, rsa_sign_rivals, rsa_labels },
        { "rsa_sign_pss", bench_rsa_sign_pss, rsa_sign_pss_rivals, rsa_pss_labels },
        { "rsa_private_key_init", bench_rsa_private_init, NULL, rsa_key_labels },
    };
    for (size_t i = 0; i < sizeof rsa_sign_cases / sizeof rsa_sign_cases[0]; i++) {
        for (size_t size = 0; size < 3; size++) {
            bench_case c;                   /* by hand: one operation a call, no octets to rate */
            memset(&c, 0, sizeof c);
            c.suite = "rivals";
            c.name = rsa_sign_cases[i].name;
            c.input = rsa_sign_cases[i].labels[size];
            c.data = (const uint8_t *)bench_rsa_private_input(size);
            c.length = sizeof(bench_rsa_private_vector);
            c.octets = 0;
            c.ours = rsa_sign_cases[i].ours;
            c.tiers = BENCH_TIERS_BEST_V1;
            c.rivals = rsa_sign && rsa_sign_cases[i].rivals ? rsa_sign_cases[i].rivals : NULL;
            c.rival_count = c.rivals ? 1 : 0;
            bench_add(&c);
        }
    }
    int hmac384 = openssl_load_hmac384() == 0;
    for (size_t i = 0; i < 2; i++)
        add("hmac_sha384", sha_labels[i], sha, sha_lengths[i], bench_hmac_sha384, hmac384 ? hmac384_rivals : NULL,
            hmac384 ? sizeof hmac384_rivals / sizeof hmac384_rivals[0] : 0);
    const uint8_t *hpack_block;
    size_t hpack_length;
    if (bench_hpack_block(&hpack_block, &hpack_length) != 0 || nghttp2_hd_inflate_new(&theirs) != 0) {
        fprintf(stderr, "bench: rivals: no HPACK block or nghttp2 decoder: the HPACK case is left out\n");
        return;
    }
    add("hpack_decode", "browser request's block", hpack_block, hpack_length, bench_hpack_decode, hpack_rivals,
        sizeof hpack_rivals / sizeof hpack_rivals[0]);
}
