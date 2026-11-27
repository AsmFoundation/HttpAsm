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
static openssl_new_raw_fn openssl_new_private, openssl_new_public;
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
    if (!openssl_new_private || !openssl_new_public || !openssl_pkey_ctx_new || !openssl_derive_init || !openssl_set_peer ||
        !openssl_derive || !openssl_pkey_ctx_free || !openssl_pkey_free) {
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

static bench_rival x25519_rivals[] = {
    { openssl_name, openssl_x25519 },
};

static bench_rival x25519_share_rivals[] = {
    { openssl_name, openssl_x25519_share },
};

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
    for (int share = 0; share < 2; share++) {
        bench_case c;                       /* by hand: one operation a call, no octets to rate */
        memset(&c, 0, sizeof c);
        c.suite = "rivals";
        c.name = share ? "x25519_key_share" : "x25519";
        c.input = share ? "public key + shared secret" : "shared secret";
        c.data = sha;
        c.length = 64;
        c.octets = 0;
        c.ours = share ? bench_x25519_share : bench_x25519;
        c.tiers = BENCH_TIERS_BEST_V1;
        c.rivals = x25519 ? (share ? x25519_share_rivals : x25519_rivals) : NULL;
        c.rival_count = x25519 ? 1 : 0;
        bench_add(&c);
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
