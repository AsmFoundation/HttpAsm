/*
 * suite_tiers.c - the tiers suite: every multi-version routine of libhttpasm.so at every CPU
 * tier (v1 to v4), on inputs sized around the vector widths (docs/DESIGN.md section 3, "CPU
 * tiers": a tier's version is kept only where it measures faster than the baseline, beyond the
 * A/A control's gap). A routine joins this suite when it gets a version above v1; a whole
 * routine whose versions sit inside it (httpasm_h1_parse_request, httpasm_h1_parse_response,
 * httpasm_hpack_decode) joins with the rivals suite's inputs, so each tier is judged against the
 * one below on realistic octets.
 *
 * Inputs are built once, deterministically, so two runs (or two machines) measure the same
 * octets.
 */
#include <stdio.h>
#include <string.h>

#include "bench.h"

/* field_value: 8 KiB of valid field-value octets (visible ASCII and space, no CR, LF or NUL), so
 * every call scans its whole length: the parsers' common case. */
static uint8_t field_value[8192];

/* field_value_scan: httpasm_field_value_scan on the case's octets, `calls` times. */
static void field_value_scan(const bench_build *b, const bench_case *c, long calls)
{
    size_t total = 0;
    for (long i = 0; i < calls; i++)
        total += b->api.httpasm_field_value_scan(c->data, c->length);
    bench_sink = total;
}

/* The lengths: each side of the 16-, 32- and 64-octet vector widths (where a version's head and
 * tail handling show), a typical value (100), and long ones where the loop dominates. */
static const size_t field_lengths[] = { 8, 15, 16, 31, 32, 63, 64, 100, 256, 1024, 4096 };
static char field_labels[sizeof field_lengths / sizeof field_lengths[0]][24];

/* add_h1_request: one tiers case for httpasm_h1_parse_request on a whole head (bench.h's heads,
 * the rivals suite's inputs): the request parser's versions (from v2 the one-pass flow, from v3
 * its 32-octet steps) each against the tier below on the same octets.
 *   input  the head's label; head  the head, NUL-terminated. */
static void add_h1_request(const char *input, const char *head)
{
    bench_case c;
    memset(&c, 0, sizeof c);
    c.suite = "tiers";
    c.name = "h1_parse_request";
    c.input = input;
    c.data = (const uint8_t *)head;
    c.length = strlen(head);
    c.octets = c.length;
    c.ours = bench_h1_request;
    c.tiers = BENCH_TIERS_ALL;
    bench_add(&c);
}

/* add_h1_response: the tiers case of httpasm_h1_parse_response on the response head (bench.h's
 * bench_response, the rivals suite's input): the response parser's versions (from v2 its one-pass
 * flow and the field lines' 16-octet steps) each against the tier below on the same octets. */
static void add_h1_response(void)
{
    bench_case c;
    memset(&c, 0, sizeof c);
    c.suite = "tiers";
    c.name = "h1_parse_response";
    c.input = "typical response head";
    c.data = bench_response(&c.length);
    c.octets = c.length;
    c.ours = bench_h1_response;
    c.tiers = BENCH_TIERS_ALL;
    bench_add(&c);
}

/* add_sha256: the tiers cases of httpasm_sha256 on 64 octets (two compressions: the block and
 * the padding's), 1 KiB and 16 KiB of bench_sha_input: the scalar compression (v1) against the
 * SHA extensions' (v2 and up, where the CPU has them). */
static void add_sha256(void)
{
    static const size_t lengths[] = { 64, 1024, 16384 };
    static const char *const labels[] = { "64 octets", "1 KiB", "16 KiB" };
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
        bench_case c;
        memset(&c, 0, sizeof c);
        c.suite = "tiers";
        c.name = "sha256";
        c.input = labels[i];
        c.data = bench_sha_input();
        c.length = lengths[i];
        c.octets = lengths[i];
        c.ours = bench_sha256;
        c.tiers = BENCH_TIERS_ALL;
        bench_add(&c);
    }
}

/* add_sha512: the tiers cases of httpasm_sha512 on 64 octets (one compression: the message and
 * its padding fit one 128-octet block), 1 KiB and 16 KiB of bench_sha_input: the scalar
 * compression (v1) against the vector-scheduled one, where the CPU has the instructions. */
static void add_sha512(void)
{
    static const size_t lengths[] = { 64, 1024, 16384 };
    static const char *const labels[] = { "64 octets", "1 KiB", "16 KiB" };
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
        bench_case c;
        memset(&c, 0, sizeof c);
        c.suite = "tiers";
        c.name = "sha512";
        c.input = labels[i];
        c.data = bench_sha_input();
        c.length = lengths[i];
        c.octets = lengths[i];
        c.ours = bench_sha512;
        c.tiers = BENCH_TIERS_ALL;
        bench_add(&c);
    }
}

/* add_hkdf_expand: the tiers case of httpasm_hkdf_sha256_expand as TLS 1.3's key schedule calls
 * it: 32 octets (one HMAC block) from a 32-octet PRK, with a 20-octet info (an HkdfLabel's size
 * for "tls13 key" and an empty context). Its time is two key compressions and two message ones,
 * all SHA-256's, at each tier. */
static void add_hkdf_expand(void)
{
    bench_case c;
    memset(&c, 0, sizeof c);
    c.suite = "tiers";
    c.name = "hkdf_sha256_expand";
    c.input = "32 octets, 20-octet info";
    c.data = bench_sha_input();
    c.length = 20;
    c.octets = 32;
    c.ours = bench_hkdf_expand;
    c.tiers = BENCH_TIERS_ALL;
    bench_add(&c);
}

/* add_hkdf384_expand: the tiers case of httpasm_hkdf_sha384_expand as TLS_AES_256_GCM_SHA384's
 * key schedule calls it: 48 octets (one HMAC block) from a 48-octet PRK, with a 20-octet info.
 * Four SHA-384 compressions (two for the key, one each for the inner and outer hash), at each
 * tier: v1's scalar compression against v3's. */
static void add_hkdf384_expand(void)
{
    bench_case c;
    memset(&c, 0, sizeof c);
    c.suite = "tiers";
    c.name = "hkdf_sha384_expand";
    c.input = "48 octets, 20-octet info";
    c.data = bench_sha_input();
    c.length = 20;
    c.octets = 48;
    c.ours = bench_hkdf384_expand;
    c.tiers = BENCH_TIERS_ALL;
    bench_add(&c);
}

/* add_hpack_decode: the tiers case of httpasm_hpack_decode on the rivals suite's block (bench.h):
 * the Huffman decoder's versions (v1's automaton, v2's table decoder) each against the tier below.
 * Left out, with a word on stderr, when the block cannot be made. */
static void add_hpack_decode(void)
{
    const uint8_t *block;
    size_t length;
    if (bench_hpack_block(&block, &length) != 0) {
        fprintf(stderr, "bench: tiers: no HPACK block: the hpack_decode case is left out\n");
        return;
    }
    bench_case c;
    memset(&c, 0, sizeof c);
    c.suite = "tiers";
    c.name = "hpack_decode";
    c.input = "browser request's block";
    c.data = block;
    c.length = length;
    c.octets = length;
    c.ours = bench_hpack_decode;
    c.tiers = BENCH_TIERS_ALL;
    bench_add(&c);
}

/* bench_suite_tiers: registers the suite's cases (bench.h). */
void bench_suite_tiers(void)
{
    add_h1_request("small GET", bench_small_request);
    add_h1_request("browser GET", bench_browser_request);
    add_h1_request("API POST", bench_api_request);
    add_h1_response();
    add_hpack_decode();
    add_sha256();
    add_sha512();
    add_hkdf_expand();
    add_hkdf384_expand();
    for (size_t i = 0; i < sizeof field_value; i++)
        field_value[i] = (uint8_t)(0x20 + (i * 37) % 95);
    for (size_t i = 0; i < sizeof field_lengths / sizeof field_lengths[0]; i++) {
        snprintf(field_labels[i], sizeof field_labels[i], "%zu octets", field_lengths[i]);
        bench_case c;
        memset(&c, 0, sizeof c);
        c.suite = "tiers";
        c.name = "field_value_scan";
        c.input = field_labels[i];
        c.data = field_value;
        c.length = field_lengths[i];
        c.octets = field_lengths[i];
        c.ours = field_value_scan;
        c.tiers = BENCH_TIERS_ALL;
        bench_add(&c);
    }
}
