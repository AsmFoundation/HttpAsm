/*
 * tiers.c - proves that every version of each multi-version routine in libhttpasm.so computes
 * the same results (docs/DESIGN.md section 2, "Fastest tier, every tier proven"; cpu.inc).
 *
 * Each input runs at every tier, switched with httpasm_cpu_limit, and the results must match
 * each other and an oracle written here from the RFC. Inputs sit against an inaccessible page,
 * so a version that reads past its input dies with SIGSEGV instead of passing.
 *
 * Why a C program as well as the .NET suite: the suite runs natively at every tier the CPU has
 * (tests/run-linux.sh), but Intel SDE, which emulates AVX-512 on CPUs without it, cannot run
 * the .NET runtime (it hangs). This program runs under SDE in seconds, so the AVX-512 versions
 * are proven equal to the baseline the suite proves, on any machine.
 *
 * Usage: tiers [random-inputs-per-routine]     (default 200000)
 * Exit status: 0 when every result matched; 1 on the first mismatch (printed with its input);
 * 2 on a usage or setup error. The tiers a run covers are the ones the CPU (or SDE) offers: the
 * output lists them, and tests/run-linux.sh checks the list says v4 under SDE.
 *
 * Build (tests/native/build.sh): cc -O2 -Wall -Wextra -Werror, against libhttpasm.so.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "httpasm.h"

/* The caps compared: each level's own. A level the CPU lacks collapses to the best one below
 * (the library's closure), which simply repeats that tier. */
static const uint64_t caps[] = { HTTPASM_CPU_CAP_V1, HTTPASM_CPU_CAP_V2, HTTPASM_CPU_CAP_V3, HTTPASM_CPU_CAP_V4 };
static const char *const cap_names[] = { "v1", "v2", "v3", "v4" };
#define TIERS (sizeof caps / sizeof caps[0])

enum { PAGE = 4096 };

/* Readable pages (main maps five), then an inaccessible one: page_end - n is where an n-octet
 * input starts, its last octet just before the guard. */
static uint8_t *page_end;

/* The state of a small deterministic generator (xorshift64*), seeded fixed, so a failure
 * reproduces run after run. */
static uint64_t rng_state = 0x9E3779B97F4A7C15u;
/* rng: the generator's next 64 pseudo-random bits. */
static uint64_t rng(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1Du;
}

/* dump: prints an input as hex on stderr, for a failure report.
 *   what  a label for the line; p, n  the input. */
static void dump(const char *what, const uint8_t *p, size_t n)
{
    fprintf(stderr, "%s (%zu octets): ", what, n);
    for (size_t i = 0; i < n; i++)
        fprintf(stderr, "%02X", p[i]);
    fputc('\n', stderr);
}

/* ---- httpasm_field_value_scan ---------------------------------------------------------- */

/* field_value_oracle: the oracle, from RFC 9110 section 5.5.
 *   p, n  the value. Returns the index of its first CTL other than HTAB (0x00-0x08,
 *   0x0A-0x1F, 0x7F), or n when it has none. */
static size_t field_value_oracle(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if ((p[i] < 0x20 && p[i] != 0x09) || p[i] == 0x7F)
            return i;
    return n;
}

/* field_value_check: runs one value at every tier, copied against the guard page first.
 *   value, n  the value. Returns 0 when every tier agrees with the oracle; 1, after
 *   reporting the tier, both results and the value, otherwise. Leaves the last tier set. */
static int field_value_check(const uint8_t *value, size_t n)
{
    uint8_t *p = page_end - n;
    memcpy(p, value, n);
    size_t expected = field_value_oracle(p, n);
    for (size_t t = 0; t < TIERS; t++) {
        uint64_t features = httpasm_cpu_limit(caps[t]);
        size_t actual = httpasm_field_value_scan(p, n);
        if (actual != expected) {
            fprintf(stderr, "httpasm_field_value_scan at %s (features %#llx): expected %zu, got %zu\n",
                    cap_names[t], (unsigned long long)features, expected, actual);
            dump("value", p, n);
            return 1;
        }
    }
    return 0;
}

/* field_value_valid: fills v[0..n) with octets a field value may hold (field-vchar, SP,
 * HTAB), drawn from the whole allowed range. */
static void field_value_valid(uint8_t *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned pick = (unsigned)(rng() % 224);        /* HTAB, 0x20-0x7E, 0x80-0xFF */
        v[i] = pick == 0 ? 0x09 : (uint8_t)(pick < 96 ? 0x1F + pick : pick + 32);
    }
}

/* field_value_scan_tiers: httpasm_field_value_scan's inputs: every length up to 300 valid and
 * with a forbidden octet at every position, every octet value at the end of a few lengths,
 * then `randoms` random values up to 1023 octets. Returns 0 when every one agreed at every
 * tier, 1 at the first that did not. */
static int field_value_scan_tiers(long randoms)
{
    static uint8_t v[PAGE];
    static const uint8_t forbidden[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x7F };
    long checked = 0;

    /* Every length up to 300 (past four 64-octet vectors), valid, and with one forbidden octet
     * at every position; then every octet value as the last of a few lengths. */
    for (size_t n = 0; n <= 300; n++) {
        field_value_valid(v, n);
        if (field_value_check(v, n))
            return 1;
        checked++;
        for (size_t at = 0; at < n; at++) {
            field_value_valid(v, n);
            v[at] = forbidden[(at + n) % sizeof forbidden];
            if (field_value_check(v, n))
                return 1;
            checked++;
        }
    }
    for (unsigned octet = 0; octet < 256; octet++) {
        for (size_t n = 1; n <= 200; n += 33) {
            field_value_valid(v, n);
            v[n - 1] = (uint8_t)octet;
            if (field_value_check(v, n))
                return 1;
            checked++;
        }
    }
    /* Random values: mostly valid, with forbidden octets sprinkled at random rates. */
    for (long i = 0; i < randoms; i++) {
        size_t n = (size_t)(rng() % 1024);
        field_value_valid(v, n);
        unsigned rate = (unsigned)(rng() % 5);
        for (size_t k = 0; k < n; k++)
            if (rate && rng() % (rate * 97) == 0)
                v[k] = forbidden[rng() % sizeof forbidden];
        if (field_value_check(v, n))
            return 1;
        checked++;
    }
    printf("httpasm_field_value_scan: %ld inputs, every tier agrees with the oracle\n", checked);
    return 0;
}

/* ---- httpasm_token_length: the token scan's versions (ha_token_length) ------------------------ */

static uint8_t tchar_pick(void);

/* token_oracle: the oracle, from RFC 9110 5.6.2: the number of leading tchars of p[0..n). */
static size_t token_oracle(const uint8_t *p, size_t n)
{
    static const char punctuation[] = "!#$%&'*+-.^_`|~";
    for (size_t i = 0; i < n; i++) {
        uint8_t c = p[i];
        int tchar = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c != 0 && strchr(punctuation, c) != NULL);
        if (!tchar)
            return i;
    }
    return n;
}

/* token_check: one input at every tier, ending `gap` octets before the guard page (random octets
 * between), against the oracle. Returns 0 when every tier agrees; 1, after reporting, otherwise. */
static int token_check(const uint8_t *token, size_t n, size_t gap)
{
    uint8_t *p = page_end - n - gap;
    memcpy(p, token, n);
    for (size_t i = 0; i < gap; i++)
        p[n + i] = (uint8_t)rng();
    size_t expected = token_oracle(p, n);
    for (size_t t = 0; t < TIERS; t++) {
        uint64_t features = httpasm_cpu_limit(caps[t]);
        size_t actual = httpasm_token_length(p, n);
        if (actual != expected) {
            fprintf(stderr, "httpasm_token_length at %s (features %#llx): expected %zu, got %zu; %zu octets before the guard page\n",
                    cap_names[t], (unsigned long long)features, expected, actual, gap);
            dump("token", p, n);
            return 1;
        }
    }
    return 0;
}

/* token_tiers: every length 0-100 all tchars and with one non-tchar (each kind: a control, SP,
 * a separator, DEL, 0x80-0xFF) at every position, every octet value as the last octet of a few
 * lengths, then `randoms` random tokens; each at distances from the guard page that reach every
 * short-token path (0-17 octets: within 16 of the page's end, or not) and the overlapping last
 * step. Returns 0 when every one agreed at every tier, 1 at the first that did not. */
static int token_tiers(long randoms)
{
    static uint8_t t[128];
    static const uint8_t breakers[] = { 0x00, 0x09, ' ', '"', '(', ',', '/', ':', '@', '[', '{', 0x7F, 0x80, 0xFF };
    static const size_t gaps[] = { 0, 1, 7, 15, 16, 17 };
    long checked = 0;
    for (size_t n = 0; n <= 100; n++) {
        for (size_t k = 0; k < n; k++)
            t[k] = tchar_pick();
        for (size_t g = 0; g < sizeof gaps / sizeof gaps[0]; g++) {
            if (token_check(t, n, gaps[g]))
                return 1;
            checked++;
        }
        for (size_t at = 0; at < n; at++) {
            uint8_t keep = t[at];
            t[at] = breakers[(at + n) % sizeof breakers];
            if (token_check(t, n, gaps[(at + n) % (sizeof gaps / sizeof gaps[0])]))
                return 1;
            checked++;
            t[at] = keep;
        }
    }
    for (unsigned c = 0; c < 256; c++) {
        for (size_t n = 1; n <= 40; n += 13) {
            for (size_t k = 0; k < n; k++)
                t[k] = tchar_pick();
            t[n - 1] = (uint8_t)c;
            if (token_check(t, n, gaps[c % (sizeof gaps / sizeof gaps[0])]))
                return 1;
            checked++;
        }
    }
    for (long i = 0; i < randoms; i++) {
        size_t n = (size_t)(rng() % 101);
        for (size_t k = 0; k < n; k++)
            t[k] = rng() % 40 == 0 ? (uint8_t)rng() : tchar_pick();
        if (token_check(t, n, (size_t)(rng() % 33)))
            return 1;
        checked++;
    }
    printf("httpasm_token_length: %ld inputs, every tier agrees with the oracle\n", checked);
    return 0;
}

/* ---- httpasm_field_id: the field-name lookup's versions (ha_field_lookup) -------------------- */

/* field_id_check: one name at every tier, ending `gap` octets before the guard page (the octets
 * between are random: whatever follows a name in a caller's buffer), so a version that reads
 * past the page dies with SIGSEGV. Every tier must give v1's id, which the .NET suite proves
 * against the known-field list.
 *   name, n  the name (n + gap <= PAGE); gap  the octets after it, before the guard page.
 * Returns 0 when every tier agrees; 1, after reporting the tier and the name, otherwise. Leaves
 * the last tier set. */
static int field_id_check(const uint8_t *name, size_t n, size_t gap)
{
    uint8_t *p = page_end - n - gap;
    memcpy(p, name, n);
    for (size_t i = 0; i < gap; i++)
        p[n + i] = (uint8_t)rng();
    httpasm_cpu_limit(caps[0]);
    uint32_t expected = httpasm_field_id(p, n);
    for (size_t t = 1; t < TIERS; t++) {
        uint64_t features = httpasm_cpu_limit(caps[t]);
        uint32_t actual = httpasm_field_id(p, n);
        if (actual != expected) {
            fprintf(stderr, "httpasm_field_id at %s (features %#llx): %u, v1 %u; the name ends %zu octets before the guard page\n",
                    cap_names[t], (unsigned long long)features, actual, expected, gap);
            dump("name", p, n);
            return 1;
        }
    }
    return 0;
}

/* field_id_gaps: field_id_check at every gap that moves a name across the page-end cases of a
 * 16-octet read: ending at the page (0), within one vector of it (1, 15), at exactly one vector
 * (16) and past it (17, 31). Returns 0 when all agree, 1 at the first that did not. */
static int field_id_gaps(const uint8_t *name, size_t n, long *checked)
{
    static const size_t gaps[] = { 0, 1, 15, 16, 17, 31 };
    for (size_t g = 0; g < sizeof gaps / sizeof gaps[0]; g++) {
        if (field_id_check(name, n, gaps[g]))
            return 1;
        (*checked)++;
    }
    return 0;
}

static uint8_t tchar_pick(void);

/* field_id_tiers: every known name (httpasm_field_name) as listed, in random mixes of case, with
 * each octet replaced in turn by the other case of a letter and by tchars of every kind (letters,
 * digits, '-', and punctuation such as '^' and '_', which | 0x20 folds onto '~' and DEL: the
 * key folds them alike, so only the compare tells them apart), one octet short and one long;
 * then `randoms` random tokens of 0-40 octets. A replaced octet makes a near miss that must not
 * match; a case change must still match. Returns 0 when every name agreed at every tier, 1 at
 * the first that did not. */
static int field_id_tiers(long randoms)
{
    static const uint8_t swaps[] = { '-', '0', '9', '^', '_', '`', '|', '~', '!', '.', 'z', 'Q' };
    uint8_t name[64];
    long checked = 0;
    for (uint32_t id = 1;; id++) {
        size_t n;
        const uint8_t *known = httpasm_field_name(id, &n);
        if (known == NULL)
            break;
        memcpy(name, known, n);
        if (field_id_gaps(name, n, &checked))
            return 1;
        for (int mix = 0; mix < 4; mix++) {                 /* the same name in mixed case */
            for (size_t i = 0; i < n; i++)
                name[i] = (uint8_t)((known[i] >= 'a' && known[i] <= 'z' && rng() % 2) ? known[i] - 32 : known[i]);
            if (field_id_gaps(name, n, &checked))
                return 1;
        }
        for (size_t at = 0; at < n; at++) {                 /* one octet replaced: a near miss */
            for (size_t s = 0; s <= sizeof swaps; s++) {
                memcpy(name, known, n);
                uint8_t c = known[at];
                name[at] = s < sizeof swaps ? swaps[s] : (uint8_t)(c >= 'a' && c <= 'z' ? c - 32 : c);
                if (field_id_gaps(name, n, &checked))
                    return 1;
            }
        }
        memcpy(name, known, n);                             /* one short, one long */
        if (n > 1 && field_id_gaps(name, n - 1, &checked))
            return 1;
        name[n] = 's';
        if (field_id_gaps(name, n + 1, &checked))
            return 1;
    }
    for (long i = 0; i < randoms; i++) {
        size_t n = (size_t)(rng() % 41);
        for (size_t k = 0; k < n; k++)
            name[k] = tchar_pick();
        if (field_id_check(name, n, (size_t)(rng() % 33)))
            return 1;
        checked++;
    }
    printf("httpasm_field_id: %ld names, every tier agrees with v1\n", checked);
    return 0;
}

/* ---- httpasm_h1_parse_request: two flows and per-line versions --------------------------------
 * From v2 up, a head searched from its request-line is parsed in one pass (request.asm's
 * .one_pass and ha_h1_fields_v2), which accepts or hands the head to the classic flow (the head's
 * end searched first, then ha_h1_fields, whose lines have v1 and v2 versions). v1 runs the
 * classic flow alone, so comparing every tier with v1 proves both flows and both line versions
 * equal on every input below: complete heads, every prefix of some, heads resumed after a cut,
 * refusals of every kind, and small limits. */

#define PARSE_FIELDS 64

/* The limits every parse_at call passes: the default, max_fields aside (the records array), and
 * varied by parse_variety (max_fields never above PARSE_FIELDS). */
static const httpasm_h1_limits default_limits = { .max_fields = PARSE_FIELDS };
static httpasm_h1_limits parse_limits = { .max_fields = PARSE_FIELDS };

/* parse_result: everything one parse hands back: its return value, the scan position, the
 * request and every field record (whose pointers point into the one input every tier parses,
 * so equal results have equal pointers). */
typedef struct parse_result {
    int64_t ret;
    size_t scan;
    httpasm_request request;
    httpasm_field fields[PARSE_FIELDS];
} parse_result;

/* parse_at: parses buf[0..len) at the tier now set, with parse_limits, into *out (zeroed first,
 * so unset parts compare equal), the search resuming at `scan` (0 for a message's first call). */
static void parse_at_from(const uint8_t *buf, size_t len, size_t scan, parse_result *out)
{
    memset(out, 0, sizeof *out);
    out->scan = scan;
    out->ret = httpasm_h1_parse_request(buf, len, &out->scan, &parse_limits, &out->request, out->fields);
}

/* parse_at: parse_at_from for a message's first call. */
static void parse_at(const uint8_t *buf, size_t len, parse_result *out)
{
    parse_at_from(buf, len, 0, out);
}

/* parse_same: whether two parses agree on everything: the return, the scan position, every
 * field of the request but its fields pointer (each parse has its own array), and the records
 * the request counts. Returns 1 when they agree, 0 otherwise. */
static int parse_same(const parse_result *a, const parse_result *b)
{
    if (a->ret != b->ret || a->scan != b->scan)
        return 0;
    httpasm_request ra = a->request, rb = b->request;
    ra.fields = rb.fields = NULL;
    if (memcmp(&ra, &rb, sizeof ra) != 0)
        return 0;
    uint32_t n = a->request.field_count < PARSE_FIELDS ? a->request.field_count : PARSE_FIELDS;
    return memcmp(a->fields, b->fields, n * sizeof a->fields[0]) == 0;
}

/* parse_check_from: one head at every tier, ending `gap` octets before the guard page (the octets
 * between are part of buf: the start of a body, as the caller would hand them over), so a version
 * that reads past the head into the unmapped page dies with SIGSEGV. Every tier must agree with
 * v1, which the .NET suite proves against the RFC.
 *   head, n  the head (n <= PAGE - gap); gap  the octets after it, before the guard page;
 *   scan     the *scan_from handed in: 0 for a message's first call, or one past the data (a
 *            stale value, which the parser ignores: from v2 up the one-pass flow then runs).
 * Returns 0 when every tier agrees; 1, after reporting the tier and the head, otherwise. Leaves
 * the last tier set. */
static int parse_check_from(const uint8_t *head, size_t n, size_t gap, size_t scan)
{
    static parse_result expected, actual;
    uint8_t *buf = page_end - n - gap;
    memcpy(buf, head, n);
    for (size_t i = 0; i < gap; i++)
        buf[n + i] = (uint8_t)rng();                   /* whatever follows a head */
    httpasm_cpu_limit(caps[0]);
    parse_at_from(buf, n + gap, scan, &expected);
    for (size_t t = 1; t < TIERS; t++) {
        uint64_t features = httpasm_cpu_limit(caps[t]);
        parse_at_from(buf, n + gap, scan, &actual);
        if (!parse_same(&expected, &actual)) {
            fprintf(stderr, "httpasm_h1_parse_request at %s (features %#llx) differs from v1: returned %lld (error %u, %u fields), "
                            "v1 %lld (error %u, %u fields); the head ends %zu octets before the guard page, the search resumed at %zu\n",
                    cap_names[t], (unsigned long long)features, (long long)actual.ret, actual.request.error, actual.request.field_count,
                    (long long)expected.ret, expected.request.error, expected.request.field_count, gap, scan);
            dump("head", buf, n);
            return 1;
        }
    }
    return 0;
}

/* parse_check: parse_check_from for a message's first call (*scan_from 0). */
static int parse_check(const uint8_t *head, size_t n, size_t gap)
{
    return parse_check_from(head, n, gap, 0);
}

/* put: appends text to a head being built. h, n: the head and its length so far (advanced);
 * the callers keep heads within their buffer. */
static void put(uint8_t *h, size_t *n, const char *text)
{
    size_t k = strlen(text);
    memcpy(h + *n, text, k);
    *n += k;
}

/* tchar_pick: a random tchar (RFC9110-5.6.2-2): mostly letters, digits and '-', which names are
 * made of, and every punctuation tchar now and then. */
static uint8_t tchar_pick(void)
{
    static const char tchars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-!#$%&'*+.^_`|~";
    unsigned r = (unsigned)(rng() % 100);
    if (r < 85)
        return (uint8_t)tchars[rng() % 26];
    if (r < 95)
        return (uint8_t)(r < 90 ? '-' : tchars[52 + rng() % 10]);
    return (uint8_t)tchars[rng() % (sizeof tchars - 1)];
}

/* field_line: appends one field line to h (advancing *n): a name of 1-40 tchars (sometimes 0,
 * or with a non-tchar, or whitespace before the colon), the colon, OWS, a value of up to 200
 * octets a value may hold (sometimes with a CTL, a bare CR, or nothing but OWS), OWS, CRLF; or,
 * now and then, an obs-fold line. Every outcome of ha_h1_fields' checks is drawn this way. */
static void field_line(uint8_t *h, size_t *n)
{
    if (rng() % 40 == 0) {                              /* obs-fold: a line starting with SP / HTAB */
        put(h, n, rng() % 2 ? " folded" : "\tfolded");
        put(h, n, "\r\n");
        return;
    }
    size_t name = rng() % 60 == 0 ? 0 : 1 + (size_t)(rng() % (rng() % 4 == 0 ? 40 : 16));
    for (size_t i = 0; i < name; i++)
        h[(*n)++] = tchar_pick();
    if (name > 0 && rng() % 50 == 0)                    /* a non-tchar inside the name */
        h[*n - 1 - rng() % name] = (uint8_t)" \"(),/;<=>?@[\\]{}\x7f\x80"[rng() % 18];
    if (rng() % 50 == 0)                                /* whitespace before the colon */
        h[(*n)++] = rng() % 2 ? ' ' : '\t';
    h[(*n)++] = ':';
    for (size_t k = rng() % 4; k > 0; k--)              /* leading OWS */
        h[(*n)++] = rng() % 3 ? ' ' : '\t';
    size_t value = rng() % 10 == 0 ? 0 : (size_t)(rng() % (rng() % 4 == 0 ? 200 : 48));
    size_t start = *n;
    field_value_valid(h + *n, value);
    *n += value;
    if (value > 0 && rng() % 25 == 0) {                 /* a CTL inside the value */
        static const uint8_t ctls[] = { 0x00, 0x01, 0x0B, 0x1F, 0x7F, 0x0D, 0x0D, 0x0A };
        h[start + rng() % value] = ctls[rng() % sizeof ctls];
    }
    for (size_t k = rng() % 4; k > 0; k--)              /* trailing OWS */
        h[(*n)++] = rng() % 3 ? ' ' : '\t';
    put(h, n, "\r\n");
}

/* parse_tiers: request heads with 0-30 field lines drawn by field_line, each parsed at every
 * tier ending 0, 1, 15, 16 and 17 octets before the guard page (a 16-octet step from the head's
 * last lines then reaches into it unless it falls back), plus every length of one field's name
 * and value up to 70 octets, so each vector width's edges are met. Returns 0 when every head
 * agreed at every tier, 1 at the first that did not. */
static int parse_tiers(long randoms)
{
    static uint8_t h[PAGE];
    static const size_t gaps[] = { 0, 1, 15, 16, 17 };
    long checked = 0;
    for (size_t name = 1; name <= 70; name++) {
        for (size_t value = 0; value <= 70; value++) {
            size_t n = 0;
            put(h, &n, "GET / HTTP/1.1\r\nHost: a\r\n");
            for (size_t i = 0; i < name; i++)
                h[n++] = (uint8_t)('a' + i % 26);
            put(h, &n, ": ");
            field_value_valid(h + n, value);
            n += value;
            put(h, &n, "\r\n\r\n");
            for (size_t g = 0; g < sizeof gaps / sizeof gaps[0]; g++) {
                if (parse_check(h, n, gaps[g]))
                    return 1;
                checked++;
            }
        }
    }
    for (long i = 0; i < randoms; i++) {
        size_t n = 0;
        put(h, &n, rng() % 2 ? "GET /index.html HTTP/1.1\r\n" : "POST /api/items?id=7 HTTP/1.1\r\n");
        if (rng() % 4 != 0)                             /* most heads valid: Host is required */
            put(h, &n, "Host: example.com\r\n");
        size_t lines = (size_t)(rng() % 31);
        for (size_t l = 0; l < lines && n < PAGE - 512; l++)
            field_line(h, &n);
        put(h, &n, "\r\n");
        if (parse_check(h, n, gaps[rng() % (sizeof gaps / sizeof gaps[0])]))
            return 1;
        checked++;
    }
    printf("httpasm_h1_parse_request: %ld heads, every tier agrees with v1\n", checked);
    return 0;
}

/* parse_report: prints a mismatch between a tier's parse and v1's (parse_check's form).
 *   what  which call differed; t  the tier; features  its bits; actual, expected  the results;
 *   buf, n  the input. */
static void parse_report(const char *what, size_t t, uint64_t features, const parse_result *actual,
                         const parse_result *expected, const uint8_t *buf, size_t n)
{
    fprintf(stderr, "httpasm_h1_parse_request (%s) at %s (features %#llx) differs from v1: returned %lld (error %u, %u fields, scan %zu), "
                    "v1 %lld (error %u, %u fields, scan %zu); limits head %u target %u fields %u\n",
            what, cap_names[t], (unsigned long long)features, (long long)actual->ret, actual->request.error,
            actual->request.field_count, actual->scan, (long long)expected->ret, expected->request.error,
            expected->request.field_count, expected->scan, parse_limits.max_head, parse_limits.max_target,
            parse_limits.max_fields);
    dump("head", buf, n);
}

/* parse_check_resumed: a head arriving in two reads, as a server sees one: its first `cut`
 * octets (against the guard page: incomplete, or already refused), then all n octets, the second
 * call resuming where the first left the search (at a new address, as a grown buffer may be; the
 * offsets carry over). The resumed call takes the classic flow at every tier, its line versions
 * per tier. Both calls must agree with v1's at every tier.
 *   head, n  the whole head (n <= PAGE); cut  the first read's length (cut <= n).
 * Returns 0 when every tier agrees; 1, after reporting, otherwise. Leaves the last tier set. */
static int parse_check_resumed(const uint8_t *head, size_t n, size_t cut)
{
    static parse_result expected[2], actual[2];
    for (size_t t = 0; t < TIERS; t++) {
        uint64_t features = httpasm_cpu_limit(caps[t]);
        parse_result *r = t == 0 ? expected : actual;
        uint8_t *first = page_end - cut;
        memcpy(first, head, cut);
        parse_at(first, cut, &r[0]);
        uint8_t *whole = page_end - n;
        memcpy(whole, head, n);
        parse_at_from(whole, n, r[0].ret == 0 ? r[0].scan : 0, &r[1]);
        if (t == 0)
            continue;
        if (!parse_same(&expected[0], &actual[0])) {
            parse_report("the first read", t, features, &actual[0], &expected[0], first, cut);
            return 1;
        }
        if (!parse_same(&expected[1], &actual[1])) {
            parse_report("the resumed read", t, features, &actual[1], &expected[1], whole, n);
            return 1;
        }
    }
    return 0;
}

/* target_octet: a random octet a request-target may hold as it is (RFC 3986's unreserved,
 * sub-delims, ":", "@", "/", "?"), never "%". */
static uint8_t target_octet(void)
{
    static const char octets[] = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-._~!$&'()*+,;=:@/?[]";
    unsigned r = (unsigned)(rng() % 100);
    if (r < 70)
        return (uint8_t)octets[rng() % 36];
    return (uint8_t)octets[rng() % (sizeof octets - 1)];
}

/* request_line: appends a request-line to h (advancing *n), drawn so that every check of the
 * request-line meets both of its outcomes: leading empty lines (RFC 9112 2.2); methods known,
 * unknown, of 1-24 tchars (past one 16-octet step), empty, or with a non-tchar; one SP mostly,
 * sometimes two, HTAB or none; targets in each form (origin up to 300 octets with
 * percent-encodings, valid or not; asterisk; absolute http(s) with or without userinfo, port or
 * host; authority for CONNECT or not), sometimes with an octet a target may not hold; versions
 * 1.1, 1.0, a later minor, another major, or malformed; CRLF, or now and then a bare LF. */
static void request_line(uint8_t *h, size_t *n)
{
    static const char *const methods[] = { "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH",
                                           "TRACE", "get", "M-SEARCH", "PROPFIND" };
    static const char *const versions[] = { "HTTP/1.1", "HTTP/1.1", "HTTP/1.1", "HTTP/1.1", "HTTP/1.1", "HTTP/1.1",
                                            "HTTP/1.0", "HTTP/1.9", "HTTP/2.0", "HTTP/1.", "http/1.1", "HTTP/1.1 ",
                                            "HTTP/11", "HTTP/1.x" };
    for (size_t k = rng() % 8 == 0 ? 1 + (size_t)(rng() % 3) : 0; k > 0; k--)
        put(h, n, "\r\n");
    unsigned r = (unsigned)(rng() % 100);
    int connect = 0, options = 0;
    if (r < 80) {
        const char *m = methods[rng() % (sizeof methods / sizeof methods[0])];
        connect = strcmp(m, "CONNECT") == 0;
        options = strcmp(m, "OPTIONS") == 0;
        put(h, n, m);
    } else if (r < 96) {
        for (size_t k = 1 + (size_t)(rng() % 24); k > 0; k--)
            h[(*n)++] = tchar_pick();
    } else if (r < 98) {
        put(h, n, "GE\x01T");                           /* a non-tchar in the method */
    }                                                   /* else no method at all */
    r = (unsigned)(rng() % 100);
    put(h, n, r < 94 ? " " : r < 96 ? "  " : r < 98 ? "\t" : "");
    r = (unsigned)(rng() % 100);
    if (connect && r < 70) {                            /* authority-form */
        put(h, n, rng() % 4 ? "example.com" : "[::1]");
        put(h, n, rng() % 5 ? ":443" : rng() % 2 ? ":" : ":99999");
    } else if (r < 5 || (options && r < 30)) {          /* asterisk-form */
        put(h, n, "*");
    } else if (r < 15) {                                /* absolute-form */
        put(h, n, rng() % 2 ? "http://" : "https://");
        r = (unsigned)(rng() % 10);
        put(h, n, r == 0 ? "" : r == 1 ? "user@example.com" : r == 2 ? ":80" : "example.com");
        if (rng() % 3 == 0)
            put(h, n, ":8080");
        put(h, n, "/path?q=1");
    } else {                                            /* origin-form */
        h[(*n)++] = '/';
        size_t length = (size_t)(rng() % (rng() % 4 == 0 ? 300 : 70));
        for (size_t k = 0; k < length; k++) {
            if (rng() % 30 == 0) {                      /* a percent-encoding, valid or not */
                static const char hex[] = "0123456789abcdefABCDEF";
                h[(*n)++] = '%';
                h[(*n)++] = rng() % 20 ? (uint8_t)hex[rng() % 22] : (uint8_t)'G';
                h[(*n)++] = rng() % 20 ? (uint8_t)hex[rng() % 22] : (uint8_t)' ';
            } else {
                h[(*n)++] = target_octet();
            }
        }
        if (rng() % 40 == 0)                            /* an octet a target may not hold */
            h[*n - (length > 0 ? 1 + rng() % (length < 8 ? length : 8) : 0)] = (uint8_t)"\"<>\\^`{|}#\x7f\x80\x01"[rng() % 13];
    }
    put(h, n, " ");
    put(h, n, versions[rng() % (sizeof versions / sizeof versions[0])]);
    put(h, n, rng() % 60 ? "\r\n" : "\n");
}

/* framing_line: appends one field line that a rule reads (Host, Content-Length,
 * Transfer-Encoding, Connection, Expect, TE, Upgrade), in a random case, with a value that
 * passes the rule or fails it: every branch of H1_FIELD_RULES, which request.asm expands twice
 * (the classic flow's ha_h1_fields, which v1 runs, and the one-pass flow's ha_h1_fields_v2), so
 * each line here reaches both. That includes HTAB as the OWS inside a list (each list rule skips
 * OWS at its own places), and tokens of the length a rule compares that are not the word it
 * looks for ("closx", "keep-alivx", "compress"). */
static void framing_line(uint8_t *h, size_t *n)
{
    static const char *const lines[] = {
        "Host: example.com", "host: example.com:8080", "Host: [::1]", "Host: a b", "Host:",
        "Content-Length: 12", "content-length: 0", "Content-Length: 12, 12", "Content-Length: 1, 2",
        "Content-Length: -1", "Content-Length: 99999999999999999999", "Content-Length:",
        "Content-Length: 12,\t12", "Content-Length: 12\t,12",
        "Transfer-Encoding: chunked", "transfer-encoding: gzip, chunked", "Transfer-Encoding: chunked, gzip",
        "Transfer-Encoding: chunked;x=1", "Transfer-Encoding: \"q\"", "Transfer-Encoding: ,",
        "Transfer-Encoding: gzip,\tchunked", "Transfer-Encoding: gzip\t,chunked", "Transfer-Encoding: chunked\t;x",
        "Connection: close", "connection: keep-alive", "Connection: Upgrade, close", "Connection: x y",
        "Connection: close,\tkeep-alive", "Connection: closx", "Connection: keep-alivx",
        "Expect: 100-continue", "expect: 100-CONTINUE", "Expect: 200-ok", "Expect:",
        "TE: trailers", "te: gzip, trailers", "TE: deflate", "TE: gzip,\ttrailers", "TE: compress",
        "Upgrade: websocket", "UPGRADE: h2c",
    };
    put(h, n, lines[rng() % (sizeof lines / sizeof lines[0])]);
    put(h, n, "\r\n");
}

/* parse_variety: `randoms` request heads drawn from every part of the grammar (request_line,
 * framing_line, field_line; sometimes a bare LF or no end at all), each checked complete at a
 * random distance from the guard page, with random limits now and then (a max_head at or near
 * the head's length, a short max_target, few max_fields), resumed after a random cut, and, for
 * one in 16, cut after every octet (each prefix against the guard page: the incomplete heads and
 * the refusals the one-pass flow must hand to the classic flow). Returns 0 when every one agreed
 * at every tier, 1 at the first that did not. */
static int parse_variety(long randoms)
{
    static uint8_t h[PAGE];
    static const size_t gaps[] = { 0, 1, 2, 15, 16, 17, 18, 33, 100 };
    long checked = 0;
    for (long i = 0; i < randoms; i++) {
        size_t n = 0;
        request_line(h, &n);
        size_t lines = (size_t)(rng() % 20);
        for (size_t l = 0; l < lines && n < PAGE - 700; l++) {
            unsigned r = (unsigned)(rng() % 10);
            if (r < 3)
                framing_line(h, &n);
            else
                field_line(h, &n);
        }
        unsigned end = (unsigned)(rng() % 100);
        put(h, &n, end < 96 ? "\r\n" : end < 98 ? "\n" : "");

        parse_limits = default_limits;
        if (rng() % 5 == 0) {
            static const uint32_t targets[] = { 0, 1, 3, 15, 16, 17, 64 };
            static const uint32_t fields[] = { PARSE_FIELDS, 1, 2, 3, 5 };
            int64_t heads[] = { 0, (int64_t)n - 1, (int64_t)n, (int64_t)n + 1, (int64_t)n / 2, 17, 40 };
            int64_t head = heads[rng() % (sizeof heads / sizeof heads[0])];
            parse_limits.max_head = head > 0 ? (uint32_t)head : 0;
            parse_limits.max_target = targets[rng() % (sizeof targets / sizeof targets[0])];
            parse_limits.max_fields = fields[rng() % (sizeof fields / sizeof fields[0])];
        }
        size_t gap = gaps[rng() % (sizeof gaps / sizeof gaps[0])];
        if (parse_check(h, n, gap))
            return 1;
        if (parse_check_resumed(h, n, n == 0 ? 0 : (size_t)(rng() % n)))
            return 1;
        checked += 2;
        if (i % 8 == 0) {                               /* a stale *scan_from past the data */
            if (parse_check_from(h, n, gap, n + gap + 1 + (size_t)(rng() % 64)))
                return 1;
            checked++;
        }
        if (i % 16 == 0) {
            for (size_t cut = 1; cut < n; cut++) {
                if (parse_check(h, cut, 0))
                    return 1;
                checked++;
            }
        }
    }
    parse_limits = default_limits;
    printf("httpasm_h1_parse_request: %ld parses of varied heads, prefixes and resumed reads, every tier agrees with v1\n", checked);
    return 0;
}

/* ---- httpasm_h1_parse_response: the client's two flows ---------------------------------------
 * From v2 up, a head searched from its start is parsed in one pass (response.asm's .one_pass and
 * ha_h1_fields_v2 in the response mode), which accepts or hands the head to the classic flow (the
 * head's end searched first, then the status-line, then ha_h1_fields). v1 runs the classic flow
 * alone, so comparing every tier with v1 proves both flows equal, as for requests. One difference
 * shapes the checks: this parser writes its buffer (the classic flow replaces an obs-fold with
 * SP in place), so every tier parses its own fresh copy of the input at the same address, and the
 * octets each leaves behind must equal v1's too. */

/* response_result: everything one response parse hands back: its return value, the scan
 * position, the head record and every field record (pointers into the one address every tier
 * parses at, so equal results have equal pointers). */
typedef struct response_result {
    int64_t ret;
    size_t scan;
    httpasm_response_head head;
    httpasm_field fields[PARSE_FIELDS];
} response_result;

/* The request's method every response parse passes (HTTPASM_METHOD_*): the framing reads it
 * (HEAD: no body; CONNECT: a 2xx opens a tunnel). Drawn per head by response_variety. */
static uint32_t response_method = HTTPASM_METHOD_GET;

/* response_at_from: parses buf[0..len) at the tier now set, with parse_limits and
 * response_method, into *out (zeroed first, so unset parts compare equal), the search resuming at
 * `scan` (0 for a response's first call). Writes buf as the parser does. */
static void response_at_from(uint8_t *buf, size_t len, size_t scan, response_result *out)
{
    memset(out, 0, sizeof *out);
    out->scan = scan;
    out->ret = httpasm_h1_parse_response(buf, len, &out->scan, &parse_limits, response_method, &out->head, out->fields);
}

/* response_same: whether two parses agree on everything: the return, the scan position, every
 * field of the head but its fields pointer (each parse has its own array), and the records the
 * head counts. Returns 1 when they agree, 0 otherwise. */
static int response_same(const response_result *a, const response_result *b)
{
    if (a->ret != b->ret || a->scan != b->scan)
        return 0;
    httpasm_response_head ha = a->head, hb = b->head;
    ha.fields = hb.fields = NULL;
    if (memcmp(&ha, &hb, sizeof ha) != 0)
        return 0;
    uint32_t n = a->head.field_count < PARSE_FIELDS ? a->head.field_count : PARSE_FIELDS;
    return memcmp(a->fields, b->fields, n * sizeof a->fields[0]) == 0;
}

/* response_report: prints a mismatch between a tier's response parse and v1's.
 *   what  which call differed; t  the tier; features  its bits; actual, expected  the results;
 *   buf, n  the input as it was handed over (before the parse wrote it). */
static void response_report(const char *what, size_t t, uint64_t features, const response_result *actual,
                            const response_result *expected, const uint8_t *buf, size_t n)
{
    fprintf(stderr, "httpasm_h1_parse_response (%s) at %s (features %#llx) differs from v1: returned %lld (error %u, %u fields, "
                    "flags %#x, scan %zu), v1 %lld (error %u, %u fields, flags %#x, scan %zu); method %u, limits head %u fields %u\n",
            what, cap_names[t], (unsigned long long)features, (long long)actual->ret, actual->head.error, actual->head.field_count,
            actual->head.flags, actual->scan, (long long)expected->ret, expected->head.error, expected->head.field_count,
            expected->head.flags, expected->scan, response_method, parse_limits.max_head, parse_limits.max_fields);
    dump("head", buf, n);
}

/* response_check_from: one input at every tier, ending `gap` octets before the guard page (the
 * octets between are part of buf: the start of a body, as the client would hand them over), so a
 * version that reads past the head into the unmapped page dies with SIGSEGV. Each tier parses a
 * fresh copy at the same address; its result and the octets it leaves in buf must equal v1's.
 *   head, n  the input (n + gap <= PAGE); gap  the octets after it, before the guard page;
 *   scan     the *scan_from handed in: 0 for a response's first call, or one past the data (a
 *            stale value, which the parser ignores: from v2 up the one-pass flow then runs).
 * Returns 0 when every tier agrees; 1, after reporting the tier and the input, otherwise. Leaves
 * the last tier set. */
static int response_check_from(const uint8_t *head, size_t n, size_t gap, size_t scan)
{
    static response_result expected, actual;
    static uint8_t input[PAGE], after[PAGE];
    uint8_t *buf = page_end - n - gap;
    memcpy(input, head, n);
    for (size_t i = 0; i < gap; i++)
        input[n + i] = (uint8_t)rng();                  /* whatever follows a head */
    for (size_t t = 0; t < TIERS; t++) {
        uint64_t features = httpasm_cpu_limit(caps[t]);
        memcpy(buf, input, n + gap);                    /* the parse may have rewritten the last copy */
        response_at_from(buf, n + gap, scan, t == 0 ? &expected : &actual);
        if (t == 0) {
            memcpy(after, buf, n + gap);
            continue;
        }
        if (!response_same(&expected, &actual) || memcmp(after, buf, n + gap) != 0) {
            response_report(memcmp(after, buf, n + gap) != 0 ? "the octets left in buf" : "the result", t, features, &actual,
                            &expected, input, n + gap);
            fprintf(stderr, "the search resumed at %zu\n", scan);
            return 1;
        }
    }
    return 0;
}

/* response_check: response_check_from for a response's first call (*scan_from 0). */
static int response_check(const uint8_t *head, size_t n, size_t gap)
{
    return response_check_from(head, n, gap, 0);
}

/* response_check_resumed: a head arriving in two reads, as a client sees one: its first `cut`
 * octets (against the guard page: incomplete, or already refused), then all n octets, the second
 * call resuming where the first left the search (at a new address, as a grown buffer may be; the
 * offsets carry over). The resumed call takes the classic flow at every tier. Both calls, and the
 * octets each leaves in its buffer, must agree with v1's at every tier.
 *   head, n  the whole head (n <= PAGE); cut  the first read's length (cut <= n).
 * Returns 0 when every tier agrees; 1, after reporting, otherwise. Leaves the last tier set. */
static int response_check_resumed(const uint8_t *head, size_t n, size_t cut)
{
    static response_result expected[2], actual[2];
    static uint8_t after[2][PAGE];
    for (size_t t = 0; t < TIERS; t++) {
        uint64_t features = httpasm_cpu_limit(caps[t]);
        response_result *r = t == 0 ? expected : actual;
        int first_octets = 0, whole_octets = 0;         /* whether this tier left other octets than v1 */
        uint8_t *first = page_end - cut;
        memcpy(first, head, cut);
        response_at_from(first, cut, 0, &r[0]);
        if (t == 0)
            memcpy(after[0], first, cut);
        else
            first_octets = memcmp(after[0], first, cut) != 0;
        uint8_t *whole = page_end - n;
        memcpy(whole, head, n);
        response_at_from(whole, n, r[0].ret == 0 ? r[0].scan : 0, &r[1]);
        if (t == 0)
            memcpy(after[1], whole, n);
        else
            whole_octets = memcmp(after[1], whole, n) != 0;
        if (t == 0)
            continue;
        if (!response_same(&expected[0], &actual[0]) || first_octets) {
            response_report("the first read", t, features, &actual[0], &expected[0], head, cut);
            return 1;
        }
        if (!response_same(&expected[1], &actual[1]) || whole_octets) {
            response_report("the resumed read", t, features, &actual[1], &expected[1], head, n);
            return 1;
        }
    }
    return 0;
}

/* reason_octet: a random octet a reason-phrase may hold (RFC 9112 4: HTAB, SP, VCHAR,
 * obs-text): mostly letters and SP, now and then HTAB, punctuation or obs-text. */
static uint8_t reason_octet(void)
{
    unsigned r = (unsigned)(rng() % 100);
    if (r < 70)
        return (uint8_t)(r < 12 ? ' ' : 'a' + rng() % 26);
    if (r < 75)
        return '\t';
    if (r < 90)
        return (uint8_t)(0x21 + rng() % 94);            /* any VCHAR */
    return (uint8_t)(0x80 + rng() % 128);               /* obs-text */
}

/* status_line: appends a status-line to h (advancing *n), drawn so that every check of the
 * status-line meets both of its outcomes: versions 1.1, 1.0, a later minor, another major, or
 * malformed; status codes of every framing class (1xx, 2xx, 204, 304, 000-099, past 599) and
 * malformed ones (a letter, two or four digits); one SP each, sometimes none or two; reasons
 * empty, short or up to 300 octets (past several 16-octet steps), sometimes with a CTL, DEL or
 * a bare CR inside; CRLF, or now and then a bare LF. */
static void status_line(uint8_t *h, size_t *n)
{
    static const char *const versions[] = { "HTTP/1.1", "HTTP/1.1", "HTTP/1.1", "HTTP/1.1", "HTTP/1.1", "HTTP/1.1",
                                            "HTTP/1.0", "HTTP/1.0", "HTTP/1.9", "HTTP/2.0", "HTTP/0.9", "HTTP/1.",
                                            "http/1.1", "HTTP/11", "HTTP/1.x", "HTTP 1.1", "HTTPS/1.1" };
    static const char *const codes[] = { "200", "200", "200", "200", "201", "204", "206", "301", "304", "404", "500",
                                         "100", "101", "103", "199", "099", "000", "600", "999", "2x0", "20", "2000" };
    put(h, n, versions[rng() % (sizeof versions / sizeof versions[0])]);
    unsigned r = (unsigned)(rng() % 100);
    put(h, n, r < 96 ? " " : r < 98 ? "  " : "");
    put(h, n, codes[rng() % (sizeof codes / sizeof codes[0])]);
    r = (unsigned)(rng() % 100);
    if (r < 3) {                                        /* no SP after the code (RFC 9112 4: it is required) */
        put(h, n, rng() % 60 ? "\r\n" : "\n");
        return;
    }
    put(h, n, r < 5 ? "\t" : " ");
    r = (unsigned)(rng() % 100);
    size_t length = r < 15 ? 0 : r < 70 ? 1 + (size_t)(rng() % 20) : (size_t)(rng() % 300);
    size_t start = *n;
    for (size_t k = 0; k < length; k++)
        h[(*n)++] = reason_octet();
    if (length > 0 && rng() % 25 == 0) {                /* a CTL inside the reason */
        static const uint8_t ctls[] = { 0x00, 0x01, 0x0B, 0x1F, 0x7F, 0x0D, 0x0D, 0x0A };
        h[start + rng() % length] = ctls[rng() % sizeof ctls];
    }
    put(h, n, rng() % 60 ? "\r\n" : "\n");
}

/* response_framing_line: appends one field line that a response's rules read (Content-Length,
 * Transfer-Encoding, Connection) or that only a request's rules read (Host, Expect, TE, Upgrade:
 * plain fields in a response, so a value a request would refuse passes here), in a random case,
 * with a value that passes its rule or fails it; now and then an obs-fold line continuing it.
 * Every branch of H1_FIELD_RULES that a response reaches, in both expansions (ha_h1_fields, which
 * v1 runs, and ha_h1_fields_v2 in the response mode). */
static void response_framing_line(uint8_t *h, size_t *n)
{
    static const char *const lines[] = {
        "Content-Length: 12", "content-length: 0", "Content-Length: 12, 12", "Content-Length: 1, 2",
        "Content-Length: -1", "Content-Length: 99999999999999999999", "Content-Length:", "Content-Length: 12,\t12",
        "Transfer-Encoding: chunked", "transfer-encoding: gzip, chunked", "Transfer-Encoding: chunked, gzip",
        "Transfer-Encoding: gzip", "Transfer-Encoding: chunked;x=1", "Transfer-Encoding: \"q\"", "Transfer-Encoding: ,",
        "Transfer-Encoding: gzip,\tchunked",
        "Connection: close", "connection: keep-alive", "Connection: Upgrade, close", "Connection: x y",
        "Connection: close,\tkeep-alive", "Connection: closx", "Connection: keep-alivx",
        "Host: a b", "Expect: 200-ok", "TE: deflate", "Upgrade: websocket", "Set-Cookie: a=b; Path=/",
    };
    put(h, n, lines[rng() % (sizeof lines / sizeof lines[0])]);
    put(h, n, "\r\n");
    if (rng() % 20 == 0)                                /* an obs-fold continuing that line */
        put(h, n, rng() % 2 ? " more\r\n" : "\t\tmore, chunked\r\n");
}

/* response_variety: `randoms` response heads drawn from every part of the grammar (status_line,
 * response_framing_line, field_line with its obs-fold lines; sometimes a bare LF or no end at all),
 * for a request method drawn among GET, HEAD, CONNECT and POST, each checked complete at a random
 * distance from the guard page, with random limits now and then (a max_head at or near the head's
 * length, few max_fields), resumed after a random cut, and, for one in 16, cut after every octet
 * (each prefix against the guard page). Before them, every reason-phrase length 0-70 at the
 * distances where its 16-octet steps meet the guard page. Returns 0 when every one agreed at every
 * tier, 1 at the first that did not. */
static int response_variety(long randoms)
{
    static uint8_t h[PAGE];
    static const size_t gaps[] = { 0, 1, 2, 15, 16, 17, 18, 33, 100 };
    static const size_t edges[] = { 0, 1, 15, 16, 17 }; /* a reason's last steps against the guard page */
    static const uint32_t methods[] = { HTTPASM_METHOD_GET, HTTPASM_METHOD_GET, HTTPASM_METHOD_HEAD,
                                        HTTPASM_METHOD_CONNECT, HTTPASM_METHOD_POST };
    long checked = 0;
    parse_limits = default_limits;
    response_method = HTTPASM_METHOD_GET;
    for (size_t reason = 0; reason <= 70; reason++) {
        for (int fields = 0; fields < 2; fields++) {
            size_t n = 0;
            put(h, &n, "HTTP/1.1 200 ");
            for (size_t k = 0; k < reason; k++)
                h[n++] = (uint8_t)('A' + k % 26);
            put(h, &n, fields ? "\r\nContent-Length: 5\r\n\r\n" : "\r\n\r\n");
            for (size_t g = 0; g < sizeof edges / sizeof edges[0]; g++) {
                if (response_check(h, n, edges[g]))
                    return 1;
                checked++;
            }
        }
    }
    for (long i = 0; i < randoms; i++) {
        size_t n = 0;
        status_line(h, &n);
        size_t lines = (size_t)(rng() % 20);
        for (size_t l = 0; l < lines && n < PAGE - 700; l++) {
            unsigned r = (unsigned)(rng() % 10);
            if (r < 3)
                response_framing_line(h, &n);
            else
                field_line(h, &n);
        }
        unsigned end = (unsigned)(rng() % 100);
        put(h, &n, end < 96 ? "\r\n" : end < 98 ? "\n" : "");
        if (rng() % 4 == 0)                             /* the start of the next message, or of a body */
            put(h, &n, rng() % 2 ? "HTTP/1.1 200 OK\r\n" : "hello");

        response_method = methods[rng() % (sizeof methods / sizeof methods[0])];
        parse_limits = default_limits;
        if (rng() % 5 == 0) {
            static const uint32_t fields[] = { PARSE_FIELDS, 1, 2, 3, 5 };
            int64_t heads[] = { 0, (int64_t)n - 1, (int64_t)n, (int64_t)n + 1, (int64_t)n / 2, 17, 40 };
            int64_t head = heads[rng() % (sizeof heads / sizeof heads[0])];
            parse_limits.max_head = head > 0 ? (uint32_t)head : 0;
            parse_limits.max_fields = fields[rng() % (sizeof fields / sizeof fields[0])];
        }
        size_t gap = gaps[rng() % (sizeof gaps / sizeof gaps[0])];
        if (response_check(h, n, gap))
            return 1;
        if (response_check_resumed(h, n, n == 0 ? 0 : (size_t)(rng() % n)))
            return 1;
        checked += 2;
        if (i % 8 == 0) {                               /* a stale *scan_from past the data */
            if (response_check_from(h, n, gap, n + gap + 1 + (size_t)(rng() % 64)))
                return 1;
            checked++;
        }
        if (i % 16 == 0) {
            for (size_t cut = 1; cut < n; cut++) {
                if (response_check(h, cut, 0))
                    return 1;
                checked++;
            }
        }
    }
    parse_limits = default_limits;
    response_method = HTTPASM_METHOD_GET;
    printf("httpasm_h1_parse_response: %ld parses of varied heads, prefixes and resumed reads, every tier agrees with v1\n", checked);
    return 0;
}

/* ---- httpasm_h2_request, httpasm_h2_trailers: HTTP/2's request rules (h2_request.asm) --------
 * Two checks have versions: h2_name (an HTTP/2 field name: tchars but A-Z; octet by octet at v1,
 * 16 octets a step from v2 by ha_span_v2 with ha_ltchar_lo) and the :path (octet by octet at v1,
 * runs of target octets between percent-encodings from v2, ha_span_v2 with ha_target_lo). Every
 * tier must give v1's answer: the return, the request record, and each record as the rules leave
 * it (its id, its trailer flag). One string of each list, a name or the :path, ends against the
 * guard page, so a version that reads past a string dies with SIGSEGV. */

#define H2_FIELDS 40

/* h2_result: everything one check hands back. The request's pointers point into the strings
 * and into h2_records, which every tier's check reuses, so equal results have equal pointers. */
typedef struct h2_result {
    int ret;
    httpasm_request request;
    httpasm_field fields[H2_FIELDS];
} h2_result;

/* The records a check is handed: a fresh copy of the list per tier (the rules write ids and
 * flags into them). */
static httpasm_field h2_records[H2_FIELDS];

/* How many lists v1 accepted: printed with the total, so a generator that drifts into refusing
 * everything (which would compare little) shows. */
static long h2_accepted;

/* h2_check: one header list at every tier, as a request's (trailers 0) or as a trailer
 * section's (trailers 1).
 *   list, count  the records (count <= H2_FIELDS), their strings placed by the caller.
 * Returns 0 when every tier agrees with v1; 1, after reporting, otherwise. Leaves the last tier
 * set. */
static int h2_check(const httpasm_field *list, uint32_t count, int trailers)
{
    static h2_result expected, actual;
    for (size_t t = 0; t < TIERS; t++) {
        uint64_t features = httpasm_cpu_limit(caps[t]);
        h2_result *r = t == 0 ? &expected : &actual;
        memset(r, 0, sizeof *r);
        memcpy(h2_records, list, count * sizeof list[0]);
        r->ret = trailers ? httpasm_h2_trailers(h2_records, count) : httpasm_h2_request(h2_records, count, &r->request);
        memcpy(r->fields, h2_records, count * sizeof list[0]);
        if (t == 0) {
            h2_accepted += r->ret == 0;
            continue;
        }
        if (actual.ret != expected.ret || memcmp(&actual.request, &expected.request, sizeof actual.request) != 0
            || memcmp(actual.fields, expected.fields, count * sizeof actual.fields[0]) != 0) {
            fprintf(stderr, "httpasm_h2_%s at %s (features %#llx) differs from v1: returned %d (error %u), v1 %d (error %u); %u records:\n",
                    trailers ? "trailers" : "request", cap_names[t], (unsigned long long)features, actual.ret, actual.request.error,
                    expected.ret, expected.request.error, count);
            for (uint32_t i = 0; i < count; i++) {
                dump("  name", list[i].name, list[i].name_length);
                dump("  value", list[i].value, list[i].value_length);
            }
            return 1;
        }
    }
    return 0;
}

/* h2_name_octet: a random octet an HTTP/2 field name may hold (a tchar but A-Z): mostly lower-case
 * letters, then "-", digits, and every other punctuation tchar now and then. */
static uint8_t h2_name_octet(void)
{
    static const char octets[] = "abcdefghijklmnopqrstuvwxyz-0123456789!#$%&'*+.^_`|~";
    unsigned r = (unsigned)(rng() % 100);
    if (r < 85)
        return (uint8_t)octets[rng() % 26];
    if (r < 95)
        return (uint8_t)octets[26 + rng() % 11];
    return (uint8_t)octets[rng() % (sizeof octets - 1)];
}

/* h2_flaw: an octet an HTTP/2 field name may not hold, of every kind the checks tell apart: an
 * upper-case letter (A, Z and between), a non-tchar in the visible range, SP, a CTL, DEL,
 * obs-text. */
static uint8_t h2_flaw(void)
{
    static const uint8_t flaws[] = { 'A', 'Z', 'M', '@', ':', '"', '(', ')', ',', '/', ';', '<', '=', '>', '?', '[', '\\', ']', '{', '}',
                                     ' ', 0x00, 0x09, 0x1F, 0x7F, 0x80, 0xC1, 0xFF };
    return flaws[rng() % sizeof flaws];
}

/* h2_path_text: writes a :path of n octets (n >= 1) to p: "/" then target octets, a
 * percent-encoding now and then (valid, with a non-HEXDIG, or cut by the value's end), and, when
 * flawed is nonzero, one octet a target may not hold at a random place past the "/". */
static void h2_path_text(uint8_t *p, size_t n, int flawed)
{
    static const char hex[] = "0123456789abcdefABCDEF";
    p[0] = '/';
    for (size_t i = 1; i < n; i++) {
        if (rng() % 12 == 0) {
            p[i] = '%';
            if (i + 1 < n)
                p[i + 1] = rng() % 100 ? (uint8_t)hex[rng() % 22] : (uint8_t)'g';
            if (i + 2 < n)
                p[i + 2] = rng() % 100 ? (uint8_t)hex[rng() % 22] : (uint8_t)':';
            i += 2;
        } else {
            p[i] = target_octet();
        }
    }
    if (flawed && n > 1) {
        static const uint8_t bad[] = { ' ', '"', '<', '>', '\\', '^', '`', '{', '|', '}', '#', 0x00, 0x09, 0x7F, 0x80, 0xFF };
        p[1 + rng() % (n - 1)] = bad[rng() % sizeof bad];
    }
}

/* h2_put: a record for name and value (pointers to strings the caller keeps). */
static httpasm_field h2_put(const uint8_t *name, size_t name_length, const uint8_t *value, size_t value_length)
{
    httpasm_field f;
    memset(&f, 0, sizeof f);
    f.name = name;
    f.name_length = (uint32_t)name_length;
    f.value = value;
    f.value_length = (uint32_t)value_length;
    return f;
}

/* h2_tiers: HTTP/2 header lists at every tier. First, every name length 1-70 with no flaw or a
 * flaw at each place, and every :path length 1-70 with a percent-encoding (or a flaw) at each
 * place, each string ending against the guard page; then `randoms` requests (and trailer
 * sections) of up to 30 regular fields: names of 1-70 octets, some known (their rules run),
 * some flawed, an empty one now and then, a :path of up to 300 octets or "*", pseudo-fields
 * sometimes missing, repeated or after a regular field, and the guard page behind a name or the
 * :path. Returns 0 when every list agreed at every tier, 1 at the first that did not. */
static int h2_tiers(long randoms)
{
    static uint8_t arena[16384];
    static httpasm_field list[H2_FIELDS];
    static const char *const known[][2] = {
        { "accept", "text/html" }, { "user-agent", "Mozilla/5.0 (X11; Linux x86_64)" }, { "content-length", "12" },
        { "te", "trailers" }, { "host", "example.com" }, { "cookie", "a=b" }, { "expect", "100-continue" },
        { "content-type", "text/plain" }, { "accept-encoding", "gzip, br" },
    };
    long checked = 0;
    const uint8_t *m = (const uint8_t *)"GET", *s = (const uint8_t *)"https", *a = (const uint8_t *)"example.com";
    /* Every name length, the name against the guard page, clean or with one flaw at each place. */
    for (size_t n = 1; n <= 70; n++) {
        for (size_t flaw = 0; flaw <= n; flaw++) {
            uint8_t *name = page_end - n;
            for (size_t i = 0; i < n; i++)
                name[i] = h2_name_octet();
            if (flaw > 0)
                name[flaw - 1] = h2_flaw();
            uint32_t c = 0;
            list[c++] = h2_put((const uint8_t *)":method", 7, m, 3);
            list[c++] = h2_put((const uint8_t *)":scheme", 7, s, 5);
            list[c++] = h2_put((const uint8_t *)":authority", 10, a, 11);
            list[c++] = h2_put((const uint8_t *)":path", 5, (const uint8_t *)"/", 1);
            list[c++] = h2_put(name, n, (const uint8_t *)"v", 1);
            if (h2_check(list, c, 0) || h2_check(list + 4, 1, 1))
                return 1;
            checked += 2;
        }
    }
    /* Every :path length, against the guard page, with a percent-encoding or a flaw at each place. */
    for (size_t n = 1; n <= 70; n++) {
        for (size_t at = 0; at <= n; at++) {
            uint8_t *path = page_end - n;
            path[0] = '/';
            for (size_t i = 1; i < n; i++)
                path[i] = target_octet();
            if (at > 0 && at < n) {
                if (rng() % 3 == 0) {
                    path[at] = h2_flaw();               /* an octet a target may not hold, or a letter */
                } else {
                    path[at] = '%';                     /* its HEXDIG inside the value, or cut by its end */
                    if (at + 1 < n)
                        path[at + 1] = rng() % 8 ? (uint8_t)"0123456789abcdefABCDEF"[rng() % 22] : (uint8_t)'z';
                    if (at + 2 < n)
                        path[at + 2] = rng() % 8 ? (uint8_t)"0123456789abcdefABCDEF"[rng() % 22] : (uint8_t)'%';
                }
            }
            uint32_t c = 0;
            list[c++] = h2_put((const uint8_t *)":method", 7, m, 3);
            list[c++] = h2_put((const uint8_t *)":scheme", 7, s, 5);
            list[c++] = h2_put((const uint8_t *)":authority", 10, a, 11);
            list[c++] = h2_put((const uint8_t *)":path", 5, path, n);
            if (h2_check(list, c, 0))
                return 1;
            checked++;
        }
    }
    /* Varied requests and trailer sections. */
    for (long k = 0; k < randoms; k++) {
        size_t used = 0;
        uint32_t c = 0;
        static const char *const methods[] = { "GET", "GET", "POST", "OPTIONS", "CONNECT", "HEAD", "get" };
        const char *method = methods[rng() % (sizeof methods / sizeof methods[0])];
        size_t path_length = rng() % 10 == 0 ? 1 : 1 + (size_t)(rng() % (rng() % 4 == 0 ? 300 : 70));
        uint8_t *path = arena + used;
        if (rng() % 20 == 0) {
            path[0] = '*';
            path_length = 1;
        } else {
            h2_path_text(path, path_length, rng() % 15 == 0);
        }
        used += path_length;
        int pseudo_late = rng() % 30 == 0;              /* a pseudo-field after a regular one */
        if (rng() % 40 != 0)
            list[c++] = h2_put((const uint8_t *)":method", 7, (const uint8_t *)method, strlen(method));
        if (rng() % 40 != 0 && strcmp(method, "CONNECT") != 0)
            list[c++] = h2_put((const uint8_t *)":scheme", 7, s, 5);
        if (rng() % 8 != 0)
            list[c++] = h2_put((const uint8_t *)":authority", 10, a, 11);
        if ((rng() % 40 != 0 && strcmp(method, "CONNECT") != 0) || rng() % 4 == 0)
            list[c++] = h2_put((const uint8_t *)":path", 5, path, path_length);
        if (rng() % 50 == 0 && c > 0) {                 /* a repeated pseudo-field */
            list[c] = list[c - 1];
            c++;
        }
        size_t regular = (size_t)(rng() % 31);
        for (size_t i = 0; i < regular && c < H2_FIELDS - 1 && used < sizeof arena - 600; i++) {
            if (rng() % 4 == 0) {
                const char *const *pair = known[rng() % (sizeof known / sizeof known[0])];
                list[c++] = h2_put((const uint8_t *)pair[0], strlen(pair[0]), (const uint8_t *)pair[1], strlen(pair[1]));
                continue;
            }
            if (rng() % 150 == 0) {                     /* connection-specific: refused in HTTP/2 */
                list[c++] = h2_put((const uint8_t *)"connection", 10, (const uint8_t *)"close", 5);
                continue;
            }
            size_t n = rng() % 200 == 0 ? 0 : 1 + (size_t)(rng() % (rng() % 4 == 0 ? 70 : 24));
            uint8_t *name = arena + used;
            for (size_t j = 0; j < n; j++)
                name[j] = h2_name_octet();
            if (n > 0 && rng() % 50 == 0)               /* rare per field, so most lists reach their end */
                name[rng() % n] = h2_flaw();
            used += n;
            size_t v = (size_t)(rng() % 80);
            uint8_t *value = arena + used;
            field_value_valid(value, v);
            if (v > 0 && (value[0] == ' ' || value[0] == '\t'))
                value[0] = 'x';                         /* HTTP/2 refuses whitespace at a value's ends */
            if (v > 0 && (value[v - 1] == ' ' || value[v - 1] == '\t'))
                value[v - 1] = 'y';
            used += v;
            list[c++] = h2_put(name, n, value, v);
        }
        if (pseudo_late && c > 1)
            list[c++] = h2_put((const uint8_t *)":path", 5, path, path_length);
        /* The guard page behind one string: the :path, or one regular name. */
        if (c > 0) {
            uint32_t victim = (uint32_t)(rng() % c);
            int use_value = list[victim].name_length > 0 && list[victim].name[0] == ':';
            size_t length = use_value ? list[victim].value_length : list[victim].name_length;
            const uint8_t *from = use_value ? list[victim].value : list[victim].name;
            if (length > 0 && length <= 512) {
                uint8_t *moved = page_end - length;
                memmove(moved, from, length);
                if (use_value)
                    list[victim].value = moved;
                else
                    list[victim].name = moved;
            }
        }
        if (h2_check(list, c, 0))
            return 1;
        checked++;
        if (k % 4 == 0) {                               /* the regular fields as a trailer section */
            uint32_t first = 0;
            while (first < c && list[first].name_length > 0 && list[first].name[0] == ':')
                first++;
            if (h2_check(list + first, c - first, 1))
                return 1;
            checked++;
        }
    }
    printf("httpasm_h2_request, httpasm_h2_trailers: %ld header lists (%ld accepted), every tier agrees with v1\n", checked, h2_accepted);
    return 0;
}

/* ---- httpasm_sha256: SHA-256's compression by versions (crypto/sha256.asm) -------------------
 * v1 is the scalar compression, v2 and up the SHA extensions' (when the CPU has them). Each
 * message ends against the guard page and is hashed at once and in random pieces at every tier;
 * the digests must equal v1's, so a version that reads past the message or computes another
 * state fails here. */

/* sha256_pieces: the digest of p[0..n) fed in random pieces (empty ones too) to a running hash.
 *   p, n  the message; digest  out, 32 octets. */
static void sha256_pieces(const uint8_t *p, size_t n, uint8_t digest[32])
{
    httpasm_sha256_ctx h;
    httpasm_sha256_init(&h);
    size_t at = 0;
    while (at < n) {
        size_t piece = (size_t)(rng() % (rng() % 4 == 0 ? 300 : 70));
        if (piece > n - at)
            piece = n - at;
        httpasm_sha256_update(&h, p + at, piece);
        at += piece;
    }
    httpasm_sha256_final(&h, digest);
}

/* sha256_tiers: every length 0-300 and `randoms` random ones to 20,000 octets, each message's
 * last octet the page's last, at every tier, at once and in pieces. Returns 0 when every digest
 * equals v1's, 1 at the first that does not. */
static int sha256_tiers(long randoms)
{
    long checked = 0;
    for (long i = -301; i < randoms; i++) {
        size_t n = i < 0 ? (size_t)(i + 301) : (size_t)(rng() % (rng() % 8 == 0 ? 20000 : 600));
        if (n > PAGE)
            n = PAGE;                       /* the message stays in the readable page */
        uint8_t *message = page_end - n;
        for (size_t k = 0; k < n; k++)
            message[k] = (uint8_t)rng();
        uint8_t expected[32], once[32], pieces[32];
        httpasm_cpu_limit(caps[0]);
        httpasm_sha256(message, n, expected);
        for (size_t t = 1; t < TIERS; t++) {
            uint64_t features = httpasm_cpu_limit(caps[t]);
            httpasm_sha256(message, n, once);
            sha256_pieces(message, n, pieces);
            if (memcmp(once, expected, 32) != 0 || memcmp(pieces, expected, 32) != 0) {
                fprintf(stderr, "httpasm_sha256 at %s (features %#llx) differs from v1 on %zu octets (%s)\n", cap_names[t],
                        (unsigned long long)features, n, memcmp(once, expected, 32) != 0 ? "at once" : "in pieces");
                dump("message", message, n < 128 ? n : 128);
                return 1;
            }
            checked++;
        }
    }
    printf("httpasm_sha256: %ld digests at tiers above v1, every one equal to v1's\n", checked);
    return 0;
}

/* ---- httpasm_sha512, httpasm_sha384: SHA-512's compression by versions (crypto/sha512.asm) -----
 * v1 is the scalar compression, v3 the AVX2 schedule of two blocks at once with BMI2 rounds (a
 * lone last block in both lanes). As for SHA-256: every message ends against the guard page, is
 * hashed at once and in pieces at every tier, and must give v1's digest. */

/* sha512_pieces: the SHA-512 (sha384 = 1: SHA-384) digest of p[0..n) fed in random pieces (empty
 * ones too, and pieces past the 128-octet block) to a running hash.
 *   p, n  the message; digest  out, 64 (48) octets. */
static void sha512_pieces(const uint8_t *p, size_t n, int sha384, uint8_t digest[64])
{
    httpasm_sha512_ctx h;
    if (sha384)
        httpasm_sha384_init(&h);
    else
        httpasm_sha512_init(&h);
    size_t at = 0;
    while (at < n) {
        size_t piece = (size_t)(rng() % (rng() % 4 == 0 ? 600 : 140));
        if (piece > n - at)
            piece = n - at;
        httpasm_sha512_update(&h, p + at, piece);
        at += piece;
    }
    if (sha384)
        httpasm_sha384_final(&h, digest);
    else
        httpasm_sha512_final(&h, digest);
}

/* sha512_tiers: SHA-512 and SHA-384 of every length 0-600 (the v3 compression's lone and paired
 * blocks, the padding's one and two blocks) and `randoms` random ones to 20,000 octets, each
 * message's last octet the page's last, at every tier, at once and in pieces. Returns 0 when
 * every digest equals v1's, 1 at the first that does not. */
static int sha512_tiers(long randoms)
{
    long checked = 0;
    for (long i = -601; i < randoms; i++) {
        size_t n = i < 0 ? (size_t)(i + 601) : (size_t)(rng() % (rng() % 8 == 0 ? 20000 : 1200));
        if (n > PAGE)
            n = PAGE;                       /* the message stays in the readable page */
        uint8_t *message = page_end - n;
        for (size_t k = 0; k < n; k++)
            message[k] = (uint8_t)rng();
        for (int sha384 = 0; sha384 <= 1; sha384++) {
            size_t size = sha384 ? 48 : 64;
            uint8_t expected[64], once[64], pieces[64];
            httpasm_cpu_limit(caps[0]);
            if (sha384)
                httpasm_sha384(message, n, expected);
            else
                httpasm_sha512(message, n, expected);
            for (size_t t = 1; t < TIERS; t++) {
                uint64_t features = httpasm_cpu_limit(caps[t]);
                if (sha384)
                    httpasm_sha384(message, n, once);
                else
                    httpasm_sha512(message, n, once);
                sha512_pieces(message, n, sha384, pieces);
                if (memcmp(once, expected, size) != 0 || memcmp(pieces, expected, size) != 0) {
                    fprintf(stderr, "httpasm_%s at %s (features %#llx) differs from v1 on %zu octets (%s)\n",
                            sha384 ? "sha384" : "sha512", cap_names[t], (unsigned long long)features, n,
                            memcmp(once, expected, size) != 0 ? "at once" : "in pieces");
                    dump("message", message, n < 128 ? n : 128);
                    return 1;
                }
                checked++;
            }
        }
    }
    printf("httpasm_sha512/384: %ld digests at tiers above v1, every one equal to v1's\n", checked);
    return 0;
}

/* ---- httpasm_sha3_*, httpasm_shake*: by versions (crypto/sha3.asm) -----------------------------
 * The Keccak permutation has v1 (rol, not + and) and v3 (rorx, andn); every tier must give v1's
 * output, at once and in pieces. */

/* sha3_pieces: the running form of one kind (0-3 SHA3-224..512, 4 SHAKE128, 5 SHAKE256): the
 * message in random pieces (empty ones too), then the final or, for SHAKE, out_n octets
 * squeezed in random pieces. */
static void sha3_pieces(const uint8_t *message, size_t n, int kind, uint8_t *out, size_t out_n)
{
    static void (*const init[6])(httpasm_sha3_ctx *) = { httpasm_sha3_224_init, httpasm_sha3_256_init, httpasm_sha3_384_init,
                                                          httpasm_sha3_512_init, httpasm_shake128_init, httpasm_shake256_init };
    httpasm_sha3_ctx h;
    init[kind](&h);
    size_t at = 0;
    while (at < n) {
        size_t piece = rng() % 4 == 0 ? 0 : 1 + rng() % 300;
        if (piece > n - at)
            piece = n - at;
        httpasm_sha3_update(&h, message + at, piece);
        at += piece;
    }
    if (kind < 4) {
        httpasm_sha3_final(&h, out);
        return;
    }
    size_t got = 0;
    while (got < out_n) {
        size_t piece = rng() % 4 == 0 ? 0 : 1 + rng() % 200;
        if (piece > out_n - got)
            piece = out_n - got;
        httpasm_shake_squeeze(&h, out + got, piece);
        got += piece;
    }
}

/* sha3_once: the one-shot form of one kind, out_n octets for SHAKE. */
static void sha3_once(const uint8_t *message, size_t n, int kind, uint8_t *out, size_t out_n)
{
    switch (kind) {
    case 0: httpasm_sha3_224(message, n, out); break;
    case 1: httpasm_sha3_256(message, n, out); break;
    case 2: httpasm_sha3_384(message, n, out); break;
    case 3: httpasm_sha3_512(message, n, out); break;
    case 4: httpasm_shake128(message, n, out, out_n); break;
    default: httpasm_shake256(message, n, out, out_n); break;
    }
}

/* sha3_tiers: every length 0-400 (the padding at every place of every rate's block) and `randoms`
 * random ones to 20,000 octets, each message's last octet the page's last, for all six kinds (SHAKE
 * with 1 to 500 octets out), at every tier, at once and in pieces, the output followed by a
 * canary. Returns 0 when every output equals v1's, 1 at the first that does not. */
static int sha3_tiers(long randoms)
{
    static const char *const names[6] = { "sha3_224", "sha3_256", "sha3_384", "sha3_512", "shake128", "shake256" };
    static const size_t digest[4] = { 28, 32, 48, 64 };
    long checked = 0;
    for (long i = -401; i < randoms; i++) {
        size_t n = i < 0 ? (size_t)(i + 401) : (size_t)(rng() % (rng() % 8 == 0 ? 20000 : 1200));
        if (n > PAGE)
            n = PAGE;                       /* the message stays in the readable page */
        uint8_t *message = page_end - n;
        for (size_t k = 0; k < n; k++)
            message[k] = (uint8_t)rng();
        for (int kind = 0; kind < 6; kind++) {
            size_t out_n = kind < 4 ? digest[kind] : 1 + (size_t)(rng() % 500);
            uint8_t expected[512], once[512 + 16], pieces[512];
            httpasm_cpu_limit(caps[0]);
            sha3_once(message, n, kind, expected, out_n);
            for (size_t t = 1; t < TIERS; t++) {
                uint64_t features = httpasm_cpu_limit(caps[t]);
                memset(once, 0xC3, sizeof once);
                sha3_once(message, n, kind, once, out_n);
                sha3_pieces(message, n, kind, pieces, out_n);
                int canary = 1;
                for (size_t k = out_n; k < out_n + 16; k++)
                    canary &= once[k] == 0xC3;
                if (!canary || memcmp(once, expected, out_n) != 0 || memcmp(pieces, expected, out_n) != 0) {
                    fprintf(stderr, "httpasm_%s at %s (features %#llx) differs from v1 on %zu octets, %zu out (%s)\n", names[kind],
                            cap_names[t], (unsigned long long)features, n, out_n,
                            !canary ? "wrote past its output" : memcmp(once, expected, out_n) != 0 ? "at once" : "in pieces");
                    dump("message", message, n < 128 ? n : 128);
                    return 1;
                }
                checked++;
            }
        }
    }
    printf("httpasm_sha3/shake: %ld outputs at tiers above v1, every one equal to v1's\n", checked);
    return 0;
}

/* ---- httpasm_aes_*: the block cipher by versions (crypto/aes.asm) -----------------------------
 * v1 is the constant-time bitsliced cipher with its own key schedule (SubWord by the bitsliced
 * S-box), AES-NI the other (aeskeygenassist for the schedule). A key holds both versions' round
 * keys, so a key made at one tier must work at every other: each key here is made at every tier
 * and each of those used at every tier, on a block that ends against the guard page. */

/* aes_tiers: `randoms` random keys of 16 and 32 octets. Returns 0 when every key made at any
 * tier is the same octet for octet and encrypts the block as v1's key does at v1; 1 at the
 * first difference. */
static int aes_tiers(long randoms)
{
    long checked = 0;
    uint8_t *block = page_end - 16;         /* the block's last octet is the page's last */
    for (long i = 0; i < randoms; i++) {
        uint8_t key[32];
        size_t length = rng() % 2 ? 32 : 16;
        for (size_t k = 0; k < length; k++)
            key[k] = (uint8_t)rng();
        for (size_t k = 0; k < 16; k++)
            block[k] = (uint8_t)rng();
        httpasm_aes_key made[TIERS];
        uint8_t expected[16];
        for (size_t t = 0; t < TIERS; t++) {
            httpasm_cpu_limit(caps[t]);
            if (httpasm_aes_init(&made[t], key, length) != 0) {
                fprintf(stderr, "httpasm_aes_init refused a %zu-octet key at %s\n", length, cap_names[t]);
                return 1;
            }
            if (memcmp(&made[t], &made[0], sizeof made[0]) != 0) {
                fprintf(stderr, "httpasm_aes_init at %s made another key than at v1\n", cap_names[t]);
                dump("key", key, length);
                return 1;
            }
        }
        httpasm_cpu_limit(caps[0]);
        httpasm_aes_encrypt_block(&made[0], block, expected);
        for (size_t t = 0; t < TIERS; t++) {
            for (size_t u = 0; u < TIERS; u++) {
                uint8_t out[16];
                uint64_t features = httpasm_cpu_limit(caps[u]);
                httpasm_aes_encrypt_block(&made[t], block, out);
                if (memcmp(out, expected, 16) != 0) {
                    fprintf(stderr, "httpasm_aes_encrypt_block at %s (features %#llx) with a key made at %s differs from v1\n",
                            cap_names[u], (unsigned long long)features, cap_names[t]);
                    dump("key", key, length);
                    dump("block", block, 16);
                    return 1;
                }
                checked++;
            }
        }
    }
    printf("httpasm_aes: %ld keys and blocks, made and used at every pair of tiers, every one equal to v1's\n", checked);
    return 0;
}

/* ---- httpasm_aes_gcm_*: AES-GCM by versions (crypto/gcm.asm) ----------------------------------
 * v1 (the bitsliced cipher, eight counters a call; GHASH by integer multiplications) against
 * AES-NI with PCLMULQDQ (eight blocks a step, GHASH aggregated over eight powers of H). Keys made
 * at every tier must be the same octets; every tier's seal must give v1's ciphertext and tag,
 * and every tier's open must give the plaintext back and refuse a flipped tag bit with zeros.
 * The text ends against the guard page (an over-read faults), and the output is followed by
 * canary octets (an over-write shows). */

/* gcm_tiers: `randoms` random keys, nonces, AAD (0-300 octets) and texts (0-3000 octets, a
 * third of them multiples of 16). Returns 0 when every tier agrees with v1, 1 at the first
 * difference. */
static int gcm_tiers(long randoms)
{
    long checked = 0;
    static uint8_t out[3000 + 64], aad[300];
    for (long i = 0; i < randoms; i++) {
        uint8_t key[32], nonce[12], tag[16], expected_tag[16];
        size_t key_length = rng() % 2 ? 32 : 16;
        size_t n = (size_t)(rng() % 3001);
        if (rng() % 3 == 0)
            n &= ~(size_t)15;
        size_t aad_length = (size_t)(rng() % 301);
        for (size_t k = 0; k < key_length; k++)
            key[k] = (uint8_t)rng();
        for (size_t k = 0; k < 12; k++)
            nonce[k] = (uint8_t)rng();
        for (size_t k = 0; k < aad_length; k++)
            aad[k] = (uint8_t)rng();
        uint8_t *text = page_end - n;       /* the plaintext, then (for open) the ciphertext */
        static uint8_t plain[3000];
        for (size_t k = 0; k < n; k++)
            plain[k] = text[k] = (uint8_t)rng();
        static httpasm_aes_gcm_key made[TIERS];
        static uint8_t expected[3000];
        for (size_t t = 0; t < TIERS; t++) {
            httpasm_cpu_limit(caps[t]);
            if (httpasm_aes_gcm_init(&made[t], key, key_length) != 0 || memcmp(&made[t], &made[0], sizeof made[0]) != 0) {
                fprintf(stderr, "httpasm_aes_gcm_init at %s refused the key or made other octets than at v1\n", cap_names[t]);
                return 1;
            }
        }
        for (size_t t = 0; t < TIERS; t++) {
            uint64_t features = httpasm_cpu_limit(caps[t]);
            memset(out, 0xC3, sizeof out);
            if (httpasm_aes_gcm_seal(&made[t], nonce, aad, aad_length, text, n, out, tag) != 0) {
                fprintf(stderr, "httpasm_aes_gcm_seal at %s refused %zu octets\n", cap_names[t], n);
                return 1;
            }
            for (size_t k = n; k < sizeof out; k++) {
                if (out[k] != 0xC3) {
                    fprintf(stderr, "httpasm_aes_gcm_seal at %s wrote past %zu octets\n", cap_names[t], n);
                    return 1;
                }
            }
            if (t == 0) {
                memcpy(expected, out, n);
                memcpy(expected_tag, tag, 16);
            } else if (memcmp(out, expected, n) != 0 || memcmp(tag, expected_tag, 16) != 0) {
                fprintf(stderr, "httpasm_aes_gcm_seal at %s (features %#llx) differs from v1 on %zu octets, %zu of AAD\n",
                        cap_names[t], (unsigned long long)features, n, aad_length);
                return 1;
            }
            /* open: the ciphertext moved against the guard page, back to the text */
            uint8_t *sealed = page_end - n;
            memcpy(sealed, expected, n);
            memset(out, 0xC3, sizeof out);
            if (httpasm_aes_gcm_open(&made[t], nonce, aad, aad_length, sealed, n, expected_tag, out) != 0 ||
                memcmp(out, plain, n) != 0) {
                fprintf(stderr, "httpasm_aes_gcm_open at %s refused or misread v1's seal (%zu octets)\n", cap_names[t], n);
                return 1;
            }
            uint8_t bad[16];
            memcpy(bad, expected_tag, 16);
            bad[rng() % 16] ^= (uint8_t)(1u << (rng() % 8));
            if (httpasm_aes_gcm_open(&made[t], nonce, aad, aad_length, sealed, n, bad, out) != -1) {
                fprintf(stderr, "httpasm_aes_gcm_open at %s accepted a flipped tag bit\n", cap_names[t]);
                return 1;
            }
            for (size_t k = 0; k < n; k++) {
                if (out[k] != 0) {
                    fprintf(stderr, "httpasm_aes_gcm_open at %s left plaintext after a refusal\n", cap_names[t]);
                    return 1;
                }
            }
            memcpy(text, plain, n);         /* the plaintext back against the guard page */
            checked++;
        }
    }
    printf("httpasm_aes_gcm: %ld seals and opens at every tier (keys made at every tier), every one equal to v1's\n", checked);
    return 0;
}

/* ---- httpasm_chacha20, httpasm_poly1305, httpasm_chacha20_poly1305_*: by versions ------------
 * (crypto/chacha20_poly1305.asm) v1 (SSE2, four blocks a step, Poly1305 by mul), v2 (the same
 * with pshufb's rotations) and v3 (AVX2, eight blocks a step, Poly1305 by mulx), each stitching
 * Poly1305 into its AEAD steps, and each sending short work through two horizontal blocks. Every
 * tier must give v1's keystream, tags, ciphertexts and plaintexts, and refuse a flipped tag bit
 * with zeros. Inputs end against the guard page (an over-read faults), outputs are followed by
 * canary octets (an over-write shows). */

/* chacha_check_canary: 0 when out[n..size) still holds the canary 0xC3 everywhere; otherwise a
 * report naming the function and tier, and 1. */
static int chacha_check_canary(const uint8_t *out, size_t n, size_t size, const char *what, size_t t)
{
    for (size_t k = n; k < size; k++) {
        if (out[k] != 0xC3) {
            fprintf(stderr, "%s at %s wrote past %zu octets\n", what, cap_names[t], n);
            return 1;
        }
    }
    return 0;
}

/* chacha_tiers: `randoms` random keys, nonces, counters (a fifth just below the 32-bit wrap),
 * AAD (0-300 octets) and texts (0-3000 octets, a third of them multiples of 64, and every tenth a
 * 16 KiB + 13 record), through the raw cipher, Poly1305 and the AEAD. Returns 0 when every tier
 * agrees with v1, 1 at the first difference. */
static int chacha_tiers(long randoms)
{
    long checked = 0;
    enum { MAX = 16384 + 13 };
    /* expected_stream holds v1's raw keystream output, expected v1's AEAD ciphertext: two
     * buffers, since each tier runs both before the next tier compares. */
    static uint8_t out[MAX + 64], aad[300], plain[MAX], expected[MAX], expected_stream[MAX];
    for (long i = 0; i < randoms; i++) {
        uint8_t key[32], nonce[12], tag[16], expected_tag[16], mac[16], expected_mac[16];
        size_t n = i % 10 == 9 ? (size_t)MAX : (size_t)(rng() % 3001);
        if (rng() % 3 == 0)
            n &= ~(size_t)63;
        uint32_t counter = (uint32_t)rng();
        if (i % 5 == 0)
            counter = 0xFFFFFFFFu - (uint32_t)(rng() % 40);
        size_t aad_length = (size_t)(rng() % 301);
        for (size_t k = 0; k < 32; k++)
            key[k] = (uint8_t)rng();
        for (size_t k = 0; k < 12; k++)
            nonce[k] = (uint8_t)rng();
        for (size_t k = 0; k < aad_length; k++)
            aad[k] = (uint8_t)rng();
        uint8_t *text = page_end - n;       /* the plaintext against the guard page */
        for (size_t k = 0; k < n; k++)
            plain[k] = text[k] = (uint8_t)rng();
        for (size_t t = 0; t < TIERS; t++) {
            uint64_t features = httpasm_cpu_limit(caps[t]);
            /* The raw cipher from the counter. */
            memset(out, 0xC3, sizeof out);
            httpasm_chacha20(key, counter, nonce, text, n, out);
            if (chacha_check_canary(out, n, sizeof out, "httpasm_chacha20", t))
                return 1;
            if (t == 0) {
                memcpy(expected_stream, out, n);
            } else if (memcmp(out, expected_stream, n) != 0) {
                fprintf(stderr, "httpasm_chacha20 at %s (features %#llx) differs from v1 on %zu octets from counter %u\n",
                        cap_names[t], (unsigned long long)features, n, counter);
                return 1;
            }
            /* Poly1305 over the text, the key from the cipher's state words. */
            httpasm_poly1305(key, text, n, mac);
            if (t == 0) {
                memcpy(expected_mac, mac, 16);
            } else if (memcmp(mac, expected_mac, 16) != 0) {
                fprintf(stderr, "httpasm_poly1305 at %s differs from v1 on %zu octets\n", cap_names[t], n);
                return 1;
            }
            /* The AEAD: seal, then open the v1 seal moved against the guard page. */
            memset(out, 0xC3, sizeof out);
            if (httpasm_chacha20_poly1305_seal(key, nonce, aad, aad_length, text, n, out, tag) != 0) {
                fprintf(stderr, "httpasm_chacha20_poly1305_seal at %s refused %zu octets\n", cap_names[t], n);
                return 1;
            }
            if (chacha_check_canary(out, n, sizeof out, "httpasm_chacha20_poly1305_seal", t))
                return 1;
            if (t == 0) {
                memcpy(expected, out, n);
                memcpy(expected_tag, tag, 16);
            } else if (memcmp(out, expected, n) != 0 || memcmp(tag, expected_tag, 16) != 0) {
                fprintf(stderr, "httpasm_chacha20_poly1305_seal at %s (features %#llx) differs from v1 on %zu octets, %zu of AAD\n",
                        cap_names[t], (unsigned long long)features, n, aad_length);
                return 1;
            }
            uint8_t *sealed = page_end - n;
            memcpy(sealed, expected, n);
            memset(out, 0xC3, sizeof out);
            if (httpasm_chacha20_poly1305_open(key, nonce, aad, aad_length, sealed, n, expected_tag, out) != 0 ||
                memcmp(out, plain, n) != 0) {
                fprintf(stderr, "httpasm_chacha20_poly1305_open at %s refused or misread v1's seal (%zu octets)\n", cap_names[t], n);
                return 1;
            }
            if (chacha_check_canary(out, n, sizeof out, "httpasm_chacha20_poly1305_open", t))
                return 1;
            uint8_t bad[16];
            memcpy(bad, expected_tag, 16);
            bad[rng() % 16] ^= (uint8_t)(1u << (rng() % 8));
            if (httpasm_chacha20_poly1305_open(key, nonce, aad, aad_length, sealed, n, bad, out) != -1) {
                fprintf(stderr, "httpasm_chacha20_poly1305_open at %s accepted a flipped tag bit\n", cap_names[t]);
                return 1;
            }
            for (size_t k = 0; k < n; k++) {
                if (out[k] != 0) {
                    fprintf(stderr, "httpasm_chacha20_poly1305_open at %s left plaintext after a refusal\n", cap_names[t]);
                    return 1;
                }
            }
            memcpy(text, plain, n);         /* the plaintext back against the guard page */
            checked++;
        }
    }
    printf("httpasm_chacha20, _poly1305, _chacha20_poly1305: %ld rounds of cipher, MAC, seal and open at every tier, every one equal to v1's\n", checked);
    return 0;
}

/* ---- httpasm_x25519, httpasm_x25519_public_key: by versions (crypto/x25519.asm) -------------
 * v1 (mul on five 51-bit limbs) against v3 (mulx with adcx/adox on four 64-bit limbs, with ADX).
 * Every tier must give v1's shared secret, return value and public key. Scalars and points end
 * against the guard page (an over-read faults); outputs are followed by canaries. */

/* x25519_tiers: `randoms` random scalars and points (a seventh with bit 255 set, a seventh
 * non-canonical, p to 2^255 - 1, and every so often a small-order point); and each scalar's
 * public key, which must equal the tier's own ladder at u = 9 (it comes from edwards25519's fixed
 * base instead) and v1's. Returns 0 when every tier agrees with v1, 1 at the first difference. */
static int x25519_tiers(long randoms)
{
    static const uint8_t small[2][32] = { { 0 }, { 1 } };   /* u = 0 and u = 1: small order */
    long checked = 0;
    for (long i = 0; i < randoms; i++) {
        uint8_t *scalar = page_end - 64, *point = page_end - 32;
        for (size_t k = 0; k < 32; k++) {
            scalar[k] = (uint8_t)rng();
            point[k] = (uint8_t)rng();
        }
        if (i % 7 == 1)
            point[31] |= 0x80;
        if (i % 7 == 2) {                                   /* p + (0..18) */
            memset(point, 0xFF, 32);
            point[0] = (uint8_t)(0xED + rng() % 19);
            point[31] = 0x7F;
        }
        if (i % 50 == 3)
            memcpy(point, small[i % 2], 32);
        uint8_t expected[32], expected_public[32], out[32 + 16];
        int expected_result = 0;
        for (size_t t = 0; t < TIERS; t++) {
            uint64_t features = httpasm_cpu_limit(caps[t]);
            memset(out, 0xC3, sizeof out);
            int result = httpasm_x25519(out, scalar, point);
            for (size_t k = 32; k < sizeof out; k++) {
                if (out[k] != 0xC3) {
                    fprintf(stderr, "httpasm_x25519 at %s wrote past its 32 octets\n", cap_names[t]);
                    return 1;
                }
            }
            if (t == 0) {
                memcpy(expected, out, 32);
                expected_result = result;
            } else if (memcmp(out, expected, 32) != 0 || result != expected_result) {
                fprintf(stderr, "httpasm_x25519 at %s (features %#llx) differs from v1\n", cap_names[t], (unsigned long long)features);
                dump("scalar", scalar, 32);
                dump("point", point, 32);
                return 1;
            }
            int zero = 1;
            for (size_t k = 0; k < 32; k++)
                zero &= out[k] == 0;
            if (result != (zero ? -1 : 0)) {
                fprintf(stderr, "httpasm_x25519 at %s returned %d for a %s result\n", cap_names[t], result, zero ? "zero" : "nonzero");
                return 1;
            }
            {
                /* every round, the public key (edwards25519's fixed base) against v1's and against
                 * this tier's own ladder at u = 9: two separate codes for X25519(scalar, 9) */
                static const uint8_t nine[32] = { 9 };
                uint8_t ladder[32];
                memset(out, 0xC3, sizeof out);
                httpasm_x25519_public_key(out, scalar);
                for (size_t k = 32; k < sizeof out; k++) {
                    if (out[k] != 0xC3) {
                        fprintf(stderr, "httpasm_x25519_public_key at %s wrote past its 32 octets\n", cap_names[t]);
                        return 1;
                    }
                }
                httpasm_x25519(ladder, scalar, nine);
                if (memcmp(out, ladder, 32) != 0) {
                    fprintf(stderr, "httpasm_x25519_public_key at %s differs from the ladder at u = 9\n", cap_names[t]);
                    dump("scalar", scalar, 32);
                    return 1;
                }
                if (t == 0) {
                    memcpy(expected_public, out, 32);
                } else if (memcmp(out, expected_public, 32) != 0) {
                    fprintf(stderr, "httpasm_x25519_public_key at %s differs from v1\n", cap_names[t]);
                    return 1;
                }
            }
            checked++;
        }
    }
    printf("httpasm_x25519: %ld scalar multiplications and public keys at every tier, every one equal to v1's (each public key to the ladder at u = 9)\n", checked);
    return 0;
}

/* ---- httpasm_p256_*: by versions (crypto/p256.asm) ---------------------------------------------
 * v1 (mul, SSE2 table scans) against v3 (mulx with adcx/adox, AVX2 scans, with ADX). Every tier
 * must give v1's public key, shared secret, signature and verdicts, return values included.
 * Every input ends against the guard page (an over-read faults); outputs are followed by
 * canaries. */

/* p256_tiers: `randoms` rounds: a private key (random, every so often 1, n - 1, or a refused
 * one: 0, n, all ones), a peer's point (v1's public key of another random key, every so often
 * with a flipped octet: refused), a digest of 0 to 80 random octets, entropy every other round;
 * then public key, ECDH, signature and its verification (and a tampered one's) at every tier.
 * Returns 0 when every tier agrees with v1, 1 at the first difference. */
static int p256_tiers(long randoms)
{
    static const uint8_t n_minus_1[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x50,
    };
    long checked = 0;
    for (long i = 0; i < randoms; i++) {
        uint8_t *key = page_end - 32, *peer = page_end - 32 - 65 - 7, *entropy = page_end - 300;
        size_t length = (size_t)(rng() % 81);
        uint8_t *digest = page_end - 200 - length;
        for (size_t k = 0; k < 32; k++) {
            key[k] = (uint8_t)rng();
            entropy[k] = (uint8_t)rng();
        }
        for (size_t k = 0; k < length; k++)
            digest[k] = (uint8_t)rng();
        if (i % 10 == 1)
            memcpy(key, n_minus_1, 32);
        if (i % 10 == 2) {
            memset(key, 0, 32);
            key[31] = 1;
        }
        if (i % 25 == 3)
            memset(key, 0, 32);                             /* refused: 0 */
        if (i % 25 == 4)
            memset(key, 0xFF, 32);                          /* refused: past n */
        uint8_t other[32];
        for (size_t k = 0; k < 32; k++)
            other[k] = (uint8_t)rng();
        httpasm_cpu_limit(caps[0]);
        if (httpasm_p256_public_key(peer, other) != 0)
            memcpy(peer, (uint8_t[65]){ 4 }, 65);           /* (a refused draw: an invalid point) */
        if (i % 9 == 5)
            peer[1 + rng() % 64] ^= (uint8_t)(1 + rng() % 255);  /* off the curve, or past p */
        const uint8_t *extra = i % 2 ? entropy : NULL;
        uint8_t expected_public[65], expected_shared[32], expected_signature[64];
        int expected[5] = { 0 };
        for (size_t t = 0; t < TIERS; t++) {
            uint64_t features = httpasm_cpu_limit(caps[t]);
            uint8_t public_key[65 + 16], shared[32 + 16], signature[64 + 16];
            memset(public_key, 0xC3, sizeof public_key);
            memset(shared, 0xC3, sizeof shared);
            memset(signature, 0xC3, sizeof signature);
            int results[5];
            results[0] = httpasm_p256_public_key(public_key, key);
            results[1] = httpasm_p256_ecdh(shared, key, peer);
            results[2] = httpasm_p256_sign(signature, key, digest, length, extra);
            results[3] = results[0] == 0 ? httpasm_p256_verify(public_key, digest, length, signature) : -1;
            uint8_t tampered[64];
            memcpy(tampered, signature, 64);
            tampered[rng() % 64] ^= (uint8_t)(1 << (rng() % 8));
            results[4] = results[0] == 0 ? httpasm_p256_verify(public_key, digest, length, tampered) : -1;
            for (size_t k = 0; k < 16; k++) {
                if (public_key[65 + k] != 0xC3 || shared[32 + k] != 0xC3 || signature[64 + k] != 0xC3) {
                    fprintf(stderr, "httpasm_p256_* at %s wrote past an output\n", cap_names[t]);
                    return 1;
                }
            }
            if (results[3] != results[0] || results[4] != -1) {
                fprintf(stderr, "httpasm_p256_verify at %s: own signature %d, tampered %d\n", cap_names[t], results[3], results[4]);
                return 1;
            }
            if (t == 0) {
                memcpy(expected_public, public_key, 65);
                memcpy(expected_shared, shared, 32);
                memcpy(expected_signature, signature, 64);
                memcpy(expected, results, sizeof expected);
            } else if (memcmp(public_key, expected_public, 65) != 0 || memcmp(shared, expected_shared, 32) != 0
                       || memcmp(signature, expected_signature, 64) != 0 || memcmp(results, expected, 3 * sizeof(int)) != 0) {
                fprintf(stderr, "httpasm_p256_* at %s (features %#llx) differs from v1\n", cap_names[t], (unsigned long long)features);
                dump("key", key, 32);
                dump("peer", peer, 65);
                dump("digest", digest, length);
                return 1;
            }
            checked++;
        }
    }
    printf("httpasm_p256_*: %ld rounds of public key, ECDH, signature and verification at every tier, every one equal to v1's\n", checked);
    return 0;
}

/* ---- httpasm_p384_*: by versions (crypto/p384.asm) ---------------------------------------------
 * p256_tiers' check at P-384's sizes: v1 (mul, SSE2 table scans) against v3 (mulx with
 * adcx/adox, AVX2 scans, with ADX); every tier must give v1's public key, shared secret,
 * signature and verdicts, return values included. Every input ends against the guard page (an
 * over-read faults); outputs are followed by canaries. */

/* p384_tiers: `randoms` rounds: a private key (random, every so often 1, n - 1, or a refused
 * one: 0, all ones), a peer's point (v1's public key of another random key, every so often with
 * a flipped octet: refused), a digest of 0 to 100 random octets, entropy every other round; then
 * public key, ECDH, signature and its verification (and a tampered one's) at every tier. Returns 0
 * when every tier agrees with v1, 1 at the first difference. */
static int p384_tiers(long randoms)
{
    static const uint8_t n_minus_1[48] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
        0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x72,
    };
    long checked = 0;
    for (long i = 0; i < randoms; i++) {
        uint8_t *key = page_end - 48, *peer = page_end - 48 - 97 - 7, *entropy = page_end - 400;
        size_t length = (size_t)(rng() % 101);
        uint8_t *digest = page_end - 260 - length;
        for (size_t k = 0; k < 48; k++) {
            key[k] = (uint8_t)rng();
            entropy[k] = (uint8_t)rng();
        }
        for (size_t k = 0; k < length; k++)
            digest[k] = (uint8_t)rng();
        if (i % 10 == 1)
            memcpy(key, n_minus_1, 48);
        if (i % 10 == 2) {
            memset(key, 0, 48);
            key[47] = 1;
        }
        if (i % 25 == 3)
            memset(key, 0, 48);                             /* refused: 0 */
        if (i % 25 == 4)
            memset(key, 0xFF, 48);                          /* refused: past n */
        uint8_t other[48];
        for (size_t k = 0; k < 48; k++)
            other[k] = (uint8_t)rng();
        httpasm_cpu_limit(caps[0]);
        if (httpasm_p384_public_key(peer, other) != 0)
            memcpy(peer, (uint8_t[97]){ 4 }, 97);           /* (a refused draw: an invalid point) */
        if (i % 9 == 5)
            peer[1 + rng() % 96] ^= (uint8_t)(1 + rng() % 255);  /* off the curve, or past p */
        const uint8_t *extra = i % 2 ? entropy : NULL;
        uint8_t expected_public[97], expected_shared[48], expected_signature[96];
        int expected[5] = { 0 };
        for (size_t t = 0; t < TIERS; t++) {
            uint64_t features = httpasm_cpu_limit(caps[t]);
            uint8_t public_key[97 + 16], shared[48 + 16], signature[96 + 16];
            memset(public_key, 0xC3, sizeof public_key);
            memset(shared, 0xC3, sizeof shared);
            memset(signature, 0xC3, sizeof signature);
            int results[5];
            results[0] = httpasm_p384_public_key(public_key, key);
            results[1] = httpasm_p384_ecdh(shared, key, peer);
            results[2] = httpasm_p384_sign(signature, key, digest, length, extra);
            results[3] = results[0] == 0 ? httpasm_p384_verify(public_key, digest, length, signature) : -1;
            uint8_t tampered[96];
            memcpy(tampered, signature, 96);
            tampered[rng() % 96] ^= (uint8_t)(1 << (rng() % 8));
            results[4] = results[0] == 0 ? httpasm_p384_verify(public_key, digest, length, tampered) : -1;
            for (size_t k = 0; k < 16; k++) {
                if (public_key[97 + k] != 0xC3 || shared[48 + k] != 0xC3 || signature[96 + k] != 0xC3) {
                    fprintf(stderr, "httpasm_p384_* at %s wrote past an output\n", cap_names[t]);
                    return 1;
                }
            }
            if (results[3] != results[0] || results[4] != -1) {
                fprintf(stderr, "httpasm_p384_verify at %s: own signature %d, tampered %d\n", cap_names[t], results[3], results[4]);
                return 1;
            }
            if (t == 0) {
                memcpy(expected_public, public_key, 97);
                memcpy(expected_shared, shared, 48);
                memcpy(expected_signature, signature, 96);
                memcpy(expected, results, sizeof expected);
            } else if (memcmp(public_key, expected_public, 97) != 0 || memcmp(shared, expected_shared, 48) != 0
                       || memcmp(signature, expected_signature, 96) != 0 || memcmp(results, expected, 3 * sizeof(int)) != 0) {
                fprintf(stderr, "httpasm_p384_* at %s (features %#llx) differs from v1\n", cap_names[t], (unsigned long long)features);
                dump("key", key, 48);
                dump("peer", peer, 97);
                dump("digest", digest, length);
                return 1;
            }
            checked++;
        }
    }
    printf("httpasm_p384_*: %ld rounds of public key, ECDH, signature and verification at every tier, every one equal to v1's\n", checked);
    return 0;
}

/* ---- httpasm_ed25519_*: by versions (crypto/ed25519.asm) ---------------------------------------
 * v1 (mul on 51-bit limbs, SSE2 table scans) against v3 (mulx with adcx/adox on 64-bit limbs,
 * AVX2 scans, with ADX). Every tier must give v1's public key, prepared key, signature and
 * verdicts. Each round puts one input against the guard page in turn (the seed, the message, the
 * prepared key, the public key, the signature), so a version reading past one faults; outputs are
 * followed by canaries. */

/* ed25519_tiers: `randoms` rounds: a seed (random, every so often all zeros or all ones) and a
 * message of 0 to 200 random octets; at every tier the public key, the prepared key (its public
 * part must be the public key), the signature, its verification, a tampered copy's, one with S
 * pushed past L (S + L: the same point, refused), and a random 32 octets as a public key with the
 * genuine signature (decoding refused, or the equation failing). Returns 0 when every tier agrees
 * with v1, 1 at the first difference. */
static int ed25519_tiers(long randoms)
{
    static const uint8_t l_octets[32] = {   /* L, little-endian */
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };
    long checked = 0;
    for (long i = 0; i < randoms; i++) {
        size_t length = (size_t)(rng() % 201);
        uint8_t *area = page_end - 1024;                    /* where the inputs off the guard go */
        int guard = (int)(i % 5);
        uint8_t *seed = guard == 0 ? page_end - 32 : area;
        uint8_t *message = guard == 1 ? page_end - length : area + 64;
        httpasm_ed25519_private_key *key = (httpasm_ed25519_private_key *)(guard == 2 ? page_end - 96 : area + 272);
        uint8_t *public_in = guard == 3 ? page_end - 32 : area + 384;
        uint8_t *signature_in = guard == 4 ? page_end - 64 : area + 448;
        for (size_t k = 0; k < 32; k++)
            seed[k] = (uint8_t)rng();
        if (i % 13 == 1)
            memset(seed, 0, 32);
        if (i % 13 == 2)
            memset(seed, 0xFF, 32);
        for (size_t k = 0; k < length; k++)
            message[k] = (uint8_t)rng();
        uint8_t random_key[32];
        for (size_t k = 0; k < 32; k++)
            random_key[k] = (uint8_t)rng();
        size_t flip = (size_t)(rng() % 512);
        uint8_t expected_public[32], expected_key[96], expected_signature[64];
        int expected[4] = { 0 };
        for (size_t t = 0; t < TIERS; t++) {
            uint64_t features = httpasm_cpu_limit(caps[t]);
            uint8_t public_key[32 + 16], signature[64 + 16];
            union { httpasm_ed25519_private_key key; uint8_t octets[96 + 16]; } prepared;
            memset(public_key, 0xC3, sizeof public_key);
            memset(signature, 0xC3, sizeof signature);
            memset(prepared.octets, 0xC3, sizeof prepared.octets);
            httpasm_ed25519_public_key(public_key, seed);
            httpasm_ed25519_private_key_init(&prepared.key, seed);
            memcpy(key, &prepared.key, 96);
            httpasm_ed25519_sign(signature, key, message, length);
            for (size_t k = 0; k < 16; k++) {
                if (public_key[32 + k] != 0xC3 || prepared.octets[96 + k] != 0xC3 || signature[64 + k] != 0xC3) {
                    fprintf(stderr, "httpasm_ed25519_* at %s wrote past an output\n", cap_names[t]);
                    return 1;
                }
            }
            if (memcmp(prepared.octets + 64, public_key, 32) != 0) {
                fprintf(stderr, "httpasm_ed25519_private_key_init at %s: its public key is not httpasm_ed25519_public_key's\n", cap_names[t]);
                return 1;
            }
            memcpy(public_in, public_key, 32);
            memcpy(signature_in, signature, 64);
            int results[4];
            results[0] = httpasm_ed25519_verify(public_in, message, length, signature_in);
            signature_in[flip / 8] ^= (uint8_t)(1 << (flip % 8));
            results[1] = httpasm_ed25519_verify(public_in, message, length, signature_in);
            memcpy(signature_in, signature, 64);
            unsigned carry = 0;                             /* S + L (S < L: no carry out of 2^256) */
            for (size_t k = 0; k < 32; k++) {
                carry += (unsigned)signature_in[32 + k] + l_octets[k];
                signature_in[32 + k] = (uint8_t)carry;
                carry >>= 8;
            }
            results[2] = httpasm_ed25519_verify(public_in, message, length, signature_in);
            memcpy(signature_in, signature, 64);
            memcpy(public_in, random_key, 32);
            results[3] = httpasm_ed25519_verify(public_in, message, length, signature_in);
            if (results[0] != 0 || results[1] != -1 || results[2] != -1 || results[3] != -1) {
                fprintf(stderr, "httpasm_ed25519_verify at %s: own %d, tampered %d, S + L %d, random key %d\n",
                        cap_names[t], results[0], results[1], results[2], results[3]);
                dump("seed", seed, 32);
                dump("message", message, length);
                return 1;
            }
            if (t == 0) {
                memcpy(expected_public, public_key, 32);
                memcpy(expected_key, prepared.octets, 96);
                memcpy(expected_signature, signature, 64);
                memcpy(expected, results, sizeof expected);
            } else if (memcmp(public_key, expected_public, 32) != 0 || memcmp(prepared.octets, expected_key, 96) != 0
                       || memcmp(signature, expected_signature, 64) != 0 || memcmp(results, expected, sizeof expected) != 0) {
                fprintf(stderr, "httpasm_ed25519_* at %s (features %#llx) differs from v1\n", cap_names[t], (unsigned long long)features);
                dump("seed", seed, 32);
                dump("message", message, length);
                return 1;
            }
            checked++;
        }
    }
    printf("httpasm_ed25519_*: %ld rounds of public key, prepared key, signature and verifications at every tier, every one equal to v1's\n", checked);
    return 0;
}

/* ---- httpasm_rsa_*: RSA verification by versions (rsa.asm) ---------------------------------
 * v3 runs the Montgomery product, square and reduction with mulx and adcx/adox, eight limbs a
 * step; v1 and v2 run them with mul. A verification only says valid or not, so each round checks
 * what can be seen from outside: FIPS 186-3's first valid 2048-bit SHA-256 SigVer15 signature
 * verifies at every tier and fails with any bit flipped; random keys (odd n of 1024 to 4096
 * bits, e 3 or 65537, every so often an even n or one of 1023 bits, refused) prepare to the
 * same octets at every tier (the init has no versions of its own: this keeps it so); random
 * signatures, n itself, all ones and lengths one off get the same answer from both encodings
 * at every tier; and n, e, the key, the digest and the signature each end against the guard
 * page in turn, so a version reading past one dies. */
static const char rsa_vector_n[] =
    "c47abacc2a84d56f3614d92fd62ed36ddde459664b9301dcd1d61781cfcc026bcb2399bee7e75681a80b7bf500e2d08c"
    "eae1c42ec0b707927f2b2fe92ae852087d25f1d260cc74905ee5f9b254ed05494a9fe06732c3680992dd6f0dc634568d"
    "11542a705f83ae96d2a49763d5fbb24398edf3702bc94bc168190166492b8671de874bb9cecb058c6c8344aa8c93754d"
    "6effcd44a41ed7de0a9dcd9144437f212b18881d042d331a4618a9e630ef9bb66305e4fdf8f0391b3b2313fe549f0189"
    "ff968b92f33c266a4bc2cffc897d1937eeb9e406f5d0eaa7a14782e76af3fce98f54ed237b4a04a4159a5f6250a296a9"
    "02880204e61d891c4da29f2d65f34cbb";
static const char rsa_vector_e[] = "49d2a1";
static const char rsa_vector_digest[] = "565ff4f36e8bd4a96007ed577f3248b4f9943826d721b417a20bb12c3ae6e874";
static const char rsa_vector_s[] =
    "51265d96f11ab338762891cb29bf3f1d2b3305107063f5f3245af376dfcc7027d39365de70a31db05e9e10eb6148cb7f"
    "6425f0c93c4fb0e2291adbd22c77656afc196858a11e1c670d9eeb592613e69eb4f3aa501730743ac4464486c7ae68fd"
    "509e896f63884e9424f69c1c5397959f1e52a368667a598a1fc90125273d9341295d2f8e1cc4969bf228c860e07a3546"
    "be2eeda1cde48ee94d062801fe666e4a7ae8cb9cd79262c017b081af874ff00453ca43e34efdb43fffb0bb42a4e2d32a"
    "5e5cc9e8546a221fe930250e5f5333e0efe58ffebf19369a3b8ae5a67f6a048bc9ef915bda25160729b508667ada84a0"
    "c27e7e26cf2abca413e5e4693f4a9405";

/* hex_octets: the octets of a hex string (two digits each) into out; returns how many. */
static size_t hex_octets(const char *hex, uint8_t *out)
{
    size_t count = strlen(hex) / 2;
    for (size_t i = 0; i < count; i++) {
        unsigned value;
        if (sscanf(hex + 2 * i, "%2x", &value) != 1)
            return 0;
        out[i] = (uint8_t)value;
    }
    return count;
}

/* rsa_both: both encodings' verifications of one signature under one key (SHA-256; PSS with a
 * 32-octet salt), the key, digest and signature where the caller put them. */
static void rsa_both(const httpasm_rsa_public_key *key, const uint8_t *digest, const uint8_t *signature, size_t length,
                     int results[2])
{
    results[0] = httpasm_rsa_verify_pkcs1(key, HTTPASM_HASH_SHA256, digest, signature, length);
    results[1] = httpasm_rsa_verify_pss(key, HTTPASM_HASH_SHA256, digest, 32, signature, length);
}

static int rsa_tiers(long randoms)
{
    /* the regions: the key against the guard, or two pages back while an input takes the guard */
    httpasm_rsa_public_key *key_guard = (httpasm_rsa_public_key *)(page_end - sizeof(httpasm_rsa_public_key));
    httpasm_rsa_public_key *key = (httpasm_rsa_public_key *)(page_end - 3 * PAGE);
    uint8_t vn[256], ve[3], vdigest[32], vsig[256];
    if (hex_octets(rsa_vector_n, vn) != 256 || hex_octets(rsa_vector_e, ve) != 3 || hex_octets(rsa_vector_digest, vdigest) != 32
        || hex_octets(rsa_vector_s, vsig) != 256) {
        fprintf(stderr, "rsa_tiers: the embedded vector does not decode\n");
        return 2;
    }
    for (size_t t = 0; t < TIERS; t++) {
        httpasm_cpu_limit(caps[t]);
        uint8_t *at = page_end - 256;
        memcpy(at, vsig, 256);
        if (httpasm_rsa_public_key_init(key, vn, 256, ve, 3) != 0 || httpasm_rsa_verify_pkcs1(key, HTTPASM_HASH_SHA256, vdigest, at, 256) != 0) {
            fprintf(stderr, "httpasm_rsa_verify_pkcs1 at %s: FIPS 186-3's valid signature refused\n", cap_names[t]);
            return 1;
        }
        for (int k = 0; k < 64; k++) {
            at[rng() % 256] ^= (uint8_t)(1 << (rng() % 8));
            if (httpasm_rsa_verify_pkcs1(key, HTTPASM_HASH_SHA256, vdigest, at, 256) != -1) {
                fprintf(stderr, "httpasm_rsa_verify_pkcs1 at %s: a changed signature verified\n", cap_names[t]);
                return 1;
            }
            memcpy(at, vsig, 256);
        }
    }

    long checked = 0;
    for (long i = 0; i < randoms; i++) {
        size_t bits = 1024 + (size_t)(rng() % 3073), octets = (bits + 7) / 8;
        uint8_t n[512], e[3] = { 0x01, 0x00, 0x01 }, digest[32], signature[513];
        for (size_t k = 0; k < octets; k++)
            n[k] = (uint8_t)rng();
        n[0] &= (uint8_t)(0xFF >> (8 * octets - bits));
        n[0] |= (uint8_t)(0x80 >> (8 * octets - bits));     /* exactly `bits` bits */
        n[octets - 1] |= 1;
        size_t e_length = 3;
        if (i % 3 == 1) {
            e[0] = 3;                                       /* e = 3 */
            e_length = 1;
        }
        if (i % 16 == 3)
            n[octets - 1] &= 0xFE;                          /* refused: even */
        if (i % 16 == 5) {
            bits = 1023;                                    /* refused: one bit short */
            octets = 128;
            n[0] = 0x7F;
        }
        for (size_t k = 0; k < 32; k++)
            digest[k] = (uint8_t)rng();
        size_t length = octets;
        for (size_t k = 0; k < sizeof signature; k++)
            signature[k] = (uint8_t)rng();
        if (i % 7 == 2)
            memcpy(signature, n, octets);                   /* s = n: not below n */
        if (i % 7 == 4)
            memset(signature, 0xFF, octets);
        if (i % 11 == 6) {
            if (rng() % 2)                                  /* the length one off */
                length++;
            else
                length--;
        }
        if (i % 2 == 0 && length > 0)
            signature[0] &= 0x7F;                           /* below n more often */

        uint8_t expected_key[sizeof(httpasm_rsa_public_key)];
        int expected[3] = { 0 };
        for (size_t t = 0; t < TIERS; t++) {
            uint64_t features = httpasm_cpu_limit(caps[t]);
            /* the init twice: n against the guard, then e */
            uint8_t *n_at = page_end - octets, *e_at = page_end - e_length;
            memcpy(n_at, n, octets);
            int results[3];
            results[0] = httpasm_rsa_public_key_init(key, n_at, octets, e, e_length);
            httpasm_rsa_public_key again;
            uint8_t n_copy[512];
            memcpy(n_copy, n, octets);
            memcpy(e_at, e, e_length);
            if (httpasm_rsa_public_key_init(&again, n_copy, octets, e_at, e_length) != results[0]
                || memcmp(&again, key, sizeof again) != 0) {
                fprintf(stderr, "httpasm_rsa_public_key_init at %s: n and e against the guard prepare different keys\n", cap_names[t]);
                return 1;
            }
            /* the verifications with the key, the digest and the signature against the guard in turn */
            int both[2];
            switch (i % 3) {
            case 0:
                memcpy(key_guard, key, sizeof *key);
                rsa_both(key_guard, digest, signature, length, both);
                break;
            case 1: {
                uint8_t *digest_at = page_end - 32;
                memcpy(digest_at, digest, 32);
                rsa_both(key, digest_at, signature, length, both);
                break;
            }
            default: {
                uint8_t *signature_at = page_end - length;
                memcpy(signature_at, signature, length);
                rsa_both(key, digest, signature_at, length, both);
                break;
            }
            }
            results[1] = both[0];
            results[2] = both[1];
            if (t == 0) {
                memcpy(expected_key, key, sizeof expected_key);
                memcpy(expected, results, sizeof expected);
            } else if (memcmp(key, expected_key, sizeof expected_key) != 0 || memcmp(results, expected, sizeof expected) != 0) {
                fprintf(stderr, "httpasm_rsa_* at %s (features %#llx) differs from v1: init %d/%d, PKCS#1 %d/%d, PSS %d/%d\n",
                        cap_names[t], (unsigned long long)features, results[0], expected[0], results[1], expected[1], results[2],
                        expected[2]);
                dump("n", n, octets);
                dump("signature", signature, length);
                return 1;
            }
        }
        checked++;
    }
    printf("httpasm_rsa_*: %ld rounds of key preparation and both verifications at every tier, every one equal to v1's\n", checked);
    return 0;
}

/* ---- httpasm_rsa_private_key_init, httpasm_rsa_sign_*: RSA signing by versions (rsa.asm) ----
 * v3 runs the CRT's products, squares, reductions and table reads with mulx, adcx/adox and AVX2;
 * v1 and v2 with mul and SSE2. Two keys (made once with OpenSSL; their numbers below, n, e, p, q,
 * dp, dq, q^-1): a 1024-bit one (k = 8: the generic square and product) and a 2048-bit one (k =
 * 16: v3's exponentiation runs its own square and product, whose results stay below R, not below
 * the prime). Each prepares to the same octets at every tier, each of its seven numbers against
 * the guard page in turn; then each round's PKCS#1 v1.5 and PSS signatures (SHA-256, a random
 * digest, a random salt of 0 to 64 octets) are equal at every tier, verify under the key's public
 * part and leave the octets after them untouched; the digest or the salt sits against the guard. */
static const char *const rsa_private_hex_1024[7] = {
    "c0101f8934307c57c9481985b2c13a4635b129c5e056d1a92223c1cfd779dfebf35416f4c8958c30dc47f0fb0bc09a53"
    "003ccda0bc20780d1385fb37a395d1d2cd31fb4cfddbd5d3c92a8dc280c064afb4949654d14c378077254b88fb05f50b"
    "0e7b1aa23725f33950ce06ddb946301ba3517e329a86fc1f834f90c395c4bdfb",
    "010001",
    "fcfbb4ac50e3f6fcdae2f17ba12b173a6181d29cd0a7cdc057388f6e9f3dbfea3abaa140bd8b162968e7bf4a5f521284"
    "232f373385a16adb5a3b41bc0777a3f3",
    "c25a717767c752d84290507bf0a549277f92fdc6b9fba9e668ceb6a500feea564f9d234f930d43fd7f25ce488f7b8c23"
    "83073343c650342a6e8bc348950c67d9",
    "6f1f54fe37cddaa8b8b0e4e7ac249460658233f403c7219e71f17b375925338e7c5b8c0736fac8324a4d397e3e9e7b59"
    "a566d0f585a6209cd7669dfa2cc185b7",
    "223b39d6f52167570dca4b52b91cf3989060bc6fff1bf35dd0c1efeb7a146c03cdbbf89730685abc5063c14488791342"
    "c1f647b23d40ad1f781f07c345f54c69",
    "e0bdd098c4795787e564eac34f8cfbc0005861c7a642ab493c90299f50c706efbc241e61d9ab09cb0c427ccbc612b3ca"
    "be48f67395a08504a38f44c720999132"
};

static const char *const rsa_private_hex_2048[7] = {
    "e421764c563244426247031d997d47d08c5003303181239b41bdac0d338f0c4344084ca53d8038b43ea65b01b7db1c48"
    "b9461a5dcf2f4836bf060d007378322e8aa96a3ac6f61283630276041fe946d796b0a6bf8ab895e8b5ff28d1934bc99c"
    "278e30e895da211ae2b3b15db045df3f9cd71595ae15471a3d47b18fa0828d00d7048487ed756ca97600450e8695aa83"
    "0e59f9acaa65e0f016d4be59b90a473f5dcf00e0ffe8a4b42681aa56f72cda8d16ff5d42c6b46c748fa3830fe372d9bc"
    "6cb2af81ce698298d5d7c38958c43863b29dbcb7c0f1529ad9a49f6b5362437d16a52a5c8c12af81624a1d941db818cf"
    "cf5e8d8bda19556398ae08e502f82763",
    "010001",
    "feb0f65ae82f63e64d084f356bd5223b8250065bbeace771710a93b3e60e438491a72d884d8e4a391f7e1bcc7b6d40ff"
    "96b2c61a8fc9a8532f150b3a21d8e21a6047655fb8749fd6cc42ef76d408cd5612ee569084b26546a01709bf4cb1b065"
    "0278dc823802270db5796931440d8876249675808b6fa6bdebe5935e5cdecf79",
    "e54d8f6ea255db59d5a3f12c36df5be764b15878b7b0493dd7c3e8ec10c5594917490411d3aaf331093202992dd3ac06"
    "3904de6e14eaa020612fe2671cf4b9da7fd5c78417bf1a2a0e3a7f0852ca0de0455320d305b33385e348b9ce7e132ad0"
    "343b96577c6a683865bb8447dd247b7d671d6cc28ad358e73cba3c0ff8a2eabb",
    "aef726e6a0a71dbbf2a388b6ac5388e6d4c8e0f559f232350e7133b2dc9263f3c893ce85dab1ab6fbea0c5bc1df69a36"
    "7b7269018a52009ed4b3623917538550955fb6d6a1430d2364c37efa65037efc6898ef42ecc619290185921ea7335278"
    "b1d011bc2b79df165ddb0056e5e75e1dbb58d973eb5652781a7c6656e6f9f211",
    "28826d4684535aaf2239165053595e6920b6dc04679f333143bf0e9535d9478ecc185029be15436574546b75184d7ee4"
    "928a33a98af470598811e79383e0103d73bc16c55554a390ae76d31e6b51dae5b6199b80ec4ede5956eff03374be7a1f"
    "d23a7cb2f3fdf06f96396c832da45654af34d993fce69d9c2c74524c1806e025",
    "8d0b3783e80edb1e0516632d8944f1f0dff3434c190790ff41d3880eb48dd0eb88266f38c1b52c44925e78f7972da9ae"
    "780c5ffd85987253d62c094dfdd76397435a8d37a0efb8fb89f7d884a0db3705b9c6c22a950bc5dec7ed5ce3fdb394f5"
    "d0df1034b35da43c04b5f9ea809609020a1b48862715914a7dac2b6ee69a368d"
};

/* rsa_sign_tiers: the check above on the key of `hex` (n, e, p, q, dp, dq, q^-1) whose modulus has
 * `octets` octets (128 or 256), `randoms` rounds. Returns 0, 1 on a difference, 2 when the hex does
 * not decode. */
static int rsa_sign_tiers(const char *const hex[7], size_t octets_n, long randoms)
{
    static uint8_t octets[7][256];
    static httpasm_rsa_private_key keys[TIERS];
    size_t lengths[7];
    for (int i = 0; i < 7; i++) {
        lengths[i] = hex_octets(hex[i], octets[i]);
        if (lengths[i] == 0) {
            fprintf(stderr, "rsa_sign_tiers: the embedded key does not decode\n");
            return 2;
        }
    }
    for (size_t t = 0; t < TIERS; t++) {
        httpasm_cpu_limit(caps[t]);
        for (int at = 0; at < 7; at++) {
            const uint8_t *place[7];
            for (int i = 0; i < 7; i++)
                place[i] = octets[i];
            uint8_t *guarded = page_end - lengths[at];
            memcpy(guarded, octets[at], lengths[at]);
            place[at] = guarded;
            httpasm_rsa_private_numbers numbers = {
                place[0], lengths[0], place[1], lengths[1], place[2], lengths[2], place[3], lengths[3],
                place[4], lengths[4], place[5], lengths[5], place[6], lengths[6],
            };
            httpasm_rsa_private_key key;
            if (httpasm_rsa_private_key_init(&key, &numbers) != 0) {
                fprintf(stderr, "httpasm_rsa_private_key_init at %s refused the key (number %d against the guard)\n", cap_names[t], at);
                return 1;
            }
            if (at == 0)
                keys[t] = key;
            else if (memcmp(&key, &keys[t], sizeof key) != 0) {
                fprintf(stderr, "httpasm_rsa_private_key_init at %s: number %d against the guard prepares another key\n", cap_names[t], at);
                return 1;
            }
        }
        if (memcmp(&keys[t], &keys[0], sizeof keys[0]) != 0) {
            fprintf(stderr, "httpasm_rsa_private_key_init at %s differs from v1\n", cap_names[t]);
            return 1;
        }
    }

    long checked = 0;
    for (long i = 0; i < randoms; i++) {
        uint8_t digest[32], salt[64], expected[2][256];
        size_t salt_length = (size_t)(rng() % 65);
        for (size_t k = 0; k < 32; k++)
            digest[k] = (uint8_t)rng();
        for (size_t k = 0; k < sizeof salt; k++)
            salt[k] = (uint8_t)rng();
        for (size_t t = 0; t < TIERS; t++) {
            uint64_t features = httpasm_cpu_limit(caps[t]);
            const uint8_t *d = digest, *s = salt;
            if (i % 2 == 0) {
                uint8_t *at = page_end - 32;
                memcpy(at, digest, 32);
                d = at;
            } else if (salt_length > 0) {
                uint8_t *at = page_end - salt_length;
                memcpy(at, salt, salt_length);
                s = at;
            }
            uint8_t out[2][256 + 16];
            memset(out, 0xC3, sizeof out);
            int signed_pkcs1 = httpasm_rsa_sign_pkcs1(&keys[0], HTTPASM_HASH_SHA256, d, out[0], octets_n);
            int signed_pss = httpasm_rsa_sign_pss(&keys[0], HTTPASM_HASH_SHA256, d, s, salt_length, out[1], octets_n);
            for (size_t k = octets_n; k < octets_n + 16; k++) {
                if (out[0][k] != 0xC3 || out[1][k] != 0xC3) {
                    fprintf(stderr, "httpasm_rsa_sign_* at %s wrote past the signature (%zu bits)\n", cap_names[t], octets_n * 8);
                    return 1;
                }
            }
            const httpasm_rsa_public_key *public_key = (const httpasm_rsa_public_key *)&keys[0];
            if (signed_pkcs1 != 0 || signed_pss != 0 || httpasm_rsa_verify_pkcs1(public_key, HTTPASM_HASH_SHA256, d, out[0], octets_n) != 0
                || httpasm_rsa_verify_pss(public_key, HTTPASM_HASH_SHA256, d, salt_length, out[1], octets_n) != 0) {
                fprintf(stderr, "httpasm_rsa_sign_* at %s: signed %d/%d, or its signature does not verify (%zu bits, salt %zu)\n",
                        cap_names[t], signed_pkcs1, signed_pss, octets_n * 8, salt_length);
                return 1;
            }
            if (t == 0) {
                memcpy(expected[0], out[0], octets_n);
                memcpy(expected[1], out[1], octets_n);
            } else if (memcmp(out[0], expected[0], octets_n) != 0 || memcmp(out[1], expected[1], octets_n) != 0) {
                fprintf(stderr, "httpasm_rsa_sign_* at %s (features %#llx) differs from v1 (%zu bits, salt %zu)\n", cap_names[t],
                        (unsigned long long)features, octets_n * 8, salt_length);
                dump("digest", digest, 32);
                return 1;
            }
        }
        checked++;
    }
    printf("httpasm_rsa_sign_*: %zu-bit key: %ld rounds of both signatures at every tier, every one equal to v1's and verified; the key alike at every tier\n",
           octets_n * 8, checked);
    return 0;
}

/* ---- httpasm_hpack_decode: Huffman strings decoded by versions (hpack.asm hp_string) ---------
 * v1 decodes a Huffman string with a nibble automaton; v2 and up with a table decoder (12-bit
 * lookups of up to two symbols, the canonical tables for codes past 12 bits, a slow loop for the
 * string's last octets and the room's last octets). They must agree on everything a decode hands
 * back: the return, the output's counts, and every field's name and value, octet for octet and
 * offset for offset in the space. */

#define HP_FIELDS 8
#define HP_SPACE 4096

/* hpack_result: one decode's output: the return value, the output record, the field records, and
 * the space their strings point into (compared through the fields only: what lies in the space
 * past a string's end is the decoder's scratch, which versions may leave differently). */
typedef struct hpack_result {
    int64_t ret;
    httpasm_hpack_output out;
    httpasm_field fields[HP_FIELDS];
    uint8_t space[HP_SPACE];
} hpack_result;

/* hpack_decode_at: decodes block[0..n) at the tier now set, with a fresh decoder table (a
 * malformed block leaves its table unusable) and `room` octets of space, into *r. */
static void hpack_decode_at(const uint8_t *block, size_t n, size_t room, hpack_result *r)
{
    static uint8_t table[16384];
    memset(r, 0, sizeof *r);
    if (httpasm_hpack_init(table, sizeof table, 4096, 0) != 0) {
        r->ret = 999;                                   /* never: 4096 fits 16 KiB */
        return;
    }
    r->out.fields = r->fields;
    r->out.space = r->space;
    r->out.space_size = room;
    r->out.max_fields = HP_FIELDS;
    r->ret = httpasm_hpack_decode((httpasm_hpack *)table, block, n, &r->out);
}

/* hpack_same: whether two decodes agree: the return, the counts, and each written field's
 * lengths, id, flags, octets, and its strings' offsets in the space (a string from the static
 * table points into the library: compared by content). Returns 1 when they agree. */
static int hpack_same(const hpack_result *a, const hpack_result *b)
{
    if (a->ret != b->ret || a->out.count != b->out.count || a->out.space_used != b->out.space_used ||
        a->out.list_size != b->out.list_size)
        return 0;
    for (uint32_t i = 0; i < a->out.count && i < HP_FIELDS; i++) {
        const httpasm_field *x = &a->fields[i], *y = &b->fields[i];
        if (x->name_length != y->name_length || x->value_length != y->value_length || x->id != y->id ||
            x->flags != y->flags)
            return 0;
        if (memcmp(x->name, y->name, x->name_length) != 0 || memcmp(x->value, y->value, x->value_length) != 0)
            return 0;
        int x_in = x->value >= a->space && x->value < a->space + HP_SPACE;
        int y_in = y->value >= b->space && y->value < b->space + HP_SPACE;
        if (x_in != y_in || (x_in && x->value - a->space != y->value - b->space))
            return 0;
    }
    return 1;
}

/* hpack_check: one block at every tier, against the guard page (its last octet is the page's
 * last, so a refill reading past a string's end, which here is the block's, faults), with `room`
 * octets of space. Every tier must agree with v1, which the .NET suite proves against RFC 7541's
 * examples. Returns 0 when every tier agrees; 1, after reporting, otherwise. */
static int hpack_check(const uint8_t *block, size_t n, size_t room)
{
    static hpack_result expected, actual;
    uint8_t *p = page_end - n;
    memcpy(p, block, n);
    httpasm_cpu_limit(caps[0]);
    hpack_decode_at(p, n, room, &expected);
    for (size_t t = 1; t < TIERS; t++) {
        uint64_t features = httpasm_cpu_limit(caps[t]);
        hpack_decode_at(p, n, room, &actual);
        if (!hpack_same(&expected, &actual)) {
            fprintf(stderr, "httpasm_hpack_decode at %s (features %#llx) differs from v1: returned %lld (%u fields, %zu used), "
                            "v1 %lld (%u fields, %zu used); %zu octets of space\n",
                    cap_names[t], (unsigned long long)features, (long long)actual.ret, actual.out.count, actual.out.space_used,
                    (long long)expected.ret, expected.out.count, expected.out.space_used, room);
            dump("block", p, n);
            return 1;
        }
    }
    return 0;
}

/* hp_put_string: appends a string literal (RFC 7541 5.2): H, the length as a 7-bit-prefix
 * integer (5.1), the octets as given (Huffman-coded or not, as `huffman` claims). Returns the
 * block's new length. */
static size_t hp_put_string(uint8_t *b, size_t n, const uint8_t *s, size_t length, int huffman)
{
    uint8_t h = huffman ? 0x80 : 0x00;
    if (length < 127) {
        b[n++] = (uint8_t)(h | length);
    } else {
        b[n++] = (uint8_t)(h | 127);
        size_t rest = length - 127;
        while (rest >= 128) {
            b[n++] = (uint8_t)(rest | 128);
            rest >>= 7;
        }
        b[n++] = (uint8_t)rest;
    }
    memcpy(b + n, s, length);
    return n + length;
}

/* hp_text: fills s[0..n) with octets drawn mostly from header text (letters, digits, the
 * punctuation of URLs and lists) and, at the rate `rare` in 64, from every octet value: the rare
 * ones (control octets, 0x80-0xFF, "\\<>{}^~|") have the long codes (13-30 bits). */
static void hp_text(uint8_t *s, size_t n, unsigned rare)
{
    static const char common[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:;=, %?&";
    for (size_t i = 0; i < n; i++)
        s[i] = rng() % 64 < rare ? (uint8_t)rng() : (uint8_t)common[rng() % (sizeof common - 1)];
}

/* hpack_tiers: header blocks of Huffman strings, each decoded at every tier with the space
 * drawn from none (measured only: the counting loop), a little (the room runs out inside a
 * string: the slow loop's stores) and plenty (the fast loop's stores):
 *   - valid strings: random header text, rare octets at rates 0-16 in 64, coded by the
 *     library's own encoder (Huffman when it is shorter), 1-4 fields of 0-300 octets;
 *   - arbitrary strings: random octets marked as Huffman (any bit string: symbols, long codes,
 *     EOS, padding too long or not all ones), 0-40 octets, alone or after a valid field, with
 *     every octet of padding tried on a valid one (its last octet replaced by each value).
 * Returns 0 when every block agreed at every tier, 1 at the first that did not. */
static int hpack_tiers(long randoms)
{
    static uint8_t encoder[16384], block[PAGE], text[2][320];
    static const size_t rooms[] = { 0, 1, 7, 15, 16, 17, 31, 64, 300, HP_SPACE };
    long checked = 0;
    for (long i = 0; i < randoms; i++) {
        size_t n = 0;
        if (rng() % 3 != 0) {                           /* valid strings, by the library's encoder */
            if (httpasm_hpack_init(encoder, sizeof encoder, 4096, HTTPASM_HPACK_HUFFMAN) != 0)
                return 1;
            httpasm_field fields[4];
            size_t count = 1 + (size_t)(rng() % 4);
            unsigned rare = (unsigned)(rng() % 17);
            for (size_t k = 0; k < count; k++) {
                memset(&fields[k], 0, sizeof fields[k]);
                size_t name = 1 + (size_t)(rng() % 20), value = (size_t)(rng() % (rng() % 4 == 0 ? 300 : 60));
                hp_text(text[0], name, 0);
                for (size_t c = 0; c < name; c++)       /* HTTP/2 names are lower case */
                    text[0][c] = (uint8_t)(text[0][c] >= 'A' && text[0][c] <= 'Z' ? text[0][c] + 32 : text[0][c]);
                hp_text(text[1], value, rare);
                fields[k].name = (const uint8_t *)memcpy(malloc(name), text[0], name);
                fields[k].name_length = (uint32_t)name;
                fields[k].value = (const uint8_t *)memcpy(malloc(value + 1), text[1], value);
                fields[k].value_length = (uint32_t)value;
                fields[k].flags = HTTPASM_FIELD_FLAG_NO_INDEX;
            }
            int64_t length = httpasm_hpack_encode((httpasm_hpack *)encoder, fields, (uint32_t)count, block, sizeof block);
            for (size_t k = 0; k < count; k++) {
                free((void *)fields[k].name);
                free((void *)fields[k].value);
            }
            if (length <= 0)
                return 1;
            n = (size_t)length;
            if (rng() % 4 == 0 && n > 0)                /* the last octet's padding, any value */
                block[n - 1] = (uint8_t)rng();
        } else {                                        /* arbitrary octets claimed to be Huffman */
            if (rng() % 2) {
                hp_text(text[0], 5, 0);
                block[n++] = 0x00;                      /* a literal field, a new name (6.2.2) */
                n = hp_put_string(block, n, (const uint8_t *)"name", 4, 0);
                n = hp_put_string(block, n, text[0], 5, 0);
            }
            size_t length = (size_t)(rng() % 41);
            for (size_t k = 0; k < length; k++)
                text[1][k] = (uint8_t)(rng() % 4 == 0 ? 0xFF : rng());
            block[n++] = 0x00;
            n = hp_put_string(block, n, (const uint8_t *)"x-huffman", 9, 0);
            n = hp_put_string(block, n, text[1], length, 1);
        }
        for (size_t r = 0; r < sizeof rooms / sizeof rooms[0]; r++) {
            if (rng() % 3 != 0 && r != 0 && r + 1 != sizeof rooms / sizeof rooms[0])
                continue;                               /* none and plenty always; the rest at random */
            if (hpack_check(block, n, rooms[r]))
                return 1;
            checked++;
        }
    }
    /* Strings that end exactly on a code in the middle of a group of lookups, followed in the
     * block by octets whose bits index a long code or a short one: "&" is 8 bits (11111000) and
     * no code fits the 4 bits after it, so each lookup takes one; n of them fill n octets
     * exactly. With 0xFF after them, the lookup after the last reads twelve ones, a long code:
     * the no-op step that hands an ended string to the single-symbol path, which must stop at
     * once. Every count 1-9 (a group is four lookups), each followed by nothing, 0xFF or 0x00. */
    static const uint8_t after[][4] = { { 0xFF, 0xFF, 0xFF, 0xFF }, { 0x00, 0x00, 0x00, 0x00 } };
    for (size_t count = 1; count <= 9; count++) {
        for (size_t tail = 0; tail <= 2; tail++) {
            static uint8_t ampersands[16];
            memset(ampersands, 0xF8, count);
            size_t n = 0;
            block[n++] = 0x00;
            n = hp_put_string(block, n, (const uint8_t *)"x", 1, 0);
            n = hp_put_string(block, n, ampersands, count, 1);
            if (tail > 0) {
                memcpy(block + n, after[tail - 1], 4);    /* the next field's octets, as it were */
                n += 4;
            }
            for (size_t r = 0; r < sizeof rooms / sizeof rooms[0]; r++) {
                if (hpack_check(block, n, rooms[r]))
                    return 1;
                checked++;
            }
        }
    }
    printf("httpasm_hpack_decode: %ld decodes of Huffman strings, every tier agrees with v1\n", checked);
    return 0;
}

/* main: sets up the guard page, prints the tiers this CPU (or SDE) gives, and runs every
 * routine's comparison. Returns 0, 1 on a mismatch, or 2 on a usage or setup error. */
int main(int argc, char **argv)
{
    long randoms = argc > 1 ? strtol(argv[1], NULL, 10) : 200000;
    if (randoms < 0) {
        fprintf(stderr, "usage: tiers [random-inputs-per-routine]\n");
        return 2;
    }

    /* GUARDED readable pages, then the guard: most checks use the last page only, the AEADs'
     * 16 KiB records reach further back. */
    enum { GUARDED = 5 };
    uint8_t *map = mmap(NULL, (GUARDED + 1) * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED || mprotect(map + GUARDED * PAGE, PAGE, PROT_NONE) != 0) {
        perror("tiers: guard page");
        return 2;
    }
    page_end = map + GUARDED * PAGE;

    uint64_t start_features = httpasm_cpu_features();
    printf("found %#llx; tiers:", (unsigned long long)httpasm_cpu_found());
    for (size_t t = 0; t < TIERS; t++)
        printf(" %s=%#llx", cap_names[t], (unsigned long long)httpasm_cpu_limit(caps[t]));
    printf("\n");

    int failed = field_value_scan_tiers(randoms);
    if (!failed)
        failed = token_tiers(randoms);
    if (!failed)
        failed = field_id_tiers(randoms);
    if (!failed)
        failed = parse_tiers(randoms / 10);
    if (!failed)
        failed = parse_variety(randoms / 20);
    if (!failed)
        failed = response_variety(randoms / 20);
    if (!failed)
        failed = h2_tiers(randoms / 4);
    if (!failed)
        failed = sha256_tiers(randoms / 40);
    if (!failed)
        failed = sha512_tiers(randoms / 40);
    if (!failed)
        failed = sha3_tiers(randoms / 40);
    if (!failed)
        failed = aes_tiers(randoms / 40);
    if (!failed)
        failed = gcm_tiers(randoms / 100);
    if (!failed)
        failed = chacha_tiers(randoms / 100);
    if (!failed)
        failed = x25519_tiers(randoms / 1000);
    if (!failed)
        failed = p256_tiers(randoms / 1000);
    if (!failed)
        failed = p384_tiers(randoms / 1000);
    if (!failed)
        failed = ed25519_tiers(randoms / 500);
    if (!failed)
        failed = rsa_tiers(randoms / 1000);
    if (!failed)
        failed = rsa_sign_tiers(rsa_private_hex_1024, 128, randoms / 1000);
    if (!failed)
        failed = rsa_sign_tiers(rsa_private_hex_2048, 256, randoms / 4000);   /* (v1 signs it in 1.4 ms) */
    if (!failed)
        failed = hpack_tiers(randoms / 4);

    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    (void)start_features;
    return failed;
}
