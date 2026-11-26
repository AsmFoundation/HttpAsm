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

/* One readable page, then an inaccessible one: page_end - n is where an n-octet input starts. */
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

/* parse_check: one head at every tier, ending `gap` octets before the guard page (the octets
 * between are part of buf: the start of a body, as the caller would hand them over), so a version
 * that reads past the head into the unmapped page dies with SIGSEGV. Every tier must agree with
 * v1, which the .NET suite proves against the RFC.
 *   head, n  the head (n <= PAGE - gap); gap  the octets after it, before the guard page.
 * Returns 0 when every tier agrees; 1, after reporting the tier and the head, otherwise. Leaves
 * the last tier set. */
static int parse_check(const uint8_t *head, size_t n, size_t gap)
{
    static parse_result expected, actual;
    uint8_t *buf = page_end - n - gap;
    memcpy(buf, head, n);
    for (size_t i = 0; i < gap; i++)
        buf[n + i] = (uint8_t)rng();                   /* whatever follows a head */
    httpasm_cpu_limit(caps[0]);
    parse_at(buf, n + gap, &expected);
    for (size_t t = 1; t < TIERS; t++) {
        uint64_t features = httpasm_cpu_limit(caps[t]);
        parse_at(buf, n + gap, &actual);
        if (!parse_same(&expected, &actual)) {
            fprintf(stderr, "httpasm_h1_parse_request at %s (features %#llx) differs from v1: returned %lld (error %u, %u fields), "
                            "v1 %lld (error %u, %u fields); the head ends %zu octets before the guard page\n",
                    cap_names[t], (unsigned long long)features, (long long)actual.ret, actual.request.error, actual.request.field_count,
                    (long long)expected.ret, expected.request.error, expected.request.field_count, gap);
            dump("head", buf, n);
            return 1;
        }
    }
    return 0;
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

    uint8_t *map = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED || mprotect(map + PAGE, PAGE, PROT_NONE) != 0) {
        perror("tiers: guard page");
        return 2;
    }
    page_end = map + PAGE;

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
        failed = hpack_tiers(randoms / 4);

    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    (void)start_features;
    return failed;
}
