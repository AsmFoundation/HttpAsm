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

/* ---- httpasm_h1_parse_request: its field lines are scanned by versions (ha_h1_fields) ------ */

#define PARSE_FIELDS 64

/* parse_result: everything one parse hands back: its return value, the scan position, the
 * request and every field record (whose pointers point into the one input every tier parses,
 * so equal results have equal pointers). */
typedef struct parse_result {
    int64_t ret;
    size_t scan;
    httpasm_request request;
    httpasm_field fields[PARSE_FIELDS];
} parse_result;

/* parse_at: parses buf[0..len) at the tier now set, into *out (zeroed first, so unset parts
 * compare equal). */
static void parse_at(const uint8_t *buf, size_t len, parse_result *out)
{
    memset(out, 0, sizeof *out);
    httpasm_h1_limits limits = { .max_fields = PARSE_FIELDS };
    out->ret = httpasm_h1_parse_request(buf, len, &out->scan, &limits, &out->request, out->fields);
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
        failed = field_id_tiers(randoms);
    if (!failed)
        failed = parse_tiers(randoms / 10);

    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    (void)start_features;
    return failed;
}
