/*
 * h1_request.c - fuzzes httpasm_h1_parse_request, HTTP/1.1's request-head parser (RFC 9112
 * sections 2-6), the first code an attacker's octets reach.
 *
 * For every input, at every CPU tier (fuzz.h), it requires:
 *   - the result's form: the head's length (at most the input's), 0 (incomplete), or one of the
 *     documented statuses (-400, -414, -417, -431, -501, -505) with request.error set;
 *   - for a parsed head: every pointer the request and its fields hold lies inside the head;
 *     every field name is a token and every field value holds only octets a value may hold,
 *     checked again through the library's own C ABI (httpasm_token_length,
 *     httpasm_field_value_scan); the version is 1.0 or 1.1; head_length is the result;
 *   - resumption: parsing a prefix (cut where the input's first octet says) and then the whole
 *     input with the scan_from the prefix left gives exactly the one-shot result, as a
 *     connection's partial reads would;
 *   - the same result, octet for octet and pointer for pointer, at every tier.
 * A broken requirement aborts with its reason (FUZZ_CHECK), which libFuzzer reports as a crash.
 */
#include "fuzz.h"

enum { MAX_FIELDS = 128 };

/* One parse's outcome: the result, the scan_from it left, the request, and its fields. */
typedef struct parse {
    int64_t result;
    size_t scan;
    httpasm_request request;
    httpasm_field fields[MAX_FIELDS];
} parse;

/* parse_once: parses buf[0..len) from a fresh scan_from (or the one in p->scan when resume is
 * nonzero), into a zeroed outcome, so unwritten parts compare equal between parses. */
static void parse_once(parse *p, const uint8_t *buf, size_t len, int resume)
{
    size_t scan = resume ? p->scan : 0;
    memset(p, 0, sizeof *p);
    p->scan = scan;
    p->result = httpasm_h1_parse_request(buf, len, &p->scan, NULL, &p->request, p->fields);
}

/* check_parse: the invariants of one outcome (this file's header). buf, size: the whole input. */
static void check_parse(const parse *p, const uint8_t *buf, size_t size)
{
    int64_t r = p->result;
    const httpasm_request *q = &p->request;
    if (r < 0) {
        FUZZ_CHECK(r == -400 || r == -414 || r == -417 || r == -431 || r == -501 || r == -505, "result %lld", (long long)r);
        FUZZ_CHECK(q->error != 0, "a refusal (%lld) without request.error", (long long)r);
        FUZZ_CHECK(p->scan == 0, "scan_from %zu after a refusal", p->scan);
        return;
    }
    if (r == 0) {
        FUZZ_CHECK(p->scan <= size, "scan_from %zu past the input (%zu)", p->scan, size);
        return;
    }
    size_t head = (size_t)r;
    FUZZ_CHECK(head <= size, "head %zu longer than the input %zu", head, size);
    FUZZ_CHECK(q->head_length == head, "head_length %u, result %zu", q->head_length, head);
    FUZZ_CHECK(q->error == 0, "error %u on success", q->error);
    FUZZ_CHECK(p->scan == 0, "scan_from %zu after a head", p->scan);
    FUZZ_CHECK(q->version == 10 || q->version == 11, "version %u", q->version);
    FUZZ_CHECK(q->method_length > 0 && fuzz_within(q->method, q->method_length, buf, head), "method outside the head");
    FUZZ_CHECK(httpasm_token_length(q->method, q->method_length) == q->method_length, "method is no token");
    FUZZ_CHECK(q->target_length > 0 && fuzz_within(q->target, q->target_length, buf, head), "target outside the head");
    FUZZ_CHECK(fuzz_within(q->authority, q->authority_length, buf, head), "authority outside the head");
    FUZZ_CHECK(fuzz_within(q->scheme, q->scheme_length, buf, head), "scheme outside the head");
    FUZZ_CHECK(q->field_count <= MAX_FIELDS, "%u fields", q->field_count);
    for (uint32_t i = 0; i < q->field_count; i++) {
        const httpasm_field *f = &p->fields[i];
        FUZZ_CHECK(f->name_length > 0 && fuzz_within(f->name, f->name_length, buf, head), "field %u's name outside the head", i);
        FUZZ_CHECK(fuzz_within(f->value, f->value_length, buf, head), "field %u's value outside the head", i);
        FUZZ_CHECK(httpasm_token_length(f->name, f->name_length) == f->name_length, "field %u's name is no token", i);
        FUZZ_CHECK(httpasm_field_value_scan(f->value, f->value_length) == f->value_length, "field %u's value holds a CTL", i);
        if (f->value_length > 0) {
            /* OWS around a value is stripped (RFC 9112 5.1): neither end is SP or HTAB. */
            uint8_t first = f->value[0], last = f->value[f->value_length - 1];
            FUZZ_CHECK(first != ' ' && first != '\t' && last != ' ' && last != '\t', "field %u's value keeps OWS", i);
        }
    }
}

/* same_parse: whether two outcomes are the same - result and error always; for a head, every
 * byte of the request and of the fields written (both outcomes start zeroed). request.fields
 * is the caller's array, which differs between outcomes by design: the arrays' contents are
 * compared instead. */
static int same_parse(const parse *a, const parse *b)
{
    if (a->result != b->result || a->request.error != b->request.error)
        return 0;
    if (a->result <= 0)
        return 1;
    httpasm_request ra = a->request, rb = b->request;
    ra.fields = rb.fields = NULL;
    return memcmp(&ra, &rb, sizeof ra) == 0
        && memcmp(a->fields, b->fields, a->request.field_count * sizeof a->fields[0]) == 0;
}

/* LLVMFuzzerTestOneInput: libFuzzer's entry, once per input. Always returns 0. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static parse first, now, split;
    if (size > FUZZ_MAX)
        return 0;
    for (size_t t = 0; t < FUZZ_TIERS; t++) {
        httpasm_cpu_limit(fuzz_caps[t]);
        uint8_t *buf = fuzz_place(data, size);
        parse_once(&now, buf, size, 0);
        check_parse(&now, buf, size);

        /* Resumption: a prefix, then the whole input from where the prefix left off. The cut
         * comes from the input itself, so libFuzzer can explore it. */
        if (size >= 2) {
            size_t cut = 1 + (size_t)data[0] * (size - 1) / 256;
            parse_once(&split, buf, cut, 0);
            if (split.result == 0)
                parse_once(&split, buf, size, 1);
            check_parse(&split, buf, size);
            FUZZ_CHECK(same_parse(&now, &split), "cut at %zu: %lld then %lld whole", cut, (long long)split.result, (long long)now.result);
        }

        if (t == 0)
            first = now;
        else
            FUZZ_CHECK(same_parse(&first, &now), "tier %zu: %lld, tier v1: %lld", t + 1, (long long)now.result, (long long)first.result);
    }
    return 0;
}
