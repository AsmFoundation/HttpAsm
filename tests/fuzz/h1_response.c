/*
 * h1_response.c - fuzzes httpasm_h1_parse_response, the client's reader of HTTP/1.1 response
 * heads (RFC 9112 sections 4-6), which reads whatever a server, or anything posing as one, sends.
 *
 * The input: its first octet chooses the request's method (octet % 10: 0 is a method the
 * library does not know, 1-9 are HTTPASM_METHOD_GET to _PATCH; HEAD and CONNECT change the
 * framing), the rest is the response. For every input, at every CPU tier (fuzz.h), it requires:
 *   - the result's form: the head's length (at most the input's), 0 (incomplete), or -400 or
 *     -431 with head.error set;
 *   - for a parsed head: head_length is the result; the version is 1.0 or 1.1; the status is
 *     three digits; the reason and every field lie inside the head; the reason and every value
 *     hold no control character but HTAB (httpasm_field_value_scan), every name is a token,
 *     and no value keeps OWS at either end;
 *   - the framing is exactly one of RFC 9112 6.3's outcomes (Content-Length, chunked, until
 *     close, no body, tunnel), with HEAD, 1xx, 204 and 304 never framing a body, a 2xx to
 *     CONNECT a tunnel, and keep-alive never with a body that runs until the close;
 *   - resumption: the response arriving in two to five reads (cut where the input's hash
 *     says, fuzz.h), each parse resuming from the scan_from the last left, gives exactly the
 *     one-shot result, and leaves the buffer as the one-shot parse does (an obs-fold is
 *     replaced with SP in place);
 *   - the same result, the same head and fields and the same rewritten buffer at every tier.
 * A broken requirement aborts with its reason (FUZZ_CHECK), which libFuzzer reports as a crash.
 */
#include "fuzz.h"

enum { MAX_FIELDS = 128 };

/* The framing flags: exactly one outcome of RFC 9112 6.3 per head (TUNNEL comes with NO_BODY). */
#define FRAMING (HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH | HTTPASM_RESPONSE_HEAD_CHUNKED | HTTPASM_RESPONSE_HEAD_UNTIL_CLOSE \
                 | HTTPASM_RESPONSE_HEAD_NO_BODY | HTTPASM_RESPONSE_HEAD_TUNNEL)

/* One parse's outcome: the result, the scan_from it left, the head, its fields, and the buffer
 * as the parse left it (obs-folds rewritten). */
typedef struct parse {
    int64_t result;
    size_t scan;
    httpasm_response_head head;
    httpasm_field fields[MAX_FIELDS];
    uint8_t after[FUZZ_MAX];
} parse;

/* parse_once: parses buf[0..len) for a request of this method, from a fresh scan_from (or the
 * one in p->scan when resume is nonzero), into a zeroed outcome, so unwritten parts compare
 * equal between parses; then keeps a copy of buf[0..size) as the parse left it.
 *   buf, len   what the parser sees; size is the whole input's length (len <= size), copied so a
 *              later whole parse of the same buffer can be compared octet for octet. */
static void parse_once(parse *p, uint8_t *buf, size_t len, size_t size, uint32_t method, int resume)
{
    size_t scan = resume ? p->scan : 0;
    memset(&p->head, 0, sizeof p->head);
    memset(p->fields, 0, sizeof p->fields);
    p->scan = scan;
    p->result = httpasm_h1_parse_response(buf, len, &p->scan, NULL, method, &p->head, p->fields);
    if (size != 0)
        memcpy(p->after, buf, size);
}

/* check_parse: the invariants of one outcome (this file's header).
 *   buf, size  the whole input as placed; method  the request's HTTPASM_METHOD_* (0: unknown). */
static void check_parse(const parse *p, const uint8_t *buf, size_t size, uint32_t method)
{
    int64_t r = p->result;
    const httpasm_response_head *h = &p->head;
    if (r < 0) {
        FUZZ_CHECK(r == -400 || r == -431, "result %lld", (long long)r);
        FUZZ_CHECK(h->error != 0, "a refusal (%lld) without head.error", (long long)r);
        FUZZ_CHECK(p->scan == 0, "scan_from %zu after a refusal", p->scan);
        return;
    }
    if (r == 0) {
        FUZZ_CHECK(p->scan <= size, "scan_from %zu past the input (%zu)", p->scan, size);
        return;
    }
    size_t head = (size_t)r;
    FUZZ_CHECK(head <= size, "head %zu longer than the input %zu", head, size);
    FUZZ_CHECK(h->head_length == head, "head_length %u, result %zu", h->head_length, head);
    FUZZ_CHECK(h->error == 0, "error %u on success", h->error);
    FUZZ_CHECK(p->scan == 0, "scan_from %zu after a head", p->scan);
    FUZZ_CHECK(h->version == 10 || h->version == 11, "version %u", h->version);
    FUZZ_CHECK(h->status <= 999, "status %u is not three digits", h->status);
    FUZZ_CHECK(fuzz_within(h->reason, h->reason_length, buf, head), "reason outside the head");
    FUZZ_CHECK(httpasm_field_value_scan(h->reason, h->reason_length) == h->reason_length, "the reason holds a CTL");
    FUZZ_CHECK(h->field_count <= MAX_FIELDS, "%u fields", h->field_count);
    for (uint32_t i = 0; i < h->field_count; i++) {
        const httpasm_field *f = &p->fields[i];
        FUZZ_CHECK(f->name_length > 0 && fuzz_within(f->name, f->name_length, buf, head), "field %u's name outside the head", i);
        FUZZ_CHECK(fuzz_within(f->value, f->value_length, buf, head), "field %u's value outside the head", i);
        FUZZ_CHECK(httpasm_token_length(f->name, f->name_length) == f->name_length, "field %u's name is no token", i);
        FUZZ_CHECK(httpasm_field_value_scan(f->value, f->value_length) == f->value_length, "field %u's value holds a CTL", i);
        if (f->value_length > 0) {
            uint8_t first = f->value[0], last = f->value[f->value_length - 1];
            FUZZ_CHECK(first != ' ' && first != '\t' && last != ' ' && last != '\t', "field %u's value keeps OWS", i);
        }
    }

    /* The framing (RFC 9112 6.3): one outcome, and the ones the status and method force. */
    uint32_t framing = h->flags & FRAMING;
    FUZZ_CHECK((h->flags & ~(FRAMING | HTTPASM_RESPONSE_HEAD_KEEP_ALIVE)) == 0, "unknown flags 0x%x", h->flags);
    FUZZ_CHECK(framing == HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH || framing == HTTPASM_RESPONSE_HEAD_CHUNKED
                   || framing == HTTPASM_RESPONSE_HEAD_UNTIL_CLOSE || framing == HTTPASM_RESPONSE_HEAD_NO_BODY
                   || framing == (HTTPASM_RESPONSE_HEAD_TUNNEL | HTTPASM_RESPONSE_HEAD_NO_BODY),
               "framing flags 0x%x", framing);
    /* Every 2xx to CONNECT, 204 included, turns the connection into a tunnel right after the
     * head (RFC 9110 9.3.6: "Any 2xx (Successful) response"; RFC 9112 6.3 item 2). Item 1 says
     * a 204 ends at its empty line too, which TUNNEL | NO_BODY also says: the two rules agree,
     * and reading the octets after a 204 to CONNECT as another response would desynchronize
     * the client from the tunnel. */
    int interim = h->status >= 100 && h->status <= 199;
    if (method == HTTPASM_METHOD_CONNECT && h->status >= 200 && h->status <= 299)
        FUZZ_CHECK(framing == (HTTPASM_RESPONSE_HEAD_TUNNEL | HTTPASM_RESPONSE_HEAD_NO_BODY), "a %u to CONNECT is no tunnel (0x%x)", h->status, framing);
    else if (method == HTTPASM_METHOD_HEAD || interim || h->status == 204 || h->status == 304)
        FUZZ_CHECK(framing == HTTPASM_RESPONSE_HEAD_NO_BODY, "status %u to method %u frames a body (0x%x)", h->status, method, framing);
    else
        FUZZ_CHECK((framing & HTTPASM_RESPONSE_HEAD_NO_BODY) == 0, "status %u to method %u has no body", h->status, method);
    if (framing & (HTTPASM_RESPONSE_HEAD_UNTIL_CLOSE | HTTPASM_RESPONSE_HEAD_TUNNEL))
        FUZZ_CHECK((h->flags & HTTPASM_RESPONSE_HEAD_KEEP_ALIVE) == 0, "keep-alive with a body that ends at the close (0x%x)", h->flags);
    if (framing != HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH)
        FUZZ_CHECK(h->content_length == 0, "content_length %llu without its flag", (unsigned long long)h->content_length);
}

/* same_parse: whether two outcomes are the same - result and error always; for a head, every
 * byte of the head record and of the fields written, and the buffer as each parse left it.
 * head.fields is the caller's array, which differs between outcomes by design. */
static int same_parse(const parse *a, const parse *b, size_t size)
{
    if (a->result != b->result || a->head.error != b->head.error)
        return 0;
    if (a->result <= 0)
        return 1;
    httpasm_response_head ha = a->head, hb = b->head;
    ha.fields = hb.fields = NULL;
    return memcmp(&ha, &hb, sizeof ha) == 0
        && memcmp(a->fields, b->fields, a->head.field_count * sizeof a->fields[0]) == 0
        && memcmp(a->after, b->after, size) == 0;
}

/* LLVMFuzzerTestOneInput: libFuzzer's entry, once per input. Always returns 0. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static parse first, now, split;
    if (size < 1 || size - 1 > FUZZ_MAX)
        return 0;
    uint32_t method = data[0] % 10;
    const uint8_t *response = data + 1;
    size_t n = size - 1;
    uint64_t hash = fuzz_hash(data, size);
    for (size_t t = 0; t < FUZZ_TIERS; t++) {
        httpasm_cpu_limit(fuzz_caps[t]);
        /* The buffer is rewritten in place (obs-fold), so every parse starts from a fresh copy. */
        uint8_t *buf = fuzz_place(response, n);
        parse_once(&now, buf, n, n, method, 0);
        check_parse(&now, buf, n, method);

        /* Resumption: the response arrives in up to four reads (cut where the input's hash
         * says, fuzz.h), on a fresh copy, each parse resuming from the scan_from the last one
         * left; the first complete answer, or the whole input's, must be the one-shot result. */
        size_t cuts[4], count = fuzz_cuts(hash, n, cuts, 4), k = 0;
        if (count != 0) {
            buf = fuzz_place(response, n);
            parse_once(&split, buf, cuts[0], n, method, 0);
            for (k = 1; split.result == 0 && k < count; k++)
                parse_once(&split, buf, cuts[k], n, method, 1);
            if (split.result == 0)
                parse_once(&split, buf, n, n, method, 1);
            check_parse(&split, buf, n, method);
            FUZZ_CHECK(same_parse(&now, &split, n), "in %zu reads (first cut at %zu): %lld, whole: %lld", count + 1, cuts[0],
                       (long long)split.result, (long long)now.result);
        }

        if (t == 0)
            first = now;
        else
            FUZZ_CHECK(same_parse(&first, &now, n), "tier %zu: %lld, tier v1: %lld", t + 1, (long long)now.result, (long long)first.result);
    }
    return 0;
}
