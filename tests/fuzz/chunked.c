/*
 * chunked.c - fuzzes httpasm_h1_chunked_decode (RFC 9112 7.1), the in-place decoder of chunked
 * bodies, and httpasm_h1_parse_trailers (RFC 9112 7.1.2), which reads what follows the last
 * chunk. A chunked body is where request smuggling lives: two parsers that disagree on where a
 * chunk ends see two different messages.
 *
 * The input is a body as received. For every input, at every CPU tier (fuzz.h), it requires:
 *   - agreement with an oracle written from the decoder's documented grammar (oracle() below):
 *     the same verdict (malformed, incomplete in the same state, or at the trailer section after
 *     the same number of octets), the same data octets, the same total and remaining counts;
 *   - streaming: the body arriving in two to five reads (cut where the input's hash says),
 *     each decoded as it comes, gives the one-shot result: the same verdict, data, octets
 *     consumed and final state;
 *   - byte at a time (for inputs up to 2 KiB): the same again, one octet per call;
 *   - the decoder never consumes more than it was given, never produces more than it consumed,
 *     and a malformed body stays malformed;
 *   - when the trailer section is reached: httpasm_h1_parse_trailers' result form (length, 0,
 *     -400, -431), every field inside the section and flagged TRAILER, names that are tokens,
 *     values without control characters or OWS at their ends, resumption across reads, and the
 *     same result at every tier.
 * The input sits against an inaccessible page each time, so a read past it crashes.
 */
#include "fuzz.h"

enum { MAX_FIELDS = 128, MAX_EXTENSION = 4096, BYTEWISE_MAX = 2048 };

/* What one decode of a whole body came to: by the oracle, or by the library over one or more
 * calls. data[0..produced) are the data octets; state is the httpasm_h1_chunked after the last
 * call; malformed is set when a call returned -400; consumed counts the octets the calls took
 * (meaningful when not malformed: the trailer section starts there). */
typedef struct decoded {
    uint8_t data[FUZZ_MAX];
    size_t produced;
    size_t consumed;
    int malformed;
    httpasm_h1_chunked state;
} decoded;

/* hex: an octet's HEXDIG value (RFC 5234 B.1, either case), or -1. */
static int hex(uint8_t c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* oracle: decodes in[0..n) by the grammar chunked.asm documents, written apart from it:
 *   chunk      = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
 *   chunk-size = 1*16HEXDIG, below 2^63 (a 17th digit, or a value past 2^63, is malformed)
 *   chunk-ext  = BWS-or-";" then anything but CTLs (HTAB allowed) up to CR; whitespace after the
 *                size may only be followed by more whitespace and a ";"; the octets after the
 *                size up to the CR count at most 4096
 *   last-chunk = a size of 0: decoding stops after its LF (the trailer section follows)
 * It records the state the library's decoder would be left in, so an incomplete body is
 * compared state for state. */
static void oracle(const uint8_t *in, size_t n, decoded *d)
{
    memset(&d->state, 0, sizeof d->state);
    d->produced = d->consumed = 0;
    d->malformed = 0;
    httpasm_h1_chunked *s = &d->state;
    size_t pos = 0;
    while (pos < n) {
        uint8_t c = in[pos];
        switch (s->state) {
        case HTTPASM_CHUNKED_SIZE: {
            int v = hex(c);
            if (v >= 0) {
                if (s->size_digits == 16 || (s->remaining >> 59) != 0)
                    goto malformed;
                s->remaining = s->remaining << 4 | (uint64_t)v;
                s->size_digits++;
                pos++;
                continue;
            }
            if (s->size_digits == 0)
                goto malformed;
            if (c == '\r')
                s->state = HTTPASM_CHUNKED_SIZE_LF;
            else if (c == ';')
                s->state = HTTPASM_CHUNKED_EXTENSION, s->extension_length = 1;
            else if (c == ' ' || c == '\t')
                s->state = HTTPASM_CHUNKED_EXTENSION_BWS, s->extension_length = 1;
            else
                goto malformed;
            pos++;
            continue;
        }
        case HTTPASM_CHUNKED_EXTENSION_BWS:
            if (c == ';')
                s->state = HTTPASM_CHUNKED_EXTENSION;
            else if (c != ' ' && c != '\t')
                goto malformed;              /* "5 x", and "5 " CRLF: no ";" after the BWS */
            if (++s->extension_length > MAX_EXTENSION)
                goto malformed;
            pos++;
            continue;
        case HTTPASM_CHUNKED_EXTENSION:
            if (c == '\r') {
                s->state = HTTPASM_CHUNKED_SIZE_LF;
                pos++;
                continue;
            }
            if ((c < 0x20 && c != '\t') || c == 0x7f)
                goto malformed;
            if (++s->extension_length > MAX_EXTENSION)
                goto malformed;
            pos++;
            continue;
        case HTTPASM_CHUNKED_SIZE_LF:
            if (c != '\n')
                goto malformed;
            pos++;
            s->size_digits = 0;
            s->extension_length = 0;
            if (s->remaining == 0) {
                s->state = HTTPASM_CHUNKED_TRAILERS;
                d->consumed = pos;
                return;
            }
            s->state = HTTPASM_CHUNKED_DATA;
            continue;
        case HTTPASM_CHUNKED_DATA: {
            size_t take = n - pos < s->remaining ? n - pos : (size_t)s->remaining;
            memcpy(d->data + d->produced, in + pos, take);
            d->produced += take;
            s->total += take;
            s->remaining -= take;
            pos += take;
            if (s->remaining == 0)
                s->state = HTTPASM_CHUNKED_DATA_CR;
            continue;
        }
        case HTTPASM_CHUNKED_DATA_CR:
            if (c != '\r')
                goto malformed;
            s->state = HTTPASM_CHUNKED_DATA_LF;
            pos++;
            continue;
        case HTTPASM_CHUNKED_DATA_LF:
            if (c != '\n')
                goto malformed;
            s->state = HTTPASM_CHUNKED_SIZE;
            pos++;
            continue;
        default:
            FUZZ_CHECK(0, "oracle in state %u", s->state);
        }
    }
    d->consumed = pos;
    return;
malformed:
    s->state = HTTPASM_CHUNKED_ERROR;
    d->malformed = 1;
    d->consumed = pos;
}

/* decode: the library's decoder over in[0..n), delivered in reads ending at cuts[0..count) and
 * then at n, each read placed alone against the guard page (a read past it crashes), as a
 * connection hands over what each read() brought. A read the decoder does not take whole ends
 * the body: it reached the trailer section (or refused the framing).
 *   cuts   strictly increasing offsets in (0, n); count may be 0 (one call for the whole body). */
static void decode(const uint8_t *in, size_t n, const size_t *cuts, size_t count, decoded *d)
{
    memset(&d->state, 0, sizeof d->state);
    d->produced = d->consumed = 0;
    d->malformed = 0;
    size_t from = 0;
    for (size_t k = 0; k <= count; k++) {
        size_t to = k < count ? cuts[k] : n;
        size_t len = to - from, produced = (size_t)-1;
        uint8_t *buf = fuzz_place(in + from, len);
        int64_t r = httpasm_h1_chunked_decode(&d->state, buf, len, &produced);
        FUZZ_CHECK(produced <= len, "produced %zu of a %zu-octet read", produced, len);
        memcpy(d->data + d->produced, buf, produced);
        d->produced += produced;
        if (r < 0) {
            FUZZ_CHECK(r == -400, "result %lld", (long long)r);
            FUZZ_CHECK(d->state.state == HTTPASM_CHUNKED_ERROR, "a refusal in state %u", d->state.state);
            d->malformed = 1;
            /* Refused once, refused forever: the state keeps saying so. */
            size_t again = (size_t)-1;
            FUZZ_CHECK(httpasm_h1_chunked_decode(&d->state, buf, len, &again) == -400 && again == 0, "a malformed body decoded again");
            return;
        }
        FUZZ_CHECK((size_t)r <= len, "consumed %lld of a %zu-octet read", (long long)r, len);
        FUZZ_CHECK(produced <= (size_t)r, "produced %zu from %lld consumed", produced, (long long)r);
        d->consumed += (size_t)r;
        if ((size_t)r < len) {
            FUZZ_CHECK(d->state.state == HTTPASM_CHUNKED_TRAILERS, "stopped after %lld of %zu octets in state %u", (long long)r, len, d->state.state);
            return;
        }
        if (d->state.state == HTTPASM_CHUNKED_TRAILERS)
            return;
        from = to;
    }
}

/* same_decode: whether two decodes agree on everything a caller sees. */
static int same_decode(const decoded *a, const decoded *b)
{
    return a->malformed == b->malformed && a->produced == b->produced && memcmp(a->data, b->data, a->produced) == 0
        && (a->malformed || (a->consumed == b->consumed && memcmp(&a->state, &b->state, sizeof a->state) == 0));
}

/* One parse of a trailer section. */
typedef struct trailers {
    int64_t result;
    size_t scan;
    uint32_t count;
    httpasm_field fields[MAX_FIELDS];
} trailers;

/* parse_trailers: parses buf[0..len) from a fresh scan_from (or the one in t->scan when resume
 * is nonzero), into a zeroed outcome. */
static void parse_trailers(trailers *t, uint8_t *buf, size_t len, int resume)
{
    size_t scan = resume ? t->scan : 0;
    memset(t, 0, sizeof *t);
    t->scan = scan;
    t->result = httpasm_h1_parse_trailers(buf, len, &t->scan, NULL, t->fields, &t->count);
}

/* check_trailers: the invariants of one trailer parse over buf[0..size). */
static void check_trailers(const trailers *t, const uint8_t *buf, size_t size)
{
    int64_t r = t->result;
    if (r < 0) {
        FUZZ_CHECK(r == -400 || r == -431, "trailers: result %lld", (long long)r);
        FUZZ_CHECK(t->scan == 0, "trailers: scan_from %zu after a refusal", t->scan);
        return;
    }
    if (r == 0) {
        FUZZ_CHECK(t->scan <= size, "trailers: scan_from %zu past the input (%zu)", t->scan, size);
        FUZZ_CHECK(t->count == 0, "trailers: %u fields while incomplete", t->count);
        return;
    }
    FUZZ_CHECK(r >= 2 && (size_t)r <= size, "trailers: length %lld of %zu", (long long)r, size);
    FUZZ_CHECK(t->scan == 0, "trailers: scan_from %zu after the section", t->scan);
    FUZZ_CHECK(t->count <= MAX_FIELDS, "trailers: %u fields", t->count);
    for (uint32_t i = 0; i < t->count; i++) {
        const httpasm_field *f = &t->fields[i];
        FUZZ_CHECK(f->flags & HTTPASM_FIELD_FLAG_TRAILER, "trailer %u not flagged", i);
        FUZZ_CHECK(f->name_length > 0 && fuzz_within(f->name, f->name_length, buf, (size_t)r), "trailer %u's name outside", i);
        FUZZ_CHECK(fuzz_within(f->value, f->value_length, buf, (size_t)r), "trailer %u's value outside", i);
        FUZZ_CHECK(httpasm_token_length(f->name, f->name_length) == f->name_length, "trailer %u's name is no token", i);
        FUZZ_CHECK(httpasm_field_value_scan(f->value, f->value_length) == f->value_length, "trailer %u's value holds a CTL", i);
        if (f->value_length > 0) {
            uint8_t first = f->value[0], last = f->value[f->value_length - 1];
            FUZZ_CHECK(first != ' ' && first != '\t' && last != ' ' && last != '\t', "trailer %u's value keeps OWS", i);
        }
    }
}

/* same_trailers: whether two trailer parses are the same, field for field. */
static int same_trailers(const trailers *a, const trailers *b)
{
    return a->result == b->result && a->count == b->count
        && (a->result <= 0 || memcmp(a->fields, b->fields, a->count * sizeof a->fields[0]) == 0);
}

/* LLVMFuzzerTestOneInput: libFuzzer's entry, once per input. Always returns 0. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static decoded expected, whole, pieces, bytes, first;
    static trailers tfirst, tnow, tsplit;
    static size_t single[BYTEWISE_MAX];
    if (size > FUZZ_MAX)
        return 0;
    uint64_t hash = fuzz_hash(data, size);
    size_t cuts[4], count = fuzz_cuts(hash, size, cuts, 4);
    oracle(data, size, &expected);

    for (size_t t = 0; t < FUZZ_TIERS; t++) {
        httpasm_cpu_limit(fuzz_caps[t]);
        decode(data, size, NULL, 0, &whole);
        FUZZ_CHECK(same_decode(&expected, &whole), "the oracle: malformed %d, %zu data octets, consumed %zu, state %u; the decoder: %d, %zu, %zu, %u",
                   expected.malformed, expected.produced, expected.consumed, expected.state.state,
                   whole.malformed, whole.produced, whole.consumed, whole.state.state);
        decode(data, size, cuts, count, &pieces);
        FUZZ_CHECK(same_decode(&whole, &pieces), "in %zu reads: malformed %d, %zu data octets; whole: %d, %zu",
                   count + 1, pieces.malformed, pieces.produced, whole.malformed, whole.produced);
        if (size >= 2 && size <= BYTEWISE_MAX) {
            for (size_t i = 0; i + 1 < size; i++)
                single[i] = i + 1;
            decode(data, size, single, size - 1, &bytes);
            FUZZ_CHECK(same_decode(&whole, &bytes), "byte at a time: malformed %d, %zu data octets; whole: %d, %zu",
                       bytes.malformed, bytes.produced, whole.malformed, whole.produced);
        }
        if (t == 0)
            first = whole;
        else
            FUZZ_CHECK(same_decode(&first, &whole), "tier %zu differs from v1", t + 1);

        /* The trailer section, when the body got there: parsed whole and in reads. */
        if (whole.malformed || whole.state.state != HTTPASM_CHUNKED_TRAILERS)
            continue;
        const uint8_t *section = data + whole.consumed;
        size_t n = size - whole.consumed;
        uint8_t *buf = fuzz_place(section, n);
        parse_trailers(&tnow, buf, n, 0);
        check_trailers(&tnow, buf, n);
        size_t tcuts[4], tcount = fuzz_cuts(hash >> 7, n, tcuts, 4);
        if (tcount != 0) {
            parse_trailers(&tsplit, buf, tcuts[0], 0);
            for (size_t k = 1; tsplit.result == 0 && k < tcount; k++)
                parse_trailers(&tsplit, buf, tcuts[k], 1);
            if (tsplit.result == 0)
                parse_trailers(&tsplit, buf, n, 1);
            check_trailers(&tsplit, buf, n);
            FUZZ_CHECK(same_trailers(&tnow, &tsplit), "trailers in %zu reads: %lld, whole: %lld", tcount + 1,
                       (long long)tsplit.result, (long long)tnow.result);
        }
        if (t == 0)
            tfirst = tnow;
        else
            FUZZ_CHECK(same_trailers(&tfirst, &tnow), "trailers: tier %zu: %lld, v1: %lld", t + 1, (long long)tnow.result, (long long)tfirst.result);
    }
    return 0;
}
