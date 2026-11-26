/*
 * hpack.c - fuzzes HPACK (RFC 7541), HTTP/2's field compression: httpasm_hpack_decode over a
 * sequence of header blocks that share one dynamic table, as a connection's do, and
 * httpasm_hpack_encode on what each block decoded to. A peer controls every octet of these
 * blocks, and an HPACK decoder that slips is a connection-wide desynchronization.
 *
 * The input: a configuration octet, then blocks, each a control octet, a 16-bit little-endian
 * length (cut to what remains) and the block's octets.
 *   configuration bits 0-2: the decoder's limit (SETTINGS_HEADER_TABLE_SIZE), one of LIMITS;
 *                 bits 3-4: the output's room: plenty, few fields, little space, or none;
 *                 bit 5:    the round trip's encoder Huffman-codes strings;
 *                 bit 6:    the encoder indexes every field (HTTPASM_HPACK_INDEX_ALL);
 *   control bit 7: before this block, the round trip's peer advertises a new, never larger,
 *                  table size (bits 0-2 choose it from LIMITS), as a SETTINGS frame would.
 *
 * For every input, at every CPU tier (fuzz.h), it requires:
 *   - each block's result is 0 (every field written), 1 (decoded, but the fields or the space
 *     ran out) or -HTTPASM_ERROR_HPACK_INDEX/INTEGER/TRUNCATED/HUFFMAN/SIZE_UPDATE; after a
 *     malformed block the table is never used again, as RFC 9113 4.3 requires;
 *   - every record lies in the caller's space (within space_used) or is a static table entry's
 *     own text; no more records than max_fields; list_size counts every field, written or
 *     not (RFC 9113 6.5.2), and exactly the written ones when all fit;
 *   - the dynamic table never passes its maximum, nor the maximum the decoder's limit;
 *   - the same results, records and table sizes at every tier (one hash over everything);
 *   - the round trip: every fully decoded block, encoded again (httpasm_hpack_encode, with a
 *     buffer one octet too small first: 0, the table unchanged) and decoded by a second
 *     decoder, gives back the same fields (names of known fields may come back in lower case:
 *     the encoder matches them through the static table, case-insensitively), keeps never-
 *     indexed fields never indexed, never passes httpasm_hpack_encode_bound, and leaves the
 *     encoder's table and the second decoder's entry for entry the same.
 */
#include "fuzz.h"

enum {
    MAX_FIELDS = 256,
    SPACE = 64 * 1024,
    MAX_TABLE = 65536,
    ENCODED_MAX = 512 * 1024,
    STATIC_ENTRIES = 61,
};

/* The table sizes the input chooses from: none, below one entry, one entry, HTTP/2's default and
 * larger ones. */
static const uint32_t LIMITS[8] = { 0, 1, 32, 64, 256, 4096, 16384, MAX_TABLE };

/* A table's memory, sized for the largest limit; aligned like any malloc'd block. */
typedef struct table_memory {
    _Alignas(64) uint8_t bytes[2 * MAX_TABLE + 64 * 1024];
} table_memory;

/* The static table's entries (1-61), as httpasm_hpack_entry gives them: a record pointing at
 * them is the library's constant text, not the caller's space. */
static httpasm_field statics[STATIC_ENTRIES + 1];

/* is_static: whether [p, p + n) is exactly a static entry's name (names) or value. */
static int is_static(const uint8_t *p, uint32_t n, int names)
{
    for (int i = 1; i <= STATIC_ENTRIES; i++) {
        const httpasm_field *s = &statics[i];
        if (names ? (p == s->name && n == s->name_length) : (p == s->value && n == s->value_length))
            return 1;
    }
    return 0;
}

/* mix: one more piece of a run's transcript into its FNV-1a hash. */
static uint64_t mix(uint64_t h, const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++)
        h = (h ^ b[i]) * 0x100000001b3u;
    return h;
}

/* mix_string: a record's string into the hash, by where it lives (the static table's text, or
 * an offset in space) and by its octets. */
static uint64_t mix_string(uint64_t h, const uint8_t *p, uint32_t n, const uint8_t *space)
{
    uint64_t where = is_static(p, n, 1) || is_static(p, n, 0) ? UINT64_MAX : (uint64_t)(p - space);
    if (n == 0)
        where = 0;                           /* an empty string's pointer means nothing */
    h = mix(h, &where, sizeof where);
    h = mix(h, &n, sizeof n);
    return n ? mix(h, p, n) : h;
}

/* new_table: an empty table with this limit in memory; aborts if the library refuses it (the
 * memory is sized for every limit the input can choose, so it never should). */
static httpasm_hpack *new_table(table_memory *m, uint32_t limit, uint32_t flags)
{
    size_t need = httpasm_hpack_size(limit);
    FUZZ_CHECK(need != 0 && need <= sizeof m->bytes, "httpasm_hpack_size(%u) = %zu", limit, need);
    FUZZ_CHECK(httpasm_hpack_init(m->bytes, need, limit, flags) == 0, "httpasm_hpack_init(%u)", limit);
    return (httpasm_hpack *)m->bytes;
}

/* check_table: a table's size against its maximum, and that maximum against the limit. */
static void check_table(const httpasm_hpack *t, uint32_t limit, const char *which)
{
    uint32_t max = 0, size = httpasm_hpack_table_size(t, &max);
    FUZZ_CHECK(size <= max, "%s: table size %u above its maximum %u", which, size, max);
    FUZZ_CHECK(max <= limit, "%s: maximum %u above the limit %u", which, max, limit);
}

/* letters_fold_equal: whether a[0..n) equals the lower-case b[0..n) with only ASCII letters
 * folded (RFC 9110 5.1: field names are case-insensitive, which is about letters; folding any
 * other octet with | 0x20 would make CR match "-" and 0x10-0x19 match digits). */
static int letters_fold_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t c = a[i];
        if (c >= 'A' && c <= 'Z')
            c = (uint8_t)(c + 32);
        if (c != b[i])
            return 0;
    }
    return 1;
}

/* known_id: the known-field id a record of this name must carry, found apart from the library's
 * lookup: through its list of names (httpasm_field_name), letters folded only. 0 when no known
 * name matches. httpasm_field_id cannot serve here: it answers 0 for any name that is not a
 * token, pseudo-fields included, by design. */
static uint32_t known_id(const uint8_t *name, size_t n)
{
    for (uint32_t id = 1; id <= HTTPASM_FIELD_COUNT; id++) {
        size_t length = 0;
        const uint8_t *k = httpasm_field_name(id, &length);
        if (k != NULL && length == n && letters_fold_equal(name, k, n))
            return id;
    }
    return 0;
}

/* same_name_octets: whether a name the encoder was given (a) and the one its peer decoded (b)
 * are the same: exactly, or, for a known field (which the encoder matches through the static
 * table without regard to the letters' case, and so sends by the static table's index), with
 * a's letters in lower case. The encoder's own table keeps a's spelling while the peer's keeps
 * the static table's: their entries' sizes, and so their evictions, stay equal. Any other
 * difference is a field the encoder changed: e.g. a name with CR where a known name has "-"
 * must never come out as that known name. */
static int same_name_octets(const uint8_t *a, uint32_t alength, const uint8_t *b, uint32_t blength)
{
    if (alength != blength)
        return 0;
    if (memcmp(a, b, alength) == 0)
        return 1;
    return known_id(a, alength) != 0 && letters_fold_equal(a, b, alength);
}

/* same_name: same_name_octets for two records. */
static int same_name(const httpasm_field *in, const httpasm_field *out)
{
    return same_name_octets(in->name, in->name_length, out->name, out->name_length);
}

/* same_entries: whether an encoder's table (a) and its peer's (b) hold the same dynamic
 * entries, newest first: the same sizes and values, and names by same_name_octets. */
static int same_entries(const httpasm_hpack *a, const httpasm_hpack *b)
{
    if (httpasm_hpack_table_size(a, NULL) != httpasm_hpack_table_size(b, NULL))
        return 0;
    for (uint32_t i = STATIC_ENTRIES + 1;; i++) {
        httpasm_field ea, eb;
        int ra = httpasm_hpack_entry(a, i, &ea), rb = httpasm_hpack_entry(b, i, &eb);
        if (ra != rb)
            return 0;
        if (ra != 0)
            return 1;
        if (!same_name_octets(ea.name, ea.name_length, eb.name, eb.name_length) || ea.value_length != eb.value_length
            || memcmp(ea.value, eb.value, ea.value_length) != 0)
            return 0;
    }
}

/* The round trip's state: the encoder and the decoder that mirrors it (the peer). */
typedef struct trip {
    httpasm_hpack *encoder, *peer;
    uint32_t peer_limit;
} trip;

/* round_trip: encodes fields[0..count) with the trip's encoder, decodes the block with its
 * peer, and checks this file's header's round-trip rules. */
static void round_trip(trip *rt, const httpasm_field *fields, uint32_t count)
{
    static uint8_t encoded[ENCODED_MAX], space[SPACE];
    static httpasm_field out[MAX_FIELDS];
    size_t bound = httpasm_hpack_encode_bound(fields, count);
    if (bound > ENCODED_MAX)
        return;
    /* One octet short of the bound: refused, and the table untouched. */
    if (bound > 0) {
        uint32_t before = httpasm_hpack_table_size(rt->encoder, NULL);
        FUZZ_CHECK(httpasm_hpack_encode(rt->encoder, fields, count, encoded, bound - 1) == 0, "encoded into %zu octets, below the bound", bound - 1);
        FUZZ_CHECK(httpasm_hpack_table_size(rt->encoder, NULL) == before, "a refused encode changed the table");
    }
    int64_t length = httpasm_hpack_encode(rt->encoder, fields, count, encoded, bound);
    FUZZ_CHECK(length >= 0 && (size_t)length <= bound, "encoded %lld octets, bound %zu", (long long)length, bound);
    FUZZ_CHECK(length > 0 || count == 0, "%u fields encoded to nothing", count);
    check_table(rt->encoder, rt->peer_limit, "encoder");

    httpasm_hpack_output o = { .fields = out, .space = space, .space_size = sizeof space, .max_fields = MAX_FIELDS };
    int64_t r = httpasm_hpack_decode(rt->peer, encoded, (size_t)length, &o);
    FUZZ_CHECK(r == 0, "the peer refused the encoder's block: %lld", (long long)r);
    FUZZ_CHECK(o.count == count, "%u fields came back of %u", o.count, count);
    for (uint32_t i = 0; i < count; i++) {
        FUZZ_CHECK(same_name(&fields[i], &out[i]), "field %u's name changed", i);
        FUZZ_CHECK(fields[i].value_length == out[i].value_length && memcmp(fields[i].value, out[i].value, out[i].value_length) == 0,
                   "field %u's value changed", i);
        if (fields[i].flags & HTTPASM_FIELD_FLAG_NEVER_INDEXED)
            FUZZ_CHECK(out[i].flags & HTTPASM_FIELD_FLAG_NEVER_INDEXED, "field %u lost never-indexed", i);
    }
    check_table(rt->peer, rt->peer_limit, "peer");
    FUZZ_CHECK(same_entries(rt->encoder, rt->peer), "the encoder's table and its peer's differ");
}

/* run: decodes every block of the input once, at the current tier, with its round trips.
 * Returns the hash of everything a caller could see, for the tiers to compare. */
static uint64_t run(const uint8_t *data, size_t size)
{
    static table_memory decoder_memory, encoder_memory, peer_memory;
    static uint8_t space[SPACE];
    static httpasm_field fields[MAX_FIELDS];
    static const size_t ROOM_SPACE[4] = { SPACE, SPACE, 64, 0 };
    static const uint32_t ROOM_FIELDS[4] = { MAX_FIELDS, 2, MAX_FIELDS, 0 };
    uint8_t config = data[0];
    uint32_t limit = LIMITS[config & 7];
    size_t room = (config >> 3) & 3;
    httpasm_hpack *decoder = new_table(&decoder_memory, limit, 0);
    uint32_t encoder_flags = ((config & 0x20) ? HTTPASM_HPACK_HUFFMAN : 0) | ((config & 0x40) ? HTTPASM_HPACK_INDEX_ALL : 0);
    trip rt = { new_table(&encoder_memory, MAX_TABLE, encoder_flags), new_table(&peer_memory, limit, 0), limit };
    httpasm_hpack_encoder_limit(rt.encoder, limit);  /* the peer's SETTINGS, before the first block */

    uint64_t h = 0xcbf29ce484222325u;
    size_t pos = 1;
    while (pos + 3 <= size) {
        uint8_t control = data[pos];
        size_t length = (size_t)data[pos + 1] | (size_t)data[pos + 2] << 8;
        pos += 3;
        if (length > size - pos)
            length = size - pos;
        const uint8_t *block = fuzz_place(data + pos, length);
        pos += length;
        if (control & 0x80) {
            uint32_t smaller = LIMITS[control & 7];
            if (smaller <= rt.peer_limit)
                httpasm_hpack_encoder_limit(rt.encoder, smaller);
        }

        httpasm_hpack_output o = { .fields = fields, .space = space, .space_size = ROOM_SPACE[room], .max_fields = ROOM_FIELDS[room] };
        int64_t r = httpasm_hpack_decode(decoder, block, length, &o);
        h = mix(h, &r, sizeof r);
        if (r < 0) {
            FUZZ_CHECK(r == -HTTPASM_ERROR_HPACK_INDEX || r == -HTTPASM_ERROR_HPACK_INTEGER || r == -HTTPASM_ERROR_HPACK_TRUNCATED
                           || r == -HTTPASM_ERROR_HPACK_HUFFMAN || r == -HTTPASM_ERROR_HPACK_SIZE_UPDATE,
                       "result %lld", (long long)r);
            break;                           /* a COMPRESSION_ERROR: the table is never used again */
        }
        FUZZ_CHECK(r == 0 || r == 1, "result %lld", (long long)r);
        FUZZ_CHECK(o.count <= o.max_fields, "%u records for room for %u", o.count, o.max_fields);
        FUZZ_CHECK(o.space_used <= o.space_size, "space_used %zu of %zu", o.space_used, o.space_size);
        uint64_t listed = 0;
        for (uint32_t i = 0; i < o.count; i++) {
            const httpasm_field *f = &fields[i];
            FUZZ_CHECK(f->name_length == 0 || is_static(f->name, f->name_length, 1) || fuzz_within(f->name, f->name_length, space, o.space_used),
                       "field %u's name is neither static text nor in space", i);
            FUZZ_CHECK(f->value_length == 0 || is_static(f->value, f->value_length, 0) || fuzz_within(f->value, f->value_length, space, o.space_used),
                       "field %u's value is neither static text nor in space", i);
            FUZZ_CHECK((f->flags & ~HTTPASM_FIELD_FLAG_NEVER_INDEXED) == 0, "field %u's flags 0x%x", i, f->flags);
            FUZZ_CHECK(f->id == known_id(f->name, f->name_length), "field %u's id %u, its name's %u", i, f->id, known_id(f->name, f->name_length));
            listed += (uint64_t)f->name_length + f->value_length + 32;
            h = mix_string(h, f->name, f->name_length, space);
            h = mix_string(h, f->value, f->value_length, space);
            h = mix(h, &f->flags, sizeof f->flags);
        }
        if (r == 0)
            FUZZ_CHECK(o.list_size == listed, "list_size %llu, the records add up to %llu", (unsigned long long)o.list_size, (unsigned long long)listed);
        else
            FUZZ_CHECK(o.list_size >= listed, "list_size %llu below the records' %llu", (unsigned long long)o.list_size, (unsigned long long)listed);
        check_table(decoder, limit, "decoder");
        uint32_t max = 0, used = httpasm_hpack_table_size(decoder, &max);
        h = mix(h, &o.count, sizeof o.count);
        h = mix(h, &o.list_size, sizeof o.list_size);
        h = mix(h, &used, sizeof used);
        h = mix(h, &max, sizeof max);

        if (r == 0)
            round_trip(&rt, fields, o.count);
    }
    return h;
}

/* LLVMFuzzerTestOneInput: libFuzzer's entry, once per input. Always returns 0. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1 || size > FUZZ_MAX)
        return 0;
    if (statics[1].name == NULL) {
        static table_memory m;
        httpasm_hpack *t = new_table(&m, 4096, 0);
        for (int i = 1; i <= STATIC_ENTRIES; i++)
            FUZZ_CHECK(httpasm_hpack_entry(t, (uint32_t)i, &statics[i]) == 0, "static entry %d", i);
    }
    uint64_t first = 0;
    for (size_t t = 0; t < FUZZ_TIERS; t++) {
        httpasm_cpu_limit(fuzz_caps[t]);
        uint64_t h = run(data, size);
        if (t == 0)
            first = h;
        else
            FUZZ_CHECK(h == first, "tier %zu's run differs from v1's", t + 1);
    }
    return 0;
}
