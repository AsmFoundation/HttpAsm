/*
 * hpack_nghttp2.c - differential fuzzing of HttpAsm's HPACK decoder (httpasm_hpack_decode)
 * against nghttp2's inflater (nghttp2_hd_inflate_hd3), the HPACK most HTTP/2 deployments run
 * (curl, Apache, Envoy and nginx-quic's predecessors among them). Two decoders that disagree on
 * a block disagree on the request: a front and a back end, or two hops, would act on different
 * headers.
 *
 * nghttp2 1.71.0 is compiled in from its pinned release tarball (tests/tools.sh): only its
 * HPACK sources, never part of HttpAsm. tests/fuzz/run.sh unpacks and compiles them.
 *
 * The input is hpack.c's format: a configuration octet, then blocks, each a control octet, a
 * 16-bit little-endian length (cut to what remains) and the block's octets. Here the
 * configuration's bits 0-1 choose the decoders' limit, SETTINGS_HEADER_TABLE_SIZE: 4096
 * (twice as likely), 16384 or 65536. Limits below 4096 are left out on purpose: HttpAsm's
 * decoder then starts its table at the limit (documented: httpasm_hpack_init), while nghttp2's
 * starts at HTTP/2's 4096 and demands a size update first, so the two model different moments
 * of a connection and would differ by design.
 *
 * For every block, in order, both decoders sharing nothing but the input, it requires:
 *   - the same verdict: both decode the block, or both refuse it (a refusal ends the input:
 *     the table is never used again, RFC 9113 4.3); error codes are not compared, as the two
 *     libraries name them differently;
 *   - for a decoded block: the same fields in the same order, octet for octet, with the same
 *     never-indexed marks (HttpAsm's HTTPASM_FIELD_FLAG_NEVER_INDEXED, nghttp2's
 *     NGHTTP2_NV_FLAG_NO_INDEX); when HttpAsm's output room runs out (result 1), the records
 *     it wrote match nghttp2's first ones and its list_size matches the whole list's;
 *   - the same dynamic table size and maximum after the block.
 * HttpAsm runs at the best tier the CPU has; tests/fuzz/hpack proves every tier equal to it.
 */
#include "fuzz.h"

#include <nghttp2/nghttp2.h>

enum { MAX_FIELDS = 4096, SPACE = 1024 * 1024, MAX_TABLE = 65536 };

/* LIMITS: the SETTINGS_HEADER_TABLE_SIZE values the input chooses from (none below 4096: see
 * this file's header). */
static const uint32_t LIMITS[4] = { 4096, 4096, 16384, MAX_TABLE };

/* A table's memory, sized for the largest limit. */
typedef struct table_memory {
    _Alignas(64) uint8_t bytes[2 * MAX_TABLE + 64 * 1024];
} table_memory;

/* compare_block: decodes one block with both decoders and checks this file's header's rules.
 * Returns 1 when both decoded it, 0 when both refused it (the input ends there). */
static int compare_block(httpasm_hpack *ours, nghttp2_hd_inflater *theirs, const uint8_t *block, size_t length)
{
    static httpasm_field fields[MAX_FIELDS];
    static uint8_t space[SPACE];
    httpasm_hpack_output o = { .fields = fields, .space = space, .space_size = sizeof space, .max_fields = MAX_FIELDS };
    int64_t r = httpasm_hpack_decode(ours, block, length, &o);

    /* nghttp2, field by field, each compared as it comes: its strings are valid only until
     * its next call. */
    const uint8_t *in = block;
    size_t left = length;
    uint32_t n = 0;
    uint64_t list = 0;
    int refused = 0;
    for (;;) {
        nghttp2_nv nv;
        int flags = 0;
        nghttp2_ssize used = nghttp2_hd_inflate_hd3(theirs, &nv, &flags, in, left, 1);
        if (used < 0) {
            refused = 1;
            break;
        }
        in += used;
        left -= (size_t)used;
        if (flags & NGHTTP2_HD_INFLATE_EMIT) {
            if (r >= 0 && n < o.count) {
                const httpasm_field *f = &fields[n];
                FUZZ_CHECK(f->name_length == nv.namelen && memcmp(f->name, nv.name, nv.namelen) == 0,
                           "field %u's name: HttpAsm %.*s, nghttp2 %.*s", n, (int)f->name_length, (const char *)f->name,
                           (int)nv.namelen, (const char *)nv.name);
                FUZZ_CHECK(f->value_length == nv.valuelen && memcmp(f->value, nv.value, nv.valuelen) == 0,
                           "field %u's value differs (%u and %zu octets)", n, f->value_length, nv.valuelen);
                FUZZ_CHECK(((f->flags & HTTPASM_FIELD_FLAG_NEVER_INDEXED) != 0) == ((nv.flags & NGHTTP2_NV_FLAG_NO_INDEX) != 0),
                           "field %u's never-indexed mark: HttpAsm %u, nghttp2 %u", n, f->flags, nv.flags);
            }
            list += (uint64_t)nv.namelen + nv.valuelen + 32;
            n++;
        }
        if (flags & NGHTTP2_HD_INFLATE_FINAL) {
            nghttp2_hd_inflate_end_headers(theirs);
            break;
        }
        if ((flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && left == 0) {
            refused = 1;                     /* in_final and nothing more: a truncated block */
            break;
        }
    }

    FUZZ_CHECK((r < 0) == refused, "verdicts differ: HttpAsm %lld, nghttp2 %s after %u fields", (long long)r,
               refused ? "refused" : "decoded", n);
    if (refused)
        return 0;
    FUZZ_CHECK(r == 0 ? o.count == n : o.count <= n, "HttpAsm wrote %u records (result %lld), nghttp2 %u fields", o.count, (long long)r, n);
    FUZZ_CHECK(o.list_size == list, "list_size: HttpAsm %llu, nghttp2's fields %llu", (unsigned long long)o.list_size, (unsigned long long)list);
    uint32_t max = 0, size = httpasm_hpack_table_size(ours, &max);
    FUZZ_CHECK(size == nghttp2_hd_inflate_get_dynamic_table_size(theirs), "table size: HttpAsm %u, nghttp2 %zu", size,
               nghttp2_hd_inflate_get_dynamic_table_size(theirs));
    FUZZ_CHECK(max == nghttp2_hd_inflate_get_max_dynamic_table_size(theirs), "table maximum: HttpAsm %u, nghttp2 %zu", max,
               nghttp2_hd_inflate_get_max_dynamic_table_size(theirs));
    return 1;
}

/* LLVMFuzzerTestOneInput: libFuzzer's entry, once per input. Always returns 0. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static table_memory memory;
    if (size < 1 || size > FUZZ_MAX)
        return 0;
    uint32_t limit = LIMITS[data[0] & 3];
    size_t need = httpasm_hpack_size(limit);
    FUZZ_CHECK(need != 0 && need <= sizeof memory.bytes && httpasm_hpack_init(memory.bytes, need, limit, 0) == 0, "init(%u)", limit);
    httpasm_hpack *ours = (httpasm_hpack *)memory.bytes;
    nghttp2_hd_inflater *theirs = NULL;
    FUZZ_CHECK(nghttp2_hd_inflate_new(&theirs) == 0 && nghttp2_hd_inflate_change_table_size(theirs, limit) == 0, "nghttp2's inflater");

    size_t pos = 1;
    while (pos + 3 <= size) {
        size_t length = (size_t)data[pos + 1] | (size_t)data[pos + 2] << 8;
        pos += 3;
        if (length > size - pos)
            length = size - pos;
        const uint8_t *block = fuzz_place(data + pos, length);
        pos += length;
        if (!compare_block(ours, theirs, block, length))
            break;
    }
    nghttp2_hd_inflate_del(theirs);
    return 0;
}
