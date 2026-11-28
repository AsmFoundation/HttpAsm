/*
 * asn1.c - fuzzes the ASN.1 reader (asn1/asn1.asm): httpasm_asn1_read, httpasm_asn1_check,
 * httpasm_asn1_check_set_of, httpasm_asn1_octets and httpasm_asn1_bits, under DER and BER. The
 * reader takes certificates from TLS peers and private keys from files: every octet is hostile.
 *
 * The input is an encoding. For every input, at every CPU tier (fuzz.h), it requires:
 *   - agreement with a model written apart from the assembly (model_read() below, in plain C
 *     from X.690's rules as httpasm.h states them): the same verdict, tag, contents, lengths and
 *     flags for the first element, and then, walking in step, for every element nested in an
 *     accepted constructed one (strings aside: their segments are the reader's own business);
 *     the model checks characters on a string's joined value and BIT STRING segments on their
 *     flattened list, where the assembly streams through the segments, so the two get there by
 *     different roads;
 *   - for each accepted element: httpasm_asn1_check under a type the input's hash picks (and
 *     the element's own universal type) agrees with the model; httpasm_asn1_check_set_of agrees
 *     on every constructed element; httpasm_asn1_octets and httpasm_asn1_bits give the model's
 *     joined value (with room to spare, and with one octet too few, which must fail);
 *   - DER is a profile of BER: an element DER reads, BER reads identically;
 *   - no read past the input: the input, and each nested element's remaining contents, sit
 *     against an inaccessible page (two mappings, the second for nested slices).
 */
#include "fuzz.h"

enum { MODEL_DEPTH = 32, TIME_ROOM = 64 };

/* An element as the model reads it: offsets into its input. */
typedef struct melem {
    size_t content, content_length, length;
    uint32_t tag, flags;
} melem;

static int model_read(const uint8_t *in, size_t n, int ber, int raw, int depth, melem *e);
static int model_type(const uint8_t *in, const melem *e, uint32_t number, int ber, int depth);

/* model_join: a string element's value (its segments' contents, joined in order; a BIT
 * STRING's without each segment's initial octet, *unused the last segment's) appended to out,
 * which has room for cap octets, at *len. Returns 0, or -1 when a segment does not read or the
 * value does not fit. The element was checked: its segments are well formed. */
static int model_join(const uint8_t *in, const melem *e, int ber, int bits, int depth,
                      uint8_t *out, size_t cap, size_t *len, unsigned *unused)
{
    const uint8_t *c = in + e->content;
    if (!(e->tag & HTTPASM_ASN1_CONSTRUCTED)) {
        size_t skip = bits ? 1 : 0;
        if (bits)
            *unused = c[0];
        if (e->content_length - skip > cap - *len)
            return -1;
        memcpy(out + *len, c + skip, e->content_length - skip);
        *len += e->content_length - skip;
        return 0;
    }
    if (depth == 0)
        return -1;
    for (size_t at = 0; at < e->content_length;) {
        melem s;
        if (model_read(c + at, e->content_length - at, ber, 1, depth - 1, &s) != 0)
            return -1;
        melem shifted = s;
        shifted.content += (size_t)(c + at - in);
        if (model_join(in, &shifted, ber, bits, depth - 1, out, cap, len, unused) != 0)
            return -1;
        at += s.length;
    }
    return 0;
}

/* model_segments: whether a constructed string's segments are, at every depth, encodings of
 * universal type seg (3 or 4), each primitive one of a BIT STRING well formed, and (for BIT
 * STRING) every primitive segment but the very last ending on a whole octet. *last carries the
 * unused bits of the latest primitive BIT STRING segment across the walk. */
static int model_segments(const uint8_t *in, const melem *e, uint32_t seg, int ber, int depth, int *last)
{
    if (depth == 0)
        return -1;
    const uint8_t *c = in + e->content;
    for (size_t at = 0; at < e->content_length;) {
        melem s;
        if (model_read(c + at, e->content_length - at, ber, 1, depth - 1, &s) != 0)
            return -1;
        if ((s.tag & ~HTTPASM_ASN1_CONSTRUCTED) != seg)
            return -1;
        if (s.tag & HTTPASM_ASN1_CONSTRUCTED) {
            melem shifted = s;
            shifted.content += (size_t)(c + at - in);
            if (model_segments(in, &shifted, seg, ber, depth - 1, last) != 0)
                return -1;
        } else if (seg == HTTPASM_ASN1_BIT_STRING) {
            const uint8_t *sc = c + at + s.content;
            if (*last != 0 || s.content_length == 0 || sc[0] > 7 || (s.content_length == 1 && sc[0] != 0))
                return -1;
            *last = sc[0];
        }
        at += s.length;
    }
    return 0;
}

/* The characters each string type allows, one octet at a time (UTF-8, BMP and Universal apart). */
static int printable(int c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ' ' ||
           c == '\'' || c == '(' || c == ')' || c == '+' || c == ',' || c == '-' || c == '.' ||
           c == '/' || c == ':' || c == '=' || c == '?';
}

/* utf8_valid: RFC 3629's UTF-8: the fewest octets, no surrogate, nothing past U+10FFFF. */
static int utf8_valid(const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n;) {
        uint32_t c = s[i];
        size_t k;
        uint32_t min;
        if (c < 0x80) {
            i++;
            continue;
        } else if ((c & 0xE0) == 0xC0) {
            k = 1, c &= 0x1F, min = 0x80;
        } else if ((c & 0xF0) == 0xE0) {
            k = 2, c &= 0x0F, min = 0x800;
        } else if ((c & 0xF8) == 0xF0) {
            k = 3, c &= 0x07, min = 0x10000;
        } else {
            return 0;
        }
        if (n - i - 1 < k)
            return 0;
        for (size_t j = 1; j <= k; j++) {
            if ((s[i + j] & 0xC0) != 0x80)
                return 0;
            c = (c << 6) | (s[i + j] & 0x3F);
        }
        if (c < min || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF))
            return 0;
        i += k + 1;
    }
    return 1;
}

/* chars_valid: whether a value is in a string type's set (X.680's tables, ISO 10646's forms). */
static int chars_valid(uint32_t number, const uint8_t *s, size_t n)
{
    switch (number) {
    case 12:
        return utf8_valid(s, n);
    case 30:
        if (n % 2)
            return 0;
        for (size_t i = 0; i < n; i += 2)
            if (s[i] >= 0xD8 && s[i] <= 0xDF)
                return 0;
        return 1;
    case 28:
        if (n % 4)
            return 0;
        for (size_t i = 0; i < n; i += 4) {
            uint32_t c = (uint32_t)s[i] << 24 | (uint32_t)s[i + 1] << 16 | (uint32_t)s[i + 2] << 8 | s[i + 3];
            if (c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF))
                return 0;
        }
        return 1;
    case 20: case 21: case 25: case 27:
        return 1;
    default:
        for (size_t i = 0; i < n; i++) {
            int c = s[i];
            int ok = number == 19 ? printable(c)
                   : number == 18 ? (c == ' ' || (c >= '0' && c <= '9'))
                   : number == 22 ? c < 128
                   : (c >= 0x20 && c <= 0x7E);          /* 26, 23, 24 */
            if (!ok)
                return 0;
        }
        return 1;
    }
}

/* two: the number two digits spell; digit: whether a character is one. */
static int digit(uint8_t c) { return c >= '0' && c <= '9'; }
static int two(const uint8_t *s) { return (s[0] - '0') * 10 + (s[1] - '0'); }

/* time_valid: a time's characters in the rules' forms (httpasm.h): DER YYMMDDhhmmssZ and
 * YYYYMMDDhhmmss[.f]Z without a trailing zero; BER X.680's (optional seconds, differentials,
 * GeneralizedTime's optional minutes, local time, fractions with "." or ","). */
static int time_valid(int generalized, int ber, const uint8_t *s, size_t n)
{
    size_t y = generalized ? 4 : 2, i, end = n;
    if (n < 10)
        return 0;
    for (i = 0; i < 10; i++)
        if (!digit(s[i]))
            return 0;
    int minute = !generalized, second = 0;
    if (generalized && i + 2 <= end && digit(s[i]) && digit(s[i + 1]))
        minute = 1, i += 2;
    if (minute && i + 2 <= end && digit(s[i]) && digit(s[i + 1]))
        second = 1, i += 2;
    if (!ber && !(minute && second))
        return 0;
    if (generalized && i < end && (s[i] == '.' || (ber && s[i] == ','))) {
        size_t f = ++i;
        while (i < end && digit(s[i]))
            i++;
        if (i == f || (!ber && s[i - 1] == '0'))
            return 0;
    }
    if (!ber) {
        if (i + 1 != end || s[i] != 'Z')
            return 0;
    } else if (i == end) {
        if (!generalized)
            return 0;
    } else if (s[i] == 'Z') {
        if (i + 1 != end)
            return 0;
    } else if (s[i] == '+' || s[i] == '-') {
        i++;
        if (end - i == 4) {
            if (!digit(s[i]) || !digit(s[i + 1]) || !digit(s[i + 2]) || !digit(s[i + 3]) || two(s + i) > 23 || two(s + i + 2) > 59)
                return 0;
        } else if (end - i == 2 && generalized) {
            if (!digit(s[i]) || !digit(s[i + 1]) || two(s + i) > 23)
                return 0;
        } else {
            return 0;
        }
    } else {
        return 0;
    }
    int year = generalized ? two(s) * 100 + two(s + 2) : two(s);
    int leap = generalized ? (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) : year % 4 == 0;
    static const int days[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    int month = two(s + y), day = two(s + y + 2), hour = two(s + y + 4);
    if (month < 1 || month > 12 || day < 1 || day > days[month - 1] + (month == 2 && leap) || hour > 23)
        return 0;
    if (minute && two(s + y + 6) > 59)
        return 0;
    if (second && two(s + y + 8) > 59)
        return 0;
    return 1;
}

/* model_type: universal type number's rules for an element (form, contents, segments). */
static int model_type(const uint8_t *in, const melem *e, uint32_t number, int ber, int depth)
{
    const uint8_t *c = in + e->content;
    size_t n = e->content_length;
    int constructed = (e->tag & HTTPASM_ASN1_CONSTRUCTED) != 0;
    switch (number) {
    case 1:
        return !constructed && n == 1 && (ber || c[0] == 0 || c[0] == 0xFF) ? 0 : -1;
    case 2: case 10:
        if (constructed || n == 0)
            return -1;
        if (n >= 2 && ((c[0] == 0 && c[1] < 0x80) || (c[0] == 0xFF && c[1] >= 0x80)))
            return -1;
        return 0;
    case 3:
        if (constructed) {
            int last = 0;
            return ber ? model_segments(in, e, 3, ber, depth, &last) : -1;
        }
        if (n == 0 || c[0] > 7 || (n == 1 && c[0] != 0))
            return -1;
        if (!ber && n > 1 && (c[n - 1] & ((1u << c[0]) - 1)))
            return -1;
        return 0;
    case 4:
        if (!constructed)
            return 0;
        {
            int last = 0;
            return ber ? model_segments(in, e, 4, ber, depth, &last) : -1;
        }
    case 5:
        return !constructed && n == 0 ? 0 : -1;
    case 6:
        if (constructed || n == 0 || (c[n - 1] & 0x80))
            return -1;
        for (size_t i = 0; i < n; i++)
            if (c[i] == 0x80 && (i == 0 || !(c[i - 1] & 0x80)))
                return -1;
        return 0;
    case 16: case 17:
        return constructed ? 0 : -1;
    case 12: case 18: case 19: case 20: case 21: case 22: case 23: case 24: case 25: case 26:
    case 27: case 28: case 30:
        {
            uint8_t *value = malloc(n ? n : 1);
            size_t len = 0;
            unsigned unused = 0;
            int ok;
            if (constructed) {
                int last = 0;
                ok = ber && model_segments(in, e, 4, ber, depth, &last) == 0 &&
                     model_join(in, e, ber, 0, depth, value, n, &len, &unused) == 0;
            } else {
                memcpy(value, c, n);
                len = n;
                ok = 1;
            }
            ok = ok && chars_valid(number, value, len);
            if (ok && (number == 23 || number == 24)) {
                /* a constructed time is gathered into 64 octets first (asn1.asm's TF_TIME) */
                ok = (!constructed || len <= TIME_ROOM) && time_valid(number == 24, ber, value, len);
            }
            free(value);
            return ok ? 0 : -1;
        }
    default:
        return -1;
    }
}

/* model_read: the first element of in[0..n) under DER (ber 0) or BER, with depth nesting levels
 * left; raw: the structure only. Returns 0 with *e set, or -1. */
static int model_read(const uint8_t *in, size_t n, int ber, int raw, int depth, melem *e)
{
    if (n < 2)
        return -1;
    size_t p = 1;
    uint32_t number = in[0] & 0x1F;
    if (number == 31) {
        int count = 0;
        number = 0;
        for (;;) {
            if (p >= n)
                return -1;
            uint8_t b = in[p++];
            if (count == 0 && b == 0x80)
                return -1;
            if (++count > 4)
                return -1;
            number = number << 7 | (b & 0x7F);
            if (!(b & 0x80))
                break;
        }
        if (number < 31)
            return -1;
    }
    e->tag = (uint32_t)(in[0] & 0xE0) << 24 | number;
    if (p >= n)
        return -1;
    uint8_t l0 = in[p++];
    if (l0 == 0x80) {
        if (!ber || !(in[0] & 0x20) || depth == 0)
            return -1;
        /* The nested elements are read whole to find the end, but structurally only when the
         * structure's own check reads them again: a raw read's (its caller's segment walk
         * checks them), and a universal string's (model_type's segment walk does). Reading
         * those whole as well doubled the work at every level of nested indefinite segments,
         * as the assembly's first version did (2^depth: tests/fuzz/asn1.c's timeout of
         * 2026-11-28); the verdict is the same, the segment walk checking more than a whole
         * read of a segment would. The assembly now ends such a string in its segment walk
         * instead, one pass: the two still get there by different roads. */
        int universal = (in[0] & 0xC0) == 0, nested_raw = raw;
        if (universal && !raw)
            switch (number) {
            case 3: case 4: case 12: case 18: case 19: case 20: case 21: case 22: case 23: case 24:
            case 25: case 26: case 27: case 28: case 30:
                nested_raw = 1;
                break;
            default:
                break;
            }
        size_t start = p;
        for (;;) {
            if (n - p < 2)
                return -1;
            if (in[p] == 0 && in[p + 1] == 0)
                break;
            melem inner;
            if (model_read(in + p, n - p, ber, nested_raw, depth - 1, &inner) != 0)
                return -1;
            p += inner.length;
        }
        e->content = start, e->content_length = p - start, e->length = p + 2, e->flags = HTTPASM_ASN1_INDEFINITE;
    } else {
        uint64_t len = l0;
        if (l0 > 0x80) {
            if (l0 == 0xFF)
                return -1;
            size_t k = l0 & 0x7F;
            if (k > n - p)
                return -1;
            len = 0;
            for (size_t i = 0; i < k; i++) {
                uint8_t b = in[p++];
                if (i == 0 && b == 0 && !ber)
                    return -1;
                if (len >> 56)
                    return -1;
                len = len << 8 | b;
            }
            if (!ber && len < 128)
                return -1;
        }
        if (len > n - p)
            return -1;
        e->content = p, e->content_length = len, e->length = p + len, e->flags = 0;
    }
    if (raw || (e->tag & HTTPASM_ASN1_CLASS))
        return 0;
    return model_type(in, e, e->tag & HTTPASM_ASN1_NUMBER, ber, depth);
}

/* model_set_of: httpasm_asn1_check_set_of's verdict: every component reads, and under DER they
 * ascend (compared as octet strings, the shorter padded with zeros). */
static int model_set_of(const uint8_t *in, const melem *e, int ber)
{
    if (!(e->tag & HTTPASM_ASN1_CONSTRUCTED))
        return -1;
    const uint8_t *c = in + e->content, *prev = NULL;
    size_t prev_length = 0;
    for (size_t at = 0; at < e->content_length;) {
        melem s;
        if (model_read(c + at, e->content_length - at, ber, 0, MODEL_DEPTH, &s) != 0)
            return -1;
        if (!ber && prev != NULL) {
            size_t common = prev_length < s.length ? prev_length : s.length, i;
            int order = 0;
            for (i = 0; i < common && order == 0; i++)
                order = prev[i] < c[at + i] ? -1 : prev[i] > c[at + i] ? 1 : 0;
            for (i = common; order == 0 && i < prev_length; i++)
                order = prev[i] != 0;
            if (order > 0)
                return -1;
        }
        prev = c + at, prev_length = s.length;
        at += s.length;
    }
    return 0;
}

/* nested_place: fuzz_place for a nested element's remaining contents, in a mapping of its own
 * (the input occupies fuzz_place's). */
static uint8_t *nested_place(const uint8_t *data, size_t n)
{
    static uint8_t *end;
    if (end == NULL) {
        size_t pages = FUZZ_MAX / FUZZ_PAGE + 1;
        uint8_t *map = mmap(NULL, (pages + 1) * FUZZ_PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map == MAP_FAILED || mprotect(map + pages * FUZZ_PAGE, FUZZ_PAGE, PROT_NONE) != 0)
            abort();
        end = map + pages * FUZZ_PAGE;
    }
    uint8_t *p = end - n;
    memmove(p, data, n);
    return p;
}

static uint64_t seed;

/* compare: the first element of in[0..n) (placed against a guard page) by both readers, and the
 * calls on it; returns its length when both read it, else 0. */
static size_t compare(const uint8_t *in, size_t n, int rules, int level)
{
    int ber = rules == HTTPASM_ASN1_BER;
    httpasm_asn1 a;
    melem m;
    int ra = httpasm_asn1_read(&a, in, n, rules);
    int rm = model_read(in, n, ber, 0, MODEL_DEPTH, &m);
    FUZZ_CHECK(ra == rm, "read: library %d, model %d, rules %d, %zu octets", ra, rm, rules, n);
    if (ra != 0)
        return 0;
    FUZZ_CHECK(a.tag == m.tag && a.content == in + m.content && a.content_length == m.content_length &&
               a.length == m.length && a.flags == m.flags,
               "fields: tag %x/%x content +%td/+%zu length %zu/%zu whole %zu/%zu flags %u/%u", a.tag, m.tag,
               a.content - in, m.content, a.content_length, m.content_length, a.length, m.length, a.flags, m.flags);
    FUZZ_CHECK(a.length <= n && fuzz_within(a.content, a.content_length, in, n), "the element lies outside its input");
    if (!ber) {
        httpasm_asn1 b;
        FUZZ_CHECK(httpasm_asn1_read(&b, in, n, HTTPASM_ASN1_BER) == 0 && memcmp(&a, &b, sizeof a) == 0,
                   "DER read an element BER did not read the same way");
    }

    /* httpasm_asn1_check under a type the hash picks, and the element's own universal type */
    seed = seed * 6364136223846793005ull + 1442695040888963407ull;
    uint32_t types[2] = { (uint32_t)(seed >> 59), a.tag & HTTPASM_ASN1_NUMBER };
    for (int t = 0; t < 2; t++) {
        uint32_t type = types[t];
        int ca = httpasm_asn1_check(&a, type, rules);
        int cm = type > 30 ? -1 : model_type(in, &m, type, ber, MODEL_DEPTH);
        FUZZ_CHECK(ca == cm, "check as %u: library %d, model %d", type, ca, cm);
    }

    if (a.tag & HTTPASM_ASN1_CONSTRUCTED) {
        int sa = httpasm_asn1_check_set_of(&a, rules), sm = model_set_of(in, &m, ber);
        FUZZ_CHECK(sa == sm, "set of: library %d, model %d", sa, sm);
    }

    /* the joined value of a string, as OCTET STRING and as BIT STRING */
    if (a.content_length <= 8192) {
        static uint8_t got[8192 + 1], want[8192 + 1];
        for (int bits = 0; bits <= 1; bits++) {
            uint32_t type = bits ? HTTPASM_ASN1_BIT_STRING : HTTPASM_ASN1_OCTET_STRING;
            int valid = model_type(in, &m, type, ber, MODEL_DEPTH) == 0;
            size_t len = 0;
            unsigned unused_model = 0;
            if (valid && model_join(in, &m, ber, bits, MODEL_DEPTH, want, sizeof want, &len, &unused_model) != 0)
                valid = 0;
            uint32_t unused = 99;
            int64_t r = bits ? httpasm_asn1_bits(&a, got, sizeof got, &unused, rules)
                             : httpasm_asn1_octets(&a, got, sizeof got, rules);
            FUZZ_CHECK((r >= 0) == valid, "%s: library %lld, model %d", bits ? "bits" : "octets", (long long)r, valid);
            if (r >= 0) {
                FUZZ_CHECK((size_t)r == len && memcmp(got, want, len) == 0, "%s: a different value", bits ? "bits" : "octets");
                FUZZ_CHECK(!bits || unused == unused_model, "bits: unused %u, model %u", unused, unused_model);
                if (len > 0) {
                    int64_t short1 = bits ? httpasm_asn1_bits(&a, got, len - 1, &unused, rules)
                                          : httpasm_asn1_octets(&a, got, len - 1, rules);
                    FUZZ_CHECK(short1 == -1, "%s: one octet too few room was taken", bits ? "bits" : "octets");
                }
            }
        }
    }

    /* the nested elements of a constructed element (not a string's segments) */
    uint32_t number = a.tag & HTTPASM_ASN1_NUMBER;
    int universal_string = !(a.tag & HTTPASM_ASN1_CLASS) &&
                           (number == 3 || number == 4 || number == 12 || (number >= 18 && number <= 28) || number == 30);
    if ((a.tag & HTTPASM_ASN1_CONSTRUCTED) && !universal_string && level < 8) {
        size_t start = (size_t)(a.content - in), length = a.content_length, done = 0;
        /* A copy per level: each child's placement overwrites the nested mapping, the slice
         * this level was itself placed in included (it is not read again after this). */
        static uint8_t copies[9][FUZZ_MAX];
        uint8_t *copy = copies[level];
        memcpy(copy, in + start, length);
        while (done < length) {
            uint8_t *at = nested_place(copy + done, length - done);
            size_t used = compare(at, length - done, rules, level + 1);
            if (used == 0)
                break;
            done += used;
        }
    }
    return a.length;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
    if (n > FUZZ_MAX)
        return 0;
    for (size_t t = 0; t < FUZZ_TIERS; t++) {
        httpasm_cpu_limit(fuzz_caps[t]);
        uint8_t *in = fuzz_place(data, n);
        seed = fuzz_hash(data, n);
        compare(in, n, HTTPASM_ASN1_DER, 0);
        compare(in, n, HTTPASM_ASN1_BER, 0);
    }
    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    return 0;
}
