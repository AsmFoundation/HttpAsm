/*
 * pem.c - fuzzes httpasm_pem_read (asn1/pem.asm), the PEM decoder (RFC 7468): the first block
 * of a text that may hold explanatory lines, several blocks and anything a file can.
 *
 * The input is a text. For every input, at every CPU tier (fuzz.h), it requires:
 *   - agreement with a model written apart from the assembly (model() below, plain C from the
 *     rules httpasm.h states, decoding base64 with a lookup table where the assembly computes
 *     each character's value with masks): the same answer (0, 1, -1, -2), label, octets,
 *     needed room and end;
 *   - the buffer untouched unless the answer is 0 (a canary fills it first), and nothing written
 *     past der_length: the decoder writes only once the block was checked;
 *   - with the room the answer -2 named, the same text reads (0) to the same octets;
 *   - every block of the text in turn, from each block's end, as a file of blocks is read;
 *   - no read past the text: it sits against an inaccessible page.
 */
#include "fuzz.h"

enum { ROOM = FUZZ_MAX };

typedef struct mblock {
    size_t label, label_length, der_length, end;
} mblock;

static int is_space(uint8_t c) { return c == ' ' || (c >= 9 && c <= 13); }
static int is_labelchar(uint8_t c) { return c >= 0x21 && c <= 0x7E && c != '-'; }
static int at(const uint8_t *t, size_t n, size_t i, const char *s)
{
    size_t k = strlen(s);
    return i <= n && k <= n - i && memcmp(t + i, s, k) == 0;
}

/* model: httpasm_pem_read's answer for t[0..n), with der of room capacity. */
static int model(const uint8_t *t, size_t n, uint8_t *der, size_t capacity, mblock *b)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    for (;; i++) {
        if (i + 11 > n)
            return 1;
        if ((i == 0 || t[i - 1] == '\n' || t[i - 1] == '\r') && at(t, n, i, "-----BEGIN "))
            break;
    }
    size_t ls = i + 11, j = ls;
    for (;;) {
        if (j >= n)
            return -1;
        if (at(t, n, j, "-----"))
            break;
        uint8_t c = t[j];
        if (c == '-' || c == ' ') {
            if (j == ls || !is_labelchar(t[j - 1]) || j + 1 >= n || !is_labelchar(t[j + 1]))
                return -1;
            j++;
            continue;
        }
        if (!is_labelchar(c))
            return -1;
        j++;
    }
    size_t label_length = j - ls, body = j + 5;
    if (body >= n)
        return -1;
    if (t[body] == '-' && !at(t, n, body, "-----END "))
        return -1;
    /* the base64 text: characters, whitespace, then up to two pads with whitespace */
    uint8_t values[ROOM];
    size_t count = 0, p = body;
    int pads = 0;
    for (;; p++) {
        if (p >= n)
            return -1;
        uint8_t c = t[p];
        const char *v = c ? strchr(alphabet, c) : NULL;
        if (v != NULL) {
            if (pads)
                return -1;
            values[count++] = (uint8_t)(v - alphabet);
        } else if (is_space(c)) {
        } else if (c == '=') {
            if (++pads > 2)
                return -1;
        } else if (c == '-') {
            break;
        } else {
            return -1;
        }
    }
    if (!at(t, n, p, "-----END ") || p + 9 + label_length + 5 > n || memcmp(t + p + 9, t + ls, label_length) != 0 ||
        !at(t, n, p + 9 + label_length, "-----"))
        return -1;
    size_t end = p + 9 + label_length + 5;
    if (end < n && t[end] == '-' && !at(t, n, end, "-----BEGIN "))
        return -1;
    size_t rest = count % 4;
    if (rest == 1 || (pads && rest + (size_t)pads != 4))
        return -1;
    if ((rest == 2 && (values[count - 1] & 0x0F)) || (rest == 3 && (values[count - 1] & 0x03)))
        return -1;
    size_t length = count / 4 * 3 + (rest ? rest - 1 : 0);
    b->label = ls, b->label_length = label_length, b->der_length = length, b->end = end;
    if (length > capacity)
        return -2;
    size_t o = 0;
    for (size_t q = 0; q + 4 <= count; q += 4) {
        uint32_t v = (uint32_t)values[q] << 18 | (uint32_t)values[q + 1] << 12 | (uint32_t)values[q + 2] << 6 | values[q + 3];
        der[o++] = (uint8_t)(v >> 16), der[o++] = (uint8_t)(v >> 8), der[o++] = (uint8_t)v;
    }
    if (rest == 2)
        der[o++] = (uint8_t)(values[count - 2] << 2 | values[count - 1] >> 4);
    if (rest == 3) {
        uint32_t v = (uint32_t)values[count - 3] << 12 | (uint32_t)values[count - 2] << 6 | values[count - 1];
        der[o++] = (uint8_t)(v >> 10), der[o++] = (uint8_t)(v >> 2);
    }
    return 0;
}

static uint8_t got[ROOM + 16], want[ROOM + 16];

/* one: the first block of t[0..n) by both, with room capacity, and the checks around it;
 * returns the library's answer and *end. */
static int one(const uint8_t *t, size_t n, size_t capacity, size_t *end)
{
    httpasm_pem a;
    mblock m = { 0 };
    /* the canary over the room and 16 octets past it (not the whole buffer: each input makes
     * several calls at four tiers, and 64 KiB a call was most of the fuzzer's time) */
    size_t reach = capacity < n ? capacity : n;     /* (the octets never outnumber the text) */
    size_t canary = reach + 16 < sizeof got ? reach + 16 : sizeof got;
    memset(got, 0xA5, canary);
    int ra = httpasm_pem_read(&a, t, n, got, capacity);
    int rm = model(t, n, want, capacity, &m);
    FUZZ_CHECK(ra == rm, "answer: library %d, model %d (%zu octets, room %zu)", ra, rm, n, capacity);
    if (ra == 0) {
        FUZZ_CHECK(a.label == t + m.label && a.label_length == m.label_length && a.der_length == m.der_length && a.end == m.end,
                   "block: label +%td/+%zu (%zu/%zu) octets %zu/%zu end %zu/%zu", a.label - t, m.label, a.label_length,
                   m.label_length, a.der_length, m.der_length, a.end, m.end);
        FUZZ_CHECK(memcmp(got, want, a.der_length) == 0, "the octets differ");
        for (size_t i = a.der_length; i < a.der_length + 16 && i < sizeof got; i++)
            FUZZ_CHECK(got[i] == 0xA5, "an octet written past der_length (%zu)", i);
        *end = a.end;
    } else {
        for (size_t i = 0; i < canary; i++)
            FUZZ_CHECK(got[i] == 0xA5, "the buffer was written on answer %d", ra);
        if (ra == -2) {
            FUZZ_CHECK(a.der_length == m.der_length && a.der_length > capacity, "the room needed: %zu, model %zu", a.der_length, m.der_length);
            size_t e;
            FUZZ_CHECK(one(t, n, a.der_length, &e) == 0, "with the room -2 named, the block did not read");
        }
    }
    return ra;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
    if (n > FUZZ_MAX)
        return 0;
    uint64_t h = fuzz_hash(data, n);
    for (size_t tier = 0; tier < FUZZ_TIERS; tier++) {
        httpasm_cpu_limit(fuzz_caps[tier]);
        uint8_t *t = fuzz_place(data, n);
        /* every block in turn, with plenty of room, and the first with a room the hash picks */
        size_t start = 0, end = 0;
        for (int blocks = 0; blocks < 64; blocks++) {
            if (one(t + start, n - start, ROOM, &end) != 0)
                break;
            start += end;
        }
        (void)one(t, n, (size_t)(h % (n / 2 + 2)), &end);
    }
    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    return 0;
}
