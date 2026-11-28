/*
 * tls_record.c - fuzzes TLS 1.3's record layer (tls/record.asm): httpasm_tls_record_length over
 * what a connection reads, httpasm_tls13_open over hostile records, and httpasm_tls13_seal and
 * open together over the contents, types, paddings and sequence numbers an input picks.
 *
 * The input: octet 0 picks the suite (of the three), octets 1-8 the sequence number, octet 9 the
 * content type, octets 10-11 the padding, octet 12 the octet a forgery changes, the rest both
 * the content to seal and a record as read from the wire, opened under the suite's key (the
 * first 32 octets of the traffic secret are RFC 8448's server handshake traffic secret, so the
 * trace's encrypted handshake record, a seed, opens under TLS_AES_128_GCM_SHA256 at sequence 0
 * and mutations start from a record that verifies). For every input, at every CPU tier
 * (fuzz.h), it requires:
 *   - the framing a model's: 0 until the header and its fragment are there, the record's length
 *     then, record_overflow past 2^14 + 256 octets for application_data and 2^14 for the others;
 *   - an opened wire record either refused with one of the opener's alerts or (never seen: a tag
 *     to forge) a content of at most 2^14 octets with a non-zero type, the sequence number
 *     advanced only then;
 *   - a sealed record of exactly 5 + content + 1 + padding + 16 octets, or a refusal the limits
 *     explain (a content over 2^14, an inner plaintext over 2^14 + 1, AES-GCM's last record),
 *     opened back by a reader at the same sequence number to the same content and type;
 *   - the same record with one octet changed refused: unexpected_message for the outer type,
 *     decode_error for the length, bad_record_mac anywhere else (the version included);
 *   - the same answers and octets at every tier;
 *   - no read past the input: it sits against an inaccessible page.
 */
#include "fuzz.h"

static const int suites[3] = { HTTPASM_TLS_AES_128_GCM_SHA256, HTTPASM_TLS_AES_256_GCM_SHA384,
                               HTTPASM_TLS_CHACHA20_POLY1305_SHA256 };
static const uint8_t traffic_secret[48] = { 0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13,
                                            0xcb, 0x2d, 0x37, 0xb4, 0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d,
                                            0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38, 0x01, 0x02, 0x03, 0x04,
                                            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

static httpasm_tls13_record_key writer, reader;
static uint8_t sealed[FUZZ_TIERS][HTTPASM_TLS_RECORD_HEADER + HTTPASM_TLS_INNER_MAX + HTTPASM_TLS_TAG + 64];
static uint8_t wire[FUZZ_MAX + 16];

/* model_length: httpasm_tls_record_length's answer by the rules. */
static int64_t model_length(const uint8_t *in, size_t n)
{
    if (n < 5)
        return 0;
    size_t length = (size_t)in[3] << 8 | in[4];
    size_t limit = in[0] == HTTPASM_TLS_CONTENT_APPLICATION_DATA ? HTTPASM_TLS_CIPHERTEXT_MAX : HTTPASM_TLS_PLAINTEXT_MAX;
    if (length > limit)
        return -HTTPASM_TLS_ALERT_RECORD_OVERFLOW;
    return n >= 5 + length ? (int64_t)(5 + length) : 0;
}

/* refused: whether an answer is one the opener may give for a refusal. */
static int refused(int64_t answer)
{
    return answer == -HTTPASM_TLS_ALERT_UNEXPECTED_MESSAGE || answer == -HTTPASM_TLS_ALERT_BAD_RECORD_MAC
        || answer == -HTTPASM_TLS_ALERT_RECORD_OVERFLOW || answer == -HTTPASM_TLS_ALERT_DECODE_ERROR
        || answer == -HTTPASM_TLS_ALERT_INTERNAL_ERROR;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
    if (n > FUZZ_MAX || n < 13)
        return 0;
    int suite = suites[data[0] % 3];
    uint64_t sequence = 0;
    for (int i = 1; i <= 8; i++)
        sequence = sequence << 8 | data[i];
    if (data[0] & 0x80)
        sequence &= 0xFFFF;                     /* (half the inputs near 0, where the keys start) */
    int type = data[9];
    size_t padding = ((size_t)data[10] << 8 | data[11]) % 20000;
    size_t forge = data[12];
    const uint8_t *content = data + 13;
    size_t length = n - 13;
    int64_t first_sealed = 0, first_wire = 0;
    for (size_t t = 0; t < FUZZ_TIERS; t++) {
        httpasm_cpu_limit(fuzz_caps[t]);
        uint8_t *in = fuzz_place(data, n);

        /* the framing, of the record part */
        int64_t framed = httpasm_tls_record_length(in + 13, length);
        FUZZ_CHECK(framed == model_length(content, length), "framed %lld, model %lld", (long long)framed,
                   (long long)model_length(content, length));

        /* the record part as a wire record, opened (the opener writes: a copy) */
        FUZZ_CHECK(httpasm_tls13_record_key_init(&reader, suite, traffic_secret) == 0, "key");
        reader.sequence = sequence;
        memcpy(wire, content, length);
        uint8_t got = 0;
        int64_t opened = httpasm_tls13_open(&reader, wire, length, &got);
        FUZZ_CHECK(refused(opened) || (opened >= 0 && opened <= HTTPASM_TLS_PLAINTEXT_MAX && got != 0),
                   "a wire record answered %lld", (long long)opened);
        FUZZ_CHECK(reader.sequence == sequence + (opened >= 0), "the sequence number moved on a refusal");
        if (t == 0)
            first_wire = opened;
        FUZZ_CHECK(opened == first_wire, "tier %zu opened the wire record otherwise", t);

        /* seal what the input picks, then open it back */
        FUZZ_CHECK(httpasm_tls13_record_key_init(&writer, suite, traffic_secret) == 0, "key");
        writer.sequence = sequence;
        int64_t made = httpasm_tls13_seal(&writer, type, content, length, padding, sealed[t], sizeof sealed[t]);
        size_t inner = length + 1 + padding;
        int over = type == 0 || length > HTTPASM_TLS_PLAINTEXT_MAX || inner > HTTPASM_TLS_INNER_MAX;
        int exhausted = !over && (suite != HTTPASM_TLS_CHACHA20_POLY1305_SHA256 ? sequence >= HTTPASM_TLS_GCM_RECORDS : sequence == UINT64_MAX);
        if (over) {
            FUZZ_CHECK(made == -1, "sealed past a limit: %lld", (long long)made);
        } else if (exhausted) {
            FUZZ_CHECK(made == -2, "sealed past the key's last record: %lld", (long long)made);
        } else {
            FUZZ_CHECK(made == (int64_t)(5 + inner + 16), "sealed %lld octets, not %zu", (long long)made, 5 + inner + 16);
            FUZZ_CHECK(writer.sequence == sequence + 1, "the writer's sequence number");
            if (t == 0)
                first_sealed = made;
            FUZZ_CHECK(made == first_sealed && memcmp(sealed[t], sealed[0], (size_t)made) == 0, "tier %zu sealed otherwise", t);
            FUZZ_CHECK(httpasm_tls13_record_key_init(&reader, suite, traffic_secret) == 0, "key");
            reader.sequence = sequence;
            memcpy(wire, sealed[t], (size_t)made);
            int64_t back = httpasm_tls13_open(&reader, wire, (size_t)made, &got);
            FUZZ_CHECK(back == (int64_t)length && got == type && memcmp(wire + 5, content, length) == 0,
                       "opened back %lld (type %d), not %zu (type %d)", (long long)back, got, length, type);

            /* one octet changed: refused, with the alert its place names */
            size_t at = forge % (size_t)made;
            memcpy(wire, sealed[t], (size_t)made);
            wire[at] ^= (uint8_t)(1 + (data[n - 1] % 255));
            FUZZ_CHECK(httpasm_tls13_record_key_init(&reader, suite, traffic_secret) == 0, "key");
            reader.sequence = sequence;
            int64_t forged = httpasm_tls13_open(&reader, wire, (size_t)made, &got);
            /* (a changed length octet never equals the record's: decode_error comes first) */
            int64_t expected = at == 0 ? -HTTPASM_TLS_ALERT_UNEXPECTED_MESSAGE
                : at == 3 || at == 4 ? -HTTPASM_TLS_ALERT_DECODE_ERROR : -HTTPASM_TLS_ALERT_BAD_RECORD_MAC;
            FUZZ_CHECK(forged == expected, "octet %zu changed: %lld, not %lld", at, (long long)forged, (long long)expected);
        }
    }
    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    return 0;
}
