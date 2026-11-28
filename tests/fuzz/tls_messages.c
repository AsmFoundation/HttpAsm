/*
 * tls_messages.c - fuzzes TLS 1.3's handshake message readers (tls/messages.asm,
 * tls/extensions.asm): every reader over hostile bodies, a peer's messages being what an
 * attacker writes.
 *
 * The input: octet 0 picks the reader (a ClientHello, a ServerHello, an EncryptedExtensions
 * block, a CertificateRequest, a Certificate, a CertificateVerify, a NewSessionTicket, a
 * KeyUpdate, or the extension walk alone under the message bit octet 1 picks), the rest is the
 * body. For every input, at every CPU tier (fuzz.h), it requires:
 *   - an answer the reader may give: 0 (a KeyUpdate's 0 or 1, a Certificate's count of entries)
 *     or minus decode_error, illegal_parameter, or missing_extension (a CertificateRequest's);
 *   - for what is read: every pointer and length inside the body, in its place (a hello's
 *     random after legacy_version, its extension block running to the body's end), and the
 *     extension block's every present extension the one a model's walk finds (written apart:
 *     the type of each extension in the block mapped to its index by a table of its own, the
 *     count, the last type, the data and length), the walk's own answer the model's (a type
 *     twice, a type in a message 4.3's table does not put it in, pre_shared_key not last);
 *   - a Certificate's entries walked one by one to the list's end, as many as it counted;
 *   - the same answers and structures at every tier;
 *   - no read past the body: it sits against an inaccessible page.
 */
#include "fuzz.h"

/* The model's table: each known type and the messages it may be in (RFC 9846 4.3, the IANA
 * registry's TLS 1.3 column, TLS 1.2's extensions in a ClientHello only), by index. */
static const struct { uint16_t type; uint8_t allowed; } known[HTTPASM_TLS_EXTENSIONS] = {
    { 0, 1 | 4 | 16 }, { 1, 1 | 4 }, { 5, 1 | 16 | 8 }, { 10, 1 | 4 }, { 11, 1 }, { 13, 1 | 16 }, { 14, 1 | 4 },
    { 15, 1 | 4 }, { 16, 1 | 4 }, { 18, 1 | 16 | 8 }, { 19, 1 | 4 }, { 20, 1 | 4 }, { 21, 1 }, { 22, 1 }, { 23, 1 },
    { 27, 1 | 16 }, { 28, 1 | 4 }, { 34, 1 | 16 | 8 }, { 35, 1 }, { 39, 1 | 4 }, { 41, 1 | 2 }, { 42, 1 | 4 | 32 },
    { 43, 1 | 2 | 64 }, { 44, 1 | 64 }, { 45, 1 }, { 47, 1 | 16 }, { 48, 16 }, { 49, 1 }, { 50, 1 | 16 },
    { 51, 1 | 2 | 64 }, { 52, 1 | 16 | 8 }, { 55, 1 | 4 }, { 56, 1 | 4 }, { 57, 1 | 4 }, { 58, 1 | 4 },
    { 0xFD00, 1 }, { 0xFE0D, 1 | 64 | 4 }, { 0xFF01, 1 },
};

static uint8_t seen[65536 / 8];

/* model_walk: the extension walk's answer over block[0..n) in message `bit`, and into *e what it
 * finds (offsets as pointers into the block). */
static int model_walk(const uint8_t *block, size_t n, int bit, httpasm_tls_extensions *e)
{
    memset(e, 0, sizeof *e);
    memset(seen, 0, sizeof seen);
    size_t at = 0;
    while (at < n) {
        if (n - at < 4)
            return -HTTPASM_TLS_ALERT_DECODE_ERROR;
        unsigned type = (unsigned)block[at] << 8 | block[at + 1], len = (unsigned)block[at + 2] << 8 | block[at + 3];
        if (len > n - at - 4)
            return -HTTPASM_TLS_ALERT_DECODE_ERROR;
        if (seen[type >> 3] & (1u << (type & 7)))
            return -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER;
        seen[type >> 3] |= (uint8_t)(1u << (type & 7));
        e->count++;
        e->last = type;
        for (int i = 0; i < HTTPASM_TLS_EXTENSIONS; i++) {
            if (known[i].type != type)
                continue;
            if (!(known[i].allowed & bit))
                return -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER;
            e->present |= 1ull << i;
            e->data[i] = block + at + 4;
            e->length[i] = (uint16_t)len;
        }
        at += 4 + len;
    }
    if (bit == HTTPASM_TLS_IN_CH && (e->present >> HTTPASM_TLS_EXT_PRE_SHARED_KEY & 1) && e->last != 41)
        return -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER;
    return 0;
}

/* same_extensions: the reader's block and the model's agree on everything found. */
static void same_extensions(const httpasm_tls_extensions *ours, const httpasm_tls_extensions *model)
{
    FUZZ_CHECK(ours->present == model->present && ours->count == model->count && ours->last == model->last,
               "present %llx / %llx, count %u / %u, last %u / %u", (unsigned long long)ours->present,
               (unsigned long long)model->present, ours->count, model->count, ours->last, model->last);
    for (int i = 0; i < HTTPASM_TLS_EXTENSIONS; i++)
        if (model->present >> i & 1)
            FUZZ_CHECK(ours->data[i] == model->data[i] && ours->length[i] == model->length[i], "extension %d placed otherwise", i);
}

/* allowed_answer: whether an answer is one the readers give. */
static int allowed_answer(int64_t a)
{
    return a >= 0 || a == -HTTPASM_TLS_ALERT_DECODE_ERROR || a == -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER
        || a == -HTTPASM_TLS_ALERT_MISSING_EXTENSION;
}

static httpasm_tls13_hello hellos[FUZZ_TIERS];
static httpasm_tls_extensions blocks[FUZZ_TIERS], model, entry;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
    if (n > FUZZ_MAX || n < 2)
        return 0;
    int reader = data[0] % 9;
    int bit = 1 << (data[1] % 7);
    const uint8_t *body = data + 1;
    size_t length = n - 1;
    int64_t first = 0;
    for (size_t t = 0; t < FUZZ_TIERS; t++) {
        httpasm_cpu_limit(fuzz_caps[t]);
        uint8_t *in = fuzz_place(body, length);
        int64_t answer = 0;
        switch (reader) {
        case 0:
        case 1: {
            httpasm_tls13_hello *h = &hellos[t];
            answer = httpasm_tls13_hello_read(h, reader + 1, in, length);
            if (answer != 0)
                break;
            FUZZ_CHECK(h->random == in + 2 && h->session_id == in + 35 && h->session_id_length <= 32, "the fixed fields");
            if (h->extensions_block != NULL) {
                FUZZ_CHECK(fuzz_within(h->extensions_block, h->extensions_length, in, length)
                           && h->extensions_block + h->extensions_length == in + length, "the block not at the end");
                int bit_of = reader == 0 ? HTTPASM_TLS_IN_CH : h->retry ? HTTPASM_TLS_IN_HRR : HTTPASM_TLS_IN_SH;
                FUZZ_CHECK(model_walk(h->extensions_block, h->extensions_length, bit_of, &model) == 0, "the model refused the block");
                same_extensions(&h->extensions, &model);
            } else {
                FUZZ_CHECK(reader == 0, "a ServerHello without a block");
            }
            if (reader == 0)
                FUZZ_CHECK(fuzz_within(h->cipher_suites, h->cipher_suites_length, in, length)
                           && fuzz_within(h->compression, h->compression_length, in, length), "the lists");
            break;
        }
        case 2:
            answer = httpasm_tls13_extensions_message_read(&blocks[t], HTTPASM_TLS_IN_EE, in, length);
            if (answer == 0) {
                /* accepted: the uint16 length was the rest (else decode_error), so the block is
                 * in[2..length) and the model must walk it to the same extensions */
                FUZZ_CHECK(((size_t)in[0] << 8 | in[1]) == length - 2, "EE: the block's length is not the rest");
                FUZZ_CHECK(model_walk(in + 2, length - 2, HTTPASM_TLS_IN_EE, &model) == 0, "EE: the model refused");
                same_extensions(&blocks[t], &model);
            }
            break;
        case 3: {
            const uint8_t *context;
            size_t context_length;
            answer = httpasm_tls13_certificate_request_read(&blocks[t], &context, &context_length, in, length);
            if (answer == 0)
                FUZZ_CHECK(context == in + 1 && context_length == in[0]
                           && (blocks[t].present >> HTTPASM_TLS_EXT_SIGNATURE_ALGORITHMS & 1), "CR");
            break;
        }
        case 4: {
            const uint8_t *context, *list;
            size_t context_length, list_length;
            answer = httpasm_tls13_certificate_read(in, length, &context, &context_length, &list, &list_length);
            if (answer < 0)
                break;
            FUZZ_CHECK(fuzz_within(list, list_length, in, length) && list + list_length == in + length, "the list");
            size_t offset = 0;
            for (int64_t e = 0; e < answer; e++) {
                const uint8_t *cert;
                size_t cert_length;
                int64_t next = httpasm_tls13_certificate_entry(list, list_length, offset, &cert, &cert_length, &entry);
                FUZZ_CHECK(next > (int64_t)offset && (size_t)next <= list_length && cert_length >= 1
                           && fuzz_within(cert, cert_length, list, list_length), "entry %lld", (long long)e);
                offset = (size_t)next;
            }
            FUZZ_CHECK(offset == list_length, "the entries end at %zu, the list at %zu", offset, list_length);
            break;
        }
        case 5: {
            uint32_t scheme;
            const uint8_t *signature;
            size_t signature_length;
            answer = httpasm_tls13_certificate_verify_read(in, length, &scheme, &signature, &signature_length);
            if (answer == 0)
                FUZZ_CHECK(signature == in + 4 && signature_length == length - 4 && scheme == ((unsigned)in[0] << 8 | in[1]), "CV");
            break;
        }
        case 6: {
            uint64_t lifetime;
            const uint8_t *nonce, *ticket;
            answer = httpasm_tls13_new_session_ticket_read(&blocks[t], in, length, &lifetime, &nonce, &ticket);
            if (answer == 0)
                FUZZ_CHECK(nonce == in + 8 && fuzz_within(ticket, 2, in, length), "NST");
            break;
        }
        case 7:
            answer = httpasm_tls13_key_update_read(in, length);
            FUZZ_CHECK(answer == (length != 1 ? -HTTPASM_TLS_ALERT_DECODE_ERROR : in[0] <= 1 ? in[0] : -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER),
                       "KeyUpdate %lld", (long long)answer);
            break;
        default: {
            /* the walk alone, under the message bit octet 1 picked, over the rest */
            const uint8_t *block = in + 1;
            size_t block_length = length - 1;
            answer = httpasm_tls_extensions_read(&blocks[t], bit, block, block_length);
            int expected = model_walk(block, block_length, bit, &model);
            FUZZ_CHECK(answer == expected, "the walk answered %lld, the model %d", (long long)answer, expected);
            if (answer == 0)
                same_extensions(&blocks[t], &model);
            break;
        }
        }
        FUZZ_CHECK(allowed_answer(answer), "reader %d answered %lld", reader, (long long)answer);
        if (t == 0)
            first = answer;
        FUZZ_CHECK(answer == first, "tier %zu answered %lld, not %lld", t, (long long)answer, (long long)first);
        /* What was read must be the same octet for octet at every tier: the input sits at one
         * address for all of them (fuzz_place), and the readers zero their structures before
         * filling them, so even the fields nothing set compare equal. */
        if (reader <= 1 && answer == 0)
            FUZZ_CHECK(memcmp(&hellos[t], &hellos[0], sizeof hellos[0]) == 0, "tier %zu read another hello", t);
        if ((reader == 2 || reader == 3 || reader == 6 || reader == 8) && answer == 0)
            FUZZ_CHECK(memcmp(&blocks[t], &blocks[0], sizeof blocks[0]) == 0, "tier %zu read another block", t);
    }
    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    return 0;
}
