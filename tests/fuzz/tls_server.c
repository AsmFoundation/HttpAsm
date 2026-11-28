/*
 * tls_server.c - fuzzes TLS 1.3's server engine (tls/engine.asm, tls/server.asm, tls/kex.asm,
 * tls/sign.asm): a server connection fed the octets a hostile client sends before it has
 * authenticated anything - its ClientHellos and whatever follows, in records cut where the input
 * says - the surface every server exposes to the whole network.
 *
 * The input is the client's octet stream; the fuzz hash (fuzz.h) picks where TCP cuts it, so the
 * engine sees records whole, cut, and several at once, and its lowest bit picks the server's
 * group policy (by share, or HTTPASM_TLS_SERVER_GROUP_ORDER: every retry path). The server: an
 * Ed25519 key and certificate (fixed below: a fuzz key, nothing else signs with it), the
 * library's 13 groups and 3 suites, a random source that is a counter (the same octets at every
 * tier, so outputs compare). For every input, at every CPU tier, it requires:
 *   - each call's answer one receive may give: the octets of one record (no more than given), 0
 *     only when no record is whole and with no event, -1 with EVENT_FAILED; the events only
 *     those a client that cannot key may cause (NONE, CLOSED; DATA and CONNECTED need the
 *     client's Finished, which no input can make without the handshake keys);
 *   - after a failure, every call answering -1 again with the same alert, and nothing more out;
 *   - the output a sequence of whole records of the types a server sends (handshake, alert,
 *     change_cipher_spec, application_data), each within TLS 1.3's lengths, a plaintext alert
 *     two octets with level fatal, a change_cipher_spec the one octet 1;
 *   - the same answers, events and output octets at every tier;
 *   - no read past the input (it sits against an inaccessible page, copied afresh at each tier:
 *     the engine opens records in place) and no write past the connection's memory (its spans,
 *     reassembly then output, end against an inaccessible page and start after another: the
 *     assembly is not AddressSanitizer's, so the pages are what catch it).
 */
#include "fuzz.h"

/* The fuzz key: PKCS#8 Ed25519 (openssl genpkey), and a certificate for it (openssl req -x509). */
static const uint8_t key_der[48] = {
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    0x05, 0x55, 0x06, 0x5a, 0xde, 0x7a, 0x65, 0xe3, 0x96, 0x71, 0x53, 0x36, 0x26, 0x7d, 0x7b, 0x22,
    0xc8, 0x82, 0xde, 0x0a, 0xa2, 0xd4, 0x8a, 0xc0, 0x61, 0x68, 0xee, 0x4e, 0x6e, 0x82, 0xa8, 0x41,
};
static const uint8_t cert_der[312] = {
    0x30, 0x82, 0x01, 0x34, 0x30, 0x81, 0xe7, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4b, 0xd7,
    0x09, 0x49, 0xd0, 0xc0, 0xda, 0x8f, 0x6a, 0xb7, 0x51, 0x2a, 0x28, 0x13, 0x87, 0x8a, 0x3e, 0x94,
    0x3f, 0xe2, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x66, 0x75, 0x7a, 0x7a, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36,
    0x31, 0x31, 0x32, 0x38, 0x30, 0x34, 0x32, 0x35, 0x34, 0x31, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32,
    0x36, 0x31, 0x31, 0x30, 0x34, 0x30, 0x34, 0x32, 0x35, 0x34, 0x31, 0x5a, 0x30, 0x0f, 0x31, 0x0d,
    0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x66, 0x75, 0x7a, 0x7a, 0x30, 0x2a, 0x30,
    0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x43, 0xdf, 0x9b, 0xa0, 0x7b, 0xcb, 0xf6,
    0xd3, 0x6f, 0x1f, 0x2d, 0x95, 0xe6, 0x84, 0xa4, 0xf1, 0x5e, 0x5a, 0x34, 0xa3, 0x60, 0xf8, 0x54,
    0x64, 0x3a, 0xd4, 0xc9, 0x53, 0x34, 0xcd, 0x2a, 0x19, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06,
    0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xb9, 0x3c, 0xa5, 0x04, 0x44, 0xe6, 0x1f, 0x04,
    0x43, 0x15, 0xba, 0x69, 0x64, 0xd7, 0xf6, 0xeb, 0xe9, 0xba, 0x58, 0x90, 0x30, 0x1f, 0x06, 0x03,
    0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xb9, 0x3c, 0xa5, 0x04, 0x44, 0xe6, 0x1f,
    0x04, 0x43, 0x15, 0xba, 0x69, 0x64, 0xd7, 0xf6, 0xeb, 0xe9, 0xba, 0x58, 0x90, 0x30, 0x0f, 0x06,
    0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0x1f, 0xdd, 0x64, 0x30, 0x0f, 0x64, 0x6b, 0xb9,
    0xee, 0x3a, 0x8b, 0xd2, 0x47, 0x5e, 0xb4, 0x84, 0xb9, 0x80, 0xbf, 0x58, 0xe4, 0x8e, 0xaa, 0x8d,
    0x90, 0x65, 0xea, 0x58, 0xb1, 0x19, 0xce, 0x52, 0x4a, 0x5b, 0x4f, 0x95, 0x26, 0x93, 0x22, 0x4e,
    0x04, 0x59, 0x01, 0x8d, 0x30, 0x03, 0x03, 0xbd, 0x58, 0x2d, 0x9e, 0x5e, 0x72, 0x0a, 0x13, 0xf5,
    0xc7, 0x1e, 0xed, 0xc8, 0x82, 0x0c, 0x5b, 0x0b,
};

static httpasm_private_key key;
static httpasm_tls13_server_config configs[2];     /* [0] by share, [1] the server's group order */
static uint8_t certificates[2][400];
static uint8_t *memories[2];                        /* each config's memory, between guard pages */
static httpasm_tls13_connection connection;
static uint64_t counter;

/* draw: the random source, a counter's octets: the same at every tier for the same input.
 *   context  unused; out, length  where the octets go. Returns 0 (it never fails). */
static int draw(void *context, uint8_t *out, size_t length)
{
    (void)context;
    for (size_t i = 0; i < length; i++)
        out[i] = (uint8_t)((++counter * 0x9E3779B97F4A7C15ull) >> 56);
    return 0;
}

/* guarded: `size` octets (a multiple of 16) ending exactly against an inaccessible page, with
 * another before them, so a write past the output span's end faults at once and one far below
 * the reassembly span's start faults too.
 *   size  the octets. Returns their start; aborts when the pages cannot be mapped. */
static uint8_t *guarded(size_t size)
{
    size_t pages = (size + FUZZ_PAGE - 1) / FUZZ_PAGE;
    uint8_t *map = mmap(NULL, (pages + 2) * FUZZ_PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED || mprotect(map, FUZZ_PAGE, PROT_NONE) != 0
        || mprotect(map + (pages + 1) * FUZZ_PAGE, FUZZ_PAGE, PROT_NONE) != 0)
        abort();
    /* the end exact (the output span's, where a flight or a record would run over); below the
       start lie the page's slack octets, then the leading guard: only a write of more than the
       slack below is caught there (the reassembly span writes from its start up) */
    return map + (pages + 1) * FUZZ_PAGE - size;
}

/* setup: the key, the two configurations and their memories, once. Aborts on any refusal (the
 * fuzzer would test nothing). */
static void setup(void)
{
    if (httpasm_private_key_load(&key, key_der, sizeof key_der) != HTTPASM_KEY_ED25519)
        abort();
    const uint8_t *chain[1] = { cert_der };
    size_t lengths[1] = { sizeof cert_der };
    for (int i = 0; i < 2; i++) {
        configs[i].key = &key;
        configs[i].random = draw;
        configs[i].flags = i ? HTTPASM_TLS_SERVER_GROUP_ORDER : 0;
        if (httpasm_tls13_server_config_init(&configs[i], chain, lengths, 1, certificates[i], sizeof certificates[i]) != 0)
            abort();
        memories[i] = guarded(configs[i].memory);
    }
}

/* What one tier saw: each call's answer and event, and the output. */
enum { CALLS_MAX = 4096, OUTPUT_MAX = 1 << 20 };
static int64_t answers[FUZZ_TIERS][CALLS_MAX];
static uint32_t events[FUZZ_TIERS][CALLS_MAX];
static size_t calls[FUZZ_TIERS];
static uint8_t output[FUZZ_TIERS][OUTPUT_MAX];
static size_t output_n[FUZZ_TIERS];

/* take: the output queued, appended to the tier's and taken off the connection.
 *   t  the tier. */
static void take(size_t t)
{
    const uint8_t *out;
    size_t n = httpasm_tls13_output(&connection, &out);
    FUZZ_CHECK(output_n[t] + n <= OUTPUT_MAX, "output past %d octets", OUTPUT_MAX);
    memcpy(output[t] + output_n[t], out, n);
    output_n[t] += n;
    httpasm_tls13_output_done(&connection, n);
}

/* check_records: the output a sequence of whole records a server may send.
 *   o, n  the output. */
static void check_records(const uint8_t *o, size_t n)
{
    size_t at = 0;
    while (at < n) {
        FUZZ_CHECK(n - at >= 5, "a record header cut at %zu", at);
        unsigned type = o[at], length = (unsigned)o[at + 3] << 8 | o[at + 4];
        FUZZ_CHECK(type >= 20 && type <= 23, "a record of type %u", type);
        FUZZ_CHECK(o[at + 1] == 3 && o[at + 2] == 3, "legacy_record_version %02x%02x", o[at + 1], o[at + 2]);
        FUZZ_CHECK(length <= (type == 23 ? 16384u + 256 : 16384u) && length > 0, "a record of %u octets", length);
        FUZZ_CHECK(n - at - 5 >= length, "a record cut");
        if (type == 21)
            FUZZ_CHECK(length == 2 && o[at + 5] == 2, "a plaintext alert of %u octets, level %u", length, o[at + 5]);
        if (type == 20)
            FUZZ_CHECK(length == 1 && o[at + 5] == 1, "a change_cipher_spec");
        at += 5 + length;
    }
}

/* LLVMFuzzerTestOneInput: the client's octets, at every tier (the file's header).
 *   data, n  the input. Returns 0. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
    static int ready;
    if (n > FUZZ_MAX)
        return 0;
    if (!ready) {
        setup();
        ready = 1;
    }
    uint64_t hash = fuzz_hash(data, n);
    const httpasm_tls13_server_config *config = &configs[hash & 1];
    uint8_t *memory = memories[hash & 1];
    size_t cuts[16];
    size_t k = fuzz_cuts(hash >> 1, n, cuts, 16);
    for (size_t t = 0; t < FUZZ_TIERS; t++) {
        httpasm_cpu_limit(fuzz_caps[t]);
        counter = 0;
        calls[t] = 0;
        output_n[t] = 0;
        FUZZ_CHECK(httpasm_tls13_server_init(&connection, config, memory, config->memory) == 0, "init");
        uint8_t *in = fuzz_place(data, n);
        size_t at = 0;
        int failed = 0;
        uint32_t alert = 0;
        for (size_t c = 0; c <= k && !failed; c++) {
            size_t have = c < k ? cuts[c] : n;              /* what TCP delivered so far */
            while (at < have && !failed) {
                httpasm_tls13_event e;
                int64_t r = httpasm_tls13_receive(&connection, in + at, have - at, &e);
                FUZZ_CHECK(calls[t] < CALLS_MAX, "calls");
                answers[t][calls[t]] = r;
                events[t][calls[t]] = e.kind | e.alert << 8 | e.flags << 16;
                calls[t]++;
                take(t);
                if (r == 0) {
                    FUZZ_CHECK(e.kind == HTTPASM_TLS_EVENT_NONE, "0 with event %u", e.kind);
                    break;                                  /* a record not whole: more octets */
                }
                if (r < 0) {
                    FUZZ_CHECK(r == -1 && e.kind == HTTPASM_TLS_EVENT_FAILED, "answer %lld, event %u", (long long)r, e.kind);
                    failed = 1;
                    alert = e.alert;
                    break;
                }
                FUZZ_CHECK((size_t)r <= have - at, "consumed %lld of %zu", (long long)r, have - at);
                FUZZ_CHECK(e.kind == HTTPASM_TLS_EVENT_NONE || e.kind == HTTPASM_TLS_EVENT_CLOSED, "event %u", e.kind);
                at += (size_t)r;
            }
        }
        if (failed) {
            /* a failed connection answers the same again, and says nothing more */
            httpasm_tls13_event e;
            int64_t again = httpasm_tls13_receive(&connection, in, n, &e);
            FUZZ_CHECK(again == -1 && e.kind == HTTPASM_TLS_EVENT_FAILED && e.alert == alert,
                       "after the failure: %lld, alert %u", (long long)again, e.alert);
            const uint8_t *out;
            FUZZ_CHECK(httpasm_tls13_output(&connection, &out) == 0, "output after the failure");
        }
        check_records(output[t], output_n[t]);
        httpasm_tls13_wipe(&connection);
        if (t > 0) {
            FUZZ_CHECK(calls[t] == calls[0] && memcmp(answers[t], answers[0], calls[0] * sizeof answers[0][0]) == 0
                       && memcmp(events[t], events[0], calls[0] * sizeof events[0][0]) == 0, "tier %zu answered otherwise", t);
            FUZZ_CHECK(output_n[t] == output_n[0] && memcmp(output[t], output[0], output_n[0]) == 0, "tier %zu sent other octets", t);
        }
    }
    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    return 0;
}
