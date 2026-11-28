/*
 * key.c - fuzzes httpasm_private_key_load (asn1/keys.asm): a key file (PEM or DER, PKCS#8,
 * PKCS#1 or SEC1, BER or DER) from wherever the server's operator got it.
 *
 * The input is a file. For every input, at every CPU tier (fuzz.h), it requires:
 *   - an answer of -2, -1 or a kind (1 to 7), the same at every tier, with the same key octets
 *     (the preparation is deterministic: one key, whatever the CPU);
 *   - a refused key all zeros;
 *   - a loaded key that holds together: its size for its kind; an EC key's public key the
 *     curve's d G recomputed from the scalar kept; an Edwards key's public key its prepared
 *     key's; an RSA key that signs a digest (PKCS#1 v1.5), the signature verifying under its own
 *     public part, and a PSS key's parameters within what the loader accepts;
 *   - DER and PEM the same: a DER input that loads, written as PEM under its format's label,
 *     loads to the same key octets;
 *   - no read past the input: it sits against an inaccessible page.
 */
#include "fuzz.h"

static httpasm_private_key keys[FUZZ_TIERS], again;

/* base64 into out (64 characters a line); returns its length. */
static size_t base64(const uint8_t *in, size_t n, char *out)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0, line = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
        char q[4] = { alphabet[v >> 18], alphabet[(v >> 12) & 63], i + 1 < n ? alphabet[(v >> 6) & 63] : '=', i + 2 < n ? alphabet[v & 63] : '=' };
        for (int k = 0; k < 4; k++) {
            out[o++] = q[k];
            if (++line == 64)
                out[o++] = '\n', line = 0;
        }
    }
    if (line)
        out[o++] = '\n';
    return o;
}

/* holds: the checks of a loaded key. */
static void holds(const httpasm_private_key *k, int kind)
{
    static const struct { uint32_t bits_min, bits_max, public_length; } shape[8] = {
        { 0, 0, 0 }, { 1024, 8192, 0 }, { 1024, 8192, 0 }, { 256, 256, 65 }, { 384, 384, 97 }, { 521, 521, 133 },
        { 256, 256, 32 }, { 448, 448, 57 },
    };
    FUZZ_CHECK(k->kind == (uint32_t)kind, "kind %u, answer %d", k->kind, kind);
    FUZZ_CHECK(k->bits >= shape[kind].bits_min && k->bits <= shape[kind].bits_max, "bits %u for kind %d", k->bits, kind);
    FUZZ_CHECK(k->public_length == shape[kind].public_length, "public length %u for kind %d", k->public_length, kind);
    const uint8_t *secret = (const uint8_t *)k->opaque;
    uint8_t point[133];
    if (kind == HTTPASM_KEY_P256)
        FUZZ_CHECK(httpasm_p256_public_key(point, secret) == 0 && memcmp(point, k->public_key, 65) == 0, "P-256: not d G");
    else if (kind == HTTPASM_KEY_P384)
        FUZZ_CHECK(httpasm_p384_public_key(point, secret) == 0 && memcmp(point, k->public_key, 97) == 0, "P-384: not d G");
    else if (kind == HTTPASM_KEY_P521)
        FUZZ_CHECK(httpasm_p521_public_key(point, secret) == 0 && memcmp(point, k->public_key, 133) == 0, "P-521: not d G");
    else if (kind == HTTPASM_KEY_ED25519)
        FUZZ_CHECK(memcmp(secret + 64, k->public_key, 32) == 0, "Ed25519: not the prepared key's public key");
    else if (kind == HTTPASM_KEY_ED448)
        FUZZ_CHECK(memcmp(secret + 113, k->public_key, 57) == 0, "Ed448: not the prepared key's public key");
    else {
        static uint8_t signature[1024];
        uint8_t digest[32] = { 1, 2, 3 };
        const httpasm_rsa_private_key *rsa = (const httpasm_rsa_private_key *)k->opaque;
        size_t length = (k->bits + 7) / 8;
        FUZZ_CHECK(httpasm_rsa_sign_pkcs1(rsa, HTTPASM_HASH_SHA256, digest, signature, length) == 0, "RSA: the key does not sign");
        FUZZ_CHECK(httpasm_rsa_verify_pkcs1((const httpasm_rsa_public_key *)rsa, HTTPASM_HASH_SHA256, digest, signature, length) == 0,
                   "RSA: its signature does not verify under its own public key");
        if (kind == HTTPASM_KEY_RSA_PSS)
            FUZZ_CHECK(k->pss_hash == 0 || (k->pss_hash >= HTTPASM_HASH_SHA256 && k->pss_hash <= HTTPASM_HASH_SHA512),
                       "PSS: hash %u", k->pss_hash);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
    if (n > FUZZ_MAX)
        return 0;
    int answers[FUZZ_TIERS];
    for (size_t t = 0; t < FUZZ_TIERS; t++) {
        httpasm_cpu_limit(fuzz_caps[t]);
        uint8_t *in = fuzz_place(data, n);
        answers[t] = httpasm_private_key_load(&keys[t], in, n);
        int a = answers[t];
        FUZZ_CHECK(a == -2 || a == -1 || (a >= 1 && a <= 7), "answer %d", a);
        if (a < 0) {
            const uint8_t *z = (const uint8_t *)&keys[t];
            for (size_t i = 0; i < sizeof keys[t]; i++)
                FUZZ_CHECK(z[i] == 0, "a refused key is not all zeros (octet %zu)", i);
        } else {
            holds(&keys[t], a);
        }
        FUZZ_CHECK(a == answers[0] && memcmp(&keys[t], &keys[0], sizeof keys[t]) == 0, "tier %zu differs from v1", t);
    }

    /* the same DER as PEM: under the label of the format it loaded as */
    if (answers[0] > 0 && n > 0 && data[0] == 0x30 && n < 16384) {
        static char text[16384 * 2];
        const char *labels[] = { "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY" };
        int loaded_as = 0;
        for (int l = 0; l < 3 && !loaded_as; l++) {
            size_t o = (size_t)sprintf(text, "-----BEGIN %s-----\n", labels[l]);
            o += base64(data, n, text + o);
            o += (size_t)sprintf(text + o, "-----END %s-----\n", labels[l]);
            int a = httpasm_private_key_load(&again, (const uint8_t *)fuzz_place((const uint8_t *)text, o), o);
            if (a > 0) {
                FUZZ_CHECK(a == answers[0] && memcmp(&again, &keys[0], sizeof again) == 0, "PEM loaded another key than DER");
                loaded_as = 1;
            }
        }
        FUZZ_CHECK(loaded_as, "a DER key that loads did not load as PEM under any label");
    }
    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    return 0;
}
