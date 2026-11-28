/*
 * x509.c - fuzzes httpasm_certificate_read, httpasm_public_key_read and httpasm_private_key_matches
 * (asn1/x509.asm): the certificates a TLS peer sends, and the public key infos inside them.
 *
 * The input is a certificate's DER, or a SubjectPublicKeyInfo's (both are tried on every input).
 * For every input, at every CPU tier (fuzz.h), it requires:
 *   - the same answers at every tier, and the same key octets (the RSA preparation included);
 *   - a certificate read only when every part it gives lies inside the input, in its place (the
 *     TBS first inside the outer SEQUENCE, the outer signature algorithm right after it, the
 *     signature's octets the input's last; in the TBS the serial number, the issuer, the subject,
 *     the public key info and the extensions in that order), version 1 to 3 with extensions only
 *     at 3, a validity of seconds a model recomputes from the two times' characters (UTCTime's YY
 *     as 1950-2049, the proleptic Gregorian calendar by another algorithm than the reader's), and
 *     a public key info that reads the same as a standalone one;
 *   - a public key read only with its kind's shape (size, point length), an EC point uncompressed
 *     and the info's last octets, an RSA key the one httpasm_rsa_public_key_init prepares from
 *     the n and e a model walks to in the info's DER;
 *   - httpasm_private_key_matches pairing an Ed25519 private key (loaded from the input's first 32
 *     octets as a seed) with the key read exactly when that key is the Ed25519 key of the same
 *     public octets, whatever the kind read;
 *   - no read past the input: it sits against an inaccessible page.
 */
#include "fuzz.h"

static httpasm_certificate certs[FUZZ_TIERS];
static httpasm_public_key keys[FUZZ_TIERS], spkis[FUZZ_TIERS], again;
static httpasm_rsa_public_key model_rsa;
static httpasm_private_key seed_key;

/* model_days: days from 1970-01-01 to the civil date y-m-d of the proleptic Gregorian calendar
 * (Howard Hinnant's days_from_civil: eras of 400 years from March, not the reader's leap-day
 * counts, so an error in either shows as a difference). */
static int64_t model_days(int64_t y, int m, int d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* model_time: the seconds since 1970 of the DER Time element at p: a UTCTime YYMMDDhhmmssZ (13
 * characters) or a GeneralizedTime YYYYMMDDhhmmssZ (15), the only forms the reader accepts in a
 * certificate, so its two-octet header and digits are trusted here. */
static int64_t model_time(const uint8_t *p)
{
    const uint8_t *s = p + 2;
#define D2(o) ((s[o] - '0') * 10 + (s[(o) + 1] - '0'))
    int64_t year;
    int at;
    if (p[0] == 0x18)
        year = D2(0) * 100 + D2(2), at = 4;
    else
        year = D2(0) < 50 ? 2000 + D2(0) : 1900 + D2(0), at = 2;
    int64_t days = model_days(year, D2(at), D2(at + 2));
    return days * 86400 + D2(at + 4) * 3600 + D2(at + 6) * 60 + D2(at + 8);
#undef D2
}

/* present: [p, p + n) inside the input and given (a NULL pointer is an absent part, which
 * fuzz_within admits with n == 0). */
static int present(const uint8_t *p, size_t n, const uint8_t *in, size_t len)
{
    return p != NULL && fuzz_within(p, n, in, len);
}

/* der_next: the DER element at *p (before end): its tag octet in *tag, its contents in
 * *contents and *length; *p moves past it. Returns 0, or -1 for what DER does not allow here
 * (a high tag number, an indefinite or over-long length, an element past end): the reader read
 * the info as DER, so a -1 on an accepted info is itself a finding. */
static int der_next(const uint8_t **p, const uint8_t *end, int *tag, const uint8_t **contents, size_t *length)
{
    const uint8_t *q = *p;
    if (end - q < 2 || (q[0] & 0x1F) == 0x1F)
        return -1;
    *tag = q[0];
    size_t n = q[1];
    q += 2;
    if (n & 0x80) {
        size_t k = n & 0x7F;
        if (k == 0 || k > 4 || (size_t)(end - q) < k)
            return -1;
        n = 0;
        while (k--)
            n = n << 8 | *q++;
    }
    if ((size_t)(end - q) < n)
        return -1;
    *contents = q;
    *length = n;
    *p = q + n;
    return 0;
}

/* model_rsa_key: walks an accepted RSA info's DER, SEQUENCE { AlgorithmIdentifier, BIT STRING
 * { 00, RSAPublicKey SEQUENCE { n, e } } }, and prepares the key from its n and e as the reader
 * should have. Returns 0 with model_rsa set, or -1 (the walk found another shape). */
static int model_rsa_key(const uint8_t *spki, size_t length)
{
    const uint8_t *p = spki, *c, *n, *e;
    size_t cl, nl, el;
    int tag;
    if (der_next(&p, spki + length, &tag, &c, &cl) != 0 || tag != 0x30)
        return -1;
    const uint8_t *end = c + cl;
    p = c;
    if (der_next(&p, end, &tag, &c, &cl) != 0 || tag != 0x30)   /* the algorithm */
        return -1;
    if (der_next(&p, end, &tag, &c, &cl) != 0 || tag != 0x03 || cl < 1 || c[0] != 0)
        return -1;
    p = c + 1;
    end = c + cl;
    if (der_next(&p, end, &tag, &c, &cl) != 0 || tag != 0x30)
        return -1;
    p = c;
    end = c + cl;
    if (der_next(&p, end, &tag, &n, &nl) != 0 || tag != 0x02 || der_next(&p, end, &tag, &e, &el) != 0 || tag != 0x02)
        return -1;
    return httpasm_rsa_public_key_init(&model_rsa, n, nl, e, el);
}

/* key_holds: the checks of a public key read as kind from spki[0..n). */
static void key_holds(const httpasm_public_key *k, int kind, const uint8_t *spki, size_t n)
{
    static const struct { uint32_t bits_min, bits_max, point; } shape[8] = {
        { 0, 0, 0 }, { 1024, 8192, 0 }, { 1024, 8192, 0 }, { 256, 256, 65 }, { 384, 384, 97 }, { 521, 521, 133 },
        { 256, 256, 32 }, { 448, 448, 57 },
    };
    FUZZ_CHECK(kind >= 1 && kind <= 7 && k->kind == (uint32_t)kind, "kind %d, the key's %u", kind, k->kind);
    FUZZ_CHECK(k->bits >= shape[kind].bits_min && k->bits <= shape[kind].bits_max, "bits %u for kind %d", k->bits, kind);
    FUZZ_CHECK(k->point_length == shape[kind].point, "point length %u for kind %d", k->point_length, kind);
    if (kind == HTTPASM_KEY_RSA || kind == HTTPASM_KEY_RSA_PSS) {
        FUZZ_CHECK(model_rsa_key(spki, n) == 0, "an RSA info the model does not walk, or n and e the init refuses");
        FUZZ_CHECK(memcmp(&model_rsa, &k->rsa, sizeof model_rsa) == 0, "an RSA key other than n and e's");
        if (kind == HTTPASM_KEY_RSA_PSS)
            FUZZ_CHECK(k->pss_hash == 0 || (k->pss_hash >= HTTPASM_HASH_SHA256 && k->pss_hash <= HTTPASM_HASH_SHA512),
                       "PSS: hash %u", k->pss_hash);
        return;
    }
    /* the key's octets are the BIT STRING's, which ends the info */
    FUZZ_CHECK(n >= k->point_length && memcmp(spki + n - k->point_length, k->point, k->point_length) == 0,
               "the key's octets are not the info's last ones");
    if (kind <= HTTPASM_KEY_P521)
        FUZZ_CHECK(k->point[0] == 4, "an EC point not uncompressed");
}

/* certificate_holds: the checks of a certificate read from in[0..n). */
static void certificate_holds(const httpasm_certificate *c, const uint8_t *in, size_t n)
{
    FUZZ_CHECK(present(c->tbs, c->tbs_length, in, n) && present(c->serial, c->serial_length, in, n) &&
               present(c->issuer, c->issuer_length, in, n) && present(c->subject, c->subject_length, in, n) &&
               present(c->spki, c->spki_length, in, n) &&
               present(c->signature_algorithm, c->signature_algorithm_length, in, n) &&
               fuzz_within(c->signature, c->signature_length, in, n) &&
               fuzz_within(c->extensions, c->extensions_length, in, n), "a part outside the input");
    const uint8_t *tbs_end = c->tbs + c->tbs_length;
    FUZZ_CHECK(c->tbs > in && c->signature_algorithm == tbs_end && c->signature + c->signature_length == in + n,
               "the outer parts out of place");
    FUZZ_CHECK(c->serial > c->tbs && c->serial + c->serial_length < c->issuer && c->subject > c->issuer &&
               c->spki > c->subject && c->spki + c->spki_length <= tbs_end, "the TBS's parts out of order");
    FUZZ_CHECK(c->version >= 1 && c->version <= 3, "version %u", c->version);
    FUZZ_CHECK(c->extensions == NULL || (c->version == 3 && c->extensions_length > 0 &&
               c->extensions > c->spki && c->extensions + c->extensions_length <= tbs_end), "extensions misplaced");
    /* the validity: the SEQUENCE between the issuer and the subject, its two times (DER: every
     * header of two octets, a validity's contents being at most 34) */
    const uint8_t *validity = c->issuer + c->issuer_length;
    FUZZ_CHECK(validity[0] == 0x30 && validity + 2 + validity[1] == c->subject, "no validity after the issuer");
    const uint8_t *first = validity + 2, *second = first + 2 + first[1];
    FUZZ_CHECK(model_time(first) == c->not_before && model_time(second) == c->not_after,
               "validity %lld..%lld, model %lld..%lld", (long long)c->not_before, (long long)c->not_after,
               (long long)model_time(first), (long long)model_time(second));
}

/* matches_holds: the pairing of the seed's Ed25519 key with a key read. */
static void matches_holds(const httpasm_public_key *k)
{
    int m = httpasm_private_key_matches(&seed_key, k);
    int same = k->kind == HTTPASM_KEY_ED25519 && memcmp(k->point, seed_key.public_key, 32) == 0;
    FUZZ_CHECK(m == (same ? 0 : -1), "matches answered %d for a key of kind %u (%s the seed's public octets)", m, k->kind,
               same ? "with" : "without");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)
{
    if (n > FUZZ_MAX)
        return 0;
    /* The seed's key: a PKCS#8 Ed25519 key (RFC 8410 10.3's shape) of the input's first 32 octets */
    static const uint8_t prefix[16] = { 0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20 };
    uint8_t pkcs8[48] = { 0 };
    memcpy(pkcs8, prefix, 16);
    memcpy(pkcs8 + 16, data, n < 32 ? n : 32);
    FUZZ_CHECK(httpasm_private_key_load(&seed_key, pkcs8, sizeof pkcs8) == HTTPASM_KEY_ED25519, "the seed's key not loaded");
    int cert_answer[FUZZ_TIERS], key_answer[FUZZ_TIERS], spki_answer[FUZZ_TIERS];
    for (size_t t = 0; t < FUZZ_TIERS; t++) {
        httpasm_cpu_limit(fuzz_caps[t]);
        uint8_t *in = fuzz_place(data, n);
        cert_answer[t] = httpasm_certificate_read(&certs[t], in, n);
        FUZZ_CHECK(cert_answer[t] == 0 || cert_answer[t] == -1, "certificate answer %d", cert_answer[t]);
        key_answer[t] = -1;
        if (cert_answer[t] == 0) {
            certificate_holds(&certs[t], in, n);
            key_answer[t] = httpasm_public_key_read(&keys[t], certs[t].spki, certs[t].spki_length);
            FUZZ_CHECK(key_answer[t] == -1 || (key_answer[t] >= 1 && key_answer[t] <= 7), "key answer %d", key_answer[t]);
            if (key_answer[t] > 0) {
                key_holds(&keys[t], key_answer[t], certs[t].spki, certs[t].spki_length);
                matches_holds(&keys[t]);
                /* the same info read again: the same key (nothing kept between reads) */
                FUZZ_CHECK(httpasm_public_key_read(&again, certs[t].spki, certs[t].spki_length) == key_answer[t] &&
                           memcmp(&again, &keys[t], sizeof again) == 0, "the info read twice differs");
            }
        }
        spki_answer[t] = httpasm_public_key_read(&spkis[t], in, n);
        FUZZ_CHECK(spki_answer[t] == -1 || (spki_answer[t] >= 1 && spki_answer[t] <= 7), "key answer %d", spki_answer[t]);
        if (spki_answer[t] > 0) {
            key_holds(&spkis[t], spki_answer[t], in, n);
            matches_holds(&spkis[t]);
        } else {
            static const httpasm_public_key zero;
            FUZZ_CHECK(memcmp(&spkis[t], &zero, sizeof zero) == 0, "a refused key not all zeros");
        }
        FUZZ_CHECK(cert_answer[t] == cert_answer[0] && key_answer[t] == key_answer[0] && spki_answer[t] == spki_answer[0],
                   "tier %zu answered otherwise", t);
        if (key_answer[t] > 0)
            FUZZ_CHECK(memcmp(&keys[t], &keys[0], sizeof keys[t]) == 0, "tier %zu: another key", t);
        if (spki_answer[t] > 0)
            FUZZ_CHECK(memcmp(&spkis[t], &spkis[0], sizeof spkis[t]) == 0, "tier %zu: another key", t);
        /* every tier's input sits at the same address (fuzz_place's one mapping), so even the
         * pointers compare */
        if (cert_answer[t] == 0)
            FUZZ_CHECK(memcmp(&certs[t], &certs[0], sizeof certs[t]) == 0, "tier %zu: another certificate", t);
    }
    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    return 0;
}
