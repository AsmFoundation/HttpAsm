/*
 * dudect.c - constant time, measured on the hardware: dudect's method (Reparaz, Balasch and
 * Verbauwhede, "Dude, is my code constant time?", DATE 2017). For each function that takes a
 * secret, two classes of inputs - a fixed secret chosen to be special (a key of 1, n - 18, all
 * zeros, a valid ciphertext) and random ones - are interleaved in a random order; every call is
 * timed with rdtscp between lfences, and Welch's t-test compares the classes' times: over all of
 * them, and over those below each of several percentiles of the whole (cropping the right tail,
 * where interrupts and frequency changes live, as dudect does). A |t| above 10 is a difference no
 * noise explains in that many measurements: the function FAILS. Above 4.5, a WARNING worth a
 * longer run (dudect's own thresholds).
 *
 * It complements tests/ct/run.sh: memcheck proves that no secret reaches a branch, an address or
 * a system call, in the code valgrind can run; this measures what the CPU does with every version
 * the machine has (the SHA extensions, VAES and AVX-512 included, which memcheck cannot run), and
 * catches what memcheck cannot see, such as an instruction whose latency depends on its operands.
 * Timing is noisy on shared machines, so it runs locally (tests/ct/dudect.sh), not in CI, as the
 * benchmarks do (the owner's rule of 2026-11-26).
 *
 * The targets, each at v1 and at the machine's best tier (httpasm_cpu_limit), fixed class first:
 *   aes256-gcm seal (key 0 / random), chacha20-poly1305 seal (key 0 / random), hmac-sha256 (key
 *   0 / random), x25519 (the clamped zero scalar / random), p256 ecdh (d = 1 / random), p256 sign
 *   (d = 1 / random, fixed digest and entropy), p521 ecdh (d = n - 18, crypto/p521.asm's doubling
 *   case / random), ed25519 sign (the zero seed's key / random keys), mlkem768 decaps (a valid
 *   ciphertext / random ones: implicit rejection), rsa2048 sign (digest 0 / random digests: the
 *   base of the exponentiation), ffdhe2048 public key (exponent 2^255 / random 256-bit ones).
 *
 * A negative control runs first: a comparison that stops at its first differing octet, which
 * must FAIL; if it does not, the run stops (exit 2), as its other verdicts would mean nothing.
 *
 * Usage: dudect [SCALE]   (SCALE multiplies every target's measurement count; default 1)
 * Exit status: 0 when no target fails; 1 when one does (printed); 2 on a setup error or when the
 * negative control passes.
 * Build and run: tests/ct/dudect.sh (cc -O2 against the Release libhttpasm.so, pinned to a core).
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#include "httpasm.h"

/* ---- randomness for the classes and the inputs (not security: xorshift64*, seeded fixed) ---- */
static uint64_t rng_state = 0x9E3779B97F4A7C15ull;

/* rng: the next 64 bits of the generator. */
static uint64_t rng(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1Dull;
}

/* random_fill: n generator octets into p. */
static void random_fill(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)rng();
}

/* ---- the targets ------------------------------------------------------------------------------
 * prepare(cls, slot) fills one measurement's input (cls 0: the fixed secret; 1: a random one)
 * outside the timing; run(slot) is the timed call. Each target keeps its inputs in its own
 * static arrays, one slot per measurement of a batch. */
enum { BATCH = 64 };

static uint8_t key32[BATCH][32], msg1k[1024], out1k[1024 + 64], tag[16];
static httpasm_aes_gcm_key gcm[BATCH];
static uint8_t point32[32], d66[BATCH][66], peer65[65], peer133[133], digest64[64], entropy[66];
static httpasm_ed25519_private_key edkeys[BATCH];
static uint8_t mlkem_ek[1184], mlkem_dk[2400], mlkem_ct[BATCH][1088], mlkem_valid[1088];
static httpasm_rsa_private_key rsa_key;
static uint8_t rsa_digests[BATCH][32], rsa_sig[256];
static uint8_t ffdhe_x[BATCH][32], ffdhe_y[256];

/* aes_prepare: slot s's AES-256-GCM key, expanded outside the timing (seal is what is measured,
 * not the expansion). cls 0: the all-zero key, whose round keys and H are the most special values a
 * data-dependent shortcut could meet; 1: a random key. */
static void aes_prepare(int cls, int s)
{
    if (cls == 0)
        memset(key32[s], 0, 32);
    else
        random_fill(key32[s], 32);
    httpasm_aes_gcm_init(&gcm[s], key32[s], 32);
}
/* aes_run: the timed call: sealing the 1 KiB message under slot s's key, no associated data (the
 * nonce repeats across slots, which is harmless here: nothing is sent). */
static void aes_run(int s)
{
    static const uint8_t nonce[12] = { 1 };
    httpasm_aes_gcm_seal(&gcm[s], nonce, NULL, 0, msg1k, sizeof msg1k, out1k, tag);
}

/* key32_prepare: slot s's 32-octet secret, shared by three targets: ChaCha20-Poly1305's key,
 * HMAC's key and X25519's scalar. cls 0: all zeros (X25519 clamps it to 2^254, the ladder's
 * sparsest scalar); 1: random. */
static void key32_prepare(int cls, int s)
{
    if (cls == 0)
        memset(key32[s], 0, 32);
    else
        random_fill(key32[s], 32);
}
/* chacha_run: the timed call: ChaCha20-Poly1305 sealing the 1 KiB message under slot s's key. */
static void chacha_run(int s)
{
    static const uint8_t nonce[12] = { 1 };
    httpasm_chacha20_poly1305_seal(key32[s], nonce, NULL, 0, msg1k, sizeof msg1k, out1k, tag);
}
/* hmac_run: the timed call: HMAC-SHA256 of 64 message octets under slot s's 32-octet key (the key
 * goes into both pads, so a key-dependent time would show twice). */
static void hmac_run(int s)
{
    httpasm_hmac_sha256(key32[s], 32, msg1k, 64, out1k);
}
/* x25519_run: the timed call: X25519 of the fixed peer point by slot s's scalar. */
static void x25519_run(int s)
{
    httpasm_x25519(out1k, key32[s], point32);
}

/* p256_prepare: slot s's P-256 private key d, the first 32 octets of d66[s] (the rest zero).
 * cls 0: d = 1, the scalar with one nonzero window, where a table walk or a ladder that skipped
 * zero windows would be fastest; 1: random below n (the top bit cleared). */
static void p256_prepare(int cls, int s)
{
    memset(d66[s], 0, 66);
    if (cls == 0)
        d66[s][31] = 1;
    else {
        random_fill(d66[s], 32);
        d66[s][0] &= 0x7F;                              /* below n */
    }
}
/* p256_ecdh_run: the timed call: ECDH of the fixed peer point by slot s's d (variable base). */
static void p256_ecdh_run(int s)
{
    httpasm_p256_ecdh(out1k, d66[s], peer65);
}
/* p256_sign_run: the timed call: ECDSA signing of the fixed digest by slot s's d with the fixed
 * entropy, so RFC 6979's k is a function of d alone: the fixed class repeats one d and one k, the
 * random class draws both (two secrets measured at once: the fixed-base k G and the arithmetic
 * with d). */
static void p256_sign_run(int s)
{
    httpasm_p256_sign(out1k, d66[s], digest64, 32, entropy);
}

/* p521_prepare: slot s's P-521 private key (66 octets). cls 0: d = n - 18, the scalar whose
 * recoding meets crypto/p521.asm's doubling case (the last addition's operands equal, answered by
 * a mask-selected doubling instead of a branch); 1: random below 2^521 (one bit in the top octet;
 * at or above n with probability about 2^-260, which the library would refuse). */
static void p521_prepare(int cls, int s)
{
    static const uint8_t n_minus_18[66] = {
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
        0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38,
        0x63, 0xF7,
    };
    if (cls == 0)
        memcpy(d66[s], n_minus_18, 66);
    else {
        random_fill(d66[s], 66);
        d66[s][0] &= 1;
    }
}
/* p521_ecdh_run: the timed call: ECDH of the fixed peer point by slot s's d (variable base). */
static void p521_ecdh_run(int s)
{
    httpasm_p521_ecdh(out1k, d66[s], peer133);
}

/* ed25519_prepare: slot s's prepared Ed25519 key, built outside the timing (the library signs
 * only with prepared keys). cls 0: the all-zero seed's key; 1: a random seed's. */
static void ed25519_prepare(int cls, int s)
{
    uint8_t seed[32] = { 0 };
    if (cls == 1)
        random_fill(seed, 32);
    httpasm_ed25519_private_key_init(&edkeys[s], seed);
}
/* ed25519_run: the timed call: signing 130 octets of the message with slot s's key (the nonce r
 * and the scalar arithmetic with the secret scalar both differ by class). */
static void ed25519_run(int s)
{
    httpasm_ed25519_sign(out1k, &edkeys[s], msg1k, 130);
}

/* mlkem_prepare: slot s's ML-KEM-768 ciphertext for the fixed key. cls 0: the valid one setup()
 * encapsulated (the re-encryption matches); 1: random octets (it does not, and FIPS 203's implicit
 * rejection answers J(z, c) instead). A decapsulation whose time told the two apart would tell an
 * attacker whether a chosen ciphertext was valid: the oracle a chosen-ciphertext attack needs. */
static void mlkem_prepare(int cls, int s)
{
    if (cls == 0)
        memcpy(mlkem_ct[s], mlkem_valid, sizeof mlkem_valid);
    else
        random_fill(mlkem_ct[s], sizeof mlkem_ct[s]);
}
/* mlkem_run: the timed call: decapsulating slot s's ciphertext with the fixed dk. */
static void mlkem_run(int s)
{
    httpasm_mlkem768_decaps(out1k, mlkem_dk, mlkem_ct[s]);
}

/* rsa_prepare: slot s's SHA-256 digest. cls 0: all zeros; 1: random. A digest is public, but its
 * encoded message is the base the CRT exponentiation raises to the secret dp and dq, so a time that
 * depended on the base (a window skipping zero limbs, a conditional final subtraction) would show
 * here as it would with a secret base. */
static void rsa_prepare(int cls, int s)
{
    if (cls == 0)
        memset(rsa_digests[s], 0, 32);
    else
        random_fill(rsa_digests[s], 32);
}
/* rsa_run: the timed call: PKCS#1 v1.5 signing of slot s's digest with the fixed 2048-bit key. */
static void rsa_run(int s)
{
    httpasm_rsa_sign_pkcs1(&rsa_key, HTTPASM_HASH_SHA256, rsa_digests[s], rsa_sig, 256);
}

/* ffdhe_prepare: slot s's 256-bit FFDHE exponent. cls 0: 2^255, one set bit, where a
 * square-and-multiply that skipped multiplications for zero bits would be fastest; 1: random with
 * the same top bit, so both classes have the same length (a length is public, and the library's
 * time may follow it). */
static void ffdhe_prepare(int cls, int s)
{
    memset(ffdhe_x[s], 0, 32);
    if (cls == 0)
        ffdhe_x[s][0] = 0x80;                           /* 2^255: one set bit */
    else {
        random_fill(ffdhe_x[s], 32);
        ffdhe_x[s][0] |= 0x80;                          /* the same length */
    }
}
/* ffdhe_run: the timed call: g^x modulo RFC 7919's 2048-bit prime for slot s's exponent x. */
static void ffdhe_run(int s)
{
    httpasm_ffdhe_public_key(HTTPASM_FFDHE2048, ffdhe_y, ffdhe_x[s], 32);
}

/* The negative control: a 64-octet comparison that stops at the first difference (memcmp's
 * shape), of a secret against a fixed value: equal (class 0) runs to the end, random (class 1)
 * stops at the first octet nearly always. It must FAIL, or the run's other verdicts mean nothing
 * (too few measurements, or a timer that cannot see a few cycles). */
static uint8_t control_secret[BATCH][64];
static const uint8_t control_fixed[64] = { 0 };
static volatile int control_sink;
/* control_prepare: slot s's control secret: cls 0 equal to control_fixed, 1 random. */
static void control_prepare(int cls, int s)
{
    if (cls == 0)
        memset(control_secret[s], 0, 64);
    else
        random_fill(control_secret[s], 64);
}
/* control_run: the timed call: the early-exit comparison, through volatile reads so the compiler
 * can neither vectorize nor remove it; the count goes to a volatile sink for the same reason. */
static void control_run(int s)
{
    const volatile uint8_t *a = control_secret[s];
    int i = 0;
    while (i < 64 && a[i] == control_fixed[i])
        i++;
    control_sink = i;
}

/* target: one function under test. name heads its line; prepare(cls, slot) builds a slot's input
 * outside the timing; run(slot) is the timed call; measurements is its count of timed calls at
 * SCALE 1, chosen so each line takes seconds (more calls for faster functions: t grows with the
 * square root of the count, so a smaller effect needs more of them). */
typedef struct {
    const char *name;
    void (*prepare)(int cls, int slot);
    void (*run)(int slot);
    long measurements;                                  /* at SCALE 1 */
} target;

static const target control = { "control: early-exit compare (must FAIL)", control_prepare, control_run, 20000 };

static const target targets[] = {
    { "aes256-gcm seal 1 KiB", aes_prepare, aes_run, 200000 },
    { "chacha20-poly1305 seal 1 KiB", key32_prepare, chacha_run, 200000 },
    { "hmac-sha256 64 octets", key32_prepare, hmac_run, 200000 },
    { "x25519", key32_prepare, x25519_run, 40000 },
    { "p256 ecdh (d = 1)", p256_prepare, p256_ecdh_run, 20000 },
    { "p256 sign (d = 1)", p256_prepare, p256_sign_run, 20000 },
    { "p521 ecdh (d = n - 18)", p521_prepare, p521_ecdh_run, 4000 },
    { "ed25519 sign (seed 0)", ed25519_prepare, ed25519_run, 40000 },
    { "mlkem768 decaps (valid / random)", mlkem_prepare, mlkem_run, 40000 },
    { "rsa2048 sign pkcs1 (digest 0)", rsa_prepare, rsa_run, 2000 },
    { "ffdhe2048 public key (2^255)", ffdhe_prepare, ffdhe_run, 1000 },
};

/* ---- Welch's t over cropped samples --------------------------------------------------------- */
enum { CROPS = 6 };
static const double crop_percentiles[CROPS] = { 100, 99, 95, 90, 75, 50 };

/* compare_u64: qsort's order for the percentiles. */
static int compare_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

/* welch: the t statistic of the times below `limit` (class 0 against class 1); 0 when either
 * class has fewer than two such times. */
static double welch(const uint64_t *times, const uint8_t *classes, long n, uint64_t limit)
{
    double mean[2] = { 0, 0 }, m2[2] = { 0, 0 };
    long count[2] = { 0, 0 };
    for (long i = 0; i < n; i++) {
        if (times[i] > limit)
            continue;
        int c = classes[i];
        double x = (double)times[i];
        count[c]++;
        double delta = x - mean[c];
        mean[c] += delta / (double)count[c];
        m2[c] += delta * (x - mean[c]);
    }
    if (count[0] < 2 || count[1] < 2)
        return 0;
    double v0 = m2[0] / (double)(count[0] - 1), v1 = m2[1] / (double)(count[1] - 1);
    double se = sqrt(v0 / (double)count[0] + v1 / (double)count[1]);
    return se > 0 ? (mean[0] - mean[1]) / se : 0;
}

/* measure: one target at the current tier (httpasm_cpu_limit's): `n` timed calls in batches of
 * BATCH (each batch prepared, then run in its random class order, so preparing never sits between
 * two timings and both classes meet the same cache and predictor state), then t over every crop.
 * t: the target; n: the number of timed calls; tier: the label printed in the tier column.
 * Returns the largest |t| of the crops, and prints the line with its verdict (FAIL above 10,
 * warning above 4.5). Exits with 2 when the sample arrays cannot be allocated. */
static double measure(const target *t, long n, const char *tier)
{
    uint64_t *times = malloc((size_t)n * sizeof *times), *sorted = malloc((size_t)n * sizeof *sorted);
    uint8_t *classes = malloc((size_t)n);
    if (times == NULL || sorted == NULL || classes == NULL) {
        fprintf(stderr, "dudect: out of memory\n");
        exit(2);
    }
    for (int warm = 0; warm < BATCH; warm++) {          /* caches, predictors, the clock */
        t->prepare(warm & 1, warm);
        t->run(warm);
    }
    for (long done = 0; done < n; done += BATCH) {
        int batch = (int)(n - done < BATCH ? n - done : BATCH);
        for (int s = 0; s < batch; s++) {
            classes[done + s] = (uint8_t)(rng() & 1);
            t->prepare(classes[done + s], s);
        }
        for (int s = 0; s < batch; s++) {
            unsigned aux;
            _mm_lfence();
            uint64_t start = __rdtscp(&aux);
            _mm_lfence();
            t->run(s);
            _mm_lfence();
            uint64_t end = __rdtscp(&aux);
            _mm_lfence();
            times[done + s] = end - start;
        }
    }
    memcpy(sorted, times, (size_t)n * sizeof *sorted);
    qsort(sorted, (size_t)n, sizeof *sorted, compare_u64);
    double worst = 0, ts[CROPS];
    for (int c = 0; c < CROPS; c++) {
        long at = (long)((double)(n - 1) * crop_percentiles[c] / 100.0);
        ts[c] = welch(times, classes, n, sorted[at]);
        if (fabs(ts[c]) > worst)
            worst = fabs(ts[c]);
    }
    printf("%-36s %-4s %7ld  median %9llu  t: all %6.2f  p99 %6.2f  p95 %6.2f  p90 %6.2f  p75 %6.2f  p50 %6.2f  %s\n",
           t->name, tier, n, (unsigned long long)sorted[n / 2], ts[0], ts[1], ts[2], ts[3], ts[4], ts[5],
           worst > 10 ? "FAIL" : worst > 4.5 ? "warning" : "ok");
    fflush(stdout);
    free(times);
    free(sorted);
    free(classes);
    return worst;
}

/* ---- the fixed inputs ------------------------------------------------------------------------ */

/* The RSA key: tests/native/tiers.c's 2048-bit one (n, e, p, q, dp, dq, q^-1). */
static const char *const rsa_2048[7] = {
    "e421764c563244426247031d997d47d08c5003303181239b41bdac0d338f0c4344084ca53d8038b43ea65b01b7db1c48"
    "b9461a5dcf2f4836bf060d007378322e8aa96a3ac6f61283630276041fe946d796b0a6bf8ab895e8b5ff28d1934bc99c"
    "278e30e895da211ae2b3b15db045df3f9cd71595ae15471a3d47b18fa0828d00d7048487ed756ca97600450e8695aa83"
    "0e59f9acaa65e0f016d4be59b90a473f5dcf00e0ffe8a4b42681aa56f72cda8d16ff5d42c6b46c748fa3830fe372d9bc"
    "6cb2af81ce698298d5d7c38958c43863b29dbcb7c0f1529ad9a49f6b5362437d16a52a5c8c12af81624a1d941db818cf"
    "cf5e8d8bda19556398ae08e502f82763",
    "010001",
    "feb0f65ae82f63e64d084f356bd5223b8250065bbeace771710a93b3e60e438491a72d884d8e4a391f7e1bcc7b6d40ff"
    "96b2c61a8fc9a8532f150b3a21d8e21a6047655fb8749fd6cc42ef76d408cd5612ee569084b26546a01709bf4cb1b065"
    "0278dc823802270db5796931440d8876249675808b6fa6bdebe5935e5cdecf79",
    "e54d8f6ea255db59d5a3f12c36df5be764b15878b7b0493dd7c3e8ec10c5594917490411d3aaf331093202992dd3ac06"
    "3904de6e14eaa020612fe2671cf4b9da7fd5c78417bf1a2a0e3a7f0852ca0de0455320d305b33385e348b9ce7e132ad0"
    "343b96577c6a683865bb8447dd247b7d671d6cc28ad358e73cba3c0ff8a2eabb",
    "aef726e6a0a71dbbf2a388b6ac5388e6d4c8e0f559f232350e7133b2dc9263f3c893ce85dab1ab6fbea0c5bc1df69a36"
    "7b7269018a52009ed4b3623917538550955fb6d6a1430d2364c37efa65037efc6898ef42ecc619290185921ea7335278"
    "b1d011bc2b79df165ddb0056e5e75e1dbb58d973eb5652781a7c6656e6f9f211",
    "28826d4684535aaf2239165053595e6920b6dc04679f333143bf0e9535d9478ecc185029be15436574546b75184d7ee4"
    "928a33a98af470598811e79383e0103d73bc16c55554a390ae76d31e6b51dae5b6199b80ec4ede5956eff03374be7a1f"
    "d23a7cb2f3fdf06f96396c832da45654af34d993fce69d9c2c74524c1806e025",
    "8d0b3783e80edb1e0516632d8944f1f0dff3434c190790ff41d3880eb48dd0eb88266f38c1b52c44925e78f7972da9ae"
    "780c5ffd85987253d62c094dfdd76397435a8d37a0efb8fb89f7d884a0db3705b9c6c22a950bc5dec7ed5ce3fdb394f5"
    "d0df1034b35da43c04b5f9ea809609020a1b48862715914a7dac2b6ee69a368d"
};

/* hex_octets: a hex string's octets into out; returns how many, 0 on a bad digit. */
static size_t hex_octets(const char *hex, uint8_t *out)
{
    size_t count = strlen(hex) / 2;
    for (size_t i = 0; i < count; i++) {
        unsigned value;
        if (sscanf(hex + 2 * i, "%2x", &value) != 1)
            return 0;
        out[i] = (uint8_t)value;
    }
    return count;
}

/* setup: the inputs every class shares (the peers' points, the ML-KEM key and its valid
 * ciphertext, the RSA key, the message). Returns 0, or -1 when a library call refuses. */
static int setup(void)
{
    random_fill(msg1k, sizeof msg1k);
    random_fill(digest64, sizeof digest64);
    random_fill(entropy, sizeof entropy);
    uint8_t other[66];
    random_fill(other, sizeof other);
    httpasm_x25519_public_key(point32, other);
    other[0] &= 0x7F;
    if (httpasm_p256_public_key(peer65, other) != 0)
        return -1;
    other[0] &= 1;
    if (httpasm_p521_public_key(peer133, other) != 0)
        return -1;
    uint8_t seed[64], m[32], shared[32];
    random_fill(seed, sizeof seed);
    random_fill(m, sizeof m);
    httpasm_mlkem768_keypair(mlkem_ek, mlkem_dk, seed);
    if (httpasm_mlkem768_encaps(mlkem_valid, shared, mlkem_ek, m) != 0)
        return -1;
    static uint8_t octets[7][256];
    size_t lengths[7];
    for (int i = 0; i < 7; i++)
        lengths[i] = hex_octets(rsa_2048[i], octets[i]);
    httpasm_rsa_private_numbers numbers = {
        octets[0], lengths[0], octets[1], lengths[1], octets[2], lengths[2], octets[3], lengths[3],
        octets[4], lengths[4], octets[5], lengths[5], octets[6], lengths[6],
    };
    return httpasm_rsa_private_key_init(&rsa_key, &numbers);
}

/* main: the setup, the negative control, then every target at v1 and at the best tier (the best
 * is skipped when it is v1). argv[1]: SCALE, the multiplier of every target's call count (default
 * 1; at least 1,000 calls per line). Returns 0 when no target fails, 1 when one does, 2 on a bad
 * SCALE, a refused setup or a control that did not fail. */
int main(int argc, char **argv)
{
    double scale = argc > 1 ? atof(argv[1]) : 1.0;
    if (!(scale > 0)) {
        fprintf(stderr, "usage: dudect [SCALE]\n");
        return 2;
    }
    if (setup() != 0) {
        fprintf(stderr, "dudect: the setup's inputs were refused\n");
        return 2;
    }
    printf("%-36s %-4s %7s  %16s  %s\n", "target", "tier", "calls", "(TSC ticks)", "Welch's t, fixed class against random, below each percentile");
    if (measure(&control, 20000, "-") <= 10) {
        fprintf(stderr, "dudect: the negative control (an early-exit compare) did not fail: the measurement cannot see a leak, so nothing below means anything\n");
        return 2;
    }
    int failed = 0;
    uint64_t best = httpasm_cpu_limit(HTTPASM_CPU_ALL);
    const uint64_t caps[2] = { HTTPASM_CPU_CAP_V1, HTTPASM_CPU_ALL };
    const char *names[2] = { "v1", "best" };
    for (size_t i = 0; i < sizeof targets / sizeof targets[0]; i++) {
        for (int c = 0; c < 2; c++) {
            if (c == 1 && best == HTTPASM_CPU_CAP_V1)
                continue;
            httpasm_cpu_limit(caps[c]);
            long n = (long)((double)targets[i].measurements * scale);
            if (measure(&targets[i], n < 1000 ? 1000 : n, names[c]) > 10)
                failed = 1;
        }
    }
    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    return failed;
}
