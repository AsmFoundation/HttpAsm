/*
 * ct.c - constant time, checked by valgrind's memcheck: every function of the C ABI that takes a
 * secret runs with the secret marked "undefined" (memcheck's client request MAKE_MEM_UNDEFINED),
 * at every CPU tier valgrind's own CPU offers. memcheck tracks undefinedness bit for bit through
 * every instruction it runs and reports each branch, memory address or system call argument that
 * depends on it - exactly what constant time forbids (cmov, masks, adc of masks and table scans
 * by mask are data flow, which it lets pass). The
 * library is the ConstantTime build (Directory.Build.props): its HA_DECLASSIFY sites mark public
 * the few values derived from a secret that the code branches on by design (a key refused as out
 * of range, RFC 6979's redrawn nonce, an AEAD tag's verdict, X25519's and X448's all-zero
 * output), each with its reason at the site; anything else memcheck reports is a finding.
 *
 * What runs (outputs are marked defined again after each call, so the program's own use of them
 * is not reported): SHA-256, SHA-384, SHA-512, SHA3-256 and SHAKE128/256 over secret data of
 * lengths around their blocks; HMAC-SHA256/384/512 and HKDF under secret keys; AES-128 and
 * AES-256 (key schedule and a block); AES-GCM and ChaCha20-Poly1305 seal and open (a good tag and
 * a forged one); X25519 and X448 (a secret scalar, a low-order point among the public ones);
 * P-256, P-384 and P-521 public keys, shared secrets and hedged signatures (secret keys, nonces'
 * entropy; n - 18 among P-521's keys); Ed25519 and Ed448 public keys, prepared keys and
 * signatures; ML-KEM-512/768/1024 key pairs, encapsulations and decapsulations (a valid and a
 * tampered ciphertext: implicit rejection must not branch); FFDHE's public key and shared secret
 * (ffdhe2048); RSA's prepared keys and PKCS#1 v1.5 and PSS signatures at 1024 bits (the generic
 * arithmetic) and 2048 (v3's own k = 16 square and product); the ASN.1 reader, PEM and the
 * private keys' loader over secret key files (encodings(), keys()); TLS 1.3's key schedule
 * (every derivation from a secret IKM) and record layer (keys from a secret traffic secret,
 * secret contents sealed and opened, a forged record refused) for its three suites; and the
 * server engine (engine()): 13 whole handshakes against a client of this file's own, the
 * server's key loaded from a secret PEM text and every octet its random source draws secret -
 * every group's key exchange (ffdhe2048 standing for the five FFDHE groups, whose code is one),
 * each kind of server key, each suite, a HelloRetryRequest,
 * client authentication in the handshake and after it, KeyUpdates, application data and
 * close_notify both ways, a forged Finished and a forged record (see "the engine" below for
 * what the engine publishes by design, and where).
 *
 * Outside valgrind the client requests do nothing and the run proves nothing: the program then
 * says so and exits 2. Usage: valgrind --error-exitcode=1 ct (tests/ct/run.sh).
 * Exit status: 0 when every call ran (memcheck's verdict is valgrind's exit status); 1 when a
 * call failed outright; 2 when not under valgrind or on a setup error.
 * Build: tests/ct/run.sh (cc against the ConstantTime libhttpasm.so, which it builds first).
 */
#define _GNU_SOURCE                             /* dladdr and Dl_info (dlfcn.h) */
#include <dlfcn.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "httpasm.h"

/* ---- valgrind's client requests, without valgrind.h ------------------------------------------
 * valgrind.h's amd64 sequence: rax = the request's six qwords (the code and five arguments), rdx
 * = the default answer, then rotations of rdi by 3, 13, 61 and 51 (128 bits: no change) and
 * xchg rbx, rbx, which valgrind recognises; on hardware it is a no-op and rdx keeps the default.
 * Codes: RUNNING_ON_VALGRIND 0x1001 (valgrind.h); memcheck's MAKE_MEM_UNDEFINED and
 * MAKE_MEM_DEFINED are VG_USERREQ_TOOL_BASE('M', 'C') + 1 and + 2 (memcheck.h). */
static unsigned long vg_request(unsigned long request, unsigned long a1, unsigned long a2)
{
    volatile unsigned long args[6] = { request, a1, a2, 0, 0, 0 };
    unsigned long result = 0;
    __asm__ volatile("rolq $3, %%rdi ; rolq $13, %%rdi\n\t"
                     "rolq $61, %%rdi ; rolq $51, %%rdi\n\t"
                     "xchgq %%rbx, %%rbx"
                     : "=d"(result)
                     : "a"(&args[0]), "0"(result)
                     : "cc", "memory");
    return result;
}

/* secret: memcheck treats the octets as undefined from here on. */
static void secret(const void *p, size_t n)
{
    vg_request(0x4D430001, (unsigned long)p, n);
}

/* public: memcheck treats the octets as defined again (an output the program may now read). */
static void public(const void *p, size_t n)
{
    vg_request(0x4D430002, (unsigned long)p, n);
}

/* ---- inputs ---------------------------------------------------------------------------------- */

/* fill: a deterministic pattern (inputs need values, not randomness: memcheck follows
 * definedness, whatever the octets are). */
static void fill(uint8_t *p, size_t n, unsigned seed)
{
    uint32_t x = 0x9E3779B9u * (seed + 1);
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        p[i] = (uint8_t)x;
    }
}

static int failures;

/* expect: a call that must succeed (or fail) did not: counted and printed. */
static void expect(int condition, const char *what, const char *tier)
{
    if (!condition) {
        fprintf(stderr, "ct: %s at %s did not answer as expected\n", what, tier);
        failures++;
    }
}

/* ---- the primitives -------------------------------------------------------------------------- */

static const size_t lengths[] = { 0, 1, 55, 56, 64, 111, 112, 128, 135, 136, 168, 200, 1000 };
#define LENGTHS (sizeof lengths / sizeof lengths[0])

/* hashes: each hash over secret data of every length above (lengths are public). */
static void hashes(void)
{
    static uint8_t data[1000];
    uint8_t out[64];
    for (size_t i = 0; i < LENGTHS; i++) {
        size_t n = lengths[i];
        fill(data, n, (unsigned)i);
        secret(data, n);
        httpasm_sha256(data, n, out);
        httpasm_sha384(data, n, out);
        httpasm_sha512(data, n, out);
        httpasm_sha3_256(data, n, out);
        httpasm_shake128(data, n, out, 64);
        httpasm_shake256(data, n, out, 64);
        public(out, sizeof out);
    }
}

/* macs: HMAC under secret keys of 0 to 200 octets (both sides of the blocks) over secret data, and
 * HKDF from secret keying material and a secret PRK. */
static void macs(void)
{
    static uint8_t key[200], data[300], okm[200];
    uint8_t mac[64], prk[64], salt[32] = { 1, 2, 3 };
    static const size_t key_lengths[] = { 0, 32, 64, 65, 128, 129, 200 };
    for (size_t i = 0; i < sizeof key_lengths / sizeof key_lengths[0]; i++) {
        size_t k = key_lengths[i];
        fill(key, k, (unsigned)(10 + i));
        fill(data, sizeof data, (unsigned)(20 + i));
        secret(key, k);
        secret(data, sizeof data);
        httpasm_hmac_sha256(key, k, data, sizeof data, mac);
        httpasm_hmac_sha384(key, k, data, sizeof data, mac);
        httpasm_hmac_sha512(key, k, data, sizeof data, mac);
        httpasm_hkdf_sha256_extract(salt, sizeof salt, key, k, prk);
        expect(httpasm_hkdf_sha256_expand(prk, 32, data, 20, okm, 100) == 0, "hkdf_sha256_expand", "-");
        httpasm_hkdf_sha384_extract(salt, sizeof salt, key, k, prk);
        expect(httpasm_hkdf_sha384_expand(prk, 48, data, 20, okm, 100) == 0, "hkdf_sha384_expand", "-");
        httpasm_hkdf_sha512_extract(salt, sizeof salt, key, k, prk);
        expect(httpasm_hkdf_sha512_expand(prk, 64, data, 20, okm, 200) == 0, "hkdf_sha512_expand", "-");
        public(mac, sizeof mac);
        public(prk, sizeof prk);
        public(okm, sizeof okm);
    }
}

/* ciphers: AES-128/256 schedules and blocks, AES-GCM and ChaCha20-Poly1305 seal and open (each
 * open with the real tag and a forged one: the verdict is public, the work before it is not). */
static void ciphers(const char *tier)
{
    static httpasm_aes_key aes;
    static httpasm_aes_gcm_key gcm;
    static uint8_t key[32], plain[300], sealed[300], opened[300];
    uint8_t nonce[12] = { 9, 8, 7 }, aad[20] = { 1 }, tag[16], block[16];
    for (size_t bits = 128; bits <= 256; bits += 128) {
        fill(key, sizeof key, (unsigned)bits);
        fill(plain, sizeof plain, (unsigned)bits + 1);
        secret(key, sizeof key);
        secret(plain, sizeof plain);
        expect(httpasm_aes_init(&aes, key, bits / 8) == 0, "aes_init", tier);
        httpasm_aes_encrypt_block(&aes, plain, block);
        public(block, sizeof block);
        expect(httpasm_aes_gcm_init(&gcm, key, bits / 8) == 0, "aes_gcm_init", tier);
        for (size_t n = 0; n <= 300; n += 75) {
            expect(httpasm_aes_gcm_seal(&gcm, nonce, aad, sizeof aad, plain, n, sealed, tag) == 0, "aes_gcm_seal", tier);
            public(sealed, n);                          /* the ciphertext and tag go on the wire */
            public(tag, sizeof tag);
            expect(httpasm_aes_gcm_open(&gcm, nonce, aad, sizeof aad, sealed, n, tag, opened) == 0, "aes_gcm_open", tier);
            tag[0] ^= 1;
            expect(httpasm_aes_gcm_open(&gcm, nonce, aad, sizeof aad, sealed, n, tag, opened) == -1, "aes_gcm_open (forged)", tier);
            public(opened, sizeof opened);
        }
        public(&aes, sizeof aes);
        public(&gcm, sizeof gcm);
    }
    for (size_t n = 0; n <= 300; n += 60) {
        fill(key, sizeof key, 300 + (unsigned)n);
        fill(plain, sizeof plain, 301 + (unsigned)n);
        secret(key, sizeof key);
        secret(plain, sizeof plain);
        httpasm_chacha20(key, 1, nonce, plain, n, sealed);  /* the cipher and the MAC alone: the */
        httpasm_poly1305(key, plain, n, tag);               /* AEAD runs its own stitched code */
        public(sealed, n);
        public(tag, sizeof tag);
        expect(httpasm_chacha20_poly1305_seal(key, nonce, aad, sizeof aad, plain, n, sealed, tag) == 0, "chacha20_poly1305_seal", tier);
        public(sealed, n);
        public(tag, sizeof tag);
        expect(httpasm_chacha20_poly1305_open(key, nonce, aad, sizeof aad, sealed, n, tag, opened) == 0, "chacha20_poly1305_open", tier);
        tag[15] ^= 0x80;
        expect(httpasm_chacha20_poly1305_open(key, nonce, aad, sizeof aad, sealed, n, tag, opened) == -1, "chacha20_poly1305_open (forged)", tier);
        public(opened, sizeof opened);
    }
}

/* montgomery: X25519 and X448 with secret scalars, against a public point and a low-order one
 * (whose all-zero shared secret the functions refuse: a public verdict). */
static void montgomery(const char *tier)
{
    uint8_t scalar[56], point[56], out[56];
    fill(scalar, 32, 25519);
    secret(scalar, 32);
    httpasm_x25519_public_key(point, scalar);
    public(point, 32);
    expect(httpasm_x25519(out, scalar, point) == 0, "x25519", tier);
    public(out, 32);
    memset(point, 0, 32);                               /* u = 0: of low order, all-zero output */
    expect(httpasm_x25519(out, scalar, point) == -1, "x25519 (low order)", tier);
    public(out, 32);
    fill(scalar, 56, 448);
    secret(scalar, 56);
    expect(httpasm_x448_public_key(point, scalar) == 0, "x448_public_key", tier);
    public(point, 56);
    expect(httpasm_x448(out, scalar, point) == 0, "x448", tier);
    public(out, 56);
    memset(point, 0, 56);
    point[0] = 1;                                       /* u = 1: of low order */
    expect(httpasm_x448(out, scalar, point) == -1, "x448 (low order)", tier);
    public(out, 56);
}

/* weierstrass: P-256, P-384 and P-521: a public key, a shared secret with a public peer, a hedged
 * signature (key and entropy secret, the digest public), and a key out of range (refused: a
 * public verdict). P-521 also signs and agrees with d = n - 18 (crypto/p521.asm's doubling case). */
static void weierstrass(const char *tier)
{
    uint8_t key[66], other[66], entropy[66], digest[64], point[133], peer[133], shared[66], signature[132];
    fill(digest, sizeof digest, 77);
    /* P-256 */
    fill(key, 32, 256);
    fill(other, 32, 257);
    fill(entropy, 32, 258);
    expect(httpasm_p256_public_key(peer, other) == 0, "p256_public_key (peer)", tier);
    secret(key, 32);
    secret(entropy, 32);
    expect(httpasm_p256_public_key(point, key) == 0, "p256_public_key", tier);
    expect(httpasm_p256_ecdh(shared, key, peer) == 0, "p256_ecdh", tier);
    expect(httpasm_p256_sign(signature, key, digest, 32, entropy) == 0, "p256_sign", tier);
    public(point, 65);
    public(shared, 32);
    public(signature, 64);
    memset(key, 0xFF, 32);
    secret(key, 32);
    expect(httpasm_p256_public_key(point, key) == -1, "p256_public_key (out of range)", tier);
    public(point, 65);
    /* P-384 */
    fill(key, 48, 384);
    fill(other, 48, 385);
    fill(entropy, 48, 386);
    expect(httpasm_p384_public_key(peer, other) == 0, "p384_public_key (peer)", tier);
    secret(key, 48);
    secret(entropy, 48);
    expect(httpasm_p384_public_key(point, key) == 0, "p384_public_key", tier);
    expect(httpasm_p384_ecdh(shared, key, peer) == 0, "p384_ecdh", tier);
    expect(httpasm_p384_sign(signature, key, digest, 48, entropy) == 0, "p384_sign", tier);
    public(point, 97);
    public(shared, 48);
    public(signature, 96);
    /* P-521, and n - 18 */
    static const uint8_t n_minus_18[66] = {
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
        0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38,
        0x63, 0xF7,
    };
    fill(other, 66, 521);
    other[0] &= 1;
    expect(httpasm_p521_public_key(peer, other) == 0, "p521_public_key (peer)", tier);
    for (int round = 0; round < 2; round++) {
        if (round == 0) {
            fill(key, 66, 522);
            key[0] &= 1;
        } else {
            memcpy(key, n_minus_18, 66);
        }
        fill(entropy, 66, 523);
        secret(key, 66);
        secret(entropy, 66);
        expect(httpasm_p521_public_key(point, key) == 0, "p521_public_key", tier);
        expect(httpasm_p521_ecdh(shared, key, peer) == 0, "p521_ecdh", tier);
        expect(httpasm_p521_sign(signature, key, digest, 64, entropy) == 0, "p521_sign", tier);
        public(point, 133);
        public(shared, 66);
        public(signature, 132);
    }
}

/* edwards: Ed25519 and Ed448: public keys and prepared keys from secret seeds, signatures under
 * secret prepared keys (the messages public). */
static void edwards(const char *tier)
{
    static httpasm_ed25519_private_key k25519;
    static httpasm_ed448_private_key k448;
    uint8_t seed[57], public_key[57], signature[114], message[130];
    fill(message, sizeof message, 130);
    fill(seed, 32, 25519);
    secret(seed, 32);
    httpasm_ed25519_public_key(public_key, seed);
    httpasm_ed25519_private_key_init(&k25519, seed);
    httpasm_ed25519_sign(signature, &k25519, message, sizeof message);
    public(public_key, 32);
    public(signature, 64);
    public(&k25519, sizeof k25519);
    fill(seed, 57, 448);
    secret(seed, 57);
    httpasm_ed448_public_key(public_key, seed);
    httpasm_ed448_private_key_init(&k448, seed);
    expect(httpasm_ed448_sign(signature, &k448, message, sizeof message, (const uint8_t *)"ctx", 3) == 0, "ed448_sign", tier);
    public(public_key, 57);
    public(signature, 114);
    public(&k448, sizeof k448);
}

/* kem: ML-KEM at its three sizes: a key pair from a secret seed, an encapsulation of a secret
 * message to the public key, a decapsulation of the ciphertext and of a tampered one under the
 * secret key (the implicit rejection: the shared secret then comes from z, and nothing may
 * branch on which). */
static void kem(const char *tier)
{
    static uint8_t ek[1568], dk[3168], c[1568];
    uint8_t seed[64], m[32], shared[32], again[32];
    struct {
        void (*keypair)(uint8_t *, uint8_t *, const uint8_t *);
        int (*encaps)(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *);
        int (*decaps)(uint8_t *, const uint8_t *, const uint8_t *);
        size_t ek_n, dk_n, c_n;
        const char *name;
    } sets[] = {
        { httpasm_mlkem512_keypair, httpasm_mlkem512_encaps, httpasm_mlkem512_decaps, 800, 1632, 768, "mlkem512" },
        { httpasm_mlkem768_keypair, httpasm_mlkem768_encaps, httpasm_mlkem768_decaps, 1184, 2400, 1088, "mlkem768" },
        { httpasm_mlkem1024_keypair, httpasm_mlkem1024_encaps, httpasm_mlkem1024_decaps, 1568, 3168, 1568, "mlkem1024" },
    };
    for (size_t s = 0; s < 3; s++) {
        fill(seed, sizeof seed, 203 + (unsigned)s);
        fill(m, sizeof m, 303 + (unsigned)s);
        secret(seed, sizeof seed);
        sets[s].keypair(ek, dk, seed);
        public(ek, sets[s].ek_n);                       /* the encapsulation key is published */
        secret(m, sizeof m);
        expect(sets[s].encaps(c, shared, ek, m) == 0, sets[s].name, tier);
        public(c, sets[s].c_n);                         /* the ciphertext goes on the wire */
        expect(sets[s].decaps(again, dk, c) == 0, sets[s].name, tier);
        c[17] ^= 4;                                     /* tampered: implicit rejection */
        expect(sets[s].decaps(again, dk, c) == 0, sets[s].name, tier);
        public(shared, sizeof shared);
        public(again, sizeof again);
        public(dk, sets[s].dk_n);
    }
}

/* ffdhe: ffdhe2048's public key and shared secret from a secret exponent (the peer public). */
static void ffdhe(const char *tier)
{
    static uint8_t x[64], y[256], peer[256], shared[256], other[64];
    fill(other, sizeof other, 2049);
    expect(httpasm_ffdhe_public_key(HTTPASM_FFDHE2048, peer, other, sizeof other) == 0, "ffdhe_public_key (peer)", tier);
    fill(x, sizeof x, 2048);
    secret(x, sizeof x);
    expect(httpasm_ffdhe_public_key(HTTPASM_FFDHE2048, y, x, sizeof x) == 0, "ffdhe_public_key", tier);
    expect(httpasm_ffdhe_shared(HTTPASM_FFDHE2048, shared, x, sizeof x, peer) == 0, "ffdhe_shared", tier);
    public(y, sizeof y);
    public(shared, sizeof shared);
}

/* The RSA keys: tests/native/tiers.c's (made with OpenSSL): n, e, p, q, dp, dq, q^-1. */
static const char *const rsa_1024[7] = {
    "c0101f8934307c57c9481985b2c13a4635b129c5e056d1a92223c1cfd779dfebf35416f4c8958c30dc47f0fb0bc09a53"
    "003ccda0bc20780d1385fb37a395d1d2cd31fb4cfddbd5d3c92a8dc280c064afb4949654d14c378077254b88fb05f50b"
    "0e7b1aa23725f33950ce06ddb946301ba3517e329a86fc1f834f90c395c4bdfb",
    "010001",
    "fcfbb4ac50e3f6fcdae2f17ba12b173a6181d29cd0a7cdc057388f6e9f3dbfea3abaa140bd8b162968e7bf4a5f521284"
    "232f373385a16adb5a3b41bc0777a3f3",
    "c25a717767c752d84290507bf0a549277f92fdc6b9fba9e668ceb6a500feea564f9d234f930d43fd7f25ce488f7b8c23"
    "83073343c650342a6e8bc348950c67d9",
    "6f1f54fe37cddaa8b8b0e4e7ac249460658233f403c7219e71f17b375925338e7c5b8c0736fac8324a4d397e3e9e7b59"
    "a566d0f585a6209cd7669dfa2cc185b7",
    "223b39d6f52167570dca4b52b91cf3989060bc6fff1bf35dd0c1efeb7a146c03cdbbf89730685abc5063c14488791342"
    "c1f647b23d40ad1f781f07c345f54c69",
    "e0bdd098c4795787e564eac34f8cfbc0005861c7a642ab493c90299f50c706efbc241e61d9ab09cb0c427ccbc612b3ca"
    "be48f67395a08504a38f44c720999132"
};

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

/* hex_octets: the octets of a hex string (two digits each) into out; returns how many, or 0 on a
 * digit that does not parse. */
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

/* rsa: a prepared key from secret numbers (n and e are public; p, q, dp, dq and q^-1 secret),
 * then PKCS#1 v1.5 and PSS signatures (a secret salt: it is random until it is published inside
 * the signature). */
static void rsa(const char *const hex[7], const char *tier)
{
    static uint8_t octets[7][256];
    static httpasm_rsa_private_key key;
    static uint8_t signature[256];
    size_t lengths7[7];
    for (int i = 0; i < 7; i++)
        lengths7[i] = hex_octets(hex[i], octets[i]);
    for (int i = 2; i < 7; i++)
        secret(octets[i], lengths7[i]);
    httpasm_rsa_private_numbers numbers = {
        octets[0], lengths7[0], octets[1], lengths7[1], octets[2], lengths7[2], octets[3], lengths7[3],
        octets[4], lengths7[4], octets[5], lengths7[5], octets[6], lengths7[6],
    };
    expect(httpasm_rsa_private_key_init(&key, &numbers) == 0, "rsa_private_key_init", tier);
    uint8_t digest[32], salt[32];
    fill(digest, sizeof digest, 32);
    fill(salt, sizeof salt, 33);
    secret(salt, sizeof salt);
    expect(httpasm_rsa_sign_pkcs1(&key, HTTPASM_HASH_SHA256, digest, signature, lengths7[0]) == 0, "rsa_sign_pkcs1", tier);
    public(signature, sizeof signature);
    expect(httpasm_rsa_sign_pss(&key, HTTPASM_HASH_SHA256, digest, salt, sizeof salt, signature, lengths7[0]) == 0, "rsa_sign_pss", tier);
    public(signature, sizeof signature);
    public(&key, sizeof key);
}

/* put_tlv: a DER element (tag, a definite length in the fewest octets, the contents) at out;
 * returns its length. */
static size_t put_tlv(uint8_t *out, uint8_t tag, const uint8_t *content, size_t n)
{
    size_t h = 0;
    out[h++] = tag;
    if (n < 128) {
        out[h++] = (uint8_t)n;
    } else if (n < 256) {
        out[h++] = 0x81, out[h++] = (uint8_t)n;
    } else {
        out[h++] = 0x82, out[h++] = (uint8_t)(n >> 8), out[h++] = (uint8_t)n;
    }
    memmove(out + h, content, n);
    return h + n;
}

/* encodings: the readers private keys go through, on secrets. PEM: the base64 text of a key
 * between its boundaries (secret; the boundaries are not), of RFC 8410's Ed25519 key and of a
 * text with every base64 character, its pads and whitespace of each kind. ASN.1: an
 * RSAPrivateKey built from the 2048-bit key's numbers, each INTEGER's contents secret (its
 * identifier and length octets are the structure: public by design), read element by element
 * under DER and BER; an OCTET STRING's secret contents gathered, primitive and BER-constructed. */
static void encodings(const char *tier)
{
    static const char *const texts[] = {
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n",
        "-----BEGIN TEST-----\r\nABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\r\n\t AQID BA\v\fU =\n-----END TEST-----",
        "-----BEGIN TEST-----\nAQIDBAU=\n-----END TEST-----",
        "-----BEGIN TEST-----\nAQIDBAUG\n-----END TEST-----",
    };
    static uint8_t text[512], der[512];
    for (size_t i = 0; i < sizeof texts / sizeof texts[0]; i++) {
        size_t n = strlen(texts[i]);
        memcpy(text, texts[i], n);
        const char *body = strchr(texts[i], '\n') + 1, *end = strstr(body, "-----END");
        secret(text + (body - texts[i]), (size_t)(end - body));
        httpasm_pem block;
        expect(httpasm_pem_read(&block, text, n, der, sizeof der) == 0, "pem_read", tier);
        public(der, sizeof der);
        public(text, n);
    }

    /* RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }: the key's numbers in
     * that order (d is not among them: q's octets stand in for it) */
    static const int order[8] = { 0, 1, 3, 2, 3, 4, 5, 6 };
    static uint8_t numbers[8][257], body[2048], key[2100], scratch[600];
    size_t at = 0;
    uint8_t zero = 0;
    at += put_tlv(body + at, 0x02, &zero, 1);
    for (int i = 0; i < 8; i++) {
        uint8_t raw[256];
        size_t m = hex_octets(rsa_2048[order[i]], raw);
        size_t off = (raw[0] & 0x80) ? 1 : 0;               /* a positive INTEGER's leading zero */
        numbers[i][0] = 0;
        memcpy(numbers[i] + off, raw, m);
        at += put_tlv(body + at, 0x02, numbers[i], m + off);
    }
    size_t total = put_tlv(key, 0x30, body, at);
    size_t p = 0;
    httpasm_asn1 e;
    expect(httpasm_asn1_read(&e, key, total, HTTPASM_ASN1_DER) == 0 && e.tag == HTTPASM_ASN1_SEQUENCE, "asn1 sequence", tier);
    p = (size_t)(e.content - key);
    int index = 0;
    while (p < total) {
        httpasm_asn1 item;
        if (httpasm_asn1_read(&item, key + p, total - p, HTTPASM_ASN1_DER) != 0)
            break;
        if (index >= 3)
            secret(item.content, item.content_length);    /* d, p, q, dp, dq, qinv */
        p += item.length;
        index++;
    }
    expect(index == 9, "asn1 integers", tier);
    for (int rules = HTTPASM_ASN1_DER; rules <= HTTPASM_ASN1_BER; rules++) {
        p = (size_t)(e.content - key);
        int read = 0;
        while (p < total) {
            httpasm_asn1 item;
            int r = httpasm_asn1_read(&item, key + p, total - p, rules);
            expect(r == 0 && item.tag == HTTPASM_ASN1_INTEGER, "asn1 integer", tier);
            if (r != 0)
                break;
            p += item.length;
            read++;
        }
        expect(read == 9, "asn1 integers read", tier);
    }
    public(key, total);

    /* an OCTET STRING's secret contents: primitive, then in BER's constructed form (two segments) */
    uint8_t value[64], octets[256];
    fill(value, sizeof value, 77);
    size_t n1 = put_tlv(octets, 0x04, value, sizeof value);
    uint8_t seg[160];
    size_t s = put_tlv(seg, 0x04, value, 32);
    s += put_tlv(seg + s, 0x04, value + 32, 32);
    size_t n2 = put_tlv(octets + n1, 0x24, seg, s);
    secret(octets + 2, sizeof value);                       /* the primitive's contents */
    secret(octets + n1 + 4, 32);                             /* each segment's contents */
    secret(octets + n1 + 4 + 34, 32);
    for (int which = 0; which < 2; which++) {
        httpasm_asn1 str;
        size_t off = which ? n1 : 0, n = which ? n2 : n1;
        int rules = which ? HTTPASM_ASN1_BER : HTTPASM_ASN1_DER;
        expect(httpasm_asn1_read(&str, octets + off, n, rules) == 0, "asn1 octet string", tier);
        expect(httpasm_asn1_octets(&str, scratch, sizeof scratch, rules) == (int64_t)sizeof value, "asn1_octets", tier);
        public(scratch, sizeof scratch);
    }
    public(octets, sizeof octets);
}

/* base64: RFC 4648's encoding of in[0..n) into out, 64 characters a line (RFC 7468's strict
 * form); returns the characters written. */
static size_t base64(const uint8_t *in, size_t n, char *out)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0, line = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
        char q[4] = { alphabet[v >> 18], alphabet[(v >> 12) & 63], i + 1 < n ? alphabet[(v >> 6) & 63] : '=', i + 2 < n ? alphabet[v & 63] : '=' };
        for (int k = 0; k < 4; k++) {
            out[o++] = q[k];
            if (++line == 64) {
                out[o++] = '\n';
                line = 0;
            }
        }
    }
    if (line)
        out[o++] = '\n';
    return o;
}

/* pem_key: label and DER as a PEM text in out; returns its length, *body and *body_length the
 * base64 text's place (the secret part: the boundaries are not). */
static size_t pem_key(const char *label, const uint8_t *der, size_t n, char *out, size_t *body, size_t *body_length)
{
    size_t o = (size_t)sprintf(out, "-----BEGIN %s-----\n", label);
    *body = o;
    o += base64(der, n, out + o);
    *body_length = o - *body;
    o += (size_t)sprintf(out + o, "-----END %s-----\n", label);
    return o;
}

/* keys: httpasm_private_key_load on PEM files whose whole base64 text is secret (so everything
 * decoded from it is too, the structure included: the loader and the reader must mark public
 * what is public by design, and nothing else may steer them): RSA-2048 in PKCS#8 and PKCS#1,
 * P-256 in PKCS#8 and SEC1, P-384 and P-521 in PKCS#8 (scalars below n, the top octet 1),
 * Ed25519 and Ed448 in PKCS#8, and a BER PKCS#8 of the RSA key (indefinite lengths, a
 * constructed privateKey). */
static void keys(const char *tier)
{
    static uint8_t rsakey[2100], body[2200], der[2400], seg[2400];
    static char text[4096];
    static httpasm_private_key key;
    /* RSAPrivateKey from the 2048-bit numbers (d: q's octets stand in; the init ignores d) */
    static const int order[8] = { 0, 1, 3, 2, 3, 4, 5, 6 };
    size_t at = 0;
    uint8_t zero = 0;
    at += put_tlv(body + at, 0x02, &zero, 1);
    for (int i = 0; i < 8; i++) {
        uint8_t raw[256], number[257];
        size_t m = hex_octets(rsa_2048[order[i]], raw);
        size_t off = (raw[0] & 0x80) ? 1 : 0;
        number[0] = 0;
        memcpy(number + off, raw, m);
        at += put_tlv(body + at, 0x02, number, m + off);
    }
    size_t rsa_length = put_tlv(rsakey, 0x30, body, at);
    static const uint8_t rsa_algorithm[] = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
    static const uint8_t version0[] = { 0x02, 0x01, 0x00 };

    typedef struct { const char *label; int kind; size_t n; } key_file;   /* a PEM label, the kind expected, the DER's octets */
    key_file files[8];
    static uint8_t ders[8][2400];
    int count = 0;
    /* RSA, PKCS#8 */
    at = 0;
    memcpy(body + at, version0, 3), at += 3;
    memcpy(body + at, rsa_algorithm, sizeof rsa_algorithm), at += sizeof rsa_algorithm;
    at += put_tlv(body + at, 0x04, rsakey, rsa_length);
    files[count] = (key_file){ "PRIVATE KEY", HTTPASM_KEY_RSA, put_tlv(ders[count], 0x30, body, at) };
        count++;
    /* RSA, PKCS#1 */
    memcpy(ders[count], rsakey, rsa_length);
    files[count] = (key_file){ "RSA PRIVATE KEY", HTTPASM_KEY_RSA, rsa_length };
        count++;
    /* the curves: PKCS#8 with ECPrivateKey (no public key), P-256 also as SEC1 */
    static const struct { int kind; size_t size; uint8_t oid[10]; size_t oid_length; } curves[] = {
        { HTTPASM_KEY_P256, 32, { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 }, 10 },
        { HTTPASM_KEY_P384, 48, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 }, 7 },
        { HTTPASM_KEY_P521, 66, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 }, 7 },
    };
    static const uint8_t ec_oid[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    for (size_t c = 0; c < 3; c++) {
        uint8_t d[512], ec[512], alg[512];   /* (room past need: put_tlv may write 255 + 3) */
        fill(d, curves[c].size, (unsigned)(90 + c));
        d[0] = 1;                                           /* below n */
        size_t e = 0;
        uint8_t one = 1;
        e += put_tlv(ec + e, 0x02, &one, 1);
        e += put_tlv(ec + e, 0x04, d, curves[c].size);
        uint8_t inner[512];
        size_t inner_length = put_tlv(inner, 0x30, ec, e);
        size_t a = 0;
        memcpy(alg + a, ec_oid, sizeof ec_oid), a += sizeof ec_oid;
        memcpy(alg + a, curves[c].oid, curves[c].oid_length), a += curves[c].oid_length;
        at = 0;
        memcpy(body + at, version0, 3), at += 3;
        at += put_tlv(body + at, 0x30, alg, a);
        at += put_tlv(body + at, 0x04, inner, inner_length);
        files[count] = (key_file){ "PRIVATE KEY", curves[c].kind, put_tlv(ders[count], 0x30, body, at) };
        count++;
        if (c == 0) {
            /* SEC1: version, privateKey, [0] the curve */
            uint8_t params[512];
            size_t pl = put_tlv(params, 0xA0, curves[c].oid, curves[c].oid_length);
            memcpy(ec + e, params, pl);
            files[count] = (key_file){ "EC PRIVATE KEY", curves[c].kind, put_tlv(ders[count], 0x30, ec, e + pl) };
        count++;
        }
    }
    /* Ed25519 and Ed448: CurvePrivateKey inside the privateKey OCTET STRING */
    static const struct { int kind; size_t size; uint8_t oid[5]; } edwards[] = {
        { HTTPASM_KEY_ED25519, 32, { 0x06, 0x03, 0x2B, 0x65, 0x70 } },
        { HTTPASM_KEY_ED448, 57, { 0x06, 0x03, 0x2B, 0x65, 0x71 } },
    };
    for (size_t k = 0; k < 2; k++) {
        uint8_t seed[512], curve_key[512], alg[512];   /* (room past need: put_tlv may write 255 + 3) */
        fill(seed, edwards[k].size, (unsigned)(95 + k));
        size_t cl = put_tlv(curve_key, 0x04, seed, edwards[k].size);
        size_t a = put_tlv(alg, 0x30, edwards[k].oid, 5);
        at = 0;
        memcpy(body + at, version0, 3), at += 3;
        memcpy(body + at, alg, a), at += a;
        at += put_tlv(body + at, 0x04, curve_key, cl);
        files[count] = (key_file){ "PRIVATE KEY", edwards[k].kind, put_tlv(ders[count], 0x30, body, at) };
        count++;
    }
    for (int f = 0; f < count; f++) {
        size_t b, bl;
        size_t n = pem_key(files[f].label, ders[f], files[f].n, text, &b, &bl);
        secret(text + b, bl);
        expect(httpasm_private_key_load(&key, (const uint8_t *)text, n) == files[f].kind, "private_key_load (PEM)", tier);
        public(&key, sizeof key);
        public(text, n);
    }

    /* the RSA key in BER's forms: indefinite lengths, a privateKey of 100-octet segments; DER
     * input, its octets all secret */
    size_t s = 0;
    for (size_t i = 0; i < rsa_length; i += 100) {
        size_t piece = rsa_length - i < 100 ? rsa_length - i : 100;
        s += put_tlv(seg + s, 0x04, rsakey + i, piece);
    }
    at = 0;
    der[at++] = 0x30, der[at++] = 0x80;
    memcpy(der + at, version0, 3), at += 3;
    memcpy(der + at, rsa_algorithm, sizeof rsa_algorithm), at += sizeof rsa_algorithm;
    der[at++] = 0x24, der[at++] = 0x80;
    memcpy(der + at, seg, s), at += s;
    der[at++] = 0, der[at++] = 0, der[at++] = 0, der[at++] = 0;
    secret(der, at);
    expect(httpasm_private_key_load(&key, der, at) == HTTPASM_KEY_RSA, "private_key_load (BER)", tier);
    public(&key, sizeof key);
    public(der, at);
}

/* tls13: the key schedule from a secret (EC)DHE output and PSK through every derivation
 * (Extract, Expand-Label, Derive-Secret, Finished, the update, the exporter), and the record
 * layer under a secret traffic secret: keys made, records of secret contents sealed with
 * padding (their wire octets then public), opened back (the content and its length come out:
 * the opener's scan is constant time and its result public by design), and a forged record
 * refused (the verdict public), for each of the three suites. */
static void tls13(const char *tier)
{
    static httpasm_tls13_record_key writer, reader;
    static uint8_t ikm[48], secret_in[48], derived[48], out[64], record[400], content[300];
    static const uint8_t label[] = "c hs traffic", transcript[48] = { 7 };
    for (int hash = HTTPASM_HASH_SHA256; hash <= HTTPASM_HASH_SHA384; hash++) {
        size_t n = hash == HTTPASM_HASH_SHA256 ? 32 : 48;
        fill(ikm, n, (unsigned)hash);
        secret(ikm, n);
        expect(httpasm_tls13_extract(hash, NULL, 0, ikm, n, secret_in) == 0, "tls13_extract", tier);
        expect(httpasm_tls13_extract(hash, NULL, 0, NULL, 0, derived) == 0, "tls13_extract (no IKM)", tier);
        public(derived, n);                             /* (from zeros alone: public) */
        expect(httpasm_tls13_derive_secret(hash, secret_in, label, sizeof label - 1, transcript, derived) == 0,
               "tls13_derive_secret", tier);
        expect(httpasm_tls13_derive_secret(hash, secret_in, (const uint8_t *)"derived", 7, NULL, out) == 0,
               "tls13_derive_secret (derived)", tier);
        expect(httpasm_tls13_expand_label(hash, derived, (const uint8_t *)"key", 3, NULL, 0, out, 32) == 0,
               "tls13_expand_label", tier);
        expect(httpasm_tls13_finished(hash, derived, transcript, out) == 0, "tls13_finished", tier);
        public(out, n);                                 /* verify_data goes on the wire */
        expect(httpasm_tls13_update_secret(hash, derived, out) == 0, "tls13_update_secret", tier);
        expect(httpasm_tls13_export(hash, derived, (const uint8_t *)"EXPORTER-ct", 11, transcript, 10, out, 64) == 0,
               "tls13_export", tier);
        public(out, sizeof out);
        public(secret_in, n);
        public(derived, n);
    }
    static const int suites[] = { HTTPASM_TLS_AES_128_GCM_SHA256, HTTPASM_TLS_AES_256_GCM_SHA384,
                                  HTTPASM_TLS_CHACHA20_POLY1305_SHA256 };
    for (size_t s = 0; s < 3; s++) {
        fill(secret_in, sizeof secret_in, 900 + (unsigned)s);
        secret(secret_in, sizeof secret_in);
        expect(httpasm_tls13_record_key_init(&writer, suites[s], secret_in) == 0, "tls13_record_key_init", tier);
        expect(httpasm_tls13_record_key_init(&reader, suites[s], secret_in) == 0, "tls13_record_key_init", tier);
        for (size_t len = 0; len <= 300; len += 100) {
            fill(content, len, 1000 + (unsigned)len);
            secret(content, len);
            int64_t sealed = httpasm_tls13_seal(&writer, HTTPASM_TLS_CONTENT_APPLICATION_DATA, content, len, 7, record, sizeof record);
            expect(sealed == (int64_t)(5 + len + 1 + 7 + 16), "tls13_seal", tier);
            public(record, sizeof record);              /* the record goes on the wire */
            uint8_t type = 0;
            int64_t opened = httpasm_tls13_open(&reader, record, (size_t)sealed, &type);
            expect(opened == (int64_t)len, "tls13_open", tier);
            public(record, sizeof record);              /* the content, delivered */
            public(&type, 1);
        }
        expect(httpasm_tls13_seal(&writer, HTTPASM_TLS_CONTENT_HANDSHAKE, content, 50, 0, record, sizeof record) > 0, "tls13_seal", tier);
        public(record, sizeof record);
        record[20] ^= 1;
        uint8_t type = 0;
        expect(httpasm_tls13_open(&reader, record, 5 + 50 + 1 + 16, &type) == -HTTPASM_TLS_ALERT_BAD_RECORD_MAC,
               "tls13_open (forged)", tier);
        public(record, sizeof record);
        public(&writer, sizeof writer);
        public(&reader, sizeof reader);
        public(secret_in, sizeof secret_in);
    }
}

/* ---- the engine: whole TLS 1.3 handshakes through the server engine -------------------------
 * A server connection's secrets: its key's private numbers (the key loaded from a PEM text whose
 * base64 is secret, as keys() loads one, then used as the loader left it), every octet its random
 * source draws (ct_draw marks each draw secret: the ephemeral keys, ML-KEM's message, the
 * signatures' salts and hedging - and the server random and a post-handshake request's context
 * too, which the engine itself must publish), everything derived from them (shared secrets,
 * traffic secrets, record keys), and application data (secret when the server sends it; opened
 * under a secret key when it receives it). What the engine publishes by design, each at its site
 * with its reason (HA_DECLASSIFY_MEM): the handshake messages it sends, once built (their octets
 * go to the peer and into the transcript); the handshake messages and alerts it receives, once
 * opened (it parses and acts on them); an opened record's content type and length
 * (tls/record.asm); an ECDSA signature's r and s before their DER (tls/sign.asm). Nothing else
 * of a secret may steer a branch, an address or a system call, down every path a secret takes:
 * each group's key exchange (ffdhe2048 for the five FFDHE groups, which share their code), each
 * kind of server key's CertificateVerify, the three suites, a HelloRetryRequest, middlebox
 * compatibility's change_cipher_spec, client authentication in the handshake (with a key, and
 * declined) and after it (answered, and declined), KeyUpdates both ways, application data both
 * ways, close_notify both ways, a forged Finished and a forged record.
 * The client is this file's own, built from the library's primitives (key shares, the key
 * schedule, the record layer, signatures): just enough TLS 1.3 to take the server down those
 * paths. Its own secrets are not marked (it is not under test), and it reads the server's output
 * only after marking it public (those octets are on the wire), so memcheck's reports can come
 * from the server's side only. */

#define CT_TLS_BUFFER 32768                     /* a transcript's, a flight's, a hello's room */
#define CT_NONE (-1)                            /* ct_scenario: no client key, no request */

/* The key kinds a server signs with, in ct_keys. */
enum { CK_RSA, CK_RSA_PSS, CK_P256, CK_P384, CK_P521, CK_ED25519, CK_ED448, CK_COUNT };

/* ct_key: a key of one kind: its PKCS#8 file (DER), a certificate of its public key, the scheme
 * it signs with here, and the same key prepared for this file's client, whose client
 * authentication signs with it. Built once (ct_key_files); the server's copies are loaded from
 * the files at each tier (ct_server_keys), secret. */
typedef struct {
    int kind;                                   /* HTTPASM_KEY_* */
    uint16_t scheme;                            /* the SignatureScheme (the client offers only it) */
    uint8_t der[2400];
    size_t der_length;
    uint8_t certificate[1600];
    size_t certificate_length;
    uint8_t scalar[66];                         /* a curve key's d, the curve's octets */
    httpasm_ed25519_private_key ed25519;
    httpasm_ed448_private_key ed448;
    httpasm_rsa_private_key rsa;
} ct_key;

static ct_key ct_keys[CK_COUNT];
static httpasm_private_key ct_server_keys[CK_COUNT];

/* ct_name: a Name of one attribute (CN "ct"), the certificates' issuer and subject. */
static const uint8_t ct_name[] = { 0x30, 0x0D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x02, 'c', 't' };

/* ct_certificate: a v1 certificate (RFC 5280 4.1: no version field, so no extensions) of a
 * subjectPublicKeyInfo, signed by nobody: its signature 64 zero octets under Ed25519's
 * identifier. The engine reads its own chain's structure and key only, and the client's leaf
 * likewise (chain validation is M3's), so nothing verifies it.
 *   spki, n  the subjectPublicKeyInfo's DER; out  1600 octets of room.
 * Returns the certificate's octets. */
static size_t ct_certificate(const uint8_t *spki, size_t n, uint8_t *out)
{
    static const uint8_t algorithm[] = { 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70 };
    static const uint8_t validity[] = {
        0x30, 0x1E, 0x17, 0x0D, '2', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
        0x17, 0x0D, '3', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
    };
    uint8_t tbs[1500], body[1600], signature[65] = { 0 };   /* (0 unused bits, then the zeros) */
    size_t t = 0;
    tbs[t++] = 0x02, tbs[t++] = 0x01, tbs[t++] = 0x01;      /* serialNumber 1 */
    memcpy(tbs + t, algorithm, sizeof algorithm), t += sizeof algorithm;
    memcpy(tbs + t, ct_name, sizeof ct_name), t += sizeof ct_name;
    memcpy(tbs + t, validity, sizeof validity), t += sizeof validity;
    memcpy(tbs + t, ct_name, sizeof ct_name), t += sizeof ct_name;
    memcpy(tbs + t, spki, n), t += n;
    size_t b = put_tlv(body, 0x30, tbs, t);
    memcpy(body + b, algorithm, sizeof algorithm), b += sizeof algorithm;
    b += put_tlv(body + b, 0x03, signature, sizeof signature);
    return put_tlv(out, 0x30, body, b);
}

/* ct_integer: a non-negative INTEGER of a big-endian value at out (a 0 octet first when its top
 * bit is set; leading zeros kept off but one), as DER writes RSA's numbers and ECDSA's r and s.
 *   v, m  the value's octets (at most 299); out  258 octets of room at least (put_tlv's bound).
 * Returns the element's octets. */
static size_t ct_integer(const uint8_t *v, size_t m, uint8_t *out)
{
    uint8_t number[300];
    while (m > 1 && v[0] == 0)
        v++, m--;
    size_t pad = (v[0] & 0x80) ? 1 : 0;
    number[0] = 0;
    memcpy(number + pad, v, m);
    return put_tlv(out, 0x02, number, m + pad);
}

/* ct_key_files: ct_keys, each as a PKCS#8 file, a certificate and the client's prepared key: the
 * RSA keys from the 2048-bit numbers above (rsaEncryption, then id-RSASSA-PSS without
 * parameters: PSS signatures only); P-256, P-384 and P-521 with scalars below n (the top octet 1)
 * and their public keys in the files (ECPrivateKey's [1] publicKey, which the loader compares
 * with the d G it computes); Ed25519 as OneAsymmetricKey v2 (its publicKey [1], compared
 * likewise) and Ed448 as v1. Built from public octets: the secrecy is the server's loading's.
 * Returns 0, or 1 with the reason printed. */
static int ct_key_files(void)
{
    static const uint8_t version0[] = { 0x02, 0x01, 0x00 };
    static uint8_t body[2400], inner[2400], spki[1700], bits[512], numbers[7][257];
    size_t at, lengths[7];
    for (int i = 0; i < 7; i++)
        lengths[i] = hex_octets(rsa_2048[i], numbers[i]);
    /* RSA: RSAPrivateKey { 0, n, e, d (q's octets stand in: the loader ignores d), p, q, dp, dq,
     * qinv }, RSAPublicKey { n, e }; the two algorithms */
    static const int order[8] = { 0, 1, 3, 2, 3, 4, 5, 6 };
    static uint8_t rsakey[2100], rsapub[600];
    at = 0;
    uint8_t zero = 0;
    at += put_tlv(body + at, 0x02, &zero, 1);
    for (int i = 0; i < 8; i++)
        at += ct_integer(numbers[order[i]], lengths[order[i]], body + at);
    size_t rsa_length = put_tlv(rsakey, 0x30, body, at);
    at = ct_integer(numbers[0], lengths[0], body);
    at += ct_integer(numbers[1], lengths[1], body + at);
    size_t pub_length = put_tlv(rsapub + 1, 0x30, body, at) + 1;
    rsapub[0] = 0;                                          /* the BIT STRING's unused bits */
    static const uint8_t rsa_algorithms[2][15] = {
        { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 },
        { 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A },
    };
    httpasm_rsa_private_numbers prepared = {
        numbers[0], lengths[0], numbers[1], lengths[1], numbers[2], lengths[2], numbers[3], lengths[3],
        numbers[4], lengths[4], numbers[5], lengths[5], numbers[6], lengths[6],
    };
    for (int r = 0; r < 2; r++) {
        ct_key *k = &ct_keys[r == 0 ? CK_RSA : CK_RSA_PSS];
        size_t algorithm_length = r == 0 ? 15 : 13;
        k->kind = r == 0 ? HTTPASM_KEY_RSA : HTTPASM_KEY_RSA_PSS;
        k->scheme = r == 0 ? HTTPASM_TLS_SCHEME_RSA_PSS_RSAE_SHA256 : HTTPASM_TLS_SCHEME_RSA_PSS_PSS_SHA256;
        at = 0;
        memcpy(body + at, version0, 3), at += 3;
        memcpy(body + at, rsa_algorithms[r], algorithm_length), at += algorithm_length;
        at += put_tlv(body + at, 0x04, rsakey, rsa_length);
        k->der_length = put_tlv(k->der, 0x30, body, at);
        at = 0;
        memcpy(body + at, rsa_algorithms[r], algorithm_length), at += algorithm_length;
        at += put_tlv(body + at, 0x03, rsapub, pub_length);
        k->certificate_length = ct_certificate(spki, put_tlv(spki, 0x30, body, at), k->certificate);
        if (httpasm_rsa_private_key_init(&k->rsa, &prepared) != 0) {
            fprintf(stderr, "ct: the engine's RSA key did not prepare\n");
            return 1;
        }
    }
    /* the curves: PKCS#8 { 0, { id-ecPublicKey, the curve }, ECPrivateKey { 1, d, [1] point } } */
    static const struct { int index, kind; size_t size; uint8_t oid[10]; size_t oid_length; uint16_t scheme; } curves[3] = {
        { CK_P256, HTTPASM_KEY_P256, 32, { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 }, 10,
          HTTPASM_TLS_SCHEME_ECDSA_SECP256R1_SHA256 },
        { CK_P384, HTTPASM_KEY_P384, 48, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 }, 7, HTTPASM_TLS_SCHEME_ECDSA_SECP384R1_SHA384 },
        { CK_P521, HTTPASM_KEY_P521, 66, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 }, 7, HTTPASM_TLS_SCHEME_ECDSA_SECP521R1_SHA512 },
    };
    static const uint8_t ec_oid[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    for (size_t c = 0; c < 3; c++) {
        ct_key *k = &ct_keys[curves[c].index];
        size_t size = curves[c].size;
        k->kind = curves[c].kind;
        k->scheme = curves[c].scheme;
        fill(k->scalar, size, (unsigned)(600 + c));
        k->scalar[0] = 1;                                   /* below n */
        uint8_t point[133];
        int made = size == 32 ? httpasm_p256_public_key(point, k->scalar)
                 : size == 48 ? httpasm_p384_public_key(point, k->scalar) : httpasm_p521_public_key(point, k->scalar);
        if (made != 0) {
            fprintf(stderr, "ct: the engine's curve key %zu made no public key\n", c);
            return 1;
        }
        bits[0] = 0;
        memcpy(bits + 1, point, 2 * size + 1);
        uint8_t bit_string[512], ec[512], algorithm[512], alg[512];   /* (room past need: put_tlv may write 255 + 3) */
        size_t bl = put_tlv(bit_string, 0x03, bits, 2 * size + 2), e = 0;
        uint8_t one = 1;
        e += put_tlv(ec + e, 0x02, &one, 1);
        e += put_tlv(ec + e, 0x04, k->scalar, size);
        e += put_tlv(ec + e, 0xA1, bit_string, bl);
        size_t il = put_tlv(inner, 0x30, ec, e), a = 0;
        memcpy(alg + a, ec_oid, sizeof ec_oid), a += sizeof ec_oid;
        memcpy(alg + a, curves[c].oid, curves[c].oid_length), a += curves[c].oid_length;
        size_t al = put_tlv(algorithm, 0x30, alg, a);
        at = 0;
        memcpy(body + at, version0, 3), at += 3;
        memcpy(body + at, algorithm, al), at += al;
        at += put_tlv(body + at, 0x04, inner, il);
        k->der_length = put_tlv(k->der, 0x30, body, at);
        at = 0;
        memcpy(body + at, algorithm, al), at += al;
        memcpy(body + at, bit_string, bl), at += bl;
        k->certificate_length = ct_certificate(spki, put_tlv(spki, 0x30, body, at), k->certificate);
    }
    /* the Edwards keys: PKCS#8 { version, { the OID }, OCTET STRING { OCTET STRING seed } [, [1]
     * publicKey] } */
    static const struct { int index, kind; size_t size; uint8_t oid; uint16_t scheme; int v2; } edwards_keys[2] = {
        { CK_ED25519, HTTPASM_KEY_ED25519, 32, 0x70, HTTPASM_TLS_SCHEME_ED25519, 1 },
        { CK_ED448, HTTPASM_KEY_ED448, 57, 0x71, HTTPASM_TLS_SCHEME_ED448, 0 },
    };
    for (size_t d = 0; d < 2; d++) {
        ct_key *k = &ct_keys[edwards_keys[d].index];
        size_t size = edwards_keys[d].size;
        uint8_t seed[57], pub[57], curve_key[512];   /* (room past need: put_tlv may write 255 + 3) */
        k->kind = edwards_keys[d].kind;
        k->scheme = edwards_keys[d].scheme;
        fill(seed, size, (unsigned)(700 + d));
        if (size == 32) {
            httpasm_ed25519_public_key(pub, seed);
            httpasm_ed25519_private_key_init(&k->ed25519, seed);
        } else {
            httpasm_ed448_public_key(pub, seed);
            httpasm_ed448_private_key_init(&k->ed448, seed);
        }
        const uint8_t algorithm[7] = { 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, edwards_keys[d].oid };
        const uint8_t version[3] = { 0x02, 0x01, (uint8_t)edwards_keys[d].v2 };
        size_t cl = put_tlv(curve_key, 0x04, seed, size);
        bits[0] = 0;
        memcpy(bits + 1, pub, size);
        at = 0;
        memcpy(body + at, version, 3), at += 3;
        memcpy(body + at, algorithm, 7), at += 7;
        at += put_tlv(body + at, 0x04, curve_key, cl);
        if (edwards_keys[d].v2)
            at += put_tlv(body + at, 0x81, bits, size + 1);  /* [1] IMPLICIT BIT STRING */
        k->der_length = put_tlv(k->der, 0x30, body, at);
        at = 0;
        memcpy(body + at, algorithm, 7), at += 7;
        at += put_tlv(body + at, 0x03, bits, size + 1);
        k->certificate_length = ct_certificate(spki, put_tlv(spki, 0x30, body, at), k->certificate);
    }
    return 0;
}

/* A handshake to run: the client's offer, the server's configuration, what the client answers. */
typedef struct {
    const char *name;
    uint16_t suite;                             /* the client's only cipher suite */
    uint16_t share;                             /* the group of its first key share */
    uint16_t groups[2];                         /* its supported_groups (0: share's alone) */
    int server_key;                             /* CK_*: the server's key */
    uint32_t flags;                             /* the configuration's (HTTPASM_TLS_CLIENT_AUTH_*, _SERVER_GROUP_ORDER) */
    uint16_t server_groups[2];                  /* the configuration's groups (0: the library's) */
    int client_key;                             /* CK_* for the handshake's request; CT_NONE: an empty Certificate */
    int post_key;                               /* CK_* for a post-handshake request (a second one
                                                 * is then declined); CT_NONE: no request */
    int compat;                                 /* a legacy_session_id (the server's change_cipher_spec, E.4) */
    int forge;                                  /* CT_FORGE_* */
} ct_scenario;

enum { CT_FORGE_NOTHING, CT_FORGE_FINISHED, CT_FORGE_RECORD };

/* ct_client: this file's TLS 1.3 client, one connection's state (see above). */
typedef struct {
    const ct_scenario *s;
    int hash;                                   /* the suite's hash: HTTPASM_HASH_SHA256 or _SHA384 */
    size_t hash_length;
    uint16_t group;                             /* the group of the share last sent */
    uint8_t transcript[CT_TLS_BUFFER];          /* the handshake's messages so far, whole */
    size_t transcript_length;
    size_t base_length;                         /* through our Finished: post-handshake exchanges start there (4.4) */
    uint8_t scalar[66];                         /* our (EC)DH private part */
    uint8_t exponent[32];                       /* FFDHE's */
    uint8_t ek[HTTPASM_MLKEM1024_EK], dk[HTTPASM_MLKEM1024_DK];
    uint8_t share[HTTPASM_MLKEM1024_EK + 133];
    size_t share_length;
    uint8_t handshake_secret[48], client_hs[48], server_hs[48], read_secret[48], write_secret[48];
    httpasm_tls13_record_key read, write;
    int keyed;                                  /* the server's records are protected from here */
    int requested;                              /* the handshake's CertificateRequest came */
    int finished;                               /* the server's Finished came (ours is queued) */
    int answers;                                /* post-handshake requests answered */
    int key_updates;                            /* the server's KeyUpdates read */
    int alert;                                  /* the server's alert (-1: none) */
    const char *broken;                         /* what went wrong on the client's side (NULL: nothing) */
    uint8_t pending[CT_TLS_BUFFER];             /* handshake octets read, not yet a whole message */
    size_t pending_length;
    uint8_t data[4096];                         /* application data received */
    size_t data_length;
    uint8_t out[CT_TLS_BUFFER];                 /* records for the server */
    size_t out_length;
} ct_client;

static ct_client ct_the_client;
static httpasm_tls13_server_config ct_config;
static uint8_t ct_certificate_message[4096], ct_memory[160 * 1024];
static httpasm_tls13_connection ct_connection;
static unsigned ct_draws;

/* ct_draw: the server's random source: fill's octets (each draw seeded by a counter, so every
 * tier draws the same), every one of them secret until the engine publishes it. A draw never
 * fails here: the engine's refusals of a failing source are the .NET tests' (FailAt).
 *   context  unused; out, length  where the octets go. Returns 0. */
static int ct_draw(void *context, uint8_t *out, size_t length)
{
    (void)context;
    fill(out, length, 5000 + ct_draws++);
    secret(out, length);
    return 0;
}

/* ct_u16, ct_u24: v's low 16 or 24 bits as big-endian octets at p (TLS's uint16 and uint24
 * lengths; a larger v is cut, which no caller here makes).
 *   p  2 or 3 octets of room; v  the value. */
static void ct_u16(uint8_t *p, size_t v)
{
    p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v;
}

static void ct_u24(uint8_t *p, size_t v)
{
    p[0] = (uint8_t)(v >> 16), p[1] = (uint8_t)(v >> 8), p[2] = (uint8_t)v;
}

/* ct_hash: data hashed with the suite's hash (the client hashes its whole transcript each time:
 * simpler than running hashes, and the client's cost is not under test).
 *   cl  the client (its hash); data, n  the octets; out  cl->hash_length octets of room. */
static void ct_hash(const ct_client *cl, const uint8_t *data, size_t n, uint8_t *out)
{
    if (cl->hash == HTTPASM_HASH_SHA384)
        httpasm_sha384(data, n, out);
    else
        httpasm_sha256(data, n, out);
}

/* ct_add: a whole handshake message appended to the client's transcript; one past its room
 * breaks the client (cl->broken) instead of writing past it.
 *   cl  the client; m, n  the message, its header included. */
static void ct_add(ct_client *cl, const uint8_t *m, size_t n)
{
    if (cl->transcript_length + n > sizeof cl->transcript) {
        cl->broken = "the transcript outgrew its room";
        return;
    }
    memcpy(cl->transcript + cl->transcript_length, m, n);
    cl->transcript_length += n;
}

/* ct_seal: one record sealed under the client's current write key (no padding) and appended to
 * its output for the server; a refusal (no room, a content too long) breaks the client.
 *   cl  the client; type  the inner content type; content, n  the content (2^14 at most). */
static void ct_seal(ct_client *cl, int type, const uint8_t *content, size_t n)
{
    int64_t r = httpasm_tls13_seal(&cl->write, type, content, n, 0, cl->out + cl->out_length,
                                   sizeof cl->out - cl->out_length);
    if (r < 0) {
        cl->broken = "the client's seal refused a record";
        return;
    }
    cl->out_length += (size_t)r;
}

/* ct_share: the client's private part for a group (fill's octets, fixed by the group; a curve's
 * scalar's top bits cleared so it lies below n) and its key_exchange (4.2.8.2, 4.2.8.1; the
 * hybrids' concatenations, RFC 10024: X25519MLKEM768's ML-KEM first, the SecP ones' ECDH
 * first), kept in cl->share; a group it lacks breaks the client.
 *   cl  the client; group  the NamedGroup. */
static void ct_share(ct_client *cl, uint16_t group)
{
    uint8_t seed[HTTPASM_MLKEM_SEED];
    fill(seed, sizeof seed, 910u + group);
    cl->group = group;
    switch (group) {
    case HTTPASM_TLS_GROUP_X25519:
        fill(cl->scalar, 32, 900);
        httpasm_x25519_public_key(cl->share, cl->scalar);
        cl->share_length = 32;
        break;
    case HTTPASM_TLS_GROUP_X448:
        fill(cl->scalar, 56, 901);
        httpasm_x448_public_key(cl->share, cl->scalar);
        cl->share_length = 56;
        break;
    case HTTPASM_TLS_GROUP_SECP256R1:
    case HTTPASM_TLS_GROUP_SECP256R1MLKEM768:
        fill(cl->scalar, 32, 902);
        cl->scalar[0] &= 0x7F;                              /* below n */
        httpasm_p256_public_key(cl->share, cl->scalar);
        cl->share_length = 65;
        if (group == HTTPASM_TLS_GROUP_SECP256R1MLKEM768) {
            httpasm_mlkem768_keypair(cl->ek, cl->dk, seed);
            memcpy(cl->share + 65, cl->ek, HTTPASM_MLKEM768_EK);
            cl->share_length += HTTPASM_MLKEM768_EK;
        }
        break;
    case HTTPASM_TLS_GROUP_SECP384R1:
    case HTTPASM_TLS_GROUP_SECP384R1MLKEM1024:
        fill(cl->scalar, 48, 903);
        cl->scalar[0] &= 0x7F;
        httpasm_p384_public_key(cl->share, cl->scalar);
        cl->share_length = 97;
        if (group == HTTPASM_TLS_GROUP_SECP384R1MLKEM1024) {
            httpasm_mlkem1024_keypair(cl->ek, cl->dk, seed);
            memcpy(cl->share + 97, cl->ek, HTTPASM_MLKEM1024_EK);
            cl->share_length += HTTPASM_MLKEM1024_EK;
        }
        break;
    case HTTPASM_TLS_GROUP_SECP521R1:
        fill(cl->scalar, 66, 904);
        cl->scalar[0] = 0;                                  /* below n */
        httpasm_p521_public_key(cl->share, cl->scalar);
        cl->share_length = 133;
        break;
    case HTTPASM_TLS_GROUP_FFDHE2048:
        fill(cl->exponent, sizeof cl->exponent, 905);
        httpasm_ffdhe_public_key(HTTPASM_FFDHE2048, cl->share, cl->exponent, sizeof cl->exponent);
        cl->share_length = 256;
        break;
    case HTTPASM_TLS_GROUP_X25519MLKEM768:
        httpasm_mlkem768_keypair(cl->ek, cl->dk, seed);
        memcpy(cl->share, cl->ek, HTTPASM_MLKEM768_EK);
        fill(cl->scalar, 32, 906);
        httpasm_x25519_public_key(cl->share + HTTPASM_MLKEM768_EK, cl->scalar);
        cl->share_length = HTTPASM_MLKEM768_EK + 32;
        break;
    default:
        cl->broken = "a group the client lacks";
    }
}

/* ct_shared: the shared secret of the client's share and the server's key_exchange (its length
 * checked against the group's; the hybrids' secrets concatenated in their shares' order).
 *   cl  the client (its group and private parts); share, n  the server's key_exchange; out
 *   1100 octets of room (ffdhe2048's 256 at most here). Returns the secret's octets, or 0 with
 *   cl->broken set (a wrong length, or a primitive's refusal). */
static size_t ct_shared(ct_client *cl, const uint8_t *share, size_t n, uint8_t *out)
{
    int ok = -1;
    size_t length = 0;
    switch (cl->group) {
    case HTTPASM_TLS_GROUP_X25519:
        ok = n == 32 ? httpasm_x25519(out, cl->scalar, share) : -1, length = 32;
        break;
    case HTTPASM_TLS_GROUP_X448:
        ok = n == 56 ? httpasm_x448(out, cl->scalar, share) : -1, length = 56;
        break;
    case HTTPASM_TLS_GROUP_SECP256R1:
        ok = n == 65 ? httpasm_p256_ecdh(out, cl->scalar, share) : -1, length = 32;
        break;
    case HTTPASM_TLS_GROUP_SECP384R1:
        ok = n == 97 ? httpasm_p384_ecdh(out, cl->scalar, share) : -1, length = 48;
        break;
    case HTTPASM_TLS_GROUP_SECP521R1:
        ok = n == 133 ? httpasm_p521_ecdh(out, cl->scalar, share) : -1, length = 66;
        break;
    case HTTPASM_TLS_GROUP_FFDHE2048:
        ok = n == 256 ? httpasm_ffdhe_shared(HTTPASM_FFDHE2048, out, cl->exponent, sizeof cl->exponent, share) : -1;
        length = 256;
        break;
    case HTTPASM_TLS_GROUP_X25519MLKEM768:
        if (n == HTTPASM_MLKEM768_CT + 32 && httpasm_mlkem768_decaps(out, cl->dk, share) == 0)
            ok = httpasm_x25519(out + 32, cl->scalar, share + HTTPASM_MLKEM768_CT);
        length = 64;
        break;
    case HTTPASM_TLS_GROUP_SECP256R1MLKEM768:
        if (n == 65 + HTTPASM_MLKEM768_CT && httpasm_p256_ecdh(out, cl->scalar, share) == 0)
            ok = httpasm_mlkem768_decaps(out + 32, cl->dk, share + 65);
        length = 64;
        break;
    case HTTPASM_TLS_GROUP_SECP384R1MLKEM1024:
        if (n == 97 + HTTPASM_MLKEM1024_CT && httpasm_p384_ecdh(out, cl->scalar, share) == 0)
            ok = httpasm_mlkem1024_decaps(out + 48, cl->dk, share + 97);
        length = 80;
        break;
    }
    if (ok != 0) {
        cl->broken = "the server's share made no secret";
        return 0;
    }
    return length;
}

/* ct_hello: the client's ClientHello for a share in `group` (the first one, or the second after a
 * HelloRetryRequest: the same octets but the share, 4.1.2), into the transcript and the output as
 * one plaintext record: TLS 1.3 only, the scenario's suite, its groups, the server key's scheme
 * alone (so the server's choice is known), the share, post_handshake_auth when a post-handshake
 * request is to come, and a legacy_session_id under middlebox compatibility.
 *   cl  the client (its scenario); group  the NamedGroup of its one share. */
static void ct_hello(ct_client *cl, uint16_t group)
{
    const ct_scenario *s = cl->s;
    static uint8_t m[4096];
    ct_share(cl, group);
    size_t at = 4;
    m[at++] = 3, m[at++] = 3;
    fill(m + at, 32, 800), at += 32;                        /* random */
    m[at++] = s->compat ? 32 : 0;
    if (s->compat)
        fill(m + at, 32, 801), at += 32;
    ct_u16(m + at, 2), ct_u16(m + at + 2, s->suite), at += 4;
    m[at++] = 1, m[at++] = 0;                               /* compression: null */
    size_t extensions = at;
    at += 2;
    static const uint8_t versions[] = { 0, 43, 0, 3, 2, 3, 4 };
    memcpy(m + at, versions, sizeof versions), at += sizeof versions;
    size_t count = s->groups[1] ? 2 : 1;
    ct_u16(m + at, 10), ct_u16(m + at + 2, 2 + 2 * count), ct_u16(m + at + 4, 2 * count), at += 6;
    for (size_t g = 0; g < count; g++)
        ct_u16(m + at, s->groups[0] ? s->groups[g] : s->share), at += 2;
    ct_u16(m + at, 13), ct_u16(m + at + 2, 4), ct_u16(m + at + 4, 2), ct_u16(m + at + 6, ct_keys[s->server_key].scheme), at += 8;
    ct_u16(m + at, 51), ct_u16(m + at + 2, 2 + 4 + cl->share_length), ct_u16(m + at + 4, 4 + cl->share_length);
    ct_u16(m + at + 6, group), ct_u16(m + at + 8, cl->share_length), at += 10;
    memcpy(m + at, cl->share, cl->share_length), at += cl->share_length;
    if (s->post_key != CT_NONE)
        ct_u16(m + at, 49), ct_u16(m + at + 2, 0), at += 4;   /* post_handshake_auth */
    ct_u16(m + extensions, at - extensions - 2);
    m[0] = HTTPASM_TLS_CLIENT_HELLO;
    ct_u24(m + 1, at - 4);
    ct_add(cl, m, at);
    uint8_t *r = cl->out + cl->out_length;
    r[0] = HTTPASM_TLS_CONTENT_HANDSHAKE, r[1] = 3, r[2] = 1;
    ct_u16(r + 3, at);
    memcpy(r + 5, m, at);
    cl->out_length += 5 + at;
}

/* ct_extension: a ServerHello's (or HelloRetryRequest's) extension, found by walking the fixed
 * fields then the extensions block (bounds checked: a short message finds nothing).
 *   m, n  the message, its header included; type  the ExtensionType; length  its data's octets
 *   when found. Returns its extension_data, or NULL when absent. */
static const uint8_t *ct_extension(const uint8_t *m, size_t n, unsigned type, size_t *length)
{
    size_t at = 4 + 2 + 32;
    if (at >= n)
        return NULL;
    at += 1 + m[at] + 2 + 1;                                /* session id echo, suite, compression */
    if (at + 2 > n)
        return NULL;
    size_t end = at + 2 + ((size_t)m[at] << 8 | m[at + 1]);
    at += 2;
    while (at + 4 <= end && end <= n) {
        unsigned t = (unsigned)m[at] << 8 | m[at + 1];
        size_t l = (size_t)m[at + 2] << 8 | m[at + 3];
        if (t == type) {
            *length = l;
            return m + at + 4;
        }
        at += 4 + l;
    }
    return NULL;
}

/* ct_derive: Derive-Secret (7.1) with the suite's hash; a refusal breaks the client.
 *   cl  the client; secret_in  the secret (hash_length octets); label  without "tls13 "; h  the
 *   transcript hash, or NULL for the hash of no messages; out  hash_length octets of room. */
static void ct_derive(ct_client *cl, const uint8_t *secret_in, const char *label, const uint8_t *h, uint8_t *out)
{
    if (httpasm_tls13_derive_secret(cl->hash, secret_in, (const uint8_t *)label, strlen(label), h, out) != 0)
        cl->broken = "Derive-Secret refused";
}

/* ct_sign: a CertificateVerify's content signed with one of ct_keys under its scheme: EdDSA over
 * the content itself, ECDSA (r || s, then DER's ECDSA-Sig-Value) and RSA-PSS (SHA-256, a salt of
 * its length) over its digest; the entropy and salt are fill's (the client's are not secret).
 *   k  CK_*; content, n  what is signed; out  512 octets of room. Returns the signature's
 *   octets, or 0 when the signer refused. */
static size_t ct_sign(int k, const uint8_t *content, size_t n, uint8_t *out)
{
    const ct_key *key = &ct_keys[k];
    uint8_t digest[64], raw[132], entropy[66], body[512];   /* (room past need: put_tlv may write 255 + 3) */
    fill(entropy, sizeof entropy, 990);
    size_t size = 0;
    switch (key->kind) {
    case HTTPASM_KEY_ED25519:
        httpasm_ed25519_sign(out, &key->ed25519, content, n);
        return 64;
    case HTTPASM_KEY_ED448:
        return httpasm_ed448_sign(out, &key->ed448, content, n, NULL, 0) == 0 ? 114 : 0;
    case HTTPASM_KEY_RSA:
    case HTTPASM_KEY_RSA_PSS:
        httpasm_sha256(content, n, digest);
        return httpasm_rsa_sign_pss(&key->rsa, HTTPASM_HASH_SHA256, digest, entropy, 32, out, 256) == 0 ? 256 : 0;
    case HTTPASM_KEY_P256:
        httpasm_sha256(content, n, digest);
        if (httpasm_p256_sign(raw, key->scalar, digest, 32, entropy) != 0)
            return 0;
        size = 32;
        break;
    case HTTPASM_KEY_P384:
        httpasm_sha384(content, n, digest);
        if (httpasm_p384_sign(raw, key->scalar, digest, 48, entropy) != 0)
            return 0;
        size = 48;
        break;
    case HTTPASM_KEY_P521:
        httpasm_sha512(content, n, digest);
        entropy[0] &= 1;
        if (httpasm_p521_sign(raw, key->scalar, digest, 64, entropy) != 0)
            return 0;
        size = 66;
        break;
    default:
        return 0;
    }
    size_t b = ct_integer(raw, size, body);
    b += ct_integer(raw + size, size, body + b);
    return put_tlv(out, 0x30, body, b);
}

/* ct_authenticate: the client's Certificate (the request's context; the key's certificate, or an
 * empty list for CT_NONE: declined) and, with a key, its CertificateVerify over the transcript
 * through that Certificate (4.4.3), each into the transcript and sealed under the current write
 * key (the handshake's, or after it the application's).
 *   cl  the client; key  CK_* or CT_NONE; context, context_length  the request's context (NULL
 *   and 0 for the handshake's). */
static void ct_authenticate(ct_client *cl, int key, const uint8_t *context, size_t context_length)
{
    static uint8_t m[4096];
    size_t at = 4;
    m[at++] = (uint8_t)context_length;
    memcpy(m + at, context, context_length), at += context_length;
    if (key == CT_NONE) {
        ct_u24(m + at, 0), at += 3;
    } else {
        size_t n = ct_keys[key].certificate_length;
        ct_u24(m + at, 3 + n + 2), ct_u24(m + at + 3, n), at += 6;
        memcpy(m + at, ct_keys[key].certificate, n), at += n;
        ct_u16(m + at, 0), at += 2;                         /* the entry's extensions: none */
    }
    m[0] = 11;
    ct_u24(m + 1, at - 4);
    ct_add(cl, m, at);
    ct_seal(cl, HTTPASM_TLS_CONTENT_HANDSHAKE, m, at);
    if (key == CT_NONE)
        return;
    uint8_t content[64 + 34 + 48];
    memset(content, 0x20, 64);
    memcpy(content + 64, "TLS 1.3, client CertificateVerify", 34);   /* (its 0 octet too) */
    ct_hash(cl, cl->transcript, cl->transcript_length, content + 98);
    size_t signature = ct_sign(key, content, 98 + cl->hash_length, m + 8);
    if (signature == 0) {
        cl->broken = "the client's key did not sign";
        return;
    }
    m[0] = 15;
    ct_u24(m + 1, 4 + signature);
    ct_u16(m + 4, ct_keys[key].scheme);
    ct_u16(m + 6, signature);
    ct_add(cl, m, 8 + signature);
    ct_seal(cl, HTTPASM_TLS_CONTENT_HANDSHAKE, m, 8 + signature);
}

/* ct_finished: the client's Finished over its transcript, into the transcript and sealed.
 *   cl  the client; base  the Base Key (4.4: its handshake traffic secret, or after the handshake
 *   its current application one); forged  nonzero to flip verify_data's first bit (the server
 *   must answer decrypt_error, its verdict the only public outcome of the compare). */
static void ct_finished(ct_client *cl, const uint8_t *base, int forged)
{
    uint8_t m[4 + 48], h[48];
    ct_hash(cl, cl->transcript, cl->transcript_length, h);
    httpasm_tls13_finished(cl->hash, base, h, m + 4);
    m[0] = 20;
    ct_u24(m + 1, cl->hash_length);
    if (forged)
        m[4] ^= 1;
    ct_add(cl, m, 4 + cl->hash_length);
    ct_seal(cl, HTTPASM_TLS_CONTENT_HANDSHAKE, m, 4 + cl->hash_length);
}

/* ct_next_key: an application traffic secret replaced by its next generation (7.2), and its
 * record key made from it (sequence 0 again).
 *   cl  the client (its suite and hash); secret_io  the secret, replaced; key  the key, remade. */
static void ct_next_key(ct_client *cl, uint8_t *secret_io, httpasm_tls13_record_key *key)
{
    uint8_t next[48];
    httpasm_tls13_update_secret(cl->hash, secret_io, next);
    memcpy(secret_io, next, cl->hash_length);
    httpasm_tls13_record_key_init(key, cl->s->suite, secret_io);
}

/* ct_key_update: a KeyUpdate of the client's sealed under its current write key, then its next
 * write key (the order 4.7.3 gives: the message is the old key's last record).
 *   cl  the client; request  1 for update_requested (the server must answer with its own). */
static void ct_key_update(ct_client *cl, int request)
{
    const uint8_t m[5] = { 24, 0, 0, 1, (uint8_t)request };
    ct_seal(cl, HTTPASM_TLS_CONTENT_HANDSHAKE, m, sizeof m);
    ct_next_key(cl, cl->write_secret, &cl->write);
}

/* ct_message: one whole handshake message from the server, handled: ServerHello (the handshake
 * keys), HelloRetryRequest (message_hash, the second hello), EncryptedExtensions,
 * CertificateRequest (in the handshake: noted; after it: answered at once, the first with the
 * scenario's post_key, later ones declined), Certificate and CertificateVerify (taken into the
 * transcript: the server's proofs are the other tests'), Finished (verified; the application
 * keys; our Certificate and CertificateVerify when asked, our Finished), KeyUpdate (our read key
 * moved; ours when asked). Anything else breaks the client.
 *   cl  the client; m, n  the message, its header included. */
static void ct_message(ct_client *cl, const uint8_t *m, size_t n)
{
    static const uint8_t hrr_random[32] = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    };
    uint8_t h[48], expected[48];
    size_t length = 0;
    const uint8_t *p;
    switch (m[0]) {
    case 2:
        if (n >= 38 && memcmp(m + 6, hrr_random, 32) == 0) {
            /* HelloRetryRequest: the first hello becomes message_hash (4.4.1), then the second */
            ct_hash(cl, cl->transcript, cl->transcript_length, h);
            cl->transcript[0] = 254, cl->transcript[1] = 0, cl->transcript[2] = 0;
            cl->transcript[3] = (uint8_t)cl->hash_length;
            memcpy(cl->transcript + 4, h, cl->hash_length);
            cl->transcript_length = 4 + cl->hash_length;
            ct_add(cl, m, n);
            p = ct_extension(m, n, 51, &length);
            if (p == NULL || length != 2) {
                cl->broken = "a HelloRetryRequest without its group";
                return;
            }
            ct_hello(cl, (uint16_t)(p[0] << 8 | p[1]));
            return;
        }
        ct_add(cl, m, n);
        p = ct_extension(m, n, 51, &length);
        if (p == NULL || length < 4) {
            cl->broken = "a ServerHello without its share";
            return;
        }
        {
            static uint8_t shared[1100], early[48], derived[48];
            size_t secret_length = ct_shared(cl, p + 4, length - 4, shared);
            if (secret_length == 0)
                return;
            httpasm_tls13_extract(cl->hash, NULL, 0, NULL, 0, early);
            ct_derive(cl, early, "derived", NULL, derived);
            httpasm_tls13_extract(cl->hash, derived, cl->hash_length, shared, secret_length, cl->handshake_secret);
            ct_hash(cl, cl->transcript, cl->transcript_length, h);
            ct_derive(cl, cl->handshake_secret, "c hs traffic", h, cl->client_hs);
            ct_derive(cl, cl->handshake_secret, "s hs traffic", h, cl->server_hs);
            httpasm_tls13_record_key_init(&cl->read, cl->s->suite, cl->server_hs);
            httpasm_tls13_record_key_init(&cl->write, cl->s->suite, cl->client_hs);
            cl->keyed = 1;
        }
        return;
    case 8:                                                 /* EncryptedExtensions */
    case 11:                                                /* the server's Certificate */
    case 15:                                                /* its CertificateVerify */
        ct_add(cl, m, n);
        return;
    case 13:
        if (!cl->finished) {
            cl->requested = 1;
            ct_add(cl, m, n);
            return;
        }
        /* post-handshake (4.7.2): over ClientHello .. our Finished + the request, each answer */
        {
            uint8_t context[256];
            size_t context_length = n > 4 ? m[4] : 0;
            memcpy(context, m + 5, context_length);
            cl->transcript_length = cl->base_length;
            ct_add(cl, m, n);
            ct_authenticate(cl, cl->answers == 0 ? cl->s->post_key : CT_NONE, context, context_length);
            ct_finished(cl, cl->write_secret, 0);
            cl->transcript_length = cl->base_length;
            cl->answers++;
        }
        return;
    case 20:
        ct_hash(cl, cl->transcript, cl->transcript_length, h);
        httpasm_tls13_finished(cl->hash, cl->server_hs, h, expected);
        if (n != 4 + cl->hash_length || memcmp(m + 4, expected, cl->hash_length) != 0) {
            cl->broken = "the server's Finished did not verify";
            return;
        }
        ct_add(cl, m, n);
        {
            static uint8_t derived[48], master[48];
            ct_derive(cl, cl->handshake_secret, "derived", NULL, derived);
            httpasm_tls13_extract(cl->hash, derived, cl->hash_length, NULL, 0, master);
            ct_hash(cl, cl->transcript, cl->transcript_length, h);
            ct_derive(cl, master, "c ap traffic", h, cl->write_secret);
            ct_derive(cl, master, "s ap traffic", h, cl->read_secret);
            httpasm_tls13_record_key_init(&cl->read, cl->s->suite, cl->read_secret);
        }
        if (cl->requested)
            ct_authenticate(cl, cl->s->client_key, NULL, 0);
        ct_finished(cl, cl->client_hs, cl->s->forge == CT_FORGE_FINISHED);
        httpasm_tls13_record_key_init(&cl->write, cl->s->suite, cl->write_secret);
        cl->base_length = cl->transcript_length;
        cl->finished = 1;
        return;
    case 24:
        if (n != 5) {
            cl->broken = "a KeyUpdate of the wrong length";
            return;
        }
        ct_next_key(cl, cl->read_secret, &cl->read);
        cl->key_updates++;
        if (m[4] == 1)
            ct_key_update(cl, 0);
        return;
    default:
        cl->broken = "a handshake message the client does not take";
    }
}

/* ct_read: the server's octets taken by the client, record by record (the engine queues whole
 * records): protected ones opened under the read key in force at each (a key changes at a
 * record's end), handshake octets gathered into whole messages and each handled at once
 * (ct_message), alerts and application data kept; anything else breaks the client.
 *   cl  the client; in, n  the octets (public: on the wire). */
static void ct_read(ct_client *cl, const uint8_t *in, size_t n)
{
    static uint8_t record[HTTPASM_TLS_RECORD_HEADER + HTTPASM_TLS_CIPHERTEXT_MAX];
    size_t at = 0;
    while (at < n && cl->broken == NULL) {
        int64_t length = httpasm_tls_record_length(in + at, n - at);
        if (length <= 0) {
            cl->broken = "the server's output is not whole records";
            return;
        }
        memcpy(record, in + at, (size_t)length);
        at += (size_t)length;
        uint8_t type = record[0];
        int64_t content = length - HTTPASM_TLS_RECORD_HEADER;
        if (type == HTTPASM_TLS_CONTENT_CHANGE_CIPHER_SPEC)
            continue;                                       /* (E.4: dropped) */
        if (type == HTTPASM_TLS_CONTENT_APPLICATION_DATA) {
            content = cl->keyed ? httpasm_tls13_open(&cl->read, record, (size_t)length, &type) : -1;
            if (content < 0) {
                cl->broken = "a server record did not open";
                return;
            }
        }
        const uint8_t *c = record + HTTPASM_TLS_RECORD_HEADER;
        if (type == HTTPASM_TLS_CONTENT_ALERT) {
            cl->alert = content == 2 ? c[1] : 256;
            continue;
        }
        if (type == HTTPASM_TLS_CONTENT_APPLICATION_DATA) {
            if (cl->data_length + (size_t)content > sizeof cl->data) {
                cl->broken = "more application data than the test sent";
                return;
            }
            memcpy(cl->data + cl->data_length, c, (size_t)content);
            cl->data_length += (size_t)content;
            continue;
        }
        if (type != HTTPASM_TLS_CONTENT_HANDSHAKE || cl->pending_length + (size_t)content > sizeof cl->pending) {
            cl->broken = "a record the client cannot take";
            return;
        }
        memcpy(cl->pending + cl->pending_length, c, (size_t)content);
        cl->pending_length += (size_t)content;
        while (cl->pending_length >= 4 && cl->broken == NULL) {
            static uint8_t message[CT_TLS_BUFFER];
            size_t m = 4 + ((size_t)cl->pending[1] << 16 | (size_t)cl->pending[2] << 8 | cl->pending[3]);
            if (m > cl->pending_length)
                break;
            memcpy(message, cl->pending, m);
            memmove(cl->pending, cl->pending + m, cl->pending_length - m);
            cl->pending_length -= m;
            ct_message(cl, message, m);
        }
    }
}

/* What the server reported over one ct_pump. */
typedef struct {
    unsigned kinds;                             /* 1 << each HTTPASM_TLS_EVENT_* seen */
    uint32_t alert;                             /* a failure's alert */
    uint8_t data[4096];                         /* application data delivered (public once taken) */
    size_t data_length;
} ct_events;

/* ct_pump: the client's records to the server, one receive each (what it reports kept in ev; a
 * failure stops the feeding), then the server's output to the client (marked public first: it
 * is on the wire); again until neither side has anything to send (32 rounds at most).
 *   cl  the client; ev  zeroed, then the events, a failure's alert, the data delivered. */
static void ct_pump(ct_client *cl, ct_events *ev)
{
    memset(ev, 0, sizeof *ev);
    for (int round = 0; round < 32 && cl->broken == NULL; round++) {
        int moved = 0;
        size_t at = 0;
        while (at < cl->out_length) {
            httpasm_tls13_event e;
            int64_t taken = httpasm_tls13_receive(&ct_connection, cl->out + at, cl->out_length - at, &e);
            ev->kinds |= 1u << e.kind;
            if (taken <= 0) {
                ev->alert = e.alert;
                break;
            }
            if (e.kind == HTTPASM_TLS_EVENT_DATA) {
                public(e.data, e.length);                   /* the caller's to read now */
                if (ev->data_length + e.length <= sizeof ev->data) {
                    memcpy(ev->data + ev->data_length, e.data, e.length);
                    ev->data_length += e.length;
                }
            }
            at += (size_t)taken;
            moved = 1;
        }
        cl->out_length = 0;
        const uint8_t *queued;
        size_t n = httpasm_tls13_output(&ct_connection, &queued);
        if (n > 0) {
            public(queued, n);
            ct_read(cl, queued, n);
            httpasm_tls13_output_done(&ct_connection, n);
            moved = 1;
        }
        if (!moved)
            break;
    }
}

/* ct_handshake: one scenario: the server configured and started, the handshake pumped through,
 * then (unless a forgery ends it) application data each way, a KeyUpdate asked by each side,
 * the post-handshake requests, a forged record, close_notify each way; each step's outcome
 * checked (a failure is counted and printed with the scenario's name), the connection wiped.
 *   s  the scenario; tier  its name, for the messages. */
static void ct_handshake(const ct_scenario *s, const char *tier)
{
    ct_client *cl = &ct_the_client;
    memset(cl, 0, sizeof *cl);
    cl->s = s;
    cl->alert = -1;
    cl->hash = s->suite == HTTPASM_TLS_AES_256_GCM_SHA384 ? HTTPASM_HASH_SHA384 : HTTPASM_HASH_SHA256;
    cl->hash_length = cl->hash == HTTPASM_HASH_SHA384 ? 48 : 32;
    char what[200];
    memset(&ct_config, 0, sizeof ct_config);
    ct_config.key = &ct_server_keys[s->server_key];
    ct_config.random = ct_draw;
    ct_config.flags = s->flags;
    for (int g = 0; g < 2 && s->server_groups[g]; g++)
        ct_config.groups[ct_config.group_count++] = s->server_groups[g];
    const uint8_t *chain[1] = { ct_keys[s->server_key].certificate };
    size_t lengths[1] = { ct_keys[s->server_key].certificate_length };
    snprintf(what, sizeof what, "the engine (%s): its configuration", s->name);
    if (httpasm_tls13_server_config_init(&ct_config, chain, lengths, 1, ct_certificate_message, sizeof ct_certificate_message) != 0
        || ct_config.memory > sizeof ct_memory
        || httpasm_tls13_server_init(&ct_connection, &ct_config, ct_memory, ct_config.memory) != 0) {
        expect(0, what, tier);
        return;
    }
    ct_events ev;
    ct_hello(cl, s->share);
    ct_pump(cl, &ev);
    if (s->forge == CT_FORGE_FINISHED) {
        snprintf(what, sizeof what, "the engine (%s): decrypt_error", s->name);
        expect(cl->broken == NULL && (ev.kinds & 1u << HTTPASM_TLS_EVENT_FAILED) && ev.alert == HTTPASM_TLS_ALERT_DECRYPT_ERROR
               && cl->alert == HTTPASM_TLS_ALERT_DECRYPT_ERROR, what, tier);
        httpasm_tls13_wipe(&ct_connection);
        return;
    }
    uint32_t suite = 0, group = 0, scheme = 0;
    snprintf(what, sizeof what, "the engine (%s): the handshake (%s)", s->name, cl->broken ? cl->broken : "the server refused");
    expect(cl->broken == NULL && (ev.kinds & 1u << HTTPASM_TLS_EVENT_CONNECTED)
           && httpasm_tls13_negotiated(&ct_connection, &suite, &group, &scheme) == 2 && suite == s->suite
           && scheme == ct_keys[s->server_key].scheme, what, tier);
    if (cl->broken || !(ev.kinds & 1u << HTTPASM_TLS_EVENT_CONNECTED)) {
        httpasm_tls13_wipe(&ct_connection);
        return;
    }
    int expected_count = (s->flags & (HTTPASM_TLS_CLIENT_AUTH_REQUEST | HTTPASM_TLS_CLIENT_AUTH_REQUIRE)) == 0 ? -1
                       : s->client_key == CT_NONE ? 0 : 1;
    snprintf(what, sizeof what, "the engine (%s): the client's chain", s->name);
    expect(httpasm_tls13_peer_certificates(&ct_connection, NULL, NULL) == expected_count, what, tier);

    /* application data each way: ours secret, the client's opened under the server's secret key */
    static uint8_t data[300], back[200];
    fill(data, sizeof data, 1100);
    secret(data, sizeof data);
    snprintf(what, sizeof what, "the engine (%s): application data out", s->name);
    expect(httpasm_tls13_send(&ct_connection, data, sizeof data) == (int64_t)sizeof data, what, tier);
    public(data, sizeof data);
    ct_pump(cl, &ev);
    expect(cl->broken == NULL && cl->data_length == sizeof data && memcmp(cl->data, data, sizeof data) == 0, what, tier);
    fill(back, sizeof back, 1101);
    ct_seal(cl, HTTPASM_TLS_CONTENT_APPLICATION_DATA, back, sizeof back);
    ct_pump(cl, &ev);
    snprintf(what, sizeof what, "the engine (%s): application data in", s->name);
    expect(ev.data_length == sizeof back && memcmp(ev.data, back, sizeof back) == 0, what, tier);

    /* KeyUpdates: the client's asking for the server's (which its next send carries), then the
     * server's asking for the client's; data under the new keys each way */
    ct_key_update(cl, 1);
    ct_pump(cl, &ev);
    cl->data_length = 0;
    secret(data, 100);
    snprintf(what, sizeof what, "the engine (%s): KeyUpdates", s->name);
    expect(httpasm_tls13_send(&ct_connection, data, 100) == 100, what, tier);
    public(data, 100);
    ct_pump(cl, &ev);
    expect(cl->key_updates == 1 && cl->data_length == 100 && memcmp(cl->data, data, 100) == 0, what, tier);
    expect(httpasm_tls13_key_update(&ct_connection, 1) == 0, what, tier);
    ct_pump(cl, &ev);
    ct_seal(cl, HTTPASM_TLS_CONTENT_APPLICATION_DATA, back, 50);
    ct_pump(cl, &ev);
    expect(cl->broken == NULL && cl->key_updates == 2 && ev.data_length == 50 && memcmp(ev.data, back, 50) == 0, what, tier);

    /* post-handshake authentication: answered with post_key's certificate, then declined */
    if (s->post_key != CT_NONE) {
        for (int round = 0; round < 2; round++) {
            snprintf(what, sizeof what, "the engine (%s): post-handshake authentication %d", s->name, round + 1);
            expect(httpasm_tls13_request_certificate(&ct_connection) == 0, what, tier);
            ct_pump(cl, &ev);
            expect(cl->broken == NULL && (ev.kinds & 1u << HTTPASM_TLS_EVENT_AUTHENTICATED)
                   && httpasm_tls13_peer_certificates(&ct_connection, NULL, NULL) == (round == 0 ? 1 : 0), what, tier);
        }
    }

    if (s->forge == CT_FORGE_RECORD) {
        /* a record whose tag does not verify: bad_record_mac, the verdict public by design */
        ct_seal(cl, HTTPASM_TLS_CONTENT_APPLICATION_DATA, back, 60);
        cl->out[cl->out_length - 1] ^= 1;
        ct_pump(cl, &ev);
        snprintf(what, sizeof what, "the engine (%s): bad_record_mac", s->name);
        expect((ev.kinds & 1u << HTTPASM_TLS_EVENT_FAILED) && ev.alert == HTTPASM_TLS_ALERT_BAD_RECORD_MAC
               && cl->alert == HTTPASM_TLS_ALERT_BAD_RECORD_MAC, what, tier);
        httpasm_tls13_wipe(&ct_connection);
        return;
    }

    /* close_notify each way */
    snprintf(what, sizeof what, "the engine (%s): close_notify", s->name);
    expect(httpasm_tls13_close(&ct_connection) == 0, what, tier);
    ct_pump(cl, &ev);
    expect(cl->alert == 0, what, tier);
    static const uint8_t close_notify[2] = { 1, 0 };
    ct_seal(cl, HTTPASM_TLS_CONTENT_ALERT, close_notify, 2);
    ct_pump(cl, &ev);
    expect(cl->broken == NULL && (ev.kinds & 1u << HTTPASM_TLS_EVENT_CLOSED), what, tier);
    httpasm_tls13_wipe(&ct_connection);
}

/* The handshakes: every group (the client's share in it; the server takes it), each server key
 * kind, each suite, and the paths around them. */
static const ct_scenario ct_scenarios[] = {
    { "x25519, AES-128-GCM, Ed25519, compatibility mode", HTTPASM_TLS_AES_128_GCM_SHA256, HTTPASM_TLS_GROUP_X25519,
      { 0 }, CK_ED25519, 0, { 0 }, CT_NONE, CT_NONE, 1, CT_FORGE_NOTHING },
    { "x448, AES-256-GCM, Ed448", HTTPASM_TLS_AES_256_GCM_SHA384, HTTPASM_TLS_GROUP_X448,
      { 0 }, CK_ED448, 0, { 0 }, CT_NONE, CT_NONE, 0, CT_FORGE_NOTHING },
    { "secp256r1, ChaCha20-Poly1305, ECDSA P-256", HTTPASM_TLS_CHACHA20_POLY1305_SHA256, HTTPASM_TLS_GROUP_SECP256R1,
      { 0 }, CK_P256, 0, { 0 }, CT_NONE, CT_NONE, 0, CT_FORGE_NOTHING },
    { "secp384r1, AES-256-GCM, ECDSA P-384", HTTPASM_TLS_AES_256_GCM_SHA384, HTTPASM_TLS_GROUP_SECP384R1,
      { 0 }, CK_P384, 0, { 0 }, CT_NONE, CT_NONE, 0, CT_FORGE_NOTHING },
    { "secp521r1, AES-128-GCM, ECDSA P-521", HTTPASM_TLS_AES_128_GCM_SHA256, HTTPASM_TLS_GROUP_SECP521R1,
      { 0 }, CK_P521, 0, { 0 }, CT_NONE, CT_NONE, 0, CT_FORGE_NOTHING },
    { "ffdhe2048, AES-128-GCM, RSA-PSS (rsaEncryption)", HTTPASM_TLS_AES_128_GCM_SHA256, HTTPASM_TLS_GROUP_FFDHE2048,
      { 0 }, CK_RSA, 0, { 0 }, CT_NONE, CT_NONE, 0, CT_FORGE_NOTHING },
    { "X25519MLKEM768, ChaCha20-Poly1305, RSA-PSS (id-RSASSA-PSS)", HTTPASM_TLS_CHACHA20_POLY1305_SHA256,
      HTTPASM_TLS_GROUP_X25519MLKEM768, { 0 }, CK_RSA_PSS, 0, { 0 }, CT_NONE, CT_NONE, 0, CT_FORGE_NOTHING },
    { "SecP256r1MLKEM768, AES-128-GCM, Ed25519, a P-256 client", HTTPASM_TLS_AES_128_GCM_SHA256,
      HTTPASM_TLS_GROUP_SECP256R1MLKEM768, { 0 }, CK_ED25519, HTTPASM_TLS_CLIENT_AUTH_REQUEST, { 0 }, CK_P256, CT_NONE, 0,
      CT_FORGE_NOTHING },
    { "SecP384r1MLKEM1024, AES-256-GCM, ECDSA P-256, an RSA client required", HTTPASM_TLS_AES_256_GCM_SHA384,
      HTTPASM_TLS_GROUP_SECP384R1MLKEM1024, { 0 }, CK_P256, HTTPASM_TLS_CLIENT_AUTH_REQUIRE, { 0 }, CK_RSA, CT_NONE, 0,
      CT_FORGE_NOTHING },
    { "a HelloRetryRequest (x25519's share, secp256r1 the server's first)", HTTPASM_TLS_AES_128_GCM_SHA256,
      HTTPASM_TLS_GROUP_X25519, { HTTPASM_TLS_GROUP_X25519, HTTPASM_TLS_GROUP_SECP256R1 }, CK_ED25519,
      HTTPASM_TLS_SERVER_GROUP_ORDER, { HTTPASM_TLS_GROUP_SECP256R1, HTTPASM_TLS_GROUP_X25519 }, CT_NONE, CT_NONE, 1,
      CT_FORGE_NOTHING },
    { "post-handshake authentication (declined in the handshake; Ed448, then declined)", HTTPASM_TLS_AES_128_GCM_SHA256,
      HTTPASM_TLS_GROUP_X25519, { 0 }, CK_ED25519, HTTPASM_TLS_CLIENT_AUTH_REQUEST, { 0 }, CT_NONE, CK_ED448, 0,
      CT_FORGE_NOTHING },
    { "a forged Finished", HTTPASM_TLS_AES_128_GCM_SHA256, HTTPASM_TLS_GROUP_X25519,
      { 0 }, CK_ED25519, 0, { 0 }, CT_NONE, CT_NONE, 0, CT_FORGE_FINISHED },
    { "a forged record", HTTPASM_TLS_CHACHA20_POLY1305_SHA256, HTTPASM_TLS_GROUP_X25519,
      { 0 }, CK_ED25519, 0, { 0 }, CT_NONE, CT_NONE, 0, CT_FORGE_RECORD },
};

/* engine: the server engine's handshakes (ct_scenarios) at this tier, its keys loaded from PEM
 * texts whose base64 is secret (so the loader's own outputs are checked as the engine uses them:
 * what it leaves secret stays so), made public and zeroed again after the last.
 *   tier  the tier's name, for the messages. */
static void engine(const char *tier)
{
    static char text[4096];
    for (int k = 0; k < CK_COUNT; k++) {
        size_t body, body_length;
        size_t n = pem_key("PRIVATE KEY", ct_keys[k].der, ct_keys[k].der_length, text, &body, &body_length);
        secret(text + body, body_length);
        expect(httpasm_private_key_load(&ct_server_keys[k], (const uint8_t *)text, n) == ct_keys[k].kind,
               "private_key_load (the engine's keys)", tier);
        public(text, n);
    }
    for (size_t s = 0; s < sizeof ct_scenarios / sizeof ct_scenarios[0]; s++)
        ct_handshake(&ct_scenarios[s], tier);
    for (int k = 0; k < CK_COUNT; k++) {
        public(&ct_server_keys[k], sizeof ct_server_keys[k]);
        memset(&ct_server_keys[k], 0, sizeof ct_server_keys[k]);
    }
}

/* checks: every primitive at every tier valgrind's CPU offers (a tier whose features equal the
 * one before is skipped: valgrind's CPU tops out below it). */
static void *checks(void *unused)
{
    (void)unused;
    static const uint64_t caps[] = { HTTPASM_CPU_CAP_V1, HTTPASM_CPU_CAP_V2, HTTPASM_CPU_CAP_V3, HTTPASM_CPU_CAP_V4 };
    static const char *const names[] = { "v1", "v2", "v3", "v4" };
    uint64_t seen = ~(uint64_t)0;
    /* the engine's keys and certificates, once (public octets: the server's loading of them at
     * each tier is what is secret) */
    if (ct_key_files() != 0) {
        failures++;
        return NULL;
    }
    for (size_t t = 0; t < sizeof caps / sizeof caps[0]; t++) {
        uint64_t features = httpasm_cpu_limit(caps[t]);
        if (features == seen)
            continue;
        seen = features;
        fprintf(stderr, "ct: %s (features %#llx)\n", names[t], (unsigned long long)features);
        hashes();
        macs();
        ciphers(names[t]);
        montgomery(names[t]);
        weierstrass(names[t]);
        edwards(names[t]);
        kem(names[t]);
        ffdhe(names[t]);
        rsa(rsa_1024, names[t]);
        rsa(rsa_2048, names[t]);
        encodings(names[t]);
        keys(names[t]);
        tls13(names[t]);
        engine(names[t]);
    }
    return NULL;
}

/* control: the negative control (ct --control): a branch on a secret octet, which memcheck must
 * report (tests/ct/run.sh requires valgrind to fail this run before it trusts a clean one: the
 * client requests reach memcheck and it sees through them). Returns what the branch chose, so the
 * compiler keeps it. */
static int control(void)
{
    static volatile uint8_t octet = 0x5A;
    uint8_t copy = octet;
    secret(&copy, 1);
    if (copy & 1)
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--control") == 0) {
        int chose = control();
        fprintf(stderr, "ct: control ran (%d)\n", chose);
        return 0;
    }
    if (vg_request(0x1001, 0, 0) == 0) {
        fprintf(stderr, "ct: not running under valgrind, so nothing is checked: run tests/ct/run.sh\n");
        return 2;
    }
    /* The library's load address, for tests/ct/run.sh's naming of the internal routines that
     * memcheck reports as ??? (NASM's labels carry no sizes, which valgrind's names need). */
    Dl_info info;
    if (dladdr((void *)httpasm_sha256, &info) == 0) {
        fprintf(stderr, "ct: dladdr found no library\n");
        return 2;
    }
    fprintf(stderr, "ct: base %p %s\n", info.dli_fbase, info.dli_fname);
    /* The checks run on a thread whose 16 MiB stack pthread maps whole: the large frames (RSA's
     * and FFDHE's, about 45 KiB, touched a page at a time) need no growth of the main thread's
     * stack, which valgrind refuses below its first mapping. */
    pthread_attr_t attributes;
    pthread_t thread;
    if (pthread_attr_init(&attributes) != 0 || pthread_attr_setstacksize(&attributes, 16u << 20) != 0
        || pthread_create(&thread, &attributes, checks, NULL) != 0 || pthread_join(thread, NULL) != 0) {
        fprintf(stderr, "ct: the checking thread did not run\n");
        return 2;
    }
    return failures ? 1 : 0;
}
