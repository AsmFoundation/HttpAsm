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
 * arithmetic) and 2048 (v3's own k = 16 square and product).
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

/* checks: every primitive at every tier valgrind's CPU offers (a tier whose features equal the
 * one before is skipped: valgrind's CPU tops out below it). */
static void *checks(void *unused)
{
    (void)unused;
    static const uint64_t caps[] = { HTTPASM_CPU_CAP_V1, HTTPASM_CPU_CAP_V2, HTTPASM_CPU_CAP_V3, HTTPASM_CPU_CAP_V4 };
    static const char *const names[] = { "v1", "v2", "v3", "v4" };
    uint64_t seen = ~(uint64_t)0;
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
