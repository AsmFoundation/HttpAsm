/*
 * bench.h - HttpAsm's benchmark framework: the measurement core every suite shares
 * (benchmarks/README.md has the method; docs/DESIGN.md section 2: a faster version stays only
 * when a single-thread measurement shows it pays).
 *
 * The pieces:
 *   - a build: one libhttpasm.so loaded into this process with dlopen (RTLD_LOCAL), its API
 *     looked up into a table (bench_api), so that two builds - the tree's and another one, the
 *     commit before a change, say - run in one process, on one core, interleaved round by
 *     round: the fairest A/B a change can get, with no second process or machine state between
 *     its two sides;
 *   - a case: one routine on one input (a suite registers its cases with bench_add);
 *   - a contender: what one row of a case measures: a build at a CPU tier (httpasm_cpu_limit),
 *     or a rival's code (picohttpparser, llhttp, nghttp2), and the first contender once more as
 *     the A/A control: whatever separates the two is noise;
 *   - the runner (bench.c): per case, sizes a batch to about sample_us, then runs rounds, each
 *     round every contender once, in a new random order each time (the seed is recorded), so
 *     drift and order effects reach all of them alike;
 *   - the record: every sample, raw, in JSON, with the host, the builds and the settings
 *     (benchmarks/report.cs turns it into statistics, verdicts and tables), and a summary on
 *     stdout for the development loop.
 *
 * Footgun: a case's batch must feed its results to bench_sink (or another volatile), or the
 * compiler may drop the calls it measures: libhttpasm.so's functions are opaque to it, but a
 * rival compiled into this binary is not.
 */
#ifndef HTTPASM_BENCH_H
#define HTTPASM_BENCH_H

#include <stddef.h>
#include <stdint.h>

#include "httpasm.h"

/* BENCH_API: the library functions the cases call, each looked up by name in every build
 * (dlsym), so a case calls a build's own code through that build's table. Add a function here
 * when a case needs one. Only the declarations of httpasm.h are used (through __typeof__): this
 * program never links libhttpasm.so, it loads it. */
#define BENCH_API(X)                \
    X(httpasm_cpu_found)            \
    X(httpasm_cpu_features)         \
    X(httpasm_cpu_limit)            \
    X(httpasm_token_length)         \
    X(httpasm_field_value_scan)     \
    X(httpasm_field_id)             \
    X(httpasm_h1_parse_request)     \
    X(httpasm_h1_parse_response)    \
    X(httpasm_h1_chunked_decode)    \
    X(httpasm_h1_parse_trailers)    \
    X(httpasm_h1_write_response)    \
    X(httpasm_h1_write_request)     \
    X(httpasm_hpack_size)           \
    X(httpasm_hpack_init)           \
    X(httpasm_hpack_decode)         \
    X(httpasm_hpack_encode_bound)   \
    X(httpasm_hpack_encode)         \
    X(httpasm_h2_request)           \
    X(httpasm_sha256)               \
    X(httpasm_hmac_sha256)          \
    X(httpasm_hkdf_sha256_expand)   \
    X(httpasm_sha512)               \
    X(httpasm_sha384)               \
    X(httpasm_hmac_sha384)          \
    X(httpasm_hkdf_sha384_expand)   \
    X(httpasm_aes_init)             \
    X(httpasm_aes_encrypt_block)    \
    X(httpasm_aes_gcm_init)         \
    X(httpasm_aes_gcm_seal)         \
    X(httpasm_chacha20_poly1305_seal) \
    X(httpasm_x25519)               \
    X(httpasm_x25519_public_key)    \
    X(httpasm_random)               \
    X(httpasm_p256_public_key)      \
    X(httpasm_p256_ecdh)            \
    X(httpasm_p256_sign)            \
    X(httpasm_p256_verify)          \
    X(httpasm_p384_public_key)      \
    X(httpasm_p384_ecdh)            \
    X(httpasm_p384_sign)            \
    X(httpasm_p384_verify)          \
    X(httpasm_ed25519_public_key)   \
    X(httpasm_ed25519_private_key_init) \
    X(httpasm_ed25519_sign)         \
    X(httpasm_ed25519_verify)       \
    X(httpasm_rsa_public_key_init)  \
    X(httpasm_rsa_verify_pkcs1)     \
    X(httpasm_rsa_private_key_init) \
    X(httpasm_rsa_sign_pkcs1)       \
    X(httpasm_rsa_sign_pss)

#define BENCH_API_FIELD(name) __typeof__(&name) name;

/* bench_api: one build's functions, resolved by name; every field is set once the build is
 * loaded (a build missing one of them is refused: an older build that lacks a routine cannot
 * run the cases that measure it). */
typedef struct bench_api {
    BENCH_API(BENCH_API_FIELD)
} bench_api;

/* bench_build: one libhttpasm.so in this process.
 *   name    "current" for the default build, or NAME of --build NAME=PATH;
 *   path    the file loaded (resolved through this binary's RUNPATH when it has no '/');
 *   handle  dlopen's handle; every build is RTLD_LOCAL, so each one's calls stay inside it;
 *   found   the CPU features the build detected (httpasm_cpu_found), recorded per build. */
typedef struct bench_build {
    const char *name;
    const char *path;
    void *handle;
    uint64_t found;
    bench_api api;
} bench_build;

struct bench_case;

/* bench_batch: runs the routine under measurement `calls` times on the case's input.
 *   build  the build whose code runs (its api table), NULL for a rival's batch;
 *   c      the case: its input (data, length) and the state its suite prepared;
 *   calls  how many calls this batch makes (at least 1).
 * It must feed every call's result to bench_sink, or the calls may be optimized away. */
typedef void (*bench_batch)(const bench_build *build, const struct bench_case *c, long calls);

/* bench_rival: another project's code on the same input: its row's name and its batch. */
typedef struct bench_rival {
    const char *name;
    bench_batch run;
} bench_rival;

/* Which tiers a case's HttpAsm contenders run at, per build:
 *   BENCH_TIERS_ALL       v1, v2, v3 and v4 (a tier the CPU lacks runs the best one it has,
 *                         and the record says which features were in effect): the tiers suite,
 *                         where each multi-version routine proves its versions;
 *   BENCH_TIERS_BEST_V1   the best tier the CPU has, then v1: whole routines (parsers,
 *                         rivals), where the question is the library's own speed and what its
 *                         vector code adds. */
enum bench_tiers {
    BENCH_TIERS_ALL,
    BENCH_TIERS_BEST_V1,
};

/* bench_case: one routine on one input.
 *   suite, name   where it belongs ("tiers", "parsers", "rivals") and the routine's name;
 *   input         the input's label for the reports ("64 octets", "browser request");
 *   data, length  the input; length also gives the throughput column (octets per ns), and a
 *                 case without a meaningful size passes 0 octets in `octets` below;
 *   octets        the octets one call processes, for octets per ns (0: no throughput);
 *   state         what the suite prepared for the case (a decoder, a field array), its own;
 *   ours          HttpAsm's batch, run per build and tier (NULL: the rivals only);
 *   tiers         which tiers `ours` runs at;
 *   rivals        the rivals' batches on the same input (rival_count of them). */
typedef struct bench_case {
    const char *suite;
    const char *name;
    const char *input;
    const uint8_t *data;
    size_t length;
    size_t octets;
    void *state;
    bench_batch ours;
    enum bench_tiers tiers;
    const bench_rival *rivals;
    size_t rival_count;
} bench_case;

/* bench_add: registers a case (copied); a suite calls it from its registration function.
 * Exits the program with status 2 when the case table is full (raise BENCH_MAX_CASES). */
void bench_add(const bench_case *c);

/* bench_state_init: makes a build's state in memory (size octets, zeroed) for a case, through
 * that build's own functions. Returns 0, or nonzero when the build refuses (the state is then
 * not kept, and the batch must not run). */
typedef int (*bench_state_init)(const bench_build *build, void *memory, size_t size);

/* bench_state: the state a batch keeps per build and per key (an HPACK table: its layout is the
 * build's own, so two builds of different commits never share one). The first call for a
 * (build, key) pair allocates size octets and runs init; later calls return the same memory.
 * Meant to be called once per batch, outside the calls it times. Returns the memory, or NULL
 * when memory runs out, init fails, or the table of states is full (64 pairs). */
void *bench_state(const bench_build *build, const void *key, size_t size, bench_state_init init);

/* bench_sink: where batches put their results, so no call is optimized away. */
extern volatile size_t bench_sink;

/* bench_first_build: the first build loaded (the tree's, "current", unless --only-builds), for a
 * suite that prepares inputs with the library itself (an HPACK block to decode): the builds are
 * loaded before the suites register. NULL when there is none (--list without builds). */
const bench_build *bench_first_build(void);

/* The request heads the rivals suite parses (suite_rivals.c: a minimal request, a browser's
 * navigation request, an API call with a bearer token), NUL-terminated. The tiers suite times
 * httpasm_h1_parse_request on the same octets at every tier, where a version above v2 must prove
 * itself against v2, which the rivals suite's best-and-v1 rows cannot show. */
extern const char bench_small_request[];
extern const char bench_browser_request[];
extern const char bench_api_request[];

/* bench_h1_request: httpasm_h1_parse_request on the case's head, `calls` times, each a
 * message's first call (scan_from 0), into a 64-record field array (suite_rivals.c). A batch for
 * either suite: bench_case.ours. */
void bench_h1_request(const bench_build *b, const bench_case *c, long calls);

/* bench_response: the response head every suite parses (suite_rivals.c: a typical 200 for a
 * page, twelve fields), as a writable copy made on the first call: httpasm_h1_parse_response may
 * write its buffer (an obs-fold is blanked in place; this head has none, so every call parses the
 * same octets). The rivals suite times it beside picohttpparser and llhttp, the parsers suite at
 * the best tier and v1, the tiers suite at every tier.
 *   length  out: the head's length. Returns the copy. */
uint8_t *bench_response(size_t *length);

/* bench_h1_response: httpasm_h1_parse_response on the case's head, `calls` times, each a
 * response's first call (scan_from 0) to a GET, into a 64-record field array (suite_rivals.c).
 * A batch for any suite: bench_case.ours. */
void bench_h1_response(const bench_build *b, const bench_case *c, long calls);

/* bench_sha_input: 16 KiB of fixed pseudo-random octets (made on the first call) that the hash
 * cases take their messages from: 64 octets (one block and its padding block), 1 KiB, 16 KiB. */
const uint8_t *bench_sha_input(void);

/* bench_sha256: httpasm_sha256 of the case's message, `calls` times (suite_rivals.c). A batch for
 * any suite: the tiers suite times it at every tier, the rivals suite beside OpenSSL. */
void bench_sha256(const bench_build *b, const bench_case *c, long calls);

/* bench_sha512, bench_sha384: httpasm_sha512 (httpasm_sha384) of the case's message, `calls`
 * times (suite_rivals.c). Batches for any suite, as bench_sha256. SHA-384 is SHA-512's
 * compression with another start and a shorter digest: its case shows the final's cost only. */
void bench_sha512(const bench_build *b, const bench_case *c, long calls);
void bench_sha384(const bench_build *b, const bench_case *c, long calls);

/* bench_hmac_sha256: httpasm_hmac_sha256 of the case's message under a fixed 32-octet key (a TLS
 * traffic secret's size), `calls` times (suite_rivals.c). */
void bench_hmac_sha256(const bench_build *b, const bench_case *c, long calls);

/* bench_hkdf_expand: httpasm_hkdf_sha256_expand of the case's length (its data is the info),
 * from a fixed 32-octet PRK, `calls` times: TLS 1.3's key schedule is made of such calls
 * (suite_rivals.c). */
void bench_hkdf_expand(const bench_build *b, const bench_case *c, long calls);

/* bench_aes_block: httpasm_aes_encrypt_block of the case's first 16 octets, `calls` times, each
 * call encrypting the last one's output, under a key of c->length octets (16 or 32) made from the
 * case's data before the loop (the key's expansion is not timed; c->octets is 16) (suite_rivals.c). */
void bench_aes_block(const bench_build *b, const bench_case *c, long calls);

/* bench_gcm128_seal, bench_gcm256_seal: httpasm_aes_gcm_seal of the case's message (c->length
 * octets) under an AES-128-GCM (AES-256-GCM) key made before the loop, with a 5-octet AAD (a TLS
 * 1.3 record header) and the nonce's last octets changed every call, as a TLS sequence number
 * changes them (suite_rivals.c). */
void bench_gcm128_seal(const bench_build *b, const bench_case *c, long calls);
void bench_gcm256_seal(const bench_build *b, const bench_case *c, long calls);

/* bench_chacha_seal: httpasm_chacha20_poly1305_seal of the case's message (c->length octets)
 * under a fixed 32-octet key (the case's first octets), with a 5-octet AAD (a TLS 1.3 record
 * header) and the nonce's last octets changed every call, as a TLS sequence number changes them
 * (suite_rivals.c). */
void bench_chacha_seal(const bench_build *b, const bench_case *c, long calls);

/* bench_x25519: httpasm_x25519 of the case's first 32 octets (the scalar) and the next 32 (the
 * peer's u-coordinate), `calls` times: the ladder alone (suite_rivals.c). */
void bench_x25519(const bench_build *b, const bench_case *c, long calls);

/* bench_x25519_public_key: httpasm_x25519_public_key of the case's first 32 octets (X25519(k, 9):
 * edwards25519's fixed base since Ed25519, the ladder before). */
void bench_x25519_public_key(const bench_build *b, const bench_case *c, long calls);

/* bench_x25519_share: a TLS 1.3 key share's X25519 work per handshake: the public key of the
 * case's scalar, then the shared secret with the peer's point (suite_rivals.c). */
void bench_x25519_share(const bench_build *b, const bench_case *c, long calls);

/* The P-256 cases' input (bench_p256_input, suite_rivals.c): a private key (32 octets), a
 * peer's public key (65: RFC 6979 A.2.5's), a digest (32) and entropy (32). */
const uint8_t *bench_p256_input(void);

/* bench_p256_ecdh: httpasm_p256_ecdh of the input's key and peer point, `calls` times: the
 * peer's point decoded and checked, the scalar multiplication, the affine x (suite_rivals.c). */
void bench_p256_ecdh(const bench_build *b, const bench_case *c, long calls);

/* bench_p256_public_key: httpasm_p256_public_key of the input's key (the fixed base). */
void bench_p256_public_key(const bench_build *b, const bench_case *c, long calls);

/* bench_p256_share: a TLS 1.3 secp256r1 key share's work per handshake: a private key drawn
 * (httpasm_random, again when refused), its public key, the shared secret with the peer's. */
void bench_p256_share(const bench_build *b, const bench_case *c, long calls);

/* bench_p256_sign: httpasm_p256_sign of the input's digest with the input's entropy (a hedged
 * RFC 6979 signature, as a TLS server makes one per handshake). */
void bench_p256_sign(const bench_build *b, const bench_case *c, long calls);

/* bench_p256_verify: httpasm_p256_verify of a valid signature (made before the loop). */
void bench_p256_verify(const bench_build *b, const bench_case *c, long calls);

/* The P-384 cases' input (bench_p384_input, suite_rivals.c): a private key (48 octets), RFC 6979
 * A.2.6's public key as the peer's (97), a SHA-384 digest (48), entropy (48). */
const uint8_t *bench_p384_input(void);

/* bench_p384_ecdh: httpasm_p384_ecdh of the input's key and peer point (the variable base, the
 * peer's point checked every call). */
void bench_p384_ecdh(const bench_build *b, const bench_case *c, long calls);

/* bench_p384_public_key: httpasm_p384_public_key of the input's key (the fixed base). */
void bench_p384_public_key(const bench_build *b, const bench_case *c, long calls);

/* bench_p384_share: a TLS 1.3 secp384r1 key share's work per handshake: a private key drawn
 * (httpasm_random, again when refused), its public key, the shared secret with the peer's. */
void bench_p384_share(const bench_build *b, const bench_case *c, long calls);

/* bench_p384_sign: httpasm_p384_sign of the input's digest with the input's entropy (a hedged
 * RFC 6979 signature). */
void bench_p384_sign(const bench_build *b, const bench_case *c, long calls);

/* bench_p384_verify: httpasm_p384_verify of a valid signature (made before the loop): a TLS
 * client's work per P-384 signature in a certificate chain. */
void bench_p384_verify(const bench_build *b, const bench_case *c, long calls);

/* The Ed25519 cases' input (bench_ed25519_input, suite_rivals.c): a private key (the 32-octet
 * seed), then a TLS 1.3 server CertificateVerify's signed content (130 octets: 64 spaces, the
 * context string, a zero, a SHA-256 transcript hash; RFC 9846 4.4.3), the message pure Ed25519
 * signs whole. */
enum { BENCH_ED25519_MESSAGE = 130 };
const uint8_t *bench_ed25519_input(void);

/* bench_ed25519_public_key: httpasm_ed25519_public_key of the input's seed (SHA-512 and the fixed
 * base: the work of making a key, and of preparing one). */
void bench_ed25519_public_key(const bench_build *b, const bench_case *c, long calls);

/* bench_ed25519_sign: httpasm_ed25519_sign of the message under a key prepared before the loop
 * (a TLS server's work per handshake with an Ed25519 certificate). */
void bench_ed25519_sign(const bench_build *b, const bench_case *c, long calls);

/* bench_ed25519_verify: httpasm_ed25519_verify of a valid signature (made before the loop): a
 * TLS client's work per Ed25519 signature, CertificateVerify's or a certificate's. */
void bench_ed25519_verify(const bench_build *b, const bench_case *c, long calls);

/* An RSA verification's input (bench_rsa_input, suite_rivals.c): a public key (n of `octets`
 * octets, e = 65537) with a SHA-256 digest and its valid RSASSA-PKCS1-v1_5 signature, from
 * Project Wycheproof's vectors. A case's data points at one; its length is the structure's size. */
typedef struct bench_rsa_vector {
    size_t octets;
    uint8_t n[512];
    uint8_t e[4];
    size_t e_length;
    uint8_t digest[32];
    uint8_t signature[512];
} bench_rsa_vector;

/* bench_rsa_input: the 2048-, 3072- or 4096-bit vector (which = 0, 1, 2), decoded from the hex
 * on first use; NULL for any other `which`. */
const bench_rsa_vector *bench_rsa_input(size_t which);

/* bench_rsa_verify: httpasm_rsa_verify_pkcs1 of the vector's signature under its key, the key
 * prepared once before the loop (a key a program keeps: a CA's, a pinned peer's). */
void bench_rsa_verify(const bench_build *b, const bench_case *c, long calls);

/* bench_rsa_init_verify: the key prepared and the signature verified, each call: a TLS client's
 * work per certificate, whose key verifies one signature. */
void bench_rsa_init_verify(const bench_build *b, const bench_case *c, long calls);

/* bench_rsa_init: httpasm_rsa_public_key_init alone (n loaded, n0, R^2 mod n by long division). */
void bench_rsa_init(const bench_build *b, const bench_case *c, long calls);

/* An RSA signing key's input (bench_rsa_private_input, suite_rivals.c): a private key of `octets`
 * octets (n, e = 65537, d, and the CRT's p, q, dp, dq, q^-1 mod p of `half` octets each) with a
 * SHA-256 digest to sign, from Project Wycheproof's rsa_pkcs1_*_sig_gen vectors (balanced primes:
 * the keys a CA issues). d is OpenSSL's alone: httpasm_rsa_private_key_init signs by the CRT
 * numbers and takes no d. A case's data points at one; its length is the structure's size. */
typedef struct bench_rsa_private_vector {
    size_t octets;
    size_t half;
    uint8_t n[512];
    uint8_t e[3];
    uint8_t d[512];
    uint8_t p[256];
    uint8_t q[256];
    uint8_t dp[256];
    uint8_t dq[256];
    uint8_t qinv[256];
    uint8_t digest[32];
} bench_rsa_private_vector;

/* bench_rsa_private_input: the 2048-, 3072- or 4096-bit signing key (which = 0, 1, 2), decoded
 * from the hex on first use (a key that does not decode ends the process: the embedded hex is
 * wrong); NULL for any other `which`. */
const bench_rsa_private_vector *bench_rsa_private_input(size_t which);

/* bench_rsa_sign_pkcs1: httpasm_rsa_sign_pkcs1 of the vector's digest, the key prepared once
 * before the loop (a server's certificate key, kept for its life). Deterministic: every call makes
 * the same signature. */
void bench_rsa_sign_pkcs1(const bench_build *b, const bench_case *c, long calls);

/* bench_rsa_sign_pss: a TLS 1.3 server's CertificateVerify under an RSA certificate (RFC 8446
 * 4.2.3 leaves it RSASSA-PSS alone): a 32-octet salt drawn with httpasm_random, then
 * httpasm_rsa_sign_pss of the vector's digest with SHA-256, each call; the key prepared once. */
void bench_rsa_sign_pss(const bench_build *b, const bench_case *c, long calls);

/* bench_rsa_private_init: httpasm_rsa_private_key_init alone: the public part prepared (R^2 mod n
 * by long division), the numbers checked (n = p q, dp, dq and q^-1 below their primes), each
 * prime's n0, R^2 (constant time) and R^3, q^-1 into Montgomery form, and a test signature of 2
 * checked under e (a whole CRT exponentiation: most of the time). A server's work once per key it
 * loads. */
void bench_rsa_private_init(const bench_build *b, const bench_case *c, long calls);

/* bench_hmac_sha384, bench_hkdf384_expand: the same over SHA-384, with a fixed 48-octet key or
 * PRK (a TLS_AES_256_GCM_SHA384 secret's size), `calls` times (suite_rivals.c). */
void bench_hmac_sha384(const bench_build *b, const bench_case *c, long calls);
void bench_hkdf384_expand(const bench_build *b, const bench_case *c, long calls);

/* bench_hpack_block: the HPACK block of a browser request's 18 fields, Huffman-coded and indexing
 * nothing, built by the first build's encoder on the first call and shared by every suite
 * (suite_rivals.c), so the tiers suite times the decoder's versions on the rivals' octets.
 *   data, length  out: the block. Returns 0, or -1 when there is no build or encoding fails. */
int bench_hpack_block(const uint8_t **data, size_t *length);

/* bench_hpack_decode: httpasm_hpack_decode of the case's block, `calls` times, with the build's
 * own decoder table (suite_rivals.c). A batch for either suite. */
void bench_hpack_decode(const bench_build *b, const bench_case *c, long calls);

/* The suites' registration functions, called by bench.c's main in this order. A suite whose
 * setup fails registers nothing and says why on stderr. */
void bench_suite_tiers(void);
void bench_suite_parsers(void);
void bench_suite_rivals(void);

#endif
