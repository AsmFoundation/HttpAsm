/*
 * httpasm.h - the C ABI of libhttpasm.so, HttpAsm's HTTP library in x86-64 assembly.
 *
 * Every HttpAsm consumer binds to these functions: the .NET adapters, C, Python, and NASM
 * programs (include/httpasm.inc, the same ABI). Linux x64 only for now; System V calling
 * convention. The structures' layouts are fixed: src/HttpAsm.Core/include/httpasm_abi.inc
 * declares the same offsets, and httpasm_struct_size() reports each size so a binding can
 * check its copy.
 *
 * Nothing is released yet. HTTPASM_ABI_VERSION is 0, and no compatibility is promised before
 * the first release: check httpasm_abi_version() against the header you compiled with.
 *
 * Memory: no function allocates. Parsers fill structures the caller provides, with pointers into
 * the caller's own buffer; those pointers are valid while that buffer is.
 */
#ifndef HTTPASM_H
#define HTTPASM_H

#include <stddef.h>
#include <stdint.h>

#include "httpasm_fields.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The ABI version these declarations describe. */
#define HTTPASM_ABI_VERSION 0

/* ------------------------------------------------------------------------------------------
 * Structures
 * ------------------------------------------------------------------------------------------ */

/* One field line (32 octets). name and value point into the caller's buffer and are not
 * NUL-terminated. id is the field's HTTPASM_FIELD_* id (httpasm_fields.h), 0 when it is not a
 * known field. */
typedef struct httpasm_field {
    const uint8_t *name;
    const uint8_t *value;
    uint32_t name_length;
    uint32_t value_length;
    uint16_t id;
    uint16_t flags;             /* HTTPASM_FIELD_FLAG_* */
    uint32_t reserved;
} httpasm_field;

#define HTTPASM_FIELD_FLAG_TRAILER 0x0001   /* the field came in a trailer section */
/* HPACK: decoder out, the field came as a literal never indexed; encoder in, encode it so. A
 * credential keeps this form when forwarded, so it never enters a compression context
 * (RFC 7541 6.2.3, 7.1.3). */
#define HTTPASM_FIELD_FLAG_NEVER_INDEXED 0x0002
/* HPACK encoder in: do not add this field to the dynamic table (a value that will not repeat). */
#define HTTPASM_FIELD_FLAG_NO_INDEX 0x0004

/* One request's head, as every HTTP version presents it (96 octets). */
typedef struct httpasm_request {
    const uint8_t *method;
    const uint8_t *target;      /* the request-target (HTTP/1.1) or :path (HTTP/2) */
    const uint8_t *authority;   /* HTTP/1.1: Host's value, or the authority of an absolute-form
                                   or authority-form target; HTTP/2: :authority. NULL if none. */
    const uint8_t *scheme;      /* an absolute-form target's scheme; HTTP/2: :scheme. Or NULL. */
    httpasm_field *fields;      /* the caller's array, filled from index 0 */
    uint64_t content_length;    /* with HTTPASM_REQUEST_CONTENT_LENGTH */
    uint32_t method_length;
    uint32_t target_length;
    uint32_t authority_length;
    uint32_t scheme_length;
    uint32_t field_count;
    uint32_t flags;             /* HTTPASM_REQUEST_* */
    uint32_t head_length;       /* HTTP/1.x: the head's octets, leading empty lines included */
    uint16_t method_id;         /* HTTPASM_METHOD_*, 0 for any other method */
    uint8_t version;            /* 10 = HTTP/1.0, 11 = HTTP/1.1, 20 = HTTP/2 */
    uint8_t target_form;        /* HTTPASM_TARGET_* */
    uint16_t error;             /* HTTPASM_ERROR_* when parsing failed, else 0 */
    uint16_t reserved0;
    uint32_t reserved1;
    uint64_t reserved2;
} httpasm_request;

#define HTTPASM_REQUEST_KEEP_ALIVE      0x0001  /* the connection persists after the response */
#define HTTPASM_REQUEST_CONTENT_LENGTH  0x0002  /* content_length is the body's length */
#define HTTPASM_REQUEST_CHUNKED         0x0004  /* the body is chunked */
#define HTTPASM_REQUEST_EXPECT_CONTINUE 0x0008  /* Expect: 100-continue (HTTP/1.1 and later) */
#define HTTPASM_REQUEST_HOST            0x0010  /* a Host field was present */
#define HTTPASM_REQUEST_TE_TRAILERS     0x0020  /* TE lists "trailers" */
#define HTTPASM_REQUEST_UPGRADE         0x0040  /* an Upgrade field was present */
#define HTTPASM_REQUEST_CLOSE           0x0080  /* Connection: close was present */

/* Methods of RFC 9110 section 9.3, and PATCH (RFC 5789). Methods are case-sensitive. */
#define HTTPASM_METHOD_GET      1
#define HTTPASM_METHOD_HEAD     2
#define HTTPASM_METHOD_POST     3
#define HTTPASM_METHOD_PUT      4
#define HTTPASM_METHOD_DELETE   5
#define HTTPASM_METHOD_CONNECT  6
#define HTTPASM_METHOD_OPTIONS  7
#define HTTPASM_METHOD_TRACE    8
#define HTTPASM_METHOD_PATCH    9

/* Request-target forms (RFC 9112 section 3.2). */
#define HTTPASM_TARGET_ORIGIN    1  /* "/path?query" */
#define HTTPASM_TARGET_ABSOLUTE  2  /* "http://host/path" */
#define HTTPASM_TARGET_AUTHORITY 3  /* "host:port", CONNECT only */
#define HTTPASM_TARGET_ASTERISK  4  /* "*", OPTIONS only */

/* Why a head was refused: httpasm_request.error. */
#define HTTPASM_ERROR_BARE_LF                1  /* a line ended in LF without CR */
#define HTTPASM_ERROR_METHOD                 2  /* the method is not a token */
#define HTTPASM_ERROR_REQUEST_LINE           3  /* not single-SP-separated elements */
#define HTTPASM_ERROR_TARGET                 4  /* an octet or escape a URI may not hold */
#define HTTPASM_ERROR_TARGET_TOO_LONG        5  /* 414 */
#define HTTPASM_ERROR_TARGET_FORM            6  /* the target's form does not suit the method */
#define HTTPASM_ERROR_VERSION                7  /* not HTTP-version's grammar */
#define HTTPASM_ERROR_VERSION_UNSUPPORTED    8  /* a major version other than 1: 505 */
#define HTTPASM_ERROR_OBS_FOLD               9  /* a line starts with whitespace */
#define HTTPASM_ERROR_FIELD_NAME            10  /* a field name is empty or not a token */
#define HTTPASM_ERROR_WHITESPACE_BEFORE_COLON 11
#define HTTPASM_ERROR_FIELD_VALUE           12  /* a control character in a field value */
#define HTTPASM_ERROR_HEAD_TOO_LARGE        13  /* 431 */
#define HTTPASM_ERROR_TOO_MANY_FIELDS       14  /* 431 */
#define HTTPASM_ERROR_HOST_MISSING          15  /* an HTTP/1.1 request without Host */
#define HTTPASM_ERROR_HOST_DUPLICATE        16
#define HTTPASM_ERROR_HOST_INVALID          17  /* Host is not uri-host [ ":" port ] (HTTP/1.1, HTTP/2) */
#define HTTPASM_ERROR_CONTENT_LENGTH        18  /* not 1*DIGIT, or values that differ */
#define HTTPASM_ERROR_TE_AND_CL             19  /* both Transfer-Encoding and Content-Length */
#define HTTPASM_ERROR_TE_HTTP10             20  /* Transfer-Encoding in an HTTP/1.0 message */
#define HTTPASM_ERROR_TE_NOT_CHUNKED        21  /* chunked missing, repeated, or not final */
#define HTTPASM_ERROR_TE_UNKNOWN            22  /* a coding not implemented yet: 501 */
#define HTTPASM_ERROR_EXPECT                23  /* an expectation other than 100-continue: 417 */
#define HTTPASM_ERROR_FRAMING_FIELD         24  /* a writer was given a field it owns */
#define HTTPASM_ERROR_STATUS                25  /* a status outside 100-599, or a bad status-line */
#define HTTPASM_ERROR_CHUNK                 26  /* malformed chunked framing */
#define HTTPASM_ERROR_AUTHORITY             27  /* an authority with octets Host may not hold */
/* HPACK decoding errors: in HTTP/2 each is a COMPRESSION_ERROR for the whole connection, since
 * the decoder's table can no longer be trusted to match the peer's encoder. */
#define HTTPASM_ERROR_HPACK_INDEX           28  /* index 0, or past both tables */
#define HTTPASM_ERROR_HPACK_INTEGER         29  /* past 2^32-1, or more than 5 continuation octets */
#define HTTPASM_ERROR_HPACK_TRUNCATED       30  /* the block ends inside a representation */
#define HTTPASM_ERROR_HPACK_HUFFMAN         31  /* EOS in a string, or bad padding */
#define HTTPASM_ERROR_HPACK_SIZE_UPDATE     32  /* a size update after a field, or above the limit */
#define HTTPASM_ERROR_HPACK_LIMIT           33  /* httpasm_hpack_init: limit too large, or memory too small */
/* HTTP/2 malformed requests (RFC 9113 8.1.1): a stream error PROTOCOL_ERROR for that request. */
#define HTTPASM_ERROR_H2_PSEUDO             34  /* a pseudo-field unknown, repeated, a response's,
                                                   after a regular field, or in trailers */
#define HTTPASM_ERROR_H2_MISSING            35  /* :method, :scheme or :path (CONNECT: :authority)
                                                   missing or empty */
#define HTTPASM_ERROR_H2_CONNECTION_FIELD   36  /* a connection-specific field, or TE but "trailers" */
#define HTTPASM_ERROR_H2_AUTHORITY          37  /* :authority empty, not uri-host [ ":" port ]
                                                   (userinfo included), a CONNECT's without a
                                                   port of 1-65535, or a Host naming another
                                                   authority */

/* What a server answers (48 octets), for httpasm_h1_write_response. flags is in and out. */
typedef struct httpasm_response {
    const httpasm_field *fields;    /* the handler's fields; never Content-Length,
                                       Transfer-Encoding, Connection, Keep-Alive, TE */
    const uint8_t *date;            /* a 29-octet IMF-fixdate, or NULL (no Date field) */
    uint64_t content_length;        /* with HTTPASM_RESPONSE_LENGTH */
    uint32_t field_count;
    uint32_t flags;                 /* HTTPASM_RESPONSE_* */
    uint16_t status;                /* 100-599 */
    uint8_t request_version;        /* the request's: 10 or 11 */
    uint8_t request_method;         /* the request's HTTPASM_METHOD_*: HEAD and CONNECT matter */
    uint32_t reserved;
    uint64_t reserved2;
} httpasm_response;

#define HTTPASM_RESPONSE_LENGTH   0x0001  /* in: content_length is the body's length */
#define HTTPASM_RESPONSE_CLOSE    0x0002  /* in/out: the connection closes after this response */
#define HTTPASM_RESPONSE_CHUNKED  0x0004  /* out: send the body chunked */
#define HTTPASM_RESPONSE_NO_BODY  0x0008  /* out: send nothing after the head */

/* A response's head as a client reads it (64 octets). */
typedef struct httpasm_response_head {
    const uint8_t *reason;
    httpasm_field *fields;          /* the caller's array */
    uint64_t content_length;        /* with HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH */
    uint32_t reason_length;
    uint32_t field_count;
    uint32_t flags;                 /* HTTPASM_RESPONSE_HEAD_* */
    uint32_t head_length;
    uint16_t status;                /* the 3DIGIT as received */
    uint8_t version;                /* 10, 11 */
    uint8_t reserved0;
    uint16_t error;                 /* HTTPASM_ERROR_* when parsing failed */
    uint16_t reserved1;
    uint64_t reserved2;
    uint64_t reserved3;
} httpasm_response_head;

#define HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH 0x0001 /* the body is content_length octets */
#define HTTPASM_RESPONSE_HEAD_CHUNKED       0x0002  /* the body is chunked */
#define HTTPASM_RESPONSE_HEAD_UNTIL_CLOSE   0x0004  /* the body runs until the server closes */
#define HTTPASM_RESPONSE_HEAD_NO_BODY       0x0008  /* no body (HEAD, 1xx, 204, 304) */
#define HTTPASM_RESPONSE_HEAD_TUNNEL        0x0010  /* a 2xx to CONNECT */
#define HTTPASM_RESPONSE_HEAD_KEEP_ALIVE    0x0020  /* the connection may carry another request */

/* The chunked decoder's state between calls (32 octets): zero it before each body. */
typedef struct httpasm_h1_chunked {
    uint64_t remaining;             /* data octets left in the current chunk */
    uint64_t total;                 /* data octets decoded so far */
    uint32_t state;                 /* HTTPASM_CHUNKED_* */
    uint32_t extension_length;
    uint32_t size_digits;
    uint32_t reserved;
} httpasm_h1_chunked;

#define HTTPASM_CHUNKED_SIZE      0
#define HTTPASM_CHUNKED_EXTENSION 1
#define HTTPASM_CHUNKED_SIZE_LF   2
#define HTTPASM_CHUNKED_DATA      3
#define HTTPASM_CHUNKED_DATA_CR   4
#define HTTPASM_CHUNKED_DATA_LF   5
#define HTTPASM_CHUNKED_TRAILERS  6   /* the last chunk was read: the trailer section follows */
#define HTTPASM_CHUNKED_ERROR     7
#define HTTPASM_CHUNKED_EXTENSION_BWS 8 /* whitespace after chunk-size: only ";" may follow */

/* What one HTTP/1.1 head may take (16 octets). A zero field takes its default. */
typedef struct httpasm_h1_limits {
    uint32_t max_head;          /* the head's octets; default 65536 (431 beyond) */
    uint32_t max_target;        /* the request-target's octets; default 8192 (414 beyond) */
    uint32_t max_fields;        /* field lines; the fields array holds this many; default 128 */
    uint32_t reserved;
} httpasm_h1_limits;

/* Where httpasm_hpack_decode puts a header block's fields (48 octets). Names and values from
 * HPACK's static table point at the library's constant text; all others are copied into space,
 * so the records stay valid however the dynamic table changes afterwards. */
typedef struct httpasm_hpack_output {
    httpasm_field *fields;      /* the caller's array */
    uint8_t *space;             /* decoded names and values go here */
    size_t space_size;
    size_t space_used;          /* out */
    uint64_t list_size;         /* out: RFC 9113 6.5.2's header list size (name + value + 32 per
                                   field), over every field, those that did not fit included */
    uint32_t max_fields;
    uint32_t count;             /* out: records written */
} httpasm_hpack_output;

/* ------------------------------------------------------------------------------------------
 * The library
 * ------------------------------------------------------------------------------------------ */

/* The ABI version of the loaded library. A program compiled against this header should refuse a
 * library whose version differs from HTTPASM_ABI_VERSION: before the first release, any change
 * may break the ABI. */
uint32_t httpasm_abi_version(void);

/* The size of one of the ABI's structures, for bindings to check their copies: 1 httpasm_field,
 * 2 httpasm_request, 3 httpasm_h1_limits, 4 httpasm_response, 5 httpasm_response_head,
 * 6 httpasm_h1_chunked, 7 httpasm_server_options, 8 httpasm_hpack_output, 9 httpasm_client_response,
 * 10 httpasm_sha256_ctx, 11 httpasm_hmac_sha256_ctx, 12 httpasm_sha512_ctx,
 * 13 httpasm_hmac_sha384_ctx, 14 httpasm_aes_key, 15 httpasm_aes_gcm_key,
 * 16 httpasm_rsa_public_key, 17 httpasm_rsa_private_key, 18 httpasm_rsa_private_numbers,
 * 19 httpasm_ed25519_private_key, 20 httpasm_sha3_ctx, 21 httpasm_ed448_private_key,
 * 22 httpasm_hmac_sha512_ctx, 23 httpasm_asn1, 24 httpasm_pem, 25 httpasm_private_key,
 * 26 httpasm_certificate, 27 httpasm_public_key, 28 httpasm_tls13_record_key,
 * 29 httpasm_tls_extensions, 30 httpasm_tls13_hello, 31 httpasm_tls13_server_config,
 * 32 httpasm_tls13_event, 33 httpasm_tls13_connection; 0 for any other value. */
uint32_t httpasm_struct_size(uint32_t which);

/* ------------------------------------------------------------------------------------------
 * CPU tiers. Each hot routine has a baseline x86-64 version and faster ones (SSE4.2, AVX2,
 * AVX-512, AES-NI, ...); the library picks the best one the CPU and the OS allow when it loads.
 * Every version computes the same results, so the choice changes speed, never behavior.
 * The environment variable HTTPASM_CPU caps the choice when the library loads (as
 * OPENSSL_ia32cap does for OpenSSL): "native" or unset for everything; "v1" to "v4" for at most
 * that x86-64 level; then ",-group" items to drop groups ("v3,-vaes", "-sha"). An invalid value
 * selects v1, the baseline, so a typo never leaves faster code running unnoticed.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_CPU_V2          (1u << 0)   /* x86-64-v2: SSE3, SSSE3, SSE4.1/4.2, POPCNT, CX16 */
#define HTTPASM_CPU_V3          (1u << 1)   /* x86-64-v3: AVX, AVX2, BMI1/2, FMA, LZCNT, MOVBE */
#define HTTPASM_CPU_V4          (1u << 2)   /* x86-64-v4: AVX-512 F, BW, CD, DQ, VL */
#define HTTPASM_CPU_AESNI       (1u << 8)
#define HTTPASM_CPU_CLMUL       (1u << 9)   /* PCLMULQDQ */
#define HTTPASM_CPU_SHA         (1u << 10)  /* SHA-1/SHA-256 extensions */
#define HTTPASM_CPU_GFNI        (1u << 11)
#define HTTPASM_CPU_BMI2        (1u << 12)  /* counted with v3 */
#define HTTPASM_CPU_ADX         (1u << 13)  /* counted with v3 */
#define HTTPASM_CPU_VAES        (1u << 14)  /* needs v3 (YMM) or v4 (ZMM) */
#define HTTPASM_CPU_VCLMUL      (1u << 15)  /* VPCLMULQDQ; needs v3 or v4 */
#define HTTPASM_CPU_SHA512      (1u << 16)  /* needs v3 */
#define HTTPASM_CPU_IFMA        (1u << 17)  /* AVX512-IFMA; needs v4 */
#define HTTPASM_CPU_VBMI        (1u << 18)  /* needs v4 */
#define HTTPASM_CPU_VBMI2       (1u << 19)  /* needs v4 */
#define HTTPASM_CPU_ALL         (HTTPASM_CPU_V2 | HTTPASM_CPU_V3 | HTTPASM_CPU_V4 | HTTPASM_CPU_AESNI | HTTPASM_CPU_CLMUL | HTTPASM_CPU_SHA | HTTPASM_CPU_GFNI | HTTPASM_CPU_BMI2 | HTTPASM_CPU_ADX | HTTPASM_CPU_VAES | HTTPASM_CPU_VCLMUL | HTTPASM_CPU_SHA512 | HTTPASM_CPU_IFMA | HTTPASM_CPU_VBMI | HTTPASM_CPU_VBMI2)
/* The caps "v1" to "v4" set: each level with the groups its encodings allow. */
#define HTTPASM_CPU_CAP_V1      0u
#define HTTPASM_CPU_CAP_V2      (HTTPASM_CPU_V2 | HTTPASM_CPU_AESNI | HTTPASM_CPU_CLMUL | HTTPASM_CPU_SHA | HTTPASM_CPU_GFNI)
#define HTTPASM_CPU_CAP_V3      (HTTPASM_CPU_CAP_V2 | HTTPASM_CPU_V3 | HTTPASM_CPU_BMI2 | HTTPASM_CPU_ADX | HTTPASM_CPU_VAES | HTTPASM_CPU_VCLMUL | HTTPASM_CPU_SHA512)
#define HTTPASM_CPU_CAP_V4      (HTTPASM_CPU_CAP_V3 | HTTPASM_CPU_V4 | HTTPASM_CPU_IFMA | HTTPASM_CPU_VBMI | HTTPASM_CPU_VBMI2)

/* What the CPU and the OS offer (HTTPASM_CPU_* bits), read when the library loaded. */
uint64_t httpasm_cpu_found(void);

/* What the library uses: httpasm_cpu_found narrowed by the cap, with every group whose level is
 * missing dropped (no VAES without v3, no IFMA without v4). */
uint64_t httpasm_cpu_features(void);

/* Replaces the cap (HTTPASM_CPU's included) and returns the new httpasm_cpu_features():
 * HTTPASM_CPU_CAP_V1 forces the baseline, HTTPASM_CPU_ALL restores everything. Meant for tests
 * and measurements that compare tiers in one process. Safe while other threads run HttpAsm
 * code: every tier computes the same results. */
uint64_t httpasm_cpu_limit(uint64_t cap);

/* ------------------------------------------------------------------------------------------
 * Hashes (FIPS 180-4). No function allocates or fails; none branches or picks an address by
 * the data, so hashing a secret shows nothing but its length.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_SHA256_DIGEST 32    /* octets of a SHA-256 digest */
#define HTTPASM_SHA256_BLOCK  64    /* octets of a SHA-256 block (HMAC pads its key to one) */

/* A running SHA-256 hash (112 octets). Its octets are its whole state: a copy forks the hash
 * (a TLS transcript hashed up to one message and then on). */
typedef struct httpasm_sha256_ctx {
    uint32_t state[8];              /* H0-H7 */
    uint64_t length;                /* octets fed so far */
    uint8_t buffer[64];             /* the next block's first octets */
    uint32_t buffered;              /* how many of them */
    uint32_t reserved;
} httpasm_sha256_ctx;

/* Starts a hash (or starts it over). */
void httpasm_sha256_init(httpasm_sha256_ctx *h);

/* Feeds n octets (n may be 0). The whole message must stay below 2^61 octets. */
void httpasm_sha256_update(httpasm_sha256_ctx *h, const uint8_t *data, size_t n);

/* Writes the digest of everything fed, then wipes h to zeros (it held the message's last
 * octets): call httpasm_sha256_init before feeding it again. */
void httpasm_sha256_final(httpasm_sha256_ctx *h, uint8_t digest[HTTPASM_SHA256_DIGEST]);

/* The digest of n octets at once. */
void httpasm_sha256(const uint8_t *data, size_t n, uint8_t digest[HTTPASM_SHA256_DIGEST]);

#define HTTPASM_SHA512_DIGEST 64    /* octets of a SHA-512 digest */
#define HTTPASM_SHA384_DIGEST 48    /* octets of a SHA-384 digest */
#define HTTPASM_SHA512_BLOCK  128   /* octets of a SHA-512 (and SHA-384) block */

/* A running SHA-512 or SHA-384 hash (208 octets): the two differ only in their start (init) and
 * in how much of the state their final writes, so they share this context and the update. As
 * with SHA-256, a copy forks the hash. Feeding a SHA-384 context to httpasm_sha512_final (or the
 * reverse) gives neither digest: finish a hash with the final of the init that started it. */
typedef struct httpasm_sha512_ctx {
    uint64_t state[8];              /* H0-H7 */
    uint64_t length;                /* octets fed so far */
    uint8_t buffer[128];            /* the next block's first octets */
    uint32_t buffered;              /* how many of them */
    uint32_t reserved;
} httpasm_sha512_ctx;

/* Starts a SHA-512 hash, or a SHA-384 one (or starts it over). */
void httpasm_sha512_init(httpasm_sha512_ctx *h);
void httpasm_sha384_init(httpasm_sha512_ctx *h);

/* Feeds n octets to either (n may be 0). The whole message must stay below 2^61 octets: the
 * length is counted in octets, and FIPS 180-4's 2^128-bit bound is far past any TLS use. */
void httpasm_sha512_update(httpasm_sha512_ctx *h, const uint8_t *data, size_t n);

/* Write the digest of everything fed (64 octets for SHA-512, 48 for SHA-384), then wipe h to
 * zeros: call an init before feeding it again. */
void httpasm_sha512_final(httpasm_sha512_ctx *h, uint8_t digest[HTTPASM_SHA512_DIGEST]);
void httpasm_sha384_final(httpasm_sha512_ctx *h, uint8_t digest[HTTPASM_SHA384_DIGEST]);

/* The digests of n octets at once. */
void httpasm_sha512(const uint8_t *data, size_t n, uint8_t digest[HTTPASM_SHA512_DIGEST]);
void httpasm_sha384(const uint8_t *data, size_t n, uint8_t digest[HTTPASM_SHA384_DIGEST]);

/* SHA-3 and SHAKE (FIPS 202): ML-KEM's hashes (SHA3-256, SHA3-512) and XOFs (SHAKE128,
 * SHAKE256), for TLS 1.3's post-quantum hybrids. Keccak-f[1600] with rorx and andn (v3) or
 * plain rotates (v1). */
#define HTTPASM_SHA3_224_DIGEST 28
#define HTTPASM_SHA3_256_DIGEST 32
#define HTTPASM_SHA3_384_DIGEST 48
#define HTTPASM_SHA3_512_DIGEST 64

/* A running SHA3-224/256/384/512 or SHAKE128/256 (216 octets): the sponge's state, into which
 * input octets are XORed at once (no buffer), and where it stands. A copy forks it. */
typedef struct httpasm_sha3_ctx {
    uint64_t state[25];             /* the Keccak lanes */
    uint32_t rate;                  /* octets a block */
    uint32_t position;              /* octets absorbed into, or squeezed from, the current block */
    uint8_t suffix;                 /* 0x06 for SHA-3, 0x1F for SHAKE */
    uint8_t squeezing;              /* 1 once the input is padded */
    uint8_t reserved[6];
} httpasm_sha3_ctx;

/* Starts (or starts over) a hash or an XOF of the kind named. */
void httpasm_sha3_224_init(httpasm_sha3_ctx *h);
void httpasm_sha3_256_init(httpasm_sha3_ctx *h);
void httpasm_sha3_384_init(httpasm_sha3_ctx *h);
void httpasm_sha3_512_init(httpasm_sha3_ctx *h);
void httpasm_shake128_init(httpasm_sha3_ctx *h);
void httpasm_shake256_init(httpasm_sha3_ctx *h);

/* Feeds n octets (n may be 0) to any of them, before its final or first squeeze. */
void httpasm_sha3_update(httpasm_sha3_ctx *h, const uint8_t *data, size_t n);

/* Writes the digest of everything fed - 28, 32, 48 or 64 octets, by the init that started h (a
 * SHAKE context gives its first 16 or 32 octets) - then wipes h to zeros. */
void httpasm_sha3_final(httpasm_sha3_ctx *h, uint8_t *digest);

/* Writes the next n octets of a SHAKE's output: the first call ends the input, later calls go
 * on with the same stream (pieces of any sizes give what one call would). h is not wiped, as
 * more may follow: zero it when done if the input was secret. */
void httpasm_shake_squeeze(httpasm_sha3_ctx *h, uint8_t *out, size_t n);

/* All at once: the SHA-3 digests, and out_n octets of SHAKE128 or SHAKE256 (out_n may be 0). */
void httpasm_sha3_224(const uint8_t *data, size_t n, uint8_t digest[HTTPASM_SHA3_224_DIGEST]);
void httpasm_sha3_256(const uint8_t *data, size_t n, uint8_t digest[HTTPASM_SHA3_256_DIGEST]);
void httpasm_sha3_384(const uint8_t *data, size_t n, uint8_t digest[HTTPASM_SHA3_384_DIGEST]);
void httpasm_sha3_512(const uint8_t *data, size_t n, uint8_t digest[HTTPASM_SHA3_512_DIGEST]);
void httpasm_shake128(const uint8_t *data, size_t n, uint8_t *out, size_t out_n);
void httpasm_shake256(const uint8_t *data, size_t n, uint8_t *out, size_t out_n);

/* ------------------------------------------------------------------------------------------
 * The block cipher: AES-128 and AES-256 encryption (FIPS 197), the base of AES-GCM and of
 * QUIC's header protection. With AES-NI where the CPU has it; otherwise a constant-time
 * bitsliced version that looks nothing up by key or data.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_AES_BLOCK 16        /* octets of an AES block */

/* An expanded AES key (496 octets): both versions' round keys, so a key made at one CPU tier
 * works at any other. It holds the key's secret: wipe it when done (explicit_bzero). */
typedef struct httpasm_aes_key {
    uint8_t round_keys[240];        /* FIPS 197's schedule, 16 octets a round */
    uint8_t ct[240];                /* the constant-time version's, compressed */
    uint32_t rounds;                /* 10 (AES-128) or 14 (AES-256) */
    uint32_t reserved[3];
} httpasm_aes_key;

/* Expands a 16-octet (AES-128) or 32-octet (AES-256) key. Returns 0, or -1 for any other
 * length (k is then untouched). */
int httpasm_aes_init(httpasm_aes_key *k, const uint8_t *key, size_t length);

/* Encrypts one block (in and out may be the same octets). */
void httpasm_aes_encrypt_block(const httpasm_aes_key *k, const uint8_t in[HTTPASM_AES_BLOCK],
                               uint8_t out[HTTPASM_AES_BLOCK]);

/* ------------------------------------------------------------------------------------------
 * AES-GCM (NIST SP 800-38D) as TLS 1.3 and QUIC use it: AES-128 or AES-256, 12-octet nonces,
 * 16-octet tags. Versions: VAES with VPCLMULQDQ (two blocks an instruction), AES-NI with
 * PCLMULQDQ, and a constant-time v1 (the bitsliced cipher, a GHASH by integer multiplications).
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_AES_GCM_NONCE 12        /* octets of a nonce */
#define HTTPASM_AES_GCM_TAG   16        /* octets of a tag */

/* An AES-GCM key (1024 octets): the AES key, H = E_K(0), and GHASH's precomputed powers of H.
 * Made once per key; read-only afterwards, so one key may serve several threads. It holds the
 * key's secret: wipe it when done (explicit_bzero). */
typedef struct httpasm_aes_gcm_key {
    httpasm_aes_key aes;
    uint8_t h[16];
    uint8_t htable[256];            /* H^16 .. H^1 in the carry-less-multiply versions' form */
    uint8_t hkara[256];             /* each power's two halves xored (Karatsuba) */
} httpasm_aes_gcm_key;

/* Makes an AES-GCM key from 16 (AES-128-GCM) or 32 (AES-256-GCM) octets. Returns 0, or -1 for
 * any other length (k is then untouched). */
int httpasm_aes_gcm_init(httpasm_aes_gcm_key *k, const uint8_t *key, size_t length);

/* Encrypts in[0..length) into out (out may be in, or must not overlap it) and writes the tag
 * over aad[0..aad_length) and the ciphertext. Returns 0, or -1 when length exceeds
 * 2^36 - 32 octets or aad_length 2^61 - 1 (SP 800-38D's limits; nothing is written then).
 * Never reuse a nonce under a key: GCM's confidentiality and integrity both fall. */
int httpasm_aes_gcm_seal(const httpasm_aes_gcm_key *k, const uint8_t nonce[HTTPASM_AES_GCM_NONCE],
                         const uint8_t *aad, size_t aad_length, const uint8_t *in, size_t length,
                         uint8_t *out, uint8_t tag[HTTPASM_AES_GCM_TAG]);

/* Verifies the tag over aad and in[0..length) and decrypts into out (out may be in, or must not
 * overlap it). Returns 0; or -1 when the tag does not match (out[0..length) is then all zeros:
 * no unauthenticated plaintext is left) or a length exceeds the limits of seal (nothing is
 * written). The tag comparison takes the same time whichever octet differs. */
int httpasm_aes_gcm_open(const httpasm_aes_gcm_key *k, const uint8_t nonce[HTTPASM_AES_GCM_NONCE],
                         const uint8_t *aad, size_t aad_length, const uint8_t *in, size_t length,
                         const uint8_t tag[HTTPASM_AES_GCM_TAG], uint8_t *out);

/* ------------------------------------------------------------------------------------------
 * ChaCha20, Poly1305 and ChaCha20-Poly1305 (RFC 8439), TLS 1.3's TLS_CHACHA20_POLY1305_SHA256
 * and QUIC's. Keys are raw octets: ChaCha20 keeps no schedule, and Poly1305's key is new for
 * every message. Versions: AVX2 (eight blocks at once), SSSE3 and SSE2 (four), each with
 * Poly1305 interleaved in the AEAD; every one constant time.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_CHACHA20_KEY   32       /* octets of a ChaCha20 (and AEAD) key */
#define HTTPASM_CHACHA20_NONCE 12       /* octets of its nonce */
#define HTTPASM_POLY1305_KEY   32       /* octets of a one-time Poly1305 key (r, then s) */
#define HTTPASM_POLY1305_TAG   16       /* octets of a Poly1305 tag, and of the AEAD's */

/* Xors in[0..length) with ChaCha20's keystream from block `counter` on into out (out may be in,
 * or must not overlap it). The block counter is 32 bits and wraps with the nonce unchanged, so
 * past (2^32 - counter) * 64 octets the keystream repeats: the caller stays below that. QUIC's
 * header protection is one call over five zero octets (RFC 9001 5.4.4). */
void httpasm_chacha20(const uint8_t key[HTTPASM_CHACHA20_KEY], uint32_t counter,
                      const uint8_t nonce[HTTPASM_CHACHA20_NONCE], const uint8_t *in, size_t length,
                      uint8_t *out);

/* The one-time authenticator: tag = Poly1305 over message[0..length) under key (r is clamped
 * here). A key must never authenticate two messages: two tags under one key give it away. */
void httpasm_poly1305(const uint8_t key[HTTPASM_POLY1305_KEY], const uint8_t *message, size_t length,
                      uint8_t tag[HTTPASM_POLY1305_TAG]);

/* Encrypts in[0..length) into out (out may be in, or must not overlap it) and writes the tag
 * over aad[0..aad_length) and the ciphertext. Returns 0, or -1 when length exceeds 2^38 - 64
 * octets (the 32-bit block counter's reach from 1; nothing is written then). Never reuse a nonce
 * under a key: the keystream and the Poly1305 key both repeat, and forgeries follow. */
int httpasm_chacha20_poly1305_seal(const uint8_t key[HTTPASM_CHACHA20_KEY],
                                   const uint8_t nonce[HTTPASM_CHACHA20_NONCE], const uint8_t *aad,
                                   size_t aad_length, const uint8_t *in, size_t length, uint8_t *out,
                                   uint8_t tag[HTTPASM_POLY1305_TAG]);

/* Verifies the full 16-octet tag over aad and in[0..length) and decrypts into out (out may be in,
 * or must not overlap it). Returns 0; or -1 when the tag does not match (out[0..length) is then
 * all zeros) or length exceeds seal's limit (nothing is written). The comparison takes the same
 * time whichever octet differs. */
int httpasm_chacha20_poly1305_open(const uint8_t key[HTTPASM_CHACHA20_KEY],
                                   const uint8_t nonce[HTTPASM_CHACHA20_NONCE], const uint8_t *aad,
                                   size_t aad_length, const uint8_t *in, size_t length,
                                   const uint8_t tag[HTTPASM_POLY1305_TAG], uint8_t *out);

/* ------------------------------------------------------------------------------------------
 * X25519 (RFC 7748), TLS 1.3's first key exchange group. Versions: mulx with adcx/adox (BMI2 and
 * ADX) on four 64-bit limbs, and mul on five 51-bit limbs; both constant time.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_X25519_KEY 32           /* octets of a scalar, a u-coordinate, a shared secret */

/* out = X25519(scalar, point): the shared secret of a private scalar and a peer's public
 * u-coordinate (its bit 255 is ignored, and values from p up are taken modulo p, as RFC 7748
 * requires). Returns 0; or -1 when out is all zeros, which a point of small order gives: TLS 1.3
 * must abort then (RFC 9846 7.4.2), and the zeros are written all the same. The scalar is
 * clamped here: any 32 random octets are a valid private key. */
int httpasm_x25519(uint8_t out[HTTPASM_X25519_KEY], const uint8_t scalar[HTTPASM_X25519_KEY],
                   const uint8_t point[HTTPASM_X25519_KEY]);

/* out = X25519(scalar, 9): the public key of a private scalar (never all zeros). Computed from
 * edwards25519's precomputed fixed base (Ed25519's table, constant time), not the ladder: the
 * same octets in about a quarter of a shared secret's time. */
void httpasm_x25519_public_key(uint8_t out[HTTPASM_X25519_KEY], const uint8_t scalar[HTTPASM_X25519_KEY]);

/* ------------------------------------------------------------------------------------------
 * X448 (RFC 7748), TLS 1.3's x448 group. The field in eight 56-bit limbs at both versions (mulx,
 * or mul), Karatsuba over 2^224; the ladder computes its products in pairs, interleaved; the
 * public key comes from Ed448's fixed base (the 4-isogeny takes its B to u = 5). Both constant
 * time. Stack (tests/native/stack measures it): 2,248 octets for a shared secret, 6,472 for a
 * public key (Ed448's frame).
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_X448_KEY 56             /* octets of a scalar, a u-coordinate, a shared secret */

/* out = X448(scalar, point): the shared secret of a private scalar and a peer's public
 * u-coordinate (values from p up are taken modulo p, as RFC 7748 requires; X448 masks no bit).
 * Returns 0; or -1 when out is all zeros, which a point of small order gives: TLS 1.3 must abort
 * then (RFC 9846 7.4.2), and the zeros are written all the same. The scalar is clamped here: any
 * 56 random octets are a valid private key. out may be the scalar or the point (it is written
 * last). */
int httpasm_x448(uint8_t out[HTTPASM_X448_KEY], const uint8_t scalar[HTTPASM_X448_KEY],
                 const uint8_t point[HTTPASM_X448_KEY]);

/* out = X448(scalar, 5): the public key of a private scalar, from edwards448's precomputed fixed
 * base ((y / x)^2 of scalar B: the same octets as the ladder at u = 5, about a third of a shared
 * secret's time, constant time). Returns 0; or -1 when out is all zeros,
 * which one clamped scalar gives: 4q, q the base point's prime order (X448's clamped range,
 * unlike X25519's, holds a multiple of q; a random scalar never meets it, but such a key share
 * would make every peer abort). */
int httpasm_x448_public_key(uint8_t out[HTTPASM_X448_KEY], const uint8_t scalar[HTTPASM_X448_KEY]);

/* ------------------------------------------------------------------------------------------
 * NIST P-256 (SP 800-186; TLS's secp256r1): ECDH for TLS 1.3's secp256r1 key share and
 * SecP256r1MLKEM768, ECDSA (FIPS 186-5) for ecdsa_secp256r1_sha256 and certificates. Versions:
 * mulx with adcx/adox and AVX2 table scans, and mul with SSE2; all constant time in the private
 * key, the nonce and the peer's point (verification's inputs are public).
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_P256_SCALAR    32       /* octets of a private key, a shared secret, r or s */
#define HTTPASM_P256_POINT     65       /* octets of a public key: 04 || x || y (SEC 1, uncompressed) */
#define HTTPASM_P256_SIGNATURE 64       /* octets of a signature: r || s (IEEE P1363's form) */
#define HTTPASM_P256_ENTROPY   32       /* octets of a signature's optional entropy */

/* The public key of a private key d (32 big-endian octets, 1 <= d < n): 04 || x || y of d G,
 * the uncompressed form a TLS 1.3 key share carries (RFC 9846 4.2.8.2). Returns 0; or -1 when d
 * is 0 or n or more (out is then all zeros): to make a key, draw 32 random octets until this
 * succeeds (a draw fails about once in 2^32). */
int httpasm_p256_public_key(uint8_t public_key[HTTPASM_P256_POINT],
                            const uint8_t private_key[HTTPASM_P256_SCALAR]);

/* ECDH: shared = the x-coordinate of d Q (32 big-endian octets, the premaster secret TLS uses),
 * for a private key d and a peer's public key Q. Returns 0; or -1 when d is out of range or Q
 * is not a point of the curve in uncompressed form (a first octet other than 04, a coordinate p
 * or more, the curve equation failing: RFC 9846 4.2.8.2's checks, which also stop the
 * invalid-curve attack); shared is all zeros then. */
int httpasm_p256_ecdh(uint8_t shared[HTTPASM_P256_SCALAR], const uint8_t private_key[HTTPASM_P256_SCALAR],
                      const uint8_t peer_key[HTTPASM_P256_POINT]);

/* ECDSA: signs a message digest (digest_length octets, any hash: its leftmost 256 bits are used,
 * as FIPS 186-5 6.4.1 says) with a private key. The nonce is RFC 6979's deterministic k
 * (HMAC-SHA256: exactly RFC 6979's for a SHA-256 digest), with entropy[0..32) mixed in as RFC
 * 6979 3.6's extra input when entropy is not NULL (pass 32 random octets: a hedged signature
 * keeps the key safe from a weak random generator and from faults alike). Returns 0; or -1
 * when the private key is out of range (signature is then all zeros). */
int httpasm_p256_sign(uint8_t signature[HTTPASM_P256_SIGNATURE],
                      const uint8_t private_key[HTTPASM_P256_SCALAR], const uint8_t *digest,
                      size_t digest_length, const uint8_t *entropy);

/* ECDSA: verifies signature (r || s) over a digest (as httpasm_p256_sign takes it) under a public
 * key. Returns 0 when valid; -1 otherwise: r or s not in [1, n - 1], the key not an uncompressed
 * point of the curve, or the equation failing. */
int httpasm_p256_verify(const uint8_t public_key[HTTPASM_P256_POINT], const uint8_t *digest,
                        size_t digest_length, const uint8_t signature[HTTPASM_P256_SIGNATURE]);

/* ------------------------------------------------------------------------------------------
 * NIST P-384 (SP 800-186; TLS's secp384r1): ECDH for TLS 1.3's secp384r1 key share and
 * SecP384r1MLKEM1024, ECDSA (FIPS 186-5) for ecdsa_secp384r1_sha384 and the certificates of
 * P-384 roots and intermediates (a TLS client verifies their signatures in every such chain).
 * P-256's functions at 48-octet scalars; the same versions and the same constant-time rules.
 * Stack: up to about 7 KiB (7,392 octets: a signature at the best tier, measured by
 * tests/native/stack), touched a page at a time on the way down (no stack clash).
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_P384_SCALAR    48       /* octets of a private key, a shared secret, r or s */
#define HTTPASM_P384_POINT     97       /* octets of a public key: 04 || x || y (SEC 1, uncompressed) */
#define HTTPASM_P384_SIGNATURE 96       /* octets of a signature: r || s (IEEE P1363's form) */
#define HTTPASM_P384_ENTROPY   48       /* octets of a signature's optional entropy */

/* The public key of a private key d (48 big-endian octets, 1 <= d < n): 04 || x || y of d G.
 * Returns 0; or -1 when d is 0 or n or more (out is then all zeros): to make a key, draw 48
 * random octets until this succeeds (a draw fails about once in 2^189). */
int httpasm_p384_public_key(uint8_t public_key[HTTPASM_P384_POINT],
                            const uint8_t private_key[HTTPASM_P384_SCALAR]);

/* ECDH: shared = the x-coordinate of d Q (48 big-endian octets), for a private key d and a peer's
 * public key Q. Returns 0; or -1 when d is out of range or Q is not a point of the curve in
 * uncompressed form (a first octet other than 04, a coordinate p or more, the curve equation
 * failing: RFC 9846 4.2.8.2's checks); shared is all zeros then. */
int httpasm_p384_ecdh(uint8_t shared[HTTPASM_P384_SCALAR], const uint8_t private_key[HTTPASM_P384_SCALAR],
                      const uint8_t peer_key[HTTPASM_P384_POINT]);

/* ECDSA: signs a message digest (digest_length octets, any hash: its leftmost 384 bits are used,
 * as FIPS 186-5 6.4.1 says) with a private key. The nonce is RFC 6979's deterministic k
 * (HMAC-SHA384: exactly RFC 6979's for a SHA-384 digest), with entropy[0..48) mixed in as RFC
 * 6979 3.6's extra input when entropy is not NULL (pass 48 random octets: a hedged signature).
 * Returns 0; or -1 when the private key is out of range (signature is then all zeros). */
int httpasm_p384_sign(uint8_t signature[HTTPASM_P384_SIGNATURE],
                      const uint8_t private_key[HTTPASM_P384_SCALAR], const uint8_t *digest,
                      size_t digest_length, const uint8_t *entropy);

/* ECDSA: verifies signature (r || s) over a digest (as httpasm_p384_sign takes it) under a public
 * key. Returns 0 when valid; -1 otherwise: r or s not in [1, n - 1], the key not an uncompressed
 * point of the curve, or the equation failing. */
int httpasm_p384_verify(const uint8_t public_key[HTTPASM_P384_POINT], const uint8_t *digest,
                        size_t digest_length, const uint8_t signature[HTTPASM_P384_SIGNATURE]);

/* ------------------------------------------------------------------------------------------
 * NIST P-521 (SP 800-186; TLS's secp521r1): ECDH for TLS 1.3's secp521r1 key share, ECDSA (FIPS
 * 186-5) for ecdsa_secp521r1_sha512 and the certificates that use it. P-256's functions at
 * 66-octet scalars and coordinates (ceil(521 / 8)); the same versions (v3: mulx with adcx/adox
 * and AVX2 table scans; v1: mul and SSE2) and the same constant-time rules.
 * Stack: up to about 10 KiB (10,112 octets: a signature at the best tier, measured by
 * tests/native/stack; 8,912 at v1), touched a page at a time on the way down (no stack clash).
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_P521_SCALAR    66       /* octets of a private key, a shared secret, r or s */
#define HTTPASM_P521_POINT     133      /* octets of a public key: 04 || x || y (SEC 1, uncompressed) */
#define HTTPASM_P521_SIGNATURE 132      /* octets of a signature: r || s (IEEE P1363's form) */
#define HTTPASM_P521_ENTROPY   66       /* octets of a signature's optional entropy */

/* The public key of a private key d (66 big-endian octets, 1 <= d < n): 04 || x || y of d G.
 * Returns 0; or -1 when d is 0 or n or more (out is then all zeros): any value with a bit set
 * above bit 520 (the first octet above 01) is n or more. To make a key, draw 66 random octets,
 * clear the first octet's seven high bits, and retry while this fails (about once in 2^260). */
int httpasm_p521_public_key(uint8_t public_key[HTTPASM_P521_POINT],
                            const uint8_t private_key[HTTPASM_P521_SCALAR]);

/* ECDH: shared = the x-coordinate of d Q (66 big-endian octets), for a private key d and a peer's
 * public key Q. Returns 0; or -1 when d is out of range or Q is not a point of the curve in
 * uncompressed form (a first octet other than 04, a coordinate p or more, the curve equation
 * failing: RFC 9846 4.2.8.2's checks); shared is all zeros then. */
int httpasm_p521_ecdh(uint8_t shared[HTTPASM_P521_SCALAR], const uint8_t private_key[HTTPASM_P521_SCALAR],
                      const uint8_t peer_key[HTTPASM_P521_POINT]);

/* ECDSA: signs a message digest (digest_length octets, any hash: its leftmost 521 bits are used,
 * as FIPS 186-5 6.4.1 says, so SHA-512's 64 octets are taken whole) with a private key. The nonce
 * is RFC 6979's deterministic k (HMAC-SHA512: exactly RFC 6979's for a SHA-512 digest), with
 * entropy[0..66) mixed in as RFC 6979 3.6's extra input when entropy is not NULL (pass 66 random
 * octets: a hedged signature). Returns 0; or -1 when the private key is out of range (signature
 * is then all zeros). */
int httpasm_p521_sign(uint8_t signature[HTTPASM_P521_SIGNATURE],
                      const uint8_t private_key[HTTPASM_P521_SCALAR], const uint8_t *digest,
                      size_t digest_length, const uint8_t *entropy);

/* ECDSA: verifies signature (r || s) over a digest (as httpasm_p521_sign takes it) under a public
 * key. Returns 0 when valid; -1 otherwise: r or s not in [1, n - 1], the key not an uncompressed
 * point of the curve, or the equation failing. */
int httpasm_p521_verify(const uint8_t public_key[HTTPASM_P521_POINT], const uint8_t *digest,
                        size_t digest_length, const uint8_t signature[HTTPASM_P521_SIGNATURE]);

/* ------------------------------------------------------------------------------------------
 * Ed25519 (RFC 8032 5.1, pure EdDSA): TLS 1.3's ed25519 signature scheme and Ed25519
 * certificates (RFC 8410). Versions: mulx with adcx/adox and AVX2 table scans on four 64-bit
 * limbs, and mul with SSE2 on five 51-bit limbs; signing is constant time in the key and r,
 * verification (public inputs) is not.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_ED25519_KEY       32    /* octets of a private key (the seed) or a public key */
#define HTTPASM_ED25519_SIGNATURE 64    /* octets of a signature: R || S */

/* The public key of a private key (32 octets, any value: RFC 8032 5.1.5's seed; draw them from
 * httpasm_random). */
void httpasm_ed25519_public_key(uint8_t public_key[HTTPASM_ED25519_KEY],
                                const uint8_t private_key[HTTPASM_ED25519_KEY]);

/* A private key ready to sign (96 octets): the scalar, the nonce prefix and the public key, all
 * derived from the seed by the library. There is no way to sign under a public key the caller
 * names: signing one message under two public keys with one seed would reveal the private
 * scalar. Its octets ARE the secret: zero it when done. */
typedef struct httpasm_ed25519_private_key {
    uint64_t opaque[12];
} httpasm_ed25519_private_key;

/* Prepares key from a private key (the seed): one public key's worth of work, so prepare a key
 * once and keep it for its signatures. */
void httpasm_ed25519_private_key_init(httpasm_ed25519_private_key *key,
                                      const uint8_t private_key[HTTPASM_ED25519_KEY]);

/* Signs message[0..length) (the message itself: pure Ed25519 hashes it twice, so a TLS
 * CertificateVerify passes its whole signed content). Deterministic, as RFC 8032 5.1.6 defines
 * it; signature may overlap the message. */
void httpasm_ed25519_sign(uint8_t signature[HTTPASM_ED25519_SIGNATURE],
                          const httpasm_ed25519_private_key *key, const uint8_t *message,
                          size_t length);

/* Verifies signature over message[0..length) under a public key (RFC 8032 5.1.7, the
 * cofactorless equation [S]B = R + [k]A). Returns 0 when valid; -1 otherwise: S not below L
 * (no malleable signature passes), the public key not a point's encoding (y not below p, or no
 * x for it, or x = 0 with the sign bit set), or the equation failing (R is compared octet for
 * octet with the encoding of [S]B - [k]A, so a non-canonical R never passes). Public keys of
 * small order are not refused by policy. */
int httpasm_ed25519_verify(const uint8_t public_key[HTTPASM_ED25519_KEY], const uint8_t *message,
                           size_t length, const uint8_t signature[HTTPASM_ED25519_SIGNATURE]);

/* ------------------------------------------------------------------------------------------
 * Ed448 (RFC 8032 5.2, pure EdDSA with SHAKE256 and dom4): TLS 1.3's ed448 signature scheme and
 * Ed448 certificates (RFC 8410). X448's field (eight 56-bit limbs; mulx and AVX2 table scans, or
 * mul and SSE2); signing is constant time in the key and r, verification (public inputs) is not.
 * Stack: 6,472 octets (tests/native/stack measures it).
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_ED448_KEY       57      /* octets of a private key (the seed) or a public key */
#define HTTPASM_ED448_SIGNATURE 114     /* octets of a signature: R || S */
#define HTTPASM_ED448_CONTEXT   255     /* the longest context (RFC 8032's dom4); TLS 1.3 uses none */

/* The public key of a private key (57 octets, any value: RFC 8032 5.2.5's seed; draw them from
 * httpasm_random). */
void httpasm_ed448_public_key(uint8_t public_key[HTTPASM_ED448_KEY],
                              const uint8_t private_key[HTTPASM_ED448_KEY]);

/* A private key ready to sign (176 octets): the scalar, the nonce prefix and the public key, all
 * derived from the seed by the library. There is no way to sign under a public key the caller
 * names: signing one message under two public keys with one seed would reveal the private
 * scalar. Its octets ARE the secret: zero it when done. */
typedef struct httpasm_ed448_private_key {
    uint64_t opaque[22];
} httpasm_ed448_private_key;

/* Prepares key from a private key (the seed): one public key's worth of work, so prepare a key
 * once and keep it for its signatures. */
void httpasm_ed448_private_key_init(httpasm_ed448_private_key *key,
                                    const uint8_t private_key[HTTPASM_ED448_KEY]);

/* Signs message[0..length) under the context (context_length octets, at most 255; 0 for none,
 * which TLS 1.3 uses: context may then be NULL), as RFC 8032 5.2.6 defines it (deterministic).
 * Returns 0; or -1 for a longer context, with nothing written. signature may overlap the message
 * (it is written after both hashes have read it). */
int httpasm_ed448_sign(uint8_t signature[HTTPASM_ED448_SIGNATURE],
                       const httpasm_ed448_private_key *key, const uint8_t *message, size_t length,
                       const uint8_t *context, size_t context_length);

/* Verifies signature over message[0..length) and the context under a public key (RFC 8032 5.2.7,
 * the cofactorless equation [S]B = R + [k]A). Returns 0 when valid; -1 otherwise: a context over
 * 255 octets, S not below L (no malleable signature passes), the public key not a point's
 * encoding (the last octet's low seven bits set, y not below p, no x for it, or x = 0 with the
 * sign bit set), or the equation failing (R is compared octet for octet with the encoding of
 * [S]B - [k]A, so a non-canonical R never passes). */
int httpasm_ed448_verify(const uint8_t public_key[HTTPASM_ED448_KEY], const uint8_t *message,
                         size_t length, const uint8_t *context, size_t context_length,
                         const uint8_t signature[HTTPASM_ED448_SIGNATURE]);

/* ------------------------------------------------------------------------------------------
 * ML-KEM (FIPS 203): the post-quantum key encapsulation of TLS 1.3's hybrids (RFC 10024's
 * X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024) and of the pure ML-KEM groups. Every
 * function is deterministic: the caller draws the randomness (httpasm_random), which also makes
 * them testable against fixed vectors. Constant time in every secret; the decapsulation's implicit
 * rejection (a modified ciphertext gives an unrelated key, not an error) included.
 * Stack: each call needs up to about 27 KiB of the calling thread's stack (27,232 octets at most,
 * measured by tests/native/stack: ML-KEM-1024 with AVX2, which holds its whole matrix; 11 KiB
 * without AVX2), touched a page at a time on the way down, so a thread with too little faults on
 * its guard page rather than writing past it. All of it but the public matrix is wiped before the
 * call returns.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_MLKEM_SEED     64       /* octets of a key generation seed: d || z (64 random) */
#define HTTPASM_MLKEM_MESSAGE  32       /* octets of an encapsulation's m (32 random) */
#define HTTPASM_MLKEM_SHARED   32       /* octets of the shared secret */
#define HTTPASM_MLKEM512_EK    800      /* the encapsulation (public) key */
#define HTTPASM_MLKEM512_DK    1632     /* the decapsulation (private) key */
#define HTTPASM_MLKEM512_CT    768      /* the ciphertext */
#define HTTPASM_MLKEM768_EK    1184
#define HTTPASM_MLKEM768_DK    2400
#define HTTPASM_MLKEM768_CT    1088
#define HTTPASM_MLKEM1024_EK   1568
#define HTTPASM_MLKEM1024_DK   3168
#define HTTPASM_MLKEM1024_CT   1568

/* Key generation (ML-KEM.KeyGen_internal, FIPS 203 Algorithm 16) from seed = d || z. The
 * decapsulation key holds the secret and the encapsulation key: zero it when done. */
void httpasm_mlkem512_keypair(uint8_t ek[HTTPASM_MLKEM512_EK], uint8_t dk[HTTPASM_MLKEM512_DK],
                              const uint8_t seed[HTTPASM_MLKEM_SEED]);
void httpasm_mlkem768_keypair(uint8_t ek[HTTPASM_MLKEM768_EK], uint8_t dk[HTTPASM_MLKEM768_DK],
                              const uint8_t seed[HTTPASM_MLKEM_SEED]);
void httpasm_mlkem1024_keypair(uint8_t ek[HTTPASM_MLKEM1024_EK], uint8_t dk[HTTPASM_MLKEM1024_DK],
                               const uint8_t seed[HTTPASM_MLKEM_SEED]);

/* Encapsulation (ML-KEM.Encaps_internal, Algorithm 17) to a peer's encapsulation key with the
 * caller's 32 random octets m: the ciphertext to send and the shared secret. Returns 0; or -1
 * when ek fails FIPS 203 7.2's modulus check (a coefficient of q or more: TLS must abort with an
 * illegal_parameter alert), c and shared then all zeros. The length check is the caller's (the
 * types carry the lengths). */
int httpasm_mlkem512_encaps(uint8_t c[HTTPASM_MLKEM512_CT], uint8_t shared[HTTPASM_MLKEM_SHARED],
                            const uint8_t ek[HTTPASM_MLKEM512_EK], const uint8_t m[HTTPASM_MLKEM_MESSAGE]);
int httpasm_mlkem768_encaps(uint8_t c[HTTPASM_MLKEM768_CT], uint8_t shared[HTTPASM_MLKEM_SHARED],
                            const uint8_t ek[HTTPASM_MLKEM768_EK], const uint8_t m[HTTPASM_MLKEM_MESSAGE]);
int httpasm_mlkem1024_encaps(uint8_t c[HTTPASM_MLKEM1024_CT], uint8_t shared[HTTPASM_MLKEM_SHARED],
                             const uint8_t ek[HTTPASM_MLKEM1024_EK], const uint8_t m[HTTPASM_MLKEM_MESSAGE]);

/* Decapsulation (ML-KEM.Decaps_internal, Algorithm 18): the shared secret of a ciphertext. A
 * ciphertext that is not the one encapsulated still gives a key, J(z || c), unrelated to the real
 * one (implicit rejection: the handshake then fails at its Finished). Returns 0; or -1 when dk
 * fails 7.3's hash check (the H(ek) it carries is not its ek's: a corrupted key, which RFC 10024
 * 4.2 answers with an internal_error alert), shared then all zeros. */
int httpasm_mlkem512_decaps(uint8_t shared[HTTPASM_MLKEM_SHARED], const uint8_t dk[HTTPASM_MLKEM512_DK],
                            const uint8_t c[HTTPASM_MLKEM512_CT]);
int httpasm_mlkem768_decaps(uint8_t shared[HTTPASM_MLKEM_SHARED], const uint8_t dk[HTTPASM_MLKEM768_DK],
                            const uint8_t c[HTTPASM_MLKEM768_CT]);
int httpasm_mlkem1024_decaps(uint8_t shared[HTTPASM_MLKEM_SHARED], const uint8_t dk[HTTPASM_MLKEM1024_DK],
                             const uint8_t c[HTTPASM_MLKEM1024_CT]);

/* ------------------------------------------------------------------------------------------
 * FFDHE (RFC 7919): finite-field Diffie-Hellman over the five named groups TLS 1.3 offers, by
 * their NamedGroup codes, generator 2. The private exponent comes from the caller (draw it with
 * httpasm_random), at least RFC 7919 Appendix A's advised length (225, 275, 325, 375 and 400
 * bits: 29, 35, 41, 47 and 50 octets) and at most p's size; its length is public (the work
 * follows it), its value is not: constant time in it (RSA signing's exponentiation, the same
 * frame). Public keys and shared secrets are p's size in octets, big-endian, left-padded (RFC
 * 9846 4.2.8.1, 7.4.1). Stack: RSA signing's frame, 49,792 octets deep (tests/native/stack), touched
 * a page at a time, wiped before a call returns.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_FFDHE2048 0x0100
#define HTTPASM_FFDHE3072 0x0101
#define HTTPASM_FFDHE4096 0x0102
#define HTTPASM_FFDHE6144 0x0103
#define HTTPASM_FFDHE8192 0x0104

/* p's size in octets for a group (256, 384, 512, 768 or 1024): a public key's and a shared
 * secret's; 0 for any other value. */
size_t httpasm_ffdhe_size(int group);

/* The public key Y = 2^x mod p of the private exponent x (private_length octets, big-endian),
 * httpasm_ffdhe_size(group) octets. Returns 0; -1 for an unknown group or a length outside
 * [the advised minimum, p's size] (nothing written). */
int httpasm_ffdhe_public_key(int group, uint8_t *public_key, const uint8_t *private_key,
                             size_t private_length);

/* The shared secret Z = Y^x mod p of the peer's public key Y (httpasm_ffdhe_size(group) octets,
 * big-endian) after RFC 7919 5.1's check 1 < Y < p - 1, as many octets. Returns 0; -1 for an
 * unknown group, a length outside the range, or Y failing the check (nothing written: TLS then
 * ends the handshake with illegal_parameter). */
int httpasm_ffdhe_shared(int group, uint8_t *shared, const uint8_t *private_key, size_t private_length,
                         const uint8_t *peer_key);

/* ------------------------------------------------------------------------------------------
 * RSA signatures (RFC 8017): verification of RSASSA-PKCS1-v1_5 (certificates' sha256With-
 * RSAEncryption and its kin) and RSASSA-PSS with MGF1 (TLS 1.3's rsa_pss_rsae_*, rsa_pss_pss_*),
 * for moduli of 1024 to 8192 bits. Every input is public: these run in variable time. Products
 * by mulx with adcx/adox, or by mul.
 * Stack: verification needs up to about 13 KiB of the calling thread's stack (a key's setup,
 * 12,944 octets measured by tests/native/stack; a verification 7,304), signing about 56 KiB (a
 * private key's setup 56,592 octets, a signature 49,792: the table of powers and the CRT's
 * values), each touched a page at a time on the way down, so a thread with too little faults on
 * its guard page rather than writing past it; signing's frame is wiped before it returns.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_HASH_SHA1   1           /* PKCS#1 v1.5 verification only (legacy certificates) */
#define HTTPASM_HASH_SHA224 2           /* PKCS#1 v1.5 verification only */
#define HTTPASM_HASH_SHA256 3
#define HTTPASM_HASH_SHA384 4
#define HTTPASM_HASH_SHA512 5

#define HTTPASM_RSA_MIN_BITS 1024
#define HTTPASM_RSA_MAX_BITS 8192

/* A public key ready for verification (2080 octets): the modulus, the Montgomery constants its
 * products need (computed once by the init: a long division, about one product's worth, 1.8 us
 * at 2048 bits), the exponent. Its octets are its whole state: copy it freely; nothing to free.
 * A certificate's key verifies one signature: the init is part of that verification's cost. */
typedef struct httpasm_rsa_public_key {
    uint64_t opaque[260];
} httpasm_rsa_public_key;

/* Prepares key from the modulus n and the public exponent e, both big-endian octet strings
 * (leading zero octets allowed, as DER's INTEGERs carry them). Returns 0; or -1 when n is even
 * or outside 1024..8192 bits, or e is even, below 3 or above 2^64 - 1 (key is then all zeros
 * and every verification under it fails). */
int httpasm_rsa_public_key_init(httpasm_rsa_public_key *key, const uint8_t *n, size_t n_length,
                                const uint8_t *e, size_t e_length);

/* RSASSA-PKCS1-v1_5 verification (RFC 8017 8.2.2) of a digest made by the hash named (one of
 * HTTPASM_HASH_*: the digest is that hash's length). Returns 0 when valid; -1 otherwise: an
 * unknown hash, a signature whose length is not the modulus' octets or whose value is not below
 * n, or any octet of the encoding other than expected (the DigestInfo is compared whole, so no
 * BER variant or trailing data passes: the forgeries of Bleichenbacher's 2006 kind fail). */
int httpasm_rsa_verify_pkcs1(const httpasm_rsa_public_key *key, int hash, const uint8_t *digest,
                             const uint8_t *signature, size_t signature_length);

/* RSASSA-PSS verification (RFC 8017 8.1.2, MGF1 with the same hash) of a digest of SHA-256,
 * SHA-384 or SHA-512 (HTTPASM_HASH_*), with the salt's length known (TLS 1.3: the digest's
 * length; a certificate's parameters otherwise). Returns 0 when valid; -1 otherwise: another
 * hash, a wrong length or value as for PKCS#1 v1.5, or an encoding that fails any of RFC 8017
 * 9.1.2's checks. */
int httpasm_rsa_verify_pss(const httpasm_rsa_public_key *key, int hash, const uint8_t *digest,
                           size_t salt_length, const uint8_t *signature, size_t signature_length);

/* An RSAPrivateKey's numbers (RFC 8017 A.1.2) for httpasm_rsa_private_key_init: big-endian octet
 * strings with their lengths (leading zero octets allowed). d itself is not needed. */
typedef struct httpasm_rsa_private_numbers {
    const uint8_t *n;    size_t n_length;
    const uint8_t *e;    size_t e_length;
    const uint8_t *p;    size_t p_length;
    const uint8_t *q;    size_t q_length;
    const uint8_t *dp;   size_t dp_length;      /* d mod (p - 1) */
    const uint8_t *dq;   size_t dq_length;      /* d mod (q - 1) */
    const uint8_t *qinv; size_t qinv_length;    /* q^-1 mod p */
} httpasm_rsa_private_numbers;

/* A private key ready to sign (6720 octets): its public key first (verify under
 * (const httpasm_rsa_public_key *)&key), then the primes, the CRT exponents and the Montgomery
 * constants. Its octets ARE the secret: copy it only where it may live, zero it when done. */
typedef struct httpasm_rsa_private_key {
    uint64_t opaque[840];
} httpasm_rsa_private_key;

/* Prepares key from an RSAPrivateKey's numbers. Returns 0; or -1 (key then all zeros) when the
 * public part is refused as httpasm_rsa_public_key_init refuses it, a prime is even, 1, or over
 * 4096 bits, p q is not n, dp is not below p, dq not below q, qinv not below p, or a test signature
 * made with the key does not verify under e (inconsistent numbers). The primes' sizes need not
 * match. Constant time in the secrets; about one signature's worth (the test signature is most
 * of it: 0.59 ms at 2048 bits), so prepare a key once and keep it. */
int httpasm_rsa_private_key_init(httpasm_rsa_private_key *key, const httpasm_rsa_private_numbers *numbers);

/* RSASSA-PKCS1-v1_5 signature (RFC 8017 8.2.1) of a digest of the hash named (HTTPASM_HASH_*),
 * signature_length octets: the modulus' length. CRT with constant-time exponentiation (fixed
 * windows over the primes' whole width, 5 bits up to 1024-bit primes and 6 above, every table
 * entry read), checked against faults
 * by verifying it under e before it is returned. It needs about 48 KiB of stack (the window
 * table of 64 entries at 4096 bits each, whatever the key's size), all of it zeroed before it
 * returns, as httpasm_rsa_private_key_init does: a thread that signs must have that room. Returns
 * 0; or -1 (signature zeroed when its length was right) for an unknown hash, a wrong length, a
 * refused key, or a result that failed the check. */
int httpasm_rsa_sign_pkcs1(const httpasm_rsa_private_key *key, int hash, const uint8_t *digest,
                           uint8_t *signature, size_t signature_length);

/* RSASSA-PSS signature (RFC 8017 8.1.1, MGF1 with the same hash) of a SHA-256, SHA-384 or
 * SHA-512 digest with the caller's salt (TLS 1.3: random octets of the digest's length, from
 * httpasm_random; salt may be NULL when salt_length is 0). The same as httpasm_rsa_sign_pkcs1
 * otherwise; also -1 when the salt does not fit (RFC 8017 9.1.1 step 3). */
int httpasm_rsa_sign_pss(const httpasm_rsa_private_key *key, int hash, const uint8_t *digest,
                         const uint8_t *salt, size_t salt_length, uint8_t *signature,
                         size_t signature_length);

/* ------------------------------------------------------------------------------------------
 * Randomness: the kernel's generator (getrandom(2), the urandom source), for TLS randoms,
 * ephemeral keys and ticket keys.
 * ------------------------------------------------------------------------------------------ */

/* Fills buffer[0..length) with random octets, continuing through short reads and signals.
 * Returns 0, or -errno when the kernel refuses (-ENOSYS, -EPERM from a sandbox's seccomp filter,
 * -EFAULT, or -EIO when a filter answers with neither octets nor an error): nothing weaker is
 * substituted, and the buffer must then not be used. */
int httpasm_random(void *buffer, size_t length);

/* ------------------------------------------------------------------------------------------
 * MACs and key derivation: HMAC (FIPS 198-1, RFC 2104) and HKDF (RFC 5869) over SHA-256 and
 * SHA-384, TLS 1.3's two hashes. Every buffer that held key octets is wiped before a function
 * returns, and finals wipe their context.
 * ------------------------------------------------------------------------------------------ */

/* A running HMAC-SHA256 (224 octets): the inner and outer hashes, each past its key block. The
 * key is not kept. A copy of a freshly started context MACs another message under the same key
 * without hashing the key again. */
typedef struct httpasm_hmac_sha256_ctx {
    httpasm_sha256_ctx inner;
    httpasm_sha256_ctx outer;
} httpasm_hmac_sha256_ctx;

/* Starts an HMAC under key[0..n) (any length: a key longer than 64 octets is hashed first). */
void httpasm_hmac_sha256_init(httpasm_hmac_sha256_ctx *h, const uint8_t *key, size_t n);

/* Feeds n octets of the message. */
void httpasm_hmac_sha256_update(httpasm_hmac_sha256_ctx *h, const uint8_t *data, size_t n);

/* Writes the 32-octet MAC and wipes h. Compare MACs with a constant-time comparison. */
void httpasm_hmac_sha256_final(httpasm_hmac_sha256_ctx *h, uint8_t mac[HTTPASM_SHA256_DIGEST]);

/* The MAC of data[0..n) under the key, at once. */
void httpasm_hmac_sha256(const uint8_t *key, size_t key_length, const uint8_t *data, size_t n,
                         uint8_t mac[HTTPASM_SHA256_DIGEST]);

/* HKDF-Extract: prk = HMAC-SHA256(salt, ikm). An empty salt is 32 zeros (RFC 5869 2.2). */
void httpasm_hkdf_sha256_extract(const uint8_t *salt, size_t salt_length, const uint8_t *ikm,
                                 size_t ikm_length, uint8_t prk[HTTPASM_SHA256_DIGEST]);

/* HKDF-Expand: okm[0..length) from the pseudorandom key and info (RFC 5869 2.3). Returns 0, or
 * -1 when length exceeds 255 * 32 = 8160 octets (nothing is written then). */
int httpasm_hkdf_sha256_expand(const uint8_t *prk, size_t prk_length, const uint8_t *info,
                               size_t info_length, uint8_t *okm, size_t length);

/* A running HMAC-SHA384 (416 octets): as httpasm_hmac_sha256_ctx, over SHA-384's hashes (the
 * key schedule of TLS_AES_256_GCM_SHA384). */
typedef struct httpasm_hmac_sha384_ctx {
    httpasm_sha512_ctx inner;
    httpasm_sha512_ctx outer;
} httpasm_hmac_sha384_ctx;

/* Starts an HMAC-SHA384 under key[0..n) (any length: a key longer than 128 octets is hashed
 * first). */
void httpasm_hmac_sha384_init(httpasm_hmac_sha384_ctx *h, const uint8_t *key, size_t n);

/* Feeds n octets of the message. */
void httpasm_hmac_sha384_update(httpasm_hmac_sha384_ctx *h, const uint8_t *data, size_t n);

/* Writes the 48-octet MAC and wipes h. Compare MACs with a constant-time comparison. */
void httpasm_hmac_sha384_final(httpasm_hmac_sha384_ctx *h, uint8_t mac[HTTPASM_SHA384_DIGEST]);

/* The MAC of data[0..n) under the key, at once. */
void httpasm_hmac_sha384(const uint8_t *key, size_t key_length, const uint8_t *data, size_t n,
                         uint8_t mac[HTTPASM_SHA384_DIGEST]);

/* HKDF-Extract: prk = HMAC-SHA384(salt, ikm). An empty salt is 48 zeros (RFC 5869 2.2). */
void httpasm_hkdf_sha384_extract(const uint8_t *salt, size_t salt_length, const uint8_t *ikm,
                                 size_t ikm_length, uint8_t prk[HTTPASM_SHA384_DIGEST]);

/* HKDF-Expand over SHA-384 (RFC 5869 2.3). Returns 0, or -1 when length exceeds
 * 255 * 48 = 12240 octets (nothing is written then). */
int httpasm_hkdf_sha384_expand(const uint8_t *prk, size_t prk_length, const uint8_t *info,
                               size_t info_length, uint8_t *okm, size_t length);

/* A running HMAC-SHA512 (416 octets): httpasm_hmac_sha384_ctx's layout over SHA-512's hashes. No
 * TLS 1.3 cipher suite uses it; RFC 6979's deterministic nonces at P-521 do (httpasm_p521_sign's
 * HMAC_DRBG), and so may a protocol of the caller's. A context is finished by the final of the
 * HMAC that started it. */
typedef struct httpasm_hmac_sha512_ctx {
    httpasm_sha512_ctx inner;
    httpasm_sha512_ctx outer;
} httpasm_hmac_sha512_ctx;

/* Starts an HMAC-SHA512 under key[0..n) (any length: a key longer than 128 octets is hashed
 * first). */
void httpasm_hmac_sha512_init(httpasm_hmac_sha512_ctx *h, const uint8_t *key, size_t n);

/* Feeds n octets of the message. */
void httpasm_hmac_sha512_update(httpasm_hmac_sha512_ctx *h, const uint8_t *data, size_t n);

/* Writes the 64-octet MAC and wipes h. Compare MACs with a constant-time comparison. */
void httpasm_hmac_sha512_final(httpasm_hmac_sha512_ctx *h, uint8_t mac[HTTPASM_SHA512_DIGEST]);

/* The MAC of data[0..n) under the key, at once. */
void httpasm_hmac_sha512(const uint8_t *key, size_t key_length, const uint8_t *data, size_t n,
                         uint8_t mac[HTTPASM_SHA512_DIGEST]);

/* HKDF-Extract: prk = HMAC-SHA512(salt, ikm). An empty salt is 64 zeros (RFC 5869 2.2). */
void httpasm_hkdf_sha512_extract(const uint8_t *salt, size_t salt_length, const uint8_t *ikm,
                                 size_t ikm_length, uint8_t prk[HTTPASM_SHA512_DIGEST]);

/* HKDF-Expand over SHA-512 (RFC 5869 2.3). Returns 0, or -1 when length exceeds
 * 255 * 64 = 16320 octets (nothing is written then). */
int httpasm_hkdf_sha512_expand(const uint8_t *prk, size_t prk_length, const uint8_t *info,
                               size_t info_length, uint8_t *okm, size_t length);

/* ------------------------------------------------------------------------------------------
 * ASN.1's encodings (ITU-T X.690): a reader of the Basic Encoding Rules and of their strict
 * profile, the Distinguished Encoding Rules, for certificates (DER: RFC 5280) and private keys
 * (BER: RFC 5958 has receivers accept it). It reads one element at a time, in place: nothing
 * is copied or allocated, an element's contents point into the caller's octets, and no octet
 * past the input is read. Every input is taken as untrusted.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_ASN1_DER 0          /* rules: X.690's clauses 8, 10 and 11 (one encoding a value) */
#define HTTPASM_ASN1_BER 1          /* rules: clause 8 alone (every sender's option) */

/* A tag as httpasm_asn1 holds it: the class in bits 31-30, the constructed form in bit 29 (the
 * identifier octet's bits 8-6, shifted up by 24), the number in bits 28-0. */
#define HTTPASM_ASN1_UNIVERSAL   0x00000000u
#define HTTPASM_ASN1_APPLICATION 0x40000000u
#define HTTPASM_ASN1_CONTEXT     0x80000000u
#define HTTPASM_ASN1_PRIVATE     0xC0000000u
#define HTTPASM_ASN1_CONSTRUCTED 0x20000000u
#define HTTPASM_ASN1_CLASS       0xC0000000u
#define HTTPASM_ASN1_NUMBER      0x1FFFFFFFu

/* The universal types the reader checks (X.680's numbers; SEQUENCE and SET with their form). */
#define HTTPASM_ASN1_BOOLEAN          1u
#define HTTPASM_ASN1_INTEGER          2u
#define HTTPASM_ASN1_BIT_STRING       3u
#define HTTPASM_ASN1_OCTET_STRING     4u
#define HTTPASM_ASN1_NULL             5u
#define HTTPASM_ASN1_OID              6u
#define HTTPASM_ASN1_ENUMERATED       10u
#define HTTPASM_ASN1_UTF8_STRING      12u
#define HTTPASM_ASN1_SEQUENCE         (16u | HTTPASM_ASN1_CONSTRUCTED)
#define HTTPASM_ASN1_SET              (17u | HTTPASM_ASN1_CONSTRUCTED)
#define HTTPASM_ASN1_NUMERIC_STRING   18u
#define HTTPASM_ASN1_PRINTABLE_STRING 19u
#define HTTPASM_ASN1_T61_STRING       20u
#define HTTPASM_ASN1_VIDEOTEX_STRING  21u
#define HTTPASM_ASN1_IA5_STRING       22u
#define HTTPASM_ASN1_UTC_TIME         23u
#define HTTPASM_ASN1_GENERALIZED_TIME 24u
#define HTTPASM_ASN1_GRAPHIC_STRING   25u
#define HTTPASM_ASN1_VISIBLE_STRING   26u
#define HTTPASM_ASN1_GENERAL_STRING   27u
#define HTTPASM_ASN1_UNIVERSAL_STRING 28u
#define HTTPASM_ASN1_BMP_STRING       30u

/* httpasm_asn1.flags */
#define HTTPASM_ASN1_INDEFINITE 1u  /* BER's indefinite length: end-of-contents octets end it */

/* One element (32 octets). Valid while the octets it was read from are. */
typedef struct httpasm_asn1 {
    const uint8_t *content;         /* the contents octets */
    size_t content_length;          /* their count (an indefinite length's: before its end-of-contents) */
    size_t length;                  /* the whole encoding: identifier, length, contents, end-of-contents */
    uint32_t tag;                   /* HTTPASM_ASN1_<class> | [HTTPASM_ASN1_CONSTRUCTED] | number */
    uint32_t flags;                 /* HTTPASM_ASN1_INDEFINITE */
} httpasm_asn1;

/* Reads the first element of in[0..length) under rules (HTTPASM_ASN1_DER or _BER); the octets
 * after it are the caller's (element->length says where it ends). Checked: the identifier
 * (8.1.2: the high-tag form only for numbers above 30 and without leading zero bits; numbers up
 * to 2^28 - 1), the length (8.1.3; never 0xFF; BER's indefinite form only for a constructed
 * encoding, its end-of-contents found by reading the nested elements; DER: definite, in the
 * fewest octets), the contents within the input; and for a universal tag, its type's rules:
 * BOOLEAN, INTEGER and ENUMERATED (the fewest octets), BIT STRING (DER: unused bits zero), OCTET
 * STRING, NULL, OBJECT IDENTIFIER, SEQUENCE and SET (constructed), the strings' characters
 * (PrintableString's table, NumericString, IA5String, VisibleString, UTF-8 in the fewest octets
 * without surrogates, BMPString and UniversalString without surrogates; T61String, Videotex-,
 * Graphic- and GeneralString's ISO 2022 octets as they are), UTCTime's and GeneralizedTime's
 * forms (DER's: Z and the seconds always, a fraction without trailing zeros; BER's: X.680's,
 * with optional seconds, differentials and local time; every field in its range, leap years
 * included), and BER's constructed strings segment by segment (DER refuses them; a constructed
 * time is gathered first, 64 characters at most). Other universal types (REAL, EXTERNAL, the TIME types, ...) are refused. The
 * reader follows nesting itself only for indefinite lengths and segments, 32 levels at most;
 * a constructed element's other contents are the caller's to read, element by element. Returns
 * 0, or -1 (element's fields then unspecified). Constant time in an INTEGER's value (only its
 * identifier and length octets steer it), for the private keys it reads. */
int httpasm_asn1_read(httpasm_asn1 *element, const uint8_t *in, size_t length, int rules);

/* Applies universal type `type`'s rules (HTTPASM_ASN1_INTEGER, ...) to an element read under
 * another tag: an IMPLICIT one, such as RFC 5958's publicKey [1] (a BIT STRING). The element
 * keeps its own form (X.690 8.14.4) and its segments' universal tags. Returns 0, or -1 (also for
 * a type the reader does not check, a class bit in `type`, unknown rules, or an element whose
 * flags httpasm_asn1_read never returns: any bit but HTTPASM_ASN1_INDEFINITE). */
int httpasm_asn1_check(const httpasm_asn1 *element, uint32_t type, int rules);

/* Reads a SET OF's components (under SET's tag or an IMPLICIT one) under rules, and under DER
 * checks their order (X.690 11.6: ascending encodings, compared as octet strings with the
 * shorter padded with zero octets; equal ones may repeat). A SET's (not SET OF) tag order
 * (10.3) is not checked: no structure the library reads has one. Returns 0, or -1. */
int httpasm_asn1_check_set_of(const httpasm_asn1 *set, int rules);

/* The value of an OCTET STRING or a restricted character string (read under its own tag, or one
 * under an implicit tag), primitive or BER-constructed: its octets in order, the segments'
 * joined, copied into out[0..capacity). The element is checked as an OCTET STRING first, so a
 * constructed element of another kind is refused rather than flattened. Returns the count, or
 * -1 when it does not fit (out then holds a prefix), the check fails (an element's flags as
 * httpasm_asn1_check takes them), or the rules are unknown. Copies without looking at the
 * octets (constant time: a private key's may be secret). */
int64_t httpasm_asn1_octets(const httpasm_asn1 *element, uint8_t *out, size_t capacity, int rules);

/* A BIT STRING's bits, primitive or BER-constructed: the octets after each segment's initial
 * octet, in order, into out[0..capacity), and in *unused the unused bits of the final octet (0 to
 * 7). The element is checked as a BIT STRING first. Returns the octets, or -1 as for
 * httpasm_asn1_octets (*unused then unchanged). */
int64_t httpasm_asn1_bits(const httpasm_asn1 *element, uint8_t *out, size_t capacity,
                          uint32_t *unused, int rules);

/* ------------------------------------------------------------------------------------------
 * PEM (RFC 7468): the textual encoding of certificates and keys, "-----BEGIN <label>-----",
 * base64, "-----END <label>-----". The base64 is decoded in constant time (only the layout,
 * where whitespace stands and where the text ends, steers the decoder), for private keys' sake.
 * ------------------------------------------------------------------------------------------ */

/* One block, as httpasm_pem_read found it (32 octets). */
typedef struct httpasm_pem {
    const uint8_t *label;           /* the label ("CERTIFICATE", "PRIVATE KEY", ...), in the text */
    size_t label_length;
    size_t der_length;              /* the octets decoded into der (on -2: the room they need) */
    size_t end;                     /* the text's offset past the END boundary: where to look next */
} httpasm_pem;

/* Finds the first block of text[0..length) whose BEGIN line starts the text or a line (text
 * before it, such as explanatory lines, is skipped) and decodes its base64 into
 * der[0..capacity). The rules: exactly five hyphen-minuses on each side; a label of printable
 * characters with single hyphen-minuses or spaces inside it; RFC 7468's lax base64 text
 * (whitespace anywhere, up to two pads, any other character refused); the END line's label the
 * BEGIN line's; pads absent or right, a final quantum's pad bits zero. Returns 0 (block filled);
 * 1 when no BEGIN line is found (a file's blocks are all read: call again from block->end until
 * then); -1 for a malformed block; -2 when the octets need more than capacity (block->der_length
 * says how much; der untouched). der is written only once the whole block was checked; a
 * private key's octets in it are the caller's to wipe. */
int httpasm_pem_read(httpasm_pem *block, const uint8_t *text, size_t length, uint8_t *der,
                     size_t capacity);

/* ------------------------------------------------------------------------------------------
 * Private keys from their files: the key a server signs its handshakes with. PEM or DER, in
 * PKCS#8 (RFC 5958's OneAsymmetricKey, "PRIVATE KEY"), PKCS#1 ("RSA PRIVATE KEY") or SEC1 (RFC
 * 5915, "EC PRIVATE KEY"); BER accepted throughout (RFC 5958: receivers MUST). Read in constant
 * time in the key's secret numbers, scalar or seed; every buffer that held them is wiped.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_KEY_RSA     1       /* rsaEncryption: PKCS#1 v1.5 and PSS signatures */
#define HTTPASM_KEY_RSA_PSS 2       /* id-RSASSA-PSS (RFC 4055): PSS signatures only */
#define HTTPASM_KEY_P256    3       /* id-ecPublicKey on prime256v1 */
#define HTTPASM_KEY_P384    4       /* ... on secp384r1 */
#define HTTPASM_KEY_P521    5       /* ... on secp521r1 */
#define HTTPASM_KEY_ED25519 6       /* id-Ed25519 (RFC 8410) */
#define HTTPASM_KEY_ED448   7       /* id-Ed448 */

/* A private key, prepared (6888 octets): its kind and size first, then the key of that kind
 * ready to sign (an httpasm_rsa_private_key, a curve's scalar with its public key, an
 * httpasm_ed25519/ed448_private_key). Its octets ARE the secret: zero it when done. */
typedef struct httpasm_private_key {
    uint32_t kind;                  /* HTTPASM_KEY_* */
    uint32_t bits;                  /* the modulus' or the curve's size in bits */
    uint32_t pss_hash;              /* HTTPASM_KEY_RSA_PSS: the hash its parameters bind (HTTPASM_HASH_*), 0: any */
    uint32_t pss_salt;              /* and the salt length they name (0 when absent) */
    uint32_t public_length;         /* public's octets: 65/97/133 (04 || x || y), 32, 57; 0 for RSA */
    uint32_t reserved[3];
    uint8_t public_key[136];        /* the public key (an RSA key's n and e are in the secret part) */
    uint64_t opaque[840];
} httpasm_private_key;

/* Loads the private key in data[0..length): DER when its first octet is 0x30, else PEM text
 * (the first "PRIVATE KEY", "RSA PRIVATE KEY" or "EC PRIVATE KEY" block; other blocks, a
 * certificate's or "EC PARAMETERS", are skipped). Accepted: OneAsymmetricKey v1 and v2 (whose
 * publicKey must be the key's own), RSA keys of two primes (rsaEncryption with NULL or absent
 * parameters; id-RSASSA-PSS with no parameters, or SHA-256/384/512 and MGF1 over the same hash),
 * P-256/384/521 keys on a named curve (their scalar padded if a writer dropped its leading
 * zeros; a public key given must be d G's, uncompressed or compressed), Ed25519 and Ed448 keys.
 * Returns the kind (HTTPASM_KEY_*) with key filled; -2 when the text's only private key is an
 * "ENCRYPTED PRIVATE KEY" (password-based decryption is not supported yet); -1 otherwise (key
 * then all zeros): any other format, algorithm (X25519 and X448 keys sign nothing) or
 * inconsistency (an RSA key's numbers that do not make one, a scalar outside 1..n-1). Needs
 * about 90 KiB of stack (touched a page at a time). */
int httpasm_private_key_load(httpasm_private_key *key, const uint8_t *data, size_t length);

/* ------------------------------------------------------------------------------------------
 * Certificates (RFC 5280 4.1): their structure, in DER, and their subject's public key; what a
 * server reads of its own chain (to know its key's kind and that the key is the certificate's)
 * and a TLS client of its peer's leaf. Chain validation (names, constraints, the extensions'
 * meanings, revocation, time) is M3's: these read and check the encoding and its shape only.
 * ------------------------------------------------------------------------------------------ */

/* A certificate's parts (152 octets): pointers into the DER read, valid while it is. */
typedef struct httpasm_certificate {
    const uint8_t *tbs;                 /* tbsCertificate's whole encoding: what the signature covers */
    size_t tbs_length;
    const uint8_t *serial;              /* serialNumber's contents (two's complement, big-endian) */
    size_t serial_length;
    const uint8_t *issuer;              /* the issuer's whole encoding (a Name) */
    size_t issuer_length;
    const uint8_t *subject;             /* the subject's */
    size_t subject_length;
    const uint8_t *spki;                /* subjectPublicKeyInfo's whole encoding (httpasm_public_key_read) */
    size_t spki_length;
    const uint8_t *extensions;          /* [3]'s Extensions SEQUENCE, whole, or NULL */
    size_t extensions_length;
    const uint8_t *signature_algorithm; /* the outer signatureAlgorithm's whole encoding */
    size_t signature_algorithm_length;
    const uint8_t *signature;           /* signatureValue's octets */
    size_t signature_length;
    int64_t not_before;                 /* validity, in seconds since 1970-01-01T00:00:00Z */
    int64_t not_after;
    uint32_t version;                   /* 1, 2 or 3 */
    uint32_t reserved;
} httpasm_certificate;

/* Reads a certificate's DER (der[0..length), one element exactly): the TBSCertificate's fields
 * in order (version present only as v2 or v3, DER's omission of v1; the inner signature the
 * outer signatureAlgorithm's octets exactly, RFC 5280 4.1.1.2; the unique identifiers v2+ and
 * the extensions v3 only, one at least, each { extnID, critical TRUE or absent, extnValue }),
 * names as RDNSequences (non-empty SETs in DER's order of { type, value }), the validity's two
 * times (UTCTime as 1950-2049, GeneralizedTime without fractions: RFC 5280 4.1.2.5), the
 * signature whole octets. Returns 0, or -1. */
int httpasm_certificate_read(httpasm_certificate *c, const uint8_t *der, size_t length);

/* A public key from a SubjectPublicKeyInfo (2248 octets). */
typedef struct httpasm_public_key {
    uint32_t kind;                      /* HTTPASM_KEY_* */
    uint32_t bits;
    uint32_t pss_hash;                  /* HTTPASM_KEY_RSA_PSS: the hash its parameters bind, 0: any */
    uint32_t pss_salt;
    uint32_t point_length;              /* point's octets: 65/97/133, 32, 57; 0 for RSA */
    uint32_t reserved[3];
    uint8_t point[136];                 /* a curve's 04 || x || y, or an Edwards key */
    httpasm_rsa_public_key rsa;         /* RSA: the key prepared for verification */
} httpasm_public_key;

/* Reads a SubjectPublicKeyInfo's DER (a certificate's spki): rsaEncryption (parameters NULL)
 * and id-RSASSA-PSS (the private keys' parameter rules) with RSAPublicKey { n, e } prepared;
 * id-ecPublicKey on P-256/384/521 with an uncompressed point of the curve's length (checked on
 * the curve when it is used); Ed25519 and Ed448 keys, parameters absent. Returns the kind, or
 * -1 (key then all zeros). */
int httpasm_public_key_read(httpasm_public_key *key, const uint8_t *spki, size_t length);

/* Whether pub (a certificate's key) is key's public half: an RSA modulus and exponent (either
 * RSA kind with either), a curve and its point, an Edwards key. Returns 0 for one key pair,
 * else -1. */
int httpasm_private_key_matches(const httpasm_private_key *key, const httpasm_public_key *pub);

/* ------------------------------------------------------------------------------------------
 * TLS 1.3 (RFC 9846): the key schedule (7.1-7.5) and the record layer (5). The handshake that
 * chains them is built on these; they are usable alone (tests, a QUIC stack's own labels).
 * Hashes are HTTPASM_HASH_SHA256 or HTTPASM_HASH_SHA384; labels are given without the
 * "tls13 " prefix HKDF-Expand-Label adds.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_TLS_AES_128_GCM_SHA256       0x1301  /* RFC 9846 9.1's MUST */
#define HTTPASM_TLS_AES_256_GCM_SHA384       0x1302
#define HTTPASM_TLS_CHACHA20_POLY1305_SHA256 0x1303

#define HTTPASM_TLS_CONTENT_CHANGE_CIPHER_SPEC 20    /* ContentType (5.1) */
#define HTTPASM_TLS_CONTENT_ALERT              21
#define HTTPASM_TLS_CONTENT_HANDSHAKE          22
#define HTTPASM_TLS_CONTENT_APPLICATION_DATA   23

/* AlertDescription (6): the record layer answers minus one of these where the connection must
 * end with that alert. */
#define HTTPASM_TLS_ALERT_CLOSE_NOTIFY            0
#define HTTPASM_TLS_ALERT_UNEXPECTED_MESSAGE      10
#define HTTPASM_TLS_ALERT_BAD_RECORD_MAC          20
#define HTTPASM_TLS_ALERT_RECORD_OVERFLOW         22
#define HTTPASM_TLS_ALERT_HANDSHAKE_FAILURE       40
#define HTTPASM_TLS_ALERT_BAD_CERTIFICATE         42
#define HTTPASM_TLS_ALERT_UNSUPPORTED_CERTIFICATE 43
#define HTTPASM_TLS_ALERT_CERTIFICATE_REVOKED     44
#define HTTPASM_TLS_ALERT_CERTIFICATE_EXPIRED     45
#define HTTPASM_TLS_ALERT_CERTIFICATE_UNKNOWN     46
#define HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER       47
#define HTTPASM_TLS_ALERT_UNKNOWN_CA              48
#define HTTPASM_TLS_ALERT_ACCESS_DENIED           49
#define HTTPASM_TLS_ALERT_DECODE_ERROR            50
#define HTTPASM_TLS_ALERT_DECRYPT_ERROR           51
#define HTTPASM_TLS_ALERT_PROTOCOL_VERSION        70
#define HTTPASM_TLS_ALERT_INSUFFICIENT_SECURITY   71
#define HTTPASM_TLS_ALERT_INTERNAL_ERROR          80
#define HTTPASM_TLS_ALERT_INAPPROPRIATE_FALLBACK  86
#define HTTPASM_TLS_ALERT_USER_CANCELED           90
#define HTTPASM_TLS_ALERT_MISSING_EXTENSION       109
#define HTTPASM_TLS_ALERT_UNSUPPORTED_EXTENSION   110
#define HTTPASM_TLS_ALERT_UNRECOGNIZED_NAME       112
#define HTTPASM_TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE 113
#define HTTPASM_TLS_ALERT_UNKNOWN_PSK_IDENTITY    115
#define HTTPASM_TLS_ALERT_CERTIFICATE_REQUIRED    116
#define HTTPASM_TLS_ALERT_GENERAL_ERROR           117
#define HTTPASM_TLS_ALERT_NO_APPLICATION_PROTOCOL 120

#define HTTPASM_TLS_RECORD_HEADER  5        /* type, legacy_record_version, length */
#define HTTPASM_TLS_PLAINTEXT_MAX  16384    /* 2^14: a record's content at most (5.1) */
#define HTTPASM_TLS_INNER_MAX      16385    /* TLSInnerPlaintext at most: the content and its type (5.4) */
#define HTTPASM_TLS_CIPHERTEXT_MAX 16640    /* 2^14 + 256: a protected record's fragment at most (5.2) */
#define HTTPASM_TLS_TAG            16       /* every suite's AEAD tag */
#define HTTPASM_TLS_GCM_RECORDS    23726566 /* floor(2^24.5): AES-GCM's records under one key (5.5) */

/* HKDF-Extract(salt, IKM) into secret[0..Hash.length) (7.1). An IKM of no octets is TLS's "0":
 * Hash.length zeros (the master secret's, and an early secret's without a PSK); no salt is
 * HKDF's default, the same zeros. Returns 0, or -1 for an unknown hash (nothing written). */
int httpasm_tls13_extract(int hash, const uint8_t *salt, size_t salt_length, const uint8_t *ikm,
                          size_t ikm_length, uint8_t *secret);

/* HKDF-Expand-Label(Secret, Label, Context, Length) (7.1): HKDF-Expand over HkdfLabel { uint16
 * Length, "tls13 " + Label, Context } into out[0..length); secret holds Hash.length octets and
 * must not overlap out, nor may the context. Returns 0, or -1 (nothing written) for an unknown
 * hash, a label empty or over 249 octets, a context over 255, or a length over 255 *
 * Hash.length. */
int httpasm_tls13_expand_label(int hash, const uint8_t *secret, const uint8_t *label,
                               size_t label_length, const uint8_t *context, size_t context_length,
                               uint8_t *out, size_t length);

/* Derive-Secret(Secret, Label, Messages) (7.1) into out[0..Hash.length), the caller having
 * hashed the messages into transcript_hash (Hash.length octets); NULL is the hash of none,
 * Hash(""): the "derived" steps and the exporter's. Returns 0, or -1 as expand_label refuses. */
int httpasm_tls13_derive_secret(int hash, const uint8_t *secret, const uint8_t *label,
                                size_t label_length, const uint8_t *transcript_hash, uint8_t *out);

/* A Finished message's verify_data (4.5.3): HMAC(HKDF-Expand-Label(base_key, "finished", "",
 * Hash.length), transcript_hash), Hash.length octets; base_key is the sender's handshake (or,
 * after the handshake, application) traffic secret. Compare what was received with this in
 * constant time. Returns 0, or -1 for an unknown hash. */
int httpasm_tls13_finished(int hash, const uint8_t *base_key, const uint8_t *transcript_hash,
                           uint8_t *verify_data);

/* application_traffic_secret_N+1 = HKDF-Expand-Label(secret_N, "traffic upd", "",
 * Hash.length) (7.2) into next (not overlapping secret); wipe the old one once its keys are
 * made. Returns 0, or -1 for an unknown hash. */
int httpasm_tls13_update_secret(int hash, const uint8_t *secret, uint8_t *next);

/* TLS-Exporter(label, context, length) (7.5) from the exporter_master_secret (or the early
 * exporter's, by a separate call: 7.5's separate interface): HKDF-Expand-Label(Derive-Secret(
 * secret, label, ""), "exporter", Hash(context), length). No context and an empty one give the
 * same value. Returns 0, or -1 as expand_label refuses the label or the length. */
int httpasm_tls13_export(int hash, const uint8_t *exporter_secret, const uint8_t *label,
                         size_t label_length, const uint8_t *context, size_t context_length,
                         uint8_t *out, size_t length);

/* One direction's record protection under one traffic secret (1056 octets): the suite, the
 * write key made ready for its AEAD, the IV, the sequence number. Its octets are a secret:
 * wipe it when done (explicit_bzero). */
typedef struct httpasm_tls13_record_key {
    uint32_t suite;                     /* HTTPASM_TLS_* */
    uint32_t limit;                     /* TLSInnerPlaintext's octets at most: 2^14 + 1, or lower
                                           for record_size_limit (RFC 8449), set after init */
    uint64_t sequence;                  /* the next record's (5.3) */
    uint8_t iv[12];
    uint32_t reserved;
    union {
        httpasm_aes_gcm_key gcm;
        uint8_t chacha20[32];
    } aead;
} httpasm_tls13_record_key;

/* The record at the start of in[0..length) (5.1): its whole length (the 5-octet header and the
 * fragment) when all of it is there; 0 when more octets are needed; or
 * -HTTPASM_TLS_ALERT_RECORD_OVERFLOW for a fragment longer than a TLS 1.3 record carries
 * (2^14 + 256 octets for application_data, 2^14 for the other types). The type's value and
 * the legacy version are not judged (the engine knows what it may receive). */
int64_t httpasm_tls_record_length(const uint8_t *in, size_t length);

/* Makes a record key from a traffic secret (Hash.length octets of the suite's hash) under
 * suite: key and IV by 7.3's labels, sequence 0, limit 2^14 + 1. Returns 0, or -1 for an
 * unknown suite (key then all zeros). */
int httpasm_tls13_record_key_init(httpasm_tls13_record_key *key, int suite,
                                  const uint8_t *traffic_secret);

/* Seals one record into out[0..capacity): header, AEAD of content || content_type || padding
 * zeros, tag; the sequence number advances. content may be out + 5 (built in place) or must
 * not overlap out. Returns the record's length; -1 (nothing written) for content_type 0,
 * content over 2^14 octets, TLSInnerPlaintext over key->limit or a record over capacity; -2
 * when the key has sealed all its AEAD may (AES-GCM's 2^24.5 records, 5.5): KeyUpdate first. */
int64_t httpasm_tls13_seal(httpasm_tls13_record_key *key, int content_type,
                           const uint8_t *content, size_t length, size_t padding, uint8_t *out,
                           size_t capacity);

/* Opens one record, record[0..length) as httpasm_tls_record_length framed it, in place: the
 * content is then record[5 ..) and *content_type its type, and the sequence number advances.
 * Returns the content's length; or minus the alert to end the connection with:
 * UNEXPECTED_MESSAGE (an outer type other than application_data, or a plaintext of zeros only),
 * DECODE_ERROR (the header's length is not length - 5), RECORD_OVERFLOW (a fragment over 2^14 +
 * 256, or TLSInnerPlaintext over key->limit), BAD_RECORD_MAC (the tag does not verify: the
 * fragment is then zeros), INTERNAL_ERROR (the sequence number would wrap). */
int64_t httpasm_tls13_open(httpasm_tls13_record_key *key, uint8_t *record, size_t length,
                           uint8_t *content_type);

/* The handshake messages (RFC 9846 4): read strictly and in place (pointers into the octets
 * given, valid while they are). Each reader answers 0 or minus the alert the handshake must end
 * with; what needs the other side's messages (a suite that was not offered, an extension that
 * was not asked for) is the engine's to judge. */
#define HTTPASM_TLS_CLIENT_HELLO         1      /* HandshakeType */
#define HTTPASM_TLS_SERVER_HELLO         2
#define HTTPASM_TLS_NEW_SESSION_TICKET   4
#define HTTPASM_TLS_END_OF_EARLY_DATA    5
#define HTTPASM_TLS_ENCRYPTED_EXTENSIONS 8
#define HTTPASM_TLS_CERTIFICATE          11
#define HTTPASM_TLS_CERTIFICATE_REQUEST  13
#define HTTPASM_TLS_CERTIFICATE_VERIFY   15
#define HTTPASM_TLS_FINISHED             20
#define HTTPASM_TLS_KEY_UPDATE           24
#define HTTPASM_TLS_MESSAGE_HASH         254

/* The messages an extension may appear in: the columns of RFC 9846 4.3's table, as bits. */
#define HTTPASM_TLS_IN_CH  1                    /* ClientHello */
#define HTTPASM_TLS_IN_SH  2                    /* ServerHello */
#define HTTPASM_TLS_IN_EE  4                    /* EncryptedExtensions */
#define HTTPASM_TLS_IN_CT  8                    /* a Certificate entry */
#define HTTPASM_TLS_IN_CR  16                   /* CertificateRequest */
#define HTTPASM_TLS_IN_NST 32                   /* NewSessionTicket */
#define HTTPASM_TLS_IN_HRR 64                   /* HelloRetryRequest */

/* The extensions the library knows, by index into httpasm_tls_extensions (the type in each
 * comment). TLS 1.2's own are known so that a TLS 1.3 answer carrying one is refused (they
 * stand in a ClientHello only). */
#define HTTPASM_TLS_EXT_SERVER_NAME               0   /* 0, RFC 6066 */
#define HTTPASM_TLS_EXT_MAX_FRAGMENT_LENGTH       1   /* 1 */
#define HTTPASM_TLS_EXT_STATUS_REQUEST            2   /* 5 */
#define HTTPASM_TLS_EXT_SUPPORTED_GROUPS          3   /* 10 */
#define HTTPASM_TLS_EXT_EC_POINT_FORMATS          4   /* 11, TLS 1.2 */
#define HTTPASM_TLS_EXT_SIGNATURE_ALGORITHMS      5   /* 13 */
#define HTTPASM_TLS_EXT_USE_SRTP                  6   /* 14 */
#define HTTPASM_TLS_EXT_HEARTBEAT                 7   /* 15 */
#define HTTPASM_TLS_EXT_ALPN                      8   /* 16, RFC 7301 */
#define HTTPASM_TLS_EXT_SCT                       9   /* 18, RFC 6962 */
#define HTTPASM_TLS_EXT_CLIENT_CERTIFICATE_TYPE   10  /* 19 */
#define HTTPASM_TLS_EXT_SERVER_CERTIFICATE_TYPE   11  /* 20 */
#define HTTPASM_TLS_EXT_PADDING                   12  /* 21, RFC 7685 */
#define HTTPASM_TLS_EXT_ENCRYPT_THEN_MAC          13  /* 22, TLS 1.2 */
#define HTTPASM_TLS_EXT_EXTENDED_MASTER_SECRET    14  /* 23, TLS 1.2 */
#define HTTPASM_TLS_EXT_COMPRESS_CERTIFICATE      15  /* 27, RFC 8879 */
#define HTTPASM_TLS_EXT_RECORD_SIZE_LIMIT         16  /* 28, RFC 8449 */
#define HTTPASM_TLS_EXT_DELEGATED_CREDENTIAL      17  /* 34, RFC 9345 */
#define HTTPASM_TLS_EXT_SESSION_TICKET            18  /* 35, TLS 1.2 */
#define HTTPASM_TLS_EXT_SUPPORTED_EKT_CIPHERS     19  /* 39 */
#define HTTPASM_TLS_EXT_PRE_SHARED_KEY            20  /* 41 */
#define HTTPASM_TLS_EXT_EARLY_DATA                21  /* 42 */
#define HTTPASM_TLS_EXT_SUPPORTED_VERSIONS        22  /* 43 */
#define HTTPASM_TLS_EXT_COOKIE                    23  /* 44 */
#define HTTPASM_TLS_EXT_PSK_KEY_EXCHANGE_MODES    24  /* 45 */
#define HTTPASM_TLS_EXT_CERTIFICATE_AUTHORITIES   25  /* 47 */
#define HTTPASM_TLS_EXT_OID_FILTERS               26  /* 48 */
#define HTTPASM_TLS_EXT_POST_HANDSHAKE_AUTH       27  /* 49 */
#define HTTPASM_TLS_EXT_SIGNATURE_ALGORITHMS_CERT 28  /* 50 */
#define HTTPASM_TLS_EXT_KEY_SHARE                 29  /* 51 */
#define HTTPASM_TLS_EXT_TRANSPARENCY_INFO         30  /* 52, RFC 9162 */
#define HTTPASM_TLS_EXT_EXTERNAL_ID_HASH          31  /* 55 */
#define HTTPASM_TLS_EXT_EXTERNAL_SESSION_ID       32  /* 56 */
#define HTTPASM_TLS_EXT_QUIC_TRANSPORT_PARAMETERS 33  /* 57, RFC 9001 */
#define HTTPASM_TLS_EXT_TICKET_REQUEST            34  /* 58, RFC 9149 */
#define HTTPASM_TLS_EXT_ECH_OUTER_EXTENSIONS      35  /* 0xFD00, RFC 9849 */
#define HTTPASM_TLS_EXT_ENCRYPTED_CLIENT_HELLO    36  /* 0xFE0D, RFC 9849 */
#define HTTPASM_TLS_EXT_RENEGOTIATION_INFO        37  /* 0xFF01, TLS 1.2 */
#define HTTPASM_TLS_EXTENSIONS                    38

/* An extension block as httpasm_tls_extensions_read found it (400 octets). */
typedef struct httpasm_tls_extensions {
    uint64_t present;                   /* bit i: the extension of index i was in the block */
    uint32_t count;                     /* the block's extensions, known or not */
    uint32_t last;                      /* the type of its last one */
    const uint8_t *data[HTTPASM_TLS_EXTENSIONS];    /* each present one's extension_data */
    uint16_t length[HTTPASM_TLS_EXTENSIONS];        /* and its octets */
    uint16_t reserved[2];
} httpasm_tls_extensions;

/* A ClientHello or a ServerHello (a HelloRetryRequest among them) as httpasm_tls13_hello_read
 * found it (464 octets): pointers into the body read. */
typedef struct httpasm_tls13_hello {
    const uint8_t *random;              /* 32 octets */
    const uint8_t *session_id;          /* legacy_session_id (a ServerHello's echo) */
    const uint8_t *cipher_suites;       /* a ClientHello's list: pairs of octets */
    const uint8_t *compression;         /* a ClientHello's legacy_compression_methods */
    const uint8_t *extensions_block;    /* the block's first octet, after its length (NULL: none) */
    size_t extensions_length;
    uint32_t cipher_suites_length;      /* octets of the list */
    uint16_t legacy_version;
    uint16_t cipher_suite;              /* a ServerHello's */
    uint8_t session_id_length;
    uint8_t compression_length;
    uint8_t compression_method;         /* a ServerHello's */
    uint8_t retry;                      /* 1: a ServerHello that is a HelloRetryRequest */
    uint8_t reserved[4];
    httpasm_tls_extensions extensions;
} httpasm_tls13_hello;

/* The handshake message at the start of in[0..length): its whole length (4 + the body's) with
 * *type and *body_length set when all of it is there; 0 when more octets are needed. */
int64_t httpasm_tls_message(const uint8_t *in, size_t length, uint32_t *type, size_t *body_length);

/* Walks an extension block's octets (after its uint16 length) as found in message (one
 * HTTPASM_TLS_IN_* bit): each known extension's data by index. Returns 0; DECODE_ERROR for an
 * extension past the block; ILLEGAL_PARAMETER for a type twice (any of the 65,536), a known type
 * the message may not carry (4.3's table), or a ClientHello's pre_shared_key not last. The data
 * is not looked into (the message readers do that). */
int httpasm_tls_extensions_read(httpasm_tls_extensions *ext, int message, const uint8_t *block,
                                size_t length);

/* A ClientHello's (type 1) or ServerHello's (type 2) body: its fields, its extension block
 * walked, and the syntax of each extension the engine reads checked (decode_error; the value
 * rules: illegal_parameter); a ClientHello offering TLS 1.3 must carry compression method 0
 * alone, a ServerHello's must be 0; a ServerHello with HelloRetryRequest's random is one
 * (hello->retry). The legacy_version is returned, not judged. Returns 0, minus an alert, or -1
 * for another type. */
int httpasm_tls13_hello_read(httpasm_tls13_hello *hello, int type, const uint8_t *body,
                             size_t length);

/* A body that is an extension block with its uint16 length (EncryptedExtensions: message
 * HTTPASM_TLS_IN_EE), walked and checked. Returns 0 or minus an alert. */
int httpasm_tls13_extensions_message_read(httpasm_tls_extensions *ext, int message,
                                          const uint8_t *body, size_t length);

/* A CertificateRequest: its context and its extensions, signature_algorithms among them (else
 * MISSING_EXTENSION). Returns 0 or minus an alert. */
int httpasm_tls13_certificate_request_read(httpasm_tls_extensions *ext, const uint8_t **context,
                                           size_t *context_length, const uint8_t *body,
                                           size_t length);

/* A Certificate message: its context and its certificate_list, each entry's extensions checked.
 * Returns the count of entries, or minus an alert; httpasm_tls13_certificate_entry reads them. */
int64_t httpasm_tls13_certificate_read(const uint8_t *body, size_t length, const uint8_t **context,
                                       size_t *context_length, const uint8_t **list,
                                       size_t *list_length);

/* The entry at list[offset..) of a list httpasm_tls13_certificate_read accepted: its cert_data
 * and its extensions. Returns the next entry's offset (list_length after the last). The entry is
 * judged again, not trusted: DECODE_ERROR for an offset at or past the end, an entry past the
 * list or an empty cert_data; its extensions' alert otherwise. Reads nothing outside the list,
 * wherever the caller keeps it. */
int64_t httpasm_tls13_certificate_entry(const uint8_t *list, size_t list_length, size_t offset,
                                        const uint8_t **cert, size_t *cert_length,
                                        httpasm_tls_extensions *ext);

/* A CertificateVerify: its SignatureScheme and signature. Returns 0 or DECODE_ERROR. */
int httpasm_tls13_certificate_verify_read(const uint8_t *body, size_t length, uint32_t *scheme,
                                          const uint8_t **signature, size_t *signature_length);

/* A NewSessionTicket: *lifetime_age_add = ticket_lifetime | (uint64_t)ticket_age_add << 32;
 * *nonce at the ticket_nonce's length octet, *ticket at the ticket's uint16 length; its
 * extensions (NST's) in ext. Returns 0 or minus an alert. */
int httpasm_tls13_new_session_ticket_read(httpasm_tls_extensions *ext, const uint8_t *body,
                                          size_t length, uint64_t *lifetime_age_add,
                                          const uint8_t **nonce, const uint8_t **ticket);

/* A KeyUpdate: its request_update, 0 or 1; or DECODE_ERROR (another length), ILLEGAL_PARAMETER
 * (another value). */
int httpasm_tls13_key_update_read(const uint8_t *body, size_t length);

/* ------------------------------------------------------------------------------------------
 * The TLS 1.3 engine (RFC 9846; docs/DESIGN.md M2 4c): a server's handshake and records,
 * sans-I/O. Bytes in (httpasm_tls13_receive, one record a call, opened in place), bytes out (the
 * connection's output span, drained by the caller: httpasm_tls13_output and _output_done).
 * Memory, randomness and time are the caller's: a configuration shared by connections, each
 * connection's state and spans in memory the caller gives, randomness through a callback.
 * ------------------------------------------------------------------------------------------ */

#define HTTPASM_TLS_GROUP_SECP256R1          0x0017  /* NamedGroup (RFC 9846 4.3.7) */
#define HTTPASM_TLS_GROUP_SECP384R1          0x0018
#define HTTPASM_TLS_GROUP_SECP521R1          0x0019
#define HTTPASM_TLS_GROUP_X25519             0x001D
#define HTTPASM_TLS_GROUP_X448               0x001E
#define HTTPASM_TLS_GROUP_FFDHE2048          0x0100  /* RFC 7919 */
#define HTTPASM_TLS_GROUP_FFDHE3072          0x0101
#define HTTPASM_TLS_GROUP_FFDHE4096          0x0102
#define HTTPASM_TLS_GROUP_FFDHE6144          0x0103
#define HTTPASM_TLS_GROUP_FFDHE8192          0x0104
#define HTTPASM_TLS_GROUP_SECP256R1MLKEM768  0x11EB  /* RFC 10024 */
#define HTTPASM_TLS_GROUP_X25519MLKEM768     0x11EC
#define HTTPASM_TLS_GROUP_SECP384R1MLKEM1024 0x11ED
#define HTTPASM_TLS_GROUPS_MAX               16      /* a configuration's list at most */

#define HTTPASM_TLS_SCHEME_ECDSA_SECP256R1_SHA256 0x0403  /* SignatureScheme (RFC 9846 4.3.3) */
#define HTTPASM_TLS_SCHEME_ECDSA_SECP384R1_SHA384 0x0503
#define HTTPASM_TLS_SCHEME_ECDSA_SECP521R1_SHA512 0x0603
#define HTTPASM_TLS_SCHEME_RSA_PSS_RSAE_SHA256    0x0804
#define HTTPASM_TLS_SCHEME_RSA_PSS_RSAE_SHA384    0x0805
#define HTTPASM_TLS_SCHEME_RSA_PSS_RSAE_SHA512    0x0806
#define HTTPASM_TLS_SCHEME_ED25519                0x0807
#define HTTPASM_TLS_SCHEME_ED448                  0x0808
#define HTTPASM_TLS_SCHEME_RSA_PSS_PSS_SHA256     0x0809
#define HTTPASM_TLS_SCHEME_RSA_PSS_PSS_SHA384     0x080A
#define HTTPASM_TLS_SCHEME_RSA_PSS_PSS_SHA512     0x080B

/* The bits of httpasm_tls13_server_config.schemes: the schemes the server's key can make. */
#define HTTPASM_TLS_SCHEME_BIT_RSA_PSS_RSAE_SHA256    0
#define HTTPASM_TLS_SCHEME_BIT_RSA_PSS_RSAE_SHA384    1
#define HTTPASM_TLS_SCHEME_BIT_RSA_PSS_RSAE_SHA512    2
#define HTTPASM_TLS_SCHEME_BIT_RSA_PSS_PSS_SHA256     3
#define HTTPASM_TLS_SCHEME_BIT_RSA_PSS_PSS_SHA384     4
#define HTTPASM_TLS_SCHEME_BIT_RSA_PSS_PSS_SHA512     5
#define HTTPASM_TLS_SCHEME_BIT_ECDSA_SECP256R1_SHA256 6
#define HTTPASM_TLS_SCHEME_BIT_ECDSA_SECP384R1_SHA384 7
#define HTTPASM_TLS_SCHEME_BIT_ECDSA_SECP521R1_SHA512 8
#define HTTPASM_TLS_SCHEME_BIT_ED25519                9
#define HTTPASM_TLS_SCHEME_BIT_ED448                  10

#define HTTPASM_TLS_CLIENT_AUTH_REQUEST 1   /* config flags: ask for a client certificate */
#define HTTPASM_TLS_CLIENT_AUTH_REQUIRE 2   /* and end the handshake without one */
#define HTTPASM_TLS_SERVER_GROUP_ORDER  4   /* the server's first group the client supports, even
                                             * at the cost of a HelloRetryRequest (default: its
                                             * first group the client sent a share for) */

#define HTTPASM_TLS_EVENT_NONE      0   /* the record was taken; nothing to report (output may wait) */
#define HTTPASM_TLS_EVENT_CONNECTED 1   /* the handshake completed */
#define HTTPASM_TLS_EVENT_DATA      2   /* application data: event->data, ->length, in the input */
#define HTTPASM_TLS_EVENT_CLOSED    3   /* the peer's close_notify: it sends nothing more */
#define HTTPASM_TLS_EVENT_FAILED    4   /* the connection failed: event->alert */
#define HTTPASM_TLS_EVENT_PEER      1   /* event->flags: the alert was the peer's */

#define HTTPASM_TLS_MESSAGE_DEFAULT 16384   /* the largest handshake message gathered by default */

/* The random source the engine draws from: fills out[0..length) and returns 0, or nonzero when
 * it cannot (the handshake then ends with internal_error). httpasm_tls_random is getrandom's. */
typedef int (*httpasm_tls_random_fn)(void *context, uint8_t *out, size_t length);

/* getrandom through httpasm_random, as an httpasm_tls_random_fn (context unused). */
int httpasm_tls_random(void *context, uint8_t *out, size_t length);

/* A server's settings (152 octets), shared by its connections and read-only while they run. The
 * caller sets the "in" fields, then httpasm_tls13_server_config_init sets the rest. */
typedef struct httpasm_tls13_server_config {
    const httpasm_private_key *key;     /* in: the server's key; must outlive the configuration */
    httpasm_tls_random_fn random;       /* in: the random source */
    void *random_context;               /* in: its first argument */
    uint16_t groups[HTTPASM_TLS_GROUPS_MAX];    /* in: NamedGroups in the server's order */
    uint32_t group_count;               /* in: 0 = the library's order */
    uint16_t suites[4];                 /* in: cipher suites in the server's order */
    uint32_t suite_count;               /* in: 0 = the library's order */
    uint32_t flags;                     /* in: HTTPASM_TLS_CLIENT_AUTH_* */
    uint32_t max_message;               /* in: the largest handshake message gathered; 0 = the default */
    const uint8_t *certificate;         /* out: the Certificate message, in the caller's buffer */
    size_t certificate_length;          /* out */
    uint64_t schemes;                   /* out: HTTPASM_TLS_SCHEME_BIT_* the key makes */
    size_t output_min;                  /* out: the output span a connection needs at least */
    size_t memory;                      /* out: a connection's memory (max_message + output_min) */
    uint64_t reserved[4];
} httpasm_tls13_server_config;

/* What httpasm_tls13_receive reports (32 octets). */
typedef struct httpasm_tls13_event {
    uint32_t kind;                      /* HTTPASM_TLS_EVENT_* */
    uint32_t alert;                     /* FAILED: the alert's description */
    const uint8_t *data;                /* DATA: the plaintext, inside the input (valid while it is) */
    size_t length;
    uint32_t flags;                     /* FAILED: HTTPASM_TLS_EVENT_PEER when the peer sent the alert */
    uint32_t reserved;
} httpasm_tls13_event;

/* One connection's state (2752 octets), opaque; its secrets are secret: httpasm_tls13_wipe it.
 * Best 16-aligned (its record keys are then 16-aligned inside it). */
typedef struct httpasm_tls13_connection {
    uint64_t opaque[344];
} httpasm_tls13_connection;

/* Checks a server's configuration and fills its "out" fields: the Certificate message built from
 * chain[0..count) (DER certificates, the leaf first; lengths[i] each) into buffer[0..capacity);
 * the leaf's public key matched to config->key; the schemes the key makes; the library's groups
 * (X25519MLKEM768, x25519, secp256r1, x448, secp384r1, secp521r1, SecP256r1MLKEM768,
 * SecP384r1MLKEM1024, ffdhe2048-8192) and suites (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
 * where none are given; the sizes a connection needs. Returns 0; -1 for no key or no random
 * source, a list over its bound or naming a group or suite the engine lacks, or no chain; -2
 * for a certificate that does not parse or a leaf whose key is not config->key's; -3 when
 * buffer is too small (config->certificate_length then holds the octets needed). */
int httpasm_tls13_server_config_init(httpasm_tls13_server_config *config,
                                     const uint8_t *const *chain, const size_t *lengths,
                                     size_t count, uint8_t *buffer, size_t capacity);

/* Starts a server connection in memory[0..length), at least config->memory octets (the
 * reassembly span, then the output span), which the connection uses until it is wiped. The
 * configuration must outlive the connection and stay as init left it while any connection uses
 * it (every connection reads it live). Returns 0, or -1 when length is too small, or when the
 * configuration was edited since init past the bounds that keep a connection inside its memory
 * (max_message + output_min over length, 0 or more than 16 groups, 0 or more than 4 suites).
 * Footgun: an output_min lowered by hand is not caught; such a connection fails its handshake
 * with internal_error when its flight does not fit, without writing past its spans. */
int httpasm_tls13_server_init(httpasm_tls13_connection *c, const httpasm_tls13_server_config *config,
                              uint8_t *memory, size_t length);

/* Takes the record at the start of in[0..length), opened in place (in is the caller's and is
 * written: decrypted records become their plaintext). Returns the record's octets, consumed,
 * with *event saying what it brought; 0 when no whole record is there yet (nothing consumed);
 * or -1 when the connection failed (event->kind FAILED, event->alert the alert, event->flags
 * HTTPASM_TLS_EVENT_PEER when the peer sent it; ours is queued in the output). After a failure
 * every call answers the same. Whatever the call answers, output may wait: check
 * httpasm_tls13_output. The engine's randomness is drawn in a fixed order (for replaying a
 * trace): the server random (32 octets); then the key share's private parts in the order its
 * share carries them (X25519MLKEM768: ML-KEM's m, then X25519's scalar; an ECDH scalar drawn
 * again while out of range; P-521's 66 octets with the first masked to its one bit); then the
 * CertificateVerify's (an RSA-PSS salt of the hash's length, or ECDSA hedging of the curve's
 * scalar size; none for EdDSA). The stack it needs: about 64 KiB (RSA's signing and FFDHE's
 * frames), touched a page at a time. */
int64_t httpasm_tls13_receive(httpasm_tls13_connection *c, uint8_t *in, size_t length,
                              httpasm_tls13_event *event);

/* The octets queued to send: *out and the count (0: none). They stay until _output_done. */
size_t httpasm_tls13_output(const httpasm_tls13_connection *c, const uint8_t **out);

/* Takes n octets (at most what httpasm_tls13_output gave) off the front of the output. */
void httpasm_tls13_output_done(httpasm_tls13_connection *c, size_t n);

/* Seals application data into the output, records of up to 2^14 octets each (fewer under the
 * peer's record_size_limit): returns how many octets of data it took (as many as fit: fewer,
 * even 0, when the output is full: drain it and call again); or -1 before our Finished is out,
 * after our close_notify, or after a failure. A KeyUpdate the peer asked for goes first, and
 * under AES-GCM one of ours goes before the key's 2^24.5 records run out (RFC 9846 5.5). */
int64_t httpasm_tls13_send(httpasm_tls13_connection *c, const uint8_t *data, size_t length);

/* Queues close_notify: nothing more will be sent (the peer may go on sending). Returns 0, or -1
 * when the connection cannot (failed, already closed, or the output is full). */
int httpasm_tls13_close(httpasm_tls13_connection *c);

/* Queues a KeyUpdate (request: 1 asks the peer to update its keys too) and moves to the next
 * write key (RFC 9846 4.7.3). Returns 0, or -1 before the handshake completed, after a failure
 * or close_notify, or when the output is full. */
int httpasm_tls13_key_update(httpasm_tls13_connection *c, int request);

/* What the handshake chose: the suite, the group and the signature scheme (0 for those not
 * chosen yet). Returns the connection's state's progress: 0 before a ServerHello, 1 while the
 * handshake goes on, 2 once connected, -1 after a failure. */
int httpasm_tls13_negotiated(const httpasm_tls13_connection *c, uint32_t *suite, uint32_t *group,
                             uint32_t *scheme);

/* Zeroes the connection (its secrets and keys) and its spans' octets. */
void httpasm_tls13_wipe(httpasm_tls13_connection *c);

/* ------------------------------------------------------------------------------------------
 * Field rules (RFC 9110 sections 5.1, 5.5, 5.6.2)
 * ------------------------------------------------------------------------------------------ */

/* The number of leading octets of p[0..n) that are tchar, n when all are. p holds a valid token
 * (a method, a field name) when n > 0 and the result is n. Reads nothing past p + n; p may be
 * NULL when n is 0. */
size_t httpasm_token_length(const uint8_t *p, size_t n);

/* The index of the first octet of p[0..n) that a field value may not hold, n when there is none.
 * The forbidden octets are the control characters other than HTAB: 0x00-0x08, 0x0A-0x1F, 0x7F.
 * CR, LF and NUL must never reach a peer. HttpAsm also refuses the other control characters,
 * which RFC 9110 lets a recipient keep. Whitespace at the value's ends is not checked: HTTP/1.1
 * trims it, and HTTP/2 and HTTP/3 forbid it. May read up to 16 octets from p when n < 16, but
 * only within p's 4 KiB page, which cannot fault. p may be NULL when n is 0. */
size_t httpasm_field_value_scan(const uint8_t *p, size_t n);

/* The HTTPASM_FIELD_* id of a field name, compared without regard to case (RFC 9110 5.1); 0 when
 * the name is not a known field or not a token. */
uint32_t httpasm_field_id(const uint8_t *name, size_t n);

/* A known field's name, lower case and not NUL-terminated, with its length in *length; NULL and
 * 0 for an id that is not a known field's. length may be NULL. */
const uint8_t *httpasm_field_name(uint32_t id, size_t *length);

/* ------------------------------------------------------------------------------------------
 * HTTP/1.1 (RFC 9112), sans-I/O
 * ------------------------------------------------------------------------------------------ */

/* Parses one request head from buf[0..len). Returns:
 *   > 0  the head's length, leading empty lines included. *request and fields[0..field_count)
 *        are filled, with pointers into buf; *scan_from is reset to 0.
 *   0    the head is incomplete: call again with more octets appended (the buffer may move; the
 *        offsets may not). *scan_from remembers where the search for the head's end resumes;
 *        set it to 0 before each new message. A *scan_from past len (a value left over from a
 *        longer buffer) is ignored and the search starts over, so a stale one costs a rescan,
 *        never a missed line; one at or below len is trusted: octets before it are not searched
 *        again.
 *   < 0  -status (400, 414, 417, 431, 501 or 505): answer with that status and close the
 *        connection. request->error names the rule. *scan_from is reset to 0.
 * limits may be NULL (every default); fields must hold limits->max_fields records (default 128).
 * Lines must end in CRLF (a bare LF is refused). A Transfer-Encoding with Content-Length, in an
 * HTTP/1.0 message, or whose final coding is not chunked is refused. Codings other than chunked
 * answer 501 for now. */
int64_t httpasm_h1_parse_request(const uint8_t *buf, size_t len, size_t *scan_from,
                                 const httpasm_h1_limits *limits, httpasm_request *request,
                                 httpasm_field *fields);

/* Decodes a chunked body in place: in[0..len) are body octets as received; the data octets are
 * moved to in[0..*produced) and the framing removed. Returns the octets consumed, or -400 (the
 * state becomes HTTPASM_CHUNKED_ERROR and stays so). It stops after the last chunk's line
 * (state HTTPASM_CHUNKED_TRAILERS): the trailer section starts at in[consumed]. chunk-size is
 * refused past 2^63; chunk-ext is skipped (at most 4096 octets per line, no control
 * characters). */
int64_t httpasm_h1_chunked_decode(httpasm_h1_chunked *state, uint8_t *in, size_t len,
                                  size_t *produced);

/* The trailer section after the last chunk (its fields flagged HTTPASM_FIELD_FLAG_TRAILER, never
 * merged into the header section). Returns its length (2 when empty), 0 incomplete (scan_from as
 * for a head), -400 or -431. *count receives the number of fields. */
int64_t httpasm_h1_parse_trailers(uint8_t *buf, size_t len, size_t *scan_from,
                                  const httpasm_h1_limits *limits, httpasm_field *fields,
                                  uint32_t *count);

/* The client's side: one response head. request_method is the request's HTTPASM_METHOD_* (HEAD
 * and CONNECT decide the framing). buf is writable: an obs-fold is replaced with SP in place, as
 * RFC 9112 5.2 requires of a user agent. Returns the head's length, 0 incomplete (*scan_from as
 * for httpasm_h1_parse_request, a stale one past len included), -400 (close and discard;
 * head->error names the rule) or -431. A 1xx comes back with HTTPASM_RESPONSE_HEAD_NO_BODY; read
 * the final response after it. */
int64_t httpasm_h1_parse_response(uint8_t *buf, size_t len, size_t *scan_from,
                                  const httpasm_h1_limits *limits, uint32_t request_method,
                                  httpasm_response_head *head, httpasm_field *fields);

/* A server's response head into out[0..cap): the status-line, the writer's framing fields
 * (Content-Length or Transfer-Encoding, Connection, Date), the caller's fields, CRLF. See
 * httpasm_response for the flags it reports. Returns the head's length, 0 if cap is too small,
 * or -HTTPASM_ERROR_* (nothing written). A content_length past 2^63 - 1 is refused
 * (-HTTPASM_ERROR_CONTENT_LENGTH): HttpAsm's own parsers refuse such a length, and a writer
 * never sends what its library would refuse to read. */
int64_t httpasm_h1_write_response(uint8_t *out, size_t cap, httpasm_response *response);

/* A client's request head from an httpasm_request: method, target, authority (sent first as
 * Host), fields; flags HTTPASM_REQUEST_CONTENT_LENGTH (with content_length) or _CHUNKED, _CLOSE,
 * _EXPECT_CONTINUE (written only when the request has content: chunked, or a length above 0).
 * Always HTTP/1.1. Returns the length, 0 if cap is too small, or -HTTPASM_ERROR_* (a
 * content_length past 2^63 - 1: -HTTPASM_ERROR_CONTENT_LENGTH, as for responses). */
int64_t httpasm_h1_write_request(uint8_t *out, size_t cap, const httpasm_request *request);

/* One chunk (len >= 1): hex size CRLF data CRLF. Returns the length, 0 if cap is too small, or
 * -HTTPASM_ERROR_CHUNK for len 0. */
int64_t httpasm_h1_write_chunk(uint8_t *out, size_t cap, const uint8_t *data, size_t len);

/* The end of a chunked body: "0" CRLF, the trailers, CRLF. Returns the length, 0 if cap is too
 * small, or -HTTPASM_ERROR_* for a trailer field that is invalid or not allowed in trailers. */
int64_t httpasm_h1_write_last_chunk(uint8_t *out, size_t cap, const httpasm_field *trailers,
                                    uint32_t count);

/* ------------------------------------------------------------------------------------------
 * HPACK (RFC 7541): HTTP/2's field compression. A table is one block of caller memory; an
 * HTTP/2 connection keeps two, the decoder's and the encoder's. Nothing here checks HTTP/2's
 * own field rules (lower-case names, pseudo-fields): the HTTP/2 layer does.
 * ------------------------------------------------------------------------------------------ */

typedef struct httpasm_hpack httpasm_hpack;     /* opaque */

#define HTTPASM_HPACK_HUFFMAN   0x0001          /* encoder: Huffman-code strings unless longer */
/* encoder: also index the fields that rarely repeat (:path, content-length, location,
 * set-cookie, ...), for traffic whose values do repeat, such as RPC calls to a few paths.
 * Credentials and NO_INDEX fields stay out regardless. */
#define HTTPASM_HPACK_INDEX_ALL 0x0002
#define HTTPASM_HPACK_MAX_LIMIT 0x1000000       /* the largest limit httpasm_hpack_init takes */

/* The octets a table with this limit needs; 0 past HTTPASM_HPACK_MAX_LIMIT. 9344 for 4096. */
size_t httpasm_hpack_size(uint32_t limit);

/* Makes memory an empty table. Decoder: limit is the SETTINGS_HEADER_TABLE_SIZE this side
 * advertises (size updates above it are errors). Encoder: limit is the most this side uses;
 * the peer's setting caps it (httpasm_hpack_encoder_limit). The table starts at 4096 octets, or
 * at limit when smaller. 0, or -HTTPASM_ERROR_HPACK_LIMIT. */
int httpasm_hpack_init(void *memory, size_t size, uint32_t limit, uint32_t flags);

/* Decodes one complete header block into output. 0: every field was written. 1: the block was
 * decoded (the table is in step) but fields or space ran out; the first records are written
 * and list_size counts all: refuse the request, keep the connection. Once the output is full
 * (max_fields records written, or a field that did not fit), nothing more is written to space:
 * the rest of the block is only measured, at a constant cost per octet, so a block of 1-octet
 * references to a large dynamic entry (an HPACK bomb) costs no more than any block of its size.
 * The field that finds the space too small may have written into the room left (never past
 * space_size). -HTTPASM_ERROR_HPACK_*: malformed; the table must not be used again (HTTP/2:
 * COMPRESSION_ERROR). */
int64_t httpasm_hpack_decode(httpasm_hpack *table, const uint8_t *block, size_t length,
                             httpasm_hpack_output *output);

/* The most octets httpasm_hpack_encode may write for these fields. */
size_t httpasm_hpack_encode_bound(const httpasm_field *fields, uint32_t count);

/* Encodes the fields as one header block. The length, or 0 when cap is below
 * httpasm_hpack_encode_bound (nothing written, the table unchanged). Credentials and fields
 * flagged NEVER_INDEXED use the never-indexed literal; NO_INDEX keeps a field out of the table. */
int64_t httpasm_hpack_encode(httpasm_hpack *table, const httpasm_field *fields, uint32_t count,
                             uint8_t *out, size_t cap);

/* The peer's SETTINGS_HEADER_TABLE_SIZE, for an encoder's table: applied now, signalled at the
 * start of the next block (the smallest maximum since the last block first). */
void httpasm_hpack_encoder_limit(httpasm_hpack *table, uint32_t limit);

/* The dynamic table's size (RFC 7541 4.1), and its maximum in *max_size (may be NULL). */
uint32_t httpasm_hpack_table_size(const httpasm_hpack *table, uint32_t *max_size);

/* The entry at an HPACK index (1-61 static, 62 on dynamic, newest first) into *field; valid
 * until the table changes. 0, or -HTTPASM_ERROR_HPACK_INDEX. */
int httpasm_hpack_entry(const httpasm_hpack *table, uint32_t index, httpasm_field *field);

/* ------------------------------------------------------------------------------------------
 * HTTP/2 (RFC 9113): the request view of a decoded header list. The server speaks HTTP/2 on
 * its own (h2c with prior knowledge); these are its rules, for callers that decode themselves.
 * ------------------------------------------------------------------------------------------ */

/* Checks a request's decoded header list (RFC 9113 8.2, 8.3: lower-case token names, valid
 * values, pseudo-fields first and once, no connection-specific field, TE only "trailers",
 * :path with HTTP/1.1's target octets, :authority without userinfo and matching any Host) and
 * fills request: method, target (:path; :authority for CONNECT), authority (else Host), scheme,
 * version 20, flags, content_length, and fields/field_count (the regular fields, after the
 * pseudo-fields in the same array). 0, or -HTTPASM_ERROR_* with request->error set: malformed
 * (a stream error PROTOCOL_ERROR), except -HTTPASM_ERROR_EXPECT (answer 417). */
int httpasm_h2_request(httpasm_field *fields, uint32_t count, httpasm_request *request);

/* Checks a request's trailer section: no pseudo-field, valid names and values. Flags each
 * record HTTPASM_FIELD_FLAG_TRAILER. 0, or -HTTPASM_ERROR_H2_PSEUDO / -FIELD_NAME / -FIELD_VALUE. */
int httpasm_h2_trailers(httpasm_field *fields, uint32_t count);

/* ------------------------------------------------------------------------------------------
 * The server (Linux): one worker thread per core, each with its own listening socket
 * (SO_REUSEPORT), io_uring ring (or epoll, where io_uring is refused or not wanted), and
 * connections. Handlers run on the worker that read the request.
 * ------------------------------------------------------------------------------------------ */

typedef struct httpasm_server httpasm_server;       /* opaque */
typedef struct httpasm_exchange httpasm_exchange;   /* one request and its response; opaque */

/* Called on a worker thread for each complete request (head, body, trailers). The handler
 * answers with httpasm_exchange_respond before returning, or calls httpasm_exchange_defer and
 * answers later from any thread. It must not block the worker for long: every connection of
 * that worker waits meanwhile. A handler that returns without either answers 500 and closes the
 * connection. */
typedef void (*httpasm_handler)(void *context, httpasm_exchange *exchange);

/* The server's settings (64 octets). A zero field takes its default. */
typedef struct httpasm_server_options {
    httpasm_handler handler;    /* required */
    void *context;              /* passed to the handler */
    uint64_t max_body;          /* request bodies past this get 413; default 1 MiB */
    uint32_t workers;           /* worker threads; default: the CPUs this process may run on */
    uint32_t idle_timeout_ms;   /* a connection idle, or a request head not complete, this long
                                   is closed; default 60000 (see min_data_rate) */
    uint32_t bind_address;      /* IPv4, network byte order; 0 is 0.0.0.0 */
    uint16_t port;              /* 0: any free port (httpasm_server_port tells which) */
    uint16_t flags;             /* HTTPASM_SERVER_* */
    httpasm_h1_limits limits;   /* the heads' limits */
    uint32_t min_data_rate;     /* octets a second a transfer must keep to outlive the idle
                                   timeout; default 240 (ASP.NET Core Kestrel's) */
    uint32_t reserved;
} httpasm_server_options;

/* Timeouts. idle_timeout_ms is a window, judged when it ends:
 * - A connection with nothing in progress closes: HTTP/1.1 between requests or within a request
 *   head (a head must be whole within one window: slowloris), HTTP/2 with no active stream.
 *   Control frames are no activity: an HTTP/2 connection that only PINGs closes, with GOAWAY.
 * - A transfer in progress - a request body arriving, an answer being sent - gets another
 *   window when it moved at least min_data_rate octets a second over the one that ended; below
 *   that the connection closes (slow-POST/RUDY, slow reads: a client that holds an answer's
 *   memory by reading it a few octets at a time). So a large transfer takes as long as it
 *   needs, at any pace a real client keeps.
 * - An HTTP/2 stream is judged on its own too, so busy connections cannot hide stuck streams: one
 *   whose request stopped arriving is answered 408 and reset; one whose answer stopped leaving
 *   (its window never opened) is reset with CANCEL.
 * - A deferred exchange (httpasm_exchange_defer) holds its connection open: the handler decides.
 * Footgun: min_data_rate counts octets the kernel took; a client with a large receive buffer
 * takes the first megabytes of an answer at once, and is then judged on how it reads the rest. */

/* The workers wait and do their I/O through epoll, unless HTTPASM_SERVER_URING asks each worker
 * for its own io_uring (Linux 5.13 or later) instead; a worker whose ring the kernel refuses
 * runs on epoll all the same (seccomp profiles such as Docker's default refuse every ring).
 * epoll is the default because it measured as cheap or cheaper (Linux 5.15, benchmarks/README.md):
 * 4.99 us of server CPU per HTTP/1.1 keep-alive request against 5.10-5.46 on io_uring, the same
 * pipelined and over HTTP/2.
 * Footgun: Linux 6.14 to 7.2 charge each worker's ring to the user's RLIMIT_MEMLOCK (84 KiB, up
 * to 144 KiB while the kernel rounds its allocation up), unless the kernel carries upstream
 * commit b59cabf9b4ac (2026-10-06), which reverts that 6.14 regression and is backported to
 * stable kernels. The limit is shared by all of the user's processes (8 MiB by default on
 * Ubuntu 24.04: at least 57 rings); a worker past it silently runs on epoll. On such kernels,
 * raise the limit (ulimit -l, systemd's LimitMEMLOCK=) for large or many servers, and check
 * httpasm_server_io. */
#define HTTPASM_SERVER_URING        0x0001
#define HTTPASM_SERVER_IO_NONE      0   /* httpasm_server_io: not running */
#define HTTPASM_SERVER_IO_EPOLL     1   /* every worker on epoll */
#define HTTPASM_SERVER_IO_URING     2   /* every worker on its own io_uring */
#define HTTPASM_SERVER_IO_MIXED     3   /* some workers on io_uring, the others on epoll */

/* A server with these options, not started. NULL on failure, with *error = -EINVAL (no handler),
 * -ENOMEM, or -EMFILE/-ENFILE (no descriptor left for a worker's eventfd); error may be NULL. */
httpasm_server *httpasm_server_create(const httpasm_server_options *options, int *error);

/* Opens every worker's socket and starts its thread. 0, or -errno (EADDRINUSE, ...): on failure
 * nothing is left running. -EINVAL when already running. */
int httpasm_server_start(httpasm_server *server);

/* The port the server listens on (the kernel's choice for port 0, once started). */
uint16_t httpasm_server_port(const httpasm_server *server);

/* What the running server's workers use: HTTPASM_SERVER_IO_URING (all of them), _EPOLL (all),
 * _MIXED (asked for io_uring, each worker makes its ring on its own, and the kernel refused
 * some: see HTTPASM_SERVER_URING's footgun), or HTTPASM_SERVER_IO_NONE when not running. A call
 * racing httpasm_server_stop may see _MIXED as the workers exit. */
uint32_t httpasm_server_io(const httpasm_server *server);

/* Stops accepting, lets exchanges in flight finish for up to 5 seconds (deferred ones too, even
 * when their client is gone), closes every connection, and returns when every worker has
 * exited. A deferred exchange may still be answered after that (its answer is dropped, freed by
 * the next start or by httpasm_server_destroy). The server may be started again. */
void httpasm_server_stop(httpasm_server *server);

/* Stops the server if it runs, and frees it with every answer still waiting for it. Every
 * deferred exchange must be answered before this: an answer after it uses freed memory, and an
 * exchange never answered leaks its connection's memory. */
void httpasm_server_destroy(httpasm_server *server);

/* The request: valid until the exchange is answered. */
const httpasm_request *httpasm_exchange_request(const httpasm_exchange *exchange);

/* The request's body, decoded (no chunked framing), *length octets; valid until answered. */
const uint8_t *httpasm_exchange_body(const httpasm_exchange *exchange, size_t *length);

/* The trailer fields of a chunked request (*count, 0 when none), kept apart from the header. */
const httpasm_field *httpasm_exchange_trailers(const httpasm_exchange *exchange, uint32_t *count);

/* In the handler: answer later, from any thread. The connection waits; later requests on it
 * too (responses leave in request order). 0, or -EINVAL outside the handler. */
int httpasm_exchange_defer(httpasm_exchange *exchange);

/* Answers the exchange: status, the caller's fields (the library adds Date, Content-Length or
 * chunked, Connection), and the body (left out for HEAD, 1xx, 204, 304). In the handler, or
 * after httpasm_exchange_defer from any thread; once. The fields and body are copied before it
 * returns. 0; -HTTPASM_ERROR_* when the status or a field is refused (nothing sent: answer
 * again); -EINVAL when already answered; -ENOMEM. Footgun: a 2xx to CONNECT is refused
 * (-HTTPASM_ERROR_STATUS), because it would start a tunnel the server cannot carry yet; answer
 * CONNECT with a 4xx or 5xx (501, 405). */
int httpasm_exchange_respond(httpasm_exchange *exchange, uint16_t status,
                             const httpasm_field *fields, uint32_t count, const uint8_t *body,
                             size_t length);

/* ------------------------------------------------------------------------------------------
 * The client (Linux): one blocking HTTP/1.1 connection, requests answered in order. Not
 * thread-safe: one thread at a time per client.
 * ------------------------------------------------------------------------------------------ */

typedef struct httpasm_client httpasm_client;       /* opaque */

/* The field records httpasm_client_send keeps for one response: the head's fields first, read
 * under httpasm_h1_limits' defaults (at most 128, in a head of at most 65536 octets), then a
 * chunked body's trailer fields in the rest (at most HTTPASM_CLIENT_FIELDS less the head's, in
 * a section of at most 65536 octets). A response past either is refused:
 * -HTTPASM_ERROR_TOO_MANY_FIELDS or -HTTPASM_ERROR_HEAD_TOO_LARGE. */
#define HTTPASM_CLIENT_FIELDS 256

/* What httpasm_client_send reads (96 octets). Every pointer is valid until the next call on the
 * client (they point into its input buffer). */
typedef struct httpasm_client_response {
    httpasm_response_head head;     /* status, reason, fields, flags (HTTPASM_RESPONSE_HEAD_*) */
    const uint8_t *body;            /* the decoded body (chunked framing removed) */
    size_t body_length;
    const httpasm_field *trailers;  /* a chunked body's trailer fields (kept apart), or NULL */
    uint32_t trailer_count;
    uint32_t reserved;
} httpasm_client_response;

/* Connects to an IPv4 address (network byte order) and port; timeout_ms bounds the connect and
 * every later read and write (0: none). NULL with *error = -errno on failure (error may be NULL):
 * -ETIMEDOUT when timeout_ms passed first, -ECONNREFUSED, -ENOMEM, or the socket's own error. */
httpasm_client *httpasm_client_connect(uint32_t address, uint16_t port, uint32_t timeout_ms,
                                       int *error);

/* Sends a request (method, target, authority as Host, fields; flags HTTPASM_REQUEST_CLOSE or
 * _EXPECT_CONTINUE; the framing is the client's: Content-Length when there is a body or the
 * method defines one) and reads the final response whole: 1xx skipped, the body by its framing
 * (chunked decoded, trailers apart, or until the close). 0; -HTTPASM_ERROR_* for a request the
 * writer refuses (nothing sent) or an invalid response (connection closed; a trailer section's
 * rule too, and the limits of HTTPASM_CLIENT_FIELDS); -errno for I/O
 * (ETIMEDOUT, ECONNRESET, ENOMEM; connection closed); -ENOTCONN once the connection is closed,
 * which also follows a response that does not keep it, or a request that asked to close.
 * Unsolicited octets are never read as a response (RFC 9112 9.2): octets after a response
 * close the connection once it is returned; octets that came while idle fail the next send
 * with -EPROTO, and an idle connection the server closed with -ECONNRESET, before anything is
 * sent (so that request can safely be retried on a new connection). */
int httpasm_client_send(httpasm_client *client, const httpasm_request *request,
                        const uint8_t *body, size_t length, httpasm_client_response *response);

/* Closes the connection and frees the client. NULL does nothing. */
void httpasm_client_close(httpasm_client *client);

#ifdef __cplusplus
}
#endif

#endif /* HTTPASM_H */
