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
 * 6 httpasm_h1_chunked, 7 httpasm_server_options, 8 httpasm_hpack_output, 9 httpasm_client_response;
 * 0 for any other value. */
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
 * writer refuses (nothing sent) or an invalid response (connection closed); -errno for I/O
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
