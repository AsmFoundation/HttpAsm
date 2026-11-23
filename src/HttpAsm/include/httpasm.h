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
#define HTTPASM_ERROR_HOST_INVALID          17
#define HTTPASM_ERROR_CONTENT_LENGTH        18  /* not 1*DIGIT, or values that differ */
#define HTTPASM_ERROR_TE_AND_CL             19  /* both Transfer-Encoding and Content-Length */
#define HTTPASM_ERROR_TE_HTTP10             20  /* Transfer-Encoding in an HTTP/1.0 message */
#define HTTPASM_ERROR_TE_NOT_CHUNKED        21  /* chunked missing, repeated, or not final */
#define HTTPASM_ERROR_TE_UNKNOWN            22  /* a coding not implemented yet: 501 */
#define HTTPASM_ERROR_EXPECT                23  /* an expectation other than 100-continue: 417 */

/* What one HTTP/1.1 head may take (16 octets). A zero field takes its default. */
typedef struct httpasm_h1_limits {
    uint32_t max_head;          /* the head's octets; default 65536 (431 beyond) */
    uint32_t max_target;        /* the request-target's octets; default 8192 (414 beyond) */
    uint32_t max_fields;        /* field lines; the fields array holds this many; default 128 */
    uint32_t reserved;
} httpasm_h1_limits;

/* ------------------------------------------------------------------------------------------
 * The library
 * ------------------------------------------------------------------------------------------ */

/* The ABI version of the loaded library. A program compiled against this header should refuse a
 * library whose version differs from HTTPASM_ABI_VERSION: before the first release, any change
 * may break the ABI. */
uint32_t httpasm_abi_version(void);

/* The size of one of the ABI's structures, for bindings to check their copies: 1 httpasm_field,
 * 2 httpasm_request, 3 httpasm_h1_limits; 0 for any other value. */
uint32_t httpasm_struct_size(uint32_t which);

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
 *        set it to 0 before each new message.
 *   < 0  -status (400, 414, 417, 431, 501 or 505): answer with that status and close the
 *        connection. request->error names the rule. *scan_from is reset to 0.
 * limits may be NULL (every default); fields must hold limits->max_fields records (default 128).
 * Lines must end in CRLF (a bare LF is refused). A Transfer-Encoding with Content-Length, in an
 * HTTP/1.0 message, or whose final coding is not chunked is refused. Codings other than chunked
 * answer 501 for now. */
int64_t httpasm_h1_parse_request(const uint8_t *buf, size_t len, size_t *scan_from,
                                 const httpasm_h1_limits *limits, httpasm_request *request,
                                 httpasm_field *fields);

#ifdef __cplusplus
}
#endif

#endif /* HTTPASM_H */
