; =============================================================================
; httpasm_abi.inc - the C ABI's structures and constants, for NASM: the same layouts as
; src/HttpAsm/include/httpasm.h, offset for offset. A change here is a change there, and in the
; tests' copies (tests/HttpAsm.Tests/Native.cs), which check every size.
; =============================================================================
%ifndef HTTPASM_ABI_INC
%define HTTPASM_ABI_INC

%include "generated/field_ids.inc"

; -----------------------------------------------------------------------------
; httpasm_field: one field line (32 octets). name and value point into memory the caller owns
; (the received head, or a decoder's buffer); neither is NUL-terminated.
; -----------------------------------------------------------------------------
struc httpasm_field
    .name:          resq 1      ; const uint8_t *
    .value:         resq 1      ; const uint8_t *
    .name_length:   resd 1      ; uint32_t
    .value_length:  resd 1      ; uint32_t
    .id:            resw 1      ; uint16_t: HTTPASM_FIELD_*, 0 when not a known field
    .flags:         resw 1      ; uint16_t: HTTPASM_FIELD_FLAG_*
    .reserved:      resd 1
endstruc

HTTPASM_FIELD_FLAG_TRAILER      equ 0x0001  ; the field came in a trailer section
; HPACK (and QPACK): decoder out, the field came as a literal never indexed; encoder in, encode it
; so. A sensitive field (a credential) must keep this representation when it is forwarded
; (RFC 7541 6.2.3, 7.1.3), so it never reaches any compression context.
HTTPASM_FIELD_FLAG_NEVER_INDEXED equ 0x0002
; HPACK (and QPACK) encoder in: do not add the field to the dynamic table (a value unlikely to
; repeat, which would only push useful entries out).
HTTPASM_FIELD_FLAG_NO_INDEX     equ 0x0004

; -----------------------------------------------------------------------------
; httpasm_request: one request's head, as every HTTP version presents it (96 octets).
; -----------------------------------------------------------------------------
struc httpasm_request
    .method:            resq 1  ; const uint8_t *: the method token
    .target:            resq 1  ; const uint8_t *: the request-target (HTTP/1.1) or :path (HTTP/2)
    .authority:         resq 1  ; const uint8_t *: the authority, or NULL (see httpasm.h)
    .scheme:            resq 1  ; const uint8_t *: the scheme, or NULL
    .fields:            resq 1  ; httpasm_field *: the caller's array, filled from index 0
    .content_length:    resq 1  ; uint64_t: with HTTPASM_REQUEST_CONTENT_LENGTH
    .method_length:     resd 1
    .target_length:     resd 1
    .authority_length:  resd 1
    .scheme_length:     resd 1
    .field_count:       resd 1
    .flags:             resd 1  ; HTTPASM_REQUEST_*
    .head_length:       resd 1  ; HTTP/1.x: the head's octets, leading empty lines included
    .method_id:         resw 1  ; HTTPASM_METHOD_*, 0 for any other method
    .version:           resb 1  ; 10 = HTTP/1.0, 11 = HTTP/1.1, 20 = HTTP/2
    .target_form:       resb 1  ; HTTPASM_TARGET_*
    .error:             resw 1  ; HTTPASM_ERROR_* when parsing failed, else 0
    .reserved0:         resw 1
    .reserved1:         resd 1
    .reserved2:         resq 1
endstruc

; httpasm_request.flags
HTTPASM_REQUEST_KEEP_ALIVE      equ 0x0001  ; the connection persists after the response (RFC 9112 9.3)
HTTPASM_REQUEST_CONTENT_LENGTH  equ 0x0002  ; content_length holds the body's length
HTTPASM_REQUEST_CHUNKED         equ 0x0004  ; the body is chunked (RFC 9112 7.1)
HTTPASM_REQUEST_EXPECT_CONTINUE equ 0x0008  ; Expect: 100-continue (RFC 9110 10.1.1)
HTTPASM_REQUEST_HOST            equ 0x0010  ; a Host field was present
HTTPASM_REQUEST_TE_TRAILERS     equ 0x0020  ; TE lists "trailers": the client accepts trailer fields
HTTPASM_REQUEST_UPGRADE         equ 0x0040  ; an Upgrade field was present (HttpAsm does not switch)
HTTPASM_REQUEST_CLOSE           equ 0x0080  ; Connection: close was present

; httpasm_request.method_id: the methods of RFC 9110 section 9.3, and PATCH (RFC 5789)
HTTPASM_METHOD_GET              equ 1
HTTPASM_METHOD_HEAD             equ 2
HTTPASM_METHOD_POST             equ 3
HTTPASM_METHOD_PUT              equ 4
HTTPASM_METHOD_DELETE           equ 5
HTTPASM_METHOD_CONNECT          equ 6
HTTPASM_METHOD_OPTIONS          equ 7
HTTPASM_METHOD_TRACE            equ 8
HTTPASM_METHOD_PATCH            equ 9

; httpasm_request.target_form (RFC 9112 section 3.2)
HTTPASM_TARGET_ORIGIN           equ 1       ; "/path?query"
HTTPASM_TARGET_ABSOLUTE         equ 2       ; "http://host/path"
HTTPASM_TARGET_AUTHORITY        equ 3       ; "host:port", CONNECT only
HTTPASM_TARGET_ASTERISK         equ 4       ; "*", OPTIONS only

; httpasm_request.error: why a head was refused (the tests name each one)
HTTPASM_ERROR_BARE_LF               equ 1   ; a line ended in LF without CR
HTTPASM_ERROR_METHOD                equ 2   ; the method is not a token
HTTPASM_ERROR_REQUEST_LINE          equ 3   ; the request-line's elements are not separated by single SPs
HTTPASM_ERROR_TARGET                equ 4   ; the request-target holds an octet or escape a URI may not
HTTPASM_ERROR_TARGET_TOO_LONG       equ 5   ; longer than the limit: 414
HTTPASM_ERROR_TARGET_FORM           equ 6   ; the target's form does not suit the method
HTTPASM_ERROR_VERSION               equ 7   ; not HTTP-version's grammar
HTTPASM_ERROR_VERSION_UNSUPPORTED   equ 8   ; a major version other than 1: 505
HTTPASM_ERROR_OBS_FOLD              equ 9   ; a line starts with whitespace (obsolete line folding)
HTTPASM_ERROR_FIELD_NAME            equ 10  ; a field name is empty or not a token
HTTPASM_ERROR_WHITESPACE_BEFORE_COLON equ 11 ; whitespace between a field name and its colon
HTTPASM_ERROR_FIELD_VALUE           equ 12  ; a field value holds a control character
HTTPASM_ERROR_HEAD_TOO_LARGE        equ 13  ; the head exceeds the limit: 431
HTTPASM_ERROR_TOO_MANY_FIELDS       equ 14  ; more field lines than the fields array holds: 431
HTTPASM_ERROR_HOST_MISSING          equ 15  ; an HTTP/1.1 request without Host
HTTPASM_ERROR_HOST_DUPLICATE        equ 16  ; more than one Host line
HTTPASM_ERROR_HOST_INVALID          equ 17  ; Host is not uri-host [ ":" port ]
HTTPASM_ERROR_CONTENT_LENGTH        equ 18  ; Content-Length is not 1*DIGIT, or its values differ
HTTPASM_ERROR_TE_AND_CL             equ 19  ; both Transfer-Encoding and Content-Length
HTTPASM_ERROR_TE_HTTP10             equ 20  ; Transfer-Encoding in an HTTP/1.0 message
HTTPASM_ERROR_TE_NOT_CHUNKED        equ 21  ; chunked is missing or not the final coding
HTTPASM_ERROR_TE_UNKNOWN            equ 22  ; a transfer coding HttpAsm does not implement: 501
HTTPASM_ERROR_EXPECT                equ 23  ; an expectation other than 100-continue: 417
HTTPASM_ERROR_FRAMING_FIELD         equ 24  ; a writer was given a field it owns (Content-Length, ...)
HTTPASM_ERROR_STATUS                equ 25  ; a status code outside 100-599, or a malformed status-line
HTTPASM_ERROR_CHUNK                 equ 26  ; malformed chunked framing
HTTPASM_ERROR_AUTHORITY             equ 27  ; a writer was given an authority with octets a Host may not hold
; HPACK decoding errors (RFC 7541): each is a COMPRESSION_ERROR for the whole HTTP/2 connection,
; because the decoder's dynamic table can no longer be trusted to match the peer's encoder.
HTTPASM_ERROR_HPACK_INDEX           equ 28  ; index 0, or past the static and dynamic tables
HTTPASM_ERROR_HPACK_INTEGER         equ 29  ; an integer past 2^32-1, or with more than 5 continuation octets
HTTPASM_ERROR_HPACK_TRUNCATED       equ 30  ; the block ends inside a representation
HTTPASM_ERROR_HPACK_HUFFMAN         equ 31  ; EOS in a string, or padding longer than 7 bits or not all ones
HTTPASM_ERROR_HPACK_SIZE_UPDATE     equ 32  ; a table size update after a field, or above the limit
HTTPASM_ERROR_HPACK_LIMIT           equ 33  ; httpasm_hpack_init: a limit past HTTPASM_HPACK_MAX_LIMIT, or memory too small
; HTTP/2 malformed requests (RFC 9113 8.1.1): a stream error PROTOCOL_ERROR for that request only.
HTTPASM_ERROR_H2_PSEUDO             equ 34  ; a pseudo-field unknown, repeated, a response's, after a regular field, or in trailers
HTTPASM_ERROR_H2_MISSING            equ 35  ; :method, :scheme or :path (CONNECT: :authority) missing or empty
HTTPASM_ERROR_H2_CONNECTION_FIELD   equ 36  ; Connection, Keep-Alive, Proxy-Connection, Transfer-Encoding, Upgrade; TE other than "trailers"
HTTPASM_ERROR_H2_AUTHORITY          equ 37  ; :authority empty, not uri-host [ ":" port ], a CONNECT's without a port of 1-65535, or Host naming another authority

; -----------------------------------------------------------------------------
; httpasm_response: what a server answers (48 octets), for httpasm_h1_write_response. flags is
; in and out: the writer reports how the body must be framed.
; -----------------------------------------------------------------------------
struc httpasm_response
    .fields:            resq 1  ; const httpasm_field *: the handler's fields, framing excluded
    .date:              resq 1  ; const uint8_t *: a 29-octet IMF-fixdate, or NULL
    .content_length:    resq 1  ; with HTTPASM_RESPONSE_LENGTH
    .field_count:       resd 1
    .flags:             resd 1  ; HTTPASM_RESPONSE_*
    .status:            resw 1  ; 100-599
    .request_version:   resb 1  ; 10 or 11: the request's version decides chunked or close
    .request_method:    resb 1  ; HTTPASM_METHOD_*: HEAD and CONNECT change the framing
    .reserved:          resd 1
    .reserved2:         resq 1
endstruc

HTTPASM_RESPONSE_LENGTH         equ 0x0001  ; in: content_length is the body's length
HTTPASM_RESPONSE_CLOSE          equ 0x0002  ; in/out: the connection closes after this response
HTTPASM_RESPONSE_CHUNKED        equ 0x0004  ; out: send the body chunked
HTTPASM_RESPONSE_NO_BODY        equ 0x0008  ; out: this response has no body at all

; -----------------------------------------------------------------------------
; httpasm_response_head: a response's head as a client reads it (64 octets).
; -----------------------------------------------------------------------------
struc httpasm_response_head
    .reason:            resq 1  ; const uint8_t *
    .fields:            resq 1  ; httpasm_field *: the caller's array
    .content_length:    resq 1  ; with HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH
    .reason_length:     resd 1
    .field_count:       resd 1
    .flags:             resd 1  ; HTTPASM_RESPONSE_HEAD_*
    .head_length:       resd 1
    .status:            resw 1  ; 3DIGIT as received (RFC 9110 15: 100-599 are valid)
    .version:           resb 1  ; 10, 11
    .reserved0:         resb 1
    .error:             resw 1  ; HTTPASM_ERROR_* when parsing failed
    .reserved1:         resw 1
    .reserved2:         resq 1
    .reserved3:         resq 1
endstruc

HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH equ 0x0001 ; the body is content_length octets
HTTPASM_RESPONSE_HEAD_CHUNKED       equ 0x0002  ; the body is chunked
HTTPASM_RESPONSE_HEAD_UNTIL_CLOSE   equ 0x0004  ; the body runs until the server closes
HTTPASM_RESPONSE_HEAD_NO_BODY       equ 0x0008  ; no body (HEAD, 1xx, 204, 304)
HTTPASM_RESPONSE_HEAD_TUNNEL        equ 0x0010  ; a 2xx to CONNECT: the connection is a tunnel now
HTTPASM_RESPONSE_HEAD_KEEP_ALIVE    equ 0x0020  ; the connection may carry another request

; -----------------------------------------------------------------------------
; httpasm_h1_chunked: the chunked decoder's state between calls (32 octets). Zero it before a
; body; the decoder updates it.
; -----------------------------------------------------------------------------
struc httpasm_h1_chunked
    .remaining:         resq 1  ; data octets left in the current chunk
    .total:             resq 1  ; data octets decoded so far
    .state:             resd 1  ; HTTPASM_CHUNKED_*
    .extension_length:  resd 1  ; chunk-ext octets so far in this chunk-size line
    .size_digits:       resd 1  ; HEXDIGs read in this chunk-size
    .reserved:          resd 1
endstruc

HTTPASM_CHUNKED_SIZE            equ 0       ; reading a chunk-size (the initial state)
HTTPASM_CHUNKED_EXTENSION       equ 1       ; reading chunk-ext, up to the line's CR
HTTPASM_CHUNKED_SIZE_LF         equ 2       ; the chunk-size line's LF
HTTPASM_CHUNKED_DATA            equ 3       ; inside chunk-data
HTTPASM_CHUNKED_DATA_CR         equ 4       ; the CR after chunk-data
HTTPASM_CHUNKED_DATA_LF         equ 5       ; the LF after chunk-data
HTTPASM_CHUNKED_TRAILERS        equ 6       ; the last chunk was read: the trailer section follows
HTTPASM_CHUNKED_ERROR           equ 7       ; refused; the decoder will not continue
HTTPASM_CHUNKED_EXTENSION_BWS   equ 8       ; whitespace after chunk-size: only ";" may follow

HA_CHUNK_MAX_EXTENSION          equ 4096    ; chunk-ext octets per line before a 400 (RFC 9112 7.1.1)

; -----------------------------------------------------------------------------
; httpasm_h1_limits: what one head may take (16 octets). Zero fields take the defaults.
; -----------------------------------------------------------------------------
struc httpasm_h1_limits
    .max_head:      resd 1      ; octets of the whole head; default 65536 (431 beyond)
    .max_target:    resd 1      ; octets of the request-target; default 8192 (414 beyond)
    .max_fields:    resd 1      ; field lines; the fields array must hold this many; default 128
    .reserved:      resd 1
endstruc

HA_H1_DEFAULT_MAX_HEAD          equ 65536
HA_H1_DEFAULT_MAX_TARGET        equ 8192
HA_H1_DEFAULT_MAX_FIELDS        equ 128

; HTTPASM_CLIENT_FIELDS: the field records httpasm_client_send keeps for one response (see
; httpasm.h): the head's, under the default limits, then the trailer section's in the rest.
HTTPASM_CLIENT_FIELDS           equ 256

; -----------------------------------------------------------------------------
; httpasm_sha256_ctx: a running SHA-256 hash (FIPS 180-4), 112 octets. httpasm_sha256_init sets it,
; httpasm_sha256_update feeds it any number of octets at a time, httpasm_sha256_final writes the
; digest and wipes it. Its octets are the hash's whole state: copying it forks the hash (a TLS
; transcript hashed up to a message, then onwards).
; -----------------------------------------------------------------------------
struc httpasm_sha256_ctx
    .state:             resd 8      ; H0-H7 of FIPS 180-4 6.2, as native dwords
    .length:            resq 1      ; octets fed so far, the buffered ones included
    .buffer:            resb 64     ; the next block's first .buffered octets
    .buffered:          resd 1      ; 0-63
    .reserved:          resd 1
endstruc

HTTPASM_SHA256_DIGEST           equ 32      ; octets of a digest
HTTPASM_SHA256_BLOCK            equ 64      ; octets of a block (HMAC's key padding)

; -----------------------------------------------------------------------------
; httpasm_aes_key: an expanded AES-128 or AES-256 key (FIPS 197 5.2), 496 octets, both
; versions' schedules (crypto/aes.asm): any tier can use a key any tier made. No alignment is
; required: the code loads round keys with unaligned moves or copies them to its stack.
; -----------------------------------------------------------------------------
struc httpasm_aes_key
    .round_keys:        resb 240    ; w[0..4(Nr+1)) as FIPS 197 orders them, 16 octets a round
    .ct:                resb 240    ; v1's round keys, compressed: two qwords a round (ct64)
    .rounds:            resd 1      ; Nr: 10 (AES-128) or 14 (AES-256)
    .reserved:          resd 3
endstruc
HTTPASM_AES_BLOCK               equ 16      ; octets of an AES block

; -----------------------------------------------------------------------------
; httpasm_aes_gcm_key: an AES-GCM key (SP 800-38D), 1024 octets (crypto/gcm.asm): the AES key,
; H = E_K(0^128), and the powers H^16 .. H^1 as the carry-less versions keep them (reflected
; and twisted) with their Karatsuba halves. Every tier's init writes the same octets.
; -----------------------------------------------------------------------------
struc httpasm_aes_gcm_key
    .aes:               resb httpasm_aes_key_size
    .h:                 resb 16     ; H, as AES made it
    .htable:            resb 256    ; H^16 first, H^1 at 240
    .hkara:             resb 256    ; each power's two halves xored, in both qwords
endstruc
HTTPASM_AES_GCM_NONCE           equ 12
HTTPASM_AES_GCM_TAG             equ 16

; ChaCha20 and Poly1305 (RFC 8439; crypto/chacha20_poly1305.asm) take their keys as raw octets:
; ChaCha20 has no schedule to keep, and Poly1305's key is new for every message.
HTTPASM_CHACHA20_KEY            equ 32      ; octets of a ChaCha20 (and AEAD) key
HTTPASM_CHACHA20_NONCE          equ 12      ; octets of its nonce (RFC 8439's 96-bit form)
HTTPASM_POLY1305_KEY            equ 32      ; octets of a one-time Poly1305 key (r, then s)
HTTPASM_POLY1305_TAG            equ 16      ; octets of a Poly1305 tag (the AEAD's tag too)

; X25519 (RFC 7748; crypto/x25519.asm): scalars, u-coordinates and shared secrets are 32 octets.
HTTPASM_X25519_KEY              equ 32

; P-256 (SP 800-186; crypto/p256.asm): scalars (private keys, shared secrets, r, s) are 32
; big-endian octets, public keys SEC 1's uncompressed form (04 || x || y), signatures r || s.
HTTPASM_P256_SCALAR             equ 32      ; octets of a private key, a shared secret, r or s
HTTPASM_P256_POINT              equ 65      ; octets of a public key: 04, x, y
HTTPASM_P256_SIGNATURE          equ 64      ; octets of a signature: r, s (IEEE P1363's form)
HTTPASM_P256_ENTROPY            equ 32      ; octets of a signature's optional entropy

; P-384 (SP 800-186; crypto/p384.asm): P-256's forms at 48-octet scalars and coordinates.
HTTPASM_P384_SCALAR             equ 48      ; octets of a private key, a shared secret, r or s
HTTPASM_P384_POINT              equ 97      ; octets of a public key: 04, x, y
HTTPASM_P384_SIGNATURE          equ 96      ; octets of a signature: r, s (IEEE P1363's form)
HTTPASM_P384_ENTROPY            equ 48      ; octets of a signature's optional entropy

; Ed25519 (RFC 8032 5.1; crypto/ed25519.asm): private keys (the 32-octet seed) and public keys
; are 32 octets, signatures R || S 64.
HTTPASM_ED25519_KEY             equ 32      ; octets of a private key (seed) or a public key
HTTPASM_ED25519_SIGNATURE       equ 64      ; octets of a signature: R, then S (little-endian)

; -----------------------------------------------------------------------------
; httpasm_ed25519_private_key: a private key ready to sign (crypto/ed25519.asm), 96 octets;
; opaque in httpasm.h (struct size id 19). httpasm_ed25519_private_key_init derives all three
; parts from the seed: the public key is the library's own, never the caller's (signing a
; message under two public keys with one seed would give the private scalar away: r does not
; depend on A). Its octets are secrets: the caller zeroes them when done.
; -----------------------------------------------------------------------------
struc httpasm_ed25519_private_key
    .scalar:            resq 4      ; a mod L (a = the clamped first half of SHA-512(seed))
    .prefix:            resb 32     ; the second half of SHA-512(seed): r's secret input
    .public:            resb 32     ; A = a B, encoded (RFC 8032 5.1.2)
endstruc

; Hash identifiers (the RSA signatures name their hash with these; SHA-1 and SHA-224 only where
; the caller brings the digest: PKCS#1 v1.5 verification of legacy certificates).
HTTPASM_HASH_SHA1               equ 1
HTTPASM_HASH_SHA224             equ 2
HTTPASM_HASH_SHA256             equ 3
HTTPASM_HASH_SHA384             equ 4
HTTPASM_HASH_SHA512             equ 5

; RSA (RFC 8017; crypto/rsa.asm): moduli of 1024 to 8192 bits.
HTTPASM_RSA_MIN_BITS            equ 1024
HTTPASM_RSA_MAX_BITS            equ 8192
HTTPASM_RSA_LIMBS               equ 128     ; 64-bit limbs of the largest modulus

; -----------------------------------------------------------------------------
; httpasm_rsa_public_key: a public key ready for verification (crypto/rsa.asm), 2080 octets;
; httpasm.h declares it opaque (a C caller only passes it), the struct size id 16 checks the
; bindings' copies. Numbers are little-endian 64-bit limbs, zero above their own. A refused key
; is all zeros (bits 0: every verification under it fails).
; -----------------------------------------------------------------------------
struc httpasm_rsa_public_key
    .n:                 resq HTTPASM_RSA_LIMBS  ; the modulus
    .rr:                resq HTTPASM_RSA_LIMBS  ; R^2 mod n, R = 2^(64 limbs)
    .n0:                resq 1      ; -n^-1 mod 2^64 (Montgomery's constant)
    .e:                 resq 1      ; the public exponent (odd, 3 or more)
    .limbs:             resd 1      ; the limbs the operations run on: n's, rounded up to 8
    .bits:              resd 1      ; n's bit length, 1024..8192
    .reserved:          resq 1
endstruc

HTTPASM_RSA_PRIME_LIMBS         equ 64      ; 64-bit limbs of the largest prime (4096 bits)

; -----------------------------------------------------------------------------
; httpasm_rsa_private_numbers: an RSAPrivateKey's numbers (RFC 8017 A.1.2) for
; httpasm_rsa_private_key_init, each a big-endian octet string (leading zero octets allowed, as
; DER's INTEGERs carry them) and its length; 112 octets. d itself is not needed: the CRT
; exponents and the coefficient are.
; -----------------------------------------------------------------------------
struc httpasm_rsa_private_numbers
    .n:                 resq 1
    .n_length:          resq 1
    .e:                 resq 1
    .e_length:          resq 1
    .p:                 resq 1
    .p_length:          resq 1
    .q:                 resq 1
    .q_length:          resq 1
    .dp:                resq 1      ; d mod (p - 1)
    .dp_length:         resq 1
    .dq:                resq 1      ; d mod (q - 1)
    .dq_length:         resq 1
    .qinv:              resq 1      ; q^-1 mod p
    .qinv_length:       resq 1
endstruc

; -----------------------------------------------------------------------------
; httpasm_rsa_private_key: a private key ready to sign (crypto/rsa.asm), 6720 octets; opaque in
; httpasm.h (struct size id 17). It begins with its public key (a caller may verify under
; (const httpasm_rsa_public_key *)&key). Both primes run on the same limbs (the larger's, rounded
; up to 8), R = 2^(64 limbs) for both. Its octets are secrets: the caller zeroes them when done.
; A refused key is all zeros and every signature under it fails.
; -----------------------------------------------------------------------------
struc httpasm_rsa_private_key
    .public:            resb httpasm_rsa_public_key_size
    .p:                 resq HTTPASM_RSA_PRIME_LIMBS
    .q:                 resq HTTPASM_RSA_PRIME_LIMBS
    .dp:                resq HTTPASM_RSA_PRIME_LIMBS
    .dq:                resq HTTPASM_RSA_PRIME_LIMBS
    .rr_p:              resq HTTPASM_RSA_PRIME_LIMBS    ; R^2 mod p
    .rr_q:              resq HTTPASM_RSA_PRIME_LIMBS    ; R^2 mod q
    .rrr_p:             resq HTTPASM_RSA_PRIME_LIMBS    ; R^3 mod p
    .rrr_q:             resq HTTPASM_RSA_PRIME_LIMBS    ; R^3 mod q
    .qinv_r:            resq HTTPASM_RSA_PRIME_LIMBS    ; q^-1 R mod p (Montgomery form)
    .p0:                resq 1      ; -p^-1 mod 2^64
    .q0:                resq 1      ; -q^-1 mod 2^64
    .limbs:             resd 1      ; the primes' limbs: a multiple of 8, 8..64
    .reserved:          resd 3
endstruc

; -----------------------------------------------------------------------------
; httpasm_sha512_ctx: a running SHA-512 or SHA-384 hash (FIPS 180-4; one layout for both, as
; SHA-384 is SHA-512 with another H(0), cut to 48 octets), 208 octets. Its octets are the hash's
; whole state, like httpasm_sha256_ctx's.
; -----------------------------------------------------------------------------
struc httpasm_sha512_ctx
    .state:             resq 8      ; H0-H7 of FIPS 180-4 6.4, as native qwords
    .length:            resq 1      ; octets fed so far, the buffered ones included
    .buffer:            resb 128    ; the next block's first .buffered octets
    .buffered:          resd 1      ; 0-127
    .reserved:          resd 1
endstruc

HTTPASM_SHA512_DIGEST           equ 64      ; octets of a SHA-512 digest
HTTPASM_SHA384_DIGEST           equ 48      ; octets of a SHA-384 digest
HTTPASM_SHA512_BLOCK            equ 128     ; octets of a block (both; HMAC's key padding)

; -----------------------------------------------------------------------------
; httpasm_hmac_sha256_ctx: a running HMAC-SHA256 (FIPS 198-1), 224 octets: the inner hash,
; already past the key's ipad block, then the outer one, past its opad block. The key itself is
; not kept. Copying it after httpasm_hmac_sha256_init reuses the key without its two
; compressions (HKDF-Expand does, once per output block).
; -----------------------------------------------------------------------------
struc httpasm_hmac_sha256_ctx
    .inner:             resb httpasm_sha256_ctx_size    ; fed the message (update)
    .outer:             resb httpasm_sha256_ctx_size    ; fed the inner digest (final)
endstruc

; -----------------------------------------------------------------------------
; httpasm_hmac_sha384_ctx: a running HMAC-SHA384, 416 octets: the same two hashes as
; httpasm_hmac_sha256_ctx's, SHA-384's (each a httpasm_sha512_ctx started by httpasm_sha384_init),
; with the same reuse by copy.
; -----------------------------------------------------------------------------
struc httpasm_hmac_sha384_ctx
    .inner:             resb httpasm_sha512_ctx_size    ; fed the message (update)
    .outer:             resb httpasm_sha512_ctx_size    ; fed the inner digest (final)
endstruc

; -----------------------------------------------------------------------------
; httpasm_hpack_output: where httpasm_hpack_decode puts one header block's fields (48 octets).
; Strings from the static table point at the library's constant text; every other name and
; value is copied into space, so the fields stay valid however the dynamic table changes
; afterwards (a later field of the same block may evict the entry an earlier one came from).
; -----------------------------------------------------------------------------
struc httpasm_hpack_output
    .fields:        resq 1      ; httpasm_field *: the caller's array
    .space:         resq 1      ; uint8_t *: the decoded names and values go here
    .space_size:    resq 1      ; its octets
    .space_used:    resq 1      ; out: octets of space written
    .list_size:     resq 1      ; out: the header list's size, RFC 9113 6.5.2 (sum of name +
                                ; value + 32 over every field, those that did not fit included)
    .max_fields:    resd 1      ; the fields array's records
    .count:         resd 1      ; out: records written
endstruc

; httpasm_hpack_init's flags
HTTPASM_HPACK_HUFFMAN           equ 0x0001  ; encoder: Huffman-code a string unless that is longer
; encoder: index every literal that fits 3/4 of the table, the fields that rarely repeat too
; (:path, content-length, location, set-cookie, ...): for traffic whose values do repeat, such
; as RPC calls to the same few paths. Credentials and NO_INDEX fields stay out regardless.
HTTPASM_HPACK_INDEX_ALL         equ 0x0002

HTTPASM_HPACK_MAX_LIMIT         equ 0x1000000   ; the largest table limit (16 MiB) httpasm_hpack_init takes
HA_HPACK_INITIAL_SIZE           equ 4096        ; SETTINGS_HEADER_TABLE_SIZE's initial value (RFC 9113 6.5.2)

; -----------------------------------------------------------------------------
; CPU features: the bits of httpasm_cpu_found, httpasm_cpu_features and httpasm_cpu_limit, and
; of the core's ha_cpu. Levels are the x86-64 psABI's; groups are instructions that CPUs of one
; level may or may not have. cpu.inc has the rules (what each level adds, which group needs
; which level, how a routine picks its version).
; -----------------------------------------------------------------------------
HTTPASM_CPU_V2          equ 1 << 0      ; x86-64-v2: SSE3, SSSE3, SSE4.1/4.2, POPCNT, CX16, LAHF
HTTPASM_CPU_V3          equ 1 << 1      ; x86-64-v3: AVX, AVX2, BMI1/2, F16C, FMA, LZCNT, MOVBE
HTTPASM_CPU_V4          equ 1 << 2      ; x86-64-v4: AVX-512 F, BW, CD, DQ, VL
HTTPASM_CPU_AESNI       equ 1 << 8      ; AES-NI
HTTPASM_CPU_CLMUL       equ 1 << 9      ; PCLMULQDQ: carry-less multiplication
HTTPASM_CPU_SHA         equ 1 << 10     ; SHA extensions: SHA-1 and SHA-256 rounds
HTTPASM_CPU_GFNI        equ 1 << 11     ; Galois-field instructions
HTTPASM_CPU_BMI2        equ 1 << 12     ; MULX, SHRX, PDEP, ... (counted with v3)
HTTPASM_CPU_ADX         equ 1 << 13     ; ADCX/ADOX (counted with v3)
HTTPASM_CPU_VAES        equ 1 << 14     ; VAES: AES on YMM (v3) and ZMM (v4)
HTTPASM_CPU_VCLMUL      equ 1 << 15     ; VPCLMULQDQ: carry-less multiplication on YMM and ZMM
HTTPASM_CPU_SHA512      equ 1 << 16     ; SHA512 extensions (VEX encoded: needs v3)
HTTPASM_CPU_IFMA        equ 1 << 17     ; AVX512-IFMA (needs v4)
HTTPASM_CPU_VBMI        equ 1 << 18     ; AVX512-VBMI (needs v4)
HTTPASM_CPU_VBMI2       equ 1 << 19     ; AVX512-VBMI2 (needs v4)

HTTPASM_CPU_ALL         equ HTTPASM_CPU_V2 | HTTPASM_CPU_V3 | HTTPASM_CPU_V4 | HTTPASM_CPU_AESNI | HTTPASM_CPU_CLMUL | HTTPASM_CPU_SHA | HTTPASM_CPU_GFNI | HTTPASM_CPU_BMI2 | HTTPASM_CPU_ADX | HTTPASM_CPU_VAES | HTTPASM_CPU_VCLMUL | HTTPASM_CPU_SHA512 | HTTPASM_CPU_IFMA | HTTPASM_CPU_VBMI | HTTPASM_CPU_VBMI2
; The caps of the levels, as HTTPASM_CPU=v1..v4 sets them: each keeps the groups its level's
; encodings allow (v1: none at all, the pure baseline; v2: the legacy-SSE groups).
HTTPASM_CPU_CAP_V1      equ 0
HTTPASM_CPU_CAP_V2      equ HTTPASM_CPU_V2 | HTTPASM_CPU_AESNI | HTTPASM_CPU_CLMUL | HTTPASM_CPU_SHA | HTTPASM_CPU_GFNI
HTTPASM_CPU_CAP_V3      equ HTTPASM_CPU_CAP_V2 | HTTPASM_CPU_V3 | HTTPASM_CPU_BMI2 | HTTPASM_CPU_ADX | HTTPASM_CPU_VAES | HTTPASM_CPU_VCLMUL | HTTPASM_CPU_SHA512
HTTPASM_CPU_CAP_V4      equ HTTPASM_CPU_CAP_V3 | HTTPASM_CPU_V4 | HTTPASM_CPU_IFMA | HTTPASM_CPU_VBMI | HTTPASM_CPU_VBMI2

%endif
