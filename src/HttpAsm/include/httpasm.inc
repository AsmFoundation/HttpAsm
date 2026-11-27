; =============================================================================
; httpasm.inc - libhttpasm.so's C ABI for NASM programs: the same functions as httpasm.h, with
; the same System V calling convention. The structures, flags and ids are in httpasm_abi.inc,
; which this file includes (it comes from HttpAsm.Core's include folder).
; =============================================================================
%ifndef HTTPASM_INC
%define HTTPASM_INC

%include "httpasm_abi.inc"

; The ABI version httpasm_abi_version() returns. 0 until the first release: no compatibility is
; promised before it.
HTTPASM_ABI_VERSION equ 0

; -----------------------------------------------------------------------------
; httpasm_server_options (httpasm.h): 64 octets. Zero fields take their defaults.
; -----------------------------------------------------------------------------
struc httpasm_server_options
    .handler:           resq 1  ; void (*)(void *context, httpasm_exchange *exchange)
    .context:           resq 1
    .max_body:          resq 1  ; request bodies past this get 413; default 1 MiB
    .workers:           resd 1  ; worker threads; default: the CPUs this process may run on
    .idle_timeout_ms:   resd 1  ; idle and request-head timeout; default 60000
    .bind_address:      resd 1  ; IPv4 in network order; 0 = 0.0.0.0
    .port:              resw 1  ; 0: any free port (httpasm_server_port tells which)
    .flags:             resw 1  ; HTTPASM_SERVER_*
    .limits:            resb httpasm_h1_limits_size
    .min_data_rate:     resd 1  ; octets a second a transfer keeps to outlive idle_timeout_ms; default 240
    .reserved:          resd 1
endstruc

; httpasm_server_options.flags
HTTPASM_SERVER_URING        equ 0x0001  ; io_uring per worker, epoll where refused (default: epoll, measured; httpasm.h)
; httpasm_server_io's answers: what the server's workers wait and do their I/O with (MIXED:
; the kernel refused some workers' rings, e.g. past RLIMIT_MEMLOCK on a kernel that charges
; rings to it; httpasm.h)
HTTPASM_SERVER_IO_NONE      equ 0       ; not running
HTTPASM_SERVER_IO_EPOLL     equ 1       ; every worker
HTTPASM_SERVER_IO_URING     equ 2       ; every worker
HTTPASM_SERVER_IO_MIXED     equ 3       ; some workers on io_uring, the others on epoll

; -----------------------------------------------------------------------------
; httpasm_client_response (httpasm.h): what httpasm_client_send reads (96 octets). Every
; pointer is valid until the next call on the client.
; -----------------------------------------------------------------------------
struc httpasm_client_response
    .head:              resb httpasm_response_head_size ; status, reason, fields, flags
    .body:              resq 1  ; the decoded body
    .body_length:       resq 1
    .trailers:          resq 1  ; a chunked body's trailer fields, or NULL
    .trailer_count:     resd 1
    .reserved:          resd 1
endstruc

extern httpasm_abi_version          ; uint32_t (void)
extern httpasm_struct_size          ; uint32_t (uint32_t which)
extern httpasm_cpu_found            ; uint64_t (void): HTTPASM_CPU_* bits the CPU and OS offer
extern httpasm_cpu_features         ; uint64_t (void): the bits the library uses
extern httpasm_cpu_limit            ; uint64_t (uint64_t cap): replaces the cap, returns the bits used
extern httpasm_sha256_init          ; void (httpasm_sha256_ctx *h)
extern httpasm_sha256_update        ; void (httpasm_sha256_ctx *h, const uint8_t *data, size_t n)
extern httpasm_sha256_final         ; void (httpasm_sha256_ctx *h, uint8_t digest[32]): wipes h
extern httpasm_sha256               ; void (const uint8_t *data, size_t n, uint8_t digest[32])
extern httpasm_sha512_init          ; void (httpasm_sha512_ctx *h)
extern httpasm_sha384_init          ; void (httpasm_sha512_ctx *h): the same context, SHA-384's H(0)
extern httpasm_sha512_update        ; void (httpasm_sha512_ctx *h, const uint8_t *data, size_t n): both
extern httpasm_sha512_final         ; void (httpasm_sha512_ctx *h, uint8_t digest[64]): wipes h
extern httpasm_sha384_final         ; void (httpasm_sha512_ctx *h, uint8_t digest[48]): wipes h
extern httpasm_sha512               ; void (const uint8_t *data, size_t n, uint8_t digest[64])
extern httpasm_sha384               ; void (const uint8_t *data, size_t n, uint8_t digest[48])
extern httpasm_sha3_224_init        ; void (httpasm_sha3_ctx *h): rate 144
extern httpasm_sha3_256_init        ; void (httpasm_sha3_ctx *h): rate 136
extern httpasm_sha3_384_init        ; void (httpasm_sha3_ctx *h): rate 104
extern httpasm_sha3_512_init        ; void (httpasm_sha3_ctx *h): rate 72
extern httpasm_shake128_init        ; void (httpasm_sha3_ctx *h): rate 168
extern httpasm_shake256_init        ; void (httpasm_sha3_ctx *h): rate 136
extern httpasm_sha3_update          ; void (httpasm_sha3_ctx *h, const uint8_t *data, size_t n)
extern httpasm_sha3_final           ; void (httpasm_sha3_ctx *h, uint8_t *digest): (200 - rate) / 2 octets; wipes h
extern httpasm_shake_squeeze        ; void (httpasm_sha3_ctx *h, uint8_t *out, size_t n): the stream goes on
extern httpasm_sha3_224             ; void (data, n, digest[28])
extern httpasm_sha3_256             ; void (data, n, digest[32])
extern httpasm_sha3_384             ; void (data, n, digest[48])
extern httpasm_sha3_512             ; void (data, n, digest[64])
extern httpasm_shake128             ; void (data, n, out, out_n)
extern httpasm_shake256             ; void (data, n, out, out_n)
extern httpasm_hmac_sha256_init     ; void (httpasm_hmac_sha256_ctx *h, const uint8_t *key, size_t n)
extern httpasm_hmac_sha256_update   ; void (httpasm_hmac_sha256_ctx *h, const uint8_t *data, size_t n)
extern httpasm_hmac_sha256_final    ; void (httpasm_hmac_sha256_ctx *h, uint8_t mac[32]): wipes h
extern httpasm_hmac_sha256          ; void (key, key_length, data, n, mac[32])
extern httpasm_hkdf_sha256_extract  ; void (salt, salt_length, ikm, ikm_length, prk[32])
extern httpasm_hkdf_sha256_expand   ; int (prk, prk_length, info, info_length, okm, length): 0, -1 past 8160
extern httpasm_aes_init             ; int (httpasm_aes_key *k, const uint8_t *key, size_t length): 0, -1 (not 16 or 32)
extern httpasm_aes_gcm_init         ; int (httpasm_aes_gcm_key *k, const uint8_t *key, size_t length): 0, -1
extern httpasm_aes_gcm_seal         ; int (k, nonce[12], aad, aad_length, in, length, out, tag[16]): 0, -1 past the limits
extern httpasm_aes_gcm_open         ; int (k, nonce[12], aad, aad_length, in, length, tag[16], out): 0, -1 (out zeroed)
extern httpasm_aes_encrypt_block    ; void (const httpasm_aes_key *k, const uint8_t in[16], uint8_t out[16])
extern httpasm_chacha20             ; void (key[32], uint32_t counter, nonce[12], in, length, out): counter wraps at 2^32
extern httpasm_poly1305             ; void (key[32], message, length, tag[16]): a one-time key per message
extern httpasm_chacha20_poly1305_seal ; int (key[32], nonce[12], aad, aad_length, in, length, out, tag[16]): 0, -1 past 2^38 - 64
extern httpasm_chacha20_poly1305_open ; int (key[32], nonce[12], aad, aad_length, in, length, tag[16], out): 0, -1 (out zeroed)
extern httpasm_x25519               ; int (out[32], scalar[32], point[32]): 0, -1 when out is all zeros (small-order point)
extern httpasm_x25519_public_key    ; void (out[32], scalar[32]): X25519(scalar, 9)
extern httpasm_p256_public_key      ; int (public_key[65], private_key[32]): 0, -1 when the key is not in [1, n)
extern httpasm_p256_ecdh            ; int (shared[32], private_key[32], peer_key[65]): 0, -1 (key or point refused; zeros)
extern httpasm_p256_sign            ; int (signature[64], private_key[32], digest, length, entropy[32] or NULL): 0, -1
extern httpasm_p256_verify          ; int (public_key[65], digest, length, signature[64]): 0 valid, -1 not
extern httpasm_p384_public_key      ; int (public_key[97], private_key[48]): 0, -1 when the key is not in [1, n)
extern httpasm_p384_ecdh            ; int (shared[48], private_key[48], peer_key[97]): 0, -1 (key or point refused; zeros)
extern httpasm_p384_sign            ; int (signature[96], private_key[48], digest, length, entropy[48] or NULL): 0, -1
extern httpasm_p384_verify          ; int (public_key[97], digest, length, signature[96]): 0 valid, -1 not
extern httpasm_ed25519_public_key   ; void (public_key[32], private_key[32]): A of the seed
extern httpasm_ed25519_private_key_init ; void (httpasm_ed25519_private_key *key, private_key[32]): a mod L, prefix, A
extern httpasm_ed25519_sign         ; void (signature[64], const httpasm_ed25519_private_key *key, message, length)
extern httpasm_ed25519_verify       ; int (public_key[32], message, length, signature[64]): 0 valid, -1 not
extern httpasm_mlkem512_keypair     ; void (ek[800], dk[1632], seed[64])
extern httpasm_mlkem512_encaps      ; int (c[768], shared[32], ek[800], m[32]): 0, -1 (ek's modulus check; zeros)
extern httpasm_mlkem512_decaps      ; int (shared[32], dk[1632], c[768]): 0, -1 (dk's hash check; zeros)
extern httpasm_mlkem768_keypair     ; void (ek[1184], dk[2400], seed[64])
extern httpasm_mlkem768_encaps      ; int (c[1088], shared[32], ek[1184], m[32])
extern httpasm_mlkem768_decaps      ; int (shared[32], dk[2400], c[1088])
extern httpasm_mlkem1024_keypair    ; void (ek[1568], dk[3168], seed[64])
extern httpasm_mlkem1024_encaps     ; int (c[1568], shared[32], ek[1568], m[32])
extern httpasm_mlkem1024_decaps     ; int (shared[32], dk[3168], c[1568])
extern httpasm_ffdhe_size           ; size_t (group): p's octets (256 .. 1024), 0 for another code
extern httpasm_ffdhe_public_key     ; int (group, public_key[size], x, x_length): 0, -1 (group, length)
extern httpasm_ffdhe_shared         ; int (group, shared[size], x, x_length, peer[size]): 0, -1 (and 1 < Y < p - 1)
extern httpasm_rsa_public_key_init  ; int (httpasm_rsa_public_key *key, n, n_length, e, e_length): 0, -1 refused
extern httpasm_rsa_verify_pkcs1     ; int (key, hash, digest, signature, signature_length): 0 valid, -1 not
extern httpasm_rsa_verify_pss       ; int (key, hash, digest, salt_length, signature, signature_length): 0 valid, -1 not
extern httpasm_rsa_private_key_init ; int (httpasm_rsa_private_key *key, const httpasm_rsa_private_numbers *numbers): 0, -1 refused
extern httpasm_rsa_sign_pkcs1       ; int (key, hash, digest, signature, signature_length): 0, -1 (signature zeroed)
extern httpasm_rsa_sign_pss         ; int (key, hash, digest, salt, salt_length, signature, signature_length): 0, -1
extern httpasm_random               ; int (void *buffer, size_t length): 0, or -errno (getrandom refused)
extern httpasm_hmac_sha384_init     ; void (httpasm_hmac_sha384_ctx *h, const uint8_t *key, size_t n)
extern httpasm_hmac_sha384_update   ; void (httpasm_hmac_sha384_ctx *h, const uint8_t *data, size_t n)
extern httpasm_hmac_sha384_final    ; void (httpasm_hmac_sha384_ctx *h, uint8_t mac[48]): wipes h
extern httpasm_hmac_sha384          ; void (key, key_length, data, n, mac[48])
extern httpasm_hkdf_sha384_extract  ; void (salt, salt_length, ikm, ikm_length, prk[48])
extern httpasm_hkdf_sha384_expand   ; int (prk, prk_length, info, info_length, okm, length): 0, -1 past 12240
extern httpasm_token_length         ; size_t (const uint8_t *p, size_t n)
extern httpasm_field_value_scan     ; size_t (const uint8_t *p, size_t n)
extern httpasm_field_id             ; uint32_t (const uint8_t *name, size_t n)
extern httpasm_field_name           ; const uint8_t * (uint32_t id, size_t *length)
extern httpasm_h1_parse_request     ; int64_t (buf, len, scan_from, limits, request, fields)
extern httpasm_h1_parse_response    ; int64_t (buf, len, scan_from, limits, request_method, head, fields)
extern httpasm_h1_chunked_decode    ; int64_t (state, in, len, produced)
extern httpasm_h1_parse_trailers    ; int64_t (buf, len, scan_from, limits, fields, count)
extern httpasm_h1_write_response    ; int64_t (out, cap, response)
extern httpasm_h1_write_request     ; int64_t (out, cap, request)
extern httpasm_h1_write_chunk       ; int64_t (out, cap, data, len)
extern httpasm_h1_write_last_chunk  ; int64_t (out, cap, trailers, count)
extern httpasm_hpack_size           ; size_t (uint32_t limit)
extern httpasm_hpack_init           ; int (memory, size, limit, flags)
extern httpasm_hpack_decode         ; int64_t (table, block, length, output)
extern httpasm_hpack_encode_bound   ; size_t (fields, count)
extern httpasm_hpack_encode         ; int64_t (table, fields, count, out, cap)
extern httpasm_hpack_encoder_limit  ; void (table, limit)
extern httpasm_hpack_table_size     ; uint32_t (table, uint32_t *max_size)
extern httpasm_hpack_entry          ; int (table, index, field)
extern httpasm_h2_request           ; int (fields, count, request)
extern httpasm_h2_trailers          ; int (fields, count)
extern httpasm_server_create        ; httpasm_server * (options, int *error)
extern httpasm_server_start         ; int (server)
extern httpasm_server_port          ; uint16_t (server)
extern httpasm_server_io            ; uint32_t (server): HTTPASM_SERVER_IO_*
extern httpasm_server_stop          ; void (server)
extern httpasm_server_destroy       ; void (server)
extern httpasm_exchange_request     ; const httpasm_request * (exchange)
extern httpasm_exchange_body        ; const uint8_t * (exchange, size_t *length)
extern httpasm_exchange_trailers    ; const httpasm_field * (exchange, uint32_t *count)
extern httpasm_exchange_defer       ; int (exchange)
extern httpasm_exchange_respond     ; int (exchange, status, fields, count, body, length)
extern httpasm_client_connect       ; httpasm_client * (address, port, timeout_ms, int *error)
extern httpasm_client_send          ; int (client, request, body, length, response)
extern httpasm_client_close         ; void (client)

%endif
