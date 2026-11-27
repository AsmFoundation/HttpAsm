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
extern httpasm_hmac_sha256_init     ; void (httpasm_hmac_sha256_ctx *h, const uint8_t *key, size_t n)
extern httpasm_hmac_sha256_update   ; void (httpasm_hmac_sha256_ctx *h, const uint8_t *data, size_t n)
extern httpasm_hmac_sha256_final    ; void (httpasm_hmac_sha256_ctx *h, uint8_t mac[32]): wipes h
extern httpasm_hmac_sha256          ; void (key, key_length, data, n, mac[32])
extern httpasm_hkdf_sha256_extract  ; void (salt, salt_length, ikm, ikm_length, prk[32])
extern httpasm_hkdf_sha256_expand   ; int (prk, prk_length, info, info_length, okm, length): 0, -1 past 8160
extern httpasm_aes_init             ; int (httpasm_aes_key *k, const uint8_t *key, size_t length): 0, -1 (not 16 or 32)
extern httpasm_aes_encrypt_block    ; void (const httpasm_aes_key *k, const uint8_t in[16], uint8_t out[16])
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
