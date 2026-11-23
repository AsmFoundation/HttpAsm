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

extern httpasm_abi_version          ; uint32_t (void)
extern httpasm_struct_size          ; uint32_t (uint32_t which)
extern httpasm_token_length         ; size_t (const uint8_t *p, size_t n)
extern httpasm_field_value_scan     ; size_t (const uint8_t *p, size_t n)
extern httpasm_field_id             ; uint32_t (const uint8_t *name, size_t n)
extern httpasm_field_name           ; const uint8_t * (uint32_t id, size_t *length)
extern httpasm_h1_parse_request     ; int64_t (buf, len, scan_from, limits, request, fields)

%endif
