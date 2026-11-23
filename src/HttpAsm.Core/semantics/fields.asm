; =============================================================================
; semantics/fields.asm - the field rules (semantics/fields.inc) as functions of the C ABI.
;
; The parsers assemble the same macros inline. These standalone copies serve the C ABI's
; callers (include/httpasm.h): a .NET adapter can check a header value set by user code
; before sending it, as Kestrel does. The tests also use them to prove the rules octet by
; octet.
; =============================================================================
default rel
%include "httpasm_core.inc"

section .text

; -----------------------------------------------------------------------------
; size_t httpasm_token_length(const uint8_t *p, size_t n)
;   The number of leading octets of p[0..n) that are tchar (RFC9110-5.6.2-2), n when all are.
;   p holds a token (a method, a field name: RFC9110-5.1-2) when n > 0 and the result is n.
;   In: rdi = p, rsi = n. Out: rax. Clobbers rcx, rdx and the flags.
;   Reads p[0..result] at most: never past p + n, and nothing at all when n is 0.
; -----------------------------------------------------------------------------
global httpasm_token_length:function (httpasm_token_length.end - httpasm_token_length)
align 16
httpasm_token_length:
    HA_TOKEN_SCAN rdi, rsi, rax, rcx, rdx
    ret
.end:

; -----------------------------------------------------------------------------
; size_t httpasm_field_value_scan(const uint8_t *p, size_t n)
;   The index of the first octet of p[0..n) that a field value may not hold, n when there is
;   none. The forbidden octets are the CTLs other than HTAB: 0x00-0x08, 0x0A-0x1F and 0x7F
;   (RFC9110-5.5-2, RFC9110-5.5-5#1, RFC9110-5.5-5#2, RFC9113-8.2.1-3.3). Whitespace at the
;   value's ends is not checked here: each version has its own rule for it.
;   In: rdi = p, rsi = n. Out: rax. Clobbers rcx, rdx, xmm0-xmm5 and the flags.
;   Memory: see HA_FIELD_VALUE_SCAN. It never reads outside p[0..n), except that a short value
;   may be read as 16 octets that lie in the same 4 KiB page as p, which cannot fault.
; -----------------------------------------------------------------------------
global httpasm_field_value_scan:function (httpasm_field_value_scan.end - httpasm_field_value_scan)
align 16
httpasm_field_value_scan:
    HA_FIELD_VALUE_SCAN rdi, rsi, rax, rcx, ecx, rdx, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5
    ret
.end:
