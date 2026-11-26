; =============================================================================
; httpasm_core.inc - the core's constants and internal symbols, for every source of the core
; and of libhttpasm.so.
;
; Conventions of all HttpAsm code (Linux x64 only, the owner's choice of 2026-11-23):
;   - System V AMD64: arguments in rdi, rsi, rdx, rcx, r8, r9; rbx, rbp and r12-r15 are kept
;     across calls; xmm0-xmm15 are not.
;   - Internal symbols start with ha_ and are hidden: they link between the core's objects but
;     are exported from no image. The C ABI's symbols start with httpasm_ and are exported
;     through src/HttpAsm/httpasm.map.
;   - SSE2 is the floor (v1, any x86-64). Faster versions (v2: SSSE3/SSE4.2; v3: AVX2; v4:
;     AVX-512; the AES, carry-less multiply and SHA instructions) are chosen at run time from
;     ha_cpu, and each is kept only when a single-thread measurement shows it pays: cpu.inc.
;   - Comments name the requirement rows they implement (specs/requirements.tsv): a row id such
;     as RFC9110-5.5-5#1 leads to the RFC Editor's paragraph of the same anchor.
; =============================================================================
%ifndef HTTPASM_CORE_INC
%define HTTPASM_CORE_INC

; -----------------------------------------------------------------------------
; Character classes: bits of the 256-byte table ha_char_class (semantics/tables.asm), one byte
; per octet value. A byte is in a class when its bit is set.
; -----------------------------------------------------------------------------
HA_CC_TCHAR     equ 0x01    ; RFC 9110 5.6.2 tchar: a token's characters (RFC9110-5.6.2-2)
HA_CC_VCHAR     equ 0x02    ; RFC 5234 B.1 VCHAR, visible US-ASCII: 0x21-0x7E
HA_CC_OBS       equ 0x04    ; RFC 9110 5.5 obs-text: 0x80-0xFF (RFC9110-5.5-2)
HA_CC_WS        equ 0x08    ; SP or HTAB, the whitespace of OWS, RWS and BWS (RFC 9110 5.6.3)
HA_CC_DIGIT     equ 0x10    ; RFC 5234 B.1 DIGIT: 0-9
HA_CC_ALPHA     equ 0x20    ; RFC 5234 B.1 ALPHA: A-Z and a-z
HA_CC_UPPER     equ 0x40    ; A-Z: forbidden in HTTP/2 and HTTP/3 field names (RFC9113-8.2.1-3.1)
HA_CC_TARGET    equ 0x80    ; an octet a request-target may hold as is (RFC 3986): unreserved,
                            ; sub-delims, ":", "@", "/", "?", "%" (checked as pct-encoded by the
                            ; parser), and "[" "]" for IP literals. Everything else must be
                            ; percent-encoded: SP, CTLs, DQUOTE, "#<>\^`{|}", DEL, 0x80-0xFF.

; The octets a field value may hold, as HttpAsm reads RFC 9110 section 5.5: field-vchar
; (VCHAR / obs-text), SP and HTAB. Every other octet is a CTL (0x00-0x08, 0x0A-0x1F, 0x7F).
; CR, LF and NUL must be rejected or replaced (RFC9110-5.5-5#1); the other CTLs are invalid too,
; and HttpAsm rejects them rather than retain them, which RFC9110-5.5-5#2 permits.
HA_CC_VALUE     equ HA_CC_VCHAR | HA_CC_OBS | HA_CC_WS

; -----------------------------------------------------------------------------
; Internal data (semantics/tables.asm). The file that defines them sets HA_DEFINING_TABLES
; first: NASM refuses a symbol declared extern and then defined in the same object.
; -----------------------------------------------------------------------------
%ifndef HA_DEFINING_TABLES
extern ha_char_class        ; 256 bytes of HA_CC_* bits, indexed by octet value
extern ha_hex_value         ; 256 bytes: an octet's HEXDIG value (0-15), 0xFF when not a HEXDIG
extern ha_x16_1f            ; 16 bytes of 0x1F: the highest CTL below SP, for pminub
extern ha_x16_09            ; 16 bytes of 0x09: HTAB, the one CTL a field value may hold
extern ha_x16_7f            ; 16 bytes of 0x7F: DEL, the CTL above the visible range
extern ha_x16_0a            ; 16 bytes of 0x0A: LF, the end of every HTTP/1.1 line
extern ha_x16_0f            ; 16 bytes of 0x0F: the low nibble, what pshufb's index keeps
extern ha_lane_window       ; 48 bytes (16 x 0x00, 16 x 0xFF, 16 x 0x00): lane masks by length
extern ha_tchar_lo          ; 16 bytes: tchar by low nibble, for pshufb (tables.asm says how)
extern ha_tchar_hi          ; 16 bytes: tchar by high nibble; an octet is a tchar when its two
                            ; entries share a bit. Its entries are the row bits of rows 2-7, so
                            ; it pairs with ha_target_lo as well
extern ha_target_lo         ; 16 bytes: request-target octets but "%", by low nibble (pairs with
                            ; ha_tchar_hi): what a vector target scan passes over
%endif

; -----------------------------------------------------------------------------
; Internal functions shared by the protocol codecs (System V; each documents its clobbers)
; -----------------------------------------------------------------------------
extern ha_field_lookup      ; eax = known-field id of name rdi[0..rsi), 0 if not known
extern ha_method_lookup     ; eax = HTTPASM_METHOD_* of method rdi[0..rsi), 0 if another
extern ha_find_lf           ; rax = offset of the first LF in rdi[0..rsi), rsi if none
extern ha_token_length      ; rax = the leading tchars of rdi[0..rsi) (rsi when all are); keeps
                            ; rdi, rsi; clobbers rcx, rdx, xmm0-xmm6 (semantics/fields.asm)
extern ha_ipv6_literal      ; [rsp] = past an IP-literal's IPv6address and "]", or 0; keeps every
                            ; register (semantics/ipv6.asm: push end, push cursor, call, pop, add rsp 8)

%include "httpasm_abi.inc"
%include "cpu.inc"
%include "semantics/fields.inc"
%include "semantics/authority.inc"

%endif
