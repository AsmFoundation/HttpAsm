; =============================================================================
; semantics/tables.asm - the core's read-only tables, computed by NASM from the grammar.
;
; The class table is not typed in: NASM evaluates each octet against the definitions of
; RFC 5234 appendix B.1 (VCHAR, DIGIT, ALPHA) and RFC 9110 sections 5.5 and 5.6.2 (obs-text,
; tchar), so the table cannot drift from the rules written next to it.
; =============================================================================
default rel
%define HA_DEFINING_TABLES          ; the symbols below are defined here, not extern
%include "httpasm_core.inc"

; HA_IS_TCHAR(c): whether octet c is a tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" /
; "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA (RFC9110-5.6.2-2), the punctuation in
; hex: !=21 #=23 $=24 %=25 &=26 '=27 *=2A +=2B -=2D .=2E ^=5E _=5F `=60 |=7C ~=7E. The one
; definition the class table and the nibble tables (ha_tchar_lo, ha_tchar_hi) are computed
; from, so the scalar and the vector token scans cannot disagree.
%define HA_IS_TCHAR(c) (((c) >= 0x30 && (c) <= 0x39) || ((c) >= 0x41 && (c) <= 0x5A) || ((c) >= 0x61 && (c) <= 0x7A) || (c) == 0x21 || ((c) >= 0x23 && (c) <= 0x27) || (c) == 0x2A || (c) == 0x2B || (c) == 0x2D || (c) == 0x2E || (c) == 0x5E || (c) == 0x5F || (c) == 0x60 || (c) == 0x7C || (c) == 0x7E)

section .rodata

; -----------------------------------------------------------------------------
; ha_char_class: 256 bytes, one per octet value, each a set of HA_CC_* bits.
; -----------------------------------------------------------------------------
align 64                            ; one table, four cache lines
global ha_char_class:data hidden (ha_char_class.end - ha_char_class)
ha_char_class:
%assign c 0
%rep 256
    %assign bits 0
    %if c >= 0x21 && c <= 0x7E                      ; VCHAR = %x21-7E
        %assign bits bits | HA_CC_VCHAR
    %endif
    %if c >= 0x80                                   ; obs-text = %x80-FF
        %assign bits bits | HA_CC_OBS
    %endif
    %if c == 0x20 || c == 0x09                      ; SP / HTAB
        %assign bits bits | HA_CC_WS
    %endif
    %if c >= 0x30 && c <= 0x39                      ; DIGIT = %x30-39
        %assign bits bits | HA_CC_DIGIT
    %endif
    %if (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)    ; ALPHA = %x41-5A / %x61-7A
        %assign bits bits | HA_CC_ALPHA
    %endif
    %if c >= 0x41 && c <= 0x5A                      ; A-Z
        %assign bits bits | HA_CC_UPPER
    %endif
    %if HA_IS_TCHAR(c)                              ; tchar (RFC9110-5.6.2-2), defined above
        %assign bits bits | HA_CC_TCHAR
    %endif
    ; RFC 3986: unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"; sub-delims = "!" / "$" /
    ; "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="; pchar adds ":" "@"; path and query
    ; add "/" "?"; pct-encoded starts with "%"; IP-literal uses "[" "]". In hex:
    ; -=2D .=2E _=5F ~=7E !=21 $=24 &=26 '=27 (=28 )=29 *=2A +=2B ,=2C ;=3B ==3D :=3A @=40
    ; /=2F ?=3F %=25 [=5B ]=5D
    %if (bits & (HA_CC_DIGIT | HA_CC_ALPHA)) || c == 0x2D || c == 0x2E || c == 0x5F || c == 0x7E || c == 0x21 || c == 0x24 || (c >= 0x26 && c <= 0x2C) || c == 0x3B || c == 0x3D || c == 0x3A || c == 0x40 || c == 0x2F || c == 0x3F || c == 0x25 || c == 0x5B || c == 0x5D
        %assign bits bits | HA_CC_TARGET
    %endif
    db      bits
    %assign c c + 1
%endrep
.end:

; -----------------------------------------------------------------------------
; ha_hex_value: 256 bytes; an octet's value as HEXDIG (RFC 5234 B.1: DIGIT / "A"-"F", and the
; lower-case letters, since ABNF strings are case-insensitive), 0xFF otherwise. Chunk sizes
; (RFC 9112 7.1) and percent-encodings (RFC 3986 2.1) are read through it.
; -----------------------------------------------------------------------------
align 64
global ha_hex_value:data hidden (ha_hex_value.end - ha_hex_value)
ha_hex_value:
%assign c 0
%rep 256
    %if c >= 0x30 && c <= 0x39
        db  c - 0x30
    %elif c >= 0x41 && c <= 0x46
        db  c - 0x41 + 10
    %elif c >= 0x61 && c <= 0x66
        db  c - 0x61 + 10
    %else
        db  0xFF
    %endif
    %assign c c + 1
%endrep
.end:

; -----------------------------------------------------------------------------
; Vector constants for HA_FIELD_VALUE_CLASSIFY (semantics/fields.inc): 16 copies each, aligned
; so that movdqa can load them.
; -----------------------------------------------------------------------------
align 16
global ha_x16_1f:data hidden (ha_x16_1f.end - ha_x16_1f)
ha_x16_1f:  times 16 db 0x1F        ; the highest CTL below SP
.end:
global ha_x16_09:data hidden (ha_x16_09.end - ha_x16_09)
ha_x16_09:  times 16 db 0x09        ; HTAB
.end:
global ha_x16_7f:data hidden (ha_x16_7f.end - ha_x16_7f)
ha_x16_7f:  times 16 db 0x7F        ; DEL
.end:
global ha_x16_0a:data hidden (ha_x16_0a.end - ha_x16_0a)
ha_x16_0a:  times 16 db 0x0A        ; LF
.end:
global ha_x16_0d:data hidden (ha_x16_0d.end - ha_x16_0d)
ha_x16_0d:  times 16 db 0x0D        ; CR
.end:
global ha_x16_0f:data hidden (ha_x16_0f.end - ha_x16_0f)
ha_x16_0f:  times 16 db 0x0F        ; a nibble: what pshufb's index keeps of an octet
.end:

; -----------------------------------------------------------------------------
; ha_tchar_lo, ha_tchar_hi: the tchar class as two 16-entry tables for pshufb, one indexed by an
; octet's low nibble and one by its high nibble: an octet is a tchar exactly when its two
; entries share a bit. tchar lives in the rows 0x20-0x7F only (it is visible ASCII), so each of
; those six rows gets a bit of its own (row 2 bit 0 ... row 7 bit 5): the high table holds a
; row's bit, the low table, for each column, the bits of the rows whose octet in that column is
; a tchar. Both are computed from HA_IS_TCHAR, and every one of the 256 octets is checked below
; at assembly time: a wrong table does not assemble.
; -----------------------------------------------------------------------------
global ha_tchar_lo:data hidden (ha_tchar_lo.end - ha_tchar_lo)
ha_tchar_lo:
%assign l 0
%rep 16
    %assign bits 0
    %assign h 2
    %rep 6
        %if HA_IS_TCHAR(h * 16 + l)
            %assign bits bits | (1 << (h - 2))
        %endif
        %assign h h + 1
    %endrep
    db      bits
    %assign l l + 1
%endrep
.end:
global ha_tchar_hi:data hidden (ha_tchar_hi.end - ha_tchar_hi)
ha_tchar_hi:
%assign h 0
%rep 16
    %if h >= 2 && h <= 7
        db  1 << (h - 2)
    %else
        db  0
    %endif
    %assign h h + 1
%endrep
.end:

; The proof: for every octet, the two tables agree with HA_IS_TCHAR (the same arithmetic as the
; tables above, recomputed per octet: a row outside 2-7 has no bit, so nothing there is a tchar).
%assign c 0
%rep 256
    %assign h c >> 4
    %assign l c & 15
    %assign hi_bit 0
    %if h >= 2 && h <= 7
        %assign hi_bit 1 << (h - 2)
    %endif
    %assign lo_bits 0
    %assign r 2
    %rep 6
        %if HA_IS_TCHAR(r * 16 + l)
            %assign lo_bits lo_bits | (1 << (r - 2))
        %endif
        %assign r r + 1
    %endrep
    %if ((lo_bits & hi_bit) != 0) != (HA_IS_TCHAR(c) != 0)
        %error the tchar nibble tables disagree with HA_IS_TCHAR at octet c
    %endif
    %assign c c + 1
%endrep
