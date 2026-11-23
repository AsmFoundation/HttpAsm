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
    ; tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" /
    ;         "~" / DIGIT / ALPHA                  (RFC9110-5.6.2-2), the punctuation in hex:
    ;         !=21 #=23 $=24 %=25 &=26 '=27 *=2A +=2B -=2D .=2E ^=5E _=5F `=60 |=7C ~=7E
    %if (bits & (HA_CC_DIGIT | HA_CC_ALPHA)) || c == 0x21 || (c >= 0x23 && c <= 0x27) || c == 0x2A || c == 0x2B || c == 0x2D || c == 0x2E || c == 0x5E || c == 0x5F || c == 0x60 || c == 0x7C || c == 0x7E
        %assign bits bits | HA_CC_TCHAR
    %endif
    db      bits
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
