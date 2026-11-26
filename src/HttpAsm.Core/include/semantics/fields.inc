; =============================================================================
; semantics/fields.inc - the field rules of RFC 9110 sections 5.1, 5.5 and 5.6.2, as macros.
;
; Shared source, separate code (docs/DESIGN.md): each rule is written once, here, and assembled
; into every place that needs it: HTTP/1.1's parser, HTTP/2's and HTTP/3's field decoders, and
; the C ABI's functions (semantics/fields.asm). Each instance is the caller's own inlined code,
; with the caller's registers: no call, no version check, no shared state.
;
; Every macro takes the registers it may use as arguments, so the caller keeps whatever else it
; holds. Labels are macro-local (%%): any number of instances can share one function.
; =============================================================================
%ifndef HTTPASM_SEMANTICS_FIELDS_INC
%define HTTPASM_SEMANTICS_FIELDS_INC

; -----------------------------------------------------------------------------
; HA_TOKEN_SCAN ptr, len, out, byte, table
;   The length of the token at the start of ptr[0..len): out = the number of leading octets that
;   are tchar (RFC9110-5.6.2-2), len when all are. A token (a method, a field name: RFC9110-5.1-2)
;   is valid when len > 0 and out == len.
;
;   ptr, len   64-bit registers, unchanged.
;   out        a 64-bit register: the result.
;   byte       a 64-bit scratch register.
;   table      a 64-bit scratch register (the class table's address).
;   Flags are clobbered. Reads ptr[0..out] at most, so never past ptr + len.
;
;   One table lookup per octet. Tokens are short (methods, field names), and the parsers that
;   call this also hash the name, so a vector form waits for a measurement that asks for it.
; -----------------------------------------------------------------------------
%macro HA_TOKEN_SCAN 5
    xor     %3, %3
    lea     %5, [rel ha_char_class]
%%next:
    cmp     %3, %2
    jae     %%done                          ; every octet was a tchar
    movzx   %4, byte [%1 + %3]
    test    byte [%5 + %4], HA_CC_TCHAR
    jz      %%done                          ; the first octet outside tchar
    inc     %3
    jmp     %%next
%%done:
%endmacro

; -----------------------------------------------------------------------------
; HA_FIELD_VALUE_CLASSIFY data, tmp, eq, low, tab, del, mask
;   One vector of 16 octets: mask = a bit per octet that a field value may not hold, a CTL other
;   than HTAB (see HA_CC_VALUE in httpasm_core.inc). Bit i is octet i.
;
;   data       an XMM register holding the octets; destroyed.
;   tmp, eq    XMM scratch registers.
;   low, tab, del  XMM registers holding ha_x16_1f, ha_x16_09 and ha_x16_7f; unchanged.
;   mask       a 32-bit register: the result. Writing it clears the upper half of its 64-bit
;              register, so the caller may test the 64-bit form. (NASM has no 64-bit form of
;              pmovmskb, and a macro cannot derive "ecx" from "rcx", so the caller names both.)
;
;   SSE2 has no unsigned byte compare, but it has an unsigned byte minimum: an octet is at most
;   0x1F exactly when min(octet, 0x1F) equals it. Octets 0x80-0xFF (obs-text) stay valid.
; -----------------------------------------------------------------------------
%macro HA_FIELD_VALUE_CLASSIFY 7
    movdqa  %2, %1
    pminub  %2, %4                          ; min(octet, 0x1F)
    pcmpeqb %2, %1                          ; 0xFF where the octet is 0x00-0x1F, the CTLs below SP
    movdqa  %3, %1
    pcmpeqb %3, %5                          ; 0xFF where the octet is HTAB
    pandn   %3, %2                          ; CTLs below SP, except HTAB
    pcmpeqb %1, %6                          ; 0xFF where the octet is DEL
    por     %1, %3                          ; every octet a field value may not hold
    pmovmskb %7, %1
%endmacro

; -----------------------------------------------------------------------------
; HA_FIELD_VALUE_SCAN ptr, len, out, t0, t0d, t1, data, tmp, eq, low, tab, del
;   The first octet of ptr[0..len) that a field value may not hold: out = its index, or len when
;   every octet may appear in a field value. Implements the octet rules of RFC9110-5.5-2,
;   RFC9110-5.5-5#1 (CR, LF and NUL are found, so the message can be rejected), RFC9110-5.5-5#2
;   (the other CTLs are found too: HttpAsm rejects rather than retains them) and
;   RFC9113-8.2.1-3.3 (no NUL, LF or CR at any position). Whitespace at the ends is the caller's
;   rule: HTTP/1.1 strips OWS around the value, HTTP/2 forbids it (RFC9113-8.2.1-3.4).
;
;   ptr, len   64-bit registers, unchanged.
;   out        a 64-bit register: the result.
;   t0, t0d    a scratch register, named in its 64-bit and its 32-bit form ("rcx", "ecx").
;   t1         a 64-bit scratch register.
;   data, tmp, eq  XMM scratch registers.
;   low, tab, del  XMM scratch registers; they receive the three constants.
;   Flags are clobbered.
;
;   Memory: 16 octets at a time. A value of 16 octets or more never reads outside ptr[0..len):
;   the last vector overlaps the one before instead of running past the end, and the octets it
;   reads twice are already known to be valid, so its first flagged octet is the first one past
;   them. A shorter value is read as one vector from ptr when those 16 octets lie in one 4 KiB
;   page (they can then never fault, wherever the value ends), and flags past len are ignored.
;   Within 16 octets of a page's end, it is read octet by octet instead.
; -----------------------------------------------------------------------------
%macro HA_FIELD_VALUE_SCAN 12
    movdqa  %10, [rel ha_x16_1f]
    movdqa  %11, [rel ha_x16_09]
    movdqa  %12, [rel ha_x16_7f]
    xor     %3, %3                          ; out: the offset of the next vector
    cmp     %2, 16
    jb      %%short

%%vector:                                   ; invariant: out + 16 <= len
    movdqu  %7, [%1 + %3]
    HA_FIELD_VALUE_CLASSIFY %7, %8, %9, %10, %11, %12, %5
    test    %4, %4
    jnz     %%found
    add     %3, 16
    lea     %6, [%3 + 16]
    cmp     %6, %2
    jbe     %%vector
    cmp     %3, %2
    je      %%done                          ; len was a multiple of 16: out == len
    ; 1 to 15 octets remain: read the last 16 octets of the value, which overlap the vector
    ; before. Every octet they share with it is valid, so the first flag is in the new ones.
    mov     %3, %2
    sub     %3, 16
    movdqu  %7, [%1 + %3]
    HA_FIELD_VALUE_CLASSIFY %7, %8, %9, %10, %11, %12, %5
    test    %4, %4
    jnz     %%found
    mov     %3, %2
    jmp     %%done

%%found:                                    ; t0 holds the flags of the vector at out
    bsf     %4, %4
    add     %3, %4
    jmp     %%done

%%short:                                    ; len < 16; out = 0
    test    %2, %2
    jz      %%done                          ; an empty value holds nothing invalid
    mov     %6, %1
    and     %6, 4095
    cmp     %6, 4096 - 16
    ja      %%octets                        ; 16 octets from ptr would reach the next page
    movdqu  %7, [%1]                        ; the same page: cannot fault
    HA_FIELD_VALUE_CLASSIFY %7, %8, %9, %10, %11, %12, %5
    test    %4, %4
    jz      %%all_valid
    bsf     %4, %4
    cmp     %4, %2
    jae     %%all_valid                     ; the flag is past the value's end
    mov     %3, %4
    jmp     %%done
%%all_valid:
    mov     %3, %2
    jmp     %%done

%%octets:                                   ; near a page's end: one table lookup per octet
    lea     %6, [rel ha_char_class]
%%octet:
    movzx   %4, byte [%1 + %3]
    test    byte [%6 + %4], HA_CC_VALUE
    jz      %%done                          ; out: the first octet not allowed
    inc     %3
    cmp     %3, %2
    jb      %%octet
%%done:
%endmacro

; -----------------------------------------------------------------------------
; HA_FIELD_VALUE_CLASSIFY_V3 data, tmp, eq, low, tab, del, mask
;   HA_FIELD_VALUE_CLASSIFY on 32 octets (AVX2): the registers are YMM registers, the constants
;   are broadcast to all 32 lanes, and bit i of mask (a 32-bit register) is octet i.
; -----------------------------------------------------------------------------
%macro HA_FIELD_VALUE_CLASSIFY_V3 7
    vpminub %2, %1, %4                      ; min(octet, 0x1F)
    vpcmpeqb %2, %2, %1                     ; 0xFF where the octet is 0x00-0x1F
    vpcmpeqb %3, %1, %5                     ; 0xFF where the octet is HTAB
    vpandn  %3, %3, %2                      ; CTLs below SP, except HTAB
    vpcmpeqb %1, %1, %6                     ; 0xFF where the octet is DEL
    vpor    %1, %1, %3
    vpmovmskb %7, %1
%endmacro

; -----------------------------------------------------------------------------
; HA_FIELD_VALUE_SCAN_V3 ptr, len, out, t0, t0d, t1, data, tmp, eq, low, tab, del
;   HA_FIELD_VALUE_SCAN's result, 32 octets at a time (v3: AVX2, BMI1). The vector registers
;   are YMM registers; the rest is as in HA_FIELD_VALUE_SCAN.
;   Requires len >= 32: a shorter value is the 16-octet version's work (it reads one vector
;   either way). Like it, this never reads outside ptr[0..len): the last vector overlaps the one
;   before, whose octets are already known to be valid.
;   The caller ends its routine with vzeroupper (cpu.inc's conventions).
; -----------------------------------------------------------------------------
%macro HA_FIELD_VALUE_SCAN_V3 12
    vpbroadcastb %10, [rel ha_x16_1f]
    vpbroadcastb %11, [rel ha_x16_09]
    vpbroadcastb %12, [rel ha_x16_7f]
    xor     %3, %3                          ; out: the offset of the next vector
%%vector:                                   ; invariant: out + 32 <= len
    vmovdqu %7, [%1 + %3]
    HA_FIELD_VALUE_CLASSIFY_V3 %7, %8, %9, %10, %11, %12, %5
    test    %4, %4
    jnz     %%found
    add     %3, 32
    lea     %6, [%3 + 32]
    cmp     %6, %2
    jbe     %%vector
    cmp     %3, %2
    je      %%done                          ; len was a multiple of 32: out == len
    mov     %3, %2                          ; 1 to 31 octets remain: the last 32, overlapping
    sub     %3, 32
    vmovdqu %7, [%1 + %3]
    HA_FIELD_VALUE_CLASSIFY_V3 %7, %8, %9, %10, %11, %12, %5
    test    %4, %4
    jnz     %%found
    mov     %3, %2
    jmp     %%done
%%found:                                    ; t0 holds the flags of the vector at out
    tzcnt   %4, %4
    add     %3, %4
%%done:
%endmacro

; -----------------------------------------------------------------------------
; HA_FIELD_VALUE_SCAN_V4 ptr, len, out, t0, t1, data, low, tab, del, klen, kflag, ktmp
;   HA_FIELD_VALUE_SCAN's result, 64 octets at a time (v4: AVX-512 BW; BMI2 comes with v3).
;   Any length: the last vector is loaded under a mask of the octets that remain, and AVX-512
;   suppresses faults on masked-off octets, so it never touches memory outside ptr[0..len), not
;   even within the same page, and needs no overlap and no page check.
;
;   ptr, len   64-bit registers, unchanged.
;   out        a 64-bit register: the result.
;   t0, t1     64-bit scratch registers.
;   data, low, tab, del  ZMM scratch registers; the last three receive the constants.
;   klen, kflag, ktmp    opmask scratch registers (k1-k7).
;   Flags are clobbered. The caller ends its routine with vzeroupper.
; -----------------------------------------------------------------------------
%macro HA_FIELD_VALUE_SCAN_V4 12
    vpbroadcastb %7, [rel ha_x16_1f]
    vpbroadcastb %8, [rel ha_x16_09]
    vpbroadcastb %9, [rel ha_x16_7f]
    xor     %3, %3                          ; out: the offset of the next vector
%%vector:
    mov     %4, %2
    sub     %4, %3                          ; octets left
    jbe     %%all                           ; none (the last vector may have run past len)
    mov     %5, -1
    cmp     %4, 64
    jae     %%load                          ; a whole vector
    bzhi    %5, %5, %4                      ; one bit per octet left
%%load:
    kmovq   %10, %5
    vmovdqu8 %6{%10}{z}, [%1 + %3]
    vpcmpub %11{%10}, %6, %7, 2             ; octet <= 0x1F, among the octets loaded
    vpcmpeqb %12{%10}, %6, %8               ; HTAB
    kandnq  %11, %12, %11                   ; CTLs below SP, except HTAB
    vpcmpeqb %12{%10}, %6, %9               ; DEL
    korq    %11, %11, %12
    kortestq %11, %11
    jnz     %%found
    add     %3, 64
    jmp     %%vector
%%found:
    kmovq   %5, %11
    tzcnt   %5, %5
    add     %3, %5
    jmp     %%done
%%all:
    mov     %3, %2
%%done:
%endmacro

%endif
