; =============================================================================
; semantics/authority.inc - the authority rules every version shares, as macros: uri-host
; [ ":" port ] (RFC 9112 3.2 for Host, RFC 3986 3.2.2-3.2.3), and the authority-form CONNECT
; names (RFC 9112 3.2.3, RFC 9110 9.3.6, RFC 9113 8.5).
;
; Shared source, separate code (docs/DESIGN.md; semantics/fields.inc says how): HTTP/1.1's Host
; and CONNECT target, and HTTP/2's :authority and Host, are checked by the same text. They must
; be: an authority one version accepts and the other refuses can be played against an HTTP/1.1
; hop behind an HTTP/2 front, which is how tests/fuzz/h2_request found the first difference
; (2026-11-26): HTTP/2 took CONNECT's :authority without a port, and any :authority or Host
; without CTLs or "@", while HTTP/1.1 refused both.
; =============================================================================
%ifndef HTTPASM_SEMANTICS_AUTHORITY_INC
%define HTTPASM_SEMANTICS_AUTHORITY_INC

; -----------------------------------------------------------------------------
; HA_URI_HOST cursor, end, class, hex, t64, t32, t8, u64, u32, fail
;   Checks [cursor, end) as uri-host [ ":" port ]: an IP-literal ("[", an IPv6address's octets
;   - HEXDIG, ":" and "." - with two colons at least, or an IPvFuture: "v" 1*HEXDIG "." then
;   unreserved, sub-delims and ":"; then "]"), or a reg-name / IPv4address (request-target
;   octets but ":", "/", "?", "@", "[" and "]", each "%" followed by two HEXDIG); then nothing,
;   or ":" and *DIGIT. The IPv6 address's own structure (eight groups, one "::") is not checked
;   yet: docs/DESIGN.md, phase H step 3. An empty range passes: whether an empty authority
;   is allowed is the caller's rule (HTTP/1.1's Host may be empty, :authority may not). userinfo
;   ("@") never passes: it hides the real authority behind a lookalike (RFC9110-4.2.4-4).
;   Falls through when the range is valid; jumps to fail otherwise.
;
;   cursor     a 64-bit register: the first octet; advanced (clobbered).
;   end        a 64-bit register: one past the last octet; unchanged.
;   class      a 64-bit register holding ha_char_class's address; unchanged.
;   hex        a 64-bit register holding ha_hex_value's address; unchanged.
;   t64, t32, t8   one scratch register, as its 64-, 32- and 8-bit names (rax, eax, al).
;   u64, u32   another scratch register, as its 64- and 32-bit names (rcx, ecx).
;   Flags are clobbered. Reads [cursor, end) only.
; -----------------------------------------------------------------------------
%macro HA_URI_HOST 10
    cmp     %1, %2
    jae     %%valid                         ; empty: the caller's rule
    cmp     byte [%1], '['
    jne     %%name
    ; IP-literal = "[" ( IPv6address / IPvFuture ) "]" (RFC 3986 3.2.2). Any request-target
    ; octet once passed here, and HTTP/1.1's target scan (which checks every "%") then refused
    ; "[%:]" where HTTP/2 took it (tests/fuzz/h2_request, 2026-11-26): now only these grammars'
    ; own octets pass.
    inc     %1
    cmp     %1, %2
    jae     %10                             ; "[" alone
    movzx   %6, byte [%1]
    cmp     %7, ']'
    je      %10                             ; "[]": no address
    or      %6, 0x20
    cmp     %6, 'v'
    je      %%future
    ; IPv6address, its whole structure, and the "]" (semantics/ipv6.asm): eight pieces, or
    ; seven at most with one "::", an IPv4 tail last with dec-octets of 255 at most and no
    ; leading zero. A function, not inline: its state needs more registers than this macro
    ; has, and the call keeps every register (pushing the range, popping the result).
    push    %2
    push    %1
    call    ha_ipv6_literal
    pop     %1                              ; past the "]", or 0
    add     rsp, 8
    test    %1, %1
    jz      %10
    jmp     %%port_or_end
%%future:                                   ; IPvFuture = "v" 1*HEXDIG "." 1*( unreserved /
    inc     %1                              ;             sub-delims / ":" )
    cmp     %1, %2
    jae     %10
    movzx   %6, byte [%1]
    cmp     byte [%4 + %5], 0xFF
    je      %10                             ; no HEXDIG after "v"
%%future_hex:
    inc     %1
    cmp     %1, %2
    jae     %10
    movzx   %6, byte [%1]
    cmp     %7, '.'
    je      %%future_dot
    cmp     byte [%4 + %5], 0xFF
    je      %10
    jmp     %%future_hex
%%future_dot:
    inc     %1
    cmp     %1, %2
    jae     %10
    cmp     byte [%1], ']'
    je      %10                             ; nothing after the "."
%%future_tail:
    cmp     %1, %2
    jae     %10                             ; no "]"
    movzx   %6, byte [%1]
    inc     %1
    cmp     %7, ']'
    je      %%port_or_end
    test    byte [%3 + %5], HA_CC_TARGET    ; unreserved, sub-delims and ":" are target octets;
    jz      %10                             ; the target octets they are not, refused below
    cmp     %7, '/'
    je      %10
    cmp     %7, '?'
    je      %10
    cmp     %7, '@'
    je      %10
    cmp     %7, '['
    je      %10
    cmp     %7, '%'
    je      %10
    jmp     %%future_tail
%%name:                                     ; reg-name or IPv4address, up to ":" or the end
    cmp     %1, %2
    jae     %%valid
    movzx   %6, byte [%1]
    cmp     %7, ':'
    je      %%port_or_end
    test    byte [%3 + %5], HA_CC_TARGET
    jz      %10
    cmp     %7, '/'
    je      %10
    cmp     %7, '?'
    je      %10
    cmp     %7, '@'
    je      %10
    cmp     %7, '['
    je      %10
    cmp     %7, ']'
    je      %10
    inc     %1
    cmp     %7, '%'
    jne     %%name
    lea     %8, [%1 + 2]                    ; pct-encoded: two HEXDIG inside the range
    cmp     %8, %2
    ja      %10
    movzx   %9, byte [%1]
    cmp     byte [%4 + %8], 0xFF
    je      %10
    movzx   %9, byte [%1 + 1]
    cmp     byte [%4 + %8], 0xFF
    je      %10
    add     %1, 2
    jmp     %%name
%%port_or_end:
    cmp     %1, %2
    jae     %%valid
    cmp     byte [%1], ':'
    jne     %10                             ; "]x": nothing but a port may follow a literal
    inc     %1
%%port:                                     ; port = *DIGIT
    cmp     %1, %2
    jae     %%valid
    movzx   %6, byte [%1]
    sub     %6, '0'
    cmp     %6, 9
    ja      %10
    inc     %1
    jmp     %%port
%%valid:
%endmacro

; -----------------------------------------------------------------------------
; HA_AUTHORITY_PORT start, end, cursor, value, digit, place, fail
;   The authority-form's own rule, for a range HA_URI_HOST has already passed: uri-host ":"
;   port with a host that is not empty and a port of 1 to 65535 (RFC 9112 3.2.3: the port is
;   required; RFC9110-9.3.6-4: a CONNECT to an empty or invalid port is refused; port 0 names
;   no service, RFC 6335 reserves it). Leading zeros are digits like others ("0443" is 443).
;   Falls through when the range is valid; jumps to fail otherwise.
;
;   start, end   64-bit registers: the range; unchanged.
;   cursor       a 64-bit scratch register: walks the range from its end backwards.
;   value, digit, place   32-bit scratch registers: the port's value, the current digit, and
;                the place value of the next digit (1, 10, ... 100000, where it stops).
;   Flags are clobbered. Reads [start, end) only. After HA_URI_HOST the last ":" before the
;   trailing digits is the port's: an IPv6 literal's own colons sit inside its brackets.
; -----------------------------------------------------------------------------
%macro HA_AUTHORITY_PORT 7
    mov     %3, %2                          ; from the end backwards
    xor     %4, %4                          ; the port's value
    mov     %6, 1                           ; the next digit's place value
%%digit:
    cmp     %3, %1
    jbe     %7                              ; digits to the start: no ":" at all
    dec     %3
    movzx   %5, byte [%3]
    cmp     %5, ':'
    je      %%colon
    sub     %5, '0'
    cmp     %5, 9
    ja      %7                              ; the range does not end in ":" port
    cmp     %6, 100000
    jae     %%high                          ; a sixth digit or more
    imul    %5, %6
    add     %4, %5
    imul    %6, %6, 10
    jmp     %%digit
%%high:
    test    %5, %5
    jnz     %7                              ; a nonzero digit there: past 65535
    jmp     %%digit                         ; a leading zero: the value stays
%%colon:
    cmp     %6, 1
    je      %7                              ; ":" with no digit after it (the place never grew)
    cmp     %3, %1
    je      %7                              ; no host before the ":"
    test    %4, %4
    jz      %7                              ; port 0
    cmp     %4, 65535
    ja      %7
%endmacro

%endif
