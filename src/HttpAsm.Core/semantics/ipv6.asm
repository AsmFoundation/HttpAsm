; =============================================================================
; semantics/ipv6.asm - an IP-literal's IPv6address, whole (RFC 3986 3.2.2), for every
; expansion of semantics/authority.inc's HA_URI_HOST.
;
; The macro checks the rest of an authority inline, in each version's own code. This grammar
; needs more state than the macro's two scratch registers hold: the pieces counted, one "::"
; at most, and an IPv4 tail with its dotted dec-octets. So its one copy lives here, and every
; expansion calls it through a convention that keeps every register. The call sites hold
; different registers live, and an IP-literal is rare enough that one call costs nothing
; that matters.
;
; Before this, HA_URI_HOST took any HEXDIG, ":" and "." with two colons at least, so
; "[1:::::::::2]" and "[::1.2.3.999]" passed as Host, as CONNECT targets and as :authority
; (docs/DESIGN.md phase H step 3 had it open).
; =============================================================================
default rel
%include "httpasm_core.inc"

section .text

; -----------------------------------------------------------------------------
; ha_ipv6_literal: the IPv6address of an IP-literal, and its closing "]" (RFC 3986 3.2.2):
;     IPv6address =  6( h16 ":" ) ls32  /  "::" 5( h16 ":" ) ls32  /  ...  /  [ *6( h16 ":" ) h16 ] "::"
;     h16 = 1*4HEXDIG     ls32 = ( h16 ":" h16 ) / IPv4address
;     IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
;     dec-octet = DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT / "25" %x30-35
;   In words: eight 16-bit pieces without "::"; seven written ones at most with one "::",
;   which stands for one or more zero pieces; an IPv4 tail counts as two pieces and comes
;   last; a dec-octet has no leading zero and is 255 at most. No zone identifier: RFC 6874's
;   "%25" form is not part of HTTP's authority, and RFC 9844 withdrew it from URIs.
;
;   Convention, for a macro expanded where any register may be live: the caller pushes the
;   end (one past the range's last octet), then the cursor (the octet after the "["), and
;   calls. On return [rsp] holds the octet after the "]" when the literal is a valid
;   IPv6address followed by "]", else 0; the caller pops it and drops the end:
;       push end / push cursor / call ha_ipv6_literal / pop cursor / add rsp, 8
;   Every register is kept; the flags are clobbered. Reads [cursor, end) only. A leaf, so the
;   stack's alignment does not matter.
; -----------------------------------------------------------------------------
V6_SAVED    equ 9 * 8                       ; the registers this function saves
V6_CURSOR   equ V6_SAVED + 8                ; the caller's cursor, above them and the return address
V6_END      equ V6_SAVED + 16               ; the caller's end

global ha_ipv6_literal:function hidden (ha_ipv6_literal.end - ha_ipv6_literal)
align 16
ha_ipv6_literal:
    push    rax
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    mov     rsi, [rsp + V6_CURSOR]
    mov     rdi, [rsp + V6_END]
    xor     r8d, r8d                        ; pieces so far
    xor     r9d, r9d                        ; 1 once the "::" was seen
    cmp     rsi, rdi
    jae     .bad
    cmp     byte [rsi], ':'
    jne     .piece
    ; A leading colon starts "::", or nothing valid (":1::" is refused).
    lea     rax, [rsi + 1]
    cmp     rax, rdi
    jae     .bad
    cmp     byte [rax], ':'
    jne     .bad
    mov     r9d, 1
    add     rsi, 2
    cmp     rsi, rdi
    jae     .bad
    cmp     byte [rsi], ']'
    je      .closed                         ; "[::]"

.piece:                                     ; an h16, or an IPv4 tail: [rsi] is its start
    mov     rdx, rsi
    xor     ecx, ecx                        ; its HEXDIG so far
.hexdig:
    cmp     rsi, rdi
    jae     .bad                            ; the range ends without "]"
    movzx   eax, byte [rsi]
    cmp     al, '.'
    je      .ipv4                           ; not an h16 after all: ls32's IPv4address
    mov     r10d, eax
    sub     r10d, '0'
    cmp     r10d, 9
    jbe     .is_hex
    or      eax, 0x20                       ; A-F as a-f; nothing else lands in a-f
    sub     eax, 'a'
    cmp     eax, 'f' - 'a'
    ja      .end_piece
.is_hex:
    inc     ecx
    cmp     ecx, 4
    ja      .bad                            ; five HEXDIG: no h16
    inc     rsi
    jmp     .hexdig
.end_piece:
    test    ecx, ecx
    jz      .bad                            ; an empty piece: ":::", or "1:]"
    inc     r8d
    cmp     r8d, 8
    ja      .bad                            ; a ninth piece
    movzx   eax, byte [rsi]                 ; rsi < rdi: .hexdig checked it
    cmp     al, ']'
    je      .closed
    cmp     al, ':'
    jne     .bad                            ; nothing else may follow an h16
    inc     rsi
    cmp     rsi, rdi
    jae     .bad
    cmp     byte [rsi], ':'
    jne     .piece                          ; one colon: another piece follows
    test    r9d, r9d
    jnz     .bad                            ; a second "::"
    mov     r9d, 1
    inc     rsi
    cmp     rsi, rdi
    jae     .bad
    cmp     byte [rsi], ']'
    je      .closed                         ; "...::]"
    jmp     .piece

.ipv4:                                      ; IPv4address, read again from the piece's start
    mov     rsi, rdx
    xor     r11d, r11d                      ; the dots so far
.octet:
    cmp     rsi, rdi
    jae     .bad
    movzx   eax, byte [rsi]
    sub     eax, '0'
    cmp     eax, 9
    ja      .bad                            ; a dec-octet starts with a DIGIT
    mov     r10d, eax                       ; its value
    inc     rsi
    test    eax, eax
    jz      .octet_end                      ; "0" ends its dec-octet: "01" is refused below
    xor     ecx, ecx                        ; the digits after the first: two at most
.octet_digit:
    cmp     rsi, rdi
    jae     .bad
    movzx   eax, byte [rsi]
    sub     eax, '0'
    cmp     eax, 9
    ja      .octet_end
    inc     ecx
    cmp     ecx, 2
    ja      .bad                            ; four digits
    imul    r10d, r10d, 10
    add     r10d, eax
    inc     rsi
    jmp     .octet_digit
.octet_end:
    cmp     r10d, 255
    ja      .bad
    cmp     rsi, rdi
    jae     .bad
    movzx   eax, byte [rsi]
    cmp     r11d, 3
    je      .ipv4_last
    cmp     al, '.'
    jne     .bad                            ; a dot between dec-octets, a leading zero's digit, ...
    inc     r11d
    inc     rsi
    jmp     .octet
.ipv4_last:
    cmp     al, ']'
    jne     .bad                            ; ls32 is last: the literal ends with it
    add     r8d, 2

.closed:                                    ; [rsi] is the "]"
    test    r9d, r9d
    jnz     .elided
    cmp     r8d, 8
    jne     .bad                            ; without "::", exactly eight pieces
    jmp     .good
.elided:
    cmp     r8d, 7
    ja      .bad                            ; "::" stands for one zero piece at least
.good:
    inc     rsi                             ; past the "]"
    mov     [rsp + V6_CURSOR], rsi
    jmp     .out
.bad:
    mov     qword [rsp + V6_CURSOR], 0
.out:
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rax
    ret
.end:
