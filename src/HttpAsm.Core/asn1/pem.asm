; =============================================================================
; asn1/pem.asm - PEM, the textual encoding of certificates and keys (RFC 7468): the next
; "-----BEGIN <label>-----" ... "-----END <label>-----" block of a text, its base64 (RFC 4648
; section 4) decoded into the caller's buffer.
;
; What is accepted, and why:
;   - The pre-encapsulation boundary (RFC 7468 2, 3): "-----BEGIN ", a label, "-----", at the
;     start of the text or of a line (after CR or LF), so that explanatory text before it
;     (5.2) is skipped and a boundary quoted inside a line is not taken for one. Exactly five
;     hyphen-minuses on either side, no more (2). The label: printable characters but "-",
;     with single hyphen-minuses or spaces between them, never at its ends (2, the ABNF's label).
;   - The base64 text: RFC 7468's lax form (Figure 2): whitespace (SP, HT, CR, LF, VT, FF)
;     anywhere in it, then up to two "=" pads with whitespace between and after. Any other
;     character refuses the block. RFC 7468 2 says parsers SHOULD ignore "other non-base64
;     characters" too; this one does not, as OpenSSL, BoringSSL, Go and .NET do not: a text
;     whose characters a parser drops is ambiguous (its section 14), and a key file with stray
;     characters is a damaged one.
;   - The post-encapsulation boundary: "-----END ", the same label (2 lets a parser disregard
;     a mismatch; this one refuses it, as some extant parsers do), "-----", directly after the
;     base64 text and its whitespace (Figure 2: no line break is required before it).
;   - The decoding: four characters to three octets; a final quantum of two or three
;     characters with or without its pads (both of RFC 7468's figures allow the pads to be
;     absent), but with them, the right number; one character alone is no quantum; the final
;     quantum's pad bits must be zero (RFC 4648 3.5 lets a decoder require it: an encoding
;     that changes without changing the octets is malleable).
;
; Constant time: a private key's PEM text is its secret. Each character's class (a base64
; character, whitespace, a pad, the hyphen-minus that starts the END line, or another) steers
; the decoder, and is public by design: the positions of whitespace are the file's layout and
; where the base64 text ends is its length. The character's value, its six bits, never steers
; anything: it is computed with masks and shifted into the output. The ConstantTime build marks
; each class public at its computation (HA_DECLASSIFY), so tests/ct/run.sh checks the rest.
; =============================================================================
default rel
%include "httpasm_core.inc"

; The classes of a character of the base64 text (pem_class).
PC_OTHER        equ 0                       ; refuses the block
PC_BASE64       equ 1
PC_SPACE        equ 2                       ; RFC 7468's W
PC_PAD          equ 3                       ; "="
PC_DASH         equ 4                       ; "-": where the END line starts

; PEM_CLASS c, value: ecx = the class of the character in c (a 32-bit register holding an octet,
; kept), edx = its six bits when it is a base64 character (0 otherwise), computed with masks
; only: no branch and no address depends on c. Clobbers eax and the flags.
%macro PEM_CLASS 1
    ; A-Z: c - 65; a-z: c - 71; 0-9: c + 4; "+": 62; "/": 63 (RFC 4648's Table 1)
    lea     eax, [%1 - 'A']
    cmp     eax, 26
    sbb     ecx, ecx                        ; all ones for A-Z
    and     eax, ecx
    mov     edx, eax                        ; the value so far
    mov     r11d, ecx                       ; the base64 mask so far
    lea     eax, [%1 - 'a']
    cmp     eax, 26
    sbb     ecx, ecx
    add     eax, 26                         ; c - 71
    and     eax, ecx
    or      edx, eax
    or      r11d, ecx
    lea     eax, [%1 - '0']
    cmp     eax, 10
    sbb     ecx, ecx
    add     eax, 52                         ; c + 4
    and     eax, ecx
    or      edx, eax
    or      r11d, ecx
    mov     eax, %1
    xor     eax, '+'
    sub     eax, 1
    sbb     ecx, ecx                        ; all ones for "+"
    mov     eax, ecx
    and     eax, 62
    or      edx, eax
    or      r11d, ecx
    mov     eax, %1
    xor     eax, '/'
    sub     eax, 1
    sbb     ecx, ecx                        ; all ones for "/"
    mov     eax, ecx
    and     eax, 63
    or      edx, eax
    or      r11d, ecx
    and     r11d, PC_BASE64                 ; the class: the masks are exclusive, so ORed
    ; whitespace: SP, or HT LF VT FF CR (0x09-0x0D)
    mov     eax, %1
    xor     eax, ' '
    sub     eax, 1
    sbb     ecx, ecx
    and     ecx, PC_SPACE
    or      r11d, ecx
    lea     eax, [%1 - 9]
    cmp     eax, 5
    sbb     ecx, ecx
    and     ecx, PC_SPACE
    or      r11d, ecx
    mov     eax, %1
    xor     eax, '='
    sub     eax, 1
    sbb     ecx, ecx
    and     ecx, PC_PAD
    or      r11d, ecx
    mov     eax, %1
    xor     eax, '-'
    sub     eax, 1
    sbb     ecx, ecx
    and     ecx, PC_DASH
    or      ecx, r11d
%endmacro

section .rodata
pem_begin:      db "-----BEGIN "                ; 11 octets
pem_end:        db "-----END "                  ; 9 octets

section .text

; -----------------------------------------------------------------------------
; int httpasm_pem_read(httpasm_pem *block, const uint8_t *text, size_t length, uint8_t *der,
;                      size_t capacity)
;   The first PEM block of text[0..length) whose BEGIN line starts the text or a line: see the
;   header above for the rules. On 0, block holds the label (a pointer into text), the octets
;   decoded into der and the text's offset just past the END boundary (where the next block's
;   search starts). Returns 0; 1 when the text holds no BEGIN line at a line's start (the end of
;   a file of blocks); -1 when the block found is malformed; -2 when its octets do not fit
;   capacity (block->der_length is then the room it needs, and der is untouched). Nothing past
;   text + length is read, nothing past der + capacity written, and der is written only once
;   the whole block has been checked.
;   Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
PF_CAPACITY     equ 0
PF_LABEL        equ 8                       ; the label's offset in the text
PF_LABEL_LENGTH equ 16
PF_BODY         equ 24                      ; the base64 text's offset
PF_SIZE         equ 40                      ; (6 pushes + 40: rsp 16-aligned)

global httpasm_pem_read:function (httpasm_pem_read.end - httpasm_pem_read)
align 16
httpasm_pem_read:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, PF_SIZE
    mov     r12, rdi                        ; block
    mov     r13, rsi                        ; text
    mov     r14, rdx                        ; length
    mov     r15, rcx                        ; der
    mov     [rsp + PF_CAPACITY], r8

    ; ---- the BEGIN line, at the text's start or a line's
    xor     ebx, ebx                        ; the offset tried
.find:
    lea     rax, [rbx + 11]
    cmp     rax, r14
    ja      .none
    test    rbx, rbx
    jz      .find_here
    movzx   eax, byte [r13 + rbx - 1]
    cmp     eax, 10                         ; LF
    je      .find_here
    cmp     eax, 13                         ; CR
    jne     .find_next
.find_here:
    mov     rax, [r13 + rbx]                ; "-----BEGIN ": eight octets, then three
    cmp     rax, [rel pem_begin]
    jne     .find_next
    movzx   eax, word [r13 + rbx + 8]
    cmp     ax, [rel pem_begin + 8]
    jne     .find_next
    cmp     byte [r13 + rbx + 10], ' '
    je      .label
.find_next:
    inc     rbx
    jmp     .find

    ; ---- the label: labelchar *( ["-" / SP] labelchar ), then exactly five "-"
.label:
    add     rbx, 11
    mov     [rsp + PF_LABEL], rbx
    mov     rbp, rbx                        ; the cursor
.label_char:
    cmp     rbp, r14
    jae     .bad
    movzx   eax, byte [r13 + rbp]
    cmp     eax, '-'
    je      .label_hyphen
    cmp     eax, ' '
    je      .label_separator
    cmp     eax, 0x21                       ; labelchar: %x21-2C / %x2E-7E ("-" handled above)
    jb      .bad
    cmp     eax, 0x7E
    ja      .bad
    inc     rbp
    jmp     .label_char
.label_hyphen:
    lea     rax, [rbp + 5]                  ; the closing "-----"?
    cmp     rax, r14
    ja      .label_separator
    cmp     dword [r13 + rbp], '----'
    jne     .label_separator
    cmp     byte [r13 + rbp + 4], '-'
    je      .label_done
.label_separator:                           ; a single "-" or SP: a labelchar on either side
    cmp     rbp, rbx
    je      .bad                            ; at the label's start
    ; (the octet before is a labelchar: a separator there would have refused this octet, which
    ; is no labelchar, as the one after it)
    lea     rax, [rbp + 1]
    cmp     rax, r14
    jae     .bad
    movzx   eax, byte [r13 + rbp + 1]
    cmp     eax, '-'
    je      .bad                            ; (two hyphen-minuses that are not the closing five)
    cmp     eax, ' '
    je      .bad
    cmp     eax, 0x21
    jb      .bad
    cmp     eax, 0x7E
    ja      .bad
    inc     rbp
    jmp     .label_char
.label_done:
    mov     rax, rbp
    sub     rax, rbx
    mov     [rsp + PF_LABEL_LENGTH], rax
    add     rbp, 5
    cmp     rbp, r14
    jae     .bad                            ; nothing after the BEGIN line: no END
    cmp     byte [r13 + rbp], '-'
    jne     .body
    ; A "-" right after the five: a sixth one (exactly five, RFC 7468 2), unless it starts the
    ; END line of an empty base64 text, which Figure 2 allows without a line break between.
    lea     rax, [rbp + 9]
    cmp     rax, r14
    ja      .bad
    mov     rax, [r13 + rbp]
    cmp     rax, [rel pem_end]
    jne     .bad
    cmp     byte [r13 + rbp + 8], ' '
    jne     .bad
.body:
    mov     [rsp + PF_BODY], rbp

    ; ---- pass 1: the base64 text's classes, to its END line; counts, pads, the pad bits
    xor     r8d, r8d                        ; base64 characters
    xor     r9d, r9d                        ; pads
    xor     r10d, r10d                      ; the last base64 character's value
.scan:
    cmp     rbp, r14
    jae     .bad                            ; no END line
    movzx   esi, byte [r13 + rbp]
    PEM_CLASS esi
    HA_DECLASSIFY rcx                       ; (public by design: the text's layout and length)
    inc     rbp
    cmp     ecx, PC_BASE64
    jne     .scan_other
    test    r9d, r9d
    jnz     .bad                            ; a base64 character after a pad
    inc     r8
    mov     r10d, edx
    jmp     .scan
.scan_other:
    cmp     ecx, PC_SPACE
    je      .scan
    cmp     ecx, PC_PAD
    jne     .scan_end
    inc     r9d
    cmp     r9d, 2
    ja      .bad                            ; two pads at most
    jmp     .scan
.scan_end:
    cmp     ecx, PC_DASH
    jne     .bad                            ; another character
    dec     rbp                             ; the END line starts at the "-"

    ; ---- the END line: "-----END ", the same label, exactly five "-"
    mov     rax, [rsp + PF_LABEL_LENGTH]
    lea     rax, [rbp + rax + 14]           ; "-----END " (9), the label, "-----" (5)
    cmp     rax, r14
    ja      .bad
    mov     rax, [r13 + rbp]                ; "-----END": eight octets, then the space
    cmp     rax, [rel pem_end]
    jne     .bad
    cmp     byte [r13 + rbp + 8], ' '
    jne     .bad
    mov     rcx, [rsp + PF_LABEL_LENGTH]
    mov     rsi, [rsp + PF_LABEL]
    add     rsi, r13
    lea     rdi, [r13 + rbp + 9]
    test    rcx, rcx                        ; an empty label: nothing to compare (and repe with
    jz      .labels_equal                   ; rcx 0 would leave the add's flags for jne to read)
    repe    cmpsb                           ; (public: the labels)
    jne     .bad
.labels_equal:
    cmp     dword [rdi], '----'
    jne     .bad
    cmp     byte [rdi + 4], '-'
    jne     .bad
    lea     rax, [rdi + 5]
    sub     rax, r13                        ; the offset past the END boundary
    cmp     rax, r14
    jae     .end_found
    cmp     byte [r13 + rax], '-'
    jne     .end_found
    ; A "-" right after the five: a sixth one, unless the next block's BEGIN follows at once
    ; (which the next call, starting at this block's end, finds at its text's start).
    lea     rcx, [rax + 11]
    cmp     rcx, r14
    ja      .bad
    mov     rcx, [r13 + rax]
    cmp     rcx, [rel pem_begin]
    jne     .bad
    movzx   ecx, word [r13 + rax + 8]
    cmp     cx, [rel pem_begin + 8]
    jne     .bad
    cmp     byte [r13 + rax + 10], ' '
    jne     .bad
.end_found:
    mov     [r12 + httpasm_pem.end], rax

    ; ---- the counts: whole quanta, then 2 or 3 characters; the pads, if any, make it 4
    mov     eax, r8d
    and     eax, 3
    cmp     eax, 1
    je      .bad                            ; one character is no quantum
    test    r9d, r9d
    jz      .counted
    lea     ecx, [rax + r9]
    cmp     ecx, 4
    jne     .bad                            ; the wrong number of pads
.counted:
    ; the final quantum's pad bits zero (2 characters: 4 bits, 3: 2 bits); the value is a
    ; secret, so the verdict is computed without a branch on it
    xor     ecx, ecx
    cmp     eax, 2
    jne     .pad_three
    mov     ecx, r10d
    and     ecx, 0x0F
    jmp     .pad_verdict
.pad_three:
    cmp     eax, 3
    jne     .pad_verdict
    mov     ecx, r10d
    and     ecx, 0x03
.pad_verdict:
    neg     ecx
    sbb     ecx, ecx
    HA_DECLASSIFY rcx                       ; (public by design: a malformed text is refused)
    test    ecx, ecx
    jnz     .bad
    ; the octets: 3 per quantum, and 1 or 2 for a final 2 or 3 characters
    mov     rcx, r8
    shr     rcx, 2
    lea     rcx, [rcx + rcx * 2]
    lea     edx, [rax - 1]
    test    eax, eax
    cmovz   edx, eax                        ; 0 -> 0, 2 -> 1, 3 -> 2
    add     rcx, rdx
    mov     [r12 + httpasm_pem.der_length], rcx
    cmp     rcx, [rsp + PF_CAPACITY]
    ja      .small

    ; ---- pass 2: the six bits of each base64 character, shifted into the octets
    mov     rsi, [rsp + PF_BODY]            ; the cursor (rbp: the END line)
    xor     r8d, r8d                        ; the bits so far
    xor     r9d, r9d                        ; characters so far in the quantum
    mov     rdi, r15                        ; out
.decode:
    cmp     rsi, rbp
    jae     .decoded
    movzx   r10d, byte [r13 + rsi]
    inc     rsi
    PEM_CLASS r10d
    HA_DECLASSIFY rcx                       ; (public by design: the text's layout and length)
    cmp     ecx, PC_BASE64
    jne     .decode                         ; whitespace or a pad (pass 1 allowed nothing else)
    shl     r8d, 6
    or      r8d, edx
    inc     r9d
    cmp     r9d, 4
    jne     .decode
    mov     eax, r8d
    shr     eax, 16
    mov     [rdi], al
    mov     eax, r8d
    shr     eax, 8
    mov     [rdi + 1], al
    mov     [rdi + 2], r8b
    add     rdi, 3
    xor     r8d, r8d
    xor     r9d, r9d
    jmp     .decode
.decoded:
    cmp     r9d, 2
    jb      .filled
    je      .two
    mov     eax, r8d                        ; three characters: 18 bits, 2 octets
    shr     eax, 10
    mov     [rdi], al
    mov     eax, r8d
    shr     eax, 2
    mov     [rdi + 1], al
    jmp     .filled
.two:
    shr     r8d, 4                          ; two characters: 12 bits, 1 octet
    mov     [rdi], r8b
.filled:
    xor     r8d, r8d                        ; no secret bits left in a register
    xor     r10d, r10d
    mov     rax, [rsp + PF_LABEL]
    add     rax, r13
    mov     [r12 + httpasm_pem.label], rax
    mov     rax, [rsp + PF_LABEL_LENGTH]
    mov     [r12 + httpasm_pem.label_length], rax
    xor     eax, eax
.done:
    add     rsp, PF_SIZE
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.none:
    mov     eax, 1
    jmp     .done
.small:
    mov     eax, -2
    jmp     .done
.bad:
    xor     r10d, r10d
    mov     eax, -1
    jmp     .done
.end:
