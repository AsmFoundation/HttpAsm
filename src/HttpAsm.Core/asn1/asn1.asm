; =============================================================================
; asn1/asn1.asm - ASN.1's encodings (ITU-T X.690): a reader of the Basic Encoding Rules and of
; their strict profile, the Distinguished Encoding Rules, one element at a time and in place.
;
; Who reads what: certificates are DER (RFC 5280 signs the DER of their contents, and a TLS
; peer's certificate is read as DER); private keys may be BER (RFC 5958 2: "receivers MUST
; support BER"). Both go through this one reader, so every rule is written once:
;   - the identifier octets (8.1.2): the class, the form, the number in the low form or, for 31
;     and above only, the high form, whose first subsequent octet may not be 0x80; numbers up to
;     2^28 - 1 (four subsequent octets: no ASN.1 module uses more);
;   - the length octets (8.1.3): the short form, the long form (never 0xFF), or BER's
;     indefinite form for a constructed encoding, whose end-of-contents octets (8.1.5) the
;     reader finds by reading the nested elements; DER takes the definite form in the fewest
;     octets (10.1);
;   - the contents within the input, and for each universal type the library reads, its own
;     rules: BOOLEAN (8.2; DER 11.1), INTEGER and ENUMERATED (8.3, 8.4), BIT STRING (8.6; DER
;     11.2.1), OCTET STRING (8.7), NULL (8.8), OBJECT IDENTIFIER (8.19), SEQUENCE and SET
;     constructed (8.9 to 8.12), the restricted character strings' characters (8.23), UTCTime's
;     and GeneralizedTime's DER forms (11.7, 11.8), and BER's constructed strings segment by
;     segment (8.6.4, 8.7.3, 8.23.3), which DER refuses (10.2); under BER, the times' forms
;     X.680 allows (seconds optional, differentials, GeneralizedTime's local time and
;     fractions of any unit), a constructed time's gathered from its segments first (64
;     characters at most, a limit no real time reaches).
; A universal type the library does not read (REAL, EXTERNAL, EMBEDDED PDV, ObjectDescriptor,
; the relative and internationalized object identifiers, the TIME types, CHARACTER STRING, and
; the unassigned numbers) is refused rather than passed through: an encoding the reader cannot
; check is not one it may call valid.
;
; Nothing is copied or allocated: an element's contents point into the caller's octets, and no
; octet past the input is read. The reader follows nesting itself only to find an indefinite
; length's end and to check BER's segments, HA_ASN1_DEPTH levels at most (a deeper encoding
; is refused; each level takes under 100 octets of stack, so 32 levels stay under 4 KiB). The
; caller walks every other nesting, element by element, with httpasm_asn1_read.
;
; Linear time: a read visits each nested element's header once, and each segment of a string
; once per walk of it (its type check, and a gather). A constructed string with an indefinite
; length is never walked to find its end and then walked again to check it: its segment walk
; (ha_asn1_segments) finds the end as it checks, and a segment's own indefinite length is left
; to the walk into it (AR_HEAD, AF_UNENDED). The first version walked first and checked after,
; each walk re-reading every deeper level whole, which doubled the work at each level of nested
; indefinite segments: 26 levels of "23 80" (107 octets) took 1.1 s, 31 levels would take 36
; s (found by tests/fuzz/asn1.c, 2026-11-28; Asn1Tests.ReadsDeepSegmentsInLinearTime).
;
; Constant time: private keys are read with this reader, so their octets may be secrets. Only an
; INTEGER's or an OCTET STRING's contents may hold one (a key's numbers, its seed or its scalar):
; an INTEGER's first two octets give 8.3.2's verdict without a branch, and an OCTET STRING's are
; never looked at. Everything else is public by design: the identifier and length octets are the
; encoding's structure (the file's own length tells as much), and the contents of the other
; types a key holds are its algorithm's identifiers, its version, its public key, its
; attributes. The ConstantTime build marks those public where the reader loads them
; (HA_DECLASSIFY, HA_DECLASSIFY_MEM), so tests/ct/run.sh checks everything else.
; =============================================================================
default rel
%include "httpasm_core.inc"

HA_ASN1_DEPTH   equ 32                      ; nesting levels the reader follows itself
; Rules flag (internal, the segment walks'): the identifier and length octets only. No type
; rules, and an indefinite length is not walked: the element comes back AF_UNENDED, for the walk
; that reads it as segments to end (finding its end-of-contents as it checks or gathers).
AR_HEAD         equ 0x100
; httpasm_asn1.flags (internal): an indefinite length whose end is not found yet. content_length
; is then the octets left in the input after the header (a bound, not the contents), length the
; header's octets alone. The walk that ends it (ha_asn1_segments, ha_asn1_gather) sets
; content_length to the contents', adds them and the two end-of-contents octets to length and
; clears the flag. Only the reader's own frames hold such an element: httpasm_asn1_read never
; returns one, and the functions that take an element refuse a flags value it never returns.
AF_UNENDED      equ 2

; The kinds of universal type (asn1_kinds): how each number is checked.
K_BAD           equ 0                       ; refused: EOC, types the library does not read
K_BOOLEAN       equ 1
K_INTEGER       equ 2                       ; INTEGER and ENUMERATED
K_BITS          equ 3
K_OCTETS        equ 4
K_NULL          equ 5
K_OID           equ 6
K_CONSTRUCTED   equ 7                       ; SEQUENCE, SET
K_STRING        equ 8                       ; the restricted character strings and the times

; The character sets (asn1_charsets), and the state of their check across BER's segments.
CK_ANY          equ 0                       ; ISO 2022's (T61, Videotex, Graphic, General): opaque
CK_PRINTABLE    equ 1                       ; X.680 41.4's table
CK_NUMERIC      equ 2                       ; digits and space
CK_IA5          equ 3                       ; 0x00-0x7F
CK_VISIBLE      equ 4                       ; 0x20-0x7E (VisibleString, and the times' characters)
CK_UTF8         equ 5                       ; ISO 10646 Annex D, each character in the fewest octets
CK_BMP          equ 6                       ; two octets a character, no surrogate
CK_UNIVERSAL    equ 7                       ; four octets a character, U+10FFFF at most, no surrogate

CS_KIND         equ 0                       ; CK_*
CS_NEED         equ 4                       ; octets a character still needs (0: none pending)
CS_LO           equ 8                       ; UTF-8: the next octet's least value
CS_HI           equ 12                      ; and greatest
CS_ACC          equ 16                      ; UniversalString: the character's octets so far
CS_UNUSED       equ 20                      ; BIT STRING's segments: the last one's unused bits
CS_SIZE         equ 24

; TWO_DIGITS dst, address: the number two decimal digits at address spell (already checked to
; be digits). dst is a 32-bit register other than r8d, which the macro clobbers; address is an
; effective address that does not use r8. Keeps the flags' meaning undefined.
%macro TWO_DIGITS 2
    movzx   %1, byte [%2]
    movzx   r8d, byte [%2 + 1]
    lea     %1, [%1 + %1 * 4]
    lea     %1, [r8d + %1 * 2 - 528]        ; d0 * 10 + d1, less '0' * 11
%endmacro

section .rodata
; The kind of each universal type number, 0 to 30 (above 30: refused).
asn1_kinds:
    db K_BAD, K_BOOLEAN, K_INTEGER, K_BITS, K_OCTETS, K_NULL, K_OID, K_BAD       ; 0-7
    db K_BAD, K_BAD, K_INTEGER, K_BAD, K_STRING, K_BAD, K_BAD, K_BAD             ; 8-15
    db K_CONSTRUCTED, K_CONSTRUCTED, K_STRING, K_STRING, K_STRING, K_STRING      ; 16-21
    db K_STRING, K_STRING, K_STRING, K_STRING, K_STRING, K_STRING, K_STRING      ; 22-28
    db K_BAD, K_STRING                                                            ; 29-30
; The character set of each string type number (0 where the kind is not K_STRING).
asn1_charsets:
    db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, CK_UTF8, 0, 0, 0                      ; 0-15
    db 0, 0, CK_NUMERIC, CK_PRINTABLE, CK_ANY, CK_ANY, CK_IA5, CK_VISIBLE        ; 16-23
    db CK_VISIBLE, CK_ANY, CK_VISIBLE, CK_ANY, CK_UNIVERSAL, 0, CK_BMP           ; 24-30
align 8
; The single-octet sets, 128 bits each (octets 0-63, then 64-127), for CK_PRINTABLE .. CK_VISIBLE.
asn1_sets:
    dq 0xA7FFFB8100000000, 0x07FFFFFE07FFFFFE   ; Printable: SP ' ( ) + , - . / 0-9 : = ? A-Z a-z
    dq 0x03FF000100000000, 0                    ; Numeric: SP 0-9
    dq -1, -1                                   ; IA5: 0x00-0x7F
    dq 0xFFFFFFFF00000000, 0x7FFFFFFFFFFFFFFF   ; Visible: 0x20-0x7E
; Days in each month, January first (February's leap day added by the time check).
asn1_days:
    db 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31

section .text

; -----------------------------------------------------------------------------
; int httpasm_asn1_read(httpasm_asn1 *element, const uint8_t *in, size_t length, int rules)
;   The first element of in[0..length) under the rules (HTTPASM_ASN1_DER or _BER): see the
;   header above for what is checked. The octets after the element are the caller's (the next
;   element of a sequence, say): element->length tells where it ends.
;   Returns eax = 0, or -1 (an unknown rules value included); on -1 element's fields are
;   unspecified. Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_asn1_read:function (httpasm_asn1_read.end - httpasm_asn1_read)
align 16
httpasm_asn1_read:
    cmp     ecx, HTTPASM_ASN1_BER
    ja      .bad                            ; not DER's or BER's (the internal flag neither)
    mov     r8d, HA_ASN1_DEPTH
    jmp     ha_asn1_read
.bad:
    mov     eax, -1
    ret
.end:

; -----------------------------------------------------------------------------
; ha_asn1_read: rdi = the element to fill, rsi = in, rdx = length, ecx = the rules
;   (HTTPASM_ASN1_BER's bit, and AR_HEAD for the header alone: the segment walks check and end
;   segments their own way), r8d = the nesting levels it may still follow (indefinite lengths,
;   segments) -> eax = 0, or -1. An indefinite length is found two ways: a universal
;   constructed string's by its type check's segment walk (one pass, which checks as it goes),
;   any other element's by reading each nested element whole until the end-of-contents octets.
;   Recursive through the indefinite walk and ha_asn1_type; each level takes AF_SIZE + 56
;   octets of stack. Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
AF_NESTED       equ 0                       ; httpasm_asn1: the indefinite walk's nested element
AF_TAG          equ 32                      ; the tag, until the element is filled
AF_START        equ 40                      ; the contents' offset in the input
AF_SIZE         equ 56                      ; (keeps rsp 16-aligned at calls: 6 pushes + 56)

global ha_asn1_read:function hidden (ha_asn1_read.end - ha_asn1_read)
align 16
ha_asn1_read:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, AF_SIZE
    mov     r12, rdi                        ; the element
    mov     r13, rsi                        ; in
    mov     r14, rdx                        ; length
    mov     r15d, ecx                       ; the rules
    mov     ebx, r8d                        ; the depth left
    cmp     r14, 2                          ; an identifier and a length octet at least
    jb      .bad

    ; ---- the identifier octets (8.1.2)
    movzx   eax, byte [r13]
    HA_DECLASSIFY rax                       ; (public by design: the encoding's structure)
    mov     ecx, eax
    and     ecx, 0xE0                       ; the class (bits 8-7) and the form (bit 6)
    shl     ecx, 24
    and     eax, 0x1F
    mov     ebp, 1                          ; the offset of the next octet
    cmp     eax, 0x1F
    jne     .tagged                         ; 8.1.2.2: numbers 0 to 30 in the one octet
    ; 8.1.2.4: the high form, 7 bits an octet, bit 8 set on all but the last
    xor     eax, eax                        ; the number
    xor     edx, edx                        ; subsequent octets so far
.high:
    cmp     rbp, r14
    jae     .bad
    movzx   r8d, byte [r13 + rbp]
    HA_DECLASSIFY r8                        ; (public by design: the encoding's structure)
    inc     rbp
    test    edx, edx
    jnz     .high_kept
    cmp     r8d, 0x80                       ; 8.1.2.4.2 c: the first's bits 7 to 1 not all zero
    je      .bad
.high_kept:
    inc     edx
    cmp     edx, 4                          ; numbers up to 2^28 - 1
    ja      .bad
    shl     eax, 7
    mov     r9d, r8d
    and     r9d, 0x7F
    or      eax, r9d
    test    r8d, 0x80
    jnz     .high
    cmp     eax, 31                         ; 8.1.2.2: 0 to 30 take the one-octet form
    jb      .bad
.tagged:
    or      ecx, eax
    mov     [rsp + AF_TAG], ecx

    ; ---- the length octets (8.1.3)
    cmp     rbp, r14
    jae     .bad
    movzx   eax, byte [r13 + rbp]
    HA_DECLASSIFY rax                       ; (public by design: the encoding's structure)
    inc     rbp
    cmp     eax, 0x80
    jb      .short                          ; 8.1.3.4
    je      .indefinite                     ; 8.1.3.6
    cmp     eax, 0xFF                       ; 8.1.3.5 c
    je      .bad
    and     eax, 0x7F                       ; 8.1.3.5 b: the subsequent octets
    mov     rdx, r14
    sub     rdx, rbp
    cmp     rax, rdx
    ja      .bad
    xor     r9d, r9d                        ; the length
    xor     r10d, r10d                      ; subsequent octets read
.long:
    movzx   edx, byte [r13 + rbp]
    HA_DECLASSIFY rdx                       ; (public by design: the encoding's structure)
    inc     rbp
    test    r10d, r10d
    jnz     .long_kept
    test    edx, edx                        ; a leading zero octet: more octets than needed,
    jnz     .long_kept                      ; a sender's option in BER (8.1.3.5 NOTE 2), not
    test    r15d, HTTPASM_ASN1_BER          ; in DER (10.1)
    jz      .bad
.long_kept:
    inc     r10d
    mov     r8, r9
    shr     r8, 56
    jnz     .bad                            ; past 2^64 - 1: no input is that long
    shl     r9, 8
    or      r9, rdx
    cmp     r10d, eax
    jb      .long
    test    r15d, HTTPASM_ASN1_BER
    jnz     .definite
    cmp     r9, 128                         ; DER (10.1): below 128, the short form
    jb      .bad
    jmp     .definite
.short:
    mov     r9d, eax
.definite:
    mov     rax, r14
    sub     rax, rbp
    cmp     r9, rax                         ; the contents within the input
    ja      .bad
    lea     rax, [r13 + rbp]
    mov     [r12 + httpasm_asn1.content], rax
    mov     [r12 + httpasm_asn1.content_length], r9
    add     r9, rbp
    mov     [r12 + httpasm_asn1.length], r9
    mov     dword [r12 + httpasm_asn1.flags], 0
    jmp     .typed

.indefinite:
    test    r15d, HTTPASM_ASN1_BER          ; DER (10.1): the definite form only
    jz      .bad
    test    dword [rsp + AF_TAG], HTTPASM_ASN1_CONSTRUCTED
    jz      .bad                            ; 8.1.3.2 a: a primitive encoding is definite
    test    ebx, ebx
    jz      .bad                            ; nested deeper than the reader follows
    ; A segment walk's read (AR_HEAD), and a universal constructed string's: its end is left to
    ; the segment walk, which checks the segments as it finds it. Walking it here first would
    ; read every segment whole and the walk read them again, each level doubling the work.
    test    r15d, AR_HEAD
    jnz     .unended
    mov     eax, [rsp + AF_TAG]
    test    eax, HTTPASM_ASN1_CLASS
    jnz     .walk_start                     ; another class: walked (its type is the caller's)
    and     eax, HTTPASM_ASN1_NUMBER
    cmp     eax, 30
    ja      .walk_start                     ; (refused by the type check, after the walk)
    lea     rcx, [rel asn1_kinds]
    movzx   eax, byte [rcx + rax]
    cmp     eax, K_BITS
    je      .unended
    cmp     eax, K_OCTETS
    je      .unended
    cmp     eax, K_STRING
    je      .unended
.walk_start:
    mov     [rsp + AF_START], rbp
    ; The contents run to the end-of-contents octets (8.1.5) at this level: every nested
    ; element is read whole (an indefinite one finds its own end the same way), until two zero
    ; octets stand where the next one would start.
.walk:
    mov     rax, r14
    sub     rax, rbp                        ; octets left
    cmp     rax, 2
    jb      .bad                            ; 8.1.3.6.2: the end-of-contents octets must follow
    movzx   ecx, word [r13 + rbp]
    HA_DECLASSIFY rcx                       ; (public by design: the encoding's structure)
    test    ecx, ecx
    jz      .ended
    lea     rdi, [rsp + AF_NESTED]
    lea     rsi, [r13 + rbp]
    mov     rdx, rax
    mov     ecx, r15d
    and     ecx, HTTPASM_ASN1_BER           ; a nested element is checked whole (never raw)
    lea     r8d, [rbx - 1]
    call    ha_asn1_read
    test    eax, eax
    jnz     .bad
    add     rbp, [rsp + AF_NESTED + httpasm_asn1.length]
    jmp     .walk
.ended:
    mov     rdx, [rsp + AF_START]
    lea     rax, [r13 + rdx]
    mov     [r12 + httpasm_asn1.content], rax
    mov     rax, rbp
    sub     rax, rdx
    mov     [r12 + httpasm_asn1.content_length], rax
    lea     rax, [rbp + 2]
    mov     [r12 + httpasm_asn1.length], rax
    mov     dword [r12 + httpasm_asn1.flags], HTTPASM_ASN1_INDEFINITE

.typed:
    mov     ecx, [rsp + AF_TAG]
    mov     [r12 + httpasm_asn1.tag], ecx
    test    r15d, AR_HEAD
    jnz     .good                           ; the header alone: the segment walk checks it
    test    ecx, HTTPASM_ASN1_CLASS
    jnz     .good                           ; another class: its type is the caller's to know
    and     ecx, HTTPASM_ASN1_NUMBER
    mov     rdi, r12
    mov     esi, ecx
    mov     edx, r15d
    mov     ecx, ebx
    call    ha_asn1_type
    jmp     .done

    ; ---- an indefinite length whose end a segment walk finds (AF_UNENDED's definition)
.unended:
    lea     rax, [r13 + rbp]
    mov     [r12 + httpasm_asn1.content], rax
    mov     rax, r14
    sub     rax, rbp
    mov     [r12 + httpasm_asn1.content_length], rax    ; the octets left: a bound for now
    mov     [r12 + httpasm_asn1.length], rbp            ; the header's octets, for now
    mov     dword [r12 + httpasm_asn1.flags], HTTPASM_ASN1_INDEFINITE | AF_UNENDED
    mov     ecx, [rsp + AF_TAG]
    mov     [r12 + httpasm_asn1.tag], ecx
    test    r15d, AR_HEAD
    jnz     .good                           ; a segment: the walk reading it ends it
    ; A universal constructed string (K_BITS, K_OCTETS, K_STRING under BER): its type check
    ; always walks its segments (ha_asn1_type's .segments), which ends it or refuses it, so it
    ; never leaves here AF_UNENDED.
    and     ecx, HTTPASM_ASN1_NUMBER
    mov     rdi, r12
    mov     esi, ecx
    mov     edx, r15d
    mov     ecx, ebx
    call    ha_asn1_type
    jmp     .done
.good:
    xor     eax, eax
.done:
    add     rsp, AF_SIZE
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.bad:
    mov     eax, -1
    jmp     .done
.end:

; -----------------------------------------------------------------------------
; int httpasm_asn1_check(const httpasm_asn1 *element, uint32_t type, int rules)
;   The rules of universal type `type` (HTTPASM_ASN1_INTEGER, ...; SEQUENCE's and SET's form
;   bit may be in it) applied to an element httpasm_asn1_read returned under another tag: an
;   IMPLICIT one, such as RFC 5958's publicKey [1] (a BIT STRING). The element keeps its own
;   form (8.14.4 a: implicit tagging does not change it) and its own segments' tags (universal,
;   8.6.4.1 NOTE 2). Returns 0, or -1 (a type the reader does not check, a class other than
;   universal in `type`, and an element whose flags httpasm_asn1_read never returns, any bit
;   but HTTPASM_ASN1_INDEFINITE, included). Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_asn1_check:function (httpasm_asn1_check.end - httpasm_asn1_check)
align 16
httpasm_asn1_check:
    cmp     edx, HTTPASM_ASN1_BER
    ja      .bad
    test    esi, HTTPASM_ASN1_CLASS
    jnz     .bad                            ; a universal type's number, nothing else
    ; A flags value httpasm_asn1_read never returns: AF_UNENDED would make the segment walk
    ; take content_length for a bound and write the caller's (const) element.
    test    dword [rdi + httpasm_asn1.flags], ~HTTPASM_ASN1_INDEFINITE
    jnz     .bad
    and     esi, HTTPASM_ASN1_NUMBER
    mov     ecx, HA_ASN1_DEPTH
    jmp     ha_asn1_type
.bad:
    mov     eax, -1
    ret
.end:

; -----------------------------------------------------------------------------
; ha_asn1_type: rdi = an element, esi = a universal type's number, edx = the rules (BER's bit),
;   ecx = the nesting levels left -> eax = 0 when the element's form and contents follow that
;   type's rules, else -1. Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
TF_STATE        equ 0                       ; the character check's state (CS_*)
TF_TIME         equ 32                      ; a BER constructed time's characters, gathered
TF_TIME_SIZE    equ 64                      ; their room: longer ones are refused (the header)
TF_SIZE         equ 104                     ; (4 pushes + 104: rsp 16-aligned at calls)

global ha_asn1_type:function hidden (ha_asn1_type.end - ha_asn1_type)
align 16
ha_asn1_type:
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, TF_SIZE
    mov     r12, rdi                        ; the element
    mov     ebx, esi                        ; the type's number
    mov     r13d, edx                       ; the rules
    mov     r14d, ecx                       ; the depth left
    cmp     ebx, 30
    ja      .bad
    lea     rax, [rel asn1_kinds]
    movzx   eax, byte [rax + rbx]
    cmp     eax, K_INTEGER
    je      .integer
    cmp     eax, K_CONSTRUCTED
    je      .constructed
    cmp     eax, K_STRING
    je      .string
    cmp     eax, K_OCTETS
    je      .octets
    cmp     eax, K_OID
    je      .oid
    cmp     eax, K_BITS
    je      .bits
    cmp     eax, K_NULL
    je      .null
    cmp     eax, K_BOOLEAN
    je      .boolean
    jmp     .bad                            ; K_BAD

.boolean:                                   ; 8.2.1: primitive, one octet
    test    dword [r12 + httpasm_asn1.tag], HTTPASM_ASN1_CONSTRUCTED
    jnz     .bad
    cmp     qword [r12 + httpasm_asn1.content_length], 1
    jne     .bad
    mov     rsi, [r12 + httpasm_asn1.content]
    HA_DECLASSIFY_MEM rsi, 1                ; (public by design: no key's secret is a BOOLEAN)
    test    r13d, HTTPASM_ASN1_BER
    jnz     .good                           ; 8.2.2: TRUE is any non-zero octet in BER
    mov     rax, [r12 + httpasm_asn1.content]
    movzx   eax, byte [rax]
    test    eax, eax
    jz      .good
    cmp     eax, 0xFF                       ; DER (11.1): TRUE is all ones
    je      .good
    jmp     .bad

.integer:                                   ; 8.3.1: primitive, one octet or more
    test    dword [r12 + httpasm_asn1.tag], HTTPASM_ASN1_CONSTRUCTED
    jnz     .bad
    mov     rcx, [r12 + httpasm_asn1.content_length]
    test    rcx, rcx
    jz      .bad
    cmp     rcx, 1
    je      .good
    ; 8.3.2: the first octet's 8 bits and the second's bit 8 neither all zero nor all ones (the
    ; fewest octets). A private key's INTEGER is a secret: the verdict is computed without a
    ; branch on its octets, and only the verdict is made public.
    mov     rax, [r12 + httpasm_asn1.content]
    movzx   edx, byte [rax]
    movzx   eax, byte [rax + 1]
    shr     eax, 7
    lea     edx, [rdx * 2 + rax]
    xor     eax, eax
    xor     ecx, ecx
    test    edx, edx
    sete    al
    cmp     edx, 0x1FF
    sete    cl
    or      eax, ecx
    HA_DECLASSIFY rax                       ; (public by design: a malformed integer is refused)
    test    eax, eax
    jnz     .bad
    jmp     .good

.bits:
    test    dword [r12 + httpasm_asn1.tag], HTTPASM_ASN1_CONSTRUCTED
    jz      .bits_primitive
    test    r13d, HTTPASM_ASN1_BER
    jz      .bad                            ; DER (10.2): the primitive form
    ; 8.6.4: BER's segments, BIT STRINGs themselves, all whole octets but the last
    mov     dword [rsp + TF_STATE + CS_KIND], CK_ANY
    mov     dword [rsp + TF_STATE + CS_UNUSED], 0
    mov     esi, HTTPASM_ASN1_BIT_STRING
    jmp     .segments
.bits_primitive:
    mov     rcx, [r12 + httpasm_asn1.content_length]
    test    rcx, rcx
    jz      .bad                            ; 8.6.2: the initial octet
    mov     rax, [r12 + httpasm_asn1.content]
    HA_DECLASSIFY_MEM rax, rcx              ; (public by design: a key's BIT STRING is its public key)
    movzx   edx, byte [rax]                 ; the unused bits of the final octet
    cmp     edx, 7
    ja      .bad                            ; 8.6.2.2
    cmp     rcx, 1
    jne     .bits_some
    test    edx, edx
    jnz     .bad                            ; 8.6.2.3: an empty bit string's initial octet is 0
    jmp     .good
.bits_some:
    test    r13d, HTTPASM_ASN1_BER
    jnz     .good
    movzx   eax, byte [rax + rcx - 1]       ; DER (11.2.1): every unused bit zero
    mov     ecx, edx
    mov     edx, 1
    shl     edx, cl
    dec     edx
    test    eax, edx
    jnz     .bad
    jmp     .good

.octets:                                    ; 8.7.2: any octets
    test    dword [r12 + httpasm_asn1.tag], HTTPASM_ASN1_CONSTRUCTED
    jz      .good
    test    r13d, HTTPASM_ASN1_BER
    jz      .bad                            ; DER (10.2): the primitive form
    mov     dword [rsp + TF_STATE + CS_KIND], CK_ANY
    mov     dword [rsp + TF_STATE + CS_NEED], 0
    mov     esi, HTTPASM_ASN1_OCTET_STRING  ; 8.7.3.2: segments of OCTET STRING
    jmp     .segments

.null:                                      ; 8.8: primitive, no contents octet
    test    dword [r12 + httpasm_asn1.tag], HTTPASM_ASN1_CONSTRUCTED
    jnz     .bad
    cmp     qword [r12 + httpasm_asn1.content_length], 0
    jne     .bad
    jmp     .good

.oid:                                       ; 8.19.1: primitive
    test    dword [r12 + httpasm_asn1.tag], HTTPASM_ASN1_CONSTRUCTED
    jnz     .bad
    mov     rcx, [r12 + httpasm_asn1.content_length]
    test    rcx, rcx
    jz      .bad                            ; 8.19.3: two components at least, so one subidentifier
    mov     rsi, [r12 + httpasm_asn1.content]
    HA_DECLASSIFY_MEM rsi, rcx              ; (public by design: an identifier names an algorithm)
    mov     edx, 1                          ; 1 at a subidentifier's first octet
.oid_octet:
    movzx   eax, byte [rsi]
    inc     rsi
    test    edx, edx
    jz      .oid_kept
    cmp     eax, 0x80                       ; 8.19.2: the fewest octets: never a leading 0x80
    je      .bad
.oid_kept:
    mov     edx, eax                        ; bit 8 clear ends a subidentifier: the next octet
    not     edx                             ; starts one
    shr     edx, 7
    and     edx, 1
    dec     rcx
    jnz     .oid_octet
    test    edx, edx
    jz      .bad                            ; the last octet must end its subidentifier
    jmp     .good

.constructed:                               ; 8.9.1, 8.10.1, 8.11.1, 8.12.1
    test    dword [r12 + httpasm_asn1.tag], HTTPASM_ASN1_CONSTRUCTED
    jz      .bad
    jmp     .good

.string:                                    ; 8.23: the characters of the type's set
    lea     rax, [rel asn1_charsets]
    movzx   eax, byte [rax + rbx]
    mov     [rsp + TF_STATE + CS_KIND], eax
    mov     dword [rsp + TF_STATE + CS_NEED], 0
    mov     dword [rsp + TF_STATE + CS_LO], 0x80
    mov     dword [rsp + TF_STATE + CS_HI], 0xBF
    mov     dword [rsp + TF_STATE + CS_ACC], 0
    test    dword [r12 + httpasm_asn1.tag], HTTPASM_ASN1_CONSTRUCTED
    jz      .string_primitive
    test    r13d, HTTPASM_ASN1_BER
    jz      .bad                            ; DER (10.2): the primitive form
    mov     esi, HTTPASM_ASN1_OCTET_STRING  ; 8.23.3: as if [UNIVERSAL x] IMPLICIT OCTET STRING:
    jmp     .segments                       ; segments of OCTET STRING, the characters across them
.string_primitive:
    mov     rsi, [r12 + httpasm_asn1.content]
    mov     rcx, [r12 + httpasm_asn1.content_length]
    HA_DECLASSIFY_MEM rsi, rcx              ; (public by design: a key's strings are its attributes)
    lea     rdi, [rsp + TF_STATE]
    mov     rsi, [r12 + httpasm_asn1.content]
    mov     rdx, [r12 + httpasm_asn1.content_length]
    call    ha_asn1_chars
    test    eax, eax
    jnz     .bad
    cmp     ebx, HTTPASM_ASN1_UTC_TIME
    jb      .string_end
    cmp     ebx, HTTPASM_ASN1_GENERALIZED_TIME
    ja      .string_end
    mov     rsi, [r12 + httpasm_asn1.content]
    mov     rdx, [r12 + httpasm_asn1.content_length]
    mov     ecx, ebx
    mov     edi, r13d
    call    ha_asn1_time                    ; the rules' forms (DER: 11.7, 11.8)
    test    eax, eax
    jnz     .bad
.string_end:
    cmp     dword [rsp + TF_STATE + CS_NEED], 0
    jne     .bad                            ; a character left unfinished
    jmp     .good

.segments:                                  ; esi = the segments' type; the state is set
    mov     rdi, r12
    mov     edx, r13d
    mov     ecx, r14d
    lea     r8, [rsp + TF_STATE]
    call    ha_asn1_segments
    test    eax, eax
    jnz     .bad
    cmp     ebx, HTTPASM_ASN1_BIT_STRING
    je      .good
    cmp     dword [rsp + TF_STATE + CS_NEED], 0
    jne     .bad                            ; a character left unfinished
    cmp     ebx, HTTPASM_ASN1_UTC_TIME
    jb      .good
    cmp     ebx, HTTPASM_ASN1_GENERALIZED_TIME
    ja      .good
    ; A time in BER's constructed form: its form spans the segments, so they are gathered
    ; first (TF_TIME_SIZE octets at most: X.680's longest times are well under it, bar a
    ; GeneralizedTime fraction of 40 digits or more, which is refused).
    mov     rdi, r12
    lea     rsi, [rsp + TF_TIME]
    mov     edx, TF_TIME_SIZE
    mov     ecx, r13d
    mov     r8d, r14d
    call    ha_asn1_gather
    test    rax, rax
    js      .bad
    lea     rsi, [rsp + TF_TIME]
    mov     rdx, rax
    mov     ecx, ebx
    mov     edi, r13d
    call    ha_asn1_time
    test    eax, eax
    jnz     .bad
    jmp     .good

.good:
    xor     eax, eax
.done:
    add     rsp, TF_SIZE
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.bad:
    mov     eax, -1
    jmp     .done
.end:

; -----------------------------------------------------------------------------
; ha_asn1_segments: rdi = a constructed string element (BER), esi = its segments' universal
;   type (3 BIT STRING, or 4 OCTET STRING for OCTET STRING and the restricted character
;   strings), edx = the rules, ecx = the nesting levels left, r8 = the state (CS_*) -> eax = 0
;   when every segment, at any depth, is an encoding of that type and the octets they hold in
;   turn pass the state's check (a BIT STRING's: only the last segment may end mid-octet,
;   8.6.4), else -1. An AF_UNENDED element is ended here: its segments run to its end-of-contents
;   octets, and its content_length, length and flags are set (AF_UNENDED's definition); on -1
;   its fields are unspecified. Each segment is read as its header alone (AR_HEAD) and a
;   constructed one walked by the recursion, which ends it in turn: every segment's header is
;   read once, whatever the nesting. Recursive, one level for each constructed segment.
;   Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
SG_NESTED       equ 0                       ; httpasm_asn1: the segment
SG_ELEMENT      equ 32                      ; the element walked (ended here when AF_UNENDED)
SG_SIZE         equ 40                      ; (6 pushes + 40: rsp 16-aligned at calls)

align 16
ha_asn1_segments:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, SG_SIZE
    mov     [rsp + SG_ELEMENT], rdi
    mov     r12, [rdi + httpasm_asn1.content]   ; the next segment
    mov     r13, [rdi + httpasm_asn1.content_length]
    add     r13, r12                        ; the contents' end (AF_UNENDED: the input's)
    mov     ebx, esi                        ; the segments' type
    mov     ebp, edx                        ; the rules
    mov     r14d, ecx                       ; the depth left
    mov     r15, r8                         ; the state
    test    r14d, r14d
    jz      .bad                            ; nested deeper than the reader follows
.segment:
    mov     rax, [rsp + SG_ELEMENT]
    test    dword [rax + httpasm_asn1.flags], AF_UNENDED
    jnz     .unended
    cmp     r12, r13
    jae     .good
    jmp     .read
.unended:                                   ; the segments run to the end-of-contents (8.1.5)
    mov     rax, r13
    sub     rax, r12                        ; octets left
    cmp     rax, 2
    jb      .bad                            ; 8.1.3.6.2: the end-of-contents octets must follow
    movzx   ecx, word [r12]
    HA_DECLASSIFY rcx                       ; (public by design: the encoding's structure)
    test    ecx, ecx
    jz      .ended
.read:
    lea     rdi, [rsp + SG_NESTED]
    mov     rsi, r12
    mov     rdx, r13
    sub     rdx, r12
    mov     ecx, ebp
    or      ecx, AR_HEAD                    ; its header: this walk checks it, and ends it
    lea     r8d, [r14 - 1]
    call    ha_asn1_read
    test    eax, eax
    jnz     .bad
    mov     eax, [rsp + SG_NESTED + httpasm_asn1.tag]
    mov     ecx, eax
    and     ecx, ~HTTPASM_ASN1_CONSTRUCTED
    cmp     ecx, ebx                        ; 8.6.4.1, 8.7.3.2: universal, the segments' type
    jne     .bad
    test    eax, HTTPASM_ASN1_CONSTRUCTED
    jz      .primitive
    lea     rdi, [rsp + SG_NESTED]          ; a segment segmented in turn (8.6.4.1, 8.7.3.2)
    mov     esi, ebx
    mov     edx, ebp
    lea     ecx, [r14 - 1]
    mov     r8, r15
    call    ha_asn1_segments
    test    eax, eax
    jnz     .bad
    jmp     .next
.primitive:
    cmp     ebx, HTTPASM_ASN1_BIT_STRING
    je      .bits
    cmp     dword [r15 + CS_KIND], CK_ANY
    je      .next                           ; an OCTET STRING's (or an ISO 2022 string's): unread
    mov     rsi, [rsp + SG_NESTED + httpasm_asn1.content]
    mov     rcx, [rsp + SG_NESTED + httpasm_asn1.content_length]
    HA_DECLASSIFY_MEM rsi, rcx              ; (public by design: a key's strings are its attributes)
    mov     rdi, r15
    mov     rsi, [rsp + SG_NESTED + httpasm_asn1.content]
    mov     rdx, [rsp + SG_NESTED + httpasm_asn1.content_length]
    call    ha_asn1_chars
    test    eax, eax
    jnz     .bad
    jmp     .next
.bits:
    cmp     dword [r15 + CS_UNUSED], 0
    jne     .bad                            ; 8.6.4: a segment after one that ended mid-octet
    mov     rcx, [rsp + SG_NESTED + httpasm_asn1.content_length]
    test    rcx, rcx
    jz      .bad                            ; 8.6.2: the initial octet
    mov     rax, [rsp + SG_NESTED + httpasm_asn1.content]
    HA_DECLASSIFY_MEM rax, rcx              ; (public by design: a key's BIT STRING is its public key)
    movzx   eax, byte [rax]
    cmp     eax, 7
    ja      .bad                            ; 8.6.2.2
    cmp     rcx, 1
    jne     .bits_kept
    test    eax, eax
    jnz     .bad                            ; 8.6.2.3
.bits_kept:
    mov     [r15 + CS_UNUSED], eax
.next:
    add     r12, [rsp + SG_NESTED + httpasm_asn1.length]    ; (an unended segment's: ended above)
    jmp     .segment
.ended:                                     ; r12 = the end-of-contents octets
    mov     rdi, [rsp + SG_ELEMENT]
    mov     rax, r12
    sub     rax, [rdi + httpasm_asn1.content]
    mov     [rdi + httpasm_asn1.content_length], rax
    add     rax, 2
    add     [rdi + httpasm_asn1.length], rax    ; the header's, the contents', the end's
    mov     dword [rdi + httpasm_asn1.flags], HTTPASM_ASN1_INDEFINITE
.good:
    xor     eax, eax
.done:
    add     rsp, SG_SIZE
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.bad:
    mov     eax, -1
    jmp     .done

; -----------------------------------------------------------------------------
; ha_asn1_gather: rdi = an element checked as an OCTET STRING, a restricted character string or
;   (with AG_BITS in ecx) a BIT STRING, under its own or an implicit tag, primitive or in BER's
;   constructed form; rsi = out, rdx = its capacity, ecx = the rules (BER's bit, and AG_BITS),
;   r8d = the nesting levels left -> rax = the value's octets written to out (a BIT STRING's
;   without the initial octets; edx = the unused bits of its final octet), or -1 when they do not
;   fit (out then holds a prefix) or a segment does not read. An AF_UNENDED element (a segment
;   the recursion read as its header) is ended as ha_asn1_segments ends one. Recursive, one level
;   for each constructed segment, each segment's header read once. Copies whole runs (rep
;   movsb): constant time in the octets, which may be a private key's. Clobbers the
;   caller-saved registers.
; -----------------------------------------------------------------------------
AG_BITS         equ 0x200                   ; rules flag (internal): gather a BIT STRING's bits
GA_NESTED       equ 0                       ; httpasm_asn1: a segment
GA_DEPTH        equ 32                      ; the depth left
GA_UNUSED       equ 36                      ; the last primitive segment's unused bits
GA_ELEMENT      equ 40                      ; the element gathered (ended here when AF_UNENDED)
GA_SIZE         equ 56                      ; (6 pushes + 56: rsp 16-aligned at calls)

global ha_asn1_gather:function hidden (ha_asn1_gather.end - ha_asn1_gather)
align 16
ha_asn1_gather:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, GA_SIZE
    mov     rbx, rsi                        ; out
    mov     rbp, rdx                        ; its capacity
    mov     r14d, ecx                       ; the rules
    mov     [rsp + GA_DEPTH], r8d
    mov     dword [rsp + GA_UNUSED], 0
    xor     r15d, r15d                      ; octets written
    test    dword [rdi + httpasm_asn1.tag], HTTPASM_ASN1_CONSTRUCTED
    jnz     .constructed
    mov     rsi, [rdi + httpasm_asn1.content]
    mov     rcx, [rdi + httpasm_asn1.content_length]
    test    r14d, AG_BITS
    jz      .copy
    movzx   eax, byte [rsi]                 ; the initial octet: the unused bits (checked)
    mov     [rsp + GA_UNUSED], eax
    inc     rsi
    dec     rcx
.copy:
    cmp     rcx, rbp
    ja      .bad
    mov     rdi, rbx
    mov     r15, rcx
    rep     movsb
    jmp     .good
.constructed:
    cmp     dword [rsp + GA_DEPTH], 0
    je      .bad
    mov     [rsp + GA_ELEMENT], rdi
    mov     r12, [rdi + httpasm_asn1.content]   ; the next segment
    mov     r13, [rdi + httpasm_asn1.content_length]
    add     r13, r12                        ; the contents' end (AF_UNENDED: the input's)
.segment:
    mov     rax, [rsp + GA_ELEMENT]
    test    dword [rax + httpasm_asn1.flags], AF_UNENDED
    jnz     .unended
    cmp     r12, r13
    jae     .good
    jmp     .read
.unended:                                   ; to the end-of-contents octets (checked: they come)
    mov     rax, r13
    sub     rax, r12
    cmp     rax, 2
    jb      .bad
    movzx   ecx, word [r12]
    HA_DECLASSIFY rcx                       ; (public by design: the encoding's structure)
    test    ecx, ecx
    jz      .ended
.read:
    lea     rdi, [rsp + GA_NESTED]
    mov     rsi, r12
    mov     rdx, r13
    sub     rdx, r12
    mov     ecx, r14d
    and     ecx, HTTPASM_ASN1_BER
    or      ecx, AR_HEAD                    ; checked already: its header is enough
    mov     r8d, [rsp + GA_DEPTH]
    dec     r8d
    call    ha_asn1_read
    test    eax, eax
    jnz     .bad
    lea     rdi, [rsp + GA_NESTED]
    lea     rsi, [rbx + r15]
    mov     rdx, rbp
    sub     rdx, r15
    mov     ecx, r14d
    mov     r8d, [rsp + GA_DEPTH]
    dec     r8d
    call    ha_asn1_gather
    test    rax, rax
    js      .bad
    add     r15, rax
    test    r14d, AG_BITS
    jz      .next
    ; The unused bits: the last primitive segment's. Or-ing keeps them, because every primitive
    ; segment before the last has none (the check refused a segment after one that ended
    ; mid-octet, 8.6.4), and a constructed segment holding no primitive one returns 0. Moving
    ; the latest segment's in (the first version) let such an empty constructed segment, after
    ; the last primitive one, reset them to 0 (23 80 03 03 02 0A 40 23 80 00 00 00 00: 2 unused
    ; bits read as 0; tests/fuzz/asn1.c, 2026-11-28).
    or      [rsp + GA_UNUSED], edx
.next:
    add     r12, [rsp + GA_NESTED + httpasm_asn1.length]    ; (an unended segment's: ended above)
    jmp     .segment
.ended:                                     ; r12 = the end-of-contents octets
    mov     rdi, [rsp + GA_ELEMENT]
    mov     rax, r12
    sub     rax, [rdi + httpasm_asn1.content]
    mov     [rdi + httpasm_asn1.content_length], rax
    add     rax, 2
    add     [rdi + httpasm_asn1.length], rax
    mov     dword [rdi + httpasm_asn1.flags], HTTPASM_ASN1_INDEFINITE
.good:
    mov     rax, r15
    mov     edx, [rsp + GA_UNUSED]
.done:
    add     rsp, GA_SIZE
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.bad:
    mov     rax, -1
    jmp     .done
.end:

; -----------------------------------------------------------------------------
; ha_asn1_chars: rdi = the state (CS_*), rsi = octets, rdx = their count -> eax = 0 when every
;   octet continues the state's character set validly (a character may stay unfinished at the
;   end: the next segment may finish it, and the caller checks CS_NEED once all are seen), else
;   -1. The state is updated. A leaf. Clobbers rax, rcx, rdx, rsi, r8-r11.
; -----------------------------------------------------------------------------
align 16
ha_asn1_chars:
    test    rdx, rdx
    jz      .good
    mov     eax, [rdi + CS_KIND]
    cmp     eax, CK_ANY
    je      .good                           ; ISO 2022's escapes: not the library's to check
    cmp     eax, CK_UTF8
    je      .utf8
    cmp     eax, CK_BMP
    je      .bmp
    cmp     eax, CK_UNIVERSAL
    je      .universal
    ; the single-octet sets: 128 bits of allowed octets
    lea     r8, [rel asn1_sets]
    shl     eax, 4                          ; 16 octets a set, CK_PRINTABLE's first
    mov     r9, [r8 + rax - 16]             ; octets 0-63
    mov     r10, [r8 + rax - 8]             ; octets 64-127
.set_octet:
    movzx   ecx, byte [rsi]
    inc     rsi
    cmp     ecx, 128
    jae     .bad
    mov     r11, r9
    cmp     ecx, 64
    jb      .set_low
    mov     r11, r10
.set_low:
    bt      r11, rcx                        ; (the bit index taken mod 64)
    jnc     .bad
    dec     rdx
    jnz     .set_octet
.good:
    xor     eax, eax
    ret
.bad:
    mov     eax, -1
    ret

.utf8:                                      ; 8.23.10: ISO 10646 Annex D, the fewest octets
    mov     r8d, [rdi + CS_NEED]            ; continuation octets still due
    mov     r9d, [rdi + CS_LO]              ; the next one's range
    mov     r10d, [rdi + CS_HI]
.utf8_octet:
    movzx   ecx, byte [rsi]
    inc     rsi
    test    r8d, r8d
    jz      .utf8_lead
    cmp     ecx, r9d
    jb      .bad
    cmp     ecx, r10d
    ja      .bad
    dec     r8d
    mov     r9d, 0x80
    mov     r10d, 0xBF
    jmp     .utf8_next
.utf8_lead:
    cmp     ecx, 0x80
    jb      .utf8_next                      ; one octet
    cmp     ecx, 0xC2
    jb      .bad                            ; a continuation octet, or C0/C1 (overlong)
    mov     r8d, 1
    cmp     ecx, 0xE0
    jb      .utf8_next                      ; two octets
    mov     r8d, 2
    cmp     ecx, 0xF0
    jae     .utf8_four
    cmp     ecx, 0xE0
    jne     .utf8_e
    mov     r9d, 0xA0                       ; E0: A0-BF (below, an overlong form)
    jmp     .utf8_next
.utf8_e:
    cmp     ecx, 0xED
    jne     .utf8_next
    mov     r10d, 0x9F                      ; ED: 80-9F (above, the surrogates D800-DFFF)
    jmp     .utf8_next
.utf8_four:
    cmp     ecx, 0xF4
    ja      .bad                            ; F5-FF: above U+10FFFF, or no UTF-8 at all
    mov     r8d, 3
    cmp     ecx, 0xF0
    jne     .utf8_f4
    mov     r9d, 0x90                       ; F0: 90-BF (below, an overlong form)
    jmp     .utf8_next
.utf8_f4:
    cmp     ecx, 0xF4
    jne     .utf8_next
    mov     r10d, 0x8F                      ; F4: 80-8F (above, past U+10FFFF)
.utf8_next:
    dec     rdx
    jnz     .utf8_octet
    mov     [rdi + CS_NEED], r8d
    mov     [rdi + CS_LO], r9d
    mov     [rdi + CS_HI], r10d
    xor     eax, eax
    ret

.bmp:                                       ; 8.23.8: two octets a character, BMP's form
    mov     r8d, [rdi + CS_NEED]            ; 1 after a character's first octet
.bmp_octet:
    movzx   ecx, byte [rsi]
    inc     rsi
    test    r8d, r8d
    jnz     .bmp_second
    and     ecx, 0xF8
    cmp     ecx, 0xD8                       ; D800-DFFF: surrogates, not characters
    je      .bad
    mov     r8d, 1
    jmp     .bmp_next
.bmp_second:
    xor     r8d, r8d
.bmp_next:
    dec     rdx
    jnz     .bmp_octet
    mov     [rdi + CS_NEED], r8d
    xor     eax, eax
    ret

.universal:                                 ; 8.23.7: four octets a character
    mov     r8d, [rdi + CS_NEED]            ; octets of the character so far
    mov     r9d, [rdi + CS_ACC]
.universal_octet:
    movzx   ecx, byte [rsi]
    inc     rsi
    shl     r9d, 8
    or      r9d, ecx
    inc     r8d
    cmp     r8d, 4
    jne     .universal_next
    cmp     r9d, 0x10FFFF                   ; ISO 10646's code space
    ja      .bad
    mov     ecx, r9d
    and     ecx, 0xFFFFF800
    cmp     ecx, 0xD800                     ; the surrogates
    je      .bad
    xor     r8d, r8d
    xor     r9d, r9d
.universal_next:
    dec     rdx
    jnz     .universal_octet
    mov     [rdi + CS_NEED], r8d
    mov     [rdi + CS_ACC], r9d
    xor     eax, eax
    ret

; -----------------------------------------------------------------------------
; ha_asn1_time: rsi = a time's characters (VisibleString's, already checked), rdx = their
;   count, ecx = 23 (UTCTime) or 24 (GeneralizedTime), edi = the rules (BER's bit) -> eax = 0
;   when they are a time in the rules' forms, else -1:
;   DER (11.7, 11.8)
;     UTCTime         YYMMDDhhmmssZ
;     GeneralizedTime YYYYMMDDhhmmss[.f...]Z, the fraction without a trailing zero
;   BER (X.680 47.3, and 46.3 with ISO 8601's basic format)
;     UTCTime         YYMMDDhhmm[ss], then Z or a differential +hhmm / -hhmm
;     GeneralizedTime YYYYMMDDhh[mm[ss]][(.|,)f...] (the fraction belongs to the last unit),
;                     then nothing (local time), Z, or a differential +hh[mm] / -hh[mm]
;   Every field in its range: month 01-12; day 01 to the month's last (February's 29th in leap
;   years: UTCTime's YY divisible by 4, as RFC 5280 reads YY as 1950-2049; Gregorian for
;   GeneralizedTime); hour 00-23 (11.7.5, 11.8.3: midnight is 00, never 24); minute and second
;   00-59 (no leap second: OpenSSL and Go refuse one too); a differential's hours 00-23 and
;   minutes 00-59. A leaf (its .pair and .digits helpers aside). Clobbers rax, rcx, rdx, r8-r11.
; -----------------------------------------------------------------------------
align 16
ha_asn1_time:
    push    rbx
    lea     r11, [rsi + rdx]                ; the end
    xor     edx, edx
    cmp     ecx, HTTPASM_ASN1_UTC_TIME
    setne   dl                              ; 1: GeneralizedTime
    lea     r9, [rsi + rdx * 2 + 2]         ; the month, after YY or YYYY
    mov     rax, r11
    sub     rax, rsi
    cmp     rax, 10                         ; YYMMDDhhmm, or YYYYMMDDhh
    jb      .bad
    mov     r8, rsi
    mov     ecx, 10
    call    .digits
    jc      .bad
    lea     r10, [rsi + 10]                 ; the cursor
    mov     ebx, 1                          ; the units present: 1 the minute, 2 the second
    test    edx, edx
    jz      .second                         ; UTCTime's ten digits end with the minute
    xor     ebx, ebx                        ; GeneralizedTime's with the hour
    call    .pair
    jc      .units
    add     r10, 2
    mov     ebx, 1
.second:
    call    .pair
    jc      .units
    add     r10, 2
    or      ebx, 2
.units:
    test    edi, HTTPASM_ASN1_BER
    jnz     .fraction
    cmp     ebx, 3                          ; DER (11.7.2, 11.8.2): the seconds always
    jne     .bad
.fraction:
    test    edx, edx
    jz      .zone                           ; UTCTime has no fraction
    cmp     r10, r11
    jae     .zone
    movzx   eax, byte [r10]
    cmp     eax, '.'
    je      .fraction_digits
    cmp     eax, ','
    jne     .zone
    test    edi, HTTPASM_ASN1_BER           ; DER (11.7.4): the point option "." only
    jz      .bad
.fraction_digits:
    inc     r10
    mov     r8, r10                         ; the fraction's first digit
.fraction_digit:
    cmp     r10, r11
    jae     .fraction_end
    movzx   eax, byte [r10]
    sub     eax, '0'
    cmp     eax, 9
    ja      .fraction_end
    inc     r10
    jmp     .fraction_digit
.fraction_end:
    cmp     r10, r8
    je      .bad                            ; a decimal sign without a digit
    test    edi, HTTPASM_ASN1_BER
    jnz     .zone
    cmp     byte [r10 - 1], '0'             ; DER (11.7.3): no trailing zero (so never all zeros)
    je      .bad
.zone:
    test    edi, HTTPASM_ASN1_BER
    jnz     .zone_ber
    lea     rax, [r10 + 1]                  ; DER (11.7.1, 11.8.1): Z, and nothing after it
    cmp     rax, r11
    jne     .bad
    cmp     byte [r10], 'Z'
    jne     .bad
    jmp     .fields
.zone_ber:
    cmp     r10, r11
    jne     .zone_some
    test    edx, edx                        ; nothing: local time, GeneralizedTime's only
    jz      .bad
    jmp     .fields
.zone_some:
    movzx   eax, byte [r10]
    cmp     eax, 'Z'
    jne     .zone_differential
    lea     rax, [r10 + 1]
    cmp     rax, r11
    jne     .bad
    jmp     .fields
.zone_differential:
    cmp     eax, '+'
    je      .zone_hours
    cmp     eax, '-'
    jne     .bad
.zone_hours:
    inc     r10
    call    .pair
    jc      .bad
    TWO_DIGITS eax, r10
    cmp     eax, 23
    ja      .bad
    add     r10, 2
    cmp     r10, r11
    jne     .zone_minutes
    test    edx, edx                        ; UTCTime's differential has its minutes
    jz      .bad
    jmp     .fields
.zone_minutes:
    call    .pair
    jc      .bad
    TWO_DIGITS eax, r10
    cmp     eax, 59
    ja      .bad
    add     r10, 2
    cmp     r10, r11
    jne     .bad

.fields:                                    ; r9 = the month; ebx = the units present
    xor     ecx, ecx                        ; 1 in a leap year
    test    edx, edx
    jnz     .gregorian
    TWO_DIGITS eax, rsi                     ; YY
    test    eax, 3
    setz    cl
    jmp     .month
.gregorian:
    TWO_DIGITS eax, rsi
    TWO_DIGITS r10d, rsi + 2
    imul    eax, eax, 100
    add     eax, r10d                       ; YYYY
    test    eax, 3                          ; divisible by 4, and not by 100 unless by 400
    jnz     .month
    xor     edx, edx
    mov     r10d, 100
    div     r10d
    test    edx, edx
    jnz     .leap
    test    eax, 3
    jnz     .month
.leap:
    mov     ecx, 1
.month:
    mov     r10d, ecx
    TWO_DIGITS eax, r9
    dec     eax
    cmp     eax, 11
    ja      .bad
    lea     rcx, [rel asn1_days]
    movzx   ecx, byte [rcx + rax]
    cmp     eax, 1
    jne     .day
    add     ecx, r10d                       ; February's 29th
.day:
    TWO_DIGITS eax, r9 + 2
    test    eax, eax
    jz      .bad
    cmp     eax, ecx
    ja      .bad
    TWO_DIGITS eax, r9 + 4                  ; the hour
    cmp     eax, 23
    ja      .bad
    test    ebx, 1
    jz      .good
    TWO_DIGITS eax, r9 + 6                  ; the minute
    cmp     eax, 59
    ja      .bad
    test    ebx, 2
    jz      .good
    TWO_DIGITS eax, r9 + 8                  ; the second
    cmp     eax, 59
    ja      .bad
.good:
    xor     eax, eax
    pop     rbx
    ret
.bad:
    mov     eax, -1
    pop     rbx
    ret
; .pair: CF clear when two digits stand at r10, before r11. Clobbers rax.
.pair:
    mov     rax, r11
    sub     rax, r10
    cmp     rax, 2
    jb      .not_pair
    movzx   eax, byte [r10]
    sub     eax, '0'
    cmp     eax, 9
    ja      .not_pair
    movzx   eax, byte [r10 + 1]
    sub     eax, '0'
    cmp     eax, 9
    ja      .not_pair
    clc
    ret
.not_pair:
    stc
    ret
; .digits: r8 = octets, ecx = their count (1 at least) -> CF clear when all are '0'-'9'.
; Clobbers rax, rcx, r8.
.digits:
    movzx   eax, byte [r8]
    sub     eax, '0'
    cmp     eax, 9
    ja      .not_digits
    inc     r8
    dec     ecx
    jnz     .digits
    clc
    ret
.not_digits:
    stc
    ret

; -----------------------------------------------------------------------------
; int64_t httpasm_asn1_octets(const httpasm_asn1 *element, uint8_t *out, size_t capacity,
;                             int rules)
;   The value of an OCTET STRING or a restricted character string (read under its own tag, or
;   checked as one under an implicit tag), primitive or in BER's constructed form: its octets in
;   order, the segments' joined, into out[0..capacity). The element is checked as an OCTET
;   STRING first (its segments must be ones), so a constructed element of another kind is
;   refused rather than flattened. Returns rax = the count, or -1 when they do not fit (out then
;   holds a prefix), the check fails (flags as httpasm_asn1_check takes them), or the rules are
;   unknown. Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_asn1_octets:function (httpasm_asn1_octets.end - httpasm_asn1_octets)
align 16
httpasm_asn1_octets:
    cmp     ecx, HTTPASM_ASN1_BER
    ja      .refused
    test    dword [rdi + httpasm_asn1.flags], ~HTTPASM_ASN1_INDEFINITE
    jnz     .refused                        ; never httpasm_asn1_read's (httpasm_asn1_check's why)
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    mov     rbx, rdi                        ; the element
    mov     r12, rsi                        ; out
    mov     r13, rdx                        ; its capacity
    mov     r14d, ecx                       ; the rules
    mov     esi, HTTPASM_ASN1_OCTET_STRING
    mov     edx, r14d
    mov     ecx, HA_ASN1_DEPTH
    call    ha_asn1_type
    test    eax, eax
    jnz     .bad
    mov     rdi, rbx
    mov     rsi, r12
    mov     rdx, r13
    mov     ecx, r14d
    mov     r8d, HA_ASN1_DEPTH
    call    ha_asn1_gather
    jmp     .done
.bad:
    mov     rax, -1
.done:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.refused:
    mov     rax, -1
    ret
.end:

; -----------------------------------------------------------------------------
; int64_t httpasm_asn1_bits(const httpasm_asn1 *element, uint8_t *out, size_t capacity,
;                           uint32_t *unused, int rules)
;   A BIT STRING's bits (read under its own tag, or checked as one under an implicit tag),
;   primitive or in BER's constructed form: the octets after each segment's initial octet, in
;   order, into out[0..capacity), and in *unused the unused bits of the final octet (0 to 7; 0
;   when empty). The element is checked as a BIT STRING first. Returns rax = the octets, or -1
;   when they do not fit (out then holds a prefix), the check fails (flags as
;   httpasm_asn1_check takes them), or the rules are unknown (*unused then unchanged). Clobbers
;   the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_asn1_bits:function (httpasm_asn1_bits.end - httpasm_asn1_bits)
align 16
httpasm_asn1_bits:
    cmp     r8d, HTTPASM_ASN1_BER
    ja      .refused
    test    dword [rdi + httpasm_asn1.flags], ~HTTPASM_ASN1_INDEFINITE
    jnz     .refused                        ; never httpasm_asn1_read's (httpasm_asn1_check's why)
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 8                          ; (6 pushes + 8: rsp 16-aligned at calls)
    mov     rbx, rdi                        ; the element
    mov     r12, rsi                        ; out
    mov     r13, rdx                        ; its capacity
    mov     r15, rcx                        ; unused
    mov     r14d, r8d                       ; the rules
    mov     esi, HTTPASM_ASN1_BIT_STRING
    mov     edx, r14d
    mov     ecx, HA_ASN1_DEPTH
    call    ha_asn1_type
    test    eax, eax
    jnz     .bad
    mov     rdi, rbx
    mov     rsi, r12
    mov     rdx, r13
    mov     ecx, r14d
    or      ecx, AG_BITS
    mov     r8d, HA_ASN1_DEPTH
    call    ha_asn1_gather
    test    rax, rax
    js      .done
    mov     [r15], edx
    jmp     .done
.bad:
    mov     rax, -1
.done:
    add     rsp, 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.refused:
    mov     rax, -1
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_asn1_check_set_of(const httpasm_asn1 *set, int rules)
;   A SET OF's components (an element httpasm_asn1_read returned, under SET's tag or an IMPLICIT
;   one): each read under the rules, and under DER in ascending order of their encodings
;   (11.6: compared as octet strings, the shorter padded with zero octets; equal ones may
;   repeat). A SET's components (not SET OF) are ordered by their tags instead (10.3), which
;   this does not check: no structure the library reads has one. Returns 0, or -1 (a primitive
;   element or an unknown rules value included). Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
SO_NESTED       equ 0                       ; httpasm_asn1: the component
SO_SIZE         equ 40                      ; (6 pushes + 40: rsp 16-aligned at calls)

global httpasm_asn1_check_set_of:function (httpasm_asn1_check_set_of.end - httpasm_asn1_check_set_of)
align 16
httpasm_asn1_check_set_of:
    cmp     esi, HTTPASM_ASN1_BER
    ja      .refused
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, SO_SIZE
    test    dword [rdi + httpasm_asn1.tag], HTTPASM_ASN1_CONSTRUCTED
    jz      .bad                            ; 8.12.1
    mov     r12, [rdi + httpasm_asn1.content]   ; the next component
    mov     r13, [rdi + httpasm_asn1.content_length]
    add     r13, r12                        ; the contents' end
    mov     ebp, esi                        ; the rules
    xor     r14d, r14d                      ; the previous component (none yet)
    xor     r15d, r15d                      ; its length
.component:
    cmp     r12, r13
    jae     .good
    lea     rdi, [rsp + SO_NESTED]
    mov     rsi, r12
    mov     rdx, r13
    sub     rdx, r12
    mov     ecx, ebp
    mov     r8d, HA_ASN1_DEPTH
    call    ha_asn1_read
    test    eax, eax
    jnz     .bad
    test    ebp, HTTPASM_ASN1_BER
    jnz     .next                           ; BER: the sender's order (8.12.3)
    test    r14, r14
    jz      .next
    ; DER (11.6): the previous encoding is not above this one
    mov     rcx, r15                        ; the previous one's length
    mov     rdx, [rsp + SO_NESTED + httpasm_asn1.length]
    mov     rax, rcx
    cmp     rax, rdx
    cmova   rax, rdx                        ; the common length
    xor     r8d, r8d
.compare:
    cmp     r8, rax
    jae     .compare_tail
    movzx   r9d, byte [r14 + r8]
    movzx   r10d, byte [r12 + r8]
    cmp     r9d, r10d
    jb      .next                           ; ascending here
    ja      .bad
    inc     r8
    jmp     .compare
.compare_tail:                              ; equal up to the shorter one's end
    cmp     rcx, rdx
    jbe     .next                           ; this one is as long or longer: not below
.compare_rest:                              ; the previous one is longer: the rest against zeros
    cmp     byte [r14 + r8], 0
    jne     .bad
    inc     r8
    cmp     r8, rcx
    jb      .compare_rest
.next:
    mov     r14, r12
    mov     r15, [rsp + SO_NESTED + httpasm_asn1.length]
    add     r12, r15
    jmp     .component
.good:
    xor     eax, eax
.done:
    add     rsp, SO_SIZE
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.bad:
    mov     eax, -1
    jmp     .done
.refused:
    mov     eax, -1
    ret
.end:
