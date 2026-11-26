; =============================================================================
; semantics/lookup.asm - the lookups every version's codec shares: a field name's known-field
; id (the generated perfect hash), a method's id, and the next line feed (SSE2).
;
; These are version-free (docs/DESIGN.md, "Sharing between the HTTP versions"): one copy of
; machine code serves HTTP/1.1, HTTP/2 and HTTP/3. The C ABI's field functions wrap them for
; consumers.
; =============================================================================
default rel
%include "httpasm_core.inc"

section .rodata
%include "generated/field_table.inc"        ; ha_field_hash, ha_field_names, ha_field_text

section .text

; -----------------------------------------------------------------------------
; ha_field_lookup: the known-field id of a field name.
;   In:  rdi = name, rsi = its length: any octets. HPACK's decoder and encoder look up names
;        nobody has validated yet, so the answer must be exact for every octet string.
;   Out: eax = HA_FIELD_* id, 0 when the name is not a known field. The compare ignores the
;        case of ASCII letters, as field names do (RFC 9110 5.1), and of nothing else.
;   Clobbers rcx, rdx, r8 and the flags. Reads rdi[0..rsi) only.
;
;   The key packs the first two and last two octets (folded with | 0x20) and the length; the
;   generated multiplier sends every known name to its own slot of 256 (specs/generate.cs).
;   One multiply and one table load find the only candidate; a compare confirms it. The key's
;   | 0x20 only picks the candidate, so it may fold too much; the compare folds letters only.
;   Folding every octet with | 0x20 there, as it once did, made CR match "-", 0x1A match ":"
;   and 0x10-0x19 match digits: HPACK's decoder gave "\x1apath" the id of :path, and its
;   encoder sent "content\rlength" as the static table's content-length (tests/fuzz/hpack,
;   2026-11-26). Token names never hold those octets, which is why HTTP/1.1 never showed it.
; -----------------------------------------------------------------------------
global ha_field_lookup:function hidden (ha_field_lookup.end - ha_field_lookup)
align 16
ha_field_lookup:
    cmp     rsi, 2
    jb      .none                           ; no known name is shorter than 2 octets
    cmp     rsi, HA_FIELD_MAX_LENGTH
    ja      .none
    movzx   eax, byte [rdi]
    or      eax, 0x20
    movzx   ecx, byte [rdi + 1]
    or      ecx, 0x20
    shl     ecx, 8
    or      eax, ecx
    movzx   ecx, byte [rdi + rsi - 2]
    or      ecx, 0x20
    shl     ecx, 16
    or      eax, ecx
    movzx   ecx, byte [rdi + rsi - 1]
    or      ecx, 0x20
    shl     ecx, 24
    or      eax, ecx                        ; rax = the four octets (the upper half is clear)
    mov     rcx, rsi
    shl     rcx, 32
    or      rax, rcx                        ; | length << 32
    mov     rcx, HA_FIELD_HASH_MULTIPLIER
    imul    rax, rcx
    shr     rax, 56                         ; the slot
    lea     rcx, [rel ha_field_hash]
    movzx   eax, byte [rcx + rax]           ; the candidate id
    test    eax, eax
    jz      .none
    lea     rcx, [rel ha_field_names]
    cmp     esi, [rcx + rax * 8 + 4]        ; the candidate's length
    jne     .none
    mov     edx, [rcx + rax * 8]            ; its offset in ha_field_text
    lea     rcx, [rel ha_field_text]
    add     rdx, rcx
    xor     ecx, ecx
.compare:                                   ; octet by octet (the names are short): equal, or
    movzx   r8d, byte [rdi + rcx]           ; the upper-case form of the known name's letter
    cmp     r8b, [rdx + rcx]
    je      .same                           ; the common case: already lower case, or "-", ":"
    or      r8d, 0x20
    cmp     r8b, [rdx + rcx]
    jne     .none
    sub     r8d, 'a'                        ; it folded to the known octet: only a letter may
    cmp     r8d, 'z' - 'a'                  ; (CR | 0x20 is "-", 0x1A | 0x20 is ":")
    ja      .none
.same:
    inc     rcx
    cmp     rcx, rsi
    jb      .compare
    ret                                     ; eax: the id
.none:
    xor     eax, eax
    ret
.end:

; -----------------------------------------------------------------------------
; ha_method_lookup: the id of a method token (methods are case-sensitive: RFC 9110 9.1).
;   In:  rdi = method, rsi = its length.
;   Out: eax = HTTPASM_METHOD_*, 0 for any other method.
;   Clobbers nothing else but the flags. Reads exactly rdi[0..rsi): each compare loads the
;   method's own octets (overlapping for 7), never past its end.
; -----------------------------------------------------------------------------
global ha_method_lookup:function hidden (ha_method_lookup.end - ha_method_lookup)
align 16
ha_method_lookup:
    xor     eax, eax
    cmp     rsi, 3
    je      .three
    cmp     rsi, 4
    je      .four
    cmp     rsi, 5
    je      .five
    cmp     rsi, 6
    je      .six
    cmp     rsi, 7
    je      .seven
    ret
.three:
    cmp     byte [rdi + 2], 'T'
    jne     .done
    cmp     word [rdi], 'GE'
    je      .get
    cmp     word [rdi], 'PU'
    jne     .done
    mov     eax, HTTPASM_METHOD_PUT
    ret
.get:
    mov     eax, HTTPASM_METHOD_GET
    ret
.four:
    cmp     dword [rdi], 'HEAD'
    je      .head
    cmp     dword [rdi], 'POST'
    jne     .done
    mov     eax, HTTPASM_METHOD_POST
    ret
.head:
    mov     eax, HTTPASM_METHOD_HEAD
    ret
.five:
    cmp     dword [rdi], 'TRAC'
    je      .trace
    cmp     dword [rdi], 'PATC'
    jne     .done
    cmp     byte [rdi + 4], 'H'
    jne     .done
    mov     eax, HTTPASM_METHOD_PATCH
    ret
.trace:
    cmp     byte [rdi + 4], 'E'
    jne     .done
    mov     eax, HTTPASM_METHOD_TRACE
    ret
.six:
    cmp     dword [rdi], 'DELE'
    jne     .done
    cmp     word [rdi + 4], 'TE'
    jne     .done
    mov     eax, HTTPASM_METHOD_DELETE
    ret
.seven:
    cmp     dword [rdi], 'CONN'
    je      .connect
    cmp     dword [rdi], 'OPTI'
    jne     .done
    cmp     dword [rdi + 3], 'IONS'
    jne     .done
    mov     eax, HTTPASM_METHOD_OPTIONS
    ret
.connect:
    cmp     dword [rdi + 3], 'NECT'
    jne     .done
    mov     eax, HTTPASM_METHOD_CONNECT
.done:
    ret
.end:

; -----------------------------------------------------------------------------
; ha_find_lf: the first line feed in rdi[0..rsi).
;   Out: rax = its offset, rsi when there is none.
;   Clobbers rcx, rdx, xmm0, xmm1 and the flags.
;   Memory: 16 octets per step; never outside rdi[0..rsi), with the same two exceptions-free
;   techniques as HA_FIELD_VALUE_SCAN: the last vector overlaps the one before (whose octets
;   held no LF), and a short range is read as one vector only within its 4 KiB page.
; -----------------------------------------------------------------------------
global ha_find_lf:function hidden (ha_find_lf.end - ha_find_lf)
align 16
ha_find_lf:
    movdqa  xmm1, [rel ha_x16_0a]
    xor     eax, eax
    cmp     rsi, 16
    jb      .short
.vector:                                    ; invariant: rax + 16 <= rsi
    movdqu  xmm0, [rdi + rax]
    pcmpeqb xmm0, xmm1
    pmovmskb ecx, xmm0
    test    ecx, ecx
    jnz     .found
    add     rax, 16
    lea     rdx, [rax + 16]
    cmp     rdx, rsi
    jbe     .vector
    cmp     rax, rsi
    je      .done                           ; rsi was a multiple of 16: none
    mov     rax, rsi                        ; the last 16 octets; the overlap holds no LF
    sub     rax, 16
    movdqu  xmm0, [rdi + rax]
    pcmpeqb xmm0, xmm1
    pmovmskb ecx, xmm0
    test    ecx, ecx
    jnz     .found
    mov     rax, rsi
    ret
.found:
    bsf     ecx, ecx
    add     rax, rcx
    ret
.short:                                     ; rsi < 16; rax = 0
    test    rsi, rsi
    jz      .done
    mov     rdx, rdi
    and     edx, 4095
    cmp     edx, 4096 - 16
    ja      .octets                         ; 16 octets would reach the next page
    movdqu  xmm0, [rdi]
    pcmpeqb xmm0, xmm1
    pmovmskb ecx, xmm0
    test    ecx, ecx
    jz      .none
    bsf     ecx, ecx
    cmp     rcx, rsi
    jae     .none                           ; the LF lies past the range
    mov     eax, ecx
    ret
.none:
    mov     rax, rsi
    ret
.octets:
    cmp     byte [rdi + rax], 0x0A
    je      .done
    inc     rax
    cmp     rax, rsi
    jb      .octets
.done:
    ret
.end:

; -----------------------------------------------------------------------------
; uint32_t httpasm_field_id(const uint8_t *name, size_t n)
;   The known-field id of a field name, matched without regard to case (RFC 9110 5.1); 0 when
;   the name is not a known field or is not a token. In: rdi, rsi. Out: eax.
;   Clobbers rcx, rdx, r8 and the flags.
; -----------------------------------------------------------------------------
global httpasm_field_id:function (httpasm_field_id.end - httpasm_field_id)
align 16
httpasm_field_id:
    ; A token first: the C ABI promises 0 for a name that is not a token (pseudo-fields
    ; included), whatever the lookup would match. (The lookup itself is exact for any octets
    ; since 2026-11-26; this check once also guarded its folding.)
    HA_TOKEN_SCAN rdi, rsi, rax, rcx, rdx
    cmp     rax, rsi
    jne     .not_token
    test    rsi, rsi
    jz      .not_token
    jmp     ha_field_lookup
.not_token:
    xor     eax, eax
    ret
.end:

; -----------------------------------------------------------------------------
; const uint8_t *httpasm_field_name(uint32_t id, size_t *length)
;   A known field's name in lower case (not NUL-terminated), and its length in *length; NULL
;   and 0 when id is not a known field's id. length may be NULL. In: edi, rsi. Out: rax.
;   Clobbers rcx, rdx and the flags.
; -----------------------------------------------------------------------------
global httpasm_field_name:function (httpasm_field_name.end - httpasm_field_name)
align 16
httpasm_field_name:
    mov     edi, edi                        ; the id is a uint32_t: ignore the upper half
    xor     eax, eax
    xor     edx, edx
    test    edi, edi
    jz      .out
    cmp     edi, HA_FIELD_COUNT
    ja      .out
    lea     rcx, [rel ha_field_names]
    mov     edx, [rcx + rdi * 8 + 4]        ; the length
    mov     eax, [rcx + rdi * 8]            ; the offset
    lea     rcx, [rel ha_field_text]
    add     rax, rcx
.out:
    test    rsi, rsi
    jz      .done
    mov     [rsi], rdx
.done:
    ret
.end:
