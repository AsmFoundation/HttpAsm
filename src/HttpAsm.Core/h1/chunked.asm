; =============================================================================
; h1/chunked.asm - the chunked transfer coding (RFC 9112 section 7.1):
; httpasm_h1_chunked_decode, httpasm_h1_parse_trailers, and ha_h1_head_end, the search for a
; head's end that the trailer and response parsers share.
;
; Rules, by registry row (specs/requirements.tsv):
;   - chunk-size = 1*HEXDIG, at most 16 digits and below 2^63: a larger numeral is refused,
;     never wrapped (RFC9112-7.1-3).
;   - chunk-ext is skipped (RFC9112-7.1.1-3: unrecognized extensions are ignored), up to
;     HA_CHUNK_MAX_EXTENSION octets per line (RFC9112-7.1.1-4 asks for a limit). It must not
;     hold a control character other than HTAB, so a CR or LF in it cannot split the line
;     differently for two parsers.
;   - Every line ends in CRLF; chunk-data is followed by CRLF.
;   - The trailer section is parsed like a head, every field flagged TRAILER and never merged
;     into the header section (RFC 9110 6.5.1).
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "h1/h1.inc"

section .text

; -----------------------------------------------------------------------------
; ha_h1_head_end: the end of a head (or trailer section): just past its first empty line.
;   In:  rdi = buf, rsi = len, rdx = start (the offset of the head's first line),
;        rcx = size_t *scan_from (the resume point; see httpasm_h1_parse_request), r8 = max
;        (the offset no head may end past).
;   Out: rax > 0 the end; 0 incomplete (*scan_from = len); -1 a bare LF; -2 over max. On
;        anything but 0, *scan_from is reset to 0.
;   An empty first line ends the head at once (an empty trailer section is just CRLF).
;   Keeps rbx, rbp, r12-r15. Clobbers the other general registers, xmm0, xmm1 and the flags.
; -----------------------------------------------------------------------------
global ha_h1_head_end:function hidden (ha_h1_head_end.end - ha_h1_head_end)
align 16
ha_h1_head_end:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15                             ; 5 pushes: rsp is 16-byte aligned for the calls
    mov     rbx, rdi
    mov     r12, rsi
    mov     r13, rdx
    mov     r14, rcx
    mov     r15, r8
    mov     rax, [r14]
    cmp     rax, r12
    cmova   rax, r13                        ; a stale resume point past the data
    cmp     rax, r13
    cmovb   rax, r13
.find:
    mov     r8, rax                         ; ha_find_lf keeps r8
    lea     rdi, [rbx + rax]
    mov     rsi, r12
    sub     rsi, rax
    call    ha_find_lf
    add     rax, r8
    cmp     rax, r12
    jae     .incomplete
    cmp     rax, r13
    jbe     .bare                           ; an LF that starts the first line
    cmp     byte [rbx + rax - 1], 0x0D
    jne     .bare
    lea     rdx, [r13 + 1]
    cmp     rax, rdx
    je      .found                          ; the first line is empty
    lea     rdx, [r13 + 3]
    cmp     rax, rdx
    jb      .next
    cmp     word [rbx + rax - 3], 0x0A0D
    je      .found                          ; CRLF CRLF
.next:
    inc     rax
    cmp     rax, r15
    ja      .large
    jmp     .find
.found:
    inc     rax
    cmp     rax, r15
    ja      .large
    mov     qword [r14], 0
    jmp     .out
.incomplete:
    cmp     r12, r15
    ja      .large
    mov     [r14], r12
    xor     eax, eax
    jmp     .out
.bare:
    mov     qword [r14], 0
    mov     rax, -1
    jmp     .out
.large:
    mov     qword [r14], 0
    mov     rax, -2
.out:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; int64_t httpasm_h1_chunked_decode(httpasm_h1_chunked *state, uint8_t *in, size_t len,
;                                   size_t *produced)
;   Decodes chunked framing in place. in[0..len) are body octets as received. The data octets
;   are moved to in[0..*produced) and the framing removed, so a buffer that keeps receiving can
;   be decoded call after call.
;   Returns the octets consumed (>= 0), or -400 when the framing is malformed (the state becomes
;   HTTPASM_CHUNKED_ERROR and stays so). The decoder stops right after the last chunk's line
;   (state HTTPASM_CHUNKED_TRAILERS): the trailer section starts at in[consumed], for
;   httpasm_h1_parse_trailers. state->total counts the data octets of the whole body.
;   In: rdi, rsi, rdx, rcx. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global httpasm_h1_chunked_decode:function (httpasm_h1_chunked_decode.end - httpasm_h1_chunked_decode)
align 16
httpasm_h1_chunked_decode:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    mov     rbx, rdi                        ; state
    mov     r12, rsi                        ; in
    mov     r13, rdx                        ; len
    mov     r14, rcx                        ; produced
    xor     r15d, r15d                      ; consumed
    xor     ebp, ebp                        ; produced so far
    cmp     dword [rbx + httpasm_h1_chunked.state], HTTPASM_CHUNKED_ERROR
    je      .malformed
    lea     r8, [rel ha_hex_value]

.next:
    cmp     r15, r13
    jae     .done
    mov     eax, [rbx + httpasm_h1_chunked.state]
    movzx   ecx, byte [r12 + r15]
    cmp     eax, HTTPASM_CHUNKED_SIZE
    je      .size
    cmp     eax, HTTPASM_CHUNKED_DATA
    je      .data
    cmp     eax, HTTPASM_CHUNKED_EXTENSION
    je      .extension
    cmp     eax, HTTPASM_CHUNKED_SIZE_LF
    je      .size_lf
    cmp     eax, HTTPASM_CHUNKED_DATA_CR
    je      .data_cr
    cmp     eax, HTTPASM_CHUNKED_DATA_LF
    je      .data_lf
    cmp     eax, HTTPASM_CHUNKED_EXTENSION_BWS
    je      .extension_bws
    jmp     .done                           ; TRAILERS: the trailer section is not ours

.size:                                      ; chunk-size = 1*HEXDIG
    movzx   edx, byte [r8 + rcx]
    cmp     edx, 0xFF
    je      .size_end
    cmp     dword [rbx + httpasm_h1_chunked.size_digits], 16
    jae     .malformed                      ; more than 64 bits of numeral
    mov     rax, [rbx + httpasm_h1_chunked.remaining]
    shr     rax, 59
    jnz     .malformed                      ; one more digit would pass 2^63: refused, not wrapped
    mov     rax, [rbx + httpasm_h1_chunked.remaining]
    shl     rax, 4
    or      rax, rdx
    mov     [rbx + httpasm_h1_chunked.remaining], rax
    inc     dword [rbx + httpasm_h1_chunked.size_digits]
    inc     r15
    jmp     .next
.size_end:
    cmp     dword [rbx + httpasm_h1_chunked.size_digits], 0
    je      .malformed                      ; no digit at all
    cmp     cl, 0x0D
    je      .to_size_lf
    cmp     cl, ';'
    je      .to_extension
    cmp     cl, ' '                         ; BWS, which only a ";" may follow
    je      .to_extension_bws
    cmp     cl, 9
    je      .to_extension_bws
    jmp     .malformed
.to_extension:
    mov     dword [rbx + httpasm_h1_chunked.state], HTTPASM_CHUNKED_EXTENSION
    mov     dword [rbx + httpasm_h1_chunked.extension_length], 1
    inc     r15
    jmp     .next
.to_extension_bws:
    mov     dword [rbx + httpasm_h1_chunked.state], HTTPASM_CHUNKED_EXTENSION_BWS
    mov     dword [rbx + httpasm_h1_chunked.extension_length], 1
    inc     r15
    jmp     .next

.extension_bws:                             ; chunk-ext = *( BWS ";" ... ): whitespace, then ";"
    cmp     cl, ';'
    jne     .extension_bws_space
    mov     dword [rbx + httpasm_h1_chunked.state], HTTPASM_CHUNKED_EXTENSION
    jmp     .extension_octet
.extension_bws_space:
    cmp     cl, ' '
    je      .extension_octet
    cmp     cl, 9
    je      .extension_octet
    jmp     .malformed                      ; "5 x" or "5 " CRLF: not chunk-ext's grammar
.to_size_lf:
    mov     dword [rbx + httpasm_h1_chunked.state], HTTPASM_CHUNKED_SIZE_LF
    inc     r15
    jmp     .next

.extension:                                 ; skipped up to CR; no CTL but HTAB inside
    cmp     cl, 0x0D
    je      .to_size_lf
    cmp     cl, 9
    je      .extension_octet
    cmp     cl, 0x20
    jb      .malformed                      ; LF, NUL and the other CTLs
    cmp     cl, 0x7F
    je      .malformed
.extension_octet:
    inc     dword [rbx + httpasm_h1_chunked.extension_length]
    cmp     dword [rbx + httpasm_h1_chunked.extension_length], HA_CHUNK_MAX_EXTENSION
    ja      .malformed
    inc     r15
    jmp     .next

.size_lf:
    cmp     cl, 0x0A
    jne     .malformed
    inc     r15
    mov     dword [rbx + httpasm_h1_chunked.size_digits], 0
    mov     dword [rbx + httpasm_h1_chunked.extension_length], 0
    cmp     qword [rbx + httpasm_h1_chunked.remaining], 0
    jne     .to_data
    mov     dword [rbx + httpasm_h1_chunked.state], HTTPASM_CHUNKED_TRAILERS
    jmp     .done                           ; last-chunk: the trailer section follows
.to_data:
    mov     dword [rbx + httpasm_h1_chunked.state], HTTPASM_CHUNKED_DATA
    jmp     .next

.data:                                      ; move min(remaining, available) octets down
    mov     rcx, r13
    sub     rcx, r15
    mov     rax, [rbx + httpasm_h1_chunked.remaining]
    cmp     rcx, rax
    cmova   rcx, rax                        ; the octets to take
    sub     [rbx + httpasm_h1_chunked.remaining], rcx
    add     [rbx + httpasm_h1_chunked.total], rcx
    cmp     rbp, r15
    je      .data_in_place                  ; nothing removed yet: the data already sits there
    lea     rsi, [r12 + r15]
    lea     rdi, [r12 + rbp]
    mov     rdx, rcx
    rep     movsb                           ; forward, destination below source: overlap-safe
    mov     rcx, rdx
.data_in_place:
    add     r15, rcx
    add     rbp, rcx
    cmp     qword [rbx + httpasm_h1_chunked.remaining], 0
    jne     .next
    mov     dword [rbx + httpasm_h1_chunked.state], HTTPASM_CHUNKED_DATA_CR
    jmp     .next

.data_cr:
    cmp     cl, 0x0D
    jne     .malformed
    mov     dword [rbx + httpasm_h1_chunked.state], HTTPASM_CHUNKED_DATA_LF
    inc     r15
    jmp     .next
.data_lf:
    cmp     cl, 0x0A
    jne     .malformed
    mov     dword [rbx + httpasm_h1_chunked.state], HTTPASM_CHUNKED_SIZE
    inc     r15
    jmp     .next

.done:
    mov     [r14], rbp
    mov     rax, r15
    jmp     .out
.malformed:
    mov     dword [rbx + httpasm_h1_chunked.state], HTTPASM_CHUNKED_ERROR
    mov     [r14], rbp
    mov     rax, -400
.out:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; int64_t httpasm_h1_parse_trailers(uint8_t *buf, size_t len, size_t *scan_from,
;                                   const httpasm_h1_limits *limits, httpasm_field *fields,
;                                   uint32_t *count)
;   The trailer section of a chunked body (trailer-section CRLF, RFC 9112 7.1.2), from buf[0]:
;   the octets after the last chunk's line. The fields go to fields[0..*count), each flagged
;   HTTPASM_FIELD_FLAG_TRAILER.
;   Returns the section's length (>= 2: an empty section is just CRLF), 0 when incomplete
;   (*scan_from as in httpasm_h1_parse_request), or -400 (malformed, a bare LF, obs-fold) /
;   -431 (over limits->max_head octets, or more than limits->max_fields fields).
;   In: rdi, rsi, rdx, rcx, r8, r9 (System V). Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
TR_FRAME_COUNT      equ h1ctx_size              ; uint32_t *count
TR_FRAME_SIZE       equ h1ctx_size + 8          ; the frame: rsp stays 16-byte aligned

global httpasm_h1_parse_trailers:function (httpasm_h1_parse_trailers.end - httpasm_h1_parse_trailers)
align 16
httpasm_h1_parse_trailers:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, TR_FRAME_SIZE
    mov     rbx, rdi
    mov     r12, rcx                        ; limits
    mov     [rsp + TR_FRAME_COUNT], r9
    mov     dword [r9], 0
    mov     [rsp + h1ctx.fields], r8
    mov     r8d, HA_H1_DEFAULT_MAX_HEAD
    mov     r13d, HA_H1_DEFAULT_MAX_FIELDS
    test    r12, r12
    jz      .limits_set
    mov     eax, [r12 + httpasm_h1_limits.max_head]
    test    eax, eax
    cmovnz  r8d, eax
    mov     eax, [r12 + httpasm_h1_limits.max_fields]
    test    eax, eax
    cmovnz  r13d, eax
.limits_set:
    mov     rdi, rbx
    mov     rcx, rdx                        ; scan_from
    xor     edx, edx                        ; the section starts at the buffer's start
    call    ha_h1_head_end
    test    rax, rax
    jz      .return                         ; incomplete
    cmp     rax, -1
    je      .malformed
    cmp     rax, -2
    je      .too_large
    mov     r14, rax                        ; the section's length
    mov     [rsp + h1ctx.buf], rbx
    mov     [rsp + h1ctx.head_end], rax
    mov     [rsp + h1ctx.max_fields], r13d
    mov     dword [rsp + h1ctx.count], 0
    mov     dword [rsp + h1ctx.mode], HA_H1_TRAILER
    mov     dword [rsp + h1ctx.seen], 0
    mov     dword [rsp + h1ctx.error], 0
    mov     dword [rsp + h1ctx.status], 0
    mov     dword [rsp + h1ctx.field_flags], HTTPASM_FIELD_FLAG_TRAILER
    mov     qword [rsp + h1ctx.request], 0
    mov     rdi, rsp
    xor     esi, esi
    call    ha_h1_fields
    mov     rcx, [rsp + TR_FRAME_COUNT]
    mov     edx, [rsp + h1ctx.count]
    mov     [rcx], edx
    test    eax, eax
    jnz     .fields_failed
    mov     rax, r14
    jmp     .return
.fields_failed:
    mov     eax, [rsp + h1ctx.status]
    neg     rax
    jmp     .return
.malformed:
    mov     rax, -400
    jmp     .return
.too_large:
    mov     rax, -431
.return:
    add     rsp, TR_FRAME_SIZE
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:
