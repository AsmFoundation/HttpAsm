; =============================================================================
; h1/response.asm - HTTP/1.1 response heads, the client's side: httpasm_h1_parse_response.
;
; Sans-I/O like the request parser: one head from the caller's buffer into the caller's
; httpasm_response_head and field array, with pointers into the buffer. The buffer is writable:
; a response's obs-fold is replaced with SP in place (RFC9112-5.2-6), which a server's request
; parser would refuse instead.
;
; Two flows give every head the same outcome, as in request.asm:
;   classic   the head's end first (ha_h1_head_end: the first CRLF CRLF, every LF checked for its
;             CR), then the status-line, then the field lines (ha_h1_fields, which rewrites an
;             obs-fold). Every tier runs it for a resumed search; v1 runs it always.
;   one-pass  v2 and up, for a head searched from its start (a response's first call): the
;             status-line and the field lines read once (ha_h1_fields_v2 in the response mode),
;             the empty line found on the way, every read below min(len, max_head). It only ever
;             accepts; anything else (a refusal, an incomplete or too large head, an obs-fold)
;             starts the classic flow over, which names the outcome (the proof is at .one_pass).
;             It saves the search for the end and a second pass over every line.
;
; The body's framing, by RFC 9112 section 6.3, which needs the request's method:
;   1. HEAD, and every 1xx, 204 and 304: no body (RFC 9112 6.3 item 1). A code outside
;      100-599 is invalid and framed as a 5xx's (RFC9110-15-6): 000-099 too are final answers
;      with a body, not interim ones, and never open a tunnel.
;   2. A 2xx to CONNECT, 204 included (RFC 9110 9.3.6: "Any 2xx"): the connection becomes a
;      tunnel after the head (TUNNEL with NO_BODY); Content-Length and Transfer-Encoding are
;      ignored (RFC9112-6.3-2.2). Checked before item 1's 204, which would otherwise hide it.
;   3. Transfer-Encoding: chunked as the final coding means chunked. Any other final coding
;      means the body runs until the server closes (item 4). In an HTTP/1.0 response the
;      framing is faulty (RFC9112-6.1-16): refused.
;   4. Content-Length: that many octets. An invalid one is refused: the user agent must close
;      and discard (RFC9112-6.3-2.5#4).
;   5. Otherwise, until the server closes (item 8).
; Persistence (RFC 9112 9.3): HTTP/1.1 unless close; HTTP/1.0 only with keep-alive; never when
; the body runs until the close.
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "h1/h1.inc"

extern ha_h1_head_end
extern ha_h1_fields_v2                      ; request.asm: the one-pass field lines (v2 and up)

section .text

; -----------------------------------------------------------------------------
; int64_t httpasm_h1_parse_response(uint8_t *buf, size_t len, size_t *scan_from,
;                                   const httpasm_h1_limits *limits, uint32_t request_method,
;                                   httpasm_response_head *head, httpasm_field *fields)
;   Returns the head's length (> 0), 0 when incomplete (*scan_from as in
;   httpasm_h1_parse_request), or -400 (malformed: head->error names the rule; the client must
;   close and discard) / -431 (over the limits). A 1xx is returned like a final response with
;   HTTPASM_RESPONSE_HEAD_NO_BODY; the final response follows it.
;   In: rdi, rsi, rdx, rcx, r8d, r9, and fields on the stack (System V). Keeps rbx, rbp, r12-r15.
;   Memory: reads buf[0..len) only, except that short scans may read up to 16 octets within the
;   page of their start (see HA_FIELD_VALUE_SCAN). Writes *head, *scan_from, the fields array,
;   and an obs-fold's octets in buf (the classic flow only: the one-pass flow never writes buf,
;   so a head it hands back is read again from the octets the caller passed).
; -----------------------------------------------------------------------------
RS_FRAME_SCAN_FROM  equ h1ctx_size              ; size_t *scan_from
RS_FRAME_METHOD     equ h1ctx_size + 8          ; uint32_t request_method
RS_FRAME_MAX_HEAD   equ h1ctx_size + 12         ; uint32_t
RS_FRAME_ONE_PASS   equ h1ctx_size + 16         ; uint32_t: 1 while the one-pass flow runs
RS_FRAME_SIZE       equ h1ctx_size + 32         ; 88 + 32: with the 6 pushes, rsp stays 16-byte aligned

global httpasm_h1_parse_response:function (httpasm_h1_parse_response.end - httpasm_h1_parse_response)
align 16
httpasm_h1_parse_response:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, RS_FRAME_SIZE
    mov     rbx, rdi                        ; buf
    mov     r12, rsi                        ; len
    mov     r14, r9                         ; head
    mov     r13, rsp                        ; the context
    mov     rax, [rsp + RS_FRAME_SIZE + 6 * 8 + 8] ; fields: the 7th argument, above the return address
    mov     [r13 + h1ctx.fields], rax
    mov     [rsp + RS_FRAME_SCAN_FROM], rdx
    mov     [rsp + RS_FRAME_METHOD], r8d
    mov     dword [rsp + RS_FRAME_ONE_PASS], 0  ; the classic flow until .one_pass says otherwise

    mov     eax, HA_H1_DEFAULT_MAX_HEAD
    mov     r11d, HA_H1_DEFAULT_MAX_FIELDS
    test    rcx, rcx
    jz      .limits_set
    mov     edx, [rcx + httpasm_h1_limits.max_head]
    test    edx, edx
    cmovnz  eax, edx
    mov     edx, [rcx + httpasm_h1_limits.max_fields]
    test    edx, edx
    cmovnz  r11d, edx
.limits_set:
    mov     [rsp + RS_FRAME_MAX_HEAD], eax
    mov     [r13 + h1ctx.max_fields], r11d
    mov     [r13 + h1ctx.buf], rbx
    xor     eax, eax
    mov     [r13 + h1ctx.request], rax
    mov     [r13 + h1ctx.content_length], rax
    mov     [r13 + h1ctx.count], eax
    mov     dword [r13 + h1ctx.mode], HA_H1_RESPONSE
    mov     [r13 + h1ctx.seen], eax
    mov     [r13 + h1ctx.error], eax
    mov     [r13 + h1ctx.status], eax
    mov     [r13 + h1ctx.field_flags], eax
    pxor    xmm0, xmm0                      ; a clean head record
    movdqu  [r14], xmm0
    movdqu  [r14 + 16], xmm0
    movdqu  [r14 + 32], xmm0
    movdqu  [r14 + 48], xmm0
    mov     rax, [r13 + h1ctx.fields]
    mov     [r14 + httpasm_response_head.fields], rax

    ; From v2 up, a head searched from its start (a response's first call, or a resume point
    ; past the data, which the search ignores) is parsed in one pass (.one_pass). A resumed
    ; search keeps this flow, which scans only the octets that arrived since.
    mov     rcx, [rsp + RS_FRAME_SCAN_FROM]
    mov     rax, [rcx]
    test    rax, rax
    jz      .from_the_start
    cmp     rax, r12
    jbe     .classic
.from_the_start:
    HA_CPU_PICK1 HTTPASM_CPU_V2, .one_pass
.classic:
    ; The head's end.
    mov     rdi, rbx
    mov     rsi, r12
    xor     edx, edx
    mov     rcx, [rsp + RS_FRAME_SCAN_FROM]
    mov     r8d, [rsp + RS_FRAME_MAX_HEAD]
    call    ha_h1_head_end
    test    rax, rax
    jz      .return                         ; incomplete
    cmp     rax, -1
    je      .bare_lf
    cmp     rax, -2
    je      .too_large
    mov     rbp, rax                        ; the head's end
    mov     [r13 + h1ctx.head_end], rbp
    mov     [r14 + httpasm_response_head.head_length], ebp

    ; status-line = HTTP-version SP status-code SP [ reason-phrase ] CRLF
    mov     rdi, rbx
    mov     rsi, rbp
    call    ha_find_lf
    mov     r15, rax                        ; the status-line's LF
    lea     rcx, [r15 - 1]                  ; its CR
    cmp     rcx, 13
    jb      .bad_status_line                ; "HTTP/1.1 200 " is 13 octets at least
    cmp     dword [rbx], 'HTTP'
    jne     .bad_version
    cmp     byte [rbx + 4], '/'
    jne     .bad_version
    movzx   eax, byte [rbx + 5]
    sub     eax, '0'
    cmp     eax, 9
    ja      .bad_version
    cmp     byte [rbx + 6], '.'
    jne     .bad_version
    movzx   edx, byte [rbx + 7]
    sub     edx, '0'
    cmp     edx, 9
    ja      .bad_version
    cmp     eax, 1
    jne     .bad_version                    ; a client of HTTP/1.x reads 1.x responses only
    mov     r8d, 11
    test    edx, edx
    jnz     .version_set
    mov     r8d, 10
.version_set:
    mov     [r14 + httpasm_response_head.version], r8b
    cmp     byte [rbx + 8], ' '
    jne     .bad_status_line
    xor     eax, eax                        ; status-code = 3DIGIT
    mov     r9d, 9
.status_digit:
    movzx   edx, byte [rbx + r9]
    sub     edx, '0'
    cmp     edx, 9
    ja      .bad_status_line
    imul    eax, eax, 10
    add     eax, edx
    inc     r9d
    cmp     r9d, 12
    jb      .status_digit
    mov     [r14 + httpasm_response_head.status], ax
    cmp     byte [rbx + 12], ' '
    jne     .bad_status_line
    ; reason-phrase: up to the CR, no CTL but HTAB.
    lea     rdi, [rbx + 13]
    lea     rsi, [rcx - 13]
    mov     [r14 + httpasm_response_head.reason], rdi
    mov     [r14 + httpasm_response_head.reason_length], esi
    HA_FIELD_VALUE_SCAN rdi, rsi, rax, rcx, ecx, rdx, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5
    cmp     rax, rsi
    jne     .bad_status_line

    ; The field lines.
    mov     rdi, r13
    lea     rsi, [r15 + 1]
    call    ha_h1_fields
    mov     ecx, [r13 + h1ctx.count]
    mov     [r14 + httpasm_response_head.field_count], ecx
    test    eax, eax
    jnz     .fields_failed

.framing:                                   ; both flows: rbp = the head's end
    ; The body's framing (this file's header).
    mov     eax, [r13 + h1ctx.seen]
    movzx   ecx, word [r14 + httpasm_response_head.status]
    mov     edx, [rsp + RS_FRAME_METHOD]
    xor     r8d, r8d                        ; the flags
    cmp     edx, HTTPASM_METHOD_HEAD
    je      .no_body
    cmp     ecx, 100
    jb      .framed_body                    ; 000-099: an invalid code, framed as a 5xx's (RFC9110-15-6):
                                            ; a body, and never a tunnel, whatever the method
    cmp     ecx, 200
    jb      .no_body                        ; 1xx (known or not: RFC9110-15-4) has no content
    ; Every 2xx to CONNECT makes a tunnel, 204 included (RFC9110-9.3.6: "Any 2xx"), so this
    ; comes before 204's own rule: a 204 ends at its empty line either way (TUNNEL comes with
    ; NO_BODY), but read as a plain 204 the octets after it would be taken for the next
    ; response instead of the tunnel's. tests/fuzz/h1_response found the order wrong
    ; (2026-11-26): a 204 to CONNECT was no tunnel, and a 099 to CONNECT was one.
    cmp     ecx, 300
    jae     .not_successful
    cmp     edx, HTTPASM_METHOD_CONNECT
    je      .tunnel
.not_successful:
    cmp     ecx, 204
    je      .no_body
    cmp     ecx, 304
    je      .no_body
.framed_body:
    test    eax, HA_SEEN_TE
    jz      .no_transfer_encoding
    cmp     byte [r14 + httpasm_response_head.version], 10
    je      .te_http10
    test    eax, HA_SEEN_BAD_CODING | HA_SEEN_AFTER_CHUNKED
    jnz     .until_close
    test    eax, HA_SEEN_CHUNKED
    jz      .until_close
    mov     r8d, HTTPASM_RESPONSE_HEAD_CHUNKED
    jmp     .persistence
.no_transfer_encoding:
    test    eax, HA_SEEN_CONTENT_LENGTH
    jz      .until_close
    mov     rdx, [r13 + h1ctx.content_length]
    mov     [r14 + httpasm_response_head.content_length], rdx
    mov     r8d, HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH
    jmp     .persistence
.until_close:
    mov     r8d, HTTPASM_RESPONSE_HEAD_UNTIL_CLOSE
    jmp     .flags_set                      ; ends at the close: never persists
.tunnel:
    mov     r8d, HTTPASM_RESPONSE_HEAD_TUNNEL | HTTPASM_RESPONSE_HEAD_NO_BODY
    jmp     .flags_set
.no_body:
    mov     r8d, HTTPASM_RESPONSE_HEAD_NO_BODY
.persistence:
    test    eax, HA_SEEN_CLOSE
    jnz     .flags_set
    cmp     byte [r14 + httpasm_response_head.version], 11
    je      .persists
    test    eax, HA_SEEN_KEEP_ALIVE
    jz      .flags_set
.persists:
    or      r8d, HTTPASM_RESPONSE_HEAD_KEEP_ALIVE
.flags_set:
    mov     [r14 + httpasm_response_head.flags], r8d
    mov     rax, rbp
    jmp     .return

.fields_failed:
    mov     ecx, [r13 + h1ctx.error]
    mov     edx, [r13 + h1ctx.status]
    jmp     .fail
.bare_lf:
    mov     ecx, HTTPASM_ERROR_BARE_LF
    mov     edx, 400
    jmp     .fail
.too_large:
    mov     ecx, HTTPASM_ERROR_HEAD_TOO_LARGE
    mov     edx, 431
    jmp     .fail
.bad_version:
    mov     ecx, HTTPASM_ERROR_VERSION
    mov     edx, 400
    jmp     .fail
.bad_status_line:
    mov     ecx, HTTPASM_ERROR_STATUS
    mov     edx, 400
    jmp     .fail
.te_http10:
    mov     ecx, HTTPASM_ERROR_TE_HTTP10
    mov     edx, 400
.fail:
    cmp     dword [rsp + RS_FRAME_ONE_PASS], 0
    jne     .one_pass_bail                  ; the one-pass flow never refuses: see .one_pass
    mov     [r14 + httpasm_response_head.error], cx
    mov     rax, [rsp + RS_FRAME_SCAN_FROM]
    mov     qword [rax], 0
    mov     rax, rdx
    neg     rax
.return:
    add     rsp, RS_FRAME_SIZE
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- The one-pass flow (v2 and up), as httpasm_h1_parse_request's (request.asm .one_pass) ----
; A head searched from its start is parsed without searching for its end first: the
; status-line here (the classic checks, then the reason-phrase 16 octets a step to its CR), the
; field lines by ha_h1_fields_v2 in the response mode, which finds the empty line on the way;
; the framing after .framing is the classic code's. Reads stay below B = min(len, max_head) (rbp
; holds it until the head's end replaces it). The flow only ever accepts: anything else - a
; refusal, B cutting the head, an obs-fold line (which only the classic flow rewrites), a step
; near B that would read into another page - goes to .one_pass_bail, which starts the classic
; flow over, and the classic flow names the outcome. A head accepted here has every line checked
; by the same rules and ended by CRLF, so no bare LF precedes its end, its end is the first
; CRLF CRLF and it holds no obs-fold: the classic flow would read it the same way.
.one_pass:
    mov     dword [rsp + RS_FRAME_ONE_PASS], 1
    mov     ecx, [rsp + RS_FRAME_MAX_HEAD]
    mov     rbp, r12
    cmp     rbp, rcx
    cmova   rbp, rcx                        ; B
    ; status-line = HTTP-version SP status-code SP [ reason-phrase ] CRLF: 13 fixed octets, then
    ; the reason to the first octet a value may not hold, which must be the line's CR.
    cmp     rbp, 15
    jb      .one_pass_bail                  ; not even an empty reason's CRLF before B
    cmp     dword [rbx], 'HTTP'
    jne     .one_pass_bail
    cmp     byte [rbx + 4], '/'
    jne     .one_pass_bail
    cmp     byte [rbx + 5], '1'
    jne     .one_pass_bail                  ; HTTP/1.x only (the classic flow refuses the rest)
    cmp     byte [rbx + 6], '.'
    jne     .one_pass_bail
    movzx   edx, byte [rbx + 7]
    sub     edx, '0'
    cmp     edx, 9
    ja      .one_pass_bail
    mov     r8d, 11                         ; 1.1, and 1.2+ as 1.1
    test    edx, edx
    jnz     .one_pass_version
    mov     r8d, 10
.one_pass_version:
    mov     [r14 + httpasm_response_head.version], r8b
    cmp     byte [rbx + 8], ' '
    jne     .one_pass_bail
    xor     eax, eax                        ; status-code = 3DIGIT
    mov     r9d, 9
.one_pass_digit:
    movzx   edx, byte [rbx + r9]
    sub     edx, '0'
    cmp     edx, 9
    ja      .one_pass_bail
    imul    eax, eax, 10
    add     eax, edx
    inc     r9d
    cmp     r9d, 12
    jb      .one_pass_digit
    mov     [r14 + httpasm_response_head.status], ax
    cmp     byte [rbx + 12], ' '
    jne     .one_pass_bail
    movdqa  xmm3, [rel ha_x16_1f]
    movdqa  xmm4, [rel ha_x16_09]
    movdqa  xmm5, [rel ha_x16_7f]
    lea     rsi, [rbx + rbp - 17]           ; the last 16-octet step with an octet to spare
    lea     rax, [rbx + 13]
.one_pass_reason:
    cmp     rax, rsi
    ja      .one_pass_reason_edge
    movdqu  xmm0, [rax]
    HA_FIELD_VALUE_CLASSIFY xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, ecx
    test    ecx, ecx
    jnz     .one_pass_reason_stop
    add     rax, 16
    jmp     .one_pass_reason
.one_pass_reason_stop:
    bsf     ecx, ecx
    add     rax, rcx
.one_pass_reason_end:                       ; rax: that octet, with the next one below B
    cmp     word [rax], 0x0A0D
    jne     .one_pass_bail                  ; a CTL, or a CR without its LF
    sub     rax, rbx                        ; the CR's offset
    lea     rdi, [rbx + 13]
    mov     [r14 + httpasm_response_head.reason], rdi
    lea     rcx, [rax - 13]
    mov     [r14 + httpasm_response_head.reason_length], ecx
    ; The field lines, with their end.
    mov     [r13 + h1ctx.head_end], rbp     ; B, for ha_h1_fields_v2
    mov     rdi, r13
    lea     rsi, [rax + 2]
    call    ha_h1_fields_v2
    mov     ecx, [r13 + h1ctx.count]
    mov     [r14 + httpasm_response_head.field_count], ecx
    test    eax, eax
    jnz     .one_pass_bail
    mov     rbp, [r13 + h1ctx.head_end]     ; just past the empty line's CRLF
    mov     [r14 + httpasm_response_head.head_length], ebp
    mov     rax, [rsp + RS_FRAME_SCAN_FROM]
    mov     qword [rax], 0                  ; as ha_h1_head_end leaves a found head
    jmp     .framing
.one_pass_reason_edge:                      ; fewer than 17 octets before B
    lea     rdx, [rbx + rbp]
    sub     rdx, rax                        ; the octets before B
    jle     .one_pass_bail
    mov     ecx, eax
    and     ecx, 4095
    cmp     ecx, 4096 - 16
    ja      .one_pass_bail                  ; 16 octets would reach the next page
    movdqu  xmm0, [rax]
    HA_FIELD_VALUE_CLASSIFY xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, ecx
    bsf     ecx, ecx
    jz      .one_pass_bail                  ; no stop in 16 octets: B cuts the line
    inc     rcx
    cmp     rcx, rdx
    jae     .one_pass_bail                  ; the stop's LF would lie at or past B
    lea     rax, [rax + rcx - 1]
    jmp     .one_pass_reason_end

.one_pass_bail:
    ; The classic flow from the start, as if this attempt had not run: the context's findings
    ; and the head record cleared as the entry clears them.
    mov     dword [rsp + RS_FRAME_ONE_PASS], 0
    xor     eax, eax
    mov     [r13 + h1ctx.content_length], rax
    mov     [r13 + h1ctx.count], eax
    mov     [r13 + h1ctx.seen], eax
    mov     [r13 + h1ctx.error], eax
    mov     [r13 + h1ctx.status], eax
    pxor    xmm0, xmm0
    movdqu  [r14], xmm0
    movdqu  [r14 + 16], xmm0
    movdqu  [r14 + 32], xmm0
    movdqu  [r14 + 48], xmm0
    mov     rax, [r13 + h1ctx.fields]
    mov     [r14 + httpasm_response_head.fields], rax
    jmp     .classic
.end:
