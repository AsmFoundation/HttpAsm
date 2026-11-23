; =============================================================================
; h1/write.asm - HTTP/1.1 messages out: httpasm_h1_write_response (a server's head),
; httpasm_h1_write_request (a client's head), httpasm_h1_write_chunk and
; httpasm_h1_write_last_chunk (the chunked coding).
;
; The writers own the framing. A caller describes the body (its length, or none known) and the
; writer picks the fields and reports the choice. A caller's own Content-Length,
; Transfer-Encoding, Connection or (requests) Host field is refused (HTTPASM_ERROR_FRAMING_FIELD),
; so a message can never carry two framings. Every input is checked before anything is written:
; a refusal leaves the output untouched.
;
; Rules, by registry row (specs/requirements.tsv):
;   - No Content-Length or Transfer-Encoding in a 1xx or 204 response, nor in a 2xx to CONNECT
;     (RFC9110-8.6-8#1, #2; RFC9112-6.1-10#1, #2). A 304 gets neither either: both are optional
;     there (RFC9110-8.6-7#1, RFC9112-6.1-9).
;   - HEAD: Content-Length when the caller gives the length its GET would carry
;     (RFC9110-8.6-6#1), no body.
;   - 205 carries no content (RFC9110-15.3.6-3): Content-Length: 0 only; a body, or one of
;     unknown length, is refused (HTTPASM_ERROR_STATUS).
;   - A body of unknown length: chunked for HTTP/1.1. HTTP/1.0 never gets Transfer-Encoding
;     (RFC9112-6.1-13#2), so the body runs to the connection's close instead.
;   - Date on final responses when the caller supplies the clock's value (RFC 9110 6.6.1).
;   - Connection: close when the connection closes after the response (RFC9112-9.6-1,
;     RFC9112-9.6-6#2); keep-alive for a persisting HTTP/1.0 connection.
;   - Field values are sent as valid field-value: no CTL but HTAB, no leading or trailing
;     whitespace (RFC9110-2.2-5#1).
;   - Requests put Host first (RFC9110-7.2-4#2) and carry exactly one framing.
; Return values: > 0 the octets written; 0 the output was too small (nothing usable written);
; < 0 -HTTPASM_ERROR_* (nothing written).
; =============================================================================
default rel
%include "httpasm_core.inc"

section .rodata
%include "generated/status.inc"             ; ha_status_line, ha_status_text

s_http11:       db "HTTP/1.1 "
s_http11_len    equ $ - s_http11
s_request_tail: db " HTTP/1.1", 13, 10
s_request_tail_len equ $ - s_request_tail
s_date:         db "Date: "
s_date_len      equ $ - s_date
s_length:       db "Content-Length: "
s_length_len    equ $ - s_length
s_chunked:      db "Transfer-Encoding: chunked", 13, 10
s_chunked_len   equ $ - s_chunked
s_close:        db "Connection: close", 13, 10
s_close_len     equ $ - s_close
s_keep_alive:   db "Connection: keep-alive", 13, 10
s_keep_alive_len equ $ - s_keep_alive
s_expect:       db "Expect: 100-continue", 13, 10
s_expect_len    equ $ - s_expect
s_host:         db "Host: "
s_host_len      equ $ - s_host
s_colon:        db ": "
s_crlf:         db 13, 10
s_space_crlf:   db " ", 13, 10
s_last_chunk:   db "0", 13, 10
s_hex_digits:   db "0123456789abcdef"

; The fields each writer owns. A caller's field with one of these ids is refused.
WR_RESPONSE     equ 0
WR_REQUEST      equ 1
WR_TRAILER      equ 2
WR_H2_RESPONSE  equ 3       ; an HTTP/2 response: as WR_RESPONSE, and Upgrade too (RFC 9113 8.2.2)

section .text

; -----------------------------------------------------------------------------
; wr_put: append rsi[0..rdx) at the cursor.
;   In: rbx = cursor, r13 = the output's end, rsi, rdx. Out: rbx advanced, CF clear; or CF set
;   when the output is full (nothing appended). Clobbers rcx, rdi, rsi.
; -----------------------------------------------------------------------------
align 16
wr_put:
    mov     rcx, r13
    sub     rcx, rbx
    cmp     rcx, rdx
    jb      .full                           ; CF is set by the compare
    mov     rdi, rbx
    mov     rcx, rdx
    rep     movsb
    mov     rbx, rdi
    clc
    ret
.full:
    stc
    ret

; -----------------------------------------------------------------------------
; wr_decimal / wr_hex: append rax in decimal / lower-case hex, no leading zeros ("0" for 0).
;   In: rbx, r13 as wr_put; rax. Out: as wr_put. Clobbers rax, rcx, rdx, rsi, rdi, r8, r9.
;   The digits are built backwards in a 32-octet stack buffer (a u64 has at most 20 decimal or
;   16 hex digits), then appended in one wr_put.
; -----------------------------------------------------------------------------
align 16
wr_decimal:
    sub     rsp, 40                         ; 32 for the digits, 8 keeps the stack aligned
    lea     r8, [rsp + 32]                  ; one past the last digit
    mov     r9, r8
    mov     rcx, 10
.digit:
    xor     edx, edx
    div     rcx
    add     dl, '0'
    dec     r9
    mov     [r9], dl
    test    rax, rax
    jnz     .digit
    mov     rsi, r9
    mov     rdx, r8
    sub     rdx, r9
    call    wr_put
    lea     rsp, [rsp + 40]                 ; lea keeps the flags wr_put left
    ret

align 16
wr_hex:
    sub     rsp, 40
    lea     r8, [rsp + 32]
    mov     r9, r8
    lea     rsi, [rel s_hex_digits]
.digit:
    mov     ecx, eax
    and     ecx, 15
    movzx   ecx, byte [rsi + rcx]
    dec     r9
    mov     [r9], cl
    shr     rax, 4
    jnz     .digit
    mov     rsi, r9
    mov     rdx, r8
    sub     rdx, r9
    call    wr_put
    lea     rsp, [rsp + 40]
    ret

; -----------------------------------------------------------------------------
; wr_check_fields (also ha_check_fields, for the driver's HTTP/2 responses): are
; fields[0..count) fit to send?
;   In: rdi = fields, esi = count, edx = WR_RESPONSE, WR_REQUEST, WR_TRAILER or WR_H2_RESPONSE.
;   Out: eax = 0, or HTTPASM_ERROR_FIELD_NAME (not a token), _FIELD_VALUE (a CTL, or whitespace
;   at an end), _FRAMING_FIELD (an id the writer owns); ecx = 1 when a Date field is among
;   them. Clobbers rdx, rsi, rdi, r8-r11, xmm0-xmm5 and the flags. Keeps rbx, rbp, r12-r15.
;   One rule set for every version's responses: a field HTTP/1.1 would refuse to send is
;   refused in HTTP/2 too, so a handler cannot behave differently per version by accident.
; -----------------------------------------------------------------------------
global ha_check_fields:function hidden
align 16
ha_check_fields:
wr_check_fields:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    mov     r12, rdi                        ; the record
    mov     r13d, esi                       ; the records left
    mov     r14d, edx                       ; the kind of message
    xor     r15d, r15d                      ; a Date field seen
.field:
    test    r13d, r13d
    jz      .ok
    ; The name: a token. The id the caller set is not trusted: it is looked up again.
    mov     rdi, [r12 + httpasm_field.name]
    mov     esi, [r12 + httpasm_field.name_length]
    test    esi, esi
    jz      .bad_name
    HA_TOKEN_SCAN rdi, rsi, rax, rcx, rdx
    cmp     rax, rsi
    jne     .bad_name
    call    ha_field_lookup                 ; eax = the id (rdi, rsi kept)
    cmp     eax, HA_FIELD_DATE
    jne     .owned
    mov     r15d, 1
.owned:
    cmp     eax, HA_FIELD_CONTENT_LENGTH
    je      .framing
    cmp     eax, HA_FIELD_TRANSFER_ENCODING
    je      .framing
    cmp     eax, HA_FIELD_CONNECTION
    je      .framing
    cmp     eax, HA_FIELD_KEEP_ALIVE
    je      .framing
    cmp     eax, HA_FIELD_PROXY_CONNECTION
    je      .framing
    ; TE travels only in a request, together with "Connection: TE" (RFC 9110 10.1.4), and the
    ; Connection field is the writer's. HttpAsm's client does not offer TE yet, so it is refused
    ; in every kind of message.
    cmp     eax, HA_FIELD_TE
    je      .framing
    cmp     r14d, WR_RESPONSE
    je      .value
    cmp     r14d, WR_H2_RESPONSE
    jne     .request_rules
    cmp     eax, HA_FIELD_UPGRADE           ; connection-specific in HTTP/2 (RFC9113-8.2.2-1)
    je      .framing
    jmp     .value
.request_rules:
    cmp     eax, HA_FIELD_HOST              ; requests and trailers: Host is the writer's
    je      .framing
    cmp     eax, HA_FIELD_EXPECT
    je      .framing
    cmp     eax, HA_FIELD_UPGRADE
    je      .framing
    cmp     r14d, WR_TRAILER
    jne     .value
    cmp     eax, HA_FIELD_TRAILER           ; never in a trailer section itself
    je      .framing
.value:
    ; The value: no CTL but HTAB, and no whitespace at either end (field-value's grammar).
    mov     rdi, [r12 + httpasm_field.value]
    mov     esi, [r12 + httpasm_field.value_length]
    test    esi, esi
    jz      .next                           ; an empty value is valid
    movzx   eax, byte [rdi]
    cmp     al, ' '
    je      .bad_value
    cmp     al, 9
    je      .bad_value
    movzx   eax, byte [rdi + rsi - 1]
    cmp     al, ' '
    je      .bad_value
    cmp     al, 9
    je      .bad_value
    HA_FIELD_VALUE_SCAN rdi, rsi, rax, rcx, ecx, rdx, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5
    cmp     rax, rsi
    jne     .bad_value
.next:
    add     r12, httpasm_field_size
    dec     r13d
    jmp     .field
.ok:
    xor     eax, eax
    mov     ecx, r15d
    jmp     .out
.bad_name:
    mov     eax, HTTPASM_ERROR_FIELD_NAME
    jmp     .out
.bad_value:
    mov     eax, HTTPASM_ERROR_FIELD_VALUE
    jmp     .out
.framing:
    mov     eax, HTTPASM_ERROR_FRAMING_FIELD
.out:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; wr_fields: append "name: value" CRLF for each of fields[0..count).
;   In: rbx, r13 as wr_put; r14 = fields, r15d = count. Out: CF set when the output is full.
;   Clobbers rcx, rdx, rsi, rdi, r14, r15.
; -----------------------------------------------------------------------------
align 16
wr_fields:
.field:
    test    r15d, r15d
    jz      .done
    mov     rsi, [r14 + httpasm_field.name]
    mov     edx, [r14 + httpasm_field.name_length]
    call    wr_put
    jc      .full
    lea     rsi, [rel s_colon]
    mov     edx, 2
    call    wr_put
    jc      .full
    mov     rsi, [r14 + httpasm_field.value]
    mov     edx, [r14 + httpasm_field.value_length]
    call    wr_put
    jc      .full
    lea     rsi, [rel s_crlf]
    mov     edx, 2
    call    wr_put
    jc      .full
    add     r14, httpasm_field_size
    dec     r15d
    jmp     .field
.done:
    clc
.full:
    ret

; -----------------------------------------------------------------------------
; int64_t httpasm_h1_write_response(uint8_t *out, size_t cap, httpasm_response *response)
;   A response's head (status-line, the writer's framing fields, the caller's fields, CRLF)
;   into out[0..cap). response->flags is in and out: give HTTPASM_RESPONSE_LENGTH with
;   content_length when the body's length is known, and HTTPASM_RESPONSE_CLOSE when the
;   connection will close. The writer adds HTTPASM_RESPONSE_CHUNKED (send the body with
;   httpasm_h1_write_chunk and _last_chunk), HTTPASM_RESPONSE_NO_BODY (send nothing after the
;   head), or HTTPASM_RESPONSE_CLOSE (an HTTP/1.0 body of unknown length ends at the close).
;   A 1xx is an interim response: its status-line and the caller's fields only.
;   Returns the head's length, 0 if cap is too small, or -HTTPASM_ERROR_STATUS /
;   _FIELD_NAME / _FIELD_VALUE / _FRAMING_FIELD.
;   In: rdi, rsi, rdx. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global httpasm_h1_write_response:function (httpasm_h1_write_response.end - httpasm_h1_write_response)
align 16
httpasm_h1_write_response:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 8
    mov     r12, rdi                        ; the output's start
    lea     r13, [rdi + rsi]                ; its end
    mov     r14, rdx                        ; the response
    mov     rbx, rdi                        ; the cursor
    movzx   eax, word [r14 + httpasm_response.status]
    cmp     eax, 100
    jb      .bad_status
    cmp     eax, 599
    ja      .bad_status
    cmp     eax, 200
    jae     .status_ok
    cmp     byte [r14 + httpasm_response.request_version], 11
    jb      .bad_status                     ; no 1xx to an HTTP/1.0 client (RFC9110-15.2-1)
.status_ok:
    mov     rdi, [r14 + httpasm_response.fields]
    mov     esi, [r14 + httpasm_response.field_count]
    mov     edx, WR_RESPONSE
    call    wr_check_fields
    test    eax, eax
    jnz     .refused
    mov     r15d, ecx                       ; the caller sent its own Date

    ; The framing (ebp = the flags out).
    mov     ebp, [r14 + httpasm_response.flags]
    and     ebp, HTTPASM_RESPONSE_LENGTH | HTTPASM_RESPONSE_CLOSE
    movzx   eax, word [r14 + httpasm_response.status]
    movzx   ecx, byte [r14 + httpasm_response.request_method]
    ; 205 (Reset Content) carries no content (RFC9110-15.3.6-3): only a declared length of 0
    ; may go out with it; a body, or one of unknown length, is refused before anything is written.
    cmp     eax, 205
    jne     .not_reset_content
    test    ebp, HTTPASM_RESPONSE_LENGTH
    jz      .bad_status
    cmp     qword [r14 + httpasm_response.content_length], 0
    jne     .bad_status
.not_reset_content:
    cmp     eax, 200
    jb      .no_framing                     ; 1xx
    cmp     eax, 204
    je      .no_framing
    cmp     eax, 304
    je      .no_framing
    cmp     ecx, HTTPASM_METHOD_CONNECT
    jne     .not_tunnel
    cmp     eax, 300
    jb      .no_framing                     ; 2xx to CONNECT: a tunnel
.not_tunnel:
    cmp     ecx, HTTPASM_METHOD_HEAD
    je      .head
    test    ebp, HTTPASM_RESPONSE_LENGTH
    jnz     .framed
    cmp     byte [r14 + httpasm_response.request_version], 11
    jb      .until_close
    or      ebp, HTTPASM_RESPONSE_CHUNKED
    jmp     .framed
.until_close:
    or      ebp, HTTPASM_RESPONSE_CLOSE     ; HTTP/1.0: never Transfer-Encoding
    jmp     .framed
.head:
    or      ebp, HTTPASM_RESPONSE_NO_BODY   ; Content-Length stays if the caller gave it
    jmp     .framed
.no_framing:
    and     ebp, ~HTTPASM_RESPONSE_LENGTH
    or      ebp, HTTPASM_RESPONSE_NO_BODY
.framed:

    ; The status-line: the registered line, or "HTTP/1.1 NNN " with an empty reason.
    movzx   eax, word [r14 + httpasm_response.status]
    lea     rcx, [rel ha_status_line]
    mov     edx, [rcx + rax * 4 - 400]
    test    edx, edx
    jz      .unregistered
    mov     esi, edx
    shr     esi, 8
    and     edx, 0xFF
    lea     rcx, [rel ha_status_text]
    add     rsi, rcx
    call    wr_put
    jc      .full
    jmp     .status_done
.unregistered:
    lea     rsi, [rel s_http11]
    mov     edx, s_http11_len
    call    wr_put
    jc      .full
    movzx   eax, word [r14 + httpasm_response.status]
    call    wr_decimal
    jc      .full
    lea     rsi, [rel s_space_crlf]
    mov     edx, 3
    call    wr_put
    jc      .full
.status_done:
    cmp     word [r14 + httpasm_response.status], 200
    jb      .caller_fields                  ; an interim response: no framing, no Date

    test    r15d, r15d
    jnz     .no_date
    mov     rax, [r14 + httpasm_response.date]
    test    rax, rax
    jz      .no_date
    lea     rsi, [rel s_date]
    mov     edx, s_date_len
    call    wr_put
    jc      .full
    mov     rsi, [r14 + httpasm_response.date]
    mov     edx, 29                         ; IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT"
    call    wr_put
    jc      .full
    lea     rsi, [rel s_crlf]
    mov     edx, 2
    call    wr_put
    jc      .full
.no_date:
    test    ebp, HTTPASM_RESPONSE_LENGTH
    jz      .no_length
    lea     rsi, [rel s_length]
    mov     edx, s_length_len
    call    wr_put
    jc      .full
    mov     rax, [r14 + httpasm_response.content_length]
    call    wr_decimal
    jc      .full
    lea     rsi, [rel s_crlf]
    mov     edx, 2
    call    wr_put
    jc      .full
.no_length:
    test    ebp, HTTPASM_RESPONSE_CHUNKED
    jz      .no_chunked
    lea     rsi, [rel s_chunked]
    mov     edx, s_chunked_len
    call    wr_put
    jc      .full
.no_chunked:
    test    ebp, HTTPASM_RESPONSE_CLOSE
    jz      .keep_alive
    lea     rsi, [rel s_close]
    mov     edx, s_close_len
    call    wr_put
    jc      .full
    jmp     .caller_fields
.keep_alive:
    cmp     byte [r14 + httpasm_response.request_version], 10
    jne     .caller_fields
    lea     rsi, [rel s_keep_alive]
    mov     edx, s_keep_alive_len
    call    wr_put
    jc      .full

.caller_fields:
    mov     rax, r14                        ; wr_fields walks r14/r15: keep the response
    mov     [rsp], rax
    mov     r14, [rax + httpasm_response.fields]
    mov     r15d, [rax + httpasm_response.field_count]
    call    wr_fields
    mov     r14, [rsp]
    jc      .full
    lea     rsi, [rel s_crlf]
    mov     edx, 2
    call    wr_put
    jc      .full
    mov     [r14 + httpasm_response.flags], ebp
    mov     rax, rbx
    sub     rax, r12
    jmp     .return
.full:
    xor     eax, eax
    jmp     .return
.bad_status:
    mov     eax, HTTPASM_ERROR_STATUS
.refused:
    neg     rax                             ; eax held the error: -error in rax
.return:
    add     rsp, 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; int64_t httpasm_h1_write_request(uint8_t *out, size_t cap, const httpasm_request *request)
;   A request's head, from the client's description in an httpasm_request: method, target,
;   authority (Host's value, sent first; may be empty), fields and field_count, and flags:
;   HTTPASM_REQUEST_CONTENT_LENGTH with content_length, or HTTPASM_REQUEST_CHUNKED (not both);
;   HTTPASM_REQUEST_CLOSE adds Connection: close; HTTPASM_REQUEST_EXPECT_CONTINUE adds Expect,
;   but only to a request with content (chunked, or a Content-Length above 0): without content
;   the flag is ignored (RFC9110-10.1.1-11.1).
;   Always HTTP/1.1. Returns the head's length, 0 if cap is too small, or -HTTPASM_ERROR_METHOD
;   / _TARGET / _AUTHORITY / _FIELD_NAME / _FIELD_VALUE / _FRAMING_FIELD.
;   In: rdi, rsi, rdx. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global httpasm_h1_write_request:function (httpasm_h1_write_request.end - httpasm_h1_write_request)
align 16
httpasm_h1_write_request:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 8
    mov     r12, rdi
    lea     r13, [rdi + rsi]
    mov     r14, rdx
    mov     rbx, rdi

    ; The method: a token.
    mov     rdi, [r14 + httpasm_request.method]
    mov     esi, [r14 + httpasm_request.method_length]
    test    esi, esi
    jz      .bad_method
    HA_TOKEN_SCAN rdi, rsi, rax, rcx, rdx
    cmp     rax, rsi
    jne     .bad_method
    ; The target: URI octets, whole percent-encodings, not empty.
    mov     rdi, [r14 + httpasm_request.target]
    mov     esi, [r14 + httpasm_request.target_length]
    test    esi, esi
    jz      .bad_target
    lea     r8, [rel ha_char_class]
    lea     r9, [rel ha_hex_value]
    xor     ecx, ecx
.target_octet:
    movzx   eax, byte [rdi + rcx]
    test    byte [r8 + rax], HA_CC_TARGET
    jz      .bad_target
    cmp     al, '%'
    jne     .target_next
    lea     edx, [ecx + 2]
    cmp     edx, esi
    jae     .bad_target                     ; the escape runs past the end
    movzx   eax, byte [rdi + rcx + 1]
    cmp     byte [r9 + rax], 0xFF
    je      .bad_target
    movzx   eax, byte [rdi + rcx + 2]
    cmp     byte [r9 + rax], 0xFF
    je      .bad_target
    add     ecx, 2
.target_next:
    inc     ecx
    cmp     ecx, esi
    jb      .target_octet
    ; The authority (Host's value): URI octets, none of "/", "?", "@", "#".
    mov     rdi, [r14 + httpasm_request.authority]
    mov     esi, [r14 + httpasm_request.authority_length]
    xor     ecx, ecx
.authority_octet:
    cmp     ecx, esi
    jae     .authority_ok
    movzx   eax, byte [rdi + rcx]
    test    byte [r8 + rax], HA_CC_TARGET
    jz      .bad_authority
    cmp     al, '/'
    je      .bad_authority
    cmp     al, '?'
    je      .bad_authority
    cmp     al, '@'
    je      .bad_authority
    inc     ecx
    jmp     .authority_octet
.authority_ok:
    mov     eax, [r14 + httpasm_request.flags]
    and     eax, HTTPASM_REQUEST_CONTENT_LENGTH | HTTPASM_REQUEST_CHUNKED
    cmp     eax, HTTPASM_REQUEST_CONTENT_LENGTH | HTTPASM_REQUEST_CHUNKED
    je      .framing                        ; two framings
    mov     rdi, [r14 + httpasm_request.fields]
    mov     esi, [r14 + httpasm_request.field_count]
    mov     edx, WR_REQUEST
    call    wr_check_fields
    test    eax, eax
    jnz     .refused

    ; method SP target " HTTP/1.1" CRLF "Host: " authority CRLF
    mov     rsi, [r14 + httpasm_request.method]
    mov     edx, [r14 + httpasm_request.method_length]
    call    wr_put
    jc      .full
    cmp     rbx, r13
    jae     .full
    mov     byte [rbx], ' '
    inc     rbx
    mov     rsi, [r14 + httpasm_request.target]
    mov     edx, [r14 + httpasm_request.target_length]
    call    wr_put
    jc      .full
    lea     rsi, [rel s_request_tail]
    mov     edx, s_request_tail_len
    call    wr_put
    jc      .full
    lea     rsi, [rel s_host]
    mov     edx, s_host_len
    call    wr_put
    jc      .full
    mov     rsi, [r14 + httpasm_request.authority]
    mov     edx, [r14 + httpasm_request.authority_length]
    call    wr_put
    jc      .full
    lea     rsi, [rel s_crlf]
    mov     edx, 2
    call    wr_put
    jc      .full
    test    dword [r14 + httpasm_request.flags], HTTPASM_REQUEST_CONTENT_LENGTH
    jz      .request_no_length
    lea     rsi, [rel s_length]
    mov     edx, s_length_len
    call    wr_put
    jc      .full
    mov     rax, [r14 + httpasm_request.content_length]
    call    wr_decimal
    jc      .full
    lea     rsi, [rel s_crlf]
    mov     edx, 2
    call    wr_put
    jc      .full
.request_no_length:
    test    dword [r14 + httpasm_request.flags], HTTPASM_REQUEST_CHUNKED
    jz      .request_no_chunked
    lea     rsi, [rel s_chunked]
    mov     edx, s_chunked_len
    call    wr_put
    jc      .full
.request_no_chunked:
    test    dword [r14 + httpasm_request.flags], HTTPASM_REQUEST_CLOSE
    jz      .request_no_close
    lea     rsi, [rel s_close]
    mov     edx, s_close_len
    call    wr_put
    jc      .full
.request_no_close:
    ; Expect: 100-continue only ahead of content: a request with none must not carry it
    ; (RFC9110-10.1.1-11.1). The flag is dropped then, not refused: with no content there is
    ; nothing to wait for, so the request means the same without it.
    test    dword [r14 + httpasm_request.flags], HTTPASM_REQUEST_EXPECT_CONTINUE
    jz      .request_fields
    test    dword [r14 + httpasm_request.flags], HTTPASM_REQUEST_CHUNKED
    jnz     .request_expect                 ; chunked: content of a length not known yet
    test    dword [r14 + httpasm_request.flags], HTTPASM_REQUEST_CONTENT_LENGTH
    jz      .request_fields                 ; no framing: no content
    cmp     qword [r14 + httpasm_request.content_length], 0
    je      .request_fields                 ; Content-Length: 0: no content either
.request_expect:
    lea     rsi, [rel s_expect]
    mov     edx, s_expect_len
    call    wr_put
    jc      .full
.request_fields:
    mov     [rsp], r14
    mov     r15d, [r14 + httpasm_request.field_count]
    mov     r14, [r14 + httpasm_request.fields]
    call    wr_fields
    mov     r14, [rsp]
    jc      .full
    lea     rsi, [rel s_crlf]
    mov     edx, 2
    call    wr_put
    jc      .full
    mov     rax, rbx
    sub     rax, r12
    jmp     .return
.full:
    xor     eax, eax
    jmp     .return
.bad_method:
    mov     eax, HTTPASM_ERROR_METHOD
    jmp     .refused
.bad_target:
    mov     eax, HTTPASM_ERROR_TARGET
    jmp     .refused
.bad_authority:
    mov     eax, HTTPASM_ERROR_AUTHORITY
    jmp     .refused
.framing:
    mov     eax, HTTPASM_ERROR_FRAMING_FIELD
.refused:
    neg     rax
.return:
    add     rsp, 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_status_reason: a registered status code's reason phrase ("Bad Request"), taken from the
; generated status-lines (each "HTTP/1.1 NNN phrase" CRLF), for the one-line explanation the
; server's own refusals carry (RFC 9110 15.5, 15.6). Used by the driver, for both versions.
;   In: edi = the status (100-599; the caller checked). Out: rax = the phrase (read-only,
;   inside the table), edx = its length; edx = 0 for a code with no registered phrase (rax
;   then points at the table: valid, with nothing to read). Clobbers rcx and the flags.
; -----------------------------------------------------------------------------
global ha_status_reason:function hidden (ha_status_reason.end - ha_status_reason)
align 16
ha_status_reason:
    mov     ecx, edi                        ; zero-extended: the table's index below
    lea     rax, [rel ha_status_line]
    mov     edx, [rax + rcx * 4 - 400]      ; offset << 8 | the line's length, or 0
    lea     rax, [rel ha_status_text]
    test    edx, edx
    jz      .out                            ; unregistered: no phrase
    mov     ecx, edx
    shr     ecx, 8                          ; the line's offset
    and     edx, 0xFF
    sub     edx, 15                         ; "HTTP/1.1 NNN " (13) before, CRLF (2) after
    lea     rax, [rax + rcx + 13]
.out:
    ret
.end:

; -----------------------------------------------------------------------------
; int64_t httpasm_h1_write_chunk(uint8_t *out, size_t cap, const uint8_t *data, size_t len)
;   One chunk: chunk-size (lower-case hex) CRLF, the data, CRLF. len must be at least 1 (a chunk
;   of 0 octets is the last chunk: httpasm_h1_write_last_chunk). Returns the octets written, 0
;   if cap is too small, or -HTTPASM_ERROR_CHUNK for len 0. In: rdi, rsi, rdx, rcx.
;   Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global httpasm_h1_write_chunk:function (httpasm_h1_write_chunk.end - httpasm_h1_write_chunk)
align 16
httpasm_h1_write_chunk:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    test    rcx, rcx
    jz      .empty
    mov     r12, rdi
    lea     r13, [rdi + rsi]
    mov     rbx, rdi
    mov     r14, rdx                        ; data
    mov     r15, rcx                        ; len
    mov     rax, rcx
    call    wr_hex
    jc      .full
    lea     rsi, [rel s_crlf]
    mov     edx, 2
    call    wr_put
    jc      .full
    mov     rsi, r14
    mov     rdx, r15
    call    wr_put
    jc      .full
    lea     rsi, [rel s_crlf]
    mov     edx, 2
    call    wr_put
    jc      .full
    mov     rax, rbx
    sub     rax, r12
    jmp     .out
.full:
    xor     eax, eax
    jmp     .out
.empty:
    mov     rax, -HTTPASM_ERROR_CHUNK
.out:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; int64_t httpasm_h1_write_last_chunk(uint8_t *out, size_t cap, const httpasm_field *trailers,
;                                     uint32_t count)
;   The end of a chunked body: "0" CRLF, the trailer fields, CRLF. Trailers may not carry
;   framing, routing or the fields the writer owns (RFC 9110 6.5.1); count may be 0.
;   Returns the octets written, 0 if cap is too small, or -HTTPASM_ERROR_FIELD_NAME /
;   _FIELD_VALUE / _FRAMING_FIELD. In: rdi, rsi, rdx, ecx. Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
global httpasm_h1_write_last_chunk:function (httpasm_h1_write_last_chunk.end - httpasm_h1_write_last_chunk)
align 16
httpasm_h1_write_last_chunk:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    mov     r12, rdi
    lea     r13, [rdi + rsi]
    mov     rbx, rdi
    mov     r14, rdx
    mov     r15d, ecx
    mov     rdi, rdx
    mov     esi, ecx
    mov     edx, WR_TRAILER
    call    wr_check_fields
    test    eax, eax
    jnz     .refused
    lea     rsi, [rel s_last_chunk]
    mov     edx, 3
    call    wr_put
    jc      .full
    call    wr_fields                       ; r14 = trailers, r15d = count
    jc      .full
    lea     rsi, [rel s_crlf]
    mov     edx, 2
    call    wr_put
    jc      .full
    mov     rax, rbx
    sub     rax, r12
    jmp     .out
.full:
    xor     eax, eax
    jmp     .out
.refused:
    neg     rax
.out:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:
