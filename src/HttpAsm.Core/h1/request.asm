; =============================================================================
; h1/request.asm - HTTP/1.1 request heads: httpasm_h1_parse_request, and ha_h1_fields, the
; field-line parser that the response parser and the chunked decoder's trailers share.
;
; The parser is sans-I/O and stateless: it reads one head from the caller's buffer and fills the
; caller's httpasm_request and httpasm_field array, with pointers into that buffer (nothing is
; copied). Only *scan_from carries over between calls on an incomplete head: where the search
; for its end resumes, so bytes arriving a few at a time are scanned once, not again per call.
;
; Two flows give every head the same outcome:
;   classic   the head's end first (the first CRLF CRLF, every LF checked for its CR), then the
;             request-line, then the field lines (ha_h1_fields). Every tier runs it for a
;             resumed search; v1 runs it always.
;   one-pass  v2 and up, for a head searched from its request-line (a message's first call):
;             the request-line and the field lines read once (ha_h1_fields_v2), the empty line
;             found on the way, every read below min(len, max_head). It only ever accepts;
;             anything else starts the classic flow over, which names the outcome (the proof is
;             at .one_pass). Against the classic flow it saves the search for the end, a second
;             pass over every line with a loop exit to predict per line: a browser's request
;             head parses in 0.58x the time (benchmarks/README.md).
;
; Rules applied, by registry row (specs/requirements.tsv) and policy where the RFCs leave a choice:
;   - Lines end in CRLF. A bare LF is refused: RFC 9112 2.2 lets a recipient accept one, and
;     HttpAsm does not, because LF-only lines are a classic smuggling vector between parsers
;     that disagree.
;   - Empty lines before the request-line are skipped (RFC 9112 2.2: SHOULD ignore at least one).
;   - The request-line is method SP request-target SP HTTP-version, one SP each. The leniency
;     RFC 9112 section 3 allows (any whitespace) is not taken.
;   - The method is a token. The request-target holds only URI octets, with well-formed
;     percent-encodings. Its form must suit the method: authority-form only and always for
;     CONNECT, asterisk-form only for OPTIONS. Over the limit, 414.
;   - HTTP/1.x: 1.0 is 10, 1.1 and higher minors are 11 (RFC 9110 2.5). Another major: 505.
;   - Field lines: a token name directly followed by ":" (whitespace before the colon: 400,
;     RFC 9112 5.1). OWS is trimmed around the value. The value holds no CTL but HTAB. A line
;     starting with whitespace (obs-fold, or whitespace after the request-line) is refused with
;     400, as RFC 9112 5.2 allows.
;   - Host: required in HTTP/1.1, at most once, and a valid uri-host [ ":" port ] (RFC 9112 3.2:
;     400 otherwise).
;   - Content-Length: 1*DIGIT, or a list of identical ones (RFC 9112 6.3); anything else is 400.
;   - Transfer-Encoding: with Content-Length, 400 (RFC 9112 6.3 lets a server reject it; it then
;     closes). In HTTP/1.0, 400 (RFC 9112 6.1: faulty framing). chunked must be the final coding,
;     once, without parameters (400; RFC9112-7.1-6). Any other coding is not implemented yet:
;     501 (RFC 9112 6.1).
;   - Expect: 100-continue is flagged; any other expectation is 417 (RFC 9110 10.1.1 MAY).
;   - Persistence (RFC 9112 9.3): HTTP/1.1 persists unless Connection: close; HTTP/1.0 only with
;     keep-alive.
; Every refusal answers with its status and closes the connection; httpasm_request.error says
; which rule refused it.
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "h1/h1.inc"

section .text

; Fail from inside ha_h1_fields: record the rule and the status, and return 1.
%macro H1_FAIL 2
    mov     dword [r12 + h1ctx.error], %1
    mov     dword [r12 + h1ctx.status], %2
    jmp     .failed
%endmacro

; Skip OWS (SP / HTAB) at %1, up to the end %2 (both pointer registers).
%macro SKIP_OWS 2
%%again:
    cmp     %1, %2
    jae     %%done
    cmp     byte [%1], ' '
    je      %%one
    cmp     byte [%1], 9
    jne     %%done
%%one:
    inc     %1
    jmp     %%again
%%done:
%endmacro

; -----------------------------------------------------------------------------
; H1_FIELD_RULES: the framing and connection rules of one field line, entered by known field:
;   .content_length     Content-Length (RFC 9112 6.3)
;   .transfer_encoding  Transfer-Encoding (RFC 9112 6.1, 7.1)
;   .connection         Connection: close and keep-alive (RFC 9112 9.3, 9.6)
;   .host               Host (RFC 9112 3.2), requests only
;   .expect             Expect: 100-continue (RFC 9110 10.1.1), requests only
;   .te                 TE: trailers (RFC 9110 10.1.4), requests only
;   .upgrade            Upgrade (flagged only), requests only
;   One source, expanded in each routine that parses field lines (ha_h1_fields, and
;   ha_h1_fields_v2, the one-pass parser of request heads), so both apply the same rules: a
;   rule fixed here is fixed for every version. The labels are the including routine's own.
;   In:  r12 = the h1ctx; r15 = the value's first octet, r14 = past its last (pointers, OWS
;        already trimmed); rbx = the buffer.
;   Out: each rule ends at .next_line, with what it found in .seen (and .content_length, the
;        request's authority), or at one of the including routine's failure labels:
;        .bad_content_length, .host_duplicate, .host_invalid, .expectation_failed.
;   Clobbers rax, rcx, rdx, rsi, rdi, r9-r11, r14, r15 and the flags. Keeps rbx, rbp, r12, r13
;   and every XMM register, which is what lets a caller hold its line position in r13 and its
;   vector constants across a rule.
; -----------------------------------------------------------------------------
%macro H1_FIELD_RULES 0
; ---- Content-Length = 1*DIGIT; a list of identical values is accepted as one (RFC 9112 6.3).
.content_length:
    SKIP_OWS r15, r14
    cmp     r15, r14
    jae     .bad_content_length             ; an empty element
    xor     eax, eax
    xor     ecx, ecx
.cl_digit:
    cmp     r15, r14
    jae     .cl_number
    movzx   edx, byte [r15]
    sub     edx, '0'
    cmp     edx, 9
    ja      .cl_number
    imul    rax, rax, 10
    jo      .bad_content_length             ; past 2^63 - 1
    add     rax, rdx
    js      .bad_content_length
    inc     r15
    inc     ecx
    jmp     .cl_digit
.cl_number:
    test    ecx, ecx
    jz      .bad_content_length
    SKIP_OWS r15, r14
    test    dword [r12 + h1ctx.seen], HA_SEEN_CONTENT_LENGTH
    jz      .cl_first
    cmp     rax, [r12 + h1ctx.content_length]
    jne     .bad_content_length             ; two lengths that differ
.cl_first:
    mov     [r12 + h1ctx.content_length], rax
    or      dword [r12 + h1ctx.seen], HA_SEEN_CONTENT_LENGTH
    cmp     r15, r14
    jae     .next_line
    cmp     byte [r15], ','
    jne     .bad_content_length
    inc     r15
    jmp     .content_length

; ---- Transfer-Encoding = #transfer-coding; transfer-coding = token *( OWS ";" OWS param )
.transfer_encoding:
    or      dword [r12 + h1ctx.seen], HA_SEEN_TE
.te_element:
    SKIP_OWS r15, r14
    cmp     r15, r14
    jae     .next_line
    cmp     byte [r15], ','
    jne     .te_token
    inc     r15                             ; an empty element: ignored (RFC 9110 5.6.1)
    jmp     .te_element
.te_token:
    mov     rsi, r14
    sub     rsi, r15
    HA_TOKEN_SCAN r15, rsi, rax, rcx, rdx
    test    rax, rax
    jnz     .te_named
    or      dword [r12 + h1ctx.seen], HA_SEEN_BAD_CODING
    jmp     .next_line
.te_named:
    ; The token must end its element: OWS, then the value's end, "," or ";" (RFC 9112 6.1:
    ; transfer-coding = token *( OWS ";" OWS transfer-parameter )). Anything else after it,
    ; as in "chunked x" or "chunked" with an obs-text octet stuck to it, makes the coding one
    ; this side cannot name: refused like any malformed coding. Skipping to the next comma, as
    ; this once did, read "chunked\xD8" as chunked where llhttp reads another coding, and two
    ; parties that disagree on chunked frame the body differently (tests/fuzz/h1_request_diff,
    ; 2026-11-26). rdi is free here; rax keeps the token's length.
    lea     rdi, [r15 + rax]
    SKIP_OWS rdi, r14
    cmp     rdi, r14
    jae     .te_delimited
    cmp     byte [rdi], ','
    je      .te_delimited
    cmp     byte [rdi], ';'
    je      .te_delimited
    or      dword [r12 + h1ctx.seen], HA_SEEN_BAD_CODING
.te_delimited:
    test    dword [r12 + h1ctx.seen], HA_SEEN_CHUNKED
    jz      .te_which
    or      dword [r12 + h1ctx.seen], HA_SEEN_AFTER_CHUNKED     ; chunked was not the last
.te_which:
    cmp     rax, 7
    jne     .te_other
    mov     ecx, [r15]
    or      ecx, 0x20202020
    cmp     ecx, 'chun'
    jne     .te_other
    mov     ecx, [r15 + 3]
    or      ecx, 0x20202020
    cmp     ecx, 'nked'
    jne     .te_other
    or      dword [r12 + h1ctx.seen], HA_SEEN_CHUNKED
    ; chunked defines no parameters: one after it is an error (RFC9112-7.1-6), handled like a
    ; coding this side cannot name (a request's 400; a response read to the close), because
    ; two parties that disagree on whether "chunked;x" is chunked frame the body differently.
    lea     rdi, [r15 + rax]                ; past the token (rax: its length, kept)
    SKIP_OWS rdi, r14
    cmp     rdi, r14
    jae     .te_parameters
    cmp     byte [rdi], ';'
    jne     .te_parameters
    or      dword [r12 + h1ctx.seen], HA_SEEN_BAD_CODING
    jmp     .te_parameters
.te_other:
    or      dword [r12 + h1ctx.seen], HA_SEEN_UNKNOWN_CODING
.te_parameters:
    add     r15, rax
.te_skip:                                   ; to the next comma outside a quoted-string
    cmp     r15, r14
    jae     .next_line
    movzx   eax, byte [r15]
    inc     r15
    cmp     al, ','
    je      .te_element
    cmp     al, '"'
    jne     .te_skip
.te_quoted:
    cmp     r15, r14
    jae     .next_line
    movzx   eax, byte [r15]
    inc     r15
    cmp     al, '\'
    jne     .te_quote_end
    inc     r15                             ; quoted-pair: skip the escaped octet
    jmp     .te_quoted
.te_quote_end:
    cmp     al, '"'
    jne     .te_quoted
    jmp     .te_skip

; ---- Connection = #connection-option; "close" and "keep-alive" matter (RFC 9112 9.3, 9.6)
.connection:
    SKIP_OWS r15, r14
    cmp     r15, r14
    jae     .next_line
    mov     rsi, r14
    sub     rsi, r15
    HA_TOKEN_SCAN r15, rsi, rax, rcx, rdx
    cmp     rax, 5
    jne     .conn_keep_alive
    mov     ecx, [r15]
    or      ecx, 0x20202020
    cmp     ecx, 'clos'
    jne     .conn_next
    movzx   ecx, byte [r15 + 4]
    or      ecx, 0x20
    cmp     ecx, 'e'
    jne     .conn_next
    or      dword [r12 + h1ctx.seen], HA_SEEN_CLOSE
    jmp     .conn_next
.conn_keep_alive:
    cmp     rax, 10
    jne     .conn_next
    mov     rcx, [r15]
    mov     rdx, 0x2020202020202020
    or      rcx, rdx
    mov     rdx, 'keep-ali'
    cmp     rcx, rdx
    jne     .conn_next
    movzx   ecx, word [r15 + 8]
    or      ecx, 0x2020
    cmp     ecx, 've'
    jne     .conn_next
    or      dword [r12 + h1ctx.seen], HA_SEEN_KEEP_ALIVE
.conn_next:
    lea     r15, [r15 + rax]
.conn_skip:                                 ; to the next element
    cmp     r15, r14
    jae     .next_line
    movzx   eax, byte [r15]
    inc     r15
    cmp     al, ','
    jne     .conn_skip
    jmp     .connection

; ---- Host = uri-host [ ":" port ]: once, valid, in every HTTP/1.1 request (RFC 9112 3.2)
.host:
    test    dword [r12 + h1ctx.seen], HA_SEEN_HOST
    jnz     .host_duplicate
    or      dword [r12 + h1ctx.seen], HA_SEEN_HOST
    lea     r9, [rel ha_char_class]
    lea     r10, [rel ha_hex_value]
    mov     r11, r15                        ; the value's start, for the authority below
    ; uri-host [ ":" port ], by the grammar HTTP/2's :authority and Host follow too
    ; (semantics/authority.inc): an empty value passes, as HTTP/1.1 allows when the target
    ; has no authority.
    HA_URI_HOST r15, r14, r9, r10, rax, eax, al, rcx, ecx, .host_invalid
.host_valid:
    ; Host names the authority, unless the request-target already did (absolute-form and
    ; authority-form: RFC 9112 3.2.2 and 3.2.3).
    mov     rax, [r12 + h1ctx.request]
    cmp     byte [rax + httpasm_request.target_form], HTTPASM_TARGET_ABSOLUTE
    je      .next_line
    cmp     byte [rax + httpasm_request.target_form], HTTPASM_TARGET_AUTHORITY
    je      .next_line
    mov     [rax + httpasm_request.authority], r11
    mov     rcx, r14
    sub     rcx, r11
    mov     [rax + httpasm_request.authority_length], ecx
    jmp     .next_line

; ---- Expect: 100-continue is the only expectation (RFC 9110 10.1.1)
.expect:
    mov     rax, [r12 + h1ctx.request]
    cmp     byte [rax + httpasm_request.version], 10
    je      .next_line                      ; HTTP/1.0: ignored (RFC9110-10.1.1-13.1)
    mov     rax, r14
    sub     rax, r15
    jz      .next_line                      ; an empty list expects nothing
    cmp     rax, 12
    jne     .expectation_failed
    mov     rcx, [r15]
    mov     rdx, 0x2020202020202020
    or      rcx, rdx
    mov     rdx, '100-cont'
    cmp     rcx, rdx
    jne     .expectation_failed
    mov     ecx, [r15 + 8]
    or      ecx, 0x20202020
    cmp     ecx, 'inue'
    jne     .expectation_failed
    or      dword [r12 + h1ctx.seen], HA_SEEN_EXPECT_CONTINUE
    jmp     .next_line

; ---- TE = #t-codings; "trailers" says the client accepts trailer fields (RFC 9110 10.1.4)
.te:
    SKIP_OWS r15, r14
    cmp     r15, r14
    jae     .next_line
    mov     rsi, r14
    sub     rsi, r15
    HA_TOKEN_SCAN r15, rsi, rax, rcx, rdx
    cmp     rax, 8
    jne     .te_list_next
    mov     rcx, [r15]
    mov     rdx, 0x2020202020202020
    or      rcx, rdx
    mov     rdx, 'trailers'
    cmp     rcx, rdx
    jne     .te_list_next
    or      dword [r12 + h1ctx.seen], HA_SEEN_TE_TRAILERS
.te_list_next:
    lea     r15, [r15 + rax]
.te_list_skip:
    cmp     r15, r14
    jae     .next_line
    movzx   eax, byte [r15]
    inc     r15
    cmp     al, ','
    jne     .te_list_skip
    jmp     .te

.upgrade:
    or      dword [r12 + h1ctx.seen], HA_SEEN_UPGRADE
    jmp     .next_line
%endmacro

; -----------------------------------------------------------------------------
; ha_h1_fields: the field lines of a head, into the context's httpasm_field array.
;   In:  rdi = h1ctx, with .buf, .head_end, .fields, .max_fields, .mode and .field_flags set,
;        .count and .seen as far as earlier lines left them; rsi = the offset of the first
;        field line (head_end - 2 when there is none).
;   Out: eax = 0, with .count records written and .seen telling what the mode's rules met;
;        or eax = 1 with .error and .status set. Records written before a failure stay.
;   Requires that every line from rsi to .head_end ends in CRLF, which the callers check when
;   they find the head's end.
;   Keeps rbx, rbp and r12-r15. Clobbers the other general registers, xmm0-xmm6 and the flags.
;
;   Two versions of each line's scanning, chosen per line (HA_CPU_PICK1: one test, never per
;   octet), the rest of the line's work shared:
;     v1  the name octet by octet (HA_TOKEN_SCAN), the value's end by ha_find_lf, the value
;         by HA_FIELD_VALUE_SCAN: three passes and a call;
;     v2  16 octets a step (.name_v2, .value_v2): the name's octets classified by two pshufb
;         lookups, the value's CR and the octets it may not hold found in one pass.
;   Both give every line the same outcome, octet for octet and error for error; a step that
;   could read into a page past the head's end gives the line to v1 (.name_scalar,
;   .value_scalar), so no version reads memory the caller did not hand over.
; -----------------------------------------------------------------------------
global ha_h1_fields:function hidden (ha_h1_fields.end - ha_h1_fields)
align 16
ha_h1_fields:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 8                          ; 16-byte aligned for the calls below
    mov     r12, rdi                        ; the context
    mov     rbx, [r12 + h1ctx.buf]
    mov     rbp, [r12 + h1ctx.head_end]
    sub     rbp, 2                          ; the final empty line starts here
    mov     r13, rsi                        ; the current line

.line:
    cmp     r13, rbp
    jae     .done
    movzx   eax, byte [rbx + r13]
    cmp     al, ' '
    je      .obs_fold
    cmp     al, 9
    je      .obs_fold

    ; The name: a token that the colon follows at once. r14 = its length.
    HA_CPU_PICK1 HTTPASM_CPU_V2, .name_v2
.name_scalar:
    lea     rdi, [rbx + r13]
    mov     rsi, rbp
    sub     rsi, r13
    HA_TOKEN_SCAN rdi, rsi, r14, rcx, rdx
.name_scanned:
    test    r14, r14
    jz      .bad_name
    lea     rcx, [r13 + r14]
    movzx   eax, byte [rbx + rcx]
    cmp     al, ':'
    je      .colon
    cmp     al, ' '
    je      .space_before_colon
    cmp     al, 9
    je      .space_before_colon
    jmp     .bad_name

.colon:
    mov     eax, [r12 + h1ctx.count]
    cmp     eax, [r12 + h1ctx.max_fields]
    jae     .too_many
    shl     rax, 5                          ; 32 octets per httpasm_field
    add     rax, [r12 + h1ctx.fields]
    mov     [r12 + h1ctx.record], rax
    lea     rdx, [rbx + r13]
    mov     [rax + httpasm_field.name], rdx
    mov     [rax + httpasm_field.name_length], r14d

    ; The value: past the colon and OWS, to the line's CR less trailing OWS.
    lea     r15, [rcx + 1]
.leading_ows:
    movzx   eax, byte [rbx + r15]
    cmp     al, ' '
    je      .leading_one
    cmp     al, 9
    jne     .find_end
.leading_one:
    inc     r15
    jmp     .leading_ows
.find_end:
    HA_CPU_PICK1 HTTPASM_CPU_V2, .value_v2
.value_scalar:
    lea     rdi, [rbx + r15]
    lea     rsi, [rbp + 2]
    sub     rsi, r15
    call    ha_find_lf                      ; every line ends in CRLF: it is found
    add     rax, r15
    mov     [r12 + h1ctx.line_lf], rax
    lea     rdx, [rax - 1]                  ; the CR
.trailing_ows:
    cmp     rdx, r15
    jbe     .trimmed
    movzx   ecx, byte [rbx + rdx - 1]
    cmp     cl, ' '
    je      .trailing_one
    cmp     cl, 9
    jne     .trimmed
.trailing_one:
    dec     rdx
    jmp     .trailing_ows
.trimmed:
    mov     r14, rdx                        ; the value's end
    lea     rdi, [rbx + r15]
    mov     rsi, rdx
    sub     rsi, r15
    HA_FIELD_VALUE_SCAN rdi, rsi, rax, rcx, ecx, rdx, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5
    cmp     rax, rsi
    jne     .bad_value                      ; a CTL other than HTAB (RFC9110-5.5-5#1, -5#2)
.value_checked:                             ; rdi, rsi = the value; .line_lf = its line's LF
    mov     r8, [r12 + h1ctx.record]
    mov     [r8 + httpasm_field.value], rdi
    mov     [r8 + httpasm_field.value_length], esi
    mov     eax, [r12 + h1ctx.field_flags]
    mov     [r8 + httpasm_field.flags], ax
    mov     dword [r8 + httpasm_field.reserved], 0
    mov     rdi, [r8 + httpasm_field.name]
    mov     esi, [r8 + httpasm_field.name_length]
    call    ha_field_lookup                 ; the name is a token: the fold is exact
    mov     r8, [r12 + h1ctx.record]
    mov     [r8 + httpasm_field.id], ax
    inc     dword [r12 + h1ctx.count]

    ; The mode's rules, by known-field id. r14 and r15 become the value's bounds.
    mov     r15, [r8 + httpasm_field.value]
    mov     r14d, [r8 + httpasm_field.value_length]
    add     r14, r15
    mov     ecx, [r12 + h1ctx.mode]
    cmp     ecx, HA_H1_TRAILER
    je      .next_line                      ; trailers carry no framing (RFC 9110 6.5.1)
    cmp     ax, HA_FIELD_CONTENT_LENGTH
    je      .content_length
    cmp     ax, HA_FIELD_TRANSFER_ENCODING
    je      .transfer_encoding
    cmp     ax, HA_FIELD_CONNECTION
    je      .connection
    cmp     ecx, HA_H1_REQUEST
    jne     .next_line
    cmp     ax, HA_FIELD_HOST
    je      .host
    cmp     ax, HA_FIELD_EXPECT
    je      .expect
    cmp     ax, HA_FIELD_TE
    je      .te
    cmp     ax, HA_FIELD_UPGRADE
    je      .upgrade

.next_line:
    mov     r13, [r12 + h1ctx.line_lf]
    inc     r13
    jmp     .line

.done:
    xor     eax, eax
.out:
    add     rsp, 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.failed:
    mov     eax, 1
    jmp     .out

; ---- v2: a line's name and value, 16 octets a step (SSSE3's pshufb; every v2 CPU has it).
;
; A 16-octet load stays in the caller's memory when it ends within the head (the head is the
; caller's to its last octet: one compare, against the head's end less 16, settles nearly every
; step) or when it does not cross into the next 4 KiB page (the page that holds its first octet
; is mapped, so all of it is). Otherwise the line goes to v1 (.name_scalar, .value_scalar),
; which reads octet by octet: only near the end of a page that is the head's last.

; .name_v2: r14 = the length of the token at the line's start (as HA_TOKEN_SCAN), then the
; checks after .name_scanned. Each step classifies 16 octets: an octet's low nibble indexes
; ha_tchar_lo, its high nibble ha_tchar_hi, and the two entries share a bit exactly for a tchar
; (tables.asm proves it at assembly time). The first octet that is not one ends the name; there
; is always one, the line's CR at the latest, so the steps end before the head does.
.name_v2:
    movdqa  xmm3, [rel ha_tchar_lo]
    movdqa  xmm4, [rel ha_tchar_hi]
    movdqa  xmm5, [rel ha_x16_0f]
    pxor    xmm6, xmm6
    lea     rdi, [rbx + r13]                ; the name's first octet
    lea     rsi, [rbx + rbp - 14]           ; the head's end less 16: the last step within it
    xor     r14d, r14d
.name_v2_step:
    lea     rax, [rdi + r14]
    cmp     rax, rsi
    jbe     .name_v2_load                   ; it ends within the head
    mov     ecx, eax
    and     ecx, 4095
    cmp     ecx, 4096 - 16
    ja      .name_scalar                    ; it would reach a page past the head: v1
.name_v2_load:
    movdqu  xmm0, [rax]
    movdqa  xmm1, xmm0
    psrlw   xmm1, 4
    pand    xmm1, xmm5                      ; each octet's high nibble
    pand    xmm0, xmm5                      ; and its low nibble
    movdqa  xmm2, xmm4
    pshufb  xmm2, xmm1                      ; ha_tchar_hi[high]
    movdqa  xmm1, xmm3
    pshufb  xmm1, xmm0                      ; ha_tchar_lo[low]
    pand    xmm1, xmm2                      ; nonzero exactly for a tchar
    pcmpeqb xmm1, xmm6                      ; 0xFF where the octet is not one
    pmovmskb ecx, xmm1
    test    ecx, ecx
    jnz     .name_v2_end
    add     r14, 16                         ; 16 tchars: the name goes on
    jmp     .name_v2_step
.name_v2_end:
    bsf     ecx, ecx                        ; the first octet that is not a tchar
    add     r14, rcx
    jmp     .name_scanned

; .value_v2: from the value's first octet (r15, past the colon and OWS), 16 octets a step, to the
; first octet a field value may not hold (HA_FIELD_VALUE_CLASSIFY: a CTL other than HTAB). In a
; valid line that octet is the line's CR, with its LF next: the line ends there, and every
; octet before it is allowed. Anything else - a CTL, or a CR the LF does not follow (a bare CR) -
; is refused, which is v1's outcome too: v1 finds the line's end (ha_find_lf) and then meets that
; octet inside the value (HA_FIELD_VALUE_SCAN). One classification serves both questions, where
; looking for the CR apart would cost a compare and a mask more a step. The OWS between the value
; and the CR is valid, so the octets checked are the trimmed value's. Then the trailing OWS is
; trimmed as v1 trims it, and the line joins .value_checked with rdi, rsi and .line_lf as v1
; leaves them.
.value_v2:
    movdqa  xmm3, [rel ha_x16_1f]
    movdqa  xmm4, [rel ha_x16_09]
    movdqa  xmm5, [rel ha_x16_7f]
    lea     rsi, [rbx + rbp - 14]           ; the head's end less 16: the last step within it
    mov     rdx, r15                        ; the step's offset
.value_v2_step:
    lea     rax, [rbx + rdx]
    cmp     rax, rsi
    jbe     .value_v2_load                  ; it ends within the head
    mov     ecx, eax
    and     ecx, 4095
    cmp     ecx, 4096 - 16
    ja      .value_scalar                   ; it would reach a page past the head: v1
.value_v2_load:
    movdqu  xmm0, [rax]
    HA_FIELD_VALUE_CLASSIFY xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, ecx
    test    ecx, ecx
    jnz     .value_v2_stop
    add     rdx, 16
    jmp     .value_v2_step
.value_v2_stop:
    bsf     ecx, ecx                        ; the first octet a value may not hold
    add     rdx, rcx
    cmp     byte [rbx + rdx], 13
    jne     .bad_value                      ; a CTL other than HTAB (RFC9110-5.5-5#1, -5#2)
    cmp     byte [rbx + rdx + 1], 10
    jne     .bad_value                      ; a bare CR: a CTL inside the value
    lea     rax, [rdx + 1]
    mov     [r12 + h1ctx.line_lf], rax      ; rdx = the line's CR
.value_v2_trailing:                         ; as .trailing_ows: OWS before the CR is not value
    cmp     rdx, r15
    jbe     .value_v2_trimmed
    movzx   ecx, byte [rbx + rdx - 1]
    cmp     cl, ' '
    je      .value_v2_one
    cmp     cl, 9
    jne     .value_v2_trimmed
.value_v2_one:
    dec     rdx
    jmp     .value_v2_trailing
.value_v2_trimmed:
    mov     r14, rdx                        ; the value's end, as v1 leaves it
    lea     rdi, [rbx + r15]
    mov     rsi, rdx
    sub     rsi, r15
    jmp     .value_checked

    H1_FIELD_RULES

.obs_fold:
    ; A line that starts with whitespace. In a request or a trailer section it is refused
    ; (RFC9112-5.2-4, RFC9112-2.2-8). In a response, a user agent MUST replace the obs-fold with
    ; SP and keep the value (RFC9112-5.2-6): the CRLF before this line becomes SP SP in the
    ; buffer, so the previous field's value runs on into this line. Directly after the
    ; status-line there is no field to continue, and refusing is allowed (RFC9112-2.2-8). A
    ; framing field is never joined: its rule already ran on the first line.
    cmp     dword [r12 + h1ctx.mode], HA_H1_RESPONSE
    jne     .obs_fold_refused
    mov     eax, [r12 + h1ctx.count]
    test    eax, eax
    jz      .obs_fold_refused
    dec     eax
    shl     rax, 5
    add     rax, [r12 + h1ctx.fields]
    mov     [r12 + h1ctx.record], rax
    movzx   ecx, word [rax + httpasm_field.id]
    cmp     ecx, HA_FIELD_CONTENT_LENGTH
    je      .obs_fold_refused
    cmp     ecx, HA_FIELD_TRANSFER_ENCODING
    je      .obs_fold_refused
    cmp     ecx, HA_FIELD_CONNECTION
    je      .obs_fold_refused
    mov     word [rbx + r13 - 2], 0x2020    ; the CRLF that ended the previous line
    lea     rdi, [rbx + r13]
    lea     rsi, [rbp + 2]
    sub     rsi, r13
    call    ha_find_lf
    add     rax, r13
    mov     [r12 + h1ctx.line_lf], rax
    lea     rdx, [rax - 1]                  ; this line's CR: the joined value ends before it
    mov     r8, [r12 + h1ctx.record]
    mov     r15, [r8 + httpasm_field.value]
    sub     r15, rbx                        ; the value's start, as an offset
.fold_leading:                              ; an empty first part leaves only whitespace in front
    cmp     r15, rdx
    jae     .fold_trailing
    movzx   ecx, byte [rbx + r15]
    cmp     cl, ' '
    je      .fold_leading_one
    cmp     cl, 9
    jne     .fold_trailing
.fold_leading_one:
    inc     r15
    jmp     .fold_leading
.fold_trailing:
    cmp     rdx, r15
    jbe     .fold_check
    movzx   ecx, byte [rbx + rdx - 1]
    cmp     cl, ' '
    je      .fold_trailing_one
    cmp     cl, 9
    jne     .fold_check
.fold_trailing_one:
    dec     rdx
    jmp     .fold_trailing
.fold_check:
    lea     rdi, [rbx + r15]
    mov     rsi, rdx
    sub     rsi, r15
    HA_FIELD_VALUE_SCAN rdi, rsi, rax, rcx, ecx, rdx, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5
    cmp     rax, rsi
    jne     .bad_value
    mov     r8, [r12 + h1ctx.record]
    mov     [r8 + httpasm_field.value], rdi
    mov     [r8 + httpasm_field.value_length], esi
    jmp     .next_line
.obs_fold_refused:
    H1_FAIL HTTPASM_ERROR_OBS_FOLD, 400
.bad_name:
    H1_FAIL HTTPASM_ERROR_FIELD_NAME, 400
.space_before_colon:
    H1_FAIL HTTPASM_ERROR_WHITESPACE_BEFORE_COLON, 400
.too_many:
    H1_FAIL HTTPASM_ERROR_TOO_MANY_FIELDS, 431
.bad_value:
    H1_FAIL HTTPASM_ERROR_FIELD_VALUE, 400
.bad_content_length:
    H1_FAIL HTTPASM_ERROR_CONTENT_LENGTH, 400
.host_duplicate:
    H1_FAIL HTTPASM_ERROR_HOST_DUPLICATE, 400
.host_invalid:
    H1_FAIL HTTPASM_ERROR_HOST_INVALID, 400
.expectation_failed:
    H1_FAIL HTTPASM_ERROR_EXPECT, 417
.end:

; -----------------------------------------------------------------------------
; h1_request_rule: the rule (H1_RULE_*) ha_h1_fields' request mode applies to each known-field
; id, 0 for none: its dispatch as one table load, for ha_h1_fields_v2. Built from the generated
; ids with "times" gaps in ascending id order, so a regenerated id that broke the order makes a
; negative count, which does not assemble, and the coverage build's preprocessor never needs an
; equ value (see tests/coverage/instrument.cs).
; -----------------------------------------------------------------------------
H1_RULE_CONTENT_LENGTH      equ 1
H1_RULE_TRANSFER_ENCODING   equ 2
H1_RULE_CONNECTION          equ 3
H1_RULE_HOST                equ 4
H1_RULE_EXPECT              equ 5
H1_RULE_TE                  equ 6
H1_RULE_UPGRADE             equ 7

section .rodata
h1_request_rule:
    times HA_FIELD_CONTENT_LENGTH db 0
    db      H1_RULE_CONTENT_LENGTH
    times HA_FIELD_EXPECT - HA_FIELD_CONTENT_LENGTH - 1 db 0
    db      H1_RULE_EXPECT
    times HA_FIELD_HOST - HA_FIELD_EXPECT - 1 db 0
    db      H1_RULE_HOST
    times HA_FIELD_TRANSFER_ENCODING - HA_FIELD_HOST - 1 db 0
    db      H1_RULE_TRANSFER_ENCODING
    times HA_FIELD_CONNECTION - HA_FIELD_TRANSFER_ENCODING - 1 db 0
    db      H1_RULE_CONNECTION
    times HA_FIELD_TE - HA_FIELD_CONNECTION - 1 db 0
    db      H1_RULE_TE
    times HA_FIELD_UPGRADE - HA_FIELD_TE - 1 db 0
    db      H1_RULE_UPGRADE
    times HA_FIELD_COUNT - HA_FIELD_UPGRADE db 0  ; ids up to HA_FIELD_COUNT: COUNT + 1 entries

; h1_response_rule: the same for ha_h1_fields' response mode, whose rules are the framing ones
; only (Content-Length, Transfer-Encoding, Connection), built the same way.
h1_response_rule:
    times HA_FIELD_CONTENT_LENGTH db 0
    db      H1_RULE_CONTENT_LENGTH
    times HA_FIELD_TRANSFER_ENCODING - HA_FIELD_CONTENT_LENGTH - 1 db 0
    db      H1_RULE_TRANSFER_ENCODING
    times HA_FIELD_CONNECTION - HA_FIELD_TRANSFER_ENCODING - 1 db 0
    db      H1_RULE_CONNECTION
    times HA_FIELD_COUNT - HA_FIELD_CONNECTION db 0
section .text

; -----------------------------------------------------------------------------
; ha_h1_fields_v2: a head's field lines and the empty line that ends it, in one pass (v2 and up:
; the one-pass flows of httpasm_h1_parse_request and httpasm_h1_parse_response).
;   In:  rdi = h1ctx, as for ha_h1_fields with .mode = HA_H1_REQUEST or HA_H1_RESPONSE (its
;        rules by h1_request_rule or h1_response_rule), except that .head_end is the bound B: an
;        offset no octet of a head the caller can accept reaches (min(len, max_head)), every
;        octet below it the caller's. rsi = the first field line's offset. A response's obs-fold
;        (which ha_h1_fields rewrites in place) is not taken here: the classic flow does it.
;   Out: eax = 0: every field line up to the empty line parsed exactly as ha_h1_fields parses
;        it (the records, their ids, .count, and the rules' findings in .seen, .content_length
;        and the request), and .head_end = the offset just past the empty line's CRLF.
;        eax = 1: anything else: a line ha_h1_fields would refuse (or the 431 of too many
;        fields), B cutting a line or coming before the empty line, a step near B that would
;        read into another page. The caller then parses the head again by the classic flow,
;        which names the outcome; what this left in the context and the records is partial, and
;        the classic flow clears or overwrites it.
;   Keeps rbx, rbp, r12-r15. Clobbers the other general registers, xmm0-xmm4, xmm8-xmm14 and
;   the flags.
;
;   Why it exists: the classic flow searches for the head's end line by line (ha_find_lf), then
;   parses every line again, and the search alone was 16% of a browser request's instructions,
;   with a loop exit to predict per line. Here each line is read once. A line: the name, 16
;   octets a step (HA_NIBBLE_CLASSIFY, tchar), must end at ":"; the value's end is the first
;   octet past the colon a value may not hold (HA_FIELD_VALUE_CLASSIFY), which must be the
;   line's CR with its LF next; OWS is trimmed as ha_h1_fields trims it; then the record,
;   ha_field_lookup, and the rules (H1_FIELD_RULES, ha_h1_fields' own source) by a table of
;   rules per id. A line that starts with CRLF ends the head.
;
;   Memory: a 16-octet step that starts at or below rbp (B less 17) ends with an octet to spare
;   before B, so whatever it finds is the caller's, and so is the octet after it (a CR's LF).
;   A step past rbp (.name_edge, .value_edge) must stay within the 4 KiB page of its first
;   octet, which is below B and so mapped, and only what it finds before B counts.
; -----------------------------------------------------------------------------
global ha_h1_fields_v2:function hidden (ha_h1_fields_v2.end - ha_h1_fields_v2)
align 16
ha_h1_fields_v2:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 8                          ; 16-byte aligned for ha_field_lookup; [rsp]: the rules
    mov     r12, rdi                        ; the context
    lea     rax, [rel h1_request_rule]
    lea     rcx, [rel h1_response_rule]
    cmp     dword [r12 + h1ctx.mode], HA_H1_RESPONSE
    cmove   rax, rcx
    mov     [rsp], rax                      ; the mode's rule table (the rules clobber r9-r11)
    mov     rbx, [r12 + h1ctx.buf]
    lea     r13, [rbx + rsi]                ; the line, as a pointer from here on
    mov     rbp, [r12 + h1ctx.head_end]
    lea     rbp, [rbx + rbp - 17]           ; the last step start with an octet to spare before B
    movdqa  xmm8, [rel ha_tchar_lo]
    movdqa  xmm9, [rel ha_tchar_hi]
    movdqa  xmm10, [rel ha_x16_0f]
    movdqa  xmm11, [rel ha_x16_1f]
    movdqa  xmm12, [rel ha_x16_09]
    movdqa  xmm13, [rel ha_x16_7f]
    pxor    xmm14, xmm14

.next_line:                                 ; where every rule ends: r13 is the next line already
.line:
    lea     rax, [r13 - 15]
    cmp     rax, rbp
    ja      .bail                           ; fewer than 2 octets before B: the head is cut
    cmp     word [r13], 0x0A0D
    je      .done                           ; the empty line: the head ends after it

    ; The name: tchars up to ":". No name, or anything else there (whitespace before the
    ; colon, an obs-fold line's SP or HTAB, any non-tchar) is a refusal: the classic flow's.
    mov     rdi, r13                        ; the name: ha_field_lookup's first argument
    cmp     r13, rbp
    ja      .name_edge
    movdqu  xmm0, [r13]
    HA_NIBBLE_CLASSIFY xmm0, xmm1, xmm2, xmm8, xmm9, xmm10, xmm14, ecx
    test    ecx, ecx
    jz      .name_more                      ; 16 tchars: the name goes on
    bsf     ecx, ecx
    lea     rsi, [r13 + rcx]                ; the first octet that is not a tchar
.name_end:                                  ; rsi: that octet, below B
    cmp     byte [rsi], ':'
    jne     .bail
    cmp     rsi, rdi
    je      .bail                           ; an empty name

    ; The record.
    mov     eax, [r12 + h1ctx.count]
    cmp     eax, [r12 + h1ctx.max_fields]
    jae     .bail                           ; one field too many: the classic flow's 431
    shl     rax, 5                          ; 32 octets per httpasm_field
    add     rax, [r12 + h1ctx.fields]
    mov     r14, rax                        ; the record, until the rules
    lea     r15, [rsi + 1]                  ; past the colon
    sub     rsi, rdi                        ; the name's length: ha_field_lookup's second argument
    mov     [r14 + httpasm_field.name], rdi
    mov     [r14 + httpasm_field.name_length], esi

    ; The value's end: the first octet past the colon that a value may not hold. OWS may stand
    ; there, so the scan starts before it; in a valid line the octet is the line's CR.
    mov     rax, r15
.value_step:
    cmp     rax, rbp
    ja      .value_edge
    movdqu  xmm0, [rax]
    HA_FIELD_VALUE_CLASSIFY xmm0, xmm1, xmm2, xmm11, xmm12, xmm13, ecx
    test    ecx, ecx
    jnz     .value_stop
    add     rax, 16
    jmp     .value_step
.value_stop:
    bsf     ecx, ecx
    add     rax, rcx
.value_end:                                 ; rax: that octet, with the next one below B
    cmp     word [rax], 0x0A0D
    jne     .bail                           ; a CTL, or a CR that no LF follows (a bare CR)
    lea     r13, [rax + 2]                  ; the next line

    ; OWS around the value, trimmed as ha_h1_fields trims it: leading OWS first (the CR stops
    ; it at the latest), then trailing OWS, down to where the leading stopped. An all-OWS value
    ; is then empty at the CR, as ha_h1_fields leaves it.
.leading:
    movzx   ecx, byte [r15]
    cmp     cl, ' '
    je      .leading_one
    cmp     cl, 9
    jne     .trailing
.leading_one:
    inc     r15
    jmp     .leading
.trailing:
    cmp     rax, r15
    jbe     .trimmed
    movzx   ecx, byte [rax - 1]
    cmp     cl, ' '
    je      .trailing_one
    cmp     cl, 9
    jne     .trimmed
.trailing_one:
    dec     rax
    jmp     .trailing
.trimmed:                                   ; the value: r15..rax
    mov     [r14 + httpasm_field.value], r15
    sub     rax, r15
    mov     [r14 + httpasm_field.value_length], eax
    mov     eax, [r12 + h1ctx.field_flags]
    mov     [r14 + httpasm_field.flags], ax
    mov     dword [r14 + httpasm_field.reserved], 0
    call    ha_field_lookup                 ; rdi, rsi: the name, a token (exact fold); eax = id
    mov     [r14 + httpasm_field.id], ax
    inc     dword [r12 + h1ctx.count]

    ; The mode's rules, by id (h1_request_rule, h1_response_rule: ha_h1_fields' dispatch as a
    ; table; a response's table names only the framing rules, so the request's never run).
    mov     rcx, [rsp]
    movzx   ecx, byte [rcx + rax]
    test    ecx, ecx
    jz      .line                           ; most fields have none
    mov     eax, [r14 + httpasm_field.value_length]
    lea     r14, [r15 + rax]                ; the rules read the value as r15..r14
    cmp     ecx, H1_RULE_HOST
    je      .host
    jb      .rule_framing
    cmp     ecx, H1_RULE_TE
    je      .te
    jb      .expect
    jmp     .upgrade
.rule_framing:
    cmp     ecx, H1_RULE_TRANSFER_ENCODING
    je      .transfer_encoding
    jb      .content_length
    jmp     .connection

    H1_FIELD_RULES

.done:
    lea     rax, [r13 + 2]
    sub     rax, rbx
    mov     [r12 + h1ctx.head_end], rax     ; just past the empty line's CRLF
    xor     eax, eax
.out:
    add     rsp, 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- Steps past rbp: fewer than 17 octets before B.
.name_edge:                                 ; the line's first step; .line left 2-16 octets
    mov     rsi, r13
.name_step_edge:                            ; rsi: the step, below B
    mov     ecx, esi
    and     ecx, 4095
    cmp     ecx, 4096 - 16
    ja      .bail                           ; 16 octets would reach the next page
    movdqu  xmm0, [rsi]
    HA_NIBBLE_CLASSIFY xmm0, xmm1, xmm2, xmm8, xmm9, xmm10, xmm14, ecx
    bsf     ecx, ecx
    jz      .bail                           ; no stop in 16 octets: B cuts the name
    lea     rdx, [rbp + 17]
    sub     rdx, rsi                        ; the octets before B
    cmp     rcx, rdx
    jae     .bail                           ; the stop lies at or past B: not the head's
    add     rsi, rcx
    jmp     .name_end
.name_more:                                 ; 16 tchars from the line's start
    lea     rsi, [r13 + 16]
.name_step:
    cmp     rsi, rbp
    ja      .name_step_edge
    movdqu  xmm0, [rsi]
    HA_NIBBLE_CLASSIFY xmm0, xmm1, xmm2, xmm8, xmm9, xmm10, xmm14, ecx
    test    ecx, ecx
    jnz     .name_step_stop
    add     rsi, 16
    jmp     .name_step
.name_step_stop:
    bsf     ecx, ecx
    add     rsi, rcx
    jmp     .name_end
.value_edge:                                ; rax: the step, at most B
    lea     rdx, [rbp + 17]
    sub     rdx, rax                        ; the octets before B
    jle     .bail                           ; none: B cuts the line
    mov     ecx, eax
    and     ecx, 4095
    cmp     ecx, 4096 - 16
    ja      .bail                           ; 16 octets would reach the next page
    movdqu  xmm0, [rax]
    HA_FIELD_VALUE_CLASSIFY xmm0, xmm1, xmm2, xmm11, xmm12, xmm13, ecx
    bsf     ecx, ecx
    jz      .bail                           ; no stop in 16 octets: B cuts the line
    inc     rcx
    cmp     rcx, rdx
    jae     .bail                           ; the octet after the stop (its LF) lies at or past B
    lea     rax, [rax + rcx - 1]
    jmp     .value_end

; The rules' refusals (H1_FIELD_RULES jumps here): the classic flow refuses again, by name.
.bad_content_length:
.host_duplicate:
.host_invalid:
.expectation_failed:
.bail:
    mov     eax, 1
    jmp     .out
.end:

; -----------------------------------------------------------------------------
; int64_t httpasm_h1_parse_request(const uint8_t *buf, size_t len, size_t *scan_from,
;                                  const httpasm_h1_limits *limits, httpasm_request *request,
;                                  httpasm_field *fields)
;   One request head from buf[0..len) (see this file's header for the rules).
;   Returns:
;     > 0  the head's length, leading empty lines included: *request and fields[0..count) are
;          filled, with pointers into buf; *scan_from is reset to 0;
;     0    the head is incomplete: call again with more octets appended (buf may move; the
;          offsets do not). *scan_from remembers where the search for the head's end resumes;
;          set it to 0 before a new message.
;     < 0  -status (400, 414, 417, 431, 501, 505): answer with it and close the connection.
;          request->error names the rule. *scan_from is reset to 0.
;   limits may be NULL (every default); fields must hold limits->max_fields records.
;   In: rdi, rsi, rdx, rcx, r8, r9 (System V). Keeps rbx, rbp, r12-r15.
;   Memory: reads buf[0..len) only, except that short scans may read up to 16 octets within the
;   page of their start (see HA_FIELD_VALUE_SCAN). Writes *request, *scan_from and the fields
;   array.
; -----------------------------------------------------------------------------
H1_FRAME_SCAN_FROM  equ h1ctx_size          ; size_t *scan_from
H1_FRAME_MAX_HEAD   equ h1ctx_size + 8      ; uint32_t
H1_FRAME_MAX_TARGET equ h1ctx_size + 12     ; uint32_t
H1_FRAME_LINE       equ h1ctx_size + 16     ; size_t: the request-line's offset, for a restart
H1_FRAME_ONE_PASS   equ h1ctx_size + 24     ; uint32_t: 1 while the one-pass flow runs
H1_FRAME_SIZE       equ h1ctx_size + 32     ; keeps rsp 16-byte aligned after the 6 pushes

global httpasm_h1_parse_request:function (httpasm_h1_parse_request.end - httpasm_h1_parse_request)
align 16
httpasm_h1_parse_request:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, H1_FRAME_SIZE
    mov     rbx, rdi                        ; buf
    mov     r12, rsi                        ; len
    mov     r14, r8                         ; request
    mov     r13, rsp                        ; the context lives at the frame's base
    mov     [rsp + H1_FRAME_SCAN_FROM], rdx
    mov     dword [rsp + H1_FRAME_ONE_PASS], 0  ; the classic flow until .one_pass says otherwise

    ; Limits: zero (or no limits at all) means the default.
    mov     eax, HA_H1_DEFAULT_MAX_HEAD
    mov     r10d, HA_H1_DEFAULT_MAX_TARGET
    mov     r11d, HA_H1_DEFAULT_MAX_FIELDS
    test    rcx, rcx
    jz      .limits_set
    mov     edx, [rcx + httpasm_h1_limits.max_head]
    test    edx, edx
    cmovnz  eax, edx
    mov     edx, [rcx + httpasm_h1_limits.max_target]
    test    edx, edx
    cmovnz  r10d, edx
    mov     edx, [rcx + httpasm_h1_limits.max_fields]
    test    edx, edx
    cmovnz  r11d, edx
.limits_set:
    mov     [rsp + H1_FRAME_MAX_HEAD], eax
    mov     [rsp + H1_FRAME_MAX_TARGET], r10d
    mov     [r13 + h1ctx.max_fields], r11d
    mov     [r13 + h1ctx.buf], rbx
    mov     [r13 + h1ctx.fields], r9
    mov     [r13 + h1ctx.request], r14
    xor     eax, eax
    mov     [r13 + h1ctx.content_length], rax
    mov     [r13 + h1ctx.count], eax
    mov     dword [r13 + h1ctx.mode], HA_H1_REQUEST
    mov     [r13 + h1ctx.seen], eax
    mov     [r13 + h1ctx.error], eax
    mov     [r13 + h1ctx.status], eax
    mov     [r13 + h1ctx.field_flags], eax

    ; A clean request record: every field the caller reads starts at 0 or NULL.
    pxor    xmm0, xmm0
    movdqu  [r14], xmm0
    movdqu  [r14 + 16], xmm0
    movdqu  [r14 + 32], xmm0
    movdqu  [r14 + 48], xmm0
    movdqu  [r14 + 64], xmm0
    movdqu  [r14 + 80], xmm0
    mov     [r14 + httpasm_request.fields], r9

    ; Empty lines before the request-line are skipped (RFC 9112 2.2).
    xor     r15d, r15d
.skip_empty:
    lea     rax, [r15 + 2]
    cmp     rax, r12
    ja      .skipped
    cmp     word [rbx + r15], 0x0A0D        ; CRLF
    jne     .skipped
    add     r15, 2
    jmp     .skip_empty
.skipped:

    ; The head's end: the first empty line. The search resumes where the last call left it, and
    ; never starts inside the skipped lines.
    mov     rdx, [rsp + H1_FRAME_SCAN_FROM]
    mov     rax, [rdx]
    cmp     rax, r12
    cmova   rax, r15                        ; a stale resume point past the data: from the start
    cmp     rax, r15
    cmovb   rax, r15
    ; From v2 up, a head searched from the request-line (a message's first call) is parsed in
    ; one pass instead (.one_pass). A resumed search keeps this flow, which scans only the
    ; octets that arrived since the last call.
    cmp     rax, r15
    jne     .find_lf
    HA_CPU_PICK1 HTTPASM_CPU_V2, .one_pass
.find_lf:
    mov     [r13 + h1ctx.line_lf], rax      ; scratch: where this search starts
    lea     rdi, [rbx + rax]
    mov     rsi, r12
    sub     rsi, rax
    call    ha_find_lf
    add     rax, [r13 + h1ctx.line_lf]
    cmp     rax, r12
    jae     .incomplete
    cmp     rax, r15
    jbe     .bare_lf                        ; an LF that starts the request-line
    cmp     byte [rbx + rax - 1], 0x0D
    jne     .bare_lf                        ; LF without CR
    lea     rdx, [r15 + 3]
    cmp     rax, rdx
    jb      .line_ended
    cmp     word [rbx + rax - 3], 0x0A0D
    je      .head_found                     ; CRLF CRLF: the empty line
.line_ended:
    inc     rax
    mov     edx, [rsp + H1_FRAME_MAX_HEAD]
    cmp     rax, rdx
    ja      .too_large
    jmp     .find_lf
.incomplete:
    mov     edx, [rsp + H1_FRAME_MAX_HEAD]
    cmp     r12, rdx
    ja      .too_large                      ; already past the limit, and still no end
    mov     rdx, [rsp + H1_FRAME_SCAN_FROM]
    mov     [rdx], r12                      ; resume at the end of what is here
    xor     eax, eax
    jmp     .return

.head_found:
    lea     rbp, [rax + 1]                  ; just past the final CRLF
    mov     edx, [rsp + H1_FRAME_MAX_HEAD]
    cmp     rbp, rdx
    ja      .too_large
    mov     [r13 + h1ctx.head_end], rbp
    mov     [r14 + httpasm_request.head_length], ebp

    ; ---- request-line = method SP request-target SP HTTP-version CRLF (RFC 9112 3)
    lea     rdi, [rbx + r15]
    mov     rsi, rbp
    sub     rsi, r15
    HA_TOKEN_SCAN rdi, rsi, rax, rcx, rdx
    test    rax, rax
    jz      .bad_method
    lea     rcx, [r15 + rax]
    movzx   edx, byte [rbx + rcx]
    cmp     dl, ' '
    je      .method_ok
    cmp     dl, 9
    je      .bad_line
    cmp     dl, 0x0D
    je      .bad_line
    jmp     .bad_method
.method_ok:
    lea     rdi, [rbx + r15]
    mov     [r14 + httpasm_request.method], rdi
    mov     [r14 + httpasm_request.method_length], eax
    mov     [r13 + h1ctx.record], rcx       ; scratch: the SP's offset
    mov     rsi, rax
    call    ha_method_lookup
    mov     [r14 + httpasm_request.method_id], ax
    mov     rcx, [r13 + h1ctx.record]
    lea     r15, [rcx + 1]                  ; the target's first octet

    ; The request-target: URI octets up to the next SP, percent-encodings well formed.
    lea     r8, [rel ha_char_class]
    lea     r9, [rel ha_hex_value]
    mov     rdx, r15
.target_octet:
    movzx   eax, byte [rbx + rdx]
    cmp     al, ' '
    je      .target_end
    test    byte [r8 + rax], HA_CC_TARGET
    jz      .target_refused
    cmp     al, '%'
    jne     .target_next
    ; Two HEXDIG follow, inside the head: the head ends in CRLF CRLF, which no HEXDIG matches.
    movzx   ecx, byte [rbx + rdx + 1]
    cmp     byte [r9 + rcx], 0xFF
    je      .bad_target
    movzx   ecx, byte [rbx + rdx + 2]
    cmp     byte [r9 + rcx], 0xFF
    je      .bad_target
    add     rdx, 2
.target_next:
    inc     rdx
    jmp     .target_octet
.target_refused:
    cmp     al, 0x0D
    je      .bad_line                       ; the line ended: no SP before HTTP-version
    cmp     al, 9
    je      .bad_line
    jmp     .bad_target
.target_end:
    mov     rax, rdx
    sub     rax, r15
    jz      .bad_line                       ; two SPs: an empty target
    mov     ecx, [rsp + H1_FRAME_MAX_TARGET]
    cmp     rax, rcx
    ja      .target_too_long
    lea     rcx, [rbx + r15]
    mov     [r14 + httpasm_request.target], rcx
    mov     [r14 + httpasm_request.target_length], eax

    ; HTTP-version = "HTTP" "/" DIGIT "." DIGIT, then CRLF at once (RFC 9112 2.3).
    lea     r15, [rdx + 1]
    lea     rax, [r15 + 10]
    cmp     rax, rbp
    ja      .bad_version
    cmp     dword [rbx + r15], 'HTTP'       ; case-sensitive (%s"HTTP")
    jne     .bad_version
    cmp     byte [rbx + r15 + 4], '/'
    jne     .bad_version
    movzx   eax, byte [rbx + r15 + 5]
    sub     eax, '0'
    cmp     eax, 9
    ja      .bad_version
    cmp     byte [rbx + r15 + 6], '.'
    jne     .bad_version
    movzx   ecx, byte [rbx + r15 + 7]
    sub     ecx, '0'
    cmp     ecx, 9
    ja      .bad_version
    cmp     word [rbx + r15 + 8], 0x0A0D
    jne     .bad_version
    cmp     eax, 1
    jne     .unsupported_version
    mov     edx, 11                         ; 1.1, and 1.2+ as 1.1 (RFC 9110 2.5)
    test    ecx, ecx
    jnz     .version_set
    mov     edx, 10
.version_set:
    mov     [r14 + httpasm_request.version], dl
    add     r15, 10                         ; the first field line

    ; ---- The request-target's form must suit the method (RFC 9112 3.2).
    mov     rsi, [r14 + httpasm_request.target]
    mov     ecx, [r14 + httpasm_request.target_length]
    movzx   eax, byte [rsi]
    movzx   edx, word [r14 + httpasm_request.method_id]
    cmp     edx, HTTPASM_METHOD_CONNECT
    je      .form_authority
    cmp     al, '/'
    je      .form_origin
    cmp     al, '*'
    jne     .form_absolute
    cmp     ecx, 1
    jne     .bad_form
    cmp     edx, HTTPASM_METHOD_OPTIONS
    jne     .bad_form                       ; asterisk-form is for OPTIONS only (RFC 9112 3.2.4)
    mov     byte [r14 + httpasm_request.target_form], HTTPASM_TARGET_ASTERISK
    jmp     .fields
.form_origin:
    mov     byte [r14 + httpasm_request.target_form], HTTPASM_TARGET_ORIGIN
    jmp     .fields

.form_absolute:
    ; absolute-URI: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ), then ":"
    test    byte [r8 + rax], HA_CC_ALPHA
    jz      .bad_form
    mov     edx, 1
.scheme_octet:
    cmp     edx, ecx
    jae     .bad_form                       ; no ":"
    movzx   eax, byte [rsi + rdx]
    cmp     al, ':'
    je      .scheme_end
    test    byte [r8 + rax], HA_CC_ALPHA | HA_CC_DIGIT
    jnz     .scheme_more
    cmp     al, '+'
    je      .scheme_more
    cmp     al, '-'
    je      .scheme_more
    cmp     al, '.'
    jne     .bad_form
.scheme_more:
    inc     edx
    jmp     .scheme_octet
.scheme_end:
    mov     [r14 + httpasm_request.scheme], rsi
    mov     [r14 + httpasm_request.scheme_length], edx
    ; "//" authority, up to "/", "?" or the target's end
    lea     eax, [edx + 3]
    cmp     eax, ecx
    ja      .no_authority
    cmp     word [rsi + rdx + 1], '//'
    jne     .no_authority
    lea     r9, [rsi + rdx + 3]             ; the authority's start
    lea     r10, [rsi + rcx]                ; the target's end
    mov     r11, r9
.authority_octet:
    cmp     r11, r10
    jae     .authority_end
    movzx   eax, byte [r11]
    cmp     al, '/'
    je      .authority_end
    cmp     al, '?'
    je      .authority_end
    inc     r11
    jmp     .authority_octet
.authority_end:
    mov     [r14 + httpasm_request.authority], r9
    sub     r11, r9
    mov     [r14 + httpasm_request.authority_length], r11d
.no_authority:
    ; An "http" or "https" URI with an empty host is invalid (RFC 9110 4.2.1, 4.2.2).
    mov     edx, [r14 + httpasm_request.scheme_length]
    cmp     edx, 4
    je      .scheme_http
    cmp     edx, 5
    jne     .absolute_done
    movzx   eax, byte [rsi + 4]
    or      eax, 0x20
    cmp     eax, 's'
    jne     .absolute_done
.scheme_http:
    mov     eax, [rsi]
    or      eax, 0x20202020
    cmp     eax, 'http'
    jne     .absolute_done
    mov     eax, [r14 + httpasm_request.authority_length]
    test    eax, eax
    jz      .bad_form
    mov     rdi, [r14 + httpasm_request.authority]
    cmp     byte [rdi], ':'
    je      .bad_form                       ; "http://:80/": a port without a host
    ; userinfo ("user@host") in an http(s) URI hides the real authority behind a lookalike
    ; (phishing): its presence is an error (RFC9110-4.2.4-4), as in HTTP/2's :authority.
.userinfo:
    cmp     byte [rdi], '@'
    je      .bad_form
    inc     rdi
    dec     eax                             ; eax: the authority's octets left
    jnz     .userinfo
    ; The rest of an http(s) authority: uri-host [ ":" port ] by Host's grammar (semantics/
    ; authority.inc), since this authority, not Host's, is the request's (RFC 9112 3.2.2): it
    ; must be held to the same rule. r8 is still ha_char_class; r9-r11 are free again.
    mov     r10, [r14 + httpasm_request.authority]
    mov     r11d, [r14 + httpasm_request.authority_length]
    add     r11, r10
    lea     r9, [rel ha_hex_value]
    HA_URI_HOST r10, r11, r8, r9, rax, eax, al, rdx, edx, .bad_form
.absolute_done:
    mov     byte [r14 + httpasm_request.target_form], HTTPASM_TARGET_ABSOLUTE
    jmp     .fields

.form_authority:
    ; CONNECT's target is uri-host ":" port and nothing else (RFC 9112 3.2.3): the host by the
    ; grammar Host follows, then the port CONNECT requires, 1 to 65535 (RFC9110-9.3.6-4). The
    ; macros are HTTP/2's too (semantics/authority.inc), so a CONNECT one version refuses the
    ; other refuses as well. r8 and r9 still hold ha_char_class and ha_hex_value (the target's
    ; scan above); rcx, the target's length, is kept for the record.
    mov     r10, rsi                        ; the cursor
    lea     r11, [rsi + rcx]                ; the target's end
    HA_URI_HOST r10, r11, r8, r9, rax, eax, al, rdx, edx, .bad_form
    HA_AUTHORITY_PORT rsi, r11, r10, eax, edx, r9d, .bad_form
    mov     byte [r14 + httpasm_request.target_form], HTTPASM_TARGET_AUTHORITY
    mov     [r14 + httpasm_request.authority], rsi
    mov     [r14 + httpasm_request.authority_length], ecx

    ; ---- The field lines, then the rules that need all of them.
.fields:
    cmp     dword [rsp + H1_FRAME_ONE_PASS], 0
    jne     .one_pass_fields                ; the one-pass flow reads them with the head's end
    mov     rdi, r13
    mov     rsi, r15
    call    ha_h1_fields
    test    eax, eax
    jnz     .context_failed
.fields_parsed:                             ; both flows: rbp = the head's end
    mov     eax, [r13 + h1ctx.count]
    mov     [r14 + httpasm_request.field_count], eax
    mov     eax, [r13 + h1ctx.seen]
    movzx   ecx, byte [r14 + httpasm_request.version]

    test    eax, HA_SEEN_HOST
    jnz     .host_present
    cmp     ecx, 11
    je      .host_missing                   ; HTTP/1.1 needs Host (RFC 9112 3.2)
.host_present:

    test    eax, HA_SEEN_TE
    jz      .no_transfer_encoding
    cmp     ecx, 10
    je      .te_in_http10                   ; RFC 9112 6.1: faulty framing
    test    eax, HA_SEEN_CONTENT_LENGTH
    jnz     .te_and_cl                      ; RFC 9112 6.3: a smuggling sign
    test    eax, HA_SEEN_BAD_CODING | HA_SEEN_AFTER_CHUNKED
    jnz     .te_not_chunked
    test    eax, HA_SEEN_CHUNKED
    jz      .te_not_chunked                 ; RFC 9112 6.3: no reliable length
    test    eax, HA_SEEN_UNKNOWN_CODING
    jnz     .te_unknown                     ; RFC 9112 6.1: 501
    or      dword [r14 + httpasm_request.flags], HTTPASM_REQUEST_CHUNKED
    jmp     .framing_done
.no_transfer_encoding:
    test    eax, HA_SEEN_CONTENT_LENGTH
    jz      .framing_done                   ; no body (RFC 9112 6.3: a request's length is 0)
    mov     rdx, [r13 + h1ctx.content_length]
    mov     [r14 + httpasm_request.content_length], rdx
    or      dword [r14 + httpasm_request.flags], HTTPASM_REQUEST_CONTENT_LENGTH
.framing_done:

    ; The flags the caller reads.
    xor     edx, edx
    test    eax, HA_SEEN_HOST
    jz      .f1
    or      edx, HTTPASM_REQUEST_HOST
.f1:
    test    eax, HA_SEEN_EXPECT_CONTINUE
    jz      .f2
    or      edx, HTTPASM_REQUEST_EXPECT_CONTINUE
.f2:
    test    eax, HA_SEEN_TE_TRAILERS
    jz      .f3
    or      edx, HTTPASM_REQUEST_TE_TRAILERS
.f3:
    test    eax, HA_SEEN_UPGRADE
    jz      .f4
    or      edx, HTTPASM_REQUEST_UPGRADE
.f4:
    test    eax, HA_SEEN_CLOSE
    jz      .f5
    or      edx, HTTPASM_REQUEST_CLOSE
    jmp     .persistence_done               ; close wins over everything (RFC 9112 9.6)
.f5:
    ; Persistence (RFC 9112 9.3): HTTP/1.1 persists; HTTP/1.0 only with keep-alive.
    cmp     ecx, 11
    je      .persists
    test    eax, HA_SEEN_KEEP_ALIVE
    jz      .persistence_done
.persists:
    or      edx, HTTPASM_REQUEST_KEEP_ALIVE
.persistence_done:
    or      [r14 + httpasm_request.flags], edx

    mov     rdx, [rsp + H1_FRAME_SCAN_FROM]
    mov     qword [rdx], 0
    mov     rax, rbp                        ; the head's length
    jmp     .return

; ---- refusals: the rule in ecx, the status in edx
.bare_lf:
    mov     ecx, HTTPASM_ERROR_BARE_LF
    mov     edx, 400
    jmp     .fail
.bad_method:
    mov     ecx, HTTPASM_ERROR_METHOD
    mov     edx, 400
    jmp     .fail
.bad_line:
    mov     ecx, HTTPASM_ERROR_REQUEST_LINE
    mov     edx, 400
    jmp     .fail
.bad_target:
    mov     ecx, HTTPASM_ERROR_TARGET
    mov     edx, 400
    jmp     .fail
.target_too_long:
    mov     ecx, HTTPASM_ERROR_TARGET_TOO_LONG
    mov     edx, 414
    jmp     .fail
.bad_form:
    mov     ecx, HTTPASM_ERROR_TARGET_FORM
    mov     edx, 400
    jmp     .fail
.bad_version:
    mov     ecx, HTTPASM_ERROR_VERSION
    mov     edx, 400
    jmp     .fail
.unsupported_version:
    mov     ecx, HTTPASM_ERROR_VERSION_UNSUPPORTED
    mov     edx, 505
    jmp     .fail
.too_large:
    mov     ecx, HTTPASM_ERROR_HEAD_TOO_LARGE
    mov     edx, 431
    jmp     .fail
.host_missing:
    mov     ecx, HTTPASM_ERROR_HOST_MISSING
    mov     edx, 400
    jmp     .fail
.te_in_http10:
    mov     ecx, HTTPASM_ERROR_TE_HTTP10
    mov     edx, 400
    jmp     .fail
.te_and_cl:
    mov     ecx, HTTPASM_ERROR_TE_AND_CL
    mov     edx, 400
    jmp     .fail
.te_not_chunked:
    mov     ecx, HTTPASM_ERROR_TE_NOT_CHUNKED
    mov     edx, 400
    jmp     .fail
.te_unknown:
    mov     ecx, HTTPASM_ERROR_TE_UNKNOWN
    mov     edx, 501
    jmp     .fail
.context_failed:
    mov     ecx, [r13 + h1ctx.error]
    mov     edx, [r13 + h1ctx.status]
    mov     eax, [r13 + h1ctx.count]
    mov     [r14 + httpasm_request.field_count], eax
.fail:
    cmp     dword [rsp + H1_FRAME_ONE_PASS], 0
    jne     .one_pass_bail                  ; the one-pass flow never refuses: see .one_pass
    mov     [r14 + httpasm_request.error], cx
    mov     rax, [rsp + H1_FRAME_SCAN_FROM]
    mov     qword [rax], 0
    mov     rax, rdx
    neg     rax                             ; -status
.return:
    add     rsp, H1_FRAME_SIZE
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- The one-pass flow (v2 and up) ----------------------------------------------------------
; A head searched from the request-line is parsed without searching for its end first: the
; method and the request-target here, 16 octets a step; the HTTP-version and the target's form
; by the classic code from .target_end on; the field lines by ha_h1_fields_v2, which finds the
; empty line on the way. Reads stay below the bound B = min(len, max_head) (rbp holds it until
; the head's end replaces it): no head the classic flow accepts reaches past it.
;
; This flow only ever accepts. Anything else - a refusal, B cutting the head (incomplete, or too
; large), a method of 16 octets or more, a step near B that would read into another page - goes
; to .one_pass_bail, which starts the classic flow over from the request-line, and the classic
; flow names the outcome. So every outcome is the classic flow's: a head accepted here has every
; line checked by the same rules, every line ended by CRLF (so no bare LF precedes its end, and
; its end is the first CRLF CRLF), and anything else is the classic flow's answer by
; construction. A refused head costs the attempt once more at most, bounded by max_head.
.one_pass:
    mov     dword [rsp + H1_FRAME_ONE_PASS], 1
    mov     [rsp + H1_FRAME_LINE], r15
    mov     ecx, [rsp + H1_FRAME_MAX_HEAD]
    mov     rbp, r12
    cmp     rbp, rcx
    cmova   rbp, rcx                        ; B
    movdqa  xmm8, [rel ha_tchar_lo]
    movdqa  xmm9, [rel ha_tchar_hi]
    movdqa  xmm10, [rel ha_x16_0f]
    movdqa  xmm11, [rel ha_target_lo]
    pxor    xmm14, xmm14
    lea     rsi, [rbx + rbp - 17]           ; the last step start with an octet to spare before B

    ; The method: tchars, then SP, within the first 16 octets.
    lea     rdi, [rbx + r15]
    cmp     rdi, rsi
    ja      .one_pass_bail                  ; fewer than 17 octets before B: the classic flow
    movdqu  xmm0, [rdi]
    HA_NIBBLE_CLASSIFY xmm0, xmm1, xmm2, xmm8, xmm9, xmm10, xmm14, ecx
    bsf     ecx, ecx
    jz      .one_pass_bail                  ; 16 tchars: a method that long takes the classic flow
    test    ecx, ecx
    jz      .one_pass_bail                  ; no method
    cmp     byte [rdi + rcx], ' '
    jne     .one_pass_bail                  ; not SP after it (HTAB, CR, a non-tchar)
    mov     [r14 + httpasm_request.method], rdi
    mov     [r14 + httpasm_request.method_length], ecx
    lea     r15, [r15 + rcx + 1]            ; the target's first octet
    mov     esi, ecx
    call    ha_method_lookup                ; rdi, rsi: the method; keeps all else but eax
    mov     [r14 + httpasm_request.method_id], ax
    lea     rsi, [rbx + rbp - 17]           ; the step limit again (rsi held the method's length)

    ; The request-target: 16 octets a step to the first octet ha_target_lo does not pass (SP, the
    ; target's end; "%", whose two HEXDIG are checked here before B; anything else is a refusal).
    ; r8 and r9 as the classic scan leaves them, for the form checks after .target_end.
    lea     r8, [rel ha_char_class]
    lea     r9, [rel ha_hex_value]
    lea     rax, [rbx + r15]
.one_pass_target:
    cmp     rax, rsi
    ja      .one_pass_target_edge
    movdqu  xmm0, [rax]
    HA_NIBBLE_CLASSIFY xmm0, xmm1, xmm2, xmm11, xmm9, xmm10, xmm14, ecx
    test    ecx, ecx
    jnz     .one_pass_target_stop
    add     rax, 16
    jmp     .one_pass_target
.one_pass_target_stop:
    bsf     ecx, ecx
    add     rax, rcx
.one_pass_target_at:                        ; rax: the octet the scan stopped at, below B
    movzx   ecx, byte [rax]
    cmp     cl, ' '
    je      .one_pass_target_end
    cmp     cl, '%'
    jne     .one_pass_bail                  ; an octet a target may not hold, or the line's CR
    lea     rdx, [rax + 3]
    lea     rcx, [rbx + rbp]
    cmp     rdx, rcx
    ja      .one_pass_bail                  ; B cuts the percent-encoding
    movzx   ecx, byte [rax + 1]
    cmp     byte [r9 + rcx], 0xFF
    je      .one_pass_bail                  ; not two HEXDIG (RFC 3986 2.1)
    movzx   ecx, byte [rax + 2]
    cmp     byte [r9 + rcx], 0xFF
    je      .one_pass_bail
    mov     rax, rdx                        ; past the percent-encoding
    jmp     .one_pass_target
.one_pass_target_edge:                      ; fewer than 17 octets before B
    lea     rdx, [rbx + rbp]
    sub     rdx, rax                        ; the octets before B
    jle     .one_pass_bail                  ; none: B cuts the target
    mov     ecx, eax
    and     ecx, 4095
    cmp     ecx, 4096 - 16
    ja      .one_pass_bail                  ; 16 octets would reach the next page
    movdqu  xmm0, [rax]
    HA_NIBBLE_CLASSIFY xmm0, xmm1, xmm2, xmm11, xmm9, xmm10, xmm14, ecx
    bsf     ecx, ecx
    jz      .one_pass_bail                  ; no stop in 16 octets: B cuts the target
    cmp     rcx, rdx
    jae     .one_pass_bail                  ; the stop lies at or past B: not the head's
    add     rax, rcx
    jmp     .one_pass_target_at
.one_pass_target_end:
    sub     rax, rbx
    mov     rdx, rax                        ; the SP's offset, as the classic scan leaves it
    jmp     .target_end                     ; rbp = B bounds the HTTP-version there

.one_pass_fields:                           ; from .fields: the request-line is done
    mov     [r13 + h1ctx.head_end], rbp     ; B, for ha_h1_fields_v2
    mov     rdi, r13
    mov     rsi, r15
    call    ha_h1_fields_v2
    test    eax, eax
    jnz     .one_pass_bail
    mov     rbp, [r13 + h1ctx.head_end]     ; just past the empty line's CRLF
    mov     [r14 + httpasm_request.head_length], ebp
    jmp     .fields_parsed

.one_pass_bail:
    ; The classic flow from the request-line, as if this attempt had not run: the context's
    ; findings and the request record cleared as the entry clears them (the records past them
    ; are overwritten, and the caller reads only field_count of them).
    mov     dword [rsp + H1_FRAME_ONE_PASS], 0
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
    movdqu  [r14 + 64], xmm0
    movdqu  [r14 + 80], xmm0
    mov     rax, [r13 + h1ctx.fields]
    mov     [r14 + httpasm_request.fields], rax
    mov     r15, [rsp + H1_FRAME_LINE]
    mov     rax, r15                        ; the search for the end starts at the request-line
    jmp     .find_lf
.end:
