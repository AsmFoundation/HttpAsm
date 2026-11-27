; =============================================================================
; h2/h2_request.asm - an HTTP/2 request's header list (as httpasm_hpack_decode gives it) into the
; request view every version shares (httpasm_request), under RFC 9113's rules; and the checks
; on a request's trailer section.
;
; Rules, by section of RFC 9113 (any failure makes the request malformed, 8.1.1: a stream error
; PROTOCOL_ERROR, except an unmet expectation, which is answered 417):
;   8.2.1  a field name is a token (RFC 9110 5.1) without upper case; a value holds no CTL but
;          HTAB (the same octet rule HTTP/1.1 applies: shared source) and no whitespace at
;          either end;
;   8.2.2  no connection-specific field (Connection, Keep-Alive, Proxy-Connection,
;          Transfer-Encoding, Upgrade); TE only as "trailers";
;   8.3    pseudo-fields come first, once each, and only the request's four (:status, :protocol
;          and unknown ones are malformed);
;   8.3.1  :method, :scheme and :path are present and not empty; :path is "*" only for OPTIONS
;          and otherwise starts with "/", with the URI octets and percent-encodings HTTP/1.1's
;          request-target allows (a :path HTTP/1.1 would refuse must not pass here, or the two
;          could be played against each other); :authority is uri-host [ ":" port ] by
;          HTTP/1.1's Host grammar (semantics/authority.inc, the same text), so it has no
;          userinfo; a Host field follows that grammar too, and must name the same authority;
;   8.5    CONNECT carries :authority and neither :scheme nor :path; its :authority is the
;          authority-form, with a port of 1 to 65535, as HTTP/1.1's CONNECT target is.
; Content-Length must be 1*DIGIT (repeated only with the same value); that it matches the DATA
; is the engine's check (8.1.1). Expect: 100-continue is flagged, any other expectation is 417.
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "h2/h2.inc"

section .rodata
s_method:       db ":method"
s_scheme:       db ":scheme"
s_authority:    db ":authority"
s_path:         db ":path"
s_trailers:     db "trailers"
s_continue:     db "100-continue"

section .text

; Which pseudo-fields were seen, and whether a regular field was (r14d)
RQ_METHOD       equ 0x01
RQ_SCHEME       equ 0x02
RQ_AUTHORITY    equ 0x04
RQ_PATH         equ 0x08
RQ_REGULAR      equ 0x10

; -----------------------------------------------------------------------------
; h2_name: whether rdi[0..rsi) is a lower-case token (RFC9113-8.2.1-3.1, RFC 9110 5.1).
;   In: rdi, rsi (kept). Out: ZF set when it is. Clobbers rax, rcx, rdx, xmm0-xmm6 and the flags.
;   Two versions, the same answer for every name (HA_CPU_PICK1 after the empty check):
;     v1  one class-table lookup per octet: HA_CC_TCHAR set and HA_CC_UPPER clear;
;     v2  ha_span_v2 with ha_ltchar_lo (tables.asm: computed from HA_IS_LTCHAR, the same
;         predicate, and proven for all 256 octets), 16 octets a step: the name is valid when
;         the span is the whole name. A browser request's 18 names cost 1,548 instructions at v1.
;   Memory: v1 reads the name only; v2 as ha_span_v2 (within the name, or 16 octets inside the
;   page of its first octet), so a name anywhere in the caller's memory is safe.
; -----------------------------------------------------------------------------
align 16
h2_name:
    test    rsi, rsi
    jz      .bad
    HA_CPU_PICK1 HTTPASM_CPU_V2, .v2
    lea     rdx, [rel ha_char_class]
    xor     ecx, ecx
    jmp     .octet                          ; over the padding: the loop starts a 32-octet window
align 32
.octet:
    movzx   eax, byte [rdi + rcx]
    movzx   eax, byte [rdx + rax]
    and     eax, HA_CC_TCHAR | HA_CC_UPPER
    cmp     eax, HA_CC_TCHAR                ; a tchar that is not A-Z
    jne     .bad
    inc     rcx
    cmp     rcx, rsi
    jb      .octet
    xor     eax, eax                        ; ZF set
    ret
.bad:
    or      eax, 1                          ; ZF clear
    ret
.v2:
    movdqa  xmm3, [rel ha_ltchar_lo]
    call    ha_span_v2                      ; rax = the leading octets a name may hold
    cmp     rax, rsi                        ; ZF set exactly when that is all of it
    ret

; -----------------------------------------------------------------------------
; h2_value: whether rdi[0..rsi) is a field value HTTP/2 accepts: no CTL but HTAB (the shared
; field-value scan: RFC9113-8.2.1-3.3 and RFC 9110 5.5), no SP or HTAB at either end
; (RFC9113-8.2.1-3.4).
;   Out: ZF set when it is. Clobbers rax, rcx, rdx, xmm0-xmm5 and the flags.
; -----------------------------------------------------------------------------
align 16
h2_value:
    test    rsi, rsi
    jz      .ok                             ; an empty value is valid
    movzx   eax, byte [rdi]
    cmp     al, ' '
    je      .bad
    cmp     al, 9
    je      .bad
    movzx   eax, byte [rdi + rsi - 1]
    cmp     al, ' '
    je      .bad
    cmp     al, 9
    je      .bad
    HA_FIELD_VALUE_SCAN rdi, rsi, rax, rcx, ecx, rdx, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5
    cmp     rax, rsi
    jne     .bad
.ok:
    xor     eax, eax
    ret
.bad:
    or      eax, 1
    ret

; -----------------------------------------------------------------------------
; name_is: whether the name of the record at r12 is the cl-octet string at rdx (exactly).
;   In: r12, rdx, cl = 4-16 (the pseudo-field names: 5, 7 and 10 octets). Out: ZF set when it
;   is. Clobbers rax, rcx, rsi and the flags.
;   Two overlapping loads per side cover any length from 4 to 16: the first and the last 4
;   octets up to 8, the first and the last 8 beyond (each octet compared at least once). It
;   replaced repe cmpsb, microcode whose start-up cost was most of each compare; every load
;   stays inside the name and the string, whose lengths are equal by then.
; -----------------------------------------------------------------------------
align 16
name_is:
    movzx   ecx, cl
    cmp     ecx, [r12 + httpasm_field.name_length]
    jne     .out                            ; ZF clear
    mov     rsi, [r12 + httpasm_field.name]
    cmp     ecx, 8
    ja      .long
    mov     eax, [rsi]
    cmp     eax, [rdx]
    jne     .out
    mov     eax, [rsi + rcx - 4]
    cmp     eax, [rdx + rcx - 4]
.out:
    ret
.long:
    mov     rax, [rsi]
    cmp     rax, [rdx]
    jne     .out
    mov     rax, [rsi + rcx - 8]
    cmp     rax, [rdx + rcx - 8]
    ret

; -----------------------------------------------------------------------------
; value_is: whether the value of the record at r12 is the cl-octet string at rdx, ignoring the
; case of letters. The string is lower-case letters, digits and "-"; the value was checked to
; hold no CTL, so folding with | 0x20 cannot make another octet match (only CR would turn into
; "-", and it was refused).
;   Out: ZF set when it is. Clobbers rax, rcx, rsi, rdi and the flags.
; -----------------------------------------------------------------------------
align 16
value_is:
    movzx   ecx, cl
    cmp     ecx, [r12 + httpasm_field.value_length]
    jne     .out
    mov     rsi, [r12 + httpasm_field.value]
    xor     edi, edi
.octet:
    movzx   eax, byte [rsi + rdi]
    or      al, 0x20
    cmp     al, [rdx + rdi]
    jne     .out
    inc     edi
    cmp     edi, ecx
    jb      .octet
    xor     eax, eax
.out:
    ret

; -----------------------------------------------------------------------------
; int httpasm_h2_request(httpasm_field *fields, uint32_t count, httpasm_request *request)
;   Checks a request's decoded header list (see this file's header) and fills request: method
;   (and method_id), target (:path, or :authority for CONNECT) and target_form, authority
;   (:authority, else Host), scheme, version 20, flags (KEEP_ALIVE always: the connection
;   persists; HOST, CONTENT_LENGTH with content_length, EXPECT_CONTINUE, TE_TRAILERS), and
;   fields/field_count: the regular fields, which follow the pseudo-fields in the same array.
;   Each record's id is set again from its name (the caller's is not trusted).
;   Returns 0; or -HTTPASM_ERROR_* with request->error set: H2_PSEUDO, H2_MISSING,
;   H2_CONNECTION_FIELD, H2_AUTHORITY, FIELD_NAME, FIELD_VALUE, METHOD, TARGET, CONTENT_LENGTH,
;   HOST_DUPLICATE, HOST_INVALID (all malformed: PROTOCOL_ERROR on the stream), or EXPECT
;   (answer 417).
; -----------------------------------------------------------------------------
RQ_PSEUDOS      equ 0       ; frame: how many pseudo-fields lead the array
RQ_HOST         equ 8       ; frame: the Host record, or 0
RQ_FRAME        equ 24      ; six pushes + 24: aligned for the calls

global httpasm_h2_request:function (httpasm_h2_request.end - httpasm_h2_request)
align 16
httpasm_h2_request:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, RQ_FRAME
    mov     rbx, rdx                        ; request
    mov     rbp, rdi                        ; the array
    mov     r12, rdi                        ; the record
    mov     r13d, esi                       ; records left
    xor     r14d, r14d                      ; RQ_* seen
    xor     eax, eax
    mov     [rsp + RQ_PSEUDOS], rax
    mov     [rsp + RQ_HOST], rax
    pxor    xmm0, xmm0                      ; a clean request: every field starts at 0 or NULL
    movdqu  [rbx], xmm0
    movdqu  [rbx + 16], xmm0
    movdqu  [rbx + 32], xmm0
    movdqu  [rbx + 48], xmm0
    movdqu  [rbx + 64], xmm0
    movdqu  [rbx + 80], xmm0
    mov     byte [rbx + httpasm_request.version], 20
    mov     dword [rbx + httpasm_request.flags], HTTPASM_REQUEST_KEEP_ALIVE

.field:
    test    r13d, r13d
    jz      .fields_done
    mov     rdi, [r12 + httpasm_field.name]
    mov     esi, [r12 + httpasm_field.name_length]
    test    esi, esi
    jz      .bad_name
    cmp     byte [rdi], ':'
    jne     .regular

    ; A pseudo-field: before every regular field, once, one of the request's four.
    test    r14d, RQ_REGULAR
    jnz     .bad_pseudo
    inc     qword [rsp + RQ_PSEUDOS]
    mov     rdi, [r12 + httpasm_field.value]
    mov     esi, [r12 + httpasm_field.value_length]
    call    h2_value
    jnz     .bad_value
    lea     rdx, [rel s_method]
    mov     cl, 7
    call    name_is
    je      .method
    lea     rdx, [rel s_scheme]
    mov     cl, 7
    call    name_is
    je      .scheme
    lea     rdx, [rel s_authority]
    mov     cl, 10
    call    name_is
    je      .authority
    lea     rdx, [rel s_path]
    mov     cl, 5
    call    name_is
    je      .path
    jmp     .bad_pseudo                     ; :status, :protocol, or not defined
.method:
    test    r14d, RQ_METHOD
    jnz     .bad_pseudo
    or      r14d, RQ_METHOD
    mov     word [r12 + httpasm_field.id], HA_FIELD_PSEUDO_METHOD
    mov     rax, [r12 + httpasm_field.value]
    mov     [rbx + httpasm_request.method], rax
    mov     eax, [r12 + httpasm_field.value_length]
    mov     [rbx + httpasm_request.method_length], eax
    jmp     .next
.scheme:
    test    r14d, RQ_SCHEME
    jnz     .bad_pseudo
    or      r14d, RQ_SCHEME
    mov     word [r12 + httpasm_field.id], HA_FIELD_PSEUDO_SCHEME
    mov     rax, [r12 + httpasm_field.value]
    mov     [rbx + httpasm_request.scheme], rax
    mov     eax, [r12 + httpasm_field.value_length]
    mov     [rbx + httpasm_request.scheme_length], eax
    jmp     .next
.authority:
    test    r14d, RQ_AUTHORITY
    jnz     .bad_pseudo
    or      r14d, RQ_AUTHORITY
    mov     word [r12 + httpasm_field.id], HA_FIELD_PSEUDO_AUTHORITY
    mov     rax, [r12 + httpasm_field.value]
    mov     [rbx + httpasm_request.authority], rax
    mov     eax, [r12 + httpasm_field.value_length]
    mov     [rbx + httpasm_request.authority_length], eax
    jmp     .next
.path:
    test    r14d, RQ_PATH
    jnz     .bad_pseudo
    or      r14d, RQ_PATH
    mov     word [r12 + httpasm_field.id], HA_FIELD_PSEUDO_PATH
    mov     rax, [r12 + httpasm_field.value]
    mov     [rbx + httpasm_request.target], rax
    mov     eax, [r12 + httpasm_field.value_length]
    mov     [rbx + httpasm_request.target_length], eax
    jmp     .next

.regular:
    or      r14d, RQ_REGULAR
    call    h2_name                         ; rdi, rsi: the name
    jnz     .bad_name
    mov     rdi, [r12 + httpasm_field.name]
    mov     esi, [r12 + httpasm_field.name_length]
    call    ha_field_lookup
    mov     [r12 + httpasm_field.id], ax
    mov     r15d, eax
    mov     rdi, [r12 + httpasm_field.value]
    mov     esi, [r12 + httpasm_field.value_length]
    call    h2_value
    jnz     .bad_value
    cmp     r15d, HA_FIELD_CONNECTION       ; connection-specific: they mean nothing in HTTP/2
    je      .connection_field               ; and would be smuggled into an HTTP/1.1 hop
    cmp     r15d, HA_FIELD_KEEP_ALIVE
    je      .connection_field
    cmp     r15d, HA_FIELD_PROXY_CONNECTION
    je      .connection_field
    cmp     r15d, HA_FIELD_TRANSFER_ENCODING
    je      .connection_field
    cmp     r15d, HA_FIELD_UPGRADE
    je      .connection_field
    cmp     r15d, HA_FIELD_TE
    je      .te
    cmp     r15d, HA_FIELD_HOST
    je      .host
    cmp     r15d, HA_FIELD_CONTENT_LENGTH
    je      .content_length
    cmp     r15d, HA_FIELD_EXPECT
    je      .expect
    jmp     .next
.te:
    lea     rdx, [rel s_trailers]
    mov     cl, 8
    call    value_is
    jne     .connection_field               ; TE carries only "trailers" (RFC9113-8.2.2-2)
    or      dword [rbx + httpasm_request.flags], HTTPASM_REQUEST_TE_TRAILERS
    jmp     .next
.host:
    cmp     qword [rsp + RQ_HOST], 0
    jne     .host_duplicate
    ; uri-host [ ":" port ], by HTTP/1.1's own Host grammar (semantics/authority.inc): a Host
    ; an HTTP/1.1 hop would refuse must not pass here either. tests/fuzz/h2_request found this
    ; open (2026-11-26): any value without CTLs passed. r8-r10 are free here (.origin loads
    ; its own tables), as are rax, rcx, rdx and rsi.
    mov     rsi, [r12 + httpasm_field.value]
    mov     ecx, [r12 + httpasm_field.value_length]
    lea     r10, [rsi + rcx]
    lea     r8, [rel ha_char_class]
    lea     r9, [rel ha_hex_value]
    HA_URI_HOST rsi, r10, r8, r9, rax, eax, al, rdx, edx, .bad_host
    mov     [rsp + RQ_HOST], r12
    or      dword [rbx + httpasm_request.flags], HTTPASM_REQUEST_HOST
    jmp     .next
.content_length:
    ; 1*DIGIT, at most 2^63 - 1; a repeat must carry the same value.
    mov     rsi, [r12 + httpasm_field.value]
    mov     ecx, [r12 + httpasm_field.value_length]
    test    ecx, ecx
    jz      .bad_length
    xor     eax, eax
    xor     edi, edi
.digit:
    movzx   edx, byte [rsi + rdi]
    sub     edx, '0'
    cmp     edx, 9
    ja      .bad_length
    mov     r8, 0x0CCCCCCCCCCCCCCC          ; past this, value * 10 + 9 can overflow 2^63 - 1
    cmp     rax, r8
    ja      .bad_length
    imul    rax, rax, 10
    add     rax, rdx
    js      .bad_length
    inc     edi
    cmp     edi, ecx
    jb      .digit
    test    dword [rbx + httpasm_request.flags], HTTPASM_REQUEST_CONTENT_LENGTH
    jz      .length_set
    cmp     rax, [rbx + httpasm_request.content_length]
    jne     .bad_length
.length_set:
    mov     [rbx + httpasm_request.content_length], rax
    or      dword [rbx + httpasm_request.flags], HTTPASM_REQUEST_CONTENT_LENGTH
    jmp     .next
.expect:
    lea     rdx, [rel s_continue]
    mov     cl, 12
    call    value_is
    jne     .bad_expect
    or      dword [rbx + httpasm_request.flags], HTTPASM_REQUEST_EXPECT_CONTINUE
.next:
    add     r12, httpasm_field_size
    dec     r13d
    jmp     .field

.fields_done:
    ; The regular fields: the array's tail, after the pseudo-fields.
    mov     rax, [rsp + RQ_PSEUDOS]
    shl     rax, 5
    add     rax, rbp
    mov     [rbx + httpasm_request.fields], rax
    mov     rax, r12                        ; one past the last record
    sub     rax, [rbx + httpasm_request.fields]
    shr     rax, 5
    mov     [rbx + httpasm_request.field_count], eax

    ; :method: present, a token.
    test    r14d, RQ_METHOD
    jz      .missing
    mov     rdi, [rbx + httpasm_request.method]
    mov     esi, [rbx + httpasm_request.method_length]
    test    esi, esi
    jz      .missing
    HA_TOKEN_SCAN rdi, rsi, rax, rcx, rdx
    cmp     rax, rsi
    jne     .bad_method
    call    ha_method_lookup
    mov     [rbx + httpasm_request.method_id], ax
    cmp     eax, HTTPASM_METHOD_CONNECT
    je      .connect

    ; :scheme and :path: present, not empty.
    test    r14d, RQ_SCHEME
    jz      .missing
    test    r14d, RQ_PATH
    jz      .missing
    mov     rdi, [rbx + httpasm_request.scheme]
    mov     esi, [rbx + httpasm_request.scheme_length]
    test    esi, esi
    jz      .missing
    HA_TOKEN_SCAN rdi, rsi, rax, rcx, rdx   ; a scheme is ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ),
    cmp     rax, rsi                        ; within tchar
    jne     .bad_pseudo
    mov     rdi, [rbx + httpasm_request.target]
    mov     esi, [rbx + httpasm_request.target_length]
    test    esi, esi
    jz      .missing
    cmp     byte [rdi], '/'
    je      .origin
    cmp     esi, 1                          ; "*": OPTIONS only (RFC9113-8.3.1-2.4.2)
    jne     .bad_target
    cmp     byte [rdi], '*'
    jne     .bad_target
    cmp     word [rbx + httpasm_request.method_id], HTTPASM_METHOD_OPTIONS
    jne     .bad_target
    mov     byte [rbx + httpasm_request.target_form], HTTPASM_TARGET_ASTERISK
    jmp     .authority_check
.origin:
    ; The octets of an HTTP/1.1 request-target, percent-encodings complete. Two versions, the
    ; same answer for every :path (HA_CPU_PICK1): v1 octet by octet below; v2 by runs
    ; (.origin_v2).
    HA_CPU_PICK1 HTTPASM_CPU_V2, .origin_v2
    lea     r8, [rel ha_char_class]
    lea     r9, [rel ha_hex_value]
    xor     edx, edx
    jmp     .path_octet                     ; over the padding: the loop starts a 32-octet window
align 32
.path_octet:
    movzx   eax, byte [rdi + rdx]
    test    byte [r8 + rax], HA_CC_TARGET
    jz      .bad_target
    cmp     al, '%'
    jne     .path_next
    lea     ecx, [rdx + 2]
    cmp     ecx, esi
    jae     .bad_target                     ; two HEXDIG must follow, inside the value
    movzx   ecx, byte [rdi + rdx + 1]
    cmp     byte [r9 + rcx], 0xFF
    je      .bad_target
    movzx   ecx, byte [rdi + rdx + 2]
    cmp     byte [r9 + rcx], 0xFF
    je      .bad_target
    add     edx, 2
.path_next:
    inc     edx
    cmp     edx, esi
    jb      .path_octet
.origin_done:
    mov     byte [rbx + httpasm_request.target_form], HTTPASM_TARGET_ORIGIN
    jmp     .authority_check

.origin_v2:
    ; v2: runs of target octets but "%" (ha_span_v2 with ha_target_lo, 16 octets a step), each
    ; run's stop a "%" whose two HEXDIG lie inside the value, or a refusal; then the next run
    ; from past the HEXDIG. v1's answer exactly: it takes every HA_CC_TARGET octet (the run
    ; class and "%": tables.asm computes both from HA_IS_TARGET) and checks each "%" the same
    ; way. rdi and rsi walk the value (the request keeps its own copy of both); r9 and xmm3
    ; survive ha_span_v2. A :path of 63 octets cost 512 instructions octet by octet.
    lea     r9, [rel ha_hex_value]
    movdqa  xmm3, [rel ha_target_lo]
.path_run:                                  ; rdi: the run's first octet; rsi: octets left (> 0)
    call    ha_span_v2
    cmp     rax, rsi
    je      .origin_done                    ; target octets to the end
    cmp     byte [rdi + rax], '%'
    jne     .bad_target                     ; an octet a target may not hold
    lea     rcx, [rax + 2]
    cmp     rcx, rsi
    jae     .bad_target                     ; two HEXDIG must follow, inside the value
    movzx   ecx, byte [rdi + rax + 1]
    cmp     byte [r9 + rcx], 0xFF
    je      .bad_target
    movzx   ecx, byte [rdi + rax + 2]
    cmp     byte [r9 + rcx], 0xFF
    je      .bad_target
    lea     rdi, [rdi + rax + 3]            ; past the percent-encoding
    sub     rsi, rax
    sub     rsi, 3
    jnz     .path_run
    jmp     .origin_done                    ; it ended the value

.connect:
    ; CONNECT names only the authority to connect to (RFC 9113 8.5).
    test    r14d, RQ_SCHEME | RQ_PATH
    jnz     .bad_pseudo
    test    r14d, RQ_AUTHORITY
    jz      .missing
    mov     rax, [rbx + httpasm_request.authority]
    mov     [rbx + httpasm_request.target], rax
    mov     eax, [rbx + httpasm_request.authority_length]
    mov     [rbx + httpasm_request.target_length], eax
    mov     byte [rbx + httpasm_request.target_form], HTTPASM_TARGET_AUTHORITY

.authority_check:
    test    r14d, RQ_AUTHORITY
    jz      .host_authority
    ; :authority: not empty, no userinfo (RFC9113-8.3.1-2.3.2); Host, if any, names the same
    ; authority (RFC9113-8.3.1-2.3.5: the rule a smuggler would play two versions against).
    mov     rdi, [rbx + httpasm_request.authority]
    mov     ecx, [rbx + httpasm_request.authority_length]
    test    ecx, ecx
    jz      .bad_authority
    mov     al, '@'
    repne   scasb
    je      .bad_authority
    ; uri-host [ ":" port ] by HTTP/1.1's Host grammar, and for CONNECT the authority-form's
    ; port, 1 to 65535 (RFC 9113 8.5: CONNECT's :authority is the authority-form of RFC 9112
    ; 3.2.3; RFC9110-9.3.6-4). The macros are HTTP/1.1's own (semantics/authority.inc), so an
    ; authority one version refuses the other refuses too: tests/fuzz/h2_request found
    ; "CONNECT" with ":authority: example.c43", no port, passing here and refused there.
    mov     rsi, [rbx + httpasm_request.authority]
    mov     ecx, [rbx + httpasm_request.authority_length]
    mov     rdi, rsi                        ; the cursor
    lea     r10, [rsi + rcx]                ; the end
    lea     r8, [rel ha_char_class]
    lea     r9, [rel ha_hex_value]
    HA_URI_HOST rdi, r10, r8, r9, rax, eax, al, rdx, edx, .bad_authority
    cmp     word [rbx + httpasm_request.method_id], HTTPASM_METHOD_CONNECT
    jne     .authority_vs_host
    HA_AUTHORITY_PORT rsi, r10, rdi, eax, edx, r9d, .bad_authority
.authority_vs_host:
    mov     r12, [rsp + RQ_HOST]
    test    r12, r12
    jz      .done
    mov     ecx, [r12 + httpasm_field.value_length]
    cmp     ecx, [rbx + httpasm_request.authority_length]
    jne     .bad_authority
    mov     rsi, [r12 + httpasm_field.value]
    mov     rdi, [rbx + httpasm_request.authority]
.authority_octet:
    test    ecx, ecx
    jz      .done
    movzx   eax, byte [rsi]
    movzx   edx, byte [rdi]
    cmp     eax, edx
    je      .authority_same
    or      eax, 0x20                       ; a host is case-insensitive: fold letters only
    or      edx, 0x20
    cmp     eax, edx
    jne     .bad_authority
    sub     eax, 'a'
    cmp     eax, 'z' - 'a'
    ja      .bad_authority                  ; the octets differ by more than a letter's case
.authority_same:
    inc     rsi
    inc     rdi
    dec     ecx
    jmp     .authority_octet
.host_authority:
    ; No :authority: Host, if any, is the authority.
    mov     r12, [rsp + RQ_HOST]
    test    r12, r12
    jz      .done
    mov     rax, [r12 + httpasm_field.value]
    mov     [rbx + httpasm_request.authority], rax
    mov     eax, [r12 + httpasm_field.value_length]
    mov     [rbx + httpasm_request.authority_length], eax
.done:
    xor     eax, eax
    jmp     .out

.bad_name:
    mov     eax, HTTPASM_ERROR_FIELD_NAME
    jmp     .fail
.bad_value:
    mov     eax, HTTPASM_ERROR_FIELD_VALUE
    jmp     .fail
.bad_pseudo:
    mov     eax, HTTPASM_ERROR_H2_PSEUDO
    jmp     .fail
.missing:
    mov     eax, HTTPASM_ERROR_H2_MISSING
    jmp     .fail
.connection_field:
    mov     eax, HTTPASM_ERROR_H2_CONNECTION_FIELD
    jmp     .fail
.bad_authority:
    mov     eax, HTTPASM_ERROR_H2_AUTHORITY
    jmp     .fail
.host_duplicate:
    mov     eax, HTTPASM_ERROR_HOST_DUPLICATE
    jmp     .fail
.bad_host:
    mov     eax, HTTPASM_ERROR_HOST_INVALID
    jmp     .fail
.bad_length:
    mov     eax, HTTPASM_ERROR_CONTENT_LENGTH
    jmp     .fail
.bad_expect:
    mov     eax, HTTPASM_ERROR_EXPECT
    jmp     .fail
.bad_method:
    mov     eax, HTTPASM_ERROR_METHOD
    jmp     .fail
.bad_target:
    mov     eax, HTTPASM_ERROR_TARGET
.fail:
    mov     [rbx + httpasm_request.error], ax
    neg     eax
.out:
    add     rsp, RQ_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_h2_trailers(httpasm_field *fields, uint32_t count)
;   Checks a request's trailer section (a second HEADERS block, which ended the stream): no
;   pseudo-field (RFC9113-8.1-2.4), names lower-case tokens, values valid (RFC 9113 8.2.1).
;   Flags each record HTTPASM_FIELD_FLAG_TRAILER and sets its id from its name.
;   Returns 0, or -HTTPASM_ERROR_H2_PSEUDO, -FIELD_NAME, -FIELD_VALUE (malformed).
; -----------------------------------------------------------------------------
global httpasm_h2_trailers:function (httpasm_h2_trailers.end - httpasm_h2_trailers)
align 16
httpasm_h2_trailers:
    push    r12
    push    r13
    sub     rsp, 8                          ; two pushes + 8: aligned
    mov     r12, rdi
    mov     r13d, esi
.field:
    test    r13d, r13d
    jz      .ok
    mov     rdi, [r12 + httpasm_field.name]
    mov     esi, [r12 + httpasm_field.name_length]
    test    esi, esi
    jz      .bad_name
    cmp     byte [rdi], ':'
    je      .bad_pseudo
    call    h2_name
    jnz     .bad_name
    mov     rdi, [r12 + httpasm_field.name]
    mov     esi, [r12 + httpasm_field.name_length]
    call    ha_field_lookup
    mov     [r12 + httpasm_field.id], ax
    or      word [r12 + httpasm_field.flags], HTTPASM_FIELD_FLAG_TRAILER
    mov     rdi, [r12 + httpasm_field.value]
    mov     esi, [r12 + httpasm_field.value_length]
    call    h2_value
    jnz     .bad_value
    add     r12, httpasm_field_size
    dec     r13d
    jmp     .field
.ok:
    xor     eax, eax
    jmp     .out
.bad_name:
    mov     eax, -HTTPASM_ERROR_FIELD_NAME
    jmp     .out
.bad_value:
    mov     eax, -HTTPASM_ERROR_FIELD_VALUE
    jmp     .out
.bad_pseudo:
    mov     eax, -HTTPASM_ERROR_H2_PSEUDO
.out:
    add     rsp, 8
    pop     r13
    pop     r12
    ret
.end:
