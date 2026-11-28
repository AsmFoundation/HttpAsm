; =============================================================================
; tls/messages.asm - TLS 1.3's handshake messages (RFC 9846 4): the handshake framing, and each
; message's body read strictly and in place: every vector's length within its bounds, nothing
; after the structure, the message's own value rules, and its extensions through the extension
; block's walk and syntax (tls/extensions.asm).
;
; What is the engine's and not here: a message's place in the handshake (which may come when),
; the reassembly of a message spread over records, and the semantics that need the other side's
; messages (a ServerHello's suite among the offered ones, an extension answered that was not
; asked for). What is here: everything a message says about itself.
;
; Nothing here is secret (a handshake's messages are public, the encrypted ones read after
; decryption). Answers are 0 or minus an alert.
; =============================================================================
default rel
%include "httpasm_core.inc"

extern httpasm_tls_extensions_read
extern ha_tls_check_extensions

section .rodata
align 16                                    ; (compared with pcmpeqb's aligned memory operand)
; SHA-256 of "HelloRetryRequest": the random that makes a ServerHello a HelloRetryRequest (4.2.3)
hm_retry_random:
    db 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91
    db 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C

section .text

; HM_U16 reg, address: reg (a 32-bit register) = the big-endian uint16 at address.
%macro HM_U16 2
    movzx   %1, word [%2]
    bswap   %1
    shr     %1, 16
%endmacro

; HM_U24 reg, address, scratch: reg = the big-endian uint24 at address (reg and scratch 32-bit
; registers), read within its own three octets. (A dword load from address - 1 with its top
; octet masked off is one instruction shorter, but it reads the octet before address: for
; httpasm_tls13_certificate_entry's first entry that is the octet before the caller's list,
; which may lie on another page, inaccessible.)
%macro HM_U24 3
    movzx   %1, byte [%2]
    shl     %1, 16
    HM_U16  %3, %2 + 1
    or      %1, %3
%endmacro

; HM_NEED n: at least n octets left between the cursor r12 and the end r13, else decode_error. n
; may be any register but r11, the macro's scratch (the first version used rax, so HM_NEED rax
; compared rax with itself: never refused, and the length was lost).
%macro HM_NEED 1
    mov     r11, r13
    sub     r11, r12
    cmp     r11, %1
    jb      .decode
%endmacro

; -----------------------------------------------------------------------------
; int64_t httpasm_tls_message(const uint8_t *in, size_t length, uint32_t *type,
;                             size_t *body_length)
;   The handshake message at the start of in[0..length) (RFC 9846 4: a HandshakeType octet, a
;   uint24 length, the body): when all of it is there, its whole length (4 + the body's), with
;   *type and *body_length set; 0 when more octets are needed (a message may span records: the
;   engine gathers them). Which types may come, and how long a message may be before the
;   engine stops gathering, are the engine's. A leaf: clobbers rax, r8, r9.
; -----------------------------------------------------------------------------
global httpasm_tls_message:function (httpasm_tls_message.end - httpasm_tls_message)
align 16
httpasm_tls_message:
    xor     eax, eax
    cmp     rsi, 4
    jb      .out                            ; not the header yet
    mov     r8d, [rdi]
    bswap   r8d
    and     r8d, 0x00FFFFFF                 ; the uint24 length
    lea     r9, [r8 + 4]
    cmp     rsi, r9
    jb      .out                            ; not the body yet
    movzx   eax, byte [rdi]
    mov     [rdx], eax
    mov     [rcx], r8
    mov     rax, r9
.out:
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_hello_read(httpasm_tls13_hello *hello, int type, const uint8_t *body,
;                              size_t length)
;   A ClientHello's (type 1) or a ServerHello's (type 2) body, body[0..length) (after the
;   handshake header), into hello (pointers into the body):
;     ClientHello (4.2.2): legacy_version, random, legacy_session_id<0..32>,
;       cipher_suites<2..2^16-2> (pairs), legacy_compression_methods<1..2^8-1>, and an extension
;       block or none (a ClientHello of TLS 1.2 or older may have none; "extensions<7..>" when
;       there is one); a ClientHello that offers TLS 1.3 (0x0304 in supported_versions) must
;       carry the one compression method 0 (illegal_parameter otherwise).
;     ServerHello (4.2.3): legacy_version, random, legacy_session_id_echo<0..32>, cipher_suite,
;       legacy_compression_method (0, else illegal_parameter), extensions; a random of
;       SHA-256("HelloRetryRequest") makes it a HelloRetryRequest (hello->retry = 1), whose
;       extensions are judged as HelloRetryRequest's (4.3's table).
;   The legacy_version is returned, not judged (the engine's version negotiation answers
;   protocol_version). The extensions go through httpasm_tls_extensions_read and then the
;   syntax of each one the engine reads. Returns 0; or -HTTPASM_TLS_ALERT_DECODE_ERROR for a
;   structure that does not parse or leaves octets after it, -ILLEGAL_PARAMETER for a rule
;   above or of the extensions; -1 for a type other than 1 or 2 (hello's fields are then
;   unspecified). Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_hello_read:function (httpasm_tls13_hello_read.end - httpasm_tls13_hello_read)
align 16
httpasm_tls13_hello_read:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 8                          ; (six pushes + 8: rsp 16-aligned at the calls)
    mov     rbx, rdi                        ; hello
    mov     ebp, esi                        ; the type
    mov     r12, rdx                        ; the cursor
    lea     r13, [rdx + rcx]                ; the end
    xor     eax, eax
    mov     ecx, httpasm_tls13_hello_size / 8
    rep     stosq
    mov     eax, -1
    cmp     ebp, HTTPASM_TLS_CLIENT_HELLO
    je      .typed
    cmp     ebp, HTTPASM_TLS_SERVER_HELLO
    jne     .done
.typed:
    ; legacy_version, random
    HM_NEED 2 + 32
    HM_U16  eax, r12
    mov     [rbx + httpasm_tls13_hello.legacy_version], ax
    lea     rax, [r12 + 2]
    mov     [rbx + httpasm_tls13_hello.random], rax
    add     r12, 2 + 32
    ; legacy_session_id<0..32> (the echo's too)
    HM_NEED 1
    movzx   ecx, byte [r12]
    cmp     ecx, 32
    ja      .decode
    inc     r12
    HM_NEED rcx
    mov     [rbx + httpasm_tls13_hello.session_id_length], cl
    mov     [rbx + httpasm_tls13_hello.session_id], r12
    add     r12, rcx
    cmp     ebp, HTTPASM_TLS_SERVER_HELLO
    je      .server
    ; ---- ClientHello: cipher_suites<2..2^16-2>, legacy_compression_methods<1..2^8-1>
    HM_NEED 2
    HM_U16  ecx, r12
    add     r12, 2
    cmp     ecx, 2
    jb      .decode
    test    ecx, 1
    jnz     .decode
    HM_NEED rcx
    mov     [rbx + httpasm_tls13_hello.cipher_suites], r12
    mov     [rbx + httpasm_tls13_hello.cipher_suites_length], ecx
    add     r12, rcx
    HM_NEED 1
    movzx   ecx, byte [r12]
    test    ecx, ecx
    jz      .decode
    inc     r12
    HM_NEED rcx
    mov     [rbx + httpasm_tls13_hello.compression], r12
    mov     [rbx + httpasm_tls13_hello.compression_length], cl
    add     r12, rcx
    cmp     r12, r13
    je      .good                           ; no extension block: a ClientHello of TLS 1.2 or older
    mov     r14d, HTTPASM_TLS_IN_CH
    mov     r15d, 7                         ; extensions<7..2^16-1> (4.2.2)
    call    .extensions
    test    eax, eax
    jnz     .done
    ; offering TLS 1.3: the one compression method 0 (4.2.2)
    call    .offers_13
    jnc     .good
    cmp     byte [rbx + httpasm_tls13_hello.compression_length], 1
    jne     .illegal
    mov     rax, [rbx + httpasm_tls13_hello.compression]
    cmp     byte [rax], 0
    jne     .illegal
    jmp     .good
.server:
    ; ---- ServerHello: cipher_suite, legacy_compression_method (0), extensions
    HM_NEED 3
    HM_U16  eax, r12
    mov     [rbx + httpasm_tls13_hello.cipher_suite], ax
    movzx   eax, byte [r12 + 2]
    mov     [rbx + httpasm_tls13_hello.compression_method], al
    add     r12, 3
    test    eax, eax
    jnz     .illegal                        ; (4.2.3's MUST: the value 0)
    ; a HelloRetryRequest: its random SHA-256("HelloRetryRequest")
    mov     r14d, HTTPASM_TLS_IN_SH
    mov     rsi, [rbx + httpasm_tls13_hello.random]
    lea     rdi, [rel hm_retry_random]
    movdqu  xmm0, [rsi]
    movdqu  xmm1, [rsi + 16]
    pcmpeqb xmm0, [rdi]
    pcmpeqb xmm1, [rdi + 16]
    pand    xmm0, xmm1
    pmovmskb eax, xmm0
    cmp     eax, 0xFFFF
    jne     .server_extensions
    mov     byte [rbx + httpasm_tls13_hello.retry], 1
    mov     r14d, HTTPASM_TLS_IN_HRR
.server_extensions:
    mov     r15d, 6                         ; extensions<6..2^16-1> (4.2.3): not optional
    call    .extensions
    test    eax, eax
    jnz     .done
.good:
    xor     eax, eax
.done:
    add     rsp, 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.decode:
    mov     eax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    jmp     .done
.illegal:
    mov     eax, -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER
    jmp     .done

; .extensions: the block at the cursor, uint16 length then the extensions, ending the body
; exactly, of r15d octets at least, walked (r14d = the message's bit) and its known extensions'
; syntax checked -> eax = 0 or minus an alert. (Called with one return address on the stack:
; rsp 8 below 16-aligned, so the calls below realign by 8.)
.extensions:
    sub     rsp, 8
    mov     rax, r13
    sub     rax, r12
    cmp     rax, 2
    jb      .extensions_decode
    HM_U16  ecx, r12
    add     r12, 2
    sub     rax, 2
    cmp     rcx, rax
    jne     .extensions_decode              ; the block, then nothing (its own length)
    cmp     rcx, r15
    jb      .extensions_decode              ; under the vector's least length
    mov     [rbx + httpasm_tls13_hello.extensions_block], r12
    mov     [rbx + httpasm_tls13_hello.extensions_length], rcx
    lea     rdi, [rbx + httpasm_tls13_hello.extensions]
    mov     esi, r14d
    mov     rdx, r12
    call    httpasm_tls_extensions_read
    test    eax, eax
    jnz     .extensions_done
    lea     rdi, [rbx + httpasm_tls13_hello.extensions]
    mov     esi, r14d
    call    ha_tls_check_extensions
.extensions_done:
    add     rsp, 8
    ret
.extensions_decode:
    mov     eax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    jmp     .extensions_done

; .offers_13: CF set when the ClientHello's supported_versions (checked) lists 0x0304.
.offers_13:
    bt      qword [rbx + httpasm_tls13_hello.extensions + httpasm_tls_extensions.present], HTTPASM_TLS_EXT_SUPPORTED_VERSIONS
    jnc     .offers_no
    mov     rsi, [rbx + httpasm_tls13_hello.extensions + httpasm_tls_extensions.data + HTTPASM_TLS_EXT_SUPPORTED_VERSIONS * 8]
    movzx   ecx, byte [rsi]                 ; the list's octets (its syntax checked: pairs)
    inc     rsi
.offers_each:
    test    ecx, ecx
    jz      .offers_no
    cmp     word [rsi], 0x0403              ; 0x0304, big-endian
    je      .offers_yes
    add     rsi, 2
    sub     ecx, 2
    jmp     .offers_each
.offers_yes:
    stc
    ret
.offers_no:
    clc
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_extensions_message_read(httpasm_tls_extensions *ext, int message,
;                                           const uint8_t *body, size_t length)
;   A message whose body is an extension block alone (EncryptedExtensions, 4.4.1: `message`
;   HTTPASM_TLS_IN_EE) or one embedded where the caller found it (a Certificate entry's: CT),
;   body[0..length) the block with its uint16 length: walked and checked as the hello's are.
;   Returns 0, or minus an alert (decode_error when the block's length is not the rest).
;   Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_extensions_message_read:function (httpasm_tls13_extensions_message_read.end - httpasm_tls13_extensions_message_read)
align 16
httpasm_tls13_extensions_message_read:
    push    rbx
    push    rbp
    sub     rsp, 8
    mov     rbx, rdi
    mov     ebp, esi
    mov     eax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    cmp     rcx, 2
    jb      .done
    HM_U16  r8d, rdx
    sub     rcx, 2
    cmp     r8, rcx
    jne     .done
    add     rdx, 2
    call    httpasm_tls_extensions_read     ; (rdi = ext, esi = the message, rdx = the block, rcx = its length)
    test    eax, eax
    jnz     .done
    mov     rdi, rbx
    mov     esi, ebp
    call    ha_tls_check_extensions
.done:
    add     rsp, 8
    pop     rbp
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_certificate_request_read(httpasm_tls_extensions *ext, const uint8_t **context,
;                                            size_t *context_length, const uint8_t *body,
;                                            size_t length)
;   A CertificateRequest (4.4.2): certificate_request_context<0..2^8-1> (*context, its length),
;   then the extension block (CR's), which must carry signature_algorithms (4.4.2: else
;   missing_extension). Returns 0 or minus an alert. Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_certificate_request_read:function (httpasm_tls13_certificate_request_read.end - httpasm_tls13_certificate_request_read)
align 16
httpasm_tls13_certificate_request_read:
    push    rbx
    sub     rsp, 16                         ; (one push + 16: rsp 16-aligned at the call)
    mov     rbx, rdi
    mov     eax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    test    r8, r8
    jz      .done
    movzx   r9d, byte [rcx]                 ; the context's length
    lea     r10, [r9 + 1]
    cmp     r10, r8
    ja      .done
    lea     r11, [rcx + 1]
    mov     [rsi], r11
    mov     [rdx], r9
    lea     rdx, [rcx + r10]                ; the extension block, with its length
    lea     rcx, [r8 - 1]
    sub     rcx, r9
    mov     esi, HTTPASM_TLS_IN_CR
    call    httpasm_tls13_extensions_message_read
    test    eax, eax
    jnz     .done
    bt      qword [rbx + httpasm_tls_extensions.present], HTTPASM_TLS_EXT_SIGNATURE_ALGORITHMS
    jc      .done                           ; (eax 0)
    mov     eax, -HTTPASM_TLS_ALERT_MISSING_EXTENSION
.done:
    add     rsp, 16
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; int64_t httpasm_tls13_certificate_read(const uint8_t *body, size_t length, const uint8_t **context,
;                                        size_t *context_length, const uint8_t **list,
;                                        size_t *list_length)
;   A Certificate message (4.5.1): certificate_request_context<0..2^8-1>, then certificate_list
;   <0..2^24-1> of CertificateEntry { cert_data<1..2^24-1>, extensions<0..2^16-1> }, each entry's
;   extension block walked and checked as a Certificate's (CT). Returns the number of entries
;   (0 is a client's empty answer to a CertificateRequest) with the context and the list set;
;   or minus an alert. The entries are then read in turn with httpasm_tls13_certificate_entry.
;   Clobbers the caller-saved registers.
;   Frame: an httpasm_tls_extensions for each entry's check (CF_EXT), the counter.
; -----------------------------------------------------------------------------
CF_EXT          equ 0
CF_FRAME        equ httpasm_tls_extensions_size + 8     ; (six pushes + the frame: 16-aligned)

global httpasm_tls13_certificate_read:function (httpasm_tls13_certificate_read.end - httpasm_tls13_certificate_read)
align 16
httpasm_tls13_certificate_read:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, CF_FRAME
    mov     r12, rdi                        ; the cursor
    lea     r13, [rdi + rsi]                ; the end
    mov     r14, r8                         ; list
    mov     r15, r9                         ; list_length
    HM_NEED 1
    movzx   eax, byte [r12]
    inc     r12
    HM_NEED rax
    mov     [rdx], r12
    mov     [rcx], rax
    add     r12, rax
    HM_NEED 3
    HM_U24  eax, r12, r10d                  ; the list's uint24 length
    add     r12, 3
    mov     rcx, r13
    sub     rcx, r12
    cmp     rax, rcx
    jne     .decode                         ; the list, then nothing
    mov     [r14], r12
    mov     [r15], rax
    xor     ebx, ebx                        ; entries
.entry:
    cmp     r12, r13
    je      .counted
    HM_NEED 3
    HM_U24  eax, r12, r10d                  ; cert_data<1..2^24-1>
    test    eax, eax
    jz      .decode
    add     r12, 3
    HM_NEED rax
    add     r12, rax
    HM_NEED 2
    HM_U16  ecx, r12
    lea     rdx, [rcx + 2]
    HM_NEED rdx
    lea     rdi, [rsp + CF_EXT]
    mov     esi, HTTPASM_TLS_IN_CT
    mov     rcx, rdx                        ; the block with its length
    mov     rdx, r12
    lea     r12, [r12 + rcx]
    call    httpasm_tls13_extensions_message_read
    test    eax, eax
    jnz     .failed
    inc     ebx
    jmp     .entry
.counted:
    mov     eax, ebx
.done:
    add     rsp, CF_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.failed:
    movsxd  rax, eax
    jmp     .done
.decode:
    mov     rax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    jmp     .done
.end:

; -----------------------------------------------------------------------------
; int64_t httpasm_tls13_certificate_entry(const uint8_t *list, size_t list_length, size_t offset,
;                                         const uint8_t **cert, size_t *cert_length,
;                                         httpasm_tls_extensions *ext)
;   The CertificateEntry at list[offset..) of a list httpasm_tls13_certificate_read accepted:
;   its cert_data (*cert, its length) and its extensions (ext, walked again). Returns the next
;   entry's offset (list_length after the last). The entry is judged again on its own, so an
;   offset that is not an entry's, or a list the reader never saw, is answered rather than
;   trusted: -HTTPASM_TLS_ALERT_DECODE_ERROR for an offset at or past the end, an entry running
;   past the list or a cert_data of no octets, minus the walk's or the syntax's alert for its
;   extensions (*cert and *cert_length may then be set). Reads nothing outside the list.
;   Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_certificate_entry:function (httpasm_tls13_certificate_entry.end - httpasm_tls13_certificate_entry)
align 16
httpasm_tls13_certificate_entry:
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, 8                          ; (four pushes + 8: rsp 16-aligned at the call)
    mov     rbx, r9                         ; ext
    mov     r14, rdi                        ; the list
    lea     r12, [rdi + rdx]                ; the entry
    lea     r13, [rdi + rsi]                ; the list's end
    mov     rax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    cmp     rdx, rsi
    jae     .done                           ; no entry there
    HM_NEED 3
    HM_U24  eax, r12, r10d                  ; cert_data's length (r10: rcx and r8 are the outputs)
    test    eax, eax
    jz      .decode                         ; cert_data<1..2^24-1>, as the list's reader requires
    add     r12, 3
    HM_NEED rax
    mov     [rcx], r12
    mov     [r8], rax
    add     r12, rax
    HM_NEED 2
    HM_U16  ecx, r12
    lea     rcx, [rcx + 2]
    HM_NEED rcx
    mov     rdx, r12
    lea     r12, [r12 + rcx]
    mov     rdi, rbx
    mov     esi, HTTPASM_TLS_IN_CT
    call    httpasm_tls13_extensions_message_read
    movsxd  rax, eax
    test    eax, eax
    jnz     .done
    mov     rax, r12
    sub     rax, r14                        ; the next entry's offset
.done:
    add     rsp, 8
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.decode:
    mov     rax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    jmp     .done
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_certificate_verify_read(const uint8_t *body, size_t length, uint32_t *scheme,
;                                           const uint8_t **signature, size_t *signature_length)
;   A CertificateVerify (4.5.2): SignatureScheme algorithm, signature<0..2^16-1>, nothing after.
;   Returns 0 or -HTTPASM_TLS_ALERT_DECODE_ERROR. A leaf: clobbers rax, rcx, r9-r11.
; -----------------------------------------------------------------------------
global httpasm_tls13_certificate_verify_read:function (httpasm_tls13_certificate_verify_read.end - httpasm_tls13_certificate_verify_read)
align 16
httpasm_tls13_certificate_verify_read:
    mov     eax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    cmp     rsi, 4
    jb      .out
    HM_U16  r9d, rdi
    HM_U16  r10d, rdi + 2
    lea     r11, [r10 + 4]
    cmp     r11, rsi
    jne     .out                            ; the signature, then nothing
    mov     [rdx], r9d
    lea     r11, [rdi + 4]
    mov     [rcx], r11
    mov     [r8], r10
    xor     eax, eax
.out:
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_new_session_ticket_read(httpasm_tls_extensions *ext, const uint8_t *body,
;                                           size_t length, uint64_t *lifetime_age_add,
;                                           const uint8_t **nonce, const uint8_t **ticket)
;   A NewSessionTicket (4.7.1): uint32 ticket_lifetime and uint32 ticket_age_add (both into
;   *lifetime_age_add: the lifetime in the low half, the age_add in the high), ticket_nonce
;   <0..255> (*nonce points at its length octet), ticket<1..2^16-1> (*ticket at its uint16
;   length), extensions<0..2^16-2> (NST's: early_data's max_early_data_size among them). The
;   lifetime's limit (604800 s) is the engine's to apply. Returns 0 or minus an alert. Clobbers
;   the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_new_session_ticket_read:function (httpasm_tls13_new_session_ticket_read.end - httpasm_tls13_new_session_ticket_read)
align 16
httpasm_tls13_new_session_ticket_read:
    push    rbx
    push    r12
    push    r13
    mov     rbx, rdi                        ; ext
    mov     r12, rsi                        ; the cursor
    lea     r13, [rsi + rdx]                ; the end
    HM_NEED 8
    mov     eax, [r12]
    bswap   eax
    mov     r10d, [r12 + 4]
    bswap   r10d
    shl     r10, 32
    or      rax, r10
    mov     [rcx], rax
    add     r12, 8
    HM_NEED 1
    mov     [r8], r12
    movzx   eax, byte [r12]
    lea     rax, [rax + 1]
    HM_NEED rax
    add     r12, rax
    HM_NEED 2
    mov     [r9], r12
    HM_U16  eax, r12
    test    eax, eax
    jz      .decode                         ; ticket<1..2^16-1>
    lea     rax, [rax + 2]
    HM_NEED rax
    add     r12, rax
    mov     rdi, rbx
    mov     esi, HTTPASM_TLS_IN_NST
    mov     rdx, r12
    mov     rcx, r13
    sub     rcx, r12
    cmp     rcx, 2 + 65534
    ja      .decode                         ; extensions<0..2^16-2> (4.7.1)
    call    httpasm_tls13_extensions_message_read   ; (the block, its length, ending the body)
.done:
    pop     r13
    pop     r12
    pop     rbx
    ret
.decode:
    mov     eax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    jmp     .done
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_key_update_read(const uint8_t *body, size_t length)
;   A KeyUpdate (4.7.3): one KeyUpdateRequest octet, update_not_requested (0) or
;   update_requested (1). Returns it; or -HTTPASM_TLS_ALERT_DECODE_ERROR for another length,
;   -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER for another value (4.7.3's MUST). A leaf: clobbers rax.
; -----------------------------------------------------------------------------
global httpasm_tls13_key_update_read:function (httpasm_tls13_key_update_read.end - httpasm_tls13_key_update_read)
align 16
httpasm_tls13_key_update_read:
    mov     eax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    cmp     rsi, 1
    jne     .out
    movzx   eax, byte [rdi]
    cmp     eax, 1
    jbe     .out
    mov     eax, -HTTPASM_TLS_ALERT_ILLEGAL_PARAMETER
.out:
    ret
.end:
