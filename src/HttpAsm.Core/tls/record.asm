; =============================================================================
; tls/record.asm - TLS 1.3's record layer (RFC 9846 5): framing a record out of the octets a
; connection read, and protecting records under one traffic secret: TLSCiphertext's AEAD with
; the per-record nonce (5.3), the content type and padding of TLSInnerPlaintext (5.4), the
; record and plaintext limits (5.1, 5.2, RFC 8449's record_size_limit through the key's
; limit), and the AEAD's own limit on records under one key (5.5).
;
; A key (httpasm_tls13_record_key) is one direction's: the writer's to seal, the reader's to
; open, each with its own sequence number, made from a traffic secret by
; httpasm_tls13_record_key_init (7.3: key = HKDF-Expand-Label(secret, "key", "", key_length),
; iv = HKDF-Expand-Label(secret, "iv", "", 12)). The cipher suites are RFC 9846 9.1's three:
; TLS_AES_128_GCM_SHA256 (its MUST), TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256 (its
; SHOULDs). Records are built and opened in place: no copy beyond the content's own move.
;
; Constant time: the AEADs are (crypto/gcm.asm, crypto/chacha20_poly1305.asm), the nonce is
; the IV's xor with the public sequence number, and the opener finds the content type, the last
; non-zero octet of the plaintext, by one pass over the whole of it with no branch on an octet
; (5.4: padding hides the content's length; a scan whose time told the padding's length would
; undo that). Only lengths, which the record header gives away anyway, steer the code.
; =============================================================================
default rel
%include "httpasm_core.inc"

extern httpasm_tls13_expand_label
extern httpasm_aes_gcm_init
extern httpasm_aes_gcm_seal
extern httpasm_aes_gcm_open
extern httpasm_chacha20_poly1305_seal
extern httpasm_chacha20_poly1305_open

section .rodata
rk_key:         db "key"                    ; (7.3)
rk_iv:          db "iv"

section .text

; -----------------------------------------------------------------------------
; int64_t httpasm_tls_record_length(const uint8_t *in, size_t length)
;   The record at the start of in[0..length) (RFC 9846 5.1): its whole length (the 5-octet header
;   and the fragment the header announces) when all of it is there; 0 when more octets are
;   needed; or -HTTPASM_TLS_ALERT_RECORD_OVERFLOW when the header announces a fragment longer than
;   any TLS 1.3 record may carry: 2^14 + 256 octets for application_data, the type every
;   protected record has (5.2), and 2^14 for the others (5.1). Neither the type's value nor the
;   legacy version is judged here (5.1: the version "MUST be ignored for all purposes"; the
;   engine knows which types it may receive). A leaf: clobbers rax, rcx, rdx.
; -----------------------------------------------------------------------------
global httpasm_tls_record_length:function (httpasm_tls_record_length.end - httpasm_tls_record_length)
align 16
httpasm_tls_record_length:
    xor     eax, eax
    cmp     rsi, HTTPASM_TLS_RECORD_HEADER
    jb      .out                            ; the header is not all here
    movzx   ecx, word [rdi + 3]
    xchg    cl, ch                          ; the fragment's length, big-endian
    mov     edx, HTTPASM_TLS_PLAINTEXT_MAX
    cmp     byte [rdi], HTTPASM_TLS_CONTENT_APPLICATION_DATA
    jne     .limit
    mov     edx, HTTPASM_TLS_CIPHERTEXT_MAX
.limit:
    cmp     ecx, edx
    ja      .overflow
    add     ecx, HTTPASM_TLS_RECORD_HEADER
    cmp     rsi, rcx
    jb      .out                            ; the fragment is not all here: 0
    mov     eax, ecx
.out:
    ret
.overflow:
    mov     rax, -HTTPASM_TLS_ALERT_RECORD_OVERFLOW
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_record_key_init(httpasm_tls13_record_key *key, int suite,
;                                   const uint8_t *traffic_secret)
;   A record key from a traffic secret (Hash.length octets of the suite's hash) under cipher
;   suite `suite` (HTTPASM_TLS_*): the write key and IV of RFC 9846 7.3, the AEAD made ready,
;   the sequence number 0 (5.3), the limit 2^14 + 1 octets of TLSInnerPlaintext (lowered for a
;   peer's record_size_limit by setting key->limit). Returns 0, or -1 for an unknown suite (the
;   key then all zeros). The key's octets are the secret: wipe it when done. The intermediate
;   write key is wiped. Clobbers the caller-saved registers.
;   Frame: the stack arguments at RI_ARGS, the write key (32 octets) at RI_KEY; four pushes +
;   RI_FRAME keep rsp 16-aligned.
; -----------------------------------------------------------------------------
RI_ARGS         equ 0
RI_KEY          equ 16
RI_FRAME        equ 56

global httpasm_tls13_record_key_init:function (httpasm_tls13_record_key_init.end - httpasm_tls13_record_key_init)
align 16
httpasm_tls13_record_key_init:
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, RI_FRAME
    mov     rbx, rdi                        ; the key
    mov     r12d, esi                       ; the suite
    mov     r13, rdx                        ; the traffic secret
    xor     eax, eax                        ; all zeros first: a refused key is left so
    mov     ecx, httpasm_tls13_record_key_size / 8
    rep     stosq
    ; the suite: its hash, its key's length
    mov     edi, HTTPASM_HASH_SHA256
    mov     r14d, 16
    cmp     r12d, HTTPASM_TLS_AES_128_GCM_SHA256
    je      .suite
    mov     r14d, 32
    cmp     r12d, HTTPASM_TLS_CHACHA20_POLY1305_SHA256
    je      .suite
    mov     edi, HTTPASM_HASH_SHA384
    cmp     r12d, HTTPASM_TLS_AES_256_GCM_SHA384
    jne     .bad
.suite:
    mov     [rbx + httpasm_tls13_record_key.suite], r12d
    mov     dword [rbx + httpasm_tls13_record_key.limit], HTTPASM_TLS_INNER_MAX
    mov     r12d, edi                       ; (the hash, from here on)
    ; key = HKDF-Expand-Label(secret, "key", "", key_length)
    lea     rax, [rsp + RI_KEY]
    mov     [rsp + RI_ARGS], rax
    mov     [rsp + RI_ARGS + 8], r14
    mov     rsi, r13
    lea     rdx, [rel rk_key]
    mov     ecx, 3
    xor     r8d, r8d
    xor     r9d, r9d
    call    httpasm_tls13_expand_label
    ; iv = HKDF-Expand-Label(secret, "iv", "", 12)
    lea     rax, [rbx + httpasm_tls13_record_key.iv]
    mov     [rsp + RI_ARGS], rax
    mov     qword [rsp + RI_ARGS + 8], 12
    mov     edi, r12d
    mov     rsi, r13
    lea     rdx, [rel rk_iv]
    mov     ecx, 2
    xor     r8d, r8d
    xor     r9d, r9d
    call    httpasm_tls13_expand_label
    ; the AEAD: AES-GCM's key schedule, or ChaCha20-Poly1305's raw key
    lea     rdi, [rbx + httpasm_tls13_record_key.aead]
    cmp     dword [rbx + httpasm_tls13_record_key.suite], HTTPASM_TLS_CHACHA20_POLY1305_SHA256
    je      .chacha
    lea     rsi, [rsp + RI_KEY]
    mov     rdx, r14
    call    httpasm_aes_gcm_init            ; (0: 16 or 32 octets)
    jmp     .wipe
.chacha:
    movdqu  xmm0, [rsp + RI_KEY]
    movdqu  xmm1, [rsp + RI_KEY + 16]
    movdqu  [rdi], xmm0
    movdqu  [rdi + 16], xmm1
    pxor    xmm0, xmm0
    pxor    xmm1, xmm1
.wipe:
    pxor    xmm2, xmm2                      ; the write key is the secret
    movdqu  [rsp + RI_KEY], xmm2
    movdqu  [rsp + RI_KEY + 16], xmm2
    xor     eax, eax
.done:
    add     rsp, RI_FRAME
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.bad:
    mov     eax, -1
    jmp     .done
.end:

; RK_NONCE key, frame: the per-record nonce (RFC 9846 5.3) at [rsp + frame]: the IV xored with
; the sequence number, big-endian in its last 8 octets. Clobbers rax, rcx.
%macro RK_NONCE 2
    mov     eax, [%1 + httpasm_tls13_record_key.iv]
    mov     [rsp + %2], eax
    mov     rax, [%1 + httpasm_tls13_record_key.sequence]
    bswap   rax
    xor     rax, [%1 + httpasm_tls13_record_key.iv + 4]
    mov     [rsp + %2 + 4], rax
%endmacro

; -----------------------------------------------------------------------------
; int64_t httpasm_tls13_seal(httpasm_tls13_record_key *key, int content_type,
;                            const uint8_t *content, size_t length, size_t padding,
;                            uint8_t *out, size_t capacity)
;   One TLSCiphertext record (RFC 9846 5.2) into out[0..capacity): the header (application_data,
;   0x0303, the fragment's length) and the AEAD of TLSInnerPlaintext = content, content_type,
;   `padding` zero octets (5.4), its tag after it, the nonce from the key's sequence number,
;   which then advances. content may be out + 5 (the record built in place) or must not overlap
;   out. Returns the record's length (5 + length + 1 + padding + 16); -1 (nothing written) when
;   content_type is 0, the content is longer than 2^14 octets (5.1), TLSInnerPlaintext longer
;   than key->limit (2^14 + 1, or the peer's record_size_limit), or the record longer than
;   capacity; -2 when the key has sealed all the records its AEAD may under one key (AES-GCM's
;   2^24.5 of 5.5; ChaCha20-Poly1305's: the sequence number's last before it wraps, 5.3): a
;   KeyUpdate first. Clobbers the caller-saved registers.
;   Frame: the AEAD call's stack arguments at SL_ARGS, the nonce at SL_NONCE; six pushes +
;   SL_FRAME keep rsp 16-aligned.
; -----------------------------------------------------------------------------
SL_ARGS         equ 0
SL_NONCE        equ 24
SL_FRAME        equ 40
SL_CALLER       equ SL_FRAME + 6 * 8 + 8    ; the caller's stack argument: capacity

global httpasm_tls13_seal:function (httpasm_tls13_seal.end - httpasm_tls13_seal)
align 16
httpasm_tls13_seal:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, SL_FRAME
    mov     rbx, rdi                        ; the key
    mov     ebp, esi                        ; the content type
    mov     r12, rdx                        ; the content
    mov     r13, rcx                        ; its length
    mov     r15, r9                         ; out
    test    ebp, ebp
    jz      .bad                            ; 0: the opener would take it for padding
    cmp     ebp, 255
    ja      .bad
    cmp     r13, HTTPASM_TLS_PLAINTEXT_MAX
    ja      .bad
    cmp     r8, HTTPASM_TLS_CIPHERTEXT_MAX
    ja      .bad                            ; (keeps the sum below from wrapping)
    lea     r14, [r13 + r8 + 1]             ; TLSInnerPlaintext's octets
    mov     eax, [rbx + httpasm_tls13_record_key.limit]
    cmp     r14, rax
    ja      .bad
    lea     rax, [r14 + HTTPASM_TLS_RECORD_HEADER + HTTPASM_TLS_TAG]
    cmp     rax, [rsp + SL_CALLER]
    ja      .bad                            ; the record does not fit
    ; the key's last record: AES-GCM's 2^24.5 (5.5), or the sequence number before it wraps
    mov     rax, [rbx + httpasm_tls13_record_key.sequence]
    mov     ecx, HTTPASM_TLS_GCM_RECORDS
    cmp     dword [rbx + httpasm_tls13_record_key.suite], HTTPASM_TLS_CHACHA20_POLY1305_SHA256
    jne     .limit
    mov     rcx, -1
.limit:
    cmp     rax, rcx
    jae     .exhausted
    ; the header: application_data, 0x0303, the fragment's length (5.2)
    mov     byte [r15], HTTPASM_TLS_CONTENT_APPLICATION_DATA
    mov     word [r15 + 1], 0x0303
    lea     eax, [r14d + HTTPASM_TLS_TAG]
    xchg    al, ah
    mov     [r15 + 3], ax
    ; TLSInnerPlaintext: the content (moved unless it is already in place), its type, zeros
    lea     rdi, [r15 + HTTPASM_TLS_RECORD_HEADER]
    cmp     rdi, r12
    je      .placed
    mov     rsi, r12
    mov     rcx, r13
    rep     movsb
    jmp     .typed
.placed:
    add     rdi, r13
.typed:
    mov     [rdi], bpl
    inc     rdi
    mov     rcx, r8
    xor     eax, eax
    rep     stosb                           ; the padding: zeros (5.4's MUST)
    RK_NONCE rbx, SL_NONCE
    ; seal(key, nonce, aad = the header, in = out = TLSInnerPlaintext, tag after it)
    lea     rax, [r15 + HTTPASM_TLS_RECORD_HEADER]
    lea     rdx, [rax + r14]
    mov     [rsp + SL_ARGS], rax            ; out
    mov     [rsp + SL_ARGS + 8], rdx        ; tag
    lea     rdi, [rbx + httpasm_tls13_record_key.aead]
    lea     rsi, [rsp + SL_NONCE]
    mov     rdx, r15
    mov     ecx, HTTPASM_TLS_RECORD_HEADER
    mov     r8, rax
    mov     r9, r14
    cmp     dword [rbx + httpasm_tls13_record_key.suite], HTTPASM_TLS_CHACHA20_POLY1305_SHA256
    je      .chacha
    call    httpasm_aes_gcm_seal            ; (0: the lengths are far below its limits)
    jmp     .sealed
.chacha:
    call    httpasm_chacha20_poly1305_seal
.sealed:
    inc     qword [rbx + httpasm_tls13_record_key.sequence]
    lea     rax, [r14 + HTTPASM_TLS_RECORD_HEADER + HTTPASM_TLS_TAG]
.done:
    add     rsp, SL_FRAME
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
.exhausted:
    mov     rax, -2
    jmp     .done
.end:

; -----------------------------------------------------------------------------
; int64_t httpasm_tls13_open(httpasm_tls13_record_key *key, uint8_t *record, size_t length,
;                            uint8_t *content_type)
;   Opens one TLSCiphertext record, record[0..length) as httpasm_tls_record_length framed it
;   (RFC 9846 5.2), in place: on success the content is record[5 ..) and *content_type its
;   type, and the key's sequence number advances. Returns the content's length; or minus the
;   alert the connection must end with: -HTTPASM_TLS_ALERT_UNEXPECTED_MESSAGE for an outer type
;   other than application_data or a plaintext of zeros only (no content type: 5.4);
;   -HTTPASM_TLS_ALERT_DECODE_ERROR when the header's length is not length - 5;
;   -HTTPASM_TLS_ALERT_RECORD_OVERFLOW for a fragment over 2^14 + 256 octets (5.2) or a
;   TLSInnerPlaintext over key->limit (2^14 + 1, or this side's record_size_limit);
;   -HTTPASM_TLS_ALERT_BAD_RECORD_MAC when the tag does not verify (the fragment then zeros: no
;   unauthenticated plaintext is left) or the fragment is shorter than one; and
;   -HTTPASM_TLS_ALERT_INTERNAL_ERROR when the sequence number would wrap (5.3: the connection
;   rekeys or ends before). The legacy version is ignored (5.1). The AEAD's limits are not
;   enforced on what is received (5.5's SHOULD NOT). Clobbers the caller-saved registers.
;   Frame: the AEAD call's stack arguments at OP_ARGS, the nonce at OP_NONCE; six pushes +
;   OP_FRAME keep rsp 16-aligned.
; -----------------------------------------------------------------------------
OP_ARGS         equ 0
OP_NONCE        equ 24
OP_FRAME        equ 40

global httpasm_tls13_open:function (httpasm_tls13_open.end - httpasm_tls13_open)
align 16
httpasm_tls13_open:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, OP_FRAME
    mov     rbx, rdi                        ; the key
    mov     r12, rsi                        ; the record
    mov     r15, rcx                        ; content_type
    mov     rax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    cmp     rdx, HTTPASM_TLS_RECORD_HEADER
    jb      .done                           ; not even a header
    movzx   eax, word [r12 + 3]
    rol     ax, 8                           ; the fragment's length, big-endian
    mov     r13d, eax
    lea     rcx, [r13 + HTTPASM_TLS_RECORD_HEADER]
    mov     rax, -HTTPASM_TLS_ALERT_DECODE_ERROR
    cmp     rcx, rdx
    jne     .done                           ; framed otherwise than its header says
    mov     rax, -HTTPASM_TLS_ALERT_UNEXPECTED_MESSAGE
    cmp     byte [r12], HTTPASM_TLS_CONTENT_APPLICATION_DATA
    jne     .done                           ; every protected record says application_data (5.2)
    mov     rax, -HTTPASM_TLS_ALERT_RECORD_OVERFLOW
    cmp     r13d, HTTPASM_TLS_CIPHERTEXT_MAX
    ja      .done                           ; (5.2)
    mov     rax, -HTTPASM_TLS_ALERT_BAD_RECORD_MAC
    cmp     r13d, HTTPASM_TLS_TAG
    jb      .done                           ; no room for the tag: it cannot verify
    lea     r14, [r13 - HTTPASM_TLS_TAG]    ; TLSInnerPlaintext's octets
    mov     rax, -HTTPASM_TLS_ALERT_RECORD_OVERFLOW
    mov     ecx, [rbx + httpasm_tls13_record_key.limit]
    cmp     r14, rcx
    ja      .done                           ; over this side's limit (5.4, RFC 8449 4)
    mov     rax, -HTTPASM_TLS_ALERT_INTERNAL_ERROR
    cmp     qword [rbx + httpasm_tls13_record_key.sequence], -1
    je      .done                           ; the sequence number would wrap (5.3)
    RK_NONCE rbx, OP_NONCE
    ; open(key, nonce, aad = the header, in = the fragment, length, tag, out = in)
    lea     r8, [r12 + HTTPASM_TLS_RECORD_HEADER]
    lea     rax, [r8 + r14]
    mov     [rsp + OP_ARGS], rax            ; tag
    mov     [rsp + OP_ARGS + 8], r8         ; out
    lea     rdi, [rbx + httpasm_tls13_record_key.aead]
    lea     rsi, [rsp + OP_NONCE]
    mov     rdx, r12
    mov     ecx, HTTPASM_TLS_RECORD_HEADER
    mov     r9, r14
    cmp     dword [rbx + httpasm_tls13_record_key.suite], HTTPASM_TLS_CHACHA20_POLY1305_SHA256
    je      .chacha
    call    httpasm_aes_gcm_open
    jmp     .opened
.chacha:
    call    httpasm_chacha20_poly1305_open
.opened:
    mov     ecx, eax
    mov     rax, -HTTPASM_TLS_ALERT_BAD_RECORD_MAC
    test    ecx, ecx
    jnz     .done
    inc     qword [rbx + httpasm_tls13_record_key.sequence]
    ; The content type: the last non-zero octet of TLSInnerPlaintext (5.4), found in one pass
    ; over all of it, the index taken with cmov whatever the octets (constant time).
    lea     rsi, [r12 + HTTPASM_TLS_RECORD_HEADER]
    mov     rdx, -1                         ; the last non-zero octet's index (-1: none yet)
    xor     ecx, ecx
    test    r14, r14
    jz      .scanned
.scan:
    movzx   eax, byte [rsi + rcx]
    test    eax, eax
    cmovnz  rdx, rcx
    inc     rcx
    cmp     rcx, r14
    jb      .scan
.scanned:
    ; Where the content ends is what the record delivers (its length is returned, and the type
    ; read from there): public by design from here, as the scan to find it was constant time.
    HA_DECLASSIFY rdx
    mov     rax, -HTTPASM_TLS_ALERT_UNEXPECTED_MESSAGE
    test    rdx, rdx
    js      .done                           ; zeros only: no content type (5.4)
    movzx   ecx, byte [rsi + rdx]
    ; the content type, likewise: what the receiver dispatches the content to (handshake, alert,
    ; application data), which its answer shows whatever the timing
    HA_DECLASSIFY rcx                       ; (public by design: the record's kind)
    mov     [r15], cl
    mov     rax, rdx                        ; the content's octets: those before its type
.done:
    add     rsp, OP_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:
