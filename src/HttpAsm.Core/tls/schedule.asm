; =============================================================================
; tls/schedule.asm - TLS 1.3's key schedule (RFC 9846 7.1, 7.2, 7.5): HKDF-Extract with TLS's
; "0", HKDF-Expand-Label, Derive-Secret, the Finished MAC (4.5.3), the traffic secret's update
; (7.2) and the exporter (7.5), over the two hashes TLS 1.3's cipher suites use, SHA-256
; (TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256) and SHA-384 (TLS_AES_256_GCM_SHA384).
;
; The schedule itself is the caller's: the handshake (4c, 4d) chains these calls, so a test or a
; QUIC stack (RFC 9001's "quic key", "quic iv" and "quic hp" labels) composes them as it needs:
;
;            0 (Hash.length zeros: httpasm_tls13_extract with no IKM)
;            |
;   PSK -> Extract = Early Secret --> Derive-Secret(., "c e traffic", ClientHello), ...
;            |
;            Derive-Secret(., "derived", "")   (a NULL transcript hash: Hash(""))
;            |
;  (EC)DHE -> Extract = Handshake Secret --> Derive-Secret(., "c hs traffic", ...), ...
;            |
;            Derive-Secret(., "derived", "")
;            |
;       0 -> Extract = Master Secret --> Derive-Secret(., "c ap traffic", ...), ...
;
; Labels are given without RFC 9846's "tls13 " prefix, which HKDF-Expand-Label adds. Every
; function takes the hash as HTTPASM_HASH_SHA256 or HTTPASM_HASH_SHA384 and refuses any other.
;
; Constant time: everything secret goes through HMAC (crypto/hmac.asm), constant time in its
; octets; this file only lays out HkdfLabel (lengths and public labels) and copies. The buffers
; that held a key derived here (the Finished key, the exporter's own secret) are wiped before
; return. HkdfLabel itself holds no key: its context is a transcript hash or a ticket nonce.
; =============================================================================
default rel
%include "httpasm_core.inc"

extern httpasm_hkdf_sha256_extract
extern httpasm_hkdf_sha256_expand
extern httpasm_hkdf_sha384_extract
extern httpasm_hkdf_sha384_expand
extern httpasm_hmac_sha256
extern httpasm_hmac_sha384

section .rodata
align 16
ks_zeros:       times 48 db 0               ; TLS's "0": Hash.length zero octets (7.1)
ks_empty256:    db 0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24
                db 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55
ks_empty384:    db 0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3, 0x6A
                db 0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6, 0xE1, 0xDA
                db 0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48, 0x98, 0xB9, 0x5B
ks_finished:    db "finished"               ; (4.5.3)
ks_update:      db "traffic upd"            ; (7.2)
ks_exporter:    db "exporter"               ; (7.5)

section .text

; KS_LENGTH hash, out, bad: out (a 32-bit register) = the digest's octets of HTTPASM_HASH_* hash
; (a 32-bit register), or a jump to bad for any other value.
%macro KS_LENGTH 3
    mov     %2, 32
    cmp     %1, HTTPASM_HASH_SHA256
    je      %%known
    mov     %2, 48
    cmp     %1, HTTPASM_HASH_SHA384
    jne     %3
%%known:
%endmacro

; -----------------------------------------------------------------------------
; int httpasm_tls13_extract(int hash, const uint8_t *salt, size_t salt_length, const uint8_t *ikm,
;                           size_t ikm_length, uint8_t *secret)
;   HKDF-Extract(salt, IKM) into secret[0..Hash.length) (RFC 9846 7.1). An IKM of no octets is
;   TLS's "0", Hash.length zero octets (the master secret's input, and an early secret's
;   without a PSK); a salt of no octets is HKDF's own default, the same zeros. Returns 0, or -1
;   for an unknown hash (nothing written). Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_extract:function (httpasm_tls13_extract.end - httpasm_tls13_extract)
align 16
httpasm_tls13_extract:
    KS_LENGTH edi, eax, .bad
    test    r8, r8
    jnz     .ikm
    lea     rcx, [rel ks_zeros]             ; "0": Hash.length zeros
    mov     r8d, eax
.ikm:
    sub     rsp, 8                          ; (the call's alignment)
    mov     r10d, edi
    mov     rdi, rsi                        ; HKDF-Extract(salt, salt_length, ikm, ikm_length, prk)
    mov     rsi, rdx
    mov     rdx, rcx
    mov     rcx, r8
    mov     r8, r9
    cmp     r10d, HTTPASM_HASH_SHA384
    je      .sha384
    call    httpasm_hkdf_sha256_extract
    jmp     .done
.sha384:
    call    httpasm_hkdf_sha384_extract
.done:
    add     rsp, 8
    xor     eax, eax
    ret
.bad:
    mov     eax, -1
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_expand_label(int hash, const uint8_t *secret, const uint8_t *label,
;                                size_t label_length, const uint8_t *context,
;                                size_t context_length, uint8_t *out, size_t length)
;   HKDF-Expand-Label(Secret, Label, Context, Length) = HKDF-Expand(Secret, HkdfLabel, Length)
;   (RFC 9846 7.1), HkdfLabel = uint16 Length, opaque label<7..255> = "tls13 " + Label, opaque
;   context<0..255> = Context. secret holds Hash.length octets; out must not overlap it or the
;   context. Returns 0; or -1 (nothing written) for an unknown hash, a Label empty or past 249
;   octets (HkdfLabel's label is 7 to 255), a Context past 255, or a Length past HKDF's
;   255 * Hash.length. Clobbers the caller-saved registers.
;   Frame: HkdfLabel (2 + 1 + 255 + 1 + 255 = 514 octets at most) in EL_BUFFER's 528; six pushes
;   + EL_FRAME keep rsp 16-aligned at the call.
; -----------------------------------------------------------------------------
EL_BUFFER       equ 528
EL_FRAME        equ EL_BUFFER + 8
EL_ARGS         equ EL_FRAME + 6 * 8 + 8    ; the caller's stack arguments: out, then length

global httpasm_tls13_expand_label:function (httpasm_tls13_expand_label.end - httpasm_tls13_expand_label)
align 16
httpasm_tls13_expand_label:
    KS_LENGTH edi, eax, .bad
    lea     r10, [rcx - 1]
    cmp     r10, 248
    ja      .bad                            ; the label: 1 to 249 octets after "tls13 "
    cmp     r9, 255
    ja      .bad                            ; the context: 255 octets at most
    imul    r11d, eax, 255
    cmp     [rsp + 16], r11
    ja      .bad                            ; HKDF-Expand's limit (RFC 5869 2.3)
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, EL_FRAME
    mov     ebx, edi                        ; the hash
    mov     r12, rsi                        ; the secret
    mov     r13d, eax                       ; Hash.length
    ; HkdfLabel: the length (big-endian), the label's length, "tls13 ", the label, the
    ; context's length, the context
    mov     rax, [rsp + EL_ARGS + 8]
    mov     [rsp + 1], al
    shr     eax, 8
    mov     [rsp], al
    lea     eax, [rcx + 6]
    mov     [rsp + 2], al
    mov     dword [rsp + 3], 'tls1'
    mov     word [rsp + 7], '3 '
    lea     rdi, [rsp + 9]
    mov     rsi, rdx
    rep     movsb                           ; (rcx: the label's length)
    mov     [rdi], r9b
    inc     rdi
    mov     rsi, r8
    mov     rcx, r9
    rep     movsb
    mov     rcx, rdi
    sub     rcx, rsp                        ; HkdfLabel's octets
    mov     rdi, r12                        ; HKDF-Expand(prk, prk_length, info, info_length, okm, length)
    mov     esi, r13d
    mov     rdx, rsp
    mov     r8, [rsp + EL_ARGS]
    mov     r9, [rsp + EL_ARGS + 8]
    cmp     ebx, HTTPASM_HASH_SHA384
    je      .sha384
    call    httpasm_hkdf_sha256_expand      ; (0: its limit was checked above)
    jmp     .done
.sha384:
    call    httpasm_hkdf_sha384_expand
.done:
    add     rsp, EL_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    xor     eax, eax
    ret
.bad:
    mov     eax, -1
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_derive_secret(int hash, const uint8_t *secret, const uint8_t *label,
;                                 size_t label_length, const uint8_t *transcript_hash,
;                                 uint8_t *out)
;   Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label,
;   Transcript-Hash(Messages), Hash.length) into out[0..Hash.length) (RFC 9846 7.1). The caller
;   hashes the messages; a NULL transcript_hash is the hash of none, Hash("") (the "derived"
;   steps, and the exporter's). Returns 0, or -1 as httpasm_tls13_expand_label refuses.
;   Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_derive_secret:function (httpasm_tls13_derive_secret.end - httpasm_tls13_derive_secret)
align 16
httpasm_tls13_derive_secret:
    KS_LENGTH edi, eax, .bad
    test    r8, r8
    jnz     .hashed
    lea     r8, [rel ks_empty256]
    cmp     edi, HTTPASM_HASH_SHA384
    jne     .hashed
    lea     r8, [rel ks_empty384]
.hashed:
    sub     rsp, 24                         ; the two stack arguments, and the call's alignment
    mov     [rsp], r9                       ; out
    mov     [rsp + 8], rax                  ; length: Hash.length
    mov     r9, rax                         ; the context: the transcript hash, Hash.length octets
    call    httpasm_tls13_expand_label
    add     rsp, 24
    ret
.bad:
    mov     eax, -1
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_finished(int hash, const uint8_t *base_key, const uint8_t *transcript_hash,
;                            uint8_t *verify_data)
;   A Finished message's verify_data (RFC 9846 4.5.3): finished_key =
;   HKDF-Expand-Label(BaseKey, "finished", "", Hash.length), verify_data =
;   HMAC(finished_key, Transcript-Hash(the handshake context, Certificate*, CertificateVerify*)),
;   Hash.length octets. BaseKey is the sender's handshake traffic secret (or, after the
;   handshake, its application traffic secret: post-handshake authentication). The receiver
;   compares the octets it got with these in constant time (the engine's job). Returns 0, or -1
;   for an unknown hash. The Finished key is wiped. Clobbers the caller-saved registers.
;   Frame: the stack arguments at FN_ARGS, the Finished key (48 octets) at FN_KEY; four
;   pushes + FN_FRAME keep rsp 16-aligned.
; -----------------------------------------------------------------------------
FN_ARGS         equ 0
FN_KEY          equ 16
FN_FRAME        equ 72

global httpasm_tls13_finished:function (httpasm_tls13_finished.end - httpasm_tls13_finished)
align 16
httpasm_tls13_finished:
    KS_LENGTH edi, eax, .bad
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, FN_FRAME
    mov     ebx, edi
    mov     r12, rdx                        ; the transcript hash
    mov     r13, rcx                        ; verify_data
    mov     r14d, eax                       ; Hash.length
    lea     rax, [rsp + FN_KEY]
    mov     [rsp + FN_ARGS], rax
    mov     [rsp + FN_ARGS + 8], r14
    lea     rdx, [rel ks_finished]
    mov     ecx, 8
    xor     r8d, r8d
    xor     r9d, r9d                        ; no context
    call    httpasm_tls13_expand_label      ; (0: its arguments are this function's own)
    lea     rdi, [rsp + FN_KEY]             ; HMAC(key, key_length, data, n, mac)
    mov     rsi, r14
    mov     rdx, r12
    mov     rcx, r14
    mov     r8, r13
    cmp     ebx, HTTPASM_HASH_SHA384
    je      .sha384
    call    httpasm_hmac_sha256
    jmp     .wipe
.sha384:
    call    httpasm_hmac_sha384
.wipe:
    pxor    xmm0, xmm0                      ; the Finished key is a secret
    movdqu  [rsp + FN_KEY], xmm0
    movdqu  [rsp + FN_KEY + 16], xmm0
    movdqu  [rsp + FN_KEY + 32], xmm0
    add     rsp, FN_FRAME
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    xor     eax, eax
    ret
.bad:
    mov     eax, -1
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_update_secret(int hash, const uint8_t *secret, uint8_t *next)
;   The next generation of an application traffic secret (RFC 9846 7.2):
;   application_traffic_secret_N+1 = HKDF-Expand-Label(application_traffic_secret_N,
;   "traffic upd", "", Hash.length), into next (not overlapping secret). The caller wipes the
;   old secret once its keys are made (7.2's SHOULD). Returns 0, or -1 for an unknown hash.
;   Clobbers the caller-saved registers.
; -----------------------------------------------------------------------------
global httpasm_tls13_update_secret:function (httpasm_tls13_update_secret.end - httpasm_tls13_update_secret)
align 16
httpasm_tls13_update_secret:
    KS_LENGTH edi, eax, .bad
    sub     rsp, 24
    mov     [rsp], rdx                      ; out: next
    mov     [rsp + 8], rax                  ; Hash.length
    lea     rdx, [rel ks_update]
    mov     ecx, 11
    xor     r8d, r8d
    xor     r9d, r9d
    call    httpasm_tls13_expand_label
    add     rsp, 24
    ret
.bad:
    mov     eax, -1
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_tls13_export(int hash, const uint8_t *exporter_secret, const uint8_t *label,
;                          size_t label_length, const uint8_t *context, size_t context_length,
;                          uint8_t *out, size_t length)
;   TLS-Exporter(label, context_value, key_length) = HKDF-Expand-Label(Derive-Secret(Secret,
;   label, ""), "exporter", Hash(context_value), key_length) (RFC 9846 7.5), Secret the
;   exporter_master_secret (or the early one, for an early exporter: a separate call by its
;   caller, 7.5's RECOMMENDED separate interface). No context and an empty one are the same
;   value, as 7.5 defines them. Returns 0; or -1 as httpasm_tls13_expand_label refuses the label
;   or the length (nothing written). The derived secret is wiped. Clobbers the caller-saved
;   registers.
;   Frame: the stack arguments, the derived secret (48 octets) at EX_DERIVED, Hash(context) at
;   EX_CONTEXT; six pushes + EX_FRAME keep rsp 16-aligned.
; -----------------------------------------------------------------------------
EX_ARGS         equ 0
EX_DERIVED      equ 16
EX_CONTEXT      equ 64
EX_FRAME        equ 120
EX_CALLER       equ EX_FRAME + 6 * 8 + 8    ; the caller's stack arguments: out, length

global httpasm_tls13_export:function (httpasm_tls13_export.end - httpasm_tls13_export)
align 16
httpasm_tls13_export:
    KS_LENGTH edi, eax, .bad_early
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, EX_FRAME
    mov     ebx, edi                        ; the hash
    mov     r12d, eax                       ; Hash.length
    mov     r13, r8                         ; the context
    mov     r14, r9                         ; its length
    ; Derive-Secret(Secret, label, ""): refuses a label HkdfLabel cannot hold
    xor     r8d, r8d
    lea     r9, [rsp + EX_DERIVED]
    call    httpasm_tls13_derive_secret
    test    eax, eax
    jnz     .wipe
    mov     rdi, r13                        ; Hash(context_value)
    mov     rsi, r14
    lea     rdx, [rsp + EX_CONTEXT]
    cmp     ebx, HTTPASM_HASH_SHA384
    je      .sha384
    call    httpasm_sha256
    jmp     .hashed
.sha384:
    call    httpasm_sha384
.hashed:
    mov     rax, [rsp + EX_CALLER]
    mov     [rsp + EX_ARGS], rax            ; out
    mov     rax, [rsp + EX_CALLER + 8]
    mov     [rsp + EX_ARGS + 8], rax        ; key_length (refused past HKDF's limit)
    mov     edi, ebx
    lea     rsi, [rsp + EX_DERIVED]
    lea     rdx, [rel ks_exporter]
    mov     ecx, 8
    lea     r8, [rsp + EX_CONTEXT]
    mov     r9d, r12d
    call    httpasm_tls13_expand_label
.wipe:
    pxor    xmm0, xmm0                      ; the derived secret is the exporter's key
    movdqu  [rsp + EX_DERIVED], xmm0
    movdqu  [rsp + EX_DERIVED + 16], xmm0
    movdqu  [rsp + EX_DERIVED + 32], xmm0
    add     rsp, EX_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.bad_early:
    mov     eax, -1
    ret
.end:
