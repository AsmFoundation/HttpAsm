; =============================================================================
; crypto/hmac.asm - HMAC (FIPS 198-1, RFC 2104) and HKDF (RFC 5869) over SHA-256: the MAC and
; the key derivation TLS 1.3's key schedule is made of (RFC 9846 7.1: HKDF-Extract, and
; HKDF-Expand under HKDF-Expand-Label).
;
; HMAC(K, m) = H((K0 ^ opad) || H((K0 ^ ipad) || m)), K0 the key padded with zeros to the block,
; or its digest padded when it is longer than a block (FIPS 198-1 section 4 steps 1-3). The
; context holds both hashes already past their key block, so the key is not kept, and a copy of
; a fresh context MACs another message with the same key without the two key compressions.
; Everything here runs on the C ABI's SHA-256 (crypto/sha256.asm), whose compression picks its
; version (scalar, SHA extensions) per call; this file adds no version of its own.
;
; Constant time: no branch or address depends on a key's or a message's octets, only on their
; lengths. Every buffer that held a key's octets (K0, the pad blocks, the inner digest, HKDF's
; T(i)) is wiped before its function returns, and finals wipe the contexts they finish.
; =============================================================================
default rel
%include "httpasm_core.inc"

section .rodata
align 16
hmac_ipad:  times 16 db 0x36        ; FIPS 198-1's ipad, 16 copies for pxor
hmac_opad:  times 16 db 0x5c        ; and opad

section .text

; -----------------------------------------------------------------------------
; void httpasm_hmac_sha256_init(httpasm_hmac_sha256_ctx *h, const uint8_t *key, size_t n)
;   Starts an HMAC with the key key[0..n) (any length; 0 is the all-zero key). The inner hash is
;   fed K0 ^ ipad, the outer K0 ^ opad; K0 and both pad blocks are wiped from the stack.
; -----------------------------------------------------------------------------
HI_K0       equ 0           ; K0: the key's block
HI_PAD      equ 64          ; K0 ^ ipad, then K0 ^ opad
HI_FRAME    equ 128         ; three pushes + 128: rsp 16-byte aligned for movdqa and the calls

global httpasm_hmac_sha256_init:function (httpasm_hmac_sha256_init.end - httpasm_hmac_sha256_init)
align 16
httpasm_hmac_sha256_init:
    push    rbx
    push    r12
    push    r13
    sub     rsp, HI_FRAME
    mov     rbx, rdi                        ; h
    mov     r12, rsi                        ; the key
    mov     r13, rdx                        ; its length
    pxor    xmm0, xmm0
    movdqa  [rsp + HI_K0], xmm0
    movdqa  [rsp + HI_K0 + 16], xmm0
    movdqa  [rsp + HI_K0 + 32], xmm0
    movdqa  [rsp + HI_K0 + 48], xmm0
    cmp     r13, HTTPASM_SHA256_BLOCK
    ja      .long_key
    lea     rdi, [rsp + HI_K0]              ; up to a block: K0 = the key, zeros after it
    mov     rsi, r12
    mov     rcx, r13
    call    ha_copy_short
    jmp     .k0
.long_key:                                  ; longer than a block: K0 = H(key), zeros after it
    mov     rdi, r12
    mov     rsi, r13
    lea     rdx, [rsp + HI_K0]
    call    httpasm_sha256
.k0:
    ; The inner hash: K0 ^ ipad.
    movdqa  xmm4, [rel hmac_ipad]
%assign i 0
%rep 4
    movdqa  xmm0, [rsp + HI_K0 + 16 * i]
    pxor    xmm0, xmm4
    movdqa  [rsp + HI_PAD + 16 * i], xmm0
  %assign i i + 1
%endrep
    lea     rdi, [rbx + httpasm_hmac_sha256_ctx.inner]
    call    httpasm_sha256_init
    lea     rdi, [rbx + httpasm_hmac_sha256_ctx.inner]
    lea     rsi, [rsp + HI_PAD]
    mov     edx, HTTPASM_SHA256_BLOCK
    call    httpasm_sha256_update
    ; The outer hash: K0 ^ opad.
    movdqa  xmm4, [rel hmac_opad]
%assign i 0
%rep 4
    movdqa  xmm0, [rsp + HI_K0 + 16 * i]
    pxor    xmm0, xmm4
    movdqa  [rsp + HI_PAD + 16 * i], xmm0
  %assign i i + 1
%endrep
    lea     rdi, [rbx + httpasm_hmac_sha256_ctx.outer]
    call    httpasm_sha256_init
    lea     rdi, [rbx + httpasm_hmac_sha256_ctx.outer]
    lea     rsi, [rsp + HI_PAD]
    mov     edx, HTTPASM_SHA256_BLOCK
    call    httpasm_sha256_update
    ; K0 and the pad are the key: wiped (the hashes keep only their compressed states).
    pxor    xmm0, xmm0
%assign i 0
%rep 8
    movdqa  [rsp + 16 * i], xmm0
  %assign i i + 1
%endrep
    add     rsp, HI_FRAME
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_hmac_sha256_update(httpasm_hmac_sha256_ctx *h, const uint8_t *data, size_t n)
;   Feeds n octets of the message to the inner hash, which starts the context: its address is
;   the context's, so this is SHA-256's update itself.
; -----------------------------------------------------------------------------
global httpasm_hmac_sha256_update:function (httpasm_hmac_sha256_update.end - httpasm_hmac_sha256_update)
align 16
httpasm_hmac_sha256_update:
    jmp     httpasm_sha256_update           ; .inner is at offset 0
.end:

; -----------------------------------------------------------------------------
; void httpasm_hmac_sha256_final(httpasm_hmac_sha256_ctx *h, uint8_t mac[32])
;   The MAC: the inner hash's digest fed to the outer hash, whose digest it is. Both hashes are
;   wiped by their finals, and the inner digest on the stack after use.
; -----------------------------------------------------------------------------
global httpasm_hmac_sha256_final:function (httpasm_hmac_sha256_final.end - httpasm_hmac_sha256_final)
align 16
httpasm_hmac_sha256_final:
    push    rbx
    push    r12
    sub     rsp, 40                         ; the inner digest (32); two pushes + 40: aligned
    mov     rbx, rdi
    mov     r12, rsi
    lea     rdi, [rbx + httpasm_hmac_sha256_ctx.inner]
    mov     rsi, rsp
    call    httpasm_sha256_final
    lea     rdi, [rbx + httpasm_hmac_sha256_ctx.outer]
    mov     rsi, rsp
    mov     edx, HTTPASM_SHA256_DIGEST
    call    httpasm_sha256_update
    lea     rdi, [rbx + httpasm_hmac_sha256_ctx.outer]
    mov     rsi, r12
    call    httpasm_sha256_final
    pxor    xmm0, xmm0
    movdqu  [rsp], xmm0
    movdqu  [rsp + 16], xmm0
    add     rsp, 40
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_hmac_sha256(const uint8_t *key, size_t key_length, const uint8_t *data,
;                          size_t n, uint8_t mac[32])
;   HMAC-SHA256 of data[0..n) under the key at once, the context on the stack (wiped by final).
; -----------------------------------------------------------------------------
global httpasm_hmac_sha256:function (httpasm_hmac_sha256.end - httpasm_hmac_sha256)
align 16
httpasm_hmac_sha256:
    push    rbx
    push    r12
    push    r13
    sub     rsp, httpasm_hmac_sha256_ctx_size   ; 224: three pushes + 224 keep rsp aligned
    mov     rbx, rdx                        ; data
    mov     r12, rcx                        ; n
    mov     r13, r8                         ; mac
    mov     rdx, rsi
    mov     rsi, rdi
    mov     rdi, rsp
    call    httpasm_hmac_sha256_init
    mov     rdi, rsp
    mov     rsi, rbx
    mov     rdx, r12
    call    httpasm_hmac_sha256_update
    mov     rdi, rsp
    mov     rsi, r13
    call    httpasm_hmac_sha256_final
    add     rsp, httpasm_hmac_sha256_ctx_size
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_hkdf_sha256_extract(const uint8_t *salt, size_t salt_length,
;                                  const uint8_t *ikm, size_t ikm_length, uint8_t prk[32])
;   HKDF-Extract (RFC 5869 2.2): PRK = HMAC-SHA256(salt, IKM). No salt (length 0) is a string of
;   32 zeros, as the RFC says, and HMAC pads either to the same block of zeros.
; -----------------------------------------------------------------------------
global httpasm_hkdf_sha256_extract:function (httpasm_hkdf_sha256_extract.end - httpasm_hkdf_sha256_extract)
align 16
httpasm_hkdf_sha256_extract:
    jmp     httpasm_hmac_sha256             ; the same five arguments, in the same order
.end:

; -----------------------------------------------------------------------------
; int httpasm_hkdf_sha256_expand(const uint8_t *prk, size_t prk_length, const uint8_t *info,
;                                size_t info_length, uint8_t *okm, size_t length)
;   HKDF-Expand (RFC 5869 2.3): OKM = the first `length` octets of T(1) || T(2) || ..., where
;   T(i) = HMAC-SHA256(PRK, T(i-1) || info || i) and T(0) is empty. The PRK's HMAC context is
;   made once and copied for each T(i) (two compressions saved per block). Returns 0; or -1 when
;   length exceeds 255 * 32 = 8160 (the RFC's limit), and then writes nothing.
; -----------------------------------------------------------------------------
HE_KEYED    equ 0                           ; the PRK's fresh HMAC context
HE_WORK     equ HE_KEYED + httpasm_hmac_sha256_ctx_size     ; the copy that makes T(i)
HE_T        equ HE_WORK + httpasm_hmac_sha256_ctx_size      ; T(i)
HE_COUNTER  equ HE_T + 32                   ; i, one octet
HE_FRAME    equ HE_COUNTER + 16             ; 496 (the counter padded to 16): six pushes + 496 + 8 below keep rsp aligned

global httpasm_hkdf_sha256_expand:function (httpasm_hkdf_sha256_expand.end - httpasm_hkdf_sha256_expand)
align 16
httpasm_hkdf_sha256_expand:
    mov     rax, -1
    cmp     r9, 255 * HTTPASM_SHA256_DIGEST
    ja      .out_early                      ; past the limit: nothing written
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, HE_FRAME + 8
    mov     rbx, rdx                        ; info
    mov     rbp, rcx                        ; its length
    mov     r12, r8                         ; the next OKM octet
    mov     r13, r9                         ; OKM octets still to write
    mov     rdx, rsi
    mov     rsi, rdi
    lea     rdi, [rsp + HE_KEYED]
    call    httpasm_hmac_sha256_init
    mov     byte [rsp + HE_COUNTER], 0
.block:
    test    r13, r13
    jz      .done
    inc     byte [rsp + HE_COUNTER]         ; i: 1 to 255
    ; The keyed context, copied: 224 octets, 14 moves.
%assign i 0
%rep 14
    movdqa  xmm0, [rsp + HE_KEYED + 16 * i]
    movdqa  [rsp + HE_WORK + 16 * i], xmm0
  %assign i i + 1
%endrep
    cmp     byte [rsp + HE_COUNTER], 1
    je      .info                           ; T(0) is empty
    lea     rdi, [rsp + HE_WORK]
    lea     rsi, [rsp + HE_T]
    mov     edx, HTTPASM_SHA256_DIGEST
    call    httpasm_hmac_sha256_update
.info:
    lea     rdi, [rsp + HE_WORK]
    mov     rsi, rbx
    mov     rdx, rbp
    call    httpasm_hmac_sha256_update
    lea     rdi, [rsp + HE_WORK]
    lea     rsi, [rsp + HE_COUNTER]
    mov     edx, 1
    call    httpasm_hmac_sha256_update
    lea     rdi, [rsp + HE_WORK]
    lea     rsi, [rsp + HE_T]
    call    httpasm_hmac_sha256_final       ; wipes the copy
    ; T(i)'s first min(32, still to write) octets go out.
    mov     ecx, HTTPASM_SHA256_DIGEST
    cmp     r13, rcx
    cmovb   rcx, r13
    mov     rdi, r12
    lea     rsi, [rsp + HE_T]
    call    ha_copy_short                   ; keeps rcx
    add     r12, rcx
    sub     r13, rcx
    jmp     .block
.done:
    ; The keyed context and T(n) hold the PRK's secret: the whole frame wiped, 16 octets a step.
    ; A loop, not %rep: HE_FRAME is an equ, which the coverage build's preprocessor (nasm -E,
    ; tests/coverage/instrument.cs) cannot count with.
    pxor    xmm0, xmm0
    xor     eax, eax
.wipe:
    movdqa  [rsp + rax], xmm0
    add     eax, 16
    cmp     eax, HE_FRAME
    jb      .wipe
    add     rsp, HE_FRAME + 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    xor     eax, eax
.out_early:
    ret
.end:
