; =============================================================================
; crypto/hmac.asm - HMAC (FIPS 198-1, RFC 2104) and HKDF (RFC 5869) over SHA-256, SHA-384 and
; SHA-512: the MACs and the key derivations TLS 1.3's key schedule is made of (RFC 9846 7.1:
; HKDF-Extract, and HKDF-Expand under HKDF-Expand-Label), SHA-256's for TLS_AES_128_GCM_SHA256
; and TLS_CHACHA20_POLY1305_SHA256, SHA-384's for TLS_AES_256_GCM_SHA384; and SHA-512's, which no
; TLS 1.3 cipher suite uses, for RFC 6979's deterministic nonces at P-521 (crypto/p521.asm's
; HMAC_DRBG: RFC 6979's own k when the digest is SHA-512's, ecdsa_secp521r1_sha512's).
;
; HMAC(K, m) = H((K0 ^ opad) || H((K0 ^ ipad) || m)), K0 the key padded with zeros to the block,
; or its digest padded when it is longer than a block (FIPS 198-1 section 4 steps 1-3). The
; context holds both hashes already past their key block, so the key is not kept, and a copy of
; a fresh context MACs another message with the same key without the two key compressions.
; Everything here runs on the C ABI's hashes (crypto/sha256.asm, crypto/sha512.asm), whose
; compressions pick their versions per call; this file adds no version of its own.
;
; One source for the three hashes: HMAC_FUNCTIONS (below) writes the six functions of one hash from
; its parameters (names, block and digest sizes, the context's size). Every count it repeats by
; is a literal of its invocation, never an equ: the coverage build preprocesses with nasm -E,
; which cannot evaluate an equ in %rep (tests/coverage/instrument.cs).
;
; Constant time: no branch or address depends on a key's or a message's octets, only on their
; lengths. Every buffer that held a key's octets (K0, the pad blocks, the inner digest, HKDF's
; T(i)) is wiped before its function returns, and finals wipe the contexts they finish.
; =============================================================================
default rel
%include "httpasm_core.inc"

extern httpasm_sha512_init                  ; crypto/sha512.asm: SHA-512's start, end and one-shot
extern httpasm_sha512_final                 ; hash, for HMAC_FUNCTIONS sha512 (httpasm_core.inc
extern httpasm_sha512                       ; declares SHA-384's and the update both share)

section .rodata
align 16
hmac_ipad:  times 16 db 0x36        ; FIPS 198-1's ipad, 16 copies for pxor
hmac_opad:  times 16 db 0x5c        ; and opad

section .text

; -----------------------------------------------------------------------------
; HMAC_FUNCTIONS name, hinit, hupdate, hfinal, hash, block, digest, ctx, block16, ctx16, digest16
;   The six functions of HMAC and HKDF over one hash:
;     name     the suffix of the C ABI's names (sha256: httpasm_hmac_sha256_init, ...)
;     hinit, hupdate, hfinal, hash
;              the hash's init, update, final and one-shot functions (C ABI)
;     block    its block in octets (64, 128)       digest  its digest in octets (32, 48)
;     ctx      the HMAC context's structure (httpasm_hmac_<name>_ctx: .inner, .outer)
;     block16, ctx16, digest16
;              block / 16, the HMAC context's size / 16, and the digest's size / 16 rounded up,
;              as literals: the counts of the moves that fill, copy and wipe them
;   Each function is documented where httpasm.h declares it; the comments here say how.
; -----------------------------------------------------------------------------
%macro HMAC_FUNCTIONS 11
; -----------------------------------------------------------------------------
; void httpasm_hmac_%1_init(httpasm_hmac_%1_ctx *h, const uint8_t *key, size_t n)
;   Starts an HMAC with the key key[0..n) (any length; 0 is the all-zero key). The inner hash is
;   fed K0 ^ ipad, the outer K0 ^ opad; K0 and both pad blocks are wiped from the stack.
;   Frame: K0 at 0, the pad block at %6; three pushes + 2 * %6 keep rsp 16-byte aligned for
;   movdqa and the calls.
; -----------------------------------------------------------------------------
global httpasm_hmac_%1_init:function (httpasm_hmac_%1_init.end - httpasm_hmac_%1_init)
align 16
httpasm_hmac_%1_init:
    push    rbx
    push    r12
    push    r13
    sub     rsp, 2 * %6
    mov     rbx, rdi                        ; h
    mov     r12, rsi                        ; the key
    mov     r13, rdx                        ; its length
    pxor    xmm0, xmm0
%assign i 0
%rep %9
    movdqa  [rsp + 16 * i], xmm0            ; K0's zeros
  %assign i i + 1
%endrep
    cmp     r13, %6
    ja      .long_key
    lea     rdi, [rsp]                      ; up to a block: K0 (at rsp) = the key, zeros after it
    mov     rsi, r12
    mov     rcx, r13
    call    ha_copy_short
    jmp     .k0
.long_key:                                  ; longer than a block: K0 = H(key), zeros after it
    mov     rdi, r12
    mov     rsi, r13
    lea     rdx, [rsp]                      ; K0
    call    %5
.k0:
    ; The inner hash: K0 ^ ipad.
    movdqa  xmm4, [rel hmac_ipad]
%assign i 0
%rep %9
    movdqa  xmm0, [rsp + 16 * i]
    pxor    xmm0, xmm4
    movdqa  [rsp + %6 + 16 * i], xmm0
  %assign i i + 1
%endrep
    lea     rdi, [rbx + %8.inner]
    call    %2
    lea     rdi, [rbx + %8.inner]
    lea     rsi, [rsp + %6]
    mov     edx, %6
    call    %3
    ; The outer hash: K0 ^ opad.
    movdqa  xmm4, [rel hmac_opad]
%assign i 0
%rep %9
    movdqa  xmm0, [rsp + 16 * i]
    pxor    xmm0, xmm4
    movdqa  [rsp + %6 + 16 * i], xmm0
  %assign i i + 1
%endrep
    lea     rdi, [rbx + %8.outer]
    call    %2
    lea     rdi, [rbx + %8.outer]
    lea     rsi, [rsp + %6]
    mov     edx, %6
    call    %3
    ; K0 and the pad are the key: wiped (the hashes keep only their compressed states).
    pxor    xmm0, xmm0
%assign i 0
%rep 2 * %9
    movdqa  [rsp + 16 * i], xmm0
  %assign i i + 1
%endrep
    add     rsp, 2 * %6
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_hmac_%1_update(httpasm_hmac_%1_ctx *h, const uint8_t *data, size_t n)
;   Feeds n octets of the message to the inner hash, which starts the context: its address is
;   the context's, so this is the hash's update itself.
; -----------------------------------------------------------------------------
global httpasm_hmac_%1_update:function (httpasm_hmac_%1_update.end - httpasm_hmac_%1_update)
align 16
httpasm_hmac_%1_update:
    jmp     %3                              ; .inner is at offset 0
.end:

; -----------------------------------------------------------------------------
; void httpasm_hmac_%1_final(httpasm_hmac_%1_ctx *h, uint8_t mac[%7])
;   The MAC: the inner hash's digest fed to the outer hash, whose digest it is. Both hashes are
;   wiped by their finals, and the inner digest on the stack after use. Frame: the inner
;   digest, 16 * %11 octets; two pushes + 16 * %11 + 8 keep rsp aligned.
; -----------------------------------------------------------------------------
global httpasm_hmac_%1_final:function (httpasm_hmac_%1_final.end - httpasm_hmac_%1_final)
align 16
httpasm_hmac_%1_final:
    push    rbx
    push    r12
    sub     rsp, 16 * %11 + 8
    mov     rbx, rdi
    mov     r12, rsi
    lea     rdi, [rbx + %8.inner]
    mov     rsi, rsp
    call    %4
    lea     rdi, [rbx + %8.outer]
    mov     rsi, rsp
    mov     edx, %7
    call    %3
    lea     rdi, [rbx + %8.outer]
    mov     rsi, r12
    call    %4
    pxor    xmm0, xmm0
%assign i 0
%rep %11
    movdqu  [rsp + 16 * i], xmm0
  %assign i i + 1
%endrep
    add     rsp, 16 * %11 + 8
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_hmac_%1(const uint8_t *key, size_t key_length, const uint8_t *data, size_t n,
;                      uint8_t mac[%7])
;   The MAC of data[0..n) under the key at once, the context on the stack (wiped by final).
;   Three pushes + the context (16 * %10 octets) keep rsp aligned.
; -----------------------------------------------------------------------------
global httpasm_hmac_%1:function (httpasm_hmac_%1.end - httpasm_hmac_%1)
align 16
httpasm_hmac_%1:
    push    rbx
    push    r12
    push    r13
    sub     rsp, 16 * %10
    mov     rbx, rdx                        ; data
    mov     r12, rcx                        ; n
    mov     r13, r8                         ; mac
    mov     rdx, rsi
    mov     rsi, rdi
    mov     rdi, rsp
    call    httpasm_hmac_%1_init
    mov     rdi, rsp
    mov     rsi, rbx
    mov     rdx, r12
    call    httpasm_hmac_%1_update
    mov     rdi, rsp
    mov     rsi, r13
    call    httpasm_hmac_%1_final
    add     rsp, 16 * %10
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_hkdf_%1_extract(const uint8_t *salt, size_t salt_length, const uint8_t *ikm,
;                              size_t ikm_length, uint8_t prk[%7])
;   HKDF-Extract (RFC 5869 2.2): PRK = HMAC(salt, IKM). No salt (length 0) is a string of %7
;   zeros, as the RFC says, and HMAC pads either to the same block of zeros.
; -----------------------------------------------------------------------------
global httpasm_hkdf_%1_extract:function (httpasm_hkdf_%1_extract.end - httpasm_hkdf_%1_extract)
align 16
httpasm_hkdf_%1_extract:
    jmp     httpasm_hmac_%1                 ; the same five arguments, in the same order
.end:

; -----------------------------------------------------------------------------
; int httpasm_hkdf_%1_expand(const uint8_t *prk, size_t prk_length, const uint8_t *info,
;                            size_t info_length, uint8_t *okm, size_t length)
;   HKDF-Expand (RFC 5869 2.3): OKM = the first `length` octets of T(1) || T(2) || ..., where
;   T(i) = HMAC(PRK, T(i-1) || info || i) and T(0) is empty. The PRK's HMAC context is made
;   once and copied for each T(i) (two compressions saved per block). Returns 0; or -1 when
;   length exceeds 255 * %7 (the RFC's limit), and then writes nothing.
;   Frame: the keyed context, its working copy, T(i) (16 * %11 octets), the counter (16); six
;   pushes + the frame + 8 keep rsp aligned.
; -----------------------------------------------------------------------------
global httpasm_hkdf_%1_expand:function (httpasm_hkdf_%1_expand.end - httpasm_hkdf_%1_expand)
align 16
httpasm_hkdf_%1_expand:
  %push hkdf
  %define %$KEYED   0                           ; the PRK's fresh HMAC context
  %define %$WORK    16 * %10                    ; the copy that makes T(i)
  %define %$T       2 * 16 * %10                ; T(i)
  %define %$COUNTER 2 * 16 * %10 + 16 * %11     ; i, one octet
  %define %$FRAME   2 * 16 * %10 + 16 * %11 + 16
    mov     rax, -1
    cmp     r9, 255 * %7
    ja      .out_early                      ; past the limit: nothing written
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, %$FRAME + 8
    mov     rbx, rdx                        ; info
    mov     rbp, rcx                        ; its length
    mov     r12, r8                         ; the next OKM octet
    mov     r13, r9                         ; OKM octets still to write
    mov     rdx, rsi
    mov     rsi, rdi
    lea     rdi, [rsp + %$KEYED]
    call    httpasm_hmac_%1_init
    mov     byte [rsp + %$COUNTER], 0
.block:
    test    r13, r13
    jz      .done
    inc     byte [rsp + %$COUNTER]          ; i: 1 to 255
    ; The keyed context, copied: 16 * %10 octets.
%assign i 0
%rep %10
    movdqa  xmm0, [rsp + %$KEYED + 16 * i]
    movdqa  [rsp + %$WORK + 16 * i], xmm0
  %assign i i + 1
%endrep
    cmp     byte [rsp + %$COUNTER], 1
    je      .info                           ; T(0) is empty
    lea     rdi, [rsp + %$WORK]
    lea     rsi, [rsp + %$T]
    mov     edx, %7
    call    httpasm_hmac_%1_update
.info:
    lea     rdi, [rsp + %$WORK]
    mov     rsi, rbx
    mov     rdx, rbp
    call    httpasm_hmac_%1_update
    lea     rdi, [rsp + %$WORK]
    lea     rsi, [rsp + %$COUNTER]
    mov     edx, 1
    call    httpasm_hmac_%1_update
    lea     rdi, [rsp + %$WORK]
    lea     rsi, [rsp + %$T]
    call    httpasm_hmac_%1_final           ; wipes the copy
    ; T(i)'s first min(%7, still to write) octets go out.
    mov     ecx, %7
    cmp     r13, rcx
    cmovb   rcx, r13
    mov     rdi, r12
    lea     rsi, [rsp + %$T]
    call    ha_copy_short                   ; keeps rcx
    add     r12, rcx
    sub     r13, rcx
    jmp     .block
.done:
    ; The keyed context and T(n) hold the PRK's secret: the whole frame wiped, 16 octets a step
    ; (a loop: the frame's size is not a literal count).
    pxor    xmm0, xmm0
    xor     eax, eax
.wipe:
    movdqa  [rsp + rax], xmm0
    add     eax, 16
    cmp     eax, %$FRAME
    jb      .wipe
    add     rsp, %$FRAME + 8
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
  %pop
%endmacro

; SHA-256: 64-octet blocks, 32-octet digests, a 224-octet context (14 x 16).
HMAC_FUNCTIONS sha256, httpasm_sha256_init, httpasm_sha256_update, httpasm_sha256_final, httpasm_sha256, 64, 32, httpasm_hmac_sha256_ctx, 4, 14, 2

; SHA-384: 128-octet blocks, 48-octet digests, a 416-octet context (26 x 16).
HMAC_FUNCTIONS sha384, httpasm_sha384_init, httpasm_sha512_update, httpasm_sha384_final, httpasm_sha384, 128, 48, httpasm_hmac_sha384_ctx, 8, 26, 3

; SHA-512: SHA-384's blocks and context (the same httpasm_sha512_ctx, started by its own init),
; 64-octet digests: HKDF-Expand's limit is 255 * 64 = 16320 octets.
HMAC_FUNCTIONS sha512, httpasm_sha512_init, httpasm_sha512_update, httpasm_sha512_final, httpasm_sha512, 128, 64, httpasm_hmac_sha512_ctx, 8, 26, 4
