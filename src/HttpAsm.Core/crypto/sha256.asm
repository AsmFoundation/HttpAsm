; =============================================================================
; crypto/sha256.asm - SHA-256 (FIPS 180-4 sections 5.1.1, 5.3.3, 6.2): the running hash of the
; C ABI (httpasm_sha256_init, _update, _final), its one-shot form (httpasm_sha256), and
; ha_sha256_blocks, the compression of whole 64-octet blocks that HMAC, HKDF and TLS's
; transcript hash build on.
;
; ha_sha256_blocks has two versions, chosen once per call (HA_CPU_PICK), never per block:
;   v1   any x86-64: FIPS 180-4 6.2.2's 64 rounds unrolled, the working variables a-h in
;        r8d-r15d and renamed by the assembler from round to round (no moves between rounds),
;        the message schedule's last 16 words on the stack, each W(t) computed just before
;        the round that first reads it.
;   SHA  the SHA extensions: sha256rnds2 does two rounds, sha256msg1 and sha256msg2 the
;        schedule; with SSSE3's pshufb (the big-endian words) and SSE4.1's pblendw (the
;        state's lane order), so it needs HTTPASM_CPU_SHA and HTTPASM_CPU_V2 together.
; Both give the same state for every input: tests/native/tiers compares them octet for octet,
; and the .NET suite runs NIST's vectors at every tier. Neither has a branch or a memory address
; that depends on the data: SHA-256 is constant time by construction, so hashing a secret (an
; HMAC key, a TLS secret) shows nothing but its length.
; =============================================================================
default rel
%include "httpasm_core.inc"

section .rodata
align 64
; K: the 64 round constants (FIPS 180-4 4.2.2), 16-octet aligned for paddd's memory operand.
sha256_k:
    dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
; pshufb's control that turns each dword of a vector around: the message is big-endian.
sha256_bswap:
    db 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
; H(0), the initial hash value (FIPS 180-4 5.3.3).
sha256_iv:
    dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

section .text

; -----------------------------------------------------------------------------
; v1's frame: the schedule's 16-word window, then the caller's arguments it keeps.
; -----------------------------------------------------------------------------
SHA_W       equ 0           ; W(t) for the last 16 t, slot t mod 16
SHA_STATE   equ 64          ; the state's address
SHA_END     equ 72          ; the data's end
SHA_FRAME   equ 88          ; five pushes + 88: rsp 16-byte aligned (nothing is called, all the same)

; -----------------------------------------------------------------------------
; SHA256_W t: W(t) for t >= 16 (FIPS 180-4 6.2.2 step 1) into the window slot t mod 16, which
; held W(t-16): W(t) = sigma1(W(t-2)) + W(t-7) + sigma0(W(t-15)) + W(t-16).
;   Clobbers eax, ecx, edx, esi.
; -----------------------------------------------------------------------------
%macro SHA256_W 1
    mov     eax, [rsp + SHA_W + 4 * ((%1 - 15) & 15)]
    mov     ecx, eax
    ror     eax, 7
    mov     edx, ecx
    ror     edx, 18
    xor     eax, edx
    shr     ecx, 3
    xor     eax, ecx                        ; sigma0(W(t-15)) = ROTR7 ^ ROTR18 ^ SHR3
    mov     ecx, [rsp + SHA_W + 4 * ((%1 - 2) & 15)]
    mov     edx, ecx
    ror     ecx, 17
    mov     esi, edx
    ror     esi, 19
    xor     ecx, esi
    shr     edx, 10
    xor     ecx, edx                        ; sigma1(W(t-2)) = ROTR17 ^ ROTR19 ^ SHR10
    add     eax, ecx
    add     eax, [rsp + SHA_W + 4 * ((%1 - 7) & 15)]
    add     [rsp + SHA_W + 4 * (%1 & 15)], eax
%endmacro

; -----------------------------------------------------------------------------
; SHA256_ROUND a, b, c, d, e, f, g, h, t: round t (FIPS 180-4 6.2.2 step 3) on the working
; variables in the eight registers named, W(t) in its window slot. The round leaves the next
; round's a in h's register and its e in d's, so the next round names the registers
; (h, a, b, c, d, e, f, g): the caller renames, nothing moves.
;   Clobbers eax, ecx, edx.
; -----------------------------------------------------------------------------
%macro SHA256_ROUND 9
    mov     eax, %5
    ror     eax, 6
    mov     ecx, %5
    ror     ecx, 11
    xor     eax, ecx
    ror     ecx, 14                         ; 11 + 14 = 25
    xor     eax, ecx                        ; Sigma1(e) = ROTR6 ^ ROTR11 ^ ROTR25
    mov     ecx, %6
    xor     ecx, %7
    and     ecx, %5
    xor     ecx, %7                         ; Ch(e, f, g) = ((f ^ g) & e) ^ g
    add     eax, ecx
    add     eax, [rel sha256_k + 4 * %9]
    add     eax, [rsp + SHA_W + 4 * (%9 & 15)]
    add     %8, eax                         ; T1, in h's register: h is not read again
    add     %4, %8                          ; the next e: d + T1
    mov     eax, %1
    ror     eax, 2
    mov     ecx, %1
    ror     ecx, 13
    xor     eax, ecx
    ror     ecx, 9                          ; 13 + 9 = 22
    xor     eax, ecx                        ; Sigma0(a) = ROTR2 ^ ROTR13 ^ ROTR22
    mov     ecx, %1
    or      ecx, %2
    and     ecx, %3
    mov     edx, %1
    and     edx, %2
    or      ecx, edx                        ; Maj(a, b, c) = ((a | b) & c) | (a & b)
    add     eax, ecx
    add     %8, eax                         ; the next a: T1 + T2
%endmacro

; -----------------------------------------------------------------------------
; SHA256_NI_QUAD q: rounds 4q to 4q + 3 of the SHA version (Intel's SHA extensions guide's
; schedule, written out from the instructions' definitions). xmm0 is the message words plus K
; (sha256rnds2's implicit operand), xmm1 and xmm2 the state as ABEF and CDGH, xmm3-xmm6 the
; schedule's four 4-word groups W(4k..4k+3) in rotation, xmm7 scratch, xmm8 the byte-swap
; control, rsi the block. Groups 0-3 are the block's words; from group 3 on, sha256msg1 and
; sha256msg2 build each later group from the four before it (W(t-16), W(t-15), W(t-7) and
; W(t-2), as SHA256_W does), one group ahead of the rounds that read it.
; -----------------------------------------------------------------------------
%macro SHA256_NI_QUAD 1
  %assign g_this 3 + ((%1) & 3)             ; the registers of groups q, q - 1 and q + 1
  %assign g_prev 3 + ((%1 - 1) & 3)
  %assign g_next 3 + ((%1 + 1) & 3)
  %if %1 < 4
    movdqu  xmm%[g_this], [rsi + 16 * %1]
    pshufb  xmm%[g_this], xmm8              ; the block's words, big-endian
  %endif
    movdqa  xmm0, xmm%[g_this]
    paddd   xmm0, [rel sha256_k + 16 * %1]
    sha256rnds2 xmm2, xmm1                  ; rounds 4q, 4q + 1 (the low two words of xmm0)
  %if %1 >= 3 && %1 <= 14
    movdqa  xmm7, xmm%[g_this]
    palignr xmm7, xmm%[g_prev], 4           ; W(t-7) for the group after this one
    paddd   xmm%[g_next], xmm7
    sha256msg2 xmm%[g_next], xmm%[g_this]   ; that group, finished with sigma1(W(t-2))
  %endif
    pshufd  xmm0, xmm0, 0x0E                ; the high two words down
    sha256rnds2 xmm1, xmm2                  ; rounds 4q + 2, 4q + 3
  %if %1 >= 1 && %1 <= 12
    sha256msg1 xmm%[g_prev], xmm%[g_this]   ; sigma0(W(t-15)) into a group 3 ahead
  %endif
%endmacro

; -----------------------------------------------------------------------------
; ha_sha256_blocks: SHA-256's compression of whole blocks into a state (FIPS 180-4 6.2.2).
;   In: rdi = the state (8 dwords, H0-H7), rsi = the blocks, rdx = how many (0 does nothing).
;   Out: the state updated. Keeps rbx, rbp, r12-r15 and rdi. Clobbers rax, rcx, rdx, rsi,
;   r8-r11, xmm0-xmm10 and the flags.
;   Memory: reads rsi[0..64 * rdx); writes the state only.
; -----------------------------------------------------------------------------
global ha_sha256_blocks:function hidden (ha_sha256_blocks.end - ha_sha256_blocks)
align 16
ha_sha256_blocks:
    test    rdx, rdx
    jz      .nothing
    HA_CPU_PICK HTTPASM_CPU_SHA | HTTPASM_CPU_V2, .sha
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, SHA_FRAME
    mov     [rsp + SHA_STATE], rdi
    shl     rdx, 6
    add     rdx, rsi
    mov     [rsp + SHA_END], rdx
    mov     rbp, rsi                        ; the block
    mov     r8d, [rdi]
    mov     r9d, [rdi + 4]
    mov     r10d, [rdi + 8]
    mov     r11d, [rdi + 12]
    mov     r12d, [rdi + 16]
    mov     r13d, [rdi + 20]
    mov     r14d, [rdi + 24]
    mov     r15d, [rdi + 28]
.block:
%xdefine SA r8d
%xdefine SB r9d
%xdefine SC r10d
%xdefine SD r11d
%xdefine SE r12d
%xdefine SF r13d
%xdefine SG r14d
%xdefine SH r15d
%assign t 0
%rep 64
  %if t < 16
    mov     eax, [rbp + 4 * t]
    bswap   eax                             ; W(t), t < 16: the block's word, big-endian
    mov     [rsp + SHA_W + 4 * t], eax
  %else
    SHA256_W t
  %endif
    SHA256_ROUND SA, SB, SC, SD, SE, SF, SG, SH, t
  %xdefine ST SH
  %xdefine SH SG
  %xdefine SG SF
  %xdefine SF SE
  %xdefine SE SD
  %xdefine SD SC
  %xdefine SC SB
  %xdefine SB SA
  %xdefine SA ST
  %assign t t + 1
%endrep
    ; 64 renamings are 8 full turns: a-h are in r8d-r15d again. H(i) = H(i-1) + a..h.
    mov     rdi, [rsp + SHA_STATE]
    add     r8d, [rdi]
    mov     [rdi], r8d
    add     r9d, [rdi + 4]
    mov     [rdi + 4], r9d
    add     r10d, [rdi + 8]
    mov     [rdi + 8], r10d
    add     r11d, [rdi + 12]
    mov     [rdi + 12], r11d
    add     r12d, [rdi + 16]
    mov     [rdi + 16], r12d
    add     r13d, [rdi + 20]
    mov     [rdi + 20], r13d
    add     r14d, [rdi + 24]
    mov     [rdi + 24], r14d
    add     r15d, [rdi + 28]
    mov     [rdi + 28], r15d
    add     rbp, 64
    cmp     rbp, [rsp + SHA_END]
    jb      .block
    add     rsp, SHA_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
.nothing:
    ret

.sha:
    ; The state as the instructions take it: xmm1 = ABEF, xmm2 = CDGH (A, C in the high dword).
    movdqu  xmm1, [rdi]                     ; D C B A (dword 0 = A)
    movdqu  xmm2, [rdi + 16]                ; H G F E
    pshufd  xmm1, xmm1, 0xB1                ; C D A B
    pshufd  xmm2, xmm2, 0x1B                ; E F G H
    movdqa  xmm7, xmm1
    palignr xmm1, xmm2, 8                   ; A B E F
    pblendw xmm2, xmm7, 0xF0                ; C D G H
    movdqa  xmm8, [rel sha256_bswap]
    shl     rdx, 6
    add     rdx, rsi                        ; the data's end
.sha_block:
    movdqa  xmm9, xmm1                      ; H(i-1), added back after the 64 rounds
    movdqa  xmm10, xmm2
%assign q 0
%rep 16
    SHA256_NI_QUAD q
  %assign q q + 1
%endrep
    paddd   xmm1, xmm9
    paddd   xmm2, xmm10
    add     rsi, 64
    cmp     rsi, rdx
    jb      .sha_block
    ; Back to H0-H7's order.
    pshufd  xmm1, xmm1, 0x1B                ; F E B A
    pshufd  xmm2, xmm2, 0xB1                ; D C H G
    movdqa  xmm7, xmm1
    pblendw xmm1, xmm2, 0xF0                ; D C B A
    palignr xmm2, xmm7, 8                   ; H G F E
    movdqu  [rdi], xmm1
    movdqu  [rdi + 16], xmm2
    ret
.end:

; -----------------------------------------------------------------------------
; ha_copy_short: a few octets (a running hash's partial block, an HMAC key) by moves sized to
; the count, no rep movsb (whose start-up costs more than such a copy: write.asm wr_put measured
; it). Shared by the crypto code (hidden).
;   In: rdi = destination, rsi = source, rcx = count (any; meant for a block or less: SHA-512's
;   partial blocks reach 127). The two may not overlap.
;   Keeps every register but rax, rdx, xmm0 and the flags.
;   Memory: reads rsi[0..rcx), writes rdi[0..rcx), nothing past either.
; -----------------------------------------------------------------------------
global ha_copy_short:function hidden (ha_copy_short.end - ha_copy_short)
align 16
ha_copy_short:
    cmp     rcx, 16
    jae     .sixteen
    cmp     rcx, 8
    jae     .eight
    cmp     rcx, 4
    jae     .four
    test    rcx, rcx
    jz      .out
    movzx   eax, byte [rsi]
    movzx   edx, byte [rsi + rcx - 1]
    mov     [rdi], al
    mov     [rdi + rcx - 1], dl             ; 1-3 octets: the first, the last, and
    cmp     rcx, 3
    jb      .out
    movzx   eax, byte [rsi + 1]
    mov     [rdi + 1], al                   ; the middle one of three
.out:
    ret
.four:                                      ; 4-7: two dwords, overlapping
    mov     eax, [rsi]
    mov     edx, [rsi + rcx - 4]
    mov     [rdi], eax
    mov     [rdi + rcx - 4], edx
    ret
.eight:                                     ; 8-15: two qwords, overlapping
    mov     rax, [rsi]
    mov     rdx, [rsi + rcx - 8]
    mov     [rdi], rax
    mov     [rdi + rcx - 8], rdx
    ret
.sixteen:                                   ; 16 and up: 16 octets a step, the last overlapping
    xor     edx, edx
.step:
    movdqu  xmm0, [rsi + rdx]
    movdqu  [rdi + rdx], xmm0
    add     rdx, 16
    lea     rax, [rdx + 16]
    cmp     rax, rcx
    jbe     .step
    movdqu  xmm0, [rsi + rcx - 16]
    movdqu  [rdi + rcx - 16], xmm0
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_sha256_init(httpasm_sha256_ctx *h)
;   A new hash: H(0), nothing fed. Writes all 112 octets.
; -----------------------------------------------------------------------------
global httpasm_sha256_init:function (httpasm_sha256_init.end - httpasm_sha256_init)
align 16
httpasm_sha256_init:
    movdqa  xmm0, [rel sha256_iv]
    movdqa  xmm1, [rel sha256_iv + 16]
    movdqu  [rdi + httpasm_sha256_ctx.state], xmm0
    movdqu  [rdi + httpasm_sha256_ctx.state + 16], xmm1
    xor     eax, eax
    mov     [rdi + httpasm_sha256_ctx.length], rax
    mov     [rdi + httpasm_sha256_ctx.buffered], rax    ; .buffered and .reserved
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_sha256_update(httpasm_sha256_ctx *h, const uint8_t *data, size_t n)
;   Feeds n octets (0 is allowed, data may then be anything). Whole blocks are compressed
;   straight from data; only a partial block's octets are copied into h.
;   The total fed must stay below 2^61 octets (FIPS 180-4: a message below 2^64 bits).
; -----------------------------------------------------------------------------
global httpasm_sha256_update:function (httpasm_sha256_update.end - httpasm_sha256_update)
align 16
httpasm_sha256_update:
    push    rbx
    push    r12
    push    r13                             ; three pushes: rsp 16-byte aligned for the calls
    mov     rbx, rdi                        ; h
    mov     r12, rsi                        ; the octets not taken yet
    mov     r13, rdx                        ; how many
    add     [rbx + httpasm_sha256_ctx.length], rdx
    mov     eax, [rbx + httpasm_sha256_ctx.buffered]
    test    eax, eax
    jz      .blocks
    ; A partial block waits: fill it, if the data can.
    mov     ecx, 64
    sub     ecx, eax                        ; the octets it lacks (1-63)
    cmp     r13, rcx
    jb      .keep                           ; still not a block
    lea     rdi, [rbx + httpasm_sha256_ctx.buffer + rax]
    mov     rsi, r12
    call    ha_copy_short                   ; keeps rcx
    add     r12, rcx
    sub     r13, rcx
    lea     rdi, [rbx + httpasm_sha256_ctx.state]
    lea     rsi, [rbx + httpasm_sha256_ctx.buffer]
    mov     edx, 1
    call    ha_sha256_blocks
    mov     dword [rbx + httpasm_sha256_ctx.buffered], 0
.blocks:
    mov     rdx, r13
    shr     rdx, 6
    jz      .tail
    lea     rdi, [rbx + httpasm_sha256_ctx.state]
    mov     rsi, r12
    call    ha_sha256_blocks
    mov     rax, r13
    and     rax, -64
    add     r12, rax
    and     r13, 63
.tail:
    xor     eax, eax                        ; the buffer is empty here
.keep:                                      ; eax = octets buffered, r13 (< 64 - eax) to add
    lea     rdi, [rbx + httpasm_sha256_ctx.buffer + rax]
    mov     rsi, r12
    mov     rcx, r13
    call    ha_copy_short
    add     [rbx + httpasm_sha256_ctx.buffered], r13d
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_sha256_final(httpasm_sha256_ctx *h, uint8_t digest[32])
;   The padding of FIPS 180-4 5.1.1 (0x80, zeros, the length in bits as 64 bits big-endian),
;   its last one or two blocks, and the digest, big-endian. The padded blocks are built in a
;   zeroed pad on the stack (the buffered octets, 0x80, the length: no octet-by-octet zeroing)
;   and compressed from there. Then h and the pad are wiped to zeros: they held the message's
;   last octets (an HMAC key's padding, a TLS secret's); another hash starts with
;   httpasm_sha256_init.
; -----------------------------------------------------------------------------
FIN_PAD     equ 0           ; two blocks: the padding needs the second past 55 octets
FIN_FRAME   equ 128         ; the pad; the frame takes 8 more, so rsp stays 16-byte aligned

global httpasm_sha256_final:function (httpasm_sha256_final.end - httpasm_sha256_final)
align 16
httpasm_sha256_final:
    push    rbx
    push    r12
    sub     rsp, FIN_FRAME + 8              ; two pushes + 136: aligned for the calls
    mov     rbx, rdi
    mov     r12, rsi
    pxor    xmm0, xmm0
%assign i 0
%rep 8
    movdqa  [rsp + FIN_PAD + 16 * i], xmm0
  %assign i i + 1
%endrep
    lea     rdi, [rsp + FIN_PAD]
    lea     rsi, [rbx + httpasm_sha256_ctx.buffer]
    mov     ecx, [rbx + httpasm_sha256_ctx.buffered]
    call    ha_copy_short                   ; keeps rcx
    mov     byte [rsp + FIN_PAD + rcx], 0x80
    ; One block when the length fits after the 0x80 (55 octets buffered at most), else two.
    mov     edx, 1
    cmp     ecx, 56
    jb      .one_block
    mov     edx, 2
.one_block:
    mov     rax, [rbx + httpasm_sha256_ctx.length]
    shl     rax, 3                          ; bits
    bswap   rax
    mov     rcx, rdx
    shl     rcx, 6
    mov     [rsp + FIN_PAD + rcx - 8], rax  ; the last 8 octets of the last block
    lea     rdi, [rbx + httpasm_sha256_ctx.state]
    lea     rsi, [rsp + FIN_PAD]
    call    ha_sha256_blocks
%assign i 0
%rep 8
    mov     eax, [rbx + httpasm_sha256_ctx.state + 4 * i]
    bswap   eax
    mov     [r12 + 4 * i], eax
  %assign i i + 1
%endrep
    pxor    xmm0, xmm0                      ; the wipes: h's 112 octets, the pad's 128
%assign i 0
%rep 7
    movdqu  [rbx + 16 * i], xmm0
  %assign i i + 1
%endrep
%assign i 0
%rep 8
    movdqa  [rsp + FIN_PAD + 16 * i], xmm0
  %assign i i + 1
%endrep
    add     rsp, FIN_FRAME + 8
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_sha256(const uint8_t *data, size_t n, uint8_t digest[32])
;   The digest of n octets at once: a running hash on the stack, fed once, finished (and so
;   wiped) before returning.
; -----------------------------------------------------------------------------
global httpasm_sha256:function (httpasm_sha256.end - httpasm_sha256)
align 16
httpasm_sha256:
    push    r12
    push    r13
    push    r14
    sub     rsp, httpasm_sha256_ctx_size        ; 112: three pushes + 112 keep rsp aligned
    mov     r12, rdi
    mov     r13, rsi
    mov     r14, rdx
    mov     rdi, rsp
    call    httpasm_sha256_init
    mov     rdi, rsp
    mov     rsi, r12
    mov     rdx, r13
    call    httpasm_sha256_update
    mov     rdi, rsp
    mov     rsi, r14
    call    httpasm_sha256_final
    add     rsp, httpasm_sha256_ctx_size
    pop     r14
    pop     r13
    pop     r12
    ret
.end:
