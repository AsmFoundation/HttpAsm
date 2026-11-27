; =============================================================================
; crypto/sha512.asm - SHA-512 and SHA-384 (FIPS 180-4 sections 5.1.2, 5.3.4, 5.3.5, 6.4, 6.5):
; the running hashes of the C ABI (httpasm_sha512_init and httpasm_sha384_init, the shared
; httpasm_sha512_update, httpasm_sha512_final and httpasm_sha384_final), their one-shot forms,
; and ha_sha512_blocks, the compression of whole 128-octet blocks. TLS 1.3's
; TLS_AES_256_GCM_SHA384, ECDSA over P-384 and Ed25519 (RFC 8032: SHA-512) are built on them.
;
; SHA-384 is SHA-512 started from another H(0) and cut to its first 48 octets, so both share
; one context layout (httpasm_sha512_ctx), one update and one compression.
;
; ha_sha512_blocks has two versions, chosen once per call (HA_CPU_PICK1), never per block:
;   v1 (any x86-64): FIPS 180-4 6.4.2's 80 rounds unrolled on 64-bit words, the working
;      variables a-h in r8-r15 renamed by the assembler from round to round (no moves between
;      rounds), the schedule's last 16 words on the stack, each W(t) computed just before the
;      round that first reads it. Each round adds K(t) + W(t) to h first, off the chain that
;      leads from e to the next e.
;   v3 (AVX2 with BMI2): the message schedule of two blocks at once in YMM registers (each
;      128-bit lane one block's pair of words: vpalignr and the shifts work per lane), stored as
;      W(t) + K(t) for both blocks while the first block's rounds run; the second block's rounds
;      then read their half of the same records. The rounds are scalar (a round's words depend
;      on the round before): rorx (BMI2) rotates without a copy, andn (BMI1) makes Ch's ~e & g,
;      Ch = (e & f) + (~e & g) and Maj = ((a ^ b) & (b ^ c)) ^ b are summed into h piece by
;      piece, a ^ b is kept as the next round's b ^ c, and Sigma0(a) is added to the next a one
;      round late, off the chain (the arrangement of OpenSSL's sha512-x86_64.pl "AVX2 + BMI"
;      code, by Andy Polyakov). A lone last block runs the same schedule with itself in both
;      lanes and skips the second rounds.
; The SHA512 extensions (vsha512rnds2 and its schedule instructions, HTTPASM_CPU_SHA512) are
; left until a CPU here can measure them. Constant time by construction: no branch or address
; depends on the data, only on the number of blocks.
; =============================================================================
default rel
%include "httpasm_core.inc"

section .rodata
align 64
; K: the 80 round constants (FIPS 180-4 4.2.3), the first 64 bits of the fractional parts of the
; cube roots of the first 80 primes (checked exactly, by integer cube roots, when this table was
; written), laid out in pairs for v3: record s (32 octets) is K(2s), K(2s+1) twice, once for
; each 128-bit lane, so one vpaddq adds a pair's constants to both blocks' words. v1 reads K(t)
; at 32 * (t >> 1) + 8 * (t & 1).
sha512_k2:
    dq 0x428a2f98d728ae22, 0x7137449123ef65cd, 0x428a2f98d728ae22, 0x7137449123ef65cd
    dq 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
    dq 0x3956c25bf348b538, 0x59f111f1b605d019, 0x3956c25bf348b538, 0x59f111f1b605d019
    dq 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118
    dq 0xd807aa98a3030242, 0x12835b0145706fbe, 0xd807aa98a3030242, 0x12835b0145706fbe
    dq 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
    dq 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1
    dq 0x9bdc06a725c71235, 0xc19bf174cf692694, 0x9bdc06a725c71235, 0xc19bf174cf692694
    dq 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3
    dq 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
    dq 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483
    dq 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
    dq 0x983e5152ee66dfab, 0xa831c66d2db43210, 0x983e5152ee66dfab, 0xa831c66d2db43210
    dq 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xb00327c898fb213f, 0xbf597fc7beef0ee4
    dq 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0xc6e00bf33da88fc2, 0xd5a79147930aa725
    dq 0x06ca6351e003826f, 0x142929670a0e6e70, 0x06ca6351e003826f, 0x142929670a0e6e70
    dq 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x27b70a8546d22ffc, 0x2e1b21385c26c926
    dq 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
    dq 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x650a73548baf63de, 0x766a0abb3c77b2a8
    dq 0x81c2c92e47edaee6, 0x92722c851482353b, 0x81c2c92e47edaee6, 0x92722c851482353b
    dq 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xa2bfe8a14cf10364, 0xa81a664bbc423001
    dq 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xc24b8b70d0f89791, 0xc76c51a30654be30
    dq 0xd192e819d6ef5218, 0xd69906245565a910, 0xd192e819d6ef5218, 0xd69906245565a910
    dq 0xf40e35855771202a, 0x106aa07032bbd1b8, 0xf40e35855771202a, 0x106aa07032bbd1b8
    dq 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53
    dq 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
    dq 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
    dq 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
    dq 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x748f82ee5defb2fc, 0x78a5636f43172f60
    dq 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x84c87814a1f0ab72, 0x8cc702081a6439ec
    dq 0x90befffa23631e28, 0xa4506cebde82bde9, 0x90befffa23631e28, 0xa4506cebde82bde9
    dq 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xbef9a3f7b2c67915, 0xc67178f2e372532b
    dq 0xca273eceea26619c, 0xd186b8c721c0c207, 0xca273eceea26619c, 0xd186b8c721c0c207
    dq 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
    dq 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x06f067aa72176fba, 0x0a637dc5a2c898a6
    dq 0x113f9804bef90dae, 0x1b710b35131c471b, 0x113f9804bef90dae, 0x1b710b35131c471b
    dq 0x28db77f523047d84, 0x32caab7b40c72493, 0x28db77f523047d84, 0x32caab7b40c72493
    dq 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
    dq 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
    dq 0x5fcb6fab3ad6faec, 0x6c44198c4a475817, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
; vpshufb masks for v3, the same 16 octets in both lanes: each qword's octets reversed (the
; message's big-endian words), and each qword rotated right by 8 bits (sigma0's ROTR8 as one
; byte shuffle instead of two shifts and an or).
align 32
sha512_bswap:
    db 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8
    db 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8
sha512_ror8:
    db 1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8
    db 1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8
; H(0) of SHA-512 (5.3.5): the square roots of the first 8 primes; of SHA-384 (5.3.4): of the
; 9th to the 16th. Aligned: sha512_start reads them with movdqa.
align 16
sha512_iv:
    dq 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
    dq 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
align 16
sha384_iv:
    dq 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939
    dq 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4

section .text

; -----------------------------------------------------------------------------
; SHA512_ROTATE: renames the working variables for the next round. A round leaves the next a
; in h's register and the next e in d's, so the next round's (a, b, c, d, e, f, g, h) are this
; round's registers (h, a, b, c, d, e, f, g). Eight renamings are a full turn: after a multiple
; of 8 rounds a-h are back in the registers they started in (SA-SH, set by each version).
; -----------------------------------------------------------------------------
%macro SHA512_ROTATE 0
  %xdefine ST SH
  %xdefine SH SG
  %xdefine SG SF
  %xdefine SF SE
  %xdefine SE SD
  %xdefine SD SC
  %xdefine SC SB
  %xdefine SB SA
  %xdefine SA ST
%endmacro

; -----------------------------------------------------------------------------
; v1's frame: the schedule's 16-word window, then the data's end (every register else holds a
; working variable, the block pointer, the state's address or a temporary).
; -----------------------------------------------------------------------------
S5_W        equ 0           ; W(t) for the last 16 t, slot t mod 16
S5_END      equ 128         ; the data's end: the loop's bound
S5_FRAME    equ 144         ; five pushes + 144 keep rsp 16-byte aligned (8 octets unused)

; -----------------------------------------------------------------------------
; SHA512_W t: W(t) for t >= 16 (FIPS 180-4 6.4.2 step 1) into the window slot t mod 16, which
; held W(t-16): W(t) = sigma1(W(t-2)) + W(t-7) + sigma0(W(t-15)) + W(t-16).
;   Clobbers rax, rcx, rdx, rsi.
; -----------------------------------------------------------------------------
%macro SHA512_W 1
    mov     rax, [rsp + S5_W + 8 * ((%1 - 15) & 15)]
    mov     rcx, rax
    ror     rax, 1
    mov     rdx, rcx
    ror     rdx, 8
    xor     rax, rdx
    shr     rcx, 7
    xor     rax, rcx                        ; sigma0(W(t-15)) = ROTR1 ^ ROTR8 ^ SHR7
    mov     rcx, [rsp + S5_W + 8 * ((%1 - 2) & 15)]
    mov     rdx, rcx
    ror     rcx, 19
    mov     rsi, rdx
    ror     rsi, 61
    xor     rcx, rsi
    shr     rdx, 6
    xor     rcx, rdx                        ; sigma1(W(t-2)) = ROTR19 ^ ROTR61 ^ SHR6
    add     rax, rcx
    add     rax, [rsp + S5_W + 8 * ((%1 - 7) & 15)]
    add     [rsp + S5_W + 8 * (%1 & 15)], rax
%endmacro

; -----------------------------------------------------------------------------
; SHA512_ROUND a, b, c, d, e, f, g, h, t: v1's round t (FIPS 180-4 6.4.2 step 3) on the working
; variables in the eight registers named, W(t) in its window slot. K(t) + W(t) go into h before
; anything that waits for e, so the chain from e to the next e is Sigma1's three steps and two
; additions. The next a is left in h's register and the next e in d's (SHA512_ROTATE).
;   Clobbers rax, rcx, rdx.
; -----------------------------------------------------------------------------
%macro SHA512_ROUND 9
    add     %8, [rel sha512_k2 + 32 * (%9 >> 1) + 8 * (%9 & 1)]
    add     %8, [rsp + S5_W + 8 * (%9 & 15)]   ; h + K(t) + W(t)
    mov     rax, %5
    ror     rax, 14
    mov     rcx, %5
    ror     rcx, 18
    xor     rax, rcx
    ror     rcx, 23                         ; 18 + 23 = 41
    xor     rax, rcx                        ; Sigma1(e) = ROTR14 ^ ROTR18 ^ ROTR41
    mov     rcx, %6
    xor     rcx, %7
    and     rcx, %5
    xor     rcx, %7                         ; Ch(e, f, g) = ((f ^ g) & e) ^ g
    add     %8, rcx
    add     %8, rax                         ; T1, in h's register: h is not read again
    add     %4, %8                          ; the next e: d + T1
    mov     rax, %1
    ror     rax, 28
    mov     rcx, %1
    ror     rcx, 34
    xor     rax, rcx
    ror     rcx, 5                          ; 34 + 5 = 39
    xor     rax, rcx                        ; Sigma0(a) = ROTR28 ^ ROTR34 ^ ROTR39
    mov     rcx, %1
    or      rcx, %2
    and     rcx, %3
    mov     rdx, %1
    and     rdx, %2
    or      rcx, rdx                        ; Maj(a, b, c) = ((a | b) & c) | (a & b)
    add     rax, rcx
    add     %8, rax                         ; the next a: T1 + T2
%endmacro

; -----------------------------------------------------------------------------
; v3's frame, rounded down to 32 octets below the pushes (vmovdqa stores); the caller's rsp is
; kept in it.
; -----------------------------------------------------------------------------
S5Y_WK      equ 0           ; W(t) + K(t) of the pair: 40 records of 32 octets, record s holding
                            ; t = 2s and 2s + 1 of the first block, then of the second
S5Y_STATE   equ 1280        ; the state's address
S5Y_DATA    equ 1288        ; the pair's first block
S5Y_END     equ 1296        ; the data's end
S5Y_RSP     equ 1304        ; rsp after the pushes, before the frame
S5Y_FRAME   equ 1312        ; rsp - 1312, rounded down to 32 octets

; v3's scalar temporaries (OpenSSL's a0-a4). Between rounds A1 holds Sigma0 of the last a (to
; add to the next a), A3 holds b ^ c, A4 holds f; A0 and A2 are free. A2 and A3 swap names every
; round (the a ^ b made in A2 is the next round's b ^ c), so a multiple of 2 rounds leaves them
; as they were.
%xdefine A0 rax
%xdefine A1 rbx
%xdefine A2 rcx
%xdefine A3 rdx
%xdefine A4 rsi

; -----------------------------------------------------------------------------
; SHA512X_ROUND a, b, c, d, e, f, g, h, wk: v3's round (FIPS 180-4 6.4.2 step 3) on the working
; variables in the eight registers named, W(t) + K(t) in memory at wk. On entry a still lacks
; Sigma0 of the round before's a (in A1): the first lea adds it, and this round's Sigma0(a)
; goes to A1 for the next. The chain from e to the next e: rorx, two xors, two leas.
;   Clobbers A0, A2, flags; updates A1, A3, A4 as described above.
; -----------------------------------------------------------------------------
%macro SHA512X_ROUND 9
    add     %8, %9                          ; h += W(t) + K(t)
    and     A4, %5                          ; e & f
    rorx    A0, %5, 41
    rorx    A2, %5, 18
    lea     %1, [%1 + A1]                   ; a += Sigma0 of the round before's a
    lea     %8, [%8 + A4]
    andn    A4, %5, %7                      ; ~e & g
    xor     A0, A2
    rorx    A1, %5, 14
    lea     %8, [%8 + A4]                   ; h += Ch(e, f, g) = (e & f) + (~e & g): disjoint bits
    xor     A0, A1                          ; Sigma1(e) = ROTR14 ^ ROTR18 ^ ROTR41
    mov     A2, %1
    rorx    A4, %1, 39
    lea     %8, [%8 + A0]                   ; h += Sigma1(e): T1
    xor     A2, %2                          ; a ^ b: the next round's b ^ c
    rorx    A1, %1, 34
    rorx    A0, %1, 28
    lea     %4, [%4 + %8]                   ; the next e: d + T1
    and     A3, A2                          ; (b ^ c) & (a ^ b)
    xor     A1, A4
    xor     A3, %2                          ; Maj(a, b, c) = ((a ^ b) & (b ^ c)) ^ b
    xor     A1, A0                          ; Sigma0(a) = ROTR28 ^ ROTR34 ^ ROTR39: the next round adds it
    lea     %8, [%8 + A3]                   ; the next a, but for Sigma0(a): T1 + Maj(a, b, c)
    mov     A4, %5                          ; e: the next round's f
  %xdefine ATMP A2
  %xdefine A2 A3
  %xdefine A3 ATMP
%endmacro

; -----------------------------------------------------------------------------
; SHA512X_SCHED k: v3's schedule step: W(t) and W(t+1) of both blocks (FIPS 180-4 6.4.2 step 1),
; from the window Y0-Y7 (Y0 = W(t-16), W(t-15) of each block ... Y7 = W(t-2), W(t-1)), into Y0's
; register, which then becomes Y7; W + K stored at rdi + 256 + 32 k (16 words ahead of the rounds
; reading rdi + 32 k), K from rbp + 256 + 32 k. Every operation works per 128-bit lane, that is
; per block. Clobbers ymm8-ymm11.
; -----------------------------------------------------------------------------
%macro SHA512X_SCHED 1
    vpalignr ymm8, Y1, Y0, 8                ; W(t-15), W(t-14)
    vpalignr ymm9, Y5, Y4, 8                ; W(t-7), W(t-6)
    vpsrlq  ymm10, ymm8, 1
    vpsllq  ymm11, ymm8, 63
    vpxor   ymm10, ymm10, ymm11             ; ROTR1
    vpsrlq  ymm11, ymm8, 7
    vpxor   ymm10, ymm10, ymm11
    vpshufb ymm11, ymm8, ymm15              ; ROTR8
    vpxor   ymm10, ymm10, ymm11             ; sigma0(W(t-15)), sigma0(W(t-14))
    vpaddq  Y0, Y0, ymm9
    vpaddq  Y0, Y0, ymm10
    vpsrlq  ymm8, Y7, 6
    vpsrlq  ymm9, Y7, 19
    vpsllq  ymm10, Y7, 45
    vpxor   ymm8, ymm8, ymm9
    vpxor   ymm8, ymm8, ymm10
    vpsrlq  ymm9, Y7, 61
    vpsllq  ymm10, Y7, 3
    vpxor   ymm8, ymm8, ymm9
    vpxor   ymm8, ymm8, ymm10               ; sigma1(W(t-2)), sigma1(W(t-1)): ROTR19 ^ ROTR61 ^ SHR6
    vpaddq  Y0, Y0, ymm8                    ; W(t), W(t+1)
    vpaddq  ymm9, Y0, [rbp + 256 + 32 * %1]
    vmovdqa [rdi + 256 + 32 * %1], ymm9
  %xdefine YT Y0
  %xdefine Y0 Y1
  %xdefine Y1 Y2
  %xdefine Y2 Y3
  %xdefine Y3 Y4
  %xdefine Y4 Y5
  %xdefine Y5 Y6
  %xdefine Y6 Y7
  %xdefine Y7 YT
%endmacro

; -----------------------------------------------------------------------------
; ha_sha512_blocks: SHA-512's compression of whole blocks into a state (FIPS 180-4 6.4.2), for
; SHA-384 as well.
;   In: rdi = the state (8 qwords, H0-H7), rsi = the blocks, rdx = how many (0 does nothing).
;   Out: the state updated. Keeps rbx, rbp, r12-r15 and rdi. Clobbers rax, rcx, rdx, rsi, r8-r11,
;   the flags, and (v3) ymm0-ymm15, whose upper halves vzeroupper clears.
;   Memory: reads rsi[0..128 * rdx); writes the state only.
; -----------------------------------------------------------------------------
global ha_sha512_blocks:function hidden (ha_sha512_blocks.end - ha_sha512_blocks)
align 16
ha_sha512_blocks:
    test    rdx, rdx
    jz      .nothing
    HA_CPU_PICK1 HTTPASM_CPU_V3, .v3
.v1:
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, S5_FRAME
    shl     rdx, 7
    add     rdx, rsi
    mov     [rsp + S5_END], rdx
    mov     rbp, rsi                        ; the block
    mov     r8, [rdi]
    mov     r9, [rdi + 8]
    mov     r10, [rdi + 16]
    mov     r11, [rdi + 24]
    mov     r12, [rdi + 32]
    mov     r13, [rdi + 40]
    mov     r14, [rdi + 48]
    mov     r15, [rdi + 56]
    ; The loop is aligned without padding inside it (the padding before .block is never run).
    jmp     .block
align 32
.block:
%xdefine SA r8
%xdefine SB r9
%xdefine SC r10
%xdefine SD r11
%xdefine SE r12
%xdefine SF r13
%xdefine SG r14
%xdefine SH r15
%assign t 0
%rep 80
  %if t < 16
    mov     rax, [rbp + 8 * t]
    bswap   rax                             ; W(t), t < 16: the block's word, big-endian
    mov     [rsp + S5_W + 8 * t], rax
  %else
    SHA512_W t
  %endif
    SHA512_ROUND SA, SB, SC, SD, SE, SF, SG, SH, t
    SHA512_ROTATE
  %assign t t + 1
%endrep
    ; 80 renamings are 10 full turns: a-h are in r8-r15 again. H(i) = H(i-1) + a..h (rdi, the
    ; state, is read by no round).
    add     r8, [rdi]
    mov     [rdi], r8
    add     r9, [rdi + 8]
    mov     [rdi + 8], r9
    add     r10, [rdi + 16]
    mov     [rdi + 16], r10
    add     r11, [rdi + 24]
    mov     [rdi + 24], r11
    add     r12, [rdi + 32]
    mov     [rdi + 32], r12
    add     r13, [rdi + 40]
    mov     [rdi + 40], r13
    add     r14, [rdi + 48]
    mov     [rdi + 48], r14
    add     r15, [rdi + 56]
    mov     [rdi + 56], r15
    add     rbp, 128
    cmp     rbp, [rsp + S5_END]
    jb      .block
    add     rsp, S5_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
.nothing:
    ret

    ; v3: pairs of blocks. Registers: a-h in r8-r15 (SA-SH), A0-A4 the temporaries, rdi the
    ; round records' walk, rbp the constants' walk (the schedule) or the walk's end (the plain
    ; rounds); ymm0-ymm7 the schedule's window (Y0-Y7), ymm8-ymm11 its temporaries, ymm14 and
    ; ymm15 the two shuffle masks.
.v3:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    mov     rax, rsp
    sub     rsp, S5Y_FRAME
    and     rsp, -32
    mov     [rsp + S5Y_RSP], rax
    mov     [rsp + S5Y_STATE], rdi
    mov     [rsp + S5Y_DATA], rsi
    shl     rdx, 7
    add     rdx, rsi
    mov     [rsp + S5Y_END], rdx
    vmovdqa ymm14, [rel sha512_bswap]
    vmovdqa ymm15, [rel sha512_ror8]
    mov     r8, [rdi]
    mov     r9, [rdi + 8]
    mov     r10, [rdi + 16]
    mov     r11, [rdi + 24]
    mov     r12, [rdi + 32]
    mov     r13, [rdi + 40]
    mov     r14, [rdi + 48]
    mov     r15, [rdi + 56]
%xdefine SA r8
%xdefine SB r9
%xdefine SC r10
%xdefine SD r11
%xdefine SE r12
%xdefine SF r13
%xdefine SG r14
%xdefine SH r15
%xdefine Y0 ymm0
%xdefine Y1 ymm1
%xdefine Y2 ymm2
%xdefine Y3 ymm3
%xdefine Y4 ymm4
%xdefine Y5 ymm5
%xdefine Y6 ymm6
%xdefine Y7 ymm7
.v3_pair:
    ; The pair's second block, or the first again when it is the data's last: its lane's
    ; schedule is then computed and never read.
    mov     rbp, [rsp + S5Y_DATA]
    lea     rax, [rbp + 128]
    cmp     rax, [rsp + S5Y_END]
    cmovae  rax, rbp
%assign i 0
%rep 8
    vmovdqu xmm%[i], [rbp + 16 * i]
    vinserti128 ymm%[i], ymm%[i], [rax + 16 * i], 1
    vpshufb ymm%[i], ymm%[i], ymm14         ; W(2i), W(2i+1) of each block
    vpaddq  ymm8, ymm%[i], [rel sha512_k2 + 32 * i]
    vmovdqa [rsp + S5Y_WK + 32 * i], ymm8
  %assign i i + 1
%endrep
    lea     rdi, [rsp + S5Y_WK]
    lea     rbp, [rel sha512_k2]
    xor     ebx, ebx                        ; A1: no Sigma0 waits before round 0
    mov     rdx, r9
    xor     rdx, r10                        ; A3: b ^ c
    mov     rsi, r13                        ; A4: f
    ; Rounds 0-63 of the first block, 16 an iteration, with the schedule of both blocks' words
    ; 16-79 (records 8-39), 8 steps an iteration, 16 words ahead of the rounds.
.v3_sched:
%assign k 0
%rep 8
    SHA512X_SCHED k
    SHA512X_ROUND SA, SB, SC, SD, SE, SF, SG, SH, [rdi + 32 * k]
    SHA512_ROTATE
    SHA512X_ROUND SA, SB, SC, SD, SE, SF, SG, SH, [rdi + 32 * k + 8]
    SHA512_ROTATE
  %assign k k + 1
%endrep
    add     rdi, 256
    add     rbp, 256
    lea     rax, [rel sha512_k2 + 1024]     ; A0 is free between rounds
    cmp     rbp, rax
    jb      .v3_sched
    lea     rbp, [rsp + S5Y_WK + 1280]      ; the first block's last 16 rounds: one iteration
    ; Rounds without schedule work, 16 an iteration, until rdi reaches rbp: the first block's
    ; 64-79, then (from .v3_second) the second block's 0-79 on the records' high halves.
.v3_plain:
%assign rnd 0
%rep 16
    SHA512X_ROUND SA, SB, SC, SD, SE, SF, SG, SH, [rdi + 32 * (rnd >> 1) + 8 * (rnd & 1)]
    SHA512_ROTATE
  %assign rnd rnd + 1
%endrep
    add     rdi, 256
    cmp     rdi, rbp
    jb      .v3_plain
    ; A block's 80 rounds are done (10 turns of the names: a-h in r8-r15 again).
    add     r8, rbx                         ; a's last Sigma0
    mov     rax, [rsp + S5Y_STATE]
    add     r8, [rax]
    mov     [rax], r8
    add     r9, [rax + 8]
    mov     [rax + 8], r9
    add     r10, [rax + 16]
    mov     [rax + 16], r10
    add     r11, [rax + 24]
    mov     [rax + 24], r11
    add     r12, [rax + 32]
    mov     [rax + 32], r12
    add     r13, [rax + 40]
    mov     [rax + 40], r13
    add     r14, [rax + 48]
    mov     [rax + 48], r14
    add     r15, [rax + 56]
    mov     [rax + 56], r15
    ; Which block ended: the walk stops at rsp + 1280 after the first block's records and at
    ; rsp + 1296 after the second's, and rsp is 32-byte aligned, so bit 4 of rdi tells them apart.
    test    dil, 16
    jnz     .v3_next
    mov     rax, [rsp + S5Y_DATA]
    add     rax, 128
    cmp     rax, [rsp + S5Y_END]
    jae     .v3_done                        ; the first block was the data's last
    lea     rdi, [rsp + S5Y_WK + 16]        ; the second block: the records' high halves
    lea     rbp, [rsp + S5Y_WK + 16 + 1280]
    xor     ebx, ebx
    mov     rdx, r9
    xor     rdx, r10
    mov     rsi, r13
    jmp     .v3_plain
.v3_next:
    mov     rax, [rsp + S5Y_DATA]
    add     rax, 256
    mov     [rsp + S5Y_DATA], rax
    cmp     rax, [rsp + S5Y_END]
    jb      .v3_pair
.v3_done:
    vzeroupper
    mov     rsp, [rsp + S5Y_RSP]
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; sha512_start: a new hash from an H(0) (SHA-512's or SHA-384's), nothing fed: all 208 octets.
;   In: rdi = h, rsi = the H(0) (8 qwords, 16-byte aligned). Clobbers rax, xmm0-xmm3.
; -----------------------------------------------------------------------------
align 16
sha512_start:
    movdqa  xmm0, [rsi]
    movdqa  xmm1, [rsi + 16]
    movdqa  xmm2, [rsi + 32]
    movdqa  xmm3, [rsi + 48]
    movdqu  [rdi + httpasm_sha512_ctx.state], xmm0
    movdqu  [rdi + httpasm_sha512_ctx.state + 16], xmm1
    movdqu  [rdi + httpasm_sha512_ctx.state + 32], xmm2
    movdqu  [rdi + httpasm_sha512_ctx.state + 48], xmm3
    xor     eax, eax
    mov     [rdi + httpasm_sha512_ctx.length], rax
    mov     [rdi + httpasm_sha512_ctx.buffered], rax    ; .buffered and .reserved
    ret

; -----------------------------------------------------------------------------
; void httpasm_sha512_init(httpasm_sha512_ctx *h), void httpasm_sha384_init(httpasm_sha512_ctx *h)
;   A new SHA-512 (or SHA-384) hash: writes all 208 octets of h.
; -----------------------------------------------------------------------------
global httpasm_sha512_init:function (httpasm_sha512_init.end - httpasm_sha512_init)
align 16
httpasm_sha512_init:
    lea     rsi, [rel sha512_iv]
    jmp     sha512_start
.end:

global httpasm_sha384_init:function (httpasm_sha384_init.end - httpasm_sha384_init)
align 16
httpasm_sha384_init:
    lea     rsi, [rel sha384_iv]
    jmp     sha512_start
.end:

; -----------------------------------------------------------------------------
; void httpasm_sha512_update(httpasm_sha512_ctx *h, const uint8_t *data, size_t n)
;   Feeds n octets to a SHA-512 or a SHA-384 hash (0 is allowed). Whole blocks are compressed
;   straight from data; only a partial block's octets are copied into h. The total fed must
;   stay below 2^61 octets (the length is counted in octets; the final shifts it to bits).
; -----------------------------------------------------------------------------
global httpasm_sha512_update:function (httpasm_sha512_update.end - httpasm_sha512_update)
align 16
httpasm_sha512_update:
    push    rbx
    push    r12
    push    r13                             ; three pushes: rsp 16-byte aligned for the calls
    mov     rbx, rdi                        ; h
    mov     r12, rsi                        ; the octets not taken yet
    mov     r13, rdx                        ; how many
    add     [rbx + httpasm_sha512_ctx.length], rdx
    mov     eax, [rbx + httpasm_sha512_ctx.buffered]
    test    eax, eax
    jz      .blocks
    ; A partial block waits: fill it, if the data can.
    mov     ecx, HTTPASM_SHA512_BLOCK
    sub     ecx, eax                        ; the octets it lacks (1-127)
    cmp     r13, rcx
    jb      .keep                           ; still not a block
    lea     rdi, [rbx + httpasm_sha512_ctx.buffer + rax]
    mov     rsi, r12
    call    ha_copy_short                   ; keeps rcx
    add     r12, rcx
    sub     r13, rcx
    lea     rdi, [rbx + httpasm_sha512_ctx.state]
    lea     rsi, [rbx + httpasm_sha512_ctx.buffer]
    mov     edx, 1
    call    ha_sha512_blocks
    mov     dword [rbx + httpasm_sha512_ctx.buffered], 0
.blocks:
    mov     rdx, r13
    shr     rdx, 7
    jz      .tail
    lea     rdi, [rbx + httpasm_sha512_ctx.state]
    mov     rsi, r12
    call    ha_sha512_blocks
    mov     rax, r13
    and     rax, -HTTPASM_SHA512_BLOCK
    add     r12, rax
    and     r13, HTTPASM_SHA512_BLOCK - 1
.tail:
    xor     eax, eax                        ; the buffer is empty here
.keep:                                      ; eax = octets buffered, r13 (< 128 - eax) to add
    lea     rdi, [rbx + httpasm_sha512_ctx.buffer + rax]
    mov     rsi, r12
    mov     rcx, r13
    call    ha_copy_short
    add     [rbx + httpasm_sha512_ctx.buffered], r13d
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; sha512_finish: the padding of FIPS 180-4 5.1.2 (0x80, zeros, the length in bits as 128 bits
; big-endian) in a zeroed stack pad, its last one or two blocks, then the first rdx octets of
; the state, big-endian (64 for SHA-512, 48 for SHA-384); h and the pad wiped after: they held
; the message's last octets (an HMAC key's padding, a TLS secret's).
;   In: rdi = h, rsi = the digest's destination, edx = its length (64 or 48).
;   Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
F5_PAD      equ 0           ; two blocks: the padding needs the second past 111 octets
F5_FRAME    equ 256         ; the pad; three pushes + 256 keep rsp 16-byte aligned (movdqa, calls)

align 16
sha512_finish:
    push    rbx
    push    r12
    push    r13
    sub     rsp, F5_FRAME
    mov     rbx, rdi
    mov     r12, rsi
    mov     r13d, edx
    pxor    xmm0, xmm0
%assign i 0
%rep 16
    movdqa  [rsp + F5_PAD + 16 * i], xmm0
  %assign i i + 1
%endrep
    lea     rdi, [rsp + F5_PAD]
    lea     rsi, [rbx + httpasm_sha512_ctx.buffer]
    mov     ecx, [rbx + httpasm_sha512_ctx.buffered]
    call    ha_copy_short                   ; keeps rcx
    mov     byte [rsp + F5_PAD + rcx], 0x80
    ; One block when the 16-octet length fits after the 0x80 (111 octets buffered at most).
    mov     edx, 1
    cmp     ecx, 112
    jb      .one_block
    mov     edx, 2
.one_block:
    mov     rax, [rbx + httpasm_sha512_ctx.length]
    mov     rcx, rax
    shl     rax, 3                          ; the length in bits: low 64 bits
    shr     rcx, 61                         ; and the high ones (0 below 2^61 octets)
    bswap   rax
    bswap   rcx
    mov     rsi, rdx
    shl     rsi, 7
    mov     [rsp + F5_PAD + rsi - 16], rcx  ; the last 16 octets of the last block, big-endian:
    mov     [rsp + F5_PAD + rsi - 8], rax   ; high half first
    lea     rdi, [rbx + httpasm_sha512_ctx.state]
    lea     rsi, [rsp + F5_PAD]
    call    ha_sha512_blocks
    ; The digest: the state's qwords big-endian, the first 6 or all 8.
    xor     ecx, ecx
.digest:
    mov     rax, [rbx + httpasm_sha512_ctx.state + rcx]
    bswap   rax
    mov     [r12 + rcx], rax
    add     ecx, 8
    cmp     ecx, r13d
    jb      .digest
    pxor    xmm0, xmm0                      ; the wipes: h's 208 octets, the pad's 256
%assign i 0
%rep 13
    movdqu  [rbx + 16 * i], xmm0
  %assign i i + 1
%endrep
%assign i 0
%rep 16
    movdqa  [rsp + F5_PAD + 16 * i], xmm0
  %assign i i + 1
%endrep
    add     rsp, F5_FRAME
    pop     r13
    pop     r12
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; void httpasm_sha512_final(httpasm_sha512_ctx *h, uint8_t digest[64])
; void httpasm_sha384_final(httpasm_sha512_ctx *h, uint8_t digest[48])
;   The digest of everything fed; then h is wiped to zeros. Which final is used decides the
;   digest's length only: finishing a SHA-384 hash with httpasm_sha512_final gives 64 octets of
;   neither digest.
; -----------------------------------------------------------------------------
global httpasm_sha512_final:function (httpasm_sha512_final.end - httpasm_sha512_final)
align 16
httpasm_sha512_final:
    mov     edx, HTTPASM_SHA512_DIGEST
    jmp     sha512_finish
.end:

global httpasm_sha384_final:function (httpasm_sha384_final.end - httpasm_sha384_final)
align 16
httpasm_sha384_final:
    mov     edx, HTTPASM_SHA384_DIGEST
    jmp     sha512_finish
.end:

; -----------------------------------------------------------------------------
; void httpasm_sha512(const uint8_t *data, size_t n, uint8_t digest[64])
; void httpasm_sha384(const uint8_t *data, size_t n, uint8_t digest[48])
;   The digest of n octets at once, through a running hash on the stack (wiped by the final).
;   Both pass rdi, rsi and rdx through to sha512_oneshot, with the H(0) in rcx and the digest's
;   length in r8d.
; -----------------------------------------------------------------------------
global httpasm_sha512:function (httpasm_sha512.end - httpasm_sha512)
align 16
httpasm_sha512:
    lea     rcx, [rel sha512_iv]
    mov     r8d, HTTPASM_SHA512_DIGEST
    jmp     sha512_oneshot
.end:

global httpasm_sha384:function (httpasm_sha384.end - httpasm_sha384)
align 16
httpasm_sha384:
    lea     rcx, [rel sha384_iv]
    mov     r8d, HTTPASM_SHA384_DIGEST
    jmp     sha512_oneshot
.end:

align 16
sha512_oneshot:
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, httpasm_sha512_ctx_size + 8    ; 208 + 8: four pushes + 216 keep rsp aligned
    mov     r12, rdi                        ; data
    mov     r13, rsi                        ; n
    mov     r14, rdx                        ; digest
    mov     r15d, r8d                       ; its length
    mov     rdi, rsp
    mov     rsi, rcx
    call    sha512_start
    mov     rdi, rsp
    mov     rsi, r12
    mov     rdx, r13
    call    httpasm_sha512_update
    mov     rdi, rsp
    mov     rsi, r14
    mov     edx, r15d
    call    sha512_finish
    add     rsp, httpasm_sha512_ctx_size + 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    ret
