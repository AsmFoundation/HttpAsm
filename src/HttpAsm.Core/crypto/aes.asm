; =============================================================================
; crypto/aes.asm - AES-128 and AES-256 encryption (FIPS 197): the key schedule (5.2), the
; cipher (5.1) one block at a time for the C ABI (httpasm_aes_init, httpasm_aes_encrypt_block)
; and eight blocks at a time for the modes built on it (crypto/gcm.asm's counter mode). Only
; encryption: GCM, CTR and QUIC's header protection never decrypt with the block cipher.
;
; Two versions, chosen per call (HA_CPU_PICK1 on HTTPASM_CPU_AESNI):
;   AES-NI   aesenc/aesenclast with the round keys of FIPS 197's schedule, as AES-NI takes
;            them; the schedule itself by aeskeygenassist.
;   v1       constant time, without a table: a lookup indexed by key or data would leak them
;            through the cache. The state of eight blocks is bitsliced over xmm0-xmm7 (SSE2
;            only): each 64-bit lane carries four blocks in the arrangement of BearSSL's
;            aes_ct64 (Thomas Pornin, MIT licence: its interleave, ortho, ShiftRows and
;            MixColumns as shifts within a lane), lane 0 blocks 0-3, lane 1 blocks 4-7, and
;            the S-box is Boyar and Peralta's circuit (include/generated/aes_sbox.inc, generated
;            and proven by specs/circuits.cs). Its schedule computes SubWord with that circuit.
;            Every branch and address depends on the key's length only.
; Both schedules are written into every key: the round keys as FIPS 197 lays them out, and
; v1's, compressed (two qwords a round, the ct64 form). A key made at one tier therefore works
; at every other, which httpasm_cpu_limit may switch to at any moment (cpu.inc).
; =============================================================================
default rel
%include "httpasm_core.inc"

section .rodata
align 16
; The S-box macro's all-ones operand (xnor gates), and the masks of the bitsliced code, each
; repeated over the two 64-bit lanes.
ha_aes_ones:    times 2 dq 0xFFFFFFFFFFFFFFFF
aes_m55:        times 2 dq 0x5555555555555555   ; ortho's exchanges of 1, 2 and 4 bits
aes_m33:        times 2 dq 0x3333333333333333
aes_m0f:        times 2 dq 0x0F0F0F0F0F0F0F0F
aes_m0000ffff:  times 2 dq 0x0000FFFF0000FFFF   ; interleave's spreads and gathers
aes_m00ff00ff:  times 2 dq 0x00FF00FF00FF00FF
aes_sr0:        times 2 dq 0x000000000000FFFF   ; ShiftRows: the parts of a lane that move
aes_sr1:        times 2 dq 0x00000000FFF00000   ;   >> 4
aes_sr2:        times 2 dq 0x00000000000F0000   ;   << 12
aes_sr3:        times 2 dq 0x0000FF0000000000   ;   >> 8
aes_sr4:        times 2 dq 0x000000FF00000000   ;   << 8
aes_sr5:        times 2 dq 0xF000000000000000   ;   >> 12
aes_sr6:        times 2 dq 0x0FFF000000000000   ;   << 4
aes_m1111:      times 2 dq 0x1111111111111111   ; the compressed schedule's four bit planes
aes_m2222:      times 2 dq 0x2222222222222222
aes_m4444:      times 2 dq 0x4444444444444444
aes_m8888:      times 2 dq 0x8888888888888888
; Rcon[i] (FIPS 197 5.2): x^(i-1) in GF(2^8), for the v1 schedule's ten rounds of words.
aes_rcon:       db 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36

section .text

%include "generated/aes_sbox.inc"

; -----------------------------------------------------------------------------
; AES_SWAPMOVE x, y, mask, s: exchanges the bits of x at (mask << s) with the bits of y at mask
; (x's moving down by s, y's up), one step of the bit-matrix transpose. Clobbers xmm8.
; -----------------------------------------------------------------------------
%macro AES_SWAPMOVE 4
    movdqa  xmm8, %1
    psrlq   xmm8, %4
    pxor    xmm8, %2
    pand    xmm8, [rel %3]                  ; t = ((x >> s) ^ y) & mask
    pxor    %2, xmm8                        ; y ^= t
    psllq   xmm8, %4
    pxor    %1, xmm8                        ; x ^= t << s
%endmacro

; -----------------------------------------------------------------------------
; AES_ORTHO: transposes the bits of xmm0-xmm7 in 8x8 blocks (each lane alike), between "eight
; words of a block's bytes" and "bit i of every byte in xmm i". Its own inverse. Clobbers xmm8.
; -----------------------------------------------------------------------------
%macro AES_ORTHO 0
    AES_SWAPMOVE xmm0, xmm1, aes_m55, 1
    AES_SWAPMOVE xmm2, xmm3, aes_m55, 1
    AES_SWAPMOVE xmm4, xmm5, aes_m55, 1
    AES_SWAPMOVE xmm6, xmm7, aes_m55, 1
    AES_SWAPMOVE xmm0, xmm2, aes_m33, 2
    AES_SWAPMOVE xmm1, xmm3, aes_m33, 2
    AES_SWAPMOVE xmm4, xmm6, aes_m33, 2
    AES_SWAPMOVE xmm5, xmm7, aes_m33, 2
    AES_SWAPMOVE xmm0, xmm4, aes_m0f, 4
    AES_SWAPMOVE xmm1, xmm5, aes_m0f, 4
    AES_SWAPMOVE xmm2, xmm6, aes_m0f, 4
    AES_SWAPMOVE xmm3, xmm7, aes_m0f, 4
%endmacro

; -----------------------------------------------------------------------------
; AES_SPREAD x, t: interleave's spread of the 32-bit word in each lane's low half: its two
; 16-bit halves to bits 0 and 32, then each one's octets to 0, 16 (and 32, 48). Clobbers t.
; AES_GATHER x, t: the reverse, the word back in each lane's low 32 bits (the high 32 bits are
; left with garbage the callers drop). Clobbers t.
; -----------------------------------------------------------------------------
%macro AES_SPREAD 2
    movdqa  %2, %1
    psllq   %2, 16
    por     %1, %2
    pand    %1, [rel aes_m0000ffff]
    movdqa  %2, %1
    psllq   %2, 8
    por     %1, %2
    pand    %1, [rel aes_m00ff00ff]
%endmacro

%macro AES_GATHER 2
    movdqa  %2, %1
    psrlq   %2, 8
    por     %1, %2
    pand    %1, [rel aes_m0000ffff]
    movdqa  %2, %1
    psrlq   %2, 16
    por     %1, %2
%endmacro

; -----------------------------------------------------------------------------
; AES_INTERLEAVE p, q, t1, t2, t3, zero: two blocks (p in lane 0, q in lane 1; both clobbered)
; to the two words of interleave_in, each lane per its block: t1 = q[j], p = q[j + 4]. zero is
; an all-zero register; t2, t3 are clobbered.
; -----------------------------------------------------------------------------
%macro AES_INTERLEAVE 6
    movdqa  %3, %1
    punpckldq %3, %2                        ; T = p0 q0 p1 q1
    punpckhdq %1, %2                        ; U = p2 q2 p3 q3
    movdqa  %4, %3
    punpckldq %4, %6                        ; X0: p0 in lane 0, q0 in lane 1 (zero-extended)
    punpckhdq %3, %6                        ; X1: p1, q1
    movdqa  %5, %1
    punpckldq %5, %6                        ; X2: p2, q2
    punpckhdq %1, %6                        ; X3: p3, q3
    AES_SPREAD %4, %2
    AES_SPREAD %3, %2
    AES_SPREAD %5, %2
    AES_SPREAD %1, %2
    psllq   %5, 8
    por     %4, %5                          ; X0 | X2 << 8
    psllq   %1, 8
    por     %3, %1                          ; X1 | X3 << 8
    movdqa  %1, %3
    movdqa  %3, %4
%endmacro

; -----------------------------------------------------------------------------
; AES_SHIFT_ROWS: ShiftRows (FIPS 197 5.1.2) on the bitsliced state xmm0-xmm7: in this
; arrangement a lane's four 16-bit parts rotate by 0, 4, 8 and 12 bits. Clobbers xmm8, xmm9.
; -----------------------------------------------------------------------------
%macro AES_SHIFT_ROWS 0
%assign i 0
%rep 8
    movdqa  xmm9, xmm%[i]
    pand    xmm9, [rel aes_sr0]
    movdqa  xmm8, xmm%[i]
    pand    xmm8, [rel aes_sr1]
    psrlq   xmm8, 4
    por     xmm9, xmm8
    movdqa  xmm8, xmm%[i]
    pand    xmm8, [rel aes_sr2]
    psllq   xmm8, 12
    por     xmm9, xmm8
    movdqa  xmm8, xmm%[i]
    pand    xmm8, [rel aes_sr3]
    psrlq   xmm8, 8
    por     xmm9, xmm8
    movdqa  xmm8, xmm%[i]
    pand    xmm8, [rel aes_sr4]
    psllq   xmm8, 8
    por     xmm9, xmm8
    movdqa  xmm8, xmm%[i]
    pand    xmm8, [rel aes_sr5]
    psrlq   xmm8, 12
    por     xmm9, xmm8
    pand    xmm%[i], [rel aes_sr6]
    psllq   xmm%[i], 4
    por     xmm%[i], xmm9
  %assign i i + 1
%endrep
%endmacro

; -----------------------------------------------------------------------------
; AES_MIX_COLUMNS: MixColumns (FIPS 197 5.1.3) on xmm0-xmm7. With r_i = q_i rotated by 16 bits
; in its lane and a_i = q_i ^ r_i: q_i' = a_(i-1) ^ r_i ^ ROTR32(a_i), with a_7 added for i = 0
; (in place of a_(i-1)), 1, 3 and 4 (the reduction by x^8 + x^4 + x^3 + x + 1). Clobbers xmm8-xmm15.
; -----------------------------------------------------------------------------
%macro AES_MIX_COLUMNS 0
%assign i 0
%rep 8
  %assign i8 i + 8
    pshuflw xmm%[i8], xmm%[i], 0x39
    pshufhw xmm%[i8], xmm%[i8], 0x39        ; r_i: each lane rotated right by 16
  %assign i i + 1
%endrep
%assign i 0
%rep 8
  %assign i8 i + 8
    pxor    xmm%[i], xmm%[i8]               ; a_i
  %assign i i + 1
%endrep
    pxor    xmm8, xmm7                      ; r0 ^ a7
    pxor    xmm9, xmm0
    pxor    xmm9, xmm7                      ; r1 ^ a0 ^ a7
    pxor    xmm10, xmm1                     ; r2 ^ a1
    pxor    xmm11, xmm2
    pxor    xmm11, xmm7                     ; r3 ^ a2 ^ a7
    pxor    xmm12, xmm3
    pxor    xmm12, xmm7                     ; r4 ^ a3 ^ a7
    pxor    xmm13, xmm4                     ; r5 ^ a4
    pxor    xmm14, xmm5                     ; r6 ^ a5
    pxor    xmm15, xmm6                     ; r7 ^ a6
%assign i 0
%rep 8
  %assign i8 i + 8
    pshufd  xmm%[i], xmm%[i], 0xB1          ; ROTR32(a_i): each lane's halves swapped
    pxor    xmm%[i], xmm%[i8]
  %assign i i + 1
%endrep
%endmacro

; -----------------------------------------------------------------------------
; AES_ADD_ROUND_KEY base: xmm i ^= [base + 16 i], i = 0-7 (an expanded v1 round key).
; -----------------------------------------------------------------------------
%macro AES_ADD_ROUND_KEY 1
%assign i 0
%rep 8
    pxor    xmm%[i], [%1 + 16 * i]
  %assign i i + 1
%endrep
%endmacro

; -----------------------------------------------------------------------------
; ha_aes_ct_encrypt8: eight blocks through AES, v1 (constant time).
;   In: rdi = the expanded round keys (ha_aes_ct_expand's: (rounds + 1) * 128 octets, 16-byte
;   aligned), esi = the rounds (10 or 14), rdx = the 128 input octets, rcx = the 128 output
;   octets (may equal rdx: every input is read before an output is written).
;   Keeps rdi, rsi, rdx, rcx and every callee-saved register. Clobbers rax, r8, xmm0-xmm15 and
;   the flags.
; -----------------------------------------------------------------------------
CT_SPILL    equ 0                           ; the S-box's spill slots
CT_FRAME    equ HA_AES_SBOX_SPILLS * 16 + 8 ; + 8: rsp 16-byte aligned (entry is 8 mod 16)

global ha_aes_ct_encrypt8:function hidden (ha_aes_ct_encrypt8.end - ha_aes_ct_encrypt8)
align 16
ha_aes_ct_encrypt8:
    sub     rsp, CT_FRAME
    ; The blocks to the bitsliced form: interleave block j with block j + 4, then transpose.
    pxor    xmm15, xmm15
%assign j 0
%rep 4
    movdqu  xmm12, [rdx + 16 * j]
    movdqu  xmm13, [rdx + 16 * (j + 4)]
    AES_INTERLEAVE xmm12, xmm13, xmm9, xmm10, xmm11, xmm15
  %assign j4 j + 4
    movdqa  xmm%[j], xmm9
    movdqa  xmm%[j4], xmm12
  %assign j j + 1
%endrep
    AES_ORTHO
    AES_ADD_ROUND_KEY rdi
    lea     rax, [rdi + 128]
    lea     r8d, [rsi - 1]                  ; the full rounds: 9 or 13
.round:
    HA_AES_SBOX_SSE2 CT_SPILL
    AES_SHIFT_ROWS
    AES_MIX_COLUMNS
    AES_ADD_ROUND_KEY rax
    add     rax, 128
    dec     r8d
    jnz     .round
    HA_AES_SBOX_SSE2 CT_SPILL               ; the last round: no MixColumns
    AES_SHIFT_ROWS
    AES_ADD_ROUND_KEY rax
    ; Back to blocks: transpose, then gather each pair of words into blocks j and j + 4.
    AES_ORTHO
%assign j 0
%rep 4
  %assign j4 j + 4
    movdqa  xmm8, xmm%[j]
    pand    xmm8, [rel aes_m00ff00ff]       ; x0
    movdqa  xmm9, xmm%[j4]
    pand    xmm9, [rel aes_m00ff00ff]       ; x1
    movdqa  xmm10, xmm%[j]
    psrlq   xmm10, 8
    pand    xmm10, [rel aes_m00ff00ff]      ; x2
    movdqa  xmm11, xmm%[j4]
    psrlq   xmm11, 8
    pand    xmm11, [rel aes_m00ff00ff]      ; x3
    AES_GATHER xmm8, xmm12
    AES_GATHER xmm9, xmm12
    AES_GATHER xmm10, xmm12
    AES_GATHER xmm11, xmm12
    movdqa  xmm12, xmm8
    punpckldq xmm12, xmm9                   ; x0 x1 of lane 0 (and garbage)
    movdqa  xmm13, xmm10
    punpckldq xmm13, xmm11                  ; x2 x3 of lane 0
    punpcklqdq xmm12, xmm13                 ; block j
    punpckhdq xmm8, xmm9                    ; x0 x1 of lane 1
    punpckhdq xmm10, xmm11                  ; x2 x3 of lane 1
    punpcklqdq xmm8, xmm10                  ; block j + 4
    movdqu  [rcx + 16 * j], xmm12
    movdqu  [rcx + 16 * (j + 4)], xmm8
  %assign j j + 1
%endrep
    add     rsp, CT_FRAME
    ret
.end:

; -----------------------------------------------------------------------------
; ha_aes_ct_expand: v1's round keys from a key's compressed schedule, as ha_aes_ct_encrypt8
; takes them: for each round, 8 words of 16 octets (each 64-bit word twice, once per lane).
;   In: rdi = the key (httpasm_aes_key), rsi = the destination ((rounds + 1) * 128 octets,
;   16-byte aligned). Keeps rdi and rsi. Clobbers rax, rcx, xmm0-xmm7 and the flags.
; -----------------------------------------------------------------------------
global ha_aes_ct_expand:function hidden (ha_aes_ct_expand.end - ha_aes_ct_expand)
align 16
ha_aes_ct_expand:
    mov     ecx, [rdi + httpasm_aes_key.rounds]
    inc     ecx                             ; round keys: 11 or 15
    xor     eax, eax                        ; the round key, times 16
.round_key:
    movdqu  xmm0, [rdi + httpasm_aes_key.ct + rax]
    pshufd  xmm1, xmm0, 0x44                ; its first word in both lanes
    pshufd  xmm0, xmm0, 0xEE                ; its second
    ; Each word: its four bit planes (bits k, k + 4, ...) spread to four bits each: the plane,
    ; shifted down to bit 0, times 15 (x << 4) - x.
%assign h 0
%rep 2
  %if h == 0
    %define AES_WORD xmm1
  %else
    %define AES_WORD xmm0
  %endif
  %assign k 0
  %rep 4
    movdqa  xmm2, AES_WORD
    %if k == 0
    pand    xmm2, [rel aes_m1111]
    %elif k == 1
    pand    xmm2, [rel aes_m2222]
    %elif k == 2
    pand    xmm2, [rel aes_m4444]
    %else
    pand    xmm2, [rel aes_m8888]
    %endif
    %if k > 0
    psrlq   xmm2, k
    %endif
    movdqa  xmm3, xmm2
    psllq   xmm3, 4
    psubq   xmm3, xmm2
    movdqa  [rsi + 8 * rax + 16 * (4 * h + k)], xmm3
    %assign k k + 1
  %endrep
  %assign h h + 1
%endrep
    add     eax, 16
    dec     ecx
    jnz     .round_key
    ret
.end:

; -----------------------------------------------------------------------------
; aes_ct_compress: v1's compressed schedule from the round keys at .round_keys (FIPS 197's
; words): two round keys at a time, each through interleave and the transpose with its two
; words repeated four times, then a bit plane of each copy kept (the ct64 form).
;   In: rdi = the key, its .round_keys and .rounds written. Out: .ct written.
;   Keeps rdi. Clobbers rax, rcx, rdx, xmm0-xmm15 and the flags.
;   The schedules have 11 and 15 round keys, odd counts: the loop always ends on a pair whose
;   second key does not exist (read from the octets after it, never written).
; -----------------------------------------------------------------------------
align 16
aes_ct_compress:
    mov     ecx, [rdi + httpasm_aes_key.rounds]   ; the last round key's number: 10 or 14
    xor     eax, eax                        ; the first of the pair, times 16
    pxor    xmm15, xmm15
.pair:
    movdqu  xmm12, [rdi + httpasm_aes_key.round_keys + rax]
    movdqu  xmm13, [rdi + httpasm_aes_key.round_keys + rax + 16] ; past the last: unused
    AES_INTERLEAVE xmm12, xmm13, xmm9, xmm10, xmm11, xmm15
    movdqa  xmm0, xmm9
    movdqa  xmm1, xmm9
    movdqa  xmm2, xmm9
    movdqa  xmm3, xmm9
    movdqa  xmm4, xmm12
    movdqa  xmm5, xmm12
    movdqa  xmm6, xmm12
    movdqa  xmm7, xmm12
    AES_ORTHO
    pand    xmm0, [rel aes_m1111]
    pand    xmm1, [rel aes_m2222]
    pand    xmm2, [rel aes_m4444]
    pand    xmm3, [rel aes_m8888]
    por     xmm0, xmm1
    por     xmm2, xmm3
    por     xmm0, xmm2                      ; the first words: this key in lane 0, the next in 1
    pand    xmm4, [rel aes_m1111]
    pand    xmm5, [rel aes_m2222]
    pand    xmm6, [rel aes_m4444]
    pand    xmm7, [rel aes_m8888]
    por     xmm4, xmm5
    por     xmm6, xmm7
    por     xmm4, xmm6                      ; the second words
    movdqa  xmm1, xmm0
    punpcklqdq xmm1, xmm4
    movdqu  [rdi + httpasm_aes_key.ct + rax], xmm1
    lea     edx, [rax + 16]
    shr     edx, 4                          ; the pair's second round key
    cmp     edx, ecx
    ja      .last                           ; it does not exist (AES-128: 11, AES-256: 15)
    punpckhqdq xmm0, xmm4
    movdqu  [rdi + httpasm_aes_key.ct + rax + 16], xmm0
    add     eax, 32
    jmp     .pair
.last:
    ret

; -----------------------------------------------------------------------------
; aes_sub_word: SubWord (FIPS 197 5.2), v1: the S-box on each octet of edi, through the
; bitsliced circuit (the word in lane 0's first slots, zeros elsewhere). Out: eax.
;   Keeps rdi. Clobbers xmm0-xmm15 and the flags.
; -----------------------------------------------------------------------------
SW_FRAME    equ HA_AES_SBOX_SPILLS * 16 + 8

align 16
aes_sub_word:
    sub     rsp, SW_FRAME
    movd    xmm0, edi
    pxor    xmm1, xmm1
    pxor    xmm2, xmm2
    pxor    xmm3, xmm3
    pxor    xmm4, xmm4
    pxor    xmm5, xmm5
    pxor    xmm6, xmm6
    pxor    xmm7, xmm7
    AES_ORTHO
    HA_AES_SBOX_SSE2 0
    AES_ORTHO
    movd    eax, xmm0
    add     rsp, SW_FRAME
    ret

; -----------------------------------------------------------------------------
; aes_schedule_v1: FIPS 197 5.2's key expansion with aes_sub_word, the words written to
; .round_keys as they come (little-endian words: the octets in order).
;   In: rdi = the key, rsi = the key octets, edx = Nk (4 or 8). Keeps rdi.
;   Clobbers rax, rcx, rdx, rsi, r8-r11, xmm0-xmm15 and the flags.
; -----------------------------------------------------------------------------
align 16
aes_schedule_v1:
    push    rbx
    push    r12
    push    r13
    mov     rbx, rdi                        ; the key
    mov     r12d, edx                       ; Nk
    ; w[0..Nk) = the key.
    xor     ecx, ecx
.copy:
    mov     eax, [rsi + 4 * rcx]
    mov     [rbx + httpasm_aes_key.round_keys + 4 * rcx], eax
    inc     ecx
    cmp     ecx, r12d
    jb      .copy
    ; i from Nk to 4 * (rounds + 1): 44 or 60 words.
    lea     r13d, [r12 + 6]                 ; rounds = Nk + 6
    lea     r13d, [4 * r13 + 4]             ; words
    mov     r8d, [rbx + httpasm_aes_key.round_keys + 4 * rcx - 4]   ; tmp = w[Nk - 1]
    xor     r9d, r9d                        ; j: i mod Nk
    xor     r10d, r10d                      ; the Rcon index
    mov     r11d, ecx                       ; i
.word:
    test    r9d, r9d
    jnz     .not_first
    ror     r8d, 8                          ; RotWord (the octets of a little-endian word)
    mov     edi, r8d
    call    aes_sub_word
    lea     rcx, [rel aes_rcon]
    movzx   ecx, byte [rcx + r10]
    xor     eax, ecx                        ; ^ Rcon in the word's first octet
    mov     r8d, eax
    inc     r10d
    jmp     .mix
.not_first:
    cmp     r12d, 8
    jne     .mix
    cmp     r9d, 4
    jne     .mix
    mov     edi, r8d                        ; Nk = 8, i mod 8 = 4: SubWord alone
    call    aes_sub_word
    mov     r8d, eax
.mix:
    mov     eax, r11d
    sub     eax, r12d
    xor     r8d, [rbx + httpasm_aes_key.round_keys + 4 * rax]   ; ^ w[i - Nk]
    mov     [rbx + httpasm_aes_key.round_keys + 4 * r11], r8d
    inc     r9d
    cmp     r9d, r12d
    jb      .next
    xor     r9d, r9d
.next:
    inc     r11d
    cmp     r11d, r13d
    jb      .word
    mov     rdi, rbx
    pop     r13
    pop     r12
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; AES_KEY_128 rcon / AES_KEY_256A rcon / AES_KEY_256B: one step of the key expansion with
; aeskeygenassist (xmm1 the previous round key or first half, xmm3 the second half; xmm2, xmm4
; clobbered): the words of a round key are each the xor of the previous key's words up to them,
; and the assist's word.
; -----------------------------------------------------------------------------
%macro AES_KEY_STEP 2                       ; key register, assist register (its word in all lanes)
    movdqa  xmm4, %1
    pslldq  xmm4, 4
    pxor    %1, xmm4
    pslldq  xmm4, 4
    pxor    %1, xmm4
    pslldq  xmm4, 4
    pxor    %1, xmm4
    pxor    %1, %2
%endmacro

; -----------------------------------------------------------------------------
; aes_schedule_ni: the same expansion with AES-NI's aeskeygenassist.
;   In: rdi = the key, rsi = the key octets, edx = Nk (4 or 8). Keeps rdi.
;   Clobbers xmm1-xmm4 and the flags.
; -----------------------------------------------------------------------------
align 16
aes_schedule_ni:
    movdqu  xmm1, [rsi]
    movdqu  [rdi + httpasm_aes_key.round_keys], xmm1
    cmp     edx, 8
    je      .k256
%assign rc 1
%assign r 1
%rep 10
    aeskeygenassist xmm2, xmm1, rc
    pshufd  xmm2, xmm2, 0xFF                ; SubWord(RotWord(w3)) ^ Rcon, in every lane
    AES_KEY_STEP xmm1, xmm2
    movdqu  [rdi + httpasm_aes_key.round_keys + 16 * r], xmm1
  %assign rc rc << 1
  %if rc > 0xFF
    %assign rc rc ^ 0x11B
  %endif
  %assign r r + 1
%endrep
    ret
.k256:
    movdqu  xmm3, [rsi + 16]
    movdqu  [rdi + httpasm_aes_key.round_keys + 16], xmm3
%assign rc 1
%assign r 2
%rep 7
    aeskeygenassist xmm2, xmm3, rc
    pshufd  xmm2, xmm2, 0xFF                ; SubWord(RotWord(w7)) ^ Rcon
    AES_KEY_STEP xmm1, xmm2
    movdqu  [rdi + httpasm_aes_key.round_keys + 16 * r], xmm1
  %if r < 14
    aeskeygenassist xmm2, xmm1, 0
    pshufd  xmm2, xmm2, 0xAA                ; SubWord(w3) alone
    AES_KEY_STEP xmm3, xmm2
    movdqu  [rdi + httpasm_aes_key.round_keys + 16 * (r + 1)], xmm3
  %endif
  %assign rc rc << 1
  %assign r r + 2
%endrep
    ret

; -----------------------------------------------------------------------------
; int httpasm_aes_init(httpasm_aes_key *k, const uint8_t *key, size_t length)
;   Expands a 16-octet (AES-128) or 32-octet (AES-256) key into both schedules. Returns 0, or
;   -1 for any other length (k untouched).
; -----------------------------------------------------------------------------
global httpasm_aes_init:function (httpasm_aes_init.end - httpasm_aes_init)
align 16
httpasm_aes_init:
    mov     eax, 10
    cmp     rdx, 16
    je      .length
    mov     eax, 14
    cmp     rdx, 32
    je      .length
    mov     eax, -1
    ret
.length:
    push    rbx
    mov     rbx, rdi
    mov     [rdi + httpasm_aes_key.rounds], eax
    xor     ecx, ecx
    mov     [rdi + httpasm_aes_key.reserved], rcx
    mov     [rdi + httpasm_aes_key.reserved + 8], ecx
    shr     edx, 2                          ; Nk
    HA_CPU_PICK1 HTTPASM_CPU_AESNI, .ni
    call    aes_schedule_v1
    jmp     .compress
.ni:
    call    aes_schedule_ni
.compress:
    mov     rdi, rbx
    call    aes_ct_compress
    pop     rbx
    xor     eax, eax
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_aes_encrypt_block(const httpasm_aes_key *k, const uint8_t in[16], uint8_t out[16])
;   One block (in and out may be the same octets). k need not be aligned: AES-NI's round keys
;   are loaded with movdqu; v1 expands its keys onto its own aligned stack.
; -----------------------------------------------------------------------------
EB_KEYS     equ 0                           ; v1: the expanded keys, 15 * 128 octets
EB_BLOCKS   equ EB_KEYS + 15 * 128          ; v1: eight blocks, the first one's
EB_FRAME    equ EB_BLOCKS + 128             ; three pushes and the frame keep rsp aligned

global httpasm_aes_encrypt_block:function (httpasm_aes_encrypt_block.end - httpasm_aes_encrypt_block)
align 16
httpasm_aes_encrypt_block:
    HA_CPU_PICK1 HTTPASM_CPU_AESNI, .ni
    push    rbx
    push    r12
    push    r13
    sub     rsp, EB_FRAME
    mov     rbx, rdi
    mov     r12, rdx                        ; out
    movdqu  xmm0, [rsi]
    pxor    xmm1, xmm1
    movdqa  [rsp + EB_BLOCKS], xmm0         ; the block in slot 0, zeros in the other seven
%assign i 1
%rep 7
    movdqa  [rsp + EB_BLOCKS + 16 * i], xmm1
  %assign i i + 1
%endrep
    lea     rsi, [rsp + EB_KEYS]
    call    ha_aes_ct_expand
    lea     rdi, [rsp + EB_KEYS]
    mov     esi, [rbx + httpasm_aes_key.rounds]
    lea     rdx, [rsp + EB_BLOCKS]
    mov     rcx, rdx
    call    ha_aes_ct_encrypt8
    movdqa  xmm0, [rsp + EB_BLOCKS]
    movdqu  [r12], xmm0
    ; The expanded keys and the block are secrets on the stack: wiped (a loop: the frame's
    ; size is an equ, which the coverage build's preprocessor cannot count a %rep with).
    pxor    xmm0, xmm0
    xor     eax, eax
.wipe:
    movdqa  [rsp + rax], xmm0
    add     eax, 16
    cmp     eax, EB_BLOCKS + 128
    jb      .wipe
    add     rsp, EB_FRAME
    pop     r13
    pop     r12
    pop     rbx
    ret
.ni:
    movdqu  xmm0, [rsi]
    movdqu  xmm1, [rdi + httpasm_aes_key.round_keys]
    pxor    xmm0, xmm1
%assign r 1
%rep 9
    movdqu  xmm1, [rdi + httpasm_aes_key.round_keys + 16 * r]
    aesenc  xmm0, xmm1
  %assign r r + 1
%endrep
    cmp     dword [rdi + httpasm_aes_key.rounds], 10
    je      .ni_last
%rep 4
    movdqu  xmm1, [rdi + httpasm_aes_key.round_keys + 16 * r]
    aesenc  xmm0, xmm1
  %assign r r + 1
%endrep
.ni_last:
    mov     eax, [rdi + httpasm_aes_key.rounds]
    shl     eax, 4
    movdqu  xmm1, [rdi + httpasm_aes_key.round_keys + rax]
    aesenclast xmm0, xmm1
    movdqu  [rdx], xmm0
    pxor    xmm1, xmm1                      ; the last round key
    ret
.end:
