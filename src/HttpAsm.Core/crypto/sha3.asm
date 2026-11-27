; =============================================================================
; crypto/sha3.asm - SHA-3 and SHAKE (FIPS 202): SHA3-224, SHA3-256, SHA3-384, SHA3-512 and the
; extendable-output functions SHAKE128 and SHAKE256, for ML-KEM (FIPS 203: SHA3-256 is H,
; SHA3-512 is G, SHAKE128 samples the matrix, SHAKE256 is the PRF and J) and RFC 10024's
; X25519MLKEM768: the C ABI's running hash (httpasm_sha3_224_init .. httpasm_shake256_init, the
; shared httpasm_sha3_update, httpasm_sha3_final and httpasm_shake_squeeze), the one-shot forms,
; and ha_keccak_f1600_v3 / _v1 and ha_keccak_absorb_v3 / _v1, the permutation and the
; absorption of whole blocks (hidden: ML-KEM's sampling calls them).
;
; Keccak-f[1600] (FIPS 202 3.3), 24 rounds of theta, rho, pi, chi and iota over 25 lanes of 64
; bits, lane (x, y) at 8 (x + 5 y) of the state, in two versions chosen once per call:
;   v3 (BMI1 and BMI2, with v3): rorx rotates into another register without touching the flags,
;      andn makes chi's ~b & c in one instruction;
;   v1 (any x86-64): rol in place, chi's ~b & c by a copy, not and and.
; A round, the same in both: theta's column parities C[x] in five registers, D[x] = C[x - 1] ^
; rol(C[x + 1], 1) in five more, then each output row Y's five lanes B[X] = rol(A[x, y] ^ D[x],
; r[x][y]) read straight from their places before pi, (x, y) = ((X + 3 Y) mod 5, X) (pi's
; inverse), and chi's E[X, Y] = B[X] ^ (~B[X + 1] & B[X + 2]) stored, iota joining E[0, 0]: 14
; registers, so nothing spills. The state alternates between its home and a 200-octet copy on
; the stack, one round each way (24 rounds: it ends at home); the copy is wiped after. Measured
; (scratchpad sha3/kf.asm, 200,000 permutations, pinned): v3 262.5 ns (about 774 cycles: 32 a
; round, against a floor near 26 for its 130 ALU operations on five ports), v1 336.7 ns;
; OpenSSL 3.0.13's SHA3-256 of 64 KiB runs at about 318 ns a block.
;
; No constant is typed in: the round constants come from FIPS 202 Algorithm 5's LFSR and rho's
; offsets from section 3.2.2's walk, both computed here by the preprocessor (checked against
; FIPS 202's tables when written; every test vector depends on them).
;
; The sponge (FIPS 202 4): absorbing XORs the input into the state's first rate octets (no
; buffer: a partial block's octets wait in the state itself, .position counting them) and
; permutes at each full block; the padding is the suffix at .position (0x06: SHA-3's 01 then
; pad10*1's first 1; 0x1F: SHAKE's 1111 then the same 1) and 0x80 in the block's last octet,
; then the state is squeezed rate octets at a time. Constant time by construction: no branch or
; address depends on the data, only on lengths.
; =============================================================================
default rel
%include "httpasm_core.inc"

section .rodata
align 64
; The 24 round constants RC[i] (FIPS 202 3.2.5): bit 2^j - 1 of RC[i] is rc(j + 7 i), rc(t) the
; output of Algorithm 5's LFSR (x^8 + x^6 + x^5 + x^4 + 1) after t steps from R = 1. t runs 0..167
; in order here, so the LFSR is stepped once per bit: R shifted up, and 0x171 (the polynomial,
; its x^8 term clearing bit 8) XORed when bit 8 came out set.
keccak_rc:
%assign kr_lfsr 1
%rep 24
  %assign kr_c 0
  %assign kr_j 0
  %rep 7
    %assign kr_c kr_c | ((kr_lfsr & 1) << ((1 << kr_j) - 1))
    %assign kr_lfsr kr_lfsr << 1
    %if kr_lfsr & 0x100
      %assign kr_lfsr kr_lfsr ^ 0x171
    %endif
    %assign kr_j kr_j + 1
  %endrep
    dq          kr_c
%endrep

section .text

; rho's offsets (FIPS 202 3.2.2): r[0][0] = 0; from (x, y) = (1, 0), the t-th lane of the walk
; (x, y) -> (y, 2 x + 3 y) (t = 0..23) rotates by (t + 1)(t + 2) / 2 mod 64. As KR_x_y.
%assign KR_0_0 0
%assign kw_x 1
%assign kw_y 0
%assign kw_t 0
%rep 24
  %assign KR_%[kw_x]_%[kw_y] ((kw_t + 1) * (kw_t + 2) / 2) % 64
  %assign kw_nx kw_y
  %assign kw_ny (2 * kw_x + 3 * kw_y) % 5
  %assign kw_x kw_nx
  %assign kw_y kw_ny
  %assign kw_t kw_t + 1
%endrep

; The registers of a round: D[x] by x, B[X] (and theta's C[X] before them) by X; r13 is chi's
; temporary, r14 walks the round constants, r15 counts the round pairs.
%define KD0 r8
%define KD1 r9
%define KD2 r10
%define KD3 r11
%define KD4 r12
%define KB0 rax
%define KB1 rbx
%define KB2 rcx
%define KB3 rdx
%define KB4 rbp

; K_LANE v, dst, x, y, src: dst = rol(lane (x, y) at src ^ D[x], r[x][y]) (no rotation for 0).
%macro K_LANE 5
    mov         %2, [%5 + 8 * (%3 + 5 * %4)]
    xor         %2, KD%3
  %assign kl_r KR_%3_%4
  %if kl_r != 0
    %ifidn %1, v3
    rorx        %2, %2, 64 - kl_r
    %else
    rol         %2, kl_r
    %endif
  %endif
%endmacro

; K_CHI v, a, b, c, dst, X, Y: lane (X, Y) at dst = a ^ (~b & c); iota's constant joins lane
; (0, 0) from [r14].
%macro K_CHI 7
  %ifidn %1, v3
    andn        r13, %3, %4
  %else
    mov         r13, %3
    not         r13
    and         r13, %4
  %endif
    xor         r13, %2
  %if %6 == 0 && %7 == 0
    xor         r13, [r14]
  %endif
    mov         [%5 + 8 * (%6 + 5 * %7)], r13
%endmacro

; K_ROUND v, src, dst: one round from the state at src into dst (both base registers).
%macro K_ROUND 3
    ; theta's column parities C[x] into KB0..KB4
  %assign kx 0
  %rep 5
    mov         KB%[kx], [%2 + 8 * kx]
    xor         KB%[kx], [%2 + 8 * (kx + 5)]
    xor         KB%[kx], [%2 + 8 * (kx + 10)]
    xor         KB%[kx], [%2 + 8 * (kx + 15)]
    xor         KB%[kx], [%2 + 8 * (kx + 20)]
    %assign kx kx + 1
  %endrep
    ; D[x] = C[x - 1] ^ rol(C[x + 1], 1)
  %ifidn %1, v3
    rorx        KD0, KB1, 63
    rorx        KD1, KB2, 63
    rorx        KD2, KB3, 63
    rorx        KD3, KB4, 63
    rorx        KD4, KB0, 63
  %else
    mov         KD0, KB1
    rol         KD0, 1
    mov         KD1, KB2
    rol         KD1, 1
    mov         KD2, KB3
    rol         KD2, 1
    mov         KD3, KB4
    rol         KD3, 1
    mov         KD4, KB0
    rol         KD4, 1
  %endif
    xor         KD0, KB4
    xor         KD1, KB0
    xor         KD2, KB1
    xor         KD3, KB2
    xor         KD4, KB3
    ; rho, pi, chi and iota, output row by output row
  %assign kY 0
  %rep 5
    %assign kX 0
    %rep 5
      %assign ksx (kX + 3 * kY) % 5
      K_LANE    %1, KB%[kX], %[ksx], %[kX], %2
      %assign kX kX + 1
    %endrep
    K_CHI       %1, KB0, KB1, KB2, %3, 0, kY
    K_CHI       %1, KB1, KB2, KB3, %3, 1, kY
    K_CHI       %1, KB2, KB3, KB4, %3, 2, kY
    K_CHI       %1, KB3, KB4, KB0, %3, 3, kY
    K_CHI       %1, KB4, KB0, KB1, %3, 4, kY
    %assign kY kY + 1
  %endrep
    add         r14, 8
%endmacro

; =============================================================================
; SHA3_ROUTINES v: every routine of one version.
; =============================================================================
%macro SHA3_ROUTINES 1

; -----------------------------------------------------------------------------
; ha_keccak_f1600_v: Keccak-f[1600] in place.
;   In: rdi = the state (25 qwords, any alignment). Keeps rbx, rbp, r12-r15 and rdi (SysV);
;   clobbers rax, rcx, rdx, rsi, r8-r11 and the flags.
;   Memory: the state; 200 octets of stack (the other copy), wiped before it returns: it held the
;   state's last round but one (a secret seed's or key's, under ML-KEM).
; -----------------------------------------------------------------------------
global ha_keccak_f1600_%1:function hidden (ha_keccak_f1600_%1.end - ha_keccak_f1600_%1)
align 16
ha_keccak_f1600_%1:
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    sub         rsp, 200 + 8
    lea         r14, [rel keccak_rc]
    mov         r15d, 12
.pair:
    K_ROUND     %1, rdi, rsp
    K_ROUND     %1, rsp, rdi
    dec         r15d
    jnz         .pair
    xor         eax, eax                    ; the stack copy wiped
  %assign kq 0
  %rep 25
    mov         [rsp + 8 * kq], rax
    %assign kq kq + 1
  %endrep
    add         rsp, 200 + 8
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_keccak_absorb_v: whole blocks XORed into the state's first rate octets, each followed by
; the permutation.
;   In: rdi = the state, rsi = the blocks, rdx = how many (0 does nothing), ecx = the rate in
;   qwords (9, 13, 17, 18 or 21; any count from 1 to 25). Out: rsi past the blocks. Keeps rbx,
;   rbp, r12-r15 and rdi; clobbers rax, rcx, rdx, r8-r11 and the flags.
;   Memory: reads rsi[0..8 rcx rdx), nothing past.
; -----------------------------------------------------------------------------
global ha_keccak_absorb_%1:function hidden (ha_keccak_absorb_%1.end - ha_keccak_absorb_%1)
align 16
ha_keccak_absorb_%1:
    test        rdx, rdx
    jz          .none
    push        rbx
    push        r12
    push        r13
    mov         rbx, rdx                    ; blocks left
    mov         r12d, ecx                   ; the rate in qwords
    mov         r13, rsi                    ; the next block
.block:
    xor         ecx, ecx
.xor:
    mov         rax, [r13 + 8 * rcx]
    xor         [rdi + 8 * rcx], rax
    inc         ecx
    cmp         ecx, r12d
    jb          .xor
    lea         r13, [r13 + 8 * rcx]
    call        ha_keccak_f1600_%1          ; (keeps rdi)
    dec         rbx
    jnz         .block
    mov         rsi, r13
    pop         r13
    pop         r12
    pop         rbx
.none:
    ret
.end:

; -----------------------------------------------------------------------------
; sha3_update_v: httpasm_sha3_update's work: rdi = h, rsi = data, rdx = n. A partial block's
; octets are XORed into the state at .position; whole blocks go straight from data.
; -----------------------------------------------------------------------------
align 16
sha3_update_%1:
    test        rdx, rdx
    jz          .none
    push        rbx
    push        r12
    push        r13
    push        r14
    mov         rbx, rdi                    ; h
    mov         r12, rsi                    ; the octets not taken yet
    mov         r13, rdx                    ; how many
    mov         r14d, [rbx + httpasm_sha3_ctx.rate]
    mov         eax, [rbx + httpasm_sha3_ctx.position]
    test        eax, eax
    jz          .blocks
    ; A partial block waits: fill it, if the data can.
    mov         ecx, r14d
    sub         ecx, eax                    ; the octets it lacks
    cmp         r13, rcx
    jb          .keep                       ; still not a block
    lea         rdi, [rbx + rax]
    mov         rsi, r12
    sub         r13, rcx
    add         r12, rcx
    call        sha3_xor_short
    mov         rdi, rbx
    call        ha_keccak_f1600_%1
.blocks:
    mov         rax, r13                    ; whole blocks: n / rate of them
    xor         edx, edx
    div         r14                         ; (once a call, on the length: not the data)
    mov         r13, rdx                    ; n mod rate octets remain after them
    mov         rdi, rbx
    mov         rsi, r12
    mov         rdx, rax
    mov         ecx, r14d
    shr         ecx, 3
    call        ha_keccak_absorb_%1         ; rsi past the blocks
    mov         r12, rsi
    xor         eax, eax                    ; the rest at position 0
.keep:                                      ; eax = the position, r13 (< rate - eax) to XOR there
    lea         ecx, [rax + r13]
    mov         [rbx + httpasm_sha3_ctx.position], ecx
    lea         rdi, [rbx + rax]
    mov         rsi, r12
    mov         rcx, r13
    call        sha3_xor_short
    pop         r14
    pop         r13
    pop         r12
    pop         rbx
.none:
    ret

; -----------------------------------------------------------------------------
; sha3_squeeze_v: httpasm_shake_squeeze's work (and the finals'): rdi = h, rsi = out, rdx = n.
; The padding first, once (.squeezing then 1); then rate octets a block, permuting between.
; -----------------------------------------------------------------------------
align 16
sha3_squeeze_%1:
    push        rbx
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rbx, rdi                    ; h
    mov         r12, rsi                    ; out
    mov         r13, rdx                    ; octets still wanted
    mov         r14d, [rbx + httpasm_sha3_ctx.rate]
    cmp         byte [rbx + httpasm_sha3_ctx.squeezing], 0
    jne         .more
    ; pad10*1 after the domain bits: the suffix at .position, 0x80 in the block's last octet
    ; (the same octet when one octet of the block is left: suffix ^ 0x80, as FIPS 202 B.2 says)
    mov         eax, [rbx + httpasm_sha3_ctx.position]
    movzx       ecx, byte [rbx + httpasm_sha3_ctx.suffix]
    xor         [rbx + rax], cl
    xor         byte [rbx + r14 - 1], 0x80
    mov         rdi, rbx
    call        ha_keccak_f1600_%1
    mov         dword [rbx + httpasm_sha3_ctx.position], 0
    mov         byte [rbx + httpasm_sha3_ctx.squeezing], 1
.more:
    test        r13, r13
    jz          .done
    mov         eax, [rbx + httpasm_sha3_ctx.position]
    cmp         eax, r14d
    jb          .copy
    mov         rdi, rbx                    ; the block is spent: the next one
    call        ha_keccak_f1600_%1
    xor         eax, eax
.copy:
    mov         r15d, r14d
    sub         r15d, eax                   ; octets left in the block
    cmp         r13, r15
    cmovb       r15, r13                    ; take the fewer
    lea         ecx, [rax + r15]
    mov         [rbx + httpasm_sha3_ctx.position], ecx
    lea         rsi, [rbx + rax]
    mov         rdi, r12
    mov         rcx, r15
    call        ha_copy_short
    add         r12, r15
    sub         r13, r15
    jmp         .more
.done:
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbx
    ret

; -----------------------------------------------------------------------------
; sha3_final_v: httpasm_sha3_final's work: rdi = h, rsi = digest. (200 - rate) / 2 octets
; squeezed (the SHA-3 digest's length for its rate: 28, 32, 48, 64; SHAKE128's 16 and
; SHAKE256's 32), then h wiped.
; -----------------------------------------------------------------------------
align 16
sha3_final_%1:
    push        rbx
    mov         rbx, rdi
    mov         edx, 200
    sub         edx, [rdi + httpasm_sha3_ctx.rate]
    shr         edx, 1
    call        sha3_squeeze_%1
    mov         rdi, rbx
    call        sha3_wipe
    pop         rbx
    ret
%endmacro

; -----------------------------------------------------------------------------
; sha3_xor_short: rcx octets of rsi XORed into rdi (qwords, then single octets): a partial
; block's. Memory: reads rsi[0..rcx), reads and writes rdi[0..rcx), nothing past either.
; Keeps every register but rax, rcx, rsi, rdi and the flags.
; -----------------------------------------------------------------------------
align 16
sha3_xor_short:
    cmp         rcx, 8
    jb          .octets
.qword:
    mov         rax, [rsi]
    xor         [rdi], rax
    add         rsi, 8
    add         rdi, 8
    sub         rcx, 8
    cmp         rcx, 8
    jae         .qword
.octets:
    test        rcx, rcx
    jz          .done
.octet:
    mov         al, [rsi]
    xor         [rdi], al
    inc         rsi
    inc         rdi
    dec         rcx
    jnz         .octet
.done:
    ret

; -----------------------------------------------------------------------------
; sha3_wipe: rdi = h, all 216 octets zeroed (the state held the message's last block): 13
; stores of 16 and one of 8. The counts are literal (the preprocessor cannot read a struc's
; size): httpasm_abi.inc's httpasm_sha3_ctx is 216 octets, and Sha3Tests holds struct size 20
; to it. Clobbers xmm0.
; -----------------------------------------------------------------------------
align 16
sha3_wipe:
    pxor        xmm0, xmm0
  %assign kq 0
  %rep 13
    movdqu      [rdi + 16 * kq], xmm0
    %assign kq kq + 1
  %endrep
    movq        [rdi + 208], xmm0
    ret

SHA3_ROUTINES v3
SHA3_ROUTINES v1

; =============================================================================
; The C ABI.
; =============================================================================

; sha3_start: rdi = h, esi = the rate in octets, edx = the suffix: the state zeroed, the sponge
; at the start of absorbing. Clobbers rax, xmm0.
align 16
sha3_start:
    call        sha3_wipe
    mov         [rdi + httpasm_sha3_ctx.rate], esi
    mov         [rdi + httpasm_sha3_ctx.suffix], dl
    ret

; -----------------------------------------------------------------------------
; void httpasm_sha3_224_init(httpasm_sha3_ctx *h) (and _256, _384, _512, httpasm_shake128_init,
; httpasm_shake256_init)
;   A new hash or XOF: writes all 216 octets of h. The rate is 200 octets less twice the
;   security strength's (FIPS 202 6.1, 6.2): 144, 136, 104, 72; SHAKE128 168, SHAKE256 136.
; -----------------------------------------------------------------------------
%macro SHA3_INIT 3
global %1:function (%1.end - %1)
align 16
%1:
    mov         esi, %2
    mov         edx, %3
    jmp         sha3_start
.end:
%endmacro

SHA3_INIT httpasm_sha3_224_init, 144, 0x06
SHA3_INIT httpasm_sha3_256_init, 136, 0x06
SHA3_INIT httpasm_sha3_384_init, 104, 0x06
SHA3_INIT httpasm_sha3_512_init, 72, 0x06
SHA3_INIT httpasm_shake128_init, 168, 0x1F
SHA3_INIT httpasm_shake256_init, 136, 0x1F

; -----------------------------------------------------------------------------
; void httpasm_sha3_update(httpasm_sha3_ctx *h, const uint8_t *data, size_t n)
;   Feeds n octets (0 is allowed) to any of the six. Whole blocks are absorbed straight from
;   data; a partial block's octets are XORed into the state at once (there is no buffer).
; -----------------------------------------------------------------------------
global httpasm_sha3_update:function (httpasm_sha3_update.end - httpasm_sha3_update)
align 16
httpasm_sha3_update:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_BMI2, .v3
    jmp         sha3_update_v1              ; (tail calls: the version returns to our caller)
.v3:
    jmp         sha3_update_v3
.end:

; -----------------------------------------------------------------------------
; void httpasm_sha3_final(httpasm_sha3_ctx *h, uint8_t *digest)
;   The digest of everything fed, (200 - rate) / 2 octets: 28, 32, 48 or 64 for SHA3-224 to
;   SHA3-512 (on a SHAKE context: SHAKE128's first 16 octets, SHAKE256's first 32); then h is
;   wiped to zeros.
; -----------------------------------------------------------------------------
global httpasm_sha3_final:function (httpasm_sha3_final.end - httpasm_sha3_final)
align 16
httpasm_sha3_final:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_BMI2, .v3
    jmp         sha3_final_v1
.v3:
    jmp         sha3_final_v3
.end:

; -----------------------------------------------------------------------------
; void httpasm_shake_squeeze(httpasm_sha3_ctx *h, uint8_t *out, size_t n)
;   The next n octets of the output (the first call pads the input; later calls continue the
;   same stream, so pieces of any sizes give the octets one call would). After it, h takes no
;   more input. h is not wiped (more output may follow): zero it when done if the input was
;   secret.
; -----------------------------------------------------------------------------
global httpasm_shake_squeeze:function (httpasm_shake_squeeze.end - httpasm_shake_squeeze)
align 16
httpasm_shake_squeeze:
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_BMI2, .v3
    jmp         sha3_squeeze_v1
.v3:
    jmp         sha3_squeeze_v3
.end:

; -----------------------------------------------------------------------------
; void httpasm_sha3_224(const uint8_t *data, size_t n, uint8_t digest[28]) (and _256, _384,
; _512); void httpasm_shake128(const uint8_t *data, size_t n, uint8_t *out, size_t out_n) (and
; httpasm_shake256)
;   The whole computation at once, through a context on the stack, wiped after. Each passes its
;   arguments to sha3_oneshot with the output's length in rcx, the rate in r8d and the suffix in
;   r9d.
; -----------------------------------------------------------------------------
%macro SHA3_ONESHOT 4
global %1:function (%1.end - %1)
align 16
%1:
  %if %2
    mov         ecx, %2
  %endif
    mov         r8d, %3
    mov         r9d, %4
    jmp         sha3_oneshot
.end:
%endmacro

SHA3_ONESHOT httpasm_sha3_224, 28, 144, 0x06
SHA3_ONESHOT httpasm_sha3_256, 32, 136, 0x06
SHA3_ONESHOT httpasm_sha3_384, 48, 104, 0x06
SHA3_ONESHOT httpasm_sha3_512, 64, 72, 0x06
SHA3_ONESHOT httpasm_shake128, 0, 168, 0x1F         ; (rcx: the caller's out_n)
SHA3_ONESHOT httpasm_shake256, 0, 136, 0x1F

; sha3_oneshot: rdi = data, rsi = n, rdx = out, rcx = out's length, r8d = rate, r9d = suffix.
O3_CTX      equ 0
O3_FRAME    equ httpasm_sha3_ctx_size + 8       ; 216 + 8: five pushes + 224 keep rsp aligned

align 16
sha3_oneshot:
    push        rbx
    push        r12
    push        r13
    push        r14
    push        r15
    sub         rsp, O3_FRAME
    mov         r12, rdi                    ; data
    mov         r13, rsi                    ; n
    mov         r14, rdx                    ; out
    mov         r15, rcx                    ; its length
    lea         rdi, [rsp + O3_CTX]
    mov         esi, r8d
    mov         edx, r9d
    call        sha3_start
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_BMI2, .v3
    lea         rdi, [rsp + O3_CTX]
    mov         rsi, r12
    mov         rdx, r13
    call        sha3_update_v1
    lea         rdi, [rsp + O3_CTX]
    mov         rsi, r14
    mov         rdx, r15
    call        sha3_squeeze_v1
    jmp         .wipe
.v3:
    lea         rdi, [rsp + O3_CTX]
    mov         rsi, r12
    mov         rdx, r13
    call        sha3_update_v3
    lea         rdi, [rsp + O3_CTX]
    mov         rsi, r14
    mov         rdx, r15
    call        sha3_squeeze_v3
.wipe:
    lea         rdi, [rsp + O3_CTX]
    call        sha3_wipe
    add         rsp, O3_FRAME
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbx
    ret
