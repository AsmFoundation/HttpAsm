; =============================================================================
; crypto/gcm.asm - AES-GCM (NIST SP 800-38D) as TLS 1.3 and QUIC use it: AES-128 or AES-256
; (crypto/aes.asm), 96-bit nonces (J0 = nonce || 1, 7.1 step 2), 128-bit tags. The C ABI:
; httpasm_aes_gcm_init, httpasm_aes_gcm_seal, httpasm_aes_gcm_open.
;
; GCM: C = P ^ E_K(inc32(J0)), E_K(inc32^2(J0)), ... (GCTR, 6.5); S = GHASH_H(A padded, C
; padded, the lengths in bits) (7.1 step 5); T = E_K(J0) ^ S. GHASH multiplies in GF(2^128)
; modulo x^128 + x^7 + x^2 + x + 1, the bits of each block in the field's reflected order (6.3).
;
; Versions, chosen per call:
;   VAES + VPCLMULQDQ (v3 with VAES, VCLMUL, AESNI and CLMUL): two blocks an instruction in YMM
;            registers, sixteen blocks a step, the GHASH of sixteen blocks interleaved with the
;            AES rounds (see the section's own comment below).
;   AES-NI + PCLMULQDQ (HTTPASM_CPU_AESNI | CLMUL | V2: pshufb):
;            counter mode eight blocks at a time, with the GHASH of eight blocks interleaved in
;            their AES rounds (see the driver's own comment); each block multiplied by its own
;            power of H (H^8 .. H^1) without reducing, summed, and reduced once. The
;            powers are kept "byte-reflected and twisted" (each one times x^-1, as OpenSSL's
;            ghash-x86_64 keeps H): a carry-less product of reflected values is then the field
;            product itself, and a two-phase shift reduction finishes it. The round keys and
;            powers are copied to the stack first: the legacy SSE forms need 16-byte aligned
;            memory operands, and the key structure need not be aligned.
;   v1       constant time: counter mode by crypto/aes.asm's bitsliced ha_aes_ct_encrypt8,
;            eight counters a call (the first call's first block is J0, for the tag); GHASH by
;            integer multiplications of operands whose bits are spread four apart, so carries
;            never reach a data bit (bmul64 below), the high halves through bit reversal - the
;            design of BearSSL's ghash_ctmul64 (Thomas Pornin, MIT).
; Every key carries the powers of H whichever tier made it (the init computes them with
; PCLMULQDQ where it can, else with v1's multiplication), so any tier can use any key.
;
; Constant time: no branch or address depends on the key, H, the nonce, the AAD or the data,
; only on their lengths and on which function runs (seal or open). open compares tags with a
; data-independent sequence and, on a mismatch, zeroes everything it wrote.
; =============================================================================
default rel
%include "httpasm_core.inc"

section .rodata
align 16
gcm_bswap:      db 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0    ; pshufb: reverse 16 octets
gcm_poly:       dq 0x0000000000000001, 0xC200000000000000   ; the twist's reduction: x^-1's terms
gcm_one:        dd 1, 0, 0, 0                               ; +1 to a counter in reversed form
gcm_two:        dd 2, 0, 0, 0, 2, 0, 0, 0                   ; +2 to both lanes' counters (VAES)

section .text

; The key's round keys and round count (the AES key is its first member).
GCM_RK      equ httpasm_aes_gcm_key.aes + httpasm_aes_key.round_keys
GCM_ROUNDS  equ httpasm_aes_gcm_key.aes + httpasm_aes_key.rounds

; -----------------------------------------------------------------------------
; GCM_CLMUL Xhi, Xi, Hkey, HK, T1, T2: <Xhi:Xi> = Xi * Hkey, the 256-bit carry-less product by
; Karatsuba (three multiplications): HK holds Hkey's two halves xored (in both qwords).
; Clobbers T1, T2; Hkey and HK are kept.
; -----------------------------------------------------------------------------
%macro GCM_CLMUL 6
    movdqa      %1, %2
    pshufd      %5, %2, 0x4E
    pxor        %5, %2                      ; Xi's halves xored
    pclmulqdq   %2, %3, 0x00                ; lo * lo
    pclmulqdq   %1, %3, 0x11                ; hi * hi
    pclmulqdq   %5, %4, 0x00                ; (lo ^ hi) * (lo ^ hi)
    pxor        %5, %2
    pxor        %5, %1                      ; the middle product
    movdqa      %6, %5
    psrldq      %5, 8
    pslldq      %6, 8
    pxor        %1, %5
    pxor        %2, %6
%endmacro

; -----------------------------------------------------------------------------
; GCM_REDUCE Xhi, Xi, T1, T2: Xi = <Xhi:Xi> reduced modulo the GHASH polynomial, in the
; reflected representation (the product of a reflected value and a twisted one): two phases of
; shifts, by 57, 62, 63 and then by 1, 2, 7. Clobbers Xhi, T1, T2.
; -----------------------------------------------------------------------------
%macro GCM_REDUCE 4
    movdqa      %4, %2
    movdqa      %3, %2
    psllq       %2, 5
    pxor        %3, %2
    psllq       %2, 1
    pxor        %2, %3
    psllq       %2, 57                      ; Xi << 63 ^ Xi << 62 ^ Xi << 57, per qword
    movdqa      %3, %2
    pslldq      %2, 8
    psrldq      %3, 8
    pxor        %2, %4
    pxor        %1, %3
    movdqa      %4, %2                      ; 2nd phase
    psrlq       %2, 1
    pxor        %1, %4
    pxor        %4, %2
    psrlq       %2, 5
    pxor        %2, %4
    psrlq       %2, 1                       ; s >> 1 ^ s >> 2 ^ s >> 7
    pxor        %2, %1
%endmacro

; -----------------------------------------------------------------------------
; GCM_TWIST x, t1, t2, t3: x (a reflected H power) times x^-1 in place: shifted left by one bit
; over 128 bits, and the reduction constant xored in when the bit shifted out was set.
; SSE2 only (v1's init uses it too). Clobbers t1-t3.
; -----------------------------------------------------------------------------
%macro GCM_TWIST 4
    pshufd      %3, %1, 0xFF                ; the top dword in every lane: its sign is bit 127
    movdqa      %2, %1
    psllq       %1, 1
    pxor        %4, %4
    psrlq       %2, 63
    pcmpgtd     %4, %3                      ; all ones where bit 127 was set
    pslldq      %2, 8
    por         %1, %2                      ; the 128-bit shift: the low qword's carry up
    pand        %4, [rel gcm_poly]
    pxor        %1, %4
%endmacro

; -----------------------------------------------------------------------------
; The C ABI's requests, passed to a version's driver as one block on the caller's stack.
; -----------------------------------------------------------------------------
GR_NONCE    equ 0           ; the 12-octet nonce
GR_AAD      equ 8
GR_AADLEN   equ 16
GR_IN       equ 24
GR_LEN      equ 32
GR_OUT      equ 40
GR_TAG      equ 48          ; where the driver writes the computed tag (16 octets)
GR_OPEN     equ 56          ; byte: 0 seal (hash the output), 1 open (hash the input)
GR_SIZE     equ 64

; =============================================================================
; v1: constant time.
; =============================================================================

; The GHASH state of v1, 64 octets: the accumulator Y and H, as big-endian halves (y1 is the
; first eight octets), with H's halves bit-reversed and xored, as bmul64's six products want them.
GV_Y1       equ 0
GV_Y0       equ 8
GV_H1       equ 16
GV_H0       equ 24
GV_H1R      equ 32
GV_H0R      equ 40
GV_H2       equ 48          ; h0 ^ h1
GV_H2R      equ 56          ; h0r ^ h1r
GV_SIZE     equ 64

; -----------------------------------------------------------------------------
; gcm_bmul64: rax = the low 64 bits of the carry-less product of rax and rdx, constant time:
; each operand split into four bit planes (every fourth bit), the planes multiplied as integers
; (a product's carries land in the three bits between data bits, which the masks then drop).
;   Clobbers rcx, rdx, r8-r11, the red zone's 40 octets below rsp, and the flags.
; -----------------------------------------------------------------------------
align 16
gcm_bmul64:
    mov     rcx, 0x1111111111111111
    mov     r8, rax
    and     r8, rcx                         ; x0
    mov     r9, rdx
    and     r9, rcx
    mov     [rsp - 8], r9                   ; y0
    add     rcx, rcx                        ; 0x2222...
    mov     r9, rax
    and     r9, rcx                         ; x1
    mov     r10, rdx
    and     r10, rcx
    mov     [rsp - 16], r10                 ; y1
    add     rcx, rcx                        ; 0x4444...
    mov     r10, rax
    and     r10, rcx                        ; x2
    mov     r11, rdx
    and     r11, rcx
    mov     [rsp - 24], r11                 ; y2
    add     rcx, rcx                        ; 0x8888...
    mov     r11, rax
    and     r11, rcx                        ; x3
    and     rdx, rcx
    mov     [rsp - 32], rdx                 ; y3
    ; z0 = x0 y0 ^ x1 y3 ^ x2 y2 ^ x3 y1, keeping bit plane 0.
    mov     rax, r8
    imul    rax, [rsp - 8]
    mov     rdx, r9
    imul    rdx, [rsp - 32]
    xor     rax, rdx
    mov     rdx, r10
    imul    rdx, [rsp - 24]
    xor     rax, rdx
    mov     rdx, r11
    imul    rdx, [rsp - 16]
    xor     rax, rdx
    mov     rcx, 0x1111111111111111
    and     rax, rcx
    mov     [rsp - 40], rax
    ; z1 = x0 y1 ^ x1 y0 ^ x2 y3 ^ x3 y2, plane 1.
    mov     rax, r8
    imul    rax, [rsp - 16]
    mov     rdx, r9
    imul    rdx, [rsp - 8]
    xor     rax, rdx
    mov     rdx, r10
    imul    rdx, [rsp - 32]
    xor     rax, rdx
    mov     rdx, r11
    imul    rdx, [rsp - 24]
    xor     rax, rdx
    add     rcx, rcx
    and     rax, rcx
    or      [rsp - 40], rax
    ; z2 = x0 y2 ^ x1 y1 ^ x2 y0 ^ x3 y3, plane 2.
    mov     rax, r8
    imul    rax, [rsp - 24]
    mov     rdx, r9
    imul    rdx, [rsp - 16]
    xor     rax, rdx
    mov     rdx, r10
    imul    rdx, [rsp - 8]
    xor     rax, rdx
    mov     rdx, r11
    imul    rdx, [rsp - 32]
    xor     rax, rdx
    add     rcx, rcx
    and     rax, rcx
    or      [rsp - 40], rax
    ; z3 = x0 y3 ^ x1 y2 ^ x2 y1 ^ x3 y0, plane 3.
    mov     rax, r8
    imul    rax, [rsp - 32]
    mov     rdx, r9
    imul    rdx, [rsp - 24]
    xor     rax, rdx
    mov     rdx, r10
    imul    rdx, [rsp - 16]
    xor     rax, rdx
    mov     rdx, r11
    imul    rdx, [rsp - 8]
    xor     rax, rdx
    add     rcx, rcx
    and     rax, rcx
    or      rax, [rsp - 40]
    ret

; -----------------------------------------------------------------------------
; gcm_rev64: rax with its 64 bits in reverse order (bswap, then nibbles, pairs and bits swapped).
;   Clobbers rcx, rdx and the flags.
; -----------------------------------------------------------------------------
align 16
gcm_rev64:
    bswap   rax
    mov     rdx, 0x0F0F0F0F0F0F0F0F
    mov     rcx, rax
    shr     rcx, 4
    and     rcx, rdx
    and     rax, rdx
    shl     rax, 4
    or      rax, rcx
    mov     rdx, 0x3333333333333333
    mov     rcx, rax
    shr     rcx, 2
    and     rcx, rdx
    and     rax, rdx
    shl     rax, 2
    or      rax, rcx
    mov     rdx, 0x5555555555555555
    mov     rcx, rax
    shr     rcx, 1
    and     rcx, rdx
    and     rax, rdx
    shl     rax, 1
    or      rax, rcx
    ret

; -----------------------------------------------------------------------------
; gcm_ghash_v1: Y = (Y ^ block) * H for each of rdx whole blocks at rsi, v1.
;   In: rdi = the GHASH state (GV_*), rsi = the blocks, rdx = how many (0 does nothing).
;   Keeps rbx, rbp, r12-r15. Clobbers rax, rcx, rdx, rsi, rdi, r8-r11 and the flags.
;   The products of a block (frame) are wiped before returning: they derive from H.
; -----------------------------------------------------------------------------
GL_Y0R      equ 0
GL_Y1R      equ 8
GL_Y2       equ 16
GL_Y2R      equ 24
GL_Z0       equ 32
GL_Z1       equ 40
GL_Z2       equ 48
GL_Z0H      equ 56
GL_Z1H      equ 64
GL_Z2H      equ 72
GL_FRAME    equ 88          ; four pushes + 88: rsp 16-byte aligned (8 octets unused)

align 16
gcm_ghash_v1:
    test    rdx, rdx
    jz      .none
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, GL_FRAME
    mov     rbx, rdi
    mov     r12, rsi
    mov     r13, rdx
.block:
    mov     rax, [r12]
    bswap   rax
    xor     [rbx + GV_Y1], rax              ; Y ^= the block, as big-endian halves
    mov     rax, [r12 + 8]
    bswap   rax
    xor     [rbx + GV_Y0], rax
    mov     rax, [rbx + GV_Y0]
    call    gcm_rev64
    mov     [rsp + GL_Y0R], rax
    mov     rax, [rbx + GV_Y1]
    call    gcm_rev64
    mov     [rsp + GL_Y1R], rax
    mov     rax, [rbx + GV_Y0]
    xor     rax, [rbx + GV_Y1]
    mov     [rsp + GL_Y2], rax
    mov     rax, [rsp + GL_Y0R]
    xor     rax, [rsp + GL_Y1R]
    mov     [rsp + GL_Y2R], rax
    ; Karatsuba's three products, and the same on the reversed halves (their low halves are
    ; the high halves of the products, reversed and shifted by one).
    mov     rax, [rbx + GV_Y0]
    mov     rdx, [rbx + GV_H0]
    call    gcm_bmul64
    mov     [rsp + GL_Z0], rax
    mov     rax, [rbx + GV_Y1]
    mov     rdx, [rbx + GV_H1]
    call    gcm_bmul64
    mov     [rsp + GL_Z1], rax
    mov     rax, [rsp + GL_Y2]
    mov     rdx, [rbx + GV_H2]
    call    gcm_bmul64
    mov     [rsp + GL_Z2], rax
    mov     rax, [rsp + GL_Y0R]
    mov     rdx, [rbx + GV_H0R]
    call    gcm_bmul64
    mov     [rsp + GL_Z0H], rax
    mov     rax, [rsp + GL_Y1R]
    mov     rdx, [rbx + GV_H1R]
    call    gcm_bmul64
    mov     [rsp + GL_Z1H], rax
    mov     rax, [rsp + GL_Y2R]
    mov     rdx, [rbx + GV_H2R]
    call    gcm_bmul64
    xor     rax, [rsp + GL_Z0H]
    xor     rax, [rsp + GL_Z1H]             ; z2h ^= z0h ^ z1h
    call    gcm_rev64
    shr     rax, 1
    mov     [rsp + GL_Z2H], rax
    mov     rax, [rsp + GL_Z0H]
    call    gcm_rev64
    shr     rax, 1
    mov     [rsp + GL_Z0H], rax
    mov     rax, [rsp + GL_Z1H]
    call    gcm_rev64
    shr     rax, 1
    mov     [rsp + GL_Z1H], rax
    mov     rax, [rsp + GL_Z2]
    xor     rax, [rsp + GL_Z0]
    xor     rax, [rsp + GL_Z1]
    mov     [rsp + GL_Z2], rax              ; z2 ^= z0 ^ z1
    ; The 256-bit product v3:v2:v1:v0, shifted left by one (the reflected order), then reduced.
    mov     r8, [rsp + GL_Z0]               ; v0
    mov     r9, [rsp + GL_Z0H]
    xor     r9, [rsp + GL_Z2]               ; v1
    mov     r10, [rsp + GL_Z1]
    xor     r10, [rsp + GL_Z2H]             ; v2
    mov     r11, [rsp + GL_Z1H]             ; v3
    shld    r11, r10, 1
    shld    r10, r9, 1
    shld    r9, r8, 1
    shl     r8, 1
    mov     rax, r8                         ; v2 ^= v0 ^ v0 >> 1 ^ v0 >> 2 ^ v0 >> 7
    xor     r10, rax
    shr     rax, 1
    xor     r10, rax
    mov     rax, r8
    shr     rax, 2
    xor     r10, rax
    mov     rax, r8
    shr     rax, 7
    xor     r10, rax
    mov     rax, r8                         ; v1 ^= v0 << 63 ^ v0 << 62 ^ v0 << 57
    shl     rax, 63
    xor     r9, rax
    mov     rax, r8
    shl     rax, 62
    xor     r9, rax
    mov     rax, r8
    shl     rax, 57
    xor     r9, rax
    mov     rax, r9                         ; v3 ^= v1 ^ v1 >> 1 ^ v1 >> 2 ^ v1 >> 7
    xor     r11, rax
    shr     rax, 1
    xor     r11, rax
    mov     rax, r9
    shr     rax, 2
    xor     r11, rax
    mov     rax, r9
    shr     rax, 7
    xor     r11, rax
    mov     rax, r9                         ; v2 ^= v1 << 63 ^ v1 << 62 ^ v1 << 57
    shl     rax, 63
    xor     r10, rax
    mov     rax, r9
    shl     rax, 62
    xor     r10, rax
    mov     rax, r9
    shl     rax, 57
    xor     r10, rax
    mov     [rbx + GV_Y0], r10
    mov     [rbx + GV_Y1], r11
    add     r12, 16
    dec     r13
    jnz     .block
    pxor    xmm0, xmm0                      ; the products derive from H: wiped
    movdqa  [rsp], xmm0
    movdqa  [rsp + 16], xmm0
    movdqa  [rsp + 32], xmm0
    movdqa  [rsp + 48], xmm0
    movdqa  [rsp + 64], xmm0
    add     rsp, GL_FRAME
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
.none:
    ret

; -----------------------------------------------------------------------------
; gcm_state_v1: a fresh v1 GHASH state: Y = 0, H's halves from the key (big-endian), their
; reversals and xors.
;   In: rdi = the state (64 octets), rsi = the key. Keeps rdi, rsi, rbx, rbp, r12-r15.
;   Clobbers rax, rcx, rdx and the flags.
; -----------------------------------------------------------------------------
align 16
gcm_state_v1:
    xor     eax, eax
    mov     [rdi + GV_Y1], rax
    mov     [rdi + GV_Y0], rax
    mov     rax, [rsi + httpasm_aes_gcm_key.h]
    bswap   rax
    mov     [rdi + GV_H1], rax
    mov     rax, [rsi + httpasm_aes_gcm_key.h + 8]
    bswap   rax
    mov     [rdi + GV_H0], rax
    xor     rax, [rdi + GV_H1]
    mov     [rdi + GV_H2], rax
    mov     rax, [rdi + GV_H1]
    call    gcm_rev64
    mov     [rdi + GV_H1R], rax
    mov     rax, [rdi + GV_H0]
    call    gcm_rev64
    mov     [rdi + GV_H0R], rax
    xor     rax, [rdi + GV_H1R]
    mov     [rdi + GV_H2R], rax
    ret

; -----------------------------------------------------------------------------
; GCM_V1_BATCH: eight counter blocks (nonce || counter, the counter r14d .. r14d + 7, big-endian)
; encrypted into CV_CTR, r14d advanced by 8; the counter wraps modulo 2^32 (inc32).
; Clobbers rax, rcx, rdx, rsi, rdi, r8, xmm0-xmm15.
; -----------------------------------------------------------------------------
%macro GCM_V1_BATCH 0
    mov     rax, [rbp + GR_NONCE]
    mov     rcx, [rax]
    mov     edx, [rax + 8]
%assign b 0
%rep 8
    mov     [rsp + CV_CTR + 16 * b], rcx
    mov     [rsp + CV_CTR + 16 * b + 8], edx
    lea     eax, [r14 + b]
    bswap   eax
    mov     [rsp + CV_CTR + 16 * b + 12], eax
  %assign b b + 1
%endrep
    add     r14d, 8
    lea     rdi, [rsp + CV_KEYS]
    mov     esi, [rbx + httpasm_aes_gcm_key.aes + httpasm_aes_key.rounds]
    lea     rdx, [rsp + CV_CTR]
    mov     rcx, rdx
    call    ha_aes_ct_encrypt8
%endmacro

; -----------------------------------------------------------------------------
; gcm_crypt_v1: one seal or open, v1: the ciphertext's GHASH and the counter mode, the tag
; computed into [request + GR_TAG] (open compares it).
;   In: rdi = the key, rsi = the request (GR_*). Keeps rbx, rbp, r12-r15.
;   The frame (expanded round keys, keystream, GHASH state, blocks) is wiped before returning.
; -----------------------------------------------------------------------------
CV_KEYS     equ 0                           ; v1's expanded round keys: up to 15 * 128 octets
CV_CTR      equ CV_KEYS + 15 * 128          ; eight counter blocks, then their keystream
CV_GV       equ CV_CTR + 128                ; the GHASH state
CV_PART     equ CV_GV + GV_SIZE             ; a block padded with zeros
CV_TMP      equ CV_PART + 16
CV_EJ0      equ CV_TMP + 16                 ; E_K(J0)
CV_END      equ CV_EJ0 + 16
CV_FRAME    equ CV_END + 8                  ; six pushes + the frame: rsp 16-byte aligned

align 16
gcm_crypt_v1:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, CV_FRAME
    mov     rbx, rdi
    mov     rbp, rsi
    lea     rsi, [rsp + CV_KEYS]
    call    ha_aes_ct_expand                ; rdi = the key: its AES key is at offset 0
    ; Counters 1-8: J0, whose encryption makes the tag, then the first seven data blocks'.
    mov     r14d, 1
    GCM_V1_BATCH
    movdqa  xmm0, [rsp + CV_CTR]
    movdqa  [rsp + CV_EJ0], xmm0
    mov     r15d, 1                         ; the next keystream block
    lea     rdi, [rsp + CV_GV]
    mov     rsi, rbx
    call    gcm_state_v1
    ; The AAD: its whole blocks, then its last octets padded with zeros.
    lea     rdi, [rsp + CV_GV]
    mov     rsi, [rbp + GR_AAD]
    mov     rdx, [rbp + GR_AADLEN]
    shr     rdx, 4
    call    gcm_ghash_v1
    mov     rcx, [rbp + GR_AADLEN]
    and     ecx, 15
    jz      .aad_done
    pxor    xmm0, xmm0
    movdqa  [rsp + CV_PART], xmm0
    lea     rdi, [rsp + CV_PART]
    mov     rsi, [rbp + GR_AADLEN]
    and     rsi, -16
    add     rsi, [rbp + GR_AAD]
    call    ha_copy_short
    lea     rdi, [rsp + CV_GV]
    lea     rsi, [rsp + CV_PART]
    mov     edx, 1
    call    gcm_ghash_v1
.aad_done:
    xor     r12d, r12d                      ; the data's offset
    mov     r13, [rbp + GR_LEN]             ; octets left
.data:
    test    r13, r13
    jz      .data_done
    cmp     r15d, 8
    jb      .stream
    GCM_V1_BATCH
    xor     r15d, r15d
.stream:
    cmp     r13, 16
    jb      .partial
    cmp     byte [rbp + GR_OPEN], 0
    je      .xor_block
    lea     rdi, [rsp + CV_GV]              ; open: the ciphertext hashed before it is replaced
    mov     rsi, [rbp + GR_IN]
    add     rsi, r12
    mov     edx, 1
    call    gcm_ghash_v1
.xor_block:
    mov     rax, [rbp + GR_IN]
    movdqu  xmm0, [rax + r12]
    mov     eax, r15d
    shl     eax, 4
    pxor    xmm0, [rsp + CV_CTR + rax]
    mov     rax, [rbp + GR_OUT]
    movdqu  [rax + r12], xmm0
    cmp     byte [rbp + GR_OPEN], 0
    jne     .next_block
    lea     rdi, [rsp + CV_GV]              ; seal: the ciphertext hashed as written
    mov     rsi, [rbp + GR_OUT]
    add     rsi, r12
    mov     edx, 1
    call    gcm_ghash_v1
.next_block:
    add     r12, 16
    sub     r13, 16
    inc     r15d
    jmp     .data
.partial:
    ; The last octets (1-15): through a zeroed block, so GHASH sees them padded with zeros.
    pxor    xmm0, xmm0
    movdqa  [rsp + CV_PART], xmm0
    lea     rdi, [rsp + CV_PART]
    mov     rsi, [rbp + GR_IN]
    add     rsi, r12
    mov     rcx, r13
    call    ha_copy_short
    cmp     byte [rbp + GR_OPEN], 0
    je      .partial_xor
    lea     rdi, [rsp + CV_GV]
    lea     rsi, [rsp + CV_PART]
    mov     edx, 1
    call    gcm_ghash_v1
.partial_xor:
    mov     eax, r15d
    shl     eax, 4
    movdqa  xmm0, [rsp + CV_PART]
    pxor    xmm0, [rsp + CV_CTR + rax]
    movdqa  [rsp + CV_TMP], xmm0
    mov     rdi, [rbp + GR_OUT]
    add     rdi, r12
    lea     rsi, [rsp + CV_TMP]
    mov     rcx, r13
    call    ha_copy_short
    cmp     byte [rbp + GR_OPEN], 0
    jne     .data_done
    pxor    xmm0, xmm0                      ; seal: the ciphertext's octets, padded with zeros
    movdqa  [rsp + CV_PART], xmm0
    lea     rdi, [rsp + CV_PART]
    lea     rsi, [rsp + CV_TMP]
    mov     rcx, r13
    call    ha_copy_short
    lea     rdi, [rsp + CV_GV]
    lea     rsi, [rsp + CV_PART]
    mov     edx, 1
    call    gcm_ghash_v1
.data_done:
    ; The lengths block: len(A) || len(C) in bits, 64 bits each, big-endian.
    mov     rax, [rbp + GR_AADLEN]
    shl     rax, 3
    bswap   rax
    mov     [rsp + CV_PART], rax
    mov     rax, [rbp + GR_LEN]
    shl     rax, 3
    bswap   rax
    mov     [rsp + CV_PART + 8], rax
    lea     rdi, [rsp + CV_GV]
    lea     rsi, [rsp + CV_PART]
    mov     edx, 1
    call    gcm_ghash_v1
    ; T = E_K(J0) ^ S, S = Y's halves big-endian.
    mov     rax, [rsp + CV_GV + GV_Y1]
    bswap   rax
    xor     rax, [rsp + CV_EJ0]
    mov     rcx, [rsp + CV_GV + GV_Y0]
    bswap   rcx
    xor     rcx, [rsp + CV_EJ0 + 8]
    mov     rdx, [rbp + GR_TAG]
    mov     [rdx], rax
    mov     [rdx + 8], rcx
    ; The frame held round keys, keystream and H: wiped, 16 octets a step (a loop: its size is
    ; an equ, which the coverage build's preprocessor cannot count a %rep with).
    pxor    xmm0, xmm0
    xor     eax, eax
.wipe:
    movdqa  [rsp + rax], xmm0
    add     eax, 16
    cmp     eax, CV_END
    jb      .wipe
    add     rsp, CV_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; -----------------------------------------------------------------------------
; gcm_powers_v1: the key's powers of H for the carry-less versions (twisted and reflected,
; H^16 first) and their Karatsuba halves, computed with v1's multiplication: H^k as GHASH would
; make it (Y = H, then Y * H with a zero block, ...), each then reflected (its big-endian halves
; are the reflected register's qwords) and twisted. SSE2 only.
;   In: rdi = the key (its .h written). Keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
PV_GV       equ 0
PV_ZERO     equ GV_SIZE                     ; a zero block, for Y = Y * H
PV_END      equ PV_ZERO + 16
PV_FRAME    equ PV_END                      ; three pushes + the frame: aligned

align 16
gcm_powers_v1:
    push    rbx
    push    r12
    push    r13
    sub     rsp, PV_FRAME
    mov     rbx, rdi
    lea     rdi, [rsp + PV_GV]
    mov     rsi, rbx
    call    gcm_state_v1
    mov     rax, [rsp + PV_GV + GV_H1]      ; Y = H: the first power
    mov     [rsp + PV_GV + GV_Y1], rax
    mov     rax, [rsp + PV_GV + GV_H0]
    mov     [rsp + PV_GV + GV_Y0], rax
    pxor    xmm0, xmm0
    movdqa  [rsp + PV_ZERO], xmm0
    mov     r12d, 15 * 16                   ; H^1's place in the tables (H^16 is at 0)
.power:
    movq    xmm0, [rsp + PV_GV + GV_Y0]     ; the reflected value: low qword y0, high y1
    movq    xmm1, [rsp + PV_GV + GV_Y1]
    punpcklqdq xmm0, xmm1
    GCM_TWIST xmm0, xmm1, xmm2, xmm3
    movdqu  [rbx + httpasm_aes_gcm_key.htable + r12], xmm0
    pshufd  xmm1, xmm0, 0x4E
    pxor    xmm1, xmm0
    movdqu  [rbx + httpasm_aes_gcm_key.hkara + r12], xmm1
    sub     r12d, 16
    js      .done
    lea     rdi, [rsp + PV_GV]
    lea     rsi, [rsp + PV_ZERO]
    mov     edx, 1
    call    gcm_ghash_v1                    ; Y = Y * H: the next power
    jmp     .power
.done:
    pxor    xmm0, xmm0
    xor     eax, eax
.wipe:
    movdqa  [rsp + rax], xmm0
    add     eax, 16
    cmp     eax, PV_END
    jb      .wipe
    add     rsp, PV_FRAME
    pop     r13
    pop     r12
    pop     rbx
    ret

; =============================================================================
; AES-NI + PCLMULQDQ.
; =============================================================================

; -----------------------------------------------------------------------------
; gcm_powers_clmul: the same tables with PCLMULQDQ: H reflected and twisted, then each power
; times the twisted H (a product of two twisted values is the twisted product).
;   In: rdi = the key (its .h written). Clobbers xmm0-xmm7 and the flags.
; -----------------------------------------------------------------------------
align 16
gcm_powers_clmul:
    movdqu  xmm0, [rdi + httpasm_aes_gcm_key.h]
    pshufb  xmm0, [rel gcm_bswap]
    GCM_TWIST xmm0, xmm1, xmm2, xmm3
    movdqa  xmm6, xmm0                      ; twisted H
    pshufd  xmm7, xmm6, 0x4E
    pxor    xmm7, xmm6                      ; its halves xored
    mov     eax, 15 * 16
.power:
    movdqu  [rdi + httpasm_aes_gcm_key.htable + rax], xmm0
    pshufd  xmm1, xmm0, 0x4E
    pxor    xmm1, xmm0
    movdqu  [rdi + httpasm_aes_gcm_key.hkara + rax], xmm1
    sub     eax, 16
    js      .done
    GCM_CLMUL xmm1, xmm0, xmm6, xmm7, xmm2, xmm3
    GCM_REDUCE xmm1, xmm0, xmm2, xmm3
    jmp     .power
.done:
    ret

; -----------------------------------------------------------------------------
; The AES-NI driver: eight blocks a step in xmm0-xmm7, the GHASH of eight blocks interleaved with
; their AES rounds (one block after each of rounds 1-8: the AES unit and the carry-less multiplier
; work at once), seal hashing the previous step's output and open its own input, as the VAES
; driver does with sixteen; the last octets (under 128) one more step through a zeroed buffer
; and one aggregated GHASH. Registers in the step: xmm8 the round key, xmm9-xmm11 GHASH's low,
; high and middle sums, xmm12 and xmm14 GHASH's temporaries (xmm14 the accumulator between
; steps), xmm13 the byte-reversing mask, xmm15 the next counter, reversed (its 32-bit counter
; then the low dword, which paddd increments modulo 2^32: inc32). Round keys and the powers
; H^8 .. H^1 are copied to the aligned stack: the legacy SSE forms need aligned memory operands.
; GPRs: rbx the key, rbp the request, r12 the data's offset, r13 octets left, r14 in, r15 out.
; -----------------------------------------------------------------------------
CN_RK       equ 0                           ; the round keys, aligned: 15 * 16
CN_HT       equ CN_RK + 15 * 16             ; H^8 .. H^1
CN_HK       equ CN_HT + 8 * 16              ; their Karatsuba halves (gcm_ghash_ni reads them at +128)
CN_TAIL     equ CN_HK + 8 * 16              ; the last octets (under 128), padded with zeros
CN_PART     equ CN_TAIL + 128               ; the AAD's last octets, then the lengths block
CN_EJ0      equ CN_PART + 16
CN_END      equ CN_EJ0 + 16
CN_FRAME    equ CN_END + 8                  ; six pushes + the frame: aligned

; GCM_NI_BLOCK x, k: one block x through AES with the stack's round keys (k: a scratch register).
; Clobbers rax, ecx, k.
%macro GCM_NI_BLOCK 2
    pxor        %1, [rsp + CN_RK]
    lea         rax, [rsp + CN_RK + 16]
    mov         ecx, [rbx + GCM_ROUNDS]
    dec         ecx
%%round:
    movdqa      %2, [rax]
    aesenc      %1, %2
    add         rax, 16
    dec         ecx
    jnz         %%round
    aesenclast  %1, [rax]
%endmacro

; GCM_NI_STEP p, j: GHASH's block j of the eight at p times H^(8-j) (the stack's table at 16 j),
; its three products added to xmm9-xmm11; for j = 0 the accumulator (xmm14) first.
; Clobbers xmm12, xmm14.
%macro GCM_NI_STEP 2
    movdqu      xmm12, [%1 + 16 * %2]
    pshufb      xmm12, xmm13
  %if %2 == 0
    pxor        xmm12, xmm14
  %endif
    pshufd      xmm14, xmm12, 0x4E
    pxor        xmm14, xmm12
    pclmulqdq   xmm14, [rsp + CN_HK + 16 * %2], 0x00
    pxor        xmm11, xmm14                ; middle
    movdqa      xmm14, xmm12
    pclmulqdq   xmm14, [rsp + CN_HT + 16 * %2], 0x00
    pxor        xmm9, xmm14                 ; low
    pclmulqdq   xmm12, [rsp + CN_HT + 16 * %2], 0x11
    pxor        xmm10, xmm12                ; high
%endmacro

; GCM_NI_REDUCE: the sums xmm9-xmm11 (Karatsuba's middle split) reduced into xmm14.
; Clobbers xmm9-xmm12.
%macro GCM_NI_REDUCE 0
    pxor        xmm11, xmm9
    pxor        xmm11, xmm10
    movdqa      xmm12, xmm11
    psrldq      xmm11, 8
    pslldq      xmm12, 8
    pxor        xmm10, xmm11
    pxor        xmm9, xmm12
    GCM_REDUCE  xmm10, xmm9, xmm11, xmm12
    movdqa      xmm14, xmm9
%endmacro

; GCM_NI_ITER ghash, p, in, out: one step of eight blocks: counter mode (the next eight counters
; from xmm15) xored with in[0..128) into out[0..128) (out may be in: every read comes before the
; stores); with ghash = 1 also GHASH of the eight blocks at p, one after each of AES rounds 1-8.
; Clobbers rax, xmm0-xmm12, xmm14 (the new accumulator when ghash = 1) and the flags.
%macro GCM_NI_ITER 4
  %if %1
    pxor        xmm9, xmm9
    pxor        xmm10, xmm10
    pxor        xmm11, xmm11
  %endif
%assign b 0
%rep 8
    movdqa      xmm%[b], xmm15
    paddd       xmm15, [rel gcm_one]
    pshufb      xmm%[b], xmm13
  %assign b b + 1
%endrep
    movdqa      xmm8, [rsp + CN_RK]
%assign b 0
%rep 8
    pxor        xmm%[b], xmm8
  %assign b b + 1
%endrep
%assign r 1
%rep 8
    movdqa      xmm8, [rsp + CN_RK + 16 * r]
  %assign b 0
  %rep 8
    aesenc      xmm%[b], xmm8
    %assign b b + 1
  %endrep
  %if %1
    %assign s r - 1
    GCM_NI_STEP %2, s
  %endif
  %assign r r + 1
%endrep
    movdqa      xmm8, [rsp + CN_RK + 16 * 9]
%assign b 0
%rep 8
    aesenc      xmm%[b], xmm8
  %assign b b + 1
%endrep
    cmp         dword [rbx + GCM_ROUNDS], 10
    je          %%last
%assign r 10
%rep 4
    movdqa      xmm8, [rsp + CN_RK + 16 * r]
  %assign b 0
  %rep 8
    aesenc      xmm%[b], xmm8
    %assign b b + 1
  %endrep
  %assign r r + 1
%endrep
%%last:
    mov         eax, [rbx + GCM_ROUNDS]
    shl         eax, 4
    movdqa      xmm8, [rsp + CN_RK + rax]
%assign b 0
%rep 8
    aesenclast  xmm%[b], xmm8
  %assign b b + 1
%endrep
  %if %1
    GCM_NI_REDUCE
  %endif
%assign b 0
%rep 8
    movdqu      xmm12, [%3 + 16 * b]
    pxor        xmm%[b], xmm12
    movdqu      [%4 + 16 * b], xmm%[b]
  %assign b b + 1
%endrep
%endmacro

; -----------------------------------------------------------------------------
; gcm_ghash_ni: the accumulator xmm14 through rdx whole blocks at rsi, eight at most per
; reduction (block i of a batch of k times H^(k-i)), legacy SSE.
;   In: rsi = the blocks, rdx = how many (0 does nothing), r11 = the stack's H^8 .. H^1 (16-byte
;   aligned; their Karatsuba halves at r11 + 128), xmm13 = the byte-reversing mask, xmm14 = the
;   accumulator. Out: xmm14. Clobbers rax, rcx, rdx, rsi, xmm0-xmm2, xmm9-xmm12, the flags.
; -----------------------------------------------------------------------------
align 16
gcm_ghash_ni:
.batch:
    test    rdx, rdx
    jz      .done
    mov     ecx, 8
    cmp     rdx, rcx
    cmovb   ecx, edx                        ; k = min(blocks, 8)
    sub     rdx, rcx
    mov     eax, 8
    sub     eax, ecx
    shl     eax, 4                          ; H^k's place in the stack's table
    pxor    xmm9, xmm9
    pxor    xmm10, xmm10
    pxor    xmm11, xmm11
    movdqu  xmm0, [rsi]
    pshufb  xmm0, xmm13
    pxor    xmm0, xmm14                     ; the accumulator into the batch's first block
    jmp     .multiply
.next:
    movdqu  xmm0, [rsi]
    pshufb  xmm0, xmm13
.multiply:
    pshufd  xmm1, xmm0, 0x4E
    pxor    xmm1, xmm0
    pclmulqdq xmm1, [r11 + 128 + rax], 0x00
    pxor    xmm11, xmm1
    movdqa  xmm2, xmm0
    pclmulqdq xmm2, [r11 + rax], 0x00
    pxor    xmm9, xmm2
    pclmulqdq xmm0, [r11 + rax], 0x11
    pxor    xmm10, xmm0
    add     rsi, 16
    add     eax, 16
    dec     ecx
    jnz     .next
    pxor    xmm11, xmm9
    pxor    xmm11, xmm10
    movdqa  xmm12, xmm11
    psrldq  xmm11, 8
    pslldq  xmm12, 8
    pxor    xmm10, xmm11
    pxor    xmm9, xmm12
    GCM_REDUCE xmm10, xmm9, xmm11, xmm12
    movdqa  xmm14, xmm9
    jmp     .batch
.done:
    ret

; -----------------------------------------------------------------------------
; gcm_crypt_ni: one seal or open with AES-NI and PCLMULQDQ; the tag into [request + GR_TAG].
;   In: rdi = the key, rsi = the request. Keeps rbx, rbp, r12-r15. The frame is wiped and
;   xmm1-xmm15 cleared before returning.
; -----------------------------------------------------------------------------
align 16
gcm_crypt_ni:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, CN_FRAME
    mov     rbx, rdi
    mov     rbp, rsi
    ; Round keys and the powers H^8 .. H^1 to the aligned stack.
    xor     eax, eax
.copy_keys:
    movdqu  xmm0, [rbx + GCM_RK + rax]
    movdqa  [rsp + CN_RK + rax], xmm0
    add     eax, 16
    cmp     eax, 15 * 16
    jb      .copy_keys
    xor     eax, eax
.copy_powers:
    movdqu  xmm0, [rbx + httpasm_aes_gcm_key.htable + 8 * 16 + rax]
    movdqa  [rsp + CN_HT + rax], xmm0
    movdqu  xmm0, [rbx + httpasm_aes_gcm_key.hkara + 8 * 16 + rax]
    movdqa  [rsp + CN_HK + rax], xmm0
    add     eax, 16
    cmp     eax, 8 * 16
    jb      .copy_powers
    movdqa  xmm13, [rel gcm_bswap]
    pxor    xmm14, xmm14
    ; J0 = nonce || 1; E_K(J0) for the tag; the first data counter is J0 + 1.
    mov     rax, [rbp + GR_NONCE]
    movq    xmm0, [rax]
    movd    xmm1, [rax + 8]
    punpcklqdq xmm0, xmm1                   ; nonce, then four zero octets
    mov     ecx, 0x01000000                 ; 1, big-endian, in the last four octets
    movd    xmm1, ecx
    pslldq  xmm1, 12
    por     xmm0, xmm1
    movdqa  xmm15, xmm0
    pshufb  xmm15, xmm13
    paddd   xmm15, [rel gcm_one]
    GCM_NI_BLOCK xmm0, xmm1
    movdqa  [rsp + CN_EJ0], xmm0
    ; The AAD: whole blocks, then its last octets padded.
    lea     r11, [rsp + CN_HT]
    mov     rsi, [rbp + GR_AAD]
    mov     rdx, [rbp + GR_AADLEN]
    shr     rdx, 4
    call    gcm_ghash_ni
    mov     rcx, [rbp + GR_AADLEN]
    and     ecx, 15
    jz      .aad_done
    pxor    xmm0, xmm0
    movdqa  [rsp + CN_PART], xmm0
    lea     rdi, [rsp + CN_PART]
    mov     rsi, [rbp + GR_AADLEN]
    and     rsi, -16
    add     rsi, [rbp + GR_AAD]
    call    ha_copy_short
    lea     r11, [rsp + CN_HT]
    lea     rsi, [rsp + CN_PART]
    mov     edx, 1
    call    gcm_ghash_ni
.aad_done:
    xor     r12d, r12d
    mov     r13, [rbp + GR_LEN]
    mov     r14, [rbp + GR_IN]
    mov     r15, [rbp + GR_OUT]
    cmp     r13, 128
    jb      .tail
    cmp     byte [rbp + GR_OPEN], 0
    jne     .open_steps
    ; seal: the first step has nothing written to hash yet.
    GCM_NI_ITER 0, none, r14, r15
    add     r12, 128
    sub     r13, 128
.seal_steps:
    cmp     r13, 128
    jb      .seal_pending
    lea     r10, [r15 + r12 - 128]          ; the step before's ciphertext
    lea     rsi, [r14 + r12]
    lea     rdi, [r15 + r12]
    GCM_NI_ITER 1, r10, rsi, rdi
    add     r12, 128
    sub     r13, 128
    jmp     .seal_steps
.seal_pending:
    lea     r11, [rsp + CN_HT]
    lea     rsi, [r15 + r12 - 128]          ; the last step's ciphertext
    mov     edx, 8
    call    gcm_ghash_ni
    jmp     .tail
.open_steps:
    cmp     r13, 128
    jb      .tail
    lea     r10, [r14 + r12]                ; open: the step's own ciphertext, read first
    lea     rdi, [r15 + r12]
    GCM_NI_ITER 1, r10, r10, rdi
    add     r12, 128
    sub     r13, 128
    jmp     .open_steps
.tail:
    test    r13, r13
    jz      .lengths
    ; Under 128 octets left: through the zeroed buffer, one counter-mode step, one GHASH.
    pxor    xmm0, xmm0
%assign b 0
%rep 8
    movdqa  [rsp + CN_TAIL + 16 * b], xmm0
  %assign b b + 1
%endrep
    lea     rdi, [rsp + CN_TAIL]
    lea     rsi, [r14 + r12]
    mov     rcx, r13
    call    ha_copy_short
    cmp     byte [rbp + GR_OPEN], 0
    je      .tail_crypt
    lea     r11, [rsp + CN_HT]              ; open: the ciphertext, padded with zeros
    lea     rsi, [rsp + CN_TAIL]
    lea     rdx, [r13 + 15]
    shr     rdx, 4
    call    gcm_ghash_ni
.tail_crypt:
    lea     rsi, [rsp + CN_TAIL]
    GCM_NI_ITER 0, none, rsi, rsi
    lea     rdi, [r15 + r12]
    lea     rsi, [rsp + CN_TAIL]
    mov     rcx, r13
    call    ha_copy_short
    cmp     byte [rbp + GR_OPEN], 0
    jne     .lengths
    pxor    xmm0, xmm0                      ; seal: the ciphertext's octets, padded with zeros
%assign b 0
%rep 8
    movdqa  [rsp + CN_TAIL + 16 * b], xmm0
  %assign b b + 1
%endrep
    lea     rdi, [rsp + CN_TAIL]
    lea     rsi, [r15 + r12]
    mov     rcx, r13
    call    ha_copy_short
    lea     r11, [rsp + CN_HT]
    lea     rsi, [rsp + CN_TAIL]
    lea     rdx, [r13 + 15]
    shr     rdx, 4
    call    gcm_ghash_ni
.lengths:
    mov     rax, [rbp + GR_AADLEN]          ; the lengths block, in bits, big-endian
    shl     rax, 3
    bswap   rax
    mov     [rsp + CN_PART], rax
    mov     rax, [rbp + GR_LEN]
    shl     rax, 3
    bswap   rax
    mov     [rsp + CN_PART + 8], rax
    lea     r11, [rsp + CN_HT]
    lea     rsi, [rsp + CN_PART]
    mov     edx, 1
    call    gcm_ghash_ni
    pshufb  xmm14, xmm13                    ; S, in the GCM order
    pxor    xmm14, [rsp + CN_EJ0]
    mov     rax, [rbp + GR_TAG]
    movdqu  [rax], xmm14
    ; Wipe the frame and the registers that held keys, keystream or H.
    pxor    xmm0, xmm0
    xor     eax, eax
.wipe:
    movdqa  [rsp + rax], xmm0
    add     eax, 16
    cmp     eax, CN_END
    jb      .wipe
%assign b 1
%rep 15
    pxor    xmm%[b], xmm%[b]
  %assign b b + 1
%endrep
    add     rsp, CN_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; =============================================================================
; VAES + VPCLMULQDQ (v3): two blocks an instruction in YMM registers.
;
; The main loop takes 256 octets (sixteen blocks, eight register pairs) a step: counter mode on
; all sixteen while GHASH works through sixteen ciphertext blocks, one register pair after each
; of the first eight AES rounds, so the AES units (ports 0 and 1) and the carry-less multiplier
; (port 5) work at once; the sixteen products are summed unreduced (block i times H^(16-i))
; and reduced once. seal hashes the previous step's output (none before the first step, the
; last step's after the loop); open hashes the step's own input before it is written over.
; What is left (under 256 octets) takes one more counter-mode step through a zeroed stack buffer
; and one aggregated GHASH: no block-at-a-time tail. Round keys and powers are read from the key
; itself (VEX memory operands need no alignment). Registers in the loop: ymm0-ymm7 the blocks,
; ymm8 the round key, ymm9-ymm11 GHASH's low, high and middle sums, ymm12 and ymm14 GHASH's
; temporaries (xmm14 the accumulator between steps, its upper lane zero), ymm13 the
; byte-reversing mask in both lanes, ymm15 the next two counters, reversed.
; =============================================================================

; -----------------------------------------------------------------------------
; GCM_REDUCE_VX Xhi, Xi, T1, T2: GCM_REDUCE in VEX form (the same two phases: Xi's per-qword
; shifts by 57, 62 and 63 folded in, then s ^ s >> 1 ^ s >> 2 ^ s >> 7 with Xhi). Out: Xi.
; Clobbers Xhi, T1, T2.
; -----------------------------------------------------------------------------
%macro GCM_REDUCE_VX 4
    vpsllq      %3, %2, 57
    vpsllq      %4, %2, 62
    vpxor       %3, %3, %4
    vpsllq      %4, %2, 63
    vpxor       %3, %3, %4                  ; Xi << 57 ^ Xi << 62 ^ Xi << 63, per qword
    vpslldq     %4, %3, 8
    vpsrldq     %3, %3, 8
    vpxor       %2, %2, %4
    vpxor       %1, %1, %3
    vpsrlq      %3, %2, 1                   ; 2nd phase, s = Xi
    vpsrlq      %4, %2, 2
    vpxor       %3, %3, %4
    vpsrlq      %4, %2, 7
    vpxor       %3, %3, %4
    vpxor       %1, %1, %2
    vpxor       %2, %1, %3                  ; Xhi ^ s ^ s >> 1 ^ s >> 2 ^ s >> 7
%endmacro

; -----------------------------------------------------------------------------
; GCM_VX_BLOCK x: one block (xmm) through AES with the key's round keys (VEX, unaligned).
; Clobbers eax and the flags.
; -----------------------------------------------------------------------------
%macro GCM_VX_BLOCK 1
    vpxor       %1, %1, [rbx + GCM_RK]
%assign r 1
%rep 9
    vaesenc     %1, %1, [rbx + GCM_RK + 16 * r]
  %assign r r + 1
%endrep
    cmp         dword [rbx + GCM_ROUNDS], 10
    je          %%last
%rep 4
    vaesenc     %1, %1, [rbx + GCM_RK + 16 * r]
  %assign r r + 1
%endrep
%%last:
    mov         eax, [rbx + GCM_ROUNDS]
    shl         eax, 4
    vaesenclast %1, %1, [rbx + GCM_RK + rax]
%endmacro

; -----------------------------------------------------------------------------
; GCM_VX_STEP p, j: GHASH's register pair j (blocks 2j and 2j + 1 at p + 32 j) multiplied by
; its powers (H^(16-2j) in the low lane, H^(15-2j) in the high: the key's table at 32 j), the
; three products added to ymm9-ymm11; for j = 0 the accumulator (xmm14) is added to the first
; block first. Clobbers ymm12, ymm14.
; -----------------------------------------------------------------------------
%macro GCM_VX_STEP 2
    vmovdqu     ymm12, [%1 + 32 * %2]
    vpshufb     ymm12, ymm12, ymm13
  %if %2 == 0
    vpxor       ymm12, ymm12, ymm14
  %endif
    vpshufd     ymm14, ymm12, 0x4E
    vpxor       ymm14, ymm14, ymm12         ; each block's halves xored
    vpclmulqdq  ymm14, ymm14, [rbx + httpasm_aes_gcm_key.hkara + 32 * %2], 0x00
    vpxor       ymm11, ymm11, ymm14         ; middle
    vpclmulqdq  ymm14, ymm12, [rbx + httpasm_aes_gcm_key.htable + 32 * %2], 0x00
    vpxor       ymm9, ymm9, ymm14           ; low
    vpclmulqdq  ymm12, ymm12, [rbx + httpasm_aes_gcm_key.htable + 32 * %2], 0x11
    vpxor       ymm10, ymm10, ymm12         ; high
%endmacro

; -----------------------------------------------------------------------------
; GCM_VX_REDUCE: the sums ymm9-ymm11 of a step's sixteen products folded (lane into lane),
; Karatsuba's middle split, and reduced into the accumulator xmm14 (upper lane zero).
; Clobbers ymm9-ymm12.
; -----------------------------------------------------------------------------
%macro GCM_VX_REDUCE 0
    vextracti128 xmm12, ymm9, 1
    vpxor       xmm9, xmm9, xmm12
    vextracti128 xmm12, ymm10, 1
    vpxor       xmm10, xmm10, xmm12
    vextracti128 xmm12, ymm11, 1
    vpxor       xmm11, xmm11, xmm12
    vpxor       xmm11, xmm11, xmm9
    vpxor       xmm11, xmm11, xmm10
    vpslldq     xmm12, xmm11, 8
    vpsrldq     xmm11, xmm11, 8
    vpxor       xmm9, xmm9, xmm12
    vpxor       xmm10, xmm10, xmm11
    GCM_REDUCE_VX xmm10, xmm9, xmm11, xmm12
    vmovdqa     xmm14, xmm9
%endmacro

; -----------------------------------------------------------------------------
; GCM_VX_ITER ghash, p, in, out: one step of sixteen blocks: counter mode (the next sixteen
; counters from ymm15) xored with in[0..256) into out[0..256) (out may be in: every input is
; read before the stores, and so is everything GHASH reads); with ghash = 1, GHASH of the
; sixteen blocks at p, one pair after each of AES rounds 1-8. Clobbers rax, ymm0-ymm12, ymm14
; (xmm14 is the new accumulator when ghash = 1, untouched otherwise) and the flags.
; -----------------------------------------------------------------------------
%macro GCM_VX_ITER 4
  %if %1
    vpxor       ymm9, ymm9, ymm9
    vpxor       ymm10, ymm10, ymm10
    vpxor       ymm11, ymm11, ymm11
  %endif
%assign j 0
%rep 8
    vpshufb     ymm%[j], ymm15, ymm13
    vpaddd      ymm15, ymm15, [rel gcm_two]
  %assign j j + 1
%endrep
    vbroadcasti128 ymm8, [rbx + GCM_RK]
%assign j 0
%rep 8
    vpxor       ymm%[j], ymm%[j], ymm8
  %assign j j + 1
%endrep
%assign r 1
%rep 8
    vbroadcasti128 ymm8, [rbx + GCM_RK + 16 * r]
  %assign j 0
  %rep 8
    vaesenc     ymm%[j], ymm%[j], ymm8
    %assign j j + 1
  %endrep
  %if %1
    %assign s r - 1
    GCM_VX_STEP %2, s
  %endif
  %assign r r + 1
%endrep
    vbroadcasti128 ymm8, [rbx + GCM_RK + 16 * 9]
%assign j 0
%rep 8
    vaesenc     ymm%[j], ymm%[j], ymm8
  %assign j j + 1
%endrep
    cmp         dword [rbx + GCM_ROUNDS], 10
    je          %%last
%assign r 10
%rep 4
    vbroadcasti128 ymm8, [rbx + GCM_RK + 16 * r]
  %assign j 0
  %rep 8
    vaesenc     ymm%[j], ymm%[j], ymm8
    %assign j j + 1
  %endrep
  %assign r r + 1
%endrep
%%last:
    mov         eax, [rbx + GCM_ROUNDS]
    shl         eax, 4
    vbroadcasti128 ymm8, [rbx + GCM_RK + rax]
%assign j 0
%rep 8
    vaesenclast ymm%[j], ymm%[j], ymm8
  %assign j j + 1
%endrep
  %if %1
    GCM_VX_REDUCE
  %endif
%assign j 0
%rep 8
    vpxor       ymm%[j], ymm%[j], [%3 + 32 * j]
    vmovdqu     [%4 + 32 * j], ymm%[j]
  %assign j j + 1
%endrep
%endmacro

; -----------------------------------------------------------------------------
; gcm_copy_vx: ha_copy_short (crypto/sha256.asm) in VEX form: rcx octets (any count) from rsi to
; rdi by moves sized to the count. The VAES driver must not run a legacy SSE instruction while
; the YMM registers' upper halves are live: on this core each such instruction paid the AVX-SSE
; transition, and a 16-to-255-octet tail cost about 1,300 cycles more than a 1-octet one
; (measured: 1,520 cycles for a 16-octet seal against 254 for 1 octet).
;   Keeps rcx and every register but rax, rdx, xmm0. The two may not overlap.
; -----------------------------------------------------------------------------
align 16
gcm_copy_vx:
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
    vmovdqu xmm0, [rsi + rdx]
    vmovdqu [rdi + rdx], xmm0
    add     rdx, 16
    lea     rax, [rdx + 16]
    cmp     rax, rcx
    jbe     .step
    vmovdqu xmm0, [rsi + rcx - 16]
    vmovdqu [rdi + rcx - 16], xmm0
    ret

; -----------------------------------------------------------------------------
; gcm_ghash_vx: the accumulator xmm14 through rdx whole blocks at rsi, sixteen at most per
; reduction (block i of a batch of k times H^(k-i)), VEX xmm operations.
;   In: rbx = the key, rsi = the blocks, rdx = how many (0 does nothing), xmm13 = the
;   byte-reversing mask, xmm14 = the accumulator. Out: xmm14.
;   Clobbers rax, rcx, rdx, rsi, xmm0-xmm2, xmm9-xmm12 and the flags.
; -----------------------------------------------------------------------------
align 16
gcm_ghash_vx:
.batch:
    test    rdx, rdx
    jz      .done
    mov     ecx, 16
    cmp     rdx, rcx
    cmovb   ecx, edx                        ; k = min(blocks, 16)
    sub     rdx, rcx
    mov     eax, 16
    sub     eax, ecx
    shl     eax, 4                          ; H^k's place in the tables
    vpxor   xmm9, xmm9, xmm9
    vpxor   xmm10, xmm10, xmm10
    vpxor   xmm11, xmm11, xmm11
    vmovdqu xmm0, [rsi]
    vpshufb xmm0, xmm0, xmm13
    vpxor   xmm0, xmm0, xmm14               ; the accumulator into the batch's first block
    jmp     .multiply
.next:
    vmovdqu xmm0, [rsi]
    vpshufb xmm0, xmm0, xmm13
.multiply:
    vpshufd xmm1, xmm0, 0x4E
    vpxor   xmm1, xmm1, xmm0
    vpclmulqdq xmm2, xmm0, [rbx + httpasm_aes_gcm_key.htable + rax], 0x00
    vpxor   xmm9, xmm9, xmm2
    vpclmulqdq xmm2, xmm0, [rbx + httpasm_aes_gcm_key.htable + rax], 0x11
    vpxor   xmm10, xmm10, xmm2
    vpclmulqdq xmm1, xmm1, [rbx + httpasm_aes_gcm_key.hkara + rax], 0x00
    vpxor   xmm11, xmm11, xmm1
    add     rsi, 16
    add     eax, 16
    dec     ecx
    jnz     .next
    vpxor   xmm11, xmm11, xmm9
    vpxor   xmm11, xmm11, xmm10
    vpslldq xmm12, xmm11, 8
    vpsrldq xmm11, xmm11, 8
    vpxor   xmm9, xmm9, xmm12
    vpxor   xmm10, xmm10, xmm11
    GCM_REDUCE_VX xmm10, xmm9, xmm11, xmm12
    vmovdqa xmm14, xmm9
    jmp     .batch
.done:
    ret

; -----------------------------------------------------------------------------
; gcm_crypt_vaes: one seal or open with VAES and VPCLMULQDQ; the tag into [request + GR_TAG].
;   In: rdi = the key, rsi = the request. Keeps rbx, rbp, r12-r15. The frame is wiped and
;   vzeroall clears every YMM register (keystream, round keys, H) before returning.
; -----------------------------------------------------------------------------
CX_TAIL     equ 0                           ; the last octets (under 256), padded with zeros
CX_PART     equ CX_TAIL + 256               ; the AAD's last octets, then the lengths block
CX_EJ0      equ CX_PART + 16
CX_END      equ CX_EJ0 + 16
CX_FRAME    equ CX_END + 8                  ; six pushes + the frame: rsp 16-byte aligned

align 16
gcm_crypt_vaes:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, CX_FRAME
    mov     rbx, rdi
    mov     rbp, rsi
    vbroadcasti128 ymm13, [rel gcm_bswap]
    vpxor   xmm14, xmm14, xmm14
    ; J0 = nonce || 1, E_K(J0), and the first two counters J0 + 1, J0 + 2 (reversed).
    mov     rax, [rbp + GR_NONCE]
    vmovq   xmm0, [rax]
    vpinsrd xmm0, xmm0, [rax + 8], 2
    mov     ecx, 0x01000000
    vpinsrd xmm0, xmm0, ecx, 3
    vpshufb xmm15, xmm0, xmm13
    GCM_VX_BLOCK xmm0
    vmovdqu [rsp + CX_EJ0], xmm0
    vpaddd  xmm15, xmm15, [rel gcm_one]
    vpaddd  xmm1, xmm15, [rel gcm_one]
    vinserti128 ymm15, ymm15, xmm1, 1
    ; The AAD: whole blocks, then its last octets padded.
    mov     rsi, [rbp + GR_AAD]
    mov     rdx, [rbp + GR_AADLEN]
    shr     rdx, 4
    call    gcm_ghash_vx
    mov     rcx, [rbp + GR_AADLEN]
    and     ecx, 15
    jz      .aad_done
    vpxor   xmm0, xmm0, xmm0
    vmovdqu [rsp + CX_PART], xmm0
    lea     rdi, [rsp + CX_PART]
    mov     rsi, [rbp + GR_AADLEN]
    and     rsi, -16
    add     rsi, [rbp + GR_AAD]
    call    gcm_copy_vx
    lea     rsi, [rsp + CX_PART]
    mov     edx, 1
    call    gcm_ghash_vx
.aad_done:
    xor     r12d, r12d
    mov     r13, [rbp + GR_LEN]
    mov     r14, [rbp + GR_IN]
    mov     r15, [rbp + GR_OUT]
    cmp     r13, 256
    jb      .tail
    cmp     byte [rbp + GR_OPEN], 0
    jne     .open_steps
    ; seal: the first step has nothing written to hash yet.
    GCM_VX_ITER 0, none, r14, r15
    add     r12, 256
    sub     r13, 256
.seal_steps:
    cmp     r13, 256
    jb      .seal_pending
    lea     r10, [r15 + r12 - 256]          ; the step before's ciphertext
    lea     rsi, [r14 + r12]
    lea     rdi, [r15 + r12]
    GCM_VX_ITER 1, r10, rsi, rdi
    add     r12, 256
    sub     r13, 256
    jmp     .seal_steps
.seal_pending:
    lea     rsi, [r15 + r12 - 256]          ; the last step's ciphertext
    mov     edx, 16
    call    gcm_ghash_vx
    jmp     .tail
.open_steps:
    cmp     r13, 256
    jb      .tail
    lea     r10, [r14 + r12]                ; open: the step's own ciphertext, read first
    lea     rdi, [r15 + r12]
    GCM_VX_ITER 1, r10, r10, rdi
    add     r12, 256
    sub     r13, 256
    jmp     .open_steps
.tail:
    test    r13, r13
    jz      .lengths
    ; Under 256 octets left: through the zeroed buffer, one counter-mode step, one GHASH.
    vpxor   xmm0, xmm0, xmm0
%assign j 0
%rep 8
    vmovdqu [rsp + CX_TAIL + 32 * j], ymm0
  %assign j j + 1
%endrep
    lea     rdi, [rsp + CX_TAIL]
    lea     rsi, [r14 + r12]
    mov     rcx, r13
    call    gcm_copy_vx
    cmp     byte [rbp + GR_OPEN], 0
    je      .tail_crypt
    lea     rsi, [rsp + CX_TAIL]            ; open: the ciphertext, padded with zeros
    lea     rdx, [r13 + 15]
    shr     rdx, 4
    call    gcm_ghash_vx
.tail_crypt:
    lea     rsi, [rsp + CX_TAIL]
    GCM_VX_ITER 0, none, rsi, rsi
    lea     rdi, [r15 + r12]
    lea     rsi, [rsp + CX_TAIL]
    mov     rcx, r13
    call    gcm_copy_vx
    cmp     byte [rbp + GR_OPEN], 0
    jne     .lengths
    vpxor   xmm0, xmm0, xmm0                ; seal: the ciphertext's octets, padded with zeros
%assign j 0
%rep 8
    vmovdqu [rsp + CX_TAIL + 32 * j], ymm0
  %assign j j + 1
%endrep
    lea     rdi, [rsp + CX_TAIL]
    lea     rsi, [r15 + r12]
    mov     rcx, r13
    call    gcm_copy_vx
    lea     rsi, [rsp + CX_TAIL]
    lea     rdx, [r13 + 15]
    shr     rdx, 4
    call    gcm_ghash_vx
.lengths:
    mov     rax, [rbp + GR_AADLEN]          ; the lengths block, in bits, big-endian
    shl     rax, 3
    bswap   rax
    mov     [rsp + CX_PART], rax
    mov     rax, [rbp + GR_LEN]
    shl     rax, 3
    bswap   rax
    mov     [rsp + CX_PART + 8], rax
    lea     rsi, [rsp + CX_PART]
    mov     edx, 1
    call    gcm_ghash_vx
    vpshufb xmm14, xmm14, xmm13
    vpxor   xmm14, xmm14, [rsp + CX_EJ0]
    mov     rax, [rbp + GR_TAG]
    vmovdqu [rax], xmm14
    vpxor   xmm0, xmm0, xmm0                ; wipe the frame (16 octets a step, a loop: see
    xor     eax, eax                        ; gcm_crypt_v1)
.wipe:
    vmovdqu [rsp + rax], xmm0
    add     eax, 16
    cmp     eax, CX_END
    jb      .wipe
    vzeroall
    add     rsp, CX_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; =============================================================================
; The C ABI.
; =============================================================================

; -----------------------------------------------------------------------------
; int httpasm_aes_gcm_init(httpasm_aes_gcm_key *k, const uint8_t *key, size_t length)
;   The AES key (httpasm_aes_init: 16 or 32 octets, else -1 and k untouched), H = E_K(0), and
;   the powers H^16 .. H^1 for the carry-less versions, by PCLMULQDQ where the CPU has it.
; -----------------------------------------------------------------------------
global httpasm_aes_gcm_init:function (httpasm_aes_gcm_init.end - httpasm_aes_gcm_init)
align 16
httpasm_aes_gcm_init:
    push    rbx
    sub     rsp, 16                         ; a zero block; one push + 16 keep rsp aligned
    mov     rbx, rdi
    call    httpasm_aes_init                ; k's AES key is at offset 0
    test    eax, eax
    jnz     .out                            ; -1: nothing written
    pxor    xmm0, xmm0
    movdqu  [rsp], xmm0
    mov     rdi, rbx
    mov     rsi, rsp
    lea     rdx, [rbx + httpasm_aes_gcm_key.h]
    call    httpasm_aes_encrypt_block       ; H = E_K(0^128)
    mov     rdi, rbx
    HA_CPU_PICK HTTPASM_CPU_CLMUL | HTTPASM_CPU_V2, .clmul
    call    gcm_powers_v1
    xor     eax, eax
    jmp     .out
.clmul:
    call    gcm_powers_clmul
    xor     eax, eax
.out:
    add     rsp, 16
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_aes_gcm_seal(const httpasm_aes_gcm_key *k, const uint8_t nonce[12],
;                          const uint8_t *aad, size_t aad_length, const uint8_t *in,
;                          size_t length, uint8_t *out, uint8_t tag[16])
;   Returns 0, or -1 when length > 2^36 - 32 or aad_length > 2^61 - 1 (nothing written).
; -----------------------------------------------------------------------------
GS_REQUEST  equ 0
GS_FRAME    equ GR_SIZE + 8                 ; the request; + 8 so rsp is aligned for the call
GS_ARGS     equ GS_FRAME + 8                ; the caller's stack arguments: out, then tag

global httpasm_aes_gcm_seal:function (httpasm_aes_gcm_seal.end - httpasm_aes_gcm_seal)
align 16
httpasm_aes_gcm_seal:
    mov     rax, 0xFFFFFFFE0                ; 2^36 - 32: SP 800-38D's limit on the text (5.2.1.1)
    cmp     r9, rax
    ja      .refused
    mov     rax, 0x1FFFFFFFFFFFFFFF         ; 2^61 - 1 octets: len(A) fits 64 bits of bits
    cmp     rcx, rax
    ja      .refused
    sub     rsp, GS_FRAME
    mov     [rsp + GR_NONCE], rsi
    mov     [rsp + GR_AAD], rdx
    mov     [rsp + GR_AADLEN], rcx
    mov     [rsp + GR_IN], r8
    mov     [rsp + GR_LEN], r9
    mov     rax, [rsp + GS_ARGS]
    mov     [rsp + GR_OUT], rax
    mov     rax, [rsp + GS_ARGS + 8]
    mov     [rsp + GR_TAG], rax
    mov     byte [rsp + GR_OPEN], 0
    mov     rsi, rsp
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_VAES | HTTPASM_CPU_VCLMUL | HTTPASM_CPU_AESNI | HTTPASM_CPU_CLMUL, .vaes
    HA_CPU_PICK HTTPASM_CPU_AESNI | HTTPASM_CPU_CLMUL | HTTPASM_CPU_V2, .ni
    call    gcm_crypt_v1
    jmp     .sealed
.vaes:
    call    gcm_crypt_vaes
    jmp     .sealed
.ni:
    call    gcm_crypt_ni
.sealed:
    add     rsp, GS_FRAME
    xor     eax, eax
    ret
.refused:
    mov     eax, -1
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_aes_gcm_open(const httpasm_aes_gcm_key *k, const uint8_t nonce[12],
;                          const uint8_t *aad, size_t aad_length, const uint8_t *in,
;                          size_t length, const uint8_t tag[16], uint8_t *out)
;   Decrypts while hashing, then compares the computed tag with tag: the sixteen differences
;   or-ed together whatever they are (pcmpeqb, pmovmskb). On a mismatch out[0..length) is
;   zeroed and -1 returned; 0 otherwise. The limits as seal's (nothing written past them).
; -----------------------------------------------------------------------------
GO_TAG      equ GR_SIZE                     ; the computed tag
GO_FRAME    equ GR_SIZE + 16 + 8            ; + 8: aligned for the call
GO_ARGS     equ GO_FRAME + 8                ; the caller's stack arguments: tag, then out

global httpasm_aes_gcm_open:function (httpasm_aes_gcm_open.end - httpasm_aes_gcm_open)
align 16
httpasm_aes_gcm_open:
    mov     rax, 0xFFFFFFFE0
    cmp     r9, rax
    ja      .refused
    mov     rax, 0x1FFFFFFFFFFFFFFF
    cmp     rcx, rax
    ja      .refused
    sub     rsp, GO_FRAME
    mov     [rsp + GR_NONCE], rsi
    mov     [rsp + GR_AAD], rdx
    mov     [rsp + GR_AADLEN], rcx
    mov     [rsp + GR_IN], r8
    mov     [rsp + GR_LEN], r9
    mov     rax, [rsp + GO_ARGS + 8]
    mov     [rsp + GR_OUT], rax
    lea     rax, [rsp + GO_TAG]
    mov     [rsp + GR_TAG], rax
    mov     byte [rsp + GR_OPEN], 1
    mov     rsi, rsp
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_VAES | HTTPASM_CPU_VCLMUL | HTTPASM_CPU_AESNI | HTTPASM_CPU_CLMUL, .vaes
    HA_CPU_PICK HTTPASM_CPU_AESNI | HTTPASM_CPU_CLMUL | HTTPASM_CPU_V2, .ni
    call    gcm_crypt_v1
    jmp     .compare
.vaes:
    call    gcm_crypt_vaes
    jmp     .compare
.ni:
    call    gcm_crypt_ni
.compare:
    mov     rax, [rsp + GO_ARGS]            ; the tag given
    movdqu  xmm0, [rax]
    movdqu  xmm1, [rsp + GO_TAG]
    pcmpeqb xmm0, xmm1
    pmovmskb eax, xmm0
    pxor    xmm1, xmm1
    movdqu  [rsp + GO_TAG], xmm1            ; the computed tag wiped either way
    cmp     eax, 0xFFFF
    je      .match
    ; A mismatch: no unauthenticated plaintext may stay. (The comparison above took the same
    ; instructions whichever octets differed; this branch only says that some did.)
    mov     rdi, [rsp + GR_OUT]
    mov     rcx, [rsp + GR_LEN]
    xor     eax, eax
    rep     stosb
    add     rsp, GO_FRAME
    mov     eax, -1
    ret
.match:
    add     rsp, GO_FRAME
    xor     eax, eax
    ret
.refused:
    mov     eax, -1
    ret
.end:
