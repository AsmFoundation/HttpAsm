; =============================================================================
; crypto/mlkem.asm - ML-KEM (FIPS 203, August 2024), the post-quantum key encapsulation TLS 1.3
; combines with X25519 (RFC 10024's X25519MLKEM768, the hybrid browsers send by default) and with
; P-256 and P-384 (SecP256r1MLKEM768, SecP384r1MLKEM1024): the C ABI's httpasm_mlkem512_*,
; httpasm_mlkem768_* and httpasm_mlkem1024_* (keypair from a 64-octet seed, encapsulation with a
; caller's 32-octet message, decapsulation), each with FIPS 203 7.2's and 7.3's input checks.
;
; Two versions, chosen once a call by the C ABI's functions (MK_PUBLIC): v1, every routine in
; plain scalar code over 16-bit coefficients (the library's own reference), and v3 in AVX2 (its
; section below says how: sixteen coefficients a register, four Keccak states at once for the
; matrix and the noise). Both compute the same octets. Arithmetic modulo q = 3329 as in the
; CRYSTALS-Kyber reference code's design (Montgomery products with R = 2^16, Barrett reduction,
; the NTT's zetas in Montgomery form), written here from FIPS 203's algorithms:
;   - NTT (Algorithm 9) and its inverse (Algorithm 10) in place, FIPS 203's coefficient order;
;     the inverse ends with a product by 1441 = R^2 / 128, so it returns its result times R
;     (Montgomery form), undoing the R^-1 every base-case product leaves;
;   - MultiplyNTTs (Algorithms 11, 12) as base-case products of coefficient pairs, summed over a
;     vector (the matrix-vector products) in one pass, each result times R^-1;
;   - SampleNTT (Algorithm 7) from SHAKE128, SamplePolyCBD (Algorithm 8) for eta 2 and 3 from
;     SHAKE256 (PRF), ByteEncode / ByteDecode (Algorithms 5, 6), Compress / Decompress (4.2.1):
;     Compress_d(x) = ((2^d x + 1664) * 10321340) >> 35 masked to d bits, an exact division by q
;     for every x below q at d = 1, 4, 5, 10, 11 (checked exhaustively when written), and
;     Decompress_d(y) = (q y + 2^(d - 1)) >> d.
; No constant is typed in: the zetas (17^BitRev7(i) R mod q, centred) are computed by the
; preprocessor.
;
; The hashes are crypto/sha3.asm's C ABI (G = SHA3-512, H = SHA3-256, J = SHAKE256 to 32 octets,
; PRF = SHAKE256(s || N), XOF = SHAKE128(rho || j || i)), and at v3 its four-state permutation.
; v1 never stores the matrix A whole: each row (key generation) or column (encryption: A
; transposed) is sampled when its product needs it; v3 samples four entries at a time and keeps
; all of A for k = 2 and 3.
;
; Constant time in the secrets (the seed, s, e, the message, r, y, the decrypted m'): no branch or
; address depends on them; the decapsulation compares the re-encrypted ciphertext with the one it
; was given by OR-ing their XORs, and picks K' or J(z || c) by mask (implicit rejection). Only
; public data steers branches: rejection sampling (rho), the input checks (the keys).
; Stack: a call goes up to 11,048 octets deep at v1 (ML-KEM-1024's decapsulation: 14 polynomials
; and the ciphertext) and 20,800 at v3 (the caches, four Keccak states and their octets, the
; matrix), callees included (tests/native/stack measures each), touched every 4032 octets on the
; way down (MK_ENTER); everything but v3's matrix (public) is wiped before a function returns.
; =============================================================================
default rel
%include "httpasm_core.inc"

extern httpasm_shake128_init               ; crypto/sha3.asm's C ABI: the XOF, the PRF, J,
extern httpasm_sha3_update                 ; G and H
extern httpasm_shake_squeeze
extern httpasm_shake256_init
extern httpasm_shake256
extern httpasm_sha3_256
extern httpasm_sha3_512
extern ha_keccak_f1600_x4_v3                ; four Keccak states at once (v3's batches)

%define MK_Q 3329

section .rodata
align 64
; zetas[i] = 17^BitRev7(i) * 2^16 mod q, centred in (-q/2, q/2] (FIPS 203 4.3's zeta^BitRev7(i),
; in Montgomery form): index 1..127 for the NTT's layers, 64..127 for the base-case products.
mk_zetas:
%assign zi 0
%rep 128
  %assign zbr 0
  %assign zbv zi
  %rep 7
    %assign zbr (zbr << 1) | (zbv & 1)
    %assign zbv zbv >> 1
  %endrep
  %assign zpw 1
  %rep zbr
    %assign zpw (zpw * 17) % MK_Q
  %endrep
  %assign zmf (zpw * 65536) % MK_Q
  %if zmf > MK_Q / 2
    %assign zmf zmf - MK_Q
  %endif
    dw          zmf
  %assign zi zi + 1
%endrep

section .text

; MK_MONT: eax = montgomery_reduce(eax), eax a signed product below 2^15 q in magnitude: the
; low 16 bits of eax * q^-1 (-3327 is q^-1 mod 2^16), times q, subtracted, the low half then
; zero, so the shift is exact: a result below q in magnitude. Clobbers edx.
%macro MK_MONT 0
    imul        edx, eax, -3327
    movsx       edx, dx
    imul        edx, edx, MK_Q
    sub         eax, edx
    sar         eax, 16
%endmacro

; MK_BARRETT: eax = a - round(a / q) q for a signed 16-bit a in eax (20159 = round(2^26 / q)):
; a result in [-(q - 1) / 2, (q - 1) / 2]. Clobbers edx.
%macro MK_BARRETT 0
    imul        edx, eax, 20159
    add         edx, 1 << 25
    sar         edx, 26
    imul        edx, edx, MK_Q
    sub         eax, edx
%endmacro

; MK_CANON: eax (a Barrett result, or anything in (-q, q)) into [0, q): q added when negative.
; Clobbers edx.
%macro MK_CANON 0
    mov         edx, eax
    sar         edx, 31
    and         edx, MK_Q
    add         eax, edx
%endmacro

; -----------------------------------------------------------------------------
; mk_ntt_v1: rdi = a polynomial (256 int16) -> its NTT (FIPS 203 Algorithm 9) in place, then
; reduced: coefficients in [-(q - 1) / 2, (q - 1) / 2]. Inputs below q in magnitude (each layer
; adds less than q: below 8q < 2^15 before the reduction).
;   Keeps rbx, rbp, r12-r15, rdi; clobbers rax, rcx, rdx, rsi, r8-r11, the flags.
; -----------------------------------------------------------------------------
align 16
mk_ntt_v1:
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    lea         r14, [rel mk_zetas]
    mov         r15d, 1                     ; the next zeta
    mov         ebp, 128                    ; len
.layer:
    xor         r12d, r12d                  ; start
.group:
    movsx       r13d, word [r14 + r15 * 2]
    inc         r15d
    mov         ecx, r12d                   ; j
    lea         r11d, [r12 + rbp]           ; start + len
.butterfly:
    lea         r10d, [rcx + rbp]           ; j + len
    movsx       eax, word [rdi + r10 * 2]
    imul        eax, r13d
    MK_MONT                                 ; t = zeta f[j + len]
    movsx       ebx, word [rdi + rcx * 2]
    mov         r8d, ebx
    sub         r8d, eax
    add         ebx, eax
    mov         [rdi + r10 * 2], r8w        ; f[j + len] = f[j] - t
    mov         [rdi + rcx * 2], bx         ; f[j] = f[j] + t
    inc         ecx
    cmp         ecx, r11d
    jb          .butterfly
    lea         r12d, [r12 + rbp * 2]
    cmp         r12d, 256
    jb          .group
    shr         ebp, 1
    cmp         ebp, 2
    jae         .layer
    xor         ecx, ecx
.reduce:
    movsx       eax, word [rdi + rcx * 2]
    MK_BARRETT
    mov         [rdi + rcx * 2], ax
    inc         ecx
    cmp         ecx, 256
    jb          .reduce
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret

; -----------------------------------------------------------------------------
; mk_invntt_v1: rdi = a polynomial in the NTT domain -> its inverse NTT (FIPS 203 Algorithm 10)
; times R (Montgomery form: the final product by 1441 = R^2 / 128 is the 1/128 and an R), in
; place, coefficients below q in magnitude. Each layer's sums are Barrett-reduced and its
; differences go through a Montgomery product, so no value leaves (-q, q).
;   Keeps rbx, rbp, r12-r15, rdi; clobbers rax, rcx, rdx, rsi, r8-r11, the flags.
; -----------------------------------------------------------------------------
align 16
mk_invntt_v1:
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    lea         r14, [rel mk_zetas]
    mov         r15d, 127                   ; the next zeta, downwards
    mov         ebp, 2                      ; len
.layer:
    xor         r12d, r12d                  ; start
.group:
    movsx       r13d, word [r14 + r15 * 2]
    dec         r15d
    mov         ecx, r12d
    lea         r11d, [r12 + rbp]
.butterfly:
    lea         r10d, [rcx + rbp]
    movsx       ebx, word [rdi + rcx * 2]   ; t = f[j]
    movsx       r8d, word [rdi + r10 * 2]   ; f[j + len]
    lea         eax, [rbx + r8]
    MK_BARRETT
    mov         [rdi + rcx * 2], ax         ; f[j] = t + f[j + len], reduced
    mov         eax, r8d
    sub         eax, ebx
    imul        eax, r13d
    MK_MONT
    mov         [rdi + r10 * 2], ax         ; f[j + len] = zeta (f[j + len] - t)
    inc         ecx
    cmp         ecx, r11d
    jb          .butterfly
    lea         r12d, [r12 + rbp * 2]
    cmp         r12d, 256
    jb          .group
    shl         ebp, 1
    cmp         ebp, 128
    jbe         .layer
    xor         ecx, ecx
.scale:
    movsx       eax, word [rdi + rcx * 2]
    imul        eax, eax, 1441
    MK_MONT
    mov         [rdi + rcx * 2], ax
    inc         ecx
    cmp         ecx, 256
    jb          .scale
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret

; -----------------------------------------------------------------------------
; mk_basemul_acc_v1: rdi = r, rsi = a vector of polynomials, rdx = b, ecx = k (the vectors' length;
; a vector's polynomials 512 octets apart) -> r = sum over j of MultiplyNTTs(a_j, b_j) times R^-1,
; reduced. Pair i of a product (FIPS 203 Algorithm 12, gamma = zeta^(2 BitRev7(i) + 1)): c0 =
; a0 b0 + a1 b1 gamma, c1 = a0 b1 + a1 b0, each product a Montgomery product (gamma =
; zetas[64 + i / 2] for even i, its negation for odd i: zeta^128 = -1). Each pair's sums stay
; below 2kq < 2^15 before the reduction. r may not overlap a or b.
;   Keeps rbx, rbp, r12-r15, rdi; clobbers rax, rcx, rdx, rsi, r8-r11, the flags.
; -----------------------------------------------------------------------------
align 16
mk_basemul_acc_v1:
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    lea         r14, [rel mk_zetas]
    mov         r15, rdx                    ; b (rdx is MK_MONT's)
    shl         ecx, 9                      ; k * 512: the vectors' end
    xor         r12d, r12d                  ; the pair
.pair:
    mov         eax, r12d
    shr         eax, 1
    movsx       r13d, word [r14 + rax * 2 + 128]    ; zetas[64 + i / 2]
    mov         eax, r12d
    and         eax, 1
    neg         eax                         ; odd i: all ones
    xor         r13d, eax
    sub         r13d, eax                   ; gamma (negated for odd i)
    xor         ebp, ebp                    ; c0's sum
    xor         ebx, ebx                    ; c1's sum
    xor         r11d, r11d                  ; j, in octets (512 a polynomial)
.vector:
    lea         r10, [rsi + r11]
    lea         r9, [r15 + r11]
    movsx       eax, word [r10 + r12 * 4 + 2]       ; a1 b1
    movsx       r8d, word [r9 + r12 * 4 + 2]
    imul        eax, r8d
    MK_MONT
    imul        eax, r13d                           ; times gamma
    MK_MONT
    add         ebp, eax
    movsx       eax, word [r10 + r12 * 4]           ; a0 b0
    movsx       r8d, word [r9 + r12 * 4]
    imul        eax, r8d
    MK_MONT
    add         ebp, eax
    movsx       eax, word [r10 + r12 * 4]           ; a0 b1
    movsx       r8d, word [r9 + r12 * 4 + 2]
    imul        eax, r8d
    MK_MONT
    add         ebx, eax
    movsx       eax, word [r10 + r12 * 4 + 2]       ; a1 b0
    movsx       r8d, word [r9 + r12 * 4]
    imul        eax, r8d
    MK_MONT
    add         ebx, eax
    add         r11d, 512
    cmp         r11d, ecx
    jb          .vector
    mov         eax, ebp
    MK_BARRETT
    mov         [rdi + r12 * 4], ax
    mov         eax, ebx
    MK_BARRETT
    mov         [rdi + r12 * 4 + 2], ax
    inc         r12d
    cmp         r12d, 128
    jb          .pair
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret

; -----------------------------------------------------------------------------
; mk_tomont_v1: rdi = a polynomial -> each coefficient times R (a Montgomery product by R^2 mod q
; = 1353), below q in magnitude. Keeps every register but rax, rcx, rdx and the flags.
; mk_reduce_v1: rdi = a polynomial -> each coefficient Barrett-reduced (into [-(q-1)/2, (q-1)/2]).
; Keeps every register but rax, rcx, rdx and the flags.
; -----------------------------------------------------------------------------
align 16
mk_tomont_v1:
    xor         ecx, ecx
.next:
    movsx       eax, word [rdi + rcx * 2]
    imul        eax, eax, 1353
    MK_MONT
    mov         [rdi + rcx * 2], ax
    inc         ecx
    cmp         ecx, 256
    jb          .next
    ret

align 16
mk_reduce_v1:
    xor         ecx, ecx
.next:
    movsx       eax, word [rdi + rcx * 2]
    MK_BARRETT
    mov         [rdi + rcx * 2], ax
    inc         ecx
    cmp         ecx, 256
    jb          .next
    ret

; -----------------------------------------------------------------------------
; mk_add_v1: rdi = r, rsi = a, rdx = b -> r = a + b; mk_sub_v1: r = a - b (16-bit lanes, no
; reduction: the callers keep the sums below 2^15). r may be a or b.
; Keep every register but rax, rcx, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_add_v1:
    xor         ecx, ecx
.next:
    movzx       eax, word [rsi + rcx * 2]
    add         ax, [rdx + rcx * 2]
    mov         [rdi + rcx * 2], ax
    inc         ecx
    cmp         ecx, 256
    jb          .next
    ret

align 16
mk_sub_v1:
    xor         ecx, ecx
.next:
    movzx       eax, word [rsi + rcx * 2]
    sub         ax, [rdx + rcx * 2]
    mov         [rdi + rcx * 2], ax
    inc         ecx
    cmp         ecx, 256
    jb          .next
    ret

; -----------------------------------------------------------------------------
; mk_cbd_v1: rdi = r, rsi = the PRF's 64 eta octets, edx = eta (2 or 3) -> SamplePolyCBD_eta
; (FIPS 203 Algorithm 8): coefficient i = (the sum of eta bits) - (the next eta bits' sum), from
; the octets' bits least significant first, as signed values in [-eta, eta]. Bit sums by masks
; (constant time). eta 3 reads its 24-bit groups one octet at a time (no read past the 192).
;   Keeps every register but rax, rcx, rdx, rsi, r8-r11 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_cbd_v1:
    cmp         edx, 3
    je          .eta3
    xor         r11d, r11d                  ; 32 words of 32 bits, 8 coefficients each
    mov         r10, rdi                    ; their 16 octets of coefficients
.word2:
    mov         eax, [rsi + r11 * 4]
    mov         edx, eax
    shr         edx, 1
    and         eax, 0x55555555
    and         edx, 0x55555555
    add         eax, edx                    ; 2-bit sums
  %assign kc 0
  %rep 8
    mov         ecx, eax
    shr         ecx, 4 * kc
    and         ecx, 3
    mov         r8d, eax
    shr         r8d, 4 * kc + 2
    and         r8d, 3
    sub         ecx, r8d
    mov         [r10 + 2 * kc], cx
    %assign kc kc + 1
  %endrep
    add         r10, 16
    inc         r11d
    cmp         r11d, 32
    jb          .word2
    ret
.eta3:
    xor         r11d, r11d                  ; 64 groups of 24 bits, 4 coefficients each
    xor         r10d, r10d                  ; their offset (3 a group)
.word3:
    movzx       eax, byte [rsi + r10]
    movzx       edx, byte [rsi + r10 + 1]
    shl         edx, 8
    or          eax, edx
    movzx       edx, byte [rsi + r10 + 2]
    shl         edx, 16
    or          eax, edx
    mov         edx, eax
    shr         edx, 1
    and         edx, 0x00249249
    mov         r8d, eax
    shr         r8d, 2
    and         r8d, 0x00249249
    and         eax, 0x00249249
    add         eax, edx
    add         eax, r8d                    ; 3-bit sums
  %assign kc 0
  %rep 4
    mov         ecx, eax
    shr         ecx, 6 * kc
    and         ecx, 7
    mov         r8d, eax
    shr         r8d, 6 * kc + 3
    and         r8d, 7
    sub         ecx, r8d
    mov         [rdi + r11 * 8 + 2 * kc], cx
    %assign kc kc + 1
  %endrep
    add         r10d, 3
    inc         r11d
    cmp         r11d, 64
    jb          .word3
    ret

; -----------------------------------------------------------------------------
; mk_rej_v1: rdi = where coefficients go, esi = how many are still wanted (1 or more: mk_sample
; calls it only while some are missing), rdx = SHAKE128's octets, ecx = how many (a multiple of
; 3) -> eax = how many coefficients written (at most esi): FIPS 203 Algorithm 7's loop, two
; 12-bit candidates from each 3 octets, each kept when below q. Variable time: the octets come
; from rho, which is public.
;   Keeps every register but rax, rcx, rdx, rsi, r8-r11 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_rej_v1:
    xor         eax, eax                    ; written
    xor         r8d, r8d                    ; the octet position
.next:
    lea         r9d, [r8 + 3]
    cmp         r9d, ecx
    ja          .done
    movzx       r9d, word [rdx + r8]        ; b0 + 256 b1
    and         r9d, 0xFFF                  ; d1 = b0 + 256 (b1 mod 16)
    movzx       r10d, word [rdx + r8 + 1]   ; b1 + 256 b2
    shr         r10d, 4                     ; d2 = b1 / 16 + 16 b2
    add         r8d, 3
    cmp         r9d, MK_Q
    jae         .second
    mov         [rdi + rax * 2], r9w
    inc         eax
    cmp         eax, esi
    jae         .done
.second:
    cmp         r10d, MK_Q
    jae         .next
    mov         [rdi + rax * 2], r10w
    inc         eax
    cmp         eax, esi
    jb          .next
.done:
    ret

; -----------------------------------------------------------------------------
; mk_encode12_v1: rdi = 384 octets <- ByteEncode_12 of the polynomial at rsi (reduced: each
; coefficient made canonical, [0, q), first). Keeps every register but rax, rcx, rdx, r8, r9 and
; the flags.
; mk_decode12_v1: rdi = the polynomial <- ByteDecode_12's raw 12-bit values of the 384 octets at
; rsi (below 4096: the caller checked they are below q, or they are a secret key the library
; wrote). Keeps every register but rax, rcx, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_encode12_v1:
    xor         ecx, ecx                    ; the pair
.next:
    movsx       eax, word [rsi + rcx * 4]
    MK_CANON
    mov         r8d, eax
    movsx       eax, word [rsi + rcx * 4 + 2]
    MK_CANON
    mov         r9d, eax
    lea         rax, [rcx + rcx * 2]        ; 3 octets a pair
    mov         [rdi + rax], r8b
    mov         edx, r8d
    shr         edx, 8
    mov         r8d, r9d
    shl         r8d, 4
    or          edx, r8d
    mov         [rdi + rax + 1], dl
    shr         r9d, 4
    mov         [rdi + rax + 2], r9b
    inc         ecx
    cmp         ecx, 128
    jb          .next
    ret

align 16
mk_decode12_v1:
    xor         ecx, ecx
.next:
    lea         r8, [rcx + rcx * 2]         ; 3 octets a pair
    movzx       eax, word [rsi + r8]
    and         eax, 0xFFF
    mov         [rdi + rcx * 4], ax         ; b0 + 256 (b1 mod 16)
    movzx       eax, word [rsi + r8 + 1]
    shr         eax, 4
    mov         [rdi + rcx * 4 + 2], ax     ; b1 / 16 + 16 b2
    inc         ecx
    cmp         ecx, 128
    jb          .next
    ret

; -----------------------------------------------------------------------------
; mk_check12: rdi = octets, ecx = how many polynomials' encodings (384 octets each) -> eax = 0 when
; every 12-bit value is below q (FIPS 203 7.2's modulus check: ByteEncode_12(ByteDecode_12(x))
; = x exactly then), else -1. The data is a public key: the loop may stop at the first offence.
; Keeps every register but rax, rcx, r8, r9 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_check12:
    imul        ecx, ecx, 128               ; pairs
    xor         r9d, r9d
.next:
    lea         r8, [r9 + r9 * 2]
    movzx       eax, word [rdi + r8]
    and         eax, 0xFFF
    cmp         eax, MK_Q
    jae         .bad
    movzx       eax, word [rdi + r8 + 1]
    shr         eax, 4
    cmp         eax, MK_Q
    jae         .bad
    inc         r9d
    cmp         r9d, ecx
    jb          .next
    xor         eax, eax
    ret
.bad:
    mov         eax, -1
    ret

; -----------------------------------------------------------------------------
; mk_compress_v1: rdi = 32 d octets <- ByteEncode_d(Compress_d) of the polynomial at rsi (reduced;
; made canonical first), edx = d (1, 4, 5, 10 or 11): each Compress_d(x) = ((2^d x + 1664) *
; 10321340) >> 35, masked, packed least significant bit first through a 64-bit accumulator.
;   Keeps every register but rax, rcx, rdx, rsi, rdi, r8-r11 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_compress_v1:
    mov         r11d, edx                   ; d
    xor         r8d, r8d                    ; the accumulator
    xor         r9d, r9d                    ; its bits
    xor         r10d, r10d                  ; the coefficient
.next:
    movsx       eax, word [rsi + r10 * 2]
    MK_CANON
    mov         ecx, r11d
    shl         eax, cl
    add         eax, 1664
    imul        rax, rax, 10321340
    shr         rax, 35
    mov         edx, 1
    shl         edx, cl
    dec         edx
    and         eax, edx                    ; Compress_d(x)
    mov         ecx, r9d
    shl         rax, cl
    or          r8, rax
    add         r9d, r11d
.flush:
    cmp         r9d, 8
    jb          .more
    mov         [rdi], r8b
    inc         rdi
    shr         r8, 8
    sub         r9d, 8
    jmp         .flush
.more:
    inc         r10d
    cmp         r10d, 256
    jb          .next
    ret

; -----------------------------------------------------------------------------
; mk_decompress_v1: rdi = the polynomial <- Decompress_d(ByteDecode_d) of the 32 d octets at rsi,
; edx = d: each Decompress_d(y) = (q y + 2^(d - 1)) >> d. Reads the octets one at a time (none
; past the 32 d).
;   Keeps every register but rax, rcx, rdx, rsi, rdi, r8-r11 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_decompress_v1:
    mov         r11d, edx                   ; d
    xor         r8d, r8d                    ; the accumulator
    xor         r9d, r9d                    ; its bits
    xor         r10d, r10d                  ; the coefficient
.next:
    cmp         r9d, r11d
    jae         .take
    movzx       eax, byte [rsi]
    inc         rsi
    mov         ecx, r9d
    shl         rax, cl
    or          r8, rax
    add         r9d, 8
    jmp         .next
.take:
    mov         ecx, r11d
    mov         edx, 1
    shl         edx, cl
    dec         edx
    mov         eax, r8d
    and         eax, edx                    ; y
    shr         r8, cl
    sub         r9d, r11d
    imul        eax, eax, MK_Q
    mov         edx, 1
    dec         ecx
    shl         edx, cl
    add         eax, edx
    inc         ecx
    shr         eax, cl
    mov         [rdi + r10 * 2], ax
    inc         r10d
    cmp         r10d, 256
    jb          .next
    ret

; -----------------------------------------------------------------------------
; mk_frommsg_v1: rdi = the polynomial <- Decompress_1(ByteDecode_1) of the 32 octets at rsi: each
; bit 1 gives (q + 1) / 2 = 1665, 0 gives 0, by mask (the message is secret).
; mk_tomsg_v1: rdi = 32 octets <- ByteEncode_1(Compress_1) of the polynomial at rsi (reduced).
; Keep every register but rax, rcx, rdx, r8-r10 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_frommsg_v1:
    xor         r8d, r8d                    ; the coefficient
.next:
    mov         ecx, r8d
    shr         ecx, 3
    movzx       eax, byte [rsi + rcx]
    mov         ecx, r8d
    and         ecx, 7
    shr         eax, cl
    and         eax, 1
    neg         eax
    and         eax, 1665
    mov         [rdi + r8 * 2], ax
    inc         r8d
    cmp         r8d, 256
    jb          .next
    ret

align 16
mk_tomsg_v1:
    xor         r8d, r8d                    ; the octet
.octet:
    xor         r9d, r9d                    ; its bits
    xor         r10d, r10d
.bit:
    lea         ecx, [r8 * 8 + r10]
    movsx       eax, word [rsi + rcx * 2]
    MK_CANON
    shl         eax, 1
    add         eax, 1664
    imul        rax, rax, 10321340
    shr         rax, 35
    and         eax, 1
    mov         ecx, r10d
    shl         eax, cl
    or          r9d, eax
    inc         r10d
    cmp         r10d, 8
    jb          .bit
    mov         [rdi + r8], r9b
    inc         r8d
    cmp         r8d, 32
    jb          .octet
    ret

; =============================================================================
; v3: the same routines in AVX2, sixteen 16-bit coefficients a register.
;
; Coefficients stay in FIPS 203's order everywhere but inside mk_ntt_v3 and mk_invntt_v3: their
; last three layers (lengths 8, 4, 2) pair coefficients inside a register, so they work on a
; shuffled order (two registers' 32 coefficients exchanged by vperm2i128, vpunpck{l,h}qdq and a
; dword blend, each exchange its own inverse) and shuffle back before storing. Pairs (2i, 2i + 1)
; are dwords in FIPS order, which is what the base-case products want. The layout and every
; formula below were proven in the scratchpad before this was written: a register simulation of
; the shuffles (0 mismatches against FIPS 203's NTT, inverse and products), and an emulation of
; each instruction sequence with exact 16- and 32-bit wrapping (NTT bit-exact with v1's, the
; inverse's and the products' intermediate bounds, Compress and Decompress on every input).
;
; Ranges (each layer of the forward NTT adds less than q; the inverse's sums double):
;   - mk_ntt_v3 takes coefficients below q in magnitude and returns them Barrett-reduced, the
;     same values as mk_ntt_v1 lane for lane (identical butterflies, identical Barrett);
;   - mk_basemul_acc_v3 returns values below q in magnitude (Montgomery-reduced 32-bit sums);
;   - mk_invntt_v3 takes values below q in magnitude, Barrett-reduces its sums after the third and
;     sixth layers (the only places a sum could otherwise pass 2^15 a layer later: peak 4q) and
;     returns values below q in magnitude, times R like mk_invntt_v1;
;   - the compressions take anything in (-2q, 2q) (an inverse NTT plus noise, plus a message):
;     adding 2q changes Compress_d by 2^(d+1), nothing modulo 2^d, so no reduction precedes them.
; Each routine ends with vzeroupper (the hashes between them are scalar code).
; =============================================================================

; MK_ZETA i: MKZ = zetas[i] (17^BitRev7(i) R mod q, centred, as mk_zetas holds it) and MKZQ =
; MKZ q^-1 mod 2^16, the low-half factor a Montgomery product by MKZ needs, as 16 bits.
%macro MK_ZETA 1
  %assign mzbr 0
  %assign mzbv %1
  %rep 7
    %assign mzbr (mzbr << 1) | (mzbv & 1)
    %assign mzbv mzbv >> 1
  %endrep
  %assign mzpw 1
  %rep mzbr
    %assign mzpw (mzpw * 17) % MK_Q
  %endrep
  %assign MKZ (mzpw * 65536) % MK_Q
  %if MKZ > MK_Q / 2
    %assign MKZ MKZ - MK_Q
  %endif
  %assign MKZQ (MKZ * -3327) & 0xFFFF
%endmacro

; MK3_BCAST i: zetas[i] in all sixteen lanes, then its MKZQ in all sixteen (64 octets).
%macro MK3_BCAST 1
    MK_ZETA     %1
    times 16 dw MKZ
    times 16 dw MKZQ
%endmacro

; MK3_SPREAD first, count, step: zetas[first], zetas[first + step], ... (count of them: 2, 4 or 8)
; each repeated over 16 / count lanes, then their MKZQs the same way: the per-lane zetas of the
; in-register layers (step -1: the inverse NTT's descending order).
%macro MK3_SPREAD 3
  %assign msi 0
  %rep %2
    MK_ZETA     %1 + msi * %3
    times (16 / %2) dw MKZ
    %assign msi msi + 1
  %endrep
  %assign msi 0
  %rep %2
    MK_ZETA     %1 + msi * %3
    times (16 / %2) dw MKZQ
    %assign msi msi + 1
  %endrep
%endmacro

section .rodata
align 32
mk3_q:          times 16 dw MK_Q
mk3_qinv:       times 16 dw -3327               ; q^-1 mod 2^16
mk3_v:          times 16 dw 20159               ; Barrett's round(2^26 / q)
mk3_32:         times 16 dw 32                  ; vpmulhrsw by 32 = (h + 512) >> 10: Barrett's rounding
mk3_f:          times 16 dw 1441                ; the inverse NTT's last factor, R^2 / 128 mod q
mk3_fq:         times 16 dw (1441 * -3327) & 0xFFFF
mk3_r2:         times 16 dw 1353                ; R^2 mod q: a Montgomery product by it multiplies by R
mk3_r2q:        times 16 dw (1353 * -3327) & 0xFFFF
mk3_2q:         times 16 dw 2 * MK_Q            ; the compressions' offset
mk3_qm1:        times 16 dw MK_Q - 1            ; vpcmpgtw against q - 1: "q or more"
mk3_1664:       times 16 dw 1664                ; Compress's rounding: (2^d x + 1664) / q
mk3_1665:       times 16 dw (MK_Q + 1) / 2      ; Decompress_1(1)
mk3_4095:       times 16 dw 0x0FFF
mk3_swap:       times 2 db 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13
; ByteDecode_12: lane 0 holds its 12 octets at 0-11, lane 1 (loaded 8 octets on) at 4-15; word 2p
; takes octets 3p, 3p + 1 (masked to 12 bits), word 2p + 1 octets 3p + 1, 3p + 2 (shifted by 4)
mk3_d12s:       db 0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11
                db 4, 5, 5, 6, 7, 8, 8, 9, 10, 11, 11, 12, 13, 14, 14, 15
; ByteEncode_12: x0 + 4096 x1 per dword (vpmaddwd), each dword's three low octets together per
; lane, then the lanes' twelve octets together (vpermd)
mk3_e12m:       times 8 dw 1, 4096
mk3_e12s:       times 2 db 0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0x80, 0x80, 0x80, 0x80
mk3_e12p:       dd 0, 1, 2, 4, 5, 6, 7, 7
; the compressions' quotient estimates, floor(2^(15 + d) / q) (rounded down: the estimate is the
; quotient or one less, never more), and their d-bit masks
mk3_m1:         times 16 dw (1 << 16) / MK_Q
mk3_m4:         times 16 dw (1 << 19) / MK_Q
mk3_m5:         times 16 dw (1 << 20) / MK_Q
mk3_m10:        times 16 dw (1 << 25) / MK_Q
mk3_m11:        times 16 dw (1 << 26) / MK_Q
mk3_mask1:      times 16 dw 1
mk3_mask4:      times 16 dw 15
mk3_mask5:      times 16 dw 31
mk3_mask10:     times 16 dw 1023
mk3_mask11:     times 16 dw 2047
; ByteEncode_4: nibble pairs (vpmaddubsw by 1, 16), then dwords back in order
mk3_c4n:        times 16 db 1, 16
mk3_c4p:        dd 0, 4, 1, 5, 2, 6, 3, 7
; ByteEncode_5/10/11: pairs into dwords (vpmaddwd by 1, 2^d), dword pairs into qwords (the even
; dword shifted to its top, then the qword right: 4 d bits a qword)
mk3_c5m:        times 8 dw 1, 32
mk3_c5s:        times 4 dd 22, 0
mk3_c10m:       times 8 dw 1, 1024
mk3_c10s:       times 4 dd 12, 0
mk3_c10b:       times 2 db 0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
mk3_c11m:       times 8 dw 1, 2048
mk3_c11s:       times 4 dd 10, 0
mk3_c11r:       times 2 dq 0, 20
; ByteDecode_4 + Decompress_4: each octet into two words (masked to their nibble), both scaled
; to y << 11 for vpmulhrsw by q
mk3_dc4s:       db 0, 0x80, 0, 0x80, 1, 0x80, 1, 0x80, 2, 0x80, 2, 0x80, 3, 0x80, 3, 0x80
                db 4, 0x80, 4, 0x80, 5, 0x80, 5, 0x80, 6, 0x80, 6, 0x80, 7, 0x80, 7, 0x80
mk3_dc4m:       times 8 dw 0x000F, 0x00F0
mk3_dc4k:       times 8 dw 2048, 128
; ByteDecode_5 + Decompress_5: word i of a lane takes octets floor(5i / 8) and the next (lane 1's
; five octets sit at 3-7: loaded 2 on), shifted by 10 - (5i mod 8) (vpmullw) to bits 10-14
mk3_dc5s:       db 0, 1, 0, 1, 1, 2, 1, 2, 2, 3, 3, 4, 3, 4, 4, 5
                db 3, 4, 3, 4, 4, 5, 4, 5, 5, 6, 6, 7, 6, 7, 7, 8
mk3_dc5k:       times 2 dw 1024, 32, 256, 8, 64, 512, 16, 128
mk3_dc5m:       times 16 dw 0x7C00
; ByteDecode_10 + Decompress_10: word i takes octets floor(10i / 8) and the next (lane 1's ten
; at 6-15: loaded 4 on), shifted by 6 - (10i mod 8) to bits 6-15, masked, halved: y << 5
mk3_dc10s:      db 0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9
                db 6, 7, 7, 8, 8, 9, 9, 10, 11, 12, 12, 13, 13, 14, 14, 15
mk3_dc10k:      times 4 dw 64, 16, 4, 1
mk3_dc10m:      times 16 dw 0xFFC0
; ByteDecode_11 + Decompress_11: dword j of a lane takes the four octets from floor(22j / 8)
; (lane 1's eleven at 5-15: loaded 6 on), shifted right by 22j mod 8: two coefficients from bit 0
mk3_dc11s:      db 0, 1, 2, 3, 2, 3, 4, 5, 5, 6, 7, 8, 8, 9, 10, 0x80
                db 5, 6, 7, 8, 7, 8, 9, 10, 10, 11, 12, 13, 13, 14, 15, 0x80
mk3_dc11r:      times 2 dd 0, 6, 4, 2
mk3_dc11lo:     times 8 dd 0x00007FF0
mk3_dc11hi:     times 8 dd 0x7FF00000
; Decompress_1 of a message: lane i tests bit i of the broadcast 16 bits
mk3_bits:       dw 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768
; SamplePolyCBD: bit-pair and bit-triple sums
mk3_x55:        times 32 db 0x55
mk3_x33:        times 32 db 0x33
mk3_x0f:        times 32 db 0x0F
mk3_x44:        times 32 db 0x44
mk3_x04:        times 32 db 0x04
mk3_cbd3s:      db 0, 1, 2, 0x80, 3, 4, 5, 0x80, 6, 7, 8, 0x80, 9, 10, 11, 0x80
                db 4, 5, 6, 0x80, 7, 8, 9, 0x80, 10, 11, 12, 0x80, 13, 14, 15, 0x80
mk3_x249:       times 8 dd 0x00249249
mk3_x1c7:       times 8 dd 0x001C71C7
mk3_x104:       times 8 dd 0x00104104       ; 4 in each coefficient's 6-bit slot (bit 2 is free)
mk3_cbd3d:      dd 0, 0, 1, 1, 2, 2, 3, 3
mk3_cbd3e:      dd 4, 4, 5, 5, 6, 6, 7, 7
mk3_cbd3r:      times 4 dd 0, 12
mk3_x7:         times 8 dd 0x00000007
mk3_x70000:     times 8 dd 0x00070000
mk3_w4:         times 16 dw 4

; The forward NTT's zetas in the order mk_ntt_v3 reads them: pass 1 (layers 1 and 2: zetas 1, 2,
; 3), then per quarter q (64 coefficients): layer 3's zeta 4 + q, layer 4's 8 + 2q and 9 + 2q,
; then for each of the quarter's two register pairs t = 2q, 2q + 1 the in-register layers: layer
; 5 (zetas 16 + 2t, 17 + 2t, eight lanes each), 6 (32 + 4t .. 35 + 4t, four each), 7 (64 + 8t ..
; 71 + 8t, two each). Each as a vector of zetas and one of their MKZQs.
align 32
mk3_nttz:
    MK3_BCAST   1
    MK3_BCAST   2
    MK3_BCAST   3
%assign nq 0
%rep 4
    MK3_BCAST   4 + nq
    MK3_BCAST   8 + 2 * nq
    MK3_BCAST   9 + 2 * nq
  %assign nt 2 * nq
  %rep 2
    MK3_SPREAD  16 + 2 * nt, 2, 1
    MK3_SPREAD  32 + 4 * nt, 4, 1
    MK3_SPREAD  64 + 8 * nt, 8, 1
    %assign nt nt + 1
  %endrep
  %assign nq nq + 1
%endrep

; The inverse NTT's (FIPS 203 Algorithm 10: zetas from 127 down): per quarter q, for each register
; pair t = 2q, 2q + 1 the in-register layers (length 2: zetas 127 - 8t down, two lanes each;
; length 4: 63 - 4t down, four each; length 8: 31 - 2t, 30 - 2t, eight each), then length 16's
; 15 - 2q and 14 - 2q, length 32's 7 - q; then pass 2: length 64's 3 and 2, length 128's 1.
align 32
mk3_inttz:
%assign nq 0
%rep 4
  %assign nt 2 * nq
  %rep 2
    MK3_SPREAD  127 - 8 * nt, 8, -1
    MK3_SPREAD  63 - 4 * nt, 4, -1
    MK3_SPREAD  31 - 2 * nt, 2, -1
    %assign nt nt + 1
  %endrep
    MK3_BCAST   15 - 2 * nq
    MK3_BCAST   14 - 2 * nq
    MK3_BCAST   7 - nq
  %assign nq nq + 1
%endrep
    MK3_BCAST   3
    MK3_BCAST   2
    MK3_BCAST   1

; The base-case products' gammas for mk_mulcache_v3, per register v (pairs 8v .. 8v + 7): each
; pair's dword holds R mod q (centred) in its low word and gamma_i = +/- zetas[64 + i / 2] (FIPS
; 203 Algorithm 11's zeta^(2 BitRev7(i) + 1), negated for odd i as mk_basemul_acc_v1 does) in its
; high word; then the MKZQs of the same 16 words. A Montgomery product by R mod q is a value
; congruent to the input: b0's lane keeps b0 (mod q) while b1's becomes b1 gamma.
%assign mkr 65536 % MK_Q
%if mkr > MK_Q / 2
  %assign mkr mkr - MK_Q
%endif
align 32
mk3_gamma:
%assign gv 0
%rep 16
  %assign gp 0
  %rep 8
    MK_ZETA     64 + 4 * gv + gp / 2
    %if gp & 1
      %assign MKZ -MKZ
    %endif
    dw          mkr, MKZ
    %assign gp gp + 1
  %endrep
  %assign gp 0
  %rep 8
    MK_ZETA     64 + 4 * gv + gp / 2
    %if gp & 1
      %assign MKZ -MKZ
    %endif
    dw          (mkr * -3327) & 0xFFFF, (MKZ * -3327) & 0xFFFF
    %assign gp gp + 1
  %endrep
  %assign gv gv + 1
%endrep

; mk_rej_v3's compaction: for each 8-bit mask of accepted candidates (eight 16-bit words), the
; vpshufb indices that gather the accepted words to the bottom, in order; 0x80 (zero) after them.
align 16
mk3_rejtab:
%assign rm 0
%rep 256
  %assign rb 0
  %assign rn 0
  %rep 8
    %if (rm >> rb) & 1
    db          2 * rb, 2 * rb + 1
      %assign rn rn + 1
    %endif
    %assign rb rb + 1
  %endrep
  %if rn < 8
    times (2 * (8 - rn)) db 0x80
  %endif
  %assign rm rm + 1
%endrep

section .text

; MK3_CT a, b, z, zq: FIPS 203 Algorithm 9's butterfly on sixteen lanes: t = zeta b R^-1 (|t| < q),
; b = a - t, a = a + t. zq = zeta q^-1 mod 2^16 folds q^-1 into the low half's product, so the
; Montgomery product is three multiplications: the low halves of b zq and of (b zq) q cancel
; exactly, which makes the high halves' difference MK_MONT's result, lane for lane. z and zq may
; be memory operands. Clobbers ymm14; ymm15 = 16 x q.
%macro MK3_CT 4
    vpmullw     ymm14, %2, %4
    vpmulhw     %2, %2, %3
    vpmulhw     ymm14, ymm14, ymm15
    vpsubw      ymm14, %2, ymm14
    vpsubw      %2, %1, ymm14
    vpaddw      %1, %1, ymm14
%endmacro

; MK3_GS a, b, z, zq: Algorithm 10's butterfly: a = a + b, b = zeta (b - a) R^-1. Clobbers ymm14.
%macro MK3_GS 4
    vpsubw      ymm14, %2, %1
    vpaddw      %1, %1, %2
    vpmullw     %2, ymm14, %4
    vpmulhw     ymm14, ymm14, %3
    vpmulhw     %2, %2, ymm15
    vpsubw      %2, ymm14, %2
%endmacro

; MK3_BARRETT x: x - round(x / q) q per lane, exactly MK_BARRETT's: floor((x 20159 + 2^25) / 2^26)
; = floor((floor(x 20159 / 2^16) + 512) / 1024), the second step being vpmulhrsw by 32.
; ymm13 = 16 x 20159, ymm12 = 16 x 32; clobbers ymm14.
%macro MK3_BARRETT 1
    vpmulhw     ymm14, %1, ymm13
    vpmulhrsw   ymm14, ymm14, ymm12
    vpmullw     ymm14, ymm14, ymm15
    vpsubw      %1, %1, ymm14
%endmacro

; MK3_MULC x, c, cq: x = x c R^-1 (a Montgomery product by a constant; cq = c q^-1 mod 2^16).
; Clobbers ymm14.
%macro MK3_MULC 3
    vpmullw     ymm14, %1, %3
    vpmulhw     %1, %1, %2
    vpmulhw     ymm14, ymm14, ymm15
    vpsubw      %1, %1, ymm14
%endmacro

; MK3_NTT_TAIL r0, r1, zetas: layers 5, 6 and 7 of two registers (32 coefficients, FIPS order),
; then the Barrett reduction, and back to FIPS order in r0, r1. Layer 5 pairs coefficients 8
; apart: X = r0.lo | r1.lo, Y = r0.hi | r1.hi puts each pair in the same lane of X and Y; layer 6
; (4 apart) exchanges their odd and even qwords, layer 7 (2 apart) their odd and even dwords. The
; last exchange leaves pairs (dwords) 0, 2, .., 14 in X and 1, 3, .., 15 in Y; unpacking dwords
; and swapping lanes restores the order. Uses ymm4-ymm7, ymm12-ymm15.
%macro MK3_NTT_TAIL 3
    vperm2i128  ymm4, %1, %2, 0x20
    vperm2i128  ymm5, %1, %2, 0x31
    MK3_CT      ymm4, ymm5, [%3], [%3 + 32]
    vpunpcklqdq ymm6, ymm4, ymm5
    vpunpckhqdq ymm7, ymm4, ymm5
    MK3_CT      ymm6, ymm7, [%3 + 64], [%3 + 96]
    vpshufd     ymm4, ymm7, 0xA0                ; Y's even dwords, each twice
    vpblendd    ymm4, ymm6, ymm4, 0xAA          ; X's even dwords, Y's even dwords between them
    vpsrlq      ymm6, ymm6, 32                  ; X's odd dwords down
    vpblendd    ymm5, ymm6, ymm7, 0xAA          ; X's odd dwords, Y's odd dwords between them
    MK3_CT      ymm4, ymm5, [%3 + 128], [%3 + 160]
    MK3_BARRETT ymm4
    MK3_BARRETT ymm5
    vpunpckldq  ymm6, ymm4, ymm5
    vpunpckhdq  ymm7, ymm4, ymm5
    vperm2i128  %1, ymm6, ymm7, 0x20
    vperm2i128  %2, ymm6, ymm7, 0x31
%endmacro

; MK3_INTT_HEAD r0, r1, zetas: the inverse's first three layers (lengths 2, 4, 8) on two registers
; in FIPS order: into the forward tail's shuffled order (lane swap, then the even and odd dwords
; apart), the three layers with the same exchanges undone in reverse, layer 3's sums Barrett-
; reduced, and the lane swap that leaves r0, r1 in FIPS order. Uses ymm4-ymm7, ymm12-ymm15.
%macro MK3_INTT_HEAD 3
    vperm2i128  ymm6, %1, %2, 0x20
    vperm2i128  ymm7, %1, %2, 0x31
    vshufps     ymm4, ymm6, ymm7, 0x88          ; pairs 0, 2, .., 14
    vshufps     ymm5, ymm6, ymm7, 0xDD          ; pairs 1, 3, .., 15
    MK3_GS      ymm4, ymm5, [%3], [%3 + 32]
    vpshufd     ymm6, ymm5, 0xA0
    vpblendd    ymm6, ymm4, ymm6, 0xAA
    vpsrlq      ymm4, ymm4, 32
    vpblendd    ymm7, ymm4, ymm5, 0xAA
    MK3_GS      ymm6, ymm7, [%3 + 64], [%3 + 96]
    vpunpcklqdq ymm4, ymm6, ymm7
    vpunpckhqdq ymm5, ymm6, ymm7
    MK3_GS      ymm4, ymm5, [%3 + 128], [%3 + 160]
    MK3_BARRETT ymm4
    vperm2i128  %1, ymm4, ymm5, 0x20
    vperm2i128  %2, ymm4, ymm5, 0x31
%endmacro

; -----------------------------------------------------------------------------
; mk_ntt_v3: rdi = a polynomial -> its NTT in place, reduced: mk_ntt_v1's result exactly. Pass 1
; does layers 1 and 2 on registers i, i + 4, i + 8, i + 12 (coefficients 16 i on, 64 apart);
; pass 2 a quarter (four registers) at a time: layers 3 and 4 between them, then each register
; pair's in-register layers and reduction (MK3_NTT_TAIL).
;   Keeps every general register but rax, rcx and the flags.
; -----------------------------------------------------------------------------
align 16
mk_ntt_v3:
    vmovdqa     ymm15, [rel mk3_q]
    vmovdqa     ymm13, [rel mk3_v]
    vmovdqa     ymm12, [rel mk3_32]
    lea         rax, [rel mk3_nttz]
    xor         ecx, ecx
.pass1:
    vmovdqu     ymm0, [rdi + rcx]
    vmovdqu     ymm1, [rdi + rcx + 128]
    vmovdqu     ymm2, [rdi + rcx + 256]
    vmovdqu     ymm3, [rdi + rcx + 384]
    MK3_CT      ymm0, ymm2, [rax], [rax + 32]           ; layer 1 (128 apart): zeta 1
    MK3_CT      ymm1, ymm3, [rax], [rax + 32]
    MK3_CT      ymm0, ymm1, [rax + 64], [rax + 96]      ; layer 2 (64 apart): zeta 2 below 128,
    MK3_CT      ymm2, ymm3, [rax + 128], [rax + 160]    ; zeta 3 above
    vmovdqu     [rdi + rcx], ymm0
    vmovdqu     [rdi + rcx + 128], ymm1
    vmovdqu     [rdi + rcx + 256], ymm2
    vmovdqu     [rdi + rcx + 384], ymm3
    add         ecx, 32
    cmp         ecx, 128
    jb          .pass1
    add         rax, 192
    xor         ecx, ecx
.pass2:
    vmovdqu     ymm0, [rdi + rcx]
    vmovdqu     ymm1, [rdi + rcx + 32]
    vmovdqu     ymm2, [rdi + rcx + 64]
    vmovdqu     ymm3, [rdi + rcx + 96]
    MK3_CT      ymm0, ymm2, [rax], [rax + 32]           ; layer 3 (32 apart)
    MK3_CT      ymm1, ymm3, [rax], [rax + 32]
    MK3_CT      ymm0, ymm1, [rax + 64], [rax + 96]      ; layer 4 (16 apart)
    MK3_CT      ymm2, ymm3, [rax + 128], [rax + 160]
    MK3_NTT_TAIL ymm0, ymm1, rax + 192
    MK3_NTT_TAIL ymm2, ymm3, rax + 384
    vmovdqu     [rdi + rcx], ymm0
    vmovdqu     [rdi + rcx + 32], ymm1
    vmovdqu     [rdi + rcx + 64], ymm2
    vmovdqu     [rdi + rcx + 96], ymm3
    add         rax, 576
    sub         ecx, -128
    cmp         ecx, 512
    jb          .pass2
    vzeroupper
    ret

; -----------------------------------------------------------------------------
; mk_invntt_v3: rdi = a polynomial in the NTT domain (values below q in magnitude) -> its inverse
; NTT times R in place, below q in magnitude: mk_invntt_v1's values modulo q. Pass 1 a quarter at
; a time: each register pair's in-register layers (MK3_INTT_HEAD), then lengths 16 and 32
; between the four registers; pass 2 on registers i, i + 4, i + 8, i + 12: lengths 64 (its sums
; Barrett-reduced) and 128, and the product by 1441.
;   Keeps every general register but rax, rcx and the flags.
; -----------------------------------------------------------------------------
align 16
mk_invntt_v3:
    vmovdqa     ymm15, [rel mk3_q]
    vmovdqa     ymm13, [rel mk3_v]
    vmovdqa     ymm12, [rel mk3_32]
    lea         rax, [rel mk3_inttz]
    xor         ecx, ecx
.pass1:
    vmovdqu     ymm0, [rdi + rcx]
    vmovdqu     ymm1, [rdi + rcx + 32]
    vmovdqu     ymm2, [rdi + rcx + 64]
    vmovdqu     ymm3, [rdi + rcx + 96]
    MK3_INTT_HEAD ymm0, ymm1, rax
    MK3_INTT_HEAD ymm2, ymm3, rax + 192
    MK3_GS      ymm0, ymm1, [rax + 384], [rax + 416]    ; length 16
    MK3_GS      ymm2, ymm3, [rax + 448], [rax + 480]
    MK3_GS      ymm0, ymm2, [rax + 512], [rax + 544]    ; length 32
    MK3_GS      ymm1, ymm3, [rax + 512], [rax + 544]
    vmovdqu     [rdi + rcx], ymm0
    vmovdqu     [rdi + rcx + 32], ymm1
    vmovdqu     [rdi + rcx + 64], ymm2
    vmovdqu     [rdi + rcx + 96], ymm3
    add         rax, 576
    sub         ecx, -128
    cmp         ecx, 512
    jb          .pass1
    vmovdqa     ymm11, [rel mk3_f]
    vmovdqa     ymm10, [rel mk3_fq]
    xor         ecx, ecx
.pass2:
    vmovdqu     ymm0, [rdi + rcx]
    vmovdqu     ymm1, [rdi + rcx + 128]
    vmovdqu     ymm2, [rdi + rcx + 256]
    vmovdqu     ymm3, [rdi + rcx + 384]
    MK3_GS      ymm0, ymm1, [rax], [rax + 32]           ; length 64: zeta 3 below 128,
    MK3_GS      ymm2, ymm3, [rax + 64], [rax + 96]      ; zeta 2 above
    MK3_BARRETT ymm0
    MK3_BARRETT ymm2
    MK3_GS      ymm0, ymm2, [rax + 128], [rax + 160]    ; length 128: zeta 1
    MK3_GS      ymm1, ymm3, [rax + 128], [rax + 160]
    MK3_MULC    ymm0, ymm11, ymm10
    MK3_MULC    ymm1, ymm11, ymm10
    MK3_MULC    ymm2, ymm11, ymm10
    MK3_MULC    ymm3, ymm11, ymm10
    vmovdqu     [rdi + rcx], ymm0
    vmovdqu     [rdi + rcx + 128], ymm1
    vmovdqu     [rdi + rcx + 256], ymm2
    vmovdqu     [rdi + rcx + 384], ymm3
    add         ecx, 32
    cmp         ecx, 128
    jb          .pass2
    vzeroupper
    ret

; -----------------------------------------------------------------------------
; mk_mulcache_v3: rdi = a cache (1024 octets) <- rsi = b, a polynomial in the NTT domain. Per 16
; coefficients, 32 octets of [b0, b1 gamma] pairs (b0 by a Montgomery product with R mod q, which
; keeps it modulo q, beside b1 gamma, as one product) and 32 of [b1, b0] (the words of each pair
; swapped): the two vpmaddwd operands that give a0 b0 + a1 b1 gamma and a0 b1 + a1 b0 for any a.
; Built once per polynomial, used by every product with it.
;   Keeps every general register but rax, rcx and the flags.
; -----------------------------------------------------------------------------
align 16
mk_mulcache_v3:
    vmovdqa     ymm15, [rel mk3_q]
    vmovdqa     ymm13, [rel mk3_swap]
    lea         rax, [rel mk3_gamma]
    xor         ecx, ecx
.next:
    vmovdqu     ymm0, [rsi + rcx]
    vpshufb     ymm1, ymm0, ymm13
    vpmullw     ymm14, ymm0, [rax + rcx * 2 + 32]
    vpmulhw     ymm0, ymm0, [rax + rcx * 2]
    vpmulhw     ymm14, ymm14, ymm15
    vpsubw      ymm0, ymm0, ymm14
    vmovdqu     [rdi + rcx * 2], ymm0
    vmovdqu     [rdi + rcx * 2 + 32], ymm1
    add         ecx, 32
    cmp         ecx, 512
    jb          .next
    vzeroupper
    ret

; -----------------------------------------------------------------------------
; mk_basemul_acc_v3: rdi = r, rsi = a vector of polynomials (512 octets apart), rdx = the caches of
; the other vector's polynomials (1024 octets apart, mk_mulcache_v3's), ecx = k -> r = the sum over
; j of MultiplyNTTs(a_j, b_j) times R^-1, each value below q in magnitude. vpmaddwd gives each
; pair's two sums exactly in 32 bits (a below q, the cache's values below q: below 2 k q^2 < 2^27
; summed), accumulated over j, then one Montgomery reduction from 32 bits: (s >> 16) minus the
; high half of (low16(s) q^-1 mod 2^16) q, in each dword's low word; c1 then moves to the high
; word. r may not overlap a or the caches.
;   Keeps every general register but rax, rcx, r8-r11 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_basemul_acc_v3:
    vmovdqa     ymm15, [rel mk3_q]
    vmovdqa     ymm13, [rel mk3_qinv]
    shl         ecx, 9                      ; k * 512: past a's last polynomial
    xor         r8d, r8d                    ; the 16 coefficients' offset in a polynomial
.vec:
    lea         r9, [rsi + r8]
    lea         r10, [rdx + r8 * 2]
    vmovdqu     ymm2, [r9]
    vpmaddwd    ymm0, ymm2, [r10]
    vpmaddwd    ymm1, ymm2, [r10 + 32]
    mov         r11d, 512
.acc:
    cmp         r11d, ecx
    jae         .reduce
    vmovdqu     ymm2, [r9 + r11]
    vpmaddwd    ymm3, ymm2, [r10 + r11 * 2]
    vpaddd      ymm0, ymm0, ymm3
    vpmaddwd    ymm3, ymm2, [r10 + r11 * 2 + 32]
    vpaddd      ymm1, ymm1, ymm3
    add         r11d, 512
    jmp         .acc
.reduce:
    vpmullw     ymm2, ymm0, ymm13
    vpmulhw     ymm2, ymm2, ymm15
    vpsrad      ymm0, ymm0, 16
    vpsubw      ymm0, ymm0, ymm2            ; c0 in each dword's low word
    vpmullw     ymm3, ymm1, ymm13
    vpmulhw     ymm3, ymm3, ymm15
    vpsrad      ymm1, ymm1, 16
    vpsubw      ymm1, ymm1, ymm3            ; c1 in each dword's low word
    vpslld      ymm1, ymm1, 16
    vpblendw    ymm0, ymm0, ymm1, 0xAA
    vmovdqu     [rdi + r8], ymm0
    add         r8d, 32
    cmp         r8d, 512
    jb          .vec
    vzeroupper
    ret

; -----------------------------------------------------------------------------
; mk_tomont_v3: rdi = a polynomial -> each coefficient times R (a Montgomery product by R^2 mod q),
; below q in magnitude. mk_add_v3: rdi = rsi + rdx; mk_sub_v3: rdi = rsi - rdx (no reduction:
; the callers keep sums below 2^15; rdi may be rsi or rdx).
;   Keep every general register but rcx and the flags.
; -----------------------------------------------------------------------------
align 16
mk_tomont_v3:
    vmovdqa     ymm15, [rel mk3_q]
    vmovdqa     ymm11, [rel mk3_r2]
    vmovdqa     ymm10, [rel mk3_r2q]
    xor         ecx, ecx
.next:
    vmovdqu     ymm0, [rdi + rcx]
    MK3_MULC    ymm0, ymm11, ymm10
    vmovdqu     [rdi + rcx], ymm0
    add         ecx, 32
    cmp         ecx, 512
    jb          .next
    vzeroupper
    ret

align 16
mk_add_v3:
    xor         ecx, ecx
.next:
    vmovdqu     ymm0, [rsi + rcx]
    vpaddw      ymm0, ymm0, [rdx + rcx]
    vmovdqu     [rdi + rcx], ymm0
    add         ecx, 32
    cmp         ecx, 512
    jb          .next
    vzeroupper
    ret

align 16
mk_sub_v3:
    xor         ecx, ecx
.next:
    vmovdqu     ymm0, [rsi + rcx]
    vpsubw      ymm0, ymm0, [rdx + rcx]
    vmovdqu     [rdi + rcx], ymm0
    add         ecx, 32
    cmp         ecx, 512
    jb          .next
    vzeroupper
    ret

; -----------------------------------------------------------------------------
; mk_encode12_v3: rdi = 384 octets <- ByteEncode_12 of the polynomial at rsi (any 16-bit values:
; Barrett-reduced, then made canonical, here). Pairs become 24-bit dwords by vpmaddwd (x0 + 4096
; x1), each lane's four dwords give 12 octets (vpshufb), the lanes' 24 octets go together (vpermd)
; and out as 16 + 8: nothing written past the 384.
;   Keeps every general register but rcx, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_encode12_v3:
    vmovdqa     ymm15, [rel mk3_q]
    vmovdqa     ymm13, [rel mk3_v]
    vmovdqa     ymm12, [rel mk3_32]
    vmovdqa     ymm11, [rel mk3_e12m]
    vmovdqa     ymm10, [rel mk3_e12s]
    vmovdqa     ymm9, [rel mk3_e12p]
    xor         ecx, ecx
    xor         r8d, r8d
.next:
    vmovdqu     ymm0, [rsi + rcx]
    MK3_BARRETT ymm0
    vpsraw      ymm1, ymm0, 15
    vpand       ymm1, ymm1, ymm15
    vpaddw      ymm0, ymm0, ymm1            ; canonical: q added to the negative ones
    vpmaddwd    ymm0, ymm0, ymm11
    vpshufb     ymm0, ymm0, ymm10
    vpermd      ymm0, ymm9, ymm0
    vmovdqu     [rdi + r8], xmm0
    vextracti128 xmm1, ymm0, 1
    vmovq       [rdi + r8 + 16], xmm1
    add         r8d, 24
    add         ecx, 32
    cmp         ecx, 512
    jb          .next
    vzeroupper
    ret

; -----------------------------------------------------------------------------
; mk_decode12_v3: rdi = the polynomial <- ByteDecode_12's raw 12-bit values of the 384 octets at
; rsi (as mk_decode12_v1: checked below q by the caller, or a key the library wrote). Each 24
; octets are read as two 16-octet loads (at 24 v and 24 v + 8: nothing past the 384), spread into
; words by vpshufb, the odd words shifted down and every word masked.
;   Keeps every general register but rcx, r8 and the flags.
; mk_check12_v3: rdi = octets, ecx = how many polynomials' encodings -> eax = 0 when every 12-bit
; value is below q, else -1 (FIPS 203 7.2's modulus check; public data, so all of it is read and
; the offences ORed together). Keeps every general register but rax, rcx, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_decode12_v3:
    vmovdqa     ymm15, [rel mk3_d12s]
    vmovdqa     ymm14, [rel mk3_4095]
    xor         ecx, ecx
    xor         r8d, r8d
.next:
    vmovdqu     xmm0, [rsi + r8]
    vinserti128 ymm0, ymm0, [rsi + r8 + 8], 1
    vpshufb     ymm0, ymm0, ymm15
    vpsrlw      ymm1, ymm0, 4
    vpblendw    ymm0, ymm0, ymm1, 0xAA
    vpand       ymm0, ymm0, ymm14
    vmovdqu     [rdi + rcx], ymm0
    add         r8d, 24
    add         ecx, 32
    cmp         ecx, 512
    jb          .next
    vzeroupper
    ret

align 16
mk_check12_v3:
    vmovdqa     ymm15, [rel mk3_d12s]
    vmovdqa     ymm14, [rel mk3_4095]
    vmovdqa     ymm13, [rel mk3_qm1]
    vpxor       ymm2, ymm2, ymm2
    imul        ecx, ecx, 384
    xor         r8d, r8d
.next:
    vmovdqu     xmm0, [rdi + r8]
    vinserti128 ymm0, ymm0, [rdi + r8 + 8], 1
    vpshufb     ymm0, ymm0, ymm15
    vpsrlw      ymm1, ymm0, 4
    vpblendw    ymm0, ymm0, ymm1, 0xAA
    vpand       ymm0, ymm0, ymm14
    vpcmpgtw    ymm0, ymm0, ymm13
    vpor        ymm2, ymm2, ymm0
    add         r8d, 24
    cmp         r8d, ecx
    jb          .next
    xor         eax, eax
    vptest      ymm2, ymm2
    setnz       al
    neg         eax
    vzeroupper
    ret

; MK3_COMPRESS_SETUP d: the compressions' constants (ymm15 = q, ymm12 = 2q, ymm11 = 1664,
; ymm10 = q - 1, ymm9 = the d-bit mask, ymm8 = the quotient estimate's factor for d).
%macro MK3_COMPRESS_SETUP 1
    vmovdqa     ymm15, [rel mk3_q]
    vmovdqa     ymm12, [rel mk3_2q]
    vmovdqa     ymm11, [rel mk3_1664]
    vmovdqa     ymm10, [rel mk3_qm1]
    vmovdqa     ymm9, [rel mk3_mask%1]
    vmovdqa     ymm8, [rel mk3_m%1]
%endmacro

; MK3_COMPRESS x, d: sixteen lanes, each in (-2q, 2q), to Compress_d of their value mod q, exactly
; floor((2^d x + 1664) / q) mod 2^d. x' = x + 2q is positive (the quotient grows by 2^(d+1):
; nothing modulo 2^d); e = vpmulhrsw(x', floor(2^(15+d) / q)) is the quotient or one less (the
; factor rounds down, and x' stays small enough); the remainder r = 2^d x' + 1664 - e q, computed
; modulo 2^16, is truly in [0, 2q), so its 16 bits are exact and r >= q says e + 1. Checked on
; every x and each d (scratchpad). Clobbers ymm13, ymm14.
%macro MK3_COMPRESS 2
    vpaddw      %1, %1, ymm12
    vpmulhrsw   ymm14, %1, ymm8
    vpsllw      %1, %1, %2
    vpaddw      %1, %1, ymm11
    vpmullw     ymm13, ymm14, ymm15
    vpsubw      %1, %1, ymm13
    vpcmpgtw    %1, %1, ymm10
    vpsubw      %1, ymm14, %1
    vpand       %1, %1, ymm9
%endmacro

; -----------------------------------------------------------------------------
; mk_compress4_v3, mk_compress5_v3, mk_compress10_v3, mk_compress11_v3: rdi = 32 d octets <-
; ByteEncode_d(Compress_d) of the polynomial at rsi (each value in (-2q, 2q)). Exactly 32 d
; octets are written: the last register's tail goes out in sized pieces where a wider store
; would pass the end.
;   d = 4: four registers (64 coefficients) into 32 octets: vpackuswb, nibble pairs by vpmaddubsw,
;          vpackuswb, the dwords back in order.
;   d = 5, 10, 11: a register's pairs into dwords (vpmaddwd by 1, 2^d), dword pairs into qwords
;          (4d bits); d = 5 and 11 then join each lane's two qwords (40 or 88 bits); each lane's
;          5, 10 or 11 octets go out, the second lane's right after the first's.
;   Keep every general register but rcx, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_compress4_v3:
    MK3_COMPRESS_SETUP 4
    vmovdqa     ymm7, [rel mk3_c4n]
    vmovdqa     ymm6, [rel mk3_c4p]
    xor         ecx, ecx
.next:
    vmovdqu     ymm0, [rsi + rcx * 4]
    vmovdqu     ymm1, [rsi + rcx * 4 + 32]
    vmovdqu     ymm2, [rsi + rcx * 4 + 64]
    vmovdqu     ymm3, [rsi + rcx * 4 + 96]
    MK3_COMPRESS ymm0, 4
    MK3_COMPRESS ymm1, 4
    MK3_COMPRESS ymm2, 4
    MK3_COMPRESS ymm3, 4
    vpackuswb   ymm0, ymm0, ymm1
    vpackuswb   ymm2, ymm2, ymm3
    vpmaddubsw  ymm0, ymm0, ymm7
    vpmaddubsw  ymm2, ymm2, ymm7
    vpackuswb   ymm0, ymm0, ymm2
    vpermd      ymm0, ymm6, ymm0
    vmovdqu     [rdi + rcx], ymm0
    add         ecx, 32
    cmp         ecx, 128
    jb          .next
    vzeroupper
    ret

align 16
mk_compress5_v3:
    MK3_COMPRESS_SETUP 5
    vmovdqa     ymm7, [rel mk3_c5m]
    vmovdqa     ymm6, [rel mk3_c5s]
    xor         ecx, ecx
    xor         r8d, r8d
.next:
    vmovdqu     ymm0, [rsi + rcx]
    MK3_COMPRESS ymm0, 5
    vpmaddwd    ymm0, ymm0, ymm7
    vpsllvd     ymm0, ymm0, ymm6
    vpsrlq      ymm0, ymm0, 22              ; 20 bits a qword
    vpsrldq     ymm1, ymm0, 8
    vpsllq      ymm1, ymm1, 20
    vpor        ymm0, ymm0, ymm1            ; each lane's 40 bits in its low qword
    vextracti128 xmm1, ymm0, 1
    cmp         ecx, 480
    jae         .last
    vmovq       [rdi + r8], xmm0            ; 5 octets and 3 the next register rewrites
    vmovq       [rdi + r8 + 5], xmm1
    add         r8d, 10
    add         ecx, 32
    jmp         .next
.last:
    vmovq       [rdi + r8], xmm0
    vmovd       [rdi + r8 + 5], xmm1
    vpextrb     [rdi + r8 + 9], xmm1, 4
    vzeroupper
    ret

align 16
mk_compress10_v3:
    MK3_COMPRESS_SETUP 10
    vmovdqa     ymm7, [rel mk3_c10m]
    vmovdqa     ymm6, [rel mk3_c10s]
    vmovdqa     ymm5, [rel mk3_c10b]
    xor         ecx, ecx
    xor         r8d, r8d
.next:
    vmovdqu     ymm0, [rsi + rcx]
    MK3_COMPRESS ymm0, 10
    vpmaddwd    ymm0, ymm0, ymm7
    vpsllvd     ymm0, ymm0, ymm6
    vpsrlq      ymm0, ymm0, 12              ; 40 bits a qword
    vpshufb     ymm0, ymm0, ymm5            ; each lane's 10 octets at its start
    vextracti128 xmm1, ymm0, 1
    cmp         ecx, 480
    jae         .last
    vmovdqu     [rdi + r8], xmm0            ; 10 octets and 6 rewritten next
    vmovdqu     [rdi + r8 + 10], xmm1
    add         r8d, 20
    add         ecx, 32
    jmp         .next
.last:
    vmovdqu     [rdi + r8], xmm0
    vmovq       [rdi + r8 + 10], xmm1
    vpextrw     [rdi + r8 + 18], xmm1, 4
    vzeroupper
    ret

align 16
mk_compress11_v3:
    MK3_COMPRESS_SETUP 11
    vmovdqa     ymm7, [rel mk3_c11m]
    vmovdqa     ymm6, [rel mk3_c11s]
    vmovdqa     ymm5, [rel mk3_c11r]
    xor         ecx, ecx
    xor         r8d, r8d
.next:
    vmovdqu     ymm0, [rsi + rcx]
    MK3_COMPRESS ymm0, 11
    vpmaddwd    ymm0, ymm0, ymm7
    vpsllvd     ymm0, ymm0, ymm6
    vpsrlq      ymm0, ymm0, 10              ; 44 bits a qword
    vpsrldq     ymm1, ymm0, 8               ; the lane's high qword in its low one
    vpsllq      ymm1, ymm1, 44              ; its low 20 bits above the low qword's 44
    vpsrlvq     ymm0, ymm0, ymm5            ; its high 24 bits down to the high qword's start
    vpor        ymm0, ymm0, ymm1            ; each lane's 88 bits at its start
    vextracti128 xmm1, ymm0, 1
    cmp         ecx, 480
    jae         .last
    vmovdqu     [rdi + r8], xmm0            ; 11 octets and 5 rewritten next
    vmovdqu     [rdi + r8 + 11], xmm1
    add         r8d, 22
    add         ecx, 32
    jmp         .next
.last:
    vmovdqu     [rdi + r8], xmm0
    vmovq       [rdi + r8 + 11], xmm1
    vpextrw     [rdi + r8 + 19], xmm1, 4
    vpextrb     [rdi + r8 + 21], xmm1, 10
    vzeroupper
    ret

; -----------------------------------------------------------------------------
; mk_tomsg_v3: rdi = 32 octets <- ByteEncode_1(Compress_1) of the polynomial at rsi (each value
; in (-2q, 2q)): 32 coefficients at a time, each bit moved to its word's sign, the words packed to
; octets (vpacksswb keeps the sign), the qwords put in order, vpmovmskb. Constant time.
;   Keeps every general register but rax, rcx, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_tomsg_v3:
    MK3_COMPRESS_SETUP 1
    xor         ecx, ecx
    xor         r8d, r8d
.next:
    vmovdqu     ymm0, [rsi + rcx]
    vmovdqu     ymm1, [rsi + rcx + 32]
    MK3_COMPRESS ymm0, 1
    MK3_COMPRESS ymm1, 1
    vpsllw      ymm0, ymm0, 15
    vpsllw      ymm1, ymm1, 15
    vpacksswb   ymm0, ymm0, ymm1
    vpermq      ymm0, ymm0, 0xD8
    vpmovmskb   eax, ymm0
    mov         [rdi + r8], eax
    add         r8d, 4
    add         ecx, 64
    cmp         ecx, 512
    jb          .next
    vzeroupper
    ret

; -----------------------------------------------------------------------------
; mk_decompress4_v3, mk_decompress5_v3, mk_decompress10_v3, mk_decompress11_v3: rdi = the
; polynomial <- Decompress_d(ByteDecode_d) of the 32 d octets at rsi: each y shifted to y << (15
; - d) (below 2^15), then vpmulhrsw by q = floor((q y + 2^(d - 1)) / 2^d) exactly. The loads
; stay inside the 32 d octets: each register's octets are read as two pieces placed so the
; second ends where its octets do.
;   d = 4: 8 octets (broadcast) give 16 words, each masked to its nibble and scaled;
;   d = 5: word i takes octets floor(5i / 8) on and is shifted left by 10 - (5i mod 8) (vpmullw);
;   d = 10: likewise to bits 6-15, masked, halved;
;   d = 11: dword j takes 4 octets from floor(22j / 8), shifted right by 22j mod 8 (vpsrlvd):
;          two coefficients, which go to their words already shifted left by 4.
;   Keep every general register but rcx, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_decompress4_v3:
    vmovdqa     ymm15, [rel mk3_q]
    vmovdqa     ymm14, [rel mk3_dc4s]
    vmovdqa     ymm13, [rel mk3_dc4m]
    vmovdqa     ymm12, [rel mk3_dc4k]
    xor         ecx, ecx
.next:
    vpbroadcastq ymm0, [rsi + rcx]
    vpshufb     ymm0, ymm0, ymm14
    vpand       ymm0, ymm0, ymm13
    vpmullw     ymm0, ymm0, ymm12
    vpmulhrsw   ymm0, ymm0, ymm15
    vmovdqu     [rdi + rcx * 4], ymm0
    add         ecx, 8
    cmp         ecx, 128
    jb          .next
    vzeroupper
    ret

align 16
mk_decompress5_v3:
    vmovdqa     ymm15, [rel mk3_q]
    vmovdqa     ymm14, [rel mk3_dc5s]
    vmovdqa     ymm13, [rel mk3_dc5k]
    vmovdqa     ymm12, [rel mk3_dc5m]
    xor         ecx, ecx
    xor         r8d, r8d
.next:
    vpbroadcastq ymm0, [rsi + r8]
    vpbroadcastq ymm1, [rsi + r8 + 2]
    vpblendd    ymm0, ymm0, ymm1, 0xF0      ; lane 1 from the second load (its octets at 3-7)
    vpshufb     ymm0, ymm0, ymm14
    vpmullw     ymm0, ymm0, ymm13
    vpand       ymm0, ymm0, ymm12
    vpmulhrsw   ymm0, ymm0, ymm15
    vmovdqu     [rdi + rcx], ymm0
    add         r8d, 10
    add         ecx, 32
    cmp         ecx, 512
    jb          .next
    vzeroupper
    ret

align 16
mk_decompress10_v3:
    vmovdqa     ymm15, [rel mk3_q]
    vmovdqa     ymm14, [rel mk3_dc10s]
    vmovdqa     ymm13, [rel mk3_dc10k]
    vmovdqa     ymm12, [rel mk3_dc10m]
    xor         ecx, ecx
    xor         r8d, r8d
.next:
    vmovdqu     xmm0, [rsi + r8]
    vinserti128 ymm0, ymm0, [rsi + r8 + 4], 1
    vpshufb     ymm0, ymm0, ymm14
    vpmullw     ymm0, ymm0, ymm13
    vpand       ymm0, ymm0, ymm12
    vpsrlw      ymm0, ymm0, 1
    vpmulhrsw   ymm0, ymm0, ymm15
    vmovdqu     [rdi + rcx], ymm0
    add         r8d, 20
    add         ecx, 32
    cmp         ecx, 512
    jb          .next
    vzeroupper
    ret

align 16
mk_decompress11_v3:
    vmovdqa     ymm15, [rel mk3_q]
    vmovdqa     ymm14, [rel mk3_dc11s]
    vmovdqa     ymm13, [rel mk3_dc11r]
    vmovdqa     ymm12, [rel mk3_dc11lo]
    vmovdqa     ymm11, [rel mk3_dc11hi]
    xor         ecx, ecx
    xor         r8d, r8d
.next:
    vmovdqu     xmm0, [rsi + r8]
    vinserti128 ymm0, ymm0, [rsi + r8 + 6], 1
    vpshufb     ymm0, ymm0, ymm14
    vpsrlvd     ymm0, ymm0, ymm13           ; c0 | c1 << 11 from bit 0 of each dword
    vpslld      ymm1, ymm0, 4
    vpand       ymm1, ymm1, ymm12           ; c0 << 4 in the low word
    vpslld      ymm0, ymm0, 9
    vpand       ymm0, ymm0, ymm11           ; c1 << 4 in the high word
    vpor        ymm0, ymm0, ymm1
    vpmulhrsw   ymm0, ymm0, ymm15
    vmovdqu     [rdi + rcx], ymm0
    add         r8d, 22
    add         ecx, 32
    cmp         ecx, 512
    jb          .next
    vzeroupper
    ret

; -----------------------------------------------------------------------------
; mk_frommsg_v3: rdi = the polynomial <- Decompress_1(ByteDecode_1) of the 32 octets at rsi: 16
; bits broadcast, lane i keeps bit i, compared, masked to 1665. Constant time (the message is
; secret). Keeps every general register but rcx, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_frommsg_v3:
    vmovdqa     ymm15, [rel mk3_bits]
    vmovdqa     ymm14, [rel mk3_1665]
    xor         ecx, ecx
    xor         r8d, r8d
.next:
    vpbroadcastw ymm0, [rsi + r8]
    vpand       ymm0, ymm0, ymm15
    vpcmpeqw    ymm0, ymm0, ymm15
    vpand       ymm0, ymm0, ymm14
    vmovdqu     [rdi + rcx], ymm0
    add         r8d, 2
    add         ecx, 32
    cmp         ecx, 512
    jb          .next
    vzeroupper
    ret

; -----------------------------------------------------------------------------
; mk_cbd2_v3: rdi = the polynomial <- SamplePolyCBD_2 of the 128 octets at rsi. 32 octets at a
; time: bit-pair sums (x and y of each 4-bit group), x + 4 - y per nibble (no borrow: it stays in
; [2, 6]), nibbles apart and interleaved back in order, minus 4, sign-extended to words.
; mk_cbd3_v3: rdi = the polynomial <- SamplePolyCBD_3 of the 192 octets at rsi (ML-KEM-512's eta1).
; 24 octets at a time: each 3-octet group (four coefficients of 3 + 3 bits) into a dword, the bit
; sums of each 3-bit field, x + 4 - y per 6-bit slot, each dword spread over a qword's four words
; (vpermd doubles the dwords, vpsrlvd brings slots 2 and 3 down, the odd slot of each pair moves up
; to the high word), minus 4. Lane 1's octets are loaded 8 on (no read past the 192).
; Constant time (the octets are a PRF's). Keep every general register but rcx, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_cbd2_v3:
    vmovdqa     ymm15, [rel mk3_x55]
    vmovdqa     ymm14, [rel mk3_x33]
    vmovdqa     ymm13, [rel mk3_x44]
    vmovdqa     ymm12, [rel mk3_x0f]
    vmovdqa     ymm11, [rel mk3_x04]
    xor         ecx, ecx
.next:
    vmovdqu     ymm0, [rsi + rcx]
    vpsrlw      ymm1, ymm0, 1
    vpand       ymm0, ymm0, ymm15
    vpand       ymm1, ymm1, ymm15
    vpaddb      ymm0, ymm0, ymm1            ; 2-bit sums: x, y, x, y per octet
    vpsrlw      ymm1, ymm0, 2
    vpand       ymm0, ymm0, ymm14           ; x of each nibble
    vpand       ymm1, ymm1, ymm14           ; y of each nibble
    vpor        ymm0, ymm0, ymm13
    vpsubb      ymm0, ymm0, ymm1            ; x + 4 - y per nibble
    vpsrlw      ymm1, ymm0, 4
    vpand       ymm0, ymm0, ymm12           ; even coefficients (+4)
    vpand       ymm1, ymm1, ymm12           ; odd coefficients (+4)
    vpsubb      ymm0, ymm0, ymm11
    vpsubb      ymm1, ymm1, ymm11
    vpunpcklbw  ymm2, ymm0, ymm1            ; lane 0: coefficients 0-15, lane 1: 32-47
    vpunpckhbw  ymm3, ymm0, ymm1            ; lane 0: 16-31, lane 1: 48-63
    vpmovsxbw   ymm0, xmm2
    vpmovsxbw   ymm1, xmm3
    vextracti128 xmm2, ymm2, 1
    vextracti128 xmm3, ymm3, 1
    vpmovsxbw   ymm2, xmm2
    vpmovsxbw   ymm3, xmm3
    vmovdqu     [rdi + rcx * 4], ymm0
    vmovdqu     [rdi + rcx * 4 + 32], ymm1
    vmovdqu     [rdi + rcx * 4 + 64], ymm2
    vmovdqu     [rdi + rcx * 4 + 96], ymm3
    add         ecx, 32
    cmp         ecx, 128
    jb          .next
    vzeroupper
    ret

align 16
mk_cbd3_v3:
    vmovdqa     ymm15, [rel mk3_cbd3s]
    vmovdqa     ymm14, [rel mk3_x249]
    vmovdqa     ymm13, [rel mk3_x1c7]
    vmovdqa     ymm12, [rel mk3_x104]
    vmovdqa     ymm11, [rel mk3_cbd3d]
    vmovdqa     ymm10, [rel mk3_cbd3e]
    vmovdqa     ymm9, [rel mk3_cbd3r]
    vmovdqa     ymm8, [rel mk3_x7]
    vmovdqa     ymm7, [rel mk3_x70000]
    vmovdqa     ymm6, [rel mk3_w4]
    xor         ecx, ecx
    xor         r8d, r8d
.next:
    vmovdqu     xmm0, [rsi + r8]
    vinserti128 ymm0, ymm0, [rsi + r8 + 8], 1
    vpshufb     ymm0, ymm0, ymm15           ; eight 3-octet groups, one a dword
    vpsrld      ymm1, ymm0, 1
    vpsrld      ymm2, ymm0, 2
    vpand       ymm0, ymm0, ymm14
    vpand       ymm1, ymm1, ymm14
    vpand       ymm2, ymm2, ymm14
    vpaddd      ymm0, ymm0, ymm1
    vpaddd      ymm0, ymm0, ymm2            ; each 3-bit field's sum
    vpsrld      ymm1, ymm0, 3
    vpand       ymm0, ymm0, ymm13           ; x of each 6-bit slot
    vpand       ymm1, ymm1, ymm13           ; y of each slot
    vpor        ymm0, ymm0, ymm12
    vpsubd      ymm0, ymm0, ymm1            ; x + 4 - y per slot
    vpermd      ymm1, ymm11, ymm0           ; groups 0-3, each twice
    vpermd      ymm0, ymm10, ymm0           ; groups 4-7, each twice
    vpsrlvd     ymm1, ymm1, ymm9            ; slots 2 and 3 down in each odd dword
    vpsrlvd     ymm0, ymm0, ymm9
    vpslld      ymm2, ymm1, 10
    vpand       ymm1, ymm1, ymm8
    vpand       ymm2, ymm2, ymm7
    vpor        ymm1, ymm1, ymm2            ; words: slots 0, 1, 2, 3 of each group
    vpslld      ymm2, ymm0, 10
    vpand       ymm0, ymm0, ymm8
    vpand       ymm2, ymm2, ymm7
    vpor        ymm0, ymm0, ymm2
    vpsubw      ymm1, ymm1, ymm6
    vpsubw      ymm0, ymm0, ymm6
    vmovdqu     [rdi + rcx], ymm1
    vmovdqu     [rdi + rcx + 32], ymm0
    add         r8d, 24
    add         ecx, 64
    cmp         ecx, 512
    jb          .next
    vzeroupper
    ret

; -----------------------------------------------------------------------------
; mk_rej_v3: as mk_rej_v1 (rdi = where coefficients go, esi = how many are still wanted, rdx =
; SHAKE128's octets, ecx = how many -> eax = how many written, at most esi; FIPS 203 Algorithm
; 7's order), 16 candidates at a time while 16 more fit and 24 octets remain: decoded as
; ByteDecode_12 does, compared with q, the mask's two halves (8 candidates each) index
; mk3_rejtab, whose vpshufb gathers the accepted words for a 16-octet store; popcnt advances.
; A store may write up to 8 words past the accepted ones, never past the wanted (the loop stops 16
; before them). The rest one pair at a time as v1. Variable time: rho is public.
;   Keeps every general register but rax, rcx, rdx, rsi, r8-r11 and the flags.
; -----------------------------------------------------------------------------
align 16
mk_rej_v3:
    vmovdqa     ymm15, [rel mk3_d12s]
    vmovdqa     ymm14, [rel mk3_4095]
    vmovdqa     ymm13, [rel mk3_q]
    lea         r11, [rel mk3_rejtab]
    xor         eax, eax                    ; written
    xor         r8d, r8d                    ; the octet position
.vector:
    lea         r9d, [rax + 16]
    cmp         r9d, esi
    ja          .pairs
    lea         r9d, [r8 + 24]
    cmp         r9d, ecx
    ja          .pairs
    vmovdqu     xmm0, [rdx + r8]
    vinserti128 ymm0, ymm0, [rdx + r8 + 8], 1
    vpshufb     ymm0, ymm0, ymm15
    vpsrlw      ymm1, ymm0, 4
    vpblendw    ymm0, ymm0, ymm1, 0xAA
    vpand       ymm0, ymm0, ymm14           ; 16 candidates
    vpcmpgtw    ymm1, ymm13, ymm0           ; accepted: below q
    vpacksswb   ymm1, ymm1, ymm1
    vpmovmskb   r9d, ymm1                   ; lane 0's 8 in bits 0-7, lane 1's in 16-23
    movzx       r10d, r9b
    shl         r10d, 4
    vpshufb     xmm1, xmm0, [r11 + r10]
    vmovdqu     [rdi + rax * 2], xmm1
    shr         r10d, 4
    popcnt      r10d, r10d
    add         eax, r10d
    shr         r9d, 16
    movzx       r10d, r9b
    shl         r10d, 4
    vextracti128 xmm0, ymm0, 1
    vpshufb     xmm1, xmm0, [r11 + r10]
    vmovdqu     [rdi + rax * 2], xmm1
    shr         r10d, 4
    popcnt      r10d, r10d
    add         eax, r10d
    add         r8d, 24
    jmp         .vector
.pairs:
    lea         r9d, [r8 + 3]
    cmp         r9d, ecx
    ja          .done
    cmp         eax, esi
    jae         .done
    movzx       r9d, word [rdx + r8]
    and         r9d, 0xFFF
    movzx       r10d, word [rdx + r8 + 1]
    shr         r10d, 4
    add         r8d, 3
    cmp         r9d, MK_Q
    jae         .second
    mov         [rdi + rax * 2], r9w
    inc         eax
    cmp         eax, esi
    jae         .done
.second:
    cmp         r10d, MK_Q
    jae         .pairs
    mov         [rdi + rax * 2], r10w
    inc         eax
    jmp         .pairs
.done:
    vzeroupper
    ret

; =============================================================================
; The schemes. The frame (rbp, 64-aligned) is sized per parameter set by MK_SCHEME; every
; routine below works in its caller's frame through these offsets.
; =============================================================================
; (Preprocessor numbers, not equ: MK_ENTER's page probes are a %rep over the frame's size, which
; the preprocessor must be able to compute.)
%define MF_G        0                       ; G's output: rho, sigma or K, r (64)
%define MF_IN       64                      ; G's input: d || k, or m || H(ek) (64)
%define MF_PRF      128                     ; a PRF's output (up to 64 eta = 192)
%define MF_PRFIN    320                     ; a PRF's input: a seed and its nonce (33)
%define MF_HEK      384                     ; H(ek) (32)
%define MF_M        416                     ; decapsulation's m' (32)
%define MF_KBAR     448                     ; J(z || c) (32)
%define MF_SEED     480                     ; the 34-octet XOF input: rho, j, i
%define MF_OUT      520                     ; the caller's arguments
%define MF_ARG1     528
%define MF_ARG2     536
%define MF_ARG3     544
%define MF_RES      552                     ; the result to return
%define MF_CNT      560                     ; loop counters
%define MF_CNT2     568
%define MF_FAIL     576                     ; decapsulation's mismatch mask
%define MF_X4CNT    584                     ; v3: four states' coefficient counts (4 dwords)
%define MF_XOF      640                     ; a SHAKE context (216)
%define MF_XBUF     896                     ; its squeezed octets (504: three blocks)
%define MF_POLYS    1408                    ; v1: the polynomials from here (512 each; 64-aligned)
%define MF_X4       1408                    ; v3: four Keccak states, interleaved (800, 64-aligned)
%define MF_X4BUF    2208                    ; v3: their squeezed octets, 504 a state
%define MF3_POLYS   4224                    ; v3: the polynomials from here (64-aligned)

; MK_ENTER frame / MK_FINISH frame, end: as ed25519.asm's: six registers kept, the 64-aligned
; frame at rbp (rsp 16-aligned for the C calls), the entry rsp in the frame's last qword;
; FINISH wipes [rbp, rbp + end) and returns MF_RES's low dword.
; The frames pass 4 KiB (up to about 17 KiB), so ENTER touches the stack every 4032 octets on
; the way down (63 lines: less than a page from the last touch even after the alignment's 63):
; a thread whose stack is nearly spent faults on its guard page instead of the frame stepping over
; it into whatever is mapped below (a stack clash).
%macro MK_ENTER 1
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    and         rsp, -64
  %rep (%1) / 4032
    sub         rsp, 4032
    or          qword [rsp], 0
  %endrep
    sub         rsp, (%1) % 4032
    mov         rbp, rsp
    mov         [rbp + %1 - 8], rax
%endmacro
%macro MK_FINISH 2
    mov         r8, [rbp + MF_RES]
    xor         eax, eax
    mov         ecx, %2 / 8
    mov         rdi, rbp
    rep         stosq
    mov         eax, r8d
    mov         rsp, [rbp + %1 - 8]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret
%endmacro

; -----------------------------------------------------------------------------
; mk_prf: rdi = the polynomial <- SamplePolyCBD_eta(PRF_eta(seed, nonce)), rsi = the 32-octet
; seed, edx = the nonce, ecx = eta (2 or 3). Works in the caller's frame (MF_PRFIN, MF_PRF).
; Keeps rbx, rbp, r12-r15; clobbers the rest.
; -----------------------------------------------------------------------------
align 16
mk_prf:
    push        rbx
    push        r12
    push        r13
    mov         rbx, rdi
    mov         r12d, ecx
    mov         r13d, edx
    lea         rdi, [rbp + MF_PRFIN]
    mov         ecx, 32
    call        ha_copy_short
    mov         [rbp + MF_PRFIN + 32], r13b
    lea         rdi, [rbp + MF_PRFIN]
    mov         esi, 33
    lea         rdx, [rbp + MF_PRF]
    imul        ecx, r12d, 64               ; 64 eta octets
    call        httpasm_shake256
    mov         rdi, rbx
    lea         rsi, [rbp + MF_PRF]
    mov         edx, r12d
    call        mk_cbd_v1
    pop         r13
    pop         r12
    pop         rbx
    ret

; -----------------------------------------------------------------------------
; mk_sample: rdi = the polynomial <- SampleNTT(rho || x || y) (FIPS 203 Algorithm 7), rsi = rho
; (32 octets), edx = x, ecx = y (one octet each): SHAKE128 squeezed three blocks at once (504
; octets: enough nearly always), then a block more while coefficients are missing. Works in the
; caller's frame (MF_SEED, MF_XOF, MF_XBUF). Keeps rbx, rbp, r12-r15; clobbers the rest.
; -----------------------------------------------------------------------------
align 16
mk_sample:
    push        rbx
    push        r12
    push        r13
    mov         rbx, rdi                    ; the polynomial
    mov         r12d, edx
    mov         r13d, ecx
    lea         rdi, [rbp + MF_SEED]
    mov         ecx, 32
    call        ha_copy_short
    mov         [rbp + MF_SEED + 32], r12b
    mov         [rbp + MF_SEED + 33], r13b
    lea         rdi, [rbp + MF_XOF]
    call        httpasm_shake128_init
    lea         rdi, [rbp + MF_XOF]
    lea         rsi, [rbp + MF_SEED]
    mov         edx, 34
    call        httpasm_sha3_update
    lea         rdi, [rbp + MF_XOF]
    lea         rsi, [rbp + MF_XBUF]
    mov         edx, 504
    call        httpasm_shake_squeeze
    mov         rdi, rbx
    mov         esi, 256
    lea         rdx, [rbp + MF_XBUF]
    mov         ecx, 504
    call        mk_rej_v1
    mov         r12d, eax                   ; coefficients so far
.more:
    cmp         r12d, 256
    jae         .done
    lea         rdi, [rbp + MF_XOF]
    lea         rsi, [rbp + MF_XBUF]
    mov         edx, 168
    call        httpasm_shake_squeeze
    lea         rdi, [rbx + r12 * 2]
    mov         esi, 256
    sub         esi, r12d
    lea         rdx, [rbp + MF_XBUF]
    mov         ecx, 168
    call        mk_rej_v1
    add         r12d, eax
    jmp         .more
.done:
    pop         r13
    pop         r12
    pop         rbx
    ret

; -----------------------------------------------------------------------------
; mk_prf_v3, mk_sample_v3: mk_prf and mk_sample with v3's CBD and rejection (same arguments, same
; frame fields). Keep rbx, rbp, r12-r15; clobber the rest.
; -----------------------------------------------------------------------------
align 16
mk_prf_v3:
    push        rbx
    push        r12
    push        r13
    mov         rbx, rdi
    mov         r12d, ecx
    mov         r13d, edx
    lea         rdi, [rbp + MF_PRFIN]
    mov         ecx, 32
    call        ha_copy_short
    mov         [rbp + MF_PRFIN + 32], r13b
    lea         rdi, [rbp + MF_PRFIN]
    mov         esi, 33
    lea         rdx, [rbp + MF_PRF]
    imul        ecx, r12d, 64
    call        httpasm_shake256
    mov         rdi, rbx
    lea         rsi, [rbp + MF_PRF]
    cmp         r12d, 3
    je          .eta3
    call        mk_cbd2_v3
    jmp         .done
.eta3:
    call        mk_cbd3_v3
.done:
    pop         r13
    pop         r12
    pop         rbx
    ret

align 16
mk_sample_v3:
    push        rbx
    push        r12
    push        r13
    mov         rbx, rdi
    mov         r12d, edx
    mov         r13d, ecx
    lea         rdi, [rbp + MF_SEED]
    mov         ecx, 32
    call        ha_copy_short
    mov         [rbp + MF_SEED + 32], r12b
    mov         [rbp + MF_SEED + 33], r13b
    lea         rdi, [rbp + MF_XOF]
    call        httpasm_shake128_init
    lea         rdi, [rbp + MF_XOF]
    lea         rsi, [rbp + MF_SEED]
    mov         edx, 34
    call        httpasm_sha3_update
    lea         rdi, [rbp + MF_XOF]
    lea         rsi, [rbp + MF_XBUF]
    mov         edx, 504
    call        httpasm_shake_squeeze
    mov         rdi, rbx
    mov         esi, 256
    lea         rdx, [rbp + MF_XBUF]
    mov         ecx, 504
    call        mk_rej_v3
    mov         r12d, eax
.more:
    cmp         r12d, 256
    jae         .done
    lea         rdi, [rbp + MF_XOF]
    lea         rsi, [rbp + MF_XBUF]
    mov         edx, 168
    call        httpasm_shake_squeeze
    lea         rdi, [rbx + r12 * 2]
    mov         esi, 256
    sub         esi, r12d
    lea         rdx, [rbp + MF_XBUF]
    mov         ecx, 168
    call        mk_rej_v3
    add         r12d, eax
    jmp         .more
.done:
    pop         r13
    pop         r12
    pop         rbx
    ret

; -----------------------------------------------------------------------------
; Four SHAKE runs at once (v3): the matrix's entries and the noise polynomials are independent
; SHAKE128 / SHAKE256 runs over a shared 32-octet seed and two or one octets of their own, so four
; of them share ha_keccak_f1600_x4_v3's permutations (1,720 cycles for four against 812 for one:
; 1.89x the throughput, measured when written). Their states live interleaved at MF_X4 and their
; squeezed octets at MF_X4BUF (504 a state), both inside the wiped part of v3's frame (the noise is
; secret).
;
; mk_x4_state: [rbp + MF_X4] <- four sponges that have absorbed the same 32 octets (rsi) and each
; its own last octets in lane 4 (r8, r9, r10, r11: those octets and SHAKE's 0x1F right after them),
; with pad10*1's last bit in lane edx (the rate's last: 20 for SHAKE128, 16 for SHAKE256); every
; other lane zero. Keeps every general register but rax, rcx.
; mk_x4_out: the first ecx lanes (the octets of a block, or of its start) of each state to rdi +
; i rdx + 8 L (state i's octets, rdx apart): four lanes at a time by a 4 x 4 transpose of qwords,
; a lane left over one qword a state. Writes exactly 8 ecx octets a state. Keeps every general
; register but rax, r8-r11.
; -----------------------------------------------------------------------------
align 16
mk_x4_state:
    vpxor       ymm0, ymm0, ymm0
    lea         rax, [rbp + MF_X4]
  %assign xl 5
  %rep 20
    vmovdqa     [rax + 32 * xl], ymm0
    %assign xl xl + 1
  %endrep
  %assign xl 0
  %rep 4
    vpbroadcastq ymm1, [rsi + 8 * xl]
    vmovdqa     [rax + 32 * xl], ymm1
    %assign xl xl + 1
  %endrep
    mov         [rax + 128], r8
    mov         [rax + 136], r9
    mov         [rax + 144], r10
    mov         [rax + 152], r11
    mov         ecx, edx
    shl         ecx, 5
    vpcmpeqd    ymm1, ymm1, ymm1
    vpsllq      ymm1, ymm1, 63              ; 0x80 in each state's last octet of the block
    vmovdqa     [rax + rcx], ymm1
    vzeroupper
    ret

align 16
mk_x4_out:
    lea         r8, [rbp + MF_X4]
    xor         r9d, r9d                    ; the lane
    lea         r10, [rdx + rdx * 2]        ; three strides
.four:
    lea         eax, [r9 + 4]
    cmp         eax, ecx
    ja          .single
    mov         eax, r9d
    shl         eax, 5
    vmovdqa     ymm0, [r8 + rax]
    vmovdqa     ymm1, [r8 + rax + 32]
    vmovdqa     ymm2, [r8 + rax + 64]
    vmovdqa     ymm3, [r8 + rax + 96]
    vpunpcklqdq ymm4, ymm0, ymm1            ; lanes L, L + 1 of states 0 | 2
    vpunpckhqdq ymm5, ymm0, ymm1            ; of states 1 | 3
    vpunpcklqdq ymm6, ymm2, ymm3            ; lanes L + 2, L + 3 of states 0 | 2
    vpunpckhqdq ymm7, ymm2, ymm3            ; of states 1 | 3
    vperm2i128  ymm0, ymm4, ymm6, 0x20      ; state 0's lanes L .. L + 3
    vperm2i128  ymm1, ymm5, ymm7, 0x20
    vperm2i128  ymm2, ymm4, ymm6, 0x31
    vperm2i128  ymm3, ymm5, ymm7, 0x31
    lea         r11, [rdi + r9 * 8]
    vmovdqu     [r11], ymm0
    vmovdqu     [r11 + rdx], ymm1
    vmovdqu     [r11 + rdx * 2], ymm2
    vmovdqu     [r11 + r10], ymm3
    add         r9d, 4
    jmp         .four
.single:
    cmp         r9d, ecx
    jae         .done
    mov         eax, r9d
    shl         eax, 5
    vmovdqa     ymm0, [r8 + rax]
    lea         r11, [rdi + r9 * 8]
    vmovq       [r11], xmm0
    vpextrq     [r11 + rdx], xmm0, 1
    vextracti128 xmm0, ymm0, 1
    vmovq       [r11 + rdx * 2], xmm0
    vpextrq     [r11 + r10], xmm0, 1
    inc         r9d
    jmp         .single
.done:
    vzeroupper
    ret

; -----------------------------------------------------------------------------
; mk_sample4_v3: rdi = the first of ecx destination polynomials (2 to 4, 512 octets apart) <-
; SampleNTT of the first ecx of the four SHAKE128 states at MF_X4 (absorbed by mk_x4_state; the
; others are squeezed and dropped). Three blocks a state (504 octets, enough nearly always), each
; state's rejection sampling, then a block more for all four while any is short.
;   Keeps rbx, rbp, r12-r15; clobbers the rest.
; -----------------------------------------------------------------------------
align 16
mk_sample4_v3:
    push        rbx
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rbx, rdi
    mov         r12d, ecx
    xor         r13d, r13d                  ; the block
.squeeze:
    lea         rdi, [rbp + MF_X4]
    call        ha_keccak_f1600_x4_v3
    imul        edi, r13d, 168
    lea         rdi, [rbp + MF_X4BUF + rdi]
    mov         edx, 504
    mov         ecx, 21
    call        mk_x4_out
    inc         r13d
    cmp         r13d, 3
    jb          .squeeze
    xor         r13d, r13d                  ; the state
.first:
    mov         eax, r13d
    shl         eax, 9
    lea         rdi, [rbx + rax]
    mov         esi, 256
    imul        edx, r13d, 504
    lea         rdx, [rbp + MF_X4BUF + rdx]
    mov         ecx, 504
    call        mk_rej_v3
    mov         [rbp + MF_X4CNT + r13 * 4], eax
    inc         r13d
    cmp         r13d, r12d
    jb          .first
.more:
    xor         r13d, r13d
    xor         r14d, r14d                  ; how many are short
.count:
    cmp         dword [rbp + MF_X4CNT + r13 * 4], 256
    adc         r14d, 0
    inc         r13d
    cmp         r13d, r12d
    jb          .count
    test        r14d, r14d
    jz          .done
    lea         rdi, [rbp + MF_X4]
    call        ha_keccak_f1600_x4_v3
    lea         rdi, [rbp + MF_X4BUF]
    mov         edx, 504
    mov         ecx, 21
    call        mk_x4_out
    xor         r13d, r13d
.again:
    mov         eax, [rbp + MF_X4CNT + r13 * 4]
    cmp         eax, 256
    jae         .full
    mov         ecx, r13d
    shl         ecx, 9
    lea         rdi, [rbx + rcx]
    lea         rdi, [rdi + rax * 2]
    mov         esi, 256
    sub         esi, eax
    imul        edx, r13d, 504
    lea         rdx, [rbp + MF_X4BUF + rdx]
    mov         ecx, 168
    call        mk_rej_v3
    add         [rbp + MF_X4CNT + r13 * 4], eax
.full:
    inc         r13d
    cmp         r13d, r12d
    jb          .again
    jmp         .more
.done:
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbx
    ret

; -----------------------------------------------------------------------------
; mk_noise_v3: rdi = the first polynomial (the rest follow, 512 octets apart) <- SamplePolyCBD of
; PRF(seed, nonce) for nonces 0 .. ecx - 1; rsi = the 32-octet seed, edx = how many of them (the
; first) take eta1, r8d = eta1; the rest take eta2 = 2. Every noise vector of a scheme is such a
; run: key generation's s and e (2k, all eta1), encryption's y, e1 and e2 (2k + 1: k of eta1).
; Four nonces at a time (those past the run computed and dropped), one block of SHAKE256 each and a
; second when eta1 is 3 (192 octets: ML-KEM-512); a lone last nonce by mk_prf_v3.
; mk_matrix_v3: rdi = the first destination polynomial (512 octets apart) <- entries edx ..
; edx + ecx - 1 of a k x k matrix (r8d = k; entry e = i k + j): A[i][j] = SampleNTT(rho || j || i)
; when r9d = 0 (key generation's rows), A[j][i] = SampleNTT(rho || i || j) when r9d = 1
; (encryption's columns: A transposed); rsi = rho. Four entries at a time (mk_sample4_v3; the idle
; lanes of a batch of 2 or 3 sample entries past it, dropped), a lone last entry by mk_sample_v3.
; Both work in the caller's frame; keep rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
align 16
mk_noise_v3:
    push        rbx
    push        r12
    push        r13
    push        r14
    push        r15
    sub         rsp, 16
    mov         rbx, rdi
    mov         r12, rsi
    xor         r13d, r13d                  ; the next nonce
    mov         r14d, ecx
    shl         edx, 8
    or          edx, r8d
    mov         r15d, edx                   ; eta1's count << 8 | eta1
.batch:
    mov         ecx, r14d
    sub         ecx, r13d
    jz          .done
    cmp         ecx, 1
    je          .single
    lea         r8d, [r13 + 0x1F00]         ; lane 4: the nonce, then SHAKE's 0x1F
    lea         r9d, [r13 + 0x1F01]
    lea         r10d, [r13 + 0x1F02]
    lea         r11d, [r13 + 0x1F03]
    mov         rsi, r12
    mov         edx, 16
    call        mk_x4_state
    lea         rdi, [rbp + MF_X4]
    call        ha_keccak_f1600_x4_v3
    lea         rdi, [rbp + MF_X4BUF]
    mov         edx, 504
    mov         ecx, 17
    call        mk_x4_out
    cmp         r15b, 3
    jne         .cbd
    lea         rdi, [rbp + MF_X4]          ; eta1 3: 192 octets, a second block's first 56
    call        ha_keccak_f1600_x4_v3
    lea         rdi, [rbp + MF_X4BUF + 136]
    mov         edx, 504
    mov         ecx, 7
    call        mk_x4_out
.cbd:
    mov         dword [rsp], 0              ; the batch's polynomial
.poly:
    mov         eax, [rsp]
    cmp         eax, 4
    jae         .advance
    lea         ecx, [r13 + rax]            ; its nonce
    cmp         ecx, r14d
    jae         .advance
    imul        esi, eax, 504
    lea         rsi, [rbp + MF_X4BUF + rsi]
    shl         eax, 9
    lea         rdi, [rbx + rax]
    mov         edx, r15d
    shr         edx, 8
    cmp         ecx, edx
    jae         .eta2
    cmp         r15b, 3
    jne         .eta2
    call        mk_cbd3_v3
    jmp         .next
.eta2:
    call        mk_cbd2_v3
.next:
    inc         dword [rsp]
    jmp         .poly
.advance:
    mov         eax, [rsp]
    add         r13d, eax
    shl         eax, 9
    add         rbx, rax
    jmp         .batch
.single:
    mov         ecx, 2
    mov         eax, r15d
    shr         eax, 8
    cmp         r13d, eax
    jae         .eta
    movzx       ecx, r15b
.eta:
    mov         rdi, rbx
    mov         rsi, r12
    mov         edx, r13d
    call        mk_prf_v3
    add         rbx, 512
    inc         r13d
    jmp         .batch
.done:
    add         rsp, 16
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbx
    ret

; MK_X4_LANE4 reg: reg = lane 4 of the matrix entry (eax = i, edx = j; r15d = transposed << 8 | k):
; x | y << 8 | 0x1F << 16 with (x, y) = (j, i) for A, (i, j) for A transposed. Clobbers rcx.
%macro MK_X4_LANE4 1
    mov         %1, rax
    shl         %1, 8
    or          %1, rdx                     ; j || i
    mov         rcx, rdx
    shl         rcx, 8
    or          rcx, rax                    ; i || j
    test        r15d, 0x100
    cmovnz      %1, rcx
    or          %1, 0x1F0000
%endmacro

; MK_X4_STEP: (eax = i, edx = j) to the next entry in row-major order (k = r15b), branch-free.
; Clobbers ecx.
%macro MK_X4_STEP 0
    inc         edx
    movzx       ecx, r15b
    cmp         edx, ecx
    sete        cl
    movzx       ecx, cl
    add         eax, ecx                    ; the next row when j reached k
    dec         ecx                         ; 0 then, all ones otherwise
    and         edx, ecx
%endmacro

align 16
mk_matrix_v3:
    push        rbx
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rbx, rdi
    mov         r12, rsi
    mov         r13d, edx                   ; the next entry
    lea         r14d, [rdx + rcx]           ; past the last
    shl         r9d, 8
    or          r9d, r8d
    mov         r15d, r9d                   ; transposed << 8 | k
.batch:
    mov         eax, r13d                   ; (i, j) of the next entry
    xor         edx, edx
    movzx       ecx, r15b
    div         ecx
    mov         ecx, r14d
    sub         ecx, r13d
    jz          .done
    cmp         ecx, 1
    je          .single
    MK_X4_LANE4 r8
    MK_X4_STEP
    MK_X4_LANE4 r9
    MK_X4_STEP
    MK_X4_LANE4 r10
    MK_X4_STEP
    MK_X4_LANE4 r11
    mov         rsi, r12
    mov         edx, 20
    call        mk_x4_state
    mov         ecx, r14d
    sub         ecx, r13d
    cmp         ecx, 4
    jbe         .n
    mov         ecx, 4
.n:
    mov         rdi, rbx                    ; this batch's destinations
    mov         eax, ecx
    shl         eax, 9
    add         rbx, rax                    ; the next batch's
    add         r13d, ecx
    call        mk_sample4_v3
    jmp         .batch
.single:
    test        r15d, 0x100
    jnz         .transposed
    mov         ecx, eax                    ; A[i][j]: rho || j || i
    jmp         .sample
.transposed:
    mov         ecx, edx                    ; A[j][i]: rho || i || j
    mov         edx, eax
.sample:
    mov         rdi, rbx
    mov         rsi, r12
    call        mk_sample_v3
    add         rbx, 512
    inc         r13d
    jmp         .batch
.done:
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbx
    ret

; =============================================================================
; MK_SCHEME name, k, eta1, du, dv: one parameter set's K-PKE and ML-KEM routines in v1 (scalar):
; <name>_keypair_v1, _encaps_v1, _decaps_v1, which MK_PUBLIC's C ABI functions pick from. eta2
; is 2 for all three.
; =============================================================================
%macro MK_SCHEME 5
  %xdefine MS_K %2
  %xdefine MS_ETA1 %3
  %xdefine MS_DU %4
  %xdefine MS_DV %5
  %xdefine MS_EK (384 * MS_K + 32)
  %xdefine MS_DK (768 * MS_K + 96)
  %xdefine MS_CT (32 * (MS_DU * MS_K + MS_DV))
  %xdefine MS_P (MF_POLYS)                          ; polynomial vector 1 (k)
  %xdefine MS_Q (MF_POLYS + 512 * MS_K)             ; vector 2 (k)
  %xdefine MS_R (MF_POLYS + 1024 * MS_K)            ; vector 3 (k: a row or a column of A)
  %xdefine MS_T (MF_POLYS + 1536 * MS_K)            ; two single polynomials
  %xdefine MS_U (MS_T + 512)
  %xdefine MS_CBUF (MS_U + 512)                     ; c', re-encrypted (decapsulation)
  %xdefine MS_END ((MS_CBUF + MS_CT + 63) & -64)
  %xdefine MS_FRAME (MS_END + 64)

; ----------------------------------------------------------------------------
; %1_pke_enc: K-PKE.Encrypt (FIPS 203 Algorithm 14) in the frame: rdi = c's destination, rsi = ek
; (its t-hat checked below q, or written by the library), rdx = m (32), rcx = r (32). t-hat
; decoded into vector 1, y sampled and transformed into vector 2; then each u_i = NTT^-1(sum over
; j of A[j][i] y_j) + e1_i (column i of A sampled into vector 3), compressed straight into c;
; v = NTT^-1(t-hat . y) + e2 + Decompress_1(m), compressed. Keeps rbx, rbp, r12-r15.
; ----------------------------------------------------------------------------
align 16
%1_pke_enc:
    push        rbx
    push        r12
    push        r13
    push        r14
    push        r15
    sub         rsp, 16
    mov         rbx, rdi                    ; c
    mov         r12, rsi                    ; ek
    mov         r13, rdx                    ; m
    mov         r14, rcx                    ; r
  %assign mi 0
  %rep MS_K
    lea         rdi, [rbp + MS_P + 512 * mi]
    lea         rsi, [r12 + 384 * mi]
    call        mk_decode12_v1
    lea         rdi, [rbp + MS_Q + 512 * mi]
    mov         rsi, r14
    mov         edx, mi
    mov         ecx, MS_ETA1
    call        mk_prf                      ; y_i (nonce i)
    lea         rdi, [rbp + MS_Q + 512 * mi]
    call        mk_ntt_v1
    %assign mi mi + 1
  %endrep
    xor         r15d, r15d                  ; i
.column:
    xor         eax, eax
    mov         [rbp + MF_CNT], rax         ; j
.sample:
    mov         rax, [rbp + MF_CNT]
    mov         rdi, rax
    shl         rdi, 9
    lea         rdi, [rbp + MS_R + rdi]
    lea         rsi, [r12 + 384 * MS_K]     ; rho
    mov         edx, r15d                   ; A[j][i] = SampleNTT(rho || i || j)
    mov         ecx, eax
    call        mk_sample
    inc         qword [rbp + MF_CNT]
    cmp         qword [rbp + MF_CNT], MS_K
    jb          .sample
    lea         rdi, [rbp + MS_T]
    lea         rsi, [rbp + MS_R]
    lea         rdx, [rbp + MS_Q]
    mov         ecx, MS_K
    call        mk_basemul_acc_v1
    lea         rdi, [rbp + MS_T]
    call        mk_invntt_v1
    lea         rdi, [rbp + MS_U]
    mov         rsi, r14
    lea         edx, [r15 + MS_K]           ; e1_i: nonce k + i
    mov         ecx, 2
    call        mk_prf
    lea         rdi, [rbp + MS_T]
    lea         rsi, [rbp + MS_T]
    lea         rdx, [rbp + MS_U]
    call        mk_add_v1
    lea         rdi, [rbp + MS_T]
    call        mk_reduce_v1
    imul        edi, r15d, 32 * MS_DU
    add         rdi, rbx
    lea         rsi, [rbp + MS_T]
    mov         edx, MS_DU
    call        mk_compress_v1
    inc         r15d
    cmp         r15d, MS_K
    jb          .column
    ; v
    lea         rdi, [rbp + MS_T]
    lea         rsi, [rbp + MS_P]
    lea         rdx, [rbp + MS_Q]
    mov         ecx, MS_K
    call        mk_basemul_acc_v1
    lea         rdi, [rbp + MS_T]
    call        mk_invntt_v1
    lea         rdi, [rbp + MS_U]
    mov         rsi, r14
    mov         edx, 2 * MS_K               ; e2: nonce 2k
    mov         ecx, 2
    call        mk_prf
    lea         rdi, [rbp + MS_T]
    lea         rsi, [rbp + MS_T]
    lea         rdx, [rbp + MS_U]
    call        mk_add_v1
    lea         rdi, [rbp + MS_U]
    mov         rsi, r13
    call        mk_frommsg_v1
    lea         rdi, [rbp + MS_T]
    lea         rsi, [rbp + MS_T]
    lea         rdx, [rbp + MS_U]
    call        mk_add_v1
    lea         rdi, [rbp + MS_T]
    call        mk_reduce_v1
    lea         rdi, [rbx + 32 * MS_DU * MS_K]
    lea         rsi, [rbp + MS_T]
    mov         edx, MS_DV
    call        mk_compress_v1
    add         rsp, 16
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbx
    ret

; ----------------------------------------------------------------------------
; <name>_keypair_v1 (httpasm_<name>_keypair's v1: uint8_t ek[EK], uint8_t dk[DK], const uint8_t
; seed[64]): ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16) from d = seed[0..32), z =
; seed[32..64).
; ----------------------------------------------------------------------------
align 16
%1_keypair_v1:
    MK_ENTER    MS_FRAME
    mov         [rbp + MF_OUT], rdi         ; ek
    mov         [rbp + MF_ARG1], rsi        ; dk
    mov         [rbp + MF_ARG2], rdx        ; seed
    ; (rho, sigma) = G(d || k)
    lea         rdi, [rbp + MF_IN]
    mov         rsi, rdx
    mov         ecx, 32
    call        ha_copy_short
    mov         byte [rbp + MF_IN + 32], MS_K
    lea         rdi, [rbp + MF_IN]
    mov         esi, 33
    lea         rdx, [rbp + MF_G]
    call        httpasm_sha3_512
    ; s (vector 1) and e (vector 2), transformed
  %assign mi 0
  %rep MS_K
    lea         rdi, [rbp + MS_P + 512 * mi]
    lea         rsi, [rbp + MF_G + 32]
    mov         edx, mi
    mov         ecx, MS_ETA1
    call        mk_prf
    lea         rdi, [rbp + MS_P + 512 * mi]
    call        mk_ntt_v1
    lea         rdi, [rbp + MS_Q + 512 * mi]
    lea         rsi, [rbp + MF_G + 32]
    mov         edx, MS_K + mi
    mov         ecx, MS_ETA1
    call        mk_prf
    lea         rdi, [rbp + MS_Q + 512 * mi]
    call        mk_ntt_v1
    %assign mi mi + 1
  %endrep
    ; t_i = (sum over j of A[i][j] s_j) R + e_i, encoded into ek and dk's copy of it
    mov         qword [rbp + MF_CNT2], 0    ; i
.row:
    mov         qword [rbp + MF_CNT], 0     ; j
.sample:
    mov         rax, [rbp + MF_CNT]
    mov         rdi, rax
    shl         rdi, 9
    lea         rdi, [rbp + MS_R + rdi]
    lea         rsi, [rbp + MF_G]           ; rho
    mov         edx, eax                    ; A[i][j] = SampleNTT(rho || j || i)
    mov         ecx, [rbp + MF_CNT2]
    call        mk_sample
    inc         qword [rbp + MF_CNT]
    cmp         qword [rbp + MF_CNT], MS_K
    jb          .sample
    lea         rdi, [rbp + MS_T]
    lea         rsi, [rbp + MS_R]
    lea         rdx, [rbp + MS_P]
    mov         ecx, MS_K
    call        mk_basemul_acc_v1
    lea         rdi, [rbp + MS_T]
    call        mk_tomont_v1
    mov         rax, [rbp + MF_CNT2]
    shl         rax, 9
    lea         rdx, [rbp + MS_Q + rax]     ; e_i
    lea         rdi, [rbp + MS_T]
    lea         rsi, [rbp + MS_T]
    call        mk_add_v1
    lea         rdi, [rbp + MS_T]
    call        mk_reduce_v1
    imul        rdi, [rbp + MF_CNT2], 384
    add         rdi, [rbp + MF_OUT]
    lea         rsi, [rbp + MS_T]
    call        mk_encode12_v1
    inc         qword [rbp + MF_CNT2]
    cmp         qword [rbp + MF_CNT2], MS_K
    jb          .row
    ; ek's rho; dk = ByteEncode_12(s-hat) || ek || H(ek) || z
    mov         rdi, [rbp + MF_OUT]
    add         rdi, 384 * MS_K
    lea         rsi, [rbp + MF_G]
    mov         ecx, 32
    call        ha_copy_short
  %assign mi 0
  %rep MS_K
    mov         rdi, [rbp + MF_ARG1]
    add         rdi, 384 * mi
    lea         rsi, [rbp + MS_P + 512 * mi]
    call        mk_encode12_v1
    %assign mi mi + 1
  %endrep
    mov         rdi, [rbp + MF_ARG1]
    add         rdi, 384 * MS_K
    mov         rsi, [rbp + MF_OUT]
    mov         ecx, MS_EK
    call        mk_copy_long
    mov         rdi, [rbp + MF_OUT]
    mov         esi, MS_EK
    mov         rdx, [rbp + MF_ARG1]
    add         rdx, 384 * MS_K + MS_EK
    call        httpasm_sha3_256
    mov         rdi, [rbp + MF_ARG1]
    add         rdi, 384 * MS_K + MS_EK + 32
    mov         rsi, [rbp + MF_ARG2]
    add         rsi, 32                     ; z
    mov         ecx, 32
    call        ha_copy_short
    mov         qword [rbp + MF_RES], 0
    MK_FINISH   MS_FRAME, MS_END
.end:

; ----------------------------------------------------------------------------
; <name>_encaps_v1 (httpasm_<name>_encaps's v1: uint8_t c[CT], uint8_t key[32], const uint8_t
; ek[EK], const uint8_t m[32] -> int): ML-KEM.Encaps_internal (FIPS 203 Algorithm 17) after 7.2's
; modulus check (-1, c and key zeroed, when a coefficient of ek is q or more).
; ----------------------------------------------------------------------------
align 16
%1_encaps_v1:
    MK_ENTER    MS_FRAME
    mov         [rbp + MF_OUT], rdi         ; c
    mov         [rbp + MF_ARG1], rsi        ; key
    mov         [rbp + MF_ARG2], rdx        ; ek
    mov         [rbp + MF_ARG3], rcx        ; m
    mov         rdi, rdx
    mov         ecx, MS_K
    call        mk_check12
    test        eax, eax
    jnz         .refused
    ; (K, r) = G(m || H(ek))
    mov         rdi, [rbp + MF_ARG2]
    mov         esi, MS_EK
    lea         rdx, [rbp + MF_IN + 32]
    call        httpasm_sha3_256
    lea         rdi, [rbp + MF_IN]
    mov         rsi, [rbp + MF_ARG3]
    mov         ecx, 32
    call        ha_copy_short
    lea         rdi, [rbp + MF_IN]
    mov         esi, 64
    lea         rdx, [rbp + MF_G]
    call        httpasm_sha3_512
    mov         rdi, [rbp + MF_OUT]
    mov         rsi, [rbp + MF_ARG2]
    mov         rdx, [rbp + MF_ARG3]
    lea         rcx, [rbp + MF_G + 32]
    call        %1_pke_enc
    mov         rdi, [rbp + MF_ARG1]
    lea         rsi, [rbp + MF_G]
    mov         ecx, 32
    call        ha_copy_short
    mov         qword [rbp + MF_RES], 0
    jmp         .done
.refused:
    mov         rdi, [rbp + MF_OUT]
    xor         eax, eax
    mov         ecx, MS_CT
    rep         stosb
    mov         rdi, [rbp + MF_ARG1]
    mov         ecx, 32
    rep         stosb
    mov         qword [rbp + MF_RES], -1
.done:
    MK_FINISH   MS_FRAME, MS_END
.end:

; ----------------------------------------------------------------------------
; <name>_decaps_v1 (httpasm_<name>_decaps's v1: uint8_t key[32], const uint8_t dk[DK], const
; uint8_t c[CT] -> int): ML-KEM.Decaps_internal (FIPS 203 Algorithm 18) after 7.3's hash check
; (-1, key zeroed, when H(dk's ek) differs from the hash dk carries). m' = K-PKE.Decrypt; (K',
; r') = G(m' || h); c' = K-PKE.Encrypt(ek, m', r'); key = K' when c' = c, J(z || c) otherwise,
; by mask.
; ----------------------------------------------------------------------------
align 16
%1_decaps_v1:
    MK_ENTER    MS_FRAME
    mov         [rbp + MF_OUT], rdi         ; key
    mov         [rbp + MF_ARG1], rsi        ; dk
    mov         [rbp + MF_ARG2], rdx        ; c
    ; the hash check (public data: dk's ek and the hash beside it)
    lea         rdi, [rsi + 384 * MS_K]
    mov         esi, MS_EK
    lea         rdx, [rbp + MF_HEK]
    call        httpasm_sha3_256
    mov         rsi, [rbp + MF_ARG1]
    add         rsi, 384 * MS_K + MS_EK
    mov         rax, [rbp + MF_HEK]
    xor         rax, [rsi]
    mov         rcx, [rbp + MF_HEK + 8]
    xor         rcx, [rsi + 8]
    or          rax, rcx
    mov         rcx, [rbp + MF_HEK + 16]
    xor         rcx, [rsi + 16]
    or          rax, rcx
    mov         rcx, [rbp + MF_HEK + 24]
    xor         rcx, [rsi + 24]
    or          rax, rcx
    jnz         .refused
    ; m' = K-PKE.Decrypt(dk_PKE, c): u' into vector 2 (transformed), v' into T, s-hat into vector 1
  %assign mi 0
  %rep MS_K
    lea         rdi, [rbp + MS_Q + 512 * mi]
    mov         rsi, [rbp + MF_ARG2]
    add         rsi, 32 * MS_DU * mi
    mov         edx, MS_DU
    call        mk_decompress_v1
    lea         rdi, [rbp + MS_Q + 512 * mi]
    call        mk_ntt_v1
    lea         rdi, [rbp + MS_P + 512 * mi]
    mov         rsi, [rbp + MF_ARG1]
    add         rsi, 384 * mi
    call        mk_decode12_v1
    %assign mi mi + 1
  %endrep
    lea         rdi, [rbp + MS_U]
    mov         rsi, [rbp + MF_ARG2]
    add         rsi, 32 * MS_DU * MS_K
    mov         edx, MS_DV
    call        mk_decompress_v1
    lea         rdi, [rbp + MS_T]
    lea         rsi, [rbp + MS_P]
    lea         rdx, [rbp + MS_Q]
    mov         ecx, MS_K
    call        mk_basemul_acc_v1
    lea         rdi, [rbp + MS_T]
    call        mk_invntt_v1
    lea         rdi, [rbp + MS_T]
    lea         rsi, [rbp + MS_U]
    lea         rdx, [rbp + MS_T]
    call        mk_sub_v1                   ; w = v' - NTT^-1(s-hat . NTT(u'))
    lea         rdi, [rbp + MS_T]
    call        mk_reduce_v1
    lea         rdi, [rbp + MF_M]
    lea         rsi, [rbp + MS_T]
    call        mk_tomsg_v1
    ; (K', r') = G(m' || h); K-bar = J(z || c)
    lea         rdi, [rbp + MF_IN]
    lea         rsi, [rbp + MF_M]
    mov         ecx, 32
    call        ha_copy_short
    lea         rdi, [rbp + MF_IN + 32]
    lea         rsi, [rbp + MF_HEK]
    mov         ecx, 32
    call        ha_copy_short
    lea         rdi, [rbp + MF_IN]
    mov         esi, 64
    lea         rdx, [rbp + MF_G]
    call        httpasm_sha3_512
    lea         rdi, [rbp + MF_XOF]
    call        httpasm_shake256_init
    lea         rdi, [rbp + MF_XOF]
    mov         rsi, [rbp + MF_ARG1]
    add         rsi, MS_DK - 32             ; z
    mov         edx, 32
    call        httpasm_sha3_update
    lea         rdi, [rbp + MF_XOF]
    mov         rsi, [rbp + MF_ARG2]
    mov         edx, MS_CT
    call        httpasm_sha3_update
    lea         rdi, [rbp + MF_XOF]
    lea         rsi, [rbp + MF_KBAR]
    mov         edx, 32
    call        httpasm_shake_squeeze
    ; c' = K-PKE.Encrypt(ek_PKE, m', r'), compared with c (every octet, by OR of XORs)
    lea         rdi, [rbp + MS_CBUF]
    mov         rsi, [rbp + MF_ARG1]
    add         rsi, 384 * MS_K             ; dk's ek
    lea         rdx, [rbp + MF_M]
    lea         rcx, [rbp + MF_G + 32]
    call        %1_pke_enc
    mov         rsi, [rbp + MF_ARG2]
    xor         eax, eax
    xor         ecx, ecx
.compare:
    mov         rdx, [rbp + MS_CBUF + rcx]
    xor         rdx, [rsi + rcx]
    or          rax, rdx
    add         ecx, 8
    cmp         ecx, MS_CT                  ; (a multiple of 8)
    jb          .compare
    neg         rax
    sbb         rax, rax                    ; all ones when they differed
    ; key = K-bar where they differ, K' where they agree
    mov         rdi, [rbp + MF_OUT]
  %assign mq 0
  %rep 4
    mov         rcx, [rbp + MF_KBAR + 8 * mq]
    mov         rdx, [rbp + MF_G + 8 * mq]
    xor         rcx, rdx
    and         rcx, rax
    xor         rdx, rcx
    mov         [rdi + 8 * mq], rdx
    %assign mq mq + 1
  %endrep
    mov         qword [rbp + MF_RES], 0
    jmp         .done
.refused:
    mov         rdi, [rbp + MF_OUT]
    xor         eax, eax
    mov         ecx, 32
    rep         stosb
    mov         qword [rbp + MF_RES], -1
.done:
    MK_FINISH   MS_FRAME, MS_END
.end:
%endmacro

; -----------------------------------------------------------------------------
; mk_copy_long: rdi = destination, rsi = source, ecx = octets (an encapsulation key's: up to
; 1568) by rep movsb. Keeps every register but rcx, rsi, rdi.
; -----------------------------------------------------------------------------
align 16
mk_copy_long:
    rep         movsb
    ret

; =============================================================================
; MK_SCHEME3 name, k, eta1, du, dv: the parameter set's v3 (AVX2) routines <name>_keypair_v3,
; _encaps_v3, _decaps_v3: MK_SCHEME's algorithms with v3's routines, in a frame of their own.
; Differences from v1's flow:
;   - each polynomial a product takes as its second factor gets a cache (mk_mulcache_v3) once:
;     key generation's s-hat, encryption's y-hat (used k + 1 times), decryption's u-hat;
;   - the matrix is sampled a group of rows (key generation) or columns (encryption) at a time:
;     all k for k = 2 and 3 (k^2 entries), one for k = 4 (4 entries); the entries are public, so
;     they sit above the wiped part of the frame;
;   - the noise vectors are sampled as one run of nonces (mk_noise_v3);
;   - no reduction before the compressions and encodings: they take the sums as they come.
; =============================================================================
%macro MK_SCHEME3 5
  %xdefine M3_K %2
  %xdefine M3_ETA1 %3
  %xdefine M3_DU %4
  %xdefine M3_DV %5
  %xdefine M3_EK (384 * M3_K + 32)
  %xdefine M3_DK (768 * M3_K + 96)
  %xdefine M3_CT (32 * (M3_DU * M3_K + M3_DV))
  %if M3_K == 4
    %xdefine M3_ROWS 1                              ; rows (or columns) sampled together
  %else
    %xdefine M3_ROWS M3_K
  %endif
  %xdefine M3_COMPU mk_compress %+ M3_DU %+ _v3
  %xdefine M3_COMPV mk_compress %+ M3_DV %+ _v3
  %xdefine M3_DECU mk_decompress %+ M3_DU %+ _v3
  %xdefine M3_DECV mk_decompress %+ M3_DV %+ _v3
  %xdefine M3_P (MF3_POLYS)                         ; vector 1: s-hat, t-hat (k)
  %xdefine M3_Q (M3_P + 512 * M3_K)                 ; vector 2: e, y-hat, u-hat (k)
  %xdefine M3_E (M3_Q + 512 * M3_K)                 ; e1, e2 (k + 1; right after vector 2)
  %xdefine M3_C (M3_E + 512 * (M3_K + 1))           ; k caches (1024 octets each)
  %xdefine M3_T (M3_C + 1024 * M3_K)                ; two single polynomials
  %xdefine M3_U (M3_T + 512)
  %xdefine M3_CBUF (M3_U + 512)                     ; c', re-encrypted (decapsulation)
  %xdefine M3_WIPE ((M3_CBUF + M3_CT + 63) & -64)   ; the frame below this is wiped
  %xdefine M3_A (M3_WIPE)                           ; the matrix's entries
  %xdefine M3_FRAME (M3_A + 512 * M3_ROWS * M3_K + 64)

; ----------------------------------------------------------------------------
; %1_pke_enc_v3: K-PKE.Encrypt in v3's frame (arguments as %1_pke_enc's: rdi = c's destination,
; rsi = ek, rdx = m, rcx = r). t-hat into vector 1; y, e1, e2 sampled as one run (vector 2 and
; the e area); y-hat cached; u_i from column i of A (the group's entries at M3_A), compressed
; straight into c; then v. Keeps rbx, rbp, r12-r15.
; ----------------------------------------------------------------------------
align 16
%1_pke_enc_v3:
    push        rbx
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rbx, rdi                    ; c
    mov         r12, rsi                    ; ek
    mov         r13, rdx                    ; m
    mov         r14, rcx                    ; r
  %assign mi 0
  %rep M3_K
    lea         rdi, [rbp + M3_P + 512 * mi]
    lea         rsi, [r12 + 384 * mi]
    call        mk_decode12_v3
    %assign mi mi + 1
  %endrep
    lea         rdi, [rbp + M3_Q]
    mov         rsi, r14
    mov         ecx, 2 * M3_K + 1           ; y (nonces 0 .. k - 1, eta1), e1, e2 (eta2)
    mov         edx, M3_K
    mov         r8d, M3_ETA1
    call        mk_noise_v3
  %assign mi 0
  %rep M3_K
    lea         rdi, [rbp + M3_Q + 512 * mi]
    call        mk_ntt_v3
    lea         rdi, [rbp + M3_C + 1024 * mi]
    lea         rsi, [rbp + M3_Q + 512 * mi]
    call        mk_mulcache_v3
    %assign mi mi + 1
  %endrep
  %if M3_ROWS > 1
    lea         rdi, [rbp + M3_A]           ; every column of A at once
    lea         rsi, [r12 + 384 * M3_K]
    xor         edx, edx
    mov         ecx, M3_K * M3_K
    mov         r8d, M3_K
    mov         r9d, 1
    call        mk_matrix_v3
  %endif
    xor         r15d, r15d                  ; i
.column:
  %if M3_ROWS == 1
    lea         rdi, [rbp + M3_A]           ; column i of A
    lea         rsi, [r12 + 384 * M3_K]
    imul        edx, r15d, M3_K
    mov         ecx, M3_K
    mov         r8d, M3_K
    mov         r9d, 1
    call        mk_matrix_v3
    lea         rsi, [rbp + M3_A]
  %else
    imul        esi, r15d, 512 * M3_K
    lea         rsi, [rbp + M3_A + rsi]
  %endif
    lea         rdi, [rbp + M3_T]
    lea         rdx, [rbp + M3_C]
    mov         ecx, M3_K
    call        mk_basemul_acc_v3
    lea         rdi, [rbp + M3_T]
    call        mk_invntt_v3
    mov         eax, r15d
    shl         eax, 9
    lea         rdx, [rbp + M3_E + rax]     ; e1_i
    lea         rdi, [rbp + M3_T]
    lea         rsi, [rbp + M3_T]
    call        mk_add_v3
    imul        edi, r15d, 32 * M3_DU
    add         rdi, rbx
    lea         rsi, [rbp + M3_T]
    call        M3_COMPU
    inc         r15d
    cmp         r15d, M3_K
    jb          .column
    ; v = NTT^-1(t-hat . y-hat) + e2 + Decompress_1(m)
    lea         rdi, [rbp + M3_T]
    lea         rsi, [rbp + M3_P]
    lea         rdx, [rbp + M3_C]
    mov         ecx, M3_K
    call        mk_basemul_acc_v3
    lea         rdi, [rbp + M3_T]
    call        mk_invntt_v3
    lea         rdi, [rbp + M3_T]
    lea         rsi, [rbp + M3_T]
    lea         rdx, [rbp + M3_E + 512 * M3_K]
    call        mk_add_v3
    lea         rdi, [rbp + M3_U]
    mov         rsi, r13
    call        mk_frommsg_v3
    lea         rdi, [rbp + M3_T]
    lea         rsi, [rbp + M3_T]
    lea         rdx, [rbp + M3_U]
    call        mk_add_v3
    lea         rdi, [rbx + 32 * M3_DU * M3_K]
    lea         rsi, [rbp + M3_T]
    call        M3_COMPV
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbx
    ret

; ----------------------------------------------------------------------------
; <name>_keypair_v3: as <name>_keypair_v1. s and e as one run of 2k nonces, transformed; s-hat
; cached; t_i from row i of A, encoded straight into ek.
; ----------------------------------------------------------------------------
align 16
%1_keypair_v3:
    MK_ENTER    M3_FRAME
    mov         [rbp + MF_OUT], rdi         ; ek
    mov         [rbp + MF_ARG1], rsi        ; dk
    mov         [rbp + MF_ARG2], rdx        ; seed
    lea         rdi, [rbp + MF_IN]          ; (rho, sigma) = G(d || k)
    mov         rsi, rdx
    mov         ecx, 32
    call        ha_copy_short
    mov         byte [rbp + MF_IN + 32], M3_K
    lea         rdi, [rbp + MF_IN]
    mov         esi, 33
    lea         rdx, [rbp + MF_G]
    call        httpasm_sha3_512
    lea         rdi, [rbp + M3_P]           ; s (vector 1), e (vector 2)
    lea         rsi, [rbp + MF_G + 32]
    mov         ecx, 2 * M3_K
    mov         edx, 2 * M3_K
    mov         r8d, M3_ETA1
    call        mk_noise_v3
  %assign mi 0
  %rep 2 * M3_K
    lea         rdi, [rbp + M3_P + 512 * mi]
    call        mk_ntt_v3
    %assign mi mi + 1
  %endrep
  %assign mi 0
  %rep M3_K
    lea         rdi, [rbp + M3_C + 1024 * mi]
    lea         rsi, [rbp + M3_P + 512 * mi]
    call        mk_mulcache_v3
    %assign mi mi + 1
  %endrep
  %if M3_ROWS > 1
    lea         rdi, [rbp + M3_A]           ; every row of A at once
    lea         rsi, [rbp + MF_G]
    xor         edx, edx
    mov         ecx, M3_K * M3_K
    mov         r8d, M3_K
    xor         r9d, r9d
    call        mk_matrix_v3
  %endif
    xor         r12d, r12d                  ; i
.row:
  %if M3_ROWS == 1
    lea         rdi, [rbp + M3_A]           ; row i of A
    lea         rsi, [rbp + MF_G]
    imul        edx, r12d, M3_K
    mov         ecx, M3_K
    mov         r8d, M3_K
    xor         r9d, r9d
    call        mk_matrix_v3
    lea         rsi, [rbp + M3_A]
  %else
    imul        esi, r12d, 512 * M3_K
    lea         rsi, [rbp + M3_A + rsi]
  %endif
    lea         rdi, [rbp + M3_T]
    lea         rdx, [rbp + M3_C]
    mov         ecx, M3_K
    call        mk_basemul_acc_v3
    lea         rdi, [rbp + M3_T]
    call        mk_tomont_v3
    mov         eax, r12d
    shl         eax, 9
    lea         rdx, [rbp + M3_Q + rax]     ; e_i
    lea         rdi, [rbp + M3_T]
    lea         rsi, [rbp + M3_T]
    call        mk_add_v3
    imul        edi, r12d, 384
    add         rdi, [rbp + MF_OUT]
    lea         rsi, [rbp + M3_T]
    call        mk_encode12_v3
    inc         r12d
    cmp         r12d, M3_K
    jb          .row
    mov         rdi, [rbp + MF_OUT]         ; ek's rho; dk = ByteEncode_12(s-hat) || ek || H(ek) || z
    add         rdi, 384 * M3_K
    lea         rsi, [rbp + MF_G]
    mov         ecx, 32
    call        ha_copy_short
  %assign mi 0
  %rep M3_K
    mov         rdi, [rbp + MF_ARG1]
    add         rdi, 384 * mi
    lea         rsi, [rbp + M3_P + 512 * mi]
    call        mk_encode12_v3
    %assign mi mi + 1
  %endrep
    mov         rdi, [rbp + MF_ARG1]
    add         rdi, 384 * M3_K
    mov         rsi, [rbp + MF_OUT]
    mov         ecx, M3_EK
    call        mk_copy_long
    mov         rdi, [rbp + MF_OUT]
    mov         esi, M3_EK
    mov         rdx, [rbp + MF_ARG1]
    add         rdx, 384 * M3_K + M3_EK
    call        httpasm_sha3_256
    mov         rdi, [rbp + MF_ARG1]
    add         rdi, 384 * M3_K + M3_EK + 32
    mov         rsi, [rbp + MF_ARG2]
    add         rsi, 32
    mov         ecx, 32
    call        ha_copy_short
    mov         qword [rbp + MF_RES], 0
    MK_FINISH   M3_FRAME, M3_WIPE

; ----------------------------------------------------------------------------
; <name>_encaps_v3: as <name>_encaps_v1 (the modulus check by mk_check12_v3).
; ----------------------------------------------------------------------------
align 16
%1_encaps_v3:
    MK_ENTER    M3_FRAME
    mov         [rbp + MF_OUT], rdi         ; c
    mov         [rbp + MF_ARG1], rsi        ; key
    mov         [rbp + MF_ARG2], rdx        ; ek
    mov         [rbp + MF_ARG3], rcx        ; m
    mov         rdi, rdx
    mov         ecx, M3_K
    call        mk_check12_v3
    test        eax, eax
    jnz         .refused
    mov         rdi, [rbp + MF_ARG2]        ; (K, r) = G(m || H(ek))
    mov         esi, M3_EK
    lea         rdx, [rbp + MF_IN + 32]
    call        httpasm_sha3_256
    lea         rdi, [rbp + MF_IN]
    mov         rsi, [rbp + MF_ARG3]
    mov         ecx, 32
    call        ha_copy_short
    lea         rdi, [rbp + MF_IN]
    mov         esi, 64
    lea         rdx, [rbp + MF_G]
    call        httpasm_sha3_512
    mov         rdi, [rbp + MF_OUT]
    mov         rsi, [rbp + MF_ARG2]
    mov         rdx, [rbp + MF_ARG3]
    lea         rcx, [rbp + MF_G + 32]
    call        %1_pke_enc_v3
    mov         rdi, [rbp + MF_ARG1]
    lea         rsi, [rbp + MF_G]
    mov         ecx, 32
    call        ha_copy_short
    mov         qword [rbp + MF_RES], 0
    jmp         .done
.refused:
    mov         rdi, [rbp + MF_OUT]
    xor         eax, eax
    mov         ecx, M3_CT
    rep         stosb
    mov         rdi, [rbp + MF_ARG1]
    mov         ecx, 32
    rep         stosb
    mov         qword [rbp + MF_RES], -1
.done:
    MK_FINISH   M3_FRAME, M3_WIPE

; ----------------------------------------------------------------------------
; <name>_decaps_v3: as <name>_decaps_v1. u' decompressed, transformed and cached (vector 2 and
; the caches), s-hat decoded (vector 1: raw 12-bit values, below 4096; the products' sums stay
; below 2^27 and their results below q all the same), v' into U.
; ----------------------------------------------------------------------------
align 16
%1_decaps_v3:
    MK_ENTER    M3_FRAME
    mov         [rbp + MF_OUT], rdi         ; key
    mov         [rbp + MF_ARG1], rsi        ; dk
    mov         [rbp + MF_ARG2], rdx        ; c
    lea         rdi, [rsi + 384 * M3_K]     ; the hash check (public data)
    mov         esi, M3_EK
    lea         rdx, [rbp + MF_HEK]
    call        httpasm_sha3_256
    mov         rsi, [rbp + MF_ARG1]
    add         rsi, 384 * M3_K + M3_EK
    mov         rax, [rbp + MF_HEK]
    xor         rax, [rsi]
    mov         rcx, [rbp + MF_HEK + 8]
    xor         rcx, [rsi + 8]
    or          rax, rcx
    mov         rcx, [rbp + MF_HEK + 16]
    xor         rcx, [rsi + 16]
    or          rax, rcx
    mov         rcx, [rbp + MF_HEK + 24]
    xor         rcx, [rsi + 24]
    or          rax, rcx
    jnz         .refused
  %assign mi 0
  %rep M3_K
    lea         rdi, [rbp + M3_Q + 512 * mi]
    mov         rsi, [rbp + MF_ARG2]
    add         rsi, 32 * M3_DU * mi
    call        M3_DECU
    lea         rdi, [rbp + M3_Q + 512 * mi]
    call        mk_ntt_v3
    lea         rdi, [rbp + M3_C + 1024 * mi]
    lea         rsi, [rbp + M3_Q + 512 * mi]
    call        mk_mulcache_v3
    lea         rdi, [rbp + M3_P + 512 * mi]
    mov         rsi, [rbp + MF_ARG1]
    add         rsi, 384 * mi
    call        mk_decode12_v3
    %assign mi mi + 1
  %endrep
    lea         rdi, [rbp + M3_U]
    mov         rsi, [rbp + MF_ARG2]
    add         rsi, 32 * M3_DU * M3_K
    call        M3_DECV
    lea         rdi, [rbp + M3_T]
    lea         rsi, [rbp + M3_P]
    lea         rdx, [rbp + M3_C]
    mov         ecx, M3_K
    call        mk_basemul_acc_v3
    lea         rdi, [rbp + M3_T]
    call        mk_invntt_v3
    lea         rdi, [rbp + M3_T]
    lea         rsi, [rbp + M3_U]
    lea         rdx, [rbp + M3_T]
    call        mk_sub_v3                   ; w = v' - NTT^-1(s-hat . NTT(u'))
    lea         rdi, [rbp + MF_M]
    lea         rsi, [rbp + M3_T]
    call        mk_tomsg_v3
    lea         rdi, [rbp + MF_IN]          ; (K', r') = G(m' || h); K-bar = J(z || c)
    lea         rsi, [rbp + MF_M]
    mov         ecx, 32
    call        ha_copy_short
    lea         rdi, [rbp + MF_IN + 32]
    lea         rsi, [rbp + MF_HEK]
    mov         ecx, 32
    call        ha_copy_short
    lea         rdi, [rbp + MF_IN]
    mov         esi, 64
    lea         rdx, [rbp + MF_G]
    call        httpasm_sha3_512
    lea         rdi, [rbp + MF_XOF]
    call        httpasm_shake256_init
    lea         rdi, [rbp + MF_XOF]
    mov         rsi, [rbp + MF_ARG1]
    add         rsi, M3_DK - 32
    mov         edx, 32
    call        httpasm_sha3_update
    lea         rdi, [rbp + MF_XOF]
    mov         rsi, [rbp + MF_ARG2]
    mov         edx, M3_CT
    call        httpasm_sha3_update
    lea         rdi, [rbp + MF_XOF]
    lea         rsi, [rbp + MF_KBAR]
    mov         edx, 32
    call        httpasm_shake_squeeze
    lea         rdi, [rbp + M3_CBUF]        ; c' = K-PKE.Encrypt(ek_PKE, m', r'), compared with c
    mov         rsi, [rbp + MF_ARG1]
    add         rsi, 384 * M3_K
    lea         rdx, [rbp + MF_M]
    lea         rcx, [rbp + MF_G + 32]
    call        %1_pke_enc_v3
    mov         rsi, [rbp + MF_ARG2]
    xor         eax, eax
    xor         ecx, ecx
.compare:
    mov         rdx, [rbp + M3_CBUF + rcx]
    xor         rdx, [rsi + rcx]
    or          rax, rdx
    add         ecx, 8
    cmp         ecx, M3_CT
    jb          .compare
    neg         rax
    sbb         rax, rax                    ; all ones when they differed
    mov         rdi, [rbp + MF_OUT]
  %assign mq 0
  %rep 4
    mov         rcx, [rbp + MF_KBAR + 8 * mq]
    mov         rdx, [rbp + MF_G + 8 * mq]
    xor         rcx, rdx
    and         rcx, rax
    xor         rdx, rcx
    mov         [rdi + 8 * mq], rdx
    %assign mq mq + 1
  %endrep
    mov         qword [rbp + MF_RES], 0
    jmp         .done
.refused:
    mov         rdi, [rbp + MF_OUT]
    xor         eax, eax
    mov         ecx, 32
    rep         stosb
    mov         qword [rbp + MF_RES], -1
.done:
    MK_FINISH   M3_FRAME, M3_WIPE
%endmacro

; =============================================================================
; MK_PUBLIC name: the C ABI's functions for one parameter set (httpasm.h documents them):
;   void httpasm_<name>_keypair(uint8_t ek[EK], uint8_t dk[DK], const uint8_t seed[64]);
;   int  httpasm_<name>_encaps(uint8_t c[CT], uint8_t key[32], const uint8_t ek[EK],
;                              const uint8_t m[32]);
;   int  httpasm_<name>_decaps(uint8_t key[32], const uint8_t dk[DK], const uint8_t c[CT]);
; each a tail jump to v3 (AVX2) when ha_cpu has it, else to v1: the versions return to the caller
; themselves, with the same results octet for octet.
; =============================================================================
%macro MK_PUBLIC 1
global httpasm_%1_keypair:function (httpasm_%1_keypair.end - httpasm_%1_keypair)
align 16
httpasm_%1_keypair:
    HA_CPU_PICK HTTPASM_CPU_V3, .v3
    jmp         %1_keypair_v1
.v3:
    jmp         %1_keypair_v3
.end:

global httpasm_%1_encaps:function (httpasm_%1_encaps.end - httpasm_%1_encaps)
align 16
httpasm_%1_encaps:
    HA_CPU_PICK HTTPASM_CPU_V3, .v3
    jmp         %1_encaps_v1
.v3:
    jmp         %1_encaps_v3
.end:

global httpasm_%1_decaps:function (httpasm_%1_decaps.end - httpasm_%1_decaps)
align 16
httpasm_%1_decaps:
    HA_CPU_PICK HTTPASM_CPU_V3, .v3
    jmp         %1_decaps_v1
.v3:
    jmp         %1_decaps_v3
.end:
%endmacro

MK_SCHEME mlkem512, 2, 3, 10, 4
MK_SCHEME mlkem768, 3, 2, 10, 4
MK_SCHEME mlkem1024, 4, 2, 11, 5
MK_SCHEME3 mlkem512, 2, 3, 10, 4
MK_SCHEME3 mlkem768, 3, 2, 10, 4
MK_SCHEME3 mlkem1024, 4, 2, 11, 5
MK_PUBLIC mlkem512
MK_PUBLIC mlkem768
MK_PUBLIC mlkem1024
