; =============================================================================
; crypto/mlkem.asm - ML-KEM (FIPS 203, August 2024), the post-quantum key encapsulation TLS 1.3
; combines with X25519 (RFC 10024's X25519MLKEM768, the hybrid browsers send by default) and with
; P-256 and P-384 (SecP256r1MLKEM768, SecP384r1MLKEM1024): the C ABI's httpasm_mlkem512_*,
; httpasm_mlkem768_* and httpasm_mlkem1024_* (keypair from a 64-octet seed, encapsulation with a
; caller's 32-octet message, decapsulation), each with FIPS 203 7.2's and 7.3's input checks.
;
; This is v1, every routine in plain scalar code over 16-bit coefficients: the library's own
; reference (an AVX2 version is the next step). Arithmetic modulo q = 3329 as in the CRYSTALS-Kyber
; reference code's design (Montgomery products with R = 2^16, Barrett reduction, the NTT's zetas
; in Montgomery form), written here from FIPS 203's algorithms:
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
; PRF = SHAKE256(s || N), XOF = SHAKE128(rho || j || i)). The matrix A is never stored whole: each
; row (key generation) or column (encryption: A transposed) is sampled when its product needs it.
;
; Constant time in the secrets (the seed, s, e, the message, r, y, the decrypted m'): no branch or
; address depends on them; the decapsulation compares the re-encrypted ciphertext with the one it
; was given by OR-ing their XORs, and picks K' or J(z || c) by mask (implicit rejection). Only
; public data steers branches: rejection sampling (rho), the input checks (the keys).
; Stack: up to about 10 KiB (ML-KEM-1024's decapsulation: 14 polynomials and the ciphertext),
; all of it wiped before a function returns.
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
; The schemes. The frame (rbp, 64-aligned) is sized per parameter set by MK_SCHEME; every
; routine below works in its caller's frame through these offsets.
; =============================================================================
MF_G        equ 0                           ; G's output: rho, sigma or K, r (64)
MF_IN       equ 64                          ; G's input: d || k, or m || H(ek) (64)
MF_PRF      equ 128                         ; a PRF's output (up to 64 eta = 192)
MF_PRFIN    equ 320                         ; a PRF's input: a seed and its nonce (33)
MF_HEK      equ 384                         ; H(ek) (32)
MF_M        equ 416                         ; decapsulation's m' (32)
MF_KBAR     equ 448                         ; J(z || c) (32)
MF_SEED     equ 480                         ; the 34-octet XOF input: rho, j, i
MF_OUT      equ 520                         ; the caller's arguments
MF_ARG1     equ 528
MF_ARG2     equ 536
MF_ARG3     equ 544
MF_RES      equ 552                         ; the result to return
MF_CNT      equ 560                         ; loop counters
MF_CNT2     equ 568
MF_FAIL     equ 576                         ; decapsulation's mismatch mask
MF_XOF      equ 640                         ; a SHAKE context (216)
MF_XBUF     equ 896                         ; its squeezed octets (504: three blocks)
MF_POLYS    equ 1408                        ; the polynomials from here (512 each; 64-aligned)

; MK_ENTER frame / MK_FINISH frame, end: as ed25519.asm's: six registers kept, the 64-aligned
; frame at rbp (rsp 16-aligned for the C calls), the entry rsp in the frame's last qword;
; FINISH wipes [rbp, rbp + end) and returns MF_RES's low dword.
%macro MK_ENTER 1
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    and         rsp, -64
    sub         rsp, %1
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

; =============================================================================
; MK_SCHEME name, k, eta1, du, dv: one parameter set's K-PKE and ML-KEM routines and its C ABI
; functions httpasm_<name>_keypair, _encaps, _decaps. eta2 is 2 for all three.
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
; void httpasm_<name>_keypair(uint8_t ek[EK], uint8_t dk[DK], const uint8_t seed[64]):
; ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16) from d = seed[0..32), z = seed[32..64).
; ----------------------------------------------------------------------------
global httpasm_%1_keypair:function (httpasm_%1_keypair.end - httpasm_%1_keypair)
align 16
httpasm_%1_keypair:
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
; int httpasm_<name>_encaps(uint8_t c[CT], uint8_t key[32], const uint8_t ek[EK],
;                           const uint8_t m[32]): ML-KEM.Encaps_internal (FIPS 203 Algorithm 17)
; after 7.2's modulus check (-1, c and key zeroed, when a coefficient of ek is q or more).
; ----------------------------------------------------------------------------
global httpasm_%1_encaps:function (httpasm_%1_encaps.end - httpasm_%1_encaps)
align 16
httpasm_%1_encaps:
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
; int httpasm_<name>_decaps(uint8_t key[32], const uint8_t dk[DK], const uint8_t c[CT]):
; ML-KEM.Decaps_internal (FIPS 203 Algorithm 18) after 7.3's hash check (-1, key zeroed, when
; H(dk's ek) differs from the hash dk carries). m' = K-PKE.Decrypt; (K', r') = G(m' || h);
; c' = K-PKE.Encrypt(ek, m', r'); key = K' when c' = c, J(z || c) otherwise, by mask.
; ----------------------------------------------------------------------------
global httpasm_%1_decaps:function (httpasm_%1_decaps.end - httpasm_%1_decaps)
align 16
httpasm_%1_decaps:
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

MK_SCHEME mlkem512, 2, 3, 10, 4
MK_SCHEME mlkem768, 3, 2, 10, 4
MK_SCHEME mlkem1024, 4, 2, 11, 5
