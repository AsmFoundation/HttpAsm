; =============================================================================
; crypto/rsa.asm - RSA signature verification (RFC 8017), as TLS 1.3 needs it for certificate
; chains (sha256WithRSAEncryption and its kin: RSASSA-PKCS1-v1_5) and for CertificateVerify
; (rsa_pss_rsae_sha256/384/512: RSASSA-PSS with MGF1): the C ABI's
; httpasm_rsa_public_key_init, httpasm_rsa_verify_pkcs1 and httpasm_rsa_verify_pss, for moduli
; of 1024 to 8192 bits and public exponents up to 2^64 - 1.
;
; The arithmetic. Numbers are little-endian 64-bit limbs; a key's operations run on k limbs, its
; modulus' limbs rounded up to a multiple of 8 (the v3 loops take eight limbs a step; the zero
; limbs above change nothing), with R = 2^(64k). Three Montgomery operations, each in two versions
; picked per verification (v3: mulx with two carry chains, adcx on CF and adox on OF; v1: mul):
;   the product (CIOS, Koc, Acar and Kaliski: k rounds of t += a b_i, then m = t_0 n' and
;   t = (t + m n) / 2^64), 2k^2 multiplies;
;   the square: the products a_i a_j above the diagonal once (k(k - 1)/2 multiplies, eight rows
;   at a time so every row's part past its own block is whole 8-limb groups), doubled, the
;   squares a_i^2 added, then k reduction rows (k^2): 1.5k^2 multiplies in all, measured 1.28x
;   faster than the product at 2048 bits;
;   the reduction alone (out of Montgomery form: t R^-1 for a t of k limbs), k^2.
; Each ends with one conditional subtraction by mask, and runs the same instructions whatever the
; values. Measured on Raptor Cove: a multiply-accumulate costs about 1.4 cycles in any shape tried
; (rows, two rows interleaved, product scanning with one to three accumulators: 1.4 to 1.7) - two
; carry chains plus the multiply's ports 1 and 5 hold it there - so the gains are in doing fewer.
; The public operation s^e mod n by left-to-right square-and-multiply (e is public): s R by the
; product with R^2 mod n, a square per bit of e below its top, a product per set bit, the
; reduction at the end (65537: 16 squares, 2 products, 1 reduction). A key's R^2 mod n comes from
; long division (Knuth's algorithm D: the dividend 2^(128k) is a single bit), k^2 multiplies with
; mul, in variable time (n is public): 1.8 us at 2048 bits where eleven squarings took 13.2.
;
; The encodings, RFC 8017's steps in order: RSASSA-PKCS1-v1_5 (8.2.2) encodes the expected EM
; (00 01 FF.. 00, the DigestInfo of the hash, the digest) and compares; RSASSA-PSS (8.1.2, 9.1.2)
; checks EM's last octet, its top bits, unmasks DB with MGF1 (B.2.1), checks the padding and the
; 01 before the salt, and compares H with Hash(00^8 || mHash || salt). Everything here handles
; public values (keys, signatures, digests): it runs in variable time.
;
; Hashes, by HTTPASM_HASH_* (httpasm_abi.inc): SHA-1 and SHA-224 for PKCS#1 v1.5 only (their
; DigestInfo; the digest comes from the caller: legacy certificates), SHA-256, SHA-384 and SHA-512
; for both (PSS hashes inside: MGF1 and H').
; =============================================================================
default rel
%include "httpasm_core.inc"

extern httpasm_sha512                       ; crypto/sha512.asm (the core's list names SHA-384's)

section .rodata
; RFC 8017 9.2 note 1: the DER of DigestInfo up to the digest, per hash.
rsa_prefix_sha1:    db 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
rsa_prefix_sha224:  db 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
rsa_prefix_sha256:  db 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
rsa_prefix_sha384:  db 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
rsa_prefix_sha512:  db 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40

section .text

; -----------------------------------------------------------------------------
; The key's layout: httpasm_rsa_public_key (httpasm_abi.inc), by shorter names.
; -----------------------------------------------------------------------------
RK_N        equ httpasm_rsa_public_key.n    ; n, HTTPASM_RSA_LIMBS limbs (zero above its own)
RK_RR       equ httpasm_rsa_public_key.rr   ; R^2 mod n
RK_N0       equ httpasm_rsa_public_key.n0   ; -n^-1 mod 2^64
RK_E        equ httpasm_rsa_public_key.e    ; e
RK_LIMBS    equ httpasm_rsa_public_key.limbs ; k (dword): a multiple of 8
RK_BITS     equ httpasm_rsa_public_key.bits ; n's bit length (dword)
RK_SIZE     equ httpasm_rsa_public_key_size

; =============================================================================
; The Montgomery product. void ha_bn_mul_vN(uint64_t *out, const uint64_t *a, const uint64_t *b,
; const uint64_t *n, uint64_t n0, size_t k): out = a b R^-1 mod n, R = 2^(64k), k a multiple of 8
; from 8 to 128, n odd, a below R and b below n (so a b < R n, and t stays below 2n), n0 = -n^-1
; mod 2^64; out may be a or b (t lives on the stack until the end). System V: keeps rbx, rbp,
; r12-r15. Constant time: the same instructions whatever the values (the final subtraction is a
; mask), so the private operations of the next commit can share it.
; =============================================================================

; The rows' registers: rdx = the multiplier (b_i or m), rsi = a or n (advancing), r15 = t
; (advancing), r10 = the high word carried to the next limb, rcx = the group counter (negative,
; up to 0). Both carry chains run through a whole row: between groups only lea, mov and jrcxz,
; which leave the flags alone (an inc would clear OF). Measured against four-limb groups that fold
; OF into r10 each group (OpenSSL's mulx4x way): 2 to 4% faster.
%macro BN_GROUP 1                           ; t[j + %1] = t[j] + src[j] rdx + high, eight limbs
  %assign g 0
  %rep 8
    mulx        r11, rax, [rsi + g]
    adcx        rax, [r15 + g]
    adox        rax, r10
    mov         [r15 + g + %1], rax
    mov         r10, r11
    %assign g g + 8
  %endrep
%endmacro
%define BN_ROW1_GROUP BN_GROUP 0            ; t[0..7] += a[0..7] rdx
%define BN_ROW2_GROUP BN_GROUP -8           ; t[j - 1] = t[j] + n[j] m (shifted down a limb)

; BN_FINAL: out (rdi) = t (rbx, k + 1 limbs, below 2n) minus n (rsi) when that does not borrow,
; else t, chosen by mask. rcx = k. Clobbers rax, rcx, rdx, r8, the flags.
%macro BN_FINAL 0
    xor         edx, edx                    ; the index; CF = 0
%%sub:
    mov         rax, [rbx + rdx * 8]
    sbb         rax, [rsi + rdx * 8]
    mov         [rdi + rdx * 8], rax        ; t - n, provisionally
    lea         rdx, [rdx + 1]
    dec         rcx                         ; (dec keeps CF)
    jnz         %%sub
    mov         rax, [rbx + rdx * 8]        ; t_k - the borrow: all ones when t < n, else 0
    sbb         rax, 0
    mov         rcx, rdx
    xor         edx, edx
%%select:
    mov         r8, [rbx + rdx * 8]         ; out = t where rax is all ones, else t - n
    xor         r8, [rdi + rdx * 8]
    and         r8, rax
    xor         [rdi + rdx * 8], r8
    inc         rdx
    cmp         rdx, rcx
    jne         %%select
%endmacro

; The product's frame (rsp-based, below the six pushes): out, a, n, n0, k, the rounds left, then
; t (k + 2 limbs).
BF_OUT      equ 0
BF_A        equ 8
BF_N        equ 16
BF_N0       equ 24
BF_K        equ 32
BF_LEFT     equ 40
BF_T        equ 48

; ha_bn_enter / ha_bn_leave: the pushes, the frame with t zeroed (rbx = t), the arguments saved,
; r12 = b. As macros: both versions share them.
%macro BN_ENTER 0
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rbp, rsp
    lea         rax, [r9 * 8 + 16 + 15]
    and         rax, -16
    sub         rsp, rax                    ; t: k + 2 limbs
    sub         rsp, BF_T
    mov         [rsp + BF_OUT], rdi
    mov         [rsp + BF_A], rsi
    mov         [rsp + BF_N], rcx
    mov         [rsp + BF_N0], r8
    mov         [rsp + BF_K], r9
    mov         [rsp + BF_LEFT], r9
    mov         r12, rdx                    ; b, a limb further each round
    lea         rbx, [rsp + BF_T]
    xor         eax, eax
    lea         rcx, [r9 + 2]
    mov         rdi, rbx
    rep         stosq                       ; t = 0
%endmacro
%macro BN_LEAVE 0
    mov         rdi, [rsp + BF_OUT]
    mov         rsi, [rsp + BF_N]
    mov         rcx, [rsp + BF_K]
    BN_FINAL
    mov         rsp, rbp
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
%endmacro

align 16
ha_bn_mul_v3:
    BN_ENTER
    xor         r13d, r13d                  ; 0, for the chains' ends
.round:
    ; row 1: t[0..k] += a b_i, the carries out of t_k into t_{k+1}
    mov         rdx, [r12]
    mov         rsi, [rsp + BF_A]
    mov         r15, rbx
    mov         rcx, [rsp + BF_K]
    shr         rcx, 3
    neg         rcx                         ; -(k / 8): the groups, counted up to 0
    xor         r10d, r10d                  ; CF = OF = 0
.row1:
    BN_ROW1_GROUP
    lea         rsi, [rsi + 64]
    lea         r15, [r15 + 64]
    lea         rcx, [rcx + 1]
    jrcxz       .row1_done
    jmp         .row1
.row1_done:
    mov         rax, [r15]                  ; t_k + the last high word + CF + OF
    adcx        rax, r10
    adox        rax, r13
    mov         [r15], rax
    mov         rax, r13
    adcx        rax, [r15 + 8]              ; t_{k+1} + CF + OF
    adox        rax, r13
    mov         [r15 + 8], rax
    ; row 2: m = t_0 n'; t = (t + m n) / 2^64
    mov         rdx, [rbx]
    imul        rdx, [rsp + BF_N0]
    mov         rsi, [rsp + BF_N]
    mov         r15, rbx
    mov         rcx, [rsp + BF_K]
    shr         rcx, 3
    neg         rcx
    lea         rcx, [rcx + 1]              ; the first group is apart (below)
    xor         r10d, r10d
    ; limbs 0..7 apart: limb 0's sum is 0 by m's choice; only its carries go on
    mulx        r11, rax, [rsi]
    adcx        rax, [r15]
    adox        rax, r10
    mov         r10, r11
  %assign g 8
  %rep 7
    mulx        r11, rax, [rsi + g]
    adcx        rax, [r15 + g]
    adox        rax, r10
    mov         [r15 + g - 8], rax
    mov         r10, r11
    %assign g g + 8
  %endrep
    lea         rsi, [rsi + 64]
    lea         r15, [r15 + 64]
    jmp         .row2_test
.row2:
    BN_ROW2_GROUP
    lea         rsi, [rsi + 64]
    lea         r15, [r15 + 64]
    lea         rcx, [rcx + 1]
.row2_test:
    jrcxz       .row2_done                  ; (rel8 only: the test sits right above its target)
    jmp         .row2
.row2_done:
    mov         rax, [r15]                  ; t_{k-1} = t_k + the high word + CF + OF
    adcx        rax, r10
    adox        rax, r13
    mov         [r15 - 8], rax
    mov         rax, r13
    adcx        rax, [r15 + 8]              ; t_k = t_{k+1} + CF + OF
    adox        rax, r13
    mov         [r15], rax
    mov         [r15 + 8], r13              ; t_{k+1} = 0
    lea         r12, [r12 + 8]
    dec         qword [rsp + BF_LEFT]
    jnz         .round
    BN_LEAVE
    ret

align 16
ha_bn_mul_v1:
    BN_ENTER
.round:
    mov         rcx, [r12]                  ; b_i
    mov         rsi, [rsp + BF_A]
    mov         r15, rbx
    mov         r14, [rsp + BF_K]
    xor         r10d, r10d                  ; the carry
.row1:
    mov         rax, [rsi]
    mul         rcx
    add         rax, r10
    adc         rdx, 0
    add         rax, [r15]
    adc         rdx, 0
    mov         [r15], rax
    mov         r10, rdx
    add         rsi, 8
    add         r15, 8
    dec         r14
    jnz         .row1
    add         [r15], r10                  ; t_k += the carry, into t_{k+1}
    adc         qword [r15 + 8], 0
    mov         rcx, [rbx]
    imul        rcx, [rsp + BF_N0]          ; m
    mov         rsi, [rsp + BF_N]
    mov         r15, rbx
    mov         rax, [rsi]
    mul         rcx
    add         rax, [r15]                  ; 0, with a carry
    adc         rdx, 0
    mov         r10, rdx
    add         rsi, 8
    add         r15, 8
    mov         r14, [rsp + BF_K]
    dec         r14
.row2:
    mov         rax, [rsi]
    mul         rcx
    add         rax, r10
    adc         rdx, 0
    add         rax, [r15]
    adc         rdx, 0
    mov         [r15 - 8], rax
    mov         r10, rdx
    add         rsi, 8
    add         r15, 8
    dec         r14
    jnz         .row2
    mov         rax, [r15]                  ; t_{k-1} = t_k + the carry
    add         rax, r10
    mov         [r15 - 8], rax
    mov         rax, [r15 + 8]
    adc         rax, 0
    mov         [r15], rax                  ; t_k = t_{k+1} + CF
    mov         qword [r15 + 8], 0
    add         r12, 8
    dec         qword [rsp + BF_LEFT]
    jnz         .round
    BN_LEAVE
    ret

; =============================================================================
; The Montgomery square and the reduction alone (v3). void ha_bn_sqr_v3(uint64_t *out,
; const uint64_t *a, const uint64_t *n, uint64_t n0, size_t k): out = a^2 R^-1 mod n;
; void ha_bn_redc_v3(... the same): out = a R^-1 mod n (leaving Montgomery form). k a multiple
; of 8 from 8 to 128, a below n, n odd, n0 = -n^-1 mod 2^64; out may be a. Both build
; t (2k + 2 limbs, on the stack), reduce it with k rows (m_i = t_i n', t[i .. i+k) += m_i n, the
; row's carry word and the pending carry, 0 to 2, added at t_i+k), and subtract n once by mask
; from t[k .. 2k) and the last pending carry (below 2n: for the square a^2 + M n < n^2 + R n,
; for the reduction a + M n < R + R n). The same instructions whatever the values. System V.
; =============================================================================

; The square's and the reduction's frame (rsp-based, below the six pushes; rbp keeps rsp).
SF_OUT      equ 0
SF_A        equ 8
SF_N        equ 16
SF_N0       equ 24
SF_K        equ 32
SF_T        equ 48                          ; t, 2k + 2 limbs (zeroed)

%macro SQ_ENTER 0
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rbp, rsp
    mov         rax, r8
    shl         rax, 4
    add         rax, 16 + 15
    and         rax, -16
    sub         rsp, rax                    ; t: 2k + 2 limbs
    sub         rsp, SF_T
    mov         [rsp + SF_OUT], rdi
    mov         [rsp + SF_A], rsi
    mov         [rsp + SF_N], rdx
    mov         [rsp + SF_N0], rcx
    mov         [rsp + SF_K], r8
    lea         rbx, [rsp + SF_T]
    mov         rdi, rbx
    lea         rcx, [r8 * 2 + 2]
    xor         eax, eax
    rep         stosq                       ; t = 0 (the rows below store their carry words
                                            ; into it unread, the rest they add to)
%endmacro

; ha_bn_groups: rcx = -(the groups) (0: none), rdx = the multiplier, rsi = the source, r15 = t,
; r10 = the high word: t[0 .. 8g) += src[0 .. 8g) rdx with both carry chains running in and out
; (call and ret leave the flags alone), rsi and r15 past the groups. Clobbers rax, rcx, r11.
align 16
ha_bn_groups:
    jmp         .test                       ; (jrcxz reaches 127 octets: the test sits below)
.group:
    BN_GROUP    0
    lea         rsi, [rsi + 64]
    lea         r15, [r15 + 64]
    lea         rcx, [rcx + 1]
.test:
    jrcxz       .done
    jmp         .group
.done:
    ret

; SQ_TRI_ROW r: the triangle's row i = 8b + r of a block (rdi = &a[8b], r12 = &t[16b], r13 =
; -(k/8 - b - 1), the groups past the block): t[2i+1 ..] += a_i a[i+1 .. 8b+7] (7 - r limbs, here
; in straight lines), then a_i a[8b+8 .. k) (whole groups), the row's carry word into t[i+k] (not
; written before: the row above ended a limb lower). The fold of CF and OF into the high word
; cannot overflow: the row's sum t + a_i A is below 2^(64 (len + 1)).
%macro SQ_TRI_ROW 1
    mov         rcx, r13
    mov         rdx, [rdi + 8 * %1]         ; a_i
    lea         rsi, [rdi + 8 * %1 + 8]     ; a[i+1 ..]
    lea         r15, [r12 + 16 * %1 + 8]    ; t[2i+1 ..]
    xor         r10d, r10d                  ; CF = OF = 0
  %assign q 0
  %rep 7 - %1
    mulx        r11, rax, [rsi + q]
    adcx        rax, [r15 + q]
    adox        rax, r10
    mov         [r15 + q], rax
    mov         r10, r11
    %assign q q + 8
  %endrep
  %if %1 < 7
    lea         rsi, [rsi + 8 * (7 - %1)]
    lea         r15, [r15 + 8 * (7 - %1)]
  %endif
    call        ha_bn_groups
    mov         eax, 0                      ; (mov: the flags stay)
    adcx        r10, rax
    adox        r10, rax                    ; the carry word
    mov         [r15], r10                  ; t[i+k]
%endmacro

align 16
ha_bn_sqr_v3:
    SQ_ENTER
    ; 1. the products above the diagonal, a block of eight rows at a time
    mov         rdi, [rsp + SF_A]           ; &a[8b]
    mov         r12, rbx                    ; &t[16b]
    mov         r13, [rsp + SF_K]
    shr         r13, 3
    neg         r13
    inc         r13                         ; -(k/8 - 1): the first block's groups past it
.block:
    SQ_TRI_ROW  0
    SQ_TRI_ROW  1
    SQ_TRI_ROW  2
    SQ_TRI_ROW  3
    SQ_TRI_ROW  4
    SQ_TRI_ROW  5
    SQ_TRI_ROW  6
    SQ_TRI_ROW  7                           ; (the last block's row 7 is empty: a zero word)
    lea         rdi, [rdi + 64]
    lea         r12, [r12 + 128]
    inc         r13                         ; a group fewer past the next block
    cmp         r13, 1
    jne         .block
    ; 2. t = 2t + the squares a_i^2 (at t[2i], t[2i+1]): CF doubles, OF adds; two squares a
    ; step (a^2 < 2^(128k): nothing carries out of t[2k-1])
    mov         rsi, [rsp + SF_A]
    mov         r15, rbx
    mov         rcx, [rsp + SF_K]
    shr         rcx, 1
    neg         rcx
    xor         r13d, r13d                  ; CF = OF = 0
.diagonal:
    mov         rdx, [rsi]
    mulx        r11, rax, rdx
    mov         r8, [r15]
    adcx        r8, r8
    adox        r8, rax
    mov         [r15], r8
    mov         r8, [r15 + 8]
    adcx        r8, r8
    adox        r8, r11
    mov         [r15 + 8], r8
    mov         rdx, [rsi + 8]
    mulx        r11, rax, rdx
    mov         r8, [r15 + 16]
    adcx        r8, r8
    adox        r8, rax
    mov         [r15 + 16], r8
    mov         r8, [r15 + 24]
    adcx        r8, r8
    adox        r8, r11
    mov         [r15 + 24], r8
    lea         rsi, [rsi + 16]
    lea         r15, [r15 + 32]
    lea         rcx, [rcx + 1]
    jrcxz       .reduce
    jmp         .diagonal
.reduce:
    ; 3. k reduction rows (ha_bn_redc_v3 joins here)
    xor         r12d, r12d                  ; i
    xor         r14d, r14d                  ; the pending carry into t[i+k]
    mov         r13, [rsp + SF_K]
    shr         r13, 3
    neg         r13                         ; -(k/8)
.row:
    mov         rdx, [rbx + r12 * 8]
    imul        rdx, [rsp + SF_N0]          ; m_i
    mov         rsi, [rsp + SF_N]
    lea         r15, [rbx + r12 * 8]
    mov         rcx, r13
    xor         r10d, r10d                  ; CF = OF = 0
    call        ha_bn_groups
    mov         rax, [r15]                  ; t[i+k] + the high word + CF, + the pending + OF
    adcx        rax, r10
    adox        rax, r14
    mov         [r15], rax
    mov         r14d, 0
    mov         r11d, 0
    adcx        r14, r11
    adox        r14, r11                    ; the next pending carry, 0..2
    inc         r12
    cmp         r12, [rsp + SF_K]
    jne         .row
    ; 4. out = t[k .. 2k) + r14 2^64k, below 2n, minus n when that does not borrow
    mov         rdi, [rsp + SF_OUT]
    mov         rsi, [rsp + SF_N]
    mov         rcx, [rsp + SF_K]
    lea         r9, [rbx + rcx * 8]
    xor         edx, edx                    ; the index; CF = 0
.subtract:
    mov         rax, [r9 + rdx * 8]
    sbb         rax, [rsi + rdx * 8]
    mov         [rdi + rdx * 8], rax        ; t - n, provisionally
    lea         rdx, [rdx + 1]
    dec         rcx                         ; (dec keeps CF)
    jnz         .subtract
    sbb         r14, 0                      ; all ones when t < n (r14 = 1 means t >= 2^64k > n)
    mov         rcx, [rsp + SF_K]
    xor         edx, edx
.select:
    mov         r8, [r9 + rdx * 8]          ; out = t where r14 is all ones, else t - n
    xor         r8, [rdi + rdx * 8]
    and         r8, r14
    xor         [rdi + rdx * 8], r8
    inc         rdx
    cmp         rdx, rcx
    jne         .select
    mov         rsp, rbp
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret

align 16
ha_bn_redc_v3:
    SQ_ENTER
    mov         rsi, [rsp + SF_A]
    mov         rdi, rbx
    mov         rcx, [rsp + SF_K]
    rep         movsq                       ; t = a (the rest stays 0)
    jmp         ha_bn_sqr_v3.reduce

; -----------------------------------------------------------------------------
; The v1 square and reduction: the product (a with a, a with the integer 1). The fallback for CPUs
; without BMI2 and ADX keeps one code path; the same arguments as the v3 ones.
; -----------------------------------------------------------------------------
align 16
ha_bn_sqr_v1:
    mov         r9, r8                      ; k
    mov         r8, rcx                     ; n0
    mov         rcx, rdx                    ; n
    mov         rdx, rsi                    ; b = a
    jmp         ha_bn_mul_v1

align 16
ha_bn_redc_v1:
    push        rbx
    push        rbp
    mov         rbp, rsp
    mov         rbx, rdi                    ; out
    mov         r10, rsi                    ; a
    mov         r11, rdx                    ; n
    mov         r9, rcx                     ; n0, for now
    lea         rax, [r8 * 8 + 15]
    and         rax, -16
    sub         rsp, rax                    ; the integer 1, k limbs
    and         rsp, -16                    ; (16-aligned at the call)
    mov         rdi, rsp
    mov         rcx, r8
    xor         eax, eax
    rep         stosq
    mov         qword [rsp], 1
    mov         rdi, rbx
    mov         rsi, r10
    mov         rdx, rsp
    mov         rcx, r11
    xchg        r8, r9                      ; r8 = n0, r9 = k
    call        ha_bn_mul_v1
    mov         rsp, rbp
    pop         rbp
    pop         rbx
    ret

; =============================================================================
; rsa_rr_div: rdi = rr (k limbs), rsi = n (its own kn limbs, the top one nonzero), rdx = k,
; rcx = kn (16 <= kn <= k <= 128) -> rr = 2^(128k) mod n = R^2 mod n. Knuth's algorithm D (TAOCP
; 4.3.1) on a dividend that is a single bit: N = n << s has its top bit set (s = the top limb's
; leading zeros), U = 2^(128k + s) (2k + 2 limbs); each step j (2k + 1 - kn down to 0) takes the
; quotient digit q of U[j .. j+kn] by N from the top two limbs over N's top one (clamped to
; 2^64 - 1 when they would not fit), lowered while q N2 > r 2^64 + u0 (Knuth's test: then q is at
; most one too big), subtracts q N, and adds N back when that went negative. U[0 .. kn) is then
; 2^s (2^128k mod n): shifted back down. Variable time (div, the tests, the add-back): only for
; public moduli. mul only (both tiers). System V: keeps rbx, rbp, r12-r15.
; =============================================================================
RR_RR       equ 0
RR_K        equ 8
RR_KN       equ 16
RR_S        equ 24
RR_J        equ 32
RR_OLDSP    equ 40
RR_NN       equ 64                          ; N, kn limbs (up to 128)
RR_P        equ RR_NN + 1024                ; q N, kn + 1 limbs
RR_U        equ RR_P + 1032                 ; U, 2k + 2 limbs (up to 258)
RR_FRAME    equ RR_U + 2064

align 16
rsa_rr_div:
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    sub         rsp, RR_FRAME
    and         rsp, -16
    mov         [rsp + RR_OLDSP], rax
    mov         [rsp + RR_RR], rdi
    mov         [rsp + RR_K], rdx
    mov         [rsp + RR_KN], rcx
    mov         r14, rcx                    ; kn, from here on
    ; s, and N = n << s from the top limb down (each limb takes the bits the one below loses)
    mov         rax, [rsi + r14 * 8 - 8]
    bsr         rax, rax
    mov         ecx, 63
    sub         ecx, eax
    mov         [rsp + RR_S], rcx
    mov         r8, r14
.normalize:
    dec         r8
    mov         rax, [rsi + r8 * 8]
    xor         edx, edx
    test        r8, r8
    jz          .lowest
    mov         rdx, [rsi + r8 * 8 - 8]
.lowest:
    shld        rax, rdx, cl                ; (s = 0: rax as it is)
    mov         [rsp + RR_NN + r8 * 8], rax
    test        r8, r8
    jnz         .normalize
    ; U = 2^s at limb 2k, zeros elsewhere
    lea         rdi, [rsp + RR_U]
    mov         rcx, [rsp + RR_K]
    lea         rcx, [rcx * 2 + 2]
    xor         eax, eax
    rep         stosq
    mov         rcx, [rsp + RR_S]
    mov         eax, 1
    shl         rax, cl
    mov         rdx, [rsp + RR_K]
    shl         rdx, 1
    mov         [rsp + RR_U + rdx * 8], rax
    ; the digits, j from 2k + 1 - kn down to 0
    mov         rax, [rsp + RR_K]
    lea         rax, [rax * 2 + 1]
    sub         rax, r14
    mov         [rsp + RR_J], rax
    mov         r12, [rsp + RR_NN + r14 * 8 - 8]    ; N1, N's top limb (top bit set)
    mov         r13, [rsp + RR_NN + r14 * 8 - 16]   ; N2, the next one
.digit:
    mov         rbx, [rsp + RR_J]
    lea         rbp, [rsp + RR_U + rbx * 8] ; the window U[j .. j+kn]
    mov         r9, [rbp + r14 * 8]         ; u2 (never above N1: the window is below N b)
    mov         r10, [rbp + r14 * 8 - 8]    ; u1
    mov         r11, [rbp + r14 * 8 - 16]   ; u0
    cmp         r9, r12
    jae         .clamp
    mov         rdx, r9
    mov         rax, r10
    div         r12                         ; q = (u2 b + u1) / N1 (u2 < N1: it fits), r
    mov         r15, rax
    mov         rcx, rdx
    jmp         .refine
.clamp:
    mov         r15, -1                     ; u2 = N1: q = b - 1, r = u1 + N1
    mov         rcx, r10
    add         rcx, r12
    jc          .subtract                   ; r >= b: the test cannot hold
.refine:
    mov         rax, r15
    mul         r13                         ; q N2
    cmp         rdx, rcx
    jb          .subtract
    ja          .lower
    cmp         rax, r11
    jbe         .subtract
.lower:
    dec         r15                         ; q N2 > r b + u0: q is too big
    add         rcx, r12
    jnc         .refine                     ; (r >= b: stop testing)
.subtract:
    ; P = q N (kn + 1 limbs), then U[j .. j+kn] -= P
    xor         r10d, r10d
    xor         r8d, r8d
.product:
    mov         rax, [rsp + RR_NN + r8 * 8]
    mul         r15
    add         rax, r10
    adc         rdx, 0
    mov         [rsp + RR_P + r8 * 8], rax
    mov         r10, rdx
    inc         r8
    cmp         r8, r14
    jne         .product
    mov         [rsp + RR_P + r8 * 8], r10
    lea         rcx, [r14 + 1]
    xor         r8d, r8d                    ; CF = 0
.minus:
    mov         rax, [rbp + r8 * 8]
    sbb         rax, [rsp + RR_P + r8 * 8]
    mov         [rbp + r8 * 8], rax
    lea         r8, [r8 + 1]
    dec         rcx                         ; (keeps CF)
    jnz         .minus
    jnc         .next
    ; negative: q was one too big; N back (the carry out of the top cancels the borrow)
    mov         rcx, r14
    xor         r8d, r8d                    ; CF = 0
.plus:
    mov         rax, [rsp + RR_NN + r8 * 8]
    adc         [rbp + r8 * 8], rax
    lea         r8, [r8 + 1]
    dec         rcx
    jnz         .plus
    adc         qword [rbp + r8 * 8], 0
.next:
    dec         qword [rsp + RR_J]
    jns         .digit
    ; rr = U[0 .. kn) >> s, zeros up to k limbs
    mov         rdi, [rsp + RR_RR]
    mov         rcx, [rsp + RR_S]
    xor         r8d, r8d
.denormalize:
    mov         rax, [rsp + RR_U + r8 * 8]
    xor         edx, edx
    lea         r9, [r8 + 1]
    cmp         r9, r14
    jae         .highest
    mov         rdx, [rsp + RR_U + r8 * 8 + 8]
.highest:
    shrd        rax, rdx, cl
    mov         [rdi + r8 * 8], rax
    inc         r8
    cmp         r8, r14
    jne         .denormalize
    mov         rcx, [rsp + RR_K]
    sub         rcx, r14
    lea         rdi, [rdi + r14 * 8]
    xor         eax, eax
    rep         stosq
    mov         rsp, [rsp + RR_OLDSP]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret

; =============================================================================
; The verification frame (rbp-based, 64-aligned), shared by the two encodings.
; =============================================================================
RV_S        equ 0                           ; the signature representative s (k limbs)
RV_SM       equ 1024                        ; s R mod n
RV_ACC      equ 2048                        ; the running power, then m = s^e mod n
RV_EM       equ 3072                        ; I2OSP(m, kbytes) (octets)
RV_DB       equ 4096                        ; PSS: DB; PKCS#1: the expected EM (octets)
RV_MP       equ 5120                        ; PSS: M' = 00^8 || mHash || salt (at most emLen + 6
                                            ; octets, 1030), then H'
RV_SEED     equ 6208                        ; PSS: MGF1's seed || counter (H, 4 octets)
RV_HASH     equ 6280                        ; PSS: a hash output (64)
RV_KEY      equ 6344                        ; the key
RV_DIGEST   equ 6352                        ; the digest
RV_SIG      equ 6360                        ; the signature
RV_SIGLEN   equ 6368                        ; its length
RV_HASHID   equ 6376                        ; HTTPASM_HASH_*
RV_SLEN     equ 6384                        ; PSS: the salt's length
RV_MUL      equ 6392                        ; the product's version (its address)
RV_SQR      equ 6400                        ; the square's
RV_REDC     equ 6408                        ; the reduction's
RV_KBYTES   equ 6416                        ; n's length in octets
RV_EMLEN    equ 6424                        ; PSS: emLen
RV_HLEN     equ 6432                        ; the digest's length
RV_CNT      equ 6440                        ; MGF1's counter
RV_OLDSP    equ 6448                        ; the caller's rsp
RV_FRAME    equ 6464                        ; a multiple of 64

%macro RV_ENTER 0
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    and         rsp, -64
    sub         rsp, RV_FRAME
    mov         rbp, rsp
    mov         [rbp + RV_OLDSP], rax
%endmacro
%macro RV_LEAVE 0
    mov         rsp, [rbp + RV_OLDSP]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
%endmacro

; -----------------------------------------------------------------------------
; rsa_hash_info: esi = HTTPASM_HASH_* -> rax = the digest's length, rdx = its DigestInfo prefix,
; rcx = the prefix's length; rax = 0 for an unknown id. Keeps the rest.
; -----------------------------------------------------------------------------
align 16
rsa_hash_info:
    mov         ecx, 19                     ; every prefix but SHA-1's is 19 octets
    cmp         esi, HTTPASM_HASH_SHA1
    je          .sha1
    cmp         esi, HTTPASM_HASH_SHA224
    je          .sha224
    cmp         esi, HTTPASM_HASH_SHA256
    je          .sha256
    cmp         esi, HTTPASM_HASH_SHA384
    je          .sha384
    cmp         esi, HTTPASM_HASH_SHA512
    je          .sha512
    xor         eax, eax
    ret
.sha1:
    mov         eax, 20
    lea         rdx, [rel rsa_prefix_sha1]
    mov         ecx, 15
    ret
.sha224:
    mov         eax, 28
    lea         rdx, [rel rsa_prefix_sha224]
    ret
.sha256:
    mov         eax, 32
    lea         rdx, [rel rsa_prefix_sha256]
    ret
.sha384:
    mov         eax, 48
    lea         rdx, [rel rsa_prefix_sha384]
    ret
.sha512:
    mov         eax, 64
    lea         rdx, [rel rsa_prefix_sha512]
    ret

; -----------------------------------------------------------------------------
; rsa_hash: rdi = data, rsi = length, rdx = out, ecx = HTTPASM_HASH_SHA256/384/512 (the caller
; checked): the digest, by the C ABI's one-shot hashes (a tail call). Must be called with rsp as
; a call leaves it (16-aligned before the call).
; -----------------------------------------------------------------------------
align 16
rsa_hash:
    cmp         ecx, HTTPASM_HASH_SHA384
    je          .sha384
    cmp         ecx, HTTPASM_HASH_SHA512
    je          .sha512
    jmp         httpasm_sha256
.sha384:
    jmp         httpasm_sha384
.sha512:
    jmp         httpasm_sha512

; -----------------------------------------------------------------------------
; rsa_load_be: rsi = an octet string of rdx octets (big-endian), rdi = k limbs (rcx = k) -> the
; integer in limbs, zero above; eax = 0, or -1 when it needs more than k limbs (after its leading
; zero octets). Whole limbs from the string's end, eight octets byte-swapped at a time, then the
; 1 to 7 octets left at its front into the next limb. Clobbers rax, rcx, rdx, rsi, rdi, r8, r9,
; the flags.
; -----------------------------------------------------------------------------
align 16
rsa_load_be:
    mov         r8, rdi
    mov         r9, rcx
    xor         eax, eax
    rep         stosq                       ; zero all k limbs
    mov         rdi, r8
.skip:
    test        rdx, rdx                    ; leading zero octets do not count
    jz          .done
    cmp         byte [rsi], 0
    jne         .fits
    inc         rsi
    dec         rdx
    jmp         .skip
.fits:
    lea         rax, [r9 * 8]
    cmp         rdx, rax
    ja          .too_long
.limb:
    cmp         rdx, 8
    jb          .front
    mov         rax, [rsi + rdx - 8]        ; the eight octets ending where the last limb began
    bswap       rax
    mov         [rdi], rax
    add         rdi, 8
    sub         rdx, 8
    jmp         .limb
.front:
    test        rdx, rdx
    jz          .done
    xor         eax, eax
.octet:
    shl         rax, 8                      ; (its low octet is 0: mov al takes it)
    mov         al, [rsi]
    inc         rsi
    dec         rdx
    jnz         .octet
    mov         [rdi], rax
.done:
    xor         eax, eax
    ret
.too_long:
    mov         eax, -1
    ret

; -----------------------------------------------------------------------------
; rsa_store_be: the limbs at rsi -> rdx octets big-endian at rdi (the low rdx octets of the
; number; the caller knows it fits): whole limbs byte-swapped into the string's end first, then
; the last 1 to 7 octets of the next limb at its front. Clobbers rax, rdx, rsi, the flags.
; -----------------------------------------------------------------------------
align 16
rsa_store_be:
.limb:
    cmp         rdx, 8
    jb          .front
    mov         rax, [rsi]
    bswap       rax
    mov         [rdi + rdx - 8], rax
    add         rsi, 8
    sub         rdx, 8
    jmp         .limb
.front:
    test        rdx, rdx
    jz          .done
    mov         rax, [rsi]
.octet:
    mov         [rdi + rdx - 1], al         ; its low octets, last first
    shr         rax, 8
    dec         rdx
    jnz         .octet
.done:
    ret

; -----------------------------------------------------------------------------
; rsa_less: rdi, rsi = two numbers of rcx limbs -> CF set when the first is below the second.
; Clobbers rax, rcx, rdx, the flags.
; -----------------------------------------------------------------------------
align 16
rsa_less:
    xor         edx, edx                    ; CF = 0
.limb:
    mov         rax, [rdi + rdx * 8]
    sbb         rax, [rsi + rdx * 8]
    lea         rdx, [rdx + 1]
    dec         rcx                         ; (keeps CF)
    jnz         .limb
    ret

; -----------------------------------------------------------------------------
; rsa_public_op: the frame's RV_S (below n) -> RV_ACC = s^e mod n, plain. s R by the product with
; R^2 mod n; left-to-right square-and-multiply over e's bits below its top one (RV_SQR, RV_MUL);
; out of Montgomery form by the reduction alone (RV_REDC). Every operand stays below n.
; -----------------------------------------------------------------------------
align 16
rsa_public_op:
    push        r12
    push        r13
    sub         rsp, 8
    mov         r12, [rbp + RV_KEY]
    ; s R mod n = s R^2 R^-1
    lea         rdi, [rbp + RV_SM]
    lea         rsi, [rbp + RV_S]
    lea         rdx, [r12 + RK_RR]
    call        .mul
    ; acc = s R
    mov         ecx, [r12 + RK_LIMBS]
    lea         rsi, [rbp + RV_SM]
    lea         rdi, [rbp + RV_ACC]
    rep         movsq
    mov         r13, [r12 + RK_E]
    bsr         rcx, r13                    ; the top bit's position
    jz          .done                       ; (e >= 3: never)
.bit:
    dec         ecx
    js          .done
    push        rcx
    sub         rsp, 8
    lea         rdi, [rbp + RV_ACC]
    lea         rsi, [rbp + RV_ACC]
    call        .sqr                        ; acc = acc^2
    add         rsp, 8
    pop         rcx
    bt          r13, rcx
    jnc         .bit
    push        rcx
    sub         rsp, 8
    lea         rdi, [rbp + RV_ACC]
    lea         rsi, [rbp + RV_ACC]
    lea         rdx, [rbp + RV_SM]
    call        .mul                        ; acc = acc s
    add         rsp, 8
    pop         rcx
    jmp         .bit
.done:
    lea         rdi, [rbp + RV_ACC]         ; out of Montgomery form: acc R^-1
    lea         rsi, [rbp + RV_ACC]
    call        .redc
    add         rsp, 8
    pop         r13
    pop         r12
    ret
; .mul: rdi = out, rsi = a, rdx = b; .sqr and .redc: rdi = out, rsi = a; under the key (r12) and
; the versions rsa_begin picked
.mul:
    lea         rcx, [r12 + RK_N]
    mov         r8, [r12 + RK_N0]
    mov         r9d, [r12 + RK_LIMBS]
    jmp         [rbp + RV_MUL]
.sqr:
    lea         rdx, [r12 + RK_N]
    mov         rcx, [r12 + RK_N0]
    mov         r8d, [r12 + RK_LIMBS]
    jmp         [rbp + RV_SQR]
.redc:
    lea         rdx, [r12 + RK_N]
    mov         rcx, [r12 + RK_N0]
    mov         r8d, [r12 + RK_LIMBS]
    jmp         [rbp + RV_REDC]

; -----------------------------------------------------------------------------
; rsa_begin: the shared start of both verifications: the frame's key, signature and length set
; -> RV_KBYTES, RV_MUL/RV_SQR/RV_REDC, RV_S = s (when sig_len = kbytes and s < n), RV_ACC =
; s^e mod n, and RV_EM = I2OSP(m, kbytes); eax = 0, or -1 (wrong length, s not below n).
; -----------------------------------------------------------------------------
align 16
rsa_begin:
    push        r12
    mov         r12, [rbp + RV_KEY]
    mov         eax, [r12 + RK_BITS]
    cmp         eax, HTTPASM_RSA_MIN_BITS   ; a refused key (all zeros) has no octets: a signature
    jb          .bad                        ; of length 0 would match them, and k = 0 limbs would
                                            ; run the loops below from 0 down through 2^64
    add         eax, 7
    shr         eax, 3
    mov         [rbp + RV_KBYTES], rax
    cmp         rax, [rbp + RV_SIGLEN]      ; RFC 8017 8.1.2 / 8.2.2 step 1: the length is n's
    jne         .bad
    ; the versions: v3 needs BMI2 (mulx: the v3 tier) and ADX (adcx, adox), both within the cap
    ; (one test of both, as p256.asm picks: a v3 CPU without ADX, Haswell, runs v1)
    HA_CPU_PICK HTTPASM_CPU_V3 | HTTPASM_CPU_ADX, .v3
    lea         rax, [rel ha_bn_mul_v1]
    lea         rcx, [rel ha_bn_sqr_v1]
    lea         rdx, [rel ha_bn_redc_v1]
    jmp         .picked
.v3:
    lea         rax, [rel ha_bn_mul_v3]
    lea         rcx, [rel ha_bn_sqr_v3]
    lea         rdx, [rel ha_bn_redc_v3]
.picked:
    mov         [rbp + RV_MUL], rax
    mov         [rbp + RV_SQR], rcx
    mov         [rbp + RV_REDC], rdx
    lea         rdi, [rbp + RV_S]
    mov         rsi, [rbp + RV_SIG]
    mov         rdx, [rbp + RV_SIGLEN]
    mov         ecx, [r12 + RK_LIMBS]
    call        rsa_load_be                 ; (fits: kbytes octets)
    lea         rdi, [rbp + RV_S]
    lea         rsi, [r12 + RK_N]
    mov         ecx, [r12 + RK_LIMBS]
    call        rsa_less
    jnc         .bad                        ; RSAVP1 step 1: s must be below n
    call        rsa_public_op
    lea         rdi, [rbp + RV_EM]
    lea         rsi, [rbp + RV_ACC]
    mov         rdx, [rbp + RV_KBYTES]
    call        rsa_store_be
    xor         eax, eax
    pop         r12
    ret
.bad:
    mov         eax, -1
    pop         r12
    ret

; =============================================================================
; The C ABI.
; =============================================================================

; -----------------------------------------------------------------------------
; int httpasm_rsa_public_key_init(httpasm_rsa_public_key *key, const uint8_t *n, size_t n_length,
;                                 const uint8_t *e, size_t e_length)
; -----------------------------------------------------------------------------
global httpasm_rsa_public_key_init:function (httpasm_rsa_public_key_init.end - httpasm_rsa_public_key_init)
align 16
httpasm_rsa_public_key_init:
    RV_ENTER
    mov         [rbp + RV_KEY], rdi
    mov         r12, rdi
    mov         r13, rcx                    ; e
    mov         r14, r8                     ; e's length
    ; the whole key zeroed first: a refused key is all zeros (and the limbs above n are 0)
    push        rsi
    push        rdx
    xor         eax, eax
    mov         ecx, RK_SIZE / 8
    rep         stosq
    pop         rdx
    pop         rsi
    ; n: its leading zero octets skipped, then at most 1024 octets
    mov         rdi, r12
    mov         ecx, HTTPASM_RSA_LIMBS
    call        rsa_load_be
    test        eax, eax
    jnz         .bad
    ; bits: the top nonzero limb's top bit
    mov         ecx, HTTPASM_RSA_LIMBS
.top:
    dec         ecx
    js          .bad                        ; n = 0
    mov         rax, [r12 + RK_N + rcx * 8]
    test        rax, rax
    jz          .top
    bsr         rax, rax
    shl         ecx, 6
    lea         eax, [rcx + rax + 1]
    cmp         eax, HTTPASM_RSA_MIN_BITS
    jb          .bad
    mov         [r12 + RK_BITS], eax
    test        byte [r12 + RK_N], 1
    jz          .bad                        ; n even: no Montgomery inverse, and no RSA modulus
    ; k = the limbs rounded up to a multiple of 8 (the v3 loops' groups)
    add         eax, 511
    shr         eax, 9
    shl         eax, 3
    mov         [r12 + RK_LIMBS], eax
    ; e: at most 8 octets after its leading zeros, odd, 3 or more
    xor         eax, eax
.e_skip:
    test        r14, r14
    jz          .bad
    cmp         byte [r13], 0
    jne         .e_digits
    inc         r13
    dec         r14
    jmp         .e_skip
.e_digits:
    cmp         r14, 8
    ja          .bad
.e_octet:
    shl         rax, 8
    mov         al, [r13]
    inc         r13
    dec         r14
    jnz         .e_octet
    cmp         rax, 3
    jb          .bad
    test        al, 1
    jz          .bad
    mov         [r12 + RK_E], rax
    ; n0 = -n^-1 mod 2^64: Newton's x = x (2 - n x) doubles the good bits; x = (3n) xor 2 is good
    ; to 5 bits, so four steps reach 64
    mov         rcx, [r12 + RK_N]
    lea         rax, [rcx + rcx * 2]
    xor         rax, 2
  %rep 4
    mov         rdx, rcx
    imul        rdx, rax
    neg         rdx
    add         rdx, 2
    imul        rax, rdx
  %endrep
    neg         rax
    mov         [r12 + RK_N0], rax
    ; R^2 mod n by long division over n's own limbs (kn = ceil(bits / 64), 16 or more)
    lea         rdi, [r12 + RK_RR]
    lea         rsi, [r12 + RK_N]
    mov         edx, [r12 + RK_LIMBS]
    mov         ecx, [r12 + RK_BITS]
    add         ecx, 63
    shr         ecx, 6
    call        rsa_rr_div
    xor         eax, eax
    jmp         .done
.bad:
    mov         rdi, r12
    xor         eax, eax
    mov         ecx, RK_SIZE / 8
    rep         stosq
    mov         eax, -1
.done:
    RV_LEAVE
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_rsa_verify_pkcs1(const httpasm_rsa_public_key *key, int hash, const uint8_t *digest,
;                              const uint8_t *signature, size_t signature_length)
; -----------------------------------------------------------------------------
global httpasm_rsa_verify_pkcs1:function (httpasm_rsa_verify_pkcs1.end - httpasm_rsa_verify_pkcs1)
align 16
httpasm_rsa_verify_pkcs1:
    RV_ENTER
    mov         [rbp + RV_KEY], rdi
    mov         [rbp + RV_HASHID], rsi
    mov         [rbp + RV_DIGEST], rdx
    mov         [rbp + RV_SIG], rcx
    mov         [rbp + RV_SIGLEN], r8
    call        rsa_hash_info
    test        eax, eax
    jz          .invalid                    ; an unknown hash
    mov         [rbp + RV_HLEN], rax
    mov         r13, rdx                    ; the prefix
    mov         r14, rcx                    ; its length
    call        rsa_begin
    test        eax, eax
    jnz         .invalid
    ; the expected EM: 00 01 FF..FF 00 prefix digest, tLen = prefix + digest, at least 8 FF
    ; (RFC 8017 9.2 step 3: emLen >= tLen + 11)
    mov         rbx, [rbp + RV_KBYTES]
    mov         r15, r14
    add         r15, [rbp + RV_HLEN]        ; tLen
    lea         rax, [r15 + 11]
    cmp         rbx, rax
    jb          .invalid
    lea         rdi, [rbp + RV_DB]
    mov         word [rdi], 0x0100          ; 00 01
    lea         rdi, [rdi + 2]
    mov         rcx, rbx
    sub         rcx, r15
    sub         rcx, 3                      ; the FF octets
    mov         al, 0xFF
    rep         stosb
    mov         byte [rdi], 0
    inc         rdi
    mov         rsi, r13
    mov         rcx, r14
    rep         movsb                       ; the DigestInfo prefix
    mov         rsi, [rbp + RV_DIGEST]
    mov         rcx, [rbp + RV_HLEN]
    rep         movsb                       ; the digest
    ; compare (public values: memcmp's way is fine)
    lea         rsi, [rbp + RV_DB]
    lea         rdi, [rbp + RV_EM]
    mov         rcx, rbx
    repe        cmpsb
    jne         .invalid
    xor         eax, eax
    jmp         .done
.invalid:
    mov         eax, -1
.done:
    RV_LEAVE
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_rsa_verify_pss(const httpasm_rsa_public_key *key, int hash, const uint8_t *digest,
;                            size_t salt_length, const uint8_t *signature,
;                            size_t signature_length)
; -----------------------------------------------------------------------------
global httpasm_rsa_verify_pss:function (httpasm_rsa_verify_pss.end - httpasm_rsa_verify_pss)
align 16
httpasm_rsa_verify_pss:
    RV_ENTER
    mov         [rbp + RV_KEY], rdi
    mov         [rbp + RV_HASHID], rsi
    mov         [rbp + RV_DIGEST], rdx
    mov         [rbp + RV_SLEN], rcx
    mov         [rbp + RV_SIG], r8
    mov         [rbp + RV_SIGLEN], r9
    cmp         esi, HTTPASM_HASH_SHA256    ; PSS hashes inside: SHA-256, -384, -512 only
    jb          .invalid
    cmp         esi, HTTPASM_HASH_SHA512
    ja          .invalid
    call        rsa_hash_info
    mov         [rbp + RV_HLEN], rax
    call        rsa_begin
    test        eax, eax
    jnz         .invalid
    ; emBits = bits - 1; emLen = ceil(emBits / 8): kbytes, or kbytes - 1 when bits = 1 mod 8,
    ; and then EM's extra top octet must be 0 (RFC 8017 8.1.2 step 2c: I2OSP fails otherwise)
    mov         r12, [rbp + RV_KEY]
    mov         eax, [r12 + RK_BITS]
    lea         r13d, [rax - 1]             ; emBits
    lea         eax, [r13 + 7]
    shr         eax, 3
    mov         [rbp + RV_EMLEN], rax
    lea         r14, [rbp + RV_EM]          ; EM's first octet
    cmp         rax, [rbp + RV_KBYTES]
    je          .em
    cmp         byte [r14], 0
    jne         .invalid
    inc         r14
.em:
    ; 9.1.2 step 3: emLen < hLen + sLen + 2 is inconsistent
    mov         rbx, [rbp + RV_EMLEN]
    mov         rax, [rbp + RV_HLEN]
    add         rax, [rbp + RV_SLEN]
    jc          .invalid
    add         rax, 2
    cmp         rbx, rax
    jb          .invalid
    ; step 4: the last octet is 0xbc
    cmp         byte [r14 + rbx - 1], 0xBC
    jne         .invalid
    ; step 6: the leftmost 8 emLen - emBits bits of maskedDB are 0
    mov         ecx, ebx
    shl         ecx, 3
    sub         ecx, r13d                   ; 8 emLen - emBits, 0..7
    mov         eax, 0xFF00
    shr         eax, cl
    mov         r15d, eax                   ; the mask of the bits that must be 0 (high octet)
    test        [r14], al
    jnz         .invalid
    ; step 7-8: DB = maskedDB xor MGF1(H, emLen - hLen - 1), H at EM + emLen - hLen - 1
    mov         r12, rbx
    sub         r12, [rbp + RV_HLEN]
    dec         r12                         ; dbLen
    lea         rsi, [r14 + r12]            ; H
    lea         rdi, [rbp + RV_SEED]
    mov         rcx, [rbp + RV_HLEN]
    rep         movsb                       ; seed = H, then the counter
    mov         qword [rbp + RV_CNT], 0
    xor         ebx, ebx                    ; DB's octets done
.mgf1:
    mov         rax, [rbp + RV_CNT]
    bswap       eax
    mov         rcx, [rbp + RV_HLEN]
    mov         [rbp + RV_SEED + rcx], eax  ; the counter, big-endian
    lea         rdi, [rbp + RV_SEED]
    lea         rsi, [rcx + 4]
    lea         rdx, [rbp + RV_HASH]
    mov         ecx, [rbp + RV_HASHID]
    call        rsa_hash
    inc         qword [rbp + RV_CNT]
    xor         ecx, ecx
.xor:
    cmp         rbx, r12
    je          .unmasked
    cmp         rcx, [rbp + RV_HLEN]
    je          .mgf1
    mov         al, [r14 + rbx]
    xor         al, [rbp + RV_HASH + rcx]
    mov         [rbp + RV_DB + rbx], al
    inc         rbx
    inc         rcx
    jmp         .xor
.unmasked:
    ; step 9: DB's top bits cleared
    mov         eax, r15d
    not         eax
    and         [rbp + RV_DB], al
    ; step 10: DB = 00..00 01 salt
    mov         rcx, r12
    sub         rcx, [rbp + RV_SLEN]
    dec         rcx                         ; the zero octets
    xor         edx, edx
.zeros:
    cmp         rdx, rcx
    je          .one
    cmp         byte [rbp + RV_DB + rdx], 0
    jne         .invalid
    inc         rdx
    jmp         .zeros
.one:
    cmp         byte [rbp + RV_DB + rdx], 1
    jne         .invalid
    ; steps 11-13: H' = Hash(00^8 || mHash || salt)
    lea         rdi, [rbp + RV_MP]
    mov         qword [rdi], 0
    add         rdi, 8
    mov         rsi, [rbp + RV_DIGEST]
    mov         rcx, [rbp + RV_HLEN]
    rep         movsb
    lea         rsi, [rbp + RV_DB + rdx + 1]
    mov         rcx, [rbp + RV_SLEN]
    rep         movsb
    lea         rsi, [rbp + RV_MP]
    sub         rdi, rsi                    ; M''s length
    mov         rsi, rdi
    lea         rdi, [rbp + RV_MP]
    lea         rdx, [rbp + RV_HASH]
    mov         ecx, [rbp + RV_HASHID]
    call        rsa_hash
    ; step 14: H = H'
    lea         rsi, [rbp + RV_HASH]
    lea         rdi, [r14 + r12]
    mov         rcx, [rbp + RV_HLEN]
    repe        cmpsb
    jne         .invalid
    xor         eax, eax
    jmp         .done
.invalid:
    mov         eax, -1
.done:
    RV_LEAVE
    ret
.end:
