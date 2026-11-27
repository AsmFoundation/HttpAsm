; =============================================================================
; crypto/chacha20_poly1305.asm - ChaCha20, Poly1305 and their AEAD (RFC 8439) as TLS 1.3
; (TLS_CHACHA20_POLY1305_SHA256) and QUIC use them: the C ABI's httpasm_chacha20 (the raw
; cipher; QUIC's header protection takes one block of it, RFC 9001 5.4.4), httpasm_poly1305
; (the one-time authenticator alone), httpasm_chacha20_poly1305_seal and _open.
;
; ChaCha20 (RFC 8439 2.1-2.4) has three versions, chosen once per call:
;   v1 (any x86-64, SSE2): four blocks at once, each XMM register one state word of the four
;      blocks (the "vertical" layout: no shuffles between rounds). Sixteen words and two
;      temporaries are eighteen registers, so two words of the third row wait on the stack,
;      swapped in pairs twice a double round (the arrangement of OpenSSL's ChaCha20_4x, by Andy
;      Polyakov). Rotations by 16 are pshuflw + pshufhw, the others two shifts and an or.
;   v2 (SSSE3): the same, with the rotations by 16 and 8 one pshufb each.
;   v3 (AVX2): eight blocks at once in YMM registers, the same arrangement in VEX form.
;   In every version, work of 128 octets or less (and a last piece that short) goes through two
;   blocks side by side in the "horizontal" layout (a block's four rows in four XMM registers,
;   its diagonals lined up by pshufd between the half rounds): one block's chain of dependent
;   instructions sets its time, which is shorter than a whole step of four or eight blocks.
;
; Poly1305 (RFC 8439 2.5) works on 64-bit limbs: h = h0 + 2^64 h1 + 2^128 h2 (h2 small), the
; clamped r = r0 + 2^64 r1, and s1 = r1 + r1 / 4 (r1 is a multiple of 4), so the products past
; 2^128 fold back as 2^130 = 5 (mod 2^130 - 5) does: h r = h0 r0 + h1 s1 + 2^64 (h0 r1 + h1 r0
; + h2 s1) + 2^128 h2 r0, reduced partially after each block (the part from 2^130 up added back
; times 5) and fully once, at the end. Two versions: mul (v1, v2) and BMI2's mulx (v3: it leaves
; the flags alone and takes r from memory). Both are constant time: mul's latency does not
; depend on its operands on the x86-64 cores this library runs on, and the last reduction
; selects with cmov.
;
; The AEAD (RFC 8439 2.8) interleaves the two ("stitching", as BoringSSL's AVX2 code by Shay
; Gueron and Vlad Krasnov does): during the rounds of each step of four or eight ChaCha20 blocks,
; which keep the vector units busy, Poly1305 hashes blocks of text on the integer units, one
; block after each pair of quarter rounds while blocks are waiting (P_SLOT). seal hashes the
; ciphertext it wrote in earlier steps; open hashes its input ahead of the output it writes. A
; step has room for more blocks than it makes (20 for four ChaCha20 blocks' 16, 40 for eight's
; 32), so the hashing keeps up. The one-time Poly1305 key is ChaCha20's block 0 (RFC 8439 2.6),
; made with block 1 (the first 64 octets' keystream) in the horizontal layout before anything
; else.
;
; Every key, keystream and intermediate value stays in registers and the routines' frames; the
; frames are wiped and the vector registers cleared before each C ABI function returns.
; =============================================================================
default rel
%include "httpasm_core.inc"

section .rodata
align 64
cc_rot16:   db 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13     ; pshufb: each dword
            db 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13     ; rotated left by 16
cc_rot8:    db 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14     ; ... by 8
            db 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14
cc_lanes:   dd 0, 1, 2, 3, 4, 5, 6, 7       ; the vertical layouts' block counters, lane by lane
cc_eight:   dd 8, 8, 8, 8, 8, 8, 8, 8       ; the next eight blocks' counters
cc_sigma:   dd 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574   ; "expand 32-byte k" (2.3)
cc_four:    dd 4, 4, 4, 4                   ; the next four blocks' counters
cc_one:     dd 1, 0, 0, 0                   ; a horizontal block's counter + 1 (modulo 2^32)

section .text

; -----------------------------------------------------------------------------
; The AEAD's request (built on the stack by the C ABI functions, read by the drivers).
; -----------------------------------------------------------------------------
CR_NONCE    equ 0           ; the 12-octet nonce
CR_AAD      equ 8
CR_AADLEN   equ 16
CR_IN       equ 24
CR_LEN      equ 32
CR_OUT      equ 40
CR_TAG      equ 48          ; where the driver writes the computed tag (16 octets)
CR_OPEN     equ 56          ; byte: 0 seal (hash the output), 1 open (hash the input)
CR_KEY      equ 64          ; the 32-octet key
CR_SIZE     equ 72

; -----------------------------------------------------------------------------
; Poly1305's area in a frame, addressed from rbp (so routines called from a driver reach it at
; any stack depth). PA_PART must be 16-aligned: the frames place the area so.
; -----------------------------------------------------------------------------
PA_R0       equ 0           ; r's low 64 bits, clamped
PA_R1       equ 8           ; r's high 64 bits, clamped (a multiple of 4)
PA_S1       equ 16          ; r1 + (r1 >> 2) = 5 r1 / 4: h1 r1 2^128 and h2 r1 2^192 folded
PA_S        equ 32          ; s, added to the reduced h for the tag (16 octets)
PA_PART     equ 48          ; a block padded with zeros (16): the last octets, the lengths
PA_END      equ 64          ; the stitched hook's limit: it hashes the block at r12 while below
PA_SRC      equ 72          ; the hashed text: out when sealing, in when opening
PA_LEN      equ 80          ; the text's length
PA_AAD      equ 88          ; the AAD's length
PA_TAG      equ 96          ; where the tag goes
PA_OPEN     equ 104         ; 1 when opening, 0 when sealing (qword)
PA_SIZE     equ 112

; -----------------------------------------------------------------------------
; Frame of the four-block (v1, v2) drivers: 64-aligned below the pushes, the caller's rsp kept.
; -----------------------------------------------------------------------------
C4_IN       equ 0                           ; the input state, each word in all four lanes
                                            ; (word 12: the four blocks' counters)
C4_SLOT     equ C4_IN + 16 * 16             ; x8, x9, x10, x11 while out of registers
C4_KEY      equ C4_SLOT + 4 * 16            ; keystream: a buffered step's 256, cc_hz2's 128
C4_STATE    equ C4_KEY + 256                ; the input state (64), word 12 the next counter
C4_POLY     equ C4_STATE + 64               ; Poly1305's area
C4_OLDSP    equ C4_POLY + PA_SIZE           ; the caller's rsp (the wipe stops below it)
C4_END      equ C4_OLDSP + 8
C4_FRAME    equ (C4_END + 63) & -64

; Frame of the eight-block (v3) drivers, the same way.
C8_IN       equ 0                           ; 16 words x 8 lanes
C8_SLOT     equ C8_IN + 16 * 32             ; x8, x9, x10, x11 while out of registers
C8_W        equ C8_SLOT + 4 * 32            ; x12-x15 while the first half is written out
C8_KEY      equ C8_W + 4 * 32               ; keystream: a buffered step's 512, cc_hz2's 128
C8_STATE    equ C8_KEY + 512                ; the input state (64), word 12 the next counter
C8_POLY     equ C8_STATE + 64               ; Poly1305's area
C8_OLDSP    equ C8_POLY + PA_SIZE
C8_END      equ C8_OLDSP + 8
C8_FRAME    equ (C8_END + 63) & -64

; =============================================================================
; ChaCha20's pieces, SSE: v = 1 (SSE2 only) or 2 (SSSE3's pshufb for the byte rotations).
; =============================================================================

; CC_ROL16 v, x: each dword of x rotated left by 16.
%macro CC_ROL16 2
  %if %1 == 1
    pshuflw     %2, %2, 0xB1
    pshufhw     %2, %2, 0xB1
  %else
    pshufb      %2, [rel cc_rot16]
  %endif
%endmacro

; CC_ROL8 v, x, t: each dword of x rotated left by 8 (v1 through the temporary t).
%macro CC_ROL8 3
  %if %1 == 1
    movdqa      %3, %2
    pslld       %2, 8
    psrld       %3, 24
    por         %2, %3
  %else
    pshufb      %2, [rel cc_rot8]
  %endif
%endmacro

; CC_ROL x, n, t: each dword of x rotated left by n, through the temporary t.
%macro CC_ROL 3
    movdqa      %3, %1
    pslld       %1, %2
    psrld       %3, 32 - %2
    por         %1, %3
%endmacro

; CC4_QR2 v, a1, b1, c1, d1, a2, b2, c2, d2: two quarter rounds (RFC 8439 2.1) side by side,
; each operand one state word of four blocks. Temporaries: xmm14, xmm15.
%macro CC4_QR2 9
    paddd       %2, %3
    paddd       %6, %7
    pxor        %5, %2
    pxor        %9, %6
    CC_ROL16    %1, %5
    CC_ROL16    %1, %9
    paddd       %4, %5
    paddd       %8, %9
    pxor        %3, %4
    pxor        %7, %8
    CC_ROL      %3, 12, xmm14
    CC_ROL      %7, 12, xmm15
    paddd       %2, %3
    paddd       %6, %7
    pxor        %5, %2
    pxor        %9, %6
    CC_ROL8     %1, %5, xmm14
    CC_ROL8     %1, %9, xmm15
    paddd       %4, %5
    paddd       %8, %9
    pxor        %3, %4
    pxor        %7, %8
    CC_ROL      %3, 7, xmm14
    CC_ROL      %7, 7, xmm15
%endmacro

; CC4_TRANSPOSE a, b, c, d, t0, t1: four words of four blocks (lane j = block j) turned into
; four blocks' rows: block 0 in a, block 1 in b, block 2 in t0, block 3 in d (c and t1 are
; left as scratch).
%macro CC4_TRANSPOSE 6
    movdqa      %5, %1
    punpckldq   %1, %2                      ; a0 b0 a1 b1
    punpckhdq   %5, %2                      ; a2 b2 a3 b3
    movdqa      %6, %3
    punpckldq   %3, %4                      ; c0 d0 c1 d1
    punpckhdq   %6, %4                      ; c2 d2 c3 d3
    movdqa      %2, %1
    punpcklqdq  %1, %3                      ; block 0
    punpckhqdq  %2, %3                      ; block 1
    movdqa      %4, %5
    punpcklqdq  %5, %6                      ; block 2
    punpckhqdq  %4, %6                      ; block 3
%endmacro

; CC4_PUT mode, off, r0, r1, r2, r3, t: the rows of blocks 0-3 for octets off..off+15 of each.
; mode 0: xored with the input at r13 + rbx into the output at r14 + rbx (each row read before
; it is written, so out may be in); mode 1: into C4_KEY.
%macro CC4_PUT 7
  %if %1 == 0
    movdqu      %7, [r13 + rbx + %2]
    pxor        %3, %7
    movdqu      [r14 + rbx + %2], %3
    movdqu      %7, [r13 + rbx + 64 + %2]
    pxor        %4, %7
    movdqu      [r14 + rbx + 64 + %2], %4
    movdqu      %7, [r13 + rbx + 128 + %2]
    pxor        %5, %7
    movdqu      [r14 + rbx + 128 + %2], %5
    movdqu      %7, [r13 + rbx + 192 + %2]
    pxor        %6, %7
    movdqu      [r14 + rbx + 192 + %2], %6
  %else
    movdqa      [rsp + C4_KEY + %2], %3
    movdqa      [rsp + C4_KEY + 64 + %2], %4
    movdqa      [rsp + C4_KEY + 128 + %2], %5
    movdqa      [rsp + C4_KEY + 192 + %2], %6
  %endif
%endmacro

; CC4_BROADCAST: C4_IN from C4_STATE: each word in all four lanes, word 12 the four counters
; (c, c + 1, c + 2, c + 3 modulo 2^32).
%macro CC4_BROADCAST 0
  %assign w 0
  %rep 16
    movd        xmm0, [rsp + C4_STATE + 4 * w]
    pshufd      xmm0, xmm0, 0
    %if w == 12
    paddd       xmm0, [rel cc_lanes]
    %endif
    movdqa      [rsp + C4_IN + 16 * w], xmm0
    %assign w w + 1
  %endrep
%endmacro

; CC4_STEP v, mode, poly: four blocks of keystream from the counters in C4_IN's word 12, then the
; counters advanced by four (in C4_IN and C4_STATE). mode as CC4_PUT's. poly 1: Poly1305 hashes
; blocks of its backlog between the quarter rounds (P_SLOT, mul: v1 and v2 do not assume BMI2).
; Clobbers ecx, xmm0-xmm15, the flags, and with poly rax, rdx, rsi, rdi, r11, r12, r8-r10.
%macro CC4_STEP 3
    movdqa      xmm0, [rsp + C4_IN + 0 * 16]
    movdqa      xmm1, [rsp + C4_IN + 1 * 16]
    movdqa      xmm2, [rsp + C4_IN + 2 * 16]
    movdqa      xmm3, [rsp + C4_IN + 3 * 16]
    movdqa      xmm4, [rsp + C4_IN + 4 * 16]
    movdqa      xmm5, [rsp + C4_IN + 5 * 16]
    movdqa      xmm6, [rsp + C4_IN + 6 * 16]
    movdqa      xmm7, [rsp + C4_IN + 7 * 16]
    movdqa      xmm8, [rsp + C4_IN + 10 * 16]
    movdqa      xmm9, [rsp + C4_IN + 11 * 16]
    movdqa      [rsp + C4_SLOT + 32], xmm8  ; x10 and x11 start out of registers
    movdqa      [rsp + C4_SLOT + 48], xmm9
    movdqa      xmm8, [rsp + C4_IN + 8 * 16]
    movdqa      xmm9, [rsp + C4_IN + 9 * 16]
    movdqa      xmm10, [rsp + C4_IN + 12 * 16]
    movdqa      xmm11, [rsp + C4_IN + 13 * 16]
    movdqa      xmm12, [rsp + C4_IN + 14 * 16]
    movdqa      xmm13, [rsp + C4_IN + 15 * 16]
    mov         ecx, 10
%%double:
    CC4_QR2     %1, xmm0, xmm4, xmm8, xmm10, xmm1, xmm5, xmm9, xmm11     ; columns 0 and 1
  %if %3
    P_SLOT      0
  %endif
    movdqa      [rsp + C4_SLOT + 0], xmm8   ; x8, x9 out; x10, x11 in
    movdqa      [rsp + C4_SLOT + 16], xmm9
    movdqa      xmm8, [rsp + C4_SLOT + 32]
    movdqa      xmm9, [rsp + C4_SLOT + 48]
    CC4_QR2     %1, xmm2, xmm6, xmm8, xmm12, xmm3, xmm7, xmm9, xmm13     ; columns 2 and 3
    CC4_QR2     %1, xmm0, xmm5, xmm8, xmm13, xmm1, xmm6, xmm9, xmm10     ; diagonals 0 5 10 15
  %if %3                                                                ; and 1 6 11 12
    P_SLOT      0
  %endif
    movdqa      [rsp + C4_SLOT + 32], xmm8  ; x10, x11 out; x8, x9 in
    movdqa      [rsp + C4_SLOT + 48], xmm9
    movdqa      xmm8, [rsp + C4_SLOT + 0]
    movdqa      xmm9, [rsp + C4_SLOT + 16]
    CC4_QR2     %1, xmm2, xmm7, xmm8, xmm11, xmm3, xmm4, xmm9, xmm12     ; diagonals 2 7 8 13
    dec         ecx                                                     ; and 3 4 9 14
    jnz         %%double
    ; The input added back (RFC 8439 2.3), word group by word group, each group transposed into
    ; the four blocks' rows and put out.
    paddd       xmm0, [rsp + C4_IN + 0 * 16]
    paddd       xmm1, [rsp + C4_IN + 1 * 16]
    paddd       xmm2, [rsp + C4_IN + 2 * 16]
    paddd       xmm3, [rsp + C4_IN + 3 * 16]
    CC4_TRANSPOSE xmm0, xmm1, xmm2, xmm3, xmm14, xmm15
    CC4_PUT     %2, 0, xmm0, xmm1, xmm14, xmm3, xmm15
    paddd       xmm4, [rsp + C4_IN + 4 * 16]
    paddd       xmm5, [rsp + C4_IN + 5 * 16]
    paddd       xmm6, [rsp + C4_IN + 6 * 16]
    paddd       xmm7, [rsp + C4_IN + 7 * 16]
    CC4_TRANSPOSE xmm4, xmm5, xmm6, xmm7, xmm14, xmm15
    CC4_PUT     %2, 16, xmm4, xmm5, xmm14, xmm7, xmm15
    movdqa      xmm0, [rsp + C4_SLOT + 32]
    movdqa      xmm1, [rsp + C4_SLOT + 48]
    paddd       xmm8, [rsp + C4_IN + 8 * 16]
    paddd       xmm9, [rsp + C4_IN + 9 * 16]
    paddd       xmm0, [rsp + C4_IN + 10 * 16]
    paddd       xmm1, [rsp + C4_IN + 11 * 16]
    CC4_TRANSPOSE xmm8, xmm9, xmm0, xmm1, xmm14, xmm15
    CC4_PUT     %2, 32, xmm8, xmm9, xmm14, xmm1, xmm15
    paddd       xmm10, [rsp + C4_IN + 12 * 16]
    paddd       xmm11, [rsp + C4_IN + 13 * 16]
    paddd       xmm12, [rsp + C4_IN + 14 * 16]
    paddd       xmm13, [rsp + C4_IN + 15 * 16]
    CC4_TRANSPOSE xmm10, xmm11, xmm12, xmm13, xmm14, xmm15
    CC4_PUT     %2, 48, xmm10, xmm11, xmm14, xmm13, xmm15
    movdqa      xmm0, [rsp + C4_IN + 12 * 16]
    paddd       xmm0, [rel cc_four]
    movdqa      [rsp + C4_IN + 12 * 16], xmm0
    add         dword [rsp + C4_STATE + 48], 4
%endmacro

; CC_HZ_QR2 v: a column round of two blocks in the horizontal layout (block A's rows in
; xmm0-xmm3, block B's in xmm4-xmm7: its four quarter rounds at once, one per lane), the two
; blocks interleaved. Diagonalized rows (pshufd) make the same code a diagonal round.
; Temporaries: xmm8, xmm9.
%macro CC_HZ_QR2 1
    paddd       xmm0, xmm1
    paddd       xmm4, xmm5
    pxor        xmm3, xmm0
    pxor        xmm7, xmm4
    CC_ROL16    %1, xmm3
    CC_ROL16    %1, xmm7
    paddd       xmm2, xmm3
    paddd       xmm6, xmm7
    pxor        xmm1, xmm2
    pxor        xmm5, xmm6
    CC_ROL      xmm1, 12, xmm8
    CC_ROL      xmm5, 12, xmm9
    paddd       xmm0, xmm1
    paddd       xmm4, xmm5
    pxor        xmm3, xmm0
    pxor        xmm7, xmm4
    CC_ROL8     %1, xmm3, xmm8
    CC_ROL8     %1, xmm7, xmm9
    paddd       xmm2, xmm3
    paddd       xmm6, xmm7
    pxor        xmm1, xmm2
    pxor        xmm5, xmm6
    CC_ROL      xmm1, 7, xmm8
    CC_ROL      xmm5, 7, xmm9
%endmacro

; CC_CLEAR_XMM: every XMM register zeroed (legacy SSE: the upper halves must already be clean,
; as after vzeroupper).
%macro CC_CLEAR_XMM 0
  %assign x 0
  %rep 16
    pxor        xmm%[x], xmm%[x]
    %assign x x + 1
  %endrep
%endmacro

; CC_WIPE_RANGE from, to: the frame's octets from..to zeroed (offsets from rsp, multiples of 16,
; from below to). A path wipes what it wrote, no more: a short record's driver wrote 300 octets
; of its frame, and wiping all 1,440 of v3's would be a quarter of its time.
; Clobbers eax, xmm0 and the flags.
%macro CC_WIPE_RANGE 2
    pxor        xmm0, xmm0
    mov         eax, %1
%%wipe:
    movdqa      [rsp + rax], xmm0
    add         eax, 16
    cmp         eax, %2
    jb          %%wipe
%endmacro

; CC_WIPE_USED length, limit, key, state, end: the frame's secrets wiped, then every XMM
; register. When the qword at rsp + length (the call's length) is at most limit (the length the
; driver's short path takes: 128 for the raw cipher, 64 for the AEAD), only what that path
; writes: the keystream at key (128 octets) and state..end (the input state and Poly1305's area);
; otherwise the whole frame below end. Clobbers eax, xmm0-xmm15 and the flags.
%macro CC_WIPE_USED 5
    cmp         qword [rsp + %1], %2
    ja          %%all
    CC_WIPE_RANGE %3, %3 + 128
    CC_WIPE_RANGE %4, %5
    jmp         %%clear
%%all:
    CC_WIPE_RANGE 0, %5
%%clear:
    CC_CLEAR_XMM
%endmacro

; =============================================================================
; ChaCha20's pieces, AVX2 (v3): the same arrangement on eight blocks in YMM registers.
; =============================================================================

; CC_VROL x, n, t: each dword of x rotated left by n, through the temporary t.
%macro CC_VROL 3
    vpslld      %3, %1, %2
    vpsrld      %1, %1, 32 - %2
    vpor        %1, %1, %3
%endmacro

; CC8_QR2 a1, b1, c1, d1, a2, b2, c2, d2: two quarter rounds side by side on eight blocks.
; Temporaries: ymm14, ymm15.
%macro CC8_QR2 8
    vpaddd      %1, %1, %2
    vpaddd      %5, %5, %6
    vpxor       %4, %4, %1
    vpxor       %8, %8, %5
    vpshufb     %4, %4, [rel cc_rot16]
    vpshufb     %8, %8, [rel cc_rot16]
    vpaddd      %3, %3, %4
    vpaddd      %7, %7, %8
    vpxor       %2, %2, %3
    vpxor       %6, %6, %7
    CC_VROL     %2, 12, ymm14
    CC_VROL     %6, 12, ymm15
    vpaddd      %1, %1, %2
    vpaddd      %5, %5, %6
    vpxor       %4, %4, %1
    vpxor       %8, %8, %5
    vpshufb     %4, %4, [rel cc_rot8]
    vpshufb     %8, %8, [rel cc_rot8]
    vpaddd      %3, %3, %4
    vpaddd      %7, %7, %8
    vpxor       %2, %2, %3
    vpxor       %6, %6, %7
    CC_VROL     %2, 7, ymm14
    CC_VROL     %6, 7, ymm15
%endmacro

; CC8_TRANSPOSE a, b, c, d, t0, t1, t2, t3: four words of eight blocks turned into rows within
; each 128-bit lane: a = blocks 0 | 4, b = 1 | 5, c = 2 | 6, d = 3 | 7 (low lane | high lane).
%macro CC8_TRANSPOSE 8
    vpunpckldq  %5, %1, %2
    vpunpckhdq  %6, %1, %2
    vpunpckldq  %7, %3, %4
    vpunpckhdq  %8, %3, %4
    vpunpcklqdq %1, %5, %7
    vpunpckhqdq %2, %5, %7
    vpunpcklqdq %3, %6, %8
    vpunpckhqdq %4, %6, %8
%endmacro

; CC8_PUT1 mode, off, j, a, b: octets off..off+31 of blocks j and j + 4, from the rows a (the
; group of octets off..off+15) and b (off+16..off+31). mode 0: xored with the input at r13 + rbx
; into the output at r14 + rbx (each piece read before it is written: out may be in); mode 1:
; into C8_KEY. Clobbers ymm8, ymm9.
%macro CC8_PUT1 5
    vperm2i128  ymm8, %4, %5, 0x20
    vperm2i128  ymm9, %4, %5, 0x31
  %if %1 == 0
    vpxor       ymm8, ymm8, [r13 + rbx + 64 * %3 + %2]
    vmovdqu     [r14 + rbx + 64 * %3 + %2], ymm8
    vpxor       ymm9, ymm9, [r13 + rbx + 64 * (%3 + 4) + %2]
    vmovdqu     [r14 + rbx + 64 * (%3 + 4) + %2], ymm9
  %else
    vmovdqu     [rsp + C8_KEY + 64 * %3 + %2], ymm8
    vmovdqu     [rsp + C8_KEY + 64 * (%3 + 4) + %2], ymm9
  %endif
%endmacro

; CC8_BROADCAST: C8_IN from C8_STATE: each word in all eight lanes, word 12 the eight counters.
%macro CC8_BROADCAST 0
  %assign w 0
  %rep 16
    vpbroadcastd ymm0, [rsp + C8_STATE + 4 * w]
    %if w == 12
    vpaddd      ymm0, ymm0, [rel cc_lanes]
    %endif
    vmovdqu     [rsp + C8_IN + 32 * w], ymm0
    %assign w w + 1
  %endrep
%endmacro

; CC8_STEP mode, poly: eight blocks of keystream from the counters in C8_IN's word 12, then the
; counters advanced by eight. mode 0: xored from r13 + rbx into r14 + rbx (512 octets); mode 1:
; into C8_KEY. poly 1: Poly1305 (mulx) hashes blocks of its backlog after each pair of quarter
; rounds (P_SLOT: up to 40 blocks a step). Clobbers ecx, ymm0-ymm15, the flags, and with poly
; rax, rdx, rsi, rdi, r11, r12, r8-r10.
%macro CC8_STEP 2
    vmovdqu     ymm0, [rsp + C8_IN + 0 * 32]
    vmovdqu     ymm1, [rsp + C8_IN + 1 * 32]
    vmovdqu     ymm2, [rsp + C8_IN + 2 * 32]
    vmovdqu     ymm3, [rsp + C8_IN + 3 * 32]
    vmovdqu     ymm4, [rsp + C8_IN + 4 * 32]
    vmovdqu     ymm5, [rsp + C8_IN + 5 * 32]
    vmovdqu     ymm6, [rsp + C8_IN + 6 * 32]
    vmovdqu     ymm7, [rsp + C8_IN + 7 * 32]
    vmovdqu     ymm8, [rsp + C8_IN + 10 * 32]
    vmovdqu     ymm9, [rsp + C8_IN + 11 * 32]
    vmovdqu     [rsp + C8_SLOT + 64], ymm8  ; x10 and x11 start out of registers
    vmovdqu     [rsp + C8_SLOT + 96], ymm9
    vmovdqu     ymm8, [rsp + C8_IN + 8 * 32]
    vmovdqu     ymm9, [rsp + C8_IN + 9 * 32]
    vmovdqu     ymm10, [rsp + C8_IN + 12 * 32]
    vmovdqu     ymm11, [rsp + C8_IN + 13 * 32]
    vmovdqu     ymm12, [rsp + C8_IN + 14 * 32]
    vmovdqu     ymm13, [rsp + C8_IN + 15 * 32]
    mov         ecx, 10
%%double:
    CC8_QR2     ymm0, ymm4, ymm8, ymm10, ymm1, ymm5, ymm9, ymm11     ; columns 0 and 1
  %if %2
    P_SLOT      1
  %endif
    vmovdqu     [rsp + C8_SLOT + 0], ymm8   ; x8, x9 out; x10, x11 in
    vmovdqu     [rsp + C8_SLOT + 32], ymm9
    vmovdqu     ymm8, [rsp + C8_SLOT + 64]
    vmovdqu     ymm9, [rsp + C8_SLOT + 96]
    CC8_QR2     ymm2, ymm6, ymm8, ymm12, ymm3, ymm7, ymm9, ymm13     ; columns 2 and 3
  %if %2
    P_SLOT      1
  %endif
    CC8_QR2     ymm0, ymm5, ymm8, ymm13, ymm1, ymm6, ymm9, ymm10     ; diagonals 0 5 10 15
  %if %2                                                            ; and 1 6 11 12
    P_SLOT      1
  %endif
    vmovdqu     [rsp + C8_SLOT + 64], ymm8  ; x10, x11 out; x8, x9 in
    vmovdqu     [rsp + C8_SLOT + 96], ymm9
    vmovdqu     ymm8, [rsp + C8_SLOT + 0]
    vmovdqu     ymm9, [rsp + C8_SLOT + 32]
    CC8_QR2     ymm2, ymm7, ymm8, ymm11, ymm3, ymm4, ymm9, ymm12     ; diagonals 2 7 8 13
  %if %2                                                            ; and 3 4 9 14
    P_SLOT      1
  %endif
    dec         ecx
    jnz         %%double
    ; The input added back; x8, x9 to their slots and x12-x15 to C8_W, freeing ymm8-ymm15 for
    ; the transposes. Octets 0-31 of the eight blocks from words 0-7, then 32-63 from 8-15.
    vpaddd      ymm8, ymm8, [rsp + C8_IN + 8 * 32]
    vpaddd      ymm9, ymm9, [rsp + C8_IN + 9 * 32]
    vmovdqu     [rsp + C8_SLOT + 0], ymm8
    vmovdqu     [rsp + C8_SLOT + 32], ymm9
    vpaddd      ymm10, ymm10, [rsp + C8_IN + 12 * 32]
    vpaddd      ymm11, ymm11, [rsp + C8_IN + 13 * 32]
    vpaddd      ymm12, ymm12, [rsp + C8_IN + 14 * 32]
    vpaddd      ymm13, ymm13, [rsp + C8_IN + 15 * 32]
    vmovdqu     [rsp + C8_W + 0], ymm10
    vmovdqu     [rsp + C8_W + 32], ymm11
    vmovdqu     [rsp + C8_W + 64], ymm12
    vmovdqu     [rsp + C8_W + 96], ymm13
    vpaddd      ymm0, ymm0, [rsp + C8_IN + 0 * 32]
    vpaddd      ymm1, ymm1, [rsp + C8_IN + 1 * 32]
    vpaddd      ymm2, ymm2, [rsp + C8_IN + 2 * 32]
    vpaddd      ymm3, ymm3, [rsp + C8_IN + 3 * 32]
    vpaddd      ymm4, ymm4, [rsp + C8_IN + 4 * 32]
    vpaddd      ymm5, ymm5, [rsp + C8_IN + 5 * 32]
    vpaddd      ymm6, ymm6, [rsp + C8_IN + 6 * 32]
    vpaddd      ymm7, ymm7, [rsp + C8_IN + 7 * 32]
    CC8_TRANSPOSE ymm0, ymm1, ymm2, ymm3, ymm8, ymm9, ymm10, ymm11
    CC8_TRANSPOSE ymm4, ymm5, ymm6, ymm7, ymm8, ymm9, ymm10, ymm11
    CC8_PUT1    %1, 0, 0, ymm0, ymm4
    CC8_PUT1    %1, 0, 1, ymm1, ymm5
    CC8_PUT1    %1, 0, 2, ymm2, ymm6
    CC8_PUT1    %1, 0, 3, ymm3, ymm7
    vmovdqu     ymm0, [rsp + C8_SLOT + 0]
    vmovdqu     ymm1, [rsp + C8_SLOT + 32]
    vmovdqu     ymm2, [rsp + C8_SLOT + 64]
    vmovdqu     ymm3, [rsp + C8_SLOT + 96]
    vpaddd      ymm2, ymm2, [rsp + C8_IN + 10 * 32]
    vpaddd      ymm3, ymm3, [rsp + C8_IN + 11 * 32]
    vmovdqu     ymm4, [rsp + C8_W + 0]
    vmovdqu     ymm5, [rsp + C8_W + 32]
    vmovdqu     ymm6, [rsp + C8_W + 64]
    vmovdqu     ymm7, [rsp + C8_W + 96]
    CC8_TRANSPOSE ymm0, ymm1, ymm2, ymm3, ymm8, ymm9, ymm10, ymm11
    CC8_TRANSPOSE ymm4, ymm5, ymm6, ymm7, ymm8, ymm9, ymm10, ymm11
    CC8_PUT1    %1, 32, 0, ymm0, ymm4
    CC8_PUT1    %1, 32, 1, ymm1, ymm5
    CC8_PUT1    %1, 32, 2, ymm2, ymm6
    CC8_PUT1    %1, 32, 3, ymm3, ymm7
    vmovdqu     ymm0, [rsp + C8_IN + 12 * 32]
    vpaddd      ymm0, ymm0, [rel cc_eight]
    vmovdqu     [rsp + C8_IN + 12 * 32], ymm0
    add         dword [rsp + C8_STATE + 48], 8
%endmacro

; =============================================================================
; Poly1305's pieces. h in r8 (h0), r9 (h1), r10 (h2); the key in the area at rbp (PA_*).
; =============================================================================

; P_FOLD: the partial reduction of a product: h2 (r10) holds bits 128 and up; bits 130 and up,
; t >> 2, come back at the low end times 5 (2^130 = 5 modulo 2^130 - 5), as 4 (t >> 2) + (t >> 2)
; = (t & ~3) + (t >> 2), and h2 keeps bits 128-129. Clobbers rax, rdx and the flags.
%macro P_FOLD 0
    mov         rax, r10
    mov         rdx, r10
    and         r10, 3
    shr         rdx, 2
    and         rax, -4
    add         rax, rdx
    add         r8, rax
    adc         r9, 0
    adc         r10, 0
%endmacro

; P_BLOCK bmi, p, hibit: h = (h + the 16 octets at p + hibit 2^128) r, partially reduced.
; Bounds: h2 is at most 4 after a block and at most 6 entering the products, r0 and r1 are
; below 2^60 and s1 below 2^61, so h2 s1 fits 64 bits, the carry word of 2^0 stays below 2^62,
; that of 2^64 below 2^62, and the 2^128 word below 2^64. bmi 1: mulx (BMI2), 0: mul.
; The products land in h's own registers where they can (no moves at the end): in the
; stitched AEAD every scalar instruction here that the scheduler sends to port 0, 1 or 5 takes a
; slot from ChaCha20's vector work, so fewer of them is a faster loop.
; Clobbers rax, rdx, rsi, rdi, r11 and the flags.
%macro P_BLOCK 3
    add         r8, [%2]
    adc         r9, [%2 + 8]
    adc         r10, %3
  %if %1
    ; The products in the order that readies the 2^0 word's carry first (it feeds 2^64, which
    ; feeds 2^128 and the reduction: the chain that sets a block's latency).
    mov         rdx, r8                     ; h0 (r8 is free once rdx holds it)
    mulx        rsi, r8, [rbp + PA_R0]      ; h0 r0: rsi:r8
    mulx        r11, rax, [rbp + PA_R1]     ; h0 r1: r11:rax
    mov         rdx, r9                     ; h1
    mulx        rdi, r9, [rbp + PA_S1]      ; h1 s1: rdi:r9
    add         r8, r9
    adc         rsi, rdi                    ; 2^0: rsi:r8 = h0 r0 + h1 s1
    mulx        rdi, r9, [rbp + PA_R0]      ; h1 r0: rdi:r9
    add         r9, rax
    adc         r11, rdi                    ; 2^64: r11:r9 = h0 r1 + h1 r0
    mov         rdx, r10
    imul        rdx, [rbp + PA_S1]          ; h2 s1 (2^64)
    imul        r10, [rbp + PA_R0]          ; h2 r0 (2^128)
    add         r9, rdx
    adc         r11, 0
    add         r9, rsi                     ; + the carry word of 2^0
    adc         r11, 0
    add         r10, r11                    ; 2^128: h2 r0 + the carry word of 2^64
  %else
    mov         rax, [rbp + PA_R0]
    mul         r8                          ; h0 r0
    mov         rsi, rax
    mov         rdi, rdx
    mov         rax, [rbp + PA_R1]
    mul         r8                          ; h0 r1
    mov         r8, rax
    mov         r11, rdx
    mov         rax, [rbp + PA_S1]
    mul         r9                          ; h1 s1
    add         rsi, rax
    adc         rdi, rdx                    ; 2^0: rdi:rsi = h0 r0 + h1 s1
    mov         rax, [rbp + PA_R0]
    mul         r9                          ; h1 r0
    add         r8, rax
    adc         r11, rdx                    ; 2^64: r11:r8 = h0 r1 + h1 r0
    mov         rax, r10
    imul        rax, [rbp + PA_S1]          ; h2 s1 (2^64)
    imul        r10, [rbp + PA_R0]          ; h2 r0 (2^128)
    add         r8, rax
    adc         r11, 0
    add         r8, rdi                     ; + the carry word of 2^0
    adc         r11, 0
    add         r10, r11                    ; 2^128: h2 r0 + the carry word of 2^64
    mov         r9, r8
    mov         r8, rsi
  %endif
    ; The partial reduction: bits 130 and up of h, times 5, back into its low end.
    P_FOLD
%endmacro

; P_KEY p: the one-time key from the 32 octets at p: r clamped (RFC 8439 2.5: the top four bits
; of r's every 32-bit word and the low two of words 1-3 cleared), s1, s; h = 0.
; Clobbers rax, rdx and the flags.
%macro P_KEY 1
    mov         rax, 0x0ffffffc0fffffff
    and         rax, [%1]
    mov         rdx, 0x0ffffffc0ffffffc
    and         rdx, [%1 + 8]
    mov         [rbp + PA_R0], rax
    mov         [rbp + PA_R1], rdx
    mov         rax, rdx
    shr         rax, 2
    add         rax, rdx
    mov         [rbp + PA_S1], rax
    mov         rax, [%1 + 16]
    mov         rdx, [%1 + 24]
    mov         [rbp + PA_S], rax
    mov         [rbp + PA_S + 8], rdx
    xor         r8d, r8d
    xor         r9d, r9d
    xor         r10d, r10d
%endmacro

; P_FINAL p: the tag into the 16 octets at p: h fully reduced (h is below 2 (2^130 - 5) after a
; partial reduction, so one conditional subtraction does it: h + 5 reaches 2^130 exactly when
; h >= 2^130 - 5, and then its low 128 bits are h - p's; selected with cmov), plus s, modulo
; 2^128. Clobbers rax, rdx, r8-r10 and the flags.
%macro P_FINAL 1
    mov         rax, r8
    mov         rdx, r9
    add         rax, 5
    adc         rdx, 0
    adc         r10, 0
    shr         r10, 2
    cmovnz      r8, rax
    cmovnz      r9, rdx
    add         r8, [rbp + PA_S]
    adc         r9, [rbp + PA_S + 8]
    mov         [%1], r8
    mov         [%1 + 8], r9
%endmacro

; P_SLOT bmi: the stitched hook: one block of Poly1305's backlog, the one at r12, hashed when
; r12 is below the area's PA_END (seal: the end of the ciphertext written; open: the end of the
; input's whole blocks), r12 advanced. Clobbers rax, rdx, rsi, rdi, r11 and the flags.
%macro P_SLOT 1
    cmp         r12, [rbp + PA_END]
    jae         %%skip
    P_BLOCK     %1, r12, 1
    add         r12, 16
%%skip:
%endmacro

; P_LENGTHS bmi: the AEAD's last block, le64(AAD length) || le64(text length), through h.
; Clobbers rax, rdx, rsi, rdi, r11, r12 and the flags.
%macro P_LENGTHS 1
    mov         rax, [rbp + PA_AAD]
    mov         [rbp + PA_PART], rax
    mov         rax, [rbp + PA_LEN]
    mov         [rbp + PA_PART + 8], rax
    lea         r12, [rbp + PA_PART]
    P_BLOCK     %1, r12, 1
%endmacro

; -----------------------------------------------------------------------------
; cp_blocks_vN: h through rcx whole blocks at r12 (each with 2^128), r12 advanced past them.
;   In: rbp = the Poly1305 area, r8-r10 = h. Clobbers rax, rcx, rdx, rsi, rdi, r11, the flags.
; cp_rest_vN: the rest of the text through h: its whole blocks from r12 up, then its last octets
; (if the length is not a multiple of 16) padded with zeros to a block (RFC 8439 2.8's pad16).
;   In: rbp = the area (PA_SRC, PA_LEN set), r12 = the next block (on the text's block grid, at
;   most at the end of its whole blocks), r8-r10 = h. Clobbers rax, rcx, rdx, rsi, rdi, r11,
;   r12, xmm0, the flags. Called once per AEAD, after (seal) or before (open) the last output.
; -----------------------------------------------------------------------------
%macro CP_ROUTINES 2    ; version (1 or 3), bmi
align 16
cp_blocks_v%1:
    test        rcx, rcx
    jz          .done
.block:
    P_BLOCK     %2, r12, 1
    add         r12, 16
    dec         rcx
    jnz         .block
.done:
    ret

align 16
cp_rest_v%1:
    mov         rcx, [rbp + PA_LEN]
    and         rcx, -16
    add         rcx, [rbp + PA_SRC]         ; the end of the text's whole blocks
    sub         rcx, r12
    shr         rcx, 4
    call        cp_blocks_v%1
    mov         rcx, [rbp + PA_LEN]
    and         ecx, 15
    jz          .done
    pxor        xmm0, xmm0
    movdqa      [rbp + PA_PART], xmm0
    lea         rdi, [rbp + PA_PART]
    mov         rsi, r12                    ; the last octets
    call        ha_copy_short
    lea         r12, [rbp + PA_PART]
    P_BLOCK     %2, r12, 1
.done:
    ret
%endmacro

CP_ROUTINES 1, 0
CP_ROUTINES 3, 1

; -----------------------------------------------------------------------------
; cc_hz2_vN (v = 1, 2): two consecutive blocks of keystream, counters c and c + 1 (modulo 2^32),
; in the horizontal layout.
;   In: rdi = the input state (64 octets: sigma, key, counter c, nonce), rsi = the output
;   (128 octets, 16-aligned). Clobbers ecx, xmm0-xmm11, the flags. Legacy SSE: a v3 caller
;   cleans the YMM upper halves first.
; -----------------------------------------------------------------------------
%macro CC_HZ2_ROUTINE 1
align 16
cc_hz2_v%1:
    movdqu      xmm0, [rdi]
    movdqu      xmm1, [rdi + 16]
    movdqu      xmm2, [rdi + 32]
    movdqu      xmm3, [rdi + 48]
    movdqa      xmm4, xmm0
    movdqa      xmm5, xmm1
    movdqa      xmm6, xmm2
    movdqa      xmm7, xmm3
    paddd       xmm7, [rel cc_one]
    mov         ecx, 10
.double:
    CC_HZ_QR2   %1
    pshufd      xmm1, xmm1, 0x39            ; rows 1-3 turned left by 1, 2, 3 words: the
    pshufd      xmm5, xmm5, 0x39            ; diagonals line up as columns
    pshufd      xmm2, xmm2, 0x4E
    pshufd      xmm6, xmm6, 0x4E
    pshufd      xmm3, xmm3, 0x93
    pshufd      xmm7, xmm7, 0x93
    CC_HZ_QR2   %1
    pshufd      xmm1, xmm1, 0x93            ; and back
    pshufd      xmm5, xmm5, 0x93
    pshufd      xmm2, xmm2, 0x4E
    pshufd      xmm6, xmm6, 0x4E
    pshufd      xmm3, xmm3, 0x39
    pshufd      xmm7, xmm7, 0x39
    dec         ecx
    jnz         .double
    movdqu      xmm8, [rdi]
    movdqu      xmm9, [rdi + 16]
    movdqu      xmm10, [rdi + 32]
    movdqu      xmm11, [rdi + 48]
    paddd       xmm0, xmm8
    paddd       xmm4, xmm8
    paddd       xmm1, xmm9
    paddd       xmm5, xmm9
    paddd       xmm2, xmm10
    paddd       xmm6, xmm10
    paddd       xmm3, xmm11
    paddd       xmm11, [rel cc_one]
    paddd       xmm7, xmm11
    movdqa      [rsi], xmm0
    movdqa      [rsi + 16], xmm1
    movdqa      [rsi + 32], xmm2
    movdqa      [rsi + 48], xmm3
    movdqa      [rsi + 64], xmm4
    movdqa      [rsi + 80], xmm5
    movdqa      [rsi + 96], xmm6
    movdqa      [rsi + 112], xmm7
    ret
%endmacro

CC_HZ2_ROUTINE 1
CC_HZ2_ROUTINE 2

; -----------------------------------------------------------------------------
; cc_xor_tail: out[0..rcx) = in[0..rcx) ^ K[0..rcx): sixteen octets at a time, then one at a
; time (each read before its write: out may be in).
;   In: rsi = in, rdi = out, rdx = K (16-aligned), rcx = count. Clobbers rax, rcx, rdx, rsi,
;   rdi, xmm0, the flags. Legacy SSE.
; -----------------------------------------------------------------------------
align 16
cc_xor_tail:
.x16:
    cmp         rcx, 16
    jb          .x1
    movdqu      xmm0, [rsi]
    pxor        xmm0, [rdx]
    movdqu      [rdi], xmm0
    add         rsi, 16
    add         rdi, 16
    add         rdx, 16
    sub         rcx, 16
    jmp         .x16
.x1:
    test        rcx, rcx
    jz          .done
.byte:
    mov         al, [rsi]
    xor         al, [rdx]
    mov         [rdi], al
    inc         rsi
    inc         rdi
    inc         rdx
    dec         rcx
    jnz         .byte
.done:
    ret

; -----------------------------------------------------------------------------
; cc_xor4_vN (v = 1, 2): in[0..length) xored with ChaCha20's keystream into out (out may be in),
; four blocks a step; work of 128 octets or less, and a last piece that short, through
; cc_hz2_vN.
;   In: rdi = the input state (64 octets; word 12 the first block's counter), rsi = in, rdx =
;   out, rcx = length. Keeps rbx, rbp, r12-r15. The frame is wiped and xmm0-xmm15 cleared.
; -----------------------------------------------------------------------------
%macro CC_XOR4_ROUTINE 1
align 16
cc_xor4_v%1:
    push        rbx
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    and         rsp, -64
    sub         rsp, C4_FRAME
    mov         [rsp + C4_OLDSP], rax
    mov         r13, rsi
    mov         r14, rdx
    mov         r15, rcx
    mov         [rsp + C4_POLY + PA_LEN], rcx   ; (the AEAD's area is free here: the wipe's choice)
    xor         ebx, ebx
    movdqu      xmm0, [rdi]
    movdqu      xmm1, [rdi + 16]
    movdqu      xmm2, [rdi + 32]
    movdqu      xmm3, [rdi + 48]
    movdqa      [rsp + C4_STATE], xmm0
    movdqa      [rsp + C4_STATE + 16], xmm1
    movdqa      [rsp + C4_STATE + 32], xmm2
    movdqa      [rsp + C4_STATE + 48], xmm3
    cmp         r15, 128
    jbe         .last                       ; short: two horizontal blocks do it all
    CC4_BROADCAST
.step:
    cmp         r15, 256
    jb          .tail
    CC4_STEP    %1, 0, 0
    add         rbx, 256
    sub         r15, 256
    jmp         .step
.tail:
    test        r15, r15
    jz          .wipe
    cmp         r15, 128
    jbe         .last
    CC4_STEP    %1, 1, 0
    jmp         .xor
.last:
    lea         rdi, [rsp + C4_STATE]
    lea         rsi, [rsp + C4_KEY]
    call        cc_hz2_v%1
.xor:
    lea         rsi, [r13 + rbx]
    lea         rdi, [r14 + rbx]
    lea         rdx, [rsp + C4_KEY]
    mov         rcx, r15
    call        cc_xor_tail
.wipe:
    CC_WIPE_USED C4_POLY + PA_LEN, 128, C4_KEY, C4_STATE, C4_OLDSP
    mov         rsp, [rsp + C4_OLDSP]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbx
    ret
%endmacro

CC_XOR4_ROUTINE 1
CC_XOR4_ROUTINE 2

; -----------------------------------------------------------------------------
; cc_xor8_v3: cc_xor4's work with AVX2, eight blocks a step; short work and a last piece of 128
; octets or less through cc_hz2_v2 (v3 has SSSE3) after vzeroupper.
;   In, out: as cc_xor4_vN's. Ends with the YMM registers cleared (vzeroupper, then the XMM
;   halves).
; -----------------------------------------------------------------------------
align 16
cc_xor8_v3:
    push        rbx
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    and         rsp, -64
    sub         rsp, C8_FRAME
    mov         [rsp + C8_OLDSP], rax
    mov         r13, rsi
    mov         r14, rdx
    mov         r15, rcx
    mov         [rsp + C8_POLY + PA_LEN], rcx   ; (the AEAD's area is free here: the wipe's choice)
    xor         ebx, ebx
    movdqu      xmm0, [rdi]
    movdqu      xmm1, [rdi + 16]
    movdqu      xmm2, [rdi + 32]
    movdqu      xmm3, [rdi + 48]
    movdqa      [rsp + C8_STATE], xmm0
    movdqa      [rsp + C8_STATE + 16], xmm1
    movdqa      [rsp + C8_STATE + 32], xmm2
    movdqa      [rsp + C8_STATE + 48], xmm3
    cmp         r15, 128
    jbe         .last
    CC8_BROADCAST
.step:
    cmp         r15, 512
    jb          .tail
    CC8_STEP    0, 0
    add         rbx, 512
    sub         r15, 512
    jmp         .step
.tail:
    vzeroupper                              ; from here on legacy SSE only
    test        r15, r15
    jz          .wipe
    cmp         r15, 128
    jbe         .last
    CC8_STEP    1, 0                        ; (C8_IN is memory: the vzeroupper above left it)
    vzeroupper
    jmp         .xor
.last:
    lea         rdi, [rsp + C8_STATE]
    lea         rsi, [rsp + C8_KEY]
    call        cc_hz2_v2
.xor:
    lea         rsi, [r13 + rbx]
    lea         rdi, [r14 + rbx]
    lea         rdx, [rsp + C8_KEY]
    mov         rcx, r15
    call        cc_xor_tail
.wipe:
    CC_WIPE_USED C8_POLY + PA_LEN, 128, C8_KEY, C8_STATE, C8_OLDSP
    mov         rsp, [rsp + C8_OLDSP]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbx
    ret

; =============================================================================
; The AEAD's drivers.
; =============================================================================

; CP_BEGIN state, key, hz, version: the opening every driver shares: the input state at counter
; 0 from the request (r15), blocks 0 and 1 by cc_hz2_v<hz> into key (128 octets), the one-time
; Poly1305 key from block 0 (RFC 8439 2.6), the request's lengths, pointers and flag into the
; Poly1305 area (rbp), r13 = in, r14 = out, and the AAD hashed with its padding. Then r12 = the
; text's first block (PA_SRC) and rbx = the text's length. Clobbers every caller-saved register.
%macro CP_BEGIN 4
    movdqa      xmm0, [rel cc_sigma]
    movdqa      [rsp + %1], xmm0
    mov         rax, [r15 + CR_KEY]
    movdqu      xmm0, [rax]
    movdqa      [rsp + %1 + 16], xmm0
    movdqu      xmm0, [rax + 16]
    movdqa      [rsp + %1 + 32], xmm0
    mov         rax, [r15 + CR_NONCE]
    mov         dword [rsp + %1 + 48], 0    ; block 0 first
    mov         rdx, [rax]
    mov         [rsp + %1 + 52], rdx
    mov         edx, [rax + 8]
    mov         [rsp + %1 + 60], edx
    lea         rdi, [rsp + %1]
    lea         rsi, [rsp + %2]
    call        cc_hz2_v%3
    P_KEY       rsp + %2
    mov         rax, [r15 + CR_AADLEN]
    mov         [rbp + PA_AAD], rax
    mov         rax, [r15 + CR_LEN]
    mov         [rbp + PA_LEN], rax
    mov         rax, [r15 + CR_TAG]
    mov         [rbp + PA_TAG], rax
    movzx       eax, byte [r15 + CR_OPEN]
    mov         [rbp + PA_OPEN], rax
    mov         r13, [r15 + CR_IN]
    mov         r14, [r15 + CR_OUT]
    mov         rax, r14                    ; seal hashes its output,
    test        byte [r15 + CR_OPEN], 1
    cmovnz      rax, r13                    ; open its input
    mov         [rbp + PA_SRC], rax
    ; The AAD and its pad16 (RFC 8439 2.8).
    mov         r12, [r15 + CR_AAD]
    mov         rcx, [r15 + CR_AADLEN]
    shr         rcx, 4
    call        cp_blocks_v%4
    mov         rcx, [rbp + PA_AAD]
    and         ecx, 15
    jz          %%aad_done
    pxor        xmm0, xmm0
    movdqa      [rbp + PA_PART], xmm0
    lea         rdi, [rbp + PA_PART]
    mov         rsi, r12
    call        ha_copy_short
    lea         r12, [rbp + PA_PART]
    mov         ecx, 1
    call        cp_blocks_v%4
%%aad_done:
    mov         r12, [rbp + PA_SRC]
    mov         rbx, [rbp + PA_LEN]
%endmacro

; CP_FIRST key, version, short: the text's first 64 octets with block 1's keystream (at key +
; 64), when the text is longer (a text of 64 octets or less jumps to short, all of it there).
; open hashes the four blocks before writing over them; afterwards PA_END is the stitched hook's
; limit (seal: the 64 octets written; open: the end of the input's whole blocks), rbx = 64 and
; r15 = the octets left. Clobbers every caller-saved register.
%macro CP_FIRST 3
    cmp         rbx, 64
    jbe         %3
    cmp         qword [rbp + PA_OPEN], 0
    je          %%write
    mov         ecx, 4
    call        cp_blocks_v%2
%%write:
    mov         rsi, r13
    mov         rdi, r14
    lea         rdx, [rsp + %1 + 64]
    mov         ecx, 64
    call        cc_xor_tail
    lea         rax, [r14 + 64]
    mov         rdx, [rbp + PA_LEN]
    and         rdx, -16
    add         rdx, r13
    cmp         qword [rbp + PA_OPEN], 0
    cmovne      rax, rdx
    mov         [rbp + PA_END], rax
    mov         r15, rbx
    sub         r15, 64
    mov         ebx, 64
%endmacro

; CP_SHORT key, version, done: a text of 64 octets or less (rbx = its length) with block 1's
; keystream: open hashes it (pad16 included) before writing, seal after; then jumps to done.
%macro CP_SHORT 3
    cmp         qword [rbp + PA_OPEN], 0
    je          %%seal
    call        cp_rest_v%2
    mov         rsi, r13
    mov         rdi, r14
    lea         rdx, [rsp + %1 + 64]
    mov         rcx, rbx
    call        cc_xor_tail
    jmp         %3
%%seal:
    mov         rsi, r13
    mov         rdi, r14
    lea         rdx, [rsp + %1 + 64]
    mov         rcx, rbx
    call        cc_xor_tail
    call        cp_rest_v%2
    jmp         %3
%endmacro

; CP_FINISH version: the lengths block, the tag to PA_TAG.
%macro CP_FINISH 1
  %if %1 == 3
    P_LENGTHS   1
  %else
    P_LENGTHS   0
  %endif
    mov         rdi, [rbp + PA_TAG]
    P_FINAL     rdi
%endmacro

; -----------------------------------------------------------------------------
; cp_aead4_vN (v = 1, 2): one seal or open with four-block ChaCha20 steps and Poly1305 (mul)
; stitched into them; the tag into the request's CR_TAG.
;   In: rdi = the request. Keeps rbx, rbp, r12-r15. The frame is wiped and xmm0-xmm15 cleared.
; -----------------------------------------------------------------------------
%macro CP_AEAD4_ROUTINE 1
align 16
cp_aead4_v%1:
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    and         rsp, -64
    sub         rsp, C4_FRAME
    mov         [rsp + C4_OLDSP], rax
    lea         rbp, [rsp + C4_POLY]
    mov         r15, rdi
    CP_BEGIN    C4_STATE, C4_KEY, %1, 1
    CP_FIRST    C4_KEY, 1, .short
    mov         dword [rsp + C4_STATE + 48], 2  ; blocks 0 and 1 are spent
    CC4_BROADCAST
.step:
    cmp         r15, 256
    jb          .tail
    CC4_STEP    %1, 0, 1
    add         rbx, 256
    sub         r15, 256
    cmp         qword [rbp + PA_OPEN], 0
    jne         .step
    lea         rax, [r14 + rbx]            ; seal: what is written now may be hashed
    mov         [rbp + PA_END], rax
    jmp         .step
.tail:
    test        r15, r15
    jz          .rest
    CC4_STEP    %1, 1, 1                    ; the last octets' keystream, the hook still hashing
    cmp         qword [rbp + PA_OPEN], 0
    je          .tail_xor
    call        cp_rest_v1                  ; open: all the rest hashed before it is written over
    lea         rsi, [r13 + rbx]
    lea         rdi, [r14 + rbx]
    lea         rdx, [rsp + C4_KEY]
    mov         rcx, r15
    call        cc_xor_tail
    jmp         .finish
.tail_xor:
    lea         rsi, [r13 + rbx]
    lea         rdi, [r14 + rbx]
    lea         rdx, [rsp + C4_KEY]
    mov         rcx, r15
    call        cc_xor_tail
.rest:
    call        cp_rest_v1                  ; seal: the ciphertext not hashed yet (open: none)
    jmp         .finish
.short:
    CP_SHORT    C4_KEY, 1, .finish
.finish:
    CP_FINISH   1
    CC_WIPE_USED C4_POLY + PA_LEN, 64, C4_KEY, C4_STATE, C4_OLDSP
    mov         rsp, [rsp + C4_OLDSP]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret
%endmacro

CP_AEAD4_ROUTINE 1
CP_AEAD4_ROUTINE 2

; -----------------------------------------------------------------------------
; cp_aead8_v3: one seal or open with eight-block AVX2 ChaCha20 steps and Poly1305 (mulx)
; stitched into them; the tag into the request's CR_TAG.
;   In: rdi = the request. Keeps rbx, rbp, r12-r15. The frame is wiped and the YMM registers
;   cleared (vzeroupper before any legacy SSE, then the XMM halves).
; -----------------------------------------------------------------------------
align 16
cp_aead8_v3:
    push        rbx
    push        rbp
    push        r12
    push        r13
    push        r14
    push        r15
    mov         rax, rsp
    and         rsp, -64
    sub         rsp, C8_FRAME
    mov         [rsp + C8_OLDSP], rax
    lea         rbp, [rsp + C8_POLY]
    mov         r15, rdi
    CP_BEGIN    C8_STATE, C8_KEY, 2, 3
    CP_FIRST    C8_KEY, 3, .short
    mov         dword [rsp + C8_STATE + 48], 2  ; blocks 0 and 1 are spent
    CC8_BROADCAST
.step:
    cmp         r15, 512
    jb          .tail
    CC8_STEP    0, 1
    add         rbx, 512
    sub         r15, 512
    cmp         qword [rbp + PA_OPEN], 0
    jne         .step
    lea         rax, [r14 + rbx]            ; seal: what is written now may be hashed
    mov         [rbp + PA_END], rax
    jmp         .step
.tail:
    test        r15, r15
    jz          .rest
    CC8_STEP    1, 1                        ; the last octets' keystream, the hook still hashing
    vzeroupper                              ; legacy SSE from here on
    cmp         qword [rbp + PA_OPEN], 0
    je          .tail_xor
    call        cp_rest_v3                  ; open: all the rest hashed before it is written over
    lea         rsi, [r13 + rbx]
    lea         rdi, [r14 + rbx]
    lea         rdx, [rsp + C8_KEY]
    mov         rcx, r15
    call        cc_xor_tail
    jmp         .finish
.tail_xor:
    lea         rsi, [r13 + rbx]
    lea         rdi, [r14 + rbx]
    lea         rdx, [rsp + C8_KEY]
    mov         rcx, r15
    call        cc_xor_tail
.rest:
    vzeroupper                              ; (already clean when coming from .tail_xor)
    call        cp_rest_v3                  ; seal: the ciphertext not hashed yet (open: none)
    jmp         .finish
.short:
    CP_SHORT    C8_KEY, 3, .finish
.finish:
    CP_FINISH   3
    CC_WIPE_USED C8_POLY + PA_LEN, 64, C8_KEY, C8_STATE, C8_OLDSP
    mov         rsp, [rsp + C8_OLDSP]
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         rbp
    pop         rbx
    ret

; =============================================================================
; The C ABI.
; =============================================================================

; -----------------------------------------------------------------------------
; void httpasm_chacha20(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
;                       const uint8_t *in, size_t length, uint8_t *out)
;   out[0..length) = in[0..length) ^ ChaCha20's keystream from block counter on (RFC 8439 2.4);
;   the counter wraps modulo 2^32 with the nonce unchanged, so more than (2^32 - counter) * 64
;   octets repeat the keystream: the caller keeps below that.
; -----------------------------------------------------------------------------
CH_FRAME    equ 64 + 8                      ; the input state; + 8: rsp aligned for the call

global httpasm_chacha20:function (httpasm_chacha20.end - httpasm_chacha20)
align 16
httpasm_chacha20:
    sub         rsp, CH_FRAME
    movdqa      xmm0, [rel cc_sigma]
    movdqu      [rsp], xmm0
    movdqu      xmm0, [rdi]
    movdqu      [rsp + 16], xmm0
    movdqu      xmm0, [rdi + 16]
    movdqu      [rsp + 32], xmm0
    mov         [rsp + 48], esi
    mov         rax, [rdx]
    mov         [rsp + 52], rax
    mov         eax, [rdx + 8]
    mov         [rsp + 60], eax
    mov         rdi, rsp
    mov         rsi, rcx
    mov         rdx, r9
    mov         rcx, r8
    HA_CPU_PICK1 HTTPASM_CPU_V3, .v3
    HA_CPU_PICK1 HTTPASM_CPU_V2, .v2
    call        cc_xor4_v1
    jmp         .done
.v3:
    call        cc_xor8_v3
    jmp         .done
.v2:
    call        cc_xor4_v2
.done:
    pxor        xmm0, xmm0                  ; the state held the key
    movdqu      [rsp], xmm0
    movdqu      [rsp + 16], xmm0
    movdqu      [rsp + 32], xmm0
    movdqu      [rsp + 48], xmm0
    add         rsp, CH_FRAME
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_poly1305(const uint8_t key[32], const uint8_t *message, size_t length,
;                       uint8_t tag[16])
;   The one-time authenticator of RFC 8439 2.5: a message's last octets (when its length is not
;   a multiple of 16) are padded with 1 and zeros, without 2^128. A key must never authenticate
;   two messages.
; -----------------------------------------------------------------------------
PO_FRAME    equ PA_SIZE + 8                 ; two pushes + 120: rsp aligned, the area 16-aligned

; P_PARTIAL bmi: the raw Poly1305's last octets (PA_LEN & 15 of them, at r12): a block of them,
; a 1 and zeros (RFC 8439 2.5.1), hashed without 2^128.
%macro P_PARTIAL 1
    mov         rcx, [rbp + PA_LEN]
    and         ecx, 15
    jz          %%none
    pxor        xmm0, xmm0
    movdqa      [rbp + PA_PART], xmm0
    lea         rdi, [rbp + PA_PART]
    mov         rsi, r12
    call        ha_copy_short
    mov         byte [rbp + PA_PART + rcx], 1
    lea         r12, [rbp + PA_PART]
    P_BLOCK     %1, r12, 0
%%none:
%endmacro

global httpasm_poly1305:function (httpasm_poly1305.end - httpasm_poly1305)
align 16
httpasm_poly1305:
    push        rbp
    push        r12
    sub         rsp, PO_FRAME
    mov         rbp, rsp
    mov         [rbp + PA_LEN], rdx
    mov         [rbp + PA_TAG], rcx
    P_KEY       rdi
    mov         r12, rsi
    mov         rcx, [rbp + PA_LEN]
    shr         rcx, 4
    HA_CPU_PICK1 HTTPASM_CPU_V3, .v3
    call        cp_blocks_v1
    P_PARTIAL   0
    jmp         .final
.v3:
    call        cp_blocks_v3
    P_PARTIAL   1
.final:
    mov         rdi, [rbp + PA_TAG]
    P_FINAL     rdi
    pxor        xmm0, xmm0                  ; r, s and the padded block wiped
    movdqa      [rbp], xmm0
    movdqa      [rbp + 16], xmm0
    movdqa      [rbp + 32], xmm0
    movdqa      [rbp + 48], xmm0
    add         rsp, PO_FRAME
    pop         r12
    pop         rbp
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_chacha20_poly1305_seal(const uint8_t key[32], const uint8_t nonce[12],
;                                    const uint8_t *aad, size_t aad_length, const uint8_t *in,
;                                    size_t length, uint8_t *out, uint8_t tag[16])
;   Returns 0, or -1 when length exceeds 2^38 - 64 octets (RFC 8439 2.8: ChaCha20's 32-bit block
;   counter, from 1; nothing is written then).
; -----------------------------------------------------------------------------
CS_FRAME    equ CR_SIZE                     ; 72: rsp aligned for the call
CS_ARGS     equ CS_FRAME + 8                ; the caller's stack arguments: out, then tag

global httpasm_chacha20_poly1305_seal:function (httpasm_chacha20_poly1305_seal.end - httpasm_chacha20_poly1305_seal)
align 16
httpasm_chacha20_poly1305_seal:
    mov         rax, 0x3FFFFFFFC0           ; (2^32 - 1) blocks of 64 octets
    cmp         r9, rax
    ja          .refused
    sub         rsp, CS_FRAME
    mov         [rsp + CR_KEY], rdi
    mov         [rsp + CR_NONCE], rsi
    mov         [rsp + CR_AAD], rdx
    mov         [rsp + CR_AADLEN], rcx
    mov         [rsp + CR_IN], r8
    mov         [rsp + CR_LEN], r9
    mov         rax, [rsp + CS_ARGS]
    mov         [rsp + CR_OUT], rax
    mov         rax, [rsp + CS_ARGS + 8]
    mov         [rsp + CR_TAG], rax
    mov         byte [rsp + CR_OPEN], 0
    mov         rdi, rsp
    HA_CPU_PICK1 HTTPASM_CPU_V3, .v3
    HA_CPU_PICK1 HTTPASM_CPU_V2, .v2
    call        cp_aead4_v1
    jmp         .sealed
.v3:
    call        cp_aead8_v3
    jmp         .sealed
.v2:
    call        cp_aead4_v2
.sealed:
    add         rsp, CS_FRAME
    xor         eax, eax
    ret
.refused:
    mov         eax, -1
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_chacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce[12],
;                                    const uint8_t *aad, size_t aad_length, const uint8_t *in,
;                                    size_t length, const uint8_t tag[16], uint8_t *out)
;   Decrypts while hashing the input, then compares the computed tag with tag: the sixteen
;   differences or-ed together whatever they are (pcmpeqb, pmovmskb). On a mismatch out[0..length)
;   is zeroed and -1 returned; 0 otherwise. The limit as seal's (nothing written past it).
; -----------------------------------------------------------------------------
CO_TAG      equ CR_SIZE                     ; the computed tag
CO_FRAME    equ CR_SIZE + 16                ; 88: rsp aligned for the call
CO_ARGS     equ CO_FRAME + 8                ; the caller's stack arguments: tag, then out

global httpasm_chacha20_poly1305_open:function (httpasm_chacha20_poly1305_open.end - httpasm_chacha20_poly1305_open)
align 16
httpasm_chacha20_poly1305_open:
    mov         rax, 0x3FFFFFFFC0
    cmp         r9, rax
    ja          .refused
    sub         rsp, CO_FRAME
    mov         [rsp + CR_KEY], rdi
    mov         [rsp + CR_NONCE], rsi
    mov         [rsp + CR_AAD], rdx
    mov         [rsp + CR_AADLEN], rcx
    mov         [rsp + CR_IN], r8
    mov         [rsp + CR_LEN], r9
    mov         rax, [rsp + CO_ARGS + 8]
    mov         [rsp + CR_OUT], rax
    lea         rax, [rsp + CO_TAG]
    mov         [rsp + CR_TAG], rax
    mov         byte [rsp + CR_OPEN], 1
    mov         rdi, rsp
    HA_CPU_PICK1 HTTPASM_CPU_V3, .v3
    HA_CPU_PICK1 HTTPASM_CPU_V2, .v2
    call        cp_aead4_v1
    jmp         .compare
.v3:
    call        cp_aead8_v3
    jmp         .compare
.v2:
    call        cp_aead4_v2
.compare:
    mov         rax, [rsp + CO_ARGS]        ; the tag given
    movdqu      xmm0, [rax]
    movdqu      xmm1, [rsp + CO_TAG]
    pcmpeqb     xmm0, xmm1
    pmovmskb    eax, xmm0
    xor         eax, 0xFFFF                 ; 0 when all sixteen octets matched
    neg         eax                         ; CF: some octet differed
    sbb         eax, eax                    ; the verdict: all ones on a mismatch
    HA_DECLASSIFY rax                       ; (public by design; which octets matched is not)
    pxor        xmm1, xmm1
    movdqu      [rsp + CO_TAG], xmm1        ; the computed tag wiped either way
    test        eax, eax
    jz          .match
    ; A mismatch: no unauthenticated plaintext may stay. (The comparison above took the same
    ; instructions whichever octets differed; this branch only says that some did.)
    mov         rdi, [rsp + CR_OUT]
    mov         rcx, [rsp + CR_LEN]
    xor         eax, eax
    rep         stosb
    add         rsp, CO_FRAME
    mov         eax, -1
    ret
.match:
    add         rsp, CO_FRAME
    xor         eax, eax
    ret
.refused:
    mov         eax, -1
    ret
.end:
