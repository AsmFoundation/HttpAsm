; =============================================================================
; cpu/cpu.asm - what the CPU offers (CPUID, XGETBV) and what HttpAsm may use (ha_cpu): the
; CPU tiers of docs/DESIGN.md section 3. The bits (HTTPASM_CPU_*) are in httpasm_abi.inc, the
; rules and the conventions in cpu.inc.
;
; Freestanding, like the rest of the core: no C library. libhttpasm.so calls ha_cpu_detect and
; ha_cpu_apply when it loads (src/HttpAsm/cpu_abi.asm), with the cap HTTPASM_CPU asks for.
; =============================================================================
default rel
%define HA_DEFINING_CPU                     ; this file defines what cpu.inc declares extern
%include "httpasm_core.inc"

section .data
align 4
; The effective bits, read by every multi-version routine's entry. 0 means the baseline: a
; consumer that never calls ha_cpu_apply runs v1 everywhere, which is always correct. A dword
; store is atomic on x86-64, and every tier computes the same results, so a change while other
; threads run only moves their next routine to another version.
global ha_cpu:data hidden 4
ha_cpu:         dd 0
; What CPUID and XGETBV reported at the last ha_cpu_detect; 0 before it ran.
global ha_cpu_found:data hidden 4
ha_cpu_found:   dd 0

section .text

; ---- CPUID bits ha_cpu_detect reads (leaf.register: bit) ----
L1C_SSE3        equ 1 << 0
L1C_PCLMUL      equ 1 << 1
L1C_SSSE3       equ 1 << 9
L1C_FMA         equ 1 << 12
L1C_CX16        equ 1 << 13
L1C_SSE41       equ 1 << 19
L1C_SSE42       equ 1 << 20
L1C_MOVBE       equ 1 << 22
L1C_POPCNT      equ 1 << 23
L1C_AES         equ 1 << 25
L1C_OSXSAVE     equ 1 << 27
L1C_AVX         equ 1 << 28
L1C_F16C        equ 1 << 29
L7B_BMI1        equ 1 << 3
L7B_AVX2        equ 1 << 5
L7B_BMI2        equ 1 << 8
L7B_AVX512F     equ 1 << 16
L7B_AVX512DQ    equ 1 << 17
L7B_ADX         equ 1 << 19
L7B_AVX512IFMA  equ 1 << 21
L7B_AVX512CD    equ 1 << 28
L7B_SHA         equ 1 << 29
L7B_AVX512BW    equ 1 << 30
L7B_AVX512VL    equ 1 << 31
L7C_AVX512VBMI  equ 1 << 1
L7C_AVX512VBMI2 equ 1 << 6
L7C_GFNI        equ 1 << 8
L7C_VAES        equ 1 << 9
L7C_VPCLMULQDQ  equ 1 << 10
L71A_SHA512     equ 1 << 0
LXC_LAHF        equ 1 << 0          ; leaf 0x80000001 ECX: LAHF/SAHF in 64-bit mode
LXC_LZCNT       equ 1 << 5          ; leaf 0x80000001 ECX: LZCNT (ABM)
XCR0_YMM        equ (1 << 1) | (1 << 2)                 ; SSE and AVX state
XCR0_ZMM        equ (1 << 5) | (1 << 6) | (1 << 7)      ; opmask, ZMM_Hi256, Hi16_ZMM

; The features each level adds, per register they are read from.
V2_L1C          equ L1C_SSE3 | L1C_SSSE3 | L1C_CX16 | L1C_SSE41 | L1C_SSE42 | L1C_POPCNT
V3_L1C          equ L1C_FMA | L1C_MOVBE | L1C_AVX | L1C_F16C | L1C_OSXSAVE
V3_L7B          equ L7B_BMI1 | L7B_AVX2 | L7B_BMI2
V4_L7B          equ L7B_AVX512F | L7B_AVX512DQ | L7B_AVX512CD | L7B_AVX512BW | L7B_AVX512VL

; Stack frame of ha_cpu_detect: the registers CPUID returned, kept for the derivations.
D_L1C           equ 0
D_L7B           equ 4
D_L7C           equ 8
D_L71A          equ 12
D_LXC           equ 16
D_XCR0          equ 20
D_FRAME         equ 32

; -----------------------------------------------------------------------------
; HA_ALL_SET reg, mask, scratch: ZF set when every bit of mask is set in reg (unchanged).
; -----------------------------------------------------------------------------
%macro HA_ALL_SET 3
    mov     %3, %1
    and     %3, %2
    cmp     %3, %2
%endmacro

; -----------------------------------------------------------------------------
; ha_cpu_detect: what this CPU and its OS offer, as HTTPASM_CPU_* bits, stored in ha_cpu_found.
;   A level counts only when every feature of it, and of the levels below, is present, and the
;   OS saves the registers it needs (XCR0: YMM for v3, ZMM and the opmasks for v4); a group
;   whose encodings need such registers counts only when they are saved. Leaves the CPU does
;   not have read as 0, so their features count as absent.
;   Out: eax = the bits. Clobbers rcx, rdx, rsi, rdi, r8-r11 and the flags; keeps rbx (CPUID
;   overwrites it, so it is saved here).
; -----------------------------------------------------------------------------
global ha_cpu_detect:function hidden (ha_cpu_detect.end - ha_cpu_detect)
align 16
ha_cpu_detect:
    push    rbx
    sub     rsp, D_FRAME
    xor     eax, eax
    mov     [rsp + D_L7B], eax
    mov     [rsp + D_L7C], eax
    mov     [rsp + D_L71A], eax
    mov     [rsp + D_LXC], eax
    mov     [rsp + D_XCR0], eax
    cpuid                                   ; leaf 0: eax = the highest standard leaf
    mov     r8d, eax
    mov     eax, 1
    xor     ecx, ecx
    cpuid
    mov     [rsp + D_L1C], ecx
    cmp     r8d, 7
    jb      .extended                       ; no leaf 7: none of its features
    mov     eax, 7
    xor     ecx, ecx
    cpuid
    mov     [rsp + D_L7B], ebx
    mov     [rsp + D_L7C], ecx
    test    eax, eax
    jz      .extended                       ; leaf 7 has no sub-leaf 1
    mov     eax, 7
    mov     ecx, 1
    cpuid
    mov     [rsp + D_L71A], eax
.extended:
    mov     eax, 0x80000000
    cpuid                                   ; the highest extended leaf
    cmp     eax, 0x80000001
    jb      .xcr0
    mov     eax, 0x80000001
    cpuid
    mov     [rsp + D_LXC], ecx
.xcr0:
    ; XGETBV exists only when the OS enabled XSAVE (OSXSAVE); without it no YMM state is saved.
    test    dword [rsp + D_L1C], L1C_OSXSAVE
    jz      .derive
    xor     ecx, ecx
    xgetbv                                  ; edx:eax = XCR0
    mov     [rsp + D_XCR0], eax

.derive:
    xor     esi, esi                        ; the HTTPASM_CPU_* bits found
    mov     r9d, [rsp + D_L1C]
    mov     r10d, [rsp + D_L7B]
    mov     r11d, [rsp + D_L7C]
    mov     edi, [rsp + D_XCR0]

    ; Groups with legacy SSE encodings: usable at any level.
    test    r9d, L1C_AES
    jz      .no_aes
    or      esi, HTTPASM_CPU_AESNI
.no_aes:
    test    r9d, L1C_PCLMUL
    jz      .no_clmul
    or      esi, HTTPASM_CPU_CLMUL
.no_clmul:
    test    r10d, L7B_SHA
    jz      .no_sha
    or      esi, HTTPASM_CPU_SHA
.no_sha:
    test    r11d, L7C_GFNI
    jz      .no_gfni
    or      esi, HTTPASM_CPU_GFNI
.no_gfni:
    test    r10d, L7B_BMI2
    jz      .no_bmi2
    or      esi, HTTPASM_CPU_BMI2
.no_bmi2:
    test    r10d, L7B_ADX
    jz      .no_adx
    or      esi, HTTPASM_CPU_ADX
.no_adx:

    ; v2.
    HA_ALL_SET r9d, V2_L1C, eax
    jne     .done
    test    dword [rsp + D_LXC], LXC_LAHF
    jz      .done
    or      esi, HTTPASM_CPU_V2

    ; Everything below needs the OS to save the YMM registers.
    HA_ALL_SET edi, XCR0_YMM, eax
    jne     .done
    test    r11d, L7C_VAES
    jz      .no_vaes
    or      esi, HTTPASM_CPU_VAES
.no_vaes:
    test    r11d, L7C_VPCLMULQDQ
    jz      .no_vclmul
    or      esi, HTTPASM_CPU_VCLMUL
.no_vclmul:
    test    dword [rsp + D_L71A], L71A_SHA512
    jz      .no_sha512
    or      esi, HTTPASM_CPU_SHA512
.no_sha512:

    ; v3.
    HA_ALL_SET r9d, V3_L1C, eax
    jne     .done
    HA_ALL_SET r10d, V3_L7B, eax
    jne     .done
    test    dword [rsp + D_LXC], LXC_LZCNT
    jz      .done
    or      esi, HTTPASM_CPU_V3

    ; v4, and the AVX-512 groups: the ZMM and opmask state must be saved too.
    HA_ALL_SET edi, XCR0_ZMM, eax
    jne     .done
    HA_ALL_SET r10d, V4_L7B, eax
    jne     .done
    or      esi, HTTPASM_CPU_V4
    test    r10d, L7B_AVX512IFMA
    jz      .no_ifma
    or      esi, HTTPASM_CPU_IFMA
.no_ifma:
    test    r11d, L7C_AVX512VBMI
    jz      .no_vbmi
    or      esi, HTTPASM_CPU_VBMI
.no_vbmi:
    test    r11d, L7C_AVX512VBMI2
    jz      .done
    or      esi, HTTPASM_CPU_VBMI2

.done:
    mov     [rel ha_cpu_found], esi
    mov     eax, esi
    add     rsp, D_FRAME
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; ha_cpu_apply: sets what HttpAsm may use: the found bits narrowed by a cap, then closed over
; the dependencies cpu.inc lists, so no routine can pick a version whose encodings the level
; does not allow (v4 without v3, VAES without the YMM registers of v3, IFMA without v4, ...).
;   In: edi = the cap: HTTPASM_CPU_* bits (HTTPASM_CPU_CAP_V1..V4 are the levels' caps,
;   HTTPASM_CPU_ALL is no cap). Out: eax = the new ha_cpu. Clobbers only the flags.
;   Footgun: call ha_cpu_detect first; before it, ha_cpu_found is 0 and this sets the baseline.
; -----------------------------------------------------------------------------
global ha_cpu_apply:function hidden (ha_cpu_apply.end - ha_cpu_apply)
align 16
ha_cpu_apply:
    mov     eax, [rel ha_cpu_found]
    and     eax, edi
    test    eax, HTTPASM_CPU_V2
    jnz     .has_v2
    and     eax, ~(HTTPASM_CPU_V3 | HTTPASM_CPU_V4)
.has_v2:
    test    eax, HTTPASM_CPU_V3
    jnz     .has_v3
    and     eax, ~(HTTPASM_CPU_V4 | HTTPASM_CPU_BMI2 | HTTPASM_CPU_ADX | HTTPASM_CPU_VAES | HTTPASM_CPU_VCLMUL | HTTPASM_CPU_SHA512)
.has_v3:
    test    eax, HTTPASM_CPU_V4
    jnz     .store
    and     eax, ~(HTTPASM_CPU_IFMA | HTTPASM_CPU_VBMI | HTTPASM_CPU_VBMI2)
.store:
    mov     [rel ha_cpu], eax
    ret
.end:
