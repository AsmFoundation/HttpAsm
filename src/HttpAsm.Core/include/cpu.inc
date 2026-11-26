; =============================================================================
; cpu.inc - CPU tiers: how HttpAsm chooses between the versions of a routine (docs/DESIGN.md,
; sections 2 and 3, "CPU tiers"). The bits themselves are part of the C ABI: HTTPASM_CPU_* in
; httpasm_abi.inc (and httpasm.h).
;
; One mask, ha_cpu (cpu/cpu.asm), says which instructions HttpAsm may use. It is the CPU's own
; features (CPUID, and XGETBV for the register state the OS saves) narrowed by a cap: the
; HTTPASM_CPU environment variable when libhttpasm.so loads, or httpasm_cpu_limit later.
; Until something sets it, ha_cpu is 0, which selects the baseline everywhere: a program that
; links the core without libhttpasm.so's loader is always correct, only slower.
;
; Levels follow the x86-64 psABI's microarchitecture levels, so "v3" means what compilers mean:
;   v1  the baseline: any x86-64 (SSE2). Every routine has a v1 version; a routine that
;       handles secrets has a constant-time one.
;   v2  + SSE3, SSSE3, SSE4.1, SSE4.2, POPCNT, CMPXCHG16B, LAHF/SAHF.
;   v3  + AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, with the YMM state saved by the OS.
;   v4  + AVX-512 F, BW, CD, DQ and VL, with the ZMM and opmask state saved by the OS.
; Instruction groups that CPUs of one level may or may not have are bits of their own. A group
; is usable only with the level its encoding needs (ha_cpu_apply enforces it):
;   AESNI, CLMUL, SHA, GFNI  legacy SSE encodings: any level (GFNI's VEX/EVEX forms need v3/v4)
;   BMI2, ADX                scalar: counted with v3 (MULX is VEX-encoded, ADX came later)
;   VAES, VCLMUL, SHA512     VEX/EVEX encodings: v3 for YMM forms, v4 for ZMM forms
;   IFMA, VBMI, VBMI2        AVX-512 only: v4
;
; Conventions of a multi-version routine:
;   - Its entry reads ha_cpu once and jumps to one version; nothing dispatches per octet.
;   - Every version computes exactly the same results, octet for octet: the tests compare them
;     on the same inputs. Tiers are therefore interchangeable at any moment, which is what
;     makes httpasm_cpu_limit safe while other threads run.
;   - A version that writes YMM or ZMM registers ends with vzeroupper before it returns, so the
;     caller's legacy SSE code (glibc, the .NET runtime) pays no AVX-SSE transition.
;   - A version is kept only when a single-thread measurement shows it beats the tier below it.
; =============================================================================
%ifndef HTTPASM_CPU_INC
%define HTTPASM_CPU_INC

%ifndef HA_DEFINING_CPU
extern ha_cpu               ; dword: the effective HTTPASM_CPU_* bits (0 until set: the baseline)
extern ha_cpu_found         ; dword: what the CPU and the OS offer (0 until ha_cpu_detect ran)
extern ha_cpu_detect        ; () -> eax = the found bits; stores ha_cpu_found
extern ha_cpu_apply         ; (edi = cap) -> eax = ha_cpu = closure(ha_cpu_found & cap)
%endif

; -----------------------------------------------------------------------------
; HA_CPU_PICK bits, label
;   Jumps to label when every bit of bits is set in ha_cpu. The entry of a multi-version
;   routine lists its versions from the fastest down and falls through to the baseline.
;   Clobbers eax and the flags (for one bit, HA_CPU_PICK1 needs only the flags).
; -----------------------------------------------------------------------------
%macro HA_CPU_PICK 2
    mov     eax, [rel ha_cpu]
    and     eax, %1
    cmp     eax, %1
    je      %2
%endmacro

; HA_CPU_PICK1 bit, label: the same for a single bit; clobbers only the flags.
%macro HA_CPU_PICK1 2
    test    dword [rel ha_cpu], %1
    jnz     %2
%endmacro

%endif
