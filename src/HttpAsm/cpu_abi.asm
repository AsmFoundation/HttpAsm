; =============================================================================
; cpu_abi.asm - the CPU tiers in libhttpasm.so: choosing them when the library loads, from the
; CPU and the HTTPASM_CPU environment variable, and the C ABI that reports and narrows them
; (httpasm_cpu_found, httpasm_cpu_features, httpasm_cpu_limit). The rules are in cpu.inc, the
; bits in httpasm_abi.inc.
;
; HTTPASM_CPU is read once, when the library loads, as OpenSSL reads OPENSSL_ia32cap:
;   unset, or empty    every feature the CPU and the OS offer
;   native             the same
;   v1, v2, v3, v4     at most that level, with the groups its encodings allow
;                      (HTTPASM_CPU_CAP_V1..V4; v1 is the pure baseline)
; followed by any number of ",-group" items, each dropping one group: aesni, clmul, sha, gfni,
; bmi2, adx, vaes, vclmul, sha512, ifma, vbmi, vbmi2. Without a level, the list starts with its
; first "-group" ("-vaes,-vclmul" is native without those two). Anything else (an unknown word,
; an item without its "-", an empty item) selects v1, the baseline: a typo must never leave the
; faster code running while someone believes it is off. httpasm_cpu_features tells what was
; chosen.
; =============================================================================
default rel
%include "httpasm.inc"
%include "cpu.inc"

extern getenv

section .rodata
s_httpasm_cpu:  db "HTTPASM_CPU", 0

; The words HTTPASM_CPU may hold: each name zero-padded to 8 octets (compared as one qword),
; then its bits. A level's bits are its cap; a group's are what its "-group" item drops.
align 8
levels:
    db "native", 0, 0
    dq HTTPASM_CPU_ALL
    db "v1", 0, 0, 0, 0, 0, 0
    dq HTTPASM_CPU_CAP_V1
    db "v2", 0, 0, 0, 0, 0, 0
    dq HTTPASM_CPU_CAP_V2
    db "v3", 0, 0, 0, 0, 0, 0
    dq HTTPASM_CPU_CAP_V3
    db "v4", 0, 0, 0, 0, 0, 0
    dq HTTPASM_CPU_CAP_V4
LEVELS equ ($ - levels) / 16
groups:
    db "aesni", 0, 0, 0
    dq HTTPASM_CPU_AESNI
    db "clmul", 0, 0, 0
    dq HTTPASM_CPU_CLMUL
    db "sha", 0, 0, 0, 0, 0
    dq HTTPASM_CPU_SHA
    db "gfni", 0, 0, 0, 0
    dq HTTPASM_CPU_GFNI
    db "bmi2", 0, 0, 0, 0
    dq HTTPASM_CPU_BMI2
    db "adx", 0, 0, 0, 0, 0
    dq HTTPASM_CPU_ADX
    db "vaes", 0, 0, 0, 0
    dq HTTPASM_CPU_VAES
    db "vclmul", 0, 0
    dq HTTPASM_CPU_VCLMUL
    db "sha512", 0, 0
    dq HTTPASM_CPU_SHA512
    db "ifma", 0, 0, 0, 0
    dq HTTPASM_CPU_IFMA
    db "vbmi", 0, 0, 0, 0
    dq HTTPASM_CPU_VBMI
    db "vbmi2", 0, 0, 0
    dq HTTPASM_CPU_VBMI2
GROUPS equ ($ - groups) / 16

; The loader runs every entry of .init_array when the library loads (before any HttpAsm call
; can be made), so the tiers are chosen exactly once, with no check on any call's path.
section .init_array alloc write noexec align=8
    dq cpu_init

section .text

; -----------------------------------------------------------------------------
; cpu_init: the library's constructor. Detects the CPU and applies HTTPASM_CPU's cap.
;   Called by the dynamic loader like a C function: keeps rbx, rbp, r12-r15.
; -----------------------------------------------------------------------------
align 16
cpu_init:
    sub     rsp, 8                          ; the loader calls with rsp = 8 mod 16
    call    ha_cpu_detect
    lea     rdi, [rel s_httpasm_cpu]
    call    getenv wrt ..plt
    mov     rdi, rax                        ; NULL when unset
    call    cap_from_text
    mov     edi, eax
    call    ha_cpu_apply
    add     rsp, 8
    ret

; -----------------------------------------------------------------------------
; cap_from_text: the cap HTTPASM_CPU's text asks for (this file's header has the grammar).
;   In: rdi = the NUL-terminated text, or NULL. Out: eax = the cap (HTTPASM_CPU_ALL when the
;   text is NULL or empty, HTTPASM_CPU_CAP_V1 when it is invalid). Clobbers rcx, rdx, rsi, rdi,
;   r8, r9 and the flags.
; -----------------------------------------------------------------------------
align 16
cap_from_text:
    mov     eax, HTTPASM_CPU_ALL
    test    rdi, rdi
    jz      .done
    cmp     byte [rdi], 0
    je      .done
    cmp     byte [rdi], '-'
    je      .group                          ; no level: native, then the groups it drops
    call    take_word                       ; rdx = the level's name
    jc      .invalid
    lea     rsi, [rel levels]
    mov     ecx, LEVELS
    call    find_word                       ; r8 = its bits
    jc      .invalid
    mov     eax, r8d
.next:
    cmp     byte [rdi], 0
    je      .done
    inc     rdi                             ; past the "," take_word stopped at
.group:
    cmp     byte [rdi], '-'
    jne     .invalid                        ; every item after the level drops a group
    inc     rdi
    call    take_word
    jc      .invalid
    lea     rsi, [rel groups]
    mov     ecx, GROUPS
    call    find_word
    jc      .invalid
    not     r8d
    and     eax, r8d
    jmp     .next
.invalid:
    mov     eax, HTTPASM_CPU_CAP_V1
.done:
    ret

; -----------------------------------------------------------------------------
; take_word: the word at rdi, up to the next "," or the end, as a qword zero-padded to 8 octets.
;   In: rdi. Out: rdx = the word; rdi = the "," or the NUL after it; CF set when the word is
;   empty or longer than 8 octets (no valid word is). Clobbers rcx, r9.
; -----------------------------------------------------------------------------
take_word:
    xor     edx, edx
    xor     ecx, ecx                        ; bits filled so far
.octet:
    movzx   r9d, byte [rdi]
    test    r9d, r9d
    jz      .end
    cmp     r9d, ','
    je      .end
    cmp     ecx, 64
    jae     .bad                            ; a ninth octet: longer than any word
    shl     r9, cl
    or      rdx, r9
    add     ecx, 8
    inc     rdi
    jmp     .octet
.end:
    test    ecx, ecx
    jz      .bad                            ; an empty item
    clc
    ret
.bad:
    stc
    ret

; -----------------------------------------------------------------------------
; find_word: the bits of the word rdx in a table of ecx 16-octet entries at rsi.
;   Out: r8 = the bits, CF clear; CF set when the word is not in the table. Clobbers rcx, rsi.
; -----------------------------------------------------------------------------
find_word:
    cmp     rdx, [rsi]
    je      .found
    add     rsi, 16
    dec     ecx
    jnz     find_word
    stc
    ret
.found:
    mov     r8, [rsi + 8]
    clc
    ret

; -----------------------------------------------------------------------------
; uint64_t httpasm_cpu_found(void)
;   What the CPU and the OS offer: HTTPASM_CPU_* bits, read when the library loaded. A level
;   counts only when the OS saves the registers it needs.
;   Out: rax. Clobbers nothing else.
; -----------------------------------------------------------------------------
global httpasm_cpu_found:function (httpasm_cpu_found.end - httpasm_cpu_found)
align 16
httpasm_cpu_found:
    mov     eax, [rel ha_cpu_found]         ; the 32-bit load zero-extends into rax
    ret
.end:

; -----------------------------------------------------------------------------
; uint64_t httpasm_cpu_features(void)
;   What HttpAsm uses: httpasm_cpu_found narrowed by HTTPASM_CPU or httpasm_cpu_limit, and
;   closed over the levels each group needs.
;   Out: rax. Clobbers nothing else.
; -----------------------------------------------------------------------------
global httpasm_cpu_features:function (httpasm_cpu_features.end - httpasm_cpu_features)
align 16
httpasm_cpu_features:
    mov     eax, [rel ha_cpu]
    ret
.end:

; -----------------------------------------------------------------------------
; uint64_t httpasm_cpu_limit(uint64_t cap)
;   Sets what HttpAsm uses to httpasm_cpu_found & cap, closed over the levels each group needs,
;   and returns it: HTTPASM_CPU_CAP_V1 forces the baseline everywhere, HTTPASM_CPU_ALL restores
;   everything the CPU has. For tests and measurements that compare tiers in one process; it
;   replaces HTTPASM_CPU's cap. Safe while other threads run HttpAsm code: every tier computes
;   the same results (cpu.inc), so a call in flight finishes on the version it started with.
;   In: rdi = cap (bits above HTTPASM_CPU_ALL are ignored). Out: rax. Clobbers the flags.
; -----------------------------------------------------------------------------
global httpasm_cpu_limit:function (httpasm_cpu_limit.end - httpasm_cpu_limit)
align 16
httpasm_cpu_limit:
    jmp     ha_cpu_apply                    ; edi: no bit is above 31 yet
.end:
