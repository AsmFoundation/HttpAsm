; =============================================================================
; semantics/fields.asm - the field rules (semantics/fields.inc) as functions of the C ABI.
;
; The parsers assemble the same macros inline. These standalone copies serve the C ABI's
; callers (include/httpasm.h): a .NET adapter can check a header value set by user code
; before sending it, as Kestrel does. The tests also use them to prove the rules octet by
; octet.
; =============================================================================
default rel
%include "httpasm_core.inc"

section .text

; -----------------------------------------------------------------------------
; size_t httpasm_token_length(const uint8_t *p, size_t n)
;   The number of leading octets of p[0..n) that are tchar (RFC9110-5.6.2-2), n when all are.
;   p holds a token (a method, a field name: RFC9110-5.1-2) when n > 0 and the result is n.
;   In: rdi = p, rsi = n. Out: rax. Clobbers rcx, rdx, xmm0-xmm6 and the flags.
;   Memory: as ha_token_length (it is that routine, exported).
; -----------------------------------------------------------------------------
global httpasm_token_length:function (httpasm_token_length.end - httpasm_token_length)
align 16
httpasm_token_length:
    jmp     ha_token_length
.end:

; -----------------------------------------------------------------------------
; ha_token_length: the number of leading octets of rdi[0..rsi) that are tchar, rsi when all are
; (httpasm_token_length's contract; the core's writers and lookups call it to check a whole
; name, where a token inside a value keeps HA_TOKEN_SCAN inline).
;   In: rdi = p, rsi = n; both kept. Out: rax. Clobbers rcx, rdx, xmm0-xmm6 and the flags.
;   Memory: v1 reads p[0..result] at most. v2 reads 16 octets a step inside p[0..n) (the last
;   step overlaps the one before); a token shorter than 16 octets is read as 16 octets within
;   the 4 KiB page of its first octet (from p, or ending at p + n when p is within 16 octets of
;   its page's end), which can never fault; lanes outside p[0..n) are ignored.
;
;   Two versions, the same index for every input (HA_CPU_PICK1 at the entry):
;     v1  HA_TOKEN_SCAN, one class-table lookup per octet (5 instructions an octet);
;     v2  HA_NIBBLE_CLASSIFY with ha_tchar_lo/_hi, 16 octets a step.
; -----------------------------------------------------------------------------
global ha_token_length:function hidden (ha_token_length.end - ha_token_length)
align 16
ha_token_length:
    HA_CPU_PICK1 HTTPASM_CPU_V2, .v2
    HA_TOKEN_SCAN rdi, rsi, rax, rcx, rdx
    ret
.v2:
    xor     eax, eax
    test    rsi, rsi
    jz      .out                            ; nothing to read
    movdqa  xmm3, [rel ha_tchar_lo]
    movdqa  xmm4, [rel ha_tchar_hi]
    movdqa  xmm5, [rel ha_x16_0f]
    pxor    xmm2, xmm2
    cmp     rsi, 16
    jb      .short
.step:                                      ; rax + 16 <= rsi: a whole step inside p[0..n)
    movdqu  xmm0, [rdi + rax]
    HA_NIBBLE_CLASSIFY xmm0, xmm1, xmm6, xmm3, xmm4, xmm5, xmm2, ecx
    test    ecx, ecx
    jnz     .found
    add     rax, 16
    lea     rdx, [rax + 16]
    cmp     rdx, rsi
    jbe     .step
    cmp     rax, rsi
    je      .out                            ; n was a multiple of 16: every octet a tchar
    ; 1-15 octets left: the last 16 of p[0..n), overlapping the step before, whose octets are
    ; known tchars; its lanes below rax are shifted out of the mask.
    mov     rdx, rsi
    sub     rdx, 16                         ; where it starts
    movdqu  xmm0, [rdi + rdx]
    mov     ecx, eax
    sub     ecx, edx                        ; the lanes already known (1-15)
    HA_NIBBLE_CLASSIFY xmm0, xmm1, xmm6, xmm3, xmm4, xmm5, xmm2, edx
    shr     edx, cl                         ; lane 0 is octet rax now
    test    edx, edx
    jz      .all                            ; the rest are tchars too
    bsf     edx, edx
    add     rax, rdx
    ret
.found:
    bsf     ecx, ecx
    add     rax, rcx
.out:
    ret
.all:
    mov     rax, rsi
    ret
.short:                                     ; 1-15 octets
    mov     ecx, edi
    and     ecx, 4095
    cmp     ecx, 4096 - 16
    ja      .short_page_end
    movdqu  xmm0, [rdi]                     ; within p's page
    HA_NIBBLE_CLASSIFY xmm0, xmm1, xmm6, xmm3, xmm4, xmm5, xmm2, edx
    mov     ecx, esi
    mov     eax, 1
    shl     eax, cl
    or      edx, eax                        ; lane n stops the scan: the answer is at most n
    bsf     eax, edx
    ret
.short_page_end:                            ; the 16 octets ending at p + n: within p's page
    movdqu  xmm0, [rdi + rsi - 16]
    HA_NIBBLE_CLASSIFY xmm0, xmm1, xmm6, xmm3, xmm4, xmm5, xmm2, edx
    mov     ecx, 16
    sub     ecx, esi
    shr     edx, cl                         ; lane 0 is p's first octet now
    mov     ecx, esi
    mov     eax, 1
    shl     eax, cl
    or      edx, eax                        ; lane n stops the scan
    bsf     eax, edx
    ret
.end:

; -----------------------------------------------------------------------------
; size_t httpasm_field_value_scan(const uint8_t *p, size_t n)
;   The index of the first octet of p[0..n) that a field value may not hold, n when there is
;   none. The forbidden octets are the CTLs other than HTAB: 0x00-0x08, 0x0A-0x1F and 0x7F
;   (RFC9110-5.5-2, RFC9110-5.5-5#1, RFC9110-5.5-5#2, RFC9113-8.2.1-3.3). Whitespace at the
;   value's ends is not checked here: each version has its own rule for it.
;   In: rdi = p, rsi = n. Out: rax. Clobbers rcx, rdx, vector registers 0-5 (YMM/ZMM upper
;   halves included), k1-k3 and the flags.
;   Versions (cpu.inc): v4 (AVX-512 BW, 64 octets per step, masked tail), v3 (AVX2, 32 octets
;   per step), v1 (SSE2, 16 octets per step). Each returns the same index for every input.
;   Values under 32 octets take the v1 version at every tier, before ha_cpu is even read: there
;   the wider versions only add work (2026-11-26, benchmarks/README.md: on a Xeon 6975P-C, 8
;   octets took 1.54 ns in v1, 1.67 in v3 and 1.81 in v4 when each tier dispatched first).
;   Memory: see HA_FIELD_VALUE_SCAN. It never reads outside p[0..n), except that the v1 and v3
;   versions may read a short value as 16 octets that lie in the same 4 KiB page as p, which
;   cannot fault.
; -----------------------------------------------------------------------------
global httpasm_field_value_scan:function (httpasm_field_value_scan.end - httpasm_field_value_scan)
align 16
httpasm_field_value_scan:
    cmp     rsi, 32
    jb      .v1                             ; short: the 16-octet version, whatever the tier
    HA_CPU_PICK1 HTTPASM_CPU_V4, .v4
    HA_CPU_PICK1 HTTPASM_CPU_V3, .v3
.v1:
    HA_FIELD_VALUE_SCAN rdi, rsi, rax, rcx, ecx, rdx, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5
    ret
.v3:                                        ; rsi >= 32, as HA_FIELD_VALUE_SCAN_V3 requires
    HA_FIELD_VALUE_SCAN_V3 rdi, rsi, rax, rcx, ecx, rdx, ymm0, ymm1, ymm2, ymm3, ymm4, ymm5
    vzeroupper
    ret
.v4:
    HA_FIELD_VALUE_SCAN_V4 rdi, rsi, rax, rcx, rdx, zmm0, zmm1, zmm2, zmm3, k1, k2, k3
    vzeroupper
    ret
.end:
