; =============================================================================
; abi.asm - the parts of libhttpasm.so's C ABI (include/httpasm.h) that belong to the library
; rather than to the core: its version, and the sizes of its structures.
; =============================================================================
default rel
%include "httpasm.inc"

section .text

; -----------------------------------------------------------------------------
; uint32_t httpasm_abi_version(void)
;   The ABI version of this library, HTTPASM_ABI_VERSION: 0 until the first release. A caller
;   compiled against another version must not use the library.
;   Out: eax. Clobbers nothing else.
; -----------------------------------------------------------------------------
global httpasm_abi_version:function (httpasm_abi_version.end - httpasm_abi_version)
align 16
httpasm_abi_version:
    mov     eax, HTTPASM_ABI_VERSION
    ret
.end:

; -----------------------------------------------------------------------------
; uint32_t httpasm_struct_size(uint32_t which)
;   The size the library uses for one of its structures, so a binding (the .NET tests' copies,
;   a C program's header) can check its layout matches: 1 httpasm_field, 2 httpasm_request,
;   3 httpasm_h1_limits; 0 for anything else.
;   In: edi. Out: eax. Clobbers the flags.
; -----------------------------------------------------------------------------
global httpasm_struct_size:function (httpasm_struct_size.end - httpasm_struct_size)
align 16
httpasm_struct_size:
    xor     eax, eax
    cmp     edi, 1
    jne     .request
    mov     eax, httpasm_field_size
    ret
.request:
    cmp     edi, 2
    jne     .limits
    mov     eax, httpasm_request_size
    ret
.limits:
    cmp     edi, 3
    jne     .done
    mov     eax, httpasm_h1_limits_size
.done:
    ret
.end:
