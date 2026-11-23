; =============================================================================
; abi.asm - the parts of libhttpasm.so's C ABI (include/httpasm.h) that belong to the library
; rather than to the core: its version.
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
