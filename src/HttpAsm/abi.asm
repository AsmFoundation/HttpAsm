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
;   3 httpasm_h1_limits, 4 httpasm_response, 5 httpasm_response_head, 6 httpasm_h1_chunked,
;   7 httpasm_server_options, 8 httpasm_hpack_output, 9 httpasm_client_response; 0 for anything
;   else.
;   In: edi. Out: eax. Clobbers rcx and the flags.
; -----------------------------------------------------------------------------
section .rodata
align 4
struct_sizes:
    dd 0
    dd httpasm_field_size
    dd httpasm_request_size
    dd httpasm_h1_limits_size
    dd httpasm_response_size
    dd httpasm_response_head_size
    dd httpasm_h1_chunked_size
    dd httpasm_server_options_size
    dd httpasm_hpack_output_size
    dd httpasm_client_response_size
STRUCT_SIZES equ ($ - struct_sizes) / 4

section .text
global httpasm_struct_size:function (httpasm_struct_size.end - httpasm_struct_size)
align 16
httpasm_struct_size:
    xor     eax, eax
    cmp     edi, STRUCT_SIZES
    jae     .done
    lea     rcx, [rel struct_sizes]
    mov     eax, [rcx + rdi * 4]            ; edi is the zero-extended uint32_t
.done:
    ret
.end:
