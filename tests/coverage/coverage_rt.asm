; =============================================================================
; coverage_rt.asm - the coverage build's runtime: when the process exits, it writes the marker
; octets every instrumented object reserved (tests/coverage/instrument.cs) to a file, for
; tests/coverage/report.cs to read. Linked into libhttpasm.so only in the Coverage configuration
; (tests/coverage/Coverage.props); never part of a released library.
;
; The linker gathers every object's "ha_cov" section into one, and defines __start_ha_cov and
; __stop_ha_cov around it (ELF linkers do that for a section whose name is a C identifier). The
; whole range is written as it is: each object's region starts with its own header, which the
; report reads.
;
; Where: the directory HTTPASM_COVERAGE_DIR names, one file per process,
; cov-<pid>-<tsc>.bin (the time-stamp counter keeps two processes that reuse a pid apart). No
; variable, no file: an instrumented library outside a coverage run writes nothing.
; =============================================================================
default rel

extern __start_ha_cov
extern __stop_ha_cov
extern getenv
extern getpid
extern snprintf
extern open
extern write
extern close

O_WRONLY_CREAT_TRUNC equ 0o1 | 0o100 | 0o1000

section .rodata
s_variable:     db "HTTPASM_COVERAGE_DIR", 0
s_pattern:      db "%s/cov-%d-%llx.bin", 0

; Run by the loader's exit processing (_dl_fini), after main returns or exit is called.
section .fini_array alloc write noexec align=8
    dq coverage_dump

section .text

; -----------------------------------------------------------------------------
; coverage_dump: writes [__start_ha_cov, __stop_ha_cov) to HTTPASM_COVERAGE_DIR's file.
;   Called like a C function at exit; keeps rbx, rbp, r12-r15. A short write is retried until
;   everything is out or write fails; a failure loses this process's markers (the report then
;   shows its blocks as not run, the safe side: it can only hide coverage, never invent it).
; -----------------------------------------------------------------------------
align 16
coverage_dump:
    push    rbx
    push    r12
    push    r13
    sub     rsp, 4096 + 16                  ; the path; three pushes + 4112: aligned
    lea     rdi, [rel s_variable]
    call    getenv wrt ..plt
    test    rax, rax
    jz      .out                            ; not a coverage run
    mov     rbx, rax                        ; the directory
    call    getpid wrt ..plt
    mov     r12d, eax
    ; snprintf(path, 4096, "%s/cov-%d-%llx.bin", directory, pid, counter). RDTSC writes edx,
    ; so the counter is formed before rdx takes the pattern.
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r9, rax                         ; %llx: the time-stamp counter
    mov     r8d, r12d                       ; %d: the pid
    mov     rcx, rbx                        ; %s: the directory
    lea     rdx, [rel s_pattern]
    mov     esi, 4096
    mov     rdi, rsp
    xor     eax, eax                        ; a variadic call: no vector registers
    call    snprintf wrt ..plt
    mov     rdi, rsp
    mov     esi, O_WRONLY_CREAT_TRUNC
    mov     edx, 0o644
    xor     eax, eax
    call    open wrt ..plt
    test    eax, eax
    js      .out
    mov     r12d, eax                       ; the descriptor
    lea     rbx, [rel __start_ha_cov]
    lea     r13, [rel __stop_ha_cov]
.write:
    cmp     rbx, r13
    jae     .close
    mov     edi, r12d
    mov     rsi, rbx
    mov     rdx, r13
    sub     rdx, rbx
    call    write wrt ..plt
    test    rax, rax
    jle     .close                          ; an error: give up (see above)
    add     rbx, rax
    jmp     .write
.close:
    mov     edi, r12d
    call    close wrt ..plt
.out:
    add     rsp, 4096 + 16
    pop     r13
    pop     r12
    pop     rbx
    ret
