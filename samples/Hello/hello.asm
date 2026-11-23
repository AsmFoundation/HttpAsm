; =============================================================================
; hello.asm - the Hello sample: an HttpAsm server answering "Hello, World!" to every request,
; over HTTP/1.1 and HTTP/2 alike (see Hello.asmproj for its settings).
;
; Startup, in this order:
;   1. settings from the environment, parsed strictly (decimal digits only, no sign, no
;      whitespace, no overflow, range-checked): an invalid value is reported with its name and
;      the process exits 2, because a typo must never fall back to a default;
;   2. SIGINT and SIGTERM blocked, before any worker exists: the workers inherit the mask, so
;      the signals reach only this thread's rt_sigtimedwait, never a worker mid-request;
;   3. httpasm_server_create and _start (exit 1 with the -errno if either fails), then
;      "hello: listening on port N" on stdout (scripts wait for that line);
;   4. wait for SIGINT or SIGTERM; httpasm_server_destroy stops gracefully (in-flight requests
;      finish) and frees everything; exit 0.
; =============================================================================
default rel
%include "httpasm.inc"

extern getenv

SYS_write           equ 1
SYS_rt_sigprocmask  equ 14
SYS_rt_sigtimedwait equ 128
SIG_BLOCK           equ 0
SIGNALS             equ (1 << (2 - 1)) | (1 << (15 - 1))   ; SIGINT, SIGTERM
EINTR               equ 4

section .rodata
s_port:         db "HELLO_PORT", 0
s_workers:      db "HELLO_WORKERS", 0
s_body:         db "Hello, World!"
s_body_len      equ $ - s_body
s_type_name:    db "Content-Type"
s_type_value:   db "text/plain"
s_listening:    db "hello: listening on port "
s_listening_len equ $ - s_listening
s_invalid:      db "hello: invalid value for "
s_invalid_len   equ $ - s_invalid
s_failed:       db "hello: the server could not start (errno "
s_failed_len    equ $ - s_failed

section .bss
alignb 8
fields:         resb httpasm_field_size        ; Content-Type: text/plain, filled by main
options:        resb httpasm_server_options_size

section .text

; -----------------------------------------------------------------------------
; handler: every request is answered 200 "Hello, World!" (text/plain), at once.
;   In: rdi = context (unused), rsi = exchange. The answer cannot be refused (its one field is
;   valid), so the result is not checked.
; -----------------------------------------------------------------------------
align 16
handler:
    sub     rsp, 8                          ; aligned for the call
    mov     rdi, rsi
    mov     esi, 200
    lea     rdx, [rel fields]
    mov     ecx, 1
    lea     r8, [rel s_body]
    mov     r9d, s_body_len
    call    httpasm_exchange_respond wrt ..plt
    add     rsp, 8
    ret

; -----------------------------------------------------------------------------
; setting: a numeric setting from the environment.
;   In: rdi = the variable's name (NUL-terminated), esi = its default, edx = the least valid
;   value, ecx = the most. Out: eax = the value; the process exits 2 (after naming the
;   variable) when it is set but not 1*DIGIT within the range.
; -----------------------------------------------------------------------------
align 16
setting:
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, 8                          ; four pushes + 8: aligned
    mov     rbx, rdi
    mov     r12d, esi
    mov     r13d, edx
    mov     r14d, ecx
    call    getenv wrt ..plt
    test    rax, rax
    jz      .default
    xor     ecx, ecx                        ; the value
    xor     edx, edx                        ; digits seen
.digit:
    movzx   esi, byte [rax + rdx]
    test    esi, esi
    jz      .end
    sub     esi, '0'
    cmp     esi, 9
    ja      .invalid
    imul    ecx, ecx, 10
    add     ecx, esi
    cmp     ecx, r14d
    ja      .invalid                        ; past the range already: no overflow possible
    inc     edx
    cmp     edx, 10
    ja      .invalid
    jmp     .digit
.end:
    test    edx, edx
    jz      .invalid                        ; set but empty
    cmp     ecx, r13d
    jb      .invalid
    mov     eax, ecx
    jmp     .out
.default:
    mov     eax, r12d
.out:
    add     rsp, 8
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.invalid:
    mov     edi, 2
    lea     rsi, [rel s_invalid]
    mov     edx, s_invalid_len
    mov     eax, SYS_write
    syscall
    mov     rsi, rbx                        ; the variable's name, then a new line
    xor     edx, edx
.name_length:
    cmp     byte [rsi + rdx], 0
    je      .name_known
    inc     edx
    jmp     .name_length
.name_known:
    mov     edi, 2
    mov     eax, SYS_write
    syscall
    call    newline_stderr
    mov     edi, 2
    jmp     exit_process

; newline_stderr: one "\n" on stderr. Clobbers rax, rcx, rdx, rsi, rdi, r11.
newline_stderr:
    push    10
    mov     edi, 2
    mov     rsi, rsp
    mov     edx, 1
    mov     eax, SYS_write
    syscall
    add     rsp, 8
    ret

; exit_process: exits the whole process (every thread) with edi.
exit_process:
    mov     eax, 231                        ; exit_group
    syscall
    ud2

; -----------------------------------------------------------------------------
; write_number: the decimal digits of eax, then "\n", on file descriptor edi.
;   Clobbers rax, rcx, rdx, rsi, r8, r11.
; -----------------------------------------------------------------------------
write_number:
    sub     rsp, 40
    lea     rsi, [rsp + 32]
    mov     byte [rsi], 10
    mov     r8d, edi
    mov     ecx, 10
.digit:
    xor     edx, edx
    div     ecx
    add     dl, '0'
    dec     rsi
    mov     [rsi], dl
    test    eax, eax
    jnz     .digit
    lea     rdx, [rsp + 33]
    sub     rdx, rsi
    mov     edi, r8d
    mov     eax, SYS_write
    syscall
    add     rsp, 40
    ret

; -----------------------------------------------------------------------------
; main: see this file's header. Out: eax = 0 after a graceful stop; 1 when the server could
; not start; 2 for an invalid setting (setting exits itself).
; -----------------------------------------------------------------------------
global main
align 16
main:
    push    rbx
    push    r12
    sub     rsp, 152                        ; siginfo (128) + error + mask; two pushes + 152: aligned
    ; Settings.
    lea     rdi, [rel s_port]
    mov     esi, 8080
    mov     edx, 1
    mov     ecx, 65535
    call    setting
    mov     ebx, eax                        ; the port
    lea     rdi, [rel s_workers]
    xor     esi, esi                        ; 0: the library's default, one per CPU
    mov     edx, 1
    mov     ecx, 1024
    call    setting
    mov     r12d, eax                       ; the workers

    ; The answer's field, with addresses only known now (no relocations in data).
    lea     rax, [rel s_type_name]
    mov     [fields + httpasm_field.name], rax
    lea     rax, [rel s_type_value]
    mov     [fields + httpasm_field.value], rax
    mov     dword [fields + httpasm_field.name_length], 12
    mov     dword [fields + httpasm_field.value_length], 10

    ; SIGINT and SIGTERM blocked before any worker exists (they inherit this mask).
    mov     qword [rsp + 144], SIGNALS
    mov     edi, SIG_BLOCK
    lea     rsi, [rsp + 144]
    xor     edx, edx
    mov     r10d, 8
    mov     eax, SYS_rt_sigprocmask
    syscall

    ; The server: every address (0.0.0.0), the port, the workers; the rest default.
    lea     rax, [rel handler]
    mov     [options + httpasm_server_options.handler], rax
    mov     [options + httpasm_server_options.workers], r12d
    mov     [options + httpasm_server_options.port], bx
    lea     rdi, [rel options]
    lea     rsi, [rsp + 136]
    call    httpasm_server_create wrt ..plt
    test    rax, rax
    jz      .failed_create
    mov     r12, rax
    mov     rdi, r12
    call    httpasm_server_start wrt ..plt
    test    eax, eax
    jnz     .failed_start

    mov     edi, 1
    lea     rsi, [rel s_listening]
    mov     edx, s_listening_len
    mov     eax, SYS_write
    syscall
    mov     rdi, r12
    call    httpasm_server_port wrt ..plt
    movzx   eax, ax
    mov     edi, 1
    call    write_number

    ; Wait for SIGINT or SIGTERM (an interrupted wait just waits again).
.wait:
    lea     rdi, [rsp + 144]                ; the set
    mov     rsi, rsp                        ; siginfo
    xor     edx, edx                        ; no timeout
    mov     r10d, 8
    mov     eax, SYS_rt_sigtimedwait
    syscall
    cmp     rax, -EINTR
    je      .wait
    mov     rdi, r12
    call    httpasm_server_destroy wrt ..plt
    xor     eax, eax
    jmp     .out

.failed_start:
    neg     eax
    mov     ebx, eax
    mov     rdi, r12
    call    httpasm_server_destroy wrt ..plt
    jmp     .report
.failed_create:
    mov     ebx, [rsp + 136]
    neg     ebx
.report:
    mov     edi, 2
    lea     rsi, [rel s_failed]
    mov     edx, s_failed_len
    mov     eax, SYS_write
    syscall
    mov     eax, ebx
    mov     edi, 2
    call    write_number
    mov     eax, 1
.out:
    add     rsp, 152
    pop     r12
    pop     rbx
    ret
