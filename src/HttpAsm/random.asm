; =============================================================================
; random.asm - the C ABI's httpasm_random: octets from the kernel's random number generator,
; for TLS's randoms, ephemeral keys and ticket keys: getrandom(2) with no flags (the urandom
; source, which blocks only until the kernel's pool is first initialized at boot, then never).
;
; getrandom can return fewer octets than asked (a request over 32 MiB - 1, or a signal arriving
; once some were copied) or -EINTR (a signal before any): the rest is asked for again until the
; buffer is full. A kernel or a seccomp filter that refuses the call (ENOSYS, EPERM) fails it
; with that error: no weaker source is substituted, since /dev/urandom would need a descriptor
; the same sandbox may refuse, and hiding the refusal would be worse. A filter answering "error
; 0" makes getrandom return 0 octets, forever: that is -EIO, not a spin.
; =============================================================================
default rel
%include "httpasm.inc"
%include "internal/driver.inc"

SYS_getrandom   equ 318
EIO             equ 5

section .text

; -----------------------------------------------------------------------------
; int httpasm_random(void *buffer, size_t length)
;   Fills buffer[0..length) with random octets (length 0 does nothing). Returns 0, or -errno
;   when the kernel refused (-ENOSYS: no getrandom; -EPERM: a seccomp filter; -EFAULT: a bad
;   buffer; -EIO: a filter that answers with no octets and no error): the buffer is then
;   partly filled at most and must not be used.
; -----------------------------------------------------------------------------
global httpasm_random:function (httpasm_random.end - httpasm_random)
align 16
httpasm_random:
    mov     r8, rdi                         ; the next octet to fill (syscall keeps r8, r9)
    mov     r9, rsi                         ; octets left
.more:
    test    r9, r9
    jz      .full
    mov     rdi, r8
    mov     rsi, r9
    xor     edx, edx                        ; flags: none (the urandom source)
    mov     eax, SYS_getrandom
    syscall
    test    rax, rax
    js      .refused
    jz      .nothing
    add     r8, rax
    sub     r9, rax
    jmp     .more
.refused:
    cmp     rax, -EINTR
    je      .more                           ; a signal came before any octet: ask again
    ret                                     ; -errno
.nothing:
    mov     eax, -EIO
    ret
.full:
    xor     eax, eax
    ret
.end:
