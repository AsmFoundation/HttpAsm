; =============================================================================
; date.asm - the Date field's value: an IMF-fixdate (RFC 9110 5.6.7), "Sun, 06 Nov 1994
; 08:49:37 GMT", always 29 octets.
;
; Computed here rather than with strftime: strftime's day and month names follow the process's
; locale, and a host (a .NET program, Python) may have set one. RFC 9110 requires the English
; names, case-sensitive. A worker formats the date once per second of realtime and reuses it in
; every response of that second (RFC9110-6.6.1-5: the best available approximation).
; =============================================================================
default rel
%include "httpasm.inc"
%include "internal/driver.inc"

section .rodata
day_names:      db "SunMonTueWedThuFriSat"
month_names:    db "JanFebMarAprMayJunJulAugSepOctNovDec"

section .text

; -----------------------------------------------------------------------------
; two_digits: rdi[0..2) = eax as two decimal digits (eax < 100). Clobbers eax, edx, ecx.
; -----------------------------------------------------------------------------
align 16
two_digits:
    xor     edx, edx
    mov     ecx, 10
    div     ecx
    add     al, '0'
    add     dl, '0'
    mov     [rdi], al
    mov     [rdi + 1], dl
    ret

; -----------------------------------------------------------------------------
; ha_date_format: the current IMF-fixdate.
;   In:  rdi = a buffer of at least 29 octets.
;   Out: the buffer holds the date (no NUL); rax = the realtime second it stands for.
;   Clobbers rcx, rdx, rsi, rdi, r8-r11, xmm registers (clock_gettime's), the flags.
;   Keeps rbx, rbp, r12-r15.
;   The calendar is Howard Hinnant's days_from_civil inverse, exact for every date from 1970
;   on (the realtime clock's range here).
; -----------------------------------------------------------------------------
global ha_date_format:function hidden (ha_date_format.end - ha_date_format)
align 16
ha_date_format:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 16                         ; struct timespec; 5 pushes + 16 keep rsp aligned
    mov     rbx, rdi
    mov     edi, CLOCK_REALTIME_COARSE
    mov     rsi, rsp
    call    clock_gettime wrt ..plt
    mov     r12, [rsp]                      ; seconds since the epoch
    mov     rax, r12
    xor     edx, edx
    mov     ecx, 86400
    div     rcx                             ; rax = days, rdx = the second of the day
    mov     r13, rax                        ; days
    mov     r14, rdx                        ; second of the day

    ; The weekday: 1970-01-01 was a Thursday (4, counting Sunday as 0).
    lea     rax, [r13 + 4]
    xor     edx, edx
    mov     ecx, 7
    div     rcx
    lea     rsi, [rel day_names]
    lea     rdx, [rdx + rdx * 2]
    mov     ax, [rsi + rdx]
    mov     [rbx], ax
    mov     al, [rsi + rdx + 2]
    mov     [rbx + 2], al
    mov     word [rbx + 3], ', '

    ; days -> year, month, day (civil_from_days).
    lea     r8, [r13 + 719468]              ; z
    mov     rax, r8
    xor     edx, edx
    mov     ecx, 146097
    div     rcx                             ; rax = era
    mov     r9, rax                         ; era
    imul    rax, rax, 146097
    mov     r10, r8
    sub     r10, rax                        ; doe = z - era * 146097, in [0, 146096]
    ; yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365
    mov     rax, r10
    xor     edx, edx
    mov     ecx, 1460
    div     rcx
    mov     r11, r10
    sub     r11, rax
    mov     rax, r10
    xor     edx, edx
    mov     ecx, 36524
    div     rcx
    add     r11, rax
    mov     rax, r10
    xor     edx, edx
    mov     ecx, 146096
    div     rcx
    sub     r11, rax
    mov     rax, r11
    xor     edx, edx
    mov     ecx, 365
    div     rcx
    mov     r11, rax                        ; yoe
    ; y = yoe + era * 400
    imul    r15, r9, 400
    add     r15, r11                        ; y
    ; doy = doe - (365 * yoe + yoe/4 - yoe/100)
    imul    rcx, r11, 365
    mov     rax, r11
    shr     rax, 2
    add     rcx, rax
    mov     rax, r11
    xor     edx, edx
    mov     r8d, 100
    div     r8
    sub     rcx, rax
    mov     r9, r10
    sub     r9, rcx                         ; doy
    ; mp = (5 * doy + 2) / 153
    lea     rax, [r9 + r9 * 4 + 2]
    xor     edx, edx
    mov     ecx, 153
    div     rcx
    mov     r10, rax                        ; mp, in [0, 11]
    ; d = doy - (153 * mp + 2) / 5 + 1
    imul    rax, r10, 153
    add     rax, 2
    xor     edx, edx
    mov     ecx, 5
    div     rcx
    mov     r11, r9
    sub     r11, rax
    inc     r11                             ; d, in [1, 31]
    ; m = mp < 10 ? mp + 3 : mp - 9; the year starts in March here, so January and February
    ; belong to the next civil year.
    cmp     r10, 10
    jb      .spring
    sub     r10, 9
    inc     r15
    jmp     .month_set
.spring:
    add     r10, 3
.month_set:

    ; "Www, DD Mmm YYYY HH:MM:SS GMT"
    lea     rdi, [rbx + 5]
    mov     eax, r11d
    call    two_digits
    mov     byte [rbx + 7], ' '
    lea     rsi, [rel month_names]
    lea     rdx, [r10 - 1]
    lea     rdx, [rdx + rdx * 2]
    mov     ax, [rsi + rdx]
    mov     [rbx + 8], ax
    mov     al, [rsi + rdx + 2]
    mov     [rbx + 10], al
    mov     byte [rbx + 11], ' '
    mov     rax, r15                        ; the year, four digits until 9999
    xor     edx, edx
    mov     ecx, 100
    div     rcx
    mov     r15, rdx                        ; the last two digits
    lea     rdi, [rbx + 12]
    call    two_digits
    lea     rdi, [rbx + 14]
    mov     eax, r15d
    call    two_digits
    mov     byte [rbx + 16], ' '
    mov     rax, r14                        ; HH:MM:SS
    xor     edx, edx
    mov     ecx, 3600
    div     rcx
    mov     r15, rdx
    lea     rdi, [rbx + 17]
    call    two_digits
    mov     byte [rbx + 19], ':'
    mov     rax, r15
    xor     edx, edx
    mov     ecx, 60
    div     rcx
    mov     r15, rdx
    lea     rdi, [rbx + 20]
    call    two_digits
    mov     byte [rbx + 22], ':'
    lea     rdi, [rbx + 23]
    mov     eax, r15d
    call    two_digits
    mov     dword [rbx + 25], ' GMT'
    mov     rax, r12
    add     rsp, 16
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.end:
