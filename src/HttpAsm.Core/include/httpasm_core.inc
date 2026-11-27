; =============================================================================
; httpasm_core.inc - the core's constants and internal symbols, for every source of the core
; and of libhttpasm.so.
;
; Conventions of all HttpAsm code (Linux x64 only, the owner's choice of 2026-11-23):
;   - System V AMD64: arguments in rdi, rsi, rdx, rcx, r8, r9; rbx, rbp and r12-r15 are kept
;     across calls; xmm0-xmm15 are not.
;   - Internal symbols start with ha_ and are hidden: they link between the core's objects but
;     are exported from no image. The C ABI's symbols start with httpasm_ and are exported
;     through src/HttpAsm/httpasm.map.
;   - SSE2 is the floor (v1, any x86-64). Faster versions (v2: SSSE3/SSE4.2; v3: AVX2; v4:
;     AVX-512; the AES, carry-less multiply and SHA instructions) are chosen at run time from
;     ha_cpu, and each is kept only when a single-thread measurement shows it pays: cpu.inc.
;   - Comments name the requirement rows they implement (specs/requirements.tsv): a row id such
;     as RFC9110-5.5-5#1 leads to the RFC Editor's paragraph of the same anchor.
; =============================================================================
%ifndef HTTPASM_CORE_INC
%define HTTPASM_CORE_INC

; -----------------------------------------------------------------------------
; Character classes: bits of the 256-byte table ha_char_class (semantics/tables.asm), one byte
; per octet value. A byte is in a class when its bit is set.
; -----------------------------------------------------------------------------
HA_CC_TCHAR     equ 0x01    ; RFC 9110 5.6.2 tchar: a token's characters (RFC9110-5.6.2-2)
HA_CC_VCHAR     equ 0x02    ; RFC 5234 B.1 VCHAR, visible US-ASCII: 0x21-0x7E
HA_CC_OBS       equ 0x04    ; RFC 9110 5.5 obs-text: 0x80-0xFF (RFC9110-5.5-2)
HA_CC_WS        equ 0x08    ; SP or HTAB, the whitespace of OWS, RWS and BWS (RFC 9110 5.6.3)
HA_CC_DIGIT     equ 0x10    ; RFC 5234 B.1 DIGIT: 0-9
HA_CC_ALPHA     equ 0x20    ; RFC 5234 B.1 ALPHA: A-Z and a-z
HA_CC_UPPER     equ 0x40    ; A-Z: forbidden in HTTP/2 and HTTP/3 field names (RFC9113-8.2.1-3.1)
HA_CC_TARGET    equ 0x80    ; an octet a request-target may hold as is (RFC 3986): unreserved,
                            ; sub-delims, ":", "@", "/", "?", "%" (checked as pct-encoded by the
                            ; parser), and "[" "]" for IP literals. Everything else must be
                            ; percent-encoded: SP, CTLs, DQUOTE, "#<>\^`{|}", DEL, 0x80-0xFF.

; The octets a field value may hold, as HttpAsm reads RFC 9110 section 5.5: field-vchar
; (VCHAR / obs-text), SP and HTAB. Every other octet is a CTL (0x00-0x08, 0x0A-0x1F, 0x7F).
; CR, LF and NUL must be rejected or replaced (RFC9110-5.5-5#1); the other CTLs are invalid too,
; and HttpAsm rejects them rather than retain them, which RFC9110-5.5-5#2 permits.
HA_CC_VALUE     equ HA_CC_VCHAR | HA_CC_OBS | HA_CC_WS

; -----------------------------------------------------------------------------
; Internal data (semantics/tables.asm). The file that defines them sets HA_DEFINING_TABLES
; first: NASM refuses a symbol declared extern and then defined in the same object.
; -----------------------------------------------------------------------------
%ifndef HA_DEFINING_TABLES
extern ha_char_class        ; 256 bytes of HA_CC_* bits, indexed by octet value
extern ha_hex_value         ; 256 bytes: an octet's HEXDIG value (0-15), 0xFF when not a HEXDIG
extern ha_x16_1f            ; 16 bytes of 0x1F: the highest CTL below SP, for pminub
extern ha_x16_09            ; 16 bytes of 0x09: HTAB, the one CTL a field value may hold
extern ha_x16_7f            ; 16 bytes of 0x7F: DEL, the CTL above the visible range
extern ha_x16_0a            ; 16 bytes of 0x0A: LF, the end of every HTTP/1.1 line
extern ha_x16_0f            ; 16 bytes of 0x0F: the low nibble, what pshufb's index keeps
extern ha_lane_window       ; 48 bytes (16 x 0x00, 16 x 0xFF, 16 x 0x00): lane masks by length
extern ha_tchar_lo          ; 16 bytes: tchar by low nibble, for pshufb (tables.asm says how)
extern ha_tchar_hi          ; 16 bytes: tchar by high nibble; an octet is a tchar when its two
                            ; entries share a bit. Its entries are the row bits of rows 2-7, so
                            ; it pairs with ha_target_lo as well
extern ha_target_lo         ; 16 bytes: request-target octets but "%", by low nibble (pairs with
                            ; ha_tchar_hi): what a vector target scan passes over
extern ha_ltchar_lo         ; 16 bytes: tchars but A-Z (an HTTP/2 field name's octets), by low
                            ; nibble (pairs with ha_tchar_hi)
%endif

; -----------------------------------------------------------------------------
; Internal functions shared by the protocol codecs (System V; each documents its clobbers)
; -----------------------------------------------------------------------------
extern ha_field_lookup      ; eax = known-field id of name rdi[0..rsi), 0 if not known
extern ha_method_lookup     ; eax = HTTPASM_METHOD_* of method rdi[0..rsi), 0 if another
extern ha_find_lf           ; rax = offset of the first LF in rdi[0..rsi), rsi if none
extern ha_token_length      ; rax = the leading tchars of rdi[0..rsi) (rsi when all are); keeps
                            ; rdi, rsi; clobbers rcx, rdx, xmm0-xmm6 (semantics/fields.asm)
extern ha_span_v2           ; v2 and up: rax = the leading octets of rdi[0..rsi) in the class of
                            ; the low-nibble table in xmm3 (paired with ha_tchar_hi); keeps rdi,
                            ; rsi, xmm3; clobbers rcx, rdx, the other xmm0-xmm6 (fields.asm)
extern ha_sha256_blocks     ; SHA-256's compression: state rdi (8 dwords), rdx 64-octet blocks at
                            ; rsi; keeps rdi, rbx, rbp, r12-r15 (crypto/sha256.asm)
extern ha_copy_short        ; rcx octets (any count; a block or less meant) rsi -> rdi by sized
                            ; moves; keeps all but rax, rdx, xmm0 (crypto/sha256.asm)
extern httpasm_sha256_init  ; the C ABI's SHA-256 (crypto/sha256.asm), for the core's HMAC and
extern httpasm_sha256_update ; HKDF (crypto/hmac.asm)
extern httpasm_sha256_final
extern httpasm_sha256
extern ha_sha512_blocks     ; SHA-512's (and SHA-384's) compression: state rdi (8 qwords), rdx
                            ; 128-octet blocks at rsi; keeps rdi, rbx, rbp, r12-r15 (crypto/sha512.asm)
extern ha_aes_ct_encrypt8   ; v1 AES of eight blocks: keys rdi (expanded), esi rounds, rdx in, rcx
                            ; out (crypto/aes.asm); keeps rdi, rsi, rdx, rcx, rbx, rbp, r12-r15
extern ha_aes_ct_expand     ; v1's round keys from key rdi to rsi ((rounds + 1) * 128 octets)
extern httpasm_aes_init     ; the C ABI's AES (crypto/aes.asm), for AES-GCM (crypto/gcm.asm)
extern httpasm_aes_encrypt_block
extern httpasm_sha384_init  ; the C ABI's SHA-384 (crypto/sha512.asm), for the core's HMAC and
extern httpasm_sha512_update ; HKDF over SHA-384 (crypto/hmac.asm); the update is SHA-512's, which
extern httpasm_sha384_final ; both hashes share
extern httpasm_sha384
extern ha_ipv6_literal      ; [rsp] = past an IP-literal's IPv6address and "]", or 0; keeps every
                            ; register (semantics/ipv6.asm: push end, push cursor, call, pop, add rsp 8)

%include "httpasm_abi.inc"
%include "cpu.inc"
%include "semantics/fields.inc"
%include "semantics/authority.inc"

; -----------------------------------------------------------------------------
; HA_STACK_DOWN size, counter: rsp -= size, touching the stack every 4032 octets on the way down.
; A frame of more than a page taken in one subtraction could step over a thread's guard page (one
; page by default: glibc's pthreads) and write into whatever is mapped below it, when that thread's
; stack is nearly spent (a stack clash: CVE-2017-1000364's class); touching each page in turn
; makes such a thread fault on its guard instead. 4032 = 63 lines: under a page from the last
; touch even after an alignment of rsp down by up to 63 octets just before. tests/native/stack
; proves every function that uses it (on stacks too small, a fault inside the guard page and
; nothing written below it).
; For frames of more than 4032 octets only (the loop runs at least once: its test at the top so
; both of its branch edges run for any count from 1); size may be an assembler expression (equ),
; which a %rep could not take. counter is a 32-bit register the caller does not need (clobbered).
; Clobbers the flags.
; -----------------------------------------------------------------------------
%macro HA_STACK_DOWN 2
    mov         %2, (%1) / 4032
%%probe:
    test        %2, %2
    jz          %%rest
    sub         rsp, 4032
    or          qword [rsp], 0
    dec         %2
    jmp         %%probe
%%rest:
    sub         rsp, (%1) % 4032
%endmacro

; -----------------------------------------------------------------------------
; HA_DECLASSIFY reg: marks reg's value public from here on, for the constant-time check
; (tests/native/ct.c under valgrind's memcheck, which tracks the secret inputs it was told about
; as "undefined" and reports every branch, address or system call that depends on them). Only
; the ConstantTime configuration (Directory.Build.props: -DHTTPASM_CT; nothing ships it) gets a
; body; every other build assembles nothing here, so shipped code is unchanged.
; Use it where code branches on a value derived from a secret ON PURPOSE because the outcome is
; public by design, and say why at the site: a private key refused as out of range, a nonce
; candidate redrawn (RFC 6979's rejection), an AEAD tag's verdict, X25519's all-zero output. A
; branch on a secret that is not public by design is a bug, and declassifying it would hide it.
; The body: memcheck's client request MAKE_MEM_DEFINED (valgrind.h's amd64 sequence: rax = the
; request's six qwords, rdx = the default answer, then four rotations of rdi that cancel out and
; xchg rbx, rbx, which valgrind intercepts; on hardware the whole is a no-op) over a stack copy of
; the value, which is then loaded back. reg is any 64-bit register; every other register is kept
; (rax, rdx, rdi saved around the request; reg restored last, so it may be one of them). Clobbers
; the flags (the rotations).
; -----------------------------------------------------------------------------
%macro HA_DECLASSIFY 1
%ifdef HTTPASM_CT
    sub         rsp, 80                     ; [0, 48) the request, [48] the value, [56..72] saved
    mov         [rsp + 48], %1
    mov         [rsp + 56], rdi
    mov         [rsp + 64], rdx
    mov         [rsp + 72], rax
    mov         qword [rsp], 0x4D430002     ; VG_USERREQ__MAKE_MEM_DEFINED (memcheck.h: 'M' 'C' + 2)
    lea         rax, [rsp + 48]
    mov         [rsp + 8], rax              ; the address
    mov         qword [rsp + 16], 8         ; the length
    xor         eax, eax
    mov         [rsp + 24], rax
    mov         [rsp + 32], rax
    mov         [rsp + 40], rax
    mov         rax, rsp
    xor         edx, edx
    rol         rdi, 3
    rol         rdi, 13
    rol         rdi, 61
    rol         rdi, 51
    xchg        rbx, rbx
    mov         rdi, [rsp + 56]
    mov         rdx, [rsp + 64]
    mov         rax, [rsp + 72]
    mov         %1, [rsp + 48]              ; last: reg may be rax, rdx or rdi
    add         rsp, 80
%endif
%endmacro

; -----------------------------------------------------------------------------
; HA_DECLASSIFY_MEM address, octets: HA_DECLASSIFY for memory: the octets at address (an
; effective address, which lea takes: "rbp + X", "rdi + 32") are public from here on, in the
; ConstantTime configuration only (elsewhere nothing). For values public by design that are
; computed from a secret, such as ML-KEM's matrix seed rho, which comes out of G(d) with the
; secret sigma and is then published in the encapsulation key. octets is an immediate. address may
; be rsp-based: it is taken before rsp moves (rax parked in the red zone meanwhile, which signal
; frames skip). Keeps every register; clobbers the flags.
; -----------------------------------------------------------------------------
%macro HA_DECLASSIFY_MEM 2
%ifdef HTTPASM_CT
    mov         [rsp - 8], rax
    lea         rax, [%1]
    sub         rsp, 80                     ; [0, 48) the request, [48], [56] saved, [72] rax
    mov         [rsp + 48], rdi
    mov         [rsp + 56], rdx
    mov         [rsp + 8], rax              ; the address
    mov         qword [rsp], 0x4D430002     ; VG_USERREQ__MAKE_MEM_DEFINED
    mov         qword [rsp + 16], %2        ; the length
    xor         eax, eax
    mov         [rsp + 24], rax
    mov         [rsp + 32], rax
    mov         [rsp + 40], rax
    mov         rax, rsp
    xor         edx, edx
    rol         rdi, 3
    rol         rdi, 13
    rol         rdi, 61
    rol         rdi, 51
    xchg        rbx, rbx
    mov         rdi, [rsp + 48]
    mov         rdx, [rsp + 56]
    mov         rax, [rsp + 72]
    add         rsp, 80
%endif
%endmacro

%endif
