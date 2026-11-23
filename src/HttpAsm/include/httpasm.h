/*
 * httpasm.h - the C ABI of libhttpasm.so, HttpAsm's HTTP library in x86-64 assembly.
 *
 * Every HttpAsm consumer binds to these functions: the .NET adapters, C, Python, and NASM
 * programs (include/httpasm.inc). Linux x64 only for now; System V calling convention.
 *
 * Nothing is released yet. HTTPASM_ABI_VERSION is 0, and no compatibility is promised before
 * the first release: check httpasm_abi_version() against the header you compiled with.
 */
#ifndef HTTPASM_H
#define HTTPASM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The ABI version these declarations describe. */
#define HTTPASM_ABI_VERSION 0

/*
 * The ABI version of the loaded library. A program compiled against this header should refuse
 * a library whose version differs from HTTPASM_ABI_VERSION: before the first release, any
 * change may break the ABI.
 */
uint32_t httpasm_abi_version(void);

/*
 * The number of leading octets of p[0..n) that are tchar (RFC 9110 section 5.6.2), n when all
 * are. p holds a valid token (a method, a field name) when n > 0 and the result is n.
 * Reads nothing past p + n; p may be NULL when n is 0.
 */
size_t httpasm_token_length(const uint8_t *p, size_t n);

/*
 * The index of the first octet of p[0..n) that a field value may not hold, n when there is
 * none (RFC 9110 section 5.5). The forbidden octets are the control characters other than
 * HTAB: 0x00-0x08, 0x0A-0x1F and 0x7F. CR, LF and NUL must never reach a peer. HttpAsm also
 * refuses the other control characters, which RFC 9110 lets a recipient keep. Whitespace at
 * the value's ends is not checked: HTTP/1.1 trims it, and HTTP/2 and HTTP/3 forbid it.
 * May read up to 16 octets from p when n < 16, but only within p's 4 KiB page, which cannot
 * fault. p may be NULL when n is 0.
 */
size_t httpasm_field_value_scan(const uint8_t *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* HTTPASM_H */
