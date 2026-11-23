; =============================================================================
; h1/h1.inc - HTTP/1.1's internal parse context, shared by the request parser, the response
; parser (the client side) and the chunked decoder's trailer section.
;
; ha_h1_fields parses a head's field lines into the caller's httpasm_field array and applies
; the framing rules of one mode as it goes. The rules differ:
;   HA_H1_REQUEST   Host, Content-Length, Transfer-Encoding, Connection, Expect, TE, Upgrade
;   HA_H1_RESPONSE  Content-Length, Transfer-Encoding, Connection
;   HA_H1_TRAILER   none: trailer fields are flagged HTTPASM_FIELD_FLAG_TRAILER and are
;                   never merged into the header section (RFC 9110 6.5.1)
; What a mode met is left in .seen for the caller to judge once every line is read. Some rules
; need all the lines: Host's presence, Transfer-Encoding against Content-Length.
; =============================================================================
%ifndef HTTPASM_H1_INC
%define HTTPASM_H1_INC

HA_H1_REQUEST   equ 1
HA_H1_RESPONSE  equ 2
HA_H1_TRAILER   equ 3

; h1ctx.seen: what the field lines held
HA_SEEN_HOST            equ 0x0001
HA_SEEN_CONTENT_LENGTH  equ 0x0002
HA_SEEN_TE              equ 0x0004  ; a Transfer-Encoding line
HA_SEEN_CHUNKED         equ 0x0008  ; the chunked coding
HA_SEEN_AFTER_CHUNKED   equ 0x0010  ; a coding after chunked: chunked is not final
HA_SEEN_UNKNOWN_CODING  equ 0x0020  ; a transfer coding HttpAsm does not implement
HA_SEEN_KEEP_ALIVE      equ 0x0040  ; Connection: keep-alive
HA_SEEN_CLOSE           equ 0x0080  ; Connection: close
HA_SEEN_EXPECT_CONTINUE equ 0x0100
HA_SEEN_TE_TRAILERS     equ 0x0200
HA_SEEN_UPGRADE         equ 0x0400
HA_SEEN_BAD_CODING      equ 0x0800  ; a Transfer-Encoding element that is not a token

struc h1ctx
    .buf:               resq 1  ; the input
    .head_end:          resq 1  ; the offset just past the head's final CRLF
    .fields:            resq 1  ; the caller's httpasm_field array
    .request:           resq 1  ; the httpasm_request being filled (HA_H1_REQUEST only)
    .content_length:    resq 1  ; Content-Length's value, once HA_SEEN_CONTENT_LENGTH
    .record:            resq 1  ; scratch: the field record being filled
    .line_lf:           resq 1  ; scratch: the offset of the current line's LF
    .max_fields:        resd 1  ; the fields array's capacity
    .count:             resd 1  ; field records written so far
    .mode:              resd 1  ; HA_H1_*
    .seen:              resd 1  ; HA_SEEN_*
    .error:             resd 1  ; HTTPASM_ERROR_* of the first failure, 0 while none
    .status:            resd 1  ; the status that failure answers with
    .field_flags:       resd 1  ; flags every record of this run gets (TRAILER for trailers)
    .pad:               resd 1
endstruc

extern ha_h1_fields         ; eax = 0, or 1 with h1ctx.error/.status set (see request.asm)

%endif
