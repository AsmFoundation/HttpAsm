; =============================================================================
; h2/h2.inc - HTTP/2's wire constants (RFC 9113): frame types and flags, error codes, settings,
; and the limits the protocol fixes. Shared by the core's HTTP/2 code and the driver's engine.
; =============================================================================
%ifndef HTTPASM_H2_INC
%define HTTPASM_H2_INC

; Frame types (RFC 9113 6). Others are extensions: ignored, except inside a field block.
H2_DATA                 equ 0x0
H2_HEADERS              equ 0x1
H2_PRIORITY             equ 0x2
H2_RST_STREAM           equ 0x3
H2_SETTINGS             equ 0x4
H2_PUSH_PROMISE         equ 0x5
H2_PING                 equ 0x6
H2_GOAWAY               equ 0x7
H2_WINDOW_UPDATE        equ 0x8
H2_CONTINUATION         equ 0x9

; Frame flags
H2_FLAG_END_STREAM      equ 0x01    ; DATA, HEADERS
H2_FLAG_ACK             equ 0x01    ; SETTINGS, PING
H2_FLAG_END_HEADERS     equ 0x04    ; HEADERS, PUSH_PROMISE, CONTINUATION
H2_FLAG_PADDED          equ 0x08    ; DATA, HEADERS, PUSH_PROMISE
H2_FLAG_PRIORITY        equ 0x20    ; HEADERS

; Error codes (RFC 9113 7)
H2_NO_ERROR             equ 0x0
H2_PROTOCOL_ERROR       equ 0x1
H2_INTERNAL_ERROR       equ 0x2
H2_FLOW_CONTROL_ERROR   equ 0x3
H2_SETTINGS_TIMEOUT     equ 0x4
H2_STREAM_CLOSED        equ 0x5
H2_FRAME_SIZE_ERROR     equ 0x6
H2_REFUSED_STREAM       equ 0x7
H2_CANCEL               equ 0x8
H2_COMPRESSION_ERROR    equ 0x9
H2_CONNECT_ERROR        equ 0xa
H2_ENHANCE_YOUR_CALM    equ 0xb
H2_INADEQUATE_SECURITY  equ 0xc
H2_HTTP_1_1_REQUIRED    equ 0xd

; Settings (RFC 9113 6.5.2)
H2_SETTINGS_HEADER_TABLE_SIZE       equ 0x1
H2_SETTINGS_ENABLE_PUSH             equ 0x2
H2_SETTINGS_MAX_CONCURRENT_STREAMS  equ 0x3
H2_SETTINGS_INITIAL_WINDOW_SIZE     equ 0x4
H2_SETTINGS_MAX_FRAME_SIZE          equ 0x5
H2_SETTINGS_MAX_HEADER_LIST_SIZE    equ 0x6

; Limits the protocol fixes
H2_FRAME_HEADER         equ 9           ; length (24), type, flags, R + stream id (31)
H2_PREFACE_LENGTH       equ 24          ; "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_PREFACE_LINE         equ 16          ; its first line, "PRI * HTTP/2.0\r\n": no HTTP/1.1 request
                                        ; starts so (version 2.0), so a client sending it speaks HTTP/2
H2_DEFAULT_WINDOW       equ 65535       ; every window until SETTINGS or WINDOW_UPDATE say otherwise
H2_MAX_WINDOW           equ 0x7FFFFFFF  ; 2^31 - 1: a window past it is a FLOW_CONTROL_ERROR
H2_MIN_FRAME_SIZE       equ 16384       ; SETTINGS_MAX_FRAME_SIZE's initial value and minimum
H2_MAX_FRAME_SIZE       equ 16777215    ; its maximum (2^24 - 1)

%endif
