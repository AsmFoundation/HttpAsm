; =============================================================================
; hpack/hpack.inc - HPACK's dynamic table as the core keeps it (RFC 7541 section 2.3.2, 4):
; one block of caller memory per decoder or encoder (httpasm_hpack_size / httpasm_hpack_init),
; opaque to the C ABI.
;
; Layout: this 64-octet header, then the ring (ring_mask + 1 dwords: each entry's offset in the
; data area, newest at .head), then the data area (.capacity octets). Everything is found from
; the block's own address, so the block holds no pointer to itself and may live anywhere.
;
; An entry in the data area: dd name length, dd value length, dd field id, the name, the value.
; Its 12-octet header is less than the 32 octets RFC 7541 4.1 counts for each entry, so the
; entries' data never exceeds .size, and .size never exceeds .max_size <= .limit <= .sized_for.
;
; Entries are appended at .end and evicted from .first (the oldest), so eviction only moves
; .first. When an append does not fit before .capacity, the live entries move to the front
; (hp_compact). .capacity is 2 * .sized_for + 64: after a compaction at least .sized_for + 64
; octets are free, so any entry that fits the table also fits the data area, and a compaction
; happens at most once per .sized_for octets appended.
; =============================================================================
%ifndef HTTPASM_HPACK_INC
%define HTTPASM_HPACK_INC

struc hpack
    .size:          resd 1  ; the entries' size, RFC 7541 4.1: name + value + 32 each
    .max_size:      resd 1  ; the table's maximum now (a size update, or the encoder's limit, sets it)
    .limit:         resd 1  ; the most .max_size may become: decoder, the SETTINGS value this side
                            ; advertised; encoder, the peer's SETTINGS value, capped at .sized_for
    .sized_for:     resd 1  ; the limit the memory was sized for at init
    .capacity:      resd 1  ; the data area's octets: 2 * .sized_for + 64
    .count:         resd 1  ; entries
    .head:          resd 1  ; the ring slot of the newest entry
    .ring_mask:     resd 1  ; ring slots - 1 (a power of two, at least .sized_for / 32 + 2 slots)
    .first:         resd 1  ; the data offset of the oldest entry
    .end:           resd 1  ; the data offset past the newest entry
    .flags:         resd 1  ; HTTPASM_HPACK_*
    .pending_min:   resd 1  ; encoder: the smallest maximum since the last block
    .pending:       resd 1  ; encoder: 1 when a size update must start the next block
    .data_offset:   resd 1  ; the data area's offset from the block's start
    .reserved:      resq 1
endstruc

HA_HPACK_HEADER         equ 64      ; hpack_size: the ring starts here
HA_HPACK_ENTRY_HEADER   equ 12      ; the octets before an entry's name in the data area
HA_HPACK_ENTRY_OVERHEAD equ 32      ; RFC 7541 4.1: what each entry adds to the table's size

%endif
