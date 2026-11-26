; =============================================================================
; hpack/hpack.asm - HPACK (RFC 7541): header blocks to fields and back, with the dynamic table
; both directions keep (include/hpack/hpack.inc). Sans-I/O like the rest of the core: the caller
; owns every byte of memory, nothing is allocated.
;
; Decoder (httpasm_hpack_decode): one complete header block (an HTTP/2 HEADERS frame's fragment
; with its CONTINUATIONs) into httpasm_field records, in block order (RFC7541-2.1-p1#2):
;   - integers with N-bit prefixes, at most 5 continuation octets and 2^32-1 (RFC7541-5.1-p15);
;   - strings raw or Huffman-coded, with RFC 7541 5.2's padding and EOS rules: at v1 4 bits per
;     step through the generated automaton (generated/huffman.inc); from v2 up by a table
;     decoder, up to two symbols per lookup of the next 12 bits (hp_string's .huffman_v2: the
;     same octets, length and errors, 1.49x faster on a browser request's block);
;   - indexed fields (index 0 and indices past both tables are errors), literals with
;     incremental indexing, without indexing and never indexed (the last keeps
;     HTTPASM_FIELD_FLAG_NEVER_INDEXED on its record, so a forwarder can keep it so);
;   - table size updates, only before the block's first field and never above the limit.
;   Names and values from the static table point at constant text; all others are copied into
;   the caller's space, because a later field of the same block may evict the entry an earlier
;   one came from. When the fields or the space run out, decoding still runs to the block's end
;   (the table must stay in step with the peer's encoder, RFC 9113 4.3) and returns 1: the
;   caller refuses the request (431) without losing the connection. From that point on nothing
;   more is copied into space (D_OUTPUT_OPEN): the rest of the block is only measured, so every
;   octet past the limits costs constant work, and a block of 1-octet references to a large
;   dynamic entry (an HPACK bomb, RFC 7541 7.3) costs no more than any other block of its size.
;   Any malformed input returns -HTTPASM_ERROR_HPACK_*: in HTTP/2 a COMPRESSION_ERROR for the
;   connection.
;
; Encoder (httpasm_hpack_encode): fields into a header block. An exact match in the static or
; dynamic table becomes an index; otherwise a literal with the name's index when the name is in
; either table. Literals are added to the dynamic table unless the field is flagged NO_INDEX,
; is a credential, or is a field that rarely repeats (the policy nghttp2 uses: :path, age,
; content-length, etag, if-modified-since, if-none-match, location, set-cookie; the table's
; HTTPASM_HPACK_INDEX_ALL lifts this one rule), or would take more than 3/4 of the table. Credentials (authorization, proxy-authorization, a cookie shorter
; than 20 octets) and fields flagged NEVER_INDEXED use the never-indexed literal (RFC 7541
; 7.1.3). Strings are Huffman-coded when the table's flags ask for it and that is not longer.
; The encoder does not check names and values: the HTTP/2 layer does that before.
;
; Table size: the decoder's limit is the SETTINGS_HEADER_TABLE_SIZE this side advertised; the
; encoder's follows the peer's (httpasm_hpack_encoder_limit), and every change is signalled at
; the start of the next block, the smallest maximum of the interval first (RFC 7541 4.2).
; =============================================================================
default rel
%include "httpasm_core.inc"
%include "hpack/hpack.inc"

section .rodata
%include "generated/hpack.inc"          ; ha_hpack_static, ha_hpack_by_id(_list), ha_hpack_text
%include "generated/huffman.inc"        ; ha_huff_code, ha_huff_length, ha_huff_decode

section .text

; -----------------------------------------------------------------------------
; size_t httpasm_hpack_size(uint32_t limit)
;   The octets of memory a table with this limit needs (httpasm_hpack_init): 64 + the ring +
;   2 * limit + 64. 0 when limit is past HTTPASM_HPACK_MAX_LIMIT. 4096 (HTTP/2's default)
;   takes 9344 octets.
; -----------------------------------------------------------------------------
global httpasm_hpack_size:function (httpasm_hpack_size.end - httpasm_hpack_size)
align 16
httpasm_hpack_size:
    xor     eax, eax
    cmp     edi, HTTPASM_HPACK_MAX_LIMIT
    ja      .out
    call    hp_ring_slots
    lea     rax, [HA_HPACK_HEADER + rax * 4]
    mov     ecx, edi
    lea     rax, [rax + rcx * 2 + 64]
.out:
    ret
.end:

; hp_ring_slots: the ring's slots for a limit: the smallest power of two above limit / 32 + 1,
; so it holds every entry the table can have (32 octets each at least) and one more while an
; insertion has not evicted yet. In: edi = limit. Out: eax. Clobbers ecx.
align 16
hp_ring_slots:
    mov     eax, edi
    shr     eax, 5
    inc     eax                             ; limit / 32 + 1 >= 1: bsr is defined
    bsr     ecx, eax
    mov     eax, 2
    shl     eax, cl
    ret

; -----------------------------------------------------------------------------
; int httpasm_hpack_init(void *memory, size_t size, uint32_t limit, uint32_t flags)
;   Makes memory (httpasm_hpack_size(limit) octets at least) an empty table: the decoder's, with
;   limit = the SETTINGS_HEADER_TABLE_SIZE this side advertises; or the encoder's, with limit =
;   the most this side will use (the peer's setting then caps it, httpasm_hpack_encoder_limit).
;   The table starts at HTTP/2's initial size, 4096, or the limit when that is smaller.
;   flags: HTTPASM_HPACK_HUFFMAN (encoder). Returns 0, or -HTTPASM_ERROR_HPACK_LIMIT (limit past
;   HTTPASM_HPACK_MAX_LIMIT, or size too small).
; -----------------------------------------------------------------------------
global httpasm_hpack_init:function (httpasm_hpack_init.end - httpasm_hpack_init)
align 16
httpasm_hpack_init:
    mov     r8, rdi                         ; memory
    mov     r9d, ecx                        ; flags
    cmp     edx, HTTPASM_HPACK_MAX_LIMIT
    ja      .bad
    mov     edi, edx
    call    hp_ring_slots                   ; eax = slots
    lea     r10, [HA_HPACK_HEADER + rax * 4]  ; the data area's offset
    mov     ecx, edi
    lea     r11, [r10 + rcx * 2 + 64]       ; the octets needed
    cmp     rsi, r11
    jb      .bad
    pxor    xmm0, xmm0                      ; a clean header: every count and offset 0
    movdqu  [r8], xmm0
    movdqu  [r8 + 16], xmm0
    movdqu  [r8 + 32], xmm0
    movdqu  [r8 + 48], xmm0
    mov     [r8 + hpack.sized_for], edi
    mov     [r8 + hpack.limit], edi
    mov     ecx, HA_HPACK_INITIAL_SIZE
    cmp     edi, ecx
    cmovb   ecx, edi
    mov     [r8 + hpack.max_size], ecx
    lea     ecx, [rdi * 2 + 64]
    mov     [r8 + hpack.capacity], ecx
    lea     ecx, [rax - 1]
    mov     [r8 + hpack.ring_mask], ecx
    mov     [r8 + hpack.head], ecx          ; the first entry lands in slot 0
    mov     [r8 + hpack.data_offset], r10d
    mov     [r8 + hpack.flags], r9d
    xor     eax, eax
    ret
.bad:
    mov     eax, -HTTPASM_ERROR_HPACK_LIMIT
    ret
.end:

; -----------------------------------------------------------------------------
; uint32_t httpasm_hpack_table_size(const httpasm_hpack *table, uint32_t *max_size)
;   The dynamic table's size now (RFC 7541 4.1), and its maximum in *max_size (may be NULL).
; -----------------------------------------------------------------------------
global httpasm_hpack_table_size:function (httpasm_hpack_table_size.end - httpasm_hpack_table_size)
align 16
httpasm_hpack_table_size:
    test    rsi, rsi
    jz      .no_max
    mov     eax, [rdi + hpack.max_size]
    mov     [rsi], eax
.no_max:
    mov     eax, [rdi + hpack.size]
    ret
.end:

; -----------------------------------------------------------------------------
; int httpasm_hpack_entry(const httpasm_hpack *table, uint32_t index, httpasm_field *field)
;   The entry at an index of HPACK's index space (1-61 the static table, 62 on the dynamic
;   one, newest first) into *field: its name, value and field id; flags 0. The pointers are
;   valid until the table next changes. Returns 0, or -HTTPASM_ERROR_HPACK_INDEX.
; -----------------------------------------------------------------------------
global httpasm_hpack_entry:function (httpasm_hpack_entry.end - httpasm_hpack_entry)
align 16
httpasm_hpack_entry:
    push    rbx
    push    r12
    mov     rbx, rdi
    mov     r12, rdx
    mov     edi, esi
    call    hp_lookup
    test    rax, rax
    js      .out
    mov     [r12 + httpasm_field.name], rsi
    mov     [r12 + httpasm_field.value], rdx
    mov     [r12 + httpasm_field.name_length], ecx
    mov     [r12 + httpasm_field.value_length], r8d
    mov     [r12 + httpasm_field.id], r9w
    mov     word [r12 + httpasm_field.flags], 0
    mov     dword [r12 + httpasm_field.reserved], 0
.out:
    pop     r12
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; hp_lookup: an index of HPACK's index space.
;   In: rbx = table, edi = index. Out: rax = 0, rsi = name, ecx = its length, rdx = value,
;   r8d = its length, r9d = field id, r10d = 1 for the static table (constant text) or 0 for
;   the dynamic one (valid until the table changes); or rax = -HTTPASM_ERROR_HPACK_INDEX for
;   index 0 (RFC7541-6.1-p5) and indices past both tables (RFC7541-2.3.3-p4).
;   Clobbers r11 and the flags.
; -----------------------------------------------------------------------------
align 16
hp_lookup:
    test    edi, edi
    jz      .bad
    cmp     edi, HA_HPACK_STATIC_COUNT
    ja      .dynamic
    lea     rax, [rel ha_hpack_static]
    lea     rax, [rax + rdi * 8]            ; 16 octets per entry, from index 1:
    lea     rax, [rax + rdi * 8 - 16]       ; static + (index - 1) * 16
    lea     r11, [rel ha_hpack_text]
    mov     esi, [rax]
    add     rsi, r11
    mov     edx, [rax + 4]
    add     rdx, r11
    movzx   ecx, word [rax + 8]
    movzx   r8d, word [rax + 10]
    movzx   r9d, byte [rax + 12]
    mov     r10d, 1
    xor     eax, eax
    ret
.dynamic:
    sub     edi, HA_HPACK_STATIC_COUNT      ; 1 = the newest entry
    cmp     edi, [rbx + hpack.count]
    ja      .bad
    mov     eax, [rbx + hpack.head]
    sub     eax, edi
    inc     eax
    and     eax, [rbx + hpack.ring_mask]
    mov     eax, [rbx + HA_HPACK_HEADER + rax * 4]
    mov     r11d, [rbx + hpack.data_offset]
    add     r11, rbx
    add     r11, rax                        ; the entry
    mov     ecx, [r11]
    mov     r8d, [r11 + 4]
    mov     r9d, [r11 + 8]
    lea     rsi, [r11 + HA_HPACK_ENTRY_HEADER]
    lea     rdx, [rsi + rcx]
    xor     r10d, r10d
    xor     eax, eax
    ret
.bad:
    mov     rax, -HTTPASM_ERROR_HPACK_INDEX
    ret

; -----------------------------------------------------------------------------
; hp_evict_to: evicts the oldest entries until the table's size is at most esi (RFC 7541 4.3).
; Eviction only moves .first: the data stays until a compaction or an append reuses it. An
; emptied table starts its data area over.
;   In: rbx = table, esi = the size to reach. Clobbers rax, rcx, rdx, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
hp_evict_to:
.loop:
    cmp     [rbx + hpack.size], esi
    jbe     .done
    mov     eax, [rbx + hpack.head]         ; the oldest: count - 1 slots behind the newest
    sub     eax, [rbx + hpack.count]
    inc     eax
    and     eax, [rbx + hpack.ring_mask]
    mov     eax, [rbx + HA_HPACK_HEADER + rax * 4]
    mov     edx, [rbx + hpack.data_offset]
    add     rdx, rbx
    mov     ecx, [rdx + rax]                ; name + value lengths
    add     ecx, [rdx + rax + 4]
    lea     r8d, [rax + rcx + HA_HPACK_ENTRY_HEADER]
    mov     [rbx + hpack.first], r8d        ; the next oldest starts after it
    add     ecx, HA_HPACK_ENTRY_OVERHEAD
    sub     [rbx + hpack.size], ecx
    dec     dword [rbx + hpack.count]
    jmp     .loop
.done:
    cmp     dword [rbx + hpack.count], 0
    jne     .out
    mov     dword [rbx + hpack.first], 0
    mov     dword [rbx + hpack.end], 0
.out:
    ret

; -----------------------------------------------------------------------------
; hp_compact: moves the live entries to the data area's front, and their ring offsets with them.
;   In: rbx = table. Clobbers rax, rcx, rdx, rsi, rdi, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
hp_compact:
    mov     r8d, [rbx + hpack.first]
    test    r8d, r8d
    jz      .done
    mov     edi, [rbx + hpack.data_offset]
    add     rdi, rbx
    lea     rsi, [rdi + r8]
    mov     ecx, [rbx + hpack.end]
    sub     ecx, r8d
    rep     movsb                           ; forward is safe: the destination is below the source
    sub     [rbx + hpack.end], r8d
    mov     dword [rbx + hpack.first], 0
    mov     ecx, [rbx + hpack.count]
    mov     eax, [rbx + hpack.head]
.offset:
    test    ecx, ecx
    jz      .done
    sub     [rbx + HA_HPACK_HEADER + rax * 4], r8d
    dec     eax
    and     eax, [rbx + hpack.ring_mask]
    dec     ecx
    jmp     .offset
.done:
    ret

; -----------------------------------------------------------------------------
; hp_reserve: room for esi octets at the data area's end (compacting when they do not fit).
;   In: rbx = table, esi = octets (at most .sized_for + 64: the callers insert only entries
;   that fit the table). Out: rax = where they go. Clobbers rcx, rdx, rsi, rdi, r8, flags.
; -----------------------------------------------------------------------------
align 16
hp_reserve:
    mov     eax, [rbx + hpack.capacity]
    sub     eax, [rbx + hpack.end]
    cmp     eax, esi
    jae     .room
    call    hp_compact
.room:
    mov     eax, [rbx + hpack.data_offset]
    add     rax, rbx
    mov     ecx, [rbx + hpack.end]
    add     rax, rcx
    ret

; -----------------------------------------------------------------------------
; hp_commit: makes the entry whose name and value hp_reserve's caller wrote (after the 12-octet
; header) the newest one, then evicts older entries until the table fits its maximum (RFC 7541
; 4.4: the new entry was checked to fit, so it survives).
;   In: rbx = table, ecx = name length, edx = value length, esi = field id.
;   Clobbers rax, rcx, rdx, rsi, rdi, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
hp_commit:
    mov     edi, [rbx + hpack.data_offset]
    add     rdi, rbx
    mov     eax, [rbx + hpack.end]
    add     rdi, rax
    mov     [rdi], ecx
    mov     [rdi + 4], edx
    mov     [rdi + 8], esi
    mov     esi, [rbx + hpack.head]
    inc     esi
    and     esi, [rbx + hpack.ring_mask]
    mov     [rbx + hpack.head], esi
    mov     [rbx + HA_HPACK_HEADER + rsi * 4], eax
    inc     dword [rbx + hpack.count]
    lea     eax, [rax + rcx + HA_HPACK_ENTRY_HEADER]
    add     eax, edx
    mov     [rbx + hpack.end], eax
    add     ecx, edx
    add     ecx, HA_HPACK_ENTRY_OVERHEAD
    add     [rbx + hpack.size], ecx
    mov     esi, [rbx + hpack.max_size]
    jmp     hp_evict_to

; -----------------------------------------------------------------------------
; hp_int: an integer with an N-bit prefix (RFC 7541 5.1).
;   In: r12 = its first octet (the prefix's bits are its low N), r13 = the block's end,
;   ecx = 2^N - 1. Out: rax = the value, r12 past it; or rax = -HTTPASM_ERROR_HPACK_TRUNCATED
;   (the block ends inside it) or -HTTPASM_ERROR_HPACK_INTEGER (past 2^32-1, or more than 5
;   continuation octets: RFC7541-5.1-p15). Clobbers rcx, rdx, r8 and the flags.
; -----------------------------------------------------------------------------
align 16
hp_int:
    movzx   eax, byte [r12]
    inc     r12
    and     eax, ecx
    cmp     eax, ecx
    jb      .done                           ; it fits the prefix
    xor     edx, edx                        ; the next 7 bits' shift
.more:
    cmp     r12, r13
    jae     .truncated
    movzx   r8d, byte [r12]
    inc     r12
    mov     ecx, edx
    add     edx, 7
    test    r8d, 0x80
    jz      .last
    and     r8d, 0x7F
    shl     r8, cl
    add     rax, r8
    cmp     edx, 28                         ; a sixth continuation octet would shift by 35
    ja      .overflow
    jmp     .more
.last:
    shl     r8, cl
    add     rax, r8
    mov     r8d, 0xFFFFFFFF
    cmp     rax, r8
    ja      .overflow
.done:
    ret
.truncated:
    mov     rax, -HTTPASM_ERROR_HPACK_TRUNCATED
    ret
.overflow:
    mov     rax, -HTTPASM_ERROR_HPACK_INTEGER
    ret

; -----------------------------------------------------------------------------
; hp_string: a string literal (RFC 7541 5.2) into rdi[0..r9): raw, copied; Huffman, decoded.
;   In: r12 = its first octet (H and the 7-bit prefix of its length), r13 = the block's end,
;   rdi = where it goes, r9 = how much room there is (0: only check it and measure it).
;   Out: rax = its decoded length (when that exceeds r9, only r9 octets were written), r12 past
;   it; or rax = -HTTPASM_ERROR_HPACK_* (truncated, an integer past the limits, a Huffman
;   string with EOS or bad padding: RFC7541-5.2-p10#1..3).
;   Clobbers rcx, rdx, rsi, rdi, r8-r11 and the flags. Keeps rbx, rbp, r13-r15.
;   Memory: reads the block only, never at or past r13 (v2's 8-octet reads may pass the string's
;   end, never the block's). Writes rdi[0..r9) only, but within that room it may write octets
;   past the decoded length (v2's two-symbol stores): every caller hands either free space or
;   exactly the decoded length, so nothing it keeps is there.
;
;   Two versions of a Huffman string (HA_CPU_PICK1 at .huffman), the same octets, length and
;   errors for every input (tests/native/tiers):
;     v1  the automaton takes a nibble per step (generate.cs Emit.Huffman): a step can finish at
;         most one symbol (no code is shorter than 5 bits), never EOS, and its ACCEPT bit says
;         whether the string may end there: on a symbol boundary, or within 7 bits of all ones
;         (the start of EOS's code). Each step's table load waits for the one before: two per
;         octet, about 10 cycles per symbol.
;     v2  a table decoder (.huffman_v2, described there): one lookup per 12 bits, up to two
;         symbols, about half the latency per symbol.
; -----------------------------------------------------------------------------
align 16
hp_string:
    cmp     r12, r13
    jae     .truncated
    movzx   r10d, byte [r12]                ; H: bit 7
    mov     ecx, 127
    call    hp_int
    test    rax, rax
    js      .out
    mov     rdx, r13
    sub     rdx, r12
    cmp     rax, rdx
    ja      .truncated
    test    r10d, 0x80
    jnz     .huffman
    mov     r8, rax                         ; raw: copy what fits
    mov     rcx, rax
    cmp     rcx, r9
    cmova   rcx, r9
    mov     rsi, r12
    rep     movsb
    add     r12, r8
    mov     rax, r8
.out:
    ret
.huffman:
    lea     r11, [r12 + rax]                ; the string's end
    mov     r10, rdi                        ; the output's start
    add     r9, rdi                         ; the output's room ends here
    HA_CPU_PICK1 HTTPASM_CPU_V2, .huffman_v2
    xor     edx, edx                        ; the automaton's state
    mov     r8d, HA_HUFF_ACCEPT             ; an empty string is valid
    lea     rsi, [rel ha_huff_decode]
.octet:
    cmp     r12, r11
    jae     .ended
    movzx   eax, byte [r12]
    inc     r12
    mov     ecx, eax
    shr     ecx, 4                          ; the high nibble first
    shl     edx, 4
    or      edx, ecx
    mov     ecx, [rsi + rdx * 4]
    test    ecx, HA_HUFF_FAIL
    jnz     .bad
    test    ecx, HA_HUFF_SYMBOL
    jz      .high_done
    cmp     rdi, r9
    jae     .high_counted
    mov     [rdi], ch                       ; bits 8-15: the symbol
.high_counted:
    inc     rdi
.high_done:
    movzx   edx, cl
    and     eax, 0x0F
    shl     edx, 4
    or      edx, eax
    mov     ecx, [rsi + rdx * 4]
    test    ecx, HA_HUFF_FAIL
    jnz     .bad
    test    ecx, HA_HUFF_SYMBOL
    jz      .low_done
    cmp     rdi, r9
    jae     .low_counted
    mov     [rdi], ch
.low_counted:
    inc     rdi
.low_done:
    mov     r8d, ecx
    and     r8d, HA_HUFF_ACCEPT
    movzx   edx, cl
    jmp     .octet
.ended:
    test    r8d, r8d
    jz      .bad                            ; the padding is not a prefix of EOS, or longer than 7 bits
    mov     rax, rdi
    sub     rax, r10
    ret
.bad:
    mov     rax, -HTTPASM_ERROR_HPACK_HUFFMAN
    ret
.truncated:
    mov     rax, -HTTPASM_ERROR_HPACK_TRUNCATED
    ret

; ---- v2: the table decoder (the same octets, length and errors as the automaton above).
;
; The string is a big-endian bit stream; r14 counts its bits not yet decoded. A window (rdx)
; holds the next bits at its top: each group reads the 8 octets that hold the next bit (inside
; the block, which may go past the string; at the block's end, the octets left, zero-filled), so
; the window has at least 57 valid bits or every bit to the block's end. Four lookups follow,
; each of the next 12 bits in ha_huff_pair (generated: up to two symbols, their bits, their
; count): when the entry's bits lie within the string, the lookup shifts the window by them (the
; dword's low byte: the load feeds the shift directly), stores the two symbols (a lone symbol's
; neighbour is overwritten by the next lookup, or lies past the string's end in the caller's room)
; and advances the output by the count. Four lookups take at most 48 bits, within the window's 57.
;
; A first code longer than 12 bits has the dword 0: it stores nothing lasting and moves nothing,
; so the lookups after it repeat it, and the check after the four (bits 0) hands the string to
; .h2_single at that code. So does an output with less than 16 octets of room (one symbol at a
; time, written while they fit; with no room at all the lookups only count, .h2_count).
; .h2_single decodes one symbol by the canonical tables (ha_huff_limit, ha_huff_offset,
; ha_huff_sorted: the first length whose top bits fall below its limit), bounded by the bits
; left. An entry whose bits pass the string's end goes to .h2_partial: the string's last bits,
; its last symbol and its padding, settled with ha_huff_first_bits without a search. Bits left
; that no code fits are padding: at most 7 bits, all ones, or the string is refused, as the
; automaton refuses it (RFC7541-5.2-p10); EOS decoded within the string is refused too. The
; decoder keeps the automaton's contract: the same octets in the room, the same length, the same
; errors (tests/native/tiers compares them on every kind of string).
;
; Registers: r12 the string, r11 its end, r13 the block's end (hp_string's caller: reads stay
; below it), r14 the string's bits left, r15 its bits in all (r14 and r15 saved here), rdx the
; window, rsi ha_huff_pair, rdi the output, r9 the room's end, r10 the output's start.

; H2_WINDOW: rdx = the window at the string's next bit (bit r15 - r14). Clobbers rax, rcx, r8.
%macro H2_WINDOW 0
    mov     rax, r15
    sub     rax, r14                        ; the bits read
    shr     rax, 3                          ; the octet that holds the next bit
    lea     r8, [r12 + rax + 8]
    cmp     r8, r13
    ja      %%tail
    mov     rdx, [r12 + rax]                ; 8 octets inside the block
    bswap   rdx
    jmp     %%shift
%%tail:                                     ; 1-7 octets to the block's end, zero-filled
    lea     r8, [r12 + rax]
    xor     edx, edx
    mov     ecx, 56
%%octet:
    movzx   eax, byte [r8]
    shl     rax, cl
    or      rdx, rax
    inc     r8
    sub     ecx, 8
    cmp     r8, r13
    jb      %%octet
%%shift:
    mov     rcx, r15
    sub     rcx, r14
    and     ecx, 7
    shl     rdx, cl                         ; the next bit at bit 63
%endmacro

.huffman_v2:
    push    r14
    push    r15
    lea     rsi, [rel ha_huff_pair]
    mov     r14, r11
    sub     r14, r12
    shl     r14, 3                          ; the string's bits, all left
    mov     r15, r14
.h2_group:
    test    r14, r14
    jz      .h2_done                        ; every bit decoded: the string ended on a code
    H2_WINDOW
    lea     rcx, [rdi + 16]
    cmp     rcx, r9
    ja      .h2_little_room                 ; the stores could pass the room's end
%rep 4
    mov     r8, rdx
    shr     r8, 64 - 12                     ; the next 12 bits (kept for .h2_partial)
    mov     ecx, [rsi + r8 * 4]             ; cl = the bits, ch = the count, then the symbols
    movzx   eax, cl
    cmp     rax, r14
    ja      .h2_partial                     ; past the string's end: its last bits
    shl     rdx, cl                         ; the chain: the load, then this shift
    sub     r14, rax
    mov     eax, ecx
    shr     eax, 16
    mov     [rdi], ax                       ; the symbols (a lone one's neighbour: overwritten next)
    movzx   eax, ch
    add     rdi, rax
%endrep
    test    cl, cl
    jz      .h2_single                      ; a long code stopped the lookups (dword 0)
    jmp     .h2_group
.h2_little_room:
    cmp     rdi, r9
    jb      .h2_single                      ; some room left: filled one symbol at a time
.h2_count:                                  ; no room: the same lookups, counting only
%rep 4
    mov     r8, rdx
    shr     r8, 64 - 12
    mov     ecx, [rsi + r8 * 4]
    movzx   eax, cl
    cmp     rax, r14
    ja      .h2_partial
    shl     rdx, cl
    sub     r14, rax
    movzx   eax, ch
    add     rdi, rax
%endrep
    test    cl, cl
    jz      .h2_single
    test    r14, r14
    jz      .h2_done
    H2_WINDOW
    jmp     .h2_count

.h2_partial:
    ; The entry's bits pass the string's end (r14 bits left; ecx = the entry, r8 = the 12 bits
    ; looked up, rdx the window there). Its first code is the string's when it fits: the code at
    ; this position is unique (a prefix code), whatever the bits past the end are. It is written
    ; when the room holds it (the counting loop's output has none left: counted only). What is
    ; left after it cannot hold the entry's second code, nor any code: it is padding. When not
    ; even the first code fits, everything left is padding.
    mov     eax, ecx                        ; the entry: its first symbol in bits 16-23
    lea     rcx, [rel ha_huff_first_bits]
    movzx   ecx, byte [rcx + r8]            ; the first code's bits alone
    cmp     rcx, r14
    ja      .h2_padding
    cmp     rdi, r9
    jae     .h2_partial_counted
    shr     eax, 16
    mov     [rdi], al
.h2_partial_counted:
    inc     rdi
    sub     r14, rcx
    shl     rdx, cl
    jmp     .h2_padding                     ; (none left: .h2_padding ends the string)

.h2_single:                                 ; one symbol, by the canonical tables
    test    r14, r14
    jz      .h2_done                        ; the string ended on a code inside a group: no
                                            ; window then (it would read past the block's end)
    H2_WINDOW
    mov     r8d, 5                          ; the shortest code's length
.h2_length:
    cmp     r8, r14
    ja      .h2_padding                     ; no code within the bits left: they are padding
    mov     ecx, 64
    sub     ecx, r8d
    mov     rax, rdx
    shr     rax, cl                         ; the next r8 bits
    lea     rcx, [rel ha_huff_limit]
    cmp     eax, [rcx + r8 * 4]
    jb      .h2_code
    inc     r8d
    jmp     .h2_length                      ; the code is complete: a length up to 30 fits
.h2_code:
    lea     rcx, [rel ha_huff_offset]
    add     eax, [rcx + r8 * 4]             ; its index in canonical order
    lea     rcx, [rel ha_huff_sorted]
    movzx   eax, word [rcx + rax * 2]
    cmp     eax, 256
    je      .h2_bad                         ; EOS inside the string (RFC7541-5.2-p10#3)
    cmp     rdi, r9
    jae     .h2_counted                     ; past the room: counted, not written
    mov     [rdi], al
.h2_counted:
    inc     rdi
    sub     r14, r8
    jmp     .h2_group
.h2_padding:
    ; r14 bits are left and no code fits in them: at most 7, all ones (EOS's start). None left
    ; is no padding at all (a string that ends on a code, met by .h2_partial's next lookup); it
    ; must not reach the shift below, whose count 64 x86 takes as 0.
    test    r14, r14
    jz      .h2_done
    cmp     r14, 7
    ja      .h2_bad
    mov     ecx, 64
    sub     ecx, r14d
    mov     rax, rdx
    shr     rax, cl                         ; the r14 bits
    mov     ecx, r14d
    mov     edx, 1
    shl     edx, cl
    dec     edx                             ; r14 ones
    cmp     eax, edx
    jne     .h2_bad
.h2_done:
    mov     r12, r11                        ; past the string
    mov     rax, rdi
    sub     rax, r10                        ; the decoded length
    pop     r15
    pop     r14
    ret
.h2_bad:
    pop     r15
    pop     r14
    jmp     .bad

; -----------------------------------------------------------------------------
; int64_t httpasm_hpack_decode(httpasm_hpack *table, const uint8_t *block, size_t length,
;                              httpasm_hpack_output *output)
;   Decodes one complete header block (see this file's header). Returns 0 when every field was
;   written to output; 1 when the block was decoded but the fields or the space ran out (the
;   records written are the first ones, in order; list_size counts them all); or
;   -HTTPASM_ERROR_HPACK_* for malformed input, after which the table must not be used again.
; -----------------------------------------------------------------------------
D_NAME          equ 0       ; the current field's name (in space, or the static table's text)
D_VALUE         equ 8       ; its value
D_NAME_POS      equ 16      ; the block position of a literal name, for decoding it again
D_VALUE_POS     equ 24      ; the block position of the value
D_CURSOR        equ 32      ; where space's next string goes (tentative until the record is written)
D_SAVE          equ 40      ; the block position, while an insertion decodes again
D_NLEN          equ 48
D_VLEN          equ 52
D_ID            equ 56
D_FFLAGS        equ 60      ; the record's flags
D_INDEX         equ 64      ; the name's index; 0 for a literal name
D_FITS          equ 68      ; 1 when the name and value are whole in space or the static table
D_INC           equ 72      ; 1 for a literal with incremental indexing
D_FRAME         equ 88      ; six pushes + 88: rsp stays 16-byte aligned for the calls

DF_SEEN         equ 1       ; a field was seen: size updates are no longer allowed
DF_OVERFLOW     equ 2       ; a field did not fit: no more records are written

; D_OUTPUT_OPEN: D_FITS = 1 while the output can take another record, 0 once it cannot (a field
; did not fit, or max_fields records are written). A field that starts with D_FITS 0 copies
; nothing into space: its strings are only measured (and decoded again into the table when it
; is inserted). Without this, a block past the limits still paid for every copy: each 1-octet
; reference to a large dynamic entry copied the whole entry again (an HPACK bomb's CPU cost,
; RFC 7541 7.3), where now every octet past the limits costs the same small, constant work.
; Clobbers eax and the flags.
%macro D_OUTPUT_OPEN 0
    mov     dword [rsp + D_FITS], 0
    test    r15d, DF_OVERFLOW
    jnz     %%closed
    mov     eax, [rbp + httpasm_hpack_output.count]
    cmp     eax, [rbp + httpasm_hpack_output.max_fields]
    jae     %%closed                        ; full: this field will overflow (.record)
    mov     dword [rsp + D_FITS], 1
%%closed:
%endmacro

global httpasm_hpack_decode:function (httpasm_hpack_decode.end - httpasm_hpack_decode)
align 16
httpasm_hpack_decode:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, D_FRAME
    mov     rbx, rdi                        ; table
    mov     r12, rsi                        ; the cursor in the block
    lea     r13, [rsi + rdx]                ; the block's end
    mov     rbp, rcx                        ; output
    xor     r15d, r15d
    xor     eax, eax
    mov     [rbp + httpasm_hpack_output.count], eax
    mov     [rbp + httpasm_hpack_output.space_used], rax
    mov     [rbp + httpasm_hpack_output.list_size], rax

.next:
    cmp     r12, r13
    jae     .done
    movzx   eax, byte [r12]
    test    al, 0x80
    jnz     .indexed
    test    al, 0x40
    jnz     .incremental
    test    al, 0x20
    jnz     .size_update
    xor     ecx, ecx                        ; 0000: without indexing; 0001: never indexed
    test    al, 0x10
    jz      .plain
    mov     ecx, HTTPASM_FIELD_FLAG_NEVER_INDEXED
.plain:
    mov     [rsp + D_FFLAGS], ecx
    mov     dword [rsp + D_INC], 0
    mov     ecx, 15
    jmp     .literal

.incremental:
    mov     dword [rsp + D_FFLAGS], 0
    mov     dword [rsp + D_INC], 1
    mov     ecx, 63

.literal:
    or      r15d, DF_SEEN
    call    hp_int                          ; the name's index, 0 for a literal name
    test    rax, rax
    js      .fail
    mov     [rsp + D_INDEX], eax
    mov     rax, [rbp + httpasm_hpack_output.space]
    add     rax, [rbp + httpasm_hpack_output.space_used]
    mov     [rsp + D_CURSOR], rax
    D_OUTPUT_OPEN
    mov     qword [rsp + D_NAME_POS], 0
    cmp     dword [rsp + D_INDEX], 0
    je      .literal_name
    mov     edi, [rsp + D_INDEX]
    call    hp_lookup
    test    rax, rax
    js      .fail
    mov     [rsp + D_NLEN], ecx
    mov     [rsp + D_ID], r9d
    test    r10d, r10d
    jz      .dynamic_name
    mov     [rsp + D_NAME], rsi             ; the static table's text: no copy
    jmp     .value
.dynamic_name:
    cmp     dword [rsp + D_FITS], 0
    je      .value                          ; the output is closed: the name is not copied
    mov     rax, [rbp + httpasm_hpack_output.space]
    add     rax, [rbp + httpasm_hpack_output.space_size]
    sub     rax, [rsp + D_CURSOR]           ; the room left
    cmp     rcx, rax
    ja      .name_no_room
    mov     rdi, [rsp + D_CURSOR]
    mov     [rsp + D_NAME], rdi
    rep     movsb                           ; rsi = the entry's name, rcx = its length
    mov     [rsp + D_CURSOR], rdi
    jmp     .value
.name_no_room:
    mov     dword [rsp + D_FITS], 0
    jmp     .value

.literal_name:
    mov     [rsp + D_NAME_POS], r12
    mov     rdi, [rsp + D_CURSOR]
    mov     r14, [rbp + httpasm_hpack_output.space]
    add     r14, [rbp + httpasm_hpack_output.space_size]
    sub     r14, rdi                        ; the room left
    cmp     dword [rsp + D_FITS], 0
    jne     .name_room
    xor     r14d, r14d                      ; the output is closed: the name is only measured
.name_room:
    mov     r9, r14
    call    hp_string
    test    rax, rax
    js      .fail
    mov     [rsp + D_NLEN], eax
    mov     dword [rsp + D_ID], 0
    cmp     rax, r14
    ja      .name_no_room
    mov     rdi, [rsp + D_CURSOR]
    mov     [rsp + D_NAME], rdi
    add     [rsp + D_CURSOR], rax
    mov     rsi, rax
    call    ha_field_lookup                 ; the known-field id, once per decoded name
    mov     [rsp + D_ID], eax

.value:
    mov     [rsp + D_VALUE_POS], r12
    xor     r14d, r14d                      ; no room unless the name fitted
    cmp     dword [rsp + D_FITS], 0
    je      .value_decode
    mov     r14, [rbp + httpasm_hpack_output.space]
    add     r14, [rbp + httpasm_hpack_output.space_size]
    sub     r14, [rsp + D_CURSOR]
.value_decode:
    mov     rdi, [rsp + D_CURSOR]
    mov     r9, r14
    call    hp_string
    test    rax, rax
    js      .fail
    mov     [rsp + D_VLEN], eax
    cmp     rax, r14
    ja      .value_no_room
    mov     rdi, [rsp + D_CURSOR]
    mov     [rsp + D_VALUE], rdi
    add     [rsp + D_CURSOR], rax
    jmp     .record
.value_no_room:
    mov     dword [rsp + D_FITS], 0
    jmp     .record

.indexed:
    or      r15d, DF_SEEN
    mov     ecx, 127
    call    hp_int
    test    rax, rax
    js      .fail
    mov     edi, eax
    call    hp_lookup                       ; index 0 and indices past both tables fail here
    test    rax, rax
    js      .fail
    mov     [rsp + D_NLEN], ecx
    mov     [rsp + D_VLEN], r8d
    mov     [rsp + D_ID], r9d
    xor     eax, eax
    mov     [rsp + D_FFLAGS], eax
    mov     [rsp + D_INC], eax
    D_OUTPUT_OPEN                           ; before rax is the cursor: it clobbers eax
    mov     rax, [rbp + httpasm_hpack_output.space]
    add     rax, [rbp + httpasm_hpack_output.space_used]
    mov     [rsp + D_CURSOR], rax
    test    r10d, r10d
    jz      .indexed_dynamic
    mov     [rsp + D_NAME], rsi
    mov     [rsp + D_VALUE], rdx
    jmp     .record
.indexed_dynamic:
    ; Copies of both: a later field of this block may evict the entry. None once the output
    ; is closed (D_OUTPUT_OPEN): a reference past the limits costs no copy.
    cmp     dword [rsp + D_FITS], 0
    je      .value_no_room
    mov     r9, [rbp + httpasm_hpack_output.space]
    add     r9, [rbp + httpasm_hpack_output.space_size]
    sub     r9, rax                         ; the room left
    mov     r10d, ecx
    add     r10, r8
    cmp     r10, r9
    ja      .value_no_room
    mov     rdi, rax
    mov     [rsp + D_NAME], rdi
    rep     movsb                           ; the name: rsi, rcx
    mov     [rsp + D_VALUE], rdi
    mov     rsi, rdx
    mov     ecx, r8d
    rep     movsb
    mov     [rsp + D_CURSOR], rdi

.record:
    mov     eax, [rsp + D_NLEN]             ; the header list's size counts every field,
    mov     ecx, [rsp + D_VLEN]             ; written or not (RFC 9113 6.5.2)
    add     rax, rcx
    add     rax, HA_HPACK_ENTRY_OVERHEAD
    add     [rbp + httpasm_hpack_output.list_size], rax
    test    r15d, DF_OVERFLOW
    jnz     .recorded
    cmp     dword [rsp + D_FITS], 0
    je      .overflow
    mov     eax, [rbp + httpasm_hpack_output.count]
    cmp     eax, [rbp + httpasm_hpack_output.max_fields]
    jae     .overflow
    shl     rax, 5                          ; 32 octets per httpasm_field
    add     rax, [rbp + httpasm_hpack_output.fields]
    mov     rcx, [rsp + D_NAME]
    mov     [rax + httpasm_field.name], rcx
    mov     rcx, [rsp + D_VALUE]
    mov     [rax + httpasm_field.value], rcx
    mov     ecx, [rsp + D_NLEN]
    mov     [rax + httpasm_field.name_length], ecx
    mov     ecx, [rsp + D_VLEN]
    mov     [rax + httpasm_field.value_length], ecx
    mov     ecx, [rsp + D_ID]
    mov     [rax + httpasm_field.id], cx
    mov     ecx, [rsp + D_FFLAGS]
    mov     [rax + httpasm_field.flags], cx
    mov     dword [rax + httpasm_field.reserved], 0
    inc     dword [rbp + httpasm_hpack_output.count]
    mov     rax, [rsp + D_CURSOR]           ; the strings are the record's now
    sub     rax, [rbp + httpasm_hpack_output.space]
    mov     [rbp + httpasm_hpack_output.space_used], rax
    jmp     .recorded
.overflow:
    or      r15d, DF_OVERFLOW
.recorded:
    cmp     dword [rsp + D_INC], 0
    je      .next

    ; Incremental indexing: the field becomes the dynamic table's newest entry.
    mov     eax, [rsp + D_NLEN]
    mov     ecx, [rsp + D_VLEN]
    add     rax, rcx
    add     rax, HA_HPACK_ENTRY_OVERHEAD
    mov     ecx, [rbx + hpack.max_size]
    cmp     rax, rcx
    jbe     .insert
    xor     esi, esi                        ; larger than the table: it empties the table and
    call    hp_evict_to                     ; is not added (RFC 7541 4.4)
    jmp     .next
.insert:
    mov     esi, [rsp + D_NLEN]
    add     esi, [rsp + D_VLEN]
    add     esi, HA_HPACK_ENTRY_HEADER
    call    hp_reserve
    lea     r14, [rax + HA_HPACK_ENTRY_HEADER]  ; the entry's name goes here
    cmp     dword [rsp + D_FITS], 0
    je      .insert_again
    mov     rdi, r14                        ; from the copies (space, or constant text): never
    mov     rsi, [rsp + D_NAME]             ; from the table itself, which hp_reserve may move
    mov     ecx, [rsp + D_NLEN]
    rep     movsb
    mov     rsi, [rsp + D_VALUE]
    mov     ecx, [rsp + D_VLEN]
    rep     movsb
    mov     esi, [rsp + D_ID]
    jmp     .commit
.insert_again:
    ; The strings did not fit the output: take them again from the block, into the entry's
    ; place. An indexed name is looked up again, after hp_reserve's compaction (which moves
    ; entries, not their indices); it is a live entry below the data's end, so it cannot
    ; overlap its copy.
    mov     [rsp + D_SAVE], r12
    cmp     dword [rsp + D_INDEX], 0
    je      .again_name
    mov     edi, [rsp + D_INDEX]
    call    hp_lookup
    mov     [rsp + D_ID], r9d
    mov     rdi, r14
    rep     movsb
    jmp     .again_value
.again_name:
    mov     r12, [rsp + D_NAME_POS]
    mov     rdi, r14
    mov     r9d, [rsp + D_NLEN]
    call    hp_string                       ; these octets decoded once already: no error
    mov     rdi, r14
    mov     esi, [rsp + D_NLEN]
    call    ha_field_lookup
    mov     [rsp + D_ID], eax
.again_value:
    mov     r12, [rsp + D_VALUE_POS]
    mov     edi, [rsp + D_NLEN]
    add     rdi, r14
    mov     r9d, [rsp + D_VLEN]
    call    hp_string
    mov     r12, [rsp + D_SAVE]
    mov     esi, [rsp + D_ID]
.commit:
    mov     ecx, [rsp + D_NLEN]
    mov     edx, [rsp + D_VLEN]
    call    hp_commit
    jmp     .next

.size_update:
    test    r15d, DF_SEEN
    jnz     .bad_size_update                ; only before the block's first field (RFC 7541 4.2)
    mov     ecx, 31
    call    hp_int
    test    rax, rax
    js      .fail
    mov     ecx, [rbx + hpack.limit]
    cmp     rax, rcx
    ja      .bad_size_update                ; above the limit (RFC7541-6.3-p5#2)
    mov     [rbx + hpack.max_size], eax
    mov     esi, eax
    call    hp_evict_to
    jmp     .next
.bad_size_update:
    mov     rax, -HTTPASM_ERROR_HPACK_SIZE_UPDATE
    jmp     .fail

.done:
    xor     eax, eax
    test    r15d, DF_OVERFLOW
    setnz   al
.fail:
    add     rsp, D_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; size_t httpasm_hpack_encode_bound(const httpasm_field *fields, uint32_t count)
;   The most octets httpasm_hpack_encode can write for these fields: two table size updates
;   (6 octets each), and per field a representation octet with its integer (6), each string's
;   length (6 each) and both strings raw (Huffman is used only when shorter).
; -----------------------------------------------------------------------------
global httpasm_hpack_encode_bound:function (httpasm_hpack_encode_bound.end - httpasm_hpack_encode_bound)
align 16
httpasm_hpack_encode_bound:
    mov     eax, 12
.field:
    test    esi, esi
    jz      .done
    mov     ecx, [rdi + httpasm_field.name_length]
    add     rax, rcx
    mov     ecx, [rdi + httpasm_field.value_length]
    add     rax, rcx
    add     rax, 18
    add     rdi, httpasm_field_size
    dec     esi
    jmp     .field
.done:
    ret
.end:

; -----------------------------------------------------------------------------
; void httpasm_hpack_encoder_limit(httpasm_hpack *table, uint32_t limit)
;   The peer's SETTINGS_HEADER_TABLE_SIZE (RFC 9113 6.5.2): the encoder's table follows it, up
;   to what its memory was sized for. A change is applied now (entries evicted) and signalled
;   at the start of the next block; after several changes, the smallest maximum first, then
;   the final one (RFC7541-4.2-p3, RFC7541-4.2-p4).
; -----------------------------------------------------------------------------
global httpasm_hpack_encoder_limit:function (httpasm_hpack_encoder_limit.end - httpasm_hpack_encoder_limit)
align 16
httpasm_hpack_encoder_limit:
    push    rbx
    mov     rbx, rdi
    mov     eax, [rbx + hpack.sized_for]
    cmp     esi, eax
    cmova   esi, eax
    mov     [rbx + hpack.limit], esi
    cmp     esi, [rbx + hpack.max_size]
    je      .out
    cmp     dword [rbx + hpack.pending], 0
    je      .first_change
    cmp     esi, [rbx + hpack.pending_min]
    jae     .changed
.first_change:
    mov     [rbx + hpack.pending_min], esi
.changed:
    mov     dword [rbx + hpack.pending], 1
    mov     [rbx + hpack.max_size], esi
    call    hp_evict_to
.out:
    pop     rbx
    ret
.end:

; -----------------------------------------------------------------------------
; hp_int_encode: an integer with an N-bit prefix (RFC 7541 5.1).
;   In: r14 = where it goes, rdx = the value, ecx = 2^N - 1, eax = the first octet's bits above
;   the prefix. Out: r14 past it. Clobbers rax, rdx and the flags.
; -----------------------------------------------------------------------------
align 16
hp_int_encode:
    cmp     rdx, rcx
    jae     .multi
    or      eax, edx
    mov     [r14], al
    inc     r14
    ret
.multi:
    or      eax, ecx
    mov     [r14], al
    inc     r14
    sub     rdx, rcx
.seven:
    cmp     rdx, 128
    jb      .last
    mov     eax, edx
    or      eax, 0x80
    mov     [r14], al                       ; the low 7 bits, continuation set
    inc     r14
    shr     rdx, 7
    jmp     .seven
.last:
    mov     [r14], dl
    inc     r14
    ret

; -----------------------------------------------------------------------------
; hp_string_encode: a string literal (RFC 7541 5.2): Huffman-coded when the table's flags ask
; for it and that is not longer (a tie goes to Huffman, as RFC 7541's examples code "307"),
; raw otherwise.
;   In: rbx = table, r14 = where it goes, rsi = the string, rcx = its length.
;   Out: r14 past it. Clobbers rax, rcx, rdx, rsi, rdi, r8-r11 and the flags.
; -----------------------------------------------------------------------------
align 16
hp_string_encode:
    test    dword [rbx + hpack.flags], HTTPASM_HPACK_HUFFMAN
    jz      .raw
    lea     r8, [rel ha_huff_length]
    xor     edx, edx                        ; the code's bits
    mov     rdi, rsi
    mov     r9, rcx
.measure:
    test    r9, r9
    jz      .measured
    movzx   eax, byte [rdi]
    movzx   eax, byte [r8 + rax]
    add     rdx, rax
    inc     rdi
    dec     r9
    jmp     .measure
.measured:
    add     rdx, 7
    shr     rdx, 3                          ; whole octets, the last one padded
    cmp     rdx, rcx
    ja      .raw                            ; longer: raw
    mov     r10, rcx                        ; the string's length
    mov     r11, rsi                        ; and its octets
    mov     eax, 0x80                       ; H
    mov     ecx, 127
    call    hp_int_encode
    lea     r8, [rel ha_huff_code]
    lea     r9, [rel ha_huff_length]
    xor     eax, eax                        ; the bits not written yet, in the low end
    xor     edx, edx                        ; how many
.symbol:
    test    r10, r10
    jz      .pad
    movzx   edi, byte [r11]
    inc     r11
    dec     r10
    movzx   ecx, byte [r9 + rdi]
    shl     rax, cl
    mov     esi, [r8 + rdi * 4]
    or      rax, rsi
    add     edx, ecx
.whole:
    cmp     edx, 8                          ; whole octets out; at most 7 bits wait, so the next
    jb      .symbol                         ; code (30 bits at most) still fits the register
    sub     edx, 8
    mov     ecx, edx
    mov     rsi, rax
    shr     rsi, cl
    mov     [r14], sil
    inc     r14
    jmp     .whole
.pad:
    test    edx, edx
    jz      .done
    mov     ecx, 8                          ; the last octet: the bits left, then ones (the
    sub     ecx, edx                        ; start of EOS's code)
    shl     rax, cl
    mov     esi, 1
    shl     esi, cl
    dec     esi
    or      eax, esi
    mov     [r14], al
    inc     r14
.done:
    ret
.raw:
    mov     rdx, rcx
    mov     r10, rcx
    xor     eax, eax
    mov     ecx, 127
    call    hp_int_encode
    mov     rdi, r14
    mov     rcx, r10
    rep     movsb                           ; rsi: the string
    mov     r14, rdi
    ret

; -----------------------------------------------------------------------------
; int64_t httpasm_hpack_encode(httpasm_hpack *table, const httpasm_field *fields,
;                              uint32_t count, uint8_t *out, size_t cap)
;   Encodes the fields, in order (RFC7541-2.1-p1#1), as one header block (see this file's
;   header for the choices). Returns the block's length, or 0 when cap is below
;   httpasm_hpack_encode_bound: then nothing is written and the table is unchanged.
; -----------------------------------------------------------------------------
E_ID            equ 0       ; the field's known-field id
E_NEVER         equ 4       ; 1: the never-indexed literal
E_EXACT         equ 8       ; the index of an exact match, 0 if none
E_NAME_INDEX    equ 12      ; the index of the name's entry, 0 if none
E_INC           equ 16      ; 1: the literal is added to the dynamic table
E_FRAME         equ 24      ; six pushes + 24: aligned for the calls

global httpasm_hpack_encode:function (httpasm_hpack_encode.end - httpasm_hpack_encode)
align 16
httpasm_hpack_encode:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, E_FRAME
    mov     rbx, rdi                        ; table
    mov     r12, rsi                        ; the next field
    mov     r13d, edx                       ; fields left
    mov     rbp, rcx                        ; out
    mov     r14, rcx                        ; the cursor
    mov     r15, r8                         ; cap (until the bound is checked)
    mov     rdi, rsi
    mov     esi, edx
    call    httpasm_hpack_encode_bound
    cmp     r15, rax
    jb      .too_small

    cmp     dword [rbx + hpack.pending], 0  ; size updates owed since the last block
    je      .field
    mov     dword [rbx + hpack.pending], 0
    mov     edx, [rbx + hpack.pending_min]
    cmp     edx, [rbx + hpack.max_size]
    jae     .final_update
    mov     eax, 0x20
    mov     ecx, 31
    call    hp_int_encode
.final_update:
    mov     edx, [rbx + hpack.max_size]
    mov     eax, 0x20
    mov     ecx, 31
    call    hp_int_encode

.field:
    test    r13d, r13d
    jz      .done
    mov     r15, r12
    mov     rdi, [r15 + httpasm_field.name]
    mov     esi, [r15 + httpasm_field.name_length]
    call    ha_field_lookup                 ; the caller's id is not trusted: a match must be real
    mov     [rsp + E_ID], eax
    ; Never indexed: the caller's flag, or a credential (RFC 7541 7.1.3; a short cookie can be
    ; guessed from the compressed size alone).
    xor     edx, edx
    test    word [r15 + httpasm_field.flags], HTTPASM_FIELD_FLAG_NEVER_INDEXED
    jnz     .never
    cmp     eax, HA_FIELD_AUTHORIZATION
    je      .never
    cmp     eax, HA_FIELD_PROXY_AUTHORIZATION
    je      .never
    cmp     eax, HA_FIELD_COOKIE
    jne     .never_set
    cmp     dword [r15 + httpasm_field.value_length], 20
    jae     .never_set
.never:
    mov     edx, 1
.never_set:
    mov     [rsp + E_NEVER], edx
    xor     edx, edx
    mov     [rsp + E_EXACT], edx
    mov     [rsp + E_NAME_INDEX], edx

    ; The static table: the entries with this name, from the generated by-id index.
    test    eax, eax
    jz      .dynamic
    lea     rcx, [rel ha_hpack_by_id]
    movzx   ecx, word [rcx + rax * 2]
    test    ecx, ecx
    jz      .dynamic
    movzx   r9d, cl                         ; how many
    shr     ecx, 8
    lea     r8, [rel ha_hpack_by_id_list]
    add     r8, rcx                         ; their indices
    movzx   eax, byte [r8]
    mov     [rsp + E_NAME_INDEX], eax
.static_entry:
    movzx   eax, byte [r8]
    lea     r10, [rel ha_hpack_static]
    shl     eax, 4
    lea     r10, [r10 + rax - 16]           ; static + (index - 1) * 16
    movzx   ecx, word [r10 + 10]
    cmp     ecx, [r15 + httpasm_field.value_length]
    jne     .static_next
    mov     esi, [r10 + 4]
    lea     rax, [rel ha_hpack_text]
    add     rsi, rax
    mov     rdi, [r15 + httpasm_field.value]
    test    rcx, rcx                        ; ZF = 1 for empty values, which repe leaves alone
    repe    cmpsb
    jne     .static_next
    movzx   eax, byte [r8]
    mov     [rsp + E_EXACT], eax
    jmp     .choose
.static_next:
    inc     r8
    dec     r9d
    jnz     .static_entry

.dynamic:
    ; The dynamic table, newest first: an exact match, else the first entry with the name.
    mov     r9d, 1                          ; k: 1 = the newest
.dynamic_entry:
    cmp     r9d, [rbx + hpack.count]
    ja      .choose
    mov     eax, [rbx + hpack.head]
    sub     eax, r9d
    inc     eax
    and     eax, [rbx + hpack.ring_mask]
    mov     eax, [rbx + HA_HPACK_HEADER + rax * 4]
    mov     r10d, [rbx + hpack.data_offset]
    add     r10, rbx
    add     r10, rax                        ; the entry
    mov     eax, [rsp + E_ID]
    test    eax, eax
    jz      .compare_name
    cmp     eax, [r10 + 8]                  ; a known name: the ids say it
    jne     .dynamic_next
    jmp     .same_name
.compare_name:
    mov     ecx, [r10]
    cmp     ecx, [r15 + httpasm_field.name_length]
    jne     .dynamic_next
    cmp     dword [r10 + 8], 0
    jne     .dynamic_next                   ; a known name cannot equal an unknown one
    lea     rsi, [r10 + HA_HPACK_ENTRY_HEADER]
    mov     rdi, [r15 + httpasm_field.name]
    test    rcx, rcx
    repe    cmpsb
    jne     .dynamic_next
.same_name:
    cmp     dword [rsp + E_NAME_INDEX], 0
    jne     .name_known
    lea     eax, [r9 + HA_HPACK_STATIC_COUNT]
    mov     [rsp + E_NAME_INDEX], eax
.name_known:
    mov     ecx, [r10 + 4]
    cmp     ecx, [r15 + httpasm_field.value_length]
    jne     .dynamic_next
    mov     esi, [r10]
    lea     rsi, [r10 + rsi + HA_HPACK_ENTRY_HEADER]
    mov     rdi, [r15 + httpasm_field.value]
    test    rcx, rcx
    repe    cmpsb
    jne     .dynamic_next
    lea     eax, [r9 + HA_HPACK_STATIC_COUNT]
    mov     [rsp + E_EXACT], eax
    jmp     .choose
.dynamic_next:
    inc     r9d
    jmp     .dynamic_entry

.choose:
    mov     edx, [rsp + E_EXACT]
    test    edx, edx
    jz      .literal
    cmp     dword [rsp + E_NEVER], 0
    jne     .literal                        ; never indexed keeps its literal form (RFC7541-6.2.3-p6#1)
    mov     eax, 0x80
    mov     ecx, 127
    call    hp_int_encode
    jmp     .next_field

.literal:
    mov     dword [rsp + E_INC], 0
    cmp     dword [rsp + E_NEVER], 0
    jne     .never_literal
    test    word [r15 + httpasm_field.flags], HTTPASM_FIELD_FLAG_NO_INDEX
    jnz     .plain_literal
    test    dword [rbx + hpack.flags], HTTPASM_HPACK_INDEX_ALL
    jnz     .fits_check
    mov     eax, [rsp + E_ID]
    cmp     eax, HA_FIELD_PSEUDO_PATH       ; fields that rarely repeat would only push useful
    je      .plain_literal                  ; entries out
    cmp     eax, HA_FIELD_AGE
    je      .plain_literal
    cmp     eax, HA_FIELD_CONTENT_LENGTH
    je      .plain_literal
    cmp     eax, HA_FIELD_ETAG
    je      .plain_literal
    cmp     eax, HA_FIELD_IF_MODIFIED_SINCE
    je      .plain_literal
    cmp     eax, HA_FIELD_IF_NONE_MATCH
    je      .plain_literal
    cmp     eax, HA_FIELD_LOCATION
    je      .plain_literal
    cmp     eax, HA_FIELD_SET_COOKIE
    je      .plain_literal
.fits_check:
    mov     eax, [r15 + httpasm_field.name_length]
    mov     ecx, [r15 + httpasm_field.value_length]
    add     rax, rcx
    add     rax, HA_HPACK_ENTRY_OVERHEAD
    shl     rax, 2                          ; entry * 4 > max * 3: more than 3/4 of the table
    mov     ecx, [rbx + hpack.max_size]
    lea     rcx, [rcx + rcx * 2]
    cmp     rax, rcx
    ja      .plain_literal
    mov     dword [rsp + E_INC], 1
    mov     edx, [rsp + E_NAME_INDEX]
    mov     eax, 0x40
    mov     ecx, 63
    call    hp_int_encode
    jmp     .literal_name
.never_literal:
    mov     edx, [rsp + E_NAME_INDEX]
    mov     eax, 0x10
    mov     ecx, 15
    call    hp_int_encode
    jmp     .literal_name
.plain_literal:
    mov     edx, [rsp + E_NAME_INDEX]
    xor     eax, eax
    mov     ecx, 15
    call    hp_int_encode
.literal_name:
    cmp     dword [rsp + E_NAME_INDEX], 0
    jne     .literal_value
    mov     rsi, [r15 + httpasm_field.name]
    mov     ecx, [r15 + httpasm_field.name_length]
    call    hp_string_encode
.literal_value:
    mov     rsi, [r15 + httpasm_field.value]
    mov     ecx, [r15 + httpasm_field.value_length]
    call    hp_string_encode
    cmp     dword [rsp + E_INC], 0
    je      .next_field
    ; The decoder adds it too: so does the encoder, from the caller's strings (never from the
    ; table itself, which hp_reserve may move).
    mov     esi, [r15 + httpasm_field.name_length]
    add     esi, [r15 + httpasm_field.value_length]
    add     esi, HA_HPACK_ENTRY_HEADER
    call    hp_reserve
    lea     rdi, [rax + HA_HPACK_ENTRY_HEADER]
    mov     rsi, [r15 + httpasm_field.name]
    mov     ecx, [r15 + httpasm_field.name_length]
    rep     movsb
    mov     rsi, [r15 + httpasm_field.value]
    mov     ecx, [r15 + httpasm_field.value_length]
    rep     movsb
    mov     ecx, [r15 + httpasm_field.name_length]
    mov     edx, [r15 + httpasm_field.value_length]
    mov     esi, [rsp + E_ID]
    call    hp_commit

.next_field:
    add     r12, httpasm_field_size
    dec     r13d
    jmp     .field

.done:
    mov     rax, r14
    sub     rax, rbp
    jmp     .out
.too_small:
    xor     eax, eax
.out:
    add     rsp, E_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
.end:
