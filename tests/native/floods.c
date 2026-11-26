/*
 * floods.c - the published HTTP/2 floods against an HttpAsm server in this process, each one
 * measured (docs/DESIGN.md phase H step 3, "the published attack corpora"; RFC 9113 10.5).
 *
 * For each flood the program checks three things:
 *   - the outcome: served (the flood's closing PING is answered, no GOAWAY) or cut with GOAWAY
 *     ENHANCE_YOUR_CALM, as the flood must be;
 *   - the server's CPU per octet of the flood (this process's CPU time minus the client's own
 *     two threads'), against a baseline flood's: no frame may cost much more than its size,
 *     however it is repeated (FLOOD_CPU_FACTOR times the baseline's octet at most). The
 *     baseline of the frame floods is a PING flood (the cheapest frame with an answer); that of
 *     the HPACK bomb is a block of the same size made of static references;
 *   - for the floods whose client never reads, the peak heap above where it started: malloc,
 *     calloc, realloc and free are interposed and count every block's usable size. A server
 *     that queues answers for a peer that does not read must stop reading instead
 *     (CVE-2019-9512, 9515): FLOOD_HEAP_LIMIT at most.
 *
 * The floods, each named with what published it:
 *   ping               CVE-2019-9512 (the baseline): PING frames, each answered
 *   settings           CVE-2019-9515: empty SETTINGS frames, each acknowledged
 *   settings-windows   RFC 9113 10.5: SETTINGS frames of 2,730 INITIAL_WINDOW_SIZE values each,
 *                      100 streams open (each value used to walk every stream)
 *   window-update      WINDOW_UPDATE on stream 0, 100 streams open and nothing waiting
 *   window-update-each WINDOW_UPDATE on each of 100 open streams in turn (the stream lookup)
 *   data-dribble       CVE-2019-9511: a 256 KiB answer pulled out 1 octet per WINDOW_UPDATE
 *   priority           CVE-2019-9513: PRIORITY frames (must end in ENHANCE_YOUR_CALM)
 *   empty-frames       CVE-2019-9518: empty DATA frames without END_STREAM (likewise)
 *   unknown-frames     RFC 9113 5.5: frames of an unknown type (likewise)
 *   rapid-reset        CVE-2023-44487: streams opened and reset at once (likewise)
 *   made-you-reset     CVE-2025-8671: streams the server is made to reset (likewise)
 *   continuation       CVE-2024-27316: a field block that never ends (likewise)
 *   empty-headers      CVE-2019-9516: field blocks of empty names and values (refused, no
 *                      memory kept)
 *   hpack-plain        the HPACK baseline: blocks of 16,000 one-octet static references
 *   hpack-bomb         RFC 7541 7.3: blocks of 16,000 one-octet references to a 400-octet
 *                      dynamic entry (each used to copy the entry)
 *   ping-unread        CVE-2019-9512 with a client that never reads: the heap must stay bounded
 *   settings-unread    CVE-2019-9515 likewise
 *   refused-heads      RFC 9113 10.5: requests refused before any handler (417: an expectation
 *                      the server cannot meet), each a head decoded and an answer for nothing
 *                      (must end in ENHANCE_YOUR_CALM)
 *   closed-stream-data RFC 9113 5.1: DATA on streams the client reset, each a stream error
 *                      answered with RST_STREAM (likewise; plain GETs between keep the
 *                      rapid-reset rule from ending it first)
 *   oversized-uploads  RFC 9113 10.5: uploads past max_body (1,024 octets on this server),
 *                      each refused 413 (likewise)
 *
 * The CPU figures are the fastest of FLOOD_RUNS runs (the host's noise only ever adds), and are
 * printed per KiB of flood. Exit status: 0 when every check held; 1 with the failures listed.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "httpasm.h"

/* FLOOD_CPU_FACTOR: the most a flood's octet may cost the server, as a multiple of its
 * baseline's. The fixed defects measured 5x to 100x; the frames that do their work cost 0.1x
 * to 2x of a PING's. FLOOD_HEAP_LIMIT: the most the heap may grow while a client floods without
 * reading (the output's back-pressure mark is 1 MiB; its buffer may hold twice that). */
#define FLOOD_CPU_FACTOR 4.0
#define FLOOD_HEAP_LIMIT (4L << 20)
#define FLOOD_RUNS 3
#define FLOOD_VOLUME (4L << 20)    /* the octets of each measured flood */
#define FLOOD_UNREAD_VOLUME (16L << 20) /* an unread flood's: more than every kernel buffer holds */
#define FLOOD_UNREAD_RCVBUF 4096   /* an unread flood's receive buffer: the server's answers cannot
                                      hide in the client's kernel buffer */

/* ---- The heap, counted: every block's usable size, live and at its peak. */
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);

static _Atomic long heap_live;     /* octets in live blocks */
static _Atomic long heap_peak;     /* the most heap_live reached since the last heap_mark */

/* heap_add: counts n octets more (or fewer, when negative), and the peak. */
static void heap_add(long n)
{
    long now = atomic_fetch_add_explicit(&heap_live, n, memory_order_relaxed) + n;
    long peak = atomic_load_explicit(&heap_peak, memory_order_relaxed);
    while (now > peak && !atomic_compare_exchange_weak_explicit(&heap_peak, &peak, now, memory_order_relaxed, memory_order_relaxed)) {
    }
}

/* heap_mark: the peak starts over from what is live now. Returns that. */
static long heap_mark(void)
{
    long live = atomic_load(&heap_live);
    atomic_store(&heap_peak, live);
    return live;
}

void *malloc(size_t n)
{
    void *p = __libc_malloc(n);
    if (p != NULL)
        heap_add((long)malloc_usable_size(p));
    return p;
}

void *calloc(size_t count, size_t n)
{
    void *p = __libc_calloc(count, n);
    if (p != NULL)
        heap_add((long)malloc_usable_size(p));
    return p;
}

void *realloc(void *old, size_t n)
{
    long before = old != NULL ? (long)malloc_usable_size(old) : 0;
    void *p = __libc_realloc(old, n);
    if (p != NULL)
        heap_add((long)malloc_usable_size(p) - before);
    else if (n == 0 && old != NULL)
        heap_add(-before);               /* glibc's realloc(p, 0) frees p */
    return p;
}

void free(void *p)
{
    if (p != NULL) {
        heap_add(-(long)malloc_usable_size(p));
        __libc_free(p);
    }
}

/* ---- Clocks. */

/* clock_ns: a clock's reading in nanoseconds. */
static int64_t clock_ns(clockid_t clock)
{
    struct timespec t;
    clock_gettime(clock, &t);
    return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

/* ---- Frames (RFC 9113 4.1) and the client's field blocks. */

enum { DATA = 0, HEADERS = 1, PRIORITY = 2, RST_STREAM = 3, SETTINGS = 4, PING = 6, GOAWAY = 7, WINDOW_UPDATE = 8, CONTINUATION = 9 };
enum { END_STREAM = 1, ACK = 1, END_HEADERS = 4 };

/* Request heads made of HPACK's static entries and a literal never added to the table, so any
 * number of them leaves both tables as they were: GET or POST, http, :path / or /big,
 * :authority "a" (a literal without indexing, name 1). */
static const uint8_t head_get[] = { 0x82, 0x86, 0x84, 0x01, 0x01, 'a' };
static const uint8_t head_post[] = { 0x83, 0x86, 0x84, 0x01, 0x01, 'a' };
static const uint8_t head_big[] = { 0x82, 0x86, 0x04, 0x04, '/', 'b', 'i', 'g', 0x01, 0x01, 'a' };
/* A GET with "expect: x" (a literal without indexing, new name): an expectation the server
 * cannot meet, refused with 417 before any handler (RFC 9110 10.1.1). */
static const uint8_t head_expect[] = { 0x82, 0x86, 0x84, 0x01, 0x01, 'a', 0x00, 0x06, 'e', 'x', 'p', 'e', 'c', 't', 0x01, 'x' };

/* The closing PING's payload: its ACK says the server took everything before it. */
static const uint8_t end_mark[8] = { 'F', 'L', 'O', 'O', 'D', 'E', 'N', 'D' };

/* bytes: a growable octet buffer the floods are built into, before any measurement. */
typedef struct bytes {
    uint8_t *data;
    size_t length;
    size_t capacity;
} bytes;

/* put: appends n octets. Exits when memory runs out (nothing to measure then). */
static void put(bytes *b, const void *octets, size_t n)
{
    if (b->length + n > b->capacity) {
        size_t capacity = b->capacity ? b->capacity * 2 : 65536;
        while (capacity < b->length + n)
            capacity *= 2;
        b->data = realloc(b->data, capacity);
        if (b->data == NULL) {
            fprintf(stderr, "floods: out of memory building a flood\n");
            exit(2);
        }
        b->capacity = capacity;
    }
    memcpy(b->data + b->length, octets, n);
    b->length += n;
}

/* frame: appends a frame: the 9-octet header, then the payload. */
static void frame(bytes *b, uint8_t type, uint8_t flags, uint32_t stream, const void *payload, uint32_t length)
{
    uint8_t h[9] = { (uint8_t)(length >> 16), (uint8_t)(length >> 8), (uint8_t)length, type, flags,
                     (uint8_t)(stream >> 24), (uint8_t)(stream >> 16), (uint8_t)(stream >> 8), (uint8_t)stream };
    put(b, h, sizeof h);
    if (length > 0)
        put(b, payload, length);
}

/* u32_frame: appends a frame whose payload is one big-endian 32-bit value. */
static void u32_frame(bytes *b, uint8_t type, uint32_t stream, uint32_t value)
{
    uint8_t v[4] = { (uint8_t)(value >> 24), (uint8_t)(value >> 16), (uint8_t)(value >> 8), (uint8_t)value };
    frame(b, type, 0, stream, v, 4);
}

/* open_streams: appends HEADERS for n POST requests without END_STREAM (streams 1, 3, ...):
 * open, their handlers not run, nothing to send - streams a flood can name or walk. */
static void open_streams(bytes *b, int n)
{
    for (int i = 0; i < n; i++)
        frame(b, HEADERS, END_HEADERS, 1 + 2 * (uint32_t)i, head_post, sizeof head_post);
}

/* ---- The server. */

static uint8_t big_body[262144];       /* /big's answer */

/* handler: /big answers 256 KiB; anything else "ok". */
static void handler(void *context, httpasm_exchange *exchange)
{
    (void)context;
    const httpasm_request *r = httpasm_exchange_request(exchange);
    if (r->target_length == 4 && memcmp(r->target, "/big", 4) == 0)
        httpasm_exchange_respond(exchange, 200, NULL, 0, big_body, sizeof big_body);
    else
        httpasm_exchange_respond(exchange, 200, NULL, 0, (const uint8_t *)"ok", 2);
}

/* ---- One connection, and its reader. */

typedef struct conn {
    int fd;
    pthread_t reader;
    int reading;                       /* the reader thread runs */
    _Atomic int marks;                 /* closing PINGs answered so far */
    _Atomic int closed;                /* the server ended the connection */
    _Atomic int goaway;                /* the GOAWAY's error code, or -1 */
    _Atomic long data;                 /* DATA octets received */
    _Atomic long data_frames;
    _Atomic int64_t reader_cpu_end;    /* the reader's CPU ns as it ended: its clock is gone then */
} conn;

/* reader_main: reads the server's frames until the connection ends: records a GOAWAY's code,
 * DATA, and each ACK of the closing PING. */
static void *reader_main(void *argument)
{
    conn *c = argument;
    enum { CAPACITY = 1 << 20 };                    /* any whole frame fits (16,393 at most) */
    uint8_t *buffer = malloc(CAPACITY);
    size_t have = 0;
    for (; buffer != NULL;) {
        ssize_t n = recv(c->fd, buffer + have, CAPACITY - have, 0);
        if (n <= 0)
            break;
        have += (size_t)n;
        size_t at = 0;
        while (have - at >= 9) {
            uint32_t length = (uint32_t)buffer[at] << 16 | (uint32_t)buffer[at + 1] << 8 | buffer[at + 2];
            if (have - at < 9 + (size_t)length)
                break;
            const uint8_t *p = buffer + at + 9;
            switch (buffer[at + 3]) {
            case GOAWAY:
                if (length >= 8)
                    atomic_store(&c->goaway, (int)((uint32_t)p[4] << 24 | (uint32_t)p[5] << 16 | (uint32_t)p[6] << 8 | p[7]));
                break;
            case PING:
                if ((buffer[at + 4] & ACK) && length == 8 && memcmp(p, end_mark, 8) == 0)
                    atomic_fetch_add(&c->marks, 1);
                break;
            case DATA:
                atomic_fetch_add(&c->data, (long)length);
                atomic_fetch_add(&c->data_frames, 1);
                break;
            default:
                break;
            }
            at += 9 + length;
        }
        memmove(buffer, buffer + at, have - at);
        have -= at;
    }
    free(buffer);
    /* Its CPU clock ends with it, so the measurement of a flood the server cut (the reader
     * ends with the connection) takes the last reading from here. */
    atomic_store(&c->reader_cpu_end, clock_ns(CLOCK_THREAD_CPUTIME_ID));
    atomic_store(&c->closed, 1);
    return NULL;
}

/* reader_cpu: the reader thread's CPU time in ns: its clock while it runs, else what it
 * recorded as it ended (a clock of an ended thread cannot be read). */
static int64_t reader_cpu(conn *c, clockid_t clock)
{
    struct timespec t;
    if (!atomic_load(&c->closed) && clock_gettime(clock, &t) == 0)
        return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
    while (!atomic_load(&c->closed))
        usleep(100);                    /* ending right now: its last reading is coming */
    return atomic_load(&c->reader_cpu_end);
}

/* connect_h2: a connection with the client's preface and a SETTINGS frame (settings: pairs of
 * identifier and value, count pairs), and its reader started unless `unread`. Returns 0, or -1. */
static int connect_h2(conn *c, uint16_t port, const uint32_t *settings, int count, int unread)
{
    memset(c, 0, sizeof *c);
    atomic_store(&c->goaway, -1);
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0)
        return -1;
    if (unread) {
        /* Before connect, so the window offered from the start is small: the server's answers
         * must pile up on its side, where the back-pressure is to stop them. */
        int size = FLOOD_UNREAD_RCVBUF;
        setsockopt(c->fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof size);
    }
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (connect(c->fd, (struct sockaddr *)&to, sizeof to) != 0)
        return -1;
    bytes b = { 0 };
    put(&b, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
    uint8_t payload[6 * 8];
    for (int i = 0; i < count; i++) {
        uint32_t id = settings[2 * i], value = settings[2 * i + 1];
        uint8_t *s = payload + 6 * i;
        s[0] = (uint8_t)(id >> 8);
        s[1] = (uint8_t)id;
        s[2] = (uint8_t)(value >> 24);
        s[3] = (uint8_t)(value >> 16);
        s[4] = (uint8_t)(value >> 8);
        s[5] = (uint8_t)value;
    }
    frame(&b, SETTINGS, 0, 0, payload, (uint32_t)(6 * count));
    ssize_t sent = send(c->fd, b.data, b.length, MSG_NOSIGNAL);
    free(b.data);
    if (sent != (ssize_t)b.length)
        return -1;
    if (!unread) {
        if (pthread_create(&c->reader, NULL, reader_main, c) != 0)
            return -1;
        c->reading = 1;
    }
    return 0;
}

/* send_all: sends octets on a blocking socket. Returns 0, or -1 when the server ended the
 * connection (an expected end for the floods it cuts). */
static int send_all(int fd, const uint8_t *p, size_t n)
{
    while (n > 0) {
        ssize_t sent = send(fd, p, n, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += sent;
        n -= (size_t)sent;
    }
    return 0;
}

/* wait_marks: waits until `marks` closing PINGs were answered or the connection ended, for up
 * to 30 s. Returns 1 when answered, 0 when ended, -1 on the timeout. */
static int wait_marks(conn *c, int marks)
{
    int64_t until = clock_ns(CLOCK_MONOTONIC) + 30000000000LL;
    while (clock_ns(CLOCK_MONOTONIC) < until) {
        if (atomic_load(&c->marks) >= marks)
            return 1;
        if (atomic_load(&c->closed))
            return 0;
        usleep(200);
    }
    return -1;
}

/* close_conn: closes the connection and joins its reader. */
static void close_conn(conn *c)
{
    shutdown(c->fd, SHUT_RDWR);
    if (c->reading)
        pthread_join(c->reader, NULL);
    close(c->fd);
}

/* ---- The floods. */

enum { SERVED = 0, CALM = 1 };

typedef struct flood {
    const char *name;
    const char *source;                /* what published it */
    int expect;                        /* SERVED, or CALM: GOAWAY ENHANCE_YOUR_CALM */
    int unread;                        /* the client does not read while it floods */
    const char *baseline;              /* whose CPU per octet bounds this one's (NULL: none) */
    uint32_t settings[4];              /* the client's SETTINGS (pairs), before the setup */
    int settings_count;
    void (*setup)(bytes *b);           /* frames before the measured part, or NULL */
    void (*make)(bytes *b);            /* the measured flood */
} flood;

/* Setups. */
static void setup_streams(bytes *b) { open_streams(b, 100); }
static void setup_open_one(bytes *b) { open_streams(b, 1); }
static void setup_dribble(bytes *b)
{
    u32_frame(b, WINDOW_UPDATE, 0, 0x7FFFFFFF - 65535);            /* the connection's window: no limit */
    frame(b, HEADERS, END_HEADERS | END_STREAM, 1, head_big, sizeof head_big);  /* 256 KiB, window 0 */
}
static void setup_bomb(bytes *b)
{
    /* One literal with incremental indexing: "x-bomb" with a 400-octet value becomes dynamic
     * entry 62. 128 references fill max_fields with 51,840 octets of 65,536, so the space still
     * had room: each later reference used to copy the 406 octets again. The block is no request
     * (no pseudo-fields): 400 and a reset, and the entry stays. */
    uint8_t block[11 + 400] = {
        0x40,                                                       /* literal, incremental indexing, new name */
        0x06, 'x', '-', 'b', 'o', 'm', 'b',                         /* the name, raw */
        0x7F, 0x91, 0x02,                                           /* the value's length: 400 = 127 + 273 */
    };
    memset(block + 11, 'v', 400);
    frame(b, HEADERS, END_HEADERS | END_STREAM, 1, block, sizeof block);
}

/* flood_volume: the octets the next flood is built to (FLOOD_VOLUME, or FLOOD_UNREAD_VOLUME
 * for a flood the client does not read): set by run() before it builds one. */
static long flood_volume = FLOOD_VOLUME;

/* Floods: each fills flood_volume octets or so with its frames. */
static void make_ping(bytes *b)
{
    while (b->length < (size_t)flood_volume)
        frame(b, PING, 0, 0, "pingping", 8);
}
static void make_settings(bytes *b)
{
    while (b->length < (size_t)flood_volume)
        frame(b, SETTINGS, 0, 0, NULL, 0);
}
static void make_settings_windows(bytes *b)
{
    /* 2,730 values a frame (16,380 octets), 65,534 and 65,535 by turns: each frame's net change
     * is 0, and each value moved every open stream's window. */
    static uint8_t payload[2730 * 6];
    for (int i = 0; i < 2730; i++) {
        uint8_t *s = payload + 6 * i;
        uint32_t value = (i & 1) ? 65535 : 65534;
        s[0] = 0;
        s[1] = 4;
        s[2] = 0;
        s[3] = 0;
        s[4] = (uint8_t)(value >> 8);
        s[5] = (uint8_t)value;
    }
    while (b->length < (size_t)flood_volume)
        frame(b, SETTINGS, 0, 0, payload, sizeof payload);
}
static void make_window_update(bytes *b)
{
    while (b->length < (size_t)flood_volume)
        u32_frame(b, WINDOW_UPDATE, 0, 1);
}
static void make_window_update_each(bytes *b)
{
    for (uint32_t i = 0; b->length < (size_t)flood_volume; i++)
        u32_frame(b, WINDOW_UPDATE, 1 + 2 * (i % 100), 1);
}
static void make_dribble(bytes *b)
{
    for (int i = 0; i < 262144; i++)
        u32_frame(b, WINDOW_UPDATE, 1, 1);                          /* 1 octet more each */
}
static void make_priority(bytes *b)
{
    static const uint8_t p[5] = { 0, 0, 0, 0, 15 };                 /* on idle stream 3, depending on 0 */
    for (int i = 0; i < 20000; i++)
        frame(b, PRIORITY, 0, 3, p, 5);
}
static void make_empty_frames(bytes *b)
{
    for (int i = 0; i < 20000; i++)
        frame(b, DATA, 0, 1, NULL, 0);
}
static void make_unknown_frames(bytes *b)
{
    for (int i = 0; i < 20000; i++)
        frame(b, 0xFE, 0, 0, NULL, 0);
}
static void make_rapid_reset(bytes *b)
{
    for (uint32_t i = 0; i < 1000; i++) {
        frame(b, HEADERS, END_HEADERS, 1 + 2 * i, head_post, sizeof head_post);
        u32_frame(b, RST_STREAM, 1 + 2 * i, 8);                     /* CANCEL */
    }
}
static void make_made_you_reset(bytes *b)
{
    /* The client's window is 0 (its SETTINGS): each answer's DATA waits, its stream active;
     * a WINDOW_UPDATE of 0 on it makes the server reset it. */
    for (uint32_t i = 0; i < 1000; i++) {
        frame(b, HEADERS, END_HEADERS | END_STREAM, 1 + 2 * i, head_get, sizeof head_get);
        u32_frame(b, WINDOW_UPDATE, 1 + 2 * i, 0);
    }
}
static void make_continuation(bytes *b)
{
    frame(b, HEADERS, END_STREAM, 1, head_get, 1);                  /* the block cut after 1 octet */
    for (int i = 0; i < 1000; i++)
        frame(b, CONTINUATION, 0, 1, NULL, 0);
}
static void make_empty_headers(bytes *b)
{
    /* 5,000 fields of empty name and value a block (a literal without indexing, new name: 00 00
     * 00), each block a new stream: past max_fields, refused with 431, nothing kept. */
    static uint8_t block[15000];
    memset(block, 0, sizeof block);
    for (uint32_t i = 0; b->length < (size_t)flood_volume; i++)
        frame(b, HEADERS, END_HEADERS | END_STREAM, 3 + 2 * i, block, sizeof block);
}
static void make_hpack_blocks(bytes *b, uint8_t reference)
{
    static uint8_t block[16000];
    memset(block, reference, sizeof block);
    for (uint32_t i = 0; b->length < (size_t)flood_volume; i++)
        frame(b, HEADERS, END_HEADERS | END_STREAM, 3 + 2 * i, block, sizeof block);
}
static void make_hpack_plain(bytes *b) { make_hpack_blocks(b, 0x82); }    /* :method GET, static */
static void make_hpack_bomb(bytes *b) { make_hpack_blocks(b, 0xBE); }     /* dynamic entry 62 */
static void setup_open_windows(bytes *b)
{
    /* The connection's window opened all the way (the client's SETTINGS opened every
     * stream's): the refusals' answers go out whole and their streams end, so none piles up
     * against MAX_CONCURRENT_STREAMS. With the windows at 65,535 the answers' bodies waited,
     * their streams stayed, and the flood met the refused-stream path's glitches instead of
     * its own (measured: 65,535 DATA octets came, and the refusal's glitch site never ran). */
    u32_frame(b, WINDOW_UPDATE, 0, 0x7FFFFFFF - 65535);
}
static void make_refused_heads(bytes *b)
{
    /* Requests refused before any handler, each costing a decoded head and an answer (417 to
     * an expectation; 431 and 413 are refused the same way), and moving nothing: a glitch each
     * (h2_block_done's .refusal), so a stream of them must end in ENHANCE_YOUR_CALM. */
    for (uint32_t i = 0; i < 20000; i++)
        frame(b, HEADERS, END_HEADERS | END_STREAM, 3 + 2 * i, head_expect, sizeof head_expect);
}
static void make_closed_stream_data(bytes *b)
{
    /* DATA on a stream the client itself reset: a stream error STREAM_CLOSED the server must
     * answer with RST_STREAM (RFC 9113 5.1), on a stream that frees no slot (it is not active
     * any more): a glitch (h2_peer_stream_error). Only the first such frame is one: the
     * server's RST_STREAM makes it a stream this side reset, whose later frames are in flight
     * and ignored (RFC 9113 5.4.2), cheap as any frame. So each round uses a stream of its own:
     * an upload opened and cancelled by the client, then one octet of DATA on it (an empty
     * frame would be the empty-frames flood's glitch, counted before the stream is looked up).
     * Two plain GETs a round keep the resets under one for every two streams opened, so the
     * rapid-reset rule does not end it first: the glitches must. */
    for (uint32_t i = 0; i < 12000; i++) {
        uint32_t id = 1 + 6 * i;
        frame(b, HEADERS, END_HEADERS | END_STREAM, id, head_get, sizeof head_get);
        frame(b, HEADERS, END_HEADERS | END_STREAM, id + 2, head_get, sizeof head_get);
        frame(b, HEADERS, END_HEADERS, id + 4, head_post, sizeof head_post);
        u32_frame(b, RST_STREAM, id + 4, 8);                            /* CANCEL */
        frame(b, DATA, 0, id + 4, "x", 1);
    }
}
static void make_oversized_uploads(bytes *b)
{
    /* Uploads past the server's max_body (1,024 octets here): each refused 413 the moment its
     * DATA goes past, a glitch each (h2_data's .too_large). Each ends its stream with that DATA,
     * so none stays open to count against MAX_CONCURRENT_STREAMS. */
    static uint8_t body[1025];
    memset(body, 'u', sizeof body);
    for (uint32_t i = 0; i < 12000; i++) {
        frame(b, HEADERS, END_HEADERS, 3 + 2 * i, head_post, sizeof head_post);
        frame(b, DATA, END_STREAM, 3 + 2 * i, body, sizeof body);
    }
}

static const flood floods[] = {
    { "ping", "CVE-2019-9512", SERVED, 0, NULL, { 0 }, 0, NULL, make_ping },
    { "settings", "CVE-2019-9515", SERVED, 0, "ping", { 0 }, 0, NULL, make_settings },
    { "settings-windows", "RFC 9113 10.5", SERVED, 0, "ping", { 0 }, 0, setup_streams, make_settings_windows },
    { "window-update", "RFC 9113 10.5", SERVED, 0, "ping", { 0 }, 0, setup_streams, make_window_update },
    { "window-update-each", "RFC 9113 10.5", SERVED, 0, "ping", { 0 }, 0, setup_streams, make_window_update_each },
    { "data-dribble", "CVE-2019-9511", SERVED, 0, "ping", { 4, 0 }, 1, setup_dribble, make_dribble },
    { "priority", "CVE-2019-9513", CALM, 0, NULL, { 0 }, 0, NULL, make_priority },
    { "empty-frames", "CVE-2019-9518", CALM, 0, NULL, { 0 }, 0, setup_open_one, make_empty_frames },
    { "unknown-frames", "RFC 9113 5.5", CALM, 0, NULL, { 0 }, 0, NULL, make_unknown_frames },
    { "rapid-reset", "CVE-2023-44487", CALM, 0, NULL, { 0 }, 0, NULL, make_rapid_reset },
    { "made-you-reset", "CVE-2025-8671", CALM, 0, NULL, { 4, 0 }, 1, NULL, make_made_you_reset },
    { "continuation", "CVE-2024-27316", CALM, 0, NULL, { 0 }, 0, NULL, make_continuation },
    { "hpack-plain", "RFC 7541 7.3", SERVED, 0, NULL, { 0 }, 0, setup_bomb, make_hpack_plain },
    { "hpack-bomb", "RFC 7541 7.3", SERVED, 0, "hpack-plain", { 0 }, 0, setup_bomb, make_hpack_bomb },
    { "empty-headers", "CVE-2019-9516", SERVED, 0, "hpack-plain", { 0 }, 0, NULL, make_empty_headers },
    { "ping-unread", "CVE-2019-9512", SERVED, 1, NULL, { 0 }, 0, NULL, make_ping },
    { "settings-unread", "CVE-2019-9515", SERVED, 1, NULL, { 0 }, 0, NULL, make_settings },
    { "refused-heads", "RFC 9113 10.5", CALM, 0, NULL, { 4, 0x7FFFFFFF }, 1, setup_open_windows, make_refused_heads },
    { "closed-stream-data", "RFC 9113 5.1", CALM, 0, NULL, { 0 }, 0, NULL, make_closed_stream_data },
    { "oversized-uploads", "RFC 9113 10.5", CALM, 0, NULL, { 4, 0x7FFFFFFF }, 1, setup_open_windows, make_oversized_uploads },
};
#define FLOOD_COUNT ((int)(sizeof floods / sizeof floods[0]))

/* result: one flood's measurements. */
typedef struct result {
    int outcome;                       /* SERVED, CALM, or -1 (anything else) */
    int goaway;                        /* the GOAWAY's code, or -1 */
    long octets;                       /* the flood's octets sent */
    double ns_per_kib;                 /* the server's CPU per KiB of flood */
    long heap_growth;                  /* the peak heap above the start (unread floods) */
    long data;                         /* DATA octets received */
    long data_frames;
} result;

/* send_unread: floods a server whose answers the client never reads: sends without blocking
 * until the server stops taking octets (no progress for 500 ms) or the whole flood is out.
 * Returns the octets sent. */
static long send_unread(int fd, const uint8_t *p, size_t n)
{
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    long total = 0;
    int64_t last = clock_ns(CLOCK_MONOTONIC);
    while ((size_t)total < n && clock_ns(CLOCK_MONOTONIC) - last < 500000000LL) {
        ssize_t sent = send(fd, p + total, n - (size_t)total, MSG_NOSIGNAL);
        if (sent > 0) {
            total += sent;
            last = clock_ns(CLOCK_MONOTONIC);
        } else if (sent < 0 && errno != EAGAIN && errno != EINTR) {
            break;
        } else {
            struct pollfd w = { .fd = fd, .events = POLLOUT };
            poll(&w, 1, 50);
        }
    }
    fcntl(fd, F_SETFL, flags);
    return total;
}

/* run: one flood against the server once. */
static result run(const flood *f, uint16_t port)
{
    result r = { .outcome = -1, .goaway = -1 };
    conn c;
    if (connect_h2(&c, port, f->settings, f->settings_count, f->unread) != 0) {
        fprintf(stderr, "floods: %s: no connection\n", f->name);
        return r;
    }
    bytes setup = { 0 }, flood_bytes = { 0 }, mark = { 0 };
    if (f->setup != NULL)
        f->setup(&setup);
    flood_volume = f->unread ? FLOOD_UNREAD_VOLUME : FLOOD_VOLUME;
    f->make(&flood_bytes);
    frame(&mark, PING, 0, 0, end_mark, 8);
    r.octets = (long)flood_bytes.length;

    if (f->unread) {
        /* Nothing is read while the client floods: the server must stop reading in turn. */
        long base = heap_mark();
        r.octets = send_unread(c.fd, flood_bytes.data, flood_bytes.length);
        usleep(200000);                                             /* what was taken is handled */
        r.heap_growth = atomic_load(&heap_peak) - base;
        /* Then the client reads: everything queued drains, and the rest is taken. */
        if (pthread_create(&c.reader, NULL, reader_main, &c) == 0) {
            c.reading = 1;
            send_all(c.fd, flood_bytes.data + r.octets, flood_bytes.length - (size_t)r.octets);
            send_all(c.fd, mark.data, mark.length);
            int answered = wait_marks(&c, 1);
            r.outcome = answered == 1 && atomic_load(&c.goaway) == -1 ? SERVED : -1;
        }
    } else {
        /* The setup first, answered, so the measured part holds the flood alone. */
        send_all(c.fd, setup.data, setup.length);
        send_all(c.fd, mark.data, mark.length);
        if (wait_marks(&c, 1) != 1) {
            fprintf(stderr, "floods: %s: the setup was not answered\n", f->name);
            r.goaway = atomic_load(&c.goaway);
            close_conn(&c);
            free(setup.data);
            free(flood_bytes.data);
            free(mark.data);
            return r;
        }
        clockid_t reader_clock;
        pthread_getcpuclockid(c.reader, &reader_clock);
        int64_t process0 = clock_ns(CLOCK_PROCESS_CPUTIME_ID), main0 = clock_ns(CLOCK_THREAD_CPUTIME_ID);
        int64_t reader0 = reader_cpu(&c, reader_clock);
        int ended = send_all(c.fd, flood_bytes.data, flood_bytes.length);
        if (ended == 0)
            send_all(c.fd, mark.data, mark.length);
        int answered = wait_marks(&c, 2);
        int64_t process1 = clock_ns(CLOCK_PROCESS_CPUTIME_ID), main1 = clock_ns(CLOCK_THREAD_CPUTIME_ID);
        int64_t reader1 = reader_cpu(&c, reader_clock);
        int64_t server = (process1 - process0) - (main1 - main0) - (reader1 - reader0);
        if (server < 0)
            server = 0;                 /* the clocks are read a moment apart: a flood cut at once
                                           can come out a few microseconds below 0 */
        r.ns_per_kib = (double)server / ((double)r.octets / 1024.0);
        if (answered == 1 && atomic_load(&c.goaway) == -1)
            r.outcome = SERVED;
        else if (answered != -1 && atomic_load(&c.goaway) == 0xb)
            r.outcome = CALM;
    }
    r.goaway = atomic_load(&c.goaway);
    r.data = atomic_load(&c.data);
    r.data_frames = atomic_load(&c.data_frames);
    close_conn(&c);
    free(setup.data);
    free(flood_bytes.data);
    free(mark.data);
    return r;
}

/* selected: whether a flood is to run: every one without arguments, else those named (a
 * baseline must be named too for its floods to be compared with it). */
static int selected(const char *name, int argc, char **argv)
{
    if (argc < 2)
        return 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], name) == 0)
            return 1;
    }
    return 0;
}

/* main: runs every flood (the measured ones FLOOD_RUNS times, keeping the fastest), prints a
 * table, and checks each against its expectations. Arguments, if any, name the floods to run. */
int main(int argc, char **argv)
{
    /* The heap counter's own check: an unread flood's "+0.00 MiB" must mean the server kept
     * nothing, not a counter that missed the server's allocations. A 1 MiB block must show. */
    long before = heap_mark();
    void *probe = malloc(1 << 20);
    long grown = atomic_load(&heap_peak) - before;
    free(probe);
    if (probe == NULL || grown < (1 << 20)) {
        fprintf(stderr, "floods: the heap counter missed a 1 MiB allocation (%ld octets counted)\n", grown);
        return 1;
    }
    memset(big_body, 'b', sizeof big_body);
    httpasm_server_options o;
    memset(&o, 0, sizeof o);
    o.handler = handler;
    o.workers = 1;
    o.bind_address = htonl(INADDR_LOOPBACK);
    o.max_body = 1024;          /* the oversized-uploads flood's limit; no other flood sends a body */
    const char *io = getenv("HTTPASM_TEST_IO");
    if (io != NULL && strcmp(io, "uring") == 0)
        o.flags = HTTPASM_SERVER_URING;
    int error = 0;
    httpasm_server *s = httpasm_server_create(&o, &error);
    if (s == NULL || httpasm_server_start(s) != 0) {
        fprintf(stderr, "floods: the server did not start (%d)\n", error);
        return 1;
    }
    uint16_t port = httpasm_server_port(s);
    /* HTTPASM_FLOODS_CPU=report: the CPU ratios are printed but not enforced. The coverage run
     * sets it: its instrumented code puts a marker store in every block, which weighs on short
     * paths far more than on long ones, so its ratios say nothing about the real code's. */
    const char *cpu_mode = getenv("HTTPASM_FLOODS_CPU");
    int cpu_enforced = cpu_mode == NULL || strcmp(cpu_mode, "report") != 0;
    printf("floods: HTTP/2 floods of about %ld KiB each, the server on %s (CPU: the fastest of %d runs%s)\n", FLOOD_VOLUME >> 10,
           httpasm_server_io(s) == HTTPASM_SERVER_IO_URING ? "io_uring" : "epoll", FLOOD_RUNS,
           cpu_enforced ? "" : "; reported, not enforced");
    printf("  %-19s %-15s %-8s %10s %12s %-18s %s\n", "flood", "published as", "outcome", "KiB sent", "CPU ns/KiB", "against", "notes");

    result results[FLOOD_COUNT];
    memset(results, 0, sizeof results);
    int failures = 0, ran = 0;
    for (int i = 0; i < FLOOD_COUNT; i++) {
        const flood *f = &floods[i];
        if (!selected(f->name, argc, argv))
            continue;
        ran++;
        /* The measured floods run FLOOD_RUNS times and keep the fastest run; a run whose
         * outcome is wrong is kept instead, so the failure is reported, not averaged away. */
        int runs = f->expect == SERVED && !f->unread ? FLOOD_RUNS : 1;
        result best = run(f, port);
        for (int k = 1; k < runs && best.outcome == f->expect; k++) {
            result again = run(f, port);
            if (again.outcome != f->expect || again.ns_per_kib < best.ns_per_kib)
                best = again;
        }
        results[i] = best;
        double factor = 0;
        for (int j = 0; f->baseline != NULL && j < i; j++) {
            if (strcmp(floods[j].name, f->baseline) == 0 && results[j].ns_per_kib > 0)
                factor = best.ns_per_kib / results[j].ns_per_kib;
        }
        char cpu[24] = "", times[24] = "", notes[128] = "";
        if (!f->unread)
            snprintf(cpu, sizeof cpu, "%.0f", best.ns_per_kib);
        if (factor > 0)
            snprintf(times, sizeof times, "%.2fx %s", factor, f->baseline);
        if (f->unread)
            snprintf(notes, sizeof notes, "heap +%.2f MiB while unread", (double)best.heap_growth / (1 << 20));
        else if (best.data_frames > 0)
            snprintf(notes, sizeof notes, "%ld DATA octets in %ld frames", best.data, best.data_frames);
        const char *outcome = best.outcome == SERVED ? "served" : best.outcome == CALM ? "calm" : "WRONG";
        printf("  %-19s %-15s %-8s %10ld %12s %-18s %s\n", f->name, f->source, outcome, best.octets >> 10, cpu, times, notes);

        if (best.outcome != f->expect) {
            fprintf(stderr, "floods: %s (%s): expected %s, got %s (GOAWAY %d)\n", f->name, f->source,
                    f->expect == SERVED ? "served" : "ENHANCE_YOUR_CALM", outcome, best.goaway);
            failures++;
        }
        if (factor > FLOOD_CPU_FACTOR) {
            fprintf(stderr, "floods: %s (%s): %.2fx the CPU per octet of %s (the limit is %.1fx)%s\n", f->name, f->source, factor,
                    f->baseline, FLOOD_CPU_FACTOR, cpu_enforced ? "" : "; not enforced in this run");
            failures += cpu_enforced;
        }
        if (f->unread && best.heap_growth > FLOOD_HEAP_LIMIT) {
            fprintf(stderr, "floods: %s (%s): the heap grew %.2f MiB while the client did not read (the limit is %.1f MiB)\n", f->name,
                    f->source, (double)best.heap_growth / (1 << 20), (double)FLOOD_HEAP_LIMIT / (1 << 20));
            failures++;
        }
        if (strcmp(f->name, "data-dribble") == 0 && (best.data != (long)sizeof big_body || best.data_frames != (long)sizeof big_body)) {
            fprintf(stderr, "floods: data-dribble: %ld DATA octets in %ld frames, expected %zu in 1-octet frames\n", best.data,
                    best.data_frames, sizeof big_body);
            failures++;
        }
    }
    httpasm_server_stop(s);
    httpasm_server_destroy(s);
    printf("floods: %d floods run, %d checks failed\n", ran, failures);
    return failures == 0 ? 0 : 1;
}
