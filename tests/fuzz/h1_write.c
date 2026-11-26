/*
 * h1_write.c - fuzzes HTTP/1.1's writers (h1/write.asm): httpasm_h1_write_response,
 * httpasm_h1_write_request, httpasm_h1_write_chunk and httpasm_h1_write_last_chunk. A writer that
 * accepts a field it should refuse, or frames a body two ways, sends a peer a message that two
 * hops can read differently; so whatever a writer accepts is read back here by HttpAsm's own
 * parsers and must say exactly what the caller asked for.
 *
 * The input's first octet picks the writer (octet % 3: response, request, chunked body); the
 * rest describes the call: the status, flags, method and version, a length, and fields as
 * (name length, name, value length, value) pairs - any octets, valid or not.
 *
 * For every input it requires:
 *   - the output never passes the capacity given (it ends at an inaccessible page), and a
 *     capacity the input chooses small either fits or gets 0, after which the full capacity
 *     must give a head or a refusal;
 *   - a refusal (-HTTPASM_ERROR_*) is a documented one and leaves the output untouched;
 *   - a response head reads back (httpasm_h1_parse_response, the request's method) as exactly
 *     one head with the caller's status and fields in order, the framing the writer reported
 *     (Content-Length and its value, chunked, no body, or to the close) and the persistence it
 *     reported;
 *   - a request head reads back (httpasm_h1_parse_request) with the caller's method, target,
 *     Host (first) and fields in order, and the framing, close and Expect the flags asked for;
 *   - chunks and the last chunk with trailers decode back (httpasm_h1_chunked_decode,
 *     httpasm_h1_parse_trailers) to the same data and trailers, consuming exactly the output.
 */
#include "fuzz.h"

enum { MAX_FIELDS = 64, OUT_MAX = 65536 };

/* A cursor over the input. */
typedef struct reader {
    const uint8_t *p;
    size_t left;
} reader;

/* take: n octets (fewer when the input ends), returned as a pointer into it. */
static const uint8_t *take(reader *r, size_t *n)
{
    if (*n > r->left)
        *n = r->left;
    const uint8_t *p = r->p;
    r->p += *n;
    r->left -= *n;
    return p;
}

/* byte: the next octet, 0 past the end. */
static uint8_t byte(reader *r)
{
    size_t n = 1;
    const uint8_t *p = take(r, &n);
    return n ? *p : 0;
}

/* fields: (name length, name, value length, value) pairs to the input's end, at most max. */
static uint32_t fields(reader *r, httpasm_field *out, uint32_t max)
{
    uint32_t count = 0;
    while (r->left > 0 && count < max) {
        size_t nl = byte(r);
        const uint8_t *name = take(r, &nl);
        size_t vl = byte(r);
        const uint8_t *value = take(r, &vl);
        out[count++] = (httpasm_field){ .name = name, .name_length = (uint32_t)nl, .value = value, .value_length = (uint32_t)vl };
    }
    return count;
}

/* The output area: OUT_MAX octets that end at an inaccessible page; out() gives the last cap
 * of them, filled with a pattern so an untouched output can be told apart. */
static uint8_t *out_area(size_t cap)
{
    static uint8_t *end;
    if (end == NULL) {
        size_t pages = OUT_MAX / FUZZ_PAGE;
        uint8_t *map = mmap(NULL, (pages + 1) * FUZZ_PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map == MAP_FAILED || mprotect(map + pages * FUZZ_PAGE, FUZZ_PAGE, PROT_NONE) != 0)
            abort();
        end = map + pages * FUZZ_PAGE;
    }
    memset(end - cap, 0xA5, cap);
    return end - cap;
}

/* untouched: whether the output still holds the pattern (a refusal writes nothing). */
static int untouched(const uint8_t *out, size_t cap)
{
    for (size_t i = 0; i < cap; i++)
        if (out[i] != 0xA5)
            return 0;
    return 1;
}

/* is_name: whether a field's name is s, letters' case aside. */
static int is_name(const httpasm_field *f, const char *s)
{
    size_t n = strlen(s);
    if (f->name_length != n)
        return 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = f->name[i];
        if (c >= 'A' && c <= 'Z')
            c = (uint8_t)(c + 32);
        if (c != (uint8_t)s[i])
            return 0;
    }
    return 1;
}

/* same_octets: two fields with the same name and value. */
static int same_field(const httpasm_field *a, const httpasm_field *b)
{
    return a->name_length == b->name_length && a->value_length == b->value_length && memcmp(a->name, b->name, a->name_length) == 0
        && memcmp(a->value, b->value, a->value_length) == 0;
}

/* check_fields: the fields read back, without the writer's own (each name in own[], at most
 * once each), are the caller's, in order. */
static void check_fields(const httpasm_field *read, uint32_t nread, const httpasm_field *given, uint32_t ngiven, const char *const *own,
                         size_t nown)
{
    uint32_t g = 0;
    int used[8] = { 0 };
    for (uint32_t i = 0; i < nread; i++) {
        int writers = 0;
        for (size_t k = 0; k < nown; k++)
            if (!used[k] && is_name(&read[i], own[k])) {
                /* The writer's own: the caller can never give these (they are refused), so
                 * a match is the writer's, unless the caller's own Date stands in for it. */
                if (g < ngiven && same_field(&read[i], &given[g]))
                    break;
                used[k] = writers = 1;
                break;
            }
        if (writers)
            continue;
        FUZZ_CHECK(g < ngiven && same_field(&read[i], &given[g]), "field %u read back is not the caller's field %u", i, g);
        g++;
    }
    FUZZ_CHECK(g == ngiven, "%u of the caller's %u fields read back", g, ngiven);
}

/* The documented refusals of each writer. */
static int response_refusal(int64_t r)
{
    return r == -HTTPASM_ERROR_FIELD_NAME || r == -HTTPASM_ERROR_FIELD_VALUE || r == -HTTPASM_ERROR_FRAMING_FIELD || r == -HTTPASM_ERROR_STATUS
        || r == -HTTPASM_ERROR_CONTENT_LENGTH;
}

static int request_refusal(int64_t r)
{
    return r == -HTTPASM_ERROR_FIELD_NAME || r == -HTTPASM_ERROR_FIELD_VALUE || r == -HTTPASM_ERROR_FRAMING_FIELD || r == -HTTPASM_ERROR_METHOD
        || r == -HTTPASM_ERROR_TARGET || r == -HTTPASM_ERROR_TARGET_FORM || r == -HTTPASM_ERROR_HOST_INVALID || r == -HTTPASM_ERROR_AUTHORITY
        || r == -HTTPASM_ERROR_REQUEST_LINE || r == -HTTPASM_ERROR_CONTENT_LENGTH;
}

/* write_twice: a writer at the capacity the input chose and, when that was too small, at the
 * full capacity; the rules of this file's header on capacity and refusals. write(out, cap)
 * calls the writer. Returns the result; *out_p is where the output is. */
typedef int64_t (*writer_fn)(uint8_t *out, size_t cap, void *context);
static int64_t write_twice(writer_fn write, void *context, size_t small, int (*refusal)(int64_t), uint8_t **out_p)
{
    uint8_t *out = out_area(small);
    int64_t r = write(out, small, context);
    FUZZ_CHECK(r <= (int64_t)small, "wrote %lld octets into %zu", (long long)r, small);
    if (r < 0) {
        FUZZ_CHECK(refusal(r), "refusal %lld", (long long)r);
        FUZZ_CHECK(untouched(out, small), "a refusal (%lld) wrote output", (long long)r);
        *out_p = out;
        return r;
    }
    if (r == 0) {
        out = out_area(OUT_MAX);
        r = write(out, OUT_MAX, context);
        FUZZ_CHECK(r != 0, "too small at %d octets too", OUT_MAX);
        FUZZ_CHECK(r < 0 ? refusal(r) && untouched(out, OUT_MAX) : r <= OUT_MAX, "the full capacity gave %lld", (long long)r);
    }
    *out_p = out;
    return r;
}

static int64_t call_response(uint8_t *out, size_t cap, void *context)
{
    httpasm_response copy = *(httpasm_response *)context;    /* flags are in and out: each call starts from the caller's */
    int64_t r = httpasm_h1_write_response(out, cap, &copy);
    if (r > 0)
        *(httpasm_response *)context = copy;
    return r;
}

static int64_t call_request(uint8_t *out, size_t cap, void *context)
{
    return httpasm_h1_write_request(out, cap, (const httpasm_request *)context);
}

/* fuzz_response: the response writer, then the head read back. */
static void fuzz_response(reader *r)
{
    static httpasm_field given[MAX_FIELDS], read[128];
    static const uint8_t date[] = "Thu, 26 Nov 2026 08:00:00 GMT";
    httpasm_response resp;
    memset(&resp, 0, sizeof resp);
    /* One octet per statement: the order of two calls inside one expression is unspecified. */
    uint32_t low = byte(r), high = byte(r);
    resp.status = (uint16_t)((low | high << 8) % 1000);
    uint8_t flags = byte(r), how = byte(r);
    resp.flags = (flags & 1 ? HTTPASM_RESPONSE_LENGTH : 0) | (flags & 2 ? HTTPASM_RESPONSE_CLOSE : 0);
    resp.date = flags & 4 ? date : NULL;
    resp.request_version = how & 1 ? 10 : 11;
    resp.request_method = (uint8_t)((how >> 1) % 10);
    uint64_t top = byte(r), mid = byte(r), bottom = byte(r);
    resp.content_length = flags & 8 ? top << 56 | mid << 24 | bottom : bottom;
    size_t small = 16 + (size_t)byte(r) * 4;
    resp.field_count = fields(r, given, MAX_FIELDS);
    resp.fields = given;
    httpasm_response asked = resp;

    uint8_t *out;
    int64_t n = write_twice(call_response, &resp, small, response_refusal, &out);
    if (n < 0)
        return;
    httpasm_response_head h;
    memset(&h, 0, sizeof h);
    size_t scan = 0;
    httpasm_h1_limits limits = { .max_fields = 128 };
    int64_t back = httpasm_h1_parse_response(out, (size_t)n, &scan, &limits, asked.request_method, &h, read);
    FUZZ_CHECK(back == n, "the head (%lld octets) reads back as %lld (error %u)", (long long)n, (long long)back, h.error);
    FUZZ_CHECK(h.status == asked.status && h.version == 11, "status %u version %u, asked %u", h.status, h.version, asked.status);
    static const char *const own[] = { "content-length", "transfer-encoding", "connection", "date" };
    check_fields(read, h.field_count, given, asked.field_count, own, asked.date ? 4 : 3);

    /* The framing the writer reported is the framing that reads back. */
    uint32_t framing = h.flags & ~HTTPASM_RESPONSE_HEAD_KEEP_ALIVE;
    if (resp.flags & HTTPASM_RESPONSE_NO_BODY)
        FUZZ_CHECK(framing & HTTPASM_RESPONSE_HEAD_NO_BODY, "NO_BODY written, 0x%x read", h.flags);
    else if (resp.flags & HTTPASM_RESPONSE_CHUNKED)
        FUZZ_CHECK(framing == HTTPASM_RESPONSE_HEAD_CHUNKED, "chunked written, 0x%x read", h.flags);
    else if (asked.flags & HTTPASM_RESPONSE_LENGTH)
        FUZZ_CHECK(framing == HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH && h.content_length == asked.content_length,
                   "Content-Length %llu written, 0x%x (%llu) read", (unsigned long long)asked.content_length, h.flags,
                   (unsigned long long)h.content_length);
    else
        FUZZ_CHECK(framing == HTTPASM_RESPONSE_HEAD_UNTIL_CLOSE, "a body to the close written, 0x%x read", h.flags);
    /* Persistence, for final responses only: a 1xx is interim (its status-line and the
     * caller's fields alone, h1/write.asm), and the final response that follows it decides. */
    if (asked.status >= 200 && !(framing & HTTPASM_RESPONSE_HEAD_UNTIL_CLOSE) && !(framing & HTTPASM_RESPONSE_HEAD_TUNNEL))
        FUZZ_CHECK(((resp.flags & HTTPASM_RESPONSE_CLOSE) != 0) == ((h.flags & HTTPASM_RESPONSE_HEAD_KEEP_ALIVE) == 0),
                   "close 0x%x written, keep-alive read 0x%x", resp.flags, h.flags);
}

/* fuzz_request: the request writer, then the head read back. */
static void fuzz_request(reader *r)
{
    static httpasm_field given[MAX_FIELDS], read[128];
    httpasm_request q;
    memset(&q, 0, sizeof q);
    size_t ml = byte(r) % 16, tl = byte(r), al = byte(r) % 64;
    q.method = take(r, &ml);
    q.method_length = (uint32_t)ml;
    q.target = take(r, &tl);
    q.target_length = (uint32_t)tl;
    q.authority = take(r, &al);
    q.authority_length = (uint32_t)al;
    uint8_t flags = byte(r);
    q.flags = (flags & 1 ? HTTPASM_REQUEST_CONTENT_LENGTH : 0) | (flags & 2 ? HTTPASM_REQUEST_CHUNKED : 0)
            | (flags & 4 ? HTTPASM_REQUEST_CLOSE : 0) | (flags & 8 ? HTTPASM_REQUEST_EXPECT_CONTINUE : 0);
    q.content_length = byte(r);
    size_t small = 16 + (size_t)byte(r) * 4;
    q.field_count = fields(r, given, MAX_FIELDS);
    q.fields = given;

    uint8_t *out;
    int64_t n = write_twice(call_request, &q, small, request_refusal, &out);
    if (n < 0)
        return;
    httpasm_request back;
    memset(&back, 0, sizeof back);
    size_t scan = 0;
    httpasm_h1_limits limits = { .max_fields = 128 };
    int64_t got = httpasm_h1_parse_request(out, (size_t)n, &scan, &limits, &back, read);
    FUZZ_CHECK(got == n, "the head (%lld octets) reads back as %lld (error %u)", (long long)n, (long long)got, back.error);
    FUZZ_CHECK(back.method_length == q.method_length && memcmp(back.method, q.method, q.method_length) == 0, "another method");
    FUZZ_CHECK(back.target_length == q.target_length && memcmp(back.target, q.target, q.target_length) == 0, "another target");
    FUZZ_CHECK(back.field_count >= 1 && is_name(&read[0], "host") && read[0].value_length == q.authority_length
                   && memcmp(read[0].value, q.authority, q.authority_length) == 0,
               "Host is not first, or not the authority");
    static const char *const own[] = { "content-length", "transfer-encoding", "connection", "expect" };
    check_fields(read + 1, back.field_count - 1, given, q.field_count, own, 4);
    int chunked = (q.flags & HTTPASM_REQUEST_CHUNKED) != 0;
    FUZZ_CHECK(((back.flags & HTTPASM_REQUEST_CHUNKED) != 0) == chunked, "chunked asked %d, read 0x%x", chunked, back.flags);
    if (!chunked && (q.flags & HTTPASM_REQUEST_CONTENT_LENGTH))
        FUZZ_CHECK((back.flags & HTTPASM_REQUEST_CONTENT_LENGTH) && back.content_length == q.content_length, "the length read back differs");
    FUZZ_CHECK(((back.flags & HTTPASM_REQUEST_CLOSE) != 0) == ((q.flags & HTTPASM_REQUEST_CLOSE) != 0), "close asked 0x%x, read 0x%x", q.flags,
               back.flags);
    int content = chunked || ((q.flags & HTTPASM_REQUEST_CONTENT_LENGTH) && q.content_length > 0);
    FUZZ_CHECK(((back.flags & HTTPASM_REQUEST_EXPECT_CONTINUE) != 0) == (content && (q.flags & HTTPASM_REQUEST_EXPECT_CONTINUE)),
               "Expect: asked 0x%x with content %d, read 0x%x", q.flags, content, back.flags);
}

/* fuzz_chunks: chunks and the last chunk, then the body decoded back. */
static void fuzz_chunks(reader *r)
{
    static uint8_t stream[OUT_MAX * 2], data[OUT_MAX];
    static httpasm_field trailers[MAX_FIELDS], read[128];
    size_t used = 0, total = 0;
    int pieces = byte(r) % 8;
    for (int i = 0; i < pieces; i++) {
        size_t len = byte(r);
        const uint8_t *piece = take(r, &len);
        uint8_t *out = out_area(OUT_MAX);
        int64_t w = httpasm_h1_write_chunk(out, OUT_MAX, piece, len);
        if (len == 0) {
            FUZZ_CHECK(w == -HTTPASM_ERROR_CHUNK && untouched(out, OUT_MAX), "an empty chunk gave %lld", (long long)w);
            continue;
        }
        FUZZ_CHECK(w > 0 && used + (size_t)w <= sizeof stream, "a %zu-octet chunk gave %lld", len, (long long)w);
        memcpy(stream + used, out, (size_t)w);
        used += (size_t)w;
        memcpy(data + total, piece, len);
        total += len;
    }
    uint32_t count = fields(r, trailers, MAX_FIELDS);
    uint8_t *out = out_area(OUT_MAX);
    int64_t w = httpasm_h1_write_last_chunk(out, OUT_MAX, trailers, count);
    if (w < 0) {
        FUZZ_CHECK(response_refusal(w) && untouched(out, OUT_MAX), "the last chunk's refusal %lld", (long long)w);
        return;
    }
    FUZZ_CHECK(w > 0 && used + (size_t)w <= sizeof stream, "the last chunk gave %lld", (long long)w);
    memcpy(stream + used, out, (size_t)w);
    used += (size_t)w;

    httpasm_h1_chunked state;
    memset(&state, 0, sizeof state);
    size_t produced = 0;
    int64_t consumed = httpasm_h1_chunked_decode(&state, stream, used, &produced);
    FUZZ_CHECK(consumed > 0 && state.state == HTTPASM_CHUNKED_TRAILERS, "the body decodes to %lld, state %u", (long long)consumed, state.state);
    FUZZ_CHECK(produced == total && memcmp(stream, data, total) == 0, "the data decoded back differs (%zu of %zu)", produced, total);
    uint32_t nread = 0;
    size_t scan = 0;
    httpasm_h1_limits limits = { .max_fields = 128 };
    int64_t t = httpasm_h1_parse_trailers(stream + consumed, used - (size_t)consumed, &scan, &limits, read, &nread);
    FUZZ_CHECK(t == (int64_t)(used - (size_t)consumed), "the trailers read back as %lld of %zu", (long long)t, used - (size_t)consumed);
    check_fields(read, nread, trailers, count, NULL, 0);
}

/* LLVMFuzzerTestOneInput: libFuzzer's entry, once per input. Always returns 0. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1 || size > FUZZ_MAX)
        return 0;
    reader r = { fuzz_place(data + 1, size - 1), size - 1 };
    switch (data[0] % 3) {
    case 0:
        fuzz_response(&r);
        break;
    case 1:
        fuzz_request(&r);
        break;
    default:
        fuzz_chunks(&r);
        break;
    }
    return 0;
}
