/*
 * h1_request_diff.c - differential fuzzing of httpasm_h1_parse_request against two widely
 * deployed HTTP/1.1 request parsers, on the same octets: llhttp 9.4.4 (Node.js's; strict, no
 * lenient flag set) and picohttpparser at dd573d8 (h2o's). Request smuggling is exactly a
 * difference between two parsers: a front and a back end that end a head, or frame its body,
 * differently see two different requests.
 *
 * Both references are compiled in from their pinned sources (tests/tools.sh); neither is part of
 * HttpAsm. The input is h1_request's (a request's octets), so its seeds and dictionary serve.
 *
 * For every input, HttpAsm's verdict and each reference's is "accepted" (a complete head),
 * "incomplete" (more octets needed) or a refusal (HttpAsm's HTTPASM_ERROR_* name, llhttp's
 * errno name, picohttpparser's "refused"). Then, per reference:
 *   - both accepted: they must agree on everything both report: the head's length, the
 *     method, the target, the version (HttpAsm reads 1.2 and later as 1.1: RFC 9110 2.5), the
 *     fields in order (names exactly, values without their OWS) and, for llhttp, the framing:
 *     chunked, or Content-Length with the same value. No difference here is ever allowed;
 *   - one accepted and the other refused (or found no end where the other did): a class,
 *     "<reference>: httpasm=<verdict> ref=<verdict>", which must be triaged against the RFC
 *     in tests/fuzz/h1_request_diff.triage (the file run.sh hands over in
 *     HTTPASM_FUZZ_TRIAGE), each line a class and the reason the difference is right. An
 *     untriaged class aborts the run with its name. With HTTPASM_FUZZ_SURVEY naming a
 *     directory, untriaged classes are written there instead (one example input each, the
 *     run goes on), to triage a whole campaign's classes at once;
 *   - both refused, or one refused while the other still waits for the head's end (llhttp
 *     refuses at the first wrong octet; HttpAsm checks a head only once it is whole): no
 *     verdict to compare.
 * HttpAsm runs at the best tier the CPU has; h1_request proves every tier equal to it.
 */
#include "fuzz.h"

#include <errno.h>
#include <sys/stat.h>

#include <llhttp.h>
#include <picohttpparser.h>

enum { MAX_FIELDS = 128, MAX_CLASSES = 1024, CLASS_LENGTH = 160 };

/* HTTPASM_ERROR_* names, by code, for the classes (httpasm.h's request-side errors). */
static const char *const ERRORS[] = {
    "none", "BARE_LF", "METHOD", "REQUEST_LINE", "TARGET", "TARGET_TOO_LONG", "TARGET_FORM", "VERSION",
    "VERSION_UNSUPPORTED", "OBS_FOLD", "FIELD_NAME", "WHITESPACE_BEFORE_COLON", "FIELD_VALUE", "HEAD_TOO_LARGE",
    "TOO_MANY_FIELDS", "HOST_MISSING", "HOST_DUPLICATE", "HOST_INVALID", "CONTENT_LENGTH", "TE_AND_CL", "TE_HTTP10",
    "TE_NOT_CHUNKED", "TE_UNKNOWN", "EXPECT", "FRAMING_FIELD", "STATUS", "CHUNK", "AUTHORITY",
};

/* One field as a reference reported it. */
typedef struct span_field {
    const char *name, *value;
    size_t name_length, value_length;
} span_field;

/* What llhttp reported for one input: its verdict, the spans its callbacks gave, and the
 * framing its parser state held when the head was complete. */
typedef struct llhttp_result {
    int verdict;                    /* 1 accepted, 0 incomplete, -1 refused */
    llhttp_errno_t error;
    size_t head;
    const char *method, *url;
    size_t method_length, url_length;
    span_field fields[MAX_FIELDS];
    size_t count;
    int last;                       /* the last callback: 0 none, 1 a name, 2 a value */
    int overflow;                   /* more fields than MAX_FIELDS */
    uint64_t content_length;
    uint16_t flags;
    uint8_t major, minor;
} llhttp_result;

static llhttp_result ll;

/* extend: a span's start (kept from its first callback) and its length up to at + n: llhttp may
 * report one element in several calls, always over contiguous octets of one buffer. */
static void extend(const char **start, size_t *length, const char *at, size_t n)
{
    if (*start == NULL)
        *start = at;
    *length = (size_t)(at + n - *start);
}

static int ll_method(llhttp_t *p, const char *at, size_t n) { (void)p; extend(&ll.method, &ll.method_length, at, n); return 0; }
static int ll_url(llhttp_t *p, const char *at, size_t n) { (void)p; extend(&ll.url, &ll.url_length, at, n); return 0; }

/* ll_field: a field name's octets; a name after a value (or first) starts a new field. */
static int ll_field(llhttp_t *p, const char *at, size_t n)
{
    (void)p;
    if (ll.last != 1) {
        if (ll.count == MAX_FIELDS) {
            ll.overflow = 1;
            ll.last = 1;
            return 0;
        }
        memset(&ll.fields[ll.count++], 0, sizeof ll.fields[0]);
    }
    ll.last = 1;
    if (!ll.overflow)
        extend(&ll.fields[ll.count - 1].name, &ll.fields[ll.count - 1].name_length, at, n);
    return 0;
}

/* ll_value: a field value's octets, for the field the last name started. */
static int ll_value(llhttp_t *p, const char *at, size_t n)
{
    (void)p;
    ll.last = 2;
    if (!ll.overflow && ll.count > 0)
        extend(&ll.fields[ll.count - 1].value, &ll.fields[ll.count - 1].value_length, at, n);
    return 0;
}

/* ll_headers: the head is complete: keeps the framing, and pauses, so llhttp_execute returns
 * with the head's end as its position. */
static int ll_headers(llhttp_t *p)
{
    ll.content_length = p->content_length;
    ll.flags = p->flags;
    ll.major = p->http_major;
    ll.minor = p->http_minor;
    return HPE_PAUSED;
}

/* run_llhttp: llhttp over buf[0..n), strict, into ll. */
static void run_llhttp(const uint8_t *buf, size_t n)
{
    static llhttp_settings_t settings;
    static int ready;
    if (!ready) {
        llhttp_settings_init(&settings);
        settings.on_method = ll_method;
        settings.on_url = ll_url;
        settings.on_header_field = ll_field;
        settings.on_header_value = ll_value;
        settings.on_headers_complete = ll_headers;
        ready = 1;
    }
    memset(&ll, 0, sizeof ll);
    llhttp_t parser;
    llhttp_init(&parser, HTTP_REQUEST, &settings);
    llhttp_errno_t e = llhttp_execute(&parser, (const char *)buf, n);
    ll.error = e;
    if (e == HPE_PAUSED) {
        ll.verdict = 1;
        ll.head = (size_t)(llhttp_get_error_pos(&parser) - (const char *)buf);
        /* The checks llhttp makes once the head is whole (a request's Transfer-Encoding
         * without chunked last, for one) run after on_headers_complete returns: resumed with
         * no octets, it runs exactly those and none of the body's (measured with llhttp
         * 9.4.4: "Transfer-Encoding: gzip" then gives HPE_INVALID_TRANSFER_ENCODING). */
        llhttp_resume(&parser);
        llhttp_errno_t after = llhttp_execute(&parser, (const char *)buf + ll.head, 0);
        if (after != HPE_OK && after != HPE_PAUSED && after != HPE_PAUSED_UPGRADE) {
            ll.verdict = -1;
            ll.error = after;
        }
    } else {
        ll.verdict = e == HPE_OK ? 0 : -1;
    }
}

/* The triaged classes (tests/fuzz/h1_request_diff.triage), and the survey's classes seen. */
static char triaged[MAX_CLASSES][CLASS_LENGTH], surveyed[MAX_CLASSES][CLASS_LENGTH];
static size_t triaged_count, surveyed_count;
static const char *survey;

/* LLVMFuzzerInitialize: libFuzzer's one-time setup. Loads the triage file named by
 * HTTPASM_FUZZ_TRIAGE (lines "<class> | <reason>", # comments), and notes the survey
 * directory. Aborts when the file is named but cannot be read: a run without its triage would
 * fail on every known class. Returns 0. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    survey = getenv("HTTPASM_FUZZ_SURVEY");
    const char *path = getenv("HTTPASM_FUZZ_TRIAGE");
    if (path == NULL || *path == 0)
        return 0;
    FILE *f = fopen(path, "r");
    FUZZ_CHECK(f != NULL, "cannot read the triage file %s", path);
    char line[1024];
    while (fgets(line, sizeof line, f) != NULL) {
        char *bar = strstr(line, " | ");
        if (line[0] == '#' || bar == NULL)
            continue;
        *bar = 0;
        FUZZ_CHECK(triaged_count < MAX_CLASSES && strlen(line) < CLASS_LENGTH, "the triage file is too long");
        strcpy(triaged[triaged_count++], line);
    }
    fclose(f);
    return 0;
}

/* in: whether a class is among n strings. */
static int in(char list[][CLASS_LENGTH], size_t n, const char *c)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(list[i], c) == 0)
            return 1;
    return 0;
}

/* difference: a verdict difference of one reference: passes when its class is triaged; in a
 * survey, records a new class with this input as its example; otherwise aborts naming it. */
static void difference(const char *ref, const char *ours, const char *theirs, const uint8_t *data, size_t size)
{
    char c[CLASS_LENGTH];
    snprintf(c, sizeof c, "%s: httpasm=%s ref=%s", ref, ours, theirs);
    if (in(triaged, triaged_count, c))
        return;
    if (survey == NULL)
        FUZZ_CHECK(0, "an untriaged difference: \"%s\" (add it to tests/fuzz/h1_request_diff.triage with the RFC's reason)", c);
    if (in(surveyed, surveyed_count, c) || surveyed_count == MAX_CLASSES)
        return;
    strcpy(surveyed[surveyed_count++], c);
    char path[4096], name[CLASS_LENGTH];
    size_t k = 0;
    for (const char *s = c; *s && k + 1 < sizeof name; s++)
        name[k++] = (*s == ' ' || *s == ':' || *s == '=' || *s == '/') ? '_' : *s;
    name[k] = 0;
    mkdir(survey, 0755);
    snprintf(path, sizeof path, "%s/%s", survey, name);
    FILE *f = fopen(path, "wb");
    if (f != NULL) {
        fwrite(data, 1, size, f);
        fclose(f);
    }
    fprintf(stderr, "survey: %s\n", c);
}

/* trimmed: [p, p + n) without leading and trailing SP and HTAB (OWS). */
static void trimmed(const char **p, size_t *n)
{
    while (*n > 0 && (**p == ' ' || **p == '\t'))
        (*p)++, (*n)--;
    while (*n > 0 && ((*p)[*n - 1] == ' ' || (*p)[*n - 1] == '\t'))
        (*n)--;
}

/* same_field: whether HttpAsm's field i and a reference's agree: the name exactly, the value
 * once the reference's OWS is gone (HttpAsm's values have none). */
static int same_field(const httpasm_field *f, const char *name, size_t nlen, const char *value, size_t vlen)
{
    if (value == NULL)
        vlen = 0;
    trimmed(&value, &vlen);
    return f->name_length == nlen && memcmp(f->name, name, nlen) == 0 && f->value_length == vlen
        && (vlen == 0 || memcmp(f->value, value, vlen) == 0);
}

/* LLVMFuzzerTestOneInput: libFuzzer's entry, once per input. Always returns 0. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static httpasm_field fields[MAX_FIELDS];
    static struct phr_header pico_fields[MAX_FIELDS];
    if (size > FUZZ_MAX)
        return 0;
    const uint8_t *buf = fuzz_place(data, size);

    httpasm_request q;
    memset(&q, 0, sizeof q);
    size_t scan = 0;
    int64_t r = httpasm_h1_parse_request(buf, size, &scan, NULL, &q, fields);
    const char *ours = r > 0 ? "accepted" : r == 0 ? "incomplete" : q.error < sizeof ERRORS / sizeof ERRORS[0] ? ERRORS[q.error] : "unknown";

    /* llhttp. */
    run_llhttp(buf, size);
    const char *theirs = ll.verdict > 0 ? "accepted" : ll.verdict == 0 ? "incomplete" : llhttp_errno_name(ll.error);
    if (r > 0 && ll.verdict > 0 && !ll.overflow) {
        FUZZ_CHECK((size_t)r == ll.head, "llhttp: the head ends at %zu, HttpAsm says %lld", ll.head, (long long)r);
        FUZZ_CHECK(q.method_length == ll.method_length && memcmp(q.method, ll.method, ll.method_length) == 0, "llhttp: another method");
        FUZZ_CHECK(q.target_length == ll.url_length && memcmp(q.target, ll.url, ll.url_length) == 0, "llhttp: another target");
        FUZZ_CHECK(ll.major == 1 && (ll.minor == 0) == (q.version == 10), "llhttp: version %u.%u, HttpAsm %u", ll.major, ll.minor, q.version);
        FUZZ_CHECK(q.field_count == ll.count, "llhttp: %zu fields, HttpAsm %u", ll.count, q.field_count);
        for (uint32_t i = 0; i < q.field_count; i++)
            FUZZ_CHECK(same_field(&fields[i], ll.fields[i].name, ll.fields[i].name_length, ll.fields[i].value, ll.fields[i].value_length),
                       "llhttp: field %u differs", i);
        int chunked = (ll.flags & F_CHUNKED) != 0, length = (ll.flags & F_CONTENT_LENGTH) != 0 && !chunked;
        FUZZ_CHECK(chunked == ((q.flags & HTTPASM_REQUEST_CHUNKED) != 0), "llhttp: chunked %d, HttpAsm flags 0x%x", chunked, q.flags);
        FUZZ_CHECK(length == ((q.flags & HTTPASM_REQUEST_CONTENT_LENGTH) != 0) && (!length || ll.content_length == q.content_length),
                   "llhttp: Content-Length %d (%llu), HttpAsm flags 0x%x (%llu)", length, (unsigned long long)ll.content_length, q.flags,
                   (unsigned long long)q.content_length);
    } else if ((r > 0) != (ll.verdict > 0) && !(r < 0 && ll.verdict == 0) && !(r == 0 && ll.verdict < 0)) {
        difference("llhttp", ours, theirs, data, size);
    }

    /* picohttpparser. */
    const char *method = NULL, *path = NULL;
    size_t method_length = 0, path_length = 0, count = MAX_FIELDS;
    int minor = -1;
    int p = phr_parse_request((const char *)buf, size, &method, &method_length, &path, &path_length, &minor, pico_fields, &count, 0);
    const char *pico = p > 0 ? "accepted" : p == -2 ? "incomplete" : "refused";
    if (r > 0 && p > 0) {
        FUZZ_CHECK((size_t)r == (size_t)p, "picohttpparser: the head ends at %d, HttpAsm says %lld", p, (long long)r);
        FUZZ_CHECK(q.method_length == method_length && memcmp(q.method, method, method_length) == 0, "picohttpparser: another method");
        FUZZ_CHECK(q.target_length == path_length && memcmp(q.target, path, path_length) == 0, "picohttpparser: another target");
        FUZZ_CHECK((minor == 0) == (q.version == 10), "picohttpparser: minor version %d, HttpAsm %u", minor, q.version);
        FUZZ_CHECK(q.field_count == count, "picohttpparser: %zu fields, HttpAsm %u", count, q.field_count);
        for (uint32_t i = 0; i < q.field_count; i++)
            FUZZ_CHECK(pico_fields[i].name != NULL
                           && same_field(&fields[i], pico_fields[i].name, pico_fields[i].name_len, pico_fields[i].value, pico_fields[i].value_len),
                       "picohttpparser: field %u differs", i);
    } else if ((r > 0) != (p > 0) && !(r < 0 && p == -2) && !(r == 0 && p == -1)) {
        /* picohttpparser names no reason for a refusal, so one is told apart here: it skips a
         * single empty line before the request-line, HttpAsm any number (RFC 9112 2.2: "at
         * least one"). With every leading CRLF gone, a head it then accepts was refused for
         * that alone; any other refusal stays a class of its own, to be triaged by itself. */
        if (r > 0 && p == -1) {
            size_t skip = 0;
            while (skip + 1 < size && buf[skip] == '\r' && buf[skip + 1] == '\n')
                skip += 2;
            count = MAX_FIELDS;
            if (skip > 2 && phr_parse_request((const char *)buf + skip, size - skip, &method, &method_length, &path, &path_length,
                                              &minor, pico_fields, &count, 0) > 0)
                pico = "refused-empty-lines";
        }
        difference("picohttpparser", ours, pico, data, size);
    }
    return 0;
}
