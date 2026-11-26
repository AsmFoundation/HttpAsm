/*
 * h2_request.c - fuzzes httpasm_h2_request and httpasm_h2_trailers: HTTP/2's rules for a
 * request's decoded header list (RFC 9113 8.2, 8.3, 8.5) and its trailer section. What a peer's
 * HPACK block decodes to reaches these checks unfiltered, and what they let through becomes
 * the request every handler, and any HTTP/1.1 hop behind a proxy, sees.
 *
 * The input is a list of fields, each a name length (one octet), the name, a value length (two
 * octets, little-endian) and the value, cut where the input ends.
 *
 * For every input, at every CPU tier (fuzz.h), it requires of httpasm_h2_request:
 *   - the result is 0 or minus one of the documented errors, with request.error set to it;
 *   - soundness: whatever it accepts is a valid request, checked here apart from the library
 *     wherever possible:
 *       - the pseudo-fields lead, are among the request's four (exact names), appear once each,
 *         and are the right set (CONNECT: :method and :authority only; otherwise :method,
 *         :scheme and a non-empty :path, "*" only for OPTIONS, else starting with "/");
 *       - the method is a token, its id is its name's (exact, case-sensitive);
 *       - every regular field has a lower-case token name, a value without CTLs (HTAB aside)
 *         or whitespace at its ends, and an id equal to an independent lookup; none is
 *         connection-specific, TE holds only "trailers", Content-Length is digits and repeats
 *         only its own value, Expect only "100-continue", and a Host names :authority's
 *         authority;
 *       - the request record says what the list says: method, target, authority, scheme,
 *         version 20, flags, content_length, and fields after the pseudo-fields;
 *       - HTTP/1.1 agrees: the same target (or CONNECT authority) and Host, written as an
 *         HTTP/1.1 head, parse (httpasm_h1_parse_request), so a request could not be played
 *         against an HTTP/1.1 hop by passing here and failing there;
 *   - the same result and the same request at every tier;
 * and of httpasm_h2_trailers: 0 or -H2_PSEUDO / -FIELD_NAME / -FIELD_VALUE; when 0, no
 * pseudo-field, lower-case token names, valid values, every record flagged TRAILER.
 */
#include "fuzz.h"

enum { MAX_FIELDS = 128 };

/* letters_fold_equal: whether a[0..n) equals the lower-case b[0..n), folding ASCII letters only. */
static int letters_fold_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t c = a[i];
        if (c >= 'A' && c <= 'Z')
            c = (uint8_t)(c + 32);
        if (c != b[i])
            return 0;
    }
    return 1;
}

/* known_id: a name's known-field id through the library's list of names (httpasm_field_name),
 * letters folded only: the id a checked record must carry. */
static uint32_t known_id(const uint8_t *name, size_t n)
{
    for (uint32_t id = 1; id <= HTTPASM_FIELD_COUNT; id++) {
        size_t length = 0;
        const uint8_t *k = httpasm_field_name(id, &length);
        if (k != NULL && length == n && letters_fold_equal(name, k, n))
            return id;
    }
    return 0;
}

/* same_host: whether two authorities name the same host: equal but for the case of letters
 * (RFC 3986 3.2.2: the host is case-insensitive). The library compares no further (no default
 * port, no percent-encoding normalization), so neither may this check accept more. */
static int same_host(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    if (an != bn)
        return 0;
    for (size_t i = 0; i < an; i++) {
        uint8_t x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z')
            x = (uint8_t)(x + 32);
        if (y >= 'A' && y <= 'Z')
            y = (uint8_t)(y + 32);
        if (x != y)
            return 0;
    }
    return 1;
}

/* is: whether the n octets at p are exactly the string s. */
static int is(const uint8_t *p, size_t n, const char *s)
{
    return strlen(s) == n && memcmp(p, s, n) == 0;
}

/* is_folded: whether the n octets at p are the lower-case string s, letters folded only. */
static int is_folded(const uint8_t *p, size_t n, const char *s)
{
    return strlen(s) == n && letters_fold_equal(p, (const uint8_t *)s, n);
}

/* lower_token: whether p[0..n) is a non-empty token without upper-case letters (RFC 9113 8.2.1). */
static int lower_token(const uint8_t *p, size_t n)
{
    if (n == 0 || httpasm_token_length(p, n) != n)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (p[i] >= 'A' && p[i] <= 'Z')
            return 0;
    return 1;
}

/* valid_value: no CTL but HTAB, no SP or HTAB at either end (RFC 9113 8.2.1). */
static int valid_value(const uint8_t *p, size_t n)
{
    if (httpasm_field_value_scan(p, n) != n)
        return 0;
    return n == 0 || (p[0] != ' ' && p[0] != '\t' && p[n - 1] != ' ' && p[n - 1] != '\t');
}

/* method_id: HTTPASM_METHOD_* of a method, compared exactly (methods are case-sensitive). */
static uint32_t method_id(const uint8_t *p, size_t n)
{
    static const char *names[] = { "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH" };
    for (uint32_t i = 0; i < 9; i++)
        if (is(p, n, names[i]))
            return i + 1;
    return 0;
}

/* parse_fields: the input's fields into fields[0..), pointing into data (which must outlive
 * them). Returns how many. */
static uint32_t parse_fields(const uint8_t *data, size_t size, httpasm_field *fields)
{
    uint32_t count = 0;
    size_t pos = 0;
    while (pos < size && count < MAX_FIELDS) {
        size_t nlen = data[pos++];
        if (nlen > size - pos)
            nlen = size - pos;
        const uint8_t *name = data + pos;
        pos += nlen;
        size_t vlen = 0;
        if (pos + 2 <= size) {
            vlen = (size_t)data[pos] | (size_t)data[pos + 1] << 8;
            pos += 2;
        } else {
            pos = size;
        }
        if (vlen > size - pos)
            vlen = size - pos;
        fields[count] = (httpasm_field){ .name = name, .name_length = (uint32_t)nlen, .value = data + pos, .value_length = (uint32_t)vlen };
        pos += vlen;
        count++;
    }
    return count;
}

/* h1_accepts: whether HTTP/1.1's request parser accepts "<method> <target> HTTP/1.1", with Host
 * <host> - the same target and authority as an HTTP/1.1 hop would receive them. */
static int h1_accepts(const char *method, const uint8_t *target, size_t tlen, const uint8_t *host, size_t hlen)
{
    static uint8_t head[3 * FUZZ_MAX];
    static httpasm_field fields[MAX_FIELDS];
    size_t n = 0, mlen = strlen(method);
    memcpy(head + n, method, mlen), n += mlen;
    head[n++] = ' ';
    memcpy(head + n, target, tlen), n += tlen;
    memcpy(head + n, " HTTP/1.1\r\nHost: ", 17), n += 17;
    memcpy(head + n, host, hlen), n += hlen;
    memcpy(head + n, "\r\n\r\n", 4), n += 4;
    httpasm_request request;
    size_t scan = 0;
    memset(&request, 0, sizeof request);
    return httpasm_h1_parse_request(head, n, &scan, NULL, &request, fields) > 0;
}

/* check_request: the soundness of an accepted request (this file's header). */
static void check_request(const httpasm_field *fields, uint32_t count, const httpasm_request *q)
{
    const httpasm_field *method = NULL, *scheme = NULL, *authority = NULL, *path = NULL, *host = NULL;
    uint32_t pseudos = 0, flags = HTTPASM_REQUEST_KEEP_ALIVE;
    uint64_t length = 0;
    int have_length = 0;
    while (pseudos < count && fields[pseudos].name_length > 0 && fields[pseudos].name[0] == ':') {
        const httpasm_field *f = &fields[pseudos];
        const httpasm_field **slot = is(f->name, f->name_length, ":method") ? &method
                                   : is(f->name, f->name_length, ":scheme") ? &scheme
                                   : is(f->name, f->name_length, ":authority") ? &authority
                                   : is(f->name, f->name_length, ":path") ? &path : NULL;
        FUZZ_CHECK(slot != NULL, "accepted the pseudo-field %.*s", (int)f->name_length, (const char *)f->name);
        FUZZ_CHECK(*slot == NULL, "accepted %.*s twice", (int)f->name_length, (const char *)f->name);
        FUZZ_CHECK(valid_value(f->value, f->value_length), "accepted an invalid %.*s value", (int)f->name_length, (const char *)f->name);
        *slot = f;
        pseudos++;
    }
    FUZZ_CHECK(method != NULL && method->value_length > 0, "accepted without :method");
    FUZZ_CHECK(httpasm_token_length(method->value, method->value_length) == method->value_length, "accepted a method that is no token");
    uint32_t mid = method_id(method->value, method->value_length);
    FUZZ_CHECK(q->method == method->value && q->method_length == method->value_length && q->method_id == mid,
               "the request's method is not :method's (id %u, expected %u)", q->method_id, mid);
    for (uint32_t i = pseudos; i < count; i++) {
        const httpasm_field *f = &fields[i];
        FUZZ_CHECK(f->name_length == 0 || f->name[0] != ':', "accepted a pseudo-field after a regular one");
        FUZZ_CHECK(lower_token(f->name, f->name_length), "accepted field %u's name", i);
        FUZZ_CHECK(valid_value(f->value, f->value_length), "accepted field %u's value", i);
        uint32_t id = known_id(f->name, f->name_length);
        FUZZ_CHECK(f->id == id, "field %u's id %u, its name's %u", i, f->id, id);
        FUZZ_CHECK(id != HTTPASM_FIELD_CONNECTION && id != HTTPASM_FIELD_KEEP_ALIVE && id != HTTPASM_FIELD_PROXY_CONNECTION
                       && id != HTTPASM_FIELD_TRANSFER_ENCODING && id != HTTPASM_FIELD_UPGRADE,
                   "accepted the connection-specific %.*s", (int)f->name_length, (const char *)f->name);
        if (id == HTTPASM_FIELD_TE) {
            FUZZ_CHECK(is_folded(f->value, f->value_length, "trailers"), "accepted TE: %.*s", (int)f->value_length, (const char *)f->value);
            flags |= HTTPASM_REQUEST_TE_TRAILERS;
        } else if (id == HTTPASM_FIELD_EXPECT) {
            FUZZ_CHECK(is_folded(f->value, f->value_length, "100-continue"), "accepted Expect: %.*s", (int)f->value_length, (const char *)f->value);
            flags |= HTTPASM_REQUEST_EXPECT_CONTINUE;
        } else if (id == HTTPASM_FIELD_HOST) {
            FUZZ_CHECK(host == NULL, "accepted two Hosts");
            host = f;
            flags |= HTTPASM_REQUEST_HOST;
        } else if (id == HTTPASM_FIELD_CONTENT_LENGTH) {
            uint64_t v = 0;
            FUZZ_CHECK(f->value_length > 0, "accepted an empty Content-Length");
            for (uint32_t k = 0; k < f->value_length; k++) {
                FUZZ_CHECK(f->value[k] >= '0' && f->value[k] <= '9', "accepted Content-Length: %.*s", (int)f->value_length, (const char *)f->value);
                FUZZ_CHECK(v <= (UINT64_MAX - 9) / 10, "accepted a Content-Length past 2^64");
                v = v * 10 + (uint64_t)(f->value[k] - '0');
            }
            FUZZ_CHECK(!have_length || v == length, "accepted two Content-Lengths, %llu and %llu", (unsigned long long)length, (unsigned long long)v);
            length = v;
            have_length = 1;
            flags |= HTTPASM_REQUEST_CONTENT_LENGTH;
        }
    }
    FUZZ_CHECK(q->fields == fields + pseudos && q->field_count == count - pseudos, "fields %p+%u, expected %p+%u",
               (const void *)q->fields, q->field_count, (const void *)(fields + pseudos), count - pseudos);
    FUZZ_CHECK(q->flags == flags, "flags 0x%x, the list says 0x%x", q->flags, flags);
    FUZZ_CHECK(q->content_length == (have_length ? length : 0), "content_length %llu", (unsigned long long)q->content_length);
    FUZZ_CHECK(q->version == 20 && q->error == 0, "version %u, error %u", q->version, q->error);
    const httpasm_field *named = authority != NULL ? authority : host;
    FUZZ_CHECK(named == NULL ? q->authority == NULL && q->authority_length == 0
                             : q->authority == named->value && q->authority_length == named->value_length,
               "the request's authority is not the list's");
    if (authority != NULL && host != NULL)
        FUZZ_CHECK(same_host(host->value, host->value_length, authority->value, authority->value_length),
                   "accepted Host %.*s with :authority %.*s", (int)host->value_length, (const char *)host->value,
                   (int)authority->value_length, (const char *)authority->value);

    if (mid == HTTPASM_METHOD_CONNECT) {
        FUZZ_CHECK(authority != NULL && authority->value_length > 0 && scheme == NULL && path == NULL, "accepted a CONNECT's pseudo-fields");
        FUZZ_CHECK(q->target == authority->value && q->target_length == authority->value_length && q->target_form == HTTPASM_TARGET_AUTHORITY,
                   "a CONNECT's target is not :authority");
        FUZZ_CHECK(h1_accepts("CONNECT", authority->value, authority->value_length, authority->value, authority->value_length),
                   "HTTP/1.1 refuses CONNECT %.*s", (int)authority->value_length, (const char *)authority->value);
        return;
    }
    FUZZ_CHECK(scheme != NULL && scheme->value_length > 0 && path != NULL && path->value_length > 0, "accepted without :scheme or :path");
    FUZZ_CHECK(q->scheme == scheme->value && q->scheme_length == scheme->value_length, "the request's scheme is not :scheme");
    FUZZ_CHECK(q->target == path->value && q->target_length == path->value_length, "the request's target is not :path");
    int asterisk = is(path->value, path->value_length, "*");
    FUZZ_CHECK(asterisk ? mid == HTTPASM_METHOD_OPTIONS : path->value[0] == '/', "accepted :path %.*s for %.*s", (int)path->value_length,
               (const char *)path->value, (int)method->value_length, (const char *)method->value);
    FUZZ_CHECK(q->target_form == (asterisk ? HTTPASM_TARGET_ASTERISK : HTTPASM_TARGET_ORIGIN), "target_form %u", q->target_form);
    const uint8_t *h = named != NULL ? named->value : (const uint8_t *)"x";
    size_t hlen = named != NULL ? named->value_length : 1;
    FUZZ_CHECK(h1_accepts(asterisk ? "OPTIONS" : "GET", path->value, path->value_length, h, hlen),
               "HTTP/1.1 refuses :path %.*s with Host %.*s", (int)path->value_length, (const char *)path->value, (int)hlen, (const char *)h);
}

/* check_trailers: httpasm_h2_trailers' result over fields[0..count). */
static void check_trailers(int r, const httpasm_field *fields, uint32_t count)
{
    if (r != 0) {
        FUZZ_CHECK(r == -HTTPASM_ERROR_H2_PSEUDO || r == -HTTPASM_ERROR_FIELD_NAME || r == -HTTPASM_ERROR_FIELD_VALUE, "trailers: result %d", r);
        return;
    }
    for (uint32_t i = 0; i < count; i++) {
        const httpasm_field *f = &fields[i];
        FUZZ_CHECK(lower_token(f->name, f->name_length), "trailers: accepted field %u's name", i);
        FUZZ_CHECK(valid_value(f->value, f->value_length), "trailers: accepted field %u's value", i);
        FUZZ_CHECK(f->flags & HTTPASM_FIELD_FLAG_TRAILER, "trailers: field %u not flagged", i);
        FUZZ_CHECK(f->id == known_id(f->name, f->name_length), "trailers: field %u's id %u", i, f->id);
    }
}

/* LLVMFuzzerTestOneInput: libFuzzer's entry, once per input. Always returns 0. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static httpasm_field fields[MAX_FIELDS], first_fields[MAX_FIELDS];
    static httpasm_request first;
    static int first_result, first_trailers;
    if (size > FUZZ_MAX)
        return 0;
    const uint8_t *input = fuzz_place(data, size);
    for (size_t t = 0; t < FUZZ_TIERS; t++) {
        httpasm_cpu_limit(fuzz_caps[t]);
        uint32_t count = parse_fields(input, size, fields);
        httpasm_request q;
        memset(&q, 0xA5, sizeof q);              /* every byte must be written, garbage or not */
        int r = httpasm_h2_request(fields, count, &q);
        if (r == 0) {
            check_request(fields, count, &q);
        } else {
            FUZZ_CHECK(r == -HTTPASM_ERROR_H2_PSEUDO || r == -HTTPASM_ERROR_H2_MISSING || r == -HTTPASM_ERROR_H2_CONNECTION_FIELD
                           || r == -HTTPASM_ERROR_H2_AUTHORITY || r == -HTTPASM_ERROR_FIELD_NAME || r == -HTTPASM_ERROR_FIELD_VALUE
                           || r == -HTTPASM_ERROR_METHOD || r == -HTTPASM_ERROR_TARGET || r == -HTTPASM_ERROR_CONTENT_LENGTH
                           || r == -HTTPASM_ERROR_HOST_DUPLICATE || r == -HTTPASM_ERROR_HOST_INVALID || r == -HTTPASM_ERROR_EXPECT,
                       "result %d", r);
            FUZZ_CHECK(q.error == (uint16_t)-r, "request.error %u for result %d", q.error, r);
        }
        if (t == 0) {
            first = q;
            first_result = r;
            memcpy(first_fields, fields, sizeof fields);
        } else {
            FUZZ_CHECK(r == first_result, "tier %zu: %d, v1: %d", t + 1, r, first_result);
            FUZZ_CHECK(memcmp(&q, &first, sizeof q) == 0 && memcmp(fields, first_fields, count * sizeof fields[0]) == 0,
                       "tier %zu's request differs from v1's", t + 1);
        }

        /* The same list as a trailer section (fresh records: the request check set ids). */
        count = parse_fields(input, size, fields);
        int tr = httpasm_h2_trailers(fields, count);
        check_trailers(tr, fields, count);
        if (t == 0)
            first_trailers = tr;
        else
            FUZZ_CHECK(tr == first_trailers, "trailers: tier %zu: %d, v1: %d", t + 1, tr, first_trailers);
    }
    return 0;
}
