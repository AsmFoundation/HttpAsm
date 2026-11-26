/*
 * faults.c - the drivers' error paths (docs/DESIGN.md phase H step 3: "memory and connection
 * exhaustion"): allocations and system calls that fail, one at a time, at every point a whole
 * server's life reaches. No other test can reach these paths: on a healthy machine nothing fails.
 *
 * The scenario: a server created and started (one worker by default, loopback), then on it:
 * an HTTP/1.1 request; a deferred one (answered from another thread); a chunked 40 KB upload
 * with a trailer, echoed (the input and the output grow); an HTTP/2 request; an HTTP/2
 * connection carrying a deferred request and an upload whose head continues in a CONTINUATION
 * frame, whose 20 KB body comes in two DATA frames and which ends with trailers; and one asking
 * for an answer whose 64 KB head takes CONTINUATION frames and for a 256 KiB answer past its
 * stream's first window (the rest waits, copied, for the WINDOW_UPDATE that follows); then the
 * httpasm client's own requests (a small answer, one whose 64 KB head outgrows the client's
 * input, a 256 KiB one, and one whose own 5 KB head outgrows its output), the stop and the
 * destroy.
 *
 *   1. Allocation failures. This program defines malloc, calloc and realloc (they interpose on
 *      the C library's for the whole process, libhttpasm.so included) and counts the calls; the
 *      scenario runs to count them, then once per allocation in a child process where that
 *      allocation returns NULL. Every child must end by itself - the scenario succeeding, or
 *      an API call reporting the failure - never by a signal, and within 20 s. An allocation
 *      is named so that it is the same one in every run: on the scenario's own thread (the
 *      server's create, start, stop and destroy, the client), by its ordinal, as that thread
 *      allocates in one order; on the others (the worker, the threads that answer deferred
 *      requests), by the scenario's step (each connection is one), its call site (the return
 *      address into the code that asked) and which call of that site it is. Ordinals over
 *      threads that run at once named a different site from run to run, and some were never
 *      failed: a count shared by both roles missed the client's third (the worker accepts while
 *      the client allocates), and a count over the other threads missed the HTTP/2 answer's
 *      copy (an earlier output grew in one step or two as the socket took the octets), both
 *      2026-11-26. "faults sites" prints the steps' sites, with their calls over three runs.
 *   2. System-call failures, lasting. For each system call the server and the client make, a
 *      child installs a seccomp filter that fails every call of it with an errno (EMFILE,
 *      ENOMEM, ENOBUFS, ...), then runs the scenario; again it must end by itself.
 *   4. System-call failures, one at a time. A filter that fails every call reaches only the
 *      first site that makes it. Here a seccomp user-notification filter (SECCOMP_RET_USER_NOTIF)
 *      hands each call of one system call to a supervisor thread of the child, which lets every
 *      call go on (SECCOMP_USER_NOTIF_FLAG_CONTINUE) but the k-th, which it fails with an errno;
 *      a first run counts the calls, then k takes every value. So each call site meets its own
 *      failure, transient ones (EINTR, EAGAIN, ECONNABORTED) included, which a lasting filter
 *      could only turn into a spin.
 * A child's exit status says how far its scenario got. A signal, a hang, or a child that spun
 * (more than CHILD_CPU_LIMIT seconds of CPU: a worker woken again and again by something it
 * cannot act on, such as a listener whose accept4 keeps failing) fails the test.
 *   3. Descriptor exhaustion, on each backend: a server whose process can open only 4 more
 *      descriptors, and 12 connections from another process. Accepting stops at the limit:
 *      the server must rest (its CPU over a second stays near zero, where a spinning worker
 *      uses the whole second), then take the waiting connections once descriptors free, and
 *      answer the request that waited in the backlog. And a stop that begins while the
 *      listener rests: the stop closes the listener, the rest ends during the stop (a request
 *      in progress holds it), and the resumed watch must not touch the closed listener; the
 *      request is answered and the stop returns.
 *
 * Exit status: 0 when every child ended by itself and the exhaustion checks held; 1 with the
 * failing ones listed.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <link.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "httpasm.h"

/* ---- 1. The allocator: glibc's own entry points, with a countdown. */
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);

static _Atomic long allocations;     /* every allocation so far, both roles */

/* main_thread: 1 on the thread that runs main and so the scenario (the server's create, start,
 * stop and destroy, the client), 0 on every other (the worker, the threads answering deferred
 * requests). A child inherits 1: fork copies only the calling thread, main's. */
static _Thread_local int main_thread;

/* The scenario's own thread: its allocations so far, and the one of them that fails (1-based;
 * -1: none). Touched by that thread alone, and in one order every run, so an ordinal names
 * one allocation. */
static long main_allocations;
static long main_fail_at = -1;

/* The other threads' allocations so far: the count's report only. Their order is no identity
 * (an ordinal over them named a different allocation from run to run: the h2_send_out copy
 * of the HTTP/2 window step came 80th, 81st or 82nd in the instrumented build, and the three
 * children failing those met it in none of them, 2026-11-26); fails() keys them by step and
 * call site instead (below). */
static _Atomic long other_allocations;

/* STEPS: the scenario steps the site tables have room for. The scenario takes 13: its
 * server's create and start, its ten raw connections, the client's, its stop and destroy. */
#define STEPS 16

/* step: the scenario's step, moved on by its own thread alone (step_enter) and only once the
 * server's threads are done with the step before: every step is one connection, and the next
 * begins after it closed, by which time the worker allocates nothing more for it (it closed
 * the socket last) and its answering thread, if any, has handed its answer over. step_names:
 * each step's name, for the reports. */
static _Atomic int step;
static const char *step_names[STEPS];

/* SITES: the call sites one step's table holds. A step's other threads allocate from about a
 * dozen; a call no slot can take is not counted and the count run fails (sites_full). */
#define SITES 48

/* site: one call site of the other threads in one step: its return address (0: a free slot),
 * set once by whichever thread meets it first, and how many calls came from it so far. */
struct site {
    _Atomic uintptr_t address;
    _Atomic long calls;
};
static struct site sites[STEPS][SITES];
static _Atomic int sites_full;

/* The other threads' allocation that fails: call fail_call (1-based) from the call site
 * fail_site, in step fail_step (-1: none). Set in a child before its scenario, read by the
 * server's threads, which start after it. */
static int fail_step = -1;
static uintptr_t fail_site;
static long fail_call;

/* site_call: counts one call from the return address `address` in step s's table, and returns
 * which call of that site this is (1-based), or 0 when the table is full. Lock-free: the worker
 * and an answering thread allocate at once. A slot is claimed by compare-and-swap from 0, so
 * two threads meeting one new site share one slot, and a thread whose claim lost to another
 * site moves on to the next. Per site, calls come in one order whatever the threads' interleaving:
 * the one thread that makes them makes them in its own order. */
static long site_call(int s, uintptr_t address)
{
    for (int i = 0; i < SITES; i++) {
        uintptr_t seen = atomic_load(&sites[s][i].address);
        if (seen == 0) {
            uintptr_t expected = 0;
            if (atomic_compare_exchange_strong(&sites[s][i].address, &expected, address))
                return atomic_fetch_add(&sites[s][i].calls, 1) + 1;
            seen = expected;
        }
        if (seen == address)
            return atomic_fetch_add(&sites[s][i].calls, 1) + 1;
    }
    atomic_store(&sites_full, 1);
    return 0;
}

/* fails: counts an allocation under its thread's role, and says whether this one is to fail
 * (errno is then ENOMEM, as a real allocator's failure leaves it: glibc's pthread_create
 * asserts that it does). The scenario's thread fails its main_fail_at-th allocation; the
 * others fail call fail_call from fail_site in step fail_step, which names one allocation in
 * every run however the worker, the answering threads and the socket's pace interleave.
 *   caller  the return address of the allocator's caller: its call site. */
static int fails(const void *caller)
{
    atomic_fetch_add(&allocations, 1);
    if (main_thread) {
        if (++main_allocations != main_fail_at)
            return 0;
    } else {
        atomic_fetch_add(&other_allocations, 1);
        int s = atomic_load(&step);
        long call = site_call(s, (uintptr_t)caller);
        if (s != fail_step || (uintptr_t)caller != fail_site || call != fail_call)
            return 0;
    }
    errno = ENOMEM;
    return 1;
}

/* debug_alloc: 1 in the debug modes ("faults alloc-main N", "faults alloc-other STEP SITE
 * CALL"), which print the code that made the failing allocation (failed_from). */
static int debug_alloc;

/* site_lookup: one dl_iterate_phdr walk's question and answer, for site_name (an address in,
 * the object holding it out) and for site_address (an object's file name in, its load bias
 * out). */
struct site_lookup {
    uintptr_t address;          /* site_name: the address asked about */
    const char *name;           /* site_address: the file name asked about (no directory) */
    size_t name_length;
    const char *found;          /* the object's file name, without its directory */
    uintptr_t bias;             /* its load bias: an address minus it is the object's own */
};

/* object_holding: dl_iterate_phdr's callback for site_name: whether this object's loaded
 * segments hold lookup->address (1 ends the walk). Returns 1 when found, 0 to go on. */
static int object_holding(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    struct site_lookup *lookup = data;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        uintptr_t start = info->dlpi_addr + ph->p_vaddr;
        if (ph->p_type == PT_LOAD && lookup->address >= start && lookup->address < start + ph->p_memsz) {
            const char *slash = strrchr(info->dlpi_name, '/');
            lookup->found = info->dlpi_name[0] == 0 ? "faults" : slash != NULL ? slash + 1 : info->dlpi_name;
            lookup->bias = info->dlpi_addr;
            return 1;
        }
    }
    return 0;
}

/* object_named: dl_iterate_phdr's callback for site_address: whether this object's file name
 * (without its directory; the program itself is "faults") is lookup->name. Returns 1 when it
 * is (its bias in lookup->bias), 0 to go on. */
static int object_named(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    struct site_lookup *lookup = data;
    const char *slash = strrchr(info->dlpi_name, '/');
    const char *name = info->dlpi_name[0] == 0 ? "faults" : slash != NULL ? slash + 1 : info->dlpi_name;
    if (strlen(name) != lookup->name_length || memcmp(name, lookup->name, lookup->name_length) != 0)
        return 0;
    lookup->bias = info->dlpi_addr;
    return 1;
}

/* site_name: writes a call site as OBJECT+OFFSET ("libhttpasm.so+0x1f2e"): its object's file
 * name and the object's own address of it, the address `nm -n` and objdump print, so the
 * function is found from it even where it is hidden (libhttpasm.so exports only its API).
 * Allocation-free, so failed_from may call it inside the allocator: dl_iterate_phdr walks the
 * loaded objects without allocating, and the text goes to the caller's buffer. */
static void site_name(uintptr_t address, char *out, size_t size)
{
    struct site_lookup lookup = { .address = address };
    if (dl_iterate_phdr(object_holding, &lookup) == 1)
        snprintf(out, size, "%s+%#lx", lookup.found, (unsigned long)(address - lookup.bias));
    else
        snprintf(out, size, "%#lx", (unsigned long)address);
}

/* site_address: the address an OBJECT+OFFSET name stands for in this process (the inverse of
 * site_name, for the debug mode's command line). Returns 0 when the text has no '+' or no
 * loaded object has that name. */
static uintptr_t site_address(const char *text)
{
    const char *plus = strchr(text, '+');
    if (plus == NULL)
        return 0;
    struct site_lookup lookup = { .name = text, .name_length = (size_t)(plus - text) };
    if (dl_iterate_phdr(object_named, &lookup) != 1)
        return 0;
    return lookup.bias + (uintptr_t)strtoul(plus + 1, NULL, 0);
}

/* failed_from: in the debug modes, prints the call site of the allocation that fails, as
 * site_name writes it. Allocation-free (it runs inside the allocator): the line is formatted on
 * the stack and written with write(2). */
static void failed_from(const void *caller)
{
    if (!debug_alloc)
        return;
    char where[160];
    char line[224];
    site_name((uintptr_t)caller, where, sizeof where);
    int n = snprintf(line, sizeof line, "faults: the failing allocation came from %s\n", where);
    if (n > 0 && write(2, line, (size_t)n) < 0)
        return;
}

/* The allocator's entry points, interposed on the C library's for the whole process (the
 * executable's definitions come first in symbol lookup, libhttpasm.so's calls included). Each
 * passes its caller's return address to fails(): the call site that keys the other threads'
 * allocations. */
void *malloc(size_t n)
{
    if (!fails(__builtin_return_address(0)))
        return __libc_malloc(n);
    failed_from(__builtin_return_address(0));
    return NULL;
}

void *calloc(size_t count, size_t n)
{
    if (!fails(__builtin_return_address(0)))
        return __libc_calloc(count, n);
    failed_from(__builtin_return_address(0));
    return NULL;
}

void *realloc(void *p, size_t n)
{
    if (!fails(__builtin_return_address(0)))
        return __libc_realloc(p, n);
    failed_from(__builtin_return_address(0));
    return NULL;
}

/* step_reset: empties the site tables and returns to step 0 (the server's create and start), at
 * a scenario's start: a child inherits the count run's tables from the parent, and must count
 * its own calls from zero. Only the scenario's thread is running then. */
static void step_reset(void)
{
    for (int s = 0; s < STEPS; s++) {
        for (int i = 0; i < SITES; i++) {
            atomic_store(&sites[s][i].address, 0);
            atomic_store(&sites[s][i].calls, 0);
        }
    }
    step_names[0] = "the server's create and start";
    atomic_store(&step, 0);
}

/* step_enter: the scenario moves on to its next step, `name`. Called by the scenario's thread
 * only between connections (step), so no other thread is allocating for the step before. The
 * last table takes any step past STEPS (never: the scenario has 13). */
static void step_enter(const char *name)
{
    int s = atomic_load(&step) + 1;
    if (s >= STEPS)
        s = STEPS - 1;
    step_names[s] = name;
    atomic_store(&step, s);
}

/* ---- The scenario. */

/* The scenario's server options, set before a run (a child inherits them from the parent,
 * which sets them for each pass): its workers (0: one per CPU, which reads the affinity mask)
 * and HTTPASM_SERVER_* flags. */
static uint32_t scenario_workers = 1;
static uint16_t scenario_flags;

/* /big's answer: large enough that the output grows and the client's input does too. */
static uint8_t big_body[256 << 10];

/* answer_later: answers a deferred exchange from this thread, with a field, as a handler's
 * worker pool would. Its result is ignored: under injection the answer may be refused, and the
 * connection then ends with the server. Returns NULL. */
static void *answer_later(void *exchange)
{
    static const httpasm_field field = { (const uint8_t *)"x-later", (const uint8_t *)"yes", 7, 3, 0, 0, 0 };
    httpasm_exchange_respond(exchange, 200, &field, 1, (const uint8_t *)"later", 5);
    return NULL;
}

/* answer_big_later: as answer_later, with big_body: the answer outgrows the connection's
 * output when the worker appends it. Returns NULL. */
static void *answer_big_later(void *exchange)
{
    httpasm_exchange_respond(exchange, 200, NULL, 0, big_body, sizeof big_body);
    return NULL;
}

/* target_is: whether the request-target (or :path) is exactly path. */
static int target_is(const httpasm_request *r, const char *path)
{
    size_t n = strlen(path);
    return r->target_length == n && memcmp(r->target, path, n) == 0;
}

/* /large-head's field value: 64,000 octets, a head past the client's 16 KiB input and the
 * connection's 16 KiB output (HTTP/1.1), and past one HTTP/2 frame (CONTINUATION follows). */
static uint8_t large_value[64000];

/* handler: "/echo" answers the body it got, "/big" big_body, "/large-head" "ok" under a 64 KB
 * field, "/defer" and "/defer-big" defer and answer from a thread of their own, small or
 * big_body (inline when no thread can be made: under injection pthread_create fails, and a
 * deferred exchange nobody answers would hold its connection until the stop); anything else
 * "ok". */
static void handler(void *context, httpasm_exchange *exchange)
{
    (void)context;
    const httpasm_request *r = httpasm_exchange_request(exchange);
    void *(*later)(void *) = target_is(r, "/defer") ? answer_later : target_is(r, "/defer-big") ? answer_big_later : NULL;
    if (target_is(r, "/echo")) {
        size_t length = 0;
        const uint8_t *body = httpasm_exchange_body(exchange, &length);
        httpasm_exchange_respond(exchange, 200, NULL, 0, body, length);
    } else if (target_is(r, "/big")) {
        httpasm_exchange_respond(exchange, 200, NULL, 0, big_body, sizeof big_body);
    } else if (target_is(r, "/large-head")) {
        static const httpasm_field large = { (const uint8_t *)"x-large", large_value, 7, sizeof large_value, 0, 0, 0 };
        httpasm_exchange_respond(exchange, 200, &large, 1, (const uint8_t *)"ok", 2);
    } else if (later != NULL && httpasm_exchange_defer(exchange) == 0) {
        pthread_t t;
        if (pthread_create(&t, NULL, later, exchange) == 0)
            pthread_detach(t);
        else
            later(exchange);
    } else {
        httpasm_exchange_respond(exchange, 200, NULL, 0, (const uint8_t *)"ok", 2);
    }
}

/* exchange_raw: one connection to the port: sends the octets, half-closes, reads to the close
 * (each wait 1 s at most: a loopback exchange takes milliseconds, and under a lasting failure -
 * every accept4 failing, say - each of the scenario's ten connections waits its full time, which
 * must stay within the child's 20 s alarm). Returns the octets read, or -1 when the connection
 * failed. */
static ssize_t exchange_raw(uint16_t port, const void *octets, size_t n)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0 || send(fd, octets, n, MSG_NOSIGNAL) != (ssize_t)n) {
        close(fd);
        return -1;
    }
    shutdown(fd, SHUT_WR);
    char buf[4096];
    ssize_t total = 0;
    for (;;) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, 1000) <= 0)
            break;
        ssize_t r = recv(fd, buf, sizeof buf, 0);
        if (r <= 0)
            break;
        total += r;
    }
    close(fd);
    return total;
}

/* The scenario's larger messages, built once by build_messages before any run (static, so
 * building them allocates nothing a count could see; children inherit them). */
static char chunked_upload[41 << 10];
static size_t chunked_upload_length;
static char length_upload[41 << 10];        /* Content-Length: 40000: the input grows to the body */
static size_t length_upload_length;
static char too_large[101 << 10];           /* a body past max_body: 413, then the rest is drained */
static size_t too_large_length;
static unsigned char h2_more[21 << 10];
static size_t h2_more_length;
static unsigned char h2_window[256];
static size_t h2_window_length;

/* put_frame_into: appends an HTTP/2 frame (RFC 9113 4.1) to a message being built.
 *   message, length  the message and its length so far (advanced past the frame);
 *   type, flags, stream  the frame header's fields; payload, size  its payload (NULL: size
 *   octets of 'y'). The callers size the messages for their frames. */
static void put_frame_into(unsigned char *message, size_t *length, int type, int flags, int stream, const void *payload, size_t size)
{
    unsigned char *at = message + *length;
    at[0] = (unsigned char)(size >> 16);
    at[1] = (unsigned char)(size >> 8);
    at[2] = (unsigned char)size;
    at[3] = (unsigned char)type;
    at[4] = (unsigned char)flags;
    at[5] = 0;
    at[6] = 0;
    at[7] = 0;
    at[8] = (unsigned char)stream;
    if (payload != NULL)
        memcpy(at + 9, payload, size);
    else
        memset(at + 9, 'y', size);
    *length += 9 + size;
}

/* put_frame: appends an HTTP/2 frame (RFC 9113 4.1) to h2_more.
 *   type, flags, stream  its header's fields; payload, length  its payload (NULL: length
 *   octets of 'y'). */
static void put_frame(int type, int flags, int stream, const void *payload, size_t length)
{
    unsigned char *at = h2_more + h2_more_length;
    at[0] = (unsigned char)(length >> 16);
    at[1] = (unsigned char)(length >> 8);
    at[2] = (unsigned char)length;
    at[3] = (unsigned char)type;
    at[4] = (unsigned char)flags;
    at[5] = 0;
    at[6] = 0;
    at[7] = 0;
    at[8] = (unsigned char)stream;
    if (payload != NULL)
        memcpy(at + 9, payload, length);
    else
        memset(at + 9, 'y', length);
    h2_more_length += 9 + length;
}

/* build_messages: big_body's octets; the chunked upload (40,000 octets in one chunk, then the
 * trailer X-T); and the HTTP/2 connection's frames: the preface, SETTINGS, stream 1 GET /defer
 * (its :authority added to the dynamic table), stream 3 POST /echo whose head is split between
 * HEADERS and a CONTINUATION (:authority from the dynamic table), 16,384 + 3,616 octets of
 * DATA, and the trailers "x-t: 1" with END_STREAM. Field blocks are written by hand, from
 * RFC 7541's static table (2 GET, 3 POST, 4 :path, 6 http; 1 :authority as a name). */
static void build_messages(void)
{
    for (size_t i = 0; i < sizeof big_body; i++)
        big_body[i] = (uint8_t)('a' + i % 26);

    int head = snprintf(chunked_upload, sizeof chunked_upload,
                        "POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%x\r\n", 40000);
    chunked_upload_length = (size_t)head;
    memset(chunked_upload + chunked_upload_length, 'x', 40000);
    chunked_upload_length += 40000;
    static const char tail[] = "\r\n0\r\nX-T: 1\r\n\r\n";
    memcpy(chunked_upload + chunked_upload_length, tail, sizeof tail - 1);
    chunked_upload_length += sizeof tail - 1;

    head = snprintf(length_upload, sizeof length_upload,
                    "POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 40000\r\nConnection: close\r\n\r\n");
    length_upload_length = (size_t)head;
    memset(length_upload + length_upload_length, 'z', 40000);
    length_upload_length += 40000;

    /* 2 MB announced against the scenario's max_body (1 MiB, the default): 413 at once, then
     * the server drains the 100,000 octets that follow before it closes. */
    head = snprintf(too_large, sizeof too_large, "POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 2000000\r\n\r\n");
    too_large_length = (size_t)head;
    memset(too_large + too_large_length, 'q', 100000);
    too_large_length += 100000;

    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    memcpy(h2_more, preface, sizeof preface - 1);
    h2_more_length = sizeof preface - 1;
    put_frame(4, 0, 0, "", 0);                                                      /* SETTINGS */
    static const unsigned char defer[] = { 0x82, 0x86, 0x04, 6, '/', 'd', 'e', 'f', 'e', 'r', 0x41, 1, 'a' };
    put_frame(1, 0x05, 1, defer, sizeof defer);                                     /* HEADERS, END_STREAM */
    static const unsigned char echo[] = { 0x83, 0x86, 0x04, 5, '/', 'e', 'c', 'h', 'o', 0xbe };
    put_frame(1, 0x00, 3, echo, 5);                                                 /* HEADERS, the head goes on */
    put_frame(9, 0x04, 3, echo + 5, sizeof echo - 5);                               /* CONTINUATION, END_HEADERS */
    put_frame(0, 0, 3, NULL, 16384);                                                /* DATA */
    put_frame(0, 0, 3, NULL, 3616);                                                 /* DATA */
    static const unsigned char trailers[] = { 0x00, 3, 'x', '-', 't', 1, '1' };
    put_frame(1, 0x05, 3, trailers, sizeof trailers);                               /* HEADERS: trailers, END_STREAM */

    /* The second HTTP/2 connection: the connection's window raised by 1 MiB; stream 1 GET
     * /large-head, whose 64 KB answer head takes HEADERS and CONTINUATION frames, each growing
     * the output from its first 16 KiB (first: an output /big's DATA had grown already would
     * take them without growing, and their allocations would never be failed); stream 3 GET
     * /big, whose 256 KiB answer outruns the stream's first window (65,535 octets: the server
     * sends that, then keeps a copy of the rest); then stream 3's window raised by 1 MiB, which
     * lets the rest of /big go. */
    for (size_t i = 0; i < sizeof large_value; i++)
        large_value[i] = 'l';
    static const unsigned char raise[] = { 0x00, 0x10, 0x00, 0x00 };              /* 1 MiB */
    memcpy(h2_window, preface, sizeof preface - 1);
    h2_window_length = sizeof preface - 1;
    put_frame_into(h2_window, &h2_window_length, 4, 0, 0, "", 0);                   /* SETTINGS */
    put_frame_into(h2_window, &h2_window_length, 8, 0, 0, raise, sizeof raise);     /* WINDOW_UPDATE, the connection */
    static const unsigned char large[] = { 0x82, 0x86, 0x04, 11, '/', 'l', 'a', 'r', 'g', 'e', '-', 'h', 'e', 'a', 'd', 0x41, 1, 'a' };
    put_frame_into(h2_window, &h2_window_length, 1, 0x05, 1, large, sizeof large);  /* HEADERS, END_STREAM */
    static const unsigned char big[] = { 0x82, 0x86, 0x04, 4, '/', 'b', 'i', 'g', 0xbe };
    put_frame_into(h2_window, &h2_window_length, 1, 0x05, 3, big, sizeof big);      /* HEADERS, END_STREAM */
    put_frame_into(h2_window, &h2_window_length, 8, 0, 3, raise, sizeof raise);     /* WINDOW_UPDATE, stream 3 */
}

/* client_get: one GET by the httpasm client. Returns httpasm_client_send's result. */
static int client_get(httpasm_client *c, const char *target)
{
    httpasm_request q;
    memset(&q, 0, sizeof q);
    q.method = (const uint8_t *)"GET";
    q.method_length = 3;
    q.target = (const uint8_t *)target;
    q.target_length = (uint32_t)strlen(target);
    q.authority = (const uint8_t *)"a";
    q.authority_length = 1;
    httpasm_client_response r;
    return httpasm_client_send(c, &q, NULL, 0, &r);
}

/* client_get_padded: a GET of "/" whose head carries a 5,000-octet field: past the client's
 * 4 KiB head buffer, which grows to write it. Returns httpasm_client_send's result. */
static int client_get_padded(httpasm_client *c)
{
    static uint8_t pad[5000];
    memset(pad, 'p', sizeof pad);
    static const uint8_t name[] = "x-pad";
    httpasm_field field = { name, pad, sizeof name - 1, sizeof pad, 0, 0, 0 };
    httpasm_request q;
    memset(&q, 0, sizeof q);
    q.method = (const uint8_t *)"GET";
    q.method_length = 3;
    q.target = (const uint8_t *)"/";
    q.target_length = 1;
    q.authority = (const uint8_t *)"a";
    q.authority_length = 1;
    q.fields = &field;
    q.field_count = 1;
    httpasm_client_response r;
    return httpasm_client_send(c, &q, NULL, 0, &r);
}

/* scenario: a server's whole life (this file's header lists its steps). Returns how far it
 * got: 0 all of it, 1-4 the step that reported a failure (an API's failure, which is an
 * acceptable outcome under injection). The raw connections' own failures are not counted:
 * they are this program's, and the steps after them go on. */
static int scenario(void)
{
    static const char h1[] = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    static const char h1_defer[] = "GET /defer HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    static const char h1_defer_big[] = "GET /defer-big HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    /* Two answers of 256 KiB asked for at once: the second is written while the first still
     * fills the output. */
    static const char h1_pipelined[] = "GET /big HTTP/1.1\r\nHost: a\r\n\r\nGET /big HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    static const unsigned char h2[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                                      "\x00\x00\x00\x04\x00\x00\x00\x00\x00"                              /* SETTINGS */
                                      "\x00\x00\x06\x01\x05\x00\x00\x00\x01\x82\x86\x84\x41\x01\x61";    /* HEADERS: GET / a */
    httpasm_server_options o;
    memset(&o, 0, sizeof o);
    o.handler = handler;
    o.workers = scenario_workers;
    o.flags = scenario_flags;
    o.bind_address = htonl(INADDR_LOOPBACK);
    /* Each connection below is a step of its own (step_enter before it): the other threads'
     * allocations are keyed by step and call site (fails), and exchange_raw returns only once
     * the server closed the connection, so a step's allocations never spill into the next. */
    step_reset();
    int error = 0;
    httpasm_server *s = httpasm_server_create(&o, &error);
    if (s == NULL)
        return 1;
    if (httpasm_server_start(s) != 0) {
        httpasm_server_destroy(s);
        return 2;
    }
    uint16_t port = httpasm_server_port(s);
    (void)httpasm_server_io(s);                     /* what the workers run on: MIXED under some failures */
    step_enter("HTTP/1.1 GET /");
    exchange_raw(port, h1, sizeof h1 - 1);
    step_enter("HTTP/1.1 GET /defer");
    exchange_raw(port, h1_defer, sizeof h1_defer - 1);
    step_enter("HTTP/1.1 GET /defer-big");
    exchange_raw(port, h1_defer_big, sizeof h1_defer_big - 1);
    step_enter("HTTP/1.1 two pipelined GET /big");
    exchange_raw(port, h1_pipelined, sizeof h1_pipelined - 1);
    step_enter("HTTP/1.1 a Content-Length upload");
    exchange_raw(port, length_upload, length_upload_length);
    step_enter("HTTP/1.1 a body past max_body");
    exchange_raw(port, too_large, too_large_length);
    step_enter("HTTP/1.1 a chunked upload");
    exchange_raw(port, chunked_upload, chunked_upload_length);
    step_enter("HTTP/2 GET /");
    exchange_raw(port, h2, sizeof h2 - 1);
    step_enter("HTTP/2 /defer, a CONTINUATION, DATA and trailers");
    exchange_raw(port, h2_more, h2_more_length);
    step_enter("HTTP/2 /large-head and /big past its window");
    exchange_raw(port, h2_window, h2_window_length);
    step_enter("the client's requests");
    int result = 0;
    httpasm_client *c = httpasm_client_connect(htonl(INADDR_LOOPBACK), port, 3000, &error);
    if (c == NULL) {
        result = 3;
    } else {
        /* /large-head before /big: /big's body grows the client's input to 512 KiB, after
         * which the 64 KB head would fit without the growth (and its allocations) it is here
         * to cause. */
        if (client_get(c, "/") != 0 || client_get(c, "/large-head") != 0 || client_get(c, "/big") != 0 || client_get_padded(c) != 0)
            result = 4;
        httpasm_client_close(c);
    }
    step_enter("the server's stop and destroy");
    httpasm_server_stop(s);
    httpasm_server_destroy(s);
    return result;
}

/* ---- 2. System calls: a seccomp filter failing one, with an errno. */

/* fail_syscall: installs a filter on this process that fails syscall nr with err. Returns 0, or
 * -1 when the kernel refuses the filter. */
static int fail_syscall(int nr, int err)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ((unsigned)err & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = sizeof filter / sizeof filter[0], .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &program);
}

/* outcomes[k]: how many children ended with scenario() returning k (0: the whole scenario,
 * 1-4: the step whose API reported the failure, 100: the filter could not be installed) - the
 * evidence that the injected failures reach the library rather than passing unnoticed. */
static long outcomes[101];

/* CHILD_CPU_LIMIT: the most CPU seconds a child may use. A whole scenario takes tens of
 * milliseconds; one whose waits time out (a server that never accepts, say) lives about ten
 * seconds, nearly all of them asleep. A worker that spins instead - woken again and again by
 * a listener or a connection it cannot act on - uses a core for all of them. */
#define CHILD_CPU_LIMIT 1.5

/* child_cpu_most: the most CPU seconds any child used, reported as the margin under the limit. */
static double child_cpu_most;

/* judge: a child's end, from wait4. Returns 0 when it ended by itself (any exit status,
 * counted in outcomes) within the CPU limit, else -1 with *how describing it. */
static int judge(int status, const struct rusage *usage, char *how, size_t how_size)
{
    if (WIFSIGNALED(status)) {
        snprintf(how, how_size, WTERMSIG(status) == SIGALRM ? "hung (20 s)" : "killed by signal %d", WTERMSIG(status));
        return -1;
    }
    double cpu = (double)(usage->ru_utime.tv_sec + usage->ru_stime.tv_sec) + (usage->ru_utime.tv_usec + usage->ru_stime.tv_usec) / 1e6;
    if (cpu > child_cpu_most)
        child_cpu_most = cpu;
    if (cpu > CHILD_CPU_LIMIT) {
        snprintf(how, how_size, "spun: %.2f s of CPU (the limit is %.1f s)", cpu, CHILD_CPU_LIMIT);
        return -1;
    }
    if (WEXITSTATUS(status) <= 100)
        outcomes[WEXITSTATUS(status)]++;
    return 0;
}

/* spawn: forks a child that runs the scenario after setup(arg), with a 20 s alarm. Returns its
 * pid, or -1. The parent's stdio is flushed first, so a child's exit() cannot print it again.
 * The child ends with exit(), not _exit(): the coverage build's library writes the markers it
 * ran from its .fini_array (tests/coverage/coverage_rt.asm), which _exit skips, and with _exit
 * every error path this program exists to reach was missing from the coverage report. */
static pid_t spawn(void (*setup)(long), long arg)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(20);
        setup(arg);
        exit(scenario());
    }
    return pid;
}

/* in_child: runs the scenario in one child process (spawn) and waits for it. Returns 0 when it
 * ended by itself within the CPU limit, else -1 with *how describing it (judge). */
static int in_child(void (*setup)(long), long arg, char *how, size_t how_size)
{
    pid_t pid = spawn(setup, arg);
    int status = 0;
    struct rusage usage;
    if (pid < 0 || wait4(pid, &status, 0, &usage) != pid) {
        snprintf(how, how_size, "fork/wait failed");
        return -1;
    }
    return judge(status, &usage, how, how_size);
}

/* PARALLEL: the children run_parallel keeps running at once. Their scenarios are independent
 * (each server on a port of its own), mostly asleep (waiting on loopback), and the judgment
 * is per child (its own CPU time from wait4), so running them side by side changes no verdict
 * and divides the time: run one by one, the sweeps took most of an hour. */
#define PARALLEL 8

/* run_parallel: runs `total` children, PARALLEL at a time. Child i is configured in this
 * process by configure(i) just before its fork (it inherits that state), then runs setup(i) and
 * the scenario. Each child that did not end by itself is reported with report(i, how).
 * Returns how many those were. */
static int run_parallel(long total, void (*configure)(long), void (*setup)(long), void (*report)(long, const char *))
{
    struct { pid_t pid; long index; } running[PARALLEL];
    int active = 0;
    int failed = 0;
    long next = 0;
    while (next < total || active > 0) {
        while (active < PARALLEL && next < total) {
            configure(next);
            pid_t pid = spawn(setup, next);
            if (pid < 0) {
                report(next, "fork failed");
                failed++;
            } else {
                running[active].pid = pid;
                running[active].index = next;
                active++;
            }
            next++;
        }
        if (active == 0)
            continue;
        int status = 0;
        struct rusage usage;
        pid_t done = wait4(-1, &status, 0, &usage);
        if (done < 0) {
            perror("faults: wait4");
            return failed + active;
        }
        for (int i = 0; i < active; i++) {
            if (running[i].pid != done)
                continue;
            char how[128];
            if (judge(status, &usage, how, sizeof how) != 0) {
                report(running[i].index, how);
                failed++;
            }
            running[i] = running[--active];
            break;
        }
    }
    return failed;
}

/* ---- 3. Descriptor exhaustion. */

/* EXHAUST_ROOM: the descriptors the server's process may still open once the limit is set,
 * and EXHAUST_CONNECTIONS: the connections the other process makes, three times as many. */
#define EXHAUST_ROOM 4
#define EXHAUST_CONNECTIONS 12

/* exhaustion_server: the server's process. It starts a server on the backend `flags` asks
 * for (idle_ms: its idle timeout, 0 the default), lowers RLIMIT_NOFILE so only EXHAUST_ROOM more descriptors can be opened, writes the
 * port to `out`, then answers commands read from `in`: 'c' writes the process's CPU time so far
 * (microseconds, a uint64_t); anything else, or the parent's end, stops and destroys the server
 * and exits 0. Exits 2 when the server cannot start, 3 when the limit cannot be set. */
static void exhaustion_server(int in, int out, uint16_t flags, uint32_t idle_ms)
{
    httpasm_server_options o;
    memset(&o, 0, sizeof o);
    o.handler = handler;
    o.workers = 1;
    o.bind_address = htonl(INADDR_LOOPBACK);
    o.flags = flags;
    o.idle_timeout_ms = idle_ms;
    int error = 0;
    httpasm_server *s = httpasm_server_create(&o, &error);
    if (s == NULL || httpasm_server_start(s) != 0)
        exit(2);
    uint16_t port = httpasm_server_port(s);
    /* The highest open descriptor, the server's own included. The holes below it (the pipe
     * ends this process closed) would add to the room, so they are filled first: the kernel
     * always hands out the lowest free descriptor, and once one lands above the top, every
     * descriptor up to the top is open. A limit of top + 1 + EXHAUST_ROOM then leaves exactly
     * EXHAUST_ROOM for the connections the worker accepts. */
    int top = -1;
    for (int fd = 0; fd < 4096; fd++) {
        if (fcntl(fd, F_GETFD) != -1)
            top = fd;
    }
    for (;;) {
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            exit(3);
        if (fd > top) {
            close(fd);
            break;
        }
    }
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
        exit(3);
    limit.rlim_cur = (rlim_t)top + 1 + EXHAUST_ROOM;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
        exit(3);
    if (write(out, &port, sizeof port) != sizeof port)
        exit(3);
    char command;
    while (read(in, &command, 1) == 1 && command == 'c') {
        struct rusage u;
        getrusage(RUSAGE_SELF, &u);
        uint64_t us = (uint64_t)(u.ru_utime.tv_sec + u.ru_stime.tv_sec) * 1000000u + (uint64_t)(u.ru_utime.tv_usec + u.ru_stime.tv_usec);
        if (write(out, &us, sizeof us) != sizeof us)
            break;
    }
    httpasm_server_stop(s);
    httpasm_server_destroy(s);
    exit(0);
}

/* server_cpu: the server process's CPU time so far, in microseconds (or UINT64_MAX when it
 * does not answer). */
static uint64_t server_cpu(int to, int from)
{
    uint64_t us;
    if (write(to, "c", 1) != 1 || read(from, &us, sizeof us) != sizeof us)
        return UINT64_MAX;
    return us;
}

/* exhaustion: the descriptor-exhaustion check on one backend (see this file's header).
 * idle_ms 0 keeps the default idle timeout, so the accepted connections hold their descriptors
 * through the check and the waiting request must not be answered early. A short one (50 ms)
 * closes them while the listener rests: the earliest deadline then comes before the pause's
 * end (100 ms), which the worker's wait must take first; the waiting request may then be
 * answered at any time, so only the rest (no spin) and the answer are checked.
 * Returns 0 when it held, else 1 with the failure printed. */
static int exhaustion(uint16_t flags, const char *backend, uint32_t idle_ms)
{
    int down[2], up[2];
    if (pipe(down) != 0 || pipe(up) != 0)
        return fprintf(stderr, "faults: exhaustion (%s): no pipe\n", backend), 1;
    fflush(NULL);                               /* the child ends with exit(): see in_child */
    pid_t pid = fork();
    if (pid == 0) {
        alarm(30);
        close(down[1]);
        close(up[0]);
        exhaustion_server(down[0], up[1], flags, idle_ms);
    }
    close(down[0]);
    close(up[1]);
    int failed = 0;
    int fds[EXHAUST_CONNECTIONS];
    int made = 0;
    uint16_t port = 0;
    if (pid < 0 || read(up[0], &port, sizeof port) != sizeof port) {
        fprintf(stderr, "faults: exhaustion (%s): the server did not start\n", backend);
        failed = 1;
        goto done;
    }
    /* Every connect completes (the kernel finishes the handshake into the backlog); the server
     * takes EXHAUST_ROOM of them, and its next accept4 fails with EMFILE. */
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    for (; made < EXHAUST_CONNECTIONS; made++) {
        fds[made] = socket(AF_INET, SOCK_STREAM, 0);
        if (fds[made] < 0 || connect(fds[made], (struct sockaddr *)&to, sizeof to) != 0) {
            fprintf(stderr, "faults: exhaustion (%s): connection %d failed: %s\n", backend, made, strerror(errno));
            if (fds[made] >= 0)
                close(fds[made]);
            failed = 1;
            goto done;
        }
    }
    static const char request[] = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    int last = fds[EXHAUST_CONNECTIONS - 1];
    if (send(last, request, sizeof request - 1, MSG_NOSIGNAL) != (ssize_t)(sizeof request - 1)) {
        fprintf(stderr, "faults: exhaustion (%s): the request was not sent\n", backend);
        failed = 1;
        goto done;
    }
    usleep(200000);                         /* the worker has met EMFILE by now */
    uint64_t before = server_cpu(down[1], up[0]);
    usleep(1000000);
    uint64_t after = server_cpu(down[1], up[0]);
    struct pollfd p = { .fd = last, .events = POLLIN };
    int answered_early = poll(&p, 1, 0);
    printf("faults: exhaustion (%s): %d connections against %d descriptors; the server used %.1f ms of CPU in the second after\n",
           backend, EXHAUST_CONNECTIONS, EXHAUST_ROOM, (double)(after - before) / 1000.0);
    if (before == UINT64_MAX || after == UINT64_MAX || after - before > 150000) {
        fprintf(stderr, "faults: exhaustion (%s): the server spun while out of descriptors (%.1f ms of CPU in 1 s)\n", backend,
                (double)(after - before) / 1000.0);
        failed = 1;
    }
    if (answered_early != 0 && idle_ms == 0) {
        fprintf(stderr, "faults: exhaustion (%s): the last connection was answered while the descriptors were short\n", backend);
        failed = 1;
    }
    /* Recovery: the first 8 connections close; the server reads their end and frees its
     * descriptors, takes the waiting connections once its pause is over, and answers. */
    for (int i = 0; i < 8; i++)
        close(fds[i]);
    char reply[64] = { 0 };
    if (poll(&p, 1, 3000) != 1 || recv(last, reply, sizeof reply - 1, 0) < 12 || memcmp(reply, "HTTP/1.1 200", 12) != 0) {
        fprintf(stderr, "faults: exhaustion (%s): the request that waited was not answered after descriptors freed\n", backend);
        failed = 1;
    }
    for (int i = 8; i < made; i++)
        close(fds[i]);
    made = 0;
done:
    for (int i = 0; i < made; i++)
        close(fds[i]);
    close(down[1]);                         /* the server's process stops and exits */
    int status = 0;
    if (pid > 0 && (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)) {
        fprintf(stderr, "faults: exhaustion (%s): the server's process ended badly (status 0x%x)\n", backend, status);
        failed = 1;
    }
    close(up[0]);
    return failed;
}

/* stop_while_resting: a stop that begins while the listener rests (see this file's header).
 * The server's process takes EXHAUST_ROOM of the connections, the first with a request head
 * in progress (so the stop waits for it: it is not idle), and rests; the stop then begins
 * ("s": exhaustion_server stops on any command but 'c'), closing the listener; the rest's end
 * (HA_ACCEPT_PAUSE_MS, 100 ms) comes during the stop and must leave the closed listener alone;
 * the head is finished 300 ms in, and its request is answered; then the stop returns and the
 * process exits 0. Returns 0 when it held, else 1 with the failure printed. */
static int stop_while_resting(uint16_t flags, const char *backend)
{
    int down[2], up[2];
    if (pipe(down) != 0 || pipe(up) != 0)
        return fprintf(stderr, "faults: stop while resting (%s): no pipe\n", backend), 1;
    fflush(NULL);                               /* the child ends with exit(): see in_child */
    pid_t pid = fork();
    if (pid == 0) {
        alarm(30);
        close(down[1]);
        close(up[0]);
        exhaustion_server(down[0], up[1], flags, 0);
    }
    close(down[0]);
    close(up[1]);
    int failed = 0;
    int fds[EXHAUST_CONNECTIONS];
    int made = 0;
    uint16_t port = 0;
    if (pid < 0 || read(up[0], &port, sizeof port) != sizeof port) {
        fprintf(stderr, "faults: stop while resting (%s): the server did not start\n", backend);
        failed = 1;
        goto done;
    }
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    for (; made < EXHAUST_CONNECTIONS; made++) {
        fds[made] = socket(AF_INET, SOCK_STREAM, 0);
        if (fds[made] < 0 || connect(fds[made], (struct sockaddr *)&to, sizeof to) != 0) {
            fprintf(stderr, "faults: stop while resting (%s): connection %d failed: %s\n", backend, made, strerror(errno));
            if (fds[made] >= 0)
                close(fds[made]);
            failed = 1;
            goto done;
        }
    }
    /* The first connection is among those accepted (the backlog is taken in order). */
    static const char start[] = "GET / HTTP/1.1\r\nHo", rest[] = "st: a\r\n\r\n";
    if (send(fds[0], start, sizeof start - 1, MSG_NOSIGNAL) != (ssize_t)(sizeof start - 1)) {
        fprintf(stderr, "faults: stop while resting (%s): the head was not sent\n", backend);
        failed = 1;
        goto done;
    }
    usleep(200000);                         /* accepted, the head read, and resting since EMFILE */
    if (write(down[1], "s", 1) != 1) {
        fprintf(stderr, "faults: stop while resting (%s): the stop was not asked for\n", backend);
        failed = 1;
        goto done;
    }
    usleep(300000);                         /* the rest ends during the stop */
    char reply[64] = { 0 };
    struct pollfd p = { .fd = fds[0], .events = POLLIN };
    if (send(fds[0], rest, sizeof rest - 1, MSG_NOSIGNAL) != (ssize_t)(sizeof rest - 1) || poll(&p, 1, 3000) != 1
        || recv(fds[0], reply, sizeof reply - 1, 0) < 12 || memcmp(reply, "HTTP/1.1 200", 12) != 0) {
        fprintf(stderr, "faults: stop while resting (%s): the request in progress was not answered during the stop\n", backend);
        failed = 1;
    }
    printf("faults: stop while resting (%s): the listener closed and the rest ended during the stop; the request in "
           "progress was answered\n", backend);
done:
    for (int i = 0; i < made; i++)
        close(fds[i]);
    close(down[1]);
    int status = 0;
    if (pid > 0 && (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)) {
        fprintf(stderr, "faults: stop while resting (%s): the server's process ended badly (status 0x%x)\n", backend, status);
        failed = 1;
    }
    close(up[0]);
    return failed;
}

static void set_syscall(long packed)
{
    if (fail_syscall((int)(packed >> 16), (int)(packed & 0xFFFF)) != 0)
        exit(100);
}

/* ---- 4. System calls: the k-th call failing, through a supervisor thread.
 *
 * A seccomp filter returning SECCOMP_RET_USER_NOTIF hands each call of one system call to the
 * listener the filter returned (SECCOMP_FILTER_FLAG_NEW_LISTENER); the supervisor thread reads
 * each (SECCOMP_IOCTL_NOTIF_RECV) and answers it (SECCOMP_IOCTL_NOTIF_SEND): the k-th with an
 * errno, every other with SECCOMP_USER_NOTIF_FLAG_CONTINUE, which lets the kernel run it as if
 * no filter were there (Linux 5.5). The supervisor is created before the filter is installed,
 * and the filter goes on the scenario's thread alone (no TSYNC): the threads that thread makes
 * afterwards - the server's workers, the threads that answer deferred requests - inherit it,
 * while the supervisor never meets it. So it can answer calls of any system call, thread
 * creation (clone3) and write included, without calling them in the middle of its own work. */

static int notify_nr = -1;                  /* the system call handed to the supervisor */
static int notify_err;                      /* the errno of the call that fails */
static long notify_fail_at;                 /* that call (1-based); 0: none fails, they are counted */
static _Atomic int notify_fd = -1;          /* the filter's listener, once installed */
static _Atomic long notify_calls;           /* calls seen by this process's supervisor */
static _Atomic long *notify_seen;           /* a counting run's calls, in memory shared with the
                                               parent (failing runs run side by side, so each
                                               counts in its own notify_calls) */

/* supervise: the supervisor's loop: waits for the listener (installing the filter takes
 * nothing from this thread), then answers every notification until the listener ends with the
 * process. Its two records are static: an allocation here would be counted with the
 * scenario's, and the notification sizes are the kernel's (SECCOMP_GET_NOTIF_SIZES).
 *   unused  pthread's argument. Returns NULL. */
static void *supervise(void *unused)
{
    (void)unused;
    int fd;
    while ((fd = atomic_load(&notify_fd)) < 0)
        usleep(50);
    struct seccomp_notif_sizes sizes;
    static _Alignas(16) unsigned char request_space[512], response_space[128];
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0 || sizes.seccomp_notif > sizeof request_space
        || sizes.seccomp_notif_resp > sizeof response_space) {
        fprintf(stderr, "faults: the kernel's notification records do not fit\n");
        exit(100);
    }
    struct seccomp_notif *request = (struct seccomp_notif *)request_space;
    struct seccomp_notif_resp *response = (struct seccomp_notif_resp *)response_space;
    for (;;) {
        memset(request, 0, sizes.seccomp_notif);    /* RECV requires a zeroed record */
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, request) != 0) {
            if (errno == EINTR)
                continue;
            return NULL;                            /* the listener is gone: the process ends */
        }
        long k = atomic_fetch_add(&notify_calls, 1) + 1;
        if (notify_fail_at == 0)
            atomic_store(notify_seen, k);           /* counting: the parent reads it */
        memset(response, 0, sizes.seccomp_notif_resp);
        response->id = request->id;
        if (k == notify_fail_at)
            response->error = -notify_err;
        else
            response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        /* ENOENT when the caller was interrupted meanwhile: its call is gone, nothing to do. */
        ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, response);
    }
}

/* start_supervised: a child's setup for the sweep: the supervisor thread, then the filter on
 * this thread, handing notify_nr's calls to it. Exits with 100 (counted apart) when the kernel
 * refuses either. */
static void start_supervised(long unused)
{
    (void)unused;
    pthread_t t;
    atomic_store(&notify_fd, -1);
    if (pthread_create(&t, NULL, supervise, NULL) != 0)
        exit(100);
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)notify_nr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = sizeof filter / sizeof filter[0], .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        exit(100);
    int fd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    if (fd < 0)
        exit(100);
    atomic_store(&notify_fd, fd);
}

/* SWEEP_LIMIT: the most calls of one system call failed in turn. A scenario makes some calls
 * hundreds of times (recvfrom, sendto); their sites are all among the first ones, and every
 * child costs a whole scenario. */
#define SWEEP_LIMIT 48

/* sweep_entry: one system call, the errno its failing call returns, and the scenario's server
 * options for it (thread creation is swept with two workers, so the second one's failure
 * leaves a server partly started; the CPU count with workers 0; io_uring's calls on a server
 * asking for io_uring). */
struct sweep_entry {
    int nr;
    int err;
    uint32_t workers;
    uint16_t flags;
    const char *name;
};

/* The entry sweep() is running, and its count: for configure_call and report_call. */
static const struct sweep_entry *sweep_entry_now;
static long sweep_count_now;

/* configure_call: before failing run i's fork: its call to fail is the (i + 1)-th. */
static void configure_call(long i)
{
    notify_fail_at = i + 1;
}

/* report_call: prints failing run i of the current entry, which did not end by itself. */
static void report_call(long i, const char *how)
{
    fprintf(stderr, "faults: %s, call %ld of %ld failing: %s\n", sweep_entry_now->name, i + 1, sweep_count_now, how);
}

/* sweep: counts entry's calls in one supervised run, then fails each of the first
 * SWEEP_LIMIT in a run of its own (run_parallel). Returns the runs whose child did not end by
 * itself (each printed), and adds the runs made to *runs. */
static int sweep(const struct sweep_entry *entry, long *runs)
{
    char how[128];
    scenario_workers = entry->workers;
    scenario_flags = entry->flags;
    notify_nr = entry->nr;
    notify_err = entry->err;
    notify_fail_at = 0;
    atomic_store(notify_seen, 0);
    int failed = 0;
    if (in_child(start_supervised, 0, how, sizeof how) != 0) {
        fprintf(stderr, "faults: %s, counting: %s\n", entry->name, how);
        failed++;
    }
    long count = atomic_load(notify_seen);
    long last = count < SWEEP_LIMIT ? count : SWEEP_LIMIT;
    sweep_entry_now = entry;
    sweep_count_now = count;
    failed += run_parallel(last, configure_call, start_supervised, report_call);
    *runs += 1 + last;
    scenario_workers = 1;
    scenario_flags = 0;
    return failed;
}

/* set_main_fail_index: a failing allocation run's setup in the child: the (i + 1)-th allocation
 * its scenario makes on its own thread fails (the child's count, at its fork, is the parent's). */
static void set_main_fail_index(long i)
{
    main_fail_at = main_allocations + i + 1;
}

/* configure_nothing: the allocation runs need no state set before their fork. */
static void configure_nothing(long i)
{
    (void)i;
}

/* The scenario's own thread's allocation runs, for its reports. */
static long main_allocation_count;

/* report_main_allocation: prints failing allocation run i of the scenario's own thread, which
 * did not end by itself, with the command that repeats it in one process (for a debugger). */
static void report_main_allocation(long i, const char *how)
{
    fprintf(stderr, "faults: allocation %ld of %ld on the scenario's thread failing: %s; in one process: faults alloc-main %ld\n",
            i + 1, main_allocation_count, how, i + 1);
}

/* COUNT_RUNS: the whole runs of the scenario whose other threads' sites make the sweep's plan,
 * each site at the most calls it made in any of them: a site whose calls follow the socket's
 * pace (an output grown once more when the peer happened to read later) shows its most in one
 * of them more surely than in one run. */
#define COUNT_RUNS 3

/* SITE_MARGIN: the calls past each site's most that the sweep fails too: a pace no count run
 * met may grow a buffer once or twice more. A child whose extra call never comes runs whole. */
#define SITE_MARGIN 2

/* seen_site: one call site of one step of the other threads over the count runs: the fewest
 * and the most calls it made in a run, and in how many runs it was met. */
struct seen_site {
    int step;
    uintptr_t site;
    long least;
    long most;
    int runs;
};

/* SEEN: the step sites the count runs may meet in all (the scenario meets about 45). */
#define SEEN 512
static struct seen_site seen[SEEN];
static long seen_count;

/* merge_sites: adds one count run's tables (sites) to seen: a site met before takes the fewest
 * and the most of its calls, a new one is appended. Returns 0, or -1 when a table or seen
 * overflowed (raise SITES or SEEN: a site left out would never be failed). */
static int merge_sites(void)
{
    int last = atomic_load(&step);
    for (int s = 0; s <= last; s++) {
        for (int i = 0; i < SITES; i++) {
            uintptr_t address = atomic_load(&sites[s][i].address);
            if (address == 0)
                continue;
            long calls = atomic_load(&sites[s][i].calls);
            long k = 0;
            while (k < seen_count && (seen[k].step != s || seen[k].site != address))
                k++;
            if (k == seen_count) {
                if (seen_count == SEEN)
                    return -1;
                seen[seen_count++] = (struct seen_site){ s, address, calls, calls, 0 };
            }
            if (calls < seen[k].least)
                seen[k].least = calls;
            if (calls > seen[k].most)
                seen[k].most = calls;
            seen[k].runs++;
        }
    }
    return atomic_load(&sites_full) ? -1 : 0;
}

/* count_runs: runs the scenario `runs` times in this process, merging each run's sites (seen).
 * Returns 0; the first run's result when a run did not go whole (the plan needs whole runs);
 * or -1 when the tables overflowed. The scenario's own thread's allocations of the first run
 * go to *main_count (they come in one order every run). */
static int count_runs(int runs, long *main_count)
{
    for (int run = 0; run < runs; run++) {
        long main_before = main_allocations;
        int r = scenario();
        if (run == 0)
            *main_count = main_allocations - main_before;
        if (r != 0)
            return r;
        if (merge_sites() != 0)
            return -1;
    }
    return 0;
}

/* planned_call: one child of the other threads' sweep: call `call` from `site` in `step` fails. */
struct planned_call {
    int step;
    uintptr_t site;
    long call;
};

/* PLANNED: the children the other threads' sweep has room for (the scenario needs about 180:
 * its 90 calls and SITE_MARGIN past each of its 45 step sites). */
#define PLANNED 2048
static struct planned_call plan[PLANNED];
static long planned;

/* plan_other_calls: the other threads' sweep from seen: every call of every step site, up to
 * its most plus SITE_MARGIN. Returns 0, or -1 when the plan overflowed (raise PLANNED). */
static int plan_other_calls(void)
{
    planned = 0;
    for (long k = 0; k < seen_count; k++) {
        for (long call = 1; call <= seen[k].most + SITE_MARGIN; call++) {
            if (planned == PLANNED)
                return -1;
            plan[planned++] = (struct planned_call){ seen[k].step, seen[k].site, call };
        }
    }
    return 0;
}

/* set_other_fail_call: a failing allocation run's setup in the child: plan[i]'s call fails. The
 * child's scenario counts its own calls from zero (step_reset), so the call is that run's. */
static void set_other_fail_call(long i)
{
    fail_step = plan[i].step;
    fail_site = plan[i].site;
    fail_call = plan[i].call;
}

/* report_other_allocation: prints failing allocation run i of the other threads, which did not
 * end by itself: its step, call and site, and the command that repeats it in one process. */
static void report_other_allocation(long i, const char *how)
{
    char where[160];
    site_name(plan[i].site, where, sizeof where);
    fprintf(stderr, "faults: call %ld from %s on the other threads in step %d (%s) failing: %s; in one process: faults "
            "alloc-other %d %s %ld\n", plan[i].call, where, plan[i].step, step_names[plan[i].step], how, plan[i].step, where,
            plan[i].call);
}

/* print_sites: the count runs' step sites (seen), by step: each site as OBJECT+OFFSET with its
 * fewest and most calls in a run (0 fewest: a run that never met it), for "faults sites". */
static void print_sites(int runs)
{
    int last = atomic_load(&step);
    for (int s = 0; s <= last; s++) {
        printf("step %d: %s\n", s, step_names[s]);
        for (long k = 0; k < seen_count; k++) {
            if (seen[k].step != s)
                continue;
            char where[160];
            site_name(seen[k].site, where, sizeof where);
            long least = seen[k].runs < runs ? 0 : seen[k].least;
            if (least == seen[k].most)
                printf("  %s: %ld\n", where, seen[k].most);
            else
                printf("  %s: %ld to %ld\n", where, least, seen[k].most);
        }
    }
}

/* main: counts the scenario's allocations, fails each, then each system call for good, then
 * each call of each system call in turn, then exhausts the descriptors. Exit status: 0 when
 * every child ended by itself and every check held, 1 otherwise.
 * Debug modes, each in this one process (no child; for a debugger, or to see a site's code):
 *   "faults alloc-main N"              the N-th allocation of the scenario's thread fails;
 *   "faults alloc-other STEP SITE N"   call N from SITE (OBJECT+OFFSET) in step STEP fails,
 *                                      as a failing child's report names it;
 *   "faults sites"                     the count runs' step sites, with their calls. */
int main(int argc, char **argv)
{
    int failures = 0;
    char how[128];
    main_thread = 1;
    build_messages();
    if (argc == 3 && strcmp(argv[1], "alloc-main") == 0) {
        main_fail_at = main_allocations + atol(argv[2]);    /* from the scenario's start, as a child's */
        debug_alloc = 1;
        int r = scenario();
        printf("faults: the scenario with allocation %s of its own thread failing returned %d\n", argv[2], r);
        return 0;
    }
    if (argc == 5 && strcmp(argv[1], "alloc-other") == 0) {
        fail_step = atoi(argv[2]);
        fail_site = site_address(argv[3]);
        fail_call = atol(argv[4]);
        if (fail_site == 0) {
            fprintf(stderr, "faults: no loaded object is named as in %s (OBJECT+OFFSET, as a report prints it)\n", argv[3]);
            return 1;
        }
        debug_alloc = 1;
        int r = scenario();
        printf("faults: the scenario with call %s from %s in step %s failing returned %d\n", argv[4], argv[3], argv[2], r);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "sites") == 0) {
        long main_count = 0;
        int r = count_runs(COUNT_RUNS, &main_count);
        print_sites(COUNT_RUNS);
        printf("faults: %d runs (%d), %ld allocations each on the scenario's thread\n", COUNT_RUNS, r, main_count);
        return r == 0 ? 0 : 1;
    }
    /* The count: COUNT_RUNS whole runs in this process (the parent's own allocations before and
     * after stay out of them). */
    long before = allocations, other_before = atomic_load(&other_allocations);
    long main_count = 0;
    int r = count_runs(COUNT_RUNS, &main_count);
    long other_count = (atomic_load(&other_allocations) - other_before) / COUNT_RUNS;
    printf("faults: the scenario runs whole (%d) %d times with %ld allocations each, %ld on its own thread and about %ld on the "
           "others, from %ld call sites of %d steps\n", r, COUNT_RUNS, (allocations - before) / COUNT_RUNS, main_count, other_count,
           seen_count, atomic_load(&step) + 1);
    if (r != 0 || plan_other_calls() != 0) {
        if (r == -1 || r == 0)
            fprintf(stderr, "faults: the site tables overflowed (SITES %d, SEEN %d, PLANNED %d): sites would go unfailed\n", SITES,
                    SEEN, PLANNED);
        return 1;
    }
    /* The scenario's own thread allocates in one order every run: two past its count is plenty. */
    main_allocation_count = main_count + 2;
    failures += run_parallel(main_allocation_count, configure_nothing, set_main_fail_index, report_main_allocation);
    failures += run_parallel(planned, configure_nothing, set_other_fail_call, report_other_allocation);
    printf("faults: each of %ld allocations of the scenario's thread failed in turn, and each of %ld calls from the others' "
           "%ld step sites: %d children did not end by themselves\n", main_allocation_count, planned, seen_count, failures);

    static const struct { int nr; int err; const char *name; } calls[] = {
        { SYS_socket, EMFILE, "socket EMFILE" },         { SYS_bind, EADDRINUSE, "bind EADDRINUSE" },
        { SYS_listen, ENOBUFS, "listen ENOBUFS" },       { SYS_setsockopt, ENOMEM, "setsockopt ENOMEM" },
        { SYS_epoll_create1, EMFILE, "epoll_create1 EMFILE" }, { SYS_epoll_ctl, ENOMEM, "epoll_ctl ENOMEM" },
        { SYS_eventfd2, EMFILE, "eventfd2 EMFILE" },     { SYS_accept4, EMFILE, "accept4 EMFILE" },
        { SYS_recvfrom, ENOMEM, "recvfrom ENOMEM" },     { SYS_sendto, ENOBUFS, "sendto ENOBUFS" },
        { SYS_sendmsg, ENOBUFS, "sendmsg ENOBUFS" },     { SYS_connect, ECONNREFUSED, "connect ECONNREFUSED" },
        { SYS_clone3, EAGAIN, "clone3 EAGAIN" },         { SYS_clone, EAGAIN, "clone EAGAIN" },
        { SYS_shutdown, ENOTCONN, "shutdown ENOTCONN" }, { SYS_timerfd_create, EMFILE, "timerfd_create EMFILE" },
    };
    int syscall_failures = 0;
    for (size_t i = 0; i < sizeof calls / sizeof calls[0]; i++) {
        if (in_child(set_syscall, (long)calls[i].nr << 16 | calls[i].err, how, sizeof how) != 0) {
            fprintf(stderr, "faults: %s: %s\n", calls[i].name, how);
            syscall_failures++;
        }
    }
    printf("faults: %zu system calls failed in turn: %d children did not end by themselves\n", sizeof calls / sizeof calls[0],
           syscall_failures);
    /* 4. The k-th call of each system call the server, the client and the scenario make, with
     * the errnos those calls can see: the transient ones (EINTR, EAGAIN, a peer gone) as well
     * as the lasting ones section 2 tries. */
    static const struct sweep_entry entries[] = {
        { SYS_socket, EMFILE, 1, 0, "socket EMFILE" },
        { SYS_setsockopt, ENOMEM, 1, 0, "setsockopt ENOMEM" },
        { SYS_bind, EADDRINUSE, 1, 0, "bind EADDRINUSE" },
        { SYS_listen, ENOBUFS, 1, 0, "listen ENOBUFS" },
        { SYS_getsockname, ENOBUFS, 1, 0, "getsockname ENOBUFS" },
        { SYS_epoll_create1, EMFILE, 1, 0, "epoll_create1 EMFILE" },
        { SYS_epoll_ctl, ENOMEM, 1, 0, "epoll_ctl ENOMEM" },
        { SYS_epoll_wait, EINTR, 1, 0, "epoll_wait EINTR" },
        { SYS_eventfd2, EMFILE, 1, 0, "eventfd2 EMFILE" },
        { SYS_accept4, ECONNABORTED, 1, 0, "accept4 ECONNABORTED" },
        { SYS_accept4, EINTR, 1, 0, "accept4 EINTR" },
        { SYS_accept4, ENFILE, 1, 0, "accept4 ENFILE" },
        { SYS_accept4, ENOBUFS, 1, 0, "accept4 ENOBUFS" },
        { SYS_accept4, ENOMEM, 1, 0, "accept4 ENOMEM" },
        { SYS_recvfrom, EINTR, 1, 0, "recvfrom EINTR" },
        { SYS_recvfrom, EAGAIN, 1, 0, "recvfrom EAGAIN" },
        { SYS_recvfrom, ECONNRESET, 1, 0, "recvfrom ECONNRESET" },
        { SYS_sendto, EINTR, 1, 0, "sendto EINTR" },
        { SYS_sendto, EAGAIN, 1, 0, "sendto EAGAIN" },
        { SYS_sendto, EPIPE, 1, 0, "sendto EPIPE" },
        { SYS_sendmsg, EINTR, 1, 0, "sendmsg EINTR" },
        { SYS_sendmsg, EAGAIN, 1, 0, "sendmsg EAGAIN" },
        { SYS_sendmsg, EPIPE, 1, 0, "sendmsg EPIPE" },
        { SYS_connect, ECONNREFUSED, 1, 0, "connect ECONNREFUSED" },
        { SYS_poll, EINTR, 1, 0, "poll EINTR" },
        { SYS_getsockopt, ENOBUFS, 1, 0, "getsockopt ENOBUFS" },
        { SYS_shutdown, ENOTCONN, 1, 0, "shutdown ENOTCONN" },
        { SYS_read, EAGAIN, 1, 0, "read EAGAIN" },
        { SYS_clone3, EAGAIN, 2, 0, "clone3 EAGAIN (two workers)" },
        { SYS_sched_getaffinity, EINVAL, 0, 0, "sched_getaffinity EINVAL (one worker per CPU)" },
        { SYS_io_uring_setup, ENOMEM, 1, HTTPASM_SERVER_URING, "io_uring_setup ENOMEM" },
        { SYS_io_uring_setup, ENOMEM, 2, HTTPASM_SERVER_URING, "io_uring_setup ENOMEM (two workers: one on epoll)" },
        { SYS_mmap, ENOMEM, 1, HTTPASM_SERVER_URING, "mmap ENOMEM (io_uring)" },
    };
    /* Not swept, measured 2026-11-26: io_uring_enter, whose completions run as the caller's
     * task work, which the notification's wait holds back - even a counting run, failing
     * nothing, hung; and the eventfd's write, which no kernel fails with EAGAIN below its
     * counter's 2^64 - 2 (a failing wake hung the stop, which waits for the woken worker). */
    /* The supervisor's count lives in memory the children share with this process. */
    notify_seen = mmap(NULL, sizeof *notify_seen, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (notify_seen == MAP_FAILED) {
        perror("faults: mmap");
        return 1;
    }
    long sweep_runs = 0;
    long before_sweep = outcomes[100];
    int sweep_failures = 0;
    for (size_t i = 0; i < sizeof entries / sizeof entries[0]; i++)
        sweep_failures += sweep(&entries[i], &sweep_runs);
    printf("faults: %zu system calls failed one call at a time (%ld runs): %d children did not end by themselves\n",
           sizeof entries / sizeof entries[0], sweep_runs, sweep_failures);
    if (outcomes[100] != before_sweep) {
        fprintf(stderr, "faults: %ld supervised children could not install the filter\n", outcomes[100] - before_sweep);
        sweep_failures++;
    }

    printf("faults: the children's scenarios: %ld whole, %ld refused at create, %ld at start, %ld at the client's connect, "
           "%ld at its send, %ld without a filter; the most CPU a child used: %.2f s (the limit is %.1f s)\n",
           outcomes[0], outcomes[1], outcomes[2], outcomes[3], outcomes[4], outcomes[100], child_cpu_most, CHILD_CPU_LIMIT);

    int exhausted = exhaustion(0, "epoll", 0) + exhaustion(HTTPASM_SERVER_URING, "io_uring", 0)
                    + exhaustion(0, "epoll, 50 ms idle", 50) + exhaustion(HTTPASM_SERVER_URING, "io_uring, 50 ms idle", 50)
                    + stop_while_resting(0, "epoll") + stop_while_resting(HTTPASM_SERVER_URING, "io_uring");
    return failures + syscall_failures + sweep_failures + exhausted == 0 ? 0 : 1;
}
