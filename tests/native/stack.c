/*
 * stack.c - proves that HttpAsm's functions whose frames pass a page (ML-KEM's: up to about 10 KiB
 * at v1 and 19 KiB at v3) touch their stack at most 4032 octets apart on the way down
 * (crypto/mlkem.asm's MK_ENTER), so that a thread whose stack is nearly spent faults on its guard
 * page instead of the frame stepping over the guard into whatever is mapped below it (a stack
 * clash: the class of CVE-2017-1000364). Each ML-KEM function, at v1 and at the best tier:
 *   - its depth is measured: run on a painted 128 KiB stack, the lowest octet it changed;
 *   - it runs again, in a forked child, on stacks too small for that depth (from 64 octets short
 *     down to 1 KiB, every 1000 octets: the guard page sits at every kind of place in the frame),
 *     with a PROT_NONE guard page below each and a 64 KiB shared sentinel below the guard, filled
 *     with a pattern: the child must die by SIGSEGV with its fault address in the guard page, and
 *     the sentinel must keep every octet of its pattern;
 *   - and on a stack 1 KiB deeper than its depth, above the same guard and sentinel: it must return
 *     the octets it returns on the main stack.
 * The calls run on their stacks through makecontext/swapcontext (one thread: the stack is exactly
 * the one given, nothing carved from it as pthread_attr_setstack would carve the thread's own
 * descriptor). A control, an unprobed 20,000-octet frame in inline assembly, must be seen stepping
 * over the guard (the sentinel changed, no fault): the check can tell a clash from a fault.
 * The children that fault leave with _exit from the handler (their marks of the coverage build are
 * not needed: the same code runs in the parent's measured calls).
 * Usage: stack
 * Exit status: 0 when every check holds; 1 when one fails (printed); 2 on a setup error.
 * Build: tests/native/build.sh.
 */
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#include "httpasm.h"

#define PAGE 4096
#define SENTINEL (64 * 1024)                /* below the guard: where a frame that stepped over it lands */
#define DEEP (128 * 1024)                   /* the painted stack that measures a call's depth */
#define PAINT 0xA5
#define SENTINEL_FILL 0x5A
#define FAULTED 77                          /* a child's exit status when its handler caught SIGSEGV */

typedef void (*keypair_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*encaps_fn)(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *);
typedef int (*decaps_fn)(uint8_t *, const uint8_t *, const uint8_t *);

/* One ML-KEM parameter set: its sizes and functions. */
typedef struct {
    const char *name;
    size_t ek, dk, ct;
    keypair_fn keypair;
    encaps_fn encaps;
    decaps_fn decaps;
} mlkem_set;

static const mlkem_set sets[3] = {
    { "mlkem512", 800, 1632, 768, httpasm_mlkem512_keypair, httpasm_mlkem512_encaps, httpasm_mlkem512_decaps },
    { "mlkem768", 1184, 2400, 1088, httpasm_mlkem768_keypair, httpasm_mlkem768_encaps, httpasm_mlkem768_decaps },
    { "mlkem1024", 1568, 3168, 1568, httpasm_mlkem1024_keypair, httpasm_mlkem1024_encaps, httpasm_mlkem1024_decaps },
};
static const char *const op_names[4] = { "keypair", "encaps", "decaps", "control" };

/* The call under test (a set and an operation, or the control) and its inputs and outputs: the
 * context's entry takes no arguments, so they travel in these. */
static const mlkem_set *cur_set;
static int cur_op;
static uint8_t seed[64], msg[32], ek[1568], dk[3168], ct[1568];
static uint8_t out_ek[1568], out_dk[3168], out_ct[1568], out_key[32];

static ucontext_t main_ctx, call_ctx;

/* control_frame: 20,000 octets taken from the stack at once and only its lowest octet written:
 * what a frame without probes does. It must step over a 4 KiB guard into the sentinel. */
static void control_frame(void)
{
    __asm__ volatile(
        "sub $20000, %%rsp\n\t"
        "movb $1, (%%rsp)\n\t"
        "add $20000, %%rsp\n\t"
        ::: "memory");
}

/* trampoline: the context's entry: the call under test, then back to main_ctx (uc_link). */
static void trampoline(void)
{
    switch (cur_op) {
    case 0:
        cur_set->keypair(out_ek, out_dk, seed);
        break;
    case 1:
        (void)cur_set->encaps(out_ct, out_key, ek, msg);
        break;
    case 2:
        (void)cur_set->decaps(out_key, dk, ct);
        break;
    default:
        control_frame();
        break;
    }
}

/* run_on: the call under test on the stack [base, base + size). Returns 0, or -1 when the context
 * could not be made (printed). */
static int run_on(uint8_t *base, size_t size)
{
    if (getcontext(&call_ctx) != 0) {
        perror("stack: getcontext");
        return -1;
    }
    call_ctx.uc_stack.ss_sp = base;
    call_ctx.uc_stack.ss_size = size;
    call_ctx.uc_link = &main_ctx;
    makecontext(&call_ctx, trampoline, 0);
    if (swapcontext(&main_ctx, &call_ctx) != 0) {
        perror("stack: swapcontext");
        return -1;
    }
    return 0;
}

/* The fault address a child's handler saw, in a shared page the parent reads after the child dies. */
static volatile uintptr_t *fault_seen;

/* on_segv: records where the fault was and leaves at once (the stack it ran on is the alternate one:
 * the call's own is spent). */
static void on_segv(int sig, siginfo_t *info, void *context)
{
    (void)sig;
    (void)context;
    *fault_seen = (uintptr_t)info->si_addr;
    _exit(FAULTED);
}

/* outputs_equal: the call's outputs against the reference ones (copies made on the main stack). */
static int outputs_equal(const uint8_t *ref_ek, const uint8_t *ref_dk, const uint8_t *ref_ct, const uint8_t *ref_key)
{
    switch (cur_op) {
    case 0:
        return memcmp(out_ek, ref_ek, cur_set->ek) == 0 && memcmp(out_dk, ref_dk, cur_set->dk) == 0;
    case 1:
        return memcmp(out_ct, ref_ct, cur_set->ct) == 0 && memcmp(out_key, ref_key, 32) == 0;
    default:
        return memcmp(out_key, ref_key, 32) == 0;
    }
}

/* depth_of: the stack depth of the call under test: run on a painted DEEP-octet stack, the distance
 * from its top to the lowest octet that changed. Returns 0 on a setup error (printed). */
static size_t depth_of(void)
{
    uint8_t *stack = mmap(NULL, DEEP, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        perror("stack: mmap");
        return 0;
    }
    memset(stack, PAINT, DEEP);
    size_t depth = 0;
    if (run_on(stack, DEEP) == 0) {
        size_t low = 0;
        while (low < DEEP && stack[low] == PAINT)
            low++;
        depth = DEEP - low;
    }
    munmap(stack, DEEP);
    return depth;
}

/* The shared region of a sized run: [sentinel][guard][stack of up to `room` octets]. */
typedef struct {
    uint8_t *base;
    size_t length;
    uint8_t *guard;
    uint8_t *stack;
} region;

/* region_make: the sentinel (filled with SENTINEL_FILL), the PROT_NONE guard above it and `room`
 * octets of stack above that, all MAP_SHARED so the parent sees what a child did. Returns 0, or -1
 * on a setup error (printed). */
static int region_make(region *r, size_t room)
{
    r->length = SENTINEL + PAGE + ((room + PAGE - 1) & ~(size_t)(PAGE - 1));
    r->base = mmap(NULL, r->length, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (r->base == MAP_FAILED) {
        perror("stack: mmap");
        return -1;
    }
    memset(r->base, SENTINEL_FILL, SENTINEL);
    r->guard = r->base + SENTINEL;
    r->stack = r->guard + PAGE;
    if (mprotect(r->guard, PAGE, PROT_NONE) != 0) {
        perror("stack: mprotect");
        return -1;
    }
    return 0;
}

/* sentinel_intact: 1 when every octet of the sentinel still holds SENTINEL_FILL. */
static int sentinel_intact(const region *r)
{
    for (size_t k = 0; k < SENTINEL; k++)
        if (r->base[k] != SENTINEL_FILL)
            return 0;
    return 1;
}

/* run_sized: the call under test in a forked child on a stack of `size` octets right above the
 * guard. Returns the child's exit status (FAULTED when it caught SIGSEGV, 0 when the call
 * returned; its outputs then in *outputs_ok) and the fault address in *fault, or -1 on a setup
 * error (printed). */
static int run_sized(region *r, size_t size, uintptr_t *fault, int *outputs_ok, const uint8_t *ref_ek,
                     const uint8_t *ref_dk, const uint8_t *ref_ct, const uint8_t *ref_key)
{
    volatile uintptr_t *shared = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) {
        perror("stack: mmap");
        return -1;
    }
    shared[0] = 0;
    shared[1] = 0;
    memset(r->base, SENTINEL_FILL, SENTINEL);
    fflush(stdout);                         /* (or a child's exit would print the parent's lines again) */
    fflush(stderr);
    pid_t child = fork();
    if (child < 0) {
        perror("stack: fork");
        return -1;
    }
    if (child == 0) {
        static uint8_t alternate[64 * 1024];
        stack_t alt = { .ss_sp = alternate, .ss_size = sizeof alternate, .ss_flags = 0 };
        struct sigaction action;
        memset(&action, 0, sizeof action);
        action.sa_sigaction = on_segv;
        action.sa_flags = SA_SIGINFO | SA_ONSTACK;
        sigemptyset(&action.sa_mask);
        fault_seen = &shared[0];
        if (sigaltstack(&alt, NULL) != 0 || sigaction(SIGSEGV, &action, NULL) != 0)
            _exit(2);
        if (run_on(r->stack, size) != 0)
            _exit(2);
        if (cur_op < 3)                     /* (the control has no outputs) */
            shared[1] = (uintptr_t)outputs_equal(ref_ek, ref_dk, ref_ct, ref_key);
        exit(0);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        perror("stack: waitpid");
        return -1;
    }
    *fault = shared[0];
    *outputs_ok = (int)shared[1];
    munmap((void *)shared, PAGE);
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    fprintf(stderr, "stack: the child died by signal %d\n", WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    return 1000;
}

/* check_call: the call under test (cur_set, cur_op) measured, then on stacks too small (each must
 * fault in its guard, the sentinel untouched) and on one 1 KiB deeper than its depth (it must give
 * the reference outputs). Returns 0, 1 on a failure, 2 on a setup error (printed). */
static int check_call(const char *tier, const uint8_t *ref_ek, const uint8_t *ref_dk, const uint8_t *ref_ct,
                      const uint8_t *ref_key, int *checks)
{
    size_t depth = depth_of();
    if (depth == 0)
        return 2;
    region r;
    if (region_make(&r, depth + 1024) != 0)
        return 2;
    int failed = 0;
    for (size_t short_by = 64; depth > short_by + 1024 && !failed; short_by += 1000) {
        size_t size = (depth - short_by) & ~(size_t)15;
        uintptr_t fault = 0;
        int outputs_ok = 0;
        int status = run_sized(&r, size, &fault, &outputs_ok, ref_ek, ref_dk, ref_ct, ref_key);
        if (status < 0) {
            failed = 2;
            break;
        }
        int in_guard = fault >= (uintptr_t)r.guard && fault < (uintptr_t)r.guard + PAGE;
        if (status != FAULTED || !in_guard || !sentinel_intact(&r)) {
            fprintf(stderr, "stack: %s %s at %s (depth %zu) on %zu octets: status %d, fault %s the guard, "
                    "sentinel %s\n", cur_set->name, op_names[cur_op], tier, depth, size, status,
                    in_guard ? "in" : "outside", sentinel_intact(&r) ? "intact" : "CHANGED (a stack clash)");
            failed = 1;
        }
        (*checks)++;
    }
    if (!failed) {
        uintptr_t fault = 0;
        int outputs_ok = 0;
        int status = run_sized(&r, (depth + 1024) & ~(size_t)15, &fault, &outputs_ok, ref_ek, ref_dk, ref_ct, ref_key);
        if (status < 0)
            failed = 2;
        else if (status != 0 || !outputs_ok || !sentinel_intact(&r)) {
            fprintf(stderr, "stack: %s %s at %s on its depth + 1 KiB: status %d, outputs %s\n", cur_set->name,
                    op_names[cur_op], tier, status, outputs_ok ? "equal" : "DIFFERENT");
            failed = 1;
        }
        (*checks)++;
    }
    printf("stack: %-9s %-7s at %-4s: %6zu octets deep, %s\n", cur_set->name, op_names[cur_op], tier, depth,
           failed ? "FAILED" : "every smaller stack faults in its guard, the sentinel intact; fits 1 KiB deeper");
    munmap(r.base, r.length);
    return failed;
}

int main(void)
{
    static const struct {
        const char *name;
        uint64_t cap;
    } tiers[2] = { { "v1", HTTPASM_CPU_CAP_V1 }, { "best", HTTPASM_CPU_ALL } };
    int checks = 0;

    /* The control: an unprobed frame must be seen stepping over the guard. */
    {
        static const mlkem_set none = { "control", 0, 0, 0, NULL, NULL, NULL };
        cur_set = &none;
        cur_op = 3;
        region r;
        if (region_make(&r, 4096) != 0)
            return 2;
        uintptr_t fault = 0;
        int outputs_ok = 0;
        int status = run_sized(&r, 2048, &fault, &outputs_ok, NULL, NULL, NULL, NULL);
        if (status < 0)
            return 2;
        if (status != 0 || sentinel_intact(&r)) {
            fprintf(stderr, "stack: the control did not step over the guard (status %d, fault at guard %+td): the "
                    "check cannot see a clash\n", status, (ptrdiff_t)(fault - (uintptr_t)r.guard));
            return 1;
        }
        printf("stack: the control (an unprobed 20,000-octet frame on 2 KiB) stepped over the guard into the "
               "sentinel, unfaulted: a clash is visible\n");
        munmap(r.base, r.length);
    }

    for (size_t k = 0; k < sizeof seed; k++)
        seed[k] = (uint8_t)(0x3C ^ (29 * k));
    for (size_t k = 0; k < sizeof msg; k++)
        msg[k] = (uint8_t)(0xC3 ^ (31 * k));
    for (int t = 0; t < 2; t++) {
        httpasm_cpu_limit(tiers[t].cap);
        for (int s = 0; s < 3; s++) {
            cur_set = &sets[s];
            /* The reference outputs, computed on the main stack. */
            static uint8_t ref_ek[1568], ref_dk[3168], ref_ct[1568], ref_key[32], ref_dec[32];
            cur_set->keypair(ref_ek, ref_dk, seed);
            memcpy(ek, ref_ek, cur_set->ek);
            memcpy(dk, ref_dk, cur_set->dk);
            if (cur_set->encaps(ref_ct, ref_key, ek, msg) != 0) {
                fprintf(stderr, "stack: %s refused its own key\n", cur_set->name);
                return 1;
            }
            memcpy(ct, ref_ct, cur_set->ct);
            if (cur_set->decaps(ref_dec, dk, ct) != 0 || memcmp(ref_dec, ref_key, 32) != 0) {
                fprintf(stderr, "stack: %s did not decapsulate its own ciphertext\n", cur_set->name);
                return 1;
            }
            for (cur_op = 0; cur_op < 3; cur_op++) {
                int failed = check_call(tiers[t].name, ref_ek, ref_dk, ref_ct, cur_op == 2 ? ref_dec : ref_key, &checks);
                if (failed)
                    return failed;
            }
        }
    }
    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    printf("stack: %d sized runs, every one as required\n", checks);
    return 0;
}
