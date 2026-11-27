/*
 * stack.c - proves that HttpAsm's functions whose frames pass a page touch their stack at most
 * 4032 octets apart on the way down (crypto/mlkem.asm's MK_ENTER, httpasm_core.inc's
 * HA_STACK_DOWN in crypto/p384.asm and crypto/rsa.asm), so that a thread whose stack is nearly
 * spent faults on its guard page instead of the frame stepping over the guard into whatever is
 * mapped below it (a stack clash: the class of CVE-2017-1000364). Every function with a frame
 * near or above a page - ML-KEM's (up to about 27 KiB at v3), RSA's (signing: about 45 KiB, and
 * its verification), FFDHE's (signing's frame, at ffdhe2048 and ffdhe8192), P-384's and P-256's,
 * Ed25519's, X25519's and X448's (its ladder's frame, then its inverse's below it) - at v1 and at
 * the best tier:
 *   - its depth is measured: run on a painted 128 KiB stack, the lowest octet it changed;
 *   - it runs again, in a forked child, on stacks too small for that depth (from 64 octets short
 *     down to 1 KiB, every 1000 octets: the guard page sits at every kind of place in the frame),
 *     with a PROT_NONE guard page below each and a 64 KiB shared sentinel below the guard, filled
 *     with a pattern: the child must die by SIGSEGV with its fault address in the guard page, and
 *     the sentinel must keep every octet of its pattern;
 *   - and on a stack 1 KiB deeper than its depth, above the same guard and sentinel: it must return
 *     what it returns on the main stack (its outputs and its result).
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

/* ---- the calls under test ----
 * Each runs one function on inputs prepared once (main) and leaves its outputs in `out` (out_n
 * octets) and its result in `result`: the fitting run must leave the same as the main stack's. */
static uint8_t out[8192];
static size_t out_n;
static long result;

/* One call: its name and the function that makes it. */
typedef struct {
    const char *name;
    void (*run)(void);
} stack_call;

/* The inputs. */
static uint8_t seed[64], msg[32], digest32[32], digest48[48], ed_message[130];
static uint8_t mk_ek[3][1568], mk_dk[3][3168], mk_ct[3][1568];
static uint8_t p256_key[32], p256_peer[65], p256_public[65], p256_signature[64];
static uint8_t p384_key[48], p384_peer[97], p384_public[97], p384_signature[96];
static uint8_t ed_seed[32], ed_public[32], ed_signature[64], x_scalar[32], x_point[32];
static httpasm_ed25519_private_key ed_key;
static uint8_t rsa_octets[7][256];
static size_t rsa_lengths[7];
static httpasm_rsa_public_key rsa_public;
static httpasm_rsa_private_key rsa_private;
static uint8_t rsa_pkcs1[256], rsa_pss[256], rsa_salt[32];

/* A 2048-bit RSA key (made once with OpenSSL; tests/native/tiers.c signs with the same): n, e, p,
 * q, dp, dq, q^-1. Its primes take the v3 exponentiation's own 16-limb square and product. */
static const char *const rsa_hex[7] = {
    "e421764c563244426247031d997d47d08c5003303181239b41bdac0d338f0c4344084ca53d8038b43ea65b01b7db1c48"
    "b9461a5dcf2f4836bf060d007378322e8aa96a3ac6f61283630276041fe946d796b0a6bf8ab895e8b5ff28d1934bc99c"
    "278e30e895da211ae2b3b15db045df3f9cd71595ae15471a3d47b18fa0828d00d7048487ed756ca97600450e8695aa83"
    "0e59f9acaa65e0f016d4be59b90a473f5dcf00e0ffe8a4b42681aa56f72cda8d16ff5d42c6b46c748fa3830fe372d9bc"
    "6cb2af81ce698298d5d7c38958c43863b29dbcb7c0f1529ad9a49f6b5362437d16a52a5c8c12af81624a1d941db818cf"
    "cf5e8d8bda19556398ae08e502f82763",
    "010001",
    "feb0f65ae82f63e64d084f356bd5223b8250065bbeace771710a93b3e60e438491a72d884d8e4a391f7e1bcc7b6d40ff"
    "96b2c61a8fc9a8532f150b3a21d8e21a6047655fb8749fd6cc42ef76d408cd5612ee569084b26546a01709bf4cb1b065"
    "0278dc823802270db5796931440d8876249675808b6fa6bdebe5935e5cdecf79",
    "e54d8f6ea255db59d5a3f12c36df5be764b15878b7b0493dd7c3e8ec10c5594917490411d3aaf331093202992dd3ac06"
    "3904de6e14eaa020612fe2671cf4b9da7fd5c78417bf1a2a0e3a7f0852ca0de0455320d305b33385e348b9ce7e132ad0"
    "343b96577c6a683865bb8447dd247b7d671d6cc28ad358e73cba3c0ff8a2eabb",
    "aef726e6a0a71dbbf2a388b6ac5388e6d4c8e0f559f232350e7133b2dc9263f3c893ce85dab1ab6fbea0c5bc1df69a36"
    "7b7269018a52009ed4b3623917538550955fb6d6a1430d2364c37efa65037efc6898ef42ecc619290185921ea7335278"
    "b1d011bc2b79df165ddb0056e5e75e1dbb58d973eb5652781a7c6656e6f9f211",
    "28826d4684535aaf2239165053595e6920b6dc04679f333143bf0e9535d9478ecc185029be15436574546b75184d7ee4"
    "928a33a98af470598811e79383e0103d73bc16c55554a390ae76d31e6b51dae5b6199b80ec4ede5956eff03374be7a1f"
    "d23a7cb2f3fdf06f96396c832da45654af34d993fce69d9c2c74524c1806e025",
    "8d0b3783e80edb1e0516632d8944f1f0dff3434c190790ff41d3880eb48dd0eb88266f38c1b52c44925e78f7972da9ae"
    "780c5ffd85987253d62c094dfdd76397435a8d37a0efb8fb89f7d884a0db3705b9c6c22a950bc5dec7ed5ce3fdb394f5"
    "d0df1034b35da43c04b5f9ea809609020a1b48862715914a7dac2b6ee69a368d"
};

/* hex_octets: lowercase hex to octets; returns how many, 0 on a bad digit. */
static size_t hex_octets(const char *hex, uint8_t *octets)
{
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[2 * i + (size_t)j];
            if (c >= '0' && c <= '9')
                v = v * 16 + (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f')
                v = v * 16 + (unsigned)(c - 'a' + 10);
            else
                return 0;
        }
        octets[i] = (uint8_t)v;
    }
    return n;
}

/* The ML-KEM sets, as tables the run functions index. */
typedef void (*keypair_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*encaps_fn)(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *);
typedef int (*decaps_fn)(uint8_t *, const uint8_t *, const uint8_t *);
static const struct {
    size_t ek, dk, ct;
    keypair_fn keypair;
    encaps_fn encaps;
    decaps_fn decaps;
} mk_sets[3] = {
    { 800, 1632, 768, httpasm_mlkem512_keypair, httpasm_mlkem512_encaps, httpasm_mlkem512_decaps },
    { 1184, 2400, 1088, httpasm_mlkem768_keypair, httpasm_mlkem768_encaps, httpasm_mlkem768_decaps },
    { 1568, 3168, 1568, httpasm_mlkem1024_keypair, httpasm_mlkem1024_encaps, httpasm_mlkem1024_decaps },
};

/* mk_keypair, mk_encaps, mk_decaps: set s's function on the prepared inputs. */
static void mk_keypair(int s)
{
    mk_sets[s].keypair(out, out + mk_sets[s].ek, seed);
    out_n = mk_sets[s].ek + mk_sets[s].dk;
    result = 0;
}
static void mk_encaps(int s)
{
    result = mk_sets[s].encaps(out, out + mk_sets[s].ct, mk_ek[s], msg);
    out_n = mk_sets[s].ct + 32;
}
static void mk_decaps(int s)
{
    result = mk_sets[s].decaps(out, mk_dk[s], mk_ct[s]);
    out_n = 32;
}
static void run_mk512_keypair(void) { mk_keypair(0); }
static void run_mk512_encaps(void) { mk_encaps(0); }
static void run_mk512_decaps(void) { mk_decaps(0); }
static void run_mk768_keypair(void) { mk_keypair(1); }
static void run_mk768_encaps(void) { mk_encaps(1); }
static void run_mk768_decaps(void) { mk_decaps(1); }
static void run_mk1024_keypair(void) { mk_keypair(2); }
static void run_mk1024_encaps(void) { mk_encaps(2); }
static void run_mk1024_decaps(void) { mk_decaps(2); }

/* The curves and RSA. */
static void run_p256_public_key(void) { result = httpasm_p256_public_key(out, p256_key); out_n = 65; }
static void run_p256_ecdh(void) { result = httpasm_p256_ecdh(out, p256_key, p256_peer); out_n = 32; }
static void run_p256_sign(void) { result = httpasm_p256_sign(out, p256_key, digest32, 32, NULL); out_n = 64; }
static void run_p256_verify(void) { result = httpasm_p256_verify(p256_public, digest32, 32, p256_signature); out_n = 0; }
static void run_p384_public_key(void) { result = httpasm_p384_public_key(out, p384_key); out_n = 97; }
static void run_p384_ecdh(void) { result = httpasm_p384_ecdh(out, p384_key, p384_peer); out_n = 48; }
static void run_p384_sign(void) { result = httpasm_p384_sign(out, p384_key, digest48, 48, NULL); out_n = 96; }
static void run_p384_verify(void) { result = httpasm_p384_verify(p384_public, digest48, 48, p384_signature); out_n = 0; }
static void run_ed_public_key(void) { httpasm_ed25519_public_key(out, ed_seed); out_n = 32; result = 0; }
static void run_ed_key_init(void)
{
    httpasm_ed25519_private_key key;
    httpasm_ed25519_private_key_init(&key, ed_seed);
    memcpy(out, &key, sizeof key);
    out_n = sizeof key;
    result = 0;
}
static void run_ed_sign(void) { httpasm_ed25519_sign(out, &ed_key, ed_message, sizeof ed_message); out_n = 64; result = 0; }
static void run_ed_verify(void) { result = httpasm_ed25519_verify(ed_public, ed_message, sizeof ed_message, ed_signature); out_n = 0; }
static void run_x25519_public_key(void) { httpasm_x25519_public_key(out, x_scalar); out_n = 32; result = 0; }
static void run_x25519(void) { result = httpasm_x25519(out, x_scalar, x_point); out_n = 32; }
static uint8_t x448_scalar[56], x448_point[56];
static void run_x448_public_key(void) { result = httpasm_x448_public_key(out, x448_scalar); out_n = 56; }
static void run_x448(void) { result = httpasm_x448(out, x448_scalar, x448_point); out_n = 56; }
static void run_rsa_public_key_init(void)
{
    httpasm_rsa_public_key key;
    result = httpasm_rsa_public_key_init(&key, rsa_octets[0], rsa_lengths[0], rsa_octets[1], rsa_lengths[1]);
    memcpy(out, &key, sizeof key);
    out_n = sizeof key;
}
static void run_rsa_verify_pkcs1(void)
{
    result = httpasm_rsa_verify_pkcs1(&rsa_public, HTTPASM_HASH_SHA256, digest32, rsa_pkcs1, 256);
    out_n = 0;
}
static void run_rsa_verify_pss(void)
{
    result = httpasm_rsa_verify_pss(&rsa_public, HTTPASM_HASH_SHA256, digest32, sizeof rsa_salt, rsa_pss, 256);
    out_n = 0;
}
static void run_rsa_private_key_init(void)
{
    httpasm_rsa_private_numbers numbers = {
        rsa_octets[0], rsa_lengths[0], rsa_octets[1], rsa_lengths[1], rsa_octets[2], rsa_lengths[2],
        rsa_octets[3], rsa_lengths[3], rsa_octets[4], rsa_lengths[4], rsa_octets[5], rsa_lengths[5],
        rsa_octets[6], rsa_lengths[6],
    };
    static httpasm_rsa_private_key key;
    result = httpasm_rsa_private_key_init(&key, &numbers);
    memcpy(out, &key, sizeof key);
    out_n = sizeof key;
}
static void run_rsa_sign_pkcs1(void)
{
    result = httpasm_rsa_sign_pkcs1(&rsa_private, HTTPASM_HASH_SHA256, digest32, out, 256);
    out_n = 256;
}
static void run_rsa_sign_pss(void)
{
    result = httpasm_rsa_sign_pss(&rsa_private, HTTPASM_HASH_SHA256, digest32, rsa_salt, sizeof rsa_salt, out, 256);
    out_n = 256;
}

/* FFDHE (in RSA signing's frame): a 64-octet exponent at the smallest and the largest group. */
static uint8_t ff_x[64], ff_peer2048[256], ff_peer8192[1024];
static void run_ffdhe2048_public_key(void) { result = httpasm_ffdhe_public_key(HTTPASM_FFDHE2048, out, ff_x, sizeof ff_x); out_n = 256; }
static void run_ffdhe2048_shared(void) { result = httpasm_ffdhe_shared(HTTPASM_FFDHE2048, out, ff_x, sizeof ff_x, ff_peer2048); out_n = 256; }
static void run_ffdhe8192_public_key(void) { result = httpasm_ffdhe_public_key(HTTPASM_FFDHE8192, out, ff_x, sizeof ff_x); out_n = 1024; }
static void run_ffdhe8192_shared(void) { result = httpasm_ffdhe_shared(HTTPASM_FFDHE8192, out, ff_x, sizeof ff_x, ff_peer8192); out_n = 1024; }

static const stack_call calls[] = {
    { "mlkem512 keypair", run_mk512_keypair }, { "mlkem512 encaps", run_mk512_encaps },
    { "mlkem512 decaps", run_mk512_decaps }, { "mlkem768 keypair", run_mk768_keypair },
    { "mlkem768 encaps", run_mk768_encaps }, { "mlkem768 decaps", run_mk768_decaps },
    { "mlkem1024 keypair", run_mk1024_keypair }, { "mlkem1024 encaps", run_mk1024_encaps },
    { "mlkem1024 decaps", run_mk1024_decaps },
    { "p256 public_key", run_p256_public_key }, { "p256 ecdh", run_p256_ecdh },
    { "p256 sign", run_p256_sign }, { "p256 verify", run_p256_verify },
    { "p384 public_key", run_p384_public_key }, { "p384 ecdh", run_p384_ecdh },
    { "p384 sign", run_p384_sign }, { "p384 verify", run_p384_verify },
    { "ed25519 public_key", run_ed_public_key }, { "ed25519 private_key_init", run_ed_key_init },
    { "ed25519 sign", run_ed_sign }, { "ed25519 verify", run_ed_verify },
    { "x25519 public_key", run_x25519_public_key }, { "x25519", run_x25519 },
    { "x448 public_key", run_x448_public_key }, { "x448", run_x448 },
    { "rsa public_key_init", run_rsa_public_key_init }, { "rsa verify_pkcs1", run_rsa_verify_pkcs1 },
    { "rsa verify_pss", run_rsa_verify_pss }, { "rsa private_key_init", run_rsa_private_key_init },
    { "rsa sign_pkcs1", run_rsa_sign_pkcs1 }, { "rsa sign_pss", run_rsa_sign_pss },
    { "ffdhe2048 public_key", run_ffdhe2048_public_key }, { "ffdhe2048 shared", run_ffdhe2048_shared },
    { "ffdhe8192 public_key", run_ffdhe8192_public_key }, { "ffdhe8192 shared", run_ffdhe8192_shared },
};

/* ---- running a call on a stack of our own ---- */
static void (*current)(void);               /* the call under test, or the control */
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
    current();
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

/* The reference: what the call left on the main stack. */
static uint8_t ref_out[8192];
static size_t ref_n;
static long ref_result;

/* outputs_equal: 1 when the call left what it left on the main stack. */
static int outputs_equal(void)
{
    return out_n == ref_n && result == ref_result && memcmp(out, ref_out, out_n) == 0;
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
 * returned; then *outputs_ok says whether it left the reference's outputs) and the fault address
 * in *fault, or -1 on a setup error (printed). check_outputs is 0 for the control. */
static int run_sized(region *r, size_t size, uintptr_t *fault, int *outputs_ok, int check_outputs)
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
        if (check_outputs)
            shared[1] = (uintptr_t)outputs_equal();
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

/* check_call: the call under test measured, then on stacks too small (each must fault in its
 * guard, the sentinel untouched) and on one 1 KiB deeper than its depth (it must leave the
 * reference's outputs). Returns 0, 1 on a failure, 2 on a setup error (printed). */
static int check_call(const char *name, const char *tier, int *checks)
{
    current();                              /* the reference, on the main stack */
    memcpy(ref_out, out, out_n);
    ref_n = out_n;
    ref_result = result;
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
        int status = run_sized(&r, size, &fault, &outputs_ok, 1);
        if (status < 0) {
            failed = 2;
            break;
        }
        int in_guard = fault >= (uintptr_t)r.guard && fault < (uintptr_t)r.guard + PAGE;
        if (status != FAULTED || !in_guard || !sentinel_intact(&r)) {
            fprintf(stderr, "stack: %s at %s (depth %zu) on %zu octets: status %d, fault %s the guard, "
                    "sentinel %s\n", name, tier, depth, size, status, in_guard ? "in" : "outside",
                    sentinel_intact(&r) ? "intact" : "CHANGED (a stack clash)");
            failed = 1;
        }
        (*checks)++;
    }
    if (!failed) {
        uintptr_t fault = 0;
        int outputs_ok = 0;
        int status = run_sized(&r, (depth + 1024) & ~(size_t)15, &fault, &outputs_ok, 1);
        if (status < 0)
            failed = 2;
        else if (status != 0 || !outputs_ok || !sentinel_intact(&r)) {
            fprintf(stderr, "stack: %s at %s on its depth + 1 KiB: status %d, outputs %s\n", name, tier, status,
                    outputs_ok ? "equal" : "DIFFERENT");
            failed = 1;
        }
        (*checks)++;
    }
    printf("stack: %-24s at %-4s: %6zu octets deep, %s\n", name, tier, depth,
           failed ? "FAILED" : "every smaller stack faults in its guard, the sentinel intact; fits 1 KiB deeper");
    munmap(r.base, r.length);
    return failed;
}

/* prepare: every call's inputs, made once on the main stack at the current tier: ML-KEM keys and
 * ciphertexts, curve keys, peers' keys and signatures, the RSA key and its signatures. Returns 0,
 * or 1 when the library refuses its own (printed), 2 when the RSA key does not decode. */
static int prepare(void)
{
    for (size_t k = 0; k < sizeof seed; k++)
        seed[k] = (uint8_t)(0x3C ^ (29 * k));
    for (size_t k = 0; k < sizeof msg; k++)
        msg[k] = (uint8_t)(0xC3 ^ (31 * k));
    for (size_t k = 0; k < 48; k++)
        digest48[k] = (uint8_t)(0x96 ^ (37 * k));
    memcpy(digest32, digest48, 32);
    for (size_t k = 0; k < sizeof ed_message; k++)
        ed_message[k] = (uint8_t)(0x20 + (k % 64));
    for (int s = 0; s < 3; s++) {
        uint8_t key[32];
        mk_sets[s].keypair(mk_ek[s], mk_dk[s], seed);
        if (mk_sets[s].encaps(mk_ct[s], key, mk_ek[s], msg) != 0) {
            fprintf(stderr, "stack: ML-KEM refused its own key\n");
            return 1;
        }
    }
    for (size_t k = 0; k < 32; k++) {
        p256_key[k] = (uint8_t)(0x11 + k);
        ed_seed[k] = (uint8_t)(0x5D ^ (7 * k));
        x_scalar[k] = (uint8_t)(0xA9 ^ (13 * k));
    }
    for (size_t k = 0; k < 48; k++)
        p384_key[k] = (uint8_t)(0x22 + k);
    uint8_t other[48];
    for (size_t k = 0; k < 48; k++)
        other[k] = (uint8_t)(0x33 + k);
    if (httpasm_p256_public_key(p256_public, p256_key) != 0 || httpasm_p256_public_key(p256_peer, other) != 0
        || httpasm_p256_sign(p256_signature, p256_key, digest32, 32, NULL) != 0
        || httpasm_p384_public_key(p384_public, p384_key) != 0 || httpasm_p384_public_key(p384_peer, other) != 0
        || httpasm_p384_sign(p384_signature, p384_key, digest48, 48, NULL) != 0) {
        fprintf(stderr, "stack: a curve refused its own key\n");
        return 1;
    }
    httpasm_ed25519_public_key(ed_public, ed_seed);
    httpasm_ed25519_private_key_init(&ed_key, ed_seed);
    httpasm_ed25519_sign(ed_signature, &ed_key, ed_message, sizeof ed_message);
    httpasm_x25519_public_key(x_point, seed);
    for (size_t k = 0; k < 56; k++)
        x448_scalar[k] = (uint8_t)(0x6D ^ (7 * k));
    uint8_t x448_other[56];
    for (size_t k = 0; k < 56; k++)
        x448_other[k] = (uint8_t)(0x91 + 3 * k);
    if (httpasm_x448_public_key(x448_point, x448_other) != 0) {
        fprintf(stderr, "stack: X448 refused its own key\n");
        return 1;
    }
    for (int i = 0; i < 7; i++) {
        rsa_lengths[i] = hex_octets(rsa_hex[i], rsa_octets[i]);
        if (rsa_lengths[i] == 0) {
            fprintf(stderr, "stack: the embedded RSA key does not decode\n");
            return 2;
        }
    }
    httpasm_rsa_private_numbers numbers = {
        rsa_octets[0], rsa_lengths[0], rsa_octets[1], rsa_lengths[1], rsa_octets[2], rsa_lengths[2],
        rsa_octets[3], rsa_lengths[3], rsa_octets[4], rsa_lengths[4], rsa_octets[5], rsa_lengths[5],
        rsa_octets[6], rsa_lengths[6],
    };
    for (size_t k = 0; k < sizeof rsa_salt; k++)
        rsa_salt[k] = (uint8_t)(0xE7 ^ (3 * k));
    if (httpasm_rsa_public_key_init(&rsa_public, rsa_octets[0], rsa_lengths[0], rsa_octets[1], rsa_lengths[1]) != 0
        || httpasm_rsa_private_key_init(&rsa_private, &numbers) != 0
        || httpasm_rsa_sign_pkcs1(&rsa_private, HTTPASM_HASH_SHA256, digest32, rsa_pkcs1, 256) != 0
        || httpasm_rsa_sign_pss(&rsa_private, HTTPASM_HASH_SHA256, digest32, rsa_salt, sizeof rsa_salt, rsa_pss, 256) != 0) {
        fprintf(stderr, "stack: RSA refused its own key\n");
        return 1;
    }
    uint8_t ff_other[64];
    for (size_t k = 0; k < sizeof ff_x; k++) {
        ff_x[k] = (uint8_t)(0x4B ^ (11 * k));
        ff_other[k] = (uint8_t)(0xB4 ^ (5 * k));
    }
    if (httpasm_ffdhe_public_key(HTTPASM_FFDHE2048, ff_peer2048, ff_other, sizeof ff_other) != 0
        || httpasm_ffdhe_public_key(HTTPASM_FFDHE8192, ff_peer8192, ff_other, sizeof ff_other) != 0) {
        fprintf(stderr, "stack: FFDHE refused its own exponent\n");
        return 1;
    }
    return 0;
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
        current = control_frame;
        region r;
        if (region_make(&r, 4096) != 0)
            return 2;
        uintptr_t fault = 0;
        int outputs_ok = 0;
        int status = run_sized(&r, 2048, &fault, &outputs_ok, 0);
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

    for (int t = 0; t < 2; t++) {
        httpasm_cpu_limit(tiers[t].cap);
        int prepared = prepare();
        if (prepared != 0)
            return prepared;
        for (size_t c = 0; c < sizeof calls / sizeof calls[0]; c++) {
            current = calls[c].run;
            int failed = check_call(calls[c].name, tiers[t].name, &checks);
            if (failed)
                return failed;
        }
    }
    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    printf("stack: %d sized runs, every one as required\n", checks);
    return 0;
}
