/*
 * replay.c - runs a fuzzer's harness on files instead of libFuzzer's mutations: every file named
 * on the command line, and every file in every directory named, once each, in sorted order.
 *
 * Linked with one tests/fuzz/<name>.c instead of libFuzzer (tests/fuzz/replay.sh builds it),
 * it turns the committed seeds and minimized corpora (tests/fuzz/seeds/, tests/fuzz/corpus/)
 * into deterministic tests: the same inputs, the same checks (FUZZ_CHECK aborts on a broken
 * invariant), on every run of tests/run-linux.sh against the Release build. Linked with the
 * Coverage build's objects instead, the same replay feeds tests/coverage/run.sh, so the blocks
 * the fuzzers reached count toward the coverage gate.
 *
 * Usage: replay FILE-OR-DIRECTORY...
 * Exit status: 0 when every input passed; a broken invariant aborts (SIGABRT) with its message,
 * followed by "replay: the failing input is <file>"; 2 for an unreadable argument.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE                 /* opendir, readdir: the build may define it already */
#endif
#include <dirent.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
/* The harnesses that need setup define it (h1_request_diff, server); the others do not, so the
 * reference is weak: NULL when absent. */
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

/* The input being run, for the fault handler: a failing input names itself without every
 * passing one filling the log. */
static const char *current;

/* on_fault: SIGABRT (a FUZZ_CHECK) or SIGSEGV/SIGBUS: names the input, then lets the signal
 * end the process as it would have (the handler is reset to the default first). */
static void on_fault(int sig)
{
    if (current != NULL) {
        static const char prefix[] = "replay: the failing input is ";
        (void)!write(2, prefix, sizeof prefix - 1);
        (void)!write(2, current, strlen(current));
        (void)!write(2, "\n", 1);
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

/* run_file: one input through the harness. Returns 0, or 2 when the file cannot be read. */
static int run_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "replay: cannot read %s\n", path);
        return 2;
    }
    static uint8_t data[1 << 20];
    size_t size = fread(data, 1, sizeof data, f);
    fclose(f);
    current = path;
    LLVMFuzzerTestOneInput(data, size);
    current = NULL;
    return 0;
}

/* compare_names: qsort's comparison for directory entry names, for a stable order. */
static int compare_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* run_path: a file, or every regular file of a directory (not recursive), sorted. Returns the
 * number of inputs run, or -1 when the path cannot be read. */
static long run_path(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    if (!S_ISDIR(st.st_mode))
        return run_file(path) == 0 ? 1 : -1;
    DIR *d = opendir(path);
    if (d == NULL)
        return -1;
    size_t count = 0, cap = 256;
    char **names = malloc(cap * sizeof *names);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        if (count == cap)
            names = realloc(names, (cap *= 2) * sizeof *names);
        size_t n = strlen(path) + strlen(e->d_name) + 2;
        names[count] = malloc(n);
        snprintf(names[count++], n, "%s/%s", path, e->d_name);
    }
    closedir(d);
    qsort(names, count, sizeof *names, compare_names);
    long run = 0;
    for (size_t i = 0; i < count; i++) {
        if (stat(names[i], &st) == 0 && S_ISREG(st.st_mode) && run_file(names[i]) == 0)
            run++;
        free(names[i]);
    }
    free(names);
    return run;
}

/* main: initializes the harness when it asks for it, then replays every argument. */
int main(int argc, char **argv)
{
    signal(SIGABRT, on_fault);
    signal(SIGSEGV, on_fault);
    signal(SIGBUS, on_fault);
    if (LLVMFuzzerInitialize != NULL)
        LLVMFuzzerInitialize(&argc, &argv);
    long total = 0;
    for (int i = 1; i < argc; i++) {
        long run = run_path(argv[i]);
        if (run < 0) {
            fprintf(stderr, "replay: cannot read %s\n", argv[i]);
            return 2;
        }
        total += run;
    }
    printf("replay: %ld inputs passed\n", total);
    return 0;
}
