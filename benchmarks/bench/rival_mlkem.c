/* rival_mlkem.c - mlkem-native 2.1.0's ML-KEM (pq-code-package; Apache-2.0 OR ISC OR MIT) as the
 * benchmark's ML-KEM rival: its multilevel native example's single compilation unit (all three
 * parameter sets, the AVX2 arithmetic backend and its four-way AVX2 Keccak, chosen at compile time
 * by -march=native and MLK_FORCE_X86_64), included whole, behind plain functions bench.h declares.
 * bench.sh compiles this file (and the example's mlkem_native_asm.S) with -O3 -march=native into
 * the rivals' objects; it is never part of the library. The source comes from tests/tools.sh's
 * pinned archive.
 *
 * The example's configuration makes mlkem-native's API static, so these wrappers are the only way
 * in; they call the deterministic forms (_keypair_derand, _enc_derand, _dec), which take the same
 * inputs as HttpAsm's functions (the 64-octet seed d || z, the 32-octet m). */
#include <stddef.h>
#include <stdint.h>

#include "mlkem_native_all.c"

/* randombytes: the example's configuration routes mlkem-native's randomness here; the benchmark
 * calls only the deterministic API, so this is never reached. Defined so the link never depends on
 * the compiler dropping the unused randomized functions. Returns -1: no randomness to give. */
int randombytes(uint8_t *buf, size_t n)
{
    (void)buf;
    (void)n;
    return -1;
}

/* rival_mlkem768_keypair, rival_mlkem1024_keypair: ML-KEM.KeyGen_internal from seed = d || z
 * (ek into pk, dk into sk). Return mlkem-native's 0 on success. */
int rival_mlkem768_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int rival_mlkem768_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    return mlkem768_keypair_derand(pk, sk, seed);
}

int rival_mlkem1024_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int rival_mlkem1024_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    return mlkem1024_keypair_derand(pk, sk, seed);
}

/* rival_mlkem768_encaps, rival_mlkem1024_encaps: ML-KEM.Encaps_internal of pk with the 32-octet m
 * (its modulus check included). Return 0, or mlkem-native's error for a refused key. */
int rival_mlkem768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *m);
int rival_mlkem768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *m)
{
    return mlkem768_enc_derand(ct, ss, pk, m);
}

int rival_mlkem1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *m);
int rival_mlkem1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *m)
{
    return mlkem1024_enc_derand(ct, ss, pk, m);
}

/* rival_mlkem768_decaps, rival_mlkem1024_decaps: ML-KEM.Decaps_internal (its hash check included).
 * Return 0, or mlkem-native's error for a refused key. */
int rival_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int rival_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    return mlkem768_dec(ss, ct, sk);
}

int rival_mlkem1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int rival_mlkem1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    return mlkem1024_dec(ss, ct, sk);
}
