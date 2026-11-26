# Synthetic CPUs for the CPU detection

`tests/run-linux.sh` runs `tests/native/cpu` under Intel SDE with each of these files
(`sde64 -cpuid_in <file> -- cpu <level>`). SDE's own CPU models are real processors, and no real
processor takes some branches of `cpu/cpu.asm`'s detection. A hypervisor can still offer such a
CPU: its custom CPU model can mask any CPUID bit, for example AVX2 while FMA stays. Each file
describes one such CPU, and the level it must reach exactly:

| File | The CPU | Level |
|---|---|---|
| `v2-no-lahf.def` | every x86-64-v2 feature of leaf 1, but no LAHF-SAHF in 64-bit mode | v1 |
| `v3-no-avx2.def` | every x86-64-v3 feature but AVX2 | v2 |
| `v3-no-lzcnt.def` | every x86-64-v3 feature but LZCNT | v2 |
| `v4-no-bw-dq-vl.def` | AVX-512F and CD with their state saved, without BW, DQ and VL (Knights Landing's set) | v3 |
| `v4.def` | every x86-64-v4 feature: the control that SDE saves the ZMM state for these tables | v4 |

One branch stays out of reach: a CPU without leaf 0x80000001. That leaf's LM bit is what says
a CPU runs 64-bit code, and SDE refuses to run a 64-bit program under a table without it
("64 bits applications are not supported by ... the input cpuid definition file", tried
2026-11-26), so `tests/coverage/unreachable.tsv` lists that branch.

The files are written for HttpAsm (they hold no Intel material): only the leaves the detection
and glibc's start-up read, with the bits below. SDE's format: `leaf subleaf => EAX EBX ECX EDX`,
in hex, `********` for "any subleaf".

- Leaf 0: highest leaf 0xD, vendor "GenuineIntel".
- Leaf 1: EAX 0x000306c3 (family 6, model 0x3c, stepping 3); EBX 0x800 (CLFLUSH line of 64
  octets); ECX 0x3ed83203: SSE3 (0), PCLMULQDQ (1), SSSE3 (9), FMA (12), CX16 (13), SSE4.1 (19),
  SSE4.2 (20), MOVBE (22), POPCNT (23), AES (25), XSAVE (26), OSXSAVE (27), AVX (28), F16C (29);
  EDX 0x078bfbff: FPU to SSE2, as every x86-64 CPU has them.
- Leaf 7, subleaf 0: EBX 0x329: FSGSBASE (0), BMI1 (3), AVX2 (5), BMI2 (8), ERMS (9); for v4,
  also AVX-512F (16), DQ (17), CD (28), BW (30), VL (31).
- Leaf 0xD: the XSAVE state components, x87, SSE and AVX (0x7; 0xe7 with AVX-512's opmask and
  ZMM state), and their size.
- Leaf 0x80000000: highest extended leaf 0x80000008.
- Leaf 0x80000001: ECX 0x21: LAHF-SAHF (0), LZCNT (5); EDX 0x28100800: SYSCALL (11), NX (20),
  RDTSCP (27), LM (29).
