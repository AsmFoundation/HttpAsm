# HttpAsm benchmarks

Two kinds of measurement, both local: benchmarks never run in CI (the owner's rule, 2026-11-26).
A change is measured on the developer's machine, against the commit before it, before it is
kept.

- **The framework, `bench.sh`:** single routines on one thread. It times every CPU tier of each
  multi-version routine, the parsers' whole routines, and the parsers beside picohttpparser,
  llhttp and nghttp2. This is where a change to the code is proven faster, or not.
- **Whole servers, `run.sh` and `ab.sh`:** HttpAsm against nginx and h2o, its HTTP/1.1-only
  build and its two backends; and what a change costs per request.

## The framework: `bench.sh`

### What it measures

A case is one routine on one input. Every contender of a case runs once per round, round after
round, in one process pinned to one CPU, in a new random order each round. Three suites:

- **`tiers`:** each multi-version routine at v1, v2, v3 and v4, on inputs around the vector
  widths. A routine joins when it gets a version above v1; today that is
  `httpasm_field_value_scan`, and the whole routines whose versions sit inside them: the
  request parser (the rivals suite's three heads), the response parser and the HPACK decoder.
- **`parsers`:** the library's whole routines on realistic inputs, at the best tier the CPU has
  and at v1. The routines: response heads, chunked bodies (small and large chunks), field-name
  lookup, token validation, response writing, HPACK encoding, and HTTP/2's request rules. These
  are the hot paths of phase H step 4.
- **`rivals`:** the HTTP/1.1 request parser beside picohttpparser (h2o) and llhttp (Node.js) on
  three request heads, the response parser beside picohttpparser's and llhttp's on a typical
  response head, and the HPACK decoder beside nghttp2. The rivals are the sources
  `tests/tools.sh` pins, compiled with `-O3 -march=native`, their best (picohttpparser's and
  llhttp's SSE4.2 paths need it). Mind what each one does: picohttpparser splits a head into
  lines and checks almost nothing else; llhttp checks the grammar; HttpAsm also applies RFC
  9112's semantics (target and Host grammar, field names and values, every framing rule,
  known-field ids).

A contender is a build of the library at a tier, or a rival. The first contender runs a second
time as the A/A control: whatever separates the two is the run's noise. The library is loaded,
not linked (`dlopen`), so another build can run beside it: see `ab` below.

### How to run

```bash
dotnet build HttpAsm.slnx -c Release                # libhttpasm.so, which the runner loads
benchmarks/bench.sh                                 # every suite: 41 rounds of ~0.5 ms samples
benchmarks/bench.sh --quick --filter 'tiers/*'     # the development loop: 11 shorter rounds
benchmarks/bench.sh --list                          # the cases, as "suite/name/input"
benchmarks/bench.sh ab HEAD~1 --suite parsers       # a change against the commit before it
benchmarks/bench.sh icount --filter 'parsers/*'    # exact instructions per call (Intel SDE)
benchmarks/bench.sh mca field_value_scan            # llvm-mca on each version's loops
```

The options: `--suite`, `--filter` (a glob over "suite/name/input"), `--rounds`, `--sample-us`,
`--quick`, `--json PATH` (the whole record: every raw sample, the host, the builds and the
settings) and `--meta KEY=VALUE` (a fact to record with it). From Windows it runs in WSL. The
runner's sources are `bench/`: `bench.c` (the runner) and one `suite_*.c` per suite.

### How to read a verdict

Each row gives the contender's speed, then its comparison with the first row:
- **fastest and median ns per call**, and octets per ns at the fastest: what the routine costs;
- **the paired ratio:** each round gives the first row's time over this row's, both measured
  within milliseconds of each other. The row shows the median of those ratios with its
  bootstrap 95% interval. Above 1, this row is faster;
- **the verdict:** `faster` when the whole interval lies above both 1 and the A/A twin's
  interval, `slower` when it lies below both, and `noise` otherwise.

Why paired rounds decide (measured 2026-11-26, the same 41-round run judged three ways):
- **The fastest sample**, the rule the earlier harness used, called identical code faster four
  times and slower once. When the two fastest samples tie, the A/A gap reads 0, and any ratio
  counts.
- **Unpaired medians** gave the right verdicts, but the A/A interval spanned ±10% (0.91-1.10 at
  1024 octets). A real 8% gain would read as noise.
- **Paired rounds** gave the right verdicts with an A/A interval of about ±2% (0.99-1.03). The
  host's drift hits both sides of a round alike, so pairing cancels it.

### The instruments

- **A/B of two builds: `ab COMMIT`.** COMMIT's libhttpasm.so is built once, in a git worktree
  under `.ab/`, and loaded beside the tree's own (`dlopen`, `RTLD_LOCAL`, so neither build's
  calls reach the other). Both run interleaved at every tier, and each case ends with "speedup
  of current over COMMIT at TIER". The A/B runs in 3 processes (`--repeat N`), and a change is
  proven only when every process gives the same verdict. The reason: identical code at another
  address can run up to 12% faster or slower in one process, through branch-predictor and
  cache-set aliasing, and every process loads the builds at new random addresses.
- **Instruction counts: `icount`.** Each contender's batch runs once under Intel SDE (the
  version `tests/tools.sh` pins), between two marker instructions. SDE counts exactly the
  instructions executed per call, and the instruction classes that ran (SSE2, AVX2...), which
  shows that a tier runs its own version. The count is the same on every run. SDE presents
  this machine's CPU family: Alder Lake here, without AVX-512.
- **Loop analysis: `mca ROUTINE`.** Each version's loops, cut from the built library, go
  through llvm-mca (Alder Lake model by default). It gives the simulated cycles per iteration,
  the throughput bound, the IPC and the busiest execution ports. It models the core alone (no
  caches, frequency or memory), so it guides a loop's design and never proves anything.

### Why trust it: the validation of 2026-11-26

Each instrument had to be consistently and empirically valid before it was used (the owner's
condition). On the i9-13900K under WSL2:

| Check | Result |
|---|---|
| Paired verdicts with known answers: 5 runs of the tiers suite (41 rounds). Identical code must say noise: v2 everywhere, and every tier below 32 octets. The AVX2 version must say faster from 32 octets up | 165 of 165 right |
| One-process A/B against an identical copy of the build (5 runs, 220 comparisons) | 6 wrong (2.7%), in random directions, 5 of them at 63 octets |
| The same comparisons, requiring 3 processes to agree | 0 wrong |
| A/B against a build slowed by one extra uop per iteration of the AVX2 loop (about 11%), 3 processes | Proven slower at 256 and 4096 octets (3 of 3 processes). Not proven at 1024 (2 of 3). Not detectable at 100 octets and below (3 iterations or fewer: under 4%). Unchanged code was never proven different |
| SDE counts, repeated, and at 10,000 against 20,000 calls | Identical. The slowed build counted exactly one more instruction per iteration (1941 against 1813 at 4096 octets) |
| llvm-mca's simulated cycles against measurements | v3 over v1 per octet: 2.00x predicted, 1.99-2.10x measured. The extra uop: +11.0% predicted, +10.7-12.6% measured |

Two agreements are a start for llvm-mca, not a proof. Each loop of step 4 gets the same check
(prediction against measurement), recorded here, and llvm-mca is dropped if it stops agreeing.

**AVX-512** is not timed, counted or analyzed where the CPU lacks it (the owner's rule,
2026-11-26): the default SDE and llvm-mca models are this machine's. `tests/native/tiers` still
proves every AVX-512 version equal to v1 under SDE: a test, not a measurement.

## Whole servers: `run.sh` and `ab.sh`

`run.sh` measures HttpAsm against nginx and h2o, against its own HTTP/1.1-only build, and its
two backends against each other. The second comparison is the isolation measurement of
[docs/DESIGN.md](../docs/DESIGN.md) section 4: it checks whether building HTTP/1.1 from shared
source, next to HTTP/2, costs it anything. The third decides which backend is the default:
`httpasm` runs on epoll, the default, and `httpasm-uring` is the same build asking for
io_uring.

Every report it writes is kept in [results/](results/), named by date and time, with the machine,
the versions and the settings it ran with.

### What is measured


Every server answers `GET /` with `200 Hello, World!` (`text/plain`), the TechEmpower plaintext
shape, from code:
- HttpAsm: `samples/Hello`'s handler;
- nginx 1.24: `return 200`;
- h2o 2.2.5: an mruby handler.

Each server runs 4 workers pinned to CPUs 0-3. The load generators run on CPUs 8-15, twice as
many, so the servers should be the limit.

| Scenario | Load generator | What it shows |
|---|---|---|
| `h1` | `wrk -t8 -c256` | HTTP/1.1 keep-alive, one request at a time per connection |
| `h1-pipelined` | `h2load --h1 -c256 -m16` | HTTP/1.1, 16 requests in flight per connection |
| `h2` | `h2load -c64 -m32` | HTTP/2 over cleartext (h2c, prior knowledge), 32 streams per connection |

Each run records two numbers:
- **requests per second**;
- **the server's CPU time per request:** utime + stime of all its processes, read from `/proc`
  before and after the run.

The second number still means something when a run is limited by the load generator or by the
machine, which throughput alone would hide. It is the measure the isolation question is decided
on.

Each round runs every server once per scenario, interleaved, so drift (heat, the host's other
work) hits all of them alike. The table gives each pair's median over the rounds, the lowest
and highest CPU time per request any round measured, and every round's numbers below it.

**The noise floor.** `httpasm-control` is a second process of the very same full build (an A/A
control), run in the HTTP/1.1 scenarios. Whatever separates it from `httpasm` is noise, so the
isolation result (the full build against the HTTP/1.1-only build) counts only where it is
larger than that gap.

### How to run

On Linux x64 (WSL2 works), with nginx, h2o (with mruby), wrk and h2load (`nghttp2-client`)
installed:

```bash
dotnet build HttpAsm.slnx -c Release                 # samples/Hello and libhttpasm.so
dotnet build src/HttpAsm/HttpAsm.asmproj -c H1Only   # the isolation control
ROUNDS=5 benchmarks/run.sh 10                        # 5 rounds of 10 s per server and scenario
```

`SERVER_CPUS`, `CLIENT_CPUS` and `WORKERS` move the pinning. Nothing else may run on the machine
meanwhile: not even a build, which here once replaced `libhttpasm.so` under the running servers.

`ab.sh` answers a narrower question, whether a change made HttpAsm cheaper or dearer: two
builds of the Hello sample, interleaved, and the second one twice (its A/A control), in `h1`
and `h1-pipelined`:

```bash
git worktree add --detach ../before <commit>                    # the build to compare against
(cd ../before && dotnet build samples/Hello/Hello.asmproj -c Release)
dotnet build samples/Hello/Hello.asmproj -c Release             # the change
benchmarks/ab.sh ../before . 5 10                               # 5 rounds of 10 s
```

`HELLO_IO_A` and `HELLO_IO_B` choose each build's backend (`epoll`, the default, or `uring`).

## Results

**2026-11-27: RSA verification.** RSASSA-PKCS1-v1_5 with SHA-256 under Project Wycheproof's
keys (e = 65537) at 2048, 3072 and 4096 bits, beside OpenSSL 3.0.13's EVP_PKEY_verify: with
the key kept (ours prepared before the loop; OpenSSL's key and context made once, its
Montgomery constants cached at the first call), and with the key made from n and e each call
(ours `httpasm_rsa_public_key_init`; OpenSSL EVP_PKEY_fromdata, a context, the digest set,
verify, both freed): a TLS client's work per certificate, whose key verifies one signature.
5 rounds; the ratio is the paired estimate:

| Case | v3 (mulx, adcx/adox) | v1 (mul) | OpenSSL 3.0.13 | |
|---|---:|---:|---:|---|
| verify, key kept, 2048 | 15.8 us | 37.7 us | 20.2 us | 1.24x OpenSSL |
| verify, key kept, 3072 | 34.6 us | 85.9 us | 43.9 us | 1.27x OpenSSL |
| verify, key kept, 4096 | 61.4 us | 162.4 us | 76.7 us | 1.25x OpenSSL |
| key made + verify, 2048 | 17.7 us | 39.4 us | 33.0 us | 1.85x OpenSSL |
| key made + verify, 3072 | 38.3 us | 89.1 us | 57.9 us | 1.52x OpenSSL |
| key made + verify, 4096 | 68.2 us | 167.5 us | 95.3 us | 1.39x OpenSSL |
| key init alone, 2048 / 3072 / 4096 | 1.82 / 3.39 / 6.26 us | the same | | |

The tiers suite: v3 2.38x v1 at 2048 bits [2.32-2.42]. The first version (CIOS products only,
R^2 mod n by eleven squarings) ran a verification in 22.3 us at 2048 bits and a key init in
13.2: 0.93x OpenSSL with the key kept. What moved it, each step measured (scratchpad rsa/,
cycles at the core's 2.8 GHz, checked with a chain of dependent imuls):
- the square: the products above the diagonal once, then doubled with the squares, then k
  reduction rows: 1.5k^2 multiplies against the product's 2k^2. Rows of every length with a
  single-limb lead-in: 2,474 cycles at k = 32 (1.18x the product); the triangle in blocks of
  eight rows, each row's in-block part in straight lines and the rest whole 8-limb groups
  through one routine the carry chains run through (call and ret keep the flags): 2,322
  (1.28x), and 690 against 828 at k = 16;
- the reduction alone to leave Montgomery form (k^2, where the product by 1 is 2k^2);
- R^2 mod n by long division, one quotient digit per limb with mul: 1.8 us at 2048 bits
  against 13.2 for the squarings (7x; 6.3 against 53.7 at 4096);
- the octet conversions eight octets at a time (bswap) instead of a shift per octet.
Tried and not kept, with the probes that explain why (scratchpad rsa/mb*.asm, units of 32 a
loop): a product row (mulx, adcx from t, adox, a store) runs at 1.4 to 1.6 cycles a limb in
every arrangement; two independent flag chains run at 1.03 cycles a pair, and so does either
chain beside a mulx (1.01), but both chains with mulx run at 1.52, and both with any one
port-1 and one port-5 instruction (imul and vpermq) at 1.48 - not a port conflict (mulx beside
two shrx on ports 0 and 6 stays at 1.02). So: the high words in two registers taking turns
(one mov a limb less: no change, 2,951 against 2,928 cycles at k = 32); two rows interleaved
eight limbs at a time, so the scheduler always has independent chains (correct, and slower:
3.29k^2 cycles against 2.85k^2); product scanning with one, two and three accumulators (1.67,
1.48 and 1.41 cycles a multiply-accumulate, no better than the rows); a nop per limb, which
had sped up the bare row (1.47 against 1.58) and slowed the whole product (3,098 against 2,930).
The products sit at about 1.4 cycles a multiply-accumulate on this core whatever their shape;
the time went into doing fewer of them.

**2026-11-27: P-256 (secp256r1).** ECDH, the public key, a TLS 1.3 key share, ECDSA's
signature and verification, beside OpenSSL 3.0.13's EVP_PKEY on P-256 (its ecp_nistz256
assembly): the derive alone (a key made once, the peer's key and the context once: OpenSSL
checks the peer's point once, ours every call); a key generated with its encoded public key;
a key share as OpenSSL's TLS 1.3 code makes one per handshake (key generated, its public key
encoded, the peer's key from its encoding, a context, the derive; ours draws its key with
`httpasm_random` too); EVP_PKEY_sign and EVP_PKEY_verify of a SHA-256 digest (contexts once),
7 rounds:

| Case | v3 (mulx, adcx/adox, AVX2) | v1 (mul, SSE2) | OpenSSL 3.0.13 | |
|---|---:|---:|---:|---|
| shared secret | 52.0 us | 54.9 us | 72.1 us | 1.37x OpenSSL |
| public key | 12.4 us | 13.2 us | 37.5 us | 3.0x OpenSSL |
| key share (key, public key, shared secret) | 65.1 us | 68.0 us | 175.2 us | 2.7x OpenSSL |
| ECDSA signature (hedged RFC 6979) | 15.5 us | 20.6 us | 26.7 us | 1.72x OpenSSL |
| ECDSA verification (Straus, wNAF) | 55.6 us | 58.6 us | 85.6 us | 1.54x OpenSSL |

The tiers suite: v3 1.049x v1 on a shared secret [1.032-1.068], 1.31x on a signature (v2 1.24x
already: the SHA extensions in RFC 6979's HMAC). How the parts measured, and what was tried
(scratchpad p256/micro.c, llvm-mca's Alder Lake model): a product 50.5 cycles chained and 37.7
four at a time, a square 42.5 and 30.6; llvm-mca put ports 0 and 6 (every adc, adcx, adox, sbb,
cmov and shift) at 94% busy and simulated 37.0 cycles a product, matching the measurement.
Taking the reduction's m << 32 and m >> 32 from one mulx moved a doubling from 378 to 356
cycles; the final subtraction by masks instead of cmov cost 14 cycles of a product's latency
and was dropped. OpenSSL's doubling (4M + 4S, a halving) against dbl-2001-b (3M + 5S): level
at v3, 7% faster at v1. The fixed base's window: 7 bits 11.85 us a public key, 6 bits 12.2, 5
bits 13.3 (tables of 151.5, 88 and 53 KB). The inversion: Bernstein and Yang's divsteps 2.16
us against Fermat's 4.1 (255 squarings in a chain); selecting the swapped f by cmov instead of
an addition 2,226 to 2,158 ns. Verification first ran both constant-time multiplications
(65.1 us); one variable-time pass with wNAF digits sharing the doublings took it to 57.6 us,
and its additions without the constant-time selection (they branch on infinity) plus the wNAF
recoding passing runs of zeros at once (bsf) to 55.6 us.

**2026-11-27: X25519.** `httpasm_x25519` (one shared secret a call) and a TLS 1.3 key share's
X25519 work (`httpasm_x25519_public_key`, then `httpasm_x25519`), beside OpenSSL 3.0.13's
EVP_PKEY X25519: the derive alone (keys and context made once), and per handshake (the private
key from raw octets, which computes its public key; the peer's key; a context; the derive),
9 rounds:

| Case | v3 (mulx, adcx/adox) | v1 (mul, 51-bit limbs) | OpenSSL 3.0.13 | |
|---|---:|---:|---:|---|
| shared secret | 33.8 us | 40.2 us | 40.2 us | 1.18x OpenSSL |
| key share (public key + shared secret) | 68.3 us | 80.8 us | 87.3 us | 1.28x OpenSSL |

The ladder's order of operations decided it: in RFC 7748's order both versions took 128k cycles
a call; with independent operations side by side (the reorder buffer overlaps only what is
adjacent), 97.5k at v3 and 111k at v1. The field's parts alone (scratchpad xx/micro.c): a
product 48 cycles chained and 26 four at a time, a square 40 and 22, an addition 13; v1's
product 46 and 40.

**2026-11-27: ChaCha20-Poly1305.** `httpasm_chacha20_poly1305_seal` in the TLS 1.3 shape (a
new nonce and a 5-octet AAD per record; the key is raw octets) beside OpenSSL 3.0.13's EVP
driven the same way (the key set once, per record the nonce, the AAD, the text, the final, the
tag), 11 rounds:

| Case | v3 (AVX2) | v2 (SSSE3) | v1 (SSE2) | OpenSSL 3.0.13 | |
|---|---:|---:|---:|---:|---|
| 64 octets | 208.6 ns | 208.0 ns | 231.7 ns | 443.3 ns | 2.12x OpenSSL |
| 1 KiB | 836.8 ns | 1,088 ns | 1,253 ns | 946.8 ns | 1.14x OpenSSL |
| 16 KiB | 8,675 ns (1.89 octets/ns) | 13,692 ns (1.20) | 16,001 ns (1.02) | 9,896 ns (1.66) | 1.14x OpenSSL |

64 octets take the same two horizontal blocks at v2 and v3 (blocks 0 and 1: the key and the
record). The stitching (Poly1305 between the quarter rounds) against a build without it, the
scratchpad's cctime.c on one core: 16 KiB 8,307 against 12,463 ns at v3 (1.50x), 13,149 against
18,457 at v2 (1.40x), 15,409 against 20,662 at v1 (1.34x). The parts alone at v3: ChaCha20 1.11
cycles an octet, Poly1305 1.01 (a chain of about 15 cycles a block), the AEAD 1.44. Two changes
measured in paired runs and dropped: the products reordered (Poly1305 2.5% slower) and the
fold's times 5 as one lea (3% slower); one kept: the short paths wipe only what they wrote
(64 octets at v3 from 246 to 220 ns).

**2026-11-27: AES-GCM, the AES-NI version interleaved.** `tiers/aes_128_gcm_seal` at v2 (the
path of CPUs without VAES) after its GHASH moved into the AES rounds (one block after each of
rounds 1-8) and its tail became one batched step, 11 rounds: 1 KiB 261.9 ns (was 316.9; OpenSSL
409.8), 16 KiB 3,350 ns, 4.89 octets/ns (was 4,358; OpenSSL 3,186, 5.14). By length
(scratchpad gcmlen.c, v2): 0 octets 195 cycles, 64 octets 276, 255 octets 376 (was 506), 1 KiB
771 (was 921). The VAES version stays the faster one where it can run (16 KiB 1,717 ns).

**2026-11-27: AES-GCM with VAES and VPCLMULQDQ.** The same cases with the third version (v3: two
blocks an instruction, the GHASH of sixteen blocks interleaved with their AES rounds), 15 rounds,
the host at 5-8% other load:

| Case | VAES + VPCLMULQDQ | AES-NI + PCLMULQDQ | OpenSSL 3.0.13 | |
|---|---:|---:|---:|---|
| AES-128-GCM, 64 octets | 76.7 ns | 88.3 ns | 223.0 ns | 2.91x OpenSSL |
| AES-128-GCM, 1 KiB | 148.8 ns | 316.9 ns | 400.2 ns | 2.69x OpenSSL |
| AES-128-GCM, 16 KiB | 1,723 ns (9.51 octets/ns) | 4,358 ns (3.76) | 3,180 ns (5.15) | 1.85x OpenSSL |
| AES-256-GCM, 1 KiB | 165.3 ns | 355 ns | 437.6 ns | 2.65x OpenSSL |
| AES-256-GCM, 16 KiB | 2,011 ns (8.15) | 5,078 ns | 3,699 ns (4.43) | 1.84x OpenSSL |

`tiers/aes_128_gcm_seal`: v3 is 2.06x v2 on 1 KiB and 2.50x on 16 KiB. On 16 KiB a 256-octet
step takes about 79 cycles where its 88 AES instructions alone need 44: the interleaving leaves
room. Short records by length (scratchpad gcmlen.c): 0 octets 155 cycles (E_K(J0), the AAD and
lengths blocks, the tag), 16-255 octets 227-279 after the VEX copy (1,520 before it).

**2026-11-27: AES-GCM, AES-NI with PCLMULQDQ and v1.** `httpasm_aes_gcm_seal` as TLS 1.3 calls it
(the key made once, a new nonce and a 5-octet AAD per record) beside OpenSSL 3.0.13's EVP driven
the same way (the key set once; per record `EVP_EncryptInit_ex` with the IV, the AAD, the text,
the final, `EVP_CTRL_AEAD_GET_TAG`), 9 rounds:

| Case | AES-NI + PCLMULQDQ | v1 (constant time) | OpenSSL 3.0.13 | |
|---|---:|---:|---:|---|
| AES-128-GCM, 64 octets | 88.3 ns | 931 ns | 230.6 ns | 2.61x OpenSSL |
| AES-128-GCM, 1 KiB | 311 ns | 8,171 ns | 401 ns | 1.29x OpenSSL |
| AES-128-GCM, 16 KiB | 4,344 ns (3.77 octets/ns) | 120.0 us | 3,185 ns (5.14) | 0.73x OpenSSL |
| AES-256-GCM, 1 KiB | 355 ns | 9,690 ns | 439 ns | 1.24x OpenSSL |
| AES-256-GCM, 16 KiB | 5,078 ns (3.23) | 142.0 us | 3,743 ns (4.38) | 0.74x OpenSSL |

On short records OpenSSL's EVP pays for its per-record setup; on long ones its AVX code wins by
interleaving the next blocks' AES rounds with the last blocks' GHASH, where this version runs the
eight-block counter mode and the eight-block GHASH one after the other. v1 runs at about 21
cycles an octet (0.14 octets/ns), 27x below AES-NI, as a table-free fallback does.

**2026-11-27: the AES block cipher.** `httpasm_aes_encrypt_block`, each call encrypting the last
call's output (one block's latency, as QUIC's header protection sees it), the key expanded
before the loop, beside OpenSSL 3.0.13's EVP (`EVP_aes_128_ecb`/`EVP_aes_256_ecb`, a context set
up once, `EVP_EncryptUpdate` of 16 octets a call), 11 rounds:

| Case | AES-NI | v1 (bitsliced, constant time) | OpenSSL 3.0.13 | |
|---|---:|---:|---:|---|
| AES-128, one block | 12.8 ns | 544 ns | 13.8 ns | 1.09x OpenSSL |
| AES-256, one block | 16.9 ns | 728 ns | 17.0 ns | level |

AES-NI's ten or fourteen dependent rounds set both libraries' times. v1 does eight blocks' work
for one (its bitsliced state holds eight blocks) and expands its compressed round keys on every
call; counter mode (GCM, next) fills all eight lanes and expands once per message.

**2026-11-27: HMAC-SHA384 and HKDF-SHA384.** `rivals/hmac_sha384/*` (21 rounds, the host at
9-14% other load, every A/A control within 1%) beside OpenSSL 3.0.13's `HMAC()` with
`EVP_sha384()`, under a 48-octet key; `tiers/hkdf_sha384_expand/*`, a 48-octet output key from a
48-octet secret with a 20-octet info:

| Case | HttpAsm best | v1 | OpenSSL 3.0.13 | |
|---|---:|---:|---:|---|
| HMAC-SHA384, 64 octets | 941.7 ns | 1,107 ns | 2,251 ns | 2.39x OpenSSL |
| HMAC-SHA384, 1 KiB | 2,607 ns | 3,191 ns | 3,909 ns | 1.50x OpenSSL |
| HKDF-Expand, 48 octets | 985 ns | 1,148 ns | | 1.17x v1 |

Four SHA-512 compressions make the 64-octet MAC (two for the key, one each for the inner and
outer hash), about 235 ns each at v3. HMAC-SHA256 and HKDF-SHA256, now written by the same
macro, measured as before (252.9 and 932.4 ns; HKDF 235.5 ns).

**2026-11-27: SHA-512 and SHA-384.** `httpasm_sha512` and `httpasm_sha384` (one shot) on the
hash cases' octets beside OpenSSL 3.0.13's `SHA512` and `SHA384` (its AVX2 + BMI2 code on this
CPU), 21 rounds, the host at 2-14% other load, every A/A control within 1.5%:

| Case | HttpAsm best (v3) | v1 | OpenSSL 3.0.13 | HttpAsm / OpenSSL |
|---|---:|---:|---:|---:|
| SHA-512, 64 octets | 241.5 ns | 279.2 ns | 628.3 ns | 2.60x faster |
| SHA-512, 1 KiB | 1,907 ns | 2,370 ns | 2,282 ns | 1.20x faster |
| SHA-512, 16 KiB | 26.76 us (0.61 octets/ns) | 33.71 us | 26.98 us (0.61) | level |
| SHA-384, 64 octets | 240.9 ns | 276.3 ns | 623.9 ns | 2.59x faster |
| SHA-384, 1 KiB | 1,904 ns | 2,353 ns | 2,283 ns | 1.20x faster |

v3 is 1.26x v1 on 1 KiB and 16 KiB (`tiers/sha512/*`). In cycles (a dependent add chain timed
beside it gives this WSL core's clock, about 2.9 GHz): 594 a block, 7.4 a round, where the
rounds alone take 6.9 (the schedule of two blocks in YMM costs the rest) and their dependencies
allow 5.0. The round is what bounds both libraries: OpenSSL runs the same arrangement, Intel's
(the Linux kernel's) runs 7.6 cycles, and 72 random valid reorderings of the 24 instructions,
adds for the LEAs and copies taken off the chain all stayed within the noise. On short messages
OpenSSL 3's one-shot pays for fetching its provider on every call.

**2026-11-27: HMAC-SHA256 and HKDF-SHA256.** `rivals/hmac_sha256/*` (31 rounds; the host carried
22% other load, the A/A control within 2%) beside OpenSSL 3.0.13's one-shot `HMAC()` with
`EVP_sha256()`, under a 32-octet key; `tiers/hkdf_sha256_expand/*`, a 32-octet output key from a
32-octet secret with a 20-octet info, as TLS 1.3's key schedule asks:

| Case | HttpAsm best | v1 | OpenSSL 3.0.13 | |
|---|---:|---:|---:|---|
| HMAC-SHA256, 64 octets | 253 ns | 1,086 ns | 1,524 ns | 6.0x OpenSSL |
| HMAC-SHA256, 1 KiB | 942 ns | 4,196 ns | 2,177 ns | 2.31x OpenSSL |
| HKDF-Expand, 32 octets | 230 ns | 886 ns | | 3.83x v1 |

Each is a few SHA-256 compressions (five for the 64-octet MAC, four for the HKDF output) at about
46 ns each with the SHA extensions; OpenSSL's one-shot HMAC also fetches its digest and builds a
context on every call.

**2026-11-27: M2's first primitive, SHA-256.** `httpasm_sha256` (one shot) on fixed
pseudo-random octets, beside OpenSSL 3.0.13's `SHA256` (the machine's libcrypto.so.3, loaded at
run time; it picks its SHA-extensions code as any application gets it), 41 rounds:

| Message | HttpAsm best (SHA extensions) | v1 (scalar) | OpenSSL 3.0.13 | HttpAsm / OpenSSL |
|---|---:|---:|---:|---:|
| 64 octets | 103.5 ns | 433.5 ns | 453.5 ns | 4.38x faster |
| 1 KiB | 793 ns | 3,553 ns | 1,143 ns | 1.44x faster |
| 16 KiB | 11.78 us (1.41 octets/ns) | 53.1 us | 12.16 us (1.37) | 1.03x faster |

Instructions (`icount`): 2.44 an octet with the SHA extensions, 46.5 at v1 (the 64 rounds at
about 30 instructions each, the schedule at 18 a word). On long messages both libraries run at
the SHA extensions' own speed; on short ones OpenSSL 3's one-shot pays for fetching its
provider on every call. The tiers suite (`tiers/sha256/*`) times all four tiers.

**2026-11-27: the whole servers at phase H's end** ([results/2026-11-27-0349.md](results/2026-11-27-0349.md),
7271315, 5 rounds of 10 s, the host quiet). Against M1's last run ([results/2026-11-23-1932.md](results/2026-11-23-1932.md),
f75c380, the same machine and load generators):

| Scenario | CPU µs/request, M1 -> now | requests/s against nginx, M1 -> now |
|---|---:|---:|
| h1 (wrk, 256 connections) | 4.13 -> 3.86 | 1.93x -> 1.78x |
| h1-pipelined (16 in flight) | 0.55 -> 0.49 | 10.75x -> 10.24x |
| h2 (64 connections, 32 streams) | 0.90 -> 0.81 | 7.96x -> 8.05x |

M1's `httpasm` ran on io_uring, then the default; today's runs on epoll, the default since
b932500, so the comparison is rough. In `h1` the A/A control (`httpasm-control`) sits 7% from
`httpasm` this time: what the kernel's networking costs per request (most of 3.8 µs) moves more
than any parser change can, and only the pipelined and HTTP/2 scenarios, where user space is a
larger part of each request, show step 4 above that noise. The HTTP/1.1-only build is
indistinguishable from the full one in both HTTP/1.1 scenarios (the isolation question,
docs/DESIGN.md section 4, still answered).

**2026-11-27: phase H step 4, HTTP/2's request rules.** SDE's profile of `httpasm_h2_request` on
the browser request's 18 fields put 30% of its 5,133 instructions in `h2_name`, which checked
each field name octet by octet, and 512 in the `:path`'s octet loop. From v2 both run through
`ha_span_v2` (`ha_token_length`'s 16-octet body, now a routine taking its class's nibble table):
names with `ha_ltchar_lo` (a tchar but A-Z), the `:path` by runs of target octets between
percent-encodings. The pseudo-field names are compared by two loads instead of `repe cmpsb`.

| Case | Instructions, before -> after | A/B against 3555a3e (3 processes) |
|---|---:|---:|
| h2_request, 18 fields, best tier | 5,133 -> 3,706 | 1.133-1.159x faster |
| h2_request, 18 fields, v1 | 5,650 -> 5,692 | 0.966-0.973x (slower, proven) |

v1's code is v1's but for a tier test per name and the new pseudo-field compare. Its first
measurement was 0.90-0.92x: both of its loops had moved, and starting each on a 32-octet window
(the padding jumped over, never run) brought it to 0.97x; the rest is the tier test. What is left
at the best tier: the per-field loop and the pseudo-field rules (1,221), the value checks
(1,186, SSE2 already: `HA_FIELD_VALUE_SCAN`), the spans (520), the field lookups (477).

**2026-11-27: phase H step 4, the one-pass response head.** The client's parser kept the classic
flow: the head's end searched line by line (`ha_h1_head_end`), then the status-line, then every
field line read again. From v2 up a head searched from its start is now read once, as requests
are: the status-line's fixed octets, the reason-phrase 16 octets a step, the field lines by
`ha_h1_fields_v2` in a response mode (its own rule table: the framing rules only). Anything it
would not accept, an obs-fold to rewrite included, goes back to the classic flow untouched.
The response head (now `bench_response`, shared by three suites) is timed beside picohttpparser's
`phr_parse_response` and llhttp's response mode (`rivals/h1_response`) and at every tier
(`tiers/h1_parse_response`):

| Contender | Instructions | Median ns (41-61 rounds) | |
|---|---:|---:|---|
| HttpAsm v1 (classic flow) | 5,123 | 405 | |
| HttpAsm v2, v3, v4 (one pass) | 2,081 | 185.6 | 2.16x over v1 [2.11-2.23] |
| picohttpparser dd573d8 | 1,701 | 184.6 | 1.009x HttpAsm's best: noise |
| llhttp 9.4.4 | 3,904 | 401.4 | HttpAsm 2.16x faster |

Against 3118fc7 (`bench.sh ab`, 3 processes): the best tier 1.60-1.62x faster (proven), v1 not
proven (1.02-1.09x, the processes disagree). The request heads, whose field lines now load their
rule table from the stack, show no difference at the best tier (0.98-1.01x on all three heads).

**2026-11-27: phase H step 4, HPACK's Huffman encoding.** `hp_string_encode` measured a string's
code first (a table load and an add per octet, the adds in one chain) and then wrote it an octet
per flush. Now the measure takes four octets a step into two sums, and the codes leave 32 bits at
a time. Every tier runs it, so the proof is the A/B against 4a9f52f (3 processes agreeing):

| Case | Instructions, before -> after | Best tier | v1 |
|---|---:|---:|---:|
| hpack_encode, the browser request's 18 fields | 21,155 -> 15,677 | 1.67-1.70x faster | 1.59-1.60x faster |

The blocks are the old encoder's octet for octet: 60,000 blocks (random fields with rare
octets, Huffman on and off, indexed or not, at every tier) encoded by both builds compared equal.

**2026-11-27: phase H step 4, chunk sizes: a whole chunk at once.** The chunked decoder read
its framing octet by octet through a state machine kept in memory (the state reloaded and
compared each octet): 184 instructions per 16-octet chunk. At a chunk's first octet it now
takes a plain, complete chunk in registers and moves its data down with sized moves; anything
else goes back to the state machine, untouched. It serves every tier, so the proof is the A/B
against f3adabd (3 processes agreeing):

| Case | Instructions, before -> after | Best tier | v1 |
|---|---:|---:|---:|
| 256 chunks of 16 octets | 47,219 -> 28,519 | 2.59-2.63x faster | 2.59-2.63x faster |
| 16 chunks of 1,024 octets | 35,667 -> 34,487 | 1.04x faster | 1.04x faster |

(SDE counts `rep movsb` by octet, so the large chunks' copies dominate their counts.) The host
carried other work during the A/B (53-56% CPU); the paired verdicts in all three processes held.

**2026-11-27: phase H step 4, whole-token checks at v2 and the response writer's copies.** SDE's
profile of writing a 200 with six fields (2,366 instructions) put half in `ha_check_fields`: each
field name checked octet by octet (`HA_TOKEN_SCAN`, 5 instructions an octet). The writer also
copied every piece with `rep movsb` and divided by 10 with `div` for each digit of the length.
  - `ha_token_length` (`semantics/fields.asm`, also `httpasm_token_length`): at v2, 16 octets a
    step with the tchar tables, the last step overlapping, a short token read within its page.
    The writers' field names and `httpasm_field_id` call it; a token inside a value keeps the
    inline scan.
  - `wr_put` copies with two overlapping moves sized to the piece, and a 16-octet loop beyond;
    `wr_decimal` divides by multiplying (x / 10 = (x * 0xCCCCCCCCCCCCCCCD) >> 67). Both serve v1.

| Case | Instructions, before -> after (best) | A/B against 199517f (3 processes): best, v1 |
|---|---:|---:|
| 200 with 6 fields | 2,366 -> 2,023 | 1.17-1.18x, v1 1.04-1.09x |
| token_length, 45-octet name | 330 -> 75 | 4.56-4.62x, v1 no difference |
| token_length, "GET" | 36 -> 40 | 1.09-1.11x, v1 0.93-0.94x |
| field_id, 12 names | 1,931 -> 1,277 | 1.54-1.58x, v1 1.19-1.23x |

v1's gain on the writer is its own (the copies and the division serve every tier); its 6% loss on
a 3-octet token is the dispatch the scan now passes through. What is left of the writer spreads
over its field checks, its 20 piece copies and the lookups, with no single block in front.

**2026-11-26: phase H step 4, HPACK's Huffman decoding at v3 (BMI2).** The v2 table decoder
shifts its window by `cl` after each lookup's bounds compare; on Intel cores `shl` by `cl` merges
the flags (a shift by 0 keeps them), so the shift waits for the compare, on the chain that sets
the time. At v3 the same decoder (one source, `H2_DECODER`, expanded twice) uses BMI2's `shlx`,
which touches no flags. `tiers/hpack_decode`, every tier in one build, 61 and 81 rounds:

| Tier | Instructions | Median ns (61 / 81 rounds) | Over v1 [95% CI], 81 rounds |
|---|---:|---:|---:|
| v1 (automaton) | 19,592 | 2,309 / 2,302 | baseline |
| v2 | 11,472 | 1,533 / 1,513 | 1.517x [1.513-1.523] |
| v3 (shlx) | 11,424 | 1,450 / 1,478 | 1.571x [1.558-1.582] |
| v4 (v3's code) | 11,424 | 1,491 / 1,450 | 1.593x [1.579-1.624] |

Both contenders that run the shlx code sit above v2 in both runs, intervals apart: v3 is kept.

**2026-11-26: phase H step 4, HPACK's Huffman decoding at v2.** An HTTP/2 server decodes a header
block on every request; the browser request's block (18 fields, 563 octets, 515 of them in
Huffman strings) took 2.3 us at v1, 60% of it in the Huffman automaton: two dependent table loads
per octet, about 10 cycles per symbol. From v2 up a table decoder takes 12 bits at a time
(`hpack.asm` `.huffman_v2`): one lookup gives up to two symbols; codes longer than 12 bits go to
the canonical tables; a string's last bits to a table of first-code lengths.

| Measure | v1 | v2 | |
|---|---:|---:|---|
| instructions per block | 19,544 | 11,424 | -42% |
| median time, same build (61 rounds) | 2,306 ns | 1,537 ns | 1.50x |
| A/B against 8836fdd (3 processes) | no difference | 1.47-1.48x faster | |
| nghttp2 1.71.0, same run | 3,434 ns | | HttpAsm 2.23x faster (1.48x before) |

The first layout put the two symbols in the dword's low bytes and the bit count in byte 2: 1.33x.
With the bit count in the low byte, the loaded dword feeds the window's shift directly, and the
same decoder with 386 more instructions per block ran 1.49x: each lookup's latency chain is the
whole cost, as with the request head. The first version of the string's end also searched the
canonical tables twice per string (the last symbol, then the padding); `ha_huff_first_bits`
settles both from the last lookup, 659 instructions fewer per block.

**2026-11-26: phase H step 4, AVX2 for the one-pass request head: measured, not kept.** The
tiers suite now times `httpasm_h1_parse_request` on the rivals suite's three heads at every tier
(`tiers/h1_parse_request/*`), so a version above v2 is judged against v2 in one build. A v3
version of the one-pass field lines (32-octet AVX2 steps for names and values, from the same
source as v2's by a width parameter, with a VEX-encoded field lookup so no SSE instruction met a
dirty upper half) ran 13.5-13.7% fewer instructions on the two larger heads and was no faster:

| Request head | Instructions, v2 -> v3 | v2, v3 (median ns, same build, 61 rounds) | v3 over v1 / v2 over v1 |
|---|---:|---:|---:|
| small GET | 674 -> 677 | 47.7, 48.6 | 1.35x / 1.37x |
| browser GET | 3,273 -> 2,825 | 295.7, 301.4 | 2.00x / 2.07x |
| API POST | 1,960 -> 1,696 | 153.1, 154.6 | 2.00x / 2.02x |

The A/A control stayed within 2% while the machine carried other work (34% CPU on the host). A
head's time is the chain from one line's end to the next line's start, which wider steps do not
shorten, and a 32-octet load splits a cache line twice as often as a 16-octet one, on that same
chain. So v3 runs v2's code (cpu.inc: a tier is kept only when it measures faster), and the
attempt stays described here rather than kept in the tree. A gain for these heads has to come from
the chain itself.

**2026-11-26: phase H step 4, the one-pass request head at v2.** With the lookup done, the
browser request's profile showed what the field lines and the lookup could not: 16% of its
instructions in the search for the head's end (`ha_find_lf`, called once per line), a pass that
the field lines then repeat, each line with its own loop exit to predict. From v2 up a head that
arrives whole is now read once (`ha_h1_fields_v2`, request.asm's `.one_pass`), the empty line
found on the way; anything it would not accept goes back to the classic flow, so outcomes are
unchanged (`tests/native/tiers`, 340,298 more parses at every tier).

| Request head | Instructions, before -> after (best tier) | v1 / best, same build | picohttpparser's lead, before -> after |
|---|---:|---:|---:|
| small GET | 804 -> 670 | 0.70x | 2.15x -> 1.58x |
| browser GET | 5,541 -> 3,239 | 0.48x | 1.79x -> 1.03x |
| API POST | 3,030 -> 1,944 | 0.50x | 1.74x -> 1.15x |

Against the commit before (f5ba99a, `bench.sh ab`, 3 processes, all agreeing), the best tier is
1.70-1.72x faster on the browser head with v1 unmoved there (no difference), 1.50-1.51x on the
API POST head and 1.36-1.38x on the small GET, where v1 moved 1.05-1.06x and 1.09-1.14x by
placement. The response parser, which keeps the classic flow, shows no difference at either
tier.

**2026-11-26: phase H step 4, the field-name lookup at v2.** After the field lines, SDE's
profile of the browser request put 20% of its instructions in `ha_field_lookup`, which compared
a candidate name octet by octet (7 instructions an octet). At v2 it now builds the same key from
two 16-bit loads and compares 16 octets at a time against two generated rows per known name, one
lower case and one upper case (`specs/generate.cs`): an octet matches when it equals either, which
is exactly the case-insensitive compare of letters and the exact compare of everything else.

| Case | Instructions, before -> after (best tier) | Against fe7f29b (3 processes): best, v1 |
|---|---:|---:|
| field_id, 12 names (10 known) | 2,536 -> 1,931 | 1.43x faster, v1 not proven (0.96-0.98x) |
| HPACK encode, 18 fields | | 1.06-1.08x faster, v1 no difference |
| HTTP/2 request rules, 18 fields | | 1.29-1.32x faster, v1 1.12-1.15x faster |
| small GET | 825 -> 804 | 0.93-0.95x, v1 0.88-0.90x |
| browser GET | 6,180 -> 5,541 | no difference, v1 no difference |
| API POST | 3,335 -> 3,030 | 1.09-1.11x faster, v1 0.95x |

In the same build the v2 lookup is 1.42x faster than v1 (`parsers/field_id`, tier verdict). The
v1 column is the control: its code changed only by the dispatch test at the lookup's entry, yet
it moved between 0.88x and 1.15x, the code-placement effect again. So the rows where v1 moved
say only that the best tier gained more (API POST, HTTP/2) or lost less (small GET) than the
placement alone. The browser head ran 10% fewer instructions in the same time: its lookups run
beside the line scans, off the path that sets its time, which is the scans' own chain from one
line's end to the next line's start.

**2026-11-26: phase H step 4, the HTTP/1.1 field lines at v2.** SDE's profile of the browser
request (7,653 instructions per call) put 55% in `ha_h1_fields`, which now scans each line 16
octets a step at v2 (docs/DESIGN.md, step 4). On the i9-13900K under WSL2:

| Request head | Instructions, v1 -> v2 | v2 over v1 (paired, 41 rounds) | picohttpparser's lead, before -> after |
|---|---:|---:|---:|
| small GET (37 octets) | 861 -> 832 | 1.10x | 2.15x -> 1.96x |
| browser GET (846 octets) | 7,717 -> 6,536 | 1.17x | 2.49x -> 1.79x |
| API POST (511 octets) | 4,032 -> 3,548 | 1.18x | 2.73x -> 1.88x |

Against the commit before the change (`bench.sh ab fd9a354`, 3 processes, all agreeing), the best
tier measured 1.08x, 1.43x and 1.37x. v1 itself measured 1.23x and 1.14x faster on the two larger
heads, though it runs slightly more instructions (two dispatch tests per line). The inserted code
moved the scalar loop to a placement this CPU runs faster. That is the code-placement effect the
validation measured, so only the tier verdict above is the vector code's own. llhttp is now
slower than HttpAsm on all three heads.

A refinement (fe7f29b) classifies each value step once, and settles a step's bounds with one
compare when it ends within the head. It cut the v2 instructions further (browser 6,536 -> 6,180,
API POST 3,548 -> 3,335, small GET 832 -> 825) with no time difference in an A/B against e0ef184
(3 processes). The same A/B measured v1, whose code had not changed, 4-5% slower on the two
larger heads: placement again, the other way round.

- 2026-11-26, `results/2026-11-26-rivals.md` (i9-13900K under WSL2, the first run, by the
  earlier `rivals` harness and its fastest-sample rule): the baseline for phase H step 4. The
  framework's rivals suite confirms it (paired, 2026-11-26): picohttpparser 2.1-2.5x faster
  on the three heads.
  - **Request heads:** picohttpparser is 2.1-2.3x faster than HttpAsm; llhttp is level or up
    to 1.34x slower.
  - **HPACK:** HttpAsm decodes 1.48x faster than nghttp2.
  - **Tiers:** HttpAsm's best tier equals its v1, because its one vector routine (the field
    value scan) is too small a share of a whole parse to show.

**2026-11-26: `httpasm_field_value_scan` per tier, the tier framework's pilot.** On this
machine (i9-13900K, WSL2, features 0xff03: v3 with VAES, VPCLMULQDQ, SHA-NI and GFNI, no
AVX-512), with the earlier `micro` harness at 41 rounds: the fastest ns per call, then the
baseline's time over the tier's. The framework's paired runs (5 runs of 41 rounds, the same
day) agree: v3 faster from 32 octets (1.36x at 32, 1.71x at 64, 2.05x at 256, 2.10x at 1024),
noise below 32.

| Octets | v1 (SSE2) | v3 (AVX2) | v3 vs v1 | A/A (v1 again vs v1) |
|---:|---:|---:|---:|---:|
| 8 | 2.80 | 2.74 | 1.02x | 0.92x |
| 16 | 2.84 | 2.93 | 0.97x | 0.95x |
| 31 | 3.36 | 4.27 | 0.79x | 0.97x |
| 32 | 3.11 | 2.42 | 1.28x | 1.00x |
| 64 | 6.24 | 3.46 | 1.80x | 1.11x |
| 256 | 15.11 | 7.43 | 2.03x | 1.04x |
| 1024 | 63.25 | 29.24 | 2.16x | 1.10x |
| 4096 | 248.84 | 114.84 | 2.17x | 0.99x |

What it shows:
- **The AVX2 version is kept**: from 32 octets up it beats the baseline by more than the A/A
  gap, 1.3x at 32 and over 2x from 256.
- **Below 32 octets every tier runs the SSE2 code**, so differences there are noise. The
  0.79x at 31 is one row; the same code measured as "v4" gave 1.07x.
- **The AVX-512 version cannot run on this CPU.** It is proven equal to the others under
  Intel SDE (`tests/native/tiers`), and is not timed here: no AVX-512 is measured where the
  CPU lacks it (the owner's rule, 2026-11-26).

Every run's report is in [results/](results/), named by date and time; a report names the
commit it measured (`-dirty` when the tree had uncommitted changes when the run began).

**2026-11-23, b932500: io_uring against epoll** ([report](results/2026-11-23-2008.md)). The same
machine and settings as the run below, 5 rounds of 10 s; at b932500 io_uring was the default,
so `httpasm`, its A/A control and the HTTP/1.1-only build ran on io_uring, and `httpasm-epoll`
was the full build asked for epoll. The server's CPU µs per request, medians (range over the
rounds):

| Scenario | io_uring | io_uring, A/A | io_uring, HTTP/1.1-only | epoll |
|---|---:|---:|---:|---:|
| `h1` | 5.37 (5.11-6.01) | 5.46 (5.21-6.24) | 5.10 (4.84-5.74) | **4.99** (4.51-5.43) |
| `h1-pipelined` | 0.71 (0.60-0.77) | 0.74 (0.61-0.80) | 0.72 (0.65-0.77) | 0.69 (0.62-0.80) |
| `h2` | 1.25 (1.01-1.34) | | | 1.17 (0.89-1.24) |

What it shows:
- **io_uring, as built, is not cheaper than epoll on Linux 5.15.** In `h1` epoll was the
  cheapest of the four HttpAsm processes in every round (tied once), which chance alone would
  give about once in a thousand runs; pipelined and over HTTP/2 the two are within the noise
  (epoll was lower in 4 of the 5 `h2` rounds). The backend arms a one-shot poll again for
  every request, which epoll's lasting registration does not pay; batching the receives and
  sends into one `io_uring_enter` per turn does not win that back.
- **So epoll became the default** (`HTTPASM_SERVER_URING` asks for io_uring), and every test
  runs on both backends. io_uring becomes the default only when a design of it measures
  faster: multishot polls, registered descriptors, and on newer kernels DEFER_TASKRUN,
  multishot receives into provided buffers and zero-copy sends.
- **This run's absolute numbers are higher than the f75c380 run's** (`h1`: nginx 8.44 against
  8.05, HttpAsm's epoll 4.99 against 4.13): the host was busier. Only comparisons within one
  run count. Whether the epoll path itself got dearer when io_uring was added was measured
  directly, with `ab.sh` ([report](results/2026-11-23-2037-ab-epoll.md)): f75c380 against the
  change that made epoll the default, interleaved, with that change twice (its A/A control).
  `h1`: 4.45 µs against 4.52 and 4.40, so the A/A pair brackets f75c380; `h1-pipelined`: 0.58
  against 0.60 and 0.60, a gap that an earlier run of the same comparison (a scratch copy of
  the script) gave the other way round, 0.64 against 0.61 and 0.62. No change is measurable.
- The ring sizes changed after this run (4096 SQEs and 16384 CQEs, then 256 and 4096, for
  the memory charge of Linux 6.14 to 7.2; docs/DESIGN.md section 7, step 4). At 64 connections per worker
  a turn queues at most 192 SQEs and no CQE overflows, so the sizes do not touch these
  numbers.

**2026-11-23, f75c380** ([report](results/2026-11-23-1932.md)): an i9-13900K under WSL2 (Linux
5.15), 4 workers per server, 5 rounds of 10 s. The medians, with the CPU time per request's
range over the rounds:

| Scenario | HttpAsm | same build (A/A) | HTTP/1.1-only build | nginx 1.24 | h2o 2.2.5 |
|---|---:|---:|---:|---:|---:|
| `h1`: requests/s | 1,022,993 | 907,096 | 1,016,105 | 529,168 | 281,458 |
| `h1`: CPU µs/request | 4.13 (3.95-4.59) | 4.17 (4.00-4.56) | 4.11 (4.06-4.43) | 8.05 | 13.07 |
| `h1-pipelined`: requests/s | 7,674,648 | 7,740,854 | 7,584,502 | 714,027 | 493,756 |
| `h1-pipelined`: CPU µs/request | 0.55 (0.53-0.61) | 0.55 (0.54-0.59) | 0.55 (0.54-0.57) | 6.04 | 8.89 |
| `h2`: requests/s | 4,573,014 | | | 574,250 | 939,066 |
| `h2`: CPU µs/request | 0.90 (0.81-0.94) | | | 7.36 | 4.62 |

What it shows:
- **The isolation question:** HTTP/1.1 built next to HTTP/2 from shared source costs nothing
  measurable. The full build and the HTTP/1.1-only one differ by 0.02 µs per request (4.13
  against 4.11) where two processes of the very same build differ by 0.04 (4.13 against 4.17),
  and all three ranges overlap; pipelined, all three measure 0.55. The design of
  [docs/DESIGN.md](../docs/DESIGN.md) section 4 stays.
- **Throughput alone would mislead:** the same build ran at 1.02 and 0.91 million requests/s in
  `h1`, 12% apart, because one request per connection at a time leaves the load generator and
  the loopback as much in charge as the server. CPU time per request is the measure.
- **Against nginx and h2o:** per request, HttpAsm uses about half of nginx's CPU time without
  pipelining, about a tenth with it, and an eighth of nginx's (a fifth of h2o's) over HTTP/2.

Scope: one machine, under WSL2 (a virtualized kernel), with servers and load generators on the
same host; a "Hello, World!" answer, so the protocol work dominates and no application work
hides it. Other machines, kernels and answers will move the numbers.
