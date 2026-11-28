# HttpAsm

A complete HTTP networking library in x86-64 assembly: HTTP/1.1, HTTP/2 and HTTP/3, with QUIC
and TLS of its own, as both client and server. It is built from the official documents, and
maximum performance is its guiding value. Part of the [AsmFoundation](https://github.com/AsmFoundation)
family, next to [KvAsm](https://github.com/AsmFoundation/KvAsm) and
[GrpcAsm](https://github.com/AsmFoundation/GrpcAsm). It builds with
[AsmSdk](https://asmfoundation.github.io/AsmSdk/).

> **Status: in development; nothing is released.** Milestone 1 (the shared semantics, HTTP/1.1
> and HTTP/2) is complete. Next: hardening and CPU acceleration of all of it, then our own
> crypto with TLS 1.3 (M2), then TLS 1.2 and certificates (M3) ([docs/DESIGN.md](docs/DESIGN.md)
> section 7). What works today, on Linux x64:
> - **a server** (`httpasm_server_*`): HTTP/1.1 and HTTP/2 (h2c with prior knowledge) on one
>   port, one worker per core on epoll, or on its own io_uring when asked
>   (`HTTPASM_SERVER_URING`; epoll measured as cheap or cheaper, so it is the default),
>   handlers that answer at once or later from any thread; HTTP/2 passes all 146 cases of
>   h2spec. Hardened against the published floods (each measured by `tests/native/floods`)
>   and slow clients: the idle timeout is a window a transfer keeps by moving at least
>   `min_data_rate` octets a second, so large transfers take as long as they need while
>   slowloris, slow bodies and slow reads are cut. Every published request-smuggling mutation
>   (defparam/smuggler's and PortSwigger's, 1,671 requests with the variants) is framed as RFC
>   9112 frames it, or refused;
> - **a client** (`httpasm_client_*`): one blocking HTTP/1.1 connection, tested against this
>   server and against Kestrel;
> - **the codecs** behind them, callable on their own: HTTP/1.1 parsing and writing in both
>   directions, chunked bodies, HPACK, HTTP/2's request rules;
> - **the cryptography** TLS 1.3 is being built from (M2): SHA-2, SHA-3, HMAC and HKDF, AES-GCM,
>   ChaCha20-Poly1305, X25519, X448, ECDH and ECDSA on P-256/384/521, Ed25519, Ed448, ML-KEM,
>   FFDHE and RSA, each with a constant-time baseline and accelerated tiers, held to NIST's and
>   Project Wycheproof's vectors and checked for constant time by valgrind (`tests/ct/`); and
>   the keys' formats: an ASN.1 reader of BER and DER (`httpasm_asn1_*`, linear in its input
>   however deep BER nests), PEM (`httpasm_pem_read`), private keys from their files
>   (`httpasm_private_key_load`: PKCS#8, PKCS#1, SEC1), and certificates' structure and public
>   keys (`httpasm_certificate_read`, `httpasm_public_key_read`, `httpasm_private_key_matches`;
>   chain validation is M3's); and the TLS 1.3 engine as far as it goes: its key schedule and
>   record layer (`httpasm_tls13_*`, proven against every secret and record of RFC 8448's
>   traces), its handshake messages and extensions, each read strictly and in place
>   (`httpasm_tls13_*_read`, `httpasm_tls_extensions_read`; every message of the traces, a
>   model written apart, a fuzzer), and the server's handshake (`httpasm_tls13_server_*`,
>   `httpasm_tls13_receive`, `_send`, `_close`, `_key_update`; sans-I/O, the caller's memory and
>   random source): every group (the post-quantum hybrids X25519MLKEM768, SecP256r1MLKEM768 and
>   SecP384r1MLKEM1024 among them) and every signature scheme a server key makes, RFC 8448's
>   flights octet for octet, against OpenSSL (SslStream, `openssl s_client`) and a client of the
>   tests' own; and client authentication, in the handshake (`HTTPASM_TLS_CLIENT_AUTH_*`) and
>   after it (`httpasm_tls13_request_certificate`): every kind of client key verified, the chain
>   handed to the caller by `httpasm_tls13_peer_certificates`, whose trust is the caller's until
>   M3's validation.
>
> [docs/DESIGN.md](docs/DESIGN.md) holds the decisions, the architecture and the milestones;
> [benchmarks/](benchmarks/README.md) holds the measurements.

## How it is built

- **From the official documents.** `specs/` pins the RFC Editor's files by SHA-256 and extracts
  every MUST, SHOULD and MAY into [specs/requirements.tsv](specs/requirements.tsv): 3,895
  requirements and 102 grammar blocks from HTTP's RFCs (9110-9114, 9204, 7541, 6585, 9000-9002),
  TLS 1.3's (9846 and its extensions), the cryptographic RFCs, the key and certificate formats
  (7468, 5958, 5915, 5480, 8410, 4055, 5280) and ITU-T X.690, whose rows are transcribed by
  hand ([specs/x690.tsv](specs/x690.tsv)): the ITU publishes it free of charge but not for
  redistribution. Each test names the rows it proves: `[Requirement("RFC9110-5.5-5#1")]`. Every row
  of milestone 1's documents is accounted for: proven by a test that names it, or deferred in
  [specs/deferred.tsv](specs/deferred.tsv) with the milestone it belongs to and a reason (a test
  fails on any row that is neither, and on a deferral that has gone stale). Tables
  (HPACK's and QPACK's static tables, the Huffman code, the known fields' perfect hash, the
  status lines) are generated from the same files, and the HPACK tests read RFC 7541's examples
  from the pinned file itself.
- **A sans-I/O core.** The protocol codecs do no I/O: bytes go in, and bytes and events come
  out. Per-core loops drive them, and so can a host's own loop or a test.
- **Shared source, separate code.** HTTP/1.1, HTTP/2 and HTTP/3 share each RFC 9110 rule as one
  NASM macro, assembled into each version's own code, so no hot path checks a version. It costs
  HTTP/1.1 nothing measurable: the full build and an HTTP/1.1-only build use the same CPU time
  per request, closer to each other than two runs of one build are
  ([benchmarks/](benchmarks/README.md)).
- **One C ABI for every consumer.** .NET's standard interfaces come first (an ASP.NET Core
  server, an `HttpClient` handler). C, Python and NASM programs bind to the same
  `libhttpasm.so` (`include/httpasm.h`, `include/httpasm.inc`).
- **Defaults chosen by measurement.** The workers wait on epoll unless asked for io_uring: the
  io_uring backend, as built, cost more CPU per HTTP/1.1 keep-alive request than epoll on
  Linux 5.15 and never less, so it stays an option until a design of it measures faster. Every
  test runs on both ([benchmarks/](benchmarks/README.md), [docs/DESIGN.md](docs/DESIGN.md)
  section 7).

## Layout

| Path | What |
|---|---|
| `src/HttpAsm.Core/` | The core: no I/O, no system calls, no allocation (freestanding): HTTP/1.1, HPACK, HTTP/2's request rules, the shared field rules |
| `src/HttpAsm/` | `libhttpasm.so`: the C ABI, the Linux driver (server, HTTP/2 engine), the client |
| `samples/Hello/` | The smallest complete server: "Hello, World!" over HTTP/1.1 and HTTP/2 |
| `benchmarks/` | The measurements against nginx and h2o, the isolation measurement, and io_uring against epoll |
| `specs/` | The pinned official documents, the registry tool (`specs.cs`), the table generator (`generate.cs`), `requirements.tsv` |
| `tests/HttpAsm.Tests/` | xunit v3 tests through the C ABI, each naming its requirement rows; h2spec |
| `docs/DESIGN.md` | Decisions, architecture, milestones |

## Building and testing

Linux x64 only for now. AsmSdk builds `libhttpasm.so` from Windows, macOS or Linux alike; the
tests run on Linux x64.

```bash
dotnet build HttpAsm.slnx                          # the library, the sample and the tests
tests/run-linux.sh Release                         # every test on Linux: natively, in WSL or in a container
dotnet test --project tests/HttpAsm.Tests          # natively, on Linux x64

dotnet run specs/specs.cs -- extract --check       # the registry matches the pinned documents
dotnet run specs/generate.cs -- --check            # the generated tables match them too
benchmarks/run.sh                                  # HttpAsm, nginx and h2o, side by side (Linux)
benchmarks/bench.sh --quick                        # routines per CPU tier, parsers, rivals (single thread)
tests/coverage/run.sh                              # every block and branch edge the tests run, and the gate
tests/fuzz/run.sh 60                               # each fuzzer for 60 s (clang with libFuzzer, Linux or WSL)
tests/ct/run.sh                                    # constant time: every secret through valgrind's memcheck
tests/ct/dudect.sh                                 # constant time on the hardware: dudect's timing test (local)
```

`tests/ct/` checks that no secret steers the code. `run.sh` builds the ConstantTime
configuration and runs every function of the C ABI that takes a secret under valgrind's memcheck
with the secret marked undefined, at every tier valgrind's CPU offers, and TLS 1.3's server
engine through 13 whole handshakes (its key and every random octet it draws secret; every group,
key kind and suite, client authentication, KeyUpdates, forgeries): a branch, a memory address
or a system call argument that a secret reaches fails it, and a negative control must be caught
first. `dudect.sh` times the Release library on this CPU, every tier it has included: a fixed
special secret against random ones, compared by Welch's t-test. It runs locally, like the
benchmarks, because timing on a shared CI runner is noise.

`tests/fuzz/` holds the coverage-guided fuzzers. Assembly has no compiler instrumentation, so the
coverage instrument's markers go into libFuzzer's extra counters, and the fuzzer steers by the
assembly's own blocks and branch edges. Every input runs at every CPU tier against a guard page,
and each fuzzer checks the parser's invariants: the result's documented forms, pointers inside
the input, and the same result whether the input arrives whole or in reads. The differential
fuzzers compare HttpAsm with nghttp2's HPACK decoder, and with llhttp and picohttpparser for
HTTP/1.1 requests, all pinned by `tests/tools.sh`. Every difference between them is either a bug
or listed with its RFC reason in `tests/fuzz/*.triage`.

`tests/run-linux.sh` fetches h2spec and Intel SDE (each pinned by SHA-256), then:
- **runs the .NET suite at every CPU tier this machine has** (`HTTPASM_CPU=v1`, `v2`, `v3`,
  and `v4` on AVX-512 hardware);
- **runs each tier twice:** on epoll, the default, then with every server asking for io_uring
  (`HTTPASM_TEST_IO=uring`). Where io_uring is known to work (WSL, a Linux host, CI), a server
  that asks for it and falls back to epoll fails the run;
- **runs `tests/native/faults`:** every allocation of a whole server's life failed in turn, 16
  system calls failed for good, and each call of 33 system calls failed alone, each in a child
  that must end by itself (no crash, no hang, no spinning);
  and a server out of descriptors on each backend, which must rest rather than spin, then
  answer the connections that waited;
- **runs `tests/native/floods`** on each backend: 17 published HTTP/2 floods (CVE-2019-9511 to
  9518, rapid reset, CONTINUATION, MadeYouReset, the HPACK bomb), each served or cut with
  ENHANCE_YOUR_CALM as it must be, none costing the server more than 4 times a PING flood's
  CPU per octet, and none growing its heap when the client never reads;
- **runs `tests/native/signals`:** 2,000 client connects under a 100 µs timer signal, all of
  which must connect;
- **runs `tests/native/tiers`:** every multi-version routine at every tier, against an oracle
  and a guard page. It runs natively, then under Intel SDE's AVX-512 emulation when the CPU
  has none, because SDE cannot run the .NET runtime;
- **replays every input the fuzzers kept** (`tests/fuzz/seeds/`, and the minimized corpora in
  `tests/fuzz/corpus/`) with every check of theirs, against the build's own objects
  (`tests/fuzz/replay.sh`). In the coverage run, the replays add their share to the report;
- **requires h2spec's 146 cases to pass.**

`HTTPASM_CPU` caps the library's CPU tier in any program, as `OPENSSL_ia32cap` does for
OpenSSL: `v1` is plain x86-64, and `v3,-vaes` is AVX2 without VAES. It is described in
`include/httpasm.h`.

## License

Apache-2.0. The files under `specs/rfc/` are the RFC Editor's unmodified copies of IETF
documents, under the IETF Trust's legal provisions (BCP 78).
