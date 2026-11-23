# HttpAsm

A complete HTTP networking library in x86-64 assembly: HTTP/1.1, HTTP/2 and HTTP/3, with QUIC
and TLS of its own, as both client and server. It is built from the official documents, and
maximum performance is its guiding value. Part of the [AsmFoundation](https://github.com/AsmFoundation)
family, next to [KvAsm](https://github.com/AsmFoundation/KvAsm) and
[GrpcAsm](https://github.com/AsmFoundation/GrpcAsm). It builds with
[AsmSdk](https://asmfoundation.github.io/AsmSdk/).

> **Status: in development; nothing is released.** The design is settled for the first
> milestone. The code so far is the requirement registry, the first shared rules (tokens and
> field values), the C ABI and its tests. [docs/DESIGN.md](docs/DESIGN.md) holds the decisions,
> the architecture and the milestones.

## How it is built

- **From the official documents.** `specs/` pins the RFC Editor's files by SHA-256 and extracts
  every MUST, SHOULD and MAY into [specs/requirements.tsv](specs/requirements.tsv): today 2,542
  requirements and 102 grammar blocks from RFC 9110-9114, 9204, 7541, 8446 and 9000-9002. Each
  test names the rows it proves: `[Requirement("RFC9110-5.5-5#1")]`.
- **A sans-I/O core.** The protocol engines do no I/O: bytes go in, and bytes and events come
  out. Per-core loops drive them, and so can a host's own loop or a test.
- **Shared source, separate code.** HTTP/1.1, HTTP/2 and HTTP/3 share each RFC 9110 rule as one
  NASM macro, assembled into each version's own code, so no hot path checks a version.
- **One C ABI for every consumer.** .NET's standard interfaces come first (an ASP.NET Core
  server, an `HttpClient` handler). C, Python and NASM programs bind to the same
  `libhttpasm.so`.

## Layout

| Path | What |
|---|---|
| `src/HttpAsm.Core/` | The core: no I/O, no system calls, no allocation (freestanding) |
| `src/HttpAsm/` | `libhttpasm.so`: the C ABI (`include/httpasm.h`, `include/httpasm.inc`); the Linux driver from M1 on |
| `specs/` | The pinned official documents, the registry tool (`specs.cs`) and `requirements.tsv` |
| `tests/HttpAsm.Tests/` | xunit v3 tests through the C ABI, each naming its requirement rows |
| `docs/DESIGN.md` | Decisions, architecture, milestones |

## Building and testing

Linux x64 only for now. AsmSdk builds `libhttpasm.so` from Windows, macOS or Linux alike; the
tests run on Linux x64.

```bash
dotnet build HttpAsm.slnx                          # the library and the tests
tests/run-linux.sh                                 # every test, in a Linux container (any host with Docker)
dotnet test --project tests/HttpAsm.Tests          # natively, on Linux x64

dotnet run specs/specs.cs -- fetch                 # re-download the pinned documents, check their hashes
dotnet run specs/specs.cs -- extract --check       # the registry matches the pinned documents
dotnet run specs/specs.cs -- stats                 # requirements per document and keyword
```

## License

Apache-2.0. The files under `specs/rfc/` are the RFC Editor's unmodified copies of IETF
documents, under the IETF Trust's legal provisions (BCP 78).
