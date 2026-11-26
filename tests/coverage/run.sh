#!/usr/bin/env bash
# =============================================================================
# run.sh - the coverage run (docs/DESIGN.md section 2: "every block of libhttpasm.so runs under
# the tests, or is listed with the reason it cannot"):
#   1. builds the Coverage configuration (Directory.Build.props): every HttpAsm source goes
#      through tests/coverage/instrument.cs, which marks its blocks and branch edges, and
#      tests/coverage/coverage_rt.asm writes the marks out when a process exits;
#   2. runs everything tests/run-linux.sh runs, against that build: the .NET suite at every CPU
#      tier on both backends, tests/native/fallback, tests/native/tiers natively and under SDE,
#      each process adding its marks to tests/coverage/.dumps/;
#   3. runs tests/coverage/report.cs: a summary per file, every mark that did not run, and the
#      gate against tests/coverage/unreachable.tsv.
#
# Usage: tests/coverage/run.sh [report.cs options: --report-only, --write-unreachable <file>]
#        HTTPASM_RUNNER=wsl|native as for tests/run-linux.sh (docker cannot carry the dumps).
# The SDK's bundled NASM, lld and llvm-ar (restored by any normal build) do the work; their
# paths go to the build in HTTPASM_COVERAGE_NASM, _LLD and _AR.
# Exit status: the report's (0, 1 when the gate fails, 2 on bad input), or the first failing
# step's when the build or the runs fail first. A failing run still gets its report: the marks
# of the processes that did finish are written.
# =============================================================================
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) rid=win-x64; exe=.exe ;;
  *) rid=linux-x64; exe= ;;
esac
packages="${NUGET_PACKAGES:-$HOME/.nuget/packages}"
toolchain="$(ls -d "$packages/asmfoundation.toolchain.$rid/"*/tools 2>/dev/null | sort -V | tail -1)"
[ -n "$toolchain" ] || { echo "run.sh: no AsmFoundation.Toolchain.$rid in $packages: build the solution once first" >&2; exit 2; }
native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
export HTTPASM_COVERAGE_NASM="$(native_path "$toolchain/nasm$exe")"
export HTTPASM_COVERAGE_LLD="$(native_path "$toolchain/lld$exe")"
export HTTPASM_COVERAGE_AR="$(native_path "$toolchain/llvm-ar$exe")"

# The test project builds the core and the library through its reference. (The solution has
# no Coverage configuration of its own; like H1Only, it is built per project.)
# Always from clean: MSBuild cannot see instrument.cs as an input of the objects, so an
# incremental build would keep objects (and maps) a changed instrumenter never saw.
for d in src/HttpAsm.Core src/HttpAsm tests/HttpAsm.Tests; do
  rm -rf "$here/$d/obj/Coverage" "$here/$d/bin/Coverage"
done
echo "run.sh: building the Coverage configuration" >&2
dotnet build "$here/tests/HttpAsm.Tests/HttpAsm.Tests.csproj" -c Coverage -nologo -v q

dumps="$here/tests/coverage/.dumps"
rm -rf "${dumps:?}"
mkdir -p "$dumps"
status=0
HTTPASM_COVERAGE_DIR="$dumps" bash "$here/tests/run-linux.sh" Coverage || status=$?

echo "run.sh: the report" >&2
report=0
dotnet run --file "$here/tests/coverage/report.cs" -- --repo "$(native_path "$here")" --dumps "$(native_path "$dumps")" "$@" || report=$?
[ "$status" -ne 0 ] && exit "$status"
exit "$report"
