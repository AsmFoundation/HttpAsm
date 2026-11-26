#!/usr/bin/env bash
# =============================================================================
# build.sh - builds HttpAsm's C programs against a built libhttpasm.so, on Linux:
#   tiers     tests/native/tiers.c: every multi-version routine at every tier, against oracles
#   fallback  tests/native/fallback.c: io_uring refused by seccomp, a server asking for it on epoll
#   signals   tests/native/signals.c: client connects under a 100 us timer signal
#   cpu       tests/native/cpu.c: CPU detection against an independent reading of CPUID/XGETBV
#   faults    tests/native/faults.c: allocations and system calls failed in turn; descriptor
#             exhaustion
#   floods    tests/native/floods.c: the published HTTP/2 floods, each one's outcome, CPU per
#             octet and heap measured
#   micro     benchmarks/micro/micro.c: single-thread measurements of those routines per tier
#
# Usage: tests/native/build.sh [Debug|Release] [output dir]   (default Release, tests/native/bin)
# Prints the output directory. The programs find libhttpasm.so through an RPATH to the build's
# output folder (src/HttpAsm/bin/<config>/libc/linux-x64), so they run without LD_LIBRARY_PATH.
#
# Warnings are errors, as everywhere in HttpAsm. Needs cc (gcc or clang) on the Linux side.
# =============================================================================
set -euo pipefail

config="${1:-Release}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${2:-$here/tests/native/bin}"
lib="$here/src/HttpAsm/bin/$config/libc/linux-x64"
[ -f "$lib/libhttpasm.so" ] || { echo "build.sh: $lib/libhttpasm.so is missing: build $config first" >&2; exit 2; }
mkdir -p "$out"

for source in tests/native/tiers.c tests/native/fallback.c tests/native/signals.c tests/native/cpu.c tests/native/faults.c tests/native/floods.c benchmarks/micro/micro.c; do
  program="$(basename "$source" .c)"
  cc -O2 -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror \
    -I "$here/src/HttpAsm/include" \
    "$here/$source" \
    -L "$lib" -l:libhttpasm.so -Wl,-rpath,"$lib" -lpthread \
    -o "$out/$program"
done
echo "$out"
