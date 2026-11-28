#!/usr/bin/env bash
# =============================================================================
# run.sh - the constant-time check: every function of the C ABI that takes a secret runs under
# valgrind's memcheck with its secrets marked undefined (tests/native/ct.c), and so does TLS 1.3's
# server engine through whole handshakes with a client of ct.c's own, against the
# ConstantTime build (Directory.Build.props: HA_DECLASSIFY's sites, the few values computed from a
# secret whose outcome is public by design, marked defined; and ADX taken with BMI2, which
# valgrind's CPU executes but does not report). memcheck reports every branch, memory address or
# system call argument that a secret reaches: any report fails the check, named by
# tests/ct/where.py (valgrind itself names only the C ABI's functions).
#
# What memcheck cannot see, and why that is acceptable here: the SHA extensions (valgrind raises
# SIGILL on sha256rnds2: its CPU does not offer them, so SHA-256's v1 runs instead) and VAES
# (likewise: AES-GCM's AES-NI version runs), and AVX-512 (v4). Those versions are straight-line
# instruction sequences whose only branches are on lengths; tests/native/tiers proves them equal
# to v1 at every tier.
#
# Usage: tests/ct/run.sh          (on Linux, or from Windows through WSL as tests/run-linux.sh)
# Needs valgrind (Ubuntu: apt-get install valgrind), cc, python3, and the .NET SDK to build.
# Exit status: 0 when memcheck reports nothing; 1 when it reports something (printed, named) or a
# call failed; 2 on a setup error.
# =============================================================================
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$here" || exit 2
command -v valgrind >/dev/null || { echo "ct/run.sh: valgrind is not installed (apt-get install valgrind)" >&2; exit 2; }

out="$here/tests/native/bin/ct"   # (bin/ is ignored by git)
mkdir -p "$out"
echo "ct/run.sh: building the ConstantTime configuration" >&2
# The build's log stays beside the program (not in /tmp, which two checkouts would share); only
# its end is printed, on a failure. Transitive project references are off: the core is the
# library's direct reference, and the SDK's IncludeTransitiveProjectReferences once added it a
# second time to this configuration's build (measured 2026-11-28, in WSL after a Windows-side
# build of another configuration), so every core object reached the link twice (lld: duplicate
# symbol).
dotnet build src/HttpAsm/HttpAsm.asmproj -c ConstantTime -nologo -v q -p:DisableTransitiveProjectReferences=true \
  > "$out/build.log" 2>&1 || { tail -20 "$out/build.log"; exit 2; }
lib="$here/src/HttpAsm/bin/ConstantTime/libc/linux-x64"
cc -O2 -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -I src/HttpAsm/include tests/native/ct.c \
  -L "$lib" -l:libhttpasm.so -Wl,-rpath,"$lib" -lpthread -o "$out/ct" || exit 2

report="$out/memcheck.txt"
# The negative control first: a branch on a secret octet (ct --control) must be reported, or a
# clean run below would prove nothing (the client requests not reaching memcheck, say).
valgrind --error-exitcode=1 "$out/ct" --control > "$out/control.txt" 2>&1
if [ $? -ne 1 ] || ! grep -q 'Conditional jump or move depends on uninitialised' "$out/control.txt"; then
  echo "ct/run.sh: the negative control (a branch on a secret) was not reported: the check sees nothing" >&2
  cat "$out/control.txt" >&2
  exit 2
fi
echo "ct/run.sh: the negative control's secret branch was reported, as it must be" >&2
echo "ct/run.sh: tests/native/ct under valgrind's memcheck (secrets undefined)" >&2
valgrind --error-exitcode=1 --num-callers=2 "$out/ct" > "$report" 2>&1
status=$?
grep -E '^ct:' "$report" >&2
grep -E 'ERROR SUMMARY' "$report" >&2
named="$(python3 tests/ct/where.py "$report" "$lib/libhttpasm.so")" || exit 2
if [ "$status" -ne 0 ] || [ -n "$named" ]; then
  echo "ct/run.sh: memcheck reported a secret reaching a branch, an address or a system call:" >&2
  echo "$named" >&2
  echo "(the whole report: $report)" >&2
  exit 1
fi
echo "ct/run.sh: no secret reached a branch, an address or a system call" >&2
exit 0
