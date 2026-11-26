#!/usr/bin/env bash
# =============================================================================
# run.sh - builds HttpAsm's fuzzers and runs each for a while (docs/DESIGN.md section 2:
# coverage-guided fuzzing of every parser).
#
#   1. On the host: the Fuzz configuration (Directory.Build.props), whose objects carry the
#      coverage markers in libFuzzer's __libfuzzer_extra_counters section; and tests/tools.sh,
#      which fetches the differential fuzzers' pinned references (nghttp2, llhttp,
#      picohttpparser).
#   2. On Linux (natively, or in WSL from Windows), per fuzzer, tests/fuzz/one.sh: each
#      tests/fuzz/<name>.c is compiled by clang with libFuzzer, AddressSanitizer and
#      UndefinedBehaviorSanitizer (for the C harness and the references), and linked with the
#      core's objects, libhttpasm.so's cpu_abi.o (the tiers and their constructor) and its
#      references; then run for SECONDS (default 60) on its corpus.
#
# Usage: tests/fuzz/run.sh [seconds per fuzzer] [fuzzer names...]   (default: 60, every fuzzer)
#        tests/fuzz/run.sh merge [fuzzer names...]: no fuzzing; each fuzzer's committed corpus
#        (tests/fuzz/corpus/<name>/) becomes the minimal set of inputs, from it, the working
#        corpus and the seeds, that reaches everything they reach (libFuzzer -merge=1).
#        tests/fuzz/replay.sh replays seeds and corpus as deterministic tests.
#        HTTPASM_RUNNER=wsl|native as for tests/run-linux.sh.
# Corpora: tests/fuzz/seeds/<name>/ (committed seeds) feeds a working corpus outside the
# repository (WSL: ~/.cache/httpasm/fuzz/corpus/<name>; native: tests/fuzz/.work/), which grows
# from run to run. tests/fuzz/<name>.dict, when present, is the fuzzer's dictionary: the words
# the assembly compares against, which libFuzzer cannot see in NASM code.
# Findings: a crash, a leak, a hang (an input over 10 s) or an out-of-memory leaves its input in
# <work>/findings/<time>-<name>-*, and the run prints each in base64, so a CI log alone is
# enough to reproduce it (base64 -d, then ./<name> <file>). Every such input becomes a seed and
# a regression test once the bug is fixed.
# Exit status: 0 when every fuzzer ran its time without a finding; else the first failure's.
# =============================================================================
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
seconds="${1:-60}"
shift || true
fuzzers=("$@")
if [ "${#fuzzers[@]}" -eq 0 ]; then
  # replay.c is the replay driver (replay.sh), not a fuzzer.
  for f in "$here"/tests/fuzz/*.c; do n="$(basename "$f" .c)"; [ "$n" = replay ] || fuzzers+=("$n"); done
fi

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) rid=win-x64; exe=.exe; runner="${HTTPASM_RUNNER:-wsl}" ;;
  *) rid=linux-x64; exe=; runner="${HTTPASM_RUNNER:-native}" ;;
esac
packages="${NUGET_PACKAGES:-$HOME/.nuget/packages}"
toolchain="$(ls -d "$packages/asmfoundation.toolchain.$rid/"*/tools 2>/dev/null | sort -V | tail -1)"
[ -n "$toolchain" ] || { echo "run.sh: no AsmFoundation.Toolchain.$rid in $packages: build the solution once first" >&2; exit 2; }
native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
export HTTPASM_COVERAGE_NASM="$(native_path "$toolchain/nasm$exe")"
export HTTPASM_COVERAGE_LLD="$(native_path "$toolchain/lld$exe")"
export HTTPASM_COVERAGE_AR="$(native_path "$toolchain/llvm-ar$exe")"

# Always from clean, as for coverage: MSBuild cannot see instrument.cs as an input.
for d in src/HttpAsm.Core src/HttpAsm; do rm -rf "${here:?}/$d/obj/Fuzz" "${here:?}/$d/bin/Fuzz"; done
echo "run.sh: building the Fuzz configuration" >&2
dotnet build "$here/src/HttpAsm/HttpAsm.asmproj" -c Fuzz -nologo -v q
bash "$here/tests/tools.sh" >/dev/null

# lpath PATH: the path as the Linux side sees it (K:/source/... is /mnt/k/source/... in WSL).
lpath() {
  local p="$1" drive
  if [ "$runner" != wsl ]; then printf '%s' "$p"; return; fi
  p="$(native_path "$p")"
  drive="$(printf '%s' "${p:0:1}" | tr 'A-Z' 'a-z')"
  printf '/mnt/%s%s' "$drive" "${p:2}"
}
# on_linux COMMAND: runs a shell command on the Linux side (in WSL, or natively); its exit status
# is the command's. The command holds no double quotes: from Git Bash it reaches wsl.exe through
# a Windows command line, whose quoting rules differ from bash's; single quotes pass unchanged.
on_linux() {
  if [ "$runner" = wsl ]; then wsl.exe -d "${HTTPASM_WSL_DISTRO:-Ubuntu}" -e bash -lc "$1"; else bash -c "$1"; fi
}

repo="$(lpath "$here")"
# The working directory stays outside the repository in WSL: /mnt/k is slow for libFuzzer's
# many small corpus files, and WSL's /tmp is emptied when the VM idles, so ~/.cache keeps the
# corpora between runs.
work='$HOME/.cache/httpasm/fuzz'
[ "$runner" = native ] && work="$here/tests/fuzz/.work"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
status=0
for name in "${fuzzers[@]}"; do
  echo "run.sh: $name, $seconds s" >&2
  # one.sh builds and runs it (its header says how). A finding's input goes to findings/ under
  # this run's time stamp, and only this run's are printed, so older ones never pose as new.
  # The command is one.sh alone, with no set -e around it: WSL's shell is a login shell
  # (bash -l), whose exit runs ~/.bash_logout, and Ubuntu's ends in a failing test
  # ([ -x /usr/bin/clear_console ]); under set -e that failure replaced the status, so "exit 0"
  # ended with 1 and "exit 3" with 1 (measured, Ubuntu 24.04's bash 5.2). Without set -e the
  # login shell ends with one.sh's own status.
  on_linux "bash '$repo/tests/fuzz/one.sh' $work $name $seconds $stamp" || { code=$?; [ "$status" -ne 0 ] || status=$code; }
done
exit "$status"
