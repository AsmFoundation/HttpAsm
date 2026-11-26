#!/usr/bin/env bash
# =============================================================================
# run-linux.sh - HttpAsm's tests on Linux x64, from any host: the .NET suite at every CPU tier
# on both I/O backends, and the native tier program natively and under Intel SDE.
#
# Usage: tests/run-linux.sh [Debug|Release] [test-app arguments...]   (default Debug)
#        HTTPASM_RUNNER=docker|wsl|native tests/run-linux.sh ...       (default: the first that works)
#        HTTPASM_TEST_CPUS="v1 v3" tests/run-linux.sh ...              (tiers; default "v1 v2 v3 v4")
#
# How: the host builds everything (AsmFoundation.Sdk assembles and links libhttpasm.so for
# linux-x64 on Windows, macOS or Linux alike), then the test app runs from its output folder on
# Linux. The test app is a portable .NET app whose deps.json names
# runtimes/linux-x64/native/libhttpasm.so, so the same folder runs unchanged in either place:
#   native  on a Linux x64 host: the folder itself
#   docker  mcr.microsoft.com/dotnet/aspnet:10.0 (ASP.NET Core: ClientTests runs Kestrel), the
#           folder mounted read-only (Docker Desktop on Windows; its default seccomp profile
#           refuses io_uring, so the io_uring run's servers fall back to epoll there). It has no
#           C compiler and no SDE: the tier program does not run there, and the run says so and
#           fails (exit 3), so a partial run never passes for a whole one
#   wsl     the WSL distribution $HTTPASM_WSL_DISTRO (default Ubuntu), with the .NET 10 runtime
#           in ~/.dotnet and a C compiler. WSL needs no Docker Desktop, and its kernel allows
#           io_uring.
#
# What runs (docs/DESIGN.md section 2, "every tier and both backends"):
#   1. The .NET suite once per tier and backend: HTTPASM_CPU=<tier> caps the library's choice
#      (cpu.inc), and each tier runs on epoll and then with every server asking for io_uring.
#      A tier above what the CPU has would only repeat the best one it has: v4 on a CPU without
#      AVX-512 is left to step 2, which can emulate it, since the .NET runtime hangs under SDE.
#   2. tests/native/fallback: a seccomp filter refuses io_uring_setup, as Docker's does; a server
#      asking for io_uring must run on epoll and serve. Then tests/native/tiers: every
#      multi-version routine at every tier in one process, against oracles and guard pages;
#      natively, and under Intel SDE as a Sapphire Rapids (AVX-512) when the CPU has no AVX-512
#      of its own.
#
# Why Linux at all: libhttpasm.so is a Linux ELF file. The native tests skip themselves
# elsewhere, and HTTPASM_REQUIRE_LINUX=1 makes such a skip a failure here, so this run can only
# pass by running them.
#
# External tools: tests/tools.sh fetches them (pinned by SHA-256) into tests/.tools/: h2spec
# (HTTPASM_H2SPEC, with HTTPASM_REQUIRE_H2SPEC=1: Http2Tests.PassesH2spec must run its 146
# cases) and Intel SDE (unpacked into ~/.cache/httpasm/sde inside WSL).
#
# Exit status: 0 when every run passes, else the first failing run's (3: a docker run, which
# cannot run step 2).
# =============================================================================
set -euo pipefail

config="${1:-Debug}"
shift || true
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cpus="${HTTPASM_TEST_CPUS:-v1 v2 v3 v4}"
sde_archive=sde-external-10.13.1-2026-07-28-lin.tar.xz

dotnet build "$here/tests/HttpAsm.Tests/HttpAsm.Tests.csproj" -c "$config" -nologo -v q
tools="$(bash "$here/tests/tools.sh")"

out="$here/tests/HttpAsm.Tests/bin/$config/net10.0"
runner="${HTTPASM_RUNNER:-}"
if [ -z "$runner" ]; then
  if [ "$(uname -s)" = "Linux" ]; then
    runner=native
  elif docker info >/dev/null 2>&1; then
    runner=docker
  else
    runner=wsl
  fi
fi
case "$runner" in native|docker|wsl) ;; *) echo "run-linux.sh: HTTPASM_RUNNER must be docker, wsl or native" >&2; exit 2;; esac

# lpath PATH: the path as the Linux side sees it (K:/source/... is /mnt/k/source/... in WSL).
lpath() {
  local p="$1" drive
  if [ "$runner" != wsl ]; then printf '%s' "$p"; return; fi
  if command -v cygpath >/dev/null 2>&1; then p="$(cygpath -m "$p")"; fi
  drive="$(printf '%s' "${p:0:1}" | tr 'A-Z' 'a-z')"
  printf '/mnt/%s%s' "$drive" "${p:2}"
}

# on_linux COMMAND: runs a shell command on the Linux side (natively or in WSL; not docker).
on_linux() {
  if [ "$runner" = wsl ]; then
    wsl.exe -d "${HTTPASM_WSL_DISTRO:-Ubuntu}" -e bash -lc "$1"
  else
    bash -c "$1"
  fi
}

# Whether the Linux side's CPU has AVX-512 (BW is the part every v4 routine relies on).
avx512=0
if [ "$runner" = docker ]; then
  docker run --rm mcr.microsoft.com/dotnet/aspnet:10.0 grep -qw avx512bw /proc/cpuinfo && avx512=1 || true
else
  on_linux "grep -qw avx512bw /proc/cpuinfo" && avx512=1 || true
fi

# run_suite IO CPU [args]: the .NET suite once. IO: "epoll" (the default) or "uring" (every
# server asks for io_uring: HTTPASM_TEST_IO=uring). WSL's and a Linux host's kernels allow
# io_uring, so a server asking for it and silently falling back to epoll fails either run there
# (HTTPASM_REQUIRE_URING=1); Docker's seccomp refuses it, so there they fall back by design.
run_suite() {
  local io="$1" cpu="$2" require_uring=0 test_io=""
  shift 2
  if [ "$io" = uring ]; then test_io=uring; fi
  if [ "$runner" != docker ]; then require_uring=1; fi
  echo "run-linux.sh: the suite at $cpu, servers on $io" >&2
  case "$runner" in
    native|wsl)
      local dotnet=dotnet
      if [ "$runner" = wsl ]; then dotnet='$HOME/.dotnet/dotnet'; fi
      on_linux "cd '$(lpath "$out")' && HTTPASM_CPU=$cpu HTTPASM_REQUIRE_LINUX=1 HTTPASM_H2SPEC='$(lpath "$tools")/h2spec' HTTPASM_REQUIRE_H2SPEC=1 HTTPASM_REQUIRE_URING=$require_uring HTTPASM_TEST_IO=$test_io DOTNET_NOLOGO=1 $dotnet HttpAsm.Tests.dll $*"
      ;;
    docker)
      # Docker Desktop on Windows needs a Windows path; Git Bash's /k/... form means nothing to it.
      local dout="$out" dtools="$tools"
      if command -v cygpath >/dev/null 2>&1; then dout="$(cygpath -m "$out")"; dtools="$(cygpath -m "$tools")"; fi
      # MSYS_NO_PATHCONV keeps Git Bash from rewriting /t into a Windows path.
      MSYS_NO_PATHCONV=1 docker run --rm \
        -v "$dout:/t:ro" -w /t -v "$dtools:/tools:ro" \
        -e HTTPASM_CPU="$cpu" -e HTTPASM_REQUIRE_LINUX=1 -e DOTNET_NOLOGO=1 -e DOTNET_CLI_TELEMETRY_OPTOUT=1 \
        -e HTTPASM_H2SPEC=/tools/h2spec -e HTTPASM_REQUIRE_H2SPEC=1 \
        -e HTTPASM_REQUIRE_URING="$require_uring" -e HTTPASM_TEST_IO="$test_io" \
        mcr.microsoft.com/dotnet/aspnet:10.0 \
        dotnet HttpAsm.Tests.dll "$@"
      ;;
  esac
}

# run_native: the native programs. tests/native/fallback (a seccomp filter refuses io_uring;
# a server asking for it must run on epoll and serve), then tests/native/tiers natively, and
# under SDE when the CPU has no AVX-512. The SDE run must report v4 among its tiers, or it
# proved nothing about the AVX-512 versions.
run_native() {
  local repo bin sde
  repo="$(lpath "$here")"
  bin='$HOME/.cache/httpasm/native'
  [ "$runner" = native ] && bin="$here/tests/native/bin"
  sde='$HOME/.cache/httpasm/sde'
  [ "$runner" = native ] && sde="$tools/sde"
  echo "run-linux.sh: tests/native/fallback and tests/native/tiers, natively" >&2
  on_linux "set -e; b=$bin; bash '$repo/tests/native/build.sh' $config \$b >/dev/null; \$b/fallback; \$b/tiers"
  if [ "$avx512" = 0 ]; then
    echo "run-linux.sh: tests/native/tiers under Intel SDE (Sapphire Rapids: AVX-512)" >&2
    # The output is captured whole, so the program's own exit status is kept (a pipe into grep
    # would report grep's), and only then searched for the v4 tier.
    on_linux "set -e; s=$sde; if [ ! -x \$s/sde64 ]; then mkdir -p \$s; tar -xJf '$(lpath "$tools")/$sde_archive' -C \$s --strip-components=1; fi; \
      o=\$(\$s/sde64 -spr -- $bin/tiers); echo \"\$o\"; \
      printf '%s\n' \"\$o\" | grep -Eq ' v4=0x[0-9a-f]*7$' || { echo 'run-linux.sh: the SDE run did not reach v4' >&2; exit 1; }"
  fi
}

# Every tier on both backends, then the tier program; the exit status is the first failure's.
status=0
note() { local code=$?; [ "$status" -ne 0 ] || status=$code; }
for cpu in $cpus; do
  if [ "$cpu" = v4 ] && [ "$avx512" = 0 ]; then
    echo "run-linux.sh: no AVX-512 on this CPU: v4 is proven by tests/native/tiers under SDE" >&2
    continue
  fi
  run_suite epoll "$cpu" "$@" || note
  run_suite uring "$cpu" "$@" || note
done
if [ "$runner" = docker ]; then
  echo "run-linux.sh: INCOMPLETE - the docker runner has no C compiler or SDE for tests/native; use the wsl or native runner" >&2
  [ "$status" -ne 0 ] || status=3
else
  run_native || note
fi
exit "$status"
