#!/usr/bin/env bash
# =============================================================================
# run-linux.sh - HttpAsm's tests on Linux x64, from any host with Docker.
#
# Usage: tests/run-linux.sh [Debug|Release]      (default Debug)
#
# How: the host builds everything (AsmFoundation.Sdk assembles and links libhttpasm.so for
# linux-x64 on Windows, macOS or Linux alike), and the test app runs from its output folder in
# mcr.microsoft.com/dotnet/runtime:10.0. The test app is a portable .NET app whose deps.json
# names runtimes/linux-x64/native/libhttpasm.so, so the same folder runs there unchanged.
#
# Why a container on Windows: libhttpasm.so is a Linux ELF file. The native tests skip
# themselves elsewhere, and HTTPASM_REQUIRE_LINUX=1 makes such a skip a failure here, so this
# run can only pass by running them.
#
# Exit status: the test app's (0 = every test passed).
# =============================================================================
set -euo pipefail

config="${1:-Debug}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

dotnet build "$here/tests/HttpAsm.Tests/HttpAsm.Tests.csproj" -c "$config" -nologo -v q

out="$here/tests/HttpAsm.Tests/bin/$config/net10.0"
# Docker Desktop on Windows needs a Windows path; Git Bash's /k/... form means nothing to it.
if command -v cygpath >/dev/null 2>&1; then
  out="$(cygpath -m "$out")"
fi

# MSYS_NO_PATHCONV keeps Git Bash from rewriting /t into a Windows path.
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$out:/t:ro" -w /t \
  -e HTTPASM_REQUIRE_LINUX=1 -e DOTNET_NOLOGO=1 -e DOTNET_CLI_TELEMETRY_OPTOUT=1 \
  mcr.microsoft.com/dotnet/runtime:10.0 \
  dotnet HttpAsm.Tests.dll
