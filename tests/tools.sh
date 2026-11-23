#!/usr/bin/env bash
# =============================================================================
# tools.sh - fetches the external test tools, each pinned by version and SHA-256, into
# tests/.tools/ (not in git), and prints the directory.
#
#   h2spec 2.6.0 (linux amd64): HTTP/2 conformance, 146 cases. Http2Tests.PassesH2spec runs it
#   when HTTPASM_H2SPEC names the binary; tests/run-linux.sh and CI set that.
#
# A download whose hash differs is deleted and the script fails: a changed release must be
# reviewed and pinned again here, never trusted silently. Already-fetched tools are re-checked
# and not downloaded again.
#
# Usage: tests/tools.sh            (prints the tools directory)
# =============================================================================
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tools="$here/.tools"
mkdir -p "$tools"

# fetch NAME URL SHA256: downloads URL to tools/NAME unless a file with that hash is there.
fetch() {
  local name="$1" url="$2" sum="$3" file="$tools/$1"
  if [ -f "$file" ] && [ "$(sha256sum "$file" | cut -d' ' -f1)" = "$sum" ]; then
    return 0
  fi
  curl -fsSL -o "$file.part" "$url"
  if [ "$(sha256sum "$file.part" | cut -d' ' -f1)" != "$sum" ]; then
    rm -f "$file.part"
    echo "tools.sh: $name from $url does not have the pinned SHA-256 $sum" >&2
    exit 1
  fi
  mv "$file.part" "$file"
}

fetch h2spec_linux_amd64.tar.gz \
  https://github.com/summerwind/h2spec/releases/download/v2.6.0/h2spec_linux_amd64.tar.gz \
  157ee0de702e01ad40e752dbf074b366027e550c8e7504f9450da2809e279318
if [ ! -x "$tools/h2spec" ] || [ "$tools/h2spec_linux_amd64.tar.gz" -nt "$tools/h2spec" ]; then
  tar -xzf "$tools/h2spec_linux_amd64.tar.gz" -C "$tools" h2spec
  chmod +x "$tools/h2spec"
  touch "$tools/h2spec"
fi

echo "$tools"
