#!/usr/bin/env bash
# =============================================================================
# tools.sh - fetches the external test tools, each pinned by version and SHA-256, into
# tests/.tools/ (not in git), and prints the directory.
#
#   h2spec 2.6.0 (linux amd64): HTTP/2 conformance, 146 cases. Http2Tests.PassesH2spec runs it
#   when HTTPASM_H2SPEC names the binary; tests/run-linux.sh and CI set that.
#   Intel SDE 10.13.1 (2026-07-28, linux): Intel's Software Development Emulator, which runs a
#   program as a CPU with newer instructions would (AVX-512 among them). tests/run-linux.sh
#   runs the suite's v4 tier under it on a CPU without AVX-512, so the AVX-512 versions are
#   proven even where they cannot run natively. Free for any use under the Intel Simplified
#   Software License; the SHA-256 below is the one Intel publishes on its download page. The
#   archive holds symbolic links, so it is unpacked only on Linux: here when this script runs
#   on Linux (into .tools/sde/), and by run-linux.sh inside WSL otherwise.
#   nghttp2, llhttp and picohttpparser sources: the differential fuzzers' references (below).
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

sde_archive=sde-external-10.13.1-2026-07-28-lin.tar.xz
fetch "$sde_archive" \
  "https://downloadmirror.intel.com/924984/$sde_archive" \
  94e97d623fec54385686e1e7ba65ebc9941748c05ee451423948334892bf2b50
if [ "$(uname -s)" = "Linux" ] && { [ ! -x "$tools/sde/sde64" ] || [ "$tools/$sde_archive" -nt "$tools/sde/sde64" ]; }; then
  rm -rf "${tools:?}/sde"
  mkdir -p "$tools/sde"
  tar -xJf "$tools/$sde_archive" -C "$tools/sde" --strip-components=1
  touch "$tools/sde/sde64"
fi

# The reference implementations the differential fuzzers compare against (tests/fuzz/, docs/
# DESIGN.md phase H step 2): sources only, compiled into the fuzzers by tests/fuzz/run.sh, never
# into HttpAsm. Each is pinned like the tools above, so a difference found today reproduces
# against the same code later.
#   nghttp2 1.71.0 (2026-11-02), the release tarball: its HPACK inflater (lib/nghttp2_hd*.c).
#   llhttp 9.4.4 (2026-11-13), Node.js's HTTP/1.1 parser: the release branch's generated C,
#   file by file at the tag's commit 8164852 (raw files are byte-stable; generated archives
#   are not promised to be).
#   picohttpparser at dd573d8 (2026-10-27), h2o's HTTP/1.1 parser: its two files.
fetch nghttp2-1.71.0.tar.xz \
  https://github.com/nghttp2/nghttp2/releases/download/v1.71.0/nghttp2-1.71.0.tar.xz \
  c0f55121d88650e4b9227aec28cebaf664d2417ca60fe70be0f8d38829f52116
llhttp=https://raw.githubusercontent.com/nodejs/llhttp/816485216511b86459b2e6478190e14c38c14891
mkdir -p "$tools/llhttp-9.4.4" "$tools/picohttpparser-dd573d8"
fetch llhttp-9.4.4/llhttp.h "$llhttp/include/llhttp.h" 52a7011f979b31f761403c1a333bf7fc26dc70f5745d8488eed1609c92097100
fetch llhttp-9.4.4/llhttp.c "$llhttp/src/llhttp.c" f3ef756529b7444630717fa5540d4a1c9a1256874bda823c49c5a99c37f89429
fetch llhttp-9.4.4/api.c "$llhttp/src/api.c" 0f8590206fe2f264db2825401b5fb856b979ee1363dc88b06f36dc9577afb941
fetch llhttp-9.4.4/http.c "$llhttp/src/http.c" a1f2b23168f8e9b5bfa464c89027d3ca259fc649ae3d7e72bfff997d1aeb5d72
pico=https://raw.githubusercontent.com/h2o/picohttpparser/dd573d8fa9264c646a400e96ce9f07dea6f156e4
fetch picohttpparser-dd573d8/picohttpparser.c "$pico/picohttpparser.c" 8aacb701e60a3a5c600f51845d9554463773eafed88f9c4f47472ed5dac6a942
fetch picohttpparser-dd573d8/picohttpparser.h "$pico/picohttpparser.h" 1fc9074dd12418b2b91e55ef3a8279bccf8d3577b790dea6f2f908ab2a157f1c

# The official test vectors of M2's crypto (docs/DESIGN.md M2 step 1), pinned like the rest.
#   NIST CAVP (the Cryptographic Algorithm Validation Program's response files), each archive
#   unpacked into cavp/: shabytetestvectors.zip has SHA-1 and SHA-2's ShortMsg, LongMsg and
#   Monte files (byte-oriented messages, the ones a TLS library meets). Sha256Tests reads
#   SHA256*.rsp.
mkdir -p "$tools/cavp"
fetch cavp/shabytetestvectors.zip \
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip \
  929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8
if [ ! -f "$tools/cavp/shabytetestvectors/SHA256Monte.rsp" ] || [ "$tools/cavp/shabytetestvectors.zip" -nt "$tools/cavp/shabytetestvectors/SHA256Monte.rsp" ]; then
  unzip -q -o "$tools/cavp/shabytetestvectors.zip" -d "$tools/cavp"
  touch "$tools/cavp/shabytetestvectors/SHA256Monte.rsp"
fi
#   hmactestvectors.zip: HMAC.rsp, every hash's MACs with keys shorter and longer than a block
#   and truncated tags; HmacTests reads its [L=32] (SHA-256) section.
fetch cavp/hmactestvectors.zip \
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip \
  418c3837d38f249d6668146bd0090db24dd3c02d2e6797e3de33860a387ae4bd
if [ ! -f "$tools/cavp/hmac/HMAC.rsp" ] || [ "$tools/cavp/hmactestvectors.zip" -nt "$tools/cavp/hmac/HMAC.rsp" ]; then
  unzip -q -o "$tools/cavp/hmactestvectors.zip" -d "$tools/cavp/hmac"
  touch "$tools/cavp/hmac/HMAC.rsp"
fi
#   Project Wycheproof (C2SP/wycheproof) at commit 65ca494 (2026-11-11), its testvectors_v1 files
#   one by one into wycheproof/: edge cases the official vectors leave out (tags cut short or
#   flipped, empty and long keys, HKDF's length limit), each test marked valid or invalid.
wycheproof=https://raw.githubusercontent.com/C2SP/wycheproof/65ca494727a52944c204441c860b039e6786b99b/testvectors_v1
mkdir -p "$tools/wycheproof"
fetch wycheproof/hmac_sha256_test.json "$wycheproof/hmac_sha256_test.json" 2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f
fetch wycheproof/hkdf_sha256_test.json "$wycheproof/hkdf_sha256_test.json" bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e

echo "$tools"
