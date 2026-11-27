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
#   KAT_AES.zip: AESAVS's known-answer files for every mode; AesTests reads the ECB ones of
#   AES-128 and AES-256 (GFSbox, KeySbox, VarKey, VarTxt): the block cipher alone.
fetch cavp/KAT_AES.zip \
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip \
  a203b16c9246b2ebae31dee5de21a606be80cf78ceabaca37150236fa098eb60
if [ ! -f "$tools/cavp/aes/ECBVarTxt256.rsp" ] || [ "$tools/cavp/KAT_AES.zip" -nt "$tools/cavp/aes/ECBVarTxt256.rsp" ]; then
  unzip -q -o "$tools/cavp/KAT_AES.zip" -d "$tools/cavp/aes"
  touch "$tools/cavp/aes/ECBVarTxt256.rsp"
fi
#   gcmtestvectors.zip: GCM's encrypt (external IV) and decrypt files for 128-, 192- and 256-bit
#   keys; AesGcmTests reads the 96-bit-IV records of the 128 and 256 ones (every tag length).
fetch cavp/gcmtestvectors.zip \
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip \
  f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023
if [ ! -f "$tools/cavp/gcm/gcmDecrypt256.rsp" ] || [ "$tools/cavp/gcmtestvectors.zip" -nt "$tools/cavp/gcm/gcmDecrypt256.rsp" ]; then
  unzip -q -o "$tools/cavp/gcmtestvectors.zip" -d "$tools/cavp/gcm"
  touch "$tools/cavp/gcm/gcmDecrypt256.rsp"
fi
#   ecccdhtestvectors.zip: the KAS ECC CDH primitive (SP 800-56A's shared-secret computation)
#   for every curve; P256Tests reads its [P-256] records (a key pair and a peer's point each).
fetch cavp/ecccdhtestvectors.zip \
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhtestvectors.zip \
  5fff092551f2d72e89a3d9362711878708f9a14b502f0dfae819649105b0ea39
if [ ! -f "$tools/cavp/ecccdh/KAS_ECC_CDH_PrimitiveTest.txt" ] || [ "$tools/cavp/ecccdhtestvectors.zip" -nt "$tools/cavp/ecccdh/KAS_ECC_CDH_PrimitiveTest.txt" ]; then
  unzip -q -o "$tools/cavp/ecccdhtestvectors.zip" -d "$tools/cavp/ecccdh"
  touch "$tools/cavp/ecccdh/KAS_ECC_CDH_PrimitiveTest.txt"
fi
#   186-4ecdsatestvectors.zip: FIPS 186-4's ECDSA files (KeyPair, PKV, SigGen with each k,
#   SigVer), unpacked flat into cavp/ecdsa/; P256Tests reads every P-256 record.
fetch cavp/186-4ecdsatestvectors.zip \
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip \
  fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752
if [ ! -f "$tools/cavp/ecdsa/SigVer.rsp" ] || [ "$tools/cavp/186-4ecdsatestvectors.zip" -nt "$tools/cavp/ecdsa/SigVer.rsp" ]; then
  unzip -q -o -j "$tools/cavp/186-4ecdsatestvectors.zip" -d "$tools/cavp/ecdsa"
  touch "$tools/cavp/ecdsa/SigVer.rsp"
fi
#   sha-3bytetestvectors.zip and shakebytetestvectors.zip: FIPS 202's byte-oriented files (SHA3VS),
#   unpacked flat into cavp/sha3/ and cavp/shake/; Sha3Tests reads SHA3-224 to SHA3-512's
#   ShortMsg, LongMsg and Monte, and SHAKE128 and SHAKE256's ShortMsg, LongMsg, VariableOut and
#   Monte.
fetch cavp/sha-3bytetestvectors.zip \
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip \
  cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c
if [ ! -f "$tools/cavp/sha3/SHA3_512Monte.rsp" ] || [ "$tools/cavp/sha-3bytetestvectors.zip" -nt "$tools/cavp/sha3/SHA3_512Monte.rsp" ]; then
  unzip -q -o -j "$tools/cavp/sha-3bytetestvectors.zip" -d "$tools/cavp/sha3"
  touch "$tools/cavp/sha3/SHA3_512Monte.rsp"
fi
fetch cavp/shakebytetestvectors.zip \
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip \
  debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7
if [ ! -f "$tools/cavp/shake/SHAKE256Monte.rsp" ] || [ "$tools/cavp/shakebytetestvectors.zip" -nt "$tools/cavp/shake/SHAKE256Monte.rsp" ]; then
  unzip -q -o -j "$tools/cavp/shakebytetestvectors.zip" -d "$tools/cavp/shake"
  touch "$tools/cavp/shake/SHAKE256Monte.rsp"
fi
#   186-3rsatestvectors.zip: FIPS 186-3's RSA files, unpacked flat into cavp/rsa/; RsaTests reads
#   the PKCS#1 v1.5 and PSS ones: SigVer15 and SigVerPSS (valid and invalid signatures, 1024 to
#   3072 bits, SHA-1 to SHA-512), SigGen15 and SigGenPSS (signatures to verify, 2048 and 3072).
fetch cavp/186-3rsatestvectors.zip \
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3rsatestvectors.zip \
  8405aeb3572a4f98ed4b1a3ccb3f2f49e725462dd28ec4759d6a15d88855d19c
if [ ! -f "$tools/cavp/rsa/SigVerPSS_186-3.rsp" ] || [ "$tools/cavp/186-3rsatestvectors.zip" -nt "$tools/cavp/rsa/SigVerPSS_186-3.rsp" ]; then
  unzip -q -o -j "$tools/cavp/186-3rsatestvectors.zip" -d "$tools/cavp/rsa"
  touch "$tools/cavp/rsa/SigVerPSS_186-3.rsp"
fi
#   Project Wycheproof (C2SP/wycheproof) at commit 65ca494 (2026-11-11), its testvectors_v1 files
#   one by one into wycheproof/: edge cases the official vectors leave out (tags cut short or
#   flipped, empty and long keys, HKDF's length limit), each test marked valid or invalid.
wycheproof=https://raw.githubusercontent.com/C2SP/wycheproof/65ca494727a52944c204441c860b039e6786b99b/testvectors_v1
mkdir -p "$tools/wycheproof"
fetch wycheproof/hmac_sha256_test.json "$wycheproof/hmac_sha256_test.json" 2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f
fetch wycheproof/hkdf_sha256_test.json "$wycheproof/hkdf_sha256_test.json" bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e
fetch wycheproof/hmac_sha384_test.json "$wycheproof/hmac_sha384_test.json" 28b9776e979dd755d852ca471043ea6cedce8b15f7a28abdf6ea9efd982b43c0
fetch wycheproof/hkdf_sha384_test.json "$wycheproof/hkdf_sha384_test.json" 69ff6ea3657bb9c1b8cdffbbb4e7832353d08fd15c0d9997b03f7a6b180e3678
fetch wycheproof/aes_gcm_test.json "$wycheproof/aes_gcm_test.json" 985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7
fetch wycheproof/chacha20_poly1305_test.json "$wycheproof/chacha20_poly1305_test.json" fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d
fetch wycheproof/x25519_test.json "$wycheproof/x25519_test.json" 35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d
fetch wycheproof/ecdh_secp256r1_ecpoint_test.json "$wycheproof/ecdh_secp256r1_ecpoint_test.json" 648f16d077caf2400d02331ca51f44744c72c799830c8d0595d0b18b6dd9f886
fetch wycheproof/ecdsa_secp256r1_sha256_p1363_test.json "$wycheproof/ecdsa_secp256r1_sha256_p1363_test.json" c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986
fetch wycheproof/ecdsa_secp256r1_sha512_p1363_test.json "$wycheproof/ecdsa_secp256r1_sha512_p1363_test.json" 95c41daca2101540641cc13ccab128d67ad665eaf8349896434e1e6a0c5c68fc
fetch wycheproof/ecdh_secp384r1_ecpoint_test.json "$wycheproof/ecdh_secp384r1_ecpoint_test.json" ffa7835fe1de359dff762c8f1272b98acebd5578e2f855d969051ff956c6dca3
fetch wycheproof/ecdsa_secp384r1_sha384_p1363_test.json "$wycheproof/ecdsa_secp384r1_sha384_p1363_test.json" e27344bf6daae75fa19663620883809f91c79fc4b4420eff9eae8036b34476be
fetch wycheproof/ecdsa_secp384r1_sha512_p1363_test.json "$wycheproof/ecdsa_secp384r1_sha512_p1363_test.json" d994c43b997760ce51c4bbae4a974bf9f9c61db2c4b0e454c3999179de7aae46
#   Ed25519 (Ed25519Tests): 210 verifications - malleable S, non-canonical and invalid encodings
#   of R and A, truncated and padded signatures, Tink's overflow cases, and the small- and
#   mixed-order public keys whose signatures either policy may take ("acceptable").
fetch wycheproof/ed25519_test.json "$wycheproof/ed25519_test.json" ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3
#   RSA signatures (RsaTests): RSASSA-PKCS1-v1_5 at 2048 to 8192 bits with every SHA-2 hash this
#   library takes (BER and malformed paddings, wrong hashes, the missing NULL, small and edge-case
#   signatures), and RSASSA-PSS: MGF1 with the same hash at the salt lengths TLS 1.3 and the
#   certificates use, the misc file's every hash pair, and SHA-1 and MGF1-SHA1 ones that must fail
#   here (this library verifies PSS with SHA-256, -384 or -512 and MGF1 on the same hash only);
#   and the signing side: rsa_pkcs1_*_sig_gen, private keys (PKCS#8) with the exact PKCS#1 v1.5
#   signatures they make at 1024 to 4096 bits.
for pin in \
  rsa_signature_2048_sha224_test.json:81b9da6e58f8a55ccc02b96f64a1d84d93100b9767dddbc906cee52d4c7daeac \
  rsa_signature_2048_sha256_test.json:94a917b01ff50fb874cfc05bf29b4af44868d944a6558201cf18380da93fb393 \
  rsa_signature_2048_sha384_test.json:c571c105d261c0ff588a2888a529f152563fb3b77894b7620d4e4f8f934f2c1d \
  rsa_signature_2048_sha512_test.json:16ea24b039905d054bdb6004f5fd179374e150b7b6d73a7ba654b6d00eab12ef \
  rsa_signature_3072_sha256_test.json:0f5f18cabfaad3e2792e82f7e9882f8999049b456714de924b8a5e202f61ca43 \
  rsa_signature_3072_sha384_test.json:73499ee649d8fb703b3f0f455fa36f7682fde677c590a736958ebce05ab27dae \
  rsa_signature_3072_sha512_test.json:09aa3336fdb7be216180ce944ca7b2a052e1de38c210435c19506327d4a36ebd \
  rsa_signature_4096_sha256_test.json:957aca128e30bd02c8982f8ca482d6521d16683f4bbc3f193cdfd4c8f04bc667 \
  rsa_signature_4096_sha384_test.json:bc26f16b9fc9a90628864d3d1111ef48a4bd00b9d4870bfab88ff326e309e073 \
  rsa_signature_4096_sha512_test.json:9d6e67b1eb0d7040db411835238efd20e9302399a258bdff82de3f38e0f2855a \
  rsa_signature_8192_sha256_test.json:86df4075b4ce5954726abfa00cc19ebe8b608d6d99094d5e123d6a3a86568bd9 \
  rsa_signature_8192_sha384_test.json:382c2795790021798099bc8e94d0f078ef1f78787f5c7a87aaa25b5556efacff \
  rsa_signature_8192_sha512_test.json:c9e5463742d192b5ff1108538841d4d302fd799604a051d09db5f496f2f851f7 \
  rsa_pss_2048_sha256_mgf1_0_test.json:b22a8d9a2e7e47f681d0ff1d1a55455daaf325d989c64ad005f848bd50b9b4c0 \
  rsa_pss_2048_sha256_mgf1_32_test.json:7f6efafc160f4816b96cbf1c12188a31051d7e3f001e27505d9edb5f2a0e325c \
  rsa_pss_2048_sha384_mgf1_48_test.json:66d464778b0b2f683a1d1a20e94f77e9472b8cc393b45f423fa08a48e677063c \
  rsa_pss_3072_sha256_mgf1_32_test.json:cca48433e6d1accb57f65b3396c4f4dd93c776467101c3f0948e74c283fd4749 \
  rsa_pss_4096_sha256_mgf1_32_test.json:e627cbf5139a01e0a446c4fe15911f6268224fdd3ef4a1eb714b3942b5686410 \
  rsa_pss_4096_sha384_mgf1_48_test.json:d632649a7630f7c267eda576714ca11cf0ff068d6622f576b8701f923c112577 \
  rsa_pss_4096_sha512_mgf1_32_test.json:af1e1c1c593edf91be3e9880927231d57f9df082f2d8caec2a61d9874ade101f \
  rsa_pss_4096_sha512_mgf1_64_test.json:c93ceaa56a190c9fd4707441c5c6a75839f108202d88aec891697f9623042547 \
  rsa_pss_misc_test.json:1fac515f67fea8ccbf44ea08fde2de00cd76169f774a54ce2994c9963c31e84f \
  rsa_pss_2048_sha1_mgf1_20_test.json:96d13ecdc356a24aec01dcbef7c5a15458b78373283113c294a60f8ddf717b29 \
  rsa_pss_2048_sha256_mgf1sha1_20_test.json:8099d28e300c86cf1cac2ab09cd777186b5ecc0f555d7c178c665b4ff3c08307 \
  rsa_pkcs1_1024_sig_gen_test.json:d29bb1d43016e8932937554291e997dc509455373b0d3cfe89ebffaee80ec9cd \
  rsa_pkcs1_1536_sig_gen_test.json:251da3f00f11cba07f8e89c94363e25ea16ef4b35aaa270063e4f763c283a8bd \
  rsa_pkcs1_2048_sig_gen_test.json:587b3d27d3429f2118cb02818da4d08eb3f36f50c747939eb550fae4337ccbf0 \
  rsa_pkcs1_3072_sig_gen_test.json:45153219d486fd135d35aa968a957a0c015c7829e8dc59bea5f87e6c30912677 \
  rsa_pkcs1_4096_sig_gen_test.json:f13eadbec6c45291cb33e6b2fa0a0c2b862d0bd2eaec29f930d3b78067cd48c7; do
  fetch "wycheproof/${pin%%:*}" "$wycheproof/${pin%%:*}" "${pin##*:}"
done

echo "$tools"
