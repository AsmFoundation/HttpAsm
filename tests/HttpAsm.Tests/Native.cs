using System.Runtime.InteropServices;

namespace HttpAsm.Tests;

/// <summary>
/// libhttpasm.so's C ABI (src/HttpAsm/include/httpasm.h), and the few C library calls the tests
/// need to build guarded buffers.
/// </summary>
/// <remarks>
/// The bare name "httpasm" makes .NET probe libhttpasm.so, which AsmFoundation.Sdk puts under
/// runtimes/linux-x64/native/ and lists in the test app's deps.json. Every entry point here is
/// a leaf that neither blocks nor calls back, so the GC transition could be suppressed. It is
/// not suppressed: these tests measure nothing, and the default is the safe one.
/// </remarks>
internal static unsafe partial class Native
{
    /// <summary>The library's name, as [LibraryImport] probes it.</summary>
    private const string Library = "httpasm";

    /// <summary>glibc by its soname: plain "libc" would make .NET probe libc.so, a linker script.</summary>
    private const string Libc = "libc.so.6";

    /// <summary>mmap's PROT_NONE: the page cannot be touched.</summary>
    internal const int ProtNone = 0;

    /// <summary>mmap's PROT_READ | PROT_WRITE.</summary>
    internal const int ProtReadWrite = 0x1 | 0x2;

    /// <summary>mmap's MAP_PRIVATE | MAP_ANONYMOUS on Linux x64.</summary>
    internal const int MapPrivateAnonymous = 0x02 | 0x20;

    /// <summary>uint32_t httpasm_abi_version(void).</summary>
    /// <returns>The loaded library's ABI version; 0 before the first release.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_abi_version")]
    internal static partial uint AbiVersion();

    /// <summary>void httpasm_sha256_init(httpasm_sha256_ctx *h).</summary>
    /// <param name="h">The running hash to start (or start over).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha256_init")]
    internal static partial void Sha256Init(Sha256Context* h);

    /// <summary>void httpasm_sha256_update(httpasm_sha256_ctx *h, const uint8_t *data, size_t n).</summary>
    /// <param name="h">The running hash.</param>
    /// <param name="data">The octets to feed (anything when n is 0).</param>
    /// <param name="n">How many.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha256_update")]
    internal static partial void Sha256Update(Sha256Context* h, byte* data, nuint n);

    /// <summary>void httpasm_sha256_final(httpasm_sha256_ctx *h, uint8_t digest[32]): wipes h.</summary>
    /// <param name="h">The running hash; all zeros afterwards.</param>
    /// <param name="digest">Receives the 32-octet digest.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha256_final")]
    internal static partial void Sha256Final(Sha256Context* h, byte* digest);

    /// <summary>void httpasm_sha256(const uint8_t *data, size_t n, uint8_t digest[32]).</summary>
    /// <param name="data">The message.</param>
    /// <param name="n">Its length.</param>
    /// <param name="digest">Receives the 32-octet digest.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha256")]
    internal static partial void Sha256(byte* data, nuint n, byte* digest);

    /// <summary>void httpasm_sha512_init(httpasm_sha512_ctx *h): a SHA-512 hash.</summary>
    /// <param name="h">The running hash to start (or start over).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha512_init")]
    internal static partial void Sha512Init(Sha512Context* h);

    /// <summary>void httpasm_sha384_init(httpasm_sha512_ctx *h): a SHA-384 hash in the same context.</summary>
    /// <param name="h">The running hash to start (or start over).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha384_init")]
    internal static partial void Sha384Init(Sha512Context* h);

    /// <summary>void httpasm_sha512_update(httpasm_sha512_ctx *h, const uint8_t *data, size_t n): either hash.</summary>
    /// <param name="h">The running hash.</param>
    /// <param name="data">The octets to feed (anything when n is 0).</param>
    /// <param name="n">How many.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha512_update")]
    internal static partial void Sha512Update(Sha512Context* h, byte* data, nuint n);

    /// <summary>void httpasm_sha512_final(httpasm_sha512_ctx *h, uint8_t digest[64]): wipes h.</summary>
    /// <param name="h">The running hash (started by <see cref="Sha512Init"/>); all zeros afterwards.</param>
    /// <param name="digest">Receives the 64-octet digest.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha512_final")]
    internal static partial void Sha512Final(Sha512Context* h, byte* digest);

    /// <summary>void httpasm_sha384_final(httpasm_sha512_ctx *h, uint8_t digest[48]): wipes h.</summary>
    /// <param name="h">The running hash (started by <see cref="Sha384Init"/>); all zeros afterwards.</param>
    /// <param name="digest">Receives the 48-octet digest.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha384_final")]
    internal static partial void Sha384Final(Sha512Context* h, byte* digest);

    /// <summary>void httpasm_sha512(const uint8_t *data, size_t n, uint8_t digest[64]).</summary>
    /// <param name="data">The message.</param>
    /// <param name="n">Its length.</param>
    /// <param name="digest">Receives the 64-octet digest.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha512")]
    internal static partial void Sha512(byte* data, nuint n, byte* digest);

    /// <summary>void httpasm_sha3_224_init(httpasm_sha3_ctx *h): a SHA3-224 hash (rate 144).</summary>
    /// <param name="h">Receives the new context (all 216 octets written).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha3_224_init")]
    internal static partial void Sha3_224Init(Sha3Context* h);

    /// <summary>void httpasm_sha3_256_init(httpasm_sha3_ctx *h): a SHA3-256 hash (rate 136).</summary>
    /// <param name="h">Receives the new context.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha3_256_init")]
    internal static partial void Sha3_256Init(Sha3Context* h);

    /// <summary>void httpasm_sha3_384_init(httpasm_sha3_ctx *h): a SHA3-384 hash (rate 104).</summary>
    /// <param name="h">Receives the new context.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha3_384_init")]
    internal static partial void Sha3_384Init(Sha3Context* h);

    /// <summary>void httpasm_sha3_512_init(httpasm_sha3_ctx *h): a SHA3-512 hash (rate 72).</summary>
    /// <param name="h">Receives the new context.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha3_512_init")]
    internal static partial void Sha3_512Init(Sha3Context* h);

    /// <summary>void httpasm_shake128_init(httpasm_sha3_ctx *h): a SHAKE128 XOF (rate 168).</summary>
    /// <param name="h">Receives the new context.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_shake128_init")]
    internal static partial void Shake128Init(Sha3Context* h);

    /// <summary>void httpasm_shake256_init(httpasm_sha3_ctx *h): a SHAKE256 XOF (rate 136).</summary>
    /// <param name="h">Receives the new context.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_shake256_init")]
    internal static partial void Shake256Init(Sha3Context* h);

    /// <summary>void httpasm_sha3_update(httpasm_sha3_ctx *h, const uint8_t *data, size_t n): any of the six.</summary>
    /// <param name="h">The running context.</param>
    /// <param name="data">The next octets.</param>
    /// <param name="n">How many (0 allowed).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha3_update")]
    internal static partial void Sha3Update(Sha3Context* h, byte* data, nuint n);

    /// <summary>void httpasm_sha3_final(httpasm_sha3_ctx *h, uint8_t *digest): (200 - rate) / 2 octets, then wipes h.</summary>
    /// <param name="h">The running context; all zeros afterwards.</param>
    /// <param name="digest">Receives the digest.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha3_final")]
    internal static partial void Sha3Final(Sha3Context* h, byte* digest);

    /// <summary>void httpasm_shake_squeeze(httpasm_sha3_ctx *h, uint8_t *out, size_t n): the stream's next n octets.</summary>
    /// <param name="h">The running context (not wiped).</param>
    /// <param name="output">Receives the octets.</param>
    /// <param name="n">How many (0 allowed).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_shake_squeeze")]
    internal static partial void ShakeSqueeze(Sha3Context* h, byte* output, nuint n);

    /// <summary>void httpasm_sha3_224(data, n, digest[28]).</summary>
    /// <param name="data">The message.</param>
    /// <param name="n">Its length.</param>
    /// <param name="digest">Receives the digest.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha3_224")]
    internal static partial void Sha3_224(byte* data, nuint n, byte* digest);

    /// <summary>void httpasm_sha3_256(data, n, digest[32]).</summary>
    /// <param name="data">The message.</param>
    /// <param name="n">Its length.</param>
    /// <param name="digest">Receives the digest.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha3_256")]
    internal static partial void Sha3_256(byte* data, nuint n, byte* digest);

    /// <summary>void httpasm_sha3_384(data, n, digest[48]).</summary>
    /// <param name="data">The message.</param>
    /// <param name="n">Its length.</param>
    /// <param name="digest">Receives the digest.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha3_384")]
    internal static partial void Sha3_384(byte* data, nuint n, byte* digest);

    /// <summary>void httpasm_sha3_512(data, n, digest[64]).</summary>
    /// <param name="data">The message.</param>
    /// <param name="n">Its length.</param>
    /// <param name="digest">Receives the digest.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha3_512")]
    internal static partial void Sha3_512(byte* data, nuint n, byte* digest);

    /// <summary>void httpasm_shake128(data, n, out, out_n).</summary>
    /// <param name="data">The message.</param>
    /// <param name="n">Its length.</param>
    /// <param name="output">Receives out_n octets.</param>
    /// <param name="outputLength">How many (0 allowed).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_shake128")]
    internal static partial void Shake128(byte* data, nuint n, byte* output, nuint outputLength);

    /// <summary>void httpasm_shake256(data, n, out, out_n).</summary>
    /// <param name="data">The message.</param>
    /// <param name="n">Its length.</param>
    /// <param name="output">Receives out_n octets.</param>
    /// <param name="outputLength">How many (0 allowed).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_shake256")]
    internal static partial void Shake256(byte* data, nuint n, byte* output, nuint outputLength);

    /// <summary>void httpasm_sha384(const uint8_t *data, size_t n, uint8_t digest[48]).</summary>
    /// <param name="data">The message.</param>
    /// <param name="n">Its length.</param>
    /// <param name="digest">Receives the 48-octet digest.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_sha384")]
    internal static partial void Sha384(byte* data, nuint n, byte* digest);

    /// <summary>void httpasm_hmac_sha256_init(httpasm_hmac_sha256_ctx *h, const uint8_t *key, size_t n).</summary>
    /// <param name="h">The running MAC to start.</param>
    /// <param name="key">The key (anything when n is 0).</param>
    /// <param name="n">Its length.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hmac_sha256_init")]
    internal static partial void HmacSha256Init(HmacSha256Context* h, byte* key, nuint n);

    /// <summary>void httpasm_hmac_sha256_update(httpasm_hmac_sha256_ctx *h, const uint8_t *data, size_t n).</summary>
    /// <param name="h">The running MAC.</param>
    /// <param name="data">The message's next octets.</param>
    /// <param name="n">How many.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hmac_sha256_update")]
    internal static partial void HmacSha256Update(HmacSha256Context* h, byte* data, nuint n);

    /// <summary>void httpasm_hmac_sha256_final(httpasm_hmac_sha256_ctx *h, uint8_t mac[32]): wipes h.</summary>
    /// <param name="h">The running MAC; all zeros afterwards.</param>
    /// <param name="mac">Receives the 32-octet MAC.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hmac_sha256_final")]
    internal static partial void HmacSha256Final(HmacSha256Context* h, byte* mac);

    /// <summary>void httpasm_hmac_sha256(key, key_length, data, n, mac[32]).</summary>
    /// <param name="key">The key.</param>
    /// <param name="keyLength">Its length.</param>
    /// <param name="data">The message.</param>
    /// <param name="n">Its length.</param>
    /// <param name="mac">Receives the 32-octet MAC.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hmac_sha256")]
    internal static partial void HmacSha256(byte* key, nuint keyLength, byte* data, nuint n, byte* mac);

    /// <summary>void httpasm_hkdf_sha256_extract(salt, salt_length, ikm, ikm_length, prk[32]).</summary>
    /// <param name="salt">The salt (anything when its length is 0).</param>
    /// <param name="saltLength">Its length.</param>
    /// <param name="ikm">The input keying material.</param>
    /// <param name="ikmLength">Its length.</param>
    /// <param name="prk">Receives the 32-octet pseudorandom key.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hkdf_sha256_extract")]
    internal static partial void HkdfSha256Extract(byte* salt, nuint saltLength, byte* ikm, nuint ikmLength, byte* prk);

    /// <summary>int httpasm_hkdf_sha256_expand(prk, prk_length, info, info_length, okm, length).</summary>
    /// <param name="prk">The pseudorandom key.</param>
    /// <param name="prkLength">Its length.</param>
    /// <param name="info">The context (anything when its length is 0).</param>
    /// <param name="infoLength">Its length.</param>
    /// <param name="okm">Receives the output keying material.</param>
    /// <param name="length">How many octets of it.</param>
    /// <returns>0, or -1 when length exceeds 8160 (nothing written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hkdf_sha256_expand")]
    internal static partial int HkdfSha256Expand(byte* prk, nuint prkLength, byte* info, nuint infoLength, byte* okm, nuint length);

    /// <summary>int httpasm_aes_init(httpasm_aes_key *k, const uint8_t *key, size_t length).</summary>
    /// <param name="k">The key to expand into (untouched on a refusal).</param>
    /// <param name="key">The key octets.</param>
    /// <param name="length">16 (AES-128) or 32 (AES-256).</param>
    /// <returns>0, or -1 for any other length.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_aes_init")]
    internal static partial int AesInit(AesKey* k, byte* key, nuint length);

    /// <summary>void httpasm_aes_encrypt_block(const httpasm_aes_key *k, const uint8_t in[16], uint8_t out[16]).</summary>
    /// <param name="k">An expanded key.</param>
    /// <param name="input">The 16-octet block.</param>
    /// <param name="output">Receives its encryption (may be input).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_aes_encrypt_block")]
    internal static partial void AesEncryptBlock(AesKey* k, byte* input, byte* output);

    /// <summary>int httpasm_aes_gcm_init(httpasm_aes_gcm_key *k, const uint8_t *key, size_t length).</summary>
    /// <param name="k">The key to make (untouched on a refusal).</param>
    /// <param name="key">The key octets.</param>
    /// <param name="length">16 or 32.</param>
    /// <returns>0, or -1 for any other length.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_aes_gcm_init")]
    internal static partial int AesGcmInit(AesGcmKey* k, byte* key, nuint length);

    /// <summary>int httpasm_aes_gcm_seal(k, nonce[12], aad, aad_length, in, length, out, tag[16]).</summary>
    /// <param name="k">The key.</param>
    /// <param name="nonce">12 octets.</param>
    /// <param name="aad">The additional data (anything when its length is 0).</param>
    /// <param name="aadLength">Its length.</param>
    /// <param name="input">The plaintext (anything when length is 0).</param>
    /// <param name="length">Its length.</param>
    /// <param name="output">Receives the ciphertext (may be input).</param>
    /// <param name="tag">Receives the 16-octet tag.</param>
    /// <returns>0, or -1 past SP 800-38D's limits (nothing written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_aes_gcm_seal")]
    internal static partial int AesGcmSeal(AesGcmKey* k, byte* nonce, byte* aad, nuint aadLength, byte* input, nuint length, byte* output, byte* tag);

    /// <summary>int httpasm_aes_gcm_open(k, nonce[12], aad, aad_length, in, length, tag[16], out).</summary>
    /// <param name="k">The key.</param>
    /// <param name="nonce">12 octets.</param>
    /// <param name="aad">The additional data.</param>
    /// <param name="aadLength">Its length.</param>
    /// <param name="input">The ciphertext.</param>
    /// <param name="length">Its length.</param>
    /// <param name="tag">The 16-octet tag to verify.</param>
    /// <param name="output">Receives the plaintext (may be input); all zeros when the tag fails.</param>
    /// <returns>0, or -1 for a wrong tag (output zeroed) or past the limits (nothing written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_aes_gcm_open")]
    internal static partial int AesGcmOpen(AesGcmKey* k, byte* nonce, byte* aad, nuint aadLength, byte* input, nuint length, byte* tag, byte* output);

    /// <summary>void httpasm_chacha20(key[32], uint32_t counter, nonce[12], in, length, out).</summary>
    /// <param name="key">32 octets.</param>
    /// <param name="counter">The first block's counter; it wraps at 2^32 with the nonce unchanged.</param>
    /// <param name="nonce">12 octets.</param>
    /// <param name="input">The octets to xor with the keystream (anything when length is 0).</param>
    /// <param name="length">Their count.</param>
    /// <param name="output">Receives the result (may be input).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_chacha20")]
    internal static partial void ChaCha20(byte* key, uint counter, byte* nonce, byte* input, nuint length, byte* output);

    /// <summary>void httpasm_poly1305(key[32], message, length, tag[16]).</summary>
    /// <param name="key">The one-time key: r (clamped by the function), then s.</param>
    /// <param name="message">The message (anything when length is 0).</param>
    /// <param name="length">Its length.</param>
    /// <param name="tag">Receives the 16-octet tag.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_poly1305")]
    internal static partial void Poly1305(byte* key, byte* message, nuint length, byte* tag);

    /// <summary>int httpasm_chacha20_poly1305_seal(key[32], nonce[12], aad, aad_length, in, length, out, tag[16]).</summary>
    /// <param name="key">32 octets.</param>
    /// <param name="nonce">12 octets.</param>
    /// <param name="aad">The additional data (anything when its length is 0).</param>
    /// <param name="aadLength">Its length.</param>
    /// <param name="input">The plaintext (anything when length is 0).</param>
    /// <param name="length">Its length.</param>
    /// <param name="output">Receives the ciphertext (may be input).</param>
    /// <param name="tag">Receives the 16-octet tag.</param>
    /// <returns>0, or -1 past 2^38 - 64 octets (nothing written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_chacha20_poly1305_seal")]
    internal static partial int ChaCha20Poly1305Seal(byte* key, byte* nonce, byte* aad, nuint aadLength, byte* input, nuint length, byte* output, byte* tag);

    /// <summary>int httpasm_chacha20_poly1305_open(key[32], nonce[12], aad, aad_length, in, length, tag[16], out).</summary>
    /// <param name="key">32 octets.</param>
    /// <param name="nonce">12 octets.</param>
    /// <param name="aad">The additional data.</param>
    /// <param name="aadLength">Its length.</param>
    /// <param name="input">The ciphertext.</param>
    /// <param name="length">Its length.</param>
    /// <param name="tag">The 16-octet tag to verify.</param>
    /// <param name="output">Receives the plaintext (may be input); all zeros when the tag fails.</param>
    /// <returns>0, or -1 for a wrong tag (output zeroed) or past the limit (nothing written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_chacha20_poly1305_open")]
    internal static partial int ChaCha20Poly1305Open(byte* key, byte* nonce, byte* aad, nuint aadLength, byte* input, nuint length, byte* tag, byte* output);

    /// <summary>int httpasm_x25519(out[32], scalar[32], point[32]).</summary>
    /// <param name="output">Receives X25519(scalar, point).</param>
    /// <param name="scalar">The private scalar (clamped by the function).</param>
    /// <param name="point">The peer's u-coordinate (bit 255 ignored).</param>
    /// <returns>0, or -1 when the output is all zeros (a small-order point; zeros written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_x25519")]
    internal static partial int X25519(byte* output, byte* scalar, byte* point);

    /// <summary>void httpasm_x25519_public_key(out[32], scalar[32]).</summary>
    /// <param name="output">Receives X25519(scalar, 9).</param>
    /// <param name="scalar">The private scalar.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_x25519_public_key")]
    internal static partial void X25519PublicKey(byte* output, byte* scalar);

    /// <summary>int httpasm_x448(out[56], scalar[56], point[56]).</summary>
    /// <param name="output">Receives X448(scalar, point); may be the scalar or the point.</param>
    /// <param name="scalar">The private scalar (clamped by the function).</param>
    /// <param name="point">The peer's u-coordinate (from p up taken modulo p).</param>
    /// <returns>0, or -1 when the output is all zeros (a small-order point; zeros written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_x448")]
    internal static partial int X448(byte* output, byte* scalar, byte* point);

    /// <summary>int httpasm_x448_public_key(out[56], scalar[56]).</summary>
    /// <param name="output">Receives X448(scalar, 5).</param>
    /// <param name="scalar">The private scalar (clamped by the function).</param>
    /// <returns>0, or -1 for the one all-zero public key (the clamped scalar 4q; zeros written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_x448_public_key")]
    internal static partial int X448PublicKey(byte* output, byte* scalar);

    /// <summary>int httpasm_p256_public_key(public_key[65], private_key[32]).</summary>
    /// <param name="publicKey">Receives 04 || x || y of d G; all zeros when d is refused.</param>
    /// <param name="privateKey">d, 32 big-endian octets.</param>
    /// <returns>0, or -1 when d is 0 or n or more.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_p256_public_key")]
    internal static partial int P256PublicKey(byte* publicKey, byte* privateKey);

    /// <summary>int httpasm_p256_ecdh(shared[32], private_key[32], peer_key[65]).</summary>
    /// <param name="shared">Receives the x-coordinate of d Q; all zeros when refused.</param>
    /// <param name="privateKey">d, 32 big-endian octets.</param>
    /// <param name="peerKey">Q, 65 octets: 04 || x || y.</param>
    /// <returns>0, or -1 when d is out of range or Q is no uncompressed point of the curve.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_p256_ecdh")]
    internal static partial int P256Ecdh(byte* shared, byte* privateKey, byte* peerKey);

    /// <summary>int httpasm_p256_sign(signature[64], private_key[32], digest, digest_length, entropy).</summary>
    /// <param name="signature">Receives r || s; all zeros when the key is refused.</param>
    /// <param name="privateKey">d, 32 big-endian octets.</param>
    /// <param name="digest">The message's digest (any hash; its leftmost 256 bits count).</param>
    /// <param name="digestLength">Its length (0 allowed).</param>
    /// <param name="entropy">32 octets mixed into RFC 6979's nonce, or null for RFC 6979's own.</param>
    /// <returns>0, or -1 when d is 0 or n or more.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_p256_sign")]
    internal static partial int P256Sign(byte* signature, byte* privateKey, byte* digest, nuint digestLength, byte* entropy);

    /// <summary>int httpasm_p256_verify(public_key[65], digest, digest_length, signature[64]).</summary>
    /// <param name="publicKey">Q, 65 octets: 04 || x || y.</param>
    /// <param name="digest">The message's digest.</param>
    /// <param name="digestLength">Its length.</param>
    /// <param name="signature">r || s, 64 octets.</param>
    /// <returns>0 when the signature is valid, else -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_p256_verify")]
    internal static partial int P256Verify(byte* publicKey, byte* digest, nuint digestLength, byte* signature);

    /// <summary>int httpasm_p384_public_key(public_key[97], private_key[48]).</summary>
    /// <param name="publicKey">Receives 04 || x || y of d G; all zeros when d is refused.</param>
    /// <param name="privateKey">d, 48 big-endian octets.</param>
    /// <returns>0, or -1 when d is 0 or n or more.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_p384_public_key")]
    internal static partial int P384PublicKey(byte* publicKey, byte* privateKey);

    /// <summary>int httpasm_p384_ecdh(shared[48], private_key[48], peer_key[97]).</summary>
    /// <param name="shared">Receives the x-coordinate of d Q; all zeros when refused.</param>
    /// <param name="privateKey">d, 48 big-endian octets.</param>
    /// <param name="peerKey">Q, 97 octets: 04 || x || y.</param>
    /// <returns>0, or -1 when d is out of range or Q is no uncompressed point of the curve.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_p384_ecdh")]
    internal static partial int P384Ecdh(byte* shared, byte* privateKey, byte* peerKey);

    /// <summary>int httpasm_p384_sign(signature[96], private_key[48], digest, digest_length, entropy).</summary>
    /// <param name="signature">Receives r || s; all zeros when the key is refused.</param>
    /// <param name="privateKey">d, 48 big-endian octets.</param>
    /// <param name="digest">The message's digest (any hash; its leftmost 384 bits count).</param>
    /// <param name="digestLength">Its length (0 allowed).</param>
    /// <param name="entropy">48 octets mixed into RFC 6979's nonce, or null for RFC 6979's own.</param>
    /// <returns>0, or -1 when d is 0 or n or more.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_p384_sign")]
    internal static partial int P384Sign(byte* signature, byte* privateKey, byte* digest, nuint digestLength, byte* entropy);

    /// <summary>int httpasm_p384_verify(public_key[97], digest, digest_length, signature[96]).</summary>
    /// <param name="publicKey">Q, 97 octets: 04 || x || y.</param>
    /// <param name="digest">The message's digest.</param>
    /// <param name="digestLength">Its length.</param>
    /// <param name="signature">r || s, 96 octets.</param>
    /// <returns>0 when the signature is valid, else -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_p384_verify")]
    internal static partial int P384Verify(byte* publicKey, byte* digest, nuint digestLength, byte* signature);

    /// <summary>int httpasm_p521_public_key(public_key[133], private_key[66]).</summary>
    /// <param name="publicKey">Receives 04 || x || y of d G; all zeros when d is refused.</param>
    /// <param name="privateKey">d, 66 big-endian octets.</param>
    /// <returns>0, or -1 when d is 0 or n or more.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_p521_public_key")]
    internal static partial int P521PublicKey(byte* publicKey, byte* privateKey);

    /// <summary>int httpasm_p521_ecdh(shared[66], private_key[66], peer_key[133]).</summary>
    /// <param name="shared">Receives the x-coordinate of d Q; all zeros when refused.</param>
    /// <param name="privateKey">d, 66 big-endian octets.</param>
    /// <param name="peerKey">Q, 133 octets: 04 || x || y.</param>
    /// <returns>0, or -1 when d is out of range or Q is no uncompressed point of the curve.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_p521_ecdh")]
    internal static partial int P521Ecdh(byte* shared, byte* privateKey, byte* peerKey);

    /// <summary>int httpasm_p521_sign(signature[132], private_key[66], digest, digest_length, entropy).</summary>
    /// <param name="signature">Receives r || s; all zeros when the key is refused.</param>
    /// <param name="privateKey">d, 66 big-endian octets.</param>
    /// <param name="digest">The message's digest (any hash; its leftmost 521 bits count).</param>
    /// <param name="digestLength">Its length (0 allowed).</param>
    /// <param name="entropy">66 octets mixed into RFC 6979's nonce, or null for RFC 6979's own.</param>
    /// <returns>0, or -1 when d is 0 or n or more.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_p521_sign")]
    internal static partial int P521Sign(byte* signature, byte* privateKey, byte* digest, nuint digestLength, byte* entropy);

    /// <summary>int httpasm_p521_verify(public_key[133], digest, digest_length, signature[132]).</summary>
    /// <param name="publicKey">Q, 133 octets: 04 || x || y.</param>
    /// <param name="digest">The message's digest.</param>
    /// <param name="digestLength">Its length.</param>
    /// <param name="signature">r || s, 132 octets.</param>
    /// <returns>0 when the signature is valid, else -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_p521_verify")]
    internal static partial int P521Verify(byte* publicKey, byte* digest, nuint digestLength, byte* signature);

    /// <summary>void httpasm_ed25519_public_key(public_key[32], private_key[32]).</summary>
    /// <param name="publicKey">Receives A, the encoding of a B (RFC 8032 5.1.5).</param>
    /// <param name="privateKey">The 32-octet seed (any value).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_ed25519_public_key")]
    internal static partial void Ed25519PublicKey(byte* publicKey, byte* privateKey);

    /// <summary>void httpasm_ed25519_private_key_init(key, private_key[32]).</summary>
    /// <param name="key">Receives a mod L, the prefix and A (<see cref="Ed25519PrivateKey"/>).</param>
    /// <param name="privateKey">The 32-octet seed.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_ed25519_private_key_init")]
    internal static partial void Ed25519PrivateKeyInit(Ed25519PrivateKey* key, byte* privateKey);

    /// <summary>void httpasm_ed25519_sign(signature[64], key, message, length).</summary>
    /// <param name="signature">Receives R || S; may overlap the message.</param>
    /// <param name="key">A prepared key.</param>
    /// <param name="message">The message itself (pure Ed25519 hashes it).</param>
    /// <param name="length">Its length (0 allowed, message may then be null).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_ed25519_sign")]
    internal static partial void Ed25519Sign(byte* signature, Ed25519PrivateKey* key, byte* message, nuint length);

    /// <summary>int httpasm_ed25519_verify(public_key[32], message, length, signature[64]).</summary>
    /// <param name="publicKey">A, 32 octets.</param>
    /// <param name="message">The message.</param>
    /// <param name="length">Its length.</param>
    /// <param name="signature">R || S, 64 octets.</param>
    /// <returns>0 when the signature is valid (the cofactorless equation), else -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_ed25519_verify")]
    internal static partial int Ed25519Verify(byte* publicKey, byte* message, nuint length, byte* signature);

    /// <summary>void httpasm_ed448_public_key(public_key[57], private_key[57]).</summary>
    /// <param name="publicKey">Receives A = s B, encoded.</param>
    /// <param name="privateKey">The 57-octet seed.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_ed448_public_key")]
    internal static partial void Ed448PublicKey(byte* publicKey, byte* privateKey);

    /// <summary>void httpasm_ed448_private_key_init(key, private_key[57]).</summary>
    /// <param name="key">Receives s, the prefix and A (<see cref="Ed448PrivateKey"/>).</param>
    /// <param name="privateKey">The 57-octet seed.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_ed448_private_key_init")]
    internal static partial void Ed448PrivateKeyInit(Ed448PrivateKey* key, byte* privateKey);

    /// <summary>int httpasm_ed448_sign(signature[114], key, message, length, context, context_length).</summary>
    /// <param name="signature">Receives R || S (may overlap the message).</param>
    /// <param name="key">A prepared key.</param>
    /// <param name="message">The message itself (pure Ed448 hashes it).</param>
    /// <param name="length">Its length (0 allowed, message may then be null).</param>
    /// <param name="context">The context (null allowed for length 0).</param>
    /// <param name="contextLength">Its length, at most 255.</param>
    /// <returns>0, or -1 for a context over 255 octets (nothing written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_ed448_sign")]
    internal static partial int Ed448Sign(byte* signature, Ed448PrivateKey* key, byte* message, nuint length, byte* context, nuint contextLength);

    /// <summary>int httpasm_ed448_verify(public_key[57], message, length, context, context_length, signature[114]).</summary>
    /// <param name="publicKey">A, 57 octets.</param>
    /// <param name="message">The message.</param>
    /// <param name="length">Its length.</param>
    /// <param name="context">The context.</param>
    /// <param name="contextLength">Its length (over 255: refused).</param>
    /// <param name="signature">R || S, 114 octets.</param>
    /// <returns>0 when the signature is valid (the cofactorless equation), else -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_ed448_verify")]
    internal static partial int Ed448Verify(byte* publicKey, byte* message, nuint length, byte* context, nuint contextLength, byte* signature);

    /// <summary>void httpasm_mlkem512_keypair(ek[800], dk[1632], seed[64]).</summary>
    /// <param name="ek">Receives the encapsulation key.</param>
    /// <param name="dk">Receives the decapsulation key.</param>
    /// <param name="seed">d || z.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_mlkem512_keypair")]
    internal static partial void MlKem512Keypair(byte* ek, byte* dk, byte* seed);

    /// <summary>int httpasm_mlkem512_encaps(c[768], shared[32], ek[800], m[32]).</summary>
    /// <param name="c">Receives the ciphertext; zeros when refused.</param>
    /// <param name="shared">Receives the shared secret; zeros when refused.</param>
    /// <param name="ek">The encapsulation key.</param>
    /// <param name="m">The 32 random octets.</param>
    /// <returns>0, or -1 when ek fails the modulus check.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_mlkem512_encaps")]
    internal static partial int MlKem512Encaps(byte* c, byte* shared, byte* ek, byte* m);

    /// <summary>int httpasm_mlkem512_decaps(shared[32], dk[1632], c[768]).</summary>
    /// <param name="shared">Receives the shared secret (implicit rejection's when c was not ek's); zeros when refused.</param>
    /// <param name="dk">The decapsulation key.</param>
    /// <param name="c">The ciphertext.</param>
    /// <returns>0, or -1 when dk fails the hash check.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_mlkem512_decaps")]
    internal static partial int MlKem512Decaps(byte* shared, byte* dk, byte* c);

    /// <summary>void httpasm_mlkem768_keypair(ek[1184], dk[2400], seed[64]).</summary>
    /// <param name="ek">Receives the encapsulation key.</param>
    /// <param name="dk">Receives the decapsulation key.</param>
    /// <param name="seed">d || z.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_mlkem768_keypair")]
    internal static partial void MlKem768Keypair(byte* ek, byte* dk, byte* seed);

    /// <summary>int httpasm_mlkem768_encaps(c[1088], shared[32], ek[1184], m[32]).</summary>
    /// <param name="c">Receives the ciphertext; zeros when refused.</param>
    /// <param name="shared">Receives the shared secret; zeros when refused.</param>
    /// <param name="ek">The encapsulation key.</param>
    /// <param name="m">The 32 random octets.</param>
    /// <returns>0, or -1 when ek fails the modulus check.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_mlkem768_encaps")]
    internal static partial int MlKem768Encaps(byte* c, byte* shared, byte* ek, byte* m);

    /// <summary>int httpasm_mlkem768_decaps(shared[32], dk[2400], c[1088]).</summary>
    /// <param name="shared">Receives the shared secret; zeros when refused.</param>
    /// <param name="dk">The decapsulation key.</param>
    /// <param name="c">The ciphertext.</param>
    /// <returns>0, or -1 when dk fails the hash check.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_mlkem768_decaps")]
    internal static partial int MlKem768Decaps(byte* shared, byte* dk, byte* c);

    /// <summary>void httpasm_mlkem1024_keypair(ek[1568], dk[3168], seed[64]).</summary>
    /// <param name="ek">Receives the encapsulation key.</param>
    /// <param name="dk">Receives the decapsulation key.</param>
    /// <param name="seed">d || z.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_mlkem1024_keypair")]
    internal static partial void MlKem1024Keypair(byte* ek, byte* dk, byte* seed);

    /// <summary>int httpasm_mlkem1024_encaps(c[1568], shared[32], ek[1568], m[32]).</summary>
    /// <param name="c">Receives the ciphertext; zeros when refused.</param>
    /// <param name="shared">Receives the shared secret; zeros when refused.</param>
    /// <param name="ek">The encapsulation key.</param>
    /// <param name="m">The 32 random octets.</param>
    /// <returns>0, or -1 when ek fails the modulus check.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_mlkem1024_encaps")]
    internal static partial int MlKem1024Encaps(byte* c, byte* shared, byte* ek, byte* m);

    /// <summary>int httpasm_mlkem1024_decaps(shared[32], dk[3168], c[1568]).</summary>
    /// <param name="shared">Receives the shared secret; zeros when refused.</param>
    /// <param name="dk">The decapsulation key.</param>
    /// <param name="c">The ciphertext.</param>
    /// <returns>0, or -1 when dk fails the hash check.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_mlkem1024_decaps")]
    internal static partial int MlKem1024Decaps(byte* shared, byte* dk, byte* c);

    /// <summary>size_t httpasm_ffdhe_size(int group).</summary>
    /// <param name="group">A TLS NamedGroup code (ffdhe2048 = 0x0100 .. ffdhe8192 = 0x0104).</param>
    /// <returns>p's size in octets (a public key's and a shared secret's), 0 for another value.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_ffdhe_size")]
    internal static partial nuint FfdheSize(int group);

    /// <summary>int httpasm_ffdhe_public_key(group, public_key[size], private_key, private_length).</summary>
    /// <param name="group">The group.</param>
    /// <param name="publicKey">Receives 2^x mod p, p's size in octets, big-endian.</param>
    /// <param name="privateKey">The exponent x, big-endian.</param>
    /// <param name="privateLength">x's octets: from the group's advised minimum to p's size.</param>
    /// <returns>0, or -1 for an unknown group or a length outside the range (nothing written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_ffdhe_public_key")]
    internal static partial int FfdhePublicKey(int group, byte* publicKey, byte* privateKey, nuint privateLength);

    /// <summary>int httpasm_ffdhe_shared(group, shared[size], private_key, private_length, peer_key[size]).</summary>
    /// <param name="group">The group.</param>
    /// <param name="shared">Receives Y^x mod p, p's size in octets, big-endian (left-padded).</param>
    /// <param name="privateKey">The exponent x, big-endian.</param>
    /// <param name="privateLength">x's octets: from the group's advised minimum to p's size.</param>
    /// <param name="peerKey">The peer's Y, p's size in octets.</param>
    /// <returns>0, or -1 for an unknown group, a length outside the range, or Y outside (1, p - 1)
    /// (nothing written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_ffdhe_shared")]
    internal static partial int FfdheShared(int group, byte* shared, byte* privateKey, nuint privateLength, byte* peerKey);

    /// <summary>int httpasm_rsa_public_key_init(key, n, n_length, e, e_length).</summary>
    /// <param name="key">Receives the key; all zeros when refused.</param>
    /// <param name="n">The modulus, big-endian (leading zero octets allowed).</param>
    /// <param name="nLength">Its length in octets.</param>
    /// <param name="e">The public exponent, big-endian (leading zero octets allowed).</param>
    /// <param name="eLength">Its length in octets.</param>
    /// <returns>0, or -1 when n is even or outside 1024..8192 bits, or e is even, below 3 or above 2^64 - 1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_rsa_public_key_init")]
    internal static partial int RsaPublicKeyInit(RsaPublicKey* key, byte* n, nuint nLength, byte* e, nuint eLength);

    /// <summary>int httpasm_rsa_verify_pkcs1(key, hash, digest, signature, signature_length).</summary>
    /// <param name="key">A key from <see cref="RsaPublicKeyInit"/>.</param>
    /// <param name="hash">HTTPASM_HASH_*: 1 SHA-1, 2 SHA-224, 3 SHA-256, 4 SHA-384, 5 SHA-512.</param>
    /// <param name="digest">The digest, that hash's length.</param>
    /// <param name="signature">The signature, big-endian.</param>
    /// <param name="signatureLength">Its length (the modulus' octets, or it fails).</param>
    /// <returns>0 when valid (RFC 8017 8.2.2), else -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_rsa_verify_pkcs1")]
    internal static partial int RsaVerifyPkcs1(RsaPublicKey* key, int hash, byte* digest, byte* signature, nuint signatureLength);

    /// <summary>int httpasm_rsa_verify_pss(key, hash, digest, salt_length, signature, signature_length).</summary>
    /// <param name="key">A key from <see cref="RsaPublicKeyInit"/>.</param>
    /// <param name="hash">3 SHA-256, 4 SHA-384 or 5 SHA-512 (MGF1 with the same hash); any other fails.</param>
    /// <param name="digest">The digest, that hash's length.</param>
    /// <param name="saltLength">The salt's length the signer used.</param>
    /// <param name="signature">The signature, big-endian.</param>
    /// <param name="signatureLength">Its length (the modulus' octets, or it fails).</param>
    /// <returns>0 when valid (RFC 8017 8.1.2), else -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_rsa_verify_pss")]
    internal static partial int RsaVerifyPss(RsaPublicKey* key, int hash, byte* digest, nuint saltLength, byte* signature, nuint signatureLength);

    /// <summary>int httpasm_rsa_private_key_init(key, numbers).</summary>
    /// <param name="key">Receives the key; all zeros when refused.</param>
    /// <param name="numbers">An RSAPrivateKey's numbers (n, e, p, q, dp, dq, qinv).</param>
    /// <returns>0, or -1 for a refused public part, a prime even, 1 or over 4096 bits, p q not n, dp, dq or qinv out of range, or a test signature that fails.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_rsa_private_key_init")]
    internal static partial int RsaPrivateKeyInit(RsaPrivateKey* key, RsaPrivateNumbers* numbers);

    /// <summary>int httpasm_rsa_sign_pkcs1(key, hash, digest, signature, signature_length).</summary>
    /// <param name="key">A key from <see cref="RsaPrivateKeyInit"/>.</param>
    /// <param name="hash">HTTPASM_HASH_*: 1 SHA-1 to 5 SHA-512.</param>
    /// <param name="digest">The digest, that hash's length.</param>
    /// <param name="signature">Receives the signature.</param>
    /// <param name="signatureLength">The modulus' octets (any other: -1, nothing written).</param>
    /// <returns>0, or -1 (the signature zeroed when its length was right).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_rsa_sign_pkcs1")]
    internal static partial int RsaSignPkcs1(RsaPrivateKey* key, int hash, byte* digest, byte* signature, nuint signatureLength);

    /// <summary>int httpasm_rsa_sign_pss(key, hash, digest, salt, salt_length, signature, signature_length).</summary>
    /// <param name="key">A key from <see cref="RsaPrivateKeyInit"/>.</param>
    /// <param name="hash">3 SHA-256, 4 SHA-384 or 5 SHA-512 (MGF1 with the same hash).</param>
    /// <param name="digest">The digest.</param>
    /// <param name="salt">The salt (null when saltLength is 0).</param>
    /// <param name="saltLength">Its length.</param>
    /// <param name="signature">Receives the signature.</param>
    /// <param name="signatureLength">The modulus' octets.</param>
    /// <returns>0, or -1 (the signature zeroed when its length was right).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_rsa_sign_pss")]
    internal static partial int RsaSignPss(RsaPrivateKey* key, int hash, byte* digest, byte* salt, nuint saltLength, byte* signature, nuint signatureLength);

    /// <summary>int httpasm_random(void *buffer, size_t length).</summary>
    /// <param name="buffer">Receives the random octets (anything when length is 0).</param>
    /// <param name="length">How many.</param>
    /// <returns>0, or -errno when the kernel refused (the buffer then unusable).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_random")]
    internal static partial int Random(byte* buffer, nuint length);

    /// <summary>void httpasm_hmac_sha384_init(httpasm_hmac_sha384_ctx *h, const uint8_t *key, size_t n).</summary>
    /// <param name="h">The context to start.</param>
    /// <param name="key">The key (anything when n is 0).</param>
    /// <param name="n">Its length (any: past 128 octets it is hashed first).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hmac_sha384_init")]
    internal static partial void HmacSha384Init(HmacSha384Context* h, byte* key, nuint n);

    /// <summary>void httpasm_hmac_sha384_update(httpasm_hmac_sha384_ctx *h, const uint8_t *data, size_t n).</summary>
    /// <param name="h">The running MAC.</param>
    /// <param name="data">The message's next octets.</param>
    /// <param name="n">How many.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hmac_sha384_update")]
    internal static partial void HmacSha384Update(HmacSha384Context* h, byte* data, nuint n);

    /// <summary>void httpasm_hmac_sha384_final(httpasm_hmac_sha384_ctx *h, uint8_t mac[48]): wipes h.</summary>
    /// <param name="h">The running MAC; all zeros afterwards.</param>
    /// <param name="mac">Receives the 48-octet MAC.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hmac_sha384_final")]
    internal static partial void HmacSha384Final(HmacSha384Context* h, byte* mac);

    /// <summary>void httpasm_hmac_sha384(key, key_length, data, n, mac[48]).</summary>
    /// <param name="key">The key.</param>
    /// <param name="keyLength">Its length.</param>
    /// <param name="data">The message.</param>
    /// <param name="n">Its length.</param>
    /// <param name="mac">Receives the 48-octet MAC.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hmac_sha384")]
    internal static partial void HmacSha384(byte* key, nuint keyLength, byte* data, nuint n, byte* mac);

    /// <summary>void httpasm_hkdf_sha384_extract(salt, salt_length, ikm, ikm_length, prk[48]).</summary>
    /// <param name="salt">The salt (anything when its length is 0).</param>
    /// <param name="saltLength">Its length.</param>
    /// <param name="ikm">The input keying material.</param>
    /// <param name="ikmLength">Its length.</param>
    /// <param name="prk">Receives the 48-octet pseudorandom key.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hkdf_sha384_extract")]
    internal static partial void HkdfSha384Extract(byte* salt, nuint saltLength, byte* ikm, nuint ikmLength, byte* prk);

    /// <summary>int httpasm_hkdf_sha384_expand(prk, prk_length, info, info_length, okm, length).</summary>
    /// <param name="prk">The pseudorandom key.</param>
    /// <param name="prkLength">Its length.</param>
    /// <param name="info">The context (anything when its length is 0).</param>
    /// <param name="infoLength">Its length.</param>
    /// <param name="okm">Receives the output keying material.</param>
    /// <param name="length">How many octets of it.</param>
    /// <returns>0, or -1 when length exceeds 12240 (nothing written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hkdf_sha384_expand")]
    internal static partial int HkdfSha384Expand(byte* prk, nuint prkLength, byte* info, nuint infoLength, byte* okm, nuint length);

    /// <summary>void httpasm_hmac_sha512_init(httpasm_hmac_sha512_ctx *h, const uint8_t *key, size_t n).</summary>
    /// <param name="h">The context to start.</param>
    /// <param name="key">The key (anything when n is 0).</param>
    /// <param name="n">Its length (any: past 128 octets it is hashed first).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hmac_sha512_init")]
    internal static partial void HmacSha512Init(HmacSha512Context* h, byte* key, nuint n);

    /// <summary>void httpasm_hmac_sha512_update(httpasm_hmac_sha512_ctx *h, const uint8_t *data, size_t n).</summary>
    /// <param name="h">The running MAC.</param>
    /// <param name="data">The message's next octets.</param>
    /// <param name="n">How many.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hmac_sha512_update")]
    internal static partial void HmacSha512Update(HmacSha512Context* h, byte* data, nuint n);

    /// <summary>void httpasm_hmac_sha512_final(httpasm_hmac_sha512_ctx *h, uint8_t mac[64]): wipes h.</summary>
    /// <param name="h">The running MAC; all zeros afterwards.</param>
    /// <param name="mac">Receives the 64-octet MAC.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hmac_sha512_final")]
    internal static partial void HmacSha512Final(HmacSha512Context* h, byte* mac);

    /// <summary>void httpasm_hmac_sha512(key, key_length, data, n, mac[64]).</summary>
    /// <param name="key">The key.</param>
    /// <param name="keyLength">Its length.</param>
    /// <param name="data">The message.</param>
    /// <param name="n">Its length.</param>
    /// <param name="mac">Receives the 64-octet MAC.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hmac_sha512")]
    internal static partial void HmacSha512(byte* key, nuint keyLength, byte* data, nuint n, byte* mac);

    /// <summary>void httpasm_hkdf_sha512_extract(salt, salt_length, ikm, ikm_length, prk[64]).</summary>
    /// <param name="salt">The salt (anything when its length is 0).</param>
    /// <param name="saltLength">Its length.</param>
    /// <param name="ikm">The input keying material.</param>
    /// <param name="ikmLength">Its length.</param>
    /// <param name="prk">Receives the 64-octet pseudorandom key.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hkdf_sha512_extract")]
    internal static partial void HkdfSha512Extract(byte* salt, nuint saltLength, byte* ikm, nuint ikmLength, byte* prk);

    /// <summary>int httpasm_hkdf_sha512_expand(prk, prk_length, info, info_length, okm, length).</summary>
    /// <param name="prk">The pseudorandom key.</param>
    /// <param name="prkLength">Its length.</param>
    /// <param name="info">The context (anything when its length is 0).</param>
    /// <param name="infoLength">Its length.</param>
    /// <param name="okm">Receives the output keying material.</param>
    /// <param name="length">How many octets of it.</param>
    /// <returns>0, or -1 when length exceeds 16320 (nothing written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hkdf_sha512_expand")]
    internal static partial int HkdfSha512Expand(byte* prk, nuint prkLength, byte* info, nuint infoLength, byte* okm, nuint length);

    /// <summary>int httpasm_asn1_read(httpasm_asn1 *element, const uint8_t *in, size_t length, int rules).</summary>
    /// <param name="element">Receives the first element (unspecified on -1).</param>
    /// <param name="input">The encoding: the element, and whatever follows it.</param>
    /// <param name="length">The octets at <paramref name="input"/> (none past them is read).</param>
    /// <param name="rules"><see cref="Asn1.Der"/> or <see cref="Asn1.Ber"/>.</param>
    /// <returns>0, or -1 when the element breaks a rule (or the rules are unknown).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_asn1_read")]
    internal static partial int Asn1Read(Asn1Element* element, byte* input, nuint length, int rules);

    /// <summary>int httpasm_asn1_check(const httpasm_asn1 *element, uint32_t type, int rules).</summary>
    /// <param name="element">An element read under another (implicit) tag.</param>
    /// <param name="type">The universal type whose rules apply (its number; SEQUENCE's and SET's
    /// form bit allowed).</param>
    /// <param name="rules"><see cref="Asn1.Der"/> or <see cref="Asn1.Ber"/>.</param>
    /// <returns>0, or -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_asn1_check")]
    internal static partial int Asn1Check(Asn1Element* element, uint type, int rules);

    /// <summary>int httpasm_asn1_check_set_of(const httpasm_asn1 *set, int rules).</summary>
    /// <param name="set">A SET OF element (any constructed one).</param>
    /// <param name="rules"><see cref="Asn1.Der"/> (components in ascending order) or <see cref="Asn1.Ber"/>.</param>
    /// <returns>0, or -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_asn1_check_set_of")]
    internal static partial int Asn1CheckSetOf(Asn1Element* set, int rules);

    /// <summary>int64_t httpasm_asn1_octets(const httpasm_asn1 *element, uint8_t *out, size_t capacity, int rules).</summary>
    /// <param name="element">An OCTET STRING or a restricted character string (or one under an implicit tag).</param>
    /// <param name="output">Receives the value's octets, the segments' joined.</param>
    /// <param name="capacity">The room at <paramref name="output"/>.</param>
    /// <param name="rules"><see cref="Asn1.Der"/> or <see cref="Asn1.Ber"/>.</param>
    /// <returns>The octets written, or -1 (too long, not such a string, unknown rules).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_asn1_octets")]
    internal static partial long Asn1Octets(Asn1Element* element, byte* output, nuint capacity, int rules);

    /// <summary>int64_t httpasm_asn1_bits(const httpasm_asn1 *element, uint8_t *out, size_t capacity, uint32_t *unused, int rules).</summary>
    /// <param name="element">A BIT STRING (or one under an implicit tag).</param>
    /// <param name="output">Receives the bits' octets, the segments' joined.</param>
    /// <param name="capacity">The room at <paramref name="output"/>.</param>
    /// <param name="unused">Receives the final octet's unused bits (unchanged on -1).</param>
    /// <param name="rules"><see cref="Asn1.Der"/> or <see cref="Asn1.Ber"/>.</param>
    /// <returns>The octets written, or -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_asn1_bits")]
    internal static partial long Asn1Bits(Asn1Element* element, byte* output, nuint capacity, uint* unused, int rules);

    /// <summary>int httpasm_pem_read(httpasm_pem *block, const uint8_t *text, size_t length, uint8_t *der, size_t capacity).</summary>
    /// <param name="block">Receives the block's label, decoded length and end.</param>
    /// <param name="text">The PEM text.</param>
    /// <param name="length">Its octets (none past them is read).</param>
    /// <param name="der">Receives the decoded octets (only once the block was checked).</param>
    /// <param name="capacity">The room at <paramref name="der"/>.</param>
    /// <returns>0; 1 when no BEGIN line is found; -1 for a malformed block; -2 when the octets do
    /// not fit (the room needed in <see cref="PemBlock.DerLength"/>).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_pem_read")]
    internal static partial int PemRead(PemBlock* block, byte* text, nuint length, byte* der, nuint capacity);

    /// <summary>int httpasm_private_key_load(httpasm_private_key *key, const uint8_t *data, size_t length).</summary>
    /// <param name="key">Receives the prepared key (all zeros when refused).</param>
    /// <param name="data">The key's file: DER, or PEM text.</param>
    /// <param name="length">Its octets (none past them is read).</param>
    /// <returns>The kind (HTTPASM_KEY_*); -2 when the only key is encrypted; -1 otherwise.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_private_key_load")]
    internal static partial int PrivateKeyLoad(PrivateKey* key, byte* data, nuint length);

    /// <summary>int httpasm_certificate_read(httpasm_certificate *c, const uint8_t *der, size_t length).</summary>
    /// <param name="certificate">Receives the parts (pointers into der).</param>
    /// <param name="der">The certificate's DER.</param>
    /// <param name="length">Its octets (none past them is read).</param>
    /// <returns>0, or -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_certificate_read")]
    internal static partial int CertificateRead(Certificate* certificate, byte* der, nuint length);

    /// <summary>int httpasm_public_key_read(httpasm_public_key *key, const uint8_t *spki, size_t length).</summary>
    /// <param name="key">Receives the key (all zeros when refused).</param>
    /// <param name="spki">A SubjectPublicKeyInfo's DER.</param>
    /// <param name="length">Its octets.</param>
    /// <returns>The kind (HTTPASM_KEY_*), or -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_public_key_read")]
    internal static partial int PublicKeyRead(PublicKey* key, byte* spki, nuint length);

    /// <summary>int httpasm_private_key_matches(const httpasm_private_key *key, const httpasm_public_key *pub).</summary>
    /// <param name="key">A loaded private key.</param>
    /// <param name="publicKey">A read public key.</param>
    /// <returns>0 for one key pair, else -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_private_key_matches")]
    internal static partial int PrivateKeyMatches(PrivateKey* key, PublicKey* publicKey);

    /// <summary>int httpasm_tls13_extract(int hash, salt, salt_length, ikm, ikm_length, secret).</summary>
    /// <param name="hash">Abi.HashSha256 or Abi.HashSha384.</param>
    /// <param name="salt">The salt (anything when its length is 0).</param>
    /// <param name="saltLength">Its length; 0: Hash.length zeros.</param>
    /// <param name="ikm">The input keying material (anything when its length is 0).</param>
    /// <param name="ikmLength">Its length; 0: TLS's "0", Hash.length zeros.</param>
    /// <param name="secret">Receives Hash.length octets.</param>
    /// <returns>0, or -1 for an unknown hash.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_extract")]
    internal static partial int Tls13Extract(int hash, byte* salt, nuint saltLength, byte* ikm, nuint ikmLength, byte* secret);

    /// <summary>int httpasm_tls13_expand_label(hash, secret, label, label_length, context, context_length, out, length).</summary>
    /// <param name="hash">Abi.HashSha256 or Abi.HashSha384.</param>
    /// <param name="secret">Hash.length octets.</param>
    /// <param name="label">The label without "tls13 ".</param>
    /// <param name="labelLength">1 to 249.</param>
    /// <param name="context">The context (anything when its length is 0).</param>
    /// <param name="contextLength">0 to 255.</param>
    /// <param name="output">Receives length octets.</param>
    /// <param name="length">Up to 255 * Hash.length.</param>
    /// <returns>0, or -1 for a refused argument (nothing written).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_expand_label")]
    internal static partial int Tls13ExpandLabel(int hash, byte* secret, byte* label, nuint labelLength, byte* context, nuint contextLength, byte* output, nuint length);

    /// <summary>int httpasm_tls13_derive_secret(hash, secret, label, label_length, transcript_hash, out).</summary>
    /// <param name="hash">Abi.HashSha256 or Abi.HashSha384.</param>
    /// <param name="secret">Hash.length octets.</param>
    /// <param name="label">The label without "tls13 ".</param>
    /// <param name="labelLength">Its length.</param>
    /// <param name="transcriptHash">Hash.length octets, or null for Hash("").</param>
    /// <param name="output">Receives Hash.length octets.</param>
    /// <returns>0, or -1 for a refused argument.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_derive_secret")]
    internal static partial int Tls13DeriveSecret(int hash, byte* secret, byte* label, nuint labelLength, byte* transcriptHash, byte* output);

    /// <summary>int httpasm_tls13_finished(hash, base_key, transcript_hash, verify_data).</summary>
    /// <param name="hash">Abi.HashSha256 or Abi.HashSha384.</param>
    /// <param name="baseKey">The sender's traffic secret, Hash.length octets.</param>
    /// <param name="transcriptHash">Hash.length octets.</param>
    /// <param name="verifyData">Receives Hash.length octets.</param>
    /// <returns>0, or -1 for an unknown hash.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_finished")]
    internal static partial int Tls13Finished(int hash, byte* baseKey, byte* transcriptHash, byte* verifyData);

    /// <summary>int httpasm_tls13_update_secret(hash, secret, next).</summary>
    /// <param name="hash">Abi.HashSha256 or Abi.HashSha384.</param>
    /// <param name="secret">The current application traffic secret.</param>
    /// <param name="next">Receives the next one (Hash.length octets).</param>
    /// <returns>0, or -1 for an unknown hash.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_update_secret")]
    internal static partial int Tls13UpdateSecret(int hash, byte* secret, byte* next);

    /// <summary>int httpasm_tls13_export(hash, exporter_secret, label, label_length, context, context_length, out, length).</summary>
    /// <param name="hash">Abi.HashSha256 or Abi.HashSha384.</param>
    /// <param name="exporterSecret">The exporter master secret.</param>
    /// <param name="label">The exporter's label (prefixed "tls13 " inside).</param>
    /// <param name="labelLength">Its length.</param>
    /// <param name="context">The context value (anything when its length is 0).</param>
    /// <param name="contextLength">Its length.</param>
    /// <param name="output">Receives length octets.</param>
    /// <param name="length">The key's length.</param>
    /// <returns>0, or -1 for a refused argument.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_export")]
    internal static partial int Tls13Export(int hash, byte* exporterSecret, byte* label, nuint labelLength, byte* context, nuint contextLength, byte* output, nuint length);

    /// <summary>int64_t httpasm_tls_record_length(in, length).</summary>
    /// <param name="input">The octets read.</param>
    /// <param name="length">Their count.</param>
    /// <returns>The first record's length, 0 for more octets, or -22 (record_overflow).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls_record_length")]
    internal static partial long TlsRecordLength(byte* input, nuint length);

    /// <summary>int httpasm_tls13_record_key_init(key, suite, traffic_secret).</summary>
    /// <param name="key">The key to make.</param>
    /// <param name="suite">A cipher suite's code (0x1301, 0x1302, 0x1303).</param>
    /// <param name="trafficSecret">Hash.length octets of the suite's hash.</param>
    /// <returns>0, or -1 for an unknown suite (the key then zeros).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_record_key_init")]
    internal static partial int Tls13RecordKeyInit(Tls13RecordKey* key, int suite, byte* trafficSecret);

    /// <summary>int64_t httpasm_tls13_seal(key, content_type, content, length, padding, out, capacity).</summary>
    /// <param name="key">The writer's key; its sequence number advances.</param>
    /// <param name="contentType">The record's inner content type (1 to 255).</param>
    /// <param name="content">The content (out + 5, or not overlapping out).</param>
    /// <param name="length">Its octets.</param>
    /// <param name="padding">Zero octets to add.</param>
    /// <param name="output">Receives the record.</param>
    /// <param name="capacity">Its room.</param>
    /// <returns>The record's length, -1 for a refused argument, -2 when the key must be updated first.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_seal")]
    internal static partial long Tls13Seal(Tls13RecordKey* key, int contentType, byte* content, nuint length, nuint padding, byte* output, nuint capacity);

    /// <summary>int64_t httpasm_tls13_open(key, record, length, content_type).</summary>
    /// <param name="key">The reader's key; its sequence number advances.</param>
    /// <param name="record">The record, decrypted in place.</param>
    /// <param name="length">Its whole length.</param>
    /// <param name="contentType">Receives the inner content type.</param>
    /// <returns>The content's length, or minus an alert.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_open")]
    internal static partial long Tls13Open(Tls13RecordKey* key, byte* record, nuint length, byte* contentType);

    /// <summary>int64_t httpasm_tls_message(in, length, type, body_length).</summary>
    /// <param name="input">Handshake octets.</param>
    /// <param name="length">Their count.</param>
    /// <param name="type">Receives the first message's type.</param>
    /// <param name="bodyLength">Receives its body's length.</param>
    /// <returns>The message's whole length, or 0 for more octets.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls_message")]
    internal static partial long TlsMessage(byte* input, nuint length, uint* type, nuint* bodyLength);

    /// <summary>int httpasm_tls_extensions_read(ext, message, block, length).</summary>
    /// <param name="extensions">Receives the block's extensions.</param>
    /// <param name="message">The message's HTTPASM_TLS_IN_* bit.</param>
    /// <param name="block">The block's octets after its length.</param>
    /// <param name="length">Their count.</param>
    /// <returns>0, or minus an alert.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls_extensions_read")]
    internal static partial int TlsExtensionsRead(TlsExtensions* extensions, int message, byte* block, nuint length);

    /// <summary>int httpasm_tls13_hello_read(hello, type, body, length).</summary>
    /// <param name="hello">Receives the message's fields.</param>
    /// <param name="type">1 (ClientHello) or 2 (ServerHello).</param>
    /// <param name="body">The body after the handshake header.</param>
    /// <param name="length">Its octets.</param>
    /// <returns>0, minus an alert, or -1 for another type.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_hello_read")]
    internal static partial int Tls13HelloRead(TlsHello* hello, int type, byte* body, nuint length);

    /// <summary>int httpasm_tls13_extensions_message_read(ext, message, body, length).</summary>
    /// <param name="extensions">Receives the block's extensions.</param>
    /// <param name="message">The message's HTTPASM_TLS_IN_* bit.</param>
    /// <param name="body">The block with its uint16 length.</param>
    /// <param name="length">Its octets.</param>
    /// <returns>0, or minus an alert.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_extensions_message_read")]
    internal static partial int Tls13ExtensionsMessageRead(TlsExtensions* extensions, int message, byte* body, nuint length);

    /// <summary>int httpasm_tls13_certificate_request_read(ext, context, context_length, body, length).</summary>
    /// <param name="extensions">Receives the request's extensions.</param>
    /// <param name="context">Receives the context's address.</param>
    /// <param name="contextLength">Receives its length.</param>
    /// <param name="body">The body.</param>
    /// <param name="length">Its octets.</param>
    /// <returns>0, or minus an alert.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_certificate_request_read")]
    internal static partial int Tls13CertificateRequestRead(TlsExtensions* extensions, byte** context, nuint* contextLength, byte* body, nuint length);

    /// <summary>int64_t httpasm_tls13_certificate_read(body, length, context, context_length, list, list_length).</summary>
    /// <param name="body">The body.</param>
    /// <param name="length">Its octets.</param>
    /// <param name="context">Receives the context's address.</param>
    /// <param name="contextLength">Receives its length.</param>
    /// <param name="list">Receives the certificate list's address.</param>
    /// <param name="listLength">Receives its length.</param>
    /// <returns>The entries' count, or minus an alert.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_certificate_read")]
    internal static partial long Tls13CertificateRead(byte* body, nuint length, byte** context, nuint* contextLength, byte** list, nuint* listLength);

    /// <summary>int64_t httpasm_tls13_certificate_entry(list, list_length, offset, cert, cert_length, ext).</summary>
    /// <param name="list">A certificate list, one httpasm_tls13_certificate_read accepted (any other is judged entry by entry, not trusted).</param>
    /// <param name="listLength">Its length.</param>
    /// <param name="offset">The entry's offset.</param>
    /// <param name="cert">Receives the cert_data's address.</param>
    /// <param name="certLength">Receives its length.</param>
    /// <param name="extensions">Receives the entry's extensions.</param>
    /// <returns>The next entry's offset, or minus an alert.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_certificate_entry")]
    internal static partial long Tls13CertificateEntry(byte* list, nuint listLength, nuint offset, byte** cert, nuint* certLength, TlsExtensions* extensions);

    /// <summary>int httpasm_tls13_certificate_verify_read(body, length, scheme, signature, signature_length).</summary>
    /// <param name="body">The body.</param>
    /// <param name="length">Its octets.</param>
    /// <param name="scheme">Receives the SignatureScheme.</param>
    /// <param name="signature">Receives the signature's address.</param>
    /// <param name="signatureLength">Receives its length.</param>
    /// <returns>0, or -50 (decode_error).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_certificate_verify_read")]
    internal static partial int Tls13CertificateVerifyRead(byte* body, nuint length, uint* scheme, byte** signature, nuint* signatureLength);

    /// <summary>int httpasm_tls13_new_session_ticket_read(ext, body, length, lifetime_age_add, nonce, ticket).</summary>
    /// <param name="extensions">Receives the ticket's extensions.</param>
    /// <param name="body">The body.</param>
    /// <param name="length">Its octets.</param>
    /// <param name="lifetimeAgeAdd">Receives the lifetime (low half) and the age_add (high).</param>
    /// <param name="nonce">Receives the nonce's length octet's address.</param>
    /// <param name="ticket">Receives the ticket's uint16 length's address.</param>
    /// <returns>0, or minus an alert.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_new_session_ticket_read")]
    internal static partial int Tls13NewSessionTicketRead(TlsExtensions* extensions, byte* body, nuint length, ulong* lifetimeAgeAdd, byte** nonce, byte** ticket);

    /// <summary>int httpasm_tls13_key_update_read(body, length).</summary>
    /// <param name="body">The body.</param>
    /// <param name="length">Its octets.</param>
    /// <returns>0 or 1, or minus an alert.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_key_update_read")]
    internal static partial int Tls13KeyUpdateRead(byte* body, nuint length);

    /// <summary>int httpasm_tls13_server_config_init(config, chain, lengths, count, buffer, capacity).</summary>
    /// <param name="config">The configuration, its "in" fields set.</param>
    /// <param name="chain">The DER certificates, the leaf first.</param>
    /// <param name="lengths">Their octets.</param>
    /// <param name="count">How many.</param>
    /// <param name="buffer">Where the Certificate message is built (it must outlive the configuration).</param>
    /// <param name="capacity">Its octets.</param>
    /// <returns>0; -1 (a setting refused), -2 (the chain or the key's match), -3 (buffer too small).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_server_config_init")]
    internal static partial int Tls13ServerConfigInit(TlsServerConfig* config, byte** chain, nuint* lengths, nuint count, byte* buffer, nuint capacity);

    /// <summary>int httpasm_tls13_server_init(connection, config, memory, length).</summary>
    /// <param name="connection">The connection to start.</param>
    /// <param name="config">An initialized configuration (kept by pointer).</param>
    /// <param name="memory">The connection's spans (kept until it is wiped).</param>
    /// <param name="length">Their octets: config->memory at least.</param>
    /// <returns>0, or -1 when length is too small.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_server_init")]
    internal static partial int Tls13ServerInit(TlsConnection* connection, TlsServerConfig* config, byte* memory, nuint length);

    /// <summary>int64_t httpasm_tls13_receive(connection, in, length, event).</summary>
    /// <param name="connection">The connection.</param>
    /// <param name="input">What arrived (a protected record is opened in place).</param>
    /// <param name="length">Its octets.</param>
    /// <param name="tlsEvent">Receives what the record brought.</param>
    /// <returns>The record's octets, 0 (more needed), or -1 (failed: see the event).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_receive")]
    internal static partial long Tls13Receive(TlsConnection* connection, byte* input, nuint length, TlsEvent* tlsEvent);

    /// <summary>size_t httpasm_tls13_output(connection, out).</summary>
    /// <param name="connection">The connection.</param>
    /// <param name="output">Receives the first queued octet's address.</param>
    /// <returns>The octets queued.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_output")]
    internal static partial nuint Tls13Output(TlsConnection* connection, byte** output);

    /// <summary>void httpasm_tls13_output_done(connection, n).</summary>
    /// <param name="connection">The connection.</param>
    /// <param name="n">The octets taken.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_output_done")]
    internal static partial void Tls13OutputDone(TlsConnection* connection, nuint n);

    /// <summary>int64_t httpasm_tls13_send(connection, data, length).</summary>
    /// <param name="connection">The connection.</param>
    /// <param name="data">Application data.</param>
    /// <param name="length">Its octets.</param>
    /// <returns>The octets taken, or -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_send")]
    internal static partial long Tls13Send(TlsConnection* connection, byte* data, nuint length);

    /// <summary>int httpasm_tls13_close(connection).</summary>
    /// <param name="connection">The connection.</param>
    /// <returns>0, or -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_close")]
    internal static partial int Tls13Close(TlsConnection* connection);

    /// <summary>int httpasm_tls13_key_update(connection, request).</summary>
    /// <param name="connection">The connection.</param>
    /// <param name="request">Nonzero: update_requested.</param>
    /// <returns>0, or -1.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_key_update")]
    internal static partial int Tls13KeyUpdate(TlsConnection* connection, int request);

    /// <summary>int httpasm_tls13_negotiated(connection, suite, group, scheme).</summary>
    /// <param name="connection">The connection.</param>
    /// <param name="suite">Receives the suite (or null).</param>
    /// <param name="group">Receives the group (or null).</param>
    /// <param name="scheme">Receives the signature scheme (or null).</param>
    /// <returns>0 (no answer yet), 1 (handshaking), 2 (connected), -1 (failed).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_negotiated")]
    internal static partial int Tls13Negotiated(TlsConnection* connection, uint* suite, uint* group, uint* scheme);

    /// <summary>int httpasm_tls13_request_certificate(connection): queues a post-handshake
    /// CertificateRequest (RFC 9846 4.7.2) under the current application key; the client's answer
    /// then comes through <see cref="Tls13Receive"/> and ends with EVENT_AUTHENTICATED. One
    /// request at a time: a second call before that event is refused.</summary>
    /// <param name="connection">A connection past its handshake whose client offered
    /// post_handshake_auth, started with client authentication configured.</param>
    /// <returns>0 (queued: drain the output), or -1 with nothing sent or changed (the reasons:
    /// httpasm.h).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_request_certificate")]
    internal static partial int Tls13RequestCertificate(TlsConnection* connection);

    /// <summary>int httpasm_tls13_peer_certificates(connection, &amp;list, &amp;length): the client's
    /// certificate_list kept by the connection.</summary>
    /// <param name="connection">The connection.</param>
    /// <param name="list">Receives the list (or null).</param>
    /// <param name="length">Receives its octets (or null).</param>
    /// <returns>Its entries (0: an empty Certificate), or -1 before the client's Certificate.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_peer_certificates")]
    internal static partial int Tls13PeerCertificates(TlsConnection* connection, byte** list, nuint* length);

    /// <summary>void httpasm_tls13_wipe(connection).</summary>
    /// <param name="connection">The connection (its spans zeroed too).</param>
    [LibraryImport(Library, EntryPoint = "httpasm_tls13_wipe")]
    internal static partial void Tls13Wipe(TlsConnection* connection);

    /// <summary>size_t httpasm_token_length(const uint8_t *p, size_t n).</summary>
    /// <param name="p">The octets.</param>
    /// <param name="n">How many there are.</param>
    /// <returns>The number of leading octets that are tchar; n when all are.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_token_length")]
    internal static partial nuint TokenLength(byte* p, nuint n);

    /// <summary>size_t httpasm_field_value_scan(const uint8_t *p, size_t n).</summary>
    /// <param name="p">The octets.</param>
    /// <param name="n">How many there are.</param>
    /// <returns>The index of the first octet a field value may not hold; n when none.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_field_value_scan")]
    internal static partial nuint FieldValueScan(byte* p, nuint n);

    /// <summary>uint32_t httpasm_struct_size(uint32_t which).</summary>
    /// <param name="which">1 httpasm_field, 2 httpasm_request, 3 httpasm_h1_limits.</param>
    /// <returns>The library's size of that structure, 0 for another value.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_struct_size")]
    internal static partial uint StructSize(uint which);

    /// <summary>uint32_t httpasm_field_id(const uint8_t *name, size_t n).</summary>
    /// <param name="name">The name.</param>
    /// <param name="n">Its length.</param>
    /// <returns>The known-field id, 0 when not known or not a token.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_field_id")]
    internal static partial uint FieldId(byte* name, nuint n);

    /// <summary>const uint8_t *httpasm_field_name(uint32_t id, size_t *length).</summary>
    /// <param name="id">A known-field id.</param>
    /// <param name="length">Receives the name's length; may be null.</param>
    /// <returns>The lower-case name, or null.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_field_name")]
    internal static partial byte* FieldName(uint id, nuint* length);

    /// <summary>int64_t httpasm_h1_parse_request(buf, len, scan_from, limits, request, fields).</summary>
    /// <param name="buffer">The received octets.</param>
    /// <param name="length">How many.</param>
    /// <param name="scanFrom">The resume point of the search for the head's end.</param>
    /// <param name="limits">The limits, or null for the defaults.</param>
    /// <param name="request">Receives the head.</param>
    /// <param name="fields">Receives the field lines.</param>
    /// <returns>The head's length, 0 when incomplete, or -status.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_parse_request")]
    internal static partial long H1ParseRequest(byte* buffer, nuint length, nuint* scanFrom, H1Limits* limits, HttpRequest* request, HttpField* fields);

    /// <summary>int64_t httpasm_h1_parse_response(buf, len, scan_from, limits, request_method, head, fields).</summary>
    /// <param name="buffer">The received octets (writable: obs-fold is joined in place).</param>
    /// <param name="length">How many.</param>
    /// <param name="scanFrom">The resume point.</param>
    /// <param name="limits">The limits, or null.</param>
    /// <param name="requestMethod">The request's HTTPASM_METHOD_*.</param>
    /// <param name="head">Receives the head.</param>
    /// <param name="fields">Receives the fields.</param>
    /// <returns>The head's length, 0 when incomplete, or -status.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_parse_response")]
    internal static partial long H1ParseResponse(byte* buffer, nuint length, nuint* scanFrom, H1Limits* limits, uint requestMethod, ResponseHead* head, HttpField* fields);

    /// <summary>int64_t httpasm_h1_chunked_decode(state, in, len, produced).</summary>
    /// <param name="state">The decoder's state.</param>
    /// <param name="input">The body octets, decoded in place.</param>
    /// <param name="length">How many.</param>
    /// <param name="produced">Receives the data octets now at the input's start.</param>
    /// <returns>The octets consumed, or -400.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_chunked_decode")]
    internal static partial long H1ChunkedDecode(ChunkedState* state, byte* input, nuint length, nuint* produced);

    /// <summary>int64_t httpasm_h1_parse_trailers(buf, len, scan_from, limits, fields, count).</summary>
    /// <param name="buffer">The octets after the last chunk's line.</param>
    /// <param name="length">How many.</param>
    /// <param name="scanFrom">The resume point.</param>
    /// <param name="limits">The limits, or null.</param>
    /// <param name="fields">Receives the trailer fields.</param>
    /// <param name="count">Receives how many.</param>
    /// <returns>The section's length, 0 when incomplete, or -status.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_parse_trailers")]
    internal static partial long H1ParseTrailers(byte* buffer, nuint length, nuint* scanFrom, H1Limits* limits, HttpField* fields, uint* count);

    /// <summary>int64_t httpasm_h1_write_response(out, cap, response).</summary>
    /// <param name="output">The output buffer.</param>
    /// <param name="capacity">Its size.</param>
    /// <param name="response">The response; its flags come back updated.</param>
    /// <returns>The head's length, 0 if too small, or -error.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_write_response")]
    internal static partial long H1WriteResponse(byte* output, nuint capacity, HttpResponse* response);

    /// <summary>int64_t httpasm_h1_write_request(out, cap, request).</summary>
    /// <param name="output">The output buffer.</param>
    /// <param name="capacity">Its size.</param>
    /// <param name="request">The request's description.</param>
    /// <returns>The head's length, 0 if too small, or -error.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_write_request")]
    internal static partial long H1WriteRequest(byte* output, nuint capacity, HttpRequest* request);

    /// <summary>int64_t httpasm_h1_write_chunk(out, cap, data, len).</summary>
    /// <param name="output">The output buffer.</param>
    /// <param name="capacity">Its size.</param>
    /// <param name="data">The chunk's data.</param>
    /// <param name="length">At least 1.</param>
    /// <returns>The chunk's length, 0 if too small, or -error.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_write_chunk")]
    internal static partial long H1WriteChunk(byte* output, nuint capacity, byte* data, nuint length);

    /// <summary>int64_t httpasm_h1_write_last_chunk(out, cap, trailers, count).</summary>
    /// <param name="output">The output buffer.</param>
    /// <param name="capacity">Its size.</param>
    /// <param name="trailers">The trailer fields, or null.</param>
    /// <param name="count">How many.</param>
    /// <returns>The length, 0 if too small, or -error.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_write_last_chunk")]
    internal static partial long H1WriteLastChunk(byte* output, nuint capacity, HttpField* trailers, uint count);

    /// <summary>size_t httpasm_hpack_size(uint32_t limit).</summary>
    /// <param name="limit">The table's limit.</param>
    /// <returns>The octets its memory needs; 0 past HTTPASM_HPACK_MAX_LIMIT.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_size")]
    internal static partial nuint HpackSize(uint limit);

    /// <summary>int httpasm_hpack_init(void *memory, size_t size, uint32_t limit, uint32_t flags).</summary>
    /// <param name="memory">The table's memory.</param>
    /// <param name="size">Its octets.</param>
    /// <param name="limit">The limit.</param>
    /// <param name="flags">HTTPASM_HPACK_*.</param>
    /// <returns>0, or -HTTPASM_ERROR_HPACK_LIMIT.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_init")]
    internal static partial int HpackInit(byte* memory, nuint size, uint limit, uint flags);

    /// <summary>int httpasm_h2_request(fields, count, request): HTTP/2's rules for a decoded request head.</summary>
    /// <param name="fields">The decoded fields, pseudo-fields first; ids are set by the call.</param>
    /// <param name="count">How many.</param>
    /// <param name="request">Filled: method, target, authority, scheme, flags, regular fields.</param>
    /// <returns>0, or -HTTPASM_ERROR_* (malformed: a stream error PROTOCOL_ERROR).</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h2_request")]
    internal static partial int H2Request(HttpField* fields, uint count, HttpRequest* request);

    /// <summary>int64_t httpasm_hpack_decode(table, block, length, output).</summary>
    /// <param name="table">The decoder's table.</param>
    /// <param name="block">The header block.</param>
    /// <param name="length">Its octets.</param>
    /// <param name="output">Where the fields go.</param>
    /// <returns>0, 1 when the output ran out, or -HTTPASM_ERROR_HPACK_*.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_decode")]
    internal static partial long HpackDecode(byte* table, byte* block, nuint length, HpackOutput* output);

    /// <summary>size_t httpasm_hpack_encode_bound(fields, count).</summary>
    /// <param name="fields">The fields.</param>
    /// <param name="count">How many.</param>
    /// <returns>The most octets the encoding can take.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_encode_bound")]
    internal static partial nuint HpackEncodeBound(HttpField* fields, uint count);

    /// <summary>int64_t httpasm_hpack_encode(table, fields, count, out, cap).</summary>
    /// <param name="table">The encoder's table.</param>
    /// <param name="fields">The fields.</param>
    /// <param name="count">How many.</param>
    /// <param name="output">Where the block goes.</param>
    /// <param name="cap">Its room.</param>
    /// <returns>The block's length, or 0 when cap is below the bound.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_encode")]
    internal static partial long HpackEncode(byte* table, HttpField* fields, uint count, byte* output, nuint cap);

    /// <summary>void httpasm_hpack_encoder_limit(table, limit).</summary>
    /// <param name="table">The encoder's table.</param>
    /// <param name="limit">The peer's SETTINGS_HEADER_TABLE_SIZE.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_encoder_limit")]
    internal static partial void HpackEncoderLimit(byte* table, uint limit);

    /// <summary>uint32_t httpasm_hpack_table_size(table, uint32_t *max_size).</summary>
    /// <param name="table">The table.</param>
    /// <param name="maxSize">Receives the maximum, or null.</param>
    /// <returns>The dynamic table's size.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_table_size")]
    internal static partial uint HpackTableSize(byte* table, uint* maxSize);

    /// <summary>int httpasm_hpack_entry(table, index, field).</summary>
    /// <param name="table">The table.</param>
    /// <param name="index">An HPACK index.</param>
    /// <param name="field">Receives the entry.</param>
    /// <returns>0, or -HTTPASM_ERROR_HPACK_INDEX.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_entry")]
    internal static partial int HpackEntry(byte* table, uint index, HttpField* field);

    /// <summary>httpasm_client *httpasm_client_connect(address, port, timeout_ms, int *error).</summary>
    /// <param name="address">IPv4, network byte order.</param>
    /// <param name="port">The port.</param>
    /// <param name="timeoutMs">The connect and I/O timeout (0: none).</param>
    /// <param name="error">Receives -errno on failure.</param>
    /// <returns>The client, or null.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_client_connect")]
    internal static partial nint ClientConnect(uint address, ushort port, uint timeoutMs, int* error);

    /// <summary>int httpasm_client_send(client, request, body, length, response).</summary>
    /// <param name="client">The client.</param>
    /// <param name="request">The request.</param>
    /// <param name="body">The body.</param>
    /// <param name="length">Its length.</param>
    /// <param name="response">Receives the response.</param>
    /// <returns>0, -HTTPASM_ERROR_*, or -errno.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_client_send")]
    internal static partial int ClientSend(nint client, HttpRequest* request, byte* body, nuint length, ClientResponse* response);

    /// <summary>void httpasm_client_close(client).</summary>
    /// <param name="client">The client.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_client_close")]
    internal static partial void ClientClose(nint client);

    /// <summary>httpasm_server *httpasm_server_create(options, int *error).</summary>
    /// <param name="options">The options.</param>
    /// <param name="error">Receives -errno on failure.</param>
    /// <returns>The server, or null.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_server_create")]
    internal static partial nint ServerCreate(ServerOptions* options, int* error);

    /// <summary>int httpasm_server_start(server).</summary>
    /// <param name="server">The server.</param>
    /// <returns>0 or -errno.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_server_start")]
    internal static partial int ServerStart(nint server);

    /// <summary>uint16_t httpasm_server_port(server).</summary>
    /// <param name="server">The server.</param>
    /// <returns>The port it listens on.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_server_port")]
    internal static partial ushort ServerPort(nint server);

    /// <summary>uint32_t httpasm_server_io(server).</summary>
    /// <param name="server">The server.</param>
    /// <returns>What its workers use: <see cref="ServerIo.Uring"/>, <see cref="ServerIo.Epoll"/>,
    /// or <see cref="ServerIo.None"/> when it is not running.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_server_io")]
    internal static partial uint ServerIoUsed(nint server);

    /// <summary>void httpasm_server_stop(server).</summary>
    /// <param name="server">The server.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_server_stop")]
    internal static partial void ServerStop(nint server);

    /// <summary>void httpasm_server_destroy(server).</summary>
    /// <param name="server">The server.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_server_destroy")]
    internal static partial void ServerDestroy(nint server);

    /// <summary>const httpasm_request *httpasm_exchange_request(exchange).</summary>
    /// <param name="exchange">The exchange.</param>
    /// <returns>The request.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_exchange_request")]
    internal static partial HttpRequest* ExchangeRequest(nint exchange);

    /// <summary>const uint8_t *httpasm_exchange_body(exchange, size_t *length).</summary>
    /// <param name="exchange">The exchange.</param>
    /// <param name="length">Receives the body's length.</param>
    /// <returns>The body.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_exchange_body")]
    internal static partial byte* ExchangeBody(nint exchange, nuint* length);

    /// <summary>const httpasm_field *httpasm_exchange_trailers(exchange, uint32_t *count).</summary>
    /// <param name="exchange">The exchange.</param>
    /// <param name="count">Receives how many.</param>
    /// <returns>The trailer fields.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_exchange_trailers")]
    internal static partial HttpField* ExchangeTrailers(nint exchange, uint* count);

    /// <summary>int httpasm_exchange_defer(exchange).</summary>
    /// <param name="exchange">The exchange.</param>
    /// <returns>0 or -EINVAL.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_exchange_defer")]
    internal static partial int ExchangeDefer(nint exchange);

    /// <summary>int httpasm_exchange_respond(exchange, status, fields, count, body, length).</summary>
    /// <param name="exchange">The exchange.</param>
    /// <param name="status">The status.</param>
    /// <param name="fields">The fields.</param>
    /// <param name="count">How many.</param>
    /// <param name="body">The body.</param>
    /// <param name="length">Its length.</param>
    /// <returns>0 or a negative error.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_exchange_respond")]
    internal static partial int ExchangeRespond(nint exchange, ushort status, HttpField* fields, uint count, byte* body, nuint length);

    /// <summary>void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset).</summary>
    /// <param name="addr">A placement hint; zero lets the kernel choose.</param>
    /// <param name="length">The mapping's size in bytes.</param>
    /// <param name="prot">PROT_* bits.</param>
    /// <param name="flags">MAP_* bits.</param>
    /// <param name="fd">-1 for an anonymous mapping.</param>
    /// <param name="offset">0 for an anonymous mapping.</param>
    /// <returns>The mapping's address, or -1 (MAP_FAILED) with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "mmap", SetLastError = true)]
    internal static partial nint Mmap(nint addr, nuint length, int prot, int flags, int fd, nint offset);

    /// <summary>int mprotect(void *addr, size_t len, int prot).</summary>
    /// <param name="addr">A page-aligned address.</param>
    /// <param name="length">The range's size in bytes.</param>
    /// <param name="prot">PROT_* bits.</param>
    /// <returns>0, or -1 with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "mprotect", SetLastError = true)]
    internal static partial int Mprotect(nint addr, nuint length, int prot);

    /// <summary>int munmap(void *addr, size_t length).</summary>
    /// <param name="addr">The mapping's address.</param>
    /// <param name="length">Its size in bytes.</param>
    /// <returns>0, or -1 with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "munmap", SetLastError = true)]
    internal static partial int Munmap(nint addr, nuint length);

    /// <summary>uint64_t httpasm_cpu_found(void).</summary>
    /// <returns>The HTTPASM_CPU_* bits the CPU and the OS offer.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_cpu_found")]
    internal static partial ulong CpuFound();

    /// <summary>uint64_t httpasm_cpu_features(void).</summary>
    /// <returns>The HTTPASM_CPU_* bits the library uses.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_cpu_features")]
    internal static partial ulong CpuFeatures();

    /// <summary>uint64_t httpasm_cpu_limit(uint64_t cap).</summary>
    /// <param name="cap">The new cap (it replaces HTTPASM_CPU's).</param>
    /// <returns>The bits the library uses from now on.</returns>
    /// <remarks>
    /// Process-wide. Every tier computes the same results, so other tests are unaffected, but a
    /// test that reads the features back must not run beside another that changes them: such
    /// tests live in <see cref="SerialCollection"/> and restore the cap they found.
    /// </remarks>
    [LibraryImport(Library, EntryPoint = "httpasm_cpu_limit")]
    internal static partial ulong CpuLimit(ulong cap);

    /// <summary>int setenv(const char *name, const char *value, int overwrite).</summary>
    /// <param name="name">The variable.</param>
    /// <param name="value">Its value.</param>
    /// <param name="overwrite">Nonzero to replace an existing value.</param>
    /// <returns>0, or -1 with errno set.</returns>
    /// <remarks>
    /// The C library's own environment, which a native library's getenv reads: .NET's
    /// Environment.SetEnvironmentVariable changes only the managed copy on Linux. Not safe while
    /// another thread calls getenv: callers run in <see cref="SerialCollection"/>.
    /// </remarks>
    [LibraryImport(Libc, EntryPoint = "setenv", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int SetEnv(string name, string value, int overwrite);

    /// <summary>int unsetenv(const char *name).</summary>
    /// <param name="name">The variable.</param>
    /// <returns>0, or -1 with errno set.</returns>
    /// <remarks>Same caveat as <see cref="SetEnv"/>.</remarks>
    [LibraryImport(Libc, EntryPoint = "unsetenv", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int UnsetEnv(string name);

    /// <summary>The io_uring_setup system call's number on x86-64.</summary>
    internal const long SysIoUringSetup = 425;

    /// <summary>long syscall(long number, ...), called with io_uring_setup's two arguments.</summary>
    /// <param name="number"><see cref="SysIoUringSetup"/>.</param>
    /// <param name="entries">The SQ ring's size to ask for.</param>
    /// <param name="parameters">struct io_uring_params (120 octets, zeroed): the kernel fills it.</param>
    /// <returns>The ring's descriptor, or -1 with errno set (ENOMEM past RLIMIT_MEMLOCK on a
    /// kernel that charges rings to it; EPERM or ENOSYS where io_uring is refused).</returns>
    /// <remarks>
    /// glibc's syscall is variadic, but on x86-64 it is assembly that only moves its integer
    /// arguments into place and ignores the vector-register count a variadic call passes in al,
    /// so this fixed-argument import calls it correctly. The caller closes a descriptor it gets.
    /// </remarks>
    [LibraryImport(Libc, EntryPoint = "syscall", SetLastError = true)]
    internal static partial long SyscallIoUringSetup(long number, long entries, byte* parameters);

    /// <summary>int close(int fd).</summary>
    /// <param name="fd">The descriptor.</param>
    /// <returns>0, or -1 with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "close", SetLastError = true)]
    internal static partial int Close(int fd);

    /// <summary>getrlimit's and setrlimit's RLIMIT_MEMLOCK on Linux x64.</summary>
    internal const int RlimitMemlock = 8;

    /// <summary>int getrlimit(int resource, struct rlimit *rlim).</summary>
    /// <param name="resource">RLIMIT_* (<see cref="RlimitMemlock"/>).</param>
    /// <param name="limit">Receives the soft and the hard limit.</param>
    /// <returns>0, or -1 with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "getrlimit", SetLastError = true)]
    internal static partial int GetRlimit(int resource, out Rlimit limit);

    /// <summary>int setrlimit(int resource, const struct rlimit *rlim).</summary>
    /// <param name="resource">RLIMIT_* (<see cref="RlimitMemlock"/>).</param>
    /// <param name="limit">The new soft and hard limit.</param>
    /// <returns>0, or -1 with errno set (EPERM: raising a hard limit without the privilege).</returns>
    /// <remarks>
    /// Process-wide: every thread of the test process sees the new limit at once, so a test that
    /// lowers one must not run beside others that depend on it (see
    /// <see cref="SerialCollection"/>), and must put the old one back.
    /// </remarks>
    [LibraryImport(Libc, EntryPoint = "setrlimit", SetLastError = true)]
    internal static partial int SetRlimit(int resource, in Rlimit limit);
}

/// <summary>struct rlimit on Linux x64: the soft limit, then the hard one (RLIM_INFINITY = ~0).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct Rlimit
{
    /// <summary>rlim_cur: what the kernel enforces now; any process may lower or raise it up to <see cref="Max"/>.</summary>
    public ulong Current;

    /// <summary>rlim_max: the ceiling for <see cref="Current"/>; only privilege raises it.</summary>
    public ulong Max;
}
