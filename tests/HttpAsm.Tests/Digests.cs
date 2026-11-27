using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// Digests by the names the vector files use, for the signature tests (P256Tests, RsaTests):
/// .NET's SHA-1 and SHA-2 hashes, and SHA-224, which .NET does not offer, written out here.
/// </summary>
internal static class Digests
{
    /// <summary>A message's digest by the hash a vector file names ("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA512").</summary>
    /// <param name="hash">The name.</param>
    /// <param name="message">The message.</param>
    /// <returns>The digest.</returns>
    /// <exception cref="InvalidDataException">An unknown hash.</exception>
    public static byte[] Digest(string hash, byte[] message) => hash.Replace("-", "", StringComparison.Ordinal) switch
    {
        "SHA1" => SHA1.HashData(message),
        "SHA224" => Sha224(message),
        "SHA256" => SHA256.HashData(message),
        "SHA384" => SHA384.HashData(message),
        "SHA512" => SHA512.HashData(message),
        _ => throw new InvalidDataException("unknown hash " + hash),
    };

    /// <summary>
    /// SHA-224 (FIPS 180-4 6.3: SHA-256 from its own initial value, the digest cut to 28 octets),
    /// which .NET does not offer and which RFC 6979's and the CAVP files' P-256 vectors use.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <returns>The 28-octet digest.</returns>
    public static byte[] Sha224(byte[] message)
    {
        uint[] k =
        [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];
        uint[] h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
        int padded = (message.Length + 9 + 63) / 64 * 64;
        byte[] data = new byte[padded];
        message.CopyTo(data, 0);
        data[message.Length] = 0x80;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(padded - 8), (ulong)message.Length * 8);
        uint[] w = new uint[64];
        for (int block = 0; block < padded; block += 64)
        {
            for (int t = 0; t < 16; t++)
            {
                w[t] = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(block + 4 * t));
            }

            for (int t = 16; t < 64; t++)
            {
                uint s0 = BitOperations.RotateRight(w[t - 15], 7) ^ BitOperations.RotateRight(w[t - 15], 18) ^ (w[t - 15] >> 3);
                uint s1 = BitOperations.RotateRight(w[t - 2], 17) ^ BitOperations.RotateRight(w[t - 2], 19) ^ (w[t - 2] >> 10);
                w[t] = w[t - 16] + s0 + w[t - 7] + s1;
            }

            uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (int t = 0; t < 64; t++)
            {
                uint t1 = hh + (BitOperations.RotateRight(e, 6) ^ BitOperations.RotateRight(e, 11) ^ BitOperations.RotateRight(e, 25)) + ((e & f) ^ (~e & g)) + k[t] + w[t];
                uint t2 = (BitOperations.RotateRight(a, 2) ^ BitOperations.RotateRight(a, 13) ^ BitOperations.RotateRight(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
                (hh, g, f, e, d, c, b, a) = (g, f, e, d + t1, c, b, a, t1 + t2);
            }

            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
            h[4] += e;
            h[5] += f;
            h[6] += g;
            h[7] += hh;
        }

        byte[] digest = new byte[28];
        for (int i = 0; i < 7; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(digest.AsSpan(4 * i), h[i]);
        }

        return digest;
    }
}
