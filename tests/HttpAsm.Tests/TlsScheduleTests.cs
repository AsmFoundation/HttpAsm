using System.Security.Cryptography;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// TLS 1.3's key schedule (tls/schedule.asm) through the C ABI: every secret, key, IV, Finished
/// value, PSK binder and resumption secret of RFC 8448's five traces (read from the pinned RFC,
/// <see cref="Rfc8448"/>), each HkdfLabel the traces print checked against this test's own
/// model of it; a differential against .NET's HKDF and HMAC over both hashes, random secrets,
/// labels, contexts and lengths, the exporter included; and every argument HkdfLabel cannot
/// hold, refused with nothing written.
/// </summary>
public sealed unsafe class TlsScheduleTests
{
    /// <summary>HkdfLabel (RFC 9846 7.1): uint16 length, "tls13 " + label, the context, each
    /// opaque vector with its one-octet length. This test's model, independent of the
    /// assembly's.</summary>
    /// <param name="length">The output's length.</param>
    /// <param name="label">The label without "tls13 ".</param>
    /// <param name="context">The context.</param>
    /// <returns>The encoding.</returns>
    private static byte[] HkdfLabel(int length, string label, byte[] context)
    {
        byte[] full = Encoding.ASCII.GetBytes("tls13 " + label);
        return [(byte)(length >> 8), (byte)length, (byte)full.Length, .. full, (byte)context.Length, .. context];
    }

    /// <summary>The .NET name of a hash id.</summary>
    /// <param name="hash">Abi.HashSha256 or Abi.HashSha384.</param>
    /// <returns>Its HashAlgorithmName.</returns>
    private static HashAlgorithmName Name(int hash) => hash == Abi.HashSha384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;

    /// <summary>A hash id's digest length.</summary>
    /// <param name="hash">Abi.HashSha256 or Abi.HashSha384.</param>
    /// <returns>32 or 48.</returns>
    private static int Length(int hash) => hash == Abi.HashSha384 ? 48 : 32;

    /// <summary>HKDF-Expand-Label by the library.</summary>
    /// <param name="hash">The hash id.</param>
    /// <param name="secret">The secret.</param>
    /// <param name="label">The label without "tls13 ".</param>
    /// <param name="context">The context.</param>
    /// <param name="length">The output's length.</param>
    /// <returns>The output; null when refused.</returns>
    internal static byte[]? ExpandLabel(int hash, byte[] secret, string label, byte[] context, int length)
    {
        byte[] l = Encoding.ASCII.GetBytes(label);
        byte[] output = new byte[length];
        fixed (byte* s = secret)
        fixed (byte* lp = l)
        fixed (byte* c = context)
        fixed (byte* o = output)
        {
            return Native.Tls13ExpandLabel(hash, s, lp, (nuint)l.Length, c, (nuint)context.Length, o, (nuint)length) == 0 ? output : null;
        }
    }

    /// <summary>HKDF-Expand-Label by the model: .NET's HKDF.Expand over <see cref="HkdfLabel"/>.</summary>
    /// <param name="hash">The hash id.</param>
    /// <param name="secret">The secret.</param>
    /// <param name="label">The label without "tls13 ".</param>
    /// <param name="context">The context.</param>
    /// <param name="length">The output's length.</param>
    /// <returns>The output.</returns>
    private static byte[] ModelExpandLabel(int hash, byte[] secret, string label, byte[] context, int length) =>
        HKDF.Expand(Name(hash), secret, length, HkdfLabel(length, label, context));

    /// <summary>The Finished value by the library.</summary>
    /// <param name="hash">The hash id.</param>
    /// <param name="baseKey">The traffic secret.</param>
    /// <param name="transcript">The transcript hash.</param>
    /// <returns>verify_data.</returns>
    private static byte[] Finished(int hash, byte[] baseKey, byte[] transcript)
    {
        byte[] verify = new byte[Length(hash)];
        fixed (byte* k = baseKey)
        fixed (byte* t = transcript)
        fixed (byte* v = verify)
        {
            Assert.Equal(0, Native.Tls13Finished(hash, k, t, v));
        }

        return verify;
    }

    /// <summary>
    /// RFC 8448's five traces, step by step: each "extract secret" step's secret from its salt
    /// and IKM (TLS's "0" for an absent IKM, HKDF's own zeros for an absent salt); each "derive
    /// secret" step's output, by Derive-Secret and by HKDF-Expand-Label both, its HkdfLabel the
    /// model's; each traffic key and IV; each Finished key and Finished value (the transcript
    /// hashed here from the messages the trace constructs, HelloRetryRequest's message_hash
    /// rule of RFC 9846 4.4.1 applied in section 5) and each PSK binder; each resumption secret.
    /// </summary>
    [Fact]
    public void DerivesEverySecretOfRfc8448sTraces()
    {
        Platform.RequireLinuxX64();
        int extracts = 0, derives = 0, keys = 0, finished = 0, resumptions = 0;
        // the handshake messages of the section so far, and where the last record sent ended in
        // them: an unprotected record's payload replaces what was constructed since (a
        // ClientHello is printed before its PSK binders, and sent with them)
        var messages = new List<byte[]>();
        int sent = 0, section = 0;
        foreach (Rfc8448.Step step in Rfc8448.Steps)
        {
            IReadOnlyDictionary<string, byte[]> f = step.Fields;
            if (step.Section != section)
            {
                section = step.Section;
                messages.Clear();
                sent = 0;
            }

            if (step.Action.StartsWith("construct a", StringComparison.Ordinal) && f.Count == 1)
            {
                messages.Add(f.Values.Single());
                continue;
            }

            if (step.Action == "send handshake record" && f.TryGetValue("complete record", out byte[]? record))
            {
                if (record[0] == Abi.TlsHandshake)
                {
                    messages.RemoveRange(sent, messages.Count - sent);
                    messages.Add(f["payload"]);
                }

                sent = messages.Count;
                continue;
            }

            if (step.Action.StartsWith("extract secret", StringComparison.Ordinal) && f.TryGetValue("secret", out byte[]? secret))
            {
                byte[] salt = f.GetValueOrDefault("salt") ?? [];
                byte[] ikm = f["IKM"];
                byte[] ours = new byte[32];
                fixed (byte* s = salt)
                fixed (byte* i = ikm)
                fixed (byte* o = ours)
                {
                    Assert.Equal(0, Native.Tls13Extract(Abi.HashSha256, s, (nuint)salt.Length, i, (nuint)ikm.Length, o));
                }

                Assert.True(secret.SequenceEqual(ours), $"section {step.Section}, {step.Who}: {step.Action}");
                if (ikm.All(b => b == 0))
                {
                    // TLS's "0": an IKM of no octets is Hash.length zeros
                    fixed (byte* s = salt)
                    fixed (byte* o = ours)
                    {
                        Assert.Equal(0, Native.Tls13Extract(Abi.HashSha256, s, (nuint)salt.Length, null, 0, o));
                    }

                    Assert.True(secret.SequenceEqual(ours), $"section {step.Section}: no IKM");
                }

                extracts++;
            }
            else if (step.Action.StartsWith("derive secret", StringComparison.Ordinal) && f.TryGetValue("expanded", out byte[]? expanded))
            {
                string label = step.Label!;
                Assert.Equal(f["info"], HkdfLabel(32, label, f["hash"]));
                Assert.Equal(expanded, ExpandLabel(Abi.HashSha256, f["PRK"], label, f["hash"], 32));
                byte[] derived = new byte[32];
                byte[] l = Encoding.ASCII.GetBytes(label);
                byte[] prk = f["PRK"], hash = f["hash"];
                fixed (byte* p = prk)
                fixed (byte* lp = l)
                fixed (byte* h = hash)
                fixed (byte* d = derived)
                {
                    Assert.Equal(0, Native.Tls13DeriveSecret(Abi.HashSha256, p, lp, (nuint)l.Length, h, d));
                }

                Assert.True(expanded.SequenceEqual(derived), $"section {step.Section}, {step.Who}: {step.Action}");
                if (label == "derived")
                {
                    // the hash of no messages: a NULL transcript hash
                    fixed (byte* p = prk)
                    fixed (byte* lp = l)
                    fixed (byte* d = derived)
                    {
                        Assert.Equal(0, Native.Tls13DeriveSecret(Abi.HashSha256, p, lp, (nuint)l.Length, null, d));
                    }

                    Assert.True(expanded.SequenceEqual(derived), $"section {step.Section}: derived from Hash(\"\")");
                }

                derives++;
            }
            else if (step.Action.Contains("traffic keys", StringComparison.Ordinal) && f.TryGetValue("key expanded", out byte[]? key))
            {
                Assert.Equal(f["key info"], HkdfLabel(key.Length, "key", []));
                Assert.Equal(f["iv info"], HkdfLabel(12, "iv", []));
                Assert.Equal(key, ExpandLabel(Abi.HashSha256, f["PRK"], "key", [], key.Length));
                Assert.Equal(f["iv expanded"], ExpandLabel(Abi.HashSha256, f["PRK"], "iv", [], 12));
                keys++;
            }
            else if (step.Action.StartsWith("calculate", StringComparison.Ordinal) && f.TryGetValue("finished", out byte[]? value))
            {
                Assert.Equal(f["info"], HkdfLabel(32, "finished", []));
                Assert.Equal(f["expanded"], ExpandLabel(Abi.HashSha256, f["PRK"], "finished", [], 32));
                // a PSK binder hashes the ClientHello up to its binders (given); a Finished the
                // messages so far
                byte[] context = f.GetValueOrDefault("binder hash") ?? TranscriptHash(messages);
                Assert.True(value.SequenceEqual(Finished(Abi.HashSha256, f["PRK"], context)), $"section {step.Section}, {step.Who}: {step.Action}");
                finished++;
            }
            else if (step.Action.StartsWith("generate resumption secret", StringComparison.Ordinal) && f.TryGetValue("expanded", out byte[]? resumption))
            {
                Assert.Equal(f["info"], HkdfLabel(32, "resumption", f["hash"]));
                Assert.Equal(resumption, ExpandLabel(Abi.HashSha256, f["PRK"], "resumption", f["hash"], 32));
                resumptions++;
            }
        }

        // every trace was read: the counts of what the RFC prints with octets
        Assert.True(extracts >= 15, $"{extracts} extractions");
        Assert.True(derives >= 30, $"{derives} derived secrets");
        Assert.True(keys >= 15, $"{keys} key derivations");
        Assert.True(finished >= 10, $"{finished} Finished values and binders");
        Assert.True(resumptions >= 1, $"{resumptions} resumption secrets");
    }

    /// <summary>The ServerHello random that makes it a HelloRetryRequest (RFC 9846 4.1.3):
    /// SHA-256 of "HelloRetryRequest".</summary>
    private static readonly byte[] HelloRetryRandom = SHA256.HashData(Encoding.ASCII.GetBytes("HelloRetryRequest"));

    /// <summary>
    /// Transcript-Hash over handshake messages (RFC 9846 4.4.1), SHA-256: their concatenation's
    /// hash, except that when a HelloRetryRequest (a ServerHello carrying its random) is among
    /// them, the messages before it (ClientHello1) stand as the synthetic message_hash message:
    /// FE 00 00 20 and Hash(ClientHello1).
    /// </summary>
    /// <param name="messages">The messages, each whole (its four-octet header first).</param>
    /// <returns>The transcript hash.</returns>
    private static byte[] TranscriptHash(List<byte[]> messages)
    {
        int retry = messages.FindIndex(m => m.Length >= 38 && m[0] == 2 && m.AsSpan(6, 32).SequenceEqual(HelloRetryRandom));
        if (retry < 0)
        {
            return SHA256.HashData([.. messages.SelectMany(m => m)]);
        }

        byte[] first = SHA256.HashData([.. messages.Take(retry).SelectMany(m => m)]);
        return SHA256.HashData([0xFE, 0x00, 0x00, 0x20, .. first, .. messages.Skip(retry).SelectMany(m => m)]);
    }

    /// <summary>
    /// The library against .NET's HKDF and HMAC (an independent implementation) over both
    /// hashes: HKDF-Extract with and without salt and IKM, HKDF-Expand-Label for 400 random
    /// secrets, labels of 1 to 249 octets, contexts of 0 to 255 and lengths of 1 to 255 *
    /// Hash.length, Derive-Secret, the Finished value, the traffic secret's update and the
    /// exporter (the same value with no context and an empty one).
    /// </summary>
    [Fact]
    public void MatchesDotNetsHkdf()
    {
        Platform.RequireLinuxX64();
        var random = new Random(8448);
        foreach (int hash in new[] { Abi.HashSha256, Abi.HashSha384 })
        {
            int n = Length(hash);
            for (int i = 0; i < 200; i++)
            {
                byte[] secret = RandomNumberGenerator.GetBytes(n);
                string label = new(Enumerable.Range(0, random.Next(1, 250)).Select(_ => (char)random.Next('a', 'z' + 1)).ToArray());
                byte[] context = RandomNumberGenerator.GetBytes(random.Next(0, 256));
                int length = i % 10 == 0 ? 255 * n : random.Next(1, 3 * n);
                Assert.Equal(ModelExpandLabel(hash, secret, label, context, length), ExpandLabel(hash, secret, label, context, length));

                byte[] salt = RandomNumberGenerator.GetBytes(random.Next(0, 2 * n));
                byte[] ikm = RandomNumberGenerator.GetBytes(random.Next(1, 2 * n));
                byte[] extracted = new byte[n];
                fixed (byte* s = salt)
                fixed (byte* k = ikm)
                fixed (byte* o = extracted)
                {
                    Assert.Equal(0, Native.Tls13Extract(hash, s, (nuint)salt.Length, k, (nuint)ikm.Length, o));
                }

                Assert.Equal(HKDF.Extract(Name(hash), ikm, salt), extracted);

                byte[] transcript = RandomNumberGenerator.GetBytes(n);
                byte[] finishedKey = ModelExpandLabel(hash, secret, "finished", [], n);
                byte[] mac = hash == Abi.HashSha384 ? HMACSHA384.HashData(finishedKey, transcript) : HMACSHA256.HashData(finishedKey, transcript);
                Assert.Equal(mac, Finished(hash, secret, transcript));

                byte[] next = new byte[n];
                fixed (byte* s = secret)
                fixed (byte* x = next)
                {
                    Assert.Equal(0, Native.Tls13UpdateSecret(hash, s, x));
                }

                Assert.Equal(ModelExpandLabel(hash, secret, "traffic upd", [], n), next);

                // the exporter: Expand-Label(Derive-Secret(secret, label, ""), "exporter", Hash(context), length)
                string exportLabel = "EXPORTER-" + label[..Math.Min(label.Length, 200)];
                byte[] exportContext = RandomNumberGenerator.GetBytes(random.Next(0, 100));
                byte[] derived = ModelExpandLabel(hash, secret, exportLabel, hash == Abi.HashSha384 ? SHA384.HashData([]) : SHA256.HashData([]), n);
                byte[] contextHash = hash == Abi.HashSha384 ? SHA384.HashData(exportContext) : SHA256.HashData(exportContext);
                byte[] expected = ModelExpandLabel(hash, derived, "exporter", contextHash, 64);
                Assert.Equal(expected, Export(hash, secret, exportLabel, exportContext, 64));
            }

            byte[] any = RandomNumberGenerator.GetBytes(n);
            Assert.Equal(Export(hash, any, "EXPORTER-x", [], 32), Export(hash, any, "EXPORTER-x", null, 32));
        }
    }

    /// <summary>The exporter by the library.</summary>
    /// <param name="hash">The hash id.</param>
    /// <param name="secret">The exporter master secret.</param>
    /// <param name="label">The exporter's label.</param>
    /// <param name="context">The context value, or null for none (a NULL pointer).</param>
    /// <param name="length">The key's length.</param>
    /// <returns>The keying material; null when refused.</returns>
    private static byte[]? Export(int hash, byte[] secret, string label, byte[]? context, int length)
    {
        byte[] l = Encoding.ASCII.GetBytes(label);
        byte[] output = new byte[length];
        fixed (byte* s = secret)
        fixed (byte* lp = l)
        fixed (byte* c = context)
        fixed (byte* o = output)
        {
            return Native.Tls13Export(hash, s, lp, (nuint)l.Length, c, (nuint)(context?.Length ?? 0), o, (nuint)length) == 0 ? output : null;
        }
    }

    /// <summary>
    /// What HkdfLabel cannot hold is refused with nothing written: a label of no octets or of
    /// 250 (with "tls13 ", over its 255), a context of 256, a length over 255 * Hash.length, and
    /// a hash other than SHA-256 and SHA-384, by every function; the limits themselves are
    /// taken (a label of 249, a context of 255, 255 * Hash.length octets).
    /// </summary>
    [Fact]
    public void RefusesWhatHkdfLabelCannotHold()
    {
        Platform.RequireLinuxX64();
        foreach (int hash in new[] { Abi.HashSha256, Abi.HashSha384 })
        {
            int n = Length(hash);
            byte[] secret = RandomNumberGenerator.GetBytes(n);
            Assert.NotNull(ExpandLabel(hash, secret, new string('a', 249), new byte[255], 255 * n));
            Assert.Null(ExpandLabel(hash, secret, "", [], 16));
            Assert.Null(ExpandLabel(hash, secret, new string('a', 250), [], 16));
            Assert.Null(ExpandLabel(hash, secret, "key", new byte[256], 16));
            Assert.Null(ExpandLabel(hash, secret, "key", [], 255 * n + 1));
            Assert.Null(Export(hash, secret, new string('a', 250), [], 16));
            Assert.Null(Export(hash, secret, "EXPORTER-x", [], 255 * n + 1));
        }

        byte[] s32 = new byte[48];
        byte[] output = new byte[48];
        byte[] l = "key"u8.ToArray();
        foreach (int hash in new[] { 0, 1, 2, 5, 6, -1 })
        {
            Array.Fill(output, (byte)0xEE);
            fixed (byte* s = s32)
            fixed (byte* o = output)
            fixed (byte* lp = l)
            {
                Assert.Equal(-1, Native.Tls13Extract(hash, null, 0, null, 0, o));
                Assert.Equal(-1, Native.Tls13ExpandLabel(hash, s, lp, 3, null, 0, o, 16));
                Assert.Equal(-1, Native.Tls13DeriveSecret(hash, s, lp, 3, null, o));
                Assert.Equal(-1, Native.Tls13Finished(hash, s, s, o));
                Assert.Equal(-1, Native.Tls13UpdateSecret(hash, s, o));
                Assert.Equal(-1, Native.Tls13Export(hash, s, lp, 3, null, 0, o, 16));
            }

            Assert.True(output.All(b => b == 0xEE), $"hash {hash}: written");
        }
    }
}
