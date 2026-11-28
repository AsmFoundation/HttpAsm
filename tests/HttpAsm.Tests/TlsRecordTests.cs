using System.Security.Cryptography;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// TLS 1.3's record layer (tls/record.asm) through the C ABI: every protected record of RFC
/// 8448's five traces sealed octet for octet from its keys and opened back (read from the pinned
/// RFC, <see cref="Rfc8448"/>), the unprotected ones framed; the three cipher suites against
/// .NET's AesGcm and ChaCha20Poly1305 (an independent AEAD) over random contents, paddings,
/// types and sequence numbers, both ways; and every limit and refusal of RFC 9846 5.
/// </summary>
public sealed unsafe class TlsRecordTests
{
    /// <summary>A record key made by the library.</summary>
    /// <param name="suite">The suite's code.</param>
    /// <param name="secret">The traffic secret.</param>
    /// <returns>The key.</returns>
    private static Tls13RecordKey Key(int suite, byte[] secret)
    {
        Tls13RecordKey key;
        fixed (byte* s = secret)
        {
            Assert.Equal(0, Native.Tls13RecordKeyInit(&key, suite, s));
        }

        return key;
    }

    /// <summary>Seals one record with a copy of the key at a sequence number.</summary>
    /// <param name="key">The key (its sequence number set by the caller).</param>
    /// <param name="type">The content type.</param>
    /// <param name="content">The content.</param>
    /// <param name="padding">Zero octets to add.</param>
    /// <returns>The record, or null with the answer when refused.</returns>
    private static (byte[]? Record, long Answer) Seal(ref Tls13RecordKey key, int type, byte[] content, int padding)
    {
        byte[] output = new byte[content.Length + padding + 32];
        long n;
        fixed (Tls13RecordKey* k = &key)
        fixed (byte* c = content)
        fixed (byte* o = output)
        {
            n = Native.Tls13Seal(k, type, c, (nuint)content.Length, (nuint)padding, o, (nuint)output.Length);
        }

        return n < 0 ? (null, n) : (output[..(int)n], n);
    }

    /// <summary>Opens one record (a copy) with the key.</summary>
    /// <param name="key">The key.</param>
    /// <param name="record">The record.</param>
    /// <returns>The answer, the content (on success) and its type.</returns>
    private static (long Answer, byte[] Content, int Type) Open(ref Tls13RecordKey key, byte[] record)
    {
        byte[] copy = (byte[])record.Clone();
        byte type = 0;
        long n;
        fixed (Tls13RecordKey* k = &key)
        fixed (byte* r = copy)
        {
            n = Native.Tls13Open(k, r, (nuint)copy.Length, &type);
        }

        // (a refused record's fragment, as the opener left it; nothing of one shorter than a header)
        return (n, n >= 0 ? copy[5..(5 + (int)n)] : copy.Length > 5 ? copy[5..] : [], type);
    }

    /// <summary>
    /// The .NET copy of httpasm_tls13_record_key has the library's size, 1056 octets, under struct
    /// id 28 (the registry's end is checked by the newest structures' tests: TlsMessageTests).
    /// </summary>
    [Fact]
    public void StructureMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(1056, sizeof(Tls13RecordKey));
        Assert.Equal((uint)sizeof(Tls13RecordKey), Native.StructSize(28));
    }

    /// <summary>
    /// Every protected record RFC 8448's traces send (handshake records, 0-RTT data,
    /// EndOfEarlyData, application data, alerts, NewSessionTicket), sealed by the library from the
    /// trace's own traffic secret at its sequence number, octet for octet the trace's record, and
    /// opened back to the payload and its content type; every unprotected record (ClientHello,
    /// ServerHello, HelloRetryRequest, change_cipher_spec) framed whole by
    /// httpasm_tls_record_length. The writer's key is the one the trace derived for it last
    /// (by the writer's "write traffic keys" step or the reader's "read traffic keys" one), its
    /// sequence number counting from 0 under each new key (RFC 9846 5.3).
    /// </summary>
    [Fact]
    [Requirement("RFC9846-5.3-1", "RFC9846-5.4-2#2", "RFC9846-5.1-8.4.1#1")]
    public void SealsAndOpensRfc8448sRecords()
    {
        Platform.RequireLinuxX64();
        int protectedRecords = 0, plainRecords = 0, section = 0;
        var writers = new Dictionary<string, (byte[] Secret, ulong Sequence)>();
        foreach (Rfc8448.Step step in Rfc8448.Steps)
        {
            if (step.Section != section)
            {
                section = step.Section;
                writers.Clear();
            }

            IReadOnlyDictionary<string, byte[]> f = step.Fields;
            if (step.Action.Contains("traffic keys", StringComparison.Ordinal) && f.TryGetValue("PRK", out byte[]? secret))
            {
                // a reader's keys are its peer's write keys
                bool reads = step.Action.Contains("read traffic keys", StringComparison.Ordinal);
                string writer = reads ? (step.Who == "server" ? "client" : "server") : step.Who;
                writers[writer] = (secret, 0);
                Tls13RecordKey made = Key(Abi.TlsAes128GcmSha256, secret);
                Assert.Equal(f["iv expanded"], new ReadOnlySpan<byte>(made.Iv, 12).ToArray());
                continue;
            }

            if (!step.Action.StartsWith("send", StringComparison.Ordinal) || !f.TryGetValue("complete record", out byte[]? record))
            {
                continue;
            }

            fixed (byte* r = record)
            {
                Assert.Equal(record.Length, Native.TlsRecordLength(r, (nuint)record.Length));
            }

            if (record[0] != Abi.TlsApplicationData)
            {
                plainRecords++;
                continue;
            }

            int type = step.Action.Contains("handshake", StringComparison.Ordinal) ? Abi.TlsHandshake
                : step.Action.Contains("alert", StringComparison.Ordinal) ? Abi.TlsAlert : Abi.TlsApplicationData;
            (byte[] key, ulong sequence) = writers[step.Who];
            Tls13RecordKey sealer = Key(Abi.TlsAes128GcmSha256, key);
            sealer.Sequence = sequence;
            (byte[]? sealedRecord, _) = Seal(ref sealer, type, f["payload"], 0);
            Assert.True(record.AsSpan().SequenceEqual(sealedRecord), $"section {step.Section}, {step.Who}: {step.Action} (sequence {sequence})");
            Assert.Equal(sequence + 1, sealer.Sequence);

            Tls13RecordKey opener = Key(Abi.TlsAes128GcmSha256, key);
            opener.Sequence = sequence;
            (long answer, byte[] content, int openedType) = Open(ref opener, record);
            Assert.Equal(f["payload"].Length, answer);
            Assert.Equal(f["payload"], content);
            Assert.Equal(type, openedType);
            writers[step.Who] = (key, sequence + 1);
            protectedRecords++;
        }

        Assert.True(protectedRecords >= 25, $"{protectedRecords} protected records");
        Assert.True(plainRecords >= 8, $"{plainRecords} unprotected records");
    }

    /// <summary>The model's key and IV for a suite and secret (RFC 9846 7.3), by .NET's HKDF.</summary>
    /// <param name="suite">The suite's code.</param>
    /// <param name="secret">The traffic secret.</param>
    /// <returns>The write key and IV.</returns>
    private static (byte[] Key, byte[] Iv) ModelKeys(int suite, byte[] secret)
    {
        HashAlgorithmName hash = suite == Abi.TlsAes256GcmSha384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
        int keyLength = suite == Abi.TlsAes128GcmSha256 ? 16 : 32;
        static byte[] Label(int length, string label) =>
            [(byte)(length >> 8), (byte)length, (byte)(6 + label.Length), .. Encoding.ASCII.GetBytes("tls13 " + label), 0];
        return (HKDF.Expand(hash, secret, keyLength, Label(keyLength, "key")), HKDF.Expand(hash, secret, 12, Label(12, "iv")));
    }

    /// <summary>The model's record: .NET's AEAD over content || type || zeros, the nonce the IV
    /// xored with the sequence number, the header as additional data.</summary>
    /// <param name="suite">The suite's code.</param>
    /// <param name="keys">The model's key and IV.</param>
    /// <param name="sequence">The record's sequence number.</param>
    /// <param name="inner">TLSInnerPlaintext.</param>
    /// <returns>The record.</returns>
    private static byte[] ModelRecord(int suite, (byte[] Key, byte[] Iv) keys, ulong sequence, byte[] inner)
    {
        byte[] nonce = (byte[])keys.Iv.Clone();
        for (int i = 0; i < 8; i++)
        {
            nonce[11 - i] ^= (byte)(sequence >> (8 * i));
        }

        int fragment = inner.Length + 16;
        byte[] header = [23, 3, 3, (byte)(fragment >> 8), (byte)fragment];
        byte[] ciphertext = new byte[inner.Length];
        byte[] tag = new byte[16];
        if (suite == Abi.TlsChaCha20Poly1305Sha256)
        {
            using var aead = new ChaCha20Poly1305(keys.Key);
            aead.Encrypt(nonce, inner, ciphertext, tag, header);
        }
        else
        {
            using var aead = new AesGcm(keys.Key, 16);
            aead.Encrypt(nonce, inner, ciphertext, tag, header);
        }

        return [.. header, .. ciphertext, .. tag];
    }

    /// <summary>
    /// Each of the three suites against .NET's AEADs: for 150 records each, a random content (of
    /// 0 to 2^14 octets, the bounds included), padding and type at a random sequence number
    /// (AES-GCM's below its 2^24.5-record limit, ChaCha20-Poly1305's anywhere in 64 bits), the
    /// library's record is the model's octet for octet, the library opens the model's record to
    /// the content and type, and the key's IV is the model's (7.3).
    /// </summary>
    /// <param name="suite">The suite's code.</param>
    [Theory]
    [InlineData(0x1301)]
    [InlineData(0x1302)]
    [InlineData(0x1303)]
    [Requirement("RFC9846-5.2-13#1", "RFC9846-5.4-5#1")]
    public void MatchesDotNetsAeads(int suite)
    {
        Platform.RequireLinuxX64();
        var random = new Random(suite);
        byte[] secret = RandomNumberGenerator.GetBytes(suite == Abi.TlsAes256GcmSha384 ? 48 : 32);
        (byte[] Key, byte[] Iv) model = ModelKeys(suite, secret);
        Tls13RecordKey key = Key(suite, secret);
        Assert.Equal(model.Iv, new ReadOnlySpan<byte>(key.Iv, 12).ToArray());
        for (int i = 0; i < 150; i++)
        {
            int length = i switch { 0 => 0, 1 => 16384, 2 => 16383, _ => random.Next(0, i % 7 == 0 ? 16385 : 300) };
            int padding = Math.Min(random.Next(0, i % 5 == 0 ? 2000 : 20), 16384 - length);
            int type = i % 4 == 3 ? random.Next(1, 256) : 21 + (i % 3);
            // (AES-GCM seals below its limit of 2^24.5 records only; ChaCha20-Poly1305 to the
            // sequence number's last but one)
            ulong sequence = i % 3 != 0 ? (ulong)i
                : suite == Abi.TlsChaCha20Poly1305Sha256 ? (ulong)random.NextInt64() * 2 : (ulong)random.Next(0, 23726566);
            byte[] content = RandomNumberGenerator.GetBytes(length);
            byte[] inner = [.. content, (byte)type, .. new byte[padding]];
            byte[] expected = ModelRecord(suite, model, sequence, inner);

            key.Sequence = sequence;
            (byte[]? record, _) = Seal(ref key, type, content, padding);
            Assert.True(expected.AsSpan().SequenceEqual(record), $"record {i}: {length} octets, padding {padding}, type {type}");

            key.Sequence = sequence;
            (long answer, byte[] opened, int openedType) = Open(ref key, expected);
            Assert.Equal(length, answer);
            Assert.True(content.AsSpan().SequenceEqual(opened), $"record {i}: opened otherwise");
            Assert.Equal(type, openedType);
            Assert.Equal(sequence + 1, key.Sequence);
        }
    }

    /// <summary>
    /// The sealer's limits: a content type of 0 (the opener would read it as padding) or above
    /// 255, a content over 2^14 octets (5.1), TLSInnerPlaintext over the key's limit (5.4; a
    /// limit lowered as record_size_limit lowers it), a record over the room given: each -1 with
    /// nothing written and the sequence number unchanged; AES-GCM's last record under one key
    /// (2^24.5 records, 5.5) and ChaCha20-Poly1305's last sequence number: -2, a KeyUpdate first;
    /// and the limits themselves sealed.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-5.1-8.6.1#1", "RFC9846-5.4-6", "RFC9846-5.5-1#1", "RFC9846-5.3-2")]
    public void SealsOnlyWhatARecordMayCarry()
    {
        Platform.RequireLinuxX64();
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        Tls13RecordKey key = Key(Abi.TlsAes128GcmSha256, secret);
        Assert.Equal(-1, Seal(ref key, 0, [1, 2, 3], 0).Answer);
        Assert.Equal(-1, Seal(ref key, 256, [1, 2, 3], 0).Answer);
        Assert.Equal(-1, Seal(ref key, 23, new byte[16385], 0).Answer);
        Assert.Equal(-1, Seal(ref key, 23, new byte[16384], 1).Answer);           // inner 16386
        Assert.True(Seal(ref key, 23, new byte[16384], 0).Answer > 0);            // inner 16385: the limit
        Assert.True(Seal(ref key, 23, [], 16384).Answer > 0);                      // padding to the limit
        Assert.Equal(2ul, key.Sequence);
        key.Limit = 100;                                                           // record_size_limit
        Assert.Equal(-1, Seal(ref key, 23, new byte[99], 1).Answer);
        Assert.True(Seal(ref key, 23, new byte[99], 0).Answer > 0);
        key.Limit = 16385;

        // the room given
        byte[] content = new byte[10];
        byte[] output = new byte[5 + 10 + 1 + 16];
        Array.Fill(output, (byte)0xEE);
        Tls13RecordKey* k = &key;
        fixed (byte* c = content)
        fixed (byte* o = output)
        {
            Assert.Equal(-1L, Native.Tls13Seal(k, 23, c, 10, 0, o, (nuint)output.Length - 1));
            Assert.True(output.All(b => b == 0xEE), "a refused record wrote something");
            Assert.Equal((long)output.Length, Native.Tls13Seal(k, 23, c, 10, 0, o, (nuint)output.Length));
        }

        // built in place: the content already at out + 5
        byte[] place = new byte[5 + 3 + 1 + 16];
        place[5] = 7;
        place[6] = 8;
        place[7] = 9;
        Tls13RecordKey inPlace = Key(Abi.TlsAes128GcmSha256, secret);
        Tls13RecordKey copied = Key(Abi.TlsAes128GcmSha256, secret);
        fixed (byte* o = place)
        {
            Assert.Equal((long)place.Length, Native.Tls13Seal(&inPlace, 23, o + 5, 3, 0, o, (nuint)place.Length));
        }

        Assert.Equal(Seal(ref copied, 23, [7, 8, 9], 0).Record, place);

        // the AEAD's last record under one key
        key.Sequence = 23726566 - 1;
        Assert.True(Seal(ref key, 23, [1], 0).Answer > 0);
        Assert.Equal(-2, Seal(ref key, 23, [1], 0).Answer);
        Assert.Equal(23726566ul, key.Sequence);
        Tls13RecordKey chacha = Key(Abi.TlsChaCha20Poly1305Sha256, secret);
        chacha.Sequence = 23726566;
        Assert.True(Seal(ref chacha, 23, [1], 0).Answer > 0);                      // ChaCha20's limit is the sequence's
        chacha.Sequence = ulong.MaxValue - 1;
        Assert.True(Seal(ref chacha, 23, [1], 0).Answer > 0);
        Assert.Equal(-2, Seal(ref chacha, 23, [1], 0).Answer);                     // the next would wrap
    }

    /// <summary>
    /// The opener's refusals, each the alert RFC 9846 names: a fragment the tag does not verify
    /// (bad_record_mac, 5.2: a changed octet anywhere, the header included, another sequence
    /// number, a fragment shorter than the tag; the fragment then zeros), a fragment over 2^14 +
    /// 256 octets or TLSInnerPlaintext over the key's limit (record_overflow, 5.2 and 5.4), a
    /// plaintext of zeros only or empty (unexpected_message, 5.4), an outer type other than
    /// application_data (unexpected_message), a header whose length is not the record's
    /// (decode_error), and a sequence number about to wrap (internal_error, 5.3). The legacy
    /// version is not judged (5.1), and the AEAD's limits are not enforced on what is received
    /// (5.5's SHOULD NOT).
    /// </summary>
    [Fact]
    [Requirement("RFC9846-5.2-12", "RFC9846-5.2-3.12.1#2", "RFC9846-5.2-13#2", "RFC9846-5.4-5#2", "RFC9846-5.1-8.4.1#3", "RFC9846-5.5-1#3")]
    public void OpensOnlyWhatVerifies()
    {
        Platform.RequireLinuxX64();
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        (byte[] Key, byte[] Iv) model = ModelKeys(Abi.TlsAes128GcmSha256, secret);
        Tls13RecordKey sealer = Key(Abi.TlsAes128GcmSha256, secret);
        byte[] good = Seal(ref sealer, 23, "hello"u8.ToArray(), 3).Record!;
        Tls13RecordKey Reader(ulong sequence)
        {
            Tls13RecordKey k = Key(Abi.TlsAes128GcmSha256, secret);
            k.Sequence = sequence;
            return k;
        }

        Tls13RecordKey reader = Reader(0);
        Assert.Equal(5, Open(ref reader, good).Answer);
        for (int i = 0; i < good.Length; i++)
        {
            if (i is 1 or 2)
            {
                continue;                                                           // the legacy version: below
            }

            byte[] bad = (byte[])good.Clone();
            bad[i] ^= 0x01;
            reader = Reader(0);
            (long answer, byte[] content, _) = Open(ref reader, bad);
            long expected = i == 0 ? -Abi.AlertUnexpectedMessage : i is 3 or 4 ? -Abi.AlertDecodeError : -Abi.AlertBadRecordMac;
            Assert.True(answer == expected, $"octet {i} changed: {answer}");
            if (answer == -Abi.AlertBadRecordMac)
            {
                // the ciphertext's octets zeroed (the tag after them is not plaintext)
                Assert.True(content[..^16].All(b => b == 0), $"octet {i}: plaintext left");
                Assert.Equal(0ul, reader.Sequence);
            }
        }

        // the version is authenticated (in the additional data), not judged: changed, the tag fails
        byte[] version = (byte[])good.Clone();
        version[2] = 0x01;
        reader = Reader(0);
        Assert.Equal(-Abi.AlertBadRecordMac, Open(ref reader, version).Answer);
        // another legacy version, sealed under that header: opened, the version ignored (5.1)
        byte[] otherVersion = ResealWithHeader(model, 0, [1, 2, 3, 23], [23, 0x07, 0x07, 0, 20]);
        reader = Reader(0);
        Assert.Equal(3, Open(ref reader, otherVersion).Answer);

        reader = Reader(1);
        Assert.Equal(-Abi.AlertBadRecordMac, Open(ref reader, good).Answer);    // another sequence number
        reader = Reader(0);
        Assert.Equal(-Abi.AlertBadRecordMac, Open(ref reader, [23, 3, 3, 0, 15, .. new byte[15]]).Answer);
        reader = Reader(0);
        Assert.Equal(-Abi.AlertDecodeError, Open(ref reader, [23, 3, 3]).Answer);
        reader = Reader(0);
        Assert.Equal(-Abi.AlertDecodeError, Open(ref reader, [.. good, 0]).Answer);
        reader = Reader(0);
        Assert.Equal(-Abi.AlertRecordOverflow, Open(ref reader, [23, 3, 3, 0x41, 0x01, .. new byte[16641]]).Answer);

        // a plaintext of zeros (no content type), and an empty one
        reader = Reader(0);
        Assert.Equal(-Abi.AlertUnexpectedMessage, Open(ref reader, ModelRecord(Abi.TlsAes128GcmSha256, model, 0, new byte[40])).Answer);
        reader = Reader(0);
        Assert.Equal(-Abi.AlertUnexpectedMessage, Open(ref reader, ModelRecord(Abi.TlsAes128GcmSha256, model, 0, [])).Answer);

        // TLSInnerPlaintext over the key's limit (record_size_limit), and over 2^14 + 1
        reader = Reader(0);
        reader.Limit = 8;
        Assert.Equal(-Abi.AlertRecordOverflow, Open(ref reader, ModelRecord(Abi.TlsAes128GcmSha256, model, 0, [1, 2, 3, 4, 5, 6, 7, 8, 23])).Answer);
        reader = Reader(0);
        Assert.Equal(-Abi.AlertRecordOverflow, Open(ref reader, ModelRecord(Abi.TlsAes128GcmSha256, model, 0, [.. new byte[16385], 23])).Answer);

        // the sequence number about to wrap; and past AES-GCM's sealing limit, still opened
        reader = Reader(ulong.MaxValue);
        Assert.Equal(-Abi.AlertInternalError, Open(ref reader, good).Answer);
        reader = Reader(23726566 + 10);
        Assert.Equal(2, Open(ref reader, ModelRecord(Abi.TlsAes128GcmSha256, model, 23726566 + 10, [1, 2, 23])).Answer);
    }

    /// <summary>The model's record with a header of the caller's (another legacy version): the
    /// additional data is the header as given.</summary>
    /// <param name="keys">The model's key and IV.</param>
    /// <param name="sequence">The sequence number.</param>
    /// <param name="inner">TLSInnerPlaintext.</param>
    /// <param name="header">The five header octets.</param>
    /// <returns>The record.</returns>
    private static byte[] ResealWithHeader((byte[] Key, byte[] Iv) keys, ulong sequence, byte[] inner, byte[] header)
    {
        byte[] nonce = (byte[])keys.Iv.Clone();
        for (int i = 0; i < 8; i++)
        {
            nonce[11 - i] ^= (byte)(sequence >> (8 * i));
        }

        byte[] ciphertext = new byte[inner.Length];
        byte[] tag = new byte[16];
        using var aead = new AesGcm(keys.Key, 16);
        aead.Encrypt(nonce, inner, ciphertext, tag, header);
        return [.. header, .. ciphertext, .. tag];
    }

    /// <summary>
    /// httpasm_tls_record_length frames what a connection read: 0 until the header and then the
    /// whole fragment are there, the record's length once they are (more octets after it are the
    /// next record's), record_overflow for a fragment over 2^14 octets in a record of another
    /// type than application_data (5.1) or over 2^14 + 256 in an application_data one (5.2), the
    /// limits themselves taken; neither the type's value nor the version judged.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-5.1-8.6.1#2")]
    public void FramesRecords()
    {
        Platform.RequireLinuxX64();
        long Length(byte[] input)
        {
            fixed (byte* p = input)
            {
                return Native.TlsRecordLength(p, (nuint)input.Length);
            }
        }

        Assert.Equal(0, Length([]));
        Assert.Equal(0, Length([22, 3, 1, 0]));
        Assert.Equal(0, Length([22, 3, 1, 0, 3, 1, 2]));
        Assert.Equal(8, Length([22, 3, 1, 0, 3, 1, 2, 3]));
        Assert.Equal(8, Length([22, 3, 1, 0, 3, 1, 2, 3, 22, 3]));               // the next record's start after it
        Assert.Equal(5, Length([99, 0x7F, 0x7F, 0, 0]));                           // any type, any version
        Assert.Equal(16389, Length([22, 3, 3, 0x40, 0x00, .. new byte[16384]]));
        Assert.Equal(-Abi.AlertRecordOverflow, Length([22, 3, 3, 0x40, 0x01]));
        Assert.Equal(-Abi.AlertRecordOverflow, Length([21, 3, 3, 0x40, 0x01]));
        Assert.Equal(16645, Length([23, 3, 3, 0x41, 0x00, .. new byte[16640]]));
        Assert.Equal(0, Length([23, 3, 3, 0x41, 0x00, .. new byte[16639]]));
        Assert.Equal(-Abi.AlertRecordOverflow, Length([23, 3, 3, 0x41, 0x01]));
        Assert.Equal(-Abi.AlertRecordOverflow, Length([23, 3, 3, 0xFF, 0xFF]));
    }

    /// <summary>
    /// The key's making: each suite's hash and key length (7.3), the sequence number 0 and the
    /// limit 2^14 + 1; an unknown suite (the CCM suites, which are not built, TLS 1.2's, 0) -1
    /// with the key all zeros.
    /// </summary>
    [Fact]
    public void MakesKeysOfTheThreeSuitesOnly()
    {
        Platform.RequireLinuxX64();
        foreach (int suite in new[] { 0x1301, 0x1302, 0x1303 })
        {
            byte[] secret = RandomNumberGenerator.GetBytes(suite == 0x1302 ? 48 : 32);
            Tls13RecordKey key = Key(suite, secret);
            Assert.Equal(((uint)suite, 16385u, 0ul), (key.Suite, key.Limit, key.Sequence));
            Assert.Equal(ModelKeys(suite, secret).Iv, new ReadOnlySpan<byte>(key.Iv, 12).ToArray());
        }

        byte[] any = new byte[48];
        foreach (int suite in new[] { 0x1304, 0x1305, 0xC02F, 0, -1 })
        {
            var key = default(Tls13RecordKey);
            new Span<byte>(&key, sizeof(Tls13RecordKey)).Fill(0xEE);
            fixed (byte* s = any)
            {
                Assert.Equal(-1, Native.Tls13RecordKeyInit(&key, suite, s));
            }

            Assert.True(new ReadOnlySpan<byte>(&key, sizeof(Tls13RecordKey)).IndexOfAnyExcept((byte)0) < 0, $"suite {suite:X4}: not zeros");
        }
    }
}
