using System.Numerics;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// TLS 1.3's server (tls/server.asm, tls/engine.asm, tls/kex.asm, tls/sign.asm, tls/config.asm)
/// through the C ABI: RFC 8448's server flights reproduced octet for octet from the traces'
/// ClientHellos with the traces' randomness replayed (the server random and ephemeral key are in
/// the traces; the RSA-PSS salt is recovered from the trace's CertificateVerify with the trace's
/// RSA key), then the client's flight, application data and close_notify taken.
/// </summary>
public sealed unsafe class TlsServerTests
{
    /// <summary>
    /// The .NET copies of httpasm_tls13_server_config, httpasm_tls13_event and
    /// httpasm_tls13_connection have the library's sizes, 152, 32 and 2,752 octets, under struct
    /// ids 31, 32 and 33, the registry's last: id 34 answers 0.
    /// </summary>
    [Fact]
    public void StructuresMatchTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(152, sizeof(TlsServerConfig));
        Assert.Equal(32, sizeof(TlsEvent));
        Assert.Equal(3008, sizeof(TlsConnection));
        Assert.Equal((uint)sizeof(TlsServerConfig), Native.StructSize(31));
        Assert.Equal((uint)sizeof(TlsEvent), Native.StructSize(32));
        Assert.Equal((uint)sizeof(TlsConnection), Native.StructSize(33));
        Assert.Equal(0u, Native.StructSize(34));
    }

    /// <summary>One section of RFC 8448 as a server sees it.</summary>
    /// <param name="Section">The section.</param>
    private sealed record Trace(int Section)
    {
        /// <summary>The section's steps.</summary>
        private IReadOnlyList<Rfc8448.Step> Steps { get; } = Rfc8448.Steps.Where(s => s.Section == Section).ToList();

        /// <summary>A field of the nth step of a party and action that has it.</summary>
        /// <param name="who">"client" or "server".</param>
        /// <param name="action">The step's action.</param>
        /// <param name="field">The field's label.</param>
        /// <param name="nth">Which of those steps (0: the first).</param>
        /// <returns>Its octets.</returns>
        public byte[] Field(string who, string action, string field, int nth = 0) =>
            Steps.Where(s => s.Who == who && s.Action == action && s.Fields.ContainsKey(field)).ElementAt(nth).Fields[field];

        /// <summary>The steps of a party and action, in order.</summary>
        /// <param name="who">"client" or "server".</param>
        /// <param name="action">The step's action.</param>
        /// <returns>The steps.</returns>
        public IEnumerable<Rfc8448.Step> All(string who, string action) => Steps.Where(s => s.Who == who && s.Action == action);

        /// <summary>The leaf certificate of the server's Certificate message.</summary>
        public byte[] Certificate
        {
            get
            {
                byte[] message = Field("server", "construct a Certificate handshake message", "Certificate");
                int length = (message[8] << 16) | (message[9] << 8) | message[10];     // the first cert_data
                return message[11..(11 + length)];
            }
        }

        /// <summary>The server's CertificateVerify signature.</summary>
        public byte[] Signature
        {
            get
            {
                byte[] message = Field("server", "construct a CertificateVerify handshake message", "CertificateVerify");
                return message[8..];
            }
        }
    }

    /// <summary>
    /// The salt of an RSASSA-PSS signature (RFC 8017 9.1.2's steps run backwards): EM = s^e mod n,
    /// DB = maskedDB xor MGF1(H), the salt the end of DB past its 0x01. What lets a test replay
    /// the randomness a trace's signer drew.
    /// </summary>
    /// <param name="signature">The signature.</param>
    /// <param name="keyDer">The signer's RSAPrivateKey (its n and e are used).</param>
    /// <param name="hashLength">The hash's octets (SHA-256's 32: MGF1 over SHA-256).</param>
    /// <returns>The salt.</returns>
    private static byte[] PssSalt(byte[] signature, byte[] keyDer, int hashLength)
    {
        using var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(keyDer, out _);
        RSAParameters p = rsa.ExportParameters(false);
        var n = new BigInteger(p.Modulus, isUnsigned: true, isBigEndian: true);
        var e = new BigInteger(p.Exponent, isUnsigned: true, isBigEndian: true);
        int emBits = (int)n.GetBitLength() - 1;
        int emLength = (emBits + 7) / 8;
        byte[] m = BigInteger.ModPow(new BigInteger(signature, true, true), e, n).ToByteArray(true, true);
        byte[] em = [.. new byte[emLength - m.Length], .. m];
        Assert.Equal(0xBC, em[^1]);
        byte[] h = em[(emLength - hashLength - 1)..(emLength - 1)];
        byte[] db = em[..(emLength - hashLength - 1)];
        var mask = new List<byte>();
        for (uint counter = 0; mask.Count < db.Length; counter++)
        {
            mask.AddRange(SHA256.HashData([.. h, (byte)(counter >> 24), (byte)(counter >> 16), (byte)(counter >> 8), (byte)counter]));
        }

        for (int i = 0; i < db.Length; i++)
        {
            db[i] ^= mask[i];
        }

        db[0] &= (byte)(0xFF >> (8 * emLength - emBits));
        int one = Array.IndexOf(db, (byte)1);
        Assert.True(one >= 0 && db[..one].All(b => b == 0), "DB: PS then 0x01");
        return db[(one + 1)..];
    }

    /// <summary>AES-128-GCM's opening of a TLS 1.3 record under a key and IV at a sequence number:
    /// the inner plaintext (content and its type), for checking a record the engine sealed under
    /// a trace's keys.</summary>
    /// <param name="record">The record.</param>
    /// <param name="key">The write key.</param>
    /// <param name="iv">The write IV.</param>
    /// <param name="sequence">The record's sequence number.</param>
    /// <returns>TLSInnerPlaintext.</returns>
    private static byte[] OpenGcm(byte[] record, byte[] key, byte[] iv, ulong sequence)
    {
        byte[] nonce = (byte[])iv.Clone();
        for (int i = 0; i < 8; i++)
        {
            nonce[nonce.Length - 1 - i] ^= (byte)(sequence >> (8 * i));
        }

        int length = (record[3] << 8) | record[4];
        Assert.Equal(record.Length, 5 + length);
        byte[] plain = new byte[length - 16];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(nonce, record.AsSpan(5, length - 16), record.AsSpan(5 + length - 16, 16), plain, record.AsSpan(0, 5));
        return plain;
    }

    /// <summary>
    /// RFC 8448 section 3, the simple 1-RTT handshake, from the server's side: the trace's
    /// ClientHello taken with the trace's server random, ephemeral X25519 key and (recovered) PSS
    /// salt replayed, the server answers the trace's ServerHello record and its flight record
    /// (EncryptedExtensions with supported_groups, record_size_limit and server_name's
    /// acknowledgment; Certificate; CertificateVerify under rsa_pss_rsae_sha256; Finished) octet
    /// for octet; then takes the client's Finished (connected), its application data (the trace's
    /// 50 octets) and its close_notify (closed); and what it sends after, application data and
    /// its own close_notify, opens under the trace's server application key at sequences 0 and 1
    /// (the trace's server sent a NewSessionTicket first, 4e's).
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.4.1-1", "RFC9846-4.5.2-1#1", "RFC9846-4.5.2-14", "RFC9846-4.2.3-4.12.1#2", "RFC9846-4.2.3-4.2.1#1", "RFC9846-4.5.3-15")]
    public void ReproducesRfc8448sSimpleHandshake()
    {
        Platform.RequireLinuxX64();
        var trace = new Trace(3);
        byte[] serverHello = trace.Field("server", "send handshake record", "complete record", 0);
        byte[] flight = trace.Field("server", "send handshake record", "complete record", 1);
        byte[] random = serverHello[11..43];
        byte[] ephemeral = trace.Field("server", "create an ephemeral x25519 key pair", "private key");
        byte[] salt = PssSalt(trace.Signature, Rfc8448.ServerRsaKey, 32);
        var script = new RandomScript { Fallback = false }.Then(random, ephemeral, salt);
        ushort[] groups = [TlsEngine.X25519, TlsEngine.Secp256r1, TlsEngine.Secp384r1, TlsEngine.Secp521r1, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104];
        using var server = new TlsServerHarness(Rfc8448.ServerRsaKey, [trace.Certificate], script, groups);
        Assert.Equal(0, server.ConfigAnswer);

        // the ClientHello: the server's first flight, whole
        byte[] clientHello = trace.Field("client", "send handshake record", "complete record", 0);
        TlsServerHarness.Received r = server.Receive(clientHello);
        Assert.Equal(clientHello.Length, r.Answer);
        Assert.Equal(TlsEngine.EventNone, r.Event.Kind);
        Assert.Empty(script.Failures);
        Assert.Equal([32, 32, 32], script.Lengths);
        Assert.Equal(Convert.ToHexString([.. serverHello, .. flight]), Convert.ToHexString(server.TakeOutput()));
        Assert.Equal((1, 0x1301u, (uint)TlsEngine.X25519, 0x0804u), server.Negotiated());

        // the client's Finished
        byte[] finished = trace.Field("client", "send handshake record", "complete record", 1);
        r = server.Receive(finished);
        Assert.Equal(finished.Length, r.Answer);
        Assert.Equal(TlsEngine.EventConnected, r.Event.Kind);
        Assert.Equal((2, 0x1301u, (uint)TlsEngine.X25519, 0x0804u), server.Negotiated());
        Assert.Empty(server.TakeOutput());

        // the client's application data and close_notify
        byte[] data = trace.Field("client", "send application_data record", "complete record");
        r = server.Receive(data);
        Assert.Equal(TlsEngine.EventData, r.Event.Kind);
        Assert.Equal(trace.Field("client", "send application_data record", "payload"), r.Data);
        byte[] alert = trace.Field("client", "send alert record", "complete record");
        r = server.Receive(alert);
        Assert.Equal(alert.Length, r.Answer);
        Assert.Equal(TlsEngine.EventClosed, r.Event.Kind);

        // ours, under the trace's server application key: data at sequence 0, close_notify at 1
        byte[] key = trace.Field("server", "derive write traffic keys for application data", "key expanded");
        byte[] iv = trace.Field("server", "derive write traffic keys for application data", "iv expanded");
        byte[] payload = trace.Field("server", "send application_data record", "payload");
        Assert.Equal(payload.Length, server.Send(payload));
        byte[] sent = server.TakeOutput();
        Assert.Equal([.. payload, 23], OpenGcm(sent, key, iv, 0));
        Assert.Equal(0, server.Close());
        Assert.Equal(new byte[] { 1, 0, 21 }, OpenGcm(server.TakeOutput(), key, iv, 1));
        Assert.Equal(-1, server.Send(payload));                     // nothing after our close_notify
    }

    /// <summary>
    /// RFC 8448 section 7, middlebox compatibility mode (Appendix E.4): the client's 32-octet
    /// legacy_session_id is echoed in the ServerHello, the server's change_cipher_spec record
    /// follows it, then the flight, each octet for octet the trace's; the client's own
    /// change_cipher_spec before its Finished is dropped, its Finished connects, and its
    /// close_notify closes.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-E.4-3")]
    public void ReproducesRfc8448sCompatibilityMode()
    {
        Platform.RequireLinuxX64();
        var trace = new Trace(7);
        byte[] serverHello = trace.Field("server", "send handshake record", "complete record", 0);
        byte[] ccs = trace.Field("server", "send change_cipher_spec record", "complete record");
        byte[] flight = trace.Field("server", "send handshake record", "complete record", 1);
        byte[] random = serverHello[11..43];
        byte[] ephemeral = trace.Field("server", "create an ephemeral x25519 key pair", "private key");
        byte[] salt = PssSalt(trace.Signature, Rfc8448.ServerRsaKey, 32);
        var script = new RandomScript { Fallback = false }.Then(random, ephemeral, salt);
        ushort[] groups = [TlsEngine.X25519, TlsEngine.Secp256r1, TlsEngine.Secp384r1, TlsEngine.Secp521r1, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104];
        using var server = new TlsServerHarness(Rfc8448.ServerRsaKey, [trace.Certificate], script, groups);
        Assert.Equal(0, server.ConfigAnswer);

        byte[] clientHello = trace.Field("client", "send handshake record", "complete record", 0);
        TlsServerHarness.Received r = server.Receive(clientHello);
        Assert.True(r.Answer == clientHello.Length, $"answer {r.Answer}, alert {r.Event.Alert}, failures {string.Join("; ", script.Failures)}");
        Assert.Equal(Convert.ToHexString([.. serverHello, .. ccs, .. flight]), Convert.ToHexString(server.TakeOutput()));

        byte[] clientCcs = trace.Field("client", "send change_cipher_spec record", "complete record");
        r = server.Receive(clientCcs);
        Assert.Equal(clientCcs.Length, r.Answer);
        Assert.Equal(TlsEngine.EventNone, r.Event.Kind);
        byte[] finished = trace.Field("client", "send handshake record", "complete record", 1);
        r = server.Receive(finished);
        Assert.Equal(TlsEngine.EventConnected, r.Event.Kind);
        r = server.Receive(trace.Field("client", "send alert record", "complete record"));
        Assert.Equal(TlsEngine.EventClosed, r.Event.Kind);
        Assert.Empty(server.TakeOutput());
    }
}
