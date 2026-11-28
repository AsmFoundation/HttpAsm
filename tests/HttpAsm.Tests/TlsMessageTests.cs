using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// TLS 1.3's handshake messages (tls/messages.asm, tls/extensions.asm) through the C ABI: every
/// message of RFC 8448's five traces read (the traces' own octets, <see cref="Rfc8448"/>), their
/// certificates read on through httpasm_certificate_read; against the tests' model
/// (<see cref="TlsModel"/>, written apart from the assembly) on every one-octet change,
/// truncation and insertion of those messages, on every extension of their blocks removed,
/// doubled, moved last or retyped, and on random ClientHellos; and every rule by name, the
/// linear time of the duplicate checks included.
/// </summary>
public sealed unsafe class TlsMessageTests
{
    /// <summary>What the library's hello reader returned.</summary>
    /// <param name="Answer">0 or minus an alert.</param>
    /// <param name="Hello">The structure (offsets made from its pointers by the caller).</param>
    /// <param name="Offsets">The structure's pointers as offsets into the body (-1: null), and its present bits.</param>
    private readonly record struct Read(int Answer, TlsHello Hello, Dictionary<string, long> Offsets);

    /// <summary>Reads a hello body placed against a guard page.</summary>
    /// <param name="body">The body.</param>
    /// <param name="type">1 or 2.</param>
    /// <returns>The answer and fields.</returns>
    private static Read Hello(byte[] body, int type)
    {
        // a page or less against a guard page; more (the linear-time cases) in native memory
        using var guard = new GuardedBuffer();
        byte* block = body.Length > GuardedBuffer.PageSize ? (byte*)NativeMemory.Alloc((nuint)body.Length) : null;
        try
        {
            byte* at = block != null ? block : guard.AtPageEnd(body);
            body.CopyTo(new Span<byte>(at, body.Length));
            return HelloAt(at, body.Length, type);
        }
        finally
        {
            NativeMemory.Free(block);
        }
    }

    /// <summary>Reads a hello body where it lies.</summary>
    /// <param name="at">The body.</param>
    /// <param name="length">Its octets.</param>
    /// <param name="type">1 or 2.</param>
    /// <returns>The answer and fields.</returns>
    private static Read HelloAt(byte* at, int length, int type)
    {
        TlsHello h;
        int answer = Native.Tls13HelloRead(&h, type, at, (nuint)length);
        long Of(byte* p) => p == null ? -1 : p - at;
        var offsets = new Dictionary<string, long>();
        if (answer == 0)
        {
            offsets["random"] = Of(h.Random);
            offsets["session_id"] = Of(h.SessionId);
            offsets["session_id_length"] = h.SessionIdLength;
            offsets["extensions_block"] = Of(h.ExtensionsBlock);
            offsets["extensions_length"] = (long)h.ExtensionsLength;
            offsets["legacy_version"] = h.LegacyVersion;
            if (type == 1)
            {
                offsets["cipher_suites"] = Of(h.CipherSuites);
                offsets["cipher_suites_length"] = h.CipherSuitesLength;
                offsets["compression"] = Of(h.Compression);
                offsets["compression_length"] = h.CompressionLength;
            }
            else
            {
                offsets["cipher_suite"] = h.CipherSuite;
                offsets["compression_method"] = h.CompressionMethod;
                offsets["retry"] = h.Retry;
            }

            for (int i = 0; i < 38; i++)
            {
                if ((h.Extensions.Present & (1ul << i)) != 0)
                {
                    offsets[$"ext{i}"] = (long)h.Extensions.Data[i] - (long)at;
                    offsets[$"ext{i}.length"] = h.Extensions.Length[i];
                }
            }

            offsets["count"] = h.Extensions.Count;
            offsets["last"] = h.Extensions.Last;
        }

        return new Read(answer, h, offsets);
    }

    /// <summary>Asserts that the library and the model read a hello alike: the same answer and,
    /// when it is 0, the same fields and extensions.</summary>
    /// <param name="body">The body.</param>
    /// <param name="type">1 or 2.</param>
    /// <param name="what">What the body is (the message of a failure).</param>
    /// <returns>The answer.</returns>
    private static int Agree(byte[] body, int type, string what)
    {
        Read ours = Hello(body, type);
        TlsModel.Hello model = TlsModel.ReadHello(body, type);
        Assert.True(ours.Answer == model.Answer, $"{what}: the library answered {ours.Answer}, the model {model.Answer}");
        if (ours.Answer != 0)
        {
            return ours.Answer;
        }

        foreach ((string field, int value) in model.Fields)
        {
            if (ours.Offsets.TryGetValue(field, out long o))
            {
                Assert.True(o == value, $"{what}: {field} {o}, the model's {value}");
            }
        }

        if (model.Block is { } block)
        {
            Assert.True(block.Present == ours.Hello.Extensions.Present, $"{what}: present {ours.Hello.Extensions.Present:X}, the model's {block.Present:X}");
            Assert.True(block.Count == ours.Hello.Extensions.Count && block.Last == ours.Hello.Extensions.Last, $"{what}: count or last");
            foreach ((int index, (int offset, int length)) in block.Known)
            {
                Assert.True(ours.Offsets[$"ext{index}"] == offset && ours.Offsets[$"ext{index}.length"] == length, $"{what}: extension {index}");
            }
        }

        return 0;
    }

    /// <summary>The handshake messages of RFC 8448's traces: (section, the message's name, its
    /// whole octets), in the traces' order.</summary>
    private static readonly (int Section, string Name, byte[] Message)[] TraceMessages =
        Rfc8448.Steps.Where(s => s.Action.StartsWith("construct a", StringComparison.Ordinal) && s.Fields.Count == 1)
            .Select(s => (s.Section, s.Fields.Keys.Single(), s.Fields.Values.Single()))
            // (a ClientHello printed before its binders is a prefix, not a message: its length
            // counts the binders; the one sent, below, is whole)
            .Where(m => m.Item3.Length >= 4 && ((m.Item3[1] << 16) | (m.Item3[2] << 8) | m.Item3[3]) == m.Item3.Length - 4)
            .Concat(Rfc8448.Steps.Where(s => s.Action == "send handshake record" && s.Fields.TryGetValue("complete record", out byte[]? r) && r[0] == 22 && s.Fields["payload"][0] == 1)
                .Select(s => (s.Section, "ClientHello (as sent)", s.Fields["payload"])))
            .ToArray();

    /// <summary>
    /// The .NET copies of httpasm_tls_extensions and httpasm_tls13_hello have the library's sizes,
    /// 400 and 464 octets, under struct ids 29 and 30, the registry's last: id 31 answers 0.
    /// </summary>
    [Fact]
    public void StructuresMatchTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(400, sizeof(TlsExtensions));
        Assert.Equal(464, sizeof(TlsHello));
        Assert.Equal((uint)sizeof(TlsExtensions), Native.StructSize(29));
        Assert.Equal((uint)sizeof(TlsHello), Native.StructSize(30));
        Assert.Equal(0u, Native.StructSize(31));
    }

    /// <summary>
    /// Every handshake message RFC 8448's traces construct and send, framed by
    /// httpasm_tls_message and read by its type's reader, as the model reads it: ClientHellos
    /// (with their PSK binders as sent), ServerHellos and the HelloRetryRequest of section 5
    /// (told apart by its random), EncryptedExtensions, CertificateRequest (section 6),
    /// Certificates (each entry's cert_data then read as a certificate), CertificateVerify,
    /// Finished, NewSessionTicket and EndOfEarlyData.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.2.3-7")]
    public void ReadsRfc8448sMessages()
    {
        Platform.RequireLinuxX64();
        int read = 0, retries = 0, certificates = 0;
        foreach ((int section, string name, byte[] message) in TraceMessages)
        {
            uint type;
            nuint bodyLength;
            fixed (byte* m = message)
            {
                Assert.Equal(message.Length, Native.TlsMessage(m, (nuint)message.Length, &type, &bodyLength));
                Assert.Equal(0, Native.TlsMessage(m, (nuint)message.Length - 1, &type, &bodyLength));
            }

            Assert.Equal(message.Length - 4, (int)bodyLength);
            byte[] body = message[4..];
            string what = $"section {section}: {name}";
            switch ((int)type)
            {
                case 1:
                case 2:
                    Assert.Equal(0, Agree(body, (int)type, what));
                    retries += type == 2 && Hello(body, 2).Hello.Retry == 1 ? 1 : 0;
                    break;
                case 8:
                    Assert.True(Extensions(body, 4).Answer == 0, what);
                    break;
                case 13:
                    Assert.Equal(0, CertificateRequest(body));
                    Assert.Equal(0, TlsModel.ReadCertificateRequest(body));
                    break;
                case 11:
                    {
                        (long entries, List<byte[]> certs) = Certificates(body);
                        Assert.True(entries >= 1 && entries == TlsModel.ReadCertificate(body), what);
                        foreach (byte[] cert in certs)
                        {
                            Certificate c;
                            fixed (byte* p = cert)
                            {
                                Assert.Equal(0, Native.CertificateRead(&c, p, (nuint)cert.Length));
                            }

                            certificates++;
                        }

                        break;
                    }

                case 15:
                    {
                        uint scheme;
                        byte* signature;
                        nuint signatureLength;
                        fixed (byte* b = body)
                        {
                            Assert.Equal(0, Native.Tls13CertificateVerifyRead(b, (nuint)body.Length, &scheme, &signature, &signatureLength));
                        }

                        Assert.Equal(body.Length - 4, (int)signatureLength);
                        break;
                    }

                case 4:
                    Assert.Equal(0, NewSessionTicket(body).Answer);
                    Assert.Equal(0, TlsModel.ReadNewSessionTicket(body));
                    break;
                case 20:
                    Assert.Equal(32, body.Length);
                    break;
                case 5:
                    Assert.Empty(body);
                    break;
                default:
                    Assert.Fail($"{what}: type {type}");
                    break;
            }

            read++;
        }

        Assert.True(read >= 40, $"{read} messages");
        Assert.Equal(1, retries);
        Assert.True(certificates >= 4, $"{certificates} certificates");
    }

    /// <summary>
    /// httpasm_tls13_certificate_entry reads a certificate_list wherever its caller keeps it: each
    /// of RFC 8448's Certificates has its list copied to the first octet of a page whose previous
    /// page is inaccessible, and read there to the same entries as in place. (The first version
    /// loaded each entry's uint24 length as a dword from the octet before it: for the first
    /// entry, the octet before the caller's list, which here faults.)
    /// </summary>
    [Fact]
    public void ReadsACertificateListAtAPagesStart()
    {
        Platform.RequireLinuxX64();
        nint mapping = Native.Mmap(0, 2 * GuardedBuffer.PageSize, Native.ProtReadWrite, Native.MapPrivateAnonymous, -1, 0);
        Assert.True(mapping != -1, $"mmap failed: errno {Marshal.GetLastPInvokeError()}");
        try
        {
            // the first page made inaccessible: a read before the second page's first octet faults
            Assert.Equal(0, Native.Mprotect(mapping, GuardedBuffer.PageSize, Native.ProtNone));
            byte* start = (byte*)(mapping + GuardedBuffer.PageSize);
            int lists = 0;
            foreach ((int section, string name, byte[] message) in TraceMessages.Where(m => m.Message[0] == 11))
            {
                byte[] body = message[4..];
                (long count, List<byte[]> inPlace) = Certificates(body);
                Assert.True(count >= 1, $"section {section}: {name}: {count}");

                // the list: after the context (its length octet and its octets) and its own uint24 length
                byte[] list = body[(1 + body[0] + 3)..];
                list.CopyTo(new Span<byte>(start, list.Length));
                var moved = new List<byte[]>();
                nuint offset = 0;
                while (offset < (nuint)list.Length)
                {
                    byte* cert;
                    nuint certLength;
                    TlsExtensions e;
                    long next = Native.Tls13CertificateEntry(start, (nuint)list.Length, offset, &cert, &certLength, &e);
                    Assert.True(next > (long)offset, $"section {section}: entry at {offset}: {next}");
                    moved.Add(new ReadOnlySpan<byte>(cert, (int)certLength).ToArray());
                    offset = (nuint)next;
                }

                Assert.Equal(count, moved.Count);
                Assert.Equal(inPlace, moved);
                lists++;
            }

            Assert.True(lists >= 4, $"{lists} lists");
        }
        finally
        {
            _ = Native.Munmap(mapping, 2 * GuardedBuffer.PageSize);
        }
    }

    /// <summary>
    /// httpasm_tls13_certificate_entry judges the entry it is pointed at instead of trusting the
    /// list: from RFC 8448's first Certificate's list, against a guard page, an offset at and past
    /// the end, the list cut inside the first entry's uint24 length, inside its cert_data, inside
    /// its extensions' length and inside its extensions, and an entry with a cert_data of no
    /// octets are each decode_error; an entry carrying signed_certificate_timestamp (a
    /// Certificate's) reads, one carrying key_share (no Certificate's) is illegal_parameter.
    /// </summary>
    [Fact]
    public void JudgesTheCertificateEntryItIsPointedAt()
    {
        Platform.RequireLinuxX64();
        static long Entry(byte[] list, nuint offset)
        {
            using var guard = new GuardedBuffer();
            byte* at = guard.AtPageEnd(list);
            byte* cert;
            nuint certLength;
            TlsExtensions e;
            return Native.Tls13CertificateEntry(at, (nuint)list.Length, offset, &cert, &certLength, &e);
        }

        byte[] body = TraceMessages.First(m => m.Message[0] == 11).Message[4..];
        byte[] list = body[(1 + body[0] + 3)..];
        int certLength = (list[0] << 16) | (list[1] << 8) | list[2];
        int extensionsAt = 3 + certLength;     // the first entry's extensions, at their uint16 length
        Assert.Equal(list.Length, extensionsAt + 2);
        Assert.Equal(0, (list[extensionsAt] << 8) | list[extensionsAt + 1]);  // (the trace's entry has none)
        Assert.Equal(list.Length, Entry(list, 0));

        Assert.Equal(-50, Entry(list, (nuint)list.Length));
        Assert.Equal(-50, Entry(list, (nuint)list.Length + 1));
        foreach (int cut in new[] { 0, 1, 2, 3, 4, extensionsAt - 1, extensionsAt, extensionsAt + 1 })
        {
            Assert.True(Entry(list[..cut], 0) == -50, $"cut at {cut}");
        }

        byte[] sct = [.. list[..extensionsAt], 0, 4, 0, 18, 0, 0];
        Assert.Equal(sct.Length, Entry(sct, 0));
        Assert.Equal(-50, Entry(sct[..^1], 0));                              // inside the extensions
        Assert.Equal(-47, Entry([.. list[..extensionsAt], 0, 4, 0, 51, 0, 0], 0));
        Assert.Equal(-50, Entry([0, 0, 0, 0, 0], 0));                        // cert_data<1..2^24-1>
    }

    /// <summary>An extension-block body (EncryptedExtensions's) read by the library.</summary>
    /// <param name="body">The block with its length.</param>
    /// <param name="message">The message's bit.</param>
    /// <returns>The answer and the block.</returns>
    private static (int Answer, TlsExtensions Extensions) Extensions(byte[] body, int message)
    {
        using var guard = new GuardedBuffer();
        byte* at = guard.AtPageEnd(body);
        TlsExtensions e;
        int answer = Native.Tls13ExtensionsMessageRead(&e, message, at, (nuint)body.Length);
        return (answer, e);
    }

    /// <summary>A CertificateRequest read by the library.</summary>
    /// <param name="body">The body.</param>
    /// <returns>The answer.</returns>
    private static int CertificateRequest(byte[] body)
    {
        using var guard = new GuardedBuffer();
        byte* at = guard.AtPageEnd(body);
        TlsExtensions e;
        byte* context;
        nuint contextLength;
        return Native.Tls13CertificateRequestRead(&e, &context, &contextLength, at, (nuint)body.Length);
    }

    /// <summary>A Certificate message read by the library, its entries walked.</summary>
    /// <param name="body">The body.</param>
    /// <returns>The answer (the entries' count, or minus an alert) and the certificates.</returns>
    private static (long Answer, List<byte[]> Certificates) Certificates(byte[] body)
    {
        using var guard = new GuardedBuffer();
        byte* at = guard.AtPageEnd(body);
        byte* context, list;
        nuint contextLength, listLength;
        long answer = Native.Tls13CertificateRead(at, (nuint)body.Length, &context, &contextLength, &list, &listLength);
        var certs = new List<byte[]>();
        if (answer > 0)
        {
            nuint offset = 0;
            for (long i = 0; i < answer; i++)
            {
                byte* cert;
                nuint certLength;
                TlsExtensions e;
                long next = Native.Tls13CertificateEntry(list, listLength, offset, &cert, &certLength, &e);
                Assert.True(next > (long)offset, $"entry {i}: {next}");
                certs.Add(new ReadOnlySpan<byte>(cert, (int)certLength).ToArray());
                offset = (nuint)next;
            }

            Assert.Equal(listLength, offset);
        }

        return (answer, certs);
    }

    /// <summary>A NewSessionTicket read by the library.</summary>
    /// <param name="body">The body.</param>
    /// <returns>The answer and the lifetime and age_add.</returns>
    private static (int Answer, ulong LifetimeAgeAdd) NewSessionTicket(byte[] body)
    {
        using var guard = new GuardedBuffer();
        byte* at = guard.AtPageEnd(body);
        TlsExtensions e;
        ulong lifetime;
        byte* nonce, ticket;
        int answer = Native.Tls13NewSessionTicketRead(&e, at, (nuint)body.Length, &lifetime, &nonce, &ticket);
        return (answer, lifetime);
    }

    /// <summary>
    /// Every one-octet change (+1, -1, xor 0x80) of every hello in RFC 8448's traces, every
    /// truncation and every inserted zero octet: the library answers what the model answers, and
    /// reads alike what both accept. Then every extension of each hello's block removed,
    /// doubled, moved to the end, and retyped as each type the library knows (misplacing it,
    /// or making it twice): the same agreement.
    /// </summary>
    [Fact]
    public void AgreesWithTheModelOnEveryChangeOfRfc8448sHellos()
    {
        Platform.RequireLinuxX64();
        int cases = 0;
        foreach ((int section, string name, byte[] message) in TraceMessages.Where(m => m.Message[0] is 1 or 2))
        {
            byte[] body = message[4..];
            int type = message[0];
            for (int i = 0; i < body.Length; i++)
            {
                foreach (int change in new[] { 1, -1, 0x80 })
                {
                    byte[] changed = (byte[])body.Clone();
                    changed[i] = change == 0x80 ? (byte)(changed[i] ^ 0x80) : (byte)(changed[i] + change);
                    Agree(changed, type, $"section {section} {name}: octet {i} {change:+0;-0}");
                    cases++;
                }

                Agree(body[..i], type, $"section {section} {name}: {i} octets");
                Agree([.. body[..i], 0, .. body[i..]], type, $"section {section} {name}: a 0 at {i}");
                cases += 2;
            }

            foreach ((string what, byte[] changed) in ExtensionChanges(body, type))
            {
                Agree(changed, type, $"section {section} {name}: {what}");
                cases++;
            }
        }

        Assert.True(cases > 10000, $"{cases} cases");
    }

    /// <summary>A hello body's extension-level changes: each extension removed, doubled, moved to
    /// the end, retyped as each known type; the block's length rewritten (the message's own
    /// framing is the caller's).</summary>
    /// <param name="body">A hello's body.</param>
    /// <param name="type">1 or 2.</param>
    /// <returns>The changes, named.</returns>
    private static IEnumerable<(string What, byte[] Body)> ExtensionChanges(byte[] body, int type)
    {
        TlsModel.Hello hello = TlsModel.ReadHello(body, type);
        int start = hello.Fields["extensions_block"], length = hello.Fields["extensions_length"];
        var extensions = new List<byte[]>();
        for (int at = start; at < start + length;)
        {
            int n = (body[at + 2] << 8) | body[at + 3];
            extensions.Add(body[at..(at + 4 + n)]);
            at += 4 + n;
        }

        byte[] Rebuild(IEnumerable<byte[]> list)
        {
            byte[] block = [.. list.SelectMany(e => e)];
            return [.. body[..(start - 2)], (byte)(block.Length >> 8), (byte)block.Length, .. block];
        }

        for (int i = 0; i < extensions.Count; i++)
        {
            int k = i;
            yield return ($"extension {k} removed", Rebuild(extensions.Where((_, j) => j != k)));
            yield return ($"extension {k} doubled", Rebuild(extensions.Take(k + 1).Append(extensions[k]).Concat(extensions.Skip(k + 1))));
            yield return ($"extension {k} last", Rebuild(extensions.Where((_, j) => j != k).Append(extensions[k])));
            foreach (int retype in TlsExtension.Types)
            {
                byte[] e = (byte[])extensions[k].Clone();
                e[0] = (byte)(retype >> 8);
                e[1] = (byte)retype;
                yield return ($"extension {k} as type {retype}", Rebuild(extensions.Take(k).Append(e).Concat(extensions.Skip(k + 1))));
            }
        }
    }

    /// <summary>
    /// The other messages of RFC 8448's traces changed as the hellos are: every one-octet change
    /// (+1, -1, xor 0x80), every truncation and every inserted zero octet of each
    /// EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify and
    /// NewSessionTicket. The library answers what the model answers, a Certificate's count of
    /// entries included (and an accepted Certificate's entries read one by one to its list's end,
    /// <see cref="Certificates"/>).
    /// </summary>
    [Fact]
    public void AgreesWithTheModelOnEveryChangeOfRfc8448sOtherMessages()
    {
        Platform.RequireLinuxX64();
        static long Ours(int type, byte[] body) => type switch
        {
            8 => Extensions(body, 4).Answer,
            13 => CertificateRequest(body),
            11 => Certificates(body).Answer,
            15 => CertificateVerify(body),
            _ => NewSessionTicket(body).Answer,
        };

        // (CertificateVerify's model is its whole syntax: a scheme, then signature<0..2^16-1>
        // running exactly to the end)
        static long Model(int type, byte[] body) => type switch
        {
            8 => TlsModel.ReadBlock(body, 0, body.Length, 4, out _),
            13 => TlsModel.ReadCertificateRequest(body),
            11 => TlsModel.ReadCertificate(body),
            15 => body.Length >= 4 && ((body[2] << 8) | body[3]) == body.Length - 4 ? 0 : -50,
            _ => TlsModel.ReadNewSessionTicket(body),
        };

        int cases = 0, kinds = 0;
        foreach (int type in new[] { 8, 13, 11, 15, 4 })
        {
            int before = cases;
            foreach ((int section, string name, byte[] message) in TraceMessages.Where(m => m.Message[0] == type))
            {
                byte[] body = message[4..];
                void Same(byte[] changed, string what)
                {
                    long ours = Ours(type, changed), model = Model(type, changed);
                    Assert.True(ours == model, $"section {section} {name}: {what}: the library answered {ours}, the model {model}");
                    cases++;
                }

                Same(body, "as sent");
                for (int i = 0; i < body.Length; i++)
                {
                    foreach (int change in new[] { 1, -1, 0x80 })
                    {
                        byte[] changed = (byte[])body.Clone();
                        changed[i] = change == 0x80 ? (byte)(changed[i] ^ 0x80) : (byte)(changed[i] + change);
                        Same(changed, $"octet {i} {change:+0;-0}");
                    }

                    Same(body[..i], $"{i} octets");
                    Same([.. body[..i], 0, .. body[i..]], $"a 0 at {i}");
                }
            }

            kinds += cases > before ? 1 : 0;
        }

        Assert.Equal(5, kinds);
        Assert.True(cases > 10000, $"{cases} cases");
    }

    /// <summary>
    /// Every known extension in every message 4.3's table (and the registry's column) allows it
    /// in, alone in an extension block read as that message's: samples of its data (well-formed
    /// ones and ones at and past each bound of its syntax: empty lists, odd lengths, a name or
    /// share of no octets, a group or name twice, binders and identities miscounted), each
    /// sample as it is, cut at every length, with an octet after it, and with each octet changed
    /// by +1, -1 and xor 0x80. The library answers what the model answers on each, so every rule
    /// of every checker meets inputs on both of its sides, in each message that reaches it.
    /// </summary>
    [Fact]
    public void AgreesWithTheModelOnEveryExtensionInEveryMessage()
    {
        Platform.RequireLinuxX64();
        static byte[] V16(params byte[] c) => [(byte)(c.Length >> 8), (byte)c.Length, .. c];
        static byte[] V8(params byte[] c) => [(byte)c.Length, .. c];
        static byte[] Ascii(string s) => System.Text.Encoding.ASCII.GetBytes(s);

        // pre_shared_key's OfferedPsks: identities of three octets each, binders of binderLength
        // octets (32, SHA-256's, unless a bound is under test)
        static byte[] OfferedPsks(int identities, int binders, int binderLength = 32)
        {
            var ids = new List<byte>();
            for (int i = 0; i < identities; i++)
            {
                ids.AddRange([.. V16(1, 2, (byte)i), 0, 0, 0, 1]);
            }

            var proofs = new List<byte>();
            for (int i = 0; i < binders; i++)
            {
                proofs.AddRange(V8(new byte[binderLength]));
            }

            return [.. V16([.. ids]), .. V16([.. proofs])];
        }

        static byte[][] Samples(int type, int message)
        {
            byte[] share = new byte[32];
            return (type, message) switch
            {
                // (a list whose name is cut after its type, or inside its length, is a list
                // whose own length still fits: only such a sample reaches the name's bounds)
                (0, 1) => [V16([0, .. V16(Ascii("example.com"))]), V16([0, .. V16(Ascii("a")), 0, .. V16(Ascii("b"))]), V16([1, .. V16(Ascii("a"))]), V16([0, .. V16()]), V16(0), V16(0, 0), V16()],
                (0, 16) => [[], [1, 2, 3]],
                (0, _) => [[], [0]],
                (10 or 13 or 50, _) => [V16(0, 0x1D, 0, 0x17), V16(0x1D), V16(), V16(0, 0x1D, 0)],
                (16, 4) => [V16(V8(Ascii("h2"))), V16([.. V8(Ascii("h2")), .. V8(Ascii("h3"))]), V16(V8()), V16()],
                (16, _) => [V16([.. V8(Ascii("h2")), .. V8(Ascii("http/1.1"))]), V16(V8()), V16()],
                (27, _) => [V8(0, 1, 0, 2), V8(0), V8()],
                (28, _) => [[0x40, 0x01], [0, 64], [0, 63], [0, 0]],
                // (a binders list of 32 octets is under its 33; one of two 31-octet binders
                // passes that bound and breaks PskBinderEntry's 32)
                (41, 1) => [OfferedPsks(1, 1), OfferedPsks(2, 2), OfferedPsks(1, 2), OfferedPsks(2, 1), OfferedPsks(1, 1, 31), OfferedPsks(1, 2, 31), [.. V16(), .. V16()]],
                (41, _) => [[0, 0], [0, 1]],
                (42, 32) => [[0, 0, 0x40, 0]],
                (42, _) => [[]],
                (43, 1) => [V8(3, 4, 3, 3), V8(3, 4), V8(3), V8()],
                (43, _) => [[3, 4]],
                (44, _) => [V16(1, 2, 3), V16(1), V16()],
                (45, _) => [V8(1), V8(0, 1), V8()],
                (47, _) => [V16(V16(0x30, 0)), V16([.. V16(0x30, 0), .. V16(0x30, 3, 0x31, 1, 0)]), V16(V16()), V16()],
                (48, _) => [V16([.. V8(0x55, 0x1D, 0x25), .. V16(0x30, 0)]), V16([.. V8(0x55), .. V16()]), V16([.. V8(), .. V16(0x30, 0)]), V16()],
                (49, _) => [[]],
                (51, 1) => [V16([0, 0x1D, .. V16(share), 0, 0x17, .. V16(4, 1, 2)]), V16([0, 0x1D, .. V16(share), 0, 0x1D, .. V16(7)]), V16([0, 0x1D, .. V16()]), V16()],
                (51, 2) => [[0, 0x1D, .. V16(share)], [0, 0x1D, .. V16()]],
                (51, 64) => [[0, 0x1D]],
                (58, 1) => [[1, 1]],
                (58, _) => [[1]],
                _ => [[1, 2, 3], []],
            };
        }

        int cases = 0, pairs = 0;
        for (int index = 0; index < TlsExtension.Types.Length; index++)
        {
            int type = TlsExtension.Types[index];
            foreach (int message in new[] { 1, 2, 4, 8, 16, 32, 64 })
            {
                if ((TlsExtension.Allowed[index] & message) == 0)
                {
                    continue;
                }

                pairs++;
                foreach (byte[] sample in Samples(type, message))
                {
                    void Same(byte[] data, string what)
                    {
                        byte[] body = V16([(byte)(type >> 8), (byte)type, .. V16(data)]);
                        int ours = Extensions(body, message).Answer, model = TlsModel.ReadBlock(body, 0, body.Length, message, out _);
                        Assert.True(ours == model, $"type {type} in message {message}: {what} ({Convert.ToHexString(data)}): the library answered {ours}, the model {model}");
                        cases++;
                    }

                    Same(sample, "the sample");
                    Same([.. sample, 0], "an octet after it");
                    for (int i = 0; i < sample.Length; i++)
                    {
                        Same(sample[..i], $"{i} octets");
                        foreach (int change in new[] { 1, -1, 0x80 })
                        {
                            byte[] changed = (byte[])sample.Clone();
                            changed[i] = change == 0x80 ? (byte)(changed[i] ^ 0x80) : (byte)(changed[i] + change);
                            Same(changed, $"octet {i} {change:+0;-0}");
                        }
                    }
                }
            }
        }

        Assert.Equal(TlsExtension.Allowed.Sum(a => System.Numerics.BitOperations.PopCount((uint)a)), pairs);
        Assert.True(cases > 4000, $"{cases} cases");    // 4,346 when written
    }

    /// <summary>A CertificateVerify read by the library, against a guard page.</summary>
    /// <param name="body">The body.</param>
    /// <returns>0 or minus an alert.</returns>
    private static int CertificateVerify(byte[] body)
    {
        using var guard = new GuardedBuffer();
        byte* at = guard.AtPageEnd(body);
        uint scheme;
        byte* signature;
        nuint signatureLength;
        return Native.Tls13CertificateVerifyRead(at, (nuint)body.Length, &scheme, &signature, &signatureLength);
    }

    /// <summary>
    /// 3,000 random ClientHellos and 1,000 random ServerHellos built from random choices of every
    /// field and of extensions (known and unknown types, well-formed and broken data, in any
    /// order, sometimes twice): the library and the model agree on each.
    /// </summary>
    [Fact]
    public void AgreesWithTheModelOnRandomHellos()
    {
        Platform.RequireLinuxX64();
        var random = new Random(9846);
        for (int i = 0; i < 4000; i++)
        {
            int type = i < 3000 ? 1 : 2;
            Agree(RandomHello(random, type), type, $"random hello {i}");
        }
    }

    /// <summary>A random hello body: valid more often than not, broken in one place otherwise.</summary>
    /// <param name="random">The generator.</param>
    /// <param name="type">1 or 2.</param>
    /// <returns>The body.</returns>
    private static byte[] RandomHello(Random random, int type)
    {
        var b = new List<byte> { 3, 3 };
        b.AddRange(random.Next(20) == 0 ? Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C") : RandomNumberGenerator.GetBytes(32));
        int session = random.Next(4) == 0 ? random.Next(34) : random.Next(2) * 32;
        b.Add((byte)session);
        b.AddRange(new byte[Math.Min(session, 32)]);
        if (type == 1)
        {
            int suites = random.Next(10) == 0 ? random.Next(5) : 2 * random.Next(1, 8);
            b.AddRange([(byte)(suites >> 8), (byte)suites]);
            b.AddRange(RandomNumberGenerator.GetBytes(suites));
            int methods = random.Next(10) == 0 ? random.Next(3) : 1;
            b.Add((byte)methods);
            b.AddRange(random.Next(10) == 0 ? RandomNumberGenerator.GetBytes(methods) : new byte[methods]);
        }
        else
        {
            b.AddRange([0x13, (byte)random.Next(1, 4), (byte)(random.Next(15) == 0 ? 1 : 0)]);
        }

        var extensions = new List<byte[]>();
        int count = random.Next(0, 12);
        for (int k = 0; k < count; k++)
        {
            int t = random.Next(4) == 0 ? random.Next(0, 70) : TlsExtension.Types[random.Next(TlsExtension.Types.Length)];
            byte[] data = RandomExtensionData(random, t, type);
            extensions.Add([(byte)(t >> 8), (byte)t, (byte)(data.Length >> 8), (byte)data.Length, .. data]);
        }

        if (random.Next(5) == 0 && extensions.Count > 0)
        {
            extensions.Add(extensions[random.Next(extensions.Count)]);
        }

        byte[] block = [.. extensions.SelectMany(e => e)];
        if (random.Next(30) != 0)
        {
            b.AddRange([(byte)(block.Length >> 8), (byte)block.Length]);
        }

        b.AddRange(block);
        return [.. b];
    }

    /// <summary>Random data for an extension of a type: its structure most of the time.</summary>
    /// <param name="random">The generator.</param>
    /// <param name="type">The extension type.</param>
    /// <param name="message">1 or 2 (the hello).</param>
    /// <returns>The data.</returns>
    private static byte[] RandomExtensionData(Random random, int type, int message)
    {
        if (random.Next(6) == 0)
        {
            return RandomNumberGenerator.GetBytes(random.Next(0, 9));
        }

        static byte[] V16(byte[] c) => [(byte)(c.Length >> 8), (byte)c.Length, .. c];
        static byte[] V8(byte[] c) => [(byte)c.Length, .. c];
        byte[] pairs = RandomNumberGenerator.GetBytes(2 * random.Next(1, 5));
        return type switch
        {
            0 => message == 1 ? V16([0, .. V16("example.com"u8.ToArray())]) : [],
            10 or 13 or 50 => V16(pairs),
            16 => V16([.. V8("h2"u8.ToArray()), .. V8("http/1.1"u8.ToArray())]),
            27 => V8(pairs),
            28 => [0x40, (byte)random.Next(0, 3)],
            41 => message == 1 ? [.. V16([.. V16([1, 2, 3]), 0, 0, 0, 1]), .. V16(V8(new byte[32]))] : [0, 0],
            42 => [],
            43 => message == 1 ? V8([3, 4, 3, 3]) : [3, 4],
            44 => V16([1, 2, 3]),
            45 => V8([1]),
            47 => V16(V16([0x30, 0])),
            49 => [],
            51 => message == 1 ? V16([0, 0x1D, .. V16(new byte[32]), 0, 0x17, .. V16(new byte[65])]) : [0, 0x1D, .. V16(new byte[32])],
            58 => [1, 1],
            _ => RandomNumberGenerator.GetBytes(random.Next(0, 6)),
        };
    }

    /// <summary>
    /// The rules by name: a type twice (illegal_parameter), a type 4.3's table puts in other
    /// messages (illegal_parameter: key_share in EncryptedExtensions, early_data in a
    /// ServerHello, TLS 1.2's extended_master_secret in a ServerHello), pre_shared_key not last
    /// in a ClientHello (illegal_parameter, 4.3.11), an extension past its block (decode_error),
    /// trailing data in an extension (decode_error), a TLS 1.3 ClientHello with a compression
    /// method other than the one 0 and a ServerHello's other than 0 (illegal_parameter), a
    /// record_size_limit below 64, a key_share group twice, a binder count other than the
    /// identities' (illegal_parameter), an EncryptedExtensions ALPN of two names (decode_error),
    /// a CertificateRequest without signature_algorithms (missing_extension), a KeyUpdate other
    /// than 0 or 1 (illegal_parameter); and unknown types, GREASE among them, passed over.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.3-6#2", "RFC9846-4.3-10", "RFC9846-4.3-13#3", "RFC9846-4.3.11-11#2", "RFC9846-4.2.2-7.10.1#2", "RFC9846-4.2.3-4.10.1#2",
        "RFC9846-4.3.8-10#4", "RFC9846-4.4.2-4.4.1#1", "RFC9846-4.7.3-3.2.1", "RFC9846-4.2.2-7.12.1")]
    public void RefusesWhatTheRulesForbid()
    {
        Platform.RequireLinuxX64();
        static byte[] E(int type, params byte[] data) => [(byte)(type >> 8), (byte)type, (byte)(data.Length >> 8), (byte)data.Length, .. data];
        static byte[] Block(params byte[][] e)
        {
            byte[] b = [.. e.SelectMany(x => x)];
            return [(byte)(b.Length >> 8), (byte)b.Length, .. b];
        }

        byte[] versions = E(43, 2, 3, 4);
        byte[] ClientHello(byte[] compression, params byte[][] e) =>
            [3, 3, .. new byte[32], 0, 0, 2, 0x13, 0x01, (byte)compression.Length, .. compression, .. Block(e)];
        byte[] ServerHello(byte compression, params byte[][] e) => [3, 3, .. new byte[32], 0, 0x13, 0x01, compression, .. Block(e)];
        Assert.Equal(0, Agree(ClientHello([0], versions), 1, "a minimal TLS 1.3 ClientHello"));
        Assert.Equal(-47, Agree(ClientHello([0], versions, versions), 1, "supported_versions twice"));
        Assert.Equal(-47, Agree(ClientHello([0], versions, E(0x1A1A), E(0x1A1A)), 1, "an unknown type twice"));
        Assert.Equal(0, Agree(ClientHello([0], versions, E(0x1A1A), E(0x2A2A, 0)), 1, "GREASE passed over"));
        Assert.Equal(-47, Agree(ClientHello([0], versions, E(41, [0, 10, 0, 4, 1, 2, 3, 4, 0, 0, 0, 0, 0, 33, 32, .. new byte[32]]), E(42)), 1, "pre_shared_key not last"));
        Assert.Equal(0, Agree(ClientHello([0], versions, E(42), E(41, [0, 10, 0, 4, 1, 2, 3, 4, 0, 0, 0, 0, 0, 33, 32, .. new byte[32]])), 1, "pre_shared_key last"));
        Assert.Equal(-47, Agree(ClientHello([0], versions, E(41, [0, 10, 0, 4, 1, 2, 3, 4, 0, 0, 0, 0, 0, 66, 32, .. new byte[32], 32, .. new byte[32]])), 1, "two binders for one identity"));
        Assert.Equal(-47, Agree(ClientHello([1, 0], versions), 1, "TLS 1.3 with another compression method"));
        Assert.Equal(0, Agree(ClientHello([1, 0], E(43, 2, 3, 3)), 1, "TLS 1.2 only: the methods are TLS 1.2's"));
        Assert.Equal(-47, Agree(ClientHello([0], versions, E(28, 0, 63)), 1, "record_size_limit 63"));
        Assert.Equal(0, Agree(ClientHello([0], versions, E(28, 0, 64)), 1, "record_size_limit 64"));
        Assert.Equal(-47, Agree(ClientHello([0], versions, E(51, 0, 10, 0, 29, 0, 1, 7, 0, 29, 0, 1, 8)), 1, "a key_share group twice"));
        Assert.Equal(-50, Agree(ClientHello([0], E(43, 2, 3, 4, 0)), 1, "trailing data in supported_versions"));
        Assert.Equal(-50, Agree(ClientHello([0], [0, 43, 0, 4, 2, 3, 4]), 1, "an extension past its block"));
        Assert.Equal(-47, Agree(ServerHello(1, E(43, 3, 4)), 2, "a ServerHello's compression method 1"));
        Assert.Equal(-47, Agree(ServerHello(0, E(43, 3, 4), E(42)), 2, "early_data in a ServerHello"));
        Assert.Equal(-47, Agree(ServerHello(0, E(43, 3, 4), E(23)), 2, "extended_master_secret in a TLS 1.3 ServerHello"));
        Assert.Equal(0, Agree(ServerHello(0, E(43, 3, 4), E(51, [0, 29, 0, 32, .. new byte[32]])), 2, "a ServerHello's key_share"));

        // the hello reader reads hellos only: another type is the caller's error (-1), not an alert
        Assert.Equal(-1, Hello(ClientHello([0], versions), 3).Answer);
        Assert.Equal(-1, Hello(ClientHello([0], versions), 0).Answer);

        // EncryptedExtensions, CertificateRequest, KeyUpdate
        Assert.Equal(-47, Extensions(Block(E(51, 0, 29, 0, 1, 7)), 4).Answer);              // key_share in EncryptedExtensions
        Assert.Equal(-50, Extensions(Block(E(16, 0, 7, 2, (byte)'h', (byte)'2', 2, (byte)'h', (byte)'3')), 4).Answer);  // ALPN: two names
        Assert.Equal(0, Extensions(Block(E(16, 0, 3, 2, (byte)'h', (byte)'2')), 4).Answer);
        Assert.Equal(-109, CertificateRequest([0, .. Block(E(47, 0, 3, 0, 1, 0x30))]));
        Assert.Equal(0, CertificateRequest([0, .. Block(E(13, 0, 2, 8, 4))]));
        fixed (byte* zero = new byte[] { 0, 1, 2 })
        {
            Assert.Equal(0, Native.Tls13KeyUpdateRead(zero, 1));
            Assert.Equal(1, Native.Tls13KeyUpdateRead(zero + 1, 1));
            Assert.Equal(-47, Native.Tls13KeyUpdateRead(zero + 2, 1));
            Assert.Equal(-50, Native.Tls13KeyUpdateRead(zero, 2));
            Assert.Equal(-50, Native.Tls13KeyUpdateRead(zero, 0));
        }

        // A NewSessionTicket's extensions<0..2^16-2> (4.7.1): a block of 65,534 octets (one
        // unknown extension filling it) reads; one of 65,535, a length its uint16 can say but
        // the vector may not hold, is decode_error. (Over a page: in native memory.)
        static byte[] Two(int n) => [(byte)(n >> 8), (byte)n];
        foreach (int blockLength in new[] { 65534, 65535 })
        {
            byte[] extension = [0x12, 0x34, .. Two(blockLength - 4), .. new byte[blockLength - 4]];
            byte[] ticket = [0, 0, 0x0E, 0x10, 1, 2, 3, 4, 0, 0, 1, 0x7F, .. Two(blockLength), .. extension];
            int expected = blockLength == 65534 ? 0 : -50;
            Assert.Equal(expected, TlsModel.ReadNewSessionTicket(ticket));
            TlsExtensions e;
            ulong lifetime;
            byte* nonce, opaque;
            fixed (byte* b = ticket)
            {
                Assert.Equal(expected, Native.Tls13NewSessionTicketRead(&e, b, (nuint)ticket.Length, &lifetime, &nonce, &opaque));
            }
        }
    }

    /// <summary>
    /// The duplicate checks cost linear time, so a hostile ClientHello cannot buy a square: an
    /// extension block of 16,000 extensions of distinct types read (the last of them twice:
    /// illegal_parameter, found), and a key_share of 13,000 entries of distinct groups read (one
    /// group twice: found), all well within a second.
    /// </summary>
    [Fact]
    public void ChecksDuplicatesInLinearTime()
    {
        Platform.RequireLinuxX64();
        var clock = System.Diagnostics.Stopwatch.StartNew();
        byte[] Many(int count, bool repeat)
        {
            var block = new List<byte>();
            for (int i = 0; i < count; i++)
            {
                int type = repeat && i == count - 1 ? 1000 : 1000 + i;
                block.AddRange([(byte)(type >> 8), (byte)type, 0, 0]);
            }

            return [.. block];
        }

        foreach (bool repeat in new[] { false, true })
        {
            byte[] block = Many(16000, repeat);
            TlsExtensions e;
            fixed (byte* b = block)
            {
                Assert.Equal(repeat ? -47 : 0, Native.TlsExtensionsRead(&e, 1, b, (nuint)block.Length));
            }

            if (!repeat)
            {
                Assert.Equal(16000u, e.Count);
            }
        }

        foreach (bool repeat in new[] { false, true })
        {
            var shares = new List<byte>();
            for (int i = 0; i < 13000; i++)
            {
                int group = repeat && i == 12999 ? 5 : i;
                shares.AddRange([(byte)(group >> 8), (byte)group, 0, 1, 7]);
            }

            byte[] data = [(byte)(shares.Count >> 8), (byte)shares.Count, .. shares];
            byte[] body = [3, 3, .. new byte[32], 0, 0, 2, 0x13, 0x01, 1, 0, .. TwoOctets(4 + data.Length + 7), 0, 43, 0, 3, 2, 3, 4, 0, 51, .. TwoOctets(data.Length), .. data];
            Assert.Equal(repeat ? -47 : 0, Hello(body, 1).Answer);
        }

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1), $"took {clock.Elapsed}");

        static byte[] TwoOctets(int n) => [(byte)(n >> 8), (byte)n];
    }
}
