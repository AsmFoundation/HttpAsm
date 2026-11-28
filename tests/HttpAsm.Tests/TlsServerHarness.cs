using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// The engine's random source as a script: the octets of each draw given in the order the engine
/// draws them (httpasm_tls13_receive's documented order: the server random, the key share's
/// private parts, the CertificateVerify's salt or hedge), so a test replays a trace's randomness
/// and checks the engine asked for exactly what it should. Past the script, draws are random
/// (<see cref="Fallback"/>) or refused.
/// </summary>
internal sealed class RandomScript
{
    /// <summary>The draws still to give, in order.</summary>
    private readonly Queue<byte[]> draws = new();

    /// <summary>Whether a draw past the script gets random octets (true) or is refused.</summary>
    public bool Fallback { get; init; } = true;

    /// <summary>When set, every draw is refused (the source failed): the engine must answer
    /// internal_error.</summary>
    public bool Broken { get; set; }

    /// <summary>The one draw refused, counted from 1 in the engine's order (0: none): a test
    /// walks it over every draw of a handshake to reach each draw site's failure path, which a
    /// source that fails from the start (<see cref="Broken"/>) never passes the first of.</summary>
    public int FailAt { get; init; }

    /// <summary>The lengths of the draws the engine made, in order.</summary>
    public List<int> Lengths { get; } = [];

    /// <summary>What went wrong: a draw of another length than the script's next.</summary>
    public List<string> Failures { get; } = [];

    /// <summary>Appends draws to the script.</summary>
    /// <param name="octets">Each draw's octets.</param>
    /// <returns>This script.</returns>
    public RandomScript Then(params byte[][] octets)
    {
        foreach (byte[] o in octets)
        {
            draws.Enqueue(o);
        }

        return this;
    }

    /// <summary>The draws left unused.</summary>
    public int Left => draws.Count;

    /// <summary>Fills one draw.</summary>
    /// <param name="output">Where the engine wants the octets.</param>
    /// <returns>Whether the draw succeeded.</returns>
    public bool Next(Span<byte> output)
    {
        Lengths.Add(output.Length);
        if (Broken || Lengths.Count == FailAt)
        {
            return false;
        }

        if (draws.TryDequeue(out byte[]? next))
        {
            if (next.Length != output.Length)
            {
                Failures.Add($"draw {Lengths.Count}: {output.Length} octets asked, the script's {next.Length}");
                return false;
            }

            next.CopyTo(output);
            return true;
        }

        if (!Fallback)
        {
            Failures.Add($"draw {Lengths.Count}: past the script");
            return false;
        }

        RandomNumberGenerator.Fill(output);
        return true;
    }
}

/// <summary>Changes a configuration in place (a pointer type cannot be a generic argument, so
/// not an Action).</summary>
/// <param name="config">The configuration.</param>
internal unsafe delegate void ConfigSetter(TlsServerConfig* config);

/// <summary>
/// One TLS 1.3 server connection of the library's engine, in native memory this harness owns: the
/// private key (httpasm_private_key_load), the configuration, the Certificate message's buffer,
/// the connection and its spans, and an input buffer records are copied into (a protected record
/// is opened in place there). Records go in (<see cref="Receive"/>), the output comes out
/// (<see cref="TakeOutput()"/>).
/// </summary>
internal sealed unsafe class TlsServerHarness : IDisposable
{
    /// <summary>The input buffer's size: several whole records.</summary>
    private const int InputSize = 1 << 18;

    /// <summary>
    /// Where the connection keeps our record key's sequence number: httpasm_tls13_connection's
    /// .write (1696: the fields before it, httpasm_abi.inc's struc, summed) plus the record key's
    /// .sequence (8). The C header keeps the connection opaque; the tests that reach AES-GCM's
    /// 2^24.5-record limit set it instead of sealing 23 million records, and check first that it
    /// holds what it must (the records sent so far), so a moved field fails them loudly.
    /// </summary>
    private const int WriteSequenceOffset = 1696 + 8;

    /// <summary>The loaded private key.</summary>
    private readonly PrivateKey* key;

    /// <summary>The configuration (kept by pointer by the connection).</summary>
    private readonly TlsServerConfig* config;

    /// <summary>The Certificate message's buffer.</summary>
    private readonly byte* certificate;

    /// <summary>The connection.</summary>
    private readonly TlsConnection* connection;

    /// <summary>The connection's spans.</summary>
    private readonly byte* memory;

    /// <summary>Where records are copied for the engine.</summary>
    private readonly byte* input;

    /// <summary>The script's handle, the random callback's context.</summary>
    private GCHandle source;

    /// <summary>Whether server_init took the connection (so its spans exist and Dispose wipes
    /// them).</summary>
    private bool started;

    /// <summary>The random source the engine draws from.</summary>
    public RandomScript Random { get; }

    /// <summary>httpasm_tls13_server_config_init's answer (0: the connection was started).</summary>
    public int ConfigAnswer { get; }

    /// <summary>The configuration as initialized (a copy).</summary>
    public TlsServerConfig Config => *config;

    /// <summary>
    /// Loads the key, initializes the configuration and starts the connection.
    /// </summary>
    /// <param name="keyFile">The private key's file (DER or PEM).</param>
    /// <param name="chain">The DER certificates, the leaf first.</param>
    /// <param name="random">The random source (a fresh random one when null).</param>
    /// <param name="groups">The server's groups in order (null: the library's).</param>
    /// <param name="suites">Its suites in order (null: the library's).</param>
    /// <param name="flags">HTTPASM_TLS_CLIENT_AUTH_* and HTTPASM_TLS_SERVER_GROUP_ORDER.</param>
    /// <param name="maxMessage">The largest handshake message gathered (0: the default).</param>
    /// <param name="beforeStart">Changes the configuration after init and before the
    /// connection starts: what a caller that edits a configuration it already initialized does
    /// (its sizes then no longer hold), so a test can prove the engine still never writes past
    /// its spans. Null: nothing changed.</param>
    /// <param name="libraryRandom">Draw from the library's own source (httpasm_tls_random) instead
    /// of <see cref="Random"/>, whose script then sees no draws.</param>
    /// <exception cref="InvalidOperationException">The key does not load, or the configuration
    /// is accepted but the connection does not start.</exception>
    public TlsServerHarness(byte[] keyFile, IReadOnlyList<byte[]> chain, RandomScript? random = null, ushort[]? groups = null,
        ushort[]? suites = null, uint flags = 0, uint maxMessage = 0, ConfigSetter? beforeStart = null, bool libraryRandom = false)
    {
        Random = random ?? new RandomScript();
        source = GCHandle.Alloc(Random);
        key = (PrivateKey*)NativeMemory.AllocZeroed((nuint)sizeof(PrivateKey));
        config = (TlsServerConfig*)NativeMemory.AllocZeroed((nuint)sizeof(TlsServerConfig));
        int total = 8 + chain.Sum(c => c.Length + 5);
        certificate = (byte*)NativeMemory.AllocZeroed((nuint)total);
        connection = (TlsConnection*)NativeMemory.AlignedAlloc((nuint)sizeof(TlsConnection), 16);
        // zeroed: a connection server_init refused is left as it was (nothing written), and
        // Dispose must not take garbage for its span pointers (it wipes only a started one too)
        new Span<byte>(connection, sizeof(TlsConnection)).Clear();
        input = (byte*)NativeMemory.AllocZeroed(InputSize);
        fixed (byte* k = keyFile)
        {
            if (Native.PrivateKeyLoad(key, k, (nuint)keyFile.Length) <= 0)
            {
                Dispose();
                throw new InvalidOperationException("the key does not load");
            }
        }

        config->Key = key;
        config->Random = &Draw;
        config->RandomContext = (void*)GCHandle.ToIntPtr(source);
        if (libraryRandom)
        {
            // the export the C header documents for this field (its context unused); the
            // library is the one the bindings already loaded, so Load only finds it
            nint library = NativeLibrary.Load("httpasm", typeof(Native).Assembly, null);
            config->Random = (delegate* unmanaged<void*, byte*, nuint, int>)NativeLibrary.GetExport(library, "httpasm_tls_random");
            config->RandomContext = null;
        }
        if (groups is not null)
        {
            for (int i = 0; i < groups.Length; i++)
            {
                config->Groups[i] = groups[i];
            }

            config->GroupCount = (uint)groups.Length;
        }

        if (suites is not null)
        {
            for (int i = 0; i < suites.Length; i++)
            {
                config->Suites[i] = suites[i];
            }

            config->SuiteCount = (uint)suites.Length;
        }

        config->Flags = flags;
        config->MaxMessage = maxMessage;

        // the "out" fields start cleared, so what they hold after init is init's own
        config->Certificate = null;
        config->CertificateLength = 0;
        config->Schemes = 0;
        config->OutputMin = 0;
        config->Memory = 0;
        ConfigAnswer = InitConfig(config, chain, certificate, (nuint)total);
        if (ConfigAnswer != 0)
        {
            return;
        }

        // the memory is sized before the change: a changed configuration meets the memory init
        // measured (server_init checks the length against config->memory, which init wrote)
        nuint size = config->Memory;
        beforeStart?.Invoke(config);
        memory = (byte*)NativeMemory.AllocZeroed(size);
        started = Native.Tls13ServerInit(connection, config, memory, size) == 0;
        if (!started)
        {
            Dispose();
            throw new InvalidOperationException("the connection does not start");
        }
    }

    /// <summary>httpasm_tls13_server_config_init over a managed chain.</summary>
    /// <param name="config">The configuration.</param>
    /// <param name="chain">The certificates.</param>
    /// <param name="buffer">The Certificate message's buffer.</param>
    /// <param name="capacity">Its octets.</param>
    /// <returns>The library's answer.</returns>
    internal static int InitConfig(TlsServerConfig* config, IReadOnlyList<byte[]> chain, byte* buffer, nuint capacity)
    {
        // the chain's arrays pinned for the call only: the library copies them into the buffer
        var handles = chain.Select(c => GCHandle.Alloc(c, GCHandleType.Pinned)).ToArray();
        try
        {
            byte** pointers = stackalloc byte*[Math.Max(1, chain.Count)];
            nuint* lengths = stackalloc nuint[Math.Max(1, chain.Count)];
            for (int i = 0; i < chain.Count; i++)
            {
                pointers[i] = (byte*)handles[i].AddrOfPinnedObject();
                lengths[i] = (nuint)chain[i].Length;
            }

            return Native.Tls13ServerConfigInit(config, pointers, lengths, (nuint)chain.Count, buffer, capacity);
        }
        finally
        {
            foreach (GCHandle h in handles)
            {
                h.Free();
            }
        }
    }

    /// <summary>The engine's random callback: the script in the context fills the draw.</summary>
    /// <param name="context">The script's GCHandle.</param>
    /// <param name="output">The octets to fill.</param>
    /// <param name="length">How many.</param>
    /// <returns>0, or -1 when the script refuses.</returns>
    [UnmanagedCallersOnly]
    private static int Draw(void* context, byte* output, nuint length)
    {
        var script = (RandomScript)GCHandle.FromIntPtr((nint)context).Target!;
        return script.Next(new Span<byte>(output, (int)length)) ? 0 : -1;
    }

    /// <summary>What one call of httpasm_tls13_receive answered.</summary>
    /// <param name="Answer">The octets consumed, 0, or -1.</param>
    /// <param name="Event">The event.</param>
    /// <param name="Data">DATA's plaintext, copied out (empty otherwise).</param>
    internal readonly record struct Received(long Answer, TlsEvent Event, byte[] Data);

    /// <summary>Gives the engine octets (copied into the native input buffer) and calls
    /// httpasm_tls13_receive once.</summary>
    /// <param name="octets">What arrived: one record or more, or part of one.</param>
    /// <returns>Its answer.</returns>
    /// <exception cref="ArgumentException">More octets than the input buffer holds.</exception>
    public Received Receive(ReadOnlySpan<byte> octets)
    {
        if (octets.Length > InputSize)
        {
            throw new ArgumentException("too long for the input buffer", nameof(octets));
        }

        octets.CopyTo(new Span<byte>(input, octets.Length));
        TlsEvent e;
        long answer = Native.Tls13Receive(connection, input, (nuint)octets.Length, &e);
        byte[] data = e.Kind == TlsEngine.EventData ? new ReadOnlySpan<byte>(e.Data, (int)e.Length).ToArray() : [];
        return new Received(answer, e, data);
    }

    /// <summary>Gives the engine a stream of records, one call a record until it is all taken or
    /// a call answers 0 or -1.</summary>
    /// <param name="octets">The records.</param>
    /// <returns>Each call's answer.</returns>
    public List<Received> ReceiveAll(ReadOnlySpan<byte> octets)
    {
        var answers = new List<Received>();
        while (octets.Length > 0)
        {
            Received r = Receive(octets);
            answers.Add(r);
            if (r.Answer <= 0)
            {
                break;
            }

            octets = octets[(int)r.Answer..];
        }

        return answers;
    }

    /// <summary>Takes everything queued in the output.</summary>
    /// <returns>The octets.</returns>
    public byte[] TakeOutput() => TakeOutput(int.MaxValue);

    /// <summary>Takes the first octets queued in the output, as a caller whose socket took only
    /// part of them does: the rest stays queued, ahead of what comes next.</summary>
    /// <param name="most">The octets to take at most.</param>
    /// <returns>The octets taken.</returns>
    public byte[] TakeOutput(int most)
    {
        byte* o;
        nuint n = Native.Tls13Output(connection, &o);
        n = Math.Min(n, (nuint)most);
        byte[] taken = new ReadOnlySpan<byte>(o, (int)n).ToArray();
        Native.Tls13OutputDone(connection, n);
        return taken;
    }

    /// <summary>The octets queued in the output, left there.</summary>
    public int Queued
    {
        get
        {
            byte* o;
            return (int)Native.Tls13Output(connection, &o);
        }
    }

    /// <summary>
    /// Our record key's next sequence number, read and written in the connection itself
    /// (<see cref="WriteSequenceOffset"/>): white-box, for the tests of AES-GCM's record limit.
    /// </summary>
    /// <remarks>Footgun: written while a test's client keeps its own count, the two disagree
    /// until the client's is set to match (<see cref="TlsTestClient.SetReadSequence"/>).</remarks>
    public ulong WriteSequence
    {
        get => *(ulong*)((byte*)connection + WriteSequenceOffset);
        set => *(ulong*)((byte*)connection + WriteSequenceOffset) = value;
    }

    /// <summary>httpasm_tls13_negotiated with every out pointer NULL (the C header allows each):
    /// the progress alone.</summary>
    /// <returns>The progress.</returns>
    public int Progress() => Native.Tls13Negotiated(connection, null, null, null);

    /// <summary>httpasm_tls13_peer_certificates: the client's certificate_list as the connection
    /// keeps it.</summary>
    /// <returns>The answer (the entries, or -1) and the list's octets (empty before the
    /// client's Certificate).</returns>
    public (int Count, byte[] List) PeerCertificates()
    {
        byte* list;
        nuint length;
        int count = Native.Tls13PeerCertificates(connection, &list, &length);
        return (count, count < 0 ? [] : new ReadOnlySpan<byte>(list, (int)length).ToArray());
    }

    /// <summary>httpasm_tls13_request_certificate on this connection: post-handshake
    /// authentication's CertificateRequest queued in the output (take it with
    /// <see cref="TakeOutput()"/>); the client's answer then goes through <see cref="Receive"/>.
    /// The request's context comes from the configured random source, so a FailAt counted to
    /// that draw makes this call fail.</summary>
    /// <returns>0 (queued), or -1 with nothing sent or changed.</returns>
    public int RequestCertificate() => Native.Tls13RequestCertificate(connection);

    /// <summary>httpasm_tls13_peer_certificates with both out pointers NULL (the C header allows
    /// either): the count alone.</summary>
    /// <returns>The entries, or -1.</returns>
    public int PeerCount() => Native.Tls13PeerCertificates(connection, null, null);

    /// <summary>The client's certificates, each entry's cert_data, walked out of the list the
    /// connection keeps by the library's own entry reader (httpasm_tls13_certificate_entry).</summary>
    /// <returns>The DER certificates, the leaf first (empty when none).</returns>
    /// <exception cref="InvalidDataException">The kept list does not walk (the engine kept what
    /// it should not have).</exception>
    public List<byte[]> PeerChain()
    {
        byte* list;
        nuint length;
        var chain = new List<byte[]>();
        if (Native.Tls13PeerCertificates(connection, &list, &length) <= 0)
        {
            return chain;
        }

        TlsExtensions extensions;
        nuint at = 0;
        while (at < length)
        {
            byte* certificate;
            nuint n;
            long next = Native.Tls13CertificateEntry(list, length, at, &certificate, &n, &extensions);
            if (next <= (long)at)
            {
                throw new InvalidDataException($"the kept list does not walk at {at}: {next}");
            }

            chain.Add(new ReadOnlySpan<byte>(certificate, (int)n).ToArray());
            at = (nuint)next;
        }

        return chain;
    }

    /// <summary>Changes the live configuration of a started connection: what a caller that edits
    /// a configuration its connections read does (the C header forbids it; the engine must stay
    /// inside its memory all the same).</summary>
    /// <param name="edit">The change.</param>
    public void EditConfig(ConfigSetter edit) => edit(config);

    /// <summary>httpasm_tls13_send.</summary>
    /// <param name="data">Application data.</param>
    /// <returns>The octets taken, or -1.</returns>
    public long Send(ReadOnlySpan<byte> data)
    {
        fixed (byte* d = data)
        {
            return Native.Tls13Send(connection, d, (nuint)data.Length);
        }
    }

    /// <summary>httpasm_tls13_close.</summary>
    /// <returns>0, or -1.</returns>
    public int Close() => Native.Tls13Close(connection);

    /// <summary>httpasm_tls13_key_update.</summary>
    /// <param name="request">Whether the peer is asked to update too.</param>
    /// <returns>0, or -1.</returns>
    public int KeyUpdate(bool request) => Native.Tls13KeyUpdate(connection, request ? 1 : 0);

    /// <summary>httpasm_tls13_negotiated.</summary>
    /// <returns>The progress and what was chosen.</returns>
    public (int Progress, uint Suite, uint Group, uint Scheme) Negotiated()
    {
        uint suite, group, scheme;
        int progress = Native.Tls13Negotiated(connection, &suite, &group, &scheme);
        return (progress, suite, group, scheme);
    }

    /// <summary>Wipes the connection and frees everything the harness holds.</summary>
    public void Dispose()
    {
        // only a started connection has spans to wipe (an unstarted one is zeroed: nothing secret)
        if (started)
        {
            Native.Tls13Wipe(connection);
            started = false;
        }

        NativeMemory.Free(memory);
        NativeMemory.AlignedFree(connection);
        NativeMemory.Free(input);
        NativeMemory.Free(certificate);
        NativeMemory.Free(config);
        if (key != null)
        {
            new Span<byte>(key, sizeof(PrivateKey)).Clear();   // the key's octets are the secret
        }

        NativeMemory.Free(key);
        if (source.IsAllocated)
        {
            source.Free();
        }
    }
}
