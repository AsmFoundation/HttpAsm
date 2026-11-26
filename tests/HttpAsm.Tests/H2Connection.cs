using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>One HTTP/2 frame as read off the wire.</summary>
/// <param name="Type">Its type.</param>
/// <param name="Flags">Its flags.</param>
/// <param name="Stream">Its stream id (the reserved bit cleared).</param>
/// <param name="Payload">Its payload.</param>
internal sealed record H2Frame(int Type, int Flags, int Stream, byte[] Payload);

/// <summary>A response read on one stream: the status, the fields (decoded) and the body.</summary>
/// <param name="Status">:status.</param>
/// <param name="Fields">The regular fields, names as sent.</param>
/// <param name="Body">The DATA, concatenated.</param>
internal sealed record H2Response(int Status, IReadOnlyList<HpackField> Fields, byte[] Body);

/// <summary>
/// A raw HTTP/2 client for the frame-level tests: it writes exactly the frames a test asks for
/// (valid or not) and reads the server's frames one by one. Field blocks it sends are encoded by
/// HttpAsm's own HPACK encoder (through the C ABI), and every block it receives is decoded in
/// order, so both tables stay in step with the server's whatever a test skips.
/// </summary>
internal sealed class H2Connection : IDisposable
{
    /// <summary>Frame types (RFC 9113 6).</summary>
    public const int Data = 0, Headers = 1, Priority = 2, RstStream = 3, Settings = 4, PushPromise = 5, Ping = 6, GoAway = 7, WindowUpdate = 8, Continuation = 9;

    /// <summary>Flags.</summary>
    public const int EndStream = 0x1, Ack = 0x1, EndHeaders = 0x4, Padded = 0x8, PriorityFlag = 0x20;

    /// <summary>Error codes (RFC 9113 7).</summary>
    public const uint NoError = 0x0, ProtocolError = 0x1, InternalError = 0x2, FlowControlError = 0x3, StreamClosed = 0x5,
        FrameSizeError = 0x6, RefusedStream = 0x7, Cancel = 0x8, CompressionError = 0x9, EnhanceYourCalm = 0xb;

    /// <summary>The client preface (RFC 9113 3.4).</summary>
    public static readonly byte[] Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    /// <summary>The socket.</summary>
    private readonly Socket socket;

    /// <summary>Encodes this side's field blocks.</summary>
    private readonly HpackTable encoder = new(4096);

    /// <summary>Decodes the server's.</summary>
    private readonly HpackTable decoder = new(4096);

    /// <summary>A field block being received across CONTINUATIONs.</summary>
    private readonly List<byte> block = [];

    /// <summary>Received octets not consumed yet: buffer[start..end).</summary>
    private byte[] buffer = new byte[1 << 16];

    /// <summary>The first unconsumed octet.</summary>
    private int start;

    /// <summary>One past the last received octet.</summary>
    private int end;

    /// <summary>Every stream id this side sent HEADERS on (valid or not): the only streams the
    /// server may send stream frames on, since it opens none itself.</summary>
    private readonly HashSet<int> opened = [];

    /// <summary>Streams the server ended (END_STREAM): no HEADERS or DATA may follow on them.</summary>
    private readonly HashSet<int> serverEnded = [];

    /// <summary>Streams the server reset: RST_STREAM was its last frame on them.</summary>
    private readonly HashSet<int> serverReset = [];

    /// <summary>The stream of a field block the server has not ended yet (END_HEADERS), or 0.</summary>
    private int serverBlock;

    /// <summary>The largest SETTINGS_MAX_FRAME_SIZE this side announced (16384 by default): no
    /// frame of the server's may be larger.</summary>
    private int maxFrame = 16384;

    /// <summary>The Last-Stream-ID of the server's most recent GOAWAY, or null before one.</summary>
    public uint? LastGoAwayStream { get; private set; }

    /// <summary>How many GOAWAY frames the server sent.</summary>
    public int GoAwayCount { get; private set; }

    /// <summary>
    /// Whether <see cref="ReadFrame"/> answers the server's PINGs with an ACK at once, as a
    /// compliant client must (RFC 9113 6.7). True by default; a test that holds the answer back
    /// (to send something before it, say) turns it off and answers with <see cref="SendFrame"/>.
    /// </summary>
    public bool AnswerPings { get; set; } = true;

    /// <summary>The PINGs (without ACK) the server sent so far.</summary>
    public int PingsReceived { get; private set; }

    /// <summary>The size of the dynamic table that decodes the server's blocks: the server's
    /// encoder's table, as its blocks so far describe it (RFC 7541 4.1).</summary>
    public uint DecoderSize => decoder.Size;

    /// <summary>Connects; with <paramref name="handshake"/>, sends the preface and SETTINGS and
    /// completes the exchange of SETTINGS and their ACKs.</summary>
    /// <param name="port">The server's port.</param>
    /// <param name="handshake">Whether to do the handshake now.</param>
    /// <param name="settings">This side's SETTINGS.</param>
    /// <exception cref="IOException">The server closed the connection during the handshake.</exception>
    /// <exception cref="SocketException">The connection was refused, or a read timed out.</exception>
    public H2Connection(int port, bool handshake = true, params (int Id, uint Value)[] settings)
        : this(port, 0, handshake, settings)
    {
    }

    /// <summary>
    /// Connects with a receive buffer of a given size, then does the handshake as the other
    /// constructor does. A small buffer keeps a server's answers on the server's side while a
    /// test reads slowly: the kernel cannot take a whole large answer at once.
    /// </summary>
    /// <param name="port">The server's port.</param>
    /// <param name="receiveBuffer">The socket's receive buffer, set before connecting.</param>
    /// <param name="settings">This side's SETTINGS.</param>
    /// <exception cref="IOException">The server closed the connection during the handshake.</exception>
    /// <exception cref="SocketException">The connection was refused, or a read timed out.</exception>
    public H2Connection(int port, int receiveBuffer, params (int Id, uint Value)[] settings)
        : this(port, receiveBuffer, true, settings)
    {
    }

    /// <summary>The constructors' common part.</summary>
    /// <param name="port">The server's port.</param>
    /// <param name="receiveBuffer">The receive buffer (0: the kernel's default).</param>
    /// <param name="handshake">Whether to do the handshake now.</param>
    /// <param name="settings">This side's SETTINGS.</param>
    /// <exception cref="IOException">The server closed the connection during the handshake.</exception>
    /// <exception cref="SocketException">The connection was refused, or a read timed out.</exception>
    private H2Connection(int port, int receiveBuffer, bool handshake, (int Id, uint Value)[] settings)
    {
        socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true, ReceiveTimeout = 5000 };
        if (receiveBuffer > 0)
        {
            socket.ReceiveBufferSize = receiveBuffer;   // before the connect: the window it offers
        }

        socket.Connect(IPAddress.Loopback, port);
        if (!handshake)
        {
            return;
        }

        socket.Send(Preface);
        SendSettings(settings);
        bool theirs = false, ours = false;
        while (!theirs || !ours)
        {
            H2Frame frame = ReadFrame() ?? throw new IOException("The server closed during the handshake.");
            if (frame.Type == Settings && (frame.Flags & Ack) == 0)
            {
                ServerSettings = ParseSettings(frame.Payload);
                SendFrame(Settings, Ack, 0, []);
                theirs = true;
            }
            else if (frame.Type == Settings)
            {
                ours = true;
            }
        }
    }

    /// <summary>The server's SETTINGS, from the handshake.</summary>
    public IReadOnlyDictionary<int, uint> ServerSettings { get; private set; } = new Dictionary<int, uint>();

    /// <summary>Writes octets as they are.</summary>
    /// <param name="octets">The octets.</param>
    public void SendRaw(ReadOnlySpan<byte> octets) => socket.Send(octets);

    /// <summary>Writes one frame.</summary>
    /// <param name="type">Its type.</param>
    /// <param name="flags">Its flags.</param>
    /// <param name="stream">Its stream id (the reserved bit may be set by the caller).</param>
    /// <param name="payload">Its payload.</param>
    public void SendFrame(int type, int flags, int stream, ReadOnlySpan<byte> payload)
    {
        if (type == Headers)
        {
            opened.Add(stream & 0x7FFFFFFF);       // the server may answer (or reset) it from now on
        }

        byte[] frame = new byte[9 + payload.Length];
        frame[0] = (byte)(payload.Length >> 16);
        frame[1] = (byte)(payload.Length >> 8);
        frame[2] = (byte)payload.Length;
        frame[3] = (byte)type;
        frame[4] = (byte)flags;
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(5), stream);
        payload.CopyTo(frame.AsSpan(9));
        socket.Send(frame);
    }

    /// <summary>
    /// Writes several frames in one send, so they reach the server in one segment and it handles
    /// them in one turn of its loop: for a test that needs two streams opened at the same
    /// instant (separate sends may be read a turn apart, and the server's clock with them).
    /// </summary>
    /// <param name="frames">The frames, in order: type, flags, stream id, payload.</param>
    public void SendFrames(params (int Type, int Flags, int Stream, byte[] Payload)[] frames)
    {
        var octets = new List<byte>();
        foreach ((int type, int flags, int stream, byte[] payload) in frames)
        {
            if (type == Headers)
            {
                opened.Add(stream & 0x7FFFFFFF);   // the server may answer (or reset) it from now on
            }

            byte[] header = new byte[9];
            header[0] = (byte)(payload.Length >> 16);
            header[1] = (byte)(payload.Length >> 8);
            header[2] = (byte)payload.Length;
            header[3] = (byte)type;
            header[4] = (byte)flags;
            BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(5), stream);
            octets.AddRange(header);
            octets.AddRange(payload);
        }

        socket.Send(octets.ToArray());
    }

    /// <summary>Writes a SETTINGS frame.</summary>
    /// <param name="settings">Its parameters, in order.</param>
    public void SendSettings(params (int Id, uint Value)[] settings)
    {
        byte[] payload = new byte[settings.Length * 6];
        for (int i = 0; i < settings.Length; i++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(i * 6), (ushort)settings[i].Id);
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(i * 6 + 2), settings[i].Value);
            if (settings[i].Id == 5 && settings[i].Value <= 16777215)
            {
                // SETTINGS_MAX_FRAME_SIZE: the largest ever announced bounds the server's frames
                // (it may not have applied a later, smaller one yet; none can go below 16384).
                maxFrame = Math.Max(maxFrame, (int)settings[i].Value);
            }
        }

        SendFrame(Settings, 0, 0, payload);
    }

    /// <summary>A frame whose payload is one 32-bit value (RST_STREAM, WINDOW_UPDATE).</summary>
    /// <param name="type">The type.</param>
    /// <param name="stream">The stream.</param>
    /// <param name="value">The value.</param>
    public void SendU32(int type, int stream, uint value)
    {
        byte[] payload = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(payload, value);
        SendFrame(type, 0, stream, payload);
    }

    /// <summary>A field block of a request: :method, :scheme http, :path, :authority, then the
    /// extra fields; encoded by this connection's encoder (its table changes with it).</summary>
    /// <remarks>
    /// Footgun: encoding inserts fields into the encoder's dynamic table, and later blocks refer
    /// to those entries. Send each block, whole and in order, before encoding the next; a block
    /// that is built and then dropped leaves the server's table behind, and every later request
    /// fails to decode (COMPRESSION_ERROR). Build a block only at the moment it is sent.
    /// </remarks>
    /// <param name="method">:method.</param>
    /// <param name="path">:path.</param>
    /// <param name="extra">More fields, in order (pseudo-fields too, for malformed tests).</param>
    /// <returns>The block.</returns>
    public byte[] RequestBlock(string method = "GET", string path = "/", params (string Name, string Value)[] extra) =>
        Block([(":method", method), (":scheme", "http"), (":path", path), (":authority", "127.0.0.1"), .. extra]);

    /// <summary>Any field block, in order, through this connection's encoder.</summary>
    /// <remarks>Changes the encoder's dynamic table: the footgun of <see cref="RequestBlock"/> applies.</remarks>
    /// <param name="fields">The fields.</param>
    /// <returns>The block.</returns>
    public byte[] Block(params (string Name, string Value)[] fields) => encoder.Encode(fields.Select(f => new HpackField(f.Name, f.Value)).ToList());

    /// <summary>Sends a request's HEADERS (END_HEADERS; END_STREAM unless a body follows).</summary>
    /// <param name="stream">The stream.</param>
    /// <param name="endStream">Whether the request ends with it.</param>
    /// <param name="method">:method.</param>
    /// <param name="path">:path.</param>
    /// <param name="extra">More fields.</param>
    public void SendRequest(int stream, bool endStream = true, string method = "GET", string path = "/", params (string Name, string Value)[] extra) =>
        SendFrame(Headers, EndHeaders | (endStream ? EndStream : 0), stream, RequestBlock(method, path, extra));

    /// <summary>Reads one frame; HEADERS and CONTINUATION blocks are decoded on the way.</summary>
    /// <returns>The frame, or null when the server closed (or reset) the connection.</returns>
    /// <exception cref="SocketException">Nothing arrived within the timeout.</exception>
    public H2Frame? ReadFrame()
    {
        if (!Fill(9))
        {
            return null;
        }

        int length = buffer[start] << 16 | buffer[start + 1] << 8 | buffer[start + 2];
        if (!Fill(9 + length))
        {
            return null;
        }

        uint word = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(start + 5));
        var frame = new H2Frame(buffer[start + 3], buffer[start + 4], (int)(word & 0x7FFFFFFF), buffer.AsSpan(start + 9, length).ToArray());
        start += 9 + length;
        CheckSendingRules(frame, reservedBit: word >> 31 != 0);
        if (frame.Type == Ping && (frame.Flags & Ack) == 0)
        {
            PingsReceived++;
            if (AnswerPings)
            {
                // What a compliant client does (RFC 9113 6.7: a PING without ACK MUST be
                // answered with one carrying the same payload). The server's graceful stop
                // waits for this answer before its final GOAWAY.
                SendFrame(Ping, Ack, 0, frame.Payload);
            }
        }
        if (frame.Type is Headers or Continuation)
        {
            block.AddRange(frame.Type == Headers ? Fragment(frame) : frame.Payload);
            if ((frame.Flags & EndHeaders) != 0)
            {
                HpackDecoded decoded = decoder.Decode([.. block]);
                block.Clear();
                if (decoded.Result == 0)
                {
                    Decoded[frame.Stream] = decoded.Fields;
                }
            }
        }

        return frame;
    }

    /// <summary>
    /// The rules for what an endpoint sends, checked on every frame the server sends, so every
    /// HTTP/2 test enforces them whatever it is about; a frame that breaks one fails the test
    /// reading it. Only rules a client can judge without races are checked: what the server knew
    /// when it sent a frame is certain only for its own END_STREAM and RST_STREAM, not for frames
    /// of this side's still in flight, so "closed by both sides" is left to targeted tests.
    /// </summary>
    /// <remarks>
    /// The rules: the reserved bit unset (RFC9113-4.1-4.8.1#1) and no flag a type does not define
    /// (RFC9113-4.1-4.6.2#2); this server pads nothing, so its padding octets are trivially zero
    /// (RFC9113-6.1-5.6#1, 6.2-4.12#1); SETTINGS, PING and GOAWAY on stream 0, DATA, HEADERS,
    /// PRIORITY, RST_STREAM and CONTINUATION never (6.1-9#1, 6.2-8#1, 6.4-6#1, 6.10-7#1); no
    /// PUSH_PROMISE and no stream this side did not open (the server opens none, so it never
    /// exceeds this side's stream limit, 5.1.2-3#1, and never resets an idle stream, 6.4-7#1);
    /// nothing after its own RST_STREAM on a stream (5.4.2: the last frame; at most one,
    /// 5.4.2-4#1); no HEADERS or DATA after its END_STREAM (half-closed (local), 5.1); field
    /// blocks contiguous (4.3-10, 6.2-6.6.2#1); frames within this side's SETTINGS_MAX_FRAME_SIZE
    /// (4.2); an empty SETTINGS ACK (6.5-6.2#1); GOAWAY's last stream never growing (6.8-17#2).
    /// </remarks>
    /// <param name="frame">The frame, its stream id without the reserved bit.</param>
    /// <param name="reservedBit">Whether the reserved bit was set on the wire.</param>
    /// <exception cref="InvalidDataException">The frame breaks a rule; the message names it.</exception>
    private void CheckSendingRules(H2Frame frame, bool reservedBit)
    {
        void Broken(string rule, string what) =>
            throw new InvalidDataException($"The server broke {rule}: {what} (type {frame.Type}, flags 0x{frame.Flags:x2}, stream {frame.Stream}).");

        if (reservedBit)
        {
            Broken("RFC9113-4.1-4.8.1#1", "the reserved bit is set");
        }

        if (frame.Payload.Length > maxFrame)
        {
            Broken("RFC 9113 4.2 (a frame within the receiver's SETTINGS_MAX_FRAME_SIZE)", $"{frame.Payload.Length} octets past {maxFrame}");
        }

        int defined = frame.Type switch
        {
            Data => EndStream | Padded,
            Headers => EndStream | EndHeaders | Padded | PriorityFlag,
            Settings or Ping => Ack,
            Continuation => EndHeaders,
            Priority or RstStream or GoAway or WindowUpdate => 0,
            PushPromise => Broken2("HttpAsm's design (no server push before M4)", "a PUSH_PROMISE"),
            _ => Broken2("RFC 9113 5.5 (no extension frame this side did not negotiate)", $"frame type {frame.Type}"),
        };
        if ((frame.Flags & ~defined) != 0)
        {
            Broken("RFC9113-4.1-4.6.2#2", "a flag its type does not define is set");
        }

        if ((frame.Flags & Padded) != 0 && frame.Type is Data or Headers)
        {
            Broken("HttpAsm's design", "padding (h2.asm writes none)");
        }

        bool connectionFrame = frame.Type is Settings or Ping or GoAway;
        if (connectionFrame != (frame.Stream == 0) && frame.Type != WindowUpdate)
        {
            Broken("RFC 9113 6 (each frame type's stream rule)", connectionFrame ? "a connection frame on a stream" : "a stream frame on stream 0");
        }

        if (frame.Stream != 0)
        {
            if (!opened.Contains(frame.Stream))
            {
                Broken("RFC9113-6.4-7#1", "a frame on a stream this side never opened");
            }

            if (serverReset.Contains(frame.Stream))
            {
                Broken("RFC9113-5.4.2-4#1", "a frame after its own RST_STREAM on the stream");
            }

            if (frame.Type is Data or Headers && serverEnded.Contains(frame.Stream))
            {
                Broken("RFC 9113 5.1 (half-closed (local) sends no HEADERS or DATA)", "HEADERS or DATA after its END_STREAM on the stream");
            }
        }

        if (serverBlock != 0 && (frame.Type != Continuation || frame.Stream != serverBlock))
        {
            Broken("RFC9113-4.3-10", $"a frame inside its field block on stream {serverBlock}");
        }

        if (serverBlock == 0 && frame.Type == Continuation)
        {
            Broken("RFC9113-6.10-8#1", "a CONTINUATION with no field block open");
        }

        switch (frame.Type)
        {
            case Headers or Continuation:
                serverBlock = (frame.Flags & EndHeaders) != 0 ? 0 : frame.Stream;
                if (frame.Type == Headers && (frame.Flags & EndStream) != 0)
                {
                    serverEnded.Add(frame.Stream);
                }

                break;
            case Data when (frame.Flags & EndStream) != 0:
                serverEnded.Add(frame.Stream);
                break;
            case RstStream:
                serverReset.Add(frame.Stream);
                break;
            case Settings when (frame.Flags & Ack) != 0 && frame.Payload.Length != 0:
                Broken("RFC9113-6.5-6.2#1", "a SETTINGS ACK with a payload");
                break;
            case GoAway:
                uint last = BinaryPrimitives.ReadUInt32BigEndian(frame.Payload) & 0x7FFFFFFF;
                if (last > LastGoAwayStream)
                {
                    Broken("RFC9113-6.8-17#2", $"a GOAWAY's last stream {last} past an earlier GOAWAY's {LastGoAwayStream}");
                }

                LastGoAwayStream = last;
                GoAwayCount++;
                break;
        }

        // A switch arm needs a value: the throwing helper typed as one.
        int Broken2(string rule, string what)
        {
            Broken(rule, what);
            return 0;
        }
    }

    /// <summary>
    /// Reads until a GOAWAY and returns it, leaving the connection to the caller (unlike
    /// <see cref="ExpectGoAway"/>, which reads to the close): for a graceful stop's two GOAWAYs.
    /// </summary>
    /// <returns>Its last stream id, error code, and payload length (8 without debug data).</returns>
    /// <exception cref="IOException">The connection closed first.</exception>
    public (uint LastStream, uint Code, int Length) ReadGoAway()
    {
        H2Frame frame = Expect(GoAway);
        return (BinaryPrimitives.ReadUInt32BigEndian(frame.Payload) & 0x7FFFFFFF, BinaryPrimitives.ReadUInt32BigEndian(frame.Payload.AsSpan(4)), frame.Payload.Length);
    }

    /// <summary>The last field block decoded on each stream.</summary>
    public Dictionary<int, IReadOnlyList<HpackField>> Decoded { get; } = [];

    /// <summary>Reads frames until one of a type (and stream) comes; others are skipped.</summary>
    /// <param name="type">The type.</param>
    /// <param name="stream">The stream, or null for any.</param>
    /// <returns>The frame.</returns>
    /// <exception cref="IOException">The connection closed first, or a GOAWAY came (when not asked for).</exception>
    public H2Frame Expect(int type, int? stream = null)
    {
        while (true)
        {
            H2Frame frame = ReadFrame() ?? throw new IOException($"The server closed before a frame of type {type}.");
            if (frame.Type == type && (stream is null || frame.Stream == stream))
            {
                return frame;
            }

            if (frame.Type == GoAway && type != GoAway)
            {
                throw new IOException($"GOAWAY {BinaryPrimitives.ReadUInt32BigEndian(frame.Payload.AsSpan(4))} while waiting for a frame of type {type}.");
            }
        }
    }

    /// <summary>
    /// A connection error: reads until GOAWAY and returns its error code; then the connection
    /// must close (RFC9113-5.4.1-2#2), with no second GOAWAY after an error's (one error is
    /// reported once). A bare close (no GOAWAY) returns null.
    /// </summary>
    /// <returns>The error code, or null.</returns>
    /// <exception cref="IOException">The GOAWAY came but the connection stayed open.</exception>
    /// <exception cref="InvalidDataException">A second GOAWAY followed an error's, or a frame broke a sending rule.</exception>
    public uint? ExpectGoAway()
    {
        while (ReadFrame() is H2Frame frame)
        {
            if (frame.Type == GoAway)
            {
                uint code = BinaryPrimitives.ReadUInt32BigEndian(frame.Payload.AsSpan(4));
                while (ReadFrame() is H2Frame after)
                {
                    // A connection error is reported once: no second GOAWAY (another error, or
                    // the same again) follows it before the close (RFC9113-5.4-4#2, 5.4-5#1).
                    if (after.Type == GoAway && code != NoError)
                    {
                        throw new InvalidDataException($"A second GOAWAY ({BinaryPrimitives.ReadUInt32BigEndian(after.Payload.AsSpan(4))}) after the connection error {code}.");
                    }
                }

                return code;
            }
        }

        return null;
    }

    /// <summary>A stream error: reads until RST_STREAM on the stream and returns its error code.</summary>
    /// <param name="stream">The stream.</param>
    /// <returns>The error code.</returns>
    /// <exception cref="IOException">The connection closed, or a GOAWAY came, first.</exception>
    public uint ExpectReset(int stream) => BinaryPrimitives.ReadUInt32BigEndian(Expect(RstStream, stream).Payload);

    /// <summary>Reads a stream's response: HEADERS, then DATA until END_STREAM.</summary>
    /// <param name="stream">The stream.</param>
    /// <returns>The response.</returns>
    /// <exception cref="IOException">The connection closed, or the stream was reset, first.</exception>
    public H2Response ReadResponse(int stream)
    {
        var body = new List<byte>();
        int status = 0;
        IReadOnlyList<HpackField> fields = [];
        while (true)
        {
            H2Frame frame = ReadFrame() ?? throw new IOException($"The server closed before stream {stream}'s response ended.");
            if (frame.Stream != stream)
            {
                continue;
            }

            if (frame.Type == RstStream)
            {
                throw new IOException($"Stream {stream} reset: {BinaryPrimitives.ReadUInt32BigEndian(frame.Payload)}.");
            }

            if (frame.Type == Headers && Decoded.TryGetValue(stream, out var decoded))
            {
                int code = int.Parse(decoded.First(f => f.Name == ":status").Value, System.Globalization.CultureInfo.InvariantCulture);
                if (code >= 200)
                {
                    status = code;
                    fields = decoded.Where(f => !f.Name.StartsWith(':')).ToList();
                }
            }
            else if (frame.Type == Data)
            {
                body.AddRange(frame.Payload);
            }

            if (frame.Type is Headers or Data && (frame.Flags & EndStream) != 0 && status != 0)
            {
                return new H2Response(status, fields, [.. body]);
            }
        }
    }

    /// <summary>Whether nothing arrives for a while (no error, no close).</summary>
    /// <param name="ms">How long to watch.</param>
    /// <returns>True when silent.</returns>
    public bool QuietFor(int ms) => start == end && !socket.Poll(ms * 1000, SelectMode.SelectRead);

    /// <summary>
    /// Every frame that arrives until the server stays silent for a while, or closes: for tests
    /// that must show what a server did not send on some stream, while frames it may send on
    /// others (a connection WINDOW_UPDATE, say) do not count against them.
    /// </summary>
    /// <param name="ms">How long a silence ends the watch.</param>
    /// <returns>The frames, in order (each checked like every frame read).</returns>
    /// <exception cref="InvalidDataException">A frame broke a sending rule.</exception>
    public List<H2Frame> FramesWithin(int ms)
    {
        var frames = new List<H2Frame>();
        while (start != end || socket.Poll(ms * 1000, SelectMode.SelectRead))
        {
            if (ReadFrame() is not H2Frame frame)
            {
                break;                                  // closed
            }

            frames.Add(frame);
        }

        return frames;
    }

    /// <summary>
    /// Resets the TCP connection (SO_LINGER 0, then the close): the server sees RST, a peer gone
    /// for good, with no GOAWAY first. The HPACK tables stay until <see cref="Dispose"/>.
    /// </summary>
    public void Abort()
    {
        socket.LingerState = new LingerOption(true, 0);
        socket.Close();
    }

    /// <summary>Closes the socket and frees the HPACK tables.</summary>
    public void Dispose()
    {
        socket.Dispose();
        encoder.Dispose();
        decoder.Dispose();
    }

    /// <summary>A HEADERS frame's field block fragment: without padding and priority.</summary>
    /// <param name="frame">The frame.</param>
    /// <returns>The fragment.</returns>
    private static byte[] Fragment(H2Frame frame)
    {
        int from = 0, to = frame.Payload.Length;
        if ((frame.Flags & Padded) != 0)
        {
            to -= frame.Payload[0];
            from = 1;
        }

        if ((frame.Flags & PriorityFlag) != 0)
        {
            from += 5;
        }

        return frame.Payload[from..to];
    }

    /// <summary>A SETTINGS payload's parameters.</summary>
    /// <param name="payload">The payload.</param>
    /// <returns>Identifier to value (the last value of a repeated identifier).</returns>
    private static Dictionary<int, uint> ParseSettings(byte[] payload)
    {
        var settings = new Dictionary<int, uint>();
        for (int i = 0; i + 6 <= payload.Length; i += 6)
        {
            settings[BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(i))] = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(i + 2));
        }

        return settings;
    }

    /// <summary>Receives until at least <paramref name="count"/> unconsumed octets are buffered.</summary>
    /// <param name="count">The octets needed.</param>
    /// <returns>False when the server closed (or reset) the connection first.</returns>
    /// <exception cref="SocketException">The read timed out.</exception>
    private bool Fill(int count)
    {
        while (end - start < count)
        {
            if (buffer.Length - start < count)
            {
                Array.Resize(ref buffer, Math.Max(buffer.Length * 2, count + 9));
            }

            if (end == buffer.Length || buffer.Length - end < count - (end - start))
            {
                Buffer.BlockCopy(buffer, start, buffer, 0, end - start);
                end -= start;
                start = 0;
            }

            int n;
            try
            {
                n = socket.Receive(buffer, end, buffer.Length - end, SocketFlags.None);
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
            {
                return false;
            }

            if (n == 0)
            {
                return false;
            }

            end += n;
        }

        return true;
    }

    /// <summary>The octets of a string as Latin-1.</summary>
    /// <param name="text">The text.</param>
    /// <returns>The octets.</returns>
    public static byte[] Octets(string text) => Encoding.Latin1.GetBytes(text);
}
