using System.Buffers.Binary;
using System.Text;
using static HttpAsm.Tests.H2Connection;

namespace HttpAsm.Tests;

/// <summary>
/// HTTP/2's rules frame by frame (RFC 9113), each test naming the rows it proves. h2spec runs the
/// same ground as a black box (Http2Tests.PassesH2spec); these tests tie each behavior to its
/// requirement, and add what h2spec does not check (the server's own preface, cookie joining,
/// lower-cased response names, early answers).
/// </summary>
public sealed class Http2FrameTests
{
    /// <summary>How many requests reached a handler of any server these tests started: a test
    /// that must prove a request never reached one compares it before and after (they run one
    /// at a time within this class, so no other test of it moves the count meanwhile).</summary>
    private static int handled;

    /// <summary>
    /// A server whose answers the tests can steer by path: /slow answers a second later (its
    /// stream stays half-closed (remote) meanwhile), /echo echoes the body, /cookie answers the
    /// cookie field it saw, /mixed answers with a mixed-case field name, "*" (OPTIONS for the
    /// server as a whole) answers "asterisk" and the method, /reset answers 205 (first with a
    /// body, which is refused, then empty), anything else "ok".
    /// </summary>
    /// <param name="idleMs">The idle timeout (0: the library's default).</param>
    /// <param name="limits">The head limits (zeros: the library's defaults).</param>
    /// <returns>The server.</returns>
    private static TestServer NewServer(uint idleMs = 0, H1Limits limits = default)
    {
        var ct = TestContext.Current.CancellationToken;
        return new TestServer(x =>
        {
            Interlocked.Increment(ref handled);
            switch (x.Target)
            {
                case "*":
                    x.Respond(200, "asterisk " + x.Method);
                    break;
                case "/reset":
                    if (x.Respond(205, "content") != 0)                 // refused: 205 carries none
                    {
                        x.Respond(205);
                    }

                    break;
                case "/slow":
                    x.Defer();
                    _ = Task.Run(async () =>
                    {
                        await Task.Delay(1000, ct);
                        x.Respond(200, "late");
                    }, ct);
                    break;
                case "/echo":
                    x.Respond(200, x.Body);
                    break;
                case "/cookie":
                    x.Respond(200, (x.Field("cookie") ?? "-") + "|" + x.Fields.Count(f => f.Name == "cookie").ToString(System.Globalization.CultureInfo.InvariantCulture));
                    break;
                case "/mixed":
                    x.Respond(200, "ok", ("X-Mixed-Case", "1"));
                    break;
                default:
                    x.Respond(200, "ok");
                    break;
            }
        }, idleMs: idleMs, maxBody: 1 << 20, limits: limits);
    }

    /// <summary>
    /// The server's preface is a SETTINGS frame, its first frame, never enabling push; it
    /// acknowledges the client's SETTINGS (an empty one here) at once; and it answers requests
    /// on the connection. What it advertises stays within the rules: a stream limit above zero
    /// (zero is for short refusals only), a frame size (if any) between 2^14 and 2^24 - 1, and
    /// receive windows of its own choosing (a stream's in SETTINGS, the connection's raised by a
    /// WINDOW_UPDATE right after it).
    /// </summary>
    [Fact]
    [Requirement("RFC9113-3.3-3", "RFC9113-3.4-6", "RFC9113-3.4-7", "RFC9113-3.4-4#1", "RFC9113-6.5-3#1", "RFC9113-6.5.3-1",
        "RFC9113-6.5.3-2#3", "RFC9113-6.5.2-2.4.3#1", "RFC9113-6.5.2-2.4.3#3", "RFC9113-5.1.1-1#2", "RFC9113-3.4-4#2",
        "RFC9113-6.5.2-2.6.2#2", "RFC9113-6.5.2-2.10.2#1", "RFC9113-5.2.1-2.3#1", "RFC9113-6.5.2-2.4.3#2")]
    public void OpensWithSettings()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port, handshake: false);

        c.SendRaw(Preface);
        c.SendSettings();                                           // empty: allowed (3.4-4#2)
        H2Frame first = c.ReadFrame()!;
        Assert.Equal(Settings, first.Type);
        Assert.Equal(0, first.Flags & Ack);
        Assert.Equal(0, first.Stream);
        var advertised = new Dictionary<int, uint>();
        for (int i = 0; i + 6 <= first.Payload.Length; i += 6)
        {
            advertised[BinaryPrimitives.ReadUInt16BigEndian(first.Payload.AsSpan(i))] = BinaryPrimitives.ReadUInt32BigEndian(first.Payload.AsSpan(i + 2));
        }

        if (advertised.TryGetValue(2, out uint push))               // ENABLE_PUSH: never 1 from a server
        {
            Assert.Equal(0u, push);
        }

        Assert.True(advertised.GetValueOrDefault(3, uint.MaxValue) > 0, "MAX_CONCURRENT_STREAMS must not refuse every stream");
        if (advertised.TryGetValue(5, out uint frameSize))          // MAX_FRAME_SIZE: 2^14..2^24 - 1
        {
            Assert.InRange(frameSize, 16384u, 16777215u);
        }

        Assert.Equal(262144u, advertised[4]);                       // INITIAL_WINDOW_SIZE, its choice
        H2Frame raise = c.Expect(WindowUpdate, 0);                  // and the connection's window
        Assert.Equal(16777216u - 65535u, BinaryPrimitives.ReadUInt32BigEndian(raise.Payload));

        H2Frame ack = c.Expect(Settings);
        Assert.Equal(Ack, ack.Flags & Ack);
        Assert.Empty(ack.Payload);
        c.SendFrame(Settings, Ack, 0, []);
        c.SendRequest(1);
        Assert.Equal(200, c.ReadResponse(1).Status);
    }

    /// <summary>
    /// Unknown frame types are discarded, unknown flags and the reserved bit are ignored, and
    /// unknown error codes trigger nothing special: the connection works on.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-4.1-4.4.1", "RFC9113-4.1-4.6.2#1", "RFC9113-4.1-4.8.1#2", "RFC9113-5.5-4#2", "RFC9113-7-5#1")]
    public void IgnoresWhatItDoesNotKnow()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendFrame(0xBB, 0xFF, 0, [1, 2, 3]);                     // an extension frame
        c.SendFrame(Ping, 0xF0, 0, [1, 2, 3, 4, 5, 6, 7, 8]);      // unknown flags on a PING
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, c.Expect(Ping).Payload);
        c.SendFrame(Headers, EndHeaders | EndStream, unchecked((int)0x80000001), c.RequestBlock());   // the reserved bit set
        Assert.Equal(200, c.ReadResponse(1).Status);
        c.SendRequest(3, endStream: false, "POST", "/echo");
        c.SendU32(RstStream, 3, 0xFFFF);                           // an unknown error code
        c.SendRequest(5);
        Assert.Equal(200, c.ReadResponse(5).Status);
    }

    /// <summary>A DATA frame of 2^14 octets (the size every endpoint must take) is accepted; one
    /// octet more is a FRAME_SIZE_ERROR, a connection error for HEADERS (it would alter the
    /// connection's state) and here for DATA too.</summary>
    /// <param name="type">The oversized frame's type.</param>
    [Theory]
    [InlineData(Data)]
    [InlineData(Headers)]
    [Requirement("RFC9113-4.2-2", "RFC9113-4.2-4#1", "RFC9113-4.2-4#2", "RFC9113-5.4.1-2#1", "RFC9113-5.4.1-2#2")]
    public void BoundsFrameSizes(int type)
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, endStream: false, "POST", "/echo");
        c.SendFrame(Data, EndStream, 1, new byte[16384]);
        Assert.Equal(16384, c.ReadResponse(1).Body.Length);
        c.SendRequest(3, endStream: false, "POST", "/echo");
        c.SendFrame(type, EndHeaders, 3, new byte[16385]);

        Assert.Equal(FrameSizeError, c.ExpectGoAway());
    }

    /// <summary>
    /// A field block is one contiguous run of HEADERS and CONTINUATIONs of one stream: another
    /// frame in between, or a block on another stream, is a connection error PROTOCOL_ERROR; a
    /// CONTINUATION never follows anything else (or a block already ended, or stream 0).
    /// </summary>
    /// <param name="interloper">What comes after the HEADERS without END_HEADERS ("none": a bare CONTINUATION).</param>
    [Theory]
    [InlineData("priority")]
    [InlineData("headers-on-another-stream")]
    [InlineData("data")]
    [InlineData("extension")]
    [InlineData("continuation-on-stream-0")]
    [InlineData("none")]
    [Requirement("RFC9113-4.3-10", "RFC9113-6.2-6.6.2#1", "RFC9113-6.2-6.6.2#2", "RFC9113-6.10-5.2.2#1", "RFC9113-6.10-5.2.2#2",
        "RFC9113-6.10-7#1", "RFC9113-6.10-7#2", "RFC9113-6.10-8#1", "RFC9113-6.10-8#2", "RFC9113-8.1-6", "RFC9113-5.5-4#3")]
    public void KeepsFieldBlocksWhole(string interloper)
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        if (interloper == "none")
        {
            c.SendRequest(1);
            Assert.Equal(200, c.ReadResponse(1).Status);
            // Encoded only now: a block built before SendRequest and never sent would leave the
            // server's HPACK table behind the encoder's, and the request above would not decode.
            c.SendFrame(Continuation, EndHeaders, 1, c.RequestBlock());   // after a block that ended
        }
        else
        {
            // The block is cut off after its first 3 octets, so the connection fails before the
            // server ever decodes it: the encoder running ahead of the server costs nothing here.
            byte[] block = c.RequestBlock();
            c.SendFrame(Headers, EndStream, 1, block[..3]);        // no END_HEADERS
            switch (interloper)
            {
                case "priority": c.SendFrame(Priority, 0, 1, [0, 0, 0, 0, 16]); break;
                case "headers-on-another-stream": c.SendFrame(Headers, EndHeaders, 3, block); break;
                case "data": c.SendFrame(Data, 0, 1, [1]); break;
                case "extension": c.SendFrame(0xBB, 0, 1, [1]); break;
                case "continuation-on-stream-0": c.SendFrame(Continuation, EndHeaders, 0, block[3..]); break;
            }
        }

        Assert.Equal(ProtocolError, c.ExpectGoAway());
    }

    /// <summary>A block split over several CONTINUATIONs is decoded as one.</summary>
    [Fact]
    [Requirement("RFC9113-6.10-5.2.2#1")]
    public void JoinsContinuations()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);
        byte[] block = c.RequestBlock(extra: ("x-long", new string('v', 100)));

        c.SendFrame(Headers, EndStream, 1, block[..5]);
        c.SendFrame(Continuation, 0, 1, block[5..40]);
        c.SendFrame(Continuation, EndHeaders, 1, block[40..]);

        Assert.Equal(200, c.ReadResponse(1).Status);
    }

    /// <summary>A field block that does not decode is a connection error COMPRESSION_ERROR.</summary>
    [Fact]
    [Requirement("RFC9113-4.3-11", "RFC9113-4.3-12")]
    public void RefusesBlocksThatDoNotDecode()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendFrame(Headers, EndHeaders | EndStream, 1, [0x80]);  // indexed field 0

        Assert.Equal(CompressionError, c.ExpectGoAway());
    }

    /// <summary>
    /// Frames on idle streams: anything but HEADERS and PRIORITY is a connection error
    /// PROTOCOL_ERROR; PRIORITY does not open the stream (a lower id may still be opened).
    /// </summary>
    /// <param name="type">The frame sent on idle stream 1.</param>
    [Theory]
    [InlineData(Data)]
    [InlineData(RstStream)]
    [InlineData(WindowUpdate)]
    [InlineData(Continuation)]
    [Requirement("RFC9113-5.1-7.2.4#1", "RFC9113-6.4-7#2", "RFC9113-6.1-10", "RFC9113-5.1-8")]
    public void RefusesFramesOnIdleStreams(int type)
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendFrame(Priority, 0, 5, [0, 0, 0, 0, 16]);            // PRIORITY on idle 5: fine
        c.SendRequest(3);                                          // and 3 still opens
        Assert.Equal(200, c.ReadResponse(3).Status);
        c.SendFrame(type, type == Continuation ? EndHeaders : 0, 7, type is RstStream or WindowUpdate ? [0, 0, 0, 1] : [0x82]);

        Assert.Equal(ProtocolError, c.ExpectGoAway());
    }

    /// <summary>
    /// A half-closed (remote) stream (its request ended, its answer not yet sent) takes
    /// WINDOW_UPDATE and PRIORITY, and its answer still comes; DATA on it is a stream error
    /// STREAM_CLOSED.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-5.1-7.12.2", "RFC9113-6.9-10")]
    public void ClosesHalfClosedStreamsToMoreData()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, path: "/slow");
        c.SendU32(WindowUpdate, 1, 100);
        c.SendFrame(Priority, 0, 1, [0, 0, 0, 0, 16]);
        Assert.Equal("late", Encoding.ASCII.GetString(c.ReadResponse(1).Body));
        c.SendRequest(3, path: "/slow");
        c.SendFrame(Data, 0, 3, [1]);

        Assert.Equal(StreamClosed, c.ExpectReset(3));
    }

    /// <summary>
    /// Closed streams: DATA after both sides ended it is a connection error STREAM_CLOSED;
    /// after the client reset it, a stream error STREAM_CLOSED, once: the server's RST_STREAM is
    /// its last word on the stream, so the client's frames still in flight after it are taken in
    /// and ignored, neither drawing another RST_STREAM nor failing the connection.
    /// WINDOW_UPDATE and RST_STREAM in flight are fine; RST_STREAM is never answered with
    /// RST_STREAM; and a stream both sides ended hears nothing more from the server (no late
    /// WINDOW_UPDATE or RST_STREAM: only PRIORITY may go on a closed stream).
    /// </summary>
    [Fact]
    [Requirement("RFC9113-5.1-7.14.3#2", "RFC9113-5.1-7.14.5", "RFC9113-5.4.2-5", "RFC9113-6.4-5#1", "RFC9113-5.4.2-4#1",
        "RFC9113-5.4.2-3", "RFC9113-6.4-5#2", "RFC9113-5.1-7.14.3#1")]
    public void ClosesClosedStreams()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, endStream: false, "POST", "/echo");
        c.SendU32(RstStream, 1, Cancel);                            // reset by the client
        Assert.True(c.QuietFor(200));                               // nothing back for it
        c.SendFrame(Data, 0, 1, [1]);
        Assert.Equal(StreamClosed, c.ExpectReset(1));
        c.SendFrame(Data, 0, 1, [2]);                               // in flight past the server's reset
        c.SendU32(WindowUpdate, 1, 10);
        Assert.True(c.QuietFor(300));                               // taken in silently: one reset per stream
        c.SendRequest(3, endStream: false, "POST", "/echo");
        c.SendFrame(Data, EndStream, 3, new byte[1000]);
        Assert.Equal(1000, c.ReadResponse(3).Body.Length);         // ended by both sides
        Assert.DoesNotContain(c.FramesWithin(300), f => f.Stream == 3 && f.Type != Priority);
        c.SendU32(WindowUpdate, 3, 10);                             // in flight: fine
        c.SendFrame(Data, 0, 3, [1]);

        Assert.Equal(StreamClosed, c.ExpectGoAway());
    }

    /// <summary>
    /// A client's stream ids are odd and increase: an even one (a stream only the server could
    /// initiate, so HEADERS on it while idle is refused too, RFC9113-5.1-7.2.4#2), or one lower
    /// than a stream already opened, is a connection error PROTOCOL_ERROR.
    /// </summary>
    /// <param name="even">An even id (true) or a decreasing one.</param>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("RFC9113-5.1.1-1#1", "RFC9113-5.1.1-2#1", "RFC9113-5.1.1-2#2", "RFC9113-5.1-7.2.4#2")]
    public void RefusesBadStreamIds(bool even)
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        if (even)
        {
            c.SendRequest(2);
        }
        else
        {
            c.SendRequest(5);
            Assert.Equal(200, c.ReadResponse(5).Status);
            c.SendRequest(3);
        }

        Assert.Equal(ProtocolError, c.ExpectGoAway());
    }

    /// <summary>
    /// Past SETTINGS_MAX_CONCURRENT_STREAMS (the server's), a new stream is refused with
    /// REFUSED_STREAM, before any of it reaches the handler (a whole GET, which an accepted
    /// stream would hand over at once: REFUSED_STREAM is only for streams no application saw);
    /// the others carry on.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-5.1.2-3#2", "RFC9113-8.7-5#1", "RFC9113-8.7-5#2")]
    public void RefusesStreamsPastTheLimit()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);
        uint limit = c.ServerSettings[3];

        for (int i = 0; i < limit; i++)
        {
            c.SendRequest(1 + i * 2, endStream: false, "POST", "/echo");
        }

        int extra = 1 + (int)limit * 2;
        int before = Volatile.Read(ref handled);
        c.SendRequest(extra);                                       // ended: accepted, a handler would see it at once
        Assert.Equal(RefusedStream, c.ExpectReset(extra));
        Assert.Equal(before, Volatile.Read(ref handled));           // REFUSED_STREAM: no handler saw it
        c.SendFrame(Data, EndStream, 1, [7]);
        Assert.Equal(new byte[] { 7 }, c.ReadResponse(1).Body);
    }

    /// <summary>Unknown settings are ignored; a repeated setting takes its last value, applied
    /// in order (an initial window of 100, then 1: the answer comes 1 octet at a time).</summary>
    [Fact]
    [Requirement("RFC9113-6.5.2-3", "RFC9113-6.5.3-2#1", "RFC9113-6.5.3-2#2", "RFC9113-5.5-4#1", "RFC9113-6.5-3#3")]
    public void AppliesSettingsInOrder()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port, true, (0x99, 7), (4, 100), (4, 1));

        c.SendRequest(1);

        H2Frame data = c.Expect(Data, 1);
        Assert.Single(data.Payload);
    }

    /// <summary>Malformed SETTINGS frames are connection errors with the code the rule names.</summary>
    /// <param name="flags">The frame's flags.</param>
    /// <param name="stream">Its stream.</param>
    /// <param name="hex">Its payload.</param>
    /// <param name="code">The error expected.</param>
    /// <remarks>The cases: an ACK with a payload; a stream other than 0; a length that is not a
    /// multiple of 6; ENABLE_PUSH 2; INITIAL_WINDOW_SIZE 2^31; MAX_FRAME_SIZE below 2^14 and
    /// above 2^24 - 1.</remarks>
    [Theory]
    [InlineData(1, 0, "000400000001", FrameSizeError)]
    [InlineData(0, 1, "000400000001", ProtocolError)]
    [InlineData(0, 0, "0004000001", FrameSizeError)]
    [InlineData(0, 0, "000200000002", ProtocolError)]
    [InlineData(0, 0, "000480000000", FlowControlError)]
    [InlineData(0, 0, "000500003FFF", ProtocolError)]
    [InlineData(0, 0, "000501000000", ProtocolError)]
    [Requirement("RFC9113-6.5-6.2#1", "RFC9113-6.5-6.2#2", "RFC9113-6.5-7#1", "RFC9113-6.5-7#2", "RFC9113-6.5-8", "RFC9113-6.5-9",
        "RFC9113-6.5.2-2.4.2", "RFC9113-6.5.2-2.8.3", "RFC9113-6.5.2-2.10.2#2")]
    public void RefusesBadSettings(int flags, int stream, string hex, uint code)
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendFrame(Settings, flags, stream, Convert.FromHexString(hex));

        Assert.Equal(code, c.ExpectGoAway());
    }

    /// <summary>
    /// Padded HEADERS and DATA are accepted: the request and its data reach the handler without
    /// the padding. The padding octets are not checked (non-zero here): treating them as an
    /// error is a receiver's option this server does not take.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-6.1-2", "RFC9113-6.9-11", "RFC9113-6.1-5.6#2", "RFC9113-6.2-4.12#2")]
    public void AcceptsPaddedData()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        byte[] block = c.RequestBlock("POST", "/echo");
        c.SendFrame(Headers, Padded | EndHeaders, 1, [3, .. block, 0x55, 0xAA, 0xFF]);
        c.SendFrame(Data, Padded | EndStream, 1, [2, (byte)'A', (byte)'B', 7, 9]);

        Assert.Equal("AB", Encoding.ASCII.GetString(c.ReadResponse(1).Body));
    }

    /// <summary>
    /// Malformed frames of each kind, each a connection error with its code: always reported (a
    /// GOAWAY naming it), and reported once (no second GOAWAY before the close).
    /// </summary>
    /// <param name="type">The frame's type.</param>
    /// <param name="flags">Its flags.</param>
    /// <param name="stream">Its stream.</param>
    /// <param name="hex">Its payload.</param>
    /// <param name="code">The error expected.</param>
    /// <remarks>The cases: DATA on stream 0; DATA padded past its length; HEADERS on stream 0;
    /// HEADERS padded past its length; PRIORITY on stream 0; RST_STREAM on stream 0; RST_STREAM of
    /// 3 octets; PING on stream 1; PING of 7 octets; GOAWAY on stream 1; WINDOW_UPDATE of 0 on the
    /// connection; WINDOW_UPDATE of 3 octets; PUSH_PROMISE from a client.</remarks>
    [Theory]
    [InlineData(Data, 0, 0, "01", ProtocolError)]
    [InlineData(Data, Padded, 1, "0501", ProtocolError)]
    [InlineData(Headers, EndHeaders, 0, "82", ProtocolError)]
    [InlineData(Headers, EndHeaders | Padded, 1, "0582", ProtocolError)]
    [InlineData(Priority, 0, 0, "0000000110", ProtocolError)]
    [InlineData(RstStream, 0, 0, "00000008", ProtocolError)]
    [InlineData(RstStream, 0, 1, "000008", FrameSizeError)]
    [InlineData(Ping, 0, 1, "0102030405060708", ProtocolError)]
    [InlineData(Ping, 0, 0, "01020304050607", FrameSizeError)]
    [InlineData(GoAway, 0, 1, "0000000000000000", ProtocolError)]
    [InlineData(WindowUpdate, 0, 0, "00000000", ProtocolError)]
    [InlineData(WindowUpdate, 0, 0, "000001", FrameSizeError)]
    [InlineData(PushPromise, EndHeaders, 1, "0000000282", ProtocolError)]
    [Requirement("RFC9113-6.1-9#2", "RFC9113-6.1-11", "RFC9113-6.2-8#1", "RFC9113-6.2-8#2", "RFC9113-6.2-10", "RFC9113-6.3-6",
        "RFC9113-6.4-6#1", "RFC9113-6.4-6#2", "RFC9113-6.4-8", "RFC9113-6.7-8", "RFC9113-6.7-9", "RFC9113-6.7-4", "RFC9113-6.8-11",
        "RFC9113-6.9-9#1", "RFC9113-6.9-12", "RFC9113-8.4-10", "RFC9113-8.4.1-7", "RFC9113-5.4-6#2", "RFC9113-5.4-4#2",
        "RFC9113-5.4-5#1")]
    public void RefusesMalformedFrames(int type, int flags, int stream, string hex, uint code)
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);
        if (type == RstStream && stream == 1)
        {
            c.SendRequest(1, endStream: false, "POST", "/echo");   // an open stream: only the length is wrong
        }

        c.SendFrame(type, flags, stream, Convert.FromHexString(hex));

        Assert.Equal(code, c.ExpectGoAway());
    }

    /// <summary>
    /// Errors that belong to one stream reset it, and the connection carries on: PRIORITY of a
    /// wrong length (FRAME_SIZE_ERROR), a WINDOW_UPDATE of 0 on a stream, a stream window past
    /// 2^31 - 1 (FLOW_CONTROL_ERROR).
    /// </summary>
    /// <param name="type">The frame.</param>
    /// <param name="hex">Its payload.</param>
    /// <param name="code">The stream error expected.</param>
    [Theory]
    [InlineData(Priority, "00000001", FrameSizeError)]
    [InlineData(WindowUpdate, "00000000", ProtocolError)]
    [InlineData(WindowUpdate, "7FFFFFFF", FlowControlError)]
    [Requirement("RFC9113-6.3-8", "RFC9113-6.9-9#2", "RFC9113-6.9.1-7#2", "RFC9113-5.4.1-4#1")]
    public void ResetsStreamsOnStreamErrors(int type, string hex, uint code)
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, path: "/slow");
        c.SendFrame(type, 0, 1, Convert.FromHexString(hex));
        Assert.Equal(code, c.ExpectReset(1));
        c.SendRequest(3);

        Assert.Equal(200, c.ReadResponse(3).Status);
    }

    /// <summary>The connection's send window past 2^31 - 1 is a connection error FLOW_CONTROL_ERROR.</summary>
    [Fact]
    [Requirement("RFC9113-6.9.1-7#1", "RFC9113-6.9.1-7#2")]
    public void BoundsTheConnectionWindow()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendU32(WindowUpdate, 0, 0x7FFFFFFF);

        Assert.Equal(FlowControlError, c.ExpectGoAway());
    }

    /// <summary>
    /// PING is answered with an ACK carrying the same 8 octets; a PING ACK is not answered.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-6.7-4", "RFC9113-6.7-5#1", "RFC9113-6.7-7.2#1", "RFC9113-6.7-7.2#2")]
    public void AnswersPings()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendFrame(Ping, Ack, 0, [9, 9, 9, 9, 9, 9, 9, 9]);
        Assert.True(c.QuietFor(200));
        c.SendFrame(Ping, 0, 0, [1, 2, 3, 4, 5, 6, 7, 8]);
        H2Frame pong = c.Expect(Ping);

        Assert.Equal(Ack, pong.Flags & Ack);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, pong.Payload);
    }

    /// <summary>
    /// After the client's GOAWAY the server opens nothing new, still answers the stream in
    /// progress (a deferred one, answered a second later), and once idle closes, saying GOAWAY
    /// itself first: NO_ERROR, the last stream the client opened, no debug data.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-6.8-3", "RFC9113-6.8-7", "RFC9113-6.8-21#1")]
    public void ClosesAfterTheClientsGoAway()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, path: "/slow");
        c.SendFrame(GoAway, 0, 0, [0, 0, 0, 1, 0, 0, 0, 0]);       // the client leaves after stream 1

        Assert.Equal("late", Encoding.ASCII.GetString(c.ReadResponse(1).Body));
        (uint last, uint code, int length) = c.ReadGoAway();
        Assert.Equal((1u, NoError, 8), (last, code, length));
        Assert.Null(c.ReadFrame());                                 // then the close
    }

    /// <summary>
    /// An idle connection the server closes (its idle timeout) hears GOAWAY first, NO_ERROR,
    /// naming the last stream it served, so its client knows every request it sent was
    /// processed; then the connection closes.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-6.8-5", "RFC9113-9.1-5", "RFC9113-5.4.1-4#2", "RFC9113-8.7-5#3", "RFC9113-6.8-21#1")]
    public void SaysGoAwayBeforeClosingIdle()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer(idleMs: 300);
        using var c = new H2Connection(server.Port);

        c.SendRequest(1);
        Assert.Equal(200, c.ReadResponse(1).Status);
        c.SendRequest(3);
        Assert.Equal(200, c.ReadResponse(3).Status);

        (uint last, uint code, int length) = c.ReadGoAway();        // after the idle timeout
        Assert.Equal((3u, NoError, 8), (last, code, length));       // every stream it handled: <= 3
        Assert.Null(c.ReadFrame());
    }

    /// <summary>
    /// A graceful stop with a stream in progress: GOAWAY(NO_ERROR) with the last stream
    /// 2^31 - 1 first, so the client opens nothing new while requests already on their way are
    /// still served (one sent after the notice, its block using the dynamic table and its body
    /// counted like any, is answered: the connection's state stays whole); the deferred stream
    /// is answered; then the final GOAWAY, its last stream lowered to the real one, and the
    /// close.
    /// </summary>
    /// <returns>A task.</returns>
    [Fact]
    [Requirement("RFC9113-6.8-18#1", "RFC9113-6.8-18#2", "RFC9113-6.8-17#1", "RFC9113-6.8-17#2", "RFC9113-6.8-19#1",
        "RFC9113-6.8-19#2")]
    public async Task ShutsDownGracefully()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        using var server = NewServer();
        using var c = new H2Connection(server.Port);
        c.SendRequest(1, path: "/slow");                            // keeps the connection busy for a second

        Task stop = Task.Run(server.Stop, ct);

        (uint first, uint code, _) = c.ReadGoAway();
        Assert.Equal((0x7FFFFFFFu, NoError), (first, code));
        c.SendRequest(3, endStream: false, "POST", "/echo");       // was on its way: still served
        c.SendFrame(Data, EndStream, 3, "after"u8);
        Assert.Equal("after", Encoding.ASCII.GetString(c.ReadResponse(3).Body));
        Assert.Equal("late", Encoding.ASCII.GetString(c.ReadResponse(1).Body));
        (uint last, code, _) = c.ReadGoAway();
        Assert.Equal((3u, NoError), (last, code));
        Assert.Equal(2, c.GoAwayCount);
        Assert.Null(c.ReadFrame());
        await stop.WaitAsync(TimeSpan.FromSeconds(10), ct);
    }

    /// <summary>
    /// A graceful stop on an idle HTTP/2 connection is graceful too: GOAWAY(NO_ERROR, 2^31 - 1)
    /// then a PING. A request the client sent before answering the PING was on its way when the
    /// notice went out, so it is served. The final GOAWAY, naming that request's stream as the
    /// last, and the close come only after the PING's ACK: RFC 9113 6.8's round trip, measured.
    /// The ACK itself is not answered (RFC9113-6.7-7.2#2). Closing an idle connection at once,
    /// as the server first did, refused such a request; ShutsDownGracefully failed that way
    /// under the slower coverage build (2026-11-26).
    /// </summary>
    /// <returns>A task.</returns>
    [Fact]
    [Requirement("RFC9113-6.8-18#1", "RFC9113-6.8-18#2", "RFC9113-6.7-7.2#2")]
    public async Task WaitsForThePingBeforeClosingAnIdleConnection()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        using var server = NewServer();
        using var c = new H2Connection(server.Port) { AnswerPings = false };

        Task stop = Task.Run(server.Stop, ct);

        (uint first, uint code, _) = c.ReadGoAway();
        Assert.Equal((0x7FFFFFFFu, NoError), (first, code));
        H2Frame ping = c.Expect(Ping);
        Assert.Equal(0, ping.Flags & Ack);
        c.SendRequest(1);                                           // already on its way: served
        c.SendFrame(Ping, Ack, 0, ping.Payload);                    // the round trip completes
        Assert.Equal(200, c.ReadResponse(1).Status);
        (uint last, code, _) = c.ReadGoAway();
        Assert.Equal((1u, NoError), (last, code));
        Assert.Null(c.ReadFrame());
        Assert.Equal(1, c.PingsReceived);
        await stop.WaitAsync(TimeSpan.FromSeconds(10), ct);
    }

    /// <summary>
    /// Flow control on the answers: with the client's initial window at 1, the body comes 1
    /// octet at a time; a SETTINGS change applies to open streams (resuming them, or making a
    /// window negative, which must be paid back first); WINDOW_UPDATE resumes them.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-5.2.1-2.3#2", "RFC9113-6.9.1-2#1", "RFC9113-6.9.2-3", "RFC9113-6.9.2-4#1", "RFC9113-6.9.2-4#2", "RFC9113-6.9-11")]
    public void SendsWithinTheWindows()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port, true, (4, 1));

        c.SendRequest(1, path: "/mixed");                           // answers "ok"
        Assert.Single(c.Expect(Data, 1).Payload);                   // "o": the window was 1
        c.SendSettings((4, 0));                                     // the stream's window: 1 - 1 + (0 - 1) = -1
        c.Expect(Settings);
        Assert.True(c.QuietFor(200));                               // nothing while negative
        c.SendU32(WindowUpdate, 1, 1);                              // back to 0: still nothing
        Assert.True(c.QuietFor(200));
        c.SendSettings((4, 5));                                     // 0 + 5: the rest comes
        H2Frame rest = c.Expect(Data, 1);

        Assert.Equal("k", Encoding.ASCII.GetString(rest.Payload));
        Assert.Equal(EndStream, rest.Flags & EndStream);
    }

    /// <summary>An initial window past 2^31 - 1 for open streams is a connection error FLOW_CONTROL_ERROR.</summary>
    [Fact]
    [Requirement("RFC9113-6.9.2-7")]
    public void BoundsStreamWindowsOnSettings()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, path: "/slow");
        c.SendU32(WindowUpdate, 1, 0x7FFFFFFF - 65535);             // the stream's window: 2^31 - 1
        c.SendSettings((4, 65536));                                 // + 1

        Assert.Equal(FlowControlError, c.ExpectGoAway());
    }

    /// <summary>
    /// Malformed requests are stream errors PROTOCOL_ERROR; the connection carries on (a request
    /// after them is answered). A malformed request head is answered 400 (with a date, as every
    /// 4xx) before the reset, which stays its stream's last frame (the 400 does not end the
    /// stream); a malformed body or trailer section is reset with no answer, as the request was
    /// already accepted when it broke. :authority and Host follow HTTP/1.1's Host grammar, and
    /// CONNECT's :authority needs a port of 1 to 65535, as HTTP/1.1's CONNECT target does:
    /// tests/fuzz/h2_request found HTTP/2 accepting what HTTP/1.1 refused (2026-11-26).
    /// </summary>
    /// <param name="case">Which rule the request breaks.</param>
    [Theory]
    [InlineData("uppercase-name")]
    [InlineData("space-in-name")]
    [InlineData("colon-in-name")]
    [InlineData("nul-in-value")]
    [InlineData("space-at-value-end")]
    [InlineData("connection-field")]
    [InlineData("te-gzip")]
    [InlineData("unknown-pseudo")]
    [InlineData("status-in-request")]
    [InlineData("pseudo-after-regular")]
    [InlineData("method-twice")]
    [InlineData("path-missing")]
    [InlineData("path-empty")]
    [InlineData("userinfo")]
    [InlineData("host-differs")]
    [InlineData("connect-with-path")]
    [InlineData("connect-without-port")]
    [InlineData("connect-port-zero")]
    [InlineData("connect-port-too-large")]
    [InlineData("authority-not-a-host")]
    [InlineData("authority-open-literal")]
    [InlineData("host-not-a-host")]
    [InlineData("content-length-short")]
    [InlineData("trailer-pseudo")]
    [InlineData("second-headers-open")]
    [Requirement("RFC9113-8.1.1-3#2", "RFC9113-8.2.1-2", "RFC9113-8.2.1-3.1", "RFC9113-8.2.1-3.2", "RFC9113-8.2.1-3.3", "RFC9113-8.2.1-3.4",
        "RFC9113-8.2.1-5#1", "RFC9113-8.2.1-1", "RFC9113-8.2.2-1#2", "RFC9113-8.2.2-2#1", "RFC9113-8.2.2-2#2", "RFC9113-8.3-2",
        "RFC9113-8.3-3#2", "RFC9113-8.3-3#4", "RFC9113-8.3-4#1", "RFC9113-8.3-4#2", "RFC9113-8.3-5#1", "RFC9113-8.3-5#2",
        "RFC9113-8.3.1-3", "RFC9113-8.3.1-2.4.2#1", "RFC9113-8.3.1-2.4.2#2", "RFC9113-8.3.1-2.3.8", "RFC9113-8.3.1-2.3.3#2",
        "RFC9113-8.5-3.2", "RFC9113-8.1-8#1", "RFC9113-8.1-8#2", "RFC9113-8.3-3#3", "RFC9113-8.1-9", "RFC9113-8.2.1-6",
        "RFC9113-8.1.1-4#1", "RFC9110-4.2.4-4", "RFC9110-9.3.6-4", "RFC9113-8.3.1-2.3.3#2")]
    public void RefusesMalformedRequests(string @case)
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);
        (string, string)[] Base(string method = "GET", string path = "/") => [(":method", method), (":scheme", "http"), (":path", path), (":authority", "127.0.0.1")];

        switch (@case)
        {
            case "uppercase-name": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([.. Base(), ("X-Upper", "1")])); break;
            case "space-in-name": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([.. Base(), ("x y", "1")])); break;
            case "colon-in-name": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([.. Base(), ("x:y", "1")])); break;
            case "nul-in-value": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([.. Base(), ("x", "a\0b")])); break;
            case "space-at-value-end": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([.. Base(), ("x", "a ")])); break;
            case "connection-field": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([.. Base(), ("connection", "keep-alive")])); break;
            case "te-gzip": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([.. Base(), ("te", "gzip")])); break;
            case "unknown-pseudo": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([.. Base(), (":foo", "1")])); break;
            case "status-in-request": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([.. Base(), (":status", "200")])); break;
            case "pseudo-after-regular": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([(":method", "GET"), (":scheme", "http"), ("x", "1"), (":path", "/")])); break;
            case "method-twice": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([.. Base(), (":method", "GET")])); break;
            case "path-missing": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([(":method", "GET"), (":scheme", "http"), (":authority", "a")])); break;
            case "path-empty": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([.. Base(path: "")])); break;
            case "userinfo": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "u@h")])); break;
            case "host-differs": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([.. Base(), ("host", "other")])); break;
            case "connect-with-path": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([(":method", "CONNECT"), (":path", "/"), (":authority", "h:1")])); break;
            case "connect-without-port": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([(":method", "CONNECT"), (":authority", "example.com")])); break;
            case "connect-port-zero": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([(":method", "CONNECT"), (":authority", "example.com:0")])); break;
            case "connect-port-too-large": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([(":method", "CONNECT"), (":authority", "example.com:65536")])); break;
            case "authority-not-a-host": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "a b")])); break;
            case "authority-open-literal": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "[::1")])); break;
            case "host-not-a-host": c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([(":method", "GET"), (":scheme", "http"), (":path", "/"), ("host", "a/b")])); break;
            case "content-length-short":
                c.SendFrame(Headers, EndHeaders, 1, c.Block([.. Base("POST", "/echo"), ("content-length", "1")]));
                c.SendFrame(Data, EndStream, 1, [1, 2]);
                break;
            case "trailer-pseudo":
                c.SendFrame(Headers, EndHeaders, 1, c.Block([.. Base("POST", "/echo")]));
                c.SendFrame(Headers, EndHeaders | EndStream, 1, c.Block([(":path", "/")]));
                break;
            case "second-headers-open":
                c.SendFrame(Headers, EndHeaders, 1, c.Block([.. Base("POST", "/echo")]));
                c.SendFrame(Headers, EndHeaders, 1, c.Block([("x", "1")]));
                break;
        }

        // What came on stream 1 before its reset: a 400 for a bad head, nothing for a bad body.
        H2Frame? answer = null;
        H2Frame reset;
        while ((reset = c.ReadFrame() ?? throw new IOException("closed before the reset")).Type != RstStream || reset.Stream != 1)
        {
            Assert.NotEqual(GoAway, reset.Type);
            answer = reset.Type == Headers && reset.Stream == 1 ? reset : answer;
        }

        Assert.Equal(ProtocolError, BinaryPrimitives.ReadUInt32BigEndian(reset.Payload));
        if (@case is "content-length-short" or "trailer-pseudo" or "second-headers-open")
        {
            Assert.Null(answer);
        }
        else
        {
            Assert.NotNull(answer);
            Assert.Equal(0, answer.Flags & EndStream);                // the reset ends the stream
            Assert.Equal("400", c.Decoded[1].Single(f => f.Name == ":status").Value);
            Assert.Single(c.Decoded[1], f => f.Name == "date");
        }

        c.SendRequest(3);
        Assert.Equal(200, c.ReadResponse(3).Status);
    }

    /// <summary>Cookies split over several fields reach the handler joined with "; " (one field).</summary>
    [Fact]
    [Requirement("RFC9113-8.2.3-2#1", "RFC9113-8.2.3-2#2")]
    public void JoinsCookies()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, path: "/cookie", extra: [("cookie", "a=1"), ("x", "y"), ("cookie", "b=2")]);

        Assert.Equal("a=1; b=2|1", Encoding.ASCII.GetString(c.ReadResponse(1).Body));
    }

    /// <summary>
    /// Answers go out with lower-case field names, :status first, and no connection-specific
    /// field; the request's :authority is the authority the handler sees.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-8.2-2", "RFC9113-8.2.2-1#1", "RFC9113-8.3.2-1", "RFC9113-8.3-3#1", "RFC9113-8.3.1-2.3.1", "RFC9113-4.1-4.2.1")]
    public void AnswersWithLowerCaseNames()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, path: "/mixed");
        H2Response response = c.ReadResponse(1);

        Assert.Equal(":status", c.Decoded[1][0].Name);
        Assert.Contains(response.Fields, f => f.Name == "x-mixed-case");
        Assert.DoesNotContain(response.Fields, f => f.Name.Any(char.IsUpper) || f.Name is "connection" or "keep-alive" or "transfer-encoding" or "upgrade");
    }

    /// <summary>
    /// A request whose declared body exceeds max_body is answered 413 before its body comes, and
    /// the stream is then reset with NO_ERROR: the client may stop sending.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-8.1-11#1", "RFC9113-8.1.1-5")]
    public void AnswersEarlyAndStopsTheUpload()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendFrame(Headers, EndHeaders, 1, c.RequestBlock("POST", "/echo", ("content-length", "99999999")));

        Assert.Equal(413, ReadStatus(c, 1));
        Assert.Equal(NoError, c.ExpectReset(1));
    }

    /// <summary>
    /// A mixed conversation under the sending rules that every frame of the server's is checked
    /// against (H2Connection.CheckSendingRules): an answer split over several DATA frames, a PING,
    /// a SETTINGS change, a stream the server resets (a self-dependency), an early answer with
    /// its NO_ERROR reset, and a connection error to end. Nothing the server sends on the way
    /// may break a rule. This test names the rules the check proves; every other HTTP/2 test
    /// enforces them too.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-4.1-4.6.2#2", "RFC9113-4.1-4.8.1#1", "RFC9113-6.1-5.6#1", "RFC9113-6.2-4.12#1", "RFC9113-6.1-9#1",
        "RFC9113-6.4-7#1", "RFC9113-5.1.2-3#1", "RFC9113-5.4.2-4#1")]
    public void KeepsTheSendingRules()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, endStream: false, "POST", "/echo");        // 40000 octets each way: frames of 16384 at most
        c.SendFrame(Data, 0, 1, new byte[16384]);
        c.SendFrame(Data, 0, 1, new byte[16384]);
        c.SendFrame(Data, EndStream, 1, new byte[40000 - 2 * 16384]);
        Assert.Equal(40000, c.ReadResponse(1).Body.Length);
        c.SendFrame(Ping, 0, 0, [1, 2, 3, 4, 5, 6, 7, 8]);
        c.Expect(Ping);
        c.SendSettings((4, 100));
        Assert.Equal(Ack, c.Expect(Settings).Flags & Ack);
        c.SendRequest(3);
        Assert.Equal("ok", Encoding.ASCII.GetString(c.ReadResponse(3).Body));
        c.SendFrame(Headers, EndHeaders | EndStream | PriorityFlag, 5, [0, 0, 0, 5, 16, .. c.RequestBlock()]);
        Assert.Equal(ProtocolError, c.ExpectReset(5));              // depends on itself: the server resets it
        c.SendFrame(Headers, EndHeaders, 7, c.RequestBlock("POST", "/echo", ("content-length", "99999999")));
        Assert.Equal(413, ReadStatus(c, 7));
        Assert.Equal(NoError, c.ExpectReset(7));
        c.SendFrame(Data, 0, 0, [1]);                               // DATA on stream 0: a connection error

        Assert.Equal(ProtocolError, c.ExpectGoAway());
    }

    /// <summary>
    /// The client lowers SETTINGS_HEADER_TABLE_SIZE below what the server's encoder holds (an
    /// answer's fields went into its table): once the server acknowledged it, its next field
    /// block starts with a Dynamic Table Size Update within the new maximum (0 here), and the
    /// table that leaves behind is empty.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-4.3.1-4#1")]
    public void ShrinksItsTableWhenAsked()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, path: "/mixed");
        Assert.Equal(200, c.ReadResponse(1).Status);
        Assert.True(c.DecoderSize > 0, "the server's encoder indexed nothing, so there is nothing to shrink");
        c.SendSettings((1, 0));
        Assert.Equal(Ack, c.Expect(Settings).Flags & Ack);
        c.SendRequest(3, path: "/mixed");
        H2Frame headers = c.Expect(Headers, 3);

        Assert.Equal(0x20, headers.Payload[0]);                     // 001 00000: a size update to 0, first
        Assert.Equal(0u, c.DecoderSize);
    }

    /// <summary>
    /// SETTINGS may come at any time, not only first: one in the middle of the connection is
    /// acknowledged and applied. Here it sets SETTINGS_MAX_CONCURRENT_STREAMS to 0, which only
    /// limits the streams the server would open (none: it does not push), so it is nothing
    /// special to the server: requests are answered as before.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-6.5-3#2", "RFC9113-6.5.2-2.6.2#1")]
    public void TakesSettingsAtAnyTime()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1);
        Assert.Equal(200, c.ReadResponse(1).Status);
        c.SendSettings((3, 0));
        Assert.Equal(Ack, c.Expect(Settings).Flags & Ack);
        c.SendRequest(3);

        Assert.Equal(200, c.ReadResponse(3).Status);
    }

    /// <summary>
    /// Frames outside flow control are taken in and acted on while the server's own answer
    /// waits for window: with the client's initial window at 0, the answer's HEADERS go out but
    /// its DATA cannot; a PING is still answered, and a WINDOW_UPDATE is still read and lets the
    /// DATA go. The server reads frames as they come, whatever its output waits for.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-6.9-4#1", "RFC9113-5.2.2-4")]
    public void ReadsFramesWhileItsAnswerWaits()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port, true, (4, 0));

        c.SendRequest(1);
        Assert.Equal(0, c.Expect(Headers, 1).Flags & EndStream);    // the body waits for window
        c.SendFrame(Ping, 0, 0, [8, 7, 6, 5, 4, 3, 2, 1]);
        Assert.Equal(Ack, c.Expect(Ping).Flags & Ack);
        c.SendU32(WindowUpdate, 1, 100);
        H2Frame data = c.Expect(Data, 1);

        Assert.Equal("ok", Encoding.ASCII.GetString(data.Payload));
        Assert.Equal(EndStream, data.Flags & EndStream);
    }

    /// <summary>
    /// A rapid-reset storm (CVE-2023-44487): streams opened and reset at once, past the floor
    /// the server tolerates and at more than one reset for every two streams, is activity the
    /// server tracks and ends as suspicious, with ENHANCE_YOUR_CALM.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-10.5-6#1", "RFC9113-10.5-6#2")]
    public void RefusesResetStorms()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        for (int i = 0; i < 300; i++)
        {
            c.SendRequest(1 + i * 2, endStream: false, "POST", "/echo");
            c.SendU32(RstStream, 1 + i * 2, Cancel);
        }

        Assert.Equal(EnhanceYourCalm, c.ExpectGoAway());
    }

    /// <summary>
    /// A CONTINUATION flood (CVE-2024-27316): a field block that never ends, frame after frame,
    /// is cut off past the server's bound with ENHANCE_YOUR_CALM, long before it could grow
    /// without limit.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-10.5-6#1", "RFC9113-10.5-6#2")]
    public void RefusesContinuationFloods()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        // The block is cut after 1 octet and never ended, so the encoder running ahead of the
        // server costs nothing: the connection ends before any later block.
        c.SendFrame(Headers, EndStream, 1, c.RequestBlock()[..1]);
        for (int i = 0; i < 200; i++)
        {
            c.SendFrame(Continuation, 0, 1, []);
        }

        Assert.Equal(EnhanceYourCalm, c.ExpectGoAway());
    }

    /// <summary>
    /// A field section larger than the server's limit (its max_head, advertised as
    /// SETTINGS_MAX_HEADER_LIST_SIZE) is answered 431, a 4xx as the semantics require. The block
    /// was still decoded whole, so the HPACK tables stay in step: the next request refers to an
    /// entry that block added to the dynamic table, and it is understood and answered. A block
    /// past twice the limit cannot even be kept for decoding, and ends the connection with
    /// ENHANCE_YOUR_CALM.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-10.5.1-3", "RFC9110-5.4-2", "RFC9113-10.5-6#2")]
    public void Answers431AndKeepsTheTablesInStep()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer(limits: new H1Limits { MaxHead = 1024 });
        using var c = new H2Connection(server.Port);
        Assert.Equal(1024u, c.ServerSettings[6]);

        c.SendRequest(1, extra: [("x-kept", "1"), ("x-big", new string('b', 1200))]);
        Assert.Equal(431, ReadStatus(c, 1));
        c.SendRequest(3, extra: [("x-kept", "1")]);                   // "x-kept: 1" now comes from the table
        Assert.Equal(200, c.ReadResponse(3).Status);

        byte[] huge = c.RequestBlock(extra: [("x-huge", new string('h', 2100))]);
        c.SendFrame(Headers, EndStream, 5, huge[..1000]);           // assembled across frames: bounded
        c.SendFrame(Continuation, EndHeaders, 5, huge[1000..]);
        Assert.Equal(EnhanceYourCalm, c.ExpectGoAway());
    }

    /// <summary>
    /// A client that sends the preface's first line, "PRI * HTTP/2.0", speaks HTTP/2; when what
    /// follows is not the rest of the preface, that is a connection error PROTOCOL_ERROR, and the
    /// server closes without a word (its GOAWAY may be omitted: the peer is not speaking HTTP/2
    /// after all) instead of answering the HTTP/1.1 505 that request line would otherwise get.
    /// An opening that is no HTTP at all (h2spec's own case) closes the same way.
    /// </summary>
    /// <param name="opening">The connection's first octets.</param>
    [Theory]
    [InlineData("PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n")]
    [InlineData("PRI * HTTP/2.0\r\nSM\r\n\r\n\r\n\r\n")]
    [InlineData("INVALID CONNECTION PREFACE\r\n\r\n")]
    [Requirement("RFC9113-3.4-9#1", "RFC9113-3.4-9#2")]
    public void RefusesAnInvalidPreface(string opening)
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new RawConnection(server.Port);

        c.Send(opening);

        Assert.True(c.ServerClosed());
    }

    /// <summary>
    /// 205 (Reset Content) carries no content over HTTP/2 either: the handler's answer with a body
    /// is refused, and its empty one ends the stream on the HEADERS, with content-length 0.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-15.3.6-3")]
    public void SendsResetContentEmpty()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, path: "/reset");
        H2Response response = c.ReadResponse(1);

        Assert.Equal(205, response.Status);
        Assert.Empty(response.Body);
        Assert.Equal("0", response.Fields.Single(f => f.Name == "content-length").Value);
    }

    /// <summary>OPTIONS for the server as a whole: the :path "*" reaches the handler as the target "*".</summary>
    [Fact]
    [Requirement("RFC9113-8.3.1-2.4.3.1")]
    public void ServesOptionsForTheServer()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, true, "OPTIONS", "*");

        Assert.Equal("asterisk OPTIONS", Encoding.ASCII.GetString(c.ReadResponse(1).Body));
    }

    /// <summary>
    /// HEAD is answered with the fields GET would get, content-length included, and no DATA:
    /// the HEADERS end the stream. A response defined to have no content may still say how
    /// long it would have been.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-8.1.1-2")]
    public void AnswersHeadWithTheLengthAlone()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, true, "HEAD");
        H2Frame headers = c.Expect(Headers, 1);

        Assert.Equal(EndStream, headers.Flags & EndStream);
        Assert.Equal("2", c.Decoded[1].Single(f => f.Name == "content-length").Value);
        Assert.DoesNotContain(c.FramesWithin(200), f => f.Stream == 1);
    }

    /// <summary>
    /// A request that expects 100-continue gets the interim 100 (HEADERS that neither end the
    /// stream nor are the final answer) before it sends its body; the final answer follows the
    /// body.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-8.1-4")]
    public void SendsContinueBeforeTheBody()
    {
        Platform.RequireLinuxX64();
        using var server = NewServer();
        using var c = new H2Connection(server.Port);

        c.SendRequest(1, false, "POST", "/echo", ("expect", "100-continue"));
        H2Frame interim = c.Expect(Headers, 1);
        Assert.Equal("100", c.Decoded[1].Single(f => f.Name == ":status").Value);
        Assert.Equal(0, interim.Flags & EndStream);
        c.SendFrame(Data, EndStream, 1, "body"u8);
        H2Response response = c.ReadResponse(1);

        Assert.Equal((200, "body"), (response.Status, Encoding.ASCII.GetString(response.Body)));
    }

    /// <summary>Reads a stream's final status (its HEADERS), without waiting for its end.</summary>
    /// <param name="c">The connection.</param>
    /// <param name="stream">The stream.</param>
    /// <returns>The status.</returns>
    private static int ReadStatus(H2Connection c, int stream)
    {
        c.Expect(Headers, stream);
        return int.Parse(c.Decoded[stream].First(f => f.Name == ":status").Value, System.Globalization.CultureInfo.InvariantCulture);
    }
}
