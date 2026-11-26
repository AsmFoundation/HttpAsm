using System.Net;
using System.Net.Sockets;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>A response as <see cref="RawConnection"/> read it off the wire.</summary>
/// <param name="Status">The status code.</param>
/// <param name="Reason">The reason phrase (may be empty).</param>
/// <param name="Fields">The header fields, in order, as sent.</param>
/// <param name="Body">The body (empty for HEAD, 1xx, 204 and 304).</param>
internal sealed record RawResponse(int Status, string Reason, IReadOnlyList<(string Name, string Value)> Fields, byte[] Body)
{
    /// <summary>The body as UTF-8 text.</summary>
    public string Text => Encoding.UTF8.GetString(Body);

    /// <summary>The value of the only field with this name (case-insensitive), or null.</summary>
    /// <param name="name">The field name.</param>
    /// <returns>The value, or null when absent.</returns>
    /// <exception cref="InvalidOperationException">The field appears more than once: a test that
    /// reads one value of a repeated field would check only part of what the server sent.</exception>
    public string? Field(string name) =>
        Fields.Where(f => string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase)).Select(f => f.Value).SingleOrDefault();
}

/// <summary>
/// A test's own HTTP/1.1 client on a plain socket. It sends exactly the octets a test writes
/// (malformed, pipelined, split byte by byte, half-closed) and reads responses with a strict
/// client's framing rules, so the server's output is checked on the wire rather than through
/// a forgiving client library that would repair or hide mistakes.
/// </summary>
/// <remarks>
/// Reads time out after the connection's timeout (a <see cref="SocketException"/>), so a server
/// that never answers fails the test instead of hanging the run. Only Content-Length bodies and
/// bodiless responses are read: the server's M1 answers always carry a length, and anything
/// else (chunked, close-delimited) throws, so a framing change shows up as a failure.
/// </remarks>
internal sealed class RawConnection : IDisposable
{
    /// <summary>The socket, connected to 127.0.0.1.</summary>
    private readonly Socket socket;

    /// <summary>Received octets; buffer[start..end) are not consumed yet.</summary>
    private byte[] buffer = new byte[65536];

    /// <summary>The first unconsumed octet.</summary>
    private int start;

    /// <summary>One past the last received octet.</summary>
    private int end;

    /// <summary>Connects to the server on 127.0.0.1.</summary>
    /// <param name="port">The server's port.</param>
    /// <param name="timeoutMs">How long a read may wait before it fails.</param>
    /// <param name="receiveBuffer">
    /// The socket's receive buffer, set before connecting (0: the kernel's default, which
    /// autotunes up to megabytes). A small one keeps a server's answer on the server's side
    /// while a test reads slowly: the kernel cannot take the whole answer at once.
    /// </param>
    /// <exception cref="SocketException">The connection was refused.</exception>
    public RawConnection(int port, int timeoutMs = 10000, int receiveBuffer = 0)
    {
        socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            // Each Send leaves at once: tests that split a request mean the split.
            NoDelay = true,
            ReceiveTimeout = timeoutMs,
            SendTimeout = timeoutMs,
        };
        if (receiveBuffer > 0)
        {
            socket.ReceiveBufferSize = receiveBuffer;   // before the connect: the window it offers
        }

        socket.Connect(IPAddress.Loopback, port);
    }

    /// <summary>
    /// Reads like a slow client: at most <paramref name="piece"/> octets at a time, pausing
    /// after each, until <paramref name="total"/> octets have come, the server closed (or reset)
    /// the connection, or a read timed out. Octets an earlier read buffered come first.
    /// </summary>
    /// <param name="total">The octets wanted.</param>
    /// <param name="piece">The most one read takes.</param>
    /// <param name="pauseMs">The pause after each read.</param>
    /// <returns>Every octet read, in order: fewer than <paramref name="total"/> when the
    /// connection ended first.</returns>
    public byte[] ReadSlowly(int total, int piece, int pauseMs)
    {
        var all = new MemoryStream(Math.Min(total, 1 << 20));       // total may be "to the end": int.MaxValue
        all.Write(buffer, start, end - start);
        start = end;
        byte[] chunk = new byte[piece];
        while (all.Length < total)
        {
            int n;
            try
            {
                n = socket.Receive(chunk, 0, (int)Math.Min(piece, total - all.Length), SocketFlags.None);
            }
            catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionReset or SocketError.TimedOut)
            {
                break;                      // the server is gone, or silent: what came is the answer
            }

            if (n == 0)
            {
                break;
            }

            all.Write(chunk, 0, n);
            Thread.Sleep(pauseMs);
        }

        return all.ToArray();
    }

    /// <summary>Sends text as Latin-1 octets (one octet per char).</summary>
    /// <param name="text">The octets to send.</param>
    /// <exception cref="SocketException">The connection failed.</exception>
    public void Send(string text) => Send(Encoding.Latin1.GetBytes(text));

    /// <summary>Sends octets, all of them.</summary>
    /// <param name="data">The octets.</param>
    /// <exception cref="SocketException">The connection failed.</exception>
    public void Send(ReadOnlySpan<byte> data)
    {
        while (!data.IsEmpty)
        {
            data = data[socket.Send(data)..];
        }
    }

    /// <summary>Half-closes: the server reads end-of-stream, and may still answer.</summary>
    public void ShutdownSend() => socket.Shutdown(SocketShutdown.Send);

    /// <summary>Reads one response.</summary>
    /// <param name="head">The request was HEAD: the response has no body, whatever its fields say.</param>
    /// <returns>The response.</returns>
    /// <exception cref="IOException">The server closed the connection before a whole response.</exception>
    /// <exception cref="FormatException">The status-line or a field line is malformed.</exception>
    /// <exception cref="NotSupportedException">The body is framed other than by Content-Length.</exception>
    /// <exception cref="SocketException">The read timed out, or the connection was reset.</exception>
    public RawResponse ReadResponse(bool head = false)
    {
        int headEnd;
        while ((headEnd = buffer.AsSpan(start, end - start).IndexOf("\r\n\r\n"u8)) < 0)
        {
            if (!Fill())
            {
                throw new IOException($"The server closed the connection after {end - start} octets of a response head.");
            }
        }

        string[] lines = Encoding.Latin1.GetString(buffer, start, headEnd).Split("\r\n");
        start += headEnd + 4;

        // status-line = HTTP-version SP status-code SP [ reason-phrase ]: the SP after the code
        // is required even with no reason (RFC9112-4-9#2), so a strict reader checks for it.
        string statusLine = lines[0];
        if (statusLine.Length < 13 || !statusLine.StartsWith("HTTP/1.1 ", StringComparison.Ordinal) || statusLine[12] != ' '
            || !int.TryParse(statusLine.AsSpan(9, 3), out int status))
        {
            throw new FormatException($"Not a status-line: \"{statusLine}\".");
        }

        var fields = new List<(string, string)>();
        foreach (string line in lines.Skip(1))
        {
            int colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                throw new FormatException($"Not a field line: \"{line}\".");
            }

            fields.Add((line[..colon], line[(colon + 1)..].Trim(' ', '\t')));
        }

        var response = new RawResponse(status, statusLine[13..], fields, []);
        if (head || status / 100 == 1 || status == 204 || status == 304)
        {
            return response;
        }

        if (response.Field("Transfer-Encoding") is not null)
        {
            throw new NotSupportedException("The response is chunked; HttpAsm's M1 server answers with Content-Length.");
        }

        string length = response.Field("Content-Length")
            ?? throw new NotSupportedException("The response has no Content-Length: its body would end at the close.");
        return response with { Body = ReadExactly(int.Parse(length, System.Globalization.CultureInfo.InvariantCulture)) };
    }

    /// <summary>
    /// Whether the server closed the connection: end-of-stream (or a reset) comes within the
    /// time, with no unread octet before it.
    /// </summary>
    /// <param name="timeoutMs">How long to wait for the close.</param>
    /// <returns>True when closed; false when octets came instead, or nothing within the time.</returns>
    public bool ServerClosed(int timeoutMs = 5000)
    {
        if (start < end)
        {
            return false;                   // a response (or garbage) the test did not read
        }

        int saved = socket.ReceiveTimeout;
        socket.ReceiveTimeout = timeoutMs;
        try
        {
            return !Fill();
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
        {
            return true;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.TimedOut)
        {
            return false;
        }
        finally
        {
            socket.ReceiveTimeout = saved;
        }
    }

    /// <summary>Whether nothing at all (no octet, no close) arrives for the given time.</summary>
    /// <param name="ms">How long to watch.</param>
    /// <returns>True when the connection stayed silent.</returns>
    public bool QuietFor(int ms) => start == end && !socket.Poll(ms * 1000, SelectMode.SelectRead);

    /// <summary>
    /// Resets the connection (SO_LINGER 0, then the close): the server sees RST - EPOLLERR or
    /// EPOLLHUP, a peer gone for good - where <see cref="Dispose"/>'s FIN is only the end of the
    /// peer's sending, after which the server may still answer.
    /// </summary>
    public void Abort()
    {
        socket.LingerState = new LingerOption(true, 0);
        socket.Close();
    }

    /// <summary>Closes the socket.</summary>
    public void Dispose() => socket.Dispose();

    /// <summary>Consumes exactly <paramref name="count"/> octets.</summary>
    /// <param name="count">How many.</param>
    /// <returns>The octets.</returns>
    /// <exception cref="IOException">The server closed the connection first.</exception>
    private byte[] ReadExactly(int count)
    {
        while (end - start < count)
        {
            if (!Fill())
            {
                throw new IOException($"The server closed the connection {count - (end - start)} octets before the body's end.");
            }
        }

        byte[] data = buffer.AsSpan(start, count).ToArray();
        start += count;
        return data;
    }

    /// <summary>Receives more octets into the buffer, compacting or growing it first when full.</summary>
    /// <returns>False at end-of-stream.</returns>
    /// <exception cref="SocketException">The read timed out, or the connection was reset.</exception>
    private bool Fill()
    {
        if (end == buffer.Length)
        {
            if (start > 0)
            {
                Buffer.BlockCopy(buffer, start, buffer, 0, end - start);
                end -= start;
                start = 0;
            }
            else
            {
                Array.Resize(ref buffer, buffer.Length * 2);
            }
        }

        int n = socket.Receive(buffer, end, buffer.Length - end, SocketFlags.None);
        end += n;
        return n > 0;
    }
}
