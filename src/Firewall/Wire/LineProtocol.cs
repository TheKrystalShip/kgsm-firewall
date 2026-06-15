using System.Net.Sockets;
using System.Text;

namespace TheKrystalShip.KGSM.Firewall.Wire;

/// <summary>
/// The newline framing shared by the daemon and the bundled client: exactly one JSON line per
/// direction. A reader stops at the first <c>'\n'</c> or at EOF (so a client may either terminate its
/// request with a newline or half-close its send side). Reads are bounded — this is a root daemon
/// reading a socket, so an unbounded line is a denial-of-service hole, not a convenience.
/// </summary>
internal static class LineProtocol
{
    /// <summary>Default cap on a single request/response line (64 KiB — orders of magnitude above any
    /// real firewall request, which is a handful of ports).</summary>
    public const int DefaultMaxBytes = 64 * 1024;

    /// <summary>
    /// Read one line (UTF-8, newline- or EOF-terminated, trailing <c>'\r'</c> trimmed) from the socket,
    /// up to <paramref name="maxBytes"/>. Returns null if the peer sent nothing before closing. Throws
    /// <see cref="InvalidDataException"/> if the cap is exceeded before a newline arrives.
    /// </summary>
    public static async Task<string?> ReadLineAsync(Socket socket, int maxBytes, CancellationToken ct)
    {
        var rented = new byte[4096];
        using var acc = new MemoryStream();

        while (true)
        {
            int n = await socket.ReceiveAsync(rented, ct).ConfigureAwait(false);
            if (n == 0) break; // EOF

            int nl = Array.IndexOf(rented, (byte)'\n', 0, n);
            int take = nl >= 0 ? nl : n;
            if (acc.Length + take > maxBytes)
                throw new InvalidDataException($"request exceeded {maxBytes} bytes");
            acc.Write(rented, 0, take);
            if (nl >= 0) break; // newline reached — line complete
        }

        if (acc.Length == 0) return null;
        string line = Encoding.UTF8.GetString(acc.GetBuffer(), 0, (int)acc.Length);
        return line.EndsWith('\r') ? line[..^1] : line;
    }

    /// <summary>Write a line (the given UTF-8 payload followed by a single <c>'\n'</c>) to the socket.</summary>
    public static async Task WriteLineAsync(Socket socket, byte[] payload, CancellationToken ct)
    {
        await socket.SendAsync(payload, ct).ConfigureAwait(false);
        await socket.SendAsync(Newline, ct).ConfigureAwait(false);
    }

    private static readonly byte[] Newline = "\n"u8.ToArray();
}
