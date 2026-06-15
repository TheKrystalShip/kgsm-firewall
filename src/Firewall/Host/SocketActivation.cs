using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace TheKrystalShip.KGSM.Firewall.Host;

/// <summary>
/// Acquires the daemon's listening unix socket, honouring the systemd socket-activation protocol
/// (<c>sd_listen_fds(3)</c>). Under activation systemd binds + listens on the socket itself, then starts
/// us with <c>LISTEN_PID</c>/<c>LISTEN_FDS</c> set and the socket as fd 3 — so a privileged helper need
/// not run 24/7 holding root; it wakes on the first connection. When not activated (a dev/manual run) we
/// bind the configured path ourselves.
/// </summary>
internal static class SocketActivation
{
    /// <summary>First file descriptor systemd passes (<c>SD_LISTEN_FDS_START</c>).</summary>
    private const int ListenFdsStart = 3;

    /// <summary>True if systemd handed us a listening socket meant for this process.</summary>
    public static bool IsActivated()
        => int.TryParse(Environment.GetEnvironmentVariable("LISTEN_PID"), out int pid)
           && pid == Environment.ProcessId
           && int.TryParse(Environment.GetEnvironmentVariable("LISTEN_FDS"), out int fds)
           && fds >= 1;

    /// <summary>
    /// Returns a ready-to-accept listening socket: the systemd-passed fd when activated, otherwise a
    /// freshly bound socket at <paramref name="fallbackPath"/>. The activation env vars are always
    /// cleared so they cannot leak into the <c>ufw</c> child we later spawn (which would make it
    /// mis-detect itself as socket-activated).
    /// </summary>
    public static Socket Acquire(string fallbackPath, ILogger logger)
    {
        bool activated = IsActivated();

        // Clear unconditionally: even on the fallback path a stale LISTEN_* (e.g. a confused parent)
        // must not be inherited by our children.
        Environment.SetEnvironmentVariable("LISTEN_PID", null);
        Environment.SetEnvironmentVariable("LISTEN_FDS", null);
        Environment.SetEnvironmentVariable("LISTEN_FDNAMES", null);

        if (activated)
        {
            // systemd already bound + listen()ed this socket; we adopt the fd and accept on it. Owning
            // the handle means it's closed on our shutdown — fine, systemd keeps the socket and re-spawns
            // us on the next connection.
            var handle = new SafeSocketHandle((nint)ListenFdsStart, ownsHandle: true);
            var socket = new Socket(handle);
            logger.LogInformation("Adopted systemd-activated socket (fd {Fd})", ListenFdsStart);
            return socket;
        }

        string? dir = Path.GetDirectoryName(fallbackPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        // A stale socket file from an unclean exit would make Bind fail with EADDRINUSE.
        if (File.Exists(fallbackPath))
            File.Delete(fallbackPath);

        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(fallbackPath));
        listener.Listen(128);
        logger.LogInformation("Bound control socket at {Path} (not socket-activated)", fallbackPath);
        return listener;
    }
}
