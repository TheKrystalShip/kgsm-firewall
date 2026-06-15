using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using TheKrystalShip.KGSM.Firewall.Core;

namespace TheKrystalShip.KGSM.Firewall.Host;

/// <summary>
/// Composition root for the daemon (<c>serve</c>): builds the object graph by hand (no DI container — the
/// helper carries no hosting stack), runs backend detection daemon-side (a privileged read the
/// unprivileged client could not do), then serves until the cancellation token fires (SIGTERM/SIGINT).
/// </summary>
internal static class DaemonHost
{
    public static async Task<int> RunAsync(FirewallOptions options, CancellationToken ct)
    {
        var loggers = new StderrLoggerFactory(LogLevel.Information);
        ILogger boot = loggers.CreateLogger("kgsm-firewall");

        // Surface typo'd KGSM_FIREWALL_* vars (they otherwise silently fall back to defaults).
        foreach (string v in FirewallOptions.UnknownConfigVars())
            boot.LogWarning("unrecognised config variable {Var} is set but has no effect (typo?)", v);

        var runner = new ProcessRunner(loggers.CreateLogger<ProcessRunner>());
        var detector = new BackendDetector(runner, loggers.CreateLogger<BackendDetector>());
        FirewallBackend backend = await detector.DetectAsync(options, ct).ConfigureAwait(false);
        IFirewallDriver driver = DriverFactory.Create(backend, options, runner, loggers);
        var service = new FirewallService(driver, loggers.CreateLogger<FirewallService>());

        // Idle-exit only makes sense under socket activation, where systemd re-spawns us on the next
        // connection; a manual/dev run has nothing to bring it back, so it stays resident. Read this
        // BEFORE Acquire(), which clears the LISTEN_* env vars that IsActivated() inspects.
        bool activated = SocketActivation.IsActivated();
        TimeSpan idleTimeout = activated ? options.IdleTimeout : TimeSpan.Zero;
        if (!activated && options.IdleTimeout > TimeSpan.Zero)
            boot.LogInformation("idle-exit disabled: not socket-activated, so nothing would re-spawn the daemon — staying resident");

        Socket listener;
        try
        {
            listener = SocketActivation.Acquire(options.SocketPath, loggers.CreateLogger("SocketActivation"));
        }
        catch (Exception ex)
        {
            boot.LogError(ex, "could not acquire control socket {Path}", options.SocketPath);
            return 1;
        }

        using (listener)
        {
            var daemon = new FirewallDaemon(listener, service, backend, idleTimeout, loggers.CreateLogger<FirewallDaemon>());
            await daemon.RunAsync(ct).ConfigureAwait(false);
        }
        return 0;
    }
}
