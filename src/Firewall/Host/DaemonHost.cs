using System.Net.Sockets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using TheKrystalShip.KGSM.Core.Models;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Services;

namespace TheKrystalShip.KGSM.Firewall.Host;

/// <summary>
/// Composition root for the daemon (<c>serve</c>): builds the object graph by hand (no DI container — the
/// helper carries no hosting stack), runs backend detection daemon-side (a privileged read the
/// unprivileged client could not do), then serves until the cancellation token fires (SIGTERM/SIGINT).
/// </summary>
internal static class DaemonHost
{
    public static async Task<int> RunAsync(FirewallOptions options, IConfiguration configuration, CancellationToken ct)
    {
        using ILoggerFactory loggers = BuildLoggerFactory(configuration);
        ILogger boot = loggers.CreateLogger("kgsm-firewall");

        // Surface Firewall__* vars naming no declared key (they otherwise bind to nothing, silently).
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

        // This authority's own event journal. The producer id is this daemon's state-directory name,
        // which is what a reader scans for, so writer and readers agree on the location without either
        // being told. Created up front rather than on the first edge: a reader discovers a producer by
        // finding its journal, so an authority that has simply changed nothing yet would otherwise be
        // indistinguishable from one that keeps no journal at all.
        var journalWriter = new EventJournalWriter(
            new EventJournalWriterOptions
            {
                Producer = "kgsm-firewall",
                Directory = options.EventJournalDirectory,
                ProducerVersion = typeof(DaemonHost).Assembly.GetName().Version?.ToString(),
            },
            loggers.CreateLogger<EventJournalWriter>());

        try
        {
            Directory.CreateDirectory(options.EventJournalDirectory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Not fatal: the writer retries on every append and says so if it still cannot.
            boot.LogWarning(ex, "could not create the event journal directory {Dir}", options.EventJournalDirectory);
        }

        var journal = new FirewallJournal(journalWriter, loggers.CreateLogger<FirewallJournal>());

        using (listener)
        {
            var daemon = new FirewallDaemon(listener, service, journal, backend, idleTimeout, loggers.CreateLogger<FirewallDaemon>());
            await daemon.RunAsync(ct).ConfigureAwait(false);
        }
        return 0;
    }

    /// <summary>
    /// Ecosystem-standard logging: a single journald-native <c>SystemdConsole</c> sink at <c>Information</c>
    /// by default, with levels taken from <c>kgsm-firewall.settings.json</c> (<c>Logging:LogLevel</c>) and,
    /// above it, environment variables (<c>Logging__LogLevel__Default=Debug</c>). The Systemd formatter
    /// emits <c>&lt;N&gt;</c> syslog priority prefixes so <c>journalctl -p</c> can filter by level, and omits
    /// the timestamp/colour journald already supplies. No DI container/host — just the bare
    /// <see cref="LoggerFactory"/>. See <c>../tks/logging-convention.md</c>.
    /// </summary>
    /// <remarks>
    /// The configuration is handed in rather than rebuilt here, so the levels come from the same stack,
    /// in the same order, as every other knob — a second builder is a second chance to disagree.
    /// </remarks>
    private static ILoggerFactory BuildLoggerFactory(IConfiguration configuration)
    {
        return LoggerFactory.Create(builder =>
        {
            builder.AddConfiguration(configuration.GetSection("Logging"));
            builder.SetMinimumLevel(LogLevel.Information);
            builder.AddSystemdConsole();
        });
    }
}
