using System.Net.Sockets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using TheKrystalShip.KGSM.Core.Models;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Events;
using TheKrystalShip.KGSM.Services;
using TheKrystalShip.KGSM.Lifecycle;

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

        // Detection answers "which firewall manages this host", which is not the same question as
        // "which one can this authority drive". ufw is the backend with a driver, and it is only
        // detected while it is ACTIVE — so a host with ufw installed but not enabled, or with none of
        // them, lands on a backend that reports every request unsupported. That is the honest outcome
        // and it stays, but it is worth saying out loud at boot: the alternative is a daemon that
        // starts cleanly and refuses the first port a server asks for, with the reason a request away.
        if (driver.Capabilities == FirewallCapabilities.None)
            boot.LogWarning(
                "detected backend {Backend}, which has no driver — every request will report unsupported and no "
                + "port will be opened. ufw is the backend this authority drives: enable it (systemctl enable "
                + "--now ufw) and it is detected automatically, or set Firewall__Backend=ufw to drive it "
                + "regardless of whether it is active", backend);
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
        // being told. The writer creates the directory as it is constructed — a reader discovers a
        // producer by finding its journal, so an authority that has simply changed nothing yet would
        // otherwise be indistinguishable from one that keeps no journal at all — and reports it if the
        // directory names a place no reader would attribute to this producer.
        var journalWriter = new EventJournalWriter(
            new EventJournalWriterOptions
            {
                Producer = FirewallOptions.JournalProducerId,
                Directory = options.EventJournalDirectory,
                ProducerVersion = ProducerVersion.Of(typeof(DaemonHost).Assembly),
            },
            loggers.CreateLogger<EventJournalWriter>());

        var journal = new FirewallJournal(journalWriter, loggers.CreateLogger<FirewallJournal>());

        // What this authority says about ITSELF, over the same writer.
        //
        // It reports degradation ONLY — no leaf_ready and no leaf_stopping. This daemon is socket
        // activated with a short idle window and woke 35 times in a measured day; a start and a stop
        // on each would be five times its whole journal's daily output, to report that a
        // socket-activated daemon did the one thing socket activation exists to make it do. Inactive
        // is its resting state, not a transition.
        // Seeded from this authority's own journal. It exits when idle and so remembers nothing
        // between wakes: without the seed it would re-report a standing fault on every one of the 35
        // wakes a measured day holds, and — worse — could never clear one, because the process that
        // sees the backend working again is not the process that saw it fail.
        var lifecycle = new LeafLifecycle(
            journalWriter,
            loggers.CreateLogger<LeafLifecycle>(),
            clock: null,
            startedAt: null,
            degraded: LeafState.DegradedComponents(options.EventJournalDirectory));

        using (listener)
        {
            var daemon = new FirewallDaemon(
                listener, service, journal, lifecycle, backend, idleTimeout,
                loggers.CreateLogger<FirewallDaemon>());
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
