using Microsoft.Extensions.Logging;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Firewall.Drivers.Ufw;

namespace TheKrystalShip.KGSM.Firewall.Host;

/// <summary>
/// Maps a detected <see cref="FirewallBackend"/> to its driver. Today only ufw has one; every other
/// backend (None, or the not-yet-implemented firewalld/nft/iptables) gets the
/// <see cref="NullFirewallDriver"/>, so the service always has a driver and degrades honestly rather than
/// crashing. Adding a backend is purely additive here (one switch arm) — the seam the whole design rests on.
/// </summary>
internal static class DriverFactory
{
    public static IFirewallDriver Create(
        FirewallBackend backend, FirewallOptions options, IProcessRunner runner, ILoggerFactory loggers)
        => backend switch
        {
            FirewallBackend.Ufw => new UfwDriver(
                runner,
                new FileUfwProfileStore(options.UfwApplicationsDirectory),
                loggers.CreateLogger<UfwDriver>()),
            _ => new NullFirewallDriver(backend),
        };
}
