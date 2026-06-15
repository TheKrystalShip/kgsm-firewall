using System.Text;

namespace TheKrystalShip.KGSM.Firewall.Core;

/// <summary>
/// Host/runtime knobs for the authority, read from the environment at composition time. Kept minimal and
/// defaulting to the standard ufw + systemd-runtime locations. The full list is self-documenting via
/// <see cref="DescribeEnvironment"/> (printed by <c>kgsm-firewall --help</c>), so an operator with only
/// the binary can discover every knob — the same convention as kgsm-watchdog.
/// </summary>
internal sealed class FirewallOptions
{
    public const string BackendEnvVar = "KGSM_FIREWALL_BACKEND";
    public const string UfwAppsDirEnvVar = "KGSM_FIREWALL_UFW_APPLICATIONS_DIR";
    public const string SocketEnvVar = "KGSM_FIREWALL_SOCKET";
    public const string IdleTimeoutEnvVar = "KGSM_FIREWALL_IDLE_TIMEOUT";

    public const string DefaultUfwApplicationsDirectory = "/etc/ufw/applications.d";
    public const string DefaultSocketPath = "/run/kgsm-firewall/firewall.sock";

    /// <summary>How long the (socket-activated) daemon stays resident with no connections before exiting,
    /// so systemd re-activates it on demand rather than holding root 24/7. A "short time" by default.</summary>
    public const int DefaultIdleTimeoutSeconds = 30;

    /// <summary>Smallest non-zero idle window honoured; a smaller positive value is clamped up to this so a
    /// fat-fingered tiny timeout can't make the daemon flap (start/idle-exit/start). 0 stays 0 (resident).</summary>
    public const int MinIdleTimeoutSeconds = 5;

    /// <summary>All recognised env vars — used to flag typo'd <c>KGSM_FIREWALL_*</c> settings.</summary>
    private static readonly string[] KnownEnvVars = [BackendEnvVar, UfwAppsDirEnvVar, SocketEnvVar, IdleTimeoutEnvVar];

    /// <summary>Forced backend (the <c>KGSM_FIREWALL_BACKEND</c> override). Null = auto-detect.</summary>
    public FirewallBackend? BackendOverride { get; init; }

    /// <summary>Directory ufw reads application profiles from; where the authority writes/removes our
    /// <c>kgsm-&lt;instance&gt;</c> profiles.</summary>
    public string UfwApplicationsDirectory { get; init; } = DefaultUfwApplicationsDirectory;

    /// <summary>Control socket the daemon listens on / the client connects to. Under systemd socket
    /// activation the daemon adopts systemd's socket and this path is what the <c>.socket</c> unit binds;
    /// the bundled client always connects here.</summary>
    public string SocketPath { get; init; } = DefaultSocketPath;

    /// <summary>Idle window before the daemon exits to be re-activated on demand. <see cref="TimeSpan.Zero"/>
    /// disables idle-exit (the daemon stays resident). Only honoured under systemd socket activation — see
    /// <see cref="Host.DaemonHost"/>; with nothing to re-spawn it, a manual run always stays resident.</summary>
    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromSeconds(DefaultIdleTimeoutSeconds);

    public static FirewallOptions FromEnvironment()
        => new()
        {
            BackendOverride = ParseBackend(Environment.GetEnvironmentVariable(BackendEnvVar)),
            UfwApplicationsDirectory = ReadOr(UfwAppsDirEnvVar, DefaultUfwApplicationsDirectory),
            SocketPath = ReadOr(SocketEnvVar, DefaultSocketPath),
            IdleTimeout = ParseIdleTimeout(Environment.GetEnvironmentVariable(IdleTimeoutEnvVar)),
        };

    private static string ReadOr(string envVar, string fallback)
        => Environment.GetEnvironmentVariable(envVar) is { Length: > 0 } v ? v : fallback;

    /// <summary>Parse the idle-timeout knob (whole seconds). Unset/non-numeric/negative → the default;
    /// <c>0</c> → resident (disabled); a positive value below <see cref="MinIdleTimeoutSeconds"/> is
    /// clamped up to that floor.</summary>
    public static TimeSpan ParseIdleTimeout(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || !int.TryParse(raw.Trim(), out int seconds) || seconds < 0)
            return TimeSpan.FromSeconds(DefaultIdleTimeoutSeconds);
        if (seconds == 0)
            return TimeSpan.Zero;
        return TimeSpan.FromSeconds(Math.Max(seconds, MinIdleTimeoutSeconds));
    }

    /// <summary>Parse a backend name (AOT-safe explicit switch — no <c>Enum.TryParse</c> reflection).</summary>
    public static FirewallBackend? ParseBackend(string? raw)
        => raw?.Trim().ToLowerInvariant() switch
        {
            "none" => FirewallBackend.None,
            "ufw" => FirewallBackend.Ufw,
            "firewalld" => FirewallBackend.Firewalld,
            "nftables" or "nft" => FirewallBackend.Nftables,
            "iptables" => FirewallBackend.Iptables,
            _ => null,
        };

    /// <summary>Set <c>KGSM_FIREWALL_*</c> vars that are not recognised (likely typos) — surfaced as a
    /// startup warning so a misspelled knob is visible rather than silently ignored.</summary>
    public static IEnumerable<string> UnknownConfigVars()
    {
        foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
        {
            if (e.Key is string key && key.StartsWith("KGSM_FIREWALL_", StringComparison.Ordinal)
                && Array.IndexOf(KnownEnvVars, key) < 0)
                yield return key;
        }
    }

    public static string DescribeEnvironment()
    {
        var sb = new StringBuilder();
        sb.AppendLine("kgsm-firewall — the KGSM host-firewall authority.");
        sb.AppendLine();
        sb.AppendLine("Usage:");
        sb.AppendLine("  kgsm-firewall serve                              run the daemon (or be socket-activated)");
        sb.AppendLine("  kgsm-firewall ensure-open <instance> <port>...   open ports (e.g. 34197/udp 27015:27020/tcp)");
        sb.AppendLine("  kgsm-firewall remove <instance>                  close all ports owned for an instance");
        sb.AppendLine("  kgsm-firewall list [instance]                    list owned rules (all, or one instance)");
        sb.AppendLine("  kgsm-firewall backend                            report the active backend + capabilities");
        sb.AppendLine();
        sb.AppendLine("Environment:");
        sb.AppendLine($"  {SocketEnvVar}");
        sb.AppendLine($"      Control socket path. Default: {DefaultSocketPath}");
        sb.AppendLine($"  {BackendEnvVar}");
        sb.AppendLine("      Force the backend (none|ufw|firewalld|nftables|iptables). Default: auto-detect.");
        sb.AppendLine($"  {UfwAppsDirEnvVar}");
        sb.AppendLine($"      ufw application-profiles directory. Default: {DefaultUfwApplicationsDirectory}");
        sb.AppendLine($"  {IdleTimeoutEnvVar}");
        sb.AppendLine("      Seconds the socket-activated daemon stays idle (no connections) before exiting;");
        sb.AppendLine($"      systemd re-activates it on the next request. 0 = stay resident. A positive value");
        sb.AppendLine($"      below {MinIdleTimeoutSeconds}s is clamped to {MinIdleTimeoutSeconds}s. Ignored when not socket-activated. Default: {DefaultIdleTimeoutSeconds}");
        return sb.ToString();
    }
}
