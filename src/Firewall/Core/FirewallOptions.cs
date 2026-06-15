namespace TheKrystalShip.KGSM.Firewall.Core;

/// <summary>
/// Host/runtime knobs for the authority. Kept minimal and read from the environment at composition
/// time, defaulting to the standard ufw locations.
/// </summary>
internal sealed class FirewallOptions
{
    public const string BackendEnvVar = "KGSM_FIREWALL_BACKEND";
    public const string UfwAppsDirEnvVar = "KGSM_FIREWALL_UFW_APPLICATIONS_DIR";
    public const string DefaultUfwApplicationsDirectory = "/etc/ufw/applications.d";

    /// <summary>Forced backend (the <c>KGSM_FIREWALL_BACKEND</c> override). Null = auto-detect.</summary>
    public FirewallBackend? BackendOverride { get; init; }

    /// <summary>Directory ufw reads application profiles from; where the authority writes/removes our
    /// <c>kgsm-&lt;instance&gt;</c> profiles.</summary>
    public string UfwApplicationsDirectory { get; init; } = DefaultUfwApplicationsDirectory;

    public static FirewallOptions FromEnvironment()
        => new()
        {
            BackendOverride = ParseBackend(Environment.GetEnvironmentVariable(BackendEnvVar)),
            UfwApplicationsDirectory =
                Environment.GetEnvironmentVariable(UfwAppsDirEnvVar) is { Length: > 0 } dir
                    ? dir
                    : DefaultUfwApplicationsDirectory,
        };

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
}
