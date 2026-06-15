using Microsoft.Extensions.Logging;

namespace TheKrystalShip.KGSM.Firewall.Core;

/// <summary>
/// Picks the active host-firewall backend. An explicit <c>KGSM_FIREWALL_BACKEND</c> override (via
/// <see cref="FirewallOptions.BackendOverride"/>) wins; otherwise auto-detect with the precedence
/// <c>active ufw/firewalld &gt; raw nftables &gt; raw iptables &gt; none</c>. ufw and firewalld are
/// themselves frontends over nft/iptables, so when one is ACTIVE we drive it and never poke the layer
/// underneath it. The lower two tiers are mere presence ("raw") since they have no active-manager state.
/// </summary>
internal sealed class BackendDetector(IProcessRunner runner, ILogger<BackendDetector> logger)
{
    public async Task<FirewallBackend> DetectAsync(FirewallOptions options, CancellationToken ct = default)
    {
        if (options.BackendOverride is { } forced)
        {
            logger.LogInformation("Backend forced to {Backend} via {EnvVar}", forced, FirewallOptions.BackendEnvVar);
            return forced;
        }

        if (await IsUfwActiveAsync(ct).ConfigureAwait(false))
            return FirewallBackend.Ufw;
        if (await IsFirewalldActiveAsync(ct).ConfigureAwait(false))
            return FirewallBackend.Firewalld;
        if (await IsCommandPresentAsync("nft", ct).ConfigureAwait(false))
            return FirewallBackend.Nftables;
        if (await IsCommandPresentAsync("iptables", ct).ConfigureAwait(false))
            return FirewallBackend.Iptables;

        logger.LogWarning("No supported firewall backend detected on this host");
        return FirewallBackend.None;
    }

    private async Task<bool> IsUfwActiveAsync(CancellationToken ct)
    {
        // `ufw status` prints "Status: active" / "Status: inactive". The real status needs root; a
        // non-root run errors (non-zero) and is treated as "not the active manager from here".
        ProcessResult r = await runner.RunAsync("ufw", ["status"], ct).ConfigureAwait(false);
        return r.Ok && r.Stdout.Contains("Status: active", StringComparison.OrdinalIgnoreCase);
    }

    private async Task<bool> IsFirewalldActiveAsync(CancellationToken ct)
    {
        // `firewall-cmd --state` exits 0 and prints "running" when firewalld is up.
        ProcessResult r = await runner.RunAsync("firewall-cmd", ["--state"], ct).ConfigureAwait(false);
        return r.Ok && r.Stdout.Contains("running", StringComparison.OrdinalIgnoreCase);
    }

    private async Task<bool> IsCommandPresentAsync(string command, CancellationToken ct)
    {
        // Presence probe: if `<command> --version` launches at all (even non-zero), the binary exists
        // on PATH. A launch failure (NoExitCode) means it is absent.
        ProcessResult r = await runner.RunAsync(command, ["--version"], ct).ConfigureAwait(false);
        return r.HasExitCode;
    }
}
