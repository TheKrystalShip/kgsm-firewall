namespace TheKrystalShip.KGSM.Firewall.Core;

/// <summary>
/// The honest-degradation driver used when no backend driver exists for the detected backend (None, or a
/// backend like firewalld/nftables/iptables whose driver is not yet implemented). It reports the detected
/// <see cref="Backend"/> truthfully, declares <see cref="FirewallCapabilities.None"/>, and answers every
/// operation as Unsupported / Unknown — never a fabricated success or a fabricated "nothing open". This
/// is what lets the service degrade honestly instead of pretending, and keeps the kgsm-api <c>open</c>
/// verdict unfabricated when the host has no driveable firewall.
/// </summary>
internal sealed class NullFirewallDriver(FirewallBackend backend) : IFirewallDriver
{
    public FirewallBackend Backend => backend;
    public FirewallCapabilities Capabilities => FirewallCapabilities.None;

    public Task<FirewallResult> EnsureOpenAsync(
        string instance, IReadOnlyList<PortSpec> ports, CancellationToken ct = default)
        => Task.FromResult(FirewallResult.Unsupported($"no firewall driver for backend {backend}"));

    public Task<FirewallResult> RemoveAsync(string instance, CancellationToken ct = default)
        => Task.FromResult(FirewallResult.Unsupported($"no firewall driver for backend {backend}"));

    public Task<OwnedRulesResult> ListOwnedAsync(string? instance = null, CancellationToken ct = default)
        => Task.FromResult(OwnedRulesResult.Unsupported);
}
