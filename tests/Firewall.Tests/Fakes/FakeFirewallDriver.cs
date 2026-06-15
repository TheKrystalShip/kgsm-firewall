using TheKrystalShip.KGSM.Firewall.Core;

namespace TheKrystalShip.KGSM.Firewall.Tests.Fakes;

/// <summary>Records dispatch and returns canned results, so <see cref="FirewallService"/> tests can
/// assert validation/capability gating independently of any real backend.</summary>
internal sealed class FakeFirewallDriver : IFirewallDriver
{
    public FirewallBackend Backend { get; init; } = FirewallBackend.Ufw;
    public FirewallCapabilities Capabilities { get; set; } = FirewallCapabilities.Full;

    public int EnsureOpenCalls { get; private set; }
    public int RemoveCalls { get; private set; }
    public int ListCalls { get; private set; }

    public FirewallResult EnsureResult { get; set; } = FirewallResult.Applied();
    public FirewallResult RemoveResult { get; set; } = FirewallResult.Removed();
    public OwnedRulesResult ListResult { get; set; } = OwnedRulesResult.Ok([]);

    public Task<FirewallResult> EnsureOpenAsync(
        string instance, IReadOnlyList<PortSpec> ports, CancellationToken ct = default)
    {
        EnsureOpenCalls++;
        return Task.FromResult(EnsureResult);
    }

    public Task<FirewallResult> RemoveAsync(string instance, CancellationToken ct = default)
    {
        RemoveCalls++;
        return Task.FromResult(RemoveResult);
    }

    public Task<OwnedRulesResult> ListOwnedAsync(string? instance = null, CancellationToken ct = default)
    {
        ListCalls++;
        return Task.FromResult(ListResult);
    }
}
