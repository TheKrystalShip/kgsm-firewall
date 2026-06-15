namespace TheKrystalShip.KGSM.Firewall.Core;

/// <summary>
/// The firewall-agnostic driver seam. The contract speaks in DOMAIN terms, declaratively — "this
/// instance's port set should be open" — not "add this iptables rule". Each backend (ufw, firewalld,
/// nftables, iptables) implements this and maps it onto its own natural per-instance grouping
/// (ufw: an application profile <c>kgsm-&lt;instance&gt;</c>; firewalld: a zone/service; nft: a
/// per-instance chain/set; iptables: a chain). Three rules every driver honors:
/// <list type="number">
/// <item>OWNERSHIP TAGGING — every rule is namespaced <c>kgsm-&lt;instance&gt;</c> so list/remove touch
/// only what we created, never the operator's own firewall config.</item>
/// <item>CAPABILITY DECLARATION — backends differ; <see cref="Capabilities"/> states what this one can do.</item>
/// <item>HONEST UNKNOWN — <see cref="ListOwnedAsync"/> returns <see cref="OwnedQueryStatus.Unknown"/>
/// rather than a guessed empty list when it cannot answer.</item>
/// </list>
/// Validation (port/proto/instance-name) happens in the service core BEFORE the driver runs, so a
/// driver may assume its inputs are already well-formed.
/// </summary>
internal interface IFirewallDriver
{
    FirewallBackend Backend { get; }

    FirewallCapabilities Capabilities { get; }

    /// <summary>Make exactly <paramref name="ports"/> open under our ownership tag for the instance.
    /// Idempotent: re-applying converges to the same state.</summary>
    Task<FirewallResult> EnsureOpenAsync(
        string instance, IReadOnlyList<PortSpec> ports, CancellationToken ct = default);

    /// <summary>Tear down everything WE own for the instance. Idempotent (removing nothing succeeds).</summary>
    Task<FirewallResult> RemoveAsync(string instance, CancellationToken ct = default);

    /// <summary>What we currently have open — for one instance, or all of ours when
    /// <paramref name="instance"/> is null. Feeds the kgsm-api <c>open</c> / <c>open_ports[]</c> view.</summary>
    Task<OwnedRulesResult> ListOwnedAsync(string? instance = null, CancellationToken ct = default);
}
