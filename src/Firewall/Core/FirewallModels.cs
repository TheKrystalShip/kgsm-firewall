namespace TheKrystalShip.KGSM.Firewall.Core;

/// <summary>
/// Which host-firewall backend the authority is driving. Detection precedence is
/// <c>active ufw/firewalld &gt; nft &gt; iptables &gt; none</c> — never poke the layer underneath an
/// active high-level manager.
/// </summary>
internal enum FirewallBackend
{
    None,
    Ufw,
    Firewalld,
    Nftables,
    Iptables,
}

/// <summary>
/// What a driver can honestly do. Backends are not equal: <see cref="FirewallBackend.None"/> applies
/// nothing; a raw nftables backend is awkward to <i>list</i>. A driver declares its capabilities so the
/// service degrades honestly instead of pretending — and so the kgsm-api <c>open</c> verdict is never
/// fabricated for a backend that genuinely cannot answer.
/// </summary>
internal sealed record FirewallCapabilities(bool CanApply, bool CanRemove, bool CanList)
{
    public static readonly FirewallCapabilities Full = new(true, true, true);
    public static readonly FirewallCapabilities None = new(false, false, false);
}

/// <summary>Outcome of an apply/remove operation.</summary>
internal enum FirewallStatus
{
    /// <summary>The requested rules are now open under our ownership tag.</summary>
    Applied,
    /// <summary>Our rules for the instance were torn down (or were already absent — idempotent).</summary>
    Removed,
    /// <summary>Nothing to do (e.g. an empty port set); completed as a no-op.</summary>
    NoOp,
    /// <summary>The active backend cannot perform this operation (its capabilities say so).</summary>
    Unsupported,
    /// <summary>The operation was attempted and failed (validation, or the backend command errored).</summary>
    Failed,
}

internal sealed record FirewallResult(FirewallStatus Status, string? Detail = null)
{
    public bool Ok => Status is FirewallStatus.Applied or FirewallStatus.Removed or FirewallStatus.NoOp;

    public static FirewallResult Applied(string? detail = null) => new(FirewallStatus.Applied, detail);
    public static FirewallResult Removed(string? detail = null) => new(FirewallStatus.Removed, detail);
    public static FirewallResult NoOp(string? detail = null) => new(FirewallStatus.NoOp, detail);
    public static FirewallResult Unsupported(string? detail = null) => new(FirewallStatus.Unsupported, detail);
    public static FirewallResult Failed(string detail) => new(FirewallStatus.Failed, detail);
}

/// <summary>
/// Honesty axis for a <c>ListOwned</c> query. <see cref="Unknown"/> is load-bearing: when a backend
/// genuinely cannot enumerate its rules, the authority returns Unknown — NEVER an empty list, which a
/// consumer would (correctly) read as "nothing open". kgsm-firewall is the only honest source for the
/// kgsm-api <c>open</c> verdict, so it must not fabricate <c>open:false</c>.
/// </summary>
internal enum OwnedQueryStatus
{
    Ok,
    Unknown,
    Unsupported,
}

/// <summary>The rules the authority owns for one instance (its <c>kgsm-&lt;instance&gt;</c> tag).</summary>
internal sealed record OwnedRule(string Instance, IReadOnlyList<PortSpec> Ports);

internal sealed record OwnedRulesResult(OwnedQueryStatus Status, IReadOnlyList<OwnedRule> Rules)
{
    public static OwnedRulesResult Ok(IReadOnlyList<OwnedRule> rules) => new(OwnedQueryStatus.Ok, rules);
    public static readonly OwnedRulesResult Unknown = new(OwnedQueryStatus.Unknown, []);
    public static readonly OwnedRulesResult Unsupported = new(OwnedQueryStatus.Unsupported, []);
}
