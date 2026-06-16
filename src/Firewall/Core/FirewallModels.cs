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
    /// <summary>The requested rules are now open under our ownership tag, and the backend is enforcing.</summary>
    Applied,
    /// <summary>The rules were written/staged, but the backend is NOT enforcing (e.g. ufw inactive): they
    /// persist and take effect on the operator's next <c>ufw enable</c>; meanwhile the port is open anyway
    /// (nothing is filtering). A SUCCESS, distinct from <see cref="Applied"/> so the caller can say "staged,
    /// not yet enforced".</summary>
    AppliedInactive,
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
    public bool Ok => Status is FirewallStatus.Applied or FirewallStatus.AppliedInactive
        or FirewallStatus.Removed or FirewallStatus.NoOp;

    public static FirewallResult Applied(string? detail = null) => new(FirewallStatus.Applied, detail);
    public static FirewallResult AppliedInactive(string? detail = null) => new(FirewallStatus.AppliedInactive, detail);
    public static FirewallResult Removed(string? detail = null) => new(FirewallStatus.Removed, detail);
    public static FirewallResult NoOp(string? detail = null) => new(FirewallStatus.NoOp, detail);
    public static FirewallResult Unsupported(string? detail = null) => new(FirewallStatus.Unsupported, detail);
    public static FirewallResult Failed(string detail) => new(FirewallStatus.Failed, detail);
}

/// <summary>
/// The backend's runtime <b>enforcement</b> state — orthogonal to "are there rules". A backend can be
/// installed yet not filtering (ufw disabled), in which case it blocks NOTHING, so every port is
/// reachable regardless of owned rules. The authority reports this so the consumer (kgsm-api) computes an
/// honest <c>open</c> verdict and never reads an inactive firewall as "closed".
/// </summary>
internal enum Enforcement
{
    /// <summary>The backend is active and filtering — owned rules determine open/closed.</summary>
    Enforcing,
    /// <summary>Installed but not enforcing (e.g. <c>ufw</c> inactive) — nothing is filtered, all ports open.</summary>
    Inactive,
    /// <summary>Cannot determine (non-root / backend absent / status unparsable) — honest unknown.</summary>
    Unknown,
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

/// <summary>
/// A <c>ListOwned</c> result: the query <see cref="Status"/>, the enumerated <see cref="Rules"/>, and the
/// backend's <see cref="Enforcement"/> state. Enforcement is load-bearing for the consumer's <c>open</c>
/// verdict and is independent of the rule set (an inactive backend has nothing in its active set yet leaves
/// every port open). A "can't enumerate" result (<see cref="Unknown"/>/<see cref="Unsupported"/>) carries
/// <see cref="Enforcement.Unknown"/> — we don't know the rules nor the enforcement.
/// </summary>
internal sealed record OwnedRulesResult(
    OwnedQueryStatus Status, IReadOnlyList<OwnedRule> Rules, Enforcement Enforcement = Enforcement.Unknown)
{
    // Default Enforcing = the legacy "enumerated rules from an active firewall" case; the ufw driver passes
    // the live-detected enforcement explicitly. Keeps non-driver callers (tests/fakes) terse.
    public static OwnedRulesResult Ok(
        IReadOnlyList<OwnedRule> rules, Enforcement enforcement = Enforcement.Enforcing) =>
        new(OwnedQueryStatus.Ok, rules, enforcement);
    public static readonly OwnedRulesResult Unknown = new(OwnedQueryStatus.Unknown, [], Enforcement.Unknown);
    public static readonly OwnedRulesResult Unsupported = new(OwnedQueryStatus.Unsupported, [], Enforcement.Unknown);
}
