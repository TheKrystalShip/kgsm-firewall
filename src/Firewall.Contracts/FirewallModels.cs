namespace TheKrystalShip.KGSM.Firewall.Contracts;

// What the firewall client reports. These are mapped in code from the wire DTOs at the client boundary and
// preserve the authority's precise outcome, never collapsing it to a bare success flag: "the backend cannot
// answer" is a different fact from "nothing is open".

/// <summary>
/// The precise outcome of an ensure-open / remove operation, mapped from the authority's wire token.
/// Distinct from the coarse <see cref="FirewallActionResult.Ok"/> bit so a caller can tell an applied
/// change from a no-op, and an unsupported backend from an outright failure.
/// </summary>
public enum FirewallOutcome
{
    /// <summary>The rule was applied and the backend is enforcing (the ports are now open for the instance).</summary>
    Applied,

    /// <summary>The rule was written/staged, but the backend is NOT enforcing (e.g. ufw inactive): it
    /// persists and takes effect on the operator's next <c>ufw enable</c>, and meanwhile the port is open
    /// anyway (nothing is filtering). A success — distinct from <see cref="Applied"/> so a caller can say
    /// "staged, not yet enforced" rather than imply an enforced open (Firewall.Contracts 1.1.0).</summary>
    AppliedInactive,

    /// <summary>The instance's rules were removed.</summary>
    Removed,

    /// <summary>Nothing to do — the desired state already held (e.g. ensure-open with no ports).</summary>
    NoOp,

    /// <summary>A read/query succeeded (used on the backend op; not an apply/remove result).</summary>
    Ok,

    /// <summary>The backend genuinely cannot answer — honest unknown, never a guessed empty/false.</summary>
    Unknown,

    /// <summary>The active backend does not support the operation (e.g. no firewall, or a read-only driver).</summary>
    Unsupported,

    /// <summary>The operation reached the backend but failed (e.g. ufw rejected the rule).</summary>
    Failed,
}

/// <summary>
/// Whether the authority could enumerate the rules it owns. <see cref="Unknown"/> is the honest "the
/// backend cannot tell" — it must never be read as "nothing is open" (that is the difference between a
/// measured empty set and an unanswerable query).
/// </summary>
public enum FirewallListStatus
{
    /// <summary>The backend enumerated its owned rules (the set may legitimately be empty).</summary>
    Ok,

    /// <summary>The backend genuinely cannot enumerate rules — honest unknown, not an empty set.</summary>
    Unknown,

    /// <summary>The active backend does not support listing.</summary>
    Unsupported,
}

/// <summary>
/// Result of an ensure-open / remove operation against the firewall authority. <see cref="Ok"/> is the
/// coarse success bit; <see cref="Outcome"/> carries the precise status. A transport failure (the
/// authority is unreachable) does not produce a result — it throws
/// <see cref="Exceptions.FirewallException"/>, mirroring the unreachable-vs-rejected split in the
/// authority's exit-code contract.
/// </summary>
public sealed record FirewallActionResult
{
    /// <summary>Coarse success bit (true for applied/removed/noop).</summary>
    public bool Ok { get; init; }

    /// <summary>The precise outcome token, mapped from the authority's reply.</summary>
    public FirewallOutcome Outcome { get; init; }

    /// <summary>The active backend (e.g. <c>"ufw"</c>, <c>"none"</c>).</summary>
    public string Backend { get; init; } = string.Empty;

    /// <summary>Human-readable detail from the authority, when present.</summary>
    public string? Detail { get; init; }
}

/// <summary>
/// The backend's runtime <b>enforcement</b> state (Firewall.Contracts 1.1.0), orthogonal to whether any
/// rules exist. A backend can be installed yet <see cref="Inactive"/> (e.g. ufw disabled), in which case
/// it filters NOTHING — so every port is reachable regardless of rules. A consumer computing an honest
/// "is this port open" verdict needs this: <see cref="Enforcing"/> → open iff a rule allows it;
/// <see cref="Inactive"/> → open (all, unfiltered); <see cref="Unknown"/> → unknown. NEVER read an
/// inactive backend's empty rule set as "closed".
/// </summary>
public enum FirewallEnforcement
{
    /// <summary>The backend is active and filtering — owned rules determine open/closed.</summary>
    Enforcing,

    /// <summary>Installed but not enforcing (e.g. <c>ufw</c> inactive) — nothing filtered, all ports open.</summary>
    Inactive,

    /// <summary>Cannot determine (non-root / backend absent / unparsable), OR a pre-1.1.0 authority that
    /// does not report enforcement — honest unknown; a consumer should fall back to its prior behaviour.</summary>
    Unknown,
}

/// <summary>The ports the authority owns for one instance, as ranges.</summary>
public sealed record FirewallOwnedRule(string Instance, IReadOnlyList<PortDto> Ports);

/// <summary>
/// Result of a list-owned query. <see cref="Status"/> distinguishes a measured result (<see cref="Rules"/>
/// is authoritative, possibly empty) from an honest <see cref="FirewallListStatus.Unknown"/>
/// (<see cref="Rules"/> is empty because the backend could not answer — never a fabricated "nothing open").
/// </summary>
public sealed record FirewallListResult
{
    /// <summary>Whether the rules could be enumerated (<see cref="FirewallListStatus.Unknown"/> ≠ empty).</summary>
    public FirewallListStatus Status { get; init; }

    /// <summary>The owned rules. Authoritative only when <see cref="Status"/> is
    /// <see cref="FirewallListStatus.Ok"/>; empty otherwise.</summary>
    public IReadOnlyList<FirewallOwnedRule> Rules { get; init; } = [];

    /// <summary>The backend's enforcement state (Firewall.Contracts 1.1.0). Load-bearing for an honest
    /// open verdict: when <see cref="FirewallEnforcement.Inactive"/>, the empty/partial rule set must NOT
    /// be read as "closed" — nothing is filtering, so every port is open. A pre-1.1.0 authority (no
    /// enforcement on the wire) maps to <see cref="FirewallEnforcement.Unknown"/>.</summary>
    public FirewallEnforcement Enforcement { get; init; } = FirewallEnforcement.Unknown;
}

/// <summary>
/// The active backend and what it can honestly do — the capabilities the authority reports for the
/// detected backend (e.g. a present-but-read-only driver reports <c>CanApply == false</c>).
/// </summary>
public sealed record FirewallBackendInfo
{
    /// <summary>The detected backend token (e.g. <c>"ufw"</c>, <c>"nftables"</c>, <c>"none"</c>).</summary>
    public string Backend { get; init; } = string.Empty;

    /// <summary>Whether the backend can apply (open) rules.</summary>
    public bool CanApply { get; init; }

    /// <summary>Whether the backend can remove rules.</summary>
    public bool CanRemove { get; init; }

    /// <summary>Whether the backend can enumerate the rules it owns.</summary>
    public bool CanList { get; init; }
}
