namespace TheKrystalShip.KGSM.Firewall.Contracts;

/// <summary>
/// The control-socket request/response DTOs and op tokens. The transport is one
/// newline-delimited JSON request → one newline-delimited JSON response over a unix domain socket
/// (see <see cref="LineProtocol"/>). This is deliberately NOT HTTP: the authority carries no ASP.NET
/// stack (a privileged helper shouldn't), and a tiny private protocol is enough.
/// <para>
/// These types are the <b>public</b> wire contract shared by both speakers: the kgsm-firewall daemon
/// (server) and kgsm-lib's <c>IFirewallService</c> (client) consume this one package, so the shapes
/// cannot drift. They carry NO kgsm-lib <c>PortMapping</c> reference — this package owns its own
/// <see cref="PortDto"/>; kgsm-lib maps <c>PortMapping</c>↔<see cref="PortDto"/> at its boundary. Wire
/// collections are arrays (the most AOT-/source-gen-friendly shape); a domain's <c>IReadOnlyList</c> is
/// mapped at each boundary.
/// </para>
/// </summary>
public static class FirewallOps
{
    public const string EnsureOpen = "ensure-open";
    public const string Remove = "remove";
    public const string List = "list";
    public const string Backend = "backend";
}

/// <summary>Outcome tokens carried in <see cref="FirewallResponse.Outcome"/> — the union of the domain's
/// apply/remove statuses and the list query statuses, flattened for the wire.</summary>
public static class Outcomes
{
    public const string Applied = "applied";
    /// <summary>The rule was written/staged, but the backend is NOT enforcing (e.g. ufw inactive): the
    /// rule persists and takes effect on the operator's next <c>ufw enable</c>, and meanwhile the port is
    /// open anyway because nothing is filtering. A success (the desired config is in place) — distinct from
    /// <see cref="Applied"/> so the caller can say "staged, not yet enforced" honestly.</summary>
    public const string AppliedInactive = "applied-inactive";
    public const string Removed = "removed";
    public const string NoOp = "noop";
    public const string Ok = "ok";            // a successful read/backend query
    public const string Unknown = "unknown";  // list: backend genuinely cannot answer (honest unknown)
    public const string Unsupported = "unsupported";
    public const string Failed = "failed";
}

/// <summary>
/// The backend's runtime <b>enforcement</b> state, carried in <see cref="FirewallResponse.Enforcement"/>
/// (added in 1.1.0; null on a pre-1.1.0 daemon → the client reads it as <see cref="Unknown"/>). Distinct
/// from "are there rules": a backend can be installed yet <see cref="Inactive"/> (ufw disabled), in which
/// case it filters NOTHING — so every port is reachable regardless of rules. The consumer needs this to
/// compute an honest <c>open</c> verdict: enforcing → open iff a rule allows it; inactive → open (all);
/// unknown → unknown. NEVER infer "closed" from an inactive backend.
/// </summary>
public static class Enforcements
{
    public const string Enforcing = "enforcing"; // the backend is active and filtering
    public const string Inactive = "inactive";   // installed but not enforcing (e.g. `ufw` disabled) → all open
    public const string Unknown = "unknown";     // cannot determine (non-root / absent / unparsable)
}

/// <summary>One port spec on the wire: a single port (<c>Start == End</c>) or an inclusive range, for one
/// protocol (<c>"tcp"</c>/<c>"udp"</c>). String protocol token keeps the JSON enum-free under AOT.</summary>
public sealed record PortDto(int Start, int End, string Protocol);

/// <summary>A request to the authority. <see cref="Op"/> is one of <see cref="FirewallOps"/>;
/// <see cref="Instance"/> is required for ensure-open/remove and optional for list (null = all owned);
/// <see cref="Ports"/> is only meaningful for ensure-open.</summary>
public sealed record FirewallRequest(string Op, string? Instance = null, PortDto[]? Ports = null);

/// <summary>The rules the authority owns for one instance (a list/backend reply payload).</summary>
public sealed record OwnedRuleDto(string Instance, PortDto[] Ports);

/// <summary>What the active backend can honestly do (a backend-op reply payload).</summary>
public sealed record CapabilitiesDto(bool CanApply, bool CanRemove, bool CanList);

/// <summary>
/// The single reply envelope for every op. <see cref="Ok"/> is the coarse success bit; <see cref="Outcome"/>
/// carries the precise status (an <see cref="Outcomes"/> token) the caller maps to an exit code / typed
/// result. <see cref="Backend"/> is always set to the active backend (useful on every reply).
/// <see cref="Rules"/> is populated for list; <see cref="Capabilities"/> for backend.
/// <see cref="Enforcement"/> (1.1.0) reports the backend's runtime enforcement state — populated on a list
/// reply (an <see cref="Enforcements"/> token), null otherwise / on a pre-1.1.0 daemon.
/// </summary>
public sealed record FirewallResponse(
    bool Ok,
    string Outcome,
    string Backend,
    string? Detail = null,
    OwnedRuleDto[]? Rules = null,
    CapabilitiesDto? Capabilities = null,
    string? Enforcement = null);
