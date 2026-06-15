namespace TheKrystalShip.KGSM.Firewall.Wire;

/// <summary>
/// The control-socket request/response DTOs and op tokens. The transport is one
/// newline-delimited JSON request → one newline-delimited JSON response over a unix domain socket
/// (see <see cref="LineProtocol"/>). This is deliberately NOT HTTP: the authority carries no ASP.NET
/// stack (a privileged helper shouldn't), and the binary is its own client — nothing external parses
/// the wire, so a tiny private protocol is enough.
/// <para>
/// These types are <c>internal</c> for Increment 1 (the daemon + its bundled CLI client are the only
/// speakers). Increment 2 lifts a public, kgsm-lib-facing copy into the standalone
/// <c>TheKrystalShip.KGSM.Firewall.Contracts</c> package; the shapes here are chosen to map onto that
/// 1:1. Wire collections are arrays (the most AOT-/source-gen-friendly shape); the domain's
/// <c>IReadOnlyList</c> is mapped at the boundary.
/// </para>
/// </summary>
internal static class FirewallOps
{
    public const string EnsureOpen = "ensure-open";
    public const string Remove = "remove";
    public const string List = "list";
    public const string Backend = "backend";
}

/// <summary>Outcome tokens carried in <see cref="FirewallResponse.Outcome"/> — the union of the domain's
/// apply/remove statuses and the list query statuses, flattened for the wire.</summary>
internal static class Outcomes
{
    public const string Applied = "applied";
    public const string Removed = "removed";
    public const string NoOp = "noop";
    public const string Ok = "ok";            // a successful read/backend query
    public const string Unknown = "unknown";  // list: backend genuinely cannot answer (honest unknown)
    public const string Unsupported = "unsupported";
    public const string Failed = "failed";
}

/// <summary>One port spec on the wire: a single port (<c>Start == End</c>) or an inclusive range, for one
/// protocol (<c>"tcp"</c>/<c>"udp"</c>). String protocol token keeps the JSON enum-free under AOT.</summary>
internal sealed record PortDto(int Start, int End, string Protocol);

/// <summary>A request to the authority. <see cref="Op"/> is one of <see cref="FirewallOps"/>;
/// <see cref="Instance"/> is required for ensure-open/remove and optional for list (null = all owned);
/// <see cref="Ports"/> is only meaningful for ensure-open.</summary>
internal sealed record FirewallRequest(string Op, string? Instance = null, PortDto[]? Ports = null);

/// <summary>The rules the authority owns for one instance (a list/backend reply payload).</summary>
internal sealed record OwnedRuleDto(string Instance, PortDto[] Ports);

/// <summary>What the active backend can honestly do (a backend-op reply payload).</summary>
internal sealed record CapabilitiesDto(bool CanApply, bool CanRemove, bool CanList);

/// <summary>
/// The single reply envelope for every op. <see cref="Ok"/> is the coarse success bit; <see cref="Outcome"/>
/// carries the precise status (an <see cref="Outcomes"/> token) the CLI maps to an exit code.
/// <see cref="Backend"/> is always set to the active backend (useful on every reply). <see cref="Rules"/>
/// is populated for list; <see cref="Capabilities"/> for backend.
/// </summary>
internal sealed record FirewallResponse(
    bool Ok,
    string Outcome,
    string Backend,
    string? Detail = null,
    OwnedRuleDto[]? Rules = null,
    CapabilitiesDto? Capabilities = null);
