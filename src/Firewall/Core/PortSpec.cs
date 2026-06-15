namespace TheKrystalShip.KGSM.Firewall.Core;

/// <summary>
/// Transport protocol for a firewall rule. A spec is always exactly one protocol — never an ambiguous
/// "both": a proto-less input is split into separate tcp/udp specs upstream (the canonical KGSM port
/// form already does this), so the authority only ever sees a concrete protocol.
/// </summary>
internal enum PortProtocol
{
    Tcp,
    Udp,
}

internal static class PortProtocolExtensions
{
    /// <summary>The lowercase ufw/wire token for the protocol (<c>tcp</c>/<c>udp</c>).</summary>
    public static string ToToken(this PortProtocol proto)
        => proto == PortProtocol.Tcp ? "tcp" : "udp";

    /// <summary>Parse a protocol token; null unless it is exactly <c>tcp</c>/<c>udp</c> (case-insensitive).</summary>
    public static PortProtocol? TryParse(string? token)
        => token?.Trim().ToLowerInvariant() switch
        {
            "tcp" => PortProtocol.Tcp,
            "udp" => PortProtocol.Udp,
            _ => null,
        };
}

/// <summary>
/// One firewall port specification: a single port (<see cref="Start"/> == <see cref="End"/>) or an
/// inclusive range, for exactly one <see cref="PortProtocol"/>.
/// <para>
/// This is the firewall authority's OWN port type. It deliberately does not reference kgsm-lib's
/// <c>PortMapping</c>: kgsm-lib consumes the firewall contract (never the reverse), so sharing the type
/// would create a dependency cycle. Callers map their port representation onto this at the boundary.
/// </para>
/// </summary>
internal sealed record PortSpec(int Start, int End, PortProtocol Protocol)
{
    public bool IsRange => End > Start;

    /// <summary>Render the ufw-style token: <c>port/proto</c> or <c>start:end/proto</c>.</summary>
    public string ToUfwToken()
        => IsRange
            ? $"{Start}:{End}/{Protocol.ToToken()}"
            : $"{Start}/{Protocol.ToToken()}";
}
