using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Firewall.Wire;

namespace TheKrystalShip.KGSM.Firewall.Host;

/// <summary>
/// Translates between the internal domain types (<see cref="PortSpec"/>, <see cref="FirewallResult"/>,
/// <see cref="OwnedRulesResult"/>) and the wire DTOs. Lives in the composition layer because it is the
/// only place that legitimately knows both vocabularies. Protocol-token validation happens here (the
/// wire carries a string, the domain an enum); range/name validation stays in the service core, which
/// re-runs regardless of what the client sent.
/// </summary>
internal static class WireMapping
{
    public static string BackendToken(FirewallBackend backend) => backend switch
    {
        FirewallBackend.None => "none",
        FirewallBackend.Ufw => "ufw",
        FirewallBackend.Firewalld => "firewalld",
        FirewallBackend.Nftables => "nftables",
        FirewallBackend.Iptables => "iptables",
        _ => "none",
    };

    /// <summary>Map wire ports → domain specs, validating only the protocol token (no domain enum for a
    /// bad one). Null/empty is valid (→ empty list; the service turns that into a NoOp).</summary>
    public static bool TryToPortSpecs(PortDto[]? ports, out List<PortSpec> result, out string? error)
    {
        result = [];
        error = null;
        if (ports is null)
            return true;

        foreach (PortDto p in ports)
        {
            PortProtocol? proto = PortProtocolExtensions.TryParse(p.Protocol);
            if (proto is null)
            {
                result = [];
                error = $"invalid protocol '{p.Protocol}' (expected tcp/udp)";
                return false;
            }
            result.Add(new PortSpec(p.Start, p.End, proto.Value));
        }
        return true;
    }

    public static PortDto[] ToPortDtos(IReadOnlyList<PortSpec> ports)
    {
        var dtos = new PortDto[ports.Count];
        for (int i = 0; i < ports.Count; i++)
            dtos[i] = new PortDto(ports[i].Start, ports[i].End, ports[i].Protocol.ToToken());
        return dtos;
    }

    public static FirewallResponse ToResponse(FirewallResult result, string backendToken)
    {
        string outcome = result.Status switch
        {
            FirewallStatus.Applied => Outcomes.Applied,
            FirewallStatus.Removed => Outcomes.Removed,
            FirewallStatus.NoOp => Outcomes.NoOp,
            FirewallStatus.Unsupported => Outcomes.Unsupported,
            FirewallStatus.Failed => Outcomes.Failed,
            _ => Outcomes.Failed,
        };
        return new FirewallResponse(result.Ok, outcome, backendToken, result.Detail);
    }

    public static FirewallResponse ToResponse(OwnedRulesResult result, string backendToken)
    {
        string outcome = result.Status switch
        {
            OwnedQueryStatus.Ok => Outcomes.Ok,
            OwnedQueryStatus.Unknown => Outcomes.Unknown,
            OwnedQueryStatus.Unsupported => Outcomes.Unsupported,
            _ => Outcomes.Unknown,
        };

        var rules = new OwnedRuleDto[result.Rules.Count];
        for (int i = 0; i < result.Rules.Count; i++)
            rules[i] = new OwnedRuleDto(result.Rules[i].Instance, ToPortDtos(result.Rules[i].Ports));

        return new FirewallResponse(result.Status == OwnedQueryStatus.Ok, outcome, backendToken, Rules: rules);
    }
}
