using System.Text.RegularExpressions;

namespace TheKrystalShip.KGSM.Firewall.Core;

/// <summary>
/// Defensive validation enforced in the service core, BEFORE any driver runs — so every backend
/// inherits the same checks and we never trust the caller, even kgsm. Validates the instance-name
/// shape, the port range, and (implicitly, via the <see cref="PortProtocol"/> enum) the protocol.
/// AOT note: the instance-name pattern is a <see cref="GeneratedRegexAttribute"/> source-generated
/// matcher — no runtime regex compilation, no reflection.
/// </summary>
internal static partial class FirewallValidator
{
    [GeneratedRegex("^[A-Za-z0-9_-]+$")]
    private static partial Regex InstanceNamePattern();

    public static bool IsValidInstanceName(string? instance)
        => !string.IsNullOrEmpty(instance) && InstanceNamePattern().IsMatch(instance);

    public static bool IsValidPort(int port) => port is >= 1 and <= 65535;

    /// <summary>Validate an instance + its ports. Returns null when valid, else a human error string.</summary>
    public static string? ValidateOpen(string? instance, IReadOnlyList<PortSpec> ports)
    {
        if (!IsValidInstanceName(instance))
            return $"invalid instance name '{instance}' (must match ^[A-Za-z0-9_-]+$)";

        for (int i = 0; i < ports.Count; i++)
        {
            PortSpec p = ports[i];
            if (!IsValidPort(p.Start) || !IsValidPort(p.End))
                return $"port out of range in '{p.Start}:{p.End}' (each must be 1..65535)";
            if (p.End < p.Start)
                return $"inverted port range '{p.Start}:{p.End}' (end < start)";
        }

        return null;
    }

    /// <summary>Validate an instance name alone (remove / list). Returns null when valid.</summary>
    public static string? ValidateInstance(string? instance)
        => IsValidInstanceName(instance)
            ? null
            : $"invalid instance name '{instance}' (must match ^[A-Za-z0-9_-]+$)";
}
