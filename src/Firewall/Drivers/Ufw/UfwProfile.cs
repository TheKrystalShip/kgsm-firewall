using System.Text;
using TheKrystalShip.KGSM.Firewall.Core;

namespace TheKrystalShip.KGSM.Firewall.Drivers.Ufw;

/// <summary>
/// Renders and parses the ufw application profile the driver owns for an instance.
/// <para>
/// The DRIVER — not kgsm — owns this rendering. A pre-baked ufw profile cannot feed a firewalld/nft
/// driver, so keeping the render inside the ufw driver is exactly what makes the cross-backend seam
/// genuinely agnostic: kgsm passes only structured ports, and each driver renders its own native shape.
/// The profile name doubles as the ownership tag — <c>kgsm-&lt;instance&gt;</c>.
/// </para>
/// </summary>
internal static class UfwProfile
{
    private const string Prefix = "kgsm-";

    /// <summary>The ufw profile / app name for an instance — also the ownership tag.</summary>
    public static string NameFor(string instance) => Prefix + instance;

    /// <summary>The instance carried by a <c>kgsm-*</c> profile name, or null if the name is not ours.</summary>
    public static string? InstanceFromName(string profileName)
        => profileName.StartsWith(Prefix, StringComparison.Ordinal) && profileName.Length > Prefix.Length
            ? profileName[Prefix.Length..]
            : null;

    /// <summary>Render the profile file body. ufw joins multiple specs with <c>|</c> on the ports line
    /// (e.g. <c>27015:27020/udp|27016/tcp</c>).</summary>
    public static string Render(string instance, IReadOnlyList<PortSpec> ports)
    {
        string name = NameFor(instance);
        string portsLine = string.Join('|', ports.Select(p => p.ToUfwToken()));
        var sb = new StringBuilder();
        sb.Append('[').Append(name).Append("]\n");
        sb.Append("title=").Append(name).Append('\n');
        sb.Append("description=KGSM-managed firewall rules for instance ").Append(instance).Append('\n');
        sb.Append("ports=").Append(portsLine).Append('\n');
        return sb.ToString();
    }

    /// <summary>Parse the <c>ports=</c> line of a profile body back into specs. Lenient: skips tokens it
    /// cannot parse (a profile we wrote is always well-formed; this only guards against hand-edits).</summary>
    public static IReadOnlyList<PortSpec> ParsePorts(string profileBody)
    {
        foreach (string raw in profileBody.Split('\n'))
        {
            string line = raw.Trim();
            if (!line.StartsWith("ports=", StringComparison.Ordinal)) continue;

            string spec = line["ports=".Length..].Trim();
            var result = new List<PortSpec>();
            foreach (string token in spec.Split(
                '|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (TryParseToken(token, out PortSpec? ps)) result.Add(ps!);
            }
            return result;
        }
        return [];
    }

    private static bool TryParseToken(string token, out PortSpec? spec)
    {
        spec = null;

        // Shape: <port | start:end>/<proto>. Our render always writes a proto, so a proto-less token
        // is not ours -> reject (don't guess tcp).
        int slash = token.IndexOf('/');
        if (slash < 0) return false;

        PortProtocol? proto = PortProtocolExtensions.TryParse(token[(slash + 1)..]);
        if (proto is null) return false;

        string portPart = token[..slash];
        int colon = portPart.IndexOf(':');
        if (colon >= 0)
        {
            if (int.TryParse(portPart[..colon], out int start)
                && int.TryParse(portPart[(colon + 1)..], out int end))
            {
                spec = new PortSpec(start, end, proto.Value);
                return true;
            }
            return false;
        }

        if (int.TryParse(portPart, out int single))
        {
            spec = new PortSpec(single, single, proto.Value);
            return true;
        }
        return false;
    }
}
