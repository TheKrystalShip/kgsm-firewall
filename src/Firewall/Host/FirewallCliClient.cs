using System.Net.Sockets;
using System.Text.Json;
using TheKrystalShip.KGSM.Firewall.Contracts;
using TheKrystalShip.KGSM.Firewall.Core;

namespace TheKrystalShip.KGSM.Firewall.Host;

/// <summary>
/// The client half of the binary. kgsm (and an operator) invoke <c>kgsm-firewall ensure-open …</c> /
/// <c>remove</c> / <c>list</c> / <c>backend</c>; this builds the wire request, sends it to the running
/// daemon over the control socket, prints a human line, and — crucially — returns an
/// <see cref="ExitCodes"/> value the bash caller maps to a kgsm exit code. Bash never speaks the wire
/// protocol; that is the whole point of bundling the client into the same binary.
/// </summary>
internal static class FirewallCliClient
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    public static async Task<int> RunAsync(
        string verb, string[] verbArgs, FirewallOptions options, CancellationToken ct)
    {
        FirewallRequest? request = BuildRequest(verb, verbArgs, out string? usageError);
        if (request is null)
        {
            Console.Error.WriteLine(usageError);
            return ExitCodes.Usage;
        }

        FirewallResponse? response;
        try
        {
            response = await SendAsync(options.SocketPath, request, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or IOException or InvalidDataException or OperationCanceledException)
        {
            Console.Error.WriteLine(
                $"kgsm-firewall: cannot reach the firewall authority at {options.SocketPath}: {ex.Message}");
            return ExitCodes.Unreachable;
        }

        if (response is null)
        {
            Console.Error.WriteLine(
                $"kgsm-firewall: the firewall authority at {options.SocketPath} sent no reply");
            return ExitCodes.Unreachable;
        }

        return Report(verb, response);
    }

    // ---- request construction -------------------------------------------------------------------

    private static FirewallRequest? BuildRequest(string verb, string[] a, out string? error)
    {
        error = null;
        switch (verb)
        {
            case FirewallOps.Backend:
                return new FirewallRequest(FirewallOps.Backend);

            case FirewallOps.List:
                // `list` or `list <instance>`
                return new FirewallRequest(FirewallOps.List, a.Length > 0 ? a[0] : null);

            case FirewallOps.Remove:
                if (a.Length != 1)
                {
                    error = "usage: kgsm-firewall remove <instance>";
                    return null;
                }
                return new FirewallRequest(FirewallOps.Remove, a[0]);

            case FirewallOps.EnsureOpen:
                if (a.Length < 2)
                {
                    error = "usage: kgsm-firewall ensure-open <instance> <port[/proto]>... "
                          + "(e.g. 34197/udp 27015:27020/tcp)";
                    return null;
                }
                var ports = new List<PortDto>(a.Length - 1);
                for (int i = 1; i < a.Length; i++)
                {
                    if (ParsePortToken(a[i]) is not { } dto)
                    {
                        error = $"invalid port token '{a[i]}' (expected <port>/<proto> or <start>:<end>/<proto>)";
                        return null;
                    }
                    ports.Add(dto);
                }
                return new FirewallRequest(FirewallOps.EnsureOpen, a[0], [.. ports]);

            default:
                error = $"unknown command '{verb}' (expected ensure-open | remove | list | backend)";
                return null;
        }
    }

    /// <summary>Parse a ufw-style port token: <c>port/proto</c> or <c>start:end/proto</c>. Returns null on
    /// any malformed shape; the daemon re-validates ranges regardless.</summary>
    internal static PortDto? ParsePortToken(string token)
    {
        int slash = token.IndexOf('/');
        if (slash <= 0 || slash == token.Length - 1)
            return null;

        string portPart = token[..slash];
        string proto = token[(slash + 1)..].ToLowerInvariant();
        if (proto is not ("tcp" or "udp"))
            return null;

        int colon = portPart.IndexOf(':');
        if (colon < 0)
        {
            return int.TryParse(portPart, out int port) ? new PortDto(port, port, proto) : null;
        }

        if (!int.TryParse(portPart[..colon], out int start) || !int.TryParse(portPart[(colon + 1)..], out int end))
            return null;
        return new PortDto(start, end, proto);
    }

    // ---- transport ------------------------------------------------------------------------------

    private static async Task<FirewallResponse?> SendAsync(
        string socketPath, FirewallRequest request, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(Timeout);

        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), timeout.Token).ConfigureAwait(false);

        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(request, WireJsonContext.Default.FirewallRequest);
        await LineProtocol.WriteLineAsync(socket, payload, timeout.Token).ConfigureAwait(false);
        socket.Shutdown(SocketShutdown.Send); // signal "request complete" to the daemon's EOF-aware reader

        string? line = await LineProtocol.ReadLineAsync(socket, LineProtocol.DefaultMaxBytes, timeout.Token)
            .ConfigureAwait(false);
        return line is null ? null : JsonSerializer.Deserialize(line, WireJsonContext.Default.FirewallResponse);
    }

    // ---- reporting ------------------------------------------------------------------------------

    private static int Report(string verb, FirewallResponse r)
    {
        if (verb == FirewallOps.Backend)
        {
            CapabilitiesDto c = r.Capabilities ?? new CapabilitiesDto(false, false, false);
            Console.WriteLine($"backend={r.Backend} apply={c.CanApply} remove={c.CanRemove} list={c.CanList}");
            return ExitCodes.Success;
        }

        if (verb == FirewallOps.List)
        {
            switch (r.Outcome)
            {
                case Outcomes.Ok:
                    foreach (OwnedRuleDto rule in r.Rules ?? [])
                        Console.WriteLine($"{rule.Instance}\t{string.Join(' ', RenderPorts(rule.Ports))}");
                    return ExitCodes.Success;
                case Outcomes.Unknown:
                    Console.Error.WriteLine($"kgsm-firewall: backend {r.Backend} cannot enumerate rules (unknown)");
                    return ExitCodes.Unknown;
                default: // unsupported
                    Console.Error.WriteLine($"kgsm-firewall: backend {r.Backend} does not support listing");
                    return ExitCodes.Unsupported;
            }
        }

        // ensure-open / remove
        switch (r.Outcome)
        {
            case Outcomes.Applied:
            case Outcomes.AppliedInactive: // rule staged; ufw is installed-but-inactive — a SUCCESS, not a
                                           // failure. Mapping this to OpFailed would abort a kgsm install on
                                           // an inactive-ufw host (the rule IS owned; it enforces on enable).
            case Outcomes.Removed:
            case Outcomes.NoOp:
                if (!string.IsNullOrEmpty(r.Detail)) Console.WriteLine(r.Detail);
                return ExitCodes.Success;
            case Outcomes.Unsupported:
                Console.Error.WriteLine(
                    $"kgsm-firewall: backend {r.Backend} cannot apply firewall rules"
                    + (string.IsNullOrEmpty(r.Detail) ? "" : $" ({r.Detail})"));
                return ExitCodes.Unsupported;
            default: // failed
                Console.Error.WriteLine($"kgsm-firewall: {r.Detail ?? "operation failed"}");
                return ExitCodes.OpFailed;
        }
    }

    private static IEnumerable<string> RenderPorts(PortDto[] ports)
    {
        foreach (PortDto p in ports)
            yield return p.Start == p.End ? $"{p.Start}/{p.Protocol}" : $"{p.Start}:{p.End}/{p.Protocol}";
    }
}
