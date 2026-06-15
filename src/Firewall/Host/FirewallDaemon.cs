using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Firewall.Wire;

namespace TheKrystalShip.KGSM.Firewall.Host;

/// <summary>
/// The resident half of the binary: accepts connections on the control socket, reads one
/// newline-delimited JSON request, dispatches it to the <see cref="FirewallService"/>, and writes one
/// JSON reply. Runs as root (it must, to drive <c>ufw</c>) and does NOT drop privilege — unlike the
/// watchdog it spawns no untrusted children; the socket's filesystem permissions are the only security
/// boundary. Detection already ran daemon-side at composition, so the backend is fixed for the daemon's
/// lifetime (a privileged read the unprivileged CLI client could not do itself).
/// </summary>
internal sealed class FirewallDaemon(
    Socket listener,
    FirewallService service,
    FirewallBackend backend,
    ILogger<FirewallDaemon> logger)
{
    // ufw takes a single global lock; concurrent `ufw app update`/`ufw allow` (plausible when autostart
    // brings several instances up at boot) would collide. Serialise every driver call through one gate —
    // firewall ops are rare, so the lost concurrency costs nothing.
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _backendToken = WireMapping.BackendToken(backend);

    public async Task RunAsync(CancellationToken ct)
    {
        logger.LogInformation(
            "kgsm-firewall daemon ready (backend={Backend}, canApply={CanApply})",
            backend, service.Capabilities.CanApply);

        while (!ct.IsCancellationRequested)
        {
            Socket connection;
            try
            {
                connection = await listener.AcceptAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "accept failed; continuing");
                continue;
            }

            // Each connection is independent and self-contained; handle it off the accept loop so a slow
            // peer never stalls new connections. The driver-touching work inside is still serialised by _gate.
            _ = HandleConnectionAsync(connection, ct);
        }

        logger.LogInformation("kgsm-firewall daemon shutting down");
    }

    private async Task HandleConnectionAsync(Socket connection, CancellationToken ct)
    {
        using (connection)
        {
            try
            {
                string? line = await LineProtocol.ReadLineAsync(connection, LineProtocol.DefaultMaxBytes, ct)
                    .ConfigureAwait(false);

                FirewallResponse response = line is null
                    ? Fail("empty request")
                    : await DispatchAsync(line, ct).ConfigureAwait(false);

                byte[] payload = JsonSerializer.SerializeToUtf8Bytes(response, WireJsonContext.Default.FirewallResponse);
                await LineProtocol.WriteLineAsync(connection, payload, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { /* shutting down */ }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "error handling connection");
            }
        }
    }

    private async Task<FirewallResponse> DispatchAsync(string line, CancellationToken ct)
    {
        FirewallRequest? request;
        try
        {
            request = JsonSerializer.Deserialize(line, WireJsonContext.Default.FirewallRequest);
        }
        catch (JsonException ex)
        {
            return Fail($"malformed request: {ex.Message}");
        }

        if (request is null)
            return Fail("null request");

        return request.Op switch
        {
            FirewallOps.Backend => BackendReply(),
            FirewallOps.EnsureOpen => await EnsureOpenAsync(request, ct).ConfigureAwait(false),
            FirewallOps.Remove => await RemoveAsync(request, ct).ConfigureAwait(false),
            FirewallOps.List => await ListAsync(request, ct).ConfigureAwait(false),
            _ => Fail($"unknown op '{request.Op}'"),
        };
    }

    private FirewallResponse BackendReply()
    {
        FirewallCapabilities caps = service.Capabilities;
        return new FirewallResponse(
            Ok: true,
            Outcome: Outcomes.Ok,
            Backend: _backendToken,
            Capabilities: new CapabilitiesDto(caps.CanApply, caps.CanRemove, caps.CanList));
    }

    private async Task<FirewallResponse> EnsureOpenAsync(FirewallRequest request, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(request.Instance))
            return Fail("ensure-open requires an instance");

        if (!WireMapping.TryToPortSpecs(request.Ports, out List<PortSpec> ports, out string? portError))
            return Fail(portError ?? "invalid port specification");

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            FirewallResult result = await service.EnsureOpenAsync(request.Instance, ports, ct).ConfigureAwait(false);
            return WireMapping.ToResponse(result, _backendToken);
        }
        finally { _gate.Release(); }
    }

    private async Task<FirewallResponse> RemoveAsync(FirewallRequest request, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(request.Instance))
            return Fail("remove requires an instance");

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            FirewallResult result = await service.RemoveAsync(request.Instance, ct).ConfigureAwait(false);
            return WireMapping.ToResponse(result, _backendToken);
        }
        finally { _gate.Release(); }
    }

    private async Task<FirewallResponse> ListAsync(FirewallRequest request, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            OwnedRulesResult result = await service.ListOwnedAsync(request.Instance, ct).ConfigureAwait(false);
            return WireMapping.ToResponse(result, _backendToken);
        }
        finally { _gate.Release(); }
    }

    private FirewallResponse Fail(string detail) =>
        new(Ok: false, Outcome: Outcomes.Failed, Backend: _backendToken, Detail: detail);
}
