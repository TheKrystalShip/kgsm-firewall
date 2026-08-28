using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TheKrystalShip.KGSM.Firewall.Contracts;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Lifecycle;

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
    FirewallJournal journal,
    LeafLifecycle lifecycle,
    FirewallBackend backend,
    TimeSpan idleTimeout,
    ILogger<FirewallDaemon> logger)
{
    // ufw takes a single global lock; concurrent `ufw app update`/`ufw allow` (plausible when autostart
    // brings several instances up at boot) would collide. Serialise every driver call through one gate —
    // firewall ops are rare, so the lost concurrency costs nothing.
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _backendToken = WireMapping.BackendToken(backend);

    // Connections currently being handled (the fire-and-forget tasks). The idle-exit must never fire while
    // any handler is mid-`ufw`-write: a graceful RunAsync return abandons those background tasks.
    private int _activeConnections;

    /// <summary>
    /// Says so when this authority is running and cannot apply a rule.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The most dangerous silent state on a KGSM host. Ports are opened when a server starts and
    /// closed when it stops, and an authority that answers but cannot write leaves them closed on a
    /// start or open on a stop — with every caller told the request was accepted, because it was.
    /// </para>
    /// <para>
    /// Reported on every wake rather than once. This daemon exits when idle, so it holds no memory of
    /// what it said last time; a consumer reading the same finding again is being told the condition
    /// still holds, which is what a fresh process observing it afresh honestly means.
    /// </para>
    /// </remarks>
    private void ReportBackend()
    {
        if (service.Capabilities.CanApply)
        {
            // Reported, not skipped. A wake that finds the backend working is the only thing that can
            // clear a fault an earlier process reported, and the emitter writes nothing unless there
            // was one — so a healthy host stays silent across all 35 of its daily wakes.
            lifecycle.MarkRecovered(FirewallComponents.Backend);
            return;
        }

        lifecycle.MarkDegraded(
            FirewallComponents.Backend,
            $"the {backend} backend cannot apply a rule; ports will not be opened when a server starts "
            + "or closed when it stops, and every caller is told the request was accepted");
    }

    public async Task RunAsync(CancellationToken ct)
    {
        if (idleTimeout > TimeSpan.Zero)
            logger.LogInformation(
                "kgsm-firewall daemon ready (backend={Backend}, canApply={CanApply}, idleExit={Idle:0.#}s)",
                backend, service.Capabilities.CanApply, idleTimeout.TotalSeconds);
        else
            logger.LogInformation(
                "kgsm-firewall daemon ready (backend={Backend}, canApply={CanApply}, resident)",
                backend, service.Capabilities.CanApply);

        ReportBackend();

        // One outstanding accept, reused across idle re-races. We never cancel + re-issue an accept on the
        // same listener (that reuse-after-cancel behaviour is the one thing we'd rather not depend on); the
        // accept is only ever torn down at real shutdown, when the caller disposes the listener.
        Task<Socket>? acceptTask = null;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                acceptTask ??= listener.AcceptAsync(ct).AsTask();

                if (idleTimeout > TimeSpan.Zero)
                {
                    // Race the pending accept against the idle window. The delay carries no token: at
                    // shutdown the accept itself faults on `ct`, winning the race, so a token here would
                    // only add an unobserved cancelled task each loop. A losing delay completes harmlessly.
                    Task winner = await Task.WhenAny(acceptTask, Task.Delay(idleTimeout)).ConfigureAwait(false);
                    if (winner != acceptTask)
                    {
                        if (ct.IsCancellationRequested)
                            break;

                        // Exit only when truly quiescent: no handler in flight, and no connection that
                        // slipped onto the still-pending accept between the timer firing and this check
                        // (accepting it here would orphan it — systemd only re-delivers what we never
                        // accept()ed). Otherwise loop and re-race the SAME acceptTask.
                        if (Volatile.Read(ref _activeConnections) == 0 && !acceptTask.IsCompleted)
                        {
                            logger.LogInformation(
                                "idle for {Seconds:0.#}s with no activity; exiting (systemd re-activates on the next connection)",
                                idleTimeout.TotalSeconds);
                            break;
                        }
                        continue;
                    }
                }

                Socket connection;
                try
                {
                    connection = await acceptTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "accept failed; continuing");
                    acceptTask = null;
                    continue;
                }
                acceptTask = null;

                // Each connection is independent and self-contained; handle it off the accept loop so a slow
                // peer never stalls new connections. The driver-touching work inside is still serialised by _gate.
                Interlocked.Increment(ref _activeConnections);
                _ = HandleConnectionAsync(connection, ct);
            }
        }
        finally
        {
            // An accept may still be outstanding (idle-exit always leaves one pending; shutdown may). The
            // caller is about to dispose the listener, faulting it — observe that so it isn't an unobserved
            // exception, and close any connection that landed but went unconsumed.
            if (acceptTask is not null)
                _ = acceptTask.ContinueWith(static t =>
                {
                    if (t.IsCompletedSuccessfully) t.Result.Dispose();
                    else _ = t.Exception;
                }, TaskScheduler.Default);
        }

        logger.LogInformation("kgsm-firewall daemon shutting down");
    }

    private async Task HandleConnectionAsync(Socket connection, CancellationToken ct)
    {
        try
        {
            using (connection)
            {
                string? line = await LineProtocol.ReadLineAsync(connection, LineProtocol.DefaultMaxBytes, ct)
                    .ConfigureAwait(false);

                FirewallResponse response = line is null
                    ? Fail("empty request")
                    : await DispatchAsync(line, ct).ConfigureAwait(false);

                byte[] payload = JsonSerializer.SerializeToUtf8Bytes(response, WireJsonContext.Default.FirewallResponse);
                await LineProtocol.WriteLineAsync(connection, payload, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { /* shutting down */ }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "error handling connection");
        }
        finally
        {
            Interlocked.Decrement(ref _activeConnections);
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

            // Recorded here, inside the gate, because this is the only place that knows the edge was
            // actually applied AND what was applied. The caller's provenance rides through from the
            // request — repeated, never vouched for.
            await journal.OpenedAsync(request.Instance, ports, result, request.Actor, request.Origin, ct)
                .ConfigureAwait(false);

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

            await journal.ClosedAsync(request.Instance, result, request.Actor, request.Origin, ct)
                .ConfigureAwait(false);

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
