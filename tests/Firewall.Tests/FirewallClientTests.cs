using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using TheKrystalShip.KGSM.Firewall.Contracts;

namespace TheKrystalShip.KGSM.Firewall.Tests;

/// <summary>
/// Tests for the kgsm-firewall control client. FirewallClient is raw socket I/O, so it is exercised
/// against an in-process canned-response authority over a real AF_UNIX socket (no external dependency) —
/// the same shape the firewall repo's own no-root end-to-end test uses. This covers the mapping both ways
/// (PortDto↔PortDto with ranges preserved, outcome token → typed result, honest Unknown) and the
/// transport (round-trip, unreachable, timeout).
/// </summary>
public class FirewallClientTests
{
    private static FirewallClient ClientFor(string socketPath, TimeSpan? timeout = null) =>
        new(new FirewallClientOptions { SocketPath = socketPath, RequestTimeout = timeout ?? TimeSpan.FromSeconds(5) },
            NullLogger<FirewallClient>.Instance);

    // ---- ensure-open / remove outcome mapping -----------------------------------------------------

    [Fact]
    public async Task EnsureOpenAsync_Applied_MapsResultAndSendsCanonicalPorts()
    {
        var response = new FirewallResponse(true, Outcomes.Applied, "ufw", "opened 2 specs");
        await using var authority = new FakeFirewallAuthority(response);
        using var client = ClientFor(authority.SocketPath);

        var ports = new List<PortDto>
        {
            new(34197, 34197, "udp"),
            new(27015, 27020, "tcp"),
        };

        FirewallActionResult result = await client.EnsureOpenAsync("factorio", ports);

        Assert.True(result.Ok);
        Assert.Equal(FirewallOutcome.Applied, result.Outcome);
        Assert.Equal("ufw", result.Backend);
        Assert.Equal("opened 2 specs", result.Detail);

        // The request reached the authority with the canonical ports mapped to wire PortDtos, ranges intact.
        FirewallRequest sent = await authority.RequestAsync();
        Assert.Equal(FirewallOps.EnsureOpen, sent.Op);
        Assert.Equal("factorio", sent.Instance);
        Assert.Equal(2, sent.Ports!.Length);
        Assert.Equal(new PortDto(34197, 34197, "udp"), sent.Ports[0]);
        Assert.Equal(new PortDto(27015, 27020, "tcp"), sent.Ports[1]);
    }

    [Theory]
    [InlineData(Outcomes.Applied, FirewallOutcome.Applied, true)]
    [InlineData(Outcomes.AppliedInactive, FirewallOutcome.AppliedInactive, true)] // staged-not-enforced is a success (1.1.0)
    [InlineData(Outcomes.NoOp, FirewallOutcome.NoOp, true)]
    [InlineData(Outcomes.Unsupported, FirewallOutcome.Unsupported, false)]
    [InlineData(Outcomes.Failed, FirewallOutcome.Failed, false)]
    public async Task EnsureOpenAsync_MapsOutcomeToken(string token, FirewallOutcome expected, bool ok)
    {
        await using var authority = new FakeFirewallAuthority(new FirewallResponse(ok, token, "ufw"));
        using var client = ClientFor(authority.SocketPath);

        FirewallActionResult result = await client.EnsureOpenAsync(
            "valheim", [new PortDto(2456, 2457, "udp")]);

        Assert.Equal(expected, result.Outcome);
        Assert.Equal(ok, result.Ok);
    }

    // The 1.1.0 enforcement axis maps onto FirewallListResult.Enforcement; a pre-1.1.0 authority omits it
    // (null) → Unknown, so a consumer falls back to its prior behaviour rather than misread "closed".
    [Theory]
    [InlineData(Enforcements.Enforcing, FirewallEnforcement.Enforcing)]
    [InlineData(Enforcements.Inactive, FirewallEnforcement.Inactive)]
    [InlineData(Enforcements.Unknown, FirewallEnforcement.Unknown)]
    [InlineData(null, FirewallEnforcement.Unknown)]
    public async Task ListOwnedAsync_MapsEnforcement(string? token, FirewallEnforcement expected)
    {
        await using var authority = new FakeFirewallAuthority(
            new FirewallResponse(true, Outcomes.Ok, "ufw", Rules: [], Enforcement: token));
        using var client = ClientFor(authority.SocketPath);

        FirewallListResult result = await client.ListOwnedAsync();

        Assert.Equal(FirewallListStatus.Ok, result.Status);
        Assert.Equal(expected, result.Enforcement);
    }

    [Fact]
    public async Task RemoveAsync_Removed_Maps()
    {
        await using var authority = new FakeFirewallAuthority(new FirewallResponse(true, Outcomes.Removed, "ufw"));
        using var client = ClientFor(authority.SocketPath);

        FirewallActionResult result = await client.RemoveAsync("factorio");

        Assert.True(result.Ok);
        Assert.Equal(FirewallOutcome.Removed, result.Outcome);

        FirewallRequest sent = await authority.RequestAsync();
        Assert.Equal(FirewallOps.Remove, sent.Op);
        Assert.Equal("factorio", sent.Instance);
        Assert.Null(sent.Ports);
    }

    // ---- list (honest Unknown must never read as "nothing open") -----------------------------------

    [Fact]
    public async Task ListOwnedAsync_Unknown_IsHonest_NotEmptyOk()
    {
        // The backend genuinely cannot enumerate. Status MUST be Unknown — not Ok-with-empty-rules.
        await using var authority = new FakeFirewallAuthority(new FirewallResponse(false, Outcomes.Unknown, "iptables"));
        using var client = ClientFor(authority.SocketPath);

        FirewallListResult result = await client.ListOwnedAsync();

        Assert.Equal(FirewallListStatus.Unknown, result.Status);
        Assert.Empty(result.Rules);
    }

    [Fact]
    public async Task ListOwnedAsync_Unsupported_Maps()
    {
        await using var authority = new FakeFirewallAuthority(new FirewallResponse(false, Outcomes.Unsupported, "none"));
        using var client = ClientFor(authority.SocketPath);

        FirewallListResult result = await client.ListOwnedAsync();

        Assert.Equal(FirewallListStatus.Unsupported, result.Status);
        Assert.Empty(result.Rules);
    }

    [Fact]
    public async Task ListOwnedAsync_Ok_MapsRulesAndPreservesRanges()
    {
        var response = new FirewallResponse(
            true, Outcomes.Ok, "ufw",
            Rules:
            [
                new OwnedRuleDto("valheim", [new PortDto(2456, 2457, "udp"), new PortDto(2456, 2456, "tcp")]),
                new OwnedRuleDto("factorio", [new PortDto(34197, 34197, "udp")]),
            ]);
        await using var authority = new FakeFirewallAuthority(response);
        using var client = ClientFor(authority.SocketPath);

        FirewallListResult result = await client.ListOwnedAsync();

        Assert.Equal(FirewallListStatus.Ok, result.Status);
        Assert.Equal(2, result.Rules.Count);

        FirewallOwnedRule valheim = result.Rules[0];
        Assert.Equal("valheim", valheim.Instance);
        Assert.Equal(2, valheim.Ports.Count);
        Assert.Equal(2456, valheim.Ports[0].Start);
        Assert.Equal(2457, valheim.Ports[0].End);     // range preserved through the mapping
        Assert.Equal("udp", valheim.Ports[0].Protocol);
        Assert.Equal(34197, result.Rules[1].Ports[0].Start);

        FirewallRequest sent = await authority.RequestAsync();
        Assert.Equal(FirewallOps.List, sent.Op);
        Assert.Null(sent.Instance); // list-all
    }

    [Fact]
    public async Task ListOwnedAsync_WithInstance_ScopesRequest()
    {
        await using var authority = new FakeFirewallAuthority(new FirewallResponse(true, Outcomes.Ok, "ufw", Rules: []));
        using var client = ClientFor(authority.SocketPath);

        await client.ListOwnedAsync("factorio");

        FirewallRequest sent = await authority.RequestAsync();
        Assert.Equal("factorio", sent.Instance);
    }

    // ---- backend ----------------------------------------------------------------------------------

    [Fact]
    public async Task BackendAsync_MapsBackendAndCapabilities()
    {
        var response = new FirewallResponse(
            true, Outcomes.Ok, "ufw", Capabilities: new CapabilitiesDto(true, true, false));
        await using var authority = new FakeFirewallAuthority(response);
        using var client = ClientFor(authority.SocketPath);

        FirewallBackendInfo info = await client.BackendAsync();

        Assert.Equal("ufw", info.Backend);
        Assert.True(info.CanApply);
        Assert.True(info.CanRemove);
        Assert.False(info.CanList);
    }

    [Fact]
    public async Task BackendAsync_MissingCapabilities_DefaultsToFalse()
    {
        // A reply without a capabilities payload must read as "can do nothing", never assumed-true.
        await using var authority = new FakeFirewallAuthority(new FirewallResponse(true, Outcomes.Ok, "none"));
        using var client = ClientFor(authority.SocketPath);

        FirewallBackendInfo info = await client.BackendAsync();

        Assert.Equal("none", info.Backend);
        Assert.False(info.CanApply);
        Assert.False(info.CanRemove);
        Assert.False(info.CanList);
    }

    // ---- transport: unreachable / timeout / guards ------------------------------------------------

    [Fact]
    public async Task Unreachable_ThrowsFirewallException_WithSocketPath()
    {
        string missing = Path.Combine(Path.GetTempPath(), $"kgsmfw-absent-{Guid.NewGuid():N}.sock");
        using var client = ClientFor(missing);

        FirewallException ex = await Assert.ThrowsAsync<FirewallException>(
            () => client.BackendAsync());
        Assert.Equal(missing, ex.SocketPath);
    }

    [Fact]
    public async Task NoReply_TimesOut_ThrowsFirewallException()
    {
        // The authority accepts and reads but never replies → the per-request timeout fires and surfaces
        // as unreachable (a FirewallException), not a bare cancellation.
        await using var authority = new FakeFirewallAuthority(new FirewallResponse(true, Outcomes.Ok, "ufw"))
        {
            ReplyEnabled = false,
        };
        using var client = ClientFor(authority.SocketPath, TimeSpan.FromMilliseconds(250));

        await Assert.ThrowsAsync<FirewallException>(() => client.BackendAsync());
    }

    [Fact]
    public async Task CallerCancellation_PropagatesAsOperationCanceled_NotFirewallException()
    {
        await using var authority = new FakeFirewallAuthority(new FirewallResponse(true, Outcomes.Ok, "ufw"))
        {
            ReplyEnabled = false,
        };
        using var client = ClientFor(authority.SocketPath, TimeSpan.FromSeconds(30));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));

        // A caller-driven cancellation is a cancellation, not an "authority unreachable" — don't mask it.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.BackendAsync(cts.Token));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task EnsureOpenAsync_BlankInstance_Throws(string instance)
    {
        using var client = ClientFor(Path.Combine(Path.GetTempPath(), $"kgsmfw-{Guid.NewGuid():N}.sock"));
        await Assert.ThrowsAsync<ArgumentException>(
            () => client.EnsureOpenAsync(instance, [new PortDto(1, 1, "tcp")]));
    }

    [Fact]
    public async Task Disposed_Throws()
    {
        var client = ClientFor(Path.Combine(Path.GetTempPath(), $"kgsmfw-{Guid.NewGuid():N}.sock"));
        client.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.BackendAsync());
    }

    // ---- in-process canned-response authority -----------------------------------------------------

    private sealed class FakeFirewallAuthority : IAsyncDisposable
    {
        public string SocketPath { get; }

        /// <summary>When false, the authority accepts and reads the request but never writes a reply
        /// (drives the client's timeout / cancellation paths).</summary>
        public bool ReplyEnabled { get; init; } = true;

        private readonly Socket _listener;
        private readonly FirewallResponse _response;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _acceptLoop;
        private readonly TaskCompletionSource<FirewallRequest> _request =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public FakeFirewallAuthority(FirewallResponse response)
        {
            _response = response;
            SocketPath = Path.Combine(Path.GetTempPath(), $"kgsmfw-{Guid.NewGuid():N}.sock");
            _listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            _listener.Bind(new UnixDomainSocketEndPoint(SocketPath));
            _listener.Listen(8);
            _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
        }

        /// <summary>The request the authority received (completes when a client connects and sends).</summary>
        public Task<FirewallRequest> RequestAsync() => _request.Task;

        private async Task AcceptLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                Socket conn;
                try { conn = await _listener.AcceptAsync(ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                _ = HandleAsync(conn, ct);
            }
        }

        private async Task HandleAsync(Socket conn, CancellationToken ct)
        {
            try
            {
                using (conn)
                {
                    string? line = await LineProtocol.ReadLineAsync(conn, LineProtocol.DefaultMaxBytes, ct)
                        .ConfigureAwait(false);
                    if (line is not null)
                    {
                        FirewallRequest? req = JsonSerializer.Deserialize(line, WireJsonContext.Default.FirewallRequest);
                        if (req is not null)
                            _request.TrySetResult(req);
                    }

                    if (!ReplyEnabled)
                    {
                        // Hold the connection open (no reply) until teardown, so the client hits its timeout.
                        await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
                        return;
                    }

                    byte[] payload = JsonSerializer.SerializeToUtf8Bytes(_response, WireJsonContext.Default.FirewallResponse);
                    await LineProtocol.WriteLineAsync(conn, payload, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { /* teardown */ }
            catch (ObjectDisposedException) { /* teardown */ }
            catch (System.Net.Sockets.SocketException) { /* peer went away */ }
        }

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            _listener.Dispose();
            try { await _acceptLoop.ConfigureAwait(false); } catch { /* ignore */ }
            try { if (File.Exists(SocketPath)) File.Delete(SocketPath); } catch { /* ignore */ }
            _cts.Dispose();
        }
    }
}
