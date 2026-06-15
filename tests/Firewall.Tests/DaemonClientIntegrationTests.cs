using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Firewall.Drivers.Ufw;
using TheKrystalShip.KGSM.Firewall.Host;
using TheKrystalShip.KGSM.Firewall.Tests.Fakes;

namespace TheKrystalShip.KGSM.Firewall.Tests;

/// <summary>
/// End-to-end over a REAL <c>AF_UNIX</c> socket in a temp dir — no root, no real ufw. Drives the actual
/// client code path (<see cref="FirewallCliClient"/>) against the actual daemon
/// (<see cref="FirewallDaemon"/>), so it proves client → socket → daemon → service → driver → reply → exit
/// code as one wire. The only Increment-1 surface this can't reach is the systemd FD adoption (validated
/// live against the published AOT binary, not here).
/// </summary>
public class DaemonClientIntegrationTests
{
    /// <summary>A running daemon bound to a throwaway unix socket; the client connects via <see cref="Options"/>.</summary>
    private sealed class Harness : IAsyncDisposable
    {
        public string SocketPath { get; }
        public InMemoryUfwProfileStore Store { get; }
        public FakeProcessRunner Runner { get; }
        private readonly Socket _listener;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _serve;

        private Harness(IFirewallDriver driver, FirewallBackend backend, InMemoryUfwProfileStore store, FakeProcessRunner runner)
        {
            Store = store;
            Runner = runner;
            SocketPath = Path.Combine(Path.GetTempPath(), $"kgfw{Guid.NewGuid():N}.sock");

            _listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            _listener.Bind(new UnixDomainSocketEndPoint(SocketPath));
            _listener.Listen(16);

            var service = new FirewallService(driver, NullLogger<FirewallService>.Instance);
            var daemon = new FirewallDaemon(_listener, service, backend, NullLogger<FirewallDaemon>.Instance);
            _serve = daemon.RunAsync(_cts.Token);
        }

        public static Harness Ufw(Func<string, IReadOnlyList<string>, ProcessResult>? handler = null)
        {
            var runner = new FakeProcessRunner();
            if (handler is not null) runner.Handler = handler;
            var store = new InMemoryUfwProfileStore();
            var driver = new UfwDriver(runner, store, NullLogger<UfwDriver>.Instance);
            return new Harness(driver, FirewallBackend.Ufw, store, runner);
        }

        public static Harness NoBackend()
        {
            var driver = new NullFirewallDriver(FirewallBackend.None);
            return new Harness(driver, FirewallBackend.None, new InMemoryUfwProfileStore(), new FakeProcessRunner());
        }

        public FirewallOptions Options => new() { SocketPath = SocketPath };

        public async ValueTask DisposeAsync()
        {
            await _cts.CancelAsync();
            try { await _serve.WaitAsync(TimeSpan.FromSeconds(5)); } catch { /* cancellation / teardown */ }
            _listener.Dispose();
            try { File.Delete(SocketPath); } catch { /* best-effort */ }
            _cts.Dispose();
        }
    }

    [Fact]
    public async Task EnsureOpen_HappyPath_Exit0_AndProfileWritten()
    {
        await using var h = Harness.Ufw();

        int code = await FirewallCliClient.RunAsync(
            "ensure-open", ["factorio", "34197/udp"], h.Options, default);

        Assert.Equal(ExitCodes.Success, code);
        Assert.True(h.Store.Files.ContainsKey("kgsm-factorio"));
        Assert.True(h.Runner.WasCalledWith("ufw", "allow", "kgsm-factorio"));
    }

    [Fact]
    public async Task EnsureOpen_UfwAllowFails_Exit5()
    {
        await using var h = Harness.Ufw((file, args) =>
            args.Count > 0 && args[0] == "allow"
                ? new ProcessResult(1, "", "ERROR: could not insert rule")
                : new ProcessResult(0, "", ""));

        int code = await FirewallCliClient.RunAsync(
            "ensure-open", ["factorio", "34197/udp"], h.Options, default);

        Assert.Equal(ExitCodes.OpFailed, code);
        Assert.False(h.Store.Files.ContainsKey("kgsm-factorio")); // rolled back
    }

    [Fact]
    public async Task Remove_Exit0_AndProfileDeleted()
    {
        await using var h = Harness.Ufw();
        h.Store.Files["kgsm-factorio"] = "irrelevant";

        int code = await FirewallCliClient.RunAsync("remove", ["factorio"], h.Options, default);

        Assert.Equal(ExitCodes.Success, code);
        Assert.False(h.Store.Files.ContainsKey("kgsm-factorio"));
        Assert.True(h.Runner.WasCalledWith("ufw", "delete", "allow", "kgsm-factorio"));
    }

    [Fact]
    public async Task List_ActiveRule_Exit0()
    {
        await using var h = Harness.Ufw((_, args) =>
            args.Count > 0 && args[0] == "status"
                ? new ProcessResult(0, "Status: active\nkgsm-factorio  ALLOW  Anywhere", "")
                : new ProcessResult(0, "", ""));
        h.Store.Files["kgsm-factorio"] = UfwProfile.Render("factorio", [new PortSpec(34197, 34197, PortProtocol.Udp)]);

        int code = await FirewallCliClient.RunAsync("list", [], h.Options, default);

        Assert.Equal(ExitCodes.Success, code);
    }

    [Fact]
    public async Task List_StatusUnreadable_Exit6_Unknown()
    {
        // Non-zero `ufw status` (e.g. non-root) must surface as honest-unknown, NOT "nothing open".
        await using var h = Harness.Ufw((_, _) => new ProcessResult(1, "", "permission denied"));
        h.Store.Files["kgsm-factorio"] = UfwProfile.Render("factorio", [new PortSpec(34197, 34197, PortProtocol.Udp)]);

        int code = await FirewallCliClient.RunAsync("list", [], h.Options, default);

        Assert.Equal(ExitCodes.Unknown, code);
    }

    [Fact]
    public async Task Backend_ReportsActiveBackend_Exit0()
    {
        await using var h = Harness.Ufw();

        int code = await FirewallCliClient.RunAsync("backend", [], h.Options, default);

        Assert.Equal(ExitCodes.Success, code);
    }

    [Fact]
    public async Task EnsureOpen_NoUsableBackend_Exit4_Unsupported()
    {
        await using var h = Harness.NoBackend();

        int code = await FirewallCliClient.RunAsync(
            "ensure-open", ["factorio", "34197/udp"], h.Options, default);

        Assert.Equal(ExitCodes.Unsupported, code);
    }

    [Fact]
    public async Task BadPortToken_Exit2_NeverContactsDaemon()
    {
        await using var h = Harness.Ufw();

        int code = await FirewallCliClient.RunAsync(
            "ensure-open", ["factorio", "not-a-port"], h.Options, default);

        Assert.Equal(ExitCodes.Usage, code);
        Assert.Empty(h.Runner.Calls); // rejected client-side, before any wire round-trip
    }

    [Fact]
    public async Task AuthorityUnreachable_Exit3()
    {
        // No daemon at this path.
        var options = new FirewallOptions
        {
            SocketPath = Path.Combine(Path.GetTempPath(), $"kgfw-absent-{Guid.NewGuid():N}.sock"),
        };

        int code = await FirewallCliClient.RunAsync("backend", [], options, default);

        Assert.Equal(ExitCodes.Unreachable, code);
    }
}
