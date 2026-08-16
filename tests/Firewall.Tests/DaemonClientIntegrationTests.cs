using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Firewall.Drivers.Ufw;
using TheKrystalShip.KGSM.Core.Models;
using TheKrystalShip.KGSM.Firewall.Host;
using TheKrystalShip.KGSM.Services;
using TheKrystalShip.KGSM.Firewall.Tests.Fakes;
using TheKrystalShip.KGSM.Lifecycle;

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

        /// <summary>Where this harness's daemon records the edges it applied — its own, per test.</summary>
        public string JournalDir { get; }

        /// <summary>Every line the daemon has recorded, oldest first.</summary>
        public IReadOnlyList<string> JournalLines =>
            Directory.Exists(JournalDir)
                ? [.. Directory.GetFiles(JournalDir, "*.ndjson").OrderBy(f => f, StringComparer.Ordinal)
                    .SelectMany(File.ReadAllLines)]
                : [];

        private Harness(IFirewallDriver driver, FirewallBackend backend, InMemoryUfwProfileStore store, FakeProcessRunner runner)
        {
            Store = store;
            Runner = runner;
            SocketPath = Path.Combine(Path.GetTempPath(), $"kgfw{Guid.NewGuid():N}.sock");
            JournalDir = Path.Combine(Path.GetTempPath(), $"kgfw-events-{Guid.NewGuid():N}");

            _listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            _listener.Bind(new UnixDomainSocketEndPoint(SocketPath));
            _listener.Listen(16);

            var service = new FirewallService(driver, NullLogger<FirewallService>.Instance);
            // TimeSpan.Zero = resident: these request/response tests drive the daemon explicitly and tear it
            // down via the CTS, so idle-exit must stay out of the way. Idle-exit has its own tests below.
            var journal = new FirewallJournal(
                new EventJournalWriter(
                    new EventJournalWriterOptions { Producer = "kgsm-firewall", Directory = JournalDir },
                    NullLogger<EventJournalWriter>.Instance),
                NullLogger<FirewallJournal>.Instance);
            var daemon = new FirewallDaemon(_listener, service, journal, NoLifecycle(), backend, TimeSpan.Zero, NullLogger<FirewallDaemon>.Instance);
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
    public async Task EnsureOpen_UfwInactive_StillExit0_RuleStagedNotAFailure()
    {
        // ufw is installed but DISABLED: `allow` succeeds (rule persisted) and the post-allow `status`
        // reports inactive -> the daemon replies `applied-inactive`. The bundled CLI must map that to
        // Success, NOT OpFailed — else a kgsm install on an inactive-ufw host would abort under the
        // hard-fail contract even though the rule is correctly owned (it enforces on `ufw enable`).
        await using var h = Harness.Ufw((file, args) =>
            args.Count > 0 && args[0] == "status"
                ? new ProcessResult(0, "Status: inactive", "")
                : new ProcessResult(0, "", ""));

        int code = await FirewallCliClient.RunAsync(
            "ensure-open", ["factorio", "34197/udp"], h.Options, default);

        Assert.Equal(ExitCodes.Success, code);
        Assert.True(h.Store.Files.ContainsKey("kgsm-factorio")); // rule still owned, not rolled back
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

    // ---- idle-exit (the Inc-1 follow-up) ----
    //
    // The daemon honours the idle timeout unconditionally; DaemonHost is what gates it on socket
    // activation (resident otherwise). These drive FirewallDaemon directly so the timeout is exercised in
    // isolation, without external cancellation — the daemon must end RunAsync ON ITS OWN.

    /// <summary>
    /// A journal for the idle-exit tests, which are about the accept loop and record nothing. It writes
    /// to a temp directory rather than being a null object, so an accidental write shows up as a stray
    /// file instead of vanishing.
    /// </summary>
    /// <summary>
    /// A lifecycle over a throwaway journal.
    /// </summary>
    /// <remarks>
    /// This daemon reports degradation only, and these tests run a backend that can apply — so a line
    /// written through this would itself be the finding.
    /// </remarks>
    private static LeafLifecycle NoLifecycle() =>
        new(new EventJournalWriter(
                new EventJournalWriterOptions
                {
                    Producer = "kgsm-firewall",
                    Directory = Path.Combine(Path.GetTempPath(), $"kgfw-lifecycle-{Guid.NewGuid():N}"),
                },
                NullLogger<EventJournalWriter>.Instance),
            NullLogger<LeafLifecycle>.Instance);

    private static FirewallJournal NoJournal() =>
        new(new EventJournalWriter(
                new EventJournalWriterOptions
                {
                    Producer = "kgsm-firewall",
                    Directory = Path.Combine(Path.GetTempPath(), $"kgfw-idle-events-{Guid.NewGuid():N}"),
                },
                NullLogger<EventJournalWriter>.Instance),
            NullLogger<FirewallJournal>.Instance);

    private static (Socket listener, string path) BindTempSocket()
    {
        string path = Path.Combine(Path.GetTempPath(), $"kgfw-idle-{Guid.NewGuid():N}.sock");
        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(path));
        listener.Listen(16);
        return (listener, path);
    }

    [Fact]
    public async Task IdleTimeout_NoConnections_DaemonExitsWithoutCancellation()
    {
        var (listener, path) = BindTempSocket();
        try
        {
            var service = new FirewallService(new NullFirewallDriver(FirewallBackend.Ufw), NullLogger<FirewallService>.Instance);
            var daemon = new FirewallDaemon(
                listener, service, NoJournal(), NoLifecycle(), FirewallBackend.Ufw, TimeSpan.FromMilliseconds(150), NullLogger<FirewallDaemon>.Instance);

            Task serve = daemon.RunAsync(CancellationToken.None);

            // No token is ever cancelled: the daemon must return once the idle window elapses.
            Task finished = await Task.WhenAny(serve, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(serve, finished);
            await serve; // observe clean completion (no exception)
        }
        finally
        {
            listener.Dispose();
            try { File.Delete(path); } catch { /* best-effort */ }
        }
    }

    [Fact]
    public async Task IdleTimeoutZero_StaysResident()
    {
        var (listener, path) = BindTempSocket();
        using var cts = new CancellationTokenSource();
        try
        {
            var service = new FirewallService(new NullFirewallDriver(FirewallBackend.Ufw), NullLogger<FirewallService>.Instance);
            var daemon = new FirewallDaemon(
                listener, service, NoJournal(), NoLifecycle(), FirewallBackend.Ufw, TimeSpan.Zero, NullLogger<FirewallDaemon>.Instance);

            Task serve = daemon.RunAsync(cts.Token);

            // Zero disables idle-exit: still running well after any idle window would have elapsed.
            Task finished = await Task.WhenAny(serve, Task.Delay(TimeSpan.FromMilliseconds(500)));
            Assert.NotSame(serve, finished);
            Assert.False(serve.IsCompleted);

            await cts.CancelAsync();
            await serve.WaitAsync(TimeSpan.FromSeconds(5)); // only the token ends it
        }
        finally
        {
            listener.Dispose();
            try { File.Delete(path); } catch { /* best-effort */ }
        }
    }

    [Fact]
    public async Task IdleTimeout_DoesNotExitWhileHandlerBusy_ThenExitsWhenIdle()
    {
        var (listener, path) = BindTempSocket();
        var release = new TaskCompletionSource();
        var driver = new FakeFirewallDriver { OnEnsureOpen = _ => release.Task };
        try
        {
            var service = new FirewallService(driver, NullLogger<FirewallService>.Instance);
            var daemon = new FirewallDaemon(
                listener, service, NoJournal(), NoLifecycle(), FirewallBackend.Ufw, TimeSpan.FromMilliseconds(150), NullLogger<FirewallDaemon>.Instance);
            Task serve = daemon.RunAsync(CancellationToken.None);

            var options = new FirewallOptions { SocketPath = path };
            // The handler blocks in the driver hook, so it stays "in flight" until we release it.
            Task<int> client = FirewallCliClient.RunAsync("ensure-open", ["factorio", "34197/udp"], options, default);

            // Several idle windows pass; the daemon must NOT exit while a handler is active — abandoning a
            // fire-and-forget handler mid-ufw-write is exactly what the active-connection guard prevents.
            await Task.Delay(TimeSpan.FromMilliseconds(600));
            Assert.False(serve.IsCompleted);
            Assert.False(client.IsCompleted);

            release.SetResult();                                   // handler finishes -> active drops to 0
            Assert.Equal(ExitCodes.Success, await client);

            // Now genuinely idle: the daemon exits on its own.
            Task finished = await Task.WhenAny(serve, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(serve, finished);
            await serve;
        }
        finally
        {
            listener.Dispose();
            try { File.Delete(path); } catch { /* best-effort */ }
        }
    }
}
