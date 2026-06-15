using Microsoft.Extensions.Logging.Abstractions;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Firewall.Drivers.Ufw;
using TheKrystalShip.KGSM.Firewall.Tests.Fakes;

namespace TheKrystalShip.KGSM.Firewall.Tests;

public class UfwDriverTests
{
    private static UfwDriver Driver(FakeProcessRunner runner, InMemoryUfwProfileStore store)
        => new(runner, store, NullLogger<UfwDriver>.Instance);

    [Fact]
    public async Task EnsureOpen_HappyPath_WritesProfileAndAllows()
    {
        var runner = new FakeProcessRunner();
        var store = new InMemoryUfwProfileStore();

        FirewallResult result = await Driver(runner, store)
            .EnsureOpenAsync("factorio", [new(34197, 34197, PortProtocol.Udp)]);

        Assert.Equal(FirewallStatus.Applied, result.Status);
        Assert.True(store.Files.ContainsKey("kgsm-factorio"));
        Assert.Contains("ports=34197/udp", store.Files["kgsm-factorio"]);
        Assert.True(runner.WasCalledWith("ufw", "app", "update", "kgsm-factorio"));
        Assert.True(runner.WasCalledWith("ufw", "allow", "kgsm-factorio"));
    }

    [Fact]
    public async Task EnsureOpen_UfwAllowFails_RollsBackProfile()
    {
        var runner = new FakeProcessRunner
        {
            // `ufw allow` errors; everything else is fine.
            Handler = (file, args) => args.Count > 0 && args[0] == "allow"
                ? new ProcessResult(1, "", "ERROR: could not insert rule")
                : new ProcessResult(0, "", ""),
        };
        var store = new InMemoryUfwProfileStore();

        FirewallResult result = await Driver(runner, store)
            .EnsureOpenAsync("factorio", [new(34197, 34197, PortProtocol.Udp)]);

        Assert.Equal(FirewallStatus.Failed, result.Status);
        // The orphan profile must be cleaned up so a failed apply leaves no ownership tag behind.
        Assert.False(store.Files.ContainsKey("kgsm-factorio"));
    }

    [Fact]
    public async Task EnsureOpen_ProfileWriteThrows_FailsWithoutAllow()
    {
        var runner = new FakeProcessRunner();
        var store = new InMemoryUfwProfileStore { ThrowOnWrite = true };

        FirewallResult result = await Driver(runner, store)
            .EnsureOpenAsync("factorio", [new(34197, 34197, PortProtocol.Udp)]);

        Assert.Equal(FirewallStatus.Failed, result.Status);
        Assert.DoesNotContain(runner.Calls, c => c.Args.Contains("allow"));
    }

    [Fact]
    public async Task Remove_DeletesRuleAndProfile()
    {
        var runner = new FakeProcessRunner();
        var store = new InMemoryUfwProfileStore();
        store.Files["kgsm-factorio"] = "irrelevant";

        FirewallResult result = await Driver(runner, store).RemoveAsync("factorio");

        Assert.Equal(FirewallStatus.Removed, result.Status);
        Assert.False(store.Files.ContainsKey("kgsm-factorio"));
        Assert.True(runner.WasCalledWith("ufw", "delete", "allow", "kgsm-factorio"));
    }

    [Fact]
    public async Task ListOwned_StatusUnreadable_ReturnsUnknown_NotEmpty()
    {
        // The honest-unknown invariant: a non-zero `ufw status` (e.g. non-root) must NOT be reported as
        // "nothing open" — that would let kgsm-api fabricate open:false.
        var runner = new FakeProcessRunner { Handler = (_, _) => new ProcessResult(1, "", "permission denied") };
        var store = new InMemoryUfwProfileStore();
        store.Files["kgsm-factorio"] = UfwProfile.Render("factorio", [new(34197, 34197, PortProtocol.Udp)]);

        OwnedRulesResult result = await Driver(runner, store).ListOwnedAsync();

        Assert.Equal(OwnedQueryStatus.Unknown, result.Status);
        Assert.Empty(result.Rules);
    }

    [Fact]
    public async Task ListOwned_ActiveProfile_ReportsParsedPorts()
    {
        var runner = new FakeProcessRunner
        {
            Handler = (_, args) => args.Count > 0 && args[0] == "status"
                ? new ProcessResult(0, "Status: active\n\nTo  Action  From\nkgsm-factorio  ALLOW  Anywhere", "")
                : new ProcessResult(0, "", ""),
        };
        var store = new InMemoryUfwProfileStore();
        store.Files["kgsm-factorio"] = UfwProfile.Render("factorio", [new(34197, 34197, PortProtocol.Udp)]);

        OwnedRulesResult result = await Driver(runner, store).ListOwnedAsync();

        Assert.Equal(OwnedQueryStatus.Ok, result.Status);
        OwnedRule rule = Assert.Single(result.Rules);
        Assert.Equal("factorio", rule.Instance);
        Assert.Equal([new PortSpec(34197, 34197, PortProtocol.Udp)], rule.Ports);
    }

    [Fact]
    public async Task ListOwned_ProfilePresentButNotActive_Excluded()
    {
        // Profile file exists but `ufw status` does not reference it -> not actually open -> excluded.
        var runner = new FakeProcessRunner
        {
            Handler = (_, args) => args.Count > 0 && args[0] == "status"
                ? new ProcessResult(0, "Status: active\n\nTo  Action  From\n", "")
                : new ProcessResult(0, "", ""),
        };
        var store = new InMemoryUfwProfileStore();
        store.Files["kgsm-factorio"] = UfwProfile.Render("factorio", [new(34197, 34197, PortProtocol.Udp)]);

        OwnedRulesResult result = await Driver(runner, store).ListOwnedAsync();

        Assert.Equal(OwnedQueryStatus.Ok, result.Status);
        Assert.Empty(result.Rules);
    }

    [Fact]
    public async Task ListOwned_FiltersByInstance()
    {
        var runner = new FakeProcessRunner
        {
            Handler = (_, args) => args.Count > 0 && args[0] == "status"
                ? new ProcessResult(0, "Status: active\nkgsm-factorio ALLOW Anywhere\nkgsm-valheim ALLOW Anywhere", "")
                : new ProcessResult(0, "", ""),
        };
        var store = new InMemoryUfwProfileStore();
        store.Files["kgsm-factorio"] = UfwProfile.Render("factorio", [new(34197, 34197, PortProtocol.Udp)]);
        store.Files["kgsm-valheim"] = UfwProfile.Render("valheim", [new(2456, 2457, PortProtocol.Udp)]);

        OwnedRulesResult result = await Driver(runner, store).ListOwnedAsync("valheim");

        OwnedRule rule = Assert.Single(result.Rules);
        Assert.Equal("valheim", rule.Instance);
    }

    [Theory]
    [InlineData("kgsm-factorio              ALLOW       Anywhere", "kgsm-factorio", true)]
    [InlineData("kgsm-factorio (v6)         ALLOW       Anywhere (v6)", "kgsm-factorio", true)]
    [InlineData("kgsm-factorio              ALLOW       Anywhere", "kgsm-fact", false)]   // prefix collision
    [InlineData("Status: active", "kgsm-factorio", false)]                                 // not a rule line
    [InlineData("To                         Action      From", "kgsm-factorio", false)]    // header
    public void StatusReferencesApp_MatchesExactToken_NotSubstring(string statusLine, string app, bool expected)
        => Assert.Equal(expected, UfwDriver.StatusReferencesApp(statusLine, app));

    [Fact]
    public async Task ListOwned_PrefixCollision_OnlyExactMatchReported()
    {
        // Two owned profiles where one name prefixes the other; only the longer's rule is active. A
        // substring check would wrongly report the shorter as open too — the exact-token match must not.
        var runner = new FakeProcessRunner
        {
            Handler = (_, args) => args.Count > 0 && args[0] == "status"
                ? new ProcessResult(0, "Status: active\nkgsm-factorio              ALLOW       Anywhere", "")
                : new ProcessResult(0, "", ""),
        };
        var store = new InMemoryUfwProfileStore();
        store.Files["kgsm-fact"] = UfwProfile.Render("fact", [new(1000, 1000, PortProtocol.Tcp)]);
        store.Files["kgsm-factorio"] = UfwProfile.Render("factorio", [new(34197, 34197, PortProtocol.Udp)]);

        OwnedRulesResult result = await Driver(runner, store).ListOwnedAsync();

        OwnedRule rule = Assert.Single(result.Rules);
        Assert.Equal("factorio", rule.Instance);
    }

    // Verbatim plain `ufw status` output captured from a live ufw 0.36.2 with our app rule installed
    // (range + multi-proto). An app rule renders as the app NAME in the "To" column (NOT resolved ports —
    // that is verbose mode), with a "(v6)" twin. Raw port rules (22/tcp, ranges) sit alongside. Pinning
    // the real shape guards the matcher against silent ufw-format drift.
    private const string RealUfwStatus =
        "Status: active\n" +
        "\n" +
        "To                         Action      From\n" +
        "--                         ------      ----\n" +
        "22                         ALLOW       Anywhere\n" +
        "26900:26903/tcp            ALLOW       Anywhere\n" +
        "22/tcp                     ALLOW       Anywhere\n" +
        "kgsm-zzztest               ALLOW       Anywhere\n" +
        "kgsm-zzztest (v6)          ALLOW       Anywhere (v6)\n";

    [Fact]
    public void StatusReferencesApp_RealCapturedFormat_MatchesAppName()
    {
        // The matcher is only ever called with kgsm-<instance> profile names (raw port rules like "22"
        // never collide with our prefix), so these are the cases that matter.
        Assert.True(UfwDriver.StatusReferencesApp(RealUfwStatus, "kgsm-zzztest"));
        Assert.False(UfwDriver.StatusReferencesApp(RealUfwStatus, "kgsm-zzz"));      // prefix, no such rule
        Assert.False(UfwDriver.StatusReferencesApp(RealUfwStatus, "kgsm-zzztes"));   // prefix of the real one
        Assert.False(UfwDriver.StatusReferencesApp(RealUfwStatus, "kgsm-other"));    // absent
    }

    [Fact]
    public async Task ListOwned_AgainstRealCapturedStatus_ReportsOurInstance()
    {
        var runner = new FakeProcessRunner
        {
            Handler = (_, args) => args.Count > 0 && args[0] == "status"
                ? new ProcessResult(0, RealUfwStatus, "")
                : new ProcessResult(0, "", ""),
        };
        var store = new InMemoryUfwProfileStore();
        store.Files["kgsm-zzztest"] = UfwProfile.Render(
            "zzztest", [new(51820, 51825, PortProtocol.Udp), new(51830, 51830, PortProtocol.Tcp)]);

        OwnedRulesResult result = await Driver(runner, store).ListOwnedAsync();

        OwnedRule rule = Assert.Single(result.Rules);
        Assert.Equal("zzztest", rule.Instance);
        Assert.Equal(
            [new PortSpec(51820, 51825, PortProtocol.Udp), new PortSpec(51830, 51830, PortProtocol.Tcp)],
            rule.Ports);
    }
}
