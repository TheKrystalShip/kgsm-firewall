using Microsoft.Extensions.Logging.Abstractions;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Firewall.Tests.Fakes;

namespace TheKrystalShip.KGSM.Firewall.Tests;

public class BackendDetectorTests
{
    private static BackendDetector Detector(FakeProcessRunner runner)
        => new(runner, NullLogger<BackendDetector>.Instance);

    private static readonly ProcessResult NotPresent = new(ProcessResult.NoExitCode, "", "not found");

    [Fact]
    public async Task Override_Wins_WithoutProbing()
    {
        var runner = new FakeProcessRunner { Handler = (_, _) => NotPresent };
        var options = new FirewallOptions { BackendOverride = FirewallBackend.Firewalld };

        FirewallBackend backend = await Detector(runner).DetectAsync(options);

        Assert.Equal(FirewallBackend.Firewalld, backend);
        Assert.Empty(runner.Calls); // no probing when forced
    }

    [Fact]
    public async Task UfwActive_Detected()
    {
        var runner = new FakeProcessRunner
        {
            Handler = (file, _) => file == "ufw"
                ? new ProcessResult(0, "Status: active", "")
                : NotPresent,
        };

        Assert.Equal(FirewallBackend.Ufw, await Detector(runner).DetectAsync(new FirewallOptions()));
    }

    [Fact]
    public async Task UfwInactive_FirewalldRunning_DetectsFirewalld()
    {
        var runner = new FakeProcessRunner
        {
            Handler = (file, _) => file switch
            {
                "ufw" => new ProcessResult(0, "Status: inactive", ""),
                "firewall-cmd" => new ProcessResult(0, "running", ""),
                _ => NotPresent,
            },
        };

        Assert.Equal(FirewallBackend.Firewalld, await Detector(runner).DetectAsync(new FirewallOptions()));
    }

    [Fact]
    public async Task NoManagerActive_NftPresent_DetectsNftables()
    {
        var runner = new FakeProcessRunner
        {
            Handler = (file, _) => file == "nft" ? new ProcessResult(0, "nftables v1.0", "") : NotPresent,
        };

        Assert.Equal(FirewallBackend.Nftables, await Detector(runner).DetectAsync(new FirewallOptions()));
    }

    [Fact]
    public async Task OnlyIptablesPresent_DetectsIptables()
    {
        var runner = new FakeProcessRunner
        {
            Handler = (file, _) => file == "iptables" ? new ProcessResult(0, "iptables v1.8", "") : NotPresent,
        };

        Assert.Equal(FirewallBackend.Iptables, await Detector(runner).DetectAsync(new FirewallOptions()));
    }

    [Fact]
    public async Task NothingPresent_DetectsNone()
    {
        var runner = new FakeProcessRunner { Handler = (_, _) => NotPresent };

        Assert.Equal(FirewallBackend.None, await Detector(runner).DetectAsync(new FirewallOptions()));
    }

    [Fact]
    public async Task Precedence_ActiveUfw_BeatsEverythingElsePresent()
    {
        // Everything is installed AND ufw is active: ufw (the active high-level manager) must win; we
        // never drop to nft/iptables underneath it.
        var runner = new FakeProcessRunner
        {
            Handler = (file, _) => file switch
            {
                "ufw" => new ProcessResult(0, "Status: active", ""),
                "firewall-cmd" => new ProcessResult(0, "running", ""),
                _ => new ProcessResult(0, "present", ""),
            },
        };

        Assert.Equal(FirewallBackend.Ufw, await Detector(runner).DetectAsync(new FirewallOptions()));
    }
}
