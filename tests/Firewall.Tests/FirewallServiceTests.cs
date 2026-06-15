using Microsoft.Extensions.Logging.Abstractions;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Firewall.Tests.Fakes;

namespace TheKrystalShip.KGSM.Firewall.Tests;

public class FirewallServiceTests
{
    private static FirewallService Service(FakeFirewallDriver driver)
        => new(driver, NullLogger<FirewallService>.Instance);

    [Fact]
    public async Task EnsureOpen_InvalidInstance_Failed_DriverNotCalled()
    {
        var driver = new FakeFirewallDriver();
        FirewallResult result = await Service(driver)
            .EnsureOpenAsync("bad name", [new(80, 80, PortProtocol.Tcp)]);

        Assert.Equal(FirewallStatus.Failed, result.Status);
        Assert.Equal(0, driver.EnsureOpenCalls);
    }

    [Fact]
    public async Task EnsureOpen_EmptyPorts_NoOp_DriverNotCalled()
    {
        var driver = new FakeFirewallDriver();
        FirewallResult result = await Service(driver).EnsureOpenAsync("factorio", []);

        Assert.Equal(FirewallStatus.NoOp, result.Status);
        Assert.Equal(0, driver.EnsureOpenCalls);
    }

    [Fact]
    public async Task EnsureOpen_Valid_DispatchesToDriver()
    {
        var driver = new FakeFirewallDriver { EnsureResult = FirewallResult.Applied("ok") };
        FirewallResult result = await Service(driver)
            .EnsureOpenAsync("factorio", [new(34197, 34197, PortProtocol.Udp)]);

        Assert.Equal(FirewallStatus.Applied, result.Status);
        Assert.Equal(1, driver.EnsureOpenCalls);
    }

    [Fact]
    public async Task EnsureOpen_BackendCannotApply_Unsupported_DriverNotCalled()
    {
        var driver = new FakeFirewallDriver { Capabilities = new FirewallCapabilities(false, true, true) };
        FirewallResult result = await Service(driver)
            .EnsureOpenAsync("factorio", [new(34197, 34197, PortProtocol.Udp)]);

        Assert.Equal(FirewallStatus.Unsupported, result.Status);
        Assert.Equal(0, driver.EnsureOpenCalls);
    }

    [Fact]
    public async Task Remove_InvalidInstance_Failed_DriverNotCalled()
    {
        var driver = new FakeFirewallDriver();
        FirewallResult result = await Service(driver).RemoveAsync("../etc");

        Assert.Equal(FirewallStatus.Failed, result.Status);
        Assert.Equal(0, driver.RemoveCalls);
    }

    [Fact]
    public async Task ListOwned_InvalidInstance_Unknown_DriverNotCalled()
    {
        var driver = new FakeFirewallDriver();
        OwnedRulesResult result = await Service(driver).ListOwnedAsync("bad name");

        Assert.Equal(OwnedQueryStatus.Unknown, result.Status);
        Assert.Equal(0, driver.ListCalls);
    }

    [Fact]
    public async Task ListOwned_BackendCannotList_Unsupported()
    {
        var driver = new FakeFirewallDriver { Capabilities = new FirewallCapabilities(true, true, false) };
        OwnedRulesResult result = await Service(driver).ListOwnedAsync();

        Assert.Equal(OwnedQueryStatus.Unsupported, result.Status);
        Assert.Equal(0, driver.ListCalls);
    }

    [Fact]
    public async Task ListOwned_Valid_DispatchesToDriver()
    {
        var driver = new FakeFirewallDriver
        {
            ListResult = OwnedRulesResult.Ok([new OwnedRule("factorio", [new PortSpec(34197, 34197, PortProtocol.Udp)])]),
        };
        OwnedRulesResult result = await Service(driver).ListOwnedAsync("factorio");

        Assert.Equal(OwnedQueryStatus.Ok, result.Status);
        Assert.Equal(1, driver.ListCalls);
        Assert.Single(result.Rules);
    }
}
