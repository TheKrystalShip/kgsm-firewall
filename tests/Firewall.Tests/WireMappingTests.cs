using TheKrystalShip.KGSM.Firewall.Contracts;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Firewall.Host;

namespace TheKrystalShip.KGSM.Firewall.Tests;

public class WireMappingTests
{
    // Internal enums can't be parameters of public xunit methods (CS0051), so pass the int and cast.
    [Theory]
    [InlineData((int)FirewallBackend.None, "none")]
    [InlineData((int)FirewallBackend.Ufw, "ufw")]
    [InlineData((int)FirewallBackend.Firewalld, "firewalld")]
    [InlineData((int)FirewallBackend.Nftables, "nftables")]
    [InlineData((int)FirewallBackend.Iptables, "iptables")]
    public void BackendToken_MapsEveryBackend(int backend, string token)
        => Assert.Equal(token, WireMapping.BackendToken((FirewallBackend)backend));

    [Fact]
    public void TryToPortSpecs_Null_IsEmptyAndOk()
    {
        Assert.True(WireMapping.TryToPortSpecs(null, out List<PortSpec> specs, out string? err));
        Assert.Empty(specs);
        Assert.Null(err);
    }

    [Fact]
    public void TryToPortSpecs_Valid_Maps()
    {
        Assert.True(WireMapping.TryToPortSpecs(
            [new PortDto(2456, 2457, "udp")], out List<PortSpec> specs, out _));
        PortSpec spec = Assert.Single(specs);
        Assert.Equal(new PortSpec(2456, 2457, PortProtocol.Udp), spec);
    }

    [Fact]
    public void TryToPortSpecs_BadProtocol_FailsHonestly()
    {
        Assert.False(WireMapping.TryToPortSpecs(
            [new PortDto(80, 80, "sctp")], out List<PortSpec> specs, out string? err));
        Assert.Empty(specs);
        Assert.Contains("sctp", err);
    }

    [Theory]
    [InlineData((int)FirewallStatus.Applied, Outcomes.Applied, true)]
    [InlineData((int)FirewallStatus.AppliedInactive, Outcomes.AppliedInactive, true)] // staged-not-enforced is a success
    [InlineData((int)FirewallStatus.Removed, Outcomes.Removed, true)]
    [InlineData((int)FirewallStatus.NoOp, Outcomes.NoOp, true)]
    [InlineData((int)FirewallStatus.Unsupported, Outcomes.Unsupported, false)]
    [InlineData((int)FirewallStatus.Failed, Outcomes.Failed, false)]
    public void ToResponse_FirewallResult_MapsOutcomeAndOk(int statusInt, string outcome, bool ok)
    {
        var result = new FirewallResult((FirewallStatus)statusInt, "detail");
        FirewallResponse response = WireMapping.ToResponse(result, "ufw");
        Assert.Equal(outcome, response.Outcome);
        Assert.Equal(ok, response.Ok);
        Assert.Equal("ufw", response.Backend);
    }

    [Fact]
    public void ToResponse_OwnedRules_Unknown_IsNotOk()
    {
        FirewallResponse response = WireMapping.ToResponse(OwnedRulesResult.Unknown, "ufw");
        Assert.Equal(Outcomes.Unknown, response.Outcome);
        Assert.False(response.Ok); // honest-unknown must never read as a successful "nothing open"
    }

    [Fact]
    public void ToResponse_OwnedRules_Ok_CarriesPorts()
    {
        var owned = OwnedRulesResult.Ok([new OwnedRule("factorio", [new PortSpec(34197, 34197, PortProtocol.Udp)])]);
        FirewallResponse response = WireMapping.ToResponse(owned, "ufw");

        Assert.True(response.Ok);
        OwnedRuleDto rule = Assert.Single(response.Rules!);
        Assert.Equal("factorio", rule.Instance);
        Assert.Equal(34197, rule.Ports[0].Start);
        Assert.Equal("udp", rule.Ports[0].Protocol);
    }

    // The 1.1.0 enforcement axis: every list reply carries the backend's enforcement token so the consumer
    // can tell "inactive → all open" from "active + no rule → closed", never inferring closed from inactive.
    [Theory]
    [InlineData((int)Enforcement.Enforcing, Enforcements.Enforcing)]
    [InlineData((int)Enforcement.Inactive, Enforcements.Inactive)]
    [InlineData((int)Enforcement.Unknown, Enforcements.Unknown)]
    public void ToResponse_OwnedRules_CarriesEnforcementToken(int enforcementInt, string token)
    {
        var owned = OwnedRulesResult.Ok([], (Enforcement)enforcementInt);
        FirewallResponse response = WireMapping.ToResponse(owned, "ufw");
        Assert.Equal(token, response.Enforcement);
    }

    [Fact]
    public void ToResponse_OwnedRules_UnknownQuery_EnforcementUnknown()
    {
        // A can't-enumerate result knows neither rules nor enforcement → enforcement token is unknown.
        FirewallResponse response = WireMapping.ToResponse(OwnedRulesResult.Unknown, "ufw");
        Assert.Equal(Enforcements.Unknown, response.Enforcement);
    }
}
