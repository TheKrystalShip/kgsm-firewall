using System.Text.Json;
using TheKrystalShip.KGSM.Firewall.Contracts;
using TheKrystalShip.KGSM.Firewall.Host;

namespace TheKrystalShip.KGSM.Firewall.Tests;

public class WireProtocolTests
{
    [Fact]
    public void Request_RoundTrips_CamelCase()
    {
        var request = new FirewallRequest(
            FirewallOps.EnsureOpen, "factorio",
            [new PortDto(34197, 34197, "udp"), new PortDto(27015, 27020, "tcp")]);

        string json = JsonSerializer.Serialize(request, WireJsonContext.Default.FirewallRequest);

        // camelCase property names on the wire; the op VALUE is the literal token.
        Assert.Contains("\"op\":\"ensure-open\"", json);
        Assert.Contains("\"instance\":\"factorio\"", json);
        Assert.Contains("\"protocol\":\"udp\"", json);

        FirewallRequest? back = JsonSerializer.Deserialize(json, WireJsonContext.Default.FirewallRequest);
        Assert.NotNull(back);
        Assert.Equal(FirewallOps.EnsureOpen, back!.Op);
        Assert.Equal("factorio", back.Instance);
        Assert.Equal(2, back.Ports!.Length);
        Assert.Equal(27020, back.Ports[1].End);
    }

    [Fact]
    public void Response_NullCollections_AreOmitted()
    {
        // WhenWritingNull keeps a bare ack tight — no "rules":null / "capabilities":null noise.
        var response = new FirewallResponse(true, Outcomes.Applied, "ufw", "opened 1 spec");
        string json = JsonSerializer.Serialize(response, WireJsonContext.Default.FirewallResponse);

        Assert.DoesNotContain("rules", json);
        Assert.DoesNotContain("capabilities", json);
        Assert.Contains("\"outcome\":\"applied\"", json);
    }

    [Fact]
    public void Response_WithRules_RoundTrips()
    {
        var response = new FirewallResponse(
            true, Outcomes.Ok, "ufw",
            Rules: [new OwnedRuleDto("valheim", [new PortDto(2456, 2457, "udp")])]);

        string json = JsonSerializer.Serialize(response, WireJsonContext.Default.FirewallResponse);
        FirewallResponse? back = JsonSerializer.Deserialize(json, WireJsonContext.Default.FirewallResponse);

        Assert.NotNull(back);
        OwnedRuleDto rule = Assert.Single(back!.Rules!);
        Assert.Equal("valheim", rule.Instance);
        Assert.Equal(2457, rule.Ports[0].End);
    }

    [Theory]
    [InlineData("34197/udp", 34197, 34197, "udp")]
    [InlineData("27015/tcp", 27015, 27015, "tcp")]
    [InlineData("27015:27020/tcp", 27015, 27020, "tcp")]
    [InlineData("2456:2457/UDP", 2456, 2457, "udp")] // proto lower-cased
    public void ParsePortToken_Valid(string token, int start, int end, string proto)
    {
        PortDto? dto = FirewallCliClient.ParsePortToken(token);
        Assert.NotNull(dto);
        Assert.Equal(start, dto!.Start);
        Assert.Equal(end, dto.End);
        Assert.Equal(proto, dto.Protocol);
    }

    [Theory]
    [InlineData("34197")]          // no proto
    [InlineData("34197/")]         // empty proto
    [InlineData("/udp")]           // no port
    [InlineData("34197/sctp")]     // unsupported proto
    [InlineData("abc/udp")]        // non-numeric port
    [InlineData("10:/udp")]        // half range
    [InlineData("")]               // empty
    public void ParsePortToken_Invalid_ReturnsNull(string token)
        => Assert.Null(FirewallCliClient.ParsePortToken(token));
}
