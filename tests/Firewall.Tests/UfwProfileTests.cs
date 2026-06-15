using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Firewall.Drivers.Ufw;

namespace TheKrystalShip.KGSM.Firewall.Tests;

public class UfwProfileTests
{
    [Fact]
    public void NameFor_PrefixesOwnershipTag()
        => Assert.Equal("kgsm-factorio", UfwProfile.NameFor("factorio"));

    [Theory]
    [InlineData("kgsm-factorio", "factorio")]
    [InlineData("kgsm-my-server_1", "my-server_1")]
    public void InstanceFromName_StripsOurPrefix(string profile, string expected)
        => Assert.Equal(expected, UfwProfile.InstanceFromName(profile));

    [Theory]
    [InlineData("other-app")]     // not ours
    [InlineData("kgsm-")]         // prefix only, no instance
    public void InstanceFromName_NotOurs_ReturnsNull(string profile)
        => Assert.Null(UfwProfile.InstanceFromName(profile));

    [Fact]
    public void Render_SinglePort_ProducesProfile()
    {
        string body = UfwProfile.Render("factorio", [new(34197, 34197, PortProtocol.Udp)]);
        Assert.Contains("[kgsm-factorio]", body);
        Assert.Contains("title=kgsm-factorio", body);
        Assert.Contains("ports=34197/udp", body);
    }

    [Fact]
    public void Render_RangeAndMulti_JoinsWithPipe()
    {
        string body = UfwProfile.Render(
            "valheim", [new(27015, 27020, PortProtocol.Udp), new(27016, 27016, PortProtocol.Tcp)]);
        Assert.Contains("ports=27015:27020/udp|27016/tcp", body);
    }

    [Fact]
    public void RenderThenParse_RoundTrips()
    {
        PortSpec[] ports = [new(27015, 27020, PortProtocol.Udp), new(80, 80, PortProtocol.Tcp)];
        string body = UfwProfile.Render("svc", ports);
        IReadOnlyList<PortSpec> parsed = UfwProfile.ParsePorts(body);
        Assert.Equal(ports, parsed);
    }

    [Fact]
    public void ParsePorts_SkipsProtoLessTokens()
    {
        // A hand-edited profile with a proto-less token: we don't guess tcp — that token is dropped.
        IReadOnlyList<PortSpec> parsed = UfwProfile.ParsePorts("ports=8080|9090/tcp\n");
        Assert.Equal([new PortSpec(9090, 9090, PortProtocol.Tcp)], parsed);
    }

    [Fact]
    public void ParsePorts_NoPortsLine_ReturnsEmpty()
        => Assert.Empty(UfwProfile.ParsePorts("[kgsm-x]\ntitle=kgsm-x\n"));
}
