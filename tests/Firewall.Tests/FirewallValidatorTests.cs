using TheKrystalShip.KGSM.Firewall.Core;

namespace TheKrystalShip.KGSM.Firewall.Tests;

public class FirewallValidatorTests
{
    [Theory]
    [InlineData("factorio")]
    [InlineData("my-server_1")]
    [InlineData("ABC123")]
    public void ValidInstanceNames_Accepted(string name)
        => Assert.True(FirewallValidator.IsValidInstanceName(name));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("bad name")]      // space
    [InlineData("../etc")]        // path traversal
    [InlineData("name;rm -rf")]   // shell metacharacters
    [InlineData("a.b")]           // dot
    public void InvalidInstanceNames_Rejected(string? name)
        => Assert.False(FirewallValidator.IsValidInstanceName(name));

    [Theory]
    [InlineData(1, true)]
    [InlineData(65535, true)]
    [InlineData(0, false)]
    [InlineData(65536, false)]
    [InlineData(-1, false)]
    public void PortBounds_Enforced(int port, bool valid)
        => Assert.Equal(valid, FirewallValidator.IsValidPort(port));

    [Fact]
    public void ValidateOpen_Valid_ReturnsNull()
    {
        PortSpec[] ports = [new(27015, 27020, PortProtocol.Udp), new(27016, 27016, PortProtocol.Tcp)];
        Assert.Null(FirewallValidator.ValidateOpen("factorio", ports));
    }

    [Fact]
    public void ValidateOpen_BadInstance_ReturnsError()
    {
        PortSpec[] ports = [new(80, 80, PortProtocol.Tcp)];
        Assert.NotNull(FirewallValidator.ValidateOpen("bad name", ports));
    }

    [Fact]
    public void ValidateOpen_PortOutOfRange_ReturnsError()
    {
        PortSpec[] ports = [new(0, 0, PortProtocol.Tcp)];
        Assert.NotNull(FirewallValidator.ValidateOpen("factorio", ports));
    }

    [Fact]
    public void ValidateOpen_InvertedRange_ReturnsError()
    {
        PortSpec[] ports = [new(3000, 2000, PortProtocol.Tcp)];
        Assert.NotNull(FirewallValidator.ValidateOpen("factorio", ports));
    }
}
