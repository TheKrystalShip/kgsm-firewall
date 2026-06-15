using TheKrystalShip.KGSM.Firewall.Core;

namespace TheKrystalShip.KGSM.Firewall.Tests;

public class FirewallOptionsTests
{
    // Pins the configurability contract of KGSM_FIREWALL_IDLE_TIMEOUT (the documented --help behaviour):
    // unset/blank/non-numeric/negative -> the 30s default; "0" -> resident (Zero); a positive value below
    // the 5s floor is clamped up to it; anything >= the floor is honoured verbatim. The daemon/host tests
    // pass a TimeSpan straight to the constructor, so without this the env->TimeSpan mapping is untested.
    [Theory]
    [InlineData(null, 30)]      // unset            -> default
    [InlineData("", 30)]        // empty            -> default
    [InlineData("   ", 30)]     // whitespace       -> default
    [InlineData("abc", 30)]     // non-numeric      -> default
    [InlineData("-5", 30)]      // negative         -> default
    [InlineData("0", 0)]        // explicit resident (idle-exit disabled)
    [InlineData("1", 5)]        // below floor      -> clamped to 5
    [InlineData("4", 5)]        // below floor      -> clamped to 5
    [InlineData("5", 5)]        // at the floor
    [InlineData("60", 60)]      // honoured as-is
    [InlineData("  10  ", 10)]  // surrounding whitespace is trimmed
    public void ParseIdleTimeout_MapsEnvValueToContract(string? raw, int expectedSeconds)
    {
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), FirewallOptions.ParseIdleTimeout(raw));
    }
}
