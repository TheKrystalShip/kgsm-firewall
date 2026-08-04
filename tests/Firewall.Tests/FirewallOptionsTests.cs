using Microsoft.Extensions.Configuration;
using TheKrystalShip.KGSM.Firewall.Core;

namespace TheKrystalShip.KGSM.Firewall.Tests;

public class FirewallOptionsTests
{
    /// <summary>Binds a settings section the way the binary does, from the given key/value pairs.</summary>
    private static FirewallOptions Bind(params (string Key, string? Value)[] values)
    {
        IConfigurationRoot config = new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v =>
                new KeyValuePair<string, string?>($"{FirewallSettings.Section}:{v.Key}", v.Value)))
            .Build();

        return FirewallOptions.FromSettings(
            config.GetSection(FirewallSettings.Section).Get<FirewallSettings>() ?? new FirewallSettings());
    }

    // Pins the configurability contract of the idle timeout (the documented --help behaviour):
    // negative -> the 30s default; 0 -> resident (Zero); a positive value below the 5s floor is clamped
    // up to it; anything >= the floor is honoured verbatim. The daemon/host tests pass a TimeSpan
    // straight to the constructor, so without this the settings->TimeSpan mapping is untested.
    [Theory]
    [InlineData(-5, 30)]    // negative         -> default
    [InlineData(0, 0)]      // explicit resident (idle-exit disabled)
    [InlineData(1, 5)]      // below floor      -> clamped to 5
    [InlineData(4, 5)]      // below floor      -> clamped to 5
    [InlineData(5, 5)]      // at the floor
    [InlineData(60, 60)]    // honoured as-is
    public void ClampIdleTimeout_MapsSecondsToContract(int seconds, int expectedSeconds)
    {
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), FirewallOptions.ClampIdleTimeout(seconds));
    }

    [Theory]
    [InlineData(null)]   // key absent entirely
    [InlineData("")]     // present but empty
    public void IdleTimeout_falls_back_to_the_default_when_nothing_is_written(string? raw)
    {
        Assert.Equal(TimeSpan.FromSeconds(FirewallOptions.DefaultIdleTimeoutSeconds),
            Bind((nameof(FirewallSettings.IdleTimeoutSeconds), raw)).IdleTimeout);
    }

    [Fact]
    public void IdleTimeout_binds_and_clamps_a_written_value()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), Bind((nameof(FirewallSettings.IdleTimeoutSeconds), "2")).IdleTimeout);
        Assert.Equal(TimeSpan.Zero, Bind((nameof(FirewallSettings.IdleTimeoutSeconds), "0")).IdleTimeout);
    }

    // A value that is present but not a number fails binding rather than being silently ignored. That is
    // the deliberate trade of typed configuration: the authority refuses to start on config it cannot
    // read, instead of running on a default the operator never chose and never sees. Blank is not that
    // case — see above; blank means unset.
    [Fact]
    public void IdleTimeout_rejects_a_value_that_is_not_a_number()
    {
        Assert.ThrowsAny<Exception>(() => Bind((nameof(FirewallSettings.IdleTimeoutSeconds), "abc")));
    }

    // Blank means auto-detect, and so does a name that is not a backend — detection is always a safe
    // landing, whereas failing here would take down the authority that a firewall-enabled install
    // hard-fails without.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-backend")]
    public void Backend_falls_back_to_auto_detection(string? raw)
    {
        Assert.Null(Bind((nameof(FirewallSettings.Backend), raw)).BackendOverride);
    }

    [Fact]
    public void Backend_is_parsed_leniently()
    {
        Assert.Equal(FirewallBackend.Ufw, Bind((nameof(FirewallSettings.Backend), "ufw")).BackendOverride);
        Assert.Equal(FirewallBackend.Ufw, Bind((nameof(FirewallSettings.Backend), "  UFW  ")).BackendOverride);
        Assert.Equal(FirewallBackend.Nftables, Bind((nameof(FirewallSettings.Backend), "nft")).BackendOverride);
        Assert.Equal(FirewallBackend.None, Bind((nameof(FirewallSettings.Backend), "none")).BackendOverride);
    }

    // A path knob written blank falls back to the coded default rather than becoming an empty path,
    // which would make the daemon bind "" and the client connect to nothing.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Blank_paths_fall_back_to_their_defaults(string? raw)
    {
        FirewallOptions o = Bind(
            (nameof(FirewallSettings.SocketPath), raw),
            (nameof(FirewallSettings.UfwApplicationsDirectory), raw));

        Assert.Equal(FirewallOptions.DefaultSocketPath, o.SocketPath);
        Assert.Equal(FirewallOptions.DefaultUfwApplicationsDirectory, o.UfwApplicationsDirectory);
    }

    [Fact]
    public void Written_paths_are_taken_and_trimmed()
    {
        FirewallOptions o = Bind((nameof(FirewallSettings.SocketPath), "  /tmp/fw.sock  "));
        Assert.Equal("/tmp/fw.sock", o.SocketPath);
    }
}
