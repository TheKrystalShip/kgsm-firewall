namespace TheKrystalShip.KGSM.Firewall.Core;

/// <summary>
/// The authority's configuration surface, shaped 1:1 to the <c>Firewall</c> section of
/// <c>kgsm-firewall.settings.json</c>. Every knob is a property here and a key there; nothing is read
/// by string lookup, so a knob cannot exist in one place and not the other. An environment variable
/// overrides one key by spelling its path with <c>__</c> (<c>Firewall__IdleTimeoutSeconds</c>).
/// </summary>
/// <remarks>
/// This type holds what was <em>written</em>, not what the authority runs on: values arrive
/// unvalidated, exactly as the file or the environment spelled them. <see cref="FirewallOptions"/> is
/// the validated form — clamping, fallbacks and backend parsing live in
/// <see cref="FirewallOptions.FromSettings"/>.
/// </remarks>
internal sealed class FirewallSettings
{
    /// <summary>The configuration section this type binds to.</summary>
    public const string Section = "Firewall";

    /// <summary>Control socket the daemon listens on and the bundled client connects to. It has to
    /// match the <c>.socket</c> unit's <c>ListenStream=</c>.</summary>
    public string SocketPath { get; set; } = FirewallOptions.DefaultSocketPath;

    /// <summary>Forces which host firewall to drive: <c>none|ufw|firewalld|nftables|iptables</c>.
    /// Blank auto-detects, which is the intended state on a normal host — hence a blank default
    /// rather than a named one.</summary>
    /// <remarks>
    /// A <see cref="string"/> rather than the <see cref="FirewallBackend"/> enum: blank has to mean
    /// "detect", which no enum member can express, and an unrecognised name has to degrade to
    /// detection rather than fail binding. <see cref="FirewallOptions.ParseBackend"/> is the lenient
    /// parse both cases go through.
    /// </remarks>
    public string Backend { get; set; } = string.Empty;

    /// <summary>Directory ufw reads application profiles from, where this authority writes one profile
    /// per instance. Applies only while ufw is the backend.</summary>
    public string UfwApplicationsDirectory { get; set; } = FirewallOptions.DefaultUfwApplicationsDirectory;

    /// <summary>Seconds the socket-activated daemon stays idle before exiting, so it does not hold
    /// root all day. Zero keeps it resident; a positive value below
    /// <see cref="FirewallOptions.MinIdleTimeoutSeconds"/> is raised to it.</summary>
    /// <remarks>
    /// Nullable so that "written blank" and "written zero" stay distinguishable. Binding a blank value
    /// to a non-nullable <see cref="int"/> throws, which would take the authority down over an env-file
    /// line left as <c>KEY=</c>; binding a null one silently yields 0, which here means "never idle-exit"
    /// — a value nobody asked for. Null means unset, and
    /// <see cref="FirewallOptions.DefaultIdleTimeoutSeconds"/> applies. A value that is present but not a
    /// number still fails loudly, which is the point of typing it.
    /// </remarks>
    public int? IdleTimeoutSeconds { get; set; }
}
