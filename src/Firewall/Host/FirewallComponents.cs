namespace TheKrystalShip.KGSM.Firewall.Host;

/// <summary>
/// The parts of this authority's job that can stop working while it keeps answering.
/// </summary>
/// <remarks>
/// <para>
/// ⚠ <b>This daemon reports degradation only — never a start or a stop.</b> It is socket activated
/// with a short idle window and woke 35 times in a measured day; a start and a stop on each would be
/// five times its whole journal's daily output, to report that a socket-activated daemon did the one
/// thing socket activation exists to make it do. <b>Inactive is its resting state, not a
/// transition</b>, which is also why nothing on this host can usefully health-poll it: connecting to
/// the socket is what starts it.
/// </para>
/// <para>
/// The same property means the process holds no memory across a wake, so a condition that still holds
/// is reported again by each fresh process that observes it. That is honest rather than duplicated: a
/// consumer reading it twice is being told it is still true.
/// </para>
/// </remarks>
internal static class FirewallComponents
{
    /// <summary>
    /// The backend this authority writes rules through.
    /// </summary>
    /// <remarks>
    /// ⚠ The most dangerous silent state on a KGSM host. Ports are opened when a server starts and
    /// closed when it stops, so an authority that answers but cannot write leaves them closed on a
    /// start — nobody can connect — or open on a stop, with every caller told the request was
    /// accepted, because it was.
    /// </remarks>
    public const string Backend = "backend";
}
