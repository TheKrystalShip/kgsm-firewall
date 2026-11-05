
namespace TheKrystalShip.KGSM.Firewall.Contracts;

/// <summary>
/// Typed client for the kgsm-firewall authority — the single C# entry point for driving the host-firewall
/// door over its control socket. Surfaces above (the Discord bot, the Control Panel API) open/close/list
/// instance firewall rules through this instead of shelling <c>ufw</c> or opening the socket directly,
/// keeping all firewall integration in this package.
/// </summary>
/// <remarks>
/// <para>
/// Transport is one newline-delimited JSON request → one reply over a unix-domain socket (the authority
/// carries no HTTP stack); the wire contract is the <c>TheKrystalShip.KGSM.Firewall.Contracts</c> package,
/// and the ports are the wire <see cref="PortDto"/>. The socket's filesystem permissions are the
/// security boundary; there is no in-band authentication.
/// </para>
/// <para>
/// <b>Unreachable vs. unsuccessful.</b> When the authority cannot be reached (no socket, timeout, no/garbled
/// reply) every method throws <see cref="FirewallException"/> — the C# analog of the authority's
/// "unreachable" exit code, the abort-the-install signal. A reachable-but-unsuccessful operation instead
/// returns a typed result whose <c>Outcome</c>/<c>Status</c> distinguishes unsupported, op-failed, and
/// honest-unknown — never collapsed to a bare bool.
/// </para>
/// <para>
/// This client performs the firewall operation only; it emits no kgsm audit events. The
/// <c>instance_ports_opened</c>/<c>instance_ports_closed</c> events are emitted separately by the caller
/// via <see cref="IEventManagementService.EmitWithProvenance"/> (mirroring how the watchdog emits its own
/// events) — kept out of the transport client deliberately, so a missing event service can never silently
/// drop the audit trail.
/// </para>
/// </remarks>
public interface IFirewallService : IDisposable
{
    /// <summary>
    /// Ensures the given <paramref name="ports"/> are open for <paramref name="instanceName"/>, replacing
    /// any rules the authority already owns for it (the authority is declarative — the result is exactly
    /// these ports). An empty/zero-port set is a no-op.
    /// </summary>
    /// <param name="instanceName">The instance whose rules to set (the firewall ownership tag).</param>
    /// <param name="ports">The range-preserving ports to open.</param>
    /// <param name="actor">
    /// Whose authority the request carries (<c>provider:name</c>), or null when the caller knows of
    /// none. Carried so the authority can record who asked on the edge it performs — it repeats the
    /// claim and cannot check it, which is why a caller that knows nobody must pass null rather than a
    /// stand-in.
    /// </param>
    /// <param name="origin">The surface that drove it, or null. Never fabricated.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The outcome (applied / no-op / unsupported / failed) and active backend.</returns>
    /// <exception cref="Exceptions.FirewallException">The authority is unreachable.</exception>
    Task<FirewallActionResult> EnsureOpenAsync(
        string instanceName, IReadOnlyList<PortDto> ports, string? actor = null,
        string? origin = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes every firewall rule the authority owns for <paramref name="instanceName"/>.
    /// </summary>
    /// <param name="instanceName">The instance whose rules to remove.</param>
    /// <param name="actor">Whose authority the request carries, or null.</param>
    /// <param name="origin">The surface that drove it, or null.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The outcome (removed / no-op / unsupported / failed) and active backend.</returns>
    /// <exception cref="Exceptions.FirewallException">The authority is unreachable.</exception>
    Task<FirewallActionResult> RemoveAsync(
        string instanceName, string? actor = null, string? origin = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the firewall rules the authority owns, optionally for a single instance. The result's
    /// <see cref="FirewallListResult.Status"/> reports honest <see cref="FirewallListStatus.Unknown"/> when
    /// the backend cannot enumerate — never a fabricated empty "nothing open".
    /// </summary>
    /// <param name="instanceName">A single instance to scope to, or <c>null</c> for all owned rules.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The owned rules and whether they could be measured.</returns>
    /// <exception cref="Exceptions.FirewallException">The authority is unreachable.</exception>
    Task<FirewallListResult> ListOwnedAsync(string? instanceName = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reports the active backend and what it can honestly do (apply / remove / list).
    /// </summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The detected backend and its capabilities.</returns>
    /// <exception cref="Exceptions.FirewallException">The authority is unreachable.</exception>
    Task<FirewallBackendInfo> BackendAsync(CancellationToken cancellationToken = default);
}
