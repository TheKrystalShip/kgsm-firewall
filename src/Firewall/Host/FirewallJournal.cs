using System.Text.Json;
using Microsoft.Extensions.Logging;
using TheKrystalShip.KGSM.Core.Interfaces;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Services;

using TheKrystalShip.KGSM.Events;

namespace TheKrystalShip.KGSM.Firewall.Host;

/// <summary>
/// Records the host-firewall edges this authority applied, in this authority's own event journal.
/// </summary>
/// <remarks>
/// <para>
/// <b>The component that changed the firewall is the one that records it.</b> Nothing else on this host
/// can honestly say a port was opened: the caller asked, and this daemon is what wrote the rule and saw
/// the backend accept it. Two components used to record it on this one's behalf — kgsm after shelling
/// the CLI, and the watchdog after calling the socket client — which meant the line naming the author
/// named the wrong one, and both had to be guarded so one edge was never written twice.
/// </para>
/// <para>
/// <b>Only a confirmed change is recorded.</b> An outcome that applied nothing — a no-op, an unsupported
/// backend, a refusal — is not an edge, and recording one would put a firewall change in the trail that
/// never happened. A staged-but-not-enforced rule (<c>applied-inactive</c>: ufw installed but disabled)
/// IS recorded, because the desired configuration is genuinely in place and the port is reachable; the
/// outcome rides on the payload so a reader can tell the two apart rather than being told they are the
/// same.
/// </para>
/// <para>
/// <b>Provenance is repeated, not vouched for.</b> The actor and origin come off the request: the caller
/// alone knows whose authority it carried, and this daemon cannot check the claim. A caller that names
/// nobody produces a real null — the honest answer, never a substituted "system".
/// </para>
/// <para>
/// <b>Idle-exit is not a problem here.</b> A journal is append-only and written inside the request the
/// daemon is already awake to serve, so it needs no resident writer and nothing is lost when the daemon
/// exits a moment later.
/// </para>
/// </remarks>
internal sealed class FirewallJournal(IEventJournalWriter writer, ILogger<FirewallJournal> logger)
    : JournalRecorder(writer, logger)
{
    /// <summary>The host firewall now admits this instance's ports.</summary>
    public const string PortsOpenedEvent = "network.ports.opened";

    /// <summary>The rules this authority held for an instance are gone.</summary>
    public const string PortsClosedEvent = "network.ports.closed";

    /// <summary>The two names, typed so the writer can take them.</summary>
    /// <remarks>
    /// Derived from the constants above rather than restated, so the name this authority writes and
    /// the name a reader matches cannot become two different strings.
    /// </remarks>
    private static readonly EventName PortsOpenedName = EventName.Parse(PortsOpenedEvent);
    private static readonly EventName PortsClosedName = EventName.Parse(PortsClosedEvent);

    /// <summary>
    /// Records an <c>ensure-open</c> that actually changed the host firewall.
    /// </summary>
    /// <param name="instance">The instance whose rules were set.</param>
    /// <param name="ports">The ports now open — what the authority applied, not what was asked for.</param>
    /// <param name="result">The driver's outcome; anything that applied nothing records nothing.</param>
    /// <param name="actor">The caller's actor, or null when it named none.</param>
    /// <param name="origin">The caller's surface, or null.</param>
    /// <param name="ct">Cancels the append.</param>
    public Task OpenedAsync(
        string instance, IReadOnlyList<PortSpec> ports, FirewallResult result,
        string? actor, string? origin, CancellationToken ct = default)
    {
        if (!Applied(result.Status))
            return Task.CompletedTask;

        return WriteAsync(
            PortsOpenedName, actor, origin,
            w =>
            {
                w.WriteString("InstanceName", instance);
                WritePorts(w, ports);
                WriteOutcome(w, result.Status);
            },
            // A door opening is a fact worth recording and nothing more; the door closing is the half
            // that leaves something unreachable, and reads louder for it.
            EventSeverity.Info,
            EventOutcome.Neutral,
            $"opened firewall ports for {instance}",
            ct);
    }

    /// <summary>
    /// Records a <c>remove</c> that actually took rules away.
    /// </summary>
    /// <remarks>
    /// The ports are not on this event: removal is declarative — the authority drops everything it owns
    /// for the instance — and it does not read back what it just deleted. Listing the ports would mean
    /// reporting the caller's idea of them as the authority's measurement.
    /// </remarks>
    public Task ClosedAsync(
        string instance, FirewallResult result, string? actor, string? origin,
        CancellationToken ct = default)
    {
        if (!Applied(result.Status))
            return Task.CompletedTask;

        return WriteAsync(
            PortsClosedName, actor, origin,
            w =>
            {
                w.WriteString("InstanceName", instance);
                WriteOutcome(w, result.Status);
            },
            EventSeverity.Warn,
            EventOutcome.Neutral,
            $"closed firewall ports for {instance}",
            ct);
    }

    /// <summary>
    /// Whether an outcome represents a host-firewall change that happened.
    /// </summary>
    /// <remarks>
    /// <see cref="FirewallStatus.AppliedInactive"/> counts: the rule is written and persists, the backend
    /// simply is not enforcing yet — so the configuration did change, and the port is reachable meanwhile.
    /// Everything else (no-op, unsupported, failed) changed nothing.
    /// </remarks>
    private static bool Applied(FirewallStatus status) =>
        status is FirewallStatus.Applied or FirewallStatus.AppliedInactive or FirewallStatus.Removed;

    private static void WritePorts(Utf8JsonWriter w, IReadOnlyList<PortSpec> ports)
    {
        // Structured, the ecosystem's one canonical port shape. A backend-rendered string here would make
        // every reader parse ufw's syntax back out of an event that is meant to be backend-agnostic.
        w.WriteStartArray("Ports");
        foreach (PortSpec port in ports)
        {
            w.WriteStartObject();
            w.WriteNumber("start", port.Start);
            w.WriteNumber("end", port.End);
            w.WriteString("protocol", port.Protocol == PortProtocol.Udp ? "udp" : "tcp");
            w.WriteEndObject();
        }
        w.WriteEndArray();
    }

    /// <summary>
    /// The precise outcome, so a reader can tell an enforced rule from a staged one.
    /// </summary>
    private static void WriteOutcome(Utf8JsonWriter w, FirewallStatus status) =>
        w.WriteString("Outcome", status switch
        {
            FirewallStatus.Applied => "applied",
            FirewallStatus.AppliedInactive => "applied-inactive",
            FirewallStatus.Removed => "removed",
            _ => "unknown",
        });

    /// <summary>
    /// This authority attributes nothing to itself.
    /// </summary>
    /// <remarks>
    /// ⚠ The one place this producer differs from an autonomous one, and it is the whole of its
    /// provenance model: an edge exists because a caller asked for it, and only that caller knows whose
    /// authority it carried. A default of <c>system:firewall</c> would answer "who wanted this port
    /// open?" with the name of the process that typed the rule — which is never the interesting
    /// answer and is not a true one. A caller that names nobody produces a real null.
    /// </remarks>
    protected override string? DefaultActor => null;

    /// <inheritdoc cref="DefaultActor"/>
    protected override string? DefaultOrigin => null;

    /// <summary>Appends one edge, saying what was lost if it cannot.</summary>
    /// <remarks>
    /// The base logs the generic failure; this adds what the base cannot know — that a firewall change
    /// happened and will not be findable afterwards. The rule is already in place either way: failing
    /// the operation now because writing it down did not work would trade a missing line for a refused
    /// bring-up.
    /// </remarks>
    private async Task WriteAsync(
        EventName type, string? actor, string? origin, Action<Utf8JsonWriter> payload,
        EventSeverity severity, EventOutcome outcome, string summary, CancellationToken ct)
    {
        bool written = await RecordAsync(type, payload, actor, origin, severity, outcome, summary, ct)
            .ConfigureAwait(false);

        if (!written)
        {
            logger.LogWarning(
                "{Event} was NOT recorded — the firewall changed, the record of it did not",
                NormalizeType(type));
        }
    }
}
