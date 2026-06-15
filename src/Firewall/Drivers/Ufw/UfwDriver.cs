using Microsoft.Extensions.Logging;
using TheKrystalShip.KGSM.Firewall.Core;

namespace TheKrystalShip.KGSM.Firewall.Drivers.Ufw;

/// <summary>
/// The ufw backend driver — today's approach, harvested from kgsm's <c>files.ufw.sh</c> but namespaced
/// and reshaped to the agnostic seam. Per-instance grouping is a ufw application profile named
/// <c>kgsm-&lt;instance&gt;</c> (the ownership tag), so list/remove touch only our rules:
/// <list type="bullet">
/// <item>EnsureOpen: write the profile, <c>ufw app update</c>, then <c>ufw allow kgsm-&lt;instance&gt;</c>.</item>
/// <item>Remove: <c>ufw delete allow kgsm-&lt;instance&gt;</c>, then delete the profile file.</item>
/// <item>ListOwned: the <c>kgsm-*</c> profiles we wrote, cross-checked against <c>ufw status</c>; if
/// status cannot be read, return Unknown rather than fabricate "nothing open".</item>
/// </list>
/// Inputs are pre-validated by the service core, so the driver assumes a well-formed instance + ports.
/// </summary>
internal sealed class UfwDriver(
    IProcessRunner runner, IUfwProfileStore profiles, ILogger<UfwDriver> logger) : IFirewallDriver
{
    public FirewallBackend Backend => FirewallBackend.Ufw;
    public FirewallCapabilities Capabilities => FirewallCapabilities.Full;

    public async Task<FirewallResult> EnsureOpenAsync(
        string instance, IReadOnlyList<PortSpec> ports, CancellationToken ct = default)
    {
        string name = UfwProfile.NameFor(instance);

        // 1) (Re)write our application profile — idempotent; same content overwrites cleanly.
        try
        {
            profiles.Write(name, UfwProfile.Render(instance, ports));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "EnsureOpen {Instance}: failed to write ufw profile {Name}", instance, name);
            return FirewallResult.Failed($"could not write ufw profile {name}: {ex.Message}");
        }

        // 2) Reload the profile cache so a changed port set takes effect, then allow it.
        await runner.RunAsync("ufw", ["app", "update", name], ct).ConfigureAwait(false);

        ProcessResult allow = await runner.RunAsync("ufw", ["allow", name], ct).ConfigureAwait(false);
        if (!allow.Ok)
        {
            string detail = !string.IsNullOrEmpty(allow.Stderr) ? allow.Stderr : allow.Stdout;
            logger.LogError("EnsureOpen {Instance}: `ufw allow {Name}` failed: {Detail}", instance, name, detail);
            // Roll back the profile we just wrote so a failed apply leaves no orphan ownership tag.
            profiles.Delete(name);
            return FirewallResult.Failed($"ufw allow {name} failed: {detail}");
        }

        return FirewallResult.Applied($"opened {ports.Count} spec(s) under {name}");
    }

    public async Task<FirewallResult> RemoveAsync(string instance, CancellationToken ct = default)
    {
        string name = UfwProfile.NameFor(instance);

        // Delete the rule. ufw returns non-zero if the rule was not there — fine on a remove (idempotent).
        await runner.RunAsync("ufw", ["delete", "allow", name], ct).ConfigureAwait(false);

        bool removed = profiles.Delete(name);
        return FirewallResult.Removed(removed ? $"removed {name}" : $"{name} was not present");
    }

    public async Task<OwnedRulesResult> ListOwnedAsync(
        string? instance = null, CancellationToken ct = default)
    {
        // The profiles we wrote tell us "what ports we own"; `ufw status` tells us which are actually
        // active. If status cannot be read (non-root / ufw absent), we cannot honestly say what is open
        // -> Unknown, never a fabricated empty list.
        ProcessResult status = await runner.RunAsync("ufw", ["status"], ct).ConfigureAwait(false);
        if (!status.Ok)
            return OwnedRulesResult.Unknown;

        var rules = new List<OwnedRule>();
        foreach (string profileName in profiles.ListOwnedNames())
        {
            string? owned = UfwProfile.InstanceFromName(profileName);
            if (owned is null) continue;
            if (instance is not null && !string.Equals(owned, instance, StringComparison.Ordinal)) continue;

            // Active only if a `ufw status` rule line's "To" column is EXACTLY our app name — a token
            // match, NOT a substring (else `kgsm-fact` would match a `kgsm-factorio` rule); the `(v6)`
            // duplicate line ufw emits for the IPv6 rule is folded in.
            if (!StatusReferencesApp(status.Stdout, profileName)) continue;

            string? body = profiles.Read(profileName);
            IReadOnlyList<PortSpec> portList = body is null ? [] : UfwProfile.ParsePorts(body);
            rules.Add(new OwnedRule(owned, portList));
        }

        return OwnedRulesResult.Ok(rules);
    }

    private static readonly string[] UfwActions = ["ALLOW", "DENY", "LIMIT", "REJECT"];

    /// <summary>
    /// True if any rule line in <c>ufw status</c> has a "To" column equal to <paramref name="appName"/>.
    /// app-profile rules render as <c>&lt;app-name&gt;   ALLOW   Anywhere</c> (plus a <c>(v6)</c> twin),
    /// so we take everything before the action keyword as the "To" token, strip a trailing <c>(v6)</c>,
    /// and compare for EQUALITY — never a substring.
    /// </summary>
    internal static bool StatusReferencesApp(string statusStdout, string appName)
    {
        foreach (string raw in statusStdout.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0) continue;

            int actionIdx = -1;
            foreach (string action in UfwActions)
            {
                int idx = line.IndexOf(action, StringComparison.Ordinal);
                if (idx >= 0) { actionIdx = idx; break; }
            }
            if (actionIdx < 0) continue; // header / "Status:" / separator line — not a rule

            string to = line[..actionIdx].Trim();
            if (to.EndsWith("(v6)", StringComparison.Ordinal))
                to = to[..^4].Trim();

            if (string.Equals(to, appName, StringComparison.Ordinal))
                return true;
        }
        return false;
    }
}
