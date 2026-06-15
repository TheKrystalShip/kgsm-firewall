using Microsoft.Extensions.Logging;

namespace TheKrystalShip.KGSM.Firewall.Core;

/// <summary>
/// The authority's core. It owns VALIDATION (so every backend inherits the same defensive checks) and
/// dispatches to the active <see cref="IFirewallDriver"/>; it performs no privileged I/O itself — that
/// lives in the driver. Callers (the socket host / CLI, added in a later increment) talk to this, never
/// to a driver directly.
/// </summary>
internal sealed class FirewallService(IFirewallDriver driver, ILogger<FirewallService> logger)
{
    public FirewallBackend Backend => driver.Backend;
    public FirewallCapabilities Capabilities => driver.Capabilities;

    public async Task<FirewallResult> EnsureOpenAsync(
        string instance, IReadOnlyList<PortSpec> ports, CancellationToken ct = default)
    {
        if (FirewallValidator.ValidateOpen(instance, ports) is { } error)
        {
            logger.LogWarning("EnsureOpen rejected: {Error}", error);
            return FirewallResult.Failed(error);
        }

        if (!driver.Capabilities.CanApply)
            return FirewallResult.Unsupported($"backend {driver.Backend} cannot apply rules");

        if (ports.Count == 0)
            return FirewallResult.NoOp("no ports requested");

        logger.LogInformation(
            "EnsureOpen {Instance}: {Count} port spec(s) via {Backend}",
            instance, ports.Count, driver.Backend);
        return await driver.EnsureOpenAsync(instance, ports, ct).ConfigureAwait(false);
    }

    public async Task<FirewallResult> RemoveAsync(string instance, CancellationToken ct = default)
    {
        if (FirewallValidator.ValidateInstance(instance) is { } error)
        {
            logger.LogWarning("Remove rejected: {Error}", error);
            return FirewallResult.Failed(error);
        }

        if (!driver.Capabilities.CanRemove)
            return FirewallResult.Unsupported($"backend {driver.Backend} cannot remove rules");

        logger.LogInformation("Remove {Instance} via {Backend}", instance, driver.Backend);
        return await driver.RemoveAsync(instance, ct).ConfigureAwait(false);
    }

    public async Task<OwnedRulesResult> ListOwnedAsync(
        string? instance = null, CancellationToken ct = default)
    {
        // A malformed instance name is a bad query; we won't fabricate an answer for it -> Unknown.
        if (instance is not null && FirewallValidator.ValidateInstance(instance) is { } error)
        {
            logger.LogWarning("ListOwned rejected: {Error}", error);
            return OwnedRulesResult.Unknown;
        }

        if (!driver.Capabilities.CanList)
            return OwnedRulesResult.Unsupported;

        return await driver.ListOwnedAsync(instance, ct).ConfigureAwait(false);
    }
}
