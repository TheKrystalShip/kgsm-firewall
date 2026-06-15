using System.Text.Json.Serialization;

namespace TheKrystalShip.KGSM.Firewall.Contracts;

/// <summary>
/// System.Text.Json source-generation context for the control-socket DTOs. Keeps every speaker —
/// the daemon, its bundled CLI client, and kgsm-lib's <c>FirewallService</c> — reflection-free, so each
/// consumer stays Native-AOT/trim-clean (0 IL2026/IL3050). camelCase on the wire. The nested payload
/// types (<see cref="PortDto"/>, <see cref="OwnedRuleDto"/>, <see cref="CapabilitiesDto"/>) are reachable
/// from the two roots, so source-gen covers them too.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(FirewallRequest))]
[JsonSerializable(typeof(FirewallResponse))]
public sealed partial class WireJsonContext : JsonSerializerContext;
