using System.Text.Json.Serialization;

namespace TheKrystalShip.KGSM.Firewall.Wire;

/// <summary>
/// System.Text.Json source-generation context for the control-socket DTOs. Keeps the daemon AND its
/// bundled client reflection-free, so the whole binary stays Native-AOT/trim-clean (0 IL2026/IL3050).
/// camelCase on the wire. The nested payload types (<see cref="PortDto"/>, <see cref="OwnedRuleDto"/>,
/// <see cref="CapabilitiesDto"/>) are reachable from the two roots, so source-gen covers them too.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(FirewallRequest))]
[JsonSerializable(typeof(FirewallResponse))]
internal sealed partial class WireJsonContext : JsonSerializerContext;
