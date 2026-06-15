using TheKrystalShip.KGSM.Firewall.Drivers.Ufw;

namespace TheKrystalShip.KGSM.Firewall.Tests.Fakes;

/// <summary>In-memory <see cref="IUfwProfileStore"/> so driver logic is tested without touching
/// <c>/etc/ufw</c>. <see cref="ThrowOnWrite"/> simulates a permission failure on the profile write.</summary>
internal sealed class InMemoryUfwProfileStore : IUfwProfileStore
{
    public Dictionary<string, string> Files { get; } = new(StringComparer.Ordinal);
    public bool ThrowOnWrite { get; set; }

    public void Write(string profileName, string content)
    {
        if (ThrowOnWrite) throw new IOException("permission denied");
        Files[profileName] = content;
    }

    public bool Delete(string profileName) => Files.Remove(profileName);

    public string? Read(string profileName) => Files.TryGetValue(profileName, out string? c) ? c : null;

    public IReadOnlyList<string> ListOwnedNames()
        => [.. Files.Keys.Where(k => k.StartsWith("kgsm-", StringComparison.Ordinal))];
}
