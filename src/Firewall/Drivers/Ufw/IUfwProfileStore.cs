namespace TheKrystalShip.KGSM.Firewall.Drivers.Ufw;

/// <summary>
/// Read/write/enumerate the ufw application-profile files the authority owns. Abstracted so the ufw
/// driver's logic is unit-testable without touching <c>/etc/ufw/applications.d</c> (the real store
/// needs root). Every profile the authority manages is named <c>kgsm-&lt;instance&gt;</c> — the
/// ownership tag — so <see cref="ListOwnedNames"/> enumerates only ours.
/// </summary>
internal interface IUfwProfileStore
{
    void Write(string profileName, string content);

    /// <summary>Delete the profile; returns false if it was not present (idempotent remove).</summary>
    bool Delete(string profileName);

    /// <summary>The profile body, or null if absent.</summary>
    string? Read(string profileName);

    /// <summary>Names (not paths) of every <c>kgsm-*</c> profile present in the store.</summary>
    IReadOnlyList<string> ListOwnedNames();
}
