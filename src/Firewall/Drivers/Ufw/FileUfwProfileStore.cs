namespace TheKrystalShip.KGSM.Firewall.Drivers.Ufw;

/// <summary>
/// Filesystem-backed <see cref="IUfwProfileStore"/> over the ufw applications directory
/// (default <c>/etc/ufw/applications.d</c>). Writing there needs root — which the authority has, since
/// it is the privileged firewall door. Profile files are named exactly by the profile name
/// (<c>kgsm-&lt;instance&gt;</c>), matching how ufw discovers application profiles.
/// </summary>
internal sealed class FileUfwProfileStore(string applicationsDirectory) : IUfwProfileStore
{
    private string PathFor(string profileName) => Path.Combine(applicationsDirectory, profileName);

    public void Write(string profileName, string content)
    {
        Directory.CreateDirectory(applicationsDirectory);
        File.WriteAllText(PathFor(profileName), content);
    }

    public bool Delete(string profileName)
    {
        string path = PathFor(profileName);
        if (!File.Exists(path)) return false;
        File.Delete(path);
        return true;
    }

    public string? Read(string profileName)
    {
        string path = PathFor(profileName);
        return File.Exists(path) ? File.ReadAllText(path) : null;
    }

    public IReadOnlyList<string> ListOwnedNames()
    {
        if (!Directory.Exists(applicationsDirectory)) return [];
        var names = new List<string>();
        foreach (string path in Directory.EnumerateFiles(applicationsDirectory, "kgsm-*"))
            names.Add(Path.GetFileName(path));
        return names;
    }
}
