using TheKrystalShip.KGSM.ComponentConfig;

// What the Control Panel shows about this authority, declared beside the configuration it describes.
// TheKrystalShip.KGSM.ComponentConfig reads this out of the built assembly and writes
// deploy/kgsm-firewall.leaf.json; deploy.sh installs that into /var/lib/kgsm/leaves/firewall.json,
// where kgsm-api scans for it. The daemon itself never reads any of this.

[assembly: Leaf(
    id: "firewall",
    displayName: "Firewall",
    unit: "kgsm-firewall.service",
    role: "The host firewall authority — opens and closes each server's ports, and is the only honest source for whether a port is open.",
    OnDemand = true)]

[assembly: ConfigGroup("general", "General", 1)]
[assembly: ConfigGroup("backend", "Firewall backend", 2)]
[assembly: ConfigGroup("runtime", "Runtime", 3)]

// Lowest precedence first — the same order the daemon resolves them in. The unit lives directly under
// /etc/systemd/system here rather than in a user-owned directory: this is the one leaf whose binary
// and units stay root-owned, because its daemon runs as root.
[assembly: ConfigFloorSource("appsettings", "/opt/kgsm-firewall/kgsm-firewall.settings.json")]
[assembly: ConfigFloorSource("systemd-unit", "kgsm-firewall.service")]
[assembly: ConfigFloorSource("env-file", "/etc/kgsm-firewall/kgsm-firewall.env")]

[assembly: ConfigFrameworkNamespace("Logging__",
    "per-category filtering is open-ended: any category name is a valid key")]

[assembly: ConfigFrameworkField("logLevel", "Logging__LogLevel__Default", "Log level",
    Description = "Minimum severity this leaf logs.",
    Group = "general",
    Type = ConfigType.Enum,
    Values = ["Trace", "Debug", "Information", "Warning", "Error", "Critical"])]
