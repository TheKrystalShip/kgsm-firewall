using Microsoft.Extensions.Logging.Abstractions;
using TheKrystalShip.KGSM.Firewall.Core;

// kgsm-firewall — the host-firewall authority for the KGSM ecosystem.
//
// Increment 0 ships the core domain + the ufw driver only. The socket-activated daemon host and the
// full CLI client surface (ensure-open / remove / list) land in Increment 1, where Main will dispatch:
// no args / "serve" -> run the socket-activated authority; a verb -> act as the CLI client that talks
// to the running authority over its unix socket.
//
// For now Main supports one read-only smoke verb — `detect` — which composes the real object graph and
// prints the detected backend. Beyond being useful, this keeps the domain + driver reachable so
// `dotnet publish` actually exercises them through ILC (an unreferenced graph would just be trimmed).

string verb = args.Length > 0 ? args[0] : "help";

switch (verb)
{
    case "detect":
    {
        FirewallOptions options = FirewallOptions.FromEnvironment();
        var runner = new ProcessRunner(NullLogger<ProcessRunner>.Instance);
        var detector = new BackendDetector(runner, NullLogger<BackendDetector>.Instance);
        FirewallBackend backend = await detector.DetectAsync(options);
        Console.WriteLine(backend);
        return backend == FirewallBackend.None ? 1 : 0;
    }

    default:
        Console.Error.WriteLine(
            "kgsm-firewall (Increment 0): only `detect` is wired so far; the socket host + the " +
            "ensure-open/remove/list CLI land in Increment 1.");
        return 0;
}
