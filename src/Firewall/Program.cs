using System.Runtime.InteropServices;
using Microsoft.Extensions.Configuration;
using TheKrystalShip.KGSM.Firewall.Core;
using TheKrystalShip.KGSM.Firewall.Host;

// kgsm-firewall — the host-firewall authority for the KGSM ecosystem.
//
// One binary, two roles:
//   * `serve` (or being socket-activated by systemd) -> run the resident authority: detect the backend
//     daemon-side, then accept newline-delimited JSON requests on the control socket.
//   * a verb (`ensure-open` / `remove` / `list` / `backend`) -> act as the CLI client that connects to
//     the running authority and maps its reply to an exit code. Bash shells these; it never speaks the
//     wire protocol (that is the point of bundling daemon + client in one binary).

if (args.Length > 0 && args[0] is "--help" or "-h")
{
    Console.Write(FirewallOptions.DescribeEnvironment());
    return 0;
}

// The settings file lives beside the binary, which is not the working directory either role starts in
// — the daemon is socket-activated by systemd, and the client is shelled from anywhere — so it is named
// absolutely. Environment variables are registered after it and therefore win, since configuration
// resolves by source order.
IConfigurationRoot configuration = new ConfigurationBuilder()
    .AddJsonFile(Path.Combine(AppContext.BaseDirectory, "kgsm-firewall.settings.json"),
        optional: true, reloadOnChange: false)
    .AddEnvironmentVariables()
    .Build();

FirewallOptions options = FirewallOptions.FromSettings(
    configuration.GetSection(FirewallSettings.Section).Get<FirewallSettings>() ?? new FirewallSettings());

// Socket activation means systemd handed us the listening socket; serve regardless of args. Otherwise
// the first arg is the verb; a bare invocation prints usage.
bool activated = SocketActivation.IsActivated();
string verb = args.Length > 0 ? args[0] : (activated ? "serve" : "help");

if (verb is "help")
{
    Console.Write(FirewallOptions.DescribeEnvironment());
    return 0;
}

if (verb is "serve")
{
    using var cts = new CancellationTokenSource();
    using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, c => { c.Cancel = true; cts.Cancel(); });
    using var sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, c => { c.Cancel = true; cts.Cancel(); });
    return await DaemonHost.RunAsync(options, configuration, cts.Token);
}

// CLI client: verb + its own arguments.
string[] verbArgs = args.Length > 1 ? args[1..] : [];
using var clientCts = new CancellationTokenSource();
using var clientSigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, c => { c.Cancel = true; clientCts.Cancel(); });
return await FirewallCliClient.RunAsync(verb, verbArgs, options, clientCts.Token);
