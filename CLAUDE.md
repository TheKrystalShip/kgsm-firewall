# CLAUDE.md — kgsm-firewall

Guidance for Claude Code working in this repo. kgsm-firewall is the KGSM ecosystem's **host-firewall
authority** — a lean, .NET 10 Native-AOT, socket-activated privileged helper that owns all host-firewall
state (open/close/list) behind a firewall-agnostic driver seam.

**Read `../headless-network-plan.md` first** — §7 is the authoritative design and §7h is the build
sequence. This file is the working-rules summary; that doc is the source of truth.

## Status

- **Increment 0 — BUILT (this repo):** the core domain (`IFirewallDriver` seam, capability model,
  validation, backend detection) + the ufw driver + unit tests + a `detect` smoke verb. No host yet.
- **Increment 1 — not built:** the socket-activated daemon host (systemd `.socket`+`.service`) + the CLI
  client surface (`ensure-open`/`remove`/`list`) + boot reconcile.
- **Increment 2 — not built:** kgsm-lib `IFirewallService` (parallel to `IWatchdogClient`) + a shared
  `TheKrystalShip.KGSM.Firewall.Contracts` NuGet + the C#-side audit-event emission.
- **Increment 3 — not built:** kgsm bash cutover (`files.ufw.sh` → call the authority; hard-fail when it's
  down) + the new `instance_ports_opened`/`instance_ports_closed` kgsm events.

## Invariants (do not break)

- **No dependency on kgsm-lib.** kgsm-lib consumes the (future) `Firewall.Contracts` package; the reverse
  is a dependency cycle. In particular **do not reference kgsm-lib's `PortMapping`** — this repo has its own
  `PortSpec`; map at the `IFirewallService` boundary (in kgsm-lib), not here.
- **Never fabricate a status.** A backend that cannot answer "is this open" returns `Unknown`, never a
  guessed empty list / `open:false`. This authority is the only honest source for the kgsm-api `open`
  verdict (ecosystem rule: measured, or explicitly unknown — never invented).
- **Validation lives in the service core, before the driver.** Drivers assume well-formed input. Don't
  trust the caller, even kgsm.
- **Each driver owns its own native rendering** (ufw profile text, firewalld zone, nft chain…). The
  contract passes structured ports only; a pre-rendered backend artifact would break agnosticism.
- **Ownership tagging is mandatory on every driver:** `kgsm-<instance>`. List/remove must touch only our
  rules. Detection precedence: `active ufw/firewalld > nft > iptables > none`.
- **Native-AOT safe / reflection-free.** Plain `Microsoft.NET.Sdk` (NOT `Sdk.Web` — a privileged helper
  should not carry the ASP.NET HTTP stack), `PublishAot`, footprint-tuned like kgsm-watchdog. Shell out via
  `Process` + `ArgumentList` only (no shell, no reflection). Every change must keep `dotnet publish -r
  linux-x64` a clean ILC pass (0 IL2026/IL3050/ILC). Use `[GeneratedRegex]`, not runtime `new Regex`.
- **emit no kgsm events from here.** Firewall audit events are kgsm events; emission happens at the caller
  boundary (kgsm command layer for the bash path, kgsm-lib `EmitWithProvenance` for the C# path) — never
  from this leaf, which has no business knowing kgsm's event socket. See the plan's *Firewall audit events*.

## Commands

```bash
dotnet build kgsm-firewall.slnx -c Release
dotnet test  kgsm-firewall.slnx -c Release
dotnet test  kgsm-firewall.slnx -c Release --filter "FullyQualifiedName~UfwDriverTests"
dotnet publish src/Firewall/Firewall.csproj -c Release -r linux-x64   # expect 0 warnings
```

## Conventions

- Namespaces `TheKrystalShip.KGSM.Firewall[.Core|.Drivers.Ufw]`; assembly `kgsm-firewall`. Types are
  `internal` (the daemon is the only consumer; the public wire surface is the separate Contracts package),
  exposed to tests via `InternalsVisibleTo`.
- Adding a backend = implement `IFirewallDriver` in `Drivers/<Backend>/`, declare its `Capabilities`, add a
  detection branch. Nothing else moves (mirrors kgsm-lib's `IDiscordIdentityResolver` one-interface seam).
- Tests use the fakes in `tests/Firewall.Tests/Fakes/` (`FakeProcessRunner`, `InMemoryUfwProfileStore`,
  `FakeFirewallDriver`) — no real `ufw`/filesystem access. Keep it that way; gate any real-ufw test on
  root/passwordless-sudo like kgsm's `test_files_ufw_logic.sh`.
