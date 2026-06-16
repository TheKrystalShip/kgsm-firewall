# CLAUDE.md — kgsm-firewall

Guidance for Claude Code working in this repo. kgsm-firewall is the KGSM ecosystem's **host-firewall
authority** — a lean, .NET 10 Native-AOT, socket-activated privileged helper that owns all host-firewall
state (open/close/list) behind a firewall-agnostic driver seam.

**Read `../headless-network-plan.md` first** — §7 is the authoritative design and rationale; `README.md` is
the authoritative deploy/operate guide. This file is the working-rules summary for editing the code.

## Current state

kgsm-firewall is feature-complete and deployed. The pieces, by directory:

- **Authority daemon + bundled CLI** (`Host/`, `Program.cs`) — one Native-AOT binary with two roles: the
  socket-activated root daemon (`serve`) and its own CLI client (`ensure-open`/`remove`/`list`/`backend`)
  over a newline-delimited-JSON unix socket. Real systemd FD adoption (`sd_listen_fds`), else bind-own-path
  for dev. ufw mutations are serialised through one gate (ufw's global lock). The **exit-code contract**
  (`ExitCodes`: unreachable / unsupported / op-failed / unknown) lets the kgsm bash caller distinguish
  "authority down → abort the install" from "backend reached but rejected the rule".
- **Idle-exit** — the socket-activated daemon exits after `KGSM_FIREWALL_IDLE_TIMEOUT`s with no connections
  (default 30; `0` = resident; a positive value below 5 is clamped to 5) so it does not hold root 24/7;
  systemd re-activates it on the next connection. Gated on socket activation (a manual run has nothing to
  re-spawn it, so it stays resident). The accept loop holds **one outstanding accept** and races it against
  the idle delay, exiting only when no handler is in flight and no connection has landed — so an in-flight
  `ufw` write is never abandoned. Idle-exit returns 0, and the `.service` carries `StartLimitIntervalSec=0`
  so activate/idle-exit bursts can't trip systemd's start-rate limit (which would make the authority
  unreachable and abort a hard-fail install). **No boot-reconcile loop by design:** ufw persists its own
  rules in `/etc/ufw` (replayed at boot by `ufw.service`), so the on-demand daemon need not run at boot.
- **Core domain + ufw driver** (`Core/`, `Drivers/Ufw/`) — the `IFirewallDriver` seam, capability model,
  validation (before any driver), backend detection, and the ufw driver: application-profile store +
  render/parse, ownership tag `kgsm-<instance>`, honest `Unknown`. ufw is the only driver today; others are
  drop-in (see Conventions).
- **Wire contract** — the standalone `src/Firewall.Contracts` project (net9.0, AOT/trim-clean, **no kgsm-lib
  reference**, own `PortDto`): the public request/response DTOs, op/outcome tokens, line protocol, and
  source-gen JSON. Both the daemon and kgsm-lib's client consume this one package, so the wire can't drift.
- **Consumers.** kgsm (bash) routes its `files firewall` path through the IPC chokepoint
  `commands/handlers/firewall.sh`, which shells the bundled CLI; on a confirmed open/close the bash command
  layer emits the `instance_ports_opened`/`instance_ports_closed` kgsm events (payload `Ports` = the
  canonical structured `[{start,end,protocol}]`). C# consumers go through kgsm-lib's `IFirewallService`
  (the socket client, parallel to `IWatchdogClient`), which maps `PortMapping`↔`PortDto` and never emits
  events. **Asymmetric hard-fail:** enable/install aborts if the authority is unreachable; disable/uninstall
  warns and continues so a down authority can't wedge an uninstall.
- **Deployment.** The AOT single-file binary lives at `/opt/kgsm-firewall/kgsm-firewall` (symlinked into
  `/usr/local/bin`); the socket is `root:kgsm` 0660; `kgsm-firewall.socket` is enabled (boots) and the
  `.service` is socket-activated + idle-exiting. `README.md` is the operator deploy/validate/troubleshoot
  guide and ships a health-check script in `deploy/`.

## Invariants (do not break)

- **No dependency on kgsm-lib.** kgsm-lib consumes the `Firewall.Contracts` package; the reverse is a
  dependency cycle. In particular **do not reference kgsm-lib's `PortMapping`** — this repo has its own
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

# De-risk systemd FD adoption against the PUBLISHED AOT binary (the one path no unit test covers):
BIN=src/Firewall/bin/Release/net10.0/linux-x64/publish/kgsm-firewall
systemd-socket-activate -l /tmp/fw.sock "$BIN" serve &
printf '{"op":"backend"}\n' | socat -t5 - UNIX-CONNECT:/tmp/fw.sock   # or: KGSM_FIREWALL_SOCKET=/tmp/fw.sock "$BIN" backend
```

## Conventions

- Namespaces `TheKrystalShip.KGSM.Firewall[.Core|.Drivers.Ufw]`; assembly `kgsm-firewall`. Types are
  `internal` (the daemon is the only consumer; the public wire surface is the separate Contracts package),
  exposed to tests via `InternalsVisibleTo`.
- Adding a backend = implement `IFirewallDriver` in `Drivers/<Backend>/`, declare its `Capabilities`, add a
  detection branch. Nothing else moves (mirrors kgsm-lib's `IDiscordIdentityResolver` one-interface seam).
- Tests use the fakes in `tests/Firewall.Tests/Fakes/` (`FakeProcessRunner`, `InMemoryUfwProfileStore`,
  `FakeFirewallDriver`) — no real `ufw`/filesystem access. Keep it that way; gate any real-ufw test on
  root/passwordless-sudo, as kgsm does for its firewall integration tests.
