# CLAUDE.md — kgsm-firewall

Guidance for Claude Code working in this repo. kgsm-firewall is the KGSM ecosystem's **host-firewall
authority** — a lean, .NET 10 Native-AOT, socket-activated privileged helper that owns all host-firewall
state (open/close/list) behind a firewall-agnostic driver seam.

**Read `../headless-network-plan.md` first** — §7 is the authoritative design and §7h is the build
sequence. This file is the working-rules summary; that doc is the source of truth.

## Status

- **Increment 0 — BUILT (this repo):** the core domain (`IFirewallDriver` seam, capability model,
  validation, backend detection) + the ufw driver + unit tests.
- **Increment 1 — BUILT (this repo):** the socket-activated daemon (`Host/`: real systemd FD adoption,
  accept loop, dispatch, mutation serialisation) + the bundled CLI client (`ensure-open`/`remove`/`list`/
  `backend`) over a newline-delimited-JSON unix-socket protocol (`Wire/`) + the exit-code contract
  (`ExitCodes`: unreachable / unsupported / op-failed / unknown — the seam Inc 3 hard-fail builds on) +
  systemd units (`deploy/`). Live-validated against real systemd socket activation + real ufw. No
  boot-reconcile loop by design: ufw persists its own rules in `/etc/ufw` (replayed at boot by
  `ufw.service`), so the socket-activated daemon need not run at boot — verified the rule lands in
  `user.rules`.
  - **Idle-exit (Inc-1 follow-up, BUILT):** the daemon exits after `KGSM_FIREWALL_IDLE_TIMEOUT`s with no
    connections (default 30; `0` = resident; positive values <5 clamped to 5) so it does not hold root
    24/7 — systemd re-activates on the next connection. Gated on socket activation (a manual run stays
    resident — nothing would re-spawn it). The accept loop holds one outstanding accept and races it
    against the idle delay; it exits only when no handler is in flight and no connection has landed, so an
    in-flight `ufw` write is never abandoned. `.service` carries `StartLimitIntervalSec=0` so activate/
    idle-exit bursts can't trip systemd's rate limit (→ unreachable → Inc-3 hard-fail abort).
- **Increment 2 — BUILT (this repo + kgsm-lib):** the wire contract is now the standalone
  `src/Firewall.Contracts` project (net9.0, AOT/trim-clean, no kgsm-lib ref), packed as
  `TheKrystalShip.KGSM.Firewall.Contracts` 1.0.0 → local-nuget; the daemon **consumes that package** (the
  internal `Wire/` is gone — one definition, no drift). kgsm-lib gained `IFirewallService` +
  `FirewallService` (an NDJSON-over-unix-socket client — the authority is not HTTP — mapping
  `PortMapping`↔`PortDto`, with outcome-distinct result types + honest `Unknown` and a `FirewallException`
  on an unreachable authority), `AddKgsmFirewallClient`, kgsm-lib → 1.11.0. **Transport-only**: the client
  emits NO events — audit-event emission is deferred to Inc 3 (where it lands with the kgsm-bash event
  definition), kept out of the transport client so a missing event service can't silently drop the audit.
- **Increment 3 — not built:** kgsm bash cutover (`files.ufw.sh` → call the authority; hard-fail when it's
  down) + **defining** the new `instance_ports_opened`/`instance_ports_closed` kgsm events and emitting
  them from both the bash path and the C# path (kgsm-lib `EmitWithProvenance`).

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
  root/passwordless-sudo like kgsm's `test_files_ufw_logic.sh`.
