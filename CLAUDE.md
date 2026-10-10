# CLAUDE.md — kgsm-firewall

The host-firewall authority: a .NET 10 Native-AOT, socket-activated helper that runs as root and owns all
host-firewall state (open, close, list) behind a firewall-agnostic driver seam. Role, contracts and peers:
`../kgsm-docs/components/kgsm-firewall.md`; behaviour and failure modes:
`../kgsm-docs/systems/operations/firewall-and-ports.md`; why it is a root authority of its own:
`../kgsm-docs/decisions/0013-firewall-is-a-root-authority-of-its-own.md`. `README.md` is the deploy,
validate and troubleshoot guide and lists the layout.

## Code map

- `Host/`, `Program.cs`: one binary, two roles. The socket-activated root daemon (`serve`) and its own CLI
  client (`ensure-open`, `remove`, `list`, `backend`) over a newline-delimited-JSON unix socket. Real
  systemd FD adoption (`sd_listen_fds`), else bind-own-path for dev. ufw mutations serialise through one
  gate (ufw's global lock). `ExitCodes` (unreachable, unsupported, op-failed, unknown) lets the kgsm bash
  caller tell "authority down, abort the install" from "backend reached but rejected the rule".
- `Host/FirewallJournal.cs`: the edges this authority applied, via `TheKrystalShip.KGSM.Journal`. The
  directory is created at startup so a reader can discover the producer before its first edge; it is
  root-owned and world-readable (0755/0644), because the record holds which ports opened, not a credential.
- `Core/`, `Drivers/Ufw/`: the `IFirewallDriver` seam, capability model, validation (before any driver),
  backend detection, and the ufw driver (profile store, render/parse, ownership tag `kgsm-<instance>`).
- `src/Firewall.Contracts`: the standalone wire package (own `PortDto`, no kgsm-lib reference, source-gen
  JSON) consumed by the daemon and by kgsm-lib's client, so the wire cannot drift. Wire:
  `../kgsm-docs/reference/firewall-authority.md`.
- Consumers: kgsm (bash) through `commands/handlers/firewall.sh`, which shells the bundled CLI; C# through
  kgsm-lib's `IFirewallService`, which maps `PortMapping` to `PortDto`.

## Idle-exit

The daemon exits after `Firewall__IdleTimeoutSeconds` with no connections (default 30; `0` is resident; a
positive value below 5 is clamped to 5), so it does not hold root around the clock. It is gated on socket
activation: a manual run has nothing to re-spawn it, so it stays resident. The accept loop holds one
outstanding accept and races it against the idle delay, exiting only when no handler is in flight and no
connection has landed, so an in-flight `ufw` write is never abandoned. Idle-exit returns 0, and the
`.service` carries `StartLimitIntervalSec=0` so activate/idle-exit bursts cannot trip systemd's start-rate
limit and make the authority unreachable. There is no boot-reconcile loop: ufw replays its own rules from
`/etc/ufw` at boot.

## Deploying

`deploy/setup.sh` provisions the host once; `deploy/deploy.sh` refuses before building with "run
`deploy/setup.sh`" on an unprovisioned host. **This is the one `deploy.sh` that asks for sudo, and
deliberately**: the daemon runs as root, so its binary and units stay root-owned (a root-executed binary an
unprivileged user can rewrite is a privilege-escalation path). The escalation is two calls, installing the
binary root-owned and refreshing the `/usr/local/bin` symlink. Do not widen it, and do not "fix" it to match
the other repos' passwordless pattern. The `systemctl` verbs still go through the polkit grant.

## Invariants

- **No dependency on kgsm-lib.** A root process takes the small packages it needs: `Firewall.Contracts` and
  `TheKrystalShip.KGSM.Journal` (whose only dependency is `Logging.Abstractions`). Do not reference
  kgsm-lib's `PortMapping`; this repo has its own `PortSpec`, mapped at kgsm-lib's `IFirewallService`.
- **Never fabricate a status.** A backend that cannot answer "is this open" returns `Unknown`, never a
  guessed empty list or `open:false`.
- **Validation lives in the service core, before the driver**; drivers assume well-formed input.
- **Each driver owns its native rendering.** The contract passes structured ports only.
- **Ownership tagging is mandatory on every driver** (`kgsm-<instance>`); list and remove touch only our
  rules. Detection precedence: `active ufw/firewalld > nft > iptables > none`.
- **Native-AOT safe and reflection-free.** Plain `Microsoft.NET.Sdk` (not `Sdk.Web`), `PublishAot`. Shell out
  through `Process` + `ArgumentList` only. `dotnet publish -r linux-x64` stays a clean ILC pass; use
  `[GeneratedRegex]`, never a runtime `new Regex`.
- **This authority alone records the firewall edges it applied**, in its own journal
  (`Firewall__EventJournalDirectory`, default `/var/lib/kgsm-firewall/events`). No caller records one; a
  second author puts one change in the trail twice under two names.
- **Provenance is repeated, never vouched for.** `FirewallRequest.Actor`/`Origin` are written onto the
  record unchecked. A caller naming nobody produces a real null, never a substituted `system`. The bundled
  CLI reads `KGSM_EVENT_ACTOR`/`KGSM_EVENT_ORIGIN`, the variables kgsm's own emitter reads.
- **Only a confirmed change is recorded.** `applied`, `applied-inactive` and `removed` are edges; a no-op,
  an unsupported backend and a refusal produce no line.

## Commands

```bash
dotnet build kgsm-firewall.slnx -c Release
dotnet test  kgsm-firewall.slnx -c Release
dotnet test  kgsm-firewall.slnx -c Release --filter "FullyQualifiedName~UfwDriverTests"
dotnet publish src/Firewall/Firewall.csproj -c Release -r linux-x64   # expect 0 warnings

# FD adoption against the PUBLISHED AOT binary (the one path no unit test covers):
BIN=src/Firewall/bin/Release/net10.0/linux-x64/publish/kgsm-firewall
# systemd-socket-activate sanitises the child's environment, so Firewall__* set around it does not reach
# the daemon (use --setenv, or run `serve` directly, to exercise a knob).
systemd-socket-activate -l /tmp/fw.sock "$BIN" serve &
printf '{"op":"backend"}\n' | socat -t5 - UNIX-CONNECT:/tmp/fw.sock   # or: Firewall__SocketPath=/tmp/fw.sock "$BIN" backend
```

## Conventions

- **Logging:** `../kgsm-docs/reference/logging-convention.md`. The daemon builds a bare
  `LoggerFactory.Create` (no host) with `AddSystemdConsole()` and `kgsm-firewall.settings.json`/env levels;
  the CLI-client path stays `Console.WriteLine` (user output, off the log channel).
- **The leaf config descriptor is generated.** `deploy/kgsm-firewall.leaf.json` comes from `[ConfigField]`
  attributes and `<panel>` doc tags on `FirewallSettings`, rewritten on every build by
  `TheKrystalShip.KGSM.ComponentConfig`: edit the settings class, never the JSON, and commit what the build
  produces. The same build writes `deploy/kgsm-firewall.leaf.actions.json` from
  `src/Firewall/ActionDeclarations.cs`. Format: `../kgsm-docs/reference/leaf-config-descriptor.md`;
  mechanism: `../kgsm-componentconfig/README.md`.
- Namespaces `TheKrystalShip.KGSM.Firewall[.Core|.Drivers.Ufw]`, assembly `kgsm-firewall`. Types are
  `internal`, exposed to tests via `InternalsVisibleTo`.
- Adding a backend: implement `IFirewallDriver` in `Drivers/<Backend>/`, declare its `Capabilities`, add a
  detection branch. Nothing else moves.
- Tests use the fakes in `tests/Firewall.Tests/Fakes/` (`FakeProcessRunner`, `InMemoryUfwProfileStore`,
  `FakeFirewallDriver`) and touch no real `ufw` or filesystem. Gate any real-ufw test on
  root/passwordless-sudo.

## Version tracking

- Versions are `<Version>` in `src/Firewall/Firewall.csproj` (the daemon and the package) and
  `src/Firewall.Contracts/Firewall.Contracts.csproj` (the contracts package, versioned independently);
  `./deploy/version.sh` prints the daemon's (`--pkgver` for the pacman form).
- Bump for every user-facing change (patch for fixes, minor for features, major for breaking changes), with a
  `CHANGELOG.md` entry under `## [Unreleased]`, and tag it `git tag -a v<version> -m "kgsm-firewall v<version>"`.

## Read before changing

- `../kgsm-docs/reference/firewall-authority.md`, `systems/operations/firewall-and-ports.md`.
- `../kgsm-docs/reference/event-vocabulary.md`: the `network.ports.*` edges it journals.
- `../kgsm-docs/systems/components/`: the descriptor and action declarations.

Docs and comments describe the system as it is now: present tense, no history, no emoji, no volatile
numbers (workspace `../CLAUDE.md`).
