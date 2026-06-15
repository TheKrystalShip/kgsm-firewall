# kgsm-firewall

The **host-firewall authority** for the KGSM ecosystem: the single, isolated, auditable door for all
host-firewall state. It owns the privileged **writes** (open/close an instance's ports) *and* the
privileged **reads** (is this port open) so that no other component ever shells `sudo ufw` — part of the
"headless KGSM, zero per-operation privilege escalation" effort.

> **Status:** **Increments 0 + 1 built** (this repo). Inc 0 = core domain + ufw driver. Inc 1 = the
> socket-activated daemon (systemd `.socket`+`.service`, real FD adoption) + the bundled CLI client
> (`ensure-open`/`remove`/`list`/`backend`) + exit-code contract — live-validated end-to-end against real
> systemd socket activation and real ufw. The daemon **idle-exits** after `KGSM_FIREWALL_IDLE_TIMEOUT`s
> (default 30; `0` = resident) so it doesn't hold root 24/7 — systemd re-activates it on the next
> connection. The kgsm-lib `IFirewallService` + `Firewall.Contracts` package (Inc 2) and the kgsm bash
> cutover (Inc 3) are not built yet. The authoritative design + build sequence live in
> **`../headless-network-plan.md` §7 (and §7h for the increments)** — read that first.

## Why it exists

kgsm currently shells `sudo ufw allow/delete` directly (`kgsm/commands/handlers/files.ufw.sh`), which
blocks headless callers (API / Discord bot / daemons). Host-firewall config is **persistent, privileged
host state** — a different axis from process-lifetime port forwarding (UPnP, which lives in the watchdog).
So it gets its own authority rather than being folded into the supervisor: the watchdog deliberately drops
to an unprivileged uid because it babysits untrusted game-server processes, and standing root does not
belong there. kgsm-firewall establishes its own privilege at activation and does nothing else.

## Design (one-paragraph version)

A **firewall-agnostic driver seam**. The contract speaks in domain terms, declaratively — *"this
instance's port set should be open"* — never *"add this iptables rule"*:

```
EnsureOpen(instance, ports[])   // make exactly these open under our ownership tag — idempotent
Remove(instance)                // tear down everything WE own for this instance
ListOwned(instance?)            // what we have open  → feeds the kgsm-api `open` / `open_ports[]` view
Backend / Capabilities          // which driver is active + what it can honestly do
```

**ufw is the first (and so far only) driver**; firewalld / nftables / iptables are drop-in drivers added
when a host needs one. Four things the seam standardizes so it is *truly* agnostic:

1. **Ownership tagging** — every rule is namespaced `kgsm-<instance>` (for ufw, an application profile of
   that name), so list/remove touch only what we created, never the operator's own firewall config.
2. **Capability declaration** — each driver states `{ canApply, canRemove, canList }`; the service
   degrades honestly instead of pretending.
3. **Honest `unknown`** — if a backend genuinely cannot answer "is this open" (e.g. `ufw status`
   unreadable), `ListOwned` returns `Unknown`, **never** a guessed empty list / `open:false`. kgsm-firewall
   is the only honest source for the kgsm-api `open` verdict, so it must not fabricate it.
4. **Detection precedence** — `active ufw/firewalld > raw nftables > raw iptables > none`
   (`KGSM_FIREWALL_BACKEND` overrides). Never poke the layer underneath an active high-level manager.

Validation (`port ∈ 1..65535`, `proto ∈ tcp|udp`, `instance` matches `^[A-Za-z0-9_-]+$`) is enforced in
the service **core, before the driver** — we don't trust the caller, even kgsm.

The **driver owns its own native rendering** (the ufw application-profile text), not kgsm — a pre-baked ufw
profile could never feed a firewalld/nft driver, so keeping rendering inside each driver is what makes the
seam genuinely backend-agnostic. kgsm passes only structured ports.

## Wiring (the dependency chokepoint holds)

- **kgsm (bash)** → kgsm-firewall directly (the binary doubles as its own CLI client; bash never speaks the
  socket protocol). *(Inc 3.)*
- **kgsm-api → kgsm-lib `IFirewallService` → kgsm-firewall** — exactly parallel to `IWatchdogClient`; the
  API never talks to kgsm-firewall directly. *(Inc 2.)*
- **No dependency on kgsm-lib.** kgsm-lib consumes the `Firewall.Contracts` package (added in Inc 2), never
  the reverse — that would be a cycle. kgsm-firewall is dependency-free apart from logging abstractions.

## Build / test / run

```bash
dotnet build kgsm-firewall.slnx -c Release
dotnet test  kgsm-firewall.slnx -c Release
# Native AOT — must be a clean ILC pass (0 IL2026/IL3050/ILC warnings):
dotnet publish src/Firewall/Firewall.csproj -c Release -r linux-x64

BIN=./src/Firewall/bin/Release/net10.0/linux-x64/publish/kgsm-firewall
$BIN --help                                   # self-documenting: verbs + env knobs

# Dev (no systemd): run the daemon in one shell, drive it from another.
KGSM_FIREWALL_SOCKET=/tmp/fw.sock sudo -E $BIN serve &
KGSM_FIREWALL_SOCKET=/tmp/fw.sock $BIN backend
KGSM_FIREWALL_SOCKET=/tmp/fw.sock $BIN ensure-open myinst 34197/udp 27015:27020/tcp
KGSM_FIREWALL_SOCKET=/tmp/fw.sock $BIN list

# Production: systemd socket activation (see deploy/). The client wakes the daemon on first connect.
sudo install -D -m0755 $BIN /opt/kgsm-firewall/kgsm-firewall
sudo install -m0644 deploy/kgsm-firewall.{socket,service} /etc/systemd/system/
sudo systemctl enable --now kgsm-firewall.socket
```

## Layout

```
src/Firewall/
  Core/        # contract types, validation, process-runner seam, service orchestrator, detection,
               #   options, the null (honest-degradation) driver
  Drivers/Ufw/ # the ufw driver: profile store, profile render/parse, the driver
  Wire/        # the control-socket protocol: request/response DTOs, source-gen JSON, newline framing
  Host/        # the daemon (socket activation + accept loop + dispatch), the bundled CLI client,
               #   driver factory, stderr logger, exit-code contract, domain↔wire mapping
  Program.cs   # one binary, two roles: `serve` (daemon / socket-activated) vs a verb (CLI client)
deploy/        # kgsm-firewall.socket + .service (+ .env.example): socket-activated, root daemon
tests/Firewall.Tests/
```
