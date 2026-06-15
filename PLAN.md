# PLAN — kgsm-firewall

The authoritative design + rationale live in **`../headless-network-plan.md`** (§7 design, §7h build
sequence, §0 the lock decision that split UPnP-into-watchdog from firewall-into-its-own-authority). This
file is just the local increment tracker.

## Locked scoping (2026-06-15)

.NET 10 Native AOT · socket-activated privileged helper (systemd; NOPASSWD rejected) · **hard-fail (B)**
install fallback (a firewall-enabled install fails outright if the authority is down — explicit error,
never a silent skip) · new sibling repo · detection precedence `active ufw/firewalld > nft > iptables >
none`.

## Increments

- [x] **Inc 0 — core domain + ufw driver (this repo).** `IFirewallDriver` seam
      (`EnsureOpen`/`Remove`/`ListOwned`/`Capabilities`/`Backend`), capability model, core validation,
      backend detection, the AOT-safe `IProcessRunner` shell-out seam, the ufw driver (profile store +
      render/parse + driver, ownership tag `kgsm-<instance>`, honest `Unknown`). 51 unit tests; AOT publish
      clean. `detect` smoke verb. **No host wiring, no cross-repo change.**
- [ ] **Inc 1 — socket-activated host + CLI client.** systemd `.socket`+`.service` (mirror
      kgsm-watchdog/deploy), a thin daemon reading a request off a unix socket → validate → dispatch →
      typed reply. The binary doubles as its own CLI client (`ensure-open`/`remove`/`list`) so bash never
      parses a wire protocol. Boot reconcile (defensive self-heal — under hard-fail (B) it is not
      load-bearing; verify ufw rules persist in `/etc/ufw` across reboot). Read `kgsm/handlers/watchdog.sh`
      + kgsm-lib `IWatchdogClient` before choosing the socket protocol.
- [ ] **Inc 2 — kgsm-lib `IFirewallService` + `Firewall.Contracts` package.** Contract DTOs defined HERE
      (own `PortSpec`-shaped types, **no kgsm-lib `PortMapping` reference** — cycle), packed to local-nuget;
      kgsm-lib's `IFirewallService` (parallel to `IWatchdogClient`) maps `PortMapping`↔DTO at the boundary
      and owns the C#-side audit-event emission via `EmitWithProvenance(actor, origin=api)`.
- [ ] **Inc 3 — kgsm bash cutover (hard-fail).** `commands/handlers/files.ufw.sh` → call the authority
      instead of `$SUDO mv/chown/ufw`; keep exit codes 215/216; new dedicated EC code + explicit message
      when the authority is unreachable. Define + emit the new `instance_ports_opened`/
      `instance_ports_closed` kgsm events from the command layer. Update `test_files_ufw_logic.sh`.
- [ ] **Inc 4 (= Phase 4) — strip the embedded direct-ufw path** once the authority is proven.
- [ ] **Downstream (kgsm-api M5/M6, separate):** `server.firewall` `AuditAction` + `KgsmAuditConsumer`
      handlers; bump kgsm-lib to the version carrying the new event types.

## Keystone follow-up (tracked, not done)

`../system-architecture.md` must learn the new `kgsm-firewall` component (project-table row + the wiring
edge `kgsm / kgsm-lib → kgsm-firewall` and the `IFirewallService` chokepoint). Deferred per
`headless-network-plan.md` §12 until more of the build lands.
