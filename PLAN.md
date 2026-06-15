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
      render/parse + driver, ownership tag `kgsm-<instance>`, honest `Unknown`). 59 unit tests; AOT publish
      clean. **No host wiring, no cross-repo change.**
- [x] **Inc 1 — socket-activated host + CLI client (this repo).** `Wire/`: a newline-delimited-JSON
      request/response protocol over a unix socket (source-gen JSON, bounded reads) — deliberately NOT
      HTTP/Kestrel (the locked no-`Sdk.Web` invariant; the binary is its own client so nothing external
      parses the wire). `Host/`: the daemon (genuine systemd FD adoption via `sd_listen_fds`, else
      bind-own-path for dev; runs as root, no privilege drop; ufw mutations serialised through one gate
      for ufw's global lock), the bundled CLI client (`ensure-open`/`remove`/`list`/`backend`), the
      `DriverFactory` + `NullFirewallDriver` (honest degradation), a tiny stderr logger, and the
      **exit-code contract** (`ExitCodes`: 3 unreachable / 4 unsupported / 5 op-failed / 6 unknown — the
      seam Inc 3's hard-fail distinguishes "authority down → abort install" from "ufw rejected the rule").
      `deploy/`: `.socket` (RuntimeDirectory on the SOCKET unit, mode 0660, SocketGroup=kgsm) + `.service`
      (root, `serve`) + `.env.example`. **No boot-reconcile loop by design** — ufw persists its own rules
      in `/etc/ufw` (replayed at boot by `ufw.service`), so the on-demand daemon need not run at boot
      (verified: an opened rule lands in `user.rules`). 97 unit tests (incl. a no-root end-to-end over a
      real `AF_UNIX` socket); AOT publish clean. **Live-validated** end-to-end: real `systemd-socket-activate`
      FD adoption against the published binary, and a full install (units + root daemon + real ufw 0.36.2)
      open→verify→list→remove round-trip via the unprivileged client.
- [ ] **Inc 2 — kgsm-lib `IFirewallService` + `Firewall.Contracts` package.** Contract DTOs defined HERE
      (own `PortSpec`-shaped types, **no kgsm-lib `PortMapping` reference** — cycle), packed to local-nuget;
      kgsm-lib's `IFirewallService` (parallel to `IWatchdogClient`) maps `PortMapping`↔DTO at the boundary
      and owns the C#-side audit-event emission via `EmitWithProvenance(actor, origin=api)`.
- [ ] **Inc 3 — kgsm bash cutover (hard-fail).** `commands/handlers/files.ufw.sh` → call the authority
      instead of `$SUDO mv/chown/ufw`; keep exit codes 215/216; new dedicated EC code + explicit message
      when the authority is unreachable. Define + emit the new `instance_ports_opened`/
      `instance_ports_closed` kgsm events from the command layer. Update `test_files_ufw_logic.sh`.
- [ ] **Inc 4 (= Phase 4) — strip the embedded direct-ufw path** once the authority is proven.
- [x] **Follow-up — daemon idle-exit (BUILT 2026-06-15).** The daemon now exits after
      `KGSM_FIREWALL_IDLE_TIMEOUT` seconds with no connections (default 30; `0` = resident; a positive value
      below 5 is clamped to 5 to stop flapping); systemd re-activates it on the next connection, so it no
      longer holds root after first use. **Gated on socket activation** — a manual/dev run has nothing to
      re-spawn it, so it stays resident (`DaemonHost` reads `IsActivated()` *before* `Acquire()` clears
      `LISTEN_*`, then passes `Zero` when not activated). The accept loop keeps **one outstanding
      `acceptTask`** and races it against `Task.Delay(idle)`; on a busy/near-miss timeout it re-races the
      SAME accept (never cancels+reissues on the live listener), and exits only when truly quiescent
      (`_activeConnections == 0 && !acceptTask.IsCompleted`) so an in-flight `ufw` write is never abandoned
      and a just-accepted connection is never orphaned. Idle-exit returns 0 (no `Restart=on-failure`); the
      `.service` gained `StartLimitIntervalSec=0` so a burst of activate/idle-exit cycles can never trip
      systemd's start-rate limit and make the authority unreachable (which would abort an Inc-3 hard-fail
      install). 3 unit tests (idle-exits unaided / `0` stays resident / stays alive while a handler is busy
      then exits) + a `ParseIdleTimeout` theory pinning the env→TimeSpan contract (default/resident/clamp/
      reject) → 112 total; AOT 0-warn. Activation race is safe by systemd requeue — a connection landing
      as we exit stays in systemd's socket backlog and is served by the re-spawn.
- [ ] **Downstream (kgsm-api M5/M6, separate):** `server.firewall` `AuditAction` + `KgsmAuditConsumer`
      handlers; bump kgsm-lib to the version carrying the new event types.

## Keystone follow-up (tracked, not done)

`../system-architecture.md` must learn the new `kgsm-firewall` component (project-table row + the wiring
edge `kgsm / kgsm-lib → kgsm-firewall` and the `IFirewallService` chokepoint). Deferred per
`headless-network-plan.md` §12 until more of the build lands.
