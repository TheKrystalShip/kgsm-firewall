# kgsm-firewall

The **host-firewall authority** for the KGSM ecosystem: the single, isolated, auditable door for all
host-firewall state. It owns the privileged **writes** (open/close a game-server instance's ports) *and*
the privileged **reads** (which of our ports are open), so no other component ever shells `sudo ufw`. It is
how a headless KGSM deployment manages the host firewall with zero per-operation privilege escalation in
the callers.

This document is the authoritative reference for what kgsm-firewall is and how to deploy, configure,
validate, and operate it from a clean machine.

---

## What it is

- A small, dependency-free **.NET 10 Native-AOT** binary. It compiles to a **single self-contained native
  executable** — the target host needs **no .NET runtime** installed.
- One binary, **two roles**:
  - `serve` — the resident **authority daemon**. Runs as **root** (it must drive the firewall and write
    its config), detects the active firewall backend, and answers requests on a unix control socket.
  - a verb (`ensure-open` / `remove` / `list` / `backend`) — the **bundled CLI client**. It connects to the
    running daemon over the socket, prints a human-readable line, and exits with a meaningful status code.
    KGSM shells these verbs; nothing outside this binary ever speaks the socket's wire protocol.
- **Socket-activated** by systemd: the daemon is not running 24/7. systemd holds the listening socket and
  starts the daemon on the first connection. After a short idle period with no connections the daemon
  **exits**, and systemd re-activates it on demand — so the privileged process does not hold root while idle.
- A **firewall-agnostic driver seam**. The contract speaks in domain terms — *"this instance's port set
  should be open"* — never *"add this iptables rule"*. **ufw is the backend shipped today**; firewalld /
  nftables / iptables are drop-in drivers added when a host needs one.

Three guarantees the seam makes:

1. **Ownership tagging.** Every rule is namespaced `kgsm-<instance>` (for ufw, an application profile of
   that name), so `list`/`remove` touch only what kgsm-firewall created — never the operator's own firewall
   rules.
2. **Honest unknown.** If the backend genuinely cannot answer "is this open" (e.g. its status is
   unreadable), `list` returns *unknown* — never a guessed empty list. This authority is the only honest
   source for an instance's open-port view, so it does not fabricate one.
3. **Validation in the core.** Ports (`1..65535`), protocol (`tcp`/`udp`), and instance name
   (`^[A-Za-z0-9_-]+$`) are validated before any backend is touched — the authority does not trust its
   callers, even KGSM.

### Backend detection (read this before deploying)

On start, the daemon picks its backend with the precedence:

```
active ufw/firewalld  >  raw nftables  >  raw iptables  >  none
```

ufw and firewalld are themselves frontends over nft/iptables, so when one is **active** it is driven and
the layer underneath is left alone. **The shipped driver is ufw only.** This has one important consequence:

> **⚠ If ufw is installed but _inactive_, auto-detection falls through to nftables — which has no driver —
> so the authority reports `apply=False` and the first `ensure-open` fails.**
> Either **activate ufw** (`sudo ufw enable`) or **pin the backend** with `KGSM_FIREWALL_BACKEND=ufw`
> (see [Configuration](#configuration)). Pinning makes the authority write rules deterministically
> regardless of ufw's runtime state; ufw persists them and enforces them once it is active.

---

## Requirements

**Target host (where the authority runs):**

| Requirement | Why |
|---|---|
| Linux with **systemd** | socket activation + lifecycle |
| **root** for the daemon | it drives the firewall and writes the backend's config |
| A **firewall backend** — `ufw` today | the shipped driver. Install it (`apt install ufw`, `pacman -S ufw`, …) |
| ufw **active**, or `KGSM_FIREWALL_BACKEND=ufw` pinned | otherwise detection finds no usable driver (see the warning above) |
| A **group** shared with your KGSM user | the socket is `root:<group> 0660`; group membership *is* the access control |
| **No .NET runtime** | the binary is Native-AOT and self-contained |

**Build host (only if you build from source):**

- The **.NET 10 SDK**, targeting `linux-x64`. The build host and target host can be the same machine or
  different — the published binary is portable to any compatible Linux x64 host.

---

## Deploy

The steps below take a freshly cloned (or downloaded) project to a running, boot-persistent deployment.
Commands that change the system use `sudo`.

### 1. Get the binary

Build it from source (produces a single native executable — no runtime needed at the destination):

```bash
dotnet publish src/Firewall/Firewall.csproj -c Release -r linux-x64
# -> src/Firewall/bin/Release/net10.0/linux-x64/publish/kgsm-firewall   (a single ~3-4 MB file)
```

Or, if you were handed a prebuilt `kgsm-firewall` binary, just copy it to the build/staging host — it has
no dependencies to install.

### 2. Create the access group

The control socket is owned `root:<group>` with mode `0660`. Membership in that group is the *entire*
access boundary (there is no in-daemon authentication), so the unprivileged KGSM user that issues firewall
commands must be in it. The default group name used by the shipped unit is `kgsm`:

```bash
sudo groupadd --system kgsm          # skip if it already exists
sudo usermod -aG kgsm <kgsm-user>    # the user KGSM runs as
```

> Group membership only takes effect in **new** login sessions. After adding the user, have them **re-login**
> (or run `newgrp kgsm` in an existing shell) before issuing firewall commands.

If you want a different group name, use it here and set `SocketGroup=` accordingly in step 4.

### 3. Install the binary

```bash
BIN=src/Firewall/bin/Release/net10.0/linux-x64/publish/kgsm-firewall
sudo install -D -m 0755 "$BIN" /opt/kgsm-firewall/kgsm-firewall
sudo ln -sf /opt/kgsm-firewall/kgsm-firewall /usr/local/bin/kgsm-firewall   # so KGSM + operators find it on PATH
```

> `/opt/kgsm-firewall/kgsm-firewall` is the path the shipped `kgsm-firewall.service` runs (`ExecStart=`).
> If you install elsewhere, update `ExecStart=` in `/etc/systemd/system/kgsm-firewall.service` to match.

### 4. Install the systemd units

```bash
sudo install -m 0644 deploy/kgsm-firewall.socket  /etc/systemd/system/
sudo install -m 0644 deploy/kgsm-firewall.service /etc/systemd/system/
```

If your KGSM user's group is **not** `kgsm`, edit `SocketGroup=` in `/etc/systemd/system/kgsm-firewall.socket`
to match before continuing.

### 5. Configure (optional)

All knobs have safe defaults and are set via an **environment file** the service reads. Create it only if
you need to change something — most commonly, to pin the backend:

```bash
sudo install -d -m 0755 /etc/kgsm-firewall
sudo cp deploy/kgsm-firewall.env.example /etc/kgsm-firewall/kgsm-firewall.env
sudo $EDITOR /etc/kgsm-firewall/kgsm-firewall.env
```

> **If ufw is not active on this host, set `KGSM_FIREWALL_BACKEND=ufw` here.** Without it, the authority
> will refuse to apply rules (it detects nftables, which has no driver). See [Configuration](#configuration)
> for the full list.

### 6. Enable and start

You enable **the socket**, never the service — the service is pulled in on demand by the socket.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kgsm-firewall.socket
```

That is it. The authority now starts on boot (the socket is enabled) and wakes on demand (the service is
socket-activated). Continue to [Validate](#validate).

---

## Configuration

Set these in `/etc/kgsm-firewall/kgsm-firewall.env` (or any way the service's `EnvironmentFile`/`Environment`
can reach them). The authoritative list is always printed by `kgsm-firewall --help`.

| Variable | Default | Purpose |
|---|---|---|
| `KGSM_FIREWALL_BACKEND` | *auto-detect* | Force the backend: `none` \| `ufw` \| `firewalld` \| `nftables` \| `iptables`. **Set to `ufw` if ufw may be inactive when a request arrives.** Auto-detect precedence: `active ufw/firewalld > nft > iptables > none`. |
| `KGSM_FIREWALL_SOCKET` | `/run/kgsm-firewall/firewall.sock` | Control socket path. **Must match `ListenStream=` in `kgsm-firewall.socket`** if you change it. |
| `KGSM_FIREWALL_UFW_APPLICATIONS_DIR` | `/etc/ufw/applications.d` | Where the ufw driver writes its `kgsm-<instance>` application profiles. |
| `KGSM_FIREWALL_IDLE_TIMEOUT` | `30` | Seconds the socket-activated daemon stays idle (no connections) before exiting; systemd re-activates it on the next request. `0` = stay resident. A positive value below `5` is clamped to `5` (anti-flap). Ignored when not socket-activated. |

Unrecognised `KGSM_FIREWALL_*` variables are flagged as a startup warning (likely typos), not silently
ignored.

The socket's filesystem permissions (`root:<group> 0660`, set on the **`.socket`** unit) are the only
access boundary — there is no application-level authentication. Guard the group accordingly.

---

## Validate

A bundled health-check script verifies the whole deployment from an **unprivileged** shell (it needs no
root — the daemon does the privileged work). Run it as a user **in the socket's group**:

```bash
deploy/kgsm-firewall-healthcheck.sh
```

It checks, with a `PASS`/`WARN`/`FAIL` line each and actionable fix hints: the binary is installed; the
socket unit is enabled (boots) and active (listening); the socket's owner/group/mode; that you can reach the
socket; that the backend is driveable (`apply=True`); and a full `open → list → remove` round-trip with a
throwaway probe that is always cleaned up. It exits non-zero if anything fails (warnings are tolerated). A
healthy host on which ufw is **active**:

```
PASS  binary found: kgsm-firewall
PASS  kgsm-firewall.socket is enabled (will start on boot)
PASS  kgsm-firewall.socket is active (listening)
PASS  socket /run/kgsm-firewall/firewall.sock is root:kgsm mode 660 (correct: the perms ARE the auth boundary)
PASS  current user (alice) is in the 'kgsm' group — may reach the authority
PASS  backend 'ufw' is driveable (backend=ufw apply=True remove=True list=True)
PASS  round-trip: ensure-open accepted (opened 1 spec(s) under kgsm-healthcheck-probe-1234)
PASS  round-trip: list shows the probe rule (ufw is active and enforcing)
PASS  round-trip: remove cleaned up the probe (zero residue)

OK — kgsm-firewall is deployed and healthy.
```

### Quick manual checks

```bash
systemctl status kgsm-firewall.socket        # should be 'active (listening)'
kgsm-firewall backend                        # -> backend=ufw apply=True remove=True list=True
```

> **Note on `list` while ufw is _inactive_.** When ufw is not active, `ensure-open` still **succeeds** — the
> rule is written and persisted — but `list` shows **nothing**, because `list` reports rules ufw is actually
> *enforcing*, and ufw enforces nothing while inactive. This is expected: the rules are saved and become
> active the moment you run `sudo ufw enable`. The health-check script reports this as a `WARN`, not a
> failure, for exactly this reason.

---

## Operating it

- **The `.service` being `inactive (dead)` is normal.** It is socket-activated and idle-exits; it runs only
  while serving a request. Look at the **socket**, not the service, for "is it up":
  `systemctl status kgsm-firewall.socket`.
- **Logs:** `journalctl -u kgsm-firewall.service` (the daemon logs to stderr; systemd captures it). Each
  activation is a fresh short-lived process, so logs come in bursts around firewall operations.
- **Restart after a config change:** `sudo systemctl restart kgsm-firewall.socket`. The next request starts
  a daemon with the new environment.
- **Enforcement is ufw's job.** kgsm-firewall writes and persists rules; ufw enforces them. If ufw is
  inactive, rules are stored but not enforced until `sudo ufw enable`.

---

## Uninstall

```bash
sudo systemctl disable --now kgsm-firewall.socket
sudo rm /etc/systemd/system/kgsm-firewall.socket /etc/systemd/system/kgsm-firewall.service
sudo systemctl daemon-reload
sudo rm -rf /opt/kgsm-firewall /usr/local/bin/kgsm-firewall /etc/kgsm-firewall
# Optionally remove any rules it created (per instance): kgsm-firewall remove <instance>  (before disabling),
# or remove leftover profiles: sudo rm /etc/ufw/applications.d/kgsm-*
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `cannot reach the firewall authority … Permission denied` | The calling user is not in the socket's group, or hasn't re-logged in since being added. `sudo usermod -aG kgsm <user>`, then re-login (or `newgrp kgsm`). |
| `cannot reach the firewall authority … No such file or directory` | The socket isn't bound. `systemctl status kgsm-firewall.socket`; `sudo systemctl enable --now kgsm-firewall.socket`. |
| `backend=… apply=False` / `backend=none` | No usable driver. Usually ufw is inactive and detection fell to nftables. `sudo ufw enable`, **or** pin `KGSM_FIREWALL_BACKEND=ufw` and `sudo systemctl restart kgsm-firewall.socket`. |
| `ensure-open` succeeds but `list` is empty | Expected while ufw is inactive — see the note under [Validate](#validate). `sudo ufw enable` to enforce. |
| A rule operation fails with a ufw error | Reachable authority, ufw rejected the rule. The daemon's stderr (`journalctl -u kgsm-firewall.service`) carries ufw's message. |

### CLI exit codes

The client maps each outcome to a distinct code so callers (KGSM) can tell "authority down" from "rule
rejected":

| Code | Meaning |
|---|---|
| `0` | success — applied / removed / no-op / successful read |
| `2` | usage error (bad arguments; never left the client) |
| `3` | **unreachable** — could not reach the authority (socket missing / refused) |
| `4` | unsupported — reached, but no usable backend/driver |
| `5` | op-failed — reached, the operation was attempted and failed |
| `6` | unknown — `list` only: the backend genuinely cannot answer (honest unknown) |

---

## CLI reference

```
kgsm-firewall serve                              run the daemon (or be socket-activated)
kgsm-firewall ensure-open <instance> <port>...   open ports (e.g. 34197/udp 27015:27020/tcp)
kgsm-firewall remove <instance>                  close all ports owned for an instance
kgsm-firewall list [instance]                    list owned rules (all, or one instance)
kgsm-firewall backend                            report the active backend + capabilities
kgsm-firewall --help                             usage + every environment knob
```

Port tokens are `<port>/<proto>` or `<start>:<end>/<proto>`, `proto ∈ {tcp,udp}`.

---

## How KGSM uses it

You normally never call `kgsm-firewall` by hand — KGSM does, through the dependency chokepoint:

- **kgsm (bash)** invokes the bundled CLI verbs directly (it never speaks the socket protocol).
- **C# components** (the Control Panel API, etc.) go through **kgsm-lib's `IFirewallService`**, which is the
  socket client on the C# side — exactly parallel to how they reach the watchdog. They never talk to
  kgsm-firewall directly.

kgsm-firewall itself **emits no events** and **depends on no other KGSM component** (in particular, not on
kgsm-lib — that would be a dependency cycle). It is a standalone authority: deploy it next to a KGSM engine
and it works on its own.

---

## Build / test / develop

```bash
dotnet build  kgsm-firewall.slnx -c Release
dotnet test   kgsm-firewall.slnx -c Release
dotnet test   kgsm-firewall.slnx -c Release --filter "FullyQualifiedName~UfwDriverTests"

# Native AOT — every change must keep this a clean ILC pass (0 IL2026/IL3050/ILC warnings):
dotnet publish src/Firewall/Firewall.csproj -c Release -r linux-x64
```

Run it without systemd (dev): start the daemon on a temp socket in one shell, drive it from another.

```bash
BIN=src/Firewall/bin/Release/net10.0/linux-x64/publish/kgsm-firewall
KGSM_FIREWALL_SOCKET=/tmp/fw.sock sudo -E "$BIN" serve &
KGSM_FIREWALL_SOCKET=/tmp/fw.sock "$BIN" backend
KGSM_FIREWALL_SOCKET=/tmp/fw.sock "$BIN" ensure-open myinst 34197/udp 27015:27020/tcp
KGSM_FIREWALL_SOCKET=/tmp/fw.sock "$BIN" list
```

A manual `serve` run stays resident (no socket activation means nothing would re-spawn it after an
idle-exit). To exercise real systemd socket-activation against the published binary:

```bash
systemd-socket-activate -l /tmp/fw.sock "$BIN" serve &
printf '{"op":"backend"}\n' | socat -t5 - UNIX-CONNECT:/tmp/fw.sock
```

---

## Layout

```
src/
  Firewall.Contracts/   # the public wire contract (request/response DTOs, source-gen JSON, line framing),
                        #   a standalone package consumed by both the daemon and kgsm-lib's client — one
                        #   definition, no drift; no kgsm-lib dependency (own PortDto)
  Firewall/
    Core/        # contract types, validation, process-runner seam, service orchestrator, backend
                 #   detection, options, the null (honest-degradation) driver
    Drivers/Ufw/ # the ufw driver: profile store, profile render/parse, the driver
    Host/        # the daemon (socket activation + accept loop + dispatch + idle-exit), the bundled CLI
                 #   client, driver factory, stderr logger, the exit-code contract, domain↔wire mapping
    Program.cs   # one binary, two roles: `serve` (daemon) vs a verb (CLI client)
deploy/          # systemd units (.socket + .service), .env.example, and the health-check script
tests/Firewall.Tests/
```
