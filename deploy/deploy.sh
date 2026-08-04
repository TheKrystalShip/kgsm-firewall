#!/usr/bin/env bash
#
# deploy.sh — build + deploy the kgsm-firewall host-firewall authority.
#
#   ./deploy/deploy.sh
#
# Assumes deploy/setup.sh has already provisioned this host (install dir, units, socket enabled,
# polkit grant). If it has not, this script says so and stops before building.
#
# ── This is the one deploy in the ecosystem that asks for sudo ────────────────────────────────
# The daemon runs as ROOT (it drives ufw), so its binary at /opt/kgsm-firewall must be root-owned
# — a root-executed binary that an unprivileged user can rewrite is a real privilege-escalation
# path. So this script sudo's exactly two things: the binary install (every deploy) and the unit
# install (only when a unit changed). The systemctl calls go through setup.sh's polkit grant, so
# you are asked once, not once per step.
#
# Publishes the Native-AOT binary as YOU — a single self-contained native binary, NO .NET runtime
# needed on the host.
#
#   * binary  → /opt/kgsm-firewall/kgsm-firewall (+ symlink /usr/local/bin/kgsm-firewall),
#   * units   → refreshed only if changed,
#   * verified by the control socket being active (the daemon idle-exits by design, so the
#     .service is NOT expected to be "running" — deploy/kgsm-firewall-healthcheck.sh probes deeper).
#
# Non-interactive: SUDO='sudo -A' SUDO_ASKPASS=/path/to/askpass ./deploy/deploy.sh
#
# Knobs: RID, HEALTH_TRIES.
#
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/deploy-common.sh"

PROJECT_CSPROJ="$REPO_DIR/src/Firewall/Firewall.csproj"
RID="${RID:-linux-x64}"

trap 'err "deploy failed (line $LINENO)."; exit 1' ERR

# ── Preflight ─────────────────────────────────────────────────────────────────
refuse_root
require_setup
[[ -f "$PROJECT_CSPROJ" ]] || { err "project not found: $PROJECT_CSPROJ"; exit 1; }
command -v clang >/dev/null 2>&1 || warn "'clang' not found — Native-AOT publish needs a C toolchain (clang + zlib). Install it if publish fails."

# ── 1. Build (Native-AOT, as the invoking user) ────────────────────────────────
log "publishing Native-AOT (${RID}) → ${PUBLISH_DIR} (ILC compile — this takes a minute)"
rm -rf "$PUBLISH_DIR"
dotnet publish "$PROJECT_CSPROJ" -c Release -r "$RID" -o "$PUBLISH_DIR"

# ── 2. Units (privileged, cmp-guarded — silent when nothing changed) ───────────
install_units_privileged
if [[ "$UNIT_CHANGED" -eq 1 ]]; then
    log "reloading systemd"
    $SUDO systemctl daemon-reload
fi

# ── 2b. Publish the leaf config descriptor (unprivileged — the dir is yours) ───
# Before the swap, so the surface kgsm-api reads never lags the binary that implements it.
install_leaf_descriptor

# ── 3. Install the binary (THE privileged step — root-owned, root-executed) ────
log "installing binary → ${BIN} (needs sudo: root-owned, the daemon runs as root)"
$SUDO install -m 0755 -o root -g root "$PUBLISH_DIR/kgsm-firewall" "$BIN"
$SUDO ln -sfn "$BIN" "$BIN_LINK"

# The settings file goes beside the binary, root-owned for the same reason the binary is: it is read by
# a root process, so an unprivileged user who could rewrite it could point the authority anywhere.
# World-readable, because the bundled CLI client reads it too and runs as whoever invoked it.
$SUDO install -m 0644 -o root -g root "$PUBLISH_DIR/kgsm-firewall.settings.json" "${PREFIX}/kgsm-firewall.settings.json"

# ── 4. Re-activate the socket (via the polkit grant — no password) ─────────────
# Stop then start so a SocketGroup change takes effect on re-listen. The daemon itself is
# socket-activated and idle-exits; we never start the .service directly.
sysctl_do stop "${ENABLE_UNITS[0]}" || true
log "starting ${ENABLE_UNITS[0]}"
sysctl_do start "${ENABLE_UNITS[0]}"

# ── 5. Verify (the socket is listening; the daemon wakes on demand) ────────────
if wait_health; then
    log "kgsm-firewall control socket is active ✓  (daemon wakes on demand, idle-exits)"
    log "deeper check: sudo ${REPO_DIR}/deploy/kgsm-firewall-healthcheck.sh"
else
    err "${ENABLE_UNITS[0]} is not active. Recent logs:"
    journalctl -u "${ENABLE_UNITS[0]}" -u kgsm-firewall.service -n 30 --no-pager || true
    exit 1
fi
