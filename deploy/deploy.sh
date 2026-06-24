#!/usr/bin/env bash
#
# Build + deploy the kgsm-firewall host-firewall authority in one go.
#
#   ./deploy/deploy.sh
#
# Publishes the Native-AOT binary as YOU (the invoking user) and uses sudo ONLY for the steps that
# touch systemd / root-owned paths. The artifact is a single self-contained native binary — NO .NET
# runtime needed. The DAEMON runs as ROOT (it drives ufw); the SOCKET's filesystem perms are the
# only access boundary, so the socket group is set to the invoking user's group (this host has no
# dedicated 'kgsm' user — the KGSM user is whoever owns the instances).
#
#   * binary  → /opt/kgsm-firewall/kgsm-firewall (+ symlink /usr/local/bin/kgsm-firewall),
#   * units   → kgsm-firewall.service (socket-activated, never enabled directly) +
#               kgsm-firewall.socket (enabled — boots, binds the control socket),
#   * env     → /etc/kgsm-firewall/kgsm-firewall.env from template if absent (optional, never clobbered).
#
# Verified by the control socket being active (the daemon itself idle-exits by design, so the
# .service is not expected to be "running" — deploy/kgsm-firewall-healthcheck.sh probes deeper).
#
# Non-interactive: SUDO='sudo -A' SUDO_ASKPASS=/path/to/askpass ./deploy/deploy.sh
#
set -euo pipefail

# ── Paths / config ────────────────────────────────────────────────────────────
PREFIX="/opt/kgsm-firewall"
BIN_LINK="/usr/local/bin/kgsm-firewall"
SVC_UNIT_DST="/etc/systemd/system/kgsm-firewall.service"
SOCK_UNIT_DST="/etc/systemd/system/kgsm-firewall.socket"
ENV_DIR="/etc/kgsm-firewall"
ENV_FILE="$ENV_DIR/kgsm-firewall.env"
SOCKET_UNIT="kgsm-firewall.socket"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$REPO_DIR/src/Firewall/Firewall.csproj"
SVC_UNIT_SRC="$REPO_DIR/deploy/kgsm-firewall.service"
SOCK_UNIT_SRC="$REPO_DIR/deploy/kgsm-firewall.socket"
ENV_EXAMPLE="$REPO_DIR/deploy/kgsm-firewall.env.example"
PUBLISH_DIR="$REPO_DIR/artifacts/publish"
RID="${RID:-linux-x64}"
# The unprivileged group allowed to talk to the (root) authority socket. Defaults to the invoking
# user's primary group — the KGSM user that owns the instances.
SOCK_GROUP="${KGSM_FIREWALL_SOCKET_GROUP:-$(id -gn)}"
SUDO="${SUDO:-sudo}"

# ── Helpers ─────────────────────────────────────────────────────────────────
log() { printf '\033[1;34m>> %s\033[0m\n' "$*"; }
err() { printf '\033[1;31m!! %s\033[0m\n' "$*" >&2; }
trap 'err "deploy failed (line $LINENO)."; exit 1' ERR

# ── Pre-flight ────────────────────────────────────────────────────────────────
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    err "do NOT run this as root — run it as the KGSM (instance-owning) user. It builds as you and"
    err "sudo's only the systemd steps; the socket group is taken from YOUR group."
    exit 1
fi
[[ -f "$PROJECT" ]] || { err "project not found: $PROJECT"; exit 1; }
command -v clang >/dev/null 2>&1 || err "warning: 'clang' not found — Native-AOT publish needs a C toolchain (clang + zlib). Install it if publish fails."

# ── 1. Build (Native-AOT, as the invoking user) ────────────────────────────────
log "publishing Native-AOT (${RID}) → ${PUBLISH_DIR} (ILC compile — this takes a minute)"
rm -rf "$PUBLISH_DIR"
dotnet publish "$PROJECT" -c Release -r "$RID" -o "$PUBLISH_DIR"

# ── 2. Install binary + symlink (root-owned; the daemon runs as root) ──────────
log "installing binary → ${PREFIX}/kgsm-firewall"
$SUDO install -d -m 0755 "$PREFIX"
$SUDO install -m 0755 "$PUBLISH_DIR/kgsm-firewall" "$PREFIX/kgsm-firewall"
$SUDO ln -sfn "$PREFIX/kgsm-firewall" "$BIN_LINK"

# Env file (optional in the unit): create from template if absent, never clobber.
if [[ ! -f "$ENV_FILE" ]]; then
    log "creating ${ENV_FILE} from template (optional overrides)"
    $SUDO install -d -m 0755 "$ENV_DIR"
    $SUDO install -m 0644 "$ENV_EXAMPLE" "$ENV_FILE"
fi

# ── 3. Units: service verbatim; socket with SocketGroup substituted ────────────
UNIT_CHANGED=0
if ! cmp -s "$SVC_UNIT_SRC" "$SVC_UNIT_DST"; then
    log "installing ${SVC_UNIT_DST}"
    $SUDO install -m 0644 "$SVC_UNIT_SRC" "$SVC_UNIT_DST"
    UNIT_CHANGED=1
fi
TMP_SOCK="$(mktemp)"
sed "s/^SocketGroup=.*/SocketGroup=${SOCK_GROUP}/" "$SOCK_UNIT_SRC" > "$TMP_SOCK"
if ! cmp -s "$TMP_SOCK" "$SOCK_UNIT_DST"; then
    log "installing ${SOCK_UNIT_DST} (SocketGroup=${SOCK_GROUP})"
    $SUDO install -m 0644 "$TMP_SOCK" "$SOCK_UNIT_DST"
    UNIT_CHANGED=1
fi
rm -f "$TMP_SOCK"

if [[ "$UNIT_CHANGED" -eq 1 ]]; then
    log "reloading systemd"
    $SUDO systemctl daemon-reload
fi

# ── 4. Enable the SOCKET (not the service — it is socket-activated + idle-exits) ──
log "enabling + starting ${SOCKET_UNIT}"
# Re-activate cleanly: stop the socket so a SocketGroup change takes effect on re-listen.
$SUDO systemctl stop "$SOCKET_UNIT" 2>/dev/null || true
$SUDO systemctl enable --now "$SOCKET_UNIT"

# ── 5. Verify (the socket is listening; the daemon wakes on demand) ────────────
if systemctl is-active --quiet "$SOCKET_UNIT"; then
    log "kgsm-firewall control socket is active ✓  (daemon wakes on demand, idle-exits)"
    log "deeper check: sudo ${REPO_DIR}/deploy/kgsm-firewall-healthcheck.sh"
else
    err "${SOCKET_UNIT} is not active. Recent logs:"
    $SUDO journalctl -u "$SOCKET_UNIT" -u kgsm-firewall.service -n 30 --no-pager || true
    exit 1
fi
