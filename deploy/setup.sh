#!/usr/bin/env bash
#
# setup.sh — one-shot host provisioning for kgsm-firewall. Run it ONCE per host.
#
#   ./deploy/setup.sh
#
# Idempotent: safe to re-run any time. A steady-state re-run changes nothing.
#
# What it provisions:
#   1. /opt/kgsm-firewall           — the install dir, ROOT-owned (the daemon runs as root).
#   2. /etc/kgsm-firewall/…env      — optional operator overrides, seeded from the repo template
#                                     if absent. NEVER overwritten.
#   3. the two units                — kgsm-firewall.service (socket-activated, never enabled
#                                     directly) + kgsm-firewall.socket (enabled — boots and binds
#                                     the control socket, with SocketGroup substituted).
#   4. a scoped polkit rule         — lets you drive systemctl for these two units with no
#                                     password, so deploy.sh needs privilege for the BINARY only.
#   5. the socket enabled + started.
#
# ── This project keeps ONE sudo step on every deploy, deliberately ────────────────────────────
# Everywhere else in the ecosystem, deploy.sh is fully headless because the install prefix and
# unit files are owned by the deploying user. That is unsafe here: this daemon runs as ROOT (it
# drives ufw), and a root-executed binary or unit that an unprivileged user can rewrite is a real
# privilege-escalation path. So the binary and the units stay root-owned and deploy.sh sudo's
# those two installs. Everything else about the contract is identical to the other projects.
#
# Non-interactive (CI / an agent): no password ever lives in this script — point sudo at an
# askpass helper instead.
#   printf '#!/bin/sh\necho YOUR_PASS\n' > /tmp/ap && chmod 700 /tmp/ap
#   SUDO='sudo -A' SUDO_ASKPASS=/tmp/ap ./deploy/setup.sh
#
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/deploy-common.sh"

trap 'err "setup failed (line ${LINENO}). The host may be partly provisioned — re-run this script."; exit 1' ERR

refuse_root

log "provisioning ${PROJECT} (root-owned daemon; socket group '${SOCK_GROUP}')"

$SUDO true || { err "sudo is not usable — setup needs it."; exit 1; }

# ── 1. The install dir (root-owned — the daemon runs as root) ─────────────────
[[ -d "$PREFIX" ]] || { log "creating ${PREFIX} (root-owned)"; $SUDO install -d -m 0755 "$PREFIX"; }

# ── 2. Operator config — seeded once, never clobbered ─────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    log "creating ${ENV_FILE} from template (optional overrides)"
    $SUDO install -d -m 0755 "$ENV_DIR"
    $SUDO install -m 0644 "$ENV_EXAMPLE" "$ENV_FILE"
fi

# ── 3. The units (root-owned regular files) ───────────────────────────────────
install_units_privileged
if [[ "$UNIT_CHANGED" -eq 1 ]]; then
    log "reloading systemd"
    $SUDO systemctl daemon-reload
fi

# ── 4. The polkit grant ───────────────────────────────────────────────────────
# Scoped to these two units and the verbs deploy.sh uses. This is what keeps the deploy down to
# a SINGLE privileged step (the binary) instead of one per systemctl call.
POLKIT_RENDERED="$(mktemp)"
{
    cat <<EOF
// 48-${PROJECT}-deploy.rules — headless-deploy grant for ${PROJECT}.
//
// Installed by ${PROJECT}/deploy/setup.sh. Lets '${DEPLOY_USER}' run the systemctl verbs that
// deploy/deploy.sh needs, for THIS project's units only, with no password and no interactive
// auth agent. Every other unit on the host is untouched by this rule.
//
// Managed by setup.sh — re-run it rather than hand-editing this file.
polkit.addRule(function(action, subject) {
    if (subject.user !== "${DEPLOY_USER}") {
        return;
    }

    // daemon-reload: global by nature (the action carries no unit), re-reads unit files only.
    if (action.id === "org.freedesktop.systemd1.reload-daemon") {
        return polkit.Result.YES;
    }

    if (action.id !== "org.freedesktop.systemd1.manage-units") {
        return;
    }

    var units = {
EOF
    for u in "${UNITS[@]}"; do printf '        "%s": true,\n' "$u"; done
    cat <<'EOF'
    };
    if (units[action.lookup("unit")] !== true) {
        return;
    }

    var verb = action.lookup("verb");
    if (verb === "start" || verb === "stop" || verb === "restart" ||
        verb === "reload" || verb === "try-restart" || verb === "reload-or-restart") {
        return polkit.Result.YES;
    }
});
EOF
} > "$POLKIT_RENDERED"

if $SUDO cmp -s "$POLKIT_RENDERED" "$POLKIT_DST" 2>/dev/null; then
    : # already current
else
    log "installing polkit grant → ${POLKIT_DST}"
    $SUDO install -D -m 0644 "$POLKIT_RENDERED" "$POLKIT_DST"
fi
rm -f "$POLKIT_RENDERED"

# ── 5. Enable the SOCKET (not the service — it is socket-activated + idle-exits) ──
# Stop first so a SocketGroup change takes effect on re-listen.
$SUDO systemctl stop "${ENABLE_UNITS[0]}" 2>/dev/null || true
log "enabling + starting ${ENABLE_UNITS[0]}"
$SUDO systemctl enable --now "${ENABLE_UNITS[0]}"

# ── 6. Verify the grant works unprivileged ────────────────────────────────────
log "verifying the headless grant (no password expected) ..."
GRANT_OK=0
for _ in 1 2 3 4 5; do
    if systemctl --no-ask-password daemon-reload 2>/dev/null &&
       systemctl --no-ask-password start "${ENABLE_UNITS[0]}" 2>/dev/null; then
        GRANT_OK=1
        break
    fi
    sleep 1
done

if [[ "$GRANT_OK" -ne 1 ]]; then
    err "the unprivileged systemctl calls were REFUSED — deploy.sh would prompt more than once."
    err "check polkit and ${POLKIT_DST}:  systemctl status polkit ; sudo cat ${POLKIT_DST}"
    exit 1
fi

trap - ERR

# ── 7. Summary ────────────────────────────────────────────────────────────────
log "${PROJECT} is provisioned ✓"
printf '   prefix : %s (root-owned — the daemon runs as root)\n' "$PREFIX"
printf '   units  : %s\n' "${UNITS[*]}"
printf '   socket : %s enabled, SocketGroup=%s\n' "${ENABLE_UNITS[0]}" "$SOCK_GROUP"
printf '   grant  : %s may start/stop/restart these units with no password\n' "$DEPLOY_USER"
printf '   config : %s\n' "$ENV_FILE"
printf '\n   deploy with:  %s/deploy/deploy.sh\n' "$REPO_DIR"
printf '   NOTE: that deploy asks for sudo ONCE, to install the root-owned binary. By design.\n'
printf '   deeper check: sudo %s/deploy/kgsm-firewall-healthcheck.sh\n' "$REPO_DIR"
