#!/usr/bin/env bash
#
# deploy-common.sh — the shared parameter block + helpers for kgsm-firewall's deploy scripts.
#
# Sourced by BOTH deploy/setup.sh (the one-shot privileged host provisioning) and
# deploy/deploy.sh (code delivery). Every path, unit name and user lives here exactly once, so
# the two entry points can never disagree about what this project installs.
#
# ── WHY THIS PROJECT DEVIATES ─────────────────────────────────────────────────────────────────
# Every other kgsm-* project deploys with ZERO privilege: its install prefix is chowned to the
# deploying user and its unit files live in a user-owned directory that /etc/systemd/system
# symlinks to (see tks/scripts/deploy-template/README.md).
#
# kgsm-firewall cannot do that. Its daemon runs as ROOT — it drives ufw. A root-executed binary,
# or a unit file that tells PID 1 what to execute as root, must NOT be writable by an
# unprivileged user: that is a genuine privilege-escalation path, not a technicality. So this
# project keeps the classic root-owned layout, and its deploy.sh sudo's exactly two things: the
# binary install and (when it changed) the unit install.
#
# It is the ONLY password prompt left in the ecosystem, and it is deliberate.
#
# Not executable on its own.

# This file only DEFINES things; every variable below is consumed by the two scripts that
# source it, which shellcheck cannot see from here.
# shellcheck disable=SC2034

set -euo pipefail

# ── Identity ──────────────────────────────────────────────────────────────────
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEPLOY_USER="${KGSM_DEPLOY_USER:-$(id -un)}"
DEPLOY_GROUP="${KGSM_DEPLOY_GROUP:-$(id -gn)}"

# ── PROJECT BLOCK ─────────────────────────────────────────────────────────────
PROJECT="kgsm-firewall"

# The service is socket-activated and idle-exits; the SOCKET is what boots and listens.
UNITS=("kgsm-firewall.service" "kgsm-firewall.socket")
ENABLE_UNITS=("kgsm-firewall.socket")

PREFIX="/opt/${PROJECT}"          # ROOT-owned (see the deviation note above)
BIN="${PREFIX}/${PROJECT}"
BIN_LINK="/usr/local/bin/${PROJECT}"

ENV_DIR="/etc/${PROJECT}"
ENV_FILE="${ENV_DIR}/${PROJECT}.env"
ENV_EXAMPLE="${REPO_DIR}/deploy/${PROJECT}.env.example"

HEALTH_TRIES="${HEALTH_TRIES:-30}"

# The unprivileged group allowed to talk to the (root) authority socket. Defaults to the invoking
# user's primary group — the KGSM user that owns the instances.
SOCK_GROUP="${KGSM_FIREWALL_SOCKET_GROUP:-$(id -gn)}"

# The socket unit carries the access boundary, so its group is substituted per host; the service
# unit installs verbatim.
render_unit() {   # $1 = unit filename
    if [[ "$1" == *.socket ]]; then
        sed "s/^SocketGroup=.*/SocketGroup=${SOCK_GROUP}/" "${REPO_DIR}/deploy/$1"
    else
        cat "${REPO_DIR}/deploy/$1"
    fi
}

# The daemon idle-exits by design, so the .service is NOT expected to be running. The honest
# check is that the control socket is listening — the daemon wakes on the next connection.
# deploy/kgsm-firewall-healthcheck.sh probes deeper (and needs root).
health_probe() {
    systemctl is-active --quiet "${ENABLE_UNITS[0]}"
}
# ── END PROJECT BLOCK ─────────────────────────────────────────────────────────

# ── Derived paths ─────────────────────────────────────────────────────────────
SYSTEMD_DIR="/etc/systemd/system"
POLKIT_DST="/etc/polkit-1/rules.d/48-${PROJECT}-deploy.rules"
SERVICE="${UNITS[0]}"
PUBLISH_DIR="${REPO_DIR}/artifacts/publish"

# Unlike the other projects, deploy.sh DOES use this — for the two root-owned installs.
SUDO="${SUDO:-sudo}"

# ── Output helpers ────────────────────────────────────────────────────────────
log()  { printf '\033[1;34m>> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m** %s\033[0m\n' "$*" >&2; }
err()  { printf '\033[1;31m!! %s\033[0m\n' "$*" >&2; }

# ── Shared preflight ──────────────────────────────────────────────────────────
refuse_root() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        err "do NOT run this as root — run it as the KGSM (instance-owning) user."
        err "the socket group is taken from YOUR group; only the root-owned installs are sudo'd."
        exit 1
    fi
}

# What deploy.sh requires before it touches anything. The units and prefix are root-owned here,
# so the assertion is that they EXIST and are enabled — not that we can write them.
require_setup() {
    local u problem=0

    [[ -d "$PREFIX" ]] || { err "install prefix ${PREFIX} does not exist."; problem=1; }
    for u in "${UNITS[@]}"; do
        [[ -f "${SYSTEMD_DIR}/${u}" ]] || { err "${SYSTEMD_DIR}/${u} is not installed."; problem=1; }
    done

    if [[ "$problem" -ne 0 ]]; then
        err ""
        err "this host is not provisioned for ${PROJECT}."
        err "run ONCE (it will ask for your sudo password):   ${REPO_DIR}/deploy/setup.sh"
        exit 1
    fi
}

# systemctl, unprivileged, via the polkit grant setup.sh installed.
sysctl_do() {   # $@ = systemctl arguments
    # --no-ask-password: this path must fail fast rather than block on a prompt nobody will answer.
    if ! systemctl --no-ask-password "$@"; then
        err "systemctl $* was refused."
        err "the polkit grant for ${DEPLOY_USER} is missing or does not cover this unit."
        err "re-run: ${REPO_DIR}/deploy/setup.sh"
        return 1
    fi
}

wait_health() {
    local i
    for ((i = 1; i <= HEALTH_TRIES; i++)); do
        health_probe && return 0
        sleep 1
    done
    return 1
}

# Install the rendered units. PRIVILEGED here (root-owned units — see the deviation note), and
# cmp-guarded so a steady-state deploy asks for nothing. Sets UNIT_CHANGED=1 when one changed.
UNIT_CHANGED=0
install_units_privileged() {
    local u tmp
    UNIT_CHANGED=0
    for u in "${UNITS[@]}"; do
        tmp="$(mktemp)"
        render_unit "$u" > "$tmp"
        if ! cmp -s "$tmp" "${SYSTEMD_DIR}/${u}"; then
            log "unit changed → ${SYSTEMD_DIR}/${u} (needs sudo: root-owned unit)"
            $SUDO install -m 0644 "$tmp" "${SYSTEMD_DIR}/${u}"
            UNIT_CHANGED=1
        fi
        rm -f "$tmp"
    done
}
