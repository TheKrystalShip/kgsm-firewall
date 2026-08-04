#!/usr/bin/env bash
#
# kgsm-firewall-healthcheck.sh
#
# Verify a kgsm-firewall deployment end to end, from an UNPRIVILEGED shell that belongs to
# the firewall control-socket's group (the same group your KGSM user uses). It needs no root:
# the daemon performs every privileged action behind the socket. That is deliberate — the most
# common real-world failure is "the KGSM user is not in the socket's group", and running this
# as root would hide exactly that.
#
# What it checks, in order:
#   1. the binary is installed and runnable
#   2. the systemd control socket is enabled (boots) and active (listening)
#   3. the socket file has the expected owner/group/mode (root:<group> 0660)
#   4. the current user can reach the socket (is in its group)
#   5. the daemon reports a driveable backend (apply=True)
#   6. a full open -> list -> remove round-trip succeeds (a throwaway probe; always cleaned up)
#
# Exit status: 0 if nothing FAILED (warnings are tolerated), 1 otherwise.
#
# Overridable via the environment:
#   KGSM_FIREWALL_BIN     path/name of the binary           (default: kgsm-firewall, else /opt/kgsm-firewall/kgsm-firewall)
#   Firewall__SocketPath  control socket path                (default: /run/kgsm-firewall/firewall.sock)

set -u

BIN="${KGSM_FIREWALL_BIN:-}"
SOCKET="${Firewall__SocketPath:-/run/kgsm-firewall/firewall.sock}"
SOCKET_UNIT="kgsm-firewall.socket"
PROBE="healthcheck-probe-$$"   # matches the authority's instance rule ^[A-Za-z0-9_-]+$

# ---- output helpers -------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_OFF=""
fi
fails=0; warns=0
pass() { printf '%sPASS%s  %s\n' "$C_OK"   "$C_OFF" "$1"; }
warn() { printf '%sWARN%s  %s\n' "$C_WARN" "$C_OFF" "$1"; warns=$((warns + 1)); }
fail() { printf '%sFAIL%s  %s\n' "$C_ERR"  "$C_OFF" "$1"; fails=$((fails + 1)); }
note() { printf '      %s%s%s\n' "$C_DIM" "$1" "$C_OFF"; }

# ---- 1. binary ------------------------------------------------------------------------------
if [ -z "$BIN" ]; then
  if command -v kgsm-firewall >/dev/null 2>&1; then
    BIN="kgsm-firewall"
  elif [ -x /opt/kgsm-firewall/kgsm-firewall ]; then
    BIN="/opt/kgsm-firewall/kgsm-firewall"
  fi
fi
if [ -n "$BIN" ] && command -v "$BIN" >/dev/null 2>&1 || { [ -n "$BIN" ] && [ -x "$BIN" ]; }; then
  pass "binary found: $BIN"
else
  fail "kgsm-firewall binary not found (looked on PATH and at /opt/kgsm-firewall/kgsm-firewall)"
  note "set KGSM_FIREWALL_BIN=/path/to/kgsm-firewall and re-run"
  printf '\n%d failed, %d warning(s)\n' "$fails" "$warns"
  exit 1
fi

# ---- 2. systemd socket unit -----------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
  if [ "$(systemctl is-enabled "$SOCKET_UNIT" 2>/dev/null)" = "enabled" ]; then
    pass "$SOCKET_UNIT is enabled (will start on boot)"
  else
    fail "$SOCKET_UNIT is not enabled — it will not come up after a reboot"
    note "fix: sudo systemctl enable --now $SOCKET_UNIT"
  fi
  if [ "$(systemctl is-active "$SOCKET_UNIT" 2>/dev/null)" = "active" ]; then
    pass "$SOCKET_UNIT is active (listening)"
  else
    fail "$SOCKET_UNIT is not active — nothing is listening on the control socket"
    note "fix: sudo systemctl start $SOCKET_UNIT  (check: systemctl status $SOCKET_UNIT)"
  fi
  # The .service idle-exits by design; 'inactive (dead)' there is NORMAL, not a fault.
else
  warn "systemctl not available — skipping unit checks (manual/dev run?)"
fi

# ---- 3. socket file owner/group/mode --------------------------------------------------------
sock_group=""
if [ -S "$SOCKET" ]; then
  owner="$(stat -c '%U' "$SOCKET" 2>/dev/null)"
  sock_group="$(stat -c '%G' "$SOCKET" 2>/dev/null)"
  mode="$(stat -c '%a' "$SOCKET" 2>/dev/null)"
  if [ "$owner" = "root" ] && [ "$mode" = "660" ]; then
    pass "socket $SOCKET is $owner:$sock_group mode $mode (correct: the perms ARE the auth boundary)"
  else
    warn "socket $SOCKET is $owner:$sock_group mode $mode (expected root:<group> mode 660)"
  fi
else
  fail "control socket $SOCKET does not exist"
  note "the socket unit is active only after it has bound; check: systemctl status $SOCKET_UNIT"
fi

# ---- 4. caller can reach the socket (group membership) --------------------------------------
if [ -n "$sock_group" ]; then
  if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx "$sock_group"; then
    pass "current user ($(id -un)) is in the '$sock_group' group — may reach the authority"
  else
    fail "current user ($(id -un)) is NOT in the '$sock_group' group — cannot reach the authority"
    note "add the KGSM user: sudo usermod -aG $sock_group <user>, then RE-LOGIN (or: newgrp $sock_group)"
  fi
fi

# ---- 5. backend is driveable ----------------------------------------------------------------
backend_line="$("$BIN" backend 2>&1)"; backend_rc=$?
if [ $backend_rc -ne 0 ]; then
  fail "could not query the authority: $backend_line"
  note "is the socket reachable? are you in the '$sock_group' group? (see above)"
else
  backend_name="$(printf '%s' "$backend_line" | sed -n 's/.*backend=\([^ ]*\).*/\1/p')"
  if printf '%s' "$backend_line" | grep -q 'apply=True'; then
    pass "backend '$backend_name' is driveable ($backend_line)"
  else
    fail "backend '$backend_name' cannot apply rules ($backend_line)"
    note "most common cause: ufw is INACTIVE, so detection fell through to nftables (no driver)."
    note "fix A (enforce now):  sudo ufw enable"
    note "fix B (pin backend):  set Firewall__Backend=ufw in /etc/kgsm-firewall/kgsm-firewall.env, then"
    note "                      sudo systemctl restart $SOCKET_UNIT"
  fi
fi

# ---- 6. open -> list -> remove round-trip ---------------------------------------------------
probe_opened=""
cleanup() { [ -n "$probe_opened" ] && "$BIN" remove "$PROBE" >/dev/null 2>&1; }
trap cleanup EXIT
# Only attempt the write path if the backend can apply (avoids a guaranteed failure line).
if printf '%s' "${backend_line:-}" | grep -q 'apply=True'; then
  if open_out="$("$BIN" ensure-open "$PROBE" 9999/tcp 2>&1)"; then
    probe_opened="yes"
    pass "round-trip: ensure-open accepted ($open_out)"
    list_out="$("$BIN" list "$PROBE" 2>&1)"
    if printf '%s' "$list_out" | grep -q "$PROBE"; then
      pass "round-trip: list shows the probe rule (ufw is active and enforcing)"
    elif command -v systemctl >/dev/null 2>&1 && [ "$(systemctl is-active ufw 2>/dev/null)" != "active" ]; then
      warn "round-trip: rule persisted but not listed — ufw appears INACTIVE, so it is not enforcing yet"
      note "the rule is saved and will take effect on: sudo ufw enable"
    else
      warn "round-trip: ensure-open succeeded but the rule is not listed (unexpected while enforcing)"
    fi
    if "$BIN" remove "$PROBE" >/dev/null 2>&1; then
      probe_opened=""
      pass "round-trip: remove cleaned up the probe (zero residue)"
    else
      fail "round-trip: remove of probe '$PROBE' failed — manual cleanup may be needed"
    fi
  else
    fail "round-trip: ensure-open failed: $open_out"
  fi
else
  warn "round-trip skipped — backend is not driveable (see above)"
fi

# ---- verdict --------------------------------------------------------------------------------
echo
if [ "$fails" -eq 0 ] && [ "$warns" -eq 0 ]; then
  printf '%sOK%s — kgsm-firewall is deployed and healthy.\n' "$C_OK" "$C_OFF"
elif [ "$fails" -eq 0 ]; then
  printf '%sOK with %d warning(s)%s — usable; review the WARN lines above.\n' "$C_WARN" "$warns" "$C_OFF"
else
  printf '%s%d check(s) FAILED%s, %d warning(s) — see the fix hints above.\n' "$C_ERR" "$fails" "$C_OFF" "$warns"
fi
[ "$fails" -eq 0 ]
