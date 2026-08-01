# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — the Control Panel can configure this authority
- **`deploy/kgsm-firewall.leaf.json` declares every knob the daemon reads** — all four
  `KGSM_FIREWALL_*` variables plus the standard logging level, each with its type, default, bounds
  and risk. `deploy.sh` installs it into `/var/lib/kgsm/leaves/` **unprivileged** (that directory is
  owned by the deploying user, so this adds nothing to the two sudo calls this project already
  makes), and kgsm-api scans it there to render this authority's configuration page.
- **A coverage test fails the build if the descriptor and the daemon disagree**, in both directions:
  a knob added without a descriptor entry, or a descriptor entry naming a variable nothing reads.
- The descriptor declares this leaf **on demand**, so an apply's post-restart check reads `inactive`
  as the resting state of a socket-activated daemon rather than a failure. Both the socket path and
  the backend are marked `wiring`: forcing a backend this host is not running stops ports being
  opened at all.

### Changed — deploy split into `setup.sh` (once) + `deploy.sh` (every time)
- **`deploy/setup.sh` provisions the host once** (asks for sudo; idempotent): creates
  `/opt/kgsm-firewall`, installs the `.socket`/`.service` units, seeds the env file, enables the
  socket, and installs a polkit grant scoped to this project's units so `deploy.sh` can drive
  `systemctl` unprivileged.
- **`deploy/deploy.sh` still asks for sudo — deliberately, and it is the only project that does.**
  The daemon runs as root, so its binary and unit files stay root-owned: a root-executed binary an
  unprivileged user can rewrite is a real privilege-escalation path. The escalation is narrowed to
  exactly two calls (`install -m 0755 -o root -g root` for the binary, `ln -sfn` for the
  `/usr/local/bin` symlink); every `systemctl` verb goes through the polkit grant. Every other
  `kgsm-*` project now deploys with zero privilege — see
  `tks/scripts/deploy-template/README.md`, which documents this repo as the exception.
- `deploy.sh` refuses up-front (before building) with "run `deploy/setup.sh`" when the host is not
  provisioned.

## [1.1.0] - 2026-06-30

### Added
- Initial versioned release.
