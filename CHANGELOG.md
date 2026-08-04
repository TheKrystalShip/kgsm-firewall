# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **`pairedApiKey` names the Control Panel API's renamed setting.** kgsm-api's environment
  variables are now spelled `Api__<Property>`, and this value is what the API resolves to warn that
  a change here has moved this leaf out of its reach. Naming the old key would have made that check
  silently find nothing and report the change as clean.

### Changed — configuration is typed, and the settings file declares all of it

**This deploy renames every environment variable the authority reads.** A host carrying the old names
loses those overrides silently and falls back to the settings file, so update
`/etc/kgsm-firewall/kgsm-firewall.env` in the same step — on this host that means the `ufw` backend pin,
without which detection falls through to nftables, finds no driver, and a firewall-enabled install
hard-fails. The Control Panel needs no change: the descriptor's `key` values are untouched, so a stored
override keeps working.

| Was | Now |
|---|---|
| `KGSM_FIREWALL_SOCKET` | `Firewall__SocketPath` |
| `KGSM_FIREWALL_BACKEND` | `Firewall__Backend` |
| `KGSM_FIREWALL_UFW_APPLICATIONS_DIR` | `Firewall__UfwApplicationsDirectory` |
| `KGSM_FIREWALL_IDLE_TIMEOUT` | `Firewall__IdleTimeoutSeconds` |

- **`kgsm-firewall.settings.json` replaces `appsettings.json` and declares the whole configurable
  surface**, hierarchically, each key with its default. An environment variable overrides one key of it
  by spelling that key's path with `__`. There is no longer a separate set of variable names that only
  the code knows: a name not in that file binds to nothing, which is what makes the descriptor checkable
  against something real rather than against a regex over the source.
- **`FirewallSettings` binds the file in one step**, and nothing reads configuration from the
  environment directly. `FirewallOptions.FromSettings` is the validating step between what was written
  and what the authority runs on — blanks fall back and an unrecognised backend name degrades to
  detection, because an authority that refuses to start hard-fails every firewall-enabled install.
- **The recognised-variable list is derived from the bound type**, so the typo warning and `--help`
  cannot fall behind the settings file. (Verified against the published AOT binary: an unknown
  `Firewall__*` variable is still reported, so the reflection survives trimming.)
- **The daemon's logging levels come from the same configuration stack as every other knob**, rather
  than a second builder constructed inside the logger factory that could resolve them differently.
- **The settings file is read from beside the binary**, by absolute path, so the working directory
  neither role starts in can decide whether it is configured.

### Fixed — a blank knob no longer takes the authority down
- **The idle timeout is a nullable int, so "written blank" means unset.** Binding a blank value to a
  non-nullable `int` throws, which would have made an env-file line left as `Firewall__IdleTimeoutSeconds=`
  a startup crash for the privileged authority. A null one binds to `0`, which here means "never
  idle-exit" — holding root all day, silently, having been asked for nothing of the sort. Null now means
  unset and the coded 30s default applies. A value that is present but not a number still fails loudly,
  which is the point of typing it.

### Fixed — the Control Panel can attribute a value
- **`floorSources` declares the settings file, first.** It was absent entirely, so once the file started
  carrying every knob the Control Panel had no way to see where a value came from. The list is
  lowest-precedence-first and the settings file is the base the environment overrides, so it goes at the
  bottom; a test pins the ordering.

### Added — the Control Panel can configure this authority
- **`deploy/kgsm-firewall.leaf.json` declares every knob the daemon reads** — all four
  `Firewall__*` variables plus the standard logging level, each with its type, default, bounds
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
