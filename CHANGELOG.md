# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — the deploy contract is files, not install-time script output

`deploy/polkit/48-kgsm-firewall-deploy.rules.in` carries the headless-deploy grant as reviewable content, and
`setup.sh` renders the deploying user and unit list into it instead of embedding the rule in a
heredoc — what a host is granted can now be read without running anything.

`deploy/sysusers.d/kgsm-firewall.conf` declares the `kgsm` service account so a packaged install provisions it
declaratively rather than relying on an account that happens to exist.

`deploy/kgsm-firewall.requires.json` states every host command, peer service and kernel feature this project
needs — each with its Arch package name, a probe that proves it works, and, for anything optional,
what is lost without it.

### Changed — the committed unit names the service account, not a developer

`User=`/`Group=` read `kgsm`, the account `sysusers.d` declares. `render_unit()` still substitutes
the deploying user at install time, so a dev-host deploy is unchanged.

### Added — this authority records the edges it applied

`FirewallJournal` appends `instance_ports_opened` / `instance_ports_closed` to
`/var/lib/kgsm-firewall/events` (`Firewall__EventJournalDirectory`), via the shared
`TheKrystalShip.KGSM.Journal` package — the journal's write half only, whose whole dependency is
`Logging.Abstractions`. Not kgsm-lib: this daemon runs as root, and a process runner, an RCON client and
a set of HTTP clients are attack surface a firewall authority has no use for.

**The component that changed the firewall is now the one that records it.** Two others used to do it on
this one's behalf — kgsm after shelling the CLI, the watchdog after calling the socket client — so the
line naming the author named the wrong one, and both had to be guarded so a single edge was never written
twice. Those guards, and the `KGSM_FIREWALL_APPLIED_EDGES` drain that carried them, are gone.

`FirewallRequest` gains `Actor` and `Origin` (Contracts 1.2.0, additive — a pre-1.2.0 client sends
neither and the edge honestly records nobody). They are **repeated, never vouched for**: the caller alone
knows whose authority a request carried, and this daemon cannot check the claim. The bundled CLI reads
`KGSM_EVENT_ACTOR`/`KGSM_EVENT_ORIGIN` — the same variables kgsm's own emitter reads, so the two paths
cannot name different actors for one action.

**Only a confirmed change is recorded.** `applied`, `applied-inactive` and `removed` are edges; a no-op,
an unsupported backend and a refusal changed nothing and produce no line. The precise outcome rides on
the payload, so a reader can tell an enforced rule from one staged against an inactive backend rather
than being told they are the same. A close carries no ports: removal is addressed by ownership tag and
the authority does not read back what it deleted — listing them would report the caller's idea of the
ports as the authority's measurement.

⚠ The unit gains `StateDirectory=kgsm-firewall` with **`StateDirectoryMode=0755`**, not systemd's default
0700. This service runs as root and every reader on the host is unprivileged; a directory they cannot
enter would report this authority's history as unreadable, which is indistinguishable from a genuine read
failure.

Idle-exit needed no change: a journal is append-only and written inside the request the daemon is already
awake to serve, so it never needed a resident writer.

### Changed — the leaf config descriptor is generated, not written
- **`deploy/kgsm-firewall.leaf.json` is now written by `TheKrystalShip.KGSM.LeafConfig` on every build**, from
  `[LeafField]` attributes and `<panel>` doc tags on `FirewallSettings`. A knob lives in two places —
  the property and the settings-file key — instead of three, and the descriptor cannot describe a
  variable this leaf does not read: the `env` name is derived from the property's position under its
  bound section, and the default from the settings file itself. **Edit the settings class, not the
  JSON.**
- **A field's operator-facing prose comes from a `<panel>` tag**, falling back to `<summary>` with a
  build message naming the field. The two are separate because they answer different questions: the
  summary tells a developer what the value means to the code, the panel tells whoever runs the host
  what changing it does.
- **`LeafDescriptorTests` is gone.** Every check it made — settings coverage in both directions, the
  field vocabulary, group and `dependsOn` references, enum values and defaults, bounds, floor-source
  order — now runs in the generator, at the point the file is produced rather than after, and in one
  implementation shared by every leaf instead of a copy per repo.
- The package is **build-only** and declares no dependencies: the attributes arrive as source and the
  generator reads this assembly's metadata in its own process, so nothing reaches the published
  output and this leaf gains no reflection.

### Added — the env template is held to the settings file
- **A test fails the build when `deploy/kgsm-firewall.env.example` names a key
  `kgsm-firewall.settings.json` does not declare.** The env file overrides the settings file one
  key at a time, so a variable naming an undeclared key binds to nothing — it reads as configuration
  and is inert. The template is the one copy of that file in version control, so it is the copy that
  can be checked. Commented lines count too, since a commented key is what someone uncomments;
  systemd's own directives quoted in the prose (`EnvironmentFile=`, `Delegate=`) do not, because they
  configure the unit rather than the leaf.

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
