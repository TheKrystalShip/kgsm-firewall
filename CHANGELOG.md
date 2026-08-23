# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.1] - 2026-08-23

### Fixed — the bundled CLI is on PATH on a packaged host

`packaging/PKGBUILD` links `/usr/bin/kgsm-firewall` to `/opt/kgsm-firewall/kgsm-firewall`. The engine
resolves this authority with `command -v kgsm-firewall`, and enable/install hard-fails when nothing
answers — so a name on PATH is what makes the authority reachable at all. `/usr/bin`, never
`/usr/local/bin`: `/usr/local` belongs to the local administrator and no package may write there.

## [1.9.0] - 2026-08-18

### Added — every journal line now carries its own id

Every event this daemon writes carries an `Id`: a UUIDv7 the shared writer mints per line, inherited by pinning
TheKrystalShip.KGSM.Journal 1.9.0. Nothing in this repo changed but the pin.

Why it exists: every durable reference to an event on this host is a byte offset into a named segment,
which holds only while a segment is appended to and deleted whole (conformance §2·l). An id makes a
rewrite **detectable** — a reference carrying both finds the line by position and proves it is the
right one by id, where before a shifted offset resolved to a real, parseable event of the wrong kind
with nothing to notice.

⚠ Optional and optional forever: lines written before this are on disk for as long as retention holds
them, and **absent means unknown, never a mismatch**. Authority: `journal-entry-id-plan.md`.

## [1.7.0] - 2026-08-16

### Added — this leaf says when the host cannot hear or speak

`leaf_degraded` and `leaf_recovered` on this leaf's own journal — its first — through
`TheKrystalShip.KGSM.Lifecycle`. The Journal package is the whole new dependency: two Abstractions
packages, no container and no host, which is what lets a bare console app take it. The writer is
constructed by hand, exactly as the firewall's is.

⚠ **Nothing else on this host could find out.** A probe cannot ask whether this leaf is well, because
connecting to the socket is what starts it — and would load 1.6GB of models to answer. Self-reporting
is the only route.

Four components, reported once the models have had their chance to load (they load on demand, which is
the whole point of a leaf that exits when nobody is speaking):

- `hearing` / `speaking` — a model that did not load means the host cannot do that thing at all.
- `hearing-accelerator` / `speaking-accelerator` — ⚠ a model that loaded **on the processor**. Whisper
  takes the first runtime that initialises, so a driver mid-upgrade silently yields the CPU: forty
  times slower to recognise, eight times slower to synthesise. Loading and running are two answers, so
  they are two components — the host can do the thing, slowly, and every surface waiting on it feels
  that while none of them can see it.

⚠ **Degradation only — no `leaf_ready` and no `leaf_stopping`.** Inactive is this leaf's resting state
rather than a transition; the whole design is a process that ends to give its memory back.

⚠ **The lifecycle is seeded from this leaf's own journal** (`LeafState`, Journal 1.8.0), and the defect
that fix exists for was measured here: a missing model was reported, the daemon idled out, it woke with
the model restored, and **no recovery was written** — the fresh process had never seen the fault.

## [1.8.0] - 2026-08-16

### Added — this authority says when it cannot apply a rule

`leaf_degraded` on component `backend`, through `TheKrystalShip.KGSM.Lifecycle`, when the daemon is
answering and `CanApply` is false.

⚠ **The most dangerous silent state on a KGSM host.** Ports are opened when a server starts and closed
when it stops, so an authority that answers but cannot write leaves them closed on a start — nobody can
connect — or open on a stop, with every caller told the request was accepted, because it was. The fact
was already computed and logged at startup; nothing outside the process could act on it.

⚠ **Degradation only — no `leaf_ready` and no `leaf_stopping`.** This daemon is socket activated with a
30s idle window and woke 35 times in a measured day; a start and a stop on each would be five times its
whole journal's daily output, to report that a socket-activated daemon did the one thing socket
activation exists to make it do. **Inactive is its resting state, not a transition** — which is also
why nothing can health-poll it: connecting to the socket is what starts it.

⚠ **The lifecycle is seeded from this authority's own journal** (`LeafState`, Journal 1.8.0). It exits
when idle and so remembers nothing between wakes: without the seed it would re-report a standing fault
on every one of those 35 wakes and — worse — could never clear one, because the process that sees the
backend working again is not the process that saw it fail. A healthy wake therefore reports rather than
skips, and the emitter writes nothing when there was no fault to clear.

## [1.7.1] - 2026-08-16

### Added — this producer reports a journal no other account can reach

`TheKrystalShip.KGSM.Journal` 1.5.0 checks at startup whether this producer's state directory grants
its group access, and warns when it does not. A directory cannot be entered without execute on every
directory above it, so a state directory closed to the group hides the journal inside it however
permissive the journal's own mode is.

⚠ **That failure is silent.** A reader that cannot traverse in gets `Directory.Exists == false`, not a
permission error — so discovery concludes this producer has recorded nothing, which is exactly what a
genuinely idle leaf looks like. This unit declares `0750` and names the shared `kgsm` group, so the
check stays quiet here; it exists for the leaf that ships `0700` and disappears.

## [1.7.0] - 2026-08-16

### Added — this producer prunes its own journal

Segments older than **90 days** are removed, matching the engine's own retention window
(`TheKrystalShip.KGSM.Journal` 1.4.0). ⚠ **Before this, only the engine pruned anything** — its daily
timer covers its own directory alone, and every leaf journal grew without bound.

Pruning runs at startup and again when the segment date rolls over, so a resident daemon prunes daily
and a short-lived one prunes every time it wakes — no timer, and therefore no hosting dependency in
the writer package. Segments are unlinked **whole**, never truncated: a consumer's position is a byte
offset into a named segment, so a rewritten file misplaces every event after the cut, where a removed
one makes the consumer report an honest gap. Age is read from the segment's **name**, not its mtime,
which a restore or a backup tool moves without any event moving.

## [1.6.0] - 2026-08-16

### Changed — journal identity comes from the producer id

`FirewallJournal` derives from `JournalRecorder` (`TheKrystalShip.KGSM.Journal` 1.3.0), so this
authority keeps what is its own — the two edge event types, the structured `Ports` payload, and the
rule that only a confirmed change is recorded — and stops carrying its own copy of the write path.

- **`ProducerVersion` is the informational version.** These edges carried `1.5.0.0`, a four-part form
  no release of this authority is ever numbered with. They now carry `1.6.0+<sha>`. ⚠ Lines already on
  disk keep the old spelling; the field is free text, so a reader comparing across the change sees both.
- **`DefaultActor` and `DefaultOrigin` are explicitly null**, which is this authority's whole provenance
  model made structural rather than incidental. Every other producer defaults to attributing an action
  to itself; here that would answer "who wanted this port open?" with the name of the process that
  typed the rule. A caller that names nobody still produces a real null.
- **`DefaultEventJournalDirectory` is composed by the writer's own layout rule** rather than spelled as
  a literal, so it cannot drift from where a reader's discovery scan looks. Same path, one definition.
- Creating the journal directory at startup moved into the writer's construction, so the daemon no
  longer does it by hand — and a directory a reader would attribute to a different producer is now
  reported rather than accepted.

The dependency surface is unchanged and still deliberate: `Journal` takes
`DependencyInjection.Abstractions` for a registration helper this daemon does not use (it has no
container), and no hosting stack follows it in.

## [1.5.1] - 2026-08-14

### Added — GPL-3.0-or-later

This project now carries a `LICENSE`. Its package declares `GPL-3.0-or-later` and installs the text
to `/usr/share/licenses/`, so a distributed binary travels with the terms it is under.

### Changed — package license metadata is GPL-3.0-or-later

`PackageLicenseExpression` now matches the repo's own `LICENSE` on every published package. Already
published versions keep the metadata they were built with, since a published version is immutable —
the correction reaches consumers on the next version bump.

### Added — an Arch package, built from the tested binaries

`packaging/PKGBUILD` builds this project into a pacman package. It compiles nothing: CI publishes
first and the recipe places that output, so the packaged bytes are the tested bytes. `pkgver()`
reads `deploy/version.sh`, so the package never restates a version.

The install prefix stays `/opt/<project>` — the same path `deploy.sh` uses — which is what lets the
committed systemd unit ship verbatim instead of being rewritten at packaging time.

Config files are listed in `backup=()`, so an upgrade writes `.pacnew` beside a file you edited
rather than over it. The unit, the sysusers fragment and the leaf descriptor are packaged files, so
the descriptor can never lag the binary it describes. Nothing is enabled by a scriptlet: pacman's
own hooks handle the service account, the state directories and the daemon reload, and enabling a
unit is the administrator's decision.

### Added — one machine-readable version, read rather than restated

`deploy/version.sh` prints this project's version from the single file that declares it, and
`--pkgver` prints the form pacman accepts (a `pkgver` may not contain a hyphen; ordering survives it,
since `vercmp` puts `3.16.0rc3` before `3.16.0`). Packaging asks for a version instead of carrying a
copy that can fall behind the binary.

It reads `src/Firewall/Firewall.csproj` specifically: the package ships the daemon, and
`Firewall.Contracts` is a separate artifact on its own version.

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
