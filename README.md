# Cleanix CLI

[![CI](https://github.com/CloudOpsWorld/cleanix-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/CloudOpsWorld/cleanix-cli/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/cleanix-cli.svg)](https://pypi.org/project/cleanix-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/cleanix-cli.svg)](https://pypi.org/project/cleanix-cli/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A safe, thorough system cleaner for **every *nix flavour** — Linux (all
major distros), macOS, and the BSDs. It **analyzes** your OS for junk — caches,
temp files, package-manager leftovers, orphaned packages, broken symlinks,
package-update config residue, rotated logs, trash, thumbnails, browser/dev
caches, container cruft — and only **removes** anything after you confirm.

It can run on a **schedule** (a systemd timer on Linux/BSD, a launchd agent on
macOS) to periodically analyze the
system and notify you. Scheduled runs *never delete anything*; they only produce
a report so you can review and clean on your own terms.

## Platform support

Cleaners declare which platforms they apply to; `cleanix` auto-detects the OS
(and Linux distro via `/etc/os-release`) and only runs the relevant ones.

| Family   | Detected as                        | Package/system cleaners |
|----------|------------------------------------|-------------------------|
| Linux    | `linux` + distro id                | apt, dnf/yum, pacman, zypper, apk, xbps, portage, flatpak, snap, nix, journald, coredumps, `/var/crash`, `.rpmnew`/`.pacnew`/`.dpkg-old` residue |
| macOS    | `macos`                            | Homebrew, MacPorts, Xcode (DerivedData/DeviceSupport/simulators), ~/Library caches & logs, Trash |
| FreeBSD  | `freebsd`                          | pkg cache + autoremove, ports distfiles & work dirs |
| NetBSD   | `netbsd`                           | pkg, pkgin cache |
| OpenBSD  | `openbsd`                          | pkg |
| Cross-OS | all of the above                   | trash, thumbnails, ~/.cache, temp files, fonts, browser caches, broken symlinks, `.DS_Store`/AppleDouble, dev/language caches (cargo/go/gradle/ccache/composer/…), pip, npm/yarn, Docker, Podman |

Run `cleanix list` to see what applies to your machine, or `cleanix list --all`
to see every platform's cleaners.

## AI / LLM leftovers (triaged, not nuked)

Local AI tooling scatters a lot of disposable junk *and* a lot of data you
deliberately downloaded. Cleanix **triages** — it removes the trash and leaves
your models and chat history alone:

| Tool | Removed (trash) | Kept (your data) |
|------|-----------------|------------------|
| **Ollama** | dangling blobs from interrupted pulls, server logs | installed models (referenced blobs/manifests) |
| **Hugging Face** | `*.incomplete` downloads, `.locks`, `.no_exist` | downloaded model/dataset weights |
| **PyTorch/Triton/vLLM/CUDA** | Triton, `torch.compile`/inductor, `torch_extensions`, vLLM, `~/.nv/ComputeCache`, FlashInfer JIT caches | — (all pure compile caches) |
| **LM Studio / Jan** | server logs | models, presets, conversations |
| **Continue.dev** | rebuildable embeddings index, logs, telemetry | sessions/config |
| **Claude Code** | throwaway shell snapshots, telemetry cache | projects, history |
| **Aider** | stray `.aider.tags.cache.*`, `.aider.chat.history.md`, `.aider.input.history` in project trees | — |

### AI coding-agent CLIs (retention-aware)

These accumulate rolling backups, per-session file-history/checkpoints, debug
logs, and transcripts that no built-in command reliably prunes. Cleanix applies
proper **retention** instead of all-or-nothing deletion:

| Tool | Removed | Kept |
|------|---------|------|
| **Claude Code** (`~/.claude`) | rolling `.claude.json` backups beyond the newest `keep_backups` (default 2); debug/telemetry/paste/download/changelog caches; stale (>`ai_history_max_age_days`) file-history & transcripts | `~/.claude.json`, `settings.json`, `plugins/`, credentials, **and any currently-running session** |
| **OpenAI Codex** (`~/.codex`) | session rollouts & TUI logs older than the retention age | recent sessions, config |
| **Gemini CLI** (`~/.gemini/tmp`) | stale per-project session/log data | config, recent sessions |
| **OpenCode** (`~/.local/share/opencode`) | logs, snapshots, tool-output | the SQLite DB, auth, storage |

Two knobs control retention (see `config/default.yaml`):

- `keep_backups: 2` — how many newest rolling backups to keep.
- `ai_history_max_age_days: 30` — transcripts/history/logs older than this are
  offered (chat history is your data, so it's age-gated and conservative).

Per-session scratch (todos, shell snapshots, session env) touched within the
last day is always left alone, so cleaning never disturbs a live agent session.

## General app bloat

- **Electron/Chromium apps** (VS Code, Slack, Discord, Signal, Obsidian, …):
  removes only rebuildable `Cache`/`Code Cache`/`GPUCache`/`Dawn*Cache`/
  `CachedData`/`Crashpad` — **never** `Local Storage`, `IndexedDB`,
  `Service Worker`, or cookies (so you stay logged in). Covers both
  `~/.config/*` and Flatpak (`~/.var/app/*`) apps.
- **Flatpak app caches** — every app's `~/.var/app/*/cache`.
- **GPU shader caches** — Mesa (`mesa_shader_cache[_db]`), NVIDIA `GLCache`,
  RADV/AMD Vulkan caches (rebuilt after driver updates).
- **Steam** — per-game shader caches, interrupted downloads, HTTP cache.
- **JetBrains IDEs** — caches, logs, and indexes (Linux `~/.cache/JetBrains`,
  macOS `~/Library/Caches/JetBrains`).

Cleaners never offer the same path twice: dedicated cleaners own their
directories and the generic `~/.cache` catch-all defers to them.

## More reclamation & review

- **Old toolchain versions** (`toolchains`). Version managers hoard
  multi-gigabyte installed runtimes — old `~/.nvm` node builds, `~/.pyenv` /
  `~/.rbenv` versions, `rustup` toolchains, SDKMAN candidates, `asdf` installs.
  Cleanix keeps the **active** version (always protected) plus the newest
  `keep_toolchain_versions` (default 2) and offers the rest for removal. It
  *skips a manager entirely if it can't prove which version is active* — pair
  with `clean --quarantine` to make removals reversible. Disable with
  `prune_old_toolchains: false`.
- **Stale project cruft** (`project_cruft`, report-only). Finds regenerable
  `node_modules` / `.venv` / `target` / `.gradle` dirs in projects under
  `project_scan_dirs` you haven't touched in `project_stale_days` (default 120).
- **Large files** (`big_files`, report-only). The biggest files in `$HOME`, so
  you can see what filled the disk. Never deletes — just a sized list + `rm` hint.
- **Stale downloads** (`downloads`, report-only). Old, large installers/ISOs in
  `~/Downloads` (which stays hard-protected from deletion).

## Working with what a scan finds

- `cleanix explain <id>` — read-only, shows the **exact** paths/commands one
  cleaner would consider (with size, root, delete-vs-report), for building trust.
- `cleanix clean --interactive` — pick individual items from a checklist before
  removing (selection is per-item, not just per-cleaner).
- `cleanix clean --simulate` — write the exact target list to a file, delete
  nothing (stronger than the dry-run summary).
- `cleanix clean --execute` — writes a **per-file audit manifest** to
  `~/.local/state/cleanix/runs/` and prints the real `df` free-space change.
- `--profile safe|balanced|aggressive` — one flag to bundle the opt-in settings
  (aggressive enables offline-repo/backup/locale/all-image pruning; it never
  bundles volume removal).
- `--min-size 100M` — ignore items below a threshold to cut table noise.
- `cleanix scan --json` emits a **versioned** schema (`schema_version`, host,
  os, `cleanable_bytes` vs `report_only_bytes`) for CI/tooling.

## Container leftovers (Docker / Podman / nerdctl / crictl)

A *leftover* is anything the engine keeps that **no existing container
references** and can be regenerated. Each category is surfaced as its own item
whose estimated size matches exactly what pruning it reclaims — so the number
you see is the number you get (no more counting unused-but-tagged images or
volumes you never asked to touch):

- **Dangling (untagged) images** — `docker image prune -f`
- **Stopped containers** (writable layers) — `docker container prune -f`
- **Build cache** — `docker builder prune -f`
- **Unused networks** — `docker network prune -f`

Two categories stay **opt-in** because they can destroy real work:

- `docker_prune_all_images` — also remove *tagged* images not used by any
  container (`image prune -a`); frees more but forces a re-pull next time.
- `docker_prune_volumes` — also remove unused anonymous volumes, which may hold
  databases or other real data.

> On macOS, Docker Desktop stores everything in a VM disk image. Pruning frees
> space *inside* the VM; the host-side `Docker.raw` file may not shrink until
> Docker Desktop compacts it.

## Shell completion

```bash
cleanix completion bash | sudo tee /etc/bash_completion.d/cleanix
cleanix completion zsh  > ~/.zfunc/_cleanix     # a dir on your $fpath
cleanix completion fish > ~/.config/fish/completions/cleanix.fish
```

Completes subcommands, options, cleaner ids (for `--only`/`--exclude`) and config
keys — baked in from the live build.

## Safe memory reclamation (RAM + swap)

Opt-in cleaners that free memory **without ever killing or trimming apps**:

```bash
sudo cleanix clean --only memory --execute   # drop clean page/dentry/inode cache
sudo cleanix clean --only swap   --execute   # move swap back to RAM (OOM-guarded)
sudo cleanix clean --only memory_macos --execute   # macOS `purge`
```

- `memory` runs `sync` then `drop_caches` — the kernel only releases *clean*
  cached pages, re-reading from disk later; no process loses data.
- `swap` runs `swapoff -a && swapon -a` **only when free RAM comfortably exceeds
  swap in use** (20% headroom), so it can never trigger an OOM kill.
- These are excluded from the default `scan`/`clean` (their effect is transient);
  run them explicitly with `--only`.

## IDE & application coverage

- **IDEs** (`ide_caches`): VS Code and forks (VSCodium, Cursor, Windsurf, …)
  logs / `CachedExtensionVSIXs` / stale workspace storage, Sublime, Atom, Emacs
  native-comp cache, Zed logs, Qt Creator, Godot, Unity — plus JetBrains and
  Xcode via their dedicated cleaners.
- **Apps** (`app_leftovers`, `snap_app_cache`): logs/crash-reports/temp for
  Minecraft, Steam, Heroic, Lutris, Bottles, OBS, Zoom, Skype, Kodi, Nextcloud,
  Dropbox, Ferdium/Rambox, browser crash reports, and every snap's per-app cache.

## Reversible cleaning, history & dashboard

- **Quarantine (undo):** `cleanix clean --quarantine` *moves* junk into a
  per-run quarantine instead of deleting it. Undo with `cleanix restore`, reclaim
  the space for good with `cleanix quarantine empty`, review with
  `cleanix quarantine list`. A safety net most cleaners don't offer.
- **History & stats:** every real clean is logged; `cleanix stats` shows lifetime
  space reclaimed and recent runs.
- **`cleanix info`:** one-glance dashboard — OS/distro, detected package
  managers, applicable cleaner counts, config path, lifetime cleaned, quarantine
  size.
- **Parallel scanning** across a thread pool (≈1.4×+ faster), with a live
  progress bar.
- **`scan --sort size --top N`** to focus on the biggest wins.
- **User ignore-globs:** `protected_globs` in config adds your own never-delete
  paths on top of the built-in guard.

## Highlights

- **Scan first, clean on confirmation.** Nothing is deleted without an explicit
  `--yes` or an interactive confirmation.
- **Dry-run by default.** `cleanix clean` shows what *would* be removed unless you
  pass `--execute`.
- **Safe deletes.** A hard-coded protected-path guard refuses to touch critical
  system directories on every platform (`/`, `/etc`, `/usr`, `/System`,
  `/Library`, `$HOME`, `~/Library`, `/usr/ports`, ...).
- **Orphan & leftover aware.** Finds orphaned packages, residual configs
  (dpkg `rc` state), package-update residue (`.rpmnew`/`.pacnew`/`.dpkg-old`),
  dangling symlinks, and orphaned launcher entries — the cruft "improperly
  designed" packages leave behind.
- **Accurate sizing.** Uses actual allocated blocks, not apparent size, so
  sparse files don't wildly overstate reclaimable space. Actively-written files
  are left alone (in-use guard).
- **Modular & platform-gated.** Each junk source is an isolated, auditable module
  that declares the platforms it applies to.
- **Root-aware.** Cleaners that need root are clearly flagged and skipped (with a
  note) when you run unprivileged.
- **Scheduling.** Install a periodic read-only scan that reports (and notifies)
  on a daily/weekly/monthly cadence — a **systemd user timer** on Linux, a
  **launchd LaunchAgent** on macOS, and a **cron job** on the BSDs (or any
  system with `crontab` but no systemd). Same `cleanix schedule` command on all.

## Install

```bash
pip install cleanix-cli      # from PyPI
# or from source:
cd cleanix-cli && pip install -e .
```

This installs the `cleanix` command. Standalone Linux/macOS binaries are also
attached to each [GitHub Release](https://github.com/CloudOpsWorld/cleanix-cli/releases).

## Usage

```bash
# List available cleaners
cleanix list

# Analyze the system (read-only) and print a report
cleanix scan

# Analyze only specific cleaners
cleanix scan --only trash,thumbnails,apt

# Preview what a clean would remove (dry-run, the default)
cleanix clean

# Actually delete, asking for confirmation
cleanix clean --execute

# Delete without prompting (for scripts)
cleanix clean --execute --yes --only trash,pip_cache

# Emit the scan report as JSON (for tooling / notifications)
cleanix scan --json

# Install a weekly read-only scan that notifies you
# (systemd timer on Linux/BSD, launchd agent on macOS)
cleanix schedule install --frequency weekly

# Check / remove the schedule
cleanix schedule status
cleanix schedule uninstall

# View and change settings (no YAML editing needed)
cleanix config list
cleanix config set remove_old_kernels false
cleanix config set keep_kernels 3
cleanix config unset keep_kernels        # revert to default

# See a factory-reset plan for this OS (advisory — runs nothing)
cleanix factory-reset
cleanix factory-reset --scope user
```

## Configuration via CLI

`cleanix config` reads/writes `~/.config/cleanix/config.yaml` with type-checked
values, so you never have to hand-edit YAML:

```bash
cleanix config list                 # every setting, value, source, description
cleanix config get <key>
cleanix config set <key> <value>    # bool/int/float/list are validated
cleanix config unset <key>          # revert to the built-in default
cleanix config path
```

## Factory-reset advisor

`cleanix factory-reset` detects how your OS can be reset and prints a **tiered,
copy-pasteable plan** — it never executes anything destructive:

- **NixOS / Guix** → declarative rollback to a prior generation (✅ reversible)
- **rpm-ostree** (Silverblue/Kinoite) → `rpm-ostree reset` to the base image (✅)
- **openSUSE MicroOS** → `snapper rollback` (✅)
- **macOS** → the built-in "Erase All Content and Settings" (recommended)
- **Traditional distros** (Fedora/Ubuntu/Arch) → honestly reports there is *no*
  true factory reset; suggests snapshot-restore/reinstall and gives best-effort
  package/config/user reset steps.

`--scope user|packages|system|full` controls how much the plan covers.

### Executing a reversible reset

On reversible systems only, cleanix can run the rollback for you:

```bash
sudo cleanix factory-reset --execute
```

This is heavily gated:

- **Only reversible strategies** run — NixOS (`nixos-rebuild switch --rollback`),
  rpm-ostree (`rpm-ostree reset`), MicroOS (`snapper rollback`), Guix
  (`guix system roll-back`). Traditional distros and macOS **refuse to execute**.
- **Only the reversible rollback command** runs — never the irreversible
  dotfile/`rm -rf` steps (those stay advisory).
- Requires **root**, an **interactive terminal**, and a **typed confirmation
  phrase** (`reset <hostname>`). Each action prints its **undo** command.
- Stops on the first failure.

Without `--execute`, `factory-reset` only prints the plan.

## System-wide mode (root)

Run unprivileged, cleanix scans **your** home. Run as **root/sudo**, it
automatically sweeps **every real user's home** plus system-wide locations:

```bash
sudo cleanix scan                 # all users + system (auto when root)
sudo cleanix scan --current-user  # restrict to the invoking user
cleanix scan --all-users          # force multi-user even unprivileged
sudo cleanix scan --min-uid 500   # change the "real user" uid threshold
```

How it works:

- Cleaners declare a **scope**: *user* (trash, caches, browsers, AI tools, …)
  or *system* (package managers, `/var/log`, journal, coredumps, …).
- User-scoped cleaners run **once per target user**, resolving `~`, `~/.cache`,
  `~/.config`, uid, etc. against *that* user — never leaking root's environment.
- Target users come from `/etc/passwd`: root plus accounts with uid ≥ `min_uid`
  (1000 on Linux/BSD, 500 on macOS) that have a real home directory.
- Shared/system paths yielded for multiple users are **de-duplicated**, so
  nothing is offered — or deleted — twice.
- The protected-path guard is extended to cover **every** scanned user's home
  (and their `~/.config`, `~/.local`, `~/Library`, …), so a bug can never wipe
  another user's home.

## Report-only tier (backups & snapshots)

Some things are *leftovers* but also *recovery data* — filesystem snapshots,
mobile-device backups, suspended-VM memory images. Cleanix surfaces these with
their size and the **correct removal command**, but they are **never** eligible
for deletion (`clean` skips them; even a forced attempt is refused):

```
Report-only — review and remove manually (never auto-deleted)
  7.5 GiB  Timeshift snapshot: 2026-01-01   timeshift --delete --snapshot '2026-01-01'
```

Covered report-only: Timeshift/Snapper snapshots, libvirt saved VM states,
macOS Time Machine local snapshots, iOS device backups, macOS sleep image.

## Extended coverage

Beyond the core cleaners, cleanix also handles:

- **Old kernels** — package-manager-driven; always keeps the running kernel and
  the newest `keep_kernels` (default 2). Set `remove_old_kernels: false` to skip.
- **System caches & spools** — `/var/cache` (PackageKit/man/fontconfig/cups),
  Debian `/var/backups`, ABRT/apport crash spool, staged offline-update payloads.
- **Language package caches** — Go modcache, rustup/deno/bun/nvm/pnpm, Android
  SDK. Offline repos (Maven/Ivy/sbt/Coursier/NuGet/RubyGems) gated behind
  `include_offline_repos`.
- **Desktop search indexes** — Baloo, Tracker, Zeitgeist, GVFS metadata.
- **VM/cloud tooling** — VirtualBox logs, Vagrant boxes, kube/minikube/helm,
  AWS/Azure/gcloud/Terraform/Pulumi caches.
- **Editor & build litter** — Vim/Neovim swap/undo, `__pycache__`,
  `.pytest_cache`/`.mypy_cache`/`.ruff_cache`/`.tox`, loose core dumps.
- **macOS extras** — Saved Application State, CocoaPods/Carthage, QuickLook.
- **Opt-in** (off by default): editor backup files (`*~`/`*.bak`/`*.orig`) via
  `remove_backup_files`, and localepurge-style unused locales/man-pages via
  `purge_unused_locales`.

## Safety model

1. **Two-phase**: `scan` is always read-only. `clean` defaults to dry-run.
2. **Protected paths**: deletion of (or inside) critical paths is refused at the
   lowest level — see `cleanix/core/safety.py`.
3. **Age thresholds**: temp/log cleaners only consider files older than a
   configurable age, so in-use files are left alone.
4. **Scheduled = analyze only**: the timer runs `scan` and writes a report; it
   does not clean.

## Configuration

Defaults live in `cleanix/config.py`. Override them with a YAML file at
`~/.config/cleanix/config.yaml` (see `config/default.yaml` for the shape).

## Project layout

```
cleanix/
  cli.py              # argparse entry point (scan / clean / list / schedule)
  config.py           # defaults + YAML overrides
  core/
    models.py         # CleanableItem, CleanerReport, dataclasses
    platform.py       # OS + distro detection, platform tokens
    context.py        # multi-user scanning (target users, current-user binding)
    safety.py         # protected-path guard + safe delete
    engine.py         # runs cleaners, aggregates reports, executes cleans
    registry.py       # discovers, platform-filters & instantiates cleaners
    utils.py          # sizes (allocated blocks), walking, age/in-use guards
    report.py         # rich tables + JSON rendering
  cleaners/
    base.py                 # Cleaner ABC (declares .platforms)
    # cross-platform
    trash, thumbnails, user_cache, temp_files, font_cache, browsers,
    broken_symlinks, apple_litter, dev_caches, pip_cache, npm_cache, containers
    # logs & crashes
    logs, coredumps, linux_extras (config residue + /var/crash)
    # linux package managers
    apt, dnf/yum, pacman, distro_pkg (zypper/apk/xbps/portage),
    more_pkg (conda/mamba, guix, eopkg, swupd, opam, sdkman, gem, cpanm),
    packaging_extras (flatpak/snap/nix/appimage)
    # AI / LLM engines & clients
    ai_tools (ollama, huggingface, compile caches, ai clients, aider)
    ai_cli (claude code, codex, gemini cli, opencode — retention-aware)
    # desktop-app bloat
    app_cruft (electron caches, flatpak caches, gpu shaders, steam, jetbrains)
    # extended system leftovers
    sys_extras (/var/cache, /var/backups, crash spool, offline updates)
    kernels (old-kernel purge), localizations (localepurge, opt-in)
    # extended user leftovers
    lang_caches (go/rust/js/.net/jvm), desktop_extras (search indexes)
    virtualization (vbox/vagrant/k8s/cloud), editor_litter (swap/pycache/cores)
    # backups & snapshots (report-only tier)
    snapshots (timeshift/snapper/timemachine/device backups)
    # macOS
    macos (caches, trash, diagnostics, homebrew, macports, xcode)
    macos_extra (saved state, cocoapods, sleep image)
    # BSD
    bsd (freebsd pkg, distfiles/work dirs, pkgin)
  scheduler/
    __init__.py       # backend() — picks systemd or launchd for the OS
    systemd.py        # install/uninstall/status of a user systemd timer (Linux/BSD)
    launchd.py        # install/uninstall/status of a launchd LaunchAgent (macOS)
```

To add a cleaner: subclass `Cleaner`, set `id`/`name`/`platforms`/`requires_root`,
implement `find_items()` (read-only, yields `CleanableItem`s), and register it in
`cleaners/__init__.py`. The engine handles dry-run, confirmation, root checks,
and the safety guard for you.

## License

MIT
