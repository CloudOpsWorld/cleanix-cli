# Cleanix CLI

[![CI](https://github.com/CloudOpsWorld/cleanix-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/CloudOpsWorld/cleanix-cli/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/cleanix-cli.svg)](https://pypi.org/project/cleanix-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/cleanix-cli.svg)](https://pypi.org/project/cleanix-cli/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A safe, thorough system cleaner for **every *nix flavour** — Linux (all
major distros), macOS, and the BSDs — and **Windows**. It **analyzes** your OS for junk — caches,
temp files, package-manager leftovers, orphaned packages, broken symlinks,
package-update config residue, rotated logs, trash, thumbnails, browser/dev
caches, container cruft — and only **removes** anything after you confirm.

It can run on a **schedule** (a systemd timer on Linux/BSD, a launchd agent on
macOS, a Task Scheduler task on Windows) to periodically analyze the
system and notify you (on Windows the report file is the output; no
notification is shown). Scheduled runs *never delete anything*; they only produce
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
| Windows  | `windows`                          | `%TEMP%`, thumbnail/icon caches, error reports & crash dumps, Recycle Bin, Windows Update/Delivery Optimization cache, system temp & dumps (admin), browser caches (Chrome/Edge/Brave/Firefox), DirectX/NVIDIA/AMD shader caches, WinGet/Chocolatey/Scoop/NuGet caches, Visual Studio cache; report-only: Prefetch, `Windows.old`, WSL disks; opt-in: DISM component store, dead registry entries (see [Windows registry cleaners](#windows-registry-cleaners-opt-in)); Task Scheduler |
| Cross-OS | all of the above                   | trash, thumbnails, ~/.cache, temp files, fonts, browser caches, broken symlinks, `.DS_Store`/AppleDouble, dev/language caches (cargo/go/gradle/ccache/composer/…), pip, npm/yarn, Docker, Podman |

Run `cleanix list` to see what applies to your machine, or `cleanix list --all`
to see every platform's cleaners.

## Windows notes

- Config is `%APPDATA%\cleanix\config.yaml`; state, history and quarantine live
  under `%LOCALAPPDATA%\cleanix`. Cleanix touches the registry only through
  the five opt-in registry cleaners (see
  [Windows registry cleaners](#windows-registry-cleaners-opt-in)): they are
  never part of a normal scan or clean, never run from the scheduled scan, and
  every other cleaner leaves the registry alone.
- Items that need admin rights (`win_system_temp`, `win_update_cache`,
  `win_system_dumps`, DISM) require an **elevated terminal** (Run as
  administrator); otherwise they are skipped with a note.
- **Report-only:** Prefetch, `Windows.old` and WSL virtual disks (`wsl_disk`)
  are sized and explained, never deleted.
- **DISM component-store cleanup is opt-in:**
  `cleanix clean --only win_component_store --execute` (elevated).
- **Quarantine moves path-based items only.** Command items such as emptying
  the Recycle Bin and DISM cannot be undone with `cleanix restore`. Registry
  entries are not moved: before one is deleted, a `.reg` and a `.json` backup
  of it is written into a quarantine run (even when "keep a copy" is off).
  Whether Cleanix promises that these can be restored is a separate, gated
  statement; see [Windows registry cleaners](#windows-registry-cleaners-opt-in).
- `cleanix schedule install` creates a per-user, scan-only Task Scheduler task
  named "Cleanix Scan" (it never cleans). It does not raise a notification:
  the JSON report at `%LOCALAPPDATA%\cleanix\last-scan.json` is the output.
- External tools are never looked up in the current directory: PowerShell,
  DISM and schtasks run from the System32 directory, everything else (e.g.
  `docker`) only from absolute `PATH` entries.
- Quarantine across volumes refuses folders that contain a junction or
  symlink (they are never copied); a locked file makes the item fail with
  nothing copied, and any copy that has to be kept is listed by
  `cleanix quarantine list`.
- **Residual limits (elevated runs).** `C:\Windows\Temp` is writable by
  standard users. Before descending into each folder the remover re-checks
  that it is still the same plain folder (not swapped for a junction), but a
  swap in the short window between that check and the deletion is not
  prevented (that needs handle-relative NT APIs), and entries in
  `Windows\Temp` are not filtered by owner. If untrusted local users share the
  machine, exclude that cleaner (`--exclude win_system_temp`).
- `cleanix factory-reset` is not supported on Windows.
- The AI-tool, dev-cache, pip/npm, Docker, Electron, JetBrains, big-file,
  duplicate, downloads, stale-project and browser-profile cleaners also run on
  Windows.

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
- **Duplicate files** (`duplicates`, report-only). Identical large files (same
  size + SHA-256) grouped with the space reclaimable by keeping one copy.
- **Stale downloads** (`downloads`, report-only). Old, large installers/ISOs in
  `~/Downloads` (which stays hard-protected from deletion).
- **Orphaned browser profiles** (`browser_profiles`, report-only). Secondary
  Chrome/Chromium/Firefox profiles idle for `browser_profile_stale_days`, with a
  clear warning that a profile holds bookmarks/passwords/history.

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
- `cleanix dashboard` — lifetime reclaim trend (sparkline) plus the last
  scheduled scan's top sources, at a glance.

## Install & packaging

- **PyPI:** `pip install cleanix-cli` (or `pipx install cleanix-cli`); add the
  `gui` extra for the desktop GUI (see [Graphical interface](#graphical-interface)).
  Standalone GUI installers are planned (Plan 2B).
- **Standalone binaries** are attached to each [GitHub Release] alongside a
  `SHA256SUMS` file and keyless **build-provenance attestations** — verify a
  download with `gh attestation verify <file> --repo CloudOpsWorld/cleanix-cli`.
- **Homebrew / AUR / Fedora** packaging lives under [`packaging/`](packaging/),
  along with a `cleanix.1` **man page** generated from the CLI
  (`python scripts/gen_manpage.py`).

[GitHub Release]: https://github.com/CloudOpsWorld/cleanix-cli/releases

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
- **Scheduling.** Install a periodic read-only scan that reports (and notifies;
  on Windows the report file is the output)
  on a daily/weekly/monthly cadence — a **systemd user timer** on Linux, a
  **launchd LaunchAgent** on macOS, a per-user **Task Scheduler** task on
  Windows, and a **cron job** on the BSDs (or any
  system with `crontab` but no systemd). Same `cleanix schedule` command on all.

## Install

```bash
pip install cleanix-cli      # from PyPI
# or from source:
cd cleanix-cli && pip install -e .
```

This installs the `cleanix` command. Standalone Linux/macOS binaries are also
attached to each [GitHub Release](https://github.com/CloudOpsWorld/cleanix-cli/releases).

## Graphical interface

An optional desktop GUI (Qt / PySide6) runs the same engine as the CLI, in
the same process: the same scan, the same safety guard, the same quarantine
and history.

```bash
pip install "cleanix-cli[gui]"    # adds PySide6; the CLI never needs it
cleanix gui                       # or: cleanix-gui
```

Without the extra, `cleanix gui` prints the install hint and the CLI keeps
working. Standalone GUI installers (Windows installer, macOS `.dmg`, Linux
AppImage) are coming in a later release (Plan 2B); for now install with pip.

**Simple and Power.** A toolbar switch at the top picks the mode; the choice
is remembered. Both modes show scan results as a short list of plain-language
groups instead of raw paths. Each group has a title, a one-line explanation,
the item count, the total size and a **safety badge**. The badge always spells
the level out in words (colour is only a hint):

- **Safe**: rebuilt automatically; can be cleaned from Simple mode.
- **Review**: needs your judgment. Report-only findings are never deleted by
  Cleanix (their row says why and, where there is one, how to remove them by
  hand). Other Review items can be cleaned only from Power mode; in Simple
  mode they are listed read-only.
- **Needs admin**: needs administrator permission and cannot be undone;
  tickable only when administrator cleaning is available and the helper would
  clean it, otherwise shown read-only with the reason.
- **Permanent**: cannot be undone (command items, for example emptying the
  Windows Recycle Bin or pruning containers).

A group shows its biggest items (top 15) and folds the rest into one
"N smaller items" row; double-click it (or Enter, or right-click and Show all)
to list them. Items with nothing to reclaim are hidden. Command items, whose
size is only an estimate, are never hidden for being 0 B. Hover a row for the
full path and any manual-removal hint; right-click an item for Copy path and
Open location.

**Simple mode** (the default) is Scan, review, Clean, Undo. A **Deep scan**
checkbox (off by default) adds the slow cleaners (duplicates, big files and
similar); a normal scan skips them. Results are split into three lists: the
main list holds groups with something pre-selected, "Also found (not
selected)" holds the Permanent and Needs admin groups, and "Needs your
review" holds the Review groups. Simple mode only lets you tick reviewed-safe
cleaners and the Trash and System groups; everything else (including cleaners
Cleanix does not know) is read-only there. Only files from reviewed-safe cleaners that
your normal user can delete are pre-selected; nothing that needs
administrator permission, nothing irreversible and no personal data is ever
pre-selected. Before cleaning, a confirmation shows the count and size and
offers **"Keep a copy so I can undo"**, ticked by default: files are moved
into quarantine instead of deleted (they use disk space until you empty it).

**Power mode** shows the same curated groups for every cleaner you choose to
scan ("Choose what to scan"), with a detail pane, JSON export and tabs for
Quarantine (restore, delete a run, empty all), History, Schedule, Settings
(every config key, including `protected_globs`) and Findings (report-only
items, with Reveal in the file manager; never deleted). Extra controls:

- **Raw list** toggles between the curated groups and the full sortable,
  filterable table of every item.
- Quick selects: **Select all visible**, **Select none**, **Safe only** and
  **Developer** act on the rows currently visible (filter and safety level).
- A safety-level filter, a text filter and **Show empty** (lists zero-size
  items and lets you tick them).

Settings saved in the Settings tab apply to the running GUI from the next scan
or clean (no restart needed). **Dry run is ticked by default**; untick it to
clean for real. A dry run never asks for administrator permission: items that
need it are listed as a preview ("would be removed after one administrator
prompt"). "Keep a copy (undo)" is also ticked by default.

**What Undo covers.** Undo (Simple mode, or Restore in the Quarantine tab) only
brings back *files* that were cleaned as your normal user with a copy kept.
These are always permanent and cannot be undone:

- items that need administrator permission (the helper never quarantines);
- command items, such as emptying the Recycle Bin / Trash or pruning
  containers;
- anything cleaned with "keep a copy" unticked.

Registry entries (Windows, Power mode only; Simple mode never cleans them) are
backed up in every case, but the Undo promise for them is **gated**: until the
checks in [docs/registry-cleanup-verification.md](docs/registry-cleanup-verification.md)
have been run on a real Windows machine, the GUI and the CLI say that registry
entries are removed permanently and that no backup or restore is available in
this version. Once the promise is switched on, per-user (`HKCU`) entries can be
restored from the Quarantine tab or with `cleanix restore <run>`, and
machine-wide (`HKLM`) entries only from an Administrator terminal (never from
the GUI).

**Administrator permission.** The GUI never runs as root: on Linux, macOS and
the BSDs it refuses to start when run as root (`sudo cleanix gui`) and asks
for administrator permission itself when needed. When you clean items
that need administrator rights, you are asked once per clean, through the
operating system's own prompt, and a separate helper (`python -m
cleanix.elevated`) removes them:

- **Windows:** the UAC prompt.
- **Linux:** `pkexec`, which needs polkit and a running polkit authentication
  agent (normal in desktop sessions). Without `pkexec` such items are shown for
  review only.
- **macOS:** the standard administrator password prompt.

The prompt itself does not list what will be removed; the GUI's confirmation is
the place to check. The helper trusts only cleaner ids and item keys from the
request, re-scans by itself and cleans only items it finds eligible. It runs
only a fixed list of system cleaners (see `admin_cleaner_ids` in
`cleanix/elevated.py`). In 1.4.0 that is 23 cleaners on Linux: the package
managers (`apt`, `dnf`, `pacman`, `zypper`, `apk`, `xbps`, `portage`,
`eopkg`, `swupd`), `old_kernels`, `snap`, system logs, journal, coredumps and
crash reports, `system_cache`, `var_backups`, `offline_updates`,
`config_leftovers`, `localepurge`, `crictl`, plus `temp` for other users'
entries. On macOS and the BSDs it is the same rule (default-enabled system
cleaners that need root and support the platform, plus `temp`). The opt-in
memory/swap actions are never included. On Windows it is 4 cleaners:
`win_system_temp`, `win_system_dumps`, `win_update_cache` and
`win_component_store` (not `temp`), plus the five registry detectors
(`win_reg_uninstall`, `win_reg_app_paths`, `win_reg_file_assoc`,
`win_reg_startup`, `win_reg_shared_dlls`), for which it deletes `HKLM` entries
only and never `HKCU`. The GUI offers only administrator items
the helper would clean; the rest are shown read-only with the reason. It uses
built-in default settings and ignores most of your config: only
`protected_globs` is honoured, since it can only add protection. It never
writes history or quarantine; the GUI records one history entry for its work.

Before offering administrator items the GUI checks once that the helper can
start (`python -I -c "import cleanix.elevated"`). A `pip install --user` or a
source-tree run fails that check: administrator items are then shown
read-only with "Administrator cleaning is not available: the helper cannot be
started from this installation"; install cleanix into the system or a venv.

**Headless / SSH.** The GUI needs a desktop session; over SSH or on a server
use the CLI. (The test suite runs the GUI headless with
`QT_QPA_PLATFORM=offscreen`.) Scheduled runs set up from the Schedule tab are
the same as `cleanix schedule`: they only scan and report, never delete.

### Security notes for the administrator helper

Known residuals, accepted for now (details in `cleanix/elevated.py`):

- **POSIX check-then-delete is path-based.** Every directory above an item is
  re-checked right before deletion, but a service account or group that owns a
  trusted parent could swap a path component between the check and the delete.
  Descriptor-anchored deletion is future work.
- **Code-location trust.** The helper is started with `python -I`, which
  ignores `PYTHONPATH`, the current directory and the user site directory.
  Consequently a `pip install --user` install cannot run the helper (install
  into a venv or system-wide). A user-writable interpreter or venv is still
  user-writable code run as administrator; a root-owned install location is
  planned with the installers (Plan 2B).
- **POSIX ACLs are not inspected**; only owner, group and mode bits are.
- **Windows: the result file is written by path**, as administrator, into the
  requesting user's directory; a junction swap after validation could redirect
  that write. Handle-based writing is future work.
- **Windows: `Windows\Temp` is cleaned only partly.** In elevated runs,
  `win_system_temp` removes plain files there; directories (user-creatable,
  swappable for junctions mid-delete) are refused. Items under `ProgramData`
  are always refused in elevated runs.
- **macOS:** the administrator path has been reasoned about from the code and
  unit-tested with mocks, but not yet run on a real Mac.

**Machine-wide registry entries (Windows).** The helper has a second, separate
action for registry entries under `HKLM`:

- Before the prompt, the GUI backs each entry up **as you** into a new
  quarantine run (`.reg` + `.json`); an entry whose backup fails is not sent.
  If you decline the prompt, that run is removed again.
- The request carries only the registry detector ids, the item keys you
  ticked (each embeds the entry's content fingerprint), the backup **run id**
  and your quarantine folder. The helper re-scans with exactly those
  detectors and deletes only `HKLM` entries its own scan found, whose key and
  fingerprint match, that pass the registry safety rules, and for which that
  run holds a verified backup it could restore. Anything else is refused or
  reported as "no longer found".
- The helper never reads or changes `HKCU`: running elevated, `HKCU` is the
  administrator's hive, not yours. A request naming an `HKCU` entry is
  refused as a whole, as is one with an unknown field, a run id containing a
  path separator, a detector outside the five registry detectors, or a helper
  that is not elevated.
- The run must be yours: the helper takes the owner of the request folder
  (created by the unelevated GUI), looks up that account's profile in
  `HKLM\...\ProfileList` (administrator-writable only), and accepts the
  quarantine folder only inside that profile, without links or junctions, and
  only when the folder, the run and its manifest are owned by that account.
  It never uses the administrator's own `%LOCALAPPDATA%`.
- The quarantine folder must be on a local drive: a network (UNC, WebDAV) or
  device path is refused from its text alone, before the helper touches the
  filesystem. A request therefore cannot point the helper at a network share
  directly. The run's manifest and backups are read once, during that
  validation, each right after it is checked, and the helper deletes using
  those in-memory copies; it never opens the run again by name.
- The helper writes nothing: no quarantine run, no history.
- Restoring these entries needs an Administrator terminal. The backup folder
  can be changed by **any program running as you**, so inspect every `.reg`
  file before importing it, then run `reg import "<absolute .reg path>" /reg:64`
  for each one. `cleanix restore <run>` works only when the Administrator
  terminal runs as the same account that made the backup (it lists exactly what
  it will write first). With over-the-shoulder UAC (a separate administrator
  account) it cannot find the run.

What this does **not** protect against:

- **Programs running as you.** A same-user (medium-integrity) program can edit
  the request or the backup run between the GUI and the helper. It can only
  choose among entries the helper's own allowlisted scan finds dead, and each
  delete still needs a verified backup; but it can alter backup files after
  the fact, which is why the GUI never offers an elevated restore and
  `cleanix restore` shows exactly what it will write before writing it.
- **The registry delete race (R17).** There is no transactional registry API:
  between the last check and `RegDeleteKeyEx` a key could be swapped for a
  registry link, and the link's target could be deleted. This is reported as
  "partially deleted … scan again", never as success.
- **Restore of tampered backups (T4).** Restore re-validates every path and
  value, but a backup in your folder may have been written by any program
  running as you; an elevated restore writes machine-wide. Review the listed
  keys and values before confirming.
- **Partial deletes (T11).** A key tree that fails mid-delete is reported with
  its backup run; restore recreates exactly the missing parts.
- **Link swaps during validation.** Each file of the run is checked with
  `lstat` (links are not followed) and opened immediately afterwards; the
  opened file must be the one just checked, or it is refused. A program
  running as you that can create symbolic links (Developer Mode, or an
  object-manager symlink) could still swap a folder in the instant between
  that check and the open. The administrator's open would then follow the
  swapped link, possibly to a network path, before the check refuses the
  file. Opening relative to an already-verified folder handle is future work.
- **"Missing" evidence in folders standard users can write.** A machine-wide
  entry is listed as dead when the program it points at is missing. Some
  locations outside `C:\Users` are writable by standard users (folders created
  directly under `C:\` inherit "Authenticated Users: Modify"; some vendor
  folders under `ProgramData`). A standard user can rename a file there so that
  a live `HKLM` entry looks dead, and it is then deleted once an administrator
  approves the prompt. This is a denial of service only (the entry is backed up
  first), not a privilege gain.

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
# (systemd timer on Linux/BSD, launchd agent on macOS; on Windows a Task
# Scheduler task whose output is the report file, no notification)
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

### Windows registry cleaners (opt-in)

Five detectors look for dead registry entries: `win_reg_uninstall`,
`win_reg_app_paths`, `win_reg_file_assoc`, `win_reg_startup` and
`win_reg_shared_dlls`. They are Windows only and **never** part of a plain
`cleanix scan` / `cleanix clean`, a `--profile`, or the scheduled scan; name
them explicitly (`cleanix list` shows them as `opt-in`) with `--only` or the
`--registry` flag. `--registry` (Windows only; elsewhere it exits 2 with
"Registry cleanup is only available on Windows.") selects exactly the five
registry cleaners, or adds them to an explicit `--only`; it counts as the
explicit selection `clean` requires and is never implied by a profile, the
configuration or the scheduled scan:

```bash
cleanix scan --registry                                         # same five ids
cleanix clean --registry --execute                              # lists every key/value, asks first
cleanix scan --only win_reg_uninstall,win_reg_startup          # read-only
cleanix scan --only win_reg_uninstall --json                    # targets in JSON
cleanix clean --only win_reg_uninstall --execute                # lists every key/value, asks first
cleanix clean --only win_reg_uninstall --execute --yes          # no prompt
cleanix restore <run-id>                                        # undo, once shipped
```

Scan output and JSON show each target as `HKCU\path\to\key [value]` (control
characters are shown escaped); JSON items add `kind`, `target` and
`registry` (`{"hive","key","value"}` or `null`), and each cleaner adds a
boolean `registry` (true for the five registry ids). `history.jsonl` entries
of runs that removed registry entries carry a `registry` count (no values).
Machine-wide (`HKLM`) entries are only removed from an elevated
(Administrator) terminal; without one they are skipped with a message.
Restoring a run that contains `HKLM` entries also needs an Administrator
terminal: `cleanix restore` prints exactly what will be written and asks you
to type `yes` (`--yes` is accepted only together with an explicit run id).

What the CLI promises about backups follows what this version ships (see
"Undo status" below). While registry undo is not shipped, the CLI says registry
entries are removed permanently and no backup or restore is available. Once
shipped, `HKCU` entries are backed up before removal and can be restored with
`cleanix restore <run>`; `HKLM` entries are backed up too, but restoring them
needs an Administrator terminal.

#### What the registry cleaners do, and do not do

They list an entry only when every piece of evidence the detector needs is
**provably missing**. "Unknown is not dead": an unreadable key, a network or
removable drive, a variable that cannot be expanded, a host program such as
`msiexec` or `rundll32`, anything under the Windows directory, Microsoft- or
Store-owned locations, an MSI- or Burn-managed uninstall entry, or an entry
whose structure the detector does not recognise is never listed. For
machine-wide entries, targets under `C:\Users` are also unknown (they belong to
another user's per-user install).

- `win_reg_uninstall`: `Uninstall` keys (including the 32-bit `WOW6432Node`
  view) whose install folder **and** uninstaller are gone.
- `win_reg_app_paths`: `App Paths\<name>.exe` entries whose program is gone.
- `win_reg_file_assoc`: "open with" handlers (a class with a
  `shell\...\command` and an optional `DefaultIcon`) whose programs and icons
  are all gone.
- `win_reg_startup`: `Run` and `RunOnce` values for programs that no longer
  exist. Nothing is "disabled": live startup entries are never touched.
- `win_reg_shared_dlls`: `SharedDLLs` counters for files that no longer exist.

They never claim to speed up Windows or free space (registry items have size 0
and are never counted in "freed"), never delete a live entry, never open
the merged `HKEY_CLASSES_ROOT` view (file-type handlers are read and removed
under the two real `Software\Classes` keys), `HKEY_USERS`,
`HKEY_CURRENT_CONFIG`, Windows Installer, policy or Explorer keys, and open only
the 64-bit registry view (`KEY_WOW64_64KEY`; the 32-bit view is reached only
through explicit `WOW6432Node` paths, also from a 32-bit Python). The findings are always
labelled **Review** in the GUI. `--all-users` does not load other users'
hives: `HKCU` is the registry of the account running Cleanix (in an elevated
terminal that is the administrator's, which is why elevated scans do not judge
`HKCU` handlers).

**Backups.** A registry entry is deleted only after a backup of exactly what
was scanned has been written and read back (a failed backup means nothing is
deleted), and only if the entry is still what the scan saw (its fingerprint is
part of the item key); otherwise it is reported as "changed since the scan;
scan again". Each removed entry gets two files in a quarantine run,
`N__registry.reg` (UTF-16 with BOM, `Windows Registry Editor Version 5.00`;
readable in Notepad, usable with `reg import`) and `N__registry.json` (typed
values, the source Cleanix's own restore uses). Restore re-creates missing keys
and values additively, refuses any entry whose values differ, validates every
path again and checks that the result equals the backup. Security descriptors
are not backed up: a restored key inherits its parent's permissions.

**Undo status (gated).** The backup code is shipped and unit-tested against an
in-memory registry, but several Windows behaviours it relies on can only be
confirmed on a real machine (registry link handling, `REG_MULTI_SZ` with empty
strings, `reg export`/`reg import` agreement). The 64-bit-view behaviour for
`HKLM\SOFTWARE` cannot be exercised safely and is covered only by unit tests
that pin the `KEY_WOW64_64KEY` flag. Until the manual
verification in
[docs/registry-cleanup-verification.md](docs/registry-cleanup-verification.md)
has passed, the switch `UNDO_SHIPPED` in `cleanix/core/regpromises.py` stays
`False` and every user-visible message says: "Registry entries are removed
permanently: no backup or restore is available in this version." The files are
still written and kept in the quarantine run; they are simply not promised.

**Restoring.** `HKCU` entries: `cleanix restore <run>`, or Restore in the GUI's
Quarantine tab. `HKLM` entries only from an **Administrator terminal**, never
from the GUI. Inspect every `.reg` file first (the backup folder can be changed
by any program running as you), then run
`reg import "<absolute .reg path>" /reg:64` for each one. `cleanix restore
<run>` from the Administrator terminal also works when it runs as the same
account that made the backup: it lists exactly which keys and values it will
write and waits for `yes`. With over-the-shoulder UAC (a separate administrator
account) only `reg import` with the absolute path works, because the run lives
in the standard user's profile.

**Limits and residual risks** (details in
[Security notes for the administrator helper](#security-notes-for-the-administrator-helper)):

- **No transaction (R17).** Between the last check and the delete a key could be
  swapped for a registry link and the link's target deleted. Cleanix reports a
  partly deleted entry as such ("scan again"), never as success. What a delete
  does to a link as the final path component is one of the points the Windows
  verification measures.
- **Programs running as you** can edit a backup between the clean and a restore.
  Restore re-validates and an elevated restore lists what it will write, but
  that is why the GUI never offers an elevated restore.
- **A standard user can make a live `HKLM` entry look dead** by renaming a file
  in a folder they can write; it is then removed only after an administrator
  approves the prompt, and it is backed up first.
- **Partial deletes**: a key tree that fails halfway is reported with its
  backup run; restore recreates exactly the missing parts.
- An entry that cannot be backed up exactly (a `Policies` subkey, names with
  line breaks, a registry link, more than 256 keys, 4096 values or 1 MiB of data) is not
  offered at all.

The elevated helper path (`HKLM`) is covered by unit tests only; it has not
been run against a real machine-wide registry and must not be tried on one.

## Configuration via CLI

`cleanix config` reads/writes `~/.config/cleanix/config.yaml` (`%APPDATA%\cleanix\config.yaml` on Windows) with type-checked
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
    schtasks.py       # per-user Task Scheduler scan task (Windows)
```

To add a cleaner: subclass `Cleaner`, set `id`/`name`/`platforms`/`requires_root`,
implement `find_items()` (read-only, yields `CleanableItem`s), and register it in
`cleaners/__init__.py`. The engine handles dry-run, confirmation, root checks,
and the safety guard for you.

## License

MIT
