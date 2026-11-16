# Cleanix: Windows support and a native GUI — design

Status: draft for approval. Date: 2026-11-16. Base: cleanix-cli v1.2.0 (`CloudOpsWorld/cleanix-cli`).

## Intent and why

Cleanix is a safe, scan-first system cleaner for Linux, macOS and the BSDs. The owner wants it to
cover **every OS variant, including Windows**, and wants a **UI** so it is usable by two audiences
with one tool:

- a **simple user** who wants "scan, then free N GB" with no terminal and no jargon;
- a **power user** who wants visual control: per-item selection, per-cleaner toggles, config,
  quarantine/restore, history, schedules.

The product's core promise must survive the port: nothing is removed without confirmation,
scheduled runs never delete, and every deletion goes through one safety layer.

## Goals

1. Windows 10/11 is a first-class platform: cleaners, safety layer, scheduling, CI.
2. A native desktop GUI (`cleanix gui`) on Windows, macOS and Linux, with a Simple and a Power mode.
3. Distribution through both **pip** and **standalone installers** (Windows, macOS, Linux).
4. The GUI reuses the existing engine; the safety rules exist in one place only.

## Non-goals

- Registry "cleaning", driver or "PC optimizer" features, startup-item disabling. (Not safe to
  automate, and they are what makes cleaner tools untrustworthy.)
- Deleting anything in Windows system areas that Windows itself manages (WinSxS contents are only
  touched via DISM's own cleanup, never by file deletion).
- A web UI or remote/multi-machine management.
- Replacing or breaking the CLI. All existing commands, flags and JSON output stay compatible.

## Anti-goals (a failure even if it technically works)

- Any path where the GUI or a Windows cleaner can delete outside the safety layer.
- A GUI whose "Simple" mode silently selects report-only or personal-data items.
- The base `pip install cleanix-cli` growing a Qt dependency or losing Python 3.10 support.
- A Windows cleaner that deletes user documents, browser profiles, passwords or logins.

## Constraints

- Python >= 3.10; base dependencies stay `rich` and `PyYAML`.
- The GUI is an optional extra: `pip install cleanix-cli[gui]` (PySide6, LGPL).
- Cleaners declare `platforms`; the engine skips non-applicable ones (existing mechanism).
- Deletion is only via `safe_rmtree` / `safe_unlink` in `cleanix/core/safety.py`.
- Existing test suite (`tests/test_cleanix.py`, 817 lines) must keep passing on Linux and macOS.

## Split into two projects, in this order

Each gets its own plan and review. Part 1 ships first because the GUI should list Windows cleaners
from its first release.

### Part 1 — Windows support

What exists: platform detection (`core/platform.py`) has no Windows token; the safety layer's
protected list is POSIX paths only (`/etc`, `/usr`, `/Users`...); `core/context.py` uses `pwd` and
`geteuid` with partial fallbacks; the scheduler picks systemd, launchd or cron; CI explicitly
excludes Windows.

Changes:

1. **Platform:** add a `windows` token (`platform.system() == "Windows"`), `is_windows()`, and a
   `windows` entry in cleaner `platforms`. XDG-style cleaners must not claim Windows.
2. **Safety layer:** add a Windows protected set (drive roots, `C:\Windows`, `C:\Program Files*`,
   `C:\ProgramData`, `C:\Users`, `C:\System Volume Information`, `%SystemRoot%` subtrees) and
   per-user protected folders (Documents, Desktop, Downloads, Pictures, Music, Videos, OneDrive,
   `AppData\Roaming` as a whole, `.ssh`). Path comparison must be case-insensitive and tolerate
   `\\?\` prefixes, drive-letter casing, 8.3 short names and junctions. Symlinks and **junctions**
   are removed as the link only, never followed. In-use/locked files are skipped and reported, not
   forced.
3. **Context and elevation:** replace `pwd`/`geteuid` assumptions with a Windows implementation
   (current user profile, admin check via `IsUserAnAdmin`). Cleaners needing admin are marked
   `requires_root` as today; elevation uses UAC re-launch.
4. **Windows cleaners** (new module(s) under `cleanix/cleaners/`), each declared `platforms=("windows",)`:
   user and system `%TEMP%`; Windows Update download cache (`SoftwareDistribution\Download`);
   Delivery Optimization cache; Recycle Bin (per-drive); thumbnail and icon cache
   (`Explorer\*.db`); Windows Error Reporting and crash dumps (`Minidump`, `MEMORY.DMP`); `Prefetch`
   (report-only by default); old `Windows.old` (report-only, with DISM/Disk Cleanup hint);
   component store via `DISM /StartComponentCleanup` (command item); package-manager caches
   (winget, Chocolatey, Scoop); Microsoft Store and Edge/Chrome/Firefox caches; DirectX/NVIDIA/AMD
   shader caches; Visual Studio and JetBrains caches; Teams/Slack/Discord/VS Code Electron caches
   via the existing Electron cleaner with Windows locations.
5. **Cross-platform cleaners made Windows-aware** where the path differs: dev caches (cargo, go,
   gradle, npm, pip, nuget), browsers, AI tool leftovers, toolchains, Docker Desktop/WSL disk
   reporting (report-only).
6. **Scheduler:** a Windows backend using Task Scheduler (`schtasks`, or the `ScheduledTasks`
   PowerShell cmdlets), same `install/uninstall/status` surface as the other backends.
7. **CI and packaging:** add `windows-latest` to the test matrix; add the Windows trove classifier;
   update README, manpage generation and the platform table. Tests that rely on POSIX paths are
   marked or parameterized, not deleted.

### Part 2 — Native GUI

Toolkit: **PySide6 (Qt)**. Entry point `cleanix gui` (and a `cleanix-gui` script for installers).
Optional extra `[gui]`; if PySide6 is missing, `cleanix gui` prints the install hint and exits.

Architecture:

- GUI code lives in `cleanix/gui/`. It calls the existing `Engine`, config, history, quarantine
  and scheduler modules directly (same process). It does not shell out to the CLI and has no second
  implementation of safety or removal.
- Scan and clean run on worker threads (`QThread`/`QRunnable`) with progress and cancel; the UI
  thread never blocks.
- Elevation: the GUI runs as the normal user. Items needing admin show an "administrator"
  badge; cleaning them triggers a single elevation prompt (UAC on Windows, polkit/`pkexec` or
  `sudo` on Linux, the macOS authorization prompt) via a small elevated helper that runs the same
  engine on only the selected items. The GUI itself is never run as root.

Simple mode (default on first launch):

- One screen: a big **Scan** button; after scanning, friendly category cards (Temporary files,
  Browser caches, Developer caches, Recycle Bin...) with sizes, a total, and one **Clean** button.
- Only deletable, low-risk categories are pre-selected. Report-only and personal-data items
  (downloads, browser profiles, duplicates, big files) are never selected here.
- A confirmation dialog states what will be removed and the total size; "Move to quarantine"
  (undo) is on by default.
- Result screen: space freed, and an **Undo** button while the quarantine run exists.

Power mode (toggle in the toolbar):

- Cleaner list with enable/disable and platform/risk badges; per-item sortable and filterable table
  with checkboxes (the GUI equivalent of `clean --interactive`) and an "explain" pane
  (`cleanix explain`).
- Panels: Quarantine (list, restore, empty), History and stats with a trend chart (the
  `dashboard` data), Schedule (install/remove/status, interval), Settings (every key in
  `config/default.yaml`, protected globs, retention knobs), Report-only findings (big files,
  duplicates, stale projects) with "reveal in file manager".
- Dry-run/simulate toggle; export scan to JSON (same schema as `scan --json`).

Look and feel: follows the OS light/dark theme; simple, readable defaults; keyboard accessible.
Exact visuals are left to the builder (see below).

Distribution:

- **pip:** `pip install cleanix-cli` (CLI) and `pip install "cleanix-cli[gui]"` (CLI + GUI).
- **Installers:** built in GitHub Actions with PyInstaller from the existing `build.yml`/`release.yml`
  pattern: Windows installer (`.exe` via Inno Setup or NSIS, plus a portable zip), macOS `.app` in
  a `.dmg`, Linux AppImage. Installers bundle the CLI and GUI.
- **Signing:** unsigned builds trigger SmartScreen (Windows) and Gatekeeper (macOS) warnings. The
  pipeline is built so signing/notarization can be enabled with repository secrets; until the owner
  supplies certificates, releases ship unsigned and the README says how to proceed past the warning.

## Approaches considered

UI approach (chosen by the owner: **B, native desktop**):

- A. Local web UI on `127.0.0.1` — one codebase, light, but a browser tab and a local server that
  can delete files needs hardening (token, localhost-only). Not chosen.
- **B. Native desktop (Qt) — chosen.** Native look on all three OSes, richest power view; costs a
  larger optional dependency and a packaging pipeline.
- C. Terminal UI (Textual) — good over SSH, not "visual" for simple users. Possible later extra.

Toolkit (the model's call, owner may override): Qt over Tk because Tk looks dated and is weak for a
data-heavy power view; Qt costs ~100+ MB in installers, acceptable because it is optional for pip.

Distribution (owner chose **both** pip and installers).

Order (model's proposal): Windows support first, then the GUI.

## Decided by the owner

- Windows is in scope; UI is for both simple and power users; native desktop UI; ship via pip and
  standalone installers.

## The model's calls (owner can overrule)

- PySide6 as the toolkit; GUI as an optional `[gui]` extra.
- Two projects, Windows first.
- Simple mode pre-selects only low-risk deletable items; quarantine-on-by-default.
- Non-goal: registry cleaning and "optimizer" features.
- Work happens in a local clone at `D:\Vaulted\workspace\cleanix-cli`; upstream is
  `CloudOpsWorld/cleanix-cli`. Whether to open PRs upstream or publish a fork is the owner's call
  later. Nothing is committed or pushed yet.
- Unsigned installers until the owner provides signing certificates.

## Clarifications from the builder check

Answered by the project or the conversation:

- **Planning scope:** the first plan covers Part 1 (Windows) only. Part 2 (GUI) gets its own plan
  after Part 1 ships. The GUI only depends on Part 1 for the Windows cleaner list.
- **Protected folders:** as today on POSIX (`~/.config` is protected but `~/.config/Code/Cache` is
  deletable), protection means the folder itself, and any ancestor of it, cannot be deleted;
  subpaths can. `AppData\Roaming` is protected as a whole, while Electron caches beneath it remain
  deletable. No allowlist override is needed.

The model's calls:

- **Elevated helper trust boundary:** the helper never trusts caller-supplied paths. The GUI passes
  only item identifiers (cleaner id + item key) in a JSON file written to a user-private temp dir;
  the helper re-runs the scan as admin, acts only on items that match the fresh scan, and every
  deletion still goes through `safe_rmtree`/`safe_unlink`. One prompt per clean run. Platform
  mechanisms: UAC re-launch (Windows), `pkexec` falling back to `sudo` (Linux), the macOS
  authorization prompt via `osascript`.
- **Command items (Recycle Bin, DISM, `apt clean`-style):** they are not quarantined, so Undo
  covers path-based items only, and the UI says so. Irreversible and admin-only items are shown in
  their own group and are **unchecked by default in Simple mode**; the user ticks them knowingly.
- **Risk classification:** the cleaner API has `report_only` and `requires_root` but no risk field.
  Add a `safe_default: bool` (or equivalent) on `Cleaner`, defaulting to **False** so any cleaner
  not yet reviewed is never pre-selected in Simple mode. Mark the clearly low-risk cleaners True
  (temp files, thumbnails, rebuildable caches).
- **Targets:** Windows 10/11 x64 first (ARM64 later); macOS arm64 plus x86_64 (universal2 if the
  PySide6 wheels allow, otherwise two builds); Linux x86_64 AppImage.
- **Windows scheduler:** a per-user scheduled task (no SYSTEM account, standard run level) that
  runs the same read-only `scan --json` the other backends run, writing `last-scan.json` and
  raising a notification. It never deletes.
- **Versioning:** Part 1 targets 1.3.0, Part 2 targets 1.4.0, each on its own feature branch.

## Left to the builder

Visual design and layout details; Inno Setup vs NSIS; exact Windows cleaner list ordering and
which are report-only vs deletable (default to report-only when unsure); naming of modules and
classes; Task Scheduler implementation (`schtasks` vs PowerShell); test strategy for Windows paths
on non-Windows CI (path-model tests) alongside real `windows-latest` runs.
