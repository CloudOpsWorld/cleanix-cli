# Curated listings, registry cleanup and system-wide orphan reports — design

Status: sub-project A (curated listings) is implemented on `feat/curated-listings`; B and C remain draft. Builds on `2026-11-16-windows-and-gui-design.md` (branch `feat/gui`).
Delivered as three sub-projects, in this order: **A** curated listings, **B** Windows registry cleanup, **C** Linux/macOS system-wide orphan reports. Each gets its own plan; this document fixes the shape of all three and the detail of A.

## Intent and why

The GUI works but a normal person cannot use it. Simple mode shows only a button; Power mode shows the raw catalog (about 35 cleaners, hundreds of rows such as `1c715cf1-…tmp.js` or `AppCrash_cloud-drive-daem_8a5bf5…`). Users cannot tell what an item is, whether deleting it is safe, or what to do next. The user wants the raw detail kept, but behind a controlled, curated presentation. They also want Windows registry cleanup and, on Linux/macOS, detection of system-wide orphans and leftovers.

## Goals

- A: every listing a user sees answers "what is this, is it safe, how big, what happens if I delete it" without reading a path. Raw detail stays one click away.
- B: Windows users can find and remove provably dead registry entries, with a mandatory backup and working Undo.
- C: Linux and macOS users get read-only reports of system-wide orphaned files and leftovers outside their home directory.

## Non-goals / anti-goals

- No "fix all registry problems" button, no registry "optimisation", no defragmenting, no speed claims. A registry cleaner that breaks an app is a failure even if it technically works.
- C never deletes in its first version (report-only, like `big_files`).
- A changes presentation only: no change to scanning, safety checks, the elevated helper, or what gets deleted.
- No new dependencies. Not a redesign of Power mode's other tabs (Quarantine, History, Schedule, Settings, Findings).

## Approaches considered

1. **Curated groups with progressive disclosure (chosen).** Human metadata layer over the existing catalog; groups -> top items -> raw list. Same grouped list drives Simple and Power. Trade-off: needs a copy table that must be maintained when cleaners are added.
2. Guided wizard (Scan -> Review -> Confirm -> Done). Clear for beginners, slow for experts, replaces the layout. Rejected as the primary fix.
3. Presets only (Quick/Deep/Developer). Cheap but does not explain items. Kept only as a small Power-mode quick-select.

For B/C the alternative of one generic "leftovers" engine was rejected: registry and filesystem orphans have different evidence rules and different risk.

## A. Curated listings

**Data.** A pure-data module (no I/O, like `catalog.py`) maps each cleaner id to: friendly title, one-line "what is this / what happens if I delete it", safety level, and a display category. Safety levels: *Safe* (regenerated automatically), *Review* (user judgment), *Needs admin*, *Permanent* (no undo: COMMAND items, admin items). Safety must be derived from existing facts (`requires_root`, `report_only`, item kind, undo availability) wherever those decide it; the table only supplies wording. A cleaner with no table entry falls back to its own `name`/`description`, never an error. Test that every registered cleaner id has an entry.

**Three levels of detail.**
1. *Group row* (one per cleaner): title, description line, total size, safety badge, one tick, item count. Sorted by size descending. Groups with nothing to remove are hidden (a "show empty" toggle in Power mode).
2. *Item rows* on expand: top N (default 15) by size; the rest collapse into one "N smaller items, X MB" row with a Show all link. Zero-size rows hidden by default. Display names are cleaned (strip redundant prefixes such as `Temp:`; shorten the home directory to `~`); full path on hover. Near-identical rows (e.g. 153 WER archives) collapse into one counted row.
3. *Raw list*: a "Show raw list" toggle shows every item unmodified; right-click gives Copy path and Open location (existing `reveal`). Nothing is permanently hidden.

**Selection semantics.** Ticking a group selects all of its items including collapsed ones; unticking likewise. A collapsed "smaller items" row is selectable as a unit. Selected size and the Clean button text count collapsed items. Existing rules stay: nothing the elevated helper would refuse is selectable without elevation; Simple-mode pre-selection still follows `catalog.preselect`.

**Simple mode.** After a scan: a large total ("3.2 GB can be freed"), then group cards (icon, title, description, size, badge, tick), one Clean button, Undo afterwards. "Review" groups (big files, duplicates, browser profiles, etc.) sit in a separate "Needs your review" section, off by default. Idle screen gets a headline, one sentence on what Cleanix touches and that it is undoable, and a prominent Scan button; the Simple/Power switch becomes a visible segmented control. The default Simple scan skips slow report-only cleaners (duplicates, big files, downloads) with a "Deep scan" option to include them.

**Power mode.** Same list as an expandable tree with filters (text, safety level, size), quick-selects ("Safe only", "Developer"), and the raw toggle. Left-hand 35-checkbox column is replaced by this.

**Categories.** Add a "Backups & leftovers" display category so tool-leftover cleaners (e.g. Claude Code backups, now in "Other") are not lumped under Other.

**Left to the builder.** Widget choice (tree view vs. cards), exact N and wording, icons, whether the model is a `QAbstractItemModel` or standard items — subject to existing hermetic offscreen tests and the "undo only where true" messaging.

## B. Windows registry cleanup (outline)

A new Windows-only cleaner family implemented with `winreg`, reported through the same grouped list as category "Registry", safety *Review*, unticked by default.

- **Detects only provably dead entries:** Uninstall entries whose install location and uninstaller are both gone; App Paths and file-association handlers pointing at missing executables; Run/startup entries pointing at missing programs; SharedDLLs counts for missing files. Hives: HKCU and HKLM `Software` only.
- **Never touches:** `HKLM\SYSTEM`, Windows/Microsoft-owned keys, anything requiring a guess, anything whose target is on an unavailable/removable/network drive (unknown is not dead).
- **Backup and undo:** before any delete, export the affected keys to a `.reg` file in the quarantine area; Undo re-imports it. If the backup cannot be written, nothing is deleted.
- **Admin:** HKLM deletions go through the existing elevated helper (new allowlisted action, same re-scan-as-admin pattern); HKCU runs as the user.
- **Left to the builder:** exact detector list within the rules above, key-path allowlists, test strategy (a fake registry layer; tests must never touch the real registry, mirroring the `HKCU\Software\Cleanix` lesson).

## C. Linux/macOS system-wide orphan reports (outline)

Read-only report cleaners (`report_only=True`, category "Review"): Linux — files under `/var/lib`, `/opt`, `/usr/local` owned by no package, stale systemd units and `.desktop` entries pointing at missing binaries, leftover package-manager state; macOS — orphaned LaunchAgents/LaunchDaemons, `Application Support`/`Library` folders of apps no longer installed, stale receipts. Each item carries a `hint` for manual removal. Must work without root (degrading gracefully, noting what needs root) and never follow symlinks out of the scanned tree. Existing leftover cleaners are reused, not duplicated. A later version may add deletion through the helper; out of scope here.

## Constraints

Python 3.10+, existing dependency set; Windows opt-in platform rule; deletion guard in `safety.py` unchanged; elevated-helper allowlist changes need the same audit rigor as before; GUI tests hermetic (offscreen, isolated QSettings, no real registry writes); commit trailer as configured.

## Risks

- Copy table drift: mitigated by the every-cleaner-has-an-entry test and a safe fallback.
- B is the highest-risk piece; hence report-first, backup-mandatory, narrow rules, and A shipping before it.
- C false positives (e.g. files owned by no package but still needed): report-only, with explanatory hints.
