# Actionable findings, a Findings tab and a Registry tab — design

Status: draft for approval. Builds on `2026-11-19-curated-listings-and-orphans-design.md` (A curated listings, B registry cleanup, C orphan reports, all shipped in 1.4.0b3).

## Intent and why

Today every "finding" (big files, duplicates, downloads, orphaned app data, unowned system files, stale launch jobs/units, leftover install receipts) is report-only: Cleanix lists it, prints a manual hint, and never acts. On a real Mac (first run of the macOS detectors) the list is long, flat and un-actionable: the user must copy `sudo pkgutil --forget …` hints by hand. The user wants to act on findings directly: per scenario from the CLI, interactively one item at a time, and by ticking single items or whole categories in the GUI. Windows registry entries should live on their own tab.

## Goals

- **Scenario = an existing finding detector** (`big_files`, `duplicates`, `downloads`, `orphan_*`, `stale_*`, and so on). A scenario can be acted on as a whole, by category, or item by item.
- **Everything deletable, including system-wide findings** (the user's decision), through the existing elevated helper with new allowlisted actions. Each detector declares a *remedy*: what "delete" means for its items (remove path, forget package receipt, unload and remove a launch job, disable and remove a systemd unit). Items with no safe remedy (e.g. "could not read", "not checked" notes) stay report-only and say why.
- **CLI, non-interactive:** `cleanix clean --act-on <scenario[,scenario…]|category>`, previewing by default and acting with `--execute`, like `clean` today.
- **CLI, interactive:** `cleanix review [scenario…]`: findings by category, one prompt per item (delete / skip / delete all remaining in this group / skip group / quit).
- **GUI (Power mode):** three tabs: *Cleanup* (today's safe items), *Findings* (the report-only items, grouped by category, tick per file and per category tri-state), *Registry* (Windows only; the five `win_reg_*` detectors, moved out of Cleanup).
- Findings are listed **by category** everywhere (CLI report, review, GUI).

## Non-goals / anti-goals

- GUI in the base package: the user decided to keep PySide6 as the optional `[gui]` extra. Only wrong hints are fixed (the standalone binary must not tell users to `pip install` the extra).
- No installers, no registry Undo (still gated by `regpromises.UNDO_SHIPPED`), no Simple-mode changes: Simple never scans or touches findings.
- No "act on everything" default: nothing is preselected anywhere, no scheduled/profile run acts on findings, and the CLI never accepts a blanket "all scenarios" word.
- A scripted run that deletes a wrong file because evidence changed between scan and delete is a failure even if it technically worked; see safeguards.

## Safeguards (kept because deletion scope is "everything")

1. **Dry run by default; explicit naming.** `--act-on` needs scenario ids or category names; acting needs `--execute`; non-interactive acting also needs `--yes` (otherwise it prompts). System-wide scenarios additionally need an elevated run or the existing elevation flow and a typed confirmation unless `--yes`.
2. **Re-verify at delete time.** Each remedy re-runs the detector's own evidence check for that item (still unowned by any package, program still missing, app still not installed, target fingerprint unchanged). Failing or unknown evidence skips the item. Fail closed.
3. **Existing deletion guard stays authoritative** (`safety.py`, never-delete roots); the helper allowlist gains only the new remedy actions, each validated lexically before any filesystem access, with the same audit rigor as the registry action.
4. **Backup before removal, Undo only where true.** Paths go to the quarantine; plists, units and receipts are copied (with metadata) before removal. Undo claims are shown only for remedies that restore verifiably; others say "permanent".
5. **Duplicates never remove the last copy.** `--keep oldest|newest|shortest-path` (default none: must be chosen); interactively and in the GUI the user picks which copy stays.
6. **Honest copy.** Hints keep their "how to verify" text; the confirmation shows what will happen per remedy and whether it is undoable.
7. **Beta until verified** on a real Linux and a real Mac (and the elevated paths on real Windows for the registry tab).

## Constraints

Python 3.8+ (floor lowered in 1.4.0b3); no new dependencies; existing hermetic test approach (fake trees, no real registry or system writes); GUI tests offscreen with isolated QSettings; CLI contract of existing commands unchanged; commit trailer as configured.

## Approaches considered

1. **Everything deletable, including system-wide in bulk (chosen by the user).** Most capable, highest risk; mitigated by safeguards above.
2. Tiered: user-space bulk, system-wide one at a time. Offered, not chosen.
3. User-space only. Offered, not chosen.

Implementation shape: a `Remedy` layer next to the report detectors (data on each finding: remedy kind plus the evidence needed to re-verify); a generic executor used by CLI, review and GUI; helper actions added per remedy kind.

## Calls made while writing this (builder-check answers; change any you disagree with)

1. **Where re-verification runs.** In whichever process deletes. For system-wide items that is the root helper, using the existing re-scan-as-admin pattern from the registry action: the helper re-runs the relevant detector itself and only acts on an item its own scan reports (matched by key/path and fingerprint). It never trusts the caller's claim that evidence still holds. The helper allowlist grows one action per remedy kind, each validated lexically before any filesystem access.
2. **Big files, duplicates, downloads.** User-confirmed deletes that go to the quarantine by default (Undo works), with a visible "space is freed when the quarantine is purged" note; `--permanent` frees space immediately and is labelled permanent. Root-owned paths use a root-owned quarantine area that only the helper writes and purges.
3. **Scan-to-act staleness.** `--act-on` re-scans in the same process and acts immediately; there are no saved reports. A path item's fingerprint is `lstat` size + mtime_ns + inode (+ device), stored per item and re-checked before the delete.
4. **Duplicates.** The model is group-aware. The executor re-stats the surviving copy at delete time and fails closed if it is missing, unreadable or changed. In the GUI, ticking a duplicate category ticks every copy except one survivor per group (default: oldest, shown and changeable); a group can never be fully ticked.
5. **Undo.** Paths: Undo via quarantine. Launch-job plists, systemd units and package receipts: copied before removal but presented as permanent (no restore is built; the copy is for manual recovery). Same honesty rule as `regpromises`.
6. **Typed confirmation.** One confirmation per batch of system-wide items (not per item), listing them; interactive runs require typing `DELETE SYSTEM FILES`; non-interactive runs need `--yes` and an elevated process.
7. **Platforms.** `big_files`, `duplicates`, `downloads` and user-space leftovers work on all three OSes. `orphan_*` / `stale_*` system-wide detectors are Linux/macOS only; on Windows the Findings tab shows only user-space scenarios and the Registry tab holds the registry detectors.

## Left to the builder

Category taxonomy and names (proposal: *Your files*, *Leftovers of removed apps*, *System files no package owns*, *Services and background jobs*, *Install records*); exact prompt wording; per-detector remedy table; how the Findings tab shows system-wide items needing admin (reuse existing "Needs admin" badge and elevation flow); whether `review` accepts `--category`.

## Risks

- System-wide deletions can break a machine: hence re-verify, backups, typed confirmation, beta label, adversarial review of every new helper action before release.
- macOS and elevated paths are unverified on real systems: verification checklist like `docs/registry-cleanup-verification.md`.
- Large result sets in the GUI: lazy children and the existing grouped tree.
