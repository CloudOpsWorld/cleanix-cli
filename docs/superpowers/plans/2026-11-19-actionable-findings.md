# Actionable findings, Findings tab and Registry tab — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users act on report-only findings (CLI scenario flag, interactive review, GUI Findings tab) including system-wide ones via the elevated helper, and move Windows registry entries to their own GUI tab.

**Architecture:** A `Remedy` (what "delete" means + evidence fingerprint) is attached to finding items by their detectors. A new executor (`cleanix/core/actions.py`) re-verifies and applies remedies; `Engine.clean` keeps refusing report-only items so every existing flow is unchanged. System-wide remedies run in the elevated helper through a new request type that re-scans and only acts on items its own scan reports (same pattern as the registry action). CLI and GUI are thin layers over the executor.

**Tech Stack:** Python 3.8+ (no `X | Y` runtime unions, no 3.9+ APIs; use `from __future__ import annotations`), rich, PyYAML, optional PySide6, pytest/pytest-qt.

**Spec:** `docs/superpowers/specs/2026-11-19-actionable-findings-design.md` (the "Calls made" section is binding). Read it and `2026-11-19-curated-listings-and-orphans-design.md` first.

## Global Constraints

- Python floor 3.8; no new dependencies; hermetic tests (fake trees, injected backends, no real registry/system writes, GUI offscreen with isolated QSettings).
- `Engine.clean` continues to refuse `report_only` items; `cleanable_items()` never includes findings; existing `clean` behaviour and output unchanged unless `--act-on` is given.
- Nothing is preselected anywhere; Simple mode, profiles and the scheduler never scan for or act on findings.
- CLI never accepts a blanket "all scenarios" word; `--act-on` takes scenario ids and finding category names. Dry run by default; `--execute` acts; non-interactive acting needs `--yes`.
- System-wide items: elevated process required, one typed confirmation per batch (`DELETE SYSTEM FILES`), helper validates lexically before any filesystem access and re-scans itself.
- Every remedy re-verifies at delete time and fails closed (unknown evidence = skip). Duplicates never remove the last copy.
- Undo claims only where true: file/dir paths via quarantine; launch jobs, systemd units and package receipts are copied before removal but presented as permanent. Registry Undo stays gated by `regpromises.UNDO_SHIPPED`.
- Existing deletion guard (`cleanix/core/safety.py`) stays authoritative; new helper actions need the audit rigor of the registry action.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.

## Review Focus

- A finding changes between scan and act (file replaced by symlink, package now owns it, app reinstalled): must be skipped, never deleted.
- Duplicate group where survivors vanish, are unreadable, or the user ticked every copy: nothing deleted.
- `--act-on` with an unknown scenario, an empty value, or a scenario that is not a finding: refused with a clear message, exit non-zero.
- Hostile/odd filenames (newlines, `..`, symlinks out of tree, non-UTF-8) reaching the helper request: refused lexically.
- Running without elevation, or helper refusing mid-batch: user-space items still processed, system items reported as not done, summary honest.
- GUI: ticking a category with collapsed/hidden items must act on exactly the ticked set (never unseen items), and must disable system items without elevation.

## File Structure

- Create `cleanix/core/remedy.py` — `RemedyKind`, `Remedy`, fingerprinting, re-verify helpers.
- Create `cleanix/core/actions.py` — executor: plan, confirm, apply, summary.
- Create `cleanix/core/findings.py` — finding categories, grouping, `plan_duplicates`.
- Modify `cleanix/core/models.py` (item `remedy`), `curation.py` (copy for categories), detectors listed per task, `service.py`, `cli.py`, `elevate.py`/`elevated.py` (request type), `report.py`, `completion.py`, GUI (`grouped_results.py`, `power_view.py`, `main_window.py`, new `findings_view.py`, `registry_view.py`), README/docs.
- Tests mirror each module under `tests/`.

---

### Task 1: Remedy model

**Files:** Create `cleanix/core/remedy.py`; modify `cleanix/core/models.py`; Test `tests/test_remedy.py`.

**Interfaces:**
- Produces: `class RemedyKind(str, Enum)`: `PATH`, `LAUNCH_JOB`, `SYSTEMD_UNIT`, `PKG_RECEIPT`. `@dataclass(frozen=True) class Remedy: kind: RemedyKind; fingerprint: Tuple[int, int, int, int]` (size, mtime_ns, inode, dev; zeros allowed for non-path kinds) `; group: Optional[str] = None` (duplicate group id) `; extra: Tuple[Tuple[str, str], ...] = ()`. `CleanableItem.remedy: Optional[Remedy] = None` (only valid with `report_only=True`; `__post_init__` raises otherwise). `fingerprint_of(path: str) -> Optional[Tuple[int,int,int,int]]` (lstat; None when missing). `unchanged(item: CleanableItem) -> bool` (re-lstat, no symlink-following, equal to stored fingerprint).
- [ ] Step 1: Tests: `test_remedy_requires_report_only`, `test_fingerprint_changes_on_edit`, `test_unchanged_false_when_replaced_by_symlink`, `test_unchanged_false_when_missing`, `test_item_key_unchanged_by_remedy`.
- [ ] Step 2: Implement; keep `item_key` unchanged. Run `pytest tests/test_remedy.py`; expect pass. Commit.

### Task 2: Finding categories and grouping

**Files:** Create `cleanix/core/findings.py`; modify `cleanix/core/curation.py`; Test `tests/test_findings.py`.

**Interfaces:**
- Produces: `FINDING_CATEGORIES: Dict[str, str]` mapping every report-only cleaner id to one of: `"Your files"`, `"Leftovers of removed apps"`, `"System files no package owns"`, `"Services and background jobs"`, `"Install records"`. `category_of(cleaner_id: str) -> str`. `@dataclass class FindingGroup: category: str; cleaner_id: str; title: str; items: List[CleanableItem]` and `group_findings(scan: ScanResult) -> List[FindingGroup]` ordered by category then size desc. `is_finding(item) -> bool` (report_only and remedy is not None). Items without a remedy are included with `actionable=False` semantics via `is_finding`.
- [ ] Step 1: Tests: `test_every_report_only_cleaner_has_category` (iterate the registry; fail with the missing id), `test_group_findings_orders_by_category`, `test_items_without_remedy_not_findings`.
- [ ] Step 2: Implement; commit.

### Task 3: User-space detectors attach remedies

**Files:** Modify `cleanix/cleaners/big_files.py`, `downloads.py`, `duplicates.py`, `orphan_app_data.py` (user-space branch), `stale_launchers.py`/`stale_services.py`/`orphan_launch_jobs.py` (user-level items only: `requires_root` False); Test `tests/test_finding_remedies_user.py`.

**Interfaces:** each such item gets `remedy=Remedy(kind=..., fingerprint=fingerprint_of(path))`; duplicates set `group=<stable id of the hash group>` and every copy is its own item. User launch jobs → `LAUNCH_JOB`, user systemd units → `SYSTEMD_UNIT`, files/dirs → `PATH`.
- [ ] Step 1: Tests per detector against fake trees: `test_big_files_items_have_path_remedy`, `test_duplicates_share_group_id`, `test_orphan_app_data_user_item_has_remedy`, `test_user_launch_job_remedy_kind`, `test_notes_have_no_remedy` (notes/"could not read" stay unremediated).
- [ ] Step 2: Implement (keep `report_only=True`, hints unchanged). Existing detector tests must still pass. Commit.

### Task 4: Executor for PATH remedies and duplicates

**Files:** Create `cleanix/core/actions.py`; modify `cleanix/core/findings.py`; Test `tests/test_actions_paths.py`.

**Interfaces:**
- Produces: `@dataclass class ActPlan: items: List[CleanableItem]; skipped: List[Tuple[CleanableItem, str]]` and `plan_duplicates(items, keep: str) -> ActPlan` where `keep in {"oldest","newest","shortest-path"}`; a group with fewer than two surviving copies, or whose survivor fails `unchanged`, yields all of its items in `skipped`. `act(items, config, *, dry_run=True, permanent=False, progress=None, cancel=None, record_history=True) -> service.CleanSummary` (reuse the summary type). For `PATH`: `unchanged(item)` else skip "changed since scan"; the existing deletion guard else skip "blocked"; quarantine move unless `permanent`; history record with mode `quarantine`/`delete`.
- [ ] Step 1: Tests: `test_act_quarantines_and_undo_restores`, `test_act_permanent_deletes`, `test_act_skips_changed_file`, `test_act_skips_symlink_swap`, `test_act_refuses_guard_blocked_path`, `test_duplicates_keep_oldest`, `test_duplicates_never_remove_all_copies`, `test_duplicates_survivor_missing_fails_closed`, `test_dry_run_touches_nothing`.
- [ ] Step 2: Implement; commit.

### Task 5: CLI `clean --act-on`

**Files:** Modify `cleanix/cli.py`, `cleanix/core/report.py`, `cleanix/completion.py`; Test `tests/test_cli_act_on.py`.

**Interfaces:** `cleanix clean --act-on IDS_OR_CATEGORIES [--keep oldest|newest|shortest-path] [--permanent] [--execute] [--yes]`. Scenarios resolved against report-only cleaner ids and `FINDING_CATEGORIES` names; unknown/empty → error exit 2 (existing convention). Scans only those cleaners (same path as `--only`); renders findings grouped by category with what-will-happen and undo line; without `--execute` prints preview; with `--execute` and no `--yes` prompts once. Duplicates scenario requires `--keep` or errors. System-wide items (requires_root) are listed as "needs elevated run" and skipped here (Task 9 enables them). `report.safe()` escaping applies to all new text.
- [ ] Step 1: Tests: `test_act_on_unknown_scenario_exits_2`, `test_act_on_preview_by_default`, `test_act_on_execute_requires_yes_noninteractive`, `test_act_on_duplicates_requires_keep`, `test_act_on_category_name`, `test_findings_rendered_by_category`, `test_default_clean_still_ignores_findings`.
- [ ] Step 2: Implement; update shell completion. Commit.

### Task 6: CLI `review` (interactive)

**Files:** Modify `cleanix/cli.py`; create `cleanix/core/review.py`; Test `tests/test_cli_review.py`.

**Interfaces:** `cleanix review [IDS_OR_CATEGORIES…] [--keep …] [--permanent]`; refuses when stdin is not a TTY. `review.run(groups, ask: Callable[[str], str], act, console)` loops category → group → item; choices `d` delete, `s` skip, `g` delete all remaining in this group, `n` skip rest of group, `q` quit; each prompt shows title, path, size, safety/undo line, hint. Duplicates show the survivor and prompt per extra copy. Ctrl-C/EOF exits cleanly with a summary.
- [ ] Step 1: Tests with scripted `ask`: `test_review_delete_and_skip`, `test_review_delete_rest_of_group`, `test_review_quit_stops`, `test_review_eof_is_clean_exit`, `test_review_refuses_non_tty`, `test_review_duplicate_never_offers_last_copy`.
- [ ] Step 2: Implement; commit.

### Task 7: User-level non-path remedies

**Files:** Modify `cleanix/core/actions.py`, create `cleanix/core/remedy_exec.py`; Test `tests/test_remedy_exec.py`.

**Interfaces:** `LAUNCH_JOB` (user agent): copy plist into the run directory (`<run>/files/…`, metadata preserved), run allowlisted `launchctl bootout gui/<uid> <label-or-path>` best effort, remove plist. `SYSTEMD_UNIT` (user): copy unit, `systemctl --user disable --now <unit>` best effort, remove file, `daemon-reload`. All commands built from validated components (label/unit regex, no leading `-`), run through an injectable runner so tests never execute them. Result copy says "permanent (a copy is kept in <dir>)".
- [ ] Step 1: Tests: `test_launch_job_backup_then_remove`, `test_unit_name_validation_rejects_option_like`, `test_remedy_reverifies_before_removing`, `test_runner_failure_does_not_block_file_removal_but_is_reported`.
- [ ] Step 2: Implement; commit.

### Task 8: Elevated request for findings

**Files:** Modify `cleanix/core/elevate.py`, `cleanix/elevated.py`, `cleanix/core/elevate_launch.py`; Test `tests/test_elevated_findings.py`.

**Interfaces:** New request type `FindingsRequest` next to `RegistryRequest`: carries scenario ids, item keys with fingerprints, `permanent`, invoking-user quarantine root. Helper (`_prepare_findings`, `_execute_findings`): lexical validation of every field before any filesystem access; `admin_finding_ids()` allowlist (separate from `admin_cleaner_ids()` and `admin_registry_cleaner_ids()`); helper re-runs the named detectors itself and acts only on items whose `item_key` and fingerprint match its own scan; root quarantine under a helper-owned directory; refuses anything outside its allowlisted remedy kinds. Helper writes nothing under the user's home.
- [ ] Step 1: Tests (fake request dirs, no real root): `test_findings_request_rejects_unknown_scenario`, `test_helper_ignores_item_not_in_own_scan`, `test_helper_rejects_hostile_paths`, `test_helper_skips_changed_fingerprint`, `test_allowlists_are_separate`, `test_helper_never_touches_user_home`.
- [ ] Step 2: Implement; commit.

### Task 9: System-wide remedies

**Files:** Modify detectors `orphan_files.py`, `stale_launchers.py`, `stale_services.py`, `orphan_launch_jobs.py`, `stale_receipts.py`, `orphan_app_data.py` (system branch), `orphan_common.py`, `cleanix/core/remedy_exec.py`; Test `tests/test_system_remedies.py`.

**Interfaces:** system items get remedies (`PATH`, `LAUNCH_JOB` with `launchctl bootout system`, `SYSTEMD_UNIT` with `systemctl disable --now`, `PKG_RECEIPT` with `pkgutil --forget <id>`). Mutating argv shapes are a **separate allowlist** (`MUTATING_COMMANDS`) usable only by the helper's remedy executor, never by `orphan_common.run` (which stays read-only). Re-verification for `orphan_files` re-runs the package-ownership query for that exact path inside the helper and skips unless it is positively unowned. Every removal copies the original (plist/unit/receipt metadata) into the root quarantine first.
- [ ] Step 1: Tests: `test_unowned_file_skipped_when_now_owned`, `test_receipt_forget_argv_exact`, `test_mutating_allowlist_not_reachable_from_read_only_run`, `test_system_unit_backup_before_remove`, `test_reverify_unknown_is_skip`.
- [ ] Step 2: Implement; commit.

### Task 10: CLI elevation and typed confirmation

**Files:** Modify `cleanix/cli.py`, `cleanix/core/actions.py`; Test `tests/test_cli_system_findings.py`.

**Interfaces:** `--act-on` / `review` include system items when the process is elevated (or via the existing elevation launcher); one batch confirmation listing them, typed `DELETE SYSTEM FILES` interactively; non-interactive needs `--yes` plus an elevated process, otherwise system items are reported "not done: needs elevation" and user-space items still proceed. Summary distinguishes done / skipped / refused.
- [ ] Step 1: Tests: `test_system_items_skipped_without_elevation`, `test_typed_confirmation_wrong_text_aborts`, `test_yes_without_elevation_skips_system_but_runs_user`, `test_summary_lists_not_done`.
- [ ] Step 2: Implement; commit.

### Task 11: GUI Findings model and tree

**Files:** Create `cleanix/gui/findings_view.py`; modify `cleanix/gui/grouped_results.py`, `cleanix/gui/models.py`; Test `tests/gui/test_findings_view.py`.

**Interfaces:** `FindingsView(QWidget)` shows `group_findings()` as category → scenario → items; tri-state category/scenario ticks; per-file tick; bulk ticks only select items that are actionable and already realised (never unseen collapsed items); system items disabled without elevation and badged "Needs admin"; duplicate scenario ticking leaves one survivor per group (default oldest, changeable through a context action), a group can never be fully ticked; footer shows selected count/size and the undo-or-permanent line; signal `actRequested(items: list, permanent: bool)`.
- [ ] Step 1: Tests (offscreen): `test_category_tick_selects_all_actionable_visible`, `test_collapsed_items_not_selected_by_bulk`, `test_duplicates_leave_one_survivor`, `test_system_items_disabled_without_elevation`, `test_nothing_preselected`.
- [ ] Step 2: Implement; commit.

### Task 12: GUI tabs and Registry tab

**Files:** Create `cleanix/gui/registry_view.py`; modify `cleanix/gui/power_view.py`, `cleanix/gui/main_window.py`, `cleanix/gui/workers.py`; Test `tests/gui/test_tabs.py`.

**Interfaces:** Power mode gets `Cleanup | Findings | Registry` tabs (Registry only on Windows). `win_reg_*` results are removed from the Cleanup tree and shown in `RegistryView` grouped by detector with the existing backup/permanent copy; act flow uses `service.act`/the helper request; Findings tab runs scans for report-only scenarios (opt-in "Scan for findings" button; slow scenarios behind the existing Deep scan wording); Undo button reuses quarantine runs. Simple mode unchanged.
- [ ] Step 1: Tests: `test_registry_items_not_in_cleanup_tab`, `test_registry_tab_only_on_windows`, `test_findings_tab_scan_button_does_not_autostart`, `test_simple_mode_has_no_findings`.
- [ ] Step 2: Implement; commit.

### Task 13: Hints, docs and release prep

**Files:** Modify `cleanix/cli.py` (gui command), `README.md`, `docs/`, `RELEASING.md`, `pyproject.toml`, `cleanix/__init__.py`; create `docs/findings-verification.md`; Test `tests/test_gui_cmd_hint.py`.

**Interfaces:** in a frozen (PyInstaller) build `cleanix gui` without PySide6 says the standalone binary does not include the GUI and to install with pip (`--pre --no-compile` note for macOS system Python 3.9 optional); README documents `--act-on`, `review`, tabs, safeguards, system-wide caveats; verification checklist for real Linux/macOS/Windows; version `1.4.0b4`.
- [ ] Step 1: Tests: `test_gui_hint_in_frozen_build` (monkeypatch `sys.frozen`).
- [ ] Step 2: Implement; run the full suite on 3.13 and on a 3.8 interpreter; commit.

### Task 14: Whole-branch adversarial review of helper actions

Not an implementation task: dispatch the most capable reviewer on the helper (`elevated.py`, `elevate.py`, `remedy_exec.py`, mutating allowlist) with the Review Focus list; fix findings in one wave; re-run all test environments (Windows+PySide6, no-GUI, 3.8, WSL/Linux POSIX tests); then open a PR (needs review before merge) — do not push to `main` or release without the user's go-ahead.
