# Curated Listings (Sub-project A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make scan results understandable: one curated row per cleaner (plain title, what-happens line, safety badge, size), top items on expand with the rest collapsed, and the raw list one click away — in both Simple and Power mode.

**Architecture:** A pure-data/policy module `cleanix/core/curation.py` (no I/O, no Qt) turns a `ScanResult` into `Group`s. One reusable Qt widget `GroupedResults` (QTreeWidget) renders groups with tri-state selection. Simple mode's results page and Power mode's Scan tab use it; Power keeps its existing table as the "Raw list" view. Scanning, safety checks, the elevated helper and what gets deleted do not change.

**Tech Stack:** Python 3.10+, PySide6 (existing `gui` extra), pytest/pytest-qt, existing `cleanix.core.catalog`.

**Spec:** `docs/superpowers/specs/2026-11-19-curated-listings-and-orphans-design.md` (section A). Parent design: `2026-11-16-windows-and-gui-design.md`.

## Global Constraints

- Python 3.10+; no new dependencies; PySide6 stays optional (`cleanix.core.*` must import without Qt).
- Safety levels exactly: `Safe`, `Review`, `Needs admin`, `Permanent`. Derived from existing facts, wording only from the table. Precedence: `report_only` -> Review; `requires_root` -> Needs admin; `ItemKind.COMMAND` -> Permanent; else `info.safe_default` -> Safe, otherwise Review.
- Default: top 15 items per group by size; zero-size items hidden by default; nothing hidden permanently (raw list shows all).
- Existing rules unchanged: `catalog.preselect` decides Simple pre-selection; items the elevated helper would refuse (`elevation.admin_problems`) are not selectable; undo is only promised for PATH items cleaned as the user; admin/COMMAND items are described as permanent.
- Tests hermetic: `QT_QPA_PLATFORM=offscreen`, isolated QSettings (existing autouse fixture), never create `HKCU\Software\Cleanix`, never run a real clean/elevation.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Do not push or merge.
- Test command (from repo root): `QT_QPA_PLATFORM=offscreen PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider <paths>`; without PySide6 the GUI tests must skip cleanly (full suite also run in a venv without PySide6).

## Review Focus

1. Scan returning nothing / only zero-size items: friendly empty state, no crash, no empty groups.
2. Thousands of items (e.g. 440 temp files, 10k+ in a cache): UI builds children lazily or in bulk and stays responsive; collapsed rows never create per-item widgets.
3. Selection arithmetic: ticking a group selects collapsed and hidden-zero items; the Clean button size and item count equal what will actually be cleaned; admin-refused items are never counted.
4. Path display on Windows and POSIX: home shortening only on a real path-component boundary (`C:\Users\bob2` is not under `C:\Users\bob`), case-insensitive on Windows, UNC/odd names untouched, full path always in the tooltip.
5. A cleaner id with no copy-table entry (third-party/new) renders via its own name/description, never raises.
6. After a partial clean or Undo the tree refreshes from the new scan state without stale ticks.

---

### Task 1: Curation core (pure logic)

**Files:**
- Create: `cleanix/core/curation.py`
- Modify: `cleanix/core/catalog.py` (add category `"backups": "Backups & leftovers"` to `CATEGORIES` and assign every currently-`"other"` cleaner id that is a tool-leftover/backup cleaner to it; leave `_NEVER_PRESELECT` containing it)
- Test: `tests/test_curation.py`

**Interfaces:**
- Consumes: `catalog.CleanerInfo`, `catalog.category_of`, `catalog.list_cleaners`, `models.ScanResult/CleanableItem/ItemKind`, `utils.human_size`.
- Produces (exact):
  - `class Safety(str, Enum)`: `SAFE="Safe"`, `REVIEW="Review"`, `ADMIN="Needs admin"`, `PERMANENT="Permanent"`.
  - `@dataclass(frozen=True) class Copy: title: str; blurb: str`.
  - `COPY: Dict[str, Copy]` — an entry for every cleaner id registered on any platform.
  - `copy_for(cleaner_id: str, name: str, description: str) -> Copy` (falls back to `Copy(name, description)`).
  - `safety_of(item: CleanableItem, info: Optional[CleanerInfo]) -> Safety` (precedence in Global Constraints; `info None` -> Review).
  - `shorten_path(path: str, home: Optional[str]) -> str` (replace a leading home dir on a component boundary with `~`; case-insensitive and separator-agnostic for Windows-style paths; otherwise return unchanged).
  - `display_label(item: CleanableItem, home: Optional[str]) -> str` (description with a redundant leading `"<Something>: "` prefix removed when the rest is non-empty; for PATH items whose cleaned description is empty use the shortened path; COMMAND items show the command text).
  - `@dataclass class Group`: `cleaner_id, title, blurb, category, safety, items (all, size desc), shown (top-N, zero-size excluded), rest (remaining non-zero), zero (zero-size items), total_size`; properties `rest_size`, `item_count`.
  - `build_groups(result: ScanResult, infos: Mapping[str, CleanerInfo], *, top_n: int = 15, show_empty: bool = False) -> List[Group]` — one group per cleaner report with items; groups whose items are all zero-size are omitted unless `show_empty`; groups sorted by `total_size` desc (stable); a group's `safety` is the most restrictive of its items (order Permanent > Needs admin > Review > Safe).

- [ ] **Step 1: Write failing tests** in `tests/test_curation.py`: `test_safety_precedence` (report_only+requires_root -> REVIEW; requires_root -> ADMIN; COMMAND -> PERMANENT; safe_default PATH -> SAFE; non-safe_default -> REVIEW; info None -> REVIEW); `test_shorten_path_boundary` (`C:\Users\bob\AppData\x` with home `C:\Users\bob` -> `~\AppData\x`; `C:\Users\bob2\x` unchanged; `c:\users\BOB\x` shortened; `/home/a/.cache` with `/home/a` -> `~/.cache`; `/home/ab/x` unchanged; home None unchanged); `test_display_label_strips_prefix` (`"Temp: a.tmp"` -> `"a.tmp"`; `"Temp:"` stays); `test_build_groups_topn_and_collapse` (440 items of mixed sizes -> `shown` length 15 sorted desc, `rest` the remainder non-zero, `zero` the zero-size, `total_size` equals sum, nothing lost: `len(shown)+len(rest)+len(zero)==len(items)`); `test_zero_only_group_hidden` (and shown with `show_empty=True`); `test_group_safety_most_restrictive`; `test_unknown_cleaner_falls_back` (no COPY entry -> title is the report name); `test_every_registered_cleaner_has_copy` (iterate `catalog.list_cleaners(Config(), include_unsupported=True)` plus all ids from `registry`; assert each id in `COPY`); `test_no_cleaner_in_other_category` (every registered id has `category_of(id) != "other"`); `test_curation_imports_without_qt` (import in a subprocess with PySide6 import blocked).
- [ ] **Step 2: Run** `pytest tests/test_curation.py` — expect FAIL (module missing).
- [ ] **Step 3: Implement** `curation.py` and the catalog category change. Copy table wording: title <= 40 chars, plain language; blurb one sentence in the form "<what it is>. <what happens if removed>." (e.g. NVIDIA/DirectX shader caches: "Compiled graphics shaders. Rebuilt automatically; the first game launch may be slower."). Write entries for all cleaner ids (enumerate with `registry`). Report-only/Review ids must say the user decides and that Cleanix will not delete it.
- [ ] **Step 4: Run** `pytest tests/test_curation.py tests/test_catalog.py` — expect PASS.
- [ ] **Step 5: Commit** `feat(core): curation layer - plain copy, safety levels, grouping`.

---

### Task 2: GroupedResults widget

**Files:**
- Create: `cleanix/gui/grouped_results.py`
- Test: `tests/gui/test_grouped_results.py`

**Interfaces:**
- Consumes: `curation.Group/Safety/display_label/shorten_path`, `models.item_key`, `elevation.admin_problems`, `utils.human_size`, `reveal` (Open location).
- Produces (exact): `class GroupedResults(QTreeWidget)` with
  - `__init__(self, parent=None, *, allow_admin_items: bool = False, admin_reason: str = "", home: Optional[str] = None)`
  - `set_groups(groups: List[Group], preselect: Callable[[CleanableItem], bool]) -> None` (rebuilds; children created only when a group is first expanded; `rest` shown as one selectable row `"N smaller items · X MB"`; a `Show all` action on that row expands it into its items)
  - `set_raw_items_visible(on: bool)` (also includes `zero` items as rows)
  - `checked_items() -> List[CleanableItem]` (includes collapsed `rest` and `zero` items of a ticked group; excludes report_only and admin-refused items)
  - `checked_size() -> int`
  - `set_checked_keys(keys: Iterable[str])`, `checked_keys() -> Set[str]` (item_key based)
  - signal `selection_changed = Signal()`
  - column layout: tick+title, description, safety badge, count, size; group tick is tri-state; report_only/admin-refused groups have no tick and show the reason as description.
  - `copy_path(item)` / `open_location(item)` via context menu; full path in tooltip.

- [ ] **Step 1: Write failing tests** (pytest-qt, offscreen): `test_groups_sorted_and_badged`; `test_group_tick_selects_collapsed_and_zero_items` (checked_items length equals group item_count, checked_size equals total_size); `test_untick_child_makes_group_partial`; `test_report_only_group_has_no_tick`; `test_admin_refused_item_not_selectable` (with `allow_admin_items=False` and True + refused problem); `test_children_lazy` (collapsed group creates no child items; expanding 5000 items completes under 2 s); `test_rest_row_show_all`; `test_set_checked_keys_roundtrip`; `test_tooltip_has_full_path_and_label_uses_tilde`; `test_empty_groups_shows_nothing_without_error`.
- [ ] **Step 2: Run** the file — expect FAIL.
- [ ] **Step 3: Implement** the widget with `QTreeWidget` + `QTreeWidgetItem` (tri-state via `ItemIsAutoTristate` or manual), accessible names on the tree and badge text (not colour alone). Selection state lives in a `Set[str]` of item keys, not in widgets.
- [ ] **Step 4: Run** the file — expect PASS.
- [ ] **Step 5: Commit** `feat(gui): GroupedResults tree widget`.

---

### Task 3: Simple mode results + idle redesign

**Files:**
- Modify: `cleanix/gui/simple_view.py`
- Modify tests: `tests/gui/test_simple_view*.py` (rewrite card-structure assertions to the new structure; keep every behavioural assertion: pre-selection, admin gating, confirm text, undo messaging, cancel/failed states)

**Interfaces:**
- Consumes: `curation.build_groups`, `GroupedResults`, `catalog.preselect`, existing `SimpleView` signals/state machine (unchanged: `request_clean`, `scanned`, `clean_finished`, `undone`, `SimpleState`).
- Produces: `SimpleView.results_tree: GroupedResults`; `SimpleView.selected_items()` and `selected_size()` keep their signatures; `clean_button_text()` -> `"Clean <size>"`/`"Nothing selected"`; `results_total_label` showing `"<size> can be freed"`; a separate section "Needs your review" (collapsed, nothing ticked) for Review-safety groups; idle page with headline, one-sentence reassurance ("Nothing is deleted until you review it. Most cleanups can be undone."), prominent Scan button, and a "Deep scan (slower: duplicates, big files)" checkbox (`SimpleView.deep_scan_check`) whose state is passed to the scan worker factory as `deep: bool`.

- [ ] **Step 1: Write failing tests** for: total label text; Review groups in their own section and unticked; only preselected (Safe, user-owned PATH) groups ticked; `selected_items()` equals ticked groups' items; Clean button text uses curated total; deep checkbox default off and forwarded to the factory (`scan_worker_factory(config, deep=...)`); admin groups non-selectable when `allow_admin_items=False` with the reason shown; empty result shows "Nothing found to clean."
- [ ] **Step 2: Run** `tests/gui/test_simple_view*.py` — expect FAIL.
- [ ] **Step 3: Implement.** Replace `CategoryCard` usage with `GroupedResults`; keep `ConfirmCleanDialog` and its undo/permanent wording; compute groups with `build_groups(result, infos)`.
- [ ] **Step 4: Run** simple-view tests and `tests/gui` — expect PASS.
- [ ] **Step 5: Commit** `feat(gui): curated Simple mode results and idle screen`.

---

### Task 4: Fast default scan + visible mode switch

**Files:**
- Modify: `cleanix/gui/workers.py` (ScanWorker accepts `exclude: Optional[List[str]]` and forwards to `service.scan`), `cleanix/gui/main_window.py` (segmented Simple | Power control replacing the toolbar text action; same persistence and accessibility names), `cleanix/core/catalog.py` (add `SLOW_SCAN_IDS = ("duplicates", "big_files", "downloads")`)
- Tests: `tests/gui/test_workers.py` (extend), `tests/gui/test_main_window.py` (extend)

**Interfaces:**
- Produces: `workers.ScanWorker(config, only=None, exclude=None)`; `catalog.SLOW_SCAN_IDS`; `SimpleView` (Task 3) builds its default factory as `lambda config, deep=False: ScanWorker(config, exclude=None if deep else list(SLOW_SCAN_IDS))` — Task 3 owns the SimpleView side, this task owns the worker param and constant, so Task 3 must read `catalog.SLOW_SCAN_IDS` (add it in this task's commit, merged before Task 3's integration; if absent at Task 3 time, Task 3 defines the call against the documented signature and the integrator wires after merge).
- Mode switch: two exclusive checkable buttons "Simple" and "Power"; `MainWindow.current_mode()`/`set_mode()` unchanged.

- [ ] **Step 1: Write failing tests:** worker forwards `exclude` to `service.scan` (patch `service.scan`); `SLOW_SCAN_IDS` are real registered ids; main window segmented control reflects and changes `current_mode()`, persists via the isolated settings.
- [ ] **Step 2: Run** — expect FAIL. **Step 3: Implement.** **Step 4: Run** `tests/gui/test_workers.py tests/gui/test_main_window.py` — expect PASS.
- [ ] **Step 5: Commit** `feat(gui): fast default scan and visible Simple/Power switch`.

---

### Task 5: Power mode curated tree + Raw list

**Files:**
- Modify: `cleanix/gui/power_view.py`
- Modify tests: `tests/gui/test_power_view*.py` (existing table/filter/export/clean tests must still pass against the Raw list; add the new ones)

**Interfaces:**
- Consumes: `curation.build_groups`, `GroupedResults.set_groups/checked_keys/set_checked_keys/selection_changed`, existing `ItemTableModel` (stays the single source of truth for selection and for what Clean selected acts on).
- Produces: in the Scan tab, a `QStackedWidget` with page 0 `GroupedResults` (default) and page 1 the existing `QTableView` (Raw list); a `Raw list` toggle button (`PowerView.raw_toggle`); the 35-checkbox cleaner column becomes a collapsible "Choose what to scan" section (collapsed after the first scan); quick-select buttons "Safe only" and "Developer" (ids: `catalog` categories `dev` for Developer; Safe = items where `curation.safety_of == SAFE`); safety-level filter combo next to the text filter; a "Show empty" checkbox (passes `show_empty` to `build_groups`); selection is bridged both ways by item key so toggling in either view updates the other; Clean/confirm/dry-run/export/quarantine behaviour unchanged and still acting on `item_model.checked_items()`.

- [ ] **Step 1: Write failing tests:** default page is the tree; toggling Raw list shows the table with identical item count; ticking a group in the tree makes `item_model.checked_items()` equal that group's items and vice-versa; "Safe only" selects exactly Safe, user-owned PATH items; safety filter hides non-matching groups; Clean selected after tree selection calls the clean worker factory with those items (fake worker); dry-run default still on; export JSON unchanged.
- [ ] **Step 2: Run** `tests/gui/test_power_view*.py` — expect FAIL. **Step 3: Implement.** **Step 4: Run** `tests/gui` — expect PASS.
- [ ] **Step 5: Commit** `feat(gui): curated Power mode with raw list toggle`.

---

### Task 6: Integration, docs, verification

**Files:** Modify `README.md` (Graphical interface section: new Simple/Power behaviour, safety badges, Raw list, Deep scan), `docs/superpowers/specs/2026-11-19-curated-listings-and-orphans-design.md` (status line: A implemented); tests as needed.

- [ ] **Step 1:** Merge task branches in order 1, 2, 3, 4, 5; run `tests/gui/test_integration*.py` (main window wiring) and fix wiring gaps (Simple factory `deep`, shared `catalog.SLOW_SCAN_IDS`).
- [ ] **Step 2:** Full suite with PySide6 and in a venv without it; expect 0 failures (skips allowed only for GUI tests without Qt).
- [ ] **Step 3:** Render real-font screenshots on Windows (no `QT_QPA_PLATFORM=offscreen`) of Simple idle, Simple results after a read-only scan, and Power curated + raw; inspect them; fix legibility problems (truncation, contrast of badges in light and dark).
- [ ] **Step 4:** Confirm `HKCU\Software\Cleanix` absent; update README; commit `docs: curated listings`.
