"""Review: findings shown as category -> scenario -> items, ticked by hand.

:class:`ReviewModel` (no Qt) holds what can be ticked and what is ticked;
:class:`ReviewView` draws it as a lazy tree with a footer and an "Act on
selected" button. Rules (all enforced by the model, not just the view):

* Nothing is preselected.
* Only items that are actionable (a report-only finding with a remedy the
  executor handles), currently offerable (system-wide items: offered to the
  administrator helper AND elevation available) and *realised* (their row
  exists in the tree) can be ticked. Bulk ticks (category / scenario /
  duplicate group) realise a small scenario (<= ``REALISE_LIMIT`` items)
  completely and a big one one page at a time; unseen items are never
  ticked.
* Duplicates: one copy per group is kept (default: the oldest, the same rule
  as :func:`findings.plan_duplicates`; "Keep this copy instead" changes it).
  The kept copy can never be ticked, so a group is never fully ticked.

The view never deletes anything and never asks for elevation: it emits
``actRequested(items, permanent, survivors)`` for its owner (Task 12).
Every text that comes from a finding is shown as plain text (tree cells,
plain-text labels) or escaped (tooltips).
"""

from __future__ import annotations

import html
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QHBoxLayout, QHeaderView, QLabel, QMenu,
    QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from cleanix.core import findings, system_findings
from cleanix.core.curation import Safety, display_label, shorten_path
from cleanix.core.findings import FindingGroup
from cleanix.core.models import CleanableItem, ItemKind, ScanResult, _visible, item_target
from cleanix.core.remedy import RemedyKind, link_target
from cleanix.core.utils import human_size
from cleanix.gui import reveal
from cleanix.gui.grouped_results import badge_color

# A scenario with at most this many items is realised completely by a bulk
# tick (and on first expand); a bigger one one page at a time.
REALISE_LIMIT = 200
PAGE = 200

COLUMNS = ["Finding", "Location", "Safety", "What will happen", "Size"]
_ROLE = Qt.ItemDataRole.UserRole
_ACCESSIBLE = Qt.ItemDataRole.AccessibleTextRole

# ---------------------------------------------------------------- wording
NO_ACTION = "Report only: no safe automatic action is known for it."
NOT_HANDLED = "Report only: Cleanix cannot act on this kind of finding."
LINK_NOT_HERE = ("Report only here: this link is only removed with "
                 "administrator rights.")
KEPT = "Kept: this is the copy that stays."
AMBIGUOUS_GROUP = ("Not offered: duplicate group is ambiguous (its id appears in "
                   "more than one place), so no copy of it is acted on.")
NEEDS_ADMIN = "Needs admin"
ADMIN_UNAVAILABLE = "administrator permission is not available here"
NOT_OFFERED = "Not offered"
CAP_ITEMS = ("At most {n} system-wide items fit one administrator run; "
             "the rest were not ticked.")
CAP_SCENARIOS = ("At most {n} system-wide scenarios fit one administrator "
                 "run; the rest were not ticked.")
MORE_NOT_SHOWN = "{title}: {n} more not shown; expand to include them."
EMPTY_BEFORE_SCAN = "Scan for findings to review them here."
EMPTY_SCAN = "No findings to review: the scan found nothing to act on or report."

USER_QUARANTINE = ("kept in quarantine; Undo available (space is freed when the "
                   "quarantine is emptied)")
USER_PERMANENT = "deleted permanently (no Undo)"
JOB_PERMANENT = "permanent (a copy of the file is kept for manual recovery)"
SYSTEM_QUARANTINE = ("moves into a root-only quarantine you cannot restore from "
                     "yet (no space freed yet)")
SYSTEM_PERMANENT = ("deleted permanently with administrator rights (no copy is "
                    "kept)")
SYSTEM_PROMPT = ("System-wide items need administrator permission: one prompt "
                 "for all of them.")

_JOB_KINDS = (RemedyKind.LAUNCH_JOB, RemedyKind.SYSTEMD_UNIT, RemedyKind.PKG_RECEIPT)

_CATEGORY_TIPS = {
    findings.YOUR_FILES: ("Files and folders you own or that hold your state "
                          "(some, such as sleep images or snapshots, are system "
                          "data kept for you). You decide what goes."),
    findings.APP_LEFTOVERS: "Data and launchers left behind by apps that are gone.",
    findings.UNOWNED_FILES: "System files that no installed package claims.",
    findings.SERVICES: "Background jobs and services whose program is gone.",
    findings.INSTALL_RECORDS: "Install records of packages whose files are gone.",
    findings.OTHER_FINDINGS: "Findings from scenarios that have no category yet.",
}


def shown(text) -> str:
    """Display form of finding-derived text (names, paths, titles, reasons):
    control, format (bidi overrides/isolates) and line/paragraph separator
    characters are shown as backslash-u escapes, as the CLI's ``report.safe``
    does, so a hostile name can neither reorder nor split what is read.
    Only for display: Copy path copies the original text."""
    return _visible(str(text or ""))


def tip_lines(*parts) -> str:
    """A plain tooltip of several finding-derived parts, one per line (each
    part sanitised with :func:`shown` first, so its own newlines never
    become line breaks)."""
    return plain_tip("\n".join(shown(p) for p in parts if p))


def plain_tip(text: str) -> str:
    """A tooltip that shows ``text`` literally (tooltips are rich text when
    Qt guesses so: escape it and say rich text explicitly)."""
    body = html.escape(text or "", quote=False).replace("\n", "<br>")
    return f"<qt>{body}</qt>"


def _plain_label(text: str = "") -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    label.setText(text)
    return label


def _remedy_kind(item: CleanableItem) -> Optional[RemedyKind]:
    remedy = item.remedy
    return remedy.kind if remedy is not None else None


def is_duplicate_copy(item: CleanableItem) -> bool:
    remedy = item.remedy
    return (findings.is_finding(item) and remedy is not None
            and remedy.kind is RemedyKind.PATH and bool(remedy.group))


def real_size(item: CleanableItem) -> int:
    """Bytes the item really holds: a duplicate copy's scan size is 0 for the
    default survivor, so its scan-time lstat size is used instead."""
    if is_duplicate_copy(item):
        try:
            size = int(item.remedy.fingerprint[0])  # type: ignore[union-attr]
        except (TypeError, ValueError, IndexError):
            size = -1
        if size >= 0:
            return size
    return max(0, int(item.size or 0))


def user_problem(item: CleanableItem) -> Optional[str]:
    """Why the in-process executor (``actions.act``) would always skip a
    user-space ``item`` (its checks that need no filesystem access), or None.
    """
    from cleanix.core import remedy_exec

    remedy = item.remedy
    if not item.report_only or remedy is None:
        return NO_ACTION
    if item.kind is not ItemKind.PATH or not item.path:
        return NOT_HANDLED
    if remedy.kind is not RemedyKind.PATH and remedy.kind not in remedy_exec.KINDS:
        return NOT_HANDLED
    if link_target(remedy) is not None:
        return LINK_NOT_HERE
    if remedy.group and remedy.kind is not RemedyKind.PATH:
        return NOT_HANDLED
    return None


def what_happens(item: CleanableItem, permanent: bool) -> str:
    """Per-item text: what acting on ``item`` does (plain text)."""
    if item.requires_root:
        return system_findings.what_happens(item, permanent)
    if _remedy_kind(item) in _JOB_KINDS:
        return ("Permanent: the job is stopped and its file removed (a copy of "
                "the file is kept for manual recovery)")
    if permanent:
        return "Deleted permanently (no Undo)"
    return "Moves to quarantine (Undo available)"


def footer_lines(items: Sequence[CleanableItem], permanent: bool) -> List[str]:
    """What acting on ``items`` does, one line per kind of effect. Undo is
    only ever claimed for user-space PATH items moved to the quarantine."""
    buckets: Dict[str, List[CleanableItem]] = {}
    for item in items:
        job = _remedy_kind(item) in _JOB_KINDS
        if item.requires_root:
            key = "sys_job" if job else ("sys_perm" if permanent else "sys_q")
        else:
            key = "job" if job else ("perm" if permanent else "q")
        buckets.setdefault(key, []).append(item)
    text = {
        "q": USER_QUARANTINE, "perm": USER_PERMANENT, "job": JOB_PERMANENT,
        "sys_q": SYSTEM_QUARANTINE, "sys_perm": SYSTEM_PERMANENT,
        "sys_job": JOB_PERMANENT,
    }
    label = {
        "q": "item(s)", "perm": "item(s)", "job": "job/service file(s)",
        "sys_q": "system-wide item(s)", "sys_perm": "system-wide item(s)",
        "sys_job": "system-wide job/service/install record(s)",
    }
    lines: List[str] = []
    for key in ("q", "perm", "job", "sys_q", "sys_perm", "sys_job"):
        its = buckets.get(key)
        if not its:
            continue
        size = human_size(sum(real_size(i) for i in its))
        lines.append(f"{len(its)} {label[key]}, {size}: {text[key]}")
    if any(i.requires_root for i in items):
        lines.append(SYSTEM_PROMPT)
    return lines


# ===================================================================== model
@dataclass
class Scenario:
    """One scenario (cleaner) of the review: its items in display units (a
    duplicate group is one unit; any other item is a unit of one)."""

    index: int
    category: str
    cleaner_id: str
    title: str
    items: List[CleanableItem] = field(default_factory=list)
    units: List[List[CleanableItem]] = field(default_factory=list)
    realised: int = 0  # units realised (rows exist) so far

    @property
    def small(self) -> bool:
        return len(self.items) <= REALISE_LIMIT

    def unit_group(self, unit: List[CleanableItem]) -> Optional[str]:
        first = unit[0]
        return first.remedy.group if is_duplicate_copy(first) else None  # type: ignore[union-attr]


def _units(items: List[CleanableItem]) -> List[List[CleanableItem]]:
    out: List[List[CleanableItem]] = []
    by_group: Dict[str, List[CleanableItem]] = {}
    for item in items:
        if is_duplicate_copy(item):
            group = item.remedy.group  # type: ignore[union-attr]
            unit = by_group.get(group)
            if unit is None:
                unit = by_group[group] = []
                out.append(unit)
            unit.append(item)
        else:
            out.append([item])
    for group, unit in by_group.items():
        first = findings.default_survivor(unit, "oldest")
        unit.sort(key=lambda i: 0 if i is first else 1)
    return out


class ReviewModel:
    """Selection state of the Review. All rules live here; see the module
    docstring."""

    def __init__(self) -> None:
        self.scenarios: List[Scenario] = []
        self.permanent = False
        self._elevation = False
        self._elevation_reason = ""
        self._static: Dict[int, Optional[str]] = {}
        self._survivors: Dict[str, CleanableItem] = {}
        self._group_of: Dict[str, List[CleanableItem]] = {}
        self._scenario_of: Dict[int, int] = {}
        self._realised: set = set()
        self._selected: Dict[int, CleanableItem] = {}
        self.cap_note = ""

    # ------------------------------------------------------------ loading
    def load(self, groups: Sequence[FindingGroup]) -> None:
        self.scenarios = []
        self._static = {}
        self._survivors = {}
        self._group_of = {}
        self._scenario_of = {}
        self._realised = set()
        self._selected = {}
        self.cap_note = ""
        for si, g in enumerate(groups):
            items = list(g.items)
            sc = Scenario(si, g.category, g.cleaner_id, g.title, items, _units(items))
            self.scenarios.append(sc)
            for item in items:
                self._scenario_of[id(item)] = si
        # A duplicate group id must name exactly one unit (one scenario):
        # one seen twice is ambiguous and fails closed -- none of its copies
        # can be ticked and it gets no survivor.
        units_of: Dict[str, List[List[CleanableItem]]] = {}
        for sc in self.scenarios:
            for unit in sc.units:
                group = sc.unit_group(unit)
                if group is not None:
                    units_of.setdefault(group, []).append(unit)
        ambiguous = set()
        for group, units in units_of.items():
            if len(units) == 1:
                self._group_of[group] = units[0]
                self._survivors[group] = units[0][0]  # default (see _units)
            else:
                ambiguous.update(id(i) for u in units for i in u)
        every = [i for sc in self.scenarios for i in sc.items]
        system = self._system_reasons([i for i in every if i.requires_root])
        for item in every:
            if id(item) in ambiguous:
                self._static[id(item)] = AMBIGUOUS_GROUP
            elif item.requires_root:
                why = (NO_ACTION if not findings.is_finding(item)
                       else system.get(id(item), None))
                self._static[id(item)] = why
            else:
                self._static[id(item)] = user_problem(item)

    @staticmethod
    def _system_reasons(items: List[CleanableItem]) -> Dict[int, Optional[str]]:
        """``{id(item): reason or None}`` from ``system_findings.plan`` -- the
        CLI's own checks -- called per scenario in chunks below the request
        limits, so a per-run cap never makes an item look unofferable (the
        caps are enforced on the selection instead)."""
        from cleanix.core import elevate

        out: Dict[int, Optional[str]] = {}
        by_scenario: Dict[str, List[CleanableItem]] = {}
        for item in items:
            by_scenario.setdefault(item.cleaner_id, []).append(item)
        step = max(1, int(elevate.MAX_FINDING_ITEMS))
        for its in by_scenario.values():
            for k in range(0, len(its), step):
                chunk = its[k:k + step]
                try:
                    plan = system_findings.plan(chunk)
                    for item in plan.offered:
                        out[id(item)] = None
                    for item, why in plan.not_offered:
                        out[id(item)] = f"{NOT_OFFERED}: {why}"
                except Exception:  # noqa: BLE001 - fail closed
                    pass
                for item in chunk:
                    out.setdefault(id(item), f"{NOT_OFFERED}: {system_findings.CANNOT_CHECK}")
        return out

    # ------------------------------------------------------------- queries
    def categories(self) -> List[str]:
        present = {sc.category for sc in self.scenarios}
        return [c for c in findings.CATEGORY_ORDER if c in present]

    def scenarios_in(self, category: str) -> List[Scenario]:
        return [sc for sc in self.scenarios if sc.category == category]

    def scenario_of(self, item: CleanableItem) -> Scenario:
        return self.scenarios[self._scenario_of[id(item)]]

    def survivor(self, group: str) -> Optional[CleanableItem]:
        return self._survivors.get(group)

    def is_survivor(self, item: CleanableItem) -> bool:
        return is_duplicate_copy(item) and \
            self._survivors.get(item.remedy.group) is item  # type: ignore[union-attr]

    def has_remedy_row(self, item: CleanableItem) -> bool:
        """Whether the item's row carries a tick box at all (it has a remedy,
        even if it cannot be ticked right now)."""
        return findings.is_finding(item)

    def reason(self, item: CleanableItem) -> Optional[str]:
        """Why ``item`` cannot be ticked now, or None when it can."""
        why = self._static.get(id(item), NO_ACTION)
        if why is not None:
            return why
        if self.is_survivor(item):
            return KEPT
        if item.requires_root and not self._elevation:
            return f"{NEEDS_ADMIN}: {self._elevation_reason or ADMIN_UNAVAILABLE}"
        return None

    def tickable(self, item: CleanableItem) -> bool:
        return self.reason(item) is None

    def is_realised(self, item: CleanableItem) -> bool:
        return id(item) in self._realised

    def is_selected(self, item: CleanableItem) -> bool:
        return id(item) in self._selected

    def _scope_units(self, sc: Scenario) -> List[List[CleanableItem]]:
        """The units a bulk tick on ``sc`` covers: all of a small scenario,
        else what is realised (at least the first page)."""
        if sc.small:
            return sc.units
        return sc.units[:max(sc.realised, self._page_end(sc, 0))]

    @staticmethod
    def _page_end(sc: Scenario, start: int) -> int:
        """Units index after one page (whole units) from ``start``."""
        n = 0
        k = start
        while k < len(sc.units) and (n == 0 or n + len(sc.units[k]) <= PAGE):
            n += len(sc.units[k])
            k += 1
        return k

    def bulk_targets(self, sc: Scenario) -> List[CleanableItem]:
        return [i for u in self._scope_units(sc) for i in u if self.tickable(i)]

    def has_ticks(self, sc: Scenario) -> bool:
        """Whether the scenario row shows a tick box (it has tickable items)."""
        return any(self.tickable(i) for i in sc.items)

    @staticmethod
    def _state(targets: List[CleanableItem], selected) -> Qt.CheckState:
        n = sum(1 for i in targets if id(i) in selected)
        if n == 0:
            return Qt.CheckState.Unchecked
        return Qt.CheckState.Checked if n == len(targets) else Qt.CheckState.PartiallyChecked

    def scenario_state(self, sc: Scenario) -> Qt.CheckState:
        """Tri-state over what a bulk tick covers (selected items are always
        inside it; unseen items of a big scenario are noted in the footer)."""
        return self._state(self.bulk_targets(sc), self._selected)

    def category_state(self, category: str) -> Qt.CheckState:
        states = {self.scenario_state(sc) for sc in self.scenarios_in(category)
                  if self.has_ticks(sc)}
        if not states:
            return Qt.CheckState.Unchecked
        if len(states) == 1:
            return states.pop()
        return Qt.CheckState.PartiallyChecked

    def unit_state(self, unit: List[CleanableItem]) -> Qt.CheckState:
        return self._state([i for i in unit if self.tickable(i)], self._selected)

    def unrealised_tickable(self, sc: Scenario) -> int:
        return sum(1 for i in sc.items if self.tickable(i) and not self.is_realised(i))

    # ------------------------------------------------------------ realising
    def realise(self, sc: Scenario, upto: int) -> List[List[CleanableItem]]:
        """Realise ``sc``'s units up to index ``upto``; returns the new ones."""
        upto = min(max(upto, sc.realised), len(sc.units))
        new = sc.units[sc.realised:upto]
        for unit in new:
            for item in unit:
                self._realised.add(id(item))
        sc.realised = upto
        return new

    def realise_initial(self, sc: Scenario) -> List[List[CleanableItem]]:
        """First expand: everything of a small scenario, else one page."""
        return self.realise(sc, len(sc.units) if sc.small else self._page_end(sc, 0))

    def realise_more(self, sc: Scenario) -> List[List[CleanableItem]]:
        return self.realise(sc, self._page_end(sc, sc.realised))

    # ------------------------------------------------------------ selecting
    def _cap_problem(self, item: CleanableItem) -> Optional[str]:
        from cleanix.core import elevate

        if not item.requires_root:
            return None
        chosen = [i for i in self._selected.values() if i.requires_root]
        if len(chosen) >= elevate.MAX_FINDING_ITEMS:
            return CAP_ITEMS.format(n=elevate.MAX_FINDING_ITEMS)
        scenarios = {i.cleaner_id for i in chosen}
        if item.cleaner_id not in scenarios and \
                len(scenarios) >= elevate.MAX_FINDING_SCENARIOS:
            return CAP_SCENARIOS.format(n=elevate.MAX_FINDING_SCENARIOS)
        return None

    def _add(self, item: CleanableItem) -> bool:
        if id(item) in self._selected:
            return False
        if not self.tickable(item) or not self.is_realised(item):
            return False
        if is_duplicate_copy(item):
            unit = self._group_of.get(item.remedy.group)  # type: ignore[union-attr]
            if unit is None or len([i for i in unit if id(i) not in self._selected]) <= 1:
                return False  # never the last unticked copy of a group
        cap = self._cap_problem(item)
        if cap is not None:
            self.cap_note = cap
            return False
        self._selected[id(item)] = item
        return True

    def set_checked(self, item: CleanableItem, on: bool) -> bool:
        """Tick/untick one item; False when nothing changed (refused)."""
        self.cap_note = ""  # an untick, or a new tick: any old cap note is stale
        if not on:
            return self._selected.pop(id(item), None) is not None
        return self._add(item)

    def set_unit(self, unit: List[CleanableItem], on: bool) -> bool:
        changed = False
        self.cap_note = ""
        for item in unit:
            changed = (self._add(item) if on else
                       self._selected.pop(id(item), None) is not None) or changed
        return changed

    def set_scenario(self, sc: Scenario, on: bool) -> List[List[CleanableItem]]:
        """Bulk tick/untick; returns the units realised for it (the view
        shows them). Unticking clears every item of the scenario."""
        self.cap_note = ""
        if not on:
            for item in sc.items:
                self._selected.pop(id(item), None)
            return []
        new = self.realise(sc, len(self._scope_units(sc)))
        for item in self.bulk_targets(sc):
            self._add(item)
        return new

    def set_category(self, category: str, on: bool) -> Dict[int, List[List[CleanableItem]]]:
        out: Dict[int, List[List[CleanableItem]]] = {}
        note = ""
        for sc in self.scenarios_in(category):
            if self.has_ticks(sc) or not on:
                out[sc.index] = self.set_scenario(sc, on)
                note = note or self.cap_note
        self.cap_note = note
        return out

    def set_survivor(self, item: CleanableItem) -> bool:
        """Keep ``item`` instead of its group's current survivor. The new
        survivor is unticked; the old one becomes tickable (not ticked)."""
        if not is_duplicate_copy(item):
            return False
        group = item.remedy.group  # type: ignore[union-attr]
        unit = self._group_of.get(group)
        if unit is None or not any(i is item for i in unit):
            return False
        if self._survivors.get(group) is item:
            return False
        self._selected.pop(id(item), None)
        self._survivors[group] = item
        return True

    def set_elevation(self, available: bool, reason: str = "") -> None:
        self._elevation = bool(available)
        self._elevation_reason = reason or ""
        self._prune()

    def _prune(self) -> None:
        self.cap_note = ""
        for key, item in list(self._selected.items()):
            if not self.tickable(item):
                del self._selected[key]

    def clear_selection(self) -> None:
        self._selected = {}
        self.cap_note = ""

    # ------------------------------------------------------------- results
    def selected_items(self) -> List[CleanableItem]:
        return [i for sc in self.scenarios for i in sc.items
                if id(i) in self._selected and self.tickable(i)]

    def selected_user_items(self) -> List[CleanableItem]:
        """The ticked user-space items (acted on in-process)."""
        return [i for i in self.selected_items() if not i.requires_root]

    def selected_system_items(self) -> List[CleanableItem]:
        """The ticked system-wide items (for the administrator helper)."""
        return [i for i in self.selected_items() if i.requires_root]

    def selected_size(self) -> int:
        return sum(real_size(i) for i in self.selected_items())

    def survivor_map(self) -> Dict[str, CleanableItem]:
        """Group id -> kept copy, for every duplicate group with a ticked
        copy (pass to ``findings.plan_duplicates_keeping``)."""
        out: Dict[str, CleanableItem] = {}
        for item in self.selected_items():
            if is_duplicate_copy(item):
                group = item.remedy.group  # type: ignore[union-attr]
                out[group] = self._survivors[group]
        return out

    def more_notes(self) -> List[str]:
        notes = []
        for sc in self.scenarios:
            n = self.unrealised_tickable(sc)
            if n and any(self.is_selected(i) for i in sc.items):
                notes.append(MORE_NOT_SHOWN.format(title=shown(sc.title), n=n))
        return notes

    def check_invariants(self) -> None:
        """Raise AssertionError when a selection rule is broken (tests)."""
        for item in self._selected.values():
            assert self.tickable(item), "ticked item is not tickable"
            assert self.is_realised(item), "ticked item was never shown"
            assert not self.is_survivor(item), "kept copy is ticked"
        for group, unit in self._group_of.items():
            survivor = self._survivors[group]
            assert any(i is survivor for i in unit), "survivor not in its group"
            assert any(id(i) not in self._selected for i in unit), \
                "every copy of a duplicate group is ticked"


# ===================================================================== view
class _Row:
    __slots__ = ("kind", "si", "item", "unit", "category")

    def __init__(self, kind: str, *, si: int = -1, item=None, unit=None,
                 category: str = "") -> None:
        self.kind = kind  # "cat" | "sc" | "dup" | "item" | "more"
        self.si = si
        self.item = item
        self.unit = unit
        self.category = category


class ReviewView(QWidget):
    """The Review tree and its footer (no tab, no act flow: see Task 12)."""

    actRequested = Signal(object, bool, object)  # items, permanent, survivors
    # The same request, split for the owner: (user_items, system_items,
    # permanent, survivors). user_items are acted on in-process; system_items
    # go to the administrator helper. Emitted right after actRequested.
    actRequestedSplit = Signal(object, object, bool, object)
    selectionChanged = Signal()

    def __init__(self, parent=None, *, home: Optional[str] = None) -> None:
        super().__init__(parent)
        self.model = ReviewModel()
        self._home = home if home is not None else os.path.expanduser("~")
        self._busy = False
        self._cat_rows: Dict[str, QTreeWidgetItem] = {}
        self._sc_rows: Dict[int, QTreeWidgetItem] = {}
        self._dup_rows: Dict[str, QTreeWidgetItem] = {}
        self._item_rows: Dict[int, QTreeWidgetItem] = {}
        self._more_rows: Dict[int, QTreeWidgetItem] = {}

        self.message = _plain_label(EMPTY_BEFORE_SCAN)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(len(COLUMNS))
        self.tree.setHeaderLabels(COLUMNS)
        self.tree.setRootIsDecorated(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.setAccessibleName("Findings to review, by category and scenario")
        hdr = self.tree.header()
        hdr.setStretchLastSection(False)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)

        self.summary = _plain_label()
        self.lines = _plain_label()
        self.notes = _plain_label()
        self.permanent_box = QCheckBox("Delete permanently (no Undo)")
        self.permanent_box.setToolTip(plain_tip(
            "Files are deleted at once instead of going to the quarantine; "
            "nothing can be restored. Launch jobs, services and install "
            "records are always permanent."))
        self.act_button = QPushButton("Act on selected")
        self.act_button.setEnabled(False)

        layout = QVBoxLayout(self)
        layout.addWidget(self.message)
        layout.addWidget(self.tree, 1)
        layout.addWidget(self.summary)
        layout.addWidget(self.lines)
        layout.addWidget(self.notes)
        bar = QHBoxLayout()
        bar.addWidget(self.permanent_box)
        bar.addStretch(1)
        bar.addWidget(self.act_button)
        layout.addLayout(bar)

        self.tree.itemExpanded.connect(self._on_expanded)
        self.tree.itemChanged.connect(self._on_changed)
        self.tree.itemDoubleClicked.connect(self._on_double_clicked)
        self.tree.customContextMenuRequested.connect(self._on_menu)
        self.permanent_box.toggled.connect(self.set_permanent)
        self.act_button.clicked.connect(self._on_act)
        self._update_footer()

    # ------------------------------------------------------------------ API
    def set_scan(self, scan) -> None:
        """Show the findings of ``scan`` (a ScanResult or a list of
        CleanerReports). Nothing is ticked."""
        if not isinstance(scan, ScanResult):
            scan = ScanResult(reports=list(scan or []))
        self.model.load(findings.group_findings(scan))
        self._reset_permanent()
        self._rebuild()
        self.message.setText("" if self.model.scenarios else EMPTY_SCAN)
        self.message.setVisible(not self.model.scenarios)
        self._changed()

    def clear(self) -> None:
        self.model.load([])
        self._reset_permanent()
        self._rebuild()
        self.message.setText(EMPTY_BEFORE_SCAN)
        self.message.setVisible(True)
        self._changed()

    def _reset_permanent(self) -> None:
        """A new scan starts with "Delete permanently" off again."""
        self.model.permanent = False
        if self.permanent_box.isChecked():
            self.permanent_box.blockSignals(True)
            self.permanent_box.setChecked(False)
            self.permanent_box.blockSignals(False)

    def selected_items(self) -> List[CleanableItem]:
        return self.model.selected_items()

    def selected_size(self) -> int:
        return self.model.selected_size()

    def survivor_map(self) -> Dict[str, CleanableItem]:
        return self.model.survivor_map()

    def set_permanent(self, on: bool) -> None:
        on = bool(on)
        if self.permanent_box.isChecked() != on:
            self.permanent_box.setChecked(on)  # re-enters via toggled
            return
        self.model.permanent = on
        self._refresh_rows()
        self._update_footer()

    def set_elevation_available(self, available: bool, reason: str = "") -> None:
        """System-wide items become tickable only with elevation available."""
        before = len(self.model.selected_items())
        self.model.set_elevation(available, reason)
        self._refresh_rows()
        self._update_footer()
        if len(self.model.selected_items()) != before:
            self.selectionChanged.emit()

    def keep_instead(self, item: CleanableItem) -> bool:
        """"Keep this copy instead" for a duplicate copy."""
        if not self.model.set_survivor(item):
            return False
        self._changed()
        return True

    def item_row(self, item: CleanableItem) -> Optional[QTreeWidgetItem]:
        return self._item_rows.get(id(item))

    def category_row(self, category: str) -> Optional[QTreeWidgetItem]:
        return self._cat_rows.get(category)

    def scenario_row(self, cleaner_id: str) -> Optional[QTreeWidgetItem]:
        for sc in self.model.scenarios:
            if sc.cleaner_id == cleaner_id:
                return self._sc_rows.get(sc.index)
        return None

    def more_row(self, cleaner_id: str) -> Optional[QTreeWidgetItem]:
        for sc in self.model.scenarios:
            if sc.cleaner_id == cleaner_id:
                return self._more_rows.get(sc.index)
        return None

    def show_more(self, cleaner_id: str) -> None:
        for sc in self.model.scenarios:
            if sc.cleaner_id == cleaner_id:
                self._show_more(sc)

    @staticmethod
    def menu_labels(item: CleanableItem, keep_offered: bool = False) -> List[str]:
        labels = ["Copy path"]
        if item.kind is ItemKind.PATH and item.path:
            labels.append("Open location")
        if keep_offered:
            labels.append("Keep this copy instead")
        return labels

    def item_menu_labels(self, item: CleanableItem) -> List[str]:
        return self.menu_labels(
            item, is_duplicate_copy(item) and not self.model.is_survivor(item))

    def copy_path(self, item: CleanableItem) -> None:
        text = item_target(item)
        if text:
            QApplication.clipboard().setText(text)

    def open_location(self, item: CleanableItem) -> bool:
        if item.kind is not ItemKind.PATH or not item.path:
            return False
        return reveal.reveal_in_file_manager(item.path)

    # ------------------------------------------------------------- building
    @staticmethod
    def _payload(row: Optional[QTreeWidgetItem]) -> Optional[_Row]:
        return row.data(0, _ROLE) if row is not None else None

    def _dark(self) -> bool:
        return self.tree.palette().base().color().lightness() < 128

    def _badge(self, row: QTreeWidgetItem, text: str, safety: Safety) -> None:
        row.setText(2, text)
        row.setForeground(2, QBrush(QColor(badge_color(safety, self._dark()))))

    def _rebuild(self) -> None:
        self._busy = True
        try:
            self.tree.clear()
            self._cat_rows, self._sc_rows = {}, {}
            self._dup_rows, self._item_rows, self._more_rows = {}, {}, {}
            for category in self.model.categories():
                cat = QTreeWidgetItem()
                cat.setData(0, _ROLE, _Row("cat", category=category))
                scs = self.model.scenarios_in(category)
                cat.setText(0, category)
                n = sum(len(sc.items) for sc in scs)
                cat.setText(3, f"{n} finding(s) in {len(scs)} scenario(s)")
                cat.setText(4, human_size(sum(i.size for sc in scs for i in sc.items)))
                cat.setTextAlignment(4, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                cat.setToolTip(0, plain_tip(_CATEGORY_TIPS.get(category, category)))
                self.tree.addTopLevelItem(cat)
                self._cat_rows[category] = cat
                for sc in scs:
                    row = QTreeWidgetItem()
                    row.setData(0, _ROLE, _Row("sc", si=sc.index))
                    row.setText(0, shown(sc.title))
                    acts = sum(1 for i in sc.items if findings.is_finding(i))
                    row.setText(3, f"{len(sc.items)} item(s), {acts} with an action")
                    row.setText(4, human_size(sum(i.size for i in sc.items)))
                    row.setTextAlignment(4, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                    row.setToolTip(0, tip_lines(f"{sc.title} ({sc.cleaner_id})"))
                    row.setChildIndicatorPolicy(
                        QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator)
                    cat.addChild(row)
                    self._sc_rows[sc.index] = row
                cat.setExpanded(True)
        finally:
            self._busy = False
        self._refresh_rows()

    def _ensure_realised(self, sc: Scenario) -> None:
        if sc.realised == 0 and sc.units:
            self._add_units(sc, self.model.realise_initial(sc))

    def _add_units(self, sc: Scenario, units: List[List[CleanableItem]]) -> None:
        if not units:
            return
        parent = self._sc_rows[sc.index]
        prev = self._busy
        self._busy = True
        try:
            more = self._more_rows.pop(sc.index, None)
            if more is not None:
                parent.removeChild(more)
            for unit in units:
                group = sc.unit_group(unit)
                if group is None:
                    parent.addChild(self._make_item_row(sc, unit[0]))
                    continue
                dup = QTreeWidgetItem()
                dup.setData(0, _ROLE, _Row("dup", si=sc.index, unit=unit))
                name = os.path.basename(unit[0].path or "") or "file"
                dup.setText(0, f"{len(unit)} copies of {shown(name)}")
                dup.setText(4, human_size(real_size(unit[0])) + " each")
                dup.setTextAlignment(4, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                dup.setToolTip(0, tip_lines(
                    f"Identical copies of {name}. One copy always stays; "
                    "right-click a copy and choose \"Keep this copy instead\" "
                    "to change which one."))
                parent.addChild(dup)
                self._dup_rows[group] = dup
                dup.addChildren([self._make_item_row(sc, i) for i in unit])
                dup.setExpanded(True)
            left = len(sc.units) - sc.realised
            if left > 0:
                rest = sc.units[sc.realised:]
                n = sum(len(u) for u in rest)
                more = QTreeWidgetItem()
                more.setData(0, _ROLE, _Row("more", si=sc.index))
                more.setText(0, f"{n} more not shown")
                more.setText(3, "Show more (double-click or right-click)")
                more.setText(4, human_size(sum(i.size for u in rest for i in u)))
                more.setTextAlignment(4, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                parent.addChild(more)
                self._more_rows[sc.index] = more
        finally:
            self._busy = prev

    def _make_item_row(self, sc: Scenario, item: CleanableItem) -> QTreeWidgetItem:
        row = QTreeWidgetItem()
        row.setData(0, _ROLE, _Row("item", si=sc.index, item=item))
        self._item_rows[id(item)] = row
        # Every copy of a duplicate group has the same description: name the
        # copy by its file name instead (its folder is in the next column).
        label = (os.path.basename(item.path or "") if is_duplicate_copy(item)
                 else "") or display_label(item, self._home)
        # Displayed sanitised; Copy path copies the original (item_target).
        row.setText(0, shown(label))
        row.setText(1, shown(shorten_path(item_target(item), self._home)))
        row.setText(4, human_size(real_size(item)))
        row.setTextAlignment(4, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if self.model.has_remedy_row(item):
            row.setCheckState(0, Qt.CheckState.Unchecked)
        self._apply_item(row, item)
        return row

    def _apply_item(self, row: QTreeWidgetItem, item: CleanableItem) -> None:
        m = self.model
        reason = m.reason(item)
        happens = what_happens(item, m.permanent) if findings.is_finding(item) else ""
        if m.is_survivor(item):
            self._badge(row, "Kept", Safety.SAFE)
        elif not findings.is_finding(item):
            self._badge(row, "Report only", Safety.REVIEW)
        elif item.requires_root:
            self._badge(row, Safety.ADMIN.value, Safety.ADMIN)
        elif _remedy_kind(item) in _JOB_KINDS:
            self._badge(row, Safety.PERMANENT.value, Safety.PERMANENT)
        else:
            self._badge(row, Safety.REVIEW.value, Safety.REVIEW)
        col3 = reason if reason is not None else happens
        if reason is None and is_duplicate_copy(item):
            kept = m.survivor(item.remedy.group)  # type: ignore[union-attr]
            if kept is not None:
                col3 = f"{happens}; keeps {shorten_path(kept.path or '', self._home)}"
        col3 = shown(col3)
        row.setText(3, col3)
        tip = tip_lines(item_target(item), reason,
                        happens if shown(happens) != col3 else "", item.hint)
        for c in range(len(COLUMNS)):
            row.setToolTip(c, tip)
        row.setData(0, _ACCESSIBLE, f"{row.text(0)}, {row.text(2)}, {row.text(4)}, {col3}")
        if m.has_remedy_row(item):
            flags = Qt.ItemFlag.ItemIsSelectable
            if reason is None:
                flags |= Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable
            elif m.is_survivor(item):
                flags |= Qt.ItemFlag.ItemIsEnabled
            row.setFlags(flags)
            row.setCheckState(0, Qt.CheckState.Checked if m.is_selected(item)
                              else Qt.CheckState.Unchecked)
        else:
            row.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)

    def _set_tick(self, row: QTreeWidgetItem, show: bool, state: Qt.CheckState) -> None:
        flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if show:
            row.setFlags(flags | Qt.ItemFlag.ItemIsUserCheckable)
            row.setCheckState(0, state)
        else:
            row.setFlags(flags)
            if row.data(0, Qt.ItemDataRole.CheckStateRole) is not None:
                row.setCheckState(0, Qt.CheckState.Unchecked)

    def _refresh_rows(self) -> None:
        m = self.model
        prev = self._busy
        self._busy = True
        try:
            for item_id, row in self._item_rows.items():
                p = self._payload(row)
                if p is not None and p.item is not None:
                    self._apply_item(row, p.item)
            for group, row in self._dup_rows.items():
                unit = self._payload(row).unit
                any_tick = any(m.tickable(i) for i in unit)
                self._set_tick(row, any_tick, m.unit_state(unit))
            for si, row in self._sc_rows.items():
                sc = m.scenarios[si]
                self._set_tick(row, m.has_ticks(sc), m.scenario_state(sc))
            for category, row in self._cat_rows.items():
                show = any(m.has_ticks(sc) for sc in m.scenarios_in(category))
                self._set_tick(row, show, m.category_state(category))
        finally:
            self._busy = prev

    def _update_footer(self) -> None:
        items = self.model.selected_items()
        size = human_size(self.model.selected_size())
        if items:
            self.summary.setText(f"Selected: {len(items)} item(s), {size}")
            self.act_button.setText(f"Act on {len(items)} selected ({size})")
        else:
            self.summary.setText("Nothing selected. Tick findings to act on them.")
            self.act_button.setText("Act on selected")
        self.act_button.setEnabled(bool(items))
        self.lines.setText("\n".join(footer_lines(items, self.model.permanent)))
        notes = self.model.more_notes()
        if self.model.cap_note:
            notes.append(self.model.cap_note)
        self.notes.setText("\n".join(notes))
        self.lines.setVisible(bool(items))
        self.notes.setVisible(bool(notes))

    def _changed(self) -> None:
        self._refresh_rows()
        self._update_footer()
        self.selectionChanged.emit()

    # -------------------------------------------------------------- events
    def _show_more(self, sc: Scenario) -> None:
        self._ensure_realised(sc)
        self._add_units(sc, self.model.realise_more(sc))
        self._refresh_rows()
        self._update_footer()

    def _show_scenario(self, sc: Scenario, units: List[List[CleanableItem]]) -> None:
        self._add_units(sc, units)
        row = self._sc_rows[sc.index]
        row.parent().setExpanded(True)
        row.setExpanded(True)
        self._reveal_ticked(sc)

    def _reveal_ticked(self, sc: Scenario) -> None:
        """Expand every duplicate-group row of ``sc`` holding a ticked copy
        (a bulk tick never leaves ticked items under a collapsed row)."""
        for unit in sc.units[:sc.realised]:
            group = sc.unit_group(unit)
            if group is not None and any(self.model.is_selected(i) for i in unit):
                dup = self._dup_rows.get(group)
                if dup is not None:
                    dup.setExpanded(True)

    def _on_expanded(self, row: QTreeWidgetItem) -> None:
        p = self._payload(row)
        if p is None or p.kind != "sc":
            return
        sc = self.model.scenarios[p.si]
        if sc.realised == 0:
            self._ensure_realised(sc)
            self._refresh_rows()

    def _on_changed(self, row: QTreeWidgetItem, column: int) -> None:
        if self._busy or column != 0:
            return
        p = self._payload(row)
        if p is None or not (row.flags() & Qt.ItemFlag.ItemIsUserCheckable):
            return
        on = row.checkState(0) != Qt.CheckState.Unchecked
        self.toggle(p, on)

    def toggle(self, p: _Row, on: bool) -> None:
        """Apply a tick on a row payload (also the test entry point). A bulk
        tick that can add nothing (all it covers is ticked already, or the
        rest is refused) unticks instead, so a partly ticked row can always
        be cleared by clicking it."""
        m = self.model
        if on and p.kind in ("dup", "sc", "cat"):
            before = len(m.selected_items())
            self._apply(p, True)
            if len(m.selected_items()) == before:
                self._apply(p, False)
        else:
            self._apply(p, on)
        self._changed()

    def _apply(self, p: _Row, on: bool) -> None:
        m = self.model
        if p.kind == "item":
            m.set_checked(p.item, on)
        elif p.kind == "dup":
            m.set_unit(p.unit, on)
            if on:  # same reveal as a scenario tick: ancestors and the row
                self._show_scenario(m.scenarios[p.si], [])
        elif p.kind == "sc":
            sc = m.scenarios[p.si]
            if on:
                self._ensure_realised(sc)
            self._show_scenario(sc, m.set_scenario(sc, on))
        elif p.kind == "cat":
            if on:
                for sc in m.scenarios_in(p.category):
                    if m.has_ticks(sc):
                        self._ensure_realised(sc)
            for si, units in m.set_category(p.category, on).items():
                if on:
                    self._show_scenario(m.scenarios[si], units)

    def _on_double_clicked(self, row: QTreeWidgetItem, column: int) -> None:
        p = self._payload(row)
        if p is not None and p.kind == "more":
            self._show_more(self.model.scenarios[p.si])

    def _on_menu(self, pos: QPoint) -> None:
        row = self.tree.itemAt(pos)
        menu = self.build_menu(row)
        if menu is not None:
            menu.exec(self.tree.viewport().mapToGlobal(pos))

    def build_menu(self, row: Optional[QTreeWidgetItem]) -> Optional[QMenu]:
        p = self._payload(row)
        if p is None:
            return None
        menu = QMenu(self)
        if p.kind == "more":
            sc = self.model.scenarios[p.si]
            menu.addAction("Show more", lambda: self._show_more(sc))
        elif p.kind == "item" and p.item is not None:
            item = p.item
            labels = self.item_menu_labels(item)
            menu.addAction("Copy path", lambda: self.copy_path(item))
            if "Open location" in labels:
                menu.addAction("Open location", lambda: self.open_location(item))
            if "Keep this copy instead" in labels:
                menu.addAction("Keep this copy instead", lambda: self.keep_instead(item))
        if menu.isEmpty():
            return None
        return menu

    def _on_act(self) -> None:
        items = self.model.selected_items()
        if not items:
            return
        survivors = self.model.survivor_map()
        self.actRequested.emit(items, self.model.permanent, survivors)
        self.actRequestedSplit.emit(self.model.selected_user_items(),
                                    self.model.selected_system_items(),
                                    self.model.permanent, survivors)
