"""Curated, grouped scan results as a lazy tree.

One top-level row per :class:`~cleanix.core.curation.Group`; children are
created only when a group is first expanded. Selection lives in a set of item
keys (``models.item_key``), never in widget state; group ticks are derived.
"""

from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Optional, Set

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QApplication, QHeaderView, QMenu, QTreeWidget, QTreeWidgetItem,
)

from cleanix.core.curation import Group, Safety, display_label, shorten_path
from cleanix.core.models import CleanableItem, ItemKind, item_key
from cleanix.core.utils import human_size
from cleanix.gui import elevation, reveal

COLUMNS = ["Item", "What it is", "Safety", "Items", "Size"]
_ROLE = Qt.ItemDataRole.UserRole
_RANK = {Safety.SAFE: 0, Safety.REVIEW: 1, Safety.ADMIN: 2, Safety.PERMANENT: 3}
_CHECK = Qt.ItemDataRole.CheckStateRole
_ACCESSIBLE = Qt.ItemDataRole.AccessibleTextRole

# Colour is only a hint; the badge text always carries the meaning.
_BADGE_COLOR = {
    Safety.SAFE: "#2e7d32",
    Safety.REVIEW: "#b26a00",
    Safety.ADMIN: "#1565c0",
    Safety.PERMANENT: "#c62828",
}

REVIEW_ONLY_REASON = "Review only: Cleanix never deletes this."
ADMIN_REASON = "Needs administrator permission."


class _Row:
    """Payload stored on a tree row."""

    __slots__ = ("kind", "gi", "item")

    def __init__(self, kind: str, gi: int, item: Optional[CleanableItem] = None):
        self.kind = kind  # "group" | "item" | "rest"
        self.gi = gi
        self.item = item


class GroupedResults(QTreeWidget):
    selection_changed = Signal()

    def __init__(self, parent=None, *, allow_admin_items: bool = False,
                 admin_reason: str = "", home: Optional[str] = None) -> None:
        super().__init__(parent)
        self._allow_admin = bool(allow_admin_items)
        self._admin_reason = admin_reason
        self._home = home
        self._groups: List[Group] = []
        self._selectable: List[List[CleanableItem]] = []
        self._keys: Set[str] = set()
        self._problems: Dict[int, str] = {}
        self._raw_visible = False
        self._rest_open: Set[int] = set()
        self._populated: Set[int] = set()
        self._group_rows: List[QTreeWidgetItem] = []
        self._rest_rows: Dict[int, QTreeWidgetItem] = {}
        self._busy = False

        self.setColumnCount(len(COLUMNS))
        self.setHeaderLabels(COLUMNS)
        self.setRootIsDecorated(True)
        self.setUniformRowHeights(True)
        self.setAlternatingRowColors(True)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.setAccessibleName("Scan results grouped by what they are")
        hdr = self.header()
        hdr.setStretchLastSection(False)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for c in (2, 3, 4):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)

        self.itemExpanded.connect(self._on_expanded)
        self.itemChanged.connect(self._on_changed)
        self.itemDoubleClicked.connect(self._on_double_clicked)
        self.customContextMenuRequested.connect(self._on_menu)

    # ------------------------------------------------------------------ API
    def group_count(self) -> int:
        return len(self._groups)

    def refusal_reason(self, item: CleanableItem) -> Optional[str]:
        """Why ``item`` can never be ticked, or None when it is selectable."""
        if item.report_only:
            return REVIEW_ONLY_REASON
        if item.requires_root:
            if not self._allow_admin:
                return self._admin_reason or ADMIN_REASON
            return self._problems.get(id(item))
        return None

    def set_groups(self, groups: List[Group],
                   preselect: Callable[[CleanableItem], bool]) -> None:
        prev = self._busy
        self._busy = True
        try:
            self._groups = list(groups)
            self._rest_open = set()
            self._keys = set()
            self._recompute_selectable()
            if preselect is not None:
                for sel in self._selectable:
                    for i in sel:
                        if preselect(i):
                            self._keys.add(item_key(i))
            self._rebuild_rows(set())
        finally:
            self._busy = prev
        self.selection_changed.emit()

    def set_allow_admin_items(self, allow: bool, reason: str = "") -> None:
        """Change admin availability at runtime; rows and selection follow."""
        self._allow_admin = bool(allow)
        self._admin_reason = reason
        prev = self._busy
        self._busy = True
        try:
            before = set(self._keys)
            expanded = {gi for gi, r in enumerate(self._group_rows) if r.isExpanded()}
            self._recompute_selectable()
            valid = {item_key(i) for sel in self._selectable for i in sel}
            self._keys &= valid
            self._rebuild_rows(expanded)
        finally:
            self._busy = prev
        if self._keys != before:
            self.selection_changed.emit()

    def _recompute_selectable(self) -> None:
        every = [i for g in self._groups for i in g.items]
        self._problems = (elevation.admin_problems(every)
                          if self._allow_admin else {})
        self._selectable = [[i for i in g.items if self.refusal_reason(i) is None]
                            for g in self._groups]

    def _rebuild_rows(self, expanded: Set[int]) -> None:
        self.clear()
        self._populated = set()
        self._rest_rows = {}
        self._group_rows = []
        for gi, g in enumerate(self._groups):
            row = self._make_group_row(gi, g)
            self.addTopLevelItem(row)
            self._group_rows.append(row)
            self._refresh_group(gi)
        for gi in sorted(expanded):
            self._fill_children(gi)
            self._group_rows[gi].setExpanded(True)

    def set_raw_items_visible(self, on: bool) -> None:
        on = bool(on)
        if on == self._raw_visible:
            return
        self._raw_visible = on
        prev = self._busy
        self._busy = True
        try:
            for gi in sorted(self._populated):
                row = self._group_rows[gi]
                row.takeChildren()
                self._rest_rows.pop(gi, None)
                self._fill_children(gi)
        finally:
            self._busy = prev

    def checked_items(self) -> List[CleanableItem]:
        keys = self._keys
        return [i for sel in self._selectable for i in sel if item_key(i) in keys]

    def checked_size(self) -> int:
        return sum(i.size for i in self.checked_items())

    def checked_keys(self) -> Set[str]:
        return set(self._keys)

    def set_checked_keys(self, keys: Iterable[str]) -> None:
        wanted = set(keys)
        valid = {item_key(i) for sel in self._selectable for i in sel}
        self._keys = wanted & valid
        self._refresh_all()
        self.selection_changed.emit()

    def show_all(self, group_row: QTreeWidgetItem) -> None:
        """Expand a group's ``rest`` row into its individual items."""
        payload = self._payload(group_row)
        if payload is None:
            return
        gi = payload.gi
        if gi in self._rest_open or not self._groups[gi].rest:
            return
        self._rest_open.add(gi)
        if gi in self._populated:
            prev = self._busy
            self._busy = True
            try:
                self._group_rows[gi].takeChildren()
                self._rest_rows.pop(gi, None)
                self._fill_children(gi)
            finally:
                self._busy = prev
        else:
            self.expandItem(self._group_rows[gi])

    def copy_path(self, item: CleanableItem) -> None:
        text = (" ".join(item.command or []) if item.kind is ItemKind.COMMAND
                else item.path or "")
        if text:
            QApplication.clipboard().setText(text)

    def open_location(self, item: CleanableItem) -> bool:
        if item.kind is ItemKind.COMMAND or not item.path:
            return False
        return reveal.reveal_in_file_manager(item.path)

    # ------------------------------------------------------------- building
    @staticmethod
    def _payload(row: Optional[QTreeWidgetItem]) -> Optional[_Row]:
        return row.data(0, _ROLE) if row is not None else None

    def _badge(self, row: QTreeWidgetItem, safety: Safety) -> None:
        row.setText(2, safety.value)
        row.setForeground(2, QBrush(QColor(_BADGE_COLOR[safety])))
        row.setToolTip(2, f"Safety: {safety.value}")

    def _make_group_row(self, gi: int, g: Group) -> QTreeWidgetItem:
        row = QTreeWidgetItem()
        row.setData(0, _ROLE, _Row("group", gi))
        row.setText(0, g.title)
        row.setText(3, str(g.item_count))
        row.setText(4, human_size(g.total_size))
        row.setTextAlignment(3, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        row.setTextAlignment(4, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._badge(row, g.safety)
        reason = None
        if not self._selectable[gi] and g.items:
            reason = self.refusal_reason(g.items[0])
        row.setText(1, reason or g.blurb)
        row.setToolTip(0, g.blurb)
        row.setToolTip(1, reason or g.blurb)
        if self._selectable[gi]:
            row.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
                         | Qt.ItemFlag.ItemIsUserCheckable)
            row.setCheckState(0, Qt.CheckState.Unchecked)
        else:
            row.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
        row.setChildIndicatorPolicy(
            QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator
            if (g.shown or g.rest or g.zero) else
            QTreeWidgetItem.ChildIndicatorPolicy.DontShowIndicator)
        text = (f"{g.title}, {g.safety.value}, {g.item_count} items, "
                f"{human_size(g.total_size)}")
        for c in range(len(COLUMNS)):
            row.setData(c, _ACCESSIBLE, text if c == 0 else row.text(c))
        return row

    @staticmethod
    def _item_safety(g: Group, item: CleanableItem) -> Safety:
        return (Safety.REVIEW if item.report_only else
                Safety.ADMIN if item.requires_root else g.safety)

    def _make_item_row(self, gi: int, item: CleanableItem) -> QTreeWidgetItem:
        g = self._groups[gi]
        row = QTreeWidgetItem()
        row.setData(0, _ROLE, _Row("item", gi, item))
        label = display_label(item, self._home)
        row.setText(0, label)
        if item.kind is ItemKind.COMMAND:
            full = " ".join(item.command or [])
            row.setText(1, item.hint or "Runs a command")
        else:
            full = item.path or ""
            row.setText(1, shorten_path(full, self._home))
        row.setToolTip(0, full)
        row.setToolTip(1, full)
        safety = self._item_safety(g, item)
        self._badge(row, safety)
        row.setText(3, "")
        row.setText(4, human_size(item.size))
        row.setTextAlignment(4, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        reason = self.refusal_reason(item)
        flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if reason is None:
            flags |= Qt.ItemFlag.ItemIsUserCheckable
            row.setFlags(flags)
            row.setCheckState(0, Qt.CheckState.Checked if item_key(item) in self._keys
                              else Qt.CheckState.Unchecked)
        else:
            row.setFlags(flags)
            row.setToolTip(0, f"{full}\n{reason}")
            row.setText(1, reason)
        row.setData(0, _ACCESSIBLE,
                    f"{label}, {safety.value}, {human_size(item.size)}")
        return row

    def _make_rest_row(self, gi: int) -> QTreeWidgetItem:
        g = self._groups[gi]
        row = QTreeWidgetItem()
        row.setData(0, _ROLE, _Row("rest", gi))
        n = len(g.rest)
        row.setText(0, f"{n} smaller items · {human_size(g.rest_size)}")
        row.setText(1, "Show all (double-click or right-click)")
        row.setText(4, human_size(g.rest_size))
        row.setTextAlignment(4, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._badge(row, max((self._item_safety(g, i) for i in g.rest),
                             key=_RANK.__getitem__, default=g.safety))
        row.setText(3, str(n))
        row.setTextAlignment(3, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if any(self.refusal_reason(i) is None for i in g.rest):
            flags |= Qt.ItemFlag.ItemIsUserCheckable
            row.setFlags(flags)
            row.setCheckState(0, Qt.CheckState.Unchecked)
        else:
            row.setFlags(flags)
            reason = self.refusal_reason(g.rest[0]) if g.rest else None
            if reason:
                row.setText(1, reason)
                row.setToolTip(1, reason)
        row.setData(0, _ACCESSIBLE, f"{row.text(0)}, {row.text(2)}")
        return row

    def _fill_children(self, gi: int) -> None:
        g = self._groups[gi]
        parent = self._group_rows[gi]
        rows: List[QTreeWidgetItem] = []
        if gi in self._rest_open:
            rows.extend(self._make_item_row(gi, i) for i in g.shown)
            rows.extend(self._make_item_row(gi, i) for i in g.rest)
        else:
            rows.extend(self._make_item_row(gi, i) for i in g.shown)
            if g.rest:
                rest = self._make_rest_row(gi)
                self._rest_rows[gi] = rest
                rows.append(rest)
        if self._raw_visible:
            rows.extend(self._make_item_row(gi, i) for i in g.zero)
        parent.addChildren(rows)
        self._populated.add(gi)
        self._refresh_group(gi)

    # ------------------------------------------------------- derived state
    @staticmethod
    def _state(selectable: List[CleanableItem], keys: Set[str]) -> Qt.CheckState:
        if not selectable:
            return Qt.CheckState.Unchecked
        n = sum(1 for i in selectable if item_key(i) in keys)
        if n == 0:
            return Qt.CheckState.Unchecked
        return Qt.CheckState.Checked if n == len(selectable) else Qt.CheckState.PartiallyChecked

    def _refresh_group(self, gi: int, children: bool = True) -> None:
        was = self._busy
        self._busy = True
        try:
            row = self._group_rows[gi]
            if self._selectable[gi]:
                row.setCheckState(0, self._state(self._selectable[gi], self._keys))
            rest = self._rest_rows.get(gi)
            if rest is not None and rest.parent() is row:
                sel = [i for i in self._groups[gi].rest if self.refusal_reason(i) is None]
                if sel:
                    rest.setCheckState(0, self._state(sel, self._keys))
            if children and gi in self._populated:
                for k in range(row.childCount()):
                    child = row.child(k)
                    p = self._payload(child)
                    if p is not None and p.kind == "item" and \
                            child.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                        child.setCheckState(
                            0, Qt.CheckState.Checked if item_key(p.item) in self._keys
                            else Qt.CheckState.Unchecked)
        finally:
            self._busy = was

    def _refresh_all(self) -> None:
        for gi in range(len(self._groups)):
            self._refresh_group(gi)

    # -------------------------------------------------------------- events
    def _on_expanded(self, row: QTreeWidgetItem) -> None:
        p = self._payload(row)
        if p is None or p.kind != "group" or p.gi in self._populated:
            return
        prev = self._busy
        self._busy = True
        try:
            self._fill_children(p.gi)
        finally:
            self._busy = prev

    def _on_changed(self, row: QTreeWidgetItem, column: int) -> None:
        if self._busy or column != 0:
            return
        p = self._payload(row)
        if p is None or not (row.flags() & Qt.ItemFlag.ItemIsUserCheckable):
            return
        on = row.checkState(0) != Qt.CheckState.Unchecked
        if p.kind == "group":
            targets = self._selectable[p.gi]
        elif p.kind == "rest":
            targets = [i for i in self._groups[p.gi].rest
                       if self.refusal_reason(i) is None]
        else:
            targets = [p.item]
        before = set(self._keys)
        for i in targets:
            (self._keys.add if on else self._keys.discard)(item_key(i))
        self._refresh_group(p.gi, children=p.kind != "item")
        if self._keys != before:
            self.selection_changed.emit()

    def keyPressEvent(self, event) -> None:  # noqa: N802
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            p = self._payload(self.currentItem())
            if p is not None and p.kind == "rest":
                self.show_all(self._group_rows[p.gi])
                event.accept()
                return
        super().keyPressEvent(event)

    def _on_double_clicked(self, row: QTreeWidgetItem, column: int) -> None:
        p = self._payload(row)
        if p is not None and p.kind == "rest":
            self.show_all(self._group_rows[p.gi])

    def _on_menu(self, pos: QPoint) -> None:
        row = self.itemAt(pos)
        p = self._payload(row)
        if p is None:
            return
        menu = QMenu(self)
        if p.kind == "rest":
            menu.addAction("Show all", lambda: self.show_all(self._group_rows[p.gi]))
        elif p.kind == "item" and p.item is not None:
            item = p.item
            menu.addAction("Copy path", lambda: self.copy_path(item))
            if item.kind is not ItemKind.COMMAND:
                menu.addAction("Open location", lambda: self.open_location(item))
        if menu.isEmpty():
            return
        menu.exec(self.viewport().mapToGlobal(pos))
