"""Power mode view: Scan tab (cleaner list, item table, detail pane) + panels."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Callable, List, Optional

from PySide6.QtGui import QTextOption
from PySide6.QtCore import QModelIndex, QSortFilterProxyModel, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListView,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableView,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from cleanix.config import Config
from cleanix.core import catalog, curation, regpromises, report
from cleanix.core.curation import Safety, is_empty
from cleanix.core.models import (
    CleanableItem, ItemKind, ScanResult, item_key, item_target,
)
from cleanix.core.utils import human_size
from cleanix.gui import elevation, workers
from cleanix.gui import models as gm
from cleanix.gui.grouped_results import GroupedResults
from cleanix.gui.models import (
    BadgeRole,
    CleanerListModel,
    ItemTableModel,
)


class _ItemFilterProxy(QSortFilterProxyModel):
    """Filters on the Cleaner and Description columns; sorts on raw values."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._text = ""
        self._safety: Optional[Safety] = None
        self._group_safety: dict = {}
        self.setSortRole(Qt.ItemDataRole.UserRole)

    def set_filter_text(self, text: str) -> None:
        begin = getattr(self, "beginFilterChange", None)
        self._text = text.strip().lower()
        if begin is not None:
            begin()
            self.endFilterChange()
        else:
            self.invalidateFilter()

    def set_safety(self, safety: Optional[Safety], group_safety: dict) -> None:
        """Only rows of cleaners whose group has ``safety`` (None = all)."""
        begin = getattr(self, "beginFilterChange", None)
        self._safety = safety
        self._group_safety = dict(group_safety)
        if begin is not None:
            begin()
            self.endFilterChange()
        else:
            self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:  # noqa: N802
        src = self.sourceModel()
        if self._safety is not None:
            item = src.item_at(row)
            if self._group_safety.get(item.cleaner_id) is not self._safety:
                return False
        if not self._text:
            return True
        for col in (1, 2):
            value = src.data(src.index(row, col, parent), Qt.ItemDataRole.DisplayRole)
            if value and self._text in str(value).lower():
                return True
        return False


class _CleanerDelegateModel(CleanerListModel):
    """Cleaner list whose display text includes the badge (e.g. "Admin")."""

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        value = super().data(index, role)
        if role == Qt.ItemDataRole.DisplayRole and value is not None:
            badge = super().data(index, BadgeRole)
            if badge:
                return f"{value}  [{badge}]"
        return value


class PowerView(QWidget):
    scan_finished = Signal(object)   # ScanResult
    clean_finished = Signal(object)  # CleanSummary

    def __init__(self, config: Config, *,
                 scan_worker_factory: Optional[Callable[[List[str]], object]] = None,
                 clean_worker_factory: Optional[Callable[..., object]] = None,
                 allow_admin_items: bool = False,
                 admin_unavailable_reason: str = "",
                 parent: Optional[QWidget] = None) -> None:
        """``scan_worker_factory(only_ids)`` and
        ``clean_worker_factory(items, dry_run=..., use_quarantine=...)`` return
        worker QObjects (see cleanix.gui.workers)."""
        super().__init__(parent)
        self._config = config
        self._allow_admin = allow_admin_items
        self._admin_reason = admin_unavailable_reason
        self._scan_factory = scan_worker_factory or self._default_scan_worker
        self._clean_factory = clean_worker_factory or self._default_clean_worker
        self._result: Optional[ScanResult] = None
        self._worker = None
        self._shutting_down = False
        self._removed_keys: set = set()
        self._sent_admin_keys: set = set()
        self._syncing = False   # re-entrancy guard for tree <-> model bridge
        self._bulk = False      # defer model->tree sync during bulk changes
        self._scanned_once = False

        self.tabs = QTabWidget()
        self.scan_tab = QWidget()
        self.tabs.addTab(self.scan_tab, "Scan")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self.tabs)
        self._build_scan_tab()

    # ----- panels -----
    def add_panel(self, title: str, widget: QWidget) -> None:
        self.tabs.addTab(widget, title)

    def panel_titles(self) -> List[str]:
        return [self.tabs.tabText(i) for i in range(self.tabs.count())]

    # ----- default factories (look workers up at call time) -----
    def _default_scan_worker(self, only: List[str]):
        return workers.ScanWorker(self._config, only=only)

    def _default_clean_worker(self, items, *, dry_run: bool, use_quarantine: bool):
        return workers.CleanWorker(items, self._config, dry_run=dry_run,
                                   use_quarantine=use_quarantine)

    # ----- UI -----
    def _build_scan_tab(self) -> None:
        # The registry detectors live on their own (Windows-only) Registry
        # tab: never listed, scanned or shown here.
        self.cleaner_model = _CleanerDelegateModel(self._config, self,
                                                   exclude=catalog.REGISTRY_IDS)
        self.item_model = ItemTableModel(self, allow_admin_items=self._allow_admin)
        self.proxy = _ItemFilterProxy(self)
        self.proxy.setSourceModel(self.item_model)

        self.scan_button = QPushButton("Scan")
        self.scan_button.setAccessibleName("Scan")
        self.clean_button = QPushButton("Clean selected")
        self.clean_button.setAccessibleName("Clean selected")
        self.clean_button.setEnabled(False)
        self.select_visible_button = QPushButton("Select all visible")
        self.select_visible_button.setAccessibleName("Select all visible")
        self.select_none_button = QPushButton("Select none")
        self.select_none_button.setAccessibleName("Select none")
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setAccessibleName("Cancel")
        self.cancel_button.setEnabled(False)
        self.dry_run_check = QCheckBox("Dry run")
        self.dry_run_check.setChecked(True)
        self.dry_run_check.setAccessibleName("Dry run")
        self.quarantine_check = QCheckBox("Keep a copy (undo)")
        self.quarantine_check.setChecked(True)
        self.quarantine_check.setAccessibleName("Keep a copy (undo)")
        self.export_button = QPushButton("Export JSON...")
        self.export_button.setAccessibleName("Export JSON")
        self.export_button.setEnabled(False)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by cleaner or description")
        self.filter_edit.setAccessibleName("Filter items")
        self.filter_edit.setClearButtonEnabled(True)
        for tb in self.filter_edit.findChildren(QToolButton):
            tb.setAccessibleName("Clear filter")

        # Two rows keep the window narrow enough for small screens.
        self.safe_only_button = QPushButton("Safe only")
        self.safe_only_button.setAccessibleName("Safe only")
        self.developer_button = QPushButton("Developer")
        self.developer_button.setAccessibleName("Developer")
        self.raw_toggle = QPushButton("Raw list")
        self.raw_toggle.setCheckable(True)
        self.raw_toggle.setAccessibleName("Raw list")
        self.safety_combo = QComboBox()
        self.safety_combo.setAccessibleName("Safety level filter")
        self.safety_combo.addItem("All", None)
        for sv in (Safety.SAFE, Safety.REVIEW, Safety.ADMIN, Safety.PERMANENT):
            self.safety_combo.addItem(sv.value, sv)
        self.show_empty_check = QCheckBox("Show empty")
        self.show_empty_check.setAccessibleName("Show empty")

        self.filter_edit.setMinimumWidth(160)
        row1 = QHBoxLayout()
        for w in (self.scan_button, self.clean_button, self.cancel_button):
            row1.addWidget(w)
        row1.addStretch(1)
        row1.addWidget(self.filter_edit, 1)
        row2 = QHBoxLayout()
        for w in (self.select_visible_button, self.select_none_button,
                  self.dry_run_check, self.quarantine_check):
            row2.addWidget(w)
        row2.addStretch(1)
        row2.addWidget(self.export_button)
        row3 = QHBoxLayout()
        row3.addWidget(self.safe_only_button)
        row3.addWidget(self.developer_button)
        row3.addWidget(self.safety_combo)
        row3.addWidget(self.show_empty_check)
        row3.addStretch(1)
        row3.addWidget(self.raw_toggle)
        self.toolbar_rows = (row1, row2)  # row3: curated-view controls
        self.toolbar_row3 = row3

        self.cleaner_list = QListView()
        self.cleaner_list.setModel(self.cleaner_model)
        self.cleaner_list.setAccessibleName("Cleaners")
        self.cleaner_list.setTextElideMode(Qt.TextElideMode.ElideRight)
        # Collapsible "Choose what to scan" section.
        self.cleaner_toggle = QToolButton()
        self.cleaner_toggle.setText("Choose what to scan")
        self.cleaner_toggle.setAccessibleName("Choose what to scan")
        self.cleaner_toggle.setCheckable(True)
        self.cleaner_toggle.setChecked(True)
        self.cleaner_toggle.setToolButtonStyle(
            Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.cleaner_toggle.setArrowType(Qt.ArrowType.DownArrow)
        self.cleaner_toggle.toggled.connect(self._on_cleaner_toggled)
        cleaner_box = QWidget()
        cb_lay = QVBoxLayout(cleaner_box)
        cb_lay.setContentsMargins(0, 0, 0, 0)
        cb_lay.addWidget(self.cleaner_toggle)
        cb_lay.addWidget(self.cleaner_list, 1)

        self.tree = GroupedResults(allow_admin_items=self._allow_admin,
                                   admin_reason=self._admin_reason,
                                   home=str(Path.home()))
        self.stack = QStackedWidget()
        self.stack.addWidget(self.tree)   # page 0: curated tree (default)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setAccessibleName("Scan results")
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.table.setWordWrap(False)
        for cb in self.table.findChildren(QAbstractButton):
            cb.setAccessibleName("Select all rows")  # the table's corner button
        self.table.verticalHeader().setVisible(False)
        hdr = self.table.horizontalHeader()
        hdr.setStretchLastSection(False)
        for col in (0, 1, 3, 4, 5):
            hdr.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.selectionModel().currentRowChanged.connect(self._on_current_changed)

        # Read-only text box: wraps long unbroken paths, keyboard focusable
        # and selectable.
        self.detail_label = QPlainTextEdit()
        self.detail_label.setReadOnly(True)
        self.detail_label.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.detail_label.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.detail_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        self.detail_label.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.detail_label.setAccessibleName("Item details")
        self._set_detail("Select an item to see details.")

        self.status_label = QLabel("")
        self.status_label.setAccessibleName("Status")

        self.stack.addWidget(self.table)  # page 1: Raw list
        right = QSplitter(Qt.Orientation.Vertical)
        right.addWidget(self.stack)
        right.addWidget(self.detail_label)
        right.setStretchFactor(0, 4)
        right.setStretchFactor(1, 1)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(cleaner_box)
        split.addWidget(right)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 3)

        lay = QVBoxLayout(self.scan_tab)
        lay.addLayout(row1)
        lay.addLayout(row2)
        lay.addLayout(row3)
        lay.addWidget(split, 1)
        lay.addWidget(self.status_label)

        QWidget.setTabOrder(self.stack, self.detail_label)
        self.scan_button.clicked.connect(self.start_scan)
        self.clean_button.clicked.connect(self.start_clean)
        self.cancel_button.clicked.connect(self.cancel_current)
        self.export_button.clicked.connect(self._on_export_clicked)
        self.filter_edit.textChanged.connect(self.proxy.set_filter_text)
        self.select_visible_button.clicked.connect(self.select_all_visible)
        self.select_none_button.clicked.connect(self.select_none_visible)
        self.safe_only_button.clicked.connect(self.select_safe_only)
        self.developer_button.clicked.connect(self.select_developer)
        self.raw_toggle.toggled.connect(self._on_raw_toggled)
        self.safety_combo.currentIndexChanged.connect(self._on_filters_changed)
        self.show_empty_check.toggled.connect(self._on_show_empty)
        self.filter_edit.textChanged.connect(self._on_filters_changed)
        self.tree.selection_changed.connect(self._tree_to_model)
        self.tree.currentItemChanged.connect(self._on_tree_current)
        self.item_model.dataChanged.connect(self._model_changed)
        self.item_model.modelReset.connect(self._rebuild_tree)

    # ----- curated tree <-> item model bridge -----
    def _on_cleaner_toggled(self, on: bool) -> None:
        self.cleaner_list.setVisible(on)
        self.cleaner_toggle.setArrowType(
            Qt.ArrowType.DownArrow if on else Qt.ArrowType.RightArrow)

    def _on_raw_toggled(self, on: bool) -> None:
        self.stack.setCurrentIndex(1 if on else 0)

    def _on_show_empty(self, on: bool) -> None:
        self.tree.set_raw_items_visible(on)
        self._rebuild_tree()

    def _infos(self) -> dict:
        return {self.cleaner_model.info_at(r).id: self.cleaner_model.info_at(r)
                for r in range(self.cleaner_model.rowCount())}

    def _current_groups(self) -> List[curation.Group]:
        """Groups for the items now in the model (all safety levels)."""
        if self._result is None:
            return []
        m = self.item_model
        present = {item_key(m.item_at(r)) for r in range(m.rowCount())}
        res = ScanResult(reports=[
            dataclasses.replace(r, items=[i for i in r.items if item_key(i) in present])
            for r in self._result.reports])
        return curation.build_groups(
            res, self._infos(), show_empty=self.show_empty_check.isChecked())

    def _rebuild_tree(self) -> None:
        if self._syncing:
            return
        groups = self._current_groups()
        gsafety = {g.cleaner_id: g.safety for g in groups}
        data = self.safety_combo.currentData()
        want = Safety(data) if data else None
        self.proxy.set_safety(want, gsafety)
        text = self.filter_edit.text().strip().lower()
        shown = []
        for g in groups:
            if want is not None and g.safety is not want:
                continue
            if text:
                g = self._filter_group(g, text)
                if g is None:
                    continue
            if not self.show_empty_check.isChecked() and g.zero:
                # Empty items are not displayed, so they must not be selectable.
                g = dataclasses.replace(g, items=[i for i in g.items if not is_empty(i)],
                                        zero=[])
            shown.append(g)
        self._syncing = True
        try:
            self.tree.set_groups(shown, None)
            self.tree.set_checked_keys(self._model_checked_keys())
        finally:
            self._syncing = False

    def _filter_group(self, g, text):
        """Same rule as the raw list filter: cleaner name or description."""
        name = self.item_model._names.get(g.cleaner_id, g.cleaner_id).lower()

        def keep(items):
            return [i for i in items if text in name or text in i.description.lower()]

        items = keep(g.items)
        if not items:
            return None
        return dataclasses.replace(
            g, items=items, shown=keep(g.shown), rest=keep(g.rest),
            zero=keep(g.zero), total_size=sum(i.size for i in items))

    def _on_filters_changed(self, *_a) -> None:
        self._rebuild_tree()

    def _model_checked_keys(self) -> set:
        return {item_key(i) for i in self.item_model.checked_items()}

    def _model_changed(self, *_a) -> None:
        if self._syncing or self._bulk:
            return
        self._model_to_tree()

    def _model_to_tree(self) -> None:
        if self._syncing:
            return
        self._syncing = True
        try:
            self.tree.set_checked_keys(self._model_checked_keys())
        finally:
            self._syncing = False

    def _tree_to_model(self) -> None:
        if self._syncing:
            return
        self._syncing = True
        try:
            keys = self.tree.checked_keys()
            universe = {item_key(i) for g in self.tree._groups for i in g.items}
            m = self.item_model
            for r in range(m.rowCount()):
                k = item_key(m.item_at(r))
                if k in universe and m.is_checked(r) != (k in keys):
                    m.set_checked(r, k in keys)
        finally:
            self._syncing = False

    def _set_selection(self, predicate) -> None:
        """Replace the selection with the checkable items matching predicate."""
        m = self.item_model
        self._bulk = True
        try:
            for r in self._actionable_rows():
                it = m.item_at(r)
                m.set_checked(r, gm.is_bulk_selectable(it) and bool(predicate(it)))
        finally:
            self._bulk = False
        self._model_to_tree()

    def select_safe_only(self) -> None:
        infos = self._infos()
        self._set_selection(
            lambda i: curation.safety_of(i, infos.get(i.cleaner_id)) is Safety.SAFE
            and i.kind is ItemKind.PATH
            and not i.requires_root and not i.report_only)

    def select_developer(self) -> None:
        infos = self._infos()

        def _dev(i: CleanableItem) -> bool:
            info = infos.get(i.cleaner_id)
            cat = info.category if info else catalog.category_of(i.cleaner_id)
            return cat == "dev"
        self._set_selection(_dev)

    def _on_tree_current(self, current, _previous=None) -> None:
        p = GroupedResults._payload(current)
        item = getattr(p, "item", None)
        if item is None:
            self._set_detail("Select an item to see details.")
            return
        self._set_detail(self.detail_text(item, allow_admin=self._allow_admin,
                                          problem=self.item_model.admin_problem(item),
                                          unavailable_reason=self._admin_reason))

    # ----- detail -----
    def _on_current_changed(self, current: QModelIndex, _previous=None) -> None:
        if not current.isValid():
            self._set_detail("Select an item to see details.")
            return
        row = self.proxy.mapToSource(current).row()
        item = self.item_model.item_at(row)
        self._set_detail(self.detail_text(item, allow_admin=self._allow_admin,
                                          problem=self.item_model.admin_problem(item),
                                          unavailable_reason=self._admin_reason))

    def _set_detail(self, text: str) -> None:
        self.detail_label.setPlainText(text)
        self.detail_label.setToolTip(text)  # full text

    @staticmethod
    def detail_text(item: CleanableItem, allow_admin: bool = True,
                    problem: Optional[str] = None,
                    unavailable_reason: str = "") -> str:
        lines = [item.description]
        registry = item.kind is ItemKind.REGISTRY
        if item.kind is ItemKind.COMMAND:
            lines.append("Command: " + " ".join(item.command or []))
        elif registry:
            lines.append("Registry: " + item_target(item))
        else:
            lines.append(f"Path: {item.path}")
        if item.hint:
            lines.append(f"{'Evidence' if registry else 'Hint'}: {item.hint}")
        if item.report_only:
            lines.append("Review only: Cleanix never deletes this item.")
        if registry:
            if regpromises.registry_undo_shipped():
                lines.append("Backed up before removal (.reg in quarantine).")
        else:
            lines.append(f"Size: {human_size(item.size)}")
        if item.requires_root:
            lines.append("Requires administrator")
            if not allow_admin:
                lines.append(unavailable_reason or (
                    "Needs administrator permission; not available "
                    "until elevation is supported."))
            elif problem:
                lines.append(f"Not selectable: {problem}.")
        return "\n".join(lines)

    # ----- busy state -----
    def _set_busy(self, busy: bool) -> None:
        self.scan_button.setEnabled(not busy)
        self.clean_button.setEnabled(not busy and self._result is not None)
        self.export_button.setEnabled(not busy and self._result is not None)
        self.cancel_button.setEnabled(busy)

    def cancel_current(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self.status_label.setText("Cancelling...")

    def _visible_rows(self) -> List[int]:
        return [self.proxy.mapToSource(self.proxy.index(r, 0)).row()
                for r in range(self.proxy.rowCount())]

    def _actionable_rows(self) -> List[int]:
        """Visible rows of the page being shown; on the tree page only items
        the tree displays (empty items only with Show empty)."""
        rows = self._visible_rows()
        if self.stack.currentWidget() is not self.tree:
            return rows
        shown = {item_key(i) for g in self.tree._groups for i in g.items}
        m = self.item_model
        return [r for r in rows if item_key(m.item_at(r)) in shown]

    def visible_checked_items(self) -> List[CleanableItem]:
        m = self.item_model
        return [m.item_at(r) for r in self._actionable_rows() if m.is_checked(r)]

    def _set_visible(self, on: bool) -> None:
        self._bulk = True
        try:
            rows = self._actionable_rows() if on else self._visible_rows()
            for r in rows:
                if on and not gm.is_bulk_selectable(self.item_model.item_at(r)):
                    continue  # never bulk-tick report-only or registry rows
                self.item_model.set_checked(r, on)
        finally:
            self._bulk = False
        self._model_to_tree()

    def select_all_visible(self) -> None:
        self._set_visible(True)

    def select_none_visible(self) -> None:
        self._set_visible(False)

    def shutdown(self) -> None:
        """Cancel any running worker; safe to call repeatedly."""
        # Keep _worker set: the thread may still run until its terminal signal,
        # so the start guard must stay up. _shutting_down blocks new work.
        already = self._shutting_down
        self._shutting_down = True
        if self._worker is not None and not already:
            self._worker.cancel()

    def _run(self, worker) -> None:
        self._worker = worker
        worker.progress.connect(self._on_progress)
        self._set_busy(True)
        workers.start_worker(worker)

    # ----- scan -----
    def start_scan(self) -> None:
        if self._worker is not None or self._shutting_down:
            return
        only = self.cleaner_model.enabled_ids()
        if not only:
            self.status_label.setText("Select at least one cleaner to scan.")
            return
        self.status_label.setText("Scanning...")
        worker = self._scan_factory(only)
        worker.finished.connect(self._on_scan_finished)
        worker.cancelled.connect(self._on_cancelled)
        worker.failed.connect(self._on_failed)
        self._run(worker)

    def _on_progress(self, name: str, done: int, total: int) -> None:
        if name == elevation.ADMIN_WAIT_MESSAGE:
            # The elevated step cannot be stopped from here.
            self.cancel_button.setEnabled(False)
        self.status_label.setText(f"{name} ({done}/{total})" if total else name)

    @staticmethod
    def without_registry(result: ScanResult) -> ScanResult:
        """``result`` without the registry detectors' reports (they belong
        to the Registry tab, never to the Scan tab's tree or table)."""
        reg = frozenset(catalog.REGISTRY_IDS)
        if not any(r.cleaner_id in reg for r in result.reports):
            return result
        return ScanResult(reports=[r for r in result.reports if r.cleaner_id not in reg])

    def _on_scan_finished(self, result) -> None:
        self._worker = None
        result = self.without_registry(result)
        self._result = result
        self._removed_keys = set()
        infos = self._infos()

        def _pre(item: CleanableItem) -> bool:
            info = infos.get(item.cleaner_id)
            if is_empty(item) and not self.show_empty_check.isChecked():
                return False  # not displayed, so never pre-checked
            return info is not None and catalog.preselect(item, info)

        self.item_model.set_result(result, _pre)
        self.table.sortByColumn(3, Qt.SortOrder.DescendingOrder)
        if not self._scanned_once:
            self._scanned_once = True
            self.cleaner_toggle.setChecked(False)  # collapse after first scan
        if result.cleanable_size <= 0 and result.report_only_items():
            self.status_label.setText(
                f"{result.total_items} findings to review (nothing to free)")
        else:
            self.status_label.setText(
                f"Found {result.total_items} items, "
                f"{human_size(result.cleanable_size)} to free")
        self._set_busy(False)
        self.scan_finished.emit(result)

    def _on_cancelled(self) -> None:
        self._worker = None
        self.status_label.setText("Cancelled.")
        self._set_busy(False)

    def _on_failed(self, message: str) -> None:
        self._worker = None
        self.status_label.setText(f"Failed: {message}")
        self._set_busy(False)

    # ----- clean -----
    @staticmethod
    def confirm_text(items: List[CleanableItem], hidden: int, keep_copy: bool) -> str:
        size = human_size(sum(i.size for i in items))
        lines = [f"{len(items)} selected item(s), {size}."]
        shipped = regpromises.registry_undo_shipped()
        reg = [i for i in items if i.kind is ItemKind.REGISTRY]
        reg_user = sum(1 for i in reg if not i.requires_root)
        reg_admin = len(reg) - reg_user
        other = [i for i in items if i.kind is not ItemKind.REGISTRY]
        admin = sum(1 for i in other if i.requires_root)
        commands = sum(1 for i in other
                       if i.kind is ItemKind.COMMAND and not i.requires_root)
        if keep_copy:
            if other and admin < len(other):
                lines.append("A copy of each removed file is kept so you can restore it"
                             + (" (except administrator items)." if admin else "."))
            if commands:
                lines.append(f"{commands} command item(s) cannot be kept or undone.")
        elif other:
            lines.append("Files and commands will be permanently removed; registry "
                         "entries are still backed up." if reg and shipped else
                         "These items will be permanently removed. This cannot be undone.")
        if reg and not shipped:
            lines.append(regpromises.PERMANENT_LINE)
        if reg_user and shipped:
            lines.append(f"{reg_user} registry entr{'y' if reg_user == 1 else 'ies'} "
                         "will be backed up first and can be restored from the "
                         "Quarantine tab.")
        if reg_admin and shipped:
            lines.append(f"{reg_admin} administrator registry entr"
                         f"{'y' if reg_admin == 1 else 'ies'} will be backed up first; "
                         "restoring them needs an Administrator terminal "
                         "(cleanix restore).")
        if admin:
            lines.append(f"{admin} item(s) need administrator permission: you will be "
                         "asked once, and they are removed permanently (cannot be undone).")
        if hidden:
            lines.append(f"{hidden} more checked item(s) are hidden by the filter "
                         "and will NOT be cleaned.")
        lines.append("Continue?")
        return "\n".join(lines)

    def confirm_clean(self, text: str) -> bool:
        answer = QMessageBox.question(
            self, "Cleanix", text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        return answer == QMessageBox.StandardButton.Yes

    def start_clean(self) -> None:
        if self._worker is not None or self._shutting_down:
            return
        items = self.visible_checked_items()
        if not items:
            self.status_label.setText("No visible items selected.")
            return
        dry_run = self.dry_run_check.isChecked()
        keep = self.quarantine_check.isChecked()
        if not dry_run:
            m = self.item_model
            total_checked = sum(1 for r in range(m.rowCount()) if m.is_checked(r))
            text = self.confirm_text(items, total_checked - len(items), keep)
            if not self.confirm_clean(text):
                return
        self.status_label.setText("Dry run..." if dry_run else "Cleaning...")
        # Administrator items actually sent in this clean (see _on_clean_finished).
        self._sent_admin_keys = {item_key(i) for i in items if i.requires_root}
        worker = self._clean_factory(items, dry_run=dry_run, use_quarantine=keep)
        worker.finished.connect(self._on_clean_finished)
        worker.cancelled.connect(self._on_cancelled)
        worker.failed.connect(self._on_failed)
        self._run(worker)

    def _on_clean_finished(self, summary) -> None:
        self._worker = None
        self._set_busy(False)
        dry = getattr(summary.result, "dry_run", False)
        verb = "Would free" if dry else "Freed"
        text = f"{verb} {human_size(summary.freed)} ({summary.removed} items)"
        if summary.cancelled:
            text = "Cancelled. " + text
        if summary.errors:
            text += f", {len(summary.errors)} errors"
        admin_lines = elevation.admin_outcome_lines(summary)
        # Administrator rows stay in the table: the helper only returns
        # counts, so they cannot be matched to outcomes; the text says to
        # scan again.
        status = f"{text}. {admin_lines[0]}" if admin_lines else text
        if getattr(summary, "late_cancel", False):
            status += " " + elevation.LATE_CANCEL_LINE
        self.status_label.setText(status)
        if not dry:
            # Done rows leave the table; a rescan is needed for fresh state.
            done = {item_key(o.item) for o in summary.result.outcomes if o.removed}
            self.item_model.remove_keys(done)
            self._removed_keys |= done
            sent = self._sent_admin_keys
            if getattr(summary, "admin_selected", 0) and sent:
                # Admin rows stay (unknown per-item outcome) but the ones sent
                # in this clean are unchecked so a second click never
                # re-prompts for them; other (e.g. hidden) rows are untouched.
                m = self.item_model
                for r in range(m.rowCount()):
                    it = m.item_at(r)
                    if it.requires_root and item_key(it) in sent:
                        m.set_checked(r, False)
            self._on_current_changed(self.table.currentIndex())
        if not self._shutting_down:
            # No modal dialog from a window that is closing (it may be hidden
            # while an administrator step finishes).
            self.show_results(summary, "\n".join([text] + admin_lines))
        self.clean_finished.emit(summary)

    def show_results(self, summary, text: str) -> None:
        lines = [text]
        for o in summary.errors[:10]:
            lines.append(f"{item_target(o.item)}: {o.error}")
        QMessageBox.information(self, "Cleanix results", "\n".join(lines))

    # ----- export -----
    def export_scan_json(self, path: Path) -> None:
        if self._result is None:
            raise ValueError("no scan result to export")
        result = self._result
        if self._removed_keys:  # leave already-deleted items out of the export
            result = ScanResult(reports=[
                dataclasses.replace(r, items=[
                    i for i in r.items if item_key(i) not in self._removed_keys])
                for r in result.reports])
        Path(path).write_text(report.scan_to_json(result), encoding="utf-8")

    def _on_export_clicked(self) -> None:
        name, _ = QFileDialog.getSaveFileName(
            self, "Export scan as JSON", "cleanix-scan.json", "JSON (*.json)")
        if not name:
            return
        try:
            self.export_scan_json(Path(name))
        except (OSError, ValueError) as exc:  # never raise into the Qt slot
            self.status_label.setText(f"Export failed: {exc}")
            return
        self.status_label.setText(f"Exported to {name}")
