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
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from cleanix.config import Config
from cleanix.core import catalog, report
from cleanix.core.models import CleanableItem, ItemKind, ScanResult, item_key
from cleanix.core.utils import human_size
from cleanix.gui import elevation, workers
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
        self.setSortRole(Qt.ItemDataRole.UserRole)

    def set_filter_text(self, text: str) -> None:
        begin = getattr(self, "beginFilterChange", None)
        self._text = text.strip().lower()
        if begin is not None:
            begin()
            self.endFilterChange()
        else:
            self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:  # noqa: N802
        if not self._text:
            return True
        src = self.sourceModel()
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
                 parent: Optional[QWidget] = None) -> None:
        """``scan_worker_factory(only_ids)`` and
        ``clean_worker_factory(items, dry_run=..., use_quarantine=...)`` return
        worker QObjects (see cleanix.gui.workers)."""
        super().__init__(parent)
        self._config = config
        self._allow_admin = allow_admin_items
        self._scan_factory = scan_worker_factory or self._default_scan_worker
        self._clean_factory = clean_worker_factory or self._default_clean_worker
        self._result: Optional[ScanResult] = None
        self._worker = None
        self._shutting_down = False
        self._removed_keys: set = set()
        self._sent_admin_keys: set = set()

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
        self.cleaner_model = _CleanerDelegateModel(self._config, self)
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

        toolbar = QHBoxLayout()
        for w in (self.scan_button, self.clean_button, self.cancel_button,
                  self.select_visible_button, self.select_none_button,
                  self.dry_run_check, self.quarantine_check, self.export_button):
            toolbar.addWidget(w)
        toolbar.addStretch(1)
        toolbar.addWidget(self.filter_edit)

        self.cleaner_list = QListView()
        self.cleaner_list.setModel(self.cleaner_model)
        self.cleaner_list.setAccessibleName("Cleaners")
        self.cleaner_list.setTextElideMode(Qt.TextElideMode.ElideRight)

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
        self.table.horizontalHeader().setStretchLastSection(True)
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

        right = QSplitter(Qt.Orientation.Vertical)
        right.addWidget(self.table)
        right.addWidget(self.detail_label)
        right.setStretchFactor(0, 4)
        right.setStretchFactor(1, 1)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self.cleaner_list)
        split.addWidget(right)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 3)

        lay = QVBoxLayout(self.scan_tab)
        lay.addLayout(toolbar)
        lay.addWidget(split, 1)
        lay.addWidget(self.status_label)

        QWidget.setTabOrder(self.table, self.detail_label)
        self.scan_button.clicked.connect(self.start_scan)
        self.clean_button.clicked.connect(self.start_clean)
        self.cancel_button.clicked.connect(self.cancel_current)
        self.export_button.clicked.connect(self._on_export_clicked)
        self.filter_edit.textChanged.connect(self.proxy.set_filter_text)
        self.select_visible_button.clicked.connect(self.select_all_visible)
        self.select_none_button.clicked.connect(self.select_none_visible)

    # ----- detail -----
    def _on_current_changed(self, current: QModelIndex, _previous=None) -> None:
        if not current.isValid():
            self._set_detail("Select an item to see details.")
            return
        row = self.proxy.mapToSource(current).row()
        item = self.item_model.item_at(row)
        self._set_detail(self.detail_text(item, allow_admin=self._allow_admin,
                                          problem=self.item_model.admin_problem(item)))

    def _set_detail(self, text: str) -> None:
        self.detail_label.setPlainText(text)
        self.detail_label.setToolTip(text)  # full text

    @staticmethod
    def detail_text(item: CleanableItem, allow_admin: bool = True,
                    problem: Optional[str] = None) -> str:
        lines = [item.description]
        if item.kind is ItemKind.COMMAND:
            lines.append("Command: " + " ".join(item.command or []))
        else:
            lines.append(f"Path: {item.path}")
        if item.hint:
            lines.append(f"Hint: {item.hint}")
        if item.report_only:
            lines.append("Review only: Cleanix never deletes this item.")
        lines.append(f"Size: {human_size(item.size)}")
        if item.requires_root:
            lines.append("Requires administrator")
            if not allow_admin:
                lines.append("Needs administrator permission; not available "
                             "until elevation is supported.")
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

    def visible_checked_items(self) -> List[CleanableItem]:
        m = self.item_model
        return [m.item_at(r) for r in self._visible_rows() if m.is_checked(r)]

    def select_all_visible(self) -> None:
        for r in self._visible_rows():
            self.item_model.set_checked(r, True)  # refuses report-only rows

    def select_none_visible(self) -> None:
        for r in self._visible_rows():
            self.item_model.set_checked(r, False)

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

    def _on_scan_finished(self, result) -> None:
        self._worker = None
        self._result = result
        self._removed_keys = set()
        infos = {self.cleaner_model.info_at(r).id: self.cleaner_model.info_at(r)
                 for r in range(self.cleaner_model.rowCount())}

        def _pre(item: CleanableItem) -> bool:
            info = infos.get(item.cleaner_id)
            return info is not None and catalog.preselect(item, info)

        self.item_model.set_result(result, _pre)
        self.table.sortByColumn(3, Qt.SortOrder.DescendingOrder)
        self.status_label.setText(
            f"Found {result.total_items} items, {human_size(result.total_size)}")
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
        admin = sum(1 for i in items if i.requires_root)
        commands = sum(1 for i in items
                       if i.kind is ItemKind.COMMAND and not i.requires_root)
        if keep_copy:
            if admin < len(items):
                lines.append("A copy of each removed file is kept so you can restore it"
                             + (" (except administrator items)." if admin else "."))
            if commands:
                lines.append(f"{commands} command item(s) cannot be kept or undone.")
        else:
            lines.append("These items will be permanently removed. This cannot be undone.")
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
            lines.append(f"{o.item.path or ' '.join(o.item.command or [])}: {o.error}")
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
        if name:
            self.export_scan_json(Path(name))
