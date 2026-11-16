"""Power mode view: Scan tab (cleaner list, item table, detail pane) + panels."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, List, Optional

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
    QPushButton,
    QSplitter,
    QTableView,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from cleanix.config import Config
from cleanix.core import report
from cleanix.core.models import CleanableItem, ItemKind, ScanResult
from cleanix.core.utils import human_size
from cleanix.gui import workers
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
        self._text = text.strip().lower()
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
                 parent: Optional[QWidget] = None) -> None:
        """``scan_worker_factory(only_ids)`` and
        ``clean_worker_factory(items, dry_run=..., use_quarantine=...)`` return
        worker QObjects (see cleanix.gui.workers)."""
        super().__init__(parent)
        self._config = config
        self._scan_factory = scan_worker_factory or self._default_scan_worker
        self._clean_factory = clean_worker_factory or self._default_clean_worker
        self._result: Optional[ScanResult] = None
        self._worker = None

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
        self.item_model = ItemTableModel(self)
        self.proxy = _ItemFilterProxy(self)
        self.proxy.setSourceModel(self.item_model)

        self.scan_button = QPushButton("Scan")
        self.scan_button.setAccessibleName("Scan")
        self.clean_button = QPushButton("Clean selected")
        self.clean_button.setAccessibleName("Clean selected")
        self.clean_button.setEnabled(False)
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

        self.detail_label = QLabel("Select an item to see details.")
        self.detail_label.setAccessibleName("Item details")
        self.detail_label.setWordWrap(True)
        self.detail_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.detail_label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)

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

        self.scan_button.clicked.connect(self.start_scan)
        self.clean_button.clicked.connect(self.start_clean)
        self.cancel_button.clicked.connect(self.cancel_current)
        self.export_button.clicked.connect(self._on_export_clicked)
        self.filter_edit.textChanged.connect(self.proxy.set_filter_text)

    # ----- detail -----
    def _on_current_changed(self, current: QModelIndex, _previous=None) -> None:
        if not current.isValid():
            self.detail_label.setText("Select an item to see details.")
            return
        row = self.proxy.mapToSource(current).row()
        self.detail_label.setText(self.detail_text(self.item_model.item_at(row)))

    @staticmethod
    def detail_text(item: CleanableItem) -> str:
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

    def _run(self, worker) -> None:
        self._worker = worker
        worker.progress.connect(self._on_progress)
        self._set_busy(True)
        workers.start_worker(worker)

    # ----- scan -----
    def start_scan(self) -> None:
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
        self.status_label.setText(f"{name} ({done}/{total})" if total else name)

    def _on_scan_finished(self, result) -> None:
        self._worker = None
        self._result = result
        self.item_model.set_result(result)
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
    def confirm_clean(self, count: int, size: int) -> bool:
        answer = QMessageBox.question(
            self, "Cleanix",
            f"Remove {count} selected items ({human_size(size)})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        return answer == QMessageBox.StandardButton.Yes

    def start_clean(self) -> None:
        items = self.item_model.checked_items()
        if not items:
            self.status_label.setText("No items selected.")
            return
        dry_run = self.dry_run_check.isChecked()
        if not dry_run and not self.confirm_clean(len(items), sum(i.size for i in items)):
            return
        self.status_label.setText("Dry run..." if dry_run else "Cleaning...")
        worker = self._clean_factory(
            items, dry_run=dry_run,
            use_quarantine=self.quarantine_check.isChecked())
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
        self.status_label.setText(text)
        self.show_results(summary, text)
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
        Path(path).write_text(report.scan_to_json(self._result), encoding="utf-8")

    def _on_export_clicked(self) -> None:
        name, _ = QFileDialog.getSaveFileName(
            self, "Export scan as JSON", "cleanix-scan.json", "JSON (*.json)")
        if name:
            self.export_scan_json(Path(name))
