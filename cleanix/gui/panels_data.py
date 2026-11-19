"""Power mode data panels: Quarantine and History (standalone widgets)."""

from __future__ import annotations

import time
from typing import Callable, Dict, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cleanix.core import history, quarantine
from cleanix.core.utils import human_size

_MAX_ERRORS_SHOWN = 3


def _default_confirm(message: str) -> bool:
    answer = QMessageBox.question(
        None, "Cleanix", message,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No,
    )
    return answer == QMessageBox.StandardButton.Yes


def _fmt_time(ts: float) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except (OverflowError, OSError, ValueError):
        return "unknown"


def _item(text: str, align_right: bool = False) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    it.setToolTip(text)  # full text, in case the column elides it
    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
    if align_right:
        it.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    return it


def _make_table(headers: List[str], name: str) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setTextElideMode(Qt.TextElideMode.ElideMiddle)
    t.horizontalHeader().setStretchLastSection(True)
    t.verticalHeader().setVisible(False)
    t.setAccessibleName(name)
    return t


class QuarantinePanel(QWidget):
    """Lists quarantine runs; restore, delete one, or empty all (each confirmed)."""

    def __init__(self, parent: Optional[QWidget] = None,
                 confirm: Optional[Callable[[str], bool]] = None):
        super().__init__(parent)
        self._confirm = confirm or _default_confirm
        self._run_ids: List[str] = []

        self.summary_label = QLabel("")
        self.table = _make_table(["Run", "Time", "Items", "Size"], "Quarantine runs")
        self.restore_btn = QPushButton("Restore")
        self.restore_btn.setAccessibleName("Restore selected quarantine run")
        self.delete_btn = QPushButton("Delete run")
        self.delete_btn.setAccessibleName("Delete selected quarantine run")
        self.empty_btn = QPushButton("Empty all")
        self.empty_btn.setAccessibleName("Empty all quarantine runs")
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setAccessibleName("Quarantine status")

        row = QHBoxLayout()
        for b in (self.restore_btn, self.delete_btn, self.empty_btn):
            row.addWidget(b)
        row.addStretch(1)
        lay = QVBoxLayout(self)
        lay.addWidget(self.summary_label)
        lay.addWidget(self.table, 1)
        lay.addLayout(row)
        lay.addWidget(self.status_label)

        self.setTabOrder(self.table, self.restore_btn)
        self.setTabOrder(self.restore_btn, self.delete_btn)
        self.setTabOrder(self.delete_btn, self.empty_btn)

        self.restore_btn.clicked.connect(self._on_restore)
        self.delete_btn.clicked.connect(self._on_delete)
        self.empty_btn.clicked.connect(self._on_empty_all)

    # --- worker-ready helpers (synchronous for now) -------------------------
    def _do_restore(self, run_id: str) -> Dict:
        return quarantine.restore(run_id)

    def _do_purge(self, run_id: str):
        return quarantine.purge_detailed(run_id)

    def _do_purge_all(self):
        return quarantine.purge_all_detailed()

    # --- UI -----------------------------------------------------------------
    def refresh(self) -> None:
        runs = quarantine.list_runs()
        self._run_ids = [r["run_id"] for r in runs]
        self.table.setRowCount(len(runs))
        for row, r in enumerate(runs):
            self.table.setItem(row, 0, _item(str(r["run_id"])))
            self.table.setItem(row, 1, _item(_fmt_time(r.get("created", 0))))
            items = str(r.get("count", 0))
            if r.get("registry", 0) > 0:
                items += f" ({r['registry']} registry)"
            self.table.setItem(row, 2, _item(items, True))
            self.table.setItem(row, 3, _item(human_size(r.get("size", 0)), True))
        total = sum(r.get("size", 0) for r in runs)
        if runs:
            self.summary_label.setText(f"{len(runs)} run(s), {human_size(total)} in quarantine")
        else:
            self.summary_label.setText("Quarantine is empty.")

    def _selected_run(self) -> Optional[str]:
        row = self.table.currentRow()
        sel = self.table.selectionModel().selectedRows()
        if sel:
            row = sel[0].row()
        elif not self.table.selectedItems():
            return None
        if 0 <= row < len(self._run_ids):
            return self._run_ids[row]
        return None

    @staticmethod
    def _errors_text(errors: List[str]) -> str:
        shown = "; ".join(str(e) for e in errors[:_MAX_ERRORS_SHOWN])
        more = len(errors) - _MAX_ERRORS_SHOWN
        return shown + (f" (+{more} more)" if more > 0 else "")

    def _report_purge(self, freed: int, errors: List[str]) -> None:
        if errors:
            self.status_label.setText(
                f"Finished with {len(errors)} error(s): {self._errors_text(errors)}. "
                f"Not everything was removed ({human_size(freed)} actually freed)."
            )
        else:
            self.status_label.setText(f"{human_size(freed)} reclaimed.")

    def _on_restore(self) -> None:
        run_id = self._selected_run()
        if not run_id:
            self.status_label.setText("Select a run first.")
            return
        if not self._confirm(f"Restore run {run_id} to its original locations?"):
            return
        try:
            result = self._do_restore(run_id)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            # OSError: filesystem; ValueError/KeyError/TypeError: corrupt manifest.
            detail = str(exc) if not isinstance(exc, KeyError) else f"missing entry {exc}"
            self.status_label.setText(f"Restore failed: {detail}")
            self.refresh()
            return
        restored, failed = len(result.get("restored", [])), result.get("failed", [])
        text = f"{restored} restored, {len(failed)} failed."
        if failed:
            text += " " + self._errors_text([f"{p} ({why})" for p, why in failed])
        self.status_label.setText(text)
        self.refresh()

    def _on_delete(self) -> None:
        run_id = self._selected_run()
        if not run_id:
            self.status_label.setText("Select a run first.")
            return
        if not self._confirm(f"Permanently delete run {run_id}? This cannot be undone."):
            return
        try:
            freed, errors = self._do_purge(run_id)
        except OSError as exc:
            self.status_label.setText(f"Delete failed: {exc}")
            self.refresh()
            return
        self._report_purge(freed, errors)
        self.refresh()

    def _on_empty_all(self) -> None:
        if not self._confirm("Permanently delete ALL quarantined runs? This cannot be undone."):
            return
        try:
            freed, errors = self._do_purge_all()
        except OSError as exc:
            self.status_label.setText(f"Delete failed: {exc}")
            self.refresh()
            return
        self._report_purge(freed, errors)
        self.refresh()


class SparklineWidget(QWidget):
    """Tiny bar chart painted with QPainter."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._values: List[float] = []
        self.setMinimumHeight(40)
        self.setAccessibleName("Reclaimed space per run")

    def set_values(self, values: List[float]) -> None:
        self._values = list(values)
        self.setToolTip(", ".join(f"{v:g}" for v in self._values) or "No data")
        self.update()

    def values(self) -> List[float]:
        return list(self._values)

    def paintEvent(self, event) -> None:  # noqa: N802
        p = QPainter(self)
        try:
            vals = self._values
            if not vals:
                return
            peak = max(vals) or 1.0
            w, h = self.width(), self.height()
            slot = w / len(vals)
            bar = max(1.0, slot - 2)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(self.palette().highlight().color())
            for i, v in enumerate(vals):
                bh = max(1.0, (v / peak) * (h - 2)) if v > 0 else 1.0
                p.drawRect(int(i * slot), int(h - bh), int(bar), int(bh))
        finally:
            p.end()


class HistoryPanel(QWidget):
    """Lifetime totals, a sparkline of the last 30 runs, and recent runs."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.totals_label = QLabel("")
        self.totals_label.setAccessibleName("Lifetime totals")
        self.sparkline = SparklineWidget()
        self.table = _make_table(["Time", "Mode", "Items", "Reclaimed"], "Recent runs")
        lay = QVBoxLayout(self)
        lay.addWidget(self.totals_label)
        lay.addWidget(self.sparkline)
        lay.addWidget(self.table, 1)

    def refresh(self) -> None:
        s = history.stats()
        entries = s.get("entries", [])
        if not entries:
            self.totals_label.setText("No clean runs yet.")
            self.sparkline.set_values([])
            self.table.setRowCount(0)
            return
        self.totals_label.setText(
            f"{human_size(s['total_freed'])} reclaimed across {s['runs']} run(s), "
            f"{s['total_items']} item(s)"
        )
        self.sparkline.set_values([e.get("freed", 0) for e in entries[-30:]])
        recent = entries[-100:]  # newest first in the table
        self.table.setRowCount(len(recent))
        for row, e in enumerate(reversed(recent)):
            self.table.setItem(row, 0, _item(_fmt_time(e.get("time", 0))))
            self.table.setItem(row, 1, _item(str(e.get("mode", ""))))
            self.table.setItem(row, 2, _item(str(e.get("items", 0)), True))
            self.table.setItem(row, 3, _item(human_size(e.get("freed", 0)), True))
