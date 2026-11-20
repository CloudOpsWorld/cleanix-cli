"""Power mode's Registry tab (Windows only): the five ``win_reg_*``
detectors, moved out of the Scan tab.

Opt-in like before: nothing is scanned until "Scan registry", nothing is
ticked for you, and Simple mode never touches the registry. Removal reuses
the Scan tab's existing path unchanged: the view's ``clean_worker_factory``
(``elevation.make_clean_worker_factory``) runs ``service.clean`` with a
registry backup for per-user (HKCU) entries and sends machine-wide (HKLM)
entries to the elevated helper's registry action after the GUI backed them
up. The wording follows ``regpromises``: a backup is always written, but
Undo is promised only once ``UNDO_SHIPPED`` is True.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, List, Optional

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from cleanix.config import Config
from cleanix.core import catalog, curation, regpromises
from cleanix.core.models import CleanableItem, ScanResult, item_key, item_target
from cleanix.gui import elevation, workers
from cleanix.gui.dialogs import TextDialog, plain_label
from cleanix.gui.findings_act import shown
from cleanix.gui.grouped_results import GroupedResults

SCAN_TEXT = "Scan registry"
REMOVE_TEXT = "Remove selected"
IDLE_TEXT = ("Registry entries left behind by removed programs. Nothing is "
             "scanned until you click Scan registry, and nothing is ticked for you.")
SHIPPED_LINE = ("Each entry is backed up before removal; per-user entries can be "
                "restored from the Quarantine tab, machine-wide ones need an "
                "Administrator terminal.")


def footer_text() -> str:
    """The honest backup wording (regpromises decides about Undo)."""
    if regpromises.registry_undo_shipped():
        return SHIPPED_LINE
    return regpromises.PERMANENT_LINE


def registry_scan_ids(config: Config) -> List[str]:
    supported = {i.id for i in catalog.list_cleaners(config)}
    return [cid for cid in catalog.REGISTRY_IDS if cid in supported]


def _entries(n: int) -> str:
    return f"{n} registry entry" if n == 1 else f"{n} registry entries"


class RegistryView(QWidget):
    cleaned = Signal(object)  # the clean summary, after a real removal

    def __init__(self, config: Config, *,
                 scan_worker_factory: Optional[Callable] = None,
                 clean_worker_factory: Optional[Callable] = None,
                 allow_admin_items: bool = False,
                 admin_unavailable_reason: str = "",
                 confirm: Optional[Callable[[TextDialog], bool]] = None,
                 show_results: Optional[Callable[[TextDialog], None]] = None,
                 parent: Optional[QWidget] = None) -> None:
        """``scan_worker_factory(config, only=ids)`` (default
        ``workers.ScanWorker``); ``clean_worker_factory(items, dry_run=...,
        use_quarantine=...)`` (default: a plain ``CleanWorker``; MainWindow
        passes the same elevation-aware factory as the Scan tab)."""
        super().__init__(parent)
        self._config = config
        self._scan_factory = scan_worker_factory or workers.ScanWorker
        self._clean_factory = clean_worker_factory or self._plain_clean_worker
        self._confirm = confirm or (lambda d: d.exec() == TextDialog.DialogCode.Accepted)
        self._show_results = show_results or (lambda d: d.exec())
        self._worker = None
        self._shutting_down = False
        self._result: Optional[ScanResult] = None
        self._removed: set = set()
        self.last_dialog: Optional[TextDialog] = None

        self.scan_button = QPushButton(SCAN_TEXT)
        self.scan_button.setAccessibleName(SCAN_TEXT)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setAccessibleName("Cancel registry scan or removal")
        self.cancel_button.setEnabled(False)
        self.status_label = plain_label(IDLE_TEXT, "Registry status")
        self.tree = GroupedResults(allow_admin_items=allow_admin_items,
                                   admin_reason=admin_unavailable_reason,
                                   home=str(Path.home()))
        self.tree.setAccessibleName("Registry entries grouped by detector")
        self.selected_label = plain_label("", "Selected registry entries")
        self.footer_label = plain_label(footer_text(), "Registry backup note")
        self.remove_button = QPushButton(REMOVE_TEXT)
        self.remove_button.setAccessibleName("Remove selected registry entries")
        self.remove_button.setEnabled(False)

        bar = QHBoxLayout()
        bar.addWidget(self.scan_button)
        bar.addWidget(self.cancel_button)
        bar.addStretch(1)
        bottom = QHBoxLayout()
        bottom.addWidget(self.selected_label, 1)
        bottom.addWidget(self.remove_button)
        lay = QVBoxLayout(self)
        lay.addLayout(bar)
        lay.addWidget(self.status_label)
        # The tree sizes itself to its rows (GroupedResults caps its height),
        # so the free space goes below the footer, not between the rows.
        lay.addWidget(self.tree)
        lay.addWidget(self.footer_label)
        lay.addLayout(bottom)
        lay.addStretch(1)

        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button.clicked.connect(self.cancel_current)
        self.remove_button.clicked.connect(self.start_clean)
        self.tree.selection_changed.connect(self._update_footer)
        self._update_footer()

    def _plain_clean_worker(self, items, *, dry_run: bool, use_quarantine: bool):
        return workers.CleanWorker(items, self._config, dry_run=dry_run,
                                   use_quarantine=use_quarantine)

    # ------------------------------------------------------------- state
    def selected_items(self) -> List[CleanableItem]:
        return self.tree.checked_items()

    def _update_footer(self) -> None:
        n = len(self.tree.checked_items())
        self.selected_label.setText(f"Selected: {_entries(n)}" if n else
                                    "Nothing selected. Tick entries to remove them.")
        self.remove_button.setEnabled(n > 0 and self._worker is None)
        self.footer_label.setText(footer_text())

    def set_allow_admin_items(self, allow: bool, reason: str = "") -> None:
        self.tree.set_allow_admin_items(allow, reason)
        self._update_footer()

    def _set_busy(self, busy: bool) -> None:
        self.scan_button.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.tree.setEnabled(not busy)
        self._update_footer()
        if busy:
            self.remove_button.setEnabled(False)

    def cancel_current(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self.status_label.setText("Cancelling...")

    def shutdown(self) -> None:
        already = self._shutting_down
        self._shutting_down = True
        if self._worker is not None and not already:
            self._worker.cancel()

    def _run(self, worker) -> None:
        self._worker = worker
        worker.progress.connect(self._on_progress)
        self._set_busy(True)
        workers.start_worker(worker)

    def _on_progress(self, name: str, done: int, total: int) -> None:
        if name == elevation.ADMIN_WAIT_MESSAGE:
            self.cancel_button.setEnabled(False)
        self.status_label.setText(f"{shown(name)} ({done}/{total})" if total else shown(name))

    def _idle(self, text: str) -> None:
        self._worker = None
        self._set_busy(False)
        self.status_label.setText(text)

    # ------------------------------------------------------------- scan
    def start_scan(self) -> None:
        if self._worker is not None or self._shutting_down:
            return
        ids = registry_scan_ids(self._config)
        if not ids:
            self.status_label.setText("The registry detectors do not apply to this system.")
            return
        self.status_label.setText("Scanning the registry...")
        worker = self._scan_factory(self._config, only=ids)
        worker.finished.connect(self._on_scan_finished)
        worker.cancelled.connect(self._on_cancelled)
        worker.failed.connect(self._on_failed)
        self._run(worker)

    def set_result(self, result: ScanResult) -> None:
        """Show the registry detectors' reports of ``result``, grouped by
        detector in their fixed order. Nothing is ticked."""
        reg = list(catalog.REGISTRY_IDS)
        self._result = ScanResult(reports=[r for r in result.reports
                                           if r.cleaner_id in reg])
        self._removed = set()
        self._render()

    def _render(self) -> None:
        result = self._result or ScanResult()
        if self._removed:
            result = ScanResult(reports=[
                type(r)(r.cleaner_id, r.name, r.description,
                        items=[i for i in r.items if item_key(i) not in self._removed])
                for r in result.reports])
        infos = {i.id: i for i in catalog.list_cleaners(self._config)}
        order = list(catalog.REGISTRY_IDS)
        groups = curation.build_groups(result, infos)
        groups.sort(key=lambda g: order.index(g.cleaner_id) if g.cleaner_id in order
                    else len(order))
        self.tree.set_groups(groups, None)
        self._update_footer()

    def _on_scan_finished(self, result) -> None:
        self.set_result(result)
        n = sum(len(g.items) for g in self.tree._groups)
        self._idle(f"Found {_entries(n)}. Tick the ones to remove." if n
                   else "No dead registry entries found.")

    def _on_cancelled(self) -> None:
        self._idle("Cancelled.")

    def _on_failed(self, message: str) -> None:
        self._idle(f"Failed: {shown(message)}")

    # ------------------------------------------------------------- clean
    def confirm_dialog(self, items: List[CleanableItem]) -> TextDialog:
        from cleanix.gui.power_view import PowerView

        text = PowerView.confirm_text(items, 0, True)
        lines = [ln for ln in text.splitlines() if ln != "Continue?"]
        body = "\n".join(f"{shown(i.description)}\n    {shown(item_target(i))}"
                         for i in items)
        return TextDialog("Cleanix: remove registry entries",
                          f"Remove {_entries(len(items))}?", body,
                          summary="\n".join(lines), accept_text="Remove", parent=self)

    def start_clean(self) -> None:
        if self._worker is not None or self._shutting_down:
            return
        items = self.tree.checked_items()
        if not items:
            return
        dialog = self.confirm_dialog(items)
        self.last_dialog = dialog
        if not self._confirm(dialog):
            self.status_label.setText("Not removed. Nothing was changed.")
            return
        self.status_label.setText("Removing registry entries...")
        # The Scan tab's own path: backups are always written for registry
        # entries (service.clean / the GUI's HKLM backup before the helper).
        worker = self._clean_factory(items, dry_run=False, use_quarantine=True)
        worker.finished.connect(self._on_clean_finished)
        worker.cancelled.connect(self._on_cancelled)
        worker.failed.connect(self._on_failed)
        self._run(worker)

    def result_text(self, summary) -> str:
        lines = [f"Removed {_entries(int(getattr(summary, 'removed', 0) or 0))}."]
        if summary.cancelled:
            lines[0] = "Stopped. " + lines[0]
        for o in list(summary.errors)[:20]:
            lines.append(f"{shown(item_target(o.item))}: {shown(o.error)}")
        if summary.quarantine_run:
            lines.append(f"Backups were written to quarantine run {shown(summary.quarantine_run)}.")
            if not regpromises.registry_undo_shipped():
                lines.append(regpromises.PERMANENT_LINE)
        if getattr(summary, "undo_record_error", None):
            lines.append(f"Warning: {shown(summary.undo_record_error)}")
        lines.extend(shown(ln) for ln in elevation.admin_outcome_lines(summary))
        return "\n".join(lines)

    def _on_clean_finished(self, summary) -> None:
        done = {item_key(o.item) for o in summary.result.outcomes if o.removed}
        self._removed |= done
        self._render()
        self._idle(f"Removed {_entries(len(done))}.")
        self.cleaned.emit(summary)
        if not self._shutting_down:
            dialog = TextDialog("Cleanix: registry results",
                                f"Removed {_entries(len(done))}.",
                                self.result_text(summary), parent=self)
            self.last_dialog = dialog
            self._show_results(dialog)
