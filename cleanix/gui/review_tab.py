"""Power mode's Review tab: an opt-in findings scan, the Review tree, and
the act flow (plan -> one confirmation -> user items, then one
administrator batch -> results).

Nothing starts by itself: the scan runs only on "Scan for findings", the
slow scenarios only with "Include deep scan (slow)", and nothing is ever
acted on without the confirmation dialog (and, for system-wide items, the
exact typed phrase). See :mod:`cleanix.gui.findings_act` for the flow.
"""

from __future__ import annotations

from typing import Callable, List, Optional

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox, QHBoxLayout, QPushButton, QVBoxLayout, QWidget,
)

from cleanix.config import Config
from cleanix.core import catalog, findings
from cleanix.gui import findings_act, workers
from cleanix.gui.dialogs import TextDialog, plain_label
from cleanix.gui.review_view import ReviewView

SCAN_TEXT = "Scan for findings"
DEEP_TEXT = "Include deep scan (slow)"
IDLE_TEXT = ("Nothing is scanned until you click Scan for findings. Scanning "
             "changes nothing; nothing is ticked for you.")
NO_SCENARIOS = "No findings scenario applies to this system."


def finding_scan_ids(config: Config, deep: bool) -> List[str]:
    """The report-only scenarios to scan: every findings scenario that
    supports this system (user-space ones everywhere, system-wide ones on
    Linux/macOS), without the slow ones unless ``deep``."""
    supported = {i.id for i in catalog.list_cleaners(config)}
    ids = [cid for cid in findings.FINDING_CATEGORIES if cid in supported]
    if not deep:
        ids = [cid for cid in ids if cid not in catalog.SLOW_SCAN_IDS]
    return ids


def _names(config: Config, ids) -> str:
    names = {i.id: i.name for i in catalog.list_cleaners(config)}
    return ", ".join(names.get(cid, cid) for cid in ids)


class ReviewTab(QWidget):
    """The Review tab. Every system-touching step can be injected:
    ``scan_worker_factory(config, only=ids)`` (default
    ``workers.ScanWorker``), ``plan_worker_factory`` / ``act_worker_factory``
    (default ``workers.FindingsPlanWorker`` / ``FindingsActWorker``),
    ``launcher`` (the elevation launcher handed to the act worker; default
    None = the platform prompt), ``confirm(dialog) -> bool`` (default: the
    dialog's ``exec``) and ``show_results(dialog)``."""

    acted = Signal(object)  # findings_act.ActOutcome, after a real act

    def __init__(self, config: Config, *,
                 scan_worker_factory: Optional[Callable] = None,
                 plan_worker_factory: Optional[Callable] = None,
                 act_worker_factory: Optional[Callable] = None,
                 launcher: Optional[Callable] = None,
                 confirm: Optional[Callable[[TextDialog], bool]] = None,
                 show_results: Optional[Callable[[TextDialog], None]] = None,
                 elevation_available: bool = False,
                 elevation_reason: str = "",
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._config = config
        self._scan_factory = scan_worker_factory or workers.ScanWorker
        self._plan_factory = plan_worker_factory or workers.FindingsPlanWorker
        self._act_factory = act_worker_factory or workers.FindingsActWorker
        self._launcher = launcher
        self._confirm = confirm or self._default_confirm
        self._show_results = show_results or self._default_show_results
        self._worker = None
        self._shutting_down = False
        self.last_dialog: Optional[TextDialog] = None
        self.last_outcome = None

        self.scan_button = QPushButton(SCAN_TEXT)
        self.scan_button.setAccessibleName(SCAN_TEXT)
        self.deep_check = QCheckBox(DEEP_TEXT)
        self.deep_check.setChecked(False)
        self.deep_check.setAccessibleName(DEEP_TEXT)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setAccessibleName("Cancel findings scan or action")
        self.cancel_button.setEnabled(False)
        self.scope_label = plain_label("", "What the findings scan looks at")
        self.status_label = plain_label(IDLE_TEXT, "Review status")
        self.view = ReviewView()
        self.view.set_elevation_available(bool(elevation_available), elevation_reason)

        bar = QHBoxLayout()
        bar.addWidget(self.scan_button)
        bar.addWidget(self.deep_check)
        bar.addWidget(self.cancel_button)
        bar.addStretch(1)
        lay = QVBoxLayout(self)
        lay.addLayout(bar)
        lay.addWidget(self.scope_label)
        lay.addWidget(self.status_label)
        lay.addWidget(self.view, 1)

        self.scan_button.clicked.connect(self.start_scan)
        self.cancel_button.clicked.connect(self.cancel_current)
        self.deep_check.toggled.connect(self._update_scope)
        self.view.actRequestedSplit.connect(self._on_act_requested)
        self._update_scope()

    # ------------------------------------------------------------- scope
    def scan_ids(self) -> List[str]:
        return finding_scan_ids(self._config, self.deep_check.isChecked())

    def _update_scope(self, *_a) -> None:
        try:
            ids = self.scan_ids()
            slow = [c for c in finding_scan_ids(self._config, True)
                    if c in catalog.SLOW_SCAN_IDS]
            text = (f"Scans for findings only: {_names(self._config, ids)}."
                    if ids else NO_SCENARIOS)
            if slow and not self.deep_check.isChecked():
                text += (f" The deep scan adds (slow): {_names(self._config, slow)}.")
        except Exception as exc:  # noqa: BLE001 - never raise into Qt
            text = f"Could not list the findings scenarios: {exc}"
        self.scope_label.setText(text)

    def set_elevation_available(self, available: bool, reason: str = "") -> None:
        self.view.set_elevation_available(available, reason)

    # ------------------------------------------------------------- busy
    def _set_busy(self, busy: bool) -> None:
        self.scan_button.setEnabled(not busy)
        self.deep_check.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.view.act_button.setEnabled(not busy and bool(self.view.selected_items()))
        self.view.tree.setEnabled(not busy)
        self.view.permanent_box.setEnabled(not busy)

    def busy(self) -> bool:
        return self._worker is not None

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
        if name == findings_act.ADMIN_WAIT:
            self.cancel_button.setEnabled(False)  # cannot be stopped from here
        self.status_label.setText(f"{name} ({done}/{total})" if total else name)

    def _idle(self, text: str) -> None:
        self._worker = None
        self._set_busy(False)
        self.status_label.setText(text)

    # ------------------------------------------------------------- scan
    def start_scan(self) -> None:
        if self._worker is not None or self._shutting_down:
            return
        ids = self.scan_ids()
        if not ids:
            self.status_label.setText(NO_SCENARIOS)
            return
        self.view.clear()
        self.status_label.setText("Scanning for findings...")
        worker = self._scan_factory(self._config, only=ids)
        worker.finished.connect(self._on_scan_finished)
        worker.cancelled.connect(self._on_cancelled)
        worker.failed.connect(self._on_failed)
        self._run(worker)

    def _on_scan_finished(self, result) -> None:
        self.view.set_scan(result)
        n = sum(len(sc.items) for sc in self.view.model.scenarios)
        self._idle(f"{n} finding(s) to review. Tick what you want to act on."
                   if n else "No findings.")

    def _on_cancelled(self) -> None:
        self._idle("Cancelled. Nothing was changed.")

    def _on_failed(self, message: str) -> None:
        self._idle(f"Failed: {findings_act.shown(message)}")

    # ------------------------------------------------------------- act
    def _on_act_requested(self, user_items, system_items, permanent, survivors) -> None:
        if self._worker is not None or self._shutting_down:
            return
        user_items, system_items = list(user_items), list(system_items)
        if not user_items and not system_items:
            return
        worker = self._plan_factory(user_items, system_items, survivors,
                                    bool(permanent), self._config)
        worker.finished.connect(self._on_plan_ready)
        worker.cancelled.connect(self._on_cancelled)
        worker.failed.connect(self._on_plan_failed)
        self._run(worker)

    def _on_plan_failed(self, message: str) -> None:
        self._idle("The selected items could not be checked "
                   f"({findings_act.shown(message)}); nothing was changed.")

    def confirm_dialog(self, plan) -> TextDialog:
        """The ONE confirmation for ``plan`` (not shown; see ``confirm``)."""
        summary = "\n".join(findings_act.bucket_lines(plan))
        if plan.empty:
            return TextDialog("Cleanix: act on findings", findings_act.headline(plan),
                              findings_act.confirm_text(plan), parent=self)
        n_sys = len(plan.system_offered)
        note = findings_act.PROMPT_FOLLOWS if n_sys else (
            "Your files are acted on when you click Act.")
        phrase = findings_act.CONFIRM_PHRASE if n_sys else None
        label = (f"Type {findings_act.CONFIRM_PHRASE} to act on these {n_sys} "
                 "system-wide item(s) (exactly as shown; anything else keeps Act "
                 "disabled):") if n_sys else ""
        return TextDialog("Cleanix: act on findings", findings_act.headline(plan),
                          findings_act.confirm_text(plan), summary=summary, note=note,
                          accept_text="Act", phrase=phrase, phrase_label=label,
                          parent=self)

    @staticmethod
    def _default_confirm(dialog: TextDialog) -> bool:
        return dialog.exec() == TextDialog.DialogCode.Accepted

    @staticmethod
    def _default_show_results(dialog: TextDialog) -> None:
        dialog.exec()

    def _on_plan_ready(self, plan) -> None:
        self._worker = None
        self._set_busy(False)
        if self._shutting_down:
            return
        dialog = self.confirm_dialog(plan)
        self.last_dialog = dialog
        ok = bool(self._confirm(dialog)) and not plan.empty
        # The typed phrase is checked again here, whatever the dialog did.
        if ok and plan.has_system and not dialog.phrase_ok():
            ok = False
        if not ok:
            self.status_label.setText("Not acted on. Nothing was changed.")
            return
        self.status_label.setText("Acting on your files...")
        worker = self._act_factory(plan, self._config, launcher=self._launcher)
        worker.finished.connect(self._on_act_finished)
        worker.cancelled.connect(self._on_act_cancelled)
        worker.failed.connect(self._on_act_failed)
        self._run(worker)

    def _on_act_cancelled(self) -> None:
        self._on_act_failed("stopped")

    def _on_act_failed(self, message: str) -> None:
        # Something may already be done: never say "nothing was changed".
        self.view.clear()
        self._idle(f"The action failed ({findings_act.shown(message)}); scan again "
                   "to see what is left.")
        self.acted.emit(None)

    def results_dialog(self, outcome) -> TextDialog:
        return TextDialog("Cleanix: results", findings_act.status_line(outcome),
                          findings_act.result_text(outcome), parent=self)

    def _on_act_finished(self, outcome) -> None:
        self.last_outcome = outcome
        # Acted-on (stamped) items must never be offered twice: scan again.
        self.view.clear()
        self._idle(findings_act.status_line(outcome))
        self.acted.emit(outcome)
        if not self._shutting_down:
            dialog = self.results_dialog(outcome)
            self.last_dialog = dialog
            self._show_results(dialog)
