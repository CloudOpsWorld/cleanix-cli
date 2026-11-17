"""Simple mode: Scan, review category cards, confirm, Clean, Undo.

Only items that ``catalog.preselect`` accepts are pre-selected; everything
else is shown read-only in a collapsed "Also found" section, except the
``trash`` and ``system`` groups, which can be opted into by ticking them.

Worker signals are connected to bound methods of this (GUI-thread) widget so
the handlers run on the GUI thread. The ``QThread`` returned by
``start_worker`` is never kept or touched.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import QRect, QSize, Qt, Signal, Slot
from PySide6.QtGui import QFontMetrics, QPainter
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from cleanix.config import Config
from cleanix.core import catalog, quarantine
from cleanix.core.models import CleanableItem, ItemKind, ScanResult
from cleanix.core.utils import human_size
from cleanix.gui import elevation, workers

# Category cards that are opt-in (shown under "Also found", unchecked).
_OPT_IN = ("trash", "system")


class SimpleState(Enum):
    IDLE = "idle"
    SCANNING = "scanning"
    RESULTS = "results"
    CLEANING = "cleaning"
    DONE = "done"


@dataclass
class ConfirmInfo:
    count: int
    size: int
    keep_copy: bool = True
    # Selected items that are not PATH items (commands such as emptying the
    # Recycle Bin or pruning containers): never quarantined, never undoable.
    irreversible: int = 0
    trash_items: int = 0
    # Selected items that need administrator permission (requires_root): the
    # elevated helper removes them permanently, never into quarantine. Not
    # counted in ``irreversible``.
    admin_items: int = 0


def admin_confirm_text(n: int) -> str:
    return (f"{n} item(s) need administrator permission: you will be asked once, "
            "and they are removed permanently (cannot be undone).")


class ElidedLabel(QLabel):
    """Single-line label that elides to its width; tooltip has the full text."""

    def __init__(self, text: str = "", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._full = ""
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setMinimumWidth(0)
        self.setFullText(text)

    def fullText(self) -> str:
        return self._full

    def setFullText(self, text: str) -> None:
        self._full = text
        self.setToolTip(text)
        super().setText(text)
        self.updateGeometry()
        self.update()

    def setText(self, text: str) -> None:  # noqa: N802 - Qt API
        self.setFullText(text)

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        return QSize(0, QFontMetrics(self.font()).height())

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(min(QFontMetrics(self.font()).horizontalAdvance(self._full), 400),
                     QFontMetrics(self.font()).height())

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        fm = painter.fontMetrics()
        rect = self.contentsRect()
        elided = fm.elidedText(self._full, Qt.TextElideMode.ElideRight, rect.width())
        painter.drawText(QRect(rect), int(self.alignment()) | int(Qt.AlignmentFlag.AlignVCenter),
                         elided)

    def elidedText(self) -> str:
        return QFontMetrics(self.font()).elidedText(
            self._full, Qt.TextElideMode.ElideRight, max(self.contentsRect().width(), 1))


class CategoryCard(QFrame):
    """One category: label, item count, size and a checkbox.

    ``mode``: ``"select"`` (pre-selected), ``"optin"`` (trash/system, unchecked,
    enabled) or ``"readonly"`` (shown only, checkbox disabled and unchecked).
    """

    toggled = Signal()

    def __init__(self, category: str, label: str, items: List[CleanableItem], *,
                 mode: str = "select", checked: bool = False,
                 admin_blocked: bool = False,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.category = category
        self.mode = mode
        self.items = list(items)
        self.size = sum(i.size for i in self.items)
        self.setFrameShape(QFrame.Shape.StyledPanel)

        self.checkbox = QCheckBox()
        self.checkbox.setChecked(checked and mode != "readonly")
        self.checkbox.setEnabled(mode != "readonly")
        self.label_widget = ElidedLabel(label)
        self.count_label = QLabel(f"{len(self.items)} item{'s' if len(self.items) != 1 else ''}")
        self.size_label = QLabel(human_size(self.size))
        self.checkbox.setAccessibleName(f"{label}, {human_size(self.size)}")
        self.checkbox.toggled.connect(self._on_toggled)

        row = QHBoxLayout()
        row.addWidget(self.checkbox)
        row.addWidget(self.label_widget, 1)
        row.addWidget(self.count_label)
        row.addWidget(self.size_label)
        outer = QVBoxLayout(self)
        outer.addLayout(row)

        self.hint_label: Optional[ElidedLabel] = None
        if mode == "readonly":
            # Each item contributes its own reason (distinct, in order).
            reasons: List[str] = []
            for i in self.items:
                if i.requires_root and admin_blocked and not i.report_only:
                    r = "Needs administrator permission"
                else:
                    r = i.hint or "Shown for review; not cleaned from Simple mode."
                if r not in reasons:
                    reasons.append(r)
            text = "; ".join(reasons)
            self.hint_label = ElidedLabel(text)
            outer.addWidget(self.hint_label)

    def _on_toggled(self, _checked: bool) -> None:
        self.toggled.emit()

    def is_checked(self) -> bool:
        return self.checkbox.isChecked()

    def selected_items(self) -> List[CleanableItem]:
        if self.mode == "readonly" or not self.is_checked():
            return []
        return [i for i in self.items if not i.report_only]


class ConfirmCleanDialog(QDialog):
    def __init__(self, info: ConfirmInfo, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Confirm clean")
        self._count = info.count
        self._size = info.size
        self._irreversible = info.irreversible
        self._trash_items = info.trash_items
        self._admin = info.admin_items
        self.summary_label = QLabel(
            f"Clean {info.count} item{'s' if info.count != 1 else ''} "
            f"({human_size(info.size)})?")
        self.warning_label = QLabel()
        self.warning_label.setWordWrap(True)
        self.keep_copy_checkbox = QCheckBox(
            "Keep a copy so I can undo (uses disk space until emptied)")
        self.keep_copy_checkbox.setChecked(info.keep_copy)
        self.keep_copy_checkbox.toggled.connect(self._update_warning)
        if info.irreversible + info.admin_items >= info.count:
            # Nothing selected can be kept: a copy is meaningless.
            self.keep_copy_checkbox.setChecked(False)
            self.keep_copy_checkbox.setEnabled(False)
        self.clean_button = QPushButton("Clean")
        self.clean_button.setDefault(True)
        self.clean_button.setAccessibleName("Clean")
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setAccessibleName("Cancel")
        self.clean_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.clean_button)
        buttons.addWidget(self.cancel_button)
        layout = QVBoxLayout(self)
        for w in (self.summary_label, self.warning_label, self.keep_copy_checkbox):
            layout.addWidget(w)
        layout.addLayout(buttons)
        self._update_warning()

    @Slot()
    def _update_warning(self, *_args) -> None:
        n = self._irreversible
        a = self._admin
        parts = []
        if n:
            parts.append(
                f"{n} selected item{'s' if n != 1 else ''} cannot be undone "
                "(for example emptying the Recycle Bin or pruning containers).")
        if a:
            parts.append(admin_confirm_text(a))
        n += a
        if n >= self._count:
            pass
        elif self.keep_copy_checkbox.isChecked():
            parts.append("The files are kept in quarantine, so "
                         + ("the rest of " if n else "")
                         + "this clean can be undone.")
        else:
            parts.append("The files will be deleted and this cannot be undone.")
        t = self._trash_items
        if t:
            parts.append(
                f"Including {t} item{'s' if t != 1 else ''} from Trash / Recycle Bin "
                "which are removed permanently.")
        self.warning_label.setText(" ".join(parts))

    def keep_copy(self) -> bool:
        return self.keep_copy_checkbox.isChecked()


def _default_confirm(info: ConfirmInfo) -> Tuple[bool, bool]:
    dlg = ConfirmCleanDialog(info)
    accepted = dlg.exec() == QDialog.DialogCode.Accepted
    return accepted, dlg.keep_copy()


def _button(text: str, name: Optional[str] = None) -> QPushButton:
    b = QPushButton(text)
    b.setAccessibleName(name or text)
    return b


class SimpleView(QWidget):
    # Notification only: emitted just BEFORE the clean worker starts, with the
    # items about to be cleaned. The view starts the clean itself.
    request_clean = Signal(list)
    scanned = Signal(object)

    def __init__(self, config: Config, *, scan_worker_factory: Optional[Callable] = None,
                 clean_worker_factory: Optional[Callable] = None,
                 confirm: Optional[Callable[[ConfirmInfo], Tuple[bool, bool]]] = None,
                 allow_admin_items: bool = False,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._config = config
        self._allow_admin = allow_admin_items
        self._kept_copy = True
        self._all_irreversible = False
        # Factories mirror the worker constructors: scan(config) and
        # clean(items, config, dry_run=..., use_quarantine=...).
        self._scan_factory = scan_worker_factory or workers.ScanWorker
        self._clean_factory = clean_worker_factory or workers.CleanWorker
        self._confirm = confirm or _default_confirm
        self._state = SimpleState.IDLE
        self._worker = None
        self._cancel_requested = False
        self._cards: List[CategoryCard] = []
        self._last_summary = None

        self._stack = QStackedWidget()
        outer = QVBoxLayout(self)
        outer.addWidget(self._stack)
        self._build_idle()
        self._build_scanning()
        self._build_results()
        self._build_cleaning()
        self._build_done()
        self._set_state(SimpleState.IDLE)

    # ---- construction -------------------------------------------------
    def _page(self) -> Tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        lay = QVBoxLayout(page)
        self._stack.addWidget(page)
        return page, lay

    def _build_idle(self) -> None:
        self._idle_page, lay = self._page()
        self.intro_label = QLabel("Find files Cleanix can safely remove.")
        self.intro_label.setWordWrap(True)
        self.error_label = QLabel("")
        self.error_label.setWordWrap(True)
        self.scan_button = _button("Scan", "Scan for files to clean")
        self.scan_button.clicked.connect(self.start_scan)
        for w in (self.intro_label, self.error_label, self.scan_button):
            lay.addWidget(w)
        lay.addStretch(1)

    def _build_scanning(self) -> None:
        self._scan_page, lay = self._page()
        self.scan_progress = QProgressBar()
        self.scan_progress.setAccessibleName("Scan progress")
        self.scan_status = ElidedLabel("Scanning...")
        self.cancel_scan_button = _button("Cancel", "Cancel scan")
        self.cancel_scan_button.clicked.connect(self.cancel)
        for w in (self.scan_status, self.scan_progress, self.cancel_scan_button):
            lay.addWidget(w)
        lay.addStretch(1)

    def _build_results(self) -> None:
        self._results_page, lay = self._page()
        self.results_summary = QLabel("")
        self.results_summary.setWordWrap(True)
        lay.addWidget(self.results_summary)
        self._cards_host = QWidget()
        self._cards_layout = QVBoxLayout(self._cards_host)
        self._cards_layout.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._cards_host)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        lay.addWidget(scroll, 1)
        self._main_cards_layout = QVBoxLayout()
        self._cards_layout.addLayout(self._main_cards_layout)
        self.also_found_toggle = QToolButton()
        self.also_found_toggle.setText("Also found (not selected)")
        self.also_found_toggle.setCheckable(True)
        self.also_found_toggle.setChecked(False)
        self.also_found_toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.also_found_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.also_found_toggle.setAccessibleName("Also found (not selected)")
        self.also_found_toggle.toggled.connect(self._on_also_found_toggled)
        self.also_found_container = QWidget()
        self._also_layout = QVBoxLayout(self.also_found_container)
        self._also_layout.setContentsMargins(0, 0, 0, 0)
        self.also_found_container.setVisible(False)
        self._cards_layout.addWidget(self.also_found_toggle)
        self._cards_layout.addWidget(self.also_found_container)
        self._cards_layout.addStretch(1)
        self.clean_button = _button("Nothing selected", "Clean selected items")
        self.clean_button.clicked.connect(self._on_clean_clicked)
        self.rescan_button = _button("Scan again")
        self.rescan_button.clicked.connect(self.start_scan)
        row = QHBoxLayout()
        row.addWidget(self.rescan_button)
        row.addStretch(1)
        row.addWidget(self.clean_button)
        lay.addLayout(row)

    def _build_cleaning(self) -> None:
        self._clean_page, lay = self._page()
        self.clean_progress = QProgressBar()
        self.clean_progress.setAccessibleName("Clean progress")
        self.clean_status = ElidedLabel("Cleaning...")
        self.cancel_clean_button = _button("Cancel", "Cancel clean")
        self.cancel_clean_button.clicked.connect(self.cancel)
        for w in (self.clean_status, self.clean_progress, self.cancel_clean_button):
            lay.addWidget(w)
        lay.addStretch(1)

    def _build_done(self) -> None:
        self._done_page, lay = self._page()
        self.done_label = QLabel("")
        self.done_label.setWordWrap(True)
        self.errors_label = QLabel("")
        # Outcome of the administrator part (empty when there was none).
        self.admin_label = QLabel("")
        self.admin_label.setWordWrap(True)
        self.admin_label.setTextFormat(Qt.TextFormat.PlainText)
        self.undo_label = QLabel("")
        self.undo_label.setWordWrap(True)
        self.undo_button = _button("Undo", "Undo this clean")
        self.undo_button.clicked.connect(self.undo)
        self.again_button = _button("Scan again")
        self.again_button.clicked.connect(self.start_scan)
        for w in (self.done_label, self.errors_label, self.admin_label, self.undo_label):
            lay.addWidget(w)
        row = QHBoxLayout()
        row.addWidget(self.undo_button)
        row.addWidget(self.again_button)
        row.addStretch(1)
        lay.addLayout(row)
        lay.addStretch(1)

    # ---- state ---------------------------------------------------------
    def state(self) -> SimpleState:
        return self._state

    def _set_state(self, state: SimpleState) -> None:
        self._state = state
        page = {
            SimpleState.IDLE: self._idle_page,
            SimpleState.SCANNING: self._scan_page,
            SimpleState.RESULTS: self._results_page,
            SimpleState.CLEANING: self._clean_page,
            SimpleState.DONE: self._done_page,
        }[state]
        self._stack.setCurrentWidget(page)

    def _on_also_found_toggled(self, expanded: bool) -> None:
        self.also_found_container.setVisible(expanded)
        self.also_found_toggle.setArrowType(
            Qt.ArrowType.DownArrow if expanded else Qt.ArrowType.RightArrow)

    def also_found_expanded(self) -> bool:
        return self.also_found_toggle.isChecked()

    # ---- scan ----------------------------------------------------------
    @Slot()
    def start_scan(self) -> None:
        if self._worker is not None:
            return
        self.error_label.setText("")
        self._clear_cards()
        self.scan_progress.setRange(0, 0)
        self.scan_status.setText("Scanning...")
        self._cancel_requested = False
        worker = self._scan_factory(self._config)
        self._worker = worker
        worker.progress.connect(self._on_scan_progress)
        worker.finished.connect(self._on_scan_finished)
        worker.cancelled.connect(self._on_scan_cancelled)
        worker.failed.connect(self._on_scan_failed)
        self._set_state(SimpleState.SCANNING)
        workers.start_worker(worker)

    @Slot(str, int, int)
    def _on_scan_progress(self, name: str, done: int, total: int) -> None:
        if self._state is not SimpleState.SCANNING:
            return
        self.scan_progress.setRange(0, max(total, 1))
        self.scan_progress.setValue(done)
        self.scan_status.setText(f"Scanning: {name}")

    @Slot(object)
    def _on_scan_finished(self, result) -> None:
        if self._state is not SimpleState.SCANNING:
            return
        self._worker = None
        if self._cancel_requested:
            self._set_state(SimpleState.IDLE)
            return
        self.set_scan_result(result)

    @Slot()
    def _on_scan_cancelled(self) -> None:
        if self._state is not SimpleState.SCANNING:
            return
        self._worker = None
        self._set_state(SimpleState.IDLE)

    @Slot(str)
    def _on_scan_failed(self, message: str) -> None:
        if self._state is not SimpleState.SCANNING:
            return
        self._worker = None
        self.error_label.setText(f"Scan failed: {message}")
        self._set_state(SimpleState.IDLE)

    @Slot()
    def cancel(self) -> None:
        """Ask the running worker to stop; the worker's signal ends the state."""
        if self._worker is None:
            return
        self._cancel_requested = True
        try:
            self._worker.cancel()
        except RuntimeError:
            pass

    # ---- results -------------------------------------------------------
    def set_scan_result(self, result: ScanResult) -> None:
        infos: Dict[str, catalog.CleanerInfo] = {
            i.id: i for i in catalog.list_cleaners(self._config, include_unsupported=True)}
        groups: Dict[Tuple[str, str], List[CleanableItem]] = {}
        for item in result.all_items():
            category = catalog.category_of(item.cleaner_id)
            info = infos.get(item.cleaner_id)
            if item.report_only or info is None:
                mode = "readonly"
            elif item.requires_root and not self._allow_admin:
                mode = "readonly"
            elif category in _OPT_IN:
                mode = "optin"
            elif catalog.preselect(item, info):
                mode = "select"
            else:
                mode = "readonly"
            groups.setdefault((category, mode), []).append(item)

        self._clear_cards()

        order = list(catalog.CATEGORIES)
        for mode in ("select", "optin", "readonly"):
            for category in order:
                items = groups.get((category, mode))
                if not items:
                    continue
                label = catalog.CATEGORIES[category]
                if mode == "readonly":
                    label += " (review only)"
                card = CategoryCard(category, label, items, mode=mode,
                                    checked=(mode == "select"),
                                    admin_blocked=not self._allow_admin)
                card.toggled.connect(self._refresh_clean_button)
                self._cards.append(card)
                (self._main_cards_layout if mode == "select" else self._also_layout
                 ).addWidget(card)

        self.also_found_toggle.setVisible(any(c.mode != "select" for c in self._cards))
        self.also_found_toggle.setChecked(False)
        self.results_summary.setText(
            "Nothing found to clean." if not result.all_items()
            else f"Found {human_size(result.total_size)} in {result.total_items} items.")
        self._refresh_clean_button()
        self._set_state(SimpleState.RESULTS)
        self.scanned.emit(result)

    def _clear_cards(self) -> None:
        for card in self._cards:
            card.setParent(None)
            card.deleteLater()
        self._cards = []
        self.also_found_toggle.setChecked(False)

    def cards(self) -> List[CategoryCard]:
        return list(self._cards)

    def selected_items(self) -> List[CleanableItem]:
        out: List[CleanableItem] = []
        for card in self._cards:
            out.extend(i for i in card.selected_items()
                       if self._allow_admin or not i.requires_root)
        return out

    def selected_size(self) -> int:
        return sum(i.size for i in self.selected_items())

    def clean_button_text(self) -> str:
        if not self.selected_items():
            return "Nothing selected"
        return f"Free {human_size(self.selected_size())}"

    @Slot()
    def _refresh_clean_button(self) -> None:
        self.clean_button.setText(self.clean_button_text())
        self.clean_button.setEnabled(bool(self.selected_items()))

    # ---- clean ---------------------------------------------------------
    @Slot()
    def _on_clean_clicked(self) -> None:
        items = self.selected_items()
        if not items or self._state is not SimpleState.RESULTS:
            return
        admin = sum(1 for i in items if i.requires_root)
        irreversible = sum(1 for i in items
                           if i.kind is not ItemKind.PATH and not i.requires_root)
        accepted, keep_copy = self._confirm(ConfirmInfo(
            len(items), sum(i.size for i in items), True, irreversible,
            sum(1 for i in items if catalog.category_of(i.cleaner_id) == "trash"),
            admin_items=admin))
        if not accepted:
            return
        self.request_clean.emit(items)
        self._start_clean(items, keep_copy)

    def _start_clean(self, items: List[CleanableItem], keep_copy: bool) -> None:
        self._cancel_requested = False
        self._kept_copy = keep_copy
        self._all_irreversible = all(i.kind is not ItemKind.PATH or i.requires_root
                                     for i in items)
        self.clean_progress.setRange(0, 0)
        self.clean_status.setText("Cleaning...")
        self.cancel_clean_button.setEnabled(True)
        worker = self._clean_factory(
            items, self._config, dry_run=False, use_quarantine=keep_copy)
        self._worker = worker
        worker.progress.connect(self._on_clean_progress)
        worker.finished.connect(self._on_clean_finished)
        worker.cancelled.connect(self._on_clean_cancelled)
        worker.failed.connect(self._on_clean_failed)
        self._set_state(SimpleState.CLEANING)
        workers.start_worker(worker)

    @Slot(str, int, int)
    def _on_clean_progress(self, name: str, done: int, total: int) -> None:
        if self._state is not SimpleState.CLEANING:
            return
        if name == elevation.ADMIN_WAIT_MESSAGE:
            # The elevated step cannot be stopped from here: Cancel would lie.
            self.cancel_clean_button.setEnabled(False)
            self.clean_progress.setRange(0, 0)
            self.clean_status.setText(name)
            return
        self.clean_progress.setRange(0, max(total, 1))
        self.clean_progress.setValue(done)
        self.clean_status.setText(f"Cleaning: {name}")

    @Slot(object)
    def _on_clean_finished(self, summary) -> None:
        if self._state is not SimpleState.CLEANING:
            return
        self._worker = None
        self._last_summary = summary
        stopped = bool(getattr(summary, "cancelled", False))
        freed = human_size(summary.freed)
        self.done_label.setText(
            f"Stopped early. Freed {freed} ({summary.removed} items removed)."
            if stopped else f"Freed {freed} ({summary.removed} items removed).")
        n_err = len(summary.errors)
        self.errors_label.setText(f"{n_err} error{'s' if n_err != 1 else ''}")
        admin_lines = elevation.admin_outcome_lines(summary)
        self.admin_label.setText("\n".join(admin_lines))
        self.admin_label.setVisible(bool(admin_lines))
        if summary.quarantine_run:
            self.undo_label.setText(
                "Undo restores only the files kept in quarantine; administrator "
                "items cannot be undone." if admin_lines else "")
        elif self._all_irreversible:
            self.undo_label.setText(
                "Nothing was kept: the selected items cannot be undone.")
        elif not self._kept_copy:
            self.undo_label.setText("Undo is unavailable: you chose not to keep a copy.")
        else:
            self.undo_label.setText("Undo is unavailable: nothing was kept.")
        self.undo_button.setEnabled(bool(summary.quarantine_run))
        self._set_state(SimpleState.DONE)

    @Slot()
    def _on_clean_cancelled(self) -> None:
        # The engine aborted before producing a summary: nothing to report.
        if self._state is not SimpleState.CLEANING:
            return
        self._worker = None
        self._stopped_before_finishing()

    def _stopped_before_finishing(self, detail: str = "") -> None:
        # Some items may already be gone: force a rescan instead of showing
        # stale cards.
        self._clear_cards()
        self.error_label.setText(
            "Clean stopped before finishing; scan again to see what is left."
            + (f" ({detail})" if detail else ""))
        self._set_state(SimpleState.IDLE)

    @Slot(str)
    def _on_clean_failed(self, message: str) -> None:
        if self._state is not SimpleState.CLEANING:
            return
        self._worker = None
        self._stopped_before_finishing(message)

    # ---- undo ----------------------------------------------------------
    @Slot()
    def undo(self) -> None:
        """Restore the last clean's quarantine run.

        Note: ``quarantine.restore`` runs synchronously on the GUI thread; a
        later task may move it to a worker.
        """
        run = getattr(self._last_summary, "quarantine_run", None)
        if self._state is not SimpleState.DONE or not run:
            return
        try:
            res = quarantine.restore(run)
        except Exception as exc:  # noqa: BLE001 - shown to the user
            self.undo_label.setText(f"Undo failed: {exc}")
            return
        restored = len(res.get("restored", []))
        failed = len(res.get("failed", []))
        text = f"Restored {restored} item{'s' if restored != 1 else ''}."
        if failed:
            text += f" {failed} could not be restored."
        self.undo_label.setText(text)
        self.undo_button.setEnabled(False)
