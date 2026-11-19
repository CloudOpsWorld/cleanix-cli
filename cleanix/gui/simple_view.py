"""Simple mode: Scan, review curated groups, confirm, Clean, Undo.

Results are curated groups (``curation.build_groups``) shown in
``GroupedResults`` trees. Only items that ``catalog.preselect`` accepts are
pre-selected. Groups with Review safety go to a collapsed "Needs your
review" section with nothing ticked; every other group that preselects
nothing sits unticked in a collapsed "Also found (not selected)" section.

Worker signals are connected to bound methods of this (GUI-thread) widget so
the handlers run on the GUI thread. The ``QThread`` returned by
``start_worker`` is never kept or touched.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import QRect, QSize, Qt, Signal, Slot
from PySide6.QtGui import QFontMetrics, QPainter
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from cleanix.config import Config
from cleanix.core import catalog, curation, quarantine
from cleanix.core.models import CleanableItem, ItemKind, ScanResult
from cleanix.core.platform import WINDOWS, current_os
from cleanix.core.utils import human_size
from cleanix.gui import elevation, workers
from cleanix.gui.grouped_results import GroupedResults

IDLE_HEADLINE = "Free up disk space"
IDLE_REASSURANCE = ("Nothing is deleted until you review it. "
                    "Most cleanups can be undone.")
DEEP_SCAN_TEXT = "Deep scan (slower: duplicates, big files, Mac leftovers)"
SLOW = catalog.SLOW_SCAN_IDS


def _default_scan_factory(config: Config, deep: bool = False):
    """Quick scans skip the slow cleaners; ``deep`` runs everything."""
    return workers.ScanWorker(config, exclude=None if deep else list(SLOW))


_OPT_IN = ("trash", "system")


REGISTRY_NOTE = "Registry leftovers are checked only in Power mode."


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
    # Selected Trash / Recycle Bin items, and how many of them are plain
    # files the GUI cleans itself (PATH, not requires_root): those go to
    # quarantine like any other file when a copy is kept.
    trash_items: int = 0
    # Selected items that need administrator permission (requires_root): the
    # elevated helper removes them permanently, never into quarantine. Not
    # counted in ``irreversible``.
    admin_items: int = 0
    trash_path_items: int = 0


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


class ConfirmCleanDialog(QDialog):
    def __init__(self, info: ConfirmInfo, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Confirm clean")
        self._count = info.count
        self._size = info.size
        self._irreversible = info.irreversible
        self._trash_items = info.trash_items
        self._trash_paths = min(info.trash_path_items, info.trash_items)
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
        kept = self._trash_paths if self.keep_copy_checkbox.isChecked() else 0
        t = self._trash_items - kept
        if t:
            parts.append(
                f"Including {t} item{'s' if t != 1 else ''} from Trash / Recycle Bin "
                "which are removed permanently.")
        if kept:
            parts.append(
                f"{kept} item{'s' if kept != 1 else ''} from Trash / Recycle Bin "
                f"{'are' if kept != 1 else 'is'} kept in quarantine like the other files.")
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
    # Emitted after a clean produced a summary (also a partial, cancelled one).
    clean_finished = Signal(object)
    # Emitted after Undo restored (part of) a quarantine run.
    undone = Signal()

    def __init__(self, config: Config, *, scan_worker_factory: Optional[Callable] = None,
                 clean_worker_factory: Optional[Callable] = None,
                 confirm: Optional[Callable[[ConfirmInfo], Tuple[bool, bool]]] = None,
                 allow_admin_items: bool = False,
                 admin_unavailable_reason: str = "",
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._config = config
        self._allow_admin = allow_admin_items
        # Shown for administrator items when they cannot be offered (e.g.
        # the helper cannot start from this installation).
        self._admin_reason = admin_unavailable_reason
        self._kept_copy = True
        self._all_irreversible = False
        # Factories mirror the worker constructors: scan(config, deep=...) and
        # clean(items, config, dry_run=..., use_quarantine=...).
        self._scan_factory = scan_worker_factory or _default_scan_factory
        self._clean_factory = clean_worker_factory or workers.CleanWorker
        self._confirm = confirm or _default_confirm
        self._state = SimpleState.IDLE
        self._worker = None
        self._cancel_requested = False
        self._shutting_down = False
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
        self.headline_label = QLabel(IDLE_HEADLINE)
        font = self.headline_label.font()
        font.setPointSizeF(font.pointSizeF() * 1.8)
        font.setBold(True)
        self.headline_label.setFont(font)
        self.headline_label.setWordWrap(True)
        self.reassurance_label = QLabel(IDLE_REASSURANCE)
        self.reassurance_label.setWordWrap(True)
        self.error_label = QLabel("")
        self.error_label.setWordWrap(True)
        self.scan_button = _button("Scan", "Scan for files to clean")
        sfont = self.scan_button.font()
        sfont.setPointSizeF(sfont.pointSizeF() * 1.3)
        sfont.setBold(True)
        self.scan_button.setFont(sfont)
        self.scan_button.setMinimumHeight(48)
        self.scan_button.setDefault(True)
        self.scan_button.clicked.connect(self.start_scan)
        self.deep_scan_check = QCheckBox(DEEP_SCAN_TEXT)
        self.deep_scan_check.setChecked(False)
        self.registry_note = QLabel(REGISTRY_NOTE)
        self.registry_note.setWordWrap(True)
        self.registry_note.setAccessibleName("Registry leftovers note")
        self.registry_note.setVisible(current_os() == WINDOWS)
        for w in (self.headline_label, self.reassurance_label, self.error_label,
                  self.scan_button, self.deep_scan_check, self.registry_note):
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

    def _section(self, title: str, tree: GroupedResults, min_height: int = 160):
        toggle = QToolButton()
        toggle.setText(title)
        toggle.setCheckable(True)
        toggle.setChecked(False)
        toggle.setArrowType(Qt.ArrowType.RightArrow)
        toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        toggle.setAccessibleName(title)
        container = QWidget()
        box = QVBoxLayout(container)
        box.setContentsMargins(0, 0, 0, 0)
        tree.setMinimumHeight(min_height)
        box.addWidget(tree)
        container.setVisible(False)

        def on_toggled(expanded: bool) -> None:
            container.setVisible(expanded)
            toggle.setArrowType(
                Qt.ArrowType.DownArrow if expanded else Qt.ArrowType.RightArrow)

        toggle.toggled.connect(on_toggled)
        return toggle, container

    def _new_tree(self) -> GroupedResults:
        tree = GroupedResults(
            allow_admin_items=self._allow_admin, admin_reason=self._admin_reason,
            home=str(Path.home()), selectable=self._simple_rule)
        tree.selection_changed.connect(self._refresh_clean_button)
        return tree

    def _build_results(self) -> None:
        self._results_page, lay = self._page()
        self.results_summary = QLabel("")
        self.results_summary.setWordWrap(True)
        self.results_total_label = QLabel("")
        tfont = self.results_total_label.font()
        tfont.setPointSizeF(tfont.pointSizeF() * 1.4)
        tfont.setBold(True)
        self.results_total_label.setFont(tfont)
        lay.addWidget(self.results_total_label)
        lay.addWidget(self.results_summary)
        self._infos: Dict[str, catalog.CleanerInfo] = {}
        self.results_tree = self._new_tree()
        self.also_tree = self._new_tree()
        self.review_tree = self._new_tree()
        self._trees = (self.results_tree, self.also_tree, self.review_tree)
        lay.addWidget(self.results_tree, 1)
        self.also_found_toggle, self.also_found_container = self._section(
            "Also found (not selected)", self.also_tree)
        self.review_toggle, self.review_container = self._section(
            "Needs your review", self.review_tree)
        for w in (self.review_toggle, self.review_container,
                  self.also_found_toggle, self.also_found_container):
            lay.addWidget(w)
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
        # The administrator wait message must be readable in full ("decline
        # the prompt to skip..."): a word-wrapped label replaces the elided
        # status line while it is shown.
        self.clean_wait_label = QLabel("")
        self.clean_wait_label.setWordWrap(True)
        self.clean_wait_label.setTextFormat(Qt.TextFormat.PlainText)
        self.clean_wait_label.setVisible(False)
        self.cancel_clean_button = _button("Cancel", "Cancel clean")
        self.cancel_clean_button.clicked.connect(self.cancel)
        for w in (self.clean_status, self.clean_wait_label, self.clean_progress,
                  self.cancel_clean_button):
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

    def trees(self) -> Tuple[GroupedResults, ...]:
        """The result trees: main, also found, needs review."""
        return self._trees

    def also_found_expanded(self) -> bool:
        return self.also_found_toggle.isChecked()

    def review_expanded(self) -> bool:
        return self.review_toggle.isChecked()

    def set_allow_admin_items(self, allow: bool, reason: str = "") -> None:
        """Admin availability changed: trees and selection follow."""
        self._allow_admin = bool(allow)
        self._admin_reason = reason
        for tree in self._trees:
            tree.set_allow_admin_items(allow, reason)
        self._refresh_clean_button()

    # ---- scan ----------------------------------------------------------
    @Slot()
    def start_scan(self) -> None:
        if self._worker is not None or self._shutting_down:
            return
        self.error_label.setText("")
        self._clear_results()
        self.scan_progress.setRange(0, 0)
        self.scan_status.setText("Scanning...")
        self._cancel_requested = False
        worker = self._scan_factory(
            self._config, deep=self.deep_scan_check.isChecked())
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

    def shutdown(self) -> None:
        """Cancel any running worker and refuse new work; safe to call repeatedly."""
        already = self._shutting_down
        self._shutting_down = True
        if not already:
            self.cancel()

    # ---- results -------------------------------------------------------
    NOT_FROM_SIMPLE = ("Not cleaned from Simple mode: use Power mode to review "
                       "and clean it.")

    def _simple_rule(self, item: CleanableItem) -> Optional[str]:
        """Simple mode cleans only pre-selectable cleaners and the opt-in
        Trash/System categories; everything else is shown read-only."""
        if curation.is_empty(item):
            return "Nothing to clean."
        info = self._infos.get(item.cleaner_id)
        if info is None:
            return self.NOT_FROM_SIMPLE
        if catalog.category_of(item.cleaner_id) in _OPT_IN:
            return None
        return None if catalog.preselect(item, info) else self.NOT_FROM_SIMPLE

    def set_scan_result(self, result: ScanResult) -> None:
        infos: Dict[str, catalog.CleanerInfo] = {
            i.id: i for i in catalog.list_cleaners(self._config, include_unsupported=True)}
        self._infos = infos

        def preselect(item: CleanableItem) -> bool:
            info = infos.get(item.cleaner_id)
            return (info is not None and not curation.is_empty(item)
                    and catalog.preselect(item, info))

        groups = curation.build_groups(result, infos)
        review, main, also = [], [], []
        for g in groups:
            if any(preselect(i) for i in g.items):
                main.append(g)
            elif g.safety is curation.Safety.REVIEW:
                review.append(g)
            else:
                also.append(g)

        self._clear_results()
        self.results_tree.set_groups(main, preselect)
        self.also_tree.set_groups(also, lambda _i: False)
        self.review_tree.set_groups(review, lambda _i: False)
        self.results_tree.setVisible(bool(main))
        self.also_found_toggle.setVisible(bool(also))
        self.review_toggle.setVisible(bool(review))
        if not groups:
            summary = "Nothing found to clean."
        elif result.cleanable_size <= 0:
            summary = f"{result.total_items} findings to review (nothing to free)."
        else:
            n = len(result.cleanable_items())
            summary = f"Found {human_size(result.cleanable_size)} in {n} items."
        self.results_summary.setText(summary)
        self._refresh_clean_button()
        self._set_state(SimpleState.RESULTS)
        self.scanned.emit(result)

    def _clear_results(self) -> None:
        for tree in self._trees:
            tree.set_groups([], lambda _i: False)
        self.also_found_toggle.setChecked(False)
        self.review_toggle.setChecked(False)
        self.results_total_label.setText("")

    def selected_items(self) -> List[CleanableItem]:
        out: List[CleanableItem] = []
        for tree in self._trees:
            out.extend(i for i in tree.checked_items()
                       if not i.report_only and (self._allow_admin or not i.requires_root))
        return out

    def selected_size(self) -> int:
        return sum(i.size for i in self.selected_items())

    def clean_button_text(self) -> str:
        if not self.selected_items():
            return "Nothing selected"
        return f"Clean {human_size(self.selected_size())}"

    @Slot()
    def _refresh_clean_button(self) -> None:
        items = self.selected_items()
        self.clean_button.setText(self.clean_button_text())
        self.clean_button.setEnabled(bool(items))
        self.results_total_label.setText(
            f"{human_size(self.selected_size())} can be freed" if items
            else "Nothing selected")

    # ---- clean ---------------------------------------------------------
    @Slot()
    def _on_clean_clicked(self) -> None:
        items = self.selected_items()
        if not items or self._state is not SimpleState.RESULTS:
            return
        admin = sum(1 for i in items if i.requires_root)
        irreversible = sum(1 for i in items
                           if i.kind is ItemKind.COMMAND and not i.requires_root)
        accepted, keep_copy = self._confirm(ConfirmInfo(
            len(items), sum(i.size for i in items), True, irreversible,
            sum(1 for i in items if catalog.category_of(i.cleaner_id) == "trash"),
            admin_items=admin,
            trash_path_items=sum(1 for i in items
                                 if catalog.category_of(i.cleaner_id) == "trash"
                                 and i.kind is ItemKind.PATH and not i.requires_root)))
        if not accepted:
            return
        self.request_clean.emit(items)
        self._start_clean(items, keep_copy)

    def _start_clean(self, items: List[CleanableItem], keep_copy: bool) -> None:
        if self._worker is not None or self._shutting_down:
            return
        self._cancel_requested = False
        self._kept_copy = keep_copy
        self._all_irreversible = all(i.kind is ItemKind.COMMAND or i.requires_root
                                     for i in items)
        self._start_clean_ui_reset()
        worker = self._clean_factory(
            items, self._config, dry_run=False, use_quarantine=keep_copy)
        self._worker = worker
        worker.progress.connect(self._on_clean_progress)
        worker.finished.connect(self._on_clean_finished)
        worker.cancelled.connect(self._on_clean_cancelled)
        worker.failed.connect(self._on_clean_failed)
        self._set_state(SimpleState.CLEANING)
        workers.start_worker(worker)

    def _start_clean_ui_reset(self) -> None:
        self.clean_progress.setRange(0, 0)
        self.clean_status.setText("Cleaning...")
        self.clean_status.setVisible(True)
        self.clean_wait_label.setVisible(False)
        self.clean_wait_label.setText("")
        self.cancel_clean_button.setEnabled(True)

    @Slot(str, int, int)
    def _on_clean_progress(self, name: str, done: int, total: int) -> None:
        if self._state is not SimpleState.CLEANING:
            return
        if name == elevation.ADMIN_WAIT_MESSAGE:
            # The elevated step cannot be stopped from here: Cancel would lie.
            self.cancel_clean_button.setEnabled(False)
            self.clean_progress.setRange(0, 0)
            self.clean_status.setVisible(False)
            self.clean_wait_label.setText(name)
            self.clean_wait_label.setVisible(True)
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
        self.clean_finished.emit(summary)

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
        self._clear_results()
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
        if res.get("not_restored"):
            text += " Registry restore is not enabled in this version."
        self.undo_label.setText(text)
        self.undo_button.setEnabled(False)
        self.undone.emit()
