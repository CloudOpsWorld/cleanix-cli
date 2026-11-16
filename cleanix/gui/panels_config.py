"""Power-mode panels: Schedule, Settings and Findings (standalone widgets)."""

from __future__ import annotations

from typing import Callable, Dict, List

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from cleanix import config, scheduler
from cleanix.core.models import ScanResult
from cleanix.core.utils import human_size
from cleanix.gui import reveal


class _WheelGuardMixin:
    """Ignore wheel events unless focused, so scrolling the form never edits values."""

    def _guard_init(self) -> None:
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    def wheelEvent(self, event):  # noqa: N802
        if self.hasFocus():
            super().wheelEvent(event)
        else:
            event.ignore()


class GuardedSpinBox(_WheelGuardMixin, QSpinBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._guard_init()


class GuardedDoubleSpinBox(_WheelGuardMixin, QDoubleSpinBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._guard_init()


class ElidedLabel(QLabel):
    """Single-line label that elides with "..." and keeps the full text as tooltip."""

    def __init__(self, text: str = "", tooltip: str | None = None, parent=None):
        super().__init__(parent)
        self._full = ""
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setMinimumWidth(40)
        self.set_full_text(text, tooltip)

    def set_full_text(self, text: str, tooltip: str | None = None) -> None:
        self._full = text
        self.setToolTip(tooltip if tooltip is not None else text)
        self._elide()

    def full_text(self) -> str:
        return self._full

    def _elide(self) -> None:
        fm = self.fontMetrics()
        width = max(self.width() - 2, 10)
        self.setText(fm.elidedText(self._full, Qt.TextElideMode.ElideRight, width))

    def resizeEvent(self, event):  # noqa: N802
        super().resizeEvent(event)
        self._elide()


def _message_label() -> QLabel:
    lab = QLabel()
    lab.setWordWrap(True)
    lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lab


def _set_message(lab: QLabel, text: str) -> None:
    lab.setText(text)
    lab.setToolTip(text)


def _button(text: str, name: str | None = None) -> QPushButton:
    b = QPushButton(text)
    b.setAccessibleName(name or text)
    return b


# ---------------------------------------------------------------- schedule


class SchedulePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._backend = None
        lay = QVBoxLayout(self)
        self.status_label = _message_label()
        self.status_label.setAccessibleName("Schedule status")
        self.frequency_combo = QComboBox()
        self.frequency_combo.setAccessibleName("Scan frequency")
        self.install_button = _button("Install", "Install scheduled scan")
        self.remove_button = _button("Remove", "Remove scheduled scan")
        self.message_label = _message_label()
        self.message_label.setAccessibleName("Schedule message")
        self.note_label = _message_label()
        self.note_label.setText(
            "Scheduled runs only scan and write a report; they never delete anything."
        )
        self.note_label.setAccessibleName("Schedule note")

        lay.addWidget(self.status_label)
        row = QHBoxLayout()
        row.addWidget(QLabel("Frequency:"))
        row.addWidget(self.frequency_combo)
        row.addWidget(self.install_button)
        row.addWidget(self.remove_button)
        row.addStretch(1)
        lay.addLayout(row)
        lay.addWidget(self.message_label)
        lay.addWidget(self.note_label)
        lay.addStretch(1)
        self.setTabOrder(self.frequency_combo, self.install_button)
        self.setTabOrder(self.install_button, self.remove_button)

        try:
            self._backend = scheduler.backend()
            self.frequency_combo.addItems(list(self._backend.FREQUENCIES))
            idx = self.frequency_combo.findText("weekly")
            if idx >= 0:
                self.frequency_combo.setCurrentIndex(idx)
        except Exception as exc:  # noqa: BLE001
            self._backend = None
            _set_message(self.message_label, f"Scheduling is unavailable: {exc}")
            for w in (self.frequency_combo, self.install_button, self.remove_button):
                w.setEnabled(False)
        self.install_button.clicked.connect(self._install)
        self.remove_button.clicked.connect(self._remove)
        self.refresh_status()

    def refresh_status(self) -> None:
        if self._backend is None:
            _set_message(self.status_label, "Status: unavailable")
            return
        try:
            text = f"Status: {self._backend.status()}"
        except Exception as exc:  # noqa: BLE001
            text = f"Status: unavailable ({exc})"
        _set_message(self.status_label, text)

    def _run(self, fn: Callable[[], str]) -> None:
        try:
            _set_message(self.message_label, str(fn()))
        except Exception as exc:  # noqa: BLE001  (never raise into the Qt loop)
            _set_message(self.message_label, f"Error: {exc}")
        self.refresh_status()

    def _install(self) -> None:
        freq = self.frequency_combo.currentText()
        self._run(lambda: self._backend.install(freq))

    def _remove(self) -> None:
        self._run(lambda: self._backend.uninstall())


# ---------------------------------------------------------------- settings

_INT_MAX = 2**31 - 1


class SettingsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.editors: Dict[str, QWidget] = {}
        self.reset_buttons: Dict[str, QPushButton] = {}
        self._baseline: Dict[str, object] = {}

        outer = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        form = QFormLayout(body)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        types = config._field_types()
        for key in config.field_names():
            editor = self._make_editor(key, types[key])
            self.editors[key] = editor
            reset = _button("Reset", f"Reset {key} to default")
            reset.clicked.connect(lambda _=False, k=key: self._reset(k))
            self.reset_buttons[key] = reset
            help_lab = ElidedLabel(config.FIELD_HELP.get(key, ""))
            help_lab.setAccessibleName(f"{key} help")
            cell = QWidget()
            cl = QVBoxLayout(cell)
            cl.setContentsMargins(0, 0, 0, 0)
            top = QHBoxLayout()
            top.addWidget(editor, 1)
            top.addWidget(reset)
            cl.addLayout(top)
            cl.addWidget(help_lab)
            form.addRow(key, cell)

        self.save_button = _button("Save", "Save settings")
        self.save_button.clicked.connect(self._save)
        self.path_label = ElidedLabel()
        self.message_label = _message_label()
        self.message_label.setAccessibleName("Settings message")
        bottom = QHBoxLayout()
        bottom.addWidget(self.save_button)
        bottom.addWidget(self.path_label, 1)
        outer.addLayout(bottom)
        outer.addWidget(self.message_label)

        order: List[QWidget] = []
        for key in self.editors:
            order += [self.editors[key], self.reset_buttons[key]]
        order.append(self.save_button)
        for a, b in zip(order, order[1:]):
            self.setTabOrder(a, b)

        self._load_all()

    @staticmethod
    def _make_editor(key: str, typ: type) -> QWidget:
        if typ is bool:
            w: QWidget = QCheckBox()
        elif typ is int:
            w = GuardedSpinBox()
            w.setRange(-_INT_MAX, _INT_MAX)
        elif typ is float:
            w = GuardedDoubleSpinBox()
            w.setDecimals(3)
            w.setRange(-1e12, 1e12)
        elif typ is list:
            w = QPlainTextEdit()
            w.setMaximumHeight(90)
            w.setTabChangesFocus(True)
            w.setPlaceholderText("one entry per line")
        else:
            w = QLineEdit()
        w.setAccessibleName(key)
        w.setToolTip(config.FIELD_HELP.get(key, key))
        return w

    # -- value plumbing
    def _get(self, key: str):
        w = self.editors[key]
        if isinstance(w, QCheckBox):
            return w.isChecked()
        if isinstance(w, (QSpinBox, QDoubleSpinBox)):
            return w.value()
        if isinstance(w, QPlainTextEdit):
            return [ln.strip() for ln in w.toPlainText().splitlines() if ln.strip()]
        return w.text()

    def _set(self, key: str, value) -> None:
        w = self.editors[key]
        if isinstance(w, QCheckBox):
            w.setChecked(bool(value))
        elif isinstance(w, QSpinBox):
            w.setValue(int(value))
        elif isinstance(w, QDoubleSpinBox):
            w.setValue(float(value))
        elif isinstance(w, QPlainTextEdit):
            items = value if isinstance(value, (list, tuple)) else [value]
            w.setPlainText("\n".join(str(v) for v in items))
        else:
            w.setText(str(value))

    def _load_all(self) -> None:
        try:
            cfg = config.Config.load()
        except Exception as exc:  # noqa: BLE001
            cfg = config.Config()
            _set_message(self.message_label, f"Could not read settings: {exc}")
        for key in self.editors:
            try:
                self._set(key, getattr(cfg, key))
            except (TypeError, ValueError):
                self._set(key, getattr(config.Config(), key))
            self._baseline[key] = self._get(key)
        self._show_path()

    def _show_path(self) -> None:
        try:
            p = str(config.config_file_path())
        except Exception as exc:  # noqa: BLE001
            p = f"(unknown: {exc})"
        self.path_label.set_full_text(f"Config file: {p}")

    def _save(self) -> None:
        saved: List[str] = []
        try:
            for key in self.editors:
                value = self._get(key)
                if value != self._baseline[key]:
                    config.write_user_override(key, value)
                    self._baseline[key] = value
                    saved.append(key)
        except Exception as exc:  # noqa: BLE001
            _set_message(self.message_label, f"Error saving settings: {exc}")
            return
        self._show_path()
        _set_message(
            self.message_label,
            f"Saved: {', '.join(saved)}" if saved else "No changes to save.",
        )

    def _reset(self, key: str) -> None:
        try:
            removed = config.remove_user_override(key)
            cfg = config.Config.load()
            self._set(key, getattr(cfg, key))
            self._baseline[key] = self._get(key)
        except Exception as exc:  # noqa: BLE001
            _set_message(self.message_label, f"Error resetting {key}: {exc}")
            return
        _set_message(
            self.message_label,
            f"{key} reset to default." if removed else f"{key} had no override.",
        )


# ---------------------------------------------------------------- findings


class _FindingRow(QWidget):
    def __init__(self, item, on_reveal: Callable[[str], None], parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(4, 2, 4, 2)
        tip = item.description + (f"\n{item.hint}" if item.hint else "")
        if item.path:
            tip += f"\n{item.path}"
        self.description_label = ElidedLabel(item.description, tip)
        self.description_label.setAccessibleName(f"Finding: {item.description}")
        self.size_label = QLabel(human_size(item.size))
        self.size_label.setAccessibleName("Size")
        self.hint_label = ElidedLabel(item.hint or "")
        self.hint_label.setAccessibleName("Hint")
        lay.addWidget(self.description_label, 3)
        lay.addWidget(self.size_label)
        lay.addWidget(self.hint_label, 2)
        self.reveal_button = None
        if item.path:
            self.reveal_button = _button("Reveal", f"Reveal {item.description}")
            self.reveal_button.clicked.connect(lambda _=False, p=item.path: on_reveal(p))
            lay.addWidget(self.reveal_button)


class FindingsPanel(QWidget):
    """Report-only findings: shown with size and hint; never deletable."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: List[_FindingRow] = []
        outer = QVBoxLayout(self)
        self.summary_label = QLabel("No findings yet. Run a scan.")
        self.summary_label.setAccessibleName("Findings summary")
        outer.addWidget(self.summary_label)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._body = QWidget()
        self._lay = QVBoxLayout(self._body)
        self._lay.addStretch(1)
        scroll.setWidget(self._body)
        outer.addWidget(scroll, 1)
        self.message_label = _message_label()
        self.message_label.setAccessibleName("Findings message")
        outer.addWidget(self.message_label)

    def set_result(self, result: ScanResult) -> None:
        for row in self.rows:
            self._lay.removeWidget(row)
            row.setParent(None)
            row.deleteLater()
        self.rows = []
        items = result.report_only_items() if result is not None else []
        prev = None
        for item in items:
            row = _FindingRow(item, self._reveal)
            self._lay.insertWidget(self._lay.count() - 1, row)
            self.rows.append(row)
            if row.reveal_button is not None:
                if prev is not None:
                    self.setTabOrder(prev, row.reveal_button)
                prev = row.reveal_button
        self.summary_label.setText(
            f"{len(items)} finding(s) for review (report only, never deleted)"
            if items
            else "No report-only findings."
        )
        _set_message(self.message_label, "")

    def _reveal(self, path: str) -> None:
        try:
            ok = reveal.reveal_in_file_manager(path)
        except Exception:  # noqa: BLE001
            ok = False
        _set_message(
            self.message_label,
            "" if ok else "Could not open the file manager for this item.",
        )
