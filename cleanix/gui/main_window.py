"""Main window shell: Simple/Power pages in a stacked layout plus a mode toolbar."""

from __future__ import annotations

from PySide6.QtCore import QSettings
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMainWindow, QStackedWidget, QToolBar, QWidget

SIMPLE, POWER = "simple", "power"
_KEY = "ui/mode"


def _settings() -> QSettings:
    # Explicit format so QSettings.setDefaultFormat() (used by tests) is honoured on every OS.
    return QSettings(QSettings.defaultFormat(), QSettings.Scope.UserScope, "Cleanix", "cleanix")


def _load_mode() -> str:
    try:
        value = _settings().value(_KEY, SIMPLE)
        return value if value in (SIMPLE, POWER) else SIMPLE
    except Exception:
        return SIMPLE


def _save_mode(mode: str) -> None:
    try:
        _settings().setValue(_KEY, mode)
    except Exception:
        pass


class MainWindow(QMainWindow):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Cleanix")
        self.resize(960, 640)
        self.stack = QStackedWidget()
        self.simple_page: QWidget = QWidget()
        self.power_page: QWidget = QWidget()
        self.stack.addWidget(self.simple_page)
        self.stack.addWidget(self.power_page)
        self.setCentralWidget(self.stack)

        self.toolbar = QToolBar("Mode")
        self.toolbar.setMovable(False)
        self.addToolBar(self.toolbar)
        self.power_action = QAction("Power mode", self)
        self.power_action.setCheckable(True)
        self.power_action.toggled.connect(self._on_toggled)
        self.toolbar.addAction(self.power_action)
        btn = self.toolbar.widgetForAction(self.power_action)
        if btn is not None:
            btn.setAccessibleName("Power mode")

        self._mode = SIMPLE
        self.set_mode(_load_mode(), persist=False)

    def current_mode(self) -> str:
        return self._mode

    def set_mode(self, mode: str, persist: bool = True) -> None:
        if mode not in (SIMPLE, POWER):
            mode = SIMPLE
        self._mode = mode
        self.power_action.blockSignals(True)
        self.power_action.setChecked(mode == POWER)
        self.power_action.blockSignals(False)
        self.stack.setCurrentWidget(self.power_page if mode == POWER else self.simple_page)
        if persist:
            _save_mode(mode)

    def _on_toggled(self, checked: bool) -> None:
        self.set_mode(POWER if checked else SIMPLE)

    def _swap(self, old: QWidget, new: QWidget) -> None:
        idx = self.stack.indexOf(old)
        self.stack.removeWidget(old)
        old.deleteLater()
        self.stack.insertWidget(idx, new)

    def set_simple_page(self, widget: QWidget) -> None:
        self._swap(self.simple_page, widget)
        self.simple_page = widget
        self.set_mode(self._mode, persist=False)

    def set_power_page(self, widget: QWidget) -> None:
        self._swap(self.power_page, widget)
        self.power_page = widget
        self.set_mode(self._mode, persist=False)
