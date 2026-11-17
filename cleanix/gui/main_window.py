"""Main window shell: Simple/Power pages in a stacked layout plus a mode toolbar."""

from __future__ import annotations

import dataclasses
from typing import Callable, Optional

from PySide6.QtCore import QSettings, QTimer, Slot
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QSizePolicy, QStackedWidget, QToolBar, QWidget,
)

from cleanix.config import Config
from cleanix.gui import elevation, workers
from cleanix.gui.panels_config import FindingsPanel, SchedulePanel, SettingsPanel
from cleanix.gui.panels_data import HistoryPanel, QuarantinePanel
from cleanix.gui.power_view import PowerView
from cleanix.gui.simple_view import SimpleView

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
    """The application window: Simple and Power views plus the Power panels.

    Everything that would touch the system can be injected for tests:
    ``config`` (default ``Config.load()``), ``scan_worker_factory``
    (``factory(config, only=None)``, default ``workers.ScanWorker``),
    ``clean_worker_factory`` (``factory(items, cfg=None, *, dry_run,
    use_quarantine)``, default ``elevation.make_clean_worker_factory``) and
    ``elevation_available`` (default ``elevation.elevation_available()``).
    """

    # Close: how long to wait for workers, then how often to check whether a
    # worker that could not be stopped (administrator prompt/helper) is done.
    SHUTDOWN_WAIT_MS = 5000
    QUIT_POLL_MS = 500

    def __init__(self, parent=None, *, config: Optional[Config] = None,
                 scan_worker_factory: Optional[Callable] = None,
                 clean_worker_factory: Optional[Callable] = None,
                 elevation_available: Optional[bool] = None) -> None:
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

        self.shutdown_wait_ms = self.SHUTDOWN_WAIT_MS
        self.quit_poll_ms = self.QUIT_POLL_MS
        self._quit_timer: Optional[QTimer] = None
        self._build_views(config, scan_worker_factory, clean_worker_factory,
                          elevation_available)

    # ---- wiring --------------------------------------------------------
    def _build_views(self, config, scan_factory, clean_factory, allow) -> None:
        if config is None:
            try:
                config = Config.load()
            except Exception:  # noqa: BLE001 - never block startup on a bad file
                config = Config()
        self.config = config
        reason = ""
        if allow is None:
            allow = elevation.elevation_available()
            if not allow:
                reason = elevation.elevation_unavailable_reason()
        self.elevation_allowed = bool(allow)
        self.admin_unavailable_reason = reason
        self._scan_factory = scan_factory or workers.ScanWorker
        if clean_factory is None:
            clean_factory = elevation.make_clean_worker_factory(
                config, elevation=self.elevation_allowed)
        self._clean_factory = clean_factory

        self.simple_view = SimpleView(
            config, scan_worker_factory=self._make_simple_scan_worker,
            clean_worker_factory=clean_factory,
            allow_admin_items=self.elevation_allowed,
            admin_unavailable_reason=reason)
        self.power_view = PowerView(
            config, scan_worker_factory=self._make_power_scan_worker,
            clean_worker_factory=clean_factory,
            allow_admin_items=self.elevation_allowed,
            admin_unavailable_reason=reason)

        self.quarantine_panel = QuarantinePanel()
        self.history_panel = HistoryPanel()
        self.schedule_panel = SchedulePanel()
        self.settings_panel = SettingsPanel()
        self.findings_panel = FindingsPanel()
        for title, panel in (("Quarantine", self.quarantine_panel),
                             ("History", self.history_panel),
                             ("Schedule", self.schedule_panel),
                             ("Settings", self.settings_panel),
                             ("Findings", self.findings_panel)):
            self.power_view.add_panel(title, panel)

        # Signals are emitted on the GUI thread; all slots are bound methods.
        self.power_view.scan_finished.connect(self.findings_panel.set_result)
        self.simple_view.scanned.connect(self.findings_panel.set_result)
        self.power_view.clean_finished.connect(self._on_clean_finished)
        self.simple_view.clean_finished.connect(self._on_clean_finished)
        self.simple_view.undone.connect(self.refresh_data_panels)
        self.settings_panel.saved.connect(self._on_settings_saved)

        self.set_simple_page(self.simple_view)
        self.set_power_page(self.power_view)
        self.refresh_data_panels()

    def _make_simple_scan_worker(self, cfg):
        return self._scan_factory(cfg)

    def _make_power_scan_worker(self, only):
        return self._scan_factory(self.config, only=only)

    @Slot(object)
    def _on_clean_finished(self, _summary) -> None:
        self.refresh_data_panels()

    APPLIED_TEXT = "Settings saved and applied to the next scan."

    @Slot()
    def _on_settings_saved(self) -> None:
        """Reload the config file into the SHARED Config object, in place, so
        both views (which hold the same object) use it from the next scan
        or clean. Never raises."""
        try:
            fresh = Config.load()
            for f in dataclasses.fields(Config):
                setattr(self.config, f.name, getattr(fresh, f.name))
        except Exception as exc:  # noqa: BLE001 - never raise into Qt
            self.settings_panel.append_message(
                f"Saved, but the settings could not be applied to this session: {exc}")
            return
        self.settings_panel.append_message(self.APPLIED_TEXT)
        try:
            self.power_view.status_label.setText(self.APPLIED_TEXT)
        except RuntimeError:
            pass

    @Slot()
    def refresh_data_panels(self) -> None:
        """Reload the Quarantine and History panels; never raises."""
        for panel, label in ((self.quarantine_panel, self.quarantine_panel.status_label),
                             (self.history_panel, self.history_panel.totals_label)):
            try:
                panel.refresh()
            except Exception as exc:  # noqa: BLE001 - never raise into Qt
                label.setText(f"Could not load: {exc}")

    # ---- shutdown ------------------------------------------------------
    def closeEvent(self, event) -> None:  # noqa: N802 - Qt API
        if self._quit_timer is not None:
            # Already hidden, waiting for a worker that cannot be stopped.
            event.ignore()
            return
        for view in (self.power_view, self.simple_view):
            try:
                view.shutdown()
            except RuntimeError:  # view already deleted (swapped out)
                pass
        if workers.cancel_all_and_wait(self.shutdown_wait_ms):
            event.accept()
            return
        # A worker is still running (typically the administrator prompt or
        # helper, which cannot be interrupted). Destroying its QThread would
        # abort the process and leave the request directory behind, so hide
        # and quit once it has finished.
        event.ignore()
        QApplication.setQuitOnLastWindowClosed(False)
        self.hide()
        self._quit_timer = QTimer(self)
        self._quit_timer.setInterval(self.quit_poll_ms)
        self._quit_timer.timeout.connect(self._quit_when_idle)
        self._quit_timer.start()

    @Slot()
    def _quit_when_idle(self) -> None:
        if workers.active_count() == 0:
            if self._quit_timer is not None:
                self._quit_timer.stop()
            self.quit_application()

    def quit_application(self) -> None:
        QApplication.quit()

    def current_mode(self) -> str:
        return self._mode

    def set_mode(self, mode: str, persist: bool = True) -> None:
        if mode not in (SIMPLE, POWER):
            mode = SIMPLE
        self._mode = mode
        self.power_action.blockSignals(True)
        self.power_action.setChecked(mode == POWER)
        self.power_action.blockSignals(False)
        current = self.power_page if mode == POWER else self.simple_page
        hidden = self.simple_page if mode == POWER else self.power_page
        # The hidden page must not constrain the window's minimum size.
        for page, policy in ((hidden, QSizePolicy.Policy.Ignored),
                             (current, QSizePolicy.Policy.Preferred)):
            sp = page.sizePolicy()
            sp.setHorizontalPolicy(policy)
            page.setSizePolicy(sp)
        self.stack.setCurrentWidget(current)
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
