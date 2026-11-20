"""MainWindow integration: views, panels, signal wiring and shutdown."""

import threading

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import QObject, Signal, Slot  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from cleanix.config import Config  # noqa: E402
from cleanix.core.models import CleanableItem, CleanerReport, ScanResult  # noqa: E402
from cleanix.gui import elevation, workers  # noqa: E402
from cleanix.gui.main_window import MainWindow  # noqa: E402
from cleanix.gui.panels_config import FindingsPanel, SchedulePanel, SettingsPanel  # noqa: E402
from cleanix.gui.panels_data import HistoryPanel, QuarantinePanel  # noqa: E402
from cleanix.gui.power_view import PowerView  # noqa: E402
from cleanix.gui.simple_view import SimpleView  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated(app_env):
    yield


def _findings_result(n=1):
    items = [CleanableItem("big_files", f"huge{i}.iso", size=10, path=f"/x/huge{i}.iso",
                           report_only=True, hint="Delete it manually") for i in range(n)]
    return ScanResult(reports=[CleanerReport("big_files", "Big files", "Big", items=items)])


class FakeWorker(QObject):
    """Scan/clean worker double. ``stoppable=False`` ignores cancel() and
    blocks until ``release`` is set (like the administrator prompt)."""

    progress = Signal(str, int, int)
    finished = Signal(object)
    cancelled = Signal()
    failed = Signal(str)

    def __init__(self, result=None, *, block=False, stoppable=True):
        super().__init__()
        self.result = result
        self.release = threading.Event()
        if not block:
            self.release.set()
        self.started = threading.Event()
        self._stoppable = stoppable
        self._cancel = threading.Event()

    def cancel(self):
        if self._stoppable:
            self._cancel.set()
            self.release.set()

    @Slot()
    def run(self):
        self.started.set()
        self.release.wait(10)
        if self._cancel.is_set():
            self.cancelled.emit()
        else:
            self.finished.emit(self.result)


class ScanFactory:
    def __init__(self, result=None):
        self.calls = []
        self.result = result

    def __call__(self, config, only=None):
        self.calls.append((config, only))
        return FakeWorker(self.result)


def _window(qtbot, **kw):
    kw.setdefault("scan_worker_factory", ScanFactory())
    kw.setdefault("elevation_available", False)
    w = MainWindow(**kw)
    qtbot.addWidget(w)
    return w


# ---- wiring ---------------------------------------------------------------
@pytest.mark.parametrize("osname", ["linux", "macos"])
def test_power_view_has_all_tabs_in_order(qtbot, monkeypatch, osname):
    # Task 12: Review after Scan; Registry only on Windows (test_tabs.py).
    from cleanix.gui import main_window
    from cleanix.gui.review_tab import ReviewTab

    monkeypatch.setattr(main_window, "current_os", lambda: osname)
    w = _window(qtbot)
    assert isinstance(w.simple_page, SimpleView) and w.simple_page is w.simple_view
    assert isinstance(w.power_page, PowerView) and w.power_page is w.power_view
    assert w.stack.count() == 2
    assert w.power_view.panel_titles() == [
        "Scan", "Review", "Quarantine", "History", "Schedule", "Settings", "Findings"]
    tabs = w.power_view.tabs
    for idx, cls in enumerate((ReviewTab, QuarantinePanel, HistoryPanel, SchedulePanel,
                               SettingsPanel, FindingsPanel), start=1):
        assert isinstance(tabs.widget(idx), cls)


def test_injected_config_is_shared_by_both_views(qtbot):
    cfg = Config()
    w = _window(qtbot, config=cfg)
    assert w.config is cfg
    assert w.simple_view._config is cfg and w.power_view._config is cfg


def test_default_config_comes_from_config_load(qtbot, monkeypatch):
    loaded = []
    real = Config.load

    def recording_load(*a, **k):
        cfg = real(*a, **k)
        loaded.append(cfg)
        return cfg

    monkeypatch.setattr(Config, "load", staticmethod(recording_load))
    w = _window(qtbot)
    # The first load is MainWindow's (SettingsPanel reads the file itself later).
    assert loaded and w.config is loaded[0]
    assert w.simple_view._config is w.config is w.power_view._config


def test_unreadable_config_falls_back_to_defaults(qtbot, monkeypatch):
    def boom(*a, **k):
        raise ValueError("bad yaml")

    monkeypatch.setattr(Config, "load", staticmethod(boom))
    w = _window(qtbot)
    assert w.config == Config()


@pytest.mark.parametrize("allow", [True, False])
def test_elevation_aware_factory_and_admin_flag(qtbot, monkeypatch, allow):
    monkeypatch.setattr(elevation, "elevation_available", lambda: allow)
    w = _window(qtbot, elevation_available=None)
    assert w.elevation_allowed is allow
    assert w.simple_view._allow_admin is allow and w.power_view._allow_admin is allow
    assert w.simple_view._clean_factory is w.power_view._clean_factory
    worker = w.power_view._clean_factory([], dry_run=True, use_quarantine=True)
    try:
        expected = workers.ElevatedCleanWorker if allow else workers.CleanWorker
        assert type(worker) is expected
        assert worker._config is w.config
    finally:
        worker.deleteLater()


def test_injected_clean_factory_is_used_by_both_views(qtbot):
    def factory(items, cfg=None, *, dry_run, use_quarantine):
        raise AssertionError("not called here")

    w = _window(qtbot, clean_worker_factory=factory)
    assert w.simple_view._clean_factory is factory
    assert w.power_view._clean_factory is factory


def test_scans_from_both_views_use_injected_factory_and_feed_findings(qtbot):
    factory = ScanFactory(_findings_result(2))
    w = _window(qtbot, scan_worker_factory=factory)
    w.power_view.start_scan()
    qtbot.waitUntil(lambda: len(w.findings_panel.rows) == 2, timeout=5000)
    cfg, only = factory.calls[0]
    assert cfg is w.config and only == w.power_view.cleaner_model.enabled_ids()

    factory.result = _findings_result(1)
    w.simple_view.start_scan()
    qtbot.waitUntil(lambda: len(w.findings_panel.rows) == 1, timeout=5000)
    assert factory.calls[1] == (w.config, None)
    qtbot.waitUntil(lambda: workers.active_count() == 0, timeout=5000)


def test_findings_panel_updates_after_scan(qtbot):
    w = _window(qtbot)
    w.power_view.scan_finished.emit(_findings_result(3))
    assert len(w.findings_panel.rows) == 3
    w.simple_view.scanned.emit(_findings_result(1))
    assert len(w.findings_panel.rows) == 1
    assert "1 finding" in w.findings_panel.summary_label.text()


def test_data_panels_refresh_after_clean_in_either_view_and_undo(qtbot, monkeypatch):
    w = _window(qtbot)
    calls = []
    monkeypatch.setattr(w.quarantine_panel, "refresh", lambda: calls.append("q"))
    monkeypatch.setattr(w.history_panel, "refresh", lambda: calls.append("h"))
    w.power_view.clean_finished.emit(object())
    assert calls == ["q", "h"]
    w.simple_view.clean_finished.emit(object())
    assert calls == ["q", "h"] * 2
    w.simple_view.undone.emit()
    assert calls == ["q", "h"] * 3


def test_data_panels_are_loaded_at_startup(qtbot):
    w = _window(qtbot)
    assert w.quarantine_panel.summary_label.text() == "Quarantine is empty."
    assert w.history_panel.totals_label.text() == "No clean runs yet."


def test_panel_refresh_errors_are_shown_not_raised(qtbot, monkeypatch):
    w = _window(qtbot)

    def boom():
        raise OSError("disk gone")

    monkeypatch.setattr(w.quarantine_panel, "refresh", boom)
    monkeypatch.setattr(w.history_panel, "refresh", boom)
    w.power_view.clean_finished.emit(object())
    assert "disk gone" in w.quarantine_panel.status_label.text()
    assert "disk gone" in w.history_panel.totals_label.text()


def test_mode_toggle_shows_real_views(qtbot):
    w = _window(qtbot)
    w.set_mode("power", persist=False)
    assert w.stack.currentWidget() is w.power_view
    w.set_mode("simple", persist=False)
    assert w.stack.currentWidget() is w.simple_view


# ---- shutdown ---------------------------------------------------------------
class _Event:
    def __init__(self):
        self.accepted = None

    def accept(self):
        self.accepted = True

    def ignore(self):
        self.accepted = False


def test_close_with_nothing_running_accepts(qtbot):
    w = _window(qtbot)
    w.show()
    ev = _Event()
    w.closeEvent(ev)
    assert ev.accepted is True
    assert w.power_view._shutting_down and w.simple_view._shutting_down


def test_close_cancels_stoppable_worker_and_accepts(qtbot):
    w = _window(qtbot)
    worker = FakeWorker(block=True, stoppable=True)
    workers.start_worker(worker)
    qtbot.waitUntil(worker.started.is_set, timeout=5000)
    ev = _Event()
    w.closeEvent(ev)
    assert ev.accepted is True
    assert workers.active_count() == 0


def test_close_with_unstoppable_worker_hides_and_quits_when_done(qtbot, qapp):
    w = _window(qtbot)
    w.shutdown_wait_ms = 50
    w.quit_poll_ms = 10
    quits = []
    w.quit_application = lambda: quits.append(True)
    w.show()
    worker = FakeWorker(block=True, stoppable=False)
    workers.start_worker(worker)
    qtbot.waitUntil(worker.started.is_set, timeout=5000)
    try:
        ev = _Event()
        w.closeEvent(ev)
        assert ev.accepted is False  # no quit while the worker runs
        assert not w.isVisible()
        assert QApplication.quitOnLastWindowClosed() is False
        assert w._quit_timer is not None and w._quit_timer.isActive()
        assert w._quit_timer.interval() == 10
        qtbot.wait(100)  # several timer ticks
        assert quits == [] and workers.active_count() == 1
        ev2 = _Event()
        w.closeEvent(ev2)  # a second close neither quits nor starts a timer
        assert ev2.accepted is False and quits == []
        worker.release.set()
        qtbot.waitUntil(lambda: quits == [True], timeout=5000)
        assert workers.active_count() == 0
        assert not w._quit_timer.isActive()
    finally:
        worker.release.set()
        QApplication.setQuitOnLastWindowClosed(True)
        qtbot.waitUntil(lambda: workers.active_count() == 0, timeout=5000)
        w._quit_timer = None  # let qtbot's teardown close the window normally


# ---- minimum width (I-7) -----------------------------------------------------
@pytest.mark.parametrize("mode", ["power", "simple"])
def test_main_window_fits_a_1024_pixel_screen(qtbot, mode):
    from cleanix.gui import main_window as mw

    w = _window(qtbot)
    w.set_mode(mode, persist=False)
    w.layout().activate()
    assert w.minimumSizeHint().width() <= 1024
    assert w.minimumSize().width() <= 1024
    # The hidden page never constrains the window.
    hidden = w.simple_page if mode == mw.POWER else w.power_page
    shown = w.power_page if mode == mw.POWER else w.simple_page
    from PySide6.QtWidgets import QSizePolicy

    assert hidden.sizePolicy().horizontalPolicy() == QSizePolicy.Policy.Ignored
    assert shown.sizePolicy().horizontalPolicy() == QSizePolicy.Policy.Preferred


def test_power_toolbar_has_two_rows(qtbot):
    w = _window(qtbot)
    pv = w.power_view
    row1, row2 = pv.toolbar_rows
    widgets1 = [row1.itemAt(i).widget() for i in range(row1.count())]
    widgets2 = [row2.itemAt(i).widget() for i in range(row2.count())]
    assert [x for x in widgets1 if x] == [pv.scan_button, pv.clean_button, pv.cancel_button,
                                         pv.filter_edit]
    assert [x for x in widgets2 if x] == [pv.select_visible_button, pv.select_none_button,
                                         pv.dry_run_check, pv.quarantine_check,
                                         pv.export_button]
    assert pv.filter_edit.minimumWidth() == 160


# ---- settings apply to the running session (I-3) --------------------------
def test_saved_protected_glob_is_honoured_by_the_next_clean(qtbot, app_env, monkeypatch):
    """A protected_globs entry saved in the Settings tab protects files in
    the SAME session: the shared Config is updated in place and service.clean
    applies it on the next call (no quarantine, so only the guard decides)."""
    import os

    from cleanix.core import safety, service
    from cleanix.core.models import CleanableItem

    monkeypatch.setattr(safety, "_EXTRA_GLOBS", [])  # restored after the test

    keep = app_env / "keep"
    keep.mkdir()
    victim = keep / "precious.tmp"
    victim.write_bytes(b"x" * 10)
    w = _window(qtbot)  # config from Config.load() (tmp path, no file yet)
    cfg = w.config
    assert cfg.protected_globs == []
    panel = w.settings_panel
    panel.editors["protected_globs"].setPlainText(os.path.join(str(keep), "*"))
    panel.save_button.click()
    assert w.config is cfg  # same object, updated in place
    assert w.simple_view._config is cfg and w.power_view._config is cfg
    assert cfg.protected_globs == [os.path.join(str(keep), "*")]
    assert "Settings saved and applied to the next scan" in panel.message_label.text()
    assert panel.message_label.text().startswith("Saved: protected_globs")
    # Control: an identical file outside the protected folder IS removed.
    other = app_env / "other"
    other.mkdir()
    control = other / "plain.tmp"
    control.write_bytes(b"x" * 10)
    items = [CleanableItem("temp", "precious", size=10, path=str(victim)),
             CleanableItem("temp", "plain", size=10, path=str(control))]
    summary = service.clean(items, w.config, dry_run=False, use_quarantine=False)
    assert victim.exists() and not control.exists()
    assert summary.removed == 1 and len(summary.errors) == 1
    assert summary.errors[0].item.path == str(victim)
    assert "safety guard" in summary.errors[0].error


def test_every_config_field_is_reloaded_in_place(qtbot, app_env):
    w = _window(qtbot)
    cfg = w.config
    panel = w.settings_panel
    panel.editors["temp_min_age_days"].setValue(42.0)
    panel.editors["browsers"].setPlainText("firefox")
    panel.save_button.click()
    assert cfg.temp_min_age_days == 42.0 and cfg.browsers == ["firefox"]
    # Reset also applies (the default comes back into the same object).
    panel.reset_buttons["temp_min_age_days"].click()
    assert cfg.temp_min_age_days == Config().temp_min_age_days
    assert "applied to the next scan" in panel.message_label.text()


def test_settings_apply_failure_is_shown_not_raised(qtbot, app_env, monkeypatch):
    w = _window(qtbot)
    before = w.config.temp_min_age_days
    w.settings_panel.editors["temp_min_age_days"].setValue(9.0)

    def boom(*a, **k):
        raise ValueError("unreadable")

    monkeypatch.setattr(Config, "load", staticmethod(boom))
    w.settings_panel.save_button.click()
    assert "could not be applied" in w.settings_panel.message_label.text()
    assert w.config.temp_min_age_days == before


def test_mode_switch_persists_via_isolated_settings(qtbot):
    from cleanix.gui import main_window
    w = MainWindow(config=Config(), elevation_available=False)
    qtbot.addWidget(w)
    w.power_button.click()
    assert main_window._load_mode() == "power"
    w.simple_button.click()
    assert main_window._load_mode() == "simple"
    assert w.stack.currentWidget() is w.simple_page


def test_simple_scan_worker_forwards_deep(qtbot, monkeypatch):
    from cleanix.gui import simple_view, workers

    # default factory goes through the Simple mode factory with the flag
    seen = []
    monkeypatch.setattr(simple_view, "_default_scan_factory",
                        lambda cfg, deep=False: seen.append(deep) or "w")
    w = _window(qtbot, scan_worker_factory=workers.ScanWorker)
    assert w._make_simple_scan_worker(w.config, deep=True) == "w"
    assert w._make_simple_scan_worker(w.config) == "w"
    assert seen == [True, False]

    # injected factory with a deep parameter receives it
    got = []
    w = _window(qtbot, scan_worker_factory=lambda cfg, deep=False: got.append(deep))
    w._make_simple_scan_worker(w.config, deep=True)
    # injected with **kwargs receives it too
    w2 = _window(qtbot, scan_worker_factory=lambda cfg, **kw: got.append(kw))
    w2._make_simple_scan_worker(w2.config, deep=True)
    # injected without it is called plainly
    w3 = _window(qtbot, scan_worker_factory=lambda cfg: got.append("plain"))
    w3._make_simple_scan_worker(w3.config, deep=True)
    assert got == [True, {"deep": True}, "plain"]


def test_power_toolbar_third_row_fits_1024(qtbot):
    w = _window(qtbot)
    pv = w.power_view
    row3 = pv.toolbar_row3
    widgets = [row3.itemAt(i).widget() for i in range(row3.count())]
    widgets = [x for x in widgets if x]
    assert widgets == [pv.safe_only_button, pv.developer_button, pv.safety_combo,
                       pv.show_empty_check, pv.raw_toggle]
    need = sum(x.sizeHint().width() for x in widgets) + row3.spacing() * (len(widgets) - 1)
    assert need < 1024 - 2 * 12
