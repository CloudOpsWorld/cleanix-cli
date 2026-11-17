import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QSettings  # noqa: E402

from cleanix.gui.main_window import MainWindow  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated(app_env):
    # MainWindow builds the real views and panels: keep them off the system.
    yield


def test_main_window_starts_in_simple_mode(qtbot):
    w = MainWindow()
    qtbot.addWidget(w)
    assert w.current_mode() == "simple"


def test_toggle_switches_page_and_persists(qtbot):
    w = MainWindow()
    qtbot.addWidget(w)
    w.power_action.trigger()
    assert w.current_mode() == "power"
    assert w.stack.currentWidget() is w.power_page
    w2 = MainWindow()
    qtbot.addWidget(w2)
    assert w2.current_mode() == "power"
    assert w2.power_action.isChecked()


def test_set_page_helpers_swap_widgets(qtbot):
    from PySide6.QtWidgets import QLabel

    w = MainWindow()
    qtbot.addWidget(w)
    new = QLabel("x")
    w.set_simple_page(new)
    assert w.simple_page is new
    assert w.stack.currentWidget() is new
    assert w.stack.count() == 2
    p = QLabel("p")
    w.set_power_page(p)
    assert w.power_page is p and w.stack.count() == 2
    w.set_mode("power")
    assert w.stack.currentWidget() is p


def test_qsettings_failure_does_not_break_startup(qtbot, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("nope")

    monkeypatch.setattr(QSettings, "value", boom)
    monkeypatch.setattr(QSettings, "setValue", boom)
    w = MainWindow()
    qtbot.addWidget(w)
    assert w.current_mode() == "simple"
    w.set_mode("power")
    assert w.current_mode() == "power"


def test_app_main_bootstraps_themed_window(qtbot, qapp, monkeypatch):
    from PySide6.QtWidgets import QApplication

    from cleanix.gui import app, main_window, theme

    applied, created, seen = [], [], {}
    monkeypatch.setattr(theme, "apply", applied.append)
    real = main_window.MainWindow

    def make():
        w = real(elevation_available=False)
        qtbot.addWidget(w)
        created.append(w)
        return w

    def fake_exec(self):
        seen["names"] = (self.organizationName(), self.applicationName())
        seen["visible"] = bool(created) and created[0].isVisible()
        return 7

    monkeypatch.setattr(main_window, "MainWindow", make)
    monkeypatch.setattr(QApplication, "exec", fake_exec)
    old = (qapp.organizationName(), qapp.applicationName())
    try:
        assert app.main(["cleanix-gui"]) == 7
    finally:
        qapp.setOrganizationName(old[0])
        qapp.setApplicationName(old[1])
    assert seen == {"names": ("Cleanix", "cleanix"), "visible": True}
    assert applied == [qapp]
    assert len(created) == 1


def test_power_mode_action_has_accessible_name(qtbot):
    w = MainWindow()
    qtbot.addWidget(w)
    assert w.power_action.isCheckable()
    assert w.power_action.text() == "Power mode"
    tb = w.findChild(type(w.toolbar))
    btn = tb.widgetForAction(w.power_action)
    assert btn.accessibleName() == "Power mode"
