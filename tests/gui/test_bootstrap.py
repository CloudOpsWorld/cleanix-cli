import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QSettings  # noqa: E402

from cleanix.gui.main_window import MainWindow  # noqa: E402


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


def test_power_mode_action_has_accessible_name(qtbot):
    w = MainWindow()
    qtbot.addWidget(w)
    assert w.power_action.isCheckable()
    assert w.power_action.text() == "Power mode"
    tb = w.findChild(type(w.toolbar))
    btn = tb.widgetForAction(w.power_action)
    assert btn.accessibleName() == "Power mode"
