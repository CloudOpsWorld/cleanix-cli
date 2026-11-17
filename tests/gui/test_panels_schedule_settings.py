import ntpath
import os
import sys

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import (  # noqa: E402
    QCheckBox,
    QDoubleSpinBox,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
)

from cleanix import config  # noqa: E402
from cleanix.core.models import CleanableItem, CleanerReport, ScanResult  # noqa: E402
from cleanix.gui import panels_config, reveal  # noqa: E402
from cleanix.gui.panels_config import FindingsPanel, SchedulePanel, SettingsPanel  # noqa: E402


class FakeBackend:
    FREQUENCIES = {"daily": "d", "weekly": "w", "monthly": "m"}

    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail
        self.installed = False

    def status(self):
        return "installed" if self.installed else "not installed"

    def install(self, frequency="weekly"):
        self.calls.append(("install", frequency))
        if self.fail:
            raise self.fail
        self.installed = True
        return f"installed {frequency}"

    def uninstall(self):
        self.calls.append(("uninstall",))
        if self.fail:
            raise self.fail
        self.installed = False
        return "removed"


def _button(panel, text):
    for b in panel.findChildren(QPushButton):
        if b.text() == text:
            return b
    raise AssertionError(text)


def test_schedule_panel_shows_status_and_installs_with_chosen_frequency(qtbot, monkeypatch):
    fake = FakeBackend()
    monkeypatch.setattr(panels_config.scheduler, "backend", lambda: fake)
    p = SchedulePanel()
    qtbot.addWidget(p)
    assert "not installed" in p.status_label.text()
    assert [p.frequency_combo.itemText(i) for i in range(p.frequency_combo.count())] == list(
        fake.FREQUENCIES
    )
    p.frequency_combo.setCurrentText("monthly")
    _button(p, "Install").click()
    assert fake.calls == [("install", "monthly")]
    assert "installed monthly" in p.message_label.text()
    assert p.status_label.text().endswith("installed")
    _button(p, "Remove").click()
    assert fake.calls[-1] == ("uninstall",)
    assert "removed" in p.message_label.text()
    assert "only scan" in p.note_label.text()


@pytest.mark.parametrize("exc", [RuntimeError("boom runtime"), ValueError("bad freq")])
def test_schedule_panel_shows_backend_errors_without_raising(qtbot, monkeypatch, exc):
    fake = FakeBackend(fail=exc)
    monkeypatch.setattr(panels_config.scheduler, "backend", lambda: fake)
    p = SchedulePanel()
    qtbot.addWidget(p)
    _button(p, "Install").click()
    assert str(exc) in p.message_label.text()
    _button(p, "Remove").click()
    assert str(exc) in p.message_label.text()


@pytest.fixture
def cfg_path(tmp_path, monkeypatch):
    path = tmp_path / "cfg" / "config.yaml"
    monkeypatch.setattr(config, "_config_path", lambda: path)
    return path


def test_settings_panel_has_editor_for_every_config_key(qtbot, cfg_path):
    p = SettingsPanel()
    qtbot.addWidget(p)
    assert set(p.editors) == set(config.field_names())
    expected = {bool: QCheckBox, int: panels_config.GuardedSpinBox, float: panels_config.GuardedDoubleSpinBox, list: QPlainTextEdit, str: QLineEdit}
    for key, typ in config._field_types().items():
        assert type(p.editors[key]) is expected[typ], key
        assert p.editors[key].accessibleName()


def test_settings_save_writes_only_changed_keys(qtbot, cfg_path):
    p = SettingsPanel()
    qtbot.addWidget(p)
    p.editors["keep_backups"].setValue(5)
    p.editors["docker_prune_volumes"].setChecked(True)
    _button(p, "Save").click()
    assert config.read_user_overrides() == {"keep_backups": 5, "docker_prune_volumes": True}
    assert str(cfg_path) in p.path_label.toolTip()
    # a second save with no further edits writes nothing new
    p.editors["keep_backups"].setValue(5)
    _button(p, "Save").click()
    assert set(config.read_user_overrides()) == {"keep_backups", "docker_prune_volumes"}


def test_settings_save_with_no_changes_creates_no_file(qtbot, cfg_path):
    p = SettingsPanel()
    qtbot.addWidget(p)
    _button(p, "Save").click()
    assert not cfg_path.exists()


def test_settings_list_values_roundtrip_with_non_ascii_entries(qtbot, cfg_path):
    p = SettingsPanel()
    qtbot.addWidget(p)
    p.editors["protected_globs"].setPlainText("~/Projekte/Übung/**\n~/größe/ü\n\n/data")
    _button(p, "Save").click()
    assert config.Config.load().protected_globs == ["~/Projekte/Übung/**", "~/größe/ü", "/data"]
    p2 = SettingsPanel()
    qtbot.addWidget(p2)
    assert p2.editors["protected_globs"].toPlainText() == "~/Projekte/Übung/**\n~/größe/ü\n/data"


def test_settings_reset_removes_override(qtbot, cfg_path):
    config.write_user_override("keep_backups", 9)
    p = SettingsPanel()
    qtbot.addWidget(p)
    assert p.editors["keep_backups"].value() == 9
    p.reset_buttons["keep_backups"].click()
    assert "keep_backups" not in config.read_user_overrides()
    assert p.editors["keep_backups"].value() == config.Config().keep_backups


def test_settings_errors_are_shown_not_raised(qtbot, cfg_path, monkeypatch):
    def boom(key, value, path=None):
        raise OSError("disk full")

    monkeypatch.setattr(config, "write_user_override", boom)
    p = SettingsPanel()
    qtbot.addWidget(p)
    p.editors["keep_backups"].setValue(5)
    _button(p, "Save").click()
    assert "disk full" in p.message_label.text()


def test_settings_tab_order_reaches_every_control(qtbot, cfg_path):
    p = SettingsPanel()
    qtbot.addWidget(p)
    p.show()
    seen = set()
    w = p.editors[config.field_names()[0]]
    for _ in range(1000):
        seen.add(w)
        w = w.nextInFocusChain()
    controls = list(p.editors.values()) + list(p.reset_buttons.values()) + [_button(p, "Save")]
    for c in controls:
        assert c in seen or c.focusProxy() in seen


def _result():
    rep = CleanerReport(
        cleaner_id="bigfiles",
        name="Big files", description="d",
        items=[
            CleanableItem("bigfiles", "huge.iso " + "x" * 300, size=5000, path="C:/x/huge.iso",
                          report_only=True, hint="delete it manually"),
            CleanableItem("tmp", "temp junk", size=10, path="C:/tmp/a"),
        ],
    )
    return ScanResult(reports=[rep])


def test_findings_panel_lists_only_report_only_items_and_no_delete_control(qtbot, monkeypatch):
    revealed = []
    monkeypatch.setattr(reveal, "reveal_in_file_manager", lambda path: revealed.append(path) or True)
    p = FindingsPanel()
    qtbot.addWidget(p)
    p.set_result(_result())
    assert len(p.rows) == 1
    texts = [b.text().lower() for b in p.findChildren(QPushButton)]
    assert texts == ["reveal"]
    assert not any("delete" in t or "remove" in t for t in texts)
    assert p.rows[0].description_label.toolTip().startswith("huge.iso")
    assert "delete it manually" in p.rows[0].description_label.toolTip()
    p.findChildren(QPushButton)[0].click()
    assert revealed == ["C:/x/huge.iso"]
    p.set_result(ScanResult())
    assert p.rows == []


def test_reveal_builds_per_platform_commands_without_shell(monkeypatch, tmp_path):
    calls = []

    class FakeProc:
        def wait(self):
            pass

    def fake_popen(argv, **kw):
        calls.append((argv, kw))
        return FakeProc()

    monkeypatch.setattr(reveal.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(reveal, "_resolve", lambda name: "/abs/" + name)
    (tmp_path / "sub").mkdir()
    target = str(tmp_path / "sub" / "f.txt")

    monkeypatch.setattr(reveal.plat, "current_os", lambda: "windows")
    assert reveal.reveal_in_file_manager(target) is True
    assert calls[-1][0] == ["/abs/explorer", "/select," + ntpath.normpath(target)]
    monkeypatch.setattr(reveal.plat, "current_os", lambda: "macos")
    assert reveal.reveal_in_file_manager(target) is True
    assert calls[-1][0] == ["/abs/open", "-R", target]
    monkeypatch.setattr(reveal.plat, "current_os", lambda: "linux")
    assert reveal.reveal_in_file_manager(target) is True
    assert calls[-1][0] == ["/abs/xdg-open", os.path.dirname(target)]
    for argv, kw in calls:
        assert isinstance(argv, list)
        assert not kw.get("shell")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows cwd search semantics")
def test_reveal_does_not_use_executable_planted_in_cwd(monkeypatch, tmp_path):
    planted = tmp_path / "cwd"
    planted.mkdir()
    (planted / "explorer.exe").write_bytes(b"")
    real = tmp_path / "bin"
    real.mkdir()
    (real / "explorer.exe").write_bytes(b"")
    monkeypatch.chdir(planted)
    monkeypatch.setenv("PATH", str(real))
    calls = []
    monkeypatch.setattr(reveal.subprocess, "Popen", lambda argv, **kw: calls.append(argv))
    monkeypatch.setattr(reveal.plat, "current_os", lambda: "windows")
    assert reveal.reveal_in_file_manager(str(tmp_path / "x")) is True
    assert os.path.dirname(calls[0][0]).lower() == str(real).lower()


def test_reveal_returns_false_when_tool_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(reveal, "_resolve", lambda name: None)
    called = []
    monkeypatch.setattr(reveal.subprocess, "Popen", lambda *a, **k: called.append(a))
    for osname in ("windows", "macos", "linux"):
        monkeypatch.setattr(reveal.plat, "current_os", lambda o=osname: o)
        assert reveal.reveal_in_file_manager(str(tmp_path / "f")) is False
    assert called == []


def test_reveal_returns_false_when_launch_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(reveal, "_resolve", lambda name: "/abs/" + name)

    def boom(*a, **k):
        raise OSError("nope")

    monkeypatch.setattr(reveal.subprocess, "Popen", boom)
    assert reveal.reveal_in_file_manager(str(tmp_path / "f")) is False


def test_reveal_windows_uses_backslash_path(monkeypatch):
    calls = []
    monkeypatch.setattr(reveal.subprocess, "Popen", lambda argv, **kw: calls.append(argv) or _Proc())
    monkeypatch.setattr(reveal, "_resolve", lambda name: "X:/" + name)
    monkeypatch.setattr(reveal.plat, "current_os", lambda: "windows")
    assert reveal.reveal_in_file_manager("C:/x/huge.iso") is True
    assert calls[0][1] == r"/select,C:\x\huge.iso"


class _Proc:
    def __init__(self):
        import threading

        self.waited = threading.Event()

    def wait(self):
        self.waited.set()


def test_reveal_reaps_child_in_background(monkeypatch, tmp_path):
    proc = _Proc()
    monkeypatch.setattr(reveal.subprocess, "Popen", lambda argv, **kw: proc)
    monkeypatch.setattr(reveal, "_resolve", lambda name: "/abs/" + name)
    monkeypatch.setattr(reveal.plat, "current_os", lambda: "macos")
    assert reveal.reveal_in_file_manager(str(tmp_path / "f")) is True
    assert proc.waited.wait(5)


def test_reveal_linux_missing_parent_returns_false(monkeypatch, tmp_path):
    called = []
    monkeypatch.setattr(reveal.subprocess, "Popen", lambda *a, **k: called.append(a))
    monkeypatch.setattr(reveal, "_resolve", lambda name: "/abs/" + name)
    monkeypatch.setattr(reveal.plat, "current_os", lambda: "linux")
    assert reveal.reveal_in_file_manager(str(tmp_path / "gone" / "f")) is False
    assert called == []


def test_spin_boxes_ignore_wheel_when_unfocused(qtbot, cfg_path):
    from PySide6.QtCore import QPoint, QPointF, Qt
    from PySide6.QtGui import QWheelEvent

    p = SettingsPanel()
    qtbot.addWidget(p)
    for key in ("keep_backups", "temp_min_age_days"):
        sb = p.editors[key]
        assert sb.focusPolicy() == Qt.FocusPolicy.StrongFocus
        before = sb.value()
        ev = QWheelEvent(QPointF(5, 5), QPointF(5, 5), QPoint(0, 0), QPoint(0, 120),
                         Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier,
                         Qt.ScrollPhase.NoScrollPhase, False)
        assert not sb.hasFocus()
        sb.wheelEvent(ev)
        assert sb.value() == before
        assert not ev.isAccepted()
