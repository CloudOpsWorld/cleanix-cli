import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

pytest.importorskip("PySide6")

from PySide6.QtCore import QSettings  # noqa: E402


@pytest.fixture(autouse=True)
def settings_isolation(tmp_path):
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    for fmt in (QSettings.Format.NativeFormat, QSettings.Format.IniFormat):
        QSettings.setPath(fmt, QSettings.Scope.UserScope, str(tmp_path))
    yield


class _FakeScheduleBackend:
    FREQUENCIES = {"daily": "d", "weekly": "w", "monthly": "m"}

    def status(self):
        return "not installed"

    def install(self, frequency="weekly"):
        raise AssertionError("tests must not install a schedule")

    def uninstall(self):
        raise AssertionError("tests must not remove a schedule")


@pytest.fixture
def app_env(tmp_path, monkeypatch):
    """Everything a full MainWindow touches, redirected under tmp_path.

    Config file, history/quarantine state and the scheduler backend are
    fakes; elevation is reported unavailable (no prompt can ever be shown).
    """
    from cleanix import config
    from cleanix.core import history, quarantine
    from cleanix.gui import elevation, panels_config

    state = tmp_path / "state"
    monkeypatch.setattr(config, "_config_path", lambda: tmp_path / "cfg" / "config.yaml")
    monkeypatch.setattr(history, "state_dir", lambda: state)
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: state / "quarantine")
    monkeypatch.setattr(panels_config.scheduler, "backend", lambda: _FakeScheduleBackend())
    monkeypatch.setattr(elevation, "elevation_available", lambda: False)
    return tmp_path
