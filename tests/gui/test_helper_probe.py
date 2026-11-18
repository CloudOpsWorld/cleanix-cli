"""I-5: elevation_available() also checks, once, that the helper can start.

subprocess.run is always replaced: no real interpreter is started here.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from cleanix.config import Config  # noqa: E402
from cleanix.core.models import CleanableItem, CleanerReport, ItemKind, ScanResult  # noqa: E402
from cleanix.core.platform import LINUX, WINDOWS  # noqa: E402
from cleanix.gui import elevation  # noqa: E402
from cleanix.gui.main_window import MainWindow  # noqa: E402

# The real probe function (the autouse conftest fixture stubs it per test).
REAL_PROBE = elevation._run_helper_probe
# The real availability check (app_env replaces it with "False").
REAL_AVAILABLE = elevation.elevation_available


class FakeRun:
    def __init__(self, rc=0, exc=None):
        self.calls = []
        self.rc = rc
        self.exc = exc

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        if self.exc is not None:
            raise self.exc
        return subprocess.CompletedProcess(argv, self.rc)


@pytest.fixture
def real_probe(monkeypatch):
    monkeypatch.setattr(elevation, "_run_helper_probe", REAL_PROBE)
    monkeypatch.setattr(elevation, "current_os", lambda: WINDOWS)


def test_probe_runs_once_unprivileged_isolated_and_short(monkeypatch, real_probe):
    run = FakeRun(rc=0)
    monkeypatch.setattr(elevation.subprocess, "run", run)
    assert elevation.elevation_available() is True
    assert elevation.elevation_available() is True  # cached
    assert len(run.calls) == 1
    argv, kw = run.calls[0]
    assert argv == [sys.executable, "-I", "-c", "import cleanix.elevated"]
    assert kw["stdin"] is subprocess.DEVNULL
    assert kw["timeout"] == 10 and not kw.get("shell")
    assert kw.get("cwd")  # neutral directory, never the caller's cwd
    assert elevation.elevation_unavailable_reason() == ""
    elevation.reset_helper_probe()
    elevation.elevation_available()
    assert len(run.calls) == 2


@pytest.mark.parametrize("run", [
    FakeRun(rc=1),
    FakeRun(exc=subprocess.TimeoutExpired("python", 10)),
    FakeRun(exc=OSError("no python")),
])
def test_probe_failure_makes_elevation_unavailable_with_reason(monkeypatch, real_probe, run):
    monkeypatch.setattr(elevation.subprocess, "run", run)
    assert elevation.elevation_available() is False
    reason = elevation.elevation_unavailable_reason()
    assert reason == elevation.HELPER_UNAVAILABLE_REASON
    assert "pip install --user" in reason and "venv" in reason


def test_probe_not_run_when_platform_cannot_prompt(monkeypatch, real_probe):
    run = FakeRun(rc=0)
    monkeypatch.setattr(elevation.subprocess, "run", run)
    monkeypatch.setattr(elevation, "current_os", lambda: LINUX)
    monkeypatch.setattr(elevation.utils, "safe_which", lambda c: None)
    assert elevation.elevation_available() is False
    assert run.calls == []
    assert elevation.elevation_unavailable_reason() == ""


def _admin_result():
    item = CleanableItem("logs", "system logs", size=10, kind=ItemKind.COMMAND,
                         command=["x"], requires_root=True)
    return item, ScanResult(reports=[CleanerReport("logs", "Logs", "l", items=[item])])


def test_main_window_shows_the_reason_in_both_views(qtbot, monkeypatch, app_env):
    # app_env stubs elevation_available to False; use the real one here, with
    # a platform that can prompt and a helper that cannot start.
    monkeypatch.setattr(elevation, "elevation_available", REAL_AVAILABLE)
    monkeypatch.setattr(elevation, "_platform_can_prompt", lambda: True)
    monkeypatch.setattr(elevation, "_run_helper_probe", lambda: False)
    w = MainWindow(elevation_available=None, config=Config())
    qtbot.addWidget(w)
    assert w.elevation_allowed is False
    assert w.admin_unavailable_reason == elevation.HELPER_UNAVAILABLE_REASON
    item, result = _admin_result()
    w.simple_view.set_scan_result(result)
    tree = w.simple_view.also_tree
    hints = [tree.topLevelItem(i).text(1) for i in range(tree.topLevelItemCount())]
    assert any(elevation.HELPER_UNAVAILABLE_REASON in h for h in hints)
    assert tree.refusal_reason(item) == elevation.HELPER_UNAVAILABLE_REASON
    assert w.power_view.detail_text(item, allow_admin=False,
                                    unavailable_reason=w.admin_unavailable_reason
                                    ).endswith(elevation.HELPER_UNAVAILABLE_REASON)
    w.power_view._on_scan_finished(result)
    pv = w.power_view
    pv.table.setCurrentIndex(pv.proxy.index(0, 1))
    assert elevation.HELPER_UNAVAILABLE_REASON in pv.detail_label.toPlainText()

