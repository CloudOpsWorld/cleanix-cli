"""Windows data locations and CLI behaviour (runs on any OS via fakes)."""

from __future__ import annotations

import pytest

from cleanix import cli, config
from cleanix.core import platform as plat
from cleanix.core import history, quarantine
from cleanix.core.engine import Engine
from cleanix.core.models import CleanableItem


@pytest.fixture
def as_windows(monkeypatch, fake_win):
    monkeypatch.setattr(plat, "is_windows", lambda: True)
    monkeypatch.setattr(plat, "current_os", lambda: "windows")
    return fake_win


def test_config_path_on_windows(as_windows):
    assert config._config_path() == as_windows.roaming / "cleanix" / "config.yaml"


def test_state_dir_on_windows(as_windows):
    assert history.state_dir() == as_windows.local / "cleanix"


def test_quarantine_root_on_windows(as_windows):
    assert quarantine.quarantine_root() == as_windows.local / "cleanix" / "quarantine"


def test_disk_free_default_is_system_drive_on_windows(as_windows, monkeypatch):
    seen = []
    import shutil

    class U:
        free = 5

    monkeypatch.setattr(shutil, "disk_usage", lambda p: seen.append(p) or U())
    assert cli._disk_free() == 5
    assert seen == ["C:\\"]


def test_requires_root_message_mentions_administrator_on_windows(as_windows, tmp_path):
    item = CleanableItem(
        cleaner_id="x", description="d", path=str(tmp_path / "f"), requires_root=True
    )
    out = Engine([]).clean([item], dry_run=False, allow_root_items=False)
    errors = [o.error for o in out.outcomes] if hasattr(out, "outcomes") else [
        o.error for o in out
    ]
    assert any("Administrator" in (e or "") for e in errors)


def test_requires_root_message_keeps_sudo_off_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(plat, "is_windows", lambda: False)
    item = CleanableItem(
        cleaner_id="x", description="d", path=str(tmp_path / "f"), requires_root=True
    )
    out = Engine([]).clean([item], dry_run=False, allow_root_items=False)
    errors = [o.error for o in out.outcomes] if hasattr(out, "outcomes") else [
        o.error for o in out
    ]
    assert any("sudo" in (e or "") for e in errors)


def test_factory_reset_unsupported_on_windows(as_windows, monkeypatch, capsys):
    import cleanix.reset as resetmod

    def boom(*a, **k):
        raise AssertionError("plan must not be built on Windows")

    monkeypatch.setattr(resetmod, "build_plan", boom)
    rc = cli.main(["factory-reset"])
    assert rc != 0
    assert "not supported on Windows" in capsys.readouterr().out.replace("\n", " ")
