"""Shared pytest fixtures."""

from __future__ import annotations

from types import SimpleNamespace

import pytest


@pytest.fixture
def fake_win(tmp_path, monkeypatch):
    """A fake Windows profile tree under tmp_path; redirects winenv and home."""
    from cleanix.core import context, winenv

    home = tmp_path / "Users" / "u"
    local = home / "AppData" / "Local"
    roaming = home / "AppData" / "Roaming"
    programdata = tmp_path / "ProgramData"
    system_root = tmp_path / "Windows"
    for d in (local, roaming, programdata, system_root):
        d.mkdir(parents=True, exist_ok=True)

    user = context.TargetUser("u", home, 1000, 1000, True)
    monkeypatch.setattr(winenv, "local_appdata", lambda: local)
    monkeypatch.setattr(winenv, "roaming_appdata", lambda: roaming)
    monkeypatch.setattr(winenv, "programdata", lambda: programdata)
    monkeypatch.setattr(winenv, "system_root", lambda: system_root)
    monkeypatch.setattr(winenv, "system_drive", lambda: "C:")
    monkeypatch.setattr(winenv, "user_temp", lambda: local / "Temp")
    monkeypatch.setattr(context, "invoking_user", lambda: user)
    monkeypatch.setattr(context, "_cached_targets", [user])
    return SimpleNamespace(
        home=home, local=local, roaming=roaming,
        programdata=programdata, system_root=system_root,
    )


@pytest.fixture(autouse=True)
def _fresh_windows_profiles_cache():
    """The guard caches the users-directory listing for a few seconds;
    tests that create or remove profile dirs must always see a fresh one."""
    from cleanix.core import safety

    safety._windows_profiles_cache_clear()
    yield
    safety._windows_profiles_cache_clear()
