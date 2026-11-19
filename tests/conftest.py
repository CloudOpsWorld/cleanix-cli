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
def _no_real_registry():
    """Tests never touch the real registry: any call to the default backend
    is recorded and raises, and a recorded call fails the test at teardown
    (a cleaner's scan would otherwise swallow the error)."""
    from _fakereg import ForbiddenBackend
    from cleanix.core import winregistry

    forbidden = ForbiddenBackend()
    winregistry.set_backend(forbidden)
    yield forbidden
    winregistry.set_backend(None)
    if forbidden.calls:
        pytest.fail(f"test touched the real registry: {forbidden.calls[:3]}")


@pytest.fixture
def fake_registry():
    """An in-memory registry installed as the backend for the test."""
    from _fakereg import FakeRegistry
    from cleanix.core import winregistry

    reg = FakeRegistry()
    winregistry.set_backend(reg)
    return reg


@pytest.fixture(autouse=True)
def _fresh_windows_profiles_cache():
    """The guard caches the users-directory listing for a few seconds;
    tests that create or remove profile dirs must always see a fresh one."""
    from cleanix.core import safety

    safety._windows_profiles_cache_clear()
    yield
    safety._windows_profiles_cache_clear()
