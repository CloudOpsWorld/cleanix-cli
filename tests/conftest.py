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
    # Also occupy the lazily built "real" backend slot, so set_backend(None)
    # on win32 still cannot reach the real registry.
    previous_real = winregistry._real
    winregistry._real = forbidden
    yield forbidden
    winregistry._real = previous_real
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
def _no_process_helper_mode():
    """``cleanix.elevated.main`` switches helper scan mode on for the whole
    process (it never goes off again in production); tests that call
    ``main`` in-process must not leak it into later tests."""
    from cleanix.core import scanmode

    scanmode._reset_for_tests()
    yield
    scanmode._reset_for_tests()


@pytest.fixture(autouse=True)
def _fresh_windows_profiles_cache():
    """The guard caches the users-directory listing for a few seconds;
    tests that create or remove profile dirs must always see a fresh one."""
    from cleanix.core import safety

    safety._windows_profiles_cache_clear()
    yield
    safety._windows_profiles_cache_clear()


class FakeCommands:
    """Stand-in for run_command/which inside orphan_common.

    ``on(prefix, rc, out, err)`` answers any argv starting with ``prefix``
    (matched after the ``env LC_ALL=C`` prefix is stripped); anything else
    returns ``(127, "", "not found")``.
    """

    def __init__(self):
        self.tools: set = set()
        self.calls: list = []       # argv without the env prefix
        self.raw_calls: list = []   # argv exactly as run_command saw it
        self._rules: list = []

    def on(self, prefix, rc=0, out="", err=""):
        self._rules.append((tuple(prefix), (rc, out, err)))

    def run_command(self, argv, timeout=120):
        argv = list(argv)
        self.raw_calls.append(argv)
        if argv[:2] == ["env", "LC_ALL=C"]:
            argv = argv[2:]
        self.calls.append(argv)
        for prefix, result in self._rules:
            if tuple(argv[: len(prefix)]) == prefix:
                return result
        return 127, "", "not found"

    def which(self, name):
        return f"/usr/bin/{name}" if name in self.tools else None


@pytest.fixture
def orphan_env(tmp_path, monkeypatch):
    """Fake sysroot + single target user + faked commands for orphan tests."""
    from cleanix.cleaners import orphan_common
    from cleanix.core import context

    root = tmp_path / "root"
    home = tmp_path / "home" / "u"
    root.mkdir(parents=True, exist_ok=True)
    home.mkdir(parents=True, exist_ok=True)

    user = context.TargetUser("u", home, 1000, 1000, True)
    monkeypatch.setattr(context, "invoking_user", lambda: user)
    monkeypatch.setattr(context, "_cached_targets", [user])
    monkeypatch.setattr(orphan_common.OrphanReporter, "sysroot", str(root))

    cmds = FakeCommands()
    monkeypatch.setattr(orphan_common, "run_command", cmds.run_command)
    monkeypatch.setattr(orphan_common, "which", cmds.which)
    return SimpleNamespace(root=root, home=home, cmds=cmds)


@pytest.fixture
def beta_system_actions(monkeypatch):
    """OPT-IN (never autouse): turn the system-wide beta gate on for a test
    that exercises the system-wide path -- CLEANIX_BETA_SYSTEM_ACTIONS=1,
    not a frozen binary, not a root process (even if the suite runs as
    root). The gate's own tests do not use it."""
    from cleanix.core import system_findings

    monkeypatch.setenv(system_findings.BETA_ENV, "1")
    monkeypatch.setattr(system_findings, "is_frozen", lambda: False)
    monkeypatch.setattr(system_findings, "euid_is_root", lambda: False)
    return True
