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
