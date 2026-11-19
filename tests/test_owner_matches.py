"""The single owner_matches policy (regtargets.scan_owner_matches / scanmode)."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from _fakereg import FakeProber
from cleanix.cleaners import winreg_base
from cleanix.cleaners.winreg_app_paths import WinRegAppPaths
from cleanix.cleaners.winreg_base import RegistryDetector
from cleanix.cleaners.winreg_file_assoc import WinRegFileAssoc
from cleanix.cleaners.winreg_shared_dlls import WinRegSharedDlls
from cleanix.cleaners.winreg_startup import WinRegStartup
from cleanix.cleaners.winreg_uninstall import WinRegUninstall
from cleanix.config import Config
from cleanix.core import context, regtargets, scanmode
from cleanix.core.context import TargetUser
from cleanix.core.regtargets import DetectorContext, Existence
from cleanix.core.winregistry import REG_EXPAND_SZ, REG_SZ

M = Existence.MISSING
CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
ENV = {
    "ProgramFiles": r"C:\Program Files",
    "SystemRoot": r"C:\Windows",
    "LOCALAPPDATA": r"C:\Users\me\AppData\Local",
}
ALL = (
    WinRegUninstall,
    WinRegAppPaths,
    WinRegFileAssoc,
    WinRegStartup,
    WinRegSharedDlls,
)

ME = TargetUser("me", Path("C:/Users/me"), 1000, 1000, True)
OTHER = TargetUser("other", Path("C:/Users/other"), 1001, 1001, False)


@pytest.fixture
def env(monkeypatch):
    """Normal unelevated invoking user, no helper mode."""
    monkeypatch.setattr(context, "is_effective_root", lambda: False)
    monkeypatch.setattr(context, "invoking_user", lambda: ME)
    monkeypatch.setattr(context, "current_user", lambda: ME)
    return monkeypatch


# --- policy matrix -----------------------------------------------------------
def test_normal_user_matches(env):
    assert regtargets.scan_owner_matches() is True


def test_helper_mode_never_matches(env):
    with scanmode.helper_mode():
        assert regtargets.scan_owner_matches() is False
    assert regtargets.scan_owner_matches() is True


def test_other_target_user_never_matches(env):
    env.setattr(context, "current_user", lambda: OTHER)
    assert regtargets.scan_owner_matches() is False


def test_bound_user_via_use_user_other_than_invoker(monkeypatch):
    monkeypatch.setattr(context, "is_effective_root", lambda: False)
    monkeypatch.setattr(context, "invoking_user", lambda: ME)
    with context.use_user(OTHER):
        assert regtargets.scan_owner_matches() is False
    with context.use_user(ME):
        assert regtargets.scan_owner_matches() is True


def test_elevated_process_never_matches(env):
    # same-account UAC elevation and another administrator account cannot be
    # told apart: both are False (conservative)
    env.setattr(context, "is_effective_root", lambda: True)
    assert regtargets.scan_owner_matches() is False


@pytest.mark.parametrize("what", ["is_effective_root", "current_user", "invoking_user"])
def test_undetermined_fails_closed(env, what):
    def boom():
        raise OSError("cannot tell")

    env.setattr(context, what, boom)
    assert regtargets.scan_owner_matches() is False


# --- scanmode ----------------------------------------------------------------
def test_scanmode_nesting_and_set():
    assert scanmode.is_helper_mode() is False
    with scanmode.helper_mode():
        assert scanmode.is_helper_mode() is True
        with scanmode.helper_mode(False):
            assert scanmode.is_helper_mode() is False
        assert scanmode.is_helper_mode() is True
    assert scanmode.is_helper_mode() is False


def test_scanmode_restored_on_exception():
    with pytest.raises(RuntimeError):
        with scanmode.helper_mode():
            raise RuntimeError("x")
    assert scanmode.is_helper_mode() is False


@pytest.fixture(autouse=True)
def _no_process_flag_leak():
    scanmode._reset_for_tests()
    yield
    scanmode._reset_for_tests()


def test_process_flag_visible_in_plain_threads_and_pools():
    from concurrent.futures import ThreadPoolExecutor

    assert scanmode.process_helper_mode_enabled() is False
    scanmode.enable_process_helper_mode()
    assert scanmode.process_helper_mode_enabled() is True
    seen = []
    t = threading.Thread(target=lambda: seen.append(scanmode.is_helper_mode()))
    t.start()
    t.join()
    with ThreadPoolExecutor(2) as pool:  # no context copy
        seen.append(pool.submit(scanmode.is_helper_mode).result())
    assert seen == [True, True]
    scanmode._reset_for_tests()
    assert scanmode.is_helper_mode() is False


def test_contextvar_alone_is_not_visible_in_plain_threads():
    from concurrent.futures import ThreadPoolExecutor

    with scanmode.helper_mode():
        with ThreadPoolExecutor(1) as pool:
            assert pool.submit(scanmode.is_helper_mode).result() is False
        assert scanmode.is_helper_mode() is True


class _Probe:
    """Engine-compatible cleaner recording what its worker thread sees."""

    def __init__(self, i, sink):
        self.name = f"probe{i}"
        self.id = self.name
        self.sink = sink

    def scan(self):
        from cleanix.core.models import CleanerReport

        self.sink.append((scanmode.is_helper_mode(), regtargets.scan_owner_matches()))
        return CleanerReport(self.id, self.name, "")


@pytest.mark.parametrize("parallel", [True, False])
def test_engine_workers_see_helper_mode(env, parallel):
    from cleanix.core.engine import Engine

    sink = []
    eng = Engine([_Probe(i, sink) for i in range(6)])
    with scanmode.helper_mode():
        eng.scan(parallel=parallel)
    assert sink == [(True, False)] * 6
    sink.clear()
    eng.scan(parallel=parallel)
    assert sink == [(False, True)] * 6


def test_engine_detector_context_in_workers(env, captured):
    from cleanix.core.engine import Engine

    flags = []

    class Det(WinRegAppPaths):
        def find_items(self):
            flags.append(self.context().owner_matches)
            return iter(())

    eng = Engine([Det(Config()) for _ in range(4)])
    with scanmode.helper_mode():
        eng.scan(parallel=True)
    assert flags == [False] * 4


def test_engine_scans_from_different_threads_are_isolated(env):
    from cleanix.core.engine import Engine

    results = {}
    barrier = threading.Barrier(2)

    def run(name, helper):
        sink = []
        eng = Engine([_Probe(i, sink) for i in range(4)])
        barrier.wait(5)
        with scanmode.helper_mode(helper):
            eng.scan(parallel=True)
        results[name] = set(sink)

    ts = [
        threading.Thread(target=run, args=("h", True)),
        threading.Thread(target=run, args=("n", False)),
    ]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert results == {"h": {(True, False)}, "n": {(False, True)}}


def test_engine_propagates_use_user(monkeypatch):
    from cleanix.core.engine import Engine

    seen = []

    class P(_Probe):
        def scan(self):
            seen.append(context.current_user())
            return super().scan()

    sink = []
    with context.use_user(OTHER):
        Engine([P(i, sink) for i in range(3)]).scan(parallel=True)
    assert seen == [OTHER] * 3


def test_default_context_passes_owner_matches_through():
    import sys

    if sys.platform != "win32":
        pytest.skip("default_context needs Windows")
    assert regtargets.default_context(owner_matches=False).owner_matches is False
    assert regtargets.default_context(owner_matches=True).owner_matches is True
    assert regtargets.default_context().owner_matches is True


def test_invoker_flag_alone_is_not_enough(env):
    impostor = TargetUser("me2", Path("C:/Users/me2"), 1002, 1002, True)
    env.setattr(context, "current_user", lambda: impostor)
    assert regtargets.scan_owner_matches() is False


def test_contextvar_is_per_context_not_per_process_engine_copies_it():
    # A plain thread starts with an empty context, so set_helper_mode there
    # does not leak; engine workers see the caller's value only because the
    # engine runs them through contextvars.copy_context().
    seen = {}

    def worker():
        seen["before"] = scanmode.is_helper_mode()
        scanmode.set_helper_mode(True)
        seen["after"] = scanmode.is_helper_mode()

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert seen == {"before": False, "after": True}
    assert scanmode.is_helper_mode() is False  # main thread unaffected


def test_scanmode_isolated_between_threads():
    inside = threading.Event()
    release = threading.Event()
    seen = {}

    def helper_thread():
        with scanmode.helper_mode():
            inside.set()
            release.wait(5)
            seen["helper"] = scanmode.is_helper_mode()

    t = threading.Thread(target=helper_thread)
    t.start()
    assert inside.wait(5)
    assert scanmode.is_helper_mode() is False  # other thread's mode invisible
    release.set()
    t.join()
    assert seen["helper"] is True


# --- detectors reflect the policy -------------------------------------------
@pytest.fixture
def captured(monkeypatch):
    """Replace default_context so the context's owner_matches is observable."""
    prober = FakeProber({}, default=M)

    def fake_default(owner_matches=True):
        return DetectorContext(ENV, prober, r"C:\Users", r"C:\Windows", owner_matches)

    monkeypatch.setattr(winreg_base, "default_context", fake_default)
    return prober


@pytest.mark.parametrize("cls", ALL)
def test_detector_context_reflects_policy(cls, env, captured):
    assert cls.context is RegistryDetector.context
    det = cls(Config())
    assert det.context().owner_matches is True
    with scanmode.helper_mode():
        assert det.context().owner_matches is False
    env.setattr(context, "current_user", lambda: OTHER)
    assert det.context().owner_matches is False
    env.setattr(context, "current_user", lambda: ME)
    env.setattr(context, "is_effective_root", lambda: True)
    assert det.context().owner_matches is False


@pytest.mark.parametrize("cls", ALL)
def test_policy_is_evaluated_at_scan_time(cls, env, captured):
    det = cls(Config())
    flags = []
    env.setattr(regtargets, "scan_owner_matches", lambda: flags.append(1) or False)
    assert det.context().owner_matches is False
    assert det.context().owner_matches is False
    assert len(flags) == 2


def test_default_context_parameter_is_additive():
    import inspect

    assert inspect.signature(regtargets.default_context).parameters[
        "owner_matches"
    ].default is True


# --- end to end ---------------------------------------------------------------
UN = CV + r"\Uninstall"
LOCAL = r"C:\Users\me\AppData\Local\Programs\Foo"


def _add_per_user_uninstall(reg):
    reg.add_key(
        "HKCU",
        UN + r"\Foo",
        {
            "DisplayName": (REG_SZ, "Foo Tool"),
            "InstallLocation": (REG_EXPAND_SZ, r"%LOCALAPPDATA%\Programs\Foo"),
            "UninstallString": (
                REG_EXPAND_SZ,
                r'"%LOCALAPPDATA%\Programs\Foo\unins.exe"',
            ),
        },
    )


def _scan(cls):
    report = cls(Config()).scan()
    assert report.skipped_reason is None, report.skipped_reason
    return list(report.items)


def test_end_to_end_uninstall_listed_normal_not_listed_in_helper_mode(
    fake_registry, env, captured
):
    _add_per_user_uninstall(fake_registry)
    assert len(_scan(WinRegUninstall)) == 1
    with scanmode.helper_mode():
        assert _scan(WinRegUninstall) == []
    assert len(_scan(WinRegUninstall)) == 1


def test_end_to_end_other_user_and_elevated_not_listed(fake_registry, env, captured):
    _add_per_user_uninstall(fake_registry)
    env.setattr(context, "current_user", lambda: OTHER)
    assert _scan(WinRegUninstall) == []
    env.setattr(context, "current_user", lambda: ME)
    env.setattr(context, "is_effective_root", lambda: True)
    assert _scan(WinRegUninstall) == []


def test_helper_mode_app_paths_per_user_var_unknown(fake_registry, env, captured):
    fake_registry.add_key(
        "HKCU",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\foo.exe",
        {"": (REG_EXPAND_SZ, r"%LOCALAPPDATA%\Gone\foo.exe")},
    )
    assert len(_scan(WinRegAppPaths)) == 1
    with scanmode.helper_mode():
        assert _scan(WinRegAppPaths) == []


def test_helper_mode_startup_per_user_var_unknown(fake_registry, env, captured):
    fake_registry.add_key(
        "HKCU", CV + r"\Run", {"a": (REG_EXPAND_SZ, r"%LOCALAPPDATA%\Gone\a.exe")}
    )
    normal = _scan(WinRegStartup)
    with scanmode.helper_mode():
        assert _scan(WinRegStartup) == []
    assert len(normal) == 1


def test_helper_mode_file_assoc_skips_hkcu_containers(fake_registry, env, captured):
    root = r"SOFTWARE\Classes\A.B"
    for hive in ("HKCU", "HKLM"):
        fake_registry.add_key(hive, root, {"": (REG_SZ, "Friendly")})
        fake_registry.add_key(
            hive, root + r"\shell\open\command", {"": (REG_SZ, r"C:\gone\app.exe")}
        )
    normal = {i.reg.hive for i in _scan(WinRegFileAssoc)}
    assert normal == {"HKCU", "HKLM"}
    with scanmode.helper_mode():
        n0 = len(fake_registry.calls)
        helper = {i.reg.hive for i in _scan(WinRegFileAssoc)}
        calls = fake_registry.calls[n0:]
    assert helper == {"HKLM"}
    assert not [c for c in calls if c[1] == "HKCU"], calls


def test_helper_mode_never_probes_per_user_paths(fake_registry, env, captured):
    """No detector ever asks the filesystem about an expanded per-user path."""
    _add_per_user_uninstall(fake_registry)
    fake_registry.add_key(
        "HKCU", CV + r"\Run", {"a": (REG_EXPAND_SZ, r"%LOCALAPPDATA%\Gone\a.exe")}
    )
    fake_registry.add_key(
        "HKCU",
        CV + r"\App Paths\foo.exe",
        {"": (REG_EXPAND_SZ, r"%LOCALAPPDATA%\Gone\foo.exe")},
    )
    with scanmode.helper_mode():
        for cls in ALL:
            _scan(cls)
    assert not [p for p in captured.calls if r"users\me" in p.casefold()]
