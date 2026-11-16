"""Cross-platform cleaners opting in to Windows, plus the WSL disk reporter."""

from __future__ import annotations

import os

import pytest

from cleanix.cleaners.ai_cli import (
    ClaudeCodeCleaner, CodexCleaner, GeminiCliCleaner, OpenCodeCleaner,
)
from cleanix.cleaners.ai_tools import (
    AIClientCleaner, AICompileCacheCleaner, AiderLitterCleaner,
    HuggingFaceCleaner, OllamaCleaner,
)
from cleanix.cleaners.big_files import BigFileReporter
from cleanix.cleaners.browser_profiles import BrowserProfileReporter
from cleanix.cleaners.containers import DockerCleaner, PodmanCleaner
from cleanix.cleaners.dev_caches import DevCacheCleaner
from cleanix.cleaners.downloads import DownloadsReporter
from cleanix.cleaners.duplicates import DuplicateFileReporter
from cleanix.cleaners.npm_cache import NpmCacheCleaner
from cleanix.cleaners.pip_cache import PipCacheCleaner
from cleanix.cleaners.project_cruft import ProjectCruftCleaner
from cleanix.cleaners.windows_wsl import WslDiskReporter
from cleanix.config import Config
from cleanix.core import platform
from cleanix.core.platform import supports
from cleanix.core.utils import walk_pruned


def _mk(path, data=b"x" * 10):
    path.mkdir(parents=True, exist_ok=True)
    (path / "f").write_bytes(data)
    return path


def _win(monkeypatch):
    monkeypatch.setattr(platform, "current_os", lambda: "windows")


def test_dev_caches_windows_locations(fake_win, monkeypatch):
    _win(monkeypatch)
    _mk(fake_win.local / "go-build", b"a" * 100)
    _mk(fake_win.local / "npm-cache", b"b" * 200)
    _mk(fake_win.local / "pip" / "Cache", b"c" * 300)
    _mk(fake_win.home / ".cargo" / "registry" / "cache", b"d" * 400)
    _mk(fake_win.home / ".cache" / "ccache", b"e" * 50)  # POSIX-only, skipped
    cfg = Config()
    dev = {str(i.path): i for i in DevCacheCleaner(cfg).find_items()}
    assert dev[str(fake_win.local / "go-build")].size >= 100
    assert dev[str(fake_win.home / ".cargo" / "registry" / "cache")].size >= 400
    assert str(fake_win.home / ".cache" / "ccache") not in dev
    npm = {str(i.path) for i in NpmCacheCleaner(cfg).find_items()}
    pip = {str(i.path) for i in PipCacheCleaner(cfg).find_items()}
    assert str(fake_win.local / "npm-cache") in npm
    assert str(fake_win.local / "pip" / "Cache") in pip
    # No path is offered by two cleaners.
    assert not (set(dev) & npm) and not (set(dev) & pip) and not (npm & pip)


OPTED_IN = [
    DevCacheCleaner, PipCacheCleaner, NpmCacheCleaner, DockerCleaner,
    OllamaCleaner, HuggingFaceCleaner, AICompileCacheCleaner, AIClientCleaner,
    AiderLitterCleaner, ClaudeCodeCleaner, CodexCleaner, GeminiCliCleaner,
    OpenCodeCleaner, BigFileReporter, DownloadsReporter, DuplicateFileReporter,
    ProjectCruftCleaner, BrowserProfileReporter,
]


def _posix_only():
    from cleanix.cleaners.apple_litter import AppleLitterCleaner
    from cleanix.cleaners.editor_litter import (
        BackupFileCleaner, BuildLitterCleaner, EditorStateCleaner,
        HomeCoreDumpCleaner,
    )
    from cleanix.cleaners.logs import JournalCleaner, RotatedLogCleaner
    from cleanix.cleaners.more_pkg import (
        CondaCleaner, CpanmCleaner, GemCleanupCleaner, OpamCleaner,
        SdkmanCleaner,
    )
    from cleanix.cleaners.snapshots import BackupCacheCleaner
    from cleanix.cleaners.toolchains import ToolchainVersionCleaner
    from cleanix.cleaners.virtualization import VmToolingCleaner

    return [
        ToolchainVersionCleaner, EditorStateCleaner, BuildLitterCleaner,
        HomeCoreDumpCleaner, BackupFileCleaner, RotatedLogCleaner,
        JournalCleaner, AppleLitterCleaner, VmToolingCleaner, CondaCleaner,
        OpamCleaner, SdkmanCleaner, GemCleanupCleaner, CpanmCleaner,
        BackupCacheCleaner, PodmanCleaner,
    ]


def test_opted_in_cleaners_run_on_windows(monkeypatch):
    _win(monkeypatch)
    for cls in OPTED_IN:
        assert supports(cls.platforms) is True, cls.__name__
    for cls in _posix_only():
        assert supports(cls.platforms) is False, cls.__name__


def test_opted_in_still_supported_on_linux(monkeypatch):
    monkeypatch.setattr(platform, "current_os", lambda: "linux")
    for cls in OPTED_IN:
        assert supports(cls.platforms) is True, cls.__name__


def test_no_cleaner_scans_run_on_windows_without_optin(monkeypatch):
    from cleanix.core.registry import build_cleaners

    _win(monkeypatch)
    cleaners = build_cleaners(Config())
    assert cleaners
    for c in cleaners:
        assert platform.WINDOWS in c.platforms, c.id
    assert "wsl_disk" in {c.id for c in cleaners}


def test_ai_cleaners_work_on_windows(fake_win, monkeypatch):
    _win(monkeypatch)
    old = fake_win.home / ".claude" / "debug"
    old.mkdir(parents=True)
    f = old / "log.txt"
    f.write_bytes(b"x" * 64)
    t = f.stat().st_mtime - 7200
    os.utime(f, (t, t))
    paths = {str(i.path) for i in ClaudeCodeCleaner(Config()).find_items()}
    assert str(f) in paths
    (fake_win.home / ".codex" / "log").mkdir(parents=True)
    assert CodexCleaner(Config()).supported()
    list(CodexCleaner(Config()).find_items())


def test_walk_pruned_skips_appdata(fake_win):
    (fake_win.home / "AppData" / "Local").mkdir(parents=True, exist_ok=True)
    (fake_win.home / "AppData" / "hidden.bin").write_bytes(b"x")
    (fake_win.home / "AppData" / "Local" / "deep.bin").write_bytes(b"x")
    (fake_win.home / "keep.bin").write_bytes(b"x")
    seen = {
        os.path.join(d, n)
        for d, _dn, fn in walk_pruned(fake_win.home) for n in fn
    }
    assert str(fake_win.home / "keep.bin") in seen
    assert not any("AppData" in os.path.relpath(p, fake_win.home) for p in seen)


def test_walk_pruned_skips_junctions_on_windows(tmp_path, monkeypatch):
    from cleanix.core import safety

    monkeypatch.setattr(platform, "is_windows", lambda: True)
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "a.bin").write_bytes(b"x")
    (tmp_path / "junc").mkdir()
    (tmp_path / "junc" / "b.bin").write_bytes(b"x")
    monkeypatch.setattr(
        safety, "is_reparse_point", lambda p: os.path.basename(str(p)) == "junc"
    )
    seen = {n for _d, _dn, fn in walk_pruned(tmp_path) for n in fn}
    assert seen == {"a.bin"}


def test_wsl_reports_vhdx_report_only(fake_win, monkeypatch):
    _win(monkeypatch)
    vhdx = (fake_win.local / "Packages" / "CanonicalGroup.Ubuntu_x" /
            "LocalState" / "ext4.vhdx")
    vhdx.parent.mkdir(parents=True)
    vhdx.write_bytes(b"v" * 1000)
    dk = fake_win.local / "Docker" / "wsl" / "data" / "ext4.vhdx"
    dk.parent.mkdir(parents=True)
    dk.write_bytes(b"d" * 500)
    other = fake_win.local / "Packages" / "Other" / "LocalState" / "x.txt"
    other.parent.mkdir(parents=True)
    other.write_bytes(b"x")
    items = list(WslDiskReporter(Config()).find_items())
    assert {str(i.path) for i in items} == {str(vhdx), str(dk)}
    for i in items:
        assert i.report_only is True
        assert "wsl --manage" in i.hint
        assert "--set-sparse true" in i.hint
    assert WslDiskReporter.platforms == (platform.WINDOWS,)


def test_browser_profiles_windows_roots(fake_win, monkeypatch):
    _win(monkeypatch)
    prof = fake_win.local / "Google" / "Chrome" / "User Data" / "Profile 2"
    _mk(prof)
    old = prof.stat().st_mtime - 400 * 86400
    base = fake_win.roaming / "Mozilla" / "Firefox"
    ff = base / "Profiles" / "abc.stale"
    active = base / "Profiles" / "xyz.default"
    _mk(ff)
    _mk(active)
    for d in (prof, ff, active):
        os.utime(d / "f", (old, old))
        os.utime(d, (old, old))
    (base / "profiles.ini").write_text(
        "[Profile0]\nName=default\nPath=Profiles/xyz.default\nDefault=1\n"
    )
    paths = {str(i.path) for i in BrowserProfileReporter(Config()).find_items()}
    assert str(prof) in paths and str(ff) in paths
    assert str(active) not in paths
