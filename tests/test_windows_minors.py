"""Task 12 minors: junction-safe sizing/walks, /tmp gating, --only platform
gate, classic Teams caches, wording, and the guard over all Windows cleaners."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

import cleanix
from cleanix import cli
from cleanix.cleaners import ai_tools, windows_apps, windows_core
from cleanix.cleaners.app_cruft import ElectronCacheCleaner
from cleanix.config import Config
from cleanix.core import platform, safety_windows, utils
from cleanix.core.models import ItemKind
from cleanix.core.registry import build_cleaners

win_only = pytest.mark.skipif(sys.platform != "win32", reason="real junctions")


def _junction(link, target):
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"cannot create junction: {r.stderr or r.stdout}")


def _mk(path, data=b"x" * 10):
    path.mkdir(parents=True, exist_ok=True)
    (path / "f").write_bytes(data)
    return path


# -- junction-safe sizing and walks ---------------------------------------------

@win_only
def test_path_size_never_counts_junction_targets(tmp_path):
    big = tmp_path / "big"
    big.mkdir()
    (big / "blob").write_bytes(b"b" * 1_000_000)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "small").write_bytes(b"s" * 10)
    _junction(tree / "j", big)
    _junction(tmp_path / "top", big)
    assert utils.path_size(tmp_path / "top") == 0
    assert utils.path_size(tree) < 100_000


@win_only
def test_wsl_walk_does_not_follow_junctions(fake_win, tmp_path):
    from cleanix.cleaners.windows_wsl import WslDiskReporter

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "ext4.vhdx").write_bytes(b"v" * 100)
    wsl = fake_win.local / "Docker" / "wsl"
    wsl.mkdir(parents=True)
    _junction(wsl / "j", outside)
    paths = {i.path for i in WslDiskReporter(Config()).find_items()}
    assert str(wsl / "j" / "ext4.vhdx") not in paths


@win_only
def test_codex_session_walk_does_not_follow_junctions(fake_win, tmp_path, monkeypatch):
    from cleanix.cleaners.ai_cli import CodexCleaner

    outside = tmp_path / "outside"
    outside.mkdir()
    old = outside / "rollout-old.jsonl"
    old.write_text("x")
    t = time.time() - 400 * 86400
    os.utime(old, (t, t))
    codex = tmp_path / "codex"
    (codex / "sessions").mkdir(parents=True)
    _junction(codex / "sessions" / "j", outside)
    monkeypatch.setenv("CODEX_HOME", str(codex))
    paths = {i.path for i in CodexCleaner(Config()).find_items()}
    assert not any("rollout-old" in p for p in paths)
    assert old.exists()


# -- /tmp candidates are POSIX-only -------------------------------------------------

def test_ai_compile_cache_has_no_tmp_candidates_on_windows(fake_win, monkeypatch):
    monkeypatch.setattr(platform, "is_windows", lambda: True)
    cands = [str(p) for p, _ in ai_tools.AICompileCacheCleaner(Config())._candidates()]
    assert not any("torchinductor_" in c or "triton_u" in c for c in cands)


def test_ai_compile_cache_keeps_tmp_candidates_on_posix(fake_win, monkeypatch):
    monkeypatch.setattr(platform, "is_windows", lambda: False)
    cands = [p.as_posix() for p, _ in ai_tools.AICompileCacheCleaner(Config())._candidates()]
    assert "/tmp/torchinductor_u" in cands and "/tmp/triton_u" in cands


# -- --only cannot run POSIX cleaners on Windows ------------------------------------

def test_only_forced_posix_cleaner_skipped_on_windows(monkeypatch):
    monkeypatch.setattr(platform, "current_os", lambda: platform.WINDOWS)
    cleaners = build_cleaners(Config(), only=["user_cache", "logs"])
    assert {c.id for c in cleaners} == {"user_cache", "logs"}
    for c in cleaners:
        rep = c.scan()
        assert rep.skipped_reason == "not supported on this platform"
        assert rep.items == []


def test_only_on_posix_still_forces_cleaner(monkeypatch):
    monkeypatch.setattr(platform, "current_os", lambda: "linux")
    (c,) = build_cleaners(Config(), only=["memory"])
    assert c.unsupported_platform is False


def test_only_windows_cleaner_runs_on_windows(fake_win, monkeypatch):
    monkeypatch.setattr(platform, "current_os", lambda: platform.WINDOWS)
    (c,) = build_cleaners(Config(), only=["win_temp"])
    assert c.unsupported_platform is False
    assert c.scan().skipped_reason is None


# -- classic Teams caches -----------------------------------------------------------

def test_electron_offers_classic_teams_but_not_other_microsoft(fake_win, monkeypatch):
    monkeypatch.setattr(platform, "is_windows", lambda: True)
    ms = fake_win.roaming / "Microsoft"
    teams = _mk(ms / "Teams" / "Cache")
    gpu = _mk(ms / "Teams" / "GPUCache")
    _mk(ms / "Teams" / "Local Storage")
    _mk(ms / "Edge" / "Cache")
    _mk(ms / "Word" / "Cache")
    paths = {i.path for i in ElectronCacheCleaner(Config()).find_items()}
    assert paths == {str(teams), str(gpu)}


# -- wording -----------------------------------------------------------------------

def test_wording_mentions_windows():
    assert "Windows" in (cleanix.__doc__ or "")
    assert "Windows" in cli.build_parser().description


def test_disk_label_is_the_system_drive_on_windows(monkeypatch):
    from cleanix.core import winenv

    monkeypatch.setattr(platform, "is_windows", lambda: True)
    monkeypatch.setattr(winenv, "system_drive", lambda: "D:")
    assert cli._disk_label() == "D:\\"
    monkeypatch.setattr(platform, "is_windows", lambda: False)
    assert cli._disk_label() == "/"


# -- every yielded deletable path of every Windows cleaner passes the guard --------

MUST_REFUSE_SUFFIXES = (
    "", "Documents", "Desktop", "AppData", "AppData\\Local", "AppData\\Roaming",
    "AppData\\Local\\Temp", "OneDrive", "OneDrive - Contoso", "OneDrive\\Documents",
)


def _populate_user(fw):
    old = time.time() - 30 * 86400
    temp = fw.local / "Temp"
    for name in ("a.tmp", "dir"):
        p = temp / name
        if name == "dir":
            _mk(p)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"t")
        os.utime(p, (old, old))
    exp = fw.local / "Microsoft" / "Windows" / "Explorer"
    exp.mkdir(parents=True)
    (exp / "thumbcache_256.db").write_bytes(b"d")
    (fw.local / "IconCache.db").write_bytes(b"i")
    _mk(fw.local / "Microsoft" / "Windows" / "WER" / "r1")
    _mk(fw.local / "CrashDumps" / "d1")
    _mk(fw.local / "Google" / "Chrome" / "User Data" / "Default" / "Cache")
    _mk(fw.local / "Microsoft" / "Edge" / "User Data" / "Default" / "GPUCache")
    _mk(fw.local / "D3DSCache")
    _mk(fw.local / "NVIDIA" / "DXCache")
    _mk(fw.local / "NuGet" / "v3-cache")
    _mk(fw.local / "Microsoft" / "VisualStudio" / "17.0_x" / "ComponentModelCache")
    _mk(fw.roaming / "Slack" / "Cache")
    _mk(fw.roaming / "Microsoft" / "Teams" / "Cache")


@pytest.mark.skipif(sys.platform != "win32",
                    reason="the Windows path model needs drive-letter temp paths")
def test_every_windows_cleaner_path_passes_guard(fake_win, monkeypatch):
    monkeypatch.setattr(platform, "is_windows", lambda: True)
    monkeypatch.delenv("SCOOP", raising=False)
    monkeypatch.delenv("ChocolateyInstall", raising=False)
    _populate_user(fake_win)
    sr = fake_win.system_root
    env = {
        "SystemRoot": str(sr),
        "SystemDrive": sr.drive or "C:",
        "ProgramData": str(fake_win.programdata),
    }
    home = str(fake_win.home)
    cfg = Config()
    cfg.browsers = ["chrome", "firefox"]
    classes = [
        windows_core.WinTempCleaner, windows_core.WinThumbnailCleaner,
        windows_core.WinErrorReportingCleaner, windows_core.WinRecycleBinCleaner,
        windows_apps.WinBrowserCacheCleaner, windows_apps.WinShaderCacheCleaner,
        windows_apps.WinPackageCacheCleaner, windows_apps.WinVisualStudioCleaner,
        ElectronCacheCleaner,
    ]
    paths = []
    for cls in classes:
        for item in cls(cfg).find_items():
            if item.kind is ItemKind.PATH and not item.report_only:
                paths.append(item.path)
    assert len(paths) >= 12
    refuse = {os.path.normcase(os.path.join(home, s)) if s else os.path.normcase(home)
              for s in MUST_REFUSE_SUFFIXES}
    for p in paths:
        assert safety_windows.violation(p, env, [home], profiles=[home]) is None, p
        assert os.path.normcase(p) not in refuse, p
    # and the must-refuse table really is refused for this home
    for s in MUST_REFUSE_SUFFIXES:
        target = home + ("\\" + s if s else "")
        assert safety_windows.violation(target, env, [home], profiles=[home]) is not None, s
