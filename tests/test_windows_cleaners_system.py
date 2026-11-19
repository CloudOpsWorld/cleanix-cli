"""Windows system (admin-level) cleaners."""

from __future__ import annotations

import os
import sys
import time

import pytest

from cleanix.cleaners import windows_system as ws
from cleanix.cleaners.windows_system import (
    WinComponentStoreCleaner,
    WinPrefetchReporter,
    WinSystemDumpsCleaner,
    WinSystemTempCleaner,
    WinUpdateCacheCleaner,
    WindowsOldReporter,
)
from cleanix.config import Config
from cleanix.core import safety_windows, winenv
from cleanix.core.models import ItemKind

NS = "ServiceProfiles/NetworkService/AppData/Local/Microsoft/Windows/DeliveryOptimization/Cache"


def _winify(path) -> str:
    """Spell a fake_win path as a Windows absolute path on every host.

    On Windows tmp_path already is one; elsewhere a POSIX path gets a ``C:``
    prefix and backslash separators so the pure string guard can judge it.
    """
    s = str(path)
    return s if os.name == "nt" else "C:" + s.replace("/", "\\")


def _mk(path, data=b"x" * 10, days=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if days:
        t = time.time() - days * 86400
        os.utime(path, (t, t))
    return path


def _populate(fw):
    sr = fw.system_root
    _mk(sr / "Temp" / "old.tmp", days=10)
    _mk(sr / "SoftwareDistribution" / "Download" / "pkg.bin")
    _mk(sr / NS / "blob")
    _mk(sr / "MEMORY.DMP")
    _mk(sr / "Minidump" / "a.dmp")
    _mk(sr / "LiveKernelReports" / "b.dmp")
    wer = fw.programdata / "Microsoft" / "Windows" / "WER"
    _mk(wer / "ReportArchive" / "r1")
    _mk(wer / "ReportQueue" / "r2")


def _deletable(fw):
    cfg = Config()
    out = []
    for cls in (WinSystemTempCleaner, WinUpdateCacheCleaner, WinSystemDumpsCleaner):
        out += list(cls(cfg).find_items())
    return out


def test_update_cache_offers_download_children(fake_win):
    _populate(fake_win)
    paths = {i.path for i in WinUpdateCacheCleaner(Config()).find_items()}
    sr = fake_win.system_root
    assert str(sr / "SoftwareDistribution" / "Download" / "pkg.bin") in paths
    assert str(sr / NS / "blob") in paths
    assert str(sr / "SoftwareDistribution" / "Download") not in paths


def test_system_dumps_cover_memory_dmp_and_minidump(fake_win):
    _populate(fake_win)
    paths = {i.path for i in WinSystemDumpsCleaner(Config()).find_items()}
    sr = fake_win.system_root
    wer = fake_win.programdata / "Microsoft" / "Windows" / "WER"
    assert str(sr / "MEMORY.DMP") in paths
    assert str(sr / "Minidump" / "a.dmp") in paths
    assert str(sr / "LiveKernelReports" / "b.dmp") in paths
    assert str(wer / "ReportArchive" / "r1") in paths
    assert str(wer / "ReportQueue" / "r2") in paths
    assert str(sr / "Minidump") not in paths


def test_system_temp_respects_age(fake_win):
    _populate(fake_win)
    _mk(fake_win.system_root / "Temp" / "fresh.tmp")
    paths = {i.path for i in WinSystemTempCleaner(Config()).find_items()}
    assert paths == {str(fake_win.system_root / "Temp" / "old.tmp")}


def test_every_path_item_passes_windows_guard(fake_win):
    _populate(fake_win)
    sr = fake_win.system_root
    env = {
        "SystemRoot": _winify(sr),
        "SystemDrive": sr.drive or "C:",
        "ProgramData": _winify(fake_win.programdata),
    }
    items = _deletable(fake_win)
    assert len(items) >= 7
    for item in items:
        assert item.kind is ItemKind.PATH
        assert safety_windows.violation(
            _winify(item.path), env, [_winify(fake_win.home)]
        ) is None, item.path


def test_prefetch_and_windows_old_are_report_only(fake_win, monkeypatch):
    _mk(fake_win.system_root / "Prefetch" / "A.pf")
    drive = fake_win.system_root.parent
    _mk(drive / "Windows.old" / "f")
    monkeypatch.setattr(winenv, "system_drive", lambda: str(drive))
    for cls in (WinPrefetchReporter, WindowsOldReporter):
        items = list(cls(Config()).find_items())
        assert len(items) == 1
        assert items[0].report_only is True
        assert items[0].hint


def test_windows_old_path_uses_system_drive(fake_win, monkeypatch):
    drive = fake_win.system_root.parent
    _mk(drive / "Windows.old" / "f")
    monkeypatch.setattr(winenv, "system_drive", lambda: str(drive))
    (item,) = WindowsOldReporter(Config()).find_items()
    assert item.path == os.path.join(str(drive) + os.sep, "Windows.old")


@pytest.mark.skipif(sys.platform != "win32",
                    reason="asserts the literal drive-letter spelling of the Windows.old path under the C: drive")
def test_windows_old_path_for_drive_letter(fake_win, monkeypatch):
    monkeypatch.setattr(winenv, "system_drive", lambda: "C:")
    seen = []
    monkeypatch.setattr(WindowsOldReporter, "report_item",
                        lambda self, path, *a, **k: seen.append(path))
    list(WindowsOldReporter(Config()).find_items())
    assert seen == ["C:" + chr(92) + "Windows.old"]


def test_component_store_is_opt_in(fake_win, monkeypatch):
    assert WinComponentStoreCleaner.default_enabled is False
    monkeypatch.setattr(ws, "which", lambda name: None)
    reason = WinComponentStoreCleaner(Config()).available()
    assert isinstance(reason, str) and reason
    monkeypatch.setattr(ws, "which", lambda name: r"C:\Windows\System32\Dism.exe")
    assert WinComponentStoreCleaner(Config()).available() is None
    (item,) = WinComponentStoreCleaner(Config()).find_items()
    assert item.kind is ItemKind.COMMAND
    assert item.command == ["Dism.exe", "/Online", "/Cleanup-Image", "/StartComponentCleanup"]
    assert item.size == 0


def test_admin_cleaners_marked_requires_root(fake_win):
    _populate(fake_win)
    items = _deletable(fake_win)
    assert items and all(i.requires_root is True for i in items)
