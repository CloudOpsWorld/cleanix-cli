"""Windows core cleaners: temp, thumbnails, error reports, Recycle Bin."""

from __future__ import annotations

import os
import time

from cleanix.cleaners import windows_core as wc
from cleanix.cleaners.windows_core import (
    WinErrorReportingCleaner,
    WinRecycleBinCleaner,
    WinTempCleaner,
    WinThumbnailCleaner,
)
from cleanix.config import Config
from cleanix.core import platform, winenv
from cleanix.core.models import ItemKind


def _age(path, days):
    t = time.time() - days * 86400
    os.utime(path, (t, t))


def _paths(items):
    return {i.path for i in items}


def test_win_temp_offers_old_files_only(fake_win):
    temp = winenv.user_temp()
    temp.mkdir(parents=True)
    old = temp / "old.tmp"
    old.write_bytes(b"x" * 100)
    _age(old, 10)
    (temp / "fresh.tmp").write_bytes(b"y" * 50)
    items = list(WinTempCleaner(Config()).find_items())
    assert len(items) == 1
    assert items[0].path == str(old)
    assert items[0].size == 100


def test_win_temp_skips_package_dirs(fake_win):
    temp = winenv.user_temp()
    for name in ("WinGet", "Chocolatey", "other"):
        d = temp / name
        d.mkdir(parents=True)
        (d / "f").write_bytes(b"z")
        _age(d / "f", 10)
        _age(d, 10)
    paths = _paths(WinTempCleaner(Config()).find_items())
    assert str(temp / "other") in paths
    assert str(temp / "WinGet") not in paths
    assert str(temp / "Chocolatey") not in paths


def test_win_temp_never_offers_temp_itself(fake_win):
    temp = winenv.user_temp()
    temp.mkdir(parents=True)
    (temp / "a").write_bytes(b"1")
    _age(temp / "a", 10)
    assert str(temp) not in _paths(WinTempCleaner(Config()).find_items())


def test_thumbnails_match_only_cache_dbs(fake_win):
    ex = fake_win.local / "Microsoft" / "Windows" / "Explorer"
    ex.mkdir(parents=True)
    (ex / "thumbcache_256.db").write_bytes(b"1")
    (ex / "iconcache_32.db").write_bytes(b"1")
    (ex / "other.db").write_bytes(b"1")
    (fake_win.local / "IconCache.db").write_bytes(b"1")
    paths = _paths(WinThumbnailCleaner(Config()).find_items())
    assert str(ex / "thumbcache_256.db") in paths
    assert str(ex / "iconcache_32.db") in paths
    assert str(fake_win.local / "IconCache.db") in paths
    assert str(ex / "other.db") not in paths


def test_error_reports_and_crashdumps_offered(fake_win):
    wer = fake_win.local / "Microsoft" / "Windows" / "WER" / "ReportArchive"
    wer.mkdir(parents=True)
    (wer / "r.wer").write_bytes(b"1")
    dumps = fake_win.local / "CrashDumps"
    dumps.mkdir()
    (dumps / "app.dmp").write_bytes(b"1")
    paths = _paths(WinErrorReportingCleaner(Config()).find_items())
    assert str(wer) in paths
    assert str(wer.parent) not in paths
    assert str(dumps / "app.dmp") in paths


def test_recycle_bin_command_item(monkeypatch):
    monkeypatch.setattr(winenv, "recycle_bin_size", lambda: 1234)
    items = list(WinRecycleBinCleaner(Config()).find_items())
    assert len(items) == 1
    assert items[0].kind is ItemKind.COMMAND
    assert items[0].size == 1234
    assert items[0].command[0] == "powershell"
    assert items[0].requires_root is False
    monkeypatch.setattr(winenv, "recycle_bin_size", lambda: 0)
    assert list(WinRecycleBinCleaner(Config()).find_items()) == []


def test_cleaners_declare_windows_only(monkeypatch):
    monkeypatch.setattr(platform, "current_os", lambda: "linux")
    for cls in (WinTempCleaner, WinThumbnailCleaner,
                WinErrorReportingCleaner, WinRecycleBinCleaner):
        assert cls.platforms == (platform.WINDOWS,)
        assert platform.supports(cls.platforms) is False
        assert cls(Config()).supported() is False


def test_unreadable_dir_does_not_raise(fake_win, monkeypatch):
    def boom(_p):
        raise PermissionError("denied")
        yield  # pragma: no cover

    monkeypatch.setattr(wc, "iter_children", boom)
    for cls in (WinTempCleaner, WinThumbnailCleaner, WinErrorReportingCleaner):
        report = cls(Config()).scan()
        assert report.skipped_reason or not report.items
