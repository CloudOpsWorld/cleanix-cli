"""Windows application cleaners: browsers, shaders, package managers, IDEs."""

from __future__ import annotations

import os
import time

from cleanix.cleaners import app_cruft
from cleanix.cleaners.app_cruft import ElectronCacheCleaner, JetBrainsCleaner
from cleanix.cleaners.windows_apps import (
    WinBrowserCacheCleaner,
    WinPackageCacheCleaner,
    WinShaderCacheCleaner,
    WinVisualStudioCleaner,
)
from cleanix.cleaners.windows_core import WinTempCleaner
from cleanix.config import Config
from cleanix.core import platform, winenv


def _paths(items):
    return {i.path for i in items}


def _mk(path, data=b"x" * 10):
    path.mkdir(parents=True, exist_ok=True)
    (path / "f").write_bytes(data)
    return path


def test_browser_offers_cache_dirs_only(fake_win):
    prof = fake_win.local / "Google" / "Chrome" / "User Data" / "Default"
    _mk(prof / "Cache")
    _mk(prof / "Code Cache")
    _mk(prof / "Local Storage")
    _mk(prof / "IndexedDB")
    (prof / "Cookies").write_bytes(b"c")
    (prof / "Login Data").write_bytes(b"l")
    (prof / "History").write_bytes(b"h")
    cfg = Config()
    cfg.browsers = ["chrome", "firefox"]
    paths = _paths(WinBrowserCacheCleaner(cfg).find_items())
    assert paths == {str(prof / "Cache"), str(prof / "Code Cache")}


def test_browser_respects_config_for_chrome_and_firefox(fake_win):
    chrome = fake_win.local / "Google" / "Chrome" / "User Data" / "Default" / "Cache"
    edge = fake_win.local / "Microsoft" / "Edge" / "User Data" / "Profile 1" / "GPUCache"
    ff = fake_win.local / "Mozilla" / "Firefox" / "Profiles" / "abc.default" / "cache2"
    for d in (chrome, edge, ff):
        _mk(d)
    cfg = Config()
    cfg.browsers = []
    assert _paths(WinBrowserCacheCleaner(cfg).find_items()) == {str(edge)}
    cfg.browsers = ["chrome", "firefox"]
    assert _paths(WinBrowserCacheCleaner(cfg).find_items()) == {
        str(chrome), str(edge), str(ff)
    }


def test_shader_cache_paths(fake_win):
    rels = [
        ("D3DSCache",), ("NVIDIA", "DXCache"), ("NVIDIA", "GLCache"),
        ("AMD", "DxCache"), ("AMD", "GLCache"),
    ]
    expected = set()
    for rel in rels:
        d = _mk(fake_win.local.joinpath(*rel))
        expected.add(str(d))
    _mk(fake_win.local / "NVIDIA" / "Other")
    assert _paths(WinShaderCacheCleaner(Config()).find_items()) == expected


def test_package_caches_and_env_override(fake_win, monkeypatch, tmp_path):
    temp = winenv.user_temp()
    winget = _mk(temp / "WinGet")
    choco = _mk(temp / "chocolatey")
    nuget = _mk(fake_win.local / "NuGet" / "v3-cache")
    choco_root = tmp_path / "choco"
    bad = _mk(choco_root / "lib-bad")
    scoop = tmp_path / "myscoop"
    scoop_cache = _mk(scoop / "cache")
    monkeypatch.setenv("ChocolateyInstall", str(choco_root))
    monkeypatch.setenv("SCOOP", str(scoop))
    paths = _paths(WinPackageCacheCleaner(Config()).find_items())
    assert paths == {str(p) for p in (winget, choco, nuget, bad, scoop_cache)}


def test_package_caches_default_scoop_and_unset_choco(fake_win, monkeypatch):
    monkeypatch.delenv("SCOOP", raising=False)
    monkeypatch.delenv("ChocolateyInstall", raising=False)
    cache = _mk(fake_win.home / "scoop" / "cache")
    assert _paths(WinPackageCacheCleaner(Config()).find_items()) == {str(cache)}


def test_visualstudio_component_cache(fake_win):
    d = _mk(fake_win.local / "Microsoft" / "VisualStudio" / "17.0_abc" / "ComponentModelCache")
    _mk(fake_win.local / "Microsoft" / "VisualStudio" / "17.0_abc" / "Settings")
    assert _paths(WinVisualStudioCleaner(Config()).find_items()) == {str(d)}


def test_electron_declares_windows():
    assert platform.WINDOWS in ElectronCacheCleaner.platforms
    assert platform.WINDOWS in JetBrainsCleaner.platforms


def test_electron_on_windows_keeps_session_data(fake_win, monkeypatch):
    monkeypatch.setattr(platform, "is_windows", lambda: True)
    slack = fake_win.roaming / "Slack"
    cache = _mk(slack / "Cache")
    _mk(slack / "Local Storage")
    (slack / "Cookies").write_bytes(b"c")
    _mk(fake_win.roaming / "BraveSoftware" / "Cache")
    _mk(fake_win.roaming / "google-chrome" / "Cache")
    assert _paths(ElectronCacheCleaner(Config()).find_items()) == {str(cache)}


def test_jetbrains_windows_caches_offered(fake_win, monkeypatch):
    monkeypatch.setattr(platform, "is_windows", lambda: True)
    prod = fake_win.local / "JetBrains" / "PyCharm2025.1"
    caches = _mk(prod / "caches")
    log = _mk(prod / "log")
    _mk(prod / "options")
    assert _paths(JetBrainsCleaner(Config()).find_items()) == {str(caches), str(log)}


def test_no_duplicate_paths_across_cleaners(fake_win, monkeypatch):
    monkeypatch.delenv("SCOOP", raising=False)
    monkeypatch.delenv("ChocolateyInstall", raising=False)
    temp = winenv.user_temp()
    t = time.time() - 20 * 86400
    for name in ("WinGet", "chocolatey", "other"):
        d = _mk(temp / name)
        os.utime(d / "f", (t, t))
        os.utime(d, (t, t))
    _mk(fake_win.local / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache")
    cfg = Config()
    seen = []
    for cls in (WinTempCleaner, WinPackageCacheCleaner, WinBrowserCacheCleaner):
        seen.extend(i.path for i in cls(cfg).find_items())
    assert len(seen) == len(set(seen))
    assert str(temp / "WinGet") in seen
