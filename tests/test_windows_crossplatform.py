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
    sess = fake_win.home / ".codex" / "sessions" / "2025" / "01" / "01"
    sess.mkdir(parents=True)
    rollout = sess / "rollout-1.jsonl"
    rollout.write_bytes(b"x" * 64)
    t = rollout.stat().st_mtime - 90 * 86400
    os.utime(rollout, (t, t))
    codex = {str(i.path) for i in CodexCleaner(Config()).find_items()}
    assert str(rollout) in codex


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


def test_walk_pruned_appdata_windows_only(tmp_path, monkeypatch):
    (tmp_path / "AppData").mkdir()
    (tmp_path / "AppData" / "in.bin").write_bytes(b"x")
    (tmp_path / "keep.bin").write_bytes(b"x")

    monkeypatch.setattr(platform, "is_windows", lambda: False)
    seen = {n for _d, _dn, fn in walk_pruned(tmp_path) for n in fn}
    assert seen == {"in.bin", "keep.bin"}

    monkeypatch.setattr(platform, "is_windows", lambda: True)
    seen = {n for _d, _dn, fn in walk_pruned(tmp_path) for n in fn}
    assert seen == {"keep.bin"}
    # A caller-supplied prune set is honoured verbatim (no implicit AppData).
    seen = {n for _d, _dn, fn in walk_pruned(tmp_path, prune={"x"}) for n in fn}
    assert seen == {"in.bin", "keep.bin"}


def test_project_cruft_skips_junctions_on_windows(tmp_path, monkeypatch):
    from cleanix.core import safety

    proj = tmp_path / "proj"
    (proj / "junc" / "node_modules").mkdir(parents=True)
    (proj / "junc" / "node_modules" / "f").write_bytes(b"x")
    (proj / "real" / "node_modules").mkdir(parents=True)
    (proj / "real" / "node_modules" / "f").write_bytes(b"x")
    old = 1_000_000_000
    for d in (proj, proj / "junc", proj / "real",
              proj / "junc" / "node_modules", proj / "real" / "node_modules"):
        os.utime(d, (old, old))
    cfg = Config()
    cfg.project_scan_dirs = [str(proj)]
    monkeypatch.setattr(
        safety, "is_reparse_point", lambda p: os.path.basename(str(p)) == "junc"
    )

    def paths():
        return {str(i.path) for i in ProjectCruftCleaner(cfg).find_items()}

    monkeypatch.setattr(platform, "is_windows", lambda: True)
    assert paths() == {str(proj / "real" / "node_modules")}
    monkeypatch.setattr(platform, "is_windows", lambda: False)
    assert str(proj / "junc" / "node_modules") in paths()


def _age(*paths, days=400):
    for p in paths:
        t = p.stat().st_mtime - days * 86400
        os.utime(p, (t, t))


def _put(path, data=b"x" * 64, days=400):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    _age(path, days=days)
    return path


def _setup_ollama(w, cfg):
    models = w.home / ".ollama" / "models"
    (models / "manifests" / "reg" / "lib" / "m").mkdir(parents=True)
    (models / "manifests" / "reg" / "lib" / "m" / "latest").write_text(
        '{"config": {"digest": "sha256:aaa"}, "layers": []}'
    )
    _put(models / "blobs" / "sha256-aaa")
    return [str(_put(models / "blobs" / "sha256-dangling")),
            str(_put(w.home / ".ollama" / "logs" / "server.log"))]


def _setup_hf(w, cfg):
    return [str(_put(
        w.home / ".cache" / "huggingface" / "hub" / "models--x" / "blobs" /
        "abc.incomplete"
    ))]


def _setup_compile_cache(w, cfg):
    _put(w.home / ".triton" / "cache" / "k.bin")
    return [str(w.home / ".triton" / "cache")]


def _setup_ai_client(w, cfg):
    _put(w.home / ".continue" / "logs" / "core.log")
    return [str(w.home / ".continue" / "logs")]


def _setup_aider(w, cfg):
    return [str(_put(w.home / "proj" / ".aider.chat.history.md"))]


def _setup_gemini(w, cfg):
    d = _put(w.home / ".gemini" / "tmp" / "hash1" / "logs.json").parent
    _age(d)
    return [str(d)]


def _setup_opencode(w, cfg):
    return [str(_put(w.home / ".local" / "share" / "opencode" / "log" / "a.log"))]


def _setup_big(w, cfg):
    cfg.big_file_min_size_mb = 0.0001
    return [str(_put(w.home / "vids" / "big.bin", b"b" * 4096))]


def _setup_downloads(w, cfg):
    cfg.downloads_min_size_mb = 0.0001
    return [str(_put(w.home / "Downloads" / "setup.exe", b"d" * 4096))]


def _setup_duplicates(w, cfg):
    cfg.dup_min_size_mb = 0.0001
    a = _put(w.home / "a" / "same.bin", b"s" * 4096)
    _put(w.home / "b" / "same.bin", b"s" * 4096)
    return [str(a)]  # representative is the sorted-first copy


def _setup_project_cruft(w, cfg):
    proj = w.home / "Projects" / "app"
    nm = proj / "node_modules"
    _put(nm / "m.js")
    _put(proj / "src.js")
    _age(nm, proj)
    return [str(nm)]


WIN_OFFERS = [
    (OllamaCleaner, _setup_ollama),
    (HuggingFaceCleaner, _setup_hf),
    (AICompileCacheCleaner, _setup_compile_cache),
    (AIClientCleaner, _setup_ai_client),
    (AiderLitterCleaner, _setup_aider),
    (GeminiCliCleaner, _setup_gemini),
    (OpenCodeCleaner, _setup_opencode),
    (BigFileReporter, _setup_big),
    (DownloadsReporter, _setup_downloads),
    (DuplicateFileReporter, _setup_duplicates),
    (ProjectCruftCleaner, _setup_project_cruft),
]


@pytest.mark.parametrize(
    "cls,setup", WIN_OFFERS, ids=[c.__name__ for c, _ in WIN_OFFERS]
)
def test_opted_in_cleaner_offers_home_relative_items_on_windows(
    fake_win, monkeypatch, cls, setup
):
    _win(monkeypatch)
    for var in ("OLLAMA_MODELS", "HF_HOME", "CODEX_HOME", "XDG_DATA_HOME"):
        monkeypatch.delenv(var, raising=False)
    cfg = Config()
    expected = setup(fake_win, cfg)
    offered = {str(i.path) for i in cls(cfg).find_items()}
    for path in expected:
        assert path in offered, (cls.__name__, path, offered)
    # Items must not leak into the AppData tree.
    appdata = str(fake_win.home / "AppData")
    assert not any(p.startswith(appdata) for p in offered)


def test_docker_has_no_offline_path_on_windows(monkeypatch):
    # DockerCleaner is command-driven (needs the docker binary), so only its
    # platform opt-in can be checked offline.
    _win(monkeypatch)
    assert supports(DockerCleaner.platforms) is True
