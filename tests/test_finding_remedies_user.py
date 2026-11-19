"""User-space report-only detectors attach remedies to their findings."""

from __future__ import annotations

import hashlib
import os
import plistlib
import sys
import time

import pytest

from cleanix.cleaners import (
    big_files,
    downloads,
    duplicates,
    orphan_app_data as oad,
    orphan_common as oc,
    orphan_launch_jobs as olj,
    stale_launchers,
    stale_services,
)
from cleanix.config import Config
from cleanix.core.remedy import RemedyKind, fingerprint_of

from test_orphan_app_data import _old_dir, mac  # noqa: F401  (mac is a fixture)

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="needs POSIX symlinks/paths"
)


def _age(path, secs):
    t = time.time() - secs
    os.utime(path, (t, t))


def test_big_files_items_have_path_remedy(tmp_path, monkeypatch):
    monkeypatch.setattr(big_files, "home", lambda: tmp_path)
    big = tmp_path / "big.bin"
    big.write_bytes(b"\xff" * 3 * 1024 * 1024)
    _age(big, 3600)
    cfg = Config()
    cfg.big_file_min_size_mb = 1.0
    (item,) = list(big_files.BigFileReporter(cfg).find_items())
    assert item.report_only
    assert item.remedy.kind is RemedyKind.PATH
    assert item.remedy.fingerprint == fingerprint_of(str(big))
    assert item.remedy.group is None


def test_downloads_items_have_path_remedy(tmp_path, monkeypatch):
    dl = tmp_path / "Downloads"
    dl.mkdir()
    monkeypatch.setattr(downloads, "home", lambda: tmp_path)
    iso = dl / "ubuntu.iso"
    iso.write_bytes(b"x" * 60 * 1024 * 1024)
    _age(iso, 120 * 86400)
    (item,) = list(downloads.DownloadsReporter(Config()).find_items())
    assert item.report_only
    assert item.remedy.kind is RemedyKind.PATH
    assert item.remedy.fingerprint == fingerprint_of(str(iso))


def test_duplicates_share_group_id(tmp_path, monkeypatch):
    monkeypatch.setattr(duplicates, "home", lambda: tmp_path)
    blob = b"X" * (12 * 1024 * 1024)
    other = b"Y" * (12 * 1024 * 1024)
    names = ["a.iso", "b.iso", "c.iso", "d.iso", "e.iso"]
    for name, data in zip(names, [blob, blob, blob, other, other]):
        (tmp_path / name).write_bytes(data)
        _age(tmp_path / name, 3600)
    items = list(duplicates.DuplicateFileReporter(Config()).find_items())
    assert len(items) == 5  # every copy is its own item
    by_group = {}
    for i in items:
        assert i.report_only and i.remedy.kind is RemedyKind.PATH
        assert i.remedy.fingerprint == fingerprint_of(i.path)
        by_group.setdefault(i.remedy.group, []).append(os.path.basename(i.path))
    assert None not in by_group and len(by_group) == 2
    assert sorted(map(sorted, by_group.values())) == [
        ["a.iso", "b.iso", "c.iso"], ["d.iso", "e.iso"],
    ]
    assert hashlib.sha256(blob).hexdigest() in by_group  # documented id


def test_orphan_app_data_user_item_has_remedy(mac):  # noqa: F811
    d = _old_dir(mac.support / "com.unknownvendor.Other")
    items = [
        i for i in oad.OrphanAppDataReporter(Config()).scan().items
        if i.description.startswith("Left by a removed app")
    ]
    (item,) = items
    assert item.requires_root is False and item.report_only
    assert item.remedy.kind is RemedyKind.PATH
    assert item.remedy.fingerprint == fingerprint_of(str(d))


def test_orphan_app_data_system_item_has_no_remedy(mac):  # noqa: F811
    lib = mac.root / "Library" / "Application Support"
    lib.mkdir(parents=True)
    _old_dir(lib / "com.unknownvendor.SysData")
    items = [
        i for i in oad.OrphanAppDataReporter(Config()).scan().items
        if i.description.startswith("Left by a removed app")
    ]
    assert items and all(i.requires_root for i in items)
    assert all(i.remedy is None for i in items)


def _job(path, label, program="/Applications/Gone.app/Contents/MacOS/gone"):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        plistlib.dump({"Label": label, "Program": program}, fh)
    return path


def test_user_launch_job_remedy_kind(orphan_env):
    plist = _job(
        orphan_env.home / "Library" / "LaunchAgents" / "com.gone.job.plist",
        "com.gone.job",
    )
    sysjob = _job(
        orphan_env.root / "Library" / "LaunchDaemons" / "com.gone.sys.plist",
        "com.gone.sys",
    )
    items = olj.OrphanLaunchJobReporter(Config()).scan().items
    user = [i for i in items if i.path == str(plist)]
    system = [i for i in items if i.path == str(sysjob)]
    assert len(user) == 1 and len(system) == 1
    r = user[0].remedy
    assert r.kind is RemedyKind.LAUNCH_JOB
    assert dict(r.extra) == {"label": "com.gone.job"}
    assert r.fingerprint == fingerprint_of(str(plist))
    assert system[0].requires_root and system[0].remedy is None  # Task 9


def test_launch_job_with_odd_label_has_no_remedy(orphan_env):
    plist = _job(
        orphan_env.home / "Library" / "LaunchAgents" / "com.odd.plist",
        "../../evil label",
    )
    items = olj.OrphanLaunchJobReporter(Config()).scan().items
    (item,) = [i for i in items if i.path == str(plist)]
    assert item.remedy is None and item.report_only


def test_user_systemd_unit_remedy_kind(orphan_env):
    unit = orphan_env.home / ".config" / "systemd" / "user" / "mine.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("[Service]\nExecStart=/opt/gone/x\n", encoding="utf-8")
    sysunit = orphan_env.root / "etc/systemd/system/sys.service"
    sysunit.parent.mkdir(parents=True)
    sysunit.write_text("[Service]\nExecStart=/opt/gone/y\n", encoding="utf-8")
    (orphan_env.root / "usr/lib/systemd/system").mkdir(parents=True)
    items = stale_services.StaleSystemdUnitReporter(Config()).scan().items
    (u,) = [i for i in items if i.path == str(unit)]
    assert u.remedy.kind is RemedyKind.SYSTEMD_UNIT
    assert dict(u.remedy.extra) == {"unit": "mine.service"}
    (s,) = [i for i in items if i.path == str(sysunit)]
    assert s.requires_root and s.remedy is None


def test_stale_launcher_user_entry_has_path_remedy(orphan_env):
    entry = orphan_env.home / ".local/share/applications/gone.desktop"
    entry.parent.mkdir(parents=True)
    entry.write_text(
        "[Desktop Entry]\nType=Application\nName=Gone\nExec=/opt/gone/bin/gone\n",
        encoding="utf-8",
    )
    sysentry = orphan_env.root / "usr/local/share/applications/sys.desktop"
    sysentry.parent.mkdir(parents=True)
    sysentry.write_text(
        "[Desktop Entry]\nType=Application\nName=S\nExec=/opt/gone/bin/s\n",
        encoding="utf-8",
    )
    items = stale_launchers.StaleDesktopEntryReporter(Config()).scan().items
    (u,) = [i for i in items if i.path == str(entry)]
    assert u.remedy.kind is RemedyKind.PATH
    assert u.remedy.fingerprint == fingerprint_of(str(entry))
    (s,) = [i for i in items if i.path == str(sysentry)]
    assert s.requires_root and s.remedy is None


def test_notes_have_no_remedy(orphan_env, monkeypatch):
    # an unreadable user LaunchAgents dir yields a "Could not read" note
    agents = orphan_env.home / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    real = oc.list_dir
    monkeypatch.setattr(
        oc, "list_dir", lambda p: None if p == agents else real(p)
    )
    items = olj.OrphanLaunchJobReporter(Config()).scan().items
    notes = [i for i in items if i.description.startswith("Could not read")]
    assert notes and all(i.remedy is None and i.report_only for i in notes)
    # a Finding flagged as a note never gets a remedy, even if it asks for one
    rep = oc.OrphanReporter(Config())
    f = oc.Finding(
        agents, "n", "h", requires_root=False, note=True,
        remedy_kind=RemedyKind.PATH,
    )
    assert rep._item(f, 0, True).remedy is None


def _dup_tree(tmp_path, monkeypatch, n):
    monkeypatch.setattr(duplicates, "home", lambda: tmp_path)
    size = 12 * 1024 * 1024
    for k in range(n):
        p = tmp_path / f"c{k}.iso"
        p.write_bytes(b"X" * size)
        _age(p, 3600 + k * 100)  # c{n-1} is the oldest
    return size


@pytest.mark.parametrize("n", [2, 3])
def test_duplicate_group_size_sum_is_reclaimable(tmp_path, monkeypatch, n):
    size = _dup_tree(tmp_path, monkeypatch, n)
    items = list(duplicates.DuplicateFileReporter(Config()).find_items())
    assert len(items) == n
    assert sum(i.size for i in items) == (n - 1) * size
    zero = [i for i in items if i.size == 0]
    assert len(zero) == 1  # exactly one default survivor
    assert os.path.basename(zero[0].path) == f"c{n - 1}.iso"  # the oldest
    assert all(i.size == size for i in items if i is not zero[0])


def test_duplicate_report_only_size_unchanged_for_pair(tmp_path, monkeypatch):
    from cleanix.core.models import CleanerReport, ScanResult

    size = _dup_tree(tmp_path, monkeypatch, 2)
    items = list(duplicates.DuplicateFileReporter(Config()).find_items())
    rep = CleanerReport(cleaner_id="duplicates", name="d", description="d",
                        items=items)
    assert ScanResult(reports=[rep]).report_only_size == size  # as before


def test_duplicate_survivor_not_hidden_by_curation(tmp_path, monkeypatch):
    from cleanix.core.curation import build_groups, is_empty

    _dup_tree(tmp_path, monkeypatch, 3)
    items = list(duplicates.DuplicateFileReporter(Config()).find_items())
    assert not any(is_empty(i) for i in items)  # report-only, group remedy


def test_remedy_skipped_for_bad_name(tmp_path):
    from cleanix.core.remedy import path_remedy

    p = tmp_path / "ok.bin"
    p.write_bytes(b"x")
    assert path_remedy(str(p)) is not None
    assert path_remedy(str(tmp_path / "bad\nname")) is None


@posix_only
def test_remedy_skipped_for_symlink(tmp_path):
    from cleanix.core.remedy import path_remedy

    real = tmp_path / "real.bin"
    real.write_bytes(b"x")
    link = tmp_path / "link.bin"
    os.symlink(real, link)
    assert path_remedy(str(link)) is None
