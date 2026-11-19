"""Tests for the findings executor: PATH remedies and duplicates (Task 4)."""

from __future__ import annotations

import dataclasses
import os
import stat
import sys

import pytest

from cleanix.config import Config
from cleanix.core import actions, findings, history, quarantine, remedy, safety, service
from cleanix.core.engine import Engine
from cleanix.core.models import CleanableItem
from cleanix.core.remedy import path_remedy

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")


@pytest.fixture(autouse=True)
def _reset_globs():
    yield
    safety.set_protected_globs([])


@pytest.fixture(autouse=True)
def state(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: tmp_path / "q")
    return tmp_path


def _file(tmp_path, name="big.bin", data=b"x" * 4096, mtime_ns=None):
    d = tmp_path / "home"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_bytes(data)
    if mtime_ns is not None:
        os.utime(str(p), ns=(mtime_ns, mtime_ns))
    return p


def _finding(p, *, group=None, cleaner="big_files", size=None, **kw):
    r = path_remedy(str(p), group=group)
    assert r is not None
    return CleanableItem(
        cleaner_id=cleaner, description=p.name, size=4096 if size is None else size,
        path=str(p), report_only=True, remedy=r, **kw,
    )


def _errors(summary):
    return [o.error for o in summary.result.outcomes if o.error]


def _dups(tmp_path, n=3, data=b"d" * 8192):
    """n identical copies; copy i is older the smaller i is."""
    base = 1_600_000_000 * 10**9
    paths = [_file(tmp_path, f"copy{i}.iso", data, mtime_ns=base + i * 10**9) for i in range(n)]
    items = [_finding(p, group="sha-1", cleaner="duplicates") for p in paths]
    return paths, items


# -- PATH remedies ------------------------------------------------------------


def test_act_quarantines_and_undo_restores(tmp_path):
    p = _file(tmp_path, data=b"keep me")
    summary = actions.act([_finding(p)], Config(), dry_run=False)
    assert not p.exists()
    assert summary.removed == 1 and summary.errors == []
    assert summary.quarantine_run
    assert summary.freed > 0
    assert summary.result.outcomes[0].item.report_only  # caller's finding comes back
    assert [e["mode"] for e in history.load()] == ["quarantine"]
    quarantine.restore(summary.quarantine_run)
    assert p.read_bytes() == b"keep me"


def test_act_quarantines_directory_finding(tmp_path):
    d = tmp_path / "home" / "old_app"
    d.mkdir(parents=True)
    (d / "a.txt").write_text("a")
    item = _finding(d, cleaner="orphan_app_data")
    summary = actions.act([item], Config(), dry_run=False)
    assert summary.removed == 1, _errors(summary)
    assert not d.exists()


def test_act_permanent_deletes(tmp_path):
    p = _file(tmp_path)
    summary = actions.act([_finding(p)], Config(), dry_run=False, permanent=True)
    assert not p.exists()
    assert summary.removed == 1
    assert summary.quarantine_run is None
    assert not (tmp_path / "q").exists() or not any((tmp_path / "q").iterdir())
    assert [e["mode"] for e in history.load()] == ["delete"]


def test_service_act_is_the_same_executor(tmp_path):
    p = _file(tmp_path)
    summary = service.act([_finding(p)], Config(), dry_run=False, permanent=True)
    assert summary.removed == 1 and not p.exists()


def test_act_skips_changed_file(tmp_path):
    p = _file(tmp_path)
    item = _finding(p)
    p.write_bytes(b"different content, different size")
    summary = actions.act([item], Config(), dry_run=False)
    assert p.exists()
    assert summary.removed == 0
    assert _errors(summary)[0].startswith("skipped: changed since scan")
    assert history.load() == []


@posix_only
def test_act_skips_symlink_swap(tmp_path):
    p = _file(tmp_path)
    item = _finding(p)
    target = _file(tmp_path, "precious.txt", b"precious")
    p.unlink()
    os.symlink(str(target), str(p))
    summary = actions.act([item], Config(), dry_run=False, permanent=True)
    assert summary.removed == 0
    assert os.path.islink(str(p))
    assert target.read_bytes() == b"precious"
    assert _errors(summary)[0].startswith("skipped: changed since scan")


def test_act_skips_directory_replaced_by_file(tmp_path):
    d = tmp_path / "home" / "thing"
    d.mkdir(parents=True)
    item = _finding(d)
    d.rmdir()
    d.write_bytes(b"now a file")
    summary = actions.act([item], Config(), dry_run=False, permanent=True)
    assert summary.removed == 0
    assert d.read_bytes() == b"now a file"


def _fake_stat(real, mode):
    fields = list(real)
    fields[stat.ST_MODE] = mode
    return os.stat_result(fields)


def test_act_skips_special_file_with_matching_identity(tmp_path, monkeypatch):
    # The fingerprint carries no mode bits: a non-regular entry with the very
    # same (size, mtime, inode, dev) must still be refused.
    p = _file(tmp_path)
    item = _finding(p)
    real = os.lstat(str(p))
    monkeypatch.setattr(remedy, "_lstat", lambda path: _fake_stat(real, stat.S_IFIFO | 0o644))
    summary = actions.act([item], Config(), dry_run=False, permanent=True)
    assert summary.removed == 0 and p.exists()
    assert "not a regular file" in _errors(summary)[0]


def test_act_skips_link_with_matching_identity(tmp_path, monkeypatch):
    p = _file(tmp_path)
    item = _finding(p)
    real = os.lstat(str(p))
    monkeypatch.setattr(remedy, "_lstat", lambda path: _fake_stat(real, stat.S_IFLNK | 0o777))
    summary = actions.act([item], Config(), dry_run=False, permanent=True)
    assert summary.removed == 0 and p.exists()
    assert "now a link" in _errors(summary)[0]


@pytest.mark.parametrize("exc", [PermissionError("denied"), ValueError("embedded null")])
def test_act_stat_oserror_is_skip(tmp_path, monkeypatch, exc):
    p = _file(tmp_path)
    item = _finding(p)

    def boom(path):
        raise exc

    monkeypatch.setattr(remedy, "_lstat", boom)
    summary = actions.act([item], Config(), dry_run=False, permanent=True)
    assert summary.removed == 0 and p.exists()
    assert _errors(summary)[0].startswith("skipped: changed since scan")


def test_act_refuses_guard_blocked_path(tmp_path):
    p = _file(tmp_path, "protected_thing.bin")
    summary = actions.act([_finding(p)], Config(protected_globs=["*protected_thing*"]),
                          dry_run=False, permanent=True)
    assert p.exists()
    assert summary.removed == 0
    assert _errors(summary) == ["skipped: " + actions.BLOCKED]


def test_act_skips_item_without_remedy(tmp_path):
    a = _file(tmp_path, "a.bin")
    b = _file(tmp_path, "b.bin")
    report_only = CleanableItem(cleaner_id="big_files", description="a", path=str(a),
                                report_only=True)
    ordinary = CleanableItem(cleaner_id="tmp", description="b", path=str(b))
    summary = actions.act([report_only, ordinary], Config(), dry_run=False, permanent=True)
    assert a.exists() and b.exists()
    assert summary.removed == 0
    assert _errors(summary) == ["skipped: " + actions.NOT_A_FINDING] * 2


def test_act_skips_requires_root_item(tmp_path):
    p = _file(tmp_path)
    item = _finding(p, requires_root=True)
    summary = actions.act([item], Config(), dry_run=False, permanent=True)
    assert p.exists()
    assert _errors(summary) == ["skipped: needs an elevated run"]


def test_act_skips_placeholder_fingerprint(tmp_path):
    p = _file(tmp_path)
    item = _finding(p)
    item = dataclasses.replace(item, remedy=dataclasses.replace(item.remedy, fingerprint=(0, 0, 0, 0)))
    summary = actions.act([item], Config(), dry_run=False, permanent=True)
    assert p.exists() and summary.removed == 0


def test_act_same_path_twice_acts_once(tmp_path):
    p = _file(tmp_path)
    item = _finding(p)
    summary = actions.act([item, item], Config(), dry_run=False, permanent=True)
    assert summary.removed == 1
    assert _errors(summary) == ["skipped: listed twice"]


def test_engine_still_refuses_report_only_items(tmp_path):
    p = _file(tmp_path)
    result = Engine([]).clean([_finding(p)], dry_run=False, allow_root_items=False)
    assert p.exists()
    assert result.removed_count == 0
    assert result.outcomes[0].error == "report only (remove manually)"
    # ... and so does service.clean (findings never reach it un-activated).
    summary = service.clean([_finding(p)], Config(), dry_run=False, use_quarantine=False)
    assert p.exists() and summary.removed == 0


def test_dry_run_touches_nothing(tmp_path):
    paths, items = _dups(tmp_path)
    plan = actions.plan_duplicates(items, "oldest")
    big = _file(tmp_path, "big2.bin")
    zero_sized = dataclasses.replace(plan.items[0], size=0)  # trust the disk, not item.size
    summary = actions.act([zero_sized, _finding(big)], Config(), dry_run=True)
    assert all(p.exists() for p in paths) and big.exists()
    assert summary.removed == 0 and summary.errors == []
    assert summary.freed >= 8192 + 4096
    assert summary.quarantine_run is None and summary.manifest_path is None
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "q").exists()


def test_act_record_history_false_refuses_quarantine(tmp_path):
    p = _file(tmp_path)
    with pytest.raises(ValueError):
        actions.act([_finding(p)], Config(), dry_run=False, record_history=False)
    assert p.exists()


# -- duplicates ---------------------------------------------------------------


def test_duplicates_keep_oldest(tmp_path):
    paths, items = _dups(tmp_path)
    plan = actions.plan_duplicates(items, "oldest")
    assert sorted(i.path for i in plan.items) == sorted(str(p) for p in paths[1:])
    assert plan.skipped == [(items[0], findings.KEPT)]
    summary = actions.act(plan.items, Config(), dry_run=False)
    assert summary.removed == 2, _errors(summary)
    assert paths[0].exists() and not paths[1].exists() and not paths[2].exists()


def test_duplicates_keep_newest_and_shortest_path(tmp_path):
    paths, items = _dups(tmp_path)
    newest = actions.plan_duplicates(items, "newest")
    assert newest.skipped == [(items[2], findings.KEPT)]
    short = _file(tmp_path, "c.iso", b"d" * 8192, mtime_ns=1_700_000_000 * 10**9)
    s_item = _finding(short, group="sha-1", cleaner="duplicates")
    shortest = actions.plan_duplicates(items + [s_item], "shortest-path")
    assert shortest.skipped == [(s_item, findings.KEPT)]
    assert len(shortest.items) == 3


def test_plan_duplicates_rejects_bad_keep(tmp_path):
    _paths, items = _dups(tmp_path)
    for bad in ("", "all", "OLDEST", None):
        with pytest.raises(ValueError):
            actions.plan_duplicates(items, bad)


def test_duplicates_never_remove_all_copies(tmp_path):
    paths, items = _dups(tmp_path)
    cfg = Config()
    # Every copy straight into act, without a plan: none names a copy to keep.
    summary = actions.act(items, cfg, dry_run=False, permanent=True)
    assert summary.removed == 0 and all(p.exists() for p in paths)
    # A plan's items plus the kept copy re-added (as a stamped copy): refused.
    plan = actions.plan_duplicates(items, "oldest")
    kept_too = findings._stamp(items[0], items[1])
    summary = actions.act(plan.items + [kept_too], cfg, dry_run=False, permanent=True)
    assert summary.removed == 0 and all(p.exists() for p in paths)
    # A single copy of a group: nothing to choose, nothing removed.
    single = actions.plan_duplicates(items[:1], "oldest")
    assert single.items == [] and len(single.skipped) == 1
    # Every copy through the plan: exactly one survives.
    summary = actions.act(actions.plan_duplicates(items, "newest").items, cfg,
                          dry_run=False, permanent=True)
    assert summary.removed == 2
    assert [p.exists() for p in paths] == [False, False, True]


def test_duplicates_survivor_missing_fails_closed(tmp_path):
    paths, items = _dups(tmp_path)
    plan = actions.plan_duplicates(items, "oldest")
    paths[0].unlink()  # the kept copy vanishes between plan and act
    summary = actions.act(plan.items, Config(), dry_run=False, permanent=True)
    assert summary.removed == 0
    assert paths[1].exists() and paths[2].exists()
    assert all("the copy to keep" in e for e in _errors(summary))
    # Planning again: the oldest is still chosen (scan-time data) and missing,
    # so the whole group is skipped rather than promoting the next copy.
    replan = actions.plan_duplicates(items, "oldest")
    assert replan.items == []
    assert len(replan.skipped) == 3


def test_duplicates_survivor_changed_fails_closed(tmp_path):
    paths, items = _dups(tmp_path)
    plan = actions.plan_duplicates(items, "oldest")
    paths[0].write_bytes(b"edited")
    summary = actions.act(plan.items, Config(), dry_run=False, permanent=True)
    assert summary.removed == 0 and paths[1].exists() and paths[2].exists()


def test_duplicates_fewer_than_two_remaining_skips_group(tmp_path):
    paths, items = _dups(tmp_path, n=2)
    paths[1].unlink()
    plan = actions.plan_duplicates(items, "oldest")
    assert plan.items == []
    assert len(plan.skipped) == 2
    assert paths[0].exists()


def test_plan_duplicates_skips_non_duplicates(tmp_path):
    p = _file(tmp_path)
    plan = actions.plan_duplicates([_finding(p)], "oldest")
    assert plan.items == [] and plan.skipped == [(_finding(p), "not a duplicate copy")]
