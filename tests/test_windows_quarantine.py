"""I2: quarantine on Windows never leaks silent copies, never copies junction
targets, and purge reports what it really reclaimed."""

from __future__ import annotations

import errno
import json
import os
import stat
import subprocess
import sys

import pytest

from cleanix.core import quarantine, safety
from cleanix.core.engine import Engine
from cleanix.core.models import CleanableItem

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows quarantine")


def _item(p, size=1):
    return CleanableItem(cleaner_id="t", description="t", size=size, path=str(p))


def _junction(link, target):
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"cannot create junction: {r.stderr or r.stdout}")


@pytest.fixture
def cross_volume(monkeypatch):
    """Force the copy fallback, as if the quarantine were on another volume."""
    def fail(src, dst):
        raise OSError(errno.EXDEV, "simulated cross-volume rename", src)

    monkeypatch.setattr(quarantine, "_rename", fail)


def _files(run):
    return list(run.files_dir.iterdir()) if run.files_dir.exists() else []


def _manifest(run):
    mf = run.dir / "manifest.json"
    return json.loads(mf.read_text(encoding="utf-8")) if mf.exists() else None


def test_store_runs_the_guard_itself(fake_win):
    docs = fake_win.home / "Documents"
    docs.mkdir()
    (docs / "cv.docx").write_text("precious")
    run = quarantine.new_run()
    with pytest.raises(safety.UnsafePathError):
        run.store(docs)
    assert (docs / "cv.docx").exists() and run.items == [] and _files(run) == []


def test_engine_hands_store_the_canonical_path(fake_win, tmp_path, monkeypatch):
    junk = tmp_path / "junk"
    junk.mkdir()
    seen = []
    run = quarantine.new_run()
    monkeypatch.setattr(run, "store", lambda p: seen.append(str(p)))
    raw = str(tmp_path / "x" / ".." / "junk").replace("\\", "/")
    Engine([]).clean([_item(raw)], dry_run=False, quarantine=run)
    assert seen == [str(safety.assert_safe_to_delete(raw))]


def test_locked_file_same_volume_fails_without_copy(fake_win, tmp_path):
    junk = tmp_path / "junk"
    junk.mkdir()
    (junk / "a.txt").write_text("a")
    locked = junk / "locked.txt"
    locked.write_text("x")
    run = quarantine.new_run()
    with open(locked, "rb"):
        res = Engine([]).clean([_item(junk)], dry_run=False, quarantine=run)
    assert res.outcomes[0].error
    assert (junk / "a.txt").exists() and locked.exists()
    assert _files(run) == [] and run.items == []


def test_locked_file_cross_volume_copy_is_recorded(fake_win, tmp_path, cross_volume):
    junk = tmp_path / "junk"
    junk.mkdir()
    (junk / "a.txt").write_text("a")
    locked = junk / "zz_locked.txt"
    locked.write_text("x")
    run = quarantine.new_run()
    with open(locked, "rb"):
        res = Engine([]).clean([_item(junk)], dry_run=False, quarantine=run)
    assert res.outcomes[0].error
    assert locked.exists()                          # source not forced
    data = _manifest(run)                           # ... and the copy is NOT silent
    assert data and len(data["items"]) == 1
    assert data["items"][0]["original"] == str(safety.assert_safe_to_delete(junk))
    assert data["items"][0].get("partial") is True
    assert any(r["run_id"] == run.run_id for r in quarantine.list_runs())
    # the recorded copy is purgeable and restore refuses to overwrite
    assert quarantine.restore(run.run_id)["failed"]
    quarantine.purge(run.run_id)
    assert not run.dir.exists()


def test_junction_inside_dir_cross_volume_never_copies_target(fake_win, tmp_path, cross_volume):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("keep")
    junk = tmp_path / "junk"
    junk.mkdir()
    (junk / "f.txt").write_text("f")
    _junction(junk / "j", target)
    run = quarantine.new_run()
    with pytest.raises(OSError):
        run.store(junk)
    assert (target / "keep.txt").exists()
    assert safety.is_reparse_point(junk / "j") and (junk / "f.txt").exists()
    assert _files(run) == [] and run.items == []


def test_top_level_junction_cross_volume_refused(fake_win, tmp_path, cross_volume):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("keep")
    link = tmp_path / "link"
    _junction(link, target)
    run = quarantine.new_run()
    with pytest.raises(OSError):
        run.store(link)
    assert (target / "keep.txt").exists() and safety.is_reparse_point(link)
    assert _files(run) == [] and run.items == []


def test_junction_same_volume_moves_link_only(fake_win, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("keep")
    link = tmp_path / "link"
    _junction(link, target)
    run = quarantine.new_run()
    run.store(link)
    assert not os.path.lexists(link)
    assert (target / "keep.txt").exists()
    stored = run.items[0]["stored"]
    assert safety.is_reparse_point(stored)


def test_cross_volume_plain_dir_and_file_roundtrip(fake_win, tmp_path, cross_volume):
    junk = tmp_path / "junk"
    (junk / "sub").mkdir(parents=True)
    (junk / "sub" / "f.txt").write_text("f" * 100)
    single = tmp_path / "single.log"
    single.write_text("s" * 50)
    run = quarantine.new_run()
    run.store(junk)
    run.store(single)
    run.save()
    assert not junk.exists() and not single.exists()
    assert all(not i.get("partial") for i in run.items)
    res = quarantine.restore(run.run_id)
    assert not res["failed"]
    assert (junk / "sub" / "f.txt").read_text() == "f" * 100
    assert single.read_text() == "s" * 50


def test_restore_plain_dir_and_file(fake_win, tmp_path):
    junk = tmp_path / "junk"
    junk.mkdir()
    (junk / "f.txt").write_text("f")
    single = tmp_path / "single.log"
    single.write_text("s")
    run = quarantine.new_run()
    Engine([]).clean([_item(junk), _item(single)], dry_run=False, quarantine=run)
    run.save()
    assert not junk.exists() and not single.exists()
    res = quarantine.restore(run.run_id)
    assert not res["failed"] and len(res["restored"]) == 2
    assert (junk / "f.txt").read_text() == "f" and single.read_text() == "s"
    assert not run.dir.exists()


def test_readonly_files_are_really_purged(fake_win, tmp_path):
    junk = tmp_path / "pack"
    junk.mkdir()
    ro = junk / "pack-123.pack"
    ro.write_bytes(b"x" * 4096)
    os.chmod(ro, stat.S_IREAD)
    run = quarantine.new_run()
    run.store(junk)
    run.save()
    freed, errors = quarantine.purge_detailed(run.run_id)
    assert errors == []
    assert freed > 0
    assert not run.dir.exists()


def test_purge_reports_errors_and_real_bytes(fake_win, tmp_path):
    junk = tmp_path / "junk"
    junk.mkdir()
    (junk / "a.bin").write_bytes(b"a" * 8192)
    (junk / "zz.bin").write_bytes(b"z" * 8192)
    run = quarantine.new_run()
    run.store(junk)
    run.save()
    stored = run.items[0]["stored"]
    total = run.items[0]["size"]
    with open(os.path.join(stored, "zz.bin"), "rb"):
        freed, errors = quarantine.purge_detailed(run.run_id)
        assert errors
        assert freed < total
        assert os.path.exists(os.path.join(stored, "zz.bin"))
    # once released, purge finishes the job
    freed2, errors2 = quarantine.purge_detailed(run.run_id)
    assert errors2 == [] and not run.dir.exists()
