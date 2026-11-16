"""Tests for the service layer and engine cancellation."""

import threading
import time

import pytest

from cleanix.config import Config
from cleanix.core import history, quarantine, safety, service
from cleanix.core.engine import Engine
from cleanix.core.models import (
    CleanableItem,
    CleanerReport,
    ItemKind,
    item_key,
)


class FakeCleaner:
    def __init__(self, n, on_scan=None):
        self.id = f"fake{n}"
        self.name = f"Fake {n}"
        self.on_scan = on_scan

    def scan(self):
        if self.on_scan:
            self.on_scan()
        return CleanerReport(cleaner_id=self.id, name=self.name, description="d")


@pytest.fixture(autouse=True)
def _reset_globs():
    yield
    safety.set_protected_globs([])


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: tmp_path / "q")
    return tmp_path


def _files(tmp_path, n=3):
    d = tmp_path / "junk"
    d.mkdir()
    paths = []
    for i in range(n):
        p = d / f"f{i}.bin"
        p.write_bytes(b"x" * 100)
        paths.append(p)
    return paths


def _items(paths):
    return [
        CleanableItem(cleaner_id="t", description=p.name, size=100, path=str(p))
        for p in paths
    ]


def test_item_key_path_and_command():
    a = CleanableItem(cleaner_id="a", description="x", path="/tmp/x")
    b = CleanableItem(cleaner_id="b", description="x", path="/tmp/x")
    assert item_key(a) != item_key(b)
    assert item_key(a) == "a|path|/tmp/x"
    c = CleanableItem(
        cleaner_id="c", description="c", kind=ItemKind.COMMAND,
        command=["apt-get", "clean"],
    )
    assert item_key(c) == "c|cmd|apt-get\x1fclean"


@pytest.mark.parametrize("parallel", [False, True])
def test_engine_scan_cancel_stops_early(parallel):
    done0 = threading.Event()

    def cancel():
        # Non-blocking apart from a short pause that lets cleaner 0 finish
        # before the submit loop asks again (keeps the parallel case stable).
        time.sleep(0.05)
        return done0.is_set()

    cleaners = [FakeCleaner(0, on_scan=done0.set)] + [FakeCleaner(i) for i in range(1, 5)]
    result = Engine(cleaners).scan(parallel=parallel, cancel=cancel)
    assert 1 <= len(result.reports) < 5


def test_engine_clean_cancel_stops_between_items(tmp_path):
    paths = _files(tmp_path)
    items = _items(paths)
    state_ = {"n": 0}

    def progress(_desc):
        state_["n"] += 1

    def cancel():
        return state_["n"] >= 1

    result = Engine([]).clean(
        items, dry_run=False, allow_root_items=False, progress=progress, cancel=cancel
    )
    assert result.removed_count == 1
    assert sum(1 for p in paths if p.exists()) == 2


def test_service_clean_dry_run_touches_nothing(tmp_path, state):
    paths = _files(tmp_path)
    summary = service.clean(_items(paths), Config(), dry_run=True)
    assert all(p.exists() for p in paths)
    assert summary.quarantine_run is None
    assert summary.manifest_path is None
    assert not (state / "state").exists()
    assert history.stats()["runs"] == 0


def test_service_clean_execute_records_history_and_manifest(tmp_path, state):
    paths = _files(tmp_path)
    summary = service.clean(
        _items(paths), Config(), dry_run=False, use_quarantine=False
    )
    assert not any(p.exists() for p in paths)
    assert history.stats()["runs"] == 1
    assert summary.manifest_path
    from pathlib import Path
    assert Path(summary.manifest_path).exists()
    assert summary.freed > 0
    assert summary.removed == 3
    assert summary.errors == []


def test_service_clean_with_quarantine_is_restorable(tmp_path, state):
    paths = _files(tmp_path, 1)
    summary = service.clean(
        _items(paths), Config(), dry_run=False, use_quarantine=True
    )
    assert not paths[0].exists()
    assert summary.quarantine_run
    quarantine.restore(summary.quarantine_run)
    assert paths[0].exists()


def test_service_scan_raises_cancelled(monkeypatch):
    monkeypatch.setattr(service, "build_cleaners", lambda *a, **k: [FakeCleaner(0)])
    with pytest.raises(service.Cancelled):
        service.scan(Config(), cancel=lambda: True)


def test_service_scan_applies_protected_globs(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "build_cleaners", lambda *a, **k: [])
    target = tmp_path / "keep" / "file.bin"
    target.parent.mkdir()
    target.write_bytes(b"x")
    assert safety.is_safe_to_delete(str(target))
    cfg = Config()
    cfg.protected_globs = [str(tmp_path / "keep" / "*")]
    service.scan(cfg)
    assert not safety.is_safe_to_delete(str(target))


def test_service_clean_nothing_processed_records_no_history(tmp_path, state):
    summary = service.clean([], Config(), dry_run=False, use_quarantine=False)
    assert summary.manifest_path is None
    assert history.stats()["runs"] == 0
    paths = _files(tmp_path)
    summary = service.clean(
        _items(paths), Config(), dry_run=False, use_quarantine=False,
        cancel=lambda: True,
    )
    assert all(p.exists() for p in paths)
    assert history.stats()["runs"] == 0
    assert summary.cancelled is True


def test_service_clean_cancelled_between_items(tmp_path, state):
    paths = _files(tmp_path)
    seen = {"n": 0}

    def progress(_d, _done, _total):
        seen["n"] += 1

    summary = service.clean(
        _items(paths), Config(), dry_run=False, use_quarantine=False,
        progress=progress, cancel=lambda: seen["n"] >= 1,
    )
    assert summary.cancelled is True
    assert summary.removed == 1
    assert history.stats()["runs"] == 1
    ok = service.clean([], Config(), dry_run=True)
    assert ok.cancelled is False
