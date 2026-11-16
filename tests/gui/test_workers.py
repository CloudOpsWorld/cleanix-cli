import threading

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import QThread  # noqa: E402

from cleanix.core import service  # noqa: E402
from cleanix.gui import workers  # noqa: E402


class Recorder:
    def __init__(self, worker):
        self.events = []
        worker.progress.connect(lambda n, d, t: self.events.append(("progress", n, d, t)))
        worker.finished.connect(lambda r: self.events.append(("finished", r)))
        worker.cancelled.connect(lambda: self.events.append(("cancelled",)))
        worker.failed.connect(lambda m: self.events.append(("failed", m)))

    def terminal(self):
        return [e[0] for e in self.events if e[0] != "progress"]


def _finished(thread):
    # The thread deletes itself (deleteLater) once finished; a deleted C++
    # object therefore also means "finished".
    try:
        return thread.isFinished()
    except RuntimeError:
        return True


def _run(qtbot, worker):
    rec = Recorder(worker)
    done = threading.Event()
    for s in (worker.finished, worker.cancelled, worker.failed):
        s.connect(lambda *_: done.set())
    thread = workers.start_worker(worker)
    qtbot.waitUntil(done.is_set, timeout=5000)
    qtbot.waitUntil(lambda: _finished(thread), timeout=5000)
    return rec, thread


def test_scan_worker_emits_progress_then_finished(qtbot, monkeypatch):
    def fake_scan(config, only=None, exclude=None, progress=None, cancel=None):
        progress("a", 1, 2)
        progress("b", 2, 2)
        return "RESULT"

    monkeypatch.setattr(workers.service, "scan", fake_scan)
    rec, _ = _run(qtbot, workers.ScanWorker(object()))
    assert rec.events[0] == ("progress", "a", 1, 2)
    assert rec.events[1] == ("progress", "b", 2, 2)
    assert rec.events[-1] == ("finished", "RESULT")
    assert rec.terminal() == ["finished"]


def test_scan_worker_cancel_emits_cancelled_once(qtbot, monkeypatch):
    started = threading.Event()

    def fake_scan(config, only=None, exclude=None, progress=None, cancel=None):
        started.set()
        while not cancel():
            QThread.msleep(5)
        raise service.Cancelled()

    monkeypatch.setattr(workers.service, "scan", fake_scan)
    worker = workers.ScanWorker(object())
    rec = Recorder(worker)
    thread = workers.start_worker(worker)
    qtbot.waitUntil(started.is_set, timeout=5000)
    worker.cancel()
    qtbot.waitUntil(lambda: _finished(thread), timeout=5000)
    assert rec.terminal() == ["cancelled"]


def test_scan_worker_exception_emits_failed_with_message(qtbot, monkeypatch):
    def fake_scan(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(workers.service, "scan", fake_scan)
    rec, _ = _run(qtbot, workers.ScanWorker(object()))
    assert rec.terminal() == ["failed"]
    assert "boom" in rec.events[-1][1]


def test_clean_worker_finished_carries_summary(qtbot, monkeypatch):
    summary = object()
    seen = {}

    def fake_clean(items, config, dry_run=True, use_quarantine=True,
                   progress=None, cancel=None):
        seen.update(items=list(items), dry_run=dry_run, q=use_quarantine)
        progress("x", 1, 1)
        return summary

    monkeypatch.setattr(workers.service, "clean", fake_clean)
    worker = workers.CleanWorker(["i1"], object(), dry_run=True, use_quarantine=False)
    rec, _ = _run(qtbot, worker)
    assert rec.events[-1] == ("finished", summary)
    assert rec.terminal() == ["finished"]
    assert seen == {"items": ["i1"], "dry_run": True, "q": False}
    assert not worker.was_cancelled


def test_clean_worker_cancel_stops_before_next_item(qtbot, monkeypatch):
    first_done = threading.Event()
    proceed = threading.Event()
    processed = []

    def fake_clean(items, config, dry_run=True, use_quarantine=True,
                   progress=None, cancel=None):
        for item in items:
            if cancel():
                break
            processed.append(item)
            first_done.set()
            proceed.wait(5)
        return ("partial", list(processed))

    monkeypatch.setattr(workers.service, "clean", fake_clean)
    worker = workers.CleanWorker(["a", "b", "c"], object(), dry_run=False,
                                 use_quarantine=True)
    rec = Recorder(worker)
    thread = workers.start_worker(worker)
    qtbot.waitUntil(first_done.is_set, timeout=5000)
    worker.cancel()
    proceed.set()
    qtbot.waitUntil(lambda: _finished(thread), timeout=5000)
    assert processed == ["a"]
    # partial summary is preserved; the UI checks was_cancelled
    assert rec.terminal() == ["finished"]
    assert rec.events[-1][1] == ("partial", ["a"])
    assert worker.was_cancelled


def test_work_runs_off_the_gui_thread(qtbot, monkeypatch):
    seen = []

    def fake_scan(*a, **k):
        seen.append(QThread.currentThread())
        return None

    monkeypatch.setattr(workers.service, "scan", fake_scan)
    _run(qtbot, workers.ScanWorker(object()))
    assert seen and seen[0] is not QThread.currentThread()


def test_thread_is_cleaned_up_after_finish(qtbot, monkeypatch):
    monkeypatch.setattr(workers.service, "scan", lambda *a, **k: None)
    worker = workers.ScanWorker(object())
    thread = workers.start_worker(worker)
    qtbot.waitUntil(lambda: _finished(thread), timeout=5000)
    qtbot.waitUntil(lambda: thread not in workers._active, timeout=5000)
