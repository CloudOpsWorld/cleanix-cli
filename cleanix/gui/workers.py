"""Worker objects that run scan/clean off the GUI thread.

Each worker emits exactly one terminal signal. ``ScanWorker`` emits
``finished`` / ``cancelled`` / ``failed``. ``CleanWorker`` emits ``finished``
(with the possibly partial ``CleanSummary``, so nothing the engine already
removed is lost) or ``failed``. ``CleanSummary.cancelled`` says whether the
engine actually stopped early; ``worker.was_cancelled`` only says that
``cancel()`` was requested.

Consumers must connect worker signals to bound slots of GUI-thread QObjects,
never to bare lambdas or plain functions: those run on the worker thread.
A terminal signal is always emitted, even for BaseException (``failed``).
"""

from __future__ import annotations

import threading
from typing import Optional, Sequence

import shiboken6
from PySide6.QtCore import QObject, QThread, Signal, Slot

from cleanix.config import Config
from cleanix.core import service
from cleanix.core.models import CleanableItem

_active: set = set()  # (thread, worker) pairs


class _BaseWorker(QObject):
    progress = Signal(str, int, int)
    finished = Signal(object)
    cancelled = Signal()
    failed = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self._cancel = threading.Event()
        self._terminal_emitted = False

    def cancel(self) -> None:
        """Thread-safe: may be called from the GUI thread while run() executes."""
        self._cancel.set()

    @property
    def was_cancelled(self) -> bool:
        return self._cancel.is_set()

    def _guarded(self) -> None:
        try:
            self._run()
        finally:
            if not self._terminal_emitted:
                self._emit(self.failed, "interrupted")

    def _emit(self, signal, *args) -> None:
        self._terminal_emitted = True
        signal.emit(*args)

    def _on_progress(self, name: str, done: int, total: int) -> None:
        self.progress.emit(name, done, total)


class ScanWorker(_BaseWorker):
    def __init__(self, config: Config, only: Optional[Sequence[str]] = None,
                 exclude: Optional[Sequence[str]] = None) -> None:
        super().__init__()
        self._config = config
        self._only = only
        self._exclude = exclude

    @Slot()
    def run(self) -> None:
        self._guarded()

    def _run(self) -> None:
        try:
            result = service.scan(
                self._config, only=self._only, exclude=self._exclude,
                progress=self._on_progress, cancel=self._cancel.is_set,
            )
        except service.Cancelled:
            self._emit(self.cancelled)
            return
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self._emit(self.failed, str(exc) or exc.__class__.__name__)
            return
        if self._cancel.is_set():
            self._emit(self.cancelled)
        else:
            self._emit(self.finished, result)


class CleanWorker(_BaseWorker):
    def __init__(self, items: Sequence[CleanableItem], config: Config, *,
                 dry_run: bool, use_quarantine: bool) -> None:
        super().__init__()
        self._items = list(items)
        self._config = config
        self._dry_run = dry_run
        self._use_quarantine = use_quarantine

    @Slot()
    def run(self) -> None:
        self._guarded()

    def _run(self) -> None:
        try:
            summary = service.clean(
                self._items, self._config, dry_run=self._dry_run,
                use_quarantine=self._use_quarantine,
                progress=self._on_progress, cancel=self._cancel.is_set,
            )
        except service.Cancelled:
            self._emit(self.cancelled)
            return
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self._emit(self.failed, str(exc) or exc.__class__.__name__)
            return
        # service.clean returns a partial summary on cancel; never drop it.
        self._emit(self.finished, summary)


def start_worker(worker: QObject) -> QThread:
    """Move ``worker`` to a new thread, start it, and clean up afterwards.

    Do not touch the returned QThread after the terminal signal: it deletes
    itself. React to the worker's signals instead.
    """
    thread = QThread()
    worker.moveToThread(thread)
    thread.started.connect(worker.run)  # type: ignore[attr-defined]
    for name in ("finished", "cancelled", "failed"):
        getattr(worker, name).connect(thread.quit)
    entry = (thread, worker)
    _active.add(entry)
    thread.finished.connect(worker.deleteLater)

    def _release() -> None:
        _active.discard(entry)
        thread.deleteLater()

    thread.finished.connect(_release)
    thread.start()
    return thread


def cancel_all_and_wait(timeout_ms: int = 5000) -> bool:
    """Cancel every running worker and wait for its thread; True if all stopped."""
    entries = list(_active)
    for thread, worker in entries:
        try:
            worker.cancel()  # type: ignore[attr-defined]
        except RuntimeError:
            pass
    ok = True
    for thread, _worker in entries:
        try:
            thread.quit()
            ok = thread.wait(timeout_ms) and ok
        except RuntimeError:  # already deleted: finished
            pass
    if ok:
        for entry in entries:
            _active.discard(entry)
    return ok
