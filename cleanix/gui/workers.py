"""Worker objects that run scan/clean off the GUI thread.

Each worker emits exactly one terminal signal. ``ScanWorker`` emits
``finished`` / ``cancelled`` / ``failed``. ``CleanWorker`` emits ``finished``
(with the possibly partial ``CleanSummary``, so nothing the engine already
removed is lost; check ``was_cancelled``) or ``failed``.
"""

from __future__ import annotations

import threading
from typing import Optional, Sequence

from PySide6.QtCore import QObject, QThread, Signal, Slot

from cleanix.config import Config
from cleanix.core import service
from cleanix.core.models import CleanableItem

_active: set = set()


class _BaseWorker(QObject):
    progress = Signal(str, int, int)
    finished = Signal(object)
    cancelled = Signal()
    failed = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self._cancel = threading.Event()

    def cancel(self) -> None:
        """Thread-safe: may be called from the GUI thread while run() executes."""
        self._cancel.set()

    @property
    def was_cancelled(self) -> bool:
        return self._cancel.is_set()

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
        try:
            result = service.scan(
                self._config, only=self._only, exclude=self._exclude,
                progress=self._on_progress, cancel=self._cancel.is_set,
            )
        except service.Cancelled:
            self.cancelled.emit()
            return
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self.failed.emit(str(exc) or exc.__class__.__name__)
            return
        if self._cancel.is_set():
            self.cancelled.emit()
        else:
            self.finished.emit(result)


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
        try:
            summary = service.clean(
                self._items, self._config, dry_run=self._dry_run,
                use_quarantine=self._use_quarantine,
                progress=self._on_progress, cancel=self._cancel.is_set,
            )
        except service.Cancelled:
            self.cancelled.emit()
            return
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self.failed.emit(str(exc) or exc.__class__.__name__)
            return
        # service.clean returns a partial summary on cancel; never drop it.
        self.finished.emit(summary)


def start_worker(worker: QObject) -> QThread:
    """Move ``worker`` to a new thread, start it, and clean up afterwards."""
    thread = QThread()
    worker.moveToThread(thread)
    thread.started.connect(worker.run)  # type: ignore[attr-defined]
    for name in ("finished", "cancelled", "failed"):
        getattr(worker, name).connect(thread.quit)
    _active.add(thread)

    def _release() -> None:
        _active.discard(thread)
        worker.deleteLater()
        thread.deleteLater()

    thread.finished.connect(_release)
    thread.start()
    return thread
