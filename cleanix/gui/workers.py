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

from PySide6.QtCore import QObject, QThread, Signal, Slot

from cleanix.config import Config
from cleanix.core import service
from cleanix.core.models import CleanableItem, ItemKind

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


class ElevatedCleanWorker(_BaseWorker):
    """Clean with a single administrator prompt for ``requires_root`` items.

    Real clean: the user items are cleaned in-process first (``service.clean``,
    with the user's quarantine choice and normal history); then, unless a
    cancel was requested, the administrator items go to the elevated helper
    (``elevation.run_elevated_part``, one prompt, permanent removal) and one
    history entry is recorded for what it removed. A dry run never elevates:
    the user items are dry-run in-process and the administrator items are
    only previewed (``admin_preview_count``/``admin_preview_size``; included
    in ``freed``/``removed``), never reported as errors.

    Terminal signals: ``finished(CombinedSummary)`` (also when the
    administrator part is declined/unavailable/failed: the user part is never
    lost), ``cancelled`` / ``failed`` only if the user part itself did so.
    The prompt and the helper cannot be interrupted once launched;
    ``cancel_all_and_wait`` may time out while they run.
    """

    def __init__(self, items: Sequence[CleanableItem], config: Config, *,
                 dry_run: bool, use_quarantine: bool, launcher=None) -> None:
        super().__init__()
        self._items = list(items)
        self._config = config
        self._dry_run = dry_run
        self._use_quarantine = use_quarantine
        self._launcher = launcher

    @Slot()
    def run(self) -> None:
        self._guarded()

    def _run(self) -> None:
        from cleanix.core.models import CleanResult
        from cleanix.gui import elevation

        user_items, admin_items = elevation.split_items(self._items)
        if self._dry_run:
            self._run_dry(user_items, admin_items)
            return
        try:
            if user_items:
                user = service.clean(
                    user_items, self._config, dry_run=self._dry_run,
                    use_quarantine=self._use_quarantine,
                    progress=self._on_progress, cancel=self._cancel.is_set,
                )
            else:
                user = service.CleanSummary(result=CleanResult(dry_run=False),
                                            cancelled=self._cancel.is_set())
        except service.Cancelled:
            self._emit(self.cancelled)
            return
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self._emit(self.failed, str(exc) or exc.__class__.__name__)
            return

        admin = None
        late_cancel = False
        stopped = bool(getattr(user, "cancelled", False)) or self._cancel.is_set()
        if admin_items and not stopped:
            # Views disable Cancel on this exact text: once launched, the
            # prompt/helper cannot be stopped from here.
            self.progress.emit(elevation.ADMIN_WAIT_MESSAGE, 0, 0)
            admin = elevation.run_elevated_part(
                admin_items, self._config, use_quarantine=False, launcher=self._launcher,
                cancel=self._cancel.is_set)
            elevation.record_admin_history(admin)
            late_cancel = bool(
                admin is not None and admin.launched and self._cancel.is_set()
                and admin.status not in (elevation.DECLINED, elevation.UNAVAILABLE))
        res = admin.result if admin is not None else None
        combined = elevation.CombinedSummary(
            result=user.result,
            quarantine_run=user.quarantine_run,
            manifest_path=user.manifest_path,
            freed=user.freed + (res.freed if res else 0),
            removed=user.removed + (res.removed if res else 0),
            errors=list(user.errors),
            cancelled=bool(getattr(user, "cancelled", False))
            or bool(admin_items and admin is None),
            admin=admin,
            admin_selected=len(admin_items),
            user_freed=user.freed,
            user_removed=user.removed,
            late_cancel=late_cancel,
        )
        self._emit(self.finished, combined)

    def _run_dry(self, user_items, admin_items) -> None:
        """Dry run: the user items are dry-run in-process; the administrator
        items are only previewed (no prompt, no helper, no errors: the
        in-process engine cannot judge what the helper may remove)."""
        from cleanix.gui import elevation

        try:
            # Called even with no user items so the result says dry_run.
            user = service.clean(
                user_items, self._config, dry_run=True,
                use_quarantine=self._use_quarantine,
                progress=self._on_progress, cancel=self._cancel.is_set,
            )
        except service.Cancelled:
            self._emit(self.cancelled)
            return
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self._emit(self.failed, str(exc) or exc.__class__.__name__)
            return
        preview_size = sum(int(i.size or 0) for i in admin_items)
        combined = elevation.CombinedSummary(
            result=user.result,
            quarantine_run=user.quarantine_run,
            manifest_path=user.manifest_path,
            freed=user.freed + preview_size,
            removed=user.removed + len(admin_items),
            errors=list(user.errors),
            cancelled=bool(getattr(user, "cancelled", False)),
            admin=None,
            admin_selected=0,
            user_freed=user.freed,
            user_removed=user.removed,
            admin_preview_count=len(admin_items),
            admin_preview_size=preview_size,
            admin_preview_registry=sum(1 for i in admin_items
                                       if i.kind is ItemKind.REGISTRY),
        )
        self._emit(self.finished, combined)


class FindingsPlanWorker(_BaseWorker):
    """Plan a Review act without changing anything
    (:func:`findings_act.build_plan`: duplicate planning, a dry run of the
    user-space items, the system-wide plan). ``finished(ActPlan)``;
    ``cancelled`` when stopped; ``failed`` on an error."""

    def __init__(self, user_items, system_items, survivors, permanent: bool,
                 config: Config) -> None:
        super().__init__()
        self._user = list(user_items)
        self._system = list(system_items)
        self._survivors = dict(survivors or {})
        self._permanent = bool(permanent)
        self._config = config

    @Slot()
    def run(self) -> None:
        self._guarded()

    def _run(self) -> None:
        from cleanix.gui import findings_act

        self.progress.emit("Checking the selected items...", 0, 0)
        try:
            plan = findings_act.build_plan(
                self._user, self._system, self._survivors, self._permanent,
                self._config, cancel=self._cancel.is_set)
        except service.Cancelled:
            self._emit(self.cancelled)
            return
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self._emit(self.failed, str(exc) or exc.__class__.__name__)
            return
        if plan.cancelled or self._cancel.is_set():
            self._emit(self.cancelled)
        else:
            self._emit(self.finished, plan)


class FindingsActWorker(_BaseWorker):
    """Act on a confirmed Review plan (:func:`findings_act.run_act`): the
    user-space items in-process first, then the system-wide batch through
    the elevated helper (one prompt). A cancel before the administrator
    step leaves the system-wide items alone; once the prompt is shown it
    cannot be stopped (``findings_act.ADMIN_WAIT`` is emitted first, and
    views disable Cancel on it). Always ``finished(ActOutcome)`` (the user
    part is never lost) unless ``run_act`` itself raised."""

    def __init__(self, plan, config: Config, *, launcher=None) -> None:
        super().__init__()
        self._plan = plan
        self._config = config
        self._launcher = launcher

    @Slot()
    def run(self) -> None:
        self._guarded()

    def _admin_wait(self) -> None:
        from cleanix.gui import findings_act

        self.progress.emit(findings_act.ADMIN_WAIT, 0, 0)

    def _run(self) -> None:
        from cleanix.gui import findings_act

        try:
            outcome = findings_act.run_act(
                self._plan, self._config, launcher=self._launcher,
                cancel=self._cancel.is_set, progress=self._on_progress,
                admin_wait=self._admin_wait)
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self._emit(self.failed, str(exc) or exc.__class__.__name__)
            return
        self._emit(self.finished, outcome)


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


def active_count() -> int:
    """Number of started workers whose thread has not finished yet.

    Call on the GUI thread (entries are released by ``thread.finished``).
    """
    return len(_active)


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
