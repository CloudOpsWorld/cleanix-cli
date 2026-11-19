"""Service layer: the engine's scan/clean flow as plain functions.

Used by the GUI (in-process) so it shares the CLI's safety, history and
quarantine behaviour instead of re-implementing it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence

from cleanix.config import Config
from cleanix.core import history, safety
from cleanix.core.engine import Engine
from cleanix.core.models import (
    CleanableItem,
    CleanOutcome,
    CleanResult,
    ItemKind,
    ScanResult,
)
from cleanix.core.registry import build_cleaners

CancelCB = Optional[Callable[[], bool]]


class Cancelled(Exception):
    """Raised when an operation was cancelled by the caller."""


@dataclass
class CleanSummary:
    result: CleanResult
    quarantine_run: Optional[str] = None
    manifest_path: Optional[str] = None
    freed: int = 0
    removed: int = 0
    errors: List[CleanOutcome] = field(default_factory=list)
    cancelled: bool = False


def scan(
    config: Config,
    *,
    only: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
    progress: Optional[Callable[[str, int, int], None]] = None,
    cancel: CancelCB = None,
) -> ScanResult:
    """Scan the selected cleaners. ``cancel`` must be thread-safe: the parallel
    engine path calls it from worker threads."""
    safety.set_protected_globs(config.protected_globs)
    cleaners = build_cleaners(config, only=only, exclude=exclude)
    total = len(cleaners)
    done = [0]

    def on_progress(name: str) -> None:
        done[0] += 1
        if progress:
            progress(name, done[0], total)

    result = Engine(cleaners).scan(progress=on_progress, cancel=cancel)
    if cancel is not None and cancel():
        raise Cancelled()
    return result


def clean(
    items: Sequence[CleanableItem],
    config: Config,
    *,
    dry_run: bool = True,
    use_quarantine: bool = True,
    progress: Optional[Callable[[str, int, int], None]] = None,
    cancel: CancelCB = None,
    record_history: bool = True,
    registry_backup_elsewhere: bool = False,
) -> CleanSummary:
    """Clean ``items``. ``cancel`` must be thread-safe: it may be called from
    worker threads.

    ``record_history=False`` skips history and the manifest (the elevated
    helper must write nothing under the user's home; the GUI records history
    itself). It cannot be combined with a real quarantine run, which would
    move files without saving the index needed to restore them.

    REGISTRY items are always backed up first (ruling R5): a real clean with
    registry items creates a quarantine run for their backups even when
    ``use_quarantine`` is False (files are then still deleted, not moved).
    ``registry_backup_elsewhere=True`` (the elevated helper only) means the
    backup was already written by the GUI as the user; no run is created
    and :class:`regclean.VerifyOnlySink` is used. Without it, a real registry
    clean needs ``record_history=True`` because the run must be saved.
    """
    from cleanix.core import regclean

    items = list(items)
    has_registry = any(i.kind is ItemKind.REGISTRY for i in items)
    if not record_history and use_quarantine and not dry_run:
        raise ValueError("record_history=False cannot be combined with quarantine")
    if not record_history and has_registry and not dry_run and not registry_backup_elsewhere:
        raise ValueError(
            "record_history=False cannot back up registry entries; "
            "registry entries are removed only with a backup"
        )
    safety.set_protected_globs(config.protected_globs)
    total = len(items)
    done = [0]

    def on_progress(description: str) -> None:
        done[0] += 1
        if progress:
            progress(description, done[0], total)

    run = None
    needs_reg_run = has_registry and not registry_backup_elsewhere
    if not dry_run and (use_quarantine or needs_reg_run):
        from cleanix.core import quarantine as qmod

        run = qmod.new_run()
    quarantine = run if use_quarantine else None
    registry_backup = None
    if not dry_run:
        registry_backup = regclean.VerifyOnlySink() if registry_backup_elsewhere else run

    result = Engine([]).clean(
        items, dry_run=dry_run, quarantine=quarantine,
        progress=on_progress, cancel=cancel, registry_backup=registry_backup,
    )

    manifest: Optional[str] = None
    run_id: Optional[str] = None
    if not dry_run and record_history and result.outcomes:
        history.record(result.freed, result.removed_count,
                       mode="quarantine" if quarantine else "delete")
        manifest = history.write_manifest(result) or None
    if run is not None and run.items:
        run.save()
        run_id = run.run_id

    return CleanSummary(
        result=result,
        quarantine_run=run_id,
        manifest_path=manifest,
        freed=result.freed,
        removed=result.removed_count,
        errors=result.errors,
        cancelled=bool(cancel is not None and cancel()),
    )
