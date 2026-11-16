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
from cleanix.core.models import CleanableItem, CleanOutcome, CleanResult, ScanResult
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


def scan(
    config: Config,
    *,
    only: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
    progress: Optional[Callable[[str, int, int], None]] = None,
    cancel: CancelCB = None,
) -> ScanResult:
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
) -> CleanSummary:
    """``record_history=False`` skips history, the manifest and saving a
    quarantine index (the elevated helper must write nothing under the
    user's home; the GUI records history itself)."""
    safety.set_protected_globs(config.protected_globs)
    items = list(items)
    total = len(items)
    done = [0]

    def on_progress(description: str) -> None:
        done[0] += 1
        if progress:
            progress(description, done[0], total)

    quarantine = None
    if use_quarantine and not dry_run:
        from cleanix.core import quarantine as qmod

        quarantine = qmod.new_run()

    result = Engine([]).clean(
        items, dry_run=dry_run, quarantine=quarantine,
        progress=on_progress, cancel=cancel,
    )

    manifest: Optional[str] = None
    run_id: Optional[str] = None
    if not dry_run and record_history:
        history.record(result.freed, result.removed_count,
                       mode="quarantine" if quarantine else "delete")
        manifest = history.write_manifest(result) or None
        if quarantine is not None and quarantine.items:
            quarantine.save()
            run_id = quarantine.run_id

    return CleanSummary(
        result=result,
        quarantine_run=run_id,
        manifest_path=manifest,
        freed=result.freed,
        removed=result.removed_count,
        errors=result.errors,
    )
