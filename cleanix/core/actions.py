"""Executor: act on report-only findings (PATH remedies and duplicates).

A finding is re-verified here, at act time, and only then turned into an
ordinary deletable item that goes through :func:`service.clean` -- so the
deletion guard, quarantine, history and Undo are exactly those of a normal
clean. :class:`~cleanix.core.engine.Engine` keeps refusing report-only items;
nothing here deletes by any other path.

Every check fails closed: an item that cannot be proven to be the entry seen
at scan time is skipped with a reason, never deleted.
"""

from __future__ import annotations

import dataclasses
from typing import Callable, List, Optional, Sequence, Set, Tuple

from cleanix.config import Config
from cleanix.core import safety
from cleanix.core.findings import (  # re-exported: actions is the public home
    KEEP_POLICIES,
    ActPlan,
    check_survivor,
    path_key,
    plan_duplicates,
    survivor_of,
)
from cleanix.core.models import CleanableItem, CleanOutcome, CleanResult, ItemKind
from cleanix.core.remedy import CHANGED, RemedyKind, unchanged, verify_path
from cleanix.core.utils import path_size

__all__ = ["ActPlan", "KEEP_POLICIES", "act", "plan_duplicates"]

NOT_A_FINDING = "not a finding with a remedy (only findings are acted on here)"
NOT_HANDLED = "this kind of finding is not handled here"
NEEDS_ELEVATION = "needs an elevated run"
BLOCKED = "blocked by safety guard (protected path)"
NO_SURVIVOR = "duplicate copy without a chosen copy to keep; nothing removed"


def _activate(item: CleanableItem, size: int) -> CleanableItem:
    """The verified finding as an ordinary deletable PATH item.

    Only ever called after :func:`_verify` passed for ``item``."""
    return dataclasses.replace(item, report_only=False, remedy=None, size=size)


def _verify(item: CleanableItem, batch: Set[str]) -> Optional[str]:
    """Why ``item`` must be skipped, or None when it may be acted on now.

    ``batch`` holds the path keys of every supplied item (a duplicate's
    kept copy must not be among them)."""
    remedy = item.remedy
    if not item.report_only or remedy is None:
        return NOT_A_FINDING
    if item.kind is not ItemKind.PATH or remedy.kind is not RemedyKind.PATH or not item.path:
        return NOT_HANDLED
    if item.requires_root:
        return NEEDS_ELEVATION
    grouped = bool(remedy.group)
    why = verify_path(item.path, remedy.fingerprint, allow_dir=not grouped)
    if why is not None:
        return why
    if not unchanged(item):
        return CHANGED
    try:
        safe = safety.is_safe_to_delete(item.path)
    except Exception:  # noqa: BLE001 - an undecidable guard is a refusal
        safe = False
    if not safe:
        return BLOCKED
    if grouped:
        kept = survivor_of(item)
        if kept is None:
            return NO_SURVIVOR
        kept_path, kept_fp = kept
        if path_key(kept_path) in batch:
            return ("the copy to keep is also selected for removal; "
                    "nothing removed")
        why = check_survivor(kept_path, kept_fp)
        if why is not None:
            return f"the copy to keep ({kept_path}) {why}; nothing removed"
    return None


def _size(path: str) -> int:
    try:
        return int(path_size(path))
    except (OSError, ValueError):
        return 0


def act(
    items: Sequence[CleanableItem],
    config: Config,
    *,
    dry_run: bool = True,
    permanent: bool = False,
    progress: Optional[Callable[[str, int, int], None]] = None,
    cancel: Optional[Callable[[], bool]] = None,
    record_history: bool = True,
):
    """Act on findings: quarantine (or, with ``permanent``, delete) each
    verified PATH finding through :func:`service.clean`.

    Returns a ``service.CleanSummary``. Skipped items appear as outcomes with
    ``removed=False`` and an ``error`` starting with "skipped: "; every
    outcome carries the caller's original (finding) item. Duplicate copies
    must come from :func:`plan_duplicates` (they name the copy to keep, which
    is re-checked here). ``requires_root`` findings are skipped ("needs an
    elevated run"). Dry run by default: then nothing is moved or written.
    """
    from cleanix.core import service

    items = list(items)
    if not record_history and not permanent and not dry_run:
        raise ValueError("record_history=False cannot be combined with quarantine")
    # The guard below must see the user's protected globs (service.clean
    # sets them again; same value).
    safety.set_protected_globs(config.protected_globs)

    batch = {path_key(i.path) for i in items if i.path}
    slots: List[Optional[CleanOutcome]] = [None] * len(items)
    todo: List[Tuple[int, CleanableItem]] = []
    seen: Set[str] = set()
    for idx, item in enumerate(items):
        key = path_key(item.path) if item.path else None
        if key is not None and key in seen:
            reason: Optional[str] = "listed twice"
        else:
            try:
                reason = _verify(item, batch)
            except Exception as exc:  # noqa: BLE001 - fail closed, never abort the batch
                reason = f"could not be verified ({str(exc) or type(exc).__name__})"
        if key is not None:
            seen.add(key)
        if reason is not None:
            slots[idx] = CleanOutcome(item=item, removed=False, dry_run=dry_run,
                                      error=f"skipped: {reason}")
        else:
            todo.append((idx, _activate(item, _size(item.path or ""))))

    inner = None
    if todo:
        inner = service.clean(
            [a for _i, a in todo], config, dry_run=dry_run,
            use_quarantine=not permanent, progress=progress, cancel=cancel,
            record_history=record_history,
        )
        # Engine yields one outcome per processed item, in order; a cancel
        # leaves the rest unprocessed (no outcome), as in a normal clean.
        for (idx, _a), outcome in zip(todo, inner.result.outcomes):
            slots[idx] = dataclasses.replace(outcome, item=items[idx])

    result = CleanResult(dry_run=dry_run,
                         outcomes=[o for o in slots if o is not None])
    return service.CleanSummary(
        result=result,
        quarantine_run=inner.quarantine_run if inner else None,
        manifest_path=inner.manifest_path if inner else None,
        freed=result.freed,
        removed=result.removed_count,
        errors=result.errors,
        cancelled=bool(inner.cancelled if inner else (cancel is not None and cancel())),
        undo_record_error=inner.undo_record_error if inner else None,
    )
