"""Service layer: the engine's scan/clean flow as plain functions.

Used by the GUI (in-process) so it shares the CLI's safety, history and
quarantine behaviour instead of re-implementing it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, List, Mapping, Optional, Sequence

from cleanix.config import Config
from cleanix.core import history, safety
from cleanix.core.engine import DeleteCB, Engine, PrecheckCB
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
    # Set when the quarantine run's final manifest save failed after items
    # were removed; ``quarantine_run`` is still set and the text says where
    # the backup files are.
    undo_record_error: Optional[str] = None


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


def act(
    items: Sequence[CleanableItem],
    config: Config,
    *,
    dry_run: bool = True,
    permanent: bool = False,
    progress: Optional[Callable[[str, int, int], None]] = None,
    cancel: CancelCB = None,
    record_history: bool = True,
) -> CleanSummary:
    """Act on report-only findings; see :func:`cleanix.core.actions.act`.

    Each finding is re-verified, then removed through :func:`clean` (same
    guard, quarantine, history and Undo). ``permanent`` deletes instead of
    quarantining."""
    from cleanix.core import actions  # actions imports this module

    return actions.act(
        items, config, dry_run=dry_run, permanent=permanent, progress=progress,
        cancel=cancel, record_history=record_history,
    )


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
    registry_backup_run: Optional[str] = None,
    registry_backup_dir: Optional[Path] = None,
    registry_backup_root: Optional[Path] = None,
    registry_verified_backups: Optional[Mapping[str, Any]] = None,
    precheck: PrecheckCB = None,
    delete_instead: DeleteCB = None,
    quarantine_root: Optional[Path] = None,
    on_outcome: Optional[Callable[[CleanOutcome], None]] = None,
    remove_path: Optional[Callable[[str], tuple]] = None,
    on_quarantine_claim: Optional[Callable[[str], None]] = None,
) -> CleanSummary:
    """Clean ``items``. ``cancel`` must be thread-safe: it may be called from
    worker threads.

    ``quarantine_root`` (the elevated helper only): the quarantine run is
    created under this already-validated, root-owned directory instead of
    the user's quarantine root. Only then may ``record_history=False`` be
    combined with a quarantine: the run's own manifest (in that directory)
    is the restore index, and nothing is written under the user's home.
    Registry items are refused in that mode. ``on_quarantine_claim(run_id)``
    (only with ``quarantine_root``) is called once that run's directory
    exists. ``on_outcome`` and ``remove_path`` are passed to
    :meth:`Engine.clean` (default None changes nothing).

    ``record_history=False`` skips history and the manifest (the elevated
    helper must write nothing under the user's home; the GUI records history
    itself). It cannot be combined with a real quarantine run, which would
    move files without saving the index needed to restore them.

    REGISTRY items are always backed up first (ruling R5): a real clean with
    registry items creates a quarantine run for their backups even when
    ``use_quarantine`` is False (files are then still deleted, not moved).
    ``registry_backup_elsewhere=True`` (the elevated helper only) means the
    backup was already written by the GUI as the user into the quarantine run
    ``registry_backup_run`` (a run id of the invoking account's quarantine;
    ``registry_backup_root`` is the quarantine root that run lives in --
    the elevated helper passes the INVOKING user's validated root, never
    its own %LOCALAPPDATA%; default ``quarantine_root()``;
    ``registry_verified_backups`` (with ``registry_backup_run``) maps item
    keys to ``regclean.VerifiedBackup`` objects the caller already read and
    verified, and then the sink performs no filesystem access at all;
    ``registry_backup_dir`` is a deprecated alias accepted only when it is
    exactly such a run directory). No run is created and
    :class:`regclean.VerifyOnlySink` deletes only HKLM entries that run would
    restore (every other registry item fails with "backup is required for
    this entry"). Without it, a real registry clean needs
    ``record_history=True`` because the run must be saved.

    Once items were removed, a failing final manifest save is not raised:
    ``quarantine_run`` is still returned and ``undo_record_error`` says
    where the backup files are.

    ``precheck`` is passed to :meth:`Engine.clean` (re-verify each path right
    before it is removed; default None changes nothing). ``delete_instead``
    is passed on too (PATH items deleted, not moved, in a quarantine run).
    """
    from cleanix.core import regclean

    items = list(items)
    has_registry = any(i.kind is ItemKind.REGISTRY for i in items)
    if quarantine_root is not None and has_registry:
        raise ValueError("registry entries are never cleaned into an explicit quarantine root")
    if not record_history and use_quarantine and not dry_run and quarantine_root is None:
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

        run = (qmod.new_run() if quarantine_root is None
               else qmod.new_run(root=quarantine_root, on_claim=on_quarantine_claim))
    quarantine = run if use_quarantine else None
    registry_backup = None
    if not dry_run:
        if registry_backup_elsewhere:
            if registry_backup_run is not None:
                bound = registry_backup_run
            elif registry_backup_dir is not None:  # deprecated alias
                bound = Path(registry_backup_dir)
            else:
                bound = None
            if registry_verified_backups is not None and registry_backup_run is not None:
                # Preloaded mode (elevated helper): no filesystem access.
                registry_backup = regclean.VerifyOnlySink.from_preloaded(
                    registry_backup_run, registry_verified_backups)
            else:
                registry_backup = regclean.VerifyOnlySink(bound, root=registry_backup_root)
        else:
            registry_backup = run

    result = Engine([]).clean(
        items, dry_run=dry_run, quarantine=quarantine,
        progress=on_progress, cancel=cancel, registry_backup=registry_backup,
        precheck=precheck, delete_instead=delete_instead,
        **{k: v for k, v in (("on_outcome", on_outcome), ("remove_path", remove_path))
           if v is not None},
    )

    manifest: Optional[str] = None
    run_id: Optional[str] = None
    if not dry_run and record_history and result.outcomes:
        history.record(
            result.freed, result.removed_count,
            mode="quarantine" if quarantine else "delete",
            registry=sum(1 for o in result.outcomes
                         if o.removed and o.item.kind is ItemKind.REGISTRY),
        )
        manifest = history.write_manifest(result) or None
    undo_error: Optional[str] = None
    if run is not None and run.items:
        run_id = run.run_id
        try:
            run.save()
        except OSError as exc:  # incl. ManifestConflict
            # Items are already removed: never lose the summary over this.
            from cleanix.core import regpromises

            word = "undo" if regpromises.registry_undo_shipped() else "backup"
            undo_error = (
                f"the {word} record could not be saved ({str(exc) or type(exc).__name__}); "
                + regpromises.backup_files_note(run.dir)
            )
    elif run is not None:
        run.discard_if_empty()

    return CleanSummary(
        result=result,
        quarantine_run=run_id,
        manifest_path=manifest,
        freed=result.freed,
        removed=result.removed_count,
        errors=result.errors,
        cancelled=bool(cancel is not None and cancel()),
        undo_record_error=undo_error,
    )
