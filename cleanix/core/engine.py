"""The engine: run scans and execute (or simulate) cleans.

All deletion goes through here so that the safety guard, dry-run behavior, and
root checks are enforced in one auditable place.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from cleanix.cleaners.base import Cleaner
from cleanix.core import regclean, regsafety, safety, winenv, winregistry
from cleanix.core.models import (
    CleanableItem,
    CleanerReport,
    CleanOutcome,
    CleanResult,
    ItemKind,
    ScanResult,
)
from cleanix.core import platform as plat
from cleanix.core.regclean import RegistryBackupSink
from cleanix.core.utils import is_root, path_size, run_command

ProgressCB = Optional[Callable[[str], None]]
CancelCB = Optional[Callable[[], bool]]


class Engine:
    def __init__(self, cleaners: Sequence[Cleaner]):
        self.cleaners = list(cleaners)

    # -- scanning ------------------------------------------------------------
    def scan(
        self,
        progress: ProgressCB = None,
        parallel: bool = True,
        cancel: CancelCB = None,
    ) -> ScanResult:
        """Scan all cleaners. Cleaners are I/O-bound (directory walks, external
        commands), so running them on a thread pool is a large speed-up.

        ``cancel`` (optional) is polled between cleaners; once it returns true
        no further cleaner is started and the partial result is returned.
        ``cancel`` must be thread-safe: the parallel path calls it from worker
        threads.
        """
        n = len(self.cleaners)
        if not parallel or n <= 1:
            reports: List[CleanerReport] = []
            for cleaner in self.cleaners:
                if cancel is not None and cancel():
                    break
                reports.append(cleaner.scan())
                if progress:
                    progress(cleaner.name)
            return ScanResult(reports=reports)

        from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

        results: List[Optional[CleanerReport]] = [None] * n
        workers = min(16, n)

        def run(idx: int) -> Optional[CleanerReport]:
            if cancel is not None and cancel():
                return None
            return self.cleaners[idx].scan()

        with ThreadPoolExecutor(max_workers=workers) as pool:
            pending = {}
            next_idx = 0
            while next_idx < n or pending:
                # Keep at most ``workers`` in flight so a cancel stops new work.
                while next_idx < n and len(pending) < workers:
                    if cancel is not None and cancel():
                        next_idx = n
                        break
                    pending[pool.submit(run, next_idx)] = next_idx
                    next_idx += 1
                if not pending:
                    break
                done, _ = wait(list(pending), return_when=FIRST_COMPLETED)
                for fut in done:
                    idx = pending.pop(fut)
                    report = fut.result()
                    if report is None:
                        continue
                    results[idx] = report
                    if progress:
                        progress(self.cleaners[idx].name)
        return ScanResult(reports=[r for r in results if r is not None])

    # -- cleaning ------------------------------------------------------------
    def clean(
        self,
        items: Sequence[CleanableItem],
        *,
        dry_run: bool = True,
        allow_root_items: Optional[bool] = None,
        progress: ProgressCB = None,
        quarantine=None,
        cancel: CancelCB = None,
        registry_backup: Optional[RegistryBackupSink] = None,
    ) -> CleanResult:
        """Remove (or simulate removing) the given items.

        Root-requiring items are skipped with an error unless the process is
        root (or ``allow_root_items`` is forced True). If ``quarantine`` is a
        Quarantine store, path items are *moved* there (reversible) instead of
        being deleted.

        REGISTRY items are removed only through ``registry_backup``, which
        writes and verifies a backup of each entry first (independent of
        ``quarantine``); without it they are refused. A dry run touches
        neither the registry nor the backup location.
        """
        if allow_root_items is None:
            allow_root_items = is_root()

        result = CleanResult(dry_run=dry_run)
        for item in items:
            if cancel is not None and cancel():
                break
            if progress:
                progress(item.description)
            result.outcomes.append(
                self._clean_one(
                    item, dry_run=dry_run, allow_root=allow_root_items,
                    quarantine=quarantine, registry_backup=registry_backup,
                )
            )
        return result

    def _clean_one(
        self, item: CleanableItem, *, dry_run: bool, allow_root: bool, quarantine=None,
        registry_backup: Optional[RegistryBackupSink] = None,
    ) -> CleanOutcome:
        # Report-only items are never deleted, even if one slips into a clean set.
        if item.report_only:
            return CleanOutcome(
                item=item, removed=False, freed=0, dry_run=dry_run,
                error="report only (remove manually)",
            )
        if item.requires_root and not allow_root:
            return CleanOutcome(
                item=item,
                removed=False,
                error=(
                    "requires root (run from an elevated (Administrator) terminal)"
                    if plat.is_windows()
                    else "requires root (re-run with sudo)"
                ),
                dry_run=dry_run,
            )

        if item.kind is ItemKind.PATH:
            return self._clean_path(item, dry_run=dry_run, quarantine=quarantine)
        if item.kind is ItemKind.COMMAND:
            return self._clean_command(item, dry_run=dry_run)
        if item.kind is ItemKind.REGISTRY:
            try:
                return self._clean_registry(item, dry_run=dry_run, sink=registry_backup)
            except Exception as exc:  # noqa: BLE001 - one item never aborts the rest
                return CleanOutcome(
                    item=item, removed=False, dry_run=dry_run,
                    error=f"registry entry not removed (state unknown, scan again): {exc}",
                )
        return CleanOutcome(
            item=item, removed=False, dry_run=dry_run, error="unknown item kind"
        )

    def _clean_path(
        self, item: CleanableItem, *, dry_run: bool, quarantine=None
    ) -> CleanOutcome:
        path = item.path or ""
        if not safety.is_safe_to_delete(path):
            return CleanOutcome(
                item=item,
                removed=False,
                error="blocked by safety guard (protected path)",
                dry_run=dry_run,
            )

        p = Path(path)
        freed = item.size or path_size(p)
        if dry_run:
            return CleanOutcome(item=item, removed=False, freed=freed, dry_run=True)

        # Reversible mode: move to quarantine instead of deleting.
        if quarantine is not None:
            try:
                if os.name == "nt":
                    # Act on exactly the (canonical) path the guard checked.
                    quarantine.store(safety.assert_safe_to_delete(path))
                else:
                    quarantine.store(p)
            except Exception as exc:  # noqa: BLE001
                return CleanOutcome(item=item, removed=False, error=f"quarantine: {exc}")
            return CleanOutcome(item=item, removed=True, freed=freed)

        try:
            safety.safe_rmtree(p)
        except safety.UnsafePathError as exc:
            return CleanOutcome(item=item, removed=False, error=str(exc))
        except OSError as exc:
            return CleanOutcome(item=item, removed=False, error=str(exc))
        return CleanOutcome(item=item, removed=True, freed=freed)

    def _clean_command(self, item: CleanableItem, *, dry_run: bool) -> CleanOutcome:
        if dry_run:
            return CleanOutcome(
                item=item, removed=False, freed=item.size, dry_run=True
            )
        if item.timeout is None:
            code, _out, err = run_command(list(item.command or []))
        else:
            code, _out, err = run_command(
                list(item.command or []), timeout=item.timeout
            )
        if code != 0:
            return CleanOutcome(
                item=item,
                removed=False,
                error=(err.strip() or f"exit code {code}"),
            )
        return CleanOutcome(item=item, removed=True, freed=item.size)

    def _clean_registry(
        self, item: CleanableItem, *, dry_run: bool, sink: Optional[RegistryBackupSink]
    ) -> CleanOutcome:
        """Back up, then delete one registry entry (see :mod:`regclean`).

        Order matters: the pure safety check, the dry run, the sink and the
        administrator check all come before any registry access."""
        reg = item.reg
        assert reg is not None  # guaranteed by CleanableItem.__post_init__

        def fail(error: str) -> CleanOutcome:
            return CleanOutcome(item=item, removed=False, dry_run=dry_run, error=error)

        reason = regsafety.check_target(item.cleaner_id, reg)
        if reason is not None:
            return fail(f"blocked by registry safety rules: {reason}")
        if dry_run:
            return CleanOutcome(item=item, removed=False, freed=0, dry_run=True)
        if sink is None:
            return fail("registry entries are removed only with a backup")
        if reg.hive == "HKLM" and not winenv.is_admin():
            return fail(
                "machine-wide (HKLM) registry entries are removed only from an "
                "elevated (Administrator) process; nothing was backed up or deleted"
            )

        backend = winregistry.get_backend()
        reason = regsafety.check_target(item.cleaner_id, reg, backend)
        if reason is not None:
            return fail(f"blocked by registry safety rules: {reason}")

        try:
            sink.before_delete(item, backend)
        except regclean.RegistryChanged:
            return fail(regclean.CHANGED)
        except Exception as exc:  # noqa: BLE001 - any failure vetoes the delete
            return fail(f"backup failed, nothing deleted: {exc or type(exc).__name__}")

        deleted = True
        error: Optional[str] = None
        try:
            regclean.delete_target(backend, item.cleaner_id, reg)
        except regclean.RegistryChanged:
            deleted, error = False, regclean.CHANGED
        except (regclean.RegistryBlocked, regclean.NotRemoved, winregistry.AccessDenied) as exc:
            deleted, error = False, str(exc) or type(exc).__name__
        except Exception as exc:  # noqa: BLE001 - PartialDelete or unknown state
            text = str(exc) or type(exc).__name__
            if not text.startswith("partially deleted"):
                text = f"partially deleted or state unknown: {text}; scan again"
            run = getattr(sink, "run_id", None)
            if run:
                text += (
                    f"; the backup is in quarantine run {run}"
                    f" (restore with cleanix restore {run})"
                )
            error = text
        try:
            sink.after_delete(item, deleted)
        except Exception:  # noqa: BLE001
            # The manifest already holds the entry with "deleted": None,
            # which restore treats as restorable; nothing is lost.
            pass
        if error is not None:
            return fail(error)
        return CleanOutcome(item=item, removed=True, freed=0)
