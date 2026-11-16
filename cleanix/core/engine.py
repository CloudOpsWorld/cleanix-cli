"""The engine: run scans and execute (or simulate) cleans.

All deletion goes through here so that the safety guard, dry-run behavior, and
root checks are enforced in one auditable place.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from cleanix.cleaners.base import Cleaner
from cleanix.core import safety
from cleanix.core.models import (
    CleanableItem,
    CleanerReport,
    CleanOutcome,
    CleanResult,
    ItemKind,
    ScanResult,
)
from cleanix.core import platform as plat
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
    ) -> CleanResult:
        """Remove (or simulate removing) the given items.

        Root-requiring items are skipped with an error unless the process is
        root (or ``allow_root_items`` is forced True). If ``quarantine`` is a
        Quarantine store, path items are *moved* there (reversible) instead of
        being deleted.
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
                    quarantine=quarantine,
                )
            )
        return result

    def _clean_one(
        self, item: CleanableItem, *, dry_run: bool, allow_root: bool, quarantine=None
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
        return self._clean_command(item, dry_run=dry_run)

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
