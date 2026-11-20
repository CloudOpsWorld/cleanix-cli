"""Executor: act on report-only findings (PATH remedies, duplicates, and
user-level launch jobs / systemd units -- see :mod:`remedy_exec`).

A finding is re-verified here, at act time, and only then turned into an
ordinary deletable item that goes through :func:`service.clean` -- so the
deletion guard, quarantine, history and Undo are exactly those of a normal
clean. :class:`~cleanix.core.engine.Engine` keeps refusing report-only items;
nothing here deletes by any other path.

Every check fails closed: an item that cannot be proven to be the entry seen
at scan time is skipped with a reason, never deleted. Each item is checked
twice: once for the whole batch up front, and again (``precheck``) by the
Engine right before that item's own move/delete, so a change made while
earlier items were being processed (a kept duplicate copy removed, a file
rewritten, a folder already taken by an earlier item) is caught. What
remains is the short window between that last lstat and the move/delete
itself: accepted residual risk (the guard and the link-safe removal in
``safety`` still apply inside it).
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from cleanix.config import Config
from cleanix.core import quarantine, safety, service
from cleanix.core.findings import (  # re-exported: actions is the public home
    DIFFERENT_OWNERS,
    KEEP_POLICIES,
    ActPlan,
    Survivor,
    check_survivor,
    content_matches_group,
    copy_vs_survivor,
    path_key,
    kept_context,
    owners_differ,
    plan_duplicates,
    plan_duplicates_keeping,
    survivor_of,
)
from cleanix.core import remedy_exec
from cleanix.core.models import CleanableItem, CleanOutcome, CleanResult, ItemKind
from cleanix.core.remedy import CHANGED, RemedyKind, link_target, unchanged, verify_path

__all__ = [
    "ActPlan", "ActSummary", "KEEP_POLICIES", "act", "holds_kept_copy",
    "kept_context", "plan_duplicates", "plan_duplicates_keeping",
]

NOT_A_FINDING = "not a finding with a remedy (only findings are acted on here)"
NOT_HANDLED = "this kind of finding is not handled here"
NEEDS_ELEVATION = "needs an elevated run"
BLOCKED = "blocked by safety guard (protected path)"
NO_SURVIVOR = "duplicate copy without a chosen copy to keep; nothing removed"
KEEPS_COPY = "it is, or contains, the copy kept of a duplicate group"
LISTED_TWICE = "listed twice"
STOPPED_AT_DEADLINE = ("the time limit was reached while it was being re-checked; "
                       "nothing was done")
NO_BACKUP_PLACE = ("no administrator location to keep a copy of the file; "
                   "nothing was done")


@dataclass
class ActSummary(service.CleanSummary):
    """A :class:`service.CleanSummary` plus the findings that were skipped.

    ``skipped`` holds (original finding, reason) for every item not acted on
    -- refused up front or by the re-check right before its removal -- in
    input order. Skipped items are NOT in ``result.outcomes`` or ``errors``;
    those hold only items that were processed (``errors`` = real failures).
    """

    skipped: List[Tuple[CleanableItem, str]] = field(default_factory=list)
    # The copy-only run holding the copies of removed launch-job/unit files
    # (manual recovery only; restore never acts on them, so this is not an
    # Undo and never ``quarantine_run``).
    backup_run: Optional[str] = None


_HANDLED = frozenset({RemedyKind.PATH}) | remedy_exec.KINDS


def _activate(item: CleanableItem) -> CleanableItem:
    """The verified finding as an ordinary deletable PATH item.

    Only ever called after :func:`_verify` passed for ``item``. Size 0 makes
    the Engine measure the real bytes at delete time (never item.size)."""
    return dataclasses.replace(item, report_only=False, remedy=None, size=0)


def _survivor_reason(item: CleanableItem, batch: Optional[Set[str]] = None) -> Optional[str]:
    """Why a duplicate copy must stay because of its kept copy (None if it may go)."""
    remedy = item.remedy
    assert remedy is not None
    kept = survivor_of(item)
    if kept is None:
        return NO_SURVIVOR
    if batch is not None and path_key(kept.path) in batch:
        return "the copy to keep is also selected for removal; nothing removed"
    why = copy_vs_survivor(remedy.fingerprint, remedy.group, kept)
    if why is not None:
        return why
    if owners_differ((item.path or "", kept.path)):
        return DIFFERENT_OWNERS
    why = check_survivor(kept.path, kept.fingerprint)
    if why is not None:
        return f"the copy to keep ({kept.path}) {why}; nothing removed"
    return None


def _recheck(item: CleanableItem, config: Config, root_mode: bool = False) -> Optional[str]:
    """The fingerprint/type (and, for a duplicate, kept-copy) checks; run up
    front and again right before the item's removal. Launch jobs and units
    get their own full re-verification: user-level ones by
    :func:`remedy_exec.check`, system-wide ones (root mode only) by
    :func:`system_remedy.check` -- never the other."""
    from cleanix.core import system_remedy

    remedy = item.remedy
    assert remedy is not None and item.path
    if root_mode:
        if remedy.kind in remedy_exec.SYSTEM_KINDS:
            return system_remedy.check(item, config)[0]
    elif remedy.kind in remedy_exec.KINDS:
        return remedy_exec.check(item, config)[0]
    if remedy.kind is not RemedyKind.PATH:
        return NOT_HANDLED
    grouped = bool(remedy.group)
    why = verify_path(item.path, remedy.fingerprint, allow_dir=not grouped,
                      link=link_target(remedy))
    if why is not None:
        return why
    if not unchanged(item):
        return CHANGED
    if grouped:
        return _survivor_reason(item)
    return None


def _verify(item: CleanableItem, batch: Set[str],
            hashed: Dict[Tuple[str, Tuple[int, ...]], Optional[str]],
            config: Config,
            cancel: Optional[Callable[[], bool]] = None,
            allow_root: bool = False,
            root_mode: bool = False,
            backup_root: Optional[Path] = None) -> Optional[str]:
    """Why ``item`` must be skipped, or None when it may be acted on now.

    ``batch`` holds the path keys of every supplied item (a duplicate's
    kept copy must not be among them); ``hashed`` caches the kept-copy
    content checks of this batch. ``allow_root`` lets ``requires_root``
    findings through (elevated helper only); ``root_mode`` (helper) handles
    plain PATH findings and -- with ``allow_root`` and a ``backup_root``
    for their copies -- system-wide launch jobs, units and package
    receipts (``requires_root`` only); never duplicates or user-level
    jobs/units."""
    remedy = item.remedy
    if not item.report_only or remedy is None:
        return NOT_A_FINDING
    if item.kind is not ItemKind.PATH or not item.path:
        return NOT_HANDLED
    if root_mode:
        if remedy.group:
            return NOT_HANDLED
        if remedy.kind in remedy_exec.SYSTEM_KINDS:
            if not (allow_root and item.requires_root):
                return NOT_HANDLED
            if backup_root is None:
                return NO_BACKUP_PLACE
        elif remedy.kind is not RemedyKind.PATH:
            return NOT_HANDLED
    elif remedy.kind not in _HANDLED:
        if remedy.kind in remedy_exec.SYSTEM_KINDS and item.requires_root:
            return NEEDS_ELEVATION
        return NOT_HANDLED
    if link_target(remedy) is not None and not root_mode:
        # Link remedies (broken system unit links) are only acted on by the
        # helper, whose re-verifier proves the link is still broken.
        return NOT_HANDLED
    if item.requires_root and not allow_root:
        return NEEDS_ELEVATION
    if remedy.group:
        if remedy.kind is not RemedyKind.PATH:
            return NOT_HANDLED
        why = _survivor_reason(item, batch)
        if why is not None:
            return why
    why = _recheck(item, config, root_mode)
    if why is not None:
        return why
    try:
        safe = safety.is_safe_to_delete(item.path)
    except Exception:  # noqa: BLE001 - an undecidable guard is a refusal
        safe = False
    if not safe:
        return BLOCKED
    if remedy.group:
        # The stamp is data a caller could forge: prove the kept copy really
        # holds the group's content (its SHA-256), once per kept copy.
        kept = survivor_of(item)
        assert kept is not None  # _survivor_reason passed
        cache_key = (path_key(kept.path), tuple(kept.fingerprint))
        if cache_key not in hashed:
            hashed[cache_key] = content_matches_group(
                kept.path, remedy.group, fingerprint=kept.fingerprint, cancel=cancel)
        why = hashed[cache_key]
        if why is not None:
            return why
    return None


def _spellings(path: str) -> Set[str]:
    """``path_key(path)`` plus, best effort, the spelling with its parent
    folders' links resolved (the final component is never followed)."""
    keys = {path_key(path)}
    try:
        parent, name = os.path.split(os.path.abspath(path))
        keys.add(os.path.normcase(os.path.join(os.path.realpath(parent), name)))
    except (OSError, ValueError):
        pass
    return keys


def _holds_kept_copy(item: CleanableItem, kept: Set[str],
                     kept_ids: Set[Tuple[int, ...]]) -> bool:
    """True when ``item`` is a kept duplicate copy (by any spelling, or by
    inode/device, e.g. another case on a case-insensitive volume) or a
    folder containing one."""
    remedy = item.remedy
    if remedy is not None:
        try:
            if tuple(int(x) for x in remedy.fingerprint)[2:] in kept_ids:
                return True
        except (TypeError, ValueError):
            pass
    for key in _spellings(item.path or ""):
        prefix = key if key.endswith(os.sep) else key + os.sep
        if any(k == key or k.startswith(prefix) for k in kept):
            return True
    return False


def holds_kept_copy(item: CleanableItem, protect: Iterable[Survivor]) -> bool:
    """True when ``item`` is, or contains, one of the kept copies in
    ``protect`` (same test as :func:`act` applies; see ``protect``)."""
    kept: Set[str] = set()
    kept_ids: Set[Tuple[int, ...]] = set()
    for stamp in protect:
        kept |= _spellings(stamp.path)
        kept_ids.add(tuple(stamp.fingerprint)[2:])
    return bool(item.path) and _holds_kept_copy(item, kept, kept_ids)


def act(
    items: Sequence[CleanableItem],
    config: Config,
    *,
    dry_run: bool = True,
    permanent: bool = False,
    progress: Optional[Callable[[str, int, int], None]] = None,
    cancel: Optional[Callable[[], bool]] = None,
    record_history: bool = True,
    allow_root: bool = False,
    quarantine_root: Optional[Path] = None,
    extra_check: Optional[Callable[[CleanableItem], Optional[str]]] = None,
    on_item: Optional[Callable[[CleanableItem, Optional[CleanOutcome], Optional[str]],
                               None]] = None,
    on_quarantine_claim: Optional[Callable[[str], None]] = None,
    backup_root: Optional[Path] = None,
    on_backup_claim: Optional[Callable[[str], None]] = None,
    protect: Optional[Iterable[Survivor]] = None,
) -> ActSummary:
    """Act on findings: quarantine (or, with ``permanent``, delete) each
    verified PATH finding through :func:`service.clean`, as one batch (one
    quarantine run, one history entry).

    Returns an :class:`ActSummary`; its outcomes and ``skipped`` carry the
    caller's original (finding) items. Duplicate copies must come from
    :func:`plan_duplicates` / :func:`plan_duplicates_keeping` (they name the
    copy to keep, which is re-checked here and again right before each
    removal). ``requires_root`` findings are skipped ("needs an elevated
    run"). Dry run by default: then nothing is moved or written and no
    command is run.

    User-level LAUNCH_JOB / SYSTEMD_UNIT findings are in the same batch but
    always permanent, whatever ``permanent`` says: right before the Engine
    removes the file, :func:`remedy_exec.check` re-verifies it, a copy is
    kept in ``backup_run`` (a copy-only run restore never acts on) and
    :func:`remedy_exec.unload` stops it (best effort; a failure is a warning
    in the outcome's ``note``); then the file is deleted, never quarantined.
    After the batch one ``systemctl --user daemon-reload`` runs if a unit
    was disabled. Their outcomes' ``note`` says what was done ("permanent:
    ... a copy of the file is kept in <dir> ..."). ``quarantine_run`` only
    ever holds PATH findings.

    Elevated helper only (never the CLI/GUI path): ``allow_root=True`` acts
    on ``requires_root`` findings (otherwise skipped "needs an elevated
    run"); ``quarantine_root`` is the helper's own validated, root-owned
    quarantine directory, the only case in which ``record_history=False``
    may be combined with a quarantine; ``extra_check`` is called (after
    every built-in check) up front and again right before each removal,
    a non-None return skipping the item; after it (same two moments) the
    finding's own evidence is re-checked by its scenario's re-verifier
    (:func:`reverify.reverify`; no re-verifier: skipped). With ``allow_root`` or
    ``quarantine_root`` only plain PATH findings and system-wide
    (``requires_root``) jobs/units/receipts are handled (never duplicates
    or user-level jobs/units). With ``allow_root`` an item that is a
    mount point or has a mount below it is skipped, and a permanent removal
    goes through :func:`root_delete.remove` (never ignores errors, never
    crosses filesystems, reports a partial removal as not removed).

    ``protect`` (default None): kept copies (:class:`findings.Survivor`,
    e.g. from :func:`kept_context`) of duplicate groups planned outside
    this batch. Like the kept copies stamped on the supplied items, they
    and any folder containing them are skipped (``KEEPS_COPY``). Callers
    that act on parts of one plan in several calls (``review``) MUST pass
    the whole plan's kept copies here, or an item of a later call could
    remove a copy kept for an earlier one.

    ``on_item(finding, outcome, skip_reason)`` (default None) reports each
    finding as soon as its fate is known: skipped up front (outcome None),
    or processed by the Engine (``skip_reason`` set when the re-check right
    before its removal refused it). ``on_quarantine_claim(run_id)`` (with
    ``quarantine_root`` only) is called once the quarantine run exists.

    System-wide launch jobs, units and package receipts (Task 9b; elevated
    helper only: ``allow_root`` AND ``backup_root``, the helper's validated
    root-owned quarantine directory, else skipped): right before each
    removal they are re-checked (:func:`system_remedy.check`, then
    ``extra_check`` and the re-verifier), the deadline is checked, every
    file is copied into a copy-only run under ``backup_root``
    (``backup_run``; ``on_backup_claim(run_id)`` once it exists; never
    under a home), then the job is stopped (:func:`system_remedy.unload`,
    best effort) and the file deleted -- or, for a receipt, ``pkgutil
    --forget`` runs and the receipt must be gone. Always permanent. One
    ``systemctl daemon-reload`` (system manager) after the batch if a
    unit was acted on. All system-scope commands run inside
    :func:`remedy_exec.system_scope`.
    """
    from cleanix.core import reverify, root_delete, system_remedy

    items = list(items)
    if not record_history and not permanent and not dry_run and quarantine_root is None:
        raise ValueError("record_history=False cannot be combined with quarantine")
    root_mode = allow_root or quarantine_root is not None

    # Root mode: the per-batch store of the re-verifiers (reverify.cached /
    # prefetch); "verify" = the up-front pass, "removal" = right before each.
    reverify_store: Dict[object, object] = {}

    def run_extra_check(item: CleanableItem, phase: str) -> Optional[str]:
        if allow_root and item.path:
            why = root_delete.mount_problem(item.path, permanent=permanent)
            if why is not None:
                return f"not removed: {why}"
        why = extra_check(item) if extra_check is not None else None
        if why is None and root_mode:
            # The finding's own evidence, re-checked right before removal;
            # a scenario without a re-verifier is refused (reverify.py).
            why = reverify.reverify(item, config, phase=phase, store=reverify_store)
        return why

    def report(item: CleanableItem, outcome: Optional[CleanOutcome],
               reason: Optional[str]) -> None:
        if on_item is not None:
            on_item(item, outcome, reason)
    # The guard below must see the user's protected globs (service.clean
    # sets them again; same value).
    safety.set_protected_globs(config.protected_globs)

    batch = {path_key(i.path) for i in items if i.path}
    # Every copy any supplied duplicate names as "kept" (verified or not) is
    # protected from EVERY item in the batch -- another cleaner's finding for
    # the same file, or a folder finding containing it, must not remove it.
    kept: Set[str] = set()
    kept_ids: Set[Tuple[int, ...]] = set()
    for i in items:
        stamp = survivor_of(i)
        if stamp is not None:
            kept |= _spellings(stamp.path)
            kept_ids.add(tuple(stamp.fingerprint)[2:])
    # ... and so is every kept copy the caller names in ``protect``: copies
    # kept by duplicate groups planned for OTHER calls of the same session
    # (review acts per answer; a preview may have skipped a stamped copy).
    for stamp in protect or ():
        kept |= _spellings(stamp.path)
        kept_ids.add(tuple(stamp.fingerprint)[2:])

    if root_mode:
        # One batched ownership query for the up-front pass (best effort).
        reverify.prefetch(items, config, reverify_store, reverify.VERIFY)
    hashed: Dict[Tuple[str, Tuple[int, ...]], Optional[str]] = {}
    skipped: Dict[int, str] = {}
    todo: List[Tuple[int, CleanableItem]] = []
    seen: Set[str] = set()
    for idx, item in enumerate(items):
        if root_mode and cancel is not None and cancel():
            # The helper's deadline passed while verifying: the rest is left
            # unprocessed (neither skipped nor acted on), as an Engine cancel.
            break
        key = path_key(item.path) if item.path else None
        if key is not None and key in seen:
            reason: Optional[str] = LISTED_TWICE
        elif item.path and _holds_kept_copy(item, kept, kept_ids):
            reason = KEEPS_COPY
        else:
            try:
                reason = _verify(item, batch, hashed, config, cancel,
                                 allow_root=allow_root, root_mode=root_mode,
                                 backup_root=backup_root)
                if reason is None:
                    reason = run_extra_check(item, reverify.VERIFY)
            except Exception as exc:  # noqa: BLE001 - fail closed, never abort the batch
                reason = f"could not be verified ({str(exc) or type(exc).__name__})"
        if key is not None:
            seen.add(key)
        if reason is not None:
            skipped[idx] = reason
            report(item, None, reason)
        else:
            todo.append((idx, _activate(item)))

    outcomes: Dict[int, CleanOutcome] = {}
    inner = None
    # Copies of launch-job/unit files: a copy-only run (created on first use),
    # never the restorable quarantine run.
    backup: List[Optional[quarantine.Quarantine]] = [None]
    if todo:
        original = {id(a): items[idx] for idx, a in todo}
        late: Dict[int, str] = {}  # id(activated item) -> precheck reason
        copy_kinds = remedy_exec.SYSTEM_KINDS if root_mode else remedy_exec.KINDS
        jobs = {id(a) for _i, a in todo
                if original[id(a)].remedy is not None
                and original[id(a)].remedy.kind in copy_kinds}  # type: ignore[union-attr]
        # id(activated) -> (kind, stop result, where the copy is) for every
        # launch job / unit / receipt that got as far as its stop attempt.
        prepared: Dict[int, Tuple[RemedyKind, remedy_exec.Stop, str]] = {}
        # path -> package id of every receipt ready to be forgotten (root mode)
        receipts: Dict[str, str] = {}

        def keep_copies(paths: Sequence[str]) -> Tuple[Optional[str], str]:
            """Copy ``paths`` into the copy-only backup run: ``(problem,
            where)``. In root mode the run lives under ``backup_root``
            only (never under a home)."""
            try:
                if backup[0] is None:
                    if root_mode:
                        if backup_root is None:  # pragma: no cover - _verify refused
                            return NO_BACKUP_PLACE, ""
                        backup[0] = quarantine.new_run(root=backup_root,
                                                       on_claim=on_backup_claim)
                    else:
                        backup[0] = quarantine.new_run()
                for p in paths:
                    backup[0].store_copy(p)
                return None, str(backup[0].files_dir)
            except Exception as exc:  # noqa: BLE001
                return ("could not keep a copy of the file, nothing removed "
                        f"({str(exc) or type(exc).__name__})"), ""

        def prepare(activated: CleanableItem, finding: CleanableItem) -> Optional[str]:
            """Re-verify a launch job/unit; on a real run keep a copy and
            stop it, right before the Engine deletes its file. Nothing after
            the stop attempt may raise."""
            assert finding.remedy is not None and finding.path
            why, name = remedy_exec.check(finding, config)
            if why is not None or dry_run:
                return why
            assert name is not None
            why, where = keep_copies([finding.path])
            if why is not None:
                return why
            stop = remedy_exec.unload(finding.remedy.kind, name, finding.path)
            prepared[id(activated)] = (finding.remedy.kind, stop, where)
            return None

        def prepare_system(activated: CleanableItem, finding: CleanableItem) -> Optional[str]:
            """Root mode: re-verify a system-wide job/unit/receipt (its own
            structural check, the helper's chain check and the scenario's
            re-verifier on its ORIGINAL evidence), stop at the deadline,
            then -- on a real run -- copy every file, stop the job, and
            leave the removal to the Engine (``remove_path``). Nothing
            after the copy may raise."""
            assert finding.remedy is not None and finding.path
            kind = finding.remedy.kind
            why, name = system_remedy.check(finding, config)
            if why is None:
                why = run_extra_check(finding, reverify.REMOVAL)
            if why is None and cancel is not None and cancel():
                why = STOPPED_AT_DEADLINE
            if why is not None or dry_run:
                return why
            assert name is not None
            try:
                paths = system_remedy.backup_paths(kind, finding.path, name)
            except Exception as exc:  # noqa: BLE001
                return f"could not be verified ({str(exc) or type(exc).__name__})"
            why, where = keep_copies(paths)
            if why is not None:
                return why
            if kind is RemedyKind.PKG_RECEIPT:
                stop = remedy_exec.Stop(stopped=True)
                receipts[path_key(finding.path)] = name
            else:
                stop = system_remedy.unload(kind, name, finding.path)
            prepared[id(activated)] = (kind, stop, where)
            return None

        def precheck(activated: CleanableItem) -> Optional[str]:
            finding = original.get(id(activated))
            if finding is None:
                why: Optional[str] = "not part of this batch"
            else:
                try:
                    assert finding.remedy is not None
                    if root_mode and finding.remedy.kind in remedy_exec.SYSTEM_KINDS:
                        why = prepare_system(activated, finding)
                    elif not root_mode and finding.remedy.kind in remedy_exec.KINDS:
                        why = prepare(activated, finding)
                    else:
                        why = _recheck(finding, config, root_mode)
                        if why is None:
                            why = run_extra_check(finding, reverify.REMOVAL)
                        if why is None and root_mode and cancel is not None and cancel():
                            # the deadline passed during its own re-check:
                            # never removed after the deadline
                            why = STOPPED_AT_DEADLINE
                except Exception as exc:  # noqa: BLE001 - fail closed
                    why = f"could not be verified ({str(exc) or type(exc).__name__})"
            if why is not None:
                late[id(activated)] = why
            return why

        # Only PATH findings are quarantined (restorable); a batch of jobs
        # alone opens no quarantine run at all.
        quarantine_paths = not permanent and len(jobs) < len(todo)

        def engine_outcome(outcome: CleanOutcome) -> None:
            finding = original.get(id(outcome.item))
            if finding is None:
                return
            why = late.get(id(outcome.item)) if not outcome.removed else None
            report(finding, outcome, why)

        root_kwargs: Dict[str, object] = {}
        if quarantine_root is not None:
            root_kwargs["quarantine_root"] = quarantine_root
            if on_quarantine_claim is not None:
                root_kwargs["on_quarantine_claim"] = on_quarantine_claim
        if allow_root and not dry_run:
            receipt_items = {path_key(a.path or "") for _i, a in todo
                             if original[id(a)].remedy is not None
                             and original[id(a)].remedy.kind is RemedyKind.PKG_RECEIPT}  # type: ignore[union-attr]

            def remove_path(path: str):
                # A prepared receipt is forgotten (pkgutil), never unlinked;
                # anything else in the receipts folder, or a receipt that
                # was not prepared, is refused (never root_delete.remove).
                pkg_id = receipts.pop(path_key(path), None)
                if pkg_id is not None:
                    return system_remedy.forget(pkg_id, path)
                if path_key(path) in receipt_items or system_remedy.in_receipts_dir(path):
                    return False, 0, system_remedy.RECEIPT_NOT_UNLINKED
                return root_delete.remove(path)

            root_kwargs["remove_path"] = remove_path
        if on_item is not None:
            root_kwargs["on_outcome"] = engine_outcome
        # System-scope commands (systemctl without
        # --user, pkgutil --forget) are runnable only inside this scope,
        # which only the helper's root mode opens.
        scope = remedy_exec.system_scope() if allow_root else contextlib.nullcontext()
        reload_warnings: List[str] = []
        with scope:
            try:
                inner = service.clean(
                    [a for _i, a in todo], config, dry_run=dry_run,
                    use_quarantine=quarantine_paths, progress=progress, cancel=cancel,
                    record_history=record_history, precheck=precheck,
                    delete_instead=lambda a: id(a) in jobs,
                    **root_kwargs,  # type: ignore[arg-type]
                )
            finally:
                if backup[0] is not None:
                    backup[0].discard_if_empty()
            if any(k is RemedyKind.SYSTEMD_UNIT for k, _s, _d in prepared.values()):
                reload_warnings = (system_remedy.reload_units() if root_mode
                                   else remedy_exec.reload_units())
        # Engine yields one outcome per processed item, in order; a cancel
        # leaves the rest unprocessed (no outcome), as in a normal clean.
        for (idx, activated), outcome in zip(todo, inner.result.outcomes):
            if id(activated) in late and not outcome.removed:
                skipped[idx] = late[id(activated)]
                continue
            info = prepared.get(id(activated))
            if info is not None and root_mode:
                kind, stop, where = info
                reload_extra = reload_warnings if kind is RemedyKind.SYSTEMD_UNIT else []
                note = system_remedy.note(kind, where, stop, outcome.removed, reload_extra)
                outcome = dataclasses.replace(outcome, note=note)
            elif info is not None:
                kind, stop, where = info
                reload_extra = reload_warnings if kind is RemedyKind.SYSTEMD_UNIT else []
                if outcome.removed:
                    note = remedy_exec.permanent_note(where, stop, reload_extra)
                else:
                    note = ("the job was stopped, but its file was not removed"
                            if stop.stopped else "its file was not removed")
                    warnings = stop.warnings + list(reload_extra)
                    if warnings:
                        note += "; warning: " + "; ".join(warnings)
                outcome = dataclasses.replace(outcome, note=note)
            outcomes[idx] = dataclasses.replace(outcome, item=items[idx])

    result = CleanResult(dry_run=dry_run,
                         outcomes=[outcomes[i] for i in sorted(outcomes)])
    return ActSummary(
        result=result,
        quarantine_run=inner.quarantine_run if inner else None,
        manifest_path=inner.manifest_path if inner else None,
        freed=result.freed,
        removed=result.removed_count,
        errors=result.errors,
        cancelled=bool(inner.cancelled if inner else (cancel is not None and cancel())),
        undo_record_error=inner.undo_record_error if inner else None,
        skipped=[(items[i], skipped[i]) for i in sorted(skipped)],
        backup_run=backup[0].run_id if backup[0] is not None and backup[0].items else None,
    )
