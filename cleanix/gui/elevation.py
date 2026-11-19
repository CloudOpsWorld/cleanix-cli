"""Elevated cleaning for the GUI: split a selection, run the admin part.

The GUI never runs as root. A clean is split in two:

* **user items** (``requires_root`` False) are cleaned in-process by the GUI,
  as the normal user, with the user's quarantine choice and the normal
  history recording (``service.clean``);
* **administrator items** (``requires_root`` True) are handed to the elevated
  helper (``python -m cleanix.elevated``) through a request file that names
  only cleaner ids and item keys. The helper re-scans, cleans only items it
  itself deems eligible (allowlisted cleaner, needs admin rights, not
  report-only), ignores ``use_quarantine`` and never writes history: these
  items are removed PERMANENTLY and can never be undone. The GUI records one
  history entry for them itself, as the user, from the helper's counts;
* **machine-wide registry items** (REGISTRY, HKLM) are first backed up by
  the GUI, as the user, into one quarantine run; the same single prompt
  then sends them in the request's registry part (run id + item keys) and
  the helper deletes only entries that run can restore (restorable only
  from an Administrator terminal, ruling R6).

The helper only returns counts, so administrator rows cannot be matched back
to per-item outcomes: views keep them and ask the user to scan again.

How the views use it (Task 12 wires this)::

    from cleanix.gui import elevation
    allow = elevation.elevation_available()
    factory = elevation.make_clean_worker_factory(config, elevation=allow)
    SimpleView(config, clean_worker_factory=factory, allow_admin_items=allow)
    PowerView(config, clean_worker_factory=factory, allow_admin_items=allow)

This module does not import Qt at import time (``make_clean_worker_factory``
imports ``cleanix.gui.workers`` lazily).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, FrozenSet, List, Optional, Sequence, Tuple

from cleanix.core import elevate, elevate_launch, service, utils
from cleanix.core.models import CleanableItem, ItemKind, item_key
from cleanix.core.platform import LINUX, MACOS, WINDOWS, current_os
from cleanix.core.utils import human_size

DONE = "done"
DECLINED = "declined"
UNAVAILABLE = "unavailable"
FAILED = "failed"


@dataclass
class ElevatedOutcome:
    """What happened to the administrator part of a clean.

    ``status``: ``done`` | ``declined`` | ``unavailable`` | ``failed``.
    ``result`` is set only for a helper result that was read successfully and
    carries this run's nonce (for ``done``; for ``failed`` only when the
    helper exited with one of its own error codes and still wrote a valid
    result, e.g. a partial run that hit its deadline). ``outcome_unknown`` is
    True after a timeout: the helper may still be running and no result was
    read. ``detail`` holds technical text (exit code, error).
    """

    status: str
    message: str
    result: Optional[elevate.HelperResult] = None
    detail: str = ""
    outcome_unknown: bool = False
    # True once the launcher (prompt + helper) was actually called.
    launched: bool = False
    # Registry (HKLM) items: how many were selected, how many could not be
    # backed up (dropped from the request), and the quarantine run holding
    # the backups the GUI wrote as the user BEFORE the launch (None when
    # nothing was backed up or the run was purged because nothing ran).
    registry_selected: int = 0
    registry_backup_failed: int = 0
    registry_backup_run: Optional[str] = None
    registry_backup_dir: str = ""


@dataclass
class CombinedSummary(service.CleanSummary):
    """``CleanSummary`` of the user part, extended with the admin part.

    ``result``/``quarantine_run``/``manifest_path``/``errors`` are the user
    part's (``errors`` holds only the user part's ``CleanOutcome`` objects;
    the helper's error strings are in ``admin.result.errors``). ``freed`` and
    ``removed`` include the administrator part when it ran. ``admin`` is None
    when there were no administrator items or the run was cancelled before
    the administrator step (then ``cancelled`` is True and
    ``admin_selected`` > 0).

    ``late_cancel`` is True when Cancel was requested after the administrator
    prompt/helper had been launched: that step cannot be stopped, so it ran
    to completion (``cancelled`` stays False because nothing stopped early).

    Dry run: nothing is elevated (``admin`` None, ``admin_selected`` 0); the
    administrator items are a preview, ``admin_preview_count`` items of
    ``admin_preview_size`` bytes, already included in ``freed``/``removed``.
    """

    admin: Optional[ElevatedOutcome] = None
    admin_selected: int = 0
    user_freed: int = 0
    user_removed: int = 0
    late_cancel: bool = False
    admin_preview_count: int = 0
    admin_preview_size: int = 0
    # Dry run: how many of the previewed administrator items are registry
    # entries (they are backed up before the helper deletes them).
    admin_preview_registry: int = 0


# Progress text the worker emits right before the (unstoppable) elevated
# step. Views compare ``progress`` names against it and disable Cancel.
ADMIN_WAIT_MESSAGE = ("Waiting for administrator permission... (it cannot be stopped "
                      "from here: decline the prompt to skip administrator items)")
LATE_CANCEL_LINE = ("Cancel arrived after administrator permission was given; "
                    "that step could not be stopped.")


# --------------------------------------------------------------------------
# availability
# --------------------------------------------------------------------------
HELPER_UNAVAILABLE_REASON = (
    "Administrator cleaning is not available: the helper cannot be started from "
    "this installation (a `pip install --user` or source-tree run); install "
    "cleanix into the system or a venv")
PROBE_TIMEOUT = 10  # seconds

# (ok, reason) of the helper start probe; None until it ran (once per process).
_probe_state: Optional[Tuple[bool, str]] = None


def reset_helper_probe() -> None:
    """Forget the cached probe result (tests)."""
    global _probe_state
    _probe_state = None


def _run_helper_probe() -> bool:
    """Can ``python -I`` import the helper the way the launcher will start
    it? Unprivileged, no shell, stdin closed, neutral cwd, short timeout.
    (``-I`` ignores PYTHONPATH, the user site directory and the current
    directory, so a ``pip install --user`` or source-tree run fails here
    instead of after the user typed the administrator password.)"""
    import sys
    import tempfile

    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", "import cleanix.elevated"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=PROBE_TIMEOUT,
            cwd=tempfile.gettempdir(), check=False, **kwargs)
    except Exception:  # noqa: BLE001 - any failure means "cannot start"
        return False
    return proc.returncode == 0


def _helper_starts() -> bool:
    global _probe_state
    if _probe_state is None:
        try:
            ok = bool(_run_helper_probe())
        except Exception:  # noqa: BLE001
            ok = False
        _probe_state = (ok, "" if ok else HELPER_UNAVAILABLE_REASON)
    return _probe_state[0]


def elevation_unavailable_reason() -> str:
    """Why administrator cleaning is unavailable because the helper cannot
    start ("" if the probe has not run or succeeded)."""
    return _probe_state[1] if _probe_state is not None else ""


def _platform_can_prompt() -> bool:
    osname = current_os()
    if osname == WINDOWS:
        return True
    if osname == LINUX:
        return bool(utils.safe_which("pkexec"))
    if osname == MACOS:
        return os.path.exists(elevate_launch._OSASCRIPT)
    return False


def elevation_available() -> bool:
    """Can this system show an elevation prompt AND start the helper?
    The helper probe runs once per process, only when the platform check
    passes. Never raises."""
    try:
        if not _platform_can_prompt():
            return False
        return _helper_starts()
    except Exception:  # noqa: BLE001 - availability probe only
        return False


# --------------------------------------------------------------------------
# which administrator items can be offered at all
# --------------------------------------------------------------------------
def admin_allowlist() -> FrozenSet[str]:
    """The helper's cleaner allowlist (``elevated.admin_cleaner_ids``).
    Compute once per scan result; never raises (empty on failure)."""
    try:
        from cleanix import elevated

        return frozenset(elevated.admin_cleaner_ids())
    except Exception:  # noqa: BLE001 - then no administrator item is offered
        return frozenset()


def admin_item_problem(item: CleanableItem, allowlist) -> Optional[str]:
    """Why the helper would always refuse ``item`` (plain language), or None.
    Only meaningful for ``requires_root`` items; never raises."""
    try:
        from cleanix import elevated

        return elevated.static_admin_problem(item, allowlist)
    except Exception:  # noqa: BLE001 - fail closed: do not offer it
        return "Cannot be checked for administrator cleaning"


def admin_problems(items: Sequence[CleanableItem]) -> dict:
    """``{id(item): reason}`` for the ``requires_root`` items (not
    report-only) that the helper would always refuse. The allowlist is
    computed once, only when there is such an item."""
    candidates = [i for i in items if i.requires_root and not i.report_only]
    if not candidates:
        return {}
    allow = admin_allowlist()
    out = {}
    for item in candidates:
        reason = admin_item_problem(item, allow)
        if reason:
            out[id(item)] = reason
    return out


# --------------------------------------------------------------------------
# split
# --------------------------------------------------------------------------
def split_items(items: Sequence[CleanableItem]
                ) -> Tuple[List[CleanableItem], List[CleanableItem]]:
    """``(user_items, admin_items)`` by ``requires_root``, order kept."""
    user: List[CleanableItem] = []
    admin: List[CleanableItem] = []
    for item in items:
        (admin if item.requires_root else user).append(item)
    return user, admin


# --------------------------------------------------------------------------
# admin part
# --------------------------------------------------------------------------
def _invoking_user_name() -> str:
    """The account name the helper will resolve from our uid (POSIX: the
    passwd name of the real uid, not LOGNAME/USER)."""
    if os.name != "nt":
        try:
            import pwd

            return pwd.getpwuid(os.getuid()).pw_name
        except Exception:  # noqa: BLE001
            pass
    import getpass

    return getpass.getuser()


def _config_path() -> str:
    from cleanix import config as config_mod

    return str(config_mod.config_file_path())


def build_selection(admin_items: Sequence[CleanableItem], *,
                    registry: Optional[elevate.RegistryRequest] = None
                    ) -> elevate.Selection:
    """Cleaner ids and item keys of the non-registry ``admin_items`` only
    (registry entries go only through ``registry``); quarantine off."""
    files = [i for i in admin_items if i.kind is not ItemKind.REGISTRY]
    only = list(dict.fromkeys(i.cleaner_id for i in files))
    keys = list(dict.fromkeys(item_key(i) for i in files))
    return elevate.Selection(invoking_user=_invoking_user_name(), only=only,
                             keys=keys, use_quarantine=False, registry=registry)


def _backup_registry(items: Sequence[CleanableItem]):
    """Back the HKLM entries up AS THE USER into one new quarantine run,
    before any launch (ruling R6). ``(run or None, backed-up items, number
    of failures)``; an entry whose backup fails is dropped. Never raises
    (except BaseException)."""
    from cleanix.core import quarantine, winregistry

    run = quarantine.new_run()
    backend = winregistry.get_backend()
    kept: List[CleanableItem] = []
    failed = 0
    for item in items:
        try:
            run.store_registry(item, backend)
            kept.append(item)
        except Exception:  # noqa: BLE001 - this entry is simply not removed
            failed += 1
    if not kept:
        try:
            run.discard_if_empty()
        except Exception:  # noqa: BLE001
            pass
        return None, [], failed
    return run, kept, failed


def _purge_run(run_id: Optional[str]) -> None:
    """Remove a backup run nothing was deleted from. Never raises."""
    if not run_id:
        return
    try:
        from cleanix.core import quarantine

        quarantine.purge(run_id)
    except Exception:  # noqa: BLE001 - leaves a harmless backup behind
        pass


def _is_timeout(exc: BaseException) -> bool:
    if isinstance(exc.__cause__, (TimeoutError, subprocess.TimeoutExpired)):
        return True
    return "timed out" in str(exc).lower()


def _read_matching_result(result_path, nonce: str) -> Tuple[Optional[elevate.HelperResult], str]:
    """(result, problem). The result only if readable AND its nonce matches."""
    try:
        result = elevate.read_result(result_path)
    except (ValueError, OSError):
        return None, "the helper's result could not be read"
    if result.nonce != nonce:
        return None, "the helper returned a stale or unexpected result"
    return result, ""


def run_elevated_part(admin_items: Sequence[CleanableItem], config=None, *,
                      use_quarantine: bool = False,
                      launcher: Optional[Callable[[List[str]], int]] = None,
                      config_path: Optional[str] = None,
                      cancel: Optional[Callable[[], bool]] = None,
                      ) -> Optional[ElevatedOutcome]:
    """Clean ``admin_items`` through the elevated helper (one prompt).

    ``use_quarantine`` is accepted for interface symmetry and ignored: the
    helper always deletes permanently, and the request always says so.
    Blocks while the prompt is open and the helper runs: call it off the GUI
    thread. Never raises (except BaseException such as KeyboardInterrupt);
    the request directory is always removed.

    ``cancel`` is checked immediately before the launcher is called (after
    the request was written): if it is set, the launcher is never called and
    None is returned ("stopped before the administrator step"). Once the
    launcher runs, nothing here can stop it.

    Registry (HKLM) items are first backed up AS THE USER into one new
    quarantine run (``Quarantine.store_registry``); an item whose backup
    fails is dropped from the request. The request names that run and the
    user's quarantine root, and the helper deletes only entries that run
    can restore. The run is purged when nothing could have been deleted
    (declined, unavailable, cancelled or failed before the launch) and kept
    otherwise.
    """
    del use_quarantine, config  # the helper loads its own default config
    admin_items = list(admin_items)
    if not admin_items:
        return ElevatedOutcome(DONE, "No administrator items were selected.",
                               elevate.HelperResult(freed=0, removed=0, errors=[],
                                                    unmatched=0))
    file_items = [i for i in admin_items if i.kind is not ItemKind.REGISTRY]
    reg_items = [i for i in admin_items if i.kind is ItemKind.REGISTRY]
    launch = launcher or elevate_launch.launch_elevated  # looked up at call time
    request_dir = None
    backup = None
    kept: List[CleanableItem] = []
    failed = 0
    launched = False

    def with_registry(outcome: ElevatedOutcome) -> ElevatedOutcome:
        outcome.registry_selected = len(reg_items)
        outcome.registry_backup_failed = failed
        if backup is not None:
            outcome.registry_backup_run = backup.run_id
            outcome.registry_backup_dir = os.path.abspath(str(backup.dir))
        return outcome

    try:
        if reg_items:
            backup, kept, failed = _backup_registry(reg_items)
            if not kept and not file_items:
                return with_registry(ElevatedOutcome(
                    FAILED, "Registry backup failed; nothing was removed."))
        registry = None
        if backup is not None:
            from cleanix.core import quarantine

            registry = elevate.RegistryRequest(
                only=list(dict.fromkeys(i.cleaner_id for i in kept)),
                keys=list(dict.fromkeys(item_key(i) for i in kept)),
                backup_run=backup.run_id,
                quarantine_root=os.path.realpath(str(quarantine.quarantine_root())))
        n = len(file_items) + len(kept)
        selection = build_selection(file_items, registry=registry)
        request_dir = elevate.make_request_dir()
        request_path = request_dir / elevate.REQUEST_NAME
        result_path = request_dir / elevate.RESULT_NAME
        elevate.write_request(request_dir, selection)
        argv = elevate_launch.elevated_command(
            request_path, result_path, config_path or _config_path())
        if cancel is not None and cancel():
            _purge_run(backup.run_id if backup is not None else None)
            return None
        launched = True
        outcome = _launch(launch, argv, n, result_path, selection.nonce)
        outcome.launched = True
        if outcome.status in (DECLINED, UNAVAILABLE) and backup is not None:
            # The helper never ran: nothing was deleted, drop the backups.
            _purge_run(backup.run_id)
            backup = None
        return with_registry(outcome)
    except Exception as exc:  # noqa: BLE001 - surfaced as a plain failure
        if not launched and backup is not None:
            _purge_run(backup.run_id)
            backup = None
        return with_registry(ElevatedOutcome(
            FAILED, "Administrator cleaning failed. Scan again to see what is left.",
            detail=type(exc).__name__))
    finally:
        if request_dir is not None:
            shutil.rmtree(request_dir, ignore_errors=True)


# Exit codes of the helper itself that may come with a (partial) result.
_HELPER_RESULT_CODES = (1, 2, 3)


def _launch(run, argv, n: int, result_path, nonce: str) -> ElevatedOutcome:
    """Call the launcher once and map its outcome (see run_elevated_part)."""
    try:
        rc = run(argv)
    except elevate_launch.ElevationDeclined:
        return ElevatedOutcome(
            DECLINED, f"Administrator permission was declined; {n} items were not cleaned")
    except elevate_launch.ElevationUnavailable as exc:
        return ElevatedOutcome(
            UNAVAILABLE, "Administrator cleaning is not available on this system; "
            f"{n} administrator items were not cleaned",
            detail=str(exc))
    except elevate_launch.ElevationFailed as exc:
        code = getattr(exc, "exit_code", None)
        if code is None and _is_timeout(exc):
            # Never trust or read a result file after a timeout.
            return ElevatedOutcome(
                FAILED,
                "The administrator helper timed out: the outcome is unknown and "
                "the helper may still be running. Scan again later to see what is left.",
                detail=str(exc), outcome_unknown=True)
        detail = str(exc) + (f" (exit code {code})" if code is not None else "")
        result = None
        if code in _HELPER_RESULT_CODES:
            # The helper's own error codes: it may have written a (partial)
            # result for this run; some items may already be gone.
            result, _problem = _read_matching_result(result_path, nonce)
        if result is not None and result.removed == 0:
            message = ("Administrator cleaning failed; no administrator items "
                       "were removed.")
        else:
            message = ("Administrator cleaning failed; some administrator items "
                       "may already have been removed. Scan again to see what is left.")
        return ElevatedOutcome(FAILED, message, result=result, detail=detail)
    if rc != 0:
        return ElevatedOutcome(
            FAILED, "Administrator cleaning failed. Scan again to see what is left.",
            detail=f"launcher returned {rc!r}")
    result, problem = _read_matching_result(result_path, nonce)
    if result is None:
        return ElevatedOutcome(
            FAILED, f"Administrator cleaning failed: {problem}. "
            "Scan again to see what is left.", detail=problem)
    return ElevatedOutcome(DONE, "Administrator items cleaned", result=result)


def record_admin_history(outcome: Optional[ElevatedOutcome]) -> None:
    """One history entry, as the user, for what the helper removed (>0 only).
    Never raises."""
    try:
        if outcome is None or outcome.result is None or outcome.result.removed <= 0:
            return
        from cleanix.core import history

        history.record(outcome.result.freed, outcome.result.removed, mode="delete")
    except Exception:  # noqa: BLE001 - history is best-effort
        pass


# --------------------------------------------------------------------------
# plain-language text for the views
# --------------------------------------------------------------------------
MAX_SHOWN_ERRORS = 5


def _entries(n: int) -> str:
    return f"{n} registry entry" if n == 1 else f"{n} registry entries"


def _undo_shipped() -> bool:
    try:
        from cleanix.core import regpromises

        return bool(regpromises.registry_undo_shipped())
    except Exception:  # noqa: BLE001 - never promise undo on doubt
        return False


def admin_preview_line(count: int, size: int, registry: int = 0) -> str:
    """Dry-run line for administrator items (nothing was elevated).
    ``registry`` of them are HKLM registry entries, which are backed up
    first; that is only said once registry undo has shipped (regpromises)."""
    head = (f"{count} administrator item(s) ({human_size(int(size or 0))}) would be "
            "removed after one administrator prompt; ")
    registry = int(registry or 0)
    if registry > 0 and _undo_shipped():
        verb = "is" if registry == 1 else "are"
        return head + (f"files and commands cannot be undone, {_entries(registry)} "
                       f"{verb} backed up first")
    return head + "they cannot be undone"


def admin_outcome_lines(summary) -> List[str]:
    """Plain-language lines describing the administrator part of ``summary``
    (empty when there were no administrator items)."""
    preview = int(getattr(summary, "admin_preview_count", 0) or 0)
    if preview:
        return [admin_preview_line(preview, getattr(summary, "admin_preview_size", 0),
                                   getattr(summary, "admin_preview_registry", 0))]
    selected = int(getattr(summary, "admin_selected", 0) or 0)
    outcome: Optional[ElevatedOutcome] = getattr(summary, "admin", None)
    if not selected:
        return []
    if outcome is None:
        return [f"Stopped before the administrator step; {selected} administrator "
                "items were not cleaned."]
    lines: List[str] = []
    res = outcome.result
    if outcome.status == DONE and res is not None:
        lines.append(f"Administrator items: removed {res.removed}, "
                     f"freed {human_size(res.freed)}")
    elif outcome.status == DECLINED:
        lines.append(f"Administrator permission was declined; {selected} items "
                     "were not cleaned")
    elif outcome.status == UNAVAILABLE:
        lines.append("Administrator cleaning is not available on this system; "
                     f"{selected} administrator items were not cleaned")
    failed = not lines
    if failed:
        lines.append("Administrator cleaning failed (see details)")
    reg_failed = int(getattr(outcome, "registry_backup_failed", 0) or 0)
    if reg_failed:
        was = "was" if reg_failed == 1 else "were"
        lines.append(f"{_entries(reg_failed)} could not be backed up and {was} "
                     "not removed")
    shipped = _undo_shipped()
    reg_run = getattr(outcome, "registry_backup_run", None)
    if reg_run and shipped:
        lines.append(
            f"Registry entries were backed up to quarantine run {reg_run} "
            f"({getattr(outcome, 'registry_backup_dir', '')}); to restore, from an "
            f"Administrator terminal run cleanix restore {reg_run} or reg import "
            "each .reg file there")
    if getattr(summary, "late_cancel", False):
        lines.append(LATE_CANCEL_LINE)
    if failed:
        lines.append(outcome.message)
        if res is not None:
            lines.append(f"Before it stopped, the helper removed {res.removed} "
                         f"administrator items ({human_size(res.freed)}).")
        if outcome.detail:
            lines.append(f"Details: {outcome.detail}")
    if res is not None:
        if res.refused:
            lines.append(f"{res.refused} administrator item(s) were not cleaned because "
                         "the administrator helper refused them (for safety it only "
                         "cleans a fixed list of system locations)")
        if res.unmatched:
            lines.append(f"{res.unmatched} administrator item(s) were not cleaned because "
                         "the administrator helper no longer found them; scan again")
        if res.deadline_hit:
            lines.append("The administrator helper reached its time limit; "
                         "some items were not cleaned.")
        if res.errors:
            lines.append(f"{len(res.errors)} administrator error(s):")
            lines.extend(f"  {e}" for e in res.errors[:MAX_SHOWN_ERRORS])
        if res.removed:
            if shipped and int(getattr(outcome, "registry_selected", 0) or 0):
                lines.append("Administrator files and commands are removed "
                             "permanently; they cannot be undone.")
            else:
                lines.append("Administrator items are removed permanently; "
                             "they cannot be undone.")
        lines.append("Scan again to refresh the list.")
    return lines


# --------------------------------------------------------------------------
# factory for the views
# --------------------------------------------------------------------------
def make_clean_worker_factory(config, *, elevation: bool = True,
                              launcher: Optional[Callable] = None) -> Callable:
    """A ``clean_worker_factory`` accepted by both views.

    SimpleView calls ``factory(items, config, dry_run=..., use_quarantine=...)``;
    PowerView calls ``factory(items, dry_run=..., use_quarantine=...)``. With
    ``elevation=True`` it returns ``ElevatedCleanWorker`` objects (user items
    in-process, administrator items through one prompt); otherwise plain
    ``CleanWorker`` objects. Pass ``elevation=elevation_available()`` and the
    same value as the views' ``allow_admin_items``.
    """
    bound = config

    def factory(items, cfg=None, *, dry_run: bool, use_quarantine: bool):
        from cleanix.gui import workers

        use = cfg if cfg is not None else bound
        if elevation:
            return workers.ElevatedCleanWorker(items, use, dry_run=dry_run,
                                               use_quarantine=use_quarantine,
                                               launcher=launcher)
        return workers.CleanWorker(items, use, dry_run=dry_run,
                                   use_quarantine=use_quarantine)

    return factory
