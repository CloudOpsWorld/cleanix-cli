"""System-wide non-path remedies (Task 9b): the elevated helper only.

Three kinds, each bound to one scenario and one platform:

* ``LAUNCH_JOB`` (macOS, ``orphan_launch_jobs``): a plist directly in
  ``/Library/LaunchDaemons`` or ``/Library/LaunchAgents`` (never
  ``/System``, never ``com.apple.*``). A daemon is stopped with ``launchctl
  bootout system/<label>``; an agent is NOT stopped (it runs in users'
  sessions; it simply is not started again at their next login). Then the
  plist is deleted.
* ``SYSTEMD_UNIT`` (Linux, ``stale_services``): a unit file directly in
  ``/etc/systemd/system`` (never a vendor folder). ``systemctl disable
  --now <unit>`` (template units: without ``--now``), the file is deleted,
  and ONE ``systemctl daemon-reload`` runs after the batch.
* ``PKG_RECEIPT`` (macOS, ``stale_receipts``): ``/var/db/receipts/<id>.plist``
  (+ ``.bom``). ``pkgutil --forget <id>`` removes both; afterwards both must
  be gone, otherwise the item is reported as not removed.

``actions.act`` (root mode, ``allow_root`` with a ``backup_root``) drives
them, per item, right before its removal and in this order: :func:`check`
(this module's structural re-check: scenario, platform, name, exact folder,
identity), the helper's chain/file-ownership check and the scenario's
re-verifier (``reverify``: the detector's ORIGINAL evidence under strict
evidence), a copy of every file into a copy-only run in the helper's
root-owned quarantine (:func:`backup_paths`), then the stop command
(:func:`unload`) and the removal (Engine; :func:`forget` for receipts). A
failing stop command never blocks the removal (a warning in the outcome's
note; "not loaded" is a soft note). These removals are PERMANENT: the
copies are for manual recovery only; nothing restores them.

Every command goes through ``remedy_exec.run_mutating(..., scope=SYSTEM)``,
which runs only inside ``remedy_exec.system_scope`` in helper scan mode.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence, Tuple

from cleanix.core import platform as plat
from cleanix.core import remedy_exec, safety
from cleanix.core.remedy import CHANGED, RemedyKind, verify_path
from cleanix.core.remedy_exec import SYSTEM, SYSTEM_KINDS, Stop

if TYPE_CHECKING:  # pragma: no cover
    from cleanix.config import Config
    from cleanix.core.models import CleanableItem

# kind -> the one scenario that may carry it, the platform it exists on and
# the remedy extra key naming it.
SCENARIO: Dict[RemedyKind, str] = {
    RemedyKind.LAUNCH_JOB: "orphan_launch_jobs",
    RemedyKind.SYSTEMD_UNIT: "stale_services",
    RemedyKind.PKG_RECEIPT: "stale_receipts",
}
PLATFORM: Dict[RemedyKind, str] = {
    RemedyKind.LAUNCH_JOB: plat.MACOS,
    RemedyKind.SYSTEMD_UNIT: plat.LINUX,
    RemedyKind.PKG_RECEIPT: plat.MACOS,
}
KEY: Dict[RemedyKind, str] = {
    RemedyKind.LAUNCH_JOB: "label",
    RemedyKind.SYSTEMD_UNIT: "unit",
    RemedyKind.PKG_RECEIPT: "pkg_id",
}
UNIT_DIR = "/etc/systemd/system"
LAUNCH_DAEMONS = "/Library/LaunchDaemons"
LAUNCH_AGENTS = "/Library/LaunchAgents"
# Every folder whose plists a ``bootout system/<label>`` could hit instead.
LABEL_DIRS = (
    "/Library/LaunchDaemons", "/System/Library/LaunchDaemons",
    "/Library/LaunchAgents", "/System/Library/LaunchAgents",
)

NOT_HANDLED = "this kind of finding is not handled here"
WRONG_SCENARIO = "this scenario does not offer this kind of action; refused"
WRONG_PLATFORM = "this kind of finding is not acted on on this system; refused"
BAD_DATA = "unexpected remedy data; refused"
BAD_NAME = "the name is not a plain label/unit/package id; refused"
APPLE = "an Apple job or package (com.apple.*); never touched"
NOT_IN_PLACE = "not directly inside a folder this action may change; refused"
IS_LINK = "a link, not a plain file; refused"
BAD_BOM = "the receipt's .bom file is not a plain file; refused"
BLOCKED = "blocked by safety guard (protected path)"
AGENT_NOT_STOPPED = ("a system-wide agent is not stopped here: copies already running "
                     "in users' sessions keep running until they log out (it is not "
                     "started again at the next login)")


def kind_dirs() -> Dict[RemedyKind, Tuple[str, ...]]:
    """kind -> the (logical) folders its files must lie DIRECTLY in."""
    from cleanix.cleaners import orphan_launch_jobs, stale_receipts

    return {
        RemedyKind.LAUNCH_JOB: tuple(orphan_launch_jobs.SYSTEM_DIRS),
        RemedyKind.SYSTEMD_UNIT: (UNIT_DIR,),
        RemedyKind.PKG_RECEIPT: (stale_receipts.RECEIPTS_DIR,),
    }


def _sysroot(kind: RemedyKind) -> str:
    """The scenario detector's system root (``/``; tests use a fake one)."""
    if kind is RemedyKind.LAUNCH_JOB:
        from cleanix.cleaners.orphan_launch_jobs import OrphanLaunchJobReporter

        return OrphanLaunchJobReporter.sysroot
    if kind is RemedyKind.SYSTEMD_UNIT:
        from cleanix.cleaners.stale_services import StaleSystemdUnitReporter

        return StaleSystemdUnitReporter.sysroot
    from cleanix.cleaners.stale_receipts import StaleReceiptReporter

    return StaleReceiptReporter.sysroot


def _real(kind: RemedyKind, logical: str) -> str:
    from cleanix.cleaners import orphan_common as oc

    return str(oc.in_root(_sysroot(kind), logical))


def _bad_chars(text: str) -> bool:
    return any(c in text for c in ("\n", "\r", "\0"))


def _name_problem(kind: RemedyKind, name: str, base: str) -> Optional[str]:
    if _bad_chars(base):
        return BAD_NAME
    if kind is RemedyKind.LAUNCH_JOB:
        if base.startswith(remedy_exec.APPLE_PREFIX) or name.startswith(remedy_exec.APPLE_PREFIX):
            return APPLE
        if not remedy_exec.valid_system_label(name):
            return BAD_NAME
        if not base.endswith(".plist") or len(base) <= len(".plist"):
            return BAD_NAME
        return None
    if kind is RemedyKind.SYSTEMD_UNIT:
        if not remedy_exec.valid_unit(name) or base != name:
            return BAD_NAME
        return None
    if name.startswith(remedy_exec.APPLE_PREFIX):
        return APPLE
    if not remedy_exec.valid_pkg_id(name) or base != f"{name}.plist":
        return BAD_NAME
    return None


def bom_path(path: str, pkg_id: str) -> str:
    return os.path.join(os.path.dirname(path), f"{pkg_id}.bom")


def _bom_problem(bom: str) -> Optional[str]:
    """The ``.bom`` next to a receipt: absent, or a plain regular file."""
    try:
        st = os.lstat(bom)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return f"{CHANGED} (the receipt's .bom cannot be inspected)"
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return BAD_BOM
    return None


def check(item: "CleanableItem", config: "Config") -> Tuple[Optional[str], Optional[str]]:
    """``(reason, None)`` when the system-wide ``item`` must be skipped,
    else ``(None, name)`` (the label / unit / package id every command
    uses). Structural only -- the detector's evidence is re-checked by
    ``reverify`` and the file's owner/mode/ACL and parent chain by the
    helper. Fail closed, in order: a system kind of a ``requires_root``
    PATH item without a group; the kind's own scenario and platform; the
    remedy data is exactly its one name; the name is valid (never Apple's,
    no option look, separators or control characters; a unit equals its
    file name, a receipt plist is ``<id>.plist``); the file lies DIRECTLY in
    one of its kind's folders (exact spelling); it is not a link and still
    the regular file fingerprinted at scan time (never the zero
    placeholder); a receipt's ``.bom`` is absent or a plain file; and the
    deletion guard allows it."""
    from cleanix.core.models import ItemKind

    remedy = item.remedy
    if remedy is None or remedy.kind not in SYSTEM_KINDS:
        return NOT_HANDLED, None
    kind = remedy.kind
    if (item.kind is not ItemKind.PATH or not item.path or remedy.group
            or not item.requires_root):
        return NOT_HANDLED, None
    if item.cleaner_id != SCENARIO[kind]:
        return WRONG_SCENARIO, None
    if plat.current_os() != PLATFORM[kind]:
        return WRONG_PLATFORM, None
    extra = tuple(remedy.extra)
    if (len(extra) != 1 or len(extra[0]) != 2 or extra[0][0] != KEY[kind]
            or not isinstance(extra[0][1], str)):
        return BAD_DATA, None
    name = extra[0][1]
    path = item.path
    if (not isinstance(path, str) or _bad_chars(path) or not os.path.isabs(path)
            or os.path.normpath(path) != path):
        return NOT_IN_PLACE, None
    base = os.path.basename(path)
    why = _name_problem(kind, name, base)
    if why is not None:
        return why, None
    parent = os.path.dirname(path)
    allowed = {os.path.normpath(_real(kind, d)) for d in kind_dirs()[kind]}
    if parent not in allowed:
        return NOT_IN_PLACE, None
    if os.path.islink(path):
        return IS_LINK, None
    why = verify_path(path, remedy.fingerprint, allow_dir=False)
    if why is not None:
        return why, None
    if kind is RemedyKind.PKG_RECEIPT:
        why = _bom_problem(bom_path(path, name))
        if why is not None:
            return why, None
    try:
        safe = safety.is_safe_to_delete(path)
    except Exception:  # noqa: BLE001 - an undecidable guard is a refusal
        safe = False
    if not safe:
        return BLOCKED, None
    return None, name


def backup_paths(kind: RemedyKind, path: str, name: str) -> List[str]:
    """Every file to copy before acting: the job/unit file; for a receipt
    its plist and (if present) its ``.bom``."""
    paths = [path]
    if kind is RemedyKind.PKG_RECEIPT:
        bom = bom_path(path, name)
        if os.path.lexists(bom):
            paths.append(bom)
    return paths


def is_agent(path: str) -> bool:
    """A plist directly in ``/Library/LaunchAgents`` (not stopped here)."""
    return os.path.dirname(path) == os.path.normpath(_real(RemedyKind.LAUNCH_JOB, LAUNCH_AGENTS))


def _unit_elsewhere(name: str) -> Optional[str]:
    """Why ``disable`` by name could hit another unit file: a unit of this
    name (or, for an instance, its template) exists in another folder of
    the system unit search path, or one cannot be checked. None when clear."""
    from cleanix.cleaners import stale_services

    mine = os.path.normpath(_real(RemedyKind.SYSTEMD_UNIT, UNIT_DIR))
    names = [name]
    stem, _dot, typ = name.rpartition(".")
    if "@" in stem and not remedy_exec.is_template(name):
        names.append(f"{stem.split('@', 1)[0]}@.{typ}")
    for logical in stale_services._SYSTEM_LOOKUP:
        d = os.path.normpath(_real(RemedyKind.SYSTEMD_UNIT, logical))
        if d == mine:
            continue
        for n in names:
            other = os.path.join(d, n)
            try:
                os.lstat(other)
            except (FileNotFoundError, NotADirectoryError):
                continue
            except OSError:
                return f"could not check {d} for another unit named {n}; not disabled"
            return f"another unit file with this name exists ({other}); not disabled"
    return None


def unload(kind: RemedyKind, name: str, path: str) -> Stop:
    """Stop/disable the job best effort (system scope); never raises."""
    try:
        soft: Sequence[int] = ()
        if kind is RemedyKind.LAUNCH_JOB:
            if is_agent(path):
                return Stop(warnings=[AGENT_NOT_STOPPED])
            argv = remedy_exec.system_bootout_argv(name)
            dirs = [Path(_real(kind, d)) for d in LABEL_DIRS]
            clash = remedy_exec._label_elsewhere(path, name, dirs)
            soft = remedy_exec._NOT_LOADED_RC
        elif kind is RemedyKind.SYSTEMD_UNIT:
            argv = remedy_exec.system_disable_argv(name)
            clash = _unit_elsewhere(name)
        else:
            return Stop(warnings=[f"no stop command for {kind}"])
    except Exception as exc:  # noqa: BLE001
        return Stop(warnings=[f"the job was not stopped ({str(exc) or type(exc).__name__})"])
    if clash is not None:
        return Stop(warnings=[clash])
    return remedy_exec._step(argv, soft, scope=SYSTEM)


def reload_units() -> List[str]:
    """``systemctl daemon-reload`` (system manager) once; warnings."""
    return remedy_exec._step(remedy_exec.system_daemon_reload_argv(), scope=SYSTEM).warnings


def _size(path: str) -> int:
    try:
        return os.lstat(path).st_size
    except (OSError, ValueError):
        return 0


def forget(pkg_id: str, path: str) -> Tuple[bool, int, Optional[str]]:
    """``pkgutil --forget <id>``, then confirm the receipt is gone: neither
    its plist nor its ``.bom`` exists any more. ``(removed, freed, error)``
    for the Engine (never raises)."""
    try:
        files = [path, bom_path(path, pkg_id)]
        size = sum(_size(p) for p in files)
        argv = remedy_exec.forget_argv(pkg_id)
    except Exception as exc:  # noqa: BLE001
        return False, 0, f"not removed: {str(exc) or type(exc).__name__}"
    rc, out, err = remedy_exec.run_mutating(argv, scope=SYSTEM)
    left = []
    for p in files:
        try:
            os.lstat(p)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except (OSError, ValueError):
            return False, 0, ("not removed: whether the install record is gone could "
                              f"not be confirmed ({p} cannot be inspected)")
        left.append(p)
    if rc != 0:
        detail = {124: "timed out", 126: "refused", 127: "command not found"}.get(rc, f"exit {rc}")
        why = remedy_exec._clip(err) or remedy_exec._clip(out)
        if left:
            return False, 0, (f"not removed: pkgutil --forget failed ({detail}"
                              f"{': ' + why if why else ''})")
    if left:
        return False, 0, ("not removed: pkgutil --forget reported success, but the "
                          f"install record is still there ({', '.join(left)})")
    return True, size, None


def planned_text(kind: RemedyKind, where: object) -> str:
    """What acting on a system-wide job / unit / receipt does."""
    if kind is RemedyKind.PKG_RECEIPT:
        return (f"permanent: the install record is forgotten (pkgutil --forget; a copy "
                f"of its files is kept in {where} for manual recovery)")
    return remedy_exec.planned_text(where)


def note(kind: RemedyKind, where: object, stop: Optional[Stop], removed: bool,
         extra_warnings: Sequence[str] = ()) -> str:
    """The result text (``CleanOutcome.note``) of one system-wide item."""
    if kind is RemedyKind.PKG_RECEIPT:
        if removed:
            return planned_text(kind, where)
        return f"the install record was not forgotten (a copy of its files is kept in {where})"
    stop = stop if stop is not None else Stop(stopped=False)
    if removed:
        return remedy_exec.permanent_note(where, stop, extra_warnings)
    text = ("the job was stopped, but its file was not removed" if stop.stopped
            else "its file was not removed")
    warnings = list(stop.warnings) + list(extra_warnings)
    if warnings:
        text += "; warning: " + "; ".join(warnings)
    return text
