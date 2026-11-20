"""User-level non-path remedies: launch agents and systemd user units.

A ``LAUNCH_JOB`` finding (a plist directly in ``~/Library/LaunchAgents``) or a
``SYSTEMD_UNIT`` finding (a ``.service`` file directly in
``~/.config/systemd/user``) is acted on by :func:`cleanix.core.actions.act`,
always permanently (never as an Undo-able quarantine move):

1. :func:`check` re-verifies it (fail closed; see there), up front and again
   right before the file is removed;
2. ``actions`` keeps a copy of the file in a copy-only backup run
   (``Quarantine.store_copy``; restore never acts on it);
3. :func:`unload` stops it best effort: ``launchctl bootout gui/<uid>/<label>``
   or ``systemctl --user disable [--now] <unit>`` -- unless another job file
   declares the same label / another unit file has the same name, which a
   stop by name would hit instead;
4. the Engine deletes the file, and once per batch :func:`reload_units` runs
   ``systemctl --user daemon-reload``.

Commands are built only from validated components, as argv lists (never a
shell string), checked against :data:`MUTATING_COMMANDS` -- a separate
allowlist from ``orphan_common.READ_ONLY_COMMANDS``, which stays read-only and
refuses every shape here -- and run through the single injectable
:data:`runner` (tests replace it; nothing else here starts a process). The
default runner uses fixed absolute tool paths where they exist, the C locale
and no stdin. A failing, missing or timed-out command never raises: it
becomes a warning.

System scope (Task 9b; the elevated helper's findings action only, see
:mod:`cleanix.core.system_remedy`): ``systemctl disable [--now] <unit>``,
``systemctl daemon-reload`` (no ``--user``) and ``pkgutil --forget <id>``.
There is deliberately NO system-domain ``launchctl bootout``: a stale
system job's program is missing, so it cannot be running from that plist,
and a bootout by label could stop a live job loaded from elsewhere. These shapes are a scope of their
own (:data:`SYSTEM_MUTATING_COMMANDS`, :func:`system_argv_allowed`): they
are run only by ``run_mutating(..., scope=SYSTEM)`` and only while
:func:`system_scope` is active inside helper scan mode (``actions.act``
root mode in the helper). An ordinary (unprivileged) call path -- the
default user scope -- refuses every one of them, and the user-scope shapes
are refused in system scope. System-scope tools are run only from their
fixed absolute paths (never looked up on ``PATH``).
"""

from __future__ import annotations

import contextlib
import contextvars
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterator, List, Optional, Sequence, Tuple

from cleanix.core import safety
from cleanix.core.remedy import CHANGED, RemedyKind, verify_path
from cleanix.core.utils import which

if TYPE_CHECKING:  # pragma: no cover
    from cleanix.config import Config
    from cleanix.core.models import CleanableItem

KINDS = frozenset({RemedyKind.LAUNCH_JOB, RemedyKind.SYSTEMD_UNIT})
# Kinds the elevated helper acts on system-wide (Task 9b; system_remedy).
SYSTEM_KINDS = frozenset({RemedyKind.LAUNCH_JOB, RemedyKind.SYSTEMD_UNIT,
                          RemedyKind.PKG_RECEIPT})
COMMAND_TIMEOUT = 30  # seconds per command
MAX_LABEL_SCAN = 10000  # plists read when looking for another job's label

USER = "user"
SYSTEM = "system"

# The mutating command shapes of the user scope (verb prefixes). The
# operands are checked by :func:`argv_allowed`.
USER_MUTATING_COMMANDS: frozenset = frozenset(
    {
        ("launchctl", "bootout"),  # gui/<uid>/<label> only
        ("systemctl", "--user", "disable", "--now"),
        ("systemctl", "--user", "disable"),  # template units only (no --now)
        ("systemctl", "--user", "daemon-reload"),
    }
)
# The system scope (elevated helper only); operands checked by
# :func:`system_argv_allowed`.
SYSTEM_MUTATING_COMMANDS: frozenset = frozenset(
    {
        ("systemctl", "disable", "--now"),
        ("systemctl", "disable"),  # template units only (no --now)
        ("systemctl", "daemon-reload"),
        ("pkgutil", "--forget"),
    }
)
# Every mutating shape; nothing outside them is ever run from here.
MUTATING_COMMANDS: frozenset = USER_MUTATING_COMMANDS | SYSTEM_MUTATING_COMMANDS

# Where the tools live; ``which`` is asked only when none of these exists
# (user scope only: system-scope commands use these fixed paths or nothing).
_TOOL_PATHS = {
    "env": ("/usr/bin/env", "/bin/env"),
    "launchctl": ("/bin/launchctl",),
    "systemctl": ("/usr/bin/systemctl", "/bin/systemctl"),
    "pkgutil": ("/usr/sbin/pkgutil",),
}

Runner = Callable[[Sequence[str], int], Tuple[int, str, str]]

_NO_FINGERPRINT = (0, 0, 0, 0)
_REPARSE = 0x400
_SERVICE_TARGET = re.compile(r"gui/(0|[1-9][0-9]{0,9})/(.+)")
# A package receipt id usable in ``pkgutil --forget`` (stricter than a label:
# pkgutil ids are reverse-DNS names).
_PKG_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}")
APPLE_PREFIX = "com.apple."


def is_apple(name: object) -> bool:
    """``com.apple.*`` in any letter case (case-insensitive volumes)."""
    return isinstance(name, str) and name.casefold().startswith(APPLE_PREFIX)
# launchctl bootout exit codes taken to mean "no such process" / "could not
# find service": the job simply was not loaded (a note, not a warning).
# UNVERIFIED on a real Mac.
_NOT_LOADED_RC = (3, 113)

NOT_IN_PLACE = "not directly inside {where}; refused"
LINK_ON_THE_WAY = ("a folder on the way is a link; move/replace it with a real "
                   "folder or act manually")
BAD_NAME = "the job's name is not a plain label/unit name; refused"
APPLE_JOB = "an Apple job (com.apple.*); never touched"
BAD_DATA = "unexpected remedy data; refused"
EVIDENCE_GONE = ("the detector no longer reports it as stale (program present, "
                 "file changed or cannot be judged); nothing removed")
NOT_OWNED = "not owned by your account; refused"
AS_ROOT = "run without sudo; this acts only on your own account's jobs"
IS_LINK = "a link, not a job file; not handled here (remove the link by hand)"
BLOCKED = "blocked by safety guard (protected path)"


# ------------------------------------------------------------------ names
def _ident(name: object) -> bool:
    from cleanix.cleaners.orphan_common import valid_ident

    return isinstance(name, str) and valid_ident(name)


def valid_label(label: object) -> bool:
    """A launchd label usable in a command (no option look, no separators)."""
    return _ident(label)


def valid_unit(unit: object) -> bool:
    """A systemd ``.service`` unit name usable in a command."""
    return _ident(unit) and str(unit).endswith(".service") and len(str(unit)) > len(".service")


def is_template(unit: str) -> bool:
    """``foo@.service``: a template, which cannot be started/stopped itself."""
    return unit.endswith("@.service")


def valid_system_label(label: object) -> bool:
    """A plain launchd label of a system-wide job, never Apple's (in any
    case). No command is ever built from it (no system-domain bootout)."""
    return valid_label(label) and not is_apple(label)


def valid_pkg_id(pkg_id: object) -> bool:
    """A package receipt id usable in ``pkgutil --forget``: a plain
    reverse-DNS name (letters, digits, ``. _ + -``; no leading ``-``, no
    ``..``, no separators, whitespace or control characters), never
    Apple's."""
    return (isinstance(pkg_id, str) and bool(_PKG_ID.fullmatch(pkg_id))
            and _ident(pkg_id) and not is_apple(pkg_id))


# --------------------------------------------------------------- commands
def bootout_argv(uid: int, label: str) -> List[str]:
    """``launchctl bootout gui/<uid>/<label>`` (the service-target form: a
    bare label after a domain target would be read as a plist path)."""
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise ValueError("invalid user id")
    if not valid_label(label):
        raise ValueError("invalid launchd label")
    return ["launchctl", "bootout", f"gui/{uid}/{label}"]


def disable_argv(unit: str) -> List[str]:
    """``systemctl --user disable --now <unit>`` (no ``--now`` for a
    template unit, which has nothing to stop)."""
    if not valid_unit(unit):
        raise ValueError("invalid systemd unit name")
    if is_template(unit):
        return ["systemctl", "--user", "disable", unit]
    return ["systemctl", "--user", "disable", "--now", unit]


def daemon_reload_argv() -> List[str]:
    return ["systemctl", "--user", "daemon-reload"]


def system_disable_argv(unit: str) -> List[str]:
    """``systemctl disable --now <unit>`` (system manager: no ``--user``;
    no ``--now`` for a template unit)."""
    if not valid_unit(unit):
        raise ValueError("invalid systemd unit name")
    if is_template(unit):
        return ["systemctl", "disable", unit]
    return ["systemctl", "disable", "--now", unit]


def system_daemon_reload_argv() -> List[str]:
    return ["systemctl", "daemon-reload"]


def forget_argv(pkg_id: str) -> List[str]:
    """``pkgutil --forget <id>``."""
    if not valid_pkg_id(pkg_id):
        raise ValueError("invalid package id")
    return ["pkgutil", "--forget", pkg_id]


def _as_argv(argv: object) -> Optional[Tuple[str, ...]]:
    if isinstance(argv, (str, bytes)):
        return None
    try:
        a = tuple(argv)  # type: ignore[arg-type]
    except TypeError:
        return None
    if not all(isinstance(x, str) for x in a):
        return None
    return a


def system_argv_allowed(argv: object) -> bool:
    """True only for exactly one of the fixed SYSTEM-scope shapes with valid
    operands (see :data:`SYSTEM_MUTATING_COMMANDS`)."""
    a = _as_argv(argv)
    if a is None:
        return False
    if a == ("systemctl", "daemon-reload"):
        return True
    if len(a) == 4 and a[:3] == ("systemctl", "disable", "--now"):
        return valid_unit(a[3]) and not is_template(a[3])
    if len(a) == 3 and a[:2] == ("systemctl", "disable"):
        return valid_unit(a[2]) and is_template(a[2])
    if len(a) == 3 and a[:2] == ("pkgutil", "--forget"):
        return valid_pkg_id(a[2])
    return False


# Set (True) only by :func:`system_scope`, i.e. by ``actions.act`` in the
# elevated helper's root mode; context-local, so no other thread or call
# path sees it.
_system_scope: "contextvars.ContextVar[bool]" = contextvars.ContextVar(
    "cleanix_system_scope", default=False)


@contextlib.contextmanager
def system_scope() -> Iterator[None]:
    """Open the system scope for the current context (helper root mode
    only; still refused outside helper scan mode)."""
    token = _system_scope.set(True)
    try:
        yield
    finally:
        _system_scope.reset(token)


def system_scope_open() -> bool:
    """Both gates of the system scope: :func:`system_scope` is active AND
    this is the elevated helper (``scanmode`` helper mode)."""
    from cleanix.core import scanmode

    return bool(_system_scope.get()) and scanmode.is_helper_mode()


def argv_allowed(argv: object) -> bool:
    """True only for exactly one of the fixed USER-scope shapes with valid
    operands."""
    a = _as_argv(argv)
    if a is None:
        return False
    if a == ("systemctl", "--user", "daemon-reload"):
        return True
    if len(a) == 5 and a[:4] == ("systemctl", "--user", "disable", "--now"):
        return valid_unit(a[4]) and not is_template(a[4])
    if len(a) == 4 and a[:3] == ("systemctl", "--user", "disable"):
        return valid_unit(a[3]) and is_template(a[3])
    if len(a) == 3 and a[:2] == ("launchctl", "bootout"):
        m = _SERVICE_TARGET.fullmatch(a[2])
        return bool(m) and valid_label(m.group(2))
    return False


def _resolve(name: str, fixed_only: bool = False) -> Optional[str]:
    """The tool's fixed absolute path, else (user scope only) ``which``
    (None: not installed)."""
    for p in _TOOL_PATHS.get(name, ()):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    if fixed_only:
        return None
    return which(name)


def _spawn(argv: List[str], timeout: int) -> Tuple[int, str, str]:
    """Start one process: argv list, no shell, no stdin, a timeout."""
    try:
        proc = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except FileNotFoundError:
        return 127, "", f"command not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "command timed out"
    out = (proc.stdout or b"").decode("utf-8", "replace")
    err = (proc.stderr or b"").decode("utf-8", "replace")
    return proc.returncode, out, err


def default_runner(argv: Sequence[str], timeout: int) -> Tuple[int, str, str]:
    """Run under the C locale (as ``orphan_common.run``) with the tools at
    fixed absolute paths where they exist (system-scope shapes: ONLY there,
    never looked up on ``PATH``)."""
    fixed = system_argv_allowed(argv)
    env = _resolve("env", fixed_only=fixed)
    tool = _resolve(argv[0], fixed_only=fixed) if argv else None
    if env is None or tool is None:
        return 127, "", f"command not found: {argv[0] if argv else ''}"
    return _spawn([env, "LC_ALL=C", tool, *argv[1:]], timeout)


# The one injection point for running a command (tests replace it).
runner: Runner = default_runner


def run_mutating(argv: Sequence[str], timeout: int = COMMAND_TIMEOUT, *,
                 scope: str = USER) -> Tuple[int, str, str]:
    """Run an allowlisted mutating command; refused shapes give rc 126 and
    are never passed on. Never raises (an exception is rc 125).

    ``scope`` USER (default): only the user-scope shapes. SYSTEM: only the
    system-scope shapes, and only while :func:`system_scope_open` (the
    elevated helper's root-mode act); anything else is refused."""
    if scope == USER:
        allowed = argv_allowed(argv)
    elif scope == SYSTEM:
        allowed = system_argv_allowed(argv) and system_scope_open()
    else:
        allowed = False
    if not allowed:
        return 126, "", "refused"
    try:
        return runner(list(argv), timeout)
    except Exception as exc:  # noqa: BLE001 - best effort, never raise after a side effect
        return 125, "", str(exc) or type(exc).__name__


def _clip(text: str) -> str:
    from cleanix.cleaners.orphan_common import safe_label

    line = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")
    return safe_label(line)[:160]


class Stop:
    """What a stop attempt did: ``stopped`` (the command succeeded),
    ``warnings`` (something to look at) and ``info`` (harmless facts)."""

    def __init__(self, stopped: bool = False, warnings: Sequence[str] = (),
                 info: Sequence[str] = ()):
        self.stopped = stopped
        self.warnings = list(warnings)
        self.info = list(info)


def _step(argv: List[str], soft: Sequence[int] = (), scope: str = USER) -> Stop:
    """Run one best-effort step."""
    rc, out, err = run_mutating(argv, scope=scope)
    if rc == 0:
        return Stop(stopped=True)
    if rc in soft:
        return Stop(info=["the job was not loaded"])
    detail = {
        124: "timed out",
        126: "refused",
        127: "command not found",
    }.get(rc, f"exit {rc}")
    why = _clip(err) or _clip(out)
    return Stop(warnings=[f"{' '.join(argv)} failed ({detail}{': ' + why if why else ''})"])


def _uid() -> Optional[int]:
    """The account the command acts for (indirection: tests pin it)."""
    getuid = getattr(os, "getuid", None)
    return getuid() if getuid is not None else None


def _same(a: object, b: object) -> bool:
    return os.path.normcase(os.path.abspath(str(a))) == os.path.normcase(os.path.abspath(str(b)))


def _label_elsewhere(path: str, label: str) -> Optional[str]:
    """Why ``bootout`` by ``label`` could hit another job: another plist in
    the user's, the local or the system LaunchAgents declares the same
    Label (or a folder/plist there cannot be read). None when clear."""
    from cleanix.cleaners import orphan_common as oc
    from cleanix.cleaners.orphan_launch_jobs import OrphanLaunchJobReporter

    load = OrphanLaunchJobReporter._load  # size-capped; uses no instance state
    root = OrphanLaunchJobReporter.sysroot
    dirs = [expected_dir(RemedyKind.LAUNCH_JOB),
            oc.in_root(root, "/Library/LaunchAgents"),
            oc.in_root(root, "/System/Library/LaunchAgents")]
    seen = 0
    for d in dirs:
        children = oc.list_dir(d)
        if children is None:
            return f"could not read {d} to rule out another job with this label; not stopped"
        for child in children:
            if child.suffix != ".plist" or _same(child, path):
                continue
            seen += 1
            if seen > MAX_LABEL_SCAN:
                return "too many job files to rule out another job with this label; not stopped"
            if os.path.islink(child) and not os.path.exists(child):
                continue  # a broken link holds no label
            data = load(None, child)  # type: ignore[arg-type]
            if data is None or data == "not a valid property list":
                continue  # launchd cannot load it either
            if isinstance(data, str):
                return (f"could not read {child} to rule out another job with this "
                        "label; not stopped")
            if data.get("Label") == label:
                return f"another job uses this label ({child}); not stopped"
    return None


def _unit_elsewhere(name: str) -> Optional[str]:
    """Why ``disable`` by name could hit another unit file: one with the
    same name exists in another user-unit directory. None when clear."""
    from cleanix.cleaners import stale_services

    mine = expected_dir(RemedyKind.SYSTEMD_UNIT)
    root = stale_services.StaleSystemdUnitReporter.sysroot
    for d in stale_services.user_lookup_dirs(_home(), root):
        if _same(d, mine):
            continue
        other = Path(d) / name
        try:
            os.lstat(other)
        except FileNotFoundError:
            continue
        except OSError:
            return f"could not check {d} for another unit named {name}; not disabled"
        return f"another unit file with this name exists ({other}); not disabled"
    return None


def unload(kind: RemedyKind, name: str, path: str) -> Stop:
    """Stop/disable the job best effort; never raises."""
    try:
        soft: Sequence[int] = ()
        if kind is RemedyKind.LAUNCH_JOB:
            uid = _uid()
            if uid is None:
                return Stop(warnings=["launchctl bootout was not run (user id unknown)"])
            argv = bootout_argv(uid, name)
            clash = _label_elsewhere(path, name)
            soft = _NOT_LOADED_RC
        elif kind is RemedyKind.SYSTEMD_UNIT:
            argv = disable_argv(name)
            clash = _unit_elsewhere(name)
        else:
            return Stop(warnings=[f"no stop command for {kind}"])
    except Exception as exc:  # noqa: BLE001
        return Stop(warnings=[f"the job was not stopped ({str(exc) or type(exc).__name__})"])
    if clash is not None:
        return Stop(warnings=[clash])
    return _step(argv, soft)


def reload_units() -> List[str]:
    """``systemctl --user daemon-reload`` once; warnings, never raises."""
    return _step(daemon_reload_argv()).warnings


def planned_text(where: object) -> str:
    """What acting on a launch job / unit does (preview, prompts, results)."""
    return (f"permanent: the job is stopped and its file removed (a copy of the "
            f"file is kept in {where} for manual recovery)")


def permanent_note(where: object, stop: Optional[Stop] = None,
                   extra_warnings: Sequence[str] = ()) -> str:
    """The result text for a removed launch job / unit file."""
    stop = stop if stop is not None else Stop(stopped=True)
    if stop.stopped:
        text = planned_text(where)
    else:
        text = (f"permanent: its file was removed (a copy of the file is kept "
                f"in {where} for manual recovery)")
    if stop.info:
        text += "; " + "; ".join(stop.info)
    warnings = list(stop.warnings) + list(extra_warnings)
    if warnings:
        text += "; warning: " + "; ".join(warnings)
    return text


# ----------------------------------------------------------- verification
def _home() -> Path:
    from cleanix.core import context

    return Path(context.invoking_user().home)


_REL = {
    RemedyKind.LAUNCH_JOB: ("Library", "LaunchAgents"),
    RemedyKind.SYSTEMD_UNIT: (".config", "systemd", "user"),
}
_KEY = {RemedyKind.LAUNCH_JOB: "label", RemedyKind.SYSTEMD_UNIT: "unit"}


def expected_dir(kind: RemedyKind) -> Path:
    """The only directory a user-level finding of ``kind`` may be in."""
    return _home().joinpath(*_REL[kind])


def _norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(p))


def _placement(path: str, kind: RemedyKind) -> Optional[str]:
    """None when ``path`` is directly inside the expected directory, by
    spelling and on disk: no link between the home folder and that folder
    (a linked LaunchAgents could point anywhere)."""
    expected = os.path.abspath(str(expected_dir(kind)))
    where = NOT_IN_PLACE.format(where=expected)
    parent = os.path.dirname(os.path.abspath(path))
    if _norm(parent) != _norm(expected):
        return where
    home = os.path.abspath(str(_home()))
    real_expected = os.path.realpath(expected)
    if _norm(real_expected) != _norm(os.path.join(os.path.realpath(home), *_REL[kind])):
        return f"{expected}: {LINK_ON_THE_WAY}"
    if _norm(os.path.realpath(parent)) != _norm(real_expected):
        return where
    return None


def _identity(path: str, fingerprint: object) -> Optional[str]:
    """The file is still the regular file seen at scan time."""
    try:
        fp = tuple(int(x) for x in fingerprint)  # type: ignore[union-attr]
    except (TypeError, ValueError):
        return "no usable fingerprint"
    if len(fp) != 4:
        return "no usable fingerprint"
    if fp != _NO_FINGERPRINT:
        return verify_path(path, fp, allow_dir=False)
    # Placeholder: no identity to compare; the file must at least be a
    # plain file, and the re-parse in _evidence must vouch for it.
    try:
        st = os.lstat(path)
    except (OSError, ValueError):
        return f"{CHANGED} (missing or unreadable)"
    if stat.S_ISLNK(st.st_mode) or (getattr(st, "st_file_attributes", 0) or 0) & _REPARSE:
        return f"{CHANGED} (now a link or reparse point)"
    if not stat.S_ISREG(st.st_mode):
        return f"{CHANGED} (not a regular file)"
    return None


def _owner(path: str) -> Optional[str]:
    """POSIX: the file must belong to the account the command acts for, and
    that account is never root (a sudo run would stop root's jobs)."""
    if os.name == "nt":
        return None
    uid = _uid()
    if uid == 0:
        return AS_ROOT
    try:
        st = os.lstat(path)
    except OSError:
        return f"{CHANGED} (missing or unreadable)"
    if uid is None or st.st_uid != uid:
        return NOT_OWNED
    return None


def _evidence(kind: RemedyKind, path: str, config: "Config"):
    """The detector's own verdict for this one file (a Finding or None)."""
    if kind is RemedyKind.LAUNCH_JOB:
        from cleanix.cleaners.orphan_launch_jobs import OrphanLaunchJobReporter

        return OrphanLaunchJobReporter(config)._check(Path(path), system=False)
    from cleanix.cleaners import stale_services

    rep = stale_services.StaleSystemdUnitReporter(config)
    lookup = stale_services.user_lookup_dirs(_home(), rep.sysroot)
    return next(iter(rep._check_unit(Path(path), lookup, user=True)), None)


def check(item: "CleanableItem", config: "Config") -> Tuple[Optional[str], Optional[str]]:
    """``(reason, None)`` when ``item`` must be skipped, else ``(None, name)``
    with the label/unit name re-derived from the file itself, which is the
    only name a command may use.

    Fail closed, in order: kind matches the item; remedy data is exactly
    the one name, and that name is valid (no leading ``-``, separators,
    whitespace or control characters; units end in ``.service`` and equal
    the file name); never an Apple job (``com.apple.*`` file or label, as
    the scan refuses); the file is directly in its kind's user folder (no
    link on the way); it is a regular file unchanged since the scan (with
    the ``(0, 0, 0, 0)`` placeholder: a regular file, vouched for by the
    re-parse below); on POSIX it is owned by this (non-root) account; the
    detector's own check, re-run on this file, still reports it with the
    same name (program still missing; the plist's own Label key, not the
    caller's claim); and the deletion guard allows it.
    """
    from cleanix.core.models import ItemKind

    remedy = item.remedy
    if remedy is None or remedy.kind not in KINDS:
        return "this kind of finding is not handled here", None
    kind = remedy.kind
    if item.kind is not ItemKind.PATH or not item.path or remedy.group:
        return "this kind of finding is not handled here", None
    path = item.path
    key = _KEY[kind]
    extra = tuple(remedy.extra)
    if len(extra) != 1 or len(extra[0]) != 2 or extra[0][0] != key:
        return BAD_DATA, None
    name = extra[0][1]
    base = os.path.basename(path)
    if kind is RemedyKind.LAUNCH_JOB:
        if (not valid_label(name) or not base.endswith(".plist")
                or any(c in base for c in ("\n", "\r", "\0"))):
            return BAD_NAME, None
        if base.startswith("com.apple.") or name.startswith("com.apple."):
            return APPLE_JOB, None
    elif not valid_unit(name) or base != name:
        return BAD_NAME, None
    why = _placement(path, kind)
    if why is not None:
        return why, None
    if os.path.islink(path):
        # e.g. a broken job link the detector reports: there is no job file
        # to stop or copy here (only a plain file is ever acted on).
        return IS_LINK, None
    why = _identity(path, remedy.fingerprint)
    if why is not None:
        return why, None
    why = _owner(path)
    if why is not None:
        return why, None
    fresh = _evidence(kind, path, config)
    if (fresh is None or fresh.note or fresh.requires_root
            or fresh.remedy_kind is not kind
            or tuple(fresh.remedy_extra) != ((key, name),)
            or os.path.abspath(str(fresh.path)) != os.path.abspath(path)):
        return EVIDENCE_GONE, None
    try:
        safe = safety.is_safe_to_delete(path)
    except Exception:  # noqa: BLE001 - an undecidable guard is a refusal
        safe = False
    if not safe:
        return BLOCKED, None
    return None, name
