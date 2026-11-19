"""User-level non-path remedies: launch agents and systemd user units.

A ``LAUNCH_JOB`` finding (a plist directly in ``~/Library/LaunchAgents``) or a
``SYSTEMD_UNIT`` finding (a ``.service`` file directly in
``~/.config/systemd/user``) is acted on by :func:`cleanix.core.actions.act`:

1. :func:`check` re-verifies it (fail closed; see there), up front and again
   right before the file is removed;
2. :func:`unload` stops it best effort: ``launchctl bootout gui/<uid>/<label>``
   or ``systemctl --user disable --now <unit>``;
3. the Engine moves the file into the batch's quarantine run (or, for a
   permanent run, deletes it after ``actions`` kept a copy), and once per
   batch :func:`reload_units` runs ``systemctl --user daemon-reload``.

These removals are presented as permanent: a copy of the file is kept for
manual recovery, but nothing re-loads the job.

Commands are built only from validated components, as argv lists (never a
shell string), checked against :data:`MUTATING_COMMANDS` -- a separate
allowlist from ``orphan_common.READ_ONLY_COMMANDS``, which stays read-only and
refuses every shape here -- and run through the single injectable
:data:`runner` (tests replace it; nothing else here starts a process). A
failing, missing or timed-out command never raises: it becomes a warning.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Callable, List, Optional, Sequence, Tuple

from cleanix.core import safety
from cleanix.core.remedy import CHANGED, RemedyKind, verify_path
from cleanix.core.utils import run_command

if TYPE_CHECKING:  # pragma: no cover
    from cleanix.config import Config
    from cleanix.core.models import CleanableItem

KINDS = frozenset({RemedyKind.LAUNCH_JOB, RemedyKind.SYSTEMD_UNIT})
COMMAND_TIMEOUT = 30  # seconds per command

# The mutating command shapes (verb prefixes). The operands are checked by
# :func:`argv_allowed`; nothing outside these shapes is ever run from here.
MUTATING_COMMANDS: frozenset = frozenset(
    {
        ("launchctl", "bootout"),
        ("systemctl", "--user", "disable", "--now"),
        ("systemctl", "--user", "daemon-reload"),
    }
)

Runner = Callable[[Sequence[str], int], Tuple[int, str, str]]

_NO_FINGERPRINT = (0, 0, 0, 0)
_REPARSE = 0x400
_SERVICE_TARGET = re.compile(r"gui/(0|[1-9][0-9]{0,9})/(.+)")

NOT_IN_PLACE = "not directly inside {where}; refused"
BAD_NAME = "the job's name is not a plain label/unit name; refused"
BAD_DATA = "unexpected remedy data; refused"
EVIDENCE_GONE = ("the detector no longer reports it as stale (program present, "
                 "file changed or cannot be judged); nothing removed")
NOT_OWNED = "not owned by your account; refused"
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
    """``systemctl --user disable --now <unit>``."""
    if not valid_unit(unit):
        raise ValueError("invalid systemd unit name")
    return ["systemctl", "--user", "disable", "--now", unit]


def daemon_reload_argv() -> List[str]:
    return ["systemctl", "--user", "daemon-reload"]


def argv_allowed(argv: object) -> bool:
    """True only for exactly one of the fixed shapes with valid operands."""
    if isinstance(argv, (str, bytes)):
        return False
    try:
        a = tuple(argv)  # type: ignore[arg-type]
    except TypeError:
        return False
    if not all(isinstance(x, str) for x in a):
        return False
    if a == ("systemctl", "--user", "daemon-reload"):
        return True
    if len(a) == 5 and a[:4] == ("systemctl", "--user", "disable", "--now"):
        return valid_unit(a[4])
    if len(a) == 3 and a[:2] == ("launchctl", "bootout"):
        m = _SERVICE_TARGET.fullmatch(a[2])
        return bool(m) and valid_label(m.group(2))
    return False


def default_runner(argv: Sequence[str], timeout: int) -> Tuple[int, str, str]:
    """Run under the C locale (as ``orphan_common.run``), argv list, timeout."""
    return run_command(["env", "LC_ALL=C", *argv], timeout)


# The one injection point for running a command (tests replace it).
runner: Runner = default_runner


def run_mutating(argv: Sequence[str], timeout: int = COMMAND_TIMEOUT) -> Tuple[int, str, str]:
    """Run an allowlisted mutating command; refused shapes give rc 126 and
    are never passed on. Never raises (an exception is rc 125)."""
    if not argv_allowed(argv):
        return 126, "", "refused"
    try:
        return runner(list(argv), timeout)
    except Exception as exc:  # noqa: BLE001 - best effort, never raise after a side effect
        return 125, "", str(exc) or type(exc).__name__


def _clip(text: str) -> str:
    from cleanix.cleaners.orphan_common import safe_label

    line = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")
    return safe_label(line)[:160]


def _step(argv: List[str]) -> List[str]:
    """Run one best-effort step; [] on success, else one warning line."""
    rc, out, err = run_mutating(argv)
    if rc == 0:
        return []
    detail = {
        124: "timed out",
        126: "refused",
        127: "command not found",
    }.get(rc, f"exit {rc}")
    why = _clip(err) or _clip(out)
    return [f"{' '.join(argv)} failed ({detail}{': ' + why if why else ''})"]


def _uid() -> Optional[int]:
    """The account the command acts for (indirection: tests pin it)."""
    getuid = getattr(os, "getuid", None)
    return getuid() if getuid is not None else None


def unload(kind: RemedyKind, name: str) -> List[str]:
    """Stop/disable the job best effort; returns warnings, never raises."""
    try:
        if kind is RemedyKind.LAUNCH_JOB:
            uid = _uid()
            if uid is None:
                return ["launchctl bootout was not run (user id unknown)"]
            argv = bootout_argv(uid, name)
        elif kind is RemedyKind.SYSTEMD_UNIT:
            argv = disable_argv(name)
        else:
            return [f"no stop command for {kind}"]
    except Exception as exc:  # noqa: BLE001
        return [f"the job was not stopped ({str(exc) or type(exc).__name__})"]
    return _step(argv)


def reload_units() -> List[str]:
    """``systemctl --user daemon-reload`` once; warnings, never raises."""
    return _step(daemon_reload_argv())


def permanent_note(where: object, warnings: Sequence[str] = ()) -> str:
    """The result text for a removed launch job / unit file."""
    text = f"permanent (a copy of the file is kept in {where})"
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
        return where + " (a folder on the way is a link)"
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
    """POSIX: the file must belong to the account the command acts for."""
    if os.name == "nt":
        return None
    uid = _uid()
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
    the file name); the file is directly in its kind's user folder (no link
    on the way); it is a regular file unchanged since the scan (with the
    ``(0, 0, 0, 0)`` placeholder: a regular file, vouched for by the
    re-parse below); on POSIX it is owned by this account; the detector's
    own check, re-run on this file, still reports it with the same name
    (program still missing; the plist's own Label key, not the caller's
    claim); and the deletion guard allows it.
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
