"""The elevated helper: ``python -m cleanix.elevated``.

Runs as root/Administrator (launched by ``cleanix.core.elevate_launch``) and
receives its instructions from a user-writable request file, so it trusts
nothing in it beyond *identifiers*, and nothing in its environment:

1. The environment is BUILT from an allowlist, never inherited (POSIX:
   locale variables plus a fixed PATH; Windows: identity/profile variables
   plus SystemRoot/windir/SystemDrive/ProgramData/ComSpec/TEMP/PATH from the
   Windows API). The launcher also starts Python with ``-I``. Note: the fixed
   POSIX PATH (/usr/sbin:/usr/bin:/sbin:/bin) hides /usr/local/bin and
   /opt/homebrew/bin, so GUI items for tools installed only there (e.g. a
   Homebrew-installed package manager) come back ``unmatched``.
2. The request directory is validated once, up front, and then used by
   descriptor (POSIX): owned by the requesting uid, private, no symlinked
   path components. Request and result live only in that directory.
3. The requesting uid comes from ``--uid``, cross-checked against pkexec's
   ``PKEXEC_UID``; the user name is resolved from the uid, never just taken
   from the request.
4. Only that user's home is in scope (``context.configure(all_users=False)``).
5. Only cleaners on a helper-side ALLOWLIST (``admin_cleaner_ids``: system
   cleaners that can yield root items on this platform, default-enabled or
   explicitly listed, plus ``temp``) are scanned; other requested cleaner ids
   are refused before any scan code runs.
6. A fresh scan is run with built-in DEFAULT settings; from the user's
   config file only ``protected_globs`` is taken (it can only add protection).
7. An item is cleaned only if its key was requested AND it is in the fresh
   scan AND it requires admin rights (relative to the requesting user) AND
   its cleaner is allowlisted AND it is not report-only. Right before each
   PATH item is deleted, every directory from ``/`` to its parent is
   re-checked with lstat: no symlink (Windows: no reparse point), modifiable
   only by root/system accounts, world/group-writable only with the sticky
   bit (``/tmp``, ``/var/tmp``). The safety guard only blocks protected roots
   and their ancestors, so without this a symlink planted in a world-writable
   tree (``/var/tmp/abrt -> /etc``) would turn ``/etc/*`` into items.
   Deletion then goes through the normal engine and its safety guard, one
   item at a time.
8. Nothing is written under the user's home: no quarantine (the request's
   ``use_quarantine`` is ignored), no history, no manifest. The GUI records
   history itself, as the user, from the result.
9. The helper has its own deadline (at most 3300 s, below the launcher's
   3600 s); each COMMAND item's timeout is clamped to the time left when it
   starts, and a watchdog writes the work done so far and ends the process
   ``grace`` seconds after the deadline (never after a completed run).

What the design does and does not protect:
* The nonce only detects stale or mixed-up result files; it provides no
  integrity. A same-user attacker who can edit the request between the
  elevation prompt and the helper reading it can only choose among items the
  helper itself deems eligible (point 7) -- which is why the allowlist,
  root-relative ``requires_root`` and default-only config matter.
* The elevation prompt (UAC / polkit / macOS) does not show what will be
  removed; the GUI's confirmation is the only place the user sees the list.
* Windows: items under ProgramData are always refused in elevated runs
  (e.g. ``WER\\ReportQueue`` grants standard users write/delete, so an empty
  folder there can become a junction between the check and the delete);
  ``win_system_dumps`` is thereby reduced to MEMORY.DMP, Minidump and
  LiveKernelReports. The proper fix is handle-verified deletion
  (``FILE_FLAG_OPEN_REPARSE_POINT`` + ``GetFinalPathNameByHandle``): future work.

Known residuals, accepted for now:
(a) POSIX check-then-delete is path-based: a service account or group that
    owns a trusted parent could swap a component between the check and the
    delete. fd-anchored deletion (openat-style directory descriptors) is the
    proper fix: future work.
(b) Code-location trust: ``-I`` ignores a user-controlled sys.path, but a
    user-writable interpreter or site-packages (a venv in the home, a
    per-user Python) is still user-writable code run as root. A root-owned
    install location plus a launcher check is future work (Plan 2B packaging).
(c) POSIX ACLs are not inspected; only owner, group and mode bits are.
(d) Windows: the result file is written by path, as administrator, into the
    requesting user's directory; a junction swap after validation could
    redirect that fixed-name file write. Handle-based writing is future work.
(e) Windows: ``win_system_temp`` cleans only plain files under
    ``Windows\\Temp`` in elevated runs; directories there (user-creatable,
    swappable for junctions mid-delete) are refused.

Exit codes (126/127 are never used: pkexec reserves them):
0 completed (details in the result file), 1 request unreadable/refused
(nothing deleted), 2 internal error, 3 deadline reached (partial result).
"""

from __future__ import annotations

import argparse
import dataclasses
import functools
import math
import ntpath
import os
import sys
import threading
import time
from pathlib import Path
from typing import FrozenSet, List, Optional, Sequence

from cleanix.core import context, elevate, service
from cleanix.core.models import ItemKind, item_key

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_INTERNAL = 2
EXIT_DEADLINE = 3
_ALLOWED_EXITS = {EXIT_OK, EXIT_REFUSED, EXIT_INTERNAL, EXIT_DEADLINE}

DEFAULT_DEADLINE = 3300.0  # seconds; also the maximum (launcher gives up at 3600)
WATCHDOG_GRACE = 30.0
DEFAULT_COMMAND_TIMEOUT = 120
MAX_CONFIG_BYTES = 1024 * 1024

POSIX_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
# The helper's environment is BUILT from an allowlist, never inherited.
# POSIX: locale only (plus PKEXEC_UID, informational). No HOME/XDG_*: the
# allowlisted cleaners work on absolute system paths and run package-manager
# commands that do not need them; Python falls back to the passwd database.
_POSIX_KEEP = {"LANG", "LANGUAGE", "PKEXEC_UID"}
_POSIX_KEEP_PREFIXES = ("LC_",)
# Windows: identity/profile values only. They point the *protective* home
# context (the user's profile is never deleted); no allowlisted Windows
# cleaner derives a deletion target from them (they use the API values below).
_WIN_KEEP = {"USERNAME", "USERDOMAIN", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
             "LOCALAPPDATA", "APPDATA", "NUMBER_OF_PROCESSORS",
             "PROCESSOR_ARCHITECTURE", "OS",
             # OneDrive roots only ever ADD protection in the safety guard.
             "ONEDRIVE", "ONEDRIVECOMMERCIAL", "ONEDRIVECONSUMER"}
_WIN_PATHEXT = ".COM;.EXE;.BAT;.CMD"

_monotonic = time.monotonic


class Refused(Exception):
    """The request (or its environment) is not acceptable; nothing deleted."""


def _is_posix() -> bool:
    return os.name != "nt"


# --------------------------------------------------------------------------
# trusted environment
# --------------------------------------------------------------------------
def _trusted_environment(source, posix: bool, win_dirs=None) -> dict:
    """The complete environment for the helper (pure; see the keep lists)."""
    env = {}
    if posix:
        for key, value in source.items():
            if key in _POSIX_KEEP or key.startswith(_POSIX_KEEP_PREFIXES):
                env[key] = value
        env["PATH"] = POSIX_PATH
        return env
    windir, sysdir, programdata, programfiles, programfiles_x86 = win_dirs
    drive = ntpath.splitdrive(windir)[0]
    if not drive:
        raise Refused("could not determine the system drive")
    for key, value in source.items():
        if key.upper() in _WIN_KEEP:
            env[key] = value
    temp = ntpath.join(windir, "Temp")
    env.update({
        "SystemRoot": windir, "windir": windir, "SystemDrive": drive,
        "ProgramData": programdata, "ComSpec": ntpath.join(sysdir, "cmd.exe"),
        "ProgramFiles": programfiles, "ProgramFiles(x86)": programfiles_x86,
        "PATHEXT": _WIN_PATHEXT, "TEMP": temp, "TMP": temp,
        "PATH": ";".join([sysdir, windir, ntpath.join(sysdir, "Wbem"),
                          ntpath.join(sysdir, "WindowsPowerShell", "v1.0")]),
    })
    return env


_FOLDERID_PROGRAMDATA = "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97"
_FOLDERID_PROGRAMFILES = "905E63B6-C1BF-494E-B29C-65B732D3D21A"
_FOLDERID_PROGRAMFILESX86 = "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E"


def _known_folder(guid_text: str) -> str:
    """SHGetKnownFolderPath for one KNOWNFOLDERID; raises OSError on failure."""
    import ctypes
    import uuid as _uuid
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                    ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

    guid = GUID()
    ctypes.memmove(ctypes.byref(guid), _uuid.UUID(guid_text).bytes_le, 16)
    fn = ctypes.windll.shell32.SHGetKnownFolderPath
    fn.argtypes = [ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE,
                   ctypes.POINTER(ctypes.c_void_p)]
    fn.restype = ctypes.c_long
    ptr = ctypes.c_void_p()
    hr = fn(ctypes.byref(guid), 0, None, ctypes.byref(ptr))
    try:
        if hr != 0 or not ptr.value:
            raise OSError("known folder lookup failed")
        value = ctypes.wstring_at(ptr.value)
    finally:
        if ptr.value:
            ctypes.windll.ole32.CoTaskMemFree(ptr)
    if not value:
        raise OSError("known folder lookup returned nothing")
    return value


def _win_known_dirs():
    """(Windows dir, System32 dir, ProgramData, Program Files,
    Program Files (x86)) from the Windows API. Raises OSError on failure
    (Program Files (x86) falls back to Program Files on 32-bit Windows)."""
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.windll.kernel32

    def call(fn) -> str:
        size = 32768
        buf = ctypes.create_unicode_buffer(size)
        fn.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        fn.restype = wintypes.UINT
        n = fn(buf, size)
        if n == 0 or n >= size:
            raise OSError("Windows directory lookup failed")
        return buf.value

    windir = call(k32.GetSystemWindowsDirectoryW)
    sysdir = call(k32.GetSystemDirectoryW)
    programdata = _known_folder(_FOLDERID_PROGRAMDATA)
    programfiles = _known_folder(_FOLDERID_PROGRAMFILES)
    try:
        programfiles_x86 = _known_folder(_FOLDERID_PROGRAMFILESX86)
    except OSError:
        programfiles_x86 = programfiles
    if not (windir and sysdir):
        raise OSError("Windows directory lookup returned nothing")
    return windir, sysdir, programdata, programfiles, programfiles_x86


def _sanitize_environment() -> None:
    """Replace the inherited, caller-controllable environment with one built
    from an allowlist (see ``_trusted_environment``)."""
    posix = _is_posix()
    dirs = None
    if not posix:
        try:
            dirs = _win_known_dirs()
        except Exception:  # noqa: BLE001
            raise Refused("could not determine the Windows system directories") from None
    env = _trusted_environment(dict(os.environ), posix, dirs)
    os.environ.clear()
    os.environ.update(env)


# --------------------------------------------------------------------------
# identity, scope, config, allowlist
# --------------------------------------------------------------------------
def _user_for_uid(uid: int) -> Optional[str]:
    """Account name for ``uid`` from the system database (None if unknown)."""
    try:
        import pwd
    except ImportError:
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OverflowError, ValueError):
        return None


def _same_dir(a: Path, b: Path) -> bool:
    def norm(p: Path) -> str:
        return os.path.normcase(os.path.abspath(str(p)))

    return norm(a) == norm(b)


def _check_identity(requested: str, expected_uid: Optional[int]) -> str:
    """The invoking user's name, resolved from the uid where possible."""
    if expected_uid is None:
        if _is_posix():
            raise Refused("the requesting uid is unknown")
        return requested
    name = _user_for_uid(expected_uid)
    if name is None:
        if _is_posix():
            raise Refused("the requesting uid has no account")
        return requested
    if name != requested:
        raise Refused("the request names a different user than the one who launched it")
    return name


def _bind_user(name: str, expected_uid: Optional[int]) -> context.TargetUser:
    """Scope scanning to the invoking user's home only."""
    if _is_posix():
        os.environ["SUDO_USER"] = name
    clear = getattr(context.invoking_user, "cache_clear", None)
    if clear is not None:
        clear()
    context.configure(all_users=False)
    users = context.get_target_users()
    if len(users) != 1:
        raise Refused("could not restrict the scan to a single user")
    if _is_posix() and (users[0].name != name or users[0].uid != expected_uid):
        raise Refused("could not switch to the requesting user")
    return users[0]


# Opt-in (default_enabled=False) cleaners the helper still accepts.
# win_component_store (DISM component-store cleanup) is the main Windows
# administrator action, is useless without elevation, and is only ever run
# when the user ticks it explicitly. It is Windows-only (its platform).
# Deliberately NOT here: memory/swap/memory_macos (drop caches / cycle swap:
# system-wide side effects with nothing to "clean").
EXPLICIT_ADMIN_IDS = frozenset({"win_component_store"})
# Cleaners that are not requires_root as a class but flag individual items
# (other users' entries) as root-only.
PER_ITEM_ROOT_IDS = frozenset({"temp"})


def admin_cleaner_ids() -> FrozenSet[str]:
    """Cleaners the helper may run. A cleaner qualifies only if it:

    * is in the "system" category (or is a per-item-root cleaner: ``temp``),
    * can yield root items at all (class ``requires_root`` or per-item),
    * supports this platform, and only Windows ``win_*`` cleaners on Windows
      (POSIX-path cleaners would resolve /tmp, /var/log to user-creatable
      folders on the current drive there) and no ``win_*`` elsewhere,
    * is enabled by default, unless listed in ``EXPLICIT_ADMIN_IDS``.

    Everything else is a user-level cleaner the GUI runs itself.
    """
    from cleanix.config import Config
    from cleanix.core import catalog, registry
    from cleanix.core import platform as plat

    windows = plat.is_windows()
    ids = set()
    for cls in registry.ALL_CLEANERS:
        cid = cls.id
        if catalog.category_of(cid) != "system" and cid not in PER_ITEM_ROOT_IDS:
            continue
        if not cls.requires_root and cid not in PER_ITEM_ROOT_IDS:
            continue
        if windows != cid.startswith("win_"):
            continue
        try:
            inst = cls(Config())
        except Exception:  # noqa: BLE001
            continue
        if not inst.supported():
            continue
        if not getattr(inst, "default_enabled", True) and cid not in EXPLICIT_ADMIN_IDS:
            continue
        ids.add(cid)
    return frozenset(ids)


# --------------------------------------------------------------------------
# parent-chain trust (the real defence against planted symlinks)
# --------------------------------------------------------------------------
_LOGIN_DEFS = "/etc/login.defs"
_UID_FLOOR_RANGE = (500, 1000)


def _read_uid_min(path: str, default: int) -> int:
    """``UID_MIN`` from a login.defs file, clamped to [500, 1000]."""
    value = default
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "UID_MIN":
                    try:
                        value = int(parts[1], 0)
                    except ValueError:
                        value = default
    except OSError:
        value = default
    lo, hi = _UID_FLOOR_RANGE
    return max(lo, min(hi, value))


@functools.lru_cache(maxsize=1)
def _human_uid_min() -> int:
    """The lowest uid/gid of human accounts (below it: system accounts)."""
    from cleanix.core.platform import MACOS, current_os

    if current_os() == MACOS:
        return 501
    return _read_uid_min(_LOGIN_DEFS, 1000)


def _trusted_owner(st, expected_uid: Optional[int]) -> bool:
    """root, or a system account that is not the requesting user."""
    uid = st.st_uid
    return uid == 0 or (uid < _human_uid_min() and uid != expected_uid)


def _untrusted_group(st, group_ids: Optional[FrozenSet[int]]) -> bool:
    """A group a human may belong to (non-system gid, or one of the
    requesting user's groups). ``group_ids=None`` means the user's groups are
    unknown: every group is untrusted (fail closed)."""
    if group_ids is None:
        return True
    return st.st_gid >= _human_uid_min() or st.st_gid in group_ids


def _component_problem(st, expected_uid: Optional[int],
                       group_ids: Optional[FrozenSet[int]]) -> Optional[str]:
    """Why a directory on an item's parent chain cannot be trusted, or None.

    Trusted: a real directory (not a symlink) that only root/system accounts
    can modify. A world- or group-writable directory is accepted only when it
    has the sticky bit and a trusted owner (``/tmp``, ``/var/tmp``,
    ``/var/crash``): there nobody can rename or replace other users' entries.
    """
    import stat as _stat

    mode = st.st_mode
    if _stat.S_ISLNK(mode):
        return "is a symbolic link"
    if not _stat.S_ISDIR(mode):
        return "is not a directory"
    if not _trusted_owner(st, expected_uid):
        return "is owned by a non-system user"
    sticky = bool(mode & _stat.S_ISVTX)
    if mode & _stat.S_IWOTH and not sticky:
        return "is writable by everyone"
    if mode & _stat.S_IWGRP and not sticky and _untrusted_group(st, group_ids):
        return "is writable by a non-system group"
    return None


_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_lstat = os.lstat


def _is_under(path: str, root: str) -> bool:
    """Case-insensitive Windows containment test (``path`` inside ``root``)."""
    p = ntpath.normcase(ntpath.normpath(str(path)))
    r = ntpath.normcase(ntpath.normpath(str(root))).rstrip("\\")
    return bool(r) and (p == r or p.startswith(r + "\\"))


def _path_chain_problem(path: str, expected_uid: Optional[int],
                        group_ids: Optional[FrozenSet[int]]) -> Optional[str]:
    """Check every directory from the filesystem root down to the item's
    parent, with lstat, right before the item is deleted. Fails closed: a
    component that cannot be inspected is a refusal."""
    if not _is_posix():
        programdata = os.environ.get("ProgramData", "")  # API value (sanitised)
        if programdata and _is_under(path, programdata):
            return ("it lies under ProgramData, where standard users can turn "
                    "folders into junctions")
        system_root = os.environ.get("SystemRoot", "")  # API value (sanitised)
        if system_root and _is_under(path, ntpath.join(system_root, "Temp")):
            # Users can create (and later swap for junctions) directories in
            # Windows\Temp; the recursive delete unlinks entries by path, so
            # only plain files are cleaned there. Judged NOW, right before
            # the delete, not at scan time.
            try:
                st = _lstat(path)
            except OSError:
                return f"{path} cannot be inspected"
            import stat as _stat

            if (_stat.S_ISDIR(st.st_mode) or not _stat.S_ISREG(st.st_mode)
                    or getattr(st, "st_file_attributes", 0)
                    & _FILE_ATTRIBUTE_REPARSE_POINT):
                return ("directories under Windows\\Temp are not cleaned with "
                        "administrator rights")
        for parent in Path(path).parents:
            try:
                st = _lstat(parent)
            except OSError:
                return f"{parent} cannot be inspected"
            if getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
                return f"{parent} is a link or junction"
        return None
    from cleanix.core.utils import canonical_system_path

    full = Path(canonical_system_path(os.path.abspath(path)))
    parts = full.parent.parts
    for i in range(len(parts)):
        comp = Path(*parts[: i + 1])
        try:
            st = _lstat(comp)
        except OSError:
            return f"{comp} cannot be inspected"
        problem = _component_problem(st, expected_uid, group_ids)
        if problem:
            return f"{comp} {problem}"
    return None


def _user_groups(user: context.TargetUser) -> Optional[FrozenSet[int]]:
    """The requesting user's groups, or None if they cannot be determined
    (then every group-writable parent is refused)."""
    try:
        return frozenset(os.getgrouplist(user.name, user.gid))
    except Exception:  # noqa: BLE001 - fail closed
        return None


def _load_config(config_path: Optional[str], home: Path, expected_uid: Optional[int]):
    """Built-in defaults for every setting; only ``protected_globs`` (which can
    only add protection) is taken from the user's file."""
    from cleanix.config import Config, _config_path

    cfg = Config()
    if config_path:
        path = Path(config_path)
    elif _is_posix():
        path = home / ".config" / "cleanix" / "config.yaml"
    else:
        path = _config_path()
    if not os.path.lexists(str(path)):
        return cfg
    try:
        data = elevate.read_secure(
            path, expected_uid=expected_uid if _is_posix() else None,
            max_bytes=MAX_CONFIG_BYTES, what="config",
        )
    except ValueError as exc:
        raise Refused(str(exc)) from None
    try:
        import yaml
    except ImportError:
        raise Refused("cannot read protected_globs from the config") from None
    try:
        obj = yaml.safe_load(data.decode("utf-8-sig")) or {}
    except Exception:  # noqa: BLE001 - never echo parser messages (file content)
        raise Refused("config is not valid YAML") from None
    if not isinstance(obj, dict):
        raise Refused("config is not a mapping")
    globs = obj.get("protected_globs") or []
    if not isinstance(globs, list) or not all(isinstance(g, str) for g in globs):
        raise Refused("config protected_globs is not a list of strings")
    cfg.protected_globs = [_user_glob(g, home) for g in globs]
    return cfg


def _user_glob(glob: str, home: Path) -> str:
    """Expand ``~``/``$HOME`` against the invoking user's home, not the admin's."""
    for prefix in ("~", "$HOME", "${HOME}"):
        if glob == prefix:
            return str(home)
        if glob.startswith(prefix + "/") or glob.startswith(prefix + "\\"):
            return str(home) + glob[len(prefix):]
    return glob


# --------------------------------------------------------------------------
# session: single final result write + watchdog
# --------------------------------------------------------------------------
WATCHDOG_LOCK_TIMEOUT = 5.0


class _Session:
    """Shared state of one run: a lock-protected tally of the work done and
    the single final result write (by the main path or the watchdog)."""

    def __init__(self, rdir: elevate.RequestDir):
        self.rdir = rdir
        self.nonce = ""
        self.lock = threading.Lock()
        self.finalized = False
        self.done = threading.Event()
        self.aborted = False
        # tally (under ``lock``)
        self.freed = 0
        self.removed = 0
        self.errors: List[str] = []
        self.processed = 0
        self.total = 0
        self.unmatched = 0
        self.refused = 0

    def record(self, summary) -> None:
        """Add one item's clean summary to the tally."""
        with self.lock:
            self.freed += summary.freed
            self.removed += summary.removed
            self.errors.extend(f"{o.item.description}: {o.error}" for o in summary.errors)
            self.processed += 1

    def note(self, *, error: Optional[str] = None, refused: int = 0,
             unmatched: int = 0) -> None:
        with self.lock:
            if error:
                self.errors.append(error)
            self.refused += refused
            self.unmatched += unmatched

    def _tally_result(self, extra_errors=(), hit: bool = False) -> elevate.HelperResult:
        return elevate.HelperResult(
            freed=self.freed, removed=self.removed,
            errors=list(self.errors) + list(extra_errors), unmatched=self.unmatched,
            nonce=self.nonce, deadline_hit=hit, refused=self.refused)

    def _write(self, result: elevate.HelperResult) -> bool:
        try:
            self.rdir.write_result(result)
            return True
        except Exception:  # noqa: BLE001
            return False

    def finish(self, extra_errors=(), hit: bool = False) -> bool:
        """Write the final result (the tally) once. False if the watchdog
        already wrote it, or the write failed."""
        with self.lock:
            if self.finalized:
                return False
            self.finalized = True
            return self._write(self._tally_result(extra_errors, hit))

    def abort_after_deadline(self) -> None:
        """Watchdog: the helper overran its deadline. Write the tally and exit
        hard -- unless the main path already finished (a completed run must
        never exit 3). The lock is waited for at most a few seconds; the
        process exits regardless."""
        got = self.lock.acquire(timeout=WATCHDOG_LOCK_TIMEOUT)
        try:
            if got and self.finalized:
                return
            self.aborted = True
            if got:
                self.finalized = True
                msg = ("the helper was stopped after its deadline; "
                       f"{self.processed} of {self.total} items had been processed")
                self._write(self._tally_result([msg], hit=True))
        finally:
            if got:
                self.lock.release()
        os._exit(EXIT_DEADLINE)


def _start_watchdog(session: _Session, limit: float) -> threading.Thread:
    def watch() -> None:
        if not session.done.wait(max(0.0, limit)):
            session.abort_after_deadline()

    t = threading.Thread(target=watch, name="cleanix-helper-watchdog", daemon=True)
    t.start()
    return t


def _valid_deadline(value) -> bool:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return False
    return math.isfinite(v) and 0 < v <= DEFAULT_DEADLINE


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------
def run(request_path: Path, result_path: Path, config_path: Optional[str] = None,
        *, expected_uid: Optional[int] = None,
        deadline: float = DEFAULT_DEADLINE, grace: float = WATCHDOG_GRACE) -> int:
    start = _monotonic()
    if not _valid_deadline(deadline):
        return EXIT_REFUSED
    deadline = float(deadline)

    request_path = Path(request_path)
    result_path = Path(result_path)
    # Root only ever writes next to the request: never to a caller-chosen path.
    if (request_path.name != elevate.REQUEST_NAME
            or result_path.name != elevate.RESULT_NAME
            or not _same_dir(result_path.parent, request_path.parent)):
        return EXIT_REFUSED
    if _is_posix() and expected_uid is None:
        return EXIT_REFUSED
    try:
        _sanitize_environment()
    except Refused:
        return EXIT_REFUSED
    # Validate the directory BEFORE anything else; no result is written into
    # a directory that failed validation.
    try:
        rdir = elevate.RequestDir(request_path.parent, expected_uid)
    except ValueError:
        return EXIT_REFUSED
    try:
        session = _Session(rdir)
        _start_watchdog(session, deadline - (_monotonic() - start) + grace)
        try:
            return _run_session(session, config_path, expected_uid, deadline, start)
        finally:
            session.done.set()
    finally:
        rdir.close()


def _run_session(session: _Session, config_path: Optional[str],
                 expected_uid: Optional[int], deadline: float, start: float) -> int:
    def cancel() -> bool:
        return _monotonic() - start >= deadline

    try:
        try:
            selection = session.rdir.read_request()
        except ValueError as exc:
            raise Refused(str(exc)) from None
        session.nonce = selection.nonce
        name = _check_identity(selection.invoking_user, expected_uid)
        user = _bind_user(name, expected_uid)
        config = _load_config(config_path, Path(user.home), expected_uid)
    except Refused as exc:
        session.finish([f"request refused: {exc}"])
        return EXIT_REFUSED

    try:
        return _execute(session, selection, config, cancel, deadline, start,
                        expected_uid, _user_groups(user) if _is_posix() else frozenset())
    except Exception as exc:  # noqa: BLE001
        session.finish([f"internal error in the elevated helper ({type(exc).__name__})"])
        if session.aborted:
            return EXIT_DEADLINE
        return EXIT_INTERNAL


def _eligible(item, allowed: FrozenSet[str]) -> bool:
    """May the helper clean this (already key-matched) item as admin?"""
    return (not item.report_only and bool(item.requires_root)
            and item.cleaner_id in allowed)


def _clamp_command(item, remaining: float):
    """A COMMAND item's timeout never exceeds the time left right now."""
    if item.kind is not ItemKind.COMMAND:
        return item
    limit = min(item.timeout or DEFAULT_COMMAND_TIMEOUT, remaining)
    return dataclasses.replace(item, timeout=max(1, int(limit)))


def _execute(session: _Session, selection: elevate.Selection, config, cancel,
             deadline: float, start: float, expected_uid: Optional[int],
             group_ids: Optional[FrozenSet[int]]) -> int:
    allowed = admin_cleaner_ids()
    wanted = set(selection.keys)
    # Keys of cleaners the helper never runs are refused without scanning.
    pre_refused = {k for k in wanted if k.split("|", 1)[0] not in allowed}
    scan_keys = wanted - pre_refused
    only = [c for c in dict.fromkeys(selection.only) if c in allowed]
    session.note(refused=len(pre_refused))

    def finish(extra=(), hit=False) -> int:
        ok = session.finish(extra, hit)
        if session.aborted:
            return EXIT_DEADLINE  # the watchdog already wrote the result
        if not ok:
            return EXIT_INTERNAL
        return EXIT_DEADLINE if hit else EXIT_OK

    if not only or not scan_keys:
        # Fail closed: an empty cleaner list never means "every cleaner".
        session.note(unmatched=len(scan_keys))
        return finish()

    try:
        scan = service.scan(config, only=only, cancel=cancel)
    except service.Cancelled:
        return finish(["deadline reached while scanning; nothing was cleaned"], hit=True)

    matched_keys = set()
    eligible = []
    for item in scan.all_items():
        key = item_key(item)
        if key not in scan_keys or key in matched_keys:
            continue
        matched_keys.add(key)
        if not _eligible(item, allowed):
            session.note(refused=1)
            continue
        eligible.append(item)
    session.note(unmatched=len(scan_keys - matched_keys))
    with session.lock:
        session.total = len(eligible)

    # One item at a time: the parent chain is re-checked right before each
    # deletion, and each command's timeout is clamped to the time left NOW.
    hit = False
    for item in eligible:
        remaining = deadline - (_monotonic() - start)
        if remaining <= 0 or cancel():
            hit = True
            break
        if item.kind is ItemKind.PATH:
            problem = _path_chain_problem(item.path or "", expected_uid, group_ids)
            if problem:
                session.note(refused=1, error=(
                    f"{item.description}: refused, untrusted parent directory "
                    f"({problem})"))
                with session.lock:
                    session.processed += 1
                continue
        summary = service.clean([_clamp_command(item, remaining)], config,
                                dry_run=False, use_quarantine=False,
                                record_history=False, cancel=cancel)
        if not summary.result.outcomes:
            hit = True
            break
        session.record(summary)

    extra = ["deadline reached; the remaining items were not cleaned"] if hit else []
    return finish(extra, hit=hit)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def _resolve_uid(arg_uid: Optional[int], environ) -> Optional[int]:
    """Under pkexec the --uid must be the uid pkexec saw launch us."""
    pk = environ.get("PKEXEC_UID")
    if pk is not None:
        try:
            pk_uid = int(pk)
        except ValueError:
            raise Refused("PKEXEC_UID is not a number") from None
        if arg_uid is None or arg_uid != pk_uid:
            raise Refused("--uid does not match the user who requested elevation")
    return arg_uid


def _deadline_arg(text: str) -> float:
    if not _valid_deadline(text):
        raise ValueError("deadline must be in (0, 3300]")
    return float(text)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cleanix.elevated", add_help=True,
                                description="cleanix elevated helper (internal)")
    p.add_argument("--request", required=True)
    p.add_argument("--result", required=True)
    p.add_argument("--config", default=None)
    p.add_argument("--uid", type=int, default=None)
    p.add_argument("--deadline", type=_deadline_arg, default=DEFAULT_DEADLINE)
    return p


def _main(argv: Optional[Sequence[str]]) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return EXIT_OK if exc.code in (0, None) else EXIT_REFUSED
    try:
        uid = _resolve_uid(args.uid, os.environ)
    except Refused:
        return EXIT_REFUSED
    return run(Path(args.request), Path(args.result), args.config,
               expected_uid=uid, deadline=args.deadline)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        rc = _main(argv)
    except BaseException:  # noqa: BLE001 - incl. SystemExit/KeyboardInterrupt
        return EXIT_INTERNAL
    if not isinstance(rc, int) or isinstance(rc, bool) or rc not in _ALLOWED_EXITS:
        return EXIT_INTERNAL
    return rc


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
