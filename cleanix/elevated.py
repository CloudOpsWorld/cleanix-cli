"""The elevated helper: ``python -m cleanix.elevated``.

Runs as root/Administrator (launched by ``cleanix.core.elevate_launch``) and
receives its instructions from a user-writable request file, so it trusts
nothing in it beyond *identifiers*, and nothing in its environment:

1. The environment is replaced by a fixed trusted one (POSIX: fixed PATH, no
   PYTHON*/LD_*/DYLD_* variables; Windows: SystemRoot/windir/SystemDrive/
   ProgramData/PATH from the Windows API, never inherited values).
2. The request directory is validated once, up front, and then used by
   descriptor (POSIX): owned by the requesting uid, private, no symlinked
   path components. Request and result live only in that directory.
3. The requesting uid comes from ``--uid``, cross-checked against pkexec's
   ``PKEXEC_UID``; the user name is resolved from the uid, never just taken
   from the request.
4. Only that user's home is in scope (``context.configure(all_users=False)``).
5. Only cleaners on a helper-side ALLOWLIST (system/administrator cleaners
   plus ``temp``) are scanned; other requested cleaner ids are refused before
   any scan code runs.
6. A fresh scan is run with built-in DEFAULT settings; from the user's
   config file only ``protected_globs`` is taken (it can only add protection).
7. An item is cleaned only if its key was requested AND it is in the fresh
   scan AND it requires admin rights (relative to the requesting user) AND
   its cleaner is allowlisted AND it is not report-only. Deletion goes through
   the normal engine and its safety guard.
8. Nothing is written under the user's home: no quarantine (the request's
   ``use_quarantine`` is ignored), no history, no manifest. The GUI records
   history itself, as the user, from the result.
9. The helper has its own deadline (at most 3300 s, below the launcher's
   3600 s); COMMAND items' timeouts are clamped to the time left, and a
   watchdog ends the process ``grace`` seconds after the deadline.

What the design does and does not protect:
* The nonce only detects stale or mixed-up result files; it provides no
  integrity. A same-user attacker who can edit the request between the
  elevation prompt and the helper reading it can only choose among items the
  helper itself deems eligible (point 7) -- which is why the allowlist,
  root-relative ``requires_root`` and default-only config matter.
* The elevation prompt (UAC / polkit / macOS) does not show what will be
  removed; the GUI's confirmation is the only place the user sees the list.

Exit codes (126/127 are never used: pkexec reserves them):
0 completed (details in the result file), 1 request unreadable/refused
(nothing deleted), 2 internal error, 3 deadline reached (partial result).
"""

from __future__ import annotations

import argparse
import dataclasses
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
# Variables that let the caller inject code into us or our children.
_DROP_EXACT = {"IFS", "ENV", "BASH_ENV", "CDPATH", "PERL5LIB", "PERLLIB",
               "PERL5OPT", "RUBYLIB", "RUBYOPT", "NODE_OPTIONS", "NODE_PATH",
               "GCONV_PATH", "HOSTALIASES", "LOCALDOMAIN", "RES_OPTIONS",
               "TMPDIR", "SHELLOPTS", "PS4"}
_DROP_PREFIXES = ("PYTHON", "LD_", "DYLD_", "BASH_FUNC_", "MALLOC_")

_monotonic = time.monotonic


class Refused(Exception):
    """The request (or its environment) is not acceptable; nothing deleted."""


def _is_posix() -> bool:
    return os.name != "nt"


# --------------------------------------------------------------------------
# trusted environment
# --------------------------------------------------------------------------
def _drop_injection_vars() -> None:
    for key in list(os.environ):
        upper = key.upper()
        if upper in _DROP_EXACT or upper.startswith(_DROP_PREFIXES):
            del os.environ[key]


def _win_known_dirs():
    """(windows dir, system32 dir, ProgramData) from the Windows API.

    Raises OSError if any call fails."""
    import ctypes
    import uuid as _uuid
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

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                    ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

    guid = GUID()
    raw = _uuid.UUID("62AB5D82-FDC1-4DC3-A9DD-070D1D495D97").bytes_le  # ProgramData
    ctypes.memmove(ctypes.byref(guid), raw, 16)
    fn = ctypes.windll.shell32.SHGetKnownFolderPath
    fn.argtypes = [ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE,
                   ctypes.POINTER(ctypes.c_void_p)]
    fn.restype = ctypes.c_long
    ptr = ctypes.c_void_p()
    hr = fn(ctypes.byref(guid), 0, None, ctypes.byref(ptr))
    try:
        if hr != 0 or not ptr.value:
            raise OSError("ProgramData lookup failed")
        programdata = ctypes.wstring_at(ptr.value)
    finally:
        if ptr.value:
            ctypes.windll.ole32.CoTaskMemFree(ptr)
    if not (windir and sysdir and programdata):
        raise OSError("Windows directory lookup returned nothing")
    return windir, sysdir, programdata


def _sanitize_environment() -> None:
    """Replace inherited, caller-controllable environment with trusted values."""
    _drop_injection_vars()
    if _is_posix():
        os.environ["PATH"] = POSIX_PATH
        return
    try:
        windir, sysdir, programdata = _win_known_dirs()
    except Exception:  # noqa: BLE001
        raise Refused("could not determine the Windows system directories") from None
    drive = ntpath.splitdrive(windir)[0]
    if not drive:
        raise Refused("could not determine the system drive")
    os.environ["SystemRoot"] = windir
    os.environ["windir"] = windir
    os.environ["SystemDrive"] = drive
    os.environ["ProgramData"] = programdata
    os.environ["PATH"] = ";".join([
        sysdir, windir, ntpath.join(sysdir, "Wbem"),
        ntpath.join(sysdir, "WindowsPowerShell", "v1.0"),
    ])


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


def admin_cleaner_ids() -> FrozenSet[str]:
    """Cleaners the helper may run: the system/administrator category plus
    the temp-files cleaner. Everything else is a user-level cleaner the GUI
    runs itself, unprivileged."""
    from cleanix.core import catalog, registry

    ids = {c.id for c in registry.ALL_CLEANERS if catalog.category_of(c.id) == "system"}
    ids.add("temp")
    return frozenset(ids)


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
class _Session:
    def __init__(self, rdir: elevate.RequestDir):
        self.rdir = rdir
        self.nonce = ""
        self.lock = threading.Lock()
        self.finalized = False
        self.done = threading.Event()
        self.processed = 0
        self.total = 0
        self.aborted = False

    def finish(self, result: elevate.HelperResult) -> bool:
        """Write the final result once; False if already written or failed."""
        with self.lock:
            if self.finalized:
                return False
            self.finalized = True
            try:
                self.rdir.write_result(result)
                return True
            except Exception:  # noqa: BLE001
                return False

    def result(self, **kw) -> elevate.HelperResult:
        base = dict(freed=0, removed=0, errors=[], unmatched=0, nonce=self.nonce)
        base.update(kw)
        return elevate.HelperResult(**base)

    def abort_after_deadline(self) -> None:
        """Watchdog: the helper overran its deadline; write and exit hard."""
        msg = ("the helper was stopped after its deadline; "
               f"{self.processed} of {self.total} items had been processed")
        self.aborted = True
        self.finish(self.result(errors=[msg], deadline_hit=True))
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
        session.finish(session.result(errors=[f"request refused: {exc}"]))
        return EXIT_REFUSED

    try:
        return _execute(session, selection, config, cancel, deadline, start)
    except Exception as exc:  # noqa: BLE001
        session.finish(session.result(
            errors=[f"internal error in the elevated helper ({type(exc).__name__})"]))
        return EXIT_INTERNAL


def _eligible(item, allowed: FrozenSet[str]) -> bool:
    """May the helper clean this (already key-matched) item as admin?"""
    return (not item.report_only and bool(item.requires_root)
            and item.cleaner_id in allowed)


def _clamp_commands(items, remaining: float):
    out = []
    for item in items:
        if item.kind is ItemKind.COMMAND:
            limit = min(item.timeout or DEFAULT_COMMAND_TIMEOUT, remaining)
            item = dataclasses.replace(item, timeout=max(1, int(limit)))
        out.append(item)
    return out


def _execute(session: _Session, selection: elevate.Selection, config, cancel,
             deadline: float, start: float) -> int:
    allowed = admin_cleaner_ids()
    wanted = set(selection.keys)
    # Keys of cleaners the helper never runs are refused without scanning.
    pre_refused = {k for k in wanted if k.split("|", 1)[0] not in allowed}
    scan_keys = wanted - pre_refused
    only = [c for c in dict.fromkeys(selection.only) if c in allowed]

    def finish(freed=0, removed=0, errors=(), unmatched=0, refused=0, hit=False) -> int:
        ok = session.finish(session.result(
            freed=freed, removed=removed, errors=list(errors), unmatched=unmatched,
            refused=refused + len(pre_refused), deadline_hit=hit))
        if session.aborted:
            return EXIT_DEADLINE  # the watchdog already wrote the result
        if not ok:
            return EXIT_INTERNAL
        return EXIT_DEADLINE if hit else EXIT_OK

    if not only or not scan_keys:
        # Fail closed: an empty cleaner list never means "every cleaner".
        return finish(unmatched=len(scan_keys))

    try:
        scan = service.scan(config, only=only, cancel=cancel)
    except service.Cancelled:
        return finish(hit=True,
                      errors=["deadline reached while scanning; nothing was cleaned"])

    matched_keys = set()
    eligible = []
    refused = 0
    for item in scan.all_items():
        key = item_key(item)
        if key not in scan_keys or key in matched_keys:
            continue
        matched_keys.add(key)
        if not _eligible(item, allowed):
            refused += 1
            continue
        eligible.append(item)
    unmatched = len(scan_keys - matched_keys)

    remaining = deadline - (_monotonic() - start)
    if remaining <= 0 or cancel():
        return finish(unmatched=unmatched, refused=refused, hit=True,
                      errors=["deadline reached before cleaning; nothing was cleaned"])
    eligible = _clamp_commands(eligible, remaining)
    session.total = len(eligible)

    def progress(_desc, done, _total):
        session.processed = done

    summary = service.clean(eligible, config, dry_run=False, use_quarantine=False,
                            record_history=False, progress=progress, cancel=cancel)
    hit = len(summary.result.outcomes) < len(eligible)
    errors: List[str] = [f"{o.item.description}: {o.error}" for o in summary.errors]
    if hit:
        errors.append("deadline reached; the remaining items were not cleaned")
    return finish(freed=summary.freed, removed=summary.removed, errors=errors,
                  unmatched=unmatched, refused=refused, hit=hit)


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
