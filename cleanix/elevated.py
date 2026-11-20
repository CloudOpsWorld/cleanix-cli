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
   are refused before any scan code runs. Registry detectors are never on
   it: registry entries come only through the separate registry action
   (point 10), with its own allowlist ``admin_registry_cleaner_ids``.
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
   item at a time. REGISTRY items are never deleted by this file path.
8. Nothing is written under the user's home: no quarantine (the request's
   ``use_quarantine`` is ignored), no history, no manifest, no quarantine
   run (also not for registry entries: their backup was written by the GUI,
   as the user, before the launch). The GUI records history itself, as the
   user, from the result.
9. The helper has its own deadline (at most 3300 s, below the launcher's
   3600 s); each COMMAND item's timeout is clamped to the time left when it
   starts, and a watchdog writes the work done so far and ends the process
   ``grace`` seconds after the deadline (never after a completed run).
10. Registry action (Windows only; the optional ``registry`` part of the
    request: registry detector ids, item keys, a backup RUN ID and the
    invoking user's quarantine root -- never a key list to delete). Before
    anything is deleted (else exit 1, nothing deleted, also no files):
    every detector id is on ``admin_registry_cleaner_ids``, every key names
    HKLM, the run id is a plain name, the process is elevated, the
    quarantine root is a LOCAL-DRIVE path (judged from its text alone,
    before any filesystem call: never UNC/WebDAV/device paths, which an
    administrator process would open over the network), the request
    directory and request are owned by one user SID, that SID's profile
    (HKLM ProfileList, writable by administrators only, itself a local
    path) strictly contains the quarantine root, which is
    ``...\\cleanix\\quarantine``, with no link/junction (lstat) from the
    profile down to the run, its registry folder and manifest, equal to its
    realpath, and whose root, run directory and manifest are owned by that
    SID. Then the
    helper re-scans with exactly those detectors in helper scan mode
    (``scanmode``: owner_matches=False) through an HKLM-only backend (an
    HKCU call never reaches the registry: R15, HKCU here is the
    administrator's hive), and deletes only REGISTRY HKLM items of its own
    scan whose key (fingerprint included) was requested and that pass the
    registry safety rules, each with ``service.clean(...,
    use_quarantine=False, record_history=False,
    registry_backup_elsewhere=True, registry_backup_run=<run>,
    registry_verified_backups=<backups preloaded at validation>)``, so
    ``VerifyOnlySink`` deletes only what that run can restore. The run's
    manifest and the needed backup JSONs are read ONCE, during validation,
    each opened right after its lstat and checked by handle (``fstat``:
    same file), and verified in memory; after validation nothing of the
    run is opened or resolved by path (the helper's own %LOCALAPPDATA%
    quarantine is never consulted either).
11. Findings action (POSIX only; the optional ``findings`` part, never
    combined with other items: scenario ids, item keys with their remedy
    fingerprints and kinds, ``permanent``). Validated from its text alone
    BEFORE the user is bound or any file is read (else exit 1, nothing
    deleted): every scenario on ``admin_finding_ids`` (system-wide finding
    detectors, separate from both other allowlists), every key a clean,
    normalised absolute path strictly inside a root its own detector scans
    (``finding_path_roots``), never a protected folder, an ancestor of one
    or the helper's own quarantine; the process is root. Items of a remedy
    kind other than PATH are refused individually. The helper then
    re-scans with exactly those scenarios in helper scan mode (the
    detectors skip their per-user candidates) and acts only on items of
    its OWN scan whose key AND remedy fingerprint equal the request's:
    report-only, requires_root, PATH remedy, no duplicate group. Anything
    else is reported (not found / changed / refused) and skipped. One
    ``actions.act`` batch with ``allow_root``: fingerprint and type
    re-checked and the parent chain (point 7) re-checked right before each
    removal, the deletion guard in force. Unless ``permanent``, items are
    moved into ONE run of a root-owned quarantine the helper creates 0700
    (``/var/lib/cleanix/quarantine``; macOS ``/Library/Application
    Support/Cleanix/quarantine``) and validates without following links;
    if it is not usable nothing is removed. No history; nothing under the
    user's home. Per-item outcomes and the run id go into the result.

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
(f) Registry action: a same-user (medium-integrity) program can edit the
    request and the backup run between the GUI and the helper. It can only
    pick among HKLM entries the helper's own allowlisted scan finds dead,
    and each delete still needs a verified backup in the run (so it stays
    restorable from an Administrator terminal); it can also tamper with
    the backup files afterwards, which is why HKLM restore is never offered
    by the GUI and shows exactly what it writes (T4). The R17 window
    (``RegDeleteKeyEx`` re-resolving the path after the last check) applies
    unchanged; the outcome is then "partially deleted", never success.
    Path validation is check-then-use: a non-local root is refused from its
    text before any filesystem call, and the run is read once, by handle,
    right after each lstat. What remains is a micro-window between the
    last lstat of a path and its open: a program running as the user that
    can create symbolic links (Developer Mode, or an object-manager
    symlink) could swap a component in that window and make the
    administrator's open follow it (possibly to a network path). The
    handle check then refuses the file, but the open already happened.
    Handle-relative opening (NtCreateFile with a parent handle) is future
    work, as for (d).

Exit codes (126/127 are never used: pkexec reserves them):
0 completed (details in the result file), 1 request unreadable/refused
(nothing deleted), 2 internal error, 3 deadline reached (partial result).
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import functools
import math
import ntpath
import os
import re
import stat as _stat_mod
import sys
import threading
import time
from pathlib import Path
from typing import FrozenSet, Iterator, List, Optional, Sequence

from cleanix.core import context, elevate, scanmode, service, winregistry
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
# registry action: allowlist and eligibility
# --------------------------------------------------------------------------
_FIXED_LIST_REASON = ("Cannot be cleaned with administrator permission from the GUI: "
                      "the administrator helper only cleans a fixed list of system locations")
HKLM_ONLY_REASON = ("Only machine-wide (HKLM) registry entries are cleaned with "
                    "administrator permission")
REGISTRY_BLOCKED_REASON = "Blocked by registry safety rules"


def _registry_supported() -> bool:
    """The one platform gate of the registry action (helper AND GUI)."""
    from cleanix.core import platform as plat

    return plat.is_windows()


def admin_registry_cleaner_ids() -> FrozenSet[str]:
    """Registry detectors whose HKLM entries the helper may delete: the
    HKLM-capable ``catalog.REGISTRY_IDS`` on Windows, nothing elsewhere.
    Separate from ``admin_cleaner_ids`` (the file-cleaner allowlist)."""
    if not _registry_supported():
        return frozenset()
    from cleanix.core import catalog

    return frozenset(catalog.admin_registry_cleaner_ids())


def _is_registry_candidate(item) -> bool:
    from cleanix.core import catalog

    return item.kind is ItemKind.REGISTRY or item.cleaner_id in catalog.REGISTRY_IDS


def _registry_problem(item, reg_allowed: Optional[FrozenSet[str]] = None) -> Optional[str]:
    """Why the helper never deletes this registry candidate (None: it may).
    Only REGISTRY items of an allowlisted registry detector, in HKLM, that
    pass the static registry safety rules."""
    allowed = admin_registry_cleaner_ids() if reg_allowed is None else reg_allowed
    if item.kind is not ItemKind.REGISTRY or item.reg is None or item.cleaner_id not in allowed:
        return _FIXED_LIST_REASON
    if item.reg.hive != "HKLM":
        return HKLM_ONLY_REASON
    from cleanix.core.regsafety import check_target

    if check_target(item.cleaner_id, item.reg) is not None:
        return REGISTRY_BLOCKED_REASON
    return None


def _registry_eligible(item, reg_allowed: FrozenSet[str]) -> bool:
    """May the helper delete this (already key-matched) registry item?"""
    return (not item.report_only and bool(item.requires_root)
            and _registry_problem(item, reg_allowed) is None)


class _MachineOnlyBackend:
    """The registry backend the helper scans and deletes through (R15).

    Running elevated, HKCU is the ADMINISTRATOR's hive, never the invoking
    user's: every HKCU call is answered here as "absent" and never reaches
    the real backend. Nothing is ever written (create/set are refused for
    every hive: the helper never restores). HKLM reads and deletes are
    forwarded unchanged."""

    def __init__(self, inner) -> None:
        self._inner = inner

    @staticmethod
    def _machine(hive: str) -> bool:
        return hive == "HKLM"

    def subkeys(self, hive, key):
        if not self._machine(hive):
            raise winregistry.KeyMissing(f"{hive} is not read by the administrator helper")
        return self._inner.subkeys(hive, key)

    def values(self, hive, key):
        if not self._machine(hive):
            raise winregistry.KeyMissing(f"{hive} is not read by the administrator helper")
        return self._inner.values(hive, key)

    def key_exists(self, hive, key):
        if not self._machine(hive):
            return False
        return self._inner.key_exists(hive, key)

    def is_link(self, hive, key):
        if not self._machine(hive):
            raise winregistry.KeyMissing(f"{hive} is not read by the administrator helper")
        return self._inner.is_link(hive, key)

    def can_delete(self, hive, key, value):
        if not self._machine(hive):
            return False
        return self._inner.can_delete(hive, key, value)

    def delete_key(self, hive, key):
        if not self._machine(hive):
            raise winregistry.AccessDenied(f"{hive} is never changed by the administrator helper")
        return self._inner.delete_key(hive, key)

    def delete_value(self, hive, key, name):
        if not self._machine(hive):
            raise winregistry.AccessDenied(f"{hive} is never changed by the administrator helper")
        return self._inner.delete_value(hive, key, name)

    def create_key(self, hive, key):
        raise winregistry.AccessDenied("the administrator helper never writes the registry")

    def set_value(self, hive, key, value):
        raise winregistry.AccessDenied("the administrator helper never writes the registry")


# The invoking account: the owner of the request directory (created by the
# unelevated GUI). Domain/local (S-1-5-21-...) and Azure AD (S-1-12-1-...)
# user SIDs only; never Administrators, SYSTEM or another well-known SID.
_USER_SID_RE = re.compile(r"S-1-5-21(?:-\d{1,10}){4}|S-1-12-1(?:-\d{1,10}){4}")
PROFILE_LIST = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
_PROFILE_VARS = re.compile(r"%([^%]*)%")


def _owner_sid(path) -> Optional[str]:
    """Owner SID (string form) of a file or directory; None if unknown."""
    try:
        from cleanix.core import regbackup

        return regbackup._win_security().file_owner(str(path))
    except Exception:  # noqa: BLE001 - unknown owner: callers fail closed
        return None


def _invoking_sid(rdir: elevate.RequestDir) -> str:
    owner = _owner_sid(rdir.path)
    if not isinstance(owner, str) or not _USER_SID_RE.fullmatch(owner):
        raise Refused("the request directory is not owned by a user account")
    if _owner_sid(rdir.path / elevate.REQUEST_NAME) != owner:
        raise Refused("the request is not owned by the account that owns its directory")
    return owner


def _profile_for_sid(sid: str) -> str:
    """The account's profile directory from HKLM ProfileList (writable by
    administrators only). REG_SZ or REG_EXPAND_SZ only; the one expansion
    is %SystemDrive% (any other %VAR% refuses); the result must be an
    absolute path on a local drive (a UNC/roaming profile refuses).
    Lexical only: nothing on the filesystem is touched here."""
    from cleanix.core.winregistry import REG_EXPAND_SZ, REG_SZ, RegistryError

    try:
        values = winregistry.get_backend().values("HKLM", PROFILE_LIST + "\\" + sid)
    except RegistryError:
        raise Refused("the requesting account has no profile") from None
    raw = None
    for v in values:
        if v.name.casefold() == "profileimagepath":
            if v.type not in (REG_SZ, REG_EXPAND_SZ) or not isinstance(v.data, str):
                raise Refused("the requesting account's profile path is not usable")
            raw = v.data
            break
    if not raw:
        raise Refused("the requesting account has no profile")

    def expand(m):
        if m.group(1).casefold() == "systemdrive":
            for k, val in os.environ.items():
                if k.casefold() == "systemdrive" and val:
                    return val
        return m.group(0)

    path = _PROFILE_VARS.sub(expand, raw)
    if "%" in path:
        raise Refused("the requesting account's profile path is not usable")
    path = os.path.normpath(path)  # lexical
    if not elevate.is_local_absolute_path(path):
        raise Refused("the requesting account's profile path is not usable")
    return path


def _no_link(path: str, what: str, *, directory: bool = True) -> None:
    """lstat (never follows) ``path``: no symlink/junction/reparse point,
    and a directory (or a regular file with ``directory=False``)."""
    try:
        st = _lstat(path)
    except OSError:
        raise Refused(f"{what} cannot be inspected") from None
    if (_stat_mod.S_ISLNK(st.st_mode)
            or getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT):
        raise Refused(f"{what} is a link or junction")
    if directory and not _stat_mod.S_ISDIR(st.st_mode):
        raise Refused(f"{what} is not a directory")
    if not directory and not _stat_mod.S_ISREG(st.st_mode):
        raise Refused(f"{what} is not a regular file")


def _read_pinned(path: str, limit: int, what: str) -> bytes:
    """Read a small file the user can write, as tightly as stdlib allows:
    lstat it (a regular file, not a link or reparse point, at most
    ``limit`` bytes), open it right away (``O_NOFOLLOW`` where available),
    check that the OPENED file is the one just inspected (``fstat``:
    same device and inode / file index, still regular), then read at most
    ``limit`` bytes through that descriptor. Refused on any doubt."""
    try:
        st0 = _lstat(path)
    except OSError:
        raise Refused(f"{what} cannot be inspected") from None
    if (_stat_mod.S_ISLNK(st0.st_mode)
            or getattr(st0, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
            or not _stat_mod.S_ISREG(st0.st_mode)):
        raise Refused(f"{what} is a link or not a regular file")
    if getattr(st0, "st_size", 0) > limit:
        raise Refused(f"{what} is too large")
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(path, flags)
    except OSError:
        raise Refused(f"{what} could not be opened") from None
    try:
        st1 = _fstat(fd)
        if (not _stat_mod.S_ISREG(st1.st_mode)
                or (st1.st_dev, st1.st_ino) != (getattr(st0, "st_dev", None),
                                                getattr(st0, "st_ino", None))):
            raise Refused(f"{what} changed while it was being opened")
        chunks, total = [], 0
        while total <= limit:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        raise Refused(f"{what} could not be read") from None
    finally:
        os.close(fd)
    if total > limit:
        raise Refused(f"{what} is too large")
    return b"".join(chunks)


def _preload_backups(req: elevate.RegistryRequest, run_dir: str, manifest: str) -> dict:
    """Read the run's manifest and the registry backups the request needs,
    ONCE, by pinned handle (``_read_pinned``), and fully verify them in
    memory. ``{item key: regclean.VerifiedBackup}``; a key whose backup is
    missing, unreadable or does not verify is simply absent (the delete of
    that item is then refused by the sink)."""
    import json

    from cleanix.core import quarantine, regbackup, regclean, regsnap
    from cleanix.core.models import RegTarget

    raw = _read_pinned(manifest, quarantine.MAX_MANIFEST_BYTES, "the backup run's manifest")
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        raise Refused("the backup run's manifest is not valid") from None
    entries = doc.get("items") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise Refused("the backup run's manifest is not valid")
    wanted: dict = {}
    for key in dict.fromkeys(req.keys):
        cid, hive, rkey, value, fp = elevate.registry_key_parts(key)
        wanted.setdefault((cid, hive, rkey, value), []).append((key, fp))
    reg_dir = os.path.join(run_dir, "registry")
    out: dict = {}
    for entry in entries[:regclean.MAX_BACKUP_FILES]:
        if not (isinstance(entry, dict) and entry.get("type") == "registry"
                and entry.get("deleted") is not False):
            continue
        sig = (entry.get("cleaner_id"), entry.get("hive"), entry.get("key"),
               entry.get("value"))
        if sig not in wanted:
            continue
        name = Path(str(entry.get("json") or "")).name
        if not regbackup.is_backup_json_name(name):
            continue
        try:
            data = _read_pinned(os.path.join(reg_dir, name), regbackup.MAX_FILE_BYTES,
                                "a registry backup")
            cid, target, snap = regbackup.load_verified_bytes(data)
        except (Refused, regbackup.RestoreError):
            continue
        got = regsnap.fingerprint(target, snap)
        for key, fp in wanted[sig]:
            if (key not in out and cid == sig[0] and got == fp
                    and target == RegTarget(sig[1], sig[2], sig[3], fp)):
                out[key] = regclean.VerifiedBackup(cid, target, got)
    return out


@dataclasses.dataclass(frozen=True)
class _RegistryPlan:
    only: List[str]
    keys: List[str]
    backup_run: str
    quarantine_root: str
    # Every backup the request needs, read and verified at validation time:
    # nothing of the run is read by name after _prepare_registry.
    backups: dict = dataclasses.field(default_factory=dict)


def _lexical_root_problem(root: str) -> Optional[str]:
    """Checks of the quarantine root that need no filesystem access."""
    if not elevate.is_local_absolute_path(root):
        return "the quarantine root is not a path on a local drive"
    if os.path.normpath(root) != root:
        return "the quarantine root is not a normalised absolute path"
    if [p.casefold() for p in Path(root).parts[-2:]] != ["cleanix", "quarantine"]:
        return "the quarantine root is not a cleanix quarantine"
    return None


def _prepare_registry(req: elevate.RegistryRequest, rdir: elevate.RequestDir) -> _RegistryPlan:
    """Validate the registry action BEFORE anything is deleted (Refused on
    any problem): Windows, allowlisted detectors, an elevated process, and
    the backup run in the INVOKING account's own quarantine root.

    Order matters (C1): every check on the caller-chosen root that needs no
    filesystem access runs FIRST -- a local-drive path (never UNC, WebDAV,
    ``\\\\?\\`` or device paths, which an administrator process would
    open over the network), normalised, ending in ``cleanix\\quarantine``,
    strictly inside the profile that HKLM ProfileList gives for the owner of
    the request directory. Only then is the filesystem touched: lstat (never
    following links) from the profile down to the run, its ``registry``
    folder and manifest (no link or junction anywhere), the realpath, and
    the owner of the root, run and manifest (that same account)."""
    from cleanix.core import winenv

    if not _registry_supported():
        raise Refused("registry cleaning is only available on Windows")
    allowed = admin_registry_cleaner_ids()
    if not req.only or any(cid not in allowed for cid in req.only):
        raise Refused("the registry part names a detector the helper does not run")
    if not winenv.is_admin():
        raise Refused("the helper is not elevated; registry entries were not removed")
    root = req.quarantine_root
    problem = _lexical_root_problem(root)
    if problem:
        raise Refused(problem)
    sid = _invoking_sid(rdir)
    profile = _profile_for_sid(sid)
    if not _is_under(root, profile) or _is_under(profile, root):
        raise Refused("the quarantine root is not inside the requesting account's profile")

    # From here on only local paths inside the profile are touched.
    chain = [p for p in Path(root).parents if _is_under(str(p), profile)]
    for p in reversed(chain):
        _no_link(str(p), "a directory of the quarantine root")
    _no_link(root, "the quarantine root")
    run_dir = os.path.join(root, req.backup_run)
    _no_link(run_dir, "the backup run")
    reg_dir = os.path.join(run_dir, "registry")
    if os.path.lexists(reg_dir):
        _no_link(reg_dir, "the backup run's registry folder")
    manifest = os.path.join(run_dir, "manifest.json")
    _no_link(manifest, "the backup run's manifest", directory=False)
    if os.path.normcase(os.path.realpath(root)) != os.path.normcase(root):
        raise Refused("the quarantine root is reached through a link")
    for path, what in ((root, "the quarantine root"), (run_dir, "the backup run"),
                       (manifest, "the backup run's manifest")):
        if _owner_sid(path) != sid:
            raise Refused(f"{what} does not belong to the requesting account")
    # The ONLY reads of the run's files, right after their checks; the
    # delete phase uses these in-memory, verified copies (no path is opened
    # or resolved again while the helper scans and deletes).
    backups = _preload_backups(req, run_dir, manifest)
    return _RegistryPlan(list(dict.fromkeys(req.only)), list(dict.fromkeys(req.keys)),
                         req.backup_run, root, backups)


@contextlib.contextmanager
def _helper_registry(guard) -> Iterator[None]:
    with scanmode.helper_mode(), winregistry.using_backend(guard):
        yield


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
_fstat = os.fstat


def _is_under(path: str, root: str) -> bool:
    """Case-insensitive Windows containment test (``path`` inside ``root``)."""
    p = ntpath.normcase(ntpath.normpath(str(path)))
    r = ntpath.normcase(ntpath.normpath(str(root))).rstrip("\\")
    return bool(r) and (p == r or p.startswith(r + "\\"))


def _static_win_dirs():
    """(ProgramData, SystemRoot) for ``static_admin_problem``: the Windows
    API values the helper itself uses, the environment only as a fallback.
    Never raises; an empty string means unknown."""
    try:
        windir, _sysdir, programdata, _pf, _pf86 = _win_known_dirs()
        return programdata, windir
    except Exception:  # noqa: BLE001 - fall back to the (unsanitised) env
        return os.environ.get("ProgramData", ""), os.environ.get("SystemRoot", "")


def static_admin_problem(item, cleaner_id_allowlist=None) -> Optional[str]:
    """Why the helper can NEVER clean ``item``, in plain language, or None.

    Pure and side-effect free (for the GUI, which offers only items this
    accepts): it mirrors the helper's fixed rules -- report-only and
    non-``requires_root`` items, cleaners not on ``admin_cleaner_ids()``
    (pass ``cleaner_id_allowlist`` to compute that once) and, on Windows,
    anything under ProgramData or a non-file under ``Windows\\Temp``. The only
    filesystem access is one ``lstat`` of an existing item under
    ``Windows\\Temp``. Rules that depend on the moment of deletion (parent
    links/junctions, ownership) are still enforced by the helper alone.
    """
    if item.report_only:
        return "Review only: Cleanix never deletes this item"
    if not item.requires_root:
        return "Does not need administrator permission"
    if _is_registry_candidate(item):
        # Registry items have their own allowlist (never the caller's file
        # allowlist): HKLM entries of a registry detector, safety rules pass.
        return _registry_problem(item)
    allowed = admin_cleaner_ids() if cleaner_id_allowlist is None else cleaner_id_allowlist
    if item.cleaner_id not in allowed:
        return _FIXED_LIST_REASON
    if _is_posix() or item.kind is not ItemKind.PATH or not item.path:
        return None
    programdata, system_root = _static_win_dirs()
    if programdata and _is_under(item.path, programdata):
        return ("Cannot be cleaned with administrator permission: items under "
                "ProgramData are never cleaned with administrator rights")
    if system_root and _is_under(item.path, ntpath.join(system_root, "Temp")):
        try:
            st = _lstat(item.path)
        except OSError:
            return None  # gone or not inspectable here: the helper decides
        import stat as _stat

        if (_stat.S_ISDIR(st.st_mode) or not _stat.S_ISREG(st.st_mode)
                or getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT):
            return ("Cannot be cleaned with administrator permission: folders in "
                    "Windows\\Temp are never cleaned with administrator rights")
    return None


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
# findings action (POSIX only)
# --------------------------------------------------------------------------
FINDINGS_NOT_SUPPORTED = ("acting on findings with administrator rights is not "
                          "supported on Windows")
KIND_NOT_SUPPORTED = ("this kind of finding is not handled by the administrator "
                      "helper yet; nothing was done")
NOT_FOUND = "not found by the administrator scan; nothing was done"
CHANGED_SINCE_SCAN = "changed since the scan; nothing was done"
NO_ACTION = "the administrator scan offers no action for this item; nothing was done"
NOT_SYSTEM_WIDE = ("not a system-wide finding (it is acted on without administrator "
                   "rights); nothing was done")
NO_DUPLICATES = "duplicates are not handled by the administrator helper; nothing was done"
STOPPED_WHILE_ACTING = ("the helper stopped while acting on it; it may have been "
                        "removed or moved")
# Remedy kinds (RemedyKind values) the helper acts on. Every other kind is
# refused per item; Task 9 registers the others with their own checks.
_HELPER_FINDING_KINDS = frozenset({"path"})
# The uid that must own the root quarantine (0; a seam for hermetic tests).
_ROOT_UID = 0
_mkdir = os.mkdir


def _findings_supported() -> bool:
    """The one platform gate of the findings action."""
    return _is_posix()


def _is_elevated() -> bool:
    from cleanix.core import utils

    return utils.is_root()


def admin_finding_ids() -> FrozenSet[str]:
    """Scenarios the findings action may act on (see
    ``elevate.admin_finding_ids``); separate from ``admin_cleaner_ids`` and
    ``admin_registry_cleaner_ids``."""
    return elevate.admin_finding_ids()


def finding_path_roots():
    """Per-scenario allowed roots (see ``elevate.finding_path_roots``)."""
    return elevate.finding_path_roots()


def _root_quarantine_location():
    """``(existing system parent, the helper's own folders below it)`` of
    the root-owned quarantine: ``/var/lib/cleanix/quarantine``, on macOS
    ``/Library/Application Support/Cleanix/quarantine``."""
    from cleanix.core.platform import MACOS, current_os

    if current_os() == MACOS:
        return "/Library/Application Support", ("Cleanix", "quarantine")
    return "/var/lib", ("cleanix", "quarantine")


def root_quarantine_never():
    """The helper's own folder and its quarantine: never a finding (a
    request naming them, a folder inside or one containing them refuses)."""
    import posixpath

    parent, own = _root_quarantine_location()
    return (posixpath.join(parent, own[0]), posixpath.join(parent, *own))


@dataclasses.dataclass(frozen=True)
class _FindingsPlan:
    only: List[str]
    items: List[elevate.FindingSelection]
    # key -> reason: items refused up front (kind not handled); never scanned for.
    refused: dict
    permanent: bool


def _prepare_findings(req: elevate.FindingsRequest) -> _FindingsPlan:
    """Validate the findings action from its text alone, BEFORE any
    filesystem access (Refused on any problem; nothing is scanned or
    deleted): POSIX, every scenario on ``admin_finding_ids()``, every key a
    lexically clean path strictly inside one of its scenario's roots
    (``finding_path_roots``) that is neither a protected folder, an
    ancestor of one, nor the helper's own quarantine; and the process runs
    as root. Items of a remedy kind the helper does not handle are refused
    individually (``KIND_NOT_SUPPORTED``)."""
    if not _findings_supported():
        raise Refused(FINDINGS_NOT_SUPPORTED)
    allowed = admin_finding_ids()
    if not req.only or any(c not in allowed for c in req.only):
        raise Refused("the findings part names a scenario the helper does not act on")
    if not req.items:
        raise Refused("the findings part names no item")
    roots = finding_path_roots()
    never = root_quarantine_never()
    refused = {}
    seen = set()
    for sel in req.items:
        try:
            cid, path = elevate.finding_key_parts(sel.key)
        except ValueError:
            raise Refused("the findings part names an invalid item") from None
        if cid not in req.only or sel.key in seen:
            raise Refused("the findings part names an invalid item")
        seen.add(sel.key)
        problem = elevate.finding_path_problem(cid, path, roots, never)
        if problem:
            raise Refused(f"the findings part names a path the helper never acts on ({problem})")
        if sel.kind not in _HELPER_FINDING_KINDS:
            refused[sel.key] = KIND_NOT_SUPPORTED
    if not _is_elevated():
        raise Refused("the helper is not running as root; nothing was removed")
    # Scan only the scenarios that still have an item to act on.
    only = [c for c in req.only
            if any(s.key.split("|", 1)[0] == c and s.key not in refused for s in req.items)]
    return _FindingsPlan(only, list(req.items), refused, bool(req.permanent))


def _finding_problem(item, sel: elevate.FindingSelection, allowed, roots, never):
    """``(status, reason)`` when the helper must not act on its own scan's
    ``item`` (already matched to ``sel`` by key), else None."""
    remedy = item.remedy
    if (not item.report_only or remedy is None or item.kind is not ItemKind.PATH
            or not item.path):
        return "refused", NO_ACTION
    if item.cleaner_id not in allowed:
        return "refused", _FIXED_LIST_REASON
    if not item.requires_root:
        return "refused", NOT_SYSTEM_WIDE
    if remedy.group:
        return "refused", NO_DUPLICATES
    kind = getattr(remedy.kind, "value", None)
    if kind not in _HELPER_FINDING_KINDS or kind != sel.kind:
        return "refused", KIND_NOT_SUPPORTED
    try:
        fp = tuple(int(x) for x in remedy.fingerprint)
    except (TypeError, ValueError):
        return "refused", NO_ACTION
    if fp != tuple(sel.fingerprint):
        return "skipped", CHANGED_SINCE_SCAN
    problem = elevate.finding_path_problem(item.cleaner_id, item.path, roots, never)
    if problem:
        return "refused", f"the helper never acts on this path ({problem})"
    return None


def _own_dir_problem(st, private: bool) -> Optional[str]:
    if _stat_mod.S_ISLNK(st.st_mode):
        return "is a symbolic link"
    if not _stat_mod.S_ISDIR(st.st_mode):
        return "is not a directory"
    if st.st_uid != _ROOT_UID:
        return "is not owned by root"
    if st.st_mode & (0o077 if private else 0o022):
        return "is accessible by other users" if private else "is writable by other users"
    return None


def _prepare_root_quarantine(expected_uid: Optional[int],
                             group_ids: Optional[FrozenSet[int]]) -> Path:
    """Create (if needed) and validate the helper's root-owned quarantine
    directory; Refused on any doubt (then nothing is removed).

    Every component of the system parent (``/var/lib`` or
    ``/Library/Application Support``) must pass the parent-chain rule
    (lstat, no link, modifiable only by root/system accounts). The
    helper's own folders are created ``0700`` if missing and must be real
    directories (never followed), owned by root, the outer one not
    writable and the quarantine itself not accessible by anyone else. The
    quarantine is then opened ``O_DIRECTORY|O_NOFOLLOW`` and the opened
    directory must be the one just checked."""
    import posixpath
    from pathlib import PurePosixPath

    parent, own = _root_quarantine_location()
    parts = PurePosixPath(parent).parts
    for i in range(1, len(parts) + 1):
        comp = str(PurePosixPath(*parts[:i]))
        try:
            st = _lstat(comp)
        except OSError:
            raise Refused(f"{comp} cannot be inspected") from None
        problem = _component_problem(st, expected_uid, group_ids)
        if problem:
            raise Refused(f"{comp} {problem}")
    current = parent
    st = None
    for idx, name in enumerate(own):
        current = posixpath.join(current, name)
        private = idx == len(own) - 1
        try:
            st = _lstat(current)
        except FileNotFoundError:
            try:
                _mkdir(current, 0o700)
            except FileExistsError:
                pass
            except OSError:
                raise Refused(f"{current} could not be created") from None
            try:
                st = _lstat(current)
            except OSError:
                raise Refused(f"{current} cannot be inspected") from None
        except OSError:
            raise Refused(f"{current} cannot be inspected") from None
        problem = _own_dir_problem(st, private)
        if problem:
            raise Refused(f"{current} {problem}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(current, flags)
    except OSError:
        raise Refused(f"{current} could not be opened") from None
    try:
        fst = _fstat(fd)
    finally:
        os.close(fd)
    problem = _own_dir_problem(fst, True)
    if problem or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
        raise Refused(f"{current} changed while it was being checked")
    return Path(current)


def _execute_findings(session: _Session, plan: _FindingsPlan, config, cancel,
                      expected_uid: Optional[int],
                      group_ids: Optional[FrozenSet[int]]) -> bool:
    """The findings action (validated by ``_prepare_findings``). Re-scans
    as root, in helper scan mode, with exactly the requested scenarios, and
    acts ONLY on items of its own scan whose key AND remedy fingerprint
    equal the request's and that pass ``_finding_problem``: one
    ``actions.act`` batch (deletion guard, fingerprint/type re-check and
    the parent-chain check right before each removal), into ONE run in the
    root-owned quarantine (``permanent``: deleted, no quarantine). No
    history, nothing under the user's home. Returns True when the deadline
    stopped it; raises service.Cancelled when it is reached while
    scanning."""
    from cleanix.core import actions

    allowed = admin_finding_ids()
    roots = finding_path_roots()
    never = root_quarantine_never()
    order = [s.key for s in plan.items]
    sels = {s.key: s for s in plan.items}
    out: dict = {}

    def put(key: str, status: str, reason: str = "", freed: int = 0) -> None:
        out[key] = elevate.FindingOutcome(key=key, status=status,
                                          freed=max(0, int(freed)), reason=reason)

    def flush() -> None:
        with session.lock:
            session.findings = [out[k] for k in order if k in out]

    try:
        for key, why in plan.refused.items():
            put(key, "refused", why)
            session.note(refused=1)
        scan_keys = [k for k in order if k not in plan.refused]
        flush()
        if not scan_keys:
            return False
        with scanmode.helper_mode():
            scan = service.scan(config, only=plan.only, cancel=cancel)
        found = {}
        for item in scan.all_items():
            key = item_key(item)
            if key in sels and key not in found:
                found[key] = item
        candidates = []
        for key in scan_keys:
            item = found.get(key)
            if item is None:
                put(key, "not_found", NOT_FOUND)
                session.note(unmatched=1)
                continue
            why = _finding_problem(item, sels[key], allowed, roots, never)
            if why is not None:
                put(key, why[0], why[1])
                if why[0] == "refused":
                    session.note(refused=1)
                else:
                    session.note(unmatched=1)
                continue
            candidates.append(item)
        flush()
        if not candidates:
            return False
        with session.lock:
            session.total += len(candidates)
        qroot = None
        if not plan.permanent:
            try:
                qroot = _prepare_root_quarantine(expected_uid, group_ids)
            except Refused as exc:
                reason = f"the administrator quarantine is not usable ({exc}); nothing was removed"
                for item in candidates:
                    put(item_key(item), "not_removed", reason)
                session.note(error=f"findings not removed: {reason}")
                return False

        def chain(item) -> Optional[str]:
            problem = _path_chain_problem(item.path or "", expected_uid, group_ids)
            return f"untrusted parent directory ({problem})" if problem else None

        # Until an item's fate is known it is reported as possibly acted on:
        # if the watchdog ends the process mid-batch, the result it writes
        # never claims "not removed" for something already moved/deleted.
        for item in candidates:
            put(item_key(item), "not_removed", STOPPED_WHILE_ACTING)
        done = set()

        def on_item(item, outcome, reason) -> None:
            key = item_key(item)
            with session.lock:
                done.add(key)
                session.processed += 1
                if outcome is None or (reason is not None and not outcome.removed):
                    put(key, "skipped", reason or "skipped")
                    session.errors.append(f"{item.description}: skipped: {reason}")
                elif outcome.removed:
                    put(key, "removed", "", outcome.freed)
                    session.freed += max(0, int(outcome.freed))
                    session.removed += 1
                else:
                    # e.g. "partially removed": the bytes really freed count.
                    put(key, "not_removed", outcome.error or "not removed", outcome.freed)
                    session.freed += max(0, int(outcome.freed or 0))
                    session.errors.append(f"{item.description}: {outcome.error}")
                session.findings = [out[k] for k in order if k in out]

        def on_claim(run_id: str) -> None:
            with session.lock:
                session.quarantine_run = str(run_id)

        flush()
        old_mask = os.umask(0o077)
        try:
            summary = actions.act(candidates, config, dry_run=False,
                                  permanent=plan.permanent, cancel=cancel,
                                  record_history=False, allow_root=True,
                                  quarantine_root=qroot, extra_check=chain,
                                  on_item=on_item, on_quarantine_claim=on_claim)
        finally:
            os.umask(old_mask)
        with session.lock:
            # A claimed run that ended up empty was discarded ("").
            session.quarantine_run = str(summary.quarantine_run or "")
        if summary.undo_record_error:
            session.note(error=summary.undo_record_error)
        hit = False
        for item in candidates:
            key = item_key(item)
            if key not in done:
                put(key, "not_removed", "deadline reached; not processed")
                hit = True
        return hit
    finally:
        flush()


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
        # findings action
        self.findings: List[elevate.FindingOutcome] = []
        self.quarantine_run = ""

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
            nonce=self.nonce, deadline_hit=hit, refused=self.refused,
            findings=list(self.findings), quarantine_run=self.quarantine_run)

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
        findings_plan = None
        if selection.findings is not None:
            # Lexical only, BEFORE the user is bound or any of their files
            # (config) is read.
            try:
                findings_plan = _prepare_findings(selection.findings)
            except Refused:
                raise
            except Exception:  # noqa: BLE001 - fail closed, never echo details
                raise Refused("the findings part could not be validated") from None
        name = _check_identity(selection.invoking_user, expected_uid)
        user = _bind_user(name, expected_uid)
        config = _load_config(config_path, Path(user.home), expected_uid)
        reg_plan = None
        if selection.registry is not None:
            try:
                reg_plan = _prepare_registry(selection.registry, session.rdir)
            except Refused:
                raise
            except Exception:  # noqa: BLE001 - fail closed, never echo details
                raise Refused("the registry part could not be validated") from None
    except Refused as exc:
        session.finish([f"request refused: {exc}"])
        return EXIT_REFUSED

    try:
        return _execute(session, selection, config, cancel, deadline, start,
                        expected_uid, _user_groups(user) if _is_posix() else frozenset(),
                        reg_plan, findings_plan)
    except Exception as exc:  # noqa: BLE001
        session.finish([f"internal error in the elevated helper ({type(exc).__name__})"])
        if session.aborted:
            return EXIT_DEADLINE
        return EXIT_INTERNAL


def _eligible(item, allowed: FrozenSet[str],
              reg_allowed: Optional[FrozenSet[str]] = None) -> bool:
    """May the helper clean this (already key-matched) item as admin?
    Registry candidates (REGISTRY items, or any item of a registry detector)
    are judged by the registry rules only (``reg_allowed`` defaults to
    ``admin_registry_cleaner_ids()``); everything else by ``allowed``."""
    if item.report_only or not item.requires_root:
        return False
    if _is_registry_candidate(item):
        return _registry_eligible(
            item, admin_registry_cleaner_ids() if reg_allowed is None else reg_allowed)
    return item.cleaner_id in allowed


def _clamp_command(item, remaining: float):
    """A COMMAND item's timeout never exceeds the time left right now."""
    if item.kind is not ItemKind.COMMAND:
        return item
    limit = min(item.timeout or DEFAULT_COMMAND_TIMEOUT, remaining)
    return dataclasses.replace(item, timeout=max(1, int(limit)))


def _execute_registry(session: _Session, plan: _RegistryPlan, config, cancel,
                      deadline: float, start: float) -> bool:
    """The registry action (validated by ``_prepare_registry``). Re-scans
    as administrator with exactly the requested registry detectors, in
    helper scan mode and through the HKLM-only backend (HKCU is never
    read), and deletes only HKLM items its own scan produced whose key
    (fingerprint included) was requested, each verified against the
    invoking user's backup run (``VerifyOnlySink``). Writes nothing.
    Returns True when the deadline stopped it. Raises service.Cancelled
    when the deadline is reached during the scan."""
    reg_allowed = admin_registry_cleaner_ids()
    wanted = set(plan.keys)
    if not wanted:
        return False
    guard = _MachineOnlyBackend(winregistry.get_backend())
    with _helper_registry(guard):
        scan = service.scan(config, only=plan.only, cancel=cancel)
    matched = set()
    eligible = []
    for item in scan.all_items():
        key = item_key(item)
        if key not in wanted or key in matched:
            continue
        matched.add(key)
        if not _registry_eligible(item, reg_allowed):
            session.note(refused=1)
            continue
        eligible.append(item)
    session.note(unmatched=len(wanted - matched))
    with session.lock:
        session.total += len(eligible)
    for item in eligible:
        if deadline - (_monotonic() - start) <= 0 or cancel():
            return True
        with _helper_registry(guard):
            summary = service.clean([item], config, dry_run=False, use_quarantine=False,
                                    record_history=False, registry_backup_elsewhere=True,
                                    registry_backup_run=plan.backup_run,
                                    registry_verified_backups=plan.backups,
                                    cancel=cancel)
        if not summary.result.outcomes:
            return True
        session.record(summary)
    return False


def _execute(session: _Session, selection: elevate.Selection, config, cancel,
             deadline: float, start: float, expected_uid: Optional[int],
             group_ids: Optional[FrozenSet[int]],
             reg_plan: Optional[_RegistryPlan] = None,
             findings_plan: Optional["_FindingsPlan"] = None) -> int:
    def finish(extra=(), hit=False) -> int:
        ok = session.finish(extra, hit)
        if session.aborted:
            return EXIT_DEADLINE  # the watchdog already wrote the result
        if not ok:
            return EXIT_INTERNAL
        return EXIT_DEADLINE if hit else EXIT_OK

    if findings_plan is not None:
        # Exclusive (parse_request refuses a findings request with other
        # items): nothing else is scanned or cleaned in this run.
        try:
            if _execute_findings(session, findings_plan, config, cancel,
                                 expected_uid, group_ids):
                return finish(["deadline reached; the remaining findings were not removed"],
                              hit=True)
        except service.Cancelled:
            return finish(["deadline reached while scanning; nothing was removed"], hit=True)
        return finish()

    if reg_plan is not None:
        try:
            if _execute_registry(session, reg_plan, config, cancel, deadline, start):
                return finish(["deadline reached; the remaining items were not cleaned"],
                              hit=True)
        except service.Cancelled:
            return finish(["deadline reached while scanning; nothing more was cleaned"],
                          hit=True)

    allowed = admin_cleaner_ids()
    wanted = set(selection.keys)
    # Keys of cleaners the helper never runs (incl. every registry detector:
    # registry entries come only through the registry action) are refused
    # without scanning.
    pre_refused = {k for k in wanted if k.split("|", 1)[0] not in allowed}
    scan_keys = wanted - pre_refused
    only = [c for c in dict.fromkeys(selection.only) if c in allowed]
    session.note(refused=len(pre_refused))

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
        # Registry entries are never deleted by the file path (no backup
        # verification there): an empty registry allowlist refuses them.
        if item.kind is ItemKind.REGISTRY or not _eligible(item, allowed, frozenset()):
            session.note(refused=1)
            continue
        eligible.append(item)
    session.note(unmatched=len(scan_keys - matched_keys))
    with session.lock:
        session.total += len(eligible)

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
        # Before any scan, for every thread (the engine scans on a pool):
        # registry detectors never read HKCU and judge evidence with
        # owner_matches=False in this process (R15).
        scanmode.enable_process_helper_mode()
        rc = _main(argv)
    except BaseException:  # noqa: BLE001 - incl. SystemExit/KeyboardInterrupt
        return EXIT_INTERNAL
    if not isinstance(rc, int) or isinstance(rc, bool) or rc not in _ALLOWED_EXITS:
        return EXIT_INTERNAL
    return rc


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
