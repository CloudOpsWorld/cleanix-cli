"""Request/result files exchanged with the elevated helper.

The unprivileged GUI writes a *request* naming only cleaner ids and item keys
(never anything to execute); the helper, running as root/Administrator,
re-scans and deletes only items that match. An optional ``registry`` part
(Windows) names registry detector ids, HKLM item keys, the id of the
quarantine run holding the GUI's backups and the user's quarantine root
(see ``RegistryRequest``). Because the request lives in a
user-writable place, everything read here is validated strictly and treated
as untrusted:

* POSIX: the request is opened with ``O_NOFOLLOW`` and the *opened* file is
  checked (regular file, owned by the expected uid, not group/world writable).
* The size is capped and every field is type-checked; unknown fields refuse.
* Error messages never quote file contents.

Both files are written atomically (temp file in the same directory, then
``os.replace``). The result is written by root into the request directory,
which is checked through a directory descriptor so it cannot be redirected.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import stat
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

REQUEST_NAME = "request.json"
RESULT_NAME = "result.json"
FORMAT_VERSION = 1
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024
MAX_KEYS = 100_000
MAX_KEY_LEN = 8192
MAX_ERRORS = 200
MAX_ERROR_LEN = 500

_NONCE_RE = re.compile(r"[0-9a-f]{32}")
_CLEANER_ID_RE = re.compile(r"[A-Za-z0-9_]{1,64}")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_REQUEST_FIELDS = {"version", "invoking_user", "only", "keys", "use_quarantine", "nonce"}
# The optional registry action (HKLM registry deletions, Windows only).
REGISTRY_FIELD = "registry"
_REGISTRY_FIELDS = {"only", "keys", "backup_run", "quarantine_root"}
MAX_ROOT_LEN = 1024
# The optional findings action (system-wide report-only findings, POSIX
# only; see ``FindingsRequest``).
FINDINGS_FIELD = "findings"
_FINDINGS_FIELDS = {"only", "items", "permanent"}
_FINDING_ITEM_FIELDS = {"key", "fingerprint", "kind"}
MAX_FINDING_SCENARIOS = 16
MAX_FINDING_ITEMS = 1000
MAX_FINDING_PATH_LEN = 1024
MAX_FINDING_COMPONENT_BYTES = 255
# Every RemedyKind value (the request may name any; the helper refuses, per
# item, the kinds it does not handle yet).
FINDING_KINDS = frozenset({"path", "launch_job", "systemd_unit", "pkg_receipt"})
FINDING_STATUSES = frozenset({"removed", "not_removed", "skipped", "refused", "not_found"})
_FP_MIN = -(2 ** 63)
_FP_MAX = 2 ** 64
# Report-only cleaners whose findings can be system-wide (requires_root).
SYSTEM_FINDING_IDS = frozenset({
    "orphan_files", "orphan_app_data", "stale_launchers", "stale_services",
    "orphan_launch_jobs", "stale_receipts",
})

_POSIX = os.name != "nt"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_lstat = os.lstat


def new_nonce() -> str:
    return uuid.uuid4().hex


@dataclass
class RegistryRequest:
    """The registry action: delete machine-wide (HKLM) registry entries.

    Identifiers only: registry detector ids, the item keys the user ticked
    (each embeds hive, key, value and fingerprint), the id of the quarantine
    run in which the GUI, as the user, already backed the entries up, and
    the invoking user's quarantine root (validated by the helper against the
    profile of the account that owns the request directory).
    """

    only: List[str]
    keys: List[str]
    backup_run: str
    quarantine_root: str


@dataclass(frozen=True)
class FindingSelection:
    """One finding the user ticked: its item key (``<cleaner>|path|<path>``),
    the remedy fingerprint seen by the caller's scan and the remedy kind
    (a ``RemedyKind`` value). Identifiers only: the helper acts on its OWN
    scan's item with this key and fingerprint, never on this claim."""

    key: str
    fingerprint: Tuple[int, int, int, int]
    kind: str


@dataclass
class FindingsRequest:
    """The findings action: act on system-wide (requires_root) report-only
    findings (POSIX only). ``only`` names the scenarios (report-only cleaner
    ids) the helper re-scans; ``permanent`` deletes instead of moving into
    the helper's root-owned quarantine. There is deliberately NO quarantine
    or home path here: the helper chooses its own root-owned location and
    writes nothing under the invoking user's home."""

    only: List[str]
    items: List[FindingSelection]
    permanent: bool = False


@dataclass
class FindingOutcome:
    """Per-item result of the findings action. ``status`` is one of
    ``FINDING_STATUSES``; ``key`` is the request's own (validated) key."""

    key: str
    status: str
    freed: int = 0
    reason: str = ""


@dataclass
class Selection:
    invoking_user: str
    only: List[str]
    keys: List[str]
    # Kept in the schema for compatibility but IGNORED by the helper: it
    # always deletes without quarantine (a root-owned quarantine/history under
    # the user's home would be a root file-placement primitive).
    use_quarantine: bool
    nonce: str = field(default_factory=new_nonce)
    registry: Optional[RegistryRequest] = None
    # Exclusive: a request with a findings part has empty only/keys and no
    # registry part.
    findings: Optional[FindingsRequest] = None


@dataclass
class HelperResult:
    freed: int
    removed: int
    errors: List[str]
    unmatched: int
    nonce: str = ""
    deadline_hit: bool = False
    # Requested keys that matched the fresh scan but are not eligible for an
    # elevated clean (report-only, or not requiring admin rights).
    refused: int = 0
    # Findings action only: one outcome per requested item (request order)
    # and the id of the run in the helper's root-owned quarantine ("" when
    # nothing was moved there).
    findings: List[FindingOutcome] = field(default_factory=list)
    quarantine_run: str = ""


# --------------------------------------------------------------------------
# low-level helpers
# --------------------------------------------------------------------------
def _check_secure(st, expected_uid: Optional[int], what: str, *,
                  allow_root: bool = False) -> None:
    """Refuse a file/dir not owned by ``expected_uid`` (or root when allowed)
    or writable by group/others. ``expected_uid=None`` skips the owner test."""
    if expected_uid is not None:
        owners = {expected_uid, 0} if allow_root else {expected_uid}
        if st.st_uid not in owners:
            raise ValueError(f"{what} is not owned by the requesting user")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"{what} is writable by other users")


def read_secure(path: Path, *, expected_uid: Optional[int], max_bytes: int,
                what: str, allow_root: bool = False,
                dir_fd: Optional[int] = None) -> bytes:
    """Read a small regular file, refusing links and (POSIX) foreign owners.

    With ``dir_fd`` (POSIX) only ``path.name`` is opened, relative to that
    already-validated directory descriptor."""
    path = Path(path)
    if _POSIX:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            if dir_fd is not None:
                fd = os.open(path.name, flags, dir_fd=dir_fd)
            else:
                fd = os.open(str(path), flags)
        except OSError as exc:
            raise ValueError(f"{what} could not be opened") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(f"{what} is not a regular file")
            _check_secure(st, expected_uid, what, allow_root=allow_root)
            if st.st_size > max_bytes:
                raise ValueError(f"{what} is too large")
            data = _read_all(fd, max_bytes)
        finally:
            os.close(fd)
        return data
    from cleanix.core import safety

    if safety.is_reparse_point(path):
        raise ValueError(f"{what} is a link")
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise ValueError(f"{what} is not a regular file")
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        raise ValueError(f"{what} could not be opened") from exc
    try:
        return _read_all(fd, max_bytes, what)
    finally:
        os.close(fd)


def _read_all(fd: int, max_bytes: int, what: str = "file") -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"{what} is too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _atomic_write(path: Path, data: bytes, mode: int, *,
                  dir_uid: Optional[int] = None, dir_fd: Optional[int] = None) -> None:
    """Write ``data`` to ``path`` via a temp file in the same directory and
    ``os.replace``. On POSIX the directory is opened with ``O_NOFOLLOW`` (or
    the given, already-validated ``dir_fd`` is used) and, when ``dir_uid`` is
    given, must be owned by it and not group/world writable; all file
    operations are relative to that descriptor."""
    path = Path(path)
    parent = path.parent
    tmp_name = f".{path.name}.{uuid.uuid4().hex}.tmp"
    if _POSIX:
        dflags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        own_fd = dir_fd is None
        dfd = os.open(str(parent), dflags) if own_fd else dir_fd
        try:
            st = os.fstat(dfd)
            if not stat.S_ISDIR(st.st_mode):
                raise ValueError("result directory is not a directory")
            if dir_uid is not None:
                _check_secure(st, dir_uid, "result directory")
            fflags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                      | getattr(os, "O_NOFOLLOW", 0))
            fd = os.open(tmp_name, fflags, mode, dir_fd=dfd)
            try:
                try:
                    os.fchmod(fd, mode)
                    _write_all(fd, data)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.replace(tmp_name, path.name, src_dir_fd=dfd, dst_dir_fd=dfd)
            except BaseException:
                try:
                    os.unlink(tmp_name, dir_fd=dfd)
                except OSError:
                    pass
                raise
        finally:
            if own_fd:
                os.close(dfd)
        return
    tmp = parent / tmp_name
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                 mode)
    try:
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(str(tmp), str(path))
    except BaseException:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise


def plain_text(message: str) -> str:
    """Single-line, bounded, control-character-free text for the result."""
    text = _CONTROL_RE.sub(" ", str(message))
    return text[:MAX_ERROR_LEN]


# --------------------------------------------------------------------------
# request
# --------------------------------------------------------------------------
def make_request_dir() -> Path:
    """A fresh private (0700) directory for one request/result exchange."""
    base = None
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if _POSIX and runtime:
        try:
            st = os.stat(runtime)
            if (stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid()
                    and not st.st_mode & 0o077):
                base = runtime
        except OSError:
            base = None
    # realpath: the helper refuses a request reached through a symlinked
    # parent (e.g. macOS /var -> /private/var), so hand out the real path.
    return Path(os.path.realpath(tempfile.mkdtemp(prefix="cleanix-elevate-", dir=base)))


def write_request(directory: Path, selection: Selection) -> Path:
    payload = {
        "version": FORMAT_VERSION,
        "invoking_user": selection.invoking_user,
        "only": list(selection.only),
        "keys": list(selection.keys),
        "use_quarantine": bool(selection.use_quarantine),
        "nonce": selection.nonce,
    }
    reg = selection.registry
    if reg is not None:
        payload[REGISTRY_FIELD] = {
            "only": list(reg.only),
            "keys": list(reg.keys),
            "backup_run": reg.backup_run,
            "quarantine_root": reg.quarantine_root,
        }
    fnd = selection.findings
    if fnd is not None:
        payload[FINDINGS_FIELD] = {
            "only": list(fnd.only),
            "items": [{"key": s.key, "fingerprint": [int(x) for x in s.fingerprint],
                       "kind": s.kind} for s in fnd.items],
            "permanent": bool(fnd.permanent),
        }
    path = Path(directory) / REQUEST_NAME
    _atomic_write(path, json.dumps(payload).encode("utf-8"), 0o600)
    return path


def _str_list(value, name: str, pattern=None, max_len: int = MAX_KEY_LEN) -> List[str]:
    if not isinstance(value, list) or len(value) > MAX_KEYS:
        raise ValueError(f"request field '{name}' is invalid")
    for v in value:
        if not isinstance(v, str) or not v or len(v) > max_len:
            raise ValueError(f"request field '{name}' is invalid")
        if pattern is not None and not pattern.fullmatch(v):
            raise ValueError(f"request field '{name}' is invalid")
        if "\x00" in v:
            raise ValueError(f"request field '{name}' is invalid")
    return list(value)


_WIN_DRIVE_ROOT = re.compile(r"[A-Za-z]:\\")
_WIN_RESERVED = frozenset(
    {"con", "prn", "aux", "nul", "conin$", "conout$"}
    | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}
    # Windows also maps the superscript digits (COM¹-³, LPT¹-³) to devices.
    | {f"{d}{s}" for d in ("com", "lpt") for s in ("¹", "²", "³")}
)


def is_local_absolute_path(path) -> bool:
    """Purely LEXICAL test (never touches the filesystem): is ``path`` an
    absolute path on a local drive?

    Windows: ``X:\\...`` only -- no UNC (``\\\\server\\share``, WebDAV
    ``\\\\host@80\\...``), no ``\\\\?\\`` / ``\\\\.\\`` device or GLOBALROOT
    paths, no forward slashes, no second ``:`` (alternate data streams),
    no empty components, no component ending in a dot or a space (Win32
    strips them, so they alias other names) and no reserved device names
    (``CON``, ``NUL``, ``COM1``, ``COM¹`` ...), judged on the part before the
    first dot -- so a profile such as ``C:\\Users\\con.CORP`` is refused
    (fail closed). Opening any of those as an
    administrator could reach the network (and leak the administrator's
    NTLM credentials) or a device. POSIX: a ``/`` path that does not start
    with ``//``."""
    if not isinstance(path, str) or not path or "\x00" in path:
        return False
    if _POSIX:
        return path.startswith("/") and not path.startswith("//")
    if not _WIN_DRIVE_ROOT.match(path) or "/" in path:
        return False
    rest = path[3:]
    if not rest:
        return True
    if ":" in rest:
        return False
    for comp in rest.split("\\"):
        if not comp or comp.endswith((".", " ")):
            return False
        if comp.split(".", 1)[0].rstrip(" ").casefold() in _WIN_RESERVED:
            return False
    return True


def registry_key_parts(key: str):
    """``(cleaner_id, hive, key, value, fingerprint)`` of a REGISTRY item key
    (``models.item_key``). Raises ValueError for anything else."""
    if not isinstance(key, str):
        raise ValueError("not a registry item key")
    parts = key.split("|", 2)
    if len(parts) != 3 or parts[1] != "reg" or not _CLEANER_ID_RE.fullmatch(parts[0]):
        raise ValueError("not a registry item key")
    try:
        fields = json.loads(parts[2])
    except ValueError:
        raise ValueError("not a registry item key") from None
    if not isinstance(fields, list) or len(fields) != 4:
        raise ValueError("not a registry item key")
    hive, reg_key, value, fingerprint = fields
    if (not isinstance(hive, str) or not isinstance(reg_key, str) or not reg_key
            or not (value is None or isinstance(value, str))
            or not isinstance(fingerprint, str) or not fingerprint):
        raise ValueError("not a registry item key")
    return parts[0], hive, reg_key, value, fingerprint


def _parse_registry(obj) -> RegistryRequest:
    """The registry action. HKLM only: a key naming any other hive (or any
    malformed part) refuses the WHOLE request, so nothing is deleted."""
    from cleanix.core.regclean import _RUN_ID

    if not isinstance(obj, dict) or set(obj) != _REGISTRY_FIELDS:
        raise ValueError("request field 'registry' has missing or unexpected fields")
    only = _str_list(obj["only"], "registry.only", _CLEANER_ID_RE, 64)
    keys = _str_list(obj["keys"], "registry.keys")
    if not only:
        raise ValueError("request field 'registry.only' is invalid")
    for key in keys:
        try:
            cid, hive, _k, _v, _fp = registry_key_parts(key)
        except ValueError:
            raise ValueError("request field 'registry.keys' is invalid") from None
        if hive != "HKLM":
            raise ValueError("request field 'registry.keys' names a non-HKLM entry")
        if cid not in only:
            raise ValueError("request field 'registry.keys' is invalid")
    run = obj["backup_run"]
    if not isinstance(run, str) or not _RUN_ID.match(run) or run in (".", ".."):
        raise ValueError("request field 'registry.backup_run' is invalid")
    root = obj["quarantine_root"]
    if (not isinstance(root, str) or not root or len(root) > MAX_ROOT_LEN
            or _CONTROL_RE.search(root) or not is_local_absolute_path(root)):
        raise ValueError("request field 'registry.quarantine_root' is invalid")
    return RegistryRequest(only=only, keys=keys, backup_run=run, quarantine_root=root)


# --------------------------------------------------------------------------
# findings action: purely lexical checks (never touch the filesystem)
# --------------------------------------------------------------------------
def _bad_char(c: str) -> bool:
    o = ord(c)
    # C0/C1 controls, DEL, lone surrogates (non-UTF-8 names arriving through
    # JSON) and the Unicode line/paragraph separators.
    return (o < 0x20 or 0x7F <= o <= 0x9F or 0xD800 <= o <= 0xDFFF
            or o in (0x2028, 0x2029))


def posix_path_problem(path) -> Optional[str]:
    """Why ``path`` is not an acceptable POSIX path for the findings action,
    judged from its text alone (``posixpath``, also on Windows), or None.

    Accepted: absolute (one leading ``/``), already normalised (no trailing
    slash, no ``//``, ``.`` or ``..`` component), no control characters,
    surrogates or line separators, at most ``MAX_FINDING_PATH_LEN``
    characters and ``MAX_FINDING_COMPONENT_BYTES`` bytes per component,
    and never the filesystem root itself."""
    if not isinstance(path, str) or not path:
        return "not a path"
    if len(path) > MAX_FINDING_PATH_LEN:
        return "the path is too long"
    if any(_bad_char(c) for c in path):
        return "the path contains control or invalid characters"
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return "the path is not valid UTF-8"
    if not path.startswith("/") or path.startswith("//"):
        return "the path is not absolute"
    if path == "/":
        return "the path is the filesystem root"
    if posixpath.normpath(path) != path:
        return "the path is not normalised"
    for comp in path.split("/")[1:]:
        if comp in ("", ".", ".."):
            return "the path is not normalised"
        if len(comp.encode("utf-8")) > MAX_FINDING_COMPONENT_BYTES:
            return "a path component is too long"
    return None


def finding_key_parts(key) -> Tuple[str, str]:
    """``(cleaner_id, path)`` of a PATH item key (``models.item_key``:
    ``<cleaner>|path|<path>``) with a lexically acceptable POSIX path.
    Raises ValueError for anything else."""
    if not isinstance(key, str) or len(key) > 64 + 6 + MAX_FINDING_PATH_LEN:
        raise ValueError("not a finding key")
    parts = key.split("|", 2)
    if len(parts) != 3 or parts[1] != "path" or not _CLEANER_ID_RE.fullmatch(parts[0]):
        raise ValueError("not a finding key")
    problem = posix_path_problem(parts[2])
    if problem:
        raise ValueError(f"not a finding key: {problem}")
    return parts[0], parts[2]


def _parse_fingerprint(value) -> Tuple[int, int, int, int]:
    if not isinstance(value, list) or len(value) != 4:
        raise ValueError("request field 'findings.items.fingerprint' is invalid")
    for v in value:
        if type(v) is not int or not _FP_MIN <= v < _FP_MAX:  # bool is refused
            raise ValueError("request field 'findings.items.fingerprint' is invalid")
    if all(v == 0 for v in value):
        raise ValueError("request field 'findings.items.fingerprint' is invalid")
    return (value[0], value[1], value[2], value[3])


def _parse_findings(obj) -> FindingsRequest:
    """The findings action. Exact fields and types, bounded sizes, every
    key a ``<cleaner>|path|<path>`` key of a listed scenario with a
    lexically acceptable path, no key twice; anything else refuses the
    WHOLE request (nothing is scanned or deleted)."""
    if not isinstance(obj, dict) or set(obj) != _FINDINGS_FIELDS:
        raise ValueError("request field 'findings' has missing or unexpected fields")
    only = _str_list(obj["only"], "findings.only", _CLEANER_ID_RE, 64)
    if not only or len(only) > MAX_FINDING_SCENARIOS or len(set(only)) != len(only):
        raise ValueError("request field 'findings.only' is invalid")
    if not isinstance(obj["permanent"], bool):
        raise ValueError("request field 'findings.permanent' is invalid")
    raw = obj["items"]
    if not isinstance(raw, list) or not raw or len(raw) > MAX_FINDING_ITEMS:
        raise ValueError("request field 'findings.items' is invalid")
    items: List[FindingSelection] = []
    seen = set()
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) != _FINDING_ITEM_FIELDS:
            raise ValueError("request field 'findings.items' is invalid")
        key = entry["key"]
        try:
            cid, _path = finding_key_parts(key)
        except ValueError:
            raise ValueError("request field 'findings.items.key' is invalid") from None
        if cid not in only:
            raise ValueError("request field 'findings.items.key' names an unlisted scenario")
        if key in seen:
            raise ValueError("request field 'findings.items' lists an item twice")
        seen.add(key)
        kind = entry["kind"]
        if not isinstance(kind, str) or kind not in FINDING_KINDS:
            raise ValueError("request field 'findings.items.kind' is invalid")
        items.append(FindingSelection(key=key, fingerprint=_parse_fingerprint(
            entry["fingerprint"]), kind=kind))
    return FindingsRequest(only=only, items=items, permanent=obj["permanent"])


def findings_request_for(items: Sequence, *, permanent: bool = False) -> FindingsRequest:
    """The findings part for ``items`` (report-only PATH items with a
    remedy), as the unprivileged caller builds it. Raises ValueError for an
    item that cannot be named (no remedy, no lexically acceptable key)."""
    from cleanix.core.models import item_key

    only: List[str] = []
    sels: List[FindingSelection] = []
    for item in items:
        remedy = getattr(item, "remedy", None)
        if remedy is None or not getattr(item, "report_only", False):
            raise ValueError("only findings with a remedy can be requested")
        key = item_key(item)
        cid, _path = finding_key_parts(key)
        if cid not in only:
            only.append(cid)
        fp = tuple(int(x) for x in remedy.fingerprint)
        sels.append(FindingSelection(key=key, fingerprint=fp,  # type: ignore[arg-type]
                                     kind=str(remedy.kind.value)))
    return FindingsRequest(only=only, items=sels, permanent=bool(permanent))


def admin_finding_ids() -> FrozenSet[str]:
    """Scenarios whose system-wide findings the helper may act on: the
    report-only cleaners in ``SYSTEM_FINDING_IDS`` that have a finding
    category and support this platform. POSIX only (empty on Windows).
    Separate from ``admin_cleaner_ids()`` (ordinary admin cleaners) and
    ``admin_registry_cleaner_ids()`` (registry detectors)."""
    from cleanix.config import Config
    from cleanix.core import platform as plat
    from cleanix.core import registry
    from cleanix.core.findings import FINDING_CATEGORIES

    if plat.is_windows():
        return frozenset()
    ids = set()
    for cls in registry.ALL_CLEANERS:
        cid = cls.id
        if cid not in SYSTEM_FINDING_IDS or cid not in FINDING_CATEGORIES:
            continue
        try:
            inst = cls(Config())
        except Exception:  # noqa: BLE001
            continue
        if inst.supported():
            ids.add(cid)
    return frozenset(ids)


def finding_path_roots() -> Dict[str, Tuple[str, ...]]:
    """Per scenario, the system directories under which its system-wide
    findings lie, taken from the detectors' own constants (never invented
    here). A findings path must lie STRICTLY below one of its scenario's
    roots. A scenario with no PATH findings has no roots."""
    from cleanix.cleaners import (
        orphan_app_data,
        orphan_files,
        orphan_launch_jobs,
        stale_launchers,
        stale_receipts,
        stale_services,
    )

    return {
        "orphan_files": tuple(orphan_files._ROOTS),
        "orphan_app_data": tuple(orphan_app_data.SYSTEM_DIRS),
        "stale_launchers": (stale_launchers._LOCAL_DIR,) + tuple(stale_launchers._OWNED_DIRS),
        "stale_services": tuple(stale_services._SYSTEM_SCAN),
        "orphan_launch_jobs": tuple(orphan_launch_jobs.SYSTEM_DIRS),
        "stale_receipts": (stale_receipts.RECEIPTS_DIR,),
    }


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def finding_path_problem(cleaner_id: str, path: str,
                         roots: Dict[str, Tuple[str, ...]],
                         never: Sequence[str] = ()) -> Optional[str]:
    """Why the helper never acts on ``path`` for ``cleaner_id`` (lexical
    only), or None. ``path`` must be acceptable to ``posix_path_problem``,
    lie strictly below one of the scenario's ``roots``, and be neither
    equal to nor an ancestor of a protected root (``safety._PROTECTED``),
    any scenario's root, the standard ``/usr/local`` folders or a path in
    ``never`` (the helper's own quarantine); nor lie inside a ``never``
    path."""
    from cleanix.cleaners import orphan_files
    from cleanix.core import safety

    problem = posix_path_problem(path)
    if problem:
        return problem
    own = roots.get(cleaner_id, ())
    if not any(path != r and _under(path, r) for r in own):
        return "it is not inside a folder this scenario reports on"
    fixed = set(safety._PROTECTED)
    for rs in roots.values():
        fixed.update(rs)
    fixed.update(f"/usr/local/{d}" for d in orphan_files._USR_LOCAL_STD)
    fixed.update(never)
    for p in fixed:
        if _under(p, path):
            return "it is, or contains, a protected folder"
    for p in never:
        if _under(path, p):
            return "it is inside the administrator quarantine"
    return None


def parse_request(data: bytes) -> Selection:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("request is not valid JSON") from None
    if not isinstance(obj, dict) or (set(obj) != _REQUEST_FIELDS
                                     and set(obj) != _REQUEST_FIELDS | {REGISTRY_FIELD}
                                     and set(obj) != _REQUEST_FIELDS | {FINDINGS_FIELD}):
        raise ValueError("request has missing or unexpected fields")
    if obj["version"] != FORMAT_VERSION or isinstance(obj["version"], bool):
        raise ValueError("request version is not supported")
    user = obj["invoking_user"]
    if (not isinstance(user, str) or not user or len(user) > 256
            or _CONTROL_RE.search(user) or "/" in user):
        raise ValueError("request field 'invoking_user' is invalid")
    if not isinstance(obj["use_quarantine"], bool):
        raise ValueError("request field 'use_quarantine' is invalid")
    nonce = obj["nonce"]
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        raise ValueError("request field 'nonce' is invalid")
    only = _str_list(obj["only"], "only", _CLEANER_ID_RE, 64)
    keys = _str_list(obj["keys"], "keys")
    findings = None
    if FINDINGS_FIELD in obj:
        # Exclusive: never combined with ordinary admin items.
        if only or keys:
            raise ValueError("request combines findings with other items")
        findings = _parse_findings(obj[FINDINGS_FIELD])
    return Selection(
        invoking_user=user,
        only=only,
        keys=keys,
        use_quarantine=obj["use_quarantine"],
        nonce=nonce,
        registry=(_parse_registry(obj[REGISTRY_FIELD])
                  if REGISTRY_FIELD in obj else None),
        findings=findings,
    )


def read_request(path: Path, *, expected_uid: Optional[int]) -> Selection:
    """Read and validate a request. Raises ValueError on anything suspicious.

    POSIX: the file must be a regular file (not a symlink) owned by
    ``expected_uid`` and not group/world writable. Windows: no owner check.
    """
    data = read_secure(Path(path), expected_uid=expected_uid if _POSIX else None,
                       max_bytes=MAX_REQUEST_BYTES, what="request")
    return parse_request(data)


class RequestDir:
    """The request directory, validated ONCE and then used by descriptor.

    POSIX: the absolute path must equal its realpath (no symlinked parent
    components); it is opened ``O_DIRECTORY|O_NOFOLLOW`` and the opened
    directory must be owned by ``expected_uid`` and not group/world writable.
    ``request.json`` is read and ``result.json`` written relative to that
    descriptor, so renaming or swapping the path afterwards has no effect.
    Windows: refused if the directory or any parent is a reparse point.
    Raises ValueError on any failure.
    """

    def __init__(self, directory: Path, expected_uid: Optional[int]):
        self.path = Path(os.path.abspath(str(directory)))
        self.expected_uid = expected_uid
        self.fd: Optional[int] = None
        if _POSIX:
            if expected_uid is None:
                raise ValueError("the requesting uid is unknown")
            if os.path.realpath(str(self.path)) != str(self.path):
                raise ValueError("request directory is reached through a symbolic link")
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(str(self.path), flags)
            except OSError:
                raise ValueError("request directory could not be opened") from None
            try:
                st = os.fstat(fd)
                if not stat.S_ISDIR(st.st_mode):
                    raise ValueError("request directory is not a directory")
                _check_secure(st, expected_uid, "request directory")
            except BaseException:
                os.close(fd)
                raise
            self.fd = fd
            return
        # Fail closed: a component that cannot be inspected is a refusal.
        for p in (self.path, *self.path.parents):
            try:
                st = _lstat(str(p))
            except OSError:
                raise ValueError("request directory path cannot be inspected") from None
            if getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
                raise ValueError("request directory path contains a link or junction")
        if not self.path.is_dir():
            raise ValueError("request directory is not a directory")

    def read_request(self) -> Selection:
        data = read_secure(self.path / REQUEST_NAME,
                           expected_uid=self.expected_uid if _POSIX else None,
                           max_bytes=MAX_REQUEST_BYTES, what="request", dir_fd=self.fd)
        return parse_request(data)

    def write_result(self, result: "HelperResult") -> None:
        data = json.dumps(_result_payload(result)).encode("utf-8")
        _atomic_write(self.path / RESULT_NAME, data, 0o644, dir_fd=self.fd,
                      dir_uid=self.expected_uid if _POSIX else None)

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            finally:
                self.fd = None


# --------------------------------------------------------------------------
# result
# --------------------------------------------------------------------------
def _result_payload(result: HelperResult) -> dict:
    return {
        "version": FORMAT_VERSION,
        "nonce": str(result.nonce),
        "freed": int(result.freed),
        "removed": int(result.removed),
        "unmatched": int(result.unmatched),
        "refused": int(result.refused),
        "deadline_hit": bool(result.deadline_hit),
        "errors": [plain_text(e) for e in list(result.errors)[:MAX_ERRORS]],
        "findings": [
            {"key": str(o.key), "status": str(o.status), "freed": max(0, int(o.freed)),
             "reason": plain_text(o.reason)}
            for o in list(result.findings)[:MAX_FINDING_ITEMS]
        ],
        "quarantine_run": str(result.quarantine_run),
    }


_RESULT_RUN_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,127}")


def _parse_finding_outcomes(value) -> List[FindingOutcome]:
    if not isinstance(value, list) or len(value) > MAX_FINDING_ITEMS:
        raise ValueError("result field 'findings' is invalid")
    out: List[FindingOutcome] = []
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"key", "status", "freed", "reason"}:
            raise ValueError("result field 'findings' is invalid")
        key, status, freed, reason = (entry["key"], entry["status"], entry["freed"],
                                      entry["reason"])
        if (not isinstance(key, str) or len(key) > 64 + 6 + MAX_FINDING_PATH_LEN
                or status not in FINDING_STATUSES or not isinstance(reason, str)
                or type(freed) is not int or freed < 0):
            raise ValueError("result field 'findings' is invalid")
        out.append(FindingOutcome(key=key, status=status, freed=freed,
                                  reason=plain_text(reason)))
    return out


def write_result(path: Path, result: HelperResult, *,
                 dir_uid: Optional[int] = None) -> None:
    """Atomically write the result (mode 0644 so the unprivileged GUI can read
    it). ``dir_uid`` (POSIX) requires the directory to belong to that user."""
    data = json.dumps(_result_payload(result)).encode("utf-8")
    _atomic_write(Path(path), data, 0o644, dir_uid=dir_uid if _POSIX else None)


def read_result(path: Path) -> HelperResult:
    data = read_secure(Path(path), expected_uid=None, max_bytes=MAX_RESULT_BYTES,
                       what="result")
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("result is not valid JSON") from None
    if not isinstance(obj, dict):
        raise ValueError("result is invalid")

    def num(name):
        v = obj.get(name, 0)
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise ValueError(f"result field '{name}' is invalid")
        return v

    errors = obj.get("errors", [])
    if not isinstance(errors, list) or not all(isinstance(e, str) for e in errors):
        raise ValueError("result field 'errors' is invalid")
    nonce = obj.get("nonce", "")
    deadline_hit = obj.get("deadline_hit", False)
    if not isinstance(nonce, str) or not isinstance(deadline_hit, bool):
        raise ValueError("result is invalid")
    run = obj.get("quarantine_run", "")
    if not isinstance(run, str) or (run and not _RESULT_RUN_RE.fullmatch(run)):
        raise ValueError("result field 'quarantine_run' is invalid")
    return HelperResult(
        freed=num("freed"), removed=num("removed"),
        errors=[plain_text(e) for e in errors[:MAX_ERRORS]],
        unmatched=num("unmatched"), nonce=nonce, deadline_hit=deadline_hit,
        refused=num("refused"),
        findings=_parse_finding_outcomes(obj.get("findings", [])),
        quarantine_run=run,
    )
