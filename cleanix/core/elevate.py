"""Request/result files exchanged with the elevated helper.

The unprivileged GUI writes a *request* naming only cleaner ids and item keys
(never anything to execute); the helper, running as root/Administrator,
re-scans and deletes only items that match. Because the request lives in a
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
import re
import stat
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

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

_POSIX = os.name != "nt"


def new_nonce() -> str:
    return uuid.uuid4().hex


@dataclass
class Selection:
    invoking_user: str
    only: List[str]
    keys: List[str]
    use_quarantine: bool
    nonce: str = field(default_factory=new_nonce)


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
                what: str, allow_root: bool = False) -> bytes:
    """Read a small regular file, refusing links and (POSIX) foreign owners."""
    path = Path(path)
    if _POSIX:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
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
                  dir_uid: Optional[int] = None) -> None:
    """Write ``data`` to ``path`` via a temp file in the same directory and
    ``os.replace``. On POSIX the directory is opened with ``O_NOFOLLOW`` and,
    when ``dir_uid`` is given, must be owned by it and not group/world
    writable; all file operations are relative to that descriptor."""
    path = Path(path)
    parent = path.parent
    tmp_name = f".{path.name}.{uuid.uuid4().hex}.tmp"
    if _POSIX:
        dflags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        dfd = os.open(str(parent), dflags)
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
    return Path(tempfile.mkdtemp(prefix="cleanix-elevate-", dir=base))


def write_request(directory: Path, selection: Selection) -> Path:
    payload = {
        "version": FORMAT_VERSION,
        "invoking_user": selection.invoking_user,
        "only": list(selection.only),
        "keys": list(selection.keys),
        "use_quarantine": bool(selection.use_quarantine),
        "nonce": selection.nonce,
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


def parse_request(data: bytes) -> Selection:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("request is not valid JSON") from None
    if not isinstance(obj, dict) or set(obj) != _REQUEST_FIELDS:
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
    return Selection(
        invoking_user=user,
        only=_str_list(obj["only"], "only", _CLEANER_ID_RE, 64),
        keys=_str_list(obj["keys"], "keys"),
        use_quarantine=obj["use_quarantine"],
        nonce=nonce,
    )


def read_request(path: Path, *, expected_uid: Optional[int]) -> Selection:
    """Read and validate a request. Raises ValueError on anything suspicious.

    POSIX: the file must be a regular file (not a symlink) owned by
    ``expected_uid`` and not group/world writable. Windows: no owner check.
    """
    data = read_secure(Path(path), expected_uid=expected_uid if _POSIX else None,
                       max_bytes=MAX_REQUEST_BYTES, what="request")
    return parse_request(data)


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
    }


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
    return HelperResult(
        freed=num("freed"), removed=num("removed"),
        errors=[plain_text(e) for e in errors[:MAX_ERRORS]],
        unmatched=num("unmatched"), nonce=nonce, deadline_hit=deadline_hit,
        refused=num("refused"),
    )
