"""Registry backups (``.reg`` + JSON) and validated restore.

Every registry delete is preceded by a backup of the exact snapshot:

* ``N__registry.reg``: UTF-16LE with BOM, CRLF, for humans, regedit and a
  manual ``reg import`` (the only HKLM Undo route, from an Administrator
  terminal).
* ``N__registry.json``: typed values, the machine source for Undo.

Restore never runs ``reg import``. It treats the JSON as untrusted input:
the whole document is validated (format, shapes, types, sizes, names) and
the target is re-judged by :func:`regsafety.check_target` before any
registry call. It is then an additive merge (Ruling R7): anything that
exists but differs fails the whole entry before anything is written.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from cleanix.core import regsafety
from cleanix.core.models import RegTarget
from cleanix.core.regsafety import check_target
from cleanix.core.regsnap import (
    MAX_BYTES,
    MAX_KEYS,
    MAX_VALUES,
    KeySnap,
    Snapshot,
    SnapshotError,
    _data_size,
    fingerprint,
    from_jsonable,
    read_values,
    snapshot,
    to_jsonable,
)
from cleanix.core.winregistry import (
    REG_BINARY,
    REG_DWORD,
    REG_EXPAND_SZ,
    REG_LINK,
    REG_MULTI_SZ,
    REG_QWORD,
    REG_SZ,
    RegistryBackend,
    RegistryError,
    RegValue,
)

REG_HEADER = "Windows Registry Editor Version 5.00"
HIVE_NAMES = {"HKCU": "HKEY_CURRENT_USER", "HKLM": "HKEY_LOCAL_MACHINE"}

FORMAT = 1
# Generous bound for a JSON file holding at most MAX_BYTES of data (base64
# and \uXXXX escapes inflate it); anything larger is refused unparsed.
MAX_FILE_BYTES = 8 * MAX_BYTES
MAX_KEY_NAME = 255
MAX_VALUE_NAME = 16383

_JSON_NAME = re.compile(r"\A([0-9]{1,9})__registry\.json\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_TOP_FIELDS = frozenset(
    {"format", "cleaner_id", "hive", "key", "value", "fingerprint", "snapshot"}
)
_STR_TYPES = (REG_SZ, REG_EXPAND_SZ)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class BackupError(Exception):
    """The backup could not be written and verified; nothing may be deleted."""


class RestoreError(Exception):
    """The entry was not (fully) restored; the message says why."""


@dataclass(frozen=True)
class BackupFiles:
    reg_path: Path
    json_path: Path


# -- .reg text ----------------------------------------------------------------------
def _utf16z(text: str) -> bytes:
    return (text + "\0").encode("utf-16-le", "surrogatepass")


def _raw_bytes(v: RegValue) -> bytes:
    """The value's data as the registry stores it."""
    data = v.data
    if data is None:
        return b""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, str):
        return _utf16z(data)
    if isinstance(data, (tuple, list)):
        return b"".join(_utf16z(s) for s in data) + _utf16z("")
    if isinstance(data, int):
        width = 8 if v.type == REG_QWORD or not 0 <= data < 2 ** 32 else 4
        return int(data).to_bytes(width, "little", signed=data < 0)
    raise ValueError(f"unsupported registry data: {type(data).__name__}")


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _hex(raw: bytes) -> str:
    return ",".join(f"{b:02x}" for b in raw)


def _value_line(v: RegValue) -> str:
    name = "@" if v.name == "" else _quote(v.name)
    data = v.data
    if v.type == REG_SZ and isinstance(data, str) and not any(c in data for c in "\r\n\0"):
        rhs = _quote(data)
    elif v.type == REG_DWORD and isinstance(data, int) and 0 <= data < 2 ** 32:
        rhs = f"dword:{data:08x}"
    elif v.type == REG_BINARY and (data is None or isinstance(data, (bytes, bytearray))):
        rhs = "hex:" + _hex(_raw_bytes(v))
    else:
        rhs = f"hex({v.type:x}):" + _hex(_raw_bytes(v))
    return f"{name}={rhs}"


def _sections(path: str, snap: KeySnap, out: List[str]) -> None:
    out.append(f"[{path}]")
    out.extend(_value_line(v) for v in snap.values)
    out.append("")
    for sub in snap.subkeys:
        _sections(path + "\\" + sub.name, sub, out)


def to_reg_text(target: RegTarget, snap: Snapshot) -> str:
    """The ``.reg`` text of ``snap`` (CRLF, no wrapping, parents first)."""
    root = HIVE_NAMES[target.hive] + "\\" + target.key
    lines = [REG_HEADER, ""]
    if isinstance(snap, RegValue):
        lines += [f"[{root}]", _value_line(snap), ""]
    else:
        _sections(root, snap, lines)
    return "\r\n".join(lines) + "\r\n"


def _reg_bytes(target: RegTarget, snap: Snapshot) -> bytes:
    return b"\xff\xfe" + to_reg_text(target, snap).encode("utf-16-le", "surrogatepass")


# -- validation of an untrusted JSON document ----------------------------------------
class _Invalid(Exception):
    pass


def _no_dups(pairs):
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise _Invalid(f"duplicate field {k!r}")
        out[k] = v
    return out


def _reject_constant(name):
    raise _Invalid(f"invalid number {name}")


def _is_int(x: Any) -> bool:
    return type(x) is int


def _bad_chars(text: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in text)


def _check_value(obj: Any, *, root_value: bool) -> RegValue:
    fields = {"name", "type", "data"} | ({"kind"} if root_value else set())
    if not isinstance(obj, dict) or set(obj) != fields:
        raise _Invalid("malformed value")
    name, typ, data = obj["name"], obj["type"], obj["data"]
    if not isinstance(name, str) or len(name) > MAX_VALUE_NAME or "\0" in name:
        raise _Invalid("invalid value name")
    if name.casefold() == "symboliclinkvalue":
        raise _Invalid("registry link value")
    if not _is_int(typ) or not 0 <= typ <= 0xFFFFFFFF:
        raise _Invalid("unknown value type")
    if typ == REG_LINK:
        raise _Invalid("registry link value")
    if typ in _STR_TYPES:
        ok = isinstance(data, str)
    elif typ == REG_MULTI_SZ:
        ok = isinstance(data, list) and all(isinstance(s, str) for s in data)
    elif typ == REG_DWORD:
        ok = _is_int(data) and 0 <= data < 2 ** 32
    elif typ == REG_QWORD:
        ok = _is_int(data) and 0 <= data < 2 ** 64
    else:  # REG_BINARY, REG_NONE, big-endian DWORD and unrecognized types
        ok = data is None or (
            isinstance(data, dict)
            and set(data) == {"b64"}
            and isinstance(data["b64"], str)
        )
        if ok and data is not None:
            try:
                base64.b64decode(data["b64"].encode("ascii"), validate=True)
            except (binascii.Error, UnicodeEncodeError, ValueError):
                ok = False
    if not ok:
        raise _Invalid("value data does not match its type")
    return from_jsonable(dict(obj, kind="value"))  # type: ignore[return-value]


def _component_denied(comps: Tuple[str, ...]) -> bool:
    for form in (comps, tuple(c.upper().casefold() for c in comps)):
        if regsafety.DENY_COMPONENTS & set(form):
            return True
        match = regsafety._strip_wow(form)
        if any(match[: len(p)] == p for p in regsafety.DENY_PREFIXES):
            return True
    return False


class _Budget:
    def __init__(self) -> None:
        self.keys = 0
        self.values = 0
        self.bytes = 0


def _check_key(obj: Any, hive: str, path: str, base: Tuple[str, ...], b: _Budget) -> None:
    if not isinstance(obj, dict) or set(obj) != {"kind", "name", "values", "subkeys"}:
        raise _Invalid("malformed key")
    if obj["kind"] != "key":
        raise _Invalid("unknown snapshot kind")
    if not isinstance(obj["values"], list) or not isinstance(obj["subkeys"], list):
        raise _Invalid("malformed key")
    b.keys += 1
    if b.keys > MAX_KEYS:
        raise _Invalid("too many subkeys")
    try:
        _h, comps = regsafety.normalize(hive, path)
    except ValueError as exc:
        raise _Invalid(str(exc)) from exc
    if comps[: len(base)] != base:
        raise _Invalid("key outside the backed-up entry")
    if len(comps) > len(base) and _component_denied(comps):
        raise _Invalid("Windows-owned key")
    seen = set()
    for v in obj["values"]:
        rv = _check_value(v, root_value=False)
        if rv.name.casefold() in seen:
            raise _Invalid("duplicate value name")
        seen.add(rv.name.casefold())
        b.values += 1
        b.bytes += _data_size(rv.data) + len(rv.name) * 2
        if b.values > MAX_VALUES:
            raise _Invalid("too many values")
        if b.bytes > MAX_BYTES:
            raise _Invalid("too much data")
    seen = set()
    for sub in obj["subkeys"]:
        name = sub.get("name") if isinstance(sub, dict) else None
        if (
            not isinstance(name, str)
            or not name
            or name in (".", "..")
            or "\\" in name
            or len(name) > MAX_KEY_NAME
            or _bad_chars(name)
            or name != name.strip()
        ):
            raise _Invalid("invalid subkey name")
        if name.casefold() in seen:
            raise _Invalid("duplicate subkey name")
        seen.add(name.casefold())
        _check_key(sub, hive, path + "\\" + name, base, b)


@dataclass(frozen=True)
class _Entry:
    cleaner_id: str
    target: RegTarget
    snap: Snapshot


def _load(raw: bytes) -> _Entry:
    """Parse and fully validate one backup document (no registry access)."""
    if len(raw) > MAX_FILE_BYTES:
        raise _Invalid("backup file is too large")
    try:
        doc = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_dups,
            parse_constant=_reject_constant,
        )
    except _Invalid:
        raise
    except (ValueError, RecursionError) as exc:
        raise _Invalid("not a readable backup file") from exc
    if not isinstance(doc, dict) or set(doc) != _TOP_FIELDS:
        raise _Invalid("unknown backup format")
    if not _is_int(doc["format"]) or doc["format"] != FORMAT:
        raise _Invalid("unknown backup format")
    cleaner_id, hive, key, value = doc["cleaner_id"], doc["hive"], doc["key"], doc["value"]
    digest = doc["fingerprint"]
    if not all(isinstance(x, str) for x in (cleaner_id, hive, key, digest)):
        raise _Invalid("malformed backup header")
    if value is not None and not isinstance(value, str):
        raise _Invalid("malformed backup header")
    if not _HEX64.match(digest):
        raise _Invalid("malformed digest")
    target = RegTarget(hive, key, value, digest)
    reason = check_target(cleaner_id, target)
    if reason is not None:
        raise _Invalid(reason)

    obj = doc["snapshot"]
    if value is not None:
        if not isinstance(obj, dict) or obj.get("kind") != "value":
            raise _Invalid("snapshot does not match the target")
        snap: Snapshot = _check_value(obj, root_value=True)
        if snap.name.casefold() != value.casefold():
            raise _Invalid("snapshot does not match the target")
        if _data_size(snap.data) > MAX_BYTES:
            raise _Invalid("too much data")
    else:
        if not isinstance(obj, dict) or obj.get("name") != key.rsplit("\\", 1)[-1]:
            raise _Invalid("snapshot does not match the target")
        _hive, base = regsafety.normalize(hive, key)
        try:
            _check_key(obj, hive, key, base, _Budget())
        except RecursionError as exc:
            raise _Invalid("snapshot is too deep") from exc
        snap = from_jsonable(obj)
    if fingerprint(target, snap) != digest:
        raise _Invalid("integrity check failed (digest mismatch)")
    return _Entry(cleaner_id, target, snap)


# -- writing ----------------------------------------------------------------------
def _fsync_dir(directory: Path) -> None:
    if sys.platform == "win32":
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _write_atomic(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` via an owner-only temp file, fsync, rename."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp), flags, 0o600)
    try:
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                view = view[n:]
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
    _fsync_dir(path.parent)


def _read_limited(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    try:
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                break
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_backup(
    directory: Path,
    index: int,
    cleaner_id: str,
    target: RegTarget,
    snap: Snapshot,
) -> BackupFiles:
    """Write and verify ``{index}__registry.reg`` and ``.json``; raise
    :class:`BackupError` unless both read back exactly and the JSON passes
    the same validation that restore applies."""
    if not _is_int(index) or index < 0 or index > 999_999_999:
        raise BackupError(f"invalid backup index: {index!r}")
    directory = Path(directory)
    files = BackupFiles(
        directory / f"{index}__registry.reg", directory / f"{index}__registry.json"
    )
    written: List[Path] = []
    try:
        if fingerprint(target, snap) != target.fingerprint:
            raise BackupError("the snapshot does not match the scanned entry")
        reg_data = _reg_bytes(target, snap)
        doc = {
            "format": FORMAT,
            "cleaner_id": cleaner_id,
            "hive": target.hive,
            "key": target.key,
            "value": target.value,
            "fingerprint": target.fingerprint,
            "snapshot": to_jsonable(snap),
        }
        json_data = json.dumps(doc, ensure_ascii=True, indent=2).encode("ascii")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        for p in (files.reg_path, files.json_path):
            if os.path.lexists(p):
                raise BackupError(f"backup file already exists: {p.name}")
        _write_atomic(files.reg_path, reg_data)
        written.append(files.reg_path)
        _write_atomic(files.json_path, json_data)
        written.append(files.json_path)

        if _read_limited(files.reg_path) != reg_data:
            raise BackupError("the .reg backup did not read back correctly")
        try:
            entry = _load(_read_limited(files.json_path))
        except _Invalid as exc:
            raise BackupError(f"the backup did not verify: {exc}") from exc
        if (
            entry.target != target
            or entry.cleaner_id != cleaner_id
            or fingerprint(entry.target, entry.snap) != target.fingerprint
        ):
            raise BackupError("the backup did not verify")
    except BackupError:
        _remove(written)
        raise
    except (OSError, ValueError) as exc:
        _remove(written)
        raise BackupError(f"could not write the registry backup: {exc}") from exc
    return files


def _remove(paths: List[Path]) -> None:
    for p in paths:
        try:
            os.unlink(str(p))
        except OSError:
            pass


# -- restore ----------------------------------------------------------------------
def _read_entry_file(json_path: Path) -> Tuple[bytes, Path]:
    json_path = Path(json_path)
    m = _JSON_NAME.match(json_path.name)
    if m is None:
        raise RestoreError(f"not a registry backup file: {json_path.name}")
    reg_path = Path(os.path.abspath(json_path.with_name(f"{m.group(1)}__registry.reg")))
    try:
        st = os.lstat(str(json_path))
    except OSError as exc:
        raise RestoreError(f"backup file not readable: {exc}") from exc
    if (
        stat.S_ISLNK(st.st_mode)
        or not stat.S_ISREG(st.st_mode)
        or getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise RestoreError("backup file is a link or not a regular file")
    if st.st_size > MAX_FILE_BYTES:
        raise RestoreError("backup file is too large")
    try:
        return _read_limited(json_path), reg_path
    except OSError as exc:
        raise RestoreError(f"backup file not readable: {exc}") from exc


def _check_ancestors(backend: RegistryBackend, hive: str, parts: List[str]) -> None:
    """Refuse a registry link at any existing key above the entry."""
    for depth in range(2, len(parts) + 1):
        if hive == "HKCU" and depth == 2 and parts[1].casefold() == "classes":
            continue  # trusted anchor, as in regsafety.check_target
        path = "\\".join(parts[:depth])
        if backend.key_exists(hive, path) and backend.is_link(hive, path):
            raise RestoreError("refused: registry link (symbolic link) in the path")


def _plan_key(
    backend: RegistryBackend,
    hive: str,
    path: str,
    snap: KeySnap,
    exists: bool,
    plan: List[Tuple],
) -> None:
    """Pre-check one key of the tree and append the writes it needs."""
    if exists and backend.is_link(hive, path):
        raise RestoreError("refused: registry link (symbolic link) in the tree")
    if not exists:
        plan.append(("create", path))
        plan.extend(("set", path, v) for v in snap.values)
        for sub in snap.subkeys:
            _plan_key(backend, hive, path + "\\" + sub.name, sub, False, plan)
        return
    have = read_values(backend, hive, path)
    want = {v.name.casefold(): v for v in snap.values}
    for fold, cur in have.items():
        if fold not in want:
            raise RestoreError(
                f"not restored: the entry exists with an extra value {cur.name!r}"
            )
    for fold, v in want.items():
        cur = have.get(fold)
        if cur is None:
            plan.append(("set", path, v))
        elif cur != v:
            raise RestoreError(
                f"not restored: the value {v.name!r} exists with different content"
            )
    existing = {s.casefold(): s for s in backend.subkeys(hive, path)}
    wanted = {s.name.casefold(): s for s in snap.subkeys}
    for fold, name in existing.items():
        if fold not in wanted or wanted[fold].name != name:
            raise RestoreError(
                f"not restored: the entry exists with a different subkey {name!r}"
            )
    for sub in snap.subkeys:
        sub_exists = sub.name.casefold() in existing
        _plan_key(backend, hive, path + "\\" + sub.name, sub, sub_exists, plan)


def _plan(backend: RegistryBackend, target: RegTarget, snap: Snapshot) -> List[Tuple]:
    hive = target.hive
    parts = target.key.split("\\")
    plan: List[Tuple] = []
    if isinstance(snap, RegValue):
        _check_ancestors(backend, hive, parts)
        if not backend.key_exists(hive, target.key):
            return [("create", target.key), ("set", target.key, snap)]
        cur = read_values(backend, hive, target.key).get(snap.name.casefold())
        if cur is None:
            return [("set", target.key, snap)]
        if cur != snap:
            raise RestoreError(
                f"not restored: the value {snap.name!r} exists with different content"
            )
        return []
    _check_ancestors(backend, hive, parts[:-1])
    exists = backend.key_exists(hive, target.key)
    _plan_key(backend, hive, target.key, snap, exists, plan)
    return plan


def _apply(backend: RegistryBackend, hive: str, plan: List[Tuple]) -> List[str]:
    failed_keys: List[str] = []
    errors: List[str] = []

    def under_failed(path: str) -> bool:
        p = path.casefold()
        return any(p == f or p.startswith(f + "\\") for f in failed_keys)

    for op in plan:
        path = op[1]
        if under_failed(path):
            errors.append(f"skipped {hive}\\{path}")
            continue
        try:
            if op[0] == "create":
                backend.create_key(hive, path)
            else:
                backend.set_value(hive, path, op[2])
        except RegistryError as exc:
            what = f"{hive}\\{path}" + (f" [{op[2].name}]" if op[0] == "set" else "")
            errors.append(f"{what}: {exc or type(exc).__name__}")
            if op[0] == "create":
                failed_keys.append(path.casefold())
    return errors


def restore_entry(json_path: Path, backend: RegistryBackend, *, is_admin: bool) -> str:
    """Restore one backed-up entry; return its display string or raise
    :class:`RestoreError`. Safe to run again (an identical entry is left as
    is)."""
    raw, reg_path = _read_entry_file(json_path)
    try:
        entry = _load(raw)
    except _Invalid as exc:
        raise RestoreError(f"refused: {exc}") from exc
    target, snap = entry.target, entry.snap

    if target.hive == "HKLM" and not is_admin:
        raise RestoreError(
            f"needs administrator: from an Administrator terminal run cleanix restore "
            f'{{run}} or reg import "{reg_path}"'
        )

    try:
        plan = _plan(backend, target, snap)
    except RegistryError as exc:
        raise RestoreError(f"not restored: could not read the registry: {exc}") from exc
    if plan:
        errors = _apply(backend, target.hive, plan)
        if errors:
            raise RestoreError(
                f"partially restored: {len(errors)} of {len(plan)} writes failed: "
                + "; ".join(errors[:5])
            )
    try:
        now = snapshot(backend, target)
    except SnapshotError as exc:
        raise RestoreError(f"restored, but the result could not be verified: {exc}") from exc
    if fingerprint(target, now) != target.fingerprint:
        raise RestoreError("restored, but the result differs from the backup")
    return target.display
