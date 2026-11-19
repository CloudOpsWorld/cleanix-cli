"""Registry snapshots and content fingerprints.

A snapshot is the exact content of one target (a key tree or a single value).
The fingerprint pins that content: any change to a name (including its case),
type or data changes it, while enumeration order does not.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Tuple, Union

from cleanix.core.models import RegTarget
from cleanix.core.winregistry import RegistryBackend, RegistryError, RegValue

MAX_KEYS = 256
MAX_VALUES = 4096
MAX_BYTES = 1_048_576


@dataclass(frozen=True)
class KeySnap:
    name: str
    values: Tuple[RegValue, ...]
    subkeys: Tuple["KeySnap", ...]


Snapshot = Union[KeySnap, RegValue]


class SnapshotError(Exception):
    """The target cannot be captured exactly (link, too large, gone, denied)."""


def _data_size(data: Any) -> int:
    if isinstance(data, (bytes, bytearray)):
        return len(data)
    if isinstance(data, str):
        return len(data) * 2
    if isinstance(data, tuple):
        return sum(_data_size(x) for x in data)
    return 8


def read_values(backend: RegistryBackend, hive: str, key: str) -> Dict[str, RegValue]:
    """The values of one key, keyed by casefolded name."""
    return {v.name.casefold(): v for v in backend.values(hive, key)}


class _Budget:
    def __init__(self) -> None:
        self.keys = 0
        self.values = 0
        self.bytes = 0


def _walk(backend: RegistryBackend, hive: str, key: str, name: str, b: _Budget) -> KeySnap:
    b.keys += 1
    if b.keys > MAX_KEYS:
        raise SnapshotError("too many subkeys")
    try:
        if backend.is_link(hive, key):
            raise SnapshotError("registry link in the tree")
        values = backend.values(hive, key)
        subs = backend.subkeys(hive, key)
    except RegistryError as exc:
        raise SnapshotError(str(exc) or type(exc).__name__) from exc
    for v in values:
        b.values += 1
        b.bytes += _data_size(v.data) + len(v.name) * 2
        if b.values > MAX_VALUES:
            raise SnapshotError("too many values")
        if b.bytes > MAX_BYTES:
            raise SnapshotError("too much data")
    children = tuple(_walk(backend, hive, key + "\\" + s, s, b) for s in subs)
    return KeySnap(name=name, values=tuple(values), subkeys=children)


def snapshot(backend: RegistryBackend, target: RegTarget) -> Snapshot:
    """Capture ``target`` or raise :class:`SnapshotError`."""
    try:
        if target.value is not None:
            if not backend.key_exists(target.hive, target.key):
                raise SnapshotError("key is missing")
            found = read_values(backend, target.hive, target.key).get(
                target.value.casefold()
            )
            if found is None:
                raise SnapshotError("value is missing")
            if _data_size(found.data) > MAX_BYTES:
                raise SnapshotError("too much data")
            return found
        if not backend.key_exists(target.hive, target.key):
            raise SnapshotError("key is missing")
    except RegistryError as exc:
        raise SnapshotError(str(exc) or type(exc).__name__) from exc
    return _walk(backend, target.hive, target.key, target.key.rsplit("\\", 1)[-1], _Budget())


# -- serialization -------------------------------------------------------------
def _data_to_json(data: Any) -> Any:
    if isinstance(data, (bytes, bytearray)):
        return {"b64": base64.b64encode(bytes(data)).decode("ascii")}
    if isinstance(data, tuple):
        return list(data)
    return data


def _data_from_json(data: Any) -> Any:
    if isinstance(data, dict):
        return base64.b64decode(data["b64"])
    if isinstance(data, list):
        return tuple(data)
    return data


def _value_json(v: RegValue) -> dict:
    return {"name": v.name, "type": v.type, "data": _data_to_json(v.data)}


def _value_from(obj: dict) -> RegValue:
    return RegValue(obj["name"], int(obj["type"]), _data_from_json(obj["data"]))


def to_jsonable(snap: Snapshot) -> dict:
    if isinstance(snap, RegValue):
        return dict(_value_json(snap), kind="value")
    return {
        "kind": "key",
        "name": snap.name,
        "values": [_value_json(v) for v in snap.values],
        "subkeys": [to_jsonable(s) for s in snap.subkeys],
    }


def from_jsonable(obj: dict) -> Snapshot:
    if obj.get("kind") == "value":
        return _value_from(obj)
    return KeySnap(
        name=obj["name"],
        values=tuple(_value_from(v) for v in obj["values"]),
        subkeys=tuple(from_jsonable(s) for s in obj["subkeys"]),
    )


def _canon(snap: Snapshot, root: bool = False) -> Any:
    if isinstance(snap, RegValue):
        return ["v", snap.name, snap.type, _data_to_json(snap.data)]
    order = lambda n: (n.casefold(), n)  # noqa: E731
    return [
        "k",
        "" if root else snap.name,  # the root's name is already in the target
        [_canon_value(v) for v in sorted(snap.values, key=lambda v: order(v.name))],
        [_canon(s) for s in sorted(snap.subkeys, key=lambda s: order(s.name))],
    ]


def _canon_value(v: RegValue) -> Any:
    return ["v", v.name, v.type, _data_to_json(v.data)]


def fingerprint(target: RegTarget, snap: Snapshot) -> str:
    """sha256 hex over the hive, casefolded key, value name and content."""
    doc = [
        target.hive,
        target.key.casefold(),
        target.value.casefold() if target.value is not None else None,
        _canon(snap, root=True),
    ]
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()
