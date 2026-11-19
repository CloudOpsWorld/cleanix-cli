"""In-memory registry for tests. Never touches the real registry."""

from __future__ import annotations

from typing import Dict, List, Mapping, Optional, Tuple

from cleanix.core.regtargets import Existence
from cleanix.core.winregistry import (
    AccessDenied,
    KeyMissing,
    RegistryError,
    RegValue,
)


class _Node:
    def __init__(self, name: str) -> None:
        self.name = name
        self.values: Dict[str, RegValue] = {}
        self.link = False
        self.deny_delete = False
        self.deny_read = False


def _path(key: str) -> Tuple[str, ...]:
    return tuple(p.casefold() for p in key.split("\\"))


class FakeRegistry:
    """Implements the RegistryBackend Protocol; names are case-insensitive."""

    def __init__(self) -> None:
        self._nodes: Dict[Tuple[str, Tuple[str, ...]], _Node] = {}
        self.calls: List[Tuple] = []
        self._fail: Dict[str, Exception] = {}

    # -- test helpers -----------------------------------------------------
    def add_key(
        self,
        hive: str,
        key: str,
        values: Mapping[str, Tuple[int, object]] = {},
        *,
        link: bool = False,
        deny_delete: bool = False,
        deny_read: bool = False,
    ) -> None:
        parts = key.split("\\")
        for i in range(1, len(parts) + 1):
            k = (hive, _path("\\".join(parts[:i])))
            if k not in self._nodes:
                self._nodes[k] = _Node(parts[i - 1])
        node = self._nodes[(hive, _path(key))]
        for name, (typ, data) in values.items():
            node.values[name.casefold()] = RegValue(name, typ, data)  # type: ignore[arg-type]
        node.link = node.link or link
        node.deny_delete = node.deny_delete or deny_delete
        node.deny_read = node.deny_read or deny_read

    def fail_next(self, op: str, exc: Exception) -> None:
        self._fail[op] = exc

    def tree(self, hive: str, key: str) -> dict:
        node = self._nodes[(hive, _path(key))]
        subs = {}
        base = _path(key)
        for (h, p), n in self._nodes.items():
            if h == hive and len(p) == len(base) + 1 and p[: len(base)] == base:
                subs[n.name] = self.tree(hive, key + "\\" + n.name)
        return {
            "values": {v.name: (v.type, v.data) for v in node.values.values()},
            "subkeys": subs,
        }

    # -- internals --------------------------------------------------------
    def _enter(self, op: str, *args) -> None:
        self.calls.append((op,) + args)
        exc = self._fail.pop(op, None)
        if exc is not None:
            raise exc

    def _node(self, hive: str, key: str) -> _Node:
        node = self._nodes.get((hive, _path(key)))
        if node is None:
            raise KeyMissing(f"{hive}\\{key}")
        return node

    def _readable(self, hive: str, key: str) -> _Node:
        node = self._node(hive, key)
        if node.deny_read:
            raise AccessDenied(f"{hive}\\{key}")
        return node

    # -- RegistryBackend --------------------------------------------------
    def subkeys(self, hive: str, key: str) -> List[str]:
        self._enter("subkeys", hive, key)
        self._readable(hive, key)
        base = _path(key)
        return [
            n.name
            for (h, p), n in self._nodes.items()
            if h == hive and len(p) == len(base) + 1 and p[: len(base)] == base
        ]

    def values(self, hive: str, key: str) -> List[RegValue]:
        self._enter("values", hive, key)
        return list(self._readable(hive, key).values.values())

    def key_exists(self, hive: str, key: str) -> bool:
        self._enter("key_exists", hive, key)
        return (hive, _path(key)) in self._nodes

    def is_link(self, hive: str, key: str) -> bool:
        self._enter("is_link", hive, key)
        node = self._nodes.get((hive, _path(key)))
        return bool(node and node.link)

    def can_delete(self, hive: str, key: str, value: Optional[str]) -> bool:
        self._enter("can_delete", hive, key, value)
        node = self._nodes.get((hive, _path(key)))
        if node is None or node.deny_delete:
            return False
        return value is None or value.casefold() in node.values

    def delete_key(self, hive: str, key: str) -> None:
        self._enter("delete_key", hive, key)
        node = self._node(hive, key)
        base = _path(key)
        if any(
            h == hive and len(p) > len(base) and p[: len(base)] == base
            for (h, p) in self._nodes
        ):
            raise RegistryError("key has subkeys")
        if node.deny_delete:
            raise AccessDenied(f"{hive}\\{key}")
        del self._nodes[(hive, base)]

    def delete_value(self, hive: str, key: str, name: str) -> None:
        self._enter("delete_value", hive, key, name)
        node = self._node(hive, key)
        if node.deny_delete:
            raise AccessDenied(f"{hive}\\{key}")
        if name.casefold() not in node.values:
            raise KeyMissing(name)
        del node.values[name.casefold()]

    def create_key(self, hive: str, key: str) -> None:
        self._enter("create_key", hive, key)
        self.add_key(hive, key)

    def set_value(self, hive: str, key: str, value: RegValue) -> None:
        self._enter("set_value", hive, key, value)
        self._node(hive, key).values[value.name.casefold()] = value


class ForbiddenBackend:
    """Fails any test that reaches the real registry. Calls are recorded
    because ``Cleaner.scan`` swallows exceptions."""

    def __init__(self) -> None:
        self.calls: List[Tuple] = []


def _forbid(name: str):
    def method(self, *args, **kwargs):
        self.calls.append((name,) + args)
        raise AssertionError("tests must never touch the real registry")

    method.__name__ = name
    return method


for _n in (
    "subkeys", "values", "key_exists", "is_link", "can_delete",
    "delete_key", "delete_value", "create_key", "set_value",
):
    setattr(ForbiddenBackend, _n, _forbid(_n))


class FakeProber:
    """Existence answers by casefolded path; anything unlisted is ``default``."""

    def __init__(
        self, states: Mapping[str, Existence], default: Existence = Existence.UNKNOWN
    ) -> None:
        self.states = {k.casefold(): v for k, v in states.items()}
        self.default = default
        self.calls: List[str] = []

    def probe(self, path: str) -> Existence:
        self.calls.append(path)
        return self.states.get(path.casefold(), self.default)
