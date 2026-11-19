"""WinRegBackend against an in-memory fake ``winreg`` module.

These tests never touch the real registry: the backend is always built with
``winreg_module=FakeWinreg()``. They run on every OS.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

from cleanix.core import winregistry
from cleanix.core.winregistry import (
    REG_BINARY,
    REG_DWORD,
    REG_EXPAND_SZ,
    REG_LINK,
    REG_MULTI_SZ,
    REG_NONE,
    REG_QWORD,
    REG_SZ,
    AccessDenied,
    KeyMissing,
    RegistryError,
    RegValue,
)

REPO = Path(__file__).resolve().parents[1]

KEY_QUERY_VALUE = 0x0001
KEY_SET_VALUE = 0x0002
KEY_CREATE_SUB_KEY = 0x0004
KEY_ENUMERATE_SUB_KEYS = 0x0008
KEY_WOW64_64KEY = 0x0100
KEY_WOW64_32KEY = 0x0200
KEY_READ = 0x20019
KEY_WRITE = 0x20006
DELETE = 0x00010000
REG_OPTION_OPEN_LINK = 0x0008


# -- the fake winreg module -----------------------------------------------------
def _err(winerror: int, cls=OSError, msg: str = "simulated") -> OSError:
    """An OSError carrying ``winerror`` on every OS (Windows promotes 2/5 to
    subclasses itself; Linux never sets ``winerror``)."""
    exc = cls(msg)
    exc.winerror = winerror
    return exc


class _Hive:
    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"<hive {self.name}>"


class _Node:
    def __init__(self, name: str) -> None:
        self.name = name
        self.children: Dict[str, "_Node"] = {}
        self.values: Dict[str, Tuple[str, object, int]] = {}
        self.link_to: Optional[Tuple[object, str]] = None
        self.deny_mask = 0  # access bits that make an open fail
        self.deny_delete = False


class _Handle:
    def __init__(self, fake: "FakeWinreg", node: _Node, access: int, options: int = 0) -> None:
        self.fake = fake
        self.node = node
        self.access = access
        self.options = options
        self.closed = False
        fake.opened += 1
        fake.handles.append(self)

    def Close(self) -> None:
        if not self.closed:
            self.closed = True
            self.fake.closed += 1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.Close()
        return False


class FakeWinreg:
    KEY_QUERY_VALUE = KEY_QUERY_VALUE
    KEY_SET_VALUE = KEY_SET_VALUE
    KEY_CREATE_SUB_KEY = KEY_CREATE_SUB_KEY
    KEY_ENUMERATE_SUB_KEYS = KEY_ENUMERATE_SUB_KEYS
    KEY_WOW64_64KEY = KEY_WOW64_64KEY
    KEY_WOW64_32KEY = KEY_WOW64_32KEY
    KEY_READ = KEY_READ
    KEY_WRITE = KEY_WRITE
    REG_OPTION_OPEN_LINK = REG_OPTION_OPEN_LINK
    REG_NONE = REG_NONE
    REG_SZ = REG_SZ
    REG_EXPAND_SZ = REG_EXPAND_SZ
    REG_BINARY = REG_BINARY
    REG_DWORD = REG_DWORD
    REG_LINK = REG_LINK
    REG_MULTI_SZ = REG_MULTI_SZ
    REG_QWORD = REG_QWORD

    def __init__(self, delete_follows_final_link: bool = True) -> None:
        # Pessimistic model of RegDeleteKeyEx: a link as the last path
        # component is followed and its target (if a leaf) is deleted.
        self.delete_follows_final_link = delete_follows_final_link
        self.handles: List[_Handle] = []
        self.before: Dict[str, object] = {}  # op -> callable run before it
        self.close_fails = False
        self.HKEY_CURRENT_USER = _Hive("HKCU")
        self.HKEY_LOCAL_MACHINE = _Hive("HKLM")
        self.HKEY_CLASSES_ROOT = _Hive("HKCR")
        self.HKEY_USERS = _Hive("HKU")
        self._roots = {
            self.HKEY_CURRENT_USER: _Node("HKCU"),
            self.HKEY_LOCAL_MACHINE: _Node("HKLM"),
        }
        self.calls: List[tuple] = []
        self.opened = 0
        self.closed = 0
        self._fail: Dict[str, OSError] = {}

    # -- helpers for tests --------------------------------------------------
    def add(self, root, path: str, values=(), *, deny_mask=0, deny_delete=False,
            link_to=None) -> _Node:
        node = self._roots[root]
        for part in path.split("\\"):
            node = node.children.setdefault(part.casefold(), _Node(part))
        for name, data, typ in values:
            node.values[name.casefold()] = (name, data, typ)
        node.deny_mask |= deny_mask
        node.deny_delete = node.deny_delete or deny_delete
        if link_to is not None:
            node.link_to = link_to
            node.values["symboliclinkvalue"] = ("SymbolicLinkValue", b"\\Registry\\x", REG_LINK)
        return node

    def find(self, root, path: str) -> Optional[_Node]:
        node = self._roots[root]
        for part in path.split("\\"):
            node = node.children.get(part.casefold())
            if node is None:
                return None
        return node

    def fail_next(self, op: str, exc: OSError) -> None:
        self._fail[op] = exc

    @property
    def leaked(self) -> int:
        return self.opened - self.closed

    # -- internals -----------------------------------------------------------
    def _enter(self, op: str, *args) -> None:
        self.calls.append((op,) + args)
        hook = self.before.pop(op, None)
        if hook is not None:
            hook()
        exc = self._fail.pop(op, None)
        if exc is not None:
            raise exc

    def _check_view(self, access: int) -> None:
        if not access & KEY_WOW64_64KEY or access & KEY_WOW64_32KEY:
            raise AssertionError(f"registry view not explicitly 64-bit: {access:#x}")

    @staticmethod
    def _need(h, right: int) -> None:
        """Like Windows: an operation needs the right on the handle."""
        if isinstance(h, _Handle) and not h.access & right:
            raise _err(5, PermissionError, msg=f"handle lacks {right:#x}")

    @staticmethod
    def _name(name) -> None:
        if not isinstance(name, str):
            raise TypeError("name must be str")
        if "\x00" in name:
            raise ValueError("embedded null character")  # as CPython does

    def _base(self, key) -> _Node:
        if isinstance(key, _Handle):
            if key.closed:
                raise AssertionError("use of a closed handle")
            return key.node
        if key not in self._roots:
            raise AssertionError(f"hive never allowed: {key!r}")
        return self._roots[key]

    def _resolve(self, key, sub_key: str, follow_last: bool, depth: int = 0) -> _Node:
        if depth > 8:
            raise _err(1, msg="link loop")
        node = self._base(key)
        parts = sub_key.split("\\") if sub_key else []
        for i, part in enumerate(parts):
            node = node.children.get(part.casefold())
            if node is None:
                raise _err(2, FileNotFoundError)
            last = i == len(parts) - 1
            if node.link_to is not None and (follow_last or not last):
                node = self._resolve(node.link_to[0], node.link_to[1], True, depth + 1)
        return node

    def _parent_and_name(self, key, sub_key: str) -> Tuple[_Node, str]:
        head, _, leaf = sub_key.rpartition("\\")
        parent = self._resolve(key, head, True) if head else self._base(key)
        return parent, leaf

    # -- winreg API --------------------------------------------------------
    def OpenKey(self, *a, **k):
        raise AssertionError("use OpenKeyEx with explicit access")

    def DeleteKey(self, *a, **k):
        raise AssertionError("use DeleteKeyEx with explicit view")

    def ConnectRegistry(self, *a, **k):
        raise AssertionError("never connect to a registry")

    def OpenKeyEx(self, key, sub_key, reserved=0, access=KEY_READ):
        self._enter("OpenKeyEx", key, sub_key, reserved, access)
        self._check_view(access)
        self._name(sub_key)
        node = self._resolve(key, sub_key, follow_last=not reserved & REG_OPTION_OPEN_LINK)
        if node.deny_mask & access:
            raise _err(5, PermissionError)
        return _Handle(self, node, access, reserved)

    def CreateKeyEx(self, key, sub_key, reserved=0, access=KEY_WRITE):
        self._enter("CreateKeyEx", key, sub_key, reserved, access)
        self._check_view(access)
        self._name(sub_key)
        if reserved != 0:  # RegCreateKeyEx's Reserved must be zero
            raise _err(87, msg="invalid parameter")
        node = self._base(key)
        for part in sub_key.split("\\"):
            nxt = node.children.get(part.casefold())
            if nxt is None:
                if node.deny_mask & KEY_CREATE_SUB_KEY:
                    raise _err(5, PermissionError)
                nxt = node.children[part.casefold()] = _Node(part)
            node = nxt
            if node.link_to is not None:
                node = self._resolve(node.link_to[0], node.link_to[1], True)
        return _Handle(self, node, access)

    def CloseKey(self, h) -> None:
        if isinstance(h, _Handle):
            h.Close()
            if self.close_fails:
                raise _err(6, msg="invalid handle")

    def EnumKey(self, h, index: int) -> str:
        self._enter("EnumKey", h, index)
        self._need(h, KEY_ENUMERATE_SUB_KEYS)
        kids = list(self._base(h).children.values())
        if index >= len(kids):
            raise _err(259, msg="no more data")
        return kids[index].name

    def EnumValue(self, h, index: int):
        self._enter("EnumValue", h, index)
        self._need(h, KEY_QUERY_VALUE)
        vals = list(self._base(h).values.values())
        if index >= len(vals):
            raise _err(259, msg="no more data")
        name, data, typ = vals[index]
        return name, data, typ

    def QueryValueEx(self, h, name: str):
        self._enter("QueryValueEx", h, name)
        self._name(name)
        self._need(h, KEY_QUERY_VALUE)
        found = self._base(h).values.get(name.casefold())
        if found is None:
            raise _err(2, FileNotFoundError)
        return found[1], found[2]

    def QueryInfoKey(self, h):
        self._enter("QueryInfoKey", h)
        self._need(h, KEY_QUERY_VALUE)
        node = self._base(h)
        return len(node.children), len(node.values), 0

    def DeleteKeyEx(self, key, sub_key, access=KEY_WOW64_64KEY, reserved=0):
        self._enter("DeleteKeyEx", key, sub_key, access, reserved)
        self._check_view(access)
        self._name(sub_key)
        parent, leaf = self._parent_and_name(key, sub_key)
        node = parent.children.get(leaf.casefold())
        if node is None:
            raise _err(2, FileNotFoundError)
        if node.link_to is not None and self.delete_follows_final_link:
            tkey, tpath = node.link_to
            parent, leaf = self._parent_and_name(tkey, tpath)
            node = parent.children.get(leaf.casefold())
            if node is None:
                raise _err(2, FileNotFoundError)
        if node.children or node.deny_delete:
            raise _err(5, PermissionError)  # Windows reports non-leaf as denied
        del parent.children[leaf.casefold()]

    def DeleteValue(self, h, name: str) -> None:
        self._enter("DeleteValue", h, name)
        self._name(name)
        self._need(h, KEY_SET_VALUE)
        node = self._base(h)
        if node.deny_delete:
            raise _err(5, PermissionError)
        if name.casefold() not in node.values:
            raise _err(2, FileNotFoundError)
        del node.values[name.casefold()]

    def SetValueEx(self, h, name, reserved, typ, data) -> None:
        self._enter("SetValueEx", h, name, reserved, typ, data)
        self._name(name)
        self._need(h, KEY_SET_VALUE)
        if typ == REG_MULTI_SZ and not isinstance(data, list):
            raise TypeError("Objects of type 'tuple' can not be used as a REG_MULTI_SZ")
        self._base(h).values[name.casefold()] = (name, data, typ)


# -- fixtures --------------------------------------------------------------------
@pytest.fixture
def w():
    return FakeWinreg()


@pytest.fixture
def be(w):
    from cleanix.core.winregistry_win import WinRegBackend

    return WinRegBackend(winreg_module=w)


APP = r"SOFTWARE\Vendor\App"


# -- required tests --------------------------------------------------------------
def test_opens_use_64bit_view(w, be):
    w.add(w.HKEY_CURRENT_USER, APP + r"\Sub", [("A", "x", REG_SZ)])
    w.add(w.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Vendor\App\Leaf", [("B", 1, REG_DWORD)])
    be.subkeys("HKCU", APP)
    be.values("HKCU", APP + r"\Sub")
    be.key_exists("HKCU", APP)
    be.is_link("HKCU", APP)
    be.can_delete("HKCU", APP, None)
    be.can_delete("HKCU", APP + r"\Sub", "A")
    be.create_key("HKCU", APP + r"\New\Deeper")
    be.set_value("HKCU", APP + r"\New", RegValue("V", REG_SZ, "y"))
    be.delete_value("HKCU", APP + r"\Sub", "A")
    be.delete_key("HKCU", APP + r"\New\Deeper")
    # The 32-bit view is reached only through the explicit container path.
    assert be.subkeys("HKLM", r"SOFTWARE\Wow6432Node\Vendor\App") == ["Leaf"]
    be.delete_key("HKLM", r"SOFTWARE\Wow6432Node\Vendor\App\Leaf")
    opening = [c for c in w.calls if c[0] in ("OpenKeyEx", "CreateKeyEx", "DeleteKeyEx")]
    assert {c[0] for c in opening} == {"OpenKeyEx", "CreateKeyEx", "DeleteKeyEx"}
    for c in opening:
        access = c[4] if c[0] != "DeleteKeyEx" else c[3]
        assert access & KEY_WOW64_64KEY and not access & KEY_WOW64_32KEY, c
    create = [c for c in w.calls if c[0] == "CreateKeyEx"]
    assert create[0][4] == KEY_WRITE | KEY_WOW64_64KEY
    assert w.leaked == 0


def test_is_link_uses_open_link_option(w, be):
    w.add(w.HKEY_CURRENT_USER, r"SOFTWARE\Target")
    w.add(w.HKEY_CURRENT_USER, r"SOFTWARE\Vendor\Link",
          link_to=(w.HKEY_CURRENT_USER, r"SOFTWARE\Target"))
    w.add(w.HKEY_CURRENT_USER, r"SOFTWARE\Vendor\Plain")
    assert be.is_link("HKCU", r"SOFTWARE\Vendor\Link") is True
    assert be.is_link("HKCU", r"SOFTWARE\Vendor\Plain") is False
    opens = [c for c in w.calls if c[0] == "OpenKeyEx"]
    assert opens and all(
        c[3] == REG_OPTION_OPEN_LINK and c[4] == KEY_QUERY_VALUE | KEY_WOW64_64KEY
        for c in opens
    )
    queries = [c for c in w.calls if c[0] == "QueryValueEx"]
    assert all(c[2] == "SymbolicLinkValue" for c in queries)
    assert w.leaked == 0


def test_is_link_requires_reg_link_type(w, be):
    # A same-named value of another type is not a link.
    w.add(w.HKEY_CURRENT_USER, APP, [("SymbolicLinkValue", "x", REG_SZ)])
    assert be.is_link("HKCU", APP) is False


def test_is_link_missing_and_denied_raise(w, be):
    w.add(w.HKEY_CURRENT_USER, APP, deny_mask=KEY_QUERY_VALUE)
    with pytest.raises(KeyMissing):
        be.is_link("HKCU", r"SOFTWARE\Nope")
    with pytest.raises(AccessDenied):
        be.is_link("HKCU", APP)
    assert w.leaked == 0


@pytest.mark.parametrize(
    "exc, expected",
    [
        (_err(2, FileNotFoundError), KeyMissing),
        (_err(2), KeyMissing),
        (_err(3), KeyMissing),
        (FileNotFoundError("no winerror"), KeyMissing),
        (_err(5, PermissionError), AccessDenied),
        (_err(5), AccessDenied),
        (PermissionError("no winerror"), AccessDenied),
        (_err(32), RegistryError),  # sharing violation / in use
        (_err(1018), RegistryError),  # key marked for deletion
        (OSError("bare"), RegistryError),
    ],
)
@pytest.mark.parametrize(
    "op, call",
    [
        ("OpenKeyEx", lambda be: be.subkeys("HKCU", APP)),
        ("EnumKey", lambda be: be.subkeys("HKCU", APP)),
        ("EnumValue", lambda be: be.values("HKCU", APP)),
        ("OpenKeyEx", lambda be: be.is_link("HKCU", APP)),
        ("DeleteKeyEx", lambda be: be.delete_key("HKCU", APP)),
        ("DeleteValue", lambda be: be.delete_value("HKCU", APP, "A")),
        ("CreateKeyEx", lambda be: be.create_key("HKCU", APP)),
        ("SetValueEx", lambda be: be.set_value("HKCU", APP, RegValue("A", REG_SZ, "x"))),
    ],
)
def test_error_mapping(w, be, op, call, exc, expected):
    w.add(w.HKEY_CURRENT_USER, APP, [("A", "x", REG_SZ)])
    w.fail_next(op, exc)
    with pytest.raises(expected) as info:
        call(be)
    assert type(info.value) is expected
    assert info.value.__cause__ is exc
    assert w.leaked == 0


def test_error_mapping_reaches_every_failure_kind(w, be):
    with pytest.raises(KeyMissing):
        be.subkeys("HKCU", r"SOFTWARE\Missing")
    with pytest.raises(KeyMissing):
        be.values("HKCU", r"SOFTWARE\Missing")
    with pytest.raises(KeyMissing):
        be.delete_key("HKCU", r"SOFTWARE\Missing")
    with pytest.raises(KeyMissing):
        be.set_value("HKCU", r"SOFTWARE\Missing", RegValue("A", REG_SZ, "x"))
    w.add(w.HKEY_CURRENT_USER, APP, [("A", "x", REG_SZ)], deny_mask=KEY_ENUMERATE_SUB_KEYS)
    with pytest.raises(AccessDenied):
        be.subkeys("HKCU", APP)
    with pytest.raises(KeyMissing):
        be.delete_value("HKCU", APP, "Nope")


def test_values_normalised(w, be):
    w.add(w.HKEY_CURRENT_USER, APP, [
        ("Multi", ["a", "", "b"], REG_MULTI_SZ),
        ("Empty", None, REG_NONE),
        ("Bin", b"\x00\x01", REG_BINARY),
        ("BinBA", bytearray(b"\x02"), REG_BINARY),
        ("Odd", b"\xff", 0x20),
        ("Dw", 7, REG_DWORD),
        ("Qw", 2**40, REG_QWORD),
        ("Str", "x", REG_SZ),
        ("Exp", "%TEMP%", REG_EXPAND_SZ),
        ("", "default", REG_SZ),
    ])
    got = {v.name: v for v in be.values("HKCU", APP)}
    assert got["Multi"] == RegValue("Multi", REG_MULTI_SZ, ("a", "", "b"))
    assert got["Empty"] == RegValue("Empty", REG_NONE, b"")
    assert got["Bin"].data == b"\x00\x01" and type(got["Bin"].data) is bytes
    assert got["BinBA"].data == b"\x02" and type(got["BinBA"].data) is bytes
    assert got["Odd"] == RegValue("Odd", 0x20, b"\xff")
    assert got["Dw"] == RegValue("Dw", REG_DWORD, 7)
    assert got["Qw"] == RegValue("Qw", REG_QWORD, 2**40)
    assert got["Str"] == RegValue("Str", REG_SZ, "x")
    assert got["Exp"] == RegValue("Exp", REG_EXPAND_SZ, "%TEMP%")
    assert got[""] == RegValue("", REG_SZ, "default")
    for v in got.values():
        hash(v)  # every value is hashable (no lists)
    assert w.leaked == 0


def test_values_compatible_with_regsnap(w, be):
    from cleanix.core.models import RegTarget
    from cleanix.core.regsnap import KeySnap, fingerprint, snapshot

    w.add(w.HKEY_CURRENT_USER, APP + r"\Child", [("M", ["x"], REG_MULTI_SZ)])
    w.add(w.HKEY_CURRENT_USER, APP, [("N", None, REG_NONE)])
    target = RegTarget("HKCU", APP, None, "")
    snap = snapshot(be, target)
    assert isinstance(snap, KeySnap)
    assert snap.values == (RegValue("N", REG_NONE, b""),)
    assert snap.subkeys[0].values == (RegValue("M", REG_MULTI_SZ, ("x",)),)
    assert fingerprint(target, snap) == fingerprint(target, snapshot(be, target))
    assert w.leaked == 0


def test_delete_key_uses_delete_key_ex_with_view(w, be):
    w.add(w.HKEY_LOCAL_MACHINE, APP + r"\Leaf")
    be.delete_key("HKLM", APP + r"\Leaf")
    deletes = [c for c in w.calls if c[0] == "DeleteKeyEx"]
    assert deletes == [("DeleteKeyEx", w.HKEY_LOCAL_MACHINE, APP + r"\Leaf", KEY_WOW64_64KEY, 0)]
    assert w.find(w.HKEY_LOCAL_MACHINE, APP + r"\Leaf") is None
    assert w.find(w.HKEY_LOCAL_MACHINE, APP) is not None
    assert w.leaked == 0


def test_delete_key_refuses_non_leaf(w, be):
    w.add(w.HKEY_CURRENT_USER, APP + r"\Child")
    with pytest.raises(RegistryError) as info:
        be.delete_key("HKCU", APP)
    assert type(info.value) is RegistryError  # not a misleading AccessDenied
    assert not [c for c in w.calls if c[0] == "DeleteKeyEx"]
    assert w.find(w.HKEY_CURRENT_USER, APP + r"\Child") is not None
    assert w.leaked == 0


def test_delete_key_refuses_link(w, be):
    w.add(w.HKEY_CURRENT_USER, r"SOFTWARE\Target")
    w.add(w.HKEY_CURRENT_USER, r"SOFTWARE\Vendor\Link",
          link_to=(w.HKEY_CURRENT_USER, r"SOFTWARE\Target"))
    with pytest.raises(RegistryError):
        be.delete_key("HKCU", r"SOFTWARE\Vendor\Link")
    assert not [c for c in w.calls if c[0] == "DeleteKeyEx"]
    assert w.find(w.HKEY_CURRENT_USER, r"SOFTWARE\Target") is not None
    # The pre-delete check opened the link itself, never its target.
    opens = [c for c in w.calls if c[0] == "OpenKeyEx"]
    assert opens and all(c[3] & REG_OPTION_OPEN_LINK for c in opens)
    assert w.leaked == 0


def test_delete_key_denied(w, be):
    w.add(w.HKEY_CURRENT_USER, APP, deny_delete=True)
    with pytest.raises(AccessDenied):
        be.delete_key("HKCU", APP)


def test_delete_value_exact_name_only(w, be):
    w.add(w.HKEY_CURRENT_USER, APP, [
        ("C:\\Program Files\\A\\a.dll", 1, REG_DWORD),
        ("C:\\Program Files\\A\\a.dll.bak", 1, REG_DWORD),
        ("", "default", REG_SZ),
    ])
    be.delete_value("HKCU", APP, "C:\\Program Files\\A\\a.dll")
    node = w.find(w.HKEY_CURRENT_USER, APP)
    assert set(node.values) == {"c:\\program files\\a\\a.dll.bak", ""}
    dels = [c for c in w.calls if c[0] == "DeleteValue"]
    assert [c[2] for c in dels] == ["C:\\Program Files\\A\\a.dll"]
    with pytest.raises(KeyMissing):
        be.delete_value("HKCU", APP, "C:\\Program Files\\A\\a.dll")
    assert w.leaked == 0


def test_delete_value_refuses_link_key(w, be):
    w.add(w.HKEY_CURRENT_USER, r"SOFTWARE\Target", [("A", "x", REG_SZ)])
    w.add(w.HKEY_CURRENT_USER, r"SOFTWARE\Vendor\Link",
          link_to=(w.HKEY_CURRENT_USER, r"SOFTWARE\Target"))
    with pytest.raises(RegistryError):
        be.delete_value("HKCU", r"SOFTWARE\Vendor\Link", "A")
    assert "a" in w.find(w.HKEY_CURRENT_USER, r"SOFTWARE\Target").values
    assert not [c for c in w.calls if c[0] == "DeleteValue"]
    assert w.leaked == 0


def test_set_value_types_passed_through(w, be):
    w.add(w.HKEY_CURRENT_USER, APP)
    vals = [
        RegValue("S", REG_SZ, "a\r\nb"),
        RegValue("E", REG_EXPAND_SZ, "%X%"),
        RegValue("B", REG_BINARY, b"\x00\xff"),
        RegValue("D", REG_DWORD, 5),
        RegValue("Q", REG_QWORD, 2**40),
        RegValue("M", REG_MULTI_SZ, ("a", "", "b")),
        RegValue("N", REG_NONE, b""),
        RegValue("U", 0x20, b"\x01"),
    ]
    for v in vals:
        be.set_value("HKCU", APP, v)
    sets = {c[2]: c for c in w.calls if c[0] == "SetValueEx"}
    for v in vals:
        _op, _h, name, reserved, typ, data = sets[v.name]
        assert (name, reserved, typ) == (v.name, 0, v.type)
        if v.type == REG_MULTI_SZ:
            assert data == list(v.data) and isinstance(data, list)
        else:
            assert data == v.data and type(data) is type(v.data)
    # Round-trip: what was written reads back equal.
    assert set(be.values("HKCU", APP)) == set(vals)
    assert w.leaked == 0


def test_set_value_missing_key_raises(w, be):
    with pytest.raises(KeyMissing):
        be.set_value("HKCU", APP, RegValue("A", REG_SZ, "x"))
    assert w.find(w.HKEY_CURRENT_USER, APP) is None


def test_create_key_idempotent(w, be):
    be.create_key("HKCU", APP + r"\A\B")
    be.create_key("HKCU", APP + r"\A\B")
    assert w.find(w.HKEY_CURRENT_USER, APP + r"\A\B") is not None
    assert w.leaked == 0


def test_key_exists(w, be):
    w.add(w.HKEY_CURRENT_USER, APP, deny_mask=0xFFFFFFFF & ~(KEY_WOW64_64KEY))
    assert be.key_exists("HKCU", APP) is True  # denied still means present
    assert be.key_exists("HKCU", r"SOFTWARE\Nope") is False
    w.fail_next("OpenKeyEx", _err(32))
    with pytest.raises(RegistryError):
        be.key_exists("HKCU", APP)
    assert w.leaked == 0


def test_subkeys_and_enumeration_end(w, be):
    w.add(w.HKEY_CURRENT_USER, APP + r"\One")
    w.add(w.HKEY_CURRENT_USER, APP + r"\Two")
    assert be.subkeys("HKCU", APP) == ["One", "Two"]
    assert be.subkeys("HKCU", APP + r"\One") == []
    assert be.values("HKCU", APP) == []
    assert w.leaked == 0


def test_can_delete(w, be):
    w.add(w.HKEY_CURRENT_USER, APP + r"\Ok", [("V", 1, REG_DWORD)])
    w.add(w.HKEY_CURRENT_USER, APP + r"\Locked", [("V", 1, REG_DWORD)], deny_mask=DELETE)
    w.add(w.HKEY_CURRENT_USER, APP + r"\RO", [("V", 1, REG_DWORD)], deny_mask=KEY_SET_VALUE)
    assert be.can_delete("HKCU", APP + r"\Ok", None) is True
    assert be.can_delete("HKCU", APP + r"\Locked", None) is False
    assert be.can_delete("HKCU", APP + r"\Missing", None) is False
    assert be.can_delete("HKCU", APP + r"\Ok", "V") is True
    assert be.can_delete("HKCU", APP + r"\Ok", "Missing") is False
    assert be.can_delete("HKCU", APP + r"\RO", "V") is False
    assert be.can_delete("HKCU", APP + r"\Missing", "V") is False
    key_opens = [c for c in w.calls if c[0] == "OpenKeyEx" and c[2] == APP + r"\Ok"]
    assert key_opens[0][4] == DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY
    assert key_opens[1][4] & KEY_SET_VALUE and key_opens[1][4] & KEY_WOW64_64KEY
    w.fail_next("OpenKeyEx", _err(32))
    with pytest.raises(RegistryError):
        be.can_delete("HKCU", APP + r"\Ok", None)
    assert w.leaked == 0


@pytest.mark.parametrize("hive", ["hkcu", "Hkcu", "HKCR", "HKU", "HKCC",
                                  "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "", None])
def test_unknown_hive_rejected(w, be, hive):
    calls = [
        lambda: be.subkeys(hive, APP),
        lambda: be.values(hive, APP),
        lambda: be.key_exists(hive, APP),
        lambda: be.is_link(hive, APP),
        lambda: be.can_delete(hive, APP, None),
        lambda: be.can_delete(hive, APP, "V"),
        lambda: be.delete_key(hive, APP),
        lambda: be.delete_value(hive, APP, "V"),
        lambda: be.create_key(hive, APP),
        lambda: be.set_value(hive, APP, RegValue("V", REG_SZ, "x")),
    ]
    for call in calls:
        with pytest.raises(ValueError):
            call()
    assert w.calls == []


@pytest.mark.parametrize("key", ["", "\\", "\\SOFTWARE", "SOFTWARE\\", "SOFTWARE\\\\X",
                                 "SOFTWARE\\X\x00Y", None])
def test_malformed_key_rejected(w, be, key):
    for call in (
        lambda: be.subkeys("HKCU", key),
        lambda: be.is_link("HKCU", key),
        lambda: be.delete_key("HKCU", key),
        lambda: be.delete_value("HKCU", key, "V"),
        lambda: be.create_key("HKCU", key),
    ):
        with pytest.raises(ValueError):
            call()
    assert w.calls == []


def test_handles_closed_on_error(w, be):
    w.add(w.HKEY_CURRENT_USER, APP + r"\Child", [("A", "x", REG_SZ)])
    w.add(w.HKEY_CURRENT_USER, APP + r"\Leaf", [("A", "x", REG_SZ)])
    cases = [
        ("EnumKey", lambda: be.subkeys("HKCU", APP)),
        ("EnumValue", lambda: be.values("HKCU", APP + r"\Child")),
        ("QueryValueEx", lambda: be.is_link("HKCU", APP)),
        ("QueryValueEx", lambda: be.delete_key("HKCU", APP + r"\Leaf")),
        ("QueryInfoKey", lambda: be.delete_key("HKCU", APP + r"\Leaf")),
        ("QueryValueEx", lambda: be.delete_value("HKCU", APP + r"\Child", "A")),
        ("DeleteValue", lambda: be.delete_value("HKCU", APP + r"\Child", "A")),
        ("SetValueEx", lambda: be.set_value("HKCU", APP, RegValue("A", REG_SZ, "x"))),
    ]
    for op, call in cases:
        w.fail_next(op, _err(5, PermissionError))
        with pytest.raises(AccessDenied):
            call()
        assert w.leaked == 0, op
    # can_delete answers False on a denied query, and still closes.
    w.fail_next("QueryValueEx", _err(5, PermissionError))
    assert be.can_delete("HKCU", APP + r"\Child", "A") is False
    w.fail_next("QueryValueEx", _err(32))
    with pytest.raises(RegistryError):
        be.can_delete("HKCU", APP + r"\Child", "A")
    assert w.leaked == 0
    # A non-OSError escaping mid-operation still closes the handle.
    w.fail_next("EnumKey", RuntimeError("boom"))  # type: ignore[arg-type]
    with pytest.raises(RuntimeError):
        be.subkeys("HKCU", APP)
    assert w.leaked == 0
    assert w.opened > 0


def test_get_backend_selects_win_backend_only_on_win32(monkeypatch, _no_real_registry):
    from cleanix.core.winregistry_win import WinRegBackend

    fake = FakeWinreg()
    monkeypatch.setitem(sys.modules, "winreg", fake)
    saved_real = winregistry._real
    try:
        winregistry.set_backend(None)
        winregistry._real = None
        monkeypatch.setattr(sys, "platform", "win32")
        b = winregistry.get_backend()
        assert isinstance(b, WinRegBackend)
        assert b._w is fake  # built with the injected module, not the real one
        for plat in ("linux", "darwin"):
            winregistry._real = None
            monkeypatch.setattr(sys, "platform", plat)
            other = winregistry.get_backend()
            assert not isinstance(other, WinRegBackend)
            with pytest.raises(winregistry.RegistryUnavailable):
                other.subkeys("HKCU", APP)
            assert winregistry._real is None
    finally:
        winregistry._real = saved_real
        winregistry.set_backend(_no_real_registry)
    assert fake.calls == []  # constructing the backend touches nothing
    assert winregistry.get_backend() is _no_real_registry


def test_module_imports_without_winreg():
    code = (
        "import sys; sys.modules['winreg'] = None\n"
        "import cleanix.core.winregistry_win as m\n"
        "try:\n"
        "    m.WinRegBackend()\n"
        "except ImportError:\n"
        "    print('ok')\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO,
        env={**__import__("os").environ, "PYTHONPATH": str(REPO)},
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "ok"


@pytest.mark.skipif(sys.platform != "win32", reason="real winreg constants only on Windows")
def test_fake_constants_match_real_winreg():
    import importlib

    real = importlib.import_module("winreg")  # constants only; no registry call
    for name in ("KEY_QUERY_VALUE", "KEY_SET_VALUE", "KEY_CREATE_SUB_KEY",
                 "KEY_ENUMERATE_SUB_KEYS", "KEY_WOW64_64KEY", "KEY_WOW64_32KEY",
                 "KEY_READ", "KEY_WRITE", "REG_OPTION_OPEN_LINK", "REG_NONE",
                 "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REG_LINK",
                 "REG_MULTI_SZ", "REG_QWORD"):
        assert getattr(real, name) == getattr(FakeWinreg, name), name


def test_matches_fake_registry_semantics(w, be):
    """The fake backend used by every other test agrees with this one."""
    from _fakereg import FakeRegistry

    ref = FakeRegistry()
    ref.add_key("HKCU", APP + r"\Child", {"A": (REG_SZ, "x")})
    w.add(w.HKEY_CURRENT_USER, APP + r"\Child", [("A", "x", REG_SZ)])
    for b in (ref, be):
        assert b.key_exists("HKCU", APP) and not b.key_exists("HKCU", APP + r"\No")
        assert b.subkeys("HKCU", APP) == ["Child"]
        assert b.values("HKCU", APP + r"\Child") == [RegValue("A", REG_SZ, "x")]
        assert b.is_link("HKCU", APP) is False
        with pytest.raises(KeyMissing):
            b.is_link("HKCU", APP + r"\No")
        with pytest.raises(RegistryError):
            b.delete_key("HKCU", APP)  # not a leaf
        with pytest.raises(KeyMissing):
            b.delete_value("HKCU", APP + r"\Child", "B")
        assert b.can_delete("HKCU", APP + r"\No", None) is False
        with pytest.raises(ValueError):
            b.subkeys("HKEY_CURRENT_USER", APP)


# -- fix round 1 -----------------------------------------------------------------
def _link(w, path=r"SOFTWARE\Vendor\Link", target=r"SOFTWARE\Target", values=()):
    w.add(w.HKEY_CURRENT_USER, target, values)
    w.add(w.HKEY_CURRENT_USER, path, link_to=(w.HKEY_CURRENT_USER, target))


def test_set_value_refuses_link_key(w, be):
    _link(w, values=[("A", "x", REG_SZ)])
    with pytest.raises(RegistryError):
        be.set_value("HKCU", r"SOFTWARE\Vendor\Link", RegValue("A", REG_SZ, "evil"))
    assert w.find(w.HKEY_CURRENT_USER, r"SOFTWARE\Target").values == {"a": ("A", "x", REG_SZ)}
    assert not [c for c in w.calls if c[0] == "SetValueEx"]
    opens = [c for c in w.calls if c[0] == "OpenKeyEx"]
    assert opens and all(c[3] & REG_OPTION_OPEN_LINK for c in opens)
    assert w.leaked == 0


def test_writes_open_the_key_itself_with_needed_rights(w, be):
    w.add(w.HKEY_CURRENT_USER, APP, [("A", "x", REG_SZ)])
    be.set_value("HKCU", APP, RegValue("B", REG_SZ, "y"))
    be.delete_value("HKCU", APP, "A")
    assert len(w.handles) == 2
    for h in w.handles:
        assert h.options == REG_OPTION_OPEN_LINK
        assert h.access == KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY
    assert w.leaked == 0


def test_delete_key_check_handle_rights(w, be):
    w.add(w.HKEY_CURRENT_USER, APP + r"\Leaf")
    be.delete_key("HKCU", APP + r"\Leaf")
    (h,) = w.handles  # DeleteKeyEx itself takes a path, not a handle
    assert h.options == REG_OPTION_OPEN_LINK
    assert h.access & KEY_QUERY_VALUE and h.access & KEY_WOW64_64KEY


def test_subkeys_requests_only_enumerate(w, be):
    w.add(w.HKEY_CURRENT_USER, APP + r"\One", deny_mask=KEY_QUERY_VALUE)
    w.add(w.HKEY_CURRENT_USER, APP, deny_mask=KEY_QUERY_VALUE)
    assert be.subkeys("HKCU", APP) == ["One"]
    assert [h.access for h in w.handles] == [KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY]


def test_create_key_passes_no_options(w, be):
    be.create_key("HKCU", APP)
    (c,) = [c for c in w.calls if c[0] == "CreateKeyEx"]
    assert c[3] == 0


def test_key_exists_does_not_follow_links(w, be):
    # A dangling link exists as a key (the link itself); following it would
    # wrongly report the key as missing.
    w.add(w.HKEY_CURRENT_USER, r"SOFTWARE\Vendor\Dangling",
          link_to=(w.HKEY_CURRENT_USER, r"SOFTWARE\Gone"))
    assert be.key_exists("HKCU", r"SOFTWARE\Vendor\Dangling") is True
    assert be.is_link("HKCU", r"SOFTWARE\Vendor\Dangling") is True
    assert all(h.options == REG_OPTION_OPEN_LINK for h in w.handles)
    assert w.leaked == 0


def test_fake_delete_key_ex_follows_final_link_pessimistically(w):
    _link(w)
    w.DeleteKeyEx(w.HKEY_CURRENT_USER, r"SOFTWARE\Vendor\Link", KEY_WOW64_64KEY, 0)
    assert w.find(w.HKEY_CURRENT_USER, r"SOFTWARE\Target") is None
    assert w.find(w.HKEY_CURRENT_USER, r"SOFTWARE\Vendor\Link") is not None
    safe = FakeWinreg(delete_follows_final_link=False)
    _link(safe)
    safe.DeleteKeyEx(safe.HKEY_CURRENT_USER, r"SOFTWARE\Vendor\Link", KEY_WOW64_64KEY, 0)
    assert safe.find(safe.HKEY_CURRENT_USER, r"SOFTWARE\Target") is not None


def test_r17_link_swapped_in_after_check_deletes_target(w, be):
    """Documents the accepted residual race (ruling R17); not a guarantee.

    delete_key checks link-ness and leaf-ness on a handle immediately before
    DeleteKeyEx, which resolves the path again. If the leaf is replaced by a
    registry link in between and RegDeleteKeyEx follows a final-component
    link (the pessimistic model here), the link TARGET leaf is deleted. The
    real behaviour must be measured in Task 14; Task 11 re-verifies the
    target's fingerprint immediately before calling delete_key."""
    w.add(w.HKEY_CURRENT_USER, r"SOFTWARE\Victim")
    w.add(w.HKEY_CURRENT_USER, APP + r"\Leaf")

    def swap():
        parent = w.find(w.HKEY_CURRENT_USER, APP)
        del parent.children["leaf"]
        w.add(w.HKEY_CURRENT_USER, APP + r"\Leaf",
              link_to=(w.HKEY_CURRENT_USER, r"SOFTWARE\Victim"))

    w.before["DeleteKeyEx"] = swap
    be.delete_key("HKCU", APP + r"\Leaf")
    assert w.find(w.HKEY_CURRENT_USER, r"SOFTWARE\Victim") is None  # the consequence
    assert w.find(w.HKEY_CURRENT_USER, APP + r"\Leaf") is not None


def test_close_failure_does_not_mask_original_error(w, be):
    w.add(w.HKEY_CURRENT_USER, APP + r"\One")
    w.close_fails = True
    w.fail_next("EnumKey", _err(5, PermissionError))
    with pytest.raises(AccessDenied):
        be.subkeys("HKCU", APP)
    with pytest.raises(RegistryError) as info:  # clean body: the close error surfaces
        be.subkeys("HKCU", APP)
    assert type(info.value) is RegistryError
    with pytest.raises(RegistryError):
        be.create_key("HKCU", APP + r"\New")
    assert w.leaked == 0


def test_nul_names_are_registry_errors(w, be):
    from cleanix.core.models import RegTarget
    from cleanix.core.regsnap import SnapshotError, snapshot

    bad = APP + "\\Bad\x00Name"
    w.add(w.HKEY_CURRENT_USER, bad)
    w.add(w.HKEY_CURRENT_USER, APP + r"\Good")
    assert sorted(be.subkeys("HKCU", APP)) == ["Bad\x00Name", "Good"]
    for call in (
        lambda: be.values("HKCU", bad),
        lambda: be.subkeys("HKCU", bad),
        lambda: be.is_link("HKCU", bad),
        lambda: be.key_exists("HKCU", bad),
        lambda: be.can_delete("HKCU", bad, None),
        lambda: be.can_delete("HKCU", APP, "V\x00"),
        lambda: be.delete_value("HKCU", APP, "V\x00"),
    ):
        with pytest.raises(RegistryError) as info:
            call()
        assert isinstance(info.value, ValueError)  # still a ValueError for callers
    with pytest.raises(SnapshotError):  # a scan sees a skip, not a crash
        snapshot(be, RegTarget("HKCU", APP, None, ""))
    # A ValueError raised by winreg itself is mapped too.
    for op, call in (
        ("EnumValue", lambda: be.values("HKCU", APP)),
        ("EnumKey", lambda: be.subkeys("HKCU", APP)),
        ("QueryValueEx", lambda: be.is_link("HKCU", APP)),
        ("OpenKeyEx", lambda: be.can_delete("HKCU", APP, None)),
    ):
        w.fail_next(op, ValueError("embedded null character"))
        with pytest.raises(RegistryError):
            call()
    assert w.leaked == 0
