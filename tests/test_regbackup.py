"""Registry backup files (.reg + JSON) and validated restore. Fake registry only."""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path

import pytest

from _fakereg import FakeRegistry
from cleanix.core import regbackup
from cleanix.core.models import RegTarget
from cleanix.core.regbackup import (
    BackupError,
    RestoreError,
    restore_entry,
    to_reg_text,
    write_backup,
)
from cleanix.core.regsnap import KeySnap, fingerprint, from_jsonable, snapshot
from cleanix.core.winregistry import (
    REG_BINARY,
    REG_DWORD,
    REG_EXPAND_SZ,
    REG_MULTI_SZ,
    REG_NONE,
    REG_QWORD,
    REG_SZ,
    AccessDenied,
    RegValue,
)

UNINST = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
SHARED = r"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs"
APP = UNINST + r"\MyApp"

WRITES = ("set_value", "create_key", "delete_key", "delete_value")


def _writes(reg: FakeRegistry):
    return [c for c in reg.calls if c[0] in WRITES]


# -- fixtures -------------------------------------------------------------------
ODD = {
    "": (REG_SZ, 'say "hi" C:\\x'),
    'q"\\n': (REG_SZ, "plain"),
    "Ünïcødé ✓": (REG_SZ, "日本語"),
    "crlf": (REG_SZ, "a\r\nb"),
    "exp": (REG_EXPAND_SZ, "%ProgramFiles%\\x"),
    "ms": (REG_MULTI_SZ, ("a", "", "b")),
    "ms_empty": (REG_MULTI_SZ, ()),
    "dw": (REG_DWORD, 0xFFFFFFFF),
    "qw": (REG_QWORD, 0x0102030405060708),
    "bin": (REG_BINARY, b"\x00\xff\x10"),
    "bin_empty": (REG_BINARY, b""),
    "odd": (0x20, b"\x01\x02"),
    "C:\\Program Files\\X\\a.dll": (REG_DWORD, 3),
}


def _odd_tree(reg: FakeRegistry, hive: str = "HKCU") -> RegTarget:
    reg.add_key(hive, APP, ODD)
    reg.add_key(hive, APP + r"\Sub", {"x": (REG_SZ, "y")})
    reg.add_key(hive, APP + '\\Sub\\Deep "q"', {"z": (REG_DWORD, 1)})
    reg.add_key(hive, APP + r"\Empty")
    t = RegTarget(hive, APP)
    return dataclasses.replace(t, fingerprint=fingerprint(t, snapshot(reg, t)))


def _target_for(reg, hive, key, value=None) -> RegTarget:
    t = RegTarget(hive, key, value)
    return dataclasses.replace(t, fingerprint=fingerprint(t, snapshot(reg, t)))


def _delete_tree(reg: FakeRegistry, hive: str, key: str) -> None:
    for sub in reg.subkeys(hive, key):
        _delete_tree(reg, hive, key + "\\" + sub)
    reg.delete_key(hive, key)


def _backup(tmp_path, reg, target, cleaner="win_reg_uninstall", index=1):
    snap = snapshot(reg, target)
    return write_backup(tmp_path / "run", index, cleaner, target, snap)


# -- a tiny .reg parser (test helper, not product code) ---------------------------
def _parse_quoted(s: str, i: int):
    assert s[i] == '"'
    i += 1
    out = []
    while s[i] != '"':
        if s[i] == "\\":
            i += 1
        out.append(s[i])
        i += 1
    return "".join(out), i + 1


def _hexbytes(text: str) -> bytes:
    return bytes(int(x, 16) for x in text.split(",")) if text else b""


def _decode(typ: int, raw: bytes):
    if typ in (REG_SZ, REG_EXPAND_SZ):
        s = raw.decode("utf-16-le", "surrogatepass")
        assert s.endswith("\0")
        return s[:-1]
    if typ == REG_MULTI_SZ:
        s = raw.decode("utf-16-le", "surrogatepass")
        assert s.endswith("\0")
        parts = s[:-1].split("\0")
        assert parts[-1] == ""
        return tuple(parts[:-1])
    if typ == REG_QWORD:
        assert len(raw) == 8
        return int.from_bytes(raw, "little")
    return raw


def parse_reg(text: str):
    lines = text.split("\r\n")
    assert lines[0] == "Windows Registry Editor Version 5.00"
    assert lines[1] == ""
    sections = {}
    cur = None
    for line in lines[2:]:
        if not line:
            continue
        if line.startswith("["):
            assert line.endswith("]")
            cur = line[1:-1]
            sections[cur] = []
            continue
        if line.startswith("@="):
            name, rest = "", line[2:]
        else:
            name, j = _parse_quoted(line, 0)
            assert line[j] == "="
            rest = line[j + 1:]
        if rest.startswith('"'):
            data, j = _parse_quoted(rest, 0)
            assert j == len(rest)
            v = RegValue(name, REG_SZ, data)
        elif rest.startswith("dword:"):
            v = RegValue(name, REG_DWORD, int(rest[6:], 16))
        elif rest.startswith("hex:"):
            v = RegValue(name, REG_BINARY, _hexbytes(rest[4:]))
        else:
            assert rest.startswith("hex(")
            close = rest.index("):")
            typ = int(rest[4:close], 16)
            v = RegValue(name, typ, _decode(typ, _hexbytes(rest[close + 2:])))
        sections[cur].append(v)
    return sections


def _flatten(prefix: str, snap: KeySnap, out: dict) -> dict:
    out[prefix] = list(snap.values)
    for s in snap.subkeys:
        _flatten(prefix + "\\" + s.name, s, out)
    return out


# -- .reg text --------------------------------------------------------------------
def test_reg_text_golden():
    snap = KeySnap(
        name="MyApp",
        values=(
            RegValue("", REG_SZ, 'say "hi" C:\\x'),
            RegValue('q"\\n', REG_SZ, "plain"),
            RegValue("crlf", REG_SZ, "a\r\nb"),
            RegValue("exp", REG_EXPAND_SZ, "%A%"),
            RegValue("ms", REG_MULTI_SZ, ("a", "", "b")),
            RegValue("dw", REG_DWORD, 0x1234),
            RegValue("qw", REG_QWORD, 0x0102030405060708),
            RegValue("bin", REG_BINARY, b"\x00\xff"),
            RegValue("odd", 0x20, b"\x01"),
            RegValue("none", REG_NONE, None),
        ),
        subkeys=(KeySnap("Sub", (RegValue("x", REG_SZ, "y"),), ()),),
    )
    text = to_reg_text(RegTarget("HKCU", APP), snap)
    expected = "\r\n".join(
        [
            "Windows Registry Editor Version 5.00",
            "",
            "[HKEY_CURRENT_USER\\" + APP + "]",
            '@="say \\"hi\\" C:\\\\x"',
            '"q\\"\\\\n"="plain"',
            '"crlf"=hex(1):61,00,0d,00,0a,00,62,00,00,00',
            '"exp"=hex(2):25,00,41,00,25,00,00,00',
            '"ms"=hex(7):61,00,00,00,00,00,62,00,00,00,00,00',
            '"dw"=dword:00001234',
            '"qw"=hex(b):08,07,06,05,04,03,02,01',
            '"bin"=hex:00,ff',
            '"odd"=hex(20):01',
            '"none"=hex(0):',
            "",
            "[HKEY_CURRENT_USER\\" + APP + "\\Sub]",
            '"x"="y"',
            "",
            "",
        ]
    )
    assert text == expected


def test_reg_text_value_target_only_one_value():
    t = RegTarget("HKLM", SHARED, "C:\\Program Files\\X\\a.dll")
    text = to_reg_text(t, RegValue("C:\\Program Files\\X\\a.dll", REG_DWORD, 2))
    assert text == (
        "Windows Registry Editor Version 5.00\r\n\r\n"
        "[HKEY_LOCAL_MACHINE\\" + SHARED + "]\r\n"
        '"C:\\\\Program Files\\\\X\\\\a.dll"=dword:00000002\r\n\r\n'
    )


def test_reg_file_is_utf16_bom_crlf(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    raw = files.reg_path.read_bytes()
    assert raw.startswith(b"\xff\xfe")
    text = raw[2:].decode("utf-16-le")
    assert text.startswith("Windows Registry Editor Version 5.00\r\n\r\n")
    assert "\n" not in text.replace("\r\n", "")
    assert text == to_reg_text(t, snapshot(fake_registry, t))
    assert files.reg_path.name == "1__registry.reg"
    assert files.json_path.name == "1__registry.json"


def test_reg_and_json_agree(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    doc = json.loads(files.json_path.read_text(encoding="utf-8"))
    assert doc["format"] == 1
    assert doc["cleaner_id"] == "win_reg_uninstall"
    assert (doc["hive"], doc["key"], doc["value"]) == ("HKCU", APP, None)
    assert doc["fingerprint"] == t.fingerprint
    from_json = _flatten("HKEY_CURRENT_USER\\" + APP, from_jsonable(doc["snapshot"]), {})
    from_reg = parse_reg(files.reg_path.read_bytes()[2:].decode("utf-16-le"))
    assert from_reg == from_json


def test_json_value_target_round_trip(tmp_path, fake_registry):
    name = "C:\\Program Files\\X\\a.dll"
    fake_registry.add_key("HKLM", SHARED, {name: (REG_DWORD, 2), "other": (REG_DWORD, 1)})
    t = _target_for(fake_registry, "HKLM", SHARED, name)
    files = _backup(tmp_path, fake_registry, t, cleaner="win_reg_shared_dlls")
    doc = json.loads(files.json_path.read_text(encoding="utf-8"))
    assert doc["value"] == name
    assert from_jsonable(doc["snapshot"]) == RegValue(name, REG_DWORD, 2)
    sections = parse_reg(files.reg_path.read_bytes()[2:].decode("utf-16-le"))
    assert sections == {"HKEY_LOCAL_MACHINE\\" + SHARED: [RegValue(name, REG_DWORD, 2)]}


# -- write_backup -----------------------------------------------------------------
def test_write_backup_verifies_readback(tmp_path, fake_registry, monkeypatch):
    t = _odd_tree(fake_registry)
    real = regbackup._write_atomic

    def corrupting(path, data):
        if str(path).endswith(".json"):
            i = data.index(b'"plain"') + 1
            data = data[:i] + b"P" + data[i + 1:]
        real(path, data)

    monkeypatch.setattr(regbackup, "_write_atomic", corrupting)
    with pytest.raises(BackupError):
        _backup(tmp_path, fake_registry, t)


def test_write_backup_rejects_truncated_readback(tmp_path, fake_registry, monkeypatch):
    t = _odd_tree(fake_registry)
    real = regbackup._write_atomic
    monkeypatch.setattr(
        regbackup, "_write_atomic",
        lambda p, d: real(p, d[: len(d) // 2] if str(p).endswith(".json") else d),
    )
    with pytest.raises(BackupError):
        _backup(tmp_path, fake_registry, t)


def test_write_backup_fingerprint_mismatch(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    stale = dataclasses.replace(t, fingerprint="0" * 64)
    with pytest.raises(BackupError):
        _backup(tmp_path, fake_registry, stale)


def test_write_backup_refuses_overwrite_and_bad_index(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    _backup(tmp_path, fake_registry, t, index=3)
    with pytest.raises(BackupError):
        _backup(tmp_path, fake_registry, t, index=3)
    for bad in (-1, True, "1", "../x"):
        with pytest.raises(BackupError):
            write_backup(tmp_path / "run", bad, "win_reg_uninstall", t, snapshot(fake_registry, t))


def test_write_backup_refuses_unrestorable_target(tmp_path, fake_registry):
    """A backup that restore would refuse must block the delete now."""
    t = _odd_tree(fake_registry)
    with pytest.raises(BackupError):
        _backup(tmp_path, fake_registry, t, cleaner="win_reg_startup")


def test_write_backup_leaves_no_temp_files(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    _backup(tmp_path, fake_registry, t)
    assert sorted(p.name for p in (tmp_path / "run").iterdir()) == [
        "1__registry.json", "1__registry.reg",
    ]


# -- restore ----------------------------------------------------------------------
def test_restore_recreates_tree_exactly(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    _delete_tree(fake_registry, "HKCU", APP)
    shown = restore_entry(files.json_path, fake_registry, is_admin=False)
    assert shown == t.display
    assert fingerprint(t, snapshot(fake_registry, t)) == t.fingerprint


def test_restore_is_idempotent(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    _delete_tree(fake_registry, "HKCU", APP)
    restore_entry(files.json_path, fake_registry, is_admin=False)
    fake_registry.calls.clear()
    restore_entry(files.json_path, fake_registry, is_admin=False)
    assert _writes(fake_registry) == []


def test_restore_merges_after_partial_delete(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    _delete_tree(fake_registry, "HKCU", APP + r"\Empty")
    fake_registry.calls.clear()
    restore_entry(files.json_path, fake_registry, is_admin=False)
    assert [c[0] for c in _writes(fake_registry)] == ["create_key"]
    assert fingerprint(t, snapshot(fake_registry, t)) == t.fingerprint


def test_restore_value_target(tmp_path, fake_registry):
    fake_registry.add_key("HKCU", RUN, {"MyApp": (REG_SZ, "C:\\gone\\a.exe"), "Keep": (REG_SZ, "k")})
    t = _target_for(fake_registry, "HKCU", RUN, "MyApp")
    files = _backup(tmp_path, fake_registry, t, cleaner="win_reg_startup")
    fake_registry.delete_value("HKCU", RUN, "MyApp")
    fake_registry.calls.clear()
    restore_entry(files.json_path, fake_registry, is_admin=False)
    assert [c[0] for c in _writes(fake_registry)] == ["set_value"]
    assert fake_registry.tree("HKCU", RUN)["values"]["MyApp"] == (REG_SZ, "C:\\gone\\a.exe")


def test_restore_conflict_writes_nothing(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    _delete_tree(fake_registry, "HKCU", APP + r"\Empty")
    fake_registry.set_value("HKCU", APP + r"\Sub", RegValue("x", REG_SZ, "changed"))
    fake_registry.calls.clear()
    with pytest.raises(RestoreError):
        restore_entry(files.json_path, fake_registry, is_admin=False)
    assert _writes(fake_registry) == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.set_value("HKCU", APP, RegValue("dw", REG_QWORD, 0xFFFFFFFF)),
        lambda r: r.set_value("HKCU", APP, RegValue("DW", REG_DWORD, 0xFFFFFFFF)),
        lambda r: r.set_value("HKCU", APP, RegValue("extra", REG_SZ, "x")),
        lambda r: r.add_key("HKCU", APP + r"\Extra"),
        lambda r: r.add_key("HKCU", APP + r"\sub"),
    ],
    ids=["type", "name-case", "extra-value", "extra-subkey", "subkey-case"],
)
def test_restore_other_conflicts_write_nothing(tmp_path, fake_registry, mutate):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    _delete_tree(fake_registry, "HKCU", APP + r"\Sub")
    _delete_tree(fake_registry, "HKCU", APP + r"\Empty")
    mutate(fake_registry)
    fake_registry.calls.clear()
    with pytest.raises(RestoreError):
        restore_entry(files.json_path, fake_registry, is_admin=False)
    assert _writes(fake_registry) == []


def test_restore_reports_partial_failure(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    _delete_tree(fake_registry, "HKCU", APP)
    fake_registry.fail_next("set_value", AccessDenied("nope"))
    with pytest.raises(RestoreError) as ei:
        restore_entry(files.json_path, fake_registry, is_admin=False)
    assert "partially" in str(ei.value)
    # A second attempt completes the merge.
    restore_entry(files.json_path, fake_registry, is_admin=False)
    assert fingerprint(t, snapshot(fake_registry, t)) == t.fingerprint


def test_restore_hklm_needs_admin(tmp_path, fake_registry):
    name = "C:\\Program Files\\X\\a.dll"
    fake_registry.add_key("HKLM", SHARED, {name: (REG_DWORD, 2)})
    t = _target_for(fake_registry, "HKLM", SHARED, name)
    files = _backup(tmp_path, fake_registry, t, cleaner="win_reg_shared_dlls")
    fake_registry.delete_value("HKLM", SHARED, name)
    fake_registry.calls.clear()
    with pytest.raises(RestoreError) as ei:
        restore_entry(files.json_path, fake_registry, is_admin=False)
    msg = str(ei.value)
    assert fake_registry.calls == []
    assert "reg import" in msg and "{run}" in msg
    assert f'"{os.path.abspath(files.reg_path)}"' in msg
    restore_entry(files.json_path, fake_registry, is_admin=True)
    assert fake_registry.tree("HKLM", SHARED)["values"][name] == (REG_DWORD, 2)


def test_restore_hkcu_classes_anchor_link_is_trusted(tmp_path, fake_registry):
    key = r"SOFTWARE\Classes\myapp.doc"
    fake_registry.add_key("HKCU", r"SOFTWARE\Classes", link=True)
    fake_registry.add_key("HKCU", key, {"": (REG_SZ, "My doc")})
    t = _target_for(fake_registry, "HKCU", key)
    # snapshot() refuses only links inside the tree, not above it.
    files = _backup(tmp_path, fake_registry, t, cleaner="win_reg_file_assoc")
    _delete_tree(fake_registry, "HKCU", key)
    restore_entry(files.json_path, fake_registry, is_admin=False)
    assert fingerprint(t, snapshot(fake_registry, t)) == t.fingerprint


# -- tamper matrix ------------------------------------------------------------------
def _tampered(tmp_path, fake_registry, edit, *, refingerprint=True, cleaner=None):
    """Back up the odd tree, delete it, apply ``edit`` to the JSON document and
    (by default) recompute the digest so the guard, not the digest, refuses."""
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    _delete_tree(fake_registry, "HKCU", APP)
    doc = json.loads(files.json_path.read_text(encoding="utf-8"))
    edit(doc)
    if refingerprint:
        try:
            tt = RegTarget(doc["hive"], doc["key"], doc["value"])
            doc["fingerprint"] = fingerprint(tt, from_jsonable(doc["snapshot"]))
        except Exception:
            pass
    files.json_path.write_text(json.dumps(doc), encoding="utf-8")
    fake_registry.calls.clear()
    return files


def _expect_refused(fake_registry, files, **kw):
    with pytest.raises(RestoreError):
        restore_entry(files.json_path, fake_registry, is_admin=kw.get("admin", True))
    assert _writes(fake_registry) == []


def _set(path, value):
    def edit(doc):
        obj = doc
        for p in path[:-1]:
            obj = obj[p]
        obj[path[-1]] = value
    return edit


def _sub(i):
    return ["snapshot", "subkeys", i]


TAMPER = {
    "modified-digest": (_set(["fingerprint"], "f" * 64), False),
    "digest-not-hex": (_set(["fingerprint"], "x"), False),
    "key-system": (_set(["key"], r"SYSTEM\x"), True),
    "key-hklm-system": (lambda d: d.update(hive="HKLM", key=r"SYSTEM\CurrentControlSet\x"), True),
    "key-denied-winnt": (_set(["key"], r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"), True),
    "key-policies": (_set(["key"], UNINST + r"\Policies"), True),
    "key-is-container": (_set(["key"], UNINST), True),
    "key-two-below": (_set(["key"], APP + r"\Deeper"), True),
    "key-traversal": (_set(["key"], UNINST + r"\..\Run"), True),
    "cleaner-not-owner": (_set(["cleaner_id"], "win_reg_startup"), True),
    "cleaner-unknown": (_set(["cleaner_id"], "evil"), True),
    "hive-hku": (_set(["hive"], "HKU"), True),
    "hive-long": (_set(["hive"], "HKEY_CURRENT_USER"), True),
    "hive-hkcr": (_set(["hive"], "HKCR"), True),
    "subkey-backslash": (_set(_sub(0) + ["name"], r"..\..\Run"), True),
    "subkey-dotdot": (_set(_sub(0) + ["name"], ".."), True),
    "subkey-empty": (_set(_sub(0) + ["name"], ""), True),
    "subkey-control": (_set(_sub(0) + ["name"], "a\nb"), True),
    "subkey-policies": (_set(_sub(0) + ["name"], "Policies"), True),
    "subkey-dup": (lambda d: d["snapshot"]["subkeys"].append(
        dict(d["snapshot"]["subkeys"][0], name="SUB")), True),
    "value-dup": (lambda d: d["snapshot"]["values"].append(
        dict(d["snapshot"]["values"][0], name="DW")), True),
    "root-name": (_set(["snapshot", "name"], "Other"), True),
    "type-link": (_set(["snapshot", "values", 0, "type"], 6), True),
    "type-string": (_set(["snapshot", "values", 0, "type"], "1"), True),
    "type-bool": (_set(["snapshot", "values", 0, "type"], True), True),
    "type-negative": (_set(["snapshot", "values", 0, "type"], -1), True),
    "type-huge": (_set(["snapshot", "values", 0, "type"], 2 ** 40), True),
    "dword-str": (lambda d: d["snapshot"]["values"].append(
        {"name": "zz", "type": REG_DWORD, "data": "1"}), True),
    "dword-range": (lambda d: d["snapshot"]["values"].append(
        {"name": "zz", "type": REG_DWORD, "data": 2 ** 32}), True),
    "dword-bool": (lambda d: d["snapshot"]["values"].append(
        {"name": "zz", "type": REG_DWORD, "data": True}), True),
    "qword-negative": (lambda d: d["snapshot"]["values"].append(
        {"name": "zz", "type": REG_QWORD, "data": -1}), True),
    "multi-nonstr": (lambda d: d["snapshot"]["values"].append(
        {"name": "zz", "type": REG_MULTI_SZ, "data": ["a", 1]}), True),
    "binary-bad-b64": (lambda d: d["snapshot"]["values"].append(
        {"name": "zz", "type": REG_BINARY, "data": {"b64": "!!!"}}), True),
    "binary-str": (lambda d: d["snapshot"]["values"].append(
        {"name": "zz", "type": REG_BINARY, "data": "abc"}), True),
    "binary-extra-field": (lambda d: d["snapshot"]["values"].append(
        {"name": "zz", "type": REG_BINARY, "data": {"b64": "", "x": 1}}), True),
    "value-name-nul": (lambda d: d["snapshot"]["values"].append(
        {"name": "a\0b", "type": REG_SZ, "data": "x"}), True),
    "value-symlink-name": (lambda d: d["snapshot"]["values"].append(
        {"name": "SymbolicLinkValue", "type": REG_SZ, "data": "x"}), True),
    "value-extra-field": (_set(["snapshot", "values", 0, "extra"], 1), True),
    "kind-unknown": (_set(["snapshot", "kind"], "link"), True),
    "kind-value-for-key": (lambda d: d.update(snapshot={"kind": "value", "name": "x", "type": 1, "data": "y"}), True),
    "format-2": (_set(["format"], 2), True),
    "format-bool": (_set(["format"], True), True),
    "format-missing": (lambda d: d.pop("format"), True),
    "extra-top-field": (_set(["extra"], 1), True),
    "too-many-keys": (lambda d: d["snapshot"]["subkeys"].extend(
        {"kind": "key", "name": f"k{i}", "values": [], "subkeys": []} for i in range(300)), True),
    "too-many-values": (lambda d: d["snapshot"]["values"].extend(
        {"name": f"v{i}", "type": REG_DWORD, "data": 1} for i in range(5000)), True),
    "too-much-data": (lambda d: d["snapshot"]["values"].append(
        {"name": "big", "type": REG_SZ, "data": "x" * 600_000}), True),
}


@pytest.mark.parametrize("case", sorted(TAMPER))
def test_restore_refuses_tampered(tmp_path, fake_registry, case):
    edit, refp = TAMPER[case]
    files = _tampered(tmp_path, fake_registry, edit, refingerprint=refp)
    _expect_refused(fake_registry, files)


def test_restore_refuses_tampered_paths(tmp_path, fake_registry):
    for case in ("key-system", "subkey-backslash", "cleaner-not-owner"):
        reg = FakeRegistry()
        edit, refp = TAMPER[case]
        files = _tampered(tmp_path / case, reg, edit, refingerprint=refp)
        _expect_refused(reg, files)


def test_restore_rejects_unknown_format(tmp_path, fake_registry):
    files = _tampered(tmp_path, fake_registry, _set(["format"], 99))
    with pytest.raises(RestoreError):
        restore_entry(files.json_path, fake_registry, is_admin=True)
    assert fake_registry.calls == []


def test_restore_refuses_link_in_tree(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    _delete_tree(fake_registry, "HKCU", APP + r"\Empty")
    fake_registry.add_key("HKCU", APP + r"\Sub", link=True)
    fake_registry.calls.clear()
    _expect_refused(fake_registry, files)


def test_restore_refuses_link_ancestor(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    _delete_tree(fake_registry, "HKCU", APP)
    fake_registry.add_key("HKCU", UNINST, link=True)
    fake_registry.calls.clear()
    _expect_refused(fake_registry, files)


@pytest.mark.parametrize(
    "mangle",
    [
        lambda b: b[: len(b) // 2],
        lambda b: b"",
        lambda b: b"\x00" + b,
        lambda b: b.replace(b'"format": 1', b'"format": 1, "format": 1', 1),
        lambda b: b.replace(b'"format": 1', b'"format": NaN', 1),
        lambda b: b"[" * 100000 + b"]" * 100000,
        lambda b: b + b" " * (regbackup.MAX_FILE_BYTES + 1),
    ],
    ids=["truncated", "empty", "garbage", "dup-key", "nan", "deep", "oversized-file"],
)
def test_restore_refuses_malformed_file(tmp_path, fake_registry, mangle):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    _delete_tree(fake_registry, "HKCU", APP)
    raw = files.json_path.read_bytes()
    files.json_path.write_bytes(mangle(raw))
    fake_registry.calls.clear()
    with pytest.raises(RestoreError):
        restore_entry(files.json_path, fake_registry, is_admin=True)
    assert fake_registry.calls == []


@pytest.mark.parametrize(
    "name", ["x__registry.json", "1__registry.json.bak", "1__registry.reg", "..__registry.json", "1_registry.json"]
)
def test_restore_refuses_bad_file_names(tmp_path, fake_registry, name):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    other = files.json_path.with_name(name)
    other.write_bytes(files.json_path.read_bytes())
    fake_registry.calls.clear()
    with pytest.raises(RestoreError):
        restore_entry(other, fake_registry, is_admin=True)
    assert fake_registry.calls == []


def test_restore_refuses_symlinked_json(tmp_path, fake_registry):
    t = _odd_tree(fake_registry)
    files = _backup(tmp_path, fake_registry, t)
    link = files.json_path.with_name("7__registry.json")
    try:
        os.symlink(files.json_path, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    fake_registry.calls.clear()
    with pytest.raises(RestoreError):
        restore_entry(link, fake_registry, is_admin=True)
    assert fake_registry.calls == []


def test_restore_missing_file(tmp_path, fake_registry):
    with pytest.raises(RestoreError):
        restore_entry(tmp_path / "1__registry.json", fake_registry, is_admin=True)
    assert fake_registry.calls == []


def test_tests_never_create_cleanix_settings_key(fake_registry):
    assert not fake_registry.key_exists("HKCU", r"Software\Cleanix")
