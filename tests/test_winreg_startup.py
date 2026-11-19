from __future__ import annotations

import pytest
from _fakereg import FakeProber

from cleanix.cleaners.winreg_startup import WinRegStartup
from cleanix.config import Config
from cleanix.core.regtargets import DetectorContext, Existence
from cleanix.core.winregistry import REG_BINARY, REG_EXPAND_SZ, REG_SZ

CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
CVW = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion"
M = Existence.MISSING
P = Existence.PRESENT
ENV = {
    "ProgramFiles": r"C:\Program Files",
    "SystemRoot": r"C:\Windows",
    "LOCALAPPDATA": r"C:\Users\u\AppData\Local",
}


def detector(states=None, default=M, owner=True):
    prober = FakeProber(states or {}, default)
    ctx = DetectorContext(ENV, prober, r"C:\Users", r"C:\Windows", owner)

    class Det(WinRegStartup):
        def context(self):
            return ctx

    return Det(Config())


def items(det):
    return det.scan().items


@pytest.mark.parametrize(
    "hive,key",
    [
        ("HKCU", CV + r"\Run"),
        ("HKCU", CV + r"\RunOnce"),
        ("HKLM", CV + r"\Run"),
        ("HKLM", CVW + r"\Run"),
        ("HKLM", CVW + r"\RunOnce"),
    ],
)
def test_dead_run_value_listed(fake_registry, hive, key):
    fake_registry.add_key(hive, key, {"Foo": (REG_SZ, r'"C:\Gone\foo.exe" -silent')})
    (it,) = items(detector())
    assert it.reg.hive == hive and it.reg.key == key and it.reg.value == "Foo"
    assert it.description == "Startup entry: Foo"
    assert r"C:\Gone\foo.exe" in it.hint and "missing" in it.hint
    assert it.requires_root is (hive == "HKLM")
    assert it.size == 0


def test_runonce_prefixed_names_ok(fake_registry):
    fake_registry.add_key("HKCU", CV + r"\RunOnce", {"!Foo": (REG_SZ, r"C:\Gone\x.exe")})
    (it,) = items(detector())
    assert it.reg.value == "!Foo"


def test_expand_sz_and_unicode_names(fake_registry):
    fake_registry.add_key(
        "HKLM",
        CV + r"\Run",
        {"Ünï ✓": (REG_EXPAND_SZ, r"%ProgramFiles%\Gone\a.exe")},
    )
    (it,) = items(detector())
    assert it.reg.value == "Ünï ✓"


def test_value_name_with_backslash_never_aborts(fake_registry):
    fake_registry.add_key("HKLM", CV + r"\Run", {r"Back\Slash": (REG_SZ, r"C:\Gone\b.exe")})
    assert len(items(detector())) <= 1  # listed or skipped, never an error


def test_present_kept(fake_registry):
    fake_registry.add_key("HKCU", CV + r"\Run", {"A": (REG_SZ, r"C:\Here\a.exe /x")})
    assert items(detector({r"C:\Here\a.exe": P})) == []


@pytest.mark.parametrize(
    "hive,data,typ",
    [
        ("HKCU", r"rundll32.exe C:\Gone\x.dll,Start", REG_SZ),
        ("HKCU", r"cmd /c C:\Gone\x.bat", REG_SZ),
        ("HKCU", r"powershell -file C:\Gone\x.ps1", REG_SZ),
        ("HKCU", r"\\server\share\x.exe", REG_SZ),
        ("HKCU", r"%UNDEFINED%\x.exe", REG_EXPAND_SZ),
        ("HKLM", r"%LOCALAPPDATA%\x\x.exe", REG_EXPAND_SZ),
        ("HKLM", r"C:\Users\bob\x.exe", REG_SZ),
        ("HKCU", b"\x01\x02", REG_BINARY),
        ("HKCU", "", REG_SZ),
        ("HKCU", r"x.exe", REG_SZ),
        ("HKCU", r'"C:\Gone\x.exe"junk', REG_SZ),
        ("HKCU", r"C:\Gone\x.exe " + "a" * 2000, REG_SZ),
    ],
)
def test_uncertain_kept(fake_registry, hive, data, typ):
    fake_registry.add_key(hive, CV + r"\Run", {"A": (typ, data)})
    assert items(detector(default=M)) == []


def test_unquoted_path_with_spaces_prefix_exists(fake_registry):
    fake_registry.add_key(
        "HKCU", CV + r"\Run", {"A": (REG_SZ, r"C:\Program Files\X\x.exe -silent")}
    )
    assert items(detector({r"C:\Program Files\X\x.exe": P})) == []


def test_unknown_state_kept(fake_registry):
    fake_registry.add_key("HKCU", CV + r"\Run", {"A": (REG_SZ, r"E:\x.exe")})
    assert items(detector(default=Existence.UNKNOWN)) == []


def test_per_user_var_unknown_when_owner_differs(fake_registry):
    fake_registry.add_key(
        "HKCU", CV + r"\Run", {"A": (REG_EXPAND_SZ, r"%LOCALAPPDATA%\x\x.exe")}
    )
    assert len(items(detector(owner=True))) == 1
    assert items(detector(owner=False)) == []


def test_default_value_never_listed(fake_registry):
    fake_registry.add_key("HKCU", CV + r"\Run", {"": (REG_SZ, r"C:\Gone\x.exe")})
    assert items(detector()) == []


def test_policies_run_not_read(fake_registry):
    pol = CV + r"\Policies\Explorer\Run"
    fake_registry.add_key("HKCU", pol, {"A": (REG_SZ, r"C:\Gone\x.exe")})
    assert items(detector()) == []


def test_winreg_startup_never_touches_unlisted_containers(fake_registry):
    fake_registry.add_key("HKCU", CV + r"\Run", {"A": (REG_SZ, r"C:\Gone\x.exe")})
    fake_registry.add_key(
        "HKCU", CV + r"\Explorer\StartupApproved\Run", {"A": (REG_BINARY, b"\x03")}
    )
    fake_registry.add_key("HKCU", CV + r"\Policies\Explorer\Run", {"A": (REG_SZ, "x")})
    fake_registry.calls.clear()
    items(detector())
    allowed = {CV + r"\Run", CV + r"\RunOnce", CVW + r"\Run", CVW + r"\RunOnce"}
    for call in fake_registry.calls:
        assert call[0] in ("values", "key_exists", "is_link", "subkeys", "can_delete")
        if call[0] == "values":  # content is only ever read from the containers
            assert call[2] in allowed
        else:  # the base's link checks may look at ancestors of a container
            assert any(a == call[2] or a.startswith(call[2] + "\\") for a in allowed)
