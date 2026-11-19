"""win_reg_uninstall: dead Apps & Features entries."""

from __future__ import annotations

import pytest

from types import SimpleNamespace

from _fakereg import FakeProber
from cleanix.cleaners import winreg_uninstall as wu
from cleanix.config import Config
from cleanix.cleaners.winreg_uninstall import WinRegUninstall
from cleanix.core.regtargets import (
    DetectorContext,
    Existence,
    WinProber,
    microsoft_roots,
)

P, M, U = Existence.PRESENT, Existence.MISSING, Existence.UNKNOWN

CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
CVW = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
ENV = {
    "ProgramFiles": r"C:\Program Files",
    "ProgramW6432": r"C:\Program Files",
    "ProgramFiles(x86)": r"C:\Program Files (x86)",
    "ProgramData": r"C:\ProgramData",
    "LOCALAPPDATA": r"C:\Users\me\AppData\Local",
    "SystemRoot": r"C:\Windows",
    "SystemDrive": "C:",
}
SZ, XSZ, BIN, DW = 1, 2, 3, 4
LOC = r"C:\Apps\Foo"
UNINS = r"C:\Apps\Foo\unins000.exe"


def _dead(**over):
    v = {
        "DisplayName": (SZ, "Foo Tool"),
        "InstallLocation": (SZ, LOC),
        "UninstallString": (SZ, f'"{UNINS}" /SILENT'),
    }
    v.update(over)
    return {k: x for k, x in v.items() if x is not None}


@pytest.fixture
def run(fake_registry, monkeypatch):
    def go(states=None, *, owner=True, ctx_owner=True, env=ENV, default=M, ctx=None):
        if ctx is None:
            prober = FakeProber(states or {}, default=default)
            ctx = DetectorContext(
                env, prober, r"C:\Users", r"C:\Windows",
                owner_matches=ctx_owner and owner,
            )
        det = WinRegUninstall(Config())
        monkeypatch.setattr(det, "context", lambda: ctx)
        report = det.scan()
        assert report.skipped_reason is None
        return list(report.items)

    return go


def _add(reg, name, values, hive="HKCU", base=CV):
    reg.add_key(hive, f"{base}\\{name}", values)


def test_dead_entry_listed(fake_registry, run):
    _add(fake_registry, "Foo", _dead(Publisher=(SZ, "Foo Inc")))
    (item,) = run()
    assert item.description == "Uninstall entry: Foo Tool (Foo Inc)"
    assert item.reg.hive == "HKCU" and item.reg.key == f"{CV}\\Foo"
    assert item.requires_root is False
    assert f"InstallLocation -> {LOC}: missing" in item.hint
    assert "UninstallString" in item.hint and "missing" in item.hint


def test_description_without_publisher(fake_registry, run):
    _add(fake_registry, "Foo", _dead())
    (item,) = run()
    assert item.description == "Uninstall entry: Foo Tool"


@pytest.mark.parametrize("base", [CV, CVW])
def test_dead_entry_listed_hklm(fake_registry, run, base):
    _add(fake_registry, "Foo", _dead(), "HKLM", base)
    (item,) = run()
    assert item.requires_root is True and item.reg.key == f"{base}\\Foo"


def test_optional_values_all_missing_still_listed(fake_registry, run):
    _add(
        fake_registry,
        "Foo",
        _dead(
            QuietUninstallString=(SZ, r"C:\Apps\Foo\q.exe /S"),
            ModifyPath=(XSZ, r"%ProgramFiles%\Foo\m.exe"),
            DisplayIcon=(SZ, r'"C:\Apps\Foo\foo.exe",0'),
        ),
    )
    (item,) = run()
    for n in ("QuietUninstallString", "ModifyPath", "DisplayIcon"):
        assert n in item.hint
    assert r"C:\Apps\Foo\foo.exe" in item.hint


def test_unicode_display_name_and_args(fake_registry, run):
    _add(
        fake_registry,
        "Foo",
        _dead(
            DisplayName=(SZ, "Программа \u00e9\u4e2d"),
            UninstallString=(SZ, f'"{UNINS}" /x "arg"'),
        ),
    )
    (item,) = run()
    assert "Программа" in item.description


def test_per_user_install_owner_matches(fake_registry, run):
    vals = _dead(
        InstallLocation=(XSZ, r"%LOCALAPPDATA%\Programs\Foo"),
        UninstallString=(XSZ, r'"%LOCALAPPDATA%\Programs\Foo\unins000.exe"'),
    )
    _add(fake_registry, "Foo", vals)
    assert len(run(owner=True)) == 1
    assert run(owner=False) == []


@pytest.mark.parametrize(
    "case",
    [
        "empty_location",
        "location_present",
        "uninstaller_unc",
        "msiexec",
        "windows_installer",
        "system_component",
        "system_component_str",
        "parent_key",
        "release_type",
        "kb_name",
        "kb_display",
        "microsoft_publisher",
        "no_display_name",
        "empty_display_name",
        "subkey",
        "icon_present",
        "quiet_unknown",
        "modifypath_present",
        "undefined_var",
        "binary_uninstall",
        "location_absent",
        "uninstall_absent",
        "location_binary",
        "icon_dword",
        "publisher_binary",
        "location_unc",
        "microsoft_upper",
        "kb_lower",
        "guid_key",
        "bundle_cache",
        "bundle_provider",
        "bundle_tag",
        "product_code",
        "inno_present",
    ],
)
def test_entry_kept(fake_registry, run, case):
    name = "Foo"
    states = {}
    v = _dead()
    if case == "empty_location":
        v["InstallLocation"] = (SZ, "")
    elif case == "location_present":
        states[LOC] = P
    elif case == "uninstaller_unc":
        v["UninstallString"] = (SZ, r"\\srv\share\unins.exe")
        states[r"\\srv\share\unins.exe"] = U
    elif case == "msiexec":
        v["UninstallString"] = (SZ, "MsiExec.exe /X{11111111-2222-3333-4444-555555555555}")
    elif case == "windows_installer":
        v["WindowsInstaller"] = (DW, 1)
    elif case == "system_component":
        v["SystemComponent"] = (DW, 1)
    elif case == "system_component_str":
        v["SystemComponent"] = (SZ, "1")
    elif case == "parent_key":
        v["ParentKeyName"] = (SZ, "OperatingSystem")
    elif case == "release_type":
        v["ReleaseType"] = (SZ, "Update")
    elif case == "kb_name":
        name = "KB5034441"
    elif case == "kb_display":
        v["DisplayName"] = (SZ, "Security Update (KB5034441)")
    elif case == "microsoft_publisher":
        v["Publisher"] = (SZ, "Microsoft Corporation")
    elif case == "no_display_name":
        del v["DisplayName"]
    elif case == "empty_display_name":
        v["DisplayName"] = (SZ, "  ")
    elif case == "subkey":
        fake_registry.add_key("HKCU", f"{CV}\\Foo\\Sub")
    elif case == "icon_present":
        v["DisplayIcon"] = (SZ, r"C:\Apps\Foo\foo.exe,0")
        states[r"C:\Apps\Foo\foo.exe"] = P
    elif case == "quiet_unknown":
        v["QuietUninstallString"] = (SZ, r"\\srv\q.exe /S")
        states[r"\\srv\q.exe"] = U
    elif case == "modifypath_present":
        v["ModifyPath"] = (SZ, r"C:\Apps\Foo\mod.exe")
        states[r"C:\Apps\Foo\mod.exe"] = P
    elif case == "undefined_var":
        v["InstallLocation"] = (XSZ, r"%UNDEFINED%\Foo")
    elif case == "binary_uninstall":
        v["UninstallString"] = (BIN, b"C:\\x.exe\0")
    elif case == "location_absent":
        del v["InstallLocation"]
    elif case == "uninstall_absent":
        del v["UninstallString"]
    elif case == "location_binary":
        v["InstallLocation"] = (BIN, b"abc")
    elif case == "icon_dword":
        v["DisplayIcon"] = (DW, 3)
    elif case == "publisher_binary":
        v["Publisher"] = (BIN, b"x")
    elif case == "microsoft_upper":
        v["Publisher"] = (SZ, "MICROSOFT CORPORATION")
    elif case == "kb_lower":
        name = "kb5034441"
    elif case == "guid_key":
        name = "{11111111-2222-3333-4444-555555555555}"
        v["UninstallString"] = (SZ, r"C:\Program Files\InstallShield\setup.exe /x")
    elif case == "bundle_cache":
        v["BundleCachePath"] = (SZ, r"C:\ProgramData\Package Cache\x\setup.exe")
    elif case == "bundle_provider":
        v["BundleProviderKey"] = (SZ, "x")
    elif case == "bundle_tag":
        v["BundleTag"] = (SZ, "x")
    elif case == "product_code":
        v["ProductCode"] = (SZ, "{11111111-2222-3333-4444-555555555555}")
    elif case == "inno_present":
        v["Inno Setup: App Path"] = (SZ, r"C:\Apps\FooApp")
        states[r"C:\Apps\FooApp"] = P
    elif case == "location_unc":
        v["InstallLocation"] = (SZ, r"\\srv\share\Foo")
        states[r"\\srv\share\Foo"] = U
    _add(fake_registry, name, v)
    assert run(states) == []


def test_hklm_location_under_users_kept(fake_registry, run):
    _add(fake_registry, "Foo", _dead(InstallLocation=(SZ, r"C:\Users\x\Foo")), "HKLM")
    assert run() == []


def test_hklm_per_user_variable_kept(fake_registry, run):
    _add(
        fake_registry,
        "Foo",
        _dead(InstallLocation=(XSZ, r"%LOCALAPPDATA%\Programs\Foo")),
        "HKLM",
    )
    assert run() == []


def test_per_user_install_ctx_owner_false_not_listed(fake_registry, run):
    vals = _dead(
        InstallLocation=(XSZ, r"%LOCALAPPDATA%\Programs\Foo"),
        UninstallString=(XSZ, r'"%LOCALAPPDATA%\Programs\Foo\unins000.exe"'),
    )
    _add(fake_registry, "Foo", vals)
    assert run(owner=True, ctx_owner=False) == []
    assert len(run(owner=True, ctx_owner=True)) == 1


def test_machine_paths_still_judged_when_owner_differs(fake_registry, run):
    _add(fake_registry, "Foo", _dead())
    assert len(run(owner=False)) == 1


def test_backup_problem_entry_skipped(fake_registry, run):
    v = _dead()
    v["Bad\nName"] = (SZ, "x")  # a value name restore can never recreate
    _add(fake_registry, "Foo", v)
    assert run() == []


def test_unreadable_entry_skipped(fake_registry, run):
    fake_registry.add_key("HKCU", f"{CV}\\Foo", _dead(), deny_read=True)
    assert run() == []


def test_link_entry_skipped(fake_registry, run):
    fake_registry.add_key("HKCU", f"{CV}\\Foo", _dead(), link=True)
    assert run() == []


def test_missing_containers_are_fine(fake_registry, run):
    assert run() == []


def test_uninstall_never_touches_unlisted_containers(fake_registry, run):
    _add(fake_registry, "Foo", _dead())
    _add(fake_registry, "Foo", _dead(), "HKLM", CVW)
    fake_registry.add_key(
        "HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", {"a": (SZ, "b")}
    )
    fake_registry.calls.clear()
    assert len(run()) == 2
    roots = [c.casefold() for c in (CV, CVW)]
    for call in fake_registry.calls:
        op = call[0]
        assert op in {"subkeys", "values", "key_exists", "is_link"}, call
        if op in ("subkeys", "values"):
            assert any(call[2].casefold().startswith(r) for r in roots), call


class _FS:
    def __init__(self, present):
        self.present = {p.casefold() for p in present} | {"c:\\"}

    def lstat(self, path):
        if path.casefold() in self.present:
            return SimpleNamespace(st_file_attributes=0x10)
        err = OSError("nf")
        err.winerror = 3
        raise err


def _real_ctx(present):
    fs = _FS(present)
    prober = WinProber(
        system_root=r"C:\Windows",
        program_files=microsoft_roots(ENV, "C:"),
        program_data=r"C:\ProgramData",
        local_appdata=r"C:\Users\me\AppData\Local",
        drive_type=lambda root: 3,
        lstat=fs.lstat,
    )
    return DetectorContext(ENV, prober, r"C:\Users", r"C:\Windows")


@pytest.mark.parametrize("value", ["ModifyPath", "QuietUninstallString"])
def test_command_values_with_arguments_are_judged_as_commands(
    fake_registry, run, value
):
    _add(
        fake_registry,
        "Foo",
        _dead(**{value: (SZ, r"C:\Apps\Foo\mod.exe /modify")}),
    )
    assert run(ctx=_real_ctx([r"C:\Apps\Foo\mod.exe"])) == []
    # sanity: with the program really gone the same entry is listed
    assert len(run(ctx=_real_ctx([]))) == 1


def test_inno_app_path_missing_still_listed(fake_registry, run):
    _add(fake_registry, "Foo", _dead(**{"Inno Setup: App Path": (SZ, r"C:\Apps\FooApp")}))
    (item,) = run()
    assert "Inno Setup: App Path" in item.hint


def test_inno_app_path_unknown_keeps(fake_registry, run):
    _add(fake_registry, "Foo", _dead(**{"Inno Setup: App Path": (SZ, r"D:\Apps\FooApp")}))
    assert run({r"D:\Apps\FooApp": U}) == []


def test_install_source_and_non_path_values_ignored(fake_registry, run):
    _add(
        fake_registry,
        "Foo",
        _dead(InstallSource=(SZ, r"C:\Users\me\Downloads"), URLInfoAbout=(SZ, "http://x")),
    )
    assert len(run({r"C:\Users\me\Downloads": P})) == 1


def test_description_sanitised_truncated_and_view_marker(fake_registry, run):
    _add(fake_registry, "Foo", _dead(DisplayName=(SZ, "Fo\x00o\n" + "x" * 500)))
    _add(fake_registry, "Bar", _dead(DisplayName=(SZ, "Foo")), "HKLM", CV)
    _add(fake_registry, "Bar", _dead(DisplayName=(SZ, "Foo")), "HKLM", CVW)
    descs = sorted(i.description for i in run())
    assert "Uninstall entry: Foo" in descs
    assert "Uninstall entry: Foo [32-bit]" in descs
    long = [d for d in descs if d.startswith("Uninstall entry: Foox")]
    assert len(long) == 1
    assert "\n" not in long[0] and "\x00" not in long[0]
    assert len(long[0]) == len("Uninstall entry: ") + 200
