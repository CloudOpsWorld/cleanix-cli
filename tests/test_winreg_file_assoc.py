"""win_reg_file_assoc: dead file-type handlers (ProgId / Applications entries)."""

from __future__ import annotations

import dataclasses

import pytest

from _fakereg import FakeProber
from cleanix.cleaners.winreg_file_assoc import WinRegFileAssoc
from cleanix.config import Config
from cleanix.core.regtargets import DetectorContext, Existence
from cleanix.core.winregistry import REG_BINARY, REG_DWORD, REG_SZ

CL = r"SOFTWARE\Classes"
GONE = r"C:\gone\app.exe"
LIVE = r"C:\live\app.exe"
CMD_GONE = '"C:\\gone\\app.exe" "%1"'
CMD_LIVE = '"C:\\live\\app.exe" "%1"'
REMOVABLE = r"E:\tools\app.exe"
S = Existence


def make_ctx(owner_matches=True, states=None):
    st = {GONE: S.MISSING, LIVE: S.PRESENT}
    st.update(states or {})
    prober = FakeProber(st, default=S.UNKNOWN)
    return DetectorContext(
        env={"SystemRoot": r"C:\Windows", "ProgramFiles": r"C:\Program Files"},
        prober=prober,
        profiles_root=r"C:\Users",
        system_root=r"C:\Windows",
        owner_matches=owner_matches,
    )


def scan(ctx=None):
    det = WinRegFileAssoc(Config())
    c = ctx or make_ctx()
    det.context = lambda: c
    return det.scan().items


def names(items):
    return sorted((i.reg.hive, i.reg.key) for i in items)


def progid(reg, name, cmd=CMD_GONE, hive="HKCU", base=CL, icon=None, extra_verbs=None):
    root = f"{base}\\{name}"
    reg.add_key(hive, root, {"": (REG_SZ, "Friendly")})
    verbs = {"open": cmd}
    verbs.update(extra_verbs or {})
    for v, c in verbs.items():
        reg.add_key(hive, f"{root}\\shell\\{v}\\command", {"": (REG_SZ, c)})
    if icon is not None:
        reg.add_key(hive, f"{root}\\DefaultIcon", {"": (REG_SZ, icon)})
    return root


def test_dead_progid_listed(fake_registry):
    progid(fake_registry, "MyApp.File", icon=GONE + ",0")
    items = scan()
    assert names(items) == [("HKCU", CL + r"\MyApp.File")]
    it = items[0]
    assert it.description == "File-type handler: MyApp.File"
    assert it.requires_root is False
    assert "missing" in it.hint and GONE in it.hint and "DefaultIcon" in it.hint
    assert it.reg.fingerprint


def test_dead_progid_hklm_requires_root(fake_registry):
    progid(fake_registry, "MyApp.File", hive="HKLM")
    items = scan()
    assert names(items) == [("HKLM", CL + r"\MyApp.File")]
    assert items[0].requires_root is True


def test_dead_applications_entry_listed(fake_registry):
    progid(fake_registry, "gone.exe", base=CL + r"\Applications")
    items = scan()
    assert names(items) == [("HKCU", CL + r"\Applications\gone.exe")]
    assert items[0].description == "File-type handler: gone.exe"


def test_dead_applications_entry_hklm(fake_registry):
    progid(fake_registry, "gone.exe", base=CL + r"\Applications", hive="HKLM")
    assert names(scan()) == [("HKLM", CL + r"\Applications\gone.exe")]


def test_all_verbs_must_be_missing(fake_registry):
    progid(fake_registry, "A.B", extra_verbs={"edit": CMD_LIVE})
    assert scan() == []


def test_two_dead_verbs_listed(fake_registry):
    progid(fake_registry, "A.B", extra_verbs={"edit": CMD_GONE})
    assert len(scan()) == 1


def test_one_verb_present_kept(fake_registry):
    progid(fake_registry, "A.B", cmd=CMD_LIVE)
    assert scan() == []


def test_icon_present_kept(fake_registry):
    progid(fake_registry, "A.B", icon=LIVE + ",0")
    assert scan() == []


def test_icon_unknown_kept(fake_registry):
    progid(fake_registry, "A.B", icon=r"\\srv\share\x.ico")
    assert scan() == []


def test_icon_non_string_kept(fake_registry):
    progid(fake_registry, "A.B")
    fake_registry.add_key("HKCU", CL + r"\A.B\DefaultIcon", {"": (REG_DWORD, 1)})
    assert scan() == []


def test_unquoted_command_unknown_kept(fake_registry):
    progid(fake_registry, "A.B", cmd=r"C:\gone\app.exe %1")
    assert scan() == []


def test_removable_drive_kept(fake_registry):
    progid(fake_registry, "A.B", cmd=f'"{REMOVABLE}" "%1"')
    assert scan() == []  # prober answers UNKNOWN for E:


def test_rundll32_kept(fake_registry):
    progid(fake_registry, "A.B", cmd=r"rundll32.exe C:\gone\x.dll,Open %1")
    assert scan() == []


def test_delegate_execute_kept(fake_registry):
    progid(fake_registry, "A.B")
    fake_registry.add_key(
        "HKCU", CL + r"\A.B\shell\open\command", {"DelegateExecute": (REG_SZ, "{GUID}")}
    )
    assert scan() == []


def test_command_without_default_kept(fake_registry):
    fake_registry.add_key(
        "HKCU", CL + r"\A.B\shell\open\command", {"DelegateExecute": (REG_SZ, "{G}")}
    )
    assert scan() == []


def test_command_binary_default_kept(fake_registry):
    progid(fake_registry, "A.B")
    fake_registry.add_key("HKCU", CL + r"\A.B\shell\open\command", {"": (REG_BINARY, b"x")})
    assert scan() == []


@pytest.mark.parametrize(
    "sub",
    [
        r"shellex",
        r"shellex\ContextMenuHandlers",
        r"CLSID",
        r"CurVer",
        r"ShellNew",
        r"OpenWithList",
        r"OpenWithProgids",
        r"SupportedTypes",
        r"shell\open\ddeexec",
        r"shell\open\DropTarget",
        r"shell\open\command\extra",
        r"shell\open\shellex",
        r"Extra",
    ],
)
def test_unexpected_subkey_kept(fake_registry, sub):
    progid(fake_registry, "A.B")
    fake_registry.add_key("HKCU", CL + r"\A.B" + "\\" + sub)
    assert scan() == []


def test_shell_without_verbs_kept(fake_registry):
    fake_registry.add_key("HKCU", CL + r"\A.B\shell")
    fake_registry.add_key("HKCU", CL + r"\A.B\DefaultIcon", {"": (REG_SZ, GONE)})
    assert scan() == []


def test_no_shell_at_all_kept(fake_registry):
    fake_registry.add_key("HKCU", CL + r"\A.B", {"": (REG_SZ, "x")})
    assert scan() == []


@pytest.mark.parametrize(
    "val",
    ["URL Protocol", "CLSID", "AppUserModelID", "PackageId", "DelegateExecute", "Mystery"],
)
def test_entry_value_kept(fake_registry, val):
    root = progid(fake_registry, "A.B")
    fake_registry.add_key("HKCU", root, {val: (REG_SZ, "")})
    assert scan() == []


def test_url_protocol_on_verb_kept(fake_registry):
    progid(fake_registry, "A.B")
    fake_registry.add_key("HKCU", CL + r"\A.B\shell\open", {"URL Protocol": (REG_SZ, "")})
    assert scan() == []


def test_extra_value_on_command_kept(fake_registry):
    progid(fake_registry, "A.B")
    fake_registry.add_key("HKCU", CL + r"\A.B\shell\open\command", {"Other": (REG_SZ, "x")})
    assert scan() == []


def test_verb_icon_evidence(fake_registry):
    progid(fake_registry, "A.B")
    fake_registry.add_key("HKCU", CL + r"\A.B\shell\open", {"Icon": (REG_SZ, LIVE + ",0")})
    assert scan() == []
    fake_registry.add_key("HKCU", CL + r"\A.B\shell\open", {"Icon": (REG_SZ, GONE + ",0")})
    assert len(scan()) == 1


def test_extension_key_not_reported(fake_registry):
    progid(fake_registry, ".txt")
    fake_registry.add_key("HKCU", CL + r"\.zzz", {"": (REG_SZ, "Dead.ProgId")})
    assert scan() == []


@pytest.mark.parametrize(
    "name",
    [
        "AppX123", "Word.Document.12", "Excel.Sheet.12", "txtfile", "http", "mailto",
        "regfile", "exefile", "Microsoft.Foo", "Windows.Thing", "ms-settings",
        "Component Categories", "Directory", "Folder", "*", "Unknown",
        "CLSID", "Interface", "Installer", "TypeLib",
    ],
)
def test_windows_names_kept(fake_registry, name):
    progid(fake_registry, name)
    assert scan() == []


def test_windows_builtin_application_kept(fake_registry):
    progid(
        fake_registry, "notepad.exe", base=CL + r"\Applications",
        cmd=CMD_GONE,
    )
    assert scan() == []


def test_non_ascii_name_refused(fake_registry):
    progid(fake_registry, "Ap\u00e9.File")
    assert scan() == []


def test_applications_itself_kept(fake_registry):
    fake_registry.add_key("HKCU", CL + r"\Applications", {"": (REG_SZ, "x")})
    assert scan() == []


def test_link_subkey_kept(fake_registry):
    progid(fake_registry, "A.B")
    fake_registry.add_key("HKCU", CL + r"\A.B\shell\open\command", link=True)
    assert scan() == []


def test_link_entry_kept(fake_registry):
    progid(fake_registry, "A.B")
    fake_registry.add_key("HKCU", CL + r"\A.B", link=True)
    assert scan() == []


def test_clsid_subtree_never_candidate(fake_registry):
    fake_registry.add_key(
        "HKLM", CL + r"\CLSID\{1234}\shell\open\command", {"": (REG_SZ, CMD_GONE)}
    )
    assert scan() == []
    deep = [c for c in fake_registry.calls if "clsid" in c[2].casefold()]
    assert deep == []


def test_wow6432node_name_refused(fake_registry):
    progid(fake_registry, "WOW6432Node", hive="HKLM")
    assert scan() == []


def test_unreadable_entry_skipped(fake_registry):
    progid(fake_registry, "A.B")
    progid(fake_registry, "C.D")
    fake_registry.add_key("HKCU", CL + r"\A.B\shell\open\command", deny_read=True)
    assert names(scan()) == [("HKCU", CL + r"\C.D")]


def test_hkcu_skipped_when_owner_differs(fake_registry):
    progid(fake_registry, "A.B")
    progid(fake_registry, "C.D", hive="HKLM")
    assert names(scan(make_ctx(owner_matches=False))) == [("HKLM", CL + r"\C.D")]


def test_per_user_var_unknown_for_hklm(fake_registry):
    progid(fake_registry, "A.B", hive="HKLM", cmd='"%LOCALAPPDATA%\\gone\\app.exe" "%1"')
    ctx = make_ctx()
    ctx = dataclasses.replace(ctx, env={**ctx.env, "LOCALAPPDATA": r"C:\Users\x\AppData\Local"})
    assert scan(ctx) == []


def test_hklm_under_users_unknown(fake_registry):
    progid(fake_registry, "A.B", hive="HKLM", cmd=r'"C:\Users\x\app.exe" "%1"')
    assert scan(make_ctx(states={r"C:\Users\x\app.exe": S.MISSING})) == []


def test_backup_problem_skipped(fake_registry):
    progid(fake_registry, "A.B")
    fake_registry.add_key("HKCU", CL + r"\A.B", {"bad\nname": (REG_SZ, "x")})
    assert scan() == []


def test_file_assoc_never_touches_unlisted_containers(fake_registry):
    progid(fake_registry, "A.B")
    fake_registry.add_key("HKCU", r"SOFTWARE\Other\X")
    progid(fake_registry, "C.D", hive="HKLM", base=CL + r"\Applications")
    scan()
    assert fake_registry.calls
    for call in fake_registry.calls:
        assert call[0] in ("subkeys", "values", "key_exists", "is_link"), call
        assert call[2].casefold().startswith(r"software\classes"), call
