"""Target evidence: env expansion, command parsing, tri-state existence."""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from cleanix.core import regtargets as rt
from cleanix.core.regtargets import (
    CommandParse,
    DetectorContext,
    Existence,
    WinProber,
    expand_env,
    microsoft_roots,
    parse_command,
    strip_icon_index,
    target_state,
)
from cleanix.core.winregistry import RegistryUnavailable

P, M, U = Existence.PRESENT, Existence.MISSING, Existence.UNKNOWN

from _fakeprobe import ENV, FakeFS, WinErr, make_ctx  # noqa: F401 (re-exported)


def test_expand_env():
    assert expand_env(r"%ProgramFiles%\a", ENV) == r"C:\Program Files\a"
    assert expand_env(r"%programfiles%\a", ENV) == r"C:\Program Files\a"
    assert expand_env(r"%NOPE%\a", ENV) is None
    assert expand_env(r"C:\plain", ENV) == r"C:\plain"
    assert expand_env(r"%ProgramFiles(x86)%\a", ENV) == r"C:\Program Files (x86)\a"


def test_strip_icon_index():
    assert strip_icon_index(r"C:\a.exe,0") == r"C:\a.exe"
    assert strip_icon_index(r"C:\a.exe,-12") == r"C:\a.exe"
    assert strip_icon_index(r"C:\a.exe") == r"C:\a.exe"
    assert strip_icon_index(r"C:\a,b.exe") == r"C:\a,b.exe"


def test_parse_command_quoted_and_args():
    p = parse_command(r'"C:\P F\u.exe" /S')
    assert isinstance(p, CommandParse)
    assert p.candidates == (r"C:\P F\u.exe",)
    assert not p.host and not p.relative


def test_parse_command_unquoted_spaces():
    p = parse_command(r"C:\Program Files\Foo\unins.exe /x")
    c = list(p.candidates)
    assert c.index(r"C:\Program") < c.index(r"C:\Program.exe") < c.index(
        r"C:\Program Files\Foo\unins.exe"
    )
    assert not p.relative


def test_parse_command_hosts():
    assert parse_command(r"MsiExec.exe /X{GUID}").host
    assert parse_command(r"rundll32.exe C:\x.dll,Run").host
    assert parse_command(r"cmd /c x").host
    assert parse_command(r'"C:\Windows\System32\cmd.exe" /c x').host
    assert not parse_command(r'"C:\Foo\unins.exe" /S').host


def test_parse_command_unparseable():
    for bad in ("", "   ", '"C:\\a.exe', '"C:\\a b"\\c.exe'):
        p = parse_command(bad)
        assert p.relative and p.candidates == ()


def test_microsoft_roots_dedup_and_32bit():
    r = microsoft_roots({"ProgramFiles": r"C:\Program Files (x86)"}, "C:")
    low = [x.casefold() for x in r]
    assert r"c:\program files" in low and r"c:\program files (x86)" in low
    assert len(low) == len(set(low))
    r2 = microsoft_roots(ENV, "c:")
    assert len({x.casefold() for x in r2}) == len(r2) == 2


PF = r"C:\Program Files"
UNQ = r"C:\Program Files\Foo\u.exe /S"

CASES = [
    # (id, raw, command, machine, fs kwargs, expected)
    ("quoted-missing", r'"C:\gone\a.exe"', True, False, {}, M),
    ("present", r'"C:\here\a.exe"', True, False, {"present": [r"C:\here\a.exe"]}, P),
    ("unc", r"\\server\share\a.exe", True, False, {}, U),
    ("unc-extended", r"\\?\UNC\server\a.exe", True, False, {}, U),
    ("extended-missing", r"\\?\C:\gone\a.exe", False, False, {}, M),
    ("device-path", r"\\.\C:\gone\a.exe", False, False, {}, U),
    ("removable", r"E:\a.exe", False, False, {"drives": {"E:": 2}}, U),
    ("network-drive", r"Z:\a.exe", False, False, {"drives": {"Z:": 4}}, U),
    ("absent-drive", r"Q:\a.exe", False, False, {}, U),
    ("root-unreadable", r"C:\gone\a.exe", False, False, {"bad_roots": ["C:\\"]}, U),
    ("access-denied", r"C:\x\a.exe", False, False, {"errors": {r"C:\x\a.exe": 5}}, U),
    ("sharing-violation", r"C:\x\a.exe", False, False, {"errors": {r"C:\x\a.exe": 32}}, U),
    ("invalid-name", r"C:\x\a.exe", False, False, {"errors": {r"C:\x\a.exe": 123}}, U),
    ("undefined-var", r"%UNDEFINED%\a.exe", False, False, {}, U),
    ("relative", "notepad.exe", True, False, {}, U),
    ("relative-path", r"sub\a.exe", False, False, {}, U),
    ("drive-relative", r"C:a.exe", False, False, {}, U),
    ("system32", r"C:\Windows\System32\gone.exe", False, False, {}, U),
    ("sysnative", r"C:\Windows\Sysnative\x.exe", False, False, {}, U),
    ("syswow64", r"C:\Windows\SysWOW64\x.exe", False, False, {}, U),
    ("dotdot-into-windows", r"C:\a\..\Windows\x.exe", False, False, {}, U),
    ("alias", r"%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe", False, False,
     {"errors": {r"C:\Users\me\AppData\Local\Microsoft\WindowsApps\python.exe": 1920}}, U),
    ("windowsapps", PF + r"\WindowsApps\x\a.exe", False, False, {}, U),
    ("windowsapps-x86", r"C:\Program Files (x86)\WindowsApps\a.exe", False, False, {}, U),
    ("pf-microsoft", PF + r"\Microsoft Office\x.exe", False, False, {}, U),
    ("pf-windows-defender", PF + r"\Windows Defender\x.exe", False, False, {}, U),
    ("pf-ie", PF + r"\Internet Explorer\iexplore.exe", False, False, {}, U),
    ("programdata-microsoft", r"C:\ProgramData\Microsoft\x.exe", False, False, {}, U),
    ("localappdata-microsoft", r"C:\Users\me\AppData\Local\Microsoft\x.exe", False, False, {}, U),
    ("microsoft-present", PF + r"\Microsoft Office\x.exe", False, False,
     {"present": [PF + r"\Microsoft Office\x.exe"]}, P),
    ("short-missing", r"C:\PROGRA~1\Gone\a.exe", False, False, {}, U),
    ("short-present", r"C:\PROGRA~1\Here\a.exe", False, False,
     {"present": [r"C:\PROGRA~1\Here\a.exe"]}, P),
    ("hklm-under-users", r"C:\Users\bob\AppData\Local\x.exe", False, True, {}, U),
    ("hklm-under-users-present", r"C:\Users\bob\x.exe", False, True,
     {"present": [r"C:\Users\bob\x.exe"]}, U),
    ("hklm-users-casefold-slash", "c:/USERS/bob/x.exe", False, True, {}, U),
    ("hkcu-under-users", r"C:\Users\bob\AppData\Local\x.exe", False, False, {}, M),
    ("hklm-not-users-prefix", r"C:\Usersx\a.exe", False, True, {}, M),
    ("unquoted-exe-prefix", UNQ, True, False, {"present": [r"C:\Program.exe"]}, P),
    ("unquoted-all-missing", UNQ, True, False, {}, M),
    ("unquoted-real", UNQ, True, False, {"present": [r"C:\Program Files\Foo\u.exe"]}, P),
    ("unquoted-one-unknown", UNQ, True, False, {"errors": {r"C:\Program": 5}}, U),
    ("msiexec", r"MsiExec.exe /X{0000}", True, False, {}, U),
    ("rundll32", r"rundll32 C:\gone.dll,X", True, False, {}, U),
    ("empty", "", True, False, {}, U),
    ("empty-path", "", False, False, {}, U),
    ("unterminated-quote", r'"C:\a.exe', True, False, {}, U),
    ("junk-after-quote", r'"C:\a b"\c.exe', True, False, {}, U),
    ("ads", r"C:\a.exe:evil", False, False, {}, U),
    ("wildcard", r"C:\a*.exe", False, False, {}, U),
    ("device-name", r"C:\nul", False, False, {}, U),
    ("env-sysroot", r"%SystemRoot%\system32\x.dll", False, False, {}, U),
    ("quoted-noext-exe-present", r'"C:\here\tool"', True, False,
     {"present": [r"C:\here\tool.exe"]}, P),
    ("quoted-noext-missing", r'"C:\here\tool"', True, False, {}, M),
]


@pytest.mark.parametrize(
    "raw,command,machine,fskw,expected",
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_target_state_matrix(raw, command, machine, fskw, expected):
    ctx = make_ctx(FakeFS(**fskw))
    assert target_state(raw, command=command, ctx=ctx, machine=machine) is expected


def test_32bit_process_env_still_guards_microsoft():
    env = {
        "ProgramFiles": r"C:\Program Files (x86)",
        "ProgramFiles(x86)": r"C:\Program Files (x86)",
        "SystemDrive": "C:",
    }
    ctx = make_ctx(FakeFS(), env)
    p = r"C:\Program Files\Microsoft Office\root\x.exe"
    assert target_state(p, command=False, ctx=ctx, machine=False) is U


def test_helper_env_without_public_and_w6432():
    env = {"SystemDrive": "C:", "SystemRoot": r"C:\Windows"}
    ctx = make_ctx(FakeFS(), env)
    assert target_state(
        r"C:\Program Files\WindowsApps\a.exe", command=False, ctx=ctx, machine=True
    ) is U


def test_drive_type_failure_is_unknown():
    def boom(root):
        raise OSError("x")

    prober = WinProber(
        system_root=r"C:\Windows",
        program_files=microsoft_roots(ENV, "C:"),
        program_data=r"C:\ProgramData",
        local_appdata=r"C:\Users\me\AppData\Local",
        drive_type=boom,
        lstat=FakeFS().lstat,
    )
    assert prober.probe(r"C:\gone\a.exe") is U


@pytest.mark.skipif(sys.platform == "win32", reason="off-Windows behaviour")
def test_default_context_unavailable_off_windows():
    with pytest.raises(RegistryUnavailable):
        rt.default_context()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_default_context_builds_on_windows(monkeypatch):
    monkeypatch.delenv("PUBLIC", raising=False)
    ctx = rt.default_context()
    assert ctx.profiles_root.casefold().endswith("users")
    assert ctx.system_root


# -- fix round 1 -------------------------------------------------------------
def _ctx(fs, env=ENV, **kw):
    c = make_ctx(fs, env)
    return DetectorContext(
        env=c.env,
        prober=c.prober,
        profiles_root=kw.get("profiles_root", c.profiles_root),
        system_root=kw.get("system_root", c.system_root),
        owner_matches=kw.get("owner_matches", True),
    )


def _ts(raw, fs=None, *, command=False, machine=False, env=ENV, **kw):
    return target_state(
        raw, command=command, ctx=_ctx(fs or FakeFS(), env, **kw), machine=machine
    )


USER_ENV = dict(
    ENV,
    APPDATA=r"D:\Redirected\AppData\Roaming",
    LOCALAPPDATA=r"D:\Redirected\Local",
    USERNAME="admin",
    USERPROFILE=r"D:\Users\admin",
    TEMP=r"D:\Temp",
)


def test_c1_machine_entries_never_use_per_user_variables():
    assert _ts(r"%APPDATA%\Foo\foo.exe", machine=True, env=USER_ENV) is U
    assert _ts(r"C:\Tools\%USERNAME%\agent.exe", machine=True, env=USER_ENV) is U
    env = dict(USER_ENV, TMP=r"D:\t", HOMEPATH=r"\x", CUSTOM=r"D:\c")
    for var in ("LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP", "HOMEPATH", "CUSTOM"):
        assert _ts(rf"%{var}%\a.exe", machine=True, env=env, command=True) is U


def test_c1_machine_allowlist_still_expands():
    assert _ts(r"%ProgramData%\Foo\a.exe", machine=True) is M
    assert _ts(r"%SystemDrive%\Tools\a.exe", machine=True) is M


def test_c1_owner_mismatch_blocks_per_user_variables_for_hkcu():
    d = FakeFS(drives={"D:": 3})
    assert _ts(r"%APPDATA%\Foo\a.exe", d, env=USER_ENV, owner_matches=False) is U
    assert _ts(r"%APPDATA%\Foo\a.exe", d, env=USER_ENV, owner_matches=True) is M
    assert _ts(r"%ProgramData%\Foo\a.exe", owner_matches=False) is M


def test_i1_wow_variants_32bit_interpreter():
    env = dict(
        ENV,
        ProgramFiles=r"C:\Program Files (x86)",
        CommonProgramFiles=r"C:\Program Files (x86)\Common Files",
        CommonProgramW6432=r"C:\Program Files\Common Files",
    )
    live = FakeFS(present=[r"C:\Program Files\Foo\a.exe"])
    assert _ts(r'"%ProgramFiles%\Foo\a.exe" /bg', live, command=True, env=env) is P
    assert _ts(r'"%ProgramFiles%\Foo\a.exe" /bg', command=True, env=env) is M
    live2 = FakeFS(present=[r"C:\Program Files\Common Files\Foo\a.exe"])
    assert _ts(r"%CommonProgramFiles%\Foo\a.exe", live2, env=env) is P
    # 32-bit without ProgramW6432: derive the native folder from the x86 one.
    env2 = {"ProgramFiles": r"C:\Program Files (x86)", "SystemDrive": "C:"}
    assert _ts(r"%ProgramFiles%\Foo\a.exe", live, env=env2) is P
    # UNKNOWN in one variant keeps the verdict out of MISSING.
    unk = FakeFS(errors={r"C:\Program Files\Foo\a.exe": 5})
    assert _ts(r"%ProgramFiles%\Foo\a.exe", unk, env=env) is U


def test_x86_native_variant_always_tried():
    env = dict(ENV, CommonProgramFiles=r"C:\Program Files (x86)\Common Files")
    del env["ProgramW6432"]
    live = FakeFS(present=[r"C:\Program Files\Common Files\Foo\a.exe"])
    assert _ts(r"%CommonProgramFiles%\Foo\a.exe", live, env=env) is P
    assert _ts(r"%CommonProgramFiles%\Foo\a.exe", env=env) is M
    env2 = {
        "ProgramFiles": r"C:\Program Files (x86)",
        "ProgramFiles(x86)": r"C:\Program Files (x86)",
        "SystemDrive": "C:",
    }
    live2 = FakeFS(present=[r"C:\Program Files\Foo\a.exe"])
    assert _ts(r"%ProgramFiles%\Foo\a.exe", live2, env=env2) is P
    assert _ts(r"%ProgramFiles%\Foo\a.exe", env=env2) is M


def test_x86_variant_kept_in_64bit_env():
    live = FakeFS(present=[r"C:\Program Files (x86)\Foo\a.exe"])
    assert _ts(r"%ProgramFiles%\Foo\a.exe", live) is P
    assert _ts(r"%ProgramFiles%\Foo\a.exe") is M


def test_ancestor_non_notfound_error_is_unknown():
    fs = FakeFS(errors={r"C:\dir": 5})
    assert _ts(r"C:\dir\gone\a.exe", fs, command=True) is U


def test_dotdot_normalised_before_guards():
    assert _ts(r"C:\Apps\..\Windows\x.exe") is U
    assert _ts(r"C:\Apps\..\Windows\x.exe", command=True) is U
    assert _ts(r"D:\a\..\Users\x\y.exe", FakeFS(drives={"D:": 3}), machine=True) is U
    assert _ts(r"D:\a\..\Users\x\y.exe", FakeFS(drives={"D:": 3})) is M


def test_i2_reparse_ancestor_is_unknown():
    fs = FakeFS(present=[r"C:\junc"], reparse=[r"C:\junc"])
    assert _ts(r"C:\junc\gone\a.exe", fs, command=True) is U
    plain = FakeFS(present=[r"C:\dir"])
    assert _ts(r"C:\dir\gone\a.exe", plain, command=True) is M


def test_i2_legacy_junction_names_unknown():
    assert _ts(r"C:\Documents and Settings\bob\a.exe") is U
    assert _ts(r"C:\Users\All Users\Foo\a.exe") is U
    assert _ts(r"C:\Users\Default User\a.exe") is U
    assert _ts(r"C:\Users\All Users\Microsoft\a.exe", machine=True) is U


def test_i3_long_paths_unknown():
    long_path = "C:\\" + "\\".join(["d" * 30] * 9) + "\\a.exe"
    assert len(long_path) >= 240
    assert _ts(long_path) is U
    assert _ts("\\\\?\\" + long_path) is U
    assert _ts("C:\\" + "d" * 200 + "\\a.exe") is M


def test_i4_moved_profiles_and_empty_roots():
    env = dict(USER_ENV)
    d = FakeFS(drives={"D:": 3})
    assert _ts(r"D:\Users\bob\AppData\Local\App\x.exe", d, machine=True,
               command=True, env=env) is U
    assert _ts(r"%USERPROFILE%\App\x.exe", d, machine=True, env=env) is U
    assert _ts(r"C:\Tools\a.exe", machine=True, profiles_root="") is U
    assert _ts(r"C:\Tools\a.exe", machine=True, system_root="") is U
    assert _ts(r"C:\Tools\a.exe", machine=True) is M
    assert _ts(r"D:\Users\bob\x.exe", d, machine=False) is M


def test_i5_pathext():
    only_cmd = FakeFS(present=[r"C:\Tools\backup.cmd"])
    assert _ts(r"C:\Tools\backup", only_cmd, command=True) is P
    assert _ts(r'"C:\Tools\backup" /x', only_cmd, command=True) is P
    assert _ts(r"C:\Tools\backup", command=True) is M
    bat = FakeFS(present=[r"C:\Tools\x.dat.bat"])
    assert _ts(r"C:\Tools\x.dat", bat, command=True) is P


def test_minor_strip_icon_index_inside_quotes():
    assert strip_icon_index(r'"C:\App\app.exe,0"') == r'"C:\App\app.exe"'
    assert strip_icon_index(r'"C:\App\app.exe",-3') == r'"C:\App\app.exe"'
    assert strip_icon_index(r"C:\App\app.exe, 2") == r"C:\App\app.exe"


def test_minor_placeholders_are_not_variables():
    assert expand_env(r'"C:\a.exe" "%1" %*', ENV) == r'"C:\a.exe" "%1" %*'
    assert expand_env(r"C:\a.exe %~dp0 %L %V %W", ENV) == r"C:\a.exe %~dp0 %L %V %W"
    for cmd in (
        r'"C:\gone\app.exe" "%1" %*',
        r'"C:\gone\app.exe" "%L" %*',
        r'"C:\gone\app.exe" %~dp0 %1',
        r'"C:\gone\app.exe" "%V" "%W" %D',
    ):
        assert _ts(cmd, command=True) is M, cmd
        assert _ts(cmd, command=True, machine=True) is M, cmd
    live = FakeFS(present=[r"C:\here\app.exe"])
    assert _ts(r'"C:\here\app.exe" "%1"', live, command=True) is P
    for cmd in (r"%1 /x", r"%1\app.exe", r'"%1" /x', r"C:\%1\app.exe", r"%~dp0\app.exe"):
        assert _ts(cmd, command=True) is U, cmd


def test_minor_profiles_root_fallback_is_testable_anywhere():
    assert rt._profiles_root({"SystemDrive": "C:"}, "C:") == r"C:\Users"
    assert rt._profiles_root({"PUBLIC": r"D:\Users\Public"}, "C:") == r"D:\Users"
    assert rt._profiles_root({"public": "garbage"}, "C:") == r"C:\Users"
