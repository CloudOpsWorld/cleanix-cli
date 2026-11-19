"""Target evidence: env expansion, command parsing, tri-state existence."""

from __future__ import annotations

import sys

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

ENV = {
    "ProgramFiles": r"C:\Program Files",
    "ProgramW6432": r"C:\Program Files",
    "ProgramFiles(x86)": r"C:\Program Files (x86)",
    "ProgramData": r"C:\ProgramData",
    "LOCALAPPDATA": r"C:\Users\me\AppData\Local",
    "SystemRoot": r"C:\Windows",
    "SystemDrive": "C:",
}


class WinErr(OSError):
    def __init__(self, code: int) -> None:
        super().__init__(f"winerror {code}")
        self._code = code

    @property
    def winerror(self):  # type: ignore[override]
        return self._code


class FakeFS:
    """Casefolded present set; everything else raises winerror 3 unless listed."""

    def __init__(self, present=(), errors=None, drives=None, bad_roots=()):
        self.present = {p.casefold() for p in present}
        self.errors = {k.casefold(): v for k, v in (errors or {}).items()}
        self.drives = {"C:": 3}
        self.drives.update(drives or {})
        self.bad_roots = {r.casefold() for r in bad_roots}
        self.roots = {"c:\\"}

    def drive_type(self, root: str) -> int:
        return self.drives.get(root[:2].upper(), 1)  # 1 = no root dir

    def lstat(self, path: str):
        key = path.casefold()
        if key in self.bad_roots:
            raise WinErr(5)
        if key in self.errors:
            raise WinErr(self.errors[key])
        if key in self.present or key in self.roots:
            return object()
        raise WinErr(3)


def make_ctx(fs: FakeFS, env=ENV) -> DetectorContext:
    prober = WinProber(
        system_root=r"C:\Windows",
        program_files=microsoft_roots(env, "C:"),
        program_data=r"C:\ProgramData",
        local_appdata=r"C:\Users\me\AppData\Local",
        drive_type=fs.drive_type,
        lstat=fs.lstat,
    )
    return DetectorContext(
        env=env, prober=prober, profiles_root=r"C:\Users", system_root=r"C:\Windows"
    )


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
