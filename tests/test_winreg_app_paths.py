"""win_reg_app_paths: App Paths entries whose executable is provably gone."""

from __future__ import annotations

import dataclasses

import pytest

from _fakeprobe import ENV, FakeFS, make_ctx
from _fakereg import FakeProber
from cleanix.cleaners.winreg_app_paths import WinRegAppPaths
from cleanix.config import Config
from cleanix.core.regtargets import DetectorContext, Existence
from cleanix.core.winregistry import (
    RegistryError,
    REG_BINARY,
    REG_DWORD,
    REG_EXPAND_SZ,
    REG_MULTI_SZ,
    REG_SZ,
)

CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
AP = CV + r"\App Paths"
APW = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths"


def _scan(monkeypatch, ctx):
    monkeypatch.setattr(WinRegAppPaths, "context", lambda self: ctx)
    report = WinRegAppPaths(Config()).scan()
    assert report.skipped_reason is None, report.skipped_reason
    return list(report.items)


def _fs_ctx(present=(), **kw):
    return make_ctx(FakeFS(present=present, **kw))


def _names(items):
    return [i.reg.key.rsplit("\\", 1)[1] for i in items]


def test_dead_app_path_listed(fake_registry, monkeypatch):
    fake_registry.add_key("HKCU", AP + r"\foo.exe", {"": (REG_SZ, r"C:\Gone\foo.exe")})
    items = _scan(monkeypatch, _fs_ctx())
    assert _names(items) == ["foo.exe"]
    it = items[0]
    assert it.description == "App Paths: foo.exe"
    assert it.requires_root is False
    assert r"C:\Gone\foo.exe" in it.hint and "missing" in it.hint


def test_hklm_and_wow_require_root(fake_registry, monkeypatch):
    fake_registry.add_key("HKLM", AP + r"\a.exe", {"": (REG_SZ, r'"C:\Gone\a.exe"')})
    fake_registry.add_key(
        "HKLM", APW + r"\b.EXE", {"": (REG_EXPAND_SZ, r"%ProgramFiles%\Gone\b.exe")}
    )
    items = _scan(monkeypatch, _fs_ctx())
    assert sorted(_names(items)) == ["a.exe", "b.EXE"]
    assert all(i.requires_root for i in items)


def test_unicode_name_and_mismatched_exe_name(fake_registry, monkeypatch):
    fake_registry.add_key(
        "HKCU", AP + "\\программа.exe", {"": (REG_SZ, r"C:\Gone\other.exe")}
    )
    assert _names(_scan(monkeypatch, _fs_ctx())) == ["программа.exe"]


def test_path_value_is_ignored(fake_registry, monkeypatch):
    fake_registry.add_key(
        "HKCU",
        AP + r"\foo.exe",
        {"": (REG_SZ, r"C:\Gone\foo.exe"), "Path": (REG_SZ, r"C:\Nope;D:\Nowhere")},
    )
    assert _names(_scan(monkeypatch, _fs_ctx())) == ["foo.exe"]


def test_x86_view_present_keeps(fake_registry, monkeypatch):
    fake_registry.add_key(
        "HKLM", AP + r"\a.exe", {"": (REG_EXPAND_SZ, r"%ProgramFiles%\App\a.exe")}
    )
    ctx = _fs_ctx(present=[r"C:\Program Files (x86)\App\a.exe"])
    assert _scan(monkeypatch, ctx) == []


def _keep(fake_registry, monkeypatch, values, name="foo.exe", ctx=None, hive="HKCU"):
    fake_registry.add_key(hive, AP + "\\" + name, values)
    assert _scan(monkeypatch, ctx or _fs_ctx()) == []


def test_kept_target_present(fake_registry, monkeypatch):
    _keep(
        fake_registry,
        monkeypatch,
        {"": (REG_SZ, r"C:\Here\foo.exe")},
        ctx=_fs_ctx(present=[r"C:\Here\foo.exe"]),
    )


def test_kept_windows_nt_wordpad(fake_registry, monkeypatch):
    _keep(
        fake_registry,
        monkeypatch,
        {"": (REG_SZ, r"C:\Program Files\Windows NT\Accessories\wordpad.exe")},
        name="wordpad.exe",
        hive="HKLM",
    )


def test_kept_msedge_x86_microsoft(fake_registry, monkeypatch):
    _keep(
        fake_registry,
        monkeypatch,
        {"": (REG_SZ, r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")},
        name="msedge.exe",
        hive="HKLM",
    )


def test_kept_no_default_value(fake_registry, monkeypatch):
    _keep(fake_registry, monkeypatch, {"Path": (REG_SZ, r"C:\Gone")})


def test_kept_empty_default(fake_registry, monkeypatch):
    _keep(fake_registry, monkeypatch, {"": (REG_SZ, "")})


def test_kept_non_exe_name(fake_registry, monkeypatch):
    fake_registry.add_key("HKCU", AP + r"\foo.dll", {"": (REG_SZ, r"C:\Gone\foo.dll")})
    fake_registry.add_key("HKCU", AP + r"\bar", {"": (REG_SZ, r"C:\Gone\bar.exe")})
    assert _scan(monkeypatch, _fs_ctx()) == []


@pytest.mark.parametrize(
    "value",
    [
        (REG_SZ, "foo.exe"),
        (REG_SZ, r"..\foo.exe"),
        (REG_SZ, r"\\server\share\foo.exe"),
        (REG_SZ, r"%UNDEFINED%\foo.exe"),
        (REG_SZ, r"D:\Gone\foo.exe"),  # unknown drive
        (REG_SZ, r"C:\Windows\System32\foo.exe"),
        (REG_SZ, r"C:\Windows\System32\cmd.exe"),
        (REG_SZ, "msiexec.exe"),
        (REG_BINARY, b"C\x00:\x00"),
        (REG_DWORD, 5),
        (REG_MULTI_SZ, (r"C:\Gone\foo.exe",)),
    ],
)
def test_kept_unknown_targets(fake_registry, monkeypatch, value):
    fake_registry.add_key("HKCU", AP + r"\foo.exe", {"": value})
    assert _scan(monkeypatch, _fs_ctx()) == []


def test_kept_app_execution_alias(fake_registry, monkeypatch):
    p = r"C:\Users\me\AppData\Local\Microsoft\WindowsApps\python.exe"
    fake_registry.add_key("HKCU", AP + r"\python.exe", {"": (REG_SZ, p)})
    assert _scan(monkeypatch, _fs_ctx()) == []


def test_kept_removable_drive(fake_registry, monkeypatch):
    fake_registry.add_key("HKCU", AP + r"\foo.exe", {"": (REG_SZ, r"E:\Tools\foo.exe")})
    assert _scan(monkeypatch, _fs_ctx(drives={"E:": 2})) == []


def test_kept_hklm_per_user_var_and_users_dir(fake_registry, monkeypatch):
    fake_registry.add_key(
        "HKLM", AP + r"\a.exe", {"": (REG_EXPAND_SZ, r"%LOCALAPPDATA%\x\a.exe")}
    )
    fake_registry.add_key("HKLM", AP + r"\b.exe", {"": (REG_SZ, r"C:\Users\bob\x\b.exe")})
    assert _scan(monkeypatch, _fs_ctx()) == []


def test_kept_entry_with_subkeys(fake_registry, monkeypatch):
    fake_registry.add_key("HKCU", AP + r"\foo.exe", {"": (REG_SZ, r"C:\Gone\foo.exe")})
    fake_registry.add_key("HKCU", AP + r"\foo.exe\sub")
    assert _scan(monkeypatch, _fs_ctx()) == []


def test_kept_delegate_execute(fake_registry, monkeypatch):
    _keep(
        fake_registry,
        monkeypatch,
        {"": (REG_SZ, r"C:\Gone\foo.exe"), "DelegateExecute": (REG_SZ, "{guid}")},
    )


def test_unreadable_entry_skipped(fake_registry, monkeypatch):
    fake_registry.add_key(
        "HKCU", AP + r"\foo.exe", {"": (REG_SZ, r"C:\Gone\foo.exe")}, deny_read=True
    )
    fake_registry.add_key("HKCU", AP + r"\ok.exe", {"": (REG_SZ, r"C:\Gone\ok.exe")})
    assert _names(_scan(monkeypatch, _fs_ctx())) == ["ok.exe"]


def test_unbackupable_entry_skipped(fake_registry, monkeypatch):
    fake_registry.add_key(
        "HKCU",
        AP + r"\foo.exe",
        {"": (REG_SZ, r"C:\Gone\foo.exe"), "bad\nname": (REG_SZ, "x")},
    )
    assert _scan(monkeypatch, _fs_ctx()) == []


def test_evidence_lists_expanded_checked_targets(fake_registry, monkeypatch):
    fake_registry.add_key(
        "HKLM", AP + r"\x.exe", {"": (REG_EXPAND_SZ, r"%ProgramFiles%\Gone\x.exe")}
    )
    (it,) = _scan(monkeypatch, _fs_ctx())
    assert it.hint.startswith("(Default) ")
    assert r"C:\Program Files\Gone\x.exe: missing" in it.hint


def _prober_ctx(present=()):
    """Every path is MISSING except ``present``: only command parsing can
    keep an entry in these tests."""
    return DetectorContext(
        env=ENV,
        prober=FakeProber({p: Existence.PRESENT for p in present}, default=Existence.MISSING),
        profiles_root=r"C:\Users",
        system_root=r"C:\Windows",
    )


def test_command_semantics_whole_string_present_kept(fake_registry, monkeypatch):
    path = r"C:\Program Files\App\a.exe"
    fake_registry.add_key("HKCU", AP + r"\a.exe", {"": (REG_SZ, path)})
    assert _scan(monkeypatch, _prober_ctx([path])) == []
    # sanity: the same entry is listed when the file is missing
    assert len(_scan(monkeypatch, _prober_ctx())) == 1


def test_command_semantics_quoted_path_with_trailing_text(fake_registry, monkeypatch):
    fake_registry.add_key(
        "HKCU", AP + r"\a.exe", {"": (REG_SZ, r'"C:\Gone\a.exe" --flag value')}
    )
    assert _scan(monkeypatch, _prober_ctx([r"C:\Gone\a.exe"])) == []
    assert len(_scan(monkeypatch, _prober_ctx())) == 1


def test_command_semantics_host_executable_is_unknown(fake_registry, monkeypatch):
    fake_registry.add_key("HKCU", AP + r"\cmd.exe", {"": (REG_SZ, r"C:\Tools\cmd.exe")})
    assert _scan(monkeypatch, _prober_ctx()) == []


def test_unreadable_container_yields_nothing(fake_registry, monkeypatch):
    fake_registry.add_key("HKCU", AP + r"\foo.exe", {"": (REG_SZ, r"C:\Gone\foo.exe")})
    fake_registry.fail_next("subkeys", RegistryError("boom"))
    # the first container read (HKCU) fails: nothing from it, no crash
    assert _scan(monkeypatch, _fs_ctx()) == []


def test_kept_whitespace_only_default(fake_registry, monkeypatch):
    _keep(fake_registry, monkeypatch, {"": (REG_SZ, "   ")})


def test_owner_mismatch_makes_per_user_vars_unknown(fake_registry, monkeypatch):
    fake_registry.add_key(
        "HKCU", AP + r"\foo.exe", {"": (REG_EXPAND_SZ, r"%LOCALAPPDATA%\Gone\foo.exe")}
    )
    ctx = _fs_ctx()
    assert len(_scan(monkeypatch, ctx)) == 1
    other = dataclasses.replace(ctx, owner_matches=False)
    assert _scan(monkeypatch, other) == []


def test_owner_wiring_not_the_hive_owner(fake_registry, monkeypatch):
    import cleanix.cleaners.winreg_app_paths as mod

    fake_registry.add_key(
        "HKCU", AP + r"\foo.exe", {"": (REG_EXPAND_SZ, r"%LOCALAPPDATA%\Gone\foo.exe")}
    )
    monkeypatch.setattr(mod, "_scan_is_for_hive_owner", lambda: True)
    assert len(_scan(monkeypatch, _fs_ctx())) == 1
    monkeypatch.setattr(mod, "_scan_is_for_hive_owner", lambda: False)
    assert _scan(monkeypatch, _fs_ctx()) == []


def test_win_reg_app_paths_never_touches_unlisted_containers(fake_registry, monkeypatch):
    fake_registry.add_key("HKCU", AP + r"\foo.exe", {"": (REG_SZ, r"C:\Gone\foo.exe")})
    fake_registry.add_key("HKLM", AP + r"\bar.exe", {"": (REG_SZ, r"C:\Gone\bar.exe")})
    fake_registry.add_key("HKCU", CV + r"\Uninstall\x", {"": (REG_SZ, "y")})
    fake_registry.add_key("HKCU", CV + r"\Run", {"a": (REG_SZ, "b")})
    _scan(monkeypatch, _fs_ctx())
    allowed = (AP.casefold(), APW.casefold())
    writes = {"create_key", "set_value", "delete_key", "delete_value"}
    seen_reads = 0
    for call in fake_registry.calls:
        assert call[0] not in writes
        if call[0] in ("subkeys", "values", "key_exists"):
            seen_reads += 1
            assert call[2].casefold().startswith(allowed), call
    assert seen_reads
