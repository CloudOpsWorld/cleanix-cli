import sys

import pytest

from cleanix.core import context, utils, winenv
from cleanix.core.context import TargetUser, use_user


def test_local_appdata_for_other_user_ignores_env(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "elsewhere"))
    home = tmp_path / "x"
    with use_user(TargetUser("x", home, 0, 0, False)):
        assert winenv.local_appdata() == home / "AppData" / "Local"
        monkeypatch.setenv("APPDATA", str(tmp_path / "elsewhere"))
        assert winenv.roaming_appdata() == home / "AppData" / "Roaming"


def test_local_appdata_honors_env_for_invoker(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "L"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "R"))
    inv = context.invoking_user()
    with use_user(TargetUser(inv.name, inv.home, inv.uid, inv.gid, True)):
        assert winenv.local_appdata() == tmp_path / "L"
        assert winenv.roaming_appdata() == tmp_path / "R"
        assert winenv.user_temp() == tmp_path / "L" / "Temp"


def test_system_paths_from_env(monkeypatch):
    monkeypatch.setenv("ProgramData", r"D:\PD")
    monkeypatch.setenv("SystemRoot", r"D:\Win")
    monkeypatch.setenv("SystemDrive", "D:")
    assert str(winenv.programdata()) == r"D:\PD"
    assert str(winenv.system_root()) == r"D:\Win"
    assert winenv.system_drive() == "D:"


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows behaviour")
def test_helpers_are_safe_off_windows():
    assert winenv.is_admin() is False
    assert winenv.recycle_bin_size() == 0
    assert winenv.relaunch_elevated(["x"]) is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_is_admin_returns_bool_on_windows():
    assert isinstance(winenv.is_admin(), bool)
    assert utils.is_root() is winenv.is_admin()
    assert context.is_effective_root() is winenv.is_admin()


def test_fake_win_fixture_redirects_home(fake_win):
    assert utils.home() == fake_win.home
    assert fake_win.local.is_dir() and fake_win.roaming.is_dir()
    assert winenv.local_appdata() == fake_win.local
    assert winenv.user_temp() == fake_win.local / "Temp"
