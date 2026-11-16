import ctypes
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from cleanix.core import elevate_launch as el
from cleanix.core import platform as plat
from cleanix.core import winenv


def _winerr(code):
    e = OSError("winerror")
    e.winerror = code
    return e


def _os(monkeypatch, name):
    monkeypatch.setattr(el, "current_os", lambda: name)


def test_elevated_command_shape(monkeypatch):
    _os(monkeypatch, plat.WINDOWS)
    cmd = el.elevated_command(Path("req.json"), Path("res.json"), "cfg.yml")
    assert cmd == [sys.executable, "-m", "cleanix.elevated", "--request", "req.json",
                   "--result", "res.json", "--config", "cfg.yml"]
    assert "--config" not in el.elevated_command(Path("a"), Path("b"))


def test_elevated_command_includes_uid_only_on_posix(monkeypatch):
    monkeypatch.setattr(el, "_invoker_uid", lambda: 1234)
    _os(monkeypatch, plat.LINUX)
    cmd = el.elevated_command(Path("a"), Path("b"))
    assert cmd[-2:] == ["--uid", "1234"]
    _os(monkeypatch, plat.WINDOWS)
    assert "--uid" not in el.elevated_command(Path("a"), Path("b"))


def _fake_run(calls, rc=0, stderr="", exc=None):
    def run(argv, **kw):
        calls.append((argv, kw))
        if exc:
            raise exc
        return SimpleNamespace(returncode=rc, stdout="", stderr=stderr)
    return run


def test_linux_uses_pkexec_and_maps_declined(monkeypatch):
    _os(monkeypatch, plat.LINUX)
    monkeypatch.setattr(el.utils, "safe_which", lambda c: "/usr/bin/pkexec")
    calls = []
    monkeypatch.setattr(subprocess, "run", _fake_run(calls, rc=0))
    assert el.launch_elevated(["/py", "-m", "x"]) == 0
    assert calls[0][0] == ["/usr/bin/pkexec", "/py", "-m", "x"]
    monkeypatch.setattr(subprocess, "run", _fake_run([], rc=126))
    with pytest.raises(el.ElevationDeclined):
        el.launch_elevated(["/py"])
    monkeypatch.setattr(subprocess, "run", _fake_run([], rc=127))
    with pytest.raises(el.ElevationDeclined):
        el.launch_elevated(["/py"])
    monkeypatch.setattr(subprocess, "run", _fake_run([], rc=3))
    with pytest.raises(el.ElevationFailed):
        el.launch_elevated(["/py"])


def test_linux_without_pkexec_is_unavailable(monkeypatch):
    _os(monkeypatch, plat.LINUX)
    monkeypatch.setattr(el.utils, "safe_which", lambda c: None)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("ran"))
    with pytest.raises(el.ElevationUnavailable):
        el.launch_elevated(["/py"])


def test_planted_pkexec_in_cwd_is_not_used(monkeypatch, tmp_path):
    _os(monkeypatch, plat.LINUX)
    (tmp_path / "pkexec").write_text("evil")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(el.utils, "safe_which", lambda c: "/usr/bin/pkexec")
    calls = []
    monkeypatch.setattr(subprocess, "run", _fake_run(calls))
    el.launch_elevated(["/py"])
    assert calls[0][0][0] == "/usr/bin/pkexec"
    # and the real resolver with only the cwd on PATH finds nothing
    monkeypatch.undo()
    assert el.utils.safe_which("pkexec", path_entries=[str(tmp_path), "."],
                               cwd=str(tmp_path)) is None


def test_macos_builds_osascript_with_quoting(monkeypatch):
    import shlex
    _os(monkeypatch, plat.MACOS)
    calls = []
    monkeypatch.setattr(subprocess, "run", _fake_run(calls))
    nasty = "a b" + chr(34) + "c" + chr(92) + "d"
    el.launch_elevated(["/py", "--request", nasty])
    argv = calls[0][0]
    assert argv[0] == "/usr/bin/osascript" and argv[1] == "-e" and len(argv) == 3
    script = argv[2]
    prefix, suffix = 'do shell script "', '" with administrator privileges'
    assert script.startswith(prefix) and script.endswith(suffix)
    body = script[len(prefix):-len(suffix)]
    # walk the literal: every double quote must be backslash-escaped
    i, out = 0, []
    while i < len(body):
        if body[i] == chr(92):
            assert body[i + 1] in (chr(92), chr(34))
            out.append(body[i + 1])
            i += 2
            continue
        assert body[i] != chr(34), "unescaped quote breaks the AppleScript string"
        out.append(body[i])
        i += 1
    assert shlex.split("".join(out)) == ["/py", "--request", nasty]


def test_macos_cancel_maps_to_declined(monkeypatch):
    _os(monkeypatch, plat.MACOS)
    monkeypatch.setattr(subprocess, "run", _fake_run([], rc=1, stderr="execution error: User canceled. (-128)"))
    with pytest.raises(el.ElevationDeclined):
        el.launch_elevated(["/py"])
    monkeypatch.setattr(subprocess, "run", _fake_run([], rc=1, stderr="boom"))
    with pytest.raises(el.ElevationFailed):
        el.launch_elevated(["/py"])


def test_windows_maps_1223_to_declined(monkeypatch):
    _os(monkeypatch, plat.WINDOWS)
    def boom(argv, timeout):
        raise _winerr(1223)
    monkeypatch.setattr(winenv, "run_elevated", boom)
    with pytest.raises(el.ElevationDeclined):
        el.launch_elevated(["py"])
    def other(argv, timeout):
        raise _winerr(5)
    monkeypatch.setattr(winenv, "run_elevated", other)
    with pytest.raises(el.ElevationFailed):
        el.launch_elevated(["py"])


def test_windows_success_returns_exit_code(monkeypatch):
    _os(monkeypatch, plat.WINDOWS)
    seen = {}
    def ok(argv, timeout):
        seen["a"] = (list(argv), timeout)
        return 7
    monkeypatch.setattr(winenv, "run_elevated", ok)
    assert el.launch_elevated(["py", "-m", "x"], timeout=9) == 7
    assert seen["a"] == (["py", "-m", "x"], 9)


@pytest.mark.parametrize("os_name", [plat.LINUX, plat.MACOS, plat.WINDOWS])
def test_timeout_maps_to_failed(monkeypatch, os_name):
    _os(monkeypatch, os_name)
    monkeypatch.setattr(el.utils, "safe_which", lambda c: "/usr/bin/pkexec")
    monkeypatch.setattr(subprocess, "run", _fake_run([], exc=subprocess.TimeoutExpired("x", 1)))
    def tmo(argv, timeout):
        raise TimeoutError("t")
    monkeypatch.setattr(winenv, "run_elevated", tmo)
    with pytest.raises(el.ElevationFailed):
        el.launch_elevated(["/py"], timeout=1)


def test_unsupported_os_is_unavailable(monkeypatch):
    _os(monkeypatch, "freebsd")
    with pytest.raises(el.ElevationUnavailable):
        el.launch_elevated(["/py"])


def test_run_elevated_off_windows_raises(monkeypatch):
    monkeypatch.setattr(winenv, "_is_win", lambda: False)
    with pytest.raises(OSError):
        winenv.run_elevated(["x"], 1)


def test_shellexecuteinfo_layout():
    cls = winenv._shellexecuteinfo_class()
    expected = 112 if ctypes.sizeof(ctypes.c_void_p) == 8 else 60
    assert ctypes.sizeof(cls) == expected
    assert cls.hProcess.offset == (104 if expected == 112 else 56)
