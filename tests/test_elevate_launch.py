import ctypes
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from cleanix.core import elevate_launch as el
from cleanix.core import platform as plat
from cleanix.core import winenv


PYX = sys.executable


def _winerr(code):
    e = OSError("winerror")
    e.winerror = code
    return e


def _os(monkeypatch, name):
    monkeypatch.setattr(el, "current_os", lambda: name)


def test_elevated_command_shape(monkeypatch):
    _os(monkeypatch, plat.WINDOWS)
    cmd = el.elevated_command(Path("req.json"), Path("res.json"), "cfg.yml")
    assert cmd == [sys.executable, "-I", "-m", "cleanix.elevated", "--request", "req.json",
                   "--result", "res.json", "--config", "cfg.yml"]
    assert "--config" not in el.elevated_command(Path("a"), Path("b"))


def test_elevated_command_includes_uid_only_on_posix(monkeypatch):
    monkeypatch.setattr(el, "_invoker_uid", lambda: 1234)
    _os(monkeypatch, plat.LINUX)
    cmd = el.elevated_command(Path("a"), Path("b"))
    assert cmd[-2:] == ["--uid", "1234"]
    _os(monkeypatch, plat.WINDOWS)
    assert "--uid" not in el.elevated_command(Path("a"), Path("b"))


class FakeProc:
    def __init__(self, rc=0, stderr="", exc=None, kill_exc=None):
        self.returncode, self._err, self._exc, self._kill_exc = rc, stderr, exc, kill_exc
        self.stdout = self.stderr = None
        self.killed = False
        self.wait_calls = []

    def communicate(self, timeout=None):
        if self._exc:
            raise self._exc
        return "", self._err

    def kill(self):
        self.killed = True
        if self._kill_exc:
            raise self._kill_exc

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        if timeout is None:
            raise AssertionError("blocking wait() would hang on a root helper")
        raise subprocess.TimeoutExpired("x", timeout)


def _fake_run(calls, rc=0, stderr="", exc=None, kill_exc=None):
    def popen(argv, **kw):
        calls.append((argv, kw))
        return FakeProc(rc, stderr, exc, kill_exc)
    return popen


def test_linux_uses_pkexec_and_maps_declined(monkeypatch):
    _os(monkeypatch, plat.LINUX)
    monkeypatch.setattr(el.utils, "safe_which", lambda c: "/usr/bin/pkexec")
    calls = []
    monkeypatch.setattr(subprocess, "Popen", _fake_run(calls, rc=0))
    assert el.launch_elevated([PYX, "-m", "x"]) == 0
    assert calls[0][0] == ["/usr/bin/pkexec", PYX, "-m", "x"]
    monkeypatch.setattr(subprocess, "Popen", _fake_run([], rc=126))
    with pytest.raises(el.ElevationDeclined):
        el.launch_elevated([PYX])
    monkeypatch.setattr(subprocess, "Popen", _fake_run([], rc=3))
    with pytest.raises(el.ElevationFailed):
        el.launch_elevated([PYX])


def test_linux_without_pkexec_is_unavailable(monkeypatch):
    _os(monkeypatch, plat.LINUX)
    monkeypatch.setattr(el.utils, "safe_which", lambda c: None)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("ran"))
    with pytest.raises(el.ElevationUnavailable):
        el.launch_elevated([PYX])


def test_planted_pkexec_in_cwd_is_not_used(monkeypatch, tmp_path):
    _os(monkeypatch, plat.LINUX)
    (tmp_path / "pkexec").write_text("evil")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(el.utils, "safe_which", lambda c: "/usr/bin/pkexec")
    calls = []
    monkeypatch.setattr(subprocess, "Popen", _fake_run(calls))
    el.launch_elevated([PYX])
    assert calls[0][0][0] == "/usr/bin/pkexec"
    # and the real resolver with only the cwd on PATH finds nothing
    monkeypatch.undo()
    assert el.utils.safe_which("pkexec", path_entries=[str(tmp_path), "."],
                               cwd=str(tmp_path)) is None


def test_macos_builds_osascript_with_quoting(monkeypatch):
    import shlex
    _os(monkeypatch, plat.MACOS)
    calls = []
    monkeypatch.setattr(subprocess, "Popen", _fake_run(calls))
    nasty = "a b" + chr(34) + "c" + chr(92) + "d"
    el.launch_elevated([PYX, "--request", nasty])
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
    assert shlex.split("".join(out)) == [PYX, "--request", nasty]


def test_macos_cancel_maps_to_declined(monkeypatch):
    _os(monkeypatch, plat.MACOS)
    monkeypatch.setattr(subprocess, "Popen", _fake_run([], rc=1, stderr="execution error: User canceled. (-128)"))
    with pytest.raises(el.ElevationDeclined):
        el.launch_elevated([PYX])
    monkeypatch.setattr(subprocess, "Popen", _fake_run([], rc=1, stderr="boom"))
    with pytest.raises(el.ElevationFailed):
        el.launch_elevated([PYX])


def test_windows_maps_1223_to_declined(monkeypatch):
    _os(monkeypatch, plat.WINDOWS)
    def boom(argv, timeout):
        raise _winerr(1223)
    monkeypatch.setattr(winenv, "run_elevated", boom)
    with pytest.raises(el.ElevationDeclined):
        el.launch_elevated([PYX])
    def other(argv, timeout):
        raise _winerr(5)
    monkeypatch.setattr(winenv, "run_elevated", other)
    with pytest.raises(el.ElevationFailed):
        el.launch_elevated([PYX])


def test_windows_success_returns_exit_code(monkeypatch):
    _os(monkeypatch, plat.WINDOWS)
    seen = {}

    def ok(argv, timeout):
        seen["a"] = (list(argv), timeout)
        return 0
    monkeypatch.setattr(winenv, "run_elevated", ok)
    assert el.launch_elevated([PYX, "-m", "x"], timeout=9) == 0
    assert seen["a"] == ([PYX, "-m", "x"], 9)
    monkeypatch.setattr(winenv, "run_elevated", lambda a, t: 7)
    with pytest.raises(el.ElevationFailed) as ei:
        el.launch_elevated([PYX])
    assert ei.value.exit_code == 7


@pytest.mark.parametrize("os_name", [plat.LINUX, plat.MACOS, plat.WINDOWS])
def test_timeout_maps_to_failed(monkeypatch, os_name):
    _os(monkeypatch, os_name)
    monkeypatch.setattr(el.utils, "safe_which", lambda c: "/usr/bin/pkexec")
    monkeypatch.setattr(subprocess, "Popen", _fake_run([], exc=subprocess.TimeoutExpired("x", 1)))
    def tmo(argv, timeout):
        raise TimeoutError("t")
    monkeypatch.setattr(winenv, "run_elevated", tmo)
    with pytest.raises(el.ElevationFailed):
        el.launch_elevated([PYX], timeout=1)


def test_unsupported_os_is_unavailable(monkeypatch):
    _os(monkeypatch, "freebsd")
    with pytest.raises(el.ElevationUnavailable):
        el.launch_elevated([PYX])


def test_run_elevated_off_windows_raises(monkeypatch):
    monkeypatch.setattr(winenv, "_is_win", lambda: False)
    with pytest.raises(OSError):
        winenv.run_elevated(["x"], 1)


@pytest.mark.skipif(sys.platform != "win32",
                    reason="SHELLEXECUTEINFOW layout is a Windows ABI")
def test_shellexecuteinfo_layout():
    cls = winenv._shellexecuteinfo_class()
    expected = 112 if ctypes.sizeof(ctypes.c_void_p) == 8 else 60
    assert ctypes.sizeof(cls) == expected
    assert cls.hProcess.offset == (104 if expected == 112 else 56)


@pytest.mark.parametrize("os_name", [plat.LINUX, plat.MACOS])
def test_posix_timeout_never_blocks_on_unkillable_root_helper(monkeypatch, os_name):
    _os(monkeypatch, os_name)
    monkeypatch.setattr(el.utils, "safe_which", lambda c: "/usr/bin/pkexec")
    procs = []

    def popen(argv, **kw):
        p = FakeProc(exc=subprocess.TimeoutExpired("x", 1), kill_exc=PermissionError("root"))
        procs.append(p)
        return p
    monkeypatch.setattr(subprocess, "Popen", popen)
    with pytest.raises(el.ElevationFailed, match="timed out and may still be running"):
        el.launch_elevated([PYX], timeout=1)
    assert procs[0].killed and None not in procs[0].wait_calls


@pytest.mark.parametrize("bad", [[], ["relative/py"], ["py"]])
def test_requires_absolute_program(bad):
    with pytest.raises(ValueError):
        el.launch_elevated(bad)


def test_linux_127_agent_missing_is_unavailable_else_failed(monkeypatch):
    _os(monkeypatch, plat.LINUX)
    monkeypatch.setattr(el.utils, "safe_which", lambda c: "/usr/bin/pkexec")
    monkeypatch.setattr(subprocess, "Popen", _fake_run([], rc=127, stderr="Error: No authentication agent found."))
    with pytest.raises(el.ElevationUnavailable):
        el.launch_elevated([PYX])
    monkeypatch.setattr(subprocess, "Popen", _fake_run([], rc=127, stderr="helper crashed"))
    with pytest.raises(el.ElevationFailed):
        el.launch_elevated([PYX])


def test_macos_cancel_text_in_middle_is_not_declined(monkeypatch):
    _os(monkeypatch, plat.MACOS)
    monkeypatch.setattr(subprocess, "Popen", _fake_run([], rc=1, stderr="helper said (-128) then died\n"))
    with pytest.raises(el.ElevationFailed):
        el.launch_elevated([PYX])
    monkeypatch.setattr(subprocess, "Popen", _fake_run([], rc=1, stderr="x (-128)\n"))
    with pytest.raises(el.ElevationDeclined):
        el.launch_elevated([PYX])
