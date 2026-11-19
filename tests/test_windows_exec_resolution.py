"""C1: bare command names must never resolve from the current directory.

Planted "executables" are tiny text files; they are never executed (every
subprocess call is replaced by a recorder).
"""

from __future__ import annotations

import ntpath
import subprocess
import sys
from types import SimpleNamespace

import pytest

from cleanix.core import utils

win_only = pytest.mark.skipif(sys.platform != "win32", reason="exercises Windows CreateProcess cwd/PATH lookup and System32 tools")


def _plant(d, name):
    p = d / name
    p.write_text("not a real program; must never be resolved or run\n")
    return p


@pytest.fixture
def planted_cwd(tmp_path, monkeypatch):
    cwd = tmp_path / "untrusted"
    cwd.mkdir()
    for n in ("Dism.exe", "docker.exe", "cleanix.exe", "powershell.exe", "schtasks.exe"):
        _plant(cwd, n)
    empty = tmp_path / "emptybin"
    empty.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("PATH", str(empty))
    # Some shells set this to opt out of cwd search; real users usually don't.
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)
    return cwd


@pytest.fixture
def recorder(monkeypatch):
    calls = []

    def fake_run(argv, *a, **k):
        calls.append((list(argv), k))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


# -- pure resolution (any OS) -------------------------------------------------

def test_safe_which_skips_cwd_dot_empty_and_relative_entries(tmp_path, monkeypatch):
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    _plant(cwd, "docker.exe")
    rel = cwd / "rel"
    rel.mkdir()
    _plant(rel, "docker.exe")
    monkeypatch.chdir(cwd)
    found = utils.safe_which(
        "docker", path_entries=["", ".", str(cwd), "rel", ".\\rel"],
        pathext=".EXE", cwd=str(cwd),
    )
    assert found is None


def test_safe_which_finds_absolute_path_entry_with_pathext(tmp_path):
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    _plant(cwd, "docker.exe")
    good = tmp_path / "bin"
    good.mkdir()
    real = _plant(good, "docker.EXE")
    found = utils.safe_which(
        "docker", path_entries=[str(cwd), str(good)], pathext=".COM;.EXE",
        cwd=str(cwd),
    )
    assert found is not None
    assert ntpath.normcase(found) == ntpath.normcase(str(real).replace("/", "\\")) or \
        found == str(real)


def test_safe_which_relative_command_with_separator_refused(tmp_path):
    assert utils.safe_which(".\\Dism.exe", path_entries=[str(tmp_path)], cwd=str(tmp_path)) is None
    assert utils.safe_which("sub/docker", path_entries=[str(tmp_path)], cwd=str(tmp_path)) is None


def test_system_tools_map_to_system_directory():
    sysdir = r"C:\Windows\System32"
    assert utils.windows_system_tool("Dism.exe", sysdir) == r"C:\Windows\System32\Dism.exe"
    assert utils.windows_system_tool("dism", sysdir) == r"C:\Windows\System32\Dism.exe"
    assert utils.windows_system_tool("powershell", sysdir) == (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    assert utils.windows_system_tool("SCHTASKS", sysdir) == r"C:\Windows\System32\schtasks.exe"
    assert utils.windows_system_tool("docker", sysdir) is None


# -- integration on Windows ----------------------------------------------------

@win_only
def test_system_dir_comes_from_the_api_not_env(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"Z:\Evil")
    d = utils.windows_system_dir()
    assert ntpath.isabs(d) and not d.lower().startswith("z:")


@win_only
@pytest.mark.parametrize("name", ["Dism.exe", "powershell", "schtasks"])
def test_run_command_uses_system32_not_planted_cwd_copy(planted_cwd, recorder, name):
    utils.run_command([name, "/?"])
    (argv, _k), = recorder
    exe = argv[0]
    assert ntpath.isabs(exe)
    assert ntpath.normcase(exe).startswith(ntpath.normcase(utils.windows_system_dir()))
    assert not ntpath.normcase(exe).startswith(ntpath.normcase(str(planted_cwd)))
    assert argv[1:] == ["/?"]


@win_only
def test_run_command_never_spawns_planted_docker(planted_cwd, recorder):
    code, _out, err = utils.run_command(["docker", "info"])
    assert code == 127 and "not found" in err
    assert recorder == []


@win_only
def test_which_ignores_planted_cwd_copy(planted_cwd):
    assert utils.which("docker") is None
    assert utils.which("docker.exe") is None
    assert not utils.has_any("docker", "cleanix")
    dism = utils.which("Dism.exe")
    assert dism is None or not ntpath.normcase(dism).startswith(
        ntpath.normcase(str(planted_cwd))
    )


@win_only
def test_docker_scan_probe_does_not_run_planted_binary(planted_cwd, recorder):
    from cleanix.cleaners.containers import DockerCleaner
    from cleanix.config import Config

    assert DockerCleaner(Config()).available() == "docker not found"
    assert recorder == []


@win_only
def test_cleanix_exe_rejects_planted_cwd_copy(planted_cwd):
    from cleanix.scheduler import schtasks

    exe, as_module = schtasks._cleanix_exe()
    assert (exe, as_module) == (sys.executable, True)


@win_only
def test_cleanix_exe_rejects_relative_which_result(planted_cwd, monkeypatch):
    from cleanix.scheduler import schtasks

    monkeypatch.setattr(schtasks.shutil, "which", lambda n: ".\\cleanix.EXE")
    assert schtasks._cleanix_exe() == (sys.executable, True)


@win_only
def test_cleanix_exe_result_is_absolute(tmp_path, monkeypatch):
    from cleanix.scheduler import schtasks

    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    monkeypatch.setattr(schtasks.shutil, "which", lambda n: r"C:\Tools\cleanix.exe")
    assert schtasks._cleanix_exe() == (r"C:\Tools\cleanix.exe", False)


@win_only
def test_cleanix_exe_under_cwd_accepted_when_on_safe_path(tmp_path, monkeypatch):
    from cleanix.scheduler import schtasks

    cwd = tmp_path / "proj"
    scripts = cwd / "venv" / "Scripts"
    scripts.mkdir(parents=True)
    real = _plant(scripts, "cleanix.exe")
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("PATH", str(scripts))
    monkeypatch.setattr(schtasks.shutil, "which", lambda n: str(real))
    exe, as_module = schtasks._cleanix_exe()
    assert as_module is False
    assert ntpath.normcase(exe) == ntpath.normcase(str(real))


@win_only
def test_schtasks_runs_system32_binary(planted_cwd, recorder):
    from cleanix.scheduler import schtasks

    schtasks.status()
    (argv, k), = recorder
    assert argv[0] == "schtasks"           # argv unchanged ...
    exe = k["executable"]                   # ... but the binary is pinned
    assert ntpath.normcase(exe) == ntpath.normcase(
        ntpath.join(utils.windows_system_dir(), "schtasks.exe")
    )
