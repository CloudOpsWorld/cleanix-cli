"""Install/uninstall a per-user **Windows Task Scheduler** task that scans.

Like the other backends this only *analyzes*: the task runs
``cleanix scan --json --output <report>`` as the current user (no ``/RU``,
never SYSTEM, ``/RL LIMITED``) and never deletes anything. Unlike the systemd
backend's ``notify-send``, no notification is raised; the report file is the
output.
"""

from __future__ import annotations

import ntpath
import os
import shutil
import subprocess
import sys
from typing import List, Tuple

from cleanix.core import history

TASK_NAME = "Cleanix Scan"
MAX_TR_LEN = 261  # schtasks limit for the /TR value

# Friendly frequency -> (schtasks /SC value, extra args after /SC).
FREQUENCIES = {
    "hourly": ("HOURLY", []),
    "daily": ("DAILY", ["/ST", "03:00"]),
    "weekly": ("WEEKLY", ["/D", "SUN", "/ST", "03:00"]),
    "monthly": ("MONTHLY", ["/D", "1", "/ST", "03:00"]),
}


def _cleanix_exe() -> Tuple[str, bool]:
    """Return ``(path, as_module)``.

    Falls back to ``sys.executable`` run as ``-m cleanix`` when no ``cleanix``
    is on PATH, so the task does not depend on PATH at run time.
    """
    exe = shutil.which("cleanix")
    if exe and os.name == "nt":
        exe = _vet_windows_exe(exe)
    if exe:
        return exe, False
    return sys.executable, True


def _vet_windows_exe(exe: str):
    """Absolutise ``exe`` and reject a copy found in the current directory.

    ``shutil.which`` searches the cwd first on Windows, so a planted
    ``.\\cleanix.exe`` would otherwise be written (as a relative path) into the
    scheduled task. Anything under the cwd is accepted only when the cwd-free
    PATH search finds the very same file; otherwise ``None`` (module fallback).
    """
    from cleanix.core.utils import safe_which

    exe = os.path.abspath(exe)
    try:
        cwd = os.path.abspath(os.getcwd())
    except OSError:
        cwd = ""
    norm = ntpath.normcase(ntpath.normpath(exe))
    cwd_norm = ntpath.normcase(ntpath.normpath(cwd)) if cwd else ""
    under_cwd = bool(cwd_norm) and (
        norm == cwd_norm or norm.startswith(cwd_norm.rstrip("\\") + "\\")
    )
    if not under_cwd:
        return exe
    safe = safe_which("cleanix")
    if safe and ntpath.normcase(ntpath.normpath(safe)) == norm:
        return exe
    return None


def build_create_args(
    frequency: str, exe: str, report_file: str, as_module: bool = False
) -> List[str]:
    spec = FREQUENCIES.get(frequency)
    if spec is None:
        raise ValueError(
            f"unknown frequency {frequency!r}; choose one of "
            f"{', '.join(FREQUENCIES)}"
        )
    sc, extra = spec
    prefix = f'"{exe}" -m cleanix' if as_module else f'"{exe}"'
    command = f'{prefix} scan --json --output "{report_file}"'
    if len(command) > MAX_TR_LEN:
        raise ValueError(
            f"scheduled command is {len(command)} characters; Task Scheduler "
            f"allows at most {MAX_TR_LEN}. Install cleanix in a shorter path."
        )
    return [
        "schtasks", "/Create", "/TN", TASK_NAME, "/TR", command,
        "/SC", sc, *extra, "/RL", "LIMITED", "/F",
    ]


def _run(argv: List[str]) -> Tuple[int, str, str]:
    kwargs = {}
    if sys.platform == "win32":
        # Never let CreateProcess search the current directory for schtasks:
        # run the System32 binary (argv itself stays unchanged).
        from cleanix.core.utils import windows_system_tool

        kwargs["executable"] = windows_system_tool("schtasks")
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, errors="replace", check=False,
            **kwargs,
        )
    except FileNotFoundError:
        return 127, "", "schtasks not found"
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def install(frequency: str = "weekly") -> str:
    state = history.state_dir()
    report_file = state / "last-scan.json"
    exe, as_module = _cleanix_exe()
    args = build_create_args(frequency, exe, str(report_file), as_module)
    state.mkdir(parents=True, exist_ok=True)
    code, out, err = _run(args)
    if code != 0:
        raise RuntimeError(
            f"failed to create scheduled task: {(err or out).strip()}"
        )
    return (
        f"Installed cleanix scheduled task ({frequency}). Reports are "
        f"written to {report_file}."
    )


def uninstall() -> str:
    code, out, err = _run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    if code == 0:
        return "Removed cleanix scheduled task."
    if code == 127:
        raise RuntimeError(err)
    return "Nothing to remove (scheduled task was not installed)."


def status() -> str:
    code, _out, err = _run(["schtasks", "/Query", "/TN", TASK_NAME])
    if code == 127:
        return err
    return (
        "Cleanix schedule: installed (Task Scheduler)."
        if code == 0
        else "Cleanix schedule: not installed."
    )
