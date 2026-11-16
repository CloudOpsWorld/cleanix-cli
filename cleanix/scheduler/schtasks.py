"""Install/uninstall a per-user **Windows Task Scheduler** task that scans.

Like the other backends this only *analyzes*: the task runs
``cleanix scan --json --output <report>`` as the current user (no ``/RU``,
never SYSTEM, ``/RL LIMITED``) and never deletes anything. Unlike the systemd
backend's ``notify-send``, no notification is raised; the report file is the
output.
"""

from __future__ import annotations

import shutil
import subprocess
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


def _cleanix_exe() -> str:
    return shutil.which("cleanix") or "cleanix"


def build_create_args(frequency: str, exe: str, report_file: str) -> List[str]:
    spec = FREQUENCIES.get(frequency)
    if spec is None:
        raise ValueError(
            f"unknown frequency {frequency!r}; choose one of "
            f"{', '.join(FREQUENCIES)}"
        )
    sc, extra = spec
    command = f'"{exe}" scan --json --output "{report_file}"'
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
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        return 127, "", "schtasks not found"
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def install(frequency: str = "weekly") -> str:
    state = history.state_dir()
    report_file = state / "last-scan.json"
    args = build_create_args(frequency, _cleanix_exe(), str(report_file))
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
