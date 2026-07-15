"""Install/uninstall a systemd *user* timer that periodically scans.

Scheduled runs only **analyze** and write a report + desktop notification; they
never delete anything. Using a user timer keeps everything inside the user's
own session — no root required, no system-wide units touched.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple

SERVICE_NAME = "cleanix-scan.service"
TIMER_NAME = "cleanix-scan.timer"

# Map friendly frequencies to systemd OnCalendar expressions.
FREQUENCIES = {
    "hourly": "hourly",
    "daily": "daily",
    "weekly": "weekly",
    "monthly": "monthly",
}


def _user_unit_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "systemd" / "user"


def _report_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser(
        "~/.local/state"
    )
    return Path(base) / "cleanix"


def _cleanix_exe() -> str:
    return shutil.which("cleanix") or "cleanix"


def _systemctl(*args: str) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["systemctl", "--user", *args],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", "systemctl not found"


def systemd_available() -> Optional[str]:
    if not shutil.which("systemctl"):
        return "systemctl not found (systemd required for scheduling)"
    return None


def _service_unit() -> str:
    exe = _cleanix_exe()
    report_dir = _report_dir()
    report_file = report_dir / "last-scan.json"
    # ExecStartPost sends a desktop notification summarizing the scan. It uses
    # the resolved {exe} (systemd's PATH is restricted, so a bare `cleanix`
    # often isn't found) and summarizes the JSON *just written* by ExecStart
    # rather than running a second full scan.
    notify = (
        "/bin/sh -c '"
        f"command -v notify-send >/dev/null 2>&1 && "
        f"notify-send \"Cleanix\" "
        f"\"$({exe} scan --summary --input {report_file} 2>/dev/null "
        f"|| echo scan complete)\" "
        "|| true'"
    )
    return f"""[Unit]
Description=Cleanix scheduled analysis (read-only, no deletion)
Documentation=man:cleanix(1)

[Service]
Type=oneshot
ExecStart={exe} scan --json --output {report_file}
ExecStartPost={notify}
Nice=15
IOSchedulingClass=idle
"""


def _timer_unit(calendar: str) -> str:
    return f"""[Unit]
Description=Run Cleanix analysis on a schedule

[Timer]
OnCalendar={calendar}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
"""


def install(frequency: str = "weekly") -> str:
    err = systemd_available()
    if err:
        raise RuntimeError(err)

    calendar = FREQUENCIES.get(frequency)
    if calendar is None:
        raise ValueError(
            f"unknown frequency {frequency!r}; choose one of "
            f"{', '.join(FREQUENCIES)}"
        )

    unit_dir = _user_unit_dir()
    unit_dir.mkdir(parents=True, exist_ok=True)
    _report_dir().mkdir(parents=True, exist_ok=True)

    (unit_dir / SERVICE_NAME).write_text(_service_unit())
    (unit_dir / TIMER_NAME).write_text(_timer_unit(calendar))

    _systemctl("daemon-reload")
    code, _out, serr = _systemctl("enable", "--now", TIMER_NAME)
    if code != 0:
        raise RuntimeError(f"failed to enable timer: {serr.strip()}")
    return (
        f"Installed {TIMER_NAME} ({frequency}). Reports are written to "
        f"{_report_dir() / 'last-scan.json'}."
    )


def uninstall() -> str:
    err = systemd_available()
    if err:
        raise RuntimeError(err)

    _systemctl("disable", "--now", TIMER_NAME)
    unit_dir = _user_unit_dir()
    removed = []
    for name in (TIMER_NAME, SERVICE_NAME):
        unit = unit_dir / name
        if unit.exists():
            unit.unlink()
            removed.append(name)
    _systemctl("daemon-reload")
    if removed:
        return f"Removed {', '.join(removed)}."
    return "Nothing to remove (timer was not installed)."


def status() -> str:
    err = systemd_available()
    if err:
        return err
    installed = (_user_unit_dir() / TIMER_NAME).exists()
    if not installed:
        return "Cleanix schedule: not installed."
    _code, out, _serr = _systemctl(
        "list-timers", TIMER_NAME, "--no-pager", "--all"
    )
    return out.strip() or "Cleanix schedule: installed."
