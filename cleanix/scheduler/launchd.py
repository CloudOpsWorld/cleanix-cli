"""Install/uninstall a launchd *user* agent that periodically scans (macOS).

This is the macOS counterpart to :mod:`cleanix.scheduler.systemd`. Scheduled
runs only **analyze** and write a report + a Notification Center banner; they
never delete anything. A LaunchAgent under ``~/Library/LaunchAgents`` runs
entirely inside the user's GUI session — no root, no system-wide daemons.
"""

from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple

LABEL = "com.cleanix.scan"
PLIST_NAME = f"{LABEL}.plist"

# launchd has no "hourly/daily/weekly" keywords, so we translate friendly
# frequencies into a StartInterval (seconds) or a StartCalendarInterval dict.
# Calendar entries fire at 03:00 local time; launchd runs a missed calendar job
# once when the machine next wakes, so an asleep Mac still gets scanned.
_HOUR = 3
FREQUENCIES = {
    "hourly": {"StartInterval": 3600},
    "daily": {"StartCalendarInterval": {"Hour": _HOUR, "Minute": 0}},
    "weekly": {"StartCalendarInterval": {"Weekday": 0, "Hour": _HOUR, "Minute": 0}},
    "monthly": {"StartCalendarInterval": {"Day": 1, "Hour": _HOUR, "Minute": 0}},
}


def _agents_dir() -> Path:
    return Path(os.path.expanduser("~/Library/LaunchAgents"))


def _plist_path() -> Path:
    return _agents_dir() / PLIST_NAME


def _report_dir() -> Path:
    # Kept consistent with the rest of cleanix, which stores its state under
    # ~/.local/state/cleanix on every platform (see core.history / quarantine).
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser(
        "~/.local/state"
    )
    return Path(base) / "cleanix"


def _cleanix_exe() -> str:
    return shutil.which("cleanix") or "cleanix"


def launchd_available() -> Optional[str]:
    if not shutil.which("launchctl"):
        return "launchctl not found (launchd required for scheduling on macOS)"
    return None


def _launchctl(*args: str) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["launchctl", *args],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", "launchctl not found"


def _program_arguments() -> list:
    exe = _cleanix_exe()
    report_file = _report_dir() / "last-scan.json"
    # A single /bin/sh wrapper runs the read-only scan, then posts a
    # Notification Center banner summarizing it (osascript is always present on
    # macOS). Failures in either half are swallowed so launchd stays happy.
    script = (
        f'{exe} scan --json --output "{report_file}"; '
        f'summary="$({exe} scan --summary --input "{report_file}" 2>/dev/null || echo "scan complete")"; '
        f'osascript -e "display notification \\"$summary\\" with title \\"Cleanix\\"" '
        f">/dev/null 2>&1 || true"
    )
    return ["/bin/sh", "-c", script]


def _plist(frequency: str) -> Dict:
    schedule = FREQUENCIES[frequency]
    plist: Dict = {
        "Label": LABEL,
        "ProgramArguments": _program_arguments(),
        "RunAtLoad": False,
        # Be a good citizen: low CPU and I/O priority for a background chore.
        "Nice": 15,
        "LowPriorityIO": True,
        "ProcessType": "Background",
        "StandardOutPath": str(_report_dir() / "scan.out.log"),
        "StandardErrorPath": str(_report_dir() / "scan.err.log"),
    }
    plist.update(schedule)
    return plist


def install(frequency: str = "weekly") -> str:
    err = launchd_available()
    if err:
        raise RuntimeError(err)

    if frequency not in FREQUENCIES:
        raise ValueError(
            f"unknown frequency {frequency!r}; choose one of "
            f"{', '.join(FREQUENCIES)}"
        )

    _agents_dir().mkdir(parents=True, exist_ok=True)
    _report_dir().mkdir(parents=True, exist_ok=True)

    plist_path = _plist_path()
    with plist_path.open("wb") as fh:
        plistlib.dump(_plist(frequency), fh)

    # Reload cleanly: unload an existing copy (ignore "not loaded"), then load
    # with -w so the agent survives logout/reboot.
    _launchctl("unload", str(plist_path))
    code, _out, serr = _launchctl("load", "-w", str(plist_path))
    if code != 0:
        raise RuntimeError(f"failed to load agent: {serr.strip() or 'unknown error'}")
    return (
        f"Installed {PLIST_NAME} ({frequency}). Reports are written to "
        f"{_report_dir() / 'last-scan.json'}."
    )


def uninstall() -> str:
    err = launchd_available()
    if err:
        raise RuntimeError(err)

    plist_path = _plist_path()
    if not plist_path.exists():
        return "Nothing to remove (schedule was not installed)."
    _launchctl("unload", "-w", str(plist_path))
    plist_path.unlink()
    return f"Removed {PLIST_NAME}."


def status() -> str:
    err = launchd_available()
    if err:
        return err
    if not _plist_path().exists():
        return "Cleanix schedule: not installed."
    code, out, _serr = _launchctl("list", LABEL)
    if code == 0:
        return f"Cleanix schedule: installed and loaded.\n{out.strip()}"
    return "Cleanix schedule: installed (plist present, not currently loaded)."
