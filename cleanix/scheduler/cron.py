"""Install/uninstall a per-user **cron** job that periodically scans.

This is the scheduling backend for the BSDs (and any system with ``crontab``
but no systemd/launchd). Like the other backends it only *analyzes* — the job
writes a JSON report and never deletes anything. The entry is fenced by marker
comments so we can add/remove exactly our own line without touching the rest of
the user's crontab.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple

BEGIN = "# >>> cleanix-scan >>>"
END = "# <<< cleanix-scan <<<"

# Friendly frequency -> cron schedule (fires at 03:00 for the calendar ones).
FREQUENCIES = {
    "hourly": "0 * * * *",
    "daily": "0 3 * * *",
    "weekly": "0 3 * * 0",
    "monthly": "0 3 1 * *",
}


def _report_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser(
        "~/.local/state"
    )
    return Path(base) / "cleanix"


def _cleanix_exe() -> str:
    return shutil.which("cleanix") or "cleanix"


def cron_available() -> Optional[str]:
    if not shutil.which("crontab"):
        return "crontab not found (cron required for scheduling on this OS)"
    return None


def _crontab_read() -> str:
    try:
        proc = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        return ""
    # A missing crontab exits non-zero with an empty body; treat as empty.
    return proc.stdout if proc.returncode == 0 else ""


def _crontab_write(body: str) -> Tuple[int, str]:
    try:
        proc = subprocess.run(
            ["crontab", "-"], input=body, capture_output=True, text=True,
            check=False,
        )
    except FileNotFoundError:
        return 127, "crontab not found"
    return proc.returncode, proc.stderr


def _strip_block(body: str) -> str:
    """Remove our fenced block from an existing crontab body."""
    out, skipping = [], False
    for line in body.splitlines():
        if line.strip() == BEGIN:
            skipping = True
            continue
        if line.strip() == END:
            skipping = False
            continue
        if not skipping:
            out.append(line)
    return "\n".join(out).strip("\n")


def install(frequency: str = "weekly") -> str:
    err = cron_available()
    if err:
        raise RuntimeError(err)
    schedule = FREQUENCIES.get(frequency)
    if schedule is None:
        raise ValueError(
            f"unknown frequency {frequency!r}; choose one of "
            f"{', '.join(FREQUENCIES)}"
        )

    _report_dir().mkdir(parents=True, exist_ok=True)
    report_file = _report_dir() / "last-scan.json"
    exe = _cleanix_exe()
    block = (
        f"{BEGIN}\n"
        f"{schedule} {exe} scan --json --output {report_file} "
        f">/dev/null 2>&1\n"
        f"{END}"
    )
    existing = _strip_block(_crontab_read())
    body = (existing + "\n" if existing else "") + block + "\n"
    code, serr = _crontab_write(body)
    if code != 0:
        raise RuntimeError(f"failed to update crontab: {serr.strip()}")
    return (
        f"Installed cleanix cron job ({frequency}). Reports are written to "
        f"{report_file}."
    )


def uninstall() -> str:
    err = cron_available()
    if err:
        raise RuntimeError(err)
    current = _crontab_read()
    if BEGIN not in current:
        return "Nothing to remove (cron job was not installed)."
    body = _strip_block(current)
    code, serr = _crontab_write(body + ("\n" if body else ""))
    if code != 0:
        raise RuntimeError(f"failed to update crontab: {serr.strip()}")
    return "Removed cleanix cron job."


def status() -> str:
    err = cron_available()
    if err:
        return err
    return (
        "Cleanix schedule: installed (cron)."
        if BEGIN in _crontab_read()
        else "Cleanix schedule: not installed."
    )
