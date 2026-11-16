"""Launch the elevated helper through the platform's own prompt.

Windows: UAC (ShellExecuteEx "runas"). Linux: pkexec. macOS: osascript
"with administrator privileges". Programs are resolved with
``utils.safe_which`` or fixed absolute system paths, never from the current
directory. Nothing here builds paths from caller input beyond the argv it is
given.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from cleanix.core import utils, winenv
from cleanix.core.platform import LINUX, MACOS, WINDOWS, current_os

_OSASCRIPT = "/usr/bin/osascript"
_ERROR_CANCELLED = 1223


class ElevationUnavailable(Exception):
    """No elevation mechanism is available on this system."""


class ElevationDeclined(Exception):
    """The user declined or cancelled the elevation prompt."""


class ElevationFailed(Exception):
    """Elevation or the elevated helper failed."""


def _invoker_uid() -> int:
    getuid = getattr(os, "getuid", None)
    return int(getuid()) if getuid else 0


def elevated_command(request_path: Path, result_path: Path,
                     config_path: Optional[str] = None) -> List[str]:
    cmd = [sys.executable, "-m", "cleanix.elevated",
           "--request", str(request_path), "--result", str(result_path)]
    if config_path:
        cmd += ["--config", str(config_path)]
    if current_os() != WINDOWS:
        cmd += ["--uid", str(_invoker_uid())]
    return cmd


def _applescript_quote(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _run(argv: List[str], timeout: int) -> "subprocess.CompletedProcess":
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as exc:
        raise ElevationFailed("elevated helper timed out") from exc
    except OSError as exc:
        raise ElevationFailed(f"could not start the elevation prompt: {exc}") from exc


def launch_elevated(argv: Sequence[str], *, timeout: int = 3600) -> int:
    args = [str(a) for a in argv]
    osname = current_os()
    if osname == WINDOWS:
        try:
            return winenv.run_elevated(args, timeout)
        except TimeoutError as exc:
            raise ElevationFailed("elevated helper timed out") from exc
        except OSError as exc:
            if getattr(exc, "winerror", None) == _ERROR_CANCELLED:
                raise ElevationDeclined("the UAC prompt was declined") from exc
            raise ElevationFailed(f"UAC elevation failed: {exc}") from exc
    if osname == LINUX:
        pkexec = utils.safe_which("pkexec")
        if not pkexec:
            raise ElevationUnavailable("pkexec (polkit) was not found")
        proc = _run([pkexec] + args, timeout)
        if proc.returncode in (126, 127):
            raise ElevationDeclined("authentication was declined or unavailable")
    elif osname == MACOS:
        script = ('do shell script "%s" with administrator privileges'
                  % _applescript_quote(shlex.join(args)))
        proc = _run([_OSASCRIPT, "-e", script], timeout)
        if proc.returncode != 0 and "(-128)" in (proc.stderr or ""):
            raise ElevationDeclined("the password prompt was cancelled")
    else:
        raise ElevationUnavailable(f"no elevation mechanism for {osname}")
    if proc.returncode != 0:
        msg = (proc.stderr or "").strip() or f"exit code {proc.returncode}"
        raise ElevationFailed(msg)
    return 0
