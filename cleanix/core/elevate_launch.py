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

    def __init__(self, message: str = "", exit_code: Optional[int] = None):
        super().__init__(message)
        self.exit_code = exit_code


def _invoker_uid() -> int:
    getuid = getattr(os, "getuid", None)
    return int(getuid()) if getuid else 0


def elevated_command(request_path: Path, result_path: Path,
                     config_path: Optional[str] = None) -> List[str]:
    """argv for the helper. ``-I`` (isolated mode) makes the elevated
    interpreter ignore PYTHONPATH/PYTHONHOME/PYTHONSTARTUP, the user site
    directory and the current directory on sys.path, before the helper gets
    a chance to sanitise its environment. Frozen builds (Plan 2B) have no
    ``-I``/``-m`` and will use a dedicated helper entry point instead."""
    cmd = [sys.executable, "-I", "-m", "cleanix.elevated",
           "--request", str(request_path), "--result", str(result_path)]
    if config_path:
        cmd += ["--config", str(config_path)]
    if current_os() != WINDOWS:
        cmd += ["--uid", str(_invoker_uid())]
    return cmd


def _applescript_quote(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _run(argv: List[str], timeout: int):
    """Popen-based runner: returns (returncode, stderr).

    After authentication the helper runs as root, so an unprivileged kill() may
    fail and a plain wait() would block until the helper exits; never block.
    """
    try:
        # Bytes, decoded leniently below: undecodable helper/prompt output
        # must never raise after the elevated helper already ran.
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    except OSError as exc:
        raise ElevationFailed(f"could not start the elevation prompt: {exc}") from exc
    try:
        _out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            proc.kill()
        except OSError:
            pass
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream:
                    stream.close()
            except Exception:
                pass
        try:
            proc.wait(timeout=1)
        except Exception:
            pass
        raise ElevationFailed("elevated helper timed out and may still be running") from exc
    return proc.returncode, _decode(err)


def _decode(data) -> str:
    """Text of a captured stream; never raises (bad bytes become U+FFFD)."""
    if not data:
        return ""
    if isinstance(data, str):
        return data
    try:
        return bytes(data).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - diagnostics only
        return ""


def launch_elevated(argv: Sequence[str], *, timeout: int = 3600) -> int:
    """Run argv elevated. Returns 0 only on success; every failure raises one
    of ElevationUnavailable / ElevationDeclined / ElevationFailed.

    The detailed outcome comes from the helper's result file, not the exit code.
    On Windows this blocks while the consent dialog is open: call it off the
    GUI thread.
    """
    if not argv or not os.path.isabs(str(argv[0])):
        raise ValueError("argv[0] must be an absolute program path")
    args = [str(a) for a in argv]
    osname = current_os()
    if osname == WINDOWS:
        try:
            rc = winenv.run_elevated(args, timeout)
        except TimeoutError as exc:
            raise ElevationFailed(str(exc) or "elevated helper timed out") from exc
        except OSError as exc:
            if getattr(exc, "winerror", None) == _ERROR_CANCELLED:
                raise ElevationDeclined("the UAC prompt was declined") from exc
            raise ElevationFailed(f"UAC elevation failed: {exc}") from exc
        if rc != 0:
            raise ElevationFailed(f"elevated helper exited with code {rc}", exit_code=rc)
        return 0
    if osname == LINUX:
        pkexec = utils.safe_which("pkexec")
        if not pkexec:
            raise ElevationUnavailable("pkexec (polkit) was not found")
        rc, err = _run([pkexec] + args, timeout)
        if rc == 126:
            raise ElevationDeclined("authentication was declined")
        if rc == 127:
            if "no authentication agent" in err.lower():
                raise ElevationUnavailable("no polkit authentication agent is running")
            raise ElevationFailed(err.strip() or "pkexec could not run the helper", exit_code=rc)
    elif osname == MACOS:
        script = ('do shell script "%s" with administrator privileges'
                  % _applescript_quote(shlex.join(args)))
        rc, err = _run([_OSASCRIPT, "-e", script], timeout)
        if rc != 0 and (err.rstrip().endswith("(-128)") or "User canceled" in err):
            raise ElevationDeclined("the password prompt was cancelled")
    else:
        raise ElevationUnavailable(f"no elevation mechanism for {osname}")
    if rc != 0:
        raise ElevationFailed(err.strip() or f"exit code {rc}", exit_code=rc)
    return 0
