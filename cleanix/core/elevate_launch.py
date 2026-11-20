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
from typing import Callable, List, Optional, Sequence

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


def run_findings_request(findings, invoking_user: str, *,
                         launcher: Optional[Callable[[List[str]], int]] = None,
                         config_path: Optional[str] = None):
    """Send one findings request (``elevate.FindingsRequest``) to the
    elevated helper and return its ``elevate.HelperResult``.

    Writes the request into a fresh private request directory, launches the
    helper through ``launcher`` (default :func:`launch_elevated`; one
    prompt), then reads the result, which must carry this request's nonce.
    A helper that refused or failed after writing its result (exit 1-3)
    still returns that result. Raises ElevationDeclined /
    ElevationUnavailable / ElevationFailed (no usable result) and
    ValueError, before any prompt, for a request the helper's lexical
    checks would refuse (platform, scenario allowlist, paths, size) or
    that cannot be written. A result naming an item that was not requested
    is ElevationFailed. The request directory is always removed. Nothing
    here touches the items themselves."""
    import shutil

    from cleanix import elevated
    from cleanix.core import elevate

    if not elevated._findings_supported():
        raise ValueError(elevated.FINDINGS_NOT_SUPPORTED)
    allowed = elevated.admin_finding_ids()
    if not findings.only or any(c not in allowed for c in findings.only):
        raise ValueError("the request names a scenario the administrator helper does not act on")
    roots = elevated.finding_path_roots()
    never = elevated.root_quarantine_never()
    for sel in findings.items:
        cid, path = elevate.finding_key_parts(sel.key)
        problem = elevate.finding_path_problem(cid, path, roots, never)
        if problem:
            raise ValueError(f"the administrator helper never acts on this item ({problem})")
    selection = elevate.Selection(invoking_user=invoking_user, only=[], keys=[],
                                  use_quarantine=False, findings=findings)
    # Round-trip through the strict parser first: never prompt for a request
    # the helper would refuse anyway.
    request_dir = elevate.make_request_dir()
    try:
        request_path = elevate.write_request(request_dir, selection)
        data = request_path.read_bytes()
        if len(data) > elevate.MAX_REQUEST_BYTES:
            raise ValueError("the request is too large; select fewer items")
        elevate.parse_request(data)
        result_path = request_dir / elevate.RESULT_NAME
        argv = elevated_command(request_path, result_path, config_path)
        launch = launcher or launch_elevated
        failure: Optional[ElevationFailed] = None
        try:
            launch(argv)
        except ElevationFailed as exc:
            if exc.exit_code not in (1, 2, 3):
                raise
            failure = exc
        try:
            result = elevate.read_result(result_path)
        except (ValueError, OSError):
            if failure is not None:
                raise failure
            raise ElevationFailed("the helper's result could not be read") from None
        if result.nonce != selection.nonce:
            raise ElevationFailed("the helper returned a stale or unexpected result")
        requested = {s.key for s in findings.items}
        if any(o.key not in requested for o in result.findings):
            raise ElevationFailed("the helper's result names an item that was not requested")
        return result
    finally:
        shutil.rmtree(request_dir, ignore_errors=True)
