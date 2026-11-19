"""Reveal a path in the OS file manager. Argv lists only, never a shell."""

from __future__ import annotations

import ntpath
import os
import shutil
import subprocess
import threading
from typing import List, Optional

from cleanix.core import platform as plat
from cleanix.core import utils


def _resolve(name: str) -> Optional[str]:
    """Absolute path of ``name``; never resolved from the current directory."""
    if plat.is_windows():
        return utils.resolve_executable(name)
    found = shutil.which(name)
    return os.path.abspath(found) if found else None


def _argv(path: str) -> Optional[List[str]]:
    if plat.is_windows():
        exe = _resolve("explorer")
        return [exe, "/select," + ntpath.normpath(path)] if exe else None
    if plat.is_macos():
        exe = _resolve("open")
        return [exe, "-R", path] if exe else None
    parent = os.path.dirname(path) or "."
    if not os.path.isdir(parent):
        return None
    exe = _resolve("xdg-open")
    return [exe, parent] if exe else None


def reveal_in_file_manager(path: str) -> bool:
    """Show ``path`` in the file manager. False if the tool is missing/fails."""
    if not path:
        return False
    argv = _argv(path)
    if argv is None:
        return False
    try:
        # Explorer exits non-zero even on success, so do not wait or check.
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError):
        return False
    threading.Thread(target=_reap, args=(proc,), daemon=True).start()
    return True


def _reap(proc) -> None:
    """Wait for the child off-thread so it does not linger as a zombie."""
    try:
        proc.wait()
    except Exception:  # noqa: BLE001
        pass
