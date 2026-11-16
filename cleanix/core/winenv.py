"""Windows environment helpers (importable on every OS).

Windows-only imports (ctypes.windll) happen inside functions. Cleaners call
these as ``winenv.local_appdata()`` so tests can monkeypatch them.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Sequence


def _is_win() -> bool:
    return sys.platform == "win32"


def is_admin() -> bool:
    if not _is_win():
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def _user_dir(env_var: str, sub: str) -> Path:
    from cleanix.core.context import current_user

    user = current_user()
    if user.is_invoker:
        val = os.environ.get(env_var)
        if val:
            return Path(val)
    return user.home / "AppData" / sub


def local_appdata() -> Path:
    return _user_dir("LOCALAPPDATA", "Local")


def roaming_appdata() -> Path:
    return _user_dir("APPDATA", "Roaming")


def user_temp() -> Path:
    return local_appdata() / "Temp"


def programdata() -> Path:
    return Path(os.environ.get("ProgramData") or r"C:\ProgramData")


def system_root() -> Path:
    return Path(os.environ.get("SystemRoot") or r"C:\Windows")


def system_drive() -> str:
    return os.environ.get("SystemDrive") or "C:"


def recycle_bin_size() -> int:
    """Total Recycle Bin bytes across drives, 0 on failure or off Windows."""
    if not _is_win():
        return 0
    try:
        import ctypes
        from ctypes import wintypes

        class SHQUERYRBINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("i64Size", ctypes.c_longlong),
                ("i64NumItems", ctypes.c_longlong),
            ]

        info = SHQUERYRBINFO()
        info.cbSize = ctypes.sizeof(SHQUERYRBINFO)
        rc = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))  # type: ignore[attr-defined]
        if rc != 0:
            return 0
        return max(0, int(info.i64Size))
    except Exception:
        return 0


def relaunch_elevated(argv: Sequence[str]) -> bool:
    """Re-run this program elevated via UAC. False off Windows or on failure."""
    if not _is_win():
        return False
    try:
        import ctypes
        import subprocess

        params = subprocess.list2cmdline(list(argv))
        rc = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", sys.executable, params, None, 1
        )
        return int(rc) > 32
    except Exception:
        return False
