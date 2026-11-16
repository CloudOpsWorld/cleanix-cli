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


ERROR_CANCELLED = 1223
_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SEE_MASK_NOASYNC = 0x00000100
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 0x102


def _shellexecuteinfo_class():
    """SHELLEXECUTEINFOW (112 bytes on x64, 60 on x86); ctypes only."""
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", ctypes.c_ulong),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hIcon", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

    return SHELLEXECUTEINFOW


def run_elevated(argv: Sequence[str], timeout: int) -> int:
    """Run argv elevated via UAC (verb runas), wait, return its exit code.

    argv[0] must be an absolute program path. Raises OSError (winerror 1223)
    if the user declines the prompt, TimeoutError if the process outlives
    ``timeout`` seconds, and OSError off Windows.
    """
    if not _is_win():
        raise OSError("elevation via UAC is only available on Windows")
    import ctypes
    import subprocess
    from ctypes import wintypes

    if not argv:
        raise ValueError("empty argv")
    info_cls = _shellexecuteinfo_class()
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(info_cls)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    info = info_cls()
    info.cbSize = ctypes.sizeof(info_cls)
    info.fMask = _SEE_MASK_NOCLOSEPROCESS | _SEE_MASK_NOASYNC
    info.lpVerb = "runas"
    info.lpFile = str(argv[0])
    info.lpParameters = subprocess.list2cmdline([str(a) for a in argv[1:]]) or None
    info.nShow = 0  # SW_HIDE: the helper has no UI
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    handle = info.hProcess
    if not handle:
        raise OSError("ShellExecuteExW returned no process handle")
    try:
        wait = kernel32.WaitForSingleObject(handle, max(0, int(timeout)) * 1000)
        if wait == _WAIT_TIMEOUT:
            raise TimeoutError("elevated process timed out")
        if wait != _WAIT_OBJECT_0:
            raise ctypes.WinError(ctypes.get_last_error())
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(code.value)
    finally:
        kernel32.CloseHandle(handle)
