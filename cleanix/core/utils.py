"""Small helpers: sizes, path walking, age filtering, command running."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterator, Optional, Sequence


def human_size(num_bytes: int) -> str:
    """Format a byte count like ``1.4 GiB``."""
    size = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(size) < 1024.0 or unit == "PiB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PiB"


def _allocated_bytes(st: os.stat_result) -> int:
    """Actual on-disk usage of a stat result.

    We use allocated blocks (``st_blocks`` * 512) rather than the apparent
    ``st_size`` so that sparse files — whose apparent size can be terabytes
    while occupying almost no disk — do not wildly overstate reclaimable space.
    Falls back to ``st_size`` on platforms without ``st_blocks``.
    """
    blocks = getattr(st, "st_blocks", None)
    if blocks is None:
        return st.st_size
    return blocks * 512


def path_size(path: str | os.PathLike) -> int:
    """Actual on-disk size of a file or directory tree in bytes (best effort)."""
    p = Path(path)
    win = sys.platform == "win32"
    if win:
        # Junctions are not symlinks: never size (or walk into) their target.
        from cleanix.core import safety as _safety

        if _safety.is_reparse_point(p):
            return 0
    try:
        if p.is_symlink():
            return 0
        if p.is_file():
            return _allocated_bytes(p.stat())
    except OSError:
        return 0

    total = 0
    for root, dirs, files in os.walk(p, onerror=lambda e: None):
        # Do not follow symlinked directories.
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        if win:
            dirs[:] = [
                d for d in dirs
                if not _safety.is_reparse_point(os.path.join(root, d))
            ]
        for name in files:
            fp = os.path.join(root, name)
            try:
                if os.path.islink(fp):
                    continue
                total += _allocated_bytes(os.lstat(fp))
            except OSError:
                continue
    return total


def iter_children(path: str | os.PathLike) -> Iterator[Path]:
    """Yield immediate children of a directory, ignoring errors."""
    try:
        with os.scandir(path) as it:
            for entry in it:
                yield Path(entry.path)
    except OSError:
        return


def older_than(path: str | os.PathLike, days: float) -> bool:
    """True if the path's mtime is older than ``days`` days."""
    if days <= 0:
        return True
    try:
        mtime = os.lstat(path).st_mtime
    except OSError:
        return False
    return (time.time() - mtime) > days * 86400


def _mtime(path: str | os.PathLike) -> float:
    try:
        return os.lstat(path).st_mtime
    except OSError:
        return 0.0


def surplus_after_keeping(paths, keep: int) -> list:
    """Return the paths to remove when keeping only the ``keep`` newest.

    Given rolling backups/snapshots, keep the ``keep`` most recently modified
    and return the older surplus (the ones safe to delete). Implements the
    common "keep max N backups" retention policy.
    """
    ordered = sorted(paths, key=_mtime, reverse=True)  # newest first
    if keep <= 0:
        return list(ordered)
    return list(ordered[keep:])


def modified_within(path: str | os.PathLike, minutes: float) -> bool:
    """True if the path was modified within the last ``minutes`` minutes.

    Used as an "in use" guard: a file being actively written (e.g. another
    program's scratch file) has a very recent mtime and should be left alone.
    """
    if minutes <= 0:
        return False
    try:
        mtime = os.lstat(path).st_mtime
    except OSError:
        return False
    return (time.time() - mtime) < minutes * 60


def exists(path: str | os.PathLike) -> bool:
    try:
        return Path(os.path.expanduser(str(path))).exists()
    except OSError:
        return False


def which(cmd: str) -> Optional[str]:
    if sys.platform == "win32":
        return resolve_executable(cmd)
    return shutil.which(cmd)


def has_any(*cmds: str) -> bool:
    if sys.platform == "win32":
        return any(resolve_executable(c) for c in cmds)
    return any(shutil.which(c) for c in cmds)


# -- Windows executable resolution -------------------------------------------
# CreateProcess and shutil.which search the *current directory* before
# System32/PATH, so a bare "Dism.exe" run from an untrusted folder would execute
# a planted .\Dism.exe (elevated, during a clean). On Windows every command is
# therefore resolved to an absolute path before it is spawned: the built-in
# system tools come from GetSystemDirectoryW, everything else from the PATH
# entries only (never the cwd, never a relative entry).

# Bare name (casefolded, without .exe) -> path relative to the system directory.
_WIN_SYSTEM_TOOLS = {
    "powershell": "WindowsPowerShell\\v1.0\\powershell.exe",
    "dism": "Dism.exe",
    "schtasks": "schtasks.exe",
}

_DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD"


def windows_system_dir() -> str:
    """The real System32 directory (GetSystemDirectoryW; never the env)."""
    try:
        import ctypes

        fn = ctypes.windll.kernel32.GetSystemDirectoryW  # type: ignore[attr-defined]
        buf = ctypes.create_unicode_buffer(1024)
        n = fn(buf, 1024)
        if 0 < n < 1024 and buf.value:
            return buf.value
    except Exception:  # noqa: BLE001
        pass
    return "C:\\Windows\\System32"


def windows_system_tool(name: str, system_dir: Optional[str] = None) -> Optional[str]:
    """Absolute path of a built-in Windows tool (powershell/Dism/schtasks)."""
    key = name.lower()
    if key.endswith(".exe"):
        key = key[:-4]
    rel = _WIN_SYSTEM_TOOLS.get(key)
    if rel is None:
        return None
    import ntpath

    return ntpath.join(system_dir or windows_system_dir(), rel)


def safe_which(
    cmd: str,
    path_entries: Optional[Sequence[str]] = None,
    pathext: Optional[str] = None,
    cwd: Optional[str] = None,
    isfile=os.path.isfile,
) -> Optional[str]:
    """``which`` that never searches the current directory.

    Only absolute PATH entries are searched (``''``, ``'.'``, relative entries
    and the cwd itself are skipped); ``PATHEXT`` is honoured. A ``cmd`` that
    contains a directory separator is returned as an absolute path only if it is
    already absolute. Pure apart from ``isfile``; all inputs are injectable.
    Path rules are the host's (``os.path``); on Windows an absolute entry must
    also carry a drive (a rooted ``\\dir`` is drive-relative).
    """
    pth = os.path

    def _absolute(p: str) -> bool:
        return pth.isabs(p) and (os.name != "nt" or bool(pth.splitdrive(p)[0]))

    if not cmd:
        return None
    if "\\" in cmd or "/" in cmd:
        if _absolute(cmd) and isfile(cmd):
            return cmd
        return None
    if path_entries is None:
        path_entries = (os.environ.get("PATH") or "").split(os.pathsep)
    if pathext is None:
        pathext = os.environ.get("PATHEXT") or _DEFAULT_PATHEXT
    if cwd is None:
        try:
            cwd = os.getcwd()
        except OSError:
            cwd = ""
    exts = [e for e in pathext.split(";") if e]
    if any(cmd.lower().endswith(e.lower()) for e in exts):
        names = [cmd]
    else:
        names = [cmd + e for e in exts]
    cwd_norm = pth.normcase(pth.normpath(cwd)) if cwd else None
    for entry in path_entries:
        entry = entry.strip().strip('"')
        if not entry or entry == ".":
            continue
        # Relative entries resolve against the cwd: skip them too.
        if not _absolute(entry):
            continue
        if cwd_norm and pth.normcase(pth.normpath(entry)) == cwd_norm:
            continue
        for name in names:
            cand = pth.join(entry, name)
            if isfile(cand):
                return pth.normpath(cand)
    return None


def resolve_executable(cmd: str) -> Optional[str]:
    """Absolute path for ``cmd`` on Windows, or ``None`` if not found safely."""
    tool = windows_system_tool(cmd)
    if tool is not None:
        return tool if os.path.isfile(tool) else None
    return safe_which(cmd)


def is_broken_symlink(path: str | os.PathLike) -> bool:
    """True if ``path`` is a symlink whose target does not exist."""
    return os.path.islink(path) and not os.path.exists(path)


# Directory names pruned when walking a home tree, to keep scans fast and to
# avoid descending into unrelated package/VCS trees.
_PRUNE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".cache", "Library",
    ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", "Photos Library.photoslibrary",
}


def walk_no_reparse(root: str | os.PathLike):
    """``os.walk`` (errors ignored) that on Windows never descends into a
    junction or other reparse point. Identical to ``os.walk`` elsewhere."""
    win = sys.platform == "win32"
    if win:
        from cleanix.core import safety as _safety
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        if win:
            dirnames[:] = [
                d for d in dirnames
                if not _safety.is_reparse_point(os.path.join(dirpath, d))
            ]
        yield dirpath, dirnames, filenames


def walk_pruned(root: str | os.PathLike, prune: Optional[set] = None):
    """os.walk a tree, skipping large/irrelevant subdirectories and errors."""
    default_prune = prune is None
    prune = prune if prune is not None else _PRUNE_DIRS
    # On Windows junctions are not symlinks, so os.path.islink misses them;
    # skip every reparse point to avoid loops such as ``Application Data``.
    from cleanix.core import platform as _plat

    win = _plat.is_windows()
    if win:
        from cleanix.core import safety as _safety

        if default_prune:
            # Windows-only: AppData holds app state, not user files. Kept out
            # of _PRUNE_DIRS so POSIX walks (e.g. a Wine prefix) are unchanged.
            prune = prune | {"AppData"}
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        if win:
            dirnames[:] = [
                d for d in dirnames
                if not _safety.is_reparse_point(os.path.join(dirpath, d))
            ]
        dirnames[:] = [
            d
            for d in dirnames
            if d not in prune and not os.path.islink(os.path.join(dirpath, d))
        ]
        yield dirpath, dirnames, filenames


def is_root() -> bool:
    if sys.platform == "win32":
        from cleanix.core import winenv

        return winenv.is_admin()
    return hasattr(os, "geteuid") and os.geteuid() == 0


def home() -> Path:
    """Home directory of the user currently being scanned (context-aware)."""
    from cleanix.core.context import current_user

    return current_user().home


def current_uid() -> Optional[int]:
    """uid of the user currently being scanned."""
    from cleanix.core.context import current_user

    return current_user().uid


def _xdg_dir(env_var: str, default_sub: str) -> Path:
    """Resolve an XDG dir for the current user.

    The invoker's own XDG_* environment is honored only for an unprivileged,
    single-user run. When sweeping multiple users (root), the standard default
    (``$HOME/<sub>``) is always used, since root's environment must not be
    projected onto other users' homes.
    """
    from cleanix.core.context import current_user

    user = current_user()
    if user.is_invoker and not is_root():
        val = os.environ.get(env_var)
        if val:
            return Path(val)
    return user.home / default_sub


def cache_dir() -> Path:
    return _xdg_dir("XDG_CACHE_HOME", ".cache")


def config_dir() -> Path:
    return _xdg_dir("XDG_CONFIG_HOME", ".config")


def data_dir() -> Path:
    return _xdg_dir("XDG_DATA_HOME", ".local/share")


def state_dir() -> Path:
    return _xdg_dir("XDG_STATE_HOME", ".local/state")


def expand(path: str | os.PathLike) -> Path:
    """Expand ``~``/vars against the *current* user's home (context-aware)."""
    from cleanix.core.context import current_user

    s = os.path.expandvars(str(path))
    if s == "~":
        return current_user().home
    if s.startswith("~/"):
        return current_user().home / s[2:]
    return Path(s)


def run_command(
    command: Sequence[str], timeout: int = 120
) -> tuple[int, str, str]:
    """Run a command, returning ``(returncode, stdout, stderr)``.

    Never raises on a non-zero exit; callers inspect the return code.
    On Windows ``command[0]`` is resolved to an absolute path first (see
    :func:`resolve_executable`) so the current directory is never searched.
    """
    if sys.platform == "win32" and command:
        exe = resolve_executable(str(command[0]))
        if exe is None:
            return 127, "", f"command not found: {command[0]}"
        command = [exe, *list(command)[1:]]
    try:
        proc = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {command[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"command timed out: {' '.join(command)}"
