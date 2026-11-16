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
    return shutil.which(cmd)


def has_any(*cmds: str) -> bool:
    return any(shutil.which(c) for c in cmds)


def is_broken_symlink(path: str | os.PathLike) -> bool:
    """True if ``path`` is a symlink whose target does not exist."""
    return os.path.islink(path) and not os.path.exists(path)


# Directory names pruned when walking a home tree, to keep scans fast and to
# avoid descending into unrelated package/VCS trees.
_PRUNE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".cache", "Library",
    ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", "Photos Library.photoslibrary",
    "AppData",
}


def walk_pruned(root: str | os.PathLike, prune: Optional[set] = None):
    """os.walk a tree, skipping large/irrelevant subdirectories and errors."""
    prune = prune if prune is not None else _PRUNE_DIRS
    # On Windows junctions are not symlinks, so os.path.islink misses them;
    # skip every reparse point to avoid loops such as ``Application Data``.
    from cleanix.core import platform as _plat

    win = _plat.is_windows()
    if win:
        from cleanix.core import safety as _safety
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
    """
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
