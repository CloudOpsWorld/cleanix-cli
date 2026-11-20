"""Mount-aware, honest removal for the elevated helper's findings action.

Used ONLY in root mode (``actions.act(allow_root=True)``); the normal
CLI/GUI deletion (``safety.safe_rmtree``) is unchanged.

* :func:`mount_problem` refuses an item that is itself a mount point or has
  any mount at or below it. Linux: ``/proc/self/mountinfo`` (mount-point
  field octal-unescaped); an unreadable table refuses (fail closed).
  Elsewhere (macOS) the mount table is not read: a directory is refused for
  permanent removal (only the rename into the quarantine is allowed, which
  never deletes through a mount), and any item whose ``st_dev`` differs from
  its parent's is refused as a mount point.
* :func:`remove` deletes permanently without ignoring errors: links are
  never followed (``shutil.rmtree`` must be the fd-based, symlink-attack
  resistant implementation, else it refuses), a directory tree with any
  entry on another device is refused before anything is deleted, and a
  partial failure is reported as not removed with the bytes really freed.
"""

from __future__ import annotations

import os
import posixpath
import shutil
import stat
import sys
from typing import List, Optional, Tuple

MOUNTINFO = "/proc/self/mountinfo"


def _read_mountinfo() -> Optional[str]:
    """The raw mount table (indirection: tests inject one). None if unreadable."""
    try:
        with open(MOUNTINFO, "rb") as fh:
            return fh.read(16 * 1024 * 1024).decode("utf-8", "surrogateescape")
    except OSError:
        return None


def _unescape(field: str) -> str:
    r"""Undo the kernel's octal escaping (``\040`` space, ``\011`` tab,
    ``\012`` newline, ``\134`` backslash)."""
    out = []
    i = 0
    while i < len(field):
        c = field[i]
        if (c == "\\" and len(field) - i >= 4
                and all(ch in "01234567" for ch in field[i + 1:i + 4])):
            out.append(chr(int(field[i + 1:i + 4], 8)))
            i += 4
            continue
        out.append(c)
        i += 1
    return "".join(out)


def parse_mountinfo(text: str) -> Optional[List[str]]:
    """Mount points (field 5) of a mountinfo text; None if any line is malformed."""
    mounts = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split(" ")
        if len(fields) < 6 or not fields[4].startswith("/"):
            return None
        mounts.append(posixpath.normpath(_unescape(fields[4])))
    return mounts


def _linux() -> bool:
    return sys.platform.startswith("linux")


def _st_dev_problem(path: str) -> Optional[str]:
    try:
        st = os.lstat(path)
        parent = os.lstat(os.path.dirname(path) or "/")
    except OSError:
        return "it cannot be inspected"
    if st.st_dev != parent.st_dev:
        return "it is a mount point"
    return None


def mount_problem(path: str, *, permanent: bool) -> Optional[str]:
    """Why ``path`` must not be removed as root because of mounts, or None."""
    path = os.path.normpath(os.path.abspath(path))
    why = _st_dev_problem(path)
    if why:
        return why
    if _linux():
        text = _read_mountinfo()
        mounts = parse_mountinfo(text) if text is not None else None
        if mounts is None:
            return "the mount table could not be read"
        prefix = path.rstrip("/") + "/"
        for m in mounts:
            if m == path:
                return "it is a mount point"
            if m.startswith(prefix):
                return "a filesystem is mounted inside it"
        return None
    if permanent:
        try:
            is_dir = stat.S_ISDIR(os.lstat(path).st_mode)
        except OSError:
            return "it cannot be inspected"
        if is_dir:
            return ("folders are not deleted permanently with administrator rights "
                    "on this system (mounted filesystems inside cannot be ruled "
                    "out); move it to the quarantine instead")
    return None


def _tree_size_and_devs(path: str, dev: int) -> Tuple[int, Optional[str]]:
    """Allocated size of the tree (lstat, links not followed) and why it is
    refused (an entry on another device or an unreadable folder)."""
    total = 0
    stack = [path]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError:
            return total, f"{d} cannot be listed"
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                return total, f"{e.path} cannot be inspected"
            if st.st_dev != dev:
                return total, f"{e.path} is on another filesystem"
            total += st.st_size
            if stat.S_ISDIR(st.st_mode):
                stack.append(e.path)
    return total, None


def _size(path: str) -> int:
    try:
        st = os.lstat(path)
    except OSError:
        return 0
    if not stat.S_ISDIR(st.st_mode):
        return st.st_size
    total, _why = _tree_size_and_devs(path, st.st_dev)
    return total + st.st_size


def remove(path: str) -> Tuple[bool, int, Optional[str]]:
    """Permanently remove ``path`` as root: ``(removed, freed, error)``."""
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        return False, 0, ("not removed: this system's recursive delete is not safe "
                          "against symbolic-link attacks")
    try:
        st = os.lstat(path)
    except OSError as exc:
        return False, 0, f"not removed: {exc.strerror or type(exc).__name__}"
    if not stat.S_ISDIR(st.st_mode):
        try:
            os.unlink(path)
        except OSError as exc:
            return False, 0, f"not removed: {exc.strerror or type(exc).__name__}"
        return True, st.st_size, None
    inner, why = _tree_size_and_devs(path, st.st_dev)
    if why:
        return False, 0, f"not removed: {why}"
    before = inner + st.st_size
    failures: List[str] = []

    def failed(_func, failed_path, _info) -> None:
        failures.append(str(failed_path))

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=failed)
    else:  # pragma: no cover - exercised on 3.8-3.11
        shutil.rmtree(path, onerror=failed)
    if failures or os.path.lexists(path):
        n = len(set(failures)) or 1
        freed = max(0, before - _size(path))
        return False, freed, f"partially removed: {n} entries could not be removed"
    return True, before, None
