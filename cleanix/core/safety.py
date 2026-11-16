"""The last line of defense against deleting something important.

Every deletion in cleanix funnels through :func:`safe_rmtree` /
:func:`safe_unlink`, which refuse to act on protected paths. This is
intentionally paranoid: a cleaner bug should never be able to wipe ``/`` or a
user's home directory.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable

from cleanix.core import platform as _platform
from cleanix.core import safety_windows

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class UnsafePathError(Exception):
    """Raised when a delete target is protected or malformed."""


# User-configured extra protection (globs). Set once at startup from config.
_EXTRA_GLOBS: list = []


def set_protected_globs(globs) -> None:
    """Register additional never-delete globs from user config."""
    import os as _os

    global _EXTRA_GLOBS
    _EXTRA_GLOBS = [
        _os.path.expanduser(_os.path.expandvars(str(g))) for g in (globs or [])
    ]


def _matches_extra_glob(*candidates: "Path") -> bool:
    import fnmatch

    # User globs are written as literal paths, so test both the canonical form
    # (parent symlinks resolved) and the plain lexical abspath.
    strs = {str(c) for c in candidates}
    for pattern in _EXTRA_GLOBS:
        for s in strs:
            if fnmatch.fnmatch(s, pattern) or s == pattern:
                return True
    return False


def _canonical(p: str | os.PathLike) -> Path:
    """Absolute, normalized path with the FINAL component left un-dereferenced.

    Two deliberate departures from ``Path.resolve()``:

    * We resolve symlinks in the *parent* chain (so ``/tmp/evil/../etc`` or a
      symlinked parent cannot smuggle a protected target past the guard) but we
      do **not** follow a symlink in the final component. If the delete target
      *is* a symlink, callers must remove the link itself — never its target.
      Following the final link is exactly how a symlinked cache
      (``~/.cache/x -> ~/Documents``) could get its target wiped (CVE-class
      data loss).
    * We do **not** ``expanduser``/``expandvars`` here. Delete targets arrive
      from scans as concrete absolute paths; a file whose name legitimately
      contains ``$`` or a leading ``~`` must be treated literally, not rewritten
      to a different sibling. (User-supplied protected globs are expanded in
      :func:`set_protected_globs`, where expansion *is* intended.)
    """
    raw = Path(os.path.abspath(str(p)))
    if os.name == "nt":
        raw = Path(_clean_windows(str(raw)))
    try:
        parent = Path(os.path.realpath(str(raw.parent)))
    except OSError:
        parent = raw.parent
    if os.name != "nt":
        return parent / raw.name if raw.name else parent
    # Windows: first clean the path exactly like safety_windows.normalize() does
    # (NTFS stream suffixes, trailing dots/spaces), so that what we check is
    # what we delete; then expand 8.3 short names (DOCUME~1) so neither the
    # built-in guard nor user globs can be bypassed by a short spelling.
    parent = Path(_long_path(str(parent)))
    if not raw.name:
        return parent
    # GetLongPathNameW works on names only and never traverses a final link,
    # so it is safe to expand the final component even when it is a junction.
    return Path(_long_path(str(parent / raw.name)))


def _clean_windows(path: str) -> str:
    p = path.replace("/", "\\")
    if p[:4] in (_EXT, "\\\\.\\") and p[4:5].isalpha() and p[5:6] == ":":
        p = p[4:]
    drive, tail = os.path.splitdrive(p)
    comps = []
    for c in tail.split("\\"):
        if c not in (".", ".."):
            c = c.split(":", 1)[0].rstrip(". ")
        comps.append(c)
    # drop empty components produced by cleaning (keep the leading root sep)
    lead = "\\" if tail.startswith("\\") else ""
    body = "\\".join(c for c in comps if c)
    return os.path.normpath(drive + lead + body)


_EXT = "\\\\?\\"  # extended-length path prefix


def _long_path(path: str) -> str:
    """GetLongPathNameW expansion; returns ``path`` unchanged on any failure."""
    try:
        import ctypes

        fn = ctypes.windll.kernel32.GetLongPathNameW
        fn.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        fn.restype = ctypes.c_uint
        src = path
        if not src.startswith(_EXT):
            src = _EXT + src
        size = 1024
        for _ in range(2):
            buf = ctypes.create_unicode_buffer(size)
            n = fn(src, buf, size)
            if n == 0:
                return path
            if n < size:
                out = buf.value
                if out.startswith(_EXT) and not out.startswith(_EXT + "UNC"):
                    out = out[4:]
                return out
            size = n + 1
    except Exception:  # noqa: BLE001
        pass
    return path


# Absolute paths that must never be deleted, nor have their *contents* wiped as
# a whole. Cleaners may still delete files *inside* some of these (e.g. an
# individual file under /var/log), but never the directory itself.
_PROTECTED = {
    "/",
    # Linux / generic Unix
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
    "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/usr", "/opt",
    "/var", "/var/lib", "/var/log", "/var/db",
    "/home",
    # macOS
    "/System", "/Library", "/Applications", "/Users", "/cores", "/Volumes",
    "/private", "/private/etc", "/private/var", "/private/tmp",
    # BSD
    "/rescue", "/boot/kernel", "/usr/ports", "/usr/src", "/usr/obj",
    "/compat", "/net", "/export",
}


# Per-home subdirectories whose wholesale deletion would be catastrophic.
# Credentials/keys and the irreplaceable media dirs are here as defense in
# depth: even a buggy cleaner that yielded one of these as a whole-directory
# target must be refused.
_HOME_PROTECTED = (
    ".config", ".local", ".local/share", ".local/state",
    ".ssh", ".gnupg", ".password-store", ".mozilla",
    "Library", "Documents", "Desktop", "Downloads", "Pictures",
    "Music", "Videos", "Movies",
)


def _home_dirs() -> list:
    """Every home directory in scope (all target users, plus the process home)."""
    homes = []
    try:
        from cleanix.core.context import get_target_users

        homes.extend(u.home for u in get_target_users())
    except Exception:  # noqa: BLE001 - safety must never depend on context
        pass
    fallback = os.path.expanduser("~")
    if fallback and fallback != "~":
        homes.append(Path(fallback))
    return homes


def _protected_roots() -> set:
    roots = {Path(p) for p in _PROTECTED}
    for home in _home_dirs():
        try:
            home_path = Path(home).resolve()
        except OSError:
            continue
        roots.add(home_path)                 # never delete a $HOME itself
        for rel in _HOME_PROTECTED:
            roots.add(home_path / rel)
    return roots


def _win_canonical_dir(path: str) -> str:
    """realpath + 8.3 long-name expansion of a directory ("" on failure)."""
    try:
        real = os.path.realpath(path)
    except (OSError, ValueError):
        return ""
    return _long_path(real) if os.name == "nt" else real


def _windows_home_forms(homes) -> list:
    """Each home in its raw spelling AND its canonical (junction-resolved,
    long-name) spelling: the delete target is canonicalised, so a home reached
    through a junction must be protected under its real path too."""
    out = []
    for h in homes:
        raw = str(h)
        if raw and raw not in out:
            out.append(raw)
        canon = _win_canonical_dir(raw) if raw else ""
        if canon and canon not in out:
            out.append(canon)
    return out


def _windows_profiles() -> list:
    """Every directory directly under ``<SystemDrive>\\Users`` (raw and
    canonical spellings), enumerated at call time; [] on any error."""
    drives = []
    for d in (safety_windows._env(os.environ, "SystemDrive"), "C:"):
        if d.upper() not in (x.upper() for x in drives):
            drives.append(d)
    found = []
    for drive in drives:
        users = drive + "\\Users"
        try:
            with os.scandir(users) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False) or is_reparse_point(entry.path):
                            found.append(entry.path)
                    except OSError:
                        found.append(entry.path)
        except OSError:
            continue
    return _windows_home_forms(found)


def _lstat(path: str):
    return os.lstat(path)


def _entry_stat(entry):
    return entry.stat(follow_symlinks=False)


def _is_link_strict(path: str) -> bool:
    """Like is_reparse_point but fails closed: raises OSError if undeterminable.

    A missing path is simply not a link (False).
    """
    if os.name != "nt":
        return os.path.islink(path)     # POSIX: exactly the previous behaviour
    try:
        st = _lstat(path)
    except FileNotFoundError:
        return False
    return bool(getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT)         if os.name == "nt" else stat.S_ISLNK(st.st_mode)


def is_reparse_point(path: str | os.PathLike) -> bool:
    """True for a symlink or (on Windows) a junction/other reparse point.

    Never follows the final component. Missing or unreadable paths are False.
    """
    if os.name == "nt":
        try:
            attrs = os.lstat(str(path)).st_file_attributes
        except (OSError, AttributeError):
            return False
        return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)
    return os.path.islink(str(path))


def assert_safe_to_delete(target: str | os.PathLike) -> Path:
    """Return the resolved path if it is safe to delete, else raise.

    A path is unsafe when it *is* a protected root, or when it is an ancestor
    of one (deleting it would take the protected root with it).
    """
    resolved = _canonical(target)

    if str(resolved) == "" or resolved.parent == resolved:
        raise UnsafePathError(f"refusing to delete filesystem root: {resolved}")

    if _matches_extra_glob(resolved):
        raise UnsafePathError(
            f"refusing to delete {resolved}: matches a user protected_globs entry"
        )

    if _platform.is_windows():
        reason = safety_windows.violation(
            str(resolved), os.environ, _windows_home_forms(_home_dirs()),
            profiles=_windows_profiles(),
        )
        if reason:
            raise UnsafePathError(reason)
        return resolved

    protected = _protected_roots()
    if resolved in protected:
        raise UnsafePathError(f"refusing to delete protected path: {resolved}")

    # Refuse if the target is an ancestor of any protected root.
    for root in protected:
        try:
            root.relative_to(resolved)
        except ValueError:
            continue
        raise UnsafePathError(
            f"refusing to delete {resolved}: it contains protected path {root}"
        )

    return resolved


def is_safe_to_delete(target: str | os.PathLike) -> bool:
    try:
        assert_safe_to_delete(target)
        return True
    except UnsafePathError:
        return False


def _remove_link(path: str) -> None:
    """Remove a symlink/junction itself, never its target."""
    try:
        is_dir = os.path.isdir(path) or bool(
            os.lstat(path).st_file_attributes & stat.FILE_ATTRIBUTE_DIRECTORY
        )
    except (OSError, AttributeError):
        is_dir = False
    if os.name == "nt" and is_dir:
        os.rmdir(path)          # directory symlink or junction
    else:
        os.unlink(path)


def _clear_readonly(path: str) -> None:
    os.chmod(path, stat.S_IWRITE)


def _win_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except PermissionError:
        _clear_readonly(path)   # one retry; a truly locked file still raises
        os.unlink(path)


def _win_rmdir(path: str) -> None:
    try:
        os.rmdir(path)
    except PermissionError:
        _clear_readonly(path)
        os.rmdir(path)


def _win_rmtree(path: str) -> None:
    """Depth-first removal that never follows junctions/symlinks.

    Errors propagate (locked files are reported, not forced).
    """
    with os.scandir(path) as it:
        entries = list(it)
    for entry in entries:
        # Fail closed: if the reparse state is unknown, raise and never recurse.
        attrs = _entry_stat(entry).st_file_attributes
        if attrs & _FILE_ATTRIBUTE_REPARSE_POINT:
            _remove_link(entry.path)
        elif attrs & stat.FILE_ATTRIBUTE_DIRECTORY:
            _win_rmtree(entry.path)
        else:
            _win_unlink(entry.path)
    _win_rmdir(path)


def safe_unlink(target: str | os.PathLike) -> None:
    """Delete a single file/symlink after the safety check.

    A symlink/junction is removed as the *link* — its target is never touched.
    """
    resolved = _canonical(target)
    assert_safe_to_delete(resolved)
    if _is_link_strict(str(resolved)):
        _remove_link(str(resolved))
        return
    if resolved.is_dir():
        raise UnsafePathError(f"{resolved} is a directory; use safe_rmtree")
    if os.name == "nt":
        try:
            _win_unlink(str(resolved))
        except FileNotFoundError:
            pass
        return
    resolved.unlink(missing_ok=True)


def safe_rmtree(target: str | os.PathLike) -> None:
    """Recursively delete a directory (or file) after the safety check.

    Critically, a symlink or junction is removed as the *link itself* and its
    target is never followed — otherwise a symlinked cache pointing at real data
    would have its target wiped. This also makes broken-symlink removal work.
    On Windows, errors (e.g. a locked file) propagate as ``OSError``.
    """
    import shutil

    resolved = _canonical(target)
    assert_safe_to_delete(resolved)
    path = str(resolved)
    if _is_link_strict(path):
        _remove_link(path)
    elif os.name == "nt":
        if resolved.is_dir():
            _win_rmtree(path)
        elif resolved.exists():
            _win_unlink(path)
    elif resolved.is_file():
        resolved.unlink(missing_ok=True)
    elif resolved.is_dir():
        shutil.rmtree(resolved, ignore_errors=True)


def filter_safe(paths: Iterable[str | os.PathLike]) -> list[Path]:
    """Keep only the paths that pass the safety check."""
    return [_canonical(p) for p in paths if is_safe_to_delete(p)]
