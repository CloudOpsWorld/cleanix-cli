"""The last line of defense against deleting something important.

Every deletion in cleanix funnels through :func:`safe_rmtree` /
:func:`safe_unlink`, which refuse to act on protected paths. This is
intentionally paranoid: a cleaner bug should never be able to wipe ``/`` or a
user's home directory.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable


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
    try:
        parent = Path(os.path.realpath(str(raw.parent)))
    except OSError:
        parent = raw.parent
    return parent / raw.name if raw.name else parent


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


def assert_safe_to_delete(target: str | os.PathLike) -> Path:
    """Return the resolved path if it is safe to delete, else raise.

    A path is unsafe when it *is* a protected root, or when it is an ancestor
    of one (deleting it would take the protected root with it).
    """
    resolved = _canonical(target)

    if str(resolved) in ("", "/"):
        raise UnsafePathError(f"refusing to delete filesystem root: {resolved}")

    if _matches_extra_glob(resolved):
        raise UnsafePathError(
            f"refusing to delete {resolved}: matches a user protected_globs entry"
        )

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


def safe_unlink(target: str | os.PathLike) -> None:
    """Delete a single file/symlink after the safety check.

    A symlink is unlinked as the *link* — its target is never touched.
    """
    resolved = _canonical(target)
    assert_safe_to_delete(resolved)
    if os.path.islink(str(resolved)):
        os.unlink(str(resolved))
        return
    if resolved.is_dir():
        raise UnsafePathError(f"{resolved} is a directory; use safe_rmtree")
    resolved.unlink(missing_ok=True)


def safe_rmtree(target: str | os.PathLike) -> None:
    """Recursively delete a directory (or file) after the safety check.

    Critically, a symlink is removed as the *link itself* and its target is
    never followed — otherwise a symlinked cache pointing at real data (or a
    planted ``/tmp/x -> /etc/shadow``) would have its target wiped. This also
    makes broken-symlink removal work: ``os.path.islink`` is true for a dangling
    link even though ``is_file``/``is_dir`` are not.
    """
    import shutil

    resolved = _canonical(target)
    assert_safe_to_delete(resolved)
    if os.path.islink(str(resolved)):
        os.unlink(str(resolved))
    elif resolved.is_file():
        resolved.unlink(missing_ok=True)
    elif resolved.is_dir():
        shutil.rmtree(resolved, ignore_errors=True)


def filter_safe(paths: Iterable[str | os.PathLike]) -> list[Path]:
    """Keep only the paths that pass the safety check."""
    return [_canonical(p) for p in paths if is_safe_to_delete(p)]
