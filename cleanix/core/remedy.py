"""Remedy: how a report-only finding can be acted on, pinned to what was seen.

A :class:`Remedy` is attached to a report-only :class:`CleanableItem`. Its
``fingerprint`` records the lstat identity at scan time so a later action can
refuse to touch an entry that changed (or was swapped for a symlink) since.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:  # pragma: no cover - avoids a circular import with models
    from cleanix.core.models import CleanableItem

Fingerprint = Tuple[int, int, int, int]


class RemedyKind(str, Enum):
    """What kind of thing the remedy acts on."""

    PATH = "path"
    LAUNCH_JOB = "launch_job"
    SYSTEMD_UNIT = "systemd_unit"
    PKG_RECEIPT = "pkg_receipt"


@dataclass(frozen=True)
class Remedy:
    """An action offered for a report-only finding.

    ``fingerprint`` is (size, mtime_ns, inode, dev); zeros are allowed for
    non-path kinds. ``group`` is a duplicate-group id.
    """

    kind: RemedyKind
    fingerprint: Fingerprint
    group: Optional[str] = None
    extra: Tuple[Tuple[str, str], ...] = ()


def fingerprint_of(path: str) -> Optional[Fingerprint]:
    """lstat identity of ``path`` (no symlink following); None when missing."""
    try:
        st = os.lstat(path)
    except (OSError, ValueError):  # ValueError: embedded NUL; fail closed
        return None
    return (st.st_size, st.st_mtime_ns, st.st_ino, st.st_dev)


def path_remedy(path: str, group: Optional[str] = None) -> Optional[Remedy]:
    """A PATH remedy pinned to ``path``'s current lstat identity.

    None when the path cannot be fingerprinted (missing/unreadable), is a
    symlink, or its name holds a newline/CR/NUL: no safe remedy.
    """
    if any(c in os.path.basename(path) for c in ("\n", "\r", "\0")):
        return None
    fp = fingerprint_of(path)
    if fp is None or stat.S_ISLNK(os.lstat(path).st_mode):
        return None
    return Remedy(RemedyKind.PATH, fp, group=group)


_NO_FINGERPRINT: Fingerprint = (0, 0, 0, 0)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
CHANGED = "changed since scan"


def _lstat(path: str) -> os.stat_result:  # indirection: tests inject failures
    return os.lstat(path)


# ``Remedy.extra`` key of a PATH remedy whose entry IS a symbolic link (a
# broken unit link of a system-wide finding): the link's recorded target.
# Only such a remedy lets :func:`verify_path` accept a link, and only when
# the link still points at exactly that target.
LINK_TARGET = "link_target"


def link_target(remedy: Optional[Remedy]) -> Optional[str]:
    """The recorded target of a link PATH remedy, else None."""
    if remedy is None or remedy.kind is not RemedyKind.PATH:
        return None
    for key, value in remedy.extra:
        if key == LINK_TARGET:
            return value
    return None


def link_remedy(path: str) -> Optional[Remedy]:
    """A PATH remedy for the symbolic link ``path`` itself (never its
    target), pinned to its lstat identity and its target text. None when it
    is not a link, cannot be read, or its name or target holds a
    newline/CR/NUL."""
    if any(c in os.path.basename(path) for c in ("\n", "\r", "\0")):
        return None
    try:
        st = os.lstat(path)
        if not stat.S_ISLNK(st.st_mode):
            return None
        target = os.readlink(path)
    except (OSError, ValueError):
        return None
    if not target or any(c in target for c in ("\n", "\r", "\0")):
        return None
    fp = (st.st_size, st.st_mtime_ns, st.st_ino, st.st_dev)
    return Remedy(RemedyKind.PATH, fp, extra=((LINK_TARGET, target),))


def _readlink(path: str) -> str:  # indirection: tests inject failures
    return os.readlink(path)


def verify_path(path: str, fingerprint: object, *, allow_dir: bool = True,
                link: Optional[str] = None) -> Optional[str]:
    """Why ``path`` must not be acted on now, or None when it is still the
    entry fingerprinted at scan time.

    One lstat (never follows links): it must be a regular file (or, with
    ``allow_dir``, a directory), not a symlink or Windows reparse point, and
    its (size, mtime_ns, inode, dev) must equal ``fingerprint``. The
    ``(0, 0, 0, 0)`` placeholder is never a path identity. Any error reading
    it fails closed.

    Every reparse point is refused, including cloud-file placeholders
    (OneDrive "files on demand" carry FILE_ATTRIBUTE_REPARSE_POINT): such a
    finding is skipped fail-closed with "link or reparse point" (wording may
    need refining once seen on real machines).
    """
    try:
        fp = tuple(int(x) for x in fingerprint)  # type: ignore[union-attr]
    except (TypeError, ValueError):
        return "no usable fingerprint"
    if len(fp) != 4 or fp == _NO_FINGERPRINT:
        return "no usable fingerprint"
    try:
        st = _lstat(path)
    except (OSError, ValueError):  # missing, unreadable, embedded NUL
        return f"{CHANGED} (missing or unreadable)"
    mode = st.st_mode
    attrs = getattr(st, "st_file_attributes", 0) or 0
    if link is not None:
        # A link remedy: the entry must still be that very link (identity
        # and target text); it is removed as a link, never followed.
        if not stat.S_ISLNK(mode):
            return f"{CHANGED} (no longer a link)"
        if (st.st_size, st.st_mtime_ns, st.st_ino, st.st_dev) != fp:
            return CHANGED
        try:
            if _readlink(path) != link:
                return f"{CHANGED} (the link points elsewhere)"
        except (OSError, ValueError):
            return f"{CHANGED} (missing or unreadable)"
        return None
    if stat.S_ISLNK(mode) or attrs & _FILE_ATTRIBUTE_REPARSE_POINT:
        return f"{CHANGED} (now a link or reparse point)"
    if not (stat.S_ISREG(mode) or (allow_dir and stat.S_ISDIR(mode))):
        return f"{CHANGED} (not a regular file" + (" or folder)" if allow_dir else ")")
    if (st.st_size, st.st_mtime_ns, st.st_ino, st.st_dev) != fp:
        return CHANGED
    return None


def unchanged(item: "CleanableItem") -> bool:
    """True when the item's path still has the fingerprint stored in its remedy.

    Only RemedyKind.PATH remedies are path-fingerprinted; any other kind
    returns False (it must be verified by its own kind-specific check).
    """
    remedy = item.remedy
    if remedy is None or remedy.kind is not RemedyKind.PATH or not item.path:
        return False
    current = fingerprint_of(item.path)
    return current is not None and current == tuple(remedy.fingerprint)
