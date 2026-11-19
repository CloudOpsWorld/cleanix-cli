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
