"""Downloads-folder triage (report only).

``~/Downloads`` is a hard-protected directory: cleanix never auto-deletes
anything inside it. But it is where stale, bulky installers, disk images and
archives quietly accumulate — the classic "I downloaded that ISO once and
forgot" junk. This cleaner *surfaces* old + large downloads (with their size
and age) so the user can decide, and attaches a manual-removal hint. Items are
always ``report_only`` and therefore never deletable, so it never conflicts
with the safety guard that protects ``~/Downloads``.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterable

from cleanix.cleaners.base import Cleaner
from cleanix.core.models import CleanableItem
from cleanix.core.platform import ALL
from cleanix.core.utils import home, human_size, iter_children, older_than, path_size

# Extensions that are almost always disposable downloads once stale: OS/app
# installers, disk images and archives. Used only to enrich the description —
# any file/dir that is old + large enough still qualifies.
_INSTALLER_SUFFIXES = (
    ".iso", ".dmg", ".pkg", ".deb", ".rpm", ".zip", ".tar.gz", ".tgz",
    ".exe", ".msi", ".img",
)


def _looks_like_installer(name: str) -> bool:
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in _INSTALLER_SUFFIXES)


def _age_days(path: str | os.PathLike) -> int:
    """Whole days since ``path`` was last modified (0 on any error)."""
    try:
        mtime = os.lstat(path).st_mtime
    except OSError:
        return 0
    return max(0, int((time.time() - mtime) // 86400))


class DownloadsReporter(Cleaner):
    id = "downloads"
    name = "Stale downloads"
    description = "Old, large files in ~/Downloads (report only — never deleted)"
    requires_root = False
    platforms = (ALL,)

    def find_items(self) -> Iterable[CleanableItem]:
        downloads = home() / "Downloads"
        try:
            if not downloads.is_dir() or downloads.is_symlink():
                return
        except OSError:
            return

        stale_days = float(getattr(self.config, "downloads_stale_days", 60))
        min_bytes = float(getattr(self.config, "downloads_min_size_mb", 50)) * 1024 * 1024

        candidates = []
        for child in iter_children(downloads):
            try:
                if child.is_symlink():
                    continue
                if not older_than(child, stale_days):
                    continue
                size = path_size(child)
            except OSError:
                continue
            if size < min_bytes:
                continue
            candidates.append((size, child))

        # Largest first — the biggest reclaimable items lead.
        candidates.sort(key=lambda pair: pair[0], reverse=True)

        for size, child in candidates:
            name = child.name
            age = _age_days(child)
            label = "Stale installer/archive" if _looks_like_installer(name) else "Stale download"
            item = self.report_item(
                child,
                f"{label}: {name} ({human_size(size)}, {age} days old)",
                hint="review and remove manually if no longer needed",
            )
            if item:
                yield item
