"""Stale files in ``/tmp`` and ``/var/tmp``.

Only files older than ``config.temp_min_age_days`` are offered, so files in
active use are left alone. We never offer the tmp directories themselves.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from cleanix.cleaners.base import Cleaner, SCOPE_SYSTEM
from cleanix.core.models import CleanableItem
from cleanix.core.utils import current_uid, iter_children, older_than


class TempFilesCleaner(Cleaner):
    id = "temp"
    safe_default = True
    scope = SCOPE_SYSTEM
    name = "Temp files (/tmp, /var/tmp)"
    description = "Stale temporary files older than the configured age"
    requires_root = False  # per-file; root items are flagged individually

    def find_items(self) -> Iterable[CleanableItem]:
        min_age = self.config.temp_min_age_days
        # Compare against the user being scanned (context-aware), not the
        # process: run as root for a user, another user's entries must still
        # count as "needs root" and the user's own as not.
        uid = current_uid() if hasattr(os, "getuid") else None

        for base in ("/tmp", "/var/tmp"):
            root = Path(base)
            if not root.exists():
                continue
            for child in iter_children(root):
                if not older_than(child, min_age):
                    continue
                # Entries not owned by the scanned user need root.
                try:
                    owned_by_us = uid is not None and child.lstat().st_uid == uid
                except OSError:
                    continue
                needs_root = not owned_by_us
                item = self.path_item(
                    child,
                    f"Temp: {child}",
                    requires_root=needs_root,
                )
                if item:
                    yield item
