"""Thumbnail cache (``~/.cache/thumbnails``)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from cleanix.cleaners.base import Cleaner
from cleanix.core.models import CleanableItem
from cleanix.core.platform import XDG_PLATFORMS
from cleanix.core.utils import cache_dir
from cleanix.core.utils import home, iter_children


class ThumbnailCleaner(Cleaner):
    id = "thumbnails"
    safe_default = True
    name = "Thumbnails"
    description = "Cached image/video thumbnails (regenerated on demand)"
    requires_root = False
    platforms = XDG_PLATFORMS

    def find_items(self) -> Iterable[CleanableItem]:
        cache = str(cache_dir())
        thumb_root = Path(cache) / "thumbnails"
        if not thumb_root.exists():
            return
        for sub in iter_children(thumb_root):  # normal, large, fail, ...
            item = self.path_item(sub, f"Thumbnails: {sub.name}")
            if item:
                yield item
