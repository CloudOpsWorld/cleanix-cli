"""pip's download/wheel cache (``~/.cache/pip``)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from cleanix.cleaners.base import Cleaner
from cleanix.core import platform, winenv
from cleanix.core.models import CleanableItem
from cleanix.core.platform import ALL, WINDOWS
from cleanix.core.utils import cache_dir
from cleanix.core.utils import home, path_size


class PipCacheCleaner(Cleaner):
    id = "pip_cache"
    safe_default = True
    name = "pip cache"
    description = "Cached wheels and downloads under ~/.cache/pip"
    requires_root = False
    platforms = (ALL, WINDOWS)

    def find_items(self) -> Iterable[CleanableItem]:
        if platform.is_windows():
            pip_dir = winenv.local_appdata() / "pip" / "Cache"
        else:
            cache = str(cache_dir())
            pip_dir = Path(cache) / "pip"
        if pip_dir.exists() and path_size(pip_dir) > 0:
            item = self.path_item(pip_dir, "pip download/wheel cache")
            if item:
                yield item
