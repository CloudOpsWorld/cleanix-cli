"""npm / yarn caches under the user home."""

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


class NpmCacheCleaner(Cleaner):
    id = "npm_cache"
    name = "npm/yarn cache"
    description = "JavaScript package manager caches"
    requires_root = False
    platforms = (ALL, WINDOWS)

    def _candidates(self):
        h = home()
        if platform.is_windows():
            local = winenv.local_appdata()
            yield local / "npm-cache", "npm cache"
            yield local / "Yarn" / "Cache", "yarn cache"
            return
        cache = str(cache_dir())
        yield h / ".npm" / "_cacache", "npm cache"
        yield Path(cache) / "yarn", "yarn cache"
        yield h / ".cache" / "yarn", "yarn cache"

    def find_items(self) -> Iterable[CleanableItem]:
        seen = set()
        for path, label in self._candidates():
            if path in seen or not path.exists() or path_size(path) <= 0:
                continue
            seen.add(path)
            item = self.path_item(path, label)
            if item:
                yield item
