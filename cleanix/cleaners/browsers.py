"""Browser HTTP/disk caches (Firefox, Chrome, Chromium).

Only *cache* directories are touched — never profiles, cookies, history, or
saved passwords.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Tuple

from cleanix.cleaners.base import Cleaner
from cleanix.core.models import CleanableItem
from cleanix.core.platform import XDG_PLATFORMS
from cleanix.core.utils import home, iter_children, path_size


class BrowserCacheCleaner(Cleaner):
    id = "browsers"
    safe_default = True
    name = "Browser caches"
    description = "Firefox/Chrome/Chromium on-disk HTTP caches"
    requires_root = False
    platforms = XDG_PLATFORMS

    def _firefox_caches(self) -> Iterable[Tuple[Path, str]]:
        # Firefox stores caches under ~/.cache/mozilla/firefox/<profile>/
        base = home() / ".cache" / "mozilla" / "firefox"
        for profile in iter_children(base):
            cache = profile / "cache2"
            if cache.exists():
                yield cache, f"Firefox cache: {profile.name}"

    def _chromium_caches(self) -> Iterable[Tuple[Path, str]]:
        roots = {
            "chrome": home() / ".config" / "google-chrome",
            "chromium": home() / ".config" / "chromium",
        }
        for name, root in roots.items():
            if not root.exists():
                continue
            for profile in iter_children(root):
                if not profile.is_dir():
                    continue
                for cache_name in ("Cache", "Code Cache", "GPUCache"):
                    cache = profile / cache_name
                    if cache.exists():
                        yield cache, f"{name} {cache_name}: {profile.name}"

    def find_items(self) -> Iterable[CleanableItem]:
        wanted = {b.lower() for b in self.config.browsers}
        sources: List[Tuple[Path, str]] = []
        if "firefox" in wanted:
            sources.extend(self._firefox_caches())
        if "chrome" in wanted:
            sources.extend(
                s for s in self._chromium_caches() if s[1].startswith("chrome ")
            )
        if "chromium" in wanted:
            sources.extend(
                s for s in self._chromium_caches() if s[1].startswith("chromium ")
            )

        for path, label in sources:
            if path_size(path) <= 0:
                continue
            item = self.path_item(path, label)
            if item:
                yield item
