"""Developer / language-toolchain caches.

These are all safely regenerable download/build caches. We deliberately avoid
directories that double as *installed* artifacts (``~/.m2/repository`` for
offline builds, installed gems, Go module source), touching only pure caches.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Tuple

from cleanix.cleaners.base import Cleaner
from cleanix.core import platform, winenv
from cleanix.core.models import CleanableItem
from cleanix.core.platform import ALL, WINDOWS
from cleanix.core.utils import home, path_size


class DevCacheCleaner(Cleaner):
    id = "dev_caches"
    safe_default = True
    name = "Developer caches"
    description = "Regenerable caches for cargo, go, gradle, ccache, composer…"
    requires_root = False
    platforms = (ALL, WINDOWS)

    def _candidates(self) -> Iterable[Tuple[Path, str]]:
        h = home()
        if platform.is_windows():
            # pip (local/pip/Cache) and npm (local/npm-cache) are owned by
            # their dedicated cleaners; only offer the rest here.
            local = winenv.local_appdata()
            yield local / "go-build", "Go build cache"
            yield local / "uv" / "cache", "uv (Python) cache"
            yield h / ".cargo" / "registry" / "cache", "Cargo registry cache"
            yield h / ".gradle" / "caches", "Gradle cache"
            yield h / ".cache" / "pre-commit", "pre-commit hook cache"
            return
        cache = h / ".cache"
        yield cache / "go-build", "Go build cache"
        yield h / ".cargo" / "registry" / "cache", "Cargo registry cache"
        yield h / ".cargo" / "registry" / "src", "Cargo registry sources"
        yield h / ".gradle" / "caches", "Gradle cache"
        yield cache / "ccache", "ccache"
        yield h / ".ccache", "ccache"
        yield cache / "composer", "Composer cache"
        yield h / ".composer" / "cache", "Composer cache"
        yield cache / "pypoetry" / "cache", "Poetry cache"
        yield cache / "pre-commit", "pre-commit hook cache"
        yield cache / "puppeteer", "Puppeteer browser cache"
        yield cache / "ms-playwright", "Playwright browser cache"
        yield h / ".dartServer", "Dart analysis cache"
        yield h / ".gradle" / "daemon", "Gradle daemon logs"
        yield cache / "uv", "uv (Python) cache"
        yield cache / "Cypress", "Cypress binary cache"
        yield cache / "electron", "Electron download cache"
        yield cache / "node-gyp", "node-gyp headers cache"
        # NOTE: model-download caches (huggingface, torch hub, gpt4all) are
        # intentionally handled by dedicated AI cleaners so we never wholesale
        # delete downloaded weights.

    def find_items(self) -> Iterable[CleanableItem]:
        seen = set()
        for path, label in self._candidates():
            if path in seen or not path.exists() or path_size(path) <= 0:
                continue
            seen.add(path)
            item = self.path_item(path, label)
            if item:
                yield item
