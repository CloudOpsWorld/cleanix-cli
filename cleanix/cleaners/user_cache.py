"""Application caches under ``~/.cache`` plus any configured extras.

We deliberately skip a small allow-list of subdirectories whose loss is
annoying (fontconfig, which is cheap but slow to rebuild) and anything the
other cleaners already own (thumbnails, pip, browsers).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from cleanix.cleaners.base import Cleaner
from cleanix.core.models import CleanableItem
from cleanix.core.platform import XDG_PLATFORMS
from cleanix.core.utils import cache_dir, expand
from cleanix.core.utils import home, iter_children, modified_within

# ~/.cache subdirectories owned by a dedicated cleaner (so we don't offer them
# twice) or deliberately preserved (downloaded AI models). This cleaner is the
# catch-all for *everything else* under ~/.cache.
_SKIP = {
    # dedicated: thumbnails / fonts / pip / browsers
    "thumbnails", "fontconfig", "pip",
    "mozilla", "google-chrome", "chromium", "BraveSoftware", "vivaldi",
    "microsoft-edge", "opera",
    # dedicated: dev_caches
    "go-build", "ccache", "composer", "pypoetry", "pre-commit", "puppeteer",
    "ms-playwright", "uv", "Cypress", "electron", "node-gyp", "yarn",
    # dedicated: AI compile caches
    "torch_extensions", "vllm", "flashinfer", "tfhub_modules",
    # dedicated: AI clients (surgical) + preserved model downloads
    "huggingface", "lm-studio", "gpt4all", "torch", "chroma", "whisper",
    # dedicated: GPU shader caches
    "mesa_shader_cache", "mesa_shader_cache_db", "nvidia",
    "radv_builtin_shaders64",
    # dedicated: JetBrains
    "JetBrains",
}


class UserCacheCleaner(Cleaner):
    id = "user_cache"
    safe_default = True
    name = "User cache (~/.cache)"
    description = "Assorted application caches under ~/.cache"
    requires_root = False
    platforms = XDG_PLATFORMS

    def find_items(self) -> Iterable[CleanableItem]:
        cache = cache_dir()
        guard = self.config.cache_min_age_minutes
        if cache.exists():
            for child in iter_children(cache):
                if child.name in _SKIP:
                    continue
                # Skip anything being actively written (in-use guard). This
                # protects e.g. another program's growing scratch file.
                if modified_within(child, guard):
                    continue
                item = self.path_item(child, f"Cache: {child.name}")
                if item:
                    yield item

        for extra in self.config.extra_cache_dirs:
            p = expand(extra)
            item = self.path_item(p, f"Cache (extra): {p}")
            if item:
                yield item
