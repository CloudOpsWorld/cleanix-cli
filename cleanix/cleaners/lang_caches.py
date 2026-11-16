"""Language / toolchain download & module caches.

These are re-downloadable package caches (distinct from the build caches in
``dev_caches``). Clearing them just forces a re-download next build.

"Offline repository" caches (Maven, Ivy, sbt, Coursier, NuGet, RubyGems) are
gated behind ``include_offline_repos`` because removing them can break offline
builds and trigger very large re-downloads.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Tuple

from cleanix.cleaners.base import Cleaner
from cleanix.core.models import CleanableItem
from cleanix.core.utils import home, path_size


class LangPackageCacheCleaner(Cleaner):
    id = "lang_caches"
    safe_default = True
    name = "Language package caches"
    description = "Go/Rust/JS/.NET/etc. re-downloadable module & package caches"
    requires_root = False

    def _always(self) -> Iterable[Tuple[Path, str]]:
        h = home()
        cache = h / ".cache"
        yield h / "go" / "pkg" / "mod" / "cache" / "download", "Go module download cache"
        yield h / ".rustup" / "downloads", "rustup downloads"
        yield h / ".rustup" / "tmp", "rustup temp"
        yield cache / "deno", "Deno cache"
        yield h / ".deno", "Deno cache"
        yield h / ".bun" / "install" / "cache", "Bun install cache"
        yield h / ".nvm" / ".cache", "nvm cache"
        yield h / ".local" / "share" / "pnpm" / "store", "pnpm store"
        yield h / ".pnpm-store", "pnpm store"
        yield h / ".android" / "cache", "Android SDK cache"
        yield h / ".android" / "build-cache", "Android build cache"
        yield h / ".gradle" / "wrapper" / "dists", "Gradle wrapper distributions"
        yield h / ".stack" / "pantry", "Haskell Stack pantry cache"
        yield h / ".pub-cache", "Dart/Flutter pub cache"
        yield h / ".cache" / "flutter", "Flutter engine cache"
        yield h / ".cargo" / "registry" / "index", "Cargo registry index"

    def _offline_repos(self) -> Iterable[Tuple[Path, str]]:
        h = home()
        yield h / ".m2" / "repository", "Maven local repository"
        yield h / ".ivy2" / "cache", "Ivy cache"
        yield h / ".sbt", "sbt cache"
        yield h / ".coursier" / "cache", "Coursier cache"
        yield h / ".cache" / "coursier", "Coursier cache"
        yield h / ".nuget" / "packages", "NuGet package cache"
        yield h / ".gem", "RubyGems cache"
        yield h / ".bundle" / "cache", "Bundler cache"

    def find_items(self) -> Iterable[CleanableItem]:
        candidates: List[Tuple[Path, str]] = list(self._always())
        if self.config.include_offline_repos:
            candidates += list(self._offline_repos())

        seen = set()
        for path, label in candidates:
            if path in seen or not path.exists() or path_size(path) <= 0:
                continue
            seen.add(path)
            item = self.path_item(path, label)
            if item:
                yield item
