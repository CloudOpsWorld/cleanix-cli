"""Additional macOS leftovers beyond the core macOS cleaners."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Tuple

from cleanix.cleaners.base import Cleaner, SCOPE_SYSTEM
from cleanix.core.models import CleanableItem
from cleanix.core.platform import MACOS
from cleanix.core.utils import home, iter_children, path_size


class MacExtraCachesCleaner(Cleaner):
    id = "macos_extra"
    name = "macOS extra caches"
    description = "Saved app state, CocoaPods/Carthage caches, QuickLook"
    requires_root = False
    platforms = (MACOS,)

    def _candidates(self) -> Iterable[Tuple[Path, str]]:
        h = home()
        lib = h / "Library"
        yield lib / "Saved Application State", "Saved application state"
        yield lib / "Caches" / "CocoaPods", "CocoaPods cache"
        yield lib / "Caches" / "org.carthage.CarthageKit", "Carthage cache"
        yield lib / "Caches" / "com.apple.QuickLook.thumbnailcache", "QuickLook thumbnails"
        yield lib / "Caches" / "Homebrew", "Homebrew cache"
        yield lib / "Developer" / "CoreSimulator" / "Devices", "CoreSimulator devices"
        yield lib / "Containers" / "com.apple.mail" / "Data" / "Library" / "Mail Downloads", "Mail downloads"

    def find_items(self) -> Iterable[CleanableItem]:
        seen = set()
        for path, label in self._candidates():
            if path in seen or not path.exists() or path_size(path) <= 0:
                continue
            seen.add(path)
            item = self.path_item(path, label)
            if item:
                yield item


class MacContainerCacheCleaner(Cleaner):
    id = "macos_containers"
    name = "macOS sandboxed app caches"
    description = "Caches inside ~/Library/Containers and Group Containers"
    requires_root = False
    platforms = (MACOS,)

    def find_items(self) -> Iterable[CleanableItem]:
        lib = home() / "Library"
        from cleanix.core.utils import modified_within
        guard = self.config.cache_min_age_minutes
        for base in ("Containers", "Group Containers"):
            root = lib / base
            if not root.is_dir():
                continue
            for container in iter_children(root):
                cache = container / "Data" / "Library" / "Caches"
                if not cache.is_dir():
                    cache = container / "Library" / "Caches"
                if cache.is_dir():
                    for child in iter_children(cache):
                        if modified_within(child, guard):
                            continue
                        item = self.path_item(
                            child, f"{container.name}: {child.name}"
                        )
                        if item:
                            yield item


class MacSystemCacheCleaner(Cleaner):
    id = "macos_system_cache"
    name = "macOS system caches"
    description = "Regenerable caches under /Library/Caches"
    requires_root = True
    platforms = (MACOS,)
    scope = SCOPE_SYSTEM

    def find_items(self) -> Iterable[CleanableItem]:
        root = Path("/Library/Caches")
        if not root.is_dir():
            return
        for child in iter_children(root):
            item = self.path_item(child, f"/Library/Caches: {child.name}")
            if item:
                yield item


class MacFontCacheCleaner(Cleaner):
    id = "macos_font_cache"
    name = "macOS font caches"
    description = "Rebuildable font registration caches (atsutil)"
    requires_root = False
    platforms = (MACOS,)

    def find_items(self) -> Iterable[CleanableItem]:
        from cleanix.core.utils import which

        if which("atsutil"):
            yield self.command_item(
                ["atsutil", "databases", "-removeUser"],
                "Clear per-user font databases",
            )


class MacSleepImageReporter(Cleaner):
    id = "macos_sleepimage"
    name = "macOS sleep image"
    description = "Hibernation image (report only — recreated by the OS)"
    requires_root = True
    platforms = (MACOS,)
    scope = SCOPE_SYSTEM

    def find_items(self) -> Iterable[CleanableItem]:
        # /var is a symlink to /private/var on macOS, so both candidates resolve
        # to the same file — report it once, keyed by its canonical path.
        seen: set = set()
        for base in ("/private/var/vm/sleepimage", "/var/vm/sleepimage"):
            p = Path(base)
            if not p.exists():
                continue
            try:
                real = os.path.realpath(p)
            except OSError:
                real = str(p)
            if real in seen:
                continue
            seen.add(real)
            item = self.report_item(
                p, "macOS sleep/hibernation image",
                hint="managed by pmset; remove only if you understand hibernation impact",
            )
            if item:
                yield item
