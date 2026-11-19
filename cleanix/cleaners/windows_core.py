"""Windows core cleaners: temp files, thumbnail/icon caches, error reports,
and the Recycle Bin.

Cleaners yield *children* of directories, never the directories themselves.
"""

from __future__ import annotations

from typing import Iterable

from cleanix.cleaners.base import Cleaner, SCOPE_SYSTEM, SCOPE_USER
from cleanix.core import winenv
from cleanix.core.models import CleanableItem
from cleanix.core.platform import WINDOWS
from cleanix.core.utils import iter_children, modified_within, older_than

# Owned by the Windows package-cache cleaner.
_PACKAGE_DIRS = {"winget", "chocolatey"}


class WinTempCleaner(Cleaner):
    id = "win_temp"
    safe_default = True
    name = "Temp files (%TEMP%)"
    description = "Stale files in the user temp folder older than the configured age"
    platforms = (WINDOWS,)
    scope = SCOPE_USER

    def find_items(self) -> Iterable[CleanableItem]:
        for child in iter_children(winenv.user_temp()):
            if child.name.lower() in _PACKAGE_DIRS:
                continue
            if not older_than(child, self.config.temp_min_age_days):
                continue
            if modified_within(child, self.config.cache_min_age_minutes):
                continue
            item = self.path_item(child, f"Temp: {child.name}")
            if item:
                yield item


class WinThumbnailCleaner(Cleaner):
    id = "win_thumbnails"
    safe_default = True
    name = "Thumbnail and icon caches"
    description = "Explorer thumbnail and icon cache databases (rebuilt automatically)"
    platforms = (WINDOWS,)
    scope = SCOPE_USER

    def find_items(self) -> Iterable[CleanableItem]:
        local = winenv.local_appdata()
        explorer = local / "Microsoft" / "Windows" / "Explorer"
        for child in iter_children(explorer):
            name = child.name.lower()
            if name.endswith(".db") and name.startswith(("thumbcache_", "iconcache_")):
                item = self.path_item(child, f"Thumbnail cache: {child.name}")
                if item:
                    yield item
        item = self.path_item(local / "IconCache.db", "Icon cache: IconCache.db")
        if item:
            yield item


class WinErrorReportingCleaner(Cleaner):
    id = "win_error_reports"
    safe_default = True
    name = "Error reports and crash dumps"
    description = "Windows Error Reporting data and user crash dumps"
    platforms = (WINDOWS,)
    scope = SCOPE_USER

    def find_items(self) -> Iterable[CleanableItem]:
        local = winenv.local_appdata()
        for base, label in (
            (local / "Microsoft" / "Windows" / "WER", "Error report"),
            (local / "CrashDumps", "Crash dump"),
        ):
            for child in iter_children(base):
                item = self.path_item(child, f"{label}: {child.name}")
                if item:
                    yield item


class WinRecycleBinCleaner(Cleaner):
    id = "win_recycle_bin"
    name = "Recycle Bin"
    description = "Files sitting in the Recycle Bin on all drives"
    platforms = (WINDOWS,)
    scope = SCOPE_SYSTEM
    requires_root = False

    def find_items(self) -> Iterable[CleanableItem]:
        size = winenv.recycle_bin_size()
        if size > 0:
            yield self.command_item(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Clear-RecycleBin -Force -ErrorAction SilentlyContinue",
                ],
                "Empty the Recycle Bin",
                size=size,
                requires_root=False,
            )
