"""Additional system-wide leftovers: /var/cache, /var/backups, crash spools."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from cleanix.cleaners.base import Cleaner, SCOPE_SYSTEM
from cleanix.core.models import CleanableItem
from cleanix.core.platform import LINUX
from cleanix.core.utils import is_trusted_system_dir, iter_children, older_than


class SystemCacheCleaner(Cleaner):
    id = "system_cache"
    name = "System caches (/var/cache)"
    description = "Regenerable PackageKit/man/fontconfig/cups caches"
    requires_root = True
    platforms = (LINUX,)
    scope = SCOPE_SYSTEM

    # Regenerable /var/cache subdirs. Package-manager caches (dnf/apt/pacman…)
    # are owned by their dedicated cleaners and intentionally excluded here.
    _SAFE = (
        "PackageKit",
        "man",
        "fontconfig",
        "cups",
        "fwupd",
        "app-info",
        "abrt-di",
    )

    def find_items(self) -> Iterable[CleanableItem]:
        root = Path("/var/cache")
        if not root.is_dir():
            return
        for name in self._SAFE:
            target = root / name
            if target.is_dir():
                for child in iter_children(target):
                    item = self.path_item(child, f"/var/cache/{name}: {child.name}")
                    if item:
                        yield item


class VarBackupsCleaner(Cleaner):
    id = "var_backups"
    name = "Debian /var/backups"
    description = "Rotated dpkg/apt status backups"
    requires_root = True
    platforms = (LINUX,)
    scope = SCOPE_SYSTEM

    def find_items(self) -> Iterable[CleanableItem]:
        root = Path("/var/backups")
        if not root.is_dir():
            return
        # These are regenerated automatically; keep only very recent ones.
        for child in iter_children(root):
            if child.is_file() and (
                child.suffix == ".gz" or child.name[-1:].isdigit()
            ):
                if older_than(child, 7):
                    item = self.path_item(child, f"Backup: {child.name}")
                    if item:
                        yield item


class CrashSpoolCleaner(Cleaner):
    id = "crash_spool"
    name = "ABRT/apport crash spool"
    description = "Queued crash reports under /var/spool/abrt and /var/tmp/abrt"
    requires_root = True
    platforms = (LINUX,)
    scope = SCOPE_SYSTEM

    BASES = ("/var/spool/abrt", "/var/tmp/abrt", "/var/spool/apport")

    def find_items(self) -> Iterable[CleanableItem]:
        for base in self.BASES:
            root = Path(base)
            # /var/tmp is world-writable: a user can create /var/tmp/abrt as a
            # symlink (e.g. to /etc). Only list a real, root-owned directory.
            if not is_trusted_system_dir(root):
                continue
            for child in iter_children(root):
                if not older_than(child, 0.02):  # ~30 min, may be mid-write
                    continue
                item = self.path_item(child, f"Crash spool: {child.name}")
                if item:
                    yield item


class OfflineUpdateCleaner(Cleaner):
    id = "offline_updates"
    name = "Downloaded offline updates"
    description = "Packages staged for offline system upgrades"
    requires_root = True
    platforms = (LINUX,)
    scope = SCOPE_SYSTEM

    def find_items(self) -> Iterable[CleanableItem]:
        for base in (
            "/var/lib/dnf/system-upgrade",
            "/var/cache/PackageKit/downloads",
            "/var/lib/PackageKit/prepared-update",
        ):
            root = Path(base)
            if root.exists():
                item = self.path_item(root, f"Offline update payload: {base}")
                if item:
                    yield item
