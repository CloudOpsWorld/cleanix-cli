"""macOS-specific cleaners.

Covers the ~/Library cache/log layout, the macOS Trash, Homebrew/MacPorts,
Xcode's notoriously large developer caches, and diagnostic/crash reports.
All are gated to ``platforms = (MACOS,)``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Tuple

from cleanix.cleaners.base import Cleaner, SCOPE_SYSTEM
from cleanix.core.models import CleanableItem
from cleanix.core.platform import MACOS
from cleanix.core.utils import current_uid
from cleanix.core.utils import home, iter_children, modified_within, path_size, run_command, which


class MacUserCacheCleaner(Cleaner):
    id = "macos_caches"
    name = "macOS user caches"
    description = "Application caches under ~/Library/Caches"
    requires_root = False
    platforms = (MACOS,)

    def find_items(self) -> Iterable[CleanableItem]:
        base = home() / "Library" / "Caches"
        if not base.is_dir():
            return
        guard = self.config.cache_min_age_minutes
        for child in iter_children(base):
            if modified_within(child, guard):
                continue
            item = self.path_item(child, f"Cache: {child.name}")
            if item:
                yield item


class MacTrashCleaner(Cleaner):
    id = "macos_trash"
    name = "macOS Trash"
    description = "Files in ~/.Trash and per-volume .Trashes"
    requires_root = False
    platforms = (MACOS,)

    def find_items(self) -> Iterable[CleanableItem]:
        trashes: List[Path] = [home() / ".Trash"]
        uid = current_uid() or 0
        volumes = Path("/Volumes")
        if volumes.is_dir():
            for vol in iter_children(volumes):
                trashes.append(vol / ".Trashes" / str(uid))
        for trash in trashes:
            for child in iter_children(trash):
                item = self.path_item(child, f"Trash: {child.name}")
                if item:
                    yield item


class MacDiagnosticsCleaner(Cleaner):
    id = "macos_diagnostics"
    name = "macOS logs & crash reports"
    description = "Diagnostic reports and logs under ~/Library/Logs"
    requires_root = False
    platforms = (MACOS,)

    def find_items(self) -> Iterable[CleanableItem]:
        targets = [
            home() / "Library" / "Logs" / "DiagnosticReports",
            home() / "Library" / "Logs",
            home() / "Library" / "Application Support" / "CrashReporter",
        ]
        seen = set()
        for base in targets:
            if not base.is_dir():
                continue
            for child in iter_children(base):
                if str(child) in seen:
                    continue
                seen.add(str(child))
                item = self.path_item(child, f"Log/report: {child.name}")
                if item:
                    yield item


class HomebrewCleaner(Cleaner):
    id = "homebrew"
    name = "Homebrew cleanup"
    description = "Old formula versions and download cache"
    requires_root = False
    platforms = (MACOS,)

    def available(self):
        if not which("brew"):
            return "brew not found"
        # Homebrew hard-refuses to run as root ("Running Homebrew as root is
        # extremely dangerous"), so skip cleanly instead of emitting a command
        # that will only error at execute time (e.g. under `sudo cleanix`).
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return "skipped as root (Homebrew must run as the owning user)"
        return None

    def find_items(self) -> Iterable[CleanableItem]:
        size = 0
        code, out, _err = run_command(["brew", "--cache"], timeout=20)
        if code == 0 and out.strip():
            cache = Path(out.strip())
            if cache.exists():
                size = path_size(cache)
        yield self.command_item(
            ["brew", "cleanup", "--prune=all", "-s"],
            "Remove old versions and scrub the Homebrew download cache",
            size=size,
        )


class MacPortsCleaner(Cleaner):
    id = "macports"
    scope = SCOPE_SYSTEM
    name = "MacPorts cleanup"
    description = "Inactive ports and build leftovers"
    requires_root = True
    platforms = (MACOS,)

    def available(self):
        if not which("port"):
            return "port not found"
        return None

    def find_items(self) -> Iterable[CleanableItem]:
        yield self.command_item(
            ["port", "-q", "clean", "--all", "installed"],
            "Clean build/distfile leftovers for installed ports",
        )
        yield self.command_item(
            ["port", "-q", "uninstall", "inactive"],
            "Uninstall inactive (superseded) port versions",
        )


class XcodeCleaner(Cleaner):
    id = "xcode"
    name = "Xcode developer caches"
    description = "DerivedData, Archives, device support, simulator caches"
    requires_root = False
    platforms = (MACOS,)

    def _paths(self) -> Iterable[Tuple[Path, str]]:
        dev = home() / "Library" / "Developer"
        yield dev / "Xcode" / "DerivedData", "Xcode DerivedData"
        yield dev / "Xcode" / "Archives", "Xcode Archives"
        yield dev / "Xcode" / "iOS DeviceSupport", "iOS DeviceSupport"
        yield dev / "Xcode" / "watchOS DeviceSupport", "watchOS DeviceSupport"
        yield dev / "Xcode" / "tvOS DeviceSupport", "tvOS DeviceSupport"
        yield dev / "CoreSimulator" / "Caches", "CoreSimulator caches"
        yield home() / "Library" / "Caches" / "com.apple.dt.Xcode", "Xcode cache"

    def find_items(self) -> Iterable[CleanableItem]:
        for path, label in self._paths():
            if path.exists() and path_size(path) > 0:
                item = self.path_item(path, label)
                if item:
                    yield item
        # Unavailable simulators (deleted OS runtimes) can waste many GB, but
        # `simctl` ships only with full Xcode — not the Command Line Tools — so
        # confirm it resolves before offering (else xcrun errors "unable to
        # find utility simctl").
        if which("xcrun"):
            code, _out, _err = run_command(
                ["xcrun", "--find", "simctl"], timeout=15
            )
            if code == 0:
                yield self.command_item(
                    ["xcrun", "simctl", "delete", "unavailable"],
                    "Delete unavailable/obsolete iOS simulators",
                )
