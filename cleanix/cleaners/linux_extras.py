"""Linux-specific leftovers: crash dumps and package-update config residue."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from cleanix.cleaners.base import Cleaner, SCOPE_SYSTEM
from cleanix.core.models import CleanableItem
from cleanix.core.platform import LINUX
from cleanix.core.utils import home, is_trusted_system_dir, iter_children, older_than

# Files a package manager leaves next to config it couldn't safely overwrite.
# Removing these discards the *packaged* copy; your edited config is untouched.
_LEFTOVER_SUFFIXES = (
    ".rpmnew", ".rpmsave", ".rpmorig",     # RPM
    ".pacnew", ".pacsave", ".pacorig",     # pacman
    ".dpkg-old", ".dpkg-dist", ".dpkg-new", ".dpkg-bak",  # dpkg
    ".ucf-old", ".ucf-dist", ".ucf-new",   # ucf (Debian)
)
LEFTOVER_SUFFIXES = _LEFTOVER_SUFFIXES  # public alias for other modules


class ConfigLeftoverCleaner(Cleaner):
    id = "config_leftovers"
    scope = SCOPE_SYSTEM
    name = "Package-update config residue"
    description = (
        "Leftover .rpmnew/.pacnew/.dpkg-old files from package upgrades"
    )
    requires_root = True
    platforms = (LINUX,)

    def available(self):
        if not self.config.remove_config_leftovers:
            return "disabled in config (remove_config_leftovers=false)"
        return None

    def find_items(self) -> Iterable[CleanableItem]:
        for base in ("/etc", "/usr/etc", "/boot"):
            root = Path(base)
            if not root.exists():
                continue
            for dirpath, dirnames, files in os.walk(root, onerror=lambda e: None):
                dirnames[:] = [
                    d
                    for d in dirnames
                    if not os.path.islink(os.path.join(dirpath, d))
                ]
                for name in files:
                    if name.endswith(_LEFTOVER_SUFFIXES):
                        p = os.path.join(dirpath, name)
                        item = self.path_item(p, f"Config residue: {p}")
                        if item:
                            yield item


class CrashReportCleaner(Cleaner):
    id = "crash_reports"
    scope = SCOPE_SYSTEM
    name = "Crash reports"
    description = "Application crash dumps under /var/crash"
    requires_root = True
    platforms = (LINUX,)

    BASES = ("/var/crash", "/var/lib/apport/coredump")

    def find_items(self) -> Iterable[CleanableItem]:
        for base in self.BASES:
            root = Path(base)
            # /var/crash is world-writable (sticky): only list a real,
            # root-owned directory, never a planted symlink.
            if not is_trusted_system_dir(root):
                continue
            for child in iter_children(root):
                # Leave very fresh reports in case they are being written.
                if not older_than(child, 0.02):  # ~30 minutes
                    continue
                item = self.path_item(child, f"Crash report: {child.name}")
                if item:
                    yield item
