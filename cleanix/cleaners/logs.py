"""Log cleaners: rotated files under /var/log, and the systemd journal."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Iterator

from cleanix.cleaners.base import Cleaner, SCOPE_SYSTEM
from cleanix.core.models import CleanableItem
from cleanix.core.platform import LINUX
from cleanix.core.utils import older_than, path_size, which

# Rotated / compressed log suffixes that are safe to drop.
_ROTATED_SUFFIXES = (".gz", ".xz", ".bz2", ".old", ".1", ".2", ".3", ".4")


def _walk_files(root: Path) -> Iterator[Path]:
    """Every file below ``root`` WITHOUT descending into symlinked
    directories (``Path.rglob`` follows them before Python 3.13, so a
    symlink under /var/log could make a root scan list another tree)."""
    for dirpath, _dirnames, filenames in os.walk(str(root), followlinks=False):
        for name in filenames:
            yield Path(dirpath) / name


class RotatedLogCleaner(Cleaner):
    id = "logs"
    scope = SCOPE_SYSTEM
    name = "Rotated logs (/var/log)"
    description = "Old rotated/compressed log files"
    requires_root = True

    def find_items(self) -> Iterable[CleanableItem]:
        root = Path("/var/log")
        if not root.exists():
            return
        min_age = self.config.log_min_age_days
        for path in _walk_files(root):
            if not path.is_file() or path.is_symlink():
                continue
            name = path.name
            is_rotated = name.endswith(_ROTATED_SUFFIXES) or (
                # e.g. syslog.1, messages-20240101
                any(part.isdigit() for part in name.split(".")[-1:])
                and "." in name
            )
            if not is_rotated:
                continue
            if not older_than(path, min_age):
                continue
            item = self.path_item(path, f"Log: {path}")
            if item:
                yield item


class JournalCleaner(Cleaner):
    id = "journal"
    scope = SCOPE_SYSTEM
    name = "systemd journal"
    description = "Vacuum journald history above the configured size cap"
    requires_root = True
    platforms = (LINUX,)

    def available(self):
        if not which("journalctl"):
            return "journalctl not found"
        return None

    def find_items(self) -> Iterable[CleanableItem]:
        # Estimate current on-disk journal size.
        size = 0
        for base in ("/var/log/journal", "/run/log/journal"):
            p = Path(base)
            if p.exists():
                size += path_size(p)

        cap_bytes = self.config.journal_max_size_mb * 1024 * 1024
        reclaimable = max(size - cap_bytes, 0)
        if reclaimable <= 0:
            return

        yield self.command_item(
            [
                "journalctl",
                "--vacuum-size=%dM" % self.config.journal_max_size_mb,
            ],
            f"Vacuum journal to {self.config.journal_max_size_mb} MiB",
            size=reclaimable,
        )
