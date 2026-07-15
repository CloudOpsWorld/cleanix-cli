"""The :class:`Cleaner` abstract base class.

A cleaner knows how to *find* junk (``scan``) and describes itself with class
attributes. It never deletes anything directly — the engine owns removal so
that the safety guard and dry-run logic live in exactly one place.
"""

from __future__ import annotations

import abc
from pathlib import Path
from typing import Iterable, List, Optional

from cleanix.config import Config
from cleanix.core.context import get_target_users, use_user
from cleanix.core.models import CleanableItem, CleanerReport, ItemKind
from cleanix.core.platform import ALL, supports
from cleanix.core.utils import path_size

# Cleaner scope:
#   SCOPE_USER   — operates within a home directory; runs once per target user
#                  (all users when root, else just the invoker).
#   SCOPE_SYSTEM — operates on system-wide, absolute paths; runs once.
SCOPE_USER = "user"
SCOPE_SYSTEM = "system"


def _path_present(p: Path) -> bool:
    """True if ``p`` exists (or is a dangling symlink), never raising.

    ``Path.exists()`` does *not* swallow ``EPERM`` — on macOS a SIP-protected
    entry under ``/Library/Caches`` raises ``PermissionError`` — so a bare
    ``p.exists()`` in a cleaner would abort the whole scan. We treat any
    unreadable path as "not present" (we couldn't size or remove it anyway).
    """
    try:
        return p.exists() or p.is_symlink()
    except OSError:
        return False


class Cleaner(abc.ABC):
    """Base class for all cleaners.

    Subclasses set :attr:`id`, :attr:`name`, :attr:`description`,
    :attr:`requires_root`, and :attr:`platforms`, then implement
    :meth:`find_items`.
    """

    id: str = ""
    name: str = ""
    description: str = ""
    requires_root: bool = False
    # Platform tokens this cleaner applies to (see cleanix.core.platform).
    # Default: every platform.
    platforms: tuple = (ALL,)
    # Whether this cleaner is per-user (default) or system-wide.
    scope: str = SCOPE_USER
    # If False, the cleaner is excluded from a normal scan/clean and only runs
    # when explicitly requested via ``--only`` (e.g. the memory cleaners, whose
    # effect is transient and shouldn't happen on every run).
    default_enabled: bool = True

    def __init__(self, config: Config):
        self.config = config

    def supported(self) -> bool:
        """True if this cleaner applies to the current operating system."""
        return supports(self.platforms)

    # -- subclass hook -------------------------------------------------------
    @abc.abstractmethod
    def find_items(self) -> Iterable[CleanableItem]:
        """Yield the removable items this cleaner found. Read-only."""

    def available(self) -> Optional[str]:
        """Return ``None`` if the cleaner can run, else a skip reason.

        Override to declare tool/OS prerequisites (e.g. "apt not installed").
        """
        return None

    # -- helpers for subclasses ---------------------------------------------
    def path_item(
        self,
        path: str | Path,
        description: str,
        *,
        requires_root: Optional[bool] = None,
    ) -> Optional[CleanableItem]:
        """Build a PATH item for ``path`` if it exists and is non-empty."""
        p = Path(path)
        if not _path_present(p):
            return None
        size = path_size(p)
        return CleanableItem(
            cleaner_id=self.id,
            description=description,
            size=size,
            kind=ItemKind.PATH,
            path=str(p),
            requires_root=self.requires_root
            if requires_root is None
            else requires_root,
        )

    def report_item(
        self,
        path: str | Path,
        description: str,
        *,
        hint: str,
        requires_root: Optional[bool] = None,
    ) -> Optional[CleanableItem]:
        """Build a *report-only* PATH item (surfaced with size, never deleted)."""
        p = Path(path)
        if not _path_present(p):
            return None
        return CleanableItem(
            cleaner_id=self.id,
            description=description,
            size=path_size(p),
            kind=ItemKind.PATH,
            path=str(p),
            requires_root=self.requires_root
            if requires_root is None
            else requires_root,
            report_only=True,
            hint=hint,
        )

    def command_item(
        self,
        command: List[str],
        description: str,
        *,
        size: int = 0,
        requires_root: Optional[bool] = None,
    ) -> CleanableItem:
        """Build a COMMAND item."""
        return CleanableItem(
            cleaner_id=self.id,
            description=description,
            size=size,
            kind=ItemKind.COMMAND,
            command=command,
            requires_root=self.requires_root
            if requires_root is None
            else requires_root,
        )

    # -- engine entry point --------------------------------------------------
    def scan(self) -> CleanerReport:
        """Produce a report. Catches cleaner errors so one bad cleaner cannot
        abort the whole scan."""
        report = CleanerReport(
            cleaner_id=self.id, name=self.name, description=self.description
        )
        reason = self.available()
        if reason:
            report.skipped_reason = reason
            return report
        try:
            if self.scope == SCOPE_SYSTEM:
                report.items = [i for i in self.find_items() if i is not None]
            else:
                report.items = self._scan_all_users()
        except Exception as exc:  # noqa: BLE001 - defensive: never crash a scan
            report.skipped_reason = f"error while scanning: {exc}"
        return report

    def _scan_all_users(self) -> List[CleanableItem]:
        """Run a per-user cleaner once for each target user, de-duplicating so
        shared directories and identical commands are never offered twice.

        Command items are keyed by their argv: a per-user cleaner that yields a
        fixed command (e.g. ``brew cleanup``) would otherwise appear once per
        target user when running as root, yet the engine runs it only once."""
        items: List[CleanableItem] = []
        seen_paths: set = set()
        seen_commands: set = set()
        for user in get_target_users():
            with use_user(user):
                for item in self.find_items():
                    if item is None:
                        continue
                    if item.path is not None:
                        if item.path in seen_paths:
                            continue
                        seen_paths.add(item.path)
                    elif item.command is not None:
                        key = tuple(item.command)
                        if key in seen_commands:
                            continue
                        seen_commands.add(key)
                    items.append(item)
        return items
