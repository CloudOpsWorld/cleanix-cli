"""Dataclasses shared across cleanix.

The scan phase produces :class:`CleanableItem` objects grouped into a
:class:`CleanerReport` per cleaner. The clean phase turns each item into a
:class:`CleanOutcome`. Nothing here performs I/O — that keeps the data model
easy to serialize (for JSON reports and scheduled runs) and easy to test.
"""

from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Sequence


class ItemKind(str, Enum):
    """How an item is removed."""

    PATH = "path"          # a file or directory to delete
    COMMAND = "command"    # an external command to run (e.g. `apt-get clean`)
    REGISTRY = "registry"  # a Windows registry key or value (backed up first)


@dataclass(frozen=True)
class RegTarget:
    """A registry key (``value is None``) or one value inside a key.

    ``key`` is the physical path below the hive (literal ``WOW6432Node``
    where it applies). ``fingerprint`` pins the exact content seen at scan
    time: a changed entry no longer matches.
    """

    hive: str
    key: str
    value: Optional[str] = None
    fingerprint: str = ""

    @property
    def display(self) -> str:
        """Human-readable path. Format, control and bidi characters are shown
        as escapes so a name cannot disguise itself in a UI."""
        text = f"{self.hive}\\{_visible(self.key)}"
        if self.value is not None:
            text += f" [{_visible(self.value)}]"
        return text


def _visible(text: str) -> str:
    out = []
    for ch in text:
        if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
            n = ord(ch)
            out.append(f"\\u{n:04x}" if n <= 0xFFFF else f"\\U{n:08x}")
        else:
            out.append(ch)
    return "".join(out)


@dataclass
class CleanableItem:
    """One removable thing discovered during a scan.

    Either ``path`` (for ``PATH`` kind) or ``command`` (for ``COMMAND`` kind)
    must be set. ``size`` is the number of bytes that would be reclaimed; for
    command-based items it is a best-effort estimate and may be 0.
    """

    cleaner_id: str
    description: str
    size: int = 0
    kind: ItemKind = ItemKind.PATH
    path: Optional[str] = None
    command: Optional[Sequence[str]] = None
    requires_root: bool = False
    # Report-only items are surfaced with their size but are NEVER deleted by
    # cleanix. Used for backups/snapshots/device data — things a user should
    # review and remove deliberately. ``hint`` explains how to remove manually.
    report_only: bool = False
    hint: Optional[str] = None
    # COMMAND items only: seconds before the command is killed. ``None`` keeps
    # run_command's default (120 s); long jobs such as DISM set their own.
    timeout: Optional[int] = None
    # REGISTRY items only: the key or value to remove.
    reg: Optional[RegTarget] = None

    def __post_init__(self) -> None:
        if self.kind is ItemKind.PATH and not self.path:
            raise ValueError("PATH item requires a path")
        if self.kind is ItemKind.COMMAND and not self.command:
            raise ValueError("COMMAND item requires a command")
        if self.kind is ItemKind.REGISTRY:
            reg = self.reg
            if reg is None:
                raise ValueError("REGISTRY item requires reg")
            if reg.hive not in ("HKCU", "HKLM"):
                raise ValueError("REGISTRY item hive must be HKCU or HKLM")
            if not reg.key or not reg.fingerprint:
                raise ValueError("REGISTRY item requires a key and a fingerprint")
            if self.path is not None or self.command is not None:
                raise ValueError("REGISTRY item must not set path or command")
        elif self.reg is not None:
            raise ValueError("reg is only valid on REGISTRY items")


def item_key(item: CleanableItem) -> str:
    """A stable, unique key for an item (used by UIs to track selection)."""
    if item.kind is ItemKind.COMMAND:
        return f"{item.cleaner_id}|cmd|" + "\x1f".join(item.command or [])
    if item.kind is ItemKind.REGISTRY and item.reg is not None:
        r = item.reg
        return f"{item.cleaner_id}|reg|" + json.dumps(
            [r.hive, r.key, r.value, r.fingerprint], ensure_ascii=True
        )
    return f"{item.cleaner_id}|path|{item.path}"


def item_target(item: CleanableItem) -> str:
    """What the item acts on as text: a path, a command line or a registry path."""
    if item.reg is not None:
        return item.reg.display
    if item.path:
        return item.path
    return " ".join(item.command or [])


@dataclass
class CleanerReport:
    """The result of scanning with a single cleaner."""

    cleaner_id: str
    name: str
    description: str
    items: List[CleanableItem] = field(default_factory=list)
    skipped_reason: Optional[str] = None  # set when the cleaner could not run

    @property
    def total_size(self) -> int:
        return sum(i.size for i in self.items)

    @property
    def count(self) -> int:
        return len(self.items)

    @property
    def ran(self) -> bool:
        return self.skipped_reason is None

    @property
    def report_only(self) -> bool:
        """True if this cleaner only surfaces (never deletes) its items."""
        return bool(self.items) and all(i.report_only for i in self.items)


@dataclass
class ScanResult:
    """Aggregated scan across all selected cleaners."""

    reports: List[CleanerReport] = field(default_factory=list)

    @property
    def total_size(self) -> int:
        return sum(r.total_size for r in self.reports)

    @property
    def total_items(self) -> int:
        return sum(r.count for r in self.reports)

    def all_items(self) -> List[CleanableItem]:
        return [item for r in self.reports for item in r.items]

    def cleanable_items(self) -> List[CleanableItem]:
        """Items eligible for deletion (excludes report-only)."""
        return [i for i in self.all_items() if not i.report_only]

    def report_only_items(self) -> List[CleanableItem]:
        return [i for i in self.all_items() if i.report_only]

    @property
    def cleanable_size(self) -> int:
        return sum(i.size for i in self.cleanable_items())

    @property
    def report_only_size(self) -> int:
        return sum(i.size for i in self.report_only_items())


@dataclass
class CleanOutcome:
    """The result of attempting to remove one item."""

    item: CleanableItem
    removed: bool
    freed: int = 0
    error: Optional[str] = None
    dry_run: bool = False


@dataclass
class CleanResult:
    """Aggregated result of a clean run."""

    outcomes: List[CleanOutcome] = field(default_factory=list)
    dry_run: bool = False

    @property
    def freed(self) -> int:
        return sum(o.freed for o in self.outcomes)

    @property
    def removed_count(self) -> int:
        return sum(1 for o in self.outcomes if o.removed)

    @property
    def errors(self) -> List[CleanOutcome]:
        return [o for o in self.outcomes if o.error]
