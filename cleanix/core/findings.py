"""Finding categories and grouping for report-only results.

Pure logic (no Qt, no I/O). A *finding* is a report-only item that carries a
:class:`~cleanix.core.remedy.Remedy`; items without one are still grouped (so
they stay visible) but are not actionable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from cleanix.core.curation import copy_for
from cleanix.core.models import CleanableItem, ScanResult

YOUR_FILES = "Your files"
APP_LEFTOVERS = "Leftovers of removed apps"
UNOWNED_FILES = "System files no package owns"
SERVICES = "Services and background jobs"
INSTALL_RECORDS = "Install records"

# Presentation order of the categories.
CATEGORY_ORDER: Tuple[str, ...] = (
    YOUR_FILES, APP_LEFTOVERS, UNOWNED_FILES, SERVICES, INSTALL_RECORDS,
)

FINDING_CATEGORIES: Dict[str, str] = {}


def _assign(category: str, ids: str) -> None:
    for cid in ids.split():
        FINDING_CATEGORIES[cid] = category


# Things the user owns (or that hold user state) and must judge themselves.
_assign(
    YOUR_FILES,
    "big_files downloads duplicates project_cruft browser_profiles "
    "snapshots time_machine device_backups libvirt_saves wsl_disk "
    "win_windows_old win_prefetch macos_sleepimage",
)
_assign(APP_LEFTOVERS, "orphan_app_data stale_launchers")
_assign(UNOWNED_FILES, "orphan_files stale_alternatives")
_assign(SERVICES, "stale_services orphan_launch_jobs")
_assign(INSTALL_RECORDS, "stale_receipts")


def category_of(cleaner_id: str) -> str:
    """Finding category of a report-only cleaner id (KeyError when unknown)."""
    return FINDING_CATEGORIES[cleaner_id]


@dataclass
class FindingGroup:
    category: str
    cleaner_id: str
    title: str
    items: List[CleanableItem] = field(default_factory=list)

    @property
    def total_size(self) -> int:
        return sum(i.size for i in self.items)


def is_finding(item: CleanableItem) -> bool:
    """True for a report-only item that offers a remedy."""
    return bool(item.report_only) and item.remedy is not None


def group_findings(scan: ScanResult) -> List[FindingGroup]:
    """Report-only items grouped per cleaner, ordered by category, then size.

    Cleaners without a finding category and non-report-only items are left out.
    """
    groups: List[FindingGroup] = []
    for rep in scan.reports:
        category = FINDING_CATEGORIES.get(rep.cleaner_id)
        if category is None:
            continue
        items = sorted(
            (i for i in rep.items if i.report_only), key=lambda i: -i.size)
        if not items:
            continue
        title = copy_for(rep.cleaner_id, rep.name, rep.description).title
        groups.append(FindingGroup(category, rep.cleaner_id, title, items))
    groups.sort(key=lambda g: (CATEGORY_ORDER.index(g.category), -g.total_size))
    return groups
