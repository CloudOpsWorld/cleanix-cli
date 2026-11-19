"""Finding categories and grouping for report-only results.

No Qt. A *finding* is a report-only item that carries a
:class:`~cleanix.core.remedy.Remedy`; items without one are still grouped (so
they stay visible) but are not actionable. Grouping is pure logic;
:func:`plan_duplicates` re-stats the copies (lstat only, never deletes).
"""

from __future__ import annotations

import dataclasses
import os
import stat
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from cleanix.core.curation import copy_for
from cleanix.core.models import CleanableItem, ScanResult
from cleanix.core.remedy import CHANGED, RemedyKind, unchanged, verify_path

YOUR_FILES = "Your files"
APP_LEFTOVERS = "Leftovers of removed apps"
UNOWNED_FILES = "System files no package owns"
SERVICES = "Services and background jobs"
INSTALL_RECORDS = "Install records"
OTHER_FINDINGS = "Other findings"

# Presentation order of the categories.
CATEGORY_ORDER: Tuple[str, ...] = (
    YOUR_FILES, APP_LEFTOVERS, UNOWNED_FILES, SERVICES, INSTALL_RECORDS,
    OTHER_FINDINGS,
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


def category_or_fallback(cleaner_id: str) -> str:
    """Category of ``cleaner_id``, or "Other findings" when it has none."""
    return FINDING_CATEGORIES.get(cleaner_id, OTHER_FINDINGS)


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

    Report-only items are never dropped: a cleaner without a category lands in
    the "Other findings" fallback group. Non-report-only items are left out.
    """
    groups: List[FindingGroup] = []
    for rep in scan.reports:
        category = category_or_fallback(rep.cleaner_id)
        items = sorted(
            (i for i in rep.items if i.report_only), key=lambda i: -i.size)
        if not items:
            continue
        title = (copy_for(rep.cleaner_id, rep.name, rep.description).title
                 or rep.cleaner_id)
        groups.append(FindingGroup(category, rep.cleaner_id, title, items))
    groups.sort(key=lambda g: (CATEGORY_ORDER.index(g.category), -g.total_size))
    return groups


# -- duplicates ---------------------------------------------------------------

KEEP_POLICIES: Tuple[str, ...] = ("oldest", "newest", "shortest-path")

# Remedy.extra keys stamped by plan_duplicates on each copy to remove: the copy
# that must still exist (unchanged) when the copy is removed.
SURVIVOR_PATH = "survivor_path"
SURVIVOR_FINGERPRINT = "survivor_fingerprint"

KEPT = "kept: this is the copy that stays"


@dataclass
class ActPlan:
    """Items to act on, and every other supplied item with the reason."""

    items: List[CleanableItem] = field(default_factory=list)
    skipped: List[Tuple[CleanableItem, str]] = field(default_factory=list)


def path_key(path: str) -> str:
    """Comparable spelling of ``path`` (lexical; no filesystem access)."""
    return os.path.normcase(os.path.abspath(path))


def _scan_mtime(item: CleanableItem) -> int:
    try:
        return int(item.remedy.fingerprint[1])  # type: ignore[union-attr]
    except (AttributeError, IndexError, TypeError, ValueError):
        return 0


def _rank_key(keep: str):
    if keep == "oldest":
        return lambda i: (_scan_mtime(i), len(i.path or ""), i.path or "")
    if keep == "newest":
        return lambda i: (-_scan_mtime(i), len(i.path or ""), i.path or "")
    return lambda i: (len(i.path or ""), i.path or "")


def survivor_of(item: CleanableItem) -> Optional[Tuple[str, Tuple[int, ...]]]:
    """The (path, fingerprint) stamped by :func:`plan_duplicates`, else None."""
    remedy = item.remedy
    if remedy is None:
        return None
    extra = dict(remedy.extra)
    path = extra.get(SURVIVOR_PATH)
    raw = extra.get(SURVIVOR_FINGERPRINT)
    if not path or not raw:
        return None
    try:
        fp = tuple(int(x) for x in raw.split(","))
    except ValueError:
        return None
    if len(fp) != 4:
        return None
    return path, fp


def _stamp(item: CleanableItem, survivor: CleanableItem) -> CleanableItem:
    remedy = item.remedy
    assert remedy is not None and survivor.remedy is not None
    extra = tuple(kv for kv in remedy.extra
                  if kv[0] not in (SURVIVOR_PATH, SURVIVOR_FINGERPRINT))
    extra += (
        (SURVIVOR_PATH, survivor.path or ""),
        (SURVIVOR_FINGERPRINT, ",".join(str(int(x)) for x in survivor.remedy.fingerprint)),
    )
    return dataclasses.replace(item, remedy=dataclasses.replace(remedy, extra=extra))


def check_survivor(path: str, fingerprint: Sequence[int]) -> Optional[str]:
    """Why the copy to keep is not usable now (None when it is): it must
    still be the same regular file, unchanged since the scan."""
    return verify_path(path, fingerprint, allow_dir=False)


def plan_duplicates(items: Sequence[CleanableItem], keep: str) -> ActPlan:
    """Choose one copy to keep per duplicate group; plan removing the rest.

    Only the supplied items are candidates, and the copy kept is always one
    of them (chosen by ``keep`` from the scan-time data, then re-checked), so
    at least one supplied copy of every group is never removed. A group whose
    chosen copy is missing, unreadable, not a regular file or changed, or
    with fewer than two usable copies, puts ALL its items in ``skipped``.
    Copies to remove are stamped with the kept copy so :func:`actions.act`
    re-checks it at delete time. Never deletes anything itself.
    """
    if keep not in KEEP_POLICIES:
        raise ValueError(
            f"keep must be one of {', '.join(KEEP_POLICIES)}, not {keep!r}")
    plan = ActPlan()
    groups: Dict[str, List[CleanableItem]] = {}
    for item in items:
        remedy = item.remedy
        if (not is_finding(item) or remedy is None or remedy.kind is not RemedyKind.PATH
                or not remedy.group or not item.path):
            plan.skipped.append((item, "not a duplicate copy"))
            continue
        groups.setdefault(remedy.group, []).append(item)

    rank = _rank_key(keep)
    for copies in groups.values():
        uniq: List[CleanableItem] = []
        seen = set()
        for c in copies:
            k = path_key(c.path or "")
            if k in seen:
                plan.skipped.append((c, "listed twice"))
                continue
            seen.add(k)
            uniq.append(c)

        survivor = min(uniq, key=rank)
        reason: Optional[str] = None
        if len(uniq) < 2:
            reason = "fewer than two copies of this file were chosen; nothing removed"
        else:
            why = check_survivor(survivor.path or "", survivor.remedy.fingerprint)  # type: ignore[union-attr]
            if why is None and not unchanged(survivor):
                why = CHANGED
            if why is not None:
                reason = (f"the copy to keep ({survivor.path}) {why}; "
                          f"nothing in this group was removed")
        removable: List[CleanableItem] = []
        bad: List[Tuple[CleanableItem, str]] = []
        if reason is None:
            for c in uniq:
                if c is survivor:
                    continue
                why = verify_path(c.path or "", c.remedy.fingerprint, allow_dir=False)  # type: ignore[union-attr]
                if why is None and not unchanged(c):
                    why = CHANGED
                if why is None:
                    removable.append(c)
                else:
                    bad.append((c, why))
            if not removable:
                reason = "fewer than two copies of this file remain; nothing removed"
        if reason is not None:
            plan.skipped.extend((c, reason) for c in uniq)
            continue
        plan.skipped.append((survivor, KEPT))
        plan.skipped.extend(bad)
        plan.items.extend(_stamp(c, survivor) for c in removable)
    return plan
