"""Finding categories and grouping for report-only results.

No Qt. A *finding* is a report-only item that carries a
:class:`~cleanix.core.remedy.Remedy`; items without one are still grouped (so
they stay visible) but are not actionable. Grouping is pure logic;
:func:`plan_duplicates` re-stats the copies (lstat only, never deletes).
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
from dataclasses import dataclass, field
from typing import (Callable, Dict, Iterable, List, Mapping, NamedTuple, Optional,
                    Sequence, Tuple)

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
# that must still exist (unchanged) when the copy is removed, and the group
# both belong to.
SURVIVOR_PATH = "survivor_path"
SURVIVOR_FINGERPRINT = "survivor_fingerprint"
SURVIVOR_GROUP = "survivor_group"

KEPT = "kept: this is the copy that stays"


@dataclass
class ActPlan:
    """Items to act on, and every other supplied item with the reason."""

    items: List[CleanableItem] = field(default_factory=list)
    skipped: List[Tuple[CleanableItem, str]] = field(default_factory=list)
    # The copies that stay (also listed in ``skipped`` with reason KEPT): a
    # structured marker so callers never classify them by wording.
    kept: List[CleanableItem] = field(default_factory=list)


class Survivor(NamedTuple):
    """The copy of a duplicate group that must stay (as stamped)."""

    path: str
    fingerprint: Tuple[int, ...]
    group: str


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


def default_survivor(copies: Sequence[CleanableItem], keep: str = "oldest"
                     ) -> CleanableItem:
    """The copy :func:`plan_duplicates` keeps by ``keep``, judged from the
    scan-time data alone (no filesystem access). ``copies`` must not be
    empty."""
    if keep not in KEEP_POLICIES:
        raise ValueError(
            f"keep must be one of {', '.join(KEEP_POLICIES)}, not {keep!r}")
    return min(copies, key=_rank_key(keep))


def survivor_of(item: CleanableItem) -> Optional[Survivor]:
    """The kept copy stamped by :func:`plan_duplicates`, else None
    (also None for a malformed stamp)."""
    remedy = item.remedy
    if remedy is None:
        return None
    extra = dict(remedy.extra)
    path = extra.get(SURVIVOR_PATH)
    raw = extra.get(SURVIVOR_FINGERPRINT)
    group = extra.get(SURVIVOR_GROUP)
    if not path or not raw or not group:
        return None
    try:
        fp = tuple(int(x) for x in raw.split(","))
    except ValueError:
        return None
    if len(fp) != 4:
        return None
    return Survivor(path, fp, group)


def _stamp(item: CleanableItem, survivor: CleanableItem) -> CleanableItem:
    remedy = item.remedy
    assert remedy is not None and survivor.remedy is not None and remedy.group
    keys = (SURVIVOR_PATH, SURVIVOR_FINGERPRINT, SURVIVOR_GROUP)
    extra = tuple(kv for kv in remedy.extra if kv[0] not in keys)
    extra += (
        (SURVIVOR_PATH, survivor.path or ""),
        (SURVIVOR_FINGERPRINT, ",".join(str(int(x)) for x in survivor.remedy.fingerprint)),
        (SURVIVOR_GROUP, remedy.group),
    )
    return dataclasses.replace(item, remedy=dataclasses.replace(remedy, extra=extra))


def check_survivor(path: str, fingerprint: Sequence[int]) -> Optional[str]:
    """Why the copy to keep is not usable now (None when it is): it must
    still be the same regular file, unchanged since the scan."""
    return verify_path(path, fingerprint, allow_dir=False)


def copy_vs_survivor(copy_fp: Sequence[int], copy_group: Optional[str],
                     survivor: Survivor) -> Optional[str]:
    """Why a copy may not be removed in favour of ``survivor``, judged from
    the recorded data alone (None when it may): same group, same size, and
    not the very same file (a hard link)."""
    try:
        cfp = tuple(int(x) for x in copy_fp)
        sfp = tuple(int(x) for x in survivor.fingerprint)
    except (TypeError, ValueError):
        return "no usable fingerprint"
    if len(cfp) != 4 or len(sfp) != 4:
        return "no usable fingerprint"
    if not copy_group or survivor.group != copy_group:
        return "the copy to keep is not from this duplicate group; nothing removed"
    if cfp[0] != sfp[0]:
        return "the copy to keep differs in size; nothing removed"
    if cfp[2:] == sfp[2:]:
        return "same file as the copy to keep (a hard link); nothing removed"
    return None


_HEX = frozenset("0123456789abcdef")
_CHUNK = 1024 * 1024


_HASH_CACHE_MAX = 64
# (path key, full fingerprint) -> SHA-256 hex of a kept copy: a dry run
# followed by a real act hashes the kept copy once. The fingerprint is
# re-verified by the caller right before every use, so a changed file never
# matches a stale entry.
_hash_cache: Dict[Tuple[str, Tuple[int, ...]], str] = {}

CANCELLED = "cancelled while checking the copy to keep; nothing removed"


def _sha256_of(path: str, cancel: Optional[Callable[[], bool]]) -> Optional[str]:
    """SHA-256 of ``path``, polling ``cancel`` between chunks (None when
    cancelled). Raises OSError/ValueError when unreadable."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            if cancel is not None and cancel():
                return None
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def content_matches_group(path: str, group: str, *,
                          fingerprint: Optional[Sequence[int]] = None,
                          cancel: Optional[Callable[[], bool]] = None
                          ) -> Optional[str]:
    """Why ``path``'s content is not proven to be the group's (None when it
    is). A duplicate group id is the full SHA-256 of the content (see
    cleaners/duplicates.py); the file is streamed and hashed. Anything else
    (not a SHA-256 id, unreadable file, cancelled) fails closed.

    ``cancel`` is polled between read chunks. With ``fingerprint`` (the file's
    lstat identity), the digest is cached under (path, fingerprint)."""
    if len(group) != 64 or not set(group) <= _HEX:
        return "cannot confirm the copy to keep has the same content; nothing removed"
    key = None
    if fingerprint is not None:
        try:
            key = (path_key(path), tuple(int(x) for x in fingerprint))
        except (TypeError, ValueError):
            key = None
    digest = _hash_cache.get(key) if key is not None else None
    if digest is None:
        try:
            digest = _sha256_of(path, cancel)
        except (OSError, ValueError):
            return "the copy to keep could not be read; nothing removed"
        if digest is None:
            return CANCELLED
        if key is not None:
            if len(_hash_cache) >= _HASH_CACHE_MAX:
                _hash_cache.clear()
            _hash_cache[key] = digest
    if digest != group:
        return "the copy to keep no longer has the same content; nothing removed"
    return None


def _as_survivor(item: CleanableItem) -> Survivor:
    remedy = item.remedy
    assert remedy is not None
    return Survivor(item.path or "", tuple(remedy.fingerprint), remedy.group or "")


def kept_context(items: Iterable[CleanableItem],
                 kept: Iterable[CleanableItem] = ()) -> List[Survivor]:
    """Every kept copy named by the stamped ``items`` (from a duplicates
    plan) plus the kept copies ``kept`` themselves (``ActPlan.kept``): the
    ``protect`` argument of :func:`actions.act` for a caller that acts on
    one plan in several calls, or on only part of it."""
    out: List[Survivor] = []
    for i in items:
        stamp = survivor_of(i)
        if stamp is not None:
            out.append(stamp)
    for k in kept:
        if k.remedy is not None and k.path:
            out.append(_as_survivor(k))
    return out


def _group_copies(items: Sequence[CleanableItem], plan: ActPlan
                  ) -> Dict[str, List[CleanableItem]]:
    """Supplied duplicate copies by group (each path once); others skipped."""
    groups: Dict[str, List[CleanableItem]] = {}
    seen = set()
    for item in items:
        remedy = item.remedy
        if (not is_finding(item) or remedy is None or remedy.kind is not RemedyKind.PATH
                or not remedy.group or not item.path):
            plan.skipped.append((item, "not a duplicate copy"))
            continue
        k = path_key(item.path)
        if k in seen:
            plan.skipped.append((item, "listed twice"))
            continue
        seen.add(k)
        groups.setdefault(remedy.group, []).append(item)
    return groups


DIFFERENT_OWNERS = "copies belong to different accounts; nothing removed"


def _is_posix() -> bool:
    return os.name != "nt"


def _owner_uid(path: str) -> Optional[int]:
    """The lstat owner uid of ``path`` (None when it cannot be read: the
    copy's own checks then refuse it). A seam for tests."""
    try:
        return int(os.lstat(path).st_uid)
    except (OSError, ValueError):
        return None


def owners_differ(paths: Iterable[str]) -> bool:
    """POSIX: True when the files at ``paths`` are owned by more than one
    account (a scan of several homes must never keep one user's copy in
    place of another's). Always False on Windows."""
    if not _is_posix():
        return False
    uids = {_owner_uid(p) for p in paths}
    uids.discard(None)
    return len(uids) > 1


def _plan_group(copies: List[CleanableItem], survivor: CleanableItem, plan: ActPlan) -> None:
    """Plan one group around ``survivor`` (one of ``copies``), fail closed."""
    reason: Optional[str] = None
    if len(copies) < 2:
        reason = "fewer than two copies of this file were chosen; nothing removed"
    elif owners_differ(c.path or "" for c in copies):
        reason = DIFFERENT_OWNERS
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
        kept = _as_survivor(survivor)
        for c in copies:
            if c is survivor:
                continue
            remedy = c.remedy
            assert remedy is not None
            why = verify_path(c.path or "", remedy.fingerprint, allow_dir=False)
            if why is None and not unchanged(c):
                why = CHANGED
            if why is None:
                why = copy_vs_survivor(remedy.fingerprint, remedy.group, kept)
            if why is None:
                removable.append(c)
            else:
                bad.append((c, why))
        if not removable:
            reason = "fewer than two copies of this file remain; nothing removed"
    if reason is not None:
        plan.skipped.extend((c, reason) for c in copies)
        return
    plan.skipped.append((survivor, KEPT))
    plan.kept.append(survivor)
    plan.skipped.extend(bad)
    plan.items.extend(_stamp(c, survivor) for c in removable)


def plan_duplicates(items: Sequence[CleanableItem], keep: str) -> ActPlan:
    """Choose one copy to keep per duplicate group; plan removing the rest.

    Only the supplied items are candidates, and the copy kept is always one
    of them (chosen by ``keep`` from the scan-time data, then re-checked), so
    at least one supplied copy of every group is never removed. A group whose
    chosen copy is missing, unreadable, not a regular file or changed, or
    with fewer than two usable copies, puts ALL its items in ``skipped``.
    Copies to remove are stamped with the kept copy and their group so
    :func:`actions.act` re-checks it at delete time. Never deletes anything.
    """
    if keep not in KEEP_POLICIES:
        raise ValueError(
            f"keep must be one of {', '.join(KEEP_POLICIES)}, not {keep!r}")
    plan = ActPlan()
    for copies in _group_copies(items, plan).values():
        _plan_group(copies, default_survivor(copies, keep), plan)
    return plan


def plan_duplicates_keeping(items: Sequence[CleanableItem],
                            survivors: Mapping[str, CleanableItem]) -> ActPlan:
    """Like :func:`plan_duplicates`, with the copy to keep chosen by the
    caller (the GUI/review pick) per group id: ``survivors[group]``.

    The chosen copy must be one of the supplied copies of that group (same
    path); otherwise, or when a group has no choice, ALL its items are
    skipped. The same checks as :func:`plan_duplicates` then apply.
    """
    plan = ActPlan()
    for group, copies in _group_copies(items, plan).items():
        chosen = survivors.get(group)
        match = None
        if chosen is not None and chosen.path:
            want = path_key(chosen.path)
            match = next((c for c in copies if path_key(c.path or "") == want), None)
        if match is None:
            reason = ("no copy to keep was chosen for this group; nothing removed"
                      if chosen is None else
                      "the copy to keep is not one of the chosen copies of this group; "
                      "nothing removed")
            plan.skipped.extend((c, reason) for c in copies)
            continue
        _plan_group(copies, match, plan)
    return plan
