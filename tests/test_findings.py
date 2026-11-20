"""Tests for finding categories and grouping."""

from __future__ import annotations

import inspect

import pytest

from cleanix.core import catalog, registry
from cleanix.core.findings import (
    CATEGORY_ORDER,
    OTHER_FINDINGS,
    category_or_fallback,
    FINDING_CATEGORIES,
    FindingGroup,
    category_of,
    group_findings,
    is_finding,
)
from cleanix.core.models import CleanableItem, CleanerReport, ScanResult
from cleanix.core.remedy import Remedy, RemedyKind


def _item(cid, path, size=1, remedy=True, report_only=True):
    r = Remedy(RemedyKind.PATH, (size, 0, 0, 0)) if remedy else None
    return CleanableItem(
        cleaner_id=cid, description="d", path=path, size=size,
        report_only=report_only, remedy=r,
    )


def _scan(*reports):
    return ScanResult(reports=[
        CleanerReport(cleaner_id=cid, name=cid, description="", items=items)
        for cid, items in reports
    ])


def _report_only_ids():
    # The catalog files every report-only cleaner under "review".
    return [i for i in registry.known_ids()
            if catalog.category_of(i) == "review"]


def test_every_report_only_cleaner_has_category():
    ids = _report_only_ids()
    assert ids, "registry exposes no report-only cleaners"
    for cid in ids:
        assert cid in FINDING_CATEGORIES, "missing finding category for %r" % cid


def test_categories_are_the_five_known_and_ids_are_real():
    assert set(FINDING_CATEGORIES.values()) <= set(CATEGORY_ORDER[:5])
    assert len(CATEGORY_ORDER) == 6 and CATEGORY_ORDER[-1] == OTHER_FINDINGS
    assert OTHER_FINDINGS not in FINDING_CATEGORIES.values()
    for cid in FINDING_CATEGORIES:
        assert cid in registry.known_ids(), "unknown cleaner id %r" % cid


def test_category_of():
    assert category_of("big_files") == "Your files"
    assert category_of("stale_receipts") == "Install records"
    with pytest.raises(KeyError):
        category_of("temp")


def test_group_findings_orders_by_category():
    scan = _scan(
        ("stale_receipts", [_item("stale_receipts", "/r", 500)]),
        ("big_files", [_item("big_files", "/a", 10), _item("big_files", "/b", 90)]),
        ("duplicates", [_item("duplicates", "/c", 1000)]),
        ("orphan_app_data", [_item("orphan_app_data", "/d", 5)]),
    )
    groups = group_findings(scan)
    assert all(isinstance(g, FindingGroup) for g in groups)
    assert [g.cleaner_id for g in groups] == [
        "duplicates", "big_files", "orphan_app_data", "stale_receipts"]
    assert [g.category for g in groups] == [
        "Your files", "Your files",
        "Leftovers of removed apps", "Install records"]
    big = groups[1]
    assert [i.size for i in big.items] == [90, 10]
    assert big.title


def test_items_without_remedy_not_findings():
    with_r = _item("big_files", "/a")
    without = _item("big_files", "/b", remedy=False)
    plain = _item("temp", "/c", remedy=False, report_only=False)
    assert is_finding(with_r) is True
    assert is_finding(without) is False
    assert is_finding(plain) is False
    groups = group_findings(_scan(("big_files", [with_r, without])))
    assert len(groups) == 1 and len(groups[0].items) == 2


def test_non_report_only_ignored():
    scan = _scan(
        ("temp", [_item("temp", "/t", remedy=False, report_only=False)]),
        ("big_files", [_item("big_files", "/a", remedy=False)]),
    )
    assert [g.cleaner_id for g in group_findings(scan)] == ["big_files"]


def test_unmapped_report_only_cleaner_goes_to_other_findings():
    scan = _scan(
        ("brand_new", [_item("brand_new", "/n", 7)]),
        ("stale_receipts", [_item("stale_receipts", "/r", 500)]),
    )
    groups = group_findings(scan)
    assert [g.cleaner_id for g in groups] == ["stale_receipts", "brand_new"]
    assert groups[-1].category == OTHER_FINDINGS
    assert groups[-1].title == "brand_new"
    assert len(groups[-1].items) == 1
    assert category_or_fallback("brand_new") == OTHER_FINDINGS
    assert category_or_fallback("big_files") == "Your files"


def _emits_report_only(cls):
    """Source-level marker: the class (or a cleaner base) builds report-only
    items, independent of the hand-maintained catalog list."""
    from cleanix.cleaners.orphan_common import OrphanReporter

    if issubclass(cls, OrphanReporter):
        return True
    for k in cls.__mro__:
        if not k.__module__.startswith("cleanix.cleaners"):
            continue
        if k.__name__ in ("Cleaner", "object"):
            continue
        src = inspect.getsource(k)
        if "report_only=True" in src or "report_item(" in src:
            return True
    return False


def test_every_cleaner_emitting_report_only_is_categorised():
    from cleanix.cleaners import ALL_CLEANERS

    emitters = [c.id for c in ALL_CLEANERS if _emits_report_only(c)]
    assert emitters, "source scan found no report-only cleaners"
    for cid in emitters:
        assert cid in FINDING_CATEGORIES, (
            "cleaner %r emits report-only items but has no finding category" % cid)


def test_catalog_review_list_and_categories_agree_both_ways():
    review = set(_report_only_ids())
    for cid in review - set(FINDING_CATEGORIES):
        pytest.fail("%r is in catalog 'review' but not FINDING_CATEGORIES" % cid)
    for cid in set(FINDING_CATEGORIES) - review:
        pytest.fail("%r has a finding category but is not in catalog 'review'" % cid)
