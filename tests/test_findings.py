"""Tests for finding categories and grouping."""

from __future__ import annotations

import pytest

from cleanix.core import catalog, registry
from cleanix.core.findings import (
    CATEGORY_ORDER,
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
    assert set(FINDING_CATEGORIES.values()) <= set(CATEGORY_ORDER)
    assert len(CATEGORY_ORDER) == 5
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


def test_non_report_only_and_unmapped_ignored():
    scan = _scan(
        ("temp", [_item("temp", "/t", remedy=False, report_only=False)]),
        ("big_files", [_item("big_files", "/a", remedy=False)]),
    )
    assert [g.cleaner_id for g in group_findings(scan)] == ["big_files"]
