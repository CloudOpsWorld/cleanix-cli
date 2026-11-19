"""Wiring of the Linux/macOS orphan reports: registry, category, copy, CLI."""

from __future__ import annotations

from unittest import mock

import pytest

from cleanix import cli, elevated
from cleanix.cleaners import ALL_CLEANERS
from cleanix.cleaners.orphan_common import OrphanReporter
from cleanix.config import Config
from cleanix.core import catalog, registry
from cleanix.core.catalog import category_of
from cleanix.core.curation import COPY, _REVIEW_TAIL

ORPHAN_IDS = [
    "orphan_files", "stale_services", "stale_launchers", "stale_alternatives",
    "orphan_launch_jobs", "orphan_app_data", "stale_receipts",
]
BY_ID = {c.id: c for c in ALL_CLEANERS}


def test_all_seven_registered_once():
    ids = [c.id for c in ALL_CLEANERS]
    for cid in ORPHAN_IDS:
        assert ids.count(cid) == 1, cid


@pytest.mark.parametrize("cid", ORPHAN_IDS)
def test_orphan_cleaners_are_review_report_only(cid):
    cls = BY_ID[cid]
    assert issubclass(cls, OrphanReporter)
    assert category_of(cid) == "review"
    assert cid not in elevated.admin_cleaner_ids()
    assert cls.requires_root is False
    assert cls.safe_default is False
    assert "windows" not in cls.platforms
    assert COPY[cid].blurb.endswith(_REVIEW_TAIL)
    assert len(COPY[cid].title) <= 40
    assert "false positive" in COPY[cid].blurb
    info = catalog._info_for(cls(Config()))
    assert info.category == "review"


@pytest.mark.parametrize("cid", ["orphan_launch_jobs", "orphan_app_data", "stale_receipts"])
def test_macos_copy_does_not_mention_package_manager(cid):
    blurb = COPY[cid].blurb
    assert "package manager" not in blurb
    assert "confirm before removing" in blurb


def test_copy_does_not_claim_etc_or_srv_for_orphan_files():
    blurb = COPY["orphan_files"].blurb
    assert "/etc" not in blurb and "/srv" not in blurb


def test_only_orphan_files_is_opt_in():
    for cid in ORPHAN_IDS:
        assert BY_ID[cid].default_enabled is (cid != "orphan_files"), cid


def test_orphan_files_is_opt_in_in_registry():
    with mock.patch("cleanix.core.platform.current_os", return_value="linux"):
        default = [c.id for c in registry.build_cleaners(Config())]
        forced = [c.id for c in registry.build_cleaners(
            Config(), only=["orphan_files"])]
    assert "orphan_files" not in default
    assert "stale_services" in default
    assert forced == ["orphan_files"]


def test_never_preselected():
    for cid in ORPHAN_IDS:
        assert cid in catalog._NEVER_PRESELECT or category_of(cid) in catalog._NEVER_PRESELECT


def test_list_marks_opt_in(capsys):
    assert cli.main(["list", "--all"]) == 0
    assert "opt-in" in capsys.readouterr().out


@pytest.mark.parametrize("cid", ORPHAN_IDS)
def test_scan_yields_only_report_only_items(cid, orphan_env):
    cleaner = BY_ID[cid](Config())
    rep = cleaner.scan()
    for it in rep.items:
        assert it.report_only and it.hint, (cid, it)
