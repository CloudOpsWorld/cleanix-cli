"""Catalog, categories and the safe_default pre-selection rule."""

from __future__ import annotations

from dataclasses import replace
from unittest import mock

import pytest

from cleanix.cleaners import ALL_CLEANERS
from cleanix.cleaners.base import Cleaner
from cleanix.config import Config
from cleanix.core import catalog
from cleanix.core.catalog import (
    CATEGORIES,
    CleanerInfo,
    category_of,
    list_cleaners,
    preselect,
)
from cleanix.core.models import CleanableItem, ItemKind
from cleanix.core.registry import known_ids

SAFE_CLASSES = {
    "temp": ["TempFilesCleaner", "WinTempCleaner"],
    "browser": ["BrowserCacheCleaner", "WinBrowserCacheCleaner"],
    "dev": [
        "DevCacheCleaner", "PipCacheCleaner", "NpmCacheCleaner",
        "LangPackageCacheCleaner", "WinPackageCacheCleaner",
        "WinVisualStudioCleaner", "JetBrainsCleaner",
    ],
    "apps": [
        "UserCacheCleaner", "ThumbnailCleaner", "WinThumbnailCleaner",
        "WinErrorReportingCleaner", "ElectronCacheCleaner",
        "GpuShaderCacheCleaner", "WinShaderCacheCleaner",
    ],
}
TRASH_CLASSES = ["TrashCleaner", "MacTrashCleaner", "WinRecycleBinCleaner"]
REVIEW_CLASSES = [
    "BigFileReporter", "DownloadsReporter", "DuplicateFileReporter",
    "ProjectCruftCleaner", "BrowserProfileReporter", "WinPrefetchReporter",
    "WindowsOldReporter", "WslDiskReporter", "SnapshotReporter",
    "TimeMachineReporter", "DeviceBackupReporter",
    "UnownedSystemFilesReporter", "StaleSystemdUnitReporter",
    "StaleDesktopEntryReporter", "BrokenAlternativesReporter",
    "OrphanLaunchJobReporter", "OrphanAppDataReporter", "StaleReceiptReporter",
]
BY_NAME = {c.__name__: c for c in ALL_CLEANERS}


def _item(**kw):
    base = dict(cleaner_id="x", description="d", size=1, path="/tmp/x")
    base.update(kw)
    return CleanableItem(**base)


def _info(**kw):
    base = dict(
        id="x", name="X", description="d", requires_root=False,
        platforms=("*",), supported=True, default_enabled=True,
        safe_default=True, category="temp",
    )
    base.update(kw)
    return CleanerInfo(**base)


def test_safe_default_is_false_on_the_base_class():
    assert Cleaner.safe_default is False


def test_every_registered_cleaner_has_a_category():
    for cid in known_ids():
        assert category_of(cid) in CATEGORIES, cid
    assert category_of("no_such_cleaner") == "other"


def test_categories_labels():
    assert CATEGORIES["temp"] == "Temporary files"
    assert CATEGORIES["system"] == "System files (administrator)"
    assert CATEGORIES["trash"] == "Trash / Recycle Bin"
    assert CATEGORIES["review"] == "Needs your review"
    assert CATEGORIES["other"] == "Other"


@pytest.mark.parametrize(
    "item_kw, info_kw, expected",
    [
        ({}, {}, True),
        ({"report_only": True, "hint": "h"}, {}, False),
        ({"requires_root": True}, {}, False),
        ({"kind": ItemKind.COMMAND, "path": None, "command": ["x"]}, {}, False),
        ({}, {"category": "trash"}, False),
        ({}, {"category": "system"}, False),
        ({}, {"category": "review"}, False),
        ({}, {"category": "other"}, False),
        ({}, {"safe_default": False}, False),
        ({}, {"category": "dev"}, True),
    ],
)
def test_preselect_rules(item_kw, info_kw, expected):
    assert preselect(_item(**item_kw), _info(**info_kw)) is expected


def test_safe_classes_have_flag_and_category():
    for cat, names in SAFE_CLASSES.items():
        for n in names:
            cls = BY_NAME[n]
            assert cls.safe_default is True, n
            assert category_of(cls.id) == cat, n
    flagged = {c.__name__ for c in ALL_CLEANERS if c.safe_default}
    assert flagged == {n for v in SAFE_CLASSES.values() for n in v}


def test_trash_and_reporters_are_never_preselected():
    cfg = Config()
    for n in TRASH_CLASSES + REVIEW_CLASSES:
        cls = BY_NAME[n]
        assert cls.safe_default is False, n
        info = catalog._info_for(cls(cfg))
        assert info.category in ("trash", "review"), n
        assert preselect(_item(cleaner_id=cls.id), info) is False, n


def test_no_root_or_system_cleaner_is_safe_default():
    for c in ALL_CLEANERS:
        if c.safe_default:
            assert category_of(c.id) not in {"trash", "system", "review", "other"}
        if c.requires_root and c.__name__ not in REVIEW_CLASSES:
            assert category_of(c.id) in {"system", "review"}, c.id


def test_unreviewed_cleaner_is_not_preselected():
    class Dummy(Cleaner):
        id = "dummy"

        def find_items(self):
            return []

    info = catalog._info_for(Dummy(Config()))
    assert info.safe_default is False
    assert preselect(_item(), replace(info, category="temp")) is False


def test_list_cleaners_filters_unsupported_platforms():
    with mock.patch("cleanix.core.platform.current_os", return_value="linux"):
        ids = [i.id for i in list_cleaners(Config())]
        assert ids and not any(i.startswith("win_") for i in ids)
        everything = list_cleaners(Config(), include_unsupported=True)
        by_id = {i.id: i for i in everything}
        assert "win_temp" in by_id
        assert by_id["win_temp"].supported is False
        assert by_id["temp"].supported is True
        assert by_id["temp"].category == "temp" and by_id["temp"].safe_default


def test_slow_scan_ids_are_registered_cleaners():
    assert catalog.SLOW_SCAN_IDS == (
        "duplicates", "big_files", "downloads", "stale_receipts", "orphan_app_data",
    )
    assert set(catalog.SLOW_SCAN_IDS) <= set(known_ids())
