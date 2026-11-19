"""Tests for the Remedy model attached to report-only findings."""

from __future__ import annotations

import dataclasses
import os

import pytest

from cleanix.core.models import CleanableItem, ItemKind, item_key
from cleanix.core.remedy import Remedy, RemedyKind, fingerprint_of, unchanged


def _item(path, remedy=None, report_only=True):
    return CleanableItem(
        cleaner_id="t",
        description="d",
        path=str(path),
        report_only=report_only,
        remedy=remedy,
    )


def _remedy_for(path):
    fp = fingerprint_of(str(path))
    assert fp is not None
    return Remedy(RemedyKind.PATH, fp)


def test_remedy_requires_report_only(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    r = _remedy_for(f)
    with pytest.raises(ValueError):
        _item(f, remedy=r, report_only=False)
    assert _item(f, remedy=r).remedy is r


def test_fingerprint_changes_on_edit(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    before = fingerprint_of(str(f))
    assert before is not None and len(before) == 4
    f.write_text("xyz")
    os.utime(str(f), ns=(1, 1))
    assert fingerprint_of(str(f)) != before


def test_unchanged_true_then_false_after_edit(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    item = _item(f, _remedy_for(f))
    assert unchanged(item) is True
    f.write_text("longer content")
    os.utime(str(f), ns=(5, 5))
    assert unchanged(item) is False


def test_unchanged_false_when_replaced_by_symlink(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    target = tmp_path / "b.txt"
    target.write_text("x")
    item = _item(f, _remedy_for(f))
    f.unlink()
    try:
        os.symlink(str(target), str(f))
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlinks unavailable")
    assert unchanged(item) is False


def test_unchanged_false_when_missing(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    item = _item(f, _remedy_for(f))
    f.unlink()
    assert fingerprint_of(str(f)) is None
    assert unchanged(item) is False


def test_unchanged_false_without_remedy(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    assert unchanged(_item(f)) is False


def test_item_key_unchanged_by_remedy(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    plain = _item(f)
    with_remedy = _item(f, _remedy_for(f))
    assert item_key(plain) == item_key(with_remedy) == "t|path|%s" % f
    assert plain.kind is ItemKind.PATH


def test_remedy_defaults_and_frozen():
    r = Remedy(RemedyKind.SYSTEMD_UNIT, (0, 0, 0, 0))
    assert r.group is None and r.extra == ()
    assert {k.value for k in RemedyKind} == {
        "path", "launch_job", "systemd_unit", "pkg_receipt"}
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.group = "g"  # type: ignore[misc]


def test_fingerprint_of_embedded_nul_fails_closed():
    assert fingerprint_of("bad\x00path") is None


def test_unchanged_false_for_non_path_kind(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    fp = fingerprint_of(str(f))
    assert fp is not None
    item = _item(f, Remedy(RemedyKind.SYSTEMD_UNIT, fp))
    assert unchanged(item) is False
