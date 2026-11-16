import json
import time

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import QObject, Qt, Signal  # noqa: E402
from PySide6.QtWidgets import QAbstractButton, QWidget  # noqa: E402

from cleanix.config import Config  # noqa: E402
from cleanix.core import catalog, report  # noqa: E402
from cleanix.core.models import (  # noqa: E402
    CleanableItem, CleanerReport, ItemKind, ScanResult,
)
from cleanix.gui import models as gm  # noqa: E402
from cleanix.gui import power_view as pv  # noqa: E402
from cleanix.gui import workers  # noqa: E402

MB = 1024 * 1024


def _info(cid, name, *, root=False, default=True, category="temp"):
    return catalog.CleanerInfo(
        id=cid, name=name, description=f"{name} desc", requires_root=root,
        platforms=("linux",), supported=True, default_enabled=default,
        safe_default=True, category=category)


def _result():
    big_path = "C:/Users/someone/AppData/Local/" + "very_long_directory/" * 10 + "cache"
    return ScanResult(reports=[
        CleanerReport("temp", "Temp", "Temp files", items=[
            CleanableItem("temp", "small cache", size=900 * 1024, path="/tmp/a"),
            CleanableItem("temp", big_path, size=10 * MB, path=big_path),
        ]),
        CleanerReport("apt", "APT", "Apt", items=[
            CleanableItem("apt", "apt clean", size=5 * MB, kind=ItemKind.COMMAND,
                          command=["apt-get", "clean"], requires_root=True),
        ]),
        CleanerReport("big_files", "Big files", "Big", items=[
            CleanableItem("big_files", "huge.iso", size=2000 * MB, path="/x/huge.iso",
                          report_only=True, hint="Delete it manually"),
        ]),
    ])


class FakeScan(QObject):
    progress = Signal(str, int, int)
    finished = Signal(object)
    cancelled = Signal()
    failed = Signal(str)

    def __init__(self, result=None):
        super().__init__()
        self.result = result

    def run(self):
        self.finished.emit(self.result)

    def cancel(self):
        pass


class FakeClean(FakeScan):
    def run(self):
        from cleanix.core.models import CleanResult
        from cleanix.core.service import CleanSummary
        self.finished.emit(CleanSummary(result=CleanResult(dry_run=True),
                                        freed=1, removed=1))


@pytest.fixture
def sync_workers(monkeypatch):
    """Run workers synchronously on the calling thread."""
    monkeypatch.setattr(workers, "start_worker", lambda w: w.run())
    monkeypatch.setattr(pv.PowerView, "show_results", lambda *a, **k: None)


@pytest.fixture
def view(qtbot, monkeypatch, sync_workers):
    monkeypatch.setattr(catalog, "list_cleaners", lambda cfg, **k: [
        _info("temp", "Temp"), _info("apt", "APT", root=True, category="system"),
        _info("big_files", "Big files", category="review"),
        _info("opt", "Optional", default=False)])
    v = pv.PowerView(Config())
    qtbot.addWidget(v)
    return v


def _load(view):
    view._on_scan_finished(_result())


def test_cleaner_model_lists_supported_cleaners_with_badges(monkeypatch):
    monkeypatch.setattr(catalog, "list_cleaners", lambda cfg, **k: [
        _info("temp", "Temp"), _info("apt", "APT", root=True),
        _info("opt", "Optional", default=False),
        _info("big_files", "Big", category="review")])
    m = gm.CleanerListModel(Config())
    assert m.rowCount() == 4
    assert m.data(m.index(1), gm.BadgeRole) == "Admin"
    assert m.data(m.index(3), gm.BadgeRole) == "Review only"
    assert m.data(m.index(2), gm.BadgeRole) == "Opt-in"
    assert m.data(m.index(2), Qt.ItemDataRole.CheckStateRole) == Qt.CheckState.Unchecked
    assert "opt" not in m.enabled_ids()
    assert m.enabled_ids() == ["temp", "apt", "big_files"]
    m.setData(m.index(2), Qt.CheckState.Checked, Qt.ItemDataRole.CheckStateRole)
    assert "opt" in m.enabled_ids()


def test_real_catalog_populates_model():
    m = gm.CleanerListModel(Config())
    assert m.rowCount() > 0
    assert m.data(m.index(0), gm.IdRole)


def test_item_model_columns_roles_and_size_sort_key(view):
    _load(view)
    m = view.item_model
    assert [m.headerData(i, Qt.Orientation.Horizontal) for i in range(6)] == [
        "", "Cleaner", "Description", "Size", "Admin", "Type"]
    assert m.data(m.index(0, 3), Qt.ItemDataRole.UserRole) == 900 * 1024
    view.proxy.sort(3, Qt.SortOrder.AscendingOrder)
    sizes = [view.proxy.data(view.proxy.index(r, 3), Qt.ItemDataRole.UserRole)
             for r in range(view.proxy.rowCount())]
    assert sizes == sorted(sizes)
    first_two = sizes[:2]
    assert first_two == [900 * 1024, 5 * MB]
    assert sizes.index(10 * MB) > sizes.index(900 * 1024)
    view.proxy.sort(3, Qt.SortOrder.DescendingOrder)
    assert view.proxy.data(view.proxy.index(0, 3), Qt.ItemDataRole.UserRole) == 2000 * MB


def test_report_only_rows_are_not_checkable(view):
    _load(view)
    m = view.item_model
    row = next(r for r in range(m.rowCount()) if m.item_at(r).report_only)
    assert not (m.flags(m.index(row, 0)) & Qt.ItemFlag.ItemIsUserCheckable)
    assert m.data(m.index(row, 0), Qt.ItemDataRole.CheckStateRole) is None
    assert m.data(m.index(row, 5)) == "Review"
    assert m.set_checked(row, True) is False
    assert all(not i.report_only for i in m.checked_items())


def test_check_toggle_updates_checked_items(view):
    _load(view)
    m = view.item_model
    assert len(m.checked_items()) == 3
    m.set_checked(0, False)
    assert m.item_at(0) not in m.checked_items()
    assert len(m.checked_items()) == 2
    m.setData(m.index(0, 0), Qt.CheckState.Checked, Qt.ItemDataRole.CheckStateRole)
    assert len(m.checked_items()) == 3


def test_filter_text_hides_non_matching_rows(view):
    _load(view)
    assert view.proxy.rowCount() == 4
    view.filter_edit.setText("apt")
    assert view.proxy.rowCount() == 1
    view.filter_edit.setText("SMALL")
    assert view.proxy.rowCount() == 1
    view.filter_edit.setText("")
    assert view.proxy.rowCount() == 4


def _select(view, predicate):
    m = view.item_model
    row = next(r for r in range(m.rowCount()) if predicate(m.item_at(r)))
    idx = view.proxy.mapFromSource(m.index(row, 0))
    view.table.setCurrentIndex(idx)


def test_detail_pane_shows_hint_for_report_only_and_command_for_command_items(view):
    _load(view)
    _select(view, lambda i: i.report_only)
    assert "Delete it manually" in view.detail_label.text()
    assert "/x/huge.iso" in view.detail_label.text()
    _select(view, lambda i: i.kind is ItemKind.COMMAND)
    text = view.detail_label.text()
    assert "apt-get clean" in text
    assert "Requires administrator" in text


def test_dry_run_default_on_and_clean_uses_it(qtbot, monkeypatch, sync_workers):
    calls = []

    class Rec(FakeClean):
        def __init__(self, items, config, *, dry_run, use_quarantine):
            super().__init__()
            calls.append((len(items), dry_run, use_quarantine))

    monkeypatch.setattr(workers, "CleanWorker", Rec)
    v = pv.PowerView(Config())
    qtbot.addWidget(v)
    assert v.dry_run_check.isChecked() and v.quarantine_check.isChecked()
    _load(v)
    with qtbot.waitSignal(v.clean_finished):
        v.clean_button.click()
    assert calls[-1][1:] == (True, True)
    monkeypatch.setattr(pv.PowerView, "confirm_clean", lambda *a: True)
    v.dry_run_check.setChecked(False)
    v.quarantine_check.setChecked(False)
    v.clean_button.click()
    assert calls[-1][1:] == (False, False)


def test_unconfirmed_real_clean_does_nothing(qtbot, monkeypatch, sync_workers):
    calls = []
    monkeypatch.setattr(workers, "CleanWorker",
                        lambda *a, **k: calls.append(1) or FakeClean())
    monkeypatch.setattr(pv.PowerView, "confirm_clean", lambda *a: False)
    v = pv.PowerView(Config())
    qtbot.addWidget(v)
    _load(v)
    v.dry_run_check.setChecked(False)
    v.clean_button.click()
    assert calls == []


def test_export_json_matches_cli_schema(view, tmp_path, monkeypatch):
    monkeypatch.setattr(time, "strftime", lambda *a, **k: "2026-01-01T00:00:00")
    _load(view)
    out = tmp_path / "scan.json"
    view.export_scan_json(out)
    assert json.loads(out.read_text(encoding="utf-8")) == json.loads(
        report.scan_to_json(view._result))


def test_enabled_cleaners_are_passed_to_scan_as_only(qtbot, monkeypatch, sync_workers):
    monkeypatch.setattr(catalog, "list_cleaners", lambda cfg, **k: [
        _info("temp", "Temp"), _info("opt", "Optional", default=False)])
    seen = []
    v = pv.PowerView(
        Config(), scan_worker_factory=lambda only: seen.append(list(only))
        or FakeScan(_result()))
    qtbot.addWidget(v)
    with qtbot.waitSignal(v.scan_finished):
        v.scan_button.click()
    assert seen == [["temp"]]
    v.cleaner_model.setData(v.cleaner_model.index(1), Qt.CheckState.Checked,
                            Qt.ItemDataRole.CheckStateRole)
    v.scan_button.click()
    assert seen[-1] == ["temp", "opt"]
    assert v.item_model.rowCount() == 4


def test_default_scan_factory_builds_scan_worker_with_only(qtbot, monkeypatch, sync_workers):
    captured = {}

    class Rec(FakeScan):
        def __init__(self, config, only=None):
            super().__init__(_result())
            captured["only"] = only

    monkeypatch.setattr(workers, "ScanWorker", Rec)
    v = pv.PowerView(Config())
    qtbot.addWidget(v)
    v.scan_button.click()
    assert captured["only"] == v.cleaner_model.enabled_ids()


def test_table_cells_elide_with_tooltip_for_long_paths(view):
    _load(view)
    assert view.table.textElideMode() == Qt.TextElideMode.ElideMiddle
    m = view.item_model
    row = next(r for r in range(m.rowCount()) if m.item_at(r).size == 10 * MB)
    long_path = m.item_at(row).path
    tip = m.data(m.index(row, 2), Qt.ItemDataRole.ToolTipRole)
    assert long_path in tip
    # the displayed text is the full string; the view elides it visually
    assert m.data(m.index(row, 2), Qt.ItemDataRole.DisplayRole) == long_path
    cmd_row = next(r for r in range(m.rowCount())
                   if m.item_at(r).kind is ItemKind.COMMAND)
    assert "apt-get clean" in m.data(m.index(cmd_row, 2), Qt.ItemDataRole.ToolTipRole)


def test_every_toolbar_control_has_accessible_name(view):
    controls = [view.scan_button, view.clean_button, view.cancel_button,
                view.dry_run_check, view.quarantine_check, view.export_button,
                view.filter_edit, view.cleaner_list, view.table]
    for c in controls:
        assert c.accessibleName().strip(), c
    for b in view.scan_tab.findChildren(QAbstractButton):
        assert b.accessibleName().strip() or b.text().strip(), b


def test_panel_titles_and_add_panel(view):
    assert view.panel_titles() == ["Scan"]
    view.add_panel("Quarantine", QWidget())
    assert view.panel_titles() == ["Scan", "Quarantine"]


def test_clean_finished_emits_summary_and_updates_status(qtbot, monkeypatch, sync_workers):
    v = pv.PowerView(Config(), clean_worker_factory=lambda items, **k: FakeClean())
    qtbot.addWidget(v)
    _load(v)
    with qtbot.waitSignal(v.clean_finished) as sig:
        v.clean_button.click()
    assert sig.args[0].removed == 1
    assert "Would free" in v.status_label.text()
