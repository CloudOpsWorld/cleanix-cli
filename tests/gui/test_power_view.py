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

# Fake cleaner ids (apt/logs/temp) count as helper-allowlisted here.
pytestmark = pytest.mark.usefixtures("fake_admin_allowlist")


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
            CleanableItem("temp", "big cache dir", size=10 * MB, path=big_path),
            CleanableItem("temp", "unicode", size=1, path="C:/Users/שלום/über/缓存"),
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
    def __init__(self, items=(), dry_run=True):
        super().__init__()
        self.items = list(items)
        self.dry_run = dry_run

    def run(self):
        from cleanix.core.models import CleanOutcome, CleanResult
        from cleanix.core.service import CleanSummary
        outs = [CleanOutcome(i, removed=not self.dry_run, freed=i.size,
                             dry_run=self.dry_run) for i in self.items]
        self.finished.emit(CleanSummary(
            result=CleanResult(outcomes=outs, dry_run=self.dry_run),
            freed=1, removed=1))


@pytest.fixture
def fake_catalog(monkeypatch):
    monkeypatch.setattr(catalog, "list_cleaners", lambda cfg, **k: [
        _info("temp", "Temp"), _info("apt", "APT", root=True, category="system"),
        _info("big_files", "Big files", category="review"),
        _info("opt", "Optional", default=False)])


@pytest.fixture
def sync_workers(monkeypatch, fake_catalog):
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


def test_admin_badge_tooltips_say_administrator(view):
    m = view.cleaner_model
    assert "Needs administrator permission" in m.data(m.index(1), Qt.ItemDataRole.ToolTipRole)
    assert m.data(m.index(0), Qt.ItemDataRole.ToolTipRole) == "Temp desc"
    assert m.data(m.index(1), gm.DescriptionRole) == "APT desc"
    _load(view)
    t = view.item_model
    rows = {t.item_at(r).description: r for r in range(t.rowCount())}
    admin_row, user_row = rows["apt clean"], rows["small cache"]
    assert t.data(t.index(admin_row, 4)) == "Admin"
    assert t.data(t.index(admin_row, 4), Qt.ItemDataRole.ToolTipRole) == (
        "Needs administrator permission")
    assert t.data(t.index(user_row, 4), Qt.ItemDataRole.ToolTipRole) is None


def test_no_results_dialog_once_shutting_down(view, monkeypatch):
    from cleanix.core.models import CleanResult
    from cleanix.core.service import CleanSummary

    shown, finished = [], []
    monkeypatch.setattr(pv.PowerView, "show_results", lambda *a, **k: shown.append(a))
    view.clean_finished.connect(finished.append)
    s = CleanSummary(result=CleanResult(dry_run=True), freed=0, removed=0)
    view._on_clean_finished(s)
    assert len(shown) == 1
    view.shutdown()
    view._on_clean_finished(s)
    assert len(shown) == 1 and finished == [s, s]


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
    first_two = sizes[1:3]
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
    assert m.item_at(0) in m.checked_items()
    m.set_checked(0, False)
    assert m.item_at(0) not in m.checked_items()
    assert len(m.checked_items()) == 2
    m.setData(m.index(0, 0), Qt.CheckState.Checked, Qt.ItemDataRole.CheckStateRole)
    assert len(m.checked_items()) == 3


def test_filter_text_hides_non_matching_rows(view):
    _load(view)
    assert view.proxy.rowCount() == 5
    view.filter_edit.setText("apt")
    assert view.proxy.rowCount() == 1
    view.filter_edit.setText("SMALL")
    assert view.proxy.rowCount() == 1
    view.filter_edit.setText("")
    assert view.proxy.rowCount() == 5


def _select(view, predicate):
    m = view.item_model
    row = next(r for r in range(m.rowCount()) if predicate(m.item_at(r)))
    idx = view.proxy.mapFromSource(m.index(row, 0))
    view.table.setCurrentIndex(idx)


def test_detail_pane_shows_hint_for_report_only_and_command_for_command_items(view):
    _load(view)
    _select(view, lambda i: i.report_only)
    assert "Delete it manually" in view.detail_label.toPlainText()
    assert "/x/huge.iso" in view.detail_label.toPlainText()
    _select(view, lambda i: i.kind is ItemKind.COMMAND)
    text = view.detail_label.toPlainText()
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


def test_export_os_error_is_shown_in_status_not_raised(view, tmp_path, monkeypatch):
    _load(view)
    target = tmp_path / "a-directory"
    target.mkdir()  # writing a file to a directory path raises OSError
    monkeypatch.setattr(pv.QFileDialog, "getSaveFileName",
                        staticmethod(lambda *a, **k: (str(target), "JSON (*.json)")))
    view._on_export_clicked()  # must not raise into the Qt slot
    assert view.status_label.text().startswith("Export failed:")
    ok = tmp_path / "scan.json"
    monkeypatch.setattr(pv.QFileDialog, "getSaveFileName",
                        staticmethod(lambda *a, **k: (str(ok), "JSON (*.json)")))
    view._on_export_clicked()
    assert ok.exists() and view.status_label.text() == f"Exported to {ok}"


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
    assert v.item_model.rowCount() == 5


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
    assert m.data(m.index(row, 2), Qt.ItemDataRole.DisplayRole) == "big cache dir"
    assert long_path != m.item_at(row).description
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
    v = pv.PowerView(Config(), clean_worker_factory=lambda items, **k: FakeClean(items))
    qtbot.addWidget(v)
    _load(v)
    with qtbot.waitSignal(v.clean_finished) as sig:
        v.clean_button.click()
    assert sig.args[0].removed == 1
    assert "Would free" in v.status_label.text()


def _stub_real_clean(monkeypatch, texts, seen):
    monkeypatch.setattr(pv.PowerView, "confirm_clean",
                        lambda self, text: texts.append(text) or True)

    def factory(items, *, dry_run, use_quarantine):
        seen.append(list(items))
        return FakeClean(items, dry_run=dry_run)
    return factory


def test_initial_checked_set_equals_preselect_set(qtbot, monkeypatch, sync_workers):
    import dataclasses
    infos = [_info("temp", "Temp"),
             _info("trashy", "Trash", category="trash"),
             dataclasses.replace(_info("unsafe", "Unsafe"), safe_default=False)]
    monkeypatch.setattr(catalog, "list_cleaners", lambda cfg, **k: infos)
    res = ScanResult(reports=[
        CleanerReport("temp", "Temp", "t", items=[
            CleanableItem("temp", "plain", size=1, path="/t/a"),
            CleanableItem("temp", "cmd", size=1, kind=ItemKind.COMMAND, command=["x"]),
        ]),
        CleanerReport("trashy", "Trash", "t", items=[
            CleanableItem("trashy", "bin", size=1, path="/t/trash")]),
        CleanerReport("unsafe", "Unsafe", "t", items=[
            CleanableItem("unsafe", "u", size=1, path="/t/u")]),
    ])
    v = pv.PowerView(Config(), allow_admin_items=True)
    qtbot.addWidget(v)
    v._on_scan_finished(res)
    assert [i.description for i in v.item_model.checked_items()] == ["plain"]
    m = v.item_model
    assert all(m.flags(m.index(r, 0)) & Qt.ItemFlag.ItemIsUserCheckable
               for r in range(m.rowCount()))


def test_unknown_cleaner_starts_unchecked(qtbot, monkeypatch, sync_workers):
    monkeypatch.setattr(catalog, "list_cleaners", lambda cfg, **k: [])
    v = pv.PowerView(Config())
    qtbot.addWidget(v)
    _load(v)
    assert v.item_model.checked_items() == []


def test_clean_only_visible_items_and_confirm_mentions_hidden(
        qtbot, monkeypatch, sync_workers, view):
    texts, seen = [], []
    v = pv.PowerView(Config(), allow_admin_items=True,
                     clean_worker_factory=_stub_real_clean(monkeypatch, texts, seen))
    qtbot.addWidget(v)
    _load(v)
    v.select_all_visible()
    assert len(v.item_model.checked_items()) == 4  # all non-report-only
    v.filter_edit.setText("apt")
    v.dry_run_check.setChecked(False)
    v.clean_button.click()
    assert [i.cleaner_id for i in seen[0]] == ["apt"]
    assert "1 selected item(s)" in texts[0]
    assert "3 more checked item(s) are hidden by the filter and will NOT be cleaned" in texts[0]


def test_select_all_visible_only_filtered_in_and_never_report_only(
        qtbot, sync_workers):
    view = pv.PowerView(Config(), allow_admin_items=True)
    qtbot.addWidget(view)
    _load(view)
    view.select_none_visible()
    assert view.item_model.checked_items() == []
    view.filter_edit.setText("apt")
    view.select_all_visible()
    assert [i.cleaner_id for i in view.item_model.checked_items()] == ["apt"]
    view.filter_edit.setText("")
    view.select_all_visible()
    assert all(not i.report_only for i in view.item_model.checked_items())
    assert len(view.item_model.checked_items()) == 4
    view.filter_edit.setText("temp")
    view.select_none_visible()
    assert [i.cleaner_id for i in view.item_model.checked_items()] == ["apt"]


def test_admin_rows_not_checkable_by_default(view):
    _load(view)
    m = view.item_model
    row = next(r for r in range(m.rowCount()) if m.item_at(r).requires_root)
    assert not (m.flags(m.index(row, 0)) & Qt.ItemFlag.ItemIsUserCheckable)
    assert m.data(m.index(row, 0), Qt.ItemDataRole.CheckStateRole) is None
    assert m.data(m.index(row, 4)) == "Admin"
    assert m.set_checked(row, True) is False
    view.select_all_visible()
    assert not any(i.requires_root for i in m.checked_items())
    assert len(m.checked_items()) == 3
    _select(view, lambda i: i.requires_root)
    assert "not available until elevation is supported" in view.detail_label.toPlainText()


def test_admin_rows_checkable_when_allowed_but_start_unchecked(qtbot, sync_workers):
    v = pv.PowerView(Config(), allow_admin_items=True)
    qtbot.addWidget(v)
    _load(v)
    m = v.item_model
    row = next(r for r in range(m.rowCount()) if m.item_at(r).requires_root)
    assert m.flags(m.index(row, 0)) & Qt.ItemFlag.ItemIsUserCheckable
    assert not m.is_checked(row)
    assert m.set_checked(row, True) is True
    assert m.item_at(row) in m.checked_items()
    _select(v, lambda i: i.requires_root)
    assert "not available until" not in v.detail_label.toPlainText()


def test_start_scan_and_clean_ignored_while_worker_running(qtbot, monkeypatch):
    monkeypatch.setattr(workers, "start_worker", lambda w: None)  # never finishes
    n = []
    v = pv.PowerView(Config(), scan_worker_factory=lambda only: n.append(1) or FakeScan(_result()))
    qtbot.addWidget(v)
    v.start_scan()
    v.start_scan()
    assert n == [1]
    v._result = _result()
    v.item_model.set_result(_result(), lambda i: True)
    v.start_clean()
    assert v.status_label.text() == "Scanning..."


def test_shutdown_cancels_worker_and_is_idempotent(qtbot, monkeypatch):
    monkeypatch.setattr(workers, "start_worker", lambda w: None)
    cancelled = []

    class W(FakeScan):
        def cancel(self):
            cancelled.append(1)

    v = pv.PowerView(Config(), scan_worker_factory=lambda only: W())
    qtbot.addWidget(v)
    pv.PowerView(Config()).shutdown()  # nothing running: no error
    v.start_scan()
    v.shutdown()
    v.shutdown()
    assert cancelled == [1]


def test_detail_pane_handles_long_unicode_paths_and_is_keyboard_reachable(view):
    _load(view)
    _select(view, lambda i: i.size == 10 * MB)
    d = view.detail_label
    path = view.item_model.item_at(
        next(r for r in range(view.item_model.rowCount())
             if view.item_model.item_at(r).size == 10 * MB)).path
    assert path in d.toolTip() and path in d.toPlainText()
    assert d.lineWrapMode() == d.LineWrapMode.WidgetWidth
    flags = d.textInteractionFlags()
    assert flags & Qt.TextInteractionFlag.TextSelectableByKeyboard
    assert d.focusPolicy() in (Qt.FocusPolicy.StrongFocus, Qt.FocusPolicy.TabFocus)
    _select(view, lambda i: i.size == 1)
    uni = next(i for i in _result().all_items() if i.size == 1).path
    assert uni in d.toolTip()
    m = view.item_model
    row = next(r for r in range(m.rowCount()) if m.item_at(r).size == 1)
    assert uni in m.data(m.index(row, 2), Qt.ItemDataRole.ToolTipRole)


def test_second_clean_after_real_clean_does_not_resubmit(qtbot, monkeypatch, sync_workers):
    texts, seen = [], []
    v = pv.PowerView(Config(), clean_worker_factory=_stub_real_clean(monkeypatch, texts, seen))
    qtbot.addWidget(v)
    _load(v)
    v.dry_run_check.setChecked(False)
    first = len(v.item_model.checked_items())
    assert first > 0
    v.clean_button.click()
    assert len(seen[0]) == first
    assert v.item_model.checked_items() == []
    v.clean_button.click()
    assert len(seen) == 1


def test_dry_run_keeps_rows(qtbot, monkeypatch, sync_workers):
    seen = []
    v = pv.PowerView(Config(), clean_worker_factory=lambda items, **k: (
        seen.append(1) or FakeClean(items, dry_run=True)))
    qtbot.addWidget(v)
    _load(v)
    n = v.item_model.rowCount()
    v.clean_button.click()
    assert v.item_model.rowCount() == n


def test_confirm_text_keep_copy_and_permanent():
    cmd = CleanableItem("apt", "x", size=MB, kind=ItemKind.COMMAND, command=["a"])
    path = CleanableItem("temp", "y", size=MB, path="/t")
    keep = pv.PowerView.confirm_text([cmd, path], 0, True)
    assert "restore" in keep and "cannot be kept" in keep and "permanently" not in keep
    perm = pv.PowerView.confirm_text([path], 2, False)
    assert "permanently removed" in perm and "cannot be undone" in perm
    assert "2 more checked" in perm
    assert "hidden" not in pv.PowerView.confirm_text([path], 0, False)


def _two_item_view(qtbot, monkeypatch, outcome_removed):
    from cleanix.core.models import CleanOutcome, CleanResult
    from cleanix.core.service import CleanSummary

    class W(FakeScan):
        def __init__(self, items, dry_run=False):
            super().__init__()
            self.items = list(items)
            self.dry_run = dry_run

        def run(self):
            outs = [CleanOutcome(i, removed=outcome_removed(i), freed=i.size)
                    for i in self.items]
            self.finished.emit(CleanSummary(result=CleanResult(outcomes=outs, dry_run=self.dry_run),
                                            freed=1, removed=1))

    texts, seen = [], []
    monkeypatch.setattr(pv.PowerView, "confirm_clean",
                        lambda self, text: texts.append(text) or True)

    def factory(items, *, dry_run, use_quarantine):
        seen.append((list(items), dry_run, use_quarantine))
        return W(items, dry_run)
    v = pv.PowerView(Config(), clean_worker_factory=factory)
    qtbot.addWidget(v)
    _load(v)
    v.dry_run_check.setChecked(False)
    return v, texts, seen


def test_failed_rows_stay_after_real_clean(qtbot, monkeypatch, sync_workers):
    v, _t, seen = _two_item_view(qtbot, monkeypatch, lambda i: i.path == "/tmp/a")
    before = list(v.item_model.checked_items())
    assert len(before) == 3
    v.clean_button.click()
    left = v.item_model.checked_items()
    assert "/tmp/a" not in [i.path for i in left]
    assert [i.path for i in left] == [i.path for i in before if i.path != "/tmp/a"]
    assert v.item_model.rowCount() == 4


def test_keep_copy_reflected_in_confirm_and_factory(qtbot, monkeypatch, sync_workers):
    v, texts, seen = _two_item_view(qtbot, monkeypatch, lambda i: False)
    v.clean_button.click()
    assert seen[-1][2] is True and "restore" in texts[-1]
    v.quarantine_check.setChecked(False)
    v.clean_button.click()
    assert seen[-1][2] is False
    assert "permanently removed" in texts[-1] and "restore" not in texts[-1]


def test_detail_pane_reset_after_rows_removed(qtbot, monkeypatch, sync_workers):
    v, _t, _s = _two_item_view(qtbot, monkeypatch, lambda i: True)
    _select(v, lambda i: i.path == "/tmp/a")
    assert "/tmp/a" in v.detail_label.toPlainText()
    v.clean_button.click()
    assert "/tmp/a" not in v.detail_label.toPlainText()
    assert "/tmp/a" not in v.detail_label.toolTip()


def _paths_in(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    return [(i["path"] or "").replace("\\", "/")
            for r in data["cleaners"] for i in r["items"]]


def test_export_after_real_clean_excludes_removed_but_dry_run_keeps(
        qtbot, monkeypatch, sync_workers, tmp_path):
    monkeypatch.setattr(time, "strftime", lambda *a, **k: "2026-01-01T00:00:00")
    v, _t, _s = _two_item_view(qtbot, monkeypatch, lambda i: i.path == "/tmp/a")
    v.dry_run_check.setChecked(True)
    v.clean_button.click()  # dry run: nothing deleted, rows stay
    out = tmp_path / "dry.json"
    v.export_scan_json(out)
    assert "/tmp/a" in _paths_in(out)
    v.dry_run_check.setChecked(False)
    v.clean_button.click()
    out2 = tmp_path / "real.json"
    v.export_scan_json(out2)
    paths = _paths_in(out2)
    assert "/tmp/a" not in paths and "/x/huge.iso" in paths
    assert any(i.path == "/tmp/a" for i in v._result.all_items())


def test_shutdown_keeps_start_guard_up(qtbot, monkeypatch):
    monkeypatch.setattr(workers, "start_worker", lambda w: None)
    n = []
    v = pv.PowerView(Config(), scan_worker_factory=lambda only: n.append(1) or FakeScan(_result()))
    qtbot.addWidget(v)
    v.start_scan()
    v.shutdown()
    v.start_scan()
    v.start_clean()
    assert n == [1]
    v._on_cancelled()  # old worker finishes; still no new work
    v.start_scan()
    assert n == [1]
