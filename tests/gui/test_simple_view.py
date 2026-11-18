import threading

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import QObject, Signal, Slot  # noqa: E402
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QWidget  # noqa: E402

from cleanix.config import Config  # noqa: E402
from cleanix.core import quarantine  # noqa: E402
from cleanix.core.models import (  # noqa: E402
    CleanableItem, CleanerReport, ItemKind, ScanResult,
)
from cleanix.core.service import CleanSummary  # noqa: E402
from cleanix.core.models import CleanResult  # noqa: E402
from cleanix.gui import simple_view  # noqa: E402
from cleanix.gui.simple_view import (  # noqa: E402
    ConfirmCleanDialog, ConfirmInfo, ElidedLabel, SimpleState, SimpleView,
)

GB = 1024 ** 3

# Fake cleaner ids (apt/temp) count as helper-allowlisted here.
pytestmark = pytest.mark.usefixtures("fake_admin_allowlist")


def item(cid="temp", size=1000, **kw):
    kw.setdefault("path", f"/tmp/{cid}/{size}")
    return CleanableItem(cleaner_id=cid, description=f"{cid} stuff", size=size, **kw)


def result(*items):
    reports = {}
    for i in items:
        reports.setdefault(i.cleaner_id, CleanerReport(i.cleaner_id, i.cleaner_id, "")).items.append(i)
    return ScanResult(reports=list(reports.values()))


class FakeWorker(QObject):
    """Worker that blocks in run() until released; honours cancel()."""

    progress = Signal(str, int, int)
    finished = Signal(object)
    cancelled = Signal()
    failed = Signal(str)

    def __init__(self, outcome=None, block=False):
        super().__init__()
        self.outcome = outcome
        self.gate = threading.Event()
        if not block:
            self.gate.set()
        self.cancel_flag = threading.Event()
        self.started = threading.Event()

    def cancel(self):
        self.cancel_flag.set()
        self.gate.set()

    @Slot()
    def run(self):
        self.started.set()
        self.gate.wait(5)
        self.finish()

    def finish(self):
        if self.cancel_flag.is_set():
            self.cancelled.emit()
        else:
            self.finished.emit(self.outcome)


class FakeCleanWorker(FakeWorker):
    """Like CleanWorker: emits finished(partial summary) even after a cancel."""

    def finish(self):
        s = self.outcome
        s.cancelled = self.cancel_flag.is_set()
        self.finished.emit(s)


def rows(tree):
    return {tree.topLevelItem(i).text(0): tree.topLevelItem(i)
            for i in range(tree.topLevelItemCount())}


def row(tree, title):
    return rows(tree)[title]


def tick(tree, title, on=True):
    row(tree, title).setCheckState(
        0, Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)


def all_trees(v):
    return (v.results_tree, v.also_tree, v.review_tree)


def make_view(qtbot, scan=None, clean=None, confirm=None, allow_admin=False, calls=None):
    def clean_factory(items, cfg, **kw):
        if calls is not None:
            calls.append(kw)
        return clean

    v = SimpleView(
        Config(),
        scan_worker_factory=(lambda cfg, deep=False: scan) if scan else None,
        clean_worker_factory=clean_factory if clean else None,
        confirm=confirm or (lambda info: (True, True)),
        allow_admin_items=allow_admin,
    )
    qtbot.addWidget(v)
    v.show()
    return v


def summary(freed=5000, removed=2, run="run1", cancelled=False, errors=()):
    return CleanSummary(result=CleanResult(), quarantine_run=run, freed=freed,
                        removed=removed, errors=list(errors), cancelled=cancelled)


def test_idle_state_shows_scan_button_only(qtbot):
    v = make_view(qtbot)
    assert v.state() is SimpleState.IDLE
    assert v.scan_button.isVisible()
    assert not v.clean_button.isVisible()
    assert not v.cancel_scan_button.isVisible()
    assert not v.undo_button.isVisible()


def test_idle_page_has_headline_reassurance_and_deep_scan_off(qtbot):
    v = make_view(qtbot)
    assert v.headline_label.text()
    assert v.reassurance_label.text() == (
        "Nothing is deleted until you review it. Most cleanups can be undone.")
    assert v.scan_button.isDefault() and v.scan_button.minimumHeight() >= 40
    assert v.deep_scan_check.text() == "Deep scan (slower: duplicates, big files)"
    assert not v.deep_scan_check.isChecked()


def test_deep_scan_flag_is_forwarded_to_factory(qtbot):
    seen = []

    def factory(cfg, deep=False):
        seen.append(deep)
        return FakeWorker(outcome=result(item("temp", 10)))

    v = SimpleView(Config(), scan_worker_factory=factory)
    qtbot.addWidget(v)
    v.start_scan()
    qtbot.waitUntil(lambda: v.state() is SimpleState.RESULTS, timeout=3000)
    v.deep_scan_check.setChecked(True)
    v.start_scan()
    qtbot.waitUntil(lambda: len(seen) == 2, timeout=3000)
    assert seen == [False, True]
    qtbot.waitUntil(lambda: v.state() is SimpleState.RESULTS, timeout=3000)


def test_default_scan_factory_excludes_slow_unless_deep(monkeypatch):
    made = []

    class Spy:
        def __init__(self, config, exclude=None):
            made.append(exclude)

    monkeypatch.setattr(simple_view.workers, "ScanWorker", Spy)
    simple_view._default_scan_factory(Config())
    simple_view._default_scan_factory(Config(), deep=True)
    assert made[0] == list(simple_view.SLOW) and made[1] is None


def test_results_are_curated_groups_with_total_label(qtbot):
    v = make_view(qtbot)
    v.set_scan_result(result(item("temp", 1000), item("temp", 500), item("browsers", 2000)))
    assert v.state() is SimpleState.RESULTS
    assert isinstance(v.results_tree, simple_view.GroupedResults)
    top = rows(v.results_tree)
    assert set(top) == {"Temporary files", "Browser caches"}
    assert top["Temporary files"].text(3) == "2"
    assert top["Temporary files"].text(4) == simple_view.human_size(1500)
    assert top["Temporary files"].checkState(0) is Qt.CheckState.Checked
    assert v.results_total_label.text() == (
        f"{simple_view.human_size(3500)} can be freed")
    assert v.clean_button_text() == f"Clean {simple_view.human_size(3500)}"


def test_empty_result_says_nothing_found(qtbot):
    v = make_view(qtbot)
    v.set_scan_result(result())
    assert v.results_summary.text() == "Nothing found to clean."
    assert v.selected_items() == []
    assert not v.clean_button.isEnabled()


def test_review_groups_in_own_collapsed_unticked_section(qtbot):
    v = make_view(qtbot)
    v.set_scan_result(result(
        item("temp", 10),
        item("big_files", 40, report_only=True, hint="Delete by hand"),
        item("toolchains", 50)))
    assert set(rows(v.review_tree)) == {"Largest files", "Old toolchain versions"}
    assert "Largest files" not in rows(v.results_tree)
    assert v.review_toggle.text() == "Needs your review"
    assert not v.review_expanded() and not v.review_container.isVisible()
    assert v.review_tree.checked_items() == []
    v.review_toggle.setChecked(True)
    assert v.review_container.isVisible()
    assert [i.cleaner_id for i in v.selected_items()] == ["temp"]


def test_selected_items_equal_ticked_groups(qtbot):
    a, b = item("temp", 10), item("browsers", 20)
    v = make_view(qtbot)
    v.set_scan_result(result(a, b))
    assert sorted(i.size for i in v.selected_items()) == [10, 20]
    tick(v.results_tree, "Temporary files", False)
    assert v.selected_items() == [b]
    assert v.selected_size() == 20


def test_only_safe_items_are_preselected(qtbot):
    safe = item("temp", 100)
    report = item("temp", 200, report_only=True)
    root = item("temp", 300, requires_root=True)
    cmd = item("temp", 400, kind=ItemKind.COMMAND, path=None, command=["x"])
    trash = item("trash", 500)
    unknown = item("brand_new_cleaner", 600)
    v = make_view(qtbot)
    v.set_scan_result(result(safe, report, root, cmd, trash, unknown))
    assert v.selected_items() == [safe]
    assert v.selected_size() == 100


def test_unreviewed_cleaner_never_preselected(qtbot):
    v = make_view(qtbot)
    v.set_scan_result(result(item("brand_new_cleaner", 600)))
    assert v.selected_items() == []
    assert v.clean_button_text() == "Nothing selected"
    assert not v.clean_button.isEnabled()
    assert v.review_tree.group_count() == 1
    assert v.review_tree.checked_items() == []


def test_clean_button_text_tracks_selection(qtbot):
    v = make_view(qtbot)
    v.set_scan_result(result(item("temp", 2 * GB), item("browsers", 2 * GB + GB // 5)))
    assert v.clean_button_text() == "Clean 4.2 GiB"
    assert v.clean_button.text() == "Clean 4.2 GiB"
    assert v.results_total_label.text() == "4.2 GiB can be freed"
    tick(v.results_tree, "Temporary files", False)
    assert v.selected_size() == 2 * GB + GB // 5
    assert v.clean_button.text() == "Clean 2.2 GiB"
    tick(v.results_tree, "Browser caches", False)
    assert v.clean_button.text() == "Nothing selected"
    assert not v.clean_button.isEnabled()


def test_also_found_section_is_collapsed_and_unchecked_by_default(qtbot):
    v = make_view(qtbot)
    v.set_scan_result(result(
        item("temp", 10), item("trash", 20), item("apt", 30, requires_root=True),
        item("big_files", 40, report_only=True, hint="Delete by hand"),
    ))
    assert not v.also_found_expanded()
    assert not v.also_found_container.isVisible()
    assert set(rows(v.also_tree)) == {"APT cache and unused packages"}
    assert set(rows(v.review_tree)) == {"Trash", "Largest files"}
    assert v.also_tree.checked_items() == [] and v.review_tree.checked_items() == []
    assert len(v.selected_items()) == 1
    v.also_found_toggle.setChecked(True)
    assert v.also_found_container.isVisible()
    v.review_toggle.setChecked(True)
    tick(v.review_tree, "Trash")
    assert {i.cleaner_id for i in v.selected_items()} == {"temp", "trash"}
    # report-only items are never cleanable
    assert all(not i.report_only for i in v.selected_items())


def test_confirm_dialog_mentions_count_size_and_undo(qtbot):
    d = ConfirmCleanDialog(ConfirmInfo(3, 2 * GB))
    qtbot.addWidget(d)
    assert "3 items" in d.summary_label.text()
    assert "2.0 GiB" in d.summary_label.text()
    assert "undone" in d.warning_label.text() and "cannot" not in d.warning_label.text()
    assert d.clean_button.text() == "Clean" and d.cancel_button.text() == "Cancel"


def test_quarantine_checkbox_default_checked(qtbot):
    d = ConfirmCleanDialog(ConfirmInfo(1, 10))
    qtbot.addWidget(d)
    assert d.keep_copy_checkbox.text() == (
        "Keep a copy so I can undo (uses disk space until emptied)")
    assert d.keep_copy_checkbox.isChecked() and d.keep_copy()
    d.keep_copy_checkbox.setChecked(False)
    assert "cannot be undone" in d.warning_label.text()
    d.keep_copy_checkbox.setChecked(True)
    assert "cannot" not in d.warning_label.text()


def test_confirm_decline_does_not_start_clean(qtbot):
    calls = []
    v = make_view(qtbot, confirm=lambda info: calls.append(info) or (False, True))
    v.set_scan_result(result(item("temp", 10)))
    v.clean_button.click()
    assert calls[0].count == 1 and calls[0].size == 10
    assert v.state() is SimpleState.RESULTS


def test_cancel_during_scan_returns_to_idle_without_error(qtbot):
    w = FakeWorker(outcome=result(item()), block=True)
    v = make_view(qtbot, scan=w)
    v.scan_button.click()
    assert v.state() is SimpleState.SCANNING
    assert v.cancel_scan_button.isVisible()
    qtbot.waitUntil(w.started.is_set, timeout=3000)
    v.cancel_scan_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.IDLE, timeout=3000)
    assert v.error_label.text() == ""
    assert v.selected_items() == []


def test_scan_failure_returns_to_idle_with_message(qtbot):
    class Bad(FakeWorker):
        def finish(self):
            self.failed.emit("boom")

    v = make_view(qtbot, scan=Bad())
    v.scan_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.IDLE, timeout=3000)
    assert "boom" in v.error_label.text()


def test_scan_flow_reaches_results_and_emits_scanned(qtbot):
    w = FakeWorker(outcome=result(item("temp", 10)))
    v = make_view(qtbot, scan=w)
    with qtbot.waitSignal(v.scanned, timeout=3000):
        v.scan_button.click()
    assert v.state() is SimpleState.RESULTS
    assert v.clean_button.isEnabled()


def test_cancel_during_clean_reports_partial_and_enters_done(qtbot):
    cw = FakeCleanWorker(outcome=summary(freed=1234, removed=1, run="r9"), block=True)
    v = make_view(qtbot, clean=cw)
    v.set_scan_result(result(item("temp", 10), item("browsers", 20)))
    emitted = []
    v.request_clean.connect(emitted.append)
    v.clean_button.click()
    assert v.state() is SimpleState.CLEANING
    assert len(emitted[0]) == 2
    qtbot.waitUntil(cw.started.is_set, timeout=3000)
    v.cancel_clean_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.DONE, timeout=3000)
    assert "Stopped early" in v.done_label.text()
    assert "1.2 KiB" in v.done_label.text()
    assert v.undo_button.isEnabled()  # the partial run is still undoable


def test_done_state_shows_freed_and_undo_restores(qtbot, monkeypatch):
    calls = []
    monkeypatch.setattr(
        quarantine, "restore",
        lambda run: calls.append(run) or {"restored": ["a", "b"], "failed": [("c", "x")]})
    cw = FakeCleanWorker(outcome=summary(freed=3 * GB, removed=4, run="run42"))
    v = make_view(qtbot, clean=cw)
    v.set_scan_result(result(item("temp", 10)))
    v.clean_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.DONE, timeout=3000)
    assert "3.0 GiB" in v.done_label.text() and "Stopped" not in v.done_label.text()
    assert v.errors_label.text() == "0 errors"
    assert v.undo_button.isEnabled()
    v.undo_button.click()
    assert calls == ["run42"]
    assert "Restored 2 items" in v.undo_label.text()
    assert "1 could not be restored" in v.undo_label.text()
    assert not v.undo_button.isEnabled()


def test_undo_failure_is_reported(qtbot, monkeypatch):
    def boom(run):
        raise FileNotFoundError("gone")

    monkeypatch.setattr(quarantine, "restore", boom)
    v = make_view(qtbot, clean=FakeCleanWorker(outcome=summary()))
    v.set_scan_result(result(item("temp", 10)))
    v.clean_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.DONE, timeout=3000)
    v.undo_button.click()
    assert "gone" in v.undo_label.text()


def test_undo_disabled_when_no_quarantine_run(qtbot):
    v = make_view(qtbot, clean=FakeCleanWorker(outcome=summary(run=None)))
    v.set_scan_result(result(item("temp", 10)))
    v.clean_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.DONE, timeout=3000)
    assert not v.undo_button.isEnabled()


def test_long_unicode_and_rtl_labels_are_elided_with_tooltip(qtbot):
    lbl = ElidedLabel("short")
    qtbot.addWidget(lbl)
    lbl.resize(300, 20)
    assert lbl.elidedText() == "short"
    arabic = "مجلد الملفات المؤقتة الطويل جدا " * 12
    for text in ("x" * 300, arabic):
        lbl = ElidedLabel(text)
        qtbot.addWidget(lbl)
        lbl.resize(320, 20)
        assert lbl.toolTip() == text and lbl.fullText() == text
        assert lbl.elidedText() != text
        assert lbl.minimumSizeHint().width() == 0


def _chain(start):
    seen, w = [], start
    while True:
        seen.append(w)
        w = w.nextInFocusChain()
        if w is start or w in seen:
            return seen


def test_tab_order_reaches_scan_clean_and_cancel_buttons(qtbot):
    v = make_view(qtbot)
    chain = _chain(v.scan_button)
    buttons = [v.scan_button, v.clean_button, v.cancel_scan_button, v.cancel_clean_button,
               v.undo_button]
    for b in buttons:
        assert b in chain
        assert b.accessibleName().strip()
    for w in chain:
        if isinstance(w, QWidget) and hasattr(w, "isCheckable") and w.accessibleName() == "":
            assert not w.text().strip() == ""
    v.set_scan_result(result(item("temp", 10)))
    chain = _chain(v.scan_button)
    for tree in all_trees(v):
        assert tree in chain
        assert tree.accessibleName()
    assert v.deep_scan_check in chain


def cmd_item(cid="win_recycle_bin", size=100):
    return item(cid, size, kind=ItemKind.COMMAND, path=None, command=["empty"])


def test_confirm_warns_when_command_items_cannot_be_undone(qtbot):
    infos = []
    v = make_view(qtbot, confirm=lambda info: infos.append(info) or (False, True))
    v.set_scan_result(result(item("temp", 10), cmd_item()))
    v.also_found_toggle.setChecked(True)
    tick(v.also_tree, "Recycle Bin")
    v.clean_button.click()
    assert infos[0].irreversible == 1 and infos[0].trash_items == 1
    d = ConfirmCleanDialog(infos[0])
    qtbot.addWidget(d)
    assert "cannot be undone" in d.warning_label.text()
    assert "1 selected item cannot be undone" in d.warning_label.text()
    d.keep_copy_checkbox.setChecked(False)
    assert "1 selected item cannot be undone" in d.warning_label.text()


def test_all_command_selection_disables_keep_copy(qtbot):
    d = ConfirmCleanDialog(ConfirmInfo(2, 10, irreversible=2))
    qtbot.addWidget(d)
    assert not d.keep_copy_checkbox.isEnabled()
    assert not d.keep_copy()
    assert "cannot be undone" in d.warning_label.text()
    assert "kept in quarantine" not in d.warning_label.text()


def test_done_explains_disabled_undo(qtbot):
    v = make_view(qtbot, clean=FakeCleanWorker(outcome=summary(run=None)))
    v.set_scan_result(result(cmd_item()))
    v.also_found_toggle.setChecked(True)
    tick(v.also_tree, "Recycle Bin")
    v.clean_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.DONE, timeout=3000)
    assert not v.undo_button.isEnabled()
    assert "cannot be undone" in v.undo_label.text()
    v = make_view(qtbot, clean=FakeCleanWorker(outcome=summary(run=None)),
                  confirm=lambda info: (True, False))
    v.set_scan_result(result(item("temp", 10)))
    v.clean_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.DONE, timeout=3000)
    assert "not to keep a copy" in v.undo_label.text()


def _root_result():
    return result(item("temp", 10), item("apt", 20, requires_root=True),
                  item("docker", 30))


def test_admin_items_not_selectable_by_default(qtbot):
    v = make_view(qtbot)
    v.set_scan_result(_root_result())
    v.also_found_toggle.setChecked(True)
    assert all(not i.requires_root for i in v.selected_items())
    tick(v.review_tree, "Docker leftovers")
    assert all(not i.requires_root for i in v.selected_items())
    assert v.selected_size() == 40
    assert v.clean_button_text() == "Clean 40 B"
    apt = row(v.also_tree, "APT cache and unused packages")
    assert not (apt.flags() & Qt.ItemFlag.ItemIsUserCheckable)
    assert "administrator" in apt.text(1).lower()
    apt.setCheckState(0, Qt.CheckState.Checked)
    assert v.selected_size() == 40


def test_admin_items_selectable_when_allowed(qtbot):
    v = make_view(qtbot, allow_admin=True)
    v.set_scan_result(_root_result())
    v.also_found_toggle.setChecked(True)
    tick(v.also_tree, "APT cache and unused packages")
    tick(v.review_tree, "Docker leftovers")
    assert any(i.requires_root for i in v.selected_items())
    assert v.selected_size() == 60
    v2 = make_view(qtbot, allow_admin=True)
    v2.set_scan_result(result(item("temp", 5, requires_root=True)))
    assert v2.selected_items() == []


def test_set_allow_admin_items_updates_trees_and_selection(qtbot):
    v = make_view(qtbot, allow_admin=True)
    v.set_scan_result(_root_result())
    tick(v.also_tree, "APT cache and unused packages")
    assert v.selected_size() == 30
    v.set_allow_admin_items(False, "Helper unavailable")
    assert any(i.requires_root for i in v.selected_items()) is False
    assert len(v.selected_items()) == 1 and v.selected_size() == 10
    apt = row(v.also_tree, "APT cache and unused packages")
    assert "Helper unavailable" in apt.text(1)
    assert v.clean_button.text() == "Clean 10 B"


def test_quarantine_choice_is_passed_to_clean_worker(qtbot):
    calls = []
    v = make_view(qtbot, clean=FakeCleanWorker(outcome=summary()), calls=calls)
    v.set_scan_result(result(item("temp", 10)))
    v.clean_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.DONE, timeout=3000)
    assert calls == [{"dry_run": False, "use_quarantine": True}]
    calls2 = []
    v = make_view(qtbot, clean=FakeCleanWorker(outcome=summary(run=None)), calls=calls2,
                  confirm=lambda info: (True, False))
    v.set_scan_result(result(item("temp", 10)))
    v.clean_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.DONE, timeout=3000)
    assert calls2 == [{"dry_run": False, "use_quarantine": False}]


def test_declined_confirm_never_creates_worker(qtbot):
    calls = []
    v = make_view(qtbot, clean=FakeCleanWorker(outcome=summary()), calls=calls,
                  confirm=lambda info: (False, True))
    emitted = []
    v.request_clean.connect(emitted.append)
    v.set_scan_result(result(item("temp", 10)))
    v.clean_button.click()
    assert calls == [] and emitted == []
    assert v.state() is SimpleState.RESULTS


@pytest.mark.parametrize("kind", ["cancelled", "failed"])
def test_clean_stopped_without_summary_forces_rescan(qtbot, kind):
    class W(FakeWorker):
        def finish(self):
            if kind == "failed":
                self.failed.emit("disk gone")
            else:
                self.cancelled.emit()

    v = make_view(qtbot, clean=W())
    v.set_scan_result(result(item("temp", 10)))
    v.clean_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.IDLE, timeout=3000)
    assert "scan again" in v.error_label.text()
    assert v.selected_items() == [] and v.results_tree.group_count() == 0


def test_cancelled_rescan_from_results_clears_old_cards(qtbot):
    w = FakeWorker(outcome=result(item()), block=True)
    v = make_view(qtbot, scan=w)
    v.set_scan_result(result(item("temp", 10)))
    assert v.results_tree.group_count() == 1
    v.rescan_button.click()
    qtbot.waitUntil(w.started.is_set, timeout=3000)
    v.cancel_scan_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.IDLE, timeout=3000)
    assert v.results_tree.group_count() == 0 and v.selected_items() == []


def test_double_start_guard(qtbot):
    made = []
    w = FakeWorker(outcome=result(item()), block=True)

    def factory(cfg, deep=False):
        made.append(1)
        return w

    v = SimpleView(Config(), scan_worker_factory=factory)
    qtbot.addWidget(v)
    v.start_scan()
    v.start_scan()
    assert len(made) == 1
    w.cancel()
    qtbot.waitUntil(lambda: v.state() is SimpleState.IDLE, timeout=3000)


def test_late_cancel_with_uncancelled_summary_is_not_stopped_early(qtbot):
    class Late(FakeWorker):
        def finish(self):  # cancel arrived after the last item
            self.finished.emit(self.outcome)

    cw = Late(outcome=summary(cancelled=False), block=True)
    v = make_view(qtbot, clean=cw)
    v.set_scan_result(result(item("temp", 10)))
    v.clean_button.click()
    qtbot.waitUntil(cw.started.is_set, timeout=3000)
    v.cancel_clean_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.DONE, timeout=3000)
    assert "Stopped" not in v.done_label.text()


def test_unticked_command_card_does_not_count_as_irreversible(qtbot):
    infos = []
    v = make_view(qtbot, confirm=lambda info: infos.append(info) or (False, True))
    v.set_scan_result(result(item("temp", 10), cmd_item()))
    v.clean_button.click()
    assert infos[0].irreversible == 0 and infos[0].count == 1
    d = ConfirmCleanDialog(infos[0])
    qtbot.addWidget(d)
    assert "cannot be undone" not in d.warning_label.text()


def test_confirm_dialog_mentions_trash_items(qtbot):
    d = ConfirmCleanDialog(ConfirmInfo(3, 10, trash_items=2))
    qtbot.addWidget(d)
    assert "2 items from Trash / Recycle Bin which are removed permanently" in (
        d.warning_label.text())
    infos = []
    v = make_view(qtbot, confirm=lambda info: infos.append(info) or (False, True))
    v.set_scan_result(result(item("temp", 10), item("trash", 5)))
    v.also_found_toggle.setChecked(True)
    tick(v.review_tree, "Trash")
    v.clean_button.click()
    assert infos[0].trash_items == 1


PERMANENT_TRASH = "from Trash / Recycle Bin which are removed permanently"
KEPT_TRASH = "from Trash / Recycle Bin are kept in quarantine like the other files"


def test_trash_files_kept_in_quarantine_are_not_called_permanent(qtbot):
    """Trash PATH items go to quarantine like other files when a copy is
    kept; only command items (Recycle Bin) or a no-copy clean are permanent."""
    infos = []
    v = make_view(qtbot, confirm=lambda info: infos.append(info) or (False, True))
    v.set_scan_result(result(item("temp", 10), item("trash", 5), item("trash", 6)))
    v.also_found_toggle.setChecked(True)
    tick(v.review_tree, "Trash")
    v.clean_button.click()
    info = infos[0]
    assert info.trash_items == 2 and info.trash_path_items == 2
    d = ConfirmCleanDialog(info)
    qtbot.addWidget(d)
    assert d.keep_copy_checkbox.isChecked()
    text = d.warning_label.text()
    assert PERMANENT_TRASH not in text
    assert "2 items " + KEPT_TRASH in text
    d.keep_copy_checkbox.setChecked(False)
    text = d.warning_label.text()
    assert "Including 2 items " + PERMANENT_TRASH in text
    assert KEPT_TRASH not in text


def test_recycle_bin_command_is_permanent_even_with_keep_copy(qtbot):
    d = ConfirmCleanDialog(ConfirmInfo(3, 10, irreversible=1, trash_items=2,
                                       trash_path_items=1))
    qtbot.addWidget(d)
    text = d.warning_label.text()
    assert "Including 1 item " + PERMANENT_TRASH in text
    assert "1 item from Trash / Recycle Bin is kept in quarantine" in text
    d.keep_copy_checkbox.setChecked(False)
    text = d.warning_label.text()
    assert "Including 2 items " + PERMANENT_TRASH in text
    assert "kept in quarantine like" not in text


def test_admin_wait_message_wraps_and_is_never_elided(qtbot):
    from cleanix.gui import elevation

    v = make_view(qtbot)
    v._set_state(SimpleState.CLEANING)
    v.resize(320, 400)
    v.show()
    v._on_clean_progress(elevation.ADMIN_WAIT_MESSAGE, 0, 0)
    label = v.clean_wait_label
    assert label.isVisible() and not v.clean_status.isVisible()
    assert label.wordWrap() and label.text() == elevation.ADMIN_WAIT_MESSAGE
    assert "decline the prompt to skip administrator items" in label.text()
    assert not v.cancel_clean_button.isEnabled()
    # A new clean shows the normal (single-line) status again.
    v._set_state(SimpleState.RESULTS)
    v._start_clean_ui_reset()
    assert not v.clean_status.isHidden() and v.clean_wait_label.isHidden()
    assert v.cancel_clean_button.isEnabled()


def test_non_selectable_rows_show_their_reason(qtbot):
    from cleanix.gui.grouped_results import ADMIN_REASON, REVIEW_ONLY_REASON

    v = make_view(qtbot)
    rep = item("temp", 1, report_only=True, hint="Review by hand")
    adm = item("temp", 2, requires_root=True)
    v.set_scan_result(result(rep, adm))
    assert v.results_tree.refusal_reason(rep) == REVIEW_ONLY_REASON
    assert v.results_tree.refusal_reason(adm) == ADMIN_REASON
    assert "administrator" in ADMIN_REASON.lower()
    # a report-only item that also needs root keeps the report-only reason
    both = item("big_files", 1, report_only=True, requires_root=True,
                hint="Delete manually")
    v.set_scan_result(result(both))
    g = row(v.review_tree, "Largest files")
    assert not (g.flags() & Qt.ItemFlag.ItemIsUserCheckable)
    assert g.text(1) == REVIEW_ONLY_REASON
    assert v.review_tree.refusal_reason(both) == REVIEW_ONLY_REASON
    assert v.review_tree.checked_items() == []
    # custom admin reason is used when admin items are unavailable
    v2 = SimpleView(Config(), admin_unavailable_reason="Helper unavailable")
    qtbot.addWidget(v2)
    v2.set_scan_result(result(item("apt", 5, requires_root=True)))
    g2 = row(v2.also_tree, "APT cache and unused packages")
    assert g2.text(1) == "Helper unavailable"


def test_mixed_group_keeps_safe_item_preselected(qtbot):
    safe = item("temp", 100)
    rep = item("temp", 50, report_only=True)
    v = make_view(qtbot)
    v.set_scan_result(result(safe, rep))
    assert "Temporary files" in rows(v.results_tree)
    assert "Temporary files" not in rows(v.review_tree)
    assert v.selected_items() == [safe]
    assert v.selected_size() == 100
    assert rep not in v.results_tree.checked_items()


def test_clean_finished_and_undone_signals(qtbot, monkeypatch):
    monkeypatch.setattr(quarantine, "restore", lambda run: {"restored": ["a"], "failed": []})
    s = summary(run="run7")
    v = make_view(qtbot, clean=FakeCleanWorker(outcome=s))
    finished, undone = [], []
    v.clean_finished.connect(finished.append)
    v.undone.connect(lambda: undone.append(True))
    v.set_scan_result(result(item("temp", 10)))
    v.clean_button.click()
    qtbot.waitUntil(lambda: v.state() is SimpleState.DONE, timeout=3000)
    assert finished == [s]
    v.undo_button.click()
    assert undone == [True]


def test_shutdown_cancels_running_worker_and_blocks_new_work(qtbot):
    sw = FakeWorker(outcome=result(item("temp", 10)), block=True)
    created = []

    def scan_factory(cfg, deep=False):
        created.append(cfg)
        return sw

    v = SimpleView(Config(), scan_worker_factory=scan_factory,
                   confirm=lambda info: (True, True))
    qtbot.addWidget(v)
    v.start_scan()
    qtbot.waitUntil(sw.started.is_set, timeout=3000)
    v.shutdown()
    v.shutdown()  # idempotent
    assert sw.cancel_flag.is_set()
    qtbot.waitUntil(lambda: v.state() is SimpleState.IDLE, timeout=3000)
    v.start_scan()
    assert len(created) == 1 and v.state() is SimpleState.IDLE
