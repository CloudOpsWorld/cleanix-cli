import threading

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import QObject, Signal, Slot  # noqa: E402
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
    CategoryCard, ConfirmCleanDialog, ConfirmInfo, ElidedLabel, SimpleState, SimpleView,
)

GB = 1024 ** 3


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


def make_view(qtbot, scan=None, clean=None, confirm=None):
    v = SimpleView(
        Config(),
        scan_worker_factory=(lambda cfg: scan) if scan else None,
        clean_worker_factory=(lambda items, cfg, **kw: clean) if clean else None,
        confirm=confirm or (lambda info: (True, True)),
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


def test_results_group_items_into_category_cards_with_sizes(qtbot):
    v = make_view(qtbot)
    v.set_scan_result(result(item("temp", 1000), item("temp", 500), item("browsers", 2000)))
    assert v.state() is SimpleState.RESULTS
    by_cat = {c.category: c for c in v.cards()}
    assert by_cat["temp"].size == 1500 and len(by_cat["temp"].items) == 2
    assert by_cat["temp"].count_label.text() == "2 items"
    assert by_cat["temp"].size_label.text() == simple_view.human_size(1500)
    assert by_cat["browser"].size == 2000
    assert "1.5 KiB" in by_cat["temp"].checkbox.accessibleName()
    assert by_cat["temp"].label_widget.fullText() in by_cat["temp"].checkbox.accessibleName()
    assert by_cat["temp"].is_checked()


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
    card = v.cards()[0]
    assert card.mode == "readonly" and not card.checkbox.isEnabled()
    assert not card.is_checked()


def test_clean_button_text_tracks_selection(qtbot):
    v = make_view(qtbot)
    v.set_scan_result(result(item("temp", 2 * GB), item("browsers", 2 * GB + GB // 5)))
    assert v.clean_button_text() == "Free 4.2 GiB"
    assert v.clean_button.text() == "Free 4.2 GiB"
    temp = next(c for c in v.cards() if c.category == "temp")
    temp.checkbox.setChecked(False)
    assert v.selected_size() == 2 * GB + GB // 5
    assert v.clean_button.text() == "Free 2.2 GiB"
    next(c for c in v.cards() if c.category == "browser").checkbox.setChecked(False)
    assert v.clean_button.text() == "Nothing selected"
    assert not v.clean_button.isEnabled()


def test_also_found_section_is_collapsed_and_unchecked_by_default(qtbot):
    v = make_view(qtbot)
    v.set_scan_result(result(
        item("temp", 10), item("trash", 20), item("apt", 30),
        item("big_files", 40, report_only=True, hint="Delete by hand"),
    ))
    assert not v.also_found_expanded()
    assert not v.also_found_container.isVisible()
    also = {c.category: c for c in v.cards() if c.mode != "select"}
    assert set(also) == {"trash", "system", "review"}
    assert all(not c.is_checked() for c in also.values())
    assert also["trash"].checkbox.isEnabled() and also["system"].checkbox.isEnabled()
    assert not also["review"].checkbox.isEnabled()
    assert also["review"].hint_label.fullText() == "Delete by hand"
    assert len(v.selected_items()) == 1
    v.also_found_toggle.setChecked(True)
    assert v.also_found_container.isVisible()
    also["trash"].checkbox.setChecked(True)
    assert {i.cleaner_id for i in v.selected_items()} == {"temp", "trash"}
    # report-only items are never cleanable, even if their card is forced on
    also["review"].checkbox.setChecked(True)
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
    assert v.cards() == []


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
    arabic = "مجلد الملفات المؤقتة الطويل جدا " * 12
    for text in ("x" * 300, arabic):
        card = CategoryCard("other", text, [item("temp", 5)], mode="select", checked=True)
        qtbot.addWidget(card)
        card.resize(320, 60)
        card.show()
        qtbot.waitExposed(card)
        lbl = card.label_widget
        assert lbl.toolTip() == text and lbl.fullText() == text
        assert lbl.width() <= card.width()
        assert lbl.elidedText() != text
        assert card.minimumSizeHint().width() < 400
    lbl = ElidedLabel("short")
    qtbot.addWidget(lbl)
    lbl.resize(300, 20)
    assert lbl.elidedText() == "short"


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
    for c in v.cards():
        assert c.checkbox in _chain(v.scan_button)
        assert c.checkbox.accessibleName()
