import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtWidgets import QPushButton  # noqa: E402

from cleanix.core import history, quarantine  # noqa: E402
from cleanix.gui.panels_data import HistoryPanel, QuarantinePanel, SparklineWidget  # noqa: E402

RUNS = [
    {"run_id": "run-a", "created": 1700000000, "count": 3, "size": 2048},
    {"run_id": "run-b", "created": 1700003600, "count": 1, "size": 10},
]


@pytest.fixture
def fake_q(monkeypatch):
    calls = {"restore": [], "purge": [], "purge_all": 0}
    state = {
        "runs": list(RUNS),
        "purge": (2048, []),
        "restore": {"restored": ["x", "y"], "failed": [("z", "boom")]},
    }
    monkeypatch.setattr(quarantine, "list_runs", lambda: list(state["runs"]))

    def restore(rid):
        calls["restore"].append(rid)
        return state["restore"]

    def purge(rid):
        calls["purge"].append(rid)
        return state["purge"]

    def purge_all():
        calls["purge_all"] += 1
        return state["purge"]

    monkeypatch.setattr(quarantine, "restore", restore)
    monkeypatch.setattr(quarantine, "purge_detailed", purge)
    monkeypatch.setattr(quarantine, "purge_all_detailed", purge_all)
    return calls, state


def _panel(qtbot, confirm=lambda m: True):
    p = QuarantinePanel(confirm=confirm)
    qtbot.addWidget(p)
    p.refresh()
    return p


def test_quarantine_panel_lists_runs(qtbot, fake_q):
    p = _panel(qtbot)
    assert p.table.rowCount() == 2
    assert p.table.item(0, 0).text() == "run-a"
    assert p.table.item(0, 2).text() == "3"
    assert p.table.item(0, 3).text() == "2.0 KiB"
    assert p.table.item(0, 0).toolTip() == "run-a"


def test_restore_calls_restore_and_reports_counts(qtbot, fake_q):
    calls, _ = fake_q
    p = _panel(qtbot)
    p.table.selectRow(0)
    p.restore_btn.click()
    assert calls["restore"] == ["run-a"]
    assert "2 restored" in p.status_label.text()
    assert "1 failed" in p.status_label.text()


def test_delete_run_reports_real_result_and_errors(qtbot, fake_q):
    calls, state = fake_q
    state["purge"] = (0, ["locked.txt"])
    p = _panel(qtbot)
    p.table.selectRow(1)
    p.delete_btn.click()
    assert calls["purge"] == ["run-b"]
    text = p.status_label.text()
    assert "locked.txt" in text
    assert "error" in text.lower()
    assert "0 B reclaimed" not in text


def test_delete_run_success_reports_bytes(qtbot, fake_q):
    p = _panel(qtbot)
    p.table.selectRow(0)
    p.delete_btn.click()
    assert "2.0 KiB reclaimed" in p.status_label.text()


def test_delete_and_empty_os_errors_are_shown_not_raised(qtbot, fake_q, monkeypatch):
    def boom(*a):
        raise PermissionError("access denied")

    monkeypatch.setattr(quarantine, "purge_detailed", boom)
    monkeypatch.setattr(quarantine, "purge_all_detailed", boom)
    p = _panel(qtbot)
    p.table.selectRow(0)
    p.delete_btn.click()  # must not raise into the event loop
    assert p.status_label.text().startswith("Delete failed:")
    assert "access denied" in p.status_label.text()
    p.status_label.setText("")
    p.empty_btn.click()
    assert p.status_label.text().startswith("Delete failed:")
    assert p.table.rowCount() == 2  # refreshed


@pytest.mark.parametrize("exc", [ValueError("bad manifest"), KeyError("original"),
                                 TypeError("string indices must be integers")])
def test_restore_corrupt_manifest_is_shown_not_raised(qtbot, fake_q, monkeypatch, exc):
    def boom(rid):
        raise exc

    monkeypatch.setattr(quarantine, "restore", boom)
    p = _panel(qtbot)
    p.table.selectRow(0)
    p.restore_btn.click()  # must not raise into the event loop
    assert p.status_label.text().startswith("Restore failed:")
    assert p.table.rowCount() == 2  # refreshed


def test_restore_real_corrupt_manifest(qtbot, tmp_path, monkeypatch):
    """A manifest whose item lacks "original" makes quarantine.restore raise
    KeyError; the panel reports it."""
    import json

    root = tmp_path / "quarantine"
    run = root / "run-x"
    run.mkdir(parents=True)
    (run / "manifest.json").write_text(json.dumps(
        {"run_id": "run-x", "created": 1, "items": [{"stored": "s", "size": 1}]}),
        encoding="utf-8")
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: root)
    p = _panel(qtbot)
    assert p.table.rowCount() == 1
    p.table.selectRow(0)
    p.restore_btn.click()
    assert p.status_label.text() == "Restore failed: missing entry 'original'"


def test_empty_all_requires_confirmation(qtbot, fake_q):
    calls, _ = fake_q
    p = _panel(qtbot, confirm=lambda m: False)
    p.empty_btn.click()
    assert calls["purge_all"] == 0
    p2 = _panel(qtbot)
    p2.empty_btn.click()
    assert calls["purge_all"] == 1


def test_restore_and_delete_need_confirmation_and_selection(qtbot, fake_q):
    calls, _ = fake_q
    p = _panel(qtbot, confirm=lambda m: False)
    p.table.selectRow(0)
    p.restore_btn.click()
    p.delete_btn.click()
    assert calls["restore"] == [] and calls["purge"] == []
    p2 = _panel(qtbot)
    p2.table.clearSelection()
    p2.restore_btn.click()
    assert calls["restore"] == []


def test_buttons_have_accessible_names(qtbot, fake_q):
    p = _panel(qtbot)
    buttons = p.findChildren(QPushButton)
    assert len(buttons) == 3
    for b in buttons:
        assert b.accessibleName()


def test_history_panel_totals_text(qtbot, monkeypatch):
    entries = [
        {"time": 1700000000 + i, "freed": 1024, "items": 2, "mode": "delete"}
        for i in range(3)
    ]
    monkeypatch.setattr(history, "stats", lambda: {
        "runs": 3, "total_freed": 3072, "total_items": 6,
        "last_time": 1700000002, "entries": entries})
    p = HistoryPanel()
    qtbot.addWidget(p)
    p.refresh()
    assert p.totals_label.text() == "3.0 KiB reclaimed across 3 run(s), 6 item(s)"
    assert p.table.rowCount() == 3
    assert p.sparkline.values() == [1024, 1024, 1024]


def test_sparkline_values_and_tooltip(qtbot):
    s = SparklineWidget()
    qtbot.addWidget(s)
    s.set_values([1, 2.5, 3])
    assert s.values() == [1, 2.5, 3]
    assert "2.5" in s.toolTip()
    s.resize(100, 30)
    s.grab()
    s.set_values([])
    s.grab()


def test_history_empty_state_message(qtbot, monkeypatch):
    monkeypatch.setattr(history, "stats", lambda: {
        "runs": 0, "total_freed": 0, "total_items": 0, "last_time": 0, "entries": []})
    p = HistoryPanel()
    qtbot.addWidget(p)
    p.refresh()
    assert "no clean runs" in p.totals_label.text().lower()
    assert p.sparkline.values() == []


def test_history_keeps_last_30_for_sparkline(qtbot, monkeypatch):
    entries = [
        {"time": 1700000000 + i, "freed": i, "items": 1, "mode": "delete"}
        for i in range(40)
    ]
    monkeypatch.setattr(history, "stats", lambda: {
        "runs": 40, "total_freed": 780, "total_items": 40,
        "last_time": 0, "entries": entries})
    p = HistoryPanel()
    qtbot.addWidget(p)
    p.refresh()
    assert p.sparkline.values() == list(range(10, 40))
