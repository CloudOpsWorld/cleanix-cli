"""GUI side of the administrator-item parity (I-4).

The real views (Power item table, Simple cards) must make an administrator
item tickable exactly when the helper's own rules would clean it, using the
REAL helper allowlist (no ``fake_admin_allowlist`` here). Nothing is cleaned
or launched.
"""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import Qt  # noqa: E402

from cleanix import elevated  # noqa: E402
from cleanix.config import Config  # noqa: E402
from cleanix.core import catalog, registry  # noqa: E402
from cleanix.core.models import CleanableItem, CleanerReport, ItemKind, ScanResult  # noqa: E402
from cleanix.gui import power_view as pv  # noqa: E402
from cleanix.gui import workers  # noqa: E402
from cleanix.gui.models import ItemTableModel  # noqa: E402
from cleanix.gui.simple_view import SimpleView  # noqa: E402
# tests/ is on sys.path (pytest's rootdir-less "prepend" import of tests/*).
from test_admin_eligibility import (  # noqa: E402
    helper_static_accepts, windows_dirs, windows_path_items,
)

__all__ = ["windows_dirs"]  # fixture re-export


def admin_items():
    """One administrator item per registered cleaner (allowlisted or not),
    plus a report-only one per cleaner."""
    out = []
    for cid in sorted({cls.id for cls in registry.ALL_CLEANERS}):
        out.append(CleanableItem(cleaner_id=cid, description=f"{cid} admin", size=10,
                                 kind=ItemKind.COMMAND, command=["tool", cid],
                                 requires_root=True))
        out.append(CleanableItem(cleaner_id=cid, description=f"{cid} review", size=1,
                                 kind=ItemKind.COMMAND, command=["tool", cid],
                                 requires_root=True, report_only=True))
    return out


def as_result(items):
    reports = {}
    for i in items:
        reports.setdefault(i.cleaner_id, CleanerReport(i.cleaner_id, i.cleaner_id, "")
                           ).items.append(i)
    return ScanResult(reports=list(reports.values()))


def tickable(model: ItemTableModel, row: int) -> bool:
    flags = model.flags(model.index(row, 0))
    return bool(flags & Qt.ItemFlag.ItemIsUserCheckable)


def assert_power_parity(items, allowed):
    model = ItemTableModel(allow_admin_items=True)
    model.set_result(as_result(items))
    assert model.rowCount() == len(items)
    for row in range(model.rowCount()):
        item = model.item_at(row)
        gui = tickable(model, row)
        assert gui == helper_static_accepts(item, allowed), item.description
        assert gui == model.set_checked(row, True), item.description
        if not gui and not item.report_only:
            reason = model.admin_problem(item)
            assert reason, item.description
            assert reason in model.data(model.index(row, 0), Qt.ItemDataRole.ToolTipRole)
            assert reason in model.data(model.index(row, 4), Qt.ItemDataRole.ToolTipRole)
    # Unticked/refused rows never reach the selection.
    assert all(helper_static_accepts(i, allowed) for i in model.checked_items())


def test_power_table_ticks_exactly_what_the_helper_cleans(qtbot):
    allowed = elevated.admin_cleaner_ids()
    assert_power_parity(admin_items(), allowed)


def test_power_table_windows_path_rules(qtbot, windows_dirs, monkeypatch):
    monkeypatch.setattr(elevated, "admin_cleaner_ids", lambda: frozenset({"win_system_temp"}))
    items = windows_path_items(windows_dirs, "win_system_temp")
    assert_power_parity(items, frozenset({"win_system_temp"}))
    m = ItemTableModel(allow_admin_items=True)
    m.set_result(as_result(items))
    ok = {m.item_at(r).description for r in range(m.rowCount()) if tickable(m, r)}
    assert ok == {"plain file in Windows\\Temp", "memory dump"}


def test_simple_cards_offer_only_what_the_helper_cleans(qtbot):
    """Simple mode never pre-selects administrator items; any card it lets
    the user tick holds only items the helper would clean, and refused items
    are read-only with their reason in the card hint."""
    allowed = elevated.admin_cleaner_ids()
    items = admin_items()
    v = SimpleView(Config(), allow_admin_items=True)
    qtbot.addWidget(v)
    v.set_scan_result(as_result(items))
    seen = 0
    for card in v.cards():
        for i in card.items:
            seen += 1
            if card.mode != "readonly":
                assert helper_static_accepts(i, allowed), i.description
            elif not i.report_only and not helper_static_accepts(i, allowed):
                assert elevated.static_admin_problem(i, allowed) in card.hint_label.fullText()
        if card.mode == "readonly":
            assert not card.checkbox.isEnabled()
    assert seen == len(items)
    for card in v.cards():
        if card.mode != "readonly":
            card.checkbox.setChecked(True)
    assert all(helper_static_accepts(i, allowed) for i in v.selected_items())


def test_refused_admin_items_excluded_from_selection_total_and_confirm(qtbot, monkeypatch,
                                                                       fake_admin_allowlist):
    """Power: Select all visible skips refused admin rows, so they are not in
    the total, the confirmation text or the clean."""
    monkeypatch.setattr(workers, "start_worker", lambda w: w.run())
    monkeypatch.setattr(pv.PowerView, "show_results", lambda *a, **k: None)
    v = pv.PowerView(Config(), allow_admin_items=True)
    qtbot.addWidget(v)
    ok = CleanableItem("logs", "ok admin", size=100, kind=ItemKind.COMMAND,
                       command=["x"], requires_root=True)
    refused = CleanableItem("not_allowlisted", "refused admin", size=5000,
                            kind=ItemKind.COMMAND, command=["y"], requires_root=True)
    v._on_scan_finished(as_result([ok, refused]))
    v.select_all_visible()
    assert v.visible_checked_items() == [ok]
    texts = []
    monkeypatch.setattr(pv.PowerView, "confirm_clean", lambda self, t: texts.append(t) or False)
    v.dry_run_check.setChecked(False)
    v.start_clean()
    assert texts and texts[0].startswith("1 selected item(s)")
    row = [r for r in range(v.item_model.rowCount())
           if v.item_model.item_at(r) is refused][0]
    v.table.setCurrentIndex(v.proxy.mapFromSource(v.item_model.index(row, 1)))
    assert "Not selectable:" in v.detail_label.toPlainText()
    assert "fixed list of system locations" in v.detail_label.toPlainText()


def test_catalog_categories_are_known_for_every_admin_cleaner():
    # Guard for the parity tables above: every allowlisted id is a real cleaner.
    ids = {cls.id for cls in registry.ALL_CLEANERS}
    assert set(elevated.admin_cleaner_ids()) <= ids
    for cid in elevated.admin_cleaner_ids():
        assert catalog.category_of(cid) in catalog.CATEGORIES
