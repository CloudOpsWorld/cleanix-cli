"""GUI presentation of Windows registry findings (never touches the registry)."""
import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from cleanix.config import Config  # noqa: E402
from cleanix.core import catalog, curation, quarantine  # noqa: E402
from cleanix.core.models import (  # noqa: E402
    CleanableItem, CleanerReport, ItemKind, RegTarget, ScanResult,
)
from cleanix.gui import elevation, reveal  # noqa: E402
from cleanix.gui import models as gm  # noqa: E402
from cleanix.gui import power_view as pv  # noqa: E402
from cleanix.gui import simple_view  # noqa: E402
from cleanix.gui.grouped_results import GroupedResults  # noqa: E402
from cleanix.gui.panels_data import QuarantinePanel  # noqa: E402
from cleanix.gui.simple_view import SimpleView  # noqa: E402

CID = "win_reg_uninstall"


def reg_item(hive="HKCU", name="Foo", hint="InstallLocation C:\\Foo: missing"):
    key = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{name}"
    return CleanableItem(
        cleaner_id=CID, description=f"Uninstall entry {name}", kind=ItemKind.REGISTRY,
        reg=RegTarget(hive, key, None, "fp" + name), requires_root=(hive == "HKLM"),
        hint=hint)


def result(*items):
    return ScanResult(reports=[CleanerReport(CID, "Registry: dead uninstall entries",
                                             "", items=list(items))])


@pytest.fixture(autouse=True)
def _allow_registry_admin(monkeypatch):
    # Registry ids join the helper allowlist in another task; not under test here.
    monkeypatch.setattr(elevation, "admin_problems", lambda items: {})


def test_simple_registry_items_read_only_with_power_hint(qtbot):
    v = SimpleView(Config(), allow_admin_items=True)
    qtbot.addWidget(v)
    a, b = reg_item("HKCU", "A"), reg_item("HKLM", "B")
    v.set_scan_result(result(a, b))
    tree = v.review_tree
    assert tree.group_count() == 1
    assert v.results_tree.group_count() == 0 and v.also_tree.group_count() == 0
    assert tree.checked_items() == [] and v.selected_items() == []
    for it in (a, b):
        assert tree.refusal_reason(it) == SimpleView.NOT_FROM_SIMPLE


@pytest.mark.parametrize("osname,visible", [("windows", True), ("linux", False),
                                            ("macos", False)])
def test_simple_registry_note_only_on_windows(qtbot, monkeypatch, osname, visible):
    monkeypatch.setattr(simple_view, "current_os", lambda: osname)
    v = SimpleView(Config())
    qtbot.addWidget(v)
    v.show()
    assert v.registry_note.text() == "Registry leftovers are checked only in Power mode."
    assert v.registry_note.isVisible() is visible
    assert v.registry_note.isHidden() is (not visible)


def _info():
    return catalog.CleanerInfo(
        id=CID, name="Registry: dead uninstall entries", description="d",
        requires_root=False, platforms=("windows",), supported=True,
        default_enabled=False, safe_default=False, category="registry")


@pytest.fixture
def pview(qtbot, monkeypatch):
    monkeypatch.setattr(catalog, "list_cleaners", lambda cfg, **k: [_info()])
    v = pv.PowerView(Config())
    qtbot.addWidget(v)
    return v


def test_power_registry_group_review_badge_and_opt_in(pview):
    info = _info()
    it = reg_item()
    assert curation.safety_of(it, info) is curation.Safety.REVIEW
    assert not catalog.preselect(it, info)
    pview._on_scan_finished(result(it, reg_item("HKLM", "B")))
    m = pview.item_model
    assert m.rowCount() == 2 and m.checked_items() == []
    assert pview.cleaner_model.enabled_ids() == []  # opt-in


def test_registry_items_never_selected_by_safe_only(pview):
    pview._on_scan_finished(result(reg_item(), reg_item("HKLM", "B")))
    pview.select_safe_only()
    assert pview.item_model.checked_items() == []


def test_power_confirm_text_registry_lines():
    u1 = [reg_item("HKCU", "A")]
    t = pv.PowerView.confirm_text(u1, 0, True)
    assert ("1 registry entry will be backed up first and can be restored from the "
            "Quarantine tab.") in t
    assert "permanently" not in t
    t = pv.PowerView.confirm_text(u1 + [reg_item("HKCU", "B")], 0, False)
    assert ("2 registry entries will be backed up first and can be restored from the "
            "Quarantine tab.") in t
    assert "permanently" not in t  # every item is registry: line omitted

    h = [reg_item("HKLM", "A")]
    t = pv.PowerView.confirm_text(h, 0, True)
    assert ("1 administrator registry entry will be backed up first; restoring them "
            "needs an Administrator terminal (cleanix restore).") in t
    assert "removed permanently" not in t and "need administrator" not in t
    t = pv.PowerView.confirm_text(h + [reg_item("HKLM", "B")], 0, True)
    assert "2 administrator registry entries will be backed up first;" in t

    files = [CleanableItem("temp", "x", size=5, path="/tmp/x")]
    t = pv.PowerView.confirm_text(files + u1 + h, 0, False)
    assert ("Files and commands will be permanently removed; registry entries are "
            "still backed up.") in t
    assert "These items will be permanently removed" not in t
    assert "1 registry entry will be backed up first" in t
    assert "1 administrator registry entry will be backed up first" in t
    assert "need administrator" not in t
    admin_file = CleanableItem("apt", "y", path="/y", requires_root=True)
    t = pv.PowerView.confirm_text([admin_file] + h, 0, True)
    assert "1 item(s) need administrator permission" in t
    assert t.endswith("Continue?")


def test_power_detail_text_registry():
    t = pv.PowerView.detail_text(reg_item("HKCU", "Foo"))
    lines = t.splitlines()
    assert lines[1] == (r"Registry: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion"
                        r"\Uninstall\Foo")
    assert "Evidence: InstallLocation C:\\Foo: missing" in lines
    assert "Backed up before removal (.reg in quarantine)." in lines
    assert "Requires administrator" not in t and "Path:" not in t
    t = pv.PowerView.detail_text(reg_item("HKLM", "Foo"))
    assert "Requires administrator" in t.splitlines()


def test_grouped_results_copy_path_and_no_open_location_for_registry(qtbot, monkeypatch):
    it = reg_item("HKLM", "Foo")
    g = curation.Group(cleaner_id=CID, title="Dead", blurb="b", category="registry",
                       safety=curation.Safety.REVIEW, items=[it], shown=[it],
                       rest=[], zero=[], total_size=0)
    w = GroupedResults()
    qtbot.addWidget(w)
    w.set_groups([g], lambda i: False)
    w.copy_path(it)
    assert QApplication.clipboard().text() == it.reg.display

    def boom(p):
        raise AssertionError("reveal must not be called")
    monkeypatch.setattr(reveal, "reveal_in_file_manager", boom)
    assert w.open_location(it) is False
    w.expandItem(w.topLevelItem(0))
    child = w.topLevelItem(0).child(0)
    assert it.reg.display in child.toolTip(0)
    assert w.menu_labels(it) == ["Copy path"]
    plain = CleanableItem("x", "d", path="/x/y")
    assert w.menu_labels(plain) == ["Copy path", "Open location"]


def test_table_type_and_target_columns_registry():
    it = reg_item("HKCU", "Foo")
    assert gm._type_label(it) == "Registry"
    assert gm._target_text(it) == it.reg.display
    m = gm.ItemTableModel()
    m.set_result(result(it))
    assert m.data(m.index(0, 5)) == "Registry"
    assert it.reg.display in m.data(m.index(0, 2), Qt.ItemDataRole.ToolTipRole)
    assert gm._type_label(CleanableItem("t", "d", path="/x")) == "Path"


def test_quarantine_panel_shows_registry_count_and_reasons(qtbot, monkeypatch):
    runs = [{"run_id": "r1", "created": 1700000000, "count": 5, "size": 10,
             "registry": 2, "registry_admin": 1},
            {"run_id": "r2", "created": 1700000001, "count": 3, "size": 0}]
    monkeypatch.setattr(quarantine, "list_runs", lambda: list(runs))
    failed = [(f"k{i}", f"reason {i}") for i in range(5)]
    monkeypatch.setattr(quarantine, "restore",
                        lambda rid: {"restored": ["a"], "failed": failed})
    p = QuarantinePanel(confirm=lambda m: True)
    qtbot.addWidget(p)
    p.refresh()
    assert p.table.item(0, 2).text() == "5 (2 registry)"
    assert p.table.item(1, 2).text() == "3"
    p.table.selectRow(0)
    p._on_restore()
    text = p.status_label.text()
    assert "1 restored, 5 failed." in text
    for i in range(3):
        assert f"k{i} (reason {i})" in text
    assert "k3" not in text and "+2 more" in text
