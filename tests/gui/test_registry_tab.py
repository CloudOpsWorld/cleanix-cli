"""Task 12: the Registry tab (Windows only). Never touches the registry:
scans are fake workers, removal goes through a recorded service.clean /
elevation seam."""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import QObject, Qt, Signal, Slot  # noqa: E402
from PySide6.QtWidgets import QLabel  # noqa: E402

from cleanix.config import Config  # noqa: E402
from cleanix.core import catalog, regpromises, service  # noqa: E402
from cleanix.core.models import (  # noqa: E402
    CleanableItem, CleanerReport, CleanOutcome, CleanResult, ItemKind, RegTarget,
    ScanResult,
)
from cleanix.gui import elevation, workers  # noqa: E402
from cleanix.gui import power_view as pv  # noqa: E402
from cleanix.gui import registry_view as rv  # noqa: E402
from cleanix.gui.registry_view import RegistryView  # noqa: E402


def info(cid, category="registry", default=False):
    return catalog.CleanerInfo(
        id=cid, name=cid, description="d", requires_root=False,
        platforms=("windows",), supported=True, default_enabled=default,
        safe_default=False, category=category)


REG_INFOS = [info(c) for c in catalog.REGISTRY_IDS]
TEMP = info("temp", category="temp", default=True)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setattr(catalog, "list_cleaners", lambda cfg, **k: [TEMP] + REG_INFOS)
    monkeypatch.setattr(elevation, "admin_problems", lambda items: {})
    monkeypatch.setattr(workers, "start_worker", lambda w: w.run())


def reg_item(cid="win_reg_uninstall", hive="HKCU", name="Foo"):
    return CleanableItem(
        cleaner_id=cid, description=f"Entry {name}", kind=ItemKind.REGISTRY,
        reg=RegTarget(hive, rf"SOFTWARE\Test\{name}", None, "fp" + name),
        requires_root=(hive == "HKLM"), hint="target missing")


def full_result():
    reps = [CleanerReport("temp", "Temp", "t",
                          items=[CleanableItem("temp", "tmp", size=5, path="/tmp/a")])]
    for k, cid in enumerate(reversed(catalog.REGISTRY_IDS)):
        reps.append(CleanerReport(cid, cid, "d", items=[reg_item(cid, name=f"N{k}")]))
    return ScanResult(reports=reps)


class FakeScan(QObject):
    progress = Signal(str, int, int)
    finished = Signal(object)
    cancelled = Signal()
    failed = Signal(str)

    def __init__(self, result):
        super().__init__()
        self.result = result

    def cancel(self):
        pass

    @Slot()
    def run(self):
        self.finished.emit(self.result)


class ScanFactory:
    def __init__(self, result=None):
        self.calls = []
        self.result = result or full_result()

    def __call__(self, config, only=None):
        self.calls.append(list(only or []))
        return FakeScan(self.result)


def make(qtbot, **kw):
    kw.setdefault("scan_worker_factory", ScanFactory())
    v = RegistryView(Config(), **kw)
    qtbot.addWidget(v)
    return v


# ------------------------------------------------------------------ tabs
@pytest.mark.parametrize("osname,present", [("windows", True), ("linux", False),
                                            ("macos", False)])
def test_registry_tab_only_on_windows(qtbot, app_env, monkeypatch, osname, present):
    from cleanix.gui import main_window

    monkeypatch.setattr(main_window, "current_os", lambda: osname)
    w = main_window.MainWindow(scan_worker_factory=ScanFactory(), elevation_available=False)
    qtbot.addWidget(w)
    assert ("Registry" in w.power_view.panel_titles()) is present
    assert (w.registry_view is not None) is present
    if present:
        idx = w.power_view.panel_titles().index("Registry")
        assert w.power_view.tabs.widget(idx) is w.registry_view
        assert idx == 2  # Scan | Review | Registry | ...


def test_registry_items_not_in_scan_tab(qtbot):
    v = pv.PowerView(Config())
    qtbot.addWidget(v)
    listed = {v.cleaner_model.info_at(r).id for r in range(v.cleaner_model.rowCount())}
    assert listed == {"temp"}
    assert not set(v.cleaner_model.enabled_ids()) & set(catalog.REGISTRY_IDS)
    v._on_scan_finished(full_result())
    m = v.item_model
    assert [m.item_at(r).cleaner_id for r in range(m.rowCount())] == ["temp"]
    assert {g.cleaner_id for g in v.tree._groups} == {"temp"}
    # Even ticking every cleaner never scans a registry detector there.
    seen = []
    v._scan_factory = lambda only: seen.append(list(only)) or FakeScan(ScanResult())
    v.start_scan()
    assert seen and not set(seen[0]) & set(catalog.REGISTRY_IDS)


def test_registry_scan_opt_in_no_autostart(qtbot):
    factory = ScanFactory()
    v = make(qtbot, scan_worker_factory=factory)
    v.show()
    qtbot.wait(10)
    assert factory.calls == []
    assert v.tree.group_count() == 0
    assert "Nothing is scanned until you click Scan registry" in v.status_label.text()
    v.scan_button.click()
    assert factory.calls == [list(catalog.REGISTRY_IDS)]
    # Grouped by detector, in the fixed order; the temp report is ignored.
    assert [g.cleaner_id for g in v.tree._groups] == list(catalog.REGISTRY_IDS)
    titles = [v.tree.topLevelItem(i).text(0) for i in range(v.tree.topLevelItemCount())]
    assert "Dead uninstall entries" in titles[0]
    assert v.selected_items() == []  # nothing preselected
    assert not v.remove_button.isEnabled()


def test_registry_footer_no_undo_promise(qtbot, monkeypatch):
    monkeypatch.setattr(regpromises, "UNDO_SHIPPED", False)
    v = make(qtbot)
    assert v.footer_label.text() == regpromises.PERMANENT_LINE
    assert v.footer_label.textFormat() == Qt.TextFormat.PlainText
    v.scan_button.click()
    item = v.tree._groups[0].items[0]
    d = v.confirm_dialog([item])
    text = d.summary.text() + d.body.toPlainText()
    assert regpromises.PERMANENT_LINE in text
    assert "can be restored" not in text and "Quarantine tab" not in text
    for label in d.findChildren(QLabel):
        assert label.textFormat() == Qt.TextFormat.PlainText
    monkeypatch.setattr(regpromises, "UNDO_SHIPPED", True)
    v._update_footer()
    assert v.footer_label.text() == rv.SHIPPED_LINE


def test_registry_act_uses_existing_service_clean_path(qtbot, monkeypatch):
    calls = []

    def fake_clean(items, config, **kw):
        calls.append((list(items), kw))
        outs = [CleanOutcome(item=i, removed=True) for i in items]
        return service.CleanSummary(result=CleanResult(outcomes=outs), removed=len(outs),
                                    quarantine_run="20261120-reg")

    monkeypatch.setattr(service, "clean", fake_clean)
    admin = []
    monkeypatch.setattr(elevation, "run_elevated_part",
                        lambda items, *a, **k: admin.append(list(items)) or None)
    # The same elevation-aware factory MainWindow gives the Scan tab.
    factory = elevation.make_clean_worker_factory(Config(), elevation=True)
    confirms, results = [], []
    v = make(qtbot, clean_worker_factory=factory, allow_admin_items=True,
             confirm=lambda d: confirms.append(d) or True,
             show_results=results.append)
    v.scan_button.click()
    v.tree.topLevelItem(0).setCheckState(0, Qt.CheckState.Checked)
    hkcu = v.selected_items()
    assert [i.reg.hive for i in hkcu] == ["HKCU"]
    hklm = reg_item("win_reg_uninstall", "HKLM", "M")
    v.set_result(ScanResult(reports=[CleanerReport("win_reg_uninstall", "u", "d",
                                                   items=[hkcu[0], hklm])]))
    v.tree.topLevelItem(0).setCheckState(0, Qt.CheckState.Checked)
    assert len(v.selected_items()) == 2
    v.remove_button.click()
    assert len(confirms) == 1
    # User (HKCU) entries: service.clean, real run, quarantine (backup) on.
    assert len(calls) == 1
    items, kw = calls[0]
    assert [i.reg.hive for i in items] == ["HKCU"]
    assert kw["dry_run"] is False and kw["use_quarantine"] is True
    # Machine-wide (HKLM) entries: the existing elevated helper part.
    assert [[i.reg.hive for i in its] for its in admin] == [["HKLM"]]
    assert results and "20261120-reg" in results[-1].body.toPlainText()
    assert regpromises.PERMANENT_LINE in results[-1].body.toPlainText()


def test_registry_cancelled_confirmation_changes_nothing(qtbot, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not clean")

    monkeypatch.setattr(service, "clean", boom)
    v = make(qtbot, confirm=lambda d: False)
    v.scan_button.click()
    v.tree.topLevelItem(0).setCheckState(0, Qt.CheckState.Checked)
    v.remove_button.click()
    assert "Nothing was changed" in v.status_label.text()
