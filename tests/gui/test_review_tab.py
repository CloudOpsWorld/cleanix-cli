"""Task 12: the Review tab -- opt-in findings scan and the act flow.

Hermetic: the scan is a fake worker, workers run synchronously, user files
live under tmp_path (quarantine and history redirected there too), and the
elevation launcher is a fake that parses the real request and writes a real
helper result. No real elevation, nothing outside tmp_path is touched.
"""

from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import QObject, Qt, Signal, Slot  # noqa: E402
from PySide6.QtWidgets import QLabel, QPlainTextEdit  # noqa: E402

from cleanix import elevated  # noqa: E402
from cleanix.config import Config  # noqa: E402
from cleanix.core import (  # noqa: E402
    catalog, elevate, elevate_launch, findings, history, quarantine, registry,
    safety, service, system_findings,
)
from cleanix.core.models import CleanableItem, CleanerReport, ScanResult, item_key  # noqa: E402
from cleanix.core.remedy import CHANGED, Remedy, RemedyKind, path_remedy  # noqa: E402
from cleanix.gui import findings_act, review_view, workers  # noqa: E402
from cleanix.gui.review_tab import DEEP_TEXT, SCAN_TEXT, ReviewTab, finding_scan_ids  # noqa: E402

PHRASE = "DELETE SYSTEM FILES"
ROOTS = {
    "orphan_files": ("/opt", "/usr/local", "/var/lib", "/var/cache"),
    "orphan_launch_jobs": ("/Library/LaunchDaemons",),
}


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: tmp_path / "q")
    # The helper's lexical world (as in test_cli_system_findings): POSIX
    # support, Linux-like roots; nothing there is ever touched.
    monkeypatch.setattr(elevated, "_findings_supported", lambda: True)
    monkeypatch.setattr(elevated, "admin_finding_ids",
                        lambda: frozenset({"orphan_files", "orphan_launch_jobs"}))
    monkeypatch.setattr(elevated, "finding_path_roots", lambda: dict(ROOTS))
    monkeypatch.setattr(elevated, "finding_kind_dirs",
                        lambda: {"launch_job": ("/Library/LaunchDaemons",),
                                 "systemd_unit": ("/etc/systemd/system",),
                                 "pkg_receipt": ("/private/var/db/receipts",)})
    monkeypatch.setattr(elevated, "helper_finding_kinds",
                        lambda: frozenset({"path", "launch_job"}))
    monkeypatch.setattr(elevated, "_root_quarantine_location",
                        lambda: ("/var/lib", ("cleanix", "quarantine")))
    # Workers run synchronously on the test thread.
    monkeypatch.setattr(workers, "start_worker", lambda w: w.run())
    findings._hash_cache.clear()
    yield
    findings._hash_cache.clear()
    safety.set_protected_globs([])


# ------------------------------------------------------------------ fakes
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
        self.result = result if result is not None else ScanResult()

    def __call__(self, config, only=None):
        self.calls.append(list(only or []))
        return FakeScan(self.result)


class Launcher:
    """Fake elevation launcher: reads the real request, writes a real
    HelperResult (default: every item removed)."""

    def __init__(self, status=None, reason="", note="", exc=None, write=True,
                 quarantine_run="", backup_run=""):
        self.calls = []
        self.status = status or {}
        self.reason = reason
        self.note = note
        self.exc = exc
        self.write = write
        self.quarantine_run = quarantine_run
        self.backup_run = backup_run
        self.on_call = None

    def __call__(self, argv):
        self.calls.append(list(argv))
        if self.on_call:
            self.on_call()
        req = Path(argv[argv.index("--request") + 1])
        res = Path(argv[argv.index("--result") + 1])
        sel = elevate.parse_request(req.read_bytes())
        if self.write:
            outs = []
            for s in sel.findings.items:
                st = self.status.get(s.key, "removed")
                outs.append(elevate.FindingOutcome(
                    key=s.key, status=st, freed=100 if st == "removed" else 0,
                    reason="" if st == "removed" else self.reason, note=self.note))
            removed = sum(1 for o in outs if o.status == "removed")
            elevate.write_result(res, elevate.HelperResult(
                freed=100 * removed, removed=removed, errors=[], unmatched=0,
                nonce=sel.nonce, findings=outs, quarantine_run=self.quarantine_run,
                backup_run=self.backup_run))
        if self.exc is not None:
            raise self.exc
        return 0


class Confirm:
    """The confirmation seam: records the dialog, optionally types the
    phrase, answers ``answer``."""

    def __init__(self, answer=True, phrase=PHRASE):
        self.answer = answer
        self.phrase = phrase
        self.dialogs = []

    def __call__(self, dialog):
        self.dialogs.append(dialog)
        if dialog.phrase_edit is not None and self.phrase is not None:
            dialog.phrase_edit.setText(self.phrase)
        return self.answer


# ------------------------------------------------------------------ items
def user_file(tmp_path, name="big.bin", data=b"x" * 4096, cid="big_files", group=None):
    d = tmp_path / "home"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_bytes(data)
    item = CleanableItem(cleaner_id=cid, description=name, size=len(data), path=str(p),
                         report_only=True, remedy=path_remedy(str(p), group=group))
    return p, item


def sys_item(path="/opt/stale-app", cid="orphan_files", kind=RemedyKind.PATH, desc=None,
             size=1000):
    return CleanableItem(cleaner_id=cid, description=desc or path.rsplit("/", 1)[-1],
                         size=size, path=path, report_only=True, requires_root=True,
                         remedy=Remedy(kind=kind, fingerprint=(1, 2, 3, 4)))


def job_item():
    return sys_item("/Library/LaunchDaemons/org.example.gone.plist",
                    cid="orphan_launch_jobs", kind=RemedyKind.LAUNCH_JOB)


def scan_of(*items):
    by = {}
    for i in items:
        by.setdefault(i.cleaner_id, []).append(i)
    return ScanResult(reports=[CleanerReport(c, c.replace("_", " ").title(), "d", items=its)
                               for c, its in by.items()])


def make_tab(qtbot, items=(), *, launcher=None, confirm=None, results=None,
             elevation=True):
    factory = ScanFactory(scan_of(*items))
    shown_results = results if results is not None else []
    tab = ReviewTab(Config(), scan_worker_factory=factory, launcher=launcher,
                    confirm=confirm or Confirm(),
                    show_results=lambda d: shown_results.append(d),
                    elevation_available=elevation)
    qtbot.addWidget(tab)
    tab.factory = factory
    tab.results = shown_results
    if items:
        tab.scan_button.click()
        for sc in tab.view.model.scenarios:
            tab.view.scenario_row(sc.cleaner_id).setExpanded(True)
    return tab


def tick(tab, *items, permanent=False):
    for i in items:
        assert tab.view.model.set_checked(i, True), i
    tab.view.set_permanent(permanent)
    tab.view._changed()


def act(tab):
    assert tab.view.act_button.isEnabled()
    tab.view.act_button.click()


def body(dialog):
    return dialog.body.toPlainText()


# ================================================================ scanning
def test_review_tab_does_not_autoscan(qtbot, app_env):
    from cleanix.gui.main_window import MainWindow

    factory = ScanFactory()
    w = MainWindow(scan_worker_factory=factory, elevation_available=False)
    qtbot.addWidget(w)
    w.set_mode("power", persist=False)
    w.show()
    w.power_view.tabs.setCurrentWidget(w.review_tab)
    qtbot.wait(20)
    assert factory.calls == []
    assert w.review_tab.view.model.scenarios == []
    assert w.review_tab.view.message.text() == review_view.EMPTY_BEFORE_SCAN
    assert w.review_tab.scan_button.text() == SCAN_TEXT


def test_scan_button_scans_only_report_only_scenarios(qtbot):
    tab = make_tab(qtbot)
    tab.scan_button.click()
    assert len(tab.factory.calls) == 1
    ids = tab.factory.calls[0]
    assert ids, "at least one findings scenario applies on every OS"
    assert set(ids) <= set(findings.FINDING_CATEGORIES)
    assert not set(ids) & set(catalog.REGISTRY_IDS)
    assert not set(ids) & set(catalog.SLOW_SCAN_IDS)
    # They really are report-only detectors that build on this system.
    built = registry.build_cleaners(Config(), only=ids)
    assert sorted(c.id for c in built) == sorted(ids)
    assert all(c.supported() for c in built)
    assert "Scans for findings only" in tab.scope_label.text()


def test_deep_scan_checkbox_default_off(qtbot):
    tab = make_tab(qtbot)
    assert tab.deep_check.text() == DEEP_TEXT
    assert not tab.deep_check.isChecked()
    quick = finding_scan_ids(Config(), False)
    assert "The deep scan adds (slow)" in tab.scope_label.text()
    tab.deep_check.setChecked(True)
    tab.scan_button.click()
    deep = tab.factory.calls[-1]
    extra = set(deep) - set(quick)
    assert extra and extra <= set(catalog.SLOW_SCAN_IDS)
    assert "big_files" in deep and "duplicates" in deep


# ============================================================ confirmation
def test_confirmation_lists_buckets_and_honest_wording(qtbot, tmp_path):
    p, user = user_file(tmp_path)
    s, j = sys_item(), job_item()
    confirm = Confirm(answer=False)
    tab = make_tab(qtbot, [user, s, j], launcher=Launcher(), confirm=confirm)
    tick(tab, user, s, j)
    act(tab)
    d = confirm.dialogs[-1]
    summary = d.summary.text()
    assert review_view.USER_QUARANTINE in summary  # Undo only for user files
    assert review_view.SYSTEM_QUARANTINE in summary
    assert review_view.JOB_PERMANENT in summary
    assert review_view.SYSTEM_PROMPT in summary
    text = body(d)
    assert "moves to quarantine (Undo available)" in text
    assert "root-only quarantine you cannot restore from yet" in text
    assert "PERMANENT: the job's file is removed" in text
    assert findings_act.SYSTEM_NOT_UNDONE in text
    # Undo is never claimed on a system-wide line.
    for line in text.splitlines():
        if "root-only" in line or "PERMANENT" in line:
            assert "Undo available" not in line
    assert "administrator prompt follows" in d.note.text()
    assert p.exists()  # declined: nothing touched

    # Permanent: the user line says so, the system path line too.
    confirm2 = Confirm(answer=False)
    tab2 = make_tab(qtbot, [user, s], launcher=Launcher(), confirm=confirm2)
    tick(tab2, user, s, permanent=True)
    act(tab2)
    d2 = confirm2.dialogs[-1]
    assert review_view.USER_PERMANENT in d2.summary.text()
    assert review_view.SYSTEM_PERMANENT in d2.summary.text()
    assert "Undo available" not in d2.summary.text() + body(d2)
    assert "PERMANENT: deleted with administrator rights" in body(d2)
    # Every label is plain text.
    for label in d2.findChildren(QLabel):
        assert label.textFormat() == Qt.TextFormat.PlainText


@pytest.mark.parametrize("typed", [
    "delete system files", "DELETE SYSTEM FILES ", " DELETE SYSTEM FILES",
    "DELETE SYSTEM", "DELETE  SYSTEM FILES", "Delete System Files", "",
    "DELETE SYSTEM FILES\n",
])
def test_system_phrase_required_exact(qtbot, tmp_path, typed):
    p, user = user_file(tmp_path)
    launcher = Launcher()
    confirm = Confirm(answer=True, phrase=typed)
    tab = make_tab(qtbot, [user, sys_item()], launcher=launcher, confirm=confirm)
    tick(tab, user, tab.view.model.scenarios[-1].items[0])
    act(tab)
    d = confirm.dialogs[-1]
    assert d.phrase_edit is not None
    assert not d.accept_button.isEnabled()
    assert not d.phrase_ok()
    # The dialog "accepted" anyway (seam): the tab re-checks the phrase.
    assert launcher.calls == [] and p.exists()
    assert "Nothing was changed" in tab.status_label.text()
    d.phrase_edit.setText(PHRASE)
    assert d.accept_button.isEnabled() and d.phrase_ok()
    # The safe button is the default one; the phrase field has focus.
    assert d.cancel_button.isDefault() and not d.accept_button.isDefault()
    assert not d.accept_button.autoDefault()
    assert d.phrase_edit.accessibleName()


# ===================================================================== act
def test_user_items_act_first_then_system_batch(qtbot, tmp_path, monkeypatch):
    order = []
    real_act = service.act

    def spy(items, config, **kw):
        order.append(("act", kw.get("dry_run"), [i.requires_root for i in items]))
        return real_act(items, config, **kw)

    monkeypatch.setattr(service, "act", spy)
    launcher = Launcher()
    launcher.on_call = lambda: order.append(("launch",))
    p, user = user_file(tmp_path)
    s = sys_item()
    tab = make_tab(qtbot, [user, s], launcher=launcher)
    tick(tab, user, s)
    act(tab)
    assert order == [("act", True, [False]), ("act", False, [False]), ("launch",)]
    assert len(launcher.calls) == 1  # one prompt for the whole batch
    assert not p.exists()  # quarantined
    text = body(tab.results[-1])
    assert text.index("Your files") < text.index("System-wide items")


def test_duplicates_use_plan_duplicates_keeping_with_survivors(qtbot, tmp_path,
                                                               monkeypatch):
    data = b"same content " * 500
    gid = hashlib.sha256(data).hexdigest()
    paths, items = [], []
    for k in range(3):
        p = tmp_path / "home" / f"d{k}"
        p.mkdir(parents=True, exist_ok=True)
        f = p / "photo.jpg"
        f.write_bytes(data)
        os.utime(str(f), (1_000_000 + k * 1000, 1_000_000 + k * 1000))
        paths.append(f)
        items.append(CleanableItem(cleaner_id="duplicates", description="photo.jpg",
                                   size=len(data), path=str(f), report_only=True,
                                   remedy=path_remedy(str(f), group=gid)))
    seen = []
    real = findings.plan_duplicates_keeping

    def spy(its, survivors):
        seen.append(([i.path for i in its], dict(survivors)))
        return real(its, survivors)

    monkeypatch.setattr(findings, "plan_duplicates_keeping", spy)
    tab = make_tab(qtbot, items)
    sc = tab.view.model.scenarios[0]
    tab.view.model.set_scenario(sc, True)
    tab.view._changed()
    survivor = tab.view.survivor_map()[gid]
    assert survivor.path == str(paths[0])  # oldest kept by default
    act(tab)
    assert seen, "plan_duplicates_keeping was not used"
    its, survivors = seen[0]
    assert str(paths[0]) in its  # the survivor is passed WITH the copies
    assert survivors[gid].path == str(paths[0])
    assert paths[0].exists() and paths[0].read_bytes() == data
    assert not paths[1].exists() and not paths[2].exists()
    runs = quarantine.list_runs()
    assert len(runs) == 1 and runs[0]["count"] == 2


def test_dry_run_verdicts_shown_in_dialog(qtbot, tmp_path):
    p1, ok = user_file(tmp_path, "ok.bin")
    p2, changed = user_file(tmp_path, "changed.bin")
    confirm = Confirm(answer=True)
    tab = make_tab(qtbot, [ok, changed], confirm=confirm)
    tick(tab, ok, changed)
    p2.write_bytes(b"different now, longer than before" * 300)  # after the scan
    act(tab)
    d = confirm.dialogs[-1]
    text = body(d)
    assert "Not acted on (checked just now):" in text
    assert f"skipped: {CHANGED}" in text
    assert "1 item(s)" in d.summary.text()  # only the eligible one counted
    assert not p1.exists() and p2.exists()  # the skipped one was left alone


def test_no_system_items_means_no_phrase_field_and_no_elevation(qtbot, tmp_path,
                                                                monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no administrator batch without system items")

    monkeypatch.setattr(system_findings, "run_batch", boom)
    launcher = Launcher()
    confirm = Confirm(answer=True)
    p, user = user_file(tmp_path)
    tab = make_tab(qtbot, [user], launcher=launcher, confirm=confirm)
    progress = []
    real_progress = tab._on_progress
    tab._on_progress = lambda n, d, t: (progress.append(n), real_progress(n, d, t))
    tick(tab, user)
    act(tab)
    assert progress  # the recorder is wired
    d = confirm.dialogs[-1]
    assert d.phrase_edit is None
    assert d.accept_button.isEnabled()
    assert "administrator" not in d.note.text().lower()
    assert launcher.calls == [] and not p.exists()
    assert findings_act.ADMIN_WAIT not in progress
    assert [e["mode"] for e in history.load()] == ["quarantine"]


@pytest.mark.parametrize("exc,expect", [
    (elevate_launch.ElevationDeclined("no"),
     "Administrator permission was declined; none of the system-wide items was removed."),
    (elevate_launch.ElevationUnavailable("pkexec missing"),
     "not available on this system (pkexec missing); none of the system-wide items "
     "was removed."),
    (elevate_launch.ElevationNotStarted("could not start"),
     "The administrator helper did not run (could not start); none of the system-wide "
     "items was removed."),
    (elevate_launch.ElevationFailed("elevated helper timed out and may still be running"),
     "the outcome is unknown, items may already have been removed"),
    (elevate_launch.ElevationFailed("boom", exit_code=9),
     "the outcome is unknown; items may already have been removed"),
])
def test_declined_elevation_message(qtbot, tmp_path, exc, expect):
    launcher = Launcher(exc=exc, write=False)
    p, user = user_file(tmp_path)
    s = sys_item()
    tab = make_tab(qtbot, [user, s], launcher=launcher)
    tick(tab, user, s)
    act(tab)
    text = body(tab.results[-1])
    assert expect in text
    assert "Your files above were already acted on." in text
    assert not p.exists()  # the user part stays done
    assert [e["mode"] for e in history.load()] == ["quarantine"]  # no admin entry


def test_helper_text_plain_and_sanitised(qtbot, tmp_path):
    s = sys_item(desc="<b>bold</b> name")
    hostile = "<i>x</i> [bold]red[/bold] ‮evil‬ \x85c1"
    launcher = Launcher(status={item_key(s): "skipped"}, reason=hostile,
                        note="<img src=x>⁦iso⁩")
    tab = make_tab(qtbot, [s], launcher=launcher)
    tick(tab, s)
    act(tab)
    d = tab.results[-1]
    assert isinstance(d.body, QPlainTextEdit)
    text = body(d)
    assert "<b>bold</b> name" in text  # shown literally, never rendered
    assert "<i>x</i>" in text and "<img src=x>" in text
    for bad in ("‮", "‬", "\x85", "⁦", "⁩"):
        assert bad not in text
    assert "evil" in text
    for label in d.findChildren(QLabel):
        assert label.textFormat() == Qt.TextFormat.PlainText


def test_quarantine_tab_refreshes_and_no_undo_for_system(qtbot, tmp_path, app_env):
    from cleanix.gui.main_window import MainWindow

    p, user = user_file(tmp_path)
    s = sys_item()
    launcher = Launcher(quarantine_run="20261120-rootrun")
    w = MainWindow(scan_worker_factory=ScanFactory(scan_of(user, s)),
                   elevation_available=True, findings_launcher=launcher)
    qtbot.addWidget(w)
    tab = w.review_tab
    results = []
    tab._confirm = Confirm()
    tab._show_results = results.append
    assert w.quarantine_panel.table.rowCount() == 0
    tab.scan_button.click()
    for sc in tab.view.model.scenarios:
        tab.view.scenario_row(sc.cleaner_id).setExpanded(True)
    tick(tab, user, s)
    act(tab)
    assert len(launcher.calls) == 1
    # The Quarantine tab was refreshed: it lists the user run (Undo) only.
    runs = quarantine.list_runs()
    assert len(runs) == 1
    assert w.quarantine_panel.table.rowCount() == 1
    panel_text = " ".join(w.quarantine_panel.table.item(0, c).text() for c in range(4))
    assert "rootrun" not in panel_text
    text = body(results[-1])
    assert f"Quarantine run {runs[0]['run_id']}: Undo it from the Quarantine tab" in text
    assert "20261120-rootrun" in text and "You cannot restore from it yet" in text
    sys_part = text[text.index("System-wide items"):]
    assert "Undo it" not in sys_part and "Undo available" not in sys_part
    assert tab.view.model.scenarios == []  # stale items cannot be acted on twice


@pytest.mark.parametrize("permanent,kind,modes", [
    (False, RemedyKind.PATH, [("administrator-quarantine", 0, 1)]),
    (True, RemedyKind.PATH, [("administrator", 100, 1)]),
    (False, RemedyKind.LAUNCH_JOB, [("administrator", 100, 1)]),
])
def test_history_modes_for_helper_batches(qtbot, permanent, kind, modes):
    s = job_item() if kind is RemedyKind.LAUNCH_JOB else sys_item()
    tab = make_tab(qtbot, [s], launcher=Launcher())
    tick(tab, s, permanent=permanent)
    act(tab)
    got = [(e["mode"], e["freed"], e["items"]) for e in history.load()]
    assert got == modes
    assert "delete" not in [m for m, _f, _n in got]


def test_cancel_stops_before_system_batch(qtbot, tmp_path, monkeypatch):
    launcher = Launcher()
    p, user = user_file(tmp_path)
    s = sys_item()
    tab = make_tab(qtbot, [user, s], launcher=launcher)
    real_act = service.act

    def act_then_cancel(items, config, **kw):
        out = real_act(items, config, **kw)
        if not kw.get("dry_run"):
            tab.cancel_current()  # the user clicks Cancel during the user part
        return out

    monkeypatch.setattr(service, "act", act_then_cancel)
    tick(tab, user, s)
    act(tab)
    assert launcher.calls == []
    text = body(tab.results[-1])
    assert ("Stopped before the administrator step: none of the system-wide items "
            "was removed.") in text
    assert not p.exists()  # the user part that ran stays done


def test_user_part_failure_never_launches_system_batch(qtbot, tmp_path, monkeypatch):
    launcher = Launcher()
    p, user = user_file(tmp_path)
    s = sys_item()
    tab = make_tab(qtbot, [user, s], launcher=launcher)
    real_act = service.act

    def fail_real(items, config, **kw):
        if not kw.get("dry_run"):
            raise OSError("disk on fire")
        return real_act(items, config, **kw)

    monkeypatch.setattr(service, "act", fail_real)
    tick(tab, user, s)
    act(tab)
    assert launcher.calls == []
    text = body(tab.results[-1])
    assert "Your files: the action failed (disk on fire)" in text
    assert ("The system-wide items were not touched because acting on your files "
            "failed; none of the system-wide items was removed.") in text


def test_cancel_button_disabled_while_admin_prompt_shown(qtbot, tmp_path):
    states = []
    s = sys_item()
    launcher = Launcher()
    tab = make_tab(qtbot, [s], launcher=launcher)
    launcher.on_call = lambda: states.append(
        (tab.cancel_button.isEnabled(), tab.status_label.text()))
    tick(tab, s)
    act(tab)
    assert states == [(False, findings_act.ADMIN_WAIT)]


# ============================================================== AST guard
def test_gui_never_passes_allow_root():
    """No GUI code asks the executor for root behaviour. The single exempt
    use of a ``quarantine_root`` keyword is ``elevate.RegistryRequest`` in
    gui/elevation.py (the HKLM registry request naming the USER's quarantine
    root for the backups), which is not the findings executor."""
    gui = Path(review_view.__file__).parent
    forbidden = {"allow_root", "quarantine_root", "backup_root"}
    files = sorted(gui.glob("*.py"))
    assert len(files) >= 10
    exempt = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = getattr(fn, "attr", None) or getattr(fn, "id", None)
                for kw in node.keywords:
                    if kw.arg == "allow_root":
                        raise AssertionError((path.name, "allow_root"))
                    if kw.arg in forbidden:
                        if (path.name, name, kw.arg) == ("elevation.py", "RegistryRequest",
                                                         "quarantine_root"):
                            exempt.append(path.name)
                            continue
                        raise AssertionError((path.name, name, kw.arg))
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert "allow_root" not in node.value, (path.name, node.value)
                assert node.value.strip() not in forbidden, (path.name, node.value)
            if isinstance(node, ast.Name):
                assert node.id != "allow_root", path.name
            if isinstance(node, ast.Dict):
                for k in node.keys:
                    if isinstance(k, ast.Constant):
                        assert k.value not in forbidden, path.name
    assert exempt == ["elevation.py"]


# ============================================================ Simple / tabs
def test_simple_mode_never_scans_findings(qtbot, app_env, monkeypatch):
    from cleanix.gui.main_window import MainWindow
    from cleanix.gui.registry_view import RegistryView
    from cleanix.gui.review_view import ReviewView

    for name in ("FindingsPlanWorker", "FindingsActWorker"):
        monkeypatch.setattr(workers, name, lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("Simple mode must never plan or act on findings")))

    def no_act(*a, **k):
        raise AssertionError("Simple mode must never act on findings")

    monkeypatch.setattr(service, "act", no_act)
    simple_calls = []

    class SimpleFactory(ScanFactory):
        def __call__(self, config, deep=False):
            simple_calls.append(deep)
            return FakeScan(ScanResult())

    review_factory = ScanFactory()
    w = MainWindow(scan_worker_factory=SimpleFactory(), elevation_available=False)
    qtbot.addWidget(w)
    w.review_tab._scan_factory = review_factory
    w.set_mode("simple", persist=False)
    sv = w.simple_view
    assert not sv.findChildren(ReviewView) and not sv.findChildren(RegistryView)
    sv.scan_button.click()
    assert simple_calls  # the Simple scan ran ...
    assert review_factory.calls == []  # ... and never the findings scan
    assert w.review_tab.view.model.scenarios == []


@pytest.mark.parametrize("osname,titles", [
    ("windows", ["Scan", "Review", "Registry", "Quarantine", "History", "Schedule",
                 "Settings", "Findings"]),
    ("linux", ["Scan", "Review", "Quarantine", "History", "Schedule", "Settings",
               "Findings"]),
    ("macos", ["Scan", "Review", "Quarantine", "History", "Schedule", "Settings",
               "Findings"]),
])
def test_tabs_order_and_names(qtbot, app_env, monkeypatch, osname, titles):
    from cleanix.gui import main_window

    monkeypatch.setattr(main_window, "current_os", lambda: osname)
    w = main_window.MainWindow(scan_worker_factory=ScanFactory(), elevation_available=False)
    qtbot.addWidget(w)
    assert w.power_view.panel_titles() == titles
    assert w.power_view.tabs.widget(1) is w.review_tab
    assert w.review_tab.scan_button.accessibleName() == SCAN_TEXT
    assert w.review_tab.deep_check.accessibleName() == DEEP_TEXT
