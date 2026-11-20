"""ReviewView / ReviewModel: findings ticked by hand (Task 11)."""

from __future__ import annotations

import hashlib
import itertools
import re

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtGui import QColor, QPalette  # noqa: E402
from PySide6.QtWidgets import QLabel, QWidget  # noqa: E402

from cleanix import elevated  # noqa: E402
from cleanix.core import actions, findings, service, system_findings  # noqa: E402
from cleanix.core.models import CleanableItem, CleanerReport, ScanResult  # noqa: E402
from cleanix.core.remedy import LINK_TARGET, Remedy, RemedyKind, path_remedy  # noqa: E402
from cleanix.gui import review_view  # noqa: E402
from cleanix.gui.review_view import ReviewModel, ReviewView, footer_lines  # noqa: E402

MB = 1024 * 1024
HOME = "/home/ann"
_ino = itertools.count(100)


def fnd(cid, name, size=MB, *, root=False, kind=RemedyKind.PATH, group=None,
        mtime=1000, remedy=True, extra=(), path=None):
    path = path or (f"/var/lib/{cid}/{name}" if root else f"{HOME}/{cid}/{name}")
    rem = (Remedy(kind, (size, mtime, next(_ino), 1), group=group, extra=extra)
           if remedy else None)
    return CleanableItem(cleaner_id=cid, description=f"{cid}: {name}", size=size,
                         path=path, report_only=True, requires_root=root,
                         hint=f"check {name} first", remedy=rem)


def report(cid, items):
    return CleanerReport(cid, cid.replace("_", " ").title(), f"about {cid}",
                         items=list(items))


def scan(*reports):
    return ScanResult(reports=list(reports))


def dup_group(gid, n=3, size=MB, base=1000):
    """``n`` copies; copy 0 is the oldest (the default survivor) and sized 0
    like the duplicates scanner does."""
    out = []
    for k in range(n):
        item = fnd("duplicates", f"{gid}-copy{k}", size=size, group=gid,
                   mtime=base + k)
        if k == 0:
            item = CleanableItem(**{**item.__dict__, "size": 0})
        out.append(item)
    return out


@pytest.fixture
def fake_plan(monkeypatch):
    """System-wide items are offered unless their path contains "bad"."""
    reason = "the administrator helper never acts on it (bad place)"

    def plan(items):
        out = system_findings.SystemPlan()
        for i in items:
            if "bad" in (i.path or ""):
                out.not_offered.append((i, reason))
            else:
                out.offered.append(i)
        return out

    monkeypatch.setattr(system_findings, "plan", plan)
    return reason


def make(qtbot, s=None, **kw):
    w = ReviewView(home=HOME, **kw)
    qtbot.addWidget(w)
    if s is not None:
        w.set_scan(s)
    return w


def payload(row):
    return row.data(0, Qt.ItemDataRole.UserRole)


def tick(w, row, on=True):
    """Tick a row as a user would (sets its check state)."""
    assert row.flags() & Qt.ItemFlag.ItemIsUserCheckable
    row.setCheckState(0, Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)


def checkable(row):
    return bool(row.flags() & Qt.ItemFlag.ItemIsUserCheckable)


def realise_all(w):
    for sc in w.model.scenarios:
        w.scenario_row(sc.cleaner_id).setExpanded(True)


# ------------------------------------------------------------------ basics
def test_nothing_preselected(qtbot, fake_plan):
    s = scan(report("big_files", [fnd("big_files", f"f{k}") for k in range(5)]),
             report("duplicates", dup_group("a" * 64)),
             report("orphan_files", [fnd("orphan_files", "x", root=True)]))
    w = make(qtbot, s)
    w.set_elevation_available(True)
    realise_all(w)
    assert w.selected_items() == []
    assert w.selected_size() == 0
    assert w.survivor_map() == {}
    assert not w.act_button.isEnabled()
    for sc in w.model.scenarios:
        for item in sc.items:
            row = w.item_row(item)
            if row is not None and row.data(0, Qt.ItemDataRole.CheckStateRole) is not None:
                assert row.checkState(0) == Qt.CheckState.Unchecked


def test_category_tick_selects_all_actionable_visible(qtbot):
    big = [fnd("big_files", f"f{k}") for k in range(4)]
    plain = fnd("big_files", "noremedy", remedy=False)
    dl = [fnd("downloads", f"d{k}") for k in range(3)]
    w = make(qtbot, scan(report("big_files", big + [plain]), report("downloads", dl)))
    cat = w.category_row(findings.YOUR_FILES)
    tick(w, cat)
    assert set(map(id, w.selected_items())) == set(map(id, big + dl))
    # every selected item is shown (its scenario expanded, its row exists)
    for item in w.selected_items():
        row = w.item_row(item)
        assert row is not None and row.checkState(0) == Qt.CheckState.Checked
        assert row.parent().isExpanded()
    assert cat.checkState(0) == Qt.CheckState.Checked
    tick(w, cat, False)
    assert w.selected_items() == []


def test_collapsed_items_not_selected_by_bulk(qtbot):
    n = review_view.REALISE_LIMIT + 50
    items = [fnd("big_files", f"f{k}", size=(n - k) * 10) for k in range(n)]
    w = make(qtbot, scan(report("big_files", items)))
    tick(w, w.scenario_row("big_files"))
    chosen = w.selected_items()
    assert len(chosen) == review_view.PAGE
    assert all(w.model.is_realised(i) and w.item_row(i) is not None for i in chosen)
    unseen = [i for i in items if not w.model.is_realised(i)]
    assert len(unseen) == 50 and not any(w.model.is_selected(i) for i in unseen)
    assert "50 more not shown; expand to include them" in w.notes.text()
    # showing more realises them, unticked: the scenario is now partly ticked
    w.show_more("big_files")
    assert len(w.selected_items()) == review_view.PAGE
    assert w.scenario_row("big_files").checkState(0) == Qt.CheckState.PartiallyChecked
    assert "more not shown" not in w.notes.text()


def test_small_scenario_is_realised_completely_by_bulk(qtbot):
    n = review_view.REALISE_LIMIT
    items = [fnd("big_files", f"f{k}") for k in range(n)]
    w = make(qtbot, scan(report("big_files", items)))
    row = w.scenario_row("big_files")
    assert not row.isExpanded() and w.item_row(items[0]) is None
    tick(w, row)
    assert len(w.selected_items()) == n
    assert row.isExpanded() and all(w.item_row(i) is not None for i in items)
    assert w.notes.text() == ""


def test_partly_ticked_bulk_row_click_clears(qtbot):
    n = review_view.REALISE_LIMIT + 5
    items = [fnd("big_files", f"f{k}") for k in range(n)]
    w = make(qtbot, scan(report("big_files", items)))
    row = w.scenario_row("big_files")
    tick(w, row)
    assert row.checkState(0) == Qt.CheckState.Checked  # all it covers
    p = payload(row)
    w.toggle(p, True)  # nothing more to add -> clears
    assert w.selected_items() == []


def test_report_only_without_remedy_not_tickable(qtbot):
    plain = fnd("big_files", "plain", remedy=False)
    w = make(qtbot, scan(report("big_files", [plain])))
    realise_all(w)
    row = w.item_row(plain)
    assert not checkable(row)
    assert row.data(0, Qt.ItemDataRole.CheckStateRole) is None
    assert row.text(3) == review_view.NO_ACTION
    assert review_view.NO_ACTION in row.toolTip(0)
    assert "check plain first" in row.toolTip(0)
    assert w.model.set_checked(plain, True) is False
    # no tick box on the scenario / category either
    assert not checkable(w.scenario_row("big_files"))
    assert not checkable(w.category_row(findings.YOUR_FILES))


@pytest.mark.parametrize("item, reason", [
    (fnd("orphan_launch_jobs", "rcpt", kind=RemedyKind.PKG_RECEIPT), review_view.NOT_HANDLED),
    (fnd("stale_services", "lnk", extra=((LINK_TARGET, "/x"),)), review_view.LINK_NOT_HERE),
    (fnd("orphan_launch_jobs", "job", kind=RemedyKind.LAUNCH_JOB, group="g"),
     review_view.NOT_HANDLED),
])
def test_user_items_the_executor_skips_are_not_tickable(qtbot, item, reason):
    w = make(qtbot, scan(report(item.cleaner_id, [item])))
    realise_all(w)
    assert w.model.reason(item) == reason
    assert not checkable(w.item_row(item))
    assert w.model.set_checked(item, True) is False


def test_user_launch_job_is_tickable(qtbot):
    job = fnd("orphan_launch_jobs", "job.plist", kind=RemedyKind.LAUNCH_JOB)
    w = make(qtbot, scan(report("orphan_launch_jobs", [job])))
    realise_all(w)
    tick(w, w.item_row(job))
    assert w.selected_items() == [job]
    assert w.item_row(job).text(2) == "Permanent"


def test_other_findings_category_shown(qtbot):
    odd = fnd("mystery_scenario", "thing")
    w = make(qtbot, scan(report("mystery_scenario", [odd])))
    assert w.category_row(findings.OTHER_FINDINGS) is not None
    tick(w, w.category_row(findings.OTHER_FINDINGS))
    assert w.selected_items() == [odd]


def test_empty_scan_shows_message(qtbot):
    w = make(qtbot)
    assert w.message.text() == review_view.EMPTY_BEFORE_SCAN
    w.set_scan(scan(report("big_files", [])))
    assert w.message.text() == review_view.EMPTY_SCAN
    assert not w.message.isHidden()
    assert w.tree.topLevelItemCount() == 0
    w.set_scan(scan(report("big_files", [fnd("big_files", "a")])))
    assert w.message.isHidden()
    w.clear()
    assert w.message.text() == review_view.EMPTY_BEFORE_SCAN
    assert w.tree.topLevelItemCount() == 0 and w.selected_items() == []


def test_set_scan_accepts_report_list(qtbot):
    a = fnd("big_files", "a")
    w = make(qtbot, [report("big_files", [a])])
    assert w.category_row(findings.YOUR_FILES) is not None


# --------------------------------------------------------------- duplicates
def test_duplicates_leave_one_survivor(qtbot):
    g1, g2 = dup_group("a" * 64), dup_group("b" * 64, n=2)
    w = make(qtbot, scan(report("duplicates", g1 + g2)))
    tick(w, w.scenario_row("duplicates"))
    chosen = w.selected_items()
    assert set(map(id, chosen)) == set(map(id, g1[1:] + g2[1:]))
    assert w.survivor_map() == {"a" * 64: g1[0], "b" * 64: g2[0]}
    kept = w.item_row(g1[0])
    assert kept.text(2) == "Kept" and not checkable(kept)
    assert kept.text(3) == review_view.KEPT
    # real sizes: the size-0 survivor marker never hides bytes
    assert w.selected_size() == 3 * MB
    # the default survivor is plan_duplicates' "oldest"
    assert findings.default_survivor(g1, "oldest") is g1[0]


def test_dup_copy_rows_show_what_stays(qtbot):
    g = dup_group("a" * 64)
    w = make(qtbot, scan(report("duplicates", g)))
    realise_all(w)
    assert "keeps" in w.item_row(g[1]).text(3)


OPS = ("tick", "untick", "keep", "bulk", "unbulk", "elev_on", "elev_off")


def _do(m, op, item, sc):
    if op == "tick":
        m.set_checked(item, True)
    elif op == "untick":
        m.set_checked(item, False)
    elif op == "keep":
        m.set_survivor(item)
    elif op == "bulk":
        m.set_scenario(sc, True)
    elif op == "unbulk":
        m.set_scenario(sc, False)
    elif op == "elev_on":
        m.set_elevation(True)
    else:
        m.set_elevation(False)


def test_duplicate_group_never_fully_ticked():
    """Model level, every sequence of up to 4 operations on a 3-copy group
    (and a 2-copy group): the invariants always hold."""
    for n in (2, 3):
        group = dup_group("c" * 64, n=n)
        steps = [(op, k) for op in OPS for k in range(n)
                 if op in ("tick", "untick", "keep") or k == 0]
        for length in range(1, 5):
            for seq in itertools.product(steps, repeat=length):
                m = ReviewModel()
                m.load(findings.group_findings(scan(report("duplicates", group))))
                sc = m.scenarios[0]
                m.realise_initial(sc)
                for op, k in seq:
                    _do(m, op, group[k], sc)
                    m.check_invariants()
                    assert len(m.selected_items()) <= n - 1


def test_unrealised_items_cannot_be_ticked_in_model():
    items = [fnd("big_files", f"f{k}") for k in range(3)]
    m = ReviewModel()
    m.load(findings.group_findings(scan(report("big_files", items))))
    assert m.set_checked(items[0], True) is False
    m.realise_initial(m.scenarios[0])
    assert m.set_checked(items[0], True) is True


def test_keep_this_copy_instead_changes_survivor(qtbot):
    g = dup_group("d" * 64)
    w = make(qtbot, scan(report("duplicates", g)))
    tick(w, w.scenario_row("duplicates"))
    assert w.model.is_selected(g[2])
    assert "Keep this copy instead" in w.item_menu_labels(g[2])
    assert "Keep this copy instead" not in w.item_menu_labels(g[0])
    menu = w.build_menu(w.item_row(g[2]))
    action = [a for a in menu.actions() if a.text() == "Keep this copy instead"][0]
    action.trigger()
    assert w.survivor_map() == {"d" * 64: g[2]}
    assert not w.model.is_selected(g[2])  # the new survivor is unticked
    assert w.item_row(g[2]).text(2) == "Kept"
    assert checkable(w.item_row(g[0]))  # old survivor may now be ticked
    tick(w, w.item_row(g[0]))
    assert set(map(id, w.selected_items())) == {id(g[0]), id(g[1])}
    assert w.selected_size() == 2 * MB  # g[0]'s real size, not its 0 marker


def test_survivor_map_matches_plan_duplicates_keeping(qtbot, tmp_path):
    content = b"same bytes" * 100
    gid = hashlib.sha256(content).hexdigest()
    copies = []
    for k in range(3):
        p = tmp_path / f"copy{k}.bin"
        p.write_bytes(content)
        copies.append(CleanableItem("duplicates", f"duplicates: {p.name}",
                                    size=len(content), path=str(p), report_only=True,
                                    remedy=path_remedy(str(p), group=gid)))
    other = fnd("big_files", "big")
    w = make(qtbot, scan(report("duplicates", copies), report("big_files", [other])))
    tick(w, w.category_row(findings.YOUR_FILES))
    keep = [c for c in copies if not w.model.is_survivor(c)][0]
    w.keep_instead(keep)
    tick(w, w.scenario_row("duplicates"), False)
    tick(w, w.scenario_row("duplicates"))
    survivors = w.survivor_map()
    assert survivors == {gid: keep}
    selected = w.selected_items()
    dups = [i for i in selected if i.remedy is not None and i.remedy.group]
    assert {id(i) for i in dups} == {id(c) for c in copies if c is not keep}
    # Task 12's recipe: the duplicate copies plus the survivors.
    plan = findings.plan_duplicates_keeping(dups + list(survivors.values()), survivors)
    assert plan.kept == [keep]
    assert {i.path for i in plan.items} == {c.path for c in dups}
    assert keep.path not in {i.path for i in plan.items}
    assert all(why == findings.KEPT for i, why in plan.skipped)
    for p in tmp_path.iterdir():
        assert p.read_bytes() == content  # nothing deleted


# ------------------------------------------------------------- system items
def _system_scan():
    good = fnd("orphan_files", "good", root=True)
    bad = fnd("orphan_files", "bad", root=True)
    user = fnd("big_files", "mine")
    return good, bad, user, scan(report("orphan_files", [good, bad]),
                                 report("big_files", [user]))


def test_system_items_disabled_without_elevation(qtbot, fake_plan):
    good, bad, user, s = _system_scan()
    w = make(qtbot, s)
    realise_all(w)
    row = w.item_row(good)
    assert not checkable(row) and not (row.flags() & Qt.ItemFlag.ItemIsEnabled)
    assert row.text(2) == "Needs admin"
    assert row.text(3).startswith("Needs admin:")
    assert w.model.set_checked(good, True) is False
    assert not checkable(w.category_row(findings.UNOWNED_FILES))
    assert not checkable(w.scenario_row("orphan_files"))
    w.model.set_category(findings.UNOWNED_FILES, True)
    assert w.selected_items() == []
    w.set_elevation_available(False, "the helper cannot start")
    assert "the helper cannot start" in w.item_row(good).text(3)


def test_system_items_enabled_with_elevation(qtbot, fake_plan):
    good, bad, user, s = _system_scan()
    w = make(qtbot, s)
    w.set_elevation_available(True)
    tick(w, w.category_row(findings.UNOWNED_FILES))
    assert w.selected_items() == [good]
    assert w.item_row(good).text(2) == "Needs admin"
    # elevation lost: system items are unticked and disabled again
    w.set_elevation_available(False)
    assert w.selected_items() == []
    assert not checkable(w.item_row(good))
    # ... and stay unticked when elevation comes back (nothing re-appears)
    w.set_elevation_available(True)
    assert w.selected_items() == []
    assert w.item_row(good).checkState(0) == Qt.CheckState.Unchecked


def test_not_offered_reason_tooltip(qtbot, fake_plan):
    good, bad, user, s = _system_scan()
    w = make(qtbot, s)
    w.set_elevation_available(True)
    realise_all(w)
    row = w.item_row(bad)
    assert not checkable(row)
    assert fake_plan in row.text(3)
    assert fake_plan in row.toolTip(0)
    assert row.text(3).startswith(review_view.NOT_OFFERED)


def test_windows_system_items_not_offered(qtbot, monkeypatch):
    monkeypatch.setattr(elevated, "_findings_supported", lambda: False)
    good, bad, user, s = _system_scan()
    w = make(qtbot, s)
    w.set_elevation_available(True)
    realise_all(w)
    for item in (good, bad):
        row = w.item_row(item)
        assert not checkable(row)
        assert system_findings.NOT_ON_WINDOWS in row.text(3)
        assert system_findings.NOT_ON_WINDOWS in row.toolTip(0)
    assert checkable(w.item_row(user))  # user-space findings still work


def test_system_plan_batch_caps_do_not_mark_items_unofferable(qtbot, monkeypatch):
    from cleanix.core import elevate

    monkeypatch.setattr(elevate, "MAX_FINDING_ITEMS", 3)
    monkeypatch.setattr(elevate, "MAX_FINDING_SCENARIOS", 1)
    calls = []

    def plan(items):
        calls.append(list(items))
        out = system_findings.SystemPlan()
        for k, i in enumerate(items):  # the real plan's caps, per call
            if k >= 3:
                out.not_offered.append((i, "too many system-wide items"))
            else:
                out.offered.append(i)
        return out

    monkeypatch.setattr(system_findings, "plan", plan)
    a = [fnd("orphan_files", f"a{k}", root=True) for k in range(5)]
    b = [fnd("stale_alternatives", "b0", root=True)]
    m = ReviewModel()
    m.load(findings.group_findings(scan(report("orphan_files", a),
                                        report("stale_alternatives", b))))
    m.set_elevation(True)
    assert all(m.tickable(i) for i in a + b)
    assert all(len(c) <= 3 and len({i.cleaner_id for i in c}) == 1 for c in calls)
    for sc in m.scenarios:
        m.realise_initial(sc)
    m.set_scenario(m.scenarios[0], True)
    assert len(m.selected_items()) == 3 and "At most 3" in m.cap_note
    m.set_scenario(m.scenarios[0], False)
    m.set_checked(a[0], True)
    assert m.set_checked(b[0], True) is False  # a second scenario: over the cap
    assert "scenarios" in m.cap_note
    m.check_invariants()


# ------------------------------------------------------------------ footer
def test_footer_wording_per_kind():
    user = fnd("big_files", "a", size=2 * MB)
    job = fnd("orphan_launch_jobs", "j", kind=RemedyKind.LAUNCH_JOB)
    unit = fnd("stale_services", "u", kind=RemedyKind.SYSTEMD_UNIT)
    sys_path = fnd("orphan_files", "p", root=True, size=3 * MB)
    sys_job = fnd("orphan_launch_jobs", "sj", root=True, kind=RemedyKind.LAUNCH_JOB)
    sys_rcpt = fnd("stale_receipts", "r", root=True, kind=RemedyKind.PKG_RECEIPT)

    [line] = footer_lines([user], False)
    assert "kept in quarantine; Undo available" in line and "2.0 MiB" in line
    [line] = footer_lines([user], True)
    assert "permanent" in line and "Undo available" not in line
    for item in (job, unit, sys_job, sys_rcpt):
        for perm in (False, True):
            lines = footer_lines([item], perm)
            assert "permanent (a copy of the file is kept for manual recovery)" in lines[0]
            assert all("undo" not in ln.lower() for ln in lines)
    lines = footer_lines([sys_path], False)
    assert "root-only quarantine you cannot restore from yet" in lines[0]
    assert "no space freed yet" in lines[0]
    assert all("undo" not in ln.lower() for ln in lines)
    lines = footer_lines([sys_path], True)
    assert "permanently" in lines[0] and all("undo" not in ln.lower() for ln in lines)
    # a mixed batch: one line per effect; Undo only on the user PATH line
    lines = footer_lines([user, job, sys_path], False)
    undo = [ln for ln in lines if "undo" in ln.lower()]
    assert len(undo) == 1 and "1 item(s)" in undo[0]


def test_footer_in_view_follows_permanent(qtbot):
    a = fnd("big_files", "a")
    w = make(qtbot, scan(report("big_files", [a])))
    realise_all(w)
    tick(w, w.item_row(a))
    assert "Undo available" in w.lines.text()
    w.permanent_box.setChecked(True)
    assert w.model.permanent and "Undo available" not in w.lines.text()
    assert "Deleted permanently" in w.item_row(a).text(3)
    w.set_permanent(False)
    assert not w.permanent_box.isChecked() and "Undo available" in w.lines.text()


# --------------------------------------------------------------------- act
def test_act_button_disabled_when_nothing_selected(qtbot):
    a = fnd("big_files", "a")
    w = make(qtbot, scan(report("big_files", [a])))
    assert not w.act_button.isEnabled()
    realise_all(w)
    tick(w, w.item_row(a))
    assert w.act_button.isEnabled() and "1 selected" in w.act_button.text()
    tick(w, w.item_row(a), False)
    assert not w.act_button.isEnabled()


def test_act_signal_carries_items_and_survivors(qtbot):
    a = fnd("big_files", "a")
    g = dup_group("e" * 64)
    w = make(qtbot, scan(report("big_files", [a]), report("duplicates", g)))
    tick(w, w.category_row(findings.YOUR_FILES))
    w.set_permanent(True)
    got = []
    w.actRequested.connect(lambda items, perm, surv: got.append((items, perm, surv)))
    qtbot.mouseClick(w.act_button, Qt.MouseButton.LeftButton)
    [(items, perm, surv)] = got
    assert perm is True
    assert {id(i) for i in items} == {id(a), id(g[1]), id(g[2])}
    originals = {id(x) for x in [a] + g}
    assert all(id(i) in originals for i in items)  # the scan's own objects
    assert list(surv) == ["e" * 64] and surv["e" * 64] is g[0]


def test_widget_never_calls_core_act(qtbot, monkeypatch, fake_plan):
    def boom(*a, **k):
        raise AssertionError("the Review widget must never act")

    for mod, name in ((actions, "act"), (service, "act"), (service, "clean"),
                      (system_findings, "run_batch")):
        monkeypatch.setattr(mod, name, boom)
    from cleanix.core import elevate_launch
    from cleanix.gui import elevation
    monkeypatch.setattr(elevate_launch, "run_findings_request", boom)
    monkeypatch.setattr(elevation, "run_elevated_part", boom)
    good, bad, user, s = _system_scan()
    w = make(qtbot, s)
    w.set_elevation_available(True)
    for cat in (findings.YOUR_FILES, findings.UNOWNED_FILES):
        tick(w, w.category_row(cat))
    got = []
    w.actRequested.connect(lambda *a: got.append(a))
    qtbot.mouseClick(w.act_button, Qt.MouseButton.LeftButton)
    assert len(got) == 1


# ------------------------------------------------------- escaping / styling
def test_untrusted_text_is_plain(qtbot):
    evil = "<b>bold</b><img src=x>&amp;"
    item = fnd("big_files", evil, path=f"{HOME}/{evil}/f")
    item = CleanableItem(**{**item.__dict__, "hint": "<i>hint</i>",
                            "description": f"big_files: {evil}"})
    w = make(qtbot, scan(report("big_files", [item])))
    realise_all(w)
    row = w.item_row(item)
    assert row.text(0) == evil  # tree cells are plain text
    tip = row.toolTip(0)
    assert "<b>" not in tip and "&lt;b&gt;" in tip and "&lt;i&gt;" in tip
    assert "&amp;amp;" in tip
    for label in w.findChildren(QLabel):
        assert label.textFormat() == Qt.TextFormat.PlainText
    tick(w, row)
    assert w.lines.textFormat() == Qt.TextFormat.PlainText


_HEX = re.compile(r"#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b")
_LIGHT_NAMES = ("white", "snow", "ivory", "ghostwhite", "whitesmoke", "lightgray",
                "lightgrey", "gainsboro")


def _light(sheet: str) -> bool:
    low = sheet.lower()
    if any(n in low for n in _LIGHT_NAMES):
        return True
    for m in _HEX.finditer(sheet):
        if QColor("#" + m.group(1)).lightness() > 200:
            return True
    for m in re.finditer(r"rgba?\((\d+),\s*(\d+),\s*(\d+)", sheet):
        if QColor(*map(int, m.groups())).lightness() > 200:
            return True
    return False


@pytest.mark.parametrize("dark", [False, True])
def test_palette_only_no_fixed_light_colours(qtbot, dark, fake_plan):
    good, bad, user, s = _system_scan()
    g = dup_group("f" * 64)
    s.reports.append(report("duplicates", g))
    w = make(qtbot)
    if dark:
        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Base, QColor("#1e1e1e"))
        pal.setColor(QPalette.ColorRole.Text, QColor("#eeeeee"))
        pal.setColor(QPalette.ColorRole.Window, QColor("#2b2b2b"))
        w.setPalette(pal)
    w.set_scan(s)
    realise_all(w)
    tick(w, w.category_row(findings.YOUR_FILES))
    for widget in [w] + w.findChildren(QWidget):
        assert not _light(widget.styleSheet()), widget
    base = w.tree.palette().base().color()
    for sc in w.model.scenarios:
        for item in sc.items:
            row = w.item_row(item)
            for c in range(len(review_view.COLUMNS)):
                brush = row.foreground(c)
                if brush.style() != Qt.BrushStyle.NoBrush:
                    fg = brush.color()
                    # readable on this base (badge colours follow the palette)
                    assert abs(fg.lightness() - base.lightness()) > 80
                assert row.background(c).style() == Qt.BrushStyle.NoBrush
