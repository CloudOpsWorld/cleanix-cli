"""The system-wide beta gate and the cross-filesystem hint in the GUI.

The gate lives in system_findings.plan(); the Review tab must show its
reason on every system-wide row (never tickable, even with elevation
available) and build_plan must never offer such an item. Hermetic: the
helper's lexical world is faked; nothing is launched or touched.
"""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from cleanix import elevated  # noqa: E402
from cleanix.config import Config  # noqa: E402
from cleanix.core import elevate, system_findings  # noqa: E402
from cleanix.core.models import item_key  # noqa: E402
from cleanix.gui import findings_act  # noqa: E402

from .test_review_view import _system_scan, checkable, make, realise_all  # noqa: E402

ROOTS = {"orphan_files": ("/var/lib",)}


@pytest.fixture(autouse=True)
def helper_world(monkeypatch):
    monkeypatch.setattr(elevated, "_findings_supported", lambda: True)
    monkeypatch.setattr(elevated, "admin_finding_ids", lambda: frozenset({"orphan_files"}))
    monkeypatch.setattr(elevated, "finding_path_roots", lambda: dict(ROOTS))
    monkeypatch.setattr(elevated, "finding_kind_dirs", lambda: {})
    monkeypatch.setattr(elevated, "helper_finding_kinds", lambda: frozenset({"path"}))
    monkeypatch.setattr(elevated, "_root_quarantine_location",
                        lambda: ("/srv/none", ("cleanix", "quarantine")))
    monkeypatch.delenv(system_findings.BETA_ENV, raising=False)
    monkeypatch.setattr(system_findings, "is_frozen", lambda: False)
    monkeypatch.setattr(system_findings, "euid_is_root", lambda: False)


def _gate(monkeypatch, case):
    if case == "env_on":
        monkeypatch.setenv(system_findings.BETA_ENV, "1")
        return None
    if case == "env_off":
        return system_findings.BETA_OFF
    monkeypatch.setenv(system_findings.BETA_ENV, "1")
    if case == "root":
        monkeypatch.setattr(system_findings, "euid_is_root", lambda: True)
        return system_findings.RUN_AS_USER
    monkeypatch.setattr(system_findings, "is_frozen", lambda: True)
    return system_findings.FROZEN_BINARY


@pytest.mark.parametrize("case", ["env_on", "env_off", "root", "frozen"])
def test_review_rows_show_the_gate_reason(qtbot, monkeypatch, case):
    reason = _gate(monkeypatch, case)
    good, bad, user, s = _system_scan()
    w = make(qtbot, s)
    w.set_elevation_available(True)  # elevation alone never opens the gate
    realise_all(w)
    row = w.item_row(good)
    if reason is None:
        assert checkable(row) and w.model.tickable(good)
        return
    assert not checkable(row) and not w.model.tickable(good)
    assert reason in row.text(3) and reason in row.toolTip(0)
    assert checkable(w.item_row(user))  # user-space findings unaffected


@pytest.mark.parametrize("case", ["env_on", "env_off", "root", "frozen"])
def test_build_plan_honours_the_gate(monkeypatch, case):
    reason = _gate(monkeypatch, case)
    good, _bad, _user, _s = _system_scan()
    plan = findings_act.build_plan([], [good], {}, False, Config())
    if reason is None:
        assert plan.system_offered == [good]
    else:
        assert plan.system_offered == []
        assert plan.system_not_offered == [(good, reason)]
        assert reason in findings_act.confirm_text(plan)


def _done(reason):
    good, _bad, _user, _s = _system_scan()
    plan = findings_act.ActPlan(permanent=False, system_offered=[good])
    res = elevate.HelperResult(
        freed=0, removed=0, errors=[], unmatched=0, nonce="0" * 32,
        deadline_hit=False, findings=[elevate.FindingOutcome(
            key=item_key(good), status="not_removed", freed=0, reason=reason, note="")])
    out = findings_act.ActOutcome(plan=plan, system_status=findings_act.SYS_DONE,
                                  result=res)
    return "\n".join(findings_act._system_lines(out))


def test_gui_cross_filesystem_hint_names_the_gui_control():
    text = _done("it is on another filesystem than the administrator quarantine; "
                 "nothing was moved (delete it permanently instead)")
    assert "tick 'Delete permanently (no Undo)'" in text
    assert "--permanent" not in text


def test_gui_permanent_refusal_is_not_the_cross_filesystem_case():
    text = _done("not removed: /var/lib/x/y is on another filesystem")
    assert "Delete permanently (no Undo)" not in text and "--permanent" not in text


def test_gui_hint_matches_the_real_checkbox_label(qtbot):
    from .test_review_view import make as make_view

    w = make_view(qtbot)
    assert f"'{w.permanent_box.text()}'" in findings_act.GUI_CROSS_FS_HINT
