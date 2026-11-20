"""The system-wide beta gate (system_findings.gate_problem, applied in
plan()), the frozen-binary refusal (I1), the request-size check before any
prompt (M6) and the exact cross-filesystem match (I3), at plan, CLI and
review level. Hermetic: the launcher is a fake; nothing is launched.

These tests do NOT use the opt-in beta_system_actions fixture: each one
sets the gate inputs itself.
"""

from __future__ import annotations

import sys

import pytest

from cleanix import cli
from cleanix.core import elevate, elevate_launch, system_findings
from cleanix.core.models import item_key

from test_cli_system_findings import (  # noqa: F401 - env is an autouse fixture
    PHRASE, Launcher, _install, _patch_scan, _phrase, _review, _run, _sys, _user, env,
)


_REAL_IS_FROZEN = system_findings.is_frozen
_REAL_EUID_IS_ROOT = system_findings.euid_is_root


@pytest.fixture(autouse=True)
def gate_inputs(monkeypatch):
    """Start from: env unset, not frozen, not root."""
    monkeypatch.delenv(system_findings.BETA_ENV, raising=False)
    monkeypatch.setattr(system_findings, "is_frozen", lambda: False)
    monkeypatch.setattr(system_findings, "euid_is_root", lambda: False)


def _on(monkeypatch):
    monkeypatch.setenv(system_findings.BETA_ENV, "1")


# -- plan() --------------------------------------------------------------------

def test_plan_off_by_default():
    s = _sys()
    p = system_findings.plan([s])
    assert p.offered == [] and p.not_offered == [(s, system_findings.BETA_OFF)]
    assert "CLEANIX_BETA_SYSTEM_ACTIONS=1" in system_findings.BETA_OFF


@pytest.mark.parametrize("value", ["", "0", "true", "yes", " 1", "1 ", "on"])
def test_plan_only_exactly_1_enables(monkeypatch, value):
    monkeypatch.setenv(system_findings.BETA_ENV, value)
    assert system_findings.plan([_sys()]).offered == []


def test_plan_on_with_env_1(monkeypatch):
    _on(monkeypatch)
    s = _sys()
    assert system_findings.plan([s]).offered == [s]


def test_plan_refuses_a_root_process_even_when_enabled(monkeypatch):
    _on(monkeypatch)
    monkeypatch.setattr(system_findings, "euid_is_root", lambda: True)
    s = _sys()
    assert system_findings.plan([s]).not_offered == [(s, system_findings.RUN_AS_USER)]


def test_plan_refuses_a_frozen_binary_even_when_enabled(monkeypatch):
    _on(monkeypatch)
    monkeypatch.setattr(system_findings, "is_frozen", lambda: True)
    s = _sys()
    assert system_findings.plan([s]).not_offered == [(s, system_findings.FROZEN_BINARY)]


def test_real_frozen_and_euid_seams(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert _REAL_IS_FROZEN()
    monkeypatch.delattr(sys, "frozen")
    assert not _REAL_IS_FROZEN()
    if sys.platform == "win32":
        assert not _REAL_EUID_IS_ROOT()  # never "root" on Windows


def test_windows_reason_wins_over_the_gate(monkeypatch):
    from cleanix import elevated

    monkeypatch.setattr(elevated, "_findings_supported", lambda: False)
    s = _sys()
    assert system_findings.plan([s]).not_offered == [(s, system_findings.NOT_ON_WINDOWS)]


# -- CLI clean --act-on -----------------------------------------------------------

@pytest.mark.parametrize("case", ["env_off", "root", "frozen"])
def test_act_on_gate_closed_never_prompts_or_launches(monkeypatch, capsys, case):
    if case != "env_off":
        _on(monkeypatch)
    if case == "root":
        monkeypatch.setattr(system_findings, "euid_is_root", lambda: True)
        reason = system_findings.RUN_AS_USER
    elif case == "frozen":
        monkeypatch.setattr(system_findings, "is_frozen", lambda: True)
        reason = system_findings.FROZEN_BINARY
    else:
        reason = system_findings.BETA_OFF
    _patch_scan(monkeypatch, [_sys()])
    launch = _install(monkeypatch, Launcher())
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    asked = _phrase(monkeypatch, PHRASE)
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute")
    assert code == 0 and launch.calls == [] and asked == []
    assert f"not offered: {reason}" in " ".join(out.split())
    assert "Nothing can be acted on right now" in out


def test_act_on_gate_open_offers_and_launches(monkeypatch, capsys):
    _on(monkeypatch)
    _patch_scan(monkeypatch, [_sys()])
    launch = _install(monkeypatch, Launcher())
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    asked = _phrase(monkeypatch, PHRASE)
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute")
    assert code == 0 and len(launch.calls) == 1 and len(asked) == 1


# -- review ------------------------------------------------------------------------

def test_review_gate_closed_lists_reason_and_never_launches(tmp_path, monkeypatch, capsys):
    p, user = _user(tmp_path)
    _patch_scan(monkeypatch, [user, _sys()])
    launch = _install(monkeypatch, Launcher())
    code, out, asked = _review(monkeypatch, capsys, ["s", "d", "d"], "big_files",
                               "orphan_files")
    assert code == 0 and launch.calls == [] and len(asked) == 1  # only the user item
    assert f"not offered: {system_findings.BETA_OFF}" in out


def test_review_gate_open_queues_the_system_item(tmp_path, monkeypatch, capsys):
    _on(monkeypatch)
    _patch_scan(monkeypatch, [_sys()])
    launch = _install(monkeypatch, Launcher())
    code, out, asked = _review(monkeypatch, capsys, ["d", PHRASE], "orphan_files")
    assert code == 0 and len(launch.calls) == 1


# -- I1: frozen binary, defence in depth ----------------------------------------------

def test_run_findings_request_refuses_in_a_frozen_binary(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    calls = []
    req = elevate.findings_request_for([_sys()])
    with pytest.raises(ValueError, match="standalone binary"):
        elevate_launch.run_findings_request(req, "ann", launcher=calls.append)
    assert calls == []


# -- M6: request size checked before any prompt ----------------------------------------

def test_oversize_request_is_not_offered_before_any_prompt(monkeypatch, capsys):
    _on(monkeypatch)
    items = [_sys(f"/opt/app{k:03d}/" + "x" * 200) for k in range(30)]
    full = system_findings._request_size(items)
    monkeypatch.setattr(elevate, "MAX_REQUEST_BYTES", full // 2)
    p = system_findings.plan(items)
    assert p.offered and len(p.offered) < len(items)
    assert system_findings._request_size(p.offered) <= full // 2
    assert {w for _i, w in p.not_offered} == {system_findings.TOO_LARGE}
    # adding the next item would not fit
    assert system_findings._request_size(items[:len(p.offered) + 1]) > full // 2
    # and the CLI: what is offered is sent, never refused after the phrase
    _patch_scan(monkeypatch, items)
    launch = _install(monkeypatch, Launcher())
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    asked = _phrase(monkeypatch, PHRASE)
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute")
    assert code == 0 and len(asked) == 1 and len(launch.calls) == 1
    assert len(launch.requests[0].findings.items) == len(p.offered)
    assert system_findings.TOO_LARGE in out


def test_request_size_failure_fails_closed(monkeypatch):
    _on(monkeypatch)

    def boom(items):
        raise RuntimeError("x")

    monkeypatch.setattr(system_findings, "_request_size", boom)
    s = _sys()
    assert system_findings.plan([s]).not_offered == [(s, system_findings.CANNOT_CHECK)]


def test_request_bytes_is_what_write_request_writes(tmp_path):
    sel = elevate.Selection(invoking_user="ann", only=[], keys=[], use_quarantine=False,
                            findings=elevate.findings_request_for([_sys()]))
    path = elevate.write_request(tmp_path, sel)
    assert path.read_bytes() == elevate.request_bytes(sel)


# -- I3: only the quarantine's own cross-filesystem message -----------------------------

QUARANTINE_REASON = ("it is on another filesystem than the administrator quarantine; "
                     "nothing was moved (delete it permanently instead)")
ROOT_DELETE_REASON = "not removed: /opt/stale-app/sub is on another filesystem"


def _outcome(reason):
    return elevate.FindingOutcome(key=item_key(_sys()), status="not_removed",
                                  freed=0, reason=reason, note="")


def test_cross_filesystem_matches_only_the_quarantine_message():
    from cleanix.core import quarantine

    assert quarantine.CROSS_FILESYSTEM_QUARANTINE in QUARANTINE_REASON
    assert system_findings.is_cross_filesystem(_outcome(QUARANTINE_REASON))
    assert not system_findings.is_cross_filesystem(_outcome(ROOT_DELETE_REASON))


def test_outcome_lines_hint_is_caller_supplied():
    s = _sys()
    cli_lines = system_findings.outcome_lines(s, _outcome(QUARANTINE_REASON), False)
    assert any("run again with --permanent" in x for x in cli_lines)
    gui = system_findings.outcome_lines(s, _outcome(QUARANTINE_REASON), False,
                                        cross_fs_hint="HINT")
    assert gui[-1] == "HINT"
    lines = system_findings.outcome_lines(s, _outcome(ROOT_DELETE_REASON), True)
    assert not any("--permanent" in x for x in lines)


def test_refused_permanent_deletion_on_another_filesystem_exits_2(monkeypatch, capsys):
    _on(monkeypatch)
    s = _sys()
    _patch_scan(monkeypatch, [s])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    _install(monkeypatch, Launcher(status={item_key(s): "not_removed"},
                                   reason=ROOT_DELETE_REASON))
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes",
                     "--permanent")
    assert "NOT removed: not removed: /opt/stale-app/sub is on another filesystem" in out
    assert "run again with --permanent" not in out
    assert code == 2
