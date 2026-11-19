"""Elevated cleaning in the GUI (Task 11).

Nothing here launches anything real: ``elevate_launch.launch_elevated`` and
``winenv.run_elevated`` are replaced by stubs that fail unless a test installs
a fake launcher. Request directories are created under tmp_path, the config
path points at a nonexistent tmp file, and history is recorded into a list.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import QObject, Qt, Signal, Slot  # noqa: E402

from cleanix import elevated  # noqa: E402
from cleanix.config import Config  # noqa: E402
from cleanix.core import (  # noqa: E402
    context, elevate, elevate_launch, engine, history, quarantine, safety, service, utils,
    winenv,
)
from cleanix.core.models import (  # noqa: E402
    CleanableItem, CleanerReport, CleanOutcome, CleanResult, ItemKind, ScanResult, item_key,
)
from cleanix.gui import elevation, workers  # noqa: E402
from cleanix.gui import power_view as pv  # noqa: E402
from cleanix.gui.simple_view import ConfirmCleanDialog, ConfirmInfo, SimpleState, SimpleView  # noqa: E402

POSIX = os.name != "nt"

# Fake cleaner ids (apt/logs/temp) count as helper-allowlisted here.
pytestmark = pytest.mark.usefixtures("fake_admin_allowlist")
UID = os.getuid() if POSIX else 1000


# --------------------------------------------------------------------------
# isolation
# --------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def isolation(tmp_path, monkeypatch):
    """No real prompt, no real config/history, request dirs under tmp."""

    def never(*a, **k):
        raise AssertionError("a real elevation was attempted")

    monkeypatch.setattr(elevate_launch, "launch_elevated", never)
    monkeypatch.setattr(winenv, "run_elevated", never)
    monkeypatch.setattr(elevation, "_config_path",
                        lambda: str(tmp_path / "no-config" / "config.yaml"))
    monkeypatch.setattr(elevation, "_invoking_user_name", lambda: "alice")
    made = []
    base = tmp_path / "reqbase"
    base.mkdir()

    def make_request_dir():
        d = Path(os.path.realpath(tempfile.mkdtemp(prefix="cleanix-elevate-", dir=base)))
        made.append(d)
        return d

    monkeypatch.setattr(elevate, "make_request_dir", make_request_dir)
    recorded = []
    monkeypatch.setattr(history, "record",
                        lambda freed, items, *, mode, registry=0: recorded.append((freed, items, mode)))
    return SimpleNamespace(made=made, history=recorded, tmp=tmp_path)


def _arg(argv, flag):
    return argv[argv.index(flag) + 1]


class FakeLauncher:
    """Replaces launch_elevated. ``action(argv, selection)`` simulates the helper."""

    def __init__(self, monkeypatch, action=None, log=None):
        self.calls = []
        self.requests = []
        self.action = action
        self.log = log
        monkeypatch.setattr(elevate_launch, "launch_elevated", self)

    def __call__(self, argv):
        argv = list(argv)
        self.calls.append(argv)
        if self.log is not None:
            self.log.append("admin")
        req = Path(_arg(argv, "--request"))
        raw = req.read_text(encoding="utf-8")
        self.requests.append(json.loads(raw))
        sel = elevate.parse_request(raw.encode("utf-8"))
        if self.action is None:
            return 0
        return self.action(argv, sel)


def write_result(argv, nonce, **kw):
    fields = dict(freed=0, removed=0, errors=[], unmatched=0)
    fields.update(kw)
    elevate.write_result(Path(_arg(argv, "--result")),
                         elevate.HelperResult(nonce=nonce, **fields))


def succeed(**kw):
    def action(argv, sel):
        write_result(argv, sel.nonce, **kw)
        return 0
    return action


def raises(exc):
    def action(argv, sel):
        raise exc
    return action


def it(name, *, root=False, cid=None, size=10, kind=ItemKind.PATH):
    cid = cid or ("logs" if root else "temp")
    if kind is ItemKind.COMMAND:
        return CleanableItem(cleaner_id=cid, description=name, size=size, kind=kind,
                             command=["tool", name], requires_root=root)
    return CleanableItem(cleaner_id=cid, description=name, size=size,
                         path=f"/somewhere/{name}", requires_root=root)


def user_summary(items=(), freed=100, removed=1, run="run1", cancelled=False):
    outs = [CleanOutcome(i, removed=True, freed=i.size) for i in items]
    return service.CleanSummary(result=CleanResult(outcomes=outs), quarantine_run=run,
                                freed=freed, removed=removed, errors=[],
                                cancelled=cancelled)


def fake_clean(monkeypatch, *, summary=None, log=None, seen=None, hook=None):
    def clean(items, config, dry_run=True, use_quarantine=True, progress=None,
              cancel=None, record_history=True):
        items = list(items)
        if seen is not None:
            seen.append(dict(items=items, dry_run=dry_run, q=use_quarantine))
        if log is not None:
            log.append("user")
        if hook is not None:
            hook()
        s = summary if summary is not None else user_summary(items)
        s.cancelled = bool(cancel and cancel())
        return s

    monkeypatch.setattr(workers.service, "clean", clean)


class Recorder:
    def __init__(self, worker):
        self.events = []
        worker.finished.connect(lambda r: self.events.append(("finished", r)))
        worker.cancelled.connect(lambda: self.events.append(("cancelled",)))
        worker.failed.connect(lambda m: self.events.append(("failed", m)))

    def terminal(self):
        return [e[0] for e in self.events]

    @property
    def summary(self):
        assert self.terminal() == ["finished"], self.events
        return self.events[0][1]


def run_sync(items, *, dry_run=False, use_quarantine=True):
    w = workers.ElevatedCleanWorker(items, Config(), dry_run=dry_run,
                                    use_quarantine=use_quarantine)
    rec = Recorder(w)
    w.run()
    return rec


# --------------------------------------------------------------------------
# split / request
# --------------------------------------------------------------------------
def test_split_items_by_requires_root():
    a, b, c = it("a"), it("b", root=True), it("c")
    user, admin = elevation.split_items([a, b, c])
    assert user == [a, c] and admin == [b]


def test_request_contains_only_ids_and_keys_never_paths_of_unselected_items(
        monkeypatch, isolation):
    user_item = it("user-only-secret")
    admins = [it("x", root=True), it("y", root=True, cid="journal"),
              it("z", root=True, kind=ItemKind.COMMAND)]
    fake_clean(monkeypatch)
    launcher = FakeLauncher(monkeypatch, succeed())
    run_sync([user_item] + admins)
    assert len(launcher.requests) == 1
    data = launcher.requests[0]
    assert set(data) == {"version", "invoking_user", "only", "keys", "use_quarantine", "nonce"}
    assert data["keys"] == [item_key(i) for i in admins]
    assert data["only"] == ["logs", "journal"]
    assert data["use_quarantine"] is False
    assert data["invoking_user"] == "alice"
    assert len(data["nonce"]) == 32 and int(data["nonce"], 16) >= 0
    raw = json.dumps(data)
    assert "user-only-secret" not in raw
    argv = launcher.calls[0]
    req = Path(_arg(argv, "--request"))
    assert req.name == "request.json"
    assert Path(_arg(argv, "--result")) == req.parent / "result.json"
    assert req.parent == isolation.made[0]
    assert _arg(argv, "--config") == str(isolation.tmp / "no-config" / "config.yaml")
    if POSIX:
        assert _arg(argv, "--uid") == str(os.getuid())
    else:
        assert "--uid" not in argv


def test_request_with_quarantine_requested_still_says_false(monkeypatch):
    launcher = FakeLauncher(monkeypatch, succeed())
    elevation.run_elevated_part([it("a", root=True)], Config(), use_quarantine=True)
    assert launcher.requests[0]["use_quarantine"] is False


def test_one_prompt_per_run(monkeypatch):
    fake_clean(monkeypatch)
    launcher = FakeLauncher(monkeypatch, succeed(removed=3, freed=30))
    rec = run_sync([it(f"a{i}", root=True) for i in range(3)] + [it("u")])
    assert len(launcher.calls) == 1
    assert rec.summary.admin.status == "done"


def test_helper_never_launched_when_there_are_no_admin_items(monkeypatch, isolation):
    fake_clean(monkeypatch)
    rec = run_sync([it("u1"), it("u2")])  # the autouse stub would raise if launched
    s = rec.summary
    assert s.admin is None and s.admin_selected == 0
    assert isolation.made == []
    assert elevation.admin_outcome_lines(s) == []


def test_dry_run_never_elevates(monkeypatch, isolation):
    seen = []
    fake_clean(monkeypatch, seen=seen)
    u, r = it("u"), it("r", root=True, size=70)
    rec = run_sync([u, r], dry_run=True)
    # Only the user items are dry-run in-process; admin items are previewed.
    assert seen[0]["items"] == [u] and seen[0]["dry_run"] is True
    assert isolation.made == []
    s = rec.summary
    assert s.admin is None and s.admin_selected == 0 and s.cancelled is False
    assert s.admin_preview_count == 1 and s.admin_preview_size == 70


def test_dry_run_of_a_mix_reports_no_errors_for_admin_items(monkeypatch, isolation, tmp_path):
    """Real service.clean (dry run): administrator items are never sent
    through the in-process engine, so no "requires root" errors; they are a
    preview included in "Would free"; the launcher is never called."""
    calls = []
    monkeypatch.setattr(elevate_launch, "launch_elevated",
                        lambda *a, **k: calls.append(a) or 0)
    f = tmp_path / "user-file.tmp"
    f.write_bytes(b"x" * 40)
    user_item = CleanableItem("temp", "user file", size=40, path=str(f))
    admins = [CleanableItem("logs", "sys log a", size=1000, path="/var/log/a",
                            requires_root=True),
              CleanableItem("logs", "sys cmd", size=500, kind=ItemKind.COMMAND,
                            command=["tool", "x"], requires_root=True)]
    s = run_sync([user_item] + admins, dry_run=True).summary
    assert calls == [] and isolation.made == [] and isolation.history == []
    assert s.errors == [] and s.admin is None and s.admin_selected == 0
    assert s.result.dry_run is True
    assert s.admin_preview_count == 2 and s.admin_preview_size == 1500
    assert s.user_freed == 40 and s.freed == 40 + 1500
    assert s.removed == s.user_removed + 2
    assert f.exists()  # dry run
    lines = elevation.admin_outcome_lines(s)
    assert lines == ["2 administrator item(s) (1.5 KiB) would be removed after one "
                     "administrator prompt; they cannot be undone"]


def test_dry_run_previews_hklm_registry_items_without_elevation(monkeypatch, isolation):
    """HKLM registry items are previewed (counted separately) and never
    elevated or backed up in a dry run."""
    from cleanix.core import regpromises
    from cleanix.core.models import RegTarget

    backups = []
    monkeypatch.setattr(quarantine.Quarantine, "store_registry",
                        lambda self, item, backend: backups.append(item))
    reg = CleanableItem("win_reg_startup", "Startup entry: Foo", size=0,
                        kind=ItemKind.REGISTRY, requires_root=True,
                        reg=RegTarget("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                      "Foo", "f" * 64))
    s = run_sync([reg, it("r", root=True, size=9)], dry_run=True).summary
    assert isolation.made == [] and backups == []
    assert s.admin_preview_count == 2 and s.admin_preview_registry == 1
    monkeypatch.setattr(regpromises, "UNDO_SHIPPED", True)
    assert "1 registry entry is backed up first" in elevation.admin_outcome_lines(s)[0]
    monkeypatch.setattr(regpromises, "UNDO_SHIPPED", False)
    assert elevation.admin_outcome_lines(s)[0].endswith("they cannot be undone")


def test_dry_run_with_only_admin_items_is_still_a_dry_run(monkeypatch, isolation):
    s = run_sync([it("r", root=True, size=9)], dry_run=True).summary
    assert s.result.dry_run is True and s.errors == [] and s.cancelled is False
    assert s.freed == 9 and s.admin_preview_count == 1


def test_power_view_dry_run_shows_admin_preview_line(qtbot, monkeypatch, isolation):
    monkeypatch.setattr(workers, "start_worker", lambda w: w.run())
    shown = []
    monkeypatch.setattr(pv.PowerView, "show_results", lambda self, s, text: shown.append(text))
    monkeypatch.setattr(elevation, "admin_allowlist", lambda: frozenset({"logs", "temp"}))
    factory = elevation.make_clean_worker_factory(Config(), elevation=True)
    v = pv.PowerView(Config(), clean_worker_factory=factory, allow_admin_items=True)
    qtbot.addWidget(v)
    items = [it("u", size=10), it("r", root=True, size=2048)]
    v._on_scan_finished(ScanResult(reports=[
        CleanerReport("temp", "Temp", "t", items=[items[0]]),
        CleanerReport("logs", "Logs", "l", items=[items[1]])]))
    m = v.item_model
    for r in range(m.rowCount()):
        assert m.set_checked(r, True)
    assert v.dry_run_check.isChecked()
    v.start_clean()
    status = v.status_label.text()
    assert status.startswith("Would free")
    assert "1 administrator item(s) (2.0 KiB) would be removed after one administrator " \
           "prompt" in status
    assert "errors" not in status
    assert "would be removed after one administrator prompt" in shown[0]


def test_simple_view_shows_admin_preview_line(qtbot):
    v = SimpleView(Config(), allow_admin_items=True)
    qtbot.addWidget(v)
    v._set_state(SimpleState.CLEANING)
    s = elevation.CombinedSummary(result=CleanResult(dry_run=True), freed=30, removed=2,
                                  admin_preview_count=1, admin_preview_size=20)
    v._on_clean_finished(s)
    assert "1 administrator item(s) (20 B) would be removed after one administrator " \
           "prompt; they cannot be undone" in v.admin_label.text()
    assert not v.admin_label.isHidden()


# --------------------------------------------------------------------------
# outcomes
# --------------------------------------------------------------------------
def test_declined_prompt_still_reports_user_part(monkeypatch, isolation):
    fake_clean(monkeypatch, summary=user_summary(freed=100, removed=1))
    FakeLauncher(monkeypatch, raises(elevate_launch.ElevationDeclined("no")))
    s = run_sync([it("u"), it("r1", root=True), it("r2", root=True)]).summary
    assert s.freed == 100 and s.removed == 1
    assert s.admin.status == "declined" and s.admin.result is None
    lines = elevation.admin_outcome_lines(s)
    assert lines[0] == "Administrator permission was declined; 2 items were not cleaned"
    assert isolation.history == []


@pytest.mark.parametrize("code", [1, 2, 3, 70])
def test_helper_crash_and_timeout_map_to_failed_without_hang(monkeypatch, code):
    fake_clean(monkeypatch)
    FakeLauncher(monkeypatch, raises(elevate_launch.ElevationFailed("boom", exit_code=code)))
    rec = run_sync([it("u"), it("r", root=True)])
    s = rec.summary  # finished, not failed
    assert s.admin.status == "failed"
    assert f"exit code {code}" in s.admin.detail
    lines = elevation.admin_outcome_lines(s)
    assert lines[0] == "Administrator cleaning failed (see details)"
    assert any(f"exit code {code}" in line for line in lines)


def test_partial_result_after_deadline_exit_is_reported(monkeypatch, isolation):
    """Exit 3 (deadline): some items are gone; their counts are not lost."""
    fake_clean(monkeypatch, summary=user_summary(freed=100, removed=1))

    def action(argv, sel):
        write_result(argv, sel.nonce, removed=1, freed=7, deadline_hit=True)
        raise elevate_launch.ElevationFailed("exit 3", exit_code=3)

    FakeLauncher(monkeypatch, action)
    s = run_sync([it("u"), it("r1", root=True), it("r2", root=True)]).summary
    assert s.admin.status == "failed" and s.admin.result.removed == 1
    assert s.freed == 107 and s.removed == 2
    assert isolation.history == [(7, 1, "delete")]
    text = "\n".join(elevation.admin_outcome_lines(s))
    assert "may already have been removed" in text and "time limit" in text


def test_refused_exit_with_zero_removed_says_nothing_was_removed(monkeypatch):
    def action(argv, sel):
        write_result(argv, sel.nonce, errors=["request refused: x"])
        raise elevate_launch.ElevationFailed("exit 1", exit_code=1)

    FakeLauncher(monkeypatch, action)
    out = elevation.run_elevated_part([it("r", root=True)], Config())
    assert out.status == "failed" and out.result.removed == 0
    assert "no administrator items were removed" in out.message
    # exit code 1 without a valid result: never claim nothing was removed
    FakeLauncher(monkeypatch, raises(elevate_launch.ElevationFailed("x", exit_code=1)))
    out = elevation.run_elevated_part([it("r", root=True)], Config())
    assert out.result is None and "may already have been removed" in out.message


@pytest.mark.parametrize("cause", [TimeoutError("t"), subprocess.TimeoutExpired("x", 1)])
def test_timeout_never_reads_a_result(monkeypatch, isolation, cause):
    fake_clean(monkeypatch, summary=user_summary(freed=100, removed=1))
    reads = []
    monkeypatch.setattr(elevate, "read_result", lambda p: reads.append(p) or None)

    def action(argv, sel):
        write_result(argv, sel.nonce, removed=5, freed=50)  # must be ignored
        try:
            raise cause
        except Exception as exc:
            raise elevate_launch.ElevationFailed("helper gave up") from exc

    FakeLauncher(monkeypatch, action)
    s = run_sync([it("u"), it("r", root=True)]).summary
    assert reads == []
    assert s.admin.status == "failed" and s.admin.result is None
    assert s.admin.outcome_unknown
    assert "unknown" in s.admin.message and "may still be running" in s.admin.message
    assert s.freed == 100 and s.removed == 1
    assert isolation.history == []
    assert not isolation.made[0].exists()


def test_timeout_detected_from_message_too(monkeypatch):
    FakeLauncher(monkeypatch, raises(elevate_launch.ElevationFailed(
        "elevated helper timed out and may still be running")))
    out = elevation.run_elevated_part([it("r", root=True)], Config())
    assert out.status == "failed" and out.outcome_unknown and out.result is None


def test_unavailable_elevation_message(monkeypatch):
    fake_clean(monkeypatch)
    FakeLauncher(monkeypatch, raises(elevate_launch.ElevationUnavailable("no pkexec")))
    s = run_sync([it("u"), it("r", root=True)]).summary
    assert s.admin.status == "unavailable"
    assert elevation.admin_outcome_lines(s)[0] == (
        "Administrator cleaning is not available on this system; "
        "1 administrator items were not cleaned")


def test_nonce_mismatch_rejected(monkeypatch, isolation):
    fake_clean(monkeypatch, summary=user_summary(freed=100, removed=1))

    def action(argv, sel):
        write_result(argv, uuid.uuid4().hex, removed=9, freed=900)
        return 0

    FakeLauncher(monkeypatch, action)
    s = run_sync([it("u"), it("r", root=True)]).summary
    assert s.admin.status == "failed" and s.admin.result is None
    assert "stale or unexpected" in s.admin.message
    assert s.freed == 100 and s.removed == 1
    assert isolation.history == []


@pytest.mark.parametrize("payload", [b"\xff\xfe garbage", b"[1, 2]", b'{"freed": -1}',
                                     b'{"freed": "x"}', b""])
def test_tampered_result_file_is_ignored_safely(monkeypatch, payload):
    def action(argv, sel):
        Path(_arg(argv, "--result")).write_bytes(payload)
        return 0

    FakeLauncher(monkeypatch, action)
    out = elevation.run_elevated_part([it("r", root=True)], Config())
    assert out.status == "failed" and out.result is None


def test_missing_result_file_is_failed(monkeypatch):
    FakeLauncher(monkeypatch, lambda argv, sel: 0)
    out = elevation.run_elevated_part([it("r", root=True)], Config())
    assert out.status == "failed" and out.result is None


def test_unexpected_launcher_exception_is_failed_with_generic_message(monkeypatch):
    FakeLauncher(monkeypatch, raises(RuntimeError("secret detail /etc/shadow")))
    out = elevation.run_elevated_part([it("r", root=True)], Config())
    assert out.status == "failed"
    assert "secret" not in out.message and "secret" not in out.detail


@pytest.mark.parametrize("case", ["success", "declined", "unavailable", "failed",
                                  "timeout", "exception", "write_request"])
def test_request_dir_removed_after_run_even_on_error(monkeypatch, isolation, case):
    actions = {
        "success": succeed(removed=1, freed=1),
        "declined": raises(elevate_launch.ElevationDeclined()),
        "unavailable": raises(elevate_launch.ElevationUnavailable()),
        "failed": raises(elevate_launch.ElevationFailed("x", exit_code=2)),
        "timeout": raises(elevate_launch.ElevationFailed("timed out")),
        "exception": raises(OSError("boom")),
    }
    if case == "write_request":
        def bad_write(directory, selection):
            (Path(directory) / "request.json.partial").write_text("x")
            raise OSError("disk full")
        monkeypatch.setattr(elevate, "write_request", bad_write)
        launcher = FakeLauncher(monkeypatch)
    else:
        launcher = FakeLauncher(monkeypatch, actions[case])
    out = elevation.run_elevated_part([it("r", root=True)], Config())
    assert len(isolation.made) == 1
    assert not isolation.made[0].exists()
    if case == "write_request":
        assert launcher.calls == [] and out.status == "failed"
    else:
        assert len(launcher.calls) == 1


def test_empty_admin_part_launches_nothing(isolation):
    out = elevation.run_elevated_part([], Config())
    assert out.status == "done" and isolation.made == []


# --------------------------------------------------------------------------
# ordering, cancel, combined summary, history
# --------------------------------------------------------------------------
def test_admin_part_runs_only_after_user_part_finished(monkeypatch):
    log = []
    fake_clean(monkeypatch, log=log)
    FakeLauncher(monkeypatch, succeed(removed=1, freed=1), log=log)
    run_sync([it("r", root=True), it("u")])
    assert log == ["user", "admin"]


def test_admin_items_only_go_to_the_helper(monkeypatch):
    seen = []
    fake_clean(monkeypatch, seen=seen)
    launcher = FakeLauncher(monkeypatch, succeed())
    u, r = it("u"), it("r", root=True)
    run_sync([r, u], use_quarantine=True)
    assert seen[0]["items"] == [u] and seen[0]["q"] is True
    assert launcher.requests[0]["keys"] == [item_key(r)]


def test_cancel_before_admin_step_skips_elevation(monkeypatch, isolation):
    holder = {}

    def cancel_during_user_part():
        holder["w"].cancel()

    fake_clean(monkeypatch, hook=cancel_during_user_part)
    launcher = FakeLauncher(monkeypatch, succeed())
    w = workers.ElevatedCleanWorker([it("u"), it("r1", root=True), it("r2", root=True)],
                                    Config(), dry_run=False, use_quarantine=True)
    holder["w"] = w
    rec = Recorder(w)
    w.run()
    s = rec.summary
    assert launcher.calls == [] and isolation.made == []
    assert s.cancelled and s.admin is None and s.admin_selected == 2
    assert "2 administrator items were not cleaned" in elevation.admin_outcome_lines(s)[0]


def test_cancel_after_user_part_without_engine_noticing_still_skips(monkeypatch):
    """The user part completed (summary.cancelled False) but cancel was then
    requested: the admin step is skipped and the run reported as stopped."""
    holder = {}
    s0 = user_summary(freed=5, removed=1)

    def clean(items, config, **kw):
        holder["w"].cancel()
        return s0  # engine already done: cancelled stays False

    monkeypatch.setattr(workers.service, "clean", clean)
    launcher = FakeLauncher(monkeypatch, succeed())
    w = workers.ElevatedCleanWorker([it("u"), it("r", root=True)], Config(),
                                    dry_run=False, use_quarantine=True)
    holder["w"] = w
    rec = Recorder(w)
    w.run()
    assert launcher.calls == []
    assert rec.summary.cancelled and rec.summary.freed == 5


def test_combined_summary_fields(monkeypatch, isolation):
    u = it("u")
    base = user_summary([u], freed=100, removed=1, run="qrun")
    base.errors = [CleanOutcome(it("bad"), removed=False, error="nope")]
    fake_clean(monkeypatch, summary=base)
    FakeLauncher(monkeypatch, succeed(removed=2, freed=30, refused=1, unmatched=1,
                                      errors=["x: denied"]))
    s = run_sync([u, it("r1", root=True), it("r2", root=True), it("r3", root=True),
                  it("r4", root=True)]).summary
    assert isinstance(s, service.CleanSummary) and isinstance(s, elevation.CombinedSummary)
    assert s.result is base.result and s.quarantine_run == "qrun"
    assert s.freed == 130 and s.removed == 3
    assert s.user_freed == 100 and s.user_removed == 1
    assert [o.error for o in s.errors] == ["nope"]  # only CleanOutcome objects
    assert s.admin.status == "done" and s.admin_selected == 4 and not s.cancelled
    lines = elevation.admin_outcome_lines(s)
    assert lines[0] == f"Administrator items: removed 2, freed {utils.human_size(30)}"
    text = "\n".join(lines)
    assert ("1 administrator item(s) were not cleaned because the administrator helper "
            "refused them (for safety it only cleans a fixed list of system "
            "locations)") in text
    assert ("1 administrator item(s) were not cleaned because the administrator helper "
            "no longer found them; scan again") in text
    assert "x: denied" in text and "cannot be undone" in text
    assert "Scan again to refresh the list." in text


def test_history_recorded_in_process_only_when_removed(monkeypatch, isolation):
    fake_clean(monkeypatch)  # fake: the user part records nothing itself
    FakeLauncher(monkeypatch, succeed(removed=2, freed=30))
    run_sync([it("r", root=True)])
    assert isolation.history == [(30, 2, "delete")]
    isolation.history.clear()
    FakeLauncher(monkeypatch, succeed(removed=0, freed=0, refused=1))
    run_sync([it("r", root=True)])
    assert isolation.history == []


def test_history_failure_never_breaks_the_flow(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disk")

    monkeypatch.setattr(history, "record", boom)
    fake_clean(monkeypatch)
    FakeLauncher(monkeypatch, succeed(removed=1, freed=1))
    assert run_sync([it("r", root=True)]).summary.admin.status == "done"


def test_user_part_failure_emits_failed_and_never_elevates(monkeypatch, isolation):
    def clean(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(workers.service, "clean", clean)
    w = workers.ElevatedCleanWorker([it("u"), it("r", root=True)], Config(),
                                    dry_run=False, use_quarantine=True)
    rec = Recorder(w)
    w.run()
    assert rec.terminal() == ["failed"] and isolation.made == []


def test_worker_on_a_real_thread_and_cancel_all_and_wait(qtbot, monkeypatch):
    import time

    entered = threading.Event()
    holder = {}

    def hook():
        # Block inside the user part until cancel_all_and_wait() cancels us.
        entered.set()
        deadline = time.monotonic() + 5
        while not holder["w"].was_cancelled and time.monotonic() < deadline:
            time.sleep(0.005)

    fake_clean(monkeypatch, hook=hook)
    launcher = FakeLauncher(monkeypatch, succeed())
    w = workers.ElevatedCleanWorker([it("u"), it("r", root=True)], Config(),
                                    dry_run=False, use_quarantine=True)
    holder["w"] = w
    done = threading.Event()
    got = []

    class Sink(QObject):
        @Slot(object)
        def on_finished(self, s):
            got.append(s)
            done.set()

    sink = Sink()
    w.finished.connect(sink.on_finished)
    workers.start_worker(w)
    qtbot.waitUntil(entered.is_set, timeout=5000)
    assert workers.cancel_all_and_wait(5000) is True
    qtbot.waitUntil(done.is_set, timeout=5000)
    assert launcher.calls == []
    assert got[0].cancelled and got[0].admin is None


# --------------------------------------------------------------------------
# availability / factory
# --------------------------------------------------------------------------
@pytest.mark.parametrize("osname, which, exists, expected", [
    ("windows", None, False, True),
    ("linux", "/usr/bin/pkexec", False, True),
    ("linux", None, True, False),
    ("macos", None, True, True),
    ("macos", None, False, False),
    ("freebsd", "/usr/bin/pkexec", True, False),
])
def test_elevation_available_per_platform(monkeypatch, osname, which, exists, expected):
    monkeypatch.setattr(elevation, "current_os", lambda: osname)
    monkeypatch.setattr(utils, "safe_which", lambda cmd, *a, **k: which if cmd == "pkexec" else None)
    monkeypatch.setattr(elevation.os.path, "exists",
                        lambda p: exists and p == "/usr/bin/osascript")
    assert elevation.elevation_available() is expected


def test_elevation_available_never_raises(monkeypatch):
    def boom(*a, **k):
        raise OSError("x")

    monkeypatch.setattr(elevation, "current_os", lambda: "linux")
    monkeypatch.setattr(utils, "safe_which", boom)
    assert elevation.elevation_available() is False


def test_factory_accepts_both_view_signatures():
    cfg = Config()
    f = elevation.make_clean_worker_factory(cfg)
    w1 = f([it("a")], cfg, dry_run=False, use_quarantine=True)       # SimpleView
    w2 = f([it("a")], dry_run=True, use_quarantine=False)            # PowerView
    assert isinstance(w1, workers.ElevatedCleanWorker)
    assert isinstance(w2, workers.ElevatedCleanWorker)
    assert w2._config is cfg and w2._dry_run is True
    plain = elevation.make_clean_worker_factory(cfg, elevation=False)
    w3 = plain([it("a")], dry_run=False, use_quarantine=True)
    assert type(w3) is workers.CleanWorker
    for w in (w1, w2, w3):
        w.deleteLater()


# --------------------------------------------------------------------------
# UI text
# --------------------------------------------------------------------------
def test_confirm_dialog_mentions_administrator_when_needed(qtbot):
    d = ConfirmCleanDialog(ConfirmInfo(3, 10, admin_items=2))
    qtbot.addWidget(d)
    text = d.warning_label.text()
    assert ("2 item(s) need administrator permission: you will be asked once, "
            "and they are removed permanently (cannot be undone)") in text
    assert "the rest of this clean can be undone" in text
    assert d.keep_copy_checkbox.isEnabled()
    only_admin = ConfirmCleanDialog(ConfirmInfo(2, 10, admin_items=2))
    qtbot.addWidget(only_admin)
    assert not only_admin.keep_copy_checkbox.isEnabled()
    assert not only_admin.keep_copy()
    assert "can be undone" not in only_admin.warning_label.text().replace("cannot be undone", "")
    plain = ConfirmCleanDialog(ConfirmInfo(2, 10))
    qtbot.addWidget(plain)
    assert "administrator" not in plain.warning_label.text()


def test_power_confirm_text_mentions_administrator():
    u, r = it("u"), it("r", root=True)
    text = pv.PowerView.confirm_text([u, r], 0, True)
    assert ("1 item(s) need administrator permission: you will be asked once, and they "
            "are removed permanently (cannot be undone)") in text
    assert "except administrator items" in text
    only_admin = pv.PowerView.confirm_text([r], 0, True)
    assert "restore" not in only_admin and "permanently" in only_admin
    assert "administrator" not in pv.PowerView.confirm_text([u], 0, True)


class FakeCleanWorker(QObject):
    progress = Signal(str, int, int)
    finished = Signal(object)
    cancelled = Signal()
    failed = Signal(str)

    def __init__(self, outcome):
        super().__init__()
        self.outcome = outcome

    def cancel(self):
        pass

    @Slot()
    def run(self):
        self.finished.emit(self.outcome)


def combined(status=None, *, admin_selected=2, result=None, run="run1",
             cancelled=False, freed=100, removed=1, **kw):
    admin = None
    if status is not None:
        admin = elevation.ElevatedOutcome(status, kw.pop("message", "m"), result=result,
                                          detail=kw.pop("detail", ""))
    extra_f = result.freed if result else 0
    extra_r = result.removed if result else 0
    return elevation.CombinedSummary(
        result=CleanResult(), quarantine_run=run, freed=freed + extra_f,
        removed=removed + extra_r, errors=[], cancelled=cancelled, admin=admin,
        admin_selected=admin_selected, user_freed=freed, user_removed=removed)


def _simple_view(qtbot, monkeypatch, outcome, infos=None):
    monkeypatch.setattr(workers, "start_worker", lambda w: w.run())
    confirms = []

    def confirm(info):
        confirms.append(info)
        return True, True

    v = SimpleView(Config(), clean_worker_factory=lambda items, cfg, **k: FakeCleanWorker(outcome),
                   confirm=confirm, allow_admin_items=True)
    qtbot.addWidget(v)
    return v, confirms


def _tick_group(v, title):
    for tree in v.trees():
        for i in range(tree.topLevelItemCount()):
            r = tree.topLevelItem(i)
            if r.text(0) == title:
                r.setCheckState(0, Qt.CheckState.Checked)
                return
    raise AssertionError(title)


def _admin_scan():
    items = [CleanableItem("temp", "user tmp", size=100, path="/t/u"),
             CleanableItem("logs", "system log", size=50, path="/var/log/x",
                           requires_root=True)]
    return ScanResult(reports=[CleanerReport("temp", "Temp", "", items=[items[0]]),
                               CleanerReport("logs", "Logs", "", items=[items[1]])])


def test_simple_confirm_counts_admin_items(qtbot, monkeypatch):
    v, confirms = _simple_view(qtbot, monkeypatch, combined("done", result=elevate.HelperResult(
        freed=50, removed=1, errors=[], unmatched=0)))
    v.set_scan_result(_admin_scan())
    assert any(r.text(0) == "Old system logs"
               for r in (v.also_tree.topLevelItem(i)
                         for i in range(v.also_tree.topLevelItemCount())))
    _tick_group(v, "Old system logs")
    v._on_clean_clicked()
    assert confirms[0].admin_items == 1 and confirms[0].count == 2
    assert confirms[0].irreversible == 0


@pytest.mark.parametrize("status, first", [
    ("done", "Administrator items: removed 1, freed "),
    ("declined", "Administrator permission was declined; 2 items were not cleaned"),
    ("unavailable", "Administrator cleaning is not available on this system; "
                    "2 administrator items were not cleaned"),
    ("failed", "Administrator cleaning failed (see details)"),
    (None, "Stopped before the administrator step; 2 administrator items were not cleaned."),
])
def test_simple_done_screen_shows_admin_outcome_and_user_part(qtbot, monkeypatch,
                                                              status, first):
    res = (elevate.HelperResult(freed=50, removed=1, errors=[], unmatched=0)
           if status == "done" else None)
    outcome = combined(status, result=res, cancelled=status is None)
    v, _ = _simple_view(qtbot, monkeypatch, outcome)
    v.set_scan_result(_admin_scan())
    _tick_group(v, "Old system logs")
    v._on_clean_clicked()
    assert v.state() is SimpleState.DONE
    assert v.admin_label.text().startswith(first)
    assert v.admin_label.isVisibleTo(v)
    assert "Freed" in v.done_label.text()  # the user part is always shown
    # Undo only ever covers the user part's quarantine run.
    assert v.undo_button.isEnabled()
    assert "administrator items cannot be undone" in v.undo_label.text()


def test_simple_done_screen_without_admin_items_unchanged(qtbot, monkeypatch):
    v, _ = _simple_view(qtbot, monkeypatch, combined(None, admin_selected=0))
    v.set_scan_result(_admin_scan())
    v._on_clean_clicked()
    assert v.state() is SimpleState.DONE
    assert v.admin_label.text() == "" and not v.admin_label.isVisibleTo(v)
    assert v.undo_label.text() == ""


def test_admin_badge_visible_in_power_table(qtbot, monkeypatch):
    monkeypatch.setattr(workers, "start_worker", lambda w: w.run())
    v = pv.PowerView(Config(), allow_admin_items=True)
    qtbot.addWidget(v)
    v._on_scan_finished(_admin_scan())
    m = v.item_model
    row = next(r for r in range(m.rowCount()) if m.item_at(r).requires_root)
    assert m.data(m.index(row, 4)) == "Admin"
    assert "Requires administrator" in pv.PowerView.detail_text(m.item_at(row))


def test_power_admin_outcome_shown_and_admin_rows_kept(qtbot, monkeypatch):
    monkeypatch.setattr(workers, "start_worker", lambda w: w.run())
    shown = []
    monkeypatch.setattr(pv.PowerView, "show_results",
                        lambda self, summary, text: shown.append(text))
    monkeypatch.setattr(pv.PowerView, "confirm_clean", lambda self, text: True)
    scan = _admin_scan()
    user_item, admin_item = scan.all_items()

    def factory(items, *, dry_run, use_quarantine):
        s = combined("declined", admin_selected=1)
        s.result = CleanResult(outcomes=[CleanOutcome(user_item, removed=True, freed=100)])
        return FakeCleanWorker(s)

    v = pv.PowerView(Config(), allow_admin_items=True, clean_worker_factory=factory)
    qtbot.addWidget(v)
    v._on_scan_finished(scan)
    m = v.item_model
    for r in range(m.rowCount()):
        m.set_checked(r, True)
    v.dry_run_check.setChecked(False)
    v.clean_button.click()
    keys = [item_key(m.item_at(r)) for r in range(m.rowCount())]
    assert keys == [item_key(admin_item)]  # the admin row stays (counts only)
    assert "Administrator permission was declined; 1 items were not cleaned" in shown[0]
    assert "declined" in v.status_label.text()
    # the kept admin row is unchecked: a second click never re-prompts
    assert m.checked_items() == []


def test_power_second_click_after_admin_clean_does_not_reprompt(qtbot, monkeypatch):
    monkeypatch.setattr(workers, "start_worker", lambda w: w.run())
    monkeypatch.setattr(pv.PowerView, "show_results", lambda *a, **k: None)
    monkeypatch.setattr(pv.PowerView, "confirm_clean", lambda self, text: True)
    calls = []

    def factory(items, *, dry_run, use_quarantine):
        calls.append(list(items))
        return FakeCleanWorker(combined("done", admin_selected=1,
                                        result=elevate.HelperResult(
                                            freed=50, removed=1, errors=[], unmatched=0)))

    v = pv.PowerView(Config(), allow_admin_items=True, clean_worker_factory=factory)
    qtbot.addWidget(v)
    v._on_scan_finished(_admin_scan())
    m = v.item_model
    v.select_none_visible()
    row = next(r for r in range(m.rowCount()) if m.item_at(r).requires_root)
    assert m.set_checked(row, True)
    v.dry_run_check.setChecked(False)
    v.clean_button.click()
    v.clean_button.click()
    assert v.status_label.text() == "No visible items selected."
    assert len(calls) == 1


# --------------------------------------------------------------------------
# end to end: the REAL helper, in-process, through a fake launcher
# --------------------------------------------------------------------------
class E2EFakeCleaner:
    def __init__(self, cid, items):
        self.id = cid
        self.name = cid
        self._items = items

    def scan(self):
        return CleanerReport(cleaner_id=self.id, name=self.name, description="d",
                             items=list(self._items))


@pytest.fixture
def helper_env(tmp_path, monkeypatch):
    """The test_elevate.py environment: fake user with a tmp home, fake scan,
    allowlist {"logs"}; owner/group trust patched (tmp is user-owned)."""
    saved = dict(os.environ)
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    user = context.TargetUser("alice", home, UID, UID, True)

    def fake_invoking_user():
        return user

    fake_invoking_user.cache_clear = lambda: None  # type: ignore[attr-defined]
    monkeypatch.setattr(context, "invoking_user", fake_invoking_user)
    monkeypatch.setattr(history, "invoking_user", fake_invoking_user)
    monkeypatch.setattr(quarantine, "invoking_user", fake_invoking_user)
    monkeypatch.setattr(elevated, "_user_for_uid", lambda uid: "alice" if uid == UID else None)
    for var, sub in (("HOME", ""), ("USERPROFILE", ""),
                     ("XDG_STATE_HOME", ".local/state"), ("XDG_DATA_HOME", ".local/share"),
                     ("XDG_CONFIG_HOME", ".config"), ("XDG_CACHE_HOME", ".cache"),
                     ("LOCALAPPDATA", "AppData/Local"), ("APPDATA", "AppData/Roaming")):
        monkeypatch.setenv(var, str(home / sub) if sub else str(home))
    monkeypatch.delenv("PKEXEC_UID", raising=False)
    monkeypatch.setattr(elevated, "admin_cleaner_ids", lambda: frozenset({"logs"}))
    monkeypatch.setattr(elevated, "_trusted_owner", lambda st, uid: True)
    monkeypatch.setattr(elevated, "_untrusted_group", lambda st, groups: False)
    cleaners = []

    def fake_build(config, only=None, exclude=None):
        wanted = {c.lower() for c in only} if only else None
        return [c for c in cleaners if wanted is None or c.id.lower() in wanted]

    monkeypatch.setattr(service, "build_cleaners", fake_build)
    assert str(history.state_dir()).startswith(str(home))
    assert str(quarantine.quarantine_root()).startswith(str(home))
    junk = tmp_path / "junk"
    junk.mkdir()
    yield SimpleNamespace(home=home, junk=junk, cleaners=cleaners)
    os.environ.clear()
    os.environ.update(saved)
    context.configure(None)
    safety.set_protected_globs([])


def _file(directory, name):
    p = Path(directory) / name
    p.write_bytes(b"x" * 10)
    return p


def test_end_to_end_with_real_helper(monkeypatch, isolation, helper_env):
    junk = helper_env.junk
    user_file = _file(junk, "user.bin")
    admin_file = _file(junk, "admin.bin")
    foreign_file = _file(junk, "foreign.bin")
    gone_file = junk / "gone.bin"  # selected, but the fresh scan won't report it
    i_user = CleanableItem("temp", "user file", size=10, path=str(user_file))
    i_admin = CleanableItem("logs", "admin file", size=10, path=str(admin_file),
                            requires_root=True)
    # requires_root but its cleaner is not on the helper's allowlist: refused
    i_foreign = CleanableItem("user_cache", "foreign", size=10, path=str(foreign_file),
                              requires_root=True)
    i_gone = CleanableItem("logs", "gone", size=10, path=str(gone_file), requires_root=True)
    # The GUI thinks this needs admin rights, but the helper's fresh scan says
    # it does not: refused after matching (in-scan eligibility check).
    flip_file = _file(junk, "flip.bin")
    i_flip = CleanableItem("logs", "flip", size=10, path=str(flip_file), requires_root=True)
    fresh_flip = CleanableItem("logs", "flip", size=10, path=str(flip_file),
                               requires_root=False)
    helper_env.cleaners.append(E2EFakeCleaner("logs", [i_admin, fresh_flip]))

    runs = []

    def launcher(argv):
        argv = list(argv)
        # Through the helper's own argument parsing: strip interpreter/-I/-m.
        helper_args = argv[argv.index("cleanix.elevated") + 1:]
        assert argv[1:3] == ["-I", "-m"]
        saved_env = dict(os.environ)
        real_is_root = engine.is_root
        engine.is_root = lambda: True  # only while the "elevated" helper runs
        try:
            rc = elevated.main(helper_args)
        finally:
            engine.is_root = real_is_root
            os.environ.clear()
            os.environ.update(saved_env)
            context.configure(None)
            safety.set_protected_globs([])
        runs.append(rc)
        if rc != 0:
            raise elevate_launch.ElevationFailed(f"exit {rc}", exit_code=rc)
        return 0

    monkeypatch.setattr(elevate_launch, "launch_elevated", launcher)
    rec = run_sync([i_user, i_admin, i_foreign, i_gone, i_flip], use_quarantine=False)
    s = rec.summary
    assert runs == [0]
    assert not user_file.exists()          # user part, in-process
    assert not admin_file.exists()         # admin part, by the helper
    assert foreign_file.exists()           # refused up front (not allowlisted)
    assert flip_file.exists()              # refused after the fresh scan
    assert s.admin.status == "done"
    r = s.admin.result
    assert (r.removed, r.freed, r.refused, r.unmatched) == (1, 10, 2, 1)
    assert s.user_removed == 1 and s.removed == 2 and s.freed == 20
    assert s.admin_selected == 4
    lines = elevation.admin_outcome_lines(s)
    assert lines[0] == f"Administrator items: removed 1, freed {utils.human_size(10)}"
    assert ("2 administrator item(s) were not cleaned because the administrator helper "
            "refused them (for safety it only cleans a fixed list of system "
            "locations)") in lines
    assert ("1 administrator item(s) were not cleaned because the administrator helper "
            "no longer found them; scan again") in lines
    # history: the user part (service.clean) and one in-process admin entry
    assert (10, 1, "delete") in isolation.history
    assert isolation.history[-1] == (10, 1, "delete")
    assert len(isolation.history) == 2
    assert not isolation.made[0].exists()
    # the helper wrote nothing under the user's home except the GUI's own
    # (user part) manifest
    assert not quarantine.quarantine_root().exists()


# --------------------------------------------------------------------------
# fix round 1: cancel around the elevated step, exit codes, Power unchecking
# --------------------------------------------------------------------------
def test_cancel_between_write_request_and_launch_skips_launcher(monkeypatch, isolation):
    fake_clean(monkeypatch)
    launcher = FakeLauncher(monkeypatch, succeed(removed=1, freed=1))
    holder = {}
    real_write = elevate.write_request

    def write_then_cancel(directory, selection):
        path = real_write(directory, selection)
        holder["w"].cancel()  # Cancel lands after the request was written
        return path

    monkeypatch.setattr(elevate, "write_request", write_then_cancel)
    w = workers.ElevatedCleanWorker([it("u"), it("r1", root=True), it("r2", root=True)],
                                    Config(), dry_run=False, use_quarantine=True)
    holder["w"] = w
    rec = Recorder(w)
    w.run()
    s = rec.summary
    assert launcher.calls == []
    assert s.admin is None and s.cancelled and s.admin_selected == 2
    assert not s.late_cancel
    assert len(isolation.made) == 1 and not isolation.made[0].exists()
    assert elevation.admin_outcome_lines(s)[0].startswith(
        "Stopped before the administrator step; 2 administrator items")
    assert isolation.history == []


def test_run_elevated_part_cancel_checked_right_before_launch(monkeypatch, isolation):
    launcher = FakeLauncher(monkeypatch, succeed())
    assert elevation.run_elevated_part([it("r", root=True)], Config(),
                                       cancel=lambda: True) is None
    assert launcher.calls == [] and not isolation.made[0].exists()
    out = elevation.run_elevated_part([it("r", root=True)], Config(), cancel=lambda: False)
    assert out.status == "done" and out.launched and len(launcher.calls) == 1


def test_late_cancel_is_reported_not_hidden(monkeypatch, isolation):
    fake_clean(monkeypatch, summary=user_summary(freed=100, removed=1))
    holder = {}

    def action(argv, sel):
        holder["w"].cancel()  # user clicks Cancel while the helper runs
        write_result(argv, sel.nonce, removed=3, freed=30)
        return 0

    launcher = FakeLauncher(monkeypatch, action)
    w = workers.ElevatedCleanWorker([it("u")] + [it(f"r{i}", root=True) for i in range(3)],
                                    Config(), dry_run=False, use_quarantine=True)
    holder["w"] = w
    progress = []
    w.progress.connect(lambda n, d, t: progress.append(n))
    rec = Recorder(w)
    w.run()
    s = rec.summary
    assert len(launcher.calls) == 1
    assert progress[-1] == elevation.ADMIN_WAIT_MESSAGE
    assert "it cannot be stopped from here" in elevation.ADMIN_WAIT_MESSAGE
    assert s.admin.status == "done" and s.admin.result.removed == 3
    assert s.late_cancel is True
    assert s.cancelled is False  # nothing was stopped early
    assert s.freed == 130 and s.removed == 4
    lines = elevation.admin_outcome_lines(s)
    assert lines[0].startswith("Administrator items: removed 3")
    assert ("Cancel arrived after administrator permission was given; that step "
            "could not be stopped.") in lines
    assert isolation.history == [(30, 3, "delete")]


def test_cancel_during_declined_prompt_is_not_a_late_cancel(monkeypatch):
    fake_clean(monkeypatch)
    holder = {}

    def action(argv, sel):
        holder["w"].cancel()
        raise elevate_launch.ElevationDeclined()

    FakeLauncher(monkeypatch, action)
    w = workers.ElevatedCleanWorker([it("r", root=True)], Config(), dry_run=False,
                                    use_quarantine=True)
    holder["w"] = w
    rec = Recorder(w)
    w.run()
    assert rec.summary.admin.status == "declined" and not rec.summary.late_cancel


@pytest.mark.parametrize("code, reads", [(1, True), (2, True), (3, True),
                                         (5, False), (127, False), (126, False)])
def test_result_read_only_for_helper_exit_codes(monkeypatch, code, reads):
    calls = []
    real_read = elevate.read_result
    monkeypatch.setattr(elevate, "read_result", lambda p: calls.append(p) or real_read(p))

    def action(argv, sel):
        write_result(argv, sel.nonce, removed=2, freed=20)
        raise elevate_launch.ElevationFailed("x", exit_code=code)

    FakeLauncher(monkeypatch, action)
    out = elevation.run_elevated_part([it("r", root=True)], Config())
    assert out.status == "failed"
    assert bool(calls) is reads
    assert (out.result is not None) is reads


class ProgressThenFinish(QObject):
    """Emits the admin wait message, records the view's Cancel state, finishes."""

    progress = Signal(str, int, int)
    finished = Signal(object)
    cancelled = Signal()
    failed = Signal(str)

    def __init__(self, outcome, probe):
        super().__init__()
        self.outcome = outcome
        self.probe = probe
        self.states = []

    def cancel(self):
        pass

    @Slot()
    def run(self):
        self.states.append(("before", self.probe()))
        self.progress.emit(elevation.ADMIN_WAIT_MESSAGE, 0, 0)
        self.states.append(("waiting", self.probe()))
        self.finished.emit(self.outcome)


def _late_summary():
    s = combined("done", admin_selected=1, result=elevate.HelperResult(
        freed=50, removed=1, errors=[], unmatched=0))
    s.late_cancel = True
    return s


def test_simple_cancel_disabled_while_waiting_for_admin_and_late_cancel_shown(
        qtbot, monkeypatch):
    monkeypatch.setattr(workers, "start_worker", lambda w: w.run())
    holder = {}

    def factory(items, cfg, **k):
        w = ProgressThenFinish(_late_summary(),
                               lambda: holder["v"].cancel_clean_button.isEnabled())
        holder["w"] = w
        return w

    v = SimpleView(Config(), clean_worker_factory=factory,
                   confirm=lambda info: (True, True), allow_admin_items=True)
    holder["v"] = v
    qtbot.addWidget(v)
    v.set_scan_result(_admin_scan())
    _tick_group(v, "Old system logs")
    v._on_clean_clicked()
    assert holder["w"].states == [("before", True), ("waiting", False)]
    assert v.state() is SimpleState.DONE
    assert elevation.LATE_CANCEL_LINE in v.admin_label.text()
    # the next clean starts with an enabled Cancel button again
    v.set_scan_result(_admin_scan())
    v._on_clean_clicked()
    assert holder["w"].states[0] == ("before", True)


def test_power_cancel_disabled_while_waiting_for_admin_and_late_cancel_shown(
        qtbot, monkeypatch):
    monkeypatch.setattr(workers, "start_worker", lambda w: w.run())
    shown = []
    monkeypatch.setattr(pv.PowerView, "show_results",
                        lambda self, summary, text: shown.append(text))
    monkeypatch.setattr(pv.PowerView, "confirm_clean", lambda self, text: True)
    holder = {}

    def factory(items, *, dry_run, use_quarantine):
        w = ProgressThenFinish(_late_summary(), lambda: holder["v"].cancel_button.isEnabled())
        holder["w"] = w
        return w

    v = pv.PowerView(Config(), allow_admin_items=True, clean_worker_factory=factory)
    holder["v"] = v
    qtbot.addWidget(v)
    v._on_scan_finished(_admin_scan())
    m = v.item_model
    row = next(r for r in range(m.rowCount()) if m.item_at(r).requires_root)
    m.set_checked(row, True)
    v.dry_run_check.setChecked(False)
    v.clean_button.click()
    assert holder["w"].states == [("before", True), ("waiting", False)]
    assert elevation.LATE_CANCEL_LINE in v.status_label.text()
    assert elevation.LATE_CANCEL_LINE in shown[0]
    assert not v.cancel_button.isEnabled()  # idle again


def test_power_unchecks_only_admin_rows_sent_in_this_clean(qtbot, monkeypatch):
    monkeypatch.setattr(workers, "start_worker", lambda w: w.run())
    monkeypatch.setattr(pv.PowerView, "show_results", lambda *a, **k: None)
    monkeypatch.setattr(pv.PowerView, "confirm_clean", lambda self, text: True)
    sent = []

    def factory(items, *, dry_run, use_quarantine):
        sent.append(list(items))
        return FakeCleanWorker(combined("declined", admin_selected=len(items)))

    scan = ScanResult(reports=[CleanerReport("logs", "Logs", "", items=[
        CleanableItem("logs", "alpha log", size=5, path="/var/log/a", requires_root=True),
        CleanableItem("logs", "beta log", size=6, path="/var/log/b", requires_root=True),
    ])])
    v = pv.PowerView(Config(), allow_admin_items=True, clean_worker_factory=factory)
    qtbot.addWidget(v)
    v._on_scan_finished(scan)
    m = v.item_model
    for r in range(m.rowCount()):
        assert m.set_checked(r, True)
    v.filter_edit.setText("alpha")  # beta is checked but hidden: not sent
    v.dry_run_check.setChecked(False)
    v.clean_button.click()
    assert [i.description for i in sent[0]] == ["alpha log"]
    assert [i.description for i in m.checked_items()] == ["beta log"]
