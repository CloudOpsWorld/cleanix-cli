"""User-level non-path remedies: launch agents and systemd user units (Task 7).

Every external command goes through ``remedy_exec.runner``, replaced here by
a recorder, so nothing is ever executed. Plist/unit parsing is pure Python,
so most tests run on Windows too (fake home and sysroot from ``orphan_env``).
"""

from __future__ import annotations

import dataclasses
import json
import os
import plistlib
import sys

import pytest

from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners import orphan_launch_jobs as olj
from cleanix.cleaners import stale_services
from cleanix.config import Config
from cleanix.core import actions, history, quarantine, remedy_exec, safety
from cleanix.core.models import CleanableItem
from cleanix.core.remedy import Remedy, RemedyKind, fingerprint_of, path_remedy

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")

UID = os.getuid() if hasattr(os, "getuid") else 501


class Recorder:
    """Stands in for the real command runner; records every argv."""

    def __init__(self):
        self.calls = []
        self.result = (0, "", "")
        self.side_effect = None

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        assert 0 < timeout <= 120
        if self.side_effect is not None:
            out = self.side_effect(list(argv))
            if out is not None:
                return out
        return self.result


@pytest.fixture(autouse=True)
def _reset_globs():
    yield
    safety.set_protected_globs([])


@pytest.fixture
def env(orphan_env, tmp_path, monkeypatch):
    monkeypatch.setattr(history, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: tmp_path / "q")
    rec = Recorder()
    monkeypatch.setattr(remedy_exec, "runner", rec)
    monkeypatch.setattr(remedy_exec, "_uid", lambda: UID)

    def _no_real_commands(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("a real command was about to run")

    monkeypatch.setattr(remedy_exec, "run_command", _no_real_commands)
    (orphan_env.root / "usr/lib/systemd/system").mkdir(parents=True)
    orphan_env.rec = rec
    orphan_env.q = tmp_path / "q"
    return orphan_env


def _agents(env):
    return env.home / "Library" / "LaunchAgents"


def _units(env):
    return env.home / ".config" / "systemd" / "user"


def _job(env, name="com.gone.job", label=None, program="/opt/gone/bin/gone", where=None):
    d = where if where is not None else _agents(env)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{name}.plist"
    with open(p, "wb") as fh:
        plistlib.dump({"Label": label or name, "ProgramArguments": [program, "--x"]}, fh)
    return p


def _unit(env, name="mine.service", program="/opt/gone/x", where=None):
    d = where if where is not None else _units(env)
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(f"[Service]\nExecStart={program}\n\n[Install]\nWantedBy=default.target\n",
                 encoding="utf-8")
    return p


def _scanned(reporter_cls, path):
    """The detector's own finding for ``path`` (as a real scan builds it)."""
    items = [i for i in reporter_cls(Config()).scan().items if i.path == str(path)]
    assert len(items) == 1, [i.description for i in items]
    assert items[0].remedy is not None
    return items[0]


def _job_item(env, **kw):
    p = _job(env, **kw)
    return p, _scanned(olj.OrphanLaunchJobReporter, p)


def _unit_item(env, **kw):
    p = _unit(env, **kw)
    return p, _scanned(stale_services.StaleSystemdUnitReporter, p)


def _forged(path, kind, extra, fp=None):
    """A hand-made finding (what a caller could pass in)."""
    return CleanableItem(
        cleaner_id="orphan_launch_jobs" if kind is RemedyKind.LAUNCH_JOB else "stale_services",
        description=os.path.basename(str(path)), size=10, path=str(path), report_only=True,
        remedy=Remedy(kind, fp if fp is not None else (fingerprint_of(str(path)) or (0, 0, 0, 0)),
                      extra=extra),
    )


def _skips(summary):
    return [r for _i, r in summary.skipped]


def _bootout(label):
    return ["launchctl", "bootout", f"gui/{UID}/{label}"]


# -- the brief's tests -----------------------------------------------------------


def test_launch_job_backup_then_remove(env):
    p, item = _job_item(env)
    data = p.read_bytes()
    seen = []
    env.rec.side_effect = lambda argv: seen.append(p.exists())
    summary = actions.act([item], Config(), dry_run=False)
    assert _skips(summary) == []
    assert summary.removed == 1 and summary.errors == []
    assert env.rec.calls == [_bootout("com.gone.job")]
    assert seen == [True]  # the job was stopped while its file still existed
    assert not p.exists()
    # The file is kept in this batch's quarantine run, metadata preserved.
    run_dir = env.q / summary.quarantine_run
    (kept,) = list((run_dir / "files").iterdir())
    assert kept.read_bytes() == data
    (out,) = summary.result.outcomes
    assert out.item is item and out.removed and out.error is None
    assert out.note.startswith("permanent (a copy of the file is kept in ")
    assert str(run_dir / "files") in out.note
    assert [e["mode"] for e in history.load()] == ["quarantine"]


def test_launch_job_permanent_keeps_a_copy_restore_does_not_claim_it(env):
    p, item = _job_item(env)
    data = p.read_bytes()
    st = os.lstat(str(p))
    summary = actions.act([item], Config(), dry_run=False, permanent=True)
    assert summary.removed == 1 and summary.errors == [] and not p.exists()
    assert summary.quarantine_run is None  # nothing here is undoable
    assert summary.backup_run
    run_dir = env.q / summary.backup_run
    (kept,) = list((run_dir / "files").iterdir())
    assert kept.read_bytes() == data
    assert os.stat(str(kept)).st_mtime_ns // 10**6 == st.st_mtime_ns // 10**6
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert [i["type"] for i in manifest["items"]] == ["copy"]
    assert str(run_dir / "files") in summary.result.outcomes[0].note
    assert [e["mode"] for e in history.load()] == ["delete"]
    # A copy is not an Undo: restore leaves it alone and says so.
    res = quarantine.restore(summary.backup_run)
    assert res["restored"] == [] and res["failed"] == []
    assert res["not_restored"] and not p.exists()
    assert kept.exists()


def test_unit_name_validation_rejects_option_like(env):
    for bad in ("-x.service", "--now.service", "a b.service", "a/b.service", "x..service",
                "a\nb.service", "mine.socket", "mine", "", "-"):
        with pytest.raises(ValueError):
            remedy_exec.disable_argv(bad)
    for bad in ("-com.x", "--help", "a b", "a/b", "..", "x\x00y", "", "com.x\t"):
        with pytest.raises(ValueError):
            remedy_exec.bootout_argv(UID, bad)
    with pytest.raises(ValueError):
        remedy_exec.bootout_argv(-1, "com.x")
    assert not remedy_exec.argv_allowed(["systemctl", "--user", "disable", "--now", "--global"])
    assert not remedy_exec.argv_allowed(["systemctl", "--user", "disable", "--now", "-x.service"])
    assert not remedy_exec.argv_allowed(["launchctl", "bootout", f"gui/{UID}/-x"])
    # An option-like unit file on disk is never acted on, and nothing runs.
    p = _unit(env, name="-x.service")
    item = _forged(p, RemedyKind.SYSTEMD_UNIT, (("unit", "-x.service"),))
    summary = actions.act([item], Config(), dry_run=False)
    assert summary.removed == 0 and len(_skips(summary)) == 1
    assert env.rec.calls == [] and p.exists()


def test_remedy_reverifies_before_removing(env):
    # Changed between scan and act: skipped up front.
    p, item = _job_item(env)
    with open(p, "ab") as fh:
        fh.write(b"\n")
    summary = actions.act([item], Config(), dry_run=False)
    assert _skips(summary) == ["changed since scan"] and p.exists()
    assert env.rec.calls == []

    # Changed while an earlier item was processed: the Engine-time re-check
    # catches it, nothing runs for it and it is not removed.
    a, ia = _job_item(env, name="com.gone.a")
    b, ib = _job_item(env, name="com.gone.b")

    def touch_b(argv):
        if argv == _bootout("com.gone.a"):
            with open(b, "wb") as fh:
                plistlib.dump({"Label": "com.gone.b", "Program": "/opt/gone/other"}, fh)

    env.rec.side_effect = touch_b
    summary = actions.act([ia, ib], Config(), dry_run=False)
    assert summary.removed == 1 and not a.exists() and b.exists()
    assert _skips(summary) and _skips(summary)[0].startswith("changed since scan")
    assert env.rec.calls == [_bootout("com.gone.a")]


def test_runner_failure_does_not_block_file_removal_but_is_reported(env):
    p, item = _job_item(env)
    u, uitem = _unit_item(env)
    env.rec.result = (5, "", "Boot-out failed: 5: Input/output error\n")
    summary = actions.act([item, uitem], Config(), dry_run=False)
    assert summary.removed == 2 and summary.errors == []
    assert not p.exists() and not u.exists()
    for out in summary.result.outcomes:
        assert out.removed and out.error is None
        assert "warning" in out.note and "exit 5" in out.note
    unit_note = summary.result.outcomes[1].note
    assert "daemon-reload" in unit_note  # the reload failed too and is said

    # A runner that raises or times out is a warning as well.
    p2, item2 = _job_item(env, name="com.gone.two")

    def boom(argv):
        raise RuntimeError("no launchctl")

    env.rec.side_effect = boom
    summary = actions.act([item2], Config(), dry_run=False)
    assert summary.removed == 1 and not p2.exists() and summary.errors == []
    assert "warning" in summary.result.outcomes[0].note


def test_file_removal_failure_is_an_error(env, monkeypatch):
    p, item = _job_item(env)

    def fail_store(self, path):
        raise OSError("disk full")

    monkeypatch.setattr(quarantine.Quarantine, "store", fail_store)
    summary = actions.act([item], Config(), dry_run=False)
    assert summary.removed == 0 and len(summary.errors) == 1 and p.exists()
    assert "disk full" in summary.errors[0].error


# -- extra coverage ----------------------------------------------------------------


def test_label_must_match_plist_label_key(env):
    # The file name differs from its Label: the Label is what is stopped.
    p = _job(env, name="renamed", label="com.real.job")
    item = _scanned(olj.OrphanLaunchJobReporter, p)
    assert dict(item.remedy.extra) == {"label": "com.real.job"}
    forged = dataclasses.replace(item, remedy=dataclasses.replace(
        item.remedy, extra=(("label", "com.other.job"),)))
    by_name = dataclasses.replace(item, remedy=dataclasses.replace(
        item.remedy, extra=(("label", "renamed"),)))
    summary = actions.act([forged], Config(), dry_run=False)
    summary2 = actions.act([by_name], Config(), dry_run=False)
    assert summary.removed == 0 and summary2.removed == 0 and p.exists()
    assert env.rec.calls == []
    summary = actions.act([item], Config(), dry_run=False)
    assert summary.removed == 1 and env.rec.calls == [_bootout("com.real.job")]


def test_placeholder_fingerprint_requires_reparse_evidence(env):
    p = _job(env, name="com.gone.ph")
    ok = _forged(p, RemedyKind.LAUNCH_JOB, (("label", "com.gone.ph"),), fp=(0, 0, 0, 0))
    wrong = _forged(p, RemedyKind.LAUNCH_JOB, (("label", "com.gone.other"),), fp=(0, 0, 0, 0))
    summary = actions.act([wrong], Config(), dry_run=False)
    assert summary.removed == 0 and p.exists() and env.rec.calls == []
    # Placeholder plus a plist that now runs an existing program: skipped.
    prog = env.root / "opt" / "gone" / "bin" / "gone"
    prog.parent.mkdir(parents=True)
    prog.write_text("#!/bin/sh\n")
    summary = actions.act([ok], Config(), dry_run=False)
    assert summary.removed == 0 and p.exists() and env.rec.calls == []
    prog.unlink()
    summary = actions.act([ok], Config(), dry_run=False)
    assert summary.removed == 1 and not p.exists()
    assert env.rec.calls == [_bootout("com.gone.ph")]


def test_unknown_or_extra_remedy_data_refused(env):
    p = _job(env, name="com.gone.x")
    for extra in ((), (("label", "com.gone.x"), ("path", "/etc/passwd")), (("unit", "com.gone.x"),)):
        summary = actions.act([_forged(p, RemedyKind.LAUNCH_JOB, extra)], Config(), dry_run=False)
        assert summary.removed == 0 and p.exists()
    assert env.rec.calls == []


@posix_only
def test_symlinked_plist_refused(env, tmp_path):
    real = _job(env, name="com.gone.real", where=tmp_path / "elsewhere")
    link = _agents(env) / "com.gone.real.plist"
    link.parent.mkdir(parents=True)
    os.symlink(str(real), str(link))
    item = _forged(link, RemedyKind.LAUNCH_JOB, (("label", "com.gone.real"),))
    summary = actions.act([item], Config(), dry_run=False)
    assert summary.removed == 0 and len(_skips(summary)) == 1
    assert "link" in _skips(summary)[0]
    assert os.path.islink(link) and real.exists() and env.rec.calls == []


@posix_only
def test_broken_job_link_from_scan_gets_an_honest_reason(env, tmp_path):
    link = _agents(env) / "com.gone.link.plist"
    link.parent.mkdir(parents=True)
    os.symlink(str(tmp_path / "nowhere.plist"), str(link))
    item = _scanned(olj.OrphanLaunchJobReporter, link)
    assert item.remedy.kind is RemedyKind.LAUNCH_JOB
    summary = actions.act([item], Config(), dry_run=False)
    assert _skips(summary) == [remedy_exec.IS_LINK]
    assert os.path.islink(link) and env.rec.calls == []


def test_copy_only_run_is_never_the_run_to_undo(env):
    f = env.home / "big.bin"
    f.write_bytes(b"x" * 4096)
    path_item = CleanableItem(cleaner_id="big_files", description="big", size=4096,
                              path=str(f), report_only=True, remedy=path_remedy(str(f)))
    first = actions.act([path_item], Config(), dry_run=False)
    assert first.quarantine_run
    _p, item = _job_item(env)
    second = actions.act([item], Config(), dry_run=False, permanent=True)
    assert second.backup_run and second.backup_run != first.quarantine_run
    run = [r for r in quarantine.list_runs() if r["run_id"] == second.backup_run][0]
    assert run["count"] == 1 and run["removed_count"] == 0
    assert quarantine.latest_run() == first.quarantine_run


@posix_only
def test_symlinked_launchagents_dir_refused(env, tmp_path):
    outside = tmp_path / "outside"
    p = _job(env, name="com.gone.out", where=outside)
    (env.home / "Library").mkdir(parents=True, exist_ok=True)
    os.symlink(str(outside), str(_agents(env)))
    via = _agents(env) / p.name
    item = _forged(via, RemedyKind.LAUNCH_JOB, (("label", "com.gone.out"),))
    summary = actions.act([item], Config(), dry_run=False)
    assert summary.removed == 0 and p.exists() and env.rec.calls == []
    assert "is a link" in _skips(summary)[0]


@posix_only
def test_unit_link_is_not_a_unit_file(env):
    u = _unit(env, name="real.service")
    wants = _units(env) / "default.target.wants"
    wants.mkdir()
    link = wants / "real.service"
    os.symlink(str(u), str(link))
    item = _forged(link, RemedyKind.SYSTEMD_UNIT, (("unit", "real.service"),))
    summary = actions.act([item], Config(), dry_run=False)
    assert summary.removed == 0 and os.path.islink(link) and env.rec.calls == []
    assert _skips(summary)[0].startswith("not directly inside")


def test_plist_outside_launchagents_refused(env, tmp_path):
    cases = [
        _job(env, name="com.gone.a", where=env.home / "Library" / "Other"),
        _job(env, name="com.gone.b", where=_agents(env) / "sub"),
        _job(env, name="com.gone.c", where=tmp_path / "LaunchAgents"),
    ]
    items = [_forged(p, RemedyKind.LAUNCH_JOB, (("label", p.stem),)) for p in cases]
    u = _unit(env, name="w.service", where=_units(env) / "default.target.wants")
    items.append(_forged(u, RemedyKind.SYSTEMD_UNIT, (("unit", "w.service"),)))
    # A plist under the unit directory is the wrong kind's directory.
    x = _job(env, name="com.gone.d", where=_units(env))
    items.append(_forged(x, RemedyKind.LAUNCH_JOB, (("label", "com.gone.d"),)))
    summary = actions.act(items, Config(), dry_run=False)
    assert summary.removed == 0 and len(_skips(summary)) == len(items)
    assert all(r.startswith("not directly inside") for r in _skips(summary))
    assert all(p.exists() for p in cases + [u, x]) and env.rec.calls == []


def test_command_argv_shapes_are_fixed(env, monkeypatch):
    assert remedy_exec.bootout_argv(501, "com.gone.job") == [
        "launchctl", "bootout", "gui/501/com.gone.job"]
    assert remedy_exec.disable_argv("mine.service") == [
        "systemctl", "--user", "disable", "--now", "mine.service"]
    assert remedy_exec.daemon_reload_argv() == ["systemctl", "--user", "daemon-reload"]
    for argv in (remedy_exec.bootout_argv(501, "com.gone.job"),
                 remedy_exec.disable_argv("mine.service"),
                 remedy_exec.daemon_reload_argv()):
        assert remedy_exec.argv_allowed(argv)
    for argv in (
        ["launchctl", "bootout", "system/com.gone.job"],
        ["launchctl", "bootout", "gui/501", "com.gone.job"],
        ["launchctl", "remove", "com.gone.job"],
        ["systemctl", "disable", "--now", "mine.service"],
        ["systemctl", "--user", "disable", "--now", "mine.service", "other.service"],
        ["systemctl", "--user", "daemon-reload", "--now"],
        ["systemctl", "--user", "stop", "mine.service"],
        ["sh", "-c", "launchctl bootout gui/501/x"],
        "launchctl bootout gui/501/com.gone.job",
        [],
    ):
        assert not remedy_exec.argv_allowed(argv), argv
        assert remedy_exec.run_mutating(argv)[0] == 126
    assert env.rec.calls == []  # refused shapes never reach the runner

    # The default runner pins the locale, passes argv as a list (no shell)
    # and a timeout.
    seen = []
    monkeypatch.setattr(remedy_exec, "run_command",
                        lambda argv, timeout: seen.append((list(argv), timeout)) or (0, "", ""))
    monkeypatch.setattr(remedy_exec, "runner", remedy_exec.default_runner)
    assert remedy_exec.run_mutating(remedy_exec.daemon_reload_argv())[0] == 0
    assert seen == [(["env", "LC_ALL=C", "systemctl", "--user", "daemon-reload"],
                     remedy_exec.COMMAND_TIMEOUT)]

    # In a real batch: bootout, disable --now, then one daemon-reload.
    monkeypatch.setattr(remedy_exec, "runner", env.rec)
    p, item = _job_item(env)
    u, uitem = _unit_item(env)
    summary = actions.act([item, uitem], Config(), dry_run=False)
    assert summary.removed == 2
    assert env.rec.calls == [
        _bootout("com.gone.job"),
        ["systemctl", "--user", "disable", "--now", "mine.service"],
        ["systemctl", "--user", "daemon-reload"],
    ]


def test_dry_run_runs_no_command_and_touches_nothing(env):
    p, item = _job_item(env)
    u, uitem = _unit_item(env)
    before = (p.read_bytes(), fingerprint_of(str(p)), u.read_bytes(), fingerprint_of(str(u)))
    summary = actions.act([item, uitem], Config())  # dry run is the default
    assert _skips(summary) == []
    assert summary.removed == 0 and summary.quarantine_run is None
    assert summary.backup_run is None
    assert len(summary.result.outcomes) == 2
    assert all(o.dry_run and not o.removed for o in summary.result.outcomes)
    assert env.rec.calls == []
    assert (p.read_bytes(), fingerprint_of(str(p)), u.read_bytes(), fingerprint_of(str(u))) == before
    assert not env.q.exists() and history.load() == []
    summary = actions.act([item, uitem], Config(), permanent=True)
    assert env.rec.calls == [] and not env.q.exists() and p.exists() and u.exists()


def test_target_now_exists_skips(env):
    p, item = _job_item(env)
    u, uitem = _unit_item(env)
    for prog in ("opt/gone/bin/gone", "opt/gone/x"):
        f = env.root / prog
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("#!/bin/sh\n")
    summary = actions.act([item, uitem], Config(), dry_run=False)
    assert summary.removed == 0 and _skips(summary) == [remedy_exec.EVIDENCE_GONE] * 2
    assert p.exists() and u.exists() and env.rec.calls == []


def test_unit_dropin_override_makes_evidence_unknown(env):
    u, uitem = _unit_item(env)
    d = _units(env) / "mine.service.d"
    d.mkdir()
    (d / "x.conf").write_text("[Service]\nExecStart=\nExecStart=/usr/bin/true\n", encoding="utf-8")
    summary = actions.act([uitem], Config(), dry_run=False)
    assert summary.removed == 0 and u.exists() and env.rec.calls == []


def test_mutating_allowlist_not_reachable_from_read_only_run(env):
    for argv in (remedy_exec.bootout_argv(501, "com.gone.job"),
                 remedy_exec.disable_argv("mine.service"),
                 remedy_exec.daemon_reload_argv()):
        assert oc.run(argv) == (126, "", "refused")
        assert tuple(argv[:2]) not in oc.READ_ONLY_COMMANDS
    assert env.cmds.calls == []  # refused before anything was run
    for shape in remedy_exec.MUTATING_COMMANDS:
        assert tuple(shape[:2]) not in oc.READ_ONLY_COMMANDS


def test_one_quarantine_run_for_mixed_batch(env, tmp_path):
    f = env.home / "big.bin"
    f.write_bytes(b"x" * 4096)
    path_item = CleanableItem(cleaner_id="big_files", description="big", size=4096,
                              path=str(f), report_only=True, remedy=path_remedy(str(f)))
    p, item = _job_item(env)
    u, uitem = _unit_item(env)
    summary = actions.act([path_item, item, uitem], Config(), dry_run=False)
    assert summary.removed == 3 and summary.errors == [] and _skips(summary) == []
    assert [d.name for d in env.q.iterdir()] == [summary.quarantine_run]
    manifest = json.loads((env.q / summary.quarantine_run / "manifest.json").read_text("utf-8"))
    assert len(manifest["items"]) == 3
    assert len(history.load()) == 1
    assert summary.result.outcomes[0].note is None  # an ordinary path: undoable
    assert all("permanent" in o.note for o in summary.result.outcomes[1:])

    # Permanent: paths deleted, job/unit copies kept in one backup run.
    f.write_bytes(b"y" * 4096)
    path_item = dataclasses.replace(path_item, remedy=path_remedy(str(f)))
    p, item = _job_item(env, name="com.gone.again")
    u, uitem = _unit_item(env, name="again.service")
    summary = actions.act([path_item, item, uitem], Config(), dry_run=False, permanent=True)
    assert summary.removed == 3 and summary.quarantine_run is None
    runs = sorted(d.name for d in env.q.iterdir())
    assert len(runs) == 2 and summary.backup_run in runs
    assert len(history.load()) == 2


def test_root_and_receipt_kinds_keep_their_reasons(env):
    p, item = _job_item(env)
    rooted = dataclasses.replace(item, requires_root=True)
    receipt = _forged(p, RemedyKind.PKG_RECEIPT, (("id", "com.gone.pkg"),))
    summary = actions.act([rooted], Config(), dry_run=False)
    assert _skips(summary) == [actions.NEEDS_ELEVATION]
    summary = actions.act([receipt], Config(), dry_run=False)
    assert _skips(summary) == [actions.NOT_HANDLED]
    assert p.exists() and env.rec.calls == []


@posix_only
def test_file_owned_by_another_account_refused(env, monkeypatch):
    p, item = _job_item(env)
    monkeypatch.setattr(remedy_exec, "_uid", lambda: UID + 1)
    summary = actions.act([item], Config(), dry_run=False)
    assert summary.removed == 0 and p.exists() and env.rec.calls == []
    assert _skips(summary) == [remedy_exec.NOT_OWNED]
