"""A spent time budget always yields exactly one "results are incomplete" note.

Detectors stop discovering silently when ``budget.expired()``; the shared
reporter base turns that into a single visible note (never a silent partial).
"""

from __future__ import annotations

import plistlib
import sys

import pytest

from cleanix.cleaners import orphan_app_data as oad
from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners import orphan_launch_jobs as olj
from cleanix.cleaners import stale_launchers as sl
from cleanix.cleaners import stale_receipts as sr
from cleanix.cleaners import stale_services as ss
from cleanix.cleaners.orphan_files import UnownedSystemFilesReporter
from cleanix.config import Config

sys.path.insert(0, "tests")
from test_orphan_files import make, setup  # noqa: E402

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")


def _expired() -> Config:
    cfg = Config()
    cfg.orphan_max_seconds = 0.0
    return cfg


def _check(report, findings_marker=None):
    notes = [i for i in report.items if "incomplete" in i.description]
    assert len(notes) == 1, [i.description for i in report.items]
    assert notes[0].size == 0 and notes[0].report_only
    assert "time limit" in notes[0].description
    # nothing but the note: no finding was produced after expiry
    assert report.items == notes


def test_remaining_counts_down():
    t = [0.0]
    b = oc.ScanBudget(5, 10.0, lambda: t[0])
    b.start()
    t[0] = 4.0
    assert b.remaining() == 6.0
    t[0] = 99.0
    assert b.remaining() == 0.0


def test_services_expired_budget_one_note(orphan_env):
    d = orphan_env.root / "etc/systemd/system"
    d.mkdir(parents=True)
    (orphan_env.root / "usr/lib/systemd/system").mkdir(parents=True)
    (d / "gone.service").write_text("[Service]\nExecStart=/usr/bin/nope-gone\n")
    user = orphan_env.home / ".config/systemd/user"
    user.mkdir(parents=True)
    (user / "gone2.service").write_text("[Service]\nExecStart=/usr/bin/nope2\n")
    _check(ss.StaleSystemdUnitReporter(_expired()).scan())


def test_services_unexpired_still_reports(orphan_env):
    d = orphan_env.root / "etc/systemd/system"
    d.mkdir(parents=True)
    (orphan_env.root / "usr/lib/systemd/system").mkdir(parents=True)
    (d / "gone.service").write_text("[Service]\nExecStart=/usr/bin/nope-gone\n")
    rep = ss.StaleSystemdUnitReporter(Config()).scan()
    assert any("gone.service" in i.description for i in rep.items)
    assert not any("incomplete" in i.description for i in rep.items)


def test_desktop_entries_expired_budget_one_note(orphan_env):
    d = orphan_env.home / ".local/share/applications"
    d.mkdir(parents=True)
    (d / "x.desktop").write_text(
        "[Desktop Entry]\nType=Application\nExec=/opt/gone/x\n"
    )
    _check(sl.StaleDesktopEntryReporter(_expired()).scan())


@posix_only
def test_alternatives_expired_budget_one_note(orphan_env):
    d = orphan_env.root / "etc/alternatives"
    d.mkdir(parents=True)
    (d / "editor").symlink_to("/opt/gone/editor")
    _check(sl.BrokenAlternativesReporter(_expired()).scan())


def test_launch_jobs_expired_budget_one_note(orphan_env):
    d = orphan_env.home / "Library" / "LaunchAgents"
    d.mkdir(parents=True)
    with open(d / "com.vendor.gone.plist", "wb") as fh:
        plistlib.dump(
            {"Label": "com.vendor.gone", "ProgramArguments": ["/Applications/G.app/x"]},
            fh,
        )
    _check(olj.OrphanLaunchJobReporter(_expired()).scan())


def test_app_data_inventory_timeout_says_time_limit(orphan_env):
    apps = orphan_env.root / "Applications"
    for k in range(6):
        app = apps / f"A{k}.app" / "Contents"
        app.mkdir(parents=True)
        with open(app / "Info.plist", "wb") as fh:
            plistlib.dump({"CFBundleIdentifier": f"com.a{k}.app"}, fh)
    rep = oad.OrphanAppDataReporter(_expired()).scan()
    _check(rep)
    assert not any("Full Disk Access" in i.hint for i in rep.items)


def test_orphan_files_expired_budget_one_note(orphan_env, monkeypatch):
    make(orphan_env, "/opt/foo", size=10)
    make(orphan_env, "/opt/bar", size=10)
    make(orphan_env, "/usr/local/baz", size=10)
    setup(orphan_env, monkeypatch)
    rep = UnownedSystemFilesReporter(_expired()).scan()
    _check(rep)


def test_receipts_expired_budget_one_note(orphan_env):
    orphan_env.cmds.tools.add("pkgutil")
    orphan_env.cmds.on(("pkgutil", "--pkgs"), out="com.vendor.gone\n")
    rep = sr.StaleReceiptReporter(_expired()).scan()
    _check(rep)
