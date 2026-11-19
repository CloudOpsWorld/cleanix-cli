"""stale_receipts: installer receipts whose installed files are all gone."""

from __future__ import annotations

import plistlib
import sys
from pathlib import Path

import pytest

from cleanix.cleaners import base, orphan_common as oc, stale_receipts as sr
from cleanix.config import Config


def _plist(volume="/", loc="Applications", pkgid="com.vendor.gone") -> str:
    d = {"pkgid": pkgid, "pkg-version": "1.0", "install-time": 1}
    if volume is not None:
        d["volume"] = volume
    if loc is not None:
        d["install-location"] = loc
    return plistlib.dumps(d).decode("utf-8")


def _receipt(env, pkgid, ext="plist") -> Path:
    p = env.root / "private/var/db/receipts" / f"{pkgid}.{ext}"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x")
    return p


def _fake(env, pkgid, files, plist=None, plist_rc=0, files_rc=0, receipt="plist"):
    """Register fake pkgutil answers for one receipt id."""
    env.cmds.tools.add("pkgutil")
    env.cmds.on(
        ("pkgutil", "--pkg-info-plist", pkgid),
        rc=plist_rc,
        out=_plist(pkgid=pkgid) if plist is None else plist,
    )
    env.cmds.on(
        ("pkgutil", "--only-files", "--files", pkgid),
        rc=files_rc,
        out="\n".join(files) + ("\n" if files else ""),
    )
    if receipt:
        _receipt(env, pkgid, receipt)


def _pkgs(env, ids):
    env.cmds.tools.add("pkgutil")
    env.cmds.on(("pkgutil", "--pkgs"), out="\n".join(ids) + "\n")


def _scan(env):
    return sr.StaleReceiptReporter(Config()).scan()


def _stale(report):
    return [i for i in report.items if i.description.startswith("Install record")]


GONE_FILES = ["Gone.app/Contents/MacOS/gone", "Gone.app/Contents/Info.plist"]


def _present(env, logical):
    p = env.root / logical
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x")


def test_attributes():
    c = sr.StaleReceiptReporter
    assert c.id == "stale_receipts"
    assert c.name == "Install records of removed packages"
    assert c.description == (
        "Installer receipts whose installed files are all gone (report only)"
    )
    assert "macos" in str(c.platforms).lower()
    assert c.requires_root is False
    assert c.scope == base.SCOPE_SYSTEM


def test_unavailable_without_pkgutil(orphan_env):
    assert sr.StaleReceiptReporter(Config()).available() == "pkgutil not found"
    assert _scan(orphan_env).skipped_reason == "pkgutil not found"


def test_stale_receipt_reported(orphan_env):
    _pkgs(orphan_env, ["com.vendor.gone"])
    _fake(orphan_env, "com.vendor.gone", GONE_FILES)
    items = _stale(_scan(orphan_env))
    assert len(items) == 1
    it = items[0]
    assert it.description == "Install record for a removed package: com.vendor.gone"
    assert it.report_only is True
    assert it.requires_root is True
    assert it.path.replace("\\", "/").endswith(
        "/private/var/db/receipts/com.vendor.gone.plist"
    )
    assert it.hint == (
        "This package may no longer be installed. After confirming with "
        "`pkgutil --pkg-info com.vendor.gone` and `pkgutil --files "
        "com.vendor.gone`, you can drop only that record: "
        "sudo pkgutil --forget com.vendor.gone"
    )


def test_bom_used_when_plist_absent(orphan_env):
    _pkgs(orphan_env, ["com.vendor.gone"])
    _fake(orphan_env, "com.vendor.gone", GONE_FILES, receipt="bom")
    items = _stale(_scan(orphan_env))
    assert len(items) == 1
    assert items[0].path.replace("\\", "/").endswith("com.vendor.gone.bom")


def test_hint_has_no_bulk_forms(orphan_env):
    _pkgs(orphan_env, ["com.vendor.a+b"])
    _fake(orphan_env, "com.vendor.a+b", GONE_FILES)
    (it,) = _stale(_scan(orphan_env))
    assert "*" not in it.hint and "xargs" not in it.hint


def test_false_positives(orphan_env):
    env = orphan_env
    ids = [
        "com.keep.present",     # one file still present
        "com.apple.pkg.X",      # Apple
        "com.ext.volume",       # other volume
        "com.empty.list",       # empty file list
        "com.rc.one",           # pkg-info-plist rc 1
        "com.bad.plist",        # unparsable plist
        "com.no.receipt",       # no receipt file on disk
        "com.files.rc",         # file list rc != 0
        "com.loc.exists",       # specific install location still exists
        "com.novolume",         # plist without volume
        "com.noloc",            # plist without install-location
        "com.dotdot",           # path traversal in file list
    ]
    _pkgs(env, ids)
    _fake(env, "com.keep.present", GONE_FILES)
    _present(env, "Applications/Gone.app/Contents/Info.plist")
    _fake(env, "com.apple.pkg.X", GONE_FILES)
    _fake(env, "com.ext.volume", GONE_FILES,
          plist=_plist(volume="/Volumes/Ext", pkgid="com.ext.volume"))
    _fake(env, "com.empty.list", [])
    _fake(env, "com.rc.one", GONE_FILES, plist_rc=1)
    _fake(env, "com.bad.plist", GONE_FILES, plist="<<not a plist>>")
    _fake(env, "com.no.receipt", GONE_FILES, receipt=None)
    _fake(env, "com.files.rc", GONE_FILES, files_rc=1)
    _fake(env, "com.loc.exists", GONE_FILES,
          plist=_plist(loc="opt/vendor", pkgid="com.loc.exists"))
    (env.root / "opt/vendor").mkdir(parents=True)
    _fake(env, "com.novolume", GONE_FILES,
          plist=_plist(volume=None, pkgid="com.novolume"))
    _fake(env, "com.noloc", GONE_FILES,
          plist=_plist(loc=None, pkgid="com.noloc"))
    _fake(env, "com.dotdot", ["../../etc/passwd"])
    report = _scan(env)
    assert _stale(report) == []
    assert report.skipped_reason in (None, "")


def test_unsafe_ids_skipped(orphan_env):
    env = orphan_env
    _pkgs(env, ["-evil", "a/b", "com.good.gone"])
    _fake(env, "com.good.gone", GONE_FILES)
    _receipt(env, "-evil")
    assert len(_stale(_scan(env))) == 1
    for argv in env.cmds.calls:
        assert "-evil" not in argv and "a/b" not in argv


BIG = [f"usr/local/vendor/f{i:03d}" for i in range(400)]


def test_sample_is_stratified_and_deterministic():
    files = sorted(BIG)
    a = sr.sample_files("com.big.gone", files)
    assert a == sr.sample_files("com.big.gone", files)
    assert len(a) == 150 and len(set(a)) == 150
    assert a[:25] == files[:25] and a[-25:] == files[-25:]
    assert a != sr.sample_files("com.other.id", files)
    assert sr.sample_files("x", files[:100]) == files[:100]


def test_file_beyond_index_fifty_present_is_not_stale(orphan_env):
    env = orphan_env
    _pkgs(env, ["com.big.gone"])
    _fake(env, "com.big.gone", BIG, plist=_plist(loc="/", pkgid="com.big.gone"))
    files = sorted(BIG)
    sample = sr.sample_files("com.big.gone", files)
    late = next(f for f in sample if files.index(f) > 60)
    assert files.index(late) > 50
    _present(env, late)
    assert _stale(_scan(env)) == []


def test_big_receipt_all_missing_is_stale(orphan_env):
    env = orphan_env
    _pkgs(env, ["com.big.gone"])
    # unsorted pkgutil output must not matter
    _fake(env, "com.big.gone", list(reversed(BIG)),
          plist=_plist(loc="/", pkgid="com.big.gone"))
    assert len(_stale(_scan(env))) == 1


def test_shared_root_with_file_present_not_stale(orphan_env):
    env = orphan_env
    _pkgs(env, ["com.tool.x"])
    _fake(env, "com.tool.x", ["usr/local/bin/tool"],
          plist=_plist(loc="/", pkgid="com.tool.x"))
    _present(env, "usr/local/bin/tool")
    assert _stale(_scan(env)) == []


def test_shared_root_all_missing_is_stale(orphan_env):
    env = orphan_env
    _pkgs(env, ["com.tool.x"])
    _fake(env, "com.tool.x", ["usr/local/bin/tool"],
          plist=_plist(loc="/", pkgid="com.tool.x"))
    assert len(_stale(_scan(env))) == 1


def test_staging_and_unstable_locations_not_reported(orphan_env):
    env = orphan_env
    locs = {
        "com.s.tmp": "/tmp/stage",
        "com.s.ptmp": "private/tmp/x",
        "com.s.folders": "private/var/folders/ab/cd",
        "com.s.vfolders": "/var/folders/ab",
        "com.s.missing": "opt/vendor/missing",
    }
    _pkgs(env, list(locs))
    for pid, loc in locs.items():
        _fake(env, pid, GONE_FILES, plist=_plist(loc=loc, pkgid=pid))
    assert _stale(_scan(env)) == []


def test_renamed_or_moved_app_not_stale(orphan_env):
    env = orphan_env
    ids = ["com.m.utilities", "com.m.user", "com.m.library", "com.m.system",
           "com.m.gone"]
    _pkgs(env, ids)
    for pid, app in zip(ids, ["A", "B", "C", "D", "E"]):
        _fake(env, pid, [f"{app}.app/Contents/MacOS/x", f"{app}.app/Contents/Info.plist"])
    _present(env, "Applications/Utilities/A.app/Contents/Info.plist")
    _present(env, "Users/bob/Applications/B.app/Contents/Info.plist")
    _present(env, "Library/C.app/Contents/Info.plist")
    _present(env, "System/Applications/D.app/Contents/Info.plist")
    items = _stale(_scan(env))
    assert [i.description.rsplit(" ", 1)[1] for i in items] == ["com.m.gone"]


def test_bundle_in_install_location_not_stale(orphan_env):
    env = orphan_env
    _pkgs(env, ["com.vendor.gone"])
    _fake(env, "com.vendor.gone", GONE_FILES)
    (env.root / "Applications/Gone.app").mkdir(parents=True)
    assert _stale(_scan(env)) == []


def test_non_ascii_id_skipped(orphan_env):
    env = orphan_env
    _pkgs(env, ["com.vendor.göne"])
    _fake(env, "com.vendor.göne", GONE_FILES)
    report = _scan(env)
    assert _stale(report) == []
    assert not [c for c in env.cmds.calls if c[1] == "--pkg-info-plist"]


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX symlinks")
def test_symlinked_receipt_skipped(orphan_env):
    env = orphan_env
    _pkgs(env, ["com.vendor.gone"])
    _fake(env, "com.vendor.gone", GONE_FILES, receipt=None)
    rdir = env.root / "private/var/db/receipts"
    rdir.mkdir(parents=True)
    (rdir / "real.dat").write_text("x")
    (rdir / "com.vendor.gone.plist").symlink_to("real.dat")  # relative target
    assert _stale(_scan(env)) == []


def test_unknown_existence_is_not_stale(orphan_env, monkeypatch):
    env = orphan_env
    _pkgs(env, ["com.vendor.gone"])
    _fake(env, "com.vendor.gone", GONE_FILES)
    monkeypatch.setattr(sr, "_exists", lambda p: None)
    assert _stale(_scan(env)) == []


def test_only_allowlisted_commands_called(orphan_env):
    env = orphan_env
    _pkgs(env, ["com.vendor.gone", "com.apple.x"])
    _fake(env, "com.vendor.gone", GONE_FILES)
    _scan(env)
    assert env.cmds.calls
    for argv in env.cmds.calls:
        assert tuple(argv[:2]) in oc.READ_ONLY_COMMANDS, argv
    assert all(argv[0] == "pkgutil" for argv in env.cmds.calls)
    assert not any("--forget" in a for argv in env.cmds.calls for a in argv)
    assert not any("com.apple.x" in argv for argv in env.cmds.calls)


def test_budget_limits_pkgutil_calls(orphan_env):
    env = orphan_env
    ids = [f"com.vendor.p{i:03d}" for i in range(30)]
    _pkgs(env, ids)
    for i in ids:
        _fake(env, i, GONE_FILES)
    cfg = Config()
    cfg.orphan_max_items = 5
    report = sr.StaleReceiptReporter(cfg).scan()
    # Receipts cost no budget slot; only the 5 findings do. The 6th finding
    # is generated (6 receipts examined) and then refused, giving one note.
    info = [c for c in env.cmds.calls if c[1] == "--pkg-info-plist"]
    files = [c for c in env.cmds.calls if c[1] == "--only-files"]
    assert len(info) == 6 and len(files) == 6
    notes = [i for i in report.items if "stopped early" in i.description]
    assert len(notes) == 1
    assert len(_stale(report)) == 5
    assert [i.description.rsplit(" ", 1)[1] for i in _stale(report)] == ids[:5]


def test_non_findings_do_not_consume_budget(orphan_env):
    env = orphan_env
    ids = [f"com.vendor.k{i:03d}" for i in range(40)]
    _pkgs(env, ids)
    for i in ids:
        _fake(env, i, GONE_FILES)
        _present(env, "Applications/Gone.app/Contents/Info.plist")
    cfg = Config()
    cfg.orphan_max_items = 3
    report = sr.StaleReceiptReporter(cfg).scan()
    assert len([c for c in env.cmds.calls if c[1] == "--pkg-info-plist"]) == 40
    assert not [i for i in report.items if "stopped early" in i.description]


def test_time_budget_stops_scan_with_one_note(orphan_env):
    env = orphan_env
    ids = [f"com.vendor.t{i:03d}" for i in range(10)]
    _pkgs(env, ids)
    for i in ids:
        _fake(env, i, GONE_FILES)
    ticks = iter(range(0, 1000))
    rep = sr.StaleReceiptReporter(Config())
    rep.budget = oc.ScanBudget(200, 3.5, clock=lambda: float(next(ticks)))
    rep._reset = lambda: None  # keep the injected budget
    report = rep.scan()
    notes = [i for i in report.items if "stopped early" in i.description]
    assert len(notes) == 1 and "time limit" in notes[0].description
    assert len([c for c in env.cmds.calls if c[1] == "--pkg-info-plist"]) < 10


def test_call_timeout_never_exceeds_budget(orphan_env, monkeypatch):
    env = orphan_env
    _pkgs(env, ["com.vendor.gone"])
    _fake(env, "com.vendor.gone", GONE_FILES)
    seen = []
    real = oc.run

    def spy(argv, timeout=60):
        seen.append(timeout)
        return real(argv, timeout)

    monkeypatch.setattr(oc, "run", spy)
    cfg = Config()
    cfg.orphan_max_seconds = 5.0
    sr.StaleReceiptReporter(cfg).scan()
    assert seen and all(1 <= t <= 5 for t in seen)


def test_pkgs_failure_emits_note(orphan_env):
    env = orphan_env
    env.cmds.tools.add("pkgutil")
    env.cmds.on(("pkgutil", "--pkgs"), rc=1)
    report = _scan(env)
    assert _stale(report) == []
    assert [i.description for i in report.items] == [
        "Not checked: could not list installer receipts"
    ]
    assert all(i.size == 0 for i in report.items)


def test_unchecked_receipts_aggregated_in_one_note(orphan_env):
    env = orphan_env
    ids = ["com.r.a", "com.r.b", "com.r.c", "com.r.ok"]
    _pkgs(env, ids)
    _fake(env, "com.r.a", GONE_FILES, plist_rc=1)
    _fake(env, "com.r.b", GONE_FILES, plist="<<bad>>")
    _fake(env, "com.r.c", GONE_FILES, files_rc=2)
    _fake(env, "com.r.ok", GONE_FILES)
    report = _scan(env)
    notes = [i for i in report.items if "could not be checked" in i.description]
    assert [n.description for n in notes] == ["3 receipts could not be checked"]
    assert len(_stale(report)) == 1
