"""stale_receipts: installer receipts whose installed files are all gone."""

from __future__ import annotations

import plistlib
from pathlib import Path

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
        "See what it installed: pkgutil --files com.vendor.gone. "
        "To drop only the record: sudo pkgutil --forget com.vendor.gone."
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


def test_only_first_fifty_files_sampled(orphan_env):
    env = orphan_env
    _pkgs(env, ["com.big.gone"])
    files = [f"Big.app/f{i}" for i in range(80)]
    _fake(env, "com.big.gone", files)
    _present(env, "Applications/Big.app/f10")  # inside the sample
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
    info = [c for c in env.cmds.calls if c[1] == "--pkg-info-plist"]
    assert len(info) <= 5
    notes = [i for i in report.items if "stopped early" in i.description]
    assert len(notes) == 1
    assert len(_stale(report)) <= 5


def test_pkgs_failure_yields_nothing(orphan_env):
    env = orphan_env
    env.cmds.tools.add("pkgutil")
    env.cmds.on(("pkgutil", "--pkgs"), rc=1)
    assert _stale(_scan(env)) == []
