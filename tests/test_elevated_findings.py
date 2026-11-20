"""The elevated helper's findings action (Task 8): system-wide report-only
findings, re-scanned and acted on as root.

Hermetic: no real elevation (every launcher is a stub), no real root, no
real /var/lib or /Library. Parsing, allowlist and lexical tests run on every
OS; tests that run the helper end to end (they move/delete files under
tmp_path) are POSIX-only.
"""

from __future__ import annotations

import json
import os
import stat
import uuid
from pathlib import Path

import pytest

from cleanix import elevated
from cleanix.cleaners import orphan_common as oc
from cleanix.config import Config
from cleanix.core import (
    actions,
    context,
    elevate,
    elevate_launch,
    engine,
    history,
    quarantine,
    reverify,
    safety,
    scanmode,
    service,
    winenv,
)
from cleanix.core import platform as plat
from cleanix.core.models import CleanableItem, CleanerReport, ItemKind, item_key
from cleanix.core.remedy import Remedy, RemedyKind, fingerprint_of

POSIX = os.name != "nt"
UID = os.getuid() if POSIX else 1000
posix_only = pytest.mark.skipif(not POSIX, reason="the findings action is POSIX only")
REAL_FINDINGS_SUPPORTED = elevated._findings_supported
LINUX_ROOTS = {"orphan_files": ("/var/lib", "/opt", "/usr/local", "/var/cache")}


# --------------------------------------------------------------------------
# fixtures / helpers
# --------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _never_elevate(monkeypatch):
    def never(*a, **k):
        pytest.fail("a real elevation was attempted")

    monkeypatch.setattr(elevate_launch, "launch_elevated", never)
    monkeypatch.setattr(winenv, "run_elevated", never)


@pytest.fixture(autouse=True)
def _restore_environ():
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)
    assert not scanmode.is_helper_mode()


@pytest.fixture
def lexical(monkeypatch):
    """Pure-validation setup: Linux-like roots, the Linux quarantine
    location, a root process, POSIX support (works on every OS)."""
    monkeypatch.setattr(elevated, "_findings_supported", lambda: True)
    monkeypatch.setattr(elevated, "_is_elevated", lambda: True)
    monkeypatch.setattr(elevated, "admin_finding_ids", lambda: frozenset({"orphan_files"}))
    monkeypatch.setattr(elevated, "finding_path_roots", lambda: dict(LINUX_ROOTS))
    monkeypatch.setattr(elevated, "_root_quarantine_location",
                        lambda: ("/var/lib", ("cleanix", "quarantine")))


def payload(items=None, *, only=("orphan_files",), permanent=False, **top):
    if items is None:
        items = [{"key": "orphan_files|path|/var/lib/gone", "fingerprint": [1, 2, 3, 4],
                  "kind": "path"}]
    obj = {"version": elevate.FORMAT_VERSION, "invoking_user": "alice", "only": [],
           "keys": [], "use_quarantine": False, "nonce": uuid.uuid4().hex,
           "findings": {"only": list(only), "items": items, "permanent": permanent}}
    obj.update(top)
    return obj


def parse(obj) -> elevate.Selection:
    return elevate.parse_request(json.dumps(obj).encode("utf-8"))


def rejected(path: str) -> bool:
    """True when a request naming ``path`` is refused, by the strict parser
    or by the helper's lexical validation (both before any filesystem
    access)."""
    obj = payload([{"key": "orphan_files|path|" + path, "fingerprint": [1, 2, 3, 4],
                    "kind": "path"}])
    try:
        sel = parse(obj)
    except ValueError:
        return True
    try:
        elevated._prepare_findings(sel.findings)
    except elevated.Refused:
        return True
    return False


class FakeCleaner:
    def __init__(self, cid, items):
        self.id = cid
        self.name = cid
        self._items = items

    def scan(self):
        items = self._items() if callable(self._items) else self._items
        return CleanerReport(cleaner_id=self.id, name=self.name, description="d",
                             items=list(items))


def finding(path, *, cid="orphan_files", requires_root=True, group=None,
            kind=RemedyKind.PATH):
    fp = fingerprint_of(str(path))
    return CleanableItem(cleaner_id=cid, description=f"Not from any package: {path}",
                         size=0, kind=ItemKind.PATH, path=str(path),
                         requires_root=requires_root, report_only=True, hint="h",
                         remedy=Remedy(kind, fp, group=group))


def tree(root):
    return sorted(str(p.relative_to(root)) for p in Path(root).rglob("*"))


@pytest.fixture
def fx(tmp_path, monkeypatch):
    """Helper environment: alice's home, a fake system root standing in for
    /var/lib (the only allowed root of orphan_files), a fake parent for the
    root quarantine, and a cleaner list the helper's scan uses."""
    if not POSIX:
        pytest.skip("the findings action is POSIX only")
    home = tmp_path / "home" / "alice"
    (home / "Documents").mkdir(parents=True)
    (home / "Documents" / "keep.txt").write_text("mine")
    sysroot = tmp_path / "sys" / "varlib"
    sysroot.mkdir(parents=True)
    qparent = tmp_path / "sys" / "state"
    qparent.mkdir()
    user = context.TargetUser("alice", home, UID, UID, True)

    def fake_invoking_user():
        return user

    fake_invoking_user.cache_clear = lambda: None  # type: ignore[attr-defined]
    monkeypatch.setattr(context, "invoking_user", fake_invoking_user)
    monkeypatch.setattr(history, "invoking_user", fake_invoking_user)
    monkeypatch.setattr(quarantine, "invoking_user", fake_invoking_user)
    user_qroot = home / ".local" / "state" / "cleanix" / "quarantine"
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: user_qroot)
    monkeypatch.setattr(elevated, "_user_for_uid", lambda uid: "alice" if uid == UID else None)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("PKEXEC_UID", raising=False)

    monkeypatch.setattr(elevated, "_findings_supported", lambda: True)
    monkeypatch.setattr(elevated, "_is_elevated", lambda: True)
    monkeypatch.setattr(elevated, "admin_finding_ids", lambda: frozenset({"orphan_files"}))
    monkeypatch.setattr(elevated, "finding_path_roots",
                        lambda: {"orphan_files": (str(sysroot),)})
    monkeypatch.setattr(elevated, "_root_quarantine_location",
                        lambda: (str(qparent), ("cleanix", "quarantine")))
    monkeypatch.setattr(elevated, "_ROOT_UID", UID)
    monkeypatch.setattr(engine, "is_root", lambda: True)
    monkeypatch.setattr(elevated, "_trusted_owner", lambda st, uid: True)
    monkeypatch.setattr(elevated, "_untrusted_group", lambda st, groups: False)
    # The fake scan's items are not real orphan_files findings: their
    # act-time re-check (Task 9a, tested in test_system_remedies) passes.
    reverified = []

    def permissive(item, config):
        reverified.append(item.path)
        return None

    monkeypatch.setitem(reverify.REVERIFIERS, "orphan_files", permissive)
    # ... and no real package-manager query is batched up front for them
    monkeypatch.setitem(reverify.PREFETCH, "orphan_files", lambda paths, config: None)

    def no_history(*a, **k):
        pytest.fail("the helper recorded history")

    monkeypatch.setattr(history, "record", no_history)
    monkeypatch.setattr(history, "write_manifest", no_history)

    cleaners = []
    scans = []

    def fake_build(config, only=None, exclude=None):
        scans.append(list(only or []))
        wanted = set(only) if only else None
        return [c for c in cleaners if wanted is None or c.id in wanted]

    monkeypatch.setattr(service, "build_cleaners", fake_build)
    reqdir = tmp_path / "req"
    reqdir.mkdir()
    os.chmod(reqdir, 0o700)

    class NS:
        pass

    ns = NS()
    ns.tmp, ns.home, ns.sys, ns.qparent = tmp_path, home, sysroot, qparent
    ns.qbase = qparent / "cleanix" / "quarantine"
    ns.user_qroot = user_qroot
    ns.cleaners, ns.scans, ns.reqdir = cleaners, scans, reqdir
    ns.result = reqdir / elevate.RESULT_NAME
    ns.reverified = reverified
    yield ns
    context.configure(None)
    safety.set_protected_globs([])


def make(fx, name, data="x" * 10):
    p = fx.sys / name
    p.write_text(data)
    return p


def request(items, *, permanent=False, fingerprints=None, kinds=None):
    req = elevate.findings_request_for(items, permanent=permanent)
    sels = []
    for i, s in enumerate(req.items):
        fp = (fingerprints or {}).get(i, s.fingerprint)
        kind = (kinds or {}).get(i, s.kind)
        sels.append(elevate.FindingSelection(key=s.key, fingerprint=fp, kind=kind))
    req.items = sels
    return elevate.Selection(invoking_user="alice", only=[], keys=[], use_quarantine=False,
                             findings=req)


def run_helper(fx, sel):
    req = elevate.write_request(fx.reqdir, sel)
    rc = elevated.run(req, fx.result, None, expected_uid=UID)
    return rc, elevate.read_result(fx.result)


def statuses(result):
    return {o.key: o.status for o in result.findings}


# --------------------------------------------------------------------------
# allowlists
# --------------------------------------------------------------------------
@pytest.mark.parametrize("osname", [plat.LINUX, plat.MACOS, plat.WINDOWS])
def test_allowlists_are_separate(monkeypatch, osname):
    monkeypatch.setattr(plat, "current_os", lambda: osname)
    findings_ids = elevate.admin_finding_ids()
    file_ids = elevated.admin_cleaner_ids()
    reg_ids = elevated.admin_registry_cleaner_ids()
    assert not findings_ids & file_ids
    assert not findings_ids & reg_ids
    assert not file_ids & reg_ids
    # admin_cleaner_ids is unchanged: no report-only scenario ever entered it.
    assert not file_ids & elevate.SYSTEM_FINDING_IDS
    expected = {
        plat.LINUX: {"orphan_files", "stale_launchers", "stale_services"},
        plat.MACOS: {"orphan_app_data", "orphan_launch_jobs", "stale_receipts"},
        plat.WINDOWS: set(),
    }[osname]
    assert set(findings_ids) == expected
    assert elevated.admin_finding_ids() == findings_ids


def test_finding_roots_come_from_the_detectors():
    from cleanix.cleaners import (
        orphan_app_data,
        orphan_files,
        orphan_launch_jobs,
        stale_launchers,
        stale_receipts,
        stale_services,
    )

    roots = elevate.finding_path_roots()
    assert set(roots) == set(elevate.SYSTEM_FINDING_IDS)
    assert roots["orphan_files"] == orphan_files._ROOTS
    assert roots["stale_services"] == stale_services._SYSTEM_SCAN
    assert set(roots["stale_launchers"]) == {stale_launchers._LOCAL_DIR,
                                            *stale_launchers._OWNED_DIRS}
    assert roots["orphan_app_data"] == orphan_app_data.SYSTEM_DIRS
    assert roots["orphan_launch_jobs"] == orphan_launch_jobs.SYSTEM_DIRS
    assert roots["stale_receipts"] == (stale_receipts.RECEIPTS_DIR,)
    for rs in roots.values():
        for r in rs:
            assert elevate.posix_path_problem(r) is None


def test_finding_kinds_match_remedy_kinds():
    assert elevate.FINDING_KINDS == {k.value for k in RemedyKind}
    assert elevated._HELPER_FINDING_KINDS == {"path"}


def test_findings_request_rejects_unknown_scenario(lexical):
    good = parse(payload())
    elevated._prepare_findings(good.findings)  # the allowlisted one passes
    for cid in ("big_files", "logs", "win_reg_startup", "stale_alternatives", "temp"):
        sel = parse(payload(
            [{"key": f"{cid}|path|/var/lib/gone", "fingerprint": [1, 2, 3, 4],
              "kind": "path"}], only=(cid,)))
        with pytest.raises(elevated.Refused, match="scenario"):
            elevated._prepare_findings(sel.findings)
    # One unknown scenario among good ones refuses the whole request.
    sel = parse(payload(only=("orphan_files", "big_files")))
    with pytest.raises(elevated.Refused):
        elevated._prepare_findings(sel.findings)


@posix_only
def test_unknown_scenario_refused_before_scan_or_user_binding(fx, monkeypatch):
    victim = make(fx, "victim")
    fx.cleaners.append(FakeCleaner("big_files", lambda: [finding(victim, cid="big_files")]))

    def forbidden(*a, **k):
        pytest.fail("a refused request reached the user binding / config")

    monkeypatch.setattr(elevated, "_bind_user", forbidden)
    monkeypatch.setattr(elevated, "_load_config", forbidden)
    sel = request([finding(victim, cid="big_files")])
    rc, result = run_helper(fx, sel)
    assert rc == elevated.EXIT_REFUSED
    assert victim.exists() and fx.scans == []
    assert any("scenario" in e for e in result.errors)


# --------------------------------------------------------------------------
# strict parsing
# --------------------------------------------------------------------------
GOOD_ITEM = {"key": "orphan_files|path|/var/lib/gone", "fingerprint": [1, 2, 3, 4],
             "kind": "path"}


def _mut(fn):
    obj = payload([dict(GOOD_ITEM)])
    fn(obj)
    return obj


@pytest.mark.parametrize("mutate", [
    lambda o: o["findings"].update(extra=1),
    lambda o: o["findings"].pop("permanent"),
    lambda o: o["findings"].update(permanent="yes"),
    lambda o: o["findings"].update(permanent=1),
    lambda o: o["findings"].update(only="orphan_files"),
    lambda o: o["findings"].update(only=[]),
    lambda o: o["findings"].update(only=["orphan_files", "orphan_files"]),
    lambda o: o["findings"].update(only=[f"s{i}" for i in range(17)]),
    lambda o: o["findings"].update(only=["bad id!"]),
    lambda o: o["findings"].update(items=[]),
    lambda o: o["findings"].update(items={"a": 1}),
    lambda o: o["findings"].update(items=[dict(GOOD_ITEM, key=f"orphan_files|path|/var/lib/g{i}")
                                          for i in range(elevate.MAX_FINDING_ITEMS + 1)]),
    lambda o: o["findings"]["items"][0].update(extra=1),
    lambda o: o["findings"]["items"][0].pop("kind"),
    lambda o: o["findings"]["items"][0].update(kind="PATH"),
    lambda o: o["findings"]["items"][0].update(kind="shell"),
    lambda o: o["findings"]["items"][0].update(kind=1),
    lambda o: o["findings"]["items"][0].update(fingerprint=[1, 2, 3]),
    lambda o: o["findings"]["items"][0].update(fingerprint=[1, 2, 3, 4, 5]),
    lambda o: o["findings"]["items"][0].update(fingerprint=[1, 2, 3, "4"]),
    lambda o: o["findings"]["items"][0].update(fingerprint=[1, 2, 3, 4.0]),
    lambda o: o["findings"]["items"][0].update(fingerprint=[1, 2, 3, True]),
    lambda o: o["findings"]["items"][0].update(fingerprint=[1, 2, 3, None]),
    lambda o: o["findings"]["items"][0].update(fingerprint=[0, 0, 0, 0]),
    lambda o: o["findings"]["items"][0].update(fingerprint=[1, 2, 3, 2 ** 64]),
    lambda o: o["findings"]["items"][0].update(fingerprint="1,2,3,4"),
    lambda o: o["findings"]["items"][0].update(key=7),
    lambda o: o["findings"]["items"][0].update(key="orphan_files|cmd|/var/lib/gone"),
    lambda o: o["findings"]["items"][0].update(key="orphan_files|reg|/var/lib/gone"),
    lambda o: o["findings"]["items"][0].update(key="other_id|path|/var/lib/gone"),
    lambda o: o["findings"]["items"][0].update(key="orphan_files|path|"),
    lambda o: o["findings"]["items"].append(dict(GOOD_ITEM)),  # listed twice
    lambda o: o.update(only=["logs"]),  # mixed with ordinary admin items
    lambda o: o.update(keys=["logs|path|/var/log/x"]),
    lambda o: o.update(use_quarantine=True),
    lambda o: o.update(registry={"only": ["win_reg_startup"], "keys": [],
                                 "backup_run": "r1", "quarantine_root": "C:\\q"}),
    lambda o: o.update(findings=[]),
    lambda o: o.update(findings=None),
])
def test_findings_request_strict_parsing(mutate):
    with pytest.raises(ValueError):
        parse(_mut(mutate))


def test_findings_request_roundtrip(tmp_path):
    sel = elevate.Selection(
        invoking_user="alice", only=[], keys=[], use_quarantine=False,
        findings=elevate.FindingsRequest(
            only=["orphan_files"], permanent=True,
            items=[elevate.FindingSelection("orphan_files|path|/var/lib/gone",
                                            (10, -5, 3, 4), "path")]))
    path = elevate.write_request(tmp_path, sel)
    got = elevate.parse_request(path.read_bytes())
    assert got.findings == sel.findings
    assert got.registry is None and got.only == [] and got.keys == []
    # A request without the part parses exactly as before.
    plain = elevate.Selection(invoking_user="alice", only=["logs"], keys=["k"],
                              use_quarantine=False)
    assert elevate.parse_request(elevate.write_request(tmp_path, plain).read_bytes()).findings is None


def test_result_roundtrip_with_findings(tmp_path):
    res = elevate.HelperResult(
        freed=5, removed=1, errors=[], unmatched=1, nonce="n", refused=1,
        findings=[elevate.FindingOutcome("orphan_files|path|/var/lib/a", "removed", 5),
                  elevate.FindingOutcome("orphan_files|path|/var/lib/b", "not_found",
                                         reason="not\nfound")],
        quarantine_run="20261120-000000-1-abcd")
    elevate.write_result(tmp_path / elevate.RESULT_NAME, res)
    got = elevate.read_result(tmp_path / elevate.RESULT_NAME)
    assert got.findings[0] == res.findings[0]
    assert got.findings[1].reason == "not found"  # control characters flattened
    assert got.quarantine_run == res.quarantine_run
    data = json.loads((tmp_path / elevate.RESULT_NAME).read_text())
    for bad in ({"status": "deleted"}, {"freed": -1}, {"freed": True}, {"extra": 1}):
        d = json.loads(json.dumps(data))
        d["findings"][0].update(bad)
        (tmp_path / elevate.RESULT_NAME).write_text(json.dumps(d))
        with pytest.raises(ValueError):
            elevate.read_result(tmp_path / elevate.RESULT_NAME)
    d = json.loads(json.dumps(data))
    d["quarantine_run"] = "../x"
    (tmp_path / elevate.RESULT_NAME).write_text(json.dumps(d))
    with pytest.raises(ValueError):
        elevate.read_result(tmp_path / elevate.RESULT_NAME)


# --------------------------------------------------------------------------
# lexical path validation
# --------------------------------------------------------------------------
HOSTILE = [
    "/var/lib/foo\nbar", "/var/lib/foo\rbar", "/var/lib/foo\tbar", "/var/lib/foo\x00",
    "/var/lib/foo\x7f", "/var/lib/foo\x85", "/var/lib/foo\u2028", "/var/lib/foo\udcff",
    "/var/lib/../etc/passwd", "/var/lib/a/../../etc", "/opt/../var/lib/x",
    "var/lib/foo", "./var/lib/foo", "~/foo", "", "//var/lib/foo", "/var/lib//foo",
    "/var/lib/./foo", "/var/lib/foo/", "/var/lib/foo/.", "/",
    # outside every root of the scenario, or a root / protected folder itself
    "/var/lib", "/opt", "/var", "/usr", "/etc/passwd", "/etc", "/home/alice/x",
    "/root/x", "/tmp/x", "/usr/local/bin", "/usr/local/share", "/var/libx/foo",
    # the helper's own quarantine, inside it, or its folder
    "/var/lib/cleanix", "/var/lib/cleanix/quarantine", "/var/lib/cleanix/quarantine/r/f",
    # oversized
    "/var/lib/" + "a" * 256, "/var/lib/" + "a/" * 600 + "x",
]


@pytest.mark.parametrize("path", HOSTILE)
def test_helper_rejects_hostile_paths(lexical, path):
    assert rejected(path)


@pytest.mark.parametrize("path", ["/var/lib/gone", "/opt/vendor app", "/usr/local/foo",
                                  "/usr/local/bin/tool", "/var/cache/x/y"])
def test_plain_system_paths_pass_lexical_validation(lexical, path):
    assert not rejected(path)


def test_stale_receipts_and_launch_jobs_have_no_path_roots_outside_their_folders(lexical,
                                                                                   monkeypatch):
    monkeypatch.setattr(elevated, "finding_path_roots", elevate.finding_path_roots)
    monkeypatch.setattr(elevated, "admin_finding_ids",
                        lambda: frozenset(elevate.SYSTEM_FINDING_IDS))
    sel = parse(payload([{"key": "stale_receipts|path|/etc/passwd",
                          "fingerprint": [1, 2, 3, 4], "kind": "path"}],
                        only=("stale_receipts",)))
    with pytest.raises(elevated.Refused):
        elevated._prepare_findings(sel.findings)


def test_non_path_kind_refused_for_its_scenario_or_platform(lexical, monkeypatch):
    # a kind its scenario never offers refuses the WHOLE request (lexical)
    sel = parse(payload([dict(GOOD_ITEM, kind="launch_job"),
                         dict(GOOD_ITEM, key="orphan_files|path|/var/lib/b", kind="path")]))
    with pytest.raises(elevated.Refused, match="never offers"):
        elevated._prepare_findings(sel.findings)
    # a kind not handled on this platform is refused per item
    monkeypatch.setattr(elevated, "admin_finding_ids",
                        lambda: frozenset({"orphan_files", "stale_services"}))
    monkeypatch.setattr(elevated, "finding_path_roots", lambda: dict(
        LINUX_ROOTS, stale_services=("/etc/systemd/system",)))
    monkeypatch.setattr(plat, "current_os", lambda: plat.MACOS)
    unit = {"key": "stale_services|path|/etc/systemd/system/gone.service",
            "fingerprint": [1, 2, 3, 4], "kind": "systemd_unit"}
    sel = parse(payload([unit, dict(GOOD_ITEM, key="orphan_files|path|/var/lib/b")],
                        only=("stale_services", "orphan_files")))
    plan = elevated._prepare_findings(sel.findings)
    assert plan.refused == {unit["key"]: elevated.KIND_NOT_SUPPORTED}
    assert plan.only == ["orphan_files"]
    assert "not handled" in elevated.KIND_NOT_SUPPORTED
    monkeypatch.setattr(plat, "current_os", lambda: plat.LINUX)
    assert elevated._prepare_findings(sel.findings).refused == {}


def test_windows_refuses_findings_request(lexical, monkeypatch):
    monkeypatch.setattr(elevated, "_findings_supported", REAL_FINDINGS_SUPPORTED)
    monkeypatch.setattr(elevated, "_is_posix", lambda: False)
    sel = parse(payload())
    with pytest.raises(elevated.Refused, match="not supported on Windows"):
        elevated._prepare_findings(sel.findings)
    monkeypatch.setattr(plat, "current_os", lambda: plat.WINDOWS)
    assert elevate.admin_finding_ids() == frozenset()


def test_not_elevated_is_refused(lexical, monkeypatch):
    monkeypatch.setattr(elevated, "_is_elevated", lambda: False)
    with pytest.raises(elevated.Refused, match="root"):
        elevated._prepare_findings(parse(payload()).findings)


# --------------------------------------------------------------------------
# the ordinary (unprivileged) act path is unchanged
# --------------------------------------------------------------------------
def test_normal_act_still_skips_requires_root_items(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "is_root", lambda: True)  # even a root process
    p = tmp_path / "sysfile"
    p.write_text("data")
    item = finding(p)
    summary = actions.act([item], Config(), dry_run=False, permanent=True,
                          record_history=False)
    assert p.exists()
    assert summary.skipped == [(item, actions.NEEDS_ELEVATION)]
    assert summary.removed == 0


def test_root_mode_handles_plain_paths_only(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "is_root", lambda: True)
    a = tmp_path / "job.plist"
    a.write_text("x")
    b = tmp_path / "dup"
    b.write_text("x")
    c = tmp_path / "user.plist"
    c.write_text("x")
    # Root mode: no duplicates, no user-level jobs; a system-wide job kind
    # only with a backup location (Task 9b) and only from its own scenario.
    items = [finding(a, kind=RemedyKind.LAUNCH_JOB), finding(b, group="g1"),
             finding(c, kind=RemedyKind.LAUNCH_JOB, requires_root=False)]
    summary = actions.act(items, Config(), dry_run=False, permanent=True,
                          record_history=False, allow_root=True)
    assert a.exists() and b.exists() and c.exists()
    assert [r for _i, r in summary.skipped] == [actions.NO_BACKUP_PLACE, actions.NOT_HANDLED,
                                                actions.NOT_HANDLED]
    from cleanix.core import system_remedy

    summary = actions.act(items[:1], Config(), dry_run=False, permanent=True,
                          record_history=False, allow_root=True,
                          backup_root=tmp_path / "backup")
    assert [r for _i, r in summary.skipped] == [system_remedy.WRONG_SCENARIO]
    assert a.exists() and not (tmp_path / "backup").exists()


def test_history_off_with_quarantine_still_refused_without_root_dir(tmp_path):
    p = tmp_path / "f"
    p.write_text("x")
    with pytest.raises(ValueError):
        actions.act([finding(p, requires_root=False)], Config(), dry_run=False,
                    record_history=False)
    with pytest.raises(ValueError):
        service.clean([], Config(), dry_run=False, use_quarantine=True, record_history=False)


def test_helper_mode_skips_user_findings(tmp_path):
    class Rep(oc.OrphanReporter):
        id = "orphan_files"
        name = "x"

        def system_findings(self):
            yield oc.Finding(tmp_path / "sys", "s", "h")

        def user_findings(self):
            yield oc.Finding(tmp_path / "user", "u", "h", requires_root=False)

    (tmp_path / "sys").write_text("x")
    (tmp_path / "user").write_text("x")
    rep = Rep(Config())
    assert sorted(Path(i.path).name for i in rep.find_items()) == ["sys", "user"]
    with scanmode.helper_mode():
        rep = Rep(Config())
        assert [Path(i.path).name for i in rep.find_items()] == ["sys"]


# --------------------------------------------------------------------------
# launcher (non-GUI): one request, one prompt, the matching result
# --------------------------------------------------------------------------
def _fake_launcher(write=True, nonce=None, rc_exc=None, key=None):
    calls = []

    def launch(argv):
        calls.append(list(argv))
        req = Path(argv[argv.index("--request") + 1])
        res = Path(argv[argv.index("--result") + 1])
        sel = elevate.parse_request(req.read_bytes())
        if write:
            elevate.write_result(res, elevate.HelperResult(
                freed=0, removed=0, errors=[], unmatched=1,
                nonce=nonce if nonce is not None else sel.nonce,
                findings=[elevate.FindingOutcome(key or sel.findings.items[0].key,
                                                 "not_found", reason=elevated.NOT_FOUND)]))
        if rc_exc is not None:
            raise rc_exc
        return 0

    launch.calls = calls
    return launch


def _req():
    return elevate.FindingsRequest(
        only=["orphan_files"],
        items=[elevate.FindingSelection("orphan_files|path|/var/lib/gone", (1, 2, 3, 4),
                                        "path")])


def test_run_findings_request_returns_matching_result(lexical):
    launch = _fake_launcher()
    result = elevate_launch.run_findings_request(_req(), "alice", launcher=launch)
    assert len(launch.calls) == 1
    assert result.findings[0].status == "not_found"
    req_dir = Path(launch.calls[0][launch.calls[0].index("--request") + 1]).parent
    assert not req_dir.exists()  # always removed


def test_run_findings_request_refused_exit_still_returns_result(lexical):
    launch = _fake_launcher(rc_exc=elevate_launch.ElevationFailed("x", exit_code=1))
    result = elevate_launch.run_findings_request(_req(), "alice", launcher=launch)
    assert result.unmatched == 1


def test_run_findings_request_rejects_stale_result(lexical):
    with pytest.raises(elevate_launch.ElevationFailed):
        elevate_launch.run_findings_request(_req(), "alice",
                                            launcher=_fake_launcher(nonce="0" * 32))
    with pytest.raises(elevate_launch.ElevationFailed):
        elevate_launch.run_findings_request(_req(), "alice",
                                            launcher=_fake_launcher(write=False))


def test_run_findings_request_never_prompts_for_an_invalid_request(lexical):
    launch = _fake_launcher()
    bad = elevate.FindingsRequest(only=["orphan_files"], items=[
        elevate.FindingSelection("orphan_files|path|/var/lib/../etc", (1, 2, 3, 4), "path")])
    with pytest.raises(ValueError):
        elevate_launch.run_findings_request(bad, "alice", launcher=launch)
    assert launch.calls == []


def test_run_findings_request_rejects_a_result_for_unrequested_items(lexical):
    launch = _fake_launcher(key="orphan_files|path|/var/lib/other")
    with pytest.raises(elevate_launch.ElevationFailed, match="not requested"):
        elevate_launch.run_findings_request(_req(), "alice", launcher=launch)


@pytest.mark.parametrize("bad", [
    elevate.FindingsRequest(only=["big_files"], items=[elevate.FindingSelection(
        "big_files|path|/var/lib/gone", (1, 2, 3, 4), "path")]),
    elevate.FindingsRequest(only=["orphan_files"], items=[elevate.FindingSelection(
        "orphan_files|path|/etc/passwd", (1, 2, 3, 4), "path")]),
    elevate.FindingsRequest(only=["orphan_files"], items=[elevate.FindingSelection(
        "orphan_files|path|/var/lib/cleanix", (1, 2, 3, 4), "path")]),
    # a remedy kind its scenario never offers (Task 9b)
    elevate.FindingsRequest(only=["orphan_files"], items=[elevate.FindingSelection(
        "orphan_files|path|/var/lib/gone", (1, 2, 3, 4), "launch_job")]),
])
def test_run_findings_request_checks_allowlist_and_paths_before_prompting(lexical, bad):
    launch = _fake_launcher()
    with pytest.raises(ValueError):
        elevate_launch.run_findings_request(bad, "alice", launcher=launch)
    assert launch.calls == []


def test_run_findings_request_refused_on_windows(lexical, monkeypatch):
    monkeypatch.setattr(elevated, "_findings_supported", lambda: False)
    launch = _fake_launcher()
    with pytest.raises(ValueError, match="Windows"):
        elevate_launch.run_findings_request(_req(), "alice", launcher=launch)
    assert launch.calls == []


def test_result_key_must_be_a_finding_key(tmp_path):
    res = elevate.HelperResult(freed=0, removed=0, errors=[], unmatched=0, findings=[
        elevate.FindingOutcome("orphan_files|path|/var/lib/../etc", "removed")])
    elevate.write_result(tmp_path / elevate.RESULT_NAME, res)
    with pytest.raises(ValueError):
        elevate.read_result(tmp_path / elevate.RESULT_NAME)
    long_key = "orphan_files|path|/var/lib/" + "a" * 250 + "/" + "b" * 250 + "/" + "c" * 200
    res.findings = [elevate.FindingOutcome(long_key, "removed")]
    elevate.write_result(tmp_path / elevate.RESULT_NAME, res)
    assert elevate.read_result(tmp_path / elevate.RESULT_NAME).findings[0].key == long_key


def test_findings_plan_scans_only_scenarios_left(lexical, monkeypatch):
    monkeypatch.setattr(elevated, "admin_finding_ids",
                        lambda: frozenset({"orphan_files", "stale_services"}))
    monkeypatch.setattr(elevated, "finding_path_roots", lambda: dict(
        LINUX_ROOTS, stale_services=("/etc/systemd/system",)))
    sel = parse(payload([dict(GOOD_ITEM),
                         {"key": "stale_services|path|/etc/systemd/system/x.service",
                          "fingerprint": [1, 2, 3, 4], "kind": "systemd_unit"}],
                        only=("orphan_files", "stale_services")))
    # systemd units are acted on on Linux only (Task 9b)
    monkeypatch.setattr(plat, "current_os", lambda: plat.MACOS)
    plan = elevated._prepare_findings(sel.findings)
    assert plan.only == ["orphan_files"]
    monkeypatch.setattr(plat, "current_os", lambda: plat.LINUX)
    plan = elevated._prepare_findings(sel.findings)
    assert plan.only == ["orphan_files", "stale_services"]


def test_run_findings_request_never_prompts_for_an_oversized_request(lexical):
    launch = _fake_launcher()
    long_dir = "/var/lib/" + "/".join(["d" * 250] * 4)  # 1012 chars, still valid
    big = elevate.FindingsRequest(only=["orphan_files"], items=[
        elevate.FindingSelection(f"orphan_files|path|{long_dir}/{i:04d}", (1, 2, 3, 4), "path")
        for i in range(elevate.MAX_FINDING_ITEMS)])
    with pytest.raises(ValueError, match="too large"):
        elevate_launch.run_findings_request(big, "alice", launcher=launch)
    assert launch.calls == []


# --------------------------------------------------------------------------
# the helper end to end (POSIX)
# --------------------------------------------------------------------------
@posix_only
def test_helper_ignores_item_not_in_own_scan(fx):
    listed = make(fx, "listed")
    claimed = make(fx, "claimed")  # exists, plausible, but NOT in the helper's scan
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(listed)]))
    sel = request([finding(listed), finding(claimed)])
    rc, result = run_helper(fx, sel)
    assert rc == elevated.EXIT_OK
    assert claimed.exists()
    assert not listed.exists()
    st = statuses(result)
    assert st[f"orphan_files|path|{claimed}"] == "not_found"
    assert st[f"orphan_files|path|{listed}"] == "removed"
    assert result.unmatched == 1 and result.removed == 1
    assert fx.scans == [["orphan_files"]]


@posix_only
def test_helper_skips_changed_fingerprint(fx):
    stale = make(fx, "stale")
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(stale)]))
    caller = finding(stale)
    fp = list(caller.remedy.fingerprint)
    fp[1] += 1  # the caller saw another mtime
    rc, result = run_helper(fx, request([caller], fingerprints={0: tuple(fp)}))
    assert rc == elevated.EXIT_OK and stale.exists()
    assert statuses(result)[f"orphan_files|path|{stale}"] == "skipped"
    assert result.removed == 0


@posix_only
def test_helper_skips_file_changed_after_its_own_scan(fx):
    moving = make(fx, "moving")
    original = finding(moving)

    def scan():
        item = finding(moving)
        moving.write_text("rewritten after the scan, longer")  # changed before the act
        return [item]

    fx.cleaners.append(FakeCleaner("orphan_files", scan))
    rc, result = run_helper(fx, request([original]))
    assert rc == elevated.EXIT_OK and moving.exists()
    out = result.findings[0]
    assert out.status == "skipped" and "changed" in out.reason


@posix_only
def test_helper_never_touches_user_home(fx):
    victim = make(fx, "victim")
    userish = make(fx, "userlevel")
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [
        finding(victim), finding(userish, requires_root=False)]))
    before = tree(fx.home)
    rc, result = run_helper(fx, request([finding(victim), finding(userish, requires_root=False)]))
    assert rc == elevated.EXIT_OK
    assert tree(fx.home) == before
    assert not fx.user_qroot.exists()
    assert not victim.exists()  # moved into the ROOT quarantine instead
    assert userish.exists()
    st = statuses(result)
    assert st[f"orphan_files|path|{userish}"] == "refused"
    assert result.quarantine_run
    assert (fx.qbase / result.quarantine_run / "manifest.json").is_file()


@posix_only
def test_helper_refuses_a_request_naming_the_users_home(fx, monkeypatch):
    mine = fx.home / "Documents" / "keep.txt"

    def forbidden(*a, **k):
        pytest.fail("a hostile request reached the user binding / config")

    monkeypatch.setattr(elevated, "_bind_user", forbidden)
    monkeypatch.setattr(elevated, "_load_config", forbidden)
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(mine)]))
    rc, result = run_helper(fx, request([finding(mine)]))
    assert rc == elevated.EXIT_REFUSED
    assert mine.exists() and fx.scans == []


@posix_only
def test_helper_refuses_item_under_a_symlinked_component(fx):
    outside = fx.tmp / "elsewhere"
    outside.mkdir()
    victim = outside / "victim"
    victim.write_text("precious")
    (fx.sys / "link").symlink_to(outside, target_is_directory=True)
    through = fx.sys / "link" / "victim"
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(through)]))
    rc, result = run_helper(fx, request([finding(through)]))
    assert rc == elevated.EXIT_OK
    assert victim.exists()
    out = result.findings[0]
    assert out.status == "skipped" and "symbolic link" in out.reason


@posix_only
def test_non_path_kind_refused_end_to_end(fx):
    job = make(fx, "job.plist")
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(job)]))
    rc, result = run_helper(fx, request([finding(job)], kinds={0: "launch_job"}))
    # orphan_files never offers a launch-job action: the request is refused
    assert rc == elevated.EXIT_REFUSED and job.exists()
    assert result.findings == []
    assert fx.scans == []  # nothing was scanned


@posix_only
def test_helper_refuses_duplicates_and_reportless_items(fx):
    dup = make(fx, "dup")
    plain = make(fx, "plain")
    noremedy = CleanableItem(cleaner_id="orphan_files", description="n", size=0,
                             kind=ItemKind.PATH, path=str(plain), requires_root=True,
                             report_only=True, hint="h")
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(dup, group="g"), noremedy]))
    rc, result = run_helper(fx, request([finding(dup, group="g"), finding(plain)]))
    assert rc == elevated.EXIT_OK and dup.exists() and plain.exists()
    st = statuses(result)
    assert st[f"orphan_files|path|{dup}"] == "refused"
    assert st[f"orphan_files|path|{plain}"] == "refused"


@posix_only
def test_helper_batch_single_quarantine_run_root_owned_dir(fx):
    a = make(fx, "a", "aaaa")
    b = make(fx, "b", "bbbbbbbb")
    d = fx.sys / "dir"
    d.mkdir()
    (d / "inner").write_text("ccc")
    items = lambda: [finding(a), finding(b), finding(d)]  # noqa: E731
    fx.cleaners.append(FakeCleaner("orphan_files", items))
    rc, result = run_helper(fx, request(items()))
    assert rc == elevated.EXIT_OK
    assert not a.exists() and not b.exists() and not d.exists()
    assert result.removed == 3
    assert set(statuses(result).values()) == {"removed"}
    runs = os.listdir(fx.qbase)
    assert runs == [result.quarantine_run]  # ONE run for the batch
    for p, private in ((fx.qparent / "cleanix", False), (fx.qbase, True)):
        st = os.lstat(p)
        assert stat.S_ISDIR(st.st_mode) and st.st_uid == UID
        assert not st.st_mode & (0o077 if private else 0o022)
    run_dir = fx.qbase / result.quarantine_run
    assert not os.lstat(run_dir).st_mode & 0o077
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert sorted(Path(i["original"]).name for i in manifest["items"]) == ["a", "b", "dir"]


@posix_only
def test_root_quarantine_never_copies_across_filesystems(fx, monkeypatch):
    import errno

    a = make(fx, "a", "payload")
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(a)]))

    def cross(src, dst):
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    monkeypatch.setattr(quarantine, "_rename", cross)

    def no_copy(*a, **k):
        pytest.fail("the root quarantine fell back to copying")

    monkeypatch.setattr(quarantine.shutil, "move", no_copy)
    monkeypatch.setattr(quarantine.shutil, "copy2", no_copy)
    monkeypatch.setattr(quarantine.shutil, "copytree", no_copy)
    rc, result = run_helper(fx, request([finding(a)]))
    assert rc == elevated.EXIT_OK
    assert a.read_text() == "payload"
    out = result.findings[0]
    assert out.status == "not_removed" and "another filesystem" in out.reason
    assert result.removed == 0 and result.quarantine_run == ""
    for run in os.listdir(fx.qbase):
        assert tree(fx.qbase / run) in ([], ["files"])


@posix_only
def test_permanent_flag_no_quarantine(fx):
    a = make(fx, "a")
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(a)]))
    rc, result = run_helper(fx, request([finding(a)], permanent=True))
    assert rc == elevated.EXIT_OK and not a.exists()
    assert result.removed == 1 and result.quarantine_run == ""
    assert not (fx.qparent / "cleanix").exists()


@posix_only
@pytest.mark.parametrize("case", ["group_writable", "symlink", "not_root", "outer_writable",
                                  "outer_symlink", "file"])
def test_unowned_root_quarantine_dir_refused(fx, monkeypatch, case):
    a = make(fx, "a")
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(a)]))
    outer = fx.qparent / "cleanix"
    if case == "outer_symlink":
        real = fx.tmp / "realouter"
        (real / "quarantine").mkdir(parents=True, mode=0o700)
        outer.symlink_to(real, target_is_directory=True)
    else:
        outer.mkdir(mode=0o755)
    if case == "group_writable":
        fx.qbase.mkdir()
        os.chmod(fx.qbase, 0o770)
    elif case == "symlink":
        real = fx.tmp / "realq"
        real.mkdir(mode=0o700)
        fx.qbase.symlink_to(real, target_is_directory=True)
    elif case == "not_root":
        fx.qbase.mkdir(mode=0o700)
        monkeypatch.setattr(elevated, "_ROOT_UID", UID + 1)
    elif case == "outer_writable":
        os.chmod(outer, 0o777)
    elif case == "file":
        fx.qbase.write_text("not a dir")
    rc, result = run_helper(fx, request([finding(a)]))
    assert rc == elevated.EXIT_OK
    assert a.exists()  # fail closed: nothing removed
    out = result.findings[0]
    assert out.status == "not_removed" and "quarantine is not usable" in out.reason
    assert result.removed == 0 and result.quarantine_run == ""


# --------------------------------------------------------------------------
# fix round 1: watchdog mid-batch, mounts and honest root removal,
# real parent-chain ownership and the per-item re-check
# --------------------------------------------------------------------------
REAL_TRUSTED_OWNER = elevated._trusted_owner


class Killed(BaseException):
    """Stands in for os._exit in the watchdog (the process ends)."""


@posix_only
def test_watchdog_mid_batch_result_is_honest_and_manifest_records_moves(fx, monkeypatch):
    a = make(fx, "a", "aaaa")
    b = make(fx, "b", "bbbb")
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(a), finding(b)]))
    sessions = []
    real_init = elevated._Session.__init__

    def init(self, rdir):
        real_init(self, rdir)
        sessions.append(self)

    monkeypatch.setattr(elevated._Session, "__init__", init)

    def hard_exit(code):
        raise Killed(code)

    monkeypatch.setattr(elevated.os, "_exit", hard_exit)
    real_rename = quarantine._rename
    calls = []

    def rename(src, dst):
        calls.append(src)
        if len(calls) == 2:  # the watchdog fires while item 2 is being moved
            sessions[0].abort_after_deadline()
        real_rename(src, dst)

    monkeypatch.setattr(quarantine, "_rename", rename)
    req = elevate.write_request(fx.reqdir, request([finding(a), finding(b)]))
    with pytest.raises(Killed):
        elevated.run(req, fx.result, None, expected_uid=UID)
    result = elevate.read_result(fx.result)
    assert result.deadline_hit
    assert not a.exists() and b.exists()
    st = {o.key: o for o in result.findings}
    assert st[f"orphan_files|path|{a}"].status == "removed"
    assert st[f"orphan_files|path|{b}"].status == "not_removed"
    assert st[f"orphan_files|path|{b}"].reason == elevated.STOPPED_WHILE_ACTING
    assert result.removed == 1 and result.freed > 0
    assert result.quarantine_run
    manifest = json.loads((fx.qbase / result.quarantine_run / "manifest.json").read_text())
    # b was recorded before its move and the kill (an asynchronous
    # exception) arrived before the rename: its entry stays (Task 9a carry-over
    # (a): only an OSError from the rename drops it), as a real os._exit
    # would leave it -- a phantom entry: stored file missing, original intact.
    assert [i["original"] for i in manifest["items"]] == [str(a), str(b)]
    assert Path(manifest["items"][0]["stored"]).read_text() == "aaaa"
    assert not Path(manifest["items"][1]["stored"]).exists() and b.exists()


@posix_only
def test_root_quarantine_records_origin_before_moving(fx, monkeypatch):
    a = make(fx, "a")
    seen = []
    real_rename = quarantine._rename

    def rename(src, dst):
        # Already recorded on disk when the move happens.
        mf = Path(dst).parent.parent / "manifest.json"
        seen.append([i["original"] for i in json.loads(mf.read_text())["items"]])
        real_rename(src, dst)

    monkeypatch.setattr(quarantine, "_rename", rename)
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(a)]))
    rc, result = run_helper(fx, request([finding(a)]))
    assert rc == elevated.EXIT_OK and result.removed == 1
    assert seen == [[str(a)]]


def test_mountinfo_parsing_unescapes_mount_points():
    from cleanix.core import root_delete

    text = ("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
            "36 35 98:0 /mnt1 /mnt/with\\040space rw,noatime master:1 - ext3 /dev/root rw\n"
            "37 35 98:0 / /var/lib/kubelet/pods/x/volumes rw - tmpfs tmpfs rw\n"
            "38 35 98:0 / /odd\\134name\\011tab rw - tmpfs tmpfs rw\n")
    assert root_delete.parse_mountinfo(text) == [
        "/", "/mnt/with space", "/var/lib/kubelet/pods/x/volumes", "/odd\\name\ttab"]
    assert root_delete.parse_mountinfo("garbage\n") is None


@pytest.fixture
def mounts(monkeypatch):
    from cleanix.core import root_delete

    table = {"text": ""}
    monkeypatch.setattr(root_delete, "_linux", lambda: True)
    monkeypatch.setattr(root_delete, "_read_mountinfo", lambda: table["text"])
    return table


ROOT_MOUNT = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"


def _mount_line(path):
    """A mount table with the root entry plus one mount at ``path``."""
    return ROOT_MOUNT + ("40 35 98:0 / " + str(path).replace(" ", "\\040")
                         + " rw - tmpfs tmpfs rw\n")


@posix_only
def test_item_with_a_mount_below_is_refused(tmp_path, mounts):
    from cleanix.core import root_delete

    d = tmp_path / "pod"
    (d / "vol").mkdir(parents=True)
    mounts["text"] = _mount_line(d / "vol")
    for permanent in (True, False):
        assert root_delete.mount_problem(str(d), permanent=permanent) == \
            "a filesystem is mounted inside it"
    mounts["text"] = _mount_line(d)
    assert root_delete.mount_problem(str(d), permanent=True) == "it is a mount point"
    mounts["text"] = _mount_line(tmp_path / "podx")  # a sibling with the same prefix
    assert root_delete.mount_problem(str(d), permanent=True) is None
    mounts["text"] = None
    assert root_delete.mount_problem(str(d), permanent=True) == \
        "the mount table could not be read"


def test_without_a_mount_table_permanent_folders_are_refused(tmp_path, monkeypatch):
    from cleanix.core import root_delete

    monkeypatch.setattr(root_delete, "_linux", lambda: False)
    d = tmp_path / "dir"
    d.mkdir()
    f = tmp_path / "file"
    f.write_text("x")
    assert "quarantine instead" in root_delete.mount_problem(str(d), permanent=True)
    assert root_delete.mount_problem(str(d), permanent=False) is None
    assert root_delete.mount_problem(str(f), permanent=True) is None


@posix_only
def test_helper_skips_an_item_with_a_mount_below(fx, mounts):
    d = fx.sys / "pod"
    (d / "vol").mkdir(parents=True)
    (d / "vol" / "data").write_text("other filesystem")
    mounts["text"] = _mount_line(d / "vol")
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(d)]))
    for permanent in (True, False):
        rc, result = run_helper(fx, request([finding(d)], permanent=permanent))
        assert rc == elevated.EXIT_OK and (d / "vol" / "data").exists()
        out = result.findings[0]
        assert out.status == "skipped" and "mounted inside it" in out.reason


@posix_only
def test_root_permanent_partial_failure_is_reported_honestly(fx, monkeypatch):
    d = fx.sys / "tree"
    (d / "sub").mkdir(parents=True)
    (d / "gone.bin").write_bytes(b"g" * 100)
    (d / "sub" / "locked").write_bytes(b"l" * 10)
    real_unlink = os.unlink

    def unlink(p, *a, **k):
        if os.fsdecode(p).endswith("locked"):
            raise PermissionError(13, "Permission denied")
        return real_unlink(p, *a, **k)

    monkeypatch.setattr(os, "unlink", unlink)
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(d)]))
    rc, result = run_helper(fx, request([finding(d)], permanent=True))
    assert rc == elevated.EXIT_OK
    out = result.findings[0]
    assert out.status == "not_removed" and out.reason.startswith("partially removed:")
    assert (d / "sub" / "locked").exists() and not (d / "gone.bin").exists()
    assert result.removed == 0
    assert out.freed >= 100 and result.freed == out.freed


@posix_only
def test_root_permanent_refused_without_symlink_safe_rmtree(tmp_path, monkeypatch):
    import shutil

    from cleanix.core import root_delete

    d = tmp_path / "t"
    d.mkdir()
    (d / "f").write_text("x")
    monkeypatch.setattr(shutil.rmtree, "avoids_symlink_attacks", False, raising=False)
    removed, freed, error = root_delete.remove(str(d))
    assert not removed and freed == 0 and "symbolic-link" in error
    assert (d / "f").exists()


@posix_only
def test_root_remove_refuses_a_tree_on_another_device(tmp_path):
    from cleanix.core import root_delete

    d = tmp_path / "t"
    d.mkdir()
    (d / "f").write_text("x")
    _size, why = root_delete._tree_size_and_devs(str(d), dev=-1)
    assert "another filesystem" in why


def test_normal_act_never_uses_root_removal(tmp_path, monkeypatch):
    from cleanix.core import root_delete

    def forbidden(*a, **k):
        pytest.fail("the normal path used the root-only removal or mount check")

    monkeypatch.setattr(root_delete, "remove", forbidden)
    monkeypatch.setattr(root_delete, "mount_problem", forbidden)
    d = tmp_path / "userdir"
    d.mkdir()
    (d / "f").write_text("x")
    summary = actions.act([finding(d, requires_root=False)], Config(), dry_run=False,
                          permanent=True, record_history=False)
    assert summary.removed == 1 and not d.exists()


@posix_only
def test_real_ownership_rule_refuses_parent_owned_by_the_user(fx, monkeypatch):
    if UID == 0:
        pytest.skip("needs a non-root test user")
    monkeypatch.setattr(elevated, "_trusted_owner", REAL_TRUSTED_OWNER)
    a = make(fx, "a")
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(a)]))
    rc, result = run_helper(fx, request([finding(a)], permanent=True))
    assert rc == elevated.EXIT_OK and a.exists()
    out = result.findings[0]
    assert out.status == "skipped" and "non-system user" in out.reason


@posix_only
def test_parent_swapped_for_a_link_mid_batch_is_caught_before_removal(fx, monkeypatch):
    (fx.sys / "d1").mkdir()
    (fx.sys / "d2").mkdir()
    f1 = fx.sys / "d1" / "f1"
    f1.write_text("one")
    f2 = fx.sys / "d2" / "f2"
    f2.write_text("two")
    elsewhere = fx.tmp / "elsewhere"
    real_rename = quarantine._rename
    calls = []

    def rename(src, dst):
        calls.append(src)
        real_rename(src, dst)
        if len(calls) == 1:  # while item 1 is moved, d2 becomes a link
            os.rename(fx.sys / "d2", elsewhere)
            (fx.sys / "d2").symlink_to(elsewhere, target_is_directory=True)

    monkeypatch.setattr(quarantine, "_rename", rename)
    items = [finding(f1), finding(f2)]
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: items))
    rc, result = run_helper(fx, request(items))
    assert rc == elevated.EXIT_OK
    assert not f1.exists()
    assert (elsewhere / "f2").read_text() == "two"
    st = {o.key: o for o in result.findings}
    assert st[f"orphan_files|path|{f1}"].status == "removed"
    late = st[f"orphan_files|path|{f2}"]
    assert late.status == "skipped" and "symbolic link" in late.reason
    assert calls == [str(f1)]


# --------------------------------------------------------------------------
# Task 9a: real detectors, act-time re-verification, hardening, end to end
# --------------------------------------------------------------------------
def _aged(path, days=100):
    import time as _time

    t = _time.time() - days * 86400
    os.utime(str(path), (t, t), follow_symlinks=False)
    return path


class _FakeDpkg:
    """dpkg behind ``oc.run``: ``owned`` paths are owned, others unowned."""

    def __init__(self):
        self.owned = set()
        self.queries = []

    def __call__(self, argv, timeout=60):
        argv = list(argv)
        if argv[:2] == ["dpkg-query", "-W"]:
            return 0, "bash\ncoreutils\n", ""
        if argv[:2] == ["dpkg-query", "-S"]:
            ps = argv[2:]
            self.queries.append(ps)
            out = [f"somepkg: {p}" for p in ps if p in self.owned]
            err = [f"dpkg-query: no path found matching pattern {p}"
                   for p in ps if p not in self.owned]
            return (1 if err else 0), "\n".join(out), "\n".join(err)
        return 127, "", "not found"


@posix_only
def test_helper_end_to_end_removes_unowned_item_and_refuses_owned_one(fx, monkeypatch):
    """The real orphan_files detector in the helper's scan, the real
    package-ownership re-verifier right before removal: a file a package
    started to own after the helper's own scan is skipped and kept."""
    from cleanix.cleaners.orphan_files import UnownedSystemFilesReporter

    sysroot = fx.tmp / "fsroot"
    varlib = sysroot / "var" / "lib"
    varlib.mkdir(parents=True)
    monkeypatch.setattr(UnownedSystemFilesReporter, "sysroot", str(sysroot))
    monkeypatch.setattr(UnownedSystemFilesReporter, "pkg_backend", lambda self: "dpkg")
    monkeypatch.setattr(elevated, "finding_path_roots", lambda: {"orphan_files": (str(varlib),)})
    monkeypatch.setitem(reverify.REVERIFIERS, "orphan_files", reverify._orphan_files)
    monkeypatch.setitem(reverify.PREFETCH, "orphan_files", reverify._prefetch_orphan_files)
    dpkg = _FakeDpkg()
    monkeypatch.setattr(oc, "run", dpkg)
    gone = varlib / "zzgone"
    gone.write_text("left over")
    owned = varlib / "zzsoon"
    owned.write_text("about to be owned")
    _aged(gone)
    _aged(owned)
    user_items = [i for i in UnownedSystemFilesReporter(Config()).scan().items
                  if i.remedy is not None]
    assert {i.path for i in user_items} == {str(gone), str(owned)}
    fx.cleaners.append(UnownedSystemFilesReporter(Config()))
    real_scan = service.scan

    def scan_then_install(*a, **k):
        result = real_scan(*a, **k)
        dpkg.owned.add("/var/lib/zzsoon")  # installed between scan and act
        return result

    monkeypatch.setattr(service, "scan", scan_then_install)
    rc, result = run_helper(fx, request(user_items))
    assert rc == elevated.EXIT_OK
    st = {o.key: o for o in result.findings}
    assert st[f"orphan_files|path|{gone}"].status == "removed"
    late = st[f"orphan_files|path|{owned}"]
    assert late.status == "skipped" and "a package owns it now" in late.reason
    assert not gone.exists() and owned.read_text() == "about to be owned"
    # the helper's own scan queried both, then ONE batched up-front re-query
    # (already answers "owned" for zzsoon), then a fresh query right before
    # zzgone's removal
    assert sorted(dpkg.queries[-2][:]) == ["/var/lib/zzgone", "/var/lib/zzsoon"]
    assert dpkg.queries[-1] == ["/var/lib/zzgone"]
    run = fx.qbase / result.quarantine_run
    manifest = json.loads((run / "manifest.json").read_text())
    assert [i["original"] for i in manifest["items"]] == [str(gone)]


@posix_only
def test_helper_end_to_end_removes_a_broken_wants_link_only_while_broken(fx, monkeypatch):
    """stale_services' broken *.wants links: the LINK itself is moved into
    the root quarantine (never its target); a link whose target appeared
    after the helper's scan is kept."""
    from cleanix.cleaners.stale_services import StaleSystemdUnitReporter

    sysroot = fx.tmp / "fsroot"
    etc = sysroot / "etc" / "systemd" / "system"
    wants = etc / "multi-user.target.wants"
    wants.mkdir(parents=True)
    unitdir = sysroot / "usr" / "lib" / "systemd" / "system"
    unitdir.mkdir(parents=True)
    for name in ("gone.service", "back.service"):
        os.symlink(f"/usr/lib/systemd/system/{name}", str(wants / name))
    monkeypatch.setattr(StaleSystemdUnitReporter, "sysroot", str(sysroot))
    monkeypatch.setattr(StaleSystemdUnitReporter, "pkg_backend", lambda self: None)
    monkeypatch.setattr(elevated, "admin_finding_ids", lambda: frozenset({"stale_services"}))
    monkeypatch.setattr(elevated, "finding_path_roots",
                        lambda: {"stale_services": (str(etc),)})
    # tmp_path lies in sticky, world-writable /tmp: accept the chain for the
    # absence rule here (its own logic is tested in test_system_remedies)
    monkeypatch.setattr(elevated, "_evidence_component_problem", lambda st, u, g: None)
    items = [i for i in StaleSystemdUnitReporter(Config()).scan().items
             if i.remedy is not None and i.path.startswith(str(wants))]
    assert {Path(i.path).name for i in items} == {"gone.service", "back.service"}
    fx.cleaners.append(StaleSystemdUnitReporter(Config()))
    real_scan = service.scan

    def scan_then_reinstall(*a, **k):
        result = real_scan(*a, **k)
        (unitdir / "back.service").write_text("[Service]\n")  # target is back
        return result

    monkeypatch.setattr(service, "scan", scan_then_reinstall)
    rc, result = run_helper(fx, request(items))
    assert rc == elevated.EXIT_OK
    st = {Path(o.key.split("|", 2)[2]).name: o for o in result.findings}
    assert st["gone.service"].status == "removed"
    assert st["back.service"].status == "skipped"
    assert "target exists now" in st["back.service"].reason
    assert not os.path.lexists(str(wants / "gone.service"))
    assert os.path.islink(str(wants / "back.service"))
    assert (unitdir / "back.service").exists()
    run = fx.qbase / result.quarantine_run
    (entry,) = json.loads((run / "manifest.json").read_text())["items"]
    assert entry["original"] == str(wants / "gone.service")
    assert os.readlink(entry["stored"]) == "/usr/lib/systemd/system/gone.service"


@posix_only
def test_helper_scan_judges_absence_with_the_chain_rule(fx, monkeypatch):
    """Helper scan with the REAL absence rule: tmp_path lies in sticky,
    world-writable /tmp (anyone may create or remove entries there), so a
    wants link whose target would lie below it is unknown: not found."""
    from cleanix.cleaners.stale_services import StaleSystemdUnitReporter

    sysroot = fx.tmp / "fsroot"
    etc = sysroot / "etc" / "systemd" / "system"
    wants = etc / "multi-user.target.wants"
    wants.mkdir(parents=True)
    os.symlink("/usr/lib/systemd/system/gone.service", str(wants / "gone.service"))
    monkeypatch.setattr(StaleSystemdUnitReporter, "sysroot", str(sysroot))
    monkeypatch.setattr(StaleSystemdUnitReporter, "pkg_backend", lambda self: None)
    monkeypatch.setattr(elevated, "admin_finding_ids", lambda: frozenset({"stale_services"}))
    monkeypatch.setattr(elevated, "finding_path_roots",
                        lambda: {"stale_services": (str(etc),)})
    items = [i for i in StaleSystemdUnitReporter(Config()).scan().items
             if i.remedy is not None]
    assert len(items) == 1
    fx.cleaners.append(StaleSystemdUnitReporter(Config()))
    rc, result = run_helper(fx, request(items))
    assert rc == elevated.EXIT_OK
    (out,) = result.findings
    assert out.status == "not_found" and os.path.islink(str(wants / "gone.service"))


@posix_only
def test_acl_on_item_chain_or_quarantine_parent_refuses(fx, monkeypatch):
    a = make(fx, "a")
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [finding(a)]))
    monkeypatch.setattr(elevated, "_acl_os", lambda: "linux")
    monkeypatch.setattr(elevated, "_list_xattrs",
                        lambda p: ["system.posix_acl_access"] if str(p) == str(fx.sys) else [])
    rc, result = run_helper(fx, request([finding(a)], permanent=True))
    (out,) = result.findings
    assert out.status == "skipped" and "access control list" in out.reason and a.exists()
    monkeypatch.setattr(elevated, "_list_xattrs",
                        lambda p: ["system.posix_acl_default"] if str(p) == str(fx.qparent)
                        else [])
    rc, result = run_helper(fx, request([finding(a)]))
    (out,) = result.findings
    assert out.status == "not_removed" and "access control list" in out.reason
    assert a.exists()


@posix_only
def test_helper_refuses_the_quarantine_under_another_spelling(fx, monkeypatch):
    """Act-time identity check: an item that IS the helper's own folder by
    (st_dev, st_ino) is refused even when its spelling differs (as another
    case of it would on a case-insensitive volume)."""
    alias = fx.sys / "Cleanix-alias"
    alias.mkdir()
    qdir = fx.qparent / "cleanix"
    qdir.mkdir()
    real_lstat = elevated._lstat

    def lstat(path):
        if str(path) == str(alias):
            return real_lstat(str(qdir))
        return real_lstat(path)

    monkeypatch.setattr(elevated, "_lstat", lstat)
    item = finding(alias)
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: [item]))
    for permanent in (True, False):
        rc, result = run_helper(fx, request([item], permanent=permanent))
        (out,) = result.findings
        assert out.status == "skipped" and "administrator quarantine" in out.reason
        assert alias.exists()


def _deadline_run(fx, monkeypatch, *, at_call):
    """Three items; the (fake) clock jumps past the deadline inside the
    ``at_call``-th re-verifier call (calls 1-3: up front, 4-6: right before
    each removal)."""
    items = [finding(make(fx, name)) for name in ("a", "b", "c")]
    fx.cleaners.append(FakeCleaner("orphan_files", lambda: items))
    clock = [1000.0]
    monkeypatch.setattr(elevated, "_monotonic", lambda: clock[0])
    calls = []

    def slow(item, config):
        calls.append(item.path)
        if len(calls) == at_call:
            clock[0] += elevated.DEFAULT_DEADLINE + 1
        return None

    monkeypatch.setitem(reverify.REVERIFIERS, "orphan_files", slow)
    rc, result = run_helper(fx, request(items))
    return rc, result, {o.key.rsplit("/", 1)[1]: o for o in result.findings}, calls


@posix_only
def test_deadline_passing_mid_batch_reports_unprocessed_items_honestly(fx, monkeypatch):
    """The deadline passes during item b's own re-check right before its
    removal: a (already done) is removed, b is NOT removed after the
    deadline, c is "deadline reached; not processed"; all honest."""
    rc, result, st, _calls = _deadline_run(fx, monkeypatch, at_call=5)
    assert rc == elevated.EXIT_DEADLINE and result.deadline_hit
    assert st["a"].status == "removed" and not (fx.sys / "a").exists()
    assert st["b"].status == "not_removed"
    assert st["b"].reason == actions.STOPPED_AT_DEADLINE and (fx.sys / "b").exists()
    assert st["c"].status == "not_removed"
    assert st["c"].reason == "deadline reached; not processed" and (fx.sys / "c").exists()
    assert result.removed == 1


@posix_only
def test_nothing_is_removed_after_the_deadline(fx, monkeypatch):
    # passes during the FIRST removal-phase re-check: nothing at all removed
    rc, result, st, _calls = _deadline_run(fx, monkeypatch, at_call=4)
    assert rc == elevated.EXIT_DEADLINE and result.removed == 0
    assert st["a"].reason == actions.STOPPED_AT_DEADLINE
    assert {st[n].reason for n in "bc"} == {"deadline reached; not processed"}
    assert all((fx.sys / n).exists() for n in "abc")


@posix_only
def test_deadline_during_the_up_front_checks_stops_verifying(fx, monkeypatch):
    rc, result, st, calls = _deadline_run(fx, monkeypatch, at_call=1)
    assert rc == elevated.EXIT_DEADLINE and result.removed == 0
    assert len(calls) == 1  # b and c were never even re-checked
    assert {st[n].status for n in "abc"} == {"not_removed"}
    assert all((fx.sys / n).exists() for n in "abc")


# --------------------------------------------------------------------------
# Task 9b: system-wide launch jobs, systemd units and package receipts,
# end to end through the helper (real detectors and re-verifiers, a
# recording command runner; nothing is ever executed)
# --------------------------------------------------------------------------
class _Runner:
    """``remedy_exec.runner`` stand-in: records argv into the shared event
    log and answers per command (``answers``: argv tuple -> result or
    callable)."""

    def __init__(self, events):
        self.events = events
        self.calls = []
        self.answers = {}

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        self.events.append(("cmd", tuple(argv)))
        ans = self.answers.get(tuple(argv), (0, "", ""))
        return ans(list(argv)) if callable(ans) else ans


class _ReadOnlyTools:
    """Fake read-only package tools behind ``orphan_common.run_command``."""

    def __init__(self):
        self.owned = set()
        self.pkgs = {}  # id -> (info text, files)

    def __call__(self, argv, timeout=120):
        argv = list(argv)
        if argv[:2] == ["env", "LC_ALL=C"]:
            argv = argv[2:]
        if argv[:2] == ["dpkg-query", "-S"]:
            out = [f"pkg: {p}" for p in argv[2:] if p in self.owned]
            err = [f"dpkg-query: no path found matching pattern {p}"
                   for p in argv[2:] if p not in self.owned]
            return (1 if err else 0), "\n".join(out), "\n".join(err)
        if argv[:2] == ["pkgutil", "--pkgs"]:
            return 0, "".join(f"{i}\n" for i in self.pkgs), ""
        if argv[:2] == ["pkgutil", "--pkg-info-plist"] and argv[2] in self.pkgs:
            return 0, self.pkgs[argv[2]][0], ""
        if argv[:3] == ["pkgutil", "--only-files", "--files"] and argv[3] in self.pkgs:
            return 0, "".join(f"{f}\n" for f in self.pkgs[argv[3]][1]), ""
        return 127, "", "not found"


def _sys_env(fx, monkeypatch, osname, cid, kind, dirs):
    """Point the real detector ``cid`` at a fake system root, as root-owned
    files (``_ROOT_UID``/``SYSTEM_FILE_UID`` = the test user), on
    ``osname``, and log verify / copy / command / delete events."""
    from cleanix.core import remedy_exec, root_delete

    sysroot = fx.tmp / "fsroot"
    sysroot.mkdir(exist_ok=True)
    monkeypatch.setattr(oc.OrphanReporter, "sysroot", str(sysroot))
    monkeypatch.setattr(plat, "current_os", lambda: osname)
    monkeypatch.setattr(oc, "SYSTEM_FILE_UID", UID)
    # tmp_path lies in sticky, world-writable /tmp: accept the chain for the
    # absence rule here (its own logic is tested in test_system_remedies)
    monkeypatch.setattr(elevated, "_evidence_component_problem", lambda st, u, g: None)
    real_dirs = tuple(str(sysroot / d.lstrip("/")) for d in dirs)
    monkeypatch.setattr(elevated, "admin_finding_ids", lambda: frozenset({cid}))
    monkeypatch.setattr(elevated, "finding_path_roots", lambda: {cid: real_dirs})
    monkeypatch.setattr(elevated, "finding_kind_dirs", lambda: {kind: real_dirs})
    events = []
    runner = _Runner(events)
    monkeypatch.setattr(remedy_exec, "runner", runner)

    def no_spawn(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("a real command was about to run")

    monkeypatch.setattr(remedy_exec, "_spawn", no_spawn)
    real_copy = quarantine.Quarantine.store_copy

    def store_copy(self, path):
        events.append(("copy", str(path)))
        return real_copy(self, path)

    monkeypatch.setattr(quarantine.Quarantine, "store_copy", store_copy)
    real_remove = root_delete.remove

    def remove(path):
        events.append(("delete", str(path)))
        return real_remove(path)

    monkeypatch.setattr(root_delete, "remove", remove)
    real_verify = reverify.REVERIFIERS[cid]

    def verify(item, config):
        events.append(("verify", item.path))
        return real_verify(item, config)

    monkeypatch.setitem(reverify.REVERIFIERS, cid, verify)
    tools = _ReadOnlyTools()
    monkeypatch.setattr(oc, "run_command", tools)
    for d in dirs:
        (sysroot / d.lstrip("/")).mkdir(parents=True, exist_ok=True)
    return sysroot, events, runner, tools


def _plain(p):
    os.chmod(str(p), 0o644)
    return p


def _plist_job(where, name, label=None, program=None):
    import plistlib

    p = where / f"{name}.plist"
    with open(str(p), "wb") as fh:
        plistlib.dump({"Label": label or name,
                       "ProgramArguments": [program or f"/opt/gone/{name}", "-x"]}, fh)
    return _plain(p)


def _own_items(reporter_cls, prefix):
    return [i for i in reporter_cls(Config()).scan().items
            if i.remedy is not None and i.path.startswith(str(prefix))]


def _by_name(result):
    return {Path(o.key.split("|", 2)[2]).name: o for o in result.findings}


def _idx(events, kind, what):
    return [n for n, e in enumerate(events) if e[0] == kind and what in str(e[1])]


@posix_only
def test_helper_system_launch_jobs_end_to_end(fx, monkeypatch):
    """macOS: a LaunchDaemon and a LaunchAgent are re-verified, copied into
    the root quarantine's copy-only run and deleted, in that order -- and
    NO command is run (fix round 1: never a system-domain bootout).
    Permanent (no quarantine run), a note says where the copy is and that
    launchd forgets the daemon at the next restart; nothing is written
    under the user's home."""
    from cleanix.cleaners.orphan_launch_jobs import OrphanLaunchJobReporter

    sysroot, events, runner, _t = _sys_env(
        fx, monkeypatch, plat.MACOS, "orphan_launch_jobs", "launch_job",
        ("/Library/LaunchAgents", "/Library/LaunchDaemons"))
    daemons = sysroot / "Library" / "LaunchDaemons"
    agents = sysroot / "Library" / "LaunchAgents"
    d = _plist_job(daemons, "com.gone.d")
    a = _plist_job(agents, "com.gone.a")
    originals = {str(d): d.read_bytes(), str(a): a.read_bytes()}
    items = _own_items(OrphanLaunchJobReporter, sysroot)
    assert {Path(i.path).name for i in items} == {"com.gone.d.plist", "com.gone.a.plist"}
    assert all(i.remedy.kind is RemedyKind.LAUNCH_JOB for i in items)
    fx.cleaners.append(OrphanLaunchJobReporter(Config()))
    home_before = tree(fx.home)
    rc, result = run_helper(fx, request(items))
    assert rc == elevated.EXIT_OK, result.errors
    st = _by_name(result)
    assert st["com.gone.d.plist"].status == "removed"
    assert st["com.gone.a.plist"].status == "removed"
    assert not d.exists() and not a.exists()
    # no command at all (no system-domain bootout)
    assert runner.calls == [] and _idx(events, "cmd", "") == []
    # order: re-verified -> copied -> deleted
    v, c = _idx(events, "verify", str(d)), _idx(events, "copy", str(d))
    x = _idx(events, "delete", str(d))
    assert len(v) == 2 and len(c) == 1 and len(x) == 1
    assert v[-1] < c[0] < x[0]
    ca, xa = _idx(events, "copy", str(a)), _idx(events, "delete", str(a))
    assert len(ca) == 1 and len(xa) == 1 and ca[0] < xa[0]
    # the copies: one copy-only run in the ROOT quarantine, no restorable run
    assert result.quarantine_run == "" and result.backup_run
    run = fx.qbase / result.backup_run
    assert stat.S_IMODE(os.lstat(str(run)).st_mode) == 0o700
    manifest = json.loads((run / "manifest.json").read_text())
    assert [m["type"] for m in manifest["items"]] == ["copy", "copy"]
    for m in manifest["items"]:
        assert Path(m["stored"]).read_bytes() == originals[m["original"]]
    # honest notes: permanent, where the copy is; the agent was not stopped
    where = str(run / "files")
    assert st["com.gone.d.plist"].note == (
        "permanent: the job's file was removed; launchd forgets it at the next restart "
        f"(it cannot run: its program is missing) (a copy of the file is kept in {where} "
        "for manual recovery)")
    assert st["com.gone.a.plist"].note.startswith("permanent: its file was removed")
    assert "not stopped here" in st["com.gone.a.plist"].note
    assert tree(fx.home) == home_before
    assert not fx.user_qroot.exists()


@posix_only
def test_helper_never_boots_out_a_label_loaded_elsewhere(fx, monkeypatch):
    """Fix round 1: a stale legacy daemon plist whose Label is also used by a
    live job (here a /System daemon; in practice e.g. an SMAppService helper
    loaded from elsewhere) is removed without ANY command, so the live job
    is never stopped."""
    from cleanix.cleaners.orphan_launch_jobs import OrphanLaunchJobReporter

    sysroot, _events, runner, _t = _sys_env(
        fx, monkeypatch, plat.MACOS, "orphan_launch_jobs", "launch_job",
        ("/Library/LaunchAgents", "/Library/LaunchDaemons"))
    daemons = sysroot / "Library" / "LaunchDaemons"
    sysd = sysroot / "System" / "Library" / "LaunchDaemons"
    sysd.mkdir(parents=True)
    s = _plist_job(daemons, "com.vendor.edr.legacy", label="com.vendor.edr")
    live = _plist_job(sysd, "com.vendor.edr.live", label="com.vendor.edr",
                      program="/usr/libexec/x")
    items = _own_items(OrphanLaunchJobReporter, daemons)
    assert len(items) == 1
    fx.cleaners.append(OrphanLaunchJobReporter(Config()))
    rc, result = run_helper(fx, request(items, permanent=True))
    assert rc == elevated.EXIT_OK
    (out,) = result.findings
    assert out.status == "removed" and not s.exists() and live.exists()
    assert "launchd forgets it at the next restart" in out.note
    assert runner.calls == []
    assert result.backup_run and result.quarantine_run == ""


@posix_only
def test_helper_launch_job_changed_after_its_scan_is_skipped(fx, monkeypatch):
    """Right before acting, the ORIGINAL evidence is re-checked: a program
    that reappeared, a plist swapped for a link, or a plist that became
    writable by others is skipped -- no copy, no command, nothing removed."""
    from cleanix.cleaners.orphan_launch_jobs import OrphanLaunchJobReporter

    sysroot, events, runner, _t = _sys_env(
        fx, monkeypatch, plat.MACOS, "orphan_launch_jobs", "launch_job",
        ("/Library/LaunchAgents", "/Library/LaunchDaemons"))
    daemons = sysroot / "Library" / "LaunchDaemons"
    back = _plist_job(daemons, "com.gone.back")
    swap = _plist_job(daemons, "com.gone.swap")
    loose = _plist_job(daemons, "com.gone.loose")
    victim = fx.tmp / "victim.plist"
    victim.write_bytes(swap.read_bytes())
    items = _own_items(OrphanLaunchJobReporter, daemons)
    assert len(items) == 3
    fx.cleaners.append(OrphanLaunchJobReporter(Config()))
    real_scan = service.scan

    def scan_then_change(*a, **k):
        result = real_scan(*a, **k)
        prog = sysroot / "opt" / "gone" / "com.gone.back"
        prog.parent.mkdir(parents=True, exist_ok=True)
        prog.write_text("#!/bin/sh\n")  # reinstalled
        swap.unlink()
        os.symlink(str(victim), str(swap))
        os.chmod(str(loose), 0o666)
        return result

    monkeypatch.setattr(service, "scan", scan_then_change)
    rc, result = run_helper(fx, request(items))
    assert rc == elevated.EXIT_OK
    st = _by_name(result)
    assert {o.status for o in st.values()} == {"skipped"}
    assert back.exists() and os.path.islink(str(swap)) and victim.exists() and loose.exists()
    assert runner.calls == [] and [e for e in events if e[0] in ("copy", "delete")] == []
    assert result.backup_run == ""


@posix_only
def test_helper_systemd_units_end_to_end(fx, monkeypatch):
    """Linux: unit files in /etc/systemd/system are re-verified (package
    ownership re-queried right before), copied, disabled (template units
    without --now) and deleted; ONE daemon-reload after the batch. A unit a
    package started owning after the helper's scan is skipped."""
    from cleanix.cleaners.stale_services import StaleSystemdUnitReporter

    sysroot, events, runner, tools = _sys_env(
        fx, monkeypatch, plat.LINUX, "stale_services", "systemd_unit", ("/etc/systemd/system",))
    monkeypatch.setattr(StaleSystemdUnitReporter, "pkg_backend", lambda self: "dpkg")
    etc = sysroot / "etc" / "systemd" / "system"
    (sysroot / "usr" / "lib" / "systemd" / "system").mkdir(parents=True)
    units = {}
    for name in ("gone.service", "tpl@.service", "owned.service"):
        p = etc / name
        p.write_text("[Service]\nExecStart=/opt/gone/bin/x\n")
        units[name] = _plain(p)
    items = _own_items(StaleSystemdUnitReporter, etc)
    assert {Path(i.path).name for i in items} == set(units)
    assert all(i.remedy.kind is RemedyKind.SYSTEMD_UNIT for i in items)
    fx.cleaners.append(StaleSystemdUnitReporter(Config()))
    real_scan = service.scan

    def scan_then_install(*a, **k):
        result = real_scan(*a, **k)
        tools.owned.add("/etc/systemd/system/owned.service")
        return result

    monkeypatch.setattr(service, "scan", scan_then_install)
    rc, result = run_helper(fx, request(items, permanent=True))
    assert rc == elevated.EXIT_OK, result.errors
    st = _by_name(result)
    assert st["gone.service"].status == "removed" and not units["gone.service"].exists()
    assert st["tpl@.service"].status == "removed" and not units["tpl@.service"].exists()
    assert st["owned.service"].status == "skipped" and units["owned.service"].exists()
    assert "package owns it" in st["owned.service"].reason
    assert runner.calls == [["systemctl", "disable", "--now", "gone.service"],
                            ["systemctl", "disable", "tpl@.service"],
                            ["systemctl", "daemon-reload"]]
    # the reload runs once, after every removal of the batch
    deletes = [n for n, e in enumerate(events) if e[0] == "delete"]
    reload = _idx(events, "cmd", "daemon-reload")
    assert len(reload) == 1 and max(deletes) < reload[0]
    for name in ("gone.service", "tpl@.service"):
        path = str(units[name])
        assert (_idx(events, "verify", path)[-1] < _idx(events, "copy", path)[0]
                < _idx(events, "delete", path)[0])
        assert st[name].note.startswith("permanent: the job is stopped and its file removed")
    # permanent run, yet the copies are kept in the root quarantine
    assert result.quarantine_run == "" and result.backup_run
    manifest = json.loads((fx.qbase / result.backup_run / "manifest.json").read_text())
    assert sorted(Path(m["original"]).name for m in manifest["items"]) == [
        "gone.service", "tpl@.service"]


@posix_only
def test_helper_receipts_end_to_end(fx, monkeypatch):
    """macOS: a receipt whose every listed file is gone is copied (plist and
    bom) and forgotten with ``pkgutil --forget <id>``; the helper then
    verifies both files are gone. A forget that leaves the receipt, or
    fails, is reported as not removed (the copy is kept)."""
    import plistlib

    from cleanix.cleaners import stale_receipts
    from cleanix.cleaners.stale_receipts import StaleReceiptReporter

    sysroot, events, runner, tools = _sys_env(
        fx, monkeypatch, plat.MACOS, "stale_receipts", "pkg_receipt",
        (stale_receipts.RECEIPTS_DIR,))
    monkeypatch.setattr(oc, "tool", lambda name: f"/usr/sbin/{name}")
    rd = sysroot / stale_receipts.RECEIPTS_DIR.lstrip("/")
    paths = {}
    for pkg_id in ("com.vendor.gone", "com.vendor.stuck", "com.vendor.fails"):
        p = rd / f"{pkg_id}.plist"
        p.write_text(f"receipt {pkg_id}")
        b = rd / f"{pkg_id}.bom"
        b.write_text(f"bom {pkg_id}")
        paths[pkg_id] = (_plain(p), _plain(b))
        info = plistlib.dumps({"pkgid": pkg_id, "volume": "/",
                               "install-location": "Applications"}).decode("utf-8")
        tools.pkgs[pkg_id] = (info, [f"Gone-{pkg_id}.app/Contents/MacOS/x"])
    items = _own_items(StaleReceiptReporter, rd)
    assert len(items) == 3 and all(i.remedy.kind is RemedyKind.PKG_RECEIPT for i in items)

    def forgets(argv):
        for f in paths[argv[2]]:
            f.unlink()
        return 0, "Forgot package 'x' on '/'.", ""

    runner.answers[("pkgutil", "--forget", "com.vendor.gone")] = forgets
    runner.answers[("pkgutil", "--forget", "com.vendor.fails")] = (1, "", "No receipt")
    fx.cleaners.append(StaleReceiptReporter(Config()))
    rc, result = run_helper(fx, request(items))
    assert rc == elevated.EXIT_OK
    st = {Path(o.key.split("|", 2)[2]).stem: o for o in result.findings}
    assert st["com.vendor.gone"].status == "removed"
    assert st["com.vendor.gone"].note.startswith(
        "permanent: the install record is forgotten (pkgutil --forget; a copy of its files")
    assert not any(f.exists() for f in paths["com.vendor.gone"])
    assert st["com.vendor.stuck"].status == "not_removed"
    assert "still there" in st["com.vendor.stuck"].reason
    assert st["com.vendor.fails"].status == "not_removed"
    assert "pkgutil --forget failed (exit 1" in st["com.vendor.fails"].reason
    assert all(f.exists() for f in paths["com.vendor.stuck"] + paths["com.vendor.fails"])
    assert sorted(runner.calls) == sorted(
        [["pkgutil", "--forget", i] for i in ("com.vendor.gone", "com.vendor.stuck",
                                              "com.vendor.fails")])
    # plist AND bom copied before the forget, for every receipt acted on
    for pkg_id, (p, b) in paths.items():
        forget = _idx(events, "cmd", pkg_id)
        assert _idx(events, "copy", str(p))[0] < forget[0]
        assert _idx(events, "copy", str(b))[0] < forget[0]
        assert _idx(events, "delete", str(p)) == []  # pkgutil removes it, never unlink
    manifest = json.loads((fx.qbase / result.backup_run / "manifest.json").read_text())
    stored = {Path(m["original"]).name: Path(m["stored"]).read_text()
              for m in manifest["items"]}
    assert stored["com.vendor.gone.plist"] == "receipt com.vendor.gone"
    assert stored["com.vendor.gone.bom"] == "bom com.vendor.gone"
    assert result.removed == 1 and result.quarantine_run == ""


@posix_only
def test_helper_receipt_with_a_file_back_is_skipped(fx, monkeypatch):
    import plistlib

    from cleanix.cleaners import stale_receipts
    from cleanix.cleaners.stale_receipts import StaleReceiptReporter

    sysroot, events, runner, tools = _sys_env(
        fx, monkeypatch, plat.MACOS, "stale_receipts", "pkg_receipt",
        (stale_receipts.RECEIPTS_DIR,))
    monkeypatch.setattr(oc, "tool", lambda name: f"/usr/sbin/{name}")
    rd = sysroot / stale_receipts.RECEIPTS_DIR.lstrip("/")
    p = rd / "com.vendor.back.plist"
    p.write_text("r")
    _plain(p)
    info = plistlib.dumps({"pkgid": "com.vendor.back", "volume": "/",
                           "install-location": "/"}).decode("utf-8")
    tools.pkgs["com.vendor.back"] = (info, ["usr/local/vend/one", "usr/local/vend/two"])
    items = _own_items(StaleReceiptReporter, rd)
    assert len(items) == 1
    fx.cleaners.append(StaleReceiptReporter(Config()))
    real_scan = service.scan

    def scan_then_reinstall(*a, **k):
        result = real_scan(*a, **k)
        f = sysroot / "usr" / "local" / "vend" / "two"
        f.parent.mkdir(parents=True)
        f.write_text("x")
        return result

    monkeypatch.setattr(service, "scan", scan_then_reinstall)
    rc, result = run_helper(fx, request(items))
    (out,) = result.findings
    assert out.status == "skipped" and "exists now" in out.reason
    assert p.exists() and runner.calls == [] and _idx(events, "copy", "") == []


@posix_only
def test_helper_job_deadline_mid_batch_is_honest(fx, monkeypatch):
    """The deadline passes during the second daemon's own re-check right
    before acting: the first was removed, the second is neither copied,
    stopped nor removed, and says so."""
    from cleanix.cleaners.orphan_launch_jobs import OrphanLaunchJobReporter

    sysroot, events, runner, _t = _sys_env(
        fx, monkeypatch, plat.MACOS, "orphan_launch_jobs", "launch_job",
        ("/Library/LaunchAgents", "/Library/LaunchDaemons"))
    daemons = sysroot / "Library" / "LaunchDaemons"
    a = _plist_job(daemons, "com.gone.a")
    b = _plist_job(daemons, "com.gone.b")
    items = sorted(_own_items(OrphanLaunchJobReporter, daemons), key=lambda i: i.path)
    fx.cleaners.append(OrphanLaunchJobReporter(Config()))
    clock = [1000.0]
    monkeypatch.setattr(elevated, "_monotonic", lambda: clock[0])
    logged = reverify.REVERIFIERS["orphan_launch_jobs"]
    calls = []

    def slow(item, config):
        calls.append(item.path)
        why = logged(item, config)
        if len(calls) == 4:  # b's re-check right before acting on it
            clock[0] += elevated.DEFAULT_DEADLINE + 1
        return why

    monkeypatch.setitem(reverify.REVERIFIERS, "orphan_launch_jobs", slow)
    rc, result = run_helper(fx, request(items))
    assert rc == elevated.EXIT_DEADLINE and result.deadline_hit
    st = _by_name(result)
    assert st["com.gone.a.plist"].status == "removed" and not a.exists()
    assert st["com.gone.b.plist"].status == "not_removed"
    assert st["com.gone.b.plist"].reason == actions.STOPPED_AT_DEADLINE and b.exists()
    assert runner.calls == []
    assert _idx(events, "copy", str(b)) == [] and _idx(events, "delete", str(b)) == []


@posix_only
def test_helper_jobs_need_a_usable_backup_location(fx, monkeypatch):
    """Even in permanent mode the copy is required: an unusable root
    quarantine means nothing is copied, stopped or removed."""
    from cleanix.cleaners.orphan_launch_jobs import OrphanLaunchJobReporter

    sysroot, events, runner, _t = _sys_env(
        fx, monkeypatch, plat.MACOS, "orphan_launch_jobs", "launch_job",
        ("/Library/LaunchAgents", "/Library/LaunchDaemons"))
    d = _plist_job(sysroot / "Library" / "LaunchDaemons", "com.gone.d")
    items = _own_items(OrphanLaunchJobReporter, sysroot)
    fx.cleaners.append(OrphanLaunchJobReporter(Config()))

    def broken(uid, groups):
        raise elevated.Refused("is writable by other users")

    monkeypatch.setattr(elevated, "_prepare_root_quarantine", broken)
    rc, result = run_helper(fx, request(items, permanent=True))
    (out,) = result.findings
    assert out.status == "not_removed"
    assert "administrator quarantine" in out.reason and "nothing was removed" in out.reason
    assert d.exists() and runner.calls == [] and events == []


@posix_only
def test_helper_refuses_job_kinds_on_the_wrong_platform(fx, monkeypatch):
    """A systemd unit request on macOS (or a launch job on Linux) is refused
    per item; nothing is scanned for it."""
    from cleanix.cleaners.orphan_launch_jobs import OrphanLaunchJobReporter

    sysroot, events, runner, _t = _sys_env(
        fx, monkeypatch, plat.MACOS, "orphan_launch_jobs", "launch_job",
        ("/Library/LaunchAgents", "/Library/LaunchDaemons"))
    d = _plist_job(sysroot / "Library" / "LaunchDaemons", "com.gone.d")
    items = _own_items(OrphanLaunchJobReporter, sysroot)
    fx.cleaners.append(OrphanLaunchJobReporter(Config()))
    monkeypatch.setattr(plat, "current_os", lambda: plat.LINUX)
    rc, result = run_helper(fx, request(items))
    (out,) = result.findings
    assert out.status == "refused" and out.reason == elevated.KIND_NOT_SUPPORTED
    assert fx.scans == [] and d.exists() and runner.calls == []


@posix_only
def test_helper_job_changed_while_the_batch_runs_is_skipped(fx, monkeypatch):
    """The re-check right before acting on EACH job: b's program comes back
    while a is being removed; b is then neither copied nor removed."""
    from cleanix.cleaners.orphan_launch_jobs import OrphanLaunchJobReporter

    sysroot, events, runner, _t = _sys_env(
        fx, monkeypatch, plat.MACOS, "orphan_launch_jobs", "launch_job",
        ("/Library/LaunchAgents", "/Library/LaunchDaemons"))
    daemons = sysroot / "Library" / "LaunchDaemons"
    a = _plist_job(daemons, "com.gone.a")
    b = _plist_job(daemons, "com.gone.b")
    items = sorted(_own_items(OrphanLaunchJobReporter, daemons), key=lambda i: i.path)

    from cleanix.core import root_delete

    logged_remove = root_delete.remove

    def remove_a_then_reinstall_b(path):
        result = logged_remove(path)
        if path == str(a):
            prog = sysroot / "opt" / "gone" / "com.gone.b"
            prog.parent.mkdir(parents=True, exist_ok=True)
            prog.write_text("#!/bin/sh\n")
        return result

    monkeypatch.setattr(root_delete, "remove", remove_a_then_reinstall_b)
    fx.cleaners.append(OrphanLaunchJobReporter(Config()))
    rc, result = run_helper(fx, request(items))
    st = _by_name(result)
    assert st["com.gone.a.plist"].status == "removed" and not a.exists()
    assert st["com.gone.b.plist"].status == "skipped" and b.exists()
    assert "program exists now" in st["com.gone.b.plist"].reason
    assert runner.calls == []
    assert _idx(events, "copy", str(b)) == [] and _idx(events, "delete", str(b)) == []


@posix_only
def test_helper_mixed_batch_keeps_quarantine_and_copies_apart(fx, monkeypatch):
    """One stale_services batch, not permanent: the broken wants link (PATH)
    is MOVED into the restorable quarantine run; the unit file (always
    permanent) is copied into a separate copy-only run and deleted. Two
    distinct runs under the root quarantine, one daemon-reload."""
    from cleanix.cleaners.stale_services import StaleSystemdUnitReporter

    sysroot, events, runner, tools = _sys_env(
        fx, monkeypatch, plat.LINUX, "stale_services", "systemd_unit", ("/etc/systemd/system",))
    monkeypatch.setattr(StaleSystemdUnitReporter, "pkg_backend", lambda self: "dpkg")
    etc = sysroot / "etc" / "systemd" / "system"
    (sysroot / "usr" / "lib" / "systemd" / "system").mkdir(parents=True)
    wants = etc / "multi-user.target.wants"
    wants.mkdir()
    link = wants / "other.service"
    os.symlink("/usr/lib/systemd/system/other.service", str(link))
    u = etc / "gone.service"
    u.write_text("[Service]\nExecStart=/opt/gone/bin/x\n")
    _plain(u)
    items = _own_items(StaleSystemdUnitReporter, etc)
    kinds = {Path(i.path).name: i.remedy.kind for i in items}
    assert kinds == {"other.service": RemedyKind.PATH, "gone.service": RemedyKind.SYSTEMD_UNIT}
    fx.cleaners.append(StaleSystemdUnitReporter(Config()))
    rc, result = run_helper(fx, request(items))
    assert rc == elevated.EXIT_OK, result.errors
    st = {o.key.split("|", 2)[2]: o for o in result.findings}
    assert st[str(link)].status == "removed" and st[str(u)].status == "removed"
    assert not os.path.lexists(str(link)) and not u.exists()
    assert st[str(link)].note == ""  # an ordinary (restorable) quarantine move
    assert st[str(u)].note.startswith("permanent: ")
    assert result.quarantine_run and result.backup_run
    assert result.quarantine_run != result.backup_run
    assert sorted(d.name for d in fx.qbase.iterdir()) == sorted(
        [result.quarantine_run, result.backup_run])
    moved = json.loads((fx.qbase / result.quarantine_run / "manifest.json").read_text())
    (entry,) = moved["items"]
    assert entry.get("type") is None and entry["original"] == str(link)
    assert os.readlink(entry["stored"]) == "/usr/lib/systemd/system/other.service"
    kept = json.loads((fx.qbase / result.backup_run / "manifest.json").read_text())
    (copy,) = kept["items"]
    assert copy["type"] == "copy" and copy["original"] == str(u)
    assert runner.calls == [["systemctl", "disable", "--now", "gone.service"],
                            ["systemctl", "daemon-reload"]]
