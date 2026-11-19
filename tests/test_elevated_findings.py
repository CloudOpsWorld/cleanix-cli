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


def test_non_path_kind_refused_for_now(lexical):
    sel = parse(payload([dict(GOOD_ITEM, kind="launch_job"),
                         dict(GOOD_ITEM, key="orphan_files|path|/var/lib/b", kind="path")]))
    plan = elevated._prepare_findings(sel.findings)
    assert plan.refused == {"orphan_files|path|/var/lib/gone": elevated.KIND_NOT_SUPPORTED}
    assert "not handled" in elevated.KIND_NOT_SUPPORTED


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
    items = [finding(a, kind=RemedyKind.LAUNCH_JOB), finding(b, group="g1")]
    summary = actions.act(items, Config(), dry_run=False, permanent=True,
                          record_history=False, allow_root=True)
    assert a.exists() and b.exists()
    assert [r for _i, r in summary.skipped] == [actions.NOT_HANDLED, actions.NOT_HANDLED]


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
def _fake_launcher(write=True, nonce=None, rc_exc=None):
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
                findings=[elevate.FindingOutcome(sel.findings.items[0].key, "not_found",
                                                 reason=elevated.NOT_FOUND)]))
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


def test_run_findings_request_returns_matching_result():
    launch = _fake_launcher()
    result = elevate_launch.run_findings_request(_req(), "alice", launcher=launch)
    assert len(launch.calls) == 1
    assert result.findings[0].status == "not_found"
    req_dir = Path(launch.calls[0][launch.calls[0].index("--request") + 1]).parent
    assert not req_dir.exists()  # always removed


def test_run_findings_request_refused_exit_still_returns_result():
    launch = _fake_launcher(rc_exc=elevate_launch.ElevationFailed("x", exit_code=1))
    result = elevate_launch.run_findings_request(_req(), "alice", launcher=launch)
    assert result.unmatched == 1


def test_run_findings_request_rejects_stale_result():
    with pytest.raises(elevate_launch.ElevationFailed):
        elevate_launch.run_findings_request(_req(), "alice",
                                            launcher=_fake_launcher(nonce="0" * 32))
    with pytest.raises(elevate_launch.ElevationFailed):
        elevate_launch.run_findings_request(_req(), "alice",
                                            launcher=_fake_launcher(write=False))


def test_run_findings_request_never_prompts_for_an_invalid_request():
    launch = _fake_launcher()
    bad = elevate.FindingsRequest(only=["orphan_files"], items=[
        elevate.FindingSelection("orphan_files|path|/var/lib/../etc", (1, 2, 3, 4), "path")])
    with pytest.raises(ValueError):
        elevate_launch.run_findings_request(bad, "alice", launcher=launch)
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
    assert rc == elevated.EXIT_OK and job.exists()
    assert result.findings[0].status == "refused"
    assert result.findings[0].reason == elevated.KIND_NOT_SUPPORTED
    assert fx.scans == []  # nothing left to scan for


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
