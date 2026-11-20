"""Task 9a: system-wide PATH remedies, their act-time re-verification, and
the hardening the helper needs before it acts on them (M1 user-steerable
evidence, M2 case-insensitive quarantine aliases, M3 ACLs, M8 long names,
mount table and rename carry-overs).

Hermetic: fake sysroots, injected command runners, fake lstat / xattr /
mountinfo seams; nothing runs as root and no real system path is touched.
Logic tests run on every OS; tests that need POSIX symlinks or renames
are skipped on Windows. The end-to-end helper tests are in
test_elevated_findings.py.
"""

from __future__ import annotations

import errno
import json
import os
import stat
import time
from pathlib import Path

import pytest

from cleanix import elevated
from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners import orphan_launch_jobs as olj
from cleanix.cleaners import stale_launchers, stale_services
from cleanix.cleaners.orphan_files import UnownedSystemFilesReporter
from cleanix.config import Config
from cleanix.core import actions, elevate, engine, quarantine, reverify, root_delete, scanmode
from cleanix.core.models import CleanableItem, ItemKind
from cleanix.core.remedy import LINK_TARGET, Remedy, RemedyKind, fingerprint_of, link_target, verify_path

POSIX = os.name != "nt"
posix_only = pytest.mark.skipif(not POSIX, reason="needs POSIX symlinks/renames")
OLD = 100  # days: older than every default age threshold


def age(path: Path, days: float = OLD) -> Path:
    t = time.time() - days * 86400
    if POSIX:
        os.utime(str(path), (t, t), follow_symlinks=False)  # a link itself
    else:
        os.utime(str(path), (t, t))
    return path


def put(base: Path, rel: str, text: str = "x") -> Path:
    p = base / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


class Dpkg:
    """A fake dpkg behind ``oc.run``: ``owned`` paths are owned, every other
    queried path is reported unowned; ``rc`` forces an unknown answer."""

    def __init__(self, monkeypatch, env):
        self.owned = set()
        self.rc = None
        self.installed = ["bash", "coreutils"]
        self.queries = []
        monkeypatch.setattr(oc.OrphanReporter, "pkg_backend", lambda self_: "dpkg")
        env.cmds.tools = {"dpkg-query"}
        (env.root / "etc").mkdir(parents=True, exist_ok=True)
        (env.root / "etc" / "passwd").write_text("root:x:0:0\n")
        monkeypatch.setattr(oc, "run_command", self)

    def __call__(self, argv, timeout=120):
        argv = list(argv)
        if argv[:2] == ["env", "LC_ALL=C"]:
            argv = argv[2:]
        if argv[:2] == ["dpkg-query", "-W"]:
            return 0, "".join(f"{n}\n" for n in self.installed), ""
        if argv[:2] == ["dpkg-query", "-S"]:
            ps = argv[2:]
            self.queries.append(ps)
            if self.rc is not None:
                return self.rc, "", ""
            out, err = [], []
            for p in ps:
                if p in self.owned:
                    out.append(f"somepkg: {p}")
                else:
                    err.append(f"dpkg-query: no path found matching pattern {p}")
            return (1 if err else 0), "\n".join(out), "\n".join(err)
        return 127, "", "not found"


def orphan_file_items(env):
    return [i for i in UnownedSystemFilesReporter(Config()).scan().items
            if i.description.startswith(("Not from any package", "Installed outside"))]


# --------------------------------------------------------------------------
# detectors attach PATH remedies to system-wide findings (and only those)
# --------------------------------------------------------------------------
def test_orphan_files_system_item_has_path_remedy(orphan_env, monkeypatch):
    Dpkg(monkeypatch, orphan_env)
    gone = age(put(orphan_env.root, "/opt/zzgone/data"))
    age(gone.parent)
    items = orphan_file_items(orphan_env)
    (item,) = [i for i in items if i.path == str(gone.parent)]
    assert item.requires_root and item.report_only
    assert item.remedy.kind is RemedyKind.PATH and item.remedy.group is None
    assert item.remedy.fingerprint == fingerprint_of(str(gone.parent))
    assert link_target(item.remedy) is None


@posix_only
def test_notes_and_unknown_have_no_remedy(orphan_env, monkeypatch):
    env = orphan_env
    dpkg = Dpkg(monkeypatch, env)
    # orphan_files: an unowned SYMLINK has no safe PATH remedy
    (env.root / "opt").mkdir(parents=True)
    os.symlink("/nowhere", str(env.root / "opt" / "zzlink"))
    age(env.root / "opt" / "zzlink")
    # orphan_files: the installed packages cannot be listed -> a note
    (env.root / "var" / "lib" / "zzstate").mkdir(parents=True)
    dpkg.installed = []
    items = UnownedSystemFilesReporter(Config()).scan().items
    link = [i for i in items if i.path == str(env.root / "opt" / "zzlink")]
    assert link and link[0].remedy is None
    notes = [i for i in items if i.description.startswith("Not checked")]
    assert notes and all(i.remedy is None for i in notes)

    # stale_services: a system unit FILE (SYSTEMD_UNIT, Task 9b) and a
    # drop-in for user units (/etc/systemd/user) get no remedy
    put(env.root, "etc/systemd/system/gone.service", "[Service]\nExecStart=/opt/gone/x\n")
    (env.root / "usr/lib/systemd/system").mkdir(parents=True)
    (env.root / "etc/systemd/user/gone-user.service.d").mkdir(parents=True)
    (env.root / "etc/systemd/system/gone-sys.service.d").mkdir(parents=True)
    items = stale_services.StaleSystemdUnitReporter(Config()).scan().items
    by = {Path(i.path).name: i for i in items}
    assert by["gone.service"].requires_root and by["gone.service"].remedy is None
    assert by["gone-user.service.d"].requires_root and by["gone-user.service.d"].remedy is None
    assert by["gone-sys.service.d"].remedy.kind is RemedyKind.PATH

    # orphan_launch_jobs: system jobs (LAUNCH_JOB, Task 9b) get no remedy,
    # also a broken system job link
    import plistlib

    d = env.root / "Library" / "LaunchDaemons"
    d.mkdir(parents=True)
    with open(str(d / "com.gone.sys.plist"), "wb") as fh:
        plistlib.dump({"Label": "com.gone.sys", "Program": "/opt/gone/sys"}, fh)
    os.symlink("/Library/Gone/com.gone.link.plist", str(d / "com.gone.link.plist"))
    items = olj.OrphanLaunchJobReporter(Config()).scan().items
    sys_items = [i for i in items if i.path.startswith(str(d))]
    assert len(sys_items) == 2
    assert all(i.requires_root and i.remedy is None for i in sys_items)

    # a note never gets a remedy, system-wide or not
    rep = oc.OrphanReporter(Config())
    f = oc.Finding(d, "n", "h", requires_root=True, note=True, remedy_kind=RemedyKind.PATH)
    assert rep._item(f, 0, True).remedy is None


def test_system_non_path_kinds_get_no_remedy(tmp_path):
    p = tmp_path / "x"
    p.write_text("x")
    rep = oc.OrphanReporter(Config())
    for kind in (RemedyKind.LAUNCH_JOB, RemedyKind.SYSTEMD_UNIT, RemedyKind.PKG_RECEIPT):
        f = oc.Finding(p, "l", "h", requires_root=True, remedy_kind=kind,
                       remedy_extra=(("label", "a.b"),))
        assert rep._item(f, 0, True).remedy is None
    f = oc.Finding(p, "l", "h", requires_root=True, remedy_kind=RemedyKind.PATH)
    assert rep._item(f, 0, True).remedy.kind is RemedyKind.PATH


# --------------------------------------------------------------------------
# act-time re-verification (re-verifier table)
# --------------------------------------------------------------------------
def test_unowned_file_skipped_when_now_owned(orphan_env, monkeypatch):
    dpkg = Dpkg(monkeypatch, orphan_env)
    f = age(put(orphan_env.root, "/opt/zzleft"))
    (item,) = [i for i in orphan_file_items(orphan_env) if i.path == str(f)]
    assert reverify.reverify(item, Config()) is None  # still unowned
    assert dpkg.queries[-1] == ["/opt/zzleft"]  # the exact path, fixed argv
    dpkg.owned.add("/opt/zzleft")  # a package installed it meanwhile
    why = reverify.reverify(item, Config())
    assert why and "a package owns it now" in why


def test_unowned_folder_reverify_requeries_probed_children(orphan_env, monkeypatch):
    dpkg = Dpkg(monkeypatch, orphan_env)
    d = orphan_env.root / "opt" / "zzvendor"
    age(put(orphan_env.root, "/opt/zzvendor/app"))
    age(d)
    (item,) = [i for i in orphan_file_items(orphan_env) if i.path == str(d)]
    assert reverify.reverify(item, Config()) is None
    dpkg.owned.add("/opt/zzvendor/app")  # only a child is owned now
    assert "owns it now" in reverify.reverify(item, Config())


def test_reverify_refuses_a_path_outside_the_scanned_folders(orphan_env, monkeypatch):
    Dpkg(monkeypatch, orphan_env)
    f = age(put(orphan_env.root, "/etc/zzleft"))
    item = CleanableItem(cleaner_id="orphan_files", description="d", size=0,
                         kind=ItemKind.PATH, path=str(f), requires_root=True,
                         report_only=True, remedy=Remedy(RemedyKind.PATH, (1, 2, 3, 4)))
    assert reverify.reverify(item, Config()) == "it is not in a folder this scenario checks"


def test_unowned_file_unknown_ownership_is_skip(orphan_env, monkeypatch):
    dpkg = Dpkg(monkeypatch, orphan_env)
    f = age(put(orphan_env.root, "/opt/zzleft"))
    (item,) = [i for i in orphan_file_items(orphan_env) if i.path == str(f)]
    for rc in (124, 125, 126, 127, 2):  # timeout, unknown, refused, missing, error
        dpkg.rc = rc
        assert "could not be confirmed" in reverify.reverify(item, Config())
    dpkg.rc = None
    monkeypatch.setattr(oc.OrphanReporter, "pkg_backend", lambda self_: None)
    assert reverify.reverify(item, Config()) == "package ownership cannot be checked now"


def test_unowned_file_now_named_after_a_package_is_skip(orphan_env, monkeypatch):
    dpkg = Dpkg(monkeypatch, orphan_env)
    d = orphan_env.root / "var" / "lib" / "zzdb"
    age(put(orphan_env.root, "/var/lib/zzdb/data"))
    age(d)
    (item,) = [i for i in orphan_file_items(orphan_env) if i.path == str(d)]
    assert reverify.reverify(item, Config()) is None
    dpkg.installed.append("zzdb-server")  # e.g. reinstalled: postinst state dir
    assert "has its name" in reverify.reverify(item, Config())
    dpkg.installed = []  # cannot list the packages: unknown
    assert "could not be listed" in reverify.reverify(item, Config())


def test_reverify_unknown_is_skip(orphan_env, monkeypatch):
    item = CleanableItem(cleaner_id="orphan_launch_jobs", description="d", size=0,
                         kind=ItemKind.PATH, path="/Library/LaunchDaemons/x.plist",
                         requires_root=True, report_only=True,
                         remedy=Remedy(RemedyKind.PATH, (1, 2, 3, 4)))
    assert reverify.reverify(item, Config()) == reverify.NO_REVERIFIER

    def boom(item, config):
        raise RuntimeError("kaputt")

    monkeypatch.setitem(reverify.REVERIFIERS, "orphan_launch_jobs", boom)
    assert reverify.reverify(item, Config()) == "could not be re-checked (kaputt)"

    # stale_launchers: the program is missing, but in strict mode with no
    # evidence rule registered its absence cannot be judged: skip
    entry = put(orphan_env.root, "usr/local/share/applications/g.desktop",
                "[Desktop Entry]\nType=Application\nName=G\nExec=/opt/gone/bin/g\n")
    sl = CleanableItem(cleaner_id="stale_launchers", description="d", size=0,
                       kind=ItemKind.PATH, path=str(entry), requires_root=True,
                       report_only=True, remedy=Remedy(RemedyKind.PATH, (1, 2, 3, 4)))
    assert "cannot be confirmed missing" in reverify.reverify(sl, Config())
    with scanmode.evidence_rule(lambda p: None):
        assert reverify.reverify(sl, Config()) is None
    with scanmode.evidence_rule(lambda p: "nope"):
        assert "cannot be confirmed missing" in reverify.reverify(sl, Config())


def _mac_inventory(env, n=5):
    for k in range(n):
        app = env.root / "Applications" / f"Filler{k}.app" / "Contents"
        app.mkdir(parents=True)
        import plistlib

        with open(str(app / "Info.plist"), "wb") as fh:
            plistlib.dump({"CFBundleIdentifier": f"com.filler{k}.app"}, fh)


def test_orphan_app_data_reverify_requires_mdfind_and_rechecks_the_id(orphan_env):
    env = orphan_env
    _mac_inventory(env)
    sup = env.root / "Library" / "Application Support" / "com.gonevendor.Thing"
    put(sup, "data.bin")
    age(sup / "data.bin")
    age(sup)
    item = CleanableItem(cleaner_id="orphan_app_data", description="d", size=0,
                         kind=ItemKind.PATH, path=str(sup), requires_root=True,
                         report_only=True, remedy=Remedy(RemedyKind.PATH, (1, 2, 3, 4)))
    mdfind = ("mdfind", "kMDItemContentType == 'com.apple.application-bundle'")
    # mdfind unavailable: unknown -> skip
    assert reverify.reverify(item, Config()) == "the installed apps could not be listed now"
    env.cmds.on(mdfind, 0, "")
    assert reverify.reverify(item, Config()) is None
    # an app with that vendor appeared meanwhile
    app = env.root / "Applications" / "Thing.app" / "Contents"
    app.mkdir(parents=True)
    import plistlib

    with open(str(app / "Info.plist"), "wb") as fh:
        plistlib.dump({"CFBundleIdentifier": "com.gonevendor.Thing"}, fh)
    assert "now uses the id" in reverify.reverify(item, Config())


def test_admin_finding_scenarios_have_re_verifiers():
    # Scenarios whose system-wide findings may carry a PATH remedy (9a)
    path_scenarios = {"orphan_files", "orphan_app_data", "stale_launchers", "stale_services"}
    # A new system scenario fails here until someone decides its re-verifier.
    assert set(elevate.SYSTEM_FINDING_IDS) == path_scenarios | {"orphan_launch_jobs",
                                                                "stale_receipts"}
    for cid in path_scenarios:
        assert reverify.has_reverifier(cid), cid
    # kinds not supported in 9a stay refused: no re-verifier, kind not handled
    for cid in set(elevate.SYSTEM_FINDING_IDS) - path_scenarios:
        assert not reverify.has_reverifier(cid), cid
    assert elevated._HELPER_FINDING_KINDS == frozenset({"path"})
    # every scenario the helper may act on (any platform) is covered
    for cid in elevate.SYSTEM_FINDING_IDS:
        item = CleanableItem(cleaner_id=cid, description="d", size=0, kind=ItemKind.PATH,
                             path="/x/y", requires_root=True, report_only=True,
                             remedy=Remedy(RemedyKind.PATH, (1, 2, 3, 4)))
        sel = elevate.FindingSelection(key=f"{cid}|path|/x/y", fingerprint=(1, 2, 3, 4),
                                       kind="path")
        why = elevated._finding_problem(item, sel, frozenset(elevate.SYSTEM_FINDING_IDS),
                                        {cid: ("/x",)}, ())
        if cid in path_scenarios:
            assert why is None, cid
        else:
            assert why == ("refused", reverify.NO_REVERIFIER), cid
    # admin_finding_ids() (any platform) is a subset of the decided set
    assert set(elevate.admin_finding_ids()) <= set(elevate.SYSTEM_FINDING_IDS)


def test_root_mode_act_refuses_a_scenario_without_re_verifier(tmp_path, monkeypatch):
    p = tmp_path / "f"
    p.write_text("x")
    item = CleanableItem(cleaner_id="stale_receipts", description="d", size=0,
                         kind=ItemKind.PATH, path=str(p), requires_root=True,
                         report_only=True, remedy=Remedy(RemedyKind.PATH, fingerprint_of(str(p))))
    monkeypatch.setattr(root_delete, "mount_problem", lambda path, permanent: None)
    s = actions.act([item], Config(), dry_run=True, permanent=True, allow_root=True)
    assert s.skipped == [(item, reverify.NO_REVERIFIER)] and p.exists()


def test_normal_path_still_skips_requires_root(orphan_env, monkeypatch):
    env = orphan_env
    entry = put(env.root, "usr/local/share/applications/g.desktop",
                "[Desktop Entry]\nType=Application\nName=G\nExec=/opt/gone/bin/g\n")
    (item,) = [i for i in stale_launchers.StaleDesktopEntryReporter(Config()).scan().items
               if i.path == str(entry)]
    assert item.requires_root and item.remedy.kind is RemedyKind.PATH
    monkeypatch.setattr(engine, "is_root", lambda: True)  # even in a root process
    monkeypatch.setattr(reverify, "reverify", lambda *a: pytest.fail("re-verified"))
    s = actions.act([item], Config(), dry_run=False, permanent=True)
    assert s.skipped == [(item, actions.NEEDS_ELEVATION)] and entry.exists()
    # a link remedy is never handled outside the helper's root mode
    link = CleanableItem(cleaner_id="stale_services", description="d", size=0,
                         kind=ItemKind.PATH, path=str(entry), requires_root=False,
                         report_only=True,
                         remedy=Remedy(RemedyKind.PATH, (1, 2, 3, 4),
                                       extra=((LINK_TARGET, "/x"),)))
    s = actions.act([link], Config(), dry_run=False, permanent=True)
    assert s.skipped == [(link, actions.NOT_HANDLED)] and entry.exists()


# --------------------------------------------------------------------------
# link remedies (broken system unit links)
# --------------------------------------------------------------------------
@posix_only
def test_link_remedy_verifies_the_link_itself(tmp_path):
    from cleanix.core.remedy import link_remedy

    link = tmp_path / "x.service"
    os.symlink("/usr/lib/systemd/system/gone.service", str(link))
    r = link_remedy(str(link))
    assert r.kind is RemedyKind.PATH and link_target(r) == "/usr/lib/systemd/system/gone.service"
    assert verify_path(str(link), r.fingerprint) is not None  # plain PATH: links refused
    assert verify_path(str(link), r.fingerprint, link=link_target(r)) is None
    assert "points elsewhere" in verify_path(str(link), r.fingerprint, link="/other")
    os.unlink(str(link))
    link.write_text("now a file")
    assert verify_path(str(link), r.fingerprint, link=link_target(r)) is not None
    assert link_remedy(str(link)) is None  # not a link


@posix_only
def test_system_wants_link_has_link_remedy(orphan_env):
    env = orphan_env
    wants = env.root / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    os.symlink("/usr/lib/systemd/system/gone.service", str(wants / "gone.service"))
    (env.root / "usr/lib/systemd/system").mkdir(parents=True)
    items = stale_services.StaleSystemdUnitReporter(Config()).scan().items
    (item,) = [i for i in items if i.path == str(wants / "gone.service")]
    assert item.requires_root
    assert link_target(item.remedy) == "/usr/lib/systemd/system/gone.service"
    with scanmode.evidence_rule(lambda p: None):
        assert reverify.reverify(item, Config()) is None


@posix_only
def test_broken_wants_link_to_a_unit_known_by_name_gets_no_remedy(orphan_env):
    """systemd adds a .wants dependency by the LINK's name: a dangling link
    still enables a unit of that name (or its template) found anywhere on
    the load path, so it is never offered for removal; nor is any link for
    user units (/etc/systemd/user)."""
    env = orphan_env
    etc = env.root / "etc/systemd/system"
    wants = etc / "multi-user.target.wants"
    wants.mkdir(parents=True)
    (env.root / "usr/lib/systemd/system").mkdir(parents=True)
    os.symlink("/usr/lib/systemd/system/copied.service", str(wants / "copied.service"))
    put(etc, "copied.service", "[Service]\nExecStart=/usr/bin/true\n")  # admin's copy
    os.symlink("/usr/lib/systemd/system/getty@tty9.service", str(wants / "getty@tty9.service"))
    put(env.root, "run/systemd/transient/getty@.service", "[Service]\n")
    user_wants = env.root / "etc/systemd/user/default.target.wants"
    user_wants.mkdir(parents=True)
    os.symlink("/usr/lib/systemd/user/gone.service", str(user_wants / "gone.service"))
    items = {i.path: i for i in stale_services.StaleSystemdUnitReporter(Config()).scan().items}
    for path in (wants / "copied.service", wants / "getty@tty9.service",
                 user_wants / "gone.service"):
        item = items[str(path)]  # still reported (the link is dangling) ...
        assert item.requires_root and item.remedy is None  # ... but never removed
    # the act-time re-check refuses too (e.g. the unit appeared after the scan)
    forged = CleanableItem(
        cleaner_id="stale_services", description="d", size=0, kind=ItemKind.PATH,
        path=str(wants / "copied.service"), requires_root=True, report_only=True,
        remedy=Remedy(RemedyKind.PATH, fingerprint_of(str(wants / "copied.service")),
                      extra=((LINK_TARGET, "/usr/lib/systemd/system/copied.service"),)))
    with scanmode.evidence_rule(lambda p: None):
        assert "may still enable it" in reverify.reverify(forged, Config())
        user_item = CleanableItem(
            cleaner_id="stale_services", description="d", size=0, kind=ItemKind.PATH,
            path=str(user_wants / "gone.service"), requires_root=True, report_only=True,
            remedy=forged.remedy)
        assert reverify.reverify(user_item, Config()) == "links for user units are never removed"


# --------------------------------------------------------------------------
# M1: user-steerable absence evidence in helper scans
# --------------------------------------------------------------------------
def _home_rule(env):
    homes = str(env.root / "home")

    def rule(path):
        return "is writable by an ordinary user" if path.startswith(homes) else None

    return rule


def _launcher_paths(env):
    return {i.path for i in stale_launchers.StaleDesktopEntryReporter(Config()).scan().items}


def test_stale_launcher_target_in_user_writable_parent_is_unknown(orphan_env):
    env = orphan_env
    in_home = put(env.root, "usr/local/share/applications/h.desktop",
                  "[Desktop Entry]\nType=Application\nName=H\nExec=/home/u/bin/tool\n")
    in_usr = put(env.root, "usr/local/share/applications/s.desktop",
                 "[Desktop Entry]\nType=Application\nName=S\nExec=/usr/bin/gone-tool\n")
    (env.root / "home" / "u").mkdir(parents=True)
    (env.root / "usr" / "bin").mkdir(parents=True)
    # ordinary scan: both programs are missing -> both reported (unchanged)
    assert {str(in_home), str(in_usr)} <= _launcher_paths(env)
    # helper scan: a program under a user-writable folder is unknown
    with scanmode.helper_mode(), scanmode.evidence_rule(_home_rule(env)):
        got = _launcher_paths(env)
    assert str(in_home) not in got and str(in_usr) in got
    # helper scan with no rule registered: every absence is unknown
    with scanmode.helper_mode():
        assert not ({str(in_home), str(in_usr)} & _launcher_paths(env))


@posix_only
def test_wants_link_target_in_home_is_unknown(orphan_env):
    env = orphan_env
    wants = env.root / "etc/systemd/system/default.target.wants"
    wants.mkdir(parents=True)
    os.symlink("/home/u/.config/systemd/user/x.service", str(wants / "x.service"))
    os.symlink("../../../../home/u/y.service", str(wants / "y.service"))  # relative
    os.symlink("/usr/lib/systemd/system/gone.service", str(wants / "gone.service"))
    (env.root / "usr/lib/systemd/system").mkdir(parents=True)
    (env.root / "home" / "u").mkdir(parents=True)

    def names():
        return {Path(i.path).name
                for i in stale_services.StaleSystemdUnitReporter(Config()).scan().items}

    assert {"x.service", "y.service", "gone.service"} <= names()
    seen = []
    rule = _home_rule(env)

    def spy(path):
        seen.append(path)
        return rule(os.path.normpath(path))

    with scanmode.helper_mode(), scanmode.evidence_rule(spy):
        got = names()
    assert "x.service" not in got and "y.service" not in got and "gone.service" in got
    assert str(env.root / "usr/lib/systemd/system/gone.service") in seen


def _st(mode, uid=0, gid=0, dev=1, ino=1):
    return os.stat_result((mode, ino, dev, 1, uid, gid, 0, 0, 0, 0))


DIR = stat.S_IFDIR | 0o755
REAL_ACL_PROBLEM = elevated._acl_problem
LNK = stat.S_IFLNK | 0o777


@pytest.fixture
def fake_fs(monkeypatch):
    """A fake filesystem for the helper's lstat-based rules (any OS)."""
    table = {}

    def lstat(path):
        p = str(path).replace("\\", "/")
        v = table.get(p)
        if v is None:
            raise FileNotFoundError(errno.ENOENT, "no such file", p)
        if isinstance(v, OSError):
            raise v
        return v

    monkeypatch.setattr(elevated, "_lstat", lstat)
    monkeypatch.setattr(elevated, "_acl_problem", lambda path: None)
    monkeypatch.setattr(elevated, "_human_uid_min", lambda: 1000)
    return table


def test_evidence_rule_judges_the_whole_chain(fake_fs):
    fake_fs.update({"/": _st(DIR), "/usr": _st(DIR), "/usr/bin": _st(DIR),
                    "/home": _st(DIR), "/home/u": _st(DIR, uid=1000, gid=1000),
                    "/tmp": _st(stat.S_IFDIR | 0o1777), "/lib": _st(LNK),
                    "/usr/bin/dangling": _st(LNK), "/etc": _st(DIR),
                    "/etc/x.wants": _st(DIR), "/opt": _st(stat.S_IFDIR | 0o775, gid=1000)})
    ev = elevated._evidence_problem
    assert ev("/usr/bin/gone", 1000, frozenset()) is None
    assert ev("/home/linuxbrew/.linuxbrew/bin/x", 1000, frozenset()) is None  # trusted absence
    assert "non-system user" in ev("/home/u/bin/tool", 1000, frozenset())
    assert "writable by everyone" in ev("/tmp/x", 1000, frozenset())  # sticky is not enough
    assert "symbolic link" in ev("/lib/systemd/system/x.service", 1000, frozenset())
    assert "symbolic link" in ev("/usr/bin/dangling", 1000, frozenset())
    assert "non-system group" in ev("/opt/x", 1000, frozenset())
    assert ev("/etc/x.wants/../gone.service", 1000, frozenset()) is None
    assert "non-system user" in ev("/etc/x.wants/../../home/u/y", 1000, frozenset())
    assert ev("relative/path", 1000, frozenset()) is not None
    fake_fs["/usr"] = PermissionError(errno.EACCES, "denied")
    assert "cannot be inspected" in ev("/usr/bin/gone", 1000, frozenset())


def test_evidence_rule_refuses_an_acl_on_the_chain(fake_fs, monkeypatch):
    fake_fs.update({"/": _st(DIR), "/usr": _st(DIR), "/usr/bin": _st(DIR)})
    monkeypatch.setattr(elevated, "_acl_problem",
                        lambda p: "carries an access control list" if p == "/usr" else None)
    assert "access control list" in elevated._evidence_problem("/usr/bin/x", 1000, frozenset())


# --------------------------------------------------------------------------
# M2: the root quarantine under another spelling (case-insensitive volume)
# --------------------------------------------------------------------------
MAC_ROOTS = {"orphan_app_data": ("/Library/Application Support", "/Library/Preferences")}
MAC_NEVER = ("/Library/Application Support/Cleanix",
             "/Library/Application Support/Cleanix/quarantine")


def test_macos_case_collision_with_quarantine_refused(monkeypatch):
    # lexical: another case of the helper's folder is still the helper's folder
    for path in ("/Library/Application Support/cleanix",
                 "/Library/Application Support/CLEANIX",
                 "/Library/Application Support/cleanix/QUARANTINE/run/files/0__x"):
        assert elevate.finding_path_problem("orphan_app_data", path, MAC_ROOTS, MAC_NEVER)
        # the old, case-sensitive comparison let these through
        assert elevate.finding_path_problem("orphan_app_data", path, MAC_ROOTS, MAC_NEVER,
                                            fold=False) is None
    assert elevate.finding_path_problem(
        "orphan_app_data", "/Library/Application Support/com.gone.App", MAC_ROOTS,
        MAC_NEVER) is None

    # by identity: a fake case-insensitive filesystem layer (inode compare)
    inodes = {"/": 2, "/library": 10, "/library/application support": 11,
              "/library/application support/cleanix": 12,
              "/library/application support/cleanix/quarantine": 13,
              "/library/application support/cleanix/quarantine/run": 14,
              "/library/application support/cleanix/quarantine/run/x": 15,
              "/library/application support/com.gone.app": 20}

    def lstat(path):
        key = str(path).replace("\\", "/").casefold()
        if key not in inodes:
            raise FileNotFoundError(path)
        return _st(DIR, dev=7, ino=inodes[key])

    monkeypatch.setattr(elevated, "_lstat", lstat)
    monkeypatch.setattr(elevated, "_root_quarantine_location",
                        lambda: ("/Library/Application Support", ("Cleanix", "quarantine")))
    alias = elevated._quarantine_alias_problem
    assert "is the administrator quarantine" in alias("/Library/Application Support/cleanix")
    assert "is the administrator quarantine" in alias(
        "/Library/Application Support/CLEANIX/Quarantine")
    assert "inside the administrator quarantine" in alias(
        "/Library/Application Support/cleanix/QUARANTINE/run/x")
    assert "folder containing it" in alias("/LIBRARY")
    assert alias("/Library/Application Support/com.gone.App") is None

    # an uninspectable helper folder refuses; a missing one protects nothing
    def broken(path):
        if str(path).replace("\\", "/").casefold().endswith("/cleanix"):
            raise PermissionError(path)
        return lstat(path)

    monkeypatch.setattr(elevated, "_lstat", broken)
    assert "cannot be inspected" in alias("/Library/Application Support/com.gone.App")
    del inodes["/library/application support/cleanix"]
    del inodes["/library/application support/cleanix/quarantine"]
    monkeypatch.setattr(elevated, "_lstat", lstat)
    assert alias("/Library/Application Support/com.gone.App") is None


# --------------------------------------------------------------------------
# M3: access control lists on the chain
# --------------------------------------------------------------------------
def test_acl_component_refused(monkeypatch):
    attrs = {"/a/acl": ["user.x", "system.posix_acl_access"],
             "/a/default": ["system.posix_acl_default"],
             "/a/nfs": ["system.nfs4_acl"], "/a/plain": ["user.comment", "security.selinux"]}

    def lister(path):
        v = attrs.get(path)
        if isinstance(v, OSError):
            raise v
        return v if v is not None else []

    monkeypatch.setattr(elevated, "_acl_os", lambda: "linux")
    monkeypatch.setattr(elevated, "_list_xattrs", lister)
    for p in ("/a/acl", "/a/default", "/a/nfs"):
        assert elevated._acl_problem(p) == "carries an access control list"
    assert elevated._acl_problem("/a/plain") is None
    # unreadable xattrs refuse; a filesystem without xattr support cannot hold one
    attrs["/a/denied"] = OSError(errno.EACCES, "denied")
    assert "cannot be read" in elevated._acl_problem("/a/denied")
    attrs["/a/nosup"] = OSError(errno.EOPNOTSUPP, "not supported")
    assert elevated._acl_problem("/a/nosup") is None

    def no_api(path):
        raise AttributeError("listxattr")

    monkeypatch.setattr(elevated, "_list_xattrs", no_api)
    assert "cannot be checked" in elevated._acl_problem("/a/plain")

    # macOS: extended ACL entries refuse, and so does not being able to tell
    monkeypatch.setattr(elevated, "_acl_os", lambda: "darwin")
    for answer, expected in ((True, "carries an access control list"),
                             (None, "cannot be checked for an access control list"),
                             (False, None)):
        monkeypatch.setattr(elevated, "_macos_has_acl", lambda p, a=answer: a)
        assert elevated._acl_problem("/Library") == expected
    # anything else: refused (cannot tell)
    monkeypatch.setattr(elevated, "_acl_os", lambda: "freebsd13")
    assert "cannot be checked" in elevated._acl_problem("/usr")


@posix_only
def test_acl_on_the_parent_chain_refuses_the_item(fake_fs, monkeypatch):
    fake_fs.update({"/": _st(DIR), "/a": _st(DIR), "/a/b": _st(DIR), "/a/b/c": _st(DIR)})
    monkeypatch.setattr(elevated, "_acl_problem", REAL_ACL_PROBLEM)
    monkeypatch.setattr(elevated, "_acl_os", lambda: "linux")
    monkeypatch.setattr(elevated, "_list_xattrs",
                        lambda p: ["system.posix_acl_default"] if p == "/a/b" else [])
    assert elevated._path_chain_problem("/a/b/c/item", 1000, frozenset()) is None
    got = elevated._path_chain_problem("/a/b/c/item", 1000, frozenset(), acls=True)
    assert got == "/a/b carries an access control list"

    def unreadable(p):
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr(elevated, "_list_xattrs", unreadable)
    assert "cannot be read" in elevated._path_chain_problem("/a/b/c/item", 1000,
                                                             frozenset(), acls=True)


# --------------------------------------------------------------------------
# M8: long names in the quarantine
# --------------------------------------------------------------------------
def test_long_name_quarantined_with_deterministic_short_name(tmp_path, monkeypatch):
    assert quarantine.stored_name(3, "file.txt") == "3__file.txt"  # unchanged
    name = "a" * 255
    got = quarantine.stored_name(0, name)
    assert len(os.fsencode(got)) <= quarantine.MAX_STORED_NAME_BYTES < 255
    assert got == quarantine.stored_name(0, name)  # deterministic
    assert got.startswith("0__") and got != quarantine.stored_name(0, "a" * 254 + "b")
    assert quarantine.stored_name(12, name).startswith("12__")
    wide = "é" * 120  # 240 bytes in UTF-8: cut on a character boundary
    short = quarantine.stored_name(1, wide)
    assert len(os.fsencode(short)) <= quarantine.MAX_STORED_NAME_BYTES
    assert short.endswith("é") and os.fsdecode(os.fsencode(short)) == short

    if not POSIX:
        return
    # end to end (root-mode store and the ordinary store): a 255-byte name
    for root_mode in (True, False):
        base = tmp_path / ("root" if root_mode else "user")
        base.mkdir()
        src = base / name
        src.write_text("long")
        qroot = base / "q"
        qroot.mkdir()
        if root_mode:
            q = quarantine.Quarantine("run1", root=qroot)
        else:  # the ordinary (per-user) store path
            monkeypatch.setattr(quarantine, "quarantine_root", lambda: qroot)
            q = quarantine.Quarantine("run1")
        q.store(src)
        q.save()
        (entry,) = q.items
        assert Path(entry["stored"]).name == quarantine.stored_name(0, name)
        assert Path(entry["stored"]).read_text() == "long" and not src.exists()
        assert entry["name"] == name and entry["original"] == str(src)
        manifest = json.loads((qroot / "run1" / "manifest.json").read_text())
        assert manifest["items"][0]["name"] == name


# --------------------------------------------------------------------------
# carry-overs: rename exceptions, mount table
# --------------------------------------------------------------------------
@posix_only
def test_rename_exception_does_not_drop_a_real_move(tmp_path, monkeypatch):
    qroot = tmp_path / "q"
    qroot.mkdir()
    src = tmp_path / "item"
    src.write_text("data")
    real = quarantine._rename

    def rename_then_interrupt(a, b):
        real(a, b)
        raise KeyboardInterrupt  # asynchronous: arrives after the move

    monkeypatch.setattr(quarantine, "_rename", rename_then_interrupt)
    q = quarantine.Quarantine("run1", root=qroot)
    with pytest.raises(KeyboardInterrupt):
        q.store(src)
    manifest = json.loads((qroot / "run1" / "manifest.json").read_text())
    (entry,) = manifest["items"]
    assert entry["original"] == str(src) and Path(entry["stored"]).read_text() == "data"
    assert not src.exists()

    # a failed rename (OSError: nothing moved) still drops its entry
    src2 = tmp_path / "item2"
    src2.write_text("two")

    def failing(a, b):
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(quarantine, "_rename", failing)
    with pytest.raises(PermissionError):
        q.store(src2)
    manifest = json.loads((qroot / "run1" / "manifest.json").read_text())
    assert [i["original"] for i in manifest["items"]] == [str(src)] and src2.exists()


def test_mountinfo_requires_root_entry(tmp_path, monkeypatch):
    root = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
    other = "36 35 98:0 / /mnt/x rw - tmpfs tmpfs rw\n"
    assert root_delete.parse_mountinfo("") is None
    assert root_delete.parse_mountinfo("\n\n") is None
    assert root_delete.parse_mountinfo(other) is None  # no "/" entry
    assert root_delete.parse_mountinfo(root + other) == ["/", "/mnt/x"]
    item = tmp_path / "item"
    item.write_text("x")
    monkeypatch.setattr(root_delete, "_linux", lambda: True)
    monkeypatch.setattr(root_delete, "_read_mountinfo", lambda: other)
    assert root_delete.mount_problem(str(item), permanent=True) == \
        "the mount table could not be read"
    monkeypatch.setattr(root_delete, "_read_mountinfo", lambda: "")
    assert root_delete.mount_problem(str(item), permanent=True) == \
        "the mount table could not be read"
    monkeypatch.setattr(root_delete, "_read_mountinfo", lambda: root + other)
    assert root_delete.mount_problem(str(item), permanent=True) is None


def test_mountinfo_truncated_refused(tmp_path, monkeypatch):
    table = tmp_path / "mountinfo"
    text = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n" * 4
    table.write_bytes(text.encode("ascii"))
    monkeypatch.setattr(root_delete, "MOUNTINFO", str(table))
    monkeypatch.setattr(root_delete, "MAX_MOUNTINFO_BYTES", len(text))
    assert root_delete._read_mountinfo() == text  # exactly at the cap: complete
    monkeypatch.setattr(root_delete, "MAX_MOUNTINFO_BYTES", len(text) - 1)
    assert root_delete._read_mountinfo() is None  # longer than the cap: truncated
    item = tmp_path / "item"
    item.write_text("x")
    monkeypatch.setattr(root_delete, "_linux", lambda: True)
    assert root_delete.mount_problem(str(item), permanent=False) == \
        "the mount table could not be read"
