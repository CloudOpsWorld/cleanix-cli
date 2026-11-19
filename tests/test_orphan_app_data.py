"""orphan_app_data: macOS data folders of removed apps (report only)."""

from __future__ import annotations

import os
import plistlib
import shlex
import sys
import time
from pathlib import Path

import pytest

from cleanix.cleaners import base, orphan_app_data as oad, orphan_common as oc
from cleanix.config import Config

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="needs POSIX symlinks/paths"
)

MDFIND = ("mdfind", "kMDItemContentType == 'com.apple.application-bundle'")
OLD_DAYS = 40


def _plist(path: Path, data, fmt=plistlib.FMT_BINARY) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        plistlib.dump(data, fh, fmt=fmt)
    return path


def _app(base_dir: Path, name: str, bundle_id: str) -> Path:
    app = base_dir / name
    _plist(app / "Contents" / "Info.plist", {"CFBundleIdentifier": bundle_id})
    return app


def _age(path: Path, days: float = OLD_DAYS) -> Path:
    t = time.time() - days * 86400
    os.utime(path, (t, t))
    return path


def _old_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "data.bin").write_text("x" * 100)
    _age(path / "data.bin")
    return _age(path)


def _old_file(path: Path) -> Path:
    _plist(path, {"k": "v"})
    return _age(path)


def _fillers(env, n, start=0):
    for k in range(start, start + n):
        _app(env.root / "Applications", f"Filler{k}.app", f"com.filler{k}.app")


@pytest.fixture
def mac(orphan_env):
    """Fake Mac: Acme Editor (+ nested helper) installed, all roots present."""
    env = orphan_env
    apps = env.root / "Applications"
    acme = _app(apps, "Acme Editor.app", "com.acme.Editor")
    _app(acme / "Contents" / "Library" / "LoginItems", "Helper.app", "com.helperco.agent")
    _fillers(env, 4)  # the inventory needs >= 5 apps with a readable id
    env.support = env.home / "Library" / "Application Support"
    env.prefs = env.home / "Library" / "Preferences"
    env.containers = env.home / "Library" / "Containers"
    for d in (env.support, env.prefs, env.containers):
        d.mkdir(parents=True)
    return env


def _scan(cfg=None):
    return oad.OrphanAppDataReporter(cfg or Config()).scan().items


def _reported(items):
    return [i for i in items if i.description.startswith("Left by a removed app")]


def _ids(items):
    return {i.description.split(": ", 1)[1].split(" (", 1)[0] for i in _reported(items)}


def _notes(items):
    return [i for i in items if i.description.startswith("Not checked")]


def test_attributes():
    c = oad.OrphanAppDataReporter
    assert c.id == "orphan_app_data"
    assert c.name == "Data of removed apps"
    assert c.description == (
        "Application Support, Preferences and Containers entries of apps "
        "that are no longer installed (report only)"
    )
    assert "macos" in str(c.platforms).lower()
    assert c.requires_root is False
    assert c.scope == base.SCOPE_USER


def test_candidate_id():
    f = oad.candidate_id
    assert f("com.oldvendor.OldApp") == "com.oldvendor.OldApp"
    assert f("com.oldvendor.OldApp.plist") == "com.oldvendor.OldApp"
    assert f("group.com.acme.x") == "com.acme.x"
    assert f("ABCDE12345.com.acme.shared") == "com.acme.shared"
    assert f("Slack") is None
    assert f("Google") is None
    assert f("Adobe.Photoshop") is None  # two labels only
    assert f("Adobe.Photoshop.2020") is None  # not reverse-DNS (capitalised)
    assert f("com.foo") is None
    assert f("com.foo bar.baz") is None
    assert f("Some App.Thing.Else") is None


def test_vendor_key():
    assert oad.vendor_key("com.Acme.Editor.helper") == "com.acme"
    assert oad.vendor_key("com.github.Alice.ToolA") == "com.github.alice"
    assert oad.vendor_key("io.gitlab.bob.x") == "io.gitlab.bob"
    assert oad.vendor_key("net.sourceforge.proj.x") == "net.sourceforge.proj"
    assert oad.vendor_key("solo") == "solo"


def test_is_excluded_rules():
    inst = {"com.acme.Editor", "com.github.alice.ToolA"}
    ex = oad.is_excluded
    assert ex("com.apple.Safari", inst)
    assert ex(".GlobalPreferences", inst)
    assert ex("loginwindow", inst) and ex("pbs", inst)
    assert ex("com.acme.Editor", inst)
    assert ex("COM.ACME.EDITOR", inst)
    assert ex("com.acme.Editor.helper", inst)  # extends an installed id
    assert ex("com.acme.Other", inst)  # same vendor
    assert ex("com.github.alice.ToolB", inst)
    assert not ex("com.github.bob.ToolB", inst)
    assert not ex("com.other.App", inst)


def test_installed_ids(mac):
    ag = mac.home / "Library" / "LaunchAgents"
    ag.mkdir(parents=True)
    (ag / "com.agentco.job.plist").write_text("x")
    (mac.root / "Library" / "LaunchDaemons").mkdir(parents=True)
    (mac.root / "Library" / "LaunchDaemons" / "com.daemonco.d.plist").write_text("x")
    mac.cmds.on(("pkgutil", "--pkgs"), 0, "com.pkgco.installer\n\n")
    ids = oad.installed_ids(mac.root, mac.home)
    assert {"com.acme.Editor", "com.helperco.agent", "com.agentco.job",
            "com.daemonco.d", "com.pkgco.installer"} <= ids


def test_installed_ids_other_locations_and_bundles(mac):
    _app(mac.root / "System" / "Applications", "Sys.app", "com.sysco.sys")
    _app(mac.home / "Applications", "Mine.app", "com.mine.app")
    _app(mac.root / "Applications" / "Setapp", "SA.app", "com.setapp.sa")
    host = mac.root / "Applications" / "Host.app"
    _app(host / "Contents" / "PlugIns", "Ext.appex", "com.hostco.host.ext")
    _app(host / "Contents" / "XPCServices", "Svc.xpc", "com.xpcco.svc")
    _plist(host / "Contents" / "Info.plist", {"CFBundleIdentifier": "com.hostco.host"})
    ids = oad.installed_ids(mac.root, mac.home)
    assert {"com.sysco.sys", "com.mine.app", "com.setapp.sa", "com.hostco.host",
            "com.hostco.host.ext", "com.xpcco.svc"} <= ids


def test_broken_plist_app_protected_by_name(mac):
    _fillers(mac, 10, start=10)  # keep the no-id share under 10%
    bad = mac.root / "Applications" / "Bad Thing.app" / "Contents"
    bad.mkdir(parents=True)
    (bad / "Info.plist").write_text("not a plist")
    assert "com.acme.Editor" in oad.installed_ids(mac.root, mac.home)
    _old_dir(mac.support / "com.unknownvendor.BadThing")
    _old_dir(mac.support / "com.unknownvendor.Other")
    assert _ids(_scan()) == {"com.unknownvendor.Other"}


def test_bare_app_without_plist_protected_by_name(mac):
    _fillers(mac, 10, start=10)
    (mac.root / "Applications" / "Bare.app").mkdir()
    _old_dir(mac.support / "com.bare.Bare.cache")
    _old_dir(mac.support / "com.zzz.bare")
    _old_dir(mac.support / "com.zzz.Other")
    assert _ids(_scan()) == {"com.zzz.Other"}


def test_too_many_unreadable_apps_means_not_checked(mac):
    for n in range(4):
        (mac.root / "Applications" / f"Bare{n}.app").mkdir()
    _old_dir(mac.support / "com.oldvendor.OldApp")
    items = _scan()
    assert _reported(items) == [] and len(_notes(items)) == 1


def test_ios_wrapper_app_id_collected(mac):
    wrap = mac.root / "Applications" / "Foo.app" / "Wrapper"
    _plist(wrap / "Foo.app" / "Info.plist", {"CFBundleIdentifier": "com.wrapco.foo"})
    assert "com.wrapco.foo" in oad.installed_ids(mac.root, mac.home)
    _old_dir(mac.support / "com.wrapco.foo.data")
    assert _reported(_scan()) == []


def test_unusable_inventory_with_launch_jobs_and_pkgs_reports_nothing(orphan_env):
    env = orphan_env
    (env.root / "Applications").mkdir()
    ag = env.home / "Library" / "LaunchAgents"
    ag.mkdir(parents=True)
    for n in range(8):
        (ag / f"com.job{n}.x.plist").write_text("x")
    env.cmds.on(("pkgutil", "--pkgs"), 0, chr(10).join(f"com.pkg{n}.i" for n in range(8)))
    _old_dir(env.home / "Library" / "Application Support" / "com.oldvendor.OldApp")
    items = _scan()
    assert _reported(items) == [] and len(_notes(items)) == 1


def test_inventory_needs_five_apps(orphan_env):
    env = orphan_env
    _fillers(env, 4)
    _old_dir(env.home / "Library" / "Application Support" / "com.oldvendor.OldApp")
    items = _scan()
    assert _reported(items) == [] and len(_notes(items)) == 1
    _fillers(env, 1, start=4)
    assert _ids(_scan()) == {"com.oldvendor.OldApp"}


def test_union_over_all_target_users(mac, monkeypatch):
    from cleanix.core import context

    home2 = mac.root.parent / "home" / "v"
    (home2 / "Library").mkdir(parents=True)
    _app(home2 / "Applications", "Second.app", "com.second.App")
    ag = home2 / "Library" / "LaunchAgents"
    ag.mkdir()
    (ag / "com.agent2.job.plist").write_text("x")
    users = [context.TargetUser("u", mac.home, 1000, 1000, True),
             context.TargetUser("v", home2, 1001, 1001, False)]
    monkeypatch.setattr(context, "_cached_targets", users)
    _old_dir(mac.support / "com.second.Data")
    _old_dir(mac.support / "com.agent2.data")
    _old_dir(mac.support / "com.oldvendor.OldApp")
    assert _ids(_scan()) == {"com.oldvendor.OldApp"}


def test_directory_with_recent_child_is_not_old(mac):
    d = _old_dir(mac.support / "com.oldvendor.Active")
    (d / "fresh.db").write_text("x")  # touched just now
    _age(d)
    assert _reported(_scan()) == []


@pytest.mark.parametrize("name", [
    "org.cups.cupsd", "edu.mit.Kerberos", "org.gnu.emacs",
    "org.freedesktop.dbus", "org.x.startx", "ORG.GNU.Emacs",
])
def test_os_cli_deny_prefixes(mac, name):
    _old_dir(mac.support / name)
    assert _reported(_scan()) == []


def test_prefix_rule_alone():
    idx = oad._Index({"com.x.y.z"})
    assert "com.x.y" in idx.prefixes
    assert oad.is_excluded("com.x.y", {"com.x.y.z"})
    assert oad.is_excluded("com.x.y.z.extra", {"com.x.y.z"})


def test_expired_budget_during_inventory_is_not_checked(mac):
    _old_dir(mac.support / "com.oldvendor.OldApp")
    cfg = Config()
    cfg.orphan_max_seconds = 0
    items = _scan(cfg)
    assert _reported(items) == [] and len(_notes(items)) == 1


def test_reports_old_app_data(mac):
    _old_dir(mac.support / "com.oldvendor.OldApp")
    _old_file(mac.prefs / "com.oldvendor.OldApp.plist")
    items = _reported(_scan())
    assert len(items) == 2
    assert {Path(i.path) for i in items} == {
        mac.support / "com.oldvendor.OldApp",
        mac.prefs / "com.oldvendor.OldApp.plist",
    }
    for it in items:
        assert it.report_only and it.hint and it.requires_root is False
        assert it.description.startswith("Left by a removed app: com.oldvendor.OldApp (")
    sized = [i for i in items if i.path.endswith("OldApp")][0]
    assert sized.size > 0
    hint = sized.hint
    assert "No installed app uses the id com.oldvendor.OldApp." in hint
    assert "mdfind \"kMDItemCFBundleIdentifier == 'com.oldvendor.OldApp'\"" in hint
    assert "Trash" in hint
    for bad in ("*", "xargs", "-rf", "rm "):
        assert bad not in hint


def test_container_reported(mac):
    _old_dir(mac.containers / "com.oldvendor.Boxed")
    assert _ids(_scan()) == {"com.oldvendor.Boxed"}


def test_system_roots_reported_requires_root(mac):
    _old_dir(mac.root / "Library" / "Application Support" / "com.sysold.Thing")
    _old_file(mac.root / "Library" / "Preferences" / "com.sysold.Thing.plist")
    items = _reported(_scan())
    assert len(items) == 2
    assert all(i.requires_root is True for i in items)
    assert all("(/Library/" in i.description for i in items)


def test_false_positives(mac):
    s, p = mac.support, mac.prefs
    _old_file(p / "com.apple.Safari.plist")
    _old_dir(s / "com.apple.Safari")
    _old_dir(s / "com.acme.Editor.helper")
    _old_dir(s / "com.acme.Updater")
    _old_dir(s / "ABCDE12345.com.acme.shared")
    _old_dir(s / "group.com.acme.x")
    _old_dir(s / "group.com.apple.notes")
    _old_dir(s / "com.helperco.agent.data")
    _old_dir(s / "Google")
    _old_dir(s / "Slack")
    fresh = s / "com.old.thing"
    fresh.mkdir()
    _age(fresh, 2)
    # id known only as a launchd label
    ag = mac.home / "Library" / "LaunchAgents"
    ag.mkdir(parents=True)
    (ag / "com.launchonly.svc.plist").write_text("x")
    _old_dir(s / "com.launchonly.svc")
    # id known only from pkgutil
    mac.cmds.on(("pkgutil", "--pkgs"), 0, "com.pkgonly.inst\n")
    _old_dir(s / "com.pkgonly.inst")
    # app known only via mdfind, outside the standard folders
    x = _app(mac.root / "opt" / "Apps", "X.app", "com.mdonly.X")
    mac.cmds.on(MDFIND, 0, f"{x}\n")
    _old_dir(s / "com.mdonly.X")
    # never-scanned folders
    _old_dir(mac.home / "Library" / "Caches" / "com.cacheold.thing")
    _old_dir(mac.home / "Library" / "Saved Application State"
             / "com.savedold.thing.savedState")
    _old_dir(mac.home / "Library" / "Group Containers" / "group.com.gcold.thing")
    assert _reported(_scan()) == []


def test_mdfind_failure_is_not_fatal(mac):
    mac.cmds.on(MDFIND, 124, "", "")
    _old_dir(mac.support / "com.oldvendor.OldApp")
    assert _ids(_scan()) == {"com.oldvendor.OldApp"}


def test_shared_host_vendor_rule(mac):
    _app(mac.root / "Applications", "ToolA.app", "com.github.alice.ToolA")
    _old_dir(mac.support / "com.github.alice.ToolA.cfg")
    _old_dir(mac.support / "com.github.bob.ToolB")
    assert _ids(_scan()) == {"com.github.bob.ToolB"}


def test_applications_unreadable_reports_only_note(mac, monkeypatch):
    _old_dir(mac.support / "com.oldvendor.OldApp")
    real = oc.list_dir
    apps = mac.root / "Applications"
    monkeypatch.setattr(
        oc, "list_dir", lambda p: None if Path(p) == apps else real(p)
    )
    items = _scan()
    assert _reported(items) == []
    notes = _notes(items)
    assert len(notes) == 1
    assert notes[0].size == 0 and notes[0].report_only and notes[0].hint


def test_no_applications_folder_reports_nothing(orphan_env):
    support = orphan_env.home / "Library" / "Application Support"
    _old_dir(support / "com.oldvendor.OldApp")
    items = _scan()
    assert _reported(items) == []
    assert len(_notes(items)) == 1


def test_containers_without_fda_yields_note(mac, monkeypatch):
    _old_dir(mac.support / "com.oldvendor.OldApp")
    real = oc.list_dir
    monkeypatch.setattr(
        oc, "list_dir", lambda p: None if Path(p) == mac.containers else real(p)
    )
    items = _scan()
    assert _ids(items) == {"com.oldvendor.OldApp"}  # other roots still reported
    notes = _notes(items)
    assert len(notes) == 1
    assert notes[0].description == (
        "Not checked: macOS needs Full Disk Access to list "
        f"{oc.logical_path(mac.root, mac.containers)}"
    )
    assert notes[0].size == 0


def test_hint_quotes_path_with_space(mac):
    d = _old_dir(mac.support / "com.oldvendor.OldApp")
    (it,) = _reported(_scan())
    q = shlex.quote(oc.logical_path(mac.root, d))
    assert q.startswith("'") and "Application Support" in q  # space => quoted
    assert f"move {q} to the Trash in Finder." in it.hint


def test_files_in_support_and_dirs_in_prefs_ignored(mac):
    (mac.support / "com.oldvendor.file").write_text("x")
    _age(mac.support / "com.oldvendor.file")
    _old_dir(mac.prefs / "com.oldvendor.dir.plist")
    _old_dir(mac.prefs / "ByHost")
    assert _reported(_scan()) == []


def test_min_age_is_configurable(mac):
    d = mac.support / "com.oldvendor.Recent"
    d.mkdir()
    _age(d, 10)
    assert _reported(_scan()) == []
    cfg = Config()
    cfg.orphan_min_age_days = 5
    assert _ids(_scan(cfg)) == {"com.oldvendor.Recent"}


@posix_only
def test_symlinked_entries_skipped(mac):
    target = mac.root / "elsewhere"
    target.mkdir()
    for link in (mac.support / "com.oldvendor.Linked",
                 mac.prefs / "com.oldvendor.Linked.plist"):
        # relative target that stays inside the fake sysroot
        os.symlink(os.path.relpath(target, link.parent), link)
    assert _reported(_scan()) == []


def test_budget_limits_results(mac):
    for n in range(5):
        _old_dir(mac.support / f"com.oldvendor.App{n}")
    cfg = Config()
    cfg.orphan_max_items = 2
    items = _scan(cfg)
    assert len(_reported(items)) == 2
    assert any("Scan stopped early" in i.description for i in items)
