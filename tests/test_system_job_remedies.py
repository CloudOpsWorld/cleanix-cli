"""Task 9b: system-wide launch jobs, systemd units and package receipts.

The mutating system-scope allowlist and its gates, the structural act-time
check (``system_remedy.check``), the detectors' scan-time remedies and
act-time re-verifiers (strict evidence), the stop/forget steps, the result
schema, and the strict app-inventory carry-over.

Hermetic: fake sysroots (``orphan_env``), fake package tools behind
``orphan_common.run_command``, a recording ``remedy_exec.runner`` (nothing
is ever executed; ``_spawn`` fails the test if reached). Argv, parsing and
logic tests run on every OS; tests that need POSIX file modes, owners or
symlinks are skipped on Windows. The helper end-to-end runs are in
test_elevated_findings.py.
"""

from __future__ import annotations

import json
import os
import plistlib
import sys
from pathlib import Path

import pytest

from cleanix import elevated
from cleanix.cleaners import orphan_app_data
from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners import orphan_launch_jobs as olj
from cleanix.cleaners import stale_receipts as sr
from cleanix.cleaners import stale_services as ss
from cleanix.config import Config
from cleanix.core import actions, elevate, engine, remedy_exec, reverify, scanmode, system_remedy
from cleanix.core import platform as plat
from cleanix.core.models import CleanableItem, ItemKind
from cleanix.core.remedy import Remedy, RemedyKind, fingerprint_of

POSIX = os.name != "nt"
posix_only = pytest.mark.skipif(not POSIX, reason="needs POSIX modes/owners/symlinks")
UID = os.getuid() if POSIX else 0
LJ, SU, PR = RemedyKind.LAUNCH_JOB, RemedyKind.SYSTEMD_UNIT, RemedyKind.PKG_RECEIPT


# --------------------------------------------------------------------------
# fixtures / helpers
# --------------------------------------------------------------------------
class Recorder:
    """Stands in for ``remedy_exec.runner``; records every argv."""

    def __init__(self):
        self.calls = []
        self.result = (0, "", "")
        self.side_effect = None

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        if self.side_effect is not None:
            out = self.side_effect(list(argv))
            if out is not None:
                return out
        return self.result


class Tools:
    """Fake read-only package tools behind ``oc.run_command``: dpkg (``owned``
    paths are owned; ``rc`` forces an unknown answer) and pkgutil (per id
    ``info`` plist text and ``files`` list)."""

    def __init__(self):
        self.owned = set()
        self.rc = None
        self.pkgs = {}  # id -> (info text, files, files rc)
        self.mdfind = None  # Spotlight's answer (None: not available)
        self.calls = []

    def __call__(self, argv, timeout=120):
        argv = list(argv)
        if argv[:2] == ["env", "LC_ALL=C"]:
            argv = argv[2:]
        self.calls.append(argv)
        if argv[:2] == ["dpkg-query", "-S"]:
            if self.rc is not None:
                return self.rc, "", ""
            out = [f"pkg: {p}" for p in argv[2:] if p in self.owned]
            err = [f"dpkg-query: no path found matching pattern {p}"
                   for p in argv[2:] if p not in self.owned]
            return (1 if err else 0), "\n".join(out), "\n".join(err)
        if argv[:2] == ["dpkg-query", "-W"]:
            return 0, "bash\n", ""
        if argv[:2] == ["pkgutil", "--pkgs"]:
            return 0, "".join(f"{i}\n" for i in self.pkgs), ""
        if argv[:2] == ["pkgutil", "--pkg-info-plist"] and argv[2] in self.pkgs:
            return 0, self.pkgs[argv[2]][0], ""
        if argv[:3] == ["pkgutil", "--only-files", "--files"] and argv[3] in self.pkgs:
            _info, files, rc = self.pkgs[argv[3]]
            return rc, "".join(f"{f}\n" for f in files), ""
        if argv[:1] == ["mdfind"] and self.mdfind is not None:
            return 0, self.mdfind, ""
        return 127, "", "not found"


@pytest.fixture
def env(orphan_env, monkeypatch):
    """A fake sysroot whose files count as root-owned, a recording runner,
    fake package tools and a trusting evidence rule for strict checks."""
    rec = Recorder()
    monkeypatch.setattr(remedy_exec, "runner", rec)

    def no_spawn(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("a real command was about to run")

    monkeypatch.setattr(remedy_exec, "_spawn", no_spawn)
    monkeypatch.setattr(oc, "SYSTEM_FILE_UID", UID)
    tools = Tools()
    monkeypatch.setattr(oc, "run_command", tools)
    orphan_env.cmds.tools |= {"pkgutil", "dpkg-query"}
    orphan_env.rec = rec
    orphan_env.tools = tools
    return orphan_env


def mac(monkeypatch):
    monkeypatch.setattr(plat, "current_os", lambda: plat.MACOS)


def linux(monkeypatch):
    monkeypatch.setattr(plat, "current_os", lambda: plat.LINUX)


def plain(path: Path) -> Path:
    if POSIX:
        os.chmod(str(path), 0o644)
    return path


def daemon(env, name="com.gone.d", label=None, program="/opt/gone/d",
           where="Library/LaunchDaemons", data=None):
    d = env.root / where
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{name}.plist"
    body = data if data is not None else {"Label": label or name,
                                          "ProgramArguments": [program, "-x"]}
    with open(str(p), "wb") as fh:
        plistlib.dump(body, fh)
    return plain(p)


def unit(env, name="gone.service", program="/opt/gone/x", where="etc/systemd/system"):
    d = env.root / where
    d.mkdir(parents=True, exist_ok=True)
    (env.root / "usr/lib/systemd/system").mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(f"[Service]\nExecStart={program}\n\n[Install]\nWantedBy=multi-user.target\n")
    return plain(p)


def receipt(env, pkg_id="com.vendor.gone", files=("Gone.app/Contents/MacOS/gone",
                                                 "Gone.app/Contents/Info.plist"),
            pkgid=None, rc=0, bom=True):
    rd = env.root / "private/var/db/receipts"
    rd.mkdir(parents=True, exist_ok=True)
    p = rd / f"{pkg_id}.plist"
    p.write_text("plist-bytes")
    plain(p)
    if bom:
        b = rd / f"{pkg_id}.bom"
        b.write_text("bom-bytes")
        plain(b)
    info = plistlib.dumps({"pkgid": pkgid or pkg_id, "volume": "/",
                           "install-location": "Applications"}).decode("utf-8")
    env.tools.pkgs[pkg_id] = (info, list(files), rc)
    return p


def scanned(reporter_cls, path):
    items = [i for i in reporter_cls(Config()).scan().items if i.path == str(path)]
    assert len(items) == 1, [i.description for i in items]
    return items[0]


def sys_item(path, kind, name, *, cid=None, fp=None, requires_root=True, group=None,
             extra=None):
    return CleanableItem(
        cleaner_id=cid or system_remedy.SCENARIO[kind], description=str(path), size=0,
        kind=ItemKind.PATH, path=str(path), requires_root=requires_root, report_only=True,
        remedy=Remedy(kind, fp if fp is not None else fingerprint_of(str(path)), group=group,
                      extra=extra if extra is not None else ((system_remedy.KEY[kind], name),)))


def trusted():
    """Strict-evidence re-checks with a rule that trusts every absence."""
    return scanmode.evidence_rule(lambda p: None)


def opened():
    """Both gates of the system scope (helper mode + system_scope)."""
    import contextlib

    stack = contextlib.ExitStack()
    stack.enter_context(scanmode.helper_mode())
    stack.enter_context(remedy_exec.system_scope())
    return stack


# --------------------------------------------------------------------------
# D. the mutating system-scope allowlist
# --------------------------------------------------------------------------
def test_system_argv_shapes_exact():
    assert remedy_exec.system_disable_argv("gone.service") == [
        "systemctl", "disable", "--now", "gone.service"]
    assert remedy_exec.system_disable_argv("tpl@.service") == [
        "systemctl", "disable", "tpl@.service"]
    assert remedy_exec.system_daemon_reload_argv() == ["systemctl", "daemon-reload"]
    assert remedy_exec.forget_argv("com.vendor.gone") == [
        "pkgutil", "--forget", "com.vendor.gone"]
    for argv in (remedy_exec.system_disable_argv("gone.service"),
                 remedy_exec.system_disable_argv("tpl@.service"),
                 remedy_exec.system_daemon_reload_argv(),
                 remedy_exec.forget_argv("com.vendor.gone")):
        assert remedy_exec.system_argv_allowed(argv), argv
        assert not remedy_exec.argv_allowed(argv), argv  # never a user-scope shape
        assert tuple(argv[:3]) in remedy_exec.SYSTEM_MUTATING_COMMANDS or \
            tuple(argv[:2]) in remedy_exec.SYSTEM_MUTATING_COMMANDS
    # the user-scope shapes are not system-scope shapes
    for argv in (remedy_exec.bootout_argv(501, "com.gone.job"),
                 remedy_exec.disable_argv("mine.service"),
                 remedy_exec.daemon_reload_argv()):
        assert remedy_exec.argv_allowed(argv) and not remedy_exec.system_argv_allowed(argv)
    assert remedy_exec.MUTATING_COMMANDS == (remedy_exec.USER_MUTATING_COMMANDS
                                             | remedy_exec.SYSTEM_MUTATING_COMMANDS)


NEAR_MISSES = [
    ["launchctl", "bootout", "system"], ["launchctl", "bootout", "system/"],
    ["launchctl", "bootout", "system", "com.gone.d"],
    ["launchctl", "bootout", "system/com.gone.d", "extra"],
    ["launchctl", "bootout", "system/com.apple.foo"], ["launchctl", "bootout", "system/-x"],
    ["launchctl", "bootout", "system/--user"], ["launchctl", "bootout", "system/a b"],
    ["launchctl", "bootout", "system/a\nb"], ["launchctl", "bootout", "system/a/b"],
    ["launchctl", "bootout", "system/a..b"], ["launchctl", "bootout", "system/" + "a" * 300],
    ["launchctl", "bootout", "system/café"], ["launchctl", "bootout", "gui/501/com.x"],
    ["launchctl", "bootout", "user/501/com.x"], ["launchctl", "bootstrap", "system/com.x"],
    ["launchctl", "remove", "com.x"], ["launchctl", "bootout", "System/com.x"],
    ["systemctl", "disable", "--now", "x@.service"], ["systemctl", "disable", "x.service"],
    ["systemctl", "--user", "disable", "--now", "x.service"],
    ["systemctl", "disable", "--now", "--user", "x.service"],
    ["systemctl", "disable", "--now", "x.service", "--user"],
    ["systemctl", "disable", "--now", "x.service", "y.service"],
    ["systemctl", "disable", "--now", "-x.service"], ["systemctl", "disable", "--now", "x.socket"],
    ["systemctl", "disable", "--now", ".service"], ["systemctl", "enable", "--now", "x.service"],
    ["systemctl", "daemon-reload", "--user"], ["systemctl", "--user", "daemon-reload"],
    ["systemctl", "disable", "--now", "../x.service"],
    ["systemctl", "disable", "--now", "a/b.service"], ["systemctl", "stop", "x.service"],
    ["systemctl", "disable", "--now", "x.service\n"], ["systemctl", "mask", "x.service"],
    ["systemctl", "disable", "--now", "--root=/", "x.service"],
    ["pkgutil", "--forget"], ["pkgutil", "--forget", "com.apple.pkg.Core"],
    ["pkgutil", "--forget", "-x"], ["pkgutil", "--forget", "--volume"],
    ["pkgutil", "--forget", "a", "b"], ["pkgutil", "--forget", "a b"],
    ["pkgutil", "--forget", "a\n"], ["pkgutil", "--forget", "a/b"],
    ["pkgutil", "--forget", "a..b"], ["pkgutil", "--forget", "a@b"],
    ["pkgutil", "--forget", "a:b"], ["pkgutil", "--forget", "x" * 300],
    ["pkgutil", "--forget", "café.pkg"], ["pkgutil", "--forget", ""],
    ["pkgutil", "--unlink", "com.x"], ["pkgutil", "--volume", "/", "--forget", "com.x"],
    ["env", "pkgutil", "--forget", "com.x"], [], ["launchctl"],
]


@pytest.mark.parametrize("argv", NEAR_MISSES)
def test_system_argv_near_misses_refused(argv):
    assert not remedy_exec.system_argv_allowed(argv)
    rec = []
    old = remedy_exec.runner
    remedy_exec.runner = lambda a, t: rec.append(a) or (0, "", "")
    try:
        with opened():
            assert remedy_exec.run_mutating(argv, scope=remedy_exec.SYSTEM)[0] == 126
    finally:
        remedy_exec.runner = old
    assert rec == []


def test_system_domain_bootout_is_never_allowed():
    # Fix round 1 (ruling): no system-domain launchctl at all; a stale
    # system job's program is missing, and a bootout by label could stop a
    # live job of that label loaded from elsewhere.
    for argv in (["launchctl", "bootout", "system/com.gone.d"],
                 ["launchctl", "bootout", "system/com.vendor.edr.helper"]):
        assert not remedy_exec.system_argv_allowed(argv)
        assert not remedy_exec.argv_allowed(argv)
        with opened():
            assert remedy_exec.run_mutating(argv, scope=remedy_exec.SYSTEM)[0] == 126
    assert not any(s[0] == "launchctl" for s in remedy_exec.SYSTEM_MUTATING_COMMANDS)
    assert not hasattr(remedy_exec, "system_bootout_argv")
    # the user-level (Task 7) bootout is untouched
    assert remedy_exec.argv_allowed(remedy_exec.bootout_argv(501, "com.gone.job"))
    assert ("launchctl", "bootout") in remedy_exec.USER_MUTATING_COMMANDS


def test_non_list_argv_refused():
    for argv in ("pkgutil --forget com.x", b"pkgutil", ("pkgutil", "--forget", 3), None, 7):
        assert not remedy_exec.system_argv_allowed(argv)


@pytest.mark.parametrize("bad", ["-x", "a b", "a/b", "a\nb", "com.apple.x", "", "x" * 300,
                                 "café", "a..b", "--user"])
def test_system_argv_builders_refuse_hostile_names(bad):
    assert not remedy_exec.valid_system_label(bad)
    with pytest.raises(ValueError):
        remedy_exec.forget_argv(bad)
    if bad != "com.apple.x":  # an ordinary unit name on Linux
        with pytest.raises(ValueError):
            remedy_exec.system_disable_argv(bad + ".service" if bad else bad)


def test_system_scope_unreachable_from_an_unprivileged_call_path(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(remedy_exec, "runner", rec)
    argv = remedy_exec.system_disable_argv("gone.service")
    forget = remedy_exec.forget_argv("com.vendor.gone")
    # the default (user) scope refuses every system shape
    assert remedy_exec.run_mutating(argv)[0] == 126
    assert remedy_exec.run_mutating(forget)[0] == 126
    # system scope without its gates: refused
    assert remedy_exec.run_mutating(argv, scope=remedy_exec.SYSTEM)[0] == 126
    with remedy_exec.system_scope():  # not the helper
        assert remedy_exec.run_mutating(argv, scope=remedy_exec.SYSTEM)[0] == 126
    with scanmode.helper_mode():  # helper, but not root-mode act
        assert remedy_exec.run_mutating(argv, scope=remedy_exec.SYSTEM)[0] == 126
    assert rec.calls == []
    with opened():
        assert remedy_exec.run_mutating(argv, scope=remedy_exec.SYSTEM)[0] == 0
        # ... and the user shapes are refused in the system scope
        user = remedy_exec.bootout_argv(501, "com.gone.job")
        assert remedy_exec.run_mutating(user, scope=remedy_exec.SYSTEM)[0] == 126
        assert remedy_exec.run_mutating(argv, scope="other")[0] == 126
    assert rec.calls == [argv]
    # the read-only runner refuses them too, and its allowlist is unchanged
    for a in (argv, forget, remedy_exec.system_disable_argv("x.service"),
              remedy_exec.system_daemon_reload_argv()):
        assert oc.run(a) == (126, "", "refused")
    assert oc.READ_ONLY_COMMANDS == frozenset({
        ("dpkg-query", "-S"), ("dpkg-query", "-W"), ("rpm", "-qf"), ("rpm", "-qa"),
        ("pacman", "-Qo"), ("pacman", "-Qq"),
        ("mdfind", "kMDItemContentType == 'com.apple.application-bundle'"),
        ("pkgutil", "--pkgs"), ("pkgutil", "--pkg-info-plist"), ("pkgutil", "--only-files"),
    })
    for shape in remedy_exec.SYSTEM_MUTATING_COMMANDS:
        assert shape not in oc.READ_ONLY_COMMANDS


def test_actions_open_the_system_scope_only_with_allow_root(tmp_path, monkeypatch):
    seen = []

    def spy_clean(*a, **k):
        seen.append(remedy_exec._system_scope.get())
        from cleanix.core.service import CleanSummary
        from cleanix.core.models import CleanResult

        return CleanSummary(result=CleanResult(dry_run=True), quarantine_run=None,
                            manifest_path=None, freed=0, removed=0, errors=[],
                            cancelled=False)

    from cleanix.core import root_delete, service

    monkeypatch.setattr(service, "clean", spy_clean)
    monkeypatch.setattr(reverify, "reverify", lambda *a, **k: None)
    monkeypatch.setattr(root_delete, "mount_problem", lambda p, permanent: None)
    p = tmp_path / "f"
    p.write_text("x")
    item = CleanableItem(cleaner_id="orphan_files", description="d", size=0,
                         kind=ItemKind.PATH, path=str(p), requires_root=False,
                         report_only=True, remedy=Remedy(RemedyKind.PATH, fingerprint_of(str(p))))
    actions.act([item], Config(), dry_run=True)
    actions.act([item], Config(), dry_run=True, allow_root=True)
    assert seen == [False, True]
    assert remedy_exec._system_scope.get() is False


def test_default_runner_system_scope_uses_fixed_paths_only(monkeypatch):
    spawned = []
    monkeypatch.setattr(remedy_exec, "_spawn", lambda argv, t: spawned.append(argv) or (0, "", ""))
    monkeypatch.setattr(remedy_exec, "which", lambda name: f"/home/evil/bin/{name}")
    monkeypatch.setattr(remedy_exec, "_TOOL_PATHS", {"env": (), "launchctl": (),
                                                     "systemctl": (), "pkgutil": ()})
    # system scope: no fixed path -> not found, nothing started (never PATH)
    rc, _o, _e = remedy_exec.default_runner(remedy_exec.forget_argv("com.vendor.x"), 5)
    assert rc == 127 and spawned == []
    # user scope keeps its which() fallback
    remedy_exec.default_runner(remedy_exec.daemon_reload_argv(), 5)
    assert spawned and spawned[0][0] == "/home/evil/bin/env"


def test_system_tools_have_fixed_paths():
    paths = dict(remedy_exec._TOOL_PATHS)
    assert paths["pkgutil"] == ("/usr/sbin/pkgutil",)
    assert paths["launchctl"] == ("/bin/launchctl",)
    assert paths["systemctl"] == ("/usr/bin/systemctl", "/bin/systemctl")
    assert all(p.startswith("/") for ps in paths.values() for p in ps)


# --------------------------------------------------------------------------
# lexical kind checks (caller side and helper side)
# --------------------------------------------------------------------------
KD = {"launch_job": ("/Library/LaunchAgents", "/Library/LaunchDaemons"),
      "systemd_unit": ("/etc/systemd/system",),
      "pkg_receipt": ("/private/var/db/receipts",)}


@pytest.mark.parametrize("cid,kind,path", [
    ("orphan_launch_jobs", "launch_job", "/Library/LaunchDaemons/com.gone.d.plist"),
    ("orphan_launch_jobs", "launch_job", "/Library/LaunchAgents/com.gone.a.plist"),
    ("stale_services", "systemd_unit", "/etc/systemd/system/gone.service"),
    ("stale_services", "systemd_unit", "/etc/systemd/system/tpl@.service"),
    ("stale_receipts", "pkg_receipt", "/private/var/db/receipts/com.vendor.gone.plist"),
    ("stale_services", "path", "/etc/systemd/system/x.service.d"),
])
def test_kind_lexical_accepts_plain_items(cid, kind, path):
    assert elevate.finding_kind_problem(cid, kind, path, KD) is None


@pytest.mark.parametrize("cid,kind,path", [
    # wrong scenario for the kind, or a kind the scenario never offers
    ("orphan_files", "launch_job", "/Library/LaunchDaemons/a.plist"),
    ("stale_services", "launch_job", "/Library/LaunchDaemons/a.plist"),
    ("orphan_launch_jobs", "path", "/Library/LaunchDaemons/a.plist"),
    ("stale_receipts", "path", "/private/var/db/receipts/a.plist"),
    ("orphan_launch_jobs", "systemd_unit", "/etc/systemd/system/a.service"),
    # not directly in the folder / another folder
    ("orphan_launch_jobs", "launch_job", "/Library/LaunchDaemons/sub/a.plist"),
    ("orphan_launch_jobs", "launch_job", "/System/Library/LaunchDaemons/a.plist"),
    ("stale_services", "systemd_unit", "/usr/lib/systemd/system/a.service"),
    ("stale_services", "systemd_unit", "/lib/systemd/system/a.service"),
    ("stale_services", "systemd_unit", "/usr/local/lib/systemd/system/a.service"),
    ("stale_services", "systemd_unit", "/etc/systemd/user/a.service"),
    ("stale_receipts", "pkg_receipt", "/var/db/receipts/a.plist"),
    # hostile or odd names
    ("orphan_launch_jobs", "launch_job", "/Library/LaunchDaemons/com.apple.x.plist"),
    ("orphan_launch_jobs", "launch_job", "/Library/LaunchDaemons/COM.APPLE.x.plist"),
    ("orphan_launch_jobs", "launch_job", "/Library/LaunchDaemons/-x.plist"),
    ("orphan_launch_jobs", "launch_job", "/Library/LaunchDaemons/a b.plist"),
    ("orphan_launch_jobs", "launch_job", "/Library/LaunchDaemons/.plist"),
    ("orphan_launch_jobs", "launch_job", "/Library/LaunchDaemons/a..b.plist"),
    ("orphan_launch_jobs", "launch_job", "/Library/LaunchDaemons/café.plist"),
    ("orphan_launch_jobs", "launch_job", "/Library/LaunchDaemons/a.txt"),
    ("orphan_launch_jobs", "launch_job", "/Library/LaunchDaemons/" + "a" * 300 + ".plist"),
    ("stale_services", "systemd_unit", "/etc/systemd/system/-x.service"),
    ("stale_services", "systemd_unit", "/etc/systemd/system/x.socket"),
    ("stale_services", "systemd_unit", "/etc/systemd/system/.service"),
    ("stale_services", "systemd_unit", "/etc/systemd/system/a b.service"),
    ("stale_receipts", "pkg_receipt", "/private/var/db/receipts/com.apple.pkg.Core.plist"),
    ("stale_receipts", "pkg_receipt", "/private/var/db/receipts/a@b.plist"),
    ("stale_receipts", "pkg_receipt", "/private/var/db/receipts/a.bom"),
    ("stale_receipts", "pkg_receipt", "/private/var/db/receipts/-a.plist"),
    ("orphan_files", "nonsense", "/var/lib/x"),
])
def test_kind_lexical_refuses(cid, kind, path):
    assert elevate.finding_kind_problem(cid, kind, path, KD)


def test_helper_kinds_per_platform(monkeypatch):
    for osname, kinds in ((plat.MACOS, {"path", "launch_job", "pkg_receipt"}),
                          (plat.LINUX, {"path", "systemd_unit"}),
                          (plat.WINDOWS, {"path"}), ("freebsd", {"path"})):
        monkeypatch.setattr(plat, "current_os", lambda o=osname: o)
        assert elevated.helper_finding_kinds() == kinds
    # Windows: no findings scenario at all (the helper refuses before kinds)
    monkeypatch.setattr(plat, "current_os", lambda: plat.WINDOWS)
    assert elevate.admin_finding_ids() == frozenset()


@pytest.mark.parametrize("osname", [plat.MACOS, plat.LINUX])
def test_admin_finding_ids_already_list_the_job_scenarios(monkeypatch, osname):
    monkeypatch.setattr(plat, "current_os", lambda: osname)
    ids = elevate.admin_finding_ids()
    if osname == plat.MACOS:
        assert {"orphan_launch_jobs", "stale_receipts"} <= ids
    else:
        assert "stale_services" in ids


# --------------------------------------------------------------------------
# result schema: notes and the backup run
# --------------------------------------------------------------------------
def _result_obj(**extra):
    obj = {"version": elevate.FORMAT_VERSION, "nonce": "n", "freed": 0, "removed": 1,
           "unmatched": 0, "refused": 0, "deadline_hit": False, "errors": [],
           "findings": [{"key": "orphan_files|path|/var/lib/x", "status": "removed",
                         "freed": 3, "reason": ""}],
           "quarantine_run": ""}
    obj.update(extra)
    return obj


def _read(tmp_path, obj):
    p = tmp_path / elevate.RESULT_NAME
    p.write_text(json.dumps(obj))
    if POSIX:
        os.chmod(str(p), 0o644)
    return elevate.read_result(p)


def test_result_note_and_backup_run_roundtrip(tmp_path):
    res = elevate.HelperResult(freed=0, removed=1, errors=[], unmatched=0, findings=[
        elevate.FindingOutcome("orphan_launch_jobs|path|/Library/LaunchDaemons/a.plist",
                               "removed", 10, "", note="permanent: x\nwarning: y")],
        backup_run="20261120-101010-1-abcd")
    elevate.write_result(tmp_path / elevate.RESULT_NAME, res)
    back = elevate.read_result(tmp_path / elevate.RESULT_NAME)
    assert back.backup_run == "20261120-101010-1-abcd"
    assert back.findings[0].note == "permanent: x warning: y"  # control chars flattened


def test_worst_case_result_with_notes_still_fits(tmp_path):
    """1000 items with the longest keys, reasons and notes (and the maximum
    errors) are written truncated and still read back: the caller never
    loses the result of a batch that stopped and removed things."""
    comp = "a" * 250
    base = "/var/lib/" + "/".join([comp] * 4)
    outcomes = []
    for i in range(elevate.MAX_FINDING_ITEMS):
        path = (base + f"/{i:04d}")[:elevate.MAX_FINDING_PATH_LEN]
        path = path[:-5] + f"{i:05d}"
        outcomes.append(elevate.FindingOutcome(
            f"orphan_launch_jobs|path|{path}", "removed", 1, "r" * 5000, note="n" * 5000))
    res = elevate.HelperResult(freed=0, removed=1000, errors=["e" * 5000] * 1000,
                               unmatched=0, findings=outcomes, backup_run="run-1",
                               quarantine_run="run-2")
    target = tmp_path / elevate.RESULT_NAME
    elevate.write_result(target, res)
    assert target.stat().st_size < elevate.MAX_RESULT_BYTES
    back = elevate.read_result(target)
    assert len(back.findings) == 1000
    assert all(len(o.note) == elevate.MAX_NOTE_LEN for o in back.findings)


def test_older_results_still_parse(tmp_path):
    back = _read(tmp_path, _result_obj())
    assert back.backup_run == "" and back.findings[0].note == ""


@pytest.mark.parametrize("extra", [
    {"backup_run": "../x"}, {"backup_run": 7}, {"backup_run": "a b"},
    {"findings": [{"key": "orphan_files|path|/var/lib/x", "status": "removed", "freed": 3,
                   "reason": "", "note": 5}]},
    {"findings": [{"key": "orphan_files|path|/var/lib/x", "status": "removed", "freed": 3,
                   "reason": "", "note": "x" * (elevate.MAX_NOTE_LEN + 1)}]},
    {"findings": [{"key": "orphan_files|path|/var/lib/x", "status": "removed", "freed": 3,
                   "reason": "", "note": "", "extra": 1}]},
])
def test_result_extensions_strictly_parsed(tmp_path, extra):
    with pytest.raises(ValueError):
        _read(tmp_path, _result_obj(**extra))


# --------------------------------------------------------------------------
# system_remedy.check: the structural act-time re-check
# --------------------------------------------------------------------------
def test_check_accepts_plain_items(env, monkeypatch):
    mac(monkeypatch)
    d = daemon(env)
    assert system_remedy.check(sys_item(d, LJ, "com.gone.d"), Config()) == (None, "com.gone.d")
    a = daemon(env, "com.gone.a", where="Library/LaunchAgents")
    assert system_remedy.check(sys_item(a, LJ, "com.gone.a"), Config())[0] is None
    r = receipt(env)
    assert system_remedy.check(sys_item(r, PR, "com.vendor.gone"), Config()) == (
        None, "com.vendor.gone")
    linux(monkeypatch)
    u = unit(env)
    assert system_remedy.check(sys_item(u, SU, "gone.service"), Config()) == (None, "gone.service")


def test_check_refuses(env, monkeypatch):
    mac(monkeypatch)
    d = daemon(env)
    ok = sys_item(d, LJ, "com.gone.d")
    c = Config()

    def why(item):
        return system_remedy.check(item, c)[0]

    assert why(sys_item(d, LJ, "com.gone.d", cid="orphan_files")) == system_remedy.WRONG_SCENARIO
    assert why(sys_item(d, LJ, "com.gone.d", requires_root=False)) == system_remedy.NOT_HANDLED
    assert why(sys_item(d, LJ, "com.gone.d", group="g")) == system_remedy.NOT_HANDLED
    assert why(sys_item(d, LJ, "x", extra=(("unit", "com.gone.d"),))) == system_remedy.BAD_DATA
    assert why(sys_item(d, LJ, "x", extra=(("label", "a"), ("label", "b")))) == \
        system_remedy.BAD_DATA
    for bad in ("-x", "a b", "a/b", "a\nb", "x" * 300, "café", "a..b", ""):
        assert why(sys_item(d, LJ, bad)) == system_remedy.BAD_NAME, bad
    assert why(sys_item(d, LJ, "com.apple.d")) == system_remedy.APPLE
    apple = daemon(env, "com.apple.d", label="com.vendor.d")
    assert why(sys_item(apple, LJ, "com.vendor.d")) == system_remedy.APPLE
    assert why(sys_item(d, LJ, "com.gone.d", fp=(0, 0, 0, 0))) == "no usable fingerprint"
    assert "changed" in why(sys_item(d, LJ, "com.gone.d", fp=(1, 2, 3, 4)))
    # outside the allowed folders: a subfolder, /System, another root
    for where in ("Library/LaunchDaemons/sub", "System/Library/LaunchDaemons",
                  "Library/LaunchDaemonsX", "opt"):
        other = daemon(env, "com.gone.o", where=where)
        assert why(sys_item(other, LJ, "com.gone.o")) == system_remedy.NOT_IN_PLACE, where
    # the platform binding
    linux(monkeypatch)
    assert why(ok) == system_remedy.WRONG_PLATFORM
    u = unit(env)
    assert why(sys_item(u, SU, "other.service")) == system_remedy.BAD_NAME
    assert why(sys_item(u, SU, "gone.socket")) == system_remedy.BAD_NAME
    vendor = unit(env, "v.service", where="usr/lib/systemd/system")
    assert why(sys_item(vendor, SU, "v.service")) == system_remedy.NOT_IN_PLACE
    local = unit(env, "l.service", where="usr/local/lib/systemd/system")
    assert why(sys_item(local, SU, "l.service")) == system_remedy.NOT_IN_PLACE
    mac(monkeypatch)
    assert why(sys_item(u, SU, "gone.service")) == system_remedy.WRONG_PLATFORM
    r = receipt(env)
    assert why(sys_item(r, PR, "com.vendor.other")) == system_remedy.BAD_NAME
    assert why(sys_item(r, PR, "com.apple.pkg.x")) == system_remedy.APPLE
    assert why(sys_item(r, PR, "a@b")) == system_remedy.BAD_NAME


@posix_only
def test_check_refuses_links(env, monkeypatch):
    mac(monkeypatch)
    target = daemon(env, "com.gone.t", where="opt/real")
    link = env.root / "Library/LaunchDaemons/com.gone.l.plist"
    link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(str(target), str(link))
    item = sys_item(link, LJ, "com.gone.l", fp=fingerprint_of(str(target)))
    assert system_remedy.check(item, Config())[0] == system_remedy.IS_LINK
    r = receipt(env, bom=False)
    os.symlink("/etc/passwd", str(r.with_name("com.vendor.gone.bom")))
    assert system_remedy.check(sys_item(r, PR, "com.vendor.gone"), Config())[0] == \
        system_remedy.BAD_BOM


# --------------------------------------------------------------------------
# scan-time remedies (only when every precondition is provable)
# --------------------------------------------------------------------------
@posix_only
def test_launch_daemon_remedy_only_when_provable(env, monkeypatch):
    d = daemon(env)
    item = scanned(olj.OrphanLaunchJobReporter, d)
    assert item.requires_root and item.remedy.kind is LJ
    assert item.remedy.extra == (("label", "com.gone.d"),)
    assert item.remedy.fingerprint == fingerprint_of(str(d))
    a = daemon(env, "com.gone.a", where="Library/LaunchAgents")
    assert scanned(olj.OrphanLaunchJobReporter, a).remedy.kind is LJ
    # no Label key of its own: launchd's name is unknown -> no remedy
    nolabel = daemon(env, "com.gone.n", data={"ProgramArguments": ["/opt/gone/n"]})
    assert scanned(olj.OrphanLaunchJobReporter, nolabel).remedy is None
    # odd label -> no remedy
    odd = daemon(env, "com.gone.odd", label="-evil")
    assert scanned(olj.OrphanLaunchJobReporter, odd).remedy is None
    # writable by others, another owner, a second hard link -> no remedy
    w = daemon(env, "com.gone.w")
    os.chmod(str(w), 0o666)
    assert scanned(olj.OrphanLaunchJobReporter, w).remedy is None
    h = daemon(env, "com.gone.h")
    os.link(str(h), str(env.root / "hardlink.plist"))
    assert scanned(olj.OrphanLaunchJobReporter, h).remedy is None
    monkeypatch.setattr(oc, "SYSTEM_FILE_UID", UID + 1)
    assert scanned(olj.OrphanLaunchJobReporter, d).remedy is None
    monkeypatch.setattr(oc, "SYSTEM_FILE_UID", UID)
    # a broken system job link: no job file -> no remedy
    link = env.root / "Library/LaunchDaemons/com.gone.link.plist"
    os.symlink("/Library/Gone/x.plist", str(link))
    assert scanned(olj.OrphanLaunchJobReporter, link).remedy is None
    # helper/strict mode: a parent chain an ordinary user can change -> none
    with scanmode.strict_evidence(), scanmode.evidence_rule(
            lambda p: "user-writable" if p == str(d) else None):
        assert scanned(olj.OrphanLaunchJobReporter, d).remedy is None


@posix_only
def test_system_unit_remedy_only_when_unowned_and_unique(env, monkeypatch):
    monkeypatch.setattr(oc.OrphanReporter, "pkg_backend", lambda self: "dpkg")
    u = unit(env)
    item = scanned(ss.StaleSystemdUnitReporter, u)
    assert item.remedy.kind is SU and item.remedy.extra == (("unit", "gone.service"),)
    assert ["dpkg-query", "-S", "/etc/systemd/system/gone.service"] in env.tools.calls
    t = unit(env, "tpl@.service")
    assert scanned(ss.StaleSystemdUnitReporter, t).remedy.kind is SU
    # owned by a package / unknown answer / no backend -> none
    env.tools.owned.add("/etc/systemd/system/gone.service")
    assert scanned(ss.StaleSystemdUnitReporter, u).remedy is None
    env.tools.owned.clear()
    env.tools.rc = 2
    assert scanned(ss.StaleSystemdUnitReporter, u).remedy is None
    env.tools.rc = None
    monkeypatch.setattr(oc.OrphanReporter, "pkg_backend", lambda self: None)
    assert scanned(ss.StaleSystemdUnitReporter, u).remedy is None
    monkeypatch.setattr(oc.OrphanReporter, "pkg_backend", lambda self: "dpkg")
    # the same name elsewhere on the search path (it would come back, still
    # enabled, and disable-by-name would hit it) -> none
    unit(env, "gone.service", program="/usr/bin/true", where="usr/lib/systemd/system")
    assert scanned(ss.StaleSystemdUnitReporter, u).remedy is None
    i = unit(env, "inst@a.service")
    unit(env, "inst@.service", program="/usr/bin/true", where="usr/lib/systemd/system")
    assert scanned(ss.StaleSystemdUnitReporter, i).remedy is None
    # not /etc/systemd/system: /usr/local/lib and /etc/systemd/user -> none
    loc = unit(env, "loc.service", where="usr/local/lib/systemd/system")
    assert scanned(ss.StaleSystemdUnitReporter, loc).remedy is None
    usr = unit(env, "usr.service", where="etc/systemd/user")
    assert scanned(ss.StaleSystemdUnitReporter, usr).remedy is None
    # world-writable unit file -> none
    w = unit(env, "w.service")
    os.chmod(str(w), 0o666)
    assert scanned(ss.StaleSystemdUnitReporter, w).remedy is None


@posix_only
def test_receipt_remedy_requires_every_listed_file_gone(env, monkeypatch):
    r = receipt(env)
    item = scanned(sr.StaleReceiptReporter, r)
    assert item.remedy.kind is PR and item.remedy.extra == (("pkg_id", "com.vendor.gone"),)
    # 200 listed files: the sample (150) misses one that still exists ->
    # still reported (sample), but NO remedy (every file is checked)
    files = [f"vend/data/f{i:04d}" for i in range(1000)]  # no bundle to survive
    r2 = receipt(env, "com.vendor.many", files=files)
    sample = set(sr.sample_files("com.vendor.many", sorted(files)))
    missed = max(f for f in files if f not in sample)  # late in the list
    assert files.index(missed) > 900
    present = env.root / "Applications" / missed
    present.parent.mkdir(parents=True)
    present.write_text("x")
    item = scanned(sr.StaleReceiptReporter, r2)
    assert item.remedy is None
    # above the cap -> no remedy
    monkeypatch.setattr(sr, "MAX_FORGET_FILES", 1)
    assert scanned(sr.StaleReceiptReporter, r).remedy is None
    monkeypatch.setattr(sr, "MAX_FORGET_FILES", 5000)
    # pkgutil names another id -> none; a world-writable receipt or bom -> none
    r3 = receipt(env, "com.vendor.alias", pkgid="com.vendor.other")
    assert scanned(sr.StaleReceiptReporter, r3).remedy is None
    os.chmod(str(r.with_name("com.vendor.gone.bom")), 0o666)
    assert scanned(sr.StaleReceiptReporter, r).remedy is None
    os.chmod(str(r.with_name("com.vendor.gone.bom")), 0o644)
    # strict mode (M-d): an absence an ordinary user could have caused is
    # unknown -> the receipt is not even reported
    with scanmode.strict_evidence(), scanmode.evidence_rule(lambda p: "user-writable"):
        rep = sr.StaleReceiptReporter(Config())
        assert [i for i in rep.scan().items if i.path == str(r)] == []
    with scanmode.strict_evidence(), trusted():
        assert scanned(sr.StaleReceiptReporter, r).remedy.kind is PR


# --------------------------------------------------------------------------
# act-time re-verification (each fails closed)
# --------------------------------------------------------------------------
@posix_only
def test_launch_job_reverify_fails_closed(env, monkeypatch):
    mac(monkeypatch)
    d = daemon(env)
    item = scanned(olj.OrphanLaunchJobReporter, d)
    with trusted():
        assert reverify.reverify(item, Config()) is None
    # no evidence rule registered: the absence cannot be judged
    assert reverify.reverify(item, Config()) is not None
    with scanmode.evidence_rule(lambda p: "user-writable"):
        assert reverify.reverify(item, Config()) is not None
    # the program exists now
    prog = env.root / "opt/gone/d"
    prog.parent.mkdir(parents=True)
    prog.write_text("x")
    with trusted():
        assert "program exists now" in reverify.reverify(item, Config())
    prog.unlink()
    # the plist now names another label
    daemon(env, label="com.vendor.important")
    with trusted():
        assert reverify.reverify(item, Config()) is not None
    daemon(env)
    os.chmod(str(d), 0o664)
    with trusted():
        assert reverify.reverify(item, Config()) is not None


@posix_only
def test_unit_reverify_fails_closed(env, monkeypatch):
    linux(monkeypatch)
    monkeypatch.setattr(oc.OrphanReporter, "pkg_backend", lambda self: "dpkg")
    u = unit(env)
    item = scanned(ss.StaleSystemdUnitReporter, u)
    with trusted():
        assert reverify.reverify(item, Config()) is None
        env.tools.owned.add("/etc/systemd/system/gone.service")  # a package owns it now
        assert "package owns it" in reverify.reverify(item, Config())
        env.tools.owned.clear()
        env.tools.rc = 124  # timeout: unknown
        assert reverify.reverify(item, Config()) is not None
        env.tools.rc = None
        vendor = unit(env, "gone.service", program="/usr/bin/true",
                      where="usr/lib/systemd/system")
        assert reverify.reverify(item, Config()) is not None
        vendor.unlink()
        prog = env.root / "opt/gone/x"
        prog.parent.mkdir(parents=True)
        prog.write_text("x")
        assert reverify.reverify(item, Config()) is not None
        prog.unlink()
        assert reverify.reverify(item, Config()) is None
        # a PATH remedy for a unit FILE is never re-verified as fine
        as_path = CleanableItem(cleaner_id="stale_services", description="d", size=0,
                                kind=ItemKind.PATH, path=str(u), requires_root=True,
                                report_only=True,
                                remedy=Remedy(RemedyKind.PATH, fingerprint_of(str(u))))
        assert reverify.reverify(as_path, Config()) is not None


@posix_only
def test_receipt_reverify_fails_closed(env, monkeypatch):
    mac(monkeypatch)
    r = receipt(env)
    item = scanned(sr.StaleReceiptReporter, r)
    with trusted():
        assert reverify.reverify(item, Config()) is None
        # a listed file is present again
        back = env.root / "Applications/Gone.app/Contents/Info.plist"
        back.parent.mkdir(parents=True)
        back.write_text("x")
        assert "exists now" in reverify.reverify(item, Config())
        import shutil

        shutil.rmtree(str(env.root / "Applications"))
        assert reverify.reverify(item, Config()) is None
        # pkgutil error
        info, files, _rc = env.tools.pkgs["com.vendor.gone"]
        env.tools.pkgs["com.vendor.gone"] = (info, files, 1)
        assert reverify.reverify(item, Config()) is not None
        env.tools.pkgs["com.vendor.gone"] = (info, files, 0)
        # list above the cap
        monkeypatch.setattr(sr, "MAX_FORGET_FILES", 1)
        assert reverify.reverify(item, Config()) is not None
        monkeypatch.setattr(sr, "MAX_FORGET_FILES", 5000)
        # not a valid id / another receipt path
        for bad in ("-x", "com.apple.pkg.Core", "a/b", "a\n"):
            forged = sys_item(r, PR, bad)
            assert reverify.reverify(forged, Config()) is not None, bad
        other = receipt(env, "com.vendor.two")
        forged = sys_item(other, PR, "com.vendor.gone")
        assert reverify.reverify(forged, Config()) == "it is not this package's receipt"


def test_reverifiers_bind_the_kind_to_the_scenario(tmp_path):
    p = tmp_path / "x.plist"
    p.write_text("x")
    for cid, kind in (("orphan_launch_jobs", RemedyKind.PATH), ("orphan_launch_jobs", PR),
                      ("stale_receipts", LJ), ("stale_receipts", RemedyKind.PATH),
                      ("stale_services", LJ), ("orphan_files", LJ), ("orphan_app_data", PR),
                      ("stale_launchers", SU)):
        item = CleanableItem(cleaner_id=cid, description="d", size=0, kind=ItemKind.PATH,
                             path=str(p), requires_root=True, report_only=True,
                             remedy=Remedy(kind, fingerprint_of(str(p)),
                                           extra=(("label", "a.b"),)))
        assert reverify.reverify(item, Config()) == reverify.WRONG_KIND, (cid, kind)


# --------------------------------------------------------------------------
# F. stop commands (system scope) and pkgutil --forget
# --------------------------------------------------------------------------
def test_agent_is_never_booted_out(env, monkeypatch):
    mac(monkeypatch)
    a = daemon(env, "com.gone.a", where="Library/LaunchAgents")
    with opened():
        stop = system_remedy.unload(LJ, "com.gone.a", str(a))
    assert env.rec.calls == [] and not stop.stopped
    assert stop.warnings == [system_remedy.AGENT_NOT_STOPPED]


def test_daemon_is_never_booted_out(env, monkeypatch):
    """Fix round 1: no command for a system daemon either -- even when a live
    job of the same label is loaded from elsewhere (an SMAppService /
    BundleProgram helper, a /System daemon). The note says launchd forgets
    it at the next restart."""
    mac(monkeypatch)
    d = daemon(env)
    for where in (None, "System/Library/LaunchDaemons", "Library/LaunchAgents"):
        twin = (daemon(env, "com.vendor.live", label="com.gone.d", where=where)
                if where else None)
        with opened():
            stop = system_remedy.unload(LJ, "com.gone.d", str(d))
        assert not stop.stopped and stop.warnings == []
        assert stop.info == [system_remedy.DAEMON_FORGOTTEN]
        if twin is not None:
            twin.unlink()
    assert env.rec.calls == []
    note = system_remedy.note(LJ, "/q/run/files", stop, True)
    assert note == ("permanent: the job's file was removed; launchd forgets it at the next "
                    "restart (it cannot run: its program is missing) (a copy of the file is "
                    "kept in /q/run/files for manual recovery)")
    assert system_remedy.note(LJ, "/q", stop, False).startswith("its file was not removed")
    # the agent note is unchanged
    agent = system_remedy.note(LJ, "/q", remedy_exec.Stop(
        warnings=[system_remedy.AGENT_NOT_STOPPED]), True)
    assert agent.startswith("permanent: its file was removed") and "not stopped here" in agent


def test_unit_disable_and_name_elsewhere(env, monkeypatch):
    linux(monkeypatch)
    u = unit(env)
    with opened():
        assert system_remedy.unload(SU, "gone.service", str(u)).stopped
        assert system_remedy.unload(SU, "tpl@.service", str(u)).stopped
        assert system_remedy.reload_units() == []
    assert env.rec.calls == [["systemctl", "disable", "--now", "gone.service"],
                             ["systemctl", "disable", "tpl@.service"],
                             ["systemctl", "daemon-reload"]]
    env.rec.calls.clear()
    for where in ("usr/lib/systemd/system", "run/systemd/system", "lib/systemd/system",
                  "run/systemd/generator", "etc/systemd/system.control"):
        other = unit(env, "gone.service", where=where)
        with opened():
            stop = system_remedy.unload(SU, "gone.service", str(u))
        assert not stop.stopped and "another unit file" in stop.warnings[0], where
        other.unlink()
    unit(env, "inst@.service", where="usr/lib/systemd/system")
    with opened():
        stop = system_remedy.unload(SU, "inst@a.service", str(u))
    assert not stop.stopped and "inst@.service" in stop.warnings[0]
    assert env.rec.calls == []


def test_forget_verifies_the_receipt_is_gone(env, monkeypatch):
    mac(monkeypatch)
    r = receipt(env)
    bom = r.with_name("com.vendor.gone.bom")
    size = r.stat().st_size + bom.stat().st_size

    def forgets(argv):
        if argv[:2] == ["pkgutil", "--forget"]:
            r.unlink()
            bom.unlink()
        return None

    # success: both files gone
    env.rec.side_effect = forgets
    with opened():
        assert system_remedy.forget("com.vendor.gone", str(r)) == (True, size, None)
    assert env.rec.calls == [["pkgutil", "--forget", "com.vendor.gone"]]
    # rc 0 but the receipt is still there
    r = receipt(env)
    env.rec.side_effect = None
    with opened():
        removed, freed, err = system_remedy.forget("com.vendor.gone", str(r))
    assert not removed and freed == 0 and "still there" in err
    # failure
    env.rec.result = (1, "", "No receipt for 'com.vendor.gone' found")
    with opened():
        removed, _f, err = system_remedy.forget("com.vendor.gone", str(r))
    assert not removed and "pkgutil --forget failed (exit 1" in err
    # outside the scope: refused, nothing run, not removed
    env.rec.calls.clear()
    removed, _f, err = system_remedy.forget("com.vendor.gone", str(r))
    assert not removed and "refused" in err and env.rec.calls == []
    # a hostile id never reaches a command
    removed, _f, err = system_remedy.forget("-x", str(r))
    assert not removed and env.rec.calls == []


# --------------------------------------------------------------------------
# the ordinary (unprivileged) path still skips these items
# --------------------------------------------------------------------------
def test_normal_act_skips_system_job_kinds(env, monkeypatch):
    mac(monkeypatch)
    d = daemon(env)
    r = receipt(env)
    items = [sys_item(d, LJ, "com.gone.d"), sys_item(r, PR, "com.vendor.gone")]
    monkeypatch.setattr(engine, "is_root", lambda: True)  # even in a root process
    for permanent in (False, True):
        s = actions.act(items, Config(), dry_run=False, permanent=permanent)
        assert [w for _i, w in s.skipped] == [actions.NEEDS_ELEVATION] * 2
    assert d.exists() and r.exists() and env.rec.calls == []
    # root mode without a backup location: skipped, nothing run
    s = actions.act(items, Config(), dry_run=False, permanent=True, allow_root=True)
    assert [w for _i, w in s.skipped] == [actions.NO_BACKUP_PLACE] * 2
    assert d.exists() and r.exists() and env.rec.calls == []


# --------------------------------------------------------------------------
# G. strict app inventory needs MIN_APPS real bundles
# --------------------------------------------------------------------------
@posix_only
def test_strict_inventory_needs_min_apps_real_bundles(env):
    store = env.root / "store"
    apps = env.root / "Applications"
    apps.mkdir(parents=True)
    for k in range(orphan_app_data.MIN_APPS):
        b = store / f"Linked{k}.app" / "Contents"
        b.mkdir(parents=True)
        with open(str(b / "Info.plist"), "wb") as fh:
            plistlib.dump({"CFBundleIdentifier": f"com.linked{k}.app"}, fh)
        os.symlink(str(store / f"Linked{k}.app"), str(apps / f"Linked{k}.app"))
    env.tools.mdfind = ""  # Spotlight answers, but lists nothing
    # ordinary scans are unchanged: links count as installed apps
    assert orphan_app_data._inventory(env.root, []) is not None
    # strict: zero real bundles walked + empty Spotlight never passes
    assert orphan_app_data._inventory(env.root, [], require_mdfind=True) is None
    # ... and neither does an empty walk
    empty = env.root / "empty"
    (empty / "Applications").mkdir(parents=True)
    assert orphan_app_data._inventory(empty, [], require_mdfind=True) is None


# --------------------------------------------------------------------------
# Fix round 1
# --------------------------------------------------------------------------
def test_receipts_are_never_unlinked(env, monkeypatch):
    """Minor 2: root removal refuses anything in the receipts folder (any
    spelling or case) unless it is a prepared receipt being forgotten."""
    from cleanix.core import root_delete

    rd = env.root / "private/var/db/receipts"
    for p in (rd / "x.plist", rd / "sub" / "y", env.root / "var/db/receipts/z.bom",
              env.root / "PRIVATE/var/DB/receipts/x.plist"):
        assert system_remedy.in_receipts_dir(str(p)), p
    for p in (env.root / "private/var/db/receiptsX/a", env.root / "var/lib/a"):
        assert not system_remedy.in_receipts_dir(str(p)), p
    victim = rd / "com.vendor.x.plist"
    rd.mkdir(parents=True)
    victim.write_text("x")
    item = CleanableItem(cleaner_id="orphan_files", description="d", size=0,
                         kind=ItemKind.PATH, path=str(victim), requires_root=True,
                         report_only=True,
                         remedy=Remedy(RemedyKind.PATH, fingerprint_of(str(victim))))
    monkeypatch.setattr(engine, "is_root", lambda: True)
    monkeypatch.setattr(reverify, "reverify", lambda *a, **k: None)
    monkeypatch.setattr(root_delete, "mount_problem", lambda p, permanent: None)
    removed = []
    monkeypatch.setattr(root_delete, "remove", lambda p: removed.append(p) or (True, 1, None))
    s = actions.act([item], Config(), dry_run=False, permanent=True, allow_root=True,
                    record_history=False)
    (out,) = s.result.outcomes
    assert not out.removed and out.error == system_remedy.RECEIPT_NOT_UNLINKED
    assert victim.exists() and removed == [] and env.rec.calls == []


def test_backup_copy_is_private_and_records_metadata(tmp_path):
    """Minor 3: the copy is 0600; the original's mode/owner/(flags) are in
    the manifest entry, taken from the lstat before copying."""
    from cleanix.core import quarantine

    src = tmp_path / "com.gone.d.plist"
    src.write_text("job")
    if POSIX:
        os.chmod(str(src), 0o644)
    st = os.lstat(str(src))
    qroot = tmp_path / "q"
    qroot.mkdir()
    run = quarantine.new_run(root=qroot)
    stored = run.store_copy(str(src))
    (entry,) = json.loads((run.dir / "manifest.json").read_text())["items"]
    assert entry["type"] == "copy" and entry["mode"] == (st.st_mode & 0o7777)
    assert entry["uid"] == st.st_uid and entry["gid"] == st.st_gid
    assert ("flags" in entry) == (getattr(st, "st_flags", None) is not None)
    assert Path(stored).read_text() == "job"
    if POSIX:
        assert (os.lstat(stored).st_mode & 0o777) == 0o600
        assert (os.lstat(str(src)).st_mode & 0o777) == 0o644  # the original untouched


class _St:
    def __init__(self, flags=None, mode=0o100644, uid=0, nlink=1):
        self.st_mode, self.st_uid, self.st_nlink = mode, uid, nlink
        self.st_dev, self.st_ino, self.st_gid = 1, 2, 0
        if flags is not None:
            self.st_flags = flags


@pytest.mark.parametrize("flags,locked", [
    (0, False), (0x2, True), (0x4, True), (0x20000, True), (0x40000, True),
    (0x8000, False),  # UF_HIDDEN: harmless
])
def test_lock_flags_from_st_flags(flags, locked):
    """Minor 4 (BSD/macOS st_flags): immutable / append-only is refused."""
    assert bool(oc.lock_flags_problem("/x", _St(flags))) is locked


def test_lock_flags_linux_ioctl_seam(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    for value, locked in ((0x10, True), (0x20, True), (0x80000, False), (None, False)):
        monkeypatch.setattr(oc, "_linux_fs_flags", lambda p, st, v=value: v)
        assert bool(oc.lock_flags_problem("/x", _St())) is locked, value
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(oc, "_linux_fs_flags", lambda p, st: pytest.fail("not on macOS"))
    assert oc.lock_flags_problem("/x", _St()) is None  # no st_flags: nothing to read


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux ioctl")
def test_lock_flags_real_linux_file_reads_or_skips(tmp_path):
    p = tmp_path / "f"
    p.write_text("x")
    flags = oc._linux_fs_flags(str(p), os.lstat(str(p)))
    assert flags is None or not flags & 0x30  # readable or not: never locked here
    assert oc.lock_flags_problem(str(p), os.lstat(str(p))) is None


def test_helper_refuses_an_immutable_job_file(monkeypatch):
    st = _St(flags=0x20000, uid=elevated._ROOT_UID)
    monkeypatch.setattr(elevated, "_lstat", lambda p: st)
    monkeypatch.setattr(elevated, "_acl_problem", lambda p: None)
    assert "immutable" in elevated._system_file_problem("/Library/LaunchDaemons/x.plist")
    st.st_flags = 0
    assert elevated._system_file_problem("/Library/LaunchDaemons/x.plist") is None


@posix_only
def test_scan_gives_no_remedy_to_an_immutable_job(env, monkeypatch):
    d = daemon(env)
    if sys.platform.startswith("linux"):
        monkeypatch.setattr(oc, "_linux_fs_flags", lambda p, st: 0x10)
    else:  # pragma: no cover - macOS/BSD
        monkeypatch.setattr(oc, "lock_flags_problem", lambda p, st: "is immutable")
    assert scanned(olj.OrphanLaunchJobReporter, d).remedy is None


@posix_only
def test_apple_names_in_any_case_get_no_remedy(env, monkeypatch):
    """Minor 5: ``COM.APPLE.*`` (any case) never carries a remedy, so one odd
    item can never get a whole helper request refused."""
    odd = daemon(env, "COM.APPLE.x", label="com.vendor.x")
    item = scanned(olj.OrphanLaunchJobReporter, odd)
    assert item.remedy is None
    label = daemon(env, "com.vendor.y", label="Com.Apple.y")
    assert scanned(olj.OrphanLaunchJobReporter, label).remedy is None
    r = receipt(env, "COM.APPLE.pkg.x")
    assert scanned(sr.StaleReceiptReporter, r).remedy is None
    monkeypatch.setattr(oc.OrphanReporter, "pkg_backend", lambda self: "dpkg")
    u = unit(env, "COM.APPLE.x.service")
    assert scanned(ss.StaleSystemdUnitReporter, u).remedy is None
    mac(monkeypatch)
    assert system_remedy.check(sys_item(odd, LJ, "com.vendor.x"), Config())[0] == \
        system_remedy.APPLE
    assert not remedy_exec.valid_pkg_id("COM.APPLE.pkg.x")
    assert not remedy_exec.valid_system_label("cOm.ApPlE.x")
