"""Cleanix test suite — core safety, engine, config, reset and quarantine."""

import os
from pathlib import Path

import pytest

from cleanix.cleaners.base import SCOPE_SYSTEM
from cleanix.config import Config, coerce_value
from cleanix import reset
from cleanix.core import context, quarantine, safety
from cleanix.core.context import TargetUser
from cleanix.core.engine import Engine
from cleanix.core.models import CleanableItem, CleanerReport, ItemKind, ScanResult
from cleanix.core.platform import ALL, LINUX, MACOS, supports
from cleanix.core.registry import build_cleaners
from cleanix.core.utils import human_size, surplus_after_keeping


# --------------------------------------------------------------------------- safety
@pytest.mark.parametrize("bad", ["/", "/etc", "/usr", "/boot", "/System", "/Library"])
def test_protected_system_paths_refused(bad):
    assert not safety.is_safe_to_delete(bad)


def test_home_and_config_protected():
    home = os.path.expanduser("~")
    assert not safety.is_safe_to_delete(home)
    assert not safety.is_safe_to_delete(home + "/.config")
    assert safety.is_safe_to_delete(home + "/.cache/some-app")


def test_ancestor_of_protected_refused(tmp_path):
    # A path that contains a protected root must be refused.
    assert not safety.is_safe_to_delete("/")


def test_protected_globs(tmp_path):
    safety.set_protected_globs([str(tmp_path) + "/keep*"])
    try:
        assert not safety.is_safe_to_delete(tmp_path / "keepme")
        assert safety.is_safe_to_delete(tmp_path / "other")
    finally:
        safety.set_protected_globs([])


def test_safe_rmtree_refuses_protected():
    with pytest.raises(safety.UnsafePathError):
        safety.safe_rmtree("/etc")


# --------------------------------------------------------------------------- engine
def _item(path, size=100, **kw):
    return CleanableItem("t", "junk", size, ItemKind.PATH, str(path), **kw)


def test_dry_run_does_not_delete(tmp_path):
    d = tmp_path / "d"; d.mkdir(); (d / "f").write_text("x")
    res = Engine([]).clean([_item(d)], dry_run=True)
    assert d.exists() and res.freed == 100 and res.removed_count == 0


def test_execute_deletes(tmp_path):
    d = tmp_path / "d"; d.mkdir(); (d / "f").write_text("x")
    res = Engine([]).clean([_item(d)], dry_run=False)
    assert not d.exists() and res.removed_count == 1


def test_report_only_never_deleted(tmp_path):
    d = tmp_path / "d"; d.mkdir()
    res = Engine([]).clean([_item(d, report_only=True)], dry_run=False)
    assert d.exists() and not res.outcomes[0].removed


def test_root_item_skipped_without_privilege(tmp_path):
    d = tmp_path / "d"; d.mkdir()
    res = Engine([]).clean([_item(d, requires_root=True)],
                           dry_run=False, allow_root_items=False)
    assert d.exists() and "root" in (res.outcomes[0].error or "")


def test_protected_path_item_refused():
    res = Engine([]).clean([_item("/etc", size=0)], dry_run=False)
    assert not res.outcomes[0].removed and os.path.isdir("/etc")


def test_parallel_scan_matches_sequential():
    eng = Engine(build_cleaners(Config()))
    seq = {r.cleaner_id for r in eng.scan(parallel=False).reports}
    par = {r.cleaner_id for r in eng.scan(parallel=True).reports}
    assert seq == par


# --------------------------------------------------------------------------- models
def test_scanresult_splits_cleanable_and_report_only():
    a = _item("/tmp/a"); b = _item("/tmp/b", report_only=True)
    sr = ScanResult([CleanerReport("t", "t", "", [a, b])])
    assert sr.cleanable_items() == [a]
    assert sr.report_only_items() == [b]
    assert sr.cleanable_size == 100 and sr.report_only_size == 100


# --------------------------------------------------------------------------- retention
def test_surplus_after_keeping(tmp_path):
    files = []
    for i in range(5):
        f = tmp_path / f"b{i}"; f.write_text("x")
        os.utime(f, (1000 + i, 1000 + i))
        files.append(f)
    surplus = surplus_after_keeping(files, 2)
    assert {p.name for p in surplus} == {"b0", "b1", "b2"}   # 3 oldest
    assert surplus_after_keeping(files, 0) == sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)


# --------------------------------------------------------------------------- config
def test_coerce_value_types():
    assert coerce_value("keep_kernels", "4") == 4
    assert coerce_value("remove_old_kernels", "off") is False
    assert coerce_value("temp_min_age_days", "1.5") == 1.5
    assert coerce_value("browsers", "a, b ,c") == ["a", "b", "c"]
    with pytest.raises(ValueError):
        coerce_value("remove_old_kernels", "maybe")
    with pytest.raises(KeyError):
        coerce_value("nonsense", "1")


def test_config_override_roundtrip(tmp_path):
    from cleanix import config as cfgmod

    p = tmp_path / "config.yaml"
    cfgmod.write_user_override("keep_kernels", 5, path=p)
    assert cfgmod.read_user_overrides(p)["keep_kernels"] == 5
    assert cfgmod.remove_user_override("keep_kernels", path=p) is True
    assert "keep_kernels" not in cfgmod.read_user_overrides(p)


# --------------------------------------------------------------------------- platform
def test_platform_supports():
    from cleanix.core.platform import current_os

    assert supports((ALL,))
    assert supports((current_os(),))
    assert not supports(("nonexistent-os",))


# --------------------------------------------------------------------------- context
def test_multi_user_iteration_and_dedup(tmp_path):
    from cleanix.cleaners.base import Cleaner, SCOPE_USER

    h1 = tmp_path / "u1"; (h1 / ".cache" / "j").mkdir(parents=True)
    h2 = tmp_path / "u2"; (h2 / ".cache" / "j").mkdir(parents=True)
    u1 = TargetUser("u1", h1, 4001, 4001, False)
    u2 = TargetUser("u2", h2, 4002, 4002, False)
    context._cached_targets = [u1, u2]
    try:
        class Shared(Cleaner):
            id = "shared"; scope = SCOPE_USER
            def find_items(self):
                yield CleanableItem("shared", "x", 0, ItemKind.PATH, "/usr/local/bin/tool")
        # shared path yielded per user collapses to one
        assert len(Shared(Config()).scan().items) == 1
    finally:
        context._cached_targets = None


# --------------------------------------------------------------------------- reset
@pytest.mark.parametrize("strategy,cmd0", [
    ("nixos", ["nixos-rebuild", "switch", "--rollback"]),
    ("ostree", ["rpm-ostree", "reset"]),
    ("guix", ["guix", "system", "roll-back"]),
])
def test_reset_actions(monkeypatch, strategy, cmd0):
    monkeypatch.setattr(reset, "_detect_strategy", lambda: strategy)
    plan = reset.build_plan("full")
    assert plan.reversible and plan.actions[0].command == cmd0


def test_reset_traditional_not_reversible(monkeypatch):
    monkeypatch.setattr(reset, "_detect_strategy", lambda: "traditional")
    plan = reset.build_plan("full")
    assert not plan.reversible and not plan.actions


def test_execute_actions_stops_on_failure(monkeypatch):
    monkeypatch.setattr(reset, "_detect_strategy", lambda: "ostree")
    plan = reset.build_plan("full")
    plan.actions.append(reset.ResetAction("second", ["true"]))
    calls = []
    def runner(cmd):
        calls.append(cmd)
        return 1 if cmd == ["rpm-ostree", "reset"] else 0
    results = reset.execute_actions(plan, runner)
    assert len(results) == 1 and calls == [["rpm-ostree", "reset"]]  # stopped


# --------------------------------------------------------------------------- quarantine
@pytest.fixture
def qroot(tmp_path, monkeypatch):
    root = tmp_path / "quar"
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: root)
    return root


def test_quarantine_roundtrip(tmp_path, qroot):
    junk = tmp_path / "junk"; junk.mkdir(); (junk / "f").write_text("x" * 500)
    run = quarantine.new_run()
    Engine([]).clean([_item(junk, 500)], dry_run=False, quarantine=run)
    run.save()
    assert not junk.exists()
    assert any(r["run_id"] == run.run_id for r in quarantine.list_runs())

    res = quarantine.restore(run.run_id)
    assert junk.exists() and (junk / "f").read_text() == "x" * 500
    assert not res["failed"]


def test_quarantine_purge(tmp_path, qroot):
    junk = tmp_path / "junk"; junk.mkdir(); (junk / "f").write_text("y" * 300)
    run = quarantine.new_run()
    Engine([]).clean([_item(junk, 300)], dry_run=False, quarantine=run)
    run.save()
    freed = quarantine.purge_all()
    assert freed > 0 and quarantine.total_size() == 0


# --------------------------------------------------------------------------- opt-in / memory
def test_memory_cleaners_are_opt_in_only():
    default_ids = {c.id for c in build_cleaners(Config())}
    assert "memory" not in default_ids and "swap" not in default_ids
    forced = {c.id for c in build_cleaners(Config(), only=["memory", "swap"])}
    assert "memory" in forced


def test_swap_guard_refuses_when_ram_too_low(monkeypatch):
    from cleanix.cleaners import memory

    # Swap used (2G) with little available RAM (1G) → must NOT offer swapoff.
    monkeypatch.setattr(memory, "_meminfo", lambda: {
        "SwapTotal": 2 * 1024**3, "SwapFree": 0,
        "MemAvailable": 1 * 1024**3,
    })
    assert list(memory.SwapReclaimCleaner(Config()).find_items()) == []
    # Plenty of RAM (8G) → offers it.
    monkeypatch.setattr(memory, "_meminfo", lambda: {
        "SwapTotal": 2 * 1024**3, "SwapFree": 0,
        "MemAvailable": 8 * 1024**3,
    })
    items = list(memory.SwapReclaimCleaner(Config()).find_items())
    assert len(items) == 1 and "swapoff" in " ".join(items[0].command)


# --------------------------------------------------------------------------- completion
@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_completion_generates(shell):
    from cleanix.completion import generate

    script = generate(shell)
    assert "cleanix" in script and "scan" in script and len(script) > 100


# --------------------------------------------------------------------------- containers
def _fake_docker(monkeypatch, **cfg):
    from cleanix.cleaners import containers

    monkeypatch.setattr(containers._ContainerCleaner, "_df_reclaimable", lambda self: {
        "Images": 8_000_000_000,       # 8 GB unused (incl. tagged, non-dangling)
        "Containers": 50_000_000,
        "Local Volumes": 2_000_000_000,
        "Build Cache": 3_000_000_000,
    })
    monkeypatch.setattr(containers._ContainerCleaner, "_dangling_images_size",
                        lambda self: 1_200_000_000)   # only 1.2 GB is dangling
    monkeypatch.setattr(containers._ContainerCleaner, "_stopped_containers",
                        lambda self: (2, 50_000_000))
    monkeypatch.setattr(containers._ContainerCleaner, "_unused_networks",
                        lambda self: 3)
    cfg_obj = Config()
    for k, v in cfg.items():
        setattr(cfg_obj, k, v)
    return list(containers.DockerCleaner(cfg_obj).find_items())


def test_docker_default_prunes_only_dangling_images(monkeypatch):
    items = _fake_docker(monkeypatch)
    by_cmd = {" ".join(i.command): i for i in items}
    # Default: dangling image prune, sized to dangling only — NOT the 8 GB
    # "Reclaimable" total that plain prune would never remove.
    assert "docker image prune -f" in by_cmd
    assert by_cmd["docker image prune -f"].size == 1_200_000_000
    assert "docker image prune -a -f" not in by_cmd
    # Volumes are opt-in, so their 2 GB is not counted by default.
    assert not any("volume" in c for c in by_cmd)
    assert {"docker container prune -f", "docker builder prune -f",
            "docker network prune -f"} <= set(by_cmd)


def test_docker_opt_in_all_images_and_volumes(monkeypatch):
    items = _fake_docker(monkeypatch, docker_prune_all_images=True,
                         docker_prune_volumes=True)
    by_cmd = {" ".join(i.command): i for i in items}
    assert by_cmd["docker image prune -a -f"].size == 8_000_000_000
    assert "docker image prune -f" not in by_cmd
    # Docker needs `-a` to prune named volumes so the size matches the action.
    assert by_cmd["docker volume prune -a -f"].size == 2_000_000_000


def test_docker_nothing_to_clean_yields_no_items(monkeypatch):
    from cleanix.cleaners import containers

    monkeypatch.setattr(containers._ContainerCleaner, "_df_reclaimable", lambda self: {})
    monkeypatch.setattr(containers._ContainerCleaner, "_dangling_images_size", lambda self: 0)
    monkeypatch.setattr(containers._ContainerCleaner, "_stopped_containers", lambda self: (0, 0))
    monkeypatch.setattr(containers._ContainerCleaner, "_unused_networks", lambda self: 0)
    assert list(containers.DockerCleaner(Config()).find_items()) == []


def test_docker_parse_size():
    from cleanix.cleaners.containers import _parse_size

    # Docker/Podman render sizes in DECIMAL (1000-based) go-units.
    assert _parse_size("1.2GB") == int(1.2 * 1000**3)
    assert _parse_size("45.6MB (virtual 1.2GB)") == int(45.6 * 1000**2)  # first token
    assert _parse_size("500kB") == 500_000
    assert _parse_size("0B") == 0
    assert _parse_size("") == 0


def test_docker_stopped_containers_no_dead_filter(monkeypatch):
    # Podman rejects `status=dead`; ensure we never send it.
    from cleanix.cleaners import containers

    captured = {}

    def fake_run(cmd, timeout=30):
        captured["cmd"] = cmd
        return 0, "", ""

    monkeypatch.setattr(containers, "run_command", fake_run)
    containers.DockerCleaner(Config())._stopped_containers()
    assert "status=dead" not in captured["cmd"]
    assert "status=exited" in captured["cmd"]


# --------------------------------------------------------------------------- scheduler
def test_scheduler_backend_per_os(monkeypatch):
    import cleanix.scheduler as sched

    monkeypatch.setattr(sched, "is_macos", lambda: True)
    monkeypatch.setattr(sched, "is_bsd", lambda: False)
    assert sched.backend().__name__.endswith("launchd")

    monkeypatch.setattr(sched, "is_macos", lambda: False)
    monkeypatch.setattr(sched, "is_bsd", lambda: True)
    assert sched.backend().__name__.endswith("cron")

    monkeypatch.setattr(sched, "is_bsd", lambda: False)
    monkeypatch.setattr(sched.shutil, "which",
                        lambda c: "/usr/bin/systemctl" if c == "systemctl" else None)
    assert sched.backend().__name__.endswith("systemd")


def test_cron_block_roundtrip(monkeypatch):
    from cleanix.scheduler import cron

    monkeypatch.setattr(cron.shutil, "which", lambda c: "/usr/bin/" + c)
    store = {"body": "MAILTO=me\n0 0 * * * echo hi\n"}
    monkeypatch.setattr(cron, "_crontab_read", lambda: store["body"])
    monkeypatch.setattr(cron, "_crontab_write",
                        lambda body: (store.__setitem__("body", body), (0, ""))[1])
    cron.install("daily")
    assert cron.BEGIN in store["body"] and "scan --json" in store["body"]
    assert "MAILTO=me" in store["body"]  # existing entries preserved
    cron.uninstall()
    assert cron.BEGIN not in store["body"]
    assert "MAILTO=me" in store["body"]


def test_config_numeric_errors_are_friendly():
    from cleanix.config import coerce_value

    with pytest.raises(ValueError, match="expected an integer"):
        coerce_value("keep_kernels", "notanint")
    with pytest.raises(ValueError, match="expected a number"):
        coerce_value("temp_min_age_days", "abc")


@pytest.mark.parametrize("freq,key", [
    ("hourly", "StartInterval"),
    ("daily", "StartCalendarInterval"),
    ("weekly", "StartCalendarInterval"),
    ("monthly", "StartCalendarInterval"),
])
def test_launchd_plist_valid(freq, key):
    import plistlib
    from cleanix.scheduler import launchd

    # dumps() raises if the dict isn't a serializable plist; loads() round-trips.
    data = plistlib.loads(plistlib.dumps(launchd._plist(freq)))
    assert data["Label"] == "com.cleanix.scan"
    assert key in data
    assert data["ProgramArguments"][0] == "/bin/sh"
    assert data["RunAtLoad"] is False


# ----------------------------------------------------- macOS field-report fixes
def test_path_item_survives_permission_error():
    # SIP-protected /Library/Caches entries make Path.exists() raise EPERM;
    # a cleaner must skip them, not abort the whole scan.
    from cleanix.cleaners import base

    class Sip:
        def exists(self):
            raise PermissionError(1, "Operation not permitted")

        def is_symlink(self):
            raise PermissionError(1, "Operation not permitted")

    assert base._path_present(Sip()) is False


def test_sleepimage_reported_once(monkeypatch):
    # /var -> /private/var symlink used to double-count the hibernation image.
    from cleanix.cleaners import macos_extra

    monkeypatch.setattr(macos_extra.Path, "exists", lambda self: True)
    monkeypatch.setattr(macos_extra.os.path, "realpath",
                        lambda p: "/private/var/vm/sleepimage")
    items = list(macos_extra.MacSleepImageReporter(Config()).find_items())
    assert len(items) == 1 and items[0].report_only


def test_homebrew_skips_as_root(monkeypatch):
    from cleanix.cleaners import macos

    monkeypatch.setattr(macos, "which", lambda c: "/usr/bin/brew")
    monkeypatch.setattr(macos.os, "geteuid", lambda: 0)
    assert "root" in (macos.HomebrewCleaner(Config()).available() or "")
    monkeypatch.setattr(macos.os, "geteuid", lambda: 501)
    assert macos.HomebrewCleaner(Config()).available() is None


def test_xcode_offers_simctl_only_when_present(monkeypatch):
    from cleanix.cleaners import macos

    monkeypatch.setattr(macos, "which",
                        lambda c: "/usr/bin/xcrun" if c == "xcrun" else None)

    def simctl(items):
        return [i for i in items if i.command and "simctl" in i.command]

    monkeypatch.setattr(macos, "run_command", lambda *a, **k: (1, "", "not found"))
    assert not simctl(list(macos.XcodeCleaner(Config()).find_items()))

    monkeypatch.setattr(macos, "run_command", lambda *a, **k: (0, "/x/simctl", ""))
    assert simctl(list(macos.XcodeCleaner(Config()).find_items()))


def test_container_skips_when_engine_down(monkeypatch):
    from cleanix.cleaners import containers

    monkeypatch.setattr(containers, "which", lambda c: "/usr/bin/docker")
    monkeypatch.setattr(containers, "run_command", lambda *a, **k: (1, "", "no socket"))
    assert "not running" in containers.DockerCleaner(Config()).available()
    monkeypatch.setattr(containers, "run_command", lambda *a, **k: (0, "ok", ""))
    assert containers.DockerCleaner(Config()).available() is None


def test_scan_all_users_dedupes_identical_commands(monkeypatch):
    # A per-user cleaner yielding a fixed command must appear once, not once
    # per target user, when running as root.
    import contextlib
    from cleanix.cleaners import base

    monkeypatch.setattr(base, "get_target_users", lambda: ["u1", "u2"])
    monkeypatch.setattr(base, "use_user", lambda u: contextlib.nullcontext())

    class C(base.Cleaner):
        id = "c"; name = "c"; description = ""

        def find_items(self):
            yield self.command_item(["brew", "cleanup"], "x")

    assert len(C(Config())._scan_all_users()) == 1


# ------------------------------------------------------ safety: symlink handling
def test_safe_rmtree_never_follows_symlink_to_real_data(tmp_path):
    # The C1 data-loss bug: deleting a symlinked "cache" wiped its target.
    precious = tmp_path / "precious"
    precious.mkdir()
    (precious / "thesis.txt").write_text("keep me")
    cache = tmp_path / "cache"
    cache.mkdir()
    link = cache / "app-cache"
    link.symlink_to(precious)

    safety.safe_rmtree(str(link))

    assert precious.exists() and (precious / "thesis.txt").exists()  # survives
    assert not link.exists()  # the link itself is gone


def test_safe_rmtree_removes_broken_symlink(tmp_path):
    # C1b: broken-symlink removal used to be a silent no-op.
    link = tmp_path / "dead"
    link.symlink_to(tmp_path / "does-not-exist")
    safety.safe_rmtree(str(link))
    assert not link.is_symlink() and not link.exists()


def test_protected_home_includes_credentials(monkeypatch, tmp_path):
    monkeypatch.setattr(safety, "_home_dirs", lambda: [tmp_path])
    for name in (".ssh", ".gnupg", ".local/state", "Music", "Videos"):
        assert not safety.is_safe_to_delete(tmp_path / name)
    # but ordinary cache dirs stay deletable
    assert safety.is_safe_to_delete(tmp_path / ".cache" / "app")


def test_dollar_sign_filename_not_reexpanded(tmp_path):
    # M2: a real file named with $VAR must be treated literally, not rewritten.
    target = tmp_path / "foo$BAR"
    target.mkdir()
    resolved = safety._canonical(str(target))
    assert resolved.name == "foo$BAR"


# ------------------------------------------------------ toolchain versions
def _mk_pyenv(tmp_path, versions, active):
    import os as _os
    import time as _time

    root = tmp_path / ".pyenv" / "versions"
    root.mkdir(parents=True)
    for i, v in enumerate(versions):
        (root / v).mkdir()
        t = _time.time() - (100 - i) * 86400  # later in list => newer
        _os.utime(root / v, (t, t))
    if active is not None:
        (tmp_path / ".pyenv" / "version").write_text(active + "\n")
    return root


def test_toolchains_protects_active_keeps_newest(tmp_path, monkeypatch):
    from cleanix.cleaners import toolchains

    _mk_pyenv(tmp_path, ["3.9.0", "3.10.0", "3.11.0", "3.12.0"], active="3.9.0")
    monkeypatch.setattr(toolchains, "home", lambda: tmp_path)
    cfg = Config()
    cfg.keep_toolchain_versions = 1
    items = list(toolchains.ToolchainVersionCleaner(cfg).find_items())
    names = {os.path.basename(i.path) for i in items}
    # active 3.9.0 protected; newest-1 (3.12.0) kept; prune 3.10.0 + 3.11.0
    assert names == {"3.10.0", "3.11.0"}
    assert all(not i.report_only for i in items)  # deletable (reversible via -q)


def test_toolchains_fail_safe_when_active_unknown(tmp_path, monkeypatch):
    from cleanix.cleaners import toolchains

    _mk_pyenv(tmp_path, ["3.9.0", "3.10.0", "3.11.0"], active=None)  # no version file
    monkeypatch.setattr(toolchains, "home", lambda: tmp_path)
    assert list(toolchains.ToolchainVersionCleaner(Config()).find_items()) == []


def test_toolchains_disabled_by_config(tmp_path, monkeypatch):
    from cleanix.cleaners import toolchains

    _mk_pyenv(tmp_path, ["3.9.0", "3.10.0", "3.11.0"], active="3.9.0")
    monkeypatch.setattr(toolchains, "home", lambda: tmp_path)
    cfg = Config()
    cfg.prune_old_toolchains = False
    assert list(toolchains.ToolchainVersionCleaner(cfg).find_items()) == []


# ------------------------------------------------------ report-only finders
def test_big_files_surfaces_only_large_report_only(tmp_path, monkeypatch):
    from cleanix.cleaners import big_files

    monkeypatch.setattr(big_files, "home", lambda: tmp_path)
    (tmp_path / "big.bin").write_bytes(b"\xff" * 3 * 1024 * 1024)
    (tmp_path / "small.txt").write_bytes(b"x" * 1024)
    import os as _os
    import time as _time
    old = _time.time() - 3600
    _os.utime(tmp_path / "big.bin", (old, old))
    cfg = Config()
    cfg.big_file_min_size_mb = 1.0
    items = list(big_files.BigFileReporter(cfg).find_items())
    assert [os.path.basename(i.path) for i in items] == ["big.bin"]
    assert all(i.report_only for i in items)


def test_downloads_surfaces_old_large_report_only(tmp_path, monkeypatch):
    import os as _os
    import time as _time
    from cleanix.cleaners import downloads

    dl = tmp_path / "Downloads"
    dl.mkdir()
    monkeypatch.setattr(downloads, "home", lambda: tmp_path)
    big_old = dl / "ubuntu.iso"
    big_old.write_bytes(b"x" * 60 * 1024 * 1024)
    t = _time.time() - 120 * 86400
    _os.utime(big_old, (t, t))
    (dl / "recent.iso").write_bytes(b"x" * 60 * 1024 * 1024)  # too recent
    items = list(downloads.DownloadsReporter(Config()).find_items())
    assert [os.path.basename(i.path) for i in items] == ["ubuntu.iso"]
    assert all(i.report_only for i in items)


def test_project_cruft_reports_stale_only(tmp_path, monkeypatch):
    import os as _os
    import time as _time

    from cleanix.cleaners.project_cruft import ProjectCruftCleaner

    def mkproj(name, stale):
        proj = tmp_path / name
        (proj / "node_modules" / "sub").mkdir(parents=True)
        (proj / "main.py").write_text("x")
        if stale:
            old = _time.time() - 300 * 86400
            for dp, _dirs, files in _os.walk(proj):
                _os.utime(dp, (old, old))
                for f in files:
                    _os.utime(_os.path.join(dp, f), (old, old))

    mkproj("old", stale=True)
    mkproj("fresh", stale=False)
    cfg = Config()
    cfg.project_scan_dirs = [str(tmp_path)]
    cfg.project_stale_days = 120
    items = list(ProjectCruftCleaner(cfg).find_items())
    paths = [i.path for i in items]
    assert any("old" in p and p.endswith("node_modules") for p in paths)
    assert not any("fresh" in p for p in paths)
    assert all(i.report_only for i in items)


# ------------------------------------------------------ containerd (nerdctl)
def test_nerdctl_inherits_docker_itemization(monkeypatch):
    from cleanix.cleaners import containerd, containers

    monkeypatch.setattr(containers._ContainerCleaner, "_df_reclaimable",
                        lambda self: {"Images": 8_000_000_000,
                                      "Build Cache": 3_000_000_000})
    monkeypatch.setattr(containers._ContainerCleaner, "_dangling_images_size",
                        lambda self: 1_200_000_000)
    monkeypatch.setattr(containers._ContainerCleaner, "_stopped_containers",
                        lambda self: (2, 50_000_000))
    monkeypatch.setattr(containers._ContainerCleaner, "_unused_networks",
                        lambda self: 1)
    by_cmd = {" ".join(i.command): i
              for i in containerd.NerdctlCleaner(Config()).find_items()}
    assert by_cmd["nerdctl image prune -f"].size == 1_200_000_000
    assert by_cmd["nerdctl builder prune -f"].size == 3_000_000_000


# ------------------------------------------------------ CLI features
def test_cli_parse_size():
    from cleanix.cli import _parse_size

    assert _parse_size("100M") == 100 * 1024**2
    assert _parse_size("1.5G") == int(1.5 * 1024**3)
    assert _parse_size(None) == 0


def test_cli_apply_profile():
    from cleanix.cli import _apply_profile

    agg = _apply_profile(Config(), "aggressive")
    assert agg.docker_prune_all_images and agg.include_offline_repos
    assert not agg.docker_prune_volumes  # volumes are never bundled
    safe = _apply_profile(Config(), "safe")
    assert not safe.remove_old_kernels and not safe.remove_backup_files


def test_cli_min_size_filters_paths_not_commands():
    from cleanix.cli import _apply_min_size

    small = CleanableItem("t", "small", 10, ItemKind.PATH, "/tmp/a")
    big = CleanableItem("t", "big", 10**9, ItemKind.PATH, "/tmp/b")
    cmd = CleanableItem("t", "cmd", 0, ItemKind.COMMAND, command=["docker", "x"])
    sr = ScanResult([CleanerReport("t", "t", "", [small, big, cmd])])
    _apply_min_size(sr, 1000)
    descs = {i.description for i in sr.all_items()}
    assert descs == {"big", "cmd"}  # small path dropped, command kept


def test_write_manifest_records_removed(tmp_path, monkeypatch):
    from cleanix.core import history
    from cleanix.core.models import CleanOutcome, CleanResult

    monkeypatch.setattr(history, "state_dir", lambda: tmp_path)
    item = CleanableItem("trash", "junk", 100, ItemKind.PATH, "/tmp/x")
    res = CleanResult([CleanOutcome(item, removed=True, freed=100)], dry_run=False)
    path = history.write_manifest(res)
    assert path and Path(path).exists()
    assert "trash" in Path(path).read_text()
    # dry-runs write nothing
    dry = CleanResult([CleanOutcome(item, removed=False)], dry_run=True)
    assert history.write_manifest(dry) == ""


def test_scan_to_dict_schema(monkeypatch):
    from cleanix.core.report import scan_to_dict

    d = scan_to_dict(ScanResult([]))
    for key in ("schema_version", "cleanix_version", "cleanable_bytes",
                "report_only_bytes", "generated_at", "os"):
        assert key in d


# --------------------------------------------------------------------------- utils
def test_human_size():
    assert human_size(0) == "0 B"
    assert human_size(1024) == "1.0 KiB"
    assert human_size(1024 ** 3) == "1.0 GiB"
