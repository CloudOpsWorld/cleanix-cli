"""Foundation for the orphan reports: budget, walker, ownership, reporter."""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path

import pytest

from cleanix.cleaners import base, orphan_common as oc
from cleanix.cleaners.base import SCOPE_USER
from cleanix.config import Config

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="needs POSIX symlinks/paths"
)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_run_refuses_non_allowlisted_commands(monkeypatch):
    called = []
    monkeypatch.setattr(oc, "run_command", lambda *a, **k: called.append(a))
    assert oc.run(["rm", "-rf", "/x"]) == (126, "", "refused")
    assert oc.run(["dpkg-query"]) == (126, "", "refused")
    assert called == []


def test_run_prefixes_c_locale(monkeypatch):
    seen = []
    monkeypatch.setattr(
        oc, "run_command",
        lambda argv, timeout=120: seen.append(list(argv)) or (0, "", ""),
    )
    assert oc.run(["dpkg-query", "-S", "/x"]) == (0, "", "")
    assert seen[0][:4] == ["env", "LC_ALL=C", "dpkg-query", "-S"]


def test_budget_item_and_time_limits():
    clk = Clock()
    b = oc.ScanBudget(2, 10.0, clk)
    assert b.take() and b.take()
    assert not b.take()
    assert b.stop_reason == "item limit"
    b2 = oc.ScanBudget(5, 10.0, clk)
    assert not b2.expired()
    clk.t = 11.0
    assert b2.expired()
    assert b2.stop_reason == "time limit"
    assert not b2.take()


def _tree(tmp_path):
    d = tmp_path / "d"
    (d / "sub").mkdir(parents=True)
    (d / "a.bin").write_bytes(b"x" * 20000)
    (d / "sub" / "b.bin").write_bytes(b"y" * 30000)
    return d


def test_bounded_size_skips_other_devices(tmp_path, monkeypatch):
    d = _tree(tmp_path)
    full, ok = oc.bounded_size(d, oc.ScanBudget(10, 100))
    assert ok and full > 0
    real = oc.device_of
    monkeypatch.setattr(
        oc, "device_of", lambda p: 999 if Path(p).name == "sub" else real(p)
    )
    part, ok2 = oc.bounded_size(d, oc.ScanBudget(10, 100))
    assert ok2 and part < full


@posix_only
def test_bounded_size_skips_symlinks(tmp_path):
    d = _tree(tmp_path)
    big = tmp_path / "elsewhere"
    big.mkdir()
    (big / "huge.bin").write_bytes(b"z" * 500000)
    base_size, _ = oc.bounded_size(d, oc.ScanBudget(10, 100))
    (d / "lnk").symlink_to(big, target_is_directory=True)
    (d / "flnk").symlink_to(big / "huge.bin")
    size, ok = oc.bounded_size(d, oc.ScanBudget(10, 100))
    assert ok and size == base_size  # target bytes not counted


def test_bounded_size_stops_when_expired(tmp_path):
    d = _tree(tmp_path)
    clk = Clock()
    b = oc.ScanBudget(10, 1.0, clk)
    clk.t = 5.0
    size, complete = oc.bounded_size(d, b)
    assert complete is False


def test_list_dir_permission_error_returns_none(tmp_path, monkeypatch):
    def boom(p):
        raise PermissionError("no")

    monkeypatch.setattr(os, "scandir", boom)
    assert oc.list_dir(tmp_path) is None


def test_list_dir_missing_and_present(tmp_path):
    assert oc.list_dir(tmp_path / "nope") == []
    (tmp_path / "f").write_text("x")
    assert oc.list_dir(tmp_path) == [tmp_path / "f"]


def test_parse_dpkg_needs_positive_evidence():
    paths = ["/opt/a", "/opt/b", "/opt/c"]
    out = "foo: /opt/a\n"
    err = "dpkg-query: no path found matching pattern /opt/b\n"
    assert oc.parse_dpkg(paths, 1, out, err) == {"/opt/b"}
    assert oc.parse_dpkg(paths, 2, out, err) is None
    # localized/garbled output proves nothing
    assert oc.parse_dpkg(paths, 1, "", "dpkg-query: kein Pfad gefunden\n") == set()


def test_parse_rpm_needs_positive_evidence():
    paths = ["/opt/a", "/opt/b"]
    out = "foo-1.0\nfile /opt/b is not owned by any package\n"
    assert oc.parse_rpm(paths, 1, out, "") == {"/opt/b"}
    assert oc.parse_rpm(paths, 2, out, "") is None
    assert oc.parse_rpm(paths, 1, "", "") == set()


def test_parse_pacman_needs_positive_evidence():
    paths = ["/opt/a", "/opt/b"]
    err = "error: No package owns /opt/b\n"
    assert oc.parse_pacman(paths, 1, "/opt/a is owned by foo 1-1\n", err) == {"/opt/b"}
    assert oc.parse_pacman(paths, 124, "", err) is None
    assert oc.parse_pacman(paths, 1, "", "") == set()


def test_query_unowned_batches(orphan_env):
    orphan_env.cmds.on(("dpkg-query", "-S"), rc=0)
    paths = [f"/opt/p{i}" for i in range(250)] + ["/opt/gl*ob"]
    oc.query_unowned("dpkg", paths, oc.ScanBudget(10, 100))
    calls = [c for c in orphan_env.cmds.calls if c[:2] == ["dpkg-query", "-S"]]
    assert len(calls) == 3
    assert all("/opt/gl*ob" not in c for c in calls)


def test_query_unowned_finds_unowned(orphan_env):
    orphan_env.cmds.on(
        ("dpkg-query", "-S"), rc=1,
        err="dpkg-query: no path found matching pattern /opt/b\n",
    )
    got = oc.query_unowned("dpkg", ["/opt/a", "/opt/b"], oc.ScanBudget(10, 100))
    assert got == {"/opt/b"}


def test_query_unowned_unknown_batch_reports_nothing(orphan_env):
    orphan_env.cmds.on(
        ("dpkg-query", "-S"), rc=124,
        err="dpkg-query: no path found matching pattern /opt/b\n",
    )
    assert oc.query_unowned("dpkg", ["/opt/b"], oc.ScanBudget(10, 100)) == set()


def test_installed_package_names(orphan_env):
    orphan_env.cmds.on(("dpkg-query", "-W"), out="a\nb\n\n")
    assert oc.installed_package_names("dpkg") == {"a", "b"}
    orphan_env.cmds.on(("pacman", "-Qq"), rc=1)
    assert oc.installed_package_names("pacman") is None
    assert oc.installed_package_names("nix") is None


def test_system_account_names(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text(
        "root:x:0:0::/root:/bin/sh\nmysql:x:1:1\n"
    )
    assert oc.system_account_names(tmp_path) == {"root", "mysql"}
    assert oc.system_account_names(tmp_path / "none") == set()


def test_detect_backend_by_family(orphan_env):
    t = orphan_env.cmds.tools
    t.update({"dpkg-query", "rpm", "pacman"})
    assert oc.detect_pkg_backend({"ubuntu"}) == "dpkg"
    assert oc.detect_pkg_backend({"fedora"}) == "rpm"
    assert oc.detect_pkg_backend({"arch"}) == "pacman"
    assert oc.detect_pkg_backend({"alpine"}) is None
    t.discard("dpkg-query")
    assert oc.detect_pkg_backend({"debian"}) is None


def test_name_matches():
    assert oc.name_matches("postgresql", {"postgresql-16"})
    assert oc.name_matches("NetworkManager", {"network-manager"})
    assert oc.name_matches("mysql", {"mysql-server-8.0"})
    assert not oc.name_matches("ucf", {"ucfx"})
    assert not oc.name_matches("myapp", {"mya"})
    assert not oc.name_matches("---", {"x"})


def test_owner_check_command_quotes():
    assert oc.owner_check_command("dpkg", "/opt/My App") == "dpkg -S '/opt/My App'"
    assert oc.owner_check_command("rpm", "/opt/x") == "rpm -qf /opt/x"
    assert oc.owner_check_command("pacman", "/opt/x") == "pacman -Qo /opt/x"
    assert oc.owner_check_command("pkgutil", "/opt/x") == "pkgutil --file-info /opt/x"
    assert oc.owner_check_command(None, "/opt/x") is None


def test_safe_label_and_bad_name():
    assert oc.safe_label("a\nb\x00c\x1b") == "a?b?c?"
    assert len(oc.safe_label("x" * 500)) == 200
    assert oc.bad_name("a\nb") and oc.bad_name("a\rb") and oc.bad_name("a\0b")
    assert not oc.bad_name("a b")


def test_is_removable_location():
    assert oc.is_removable_location("/media/u/x")
    assert oc.is_removable_location("/Volumes/Ext/a")
    assert oc.is_removable_location("/run/media/u/x")
    assert not oc.is_removable_location("/opt/x")


def test_path_helpers(tmp_path):
    p = oc.in_root(tmp_path, "/opt/x")
    assert p == tmp_path / "opt" / "x"
    assert oc.logical_path(tmp_path, p) == "/opt/x"
    assert oc.in_root("/", "/opt/x") == Path("/opt/x")


@posix_only
def test_link_target_exists(tmp_path):
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "usr" / "bin" / "real").write_text("x")
    d = tmp_path / "etc"
    d.mkdir()
    (d / "abs-ok").symlink_to("/usr/bin/real")
    (d / "abs-bad").symlink_to("/usr/bin/gone")
    (d / "rel-ok").symlink_to("../usr/bin/real")
    (d / "null").symlink_to("/dev/null")
    assert oc.link_target_exists(d / "abs-ok", tmp_path) is True
    assert oc.link_target_exists(d / "abs-bad", tmp_path) is False
    assert oc.link_target_exists(d / "rel-ok", tmp_path) is True
    assert oc.link_target_exists(d / "null", tmp_path) is True
    assert oc.link_target_exists(d / "not-a-link", tmp_path) is None


def test_reporter_system_part_once_user_part_per_user(orphan_env, monkeypatch):
    cur = {"u": None}

    class D(oc.OrphanReporter):
        id = "dummy"
        name = "dummy"
        description = ""
        scope = SCOPE_USER

        def system_findings(self):
            yield self.note(Path(self.sysroot) / "sys", "sys thing", "hint-s")

        def user_findings(self):
            yield oc.Finding(
                orphan_env.home / cur["u"] / "thing", "user thing", "hint-u",
                requires_root=False,
            )

    monkeypatch.setattr(base, "get_target_users", lambda: ["u1", "u2"])

    def fake_use(u):
        cur["u"] = u
        return contextlib.nullcontext()

    monkeypatch.setattr(base, "use_user", fake_use)
    items = D(Config()).scan().items
    assert len(items) == 3
    assert all(i.report_only and i.hint for i in items)
    assert sum(1 for i in items if i.description == "sys thing") == 1


def test_reporter_truncation_note(orphan_env):
    class T(oc.OrphanReporter):
        id = "t"
        name = "t"
        description = ""

        def user_findings(self):
            for n in "abc":
                p = orphan_env.home / n
                p.write_bytes(b"x" * 10000)
                yield oc.Finding(p, n, "h", requires_root=False)

    cfg = Config()
    cfg.orphan_max_items = 1
    items = T(cfg).scan().items
    assert len(items) == 2
    assert items[0].size > 0
    assert items[1].size == 0 and "stopped early" in items[1].description
    assert items[1].report_only and items[1].hint


def test_reporter_partial_size_suffix(orphan_env, monkeypatch):
    monkeypatch.setattr(oc, "bounded_size", lambda p, b: (5, False))

    class T(oc.OrphanReporter):
        id = "t"
        name = "t"
        description = ""

        def user_findings(self):
            yield oc.Finding(orphan_env.home, "x", "h")

    (item,) = T(Config()).find_items()
    assert item.size == 5 and item.description.endswith("(size is a lower bound)")


def test_note_is_never_sized(orphan_env, monkeypatch):
    def boom(p, b):
        raise AssertionError("sized a note")

    monkeypatch.setattr(oc, "bounded_size", boom)

    class T(oc.OrphanReporter):
        id = "t"
        name = "t"
        description = ""

        def user_findings(self):
            yield self.note(orphan_env.home / "x", "could not read", "hint")

    (item,) = T(Config()).find_items()
    assert item.size == 0 and item.report_only


def test_reporter_defaults():
    assert oc.OrphanReporter.requires_root is False
    assert oc.OrphanReporter.sysroot == "/"
