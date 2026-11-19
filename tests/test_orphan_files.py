"""orphan_files: Linux files owned by no package (report only)."""

from __future__ import annotations

import sys

import pytest

from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners.orphan_files import UnownedSystemFilesReporter
from cleanix.config import Config

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="needs POSIX symlinks/paths"
)


def make(env, rel, *, is_dir=True, size=0):
    p = env.root / rel.lstrip("/")
    if is_dir:
        p.mkdir(parents=True, exist_ok=True)
        if size:
            (p / "data").write_bytes(b"x" * size)
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x" * size)
    return p


def setup(env, monkeypatch, *, owned=(), installed=("bash",),
          passwd="root:x:0:0\n", installed_ok=True, query_rc=None):
    """Fake dpkg: paths in ``owned`` are owned, every other queried one is not."""
    monkeypatch.setattr(oc.OrphanReporter, "pkg_backend", lambda self: "dpkg")
    env.cmds.tools = {"dpkg-query"}
    if passwd is not None:
        make(env, "/etc")
        (env.root / "etc" / "passwd").write_text(passwd)
    queried = []
    batches = []

    def fake(argv, timeout=120):
        argv = list(argv)
        if argv[:2] == ["env", "LC_ALL=C"]:
            argv = argv[2:]
        if argv[:2] == ["dpkg-query", "-W"]:
            if not installed_ok:
                return 1, "", "failed"
            return 0, "".join(f"{n}\n" for n in installed), ""
        if argv[:2] == ["dpkg-query", "-S"]:
            ps = argv[2:]
            queried.extend(ps)
            batches.append(ps)
            if query_rc is not None:
                return query_rc, "", ""
            out, err = [], []
            for p in ps:
                if p in owned:
                    out.append(f"somepkg: {p}")
                else:
                    err.append(f"dpkg-query: no path found matching pattern {p}")
            return (1 if err else 0), "\n".join(out), "\n".join(err)
        return 127, "", "not found"

    monkeypatch.setattr(oc, "run_command", fake)
    env.queried = queried
    env.batches = batches


def scan(env, **cfg):
    config = Config()
    for k, v in cfg.items():
        setattr(config, k, v)
    return UnownedSystemFilesReporter(config).scan()


def paths(report, env):
    return sorted(
        i.path.replace(str(env.root), "").replace("\\", "/") for i in report.items
    )


def test_metadata():
    from cleanix.cleaners.base import SCOPE_SYSTEM
    from cleanix.core.platform import LINUX

    c = UnownedSystemFilesReporter(Config())
    assert c.id == "orphan_files"
    assert c.platforms == (LINUX,) and c.scope == SCOPE_SYSTEM
    assert c.default_enabled is False
    assert c.description == (
        "Items under /opt, /usr/local, /var/lib and /var/cache that no "
        "installed package owns (report only)"
    )
    assert "/etc" not in c.description and "/srv" not in c.description


def test_available_without_backend(orphan_env, monkeypatch):
    monkeypatch.setattr(oc.OrphanReporter, "pkg_backend", lambda self: None)
    c = UnownedSystemFilesReporter(Config())
    assert c.available() == (
        "package ownership lookup is not supported on this distribution"
    )


def test_reports_unowned_opt_dir(orphan_env, monkeypatch):
    setup(orphan_env, monkeypatch, owned={"/opt/google"})
    make(orphan_env, "/opt/oldapp", size=100)
    make(orphan_env, "/opt/google", size=100)
    items = scan(orphan_env).items
    assert len(items) == 1
    (it,) = items
    assert it.report_only and it.requires_root
    assert it.description == "Not from any package: /opt/oldapp"
    assert "dpkg -S /opt/oldapp" in it.hint
    assert "Nothing installed this through dpkg." in it.hint
    assert "remove /opt/oldapp by hand (administrator rights needed)" in it.hint


def test_one_batched_query(orphan_env, monkeypatch):
    setup(orphan_env, monkeypatch)
    for n in ("a", "b", "c"):
        make(orphan_env, f"/opt/{n}")
    scan(orphan_env)
    assert len(orphan_env.batches) == 1
    assert sorted(orphan_env.batches[0]) == ["/opt/a", "/opt/b", "/opt/c"]


def test_roots_do_not_include_etc_or_srv(orphan_env, monkeypatch):
    setup(orphan_env, monkeypatch)
    make(orphan_env, "/etc/foo.d")
    make(orphan_env, "/srv/www")
    make(orphan_env, "/opt/x")
    r = scan(orphan_env)
    assert paths(r, orphan_env) == ["/opt/x"]
    assert not any(q.startswith(("/etc", "/srv")) for q in orphan_env.queried)


def test_false_positives_not_reported(orphan_env, monkeypatch):
    setup(
        orphan_env, monkeypatch,
        installed=("postgresql-16", "bash"),
        passwd="root:x:0:0\ncolord:x:1:1\n",
    )
    e = orphan_env
    for d in ("dpkg", "docker", "flatpak", "snapd", "systemd", "postgresql",
              "colord", "foo", "oldjunk.dpkg-old", "zzzgenuine"):
        make(e, f"/var/lib/{d}")
    for d in ("apt", "fontconfig"):
        make(e, f"/var/cache/{d}")
    (e.root / "etc" / "systemd" / "system").mkdir(parents=True)
    (e.root / "etc" / "systemd" / "system" / "foo.service").write_text("")
    make(e, "/usr/local/share/man")
    make(e, "/usr/local/bin")
    make(e, "/opt/real")
    r = scan(e)
    assert paths(r, e) == ["/opt/real", "/var/lib/zzzgenuine"]
    queried = set(e.queried)
    for bad in ("/var/lib/dpkg", "/var/lib/colord", "/var/lib/foo",
                "/var/lib/postgresql", "/usr/local/bin", "/usr/local/share/man",
                "/var/lib/oldjunk.dpkg-old"):
        assert bad not in queried


@posix_only
def test_glob_name_skipped(orphan_env, monkeypatch):
    setup(orphan_env, monkeypatch)
    make(orphan_env, "/opt/a*b")
    make(orphan_env, "/opt/real")
    r = scan(orphan_env)
    assert paths(r, orphan_env) == ["/opt/real"]


def test_newline_name_skipped(orphan_env, monkeypatch):
    setup(orphan_env, monkeypatch)
    try:
        make(orphan_env, "/opt/bad\nname")
    except OSError:
        pytest.skip("filesystem rejects newline names")
    make(orphan_env, "/opt/real")
    assert paths(scan(orphan_env), orphan_env) == ["/opt/real"]


def test_usr_local_depth_two(orphan_env, monkeypatch):
    setup(orphan_env, monkeypatch)
    make(orphan_env, "/usr/local/bin/mytool", is_dir=False, size=10)
    make(orphan_env, "/usr/local/go", size=10)
    make(orphan_env, "/usr/local/share/man/man1")
    make(orphan_env, "/usr/local/share/myshare")
    r = scan(orphan_env)
    assert paths(r, orphan_env) == [
        "/usr/local/bin/mytool", "/usr/local/go", "/usr/local/share/myshare",
    ]
    for i in r.items:
        assert i.description.startswith("Installed outside the package manager: ")
        assert "make install" in i.hint and "pip" in i.hint


def test_unknown_ownership_reports_nothing(orphan_env, monkeypatch):
    setup(orphan_env, monkeypatch, query_rc=124)
    make(orphan_env, "/opt/oldapp")
    assert scan(orphan_env).items == []


def test_installed_names_unknown_skips_name_evidence_roots(orphan_env, monkeypatch):
    setup(orphan_env, monkeypatch, installed_ok=False)
    make(orphan_env, "/var/lib/mystery")
    make(orphan_env, "/var/cache/mystery")
    make(orphan_env, "/opt/oldapp")
    r = scan(orphan_env)
    real = [i for i in r.items if i.description.startswith("Not from any")]
    assert [i.description for i in real] == ["Not from any package: /opt/oldapp"]
    notes = [i for i in r.items if "Not checked" in i.description]
    assert len(notes) == 2
    assert all(i.size == 0 and i.report_only for i in notes)
    assert not any(q.startswith(("/var/lib", "/var/cache")) for q in orphan_env.queried)


def test_unreadable_root_yields_note(orphan_env, monkeypatch):
    setup(orphan_env, monkeypatch)
    make(orphan_env, "/opt/oldapp")
    make(orphan_env, "/var/lib")
    real_list = oc.list_dir
    monkeypatch.setattr(
        oc, "list_dir",
        lambda p: None if str(p).replace("\\", "/").endswith("/var/lib") else real_list(p),
    )
    r = scan(orphan_env)
    notes = [i for i in r.items if "needs administrator" in i.description]
    assert len(notes) == 1 and notes[0].size == 0 and notes[0].report_only
    assert "/var/lib" in notes[0].description
    assert any(i.path.endswith("oldapp") for i in r.items)


@posix_only
def test_symlink_entry_not_followed(orphan_env, monkeypatch, tmp_path):
    setup(orphan_env, monkeypatch)
    big = tmp_path / "elsewhere" / "big"
    big.mkdir(parents=True)
    (big / "blob").write_bytes(b"x" * 100000)
    make(orphan_env, "/opt")
    (orphan_env.root / "opt" / "link").symlink_to(big)
    listed = []
    real_list = oc.list_dir
    monkeypatch.setattr(oc, "list_dir", lambda p: listed.append(str(p)) or real_list(p))
    r = scan(orphan_env)
    (it,) = r.items
    assert it.path.endswith("link") and it.size == 0 and it.report_only
    assert not any("elsewhere" in x for x in listed)


def test_other_device_entry_skipped(orphan_env, monkeypatch):
    setup(orphan_env, monkeypatch)
    make(orphan_env, "/opt/local")
    make(orphan_env, "/opt/nfs")
    real_dev = oc.device_of
    monkeypatch.setattr(
        oc, "device_of",
        lambda p: 999 if str(p).endswith("nfs") else real_dev(p),
    )
    assert paths(scan(orphan_env), orphan_env) == ["/opt/local"]


def test_hint_quotes_path_with_space(orphan_env, monkeypatch):
    setup(orphan_env, monkeypatch)
    make(orphan_env, "/opt/My App")
    (it,) = scan(orphan_env).items
    assert "'/opt/My App'" in it.hint
    for bad in ("*", "-rf", "xargs"):
        assert bad not in it.hint


def test_budget_caps_items(orphan_env, monkeypatch):
    setup(orphan_env, monkeypatch)
    for n in range(5):
        make(orphan_env, f"/opt/app{n}", size=10)
    r = scan(orphan_env, orphan_max_items=2)
    real = [i for i in r.items if i.description.startswith("Not from any")]
    assert len(real) == 2
    assert len(r.items) == 3
    assert "Scan stopped early" in r.items[-1].description
