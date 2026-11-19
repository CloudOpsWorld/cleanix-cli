"""stale_services: report-only detector for stale systemd units."""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path

import pytest

from cleanix.cleaners import base
from cleanix.cleaners.stale_services import StaleSystemdUnitReporter
from cleanix.config import Config

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="needs POSIX symlinks/paths"
)

ETC = "/etc/systemd/system"
VENDOR = "/usr/lib/systemd/system"


def put(env, logical, text="", home=False):
    base_dir = env.home if home else env.root
    p = base_dir / logical.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def svc(exec_start="/opt/x/bin/x", extra=""):
    lines = ["[Unit]", "Description=t", extra, "[Service]"]
    for e in ([exec_start] if isinstance(exec_start, str) else exec_start):
        lines.append(f"ExecStart={e}")
    return "\n".join(lines) + "\n"


def reporter():
    return StaleSystemdUnitReporter(Config())


def sysf(env):
    env.root.joinpath("usr/lib/systemd/system").mkdir(parents=True, exist_ok=True)
    return list(reporter().system_findings())


def descs(findings):
    return [f.label for f in findings]


def test_metadata(orphan_env):
    r = reporter()
    assert r.id == "stale_services"
    assert r.name == "Services for removed programs"
    assert r.scope == base.SCOPE_USER
    assert r.requires_root is False


def test_unavailable_without_systemd_dirs(orphan_env):
    assert reporter().available() == "systemd unit directories not found"
    (orphan_env.root / "usr/lib/systemd/system").mkdir(parents=True)
    assert reporter().available() is None


def test_service_with_missing_binary_reported(orphan_env):
    p = put(orphan_env, f"{ETC}/foo.service", svc("/opt/gone/bin/foo --x"))
    (f,) = sysf(orphan_env)
    assert f.label == (
        "Service for a missing program: foo.service (runs /opt/gone/bin/foo)"
    )
    assert f.path == p and f.requires_root and not f.note
    assert "systemctl status foo.service" in f.hint
    assert "sudo systemctl disable foo.service" in f.hint
    assert "daemon-reload" in f.hint


def test_false_positives_not_reported(orphan_env):
    e = orphan_env
    put(e, "/usr/bin/present", "")
    put(e, "/usr/bin/foo", "")
    put(e, "/opt/x/bin/x", "")
    put(e, f"{ETC}/ok1.service", svc("/usr/bin/present"))
    put(e, f"{ETC}/ok2.service", svc("foo --arg"))  # relative, in /usr/bin
    put(e, f"{ETC}/spec.service", svc("%h/bin/x"))
    put(e, f"{ETC}/var.service", svc("${X}/y"))
    put(e, f"{ETC}/cond.service", svc(
        "/opt/gone2/bin/x", "ConditionPathExists=/opt/gone2/bin/x"))
    put(e, f"{ETC}/assert.service", svc(
        "/opt/gone3/bin/x", "AssertPathExists=/opt/gone3/bin/x"))
    put(e, f"{ETC}/usb.service", svc("/mnt/usb/x"))
    put(e, f"{ETC}/two.service", svc(["/opt/gone4/a", "/usr/bin/present"]))
    put(e, f"{ETC}/dash.service", svc("-/opt/gone5/a"))
    put(e, f"{ETC}/empty.service", "[Service]\nExecStart=\n")
    put(e, f"{ETC}/noexec.service", "[Service]\nType=oneshot\n")
    put(e, f"{ETC}/bad.service", svc("/opt/q 'unterminated"))
    put(e, f"{ETC}/relslash.service", svc("sub/dir/x"))
    put(e, f"{VENDOR}/vendor.service", svc("/opt/gone6/x"))
    put(e, f"{ETC}/service.d/a.conf", "")
    put(e, f"{ETC}/foo-.service.d/a.conf", "")
    put(e, f"{ETC}/getty@tty1.service.d/a.conf", "")
    put(e, "/lib/systemd/system/getty@.service", svc("/usr/bin/present"))
    put(e, f"{ETC}/foo.mount.d/a.conf", "")
    put(e, f"{ETC}/notes.txt", "x")
    assert descs(sysf(e)) == []


@posix_only
def test_masked_unit_not_reported(orphan_env):
    e = orphan_env
    (e.root / "etc/systemd/system").mkdir(parents=True)
    os.symlink("/dev/null", e.root / "etc/systemd/system/masked.service")
    os.makedirs(e.root / "etc/systemd/system/multi-user.target.wants")
    os.symlink(
        "/dev/null", e.root / "etc/systemd/system/multi-user.target.wants/m.service"
    )
    assert descs(sysf(e)) == []


@posix_only
def test_broken_wants_link_reported(orphan_env):
    e = orphan_env
    wants = e.root / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    os.symlink("/usr/lib/systemd/system/gone.service", wants / "gone.service")
    put(e, "/usr/lib/systemd/system/here.service", svc("/usr/bin/x"))
    os.symlink("/usr/lib/systemd/system/here.service", wants / "here.service")
    os.symlink("/etc/systemd/system/gone2.service",
               e.root / "etc/systemd/system/alias.service")
    os.symlink("/run/systemd/generator/g.service", wants / "gen.service")
    os.symlink("/mnt/usb/u.service", wants / "usb.service")
    got = {f.label: f for f in sysf(e)}
    assert set(got) == {
        "Broken unit link: /etc/systemd/system/multi-user.target.wants/"
        "gone.service -> /usr/lib/systemd/system/gone.service",
        "Broken unit link: /etc/systemd/system/alias.service"
        " -> /etc/systemd/system/gone2.service",
    }
    f = next(v for k, v in got.items() if "wants/gone.service" in k)
    assert f.path == wants / "gone.service"
    assert "systemctl status gone.service" in f.hint


def test_orphan_dropin_reported(orphan_env):
    e = orphan_env
    put(e, f"{ETC}/gone.service.d/override.conf", "[Service]\nNice=1\n")
    put(e, f"{ETC}/present.service.d/o.conf", "")
    put(e, VENDOR + "/present.service", svc("/usr/bin/x"))
    put(e, f"{ETC}/gone.timer.d/o.conf", "")
    put(e, "/run/systemd/generator/gen.service", "")
    put(e, f"{ETC}/gen.service.d/o.conf", "")
    put(e, f"{ETC}/tpl@inst.service.d/o.conf", "")
    put(e, f"{ETC}/tpl2@inst.service.d/o.conf", "")
    put(e, "/usr/local/lib/systemd/system/tpl2@.service", svc("/usr/bin/x"))
    put(e, "/usr/bin/x", "")
    got = descs(sysf(e))
    assert sorted(got) == [
        "Settings for a removed service: /etc/systemd/system/gone.service.d",
        "Settings for a removed service: /etc/systemd/system/gone.timer.d",
        "Settings for a removed service: /etc/systemd/system/tpl@inst.service.d",
    ]


def test_user_unit_hint_has_no_sudo(orphan_env):
    e = orphan_env
    p = put(e, "/.config/systemd/user/mine.service", svc("/opt/gone/x"), home=True)
    (f,) = list(reporter().user_findings())
    assert f.path == p and f.requires_root is False
    assert "systemctl --user status mine.service" in f.hint
    assert "systemctl --user disable mine.service" in f.hint
    assert "sudo" not in f.hint
    assert "systemctl --user daemon-reload" in f.hint


def test_user_dropin_lookup_includes_home_dirs(orphan_env):
    e = orphan_env
    put(e, "/.config/systemd/user/a.service.d/o.conf", "", home=True)
    put(e, "/.local/share/systemd/user/a.service", svc("/usr/bin/x"), home=True)
    put(e, "/.config/systemd/user/b.service.d/o.conf", "", home=True)
    got = descs(list(reporter().user_findings()))
    assert len(got) == 1 and got[0].endswith("b.service.d")


def test_hint_quotes_path_with_space(orphan_env):
    put(orphan_env, f"{ETC}/my svc.service", svc("/opt/gone/x"))
    (f,) = sysf(orphan_env)
    assert "'/etc/systemd/system/my svc.service'" in f.hint
    assert "systemctl status 'my svc.service'" in f.hint
    for bad in ("*", "xargs", "-rf", "rm -r"):
        assert bad not in f.hint


def test_hint_has_owner_check_when_backend(orphan_env, monkeypatch):
    put(orphan_env, f"{ETC}/foo.service", svc("/opt/gone/x"))
    monkeypatch.setattr(StaleSystemdUnitReporter, "pkg_backend", lambda s: "dpkg")
    (f,) = sysf(orphan_env)
    assert "; dpkg -S /etc/systemd/system/foo.service." in f.hint


def test_no_commands_run(orphan_env):
    put(orphan_env, f"{ETC}/foo.service", svc("/opt/gone/x"))
    sysf(orphan_env)
    assert orphan_env.cmds.calls == []


def test_system_part_once_across_users(orphan_env, monkeypatch):
    e = orphan_env
    put(e, f"{ETC}/foo.service", svc("/opt/gone/x"))
    put(e, "/.config/systemd/user/mine.service", svc("/opt/gone/y"), home=True)
    monkeypatch.setattr(base, "get_target_users", lambda: ["u1", "u2"])
    monkeypatch.setattr(base, "use_user", lambda u: contextlib.nullcontext())
    items = reporter().scan().items
    assert all(i.report_only and i.hint for i in items)
    assert sum(1 for i in items if "foo.service" in i.description) == 1
    assert sum(1 for i in items if "mine.service" in i.description) == 1


def test_unreadable_dir_yields_note(orphan_env, monkeypatch):
    from cleanix.cleaners import orphan_common as oc

    real = oc.list_dir
    target = orphan_env.root / "etc/systemd/system"
    target.mkdir(parents=True)
    monkeypatch.setattr(
        oc, "list_dir", lambda p: None if Path(p) == target else real(p)
    )
    (f,) = sysf(orphan_env)
    assert f.note and f.hint


def test_dropin_execstart_override_skips_unit(orphan_env):
    e = orphan_env
    put(e, "/usr/bin/real", "")
    put(e, f"{ETC}/foo.service", svc("/opt/gone/y"))
    put(e, f"{ETC}/foo.service.d/override.conf",
        "[Service]\nExecStart=\nExecStart=/usr/bin/real\n")
    assert descs(sysf(e)) == []


@pytest.mark.parametrize("where", [
    "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
])
def test_dropin_in_other_lookup_dirs_skips_unit(orphan_env, where):
    e = orphan_env
    put(e, f"{ETC}/foo.service", svc("/opt/gone/y"))
    put(e, f"{where}/foo.service.d/o.conf", "[Service]\nExecStart=/usr/bin/z\n")
    assert descs(sysf(e)) == []


def test_dropin_condition_skips_unit(orphan_env):
    e = orphan_env
    put(e, f"{ETC}/foo.service", svc("/opt/gone/y"))
    put(e, f"{ETC}/foo.service.d/o.conf",
        "[Unit]\nConditionPathExists=/opt/gone/y\n")
    assert descs(sysf(e)) == []


def test_prefix_dropin_skips_unit(orphan_env):
    e = orphan_env
    put(e, f"{ETC}/foo-bar.service", svc("/opt/gone/y"))
    put(e, f"{ETC}/foo-.service.d/o.conf", "[Service]\nExecStart=/usr/bin/z\n")
    assert descs(sysf(e)) == []


def test_dropin_without_execstart_still_reported(orphan_env):
    e = orphan_env
    put(e, f"{ETC}/foo.service", svc("/opt/gone/y"))
    put(e, f"{ETC}/foo.service.d/o.conf", "[Service]\nNice=5\n")
    assert len(sysf(e)) == 1


@pytest.mark.parametrize("prefix", ["+-", ":-", "@-", "!-", "-", "-+", "-@"])
def test_every_dash_prefix_combination_tolerated(orphan_env, prefix):
    put(orphan_env, f"{ETC}/foo.service", svc(f"{prefix}/opt/gone/x"))
    assert descs(sysf(orphan_env)) == []


@pytest.mark.parametrize("prefix", ["+", "@", ":", "!"])
def test_non_dash_prefix_still_reported(orphan_env, prefix):
    put(orphan_env, f"{ETC}/foo.service", svc(f"{prefix}/opt/gone/x"))
    assert len(sysf(orphan_env)) == 1


def test_user_dropin_in_xdg_dir_not_orphan(orphan_env):
    e = orphan_env
    put(e, "/.config/systemd/user/a.service.d/o.conf", "", home=True)
    put(e, "/usr/share/systemd/user/a.service", svc("/usr/bin/x"))
    assert descs(list(reporter().user_findings())) == []


def test_control_char_names_skipped(orphan_env):
    try:
        put(orphan_env, f"{ETC}/a\nb.service", svc("/opt/gone/x"))
    except OSError:
        pytest.skip("filesystem rejects newline names")
    assert descs(sysf(orphan_env)) == []


def test_package_backend_detected_once_per_scan(orphan_env, monkeypatch):
    from cleanix.cleaners import orphan_common as oc
    from cleanix.cleaners.stale_services import StaleSystemdUnitReporter
    from cleanix.config import Config

    d = orphan_env.root / "etc/systemd/system"
    d.mkdir(parents=True)
    (orphan_env.root / "usr/lib/systemd/system").mkdir(parents=True)
    for n in ("a", "b", "c"):
        (d / f"{n}.service").write_text(f"[Service]\nExecStart=/usr/bin/nope-{n}\n")
    calls = []
    monkeypatch.setattr(
        oc.OrphanReporter, "pkg_backend", lambda self: calls.append(1) or "dpkg"
    )
    rep = StaleSystemdUnitReporter(Config()).scan()
    assert len(rep.items) >= 3
    assert len(calls) == 1
