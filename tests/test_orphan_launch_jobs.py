"""orphan_launch_jobs: LaunchAgents/Daemons whose program is missing."""

from __future__ import annotations

import contextlib
import plistlib
import sys
from pathlib import Path

import pytest

from cleanix.cleaners import base, orphan_common as oc, orphan_launch_jobs as olj
from cleanix.config import Config

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="needs POSIX symlinks/paths"
)

GONE = "/Applications/Gone.app/Contents/MacOS/gone"


def _write(path: Path, data, fmt=plistlib.FMT_XML) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        plistlib.dump(data, fh, fmt=fmt)
    return path


def _user_dir(env) -> Path:
    return env.home / "Library" / "LaunchAgents"


def _sys_dir(env, name="LaunchDaemons") -> Path:
    return env.root / "Library" / name


def _scan(env):
    return olj.OrphanLaunchJobReporter(Config()).scan().items


def _jobs(items):
    return [i for i in items if "Background job" in i.description]


def _touch_program(env, logical: str) -> None:
    p = env.root / logical.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x")


def test_attributes():
    c = olj.OrphanLaunchJobReporter
    assert c.id == "orphan_launch_jobs"
    assert c.name == "Background jobs of removed apps"
    assert c.description == (
        "LaunchAgents and LaunchDaemons whose program is missing (report only)"
    )
    assert "macos" in str(c.platforms).lower()
    assert c.requires_root is False
    assert c.scope == base.SCOPE_USER


@pytest.mark.parametrize("fmt", [plistlib.FMT_XML, plistlib.FMT_BINARY])
def test_missing_program_reported(orphan_env, fmt):
    _write(
        _user_dir(orphan_env) / "com.vendor.gone.plist",
        {"Label": "com.vendor.gone", "ProgramArguments": [GONE, "-x"]},
        fmt,
    )
    items = _scan(orphan_env)
    assert len(items) == 1
    it = items[0]
    assert it.report_only and it.hint and it.requires_root is False
    assert it.description == (
        f"Background job for a missing program: com.vendor.gone (runs {GONE})"
    )


def test_job_program():
    assert olj.job_program({"Program": "/a/b", "ProgramArguments": ["/c"]}) == "/a/b"
    assert olj.job_program({"ProgramArguments": ["/c", "x"]}) == "/c"
    assert olj.job_program({"BundleProgram": "x", "Program": "/a"}) is None
    assert olj.job_program({}) is None
    assert olj.job_program({"ProgramArguments": []}) is None
    assert olj.job_program({"ProgramArguments": [1]}) is None


def test_false_positives(orphan_env):
    env = orphan_env
    u = _user_dir(env)
    _touch_program(env, "/opt/tool/bin/exists")
    _touch_program(env, "/opt/tool/bin/argv0")
    _write(u / "com.apple.foo.plist", {"Label": "x.y", "Program": GONE})
    _write(u / "other.plist", {"Label": "com.apple.bar", "Program": GONE})
    _write(u / "exists.plist", {"Label": "a.exists", "Program": "/opt/tool/bin/exists"})
    _write(u / "bundle.plist", {"Label": "a.b", "BundleProgram": "Contents/x"})
    _write(u / "rel.plist", {"Label": "a.rel", "Program": "bin/gone"})
    _write(u / "tilde.plist", {"Label": "a.t", "Program": "~/bin/gone"})
    _write(u / "env.plist", {"Label": "a.env", "Program": "$HOME/bin/gone"})
    _write(u / "vol.plist", {"Label": "a.vol", "Program": "/Volumes/Ext/app/bin"})
    _write(u / "net.plist", {"Label": "a.net", "Program": "/net/host/bin/x"})
    _write(
        u / "argv0.plist",
        {"Label": "a.argv0", "ProgramArguments": ["/opt/tool/bin/argv0"]},
    )
    _write(u / "noprog.plist", {"Label": "a.none"})
    _write(
        u / "envwrap.plist",
        {"Label": "a.wrap", "ProgramArguments": ["/usr/bin/env", "python3", "/x/y.py"]},
    )
    _write(u / "sip.plist", {"Label": "a.sip", "Program": "/usr/libexec/missing"})
    _write(u / "sh.plist", {"Label": "a.sh", "ProgramArguments": ["/bin/sh", "-c", "x"]})
    _write(u / "sys.plist", {"Label": "a.sys", "Program": "/System/Library/x/y"})
    (env.root / "Applications" / "Here.app" / "Contents").mkdir(parents=True)
    _write(
        u / "bundleexists.plist",
        {"Label": "a.be", "Program": "/Applications/Here.app/Contents/MacOS/helper"},
    )
    (u / "garbage.plist").write_bytes(b"\x00not a plist at all")
    (u / "notplist.txt").write_text("x")
    _write(
        env.root / "System" / "Library" / "LaunchDaemons" / "z.plist",
        {"Label": "z", "Program": GONE},
    )
    items = _scan(env)
    assert _jobs(items) == []
    # the unparsable plist is a size-0 note, never a finding
    notes = [i for i in items if "garbage.plist" in (i.path or "")]
    assert len(notes) == 1 and notes[0].size == 0
    assert all(i.report_only and i.hint for i in items)


def test_non_dict_plist_skipped(orphan_env):
    _write(_user_dir(orphan_env) / "list.plist", ["a", "b"])
    assert _jobs(_scan(orphan_env)) == []


def test_disabled_job_still_reported(orphan_env):
    _write(
        _user_dir(orphan_env) / "d.plist",
        {"Label": "com.v.d", "Disabled": True, "Program": GONE},
    )
    items = _scan(orphan_env)
    assert len(items) == 1 and "com.v.d" in items[0].description


def test_homebrew_hint(orphan_env):
    _write(
        _user_dir(orphan_env) / "homebrew.mxcl.redis.plist",
        {
            "Label": "homebrew.mxcl.redis",
            "ProgramArguments": ["/opt/homebrew/opt/redis/bin/redis-server"],
        },
    )
    _write(
        _user_dir(orphan_env) / "other.plist", {"Label": "com.v.o", "Program": GONE}
    )
    items = _scan(orphan_env)
    brew = [i for i in items if "homebrew.mxcl.redis" in i.description][0]
    other = [i for i in items if "com.v.o" in i.description][0]
    assert "brew services list" in brew.hint
    assert "brew services" not in other.hint


def test_user_hint_uses_uid_and_quotes_path_with_space(orphan_env):
    p = _write(
        _user_dir(orphan_env) / "My Job.plist",
        {"Label": "com.v.space", "Program": GONE},
    )
    (it,) = _scan(orphan_env)
    q = "'" + p.as_posix() + "'"
    assert f"Confirm with: pkgutil --file-info {q}." in it.hint
    assert f"launchctl bootout gui/1000 {q}" in it.hint
    assert f"move {q} to the Trash." in it.hint
    for bad in ("*", "xargs", "-rf", "rm -r"):
        assert bad not in it.hint


def test_system_job_hint_and_root(orphan_env):
    _write(_sys_dir(orphan_env) / "com.v.d.plist", {"Label": "com.v.d", "Program": GONE})
    _write(
        _sys_dir(orphan_env, "LaunchAgents") / "com.v.a.plist",
        {"Label": "com.v.a", "Program": GONE},
    )
    items = _scan(orphan_env)
    assert len(items) == 2
    for it in items:
        assert it.requires_root is True
        assert "sudo launchctl bootout system /Library/Launch" in it.hint
        assert "gui/" not in it.hint
    # hints show the logical path, not the sysroot
    assert any("/Library/LaunchDaemons/com.v.d.plist" in i.hint for i in items)
    assert all(str(orphan_env.root) not in i.hint for i in items)


def test_system_part_once_across_users(orphan_env, monkeypatch):
    _write(_sys_dir(orphan_env) / "com.v.d.plist", {"Label": "com.v.d", "Program": GONE})
    monkeypatch.setattr(base, "get_target_users", lambda: ["u1", "u2"])
    monkeypatch.setattr(base, "use_user", lambda u: contextlib.nullcontext())
    items = _scan(orphan_env)
    assert len([i for i in items if "com.v.d" in i.description]) == 1


@posix_only
def test_broken_plist_link_reported(orphan_env):
    d = _user_dir(orphan_env)
    d.mkdir(parents=True)
    link = d / "com.v.link.plist"
    link.symlink_to("/nonexistent-target/com.v.link.plist")
    (it,) = _scan(orphan_env)
    assert it.description == f"Broken job link: {link.as_posix()}"
    assert it.report_only and it.hint and it.size == 0


@posix_only
def test_plist_symlink_with_target_read_normally(orphan_env, tmp_path):
    real = _write(
        tmp_path / "elsewhere" / "t.plist", {"Label": "com.v.t", "Program": GONE}
    )
    d = _user_dir(orphan_env)
    d.mkdir(parents=True)
    (d / "t.plist").symlink_to(real)
    (d / "null.plist").symlink_to("/dev/null")
    items = _scan(orphan_env)
    assert len(_jobs(items)) == 1
    assert not [i for i in items if "null.plist" in (i.path or "")]


def test_unreadable_dir_yields_note(orphan_env, monkeypatch):
    _user_dir(orphan_env).mkdir(parents=True)
    real = oc.list_dir
    monkeypatch.setattr(
        oc, "list_dir", lambda p: None if Path(p).name == "LaunchAgents" else real(p)
    )
    items = _scan(orphan_env)
    # the system and the user LaunchAgents directory both match the stub
    assert len(items) == 2
    assert all(i.size == 0 and i.report_only and i.hint for i in items)


def test_bad_names_skipped(orphan_env):
    d = _user_dir(orphan_env)
    d.mkdir(parents=True)
    try:
        _write(d / "a\nb.plist", {"Label": "x", "Program": GONE})
    except OSError:
        pytest.skip("filesystem rejects newline names")
    assert _scan(orphan_env) == []


def test_label_control_chars_sanitised(orphan_env):
    _write(
        _user_dir(orphan_env) / "c.plist", {"Label": "evil\nlabel", "Program": GONE}
    )
    (it,) = _scan(orphan_env)
    assert "\n" not in it.description


def test_unknown_existence_not_reported(orphan_env, monkeypatch):
    _write(_user_dir(orphan_env) / "p.plist", {"Label": "a.p", "Program": GONE})
    monkeypatch.setattr(olj, "_exists", lambda p: None)
    assert _scan(orphan_env) == []
