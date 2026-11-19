"""stale_launchers and stale_alternatives: report-only detectors."""

from __future__ import annotations

import os
import sys

import pytest

from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners.stale_launchers import (
    BrokenAlternativesReporter,
    StaleDesktopEntryReporter,
)
from cleanix.config import Config

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="needs POSIX symlinks/paths"
)


def entry(exec_line=None, name="App", extra="", try_exec=None, typ="Application"):
    lines = ["[Desktop Entry]", f"Type={typ}", f"Name={name}"]
    if exec_line is not None:
        lines.append(f"Exec={exec_line}")
    if try_exec is not None:
        lines.append(f"TryExec={try_exec}")
    if extra:
        lines.append(extra)
    return "\n".join(lines) + "\n"


def put(base, rel, text):
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def prog(root, logical):
    p = root / logical.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("#!/bin/sh\n")
    return p


def scan(orphan_env, cls=StaleDesktopEntryReporter):
    return cls(Config()).scan()


def descs(report):
    return [i.description for i in report.items]


def test_desktop_missing_exec_reported(orphan_env):
    env = orphan_env
    put(env.home, ".local/share/applications/gone.desktop",
        entry("/opt/gone/bin/gone %U", name="Gone"))
    put(env.root, "usr/local/share/applications/loc.desktop",
        entry("loc-bin", name="Loc"))
    rep = scan(env)
    assert rep.skipped_reason is None
    assert len(rep.items) == 2
    user = next(i for i in rep.items if "Gone" in i.description)
    assert user.description.startswith(
        "Menu entry for a missing program: Gone ("
    )
    assert user.report_only and user.requires_root is False
    assert "/opt/gone/bin/gone" in user.hint
    assert "remove" in user.hint and "menu shortcut" in user.hint
    sysi = next(i for i in rep.items if "Loc" in i.description)
    assert sysi.requires_root is True
    assert "Administrator" in sysi.hint
    assert sysi.description.endswith("(/usr/local/share/applications/loc.desktop)") or (
        "usr/local/share/applications/loc.desktop" in sysi.description
    )


def test_autostart_reported(orphan_env):
    put(orphan_env.home, ".config/autostart/x.desktop", entry("nope-bin"))
    assert len(scan(orphan_env).items) == 1


def test_user_applications_depth_limit(orphan_env):
    base = orphan_env.home / ".local/share/applications"
    put(base, "a/b/c/deep.desktop", entry("nope1"))  # depth 3: found
    put(base, "a/b/c/d/too-deep.desktop", entry("nope2"))  # depth 4: skipped
    rep = scan(orphan_env)
    assert len(rep.items) == 1
    assert "deep.desktop" in rep.items[0].description


def test_desktop_false_positives(orphan_env):
    env = orphan_env
    apps = ".local/share/applications"
    prog(env.root, "/usr/bin/present")
    prog(env.root, "/opt/p/abs")
    prog(env.root, "/usr/bin/bar")
    prog(env.root, "/usr/bin/wrapped")
    cases = {
        "abs": entry("/opt/p/abs --x"),
        "rel": entry("present %U"),
        "env": entry("env FOO=1 BAR=2 bar %U"),
        "usrenv": entry("/usr/bin/env FOO=1 bar"),
        "tryexec": entry("'odd \"quote", try_exec="/usr/bin/present"),
        "hidden": entry("missing1", extra="Hidden=true"),
        "link": entry("missing2", typ="Link"),
        "dir": entry("missing3", typ="Directory"),
        "noexec": entry(None),
        "badshlex": entry("'unterminated"),
        "flatpak": entry("flatpak run org.x.App"),
        "snap": entry("snap run thing"),
        "sh": entry('sh -c "missing4 --x"'),
        "bash": entry('/bin/bash -c "missing5"'),
        "envsh": entry("env FOO=1 sh -c missing6"),
        "xdg": entry("xdg-open https://x"),
        "sudo": entry("pkexec missing7"),
        "removable": entry("/media/u/x/prog"),
        "removable2": entry("/run/media/u/disk/prog"),
        "pct": entry("%k"),
        "dollar": entry("$HOME/x"),
        "tilde": entry("~/bin/x"),
        "envopt": entry("env -u X missing8"),
        "relslash": entry("sub/dir/prog"),
        "trypct": entry("missing9", try_exec="/usr/bin/present"),
    }
    for k, text in cases.items():
        put(env.home, f"{apps}/{k}.desktop", text)
    put(env.home, f"{apps}/appimagekit_x.desktop", entry("/nope/AppImage"))
    # a different group first must not confuse parsing
    put(env.home, f"{apps}/groups.desktop",
        "[Other]\nExec=missing10\n[Desktop Entry]\nType=Application\n"
        "Name=G\nExec=/usr/bin/present\n")
    assert scan(env).items == []


def test_try_exec_missing_is_reported_even_if_exec_present(orphan_env):
    prog(orphan_env.root, "/usr/bin/present")
    put(orphan_env.home, ".local/share/applications/t.desktop",
        entry("present", try_exec="/usr/bin/vanished"))
    assert len(scan(orphan_env).items) == 1


def test_relative_exec_uses_fixed_dirs_not_path(orphan_env, monkeypatch):
    env = orphan_env
    monkeypatch.setenv("PATH", str(env.root / "custom"))
    prog(env.root, "/custom/inpath")  # only reachable through $PATH
    prog(env.home, ".local/bin/inhome")
    prog(env.root, "/snap/bin/insnap")
    apps = ".local/share/applications"
    put(env.home, f"{apps}/a.desktop", entry("inpath"))
    put(env.home, f"{apps}/b.desktop", entry("inhome"))
    put(env.home, f"{apps}/c.desktop", entry("insnap"))
    rep = scan(env)
    assert len(rep.items) == 1
    assert "a.desktop" in rep.items[0].description


@posix_only
def test_symlinked_desktop_skipped(orphan_env):
    base = orphan_env.home / ".local/share/applications"
    base.mkdir(parents=True)
    real = put(orphan_env.home, "elsewhere/real.desktop", entry("nope"))
    os.symlink(real, base / "link.desktop")
    assert scan(orphan_env).items == []


@posix_only
def test_dangling_symlink_to_removable_is_unknown(orphan_env):
    env = orphan_env
    (env.home / ".local/bin").mkdir(parents=True)
    os.symlink("/media/u/usb/tool", env.home / ".local/bin/tool")
    put(env.home, ".local/share/applications/t.desktop", entry("tool"))
    assert scan(env).items == []


def _dpkg(env, monkeypatch, family=("debian",)):
    monkeypatch.setattr(oc._platform, "distro_family", lambda: set(family))
    env.cmds.tools.add("dpkg-query")


def test_usr_share_entry_needs_unowned(orphan_env, monkeypatch):
    env = orphan_env
    put(env.root, "usr/share/applications/a.desktop", entry("gone-a", name="A"))
    put(env.root, "usr/share/applications/b.desktop", entry("gone-b", name="B"))
    put(env.root, "etc/xdg/autostart/c.desktop", entry("gone-c", name="C"))
    # with no backend: nothing from these two directories
    assert scan(env).items == []
    _dpkg(env, monkeypatch)
    env.cmds.on(
        ["dpkg-query", "-S"], rc=1,
        err="dpkg-query: no path found matching pattern "
            "/usr/share/applications/b.desktop\n"
            "dpkg-query: no path found matching pattern "
            "/etc/xdg/autostart/c.desktop\n",
    )
    rep = scan(env)
    assert sorted(descs(rep)) == sorted(
        [
            "Menu entry for a missing program: B (/usr/share/applications/b.desktop)",
            "Menu entry for a missing program: C (/etc/xdg/autostart/c.desktop)",
        ]
    )
    b = next(i for i in rep.items if "(/usr/share/applications/b" in i.description)
    assert "Check first: dpkg -S /usr/share/applications/b.desktop" in b.hint
    assert "Administrator" in b.hint
    assert b.requires_root


def test_unknown_ownership_not_reported(orphan_env, monkeypatch):
    env = orphan_env
    put(env.root, "usr/share/applications/a.desktop", entry("gone-a"))
    _dpkg(env, monkeypatch)
    env.cmds.on(["dpkg-query", "-S"], rc=127, err="not found")  # unknown
    assert scan(env).items == []


def test_only_dpkg_query_s_is_called(orphan_env, monkeypatch):
    env = orphan_env
    put(env.root, "usr/share/applications/a.desktop", entry("gone-a"))
    _dpkg(env, monkeypatch)
    scan(env)
    assert all(c[:2] == ["dpkg-query", "-S"] for c in env.cmds.calls)


def test_hint_quotes_path_with_space_desktop(orphan_env):
    put(orphan_env.home, ".local/share/applications/my app.desktop",
        entry("nope", name="Spacey"))
    (item,) = scan(orphan_env).items
    assert "remove '" in item.hint and "my app.desktop'" in item.hint


def test_control_chars_in_names_sanitised(orphan_env):
    put(orphan_env.home, ".local/share/applications/c.desktop",
        entry("nope", name="Evil\x1b[31mName"))
    (item,) = scan(orphan_env).items
    assert "\x1b" not in item.description


# ------------------------------------------------------------ alternatives
def _alt(env):
    d = env.root / "etc" / "alternatives"
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_alternatives_unavailable_without_dir(orphan_env):
    rep = scan(orphan_env, BrokenAlternativesReporter)
    assert rep.skipped_reason == "no alternatives system"


@posix_only
def test_alternative_broken_link_reported(orphan_env):
    env = orphan_env
    d = _alt(env)
    os.symlink("/usr/bin/gone-editor", d / "editor")
    env.cmds.tools.add("update-alternatives")
    rep = scan(env, BrokenAlternativesReporter)
    (item,) = rep.items
    assert item.description == "Broken default-program link: editor -> /usr/bin/gone-editor"
    assert item.report_only and item.requires_root
    assert item.hint == (
        "See the choices: update-alternatives --display editor. "
        "Pick a working one with: sudo update-alternatives --config editor."
    )


@posix_only
def test_alternative_uses_alternatives_cmd_when_no_update_alternatives(orphan_env):
    d = _alt(orphan_env)
    os.symlink("/usr/bin/gone", d / "x")
    (item,) = scan(orphan_env, BrokenAlternativesReporter).items
    assert "alternatives --config x" in item.hint
    assert "update-alternatives" not in item.hint


@posix_only
def test_alternative_working_link_not_reported(orphan_env):
    env = orphan_env
    d = _alt(env)
    prog(env.root, "/usr/bin/vim")
    os.symlink("/usr/bin/vim", d / "editor")
    os.symlink("/dev/null", d / "nullish")
    (d / "regular-file").write_text("x")
    assert scan(env, BrokenAlternativesReporter).items == []


@posix_only
def test_alternative_removable_target_unknown(orphan_env):
    d = _alt(orphan_env)
    os.symlink("/media/u/usb/bin/tool", d / "tool")
    os.symlink("/mnt/net/tool", d / "tool2")
    assert scan(orphan_env, BrokenAlternativesReporter).items == []


@posix_only
def test_hint_quotes_path_with_space_alternatives(orphan_env):
    d = _alt(orphan_env)
    os.symlink("/usr/bin/gone", d / "my alt")
    (item,) = scan(orphan_env, BrokenAlternativesReporter).items
    assert "--display 'my alt'." in item.hint
    assert "--config 'my alt'." in item.hint


def test_class_metadata():
    from cleanix.cleaners.base import SCOPE_SYSTEM, SCOPE_USER

    assert StaleDesktopEntryReporter.id == "stale_launchers"
    assert StaleDesktopEntryReporter.scope == SCOPE_USER
    assert BrokenAlternativesReporter.id == "stale_alternatives"
    assert BrokenAlternativesReporter.scope == SCOPE_SYSTEM
    assert StaleDesktopEntryReporter.platforms == ("linux",)
