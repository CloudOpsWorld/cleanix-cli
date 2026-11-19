"""The real-Windows verification script: its pure logic and its safety gates.

The script is imported by path and ``main`` is only called for ``--dry-run`` and
for refusals. Nothing here touches the real registry: the flow test runs the
whole script flow on the in-memory FakeRegistry.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from _fakereg import FakeRegistry
from cleanix.core.models import RegTarget
from cleanix.core.winregistry import REG_SZ, RegValue

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_registry_cleanup.py"


def _load():
    spec = importlib.util.spec_from_file_location("verify_registry_cleanup", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses look the module up by name
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def v():
    return _load()


ROOT = r"SOFTWARE\CleanixTest"


# -- ReRootedBackend / Confined -------------------------------------------------------
def test_rerooted_maps_into_test_root(v):
    fake = FakeRegistry()
    rr = v.ReRootedBackend(fake)
    key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Foo"
    rr.create_key("HKLM", key)
    rr.set_value("HKLM", key, RegValue("DisplayName", REG_SZ, "Foo"))
    assert fake.key_exists("HKCU", ROOT + r"\HKLM" + "\\" + key)
    assert rr.values("HKLM", key)[0].data == "Foo"
    assert rr.subkeys("HKLM", key.rsplit("\\", 1)[0]) == ["Foo"]
    assert rr.physical("HKCU", key) == ("HKCU", ROOT + r"\HKCU" + "\\" + key)
    assert {c[1] for c in fake.calls if len(c) > 1} == {"HKCU"}
    assert not fake.key_exists("HKLM", key)  # the logical location is untouched


def test_rerooted_refuses_escape(v):
    fake = FakeRegistry()
    rr = v.ReRootedBackend(fake)
    for hive, key in (
        ("HKCU", r"SOFTWARE\..\..\Run"),
        ("HKCU", r"SOFTWARE\a\..\b"),
        ("HKCU", r"SOFTWARE\\x"),
        ("HKCU", "SYSTEM\\CurrentControlSet"),
        ("HKCR", r"SOFTWARE\x"),
        ("HKU", r"SOFTWARE\x"),
    ):
        with pytest.raises(ValueError):
            rr.create_key(hive, key)
    assert fake.calls == []
    # A custom root: a mapped key that is not under it raises.
    rr2 = v.ReRootedBackend(fake, root_key=ROOT)
    rr2._guard._root = ("software", "somewhere", "else")
    with pytest.raises(ValueError):
        rr2.create_key("HKCU", r"SOFTWARE\x")
    assert fake.calls == []


def test_confined_allows_only_the_test_key(v):
    fake = FakeRegistry()
    g = v.Confined(fake)
    g.create_key("HKCU", ROOT)
    g.create_key("HKCU", ROOT + r"\_probe\x")
    assert g.key_exists("HKCU", ROOT)
    for hive, key in (
        ("HKLM", ROOT),
        ("HKCU", r"SOFTWARE\Cleanix"),
        ("HKCU", r"SOFTWARE\CleanixTest2"),
        ("HKCU", "SOFTWARE"),
        ("HKCU", ROOT + r"\..\Cleanix"),
        ("HKCU", ROOT + r"\\x"),
        ("HKCU", ""),
    ):
        for op in (lambda: g.create_key(hive, key), lambda: g.delete_key(hive, key),
                   lambda: g.set_value(hive, key, RegValue("a", REG_SZ, "b")),
                   lambda: g.delete_value(hive, key, "a"), lambda: g.subkeys(hive, key),
                   lambda: g.key_exists(hive, key)):
            with pytest.raises(ValueError):
                op()
    assert not any(c[0] == "delete_key" for c in fake.calls)


def test_delete_tree_children_first_and_never_follows_links(v):
    fake = FakeRegistry()
    fake.add_key("HKCU", ROOT + r"\a\b\c")
    fake.add_key("HKCU", ROOT + r"\a\d")
    g = v.Confined(fake)
    assert v.delete_tree(g, "HKCU", ROOT) == 5
    assert not fake.key_exists("HKCU", ROOT)

    fake = FakeRegistry()
    fake.add_key("HKCU", ROOT + r"\a")
    fake.add_key("HKCU", ROOT + r"\link", link=True)
    g = v.Confined(fake)
    with pytest.raises(RuntimeError):
        v.delete_tree(g, "HKCU", ROOT)
    seen = []
    v.delete_tree(g, "HKCU", ROOT + r"\link", on_link=lambda h, k: seen.append(k))
    assert seen == [ROOT + r"\link"]


# -- argument gating -------------------------------------------------------------------
def test_arg_gating(v):
    flag = v.ARM_FLAG
    assert flag == "--i-understand-this-writes-to-hkcu-software-cleanixtest"
    plain = v.parse_args([])
    armed = v.parse_args([flag])
    dry = v.parse_args(["--dry-run"])
    assert "not win32" in v.refusal(plain, "linux") or "only on Windows" in v.refusal(plain, "linux")
    assert "only on Windows" in v.refusal(armed, "linux")
    assert "only on Windows" in v.refusal(armed, "darwin")
    assert flag in v.refusal(plain, "win32")
    assert v.refusal(armed, "win32") is None
    assert v.refusal(dry, "linux") is None  # a dry run touches nothing
    assert v.refusal(dry, "win32") is None


def test_unknown_flags_are_rejected(v):
    with pytest.raises(SystemExit):
        v.parse_args(["--hklm"])


def test_main_refuses_on_non_windows_without_importing_winreg(v, monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "linux")
    before = {m for m in ("winreg", "cleanix.core.winregistry_win") if m in sys.modules}
    assert v.main([v.ARM_FLAG]) == 2
    assert "only on Windows" in capsys.readouterr().out
    assert {m for m in ("winreg", "cleanix.core.winregistry_win") if m in sys.modules} == before


def test_main_refuses_without_the_flag_on_windows(v, monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "win32")
    assert v.main([]) == 2
    assert v.ARM_FLAG in capsys.readouterr().out


def test_dry_run_prints_the_plan_and_touches_nothing(v, capsys, _no_real_registry):
    assert v.main(["--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "PLAN" in out and "dry run" in out
    assert r"HKCU\SOFTWARE\CleanixTest" in out
    assert "HKLM is never opened" in out
    assert "win_reg_uninstall" in out and "win_reg_shared_dlls" in out
    assert v.ARM_FLAG in out
    assert _no_real_registry.calls == []


def test_no_registry_import_at_module_import_time():
    code = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('v', {str(SCRIPT)!r})\n"
        "m = importlib.util.module_from_spec(spec); sys.modules['v'] = m; spec.loader.exec_module(m)\n"
        "bad = [n for n in ('cleanix.core.winregistry_win',) if n in sys.modules]\n"
        "if sys.platform != 'win32' and 'winreg' in sys.modules: bad.append('winreg')\n"
        "print(','.join(bad))\n"
    )
    env = dict(os.environ, PYTHONPATH=str(SCRIPT.parent.parent), PYTHONDONTWRITEBYTECODE="1")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == ""


def test_source_never_names_hklm_or_a_top_level_winreg_import():
    src = SCRIPT.read_text(encoding="utf-8")
    assert "HKEY_LOCAL_MACHINE" not in src
    assert not re.search(r"^\s*(import winreg|from winreg)", src.split("class _Nt")[0], re.M)
    # elevation is never requested
    assert "runas" not in src.casefold() and "ShellExecute" not in src


# -- abort when the test key exists ---------------------------------------------------------
def test_execute_aborts_when_the_test_key_exists(v, capsys):
    fake = FakeRegistry()
    fake.add_key("HKCU", ROOT + r"\leftover")
    rc = v.execute(fake, v.Report(lambda s: None), system_drive="C:", elevated=False,
                   with_probes=False)
    assert rc == 2
    assert "already exists" in capsys.readouterr().out
    assert [c[0] for c in fake.calls] == ["key_exists"]
    assert fake.key_exists("HKCU", ROOT + r"\leftover")  # nothing was removed


# -- pure helpers ------------------------------------------------------------------------------
def test_reg_text_confined(v):
    p = r"HKEY_CURRENT_USER\SOFTWARE\CleanixTest\_probe"
    ok = "Windows Registry Editor Version 5.00\r\n\r\n[" + p + "\\import]\r\n\"a\"=\"b\"\r\n"
    assert v.reg_text_confined(ok, p)
    assert v.reg_text_confined(ok.replace("import]", "import\\x]"), p)
    assert not v.reg_text_confined("Windows Registry Editor Version 5.00\r\n", p)  # nothing
    for bad in (
        r"[HKEY_CURRENT_USER\SOFTWARE\Cleanix]",
        r"[HKEY_LOCAL_MACHINE\SOFTWARE\CleanixTest\_probe\x]",
        "[-" + p + "\\x]",
        r"[HKEY_CURRENT_USER\SOFTWARE\CleanixTest\_probe2]",
        ok + r"[HKEY_CURRENT_USER\SOFTWARE\Run]",
        "[" + p,
    ):
        assert not v.reg_text_confined(bad, p), bad


def test_normalize_reg_text_joins_wrapping_and_ignores_order(v):
    a = ("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\K]\r\n"
         '"x"=hex:01,02,03,04\r\n"y"="v"\r\n\r\n')
    b = ("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\k]\r\n"
         '"y"="v"\r\n"x"=hex:01,02,\\\r\n  03,04\r\n\r\n')
    assert v.normalize_reg_text(a) == v.normalize_reg_text(b)
    c = b.replace("03,04", "03,05")
    assert v.normalize_reg_text(a) != v.normalize_reg_text(c)


def test_to_reg_text_round_trips_through_normalize(v):
    from cleanix.core import regbackup
    from cleanix.core.regsnap import KeySnap

    snap = KeySnap(name="", values=(RegValue("a", REG_SZ, "b"),), subkeys=())
    text = regbackup.to_reg_text(RegTarget("HKCU", ROOT + r"\_probe\x"), snap)
    assert v.reg_text_confined(text, "HKEY_CURRENT_USER\\" + ROOT)
    assert list(v.normalize_reg_text(text).values()) == [['"a"="b"']]


def test_parse_multi_sz_keeps_empty_strings(v):
    raw = "a\0\0b\0\0\0".encode("utf-16-le")
    assert v.parse_multi_sz(raw) == ("a", "", "b", "")
    assert v.parse_multi_sz("x\0y z\0\0".encode("utf-16-le")) == ("x", "y z")
    assert v.parse_multi_sz(b"") == ()
    assert v.parse_multi_sz("\0".encode("utf-16-le")) == ()


def test_fixtures_are_consistent(v):
    from cleanix.core import catalog, regsafety

    fx = v.build_fixtures(r"C:\CleanixVerify-x\dead", r"C:\CleanixVerify-x\live", r"C:\Windows")
    dead = v.expected_dead(fx)
    assert len(dead) == len(set(dead)) == 12
    assert {d[0] for d in dead} == set(catalog.REGISTRY_IDS)
    for cid, hive, key, value in dead:
        assert regsafety.check_target(cid, RegTarget(hive, key, value)) is None
    for f in fx:
        assert f.hive in ("HKCU", "HKLM")
        for key, values in f.keys:
            assert key.startswith("SOFTWARE\\")
    # every dead target is in the dead folder, every live one is not
    for f in fx:
        text = " ".join(str(d) for _k, vals in f.keys for _n, _t, d in vals) + " ".join(
            n for _k, vals in f.keys for n, _t, _d in vals)
        if f.dead is not None:
            assert r"CleanixVerify-x\dead" in text, f.label
        else:
            assert r"CleanixVerify-x\dead" not in text, f.label
    # HKLM-only SharedDLLs; both hives for the others
    assert [d for d in dead if d[0] == "win_reg_shared_dlls" and d[1] != "HKLM"] == []


# -- the whole flow on the in-memory registry (Windows only: it uses real files and ownership) ---
@pytest.mark.skipif(sys.platform != "win32", reason="needs the Windows detectors and file checks")
def test_whole_flow_on_the_fake_registry(v, tmp_path, capsys, monkeypatch):
    from cleanix.core import winenv

    drive = os.environ.get("SystemDrive", "C:")
    try:
        probe = Path(drive + "\\") / f"CleanixVerify-write-test-{os.getpid()}"
        probe.mkdir()
        probe.rmdir()
    except OSError:
        pytest.skip("cannot create folders in the system drive root")
    lines = []
    fake = FakeRegistry()
    rep = v.Report(lines.append)
    rc = v.execute(fake, rep, system_drive=drive, elevated=winenv.is_admin(), with_probes=False)
    text = "\n".join(lines)
    assert rc == 0, text
    assert all(ok for _n, ok, _d in rep.results), text
    assert any("restore" in n for n, _o, _d in rep.results)
    assert not fake.key_exists("HKCU", ROOT)
    # Only the test key was ever written.
    for c in fake.calls:
        if c[0] in ("create_key", "set_value", "delete_key", "delete_value"):
            assert c[1] == "HKCU" and c[2].startswith(ROOT), c


def test_script_compiles_without_warnings():
    import warnings

    src = SCRIPT.read_text(encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # e.g. an invalid escape sequence
        compile(src, str(SCRIPT), "exec")
