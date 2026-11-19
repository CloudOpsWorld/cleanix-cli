"""Task 12: registry cleaners through the CLI (list/scan/clean/restore/JSON/history).

Everything runs on the in-memory FakeRegistry with a faked Windows platform;
the real registry is never touched.
"""

from __future__ import annotations

import json
import sys

import pytest

from cleanix import cli, completion
from cleanix.core import catalog, history, quarantine, regpromises, regsnap, winenv
from cleanix.core import platform as plat
from cleanix.core.models import (
    CleanableItem,
    CleanerReport,
    ItemKind,
    RegTarget,
)
from cleanix.core.winregistry import REG_SZ

CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
UNINST = CV + r"\Uninstall"
FOO = UNINST + r"\Foo"
RUN = CV + r"\Run"

UNDO_FALSE_TEXT = "no backup or restore is available in this version"
UNDO_TRUE_TEXT = "can be restored with cleanix restore"


@pytest.fixture
def env(tmp_path, monkeypatch, fake_win, fake_registry):
    monkeypatch.setattr(plat, "is_windows", lambda: True)
    monkeypatch.setattr(plat, "current_os", lambda: "windows")
    monkeypatch.setattr(history, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: tmp_path / "q")
    monkeypatch.setattr(winenv, "is_admin", lambda: False)
    monkeypatch.setattr(regpromises, "UNDO_SHIPPED", False)
    monkeypatch.setenv("COLUMNS", "400")
    return fake_registry


@pytest.fixture
def shipped(monkeypatch):
    monkeypatch.setattr(regpromises, "UNDO_SHIPPED", True)


def _item(reg, cid="win_reg_uninstall", hive="HKCU", key=FOO, value=None,
          desc="Foo App: InstallLocation C:\\Gone\\Foo is missing",
          hint="Removes the leftover uninstall entry"):
    t = RegTarget(hive, key, value)
    fp = regsnap.fingerprint(t, regsnap.snapshot(reg, t))
    return CleanableItem(
        cleaner_id=cid, description=desc, kind=ItemKind.REGISTRY,
        reg=RegTarget(hive, key, value, fp), requires_root=(hive == "HKLM"),
        hint=hint,
    )


class _FakeCleaner:
    def __init__(self, cid, items):
        self.id = cid
        self.name = cid
        self._items = items

    def scan(self):
        return CleanerReport(cleaner_id=self.id, name=self.name,
                             description="registry", items=list(self._items))


def _patch_scan(monkeypatch, items):
    by_cid = {}
    for i in items:
        by_cid.setdefault(i.cleaner_id, []).append(i)

    def fake_build(config, only=None, exclude=None):
        ids = only or list(by_cid)
        return [_FakeCleaner(c, by_cid.get(c, [])) for c in ids]

    monkeypatch.setattr(cli, "build_cleaners", fake_build)


def _foo(reg, hive="HKCU", key=FOO):
    reg.add_key(hive, key, {"DisplayName": (REG_SZ, "Foo App")})
    reg.add_key(hive, key + r"\Sub", {"A": (REG_SZ, "x")})


def _writes(reg):
    return [c for c in reg.calls if c[0] in ("delete_key", "delete_value",
                                             "create_key", "set_value")]


def _out(capsys):
    return capsys.readouterr().out.replace("\n", " ")


# -- (1) opt-in exposure ---------------------------------------------------------
def test_default_build_has_no_registry_cleaners(env):
    from cleanix.config import Config
    from cleanix.core.registry import build_cleaners

    ids = {c.id for c in build_cleaners(Config())}
    assert not ids & set(catalog.REGISTRY_IDS)
    explicit = {c.id for c in build_cleaners(Config(), only=list(catalog.REGISTRY_IDS))}
    assert explicit == set(catalog.REGISTRY_IDS)


def test_list_shows_registry_cleaners_as_opt_in(env, capsys):
    from rich.console import Console

    con = Console(width=250, force_terminal=False)
    args = cli.build_parser().parse_args(["list"])
    cli.cmd_list(args, con)
    out = capsys.readouterr().out
    for cid in catalog.REGISTRY_IDS:
        line = next(ln for ln in out.splitlines() if cid in ln)
        assert "opt-in" in line
    plain = next(ln for ln in out.splitlines() if " temp " in f" {ln} ")
    assert "opt-in" not in plain


def test_scan_only_registry_id_runs_and_plain_scan_does_not(env, capsys):
    rc = cli.main(["scan", "--only", "win_reg_uninstall", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert [c["id"] for c in data["cleaners"]] == ["win_reg_uninstall"]
    rc = cli.main(["scan", "--json", "--exclude",
                   "duplicates,big_files,downloads"])
    data = json.loads(capsys.readouterr().out)
    assert not {c["id"] for c in data["cleaners"]} & set(catalog.REGISTRY_IDS)


# -- (2) scan output ------------------------------------------------------------------
def test_scan_table_prints_registry_targets_escaped(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    reg.add_key("HKCU", RUN, {"Gone\u202eApp": (REG_SZ, r"C:\x.exe")})
    items = [_item(reg), _item(reg, cid="win_reg_startup", key=RUN, value="Gone\u202eApp")]
    _patch_scan(monkeypatch, items)
    rc = cli.main(["scan", "--only", "win_reg_uninstall,win_reg_startup"])
    assert rc == 0
    out = _out(capsys)
    assert "HKCU\\" + FOO in out.replace("\n", "")
    assert "Run [Gone" in out
    assert "\u202e" not in out
    assert "InstallLocation" in out and "leftover uninstall entry" in out
    assert not out.lstrip().startswith("$")


def test_scan_json_has_registry_fields_and_old_keys(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    reg.add_key("HKLM", RUN, {"V": (REG_SZ, "x")})
    items = [_item(reg), _item(reg, cid="win_reg_startup", hive="HKLM", key=RUN, value="V")]
    path_item = CleanableItem(cleaner_id="temp", description="t", size=5, path="C:\\t")
    _patch_scan(monkeypatch, items + [path_item])
    rc = cli.main(["scan", "--only", "win_reg_uninstall,win_reg_startup,temp", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == 1
    by = {c["id"]: c for c in data["cleaners"]}
    it = by["win_reg_uninstall"]["items"][0]
    assert it["kind"] == "registry"
    assert it["registry"] == {"hive": "HKCU", "key": FOO, "value": None}
    assert it["target"] == "HKCU\\" + FOO
    assert it["path"] is None and it["command"] is None
    assert it["hint"] and it["description"]
    assert by["win_reg_uninstall"]["registry"] is True
    vi = by["win_reg_startup"]["items"][0]
    assert vi["registry"] == {"hive": "HKLM", "key": RUN, "value": "V"}
    assert vi["target"] == "HKLM\\" + RUN + " [V]" and vi["requires_root"] is True
    pi = by["temp"]["items"][0]
    assert pi["kind"] == "path" and pi["registry"] is None and pi["path"] == "C:\\t"
    assert by["temp"]["registry"] is False
    for k in ("description", "bytes", "path", "command", "requires_root",
              "report_only", "hint"):
        assert k in pi


def test_scan_notice_follows_regpromises_false(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    _patch_scan(monkeypatch, [_item(reg)])
    cli.main(["scan", "--only", "win_reg_uninstall"])
    out = _out(capsys)
    assert UNDO_FALSE_TEXT in out
    assert "Administrator" not in out


def test_scan_notice_follows_regpromises_true(env, shipped, monkeypatch, capsys):
    reg = env
    _foo(reg)
    _patch_scan(monkeypatch, [_item(reg)])
    cli.main(["scan", "--only", "win_reg_uninstall"])
    out = _out(capsys)
    assert UNDO_FALSE_TEXT not in out
    assert "backed up" in out and "cleanix restore" in out
    assert "HKLM" in out and "Administrator terminal" in out


def test_no_notice_without_registry_items(env, monkeypatch, capsys):
    p = CleanableItem(cleaner_id="temp", description="t", size=5, path="C:\\t")
    _patch_scan(monkeypatch, [p])
    cli.main(["scan", "--only", "temp"])
    out = _out(capsys)
    assert "backed up" not in out and "removed permanently" not in out


def test_simulate_and_explain_show_registry_target(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    reg.add_key("HKCU", RUN, {"V": (REG_SZ, "x")})
    items = [_item(reg), _item(reg, cid="win_reg_startup", key=RUN, value="V")]
    _patch_scan(monkeypatch, items)
    rc = cli.main(["clean", "--only", "win_reg_uninstall,win_reg_startup", "--simulate"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "$ " not in out
    assert "HKCU\\" + FOO in out.replace("\n", "")
    assert "Run [V]" in out
    assert _writes(reg) == []
    sim = (history.state_dir() / "last-simulation.txt").read_text(encoding="utf-8")
    assert "HKCU\\" + FOO in sim and "$ " not in sim
    rc = cli.main(["explain", "win_reg_startup"])
    assert rc == 0
    out = capsys.readouterr().out.replace("\n", "")
    assert "Run [V]" in out and "registry" in out


# -- (3) clean ---------------------------------------------------------------------------
def test_clean_dry_run_lists_and_touches_nothing(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    _patch_scan(monkeypatch, [_item(reg)])
    rc = cli.main(["clean", "--only", "win_reg_uninstall"])
    assert rc == 0
    out = _out(capsys)
    assert "HKCU\\" + FOO in out.replace(" ", "") or "HKCU" in out
    assert "dry run" in out.lower() and "nothing" in out.lower()
    assert _writes(reg) == []
    assert reg.key_exists("HKCU", FOO)


def test_clean_execute_prompt_lists_exact_targets_and_decline_aborts(
        env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    reg.add_key("HKCU", RUN, {"V\u202ex": (REG_SZ, "x")})
    items = [_item(reg), _item(reg, cid="win_reg_startup", key=RUN, value="V\u202ex")]
    _patch_scan(monkeypatch, items)
    asked = []
    monkeypatch.setattr(cli.Confirm, "ask",
                        lambda prompt, **kw: asked.append(prompt) or False)
    rc = cli.main(["clean", "--only", "win_reg_uninstall,win_reg_startup", "--execute"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "\u202e" not in out and "\u202e" not in "".join(asked)
    flat = out.replace("\n", "")
    assert "HKCU\\" + FOO in flat and "Run [V" in flat
    assert asked
    assert _writes(reg) == []
    assert reg.key_exists("HKCU", FOO)


def test_clean_execute_yes_removes_hkcu_and_backs_up(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    _patch_scan(monkeypatch, [_item(reg)])
    monkeypatch.setattr(cli.Confirm, "ask", lambda *a, **k: pytest.fail("prompted"))
    rc = cli.main(["clean", "--only", "win_reg_uninstall", "--execute", "--yes"])
    assert rc == 0
    assert not reg.key_exists("HKCU", FOO)
    runs = quarantine.list_runs()
    assert len(runs) == 1 and runs[0]["registry"] == 1
    out = _out(capsys)
    # promise False: no restore hint, permanent wording
    assert UNDO_FALSE_TEXT in out
    assert "cleanix restore" not in out


def test_clean_execute_prints_run_hint_when_shipped(env, shipped, monkeypatch, capsys):
    reg = env
    _foo(reg)
    _patch_scan(monkeypatch, [_item(reg)])
    rc = cli.main(["clean", "--only", "win_reg_uninstall", "--execute", "--yes"])
    assert rc == 0
    run_id = quarantine.list_runs()[0]["run_id"]
    out = _out(capsys)
    assert f"cleanix restore {run_id}" in out
    assert UNDO_FALSE_TEXT not in out


def test_clean_no_hint_when_nothing_removed(env, shipped, monkeypatch, capsys):
    reg = env
    _foo(reg)
    item = _item(reg)
    reg.add_key("HKCU", FOO + r"\New")  # changed since the scan
    _patch_scan(monkeypatch, [item])
    rc = cli.main(["clean", "--only", "win_reg_uninstall", "--execute", "--yes"])
    assert rc == 2
    out = _out(capsys)
    assert "undo with" not in out and "saved in run" not in out
    assert reg.key_exists("HKCU", FOO)


def test_clean_prints_undo_record_error(env, shipped, monkeypatch, capsys):
    from cleanix.core import service

    reg = env
    _foo(reg)
    _patch_scan(monkeypatch, [_item(reg)])
    real = service.clean

    def wrapped(*a, **k):
        s = real(*a, **k)
        s.undo_record_error = "the undo record could not be saved (boom)"
        return s

    monkeypatch.setattr(service, "clean", wrapped)
    cli.main(["clean", "--only", "win_reg_uninstall", "--execute", "--yes"])
    assert "undo record could not be saved (boom)" in _out(capsys)


def test_clean_hklm_requires_elevation(env, monkeypatch, capsys):
    reg = env
    _foo(reg, hive="HKLM")
    _patch_scan(monkeypatch, [_item(reg, hive="HKLM")])
    rc = cli.main(["clean", "--only", "win_reg_uninstall", "--execute", "--yes"])
    assert rc != 0
    out = _out(capsys)
    assert "Administrator" in out and "HKLM" in out
    assert _writes(reg) == []
    assert reg.key_exists("HKLM", FOO)


def test_clean_hklm_elevated_goes_through(env, monkeypatch, capsys):
    reg = env
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    _foo(reg, hive="HKLM")
    _patch_scan(monkeypatch, [_item(reg, hive="HKLM")])
    rc = cli.main(["clean", "--only", "win_reg_uninstall", "--execute", "--yes"])
    assert rc == 0
    assert not reg.key_exists("HKLM", FOO)


def test_clean_hklm_and_hkcu_nonelevated_cleans_only_hkcu(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    _foo(reg, hive="HKLM", key=UNINST + r"\Bar")
    _patch_scan(monkeypatch, [_item(reg), _item(reg, hive="HKLM", key=UNINST + r"\Bar")])
    reg.calls.clear()
    rc = cli.main(["clean", "--only", "win_reg_uninstall", "--execute", "--yes"])
    out = _out(capsys)
    hklm_calls = [c for c in reg.calls if len(c) > 1 and c[1] == "HKLM"]
    assert hklm_calls == []  # the backend never saw an HKLM entry
    assert rc == 1
    assert "Administrator" in out
    assert not reg.key_exists("HKCU", FOO)
    assert reg.key_exists("HKLM", UNINST + r"\Bar")
    assert "require root" not in out


def test_clean_requires_explicit_selection(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    _patch_scan(monkeypatch, [_item(reg)])
    # A registry item that slips into a run without --only naming its cleaner.
    monkeypatch.setattr(cli, "build_cleaners",
                        lambda config, only=None, exclude=None:
                        [_FakeCleaner("win_reg_uninstall", [_item(reg)])])
    rc = cli.main(["clean", "--execute", "--yes"])
    assert rc != 0
    assert reg.key_exists("HKCU", FOO)
    assert "--only" in _out(capsys)


# -- (4) restore --------------------------------------------------------------------------
def _hklm_run(env, monkeypatch):
    reg = env
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    _foo(reg, hive="HKLM")
    _patch_scan(monkeypatch, [_item(reg, hive="HKLM")])
    assert cli.main(["clean", "--only", "win_reg_uninstall", "--execute", "--yes"]) == 0
    run_id = quarantine.list_runs()[0]["run_id"]
    assert not reg.key_exists("HKLM", FOO)
    return reg, run_id


def test_restore_hklm_describes_confirms_then_allows_machine(env, monkeypatch, capsys):
    reg, run_id = _hklm_run(env, monkeypatch)
    capsys.readouterr()
    calls = []
    real_desc = quarantine.describe_registry_entries
    real_restore = quarantine.restore
    monkeypatch.setattr(quarantine, "describe_registry_entries",
                        lambda r: calls.append(("describe", r)) or real_desc(r))
    monkeypatch.setattr(quarantine, "restore",
                        lambda r, **kw: calls.append(("restore", r, kw)) or real_restore(r, **kw))
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr(cli.Prompt, "ask", lambda *a, **k: "yes")
    rc = cli.main(["restore", run_id])
    assert rc == 0
    assert calls[0] == ("describe", run_id)
    assert calls[1] == ("restore", run_id, {"allow_machine_restore": True})
    assert reg.key_exists("HKLM", FOO)
    assert "WRITTEN machine-wide" in capsys.readouterr().out.replace("\n", " ")


def test_restore_hklm_decline_restores_nothing(env, monkeypatch, capsys):
    reg, run_id = _hklm_run(env, monkeypatch)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr(cli.Prompt, "ask", lambda *a, **k: "y")
    rc = cli.main(["restore", run_id])
    assert rc == 1
    assert not reg.key_exists("HKLM", FOO)


def test_restore_hklm_noninteractive_refuses_without_yes(env, monkeypatch, capsys):
    reg, run_id = _hklm_run(env, monkeypatch)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)
    monkeypatch.setattr(cli.Prompt, "ask", lambda *a, **k: pytest.fail("prompted"))
    rc = cli.main(["restore", run_id])
    assert rc != 0
    assert not reg.key_exists("HKLM", FOO)


def test_restore_hklm_yes_with_explicit_run_id(env, monkeypatch, capsys):
    reg, run_id = _hklm_run(env, monkeypatch)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)
    monkeypatch.setattr(cli.Prompt, "ask", lambda *a, **k: pytest.fail("prompted"))
    rc = cli.main(["restore", run_id, "--yes"])
    assert rc == 0
    assert reg.key_exists("HKLM", FOO)


def test_restore_yes_never_for_latest(env, monkeypatch, capsys):
    reg, run_id = _hklm_run(env, monkeypatch)
    rc = cli.main(["restore", "--yes"])
    assert rc != 0
    assert not reg.key_exists("HKLM", FOO)
    assert "run id" in _out(capsys)


def test_restore_hklm_nonelevated_prints_admin_advice(env, monkeypatch, capsys):
    reg, run_id = _hklm_run(env, monkeypatch)
    monkeypatch.setattr(winenv, "is_admin", lambda: False)
    monkeypatch.setattr(cli.Prompt, "ask", lambda *a, **k: pytest.fail("prompted"))
    capsys.readouterr()
    rc = cli.main(["restore", run_id])
    assert rc != 0
    out = _out(capsys)
    assert "Administrator" in out
    assert not reg.key_exists("HKLM", FOO)


def test_restore_hkcu_only_run_needs_no_confirmation(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    _patch_scan(monkeypatch, [_item(reg)])
    assert cli.main(["clean", "--only", "win_reg_uninstall", "--execute", "--yes"]) == 0
    run_id = quarantine.list_runs()[0]["run_id"]
    monkeypatch.setattr(cli.Prompt, "ask", lambda *a, **k: pytest.fail("prompted"))
    desc = []
    monkeypatch.setattr(quarantine, "describe_registry_entries",
                        lambda r: desc.append(r) or [])
    rc = cli.main(["restore", run_id])
    assert rc == 0 and reg.key_exists("HKCU", FOO)
    assert desc == []


# -- (5) history -----------------------------------------------------------------------------
def test_history_manifest_registry_field(env, monkeypatch):
    reg = env
    _foo(reg)
    reg.add_key("HKCU", RUN, {"V": (REG_SZ, "secret-data")})
    items = [_item(reg), _item(reg, cid="win_reg_startup", key=RUN, value="V")]
    _patch_scan(monkeypatch, items)
    assert cli.main(["clean", "--only", "win_reg_uninstall,win_reg_startup",
                     "--execute", "--yes"]) == 0
    runs = list((history.state_dir() / "runs").glob("*.jsonl"))
    assert len(runs) == 1
    rows = [json.loads(ln) for ln in runs[0].read_text(encoding="utf-8").splitlines()]
    shown = {r["registry"] for r in rows}
    assert shown == {"HKCU\\" + FOO, "HKCU\\" + RUN + " [V]"}
    assert all(r["path"] is None and r["command"] is None for r in rows)
    assert "secret-data" not in runs[0].read_text(encoding="utf-8")
    entries = history.load()
    assert entries[-1]["registry"] == 2
    json.dumps(entries)


def test_history_manifest_path_items_have_null_registry(env, tmp_path):
    from cleanix.core.models import CleanOutcome, CleanResult

    f = tmp_path / "x.bin"
    f.write_bytes(b"1")
    item = CleanableItem(cleaner_id="t", description="d", size=1, path=str(f))
    res = CleanResult(outcomes=[CleanOutcome(item=item, removed=True, freed=1)])
    p = history.write_manifest(res)
    row = json.loads(open(p, encoding="utf-8").read().splitlines()[0])
    assert row["registry"] is None and row["path"] == str(f)


# -- (6) completion / man page -----------------------------------------------------------------
@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_completion_offers_registry_ids(shell):
    script = completion.generate(shell)
    for cid in catalog.REGISTRY_IDS:
        assert cid in script


def test_manpage_in_sync(capsys):
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "gen_manpage", root / "scripts" / "gen_manpage.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()
    fresh = capsys.readouterr().out

    def body(t):
        return "\n".join(ln for ln in t.splitlines() if not ln.startswith(".TH "))

    committed = (root / "cleanix.1").read_text(encoding="utf-8")
    assert body(fresh).strip() == body(committed).strip()
    assert "\\-\\-yes" in committed



# -- fix round 1 ------------------------------------------------------------------
def _capture_only(monkeypatch):
    seen = []

    def fake_build(config, only=None, exclude=None):
        seen.append(None if only is None else list(only))
        return [_FakeCleaner(c, []) for c in (only or ["temp"])]

    monkeypatch.setattr(cli, "build_cleaners", fake_build)
    return seen


def test_registry_flag_selects_only_registry_ids(env, monkeypatch, capsys):
    seen = _capture_only(monkeypatch)
    assert cli.main(["scan", "--registry", "--json"]) == 0
    assert seen[-1] == list(catalog.REGISTRY_IDS)
    assert cli.main(["scan", "--registry", "--only", "temp", "--json"]) == 0
    assert seen[-1] == ["temp"] + list(catalog.REGISTRY_IDS)
    assert cli.main(["scan", "--registry", "--only", "win_reg_startup", "--json"]) == 0
    assert seen[-1].count("win_reg_startup") == 1
    assert cli.main(["scan", "--json"]) == 0 and seen[-1] is None
    assert cli.main(["scan", "--profile", "aggressive", "--json"]) == 0
    assert seen[-1] is None


def test_registry_flag_non_windows_exits_2(monkeypatch, capsys):
    monkeypatch.setattr(plat, "is_windows", lambda: False)
    for cmd in ("scan", "clean"):
        with pytest.raises(SystemExit) as ei:
            cli.main([cmd, "--registry"])
        assert ei.value.code == 2
        assert "Registry cleanup is only available on Windows." in capsys.readouterr().out


def test_registry_flag_counts_as_explicit_selection_for_clean(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    item = _item(reg)
    monkeypatch.setattr(cli, "build_cleaners", lambda config, only=None, exclude=None:
                        [_FakeCleaner(c, [item] if c == "win_reg_uninstall" else [])
                         for c in only])
    assert cli.main(["clean", "--registry", "--execute", "--yes"]) == 0
    assert not reg.key_exists("HKCU", FOO)


def test_completion_and_manpage_have_registry_flag():
    assert "--registry" in completion.SCAN_CLEAN_OPTS
    for sh in ("bash", "zsh"):
        assert "--registry" in completion.generate(sh)
    import pathlib
    man = (pathlib.Path(__file__).resolve().parent.parent / "cleanix.1").read_text(encoding="utf-8")
    assert "\\-\\-registry" in man


def _two_items(reg):
    _foo(reg)
    reg.add_key("HKCU", RUN, {"V": (REG_SZ, "x")})
    return [_item(reg), _item(reg, cid="win_reg_startup", key=RUN, value="V")]


def _tty(monkeypatch, answer):
    from rich.console import Console
    monkeypatch.setattr(Console, "is_terminal", property(lambda self: True))
    monkeypatch.setattr(cli.Prompt, "ask", lambda *a, **k: answer)


def test_interactive_deselected_registry_item_not_listed_nor_deleted(env, monkeypatch, capsys):
    reg = env
    items = _two_items(reg)
    _patch_scan(monkeypatch, items)
    _tty(monkeypatch, "1")  # skip the first (uninstall) entry
    monkeypatch.setattr(cli.Confirm, "ask", lambda *a, **k: True)
    rc = cli.main(["clean", "--only", "win_reg_uninstall,win_reg_startup",
                   "--execute", "--interactive"])
    import re
    out = re.sub(r"\[[0-9;]*m", "", capsys.readouterr().out)
    assert rc == 0
    assert reg.key_exists("HKCU", FOO)
    assert not reg.tree("HKCU", RUN)["values"]
    after = out.split("These registry entries will be removed:")[1]
    assert "Run [V]" in after and "Uninstall" not in after.split("Run [V]")[0]


def test_interactive_deselect_all_registry_no_notice(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    path_item = CleanableItem(cleaner_id="temp", description="t", size=999, path="C:\\none")
    _patch_scan(monkeypatch, [_item(reg), path_item])
    _tty(monkeypatch, "2")
    monkeypatch.setattr(cli.Confirm, "ask", lambda *a, **k: False)
    cli.main(["clean", "--only", "win_reg_uninstall,temp", "--execute", "--interactive"])
    out = capsys.readouterr().out
    assert "These registry entries will be removed" not in out
    assert reg.key_exists("HKCU", FOO)


EVIL = "evil[/].exe [red]x\u202etxt"


def _evil_item(reg, **kw):
    return _item(reg, desc="d " + EVIL, hint="h " + EVIL, **kw)


def _assert_literal(out):
    flat = out.replace("\n", "")
    assert "\u202e" not in out
    assert "evil[/].exe" in flat


def test_markup_safe_at_every_site(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    reg.add_key("HKCU", RUN, {"V" + EVIL: (REG_SZ, "x")})
    reg_item = _evil_item(reg)
    val_item = _evil_item(reg, cid="win_reg_startup", key=RUN, value="V" + EVIL)
    ro = CleanableItem(cleaner_id="temp", description="ro " + EVIL, size=1,
                       path="C:\\r", report_only=True, hint="how " + EVIL)
    _patch_scan(monkeypatch, [reg_item, val_item, ro])
    ids = "win_reg_uninstall,win_reg_startup,temp"
    # scan table + registry table + report-only list
    assert cli.main(["scan", "--only", ids]) == 0
    _assert_literal(capsys.readouterr().out)
    # explain
    assert cli.main(["explain", "win_reg_startup"]) == 0
    _assert_literal(capsys.readouterr().out)
    # simulation
    assert cli.main(["clean", "--only", ids, "--simulate"]) == 0
    _assert_literal(capsys.readouterr().out)
    # dry run + confirmation list (declined) + interactive labels
    assert cli.main(["clean", "--only", ids]) == 0
    _assert_literal(capsys.readouterr().out)
    monkeypatch.setattr(cli.Confirm, "ask", lambda *a, **k: False)
    assert cli.main(["clean", "--only", ids, "--execute"]) == 1
    _assert_literal(capsys.readouterr().out)
    _tty(monkeypatch, "")
    assert cli.main(["clean", "--only", ids, "--execute", "--interactive"]) == 1
    _assert_literal(capsys.readouterr().out)


def test_clean_summary_errors_are_markup_safe_and_run_id_survives(env, shipped, monkeypatch, capsys):
    reg = env
    _foo(reg)
    ok = _evil_item(reg)
    bad_reg = _evil_item(reg)
    reg.add_key("HKCU", FOO, {"DisplayVersion": (REG_SZ, "2.0")})  # changed since scan
    # `ok` now also fails its fingerprint; add a fresh good entry
    reg.add_key("HKCU", UNINST + r"\Good", {"DisplayName": (REG_SZ, "g")})
    good = _evil_item(reg, key=UNINST + r"\Good")
    _patch_scan(monkeypatch, [ok, good])
    rc = cli.main(["clean", "--only", "win_reg_uninstall", "--execute", "--yes"])
    out = capsys.readouterr().out
    assert rc == 2
    assert "evil[/].exe" in out.replace("\n", "")
    assert "\u202e" not in out
    run_id = quarantine.list_runs()[0]["run_id"]
    assert f"cleanix restore {run_id}" in out.replace("\n", "")


def test_run_id_and_undo_error_survive_summary_failure(env, shipped, monkeypatch, capsys):
    from cleanix.core import service

    reg = env
    _foo(reg)
    _patch_scan(monkeypatch, [_item(reg)])
    real = service.clean

    def wrapped(*a, **k):
        s = real(*a, **k)
        s.undo_record_error = "boom [red]x"
        return s

    monkeypatch.setattr(service, "clean", wrapped)

    def explode(*a, **k):
        raise RuntimeError("markup")

    monkeypatch.setattr(cli, "render_clean_summary", explode)
    cli.main(["clean", "--only", "win_reg_uninstall", "--execute", "--yes"])
    out = capsys.readouterr().out.replace("\n", "")
    run_id = quarantine.list_runs()[0]["run_id"]
    assert f"undo with cleanix restore {run_id}" in out
    assert "boom [red]x" in out


def test_restore_failure_lines_markup_safe(env, monkeypatch, capsys):
    monkeypatch.setattr(quarantine, "restore", lambda r, **k: {
        "restored": [], "failed": [("HKCU\\k [v" + EVIL + "]", "why [/] " + EVIL)]})
    monkeypatch.setattr(quarantine, "list_runs", lambda: [])
    assert cli.main(["restore", "run1"]) == 2
    _assert_literal(capsys.readouterr().out)


def test_history_registry_count_recorded_by_service(env, tmp_path):
    from cleanix.config import Config
    from cleanix.core import service

    reg = env
    _foo(reg)
    s = service.clean([_item(reg)], Config(), dry_run=False)
    assert s.removed == 1
    assert history.load()[-1]["registry"] == 1
    assert not hasattr(history, "annotate_last_registry")


def test_clean_no_terminal_without_yes_refuses_cleanly(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    _patch_scan(monkeypatch, [_item(reg)])

    def eof(*a, **k):
        raise EOFError

    monkeypatch.setattr(cli.Confirm, "ask", eof)
    assert cli.main(["clean", "--only", "win_reg_uninstall", "--execute"]) == 2
    assert reg.key_exists("HKCU", FOO)


def test_restore_no_terminal_refuses_cleanly(env, monkeypatch, capsys):
    reg, run_id = _hklm_run(env, monkeypatch)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)

    def eof(*a, **k):
        raise EOFError

    monkeypatch.setattr(cli.Prompt, "ask", eof)
    assert cli.main(["restore", run_id]) == 2
    assert not reg.key_exists("HKLM", FOO)


def test_dry_run_hklm_single_message_and_only_runnable_listed(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    _foo(reg, hive="HKLM", key=UNINST + r"\Bar")
    _patch_scan(monkeypatch, [_item(reg), _item(reg, hive="HKLM", key=UNINST + r"\Bar")])
    cli.main(["clean", "--only", "win_reg_uninstall"])
    out = capsys.readouterr().out.replace("\n", "")
    assert "will be skipped" in out and "require root" not in out
    tail = out.split("would be removed:")[1]
    assert "Foo" in tail and "Bar" not in tail


def test_confirmation_keeps_permanently_for_files(env, monkeypatch, capsys):
    reg = env
    _foo(reg)
    p = CleanableItem(cleaner_id="temp", description="t", size=5, path="C:\\none")
    _patch_scan(monkeypatch, [_item(reg), p])
    asked = []
    monkeypatch.setattr(cli.Confirm, "ask", lambda prompt, **k: asked.append(prompt) or False)
    cli.main(["clean", "--only", "win_reg_uninstall,temp", "--execute"])
    out = capsys.readouterr().out.replace("\n", "")
    assert asked and asked[0].startswith("Permanently remove")
    assert "permanently removed" in out
