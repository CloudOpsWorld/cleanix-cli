"""Task 5: `cleanix clean --act-on` (hermetic: tmp home, state and quarantine)."""

from __future__ import annotations

import hashlib
import os

import pytest

from cleanix import cli, completion
from cleanix.config import Config
from cleanix.core import actions, findings, history, quarantine, safety, service
from cleanix.core.models import CleanableItem, CleanerReport
from cleanix.core.remedy import path_remedy


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: tmp_path / "q")
    monkeypatch.setattr(cli, "_load_config", lambda: Config())
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)
    monkeypatch.setenv("COLUMNS", "400")
    findings._hash_cache.clear()
    yield
    findings._hash_cache.clear()
    safety.set_protected_globs([])


class _Fake:
    def __init__(self, cid, items):
        self.id = cid
        self.name = cid
        self._items = items

    def scan(self):
        return CleanerReport(cleaner_id=self.id, name=self.name,
                             description="test", items=list(self._items))


def _patch_scan(monkeypatch, items):
    by_cid = {}
    for i in items:
        by_cid.setdefault(i.cleaner_id, []).append(i)
    calls = []

    def fake_build(config, only=None, exclude=None):
        calls.append(list(only) if only else None)
        ids = only or list(by_cid)
        return [_Fake(c, by_cid.get(c, [])) for c in ids]

    monkeypatch.setattr(cli, "build_cleaners", fake_build)
    return calls


def _file(tmp_path, name="big.bin", data=b"x" * 4096, mtime_ns=None):
    d = tmp_path / "home"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_bytes(data)
    if mtime_ns is not None:
        os.utime(str(p), ns=(mtime_ns, mtime_ns))
    return p


def _finding(p, cleaner="big_files", group=None, desc=None, **kw):
    r = path_remedy(str(p), group=group)
    assert r is not None
    return CleanableItem(
        cleaner_id=cleaner, description=desc or p.name, size=4096,
        path=str(p), report_only=True, remedy=r, **kw)


def _dups(tmp_path, n=2, data=b"d" * 8192):
    base = 1_600_000_000 * 10**9
    paths = [_file(tmp_path, f"copy{i}.iso", data, mtime_ns=base + i * 10**9)
             for i in range(n)]
    group = hashlib.sha256(data).hexdigest()
    return paths, [_finding(p, "duplicates", group) for p in paths]


def _run(capsys, *argv):
    code = cli.main(["clean", *argv])
    return code, capsys.readouterr().out.replace("\n", " ")


def test_act_on_unknown_scenario_exits_2(capsys):
    code, out = _run(capsys, "--act-on", "nonsense")
    assert code == 2 and "unknown scenario" in out
    code, out = _run(capsys, "--act-on", "")
    assert code == 2
    code, out = _run(capsys, "--act-on", "big_files,")
    assert code == 2


def test_act_on_rejects_all_word(capsys):
    for word in ("all", "ALL", "*", "big_files,all"):
        code, out = _run(capsys, "--act-on", word)
        assert code == 2 and "does not accept" in out


def test_act_on_rejects_non_finding_cleaner(capsys):
    code, out = _run(capsys, "--act-on", "temp")
    assert code == 2 and "not a findings scenario" in out


def test_act_on_rejects_combination_with_only(capsys):
    for extra in (["--only", "temp"], ["--exclude", "temp"], ["--registry"],
                  ["--profile", "safe"], ["--quarantine"], ["--simulate"]):
        code, out = _run(capsys, "--act-on", "big_files", *extra)
        assert code == 2 and "cannot be combined" in out


def test_act_on_preview_by_default(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path)
    calls = _patch_scan(monkeypatch, [_finding(p)])
    code, out = _run(capsys, "--act-on", "big_files")
    assert code == 0 and p.exists()
    assert calls == [["big_files"]]  # only the named scenario is scanned
    assert "--execute" in out and "dry run" in out
    assert "cleanix restore" in out and "undo" in out
    assert quarantine.list_runs() == []


def test_act_on_execute_requires_yes_noninteractive(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path)
    _patch_scan(monkeypatch, [_finding(p)])
    code, out = _run(capsys, "--act-on", "big_files", "--execute")
    assert code == 2 and p.exists() and "--yes" in out


def test_act_on_execute_prompts_when_interactive(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path)
    _patch_scan(monkeypatch, [_finding(p)])
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    asked = []
    monkeypatch.setattr(cli.Confirm, "ask",
                        lambda q, **kw: asked.append(q) or False)
    code, out = _run(capsys, "--act-on", "big_files", "--execute")
    assert code == 1 and p.exists() and len(asked) == 1 and "1 item" in asked[0]


def test_act_on_duplicates_requires_keep(tmp_path, monkeypatch, capsys):
    paths, items = _dups(tmp_path)
    _patch_scan(monkeypatch, items)
    code, out = _run(capsys, "--act-on", "duplicates")
    assert code == 2 and "--keep" in out
    assert all(p.exists() for p in paths)


def test_act_on_executes_and_quarantines_with_yes(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path, data=b"keep me")
    _patch_scan(monkeypatch, [_finding(p)])
    code, out = _run(capsys, "--act-on", "big_files", "--execute", "--yes")
    assert code == 0 and not p.exists()
    runs = quarantine.list_runs()
    assert len(runs) == 1 and runs[0]["run_id"] in out
    assert "Freed" in out and "cleanix restore" in out
    quarantine.restore(runs[0]["run_id"])
    assert p.read_bytes() == b"keep me"


def test_act_on_duplicates_keep_oldest(tmp_path, monkeypatch, capsys):
    paths, items = _dups(tmp_path, n=3)
    _patch_scan(monkeypatch, items)
    code, out = _run(capsys, "--act-on", "duplicates", "--keep", "oldest",
                     "--execute", "--yes")
    assert code == 0
    assert paths[0].exists() and not paths[1].exists() and not paths[2].exists()


def test_act_on_permanent(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path)
    _patch_scan(monkeypatch, [_finding(p)])
    code, out = _run(capsys, "--act-on", "big_files", "--permanent")
    assert "permanent, no undo" in out and p.exists()
    code, out = _run(capsys, "--act-on", "big_files", "--permanent",
                     "--execute", "--yes")
    assert code == 0 and not p.exists()
    assert quarantine.list_runs() == []
    assert [e["mode"] for e in history.load()] == ["delete"]


def test_act_on_category_name(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path)
    calls = _patch_scan(monkeypatch, [_finding(p)])
    code, out = _run(capsys, "--act-on", "your FILES", "--keep", "oldest")
    assert code == 0
    ids = set(calls[0])
    assert {"big_files", "downloads"} <= ids
    assert ids <= {c for c, k in findings.FINDING_CATEGORIES.items()
                   if k == findings.YOUR_FILES}


def test_findings_rendered_by_category(tmp_path, monkeypatch, capsys):
    a = _file(tmp_path, "a.bin")
    b = _file(tmp_path, "b.dir")
    _patch_scan(monkeypatch, [
        _finding(b, "orphan_app_data", desc="Leftover B"),
        _finding(a, "big_files", desc="Big A"),
    ])
    code, out = _run(capsys, "--act-on", "big_files,orphan_app_data")
    assert code == 0
    i1, i2 = out.index(findings.YOUR_FILES), out.index(findings.APP_LEFTOVERS)
    assert i1 < i2
    assert out.index("Big A") < i2 < out.index("Leftover B")


def test_default_clean_still_ignores_findings(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path)
    _patch_scan(monkeypatch, [_finding(p)])
    code = cli.main(["clean", "--execute", "--yes"])
    out = capsys.readouterr().out
    assert p.exists()
    assert "Nothing to clean" in out or "report-only" in out.lower()
    assert code == 0
    assert cli.main(["clean", "--keep", "oldest"]) == 2


def test_act_on_skips_and_errors_reported_separately(tmp_path, monkeypatch, capsys):
    ok = _file(tmp_path, "ok.bin", b"ok")
    gone = _file(tmp_path, "gone.bin", b"gone")
    sysf = _file(tmp_path, "sys.bin", b"sys")
    items = [_finding(ok), _finding(gone),
             _finding(sysf, requires_root=True)]
    _patch_scan(monkeypatch, items)
    real = actions.act

    def act_and_change(its, config, **kw):
        if not kw.get("dry_run", True):
            gone.write_bytes(b"changed after the preview")
        return real(its, config, **kw)

    monkeypatch.setattr(service, "act", act_and_change)
    code, out = _run(capsys, "--act-on", "big_files", "--execute", "--yes")
    assert code == 0  # skips are not failures
    assert not ok.exists() and gone.exists() and sysf.exists()
    assert "Needs an elevated run (not done here)" in out
    assert "Skipped 2 item(s)" in out and "changed since scan" in out


def test_act_on_exit_code_2_on_real_error(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path)
    _patch_scan(monkeypatch, [_finding(p)])
    def boom(*a, **k):
        raise OSError("disk on fire")

    monkeypatch.setattr(safety, "safe_rmtree", boom)
    code, out = _run(capsys, "--act-on", "big_files", "--permanent",
                     "--execute", "--yes")
    assert code == 2 and "disk on fire" in out and p.exists()


def test_hostile_filename_is_escaped_in_output(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path, "[bold red]boo.bin")
    q = _file(tmp_path, "plain.bin")
    _patch_scan(monkeypatch, [
        _finding(p), _finding(q, desc="evil\x1b[31m‮gnp.exe")])
    code, out = _run(capsys, "--act-on", "big_files")
    assert code == 0
    assert "[bold red]boo.bin" in out
    assert "\x1b" not in out and "‮" not in out


def test_completion_mentions_act_on():
    assert "--act-on" in completion.generate("bash")
    assert "--keep" in completion.generate("bash")
    assert "--permanent" in completion.generate("zsh")
    assert "oldest" in completion.generate("fish")


def test_hash_cache_and_cancel(tmp_path, monkeypatch):
    p = _file(tmp_path, data=b"h" * 5000)
    group = hashlib.sha256(b"h" * 5000).hexdigest()
    fp = path_remedy(str(p)).fingerprint
    reads = []
    real = findings._sha256_of

    def counting(path, cancel):
        reads.append(path)
        return real(path, cancel)

    monkeypatch.setattr(findings, "_sha256_of", counting)
    # A cancel mid-hash is a refusal and is not cached.
    why = findings.content_matches_group(str(p), group, fingerprint=fp,
                                         cancel=lambda: True)
    assert why == findings.CANCELLED and not findings._hash_cache
    # Hashed once for repeated checks (dry run then real act).
    assert findings.content_matches_group(str(p), group, fingerprint=fp) is None
    assert findings.content_matches_group(str(p), group, fingerprint=fp) is None
    assert len(reads) == 2  # the cancelled attempt + one real hash
    # A different fingerprint never reuses the entry.
    other = (fp[0], fp[1] + 1, fp[2], fp[3])
    assert findings.content_matches_group(str(p), group, fingerprint=other) is None
    assert len(reads) == 3
    # Cancel is polled between chunks, not only at the start.
    big = _file(tmp_path, "big2.bin", b"z" * (findings._CHUNK * 3))
    polls = []

    def cancel():
        polls.append(1)
        return len(polls) >= 2

    why = findings.content_matches_group(
        str(big), hashlib.sha256(b"z" * (findings._CHUNK * 3)).hexdigest(),
        cancel=cancel)
    assert why == findings.CANCELLED and len(polls) == 2


def test_act_dry_run_then_act_hashes_kept_copy_once(tmp_path, monkeypatch):
    paths, items = _dups(tmp_path, n=2)
    plan = findings.plan_duplicates(items, "oldest")
    reads = []
    real = findings._sha256_of
    monkeypatch.setattr(findings, "_sha256_of",
                        lambda p, c: reads.append(p) or real(p, c))
    actions.act(plan.items, Config(), dry_run=True, record_history=False)
    s = actions.act(plan.items, Config(), dry_run=False)
    assert s.removed == 1 and len(reads) == 1


def test_act_on_keep_without_duplicates_is_an_error(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path)
    _patch_scan(monkeypatch, [_finding(p)])
    code, out = _run(capsys, "--act-on", "big_files", "--keep", "oldest")
    assert code == 2 and "--keep only applies" in out and p.exists()


def test_plan_exposes_kept_copies_and_cli_never_lists_them_as_skipped(
        tmp_path, monkeypatch, capsys):
    paths, items = _dups(tmp_path, n=2)
    plan = findings.plan_duplicates(items, "oldest")
    assert [i.path for i in plan.kept] == [str(paths[0])]
    monkeypatch.setattr(findings, "KEPT", "zzz: the one that stays")
    _patch_scan(monkeypatch, items)
    code, out = _run(capsys, "--act-on", "duplicates", "--keep", "oldest",
                     "--execute", "--yes")
    assert code == 0 and paths[0].exists() and not paths[1].exists()
    assert "Skipped" not in out
