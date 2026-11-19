"""Task 6: `cleanix review` and review.run (hermetic: tmp state/quarantine)."""

from __future__ import annotations

import builtins
import hashlib
import os

import pytest
from rich.console import Console

from cleanix import cli, completion
from cleanix.config import Config
from cleanix.core import actions, findings, history, quarantine, review, safety, service
from cleanix.core.models import CleanableItem, CleanerReport, ScanResult
from cleanix.core.remedy import path_remedy


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: tmp_path / "q")
    monkeypatch.setattr(cli, "_load_config", lambda: Config())
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
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


def _groups(items):
    scan = ScanResult(reports=[])
    by = {}
    for i in items:
        by.setdefault(i.cleaner_id, []).append(i)
    for cid, its in by.items():
        scan.reports.append(CleanerReport(cleaner_id=cid, name=cid,
                                          description="t", items=its))
    return findings.group_findings(scan)


def _script(answers):
    asked = []
    it = iter(answers)

    def ask(prompt):
        asked.append(prompt)
        a = next(it)
        if a is EOFError:
            raise EOFError
        if a is KeyboardInterrupt:
            raise KeyboardInterrupt
        return a

    ask.asked = asked
    return ask


def _act(permanent=False):
    return lambda its: service.act(its, Config(), dry_run=False,
                                   permanent=permanent)


def _console():
    return Console(record=True, width=300, force_terminal=False)


def _text(c):
    return c.export_text(clear=False).replace("\n", " ")


def _cli(monkeypatch, capsys, answers, *argv):
    ask = _script(answers)
    monkeypatch.setattr(builtins, "input", ask)
    code = cli.main(["review", *argv])
    return code, capsys.readouterr().out.replace("\n", " "), ask


# -- run()-level ----------------------------------------------------------

def test_review_delete_and_skip(tmp_path):
    a, b = _file(tmp_path, "a.bin", b"a"), _file(tmp_path, "b.bin", b"b")
    items = [_finding(a), _finding(b)]
    items[0] = CleanableItem(**{**items[0].__dict__, "size": 9000})
    c = _console()
    res = review.run(_groups(items), _script(["d", "s"]), _act(), c)
    assert not a.exists() and b.exists()
    assert res.removed == 1 and res.declined == 1 and len(res.runs) == 1
    out = _text(c)
    assert "cleanix restore" in out and res.runs[0] in out


def test_review_delete_rest_of_group(tmp_path):
    ps = [_file(tmp_path, f"f{i}.bin", bytes([i])) for i in range(3)]
    items = [_finding(p) for p in ps]
    ask = _script(["s", "g"])
    res = review.run(_groups(items), ask, _act(), _console())
    assert len(ask.asked) == 2  # no prompt after g
    assert res.removed == 2 and len(res.runs) == 1  # one batched run
    assert sum(p.exists() for p in ps) == 1


def test_review_skip_rest_of_group(tmp_path):
    ps = [_file(tmp_path, f"f{i}.bin", bytes([i])) for i in range(3)]
    ask = _script(["n"])
    res = review.run(_groups([_finding(p) for p in ps]), ask, _act(), _console())
    assert len(ask.asked) == 1 and res.removed == 0 and res.declined == 3
    assert all(p.exists() for p in ps)


def test_review_quit_stops(tmp_path):
    ps = [_file(tmp_path, f"f{i}.bin", bytes([i])) for i in range(3)]
    ask = _script(["d", "q"])
    res = review.run(_groups([_finding(p) for p in ps]), ask, _act(), _console())
    assert res.quit and not res.aborted and res.removed == 1
    assert sum(p.exists() for p in ps) == 2


def test_review_eof_is_clean_exit(tmp_path, monkeypatch, capsys):
    ps = [_file(tmp_path, f"f{i}.bin", bytes([i])) for i in range(2)]
    c = _console()
    res = review.run(_groups([_finding(p) for p in ps]),
                     _script(["d", EOFError]), _act(), c)
    assert res.aborted and res.removed == 1 and "interrupted" in _text(c)
    res = review.run(_groups([_finding(p) for p in ps if p.exists()]),
                     _script([KeyboardInterrupt]), _act(), c)
    assert res.aborted and res.removed == 0
    # CLI level: exit 1 for a user abort, nothing deleted without a "d"
    p = _file(tmp_path, "solo.bin", b"solo")
    _patch_scan(monkeypatch, [_finding(p)])
    code, out, _ = _cli(monkeypatch, capsys, [EOFError], "big_files")
    assert code == 1 and p.exists() and "interrupted" in out.lower()


def test_review_empty_input_is_skip(tmp_path):
    p = _file(tmp_path)
    res = review.run(_groups([_finding(p)]), _script([""]), _act(), _console())
    assert p.exists() and res.declined == 1 and res.removed == 0


def test_review_invalid_input_reprompts(tmp_path):
    p = _file(tmp_path)
    ask = _script(["delete", "yes", "D!", "?", "x", "d"])
    c = _console()
    res = review.run(_groups([_finding(p)]), ask, _act(), c)
    assert len(ask.asked) == 6 and not p.exists() and res.removed == 1
    assert "Not understood" in _text(c) and "quit the review" in _text(c)


def test_review_duplicate_never_offers_last_copy(tmp_path):
    paths, items = _dups(tmp_path, n=2)
    ask = _script(["d"])
    c = _console()
    res = review.run(_groups(items), ask, _act(), c, keep="oldest")
    assert len(ask.asked) == 1  # only the other copy is asked about
    assert paths[0].exists() and not paths[1].exists() and res.removed == 1
    assert str(paths[0]) in _text(c)  # the survivor is shown
    # Even answering g for everything never removes the survivor.
    paths, items = _dups(tmp_path, n=3, data=b"e" * 9000)
    res = review.run(_groups(items), _script(["g"]), _act(), _console(),
                     keep="newest")
    assert paths[2].exists() and not paths[0].exists() and not paths[1].exists()


def test_review_hostile_filename_escaped(tmp_path):
    p = _file(tmp_path, "[bold red]boo.bin")
    it = _finding(p, desc="evil\x1b[31m‮gnp.exe")
    c = _console()
    review.run(_groups([it]), _script(["s"]), _act(), c)
    out = c.export_text()
    assert "\x1b" not in out and "‮" not in out and "[bold red]boo.bin" in out


def test_review_summary_lists_skips_and_errors_separately(tmp_path, monkeypatch):
    ok = _file(tmp_path, "ok.bin", b"ok")
    gone = _file(tmp_path, "gone.bin", b"gone")
    bad = _file(tmp_path, "bad.bin", b"bad")
    items = [_finding(ok), _finding(gone), _finding(bad)]
    real = actions.act
    gone.write_bytes(b"changed after the scan")

    def boom(*a, **k):
        raise OSError("disk on fire")

    c = _console()
    # ok removed; gone is stale -> skipped; bad hits a real error.
    ans = iter(["d", "d", "d"])

    def ask(prompt):
        a = next(ans)
        return a

    def act(its):
        if its[0].path == str(bad):
            monkeypatch.setattr(safety, "safe_rmtree", boom)
        return real(its, Config(), dry_run=False, permanent=True)

    res = review.run(_groups(items), ask, act, c, permanent=True)
    out = _text(c)
    assert not ok.exists() and gone.exists()
    assert len(res.skipped) == 1 and "changed since scan" in out
    assert "Skipped 1 item(s)" in out
    assert "error(s)" in out and "disk on fire" in out and res.failed
    assert res.removed == 1 and bad.exists()


# -- CLI-level ------------------------------------------------------------

def test_review_refuses_non_tty(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path)
    calls = _patch_scan(monkeypatch, [_finding(p)])
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)
    code, out, ask = _cli(monkeypatch, capsys, [], "big_files")
    assert code == 2 and "terminal" in out and p.exists()
    assert ask.asked == [] and calls == []


def test_review_unknown_scenario_exits_2(monkeypatch, capsys):
    code, out, _ = _cli(monkeypatch, capsys, [], "nonsense")
    assert code == 2 and "unknown scenario" in out
    code, out, _ = _cli(monkeypatch, capsys, [], "temp")
    assert code == 2 and "not a findings scenario" in out


def test_review_rejects_all_word(monkeypatch, capsys):
    for word in ("all", "ALL", "*"):
        code, out, _ = _cli(monkeypatch, capsys, [], word)
        assert code == 2 and "does not accept" in out


def test_review_cli_delete_and_exit_codes(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path, data=b"keep me")
    calls = _patch_scan(monkeypatch, [_finding(p)])
    code, out, _ = _cli(monkeypatch, capsys, ["d"], "BIG_FILES")
    assert code == 0 and not p.exists() and calls == [["big_files"]]
    (run,) = quarantine.list_runs()
    quarantine.restore(run["run_id"])
    assert p.read_bytes() == b"keep me"


def test_review_no_args_reviews_applicable_scenarios(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path)
    calls = _patch_scan(monkeypatch, [_finding(p)])
    code, out, ask = _cli(monkeypatch, capsys, ["s"])
    assert code == 0 and p.exists() and len(ask.asked) == 1
    assert calls[0] and set(calls[0]) <= set(findings.FINDING_CATEGORIES)


def test_review_duplicates_require_keep(tmp_path, monkeypatch, capsys):
    paths, items = _dups(tmp_path)
    _patch_scan(monkeypatch, items)
    code, out, ask = _cli(monkeypatch, capsys, ["d"], "duplicates")
    assert code == 2 and "--keep" in out and ask.asked == []
    assert all(p.exists() for p in paths)
    # also when found via a no-argument review
    code, out, ask = _cli(monkeypatch, capsys, ["d"])
    assert code == 2 and "--keep" in out and ask.asked == []
    code, out, ask = _cli(monkeypatch, capsys, ["d"], "duplicates", "--keep", "oldest")
    assert code == 0 and paths[0].exists() and not paths[1].exists()


def test_review_never_offers_root_items(tmp_path, monkeypatch, capsys):
    user = _file(tmp_path, "u.bin", b"u")
    sysf = _file(tmp_path, "sys.bin", b"s")
    _patch_scan(monkeypatch, [_finding(user), _finding(sysf, requires_root=True)])
    code, out, ask = _cli(monkeypatch, capsys, ["d", "d"], "big_files")
    assert len(ask.asked) == 1 and sysf.exists() and not user.exists()
    assert "sys.bin" not in out


def test_review_permanent_wording(tmp_path, monkeypatch, capsys):
    p = _file(tmp_path)
    _patch_scan(monkeypatch, [_finding(p)])
    code, out, _ = _cli(monkeypatch, capsys, ["d"], "big_files", "--permanent")
    assert code == 0 and not p.exists() and "permanent, no undo" in out
    assert quarantine.list_runs() == []


def test_completion_mentions_review():
    for shell in ("bash", "zsh", "fish"):
        assert "review" in completion.generate(shell)
