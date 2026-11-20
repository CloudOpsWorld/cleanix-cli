"""Final-review data-loss regressions (hermetic: tmp homes, state, quarantine).

C1: acting on findings in several calls (``review`` acts per answer) must
never remove the copy a duplicate group keeps -- e.g. a Downloads finding
that IS that kept copy.
C2: duplicate groups never span accounts; acting on findings never scans
every user's home.
I2: ``clean --act-on --execute`` acts only on what the preview showed as
acted on.
"""

from __future__ import annotations

import hashlib
import os
import time

import pytest
from rich.console import Console

from cleanix import cli
from cleanix.cleaners import downloads as wmod
from cleanix.cleaners import duplicates as dmod
from cleanix.config import Config
from cleanix.core import actions, context, findings, history, quarantine, review, safety, service
from cleanix.core.models import CleanableItem, CleanerReport, ScanResult
from cleanix.core.remedy import path_remedy


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: tmp_path / "q")
    monkeypatch.setattr(cli, "_load_config", lambda: Config())
    monkeypatch.setenv("COLUMNS", "400")
    findings._hash_cache.clear()
    yield
    findings._hash_cache.clear()
    safety.set_protected_globs([])


def _config():
    cfg = Config()
    cfg.dup_min_size_mb = 1.0
    cfg.downloads_min_size_mb = 1.0
    cfg.downloads_stale_days = 1
    cfg.protected_globs = []
    return cfg


def _downloads_and_dups(tmp_path, monkeypatch):
    """~/Downloads/x.iso (oldest, so kept by --keep oldest), ~/b.iso and
    ~/c.iso identical; x.iso is also an old download. Returns (kept,
    others, groups) from the real reporters, dup group first."""
    root = tmp_path / "home"
    (root / "Downloads").mkdir(parents=True)
    data = os.urandom(2 * 1024 * 1024)
    kept = root / "Downloads" / "x.iso"
    others = [root / "b.iso", root / "c.iso"]
    for i, p in enumerate([kept] + others):
        p.write_bytes(data)
        t = time.time() - 86400 * (100 - i)  # kept is the oldest
        os.utime(str(p), (t, t))
    monkeypatch.setattr(dmod, "home", lambda: root)
    monkeypatch.setattr(wmod, "home", lambda: root)
    cfg = _config()
    reports = [dmod.DuplicateFileReporter(cfg).scan(), wmod.DownloadsReporter(cfg).scan()]
    groups = findings.group_findings(ScanResult(reports=reports))
    order = [g.cleaner_id for g in groups]
    assert order.index("duplicates") < order.index("downloads"), order
    return kept, others, groups


def _real_act(cfg):
    def act(items, protect=None):
        return service.act(items, cfg, dry_run=False, permanent=True,
                           record_history=False, protect=protect)
    return act


# -- C1 ------------------------------------------------------------------------

def test_review_never_removes_the_kept_copy_offered_by_another_scenario(tmp_path, monkeypatch):
    """The reviewer's reproduction: d to b and c (each keeps x.iso), then
    d to the Downloads finding x.iso. Before the fix all three were gone."""
    kept, others, groups = _downloads_and_dups(tmp_path, monkeypatch)
    answers = iter(["d"] * 20)
    c = Console(record=True, width=300, force_terminal=False)
    res = review.run(groups, lambda p: next(answers), _real_act(_config()), c,
                     keep="oldest", permanent=True)
    assert kept.exists(), "the copy kept by the duplicate group was removed"
    assert not any(p.exists() for p in others)
    assert any(i.path == str(kept) and why == actions.KEEPS_COPY for i, why in res.skipped)
    assert actions.KEEPS_COPY in c.export_text()


def test_review_layer_never_passes_a_kept_copy_to_act(tmp_path, monkeypatch):
    """Even with an act callable that ignores ``protect``, review itself
    never hands the kept copy over (independent of the executor layer)."""
    kept, others, groups = _downloads_and_dups(tmp_path, monkeypatch)
    cfg = _config()
    seen = []

    def act(items, protect=None):  # ignores protect on purpose
        seen.extend(i.path for i in items)
        return service.act(items, cfg, dry_run=False, permanent=True,
                           record_history=False)

    answers = iter(["d"] * 20)
    review.run(groups, lambda p: next(answers), act,
               Console(record=True, width=300), keep="oldest", permanent=True)
    assert str(kept) not in seen
    assert kept.exists()


def test_review_g_answer_also_protects_the_kept_copy(tmp_path, monkeypatch):
    kept, others, groups = _downloads_and_dups(tmp_path, monkeypatch)
    answers = iter(["g"] * 20)
    review.run(groups, lambda p: next(answers), _real_act(_config()),
               Console(record=True, width=300), keep="oldest", permanent=True)
    assert kept.exists()


def test_review_passes_the_session_kept_copies_to_act(tmp_path, monkeypatch):
    kept, others, groups = _downloads_and_dups(tmp_path, monkeypatch)
    got = []

    def act(items, protect=None):
        got.append(list(protect or []))
        return service.act(items, _config(), dry_run=True, record_history=False,
                           protect=protect)

    answers = iter(["d"] * 20)
    review.run(groups, lambda p: next(answers), act,
               Console(record=True, width=300), keep="oldest")
    assert got and all(findings.path_key(kept) in
                       {findings.path_key(s.path) for s in p} for p in got)


def test_same_set_in_one_batch_fails_closed(tmp_path, monkeypatch):
    kept, others, groups = _downloads_and_dups(tmp_path, monkeypatch)
    dups = [i for g in groups if g.cleaner_id == "duplicates" for i in g.items]
    dl = [i for g in groups if g.cleaner_id == "downloads" for i in g.items]
    plan = findings.plan_duplicates(dups, "oldest")
    pre = service.act(plan.items + dl, _config(), dry_run=True, record_history=False)
    assert any(i.path == str(kept) and why == actions.KEEPS_COPY for i, why in pre.skipped)


def test_separate_act_calls_protect_with_kept_context(tmp_path, monkeypatch):
    """GUI-like pattern: copies acted on in one call, the Downloads item in
    a later call. With the plan's kept context the later call refuses the
    kept copy; without it, the executor alone cannot know (dry run only)."""
    kept, others, groups = _downloads_and_dups(tmp_path, monkeypatch)
    cfg = _config()
    dups = [i for g in groups if g.cleaner_id == "duplicates" for i in g.items]
    dl = [i for g in groups if g.cleaner_id == "downloads" for i in g.items]
    plan = findings.plan_duplicates(dups, "oldest")
    ctx = findings.kept_context(plan.items, plan.kept)
    first = actions.act(plan.items, cfg, dry_run=False, permanent=True,
                        record_history=False, protect=ctx)
    assert first.removed == 2
    # Without protect the later call would act on it (shown on a dry run).
    unprotected = actions.act(dl, cfg, dry_run=True, record_history=False)
    assert not unprotected.skipped
    second = actions.act(dl, cfg, dry_run=False, permanent=True,
                         record_history=False, protect=ctx)
    assert second.removed == 0
    assert [(i.path, w) for i, w in second.skipped] == [(str(kept), actions.KEEPS_COPY)]
    assert kept.exists()


def test_act_protect_covers_a_group_planned_in_another_call(tmp_path):
    """``protect`` alone (no stamped copy in this batch) protects the kept
    copy and any folder containing it."""
    d = tmp_path / "home" / "keep"
    d.mkdir(parents=True)
    k = d / "kept.bin"
    k.write_bytes(b"k" * 4096)
    r = path_remedy(str(k), group="a" * 64)
    stamp = findings.Survivor(str(k), tuple(r.fingerprint), "a" * 64)
    file_item = CleanableItem(cleaner_id="big_files", description="k", size=1,
                              path=str(k), report_only=True, remedy=path_remedy(str(k)))
    folder_item = CleanableItem(cleaner_id="big_files", description="d", size=1,
                                path=str(d), report_only=True, remedy=path_remedy(str(d)))
    for item in (file_item, folder_item):
        s = actions.act([item], Config(), dry_run=False, permanent=True,
                        record_history=False, protect=[stamp])
        assert s.removed == 0 and s.skipped[0][1] == actions.KEEPS_COPY
    assert k.exists()


def test_service_act_passes_protect_through(tmp_path, monkeypatch):
    got = {}

    def fake(items, config, **kw):
        got.update(kw)
        return "ok"

    monkeypatch.setattr(actions, "act", fake)
    service.act([], Config(), protect=["x"])
    assert got["protect"] == ["x"]


# -- C2 ------------------------------------------------------------------------

def _two_accounts(tmp_path):
    data = b"z" * 8192
    group = hashlib.sha256(data).hexdigest()
    items, owner = [], {}
    base = 1_600_000_000 * 10**9
    for n, (user, uid) in enumerate((("alice", 1000), ("bob", 1001))):
        h = tmp_path / user
        h.mkdir()
        for m, name in enumerate(("x.iso", "copy of x.iso")):
            p = h / name
            p.write_bytes(data)
            t = base + (n * 10 + m) * 10**9  # alice's files are older
            os.utime(str(p), ns=(t, t))
            owner[findings.path_key(str(p))] = uid
            items.append(CleanableItem(cleaner_id="duplicates", description=name,
                                       size=8192, path=str(p), report_only=True,
                                       remedy=path_remedy(str(p), group=group)))
    return items, owner


def _fake_owners(monkeypatch, owner):
    monkeypatch.setattr(findings, "_is_posix", lambda: True)
    monkeypatch.setattr(findings, "_owner_uid",
                        lambda p: owner.get(findings.path_key(p)))


def test_plan_duplicates_skips_a_group_spanning_accounts(tmp_path, monkeypatch):
    items, owner = _two_accounts(tmp_path)
    _fake_owners(monkeypatch, owner)
    plan = findings.plan_duplicates(items, "oldest")
    assert plan.items == [] and plan.kept == []
    assert {w for _i, w in plan.skipped} == {findings.DIFFERENT_OWNERS}
    assert len(plan.skipped) == 4


def test_plan_duplicates_keeping_skips_a_group_spanning_accounts(tmp_path, monkeypatch):
    """The GUI's planner goes through the same check."""
    items, owner = _two_accounts(tmp_path)
    _fake_owners(monkeypatch, owner)
    plan = findings.plan_duplicates_keeping(items, {items[0].remedy.group: items[0]})
    assert plan.items == [] and plan.kept == []
    assert {w for _i, w in plan.skipped} == {findings.DIFFERENT_OWNERS}


def test_same_account_group_is_still_planned(tmp_path, monkeypatch):
    items, owner = _two_accounts(tmp_path)
    owner = {k: 1000 for k in owner}
    _fake_owners(monkeypatch, owner)
    plan = findings.plan_duplicates(items, "oldest")
    assert len(plan.items) == 3 and len(plan.kept) == 1


def test_owner_check_is_off_on_windows(monkeypatch):
    monkeypatch.setattr(findings, "_is_posix", lambda: False)
    monkeypatch.setattr(findings, "_owner_uid", lambda p: {"a": 1, "b": 2}[p])
    assert not findings.owners_differ(["a", "b"])


def test_act_refuses_a_stamped_copy_owned_by_another_account(tmp_path, monkeypatch):
    items, owner = _two_accounts(tmp_path)
    alice = [i for i in items if "alice" in i.path]
    plan = findings.plan_duplicates(alice, "oldest")  # same owner: planned
    assert len(plan.items) == 1
    # A forged/old stamp now naming bob's file as the kept copy is refused
    # at act time when the owners differ.
    _fake_owners(monkeypatch, {**owner, findings.path_key(alice[0].path): 1001})
    s = actions.act(plan.items, Config(), dry_run=True, record_history=False)
    assert [w for _i, w in s.skipped] == [findings.DIFFERENT_OWNERS]


def _patch_scan(monkeypatch, items):
    class _Fake:
        def __init__(self, cid, its):
            self.id = self.name = cid
            self._items = its

        def scan(self):
            return CleanerReport(cleaner_id=self.id, name=self.name,
                                 description="t", items=list(self._items))

    by = {}
    for i in items:
        by.setdefault(i.cleaner_id, []).append(i)
    monkeypatch.setattr(cli, "build_cleaners",
                        lambda config, only=None, exclude=None:
                        [_Fake(c, by.get(c, [])) for c in (only or list(by))])


@pytest.mark.parametrize("extra", [["--all-users"], ["--current-user"],
                                   ["--min-uid", "0"], ["--min-uid", "1000"]])
def test_act_on_rejects_scope_flags(capsys, extra):
    code = cli.main(["clean", "--act-on", "big_files", *extra])
    out = capsys.readouterr().out.replace("\n", " ")
    assert code == 2
    assert "cannot be combined with" in out and "only your own account" in out


def _record_scope(monkeypatch):
    calls = []
    real = context.configure

    def spy(all_users=None, min_uid=None):
        calls.append(all_users)
        real(all_users=all_users, min_uid=min_uid)

    monkeypatch.setattr(context, "configure", spy)
    return calls


def test_act_on_scans_only_the_invoking_user_even_as_root(tmp_path, monkeypatch, capsys):
    p = tmp_path / "f.bin"
    p.write_bytes(b"x" * 10)
    _patch_scan(monkeypatch, [CleanableItem(
        cleaner_id="big_files", description="f", size=10, path=str(p),
        report_only=True, remedy=path_remedy(str(p)))])
    monkeypatch.setattr(context, "is_effective_root", lambda: True)
    calls = _record_scope(monkeypatch)
    assert cli.main(["clean", "--act-on", "big_files"]) == 0
    assert calls == [False]


def test_review_scans_only_the_invoking_user_even_as_root(tmp_path, monkeypatch, capsys):
    p = tmp_path / "f.bin"
    p.write_bytes(b"x" * 10)
    _patch_scan(monkeypatch, [CleanableItem(
        cleaner_id="big_files", description="f", size=10, path=str(p),
        report_only=True, remedy=path_remedy(str(p)))])
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "q")
    monkeypatch.setattr(context, "is_effective_root", lambda: True)
    calls = _record_scope(monkeypatch)
    assert cli.main(["review", "big_files"]) == 0
    assert calls == [False]


def test_single_user_scope_under_root_is_the_invoking_user(monkeypatch, tmp_path):
    """What _act_scope relies on: all_users=False under root (sudo) means
    the invoking (SUDO_USER) account only."""
    me = context.TargetUser("alice", tmp_path, 1000, 1000, True)
    monkeypatch.setattr(context, "is_effective_root", lambda: True)
    monkeypatch.setattr(context, "invoking_user", lambda: me)
    monkeypatch.setattr(context, "_all_users",
                        lambda min_uid: pytest.fail("all users scanned"))
    try:
        cli._act_scope()
        assert context.get_target_users() == [me]
    finally:
        context.configure()


# -- I2 ------------------------------------------------------------------------

def test_execute_never_acts_on_an_item_the_preview_skipped(tmp_path, monkeypatch, capsys):
    """A transient failure (the kept copy could not be read) skips a copy in
    the preview; it must not be acted on after confirmation even though
    the condition cleared."""
    data = b"d" * 8192
    group = hashlib.sha256(data).hexdigest()
    home = tmp_path / "home"
    home.mkdir()
    paths = []
    for n in range(2):
        p = home / f"copy{n}.iso"
        p.write_bytes(data)
        t = 1_600_000_000 * 10**9 + n * 10**9
        os.utime(str(p), ns=(t, t))
        paths.append(p)
    items = [CleanableItem(cleaner_id="duplicates", description=p.name, size=8192,
                           path=str(p), report_only=True,
                           remedy=path_remedy(str(p), group=group)) for p in paths]
    other = home / "big.bin"  # eligible, so the real act does run
    other.write_bytes(b"b" * 100)
    items.append(CleanableItem(cleaner_id="big_files", description="big", size=100,
                               path=str(other), report_only=True,
                               remedy=path_remedy(str(other))))
    _patch_scan(monkeypatch, items)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)
    calls = []
    real = actions.content_matches_group

    def flaky(path, grp, **kw):
        calls.append(path)
        if len(calls) == 1:
            return "the copy to keep could not be read; nothing removed"
        return real(path, grp, **kw)

    monkeypatch.setattr(actions, "content_matches_group", flaky)
    code = cli.main(["clean", "--act-on", "duplicates,big_files", "--keep", "oldest",
                     "--execute", "--yes", "--permanent"])
    out = capsys.readouterr().out.replace("\n", " ")
    assert "could not be read" in out
    assert code == 0
    assert not other.exists()  # the confirmed item was acted on
    assert all(p.exists() for p in paths), "an item shown as skipped was acted on"
