"""Tests for the elevated helper (request file, re-scan, match, clean).

Nothing here needs real privileges and nothing is deleted outside tmp_path:
scans are served by fake cleaners and the engine's root check is patched.
History/quarantine locations are NOT patched away: HOME/XDG/APPDATA point
into tmp_path so that any write the helper made would be visible there.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from cleanix import elevated
from cleanix.core import context, elevate, engine, history, quarantine, safety, service
from cleanix.core.models import CleanableItem, CleanerReport, ItemKind, item_key

POSIX = os.name != "nt"
# Files created by the tests are owned by the test runner: on POSIX the helper
# really checks that, so the "requesting uid" must be ours.
UID = os.getuid() if POSIX else 1000
FAKE_UID = 1000  # for pure ownership checks on fake stat results


# --------------------------------------------------------------------------
# fixtures / helpers
# --------------------------------------------------------------------------
class FakeCleaner:
    def __init__(self, cid, items):
        self.id = cid
        self.name = cid
        self._items = items

    def scan(self):
        items = self._items() if callable(self._items) else self._items
        return CleanerReport(cleaner_id=self.id, name=self.name, description="d",
                             items=list(items))


def _item(path, cid="logs", *, root=True, report_only=False):
    return CleanableItem(cleaner_id=cid, description=f"item {Path(path).name}",
                         size=10, path=str(path), requires_root=root,
                         report_only=report_only)


@pytest.fixture(autouse=True)
def _restore_environ():
    """The helper rewrites os.environ (trusted PATH etc.); restore it fully."""
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolated helper environment: fake user whose home is in tmp_path, fake scan."""
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    user = context.TargetUser("alice", home, UID, UID, True)

    def fake_invoking_user():
        return user

    fake_invoking_user.cache_clear = lambda: None  # type: ignore[attr-defined]
    monkeypatch.setattr(context, "invoking_user", fake_invoking_user)
    # history/quarantine imported the function by name; bind them to the same
    # user (their state LOCATIONS stay real and resolve into the fake home)
    monkeypatch.setattr(history, "invoking_user", fake_invoking_user)
    monkeypatch.setattr(quarantine, "invoking_user", fake_invoking_user)
    monkeypatch.setattr(elevated, "_user_for_uid", lambda uid: "alice" if uid == UID else None)
    for var, sub in (("HOME", ""), ("USERPROFILE", ""),
                     ("XDG_STATE_HOME", ".local/state"), ("XDG_DATA_HOME", ".local/share"),
                     ("XDG_CONFIG_HOME", ".config"), ("XDG_CACHE_HOME", ".cache"),
                     ("LOCALAPPDATA", "AppData/Local"), ("APPDATA", "AppData/Roaming")):
        monkeypatch.setenv(var, str(home / sub) if sub else str(home))
    monkeypatch.setattr(engine, "is_root", lambda: True)
    monkeypatch.delenv("PKEXEC_UID", raising=False)
    # Fake cleaner ids the helper accepts on every platform (the real
    # allowlist is platform-dependent and tested separately).
    monkeypatch.setattr(elevated, "admin_cleaner_ids",
                        lambda: frozenset({"logs", "temp", "journal"}))
    # tmp_path lives under directories owned by the test runner, which the
    # real parent-chain policy rightly distrusts; the OWNER/GROUP part of the
    # policy is unit-tested separately, symlink and mode checks stay real.
    monkeypatch.setattr(elevated, "_trusted_owner", lambda st, uid: True)
    monkeypatch.setattr(elevated, "_untrusted_group", lambda st, groups: False)

    cleaners = []
    built = []

    def fake_build(config, only=None, exclude=None):
        built.append(list(only) if only else None)
        wanted = {c.lower() for c in only} if only else None
        return [c for c in cleaners if wanted is None or c.id.lower() in wanted]

    monkeypatch.setattr(service, "build_cleaners", fake_build)
    scans = []
    real_scan = service.scan

    def spy_scan(config, **kw):
        scans.append(config)
        return real_scan(config, **kw)

    monkeypatch.setattr(service, "scan", spy_scan)

    reqdir = tmp_path / "req"
    reqdir.mkdir()
    if POSIX:
        os.chmod(reqdir, 0o700)
    junk = tmp_path / "junk"
    junk.mkdir()
    yield SimpleNamespace(tmp=tmp_path, home=home, cleaners=cleaners,
                          reqdir=reqdir, junk=junk, built=built, scans=scans,
                          result=reqdir / elevate.RESULT_NAME)
    context.configure(None)
    safety.set_protected_globs([])


def _file(directory, name, data=b"x" * 10):
    p = Path(directory) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def _selection(keys, only=("logs",), *, user="alice", quarantine_=False, nonce=None):
    return elevate.Selection(invoking_user=user, only=list(only), keys=list(keys),
                             use_quarantine=quarantine_, nonce=nonce or uuid.uuid4().hex)


def _run(env, selection, *, config=None, **kw):
    req = elevate.write_request(env.reqdir, selection)
    rc = elevated.run(req, env.result, config, expected_uid=UID, **kw)
    return rc, req


def _uid_for_files():
    return os.getuid() if POSIX else None


# --------------------------------------------------------------------------
# request / result files
# --------------------------------------------------------------------------
def test_request_roundtrip_and_permissions(tmp_path):
    sel = _selection(["a|path|/x"], only=["a", "b"], quarantine_=True)
    path = elevate.write_request(tmp_path, sel)
    assert path == tmp_path / elevate.REQUEST_NAME
    assert elevate.read_request(path, expected_uid=_uid_for_files()) == sel
    if POSIX:
        assert (os.stat(path).st_mode & 0o777) == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership")
def test_read_request_refuses_foreign_owner(tmp_path):
    path = elevate.write_request(tmp_path, _selection([]))
    with pytest.raises(ValueError):
        elevate.read_request(path, expected_uid=os.getuid() + 1)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_read_request_refuses_world_writable(tmp_path):
    path = elevate.write_request(tmp_path, _selection([]))
    os.chmod(path, 0o666)
    with pytest.raises(ValueError):
        elevate.read_request(path, expected_uid=os.getuid())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_read_request_refuses_symlink(tmp_path):
    real = elevate.write_request(tmp_path, _selection([]))
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(ValueError):
        elevate.read_request(link, expected_uid=os.getuid())


@pytest.mark.parametrize("st, ok", [
    (SimpleNamespace(st_uid=FAKE_UID, st_mode=0o100600), True),
    (SimpleNamespace(st_uid=FAKE_UID + 1, st_mode=0o100600), False),
    (SimpleNamespace(st_uid=FAKE_UID, st_mode=0o100620), False),
    (SimpleNamespace(st_uid=FAKE_UID, st_mode=0o100602), False),
    (SimpleNamespace(st_uid=0, st_mode=0o100644), False),
])
def test_check_secure_owner_and_mode(st, ok):
    if ok:
        elevate._check_secure(st, FAKE_UID, "request")
    else:
        with pytest.raises(ValueError):
            elevate._check_secure(st, FAKE_UID, "request")


def test_check_secure_allows_root_owner_only_when_asked():
    st = SimpleNamespace(st_uid=0, st_mode=0o100644)
    elevate._check_secure(st, FAKE_UID, "config", allow_root=True)


def test_every_real_cleaner_id_is_accepted_in_requests():
    from cleanix.core.registry import ALL_CLEANERS

    bad = [c.id for c in ALL_CLEANERS if not elevate._CLEANER_ID_RE.fullmatch(c.id)]
    assert bad == []


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(use_quarantine="false"),
    lambda d: d.update(keys="a|path|/x"),
    lambda d: d.update(keys=[1]),
    lambda d: d.update(only=["../etc"]),
    lambda d: d.update(nonce="not-a-nonce"),
    lambda d: d.update(invoking_user=""),
    lambda d: d.update(invoking_user="al\x00ice"),
    lambda d: d.update(extra="field"),
    lambda d: d.update(version=99),
    lambda d: d.pop("keys"),
])
def test_read_request_rejects_malformed(tmp_path, mutate):
    path = elevate.write_request(tmp_path, _selection(["a|path|/x"]))
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        elevate.read_request(path, expected_uid=_uid_for_files())


def test_read_request_rejects_garbage_and_oversize(tmp_path):
    path = tmp_path / "request.json"
    path.write_bytes(b"\xff\xfe not json")
    with pytest.raises(ValueError):
        elevate.read_request(path, expected_uid=_uid_for_files())
    path.write_bytes(b" " * (elevate.MAX_REQUEST_BYTES + 1))
    with pytest.raises(ValueError):
        elevate.read_request(path, expected_uid=_uid_for_files())


def test_result_roundtrip(tmp_path):
    res = elevate.HelperResult(freed=5, removed=1, errors=["e"], unmatched=2,
                               nonce="ab" * 16, deadline_hit=True, refused=3)
    path = tmp_path / "result.json"
    elevate.write_result(path, res)
    assert elevate.read_result(path) == res
    if POSIX:
        assert (os.stat(path).st_mode & 0o777) == 0o644


def test_make_request_dir_is_private(tmp_path):
    d = elevate.make_request_dir()
    try:
        assert d.is_dir()
        if POSIX:
            assert (os.stat(d).st_mode & 0o777) == 0o700
    finally:
        d.rmdir()


# --------------------------------------------------------------------------
# helper behaviour
# --------------------------------------------------------------------------
def test_helper_deletes_only_matching_keys(env):
    a, b = _file(env.junk, "a.bin"), _file(env.junk, "b.bin")
    ia, ib = _item(a), _item(b)
    env.cleaners.append(FakeCleaner("logs", [ia, ib]))
    rc, _ = _run(env, _selection([item_key(ia)]))
    assert rc == 0
    assert not a.exists() and b.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 1 and res.unmatched == 0 and res.errors == []
    assert res.freed == 10


def test_helper_ignores_keys_not_in_fresh_scan(env):
    a, outside = _file(env.junk, "a.bin"), _file(env.tmp / "outside", "o.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    forged = ["logs|path|/etc/passwd", item_key(_item(outside))]
    rc, _ = _run(env, _selection(forged))
    assert rc == 0
    assert a.exists() and outside.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 0 and res.unmatched == 2


def test_tampered_request_with_extra_cleaner_and_duplicate_keys(env):
    """Review Focus 3: extra keys / cleaners not in the scan delete nothing."""
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    keys = [item_key(ia), item_key(ia), "evil|path|" + str(env.home),
            "logs|cmd|rm\x1f-rf\x1f/"]
    rc, _ = _run(env, _selection(keys, only=["logs", "evil", "nonexistent"]))
    assert rc == 0
    assert not a.exists()
    assert env.home.exists()
    res = elevate.read_result(env.result)
    # the "evil" key is refused up front (cleaner not allowlisted), the
    # forged command key is simply not in the fresh scan
    assert res.removed == 1 and res.unmatched == 1 and res.refused == 1
    assert env.built == [["logs"]]  # non-allowlisted ids are never scanned


def test_helper_never_cleans_report_only(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a, report_only=True)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    rc, _ = _run(env, _selection([item_key(ia)]))
    assert rc == 0
    assert a.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 0 and res.refused == 1


def test_helper_never_cleans_items_that_do_not_need_admin(env):
    """User-level items (e.g. from a user-writable config) are never deleted as admin."""
    a = _file(env.junk, "a.bin")
    ia = _item(a, root=False)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    rc, _ = _run(env, _selection([item_key(ia)]))
    assert rc == 0
    assert a.exists()
    assert elevate.read_result(env.result).refused == 1


def test_config_only_contributes_protected_globs(env):
    """A user-writable config must not steer root cleaners: every setting
    except protected_globs keeps its built-in default in the helper."""
    import dataclasses as dc

    from cleanix.config import Config

    victim = _file(env.tmp / "system" / "lib", "important.so")
    link_dir = env.tmp / "userdir"
    link_dir.mkdir()
    cfg = env.reqdir / "config.yaml"
    d = json.dumps(str(victim.parent))
    cfg.write_text(
        "temp_min_age_days: 0\nlog_min_age_days: 0\ncoredump_min_age_days: 0\n"
        "journal_max_size_mb: 1\nkeep_kernels: 0\nremove_old_kernels: true\n"
        "purge_unused_locales: true\ndocker_prune_volumes: true\n"
        "docker_prune_all_images: true\ndisabled_cleaners: [logs]\n"
        f"extra_cache_dirs: [{d}]\n"
        f"symlink_scan_dirs: [{json.dumps(str(link_dir))}]\nproject_scan_dirs: [{d}]\n"
        f"protected_globs: [{json.dumps(str(env.tmp / 'nothing' / '*'))}]\n",
        encoding="utf-8")
    if POSIX:
        os.chmod(cfg, 0o600)

    def from_config():
        c = env.scans[-1]
        # Worst case: a cleaner turns every configured dir into an admin item.
        dirs = list(c.extra_cache_dirs) + list(c.symlink_scan_dirs) + list(c.project_scan_dirs)
        return [CleanableItem(cleaner_id="logs", description="cfg", size=1,
                              path=p, requires_root=True) for p in dirs
                if p in (str(victim.parent), str(link_dir))]

    env.cleaners.append(FakeCleaner("logs", from_config))
    keys = ["logs|path|" + str(victim.parent), "logs|path|" + str(link_dir)]
    rc, _ = _run(env, _selection(keys), config=str(cfg))
    assert rc == 0
    loaded = env.scans[-1]
    expected = Config()
    expected.protected_globs = [str(env.tmp / "nothing" / "*")]  # the file was read
    assert dc.asdict(loaded) == dc.asdict(expected)
    assert victim.exists() and link_dir.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 0 and res.unmatched == 2


def test_config_with_bad_protected_globs_is_refused(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    cfg = env.reqdir / "config.yaml"
    cfg.write_text("protected_globs: 5\n", encoding="utf-8")
    if POSIX:
        os.chmod(cfg, 0o600)
    rc, _ = _run(env, _selection([item_key(ia)]), config=str(cfg))
    assert rc == 1
    assert a.exists() and env.scans == []


def test_protected_globs_expand_against_invoking_user_home(env, monkeypatch):
    keep = _file(env.home / "keep", "k.bin")
    cfg = env.reqdir / "config.yaml"
    cfg.write_text('protected_globs: ["~/keep/*"]\n', encoding="utf-8")
    if POSIX:
        os.chmod(cfg, 0o600)
    # As root, "~" would otherwise expand to the admin's own home.
    monkeypatch.setattr(os.path, "expanduser",
                        lambda p: p.replace("~", str(env.tmp / "roothome"), 1)
                        if p.startswith("~") else p)
    ik = _item(keep)
    env.cleaners.append(FakeCleaner("logs", [ik]))
    rc, _ = _run(env, _selection([item_key(ik)]), config=str(cfg))
    assert rc == 0
    assert keep.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 0 and res.errors


def test_helper_respects_safety_guard(env, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("safety guard bypassed")

    monkeypatch.setattr(safety, "safe_rmtree", boom)
    monkeypatch.setattr(quarantine.Quarantine, "store", boom, raising=False)
    sentinel = _file(env.home, "sentinel.txt")
    ih = _item(env.home)  # a home directory itself is always protected
    env.cleaners.append(FakeCleaner("logs", [ih]))
    rc, _ = _run(env, _selection([item_key(ih)]))
    assert rc == 0
    assert sentinel.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 0 and res.errors
    assert "safety" in res.errors[0]


def test_helper_writes_result_json_and_exit_zero(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    sel = _selection([item_key(ia)])
    rc, _ = _run(env, sel)
    assert rc == 0
    data = json.loads(env.result.read_text(encoding="utf-8"))
    assert data["removed"] == 1 and data["nonce"] == sel.nonce
    assert set(data) >= {"freed", "removed", "errors", "unmatched", "nonce", "deadline_hit"}
    if POSIX:
        assert (os.stat(env.result).st_mode & 0o777) == 0o644


def test_nonce_is_echoed(env):
    env.cleaners.append(FakeCleaner("logs", []))
    nonce = uuid.uuid4().hex
    rc, _ = _run(env, _selection([], nonce=nonce))
    assert rc == 0
    assert elevate.read_result(env.result).nonce == nonce


def test_helper_bad_request_exits_nonzero_and_deletes_nothing(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    req = env.reqdir / elevate.REQUEST_NAME
    req.write_text('{"keys": ["%s"' % item_key(ia).replace("\\", "\\\\"), encoding="utf-8")
    rc = elevated.run(req, env.result, None, expected_uid=UID)
    assert rc == 1
    assert a.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 0 and res.errors
    assert "keys" not in res.errors[0]  # never echoes file contents


def test_missing_request_exits_one(env):
    rc = elevated.run(env.reqdir / elevate.REQUEST_NAME, env.result, None, expected_uid=UID)
    assert rc == 1
    assert elevate.read_result(env.result).errors
    # a request file under another name is refused outright
    assert elevated.run(env.reqdir / "nope.json", env.result, None, expected_uid=UID) == 1


def test_result_outside_request_dir_is_refused(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    req = elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    elsewhere = env.tmp / "elsewhere" / "result.json"
    elsewhere.parent.mkdir()
    rc = elevated.run(req, elsewhere, None, expected_uid=UID)
    assert rc == 1
    assert a.exists() and not elsewhere.exists()


def test_posix_requires_uid(env, monkeypatch):
    monkeypatch.setattr(elevated, "_is_posix", lambda: True)
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    req = elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    rc = elevated.run(req, env.result, None, expected_uid=None)
    assert rc == 1
    assert a.exists()


def test_helper_scope_is_single_user(env, monkeypatch):
    calls = []
    real = context.configure

    def spy(*a, **k):
        calls.append((a, k))
        return real(*a, **k)

    monkeypatch.setattr(context, "configure", spy)
    env.cleaners.append(FakeCleaner("logs", []))
    rc, _ = _run(env, _selection([]))
    assert rc == 0
    assert calls and calls[-1] == ((), {"all_users": False})
    assert [u.name for u in context.get_target_users()] == ["alice"]


def test_invoking_user_mismatch_refused(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    rc, _ = _run(env, _selection([item_key(ia)], user="bob"))
    assert rc == 1
    assert a.exists()


def test_unknown_uid_refused_on_posix(env, monkeypatch):
    monkeypatch.setattr(elevated, "_is_posix", lambda: True)
    monkeypatch.setattr(elevated, "_user_for_uid", lambda uid: None)
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    rc, _ = _run(env, _selection([item_key(ia)]))
    assert rc == 1
    assert a.exists()


# --------------------------------------------------------------------------
# main(): argv, exit codes, pkexec uid, deadline, atomic writes
# --------------------------------------------------------------------------
def _argv(env, req, *extra):
    return ["--request", str(req), "--result", str(env.result), "--uid", str(UID), *extra]


def test_main_runs_helper(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    req = elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    assert elevated.main(_argv(env, req)) == 0
    assert not a.exists()


def test_uid_must_match_pkexec_uid(env, monkeypatch):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    req = elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    monkeypatch.setenv("PKEXEC_UID", str(UID + 1))
    assert elevated.main(_argv(env, req)) == 1
    assert a.exists()
    monkeypatch.setenv("PKEXEC_UID", "garbage")
    assert elevated.main(_argv(env, req)) == 1
    assert a.exists()
    monkeypatch.setenv("PKEXEC_UID", str(UID))
    assert elevated.main(_argv(env, req)) == 0
    assert not a.exists()


def test_deadline_stops_cleaning_and_writes_partial_result_with_exit_3(env, monkeypatch):
    files = [_file(env.junk, f"f{i}.bin") for i in range(3)]
    items = [_item(p) for p in files]
    env.cleaners.append(FakeCleaner("logs", items))
    clock = [0.0]
    monkeypatch.setattr(elevated, "_monotonic", lambda: clock[0])
    real_rmtree = safety.safe_rmtree

    def rmtree_then_time_passes(p):
        real_rmtree(p)
        clock[0] = 10_000.0

    monkeypatch.setattr(safety, "safe_rmtree", rmtree_then_time_passes)
    sel = _selection([item_key(i) for i in items])
    req = elevate.write_request(env.reqdir, sel)
    assert elevated.main(_argv(env, req, "--deadline", "100")) == 3
    assert [p.exists() for p in files] == [False, True, True]
    res = elevate.read_result(env.result)
    assert res.deadline_hit and res.removed == 1 and res.nonce == sel.nonce


def test_deadline_during_scan_cleans_nothing(env, monkeypatch):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    clock = [0.0]

    def slow_scan():
        clock[0] = 10_000.0
        return [ia]

    env.cleaners.append(FakeCleaner("logs", slow_scan))
    monkeypatch.setattr(elevated, "_monotonic", lambda: clock[0])
    req = elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    assert elevated.main(_argv(env, req, "--deadline", "100")) == 3
    assert a.exists()
    res = elevate.read_result(env.result)
    assert res.deadline_hit and res.removed == 0


def test_default_deadline_is_below_launcher_timeout():
    assert elevated.DEFAULT_DEADLINE == 3300


@pytest.mark.parametrize("case", [
    "bad_args", "help", "missing_request", "garbage_request", "pkexec_mismatch",
    "bad_deadline", "deadline_too_large", "scan_raises", "run_returns_126", "run_returns_127",
    "run_exits_127", "keyboard_interrupt",
])
def test_main_never_returns_126_or_127(env, monkeypatch, case):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    req = elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    argv = _argv(env, req)
    if case == "bad_args":
        argv = ["--bogus"]
    elif case == "help":
        argv = ["--help"]
    elif case == "missing_request":
        argv = _argv(env, env.reqdir / "nope.json")
    elif case == "garbage_request":
        req.write_bytes(b"\x00\x01")
    elif case == "pkexec_mismatch":
        monkeypatch.setenv("PKEXEC_UID", "4242")
    elif case == "bad_deadline":
        argv = _argv(env, req, "--deadline", "-5")
    elif case == "deadline_too_large":
        argv = _argv(env, req, "--deadline", "3301")
    elif case == "scan_raises":
        def boom(*a, **k):
            raise RuntimeError("secret file contents")
        monkeypatch.setattr(service, "scan", boom)
    elif case in ("run_returns_126", "run_returns_127"):
        monkeypatch.setattr(elevated, "run", lambda *a, **k: int(case[-3:]))
    elif case == "run_exits_127":
        def ex(*a, **k):
            raise SystemExit(127)
        monkeypatch.setattr(elevated, "run", ex)
    elif case == "keyboard_interrupt":
        def ki(*a, **k):
            raise KeyboardInterrupt
        monkeypatch.setattr(elevated, "run", ki)
    rc = elevated.main(argv)
    assert rc not in (126, 127)
    assert rc in (0, 1, 2, 3)
    assert a.exists()
    if case == "scan_raises":
        assert rc == 2
        res = elevate.read_result(env.result)
        assert all("secret" not in e for e in res.errors)


def test_result_written_atomically(env, monkeypatch):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    req = elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    calls = []
    real_replace = os.replace

    def recording_replace(src, dst, *args, **kwargs):
        dst_path = Path(dst) if kwargs.get("dst_dir_fd") is None else env.reqdir / dst
        src_path = Path(src) if kwargs.get("src_dir_fd") is None else env.reqdir / src
        calls.append((src_path, dst_path, dst_path.exists()))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", recording_replace)
    rc = elevated.run(req, env.result, None, expected_uid=UID)
    assert rc == 0
    results = [c for c in calls if c[1].name == elevate.RESULT_NAME]
    assert len(results) == 1
    src, dst, existed_before = results[0]
    assert dst == env.result and not existed_before
    assert src.parent == env.reqdir and src != dst
    assert env.result.exists()
    leftovers = [p.name for p in env.reqdir.iterdir()
                 if p.name not in (elevate.REQUEST_NAME, elevate.RESULT_NAME)]
    assert leftovers == []


def test_request_written_atomically(tmp_path, monkeypatch):
    calls = []
    real_replace = os.replace

    def recording_replace(src, dst, *args, **kwargs):
        calls.append(Path(dst).name)
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", recording_replace)
    elevate.write_request(tmp_path, _selection([]))
    assert calls == [elevate.REQUEST_NAME]
    assert [p.name for p in tmp_path.iterdir()] == [elevate.REQUEST_NAME]


def test_module_entry_point_exists():
    import importlib.util

    assert importlib.util.find_spec("cleanix.elevated") is not None
    assert callable(elevated.main)


# --------------------------------------------------------------------------
# C1: the helper writes nothing under the user's home (no history/quarantine)
# --------------------------------------------------------------------------
def _tree(root):
    return sorted(str(p.relative_to(root)) for p in Path(root).rglob("*"))


def test_helper_writes_nothing_under_user_home_even_with_quarantine(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    assert _tree(env.home) == []
    # the real (unpatched) state locations resolve into the fake home
    assert str(history.state_dir()).startswith(str(env.home))
    assert str(quarantine.quarantine_root()).startswith(str(env.home))
    rc, _ = _run(env, _selection([item_key(ia)], quarantine_=True))
    assert rc == 0
    assert not a.exists()  # deleted for real, not moved into a quarantine
    assert elevate.read_result(env.result).removed == 1
    assert _tree(env.home) == []
    assert not quarantine.quarantine_root().exists()
    assert not history.state_dir().exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_planted_state_symlink_is_never_followed(env):
    target = env.tmp / "victim_dir"
    target.mkdir()
    state = env.home / ".local" / "state"
    state.mkdir(parents=True)
    (state / "cleanix").symlink_to(target)
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    rc, _ = _run(env, _selection([item_key(ia)], quarantine_=True))
    assert rc == 0
    assert not a.exists()
    assert list(target.iterdir()) == []
    assert (state / "cleanix").is_symlink()


# --------------------------------------------------------------------------
# C2 / I3: allowlist and requires_root relative to the requesting user
# --------------------------------------------------------------------------
_NEVER_ADMIN = {"user_cache", "broken_symlinks", "docker", "podman", "nerdctl",
                "flatpak", "nix_gc", "homebrew", "memory", "swap", "memory_macos"}


def test_allowlist_rules_hold_for_this_platform():
    from cleanix.config import Config
    from cleanix.core import catalog, registry
    from cleanix.core import platform as plat

    ids = elevated.admin_cleaner_ids()
    assert ids and not ids & _NEVER_ADMIN
    by_id = {c.id: c for c in registry.ALL_CLEANERS}
    for cid in ids:
        cls = by_id[cid]
        inst = cls(Config())
        assert inst.supported()
        assert catalog.category_of(cid) == "system" or cid == "temp"
        assert cls.requires_root or cid in elevated.PER_ITEM_ROOT_IDS
        assert inst.default_enabled or cid in elevated.EXPLICIT_ADMIN_IDS
        assert cid.startswith("win_") == plat.is_windows()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows allowlist")
def test_allowlist_on_windows():
    ids = elevated.admin_cleaner_ids()
    assert {"win_system_temp", "win_component_store"} <= ids
    assert "temp" not in ids and "logs" not in ids


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux allowlist")
def test_allowlist_on_linux():
    ids = elevated.admin_cleaner_ids()
    assert {"temp", "logs", "journal", "crash_spool", "apt"} <= ids
    assert "win_component_store" not in ids


def test_root_item_from_non_allowlisted_cleaner_is_refused_and_never_scanned(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a, cid="user_cache", root=True)
    scanned = []
    env.cleaners.append(FakeCleaner("user_cache", lambda: scanned.append(1) or [ia]))
    rc, _ = _run(env, _selection([item_key(ia)], only=["user_cache"]))
    assert rc == 0
    assert a.exists() and scanned == []
    assert env.scans == []  # the scan phase never ran as root
    assert elevate.read_result(env.result).refused == 1


def test_non_allowlisted_item_in_scan_is_refused_even_if_flagged_root(env):
    """An allowlisted cleaner reporting a foreign cleaner id is not cleaned."""
    a = _file(env.junk, "a.bin")
    ia = _item(a, cid="user_cache", root=True)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    rc, _ = _run(env, _selection([item_key(ia)], only=["logs"]))
    assert rc == 0
    assert a.exists()


@pytest.mark.parametrize("cid, root, report_only, ok", [
    ("logs", True, False, True),
    ("temp", True, False, True),
    ("logs", False, False, False),
    ("logs", True, True, False),
    ("user_cache", True, False, False),
    ("broken_symlinks", True, False, False),
])
def test_eligibility_rule(cid, root, report_only, ok):
    item = _item("/x/y", cid=cid, root=root, report_only=report_only)
    assert elevated._eligible(item, frozenset({"logs", "temp"})) is ok


def test_user_owned_temp_entry_is_not_eligible(env):
    planted = _file(env.junk, "planted")
    it = _item(planted, cid="temp", root=False)  # owned by the requesting user
    env.cleaners.append(FakeCleaner("temp", [it]))
    rc, _ = _run(env, _selection([item_key(it)], only=["temp"]))
    assert rc == 0
    assert planted.exists()
    assert elevate.read_result(env.result).refused == 1


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX st_uid / os.getuid")
def test_temp_cleaner_requires_root_is_relative_to_bound_user(monkeypatch):
    from cleanix.cleaners import temp_files
    from cleanix.config import Config

    class FakeChild:
        def __init__(self, name, uid):
            self.name, self.uid = name, uid

        def lstat(self):
            return SimpleNamespace(st_uid=self.uid)

        def __str__(self):
            return "/tmp/" + self.name

    children = {"/tmp": [FakeChild("mine", 1234), FakeChild("theirs", 4321)]}
    monkeypatch.setattr(temp_files, "iter_children", lambda root: children.get(str(root), []))
    monkeypatch.setattr(temp_files, "older_than", lambda p, d: True)
    cleaner = temp_files.TempFilesCleaner(Config())
    monkeypatch.setattr(cleaner, "path_item", lambda p, desc, requires_root: CleanableItem(
        cleaner_id="temp", description=desc, path=str(p), requires_root=requires_root))
    user = context.TargetUser("u", Path("/home/u"), 1234, 1234, True)
    with context.use_user(user):
        items = {Path(i.path).name: i.requires_root for i in cleaner.find_items()}
    assert items == {"mine": False, "theirs": True}


# --------------------------------------------------------------------------
# I3 / I7: trusted environment
# --------------------------------------------------------------------------
def test_posix_environment_is_sanitized(monkeypatch):
    monkeypatch.setattr(elevated, "_is_posix", lambda: True)
    for k, v in {"PATH": "/evil", "PYTHONPATH": "/evil", "PYTHONHOME": "/x",
                 "PYTHONSTARTUP": "/x", "LD_PRELOAD": "/evil.so",
                 "LD_LIBRARY_PATH": "/evil", "DYLD_INSERT_LIBRARIES": "/x",
                 "BASH_ENV": "/x", "IFS": "x", "HOME": "/home/evil",
                 "XDG_CONFIG_HOME": "/x", "APT_CONFIG": "/x", "DOCKER_HOST": "x",
                 "GIT_DIR": "/x", "DPKG_ROOT": "/x", "PAGER": "x",
                 "SOMETHING_NEW": "x", "LANG": "C.UTF-8", "LC_ALL": "C"}.items():
        monkeypatch.setenv(k, v)
    elevated._sanitize_environment()
    # built from an allowlist: only locale variables survive, PATH is fixed
    keys = {k.upper() for k in os.environ}
    assert keys <= {"PATH", "LANG", "LC_ALL", "LANGUAGE", "PKEXEC_UID"} | {
        k for k in keys if k.startswith("LC_")}
    assert os.environ["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"
    assert os.environ["LANG"] == "C.UTF-8"


def test_trusted_environment_is_an_allowlist():
    src = {"PATH": "/evil", "HOME": "/h", "LANG": "C", "LC_TIME": "C", "X": "1",
           "PKEXEC_UID": "1000", "PYTHONPATH": "/e"}
    assert elevated._trusted_environment(src, True) == {
        "PATH": elevated.POSIX_PATH, "LANG": "C", "LC_TIME": "C", "PKEXEC_UID": "1000"}
    win = elevated._trusted_environment(
        {"USERNAME": "u", "USERPROFILE": r"C:\Users\u", "ComSpec": r"C:\evil.exe",
         "TEMP": r"C:\evil", "PSModulePath": r"C:\evil"}, False,
        (r"C:\Windows", r"C:\Windows\System32", r"C:\ProgramData"))
    assert win["ComSpec"] == r"C:\Windows\System32\cmd.exe"
    assert win["TEMP"] == win["TMP"] == r"C:\Windows\Temp"
    assert win["USERNAME"] == "u" and "PSModulePath" not in win


def test_windows_environment_comes_from_api(monkeypatch):
    monkeypatch.setattr(elevated, "_is_posix", lambda: False)
    monkeypatch.setattr(elevated, "_win_known_dirs",
                        lambda: (r"D:\Win", r"D:\Win\System32", r"D:\PD"))
    for k, v in {"SystemRoot": r"C:\evil", "windir": r"C:\evil",
                 "SystemDrive": "E:", "ProgramData": r"C:\evil",
                 "PATH": r"C:\evil", "PYTHONPATH": r"C:\evil"}.items():
        monkeypatch.setenv(k, v)
    elevated._sanitize_environment()
    env_ = {k.lower(): v for k, v in os.environ.items()}
    assert env_["systemroot"] == r"D:\Win" and env_["windir"] == r"D:\Win"
    assert env_["systemdrive"] == "D:" and env_["programdata"] == r"D:\PD"
    assert env_["path"].split(";")[0] == r"D:\Win\System32"
    assert "evil" not in env_["path"] and "pythonpath" not in env_
    assert env_["comspec"] == r"D:\Win\System32\cmd.exe"
    assert env_["temp"] == r"D:\Win\Temp"


def test_windows_api_failure_refuses_run(env, monkeypatch):
    monkeypatch.setattr(elevated, "_is_posix", lambda: False)

    def fail():
        raise OSError("api down")

    monkeypatch.setattr(elevated, "_win_known_dirs", fail)
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    rc, _ = _run(env, _selection([item_key(ia)]))
    assert rc == 1
    assert a.exists() and env.scans == []


@pytest.mark.skipif(sys.platform != "win32", reason="real Windows API")
def test_real_windows_known_dirs_override_tampered_env(monkeypatch):
    windir, sysdir, programdata = elevated._win_known_dirs()
    assert Path(windir).is_dir() and Path(sysdir).is_dir() and Path(programdata).is_dir()
    monkeypatch.setenv("SystemRoot", r"C:\evil")
    monkeypatch.setenv("ProgramData", r"C:\evil")
    elevated._sanitize_environment()
    assert os.environ["SystemRoot"] == windir
    assert os.environ["ProgramData"] == programdata


# --------------------------------------------------------------------------
# I4: request directory validated up front
# --------------------------------------------------------------------------
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_world_writable_request_dir_refused_before_scan(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    req = elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    os.chmod(env.reqdir, 0o777)
    try:
        rc = elevated.run(req, env.result, None, expected_uid=UID)
    finally:
        os.chmod(env.reqdir, 0o700)
    assert rc == 1
    assert a.exists() and env.scans == [] and not env.result.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_request_through_symlinked_parent_refused(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    link = env.tmp / "link"
    link.symlink_to(env.tmp)
    via = link / "req"
    rc = elevated.run(via / elevate.REQUEST_NAME, via / elevate.RESULT_NAME, None,
                      expected_uid=UID)
    assert rc == 1
    assert a.exists() and env.scans == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership")
def test_request_dir_owned_by_someone_else_refused(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    req = elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    with pytest.raises(ValueError):
        elevate.RequestDir(env.reqdir, UID + 1)
    rc = elevated.run(req, env.result, None, expected_uid=UID + 1)
    assert rc == 1 and a.exists() and env.scans == []


@pytest.mark.skipif(sys.platform != "win32", reason="Windows reparse-point check")
def test_windows_reparse_point_in_request_path_refused(env, monkeypatch):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    req = elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    monkeypatch.setattr(safety, "is_reparse_point",
                        lambda p: Path(p) == env.tmp)  # a parent is a junction
    rc = elevated.run(req, env.result, None, expected_uid=UID)
    assert rc == 1
    assert a.exists() and env.scans == []


# --------------------------------------------------------------------------
# I5: hard deadline
# --------------------------------------------------------------------------
@pytest.mark.parametrize("value", [0, -1, 3300.5, float("inf"), float("nan")])
def test_run_rejects_deadline_outside_range(env, value):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    req = elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    assert elevated.run(req, env.result, None, expected_uid=UID, deadline=value) == 1
    assert a.exists()


def test_command_timeouts_are_clamped_to_remaining_deadline(env, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(elevated, "_monotonic", lambda: clock[0])
    calls = []

    def fake_run_command(cmd, timeout=120):
        calls.append(timeout)
        return 0, "", ""

    monkeypatch.setattr(engine, "run_command", fake_run_command)
    long_ = CleanableItem(cleaner_id="logs", description="long", kind=ItemKind.COMMAND,
                          command=["true", "1"], requires_root=True, timeout=3000)
    default = CleanableItem(cleaner_id="logs", description="dflt", kind=ItemKind.COMMAND,
                            command=["true", "2"], requires_root=True)
    short = CleanableItem(cleaner_id="logs", description="short", kind=ItemKind.COMMAND,
                          command=["true", "3"], requires_root=True, timeout=10)
    env.cleaners.append(FakeCleaner("logs", [long_, default, short]))
    rc, _ = _run(env, _selection([item_key(i) for i in (long_, default, short)]),
                 deadline=60)
    assert rc == 0
    assert calls == [60, 60, 10]


def test_watchdog_writes_deadline_result_and_exits_3(env, monkeypatch):
    import threading

    a = _file(env.junk, "a.bin")
    ia = _item(a)
    release = threading.Event()

    def blocking_scan():
        release.wait(10)
        return [ia]

    env.cleaners.append(FakeCleaner("logs", blocking_scan))
    exits = []

    def fake_exit(code):
        exits.append(code)
        release.set()

    monkeypatch.setattr(os, "_exit", fake_exit)
    sel = _selection([item_key(ia)])
    rc, _ = _run(env, sel, deadline=0.2, grace=0.2)
    assert exits == [3]
    assert rc == 3
    assert a.exists()
    res = elevate.read_result(env.result)
    assert res.deadline_hit and res.nonce == sel.nonce
    assert "stopped after its deadline" in res.errors[0]


# --------------------------------------------------------------------------
# minors
# --------------------------------------------------------------------------
def test_bound_user_uid_must_match_expected_uid(env, monkeypatch):
    monkeypatch.setattr(elevated, "_is_posix", lambda: True)
    other = context.TargetUser("alice", env.home, UID + 1, UID + 1, True)
    fake = lambda: other  # noqa: E731
    fake.cache_clear = lambda: None
    monkeypatch.setattr(context, "invoking_user", fake)
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    rc, _ = _run(env, _selection([item_key(ia)]))
    assert rc == 1
    assert a.exists() and env.scans == []


def test_config_check_does_not_allow_root_owner():
    st = SimpleNamespace(st_uid=0, st_mode=0o100644)
    with pytest.raises(ValueError):
        elevate._check_secure(st, FAKE_UID, "config")


# --------------------------------------------------------------------------
# N1: planted symlinks / untrusted parent directories
# --------------------------------------------------------------------------
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks/modes")


def _stand_in_etc(env):
    etc = env.tmp / "etc"
    shadow = _file(etc, "shadow", b"secret")
    sudoers = _file(etc / "sudoers.d", "x", b"secret")
    return etc, shadow, sudoers


@posix_only
def test_crash_spool_cleaner_ignores_symlinked_base(env, monkeypatch):
    """Cleaner layer: /var/tmp/abrt planted as a symlink to /etc yields nothing."""
    from cleanix.cleaners import sys_extras
    from cleanix.config import Config

    etc, _shadow, _ = _stand_in_etc(env)
    var_tmp = env.tmp / "var_tmp"
    var_tmp.mkdir()
    (var_tmp / "abrt").symlink_to(etc)
    monkeypatch.setattr(sys_extras, "older_than", lambda p, d: True)
    cleaner = sys_extras.CrashSpoolCleaner(Config())
    monkeypatch.setattr(cleaner, "BASES", (str(var_tmp / "abrt"),))
    assert list(cleaner.find_items()) == []


@posix_only
def test_trusted_system_dir_requires_real_root_owned_dir(env):
    from cleanix.core.utils import is_trusted_system_dir

    assert is_trusted_system_dir("/")
    real = env.tmp / "real"
    real.mkdir()
    link = env.tmp / "link"
    link.symlink_to("/")
    assert not is_trusted_system_dir(link)          # a symlink, even to /
    assert is_trusted_system_dir(real) is (os.getuid() == 0)  # not root-owned


@posix_only
def test_helper_refuses_items_under_symlinked_base(env):
    """Helper layer: even if a cleaner lists a symlinked base, nothing is deleted."""
    etc, shadow, sudoers = _stand_in_etc(env)
    var_tmp = env.tmp / "var_tmp"
    var_tmp.mkdir()
    os.chmod(var_tmp, 0o1777)
    (var_tmp / "abrt").symlink_to(etc)
    items = [_item(var_tmp / "abrt" / "shadow"), _item(var_tmp / "abrt" / "sudoers.d")]
    env.cleaners.append(FakeCleaner("logs", items))
    rc, _ = _run(env, _selection([item_key(i) for i in items]))
    assert rc == 0
    assert shadow.exists() and sudoers.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 0 and res.refused == 2
    assert "symbolic link" in res.errors[0]


@posix_only
def test_helper_refuses_symlinked_intermediate_component(env):
    real = env.tmp / "real"
    victim = _file(real / "sub", "victim")
    a = env.tmp / "a"
    a.mkdir()
    (a / "link").symlink_to(real)
    it = _item(a / "link" / "sub" / "victim")
    env.cleaners.append(FakeCleaner("logs", [it]))
    rc, _ = _run(env, _selection([item_key(it)]))
    assert rc == 0 and victim.exists()
    assert elevate.read_result(env.result).refused == 1


@posix_only
def test_helper_refuses_world_writable_non_sticky_parent(env):
    d = env.tmp / "open"
    f = _file(d, "f")
    os.chmod(d, 0o777)
    it = _item(f)
    env.cleaners.append(FakeCleaner("logs", [it]))
    rc, _ = _run(env, _selection([item_key(it)]))
    assert rc == 0 and f.exists()
    assert "writable by everyone" in elevate.read_result(env.result).errors[0]


@posix_only
def test_helper_allows_sticky_world_writable_base(env):
    d = env.tmp / "sticky"
    f = _file(d, "f")
    os.chmod(d, 0o1777)
    it = _item(f)
    env.cleaners.append(FakeCleaner("logs", [it]))
    rc, _ = _run(env, _selection([item_key(it)]))
    assert rc == 0 and not f.exists()
    assert elevate.read_result(env.result).removed == 1


@posix_only
def test_recheck_catches_component_swapped_between_scan_and_clean(env, monkeypatch):
    f1 = _file(env.tmp / "d1", "f1")
    f2 = _file(env.tmp / "d2", "f2")
    items = [_item(f1), _item(f2)]
    env.cleaners.append(FakeCleaner("logs", items))
    real_rmtree = safety.safe_rmtree

    def rmtree_then_swap(p):
        real_rmtree(p)
        if Path(p).name == "f1":  # after the scan, before item 2 is cleaned
            (env.tmp / "d2").rename(env.tmp / "d2_real")
            (env.tmp / "d2").symlink_to(env.tmp / "d2_real")

    monkeypatch.setattr(safety, "safe_rmtree", rmtree_then_swap)
    rc, _ = _run(env, _selection([item_key(i) for i in items]))
    assert rc == 0
    assert not f1.exists()
    assert (env.tmp / "d2_real" / "f2").exists()
    res = elevate.read_result(env.result)
    assert res.removed == 1 and res.refused == 1


def test_windows_reparse_point_in_item_parent_chain_is_refused(env, monkeypatch):
    monkeypatch.setattr(elevated, "_is_posix", lambda: False)
    monkeypatch.setattr(elevated, "_win_known_dirs",
                        lambda: (r"C:\Windows", r"C:\Windows\System32", r"C:\ProgramData"))
    f = _file(env.junk / "sub", "f")
    real_is_reparse = safety.is_reparse_point
    monkeypatch.setattr(safety, "is_reparse_point",
                        lambda p: Path(p) == env.junk or real_is_reparse(p))
    it = _item(f)
    env.cleaners.append(FakeCleaner("logs", [it]))
    rc, _ = _run(env, _selection([item_key(it)]))
    assert rc == 0 and f.exists()
    res = elevate.read_result(env.result)
    assert res.refused == 1 and "junction" in res.errors[0]


def _st(mode, uid=0, gid=0):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid)


@pytest.mark.parametrize("st, groups, problem", [
    (_st(0o040755), set(), None),                         # root dir
    (_st(0o041777), set(), None),                         # sticky /tmp
    (_st(0o120777), set(), "symbolic link"),
    (_st(0o100644), set(), "not a directory"),
    (_st(0o040755, uid=1000), set(), "non-system user"),   # human owner
    (_st(0o040755, uid=50), set(), "non-system user"),     # == requesting uid
    (_st(0o040755, uid=104), set(), None),                 # system account
    (_st(0o040777), set(), "everyone"),                    # world, no sticky
    (_st(0o040775, gid=1000), set(), "non-system group"),
    (_st(0o040775, gid=4), set(), None),                   # e.g. root:syslog 0775
    (_st(0o040775, gid=4), {4}, "non-system group"),       # user is in that group
])
def test_component_policy(st, groups, problem):
    got = elevated._component_problem(st, 50, frozenset(groups))
    if problem is None:
        assert got is None
    else:
        assert got and problem in got


@posix_only
def test_rotated_log_walk_does_not_follow_symlinked_dirs(tmp_path):
    from cleanix.cleaners import logs

    outside = tmp_path / "outside"
    _file(outside, "secret.1")
    root = tmp_path / "log"
    _file(root / "app", "app.log.1")
    (root / "evil").symlink_to(outside)
    names = sorted(p.name for p in logs._walk_files(root))
    assert names == ["app.log.1"]


@posix_only
def test_temp_cleaner_skips_symlinked_base(env, monkeypatch):
    from cleanix.cleaners import temp_files
    from cleanix.config import Config

    etc, _shadow, _ = _stand_in_etc(env)
    link = env.tmp / "faketmp"
    link.symlink_to(etc)
    cleaner = temp_files.TempFilesCleaner(Config())
    monkeypatch.setattr(cleaner, "BASES", (str(link),))
    monkeypatch.setattr(temp_files, "older_than", lambda p, d: True)
    assert list(cleaner.find_items()) == []


# --------------------------------------------------------------------------
# N3 / N5: per-item deadline, watchdog tally, completed run never exits 3
# --------------------------------------------------------------------------
def test_each_command_timeout_uses_time_left_when_it_starts(env, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(elevated, "_monotonic", lambda: clock[0])
    calls = []

    def sleepy(cmd, timeout=120):
        calls.append(timeout)
        clock[0] += 40  # each command "takes" 40 s
        return 0, "", ""

    monkeypatch.setattr(engine, "run_command", sleepy)
    cmds = [CleanableItem(cleaner_id="logs", description=f"c{i}", kind=ItemKind.COMMAND,
                          command=["true", str(i)], requires_root=True, size=5)
            for i in range(2)]
    env.cleaners.append(FakeCleaner("logs", cmds))
    rc, _ = _run(env, _selection([item_key(c) for c in cmds]), deadline=100)
    assert rc == 0
    assert calls == [100, 60]
    res = elevate.read_result(env.result)
    assert res.removed == 2 and res.freed == 10  # totals as before


def test_watchdog_reports_work_done_so_far(env, monkeypatch):
    import threading

    done_file = _file(env.junk, "a.bin")
    release = threading.Event()

    def blocking(cmd, timeout=120):
        release.wait(10)
        return 0, "", ""

    monkeypatch.setattr(engine, "run_command", blocking)
    path_item = _item(done_file)
    cmd = CleanableItem(cleaner_id="logs", description="slow", kind=ItemKind.COMMAND,
                        command=["true"], requires_root=True)
    env.cleaners.append(FakeCleaner("logs", [path_item, cmd]))
    exits = []

    def fake_exit(code):
        exits.append(code)
        release.set()

    monkeypatch.setattr(os, "_exit", fake_exit)
    rc, _ = _run(env, _selection([item_key(path_item), item_key(cmd)]),
                 deadline=0.3, grace=0.2)
    assert exits == [3] and rc == 3
    res = elevate.read_result(env.result)
    assert res.deadline_hit and res.removed == 1 and res.freed == 10
    assert "1 of 2" in res.errors[0]


def test_completed_run_never_exits_3_when_watchdog_fires_late(tmp_path, monkeypatch):
    exits = []
    monkeypatch.setattr(os, "_exit", lambda code: exits.append(code))
    written = []
    rdir = SimpleNamespace(write_result=lambda r: written.append(r))
    session = elevated._Session(rdir)
    assert session.finish()            # main path completed
    session.abort_after_deadline()     # watchdog fires before done.set()
    assert exits == [] and len(written) == 1 and not session.aborted


def test_watchdog_exits_even_if_lock_is_stuck(monkeypatch):
    exits = []
    monkeypatch.setattr(os, "_exit", lambda code: exits.append(code))
    monkeypatch.setattr(elevated, "WATCHDOG_LOCK_TIMEOUT", 0.05)
    session = elevated._Session(SimpleNamespace(write_result=lambda r: None))
    session.lock.acquire()
    try:
        session.abort_after_deadline()
    finally:
        session.lock.release()
    assert exits == [3]


def test_run_accepts_deadline_as_string(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("logs", [ia]))
    rc, _ = _run(env, _selection([item_key(ia)]), deadline="5")
    assert rc == 0 and not a.exists()
