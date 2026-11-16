"""Tests for the elevated helper (request file, re-scan, match, clean).

Nothing here needs real privileges and nothing is deleted outside tmp_path:
scans are served by fake cleaners, the engine's root check is patched, and
history/quarantine state is redirected into tmp_path.
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


def _item(path, cid="sys", *, root=True, report_only=False):
    return CleanableItem(cleaner_id=cid, description=f"item {Path(path).name}",
                         size=10, path=str(path), requires_root=root,
                         report_only=report_only)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolated helper environment: fake user, redirected state, fake scan."""
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    user = context.TargetUser("alice", home, UID, UID, True)

    def fake_invoking_user():
        return user

    fake_invoking_user.cache_clear = lambda: None  # type: ignore[attr-defined]
    monkeypatch.setattr(context, "invoking_user", fake_invoking_user)
    monkeypatch.setattr(elevated, "_user_for_uid", lambda uid: "alice" if uid == UID else None)
    monkeypatch.setattr(history, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: tmp_path / "q")
    monkeypatch.setattr(engine, "is_root", lambda: True)
    monkeypatch.delenv("PKEXEC_UID", raising=False)
    # set-then-delete registers an undo, so a SUDO_USER the helper sets is removed
    monkeypatch.setenv("SUDO_USER", "x")
    monkeypatch.delenv("SUDO_USER")

    cleaners = []

    def fake_build(config, only=None, exclude=None):
        wanted = {c.lower() for c in only} if only else None
        return [c for c in cleaners if wanted is None or c.id.lower() in wanted]

    monkeypatch.setattr(service, "build_cleaners", fake_build)

    reqdir = tmp_path / "req"
    reqdir.mkdir()
    if POSIX:
        os.chmod(reqdir, 0o700)
    junk = tmp_path / "junk"
    junk.mkdir()
    yield SimpleNamespace(tmp=tmp_path, home=home, cleaners=cleaners,
                          reqdir=reqdir, junk=junk,
                          result=reqdir / elevate.RESULT_NAME)
    context.configure(None)
    safety.set_protected_globs([])


def _file(directory, name, data=b"x" * 10):
    p = Path(directory) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def _selection(keys, only=("sys",), *, user="alice", quarantine_=False, nonce=None):
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
    env.cleaners.append(FakeCleaner("sys", [ia, ib]))
    rc, _ = _run(env, _selection([item_key(ia)]))
    assert rc == 0
    assert not a.exists() and b.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 1 and res.unmatched == 0 and res.errors == []
    assert res.freed == 10


def test_helper_ignores_keys_not_in_fresh_scan(env):
    a, outside = _file(env.junk, "a.bin"), _file(env.tmp / "outside", "o.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("sys", [ia]))
    forged = ["sys|path|/etc/passwd", item_key(_item(outside))]
    rc, _ = _run(env, _selection(forged))
    assert rc == 0
    assert a.exists() and outside.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 0 and res.unmatched == 2


def test_tampered_request_with_extra_cleaner_and_duplicate_keys(env):
    """Review Focus 3: extra keys / cleaners not in the scan delete nothing."""
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("sys", [ia]))
    keys = [item_key(ia), item_key(ia), "evil|path|" + str(env.home),
            "sys|cmd|rm\x1f-rf\x1f/"]
    rc, _ = _run(env, _selection(keys, only=["sys", "evil", "nonexistent"]))
    assert rc == 0
    assert not a.exists()
    assert env.home.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 1 and res.unmatched == 2


def test_helper_never_cleans_report_only(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a, report_only=True)
    env.cleaners.append(FakeCleaner("sys", [ia]))
    rc, _ = _run(env, _selection([item_key(ia)]))
    assert rc == 0
    assert a.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 0 and res.refused == 1


def test_helper_never_cleans_items_that_do_not_need_admin(env):
    """User-level items (e.g. from a user-writable config) are never deleted as admin."""
    a = _file(env.junk, "a.bin")
    ia = _item(a, root=False)
    env.cleaners.append(FakeCleaner("sys", [ia]))
    rc, _ = _run(env, _selection([item_key(ia)]))
    assert rc == 0
    assert a.exists()
    assert elevate.read_result(env.result).refused == 1


def test_config_supplied_paths_are_not_deleted_as_admin(env, monkeypatch):
    """A user-writable config must not steer the admin re-scan to new places."""
    from cleanix.config import Config

    victim = _file(env.tmp / "system" / "lib", "important.so")
    link_dir = env.tmp / "userdir"
    link_dir.mkdir()
    cfg = env.reqdir / "config.yaml"
    d = json.dumps(str(victim.parent))
    cfg.write_text(
        f"temp_min_age_days: 42\nextra_cache_dirs: [{d}]\n"
        f"symlink_scan_dirs: [{json.dumps(str(link_dir))}]\nproject_scan_dirs: [{d}]\n",
        encoding="utf-8")
    if POSIX:
        os.chmod(cfg, 0o600)
    seen = {}

    def from_config():
        c = seen["cfg"]
        # Worst case: a cleaner turns every configured dir into an admin item.
        dirs = list(c.extra_cache_dirs) + list(c.symlink_scan_dirs) + list(c.project_scan_dirs)
        return [CleanableItem(cleaner_id="sys", description="cfg", size=1,
                              path=p, requires_root=True) for p in dirs
                if p in (str(victim.parent), str(link_dir))]

    real_scan = service.scan

    def spy_scan(config, **kw):
        seen["cfg"] = config
        return real_scan(config, **kw)

    monkeypatch.setattr(service, "scan", spy_scan)
    env.cleaners.append(FakeCleaner("sys", from_config))
    keys = ["sys|path|" + str(victim.parent), "sys|path|" + str(link_dir)]
    rc, _ = _run(env, _selection(keys), config=str(cfg))
    assert rc == 0
    loaded = seen["cfg"]
    assert loaded.temp_min_age_days == 42  # the config was really loaded
    defaults = Config()
    assert loaded.extra_cache_dirs == defaults.extra_cache_dirs
    assert loaded.symlink_scan_dirs == defaults.symlink_scan_dirs
    assert loaded.project_scan_dirs == defaults.project_scan_dirs
    assert victim.exists() and link_dir.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 0 and res.unmatched == 2


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
    env.cleaners.append(FakeCleaner("sys", [ik]))
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
    env.cleaners.append(FakeCleaner("sys", [ih]))
    rc, _ = _run(env, _selection([item_key(ih)]))
    assert rc == 0
    assert sentinel.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 0 and res.errors
    assert "safety" in res.errors[0]


def test_helper_writes_result_json_and_exit_zero(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("sys", [ia]))
    sel = _selection([item_key(ia)])
    rc, _ = _run(env, sel)
    assert rc == 0
    data = json.loads(env.result.read_text(encoding="utf-8"))
    assert data["removed"] == 1 and data["nonce"] == sel.nonce
    assert set(data) >= {"freed", "removed", "errors", "unmatched", "nonce", "deadline_hit"}
    if POSIX:
        assert (os.stat(env.result).st_mode & 0o777) == 0o644


def test_nonce_is_echoed(env):
    env.cleaners.append(FakeCleaner("sys", []))
    nonce = uuid.uuid4().hex
    rc, _ = _run(env, _selection([], nonce=nonce))
    assert rc == 0
    assert elevate.read_result(env.result).nonce == nonce


def test_helper_bad_request_exits_nonzero_and_deletes_nothing(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("sys", [ia]))
    req = env.reqdir / elevate.REQUEST_NAME
    req.write_text('{"keys": ["%s"' % item_key(ia).replace("\\", "\\\\"), encoding="utf-8")
    rc = elevated.run(req, env.result, None, expected_uid=UID)
    assert rc == 1
    assert a.exists()
    res = elevate.read_result(env.result)
    assert res.removed == 0 and res.errors
    assert "keys" not in res.errors[0]  # never echoes file contents


def test_missing_request_exits_one(env):
    rc = elevated.run(env.reqdir / "nope.json", env.result, None, expected_uid=UID)
    assert rc == 1


def test_result_outside_request_dir_is_refused(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("sys", [ia]))
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
    env.cleaners.append(FakeCleaner("sys", [ia]))
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
    env.cleaners.append(FakeCleaner("sys", []))
    rc, _ = _run(env, _selection([]))
    assert rc == 0
    assert calls and calls[-1] == ((), {"all_users": False})
    assert [u.name for u in context.get_target_users()] == ["alice"]


def test_invoking_user_mismatch_refused(env):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("sys", [ia]))
    rc, _ = _run(env, _selection([item_key(ia)], user="bob"))
    assert rc == 1
    assert a.exists()


def test_unknown_uid_refused_on_posix(env, monkeypatch):
    monkeypatch.setattr(elevated, "_is_posix", lambda: True)
    monkeypatch.setattr(elevated, "_user_for_uid", lambda uid: None)
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("sys", [ia]))
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
    env.cleaners.append(FakeCleaner("sys", [ia]))
    req = elevate.write_request(env.reqdir, _selection([item_key(ia)]))
    assert elevated.main(_argv(env, req)) == 0
    assert not a.exists()


def test_uid_must_match_pkexec_uid(env, monkeypatch):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("sys", [ia]))
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
    env.cleaners.append(FakeCleaner("sys", items))
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

    env.cleaners.append(FakeCleaner("sys", slow_scan))
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
    "bad_deadline", "scan_raises", "run_returns_126", "run_returns_127",
    "run_exits_127", "keyboard_interrupt",
])
def test_main_never_returns_126_or_127(env, monkeypatch, case):
    a = _file(env.junk, "a.bin")
    ia = _item(a)
    env.cleaners.append(FakeCleaner("sys", [ia]))
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
    env.cleaners.append(FakeCleaner("sys", [ia]))
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
