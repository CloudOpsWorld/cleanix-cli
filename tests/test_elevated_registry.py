"""The elevated helper's registry action: machine-wide (HKLM) registry
deletions, backed up first by the GUI as the user (ruling R6).

Everything runs against FakeRegistry: no real registry access, no real
elevation prompt (every launcher is a stub), nothing outside tmp_path.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from cleanix import elevated
from cleanix.core import (
    catalog,
    context,
    elevate,
    engine,
    history,
    quarantine,
    regpromises,
    regsnap,
    safety,
    scanmode,
    service,
    winenv,
    winregistry,
)
from cleanix.core.models import (
    CleanableItem,
    CleanerReport,
    ItemKind,
    RegTarget,
    item_key,
)
from cleanix.core.winregistry import REG_EXPAND_SZ, REG_SZ, KeyMissing

POSIX = os.name != "nt"
UID = os.getuid() if POSIX else 1000
CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
RUN = CV + r"\Run"
USER_SID = "S-1-5-21-111-222-333-1001"
OTHER_SID = "S-1-5-21-111-222-333-1002"
ADMINS_SID = "S-1-5-32-544"


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


def reg_item(reg, value="Foo", *, hive="HKLM", key=RUN, cid="win_reg_startup"):
    t = RegTarget(hive, key, value)
    fp = regsnap.fingerprint(t, regsnap.snapshot(reg, t))
    return CleanableItem(cleaner_id=cid, description=f"Startup entry: {value}", size=0,
                         kind=ItemKind.REGISTRY, requires_root=(hive == "HKLM"),
                         reg=dataclasses.replace(t, fingerprint=fp))


def _norm(p) -> str:
    return os.path.normcase(os.path.abspath(str(p)))


@pytest.fixture(autouse=True)
def _restore_environ():
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)
    assert not scanmode.is_helper_mode()


@pytest.fixture
def h(tmp_path, monkeypatch, fake_registry):
    """Helper environment: alice's profile under tmp_path, her quarantine
    root inside it, FakeRegistry with live HKLM/HKCU Run values and the
    ProfileList entry for her SID, and a DIFFERENT default quarantine root
    for the helper process (the administrator's)."""
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    qroot = home / "AppData" / "Local" / "cleanix" / "quarantine"
    admin_root = tmp_path / "adminprofile" / "AppData" / "Local" / "cleanix" / "quarantine"
    user = context.TargetUser("alice", home, UID, UID, True)

    def fake_invoking_user():
        return user

    fake_invoking_user.cache_clear = lambda: None  # type: ignore[attr-defined]
    monkeypatch.setattr(context, "invoking_user", fake_invoking_user)
    monkeypatch.setattr(history, "invoking_user", fake_invoking_user)
    monkeypatch.setattr(quarantine, "invoking_user", fake_invoking_user)
    monkeypatch.setattr(elevated, "_user_for_uid", lambda uid: "alice" if uid == UID else None)
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.setenv("LOCALAPPDATA", str(admin_root.parent.parent))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.delenv("PKEXEC_UID", raising=False)
    # The helper's own default quarantine root is the administrator's.
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: admin_root)
    monkeypatch.setattr(engine, "is_root", lambda: True)
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    monkeypatch.setattr(elevated, "_registry_supported", lambda: True)
    monkeypatch.setattr(elevated, "admin_cleaner_ids", lambda: frozenset({"logs"}))
    monkeypatch.setattr(elevated, "_trusted_owner", lambda st, uid: True)
    monkeypatch.setattr(elevated, "_untrusted_group", lambda st, groups: False)
    owners = {}
    monkeypatch.setattr(elevated, "_owner_sid",
                        lambda p: owners.get(_norm(p), USER_SID))

    reg = fake_registry
    reg.add_key("HKLM", RUN, {"Foo": (REG_SZ, r"C:\Gone\foo.exe"),
                              "Bar": (REG_SZ, r"C:\Gone\bar.exe")})
    reg.add_key("HKCU", RUN, {"Mine": (REG_SZ, r"C:\Gone\mine.exe")})
    reg.add_key("HKLM", elevated.PROFILE_LIST + "\\" + USER_SID,
                {"ProfileImagePath": (REG_EXPAND_SZ, str(home))})

    cleaners = []

    def fake_build(config, only=None, exclude=None):
        wanted = {c.lower() for c in only} if only else None
        return [c for c in cleaners if wanted is None or c.id.lower() in wanted]

    monkeypatch.setattr(service, "build_cleaners", fake_build)
    reqdir = tmp_path / "req"
    reqdir.mkdir()
    if POSIX:
        os.chmod(reqdir, 0o700)
    ns = SimpleNamespace(tmp=tmp_path, home=home, qroot=qroot, admin_root=admin_root,
                         reg=reg, cleaners=cleaners, owners=owners, reqdir=reqdir,
                         result=reqdir / elevate.RESULT_NAME)
    yield ns
    context.configure(None)
    safety.set_protected_globs([])


def startup_cleaner(h, hive="HKLM"):
    """A stand-in for win_reg_startup: one item per live value in ``hive``'s
    Run key, built from the registry AT SCAN TIME (so the fingerprint is
    what the helper sees)."""
    def scan():
        backend = winregistry.get_backend()
        out = []
        for v in backend.values(hive, RUN):
            out.append(reg_item(backend, v.name, hive=hive))
        return out

    return FakeCleaner("win_reg_startup", scan)


def gui_backup(h, items) -> str:
    """What the GUI does before launching: back the entries up AS THE USER
    into her quarantine root; returns the run id."""
    saved = quarantine.quarantine_root
    quarantine.quarantine_root = lambda: h.qroot
    try:
        run = quarantine.new_run()
        for it in items:
            run.store_registry(it, h.reg)
        return run.run_id
    finally:
        quarantine.quarantine_root = saved


def selection(h, reg_keys, run, *, only=("win_reg_startup",), root=None,
              file_keys=(), file_only=()):
    return elevate.Selection(
        invoking_user="alice", only=list(file_only), keys=list(file_keys),
        use_quarantine=False, nonce=uuid.uuid4().hex,
        registry=elevate.RegistryRequest(list(only), list(reg_keys), run,
                                         str(root if root is not None else h.qroot)))


def run_helper(h, sel, **kw):
    req = elevate.write_request(h.reqdir, sel)
    return elevated.run(req, h.result, None, expected_uid=UID, **kw)


def write_raw_request(h, mutate):
    sel = selection(h, [], "20261119-000000-1-abcd")
    req = elevate.write_request(h.reqdir, sel)
    data = json.loads(req.read_text(encoding="utf-8"))
    mutate(data)
    req.write_text(json.dumps(data), encoding="utf-8")
    return req


def present(h, value, hive="HKLM"):
    return value.casefold() in {v.name.casefold() for v in h.reg.values(hive, RUN)}


def tree(root):
    return sorted(str(p.relative_to(root)) for p in Path(root).rglob("*"))


# --------------------------------------------------------------------------
# allowlists
# --------------------------------------------------------------------------
def test_catalog_admin_registry_ids_are_the_five_hklm_capable():
    ids = catalog.admin_registry_cleaner_ids()
    assert ids == frozenset(catalog.REGISTRY_IDS)
    from cleanix.core.regsafety import containers_for

    for cid in ids:
        assert any(c.hive == "HKLM" for c in containers_for(cid))


def test_registry_ids_allowlisted_on_windows_only(monkeypatch):
    from cleanix.core import platform as plat

    monkeypatch.setattr(plat, "is_windows", lambda: True)
    assert elevated.admin_registry_cleaner_ids() == frozenset(catalog.REGISTRY_IDS)
    monkeypatch.setattr(plat, "is_windows", lambda: False)
    assert elevated.admin_registry_cleaner_ids() == frozenset()


def test_registry_ids_stay_out_of_the_file_allowlist():
    assert not set(catalog.REGISTRY_IDS) & set(elevated.admin_cleaner_ids())


# --------------------------------------------------------------------------
# protocol
# --------------------------------------------------------------------------
def test_request_roundtrip_with_registry_part(tmp_path, fake_registry):
    fake_registry.add_key("HKLM", RUN, {"Foo": (REG_SZ, "x")})
    key = item_key(reg_item(fake_registry))
    sel = elevate.Selection(invoking_user="alice", only=[], keys=[], use_quarantine=False,
                            registry=elevate.RegistryRequest(
                                ["win_reg_startup"], [key], "20261119-1-ab", r"C:\q"))
    path = elevate.write_request(tmp_path, sel)
    assert elevate.read_request(path, expected_uid=UID if POSIX else None) == sel


def test_request_without_registry_part_parses_as_before(tmp_path):
    sel = elevate.Selection(invoking_user="alice", only=["logs"], keys=["logs|path|/x"],
                            use_quarantine=False)
    path = elevate.write_request(tmp_path, sel)
    assert "registry" not in json.loads(path.read_text(encoding="utf-8"))
    assert elevate.read_request(path, expected_uid=UID if POSIX else None).registry is None


HKCU_KEY = "win_reg_startup|reg|" + json.dumps(["HKCU", RUN, "Mine", "f" * 64])
HKLM_KEY = "win_reg_startup|reg|" + json.dumps(["HKLM", RUN, "Foo", "f" * 64])


@pytest.mark.parametrize("mutate", [
    lambda d: d["registry"].update(keys=[HKCU_KEY]),                       # HKCU target
    lambda d: d["registry"].update(keys=[HKLM_KEY, HKCU_KEY]),             # mixed
    lambda d: d["registry"].update(keys=[HKLM_KEY.replace("HKLM", "HKU")]),
    lambda d: d["registry"].update(keys=["win_reg_startup|path|C:\\x"]),   # not a reg key
    lambda d: d["registry"].update(keys=["win_reg_startup|reg|[1,2]"]),
    lambda d: d["registry"].update(keys=[HKLM_KEY.replace("win_reg_startup", "win_reg_uninstall")]),
    lambda d: d["registry"].update(extra=1),                               # extra keys
    lambda d: d["registry"].pop("backup_run"),
    lambda d: d["registry"].update(backup_run="..\\other"),                # separators
    lambda d: d["registry"].update(backup_run="a/b"),
    lambda d: d["registry"].update(backup_run="a\\b"),
    lambda d: d["registry"].update(backup_run=".."),
    lambda d: d["registry"].update(backup_run="C:x"),
    lambda d: d["registry"].update(backup_run=""),
    lambda d: d["registry"].update(backup_run=5),
    lambda d: d["registry"].update(quarantine_root=""),
    lambda d: d["registry"].update(quarantine_root="C:\\q\x00"),
    lambda d: d["registry"].update(quarantine_root=["C:\\q"]),
    lambda d: d["registry"].update(only=[]),
    lambda d: d["registry"].update(only=["../x"]),
    lambda d: d.update(registry=[]),
    lambda d: d.update(registry=None),
])
def test_malformed_registry_part_is_refused(tmp_path, mutate):
    sel = elevate.Selection(invoking_user="alice", only=[], keys=[], use_quarantine=False,
                            registry=elevate.RegistryRequest(
                                ["win_reg_startup"], [HKLM_KEY], "20261119-1-ab", r"C:\q"))
    path = elevate.write_request(tmp_path, sel)
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        elevate.read_request(path, expected_uid=UID if POSIX else None)


# --------------------------------------------------------------------------
# the helper: happy path and invariants
# --------------------------------------------------------------------------
def test_helper_deletes_backed_up_hklm_entry(h):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.cleaners.append(startup_cleaner(h))
    rc = run_helper(h, selection(h, [item_key(item)], run))
    assert rc == elevated.EXIT_OK
    assert not present(h, "Foo") and present(h, "Bar") and present(h, "Mine", "HKCU")
    res = elevate.read_result(h.result)
    assert res.removed == 1 and res.unmatched == 0 and res.refused == 0 and res.errors == []


def test_helper_writes_nothing_creates_no_run_and_records_no_history(h):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.cleaners.append(startup_cleaner(h))
    before = tree(h.home)
    manifest = (h.qroot / run / "manifest.json").read_bytes()
    rc = run_helper(h, selection(h, [item_key(item)], run))
    assert rc == 0 and not present(h, "Foo")
    assert tree(h.home) == before                      # no new run, no history
    assert (h.qroot / run / "manifest.json").read_bytes() == manifest
    assert not h.admin_root.exists()                   # nothing in its own profile
    assert not history.state_dir().exists() or not any(history.state_dir().iterdir())


def test_helper_ignores_its_own_quarantine_root(h):
    """A valid backup in the HELPER's own %LOCALAPPDATA% quarantine never
    counts: only the invoking user's root (from the request) is used."""
    item = reg_item(h.reg, "Foo")
    saved = h.qroot
    h.qroot = h.admin_root
    run = gui_backup(h, [item])           # backup in the administrator's root
    h.qroot = saved
    # same run id in alice's root, with a manifest that holds nothing
    (h.qroot / run).mkdir(parents=True)
    (h.qroot / run / "manifest.json").write_text(
        json.dumps({"run_id": run, "created": 0, "items": []}), encoding="utf-8")
    h.cleaners.append(startup_cleaner(h))
    rc = run_helper(h, selection(h, [item_key(item)], run))
    assert rc == 0
    assert present(h, "Foo")
    res = elevate.read_result(h.result)
    assert res.removed == 0 and any("backup" in e for e in res.errors)


def test_quarantine_root_override_is_restored(h):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.cleaners.append(startup_cleaner(h))
    assert run_helper(h, selection(h, [item_key(item)], run)) == 0
    assert quarantine.quarantine_root() == h.admin_root


def test_backup_run_without_this_entry_refuses_delete(h):
    foo, bar = reg_item(h.reg, "Foo"), reg_item(h.reg, "Bar")
    run = gui_backup(h, [bar])            # the run holds Bar only
    h.cleaners.append(startup_cleaner(h))
    rc = run_helper(h, selection(h, [item_key(foo)], run))
    assert rc == 0
    assert present(h, "Foo")
    res = elevate.read_result(h.result)
    assert res.removed == 0 and res.errors and "backup" in res.errors[0]


def test_fingerprint_mismatch_is_unmatched(h):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.reg.set_value("HKLM", RUN, winregistry.RegValue("Foo", REG_SZ, r"C:\Gone\new.exe"))
    h.cleaners.append(startup_cleaner(h))
    rc = run_helper(h, selection(h, [item_key(item)], run))
    assert rc == 0
    assert present(h, "Foo")
    res = elevate.read_result(h.result)
    assert res.unmatched == 1 and res.removed == 0


def test_target_absent_from_helper_scan_is_unmatched(h):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    # allowlisted detector, but its scan does not produce this target
    h.cleaners.append(FakeCleaner("win_reg_startup", []))
    rc = run_helper(h, selection(h, [item_key(item)], run))
    assert rc == 0
    assert present(h, "Foo")
    assert elevate.read_result(h.result).unmatched == 1


def test_scan_item_from_wrong_detector_or_hive_is_refused(h):
    """Defence in depth after the scan: an HKCU item or an item reporting a
    non-registry cleaner id is refused even if its key was requested."""
    hkcu = reg_item(h.reg, "Mine", hive="HKCU")
    hklm = reg_item(h.reg, "Foo")
    forged = dataclasses.replace(hklm, cleaner_id="win_reg_app_paths")
    run = gui_backup(h, [hklm])
    h.cleaners.append(FakeCleaner("win_reg_startup", [forged]))
    h.cleaners.append(FakeCleaner("win_reg_app_paths", [forged]))
    rc = run_helper(h, selection(h, [item_key(forged)], run,
                                 only=("win_reg_startup", "win_reg_app_paths")))
    assert rc == 0 and present(h, "Foo")
    assert elevate.read_result(h.result).refused == 1
    assert not elevated._registry_eligible(hkcu, elevated.admin_registry_cleaner_ids())


def test_combined_file_and_registry_parts_one_run(h):
    junk = h.tmp / "junk"
    junk.mkdir()
    f = junk / "a.log"
    f.write_bytes(b"x" * 10)
    fitem = CleanableItem(cleaner_id="logs", description="a", size=10, path=str(f),
                          requires_root=True)
    h.cleaners.append(FakeCleaner("logs", [fitem]))
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.cleaners.append(startup_cleaner(h))
    rc = run_helper(h, selection(h, [item_key(item)], run,
                                 file_keys=[item_key(fitem)], file_only=["logs"]))
    assert rc == 0
    assert not f.exists() and not present(h, "Foo")
    assert elevate.read_result(h.result).removed == 2


def test_registry_key_in_file_part_is_refused(h):
    item = reg_item(h.reg, "Foo")
    h.cleaners.append(startup_cleaner(h))
    sel = elevate.Selection(invoking_user="alice", only=["win_reg_startup"],
                            keys=[item_key(item)], use_quarantine=False)
    req = elevate.write_request(h.reqdir, sel)
    assert elevated.run(req, h.result, None, expected_uid=UID) == 0
    assert present(h, "Foo")
    assert elevate.read_result(h.result).refused == 1


# --------------------------------------------------------------------------
# the helper: refusals (exit 1, nothing deleted)
# --------------------------------------------------------------------------
def assert_refused(h, rc, *, file=None):
    assert rc == elevated.EXIT_REFUSED
    assert present(h, "Foo") and present(h, "Bar") and present(h, "Mine", "HKCU")
    if file is not None:
        assert file.exists()
    res = elevate.read_result(h.result)
    assert res.removed == 0 and res.errors and res.errors[0].startswith("request refused")


@pytest.mark.parametrize("mutate", [
    lambda d: d["registry"].update(keys=[HKCU_KEY]),
    lambda d: d["registry"].update(extra="x"),
    lambda d: d["registry"].update(backup_run="..\\..\\x"),
    lambda d: d["registry"].update(backup_run="a/b"),
])
def test_forged_registry_request_refused_before_anything_is_deleted(h, mutate):
    junk = h.tmp / "junk"
    junk.mkdir()
    f = junk / "a.log"
    f.write_bytes(b"x")
    h.cleaners.append(FakeCleaner("logs", [CleanableItem(
        cleaner_id="logs", description="a", size=1, path=str(f), requires_root=True)]))
    h.cleaners.append(startup_cleaner(h))
    req = write_raw_request(h, mutate)
    assert_refused(h, elevated.run(req, h.result, None, expected_uid=UID))


def test_non_registry_detector_id_in_registry_part_refused(h):
    h.cleaners.append(FakeCleaner("logs", []))
    key = "logs|reg|" + json.dumps(["HKLM", RUN, "Foo", "f" * 64])
    assert_refused(h, run_helper(h, selection(h, [key], "20261119-1-ab", only=("logs",))))


def test_registry_part_refused_when_not_elevated(h, monkeypatch):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.cleaners.append(startup_cleaner(h))
    monkeypatch.setattr(winenv, "is_admin", lambda: False)
    assert_refused(h, run_helper(h, selection(h, [item_key(item)], run)))


def test_registry_part_refused_off_windows(h, monkeypatch):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    monkeypatch.setattr(elevated, "_registry_supported", lambda: False)
    assert_refused(h, run_helper(h, selection(h, [item_key(item)], run)))


def test_run_of_another_account_refused(h):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.owners[_norm(h.qroot / run)] = OTHER_SID
    h.cleaners.append(startup_cleaner(h))
    assert_refused(h, run_helper(h, selection(h, [item_key(item)], run)))


def test_manifest_of_another_account_refused(h):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.owners[_norm(h.qroot / run / "manifest.json")] = ADMINS_SID
    h.cleaners.append(startup_cleaner(h))
    assert_refused(h, run_helper(h, selection(h, [item_key(item)], run)))


def test_quarantine_root_of_another_account_refused(h):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.owners[_norm(h.qroot)] = OTHER_SID
    h.cleaners.append(startup_cleaner(h))
    assert_refused(h, run_helper(h, selection(h, [item_key(item)], run)))


@pytest.mark.parametrize("owner", [None, ADMINS_SID, "S-1-5-18", "garbage"])
def test_request_dir_not_owned_by_a_user_account_refused(h, owner):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.owners[_norm(h.reqdir)] = owner
    h.cleaners.append(startup_cleaner(h))
    assert_refused(h, run_helper(h, selection(h, [item_key(item)], run)))


def test_request_file_owned_by_another_account_refused(h):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.owners[_norm(h.reqdir / elevate.REQUEST_NAME)] = OTHER_SID
    h.cleaners.append(startup_cleaner(h))
    assert_refused(h, run_helper(h, selection(h, [item_key(item)], run)))


def test_quarantine_root_of_the_other_account_profile_refused(h):
    """The run exists, owned by alice, but the root is not under the profile
    that ProfileList gives for the request directory's owner."""
    item = reg_item(h.reg, "Foo")
    elsewhere = h.tmp / "elsewhere" / "cleanix" / "quarantine"
    saved = h.qroot
    h.qroot = elsewhere
    run = gui_backup(h, [item])
    h.qroot = saved
    h.cleaners.append(startup_cleaner(h))
    assert_refused(h, run_helper(h, selection(h, [item_key(item)], run, root=elsewhere)))


@pytest.mark.parametrize("make_root", [
    lambda h: h.home / "AppData" / "Local" / "cleanix",                     # wrong tail
    lambda h: h.home / "AppData" / "Local" / "x" / "quarantine",
    lambda h: h.home,                                                      # the profile
    lambda h: str(h.qroot) + os.sep + ".." + os.sep + "quarantine",        # not normal
    lambda h: "cleanix" + os.sep + "quarantine",                           # relative
])
def test_bad_quarantine_root_refused(h, make_root):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    root = make_root(h)
    (Path(str(root)) / run).mkdir(parents=True, exist_ok=True) if os.path.isabs(str(root)) else None
    h.cleaners.append(startup_cleaner(h))
    assert_refused(h, run_helper(h, selection(h, [item_key(item)], run, root=root)))


def test_missing_profile_list_entry_refused(h):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.reg.add_key("HKLM", elevated.PROFILE_LIST + "\\" + OTHER_SID,
                  {"ProfileImagePath": (REG_SZ, str(h.home))})
    h.owners[_norm(h.reqdir)] = "S-1-5-21-9-9-9-9"
    h.owners[_norm(h.reqdir / elevate.REQUEST_NAME)] = "S-1-5-21-9-9-9-9"
    h.cleaners.append(startup_cleaner(h))
    assert_refused(h, run_helper(h, selection(h, [item_key(item)], run)))


def test_reparse_point_on_quarantine_root_chain_refused(h, monkeypatch):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.cleaners.append(startup_cleaner(h))
    real = os.lstat
    local = _norm(h.home / "AppData" / "Local")

    def lstat(p, *a, **k):
        st = real(p, *a, **k)
        if _norm(p) == local:
            return SimpleNamespace(st_mode=st.st_mode, st_file_attributes=0x400,
                                   st_uid=getattr(st, "st_uid", 0))
        return st

    monkeypatch.setattr(elevated, "_lstat", lstat)
    assert_refused(h, run_helper(h, selection(h, [item_key(item)], run)))


def test_run_dir_is_a_link_refused(h, monkeypatch):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.cleaners.append(startup_cleaner(h))
    real = os.lstat
    target = _norm(h.qroot / run)

    def lstat(p, *a, **k):
        st = real(p, *a, **k)
        if _norm(p) == target:
            return SimpleNamespace(st_mode=st.st_mode, st_file_attributes=0x400,
                                   st_uid=getattr(st, "st_uid", 0))
        return st

    monkeypatch.setattr(elevated, "_lstat", lstat)
    assert_refused(h, run_helper(h, selection(h, [item_key(item)], run)))


# --------------------------------------------------------------------------
# HKCU is never read (R15)
# --------------------------------------------------------------------------
def test_machine_only_backend_never_forwards_hkcu(fake_registry):
    fake_registry.add_key("HKCU", RUN, {"Mine": (REG_SZ, "x")})
    fake_registry.add_key("HKLM", RUN, {"Foo": (REG_SZ, "x")})
    guard = elevated._MachineOnlyBackend(fake_registry)
    assert guard.key_exists("HKCU", RUN) is False
    for call in (lambda: guard.subkeys("HKCU", "SOFTWARE"), lambda: guard.values("HKCU", RUN),
                 lambda: guard.is_link("HKCU", RUN)):
        with pytest.raises(KeyMissing):
            call()
    assert guard.can_delete("HKCU", RUN, "Mine") is False
    for call in (lambda: guard.delete_value("HKCU", RUN, "Mine"),
                 lambda: guard.delete_key("HKCU", RUN),
                 lambda: guard.create_key("HKLM", RUN + r"\x"),
                 lambda: guard.set_value("HKLM", RUN, winregistry.RegValue("a", REG_SZ, "b"))):
        with pytest.raises(winregistry.AccessDenied):
            call()
    assert not [c for c in fake_registry.calls if "HKCU" in c]
    assert [v.name for v in guard.values("HKLM", RUN)] == ["Foo"]


def test_helper_mode_scan_reads_no_hkcu_key(h):
    """A detector run by the helper reads HKCU (as every real detector's
    container list does): the helper's backend makes HKCU look absent and
    never forwards a single HKCU call; HKLM findings are kept."""
    seen = {}

    def scan():
        backend = winregistry.get_backend()
        seen["helper_mode"] = scanmode.is_helper_mode()
        out = []
        for hive in ("HKCU", "HKLM"):
            try:
                for v in backend.values(hive, RUN):
                    out.append(reg_item(backend, v.name, hive=hive))
            except winregistry.RegistryError:
                seen[hive] = "missing"
        return out

    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.cleaners.append(FakeCleaner("win_reg_startup", scan))
    h.reg.calls.clear()
    assert run_helper(h, selection(h, [item_key(item)], run)) == 0
    assert not [c for c in h.reg.calls if "HKCU" in c]
    assert not present(h, "Foo") and present(h, "Mine", "HKCU")
    assert seen == {"helper_mode": True, "HKCU": "missing"}


@pytest.fixture
def real_detectors(h, monkeypatch):
    """The real win_reg_startup detector through the real service.scan and
    Engine (parallel) path, with an evidence context whose prober says every
    target is MISSING."""
    from _fakereg import FakeProber
    from cleanix.cleaners import winreg_base
    from cleanix.core import registry
    from cleanix.core.regtargets import DetectorContext, Existence

    monkeypatch.setattr(service, "build_cleaners", registry.build_cleaners)
    contexts = []
    env = {"SystemRoot": r"C:\Windows", "ProgramFiles": r"C:\Program Files"}

    def fake_default_context():
        return DetectorContext(env, FakeProber({}, Existence.MISSING), r"C:\Users",
                               r"C:\Windows")

    monkeypatch.setattr(winreg_base, "default_context", fake_default_context)
    from cleanix.cleaners.winreg_startup import WinRegStartup

    real_entries = WinRegStartup.entries

    def spy_entries(self, container, backend, ctx):
        contexts.append((container.hive, ctx.owner_matches))
        return real_entries(self, container, backend, ctx)

    monkeypatch.setattr(WinRegStartup, "entries", spy_entries)
    return contexts


@pytest.mark.skipif(sys.platform != "win32", reason="real registry detectors are Windows-only")
def test_real_detector_helper_scan_reads_no_hkcu(h, real_detectors):
    from cleanix.core import registry
    from cleanix.config import Config

    det = [c for c in registry.build_cleaners(Config(), only=["win_reg_startup"])][0]
    user_items = det.scan().items                  # the GUI's own scan (reads HKCU)
    foo = [i for i in user_items if i.reg.value == "Foo"][0]
    run = gui_backup(h, [foo])
    h.reg.calls.clear()
    real_detectors.clear()
    assert run_helper(h, selection(h, [item_key(foo)], run)) == 0
    assert not [c for c in h.reg.calls if "HKCU" in c]
    assert real_detectors  # the real detector ran
    assert not present(h, "Foo") and present(h, "Mine", "HKCU")
    assert elevate.read_result(h.result).removed == 1


@pytest.mark.skipif(sys.platform != "win32", reason="real registry detectors are Windows-only")
def test_real_detector_helper_scan_uses_owner_matches_false(h, real_detectors, monkeypatch):
    """Through the helper's real path (service.scan -> parallel Engine), the
    detector context says the scanning process is not the hive owner."""
    from cleanix.cleaners import winreg_base

    if not hasattr(winreg_base, "scanmode"):
        pytest.skip("owner_matches centralisation (RegistryDetector.context reading "
                    "scanmode.is_helper_mode) is not merged in this branch")
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    # No process-wide switch here (conftest disables it): the helper's own
    # scanmode.helper_mode() around its scan must reach the engine threads.
    assert run_helper(h, selection(h, [item_key(item)], run)) == 0
    assert real_detectors and all(om is False for _hive, om in real_detectors)
    assert all(hive == "HKLM" for hive, _om in real_detectors)


def test_main_enables_process_helper_mode_before_running(monkeypatch):
    order = []
    monkeypatch.setattr(scanmode, "enable_process_helper_mode", lambda: order.append("mode"))
    monkeypatch.setattr(elevated, "_main", lambda argv: order.append("run") or 0)
    assert elevated.main([]) == 0
    assert order == ["mode", "run"]


# --------------------------------------------------------------------------
# deadline / exit codes
# --------------------------------------------------------------------------
def test_deadline_during_registry_scan_deletes_nothing_exit_3(h, monkeypatch):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    clock = [0.0]

    def slow():
        clock[0] = 10_000.0
        return [reg_item(winregistry.get_backend(), "Foo")]

    h.cleaners.append(FakeCleaner("win_reg_startup", slow))
    monkeypatch.setattr(elevated, "_monotonic", lambda: clock[0])
    rc = run_helper(h, selection(h, [item_key(item)], run), deadline=100)
    assert rc == elevated.EXIT_DEADLINE
    assert present(h, "Foo")
    res = elevate.read_result(h.result)
    assert res.deadline_hit and res.removed == 0


def test_internal_error_in_registry_part_exits_2(h, monkeypatch):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.cleaners.append(startup_cleaner(h))

    def boom(*a, **k):
        raise RuntimeError("secret")

    monkeypatch.setattr(elevated, "_registry_eligible", boom)
    assert run_helper(h, selection(h, [item_key(item)], run)) == elevated.EXIT_INTERNAL
    assert present(h, "Foo")
    assert all("secret" not in e for e in elevate.read_result(h.result).errors)


def test_registry_result_echoes_nonce(h):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.cleaners.append(startup_cleaner(h))
    sel = selection(h, [item_key(item)], run)
    assert run_helper(h, sel) == 0
    assert elevate.read_result(h.result).nonce == sel.nonce


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_world_writable_request_dir_refused_for_registry(h):
    item = reg_item(h.reg, "Foo")
    run = gui_backup(h, [item])
    h.cleaners.append(startup_cleaner(h))
    os.chmod(h.reqdir, 0o777)
    rc = run_helper(h, selection(h, [item_key(item)], run))
    assert rc == 1 and present(h, "Foo") and not h.result.exists()


# --------------------------------------------------------------------------
# static eligibility parity (what the GUI offers == what the helper cleans)
# --------------------------------------------------------------------------
def _variants(cid, reg):
    hklm = reg_item(reg, "Foo")
    hkcu = reg_item(reg, "Mine", hive="HKCU")
    return [
        dataclasses.replace(hklm, cleaner_id=cid),
        dataclasses.replace(hkcu, cleaner_id=cid),
        dataclasses.replace(hklm, cleaner_id=cid, report_only=True),
        CleanableItem(cleaner_id=cid, description="c", size=1, kind=ItemKind.COMMAND,
                      command=["tool"], requires_root=True),
        dataclasses.replace(hklm, cleaner_id=cid, reg=dataclasses.replace(
            hklm.reg, key=r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Run")),
    ]


@pytest.mark.parametrize("windows", [True, False])
def test_static_problem_parity_registry(fake_registry, monkeypatch, windows):
    from cleanix.core import registry

    monkeypatch.setattr(elevated, "_registry_supported", lambda: windows)
    fake_registry.add_key("HKLM", RUN, {"Foo": (REG_SZ, "x")})
    fake_registry.add_key("HKCU", RUN, {"Mine": (REG_SZ, "x")})
    allowed = frozenset({"logs"})
    offered = set()
    for cid in sorted({c.id for c in registry.ALL_CLEANERS}) + ["not_a_cleaner"]:
        for item in _variants(cid, fake_registry):
            static_ok = elevated.static_admin_problem(item, allowed) is None
            assert static_ok == elevated._eligible(item, allowed), (cid, item)
            if static_ok and item.kind is ItemKind.REGISTRY:
                offered.add(cid)
    if windows:
        # Only the startup id has a container for RUN: the HKLM variant of
        # every other registry id is outside its detector's containers.
        assert offered == {"win_reg_startup"}
    else:
        assert offered == set()


def test_static_problem_registry_reasons(fake_registry, monkeypatch):
    monkeypatch.setattr(elevated, "_registry_supported", lambda: True)
    fake_registry.add_key("HKLM", RUN, {"Foo": (REG_SZ, "x")})
    fake_registry.add_key("HKCU", RUN, {"Mine": (REG_SZ, "x")})
    hklm = reg_item(fake_registry, "Foo")
    hkcu_root = dataclasses.replace(reg_item(fake_registry, "Mine", hive="HKCU"),
                                    requires_root=True)
    assert elevated.static_admin_problem(hklm, frozenset()) is None
    assert "HKLM" in elevated.static_admin_problem(hkcu_root, frozenset())
    assert not elevated._eligible(hkcu_root, frozenset())
    blocked = dataclasses.replace(hklm, reg=dataclasses.replace(
        hklm.reg, key=r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Run"))
    assert "safety rules" in elevated.static_admin_problem(blocked, frozenset())
    other = dataclasses.replace(hklm, cleaner_id="logs")
    assert "fixed list" in elevated.static_admin_problem(other, frozenset({"logs"}))
    assert not elevated._eligible(other, frozenset({"logs"}))


def test_admin_problems_registry_items_ignore_the_file_allowlist(fake_registry, monkeypatch):
    from cleanix.gui import elevation

    monkeypatch.setattr(elevated, "_registry_supported", lambda: True)
    monkeypatch.setattr(elevation, "admin_allowlist", lambda: frozenset({"logs"}))
    fake_registry.add_key("HKLM", RUN, {"Foo": (REG_SZ, "x")})
    ok = reg_item(fake_registry, "Foo")
    bad = dataclasses.replace(ok, reg=dataclasses.replace(
        ok.reg, key=r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Run"))
    problems = elevation.admin_problems([ok, bad])
    assert id(ok) not in problems and id(bad) in problems


# --------------------------------------------------------------------------
# GUI side (no Qt): backup before launch, one launch, purge on decline
# --------------------------------------------------------------------------
@pytest.fixture
def gui(h, monkeypatch):
    """The GUI's quarantine root is alice's; the helper (launcher stub) is
    run in-process with the administrator's default root."""
    from cleanix.gui import elevation

    monkeypatch.setattr(quarantine, "quarantine_root", lambda: h.qroot)
    monkeypatch.setattr(elevation, "_invoking_user_name", lambda: "alice")
    calls = []

    def helper_launcher(argv):
        req = Path(argv[argv.index("--request") + 1])
        res = Path(argv[argv.index("--result") + 1])
        sel = elevate.read_request(req, expected_uid=UID if POSIX else None)
        run = sel.registry.backup_run if sel.registry else None
        calls.append(SimpleNamespace(
            sel=sel, backup_exists=bool(run) and (h.qroot / run / "manifest.json").is_file()))
        saved = quarantine.quarantine_root
        quarantine.quarantine_root = lambda: h.admin_root
        try:
            if POSIX:
                os.chmod(req.parent, 0o700)
            rc = elevated.run(req, res, None, expected_uid=UID)
        finally:
            quarantine.quarantine_root = saved
        if rc != 0:
            from cleanix.core import elevate_launch

            errors = elevate.read_result(res).errors if res.exists() else []
            raise elevate_launch.ElevationFailed(f"helper failed {errors}", exit_code=rc)
        return 0

    return SimpleNamespace(calls=calls, launcher=helper_launcher)


def test_gui_writes_backup_before_launch_and_helper_deletes(h, gui):
    from cleanix.gui import elevation

    h.cleaners.append(startup_cleaner(h))
    item = reg_item(h.reg, "Foo")
    out = elevation.run_elevated_part([item], launcher=gui.launcher)
    assert out.status == elevation.DONE, (out.message, out.detail)
    (call,) = gui.calls
    assert call.backup_exists
    reg = call.sel.registry
    assert reg.only == ["win_reg_startup"] and reg.keys == [item_key(item)]
    assert reg.backup_run == out.registry_backup_run
    assert os.path.normcase(reg.quarantine_root) == os.path.normcase(str(h.qroot))
    assert call.sel.keys == [] and call.sel.only == []
    assert not present(h, "Foo") and out.result.removed == 1
    # the run is kept (restorable from an Administrator terminal)
    assert (h.qroot / out.registry_backup_run / "manifest.json").is_file()


def test_gui_combined_file_and_registry_launches_once(h, gui):
    from cleanix.gui import elevation

    junk = h.tmp / "junk"
    junk.mkdir()
    f = junk / "a.log"
    f.write_bytes(b"x" * 10)
    fitem = CleanableItem(cleaner_id="logs", description="a", size=10, path=str(f),
                          requires_root=True)
    h.cleaners.append(FakeCleaner("logs", [fitem]))
    h.cleaners.append(startup_cleaner(h))
    item = reg_item(h.reg, "Foo")
    out = elevation.run_elevated_part([fitem, item], launcher=gui.launcher)
    assert out.status == elevation.DONE
    assert len(gui.calls) == 1
    assert gui.calls[0].sel.keys == [item_key(fitem)]
    assert not f.exists() and not present(h, "Foo")
    assert out.result.removed == 2


def test_backup_failure_drops_item_from_request(h, gui, monkeypatch):
    from cleanix.gui import elevation

    h.cleaners.append(startup_cleaner(h))
    foo, bar = reg_item(h.reg, "Foo"), reg_item(h.reg, "Bar")
    real = quarantine.Quarantine.store_registry

    def store(self, item, backend):
        if item.reg.value == "Bar":
            raise OSError("disk full")
        return real(self, item, backend)

    monkeypatch.setattr(quarantine.Quarantine, "store_registry", store)
    out = elevation.run_elevated_part([foo, bar], launcher=gui.launcher)
    assert out.status == elevation.DONE
    assert out.registry_backup_failed == 1
    assert gui.calls[0].sel.registry.keys == [item_key(foo)]
    assert not present(h, "Foo") and present(h, "Bar")


def test_all_backups_failed_nothing_launched(h, gui, monkeypatch):
    from cleanix.gui import elevation

    def store(self, item, backend):
        raise OSError("disk full")

    monkeypatch.setattr(quarantine.Quarantine, "store_registry", store)
    out = elevation.run_elevated_part([reg_item(h.reg, "Foo")], launcher=gui.launcher)
    assert out.status == elevation.FAILED
    assert out.message == "Registry backup failed; nothing was removed."
    assert gui.calls == [] and present(h, "Foo")
    assert not h.qroot.exists() or quarantine.list_runs() == []


@pytest.mark.parametrize("exc_name, status", [
    ("ElevationDeclined", "declined"), ("ElevationUnavailable", "unavailable")])
def test_declined_or_unavailable_purges_backup_run(h, gui, exc_name, status):
    from cleanix.core import elevate_launch
    from cleanix.gui import elevation

    seen = []

    def launcher(argv):
        req = Path(argv[argv.index("--request") + 1])
        seen.append(elevate.read_request(req, expected_uid=UID if POSIX else None))
        raise getattr(elevate_launch, exc_name)("no")

    out = elevation.run_elevated_part([reg_item(h.reg, "Foo")], launcher=launcher)
    assert out.status == status
    assert seen and (h.qroot / seen[0].registry.backup_run).exists() is False
    assert quarantine.list_runs() == []
    assert out.registry_backup_run is None
    assert present(h, "Foo")


def test_cancel_before_launch_purges_backup_run(h, gui):
    from cleanix.gui import elevation

    out = elevation.run_elevated_part([reg_item(h.reg, "Foo")], launcher=gui.launcher,
                                      cancel=lambda: True)
    assert out is None and gui.calls == []
    assert quarantine.list_runs() == []


def test_launch_failure_keeps_backup_run(h, gui):
    from cleanix.core import elevate_launch
    from cleanix.gui import elevation

    def launcher(argv):
        raise elevate_launch.ElevationFailed("boom", exit_code=2)

    out = elevation.run_elevated_part([reg_item(h.reg, "Foo")], launcher=launcher)
    assert out.status == elevation.FAILED
    assert out.registry_backup_run and len(quarantine.list_runs()) == 1


def test_build_selection_never_puts_registry_items_in_the_file_part(fake_registry):
    from cleanix.gui import elevation

    fake_registry.add_key("HKLM", RUN, {"Foo": (REG_SZ, "x")})
    item = reg_item(fake_registry)
    sel = elevation.build_selection([item])
    assert sel.keys == [] and sel.only == [] and sel.registry is None


# --------------------------------------------------------------------------
# wording
# --------------------------------------------------------------------------
def _summary(outcome, selected=1, **kw):
    from cleanix.gui import elevation

    return SimpleNamespace(admin=outcome, admin_selected=selected, late_cancel=False,
                           admin_preview_count=0, admin_preview_size=0,
                           admin_preview_registry=0, **kw)


def test_outcome_lines_registry_wording_when_undo_shipped(monkeypatch, tmp_path):
    from cleanix.gui import elevation

    monkeypatch.setattr(regpromises, "UNDO_SHIPPED", True)
    run_dir = tmp_path / "q" / "20261119-1-ab"
    out = elevation.ElevatedOutcome(
        elevation.DONE, "ok", elevate.HelperResult(freed=0, removed=1, errors=[], unmatched=0),
        registry_backup_run="20261119-1-ab", registry_backup_dir=str(run_dir),
        registry_selected=1)
    text = "\n".join(elevation.admin_outcome_lines(_summary(out)))
    assert "20261119-1-ab" in text and str(run_dir) in text and "reg import" in text
    assert "Administrator terminal" in text
    assert "Administrator files and commands are removed permanently" in text
    assert "Administrator items are removed permanently" not in text


def test_outcome_lines_registry_wording_before_undo_ships(monkeypatch, tmp_path):
    from cleanix.gui import elevation

    monkeypatch.setattr(regpromises, "UNDO_SHIPPED", False)
    out = elevation.ElevatedOutcome(
        elevation.DONE, "ok", elevate.HelperResult(freed=0, removed=1, errors=[], unmatched=0),
        registry_backup_run="20261119-1-ab", registry_backup_dir=str(tmp_path),
        registry_selected=1, registry_backup_failed=2)
    text = "\n".join(elevation.admin_outcome_lines(_summary(out)))
    assert "reg import" not in text and "backed up to quarantine run" not in text
    assert "cannot be undone" in text
    assert "2 registry entries could not be backed up" in text


def test_dry_run_preview_registry_wording(monkeypatch):
    from cleanix.gui import elevation

    monkeypatch.setattr(regpromises, "UNDO_SHIPPED", True)
    line = elevation.admin_preview_line(3, 100, registry=2)
    assert "files and commands cannot be undone" in line
    assert "2 registry entries are backed up first" in line
    assert "1 registry entry is backed up first" in elevation.admin_preview_line(1, 0, registry=1)
    monkeypatch.setattr(regpromises, "UNDO_SHIPPED", False)
    assert "backed up" not in elevation.admin_preview_line(3, 100, registry=2)
    assert elevation.admin_preview_line(3, 100) == elevation.admin_preview_line(3, 100, registry=0)
    summary = SimpleNamespace(admin_preview_count=3, admin_preview_size=100,
                              admin_preview_registry=2)
    monkeypatch.setattr(regpromises, "UNDO_SHIPPED", True)
    assert "registry entries are backed up first" in elevation.admin_outcome_lines(summary)[0]


def test_dry_run_worker_counts_registry_previews(fake_registry, monkeypatch):
    pytest.importorskip("PySide6")
    from cleanix.config import Config
    from cleanix.gui import workers

    fake_registry.add_key("HKLM", RUN, {"Foo": (REG_SZ, "x")})
    item = reg_item(fake_registry)
    from cleanix.gui import elevation

    called = []
    monkeypatch.setattr(elevation, "run_elevated_part", lambda *a, **k: called.append(1))
    w = workers.ElevatedCleanWorker([item], Config(), dry_run=True, use_quarantine=False,
                                    launcher=lambda argv: called.append(argv))
    got = []
    w.finished.connect(got.append)
    w.run()
    (summary,) = got
    assert summary.admin_preview_count == 1 and summary.admin_preview_registry == 1
    assert called == []
