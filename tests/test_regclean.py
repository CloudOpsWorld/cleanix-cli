"""Task 11: backed-up registry deletion, undo through quarantine.

Every test uses the in-memory FakeRegistry (or WinRegBackend over the fake
``winreg`` module from test_winreg_backend); the real registry is never
touched (the autouse ForbiddenBackend fixture enforces that).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from cleanix.config import Config
from cleanix.core import (
    history,
    quarantine,
    regclean,
    regsnap,
    safety,
    service,
    winenv,
    winregistry,
)
from cleanix.core.engine import Engine
from cleanix.core.models import CleanableItem, ItemKind, RegTarget
from cleanix.core.winregistry import (
    REG_DWORD,
    REG_SZ,
    AccessDenied,
    RegistryError,
)

CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
UNINST = CV + r"\Uninstall"
FOO = UNINST + r"\Foo"
RUN = CV + r"\Run"


# -- fixtures and helpers ------------------------------------------------------
@pytest.fixture(autouse=True)
def _reset_globs():
    yield
    safety.set_protected_globs([])


@pytest.fixture
def state(tmp_path, monkeypatch):
    """Quarantine and history under tmp_path; not elevated unless a test says so."""
    monkeypatch.setattr(history, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: tmp_path / "q")
    monkeypatch.setattr(winenv, "is_admin", lambda: False)
    return tmp_path


def _foo_tree(reg, hive="HKCU", key=FOO):
    reg.add_key(hive, key, {
        "DisplayName": (REG_SZ, "Foo App"),
        "InstallLocation": (REG_SZ, r"C:\Gone\Foo"),
        "EstimatedSize": (REG_DWORD, 42),
    })
    reg.add_key(hive, key + r"\Sub", {"A": (REG_SZ, "x")})
    reg.add_key(hive, key + r"\Sub\Deeper", {"B": (REG_DWORD, 1)})


def _item(reg, cid="win_reg_uninstall", hive="HKCU", key=FOO, value=None):
    t = RegTarget(hive, key, value)
    snap = regsnap.snapshot(reg, t)
    fp = regsnap.fingerprint(t, snap)
    return CleanableItem(
        cleaner_id=cid, description="dead entry", kind=ItemKind.REGISTRY,
        reg=RegTarget(hive, key, value, fp), requires_root=(hive == "HKLM"),
    )


def _writes(reg):
    return [c for c in reg.calls if c[0] in ("delete_key", "delete_value",
                                             "create_key", "set_value")]


def _manifest(run_dir: Path) -> dict:
    return json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))


def _path_item(tmp_path, name="junk.bin"):
    d = tmp_path / "junk"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_bytes(b"x" * 100)
    return p, CleanableItem(cleaner_id="t", description=p.name, size=100, path=str(p))


# -- happy path -----------------------------------------------------------------
def test_clean_hkcu_entry_backs_up_then_deletes(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    run = quarantine.new_run()
    seen = []
    real_delete = reg.delete_key

    def hooked(hive, key):
        # The manifest (with the backup entry) is durable before any delete.
        mf = run.dir / "manifest.json"
        seen.append(mf.exists() and _manifest(run.dir)["items"][0]["type"] == "registry")
        return real_delete(hive, key)

    reg.delete_key = hooked
    res = Engine([]).clean([item], dry_run=False, registry_backup=run)
    o = res.outcomes[0]
    assert o.removed is True and o.error is None and o.freed == 0
    assert seen and all(seen)
    assert not reg.key_exists("HKCU", FOO)
    assert reg.key_exists("HKCU", UNINST)  # the container is untouched
    entry = _manifest(run.dir)["items"][0]
    assert entry["deleted"] is True
    assert entry["hive"] == "HKCU" and entry["key"] == FOO and entry["value"] is None
    assert entry["cleaner_id"] == "win_reg_uninstall" and entry["size"] == 0
    assert Path(entry["json"]).is_file() and Path(entry["reg"]).is_file()
    assert Path(entry["json"]).parent == run.dir / "registry"
    # Bottom-up, leaf keys only, by exact path.
    deletes = [c[2] for c in reg.calls if c[0] == "delete_key"]
    assert deletes == [FOO + r"\Sub\Deeper", FOO + r"\Sub", FOO]


def test_value_target_deleted_by_exact_name(state, fake_registry):
    reg = fake_registry
    reg.add_key("HKCU", RUN, {"GoneApp": (REG_SZ, r"C:\Gone\app.exe"),
                              "Keep": (REG_SZ, r"C:\Live\app.exe")})
    item = _item(reg, cid="win_reg_startup", key=RUN, value="goneapp")
    run = quarantine.new_run()
    o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert o.removed is True, o.error
    assert ("delete_value", "HKCU", RUN, "GoneApp") in reg.calls
    assert set(reg.tree("HKCU", RUN)["values"]) == {"Keep"}


# -- Review Focus 1: changed since the scan --------------------------------------
def test_changed_since_scan_nothing_deleted(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    reg.add_key("HKCU", FOO, {"DisplayVersion": (REG_SZ, "2.0")})  # reinstalled
    run = quarantine.new_run()
    o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert o.removed is False
    assert o.error == "changed since the scan; scan again"
    assert _writes(reg) == []
    assert reg.key_exists("HKCU", FOO + r"\Sub\Deeper")
    # No orphan backup entry marked deleted (none was even written).
    assert not (run.dir / "manifest.json").exists() or all(
        e.get("deleted") is not True for e in _manifest(run.dir)["items"]
    )


def test_changed_between_backup_and_delete_nothing_deleted(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    run = quarantine.new_run()

    class Racy:
        run_id = run.run_id

        def before_delete(self, it, backend):
            run.store_registry(it, backend)
            reg.add_key("HKCU", FOO + r"\Sub", {"A": (REG_SZ, "changed")})

        def after_delete(self, it, deleted):
            run.mark_registry(it, deleted)

    o = Engine([]).clean([item], dry_run=False, registry_backup=Racy()).outcomes[0]
    assert o.removed is False and "changed since the scan" in o.error
    assert _writes(reg) == []
    assert _manifest(run.dir)["items"][0]["deleted"] is False


def test_delete_target_raises_registry_changed(fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    reg.add_key("HKCU", FOO + r"\New")
    with pytest.raises(regclean.RegistryChanged):
        regclean.delete_target(reg, "win_reg_uninstall", item.reg, is_admin=False)
    assert _writes(reg) == []


# -- Review Focus 3: backup location unwritable -------------------------------------
def test_backup_dir_unwritable_nothing_deleted(state, fake_registry, tmp_path):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    p, path_item = _path_item(tmp_path)
    run = quarantine.new_run()
    # A regular file where the "registry" backup directory must go.
    run._claim()
    (run.dir / "registry").write_bytes(b"not a directory")
    res = Engine([]).clean([item, path_item], dry_run=False, registry_backup=run)
    reg_o, path_o = res.outcomes
    assert reg_o.removed is False
    assert reg_o.error.startswith("backup failed, nothing deleted: ")
    assert _writes(reg) == []
    assert reg.key_exists("HKCU", FOO + r"\Sub\Deeper")
    assert run.items == []
    assert path_o.removed is True and not p.exists()  # file items unaffected


def test_backup_error_vetoes(state, fake_registry, monkeypatch):
    from cleanix.core import regbackup

    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)

    def fail(*a, **k):
        raise regbackup.BackupError("disk full")

    monkeypatch.setattr(regbackup, "write_backup", fail)
    run = quarantine.new_run()
    o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert o.error == "backup failed, nothing deleted: disk full"
    assert _writes(reg) == [] and run.items == []


def test_manifest_save_failure_vetoes_and_rolls_back(state, fake_registry, monkeypatch):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    run = quarantine.new_run()

    def broken_save():
        raise OSError("disk full")

    monkeypatch.setattr(run, "save", broken_save)
    o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert o.removed is False and o.error.startswith("backup failed, nothing deleted")
    assert _writes(reg) == []
    assert run.items == []
    assert not list((run.dir / "registry").glob("*__registry.*"))


def test_failed_manifest_save_keeps_earlier_entries_restorable(
    state, fake_registry, monkeypatch
):
    reg = fake_registry
    _foo_tree(reg)
    reg.add_key("HKCU", UNINST + r"\Bar", {"DisplayName": (REG_SZ, "Bar")})
    first, second = _item(reg), _item(reg, key=UNINST + r"\Bar")
    run = quarantine.new_run()
    assert Engine([]).clean([first], dry_run=False, registry_backup=run).outcomes[0].removed

    def disk_full(src, dst):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(quarantine, "_replace", disk_full)
    o = Engine([]).clean([second], dry_run=False, registry_backup=run).outcomes[0]
    assert o.removed is False and o.error.startswith("backup failed, nothing deleted")
    assert reg.key_exists("HKCU", UNINST + r"\Bar")
    assert not list(run.dir.glob(".manifest.*"))
    monkeypatch.undo()
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: state / "q")
    monkeypatch.setattr(winenv, "is_admin", lambda: False)
    row, = quarantine.list_runs()
    assert row["registry"] == 1
    res = quarantine.restore(run.run_id)
    assert res == {"restored": [first.reg.display], "failed": []}
    assert reg.key_exists("HKCU", FOO + r"\Sub\Deeper")


# -- preflight ---------------------------------------------------------------------------
def test_preflight_denied_nothing_deleted(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    reg.add_key("HKCU", FOO + r"\Sub", deny_delete=True)  # ACL on one subkey
    item = _item(reg)
    run = quarantine.new_run()
    o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert o.removed is False and "nothing was deleted" in o.error
    assert _writes(reg) == []
    assert _manifest(run.dir)["items"][0]["deleted"] is False
    with pytest.raises(AccessDenied):
        regclean.delete_target(reg, "win_reg_uninstall", item.reg, is_admin=False)


# -- Review Focus 2: failure mid-tree ------------------------------------------------------
def test_partial_delete_reports_run_and_restore_completes(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    run = quarantine.new_run()
    real_delete = reg.delete_key
    n = [0]

    def flaky(hive, key):
        n[0] += 1
        if n[0] == 2:  # the first leaf is gone, then a key is locked
            raise RegistryError("key in use")
        return real_delete(hive, key)

    reg.delete_key = flaky
    o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert o.removed is False
    assert o.error.startswith("partially deleted")
    assert f"cleanix restore {run.run_id}" in o.error
    assert not reg.key_exists("HKCU", FOO + r"\Sub\Deeper")
    assert reg.key_exists("HKCU", FOO + r"\Sub")
    assert _manifest(run.dir)["items"][0]["deleted"] is True
    run.save()
    reg.delete_key = real_delete
    res = quarantine.restore(run.run_id)
    assert res["failed"] == [] and res["restored"] == [item.reg.display]
    t = RegTarget("HKCU", FOO)
    assert regsnap.fingerprint(t, regsnap.snapshot(reg, t)) == item.reg.fingerprint


def test_each_leaf_reverified_before_its_delete(state, fake_registry):
    """A change (here: a key turning into a link) between two leaf deletes
    stops the delete before the changed key is touched."""
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    run = quarantine.new_run()
    real_delete = reg.delete_key

    def then_change(hive, key):
        real_delete(hive, key)
        reg.add_key("HKCU", FOO + r"\Sub", link=True)

    reg.delete_key = then_change
    o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert o.removed is False and o.error.startswith("partially deleted")
    assert [c[2] for c in reg.calls if c[0] == "delete_key"] == [FOO + r"\Sub\Deeper"]
    assert reg.key_exists("HKCU", FOO + r"\Sub")


def test_first_delete_failure_with_entry_intact_is_not_partial(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    run = quarantine.new_run()
    reg.fail_next("delete_key", RegistryError("key in use"))
    o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert o.removed is False and o.error.startswith("not removed: ")
    assert reg.key_exists("HKCU", FOO + r"\Sub\Deeper")
    assert _manifest(run.dir)["items"][0]["deleted"] is False


def test_unverified_removal_is_reported(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    run = quarantine.new_run()
    real_delete = reg.delete_key

    def silent(hive, key):  # claims success on the last key, leaves it
        if key == FOO:
            return None
        return real_delete(hive, key)

    reg.delete_key = silent
    o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert o.removed is False and o.error.startswith("partially deleted")
    assert "scan again" in o.error
    assert _manifest(run.dir)["items"][0]["deleted"] is True


# -- links (R17) --------------------------------------------------------------------------
def _win_backend():
    from test_winreg_backend import FakeWinreg

    from cleanix.core.winregistry_win import WinRegBackend

    w = FakeWinreg()  # pessimistic: DeleteKeyEx follows a final-component link
    w.add(w.HKEY_CURRENT_USER, r"SOFTWARE\Victim", [("Precious", "1", REG_SZ)])
    w.add(w.HKEY_CURRENT_USER, FOO, [("DisplayName", "Foo", REG_SZ)])
    return w, WinRegBackend(winreg_module=w)


def _swap_leaf_for_link(w):
    parent = w.find(w.HKEY_CURRENT_USER, UNINST)
    del parent.children["foo"]
    w.add(w.HKEY_CURRENT_USER, FOO, link_to=(w.HKEY_CURRENT_USER, r"SOFTWARE\Victim"))


def test_link_swapped_in_after_backup_is_refused(state):
    w, be = _win_backend()
    with winregistry.using_backend(be):
        item = _item(be)
        run = quarantine.new_run()

        class Swapper:
            run_id = run.run_id

            def before_delete(self, it, backend):
                run.store_registry(it, backend)
                _swap_leaf_for_link(w)

            def after_delete(self, it, deleted):
                run.mark_registry(it, deleted)

        o = Engine([]).clean([item], dry_run=False, registry_backup=Swapper()).outcomes[0]
    assert o.removed is False
    assert w.find(w.HKEY_CURRENT_USER, r"SOFTWARE\Victim") is not None
    assert not any(c[0] in ("DeleteKeyEx", "DeleteValue") for c in w.calls)
    assert _manifest(run.dir)["items"][0]["deleted"] is False


def test_link_swapped_in_during_verification_is_refused(state):
    """A swap after check_target but before the pre-delete re-snapshot."""
    w, be = _win_backend()
    with winregistry.using_backend(be):
        item = _item(be)
    original = be.is_link
    seen = [0]

    def is_link(hive, key):
        if key == FOO:
            seen[0] += 1
        if key == FOO and seen[0] == 1:
            r = original(hive, key)  # check_target's own look: still a key
            _swap_leaf_for_link(w)
            return r
        return original(hive, key)

    be.is_link = is_link
    with pytest.raises(regclean.RegistryChanged):
        regclean.delete_target(be, "win_reg_uninstall", item.reg, is_admin=False)
    assert w.find(w.HKEY_CURRENT_USER, r"SOFTWARE\Victim") is not None
    assert not any(c[0] == "DeleteKeyEx" for c in w.calls)


def test_r17_residual_link_swap_inside_delete_is_reported_not_success(state):
    """The accepted residual race (R17): a swap between the backend's own
    handle check and DeleteKeyEx cannot be seen by any caller. Under the
    pessimistic model the link TARGET leaf is deleted. delete_target's
    post-delete check still finds the entry (now a link) and reports an
    error with scan-again advice instead of success."""
    w, be = _win_backend()
    with winregistry.using_backend(be):
        item = _item(be)
        run = quarantine.new_run()
        w.before["DeleteKeyEx"] = lambda: _swap_leaf_for_link(w)
        o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert w.find(w.HKEY_CURRENT_USER, r"SOFTWARE\Victim") is None  # the residual
    assert o.removed is False
    assert o.error.startswith("partially deleted") and "scan again" in o.error


# -- engine contract ------------------------------------------------------------------------
def test_no_sink_refuses(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    reg.calls.clear()
    o = Engine([]).clean([item], dry_run=False).outcomes[0]
    assert o.removed is False
    assert o.error == "registry entries are removed only with a backup"
    assert reg.calls == []


def test_blocked_by_safety_rules(state, fake_registry):
    reg = fake_registry
    reg.add_key("HKCU", r"SOFTWARE\Policies\Foo")
    item = CleanableItem(
        cleaner_id="win_reg_uninstall", description="x", kind=ItemKind.REGISTRY,
        reg=RegTarget("HKCU", r"SOFTWARE\Policies\Foo", None, "fp"),
    )
    run = quarantine.new_run()
    for dry in (True, False):
        o = Engine([]).clean([item], dry_run=dry, registry_backup=run).outcomes[0]
        assert o.removed is False
        assert o.error.startswith("blocked by registry safety rules")
    assert reg.calls == []


def test_dry_run_touches_nothing(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    reg.calls.clear()
    run = quarantine.new_run()
    res = Engine([]).clean([item], dry_run=True, registry_backup=run)
    o = res.outcomes[0]
    assert o.dry_run and o.removed is False and o.error is None and o.freed == 0
    assert reg.calls == []  # a dry run makes no registry call at all
    assert not (state / "q").exists()
    summary = service.clean([item], Config(), dry_run=True)
    assert summary.quarantine_run is None and not (state / "q").exists()
    assert not (state / "state").exists()
    assert _writes(reg) == []


def test_cancel_between_items(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    reg.add_key("HKCU", UNINST + r"\Bar", {"DisplayName": (REG_SZ, "Bar")})
    items = [_item(reg), _item(reg, key=UNINST + r"\Bar")]
    run = quarantine.new_run()
    calls = [0]

    def cancel():
        calls[0] += 1
        return calls[0] > 1

    res = Engine([]).clean(items, dry_run=False, registry_backup=run, cancel=cancel)
    assert len(res.outcomes) == 1 and res.outcomes[0].removed
    assert reg.key_exists("HKCU", UNINST + r"\Bar")


def test_one_failure_does_not_abort_others(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    reg.add_key("HKCU", UNINST + r"\Bar", {"DisplayName": (REG_SZ, "Bar")})
    a, b = _item(reg), _item(reg, key=UNINST + r"\Bar")
    reg.add_key("HKCU", FOO, {"X": (REG_SZ, "changed")})
    run = quarantine.new_run()
    res = Engine([]).clean([a, b], dry_run=False, registry_backup=run)
    assert res.outcomes[0].removed is False
    assert res.outcomes[1].removed is True
    assert not reg.key_exists("HKCU", UNINST + r"\Bar")


def test_unexpected_exception_is_contained(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)

    class Boom:
        def before_delete(self, it, backend):
            raise RuntimeError("bug")

        def after_delete(self, it, deleted):
            raise AssertionError("not reached")

    o = Engine([]).clean([item], dry_run=False, registry_backup=Boom()).outcomes[0]
    assert o.removed is False and o.error == "backup failed, nothing deleted: bug"
    assert _writes(reg) == []


# -- HKLM ----------------------------------------------------------------------------------
def test_hklm_not_admin_refused_before_backup(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg, hive="HKLM")
    item = _item(reg, hive="HKLM")
    reg.calls.clear()
    run = quarantine.new_run()
    o = Engine([]).clean([item], dry_run=False, registry_backup=run,
                         allow_root_items=True).outcomes[0]
    assert o.removed is False
    assert "administrator" in o.error.lower() and "HKLM" in o.error
    assert reg.calls == [] and run.items == []
    with pytest.raises(regclean.AdminRequired) as ei:
        regclean.delete_target(reg, "win_reg_uninstall", item.reg, is_admin=False)
    assert "Administrator" in str(ei.value)
    assert _writes(reg) == []


def test_hklm_admin_deletes(state, fake_registry, monkeypatch):
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    reg = fake_registry
    _foo_tree(reg, hive="HKLM")
    item = _item(reg, hive="HKLM")
    run = quarantine.new_run()
    o = Engine([]).clean([item], dry_run=False, registry_backup=run,
                         allow_root_items=True).outcomes[0]
    assert o.removed is True, o.error
    assert not reg.key_exists("HKLM", FOO)


# -- service ------------------------------------------------------------------------------------
def test_service_creates_run_without_keep_copy(state, fake_registry, tmp_path):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    p, path_item = _path_item(tmp_path)
    summary = service.clean([item, path_item], Config(), dry_run=False,
                            use_quarantine=False)
    assert summary.removed == 2, summary.errors
    assert not p.exists()
    assert summary.quarantine_run
    data = _manifest(state / "q" / summary.quarantine_run)
    # Only the registry backup is in the run: the file was deleted, not moved.
    assert [e.get("type") for e in data["items"]] == ["registry"]
    assert not (state / "q" / summary.quarantine_run / "files").exists()


def test_service_helper_mode_writes_nothing(state, fake_registry, monkeypatch):
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    reg = fake_registry
    _foo_tree(reg, hive="HKLM")
    item = _item(reg, hive="HKLM")
    gui_run = quarantine.new_run()  # the GUI's backup, written as the user
    gui_run.store_registry(item, reg)
    before = sorted(p.name for p in (state / "q").iterdir())
    reg.calls.clear()
    summary = service.clean([item], Config(), dry_run=False, use_quarantine=False,
                            record_history=False, registry_backup_elsewhere=True,
                            registry_backup_run=gui_run.run_id)
    assert summary.removed == 1, summary.errors
    assert summary.quarantine_run is None
    assert sorted(p.name for p in (state / "q").iterdir()) == before
    assert not (state / "state").exists()
    assert not reg.key_exists("HKLM", FOO)
    assert not [c for c in reg.calls if c[0] in ("create_key", "set_value")]


def test_service_registry_without_history_refused(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    reg.calls.clear()
    with pytest.raises(ValueError):
        service.clean([item], Config(), dry_run=False, use_quarantine=False,
                      record_history=False)
    assert reg.calls == [] and not (state / "q").exists()


def test_service_history_records_registry_run(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    summary = service.clean([item], Config(), dry_run=False, use_quarantine=False)
    stats = history.stats()
    assert stats["runs"] == 1 and stats["total_items"] == 1 and stats["total_freed"] == 0
    lines = Path(summary.manifest_path).read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    assert rec["cleaner_id"] == "win_reg_uninstall" and rec["bytes"] == 0
    assert "Foo App" not in Path(summary.manifest_path).read_text(encoding="utf-8")


# -- quarantine restore / list -------------------------------------------------------------------
def test_restore_hkcu_roundtrip_via_quarantine_restore(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    summary = service.clean([item], Config(), dry_run=False, use_quarantine=False)
    assert not reg.key_exists("HKCU", FOO)
    res = quarantine.restore(summary.quarantine_run)
    assert res == {"restored": [item.reg.display], "failed": []}
    t = RegTarget("HKCU", FOO)
    assert regsnap.fingerprint(t, regsnap.snapshot(reg, t)) == item.reg.fingerprint
    assert not (state / "q" / summary.quarantine_run).exists()


def test_restore_hklm_not_admin_reports_instruction(state, fake_registry, monkeypatch):
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    reg = fake_registry
    _foo_tree(reg, hive="HKLM")
    item = _item(reg, hive="HKLM")
    summary = service.clean([item], Config(), dry_run=False, use_quarantine=False)
    run_id = summary.quarantine_run
    assert run_id and not reg.key_exists("HKLM", FOO)
    monkeypatch.setattr(winenv, "is_admin", lambda: False)
    reg.calls.clear()
    res = quarantine.restore(run_id)
    assert res["restored"] == []
    (orig, reason), = res["failed"]
    assert orig == item.reg.display
    assert f"cleanix restore {run_id}" in reason and "reg import" in reason
    assert "{run}" not in reason
    assert _writes(reg) == []
    assert (state / "q" / run_id / "manifest.json").exists()  # the run is kept


def test_restore_skips_not_deleted_entries(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    run = quarantine.new_run()
    # A backup written, then the delete vetoed: the entry is still there.
    run.store_registry(item, reg)
    run.mark_registry(item, False)
    reg.add_key("HKCU", FOO, {"X": (REG_SZ, "changed since")})
    reg.calls.clear()
    res = quarantine.restore(run.run_id)
    assert res == {"restored": [], "failed": []}
    assert _writes(reg) == []
    # Nothing was consumed: the run and its backup are kept.
    assert (run.dir / "manifest.json").is_file()
    assert list((run.dir / "registry").glob("*__registry.json"))


def test_restore_ignores_paths_outside_the_run(state, fake_registry, tmp_path):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    summary = service.clean([item], Config(), dry_run=False, use_quarantine=False)
    run_dir = state / "q" / summary.quarantine_run
    data = _manifest(run_dir)
    data["items"][0]["json"] = str(tmp_path / "elsewhere" / "0__registry.json")
    (run_dir / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
    res = quarantine.restore(summary.quarantine_run)
    # The backup inside the run is used, never the recorded foreign path.
    assert res["failed"] == [] and res["restored"] == [item.reg.display]


def test_old_file_manifests_still_restore(state, tmp_path):
    root = state / "q" / "20250101-000000-1"
    files = root / "files"
    files.mkdir(parents=True)
    stored = files / "0__a.txt"
    stored.write_text("hello", encoding="utf-8")
    original = tmp_path / "orig" / "a.txt"
    (root / "manifest.json").write_text(json.dumps({
        "run_id": "20250101-000000-1", "created": 1.0,
        "items": [{"original": str(original), "stored": str(stored), "size": 5}],
    }), encoding="utf-8")
    runs = quarantine.list_runs()
    assert runs == [{"run_id": "20250101-000000-1", "created": 1.0, "count": 1,
                     "size": 5, "registry": 0, "registry_admin": 0,
                     "removed_count": 1}]
    res = quarantine.restore("20250101-000000-1")
    assert res == {"restored": [str(original)], "failed": []}
    assert original.read_text(encoding="utf-8") == "hello"


def test_list_runs_registry_counts(state, fake_registry, monkeypatch, tmp_path):
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    reg = fake_registry
    _foo_tree(reg)
    _foo_tree(reg, hive="HKLM")
    reg.add_key("HKLM", UNINST + r"\Bar", {"DisplayName": (REG_SZ, "Bar")})
    items = [_item(reg), _item(reg, hive="HKLM"), _item(reg, hive="HKLM", key=UNINST + r"\Bar")]
    p, path_item = _path_item(tmp_path)
    summary = service.clean(items + [path_item], Config(), dry_run=False,
                            use_quarantine=True)
    assert summary.removed == 4, summary.errors
    row, = quarantine.list_runs()
    assert row["run_id"] == summary.quarantine_run
    assert row["count"] == 4 and row["size"] == 100
    assert row["registry"] == 3 and row["registry_admin"] == 2
    # purge is unchanged and removes the whole run.
    quarantine.purge(summary.quarantine_run)
    assert quarantine.list_runs() == []


def test_unknown_entry_type_fails_restore(state):
    root = state / "q" / "r1"
    root.mkdir(parents=True)
    (root / "manifest.json").write_text(json.dumps({
        "run_id": "r1", "created": 1.0,
        "items": [{"type": "mystery", "original": "x", "size": 0}],
    }), encoding="utf-8")
    res = quarantine.restore("r1")
    assert res["restored"] == [] and res["failed"] == [("x", "unknown entry type")]
    assert root.exists()


def test_verify_only_sink_writes_nothing(state, fake_registry):
    _foo_tree(fake_registry, hive="HKLM")
    item = _item(fake_registry, hive="HKLM")
    run = quarantine.new_run()
    run.store_registry(item, fake_registry)
    fake_registry.calls.clear()
    for sink in (regclean.VerifyOnlySink(run.run_id), regclean.VerifyOnlySink(run.dir)):
        sink.before_delete(item, fake_registry)
        sink.after_delete(item, True)
    assert fake_registry.calls == []


# == fix round 1 ====================================================================
# -- C1: unique run ids, manifest guard ------------------------------------------------
def test_new_run_ids_unique_within_one_second(state, monkeypatch):
    monkeypatch.setattr(quarantine.time, "strftime", lambda fmt, *a: "20261119-120000")
    a, b = quarantine.new_run(), quarantine.new_run()
    assert a.run_id != b.run_id
    assert a.run_id.startswith("20261119-120000-") and b.run_id.startswith("20261119-120000-")
    a._claim()
    b._claim()
    assert a.dir != b.dir and a.dir.is_dir() and b.dir.is_dir()


def test_same_id_takes_a_fresh_directory(state, fake_registry, monkeypatch, tmp_path):
    """Two runs constructed with the same id (the old same-second case)
    never share a directory; restoring one cannot touch the other."""
    monkeypatch.setattr(quarantine, "new_run",
                        lambda: quarantine.Quarantine("20261119-000000-1"))
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    s1 = service.clean([item], Config(), dry_run=False, use_quarantine=False)
    p, path_item = _path_item(tmp_path)
    s2 = service.clean([path_item], Config(), dry_run=False, use_quarantine=True)
    assert s1.quarantine_run and s2.quarantine_run and s1.quarantine_run != s2.quarantine_run
    first = _manifest(state / "q" / s1.quarantine_run)
    assert [e.get("type") for e in first["items"]] == ["registry"]
    json_path = Path(first["items"][0]["json"])
    assert json_path.is_file()
    # Restoring run B leaves run A's backups alone.
    assert quarantine.restore(s2.quarantine_run)["failed"] == []
    assert p.exists() and json_path.is_file()
    res = quarantine.restore(s1.quarantine_run)
    assert res == {"restored": [item.reg.display], "failed": []}
    assert reg.key_exists("HKCU", FOO + r"\Sub\Deeper")


def test_two_registry_cleans_same_second_do_not_collide(state, fake_registry, monkeypatch):
    monkeypatch.setattr(quarantine.time, "strftime", lambda fmt, *a: "20261119-120000")
    reg = fake_registry
    _foo_tree(reg)
    reg.add_key("HKCU", UNINST + r"\Bar", {"DisplayName": (REG_SZ, "Bar")})
    a, b = _item(reg), _item(reg, key=UNINST + r"\Bar")
    s1 = service.clean([a], Config(), dry_run=False, use_quarantine=False)
    s2 = service.clean([b], Config(), dry_run=False, use_quarantine=False)
    assert s1.removed == 1 and s2.removed == 1, (s1.errors, s2.errors)
    assert s1.quarantine_run != s2.quarantine_run
    assert len(_manifest(state / "q" / s1.quarantine_run)["items"]) == 1
    assert len(_manifest(state / "q" / s2.quarantine_run)["items"]) == 1


def test_save_refuses_a_manifest_it_did_not_write(state):
    a = quarantine.new_run()
    a.items.append({"original": "x", "stored": "y", "size": 1})
    a.save()
    before = (a.dir / "manifest.json").read_bytes()
    b = quarantine.Quarantine(a.run_id)
    b._claimed = True  # as if it had (wrongly) got the same directory
    with pytest.raises(quarantine.ManifestConflict):
        b.save()
    assert (a.dir / "manifest.json").read_bytes() == before
    a.items.append({"original": "z", "stored": "w", "size": 1})
    a.save()  # the owner can still update it


def test_save_fsyncs_and_retries_permission_error(state, monkeypatch):
    synced, attempts = [], [0]
    real_fsync, real_replace = quarantine.os.fsync, quarantine._replace
    monkeypatch.setattr(quarantine.os, "fsync", lambda fd: synced.append(fd) or real_fsync(fd))
    monkeypatch.setattr(quarantine.time, "sleep", lambda s: None)

    def flaky(src, dst):
        attempts[0] += 1
        if attempts[0] < 3:
            raise PermissionError(13, "in use")
        real_replace(src, dst)

    monkeypatch.setattr(quarantine, "_replace", flaky)
    run = quarantine.new_run()
    run.save()
    assert synced and attempts[0] == 3
    assert (run.dir / "manifest.json").is_file()
    assert not list(run.dir.glob(".manifest.*"))


def test_vetoed_registry_clean_saves_no_empty_run(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    reg.add_key("HKCU", FOO, {"New": (REG_SZ, "x")})
    summary = service.clean([item], Config(), dry_run=False, use_quarantine=False)
    assert summary.removed == 0 and summary.quarantine_run is None
    assert quarantine.list_runs() == []


# -- I1: strict backup-elsewhere -------------------------------------------------------------
def test_elsewhere_refuses_hkcu(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    run = quarantine.new_run()
    run.store_registry(item, reg)  # even with a backup
    reg.calls.clear()
    s = service.clean([item], Config(), dry_run=False, use_quarantine=False,
                      record_history=False, registry_backup_elsewhere=True,
                      registry_backup_run=run.run_id)
    assert s.removed == 0
    assert "backup is required for this entry" in s.errors[0].error
    assert _writes(reg) == [] and reg.key_exists("HKCU", FOO)


def test_elsewhere_hklm_without_valid_backup_refused(state, fake_registry, monkeypatch, tmp_path):
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    reg = fake_registry
    _foo_tree(reg, hive="HKLM")
    reg.add_key("HKLM", UNINST + r"\Bar", {"DisplayName": (REG_SZ, "Bar")})
    item = _item(reg, hive="HKLM")
    other = _item(reg, hive="HKLM", key=UNINST + r"\Bar")
    run = quarantine.new_run()
    run.store_registry(other, reg)  # a backup, but of another entry
    empty = tmp_path / "empty"
    empty.mkdir()
    for kw in ({}, {"registry_backup_dir": empty}, {"registry_backup_run": run.run_id},
               {"registry_backup_dir": run.dir}):
        s = service.clean([item], Config(), dry_run=False, use_quarantine=False,
                          record_history=False, registry_backup_elsewhere=True, **kw)
        assert s.removed == 0, kw
        assert "backup is required for this entry" in s.errors[0].error
    # A tampered backup of the right entry does not count either.
    run.store_registry(item, reg)
    jp = Path(run.items[-1]["json"])
    doc = json.loads(jp.read_text(encoding="ascii"))
    doc["snapshot"]["values"][0]["data"] = "tampered"
    jp.write_text(json.dumps(doc), encoding="ascii")
    s = service.clean([item], Config(), dry_run=False, use_quarantine=False,
                      record_history=False, registry_backup_elsewhere=True,
                      registry_backup_run=run.run_id)
    assert s.removed == 0
    assert _writes(reg) == [] and reg.key_exists("HKLM", FOO + r"\Sub\Deeper")


def test_elsewhere_partial_names_backup_location(state, fake_registry, monkeypatch):
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    reg = fake_registry
    _foo_tree(reg, hive="HKLM")
    item = _item(reg, hive="HKLM")
    run = quarantine.new_run()
    run.store_registry(item, reg)
    real_delete, n = reg.delete_key, [0]

    def flaky(hive, key):
        n[0] += 1
        if n[0] == 2:
            raise RegistryError("in use")
        return real_delete(hive, key)

    reg.delete_key = flaky
    s = service.clean([item], Config(), dry_run=False, use_quarantine=False,
                      record_history=False, registry_backup_elsewhere=True,
                      registry_backup_run=run.run_id)
    err = s.errors[0].error
    assert err.startswith("partially deleted") and f"cleanix restore {run.run_id}" in err


# == fix round 2 ====================================================================
# -- N1: the helper's sink is bound to a run of this account ------------------------------
def _gui_backup(reg, monkeypatch):
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    _foo_tree(reg, hive="HKLM")
    item = _item(reg, hive="HKLM")
    run = quarantine.new_run()
    run.store_registry(item, reg)
    return item, run


def _helper_clean(item, **kw):
    return service.clean([item], Config(), dry_run=False, use_quarantine=False,
                         record_history=False, registry_backup_elsewhere=True, **kw)


def test_sink_refuses_backup_marked_not_deleted(state, fake_registry, monkeypatch):
    reg = fake_registry
    item, run = _gui_backup(reg, monkeypatch)
    run.mark_registry(item, False)  # Undo would skip this entry
    s = _helper_clean(item, registry_backup_run=run.run_id)
    assert s.removed == 0 and "backup is required for this entry" in s.errors[0].error
    assert reg.key_exists("HKLM", FOO + r"\Sub\Deeper")
    # ...and Undo of that run keeps its only backup.
    from cleanix.core import regbackup

    monkeypatch.setattr(regbackup, "owner_is_current_user", lambda p: True)
    assert quarantine.restore(run.run_id, allow_machine_restore=True) == {
        "restored": [], "failed": []}
    assert list((run.dir / "registry").glob("*__registry.json"))


def test_sink_refuses_orphan_backup_outside_a_run(state, fake_registry, monkeypatch, tmp_path):
    reg = fake_registry
    item, run = _gui_backup(reg, monkeypatch)
    for name in ("outside", ):
        loose = tmp_path / name
        loose.mkdir()
        for f in (run.dir / "registry").iterdir():
            shutil.copy(f, loose / f.name)
    # A copy under the root but without a manifest entry.
    inside = state / "q" / "loose-run"
    (inside / "registry").mkdir(parents=True)
    for f in (run.dir / "registry").iterdir():
        shutil.copy(f, inside / "registry" / f.name)
    shutil.rmtree(run.dir)
    for kw in ({"registry_backup_dir": tmp_path / "outside"},
               {"registry_backup_run": "loose-run"},
               {"registry_backup_run": run.run_id}):
        s = _helper_clean(item, **kw)
        assert s.removed == 0, kw
    assert _writes(reg) == [] and reg.key_exists("HKLM", FOO)


@pytest.mark.parametrize("bad", ["..", ".", "", "a/b", "a\\b", "..\\q", "/abs", "C:x", "x\x00"])
def test_sink_refuses_unsafe_run_ids(state, fake_registry, monkeypatch, bad):
    reg = fake_registry
    item, run = _gui_backup(reg, monkeypatch)
    sink = regclean.VerifyOnlySink(bad)
    with pytest.raises(Exception) as ei:
        sink.before_delete(item, reg)
    assert "backup is required for this entry" in str(ei.value)


def test_sink_path_must_be_under_root(state, fake_registry, monkeypatch, tmp_path):
    reg = fake_registry
    item, run = _gui_backup(reg, monkeypatch)
    regclean.VerifyOnlySink(run.dir).before_delete(item, reg)  # inside: fine
    with pytest.raises(Exception):
        regclean.VerifyOnlySink(run.dir / "registry").before_delete(item, reg)
    with pytest.raises(Exception):
        regclean.VerifyOnlySink(state / "q" / "x" / ".." / run.run_id / "..").before_delete(item, reg)


def test_sink_matches_cleaner_target_and_fingerprint_exactly(state, fake_registry, monkeypatch):
    reg = fake_registry
    item, run = _gui_backup(reg, monkeypatch)
    sink = regclean.VerifyOnlySink(run.run_id)
    sink.before_delete(item, reg)
    variants = [
        CleanableItem(cleaner_id="win_reg_app_paths", description="x",
                      kind=ItemKind.REGISTRY, reg=item.reg, requires_root=True),
        CleanableItem(cleaner_id=item.cleaner_id, description="x", kind=ItemKind.REGISTRY,
                      reg=RegTarget("HKLM", FOO, None, "0" * 64), requires_root=True),
        CleanableItem(cleaner_id=item.cleaner_id, description="x", kind=ItemKind.REGISTRY,
                      reg=RegTarget("HKLM", UNINST + r"\Other", None, item.reg.fingerprint),
                      requires_root=True),
        CleanableItem(cleaner_id=item.cleaner_id, description="x", kind=ItemKind.REGISTRY,
                      reg=RegTarget("HKLM", FOO, "DisplayName", item.reg.fingerprint),
                      requires_root=True),
    ]
    for v in variants:
        with pytest.raises(Exception) as ei:
            sink.before_delete(v, reg)
        assert "backup is required for this entry" in str(ei.value), v


def test_sink_manifest_and_json_must_agree(state, fake_registry, monkeypatch):
    """A manifest entry whose json file is another entry's backup is refused."""
    reg = fake_registry
    item, run = _gui_backup(reg, monkeypatch)
    reg.add_key("HKLM", UNINST + r"\Bar", {"DisplayName": (REG_SZ, "Bar")})
    other = _item(reg, hive="HKLM", key=UNINST + r"\Bar")
    run.store_registry(other, reg)
    data = _manifest(run.dir)
    data["items"][0]["json"], data["items"][1]["json"] = (
        data["items"][1]["json"], data["items"][0]["json"])
    (run.dir / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(Exception):
        regclean.VerifyOnlySink(run.run_id).before_delete(item, reg)


def test_restore_keeps_run_unless_fully_consumed(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    reg.add_key("HKCU", UNINST + r"\Bar", {"DisplayName": (REG_SZ, "Bar")})
    a, b = _item(reg), _item(reg, key=UNINST + r"\Bar")
    run = quarantine.new_run()
    Engine([]).clean([a], dry_run=False, registry_backup=run)
    run.store_registry(b, reg)
    run.mark_registry(b, False)
    res = quarantine.restore(run.run_id)
    assert res == {"restored": [a.reg.display], "failed": []}
    assert run.dir.is_dir()  # b's backup is still there
    # A run whose every entry was restored is removed as before.
    run2 = quarantine.new_run()
    reg.add_key("HKCU", UNINST + r"\Baz", {"DisplayName": (REG_SZ, "Baz")})
    c = _item(reg, key=UNINST + r"\Baz")
    Engine([]).clean([c], dry_run=False, registry_backup=run2)
    assert quarantine.restore(run2.run_id)["restored"] == [c.reg.display]
    assert not run2.dir.exists()


def test_external_manifest_change_vetoes_next_delete(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    reg.add_key("HKCU", UNINST + r"\Bar", {"DisplayName": (REG_SZ, "Bar")})
    a, b = _item(reg), _item(reg, key=UNINST + r"\Bar")
    run = quarantine.new_run()
    real_after = run.after_delete

    def after(item, deleted):
        real_after(item, deleted)
        mf = run.dir / "manifest.json"
        mf.write_bytes(mf.read_bytes() + b" ")  # someone else touched it

    run.after_delete = after
    res = Engine([]).clean([a, b], dry_run=False, registry_backup=run)
    assert res.outcomes[0].removed is True
    assert res.outcomes[1].removed is False
    assert res.outcomes[1].error.startswith("backup failed, nothing deleted")
    assert reg.key_exists("HKCU", UNINST + r"\Bar")


def test_backup_failure_after_claim_leaves_no_empty_run(state, fake_registry, monkeypatch):
    from cleanix.core import regbackup

    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)

    def fail(directory, *a, **k):
        Path(directory).mkdir(parents=True, exist_ok=True)
        raise regbackup.BackupError("disk full")

    monkeypatch.setattr(regbackup, "write_backup", fail)
    s = service.clean([item], Config(), dry_run=False, use_quarantine=False)
    assert s.removed == 0 and s.quarantine_run is None
    assert list((state / "q").iterdir()) == []


def test_latest_run_sorts_by_creation_time(state):
    root = state / "q"
    for rid, created in (("20261119-120000-99999-aaaa", 2.0),
                         ("20261119-120000-100000-bbbb", 1.0)):
        (root / rid).mkdir(parents=True)
        (root / rid / "manifest.json").write_text(json.dumps(
            {"run_id": rid, "created": created, "items": []}), encoding="utf-8")
    assert quarantine.latest_run() == "20261119-120000-99999-aaaa"


# -- N2: an informative machine-restore confirmation ----------------------------------------
def test_describe_shows_types_data_and_escapes(state, fake_registry, monkeypatch):
    from cleanix.core.winregistry import REG_BINARY, REG_MULTI_SZ, REG_QWORD

    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    reg = fake_registry
    long = "C:\\x\\" + "a" * 400
    reg.add_key("HKLM", FOO, {
        "Upd\u202eexe.dab": (REG_SZ, "evil.exe\r\n--flag"),
        "Long": (REG_SZ, long),
        "Bin": (REG_BINARY, bytes(range(40))),
        "Multi": (REG_MULTI_SZ, ("one", "tw\u200eo", "")),
        "Q": (REG_QWORD, 2 ** 40),
    })
    reg.add_key("HKLM", FOO + "\\Sub\u202e", {"": (REG_SZ, "default")})
    item = _item(reg, hive="HKLM")
    s = service.clean([item], Config(), dry_run=False, use_quarantine=False)
    assert s.removed == 1, s.errors
    lines = quarantine.describe_registry_entries(s.quarantine_run)
    text = "\n".join(lines)
    assert lines[0] == quarantine.MACHINE_WARNING
    assert "\u202e" not in text and "\u200e" not in text and "\r" not in text
    assert '[Upd\\u202eexe.dab] = REG_SZ "evil.exe\\u000d\\u000a--flag"' in text
    assert "Sub\\u202e [(Default)] = REG_SZ \"default\"" in text
    assert "REG_SZ \"" + long[:300] + "\u2026\" (" + str(len(long)) + " characters)" in text
    assert "REG_BINARY " + bytes(range(32)).hex(" ") + " \u2026 (40 bytes)" in text
    assert "REG_QWORD 1099511627776 (0x0000010000000000)" in text
    assert '    "one"' in lines and '    "tw\\u200eo"' in lines and '    ""' in lines


def test_describe_lists_only_entries_restore_would_touch(state, fake_registry, monkeypatch):
    reg = fake_registry
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    _foo_tree(reg, hive="HKLM")
    reg.add_key("HKLM", UNINST + r"\Bar", {"DisplayName": (REG_SZ, "Bar")})
    a, b = _item(reg, hive="HKLM"), _item(reg, hive="HKLM", key=UNINST + r"\Bar")
    run = quarantine.new_run()
    Engine([]).clean([a], dry_run=False, registry_backup=run, allow_root_items=True)
    run.store_registry(b, reg)
    run.mark_registry(b, False)
    text = "\n".join(quarantine.describe_registry_entries(run.run_id))
    assert FOO in text and "Bar" not in text


# -- N3: the final save after deletes is non-fatal --------------------------------------------
@pytest.mark.parametrize("mode", ["oserror", "conflict"])
def test_final_save_failure_is_reported_not_raised(state, fake_registry, monkeypatch, mode):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    real_new = quarantine.new_run

    def new_run():
        r = real_new()
        real_save, n = r.save, [0]

        def save():
            n[0] += 1
            if n[0] >= 2:
                if mode == "conflict":
                    raise quarantine.ManifestConflict("not this run's manifest")
                raise OSError("disk full")
            return real_save()

        r.save = save
        return r

    monkeypatch.setattr(quarantine, "new_run", new_run)
    monkeypatch.setattr(quarantine.time, "sleep", lambda s: None)
    s = service.clean([item], Config(), dry_run=False, use_quarantine=False)
    assert s.removed == 1 and not reg.key_exists("HKCU", FOO)
    assert s.quarantine_run
    assert s.undo_record_error and "the backup files are in" in s.undo_record_error
    assert history.stats()["runs"] == 1
    note = s.result.outcomes[0].error
    assert note.startswith("deleted, but")
    if mode == "conflict":
        assert "still safe" not in note and "the backup files are in" in note
    else:
        assert "cleanix restore is still safe" in note


# -- I2: machine restore needs confirmation, ownership ---------------------------------------
def _hklm_run(reg, monkeypatch):
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    _foo_tree(reg, hive="HKLM")
    item = _item(reg, hive="HKLM")
    s = service.clean([item], Config(), dry_run=False, use_quarantine=False)
    assert s.removed == 1, s.errors
    return item, s.quarantine_run


def test_hklm_restore_needs_explicit_confirmation(state, fake_registry, monkeypatch):
    from cleanix.core import regbackup

    reg = fake_registry
    item, run_id = _hklm_run(reg, monkeypatch)
    monkeypatch.setattr(regbackup, "owner_is_current_user", lambda p: True)
    res = quarantine.restore(run_id)  # admin, but not confirmed
    (_orig, reason), = res["failed"]
    assert "explicit confirmation" in reason and run_id in reason
    assert "Administrator terminal" not in reason
    assert not reg.key_exists("HKLM", FOO)
    lines = quarantine.describe_registry_entries(run_id)
    assert lines == quarantine.Quarantine.describe_registry_entries(run_id)
    assert lines[0] == quarantine.MACHINE_WARNING
    assert "HKLM\\" + FOO in lines
    assert "HKLM\\" + FOO + ' [DisplayName] = REG_SZ "Foo App"' in lines
    assert "HKLM\\" + FOO + " [EstimatedSize] = REG_DWORD 42 (0x0000002a)" in lines
    assert "HKLM\\" + FOO + r"\Sub\Deeper [B] = REG_DWORD 1 (0x00000001)" in lines
    # Not confirmed, not admin: the Administrator-terminal advice as before.
    monkeypatch.setattr(winenv, "is_admin", lambda: False)
    (_orig, reason), = quarantine.restore(run_id)["failed"]
    assert f"cleanix restore {run_id}" in reason and "reg import" in reason
    monkeypatch.setattr(winenv, "is_admin", lambda: True)
    res = quarantine.restore(run_id, allow_machine_restore=True)
    assert res == {"restored": [item.reg.display], "failed": []}
    assert reg.key_exists("HKLM", FOO + r"\Sub\Deeper")


@pytest.mark.parametrize("owner", [None, False])
def test_hklm_restore_refused_when_owner_not_verified(state, fake_registry, monkeypatch, owner):
    from cleanix.core import regbackup

    reg = fake_registry
    _it, run_id = _hklm_run(reg, monkeypatch)
    monkeypatch.setattr(regbackup, "owner_is_current_user", lambda p: owner)
    reg.calls.clear()
    res = quarantine.restore(run_id, allow_machine_restore=True)
    (_orig, reason), = res["failed"]
    assert reason.startswith("refused")
    assert _writes(reg) == [] and not reg.key_exists("HKLM", FOO)


def test_hkcu_restore_refused_only_for_foreign_owner(state, fake_registry, monkeypatch):
    from cleanix.core import regbackup

    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    s = service.clean([item], Config(), dry_run=False, use_quarantine=False)
    monkeypatch.setattr(regbackup, "owner_is_current_user", lambda p: False)
    res = quarantine.restore(s.quarantine_run)
    assert res["failed"][0][1].startswith("refused: the backup file is not owned")
    monkeypatch.setattr(regbackup, "owner_is_current_user", lambda p: None)
    res = quarantine.restore(s.quarantine_run)  # unknown owner: HKCU as today
    assert res == {"restored": [item.reg.display], "failed": []}


class _Sec:
    def __init__(self, owner, user="S-1-5-21-1", admins=None, boom=False):
        self.owner, self.user, self.admins, self.boom = owner, user, admins, boom

    def file_owner(self, path):
        if self.boom:
            raise OSError("ctypes failed")
        return self.owner

    def user_sid(self):
        return self.user

    def admins_sid_if_member(self):
        return self.admins


@pytest.mark.parametrize("sec, expected", [
    (_Sec("S-1-5-21-1"), True),
    (_Sec("S-1-5-21-2"), False),
    (_Sec("S-1-5-32-544", admins="S-1-5-32-544"), True),
    (_Sec("S-1-5-32-544", admins=None), False),
    (_Sec(None), None),
    (_Sec("S-1-5-21-1", user=None), None),
    (_Sec("S-1-5-21-1", boom=True), None),
])
def test_owner_is_current_user_windows_mocked(monkeypatch, tmp_path, sec, expected):
    from cleanix.core import regbackup

    monkeypatch.setattr(regbackup.sys, "platform", "win32")
    monkeypatch.setattr(regbackup, "_win_security", lambda: sec)
    assert regbackup.owner_is_current_user(tmp_path / "f") is expected


def test_owner_is_current_user_posix_mocked(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from cleanix.core import regbackup

    monkeypatch.setattr(regbackup.sys, "platform", "linux")
    monkeypatch.setattr(regbackup.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(regbackup, "_lstat", lambda p: SimpleNamespace(st_uid=1000))
    assert regbackup.owner_is_current_user(tmp_path / "f") is True
    monkeypatch.setattr(regbackup, "_lstat", lambda p: SimpleNamespace(st_uid=0))
    assert regbackup.owner_is_current_user(tmp_path / "f") is False


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="real Windows security API")
def test_owner_is_current_user_windows_real(tmp_path):
    from cleanix.core import regbackup

    f = tmp_path / "mine.json"
    f.write_text("{}", encoding="ascii")
    assert regbackup.owner_is_current_user(f) is True


# -- I3: pin the delete path ---------------------------------------------------------------------
def test_link_planted_between_target_and_leaf_refused(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    real = reg.can_delete

    def plant(hive, key, value):
        r = real(hive, key, value)
        if key == FOO:  # the last preflight call, after the step-2 snapshot
            reg.add_key("HKCU", FOO + r"\Sub", link=True)
        return r

    reg.can_delete = plant
    with pytest.raises(regclean.RegistryChanged):
        regclean.delete_target(reg, "win_reg_uninstall", item.reg, is_admin=False)
    assert _writes(reg) == []


def test_ancestor_changed_between_deletes_stops(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    real = reg.delete_key

    def then_link_ancestor(hive, key):
        real(hive, key)
        reg.add_key("HKCU", UNINST, link=True)

    reg.delete_key = then_link_ancestor
    with pytest.raises(regclean.PartialDelete):
        regclean.delete_target(reg, "win_reg_uninstall", item.reg, is_admin=False)
    assert [c[2] for c in reg.calls if c[0] == "delete_key"] == [FOO + r"\Sub\Deeper"]


def test_value_changed_just_before_delete_value(state, fake_registry):
    reg = fake_registry
    reg.add_key("HKCU", RUN, {"GoneApp": (REG_SZ, r"C:\Gone\app.exe")})
    item = _item(reg, cid="win_reg_startup", key=RUN, value="GoneApp")
    real = reg.can_delete

    def change(hive, key, value):
        r = real(hive, key, value)
        reg.add_key("HKCU", RUN, {"GoneApp": (REG_SZ, r"C:\Live\app.exe")})
        return r

    reg.can_delete = change
    with pytest.raises(regclean.RegistryChanged):
        regclean.delete_target(reg, "win_reg_startup", item.reg, is_admin=False)
    assert _writes(reg) == []


def test_value_preflight_denied(state, fake_registry):
    reg = fake_registry
    reg.add_key("HKCU", RUN, {"GoneApp": (REG_SZ, r"C:\Gone\app.exe")}, deny_delete=True)
    item = _item(reg, cid="win_reg_startup", key=RUN, value="GoneApp")
    with pytest.raises(AccessDenied):
        regclean.delete_target(reg, "win_reg_startup", item.reg, is_admin=False)
    assert not [c for c in reg.calls if c[0] == "delete_value"]


def test_two_items_different_outcomes_exact_flags(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    reg.add_key("HKCU", UNINST + r"\Bar", {"DisplayName": (REG_SZ, "Bar")})
    a, b = _item(reg), _item(reg, key=UNINST + r"\Bar")
    run = quarantine.new_run()

    class SecondRacy:
        run_id = run.run_id

        def before_delete(self, it, backend):
            run.store_registry(it, backend)
            if it is b:
                reg.add_key("HKCU", UNINST + r"\Bar", {"X": (REG_SZ, "new")})

        def after_delete(self, it, deleted):
            run.mark_registry(it, deleted)

    res = Engine([]).clean([a, b], dry_run=False, registry_backup=SecondRacy())
    assert [o.removed for o in res.outcomes] == [True, False]
    assert [e["deleted"] for e in _manifest(run.dir)["items"]] == [True, False]
    assert [e["deleted"] for e in run.items] == [True, False]
    res = quarantine.restore(run.run_id)
    assert res == {"restored": [a.reg.display], "failed": []}
    assert reg.key_exists("HKCU", FOO + r"\Sub\Deeper")


def test_unknown_deleted_state_is_restored(state, fake_registry):
    """``deleted: None`` (a crash or a failed after_delete) still restores."""
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    run = quarantine.new_run()
    run.store_registry(item, reg)
    regclean.delete_target(reg, "win_reg_uninstall", item.reg, is_admin=False)
    assert _manifest(run.dir)["items"][0]["deleted"] is None
    res = quarantine.restore(run.run_id)
    assert res == {"restored": [item.reg.display], "failed": []}


def test_failure_after_target_gone_is_partial_not_intact(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    run = quarantine.new_run()
    real = reg.delete_key

    def delete_then_fail(hive, key):
        real(hive, key)
        if key == FOO:
            raise RegistryError("reported failure after deleting")

    reg.delete_key = delete_then_fail
    o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert o.error.startswith("partially deleted")
    assert _manifest(run.dir)["items"][0]["deleted"] is True


# -- minors ---------------------------------------------------------------------------------------
def test_entry_gone_since_scan_is_changed_not_blocked(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    for k in (FOO + r"\Sub\Deeper", FOO + r"\Sub", FOO):
        reg.delete_key("HKCU", k)
    run = quarantine.new_run()
    o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert o.error == "changed since the scan; scan again"
    assert run.items == []


def test_mark_save_failure_is_reported_and_consistent(state, fake_registry, monkeypatch):
    reg = fake_registry
    _foo_tree(reg)
    item = _item(reg)
    run = quarantine.new_run()
    real_save, n = run.save, [0]

    def save():
        n[0] += 1
        if n[0] >= 2:  # every save after the backup entry fails
            raise OSError("disk full")
        return real_save()

    monkeypatch.setattr(run, "save", save)
    o = Engine([]).clean([item], dry_run=False, registry_backup=run).outcomes[0]
    assert o.removed is True
    assert o.error.startswith("deleted, but the undo record could not be updated")
    assert "cleanix restore is still safe" in o.error
    assert n[0] == 3  # the result save was tried twice
    assert run.items[0]["deleted"] is None
    assert _manifest(run.dir)["items"][0]["deleted"] is None
    assert not reg.key_exists("HKCU", FOO)


def test_non_dict_manifest_items_do_not_crash(state):
    root = state / "q" / "r1"
    root.mkdir(parents=True)
    (root / "manifest.json").write_text(json.dumps({
        "run_id": "r1", "created": 1.0,
        "items": ["x", 5, {"type": "registry"}, {"type": "registry", "deleted": False}],
    }), encoding="utf-8")
    row, = quarantine.list_runs()
    assert row["count"] == 4 and row["registry"] == 2 and row["size"] == 0
    res = quarantine.restore("r1")
    assert res["restored"] == []
    reasons = [r for _o, r in res["failed"]]
    assert len(reasons) == 3  # the deleted:False entry is skipped
    assert reasons[0] == reasons[1] == "invalid manifest entry"
    assert reasons[2].startswith("not a registry backup file")
    (root / "manifest.json").write_text("[1, 2]", encoding="utf-8")
    assert quarantine.list_runs() == []


def test_list_runs_removed_count(state, fake_registry):
    reg = fake_registry
    _foo_tree(reg)
    reg.add_key("HKCU", UNINST + r"\Bar", {"DisplayName": (REG_SZ, "Bar")})
    a, b = _item(reg), _item(reg, key=UNINST + r"\Bar")
    run = quarantine.new_run()
    Engine([]).clean([a], dry_run=False, registry_backup=run)
    run.store_registry(b, reg)
    run.mark_registry(b, False)
    row, = quarantine.list_runs()
    assert row["registry"] == 2 and row["removed_count"] == 1
