"""Task 11: backed-up registry deletion, undo through quarantine.

Every test uses the in-memory FakeRegistry (or WinRegBackend over the fake
``winreg`` module from test_winreg_backend); the real registry is never
touched (the autouse ForbiddenBackend fixture enforces that).
"""

from __future__ import annotations

import json
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
    run.dir.mkdir(parents=True)
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
    assert _writes(reg) == []
    assert all(c[0] in ("subkeys", "values", "key_exists", "is_link", "can_delete")
               for c in reg.calls)
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
    summary = service.clean([item], Config(), dry_run=False, use_quarantine=False,
                            record_history=False, registry_backup_elsewhere=True,
                            )
    assert summary.removed == 1, summary.errors
    assert summary.quarantine_run is None
    assert not (state / "q").exists() and not (state / "state").exists()
    assert not reg.key_exists("HKLM", FOO)


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
                     "size": 5, "registry": 0, "registry_admin": 0}]
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


def test_verify_only_sink_is_noop(fake_registry):
    sink = regclean.VerifyOnlySink()
    _foo_tree(fake_registry)
    item = _item(fake_registry)
    fake_registry.calls.clear()
    sink.before_delete(item, fake_registry)
    sink.after_delete(item, True)
    assert fake_registry.calls == []
