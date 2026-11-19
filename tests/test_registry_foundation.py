"""Foundation of the registry cleanup: item model, backend protocol, safety
rules, snapshots, catalog/copy and the opt-in detector stubs."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from _fakereg import FakeRegistry
from cleanix.config import Config
from cleanix.core import catalog, curation, regsafety, regsnap, winregistry
from cleanix.core.models import (
    CleanableItem,
    CleanerReport,
    ItemKind,
    RegTarget,
    ScanResult,
    item_key,
    item_target,
)
from cleanix.core.regsafety import check_target, match_form, normalize
from cleanix.core.regsnap import KeySnap, SnapshotError
from cleanix.core.winregistry import (
    REG_BINARY,
    REG_DWORD,
    REG_DWORD_BIG_ENDIAN,
    REG_EXPAND_SZ,
    REG_MULTI_SZ,
    REG_NONE,
    REG_QWORD,
    REG_SZ,
    RegValue,
)

REPO = Path(__file__).resolve().parent.parent
CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
CVW = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion"


def reg_item(**kw):
    base = dict(
        cleaner_id="win_reg_uninstall",
        description="d",
        kind=ItemKind.REGISTRY,
        reg=RegTarget("HKCU", CV + r"\Uninstall\Foo", None, "fp"),
    )
    base.update(kw)
    return CleanableItem(**base)


# -- model -------------------------------------------------------------------
def test_registry_item_validation():
    assert reg_item().reg.hive == "HKCU"
    with pytest.raises(ValueError):
        reg_item(reg=None)
    with pytest.raises(ValueError):
        reg_item(reg=RegTarget("HKCR", "SOFTWARE\\x", None, "fp"))
    with pytest.raises(ValueError):
        reg_item(reg=RegTarget("HKCU", "SOFTWARE\\x", None, ""))
    with pytest.raises(ValueError):
        reg_item(reg=RegTarget("HKCU", "", None, "fp"))
    with pytest.raises(ValueError):
        reg_item(path="C:\\x")
    with pytest.raises(ValueError):
        reg_item(command=["x"])
    with pytest.raises(ValueError):
        CleanableItem(
            cleaner_id="x", description="d", path="C:\\x",
            reg=RegTarget("HKCU", "SOFTWARE\\x", None, "fp"),
        )


def test_item_key_registry_unique():
    a = reg_item(reg=RegTarget("HKLM", r"SOFTWARE\a|b", "c", "fp"))
    b = reg_item(reg=RegTarget("HKLM", r"SOFTWARE\a", "b|c", "fp"))
    c = reg_item(reg=RegTarget("HKLM", r"SOFTWARE\a|b", "c", "other"))
    assert len({item_key(a), item_key(b), item_key(c)}) == 3
    assert item_key(a).startswith("win_reg_uninstall|reg|")


def test_item_target_and_display():
    t = RegTarget("HKLM", r"SOFTWARE\X", "v", "fp")
    assert t.display == r"HKLM\SOFTWARE\X [v]"
    assert RegTarget("HKLM", r"SOFTWARE\X", None, "fp").display == r"HKLM\SOFTWARE\X"
    assert item_target(reg_item(reg=t)) == r"HKLM\SOFTWARE\X [v]"
    assert item_target(CleanableItem("x", "d", path="/p")) == "/p"
    assert item_target(
        CleanableItem("x", "d", kind=ItemKind.COMMAND, command=["a", "b"])
    ) == "a b"


# -- regsafety ---------------------------------------------------------------
def test_normalize_and_match_form():
    assert match_form("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Microsoft") == (
        match_form("HKLM", r"SOFTWARE\Microsoft")
    )
    assert normalize("HKEY_CURRENT_USER", r"Software\A") == ("HKCU", ("software", "a"))
    assert match_form("HKLM", r"SOFTWARE\Classes\WOW6432Node\x") == (
        "software", "classes", "x",
    )
    for hive, key in [
        ("HKEY_CLASSES_ROOT", r"SOFTWARE\a"),
        ("HKU", r"SOFTWARE\a"),
        ("HKLM", r"SYSTEM\CurrentControlSet"),
        ("HKLM", r"SOFTWARE\\a"),
        ("HKLM", r"SOFTWARE\..\SYSTEM"),
        ("HKLM", r"SOFTWARE\a "),
        ("HKLM", r"SOFTWARE\.\a"),
        ("HKLM", "SOFTWARE\\a\x01"),
        ("HKLM", ""),
    ]:
        with pytest.raises(ValueError):
            normalize(hive, key)


def _t(hive, key, value=None):
    return RegTarget(hive, key, value, "")


def _variants(key):
    """key as given, upper-cased, lower-cased and with a WOW6432Node alias."""
    out = [key, key.upper(), key.lower()]
    if key.upper().startswith("SOFTWARE\\") and "WOW6432NODE" not in key.upper():
        out.append("SOFTWARE\\WOW6432Node\\" + key.split("\\", 1)[1])
    return out


def test_check_target_allowlist():
    ok = check_target("win_reg_uninstall", _t("HKCU", CV + r"\Uninstall\Foo"))
    assert ok is None
    for k in _variants(CV + r"\Uninstall\Foo"):
        assert check_target("win_reg_uninstall", _t("HKLM", k)) is None, k
    assert check_target("win_reg_uninstall", _t("HKLM", CVW + r"\Uninstall\Foo")) is None
    assert check_target("win_reg_startup", _t("HKCU", CV + r"\Run", "Foo")) is None
    assert check_target("win_reg_shared_dlls", _t("HKLM", CV + r"\SharedDLLs", "C:\\a.dll")) is None
    assert check_target("win_reg_file_assoc", _t("HKCU", r"SOFTWARE\Classes\MyApp.File")) is None
    assert check_target(
        "win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\Applications\foo.exe")
    ) is None
    assert check_target("win_reg_app_paths", _t("HKLM", CV + r"\App Paths\foo.exe")) is None

    refused = [
        ("win_reg_uninstall", _t("HKCU", CV + r"\Uninstall")),                    # container
        ("win_reg_uninstall", _t("HKCU", CV + r"\Uninstall\Foo\Sub")),            # too deep
        ("win_reg_startup", _t("HKCU", CV + r"\Uninstall\Foo")),                  # wrong detector
        ("win_reg_uninstall", _t("HKCU", CV + r"\Uninstall\Foo", "v")),           # value in key-container
        ("win_reg_startup", _t("HKCU", CV + r"\Run")),                            # key in value-container
        ("win_reg_startup", _t("HKCU", CV + r"\Run", "")),                        # empty value name
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\CLSID")),
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\CLSID\{x}")),
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\.txt")),
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\Applications")),
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\Microsoft.Foo")),
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\Interface")),
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\Installer")),
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\exefile")),
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\AppX123")),
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\ms-settings")),
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\Word.Document.12")),
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\*")),
        ("win_reg_file_assoc", _t("HKLM", r"SOFTWARE\Classes\Directory")),
        ("win_reg_startup", _t("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Run", "x")),
        ("win_reg_startup", _t("HKLM", CV + r"\Policies\Explorer\Run", "x")),
        ("win_reg_uninstall", _t("HKLM", r"SYSTEM\CurrentControlSet\Services\Foo")),
        ("win_reg_uninstall", _t("HKCR", CV + r"\Uninstall\Foo")),
        ("win_reg_uninstall", _t("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Uninstall\Foo")),
        ("win_reg_uninstall", _t("HKLM", CV + r"\Installer\UserData\Foo")),
        ("nope", _t("HKCU", CV + r"\Uninstall\Foo")),
    ]
    for cid, tgt in refused:
        for k in _variants(tgt.key):
            reason = check_target(cid, RegTarget(tgt.hive, k, tgt.value, ""))
            assert reason, (cid, tgt, k)
            assert isinstance(reason, str)


def test_check_target_links(fake_registry: FakeRegistry):
    base = CV + r"\Uninstall"
    fake_registry.add_key("HKLM", base + r"\Foo")
    t = _t("HKLM", base + r"\Foo")
    assert check_target("win_reg_uninstall", t, fake_registry) is None
    fake_registry.add_key("HKLM", base + r"\Bar", link=True)
    assert check_target("win_reg_uninstall", _t("HKLM", base + r"\Bar"), fake_registry)
    # A link in the middle of the path (above the container) is refused too.
    fake_registry.add_key("HKCU", base + r"\Foo")
    assert check_target("win_reg_uninstall", _t("HKCU", base + r"\Foo"), fake_registry) is None
    fake_registry.add_key("HKCU", r"SOFTWARE\Microsoft", link=True)
    assert check_target("win_reg_uninstall", _t("HKCU", base + r"\Foo"), fake_registry)
    # The HKCU\SOFTWARE\Classes anchor is trusted.
    fake_registry.add_key("HKCU", r"SOFTWARE\Classes", link=True)
    fake_registry.add_key("HKCU", r"SOFTWARE\Classes\MyApp.File")
    assert check_target(
        "win_reg_file_assoc", _t("HKCU", r"SOFTWARE\Classes\MyApp.File"), fake_registry
    ) is None


# -- regsnap -----------------------------------------------------------------
def _tree(reg: FakeRegistry, key=CV + r"\Uninstall\Foo", order=1):
    vals = {
        "DisplayName": (REG_SZ, "Foo"),
        "Blob": (REG_BINARY, b"\x00\x01\x02"),
        "N": (REG_DWORD, 5),
    }
    items = list(vals.items())
    if order < 0:
        items.reverse()
    reg.add_key("HKCU", key, dict(items))
    sub = {"x": (REG_SZ, "1")}
    reg.add_key("HKCU", key + r"\Sub", sub)
    return RegTarget("HKCU", key, None, "")


def test_snapshot_fingerprint_stable_and_sensitive():
    def fp(mutate=None, order=1):
        reg = FakeRegistry()
        t = _tree(reg, order=order)
        if mutate:
            mutate(reg)
        return regsnap.fingerprint(t, regsnap.snapshot(reg, t))

    base = fp()
    assert base == fp()
    assert re.fullmatch(r"[0-9a-f]{64}", base)
    assert fp(order=-1) == base

    key = CV + r"\Uninstall\Foo"
    assert fp(lambda r: r.add_key("HKCU", key, {"Blob": (REG_BINARY, b"\x00\x01\x03")})) != base
    assert fp(lambda r: r.add_key("HKCU", key, {"N": (REG_QWORD, 5)})) != base
    # Re-add a value with another case of the name (case-insensitive registry).
    def recase(r):
        r.delete_value("HKCU", key, "N")
        r.set_value("HKCU", key, RegValue("n", REG_DWORD, 5))
    assert fp(recase) != base
    assert fp(lambda r: r.add_key("HKCU", key + r"\Sub2")) != base


def test_snapshot_value_target():
    reg = FakeRegistry()
    reg.add_key("HKCU", CV + r"\Run", {"App": (REG_SZ, "C:\\a.exe")})
    t = RegTarget("HKCU", CV + r"\Run", "app", "")
    snap = regsnap.snapshot(reg, t)
    assert isinstance(snap, RegValue) and snap.data == "C:\\a.exe"
    with pytest.raises(SnapshotError):
        regsnap.snapshot(reg, RegTarget("HKCU", CV + r"\Run", "missing", ""))
    assert regsnap.fingerprint(t, snap) != regsnap.fingerprint(
        RegTarget("HKCU", CV + r"\Run", "other", ""), snap
    )


def test_snapshot_limits_and_links():
    reg = FakeRegistry()
    base = CV + r"\Uninstall\Big"
    reg.add_key("HKCU", base)
    for i in range(255):
        reg.add_key("HKCU", f"{base}\\k{i}")
    t = RegTarget("HKCU", base, None, "")
    regsnap.snapshot(reg, t)  # 256 keys: fine
    reg.add_key("HKCU", f"{base}\\k255")
    with pytest.raises(SnapshotError):
        regsnap.snapshot(reg, t)  # 257

    reg2 = FakeRegistry()
    reg2.add_key("HKCU", base)
    reg2.add_key("HKCU", base + r"\lnk", link=True)
    with pytest.raises(SnapshotError):
        regsnap.snapshot(reg2, t)

    reg3 = FakeRegistry()
    reg3.add_key("HKCU", base, {"a": (REG_SZ, "x")}, deny_read=True)
    with pytest.raises(SnapshotError):
        regsnap.snapshot(reg3, t)

    reg4 = FakeRegistry()
    with pytest.raises(SnapshotError):
        regsnap.snapshot(reg4, t)  # missing

    reg5 = FakeRegistry()
    reg5.add_key("HKCU", base, {"big": (REG_BINARY, b"x" * (regsnap.MAX_BYTES + 1))})
    with pytest.raises(SnapshotError):
        regsnap.snapshot(reg5, t)

    reg6 = FakeRegistry()
    reg6.add_key("HKCU", base, {f"v{i}": (REG_DWORD, i) for i in range(regsnap.MAX_VALUES + 1)})
    with pytest.raises(SnapshotError):
        regsnap.snapshot(reg6, t)


def test_jsonable_roundtrip_all_types():
    vals = (
        RegValue("none", REG_NONE, b""),
        RegValue("sz", REG_SZ, 'a"b\\c\r\nd\u00e9\u4e2d'),
        RegValue("exp", REG_EXPAND_SZ, "%TEMP%\\x"),
        RegValue("bin", REG_BINARY, bytes(range(256))),
        RegValue("dw", REG_DWORD, 0xFFFFFFFF),
        RegValue("dwbe", REG_DWORD_BIG_ENDIAN, 1),
        RegValue("multi", REG_MULTI_SZ, ("a", "", "b")),
        RegValue("qw", REG_QWORD, 2**63),
        RegValue("odd", 0x20, b"\x01\x02"),
        RegValue("", REG_SZ, "default"),
    )
    snap = KeySnap("root", vals, (KeySnap("child", (vals[1],), ()),))
    out = regsnap.from_jsonable(regsnap.to_jsonable(snap))
    assert out == snap
    import json
    assert regsnap.from_jsonable(json.loads(json.dumps(regsnap.to_jsonable(snap)))) == snap
    for v in vals:
        assert regsnap.from_jsonable(regsnap.to_jsonable(v)) == v


def test_read_values_keyed_casefolded():
    reg = FakeRegistry()
    reg.add_key("HKLM", CV + r"\SharedDLLs", {"C:\\A.dll": (REG_DWORD, 1)})
    out = regsnap.read_values(reg, "HKLM", CV + r"\SharedDLLs")
    assert list(out) == ["c:\\a.dll"]
    assert out["c:\\a.dll"].name == "C:\\A.dll"


# -- catalog / curation ------------------------------------------------------
def test_registry_ids_catalog_and_copy():
    assert catalog.REGISTRY_IDS == (
        "win_reg_uninstall", "win_reg_app_paths", "win_reg_file_assoc",
        "win_reg_startup", "win_reg_shared_dlls",
    )
    assert catalog.CATEGORIES["registry"] == "Registry leftovers"
    infos = {i.id: i for i in catalog.list_cleaners(Config(), include_unsupported=True)}
    for cid in catalog.REGISTRY_IDS:
        assert catalog.category_of(cid) == "registry"
        assert cid in curation.COPY
        info = infos[cid]
        for hive in ("HKCU", "HKLM"):
            it = reg_item(
                cleaner_id=cid, requires_root=hive == "HKLM",
                reg=RegTarget(hive, CV + r"\X\a", None, "fp"),
            )
            assert not catalog.preselect(it, info)
            assert curation.safety_of(it, info) is curation.Safety.REVIEW
            assert curation.safety_of(it, None) is curation.Safety.REVIEW
            assert not curation.is_empty(it)
    assert "registry" in catalog._NEVER_PRESELECT
    assert curation.display_label(reg_item(description=""), None) == (
        "HKCU\\" + CV + "\\Uninstall\\Foo"
    )


def test_build_groups_keeps_zero_size_registry():
    infos = {i.id: i for i in catalog.list_cleaners(Config(), include_unsupported=True)}
    rep = CleanerReport("win_reg_uninstall", "n", "d", items=[reg_item()])
    groups = curation.build_groups(ScanResult([rep]), infos)
    assert len(groups) == 1
    assert groups[0].shown and not groups[0].zero
    assert groups[0].safety is curation.Safety.REVIEW
    assert groups[0].title == "Dead uninstall entries"


def test_engine_never_runs_registry_as_command(monkeypatch):
    from cleanix.core import engine as eng

    def boom(*a, **k):
        raise AssertionError("run_command must not be called")

    monkeypatch.setattr(eng, "run_command", boom)
    e = eng.Engine([])
    res = e.clean([reg_item()], dry_run=True, allow_root_items=True)
    o = res.outcomes[0]
    assert o.removed is False and o.error is None and o.freed == 0
    res = e.clean([reg_item()], dry_run=False, allow_root_items=True)
    o = res.outcomes[0]
    assert o.removed is False
    assert o.error == "registry entries are removed only with a backup"
    bogus = reg_item()
    object.__setattr__(bogus, "kind", "weird")  # dataclass is not frozen; plain set
    res = e.clean([bogus], dry_run=False, allow_root_items=True)
    assert res.outcomes[0].error == "unknown item kind"


# -- detectors ---------------------------------------------------------------
def test_stub_detectors_registered_opt_in():
    from cleanix.cleaners import ALL_CLEANERS
    from cleanix.cleaners.base import SCOPE_SYSTEM
    from cleanix.core.platform import WINDOWS
    from cleanix.core.registry import build_cleaners

    by_id = {c.id: c for c in ALL_CLEANERS}
    names = {
        "win_reg_uninstall": "Registry: dead uninstall entries",
        "win_reg_app_paths": "Registry: dead App Paths",
        "win_reg_file_assoc": "Registry: dead file-type handlers",
        "win_reg_startup": "Registry: dead startup entries",
        "win_reg_shared_dlls": "Registry: SharedDLLs counts for missing files",
    }
    for cid in catalog.REGISTRY_IDS:
        c = by_id[cid]
        assert c.default_enabled is False
        assert c.scope == SCOPE_SYSTEM
        assert c.platforms == (WINDOWS,)
        assert c.safe_default is False
        assert c.requires_root is False
        assert c.name == names[cid]
    assert [c.id for c in ALL_CLEANERS if c.id in by_id and c.id.startswith("win_reg_")] == list(
        catalog.REGISTRY_IDS
    )
    default_ids = {c.id for c in build_cleaners(Config())}
    assert not default_ids & set(catalog.REGISTRY_IDS)


def test_detector_base_builds_items(fake_registry):
    from cleanix.cleaners.winreg_base import Finding, RegistryDetector
    from cleanix.core.regtargets import DetectorContext

    base = CV + r"\Uninstall"
    fake_registry.add_key("HKCU", base + r"\A", {"v": (REG_SZ, "1")})
    fake_registry.add_key("HKLM", base + r"\B")
    fake_registry.add_key("HKLM", base + r"\Denied", {"x": (REG_SZ, "1")}, deny_read=True)
    fake_registry.add_key("HKLM", base + r"\Deep\Child")

    class Det(RegistryDetector):
        id = "win_reg_uninstall"
        name = "t"
        description = "t"

        def context(self):
            return DetectorContext({}, None, "C:\\Users", "C:\\Windows")

        def entries(self, container, backend, ctx):
            if (container.hive, container.key) not in (("HKCU", base), ("HKLM", base)):
                return
            if container.hive == "HKCU":
                yield Finding(RegTarget("HKCU", base + r"\A", None, ""), "A dead", "ev A")
            else:
                yield Finding(RegTarget("HKLM", base + r"\B", None, ""), "B dead", "ev B")
                yield Finding(RegTarget("HKLM", base + r"\Denied", None, ""), "x", "x")
                # refused by regsafety (the container itself)
                yield Finding(RegTarget("HKLM", base, None, ""), "c", "c")

    items = Det(Config()).scan().items
    assert [i.reg.key.rsplit("\\", 1)[1] for i in items] == ["A", "B"]
    a, b = items
    assert a.requires_root is False and b.requires_root is True
    assert a.reg.fingerprint and b.reg.fingerprint and a.reg.fingerprint != b.reg.fingerprint
    assert a.kind is ItemKind.REGISTRY and a.size == 0 and a.hint == "ev A"
    assert a.description == "A dead"
    expect = regsnap.fingerprint(a.reg, regsnap.snapshot(fake_registry, a.reg))
    assert a.reg.fingerprint == expect


def test_forbidden_backend_active(_no_real_registry):
    with pytest.raises(AssertionError):
        winregistry.get_backend().subkeys("HKCU", "SOFTWARE")
    assert _no_real_registry.calls
    _no_real_registry.calls.clear()


def test_detectors_unavailable_off_windows(monkeypatch, _no_real_registry):
    from cleanix.cleaners.winreg_uninstall import WinRegUninstall

    winregistry.set_backend(None)
    monkeypatch.setattr(sys, "platform", "linux")
    # the forbidden backend stays installed as the lazily built "real" one
    assert winregistry._real is _no_real_registry
    rep = WinRegUninstall(Config()).scan()
    assert rep.skipped_reason == "only available on Windows"
    assert rep.items == []
    assert not _no_real_registry.calls
    with pytest.raises(winregistry.RegistryUnavailable):
        winregistry.get_backend().subkeys("HKCU", "SOFTWARE")


@pytest.mark.skipif(sys.platform != "win32", reason="lazy real backend is Windows only")
def test_no_override_cannot_reach_real_registry(_no_real_registry):
    winregistry.set_backend(None)
    with pytest.raises(AssertionError):
        winregistry.get_backend().subkeys("HKCU", "SOFTWARE")
    assert _no_real_registry.calls
    _no_real_registry.calls.clear()


def test_core_imports_without_winreg():
    code = (
        "import sys; sys.modules['winreg'] = None\n"
        "import cleanix.core.winregistry, cleanix.core.regsafety, "
        "cleanix.core.regsnap, cleanix.core.regtargets, cleanix.cleaners\n"
        "from cleanix.core import winregistry\n"
        "assert 'winreg' not in [m for m, v in sys.modules.items() if v is not None]\n"
    )
    env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO, env=env,
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr


def test_winreg_imported_only_in_backend_module():
    pat = re.compile(
        r"^\s*import\s+[^\n#]*\bwinreg\b|^\s*from\s+winreg\b"
        r"|import_module\(\s*['\"]winreg|__import__\(\s*['\"]winreg",
        re.M,
    )
    for sample in (
        "import os, winreg", "import winreg as w", "from winreg import X",
        'importlib.import_module("winreg")', "__import__('winreg')",
    ):
        assert pat.search(sample), sample
    assert not pat.search("import winregistry")
    hits = [
        p.relative_to(REPO).as_posix()
        for p in (REPO / "cleanix").rglob("*.py")
        if pat.search(p.read_text(encoding="utf-8"))
    ]
    assert set(hits) == {"cleanix/core/winregistry_win.py"}


# -- fix round 1 -------------------------------------------------------------
def test_wow6432node_cannot_be_a_file_assoc_entry():
    for hive in ("HKCU", "HKLM"):
        for name in ("Wow6432Node", "WOW6432NODE", "wow6432node"):
            for key in (
                rf"SOFTWARE\Classes\{name}",
                rf"SOFTWARE\Classes\{name}\{name}",
                rf"SOFTWARE\{name}\Classes",
                rf"SOFTWARE\Classes\Applications\{name}",
                rf"SOFTWARE\Classes\{name}\Foo",
            ):
                assert check_target("win_reg_file_assoc", _t(hive, key)), (hive, key)
    assert check_target(
        "win_reg_uninstall",
        _t("HKLM", r"SOFTWARE\Wow6432Node\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Foo"),
    )


def test_hive_spelling_is_exact(fake_registry):
    key = CV + r"\Uninstall\Foo"
    fake_registry.add_key("HKCU", key, link=True)
    for hive in ("hkcu", "HKEY_CURRENT_USER", "HKCR", "", "Hkcu"):
        assert check_target("win_reg_uninstall", _t(hive, key), fake_registry), hive
        assert check_target("win_reg_uninstall", _t(hive, key)), hive
    assert check_target("win_reg_uninstall", _t("HKCU", key), fake_registry)


def test_fake_registry_is_strict(fake_registry):
    with pytest.raises(winregistry.KeyMissing):
        fake_registry.is_link("HKCU", r"SOFTWARE\nope")
    with pytest.raises(ValueError):
        fake_registry.add_key("HKCR", r"SOFTWARE\x")
    with pytest.raises(ValueError):
        fake_registry.key_exists("hkcu", r"SOFTWARE\x")


def test_one_bad_finding_does_not_abort_scan(fake_registry, monkeypatch):
    from cleanix.cleaners.winreg_base import Finding, RegistryDetector
    from cleanix.core.regtargets import DetectorContext

    base = CV + r"\Uninstall"
    for n in ("A", "B"):
        fake_registry.add_key("HKCU", base + "\\" + n)

    class Det(RegistryDetector):
        id = "win_reg_uninstall"
        name = description = "t"

        def context(self):
            return DetectorContext({}, None, r"C:\Users", r"C:\Windows")

        def entries(self, container, backend, ctx):
            if (container.hive, container.key) == ("HKCU", base):
                yield Finding(RegTarget("hkcu", base + r"\A"), "bad hive", "")
                yield Finding(RegTarget("HKCU", base + r"\A"), "A", "")
                yield Finding(RegTarget("HKCU", base + r"\B"), "B", "")

    orig = RegistryDetector.registry_item
    seen = []

    def flaky(self, finding, fp):
        seen.append(finding.description)
        if finding.description == "A":
            raise ValueError("model refused")
        return orig(self, finding, fp)

    monkeypatch.setattr(RegistryDetector, "registry_item", flaky)
    rep = Det(Config()).scan()
    assert rep.skipped_reason is None
    assert [i.description for i in rep.items] == ["B"]
    assert seen == ["A", "B"]


def test_lookalike_characters_are_refused():
    names = [
        "CLS\u0131D",           # dotless i: upper() is I
        "Pol\u0131cies",
        "M\u0131crosoft.X",
        "Local \u017fettings",  # long s: upper() is S
        "msi.pac\u212aage",     # Kelvin sign
        "M\u0130crosoft.X",     # capital I with dot
        "\uff23\uff2c\uff33\uff29\uff24",  # fullwidth CLSID
        "Foo\u202e",
        "Foo\u200b",
    ]
    for hive in ("HKCU", "HKLM"):
        for n in names:
            assert check_target("win_reg_file_assoc", _t(hive, "SOFTWARE\\Classes\\" + n)), n
    # lookalikes above the entry name (inside the container path) are refused
    assert check_target(
        "win_reg_uninstall",
        _t("HKLM", CV.replace("Windows", "W\u0131ndows") + r"\Uninstall\Foo"),
    )
    assert check_target(
        "win_reg_uninstall",
        _t("HKCU", "\u017fOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Foo"),
    )
    assert check_target(
        "win_reg_uninstall", _t("HKCU", CV + "\\Uninstall\u212a\\Foo"),
    )
    assert check_target(
        "win_reg_startup", _t("HKLM", CV.replace("Windows", "W\u0131ndows") + r"\Run", "x")
    )
    # a normal non-ASCII app name is still fine in an Uninstall entry
    assert check_target("win_reg_uninstall", _t("HKCU", CV + "\\Uninstall\\\u4e2d\u6587")) is None


def test_value_names_validated():
    for bad in ("a\x00b", "a\nb", "x\x7f"):
        assert check_target("win_reg_startup", _t("HKCU", CV + r"\Run", bad)), repr(bad)
    assert check_target("win_reg_shared_dlls", _t("HKLM", CV + r"\SharedDLLs", "C:\\a b\\c.dll")) is None


def test_display_escapes_format_characters():
    t = RegTarget("HKCU", "SOFTWARE\\a\u202eb\u200bc\u2066", "v\u202a", "fp")
    d = t.display
    for ch in ("\u202e", "\u200b", "\u2066", "\u202a"):
        assert ch not in d
    for esc in (r"\u202e", r"\u200b", r"\u2066", r"\u202a"):
        assert esc in d
    assert RegTarget("HKCU", r"SOFTWARE\X", "v", "fp").display == r"HKCU\SOFTWARE\X [v]"


def test_snapshot_counts_list_multisz():
    class ListBackend(FakeRegistry):
        def values(self, hive, key):
            return [RegValue("m", REG_MULTI_SZ, ["x" * 600_000, "y" * 600_000])]

    reg = ListBackend()
    reg.add_key("HKCU", CV + r"\Uninstall\Big")
    t = RegTarget("HKCU", CV + r"\Uninstall\Big", None, "")
    with pytest.raises(SnapshotError):
        regsnap.snapshot(reg, t)

    class Small(FakeRegistry):
        def values(self, hive, key):
            return [RegValue("m", REG_MULTI_SZ, ["a", ""])]

    s = Small()
    s.add_key("HKCU", CV + r"\Uninstall\S")
    t2 = RegTarget("HKCU", CV + r"\Uninstall\S", None, "")
    snap = regsnap.snapshot(s, t2)
    assert snap.values[0].data == ("a", "")
    assert regsnap.fingerprint(t2, snap)


def test_stub_detectors_use_the_base_context():
    from cleanix.cleaners import ALL_CLEANERS
    from cleanix.cleaners.winreg_base import RegistryDetector

    for cls in ALL_CLEANERS:
        if cls.id in catalog.REGISTRY_IDS:
            assert cls.context is RegistryDetector.context, cls.__name__


def test_no_registry_copy_promises_a_backup_or_restore_while_undo_is_off():
    from cleanix.core import catalog, curation, regpromises

    assert regpromises.registry_undo_shipped() is False
    for cid in catalog.REGISTRY_IDS:
        c = curation.COPY[cid]
        text = " ".join(str(getattr(c, f, "")) for f in c.__dataclass_fields__).casefold()
        for word in ("backup", "restore", "undo", "back up"):
            assert word not in text, (cid, word)
