"""win_reg_shared_dlls: SharedDLLs counters for files that are provably gone."""

from __future__ import annotations

import pytest

from _fakereg import FakeProber
from cleanix.config import Config
from cleanix.cleaners import winreg_shared_dlls as mod
from cleanix.cleaners.winreg_shared_dlls import WinRegSharedDlls
from cleanix.core.models import item_key
from cleanix.core.regtargets import DetectorContext, Existence
from cleanix.core.winregistry import REG_DWORD, REG_SZ

P, M, U = Existence.PRESENT, Existence.MISSING, Existence.UNKNOWN
CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs"
CVW = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs"
ENV = {"ProgramFiles": r"C:\Program Files", "SystemRoot": r"C:\Windows"}
GONE = r"C:\Program Files\Gone\gone.dll"


def make(states, default=M):
    prober = FakeProber(states, default=default)
    ctx = DetectorContext(
        env=ENV, prober=prober, profiles_root=r"C:\Users", system_root=r"C:\Windows"
    )

    class D(WinRegSharedDlls):
        def context(self):
            return ctx

    return D(Config()), prober


def scan(reg, values, states=None, default=M, key=CV):
    reg.add_key("HKLM", key, values)
    det, prober = make(states or {}, default)
    return list(det.find_items()), prober


def test_dead_counter_listed(fake_registry):
    items, _ = scan(fake_registry, {GONE: (REG_DWORD, 1)})
    assert len(items) == 1
    it = items[0]
    assert it.description == f"Shared file counter: {GONE}"
    assert it.requires_root is True
    assert it.reg.hive == "HKLM" and it.reg.key == CV and it.reg.value == GONE
    assert GONE in it.hint and "missing" in it.hint


def test_wow6432_variant_listed(fake_registry):
    items, _ = scan(fake_registry, {GONE: (REG_DWORD, 2)}, key=CVW)
    assert len(items) == 1 and items[0].reg.key == CVW


@pytest.mark.parametrize("count", [0, 1, 7])
def test_any_count_is_dead_when_file_gone(fake_registry, count):
    items, _ = scan(fake_registry, {GONE: (REG_DWORD, count)})
    assert len(items) == 1


def test_present_file_kept(fake_registry):
    items, _ = scan(fake_registry, {GONE: (REG_DWORD, 1)}, {GONE: P})
    assert items == []


@pytest.mark.parametrize(
    "name",
    [
        r"C:\Windows\System32\foo.dll",
        r"C:\Windows\SysWOW64\foo.dll",
        r"c:\windows\system32\foo.dll",
        r"\\server\share\foo.dll",
        r"relative\foo.dll",
        "foo.dll",
        r"C:foo.dll",
        r"\\?\C:\Gone\foo.dll",
        r"C:\Gone/foo.dll",
        r"%SystemRoot%\foo.dll",
        r'"C:\Gone\foo.dll"',
        "C:\\Gone\\fo\no.dll",
    ],
)
def test_kept_names(fake_registry, name):
    # a prober that says MISSING for everything: the rule itself must refuse
    items, _ = scan(fake_registry, {name: (REG_DWORD, 1)}, default=M)
    assert items == []


def test_unknown_states_kept(fake_registry):
    # removable/network drives, 8.3 names, reparse points: prober says UNKNOWN
    names = [r"E:\x\a.dll", r"C:\PROGRA~1\a.dll", r"D:\net\a.dll"]
    items, _ = scan(fake_registry, {n: (REG_DWORD, 1) for n in names}, default=U)
    assert items == []


def test_non_dword_kept(fake_registry):
    items, _ = scan(
        fake_registry,
        {r"C:\Gone\a.dll": (REG_SZ, "1"), r"C:\Gone\b.dll": (3, b"\x01")},
    )
    assert items == []


def test_default_value_kept(fake_registry):
    items, _ = scan(fake_registry, {"": (REG_DWORD, 1)})
    assert items == []


def test_case_and_non_ascii_names(fake_registry):
    name = "C:\\Program Files\\Gönül\\GONE.DLL"
    items, _ = scan(fake_registry, {name: (REG_DWORD, 1)})
    assert [i.reg.value for i in items] == [name]


def test_value_names_with_backslashes_roundtrip_key(fake_registry):
    items, _ = scan(fake_registry, {GONE: (REG_DWORD, 1)})
    assert items[0].reg.value == GONE
    assert "\\\\" in item_key(items[0])  # JSON-escaped backslashes
    import json

    assert GONE in json.loads(item_key(items[0]).split("|reg|", 1)[1])


def test_prober_error_means_unknown(fake_registry):
    fake_registry.add_key("HKLM", CV, {GONE: (REG_DWORD, 1)})
    det, prober = make({})

    def boom(path):
        raise OSError("x")

    prober.probe = boom
    assert list(det.find_items()) == []


def test_huge_container_is_bounded(fake_registry, monkeypatch):
    monkeypatch.setattr(mod, "MAX_CHECKED", 50)
    monkeypatch.setattr(mod, "MAX_FINDINGS", 10)
    vals = {rf"C:\Gone\f{i:03}.dll": (REG_DWORD, 1) for i in range(300)}
    fake_registry.add_key("HKLM", CV, vals)
    det, prober = make({})
    report = det.scan()
    assert report.skipped_reason is None, report.skipped_reason
    names = [i.reg.value for i in report.items]
    # the first ten in sorted order, and the cut is announced
    assert names == [rf"C:\Gone\f{i:03}.dll" for i in range(10)]
    assert report.ran and report.incomplete and "10" in report.incomplete
    assert len(prober.calls) <= 50
    # the container is read once, never once per finding
    assert len([c for c in fake_registry.calls if c[0] == "values"]) <= 2


def test_complete_scan_has_no_incomplete_note(fake_registry):
    fake_registry.add_key("HKLM", CV, {GONE: (REG_DWORD, 1)})
    det, _ = make({})
    report = det.scan()
    assert report.skipped_reason is None, report.skipped_reason
    assert len(report.items) == 1 and report.incomplete is None


def test_checked_cap_announced(fake_registry, monkeypatch):
    monkeypatch.setattr(mod, "MAX_CHECKED", 5)
    fake_registry.add_key(
        "HKLM", CV, {rf"C:\Here\f{i}.dll": (REG_DWORD, 1) for i in range(9)}
    )
    det, _ = make({}, default=P)
    report = det.scan()
    assert report.skipped_reason is None, report.skipped_reason
    assert report.items == [] and report.incomplete


class Clock:
    def __init__(self, step=0.0):
        self.now = 0.0
        self.step = step

    def __call__(self):
        self.now += self.step
        return self.now


def test_deadline_stops_and_announces(fake_registry, monkeypatch):
    monkeypatch.setattr(mod, "_clock", Clock(step=1.0))
    monkeypatch.setattr(mod, "MAX_SECONDS", 5.0)
    fake_registry.add_key(
        "HKLM", CV, {rf"C:\Gone\f{i:03}.dll": (REG_DWORD, 1) for i in range(100)}
    )
    det, _ = make({})
    report = det.scan()
    assert report.skipped_reason is None, report.skipped_reason
    assert 0 < len(report.items) < 100
    assert report.incomplete and "time" in report.incomplete


def test_deadline_ignores_time_suspended_at_yield(fake_registry, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(mod, "_clock", clock)
    monkeypatch.setattr(mod, "MAX_SECONDS", 5.0)
    fake_registry.add_key(
        "HKLM", CV, {rf"C:\Gone\f{i:03}.dll": (REG_DWORD, 1) for i in range(20)}
    )
    det, _ = make({})
    n = 0
    for _ in det.find_items():
        n += 1
        clock.now += 100.0  # a slow consumer
    assert n == 20 and det.incomplete == []


def test_findings_are_in_sorted_order(fake_registry):
    names = [r"C:\Gone\b.dll", r"C:\Gone\A.dll", r"C:\Gone\c.dll"]
    items, _ = scan(fake_registry, {n: (REG_DWORD, 1) for n in names})
    assert [i.reg.value for i in items] == sorted(names, key=str.casefold)


def test_per_user_path_not_listed(fake_registry):
    items, _ = scan(fake_registry, {r"C:\Users\x\AppData\a.dll": (REG_DWORD, 1)})
    assert items == []


def test_qword_not_listed(fake_registry):
    items, _ = scan(fake_registry, {GONE: (11, 1)})
    assert items == []


def test_backup_problem_is_consulted(fake_registry, monkeypatch):
    seen = []

    def refuse(cid, target, snap):
        seen.append(target.value)
        return "nope"

    monkeypatch.setattr(mod.regbackup, "backup_problem", refuse)
    items, _ = scan(fake_registry, {GONE: (REG_DWORD, 1)})
    assert items == [] and seen == [GONE]


def test_missing_container_not_read(fake_registry):
    det, _ = make({})
    assert list(det.find_items()) == []
    assert not [c for c in fake_registry.calls if c[0] == "values"]


def test_never_helper_eligible():
    from cleanix import elevated

    # class flag stays False: tests/test_catalog.py forbids requires_root outside
    # the system/review categories; the items themselves carry requires_root
    assert "win_reg_shared_dlls" not in elevated.admin_cleaner_ids()


def test_never_touches_unlisted_containers(fake_registry):
    reg = fake_registry
    reg.add_key("HKLM", CV, {GONE: (REG_DWORD, 1)})
    reg.add_key("HKCU", CV, {GONE: (REG_DWORD, 1)})
    reg.add_key(
        "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", {"x": (REG_SZ, "y")}
    )
    det, _ = make({})
    items = list(det.find_items())
    assert len(items) == 1
    allowed = {CV.casefold(), CVW.casefold()}
    writes = {"delete_key", "delete_value", "create_key", "set_value"}
    for call in reg.calls:
        assert call[0] not in writes
        assert call[1] == "HKLM"
        if len(call) > 2:
            k = call[2].casefold()
            assert k in allowed or any(a.startswith(k + "\\") for a in allowed)


def test_missing_container_is_fine(fake_registry):
    det, _ = make({})
    assert list(det.find_items()) == []


def test_backup_problem_values_skipped(fake_registry):
    # CR/LF names cannot be backed up and restored
    items, _ = scan(fake_registry, {"C:\\Gone\\a\r\nb.dll": (REG_DWORD, 1)})
    assert items == []
