"""I4: per-item command timeouts (DISM runs far longer than the 120 s default)."""

from __future__ import annotations

from cleanix.config import Config
from cleanix.core import engine as engine_mod
from cleanix.core.engine import Engine
from cleanix.core.models import CleanableItem, ItemKind
from cleanix.core.report import scan_to_json
from cleanix.core.models import CleanerReport, ScanResult


def _record(monkeypatch):
    calls = []

    def fake(cmd, *a, **k):
        calls.append((list(cmd), a, k))
        return 0, "", ""

    monkeypatch.setattr(engine_mod, "run_command", fake)
    return calls


def test_default_timeout_field_is_none():
    item = CleanableItem("t", "cmd", 0, ItemKind.COMMAND, command=["x"])
    assert item.timeout is None


def test_engine_uses_default_when_no_item_timeout(monkeypatch):
    calls = _record(monkeypatch)
    item = CleanableItem("t", "cmd", 0, ItemKind.COMMAND, command=["x", "y"])
    Engine([]).clean([item], dry_run=False, allow_root_items=True)
    assert calls == [(["x", "y"], (), {})]      # run_command's own default (120)


def test_engine_passes_item_timeout(monkeypatch):
    calls = _record(monkeypatch)
    item = CleanableItem("t", "cmd", 0, ItemKind.COMMAND, command=["x"], timeout=3600)
    Engine([]).clean([item], dry_run=False, allow_root_items=True)
    assert calls == [(["x"], (), {"timeout": 3600})]


def test_dism_item_carries_long_timeout(monkeypatch):
    from cleanix.cleaners import windows_system as ws

    monkeypatch.setattr(ws, "which", lambda name: r"C:\Windows\System32\Dism.exe")
    (item,) = ws.WinComponentStoreCleaner(Config()).find_items()
    assert item.timeout == 3600


def test_other_command_items_keep_default(monkeypatch):
    from cleanix.cleaners import windows_core as wc

    monkeypatch.setattr(wc.winenv, "recycle_bin_size", lambda: 10)
    (item,) = wc.WinRecycleBinCleaner(Config()).find_items()
    assert item.timeout is None


def test_json_output_unchanged_by_timeout_field():
    a = CleanableItem("t", "cmd", 0, ItemKind.COMMAND, command=["x"])
    b = CleanableItem("t", "cmd", 0, ItemKind.COMMAND, command=["x"], timeout=3600)
    ra = ScanResult([CleanerReport("t", "T", "d", items=[a])])
    rb = ScanResult([CleanerReport("t", "T", "d", items=[b])])
    assert "timeout" not in scan_to_json(ra)
    assert scan_to_json(ra) == scan_to_json(rb)
