"""I3: config/history/manifests are UTF-8 regardless of the locale code page.

On a UTF-8 locale these pass trivially; on a cp1252 Windows host they fail if
files are read with the locale default."""

from __future__ import annotations

import json

import pytest

from cleanix import config as cfgmod
from cleanix.config import Config
from cleanix.core import safety


@pytest.mark.parametrize("bom", [b"", b"\xef\xbb\xbf"])
def test_non_ascii_protected_glob_loads_and_protects(tmp_path, bom):
    keep = tmp_path / "Geschäft"
    keep.mkdir()
    pattern = str(keep) + "/*" if "/" in str(tmp_path) else str(keep) + "\\*"
    # Literal (unescaped) non-ASCII, as a text editor would save it.
    text = "protected_globs:\n  - '" + pattern + "'\n"
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_bytes(bom + text.encode("utf-8"))

    cfg = Config.load(cfg_file)
    assert cfg.protected_globs == [pattern]
    assert cfgmod.read_user_overrides(cfg_file)["protected_globs"] == [pattern]
    safety.set_protected_globs(cfg.protected_globs)
    try:
        assert not safety.is_safe_to_delete(keep / "bilanz.xlsx")
    finally:
        safety.set_protected_globs([])


def test_config_write_is_utf8(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfgmod.write_user_override("protected_globs", ["C:/Zoë/Geschäft/*"], cfg_file)
    raw = cfg_file.read_bytes().decode("utf-8")      # must decode as UTF-8
    assert cfgmod.read_user_overrides(cfg_file)["protected_globs"] == ["C:/Zoë/Geschäft/*"]
    assert raw


def test_history_and_manifest_read_utf8(tmp_path, monkeypatch):
    from cleanix.core import history, quarantine

    monkeypatch.setattr(history, "state_dir", lambda: tmp_path)
    entry = {"time": 1.0, "freed": 1, "items": 1, "mode": "delete", "note": "Geschäft ✓"}
    (tmp_path / "history.jsonl").write_bytes(
        (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")
    )
    assert history.load() == [entry]

    run = tmp_path / "run1"
    run.mkdir()
    manifest = {"run_id": "run1", "created": 0,
                "items": [{"original": "C:/Zoë/Geschäft ✓", "stored": "x", "size": 3}]}
    (run / "manifest.json").write_bytes(
        json.dumps(manifest, ensure_ascii=False).encode("utf-8")
    )
    assert quarantine._read_manifest(run) == manifest
