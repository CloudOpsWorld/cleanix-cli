"""``elevated.static_admin_problem`` (what the GUI may offer) versus the
helper's own rules (what ``python -m cleanix.elevated`` will clean).

No Qt here; the GUI side of the parity is in tests/gui/test_admin_eligibility.py.
Nothing is deleted or launched; Windows-branch cases use real files under
tmp_path with ProgramData/SystemRoot pointed at tmp directories.
"""

from __future__ import annotations

import pytest

from cleanix import elevated
from cleanix.core import registry
from cleanix.core.models import CleanableItem, ItemKind


def command_item(cid, *, root=True, report_only=False):
    return CleanableItem(cleaner_id=cid, description=f"{cid} item", size=1,
                         kind=ItemKind.COMMAND, command=["tool", cid],
                         requires_root=root, report_only=report_only)


def helper_static_accepts(item, allowed) -> bool:
    """The helper's rules that do not depend on the moment of deletion:
    ``_eligible`` plus, on Windows, the ProgramData / Windows\\Temp branch of
    ``_path_chain_problem`` (evaluated for real against tmp directories)."""
    if not elevated._eligible(item, allowed):
        return False
    if item.kind is ItemKind.PATH and not elevated._is_posix():
        return elevated._path_chain_problem(item.path, None, frozenset()) is None
    return True


def all_cleaner_ids():
    return sorted({cls.id for cls in registry.ALL_CLEANERS})


def test_static_problem_matches_helper_for_every_cleaner():
    """One fake administrator item per cleaner (allowlisted or not), plus
    report-only and non-root variants: the static predicate and the helper's
    eligibility agree on every one."""
    allowed = elevated.admin_cleaner_ids()
    checked = 0
    for cid in all_cleaner_ids() + ["not_a_cleaner"]:
        for item in (command_item(cid), command_item(cid, report_only=True),
                     command_item(cid, root=False)):
            static_ok = elevated.static_admin_problem(item, allowed) is None
            assert static_ok == elevated._eligible(item, allowed), (cid, item)
            # Default allowlist argument is the same allowlist.
            assert (elevated.static_admin_problem(item) is None) == static_ok
            checked += 1
    assert checked >= 3 * len(allowed)
    # Every allowlisted cleaner's admin item is offered...
    for cid in allowed:
        assert elevated.static_admin_problem(command_item(cid), allowed) is None
    # ...and nothing outside the allowlist is.
    for cid in set(all_cleaner_ids()) - set(allowed):
        reason = elevated.static_admin_problem(command_item(cid), allowed)
        assert reason and "fixed list of system locations" in reason


def test_opt_in_memory_and_swap_are_never_offered_as_admin():
    allowed = elevated.admin_cleaner_ids()
    for cid in ("memory", "swap", "memory_macos"):
        assert cid not in allowed
        assert elevated.static_admin_problem(command_item(cid), allowed)


@pytest.fixture
def windows_dirs(tmp_path, monkeypatch):
    """Pretend to be Windows with ProgramData/SystemRoot under tmp_path, for
    both the static predicate and the helper's path rule."""
    pd = tmp_path / "ProgramData"
    win = tmp_path / "Windows"
    (pd / "Microsoft" / "Windows" / "WER" / "ReportQueue").mkdir(parents=True)
    (win / "Temp" / "somedir").mkdir(parents=True)
    (win / "Temp" / "file.log").write_bytes(b"x")
    (pd / "Microsoft" / "Windows" / "WER" / "ReportQueue" / "r.wer").write_bytes(b"x")
    (tmp_path / "Other").mkdir()
    (tmp_path / "Other" / "MEMORY.DMP").write_bytes(b"x")
    monkeypatch.setattr(elevated, "_is_posix", lambda: False)
    monkeypatch.setattr(elevated, "_static_win_dirs", lambda: (str(pd), str(win)))
    monkeypatch.setenv("ProgramData", str(pd))
    monkeypatch.setenv("SystemRoot", str(win))
    return tmp_path


def windows_path_items(base, cid):
    def p(rel, desc):
        return CleanableItem(cleaner_id=cid, description=desc, size=1,
                             path=str(base / rel), requires_root=True)

    return [
        p("Windows/Temp/file.log", "plain file in Windows\\Temp"),
        p("Windows/Temp/somedir", "folder in Windows\\Temp"),
        p("ProgramData/Microsoft/Windows/WER/ReportQueue/r.wer", "WER report"),
        p("ProgramData/Microsoft/Windows/WER/ReportQueue", "WER folder"),
        p("Other/MEMORY.DMP", "memory dump"),
    ]


def test_windows_path_rules_match_the_helper(windows_dirs):
    cid = "win_system_temp"
    allowed = frozenset({cid})
    verdicts = {}
    for item in windows_path_items(windows_dirs, cid):
        reason = elevated.static_admin_problem(item, allowed)
        assert (reason is None) == helper_static_accepts(item, allowed), item.description
        verdicts[item.description] = reason
    assert verdicts["plain file in Windows\\Temp"] is None
    assert verdicts["memory dump"] is None
    assert "Windows\\Temp" in verdicts["folder in Windows\\Temp"]
    assert "ProgramData" in verdicts["WER report"]
    assert "ProgramData" in verdicts["WER folder"]


def test_static_problem_is_side_effect_free(windows_dirs, monkeypatch):
    """Only an lstat, and only for items under Windows\\Temp."""
    seen = []
    real = elevated._lstat
    monkeypatch.setattr(elevated, "_lstat", lambda p: seen.append(str(p)) or real(p))
    items = windows_path_items(windows_dirs, "win_system_temp")
    for item in items:
        elevated.static_admin_problem(item, frozenset({"win_system_temp"}))
    assert sorted(seen) == sorted(i.path for i in items[:2])
    for item in items:
        assert __import__("os").path.lexists(item.path)


def test_missing_windows_temp_item_is_left_to_the_helper(windows_dirs):
    item = CleanableItem(cleaner_id="win_system_temp", description="gone", size=1,
                         path=str(windows_dirs / "Windows" / "Temp" / "gone.tmp"),
                         requires_root=True)
    assert elevated.static_admin_problem(item, frozenset({"win_system_temp"})) is None
