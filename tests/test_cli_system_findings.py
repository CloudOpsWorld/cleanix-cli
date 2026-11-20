"""Task 10: system-wide findings in `clean --act-on` and `review` through the
elevated helper (hermetic: the launcher is a fake that writes a helper
result; no real elevation, no real helper, no system path is touched)."""

from __future__ import annotations

import builtins
import sys
import re
from pathlib import Path

import pytest

from cleanix import cli, elevated
from cleanix.config import Config
from cleanix.core import (
    actions,
    elevate,
    elevate_launch,
    findings,
    history,
    quarantine,
    report,
    review,
    safety,
    service,
    system_findings,
)
from cleanix.core.models import CleanableItem, CleanerReport, item_key
from cleanix.core.remedy import Remedy, RemedyKind, path_remedy

# The system-wide path is behind the beta gate (system_findings.gate_problem):
# these tests opt in to it explicitly (tests/conftest.py beta_system_actions).
pytestmark = pytest.mark.usefixtures("beta_system_actions")

PHRASE = "DELETE SYSTEM FILES"
ROOTS = {
    "orphan_files": ("/opt", "/usr/local", "/var/lib", "/var/cache"),
    "orphan_launch_jobs": ("/Library/LaunchDaemons",),
}


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(quarantine, "quarantine_root", lambda: tmp_path / "q")
    monkeypatch.setattr(cli, "_load_config", lambda: Config())
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)
    monkeypatch.setattr(cli, "_is_root_process", lambda: False)
    monkeypatch.setenv("COLUMNS", "400")
    # The helper's lexical world: POSIX support, Linux-like roots, the
    # Linux root quarantine (works on every OS; nothing is touched).
    monkeypatch.setattr(elevated, "_findings_supported", lambda: True)
    monkeypatch.setattr(elevated, "admin_finding_ids",
                        lambda: frozenset({"orphan_files", "orphan_launch_jobs"}))
    monkeypatch.setattr(elevated, "finding_path_roots", lambda: dict(ROOTS))
    monkeypatch.setattr(elevated, "finding_kind_dirs",
                        lambda: {"launch_job": ("/Library/LaunchDaemons",),
                                 "systemd_unit": ("/etc/systemd/system",),
                                 "pkg_receipt": ("/private/var/db/receipts",)})
    monkeypatch.setattr(elevated, "helper_finding_kinds",
                        lambda: frozenset({"path", "launch_job"}))
    monkeypatch.setattr(elevated, "_root_quarantine_location",
                        lambda: ("/var/lib", ("cleanix", "quarantine")))
    monkeypatch.setattr(cli, "_findings_launcher", None)
    findings._hash_cache.clear()
    yield
    findings._hash_cache.clear()
    safety.set_protected_globs([])


class _Fake:
    def __init__(self, cid, items):
        self.id = cid
        self.name = cid
        self._items = items

    def scan(self):
        return CleanerReport(cleaner_id=self.id, name=self.name,
                             description="test", items=list(self._items))


def _patch_scan(monkeypatch, items):
    by_cid = {}
    for i in items:
        by_cid.setdefault(i.cleaner_id, []).append(i)

    def fake_build(config, only=None, exclude=None):
        ids = only or list(by_cid)
        return [_Fake(c, by_cid.get(c, [])) for c in ids]

    monkeypatch.setattr(cli, "build_cleaners", fake_build)


def _user(tmp_path, name="big.bin", data=b"x" * 4096):
    d = tmp_path / "home"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_bytes(data)
    item = CleanableItem(cleaner_id="big_files", description=name, size=len(data),
                         path=str(p), report_only=True, remedy=path_remedy(str(p)))
    return p, item


def _sys(path="/opt/stale-app", cid="orphan_files", kind=RemedyKind.PATH,
         desc=None, size=1000, group=None):
    return CleanableItem(cleaner_id=cid, description=desc or path.rsplit("/", 1)[-1],
                         size=size, path=path, report_only=True, requires_root=True,
                         remedy=Remedy(kind=kind, fingerprint=(1, 2, 3, 4), group=group))


def _job(path="/Library/LaunchDaemons/org.example.gone.plist"):
    return _sys(path, cid="orphan_launch_jobs", kind=RemedyKind.LAUNCH_JOB)


class Launcher:
    """A fake elevation launcher: reads the request it was given and writes
    the helper result the test wants (default: every item removed)."""

    def __init__(self, status=None, reason="", note="", exc=None, write=True,
                 quarantine_run="", backup_run="", deadline=False, errors=(),
                 omit=False, removed_count=None):
        self.calls = []
        self.requests = []
        self.status = status or {}
        self.reason = reason
        self.note = note
        self.exc = exc
        self.write = write
        self.quarantine_run = quarantine_run
        self.backup_run = backup_run
        self.deadline = deadline
        self.errors = list(errors)
        self.omit = omit
        self.removed_count = removed_count
        self.on_call = None

    def __call__(self, argv):
        self.calls.append(list(argv))
        if self.on_call:
            self.on_call()
        req = Path(argv[argv.index("--request") + 1])
        res = Path(argv[argv.index("--result") + 1])
        sel = elevate.parse_request(req.read_bytes())
        self.requests.append(sel)
        if self.write:
            outs = []
            if not self.omit:
                for s in sel.findings.items:
                    st = self.status.get(s.key, "removed")
                    outs.append(elevate.FindingOutcome(
                        key=s.key, status=st, freed=100 if st == "removed" else 0,
                        reason="" if st == "removed" else self.reason,
                        note=self.note))
            removed = sum(1 for o in outs if o.status == "removed")
            if self.removed_count is not None:
                removed = self.removed_count
            elevate.write_result(res, elevate.HelperResult(
                freed=100 * removed, removed=removed, errors=self.errors,
                unmatched=0, nonce=sel.nonce, deadline_hit=self.deadline,
                findings=outs, quarantine_run=self.quarantine_run,
                backup_run=self.backup_run))
        if self.exc is not None:
            raise self.exc
        return 0


def _install(monkeypatch, launcher):
    monkeypatch.setattr(cli, "_findings_launcher", launcher)
    return launcher


def _run(capsys, *argv):
    code = cli.main(["clean", *argv])
    return code, " ".join(capsys.readouterr().out.split())


def _phrase(monkeypatch, answer):
    """Answer the typed-phrase prompt through the REAL reading path
    (console.input -> builtins.input); Rich's Prompt.ask must not be used
    (it strips the answer)."""
    asked = []

    def fake_input(prompt=""):
        asked.append(prompt)
        if isinstance(answer, type) and issubclass(answer, BaseException):
            raise answer
        return answer

    def no_prompt(*a, **k):
        raise AssertionError("the typed phrase must not be read with Prompt.ask")

    monkeypatch.setattr(builtins, "input", fake_input)
    monkeypatch.setattr(cli.Prompt, "ask", no_prompt)
    return asked


def _confirm(monkeypatch, value=True):
    asked = []
    monkeypatch.setattr(cli.Confirm, "ask", lambda q, **kw: asked.append(q) or value)
    return asked


# --------------------------------------------------------------------------
# clean --act-on
# --------------------------------------------------------------------------
def test_system_items_skipped_without_elevation(tmp_path, monkeypatch, capsys):
    p, user = _user(tmp_path)
    _patch_scan(monkeypatch, [user, _sys()])
    launch = _install(monkeypatch, Launcher())
    # Preview: listed with what would happen, never launched.
    code, out = _run(capsys, "--act-on", "big_files,orphan_files")
    assert code == 0 and launch.calls == [] and p.exists()
    assert "System-wide items (need administrator rights)" in out
    assert "root-only quarantine you cannot restore from yet" in out
    assert PHRASE in out
    # Non-interactive, no --yes: refused as before, nothing done, no launch.
    code, out = _run(capsys, "--act-on", "big_files,orphan_files", "--execute")
    assert code == 2 and launch.calls == [] and p.exists()
    assert "not done: needs a terminal to type the confirmation" in out
    assert "Nothing was changed" in out


def test_typed_confirmation_wrong_text_aborts(tmp_path, monkeypatch, capsys):
    p, user = _user(tmp_path)
    _patch_scan(monkeypatch, [user, _sys()])
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    launch = _install(monkeypatch, Launcher())
    for wrong in ("delete system files", "DELETE SYSTEM", "yes", "", " DELETE SYSTEM FILES",
                  "DELETE SYSTEM FILES ", "Delete System Files", "DELETE  SYSTEM FILES"):
        asked = _phrase(monkeypatch, wrong)
        code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
        assert code == 1 and len(asked) == 1
        assert f"Type {PHRASE} to act on these 1 system-wide item(s)" in out
        assert launch.calls == [] and "Aborted" in out
    # EOF at the phrase prompt is an abort too.
    _phrase(monkeypatch, EOFError)
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 1 and launch.calls == []


def test_typed_confirmation_exact_text_proceeds(tmp_path, monkeypatch, capsys):
    p, user = _user(tmp_path)
    s = _sys()
    _patch_scan(monkeypatch, [user, s])
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    confirms = _confirm(monkeypatch, True)
    asked = _phrase(monkeypatch, PHRASE)
    launch = _install(monkeypatch, Launcher(quarantine_run="20261120-root"))
    code, out = _run(capsys, "--act-on", "big_files,orphan_files", "--execute")
    assert code == 0 and len(confirms) == 1 and len(asked) == 1
    assert len(launch.calls) == 1 and not p.exists()
    (sel,) = launch.requests
    assert [x.key for x in sel.findings.items] == [item_key(s)]
    assert sel.findings.permanent is False
    assert "moved to the root-only quarantine (you cannot restore from it yet; 100 B moved, no space freed)" in out
    assert "moved 1 item(s) (100 B) into the root-only quarantine; no space was freed" in out
    assert "20261120-root" in out and "/var/lib/cleanix/quarantine" in out
    assert "You cannot restore from it yet" in out
    # one history entry for the user part, one for the helper's removals
    # the moved bytes are never counted as freed
    assert [(e["mode"], e["freed"], e["items"]) for e in history.load()][1:] == [
        ("administrator-quarantine", 0, 1)]
    assert history.load()[0]["mode"] == "quarantine"


def test_yes_without_elevation_skips_system_but_runs_user(tmp_path, monkeypatch, capsys):
    p, user = _user(tmp_path)
    _patch_scan(monkeypatch, [user, _sys()])
    launch = _install(monkeypatch, Launcher())
    asked = _phrase(monkeypatch, PHRASE)
    code, out = _run(capsys, "--act-on", "big_files,orphan_files", "--execute", "--yes")
    assert code == 0 and not p.exists()  # the user part ran
    assert launch.calls == [] and asked == []  # never prompts without a TTY
    assert "not done: needs a terminal to type the confirmation" in out
    # M2: exit 0, but the not-done list is announced prominently
    assert "1 system-wide item(s) NOT done" in out
    assert len(quarantine.list_runs()) == 1


def test_yes_with_elevated_process_skips_typed_phrase(tmp_path, monkeypatch, capsys):
    _patch_scan(monkeypatch, [_sys()])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    asked = _phrase(monkeypatch, "never asked")
    launch = _install(monkeypatch, Launcher())
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 0 and len(launch.calls) == 1 and asked == []
    # also on a terminal: --yes + root skips the phrase (still the helper path)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 0 and len(launch.calls) == 2 and asked == []
    # root WITHOUT --yes on a terminal: the phrase is still required
    asked = _phrase(monkeypatch, "no")
    _confirm(monkeypatch, True)
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute")
    assert code == 1 and len(asked) == 1 and len(launch.calls) == 2


def test_summary_lists_not_done(tmp_path, monkeypatch, capsys):
    a, b, c, d = (_sys("/opt/a"), _sys("/opt/b"), _sys("/opt/c"), _sys("/opt/d"))
    bad = _sys("/etc/passwd")  # outside every root: never offered
    _patch_scan(monkeypatch, [a, b, c, d, bad])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    launch = _install(monkeypatch, Launcher(status={
        item_key(b): "skipped", item_key(c): "not_found", item_key(d): "refused"},
        reason="changed since the scan; nothing was done"))
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert len(launch.calls) == 1
    assert [x.key for x in launch.requests[0].findings.items] == [
        item_key(i) for i in (a, b, c, d)]
    assert "not offered: the administrator helper never acts on it" in out
    assert "skipped: changed since the scan" in out
    assert "not done: the administrator scan did not report this item" in out
    assert "refused by the administrator helper" in out
    assert "moved 1 item(s)" in out
    assert code == 2  # a refusal is a real error


def test_system_wording_never_offers_restore(tmp_path, monkeypatch, capsys):
    _patch_scan(monkeypatch, [_sys(), _job()])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    _install(monkeypatch, Launcher(
        quarantine_run="r-q", backup_run="r-b",
        note="permanent: the job's file was removed (a copy of the file is kept in "
             "/var/lib/cleanix/quarantine/r-b/files for manual recovery)"))
    code, out = _run(capsys, "--act-on", "orphan_files,orphan_launch_jobs")
    assert code == 0
    assert "cleanix restore" not in out and "quarantine empty" not in out
    assert "PERMANENT: the job's file is removed (a copy is kept in " \
           "/var/lib/cleanix/quarantine for manual recovery" in out
    code, out = _run(capsys, "--act-on", "orphan_files,orphan_launch_jobs",
                     "--execute", "--yes")
    assert code == 0
    assert "cleanix restore" not in out and "quarantine empty" not in out
    assert "undo with" not in out.lower()
    assert "/var/lib/cleanix/quarantine/r-b/files for manual recovery" in out
    assert "note: permanent: the job's file was removed" in out
    assert "removed permanently" in out
    # --permanent: the PATH item is labelled permanent too
    code, out = _run(capsys, "--act-on", "orphan_files", "--permanent")
    assert "PERMANENT: deleted with administrator rights; no undo" in out


def test_cross_filesystem_not_removed_suggests_permanent(tmp_path, monkeypatch, capsys):
    s = _sys()
    _patch_scan(monkeypatch, [s])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    _install(monkeypatch, Launcher(
        status={item_key(s): "not_removed"},
        reason="it is on another filesystem than the administrator quarantine; "
               "nothing was moved (delete it permanently instead)"))
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert "NOT removed: it is on another filesystem" in out
    assert "run again with --permanent" in out
    assert "DELETES it permanently, with no undo and no copy kept" in out
    assert "Nothing was removed by the administrator helper" in out
    assert code == 0  # a limitation explained, not a helper failure


def test_settings_mismatch_wording(tmp_path, monkeypatch, capsys):
    s = _sys()
    _patch_scan(monkeypatch, [s])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    _install(monkeypatch, Launcher(status={item_key(s): "not_found"},
                                   reason=elevated.NOT_FOUND))
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 0
    assert ("the administrator scan did not report this item (it uses default "
            "settings, e.g. orphan_min_age_days / orphan_max_items, so a changed "
            "setting can hide items)") in out
    assert "Nothing was removed" in out


def test_helper_text_is_escaped_and_c1_bidi_stripped(tmp_path, monkeypatch, capsys):
    # safe() keeps its behaviour for normal text; helper_safe strips C1/bidi.
    assert report.safe("plain text 1.2 KB") == "plain text 1.2 KB"
    assert report.helper_safe("plain text") == "plain text"
    assert report.helper_safe("a\x9bb‮c⁦d‏e") == "abcde"
    assert report.helper_safe("[bold]x") == report.safe("[bold]x")
    assert "\ud800" not in report.helper_safe("x\ud800")
    s = _sys("/opt/evil‮gnp.exe", desc="evil‮gnp.exe")
    t = _sys("/opt/other")
    _patch_scan(monkeypatch, [s, t])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    _install(monkeypatch, Launcher(
        status={item_key(s): "skipped", item_key(t): "not_removed"},
        reason="[bold red]boom\x9b31m‮evil⁧[/bold red]",
        note="[link=http://x]click\x85‭[/link]"))
    capsys.readouterr()
    code = cli.main(["clean", "--act-on", "orphan_files", "--execute", "--yes"])
    raw = capsys.readouterr().out
    for bad in ("\x9b", "\x85", "‮", "‭", "⁧", "\x1b]8"):
        assert bad not in raw
    assert "[bold red]boom31mevil[/bold red]" in raw  # markup shown, not applied
    assert "[link=http://x]click[/link]" in raw
    assert code == 2


def test_windows_not_offered(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(elevated, "_findings_supported", lambda: False)
    p, user = _user(tmp_path)
    _patch_scan(monkeypatch, [user, _sys()])
    launch = _install(monkeypatch, Launcher())
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    code, out = _run(capsys, "--act-on", "big_files,orphan_files", "--execute", "--yes")
    assert code == 0 and not p.exists() and launch.calls == []
    assert "not offered: system-wide findings are not supported on Windows" in out
    # only system items on Windows: nothing to act on, no crash
    _patch_scan(monkeypatch, [_sys()])
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 0 and "Nothing can be acted on right now" in out


def test_helper_error_exit_code_2(tmp_path, monkeypatch, capsys):
    s = _sys()
    _patch_scan(monkeypatch, [s])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    # helper crashed without a usable result
    _install(monkeypatch, Launcher(write=False, exc=elevate_launch.ElevationFailed(
        "helper exited", exit_code=2)))
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 2 and "outcome is unknown" in out
    # timed out: never "nothing was removed"
    _install(monkeypatch, Launcher(write=False, exc=elevate_launch.ElevationFailed(
        "elevated helper timed out and may still be running")))
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 2 and "may still be running" in out
    assert "nothing was removed" not in out.lower()
    # no elevation mechanism
    _install(monkeypatch, Launcher(write=False, exc=elevate_launch.ElevationUnavailable(
        "pkexec (polkit) was not found")))
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 2 and "none of the system-wide items was removed" in out
    # helper refused the whole request (exit 1 with a result, no outcomes)
    _install(monkeypatch, Launcher(omit=True, errors=["refused: the process is not root"],
                                   exc=elevate_launch.ElevationFailed("x", exit_code=1)))
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 2 and "refused the request" in out and "not root" in out
    assert "Nothing was removed by the administrator helper" in out
    assert "did not report on it" in out
    # deadline
    _install(monkeypatch, Launcher(deadline=True))
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 2 and "time limit" in out
    # a request the helper would refuse lexically: no prompt at all
    def too_big(*a, **k):
        raise ValueError("the request is too large; select fewer items")

    launch = _install(monkeypatch, Launcher())
    monkeypatch.setattr(elevate_launch, "run_findings_request", too_big)
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 2 and "No prompt was shown; none of the system-wide items was removed" in out
    assert launch.calls == []


def test_abort_exit_code_1(tmp_path, monkeypatch, capsys):
    _patch_scan(monkeypatch, [_sys()])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    _install(monkeypatch, Launcher(write=False, exc=elevate_launch.ElevationDeclined(
        "authentication was declined")))
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 1 and "declined; none of the system-wide items was removed" in out
    monkeypatch.setattr(cli, "_is_root_process", lambda: False)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    _phrase(monkeypatch, KeyboardInterrupt)
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 1 and "Aborted" in out


def test_user_space_part_still_runs_when_system_part_declined(tmp_path, monkeypatch, capsys):
    p, user = _user(tmp_path, data=b"keep me")
    s = _sys()
    _patch_scan(monkeypatch, [user, s])
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    _phrase(monkeypatch, "no thanks")
    launch = _install(monkeypatch, Launcher())
    code, out = _run(capsys, "--act-on", "big_files,orphan_files", "--execute", "--yes")
    assert code == 1 and not p.exists() and launch.calls == []
    (run,) = quarantine.list_runs()
    quarantine.restore(run["run_id"])  # the user part is done and undoable
    assert p.read_bytes() == b"keep me"
    # In process, a system item is only ever skipped (needs an elevated run).
    summary = actions.act([s], Config(), dry_run=False, record_history=False,
                          permanent=True)
    assert summary.removed == 0
    assert [why for _i, why in summary.skipped] == [actions.NEEDS_ELEVATION]


def test_user_decline_stops_whole_run_and_says_so(tmp_path, monkeypatch, capsys):
    p, user = _user(tmp_path)
    _patch_scan(monkeypatch, [user, _sys()])
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    confirms = _confirm(monkeypatch, False)
    asked = _phrase(monkeypatch, PHRASE)
    launch = _install(monkeypatch, Launcher())
    code, out = _run(capsys, "--act-on", "big_files,orphan_files", "--execute")
    assert code == 1 and p.exists() and launch.calls == [] and asked == []
    assert "answering no stops the whole run" in confirms[0]
    assert "system-wide items were not touched either" in out


def test_request_identity_and_config_agree(tmp_path, monkeypatch, capsys):
    """--uid / invoking_user come from the real uid; --config must belong to
    the same account: in a root process (sudo) no user's config is sent."""
    s = _sys()
    _patch_scan(monkeypatch, [s])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    monkeypatch.setattr(system_findings, "_is_posix", lambda: True)
    monkeypatch.setattr(system_findings, "invoking_user_name", lambda: "root")
    launch = _install(monkeypatch, Launcher())
    monkeypatch.setattr(system_findings, "_process_is_root", lambda: True)
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 0 and "--config" not in launch.calls[-1]
    assert launch.requests[-1].invoking_user == "root"
    # a normal user: its own config file, as the GUI sends it
    monkeypatch.setattr(system_findings, "_process_is_root", lambda: False)
    monkeypatch.setattr(system_findings, "invoking_user_name", lambda: "alice")
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    argv = launch.calls[-1]
    from cleanix import config as config_mod

    assert argv[argv.index("--config") + 1] == str(config_mod.config_file_path())
    assert launch.requests[-1].invoking_user == "alice"


def test_cli_never_passes_allow_root(tmp_path, monkeypatch, capsys):
    import ast

    root = Path(cli.__file__).parent
    forbidden = {"allow_root", "quarantine_root", "backup_root"}
    for rel in ("cli.py", "core/review.py", "core/system_findings.py"):
        text = (root / rel).read_text(encoding="utf-8")
        assert not re.search(r"allow_root\s*=", text), rel
        assert "quarantine_root=" not in text and "backup_root=" not in text, rel
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.keyword):
                assert node.arg not in forbidden, (rel, node.arg)
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert not forbidden & {node.value.strip()}, (rel, node.value)
                assert "allow_root" not in node.value, (rel, node.value)
            if isinstance(node, ast.Name):
                assert node.id != "allow_root", rel
    seen = []
    real = actions.act

    def spy(items, config, **kw):
        seen.append((list(items), kw))
        return real(items, config, **kw)

    monkeypatch.setattr(actions, "act", spy)
    p, user = _user(tmp_path)
    _patch_scan(monkeypatch, [user, _sys()])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    launch = _install(monkeypatch, Launcher())
    code, out = _run(capsys, "--act-on", "big_files,orphan_files", "--execute", "--yes")
    assert code == 0 and seen and len(launch.calls) == 1
    for its, kw in seen:
        assert not kw.get("allow_root") and kw.get("quarantine_root") is None
        assert kw.get("backup_root") is None
        # the in-process batch never contains a system-wide item
        assert not any(i.requires_root for i in its)


def test_mixed_batch_history_mode_honest(tmp_path):
    def item(name):
        p = tmp_path / name
        p.write_bytes(b"z" * 10)
        return CleanableItem(cleaner_id="t", description=name, size=10, path=str(p))

    a, b = item("a"), item("b")
    service.clean([a, b], Config(), dry_run=False, use_quarantine=True,
                  delete_instead=lambda i: i is b)
    c = item("c")
    service.clean([c], Config(), dry_run=False, use_quarantine=True,
                  delete_instead=lambda i: True)
    d = item("d")
    service.clean([d], Config(), dry_run=False, use_quarantine=True,
                  delete_instead=lambda i: False)
    e = item("e")
    service.clean([e], Config(), dry_run=False, use_quarantine=True)  # plain clean
    f = item("f")
    service.clean([f], Config(), dry_run=False, use_quarantine=False)
    assert [x["mode"] for x in history.load()] == [
        "mixed", "delete", "quarantine", "quarantine", "delete"]


def test_jobs_only_headline_wording():
    text = cli._batch_text(0, 2, False, "would be")
    assert "quarantined" not in text and "stopped and removed permanently" in text
    assert cli._batch_text(3, 0, False, "will be") == "3 will be quarantined"
    assert cli._batch_text(1, 0, True, "would be") == "1 would be deleted permanently"
    # The job preview no longer names the quarantine root as the copy's place.
    job = CleanableItem(cleaner_id="orphan_launch_jobs", description="j", size=1,
                        path="/x/j.plist", report_only=True,
                        remedy=Remedy(kind=RemedyKind.LAUNCH_JOB, fingerprint=(1, 2, 3, 4)))
    line = review.undo_line(job, False)
    assert line == review.JOB_PLANNED and "location is shown after the run" in line
    assert str(quarantine.quarantine_root()) not in line


def test_backup_line_warns_about_quarantine_empty():
    line = review.backup_line("20261120-x")
    assert "cleanix quarantine empty" in line and "deletes these copies too" in line
    assert "does not bring them back" in line
    # the command really is spelled that way (parser) and purges every run
    parser = cli.build_parser()
    ns = parser.parse_args(["quarantine", "empty"])
    assert ns.quarantine_action == "empty"


def test_describe_undo_line_is_escaped(tmp_path, monkeypatch):
    from rich.console import Console

    monkeypatch.setattr(review, "undo_line", lambda item, permanent: "[bold]x[/] [oops")
    p, user = _user(tmp_path)
    c = Console(record=True, width=300, force_terminal=False)
    review.run(findings.group_findings(_scan([user])), lambda prompt: "s",
               lambda its, protect=None: None, c)
    assert "[bold]x[/] [oops" in c.export_text()


# --------------------------------------------------------------------------
# review
# --------------------------------------------------------------------------
def _scan(items):
    from cleanix.core.models import ScanResult

    by = {}
    for i in items:
        by.setdefault(i.cleaner_id, []).append(i)
    return ScanResult(reports=[CleanerReport(cleaner_id=c, name=c, description="t",
                                             items=its) for c, its in by.items()])


def _review(monkeypatch, capsys, answers, *argv):
    asked = []
    it = iter(answers)

    def ask(prompt):
        asked.append(prompt)
        a = next(it)
        if isinstance(a, type) and issubclass(a, BaseException):
            raise a
        return a

    monkeypatch.setattr(builtins, "input", ask)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    code = cli.main(["review", *argv])
    return code, " ".join(capsys.readouterr().out.split()), asked


def test_review_batches_system_items_once(tmp_path, monkeypatch, capsys):
    p, user = _user(tmp_path)
    s1, s2 = _sys("/opt/one"), _sys("/opt/two")
    _patch_scan(monkeypatch, [user, s1, s2])
    launch = _install(monkeypatch, Launcher(quarantine_run="rq"))
    code, out, asked = _review(monkeypatch, capsys, ["d", "d", "d", PHRASE],
                               "big_files", "orphan_files")
    assert code == 0 and not p.exists()
    assert len(launch.calls) == 1
    assert sorted(x.key for x in launch.requests[0].findings.items) == sorted(
        [item_key(s1), item_key(s2)])
    assert PHRASE in asked[-1] and len(asked) == 4
    assert "queued" in out and "cannot restore from it yet" in out
    assert "System-wide items chosen: 2" in out
    # a wrong phrase aborts the batch: exit 1, nothing launched
    _patch_scan(monkeypatch, [_sys("/opt/three")])
    code, out, asked = _review(monkeypatch, capsys, ["d", "nope"], "orphan_files")
    assert code == 1 and len(launch.calls) == 1 and "Aborted" in out


def test_review_no_per_item_elevation(tmp_path, monkeypatch, capsys):
    items = [_sys(f"/opt/s{i}") for i in range(3)]
    _patch_scan(monkeypatch, items)
    launch = _install(monkeypatch, Launcher())
    prompts_at_launch = []
    code_holder = {}

    def on_call():
        prompts_at_launch.append(len(code_holder["asked"]))

    launch.on_call = on_call
    asked = []
    answers = iter(["d", "q", PHRASE])

    def ask(prompt):
        asked.append(prompt)
        return next(answers)

    code_holder["asked"] = asked
    monkeypatch.setattr(builtins, "input", ask)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    code = cli.main(["review", "orphan_files"])
    out = " ".join(capsys.readouterr().out.split())
    # q stops the review; the ONE batch (one item) then runs after the phrase
    assert code == 0 and len(launch.calls) == 1 and prompts_at_launch == [3]
    assert len(launch.requests[0].findings.items) == 1
    # g queues the rest of the group at once: still one launch
    code, out, asked = _review(monkeypatch, capsys, ["g", PHRASE], "orphan_files")
    assert code == 0 and len(launch.calls) == 2
    assert len(launch.requests[1].findings.items) == 3
    # end of input: the collected items are never acted on
    code, out, asked = _review(monkeypatch, capsys, ["d", EOFError], "orphan_files")
    assert code == 1 and len(launch.calls) == 2
    assert "interrupted before the system-wide batch" in out


def test_review_lists_not_offered_system_items(tmp_path, monkeypatch, capsys):
    p, user = _user(tmp_path)
    root_big = CleanableItem(cleaner_id="big_files", description="root.bin", size=5,
                             path="/root/root.bin", report_only=True, requires_root=True,
                             remedy=Remedy(kind=RemedyKind.PATH, fingerprint=(1, 2, 3, 4)))
    _patch_scan(monkeypatch, [user, root_big])
    launch = _install(monkeypatch, Launcher())
    code, out, asked = _review(monkeypatch, capsys, ["s"], "big_files")
    assert code == 0 and len(asked) == 1 and launch.calls == []
    assert "root.bin: not offered: the administrator helper does not act on this " \
           "scenario" in out


# --------------------------------------------------------------------------
# fix round 1
# --------------------------------------------------------------------------
def test_root_quarantine_moves_free_nothing(tmp_path, monkeypatch, capsys):
    _patch_scan(monkeypatch, [_sys("/opt/a"), _sys("/opt/b")])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    _install(monkeypatch, Launcher(quarantine_run="rq"))
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 0
    assert ("moved 2 item(s) (200 B) into the root-only quarantine; no space was "
            "freed (there is no purge for it yet)") in out
    assert "freed 200 B" not in out
    assert [(e["mode"], e["freed"], e["items"]) for e in history.load()] == [
        ("administrator-quarantine", 0, 2)]
    assert history.stats()["total_freed"] == 0


def test_permanent_helper_batch_records_real_freed(tmp_path, monkeypatch, capsys):
    _patch_scan(monkeypatch, [_sys("/opt/a"), _sys("/opt/b")])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    _install(monkeypatch, Launcher())
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes",
                     "--permanent")
    assert code == 0 and "removed 2 item(s) permanently, freed 200 B" in out
    assert "into the root-only quarantine" not in out
    assert [(e["mode"], e["freed"], e["items"]) for e in history.load()] == [
        ("administrator", 200, 2)]


def test_mixed_helper_batch_history(tmp_path, monkeypatch, capsys):
    _patch_scan(monkeypatch, [_sys("/opt/a"), _job()])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    _install(monkeypatch, Launcher(quarantine_run="rq", backup_run="rb"))
    code, out = _run(capsys, "--act-on", "orphan_files,orphan_launch_jobs",
                     "--execute", "--yes")
    assert code == 0
    assert "removed 1 item(s) permanently, freed 100 B" in out
    assert "moved 1 item(s) (100 B) into the root-only quarantine" in out
    assert sorted((e["mode"], e["freed"], e["items"]) for e in history.load()) == [
        ("administrator", 100, 1), ("administrator-quarantine", 0, 1)]


def test_never_started_vs_unknown_outcome(tmp_path, monkeypatch, capsys):
    _patch_scan(monkeypatch, [_sys()])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    for exc in (elevate_launch.ElevationNotStarted(
                    "could not start the elevation prompt: [Errno 2] no such file"),
                elevate_launch.ElevationNotStarted("pkexec could not run the helper",
                                                   exit_code=127)):
        _install(monkeypatch, Launcher(write=False, exc=exc))
        code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
        assert code == 2
        assert ("the administrator helper did not run" in out.lower()
                and "none of the system-wide items was removed" in out)
        assert "unknown" not in out
    # the launcher's own failures map to the typed class
    real_run = elevate_launch._run
    monkeypatch.setattr(elevate_launch, "current_os", lambda: "linux")
    monkeypatch.setattr(elevate_launch.utils, "safe_which", lambda n: "/usr/bin/pkexec")
    monkeypatch.setattr(elevate_launch, "_run",
                        lambda argv, timeout: (127, "Error executing command"))
    with pytest.raises(elevate_launch.ElevationNotStarted):
        elevate_launch.launch_elevated([sys.executable, "-I"])

    def popen_fails(*a, **k):
        raise OSError(2, "No such file or directory")

    monkeypatch.setattr(elevate_launch.subprocess, "Popen", popen_fails)
    with pytest.raises(elevate_launch.ElevationNotStarted):
        real_run(["/nope"], 5)
    # still an ElevationFailed for every older caller
    assert issubclass(elevate_launch.ElevationNotStarted, elevate_launch.ElevationFailed)


def test_interrupt_during_launch_and_request_dir_error(tmp_path, monkeypatch, capsys):
    _patch_scan(monkeypatch, [_sys()])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    _install(monkeypatch, Launcher(write=False, exc=KeyboardInterrupt()))
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 2 and "may still be running; check before retrying" in out

    def no_dir():
        raise OSError(28, "No space left on device")

    launch = _install(monkeypatch, Launcher())
    monkeypatch.setattr(elevate, "make_request_dir", no_dir)
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 2 and launch.calls == []
    assert "could not be prepared" in out and "none of the system-wide items was removed" in out


def test_review_interrupt_during_launch_still_prints_summary(tmp_path, monkeypatch, capsys):
    p, user = _user(tmp_path)
    _patch_scan(monkeypatch, [user, _sys()])
    _install(monkeypatch, Launcher(write=False, exc=KeyboardInterrupt()))
    code, out, asked = _review(monkeypatch, capsys, ["d", "d", PHRASE],
                               "big_files", "orphan_files")
    assert code == 2 and not p.exists()
    assert "may still be running" in out and "Removed 1 item(s)" in out


def test_invalid_run_ids_are_never_printed(tmp_path, monkeypatch, capsys):
    # read_result validates both run ids with a strict regex: an invalid one
    # makes the whole result unreadable, so no path is ever joined/printed.
    _patch_scan(monkeypatch, [_sys()])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    for field in ("backup_run", "quarantine_run"):
        bad = "../../etc"
        kw = {field: bad}
        _install(monkeypatch, Launcher(**kw))
        code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
        assert code == 2 and "../../etc" not in out and "/etc/files" not in out
        assert "outcome is unknown" in out


def test_preview_and_non_tty_wording(tmp_path, monkeypatch, capsys):
    _patch_scan(monkeypatch, [_sys()])
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    code, out = _run(capsys, "--act-on", "orphan_files", "--yes")
    # A root process is never offered system-wide items (beta gate), so the
    # preview never promises a root shortcut past the typed phrase.
    assert f"after typing {PHRASE}" in out and "no typed confirmation" not in out
    monkeypatch.setattr(cli, "_is_root_process", lambda: False)
    code, out = _run(capsys, "--act-on", "orphan_files")
    assert f"after typing {PHRASE}" in out
    # non-TTY with --yes but not root: no "to act on" banner, just not done
    p, user = _user(tmp_path)
    _patch_scan(monkeypatch, [user, _sys()])
    code, out = _run(capsys, "--act-on", "big_files,orphan_files", "--execute", "--yes")
    assert code == 0 and "to act on with administrator rights" not in out
    assert "not done: needs a terminal to type the confirmation" in out
    # executing lists each offered item in full only once
    monkeypatch.setattr(cli, "_is_root_process", lambda: True)
    _patch_scan(monkeypatch, [_sys("/opt/only-once")])
    _install(monkeypatch, Launcher())
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert out.count("root-only quarantine you cannot restore from yet") == 1


# --------------------------------------------------------------------------
# fix round 2: the real prompt keeps the answer exactly as typed
# --------------------------------------------------------------------------
WRONG_SPACING = (" DELETE SYSTEM FILES", "DELETE SYSTEM FILES ", "\tDELETE SYSTEM FILES",
                 "Delete System Files", "delete system files", "DELETE  SYSTEM FILES",
                 "DELETE SYSTEM")


def test_real_prompt_phrase_is_exact_in_act_on(tmp_path, monkeypatch, capsys):
    _patch_scan(monkeypatch, [_sys()])
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    launch = _install(monkeypatch, Launcher())
    for wrong in WRONG_SPACING:
        # only builtins.input is replaced: console.input and the comparison
        # in _system_part are the real code
        monkeypatch.setattr(builtins, "input", lambda prompt="", w=wrong: w)
        code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
        assert code == 1 and launch.calls == [] and "Aborted" in out, repr(wrong)
    monkeypatch.setattr(builtins, "input", lambda prompt="": PHRASE)
    code, out = _run(capsys, "--act-on", "orphan_files", "--execute", "--yes")
    assert code == 0 and len(launch.calls) == 1


def test_real_prompt_phrase_is_exact_in_review(tmp_path, monkeypatch, capsys):
    _patch_scan(monkeypatch, [_sys()])
    launch = _install(monkeypatch, Launcher())
    for wrong in WRONG_SPACING:
        code, out, asked = _review(monkeypatch, capsys, ["d", wrong], "orphan_files")
        assert code == 1 and launch.calls == [] and "Aborted" in out, repr(wrong)
    code, out, asked = _review(monkeypatch, capsys, ["d", PHRASE], "orphan_files")
    assert code == 0 and len(launch.calls) == 1


def test_console_input_does_not_strip():
    import io

    from rich.console import Console

    c = Console(file=io.StringIO())
    assert c.input("x: ", markup=False, stream=io.StringIO(" A \n")) == " A \n"
