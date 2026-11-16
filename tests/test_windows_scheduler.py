"""Windows Task Scheduler backend (runs on any OS; subprocess is mocked)."""

import subprocess
from types import SimpleNamespace

import pytest

from cleanix import scheduler
from cleanix.scheduler import schtasks

EXE = r"C:\Program Files\Cleanix\cleanix.exe"
REPORT = r"C:\Users\Zoë Müller\AppData\Local\cleanix\last-scan.json"


def _arg_after(args, flag):
    return args[args.index(flag) + 1]


def test_backend_selects_schtasks_on_windows(monkeypatch):
    monkeypatch.setattr(scheduler, "is_windows", lambda: True)
    assert scheduler.backend().__name__.endswith("schtasks")


def test_create_args_quote_paths_with_spaces_and_unicode():
    args = schtasks.build_create_args("daily", EXE, REPORT)
    tr = _arg_after(args, "/TR")
    assert tr == f'"{EXE}" scan --json --output "{REPORT}"'
    assert args[:4] == ["schtasks", "/Create", "/TN", "Cleanix Scan"]
    assert _arg_after(args, "/SC") == "DAILY"
    assert _arg_after(args, "/ST") == "03:00"
    assert args[-1] == "/F"


def test_create_args_never_use_system_account():
    args = schtasks.build_create_args("weekly", EXE, REPORT)
    assert "/RU" not in args
    assert _arg_after(args, "/RL") == "LIMITED"


def test_hourly_has_no_start_time():
    args = schtasks.build_create_args("hourly", EXE, REPORT)
    assert "/ST" not in args
    assert _arg_after(args, "/SC") == "HOURLY"


def test_weekly_and_monthly_pin_the_day():
    weekly = schtasks.build_create_args("weekly", EXE, REPORT)
    assert _arg_after(weekly, "/D") == "SUN"
    monthly = schtasks.build_create_args("monthly", EXE, REPORT)
    assert _arg_after(monthly, "/D") == "1"
    assert "/D" not in schtasks.build_create_args("daily", EXE, REPORT)


def test_unknown_frequency_raises_value_error():
    with pytest.raises(ValueError):
        schtasks.build_create_args("yearly", EXE, REPORT)


def test_overlong_command_raises():
    long_exe = "C:\\" + "a" * 300 + "\\cleanix.exe"
    with pytest.raises(ValueError, match="261"):
        schtasks.build_create_args("daily", long_exe, REPORT)


def _record(monkeypatch, code=0, stdout="", stderr=""):
    calls = []

    def fake_run(argv, *a, **k):
        calls.append(argv)
        return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_install_calls_schtasks(monkeypatch, tmp_path):
    monkeypatch.setattr(schtasks.history, "state_dir", lambda: tmp_path)
    calls = _record(monkeypatch)
    msg = schtasks.install("daily")
    assert calls and calls[0][:2] == ["schtasks", "/Create"]
    assert _arg_after(calls[0], "/SC") == "DAILY"
    assert str(tmp_path / "last-scan.json") in _arg_after(calls[0], "/TR")
    assert "daily" in msg


def test_install_failure_raises_with_stderr(monkeypatch, tmp_path):
    monkeypatch.setattr(schtasks.history, "state_dir", lambda: tmp_path)
    _record(monkeypatch, code=1, stderr="ERROR: Access is denied.")
    with pytest.raises(RuntimeError, match="Access is denied"):
        schtasks.install("daily")


def test_uninstall_and_status_when_absent(monkeypatch):
    calls = _record(monkeypatch, code=1)
    assert "not installed" in schtasks.status()
    assert calls[-1] == ["schtasks", "/Query", "/TN", "Cleanix Scan"]
    assert "Nothing to remove" in schtasks.uninstall()
    assert calls[-1] == ["schtasks", "/Delete", "/TN", "Cleanix Scan", "/F"]


def test_uninstall_and_status_when_present(monkeypatch):
    _record(monkeypatch, code=0)
    assert "installed (Task Scheduler)" in schtasks.status()
    assert "Removed" in schtasks.uninstall()
