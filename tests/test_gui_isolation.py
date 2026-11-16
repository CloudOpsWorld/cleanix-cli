import subprocess
import sys

from cleanix import cli


def test_cleanix_cli_does_not_import_pyside6():
    code = "import sys, cleanix.cli; assert 'PySide6' not in sys.modules"
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_gui_package_does_not_import_pyside6():
    code = "import sys, cleanix.gui; assert 'PySide6' not in sys.modules"
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_cmd_gui_without_qt_prints_hint(monkeypatch, capsys):
    from cleanix.gui import app

    def boom():
        raise app.GuiUnavailable('Install the GUI extra: pip install "cleanix-cli[gui]"')

    monkeypatch.setattr(app, "require_qt", boom)
    assert cli.main(["gui"]) == 1
    out = capsys.readouterr().out
    assert "Install the GUI extra" in out
