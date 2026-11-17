import re
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


def test_require_qt_raises_hint_when_pyside6_is_missing(monkeypatch):
    import pytest

    from cleanix.gui import app

    # A None entry makes "import PySide6" raise ImportError, as if not installed.
    monkeypatch.setitem(sys.modules, "PySide6", None)
    monkeypatch.setitem(sys.modules, "PySide6.QtWidgets", None)
    with pytest.raises(app.GuiUnavailable) as exc:
        app.require_qt()
    assert 'pip install "cleanix-cli[gui]"' in str(exc.value)
    assert isinstance(exc.value.__cause__, ImportError)


def test_cmd_gui_without_real_pyside6_prints_hint(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "PySide6", None)
    monkeypatch.setitem(sys.modules, "PySide6.QtWidgets", None)
    assert cli.main(["gui"]) == 1
    assert "Install the GUI extra" in capsys.readouterr().out


def test_completion_scripts_offer_gui_command():
    from cleanix.completion import SUBCOMMANDS, generate

    assert "gui" in SUBCOMMANDS
    for shell in ("bash", "zsh", "fish"):
        # Whole token: "guix" (a cleaner id) must not count.
        assert "gui" in re.split(r'[\s"()]+', generate(shell)), shell


def test_cmd_gui_without_qt_prints_hint(monkeypatch, capsys):
    from cleanix.gui import app

    def boom():
        raise app.GuiUnavailable('Install the GUI extra: pip install "cleanix-cli[gui]"')

    monkeypatch.setattr(app, "require_qt", boom)
    assert cli.main(["gui"]) == 1
    out = capsys.readouterr().out
    assert "Install the GUI extra" in out
