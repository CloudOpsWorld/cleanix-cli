"""`cleanix gui` without PySide6: the hint depends on how Cleanix was installed."""

import sys

import pytest

from cleanix import cli
from cleanix.gui import app


@pytest.fixture
def no_qt(monkeypatch):
    # A None entry makes "import PySide6" raise ImportError.
    monkeypatch.setitem(sys.modules, "PySide6", None)
    monkeypatch.setitem(sys.modules, "PySide6.QtWidgets", None)


def _gui_output(capsys):
    code = cli.main(["gui"])
    return code, " ".join(capsys.readouterr().out.split())


def test_gui_hint_in_frozen_build(monkeypatch, capsys, no_qt):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    code, out = _gui_output(capsys)
    assert code == 1
    assert "standalone binary does not include the desktop GUI" in out
    assert 'pip install --pre "cleanix-cli[gui]"' in out
    assert "Python 3.9+" in out
    assert "--no-compile" in out


def test_frozen_build_hint_even_for_a_final_release(monkeypatch, capsys, no_qt):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr("cleanix.__version__", "2.0.0")
    code, out = _gui_output(capsys)
    assert code == 1
    assert "standalone binary does not include the desktop GUI" in out


def test_pip_install_prerelease_adds_pre_hint(monkeypatch, capsys, no_qt):
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setattr("cleanix.__version__", "1.5.0b1")
    code, out = _gui_output(capsys)
    assert code == 1
    assert "Install the GUI extra" in out
    assert 'pip install "cleanix-cli[gui]"' in out
    assert 'pip install --pre "cleanix-cli[gui]"' in out
    assert "standalone" not in out


@pytest.mark.parametrize("version", ["1.5.0a2", "1.5.0b1", "2.0.0rc1"])
def test_prerelease_versions_detected(version):
    assert app._is_prerelease(version)


@pytest.mark.parametrize("version", ["1.5.0", "1.4.0", "10.0.12"])
def test_final_versions_are_not_prereleases(version):
    assert not app._is_prerelease(version)


def test_pip_install_final_release_keeps_the_plain_hint(monkeypatch, capsys, no_qt):
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setattr("cleanix.__version__", "1.5.0")
    code, out = _gui_output(capsys)
    assert code == 1
    assert 'pip install "cleanix-cli[gui]"' in out
    assert "--pre" not in out
    assert "standalone" not in out
