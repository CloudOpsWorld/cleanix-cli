"""GUI entry point. Qt is imported lazily so the CLI never needs PySide6."""

from __future__ import annotations

import os
import sys
from typing import Optional, Sequence

HINT = 'Install the GUI extra: pip install "cleanix-cli[gui]"'
ROOT_MESSAGE = ("Cleanix GUI must not run as root: it asks for administrator "
                "permission when needed")


class GuiUnavailable(Exception):
    pass


def require_qt() -> None:
    try:
        import PySide6  # noqa: F401
        from PySide6 import QtWidgets  # noqa: F401
    except ImportError as exc:
        raise GuiUnavailable(HINT) from exc


def running_as_root() -> bool:
    """POSIX: is the effective uid 0? (Windows has no geteuid: False.)"""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    try:
        return geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


def _error(text: str) -> None:
    # gui-scripts may have no console (sys.stderr is None): print is a no-op.
    if sys.stderr is not None:
        print(text, file=sys.stderr)


def main(argv: Optional[Sequence[str]] = None) -> int:
    # The GUI never runs as root: only the elevated helper does.
    if running_as_root():
        _error(ROOT_MESSAGE)
        return 1
    try:
        require_qt()
    except GuiUnavailable as exc:
        _error(str(exc))
        return 1
    from PySide6.QtWidgets import QApplication

    from cleanix.gui import theme
    from cleanix.gui.main_window import MainWindow

    args = list(sys.argv if argv is None else argv)
    app = QApplication.instance() or QApplication(args)
    app.setOrganizationName("Cleanix")
    app.setApplicationName("cleanix")
    theme.apply(app)
    window = MainWindow()
    window.show()
    return app.exec()
