"""GUI entry point. Qt is imported lazily so the CLI never needs PySide6."""

from __future__ import annotations

import sys
from typing import Optional, Sequence

HINT = 'Install the GUI extra: pip install "cleanix-cli[gui]"'


class GuiUnavailable(Exception):
    pass


def require_qt() -> None:
    try:
        import PySide6  # noqa: F401
        from PySide6 import QtWidgets  # noqa: F401
    except ImportError as exc:
        raise GuiUnavailable(HINT) from exc


def main(argv: Optional[Sequence[str]] = None) -> int:
    require_qt()
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
