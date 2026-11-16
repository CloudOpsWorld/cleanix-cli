"""Theme: follow the OS light/dark scheme through Qt; no hard-coded colours except the accent."""

from __future__ import annotations

import sys

ACCENT = "#2e7d6b"


def apply(app) -> None:
    from PySide6.QtGui import QColor, QPalette

    if sys.platform.startswith("linux"):
        app.setStyle("Fusion")
    pal = app.palette()
    accent = QColor(ACCENT)
    pal.setColor(QPalette.ColorRole.Highlight, accent)
    pal.setColor(QPalette.ColorRole.Link, accent)
    app.setPalette(pal)
