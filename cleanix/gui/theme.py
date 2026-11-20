"""Theme: follow the OS light/dark scheme through Qt; no hard-coded colours except the accent."""

from __future__ import annotations

import sys

ACCENT = "#2e7d6b"


def readable_palette(pal):
    """Return ``pal`` with an ``AlternateBase`` that matches the scheme.

    Copying ``app.palette()`` back with ``setPalette`` freezes it; on macOS dark
    mode that left a light alternate-row colour under white text. Derive the
    alternate row from ``Base`` instead, a little lighter on dark schemes and a
    little darker on light ones, so text keeps its contrast on every row.
    """
    from PySide6.QtGui import QPalette

    base = pal.color(QPalette.ColorRole.Base)
    text = pal.color(QPalette.ColorRole.Text)
    dark = base.lightness() < text.lightness()
    alt = base.lighter(118) if dark else base.darker(106)
    pal.setColor(QPalette.ColorRole.AlternateBase, alt)
    return pal


def apply(app) -> None:
    from PySide6.QtGui import QColor, QPalette

    if sys.platform.startswith("linux"):
        app.setStyle("Fusion")
    pal = readable_palette(app.palette())
    accent = QColor(ACCENT)
    pal.setColor(QPalette.ColorRole.Highlight, accent)
    pal.setColor(QPalette.ColorRole.Link, accent)
    app.setPalette(pal)
