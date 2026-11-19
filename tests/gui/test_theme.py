"""Theme palette must stay readable in dark and light schemes (macOS dark mode
showed pale alternating rows under white text)."""

from PySide6.QtGui import QColor, QPalette

from cleanix.gui import theme


def _palette(base: str, text: str, alt: str) -> QPalette:
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Base, QColor(base))
    pal.setColor(QPalette.ColorRole.Text, QColor(text))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(alt))
    return pal


def _lightness(pal, role):
    return pal.color(role).lightness()


def test_dark_scheme_alternate_base_stays_dark():
    # The macOS dark palette: dark base, white text, but a *light* alternate.
    pal = theme.readable_palette(_palette("#1e1e1e", "#ffffff", "#f0f0f0"))
    alt = _lightness(pal, QPalette.ColorRole.AlternateBase)
    assert alt < 100
    assert _lightness(pal, QPalette.ColorRole.Text) - alt > 120


def test_light_scheme_alternate_base_stays_light():
    pal = theme.readable_palette(_palette("#ffffff", "#000000", "#202020"))
    alt = _lightness(pal, QPalette.ColorRole.AlternateBase)
    assert alt > 155
    assert alt - _lightness(pal, QPalette.ColorRole.Text) > 120


def test_alternate_base_differs_slightly_from_base():
    pal = theme.readable_palette(_palette("#1e1e1e", "#ffffff", "#f0f0f0"))
    assert pal.color(QPalette.ColorRole.AlternateBase) != pal.color(QPalette.ColorRole.Base)


def _groups(n):
    from cleanix.core.curation import Group, Safety
    from cleanix.core.models import CleanableItem

    out = []
    for i in range(n):
        it = CleanableItem(cleaner_id="temp", description="x", size=10, path=f"/tmp/a{i}")
        out.append(Group(cleaner_id="temp", title=f"Group {i}", blurb="b", category="c",
                         safety=Safety.SAFE, items=[it], shown=[it], total_size=10))
    return out


def test_tree_height_fits_rows_instead_of_filling_the_page(qtbot):
    """A few result rows must not leave a screen-high striped blank area."""
    from cleanix.gui.grouped_results import GroupedResults

    tree = GroupedResults()
    qtbot.addWidget(tree)
    tree.show()
    tree.set_groups(_groups(3), lambda _i: False)
    few = tree.maximumHeight()
    assert few < 250
    tree.set_groups(_groups(80), lambda _i: False)
    many = tree.maximumHeight()
    assert few < many < 600  # grows with rows, but is capped (it scrolls inside)
