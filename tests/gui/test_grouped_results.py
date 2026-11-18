import time

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import Qt  # noqa: E402

from cleanix.core.curation import Group, Safety  # noqa: E402
from cleanix.core.models import CleanableItem, ItemKind, item_key  # noqa: E402
from cleanix.core.utils import human_size  # noqa: E402
from cleanix.gui import elevation  # noqa: E402
from cleanix.gui.grouped_results import GroupedResults  # noqa: E402

MB = 1024 * 1024
HOME = "/home/ann"


def mk(cid, n, size, **kw):
    kw.setdefault("path", f"{HOME}/.cache/{cid}/f{n}")
    return CleanableItem(cleaner_id=cid, description=f"{cid}: file {n}",
                         size=size, **kw)


def group(cid="user_cache", n=20, top_n=5, zero=3, safety=Safety.SAFE, title=None,
          **kw):
    nz = [mk(cid, i, (n - i) * MB, **kw) for i in range(n)]
    zr = [mk(cid, n + i, 0, **kw) for i in range(zero)]
    items = nz + zr
    return Group(cleaner_id=cid, title=title or cid.title(), blurb=f"blurb {cid}",
                 category="apps", safety=safety, items=items, shown=nz[:top_n],
                 rest=nz[top_n:], zero=zr, total_size=sum(i.size for i in items))


def make(qtbot, groups, preselect=lambda i: False, **kw):
    w = GroupedResults(**kw)
    qtbot.addWidget(w)
    w.set_groups(groups, preselect)
    return w


def top(w, row):
    return w.topLevelItem(row)


def test_groups_sorted_and_badged(qtbot):
    gs = [group("a", n=3, top_n=3, zero=0, title="Alpha"),
          group("b", n=2, top_n=2, zero=0, safety=Safety.REVIEW, title="Beta")]
    w = make(qtbot, gs)
    assert w.topLevelItemCount() == 2 == w.group_count()
    assert top(w, 0).text(0) == "Alpha"
    assert top(w, 0).text(2) == "Safe"
    assert top(w, 1).text(2) == "Review"
    assert top(w, 0).text(3) == "3"
    assert top(w, 0).text(4) == human_size(6 * MB)
    assert top(w, 0).text(1) == "blurb a"
    assert w.accessibleName()


def test_group_tick_selects_collapsed_and_zero_items(qtbot):
    g = group()
    w = make(qtbot, [g])
    seen = []
    w.selection_changed.connect(lambda: seen.append(1))
    top(w, 0).setCheckState(0, Qt.CheckState.Checked)
    assert len(w.checked_items()) == g.item_count == 23
    assert w.checked_size() == g.total_size
    assert seen
    top(w, 0).setCheckState(0, Qt.CheckState.Unchecked)
    assert w.checked_items() == []


def test_untick_child_makes_group_partial(qtbot):
    g = group()
    w = make(qtbot, [g], preselect=lambda i: True)
    assert top(w, 0).checkState(0) == Qt.CheckState.Checked
    top(w, 0).setExpanded(True)
    child = top(w, 0).child(0)
    child.setCheckState(0, Qt.CheckState.Unchecked)
    assert top(w, 0).checkState(0) == Qt.CheckState.PartiallyChecked
    assert len(w.checked_items()) == g.item_count - 1


def test_report_only_group_has_no_tick(qtbot):
    g = group("big_files", n=3, top_n=3, zero=0, safety=Safety.REVIEW,
              report_only=True)
    w = make(qtbot, [g], preselect=lambda i: True)
    it = top(w, 0)
    assert it.data(0, Qt.ItemDataRole.CheckStateRole) is None
    assert it.text(1)  # reason shown as description
    assert w.checked_items() == []
    assert w.checked_size() == 0


def test_admin_refused_item_not_selectable(qtbot, monkeypatch):
    g = group("apt", n=3, top_n=3, zero=0, safety=Safety.ADMIN, requires_root=True)
    refused = g.items[0]
    monkeypatch.setattr(elevation, "admin_problems",
                        lambda items: {id(refused): "helper refuses this"})
    w = make(qtbot, [g], preselect=lambda i: True)  # allow_admin_items False
    assert w.checked_items() == []
    assert top(w, 0).data(0, Qt.ItemDataRole.CheckStateRole) is None
    assert w.refusal_reason(refused)

    w2 = make(qtbot, [g], preselect=lambda i: True, allow_admin_items=True)
    assert refused not in w2.checked_items()
    assert len(w2.checked_items()) == 2
    assert w2.refusal_reason(refused) == "helper refuses this"
    assert w2.refusal_reason(g.items[1]) is None
    w2.set_checked_keys([item_key(refused)])
    assert w2.checked_items() == []


def test_children_lazy(qtbot):
    g = group(n=5000, top_n=15, zero=0)
    w = make(qtbot, [g], preselect=lambda i: True)
    assert top(w, 0).childCount() == 0
    t0 = time.perf_counter()
    top(w, 0).setExpanded(True)
    assert time.perf_counter() - t0 < 2
    assert top(w, 0).childCount() == 16  # 15 shown + rest row
    assert len(w.checked_items()) == 5000


def test_rest_row_show_all(qtbot):
    g = group(n=20, top_n=5, zero=0)
    w = make(qtbot, [g])
    top(w, 0).setExpanded(True)
    rest = top(w, 0).child(5)
    assert rest.text(0) == "15 smaller items · " + human_size(g.rest_size)
    rest.setCheckState(0, Qt.CheckState.Checked)
    assert len(w.checked_items()) == 15
    assert top(w, 0).checkState(0) == Qt.CheckState.PartiallyChecked
    w.show_all(top(w, 0))
    assert top(w, 0).childCount() == 20
    assert len(w.checked_items()) == 15


def test_set_checked_keys_roundtrip(qtbot):
    g = group()
    w = make(qtbot, [g])
    keys = {item_key(g.items[0]), item_key(g.rest[0]), "bogus"}
    w.set_checked_keys(keys)
    assert w.checked_keys() == keys - {"bogus"}
    assert top(w, 0).checkState(0) == Qt.CheckState.PartiallyChecked
    top(w, 0).setExpanded(True)
    assert top(w, 0).child(0).checkState(0) == Qt.CheckState.Checked
    assert top(w, 0).child(1).checkState(0) == Qt.CheckState.Unchecked


def test_raw_items_visible_includes_zero(qtbot):
    g = group(n=3, top_n=3, zero=2)
    w = make(qtbot, [g])
    top(w, 0).setExpanded(True)
    assert top(w, 0).childCount() == 3
    w.set_raw_items_visible(True)
    assert top(w, 0).childCount() == 5


def test_tooltip_has_full_path_and_label_uses_tilde(qtbot):
    g = group(n=2, top_n=2, zero=0)
    w = make(qtbot, [g], home=HOME)
    top(w, 0).setExpanded(True)
    child = top(w, 0).child(0)
    assert HOME in child.toolTip(0)
    assert HOME not in child.text(1)
    assert child.text(1).startswith("~")
    assert child.text(0) == "file 0"


def test_empty_groups_shows_nothing_without_error(qtbot):
    w = make(qtbot, [])
    assert w.topLevelItemCount() == 0
    assert w.checked_items() == [] and w.checked_size() == 0
    w.set_checked_keys(["x"])
    assert w.checked_keys() == set()
