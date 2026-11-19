"""Curation layer: plain copy, safety levels, path display, grouping."""

from __future__ import annotations

import subprocess
import sys

from cleanix.config import Config
from cleanix.core import catalog, registry
from cleanix.core.catalog import CleanerInfo, category_of
from cleanix.core.curation import (
    COPY,
    Safety,
    build_groups,
    copy_for,
    display_label,
    is_empty,
    safety_of,
    shorten_path,
)
from cleanix.core.models import (
    CleanableItem,
    CleanerReport,
    ItemKind,
    ScanResult,
)


def _info(cid="x", *, safe_default=False, requires_root=False, category="dev"):
    return CleanerInfo(
        id=cid, name=cid, description="", requires_root=requires_root,
        platforms=(), supported=True, default_enabled=True,
        safe_default=safe_default, category=category,
    )


def _path_item(cid="x", desc="d", size=1, **kw):
    return CleanableItem(cleaner_id=cid, description=desc, size=size,
                         path=f"/tmp/{desc}-{size}", **kw)


def test_safety_precedence():
    info = _info(safe_default=True)
    assert safety_of(_path_item(report_only=True, requires_root=True), info) is Safety.REVIEW
    assert safety_of(_path_item(requires_root=True), info) is Safety.ADMIN
    cmd = CleanableItem(cleaner_id="x", description="c", kind=ItemKind.COMMAND,
                        command=["echo"])
    assert safety_of(cmd, info) is Safety.PERMANENT
    assert safety_of(_path_item(), info) is Safety.SAFE
    assert safety_of(_path_item(), _info(safe_default=False)) is Safety.REVIEW
    assert safety_of(_path_item(), None) is Safety.REVIEW


def test_shorten_path_boundary():
    assert shorten_path(r"C:\Users\bob\AppData\x", r"C:\Users\bob") == r"~\AppData\x"
    assert shorten_path(r"C:\Users\bob2\x", r"C:\Users\bob") == r"C:\Users\bob2\x"
    assert shorten_path(r"c:\users\BOB\x", r"C:\Users\bob") == r"~\x"
    assert shorten_path("/home/a/.cache", "/home/a") == "~/.cache"
    assert shorten_path("/home/ab/x", "/home/a") == "/home/ab/x"
    assert shorten_path("/home/a/x", None) == "/home/a/x"
    assert shorten_path("/home/a", "/home/a") == "~"


def test_display_label_strips_prefix():
    assert display_label(_path_item(desc="Temp: a.tmp"), None) == "a.tmp"
    assert display_label(_path_item(desc="Temp:"), None) == "Temp:"


def test_display_label_path_and_command():
    it = CleanableItem(cleaner_id="x", description="", size=1,
                       path="/home/a/.cache/z")
    assert display_label(it, "/home/a") == "~/.cache/z"
    cmd = CleanableItem(cleaner_id="x", description="Run", kind=ItemKind.COMMAND,
                        command=["apt-get", "clean"])
    assert display_label(cmd, None) == "apt-get clean"


def _result(items, cid="x", name="X"):
    return ScanResult(reports=[CleanerReport(cleaner_id=cid, name=name,
                                             description="desc", items=items)])


def test_build_groups_topn_and_collapse():
    items = [_path_item(desc=f"f{i}", size=(i % 50)) for i in range(440)]
    g = build_groups(_result(items), {"x": _info(safe_default=True)})[0]
    assert len(g.shown) == 15
    assert [i.size for i in g.shown] == sorted((i.size for i in g.shown), reverse=True)
    assert all(i.size > 0 for i in g.rest)
    assert all(i.size == 0 for i in g.zero)
    assert g.total_size == sum(i.size for i in items)
    assert len(g.shown) + len(g.rest) + len(g.zero) == len(g.items) == 440
    assert g.item_count == 440
    assert g.rest_size == sum(i.size for i in g.rest)
    assert g.items == sorted(g.items, key=lambda i: -i.size)


def test_zero_only_group_hidden():
    items = [_path_item(desc="a", size=0), _path_item(desc="b", size=0)]
    infos = {"x": _info()}
    assert build_groups(_result(items), infos) == []
    g = build_groups(_result(items), infos, show_empty=True)
    assert len(g) == 1 and g[0].shown == [] and len(g[0].zero) == 2


def _ro_item(desc="note", size=0, cid="x"):
    return CleanableItem(cleaner_id=cid, description=desc, size=size,
                         path=f"/opt/{desc}", report_only=True, hint="check it")


def test_zero_size_report_only_group_stays_visible():
    g = build_groups(_result([_ro_item("a"), _ro_item("b")]), {"x": _info()})
    assert len(g) == 1
    assert len(g[0].shown) == 2 and g[0].zero == []
    assert g[0].safety is Safety.REVIEW


def test_report_only_zero_is_not_empty_but_plain_zero_still_is():
    assert not is_empty(_ro_item())
    assert is_empty(_path_item(size=0))


def test_zero_size_non_report_only_group_still_hidden():
    items = [_path_item(desc="a", size=0), _path_item(desc="b", size=0)]
    assert build_groups(_result(items), {"x": _info()}) == []


def test_mixed_group_keeps_zero_report_only_among_shown():
    items = [_path_item(desc="big", size=9), _ro_item("note"),
             _path_item(desc="z", size=0)]
    g = build_groups(_result(items), {"x": _info()})[0]
    assert [i.description for i in g.shown] == ["big", "note"]
    assert [i.description for i in g.zero] == ["z"]


def _cmd_item(size=0, cid="x"):
    return CleanableItem(cleaner_id=cid, description="Empty the Recycle Bin",
                         size=size, kind=ItemKind.COMMAND, command=["empty-bin"])


def test_command_item_size_zero_is_never_empty():
    assert not is_empty(_cmd_item(0))
    assert is_empty(_path_item(size=0))
    assert not is_empty(_path_item(size=1))


def test_command_only_zero_group_visible_without_show_empty():
    g = build_groups(_result([_cmd_item(0)]), {"x": _info()})
    assert len(g) == 1
    assert len(g[0].shown) == 1 and g[0].zero == []


def test_command_zero_sorts_after_sized_items_but_stays_visible():
    items = [_path_item(desc="a", size=0), _cmd_item(0), _path_item(desc="b", size=5)]
    g = build_groups(_result(items), {"x": _info()})[0]
    assert [i.size for i in g.shown] == [5, 0]
    assert g.shown[1].kind is ItemKind.COMMAND
    assert [i.kind for i in g.zero] == [ItemKind.PATH]


def test_empty_report_omitted():
    assert build_groups(_result([]), {}, show_empty=True) == []


def test_group_safety_most_restrictive():
    infos = {"x": _info(safe_default=True)}
    safe = _path_item(desc="s", size=1)
    admin = _path_item(desc="a", size=2, requires_root=True)
    assert build_groups(_result([safe]), infos)[0].safety is Safety.SAFE
    assert build_groups(_result([safe, admin]), infos)[0].safety is Safety.ADMIN
    cmd = CleanableItem(cleaner_id="x", description="c", size=1,
                        kind=ItemKind.COMMAND, command=["a"])
    assert build_groups(_result([safe, admin, cmd]), infos)[0].safety is Safety.PERMANENT


def test_groups_sorted_by_size_desc():
    r = ScanResult(reports=[
        CleanerReport("a", "A", "", [_path_item("a", "p", 1)]),
        CleanerReport("b", "B", "", [_path_item("b", "q", 9)]),
    ])
    assert [g.cleaner_id for g in build_groups(r, {})] == ["b", "a"]


def test_unknown_cleaner_falls_back():
    assert "zz_unknown" not in COPY
    c = copy_for("zz_unknown", "Zed", "Zed things")
    assert (c.title, c.blurb) == ("Zed", "Zed things")
    g = build_groups(_result([_path_item("zz_unknown", size=3)], "zz_unknown", "Zed"), {})[0]
    assert g.title == "Zed" and g.safety is Safety.REVIEW


def _all_ids():
    ids = {i.id for i in catalog.list_cleaners(Config(), include_unsupported=True)}
    return ids | set(registry.known_ids())


def test_every_registered_cleaner_has_copy():
    missing = sorted(i for i in _all_ids() if i not in COPY)
    assert not missing
    for cid, c in COPY.items():
        assert 0 < len(c.title) <= 40, cid
        assert c.blurb.endswith("."), cid


def test_no_cleaner_in_other_category():
    assert [i for i in _all_ids() if category_of(i) == "other"] == []


def test_curation_imports_without_qt():
    code = (
        "import sys\n"
        "class B:\n"
        "    def find_spec(self, n, p=None, t=None):\n"
        "        if n.split('.')[0] in ('PySide6','shiboken6'):\n"
        "            raise ImportError('blocked')\n"
        "sys.meta_path.insert(0, B())\n"
        "import cleanix.core.curation\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_will_not_delete_copy_only_on_report_only_cleaners():
    import inspect

    cleaners = registry.describe_all(Config())
    flagged = [cid for cid, c in COPY.items() if "will not delete" in c.blurb]
    assert flagged
    for cid in flagged:
        assert cid in cleaners, cid
        src = "".join(
            inspect.getsource(k) for k in type(cleaners[cid]).__mro__
            if k.__name__ not in ("Cleaner", "ABC", "object"))
        assert "report_item(" in src or "report_only=True" in src, cid


def test_preselectable_cleaner_ids_are_pinned():
    pinned = {
        "temp", "win_temp", "browsers", "win_browser_cache", "dev_caches",
        "pip_cache", "npm_cache", "lang_caches", "win_pkg_caches",
        "win_visualstudio", "jetbrains", "user_cache", "thumbnails",
        "win_thumbnails", "win_error_reports", "electron_cache",
        "gpu_shader_cache", "win_shader_cache",
    }
    infos = catalog.list_cleaners(Config(), include_unsupported=True)
    eligible = {i.id for i in infos
                if i.safe_default and i.category not in catalog._NEVER_PRESELECT}
    assert eligible == pinned
