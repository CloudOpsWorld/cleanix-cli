"""Windows-only integration tests for the deletion layer."""

import os
import stat
import subprocess
import sys

import pytest

from cleanix.core import safety
from cleanix.core.engine import Engine
from cleanix.core.models import CleanableItem

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")


def test_drive_root_refused():
    assert safety.is_safe_to_delete("/") is False
    assert safety.is_safe_to_delete("C:\\") is False
    assert safety.is_safe_to_delete("C:/") is False


def test_short_name_cannot_bypass():
    import ctypes

    root = os.path.expandvars(r"%SystemRoot%")
    buf = ctypes.create_unicode_buffer(1024)
    n = ctypes.windll.kernel32.GetShortPathNameW(root, buf, 1024)
    spellings = [root.upper(), root.lower(), root.replace("\\", "/")]
    if n:
        spellings.append(buf.value)
    for s in spellings:
        assert safety.is_safe_to_delete(s) is False, s


def test_is_reparse_point_false_for_plain(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    assert safety.is_reparse_point(d) is False
    assert safety.is_reparse_point(tmp_path / "missing") is False


def test_junction_removed_as_link_only(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("x")
    link = tmp_path / "link"
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"cannot create junction: {r.stderr or r.stdout}")
    assert safety.is_reparse_point(link)
    safety.safe_rmtree(link)
    assert not os.path.lexists(link)
    assert (target / "keep.txt").exists()


def test_nested_junction_not_followed(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("x")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "f.txt").write_text("y")
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(tree / "j"), str(target)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("cannot create junction")
    safety.safe_rmtree(tree)
    assert not tree.exists()
    assert (target / "keep.txt").exists()


def test_dir_symlink_removed_as_link_only(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("x")
    link = tmp_path / "link"
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation not permitted")
    safety.safe_rmtree(link)
    assert not os.path.lexists(link)
    assert (target / "keep.txt").exists()


def test_readonly_file_removed(tmp_path):
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    f = tree / "sub" / "ro.txt"
    f.write_text("x")
    os.chmod(f, stat.S_IREAD)
    safety.safe_rmtree(tree)
    assert not tree.exists()


def test_readonly_file_unlink(tmp_path):
    f = tmp_path / "ro.txt"
    f.write_text("x")
    os.chmod(f, stat.S_IREAD)
    safety.safe_unlink(f)
    assert not f.exists()


def test_locked_file_reports_error_not_crash(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    f = tree / "locked.txt"
    f.write_text("x")
    item = CleanableItem(cleaner_id="t", description="t", size=1, path=str(tree))
    with open(f, "rb"):
        with pytest.raises(OSError):
            safety.safe_rmtree(tree)
        result = Engine([]).clean([item], dry_run=False)
    assert result.outcomes[0].error
