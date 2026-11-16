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


def _short(path):
    import ctypes

    buf = ctypes.create_unicode_buffer(2048)
    n = ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, 2048)
    return buf.value if n else str(path)


def _needs_short(path):
    short = _short(path)
    if short.lower() == str(path).lower():
        pytest.skip("8.3 short names are disabled/unavailable for " + str(path))
    return short


def test_short_name_cannot_bypass_user_glob(tmp_path):
    prot = tmp_path / "ProtectedLongFolderName"
    inner = prot / "ImportantSubFolder"
    inner.mkdir(parents=True)
    short = _needs_short(inner)
    assert short.lower() != str(inner).lower()
    safety.set_protected_globs([str(inner)])   # exact path: last component must be expanded
    try:
        assert not safety.is_safe_to_delete(str(inner))          # long name
        assert not safety.is_safe_to_delete(short)               # short in parent and last
        with pytest.raises(safety.UnsafePathError):
            safety.safe_rmtree(short)
        # short name in the PARENT only (glob on a child of the long-named folder)
        child = prot / "ChildLongFolderName"
        child.mkdir()
        safety.set_protected_globs([str(child)])
        assert not safety.is_safe_to_delete(os.path.join(os.path.dirname(short), "ChildLongFolderName"))
    finally:
        safety.set_protected_globs([])
    assert inner.exists()


def test_short_name_cannot_bypass_user_folders():
    home = os.path.expanduser("~")
    tried = 0
    for name in ("Documents", "Pictures", "Downloads"):
        long_p = os.path.join(home, name)
        if not os.path.isdir(long_p):
            continue
        short = _short(long_p)
        if short.lower() == long_p.lower():
            continue
        tried += 1
        assert short != long_p
        assert not safety.is_safe_to_delete(long_p)
        assert not safety.is_safe_to_delete(short), short
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    short_pf = _short(pf)
    if short_pf.lower() != pf.lower():
        tried += 1
        assert not safety.is_safe_to_delete(short_pf), short_pf
    if not tried:
        pytest.skip("no 8.3 aliases exist for user folders / Program Files on this machine")


def _mk_junction(link, target):
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("cannot create junction")


def test_junction_with_short_name_removed_as_link_only(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("x")
    link = tmp_path / "JunctionWithLongName"
    _mk_junction(link, target)
    short = _needs_short(link)
    assert short.lower() != str(link).lower()
    safety.safe_rmtree(short)
    assert not os.path.lexists(link)
    assert (target / "keep.txt").exists()


def test_glob_protected_junction_refused_by_short_name(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("x")
    link = tmp_path / "JunctionWithLongName"
    _mk_junction(link, target)
    short = _needs_short(link)
    assert short.lower() != str(link).lower()
    safety.set_protected_globs([str(link)])
    try:
        with pytest.raises(safety.UnsafePathError):
            safety.safe_rmtree(short)
    finally:
        safety.set_protected_globs([])
    assert os.path.lexists(link) and (target / "keep.txt").exists()


_SUFFIXES = ["::$INDEX_ALLOCATION", ":x", "::$INDEX_ALLOCATION.", ":x:$DATA", " ", "."]


@pytest.mark.parametrize("suffix", _SUFFIXES)
def test_short_name_plus_stream_suffix_cannot_bypass_glob(tmp_path, suffix):
    prot = tmp_path / "ProtectedLongFolderName"
    inner = prot / "ImportantSubFolder"
    inner.mkdir(parents=True)
    (inner / "data.txt").write_text("x")
    short = _needs_short(inner)
    assert short.lower() != str(inner).lower()
    safety.set_protected_globs([str(inner)])
    try:
        assert not safety.is_safe_to_delete(short + suffix)
        with pytest.raises(safety.UnsafePathError):
            safety.safe_rmtree(short + suffix)
    finally:
        safety.set_protected_globs([])
    assert (inner / "data.txt").exists()


@pytest.mark.parametrize("suffix", _SUFFIXES)
def test_short_name_plus_stream_suffix_cannot_bypass_builtin(suffix):
    home = os.path.expanduser("~")
    cands = [os.path.join(home, n) for n in ("Documents", "Pictures", "Downloads")]
    cands.append(os.environ.get("ProgramFiles", r"C:\Program Files"))
    tried = 0
    for long_p in cands:
        if not os.path.isdir(long_p):
            continue
        short = _short(long_p)
        if short.lower() == long_p.lower():
            continue
        tried += 1
        assert short != long_p
        assert not safety.is_safe_to_delete(short + suffix), short + suffix
    if not tried:
        pytest.skip("no 8.3 aliases exist for user folders / Program Files on this machine")


def test_link_check_fails_closed_in_walk(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("x")
    tree = tmp_path / "tree"
    tree.mkdir()
    j = tree / "j"
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(j), str(target)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("cannot create junction")
    real = safety._entry_stat

    def boom(entry):
        if entry.name == "j":
            raise OSError("simulated stat failure")
        return real(entry)

    monkeypatch.setattr(safety, "_entry_stat", boom)
    with pytest.raises(OSError):
        safety.safe_rmtree(tree)
    assert (target / "keep.txt").exists()


def test_link_check_fails_closed_at_top_level(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("x")
    j = tmp_path / "j"
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(j), str(target)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("cannot create junction")
    real = safety._lstat

    def boom(path):
        if os.path.basename(str(path)) == "j":
            raise PermissionError("simulated lstat failure")
        return real(path)

    monkeypatch.setattr(safety, "_lstat", boom)
    with pytest.raises(OSError):
        safety.safe_rmtree(j)
    assert (target / "keep.txt").exists()


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
