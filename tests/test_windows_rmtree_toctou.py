"""I5: _win_rmtree re-checks each directory right before descending into it.

Simulates a local user swapping a listed subdirectory for a junction between
the listing and the descent (the elevated run must not follow it)."""

from __future__ import annotations

import os
import stat
import sys
from types import SimpleNamespace

import pytest

from cleanix.core import safety

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="tests the Windows-only _win_rmtree remover (reparse points, file ids)")

REPARSE = 0x400


def _tree(tmp_path):
    tree = tmp_path / "tree"
    sub = tree / "sub"
    sub.mkdir(parents=True)
    (sub / "keep.txt").write_text("x")
    (tree / "top.txt").write_text("y")
    return tree, sub


def test_descent_aborts_when_subdir_became_reparse_point(tmp_path, monkeypatch):
    tree, sub = _tree(tmp_path)
    real = safety._lstat

    def swapped(path):
        st = real(path)
        if os.path.normcase(str(path)) == os.path.normcase(str(sub)):
            return SimpleNamespace(
                st_file_attributes=st.st_file_attributes | REPARSE,
                st_ino=st.st_ino, st_dev=st.st_dev, st_mode=st.st_mode,
            )
        return st

    monkeypatch.setattr(safety, "_lstat", swapped)
    with pytest.raises(OSError, match="changed|reparse"):
        safety.safe_rmtree(tree)
    assert (sub / "keep.txt").exists()


def test_descent_aborts_when_subdir_identity_changed(tmp_path, monkeypatch):
    tree, sub = _tree(tmp_path)
    real = safety._entry_inode

    def other(entry):
        ino = real(entry)
        return ino + 1 if entry.name == "sub" else ino

    monkeypatch.setattr(safety, "_entry_inode", other)
    with pytest.raises(OSError, match="changed"):
        safety.safe_rmtree(tree)
    assert (sub / "keep.txt").exists()


def test_descent_aborts_when_subdir_became_file(tmp_path, monkeypatch):
    tree, sub = _tree(tmp_path)
    real = safety._lstat

    def as_file(path):
        st = real(path)
        if os.path.normcase(str(path)) == os.path.normcase(str(sub)):
            return SimpleNamespace(
                st_file_attributes=st.st_file_attributes & ~stat.FILE_ATTRIBUTE_DIRECTORY,
                st_ino=st.st_ino, st_dev=st.st_dev, st_mode=stat.S_IFREG,
            )
        return st

    monkeypatch.setattr(safety, "_lstat", as_file)
    with pytest.raises(OSError):
        safety.safe_rmtree(tree)
    assert (sub / "keep.txt").exists()


def test_unchanged_tree_still_removed(tmp_path):
    tree, _sub = _tree(tmp_path)
    safety.safe_rmtree(tree)
    assert not tree.exists()
