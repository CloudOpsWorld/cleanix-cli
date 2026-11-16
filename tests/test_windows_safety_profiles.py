"""I1: per-user protection (OneDrive, other profiles, Public, Temp root, junction
homes). The model tests are pure strings and run on any OS."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from cleanix.core import safety
from cleanix.core.safety_windows import violation

HOMES = [r"C:\Users\bob"]
PROFILES = [r"C:\Users\bob", r"C:\Users\alice", r"C:\Users\Public", r"C:\Users\Default"]
ENV = {"OneDrive": r"D:\Sync\OneDrive", "OneDriveCommercial": r"C:\Users\bob\OneDrive - Contoso"}


def v(target, env=ENV, homes=HOMES, profiles=PROFILES):
    return violation(target, env, homes, profiles=profiles)


MUST_REFUSE = [
    # OneDrive roots next to the home, and Known Folder Move targets
    r"C:\Users\bob\OneDrive",
    r"C:\Users\bob\OneDrive - Contoso",
    r"C:\Users\bob\OneDrive - Contoso\Documents",
    r"C:\Users\bob\OneDrive\Documents",
    r"C:\Users\bob\OneDrive\Desktop",
    r"C:\Users\bob\OneDrive\Pictures",
    r"C:\Users\bob\OneDrive\Music",
    r"C:\Users\bob\OneDrive\Videos",
    r"C:\Users\bob\OneDrive\Downloads",
    r"C:\Users\bob\OneDrive - Personal",
    # env-provided OneDrive root elsewhere (and its ancestor)
    r"D:\Sync\OneDrive",
    r"D:\Sync\OneDrive\Documents",
    r"D:\Sync",
    # another profile (an elevated run may see it)
    r"C:\Users\alice",
    r"C:\Users\alice\Documents",
    r"C:\Users\alice\Desktop",
    r"C:\Users\alice\Pictures",
    r"C:\Users\alice\Music",
    r"C:\Users\alice\Videos",
    r"C:\Users\alice\Downloads",
    r"C:\Users\alice\AppData",
    r"C:\Users\alice\AppData\Roaming",
    r"C:\Users\alice\AppData\Local",
    r"C:\Users\alice\.ssh",
    r"C:\Users\alice\.gnupg",
    r"C:\Users\alice\OneDrive",
    # Public
    r"C:\Users\Public",
    r"C:\Users\Public\Documents",
    # the temp folder itself (only its children may go)
    r"C:\Users\bob\AppData\Local\Temp",
    r"C:\Users\alice\AppData\Local\Temp",
]

MUST_ALLOW = [
    r"C:\Users\bob\AppData\Local\Temp\x.tmp",
    r"C:\Users\bob\AppData\Local\Temp\sub\dir",
    r"C:\Users\alice\AppData\Local\Temp\x.tmp",
    r"C:\Users\bob\AppData\Roaming\Slack\Cache",
    r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
    r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive\r1",
    r"C:\Windows\SoftwareDistribution\Download\x",
    r"C:\Users\bob\OneDrive\Documents\project\node_modules",
    r"C:\Users\bob\OneDriveSomething\cache\x",
]


@pytest.mark.parametrize("p", MUST_REFUSE)
def test_must_refuse(p):
    assert v(p) is not None, p


@pytest.mark.parametrize("p", MUST_ALLOW)
def test_must_allow(p):
    assert v(p) is None, (p, v(p))


def test_public_and_temp_root_refused_without_profiles():
    assert violation(r"C:\Users\Public", {}, HOMES) is not None
    assert violation(r"C:\Users\bob\AppData\Local\Temp", {}, HOMES) is not None
    assert violation(r"C:\Users\bob\OneDrive - Contoso", {}, HOMES) is not None
    assert violation(r"C:\Users\bob\OneDrive\Documents", {}, HOMES) is not None


@pytest.mark.parametrize("bad", ["OneDrive", "C:\\", "\\\\srv\\share\\od", " ", "%OneDrive%"])
def test_malformed_onedrive_env_ignored(bad):
    env = {"OneDrive": bad}
    assert violation(r"C:\Users\bob\AppData\Local\Temp\x", env, HOMES) is None
    assert violation(r"E:\cache\x", env, HOMES) is None


def test_raw_and_canonical_home_both_protect():
    homes = [r"C:\Junction\bob", r"D:\Real\bob"]
    for h in homes:
        assert violation(h + r"\Documents", {}, homes) is not None
        assert violation(h + r"\AppData\Local", {}, homes) is not None
    assert violation(r"D:\Real\bob\AppData\Local\Temp\x", {}, homes) is None


def test_extra_roots_protected():
    assert violation(r"E:\Keep", {}, HOMES, extra_roots=[r"E:\Keep"]) is not None
    assert violation(r"E:\Keep\x", {}, HOMES, extra_roots=[r"E:\Keep"]) is None


# -- integration on Windows ----------------------------------------------------

win_only = pytest.mark.skipif(sys.platform != "win32", reason="real junctions / profiles")


def _junction(link: Path, target: Path) -> None:
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"cannot create junction: {r.stderr or r.stdout}")


@win_only
def test_home_configured_as_junction_still_protected(tmp_path, monkeypatch):
    real = tmp_path / "realhome"
    for sub in ("Documents", "AppData/Local/Temp", "AppData/Roaming"):
        (real / sub).mkdir(parents=True)
    jhome = tmp_path / "jhome"
    _junction(jhome, real)
    monkeypatch.setattr(safety, "_home_dirs", lambda: [jhome])
    for base in (jhome, real):
        for sub in ("", "Documents", "AppData", "AppData/Local", "AppData/Roaming",
                    "AppData/Local/Temp"):
            p = base / sub if sub else base
            assert not safety.is_safe_to_delete(p), p
    assert safety.is_safe_to_delete(jhome / "AppData" / "Local" / "Temp" / "x.tmp")
    assert safety.is_safe_to_delete(real / "AppData" / "Local" / "Temp" / "x.tmp")


@win_only
def test_real_profiles_enumerated_and_protected():
    drive = os.environ.get("SystemDrive") or "C:"
    users = Path(drive + "\\Users")
    if not users.is_dir():
        pytest.skip("no Users directory")
    profiles = safety._windows_profiles()
    assert any(Path(p).name.lower() == "public" for p in profiles)
    for p in profiles:
        assert not safety.is_safe_to_delete(p), p
        assert not safety.is_safe_to_delete(os.path.join(p, "Documents")), p
        assert not safety.is_safe_to_delete(os.path.join(p, "AppData", "Local")), p
    assert not safety.is_safe_to_delete(users / "Public")
