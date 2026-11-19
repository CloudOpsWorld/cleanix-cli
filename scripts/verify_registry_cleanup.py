#!/usr/bin/env python3
"""Real-Windows verification of the registry cleanup feature (manual).

WHAT THIS WRITES TO THE REGISTRY
    Only the disposable key ``HKCU\\SOFTWARE\\CleanixTest`` and everything
    below it. Nothing else is ever created, changed or deleted: not HKLM, not
    ``HKCU\\SOFTWARE\\Cleanix``, not any real Uninstall/Run/App Paths key. It
    never starts an elevation prompt and never runs ``reg import`` on a backup
    written by Cleanix (those name the *logical* keys, which would be real
    ones).

HOW
    The detectors, ``service.clean`` and ``quarantine.restore`` run against a
    ``ReRootedBackend`` that maps every logical ``(HKCU|HKLM, key)`` to
    ``HKCU\\SOFTWARE\\CleanixTest\\<hive>\\<key>``, so the real code paths run
    on fixtures that are physically inside the test key. Extra "probes"
    measure the Windows facts the unit tests can only assume (see PROBES).

SAFETY GATES
    * refuses unless ``sys.platform == "win32"``;
    * refuses unless ``--i-understand-this-writes-to-hkcu-software-cleanixtest``
      is given (``--dry-run`` needs neither and does no registry access);
    * aborts (exit 2) if ``HKCU\\SOFTWARE\\CleanixTest`` already exists;
    * every registry call is confined to that key by a guard that raises
      ``ValueError`` for anything outside it;
    * the cleanup (links first, then the tree) runs in a ``finally``.

Run from the repository root, first as a normal user, then from an
Administrator terminal:

    python scripts/verify_registry_cleanup.py --dry-run
    python scripts/verify_registry_cleanup.py --i-understand-this-writes-to-hkcu-software-cleanixtest

Exit code: 0 all steps passed, 1 a step failed, 2 refused or aborted.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ARM_FLAG = "--i-understand-this-writes-to-hkcu-software-cleanixtest"
TEST_HIVE = "HKCU"
TEST_ROOT = r"SOFTWARE\CleanixTest"
APP_KEY = r"SOFTWARE\Cleanix"  # only ever READ (existence), never written
PROBE_ROOT = TEST_ROOT + r"\_probe"

REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD = 0, 1, 2, 3, 4
REG_MULTI_SZ, REG_QWORD = 7, 11

PROBES = (
    "REG_MULTI_SZ with empty strings: raw bytes vs the backend read (lossy read)",
    "reg export vs regbackup.to_reg_text, line by line (continuations joined)",
    "reg import of a Cleanix-written .reg into a probe key (guarded: every "
    "[section] must lie inside the test key)",
    "registry link keys made with REG_OPTION_CREATE_LINK (ctypes): is_link, "
    "OPEN_LINK vs followed handles, what DeleteKeyEx removes for a link as "
    "the final path component",
    "reg query /reg:64 sees the test key (informational: HKCU\\Software is not "
    "WOW64-redirected); Python bitness is reported",
)


# -- confinement ----------------------------------------------------------------------
class Confined:
    """Raises ``ValueError`` for any call outside ``<hive>\\<root>``, then
    delegates to ``inner``. The root itself is allowed (create/delete it)."""

    OPS = ("subkeys", "values", "key_exists", "is_link", "can_delete",
           "delete_key", "delete_value", "create_key", "set_value")

    def __init__(self, inner, hive: str = TEST_HIVE, root: str = TEST_ROOT) -> None:
        self._inner = inner
        self._hive = hive
        self._root = tuple(p.casefold() for p in root.strip("\\").split("\\"))

    def check(self, hive: str, key: str) -> None:
        if hive != self._hive:
            raise ValueError(f"outside the test key: hive {hive!r}")
        if not isinstance(key, str):
            raise ValueError("outside the test key: not a string")
        parts = key.split("\\")
        if any(p in ("", ".", "..") for p in parts):
            raise ValueError(f"outside the test key: bad component in {key!r}")
        if tuple(p.casefold() for p in parts[: len(self._root)]) != self._root:
            raise ValueError(f"outside the test key: {key!r}")

    def subkeys(self, hive, key):
        self.check(hive, key)
        return self._inner.subkeys(hive, key)

    def values(self, hive, key):
        self.check(hive, key)
        return self._inner.values(hive, key)

    def key_exists(self, hive, key):
        self.check(hive, key)
        return self._inner.key_exists(hive, key)

    def is_link(self, hive, key):
        self.check(hive, key)
        return self._inner.is_link(hive, key)

    def can_delete(self, hive, key, value):
        self.check(hive, key)
        return self._inner.can_delete(hive, key, value)

    def delete_key(self, hive, key):
        self.check(hive, key)
        return self._inner.delete_key(hive, key)

    def delete_value(self, hive, key, name):
        self.check(hive, key)
        return self._inner.delete_value(hive, key, name)

    def create_key(self, hive, key):
        self.check(hive, key)
        return self._inner.create_key(hive, key)

    def set_value(self, hive, key, value):
        self.check(hive, key)
        return self._inner.set_value(hive, key, value)


class ReRootedBackend:
    """Maps each logical ``(hive, key)`` to
    ``(root_hive, f"{root_key}\\{hive}\\{key}")`` and delegates to ``inner``
    through a :class:`Confined` guard, so nothing outside the root is reachable.
    The logical key must pass ``regsafety.normalize`` (so ``..`` is refused)."""

    def __init__(self, inner, root_hive: str = "HKCU",
                 root_key: str = r"SOFTWARE\CleanixTest") -> None:
        self.root_hive = root_hive
        self.root_key = root_key.strip("\\")
        self._guard = Confined(inner, root_hive, self.root_key)

    def physical(self, hive: str, key: str) -> Tuple[str, str]:
        from cleanix.core import regsafety

        short, _comps = regsafety.normalize(hive, key)  # ValueError if malformed
        mapped = f"{self.root_key}\\{short}\\{key}"
        self._guard.check(self.root_hive, mapped)
        return self.root_hive, mapped

    def subkeys(self, hive, key):
        return self._guard.subkeys(*self.physical(hive, key))

    def values(self, hive, key):
        return self._guard.values(*self.physical(hive, key))

    def key_exists(self, hive, key):
        return self._guard.key_exists(*self.physical(hive, key))

    def is_link(self, hive, key):
        return self._guard.is_link(*self.physical(hive, key))

    def can_delete(self, hive, key, value):
        h, k = self.physical(hive, key)
        return self._guard.can_delete(h, k, value)

    def delete_key(self, hive, key):
        return self._guard.delete_key(*self.physical(hive, key))

    def delete_value(self, hive, key, name):
        h, k = self.physical(hive, key)
        return self._guard.delete_value(h, k, name)

    def create_key(self, hive, key):
        return self._guard.create_key(*self.physical(hive, key))

    def set_value(self, hive, key, value):
        h, k = self.physical(hive, key)
        return self._guard.set_value(h, k, value)


def delete_tree(backend, hive: str, key: str,
                on_link: Optional[Callable[[str, str], None]] = None) -> int:
    """Delete ``key`` and everything below it, children first, never following
    a registry link: a link is handed to ``on_link`` (which removes the link
    itself) and, without ``on_link``, raises. Returns the number of keys
    removed. ``backend`` should be a :class:`Confined` guard."""
    removed = 0
    if backend.is_link(hive, key):
        if on_link is None:
            raise RuntimeError(f"registry link found, not following it: {key}")
        on_link(hive, key)
        return 1
    for sub in backend.subkeys(hive, key):
        removed += delete_tree(backend, hive, key + "\\" + sub, on_link)
    backend.delete_key(hive, key)
    return removed + 1


# -- .reg text helpers (pure) -----------------------------------------------------------
def normalize_reg_text(text: str) -> Dict[str, List[str]]:
    """``{casefolded [section]: sorted value lines}`` of a ``.reg`` text.
    ``reg export`` wraps long ``hex`` lines (``,\\`` + CRLF + two spaces) and
    orders values by enumeration; Cleanix writes them unwrapped, parents first.
    Wrapping and order are therefore normalised away; content is not."""
    sections: Dict[str, List[str]] = {}
    current: Optional[str] = None
    pending = ""
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = pending + raw.strip() if pending else raw
        pending = ""
        if line.endswith(",\\"):
            pending = line[:-1]
            continue
        if not line.strip() or line.startswith("Windows Registry Editor"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].casefold()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return {k: sorted(v) for k, v in sections.items()}


def reg_text_confined(text: str, prefix: str) -> bool:
    """True only if the text has at least one ``[section]`` and every section
    header lies at or under ``prefix`` (a ``HKEY_CURRENT_USER\\...`` path). A
    ``[-key]`` (delete) section, or any section elsewhere, makes it False."""
    want = prefix.rstrip("\\").casefold()
    seen = 0
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if line.startswith("["):
            if not line.endswith("]"):
                return False
            name = line[1:-1].casefold()
            if not (name == want or name.startswith(want + "\\")):
                return False
            seen += 1
    return seen > 0


# -- fixtures (pure) --------------------------------------------------------------------
_CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
_CVW = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion"
_CLASSES = r"SOFTWARE\Classes"

Entry = Tuple[str, int, object]  # (value name, type, data)


@dataclass(frozen=True)
class Fixture:
    label: str
    cleaner: str
    hive: str                      # logical hive
    keys: Tuple[Tuple[str, Tuple[Entry, ...]], ...]  # keys to create, with values
    # (cleaner, hive, key, value) when the entry must be found; None = keep it
    dead: Optional[Tuple[str, str, str, Optional[str]]]

    @property
    def machine(self) -> bool:
        return self.hive == "HKLM"


def build_fixtures(dead_dir: str, live_dir: str, system_root: str) -> List[Fixture]:
    """One dead and one live entry per detector (both hives where the
    detector covers both), the WOW6432Node variant of Uninstall, and controls
    that must NOT be found: UNC, an undefined %VAR%, a target under the
    Windows directory. ``live_dir`` holds a real ``live.exe``."""
    out: List[Fixture] = []
    nohost = r"\\cleanix-verify-nohost\share"
    undef = r"%CLEANIX_VERIFY_UNDEFINED%"
    winnope = system_root + r"\CleanixVerifyNope"
    dead_exe = dead_dir + r"\app.exe"
    live_exe = live_dir + r"\live.exe"

    def uninstall(label, hive, container, name, loc, exe, expand=False, dead=False):
        t = REG_EXPAND_SZ if expand else REG_SZ
        key = f"{container}\\{name}"
        vals = (
            ("DisplayName", REG_SZ, "Cleanix verify " + label),
            ("Publisher", REG_SZ, "Cleanix verify"),
            ("InstallLocation", t, loc),
            ("UninstallString", t, f'"{exe}"'),
        )
        out.append(Fixture(f"uninstall {label} ({hive})", "win_reg_uninstall", hive,
                           ((key, vals),),
                           ("win_reg_uninstall", hive, key, None) if dead else None))

    for hive in ("HKCU", "HKLM"):
        c = _CV + r"\Uninstall"
        uninstall("dead", hive, c, "CxDeadUninstall", dead_dir, dead_dir + r"\uninstall.exe", dead=True)
        uninstall("live", hive, c, "CxLiveUninstall", live_dir, live_exe)
        uninstall("unc", hive, c, "CxCtlUnc", nohost + r"\app", nohost + r"\u.exe")
        uninstall("undefined-var", hive, c, "CxCtlUndef", undef + r"\app", undef + r"\u.exe", expand=True)
        uninstall("under-windows", hive, c, "CxCtlWin", winnope + r"\app", winnope + r"\u.exe")
    uninstall("dead 32-bit", "HKLM", _CVW + r"\Uninstall", "CxDeadUninstall32",
              dead_dir, dead_dir + r"\uninstall.exe", dead=True)

    def app_path(label, hive, name, exe, dead=False):
        key = f"{_CV}\\App Paths\\{name}"
        out.append(Fixture(f"app paths {label} ({hive})", "win_reg_app_paths", hive,
                           ((key, (("", REG_SZ, exe),)),),
                           ("win_reg_app_paths", hive, key, None) if dead else None))

    for hive in ("HKCU", "HKLM"):
        app_path("dead", hive, "cxdead.exe", dead_exe, dead=True)
        app_path("live", hive, "cxlive.exe", live_exe)
        app_path("unc", hive, "cxunc.exe", nohost + r"\a.exe")
        app_path("undefined-var", hive, "cxundef.exe", undef + r"\a.exe")
        app_path("under-windows", hive, "cxwin.exe", winnope + r"\a.exe")

    def assoc(label, hive, name, exe, dead=False):
        key = f"{_CLASSES}\\{name}"
        shell = key + r"\shell"
        verb = shell + r"\open"
        cmd = verb + r"\command"
        icon = key + r"\DefaultIcon"
        out.append(Fixture(
            f"file-type handler {label} ({hive})", "win_reg_file_assoc", hive,
            ((key, (("", REG_SZ, "Cleanix verify " + label),)),
             (shell, ()), (verb, ()),
             (cmd, (("", REG_SZ, f'"{exe}" --open'),)),
             (icon, (("", REG_SZ, f"{exe},0"),))),
            ("win_reg_file_assoc", hive, key, None) if dead else None))

    for hive in ("HKCU", "HKLM"):
        assoc("dead", hive, "CxVerifyDead", dead_exe, dead=True)
        assoc("live", hive, "CxVerifyLive", live_exe)
        assoc("unc", hive, "CxVerifyUnc", nohost + r"\a.exe")
        assoc("under-windows", hive, "CxVerifyWin", winnope + r"\a.exe")

    def run_value(label, hive, container, name, cmd, dead=False):
        key = f"{_CV}\\{container}"
        out.append(Fixture(f"startup {container} {label} ({hive})", "win_reg_startup", hive,
                           ((key, ((name, REG_SZ, cmd),)),),
                           ("win_reg_startup", hive, key, name) if dead else None))

    for hive in ("HKCU", "HKLM"):
        run_value("dead", hive, "Run", "CxDeadRun", f'"{dead_dir}\\run.exe" /silent', dead=True)
        run_value("live", hive, "Run", "CxLiveRun", f'"{live_exe}" /silent')
        run_value("unc", hive, "Run", "CxCtlUnc", f'"{nohost}\\r.exe"')
        run_value("undefined-var", hive, "Run", "CxCtlUndef", undef + r"\r.exe")
        run_value("under-windows", hive, "Run", "CxCtlWin", f'"{winnope}\\r.exe"')
        run_value("dead", hive, "RunOnce", "CxDeadOnce", f'"{dead_dir}\\once.exe"', dead=True)

    def shared(label, name, dead=False):
        key = _CV + r"\SharedDLLs"
        out.append(Fixture(f"shared DLL {label} (HKLM)", "win_reg_shared_dlls", "HKLM",
                           ((key, ((name, REG_DWORD, 1),)),),
                           ("win_reg_shared_dlls", "HKLM", key, name) if dead else None))

    shared("dead", dead_dir + r"\shared.dll", dead=True)
    shared("live", live_exe)
    shared("unc", nohost + r"\x.dll")
    shared("under-windows", winnope + r"\x.dll")
    return out


def expected_dead(fixtures: Sequence[Fixture]) -> List[Tuple[str, str, str, Optional[str]]]:
    return [f.dead for f in fixtures if f.dead is not None]


# -- plan / arguments (pure) --------------------------------------------------------------
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="verify_registry_cleanup.py",
        description="Real-Windows verification of Cleanix registry cleanup. "
        r"Writes only HKCU\SOFTWARE\CleanixTest.",
    )
    p.add_argument(ARM_FLAG, dest="armed", action="store_true",
                   help=r"required to run: confirms this writes (and removes) HKCU\Software\CleanixTest")
    p.add_argument("--dry-run", action="store_true",
                   help="print the plan and exit; no registry access, no file changes")
    return p.parse_args(argv)


def refusal(args: argparse.Namespace, platform: str) -> Optional[str]:
    """Why a real run is refused, or None. ``--dry-run`` is never refused."""
    if args.dry_run:
        return None
    if platform != "win32":
        return "refused: this verification runs only on Windows (sys.platform is not win32)"
    if not args.armed:
        return f"refused: pass {ARM_FLAG} to confirm that this writes to HKCU\\Software\\CleanixTest"
    return None


def plan_lines() -> List[str]:
    fixtures = build_fixtures(r"C:\CleanixVerify-<uuid>\dead", r"C:\CleanixVerify-<uuid>\live",
                              r"C:\Windows")
    dead = expected_dead(fixtures)
    lines = [
        r"PLAN (dry run: nothing is read or written)",
        r"Registry writes happen ONLY under HKCU\SOFTWARE\CleanixTest; HKLM is never opened.",
        r"HKCU\SOFTWARE\Cleanix is only checked for existence (read), never changed.",
        "",
        "1. refuse unless win32 and the explicit flag is given; abort if the test key exists",
        r"2. create C:\CleanixVerify-<uuid>\ (a dead folder that is created, then removed, and a live "
        "folder with live.exe) and "
        f"{len(fixtures)} fixture entries ({len(dead)} expected dead) under the test key",
        "3. scan with the five detectors through ReRootedBackend, quarantine and history redirected "
        "to a temporary directory",
        "4. assert exactly the dead entries are found (controls and live entries are not)",
        "5. dry-run clean writes nothing; real clean removes the dead entries, keeps the rest",
        "6. assert both backup files per entry (.reg UTF-16 with BOM + header, .json)",
        "7. quarantine.restore: HKCU-logical entries come back with equal fingerprints; HKLM-logical "
        "ones are refused with the 'reg import' text (non-admin), then restored with "
        "regbackup.restore_entry(is_admin=True), which is safe: they are physically under HKCU",
        "8. probes (real winreg only):",
    ]
    lines += [f"     - {p}" for p in PROBES]
    lines += [
        r"9. finally: delete link keys, then the whole test tree; remove the folders; assert "
        r"HKCU\SOFTWARE\CleanixTest is gone and HKCU\SOFTWARE\Cleanix is unchanged",
        "",
        "Expected-dead entries:",
    ]
    for cid, hive, key, value in dead:
        lines.append(f"     {cid}: {hive}\\{key}" + (f" [{value}]" if value else ""))
    lines += ["", f"To run: python scripts/verify_registry_cleanup.py {ARM_FLAG}"]
    return lines


# -- reporting ----------------------------------------------------------------------------
class Report:
    def __init__(self, out: Callable[[str], None] = print) -> None:
        self._out = out
        self.results: List[Tuple[str, bool, str]] = []

    def step(self, name: str, ok: bool, detail: str = "") -> bool:
        self.results.append((name, bool(ok), detail))
        self._out(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail else ""))
        return bool(ok)

    def info(self, text: str) -> None:
        self._out("INFO  " + text)

    @property
    def ok(self) -> bool:
        return all(ok for _n, ok, _d in self.results)


@contextlib.contextmanager
def _patched(obj, name: str, value) -> Iterator[None]:
    old = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, old)


# -- helpers on the registry (through guards) ------------------------------------------------
def _value_present(backend, hive: str, key: str, name: str) -> bool:
    try:
        return any(v.name.casefold() == name.casefold() for v in backend.values(hive, key))
    except Exception:  # noqa: BLE001 - a missing key means the value is gone
        return False


def _entry_present(backend, target: Tuple[str, str, str, Optional[str]]) -> bool:
    _cid, hive, key, value = target
    if value is None:
        return backend.key_exists(hive, key)
    return backend.key_exists(hive, key) and _value_present(backend, hive, key, value)


def _create_fixtures(rerooted: ReRootedBackend, fixtures: Sequence[Fixture]) -> int:
    from cleanix.core.winregistry import RegValue

    n = 0
    for fx in fixtures:
        for key, values in fx.keys:
            rerooted.create_key(fx.hive, key)
            for name, typ, data in values:
                rerooted.set_value(fx.hive, key, RegValue(name, typ, data))
        n += 1
    return n


def _find_live_leftovers(rerooted, fixtures: Sequence[Fixture]) -> List[str]:
    """Fixture entries that should still exist after the clean but do not."""
    gone: List[str] = []
    for fx in fixtures:
        if fx.dead is not None:
            continue
        for key, values in fx.keys:
            if not rerooted.key_exists(fx.hive, key):
                gone.append(f"{fx.label}: {key}")
                continue
            for name, _t, _d in values:
                if not _value_present(rerooted, fx.hive, key, name):
                    gone.append(f"{fx.label}: {key} [{name}]")
    return gone


# -- the main flow --------------------------------------------------------------------------
def run_flow(inner, report: Report, tmp: Path, base: Path, *, elevated: bool) -> None:
    """Steps 2-7. ``inner`` is the real backend (or a FakeRegistry in the unit
    test). Raises nothing for failed assertions; they are recorded."""
    from cleanix.config import Config
    from cleanix.core import (catalog, engine, history, quarantine, regbackup, regpromises,
                              regsnap, service, winenv, winregistry)
    from cleanix.core.registry import build_cleaners

    guard = Confined(inner)
    rerooted = ReRootedBackend(inner)
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    dead_dir = base / "dead"
    live_dir = base / "live"

    base.mkdir()
    dead_dir.mkdir()
    live_dir.mkdir()
    (live_dir / "live.exe").write_bytes(b"MZ")
    (dead_dir / "x").write_bytes(b"x")
    shutil.rmtree(dead_dir)  # the dead targets now point at a missing folder

    fixtures = build_fixtures(str(dead_dir), str(live_dir), system_root)
    guard.create_key(TEST_HIVE, TEST_ROOT)
    n = _create_fixtures(rerooted, fixtures)
    dead = expected_dead(fixtures)
    report.step("fixtures created under the test key", n == len(fixtures),
                f"{n} entries, {len(dead)} expected dead")

    qroot = tmp / "q"
    state = tmp / "state"
    qroot.mkdir()
    state.mkdir()
    # The restore path is what is being verified: switch it on in this process only.
    with _patched(regpromises, "UNDO_SHIPPED", True), \
            _patched(quarantine, "quarantine_root", lambda: qroot), \
            _patched(history, "state_dir", lambda: state), \
            winregistry.using_backend(rerooted):
        # -- 3/4: scan ---------------------------------------------------------------
        found: Dict[Tuple[str, str, str, Optional[str]], object] = {}
        for cleaner in build_cleaners(Config(), only=list(catalog.REGISTRY_IDS)):
            rep = cleaner.scan()
            if not rep.ran:
                report.step(f"{cleaner.id} ran", False, str(rep.skipped_reason))
                continue
            if rep.incomplete:
                report.info(f"{cleaner.id}: incomplete scan: {rep.incomplete}")
            for item in rep.items:
                t = item.reg
                found[(item.cleaner_id, t.hive, t.key, t.value)] = item
        want = set(dead)
        # Elevated: the helper-style policy treats HKCU as the administrator's
        # hive (R15), so HKCU-logical entries may legitimately be skipped.
        must = {d for d in want if not (elevated and d[1] == "HKCU")}
        got = set(found)
        missing = sorted(must - got)
        extra = sorted(got - want)
        report.step("scan finds every expected dead entry", not missing,
                    "; ".join(f"{m[0]} {m[1]}\\{m[2]}" for m in missing))
        report.step("scan finds nothing else (live entries and controls are kept)", not extra,
                    "; ".join(f"{e[0]} {e[1]}\\{e[2]}" for e in extra))
        if elevated:
            report.info("elevated run: HKCU-logical entries are not required to be found")
        items = [found[k] for k in sorted(got & want, key=lambda k: (k[0], k[1], k[2], k[3] or ""))]
        if extra or not items:
            report.step("clean/restore skipped: the scan result is not trustworthy", False)
            return

        # -- 5: dry run, then the real clean --------------------------------------------
        service.clean(items, Config(), dry_run=True)
        report.step("dry-run clean removes nothing", all(_entry_present(rerooted, d) for d in got))

        with _patched(winenv, "is_admin", lambda: True), _patched(engine, "is_root", lambda: True):
            # The HKLM-logical entries are physically in HKCU; the engine's
            # "needs Administrator" gate is stepped over for this call only.
            summary = service.clean(items, Config(), dry_run=False, use_quarantine=False)
        report.step("clean reports every entry removed, no errors",
                    summary.removed == len(items) and not summary.errors,
                    f"removed {summary.removed}/{len(items)}; "
                    + "; ".join(str(getattr(e, 'error', e)) for e in summary.errors))
        report.step("dead entries are gone", not any(_entry_present(rerooted, d) for d in got))
        left = _find_live_leftovers(rerooted, fixtures)
        report.step("live entries and controls are kept", not left, "; ".join(left))

        # -- 6: backups ----------------------------------------------------------------------
        run_id = summary.quarantine_run
        report.step("a quarantine run holds the backups", bool(run_id), str(run_id))
        if not run_id:
            return
        run_dir = qroot / run_id
        regs = sorted((run_dir / "registry").glob("*.reg"))
        jsons = sorted((run_dir / "registry").glob("*.json"))
        report.step("one .reg and one .json backup per removed entry",
                    len(regs) == len(items) == len(jsons), f"{len(regs)} .reg, {len(jsons)} .json")
        bad = []
        for f in regs:
            raw = f.read_bytes()
            if raw[:2] != b"\xff\xfe" or not raw[2:].decode("utf-16-le").startswith(
                    regbackup.REG_HEADER):
                bad.append(f.name)
        report.step(".reg backups are UTF-16 with BOM and the Version 5.00 header", not bad, ", ".join(bad))

        # -- 7: restore -----------------------------------------------------------------------
        result = quarantine.restore(run_id)
        restored = list(result["restored"])
        failed = list(result["failed"])
        hkcu = [i for i in items if i.reg.hive == "HKCU"]
        hklm = [i for i in items if i.reg.hive == "HKLM"]
        report.step("every HKCU-logical entry was restored",
                    len(restored) == len(hkcu), f"{len(restored)} restored, {len(hkcu)} expected")
        fp_bad = []
        for i in hkcu:
            snap = regsnap.snapshot(rerooted, i.reg)
            if regsnap.fingerprint(i.reg, snap) != i.reg.fingerprint:
                fp_bad.append(i.reg.display)
        report.step("restored HKCU entries have the scanned fingerprints", not fp_bad, "; ".join(fp_bad))
        want_text = "confirm" if winenv.is_admin() else "reg import"
        texts = [str(t) for _o, t in failed]
        report.step(f"HKLM-logical entries are refused with the '{want_text}' instruction",
                    len(failed) == len(hklm) and all(want_text in t for t in texts),
                    "; ".join(texts[:1]))
        # The documented manual route, made safe here: these entries are
        # physically under the HKCU test key. (Never `reg import` a backup.)
        hklm_fail = []
        for path in jsons:
            cid, target, _snap = regbackup.load_verified(path)
            if target.hive != "HKLM":
                continue
            try:
                regbackup.restore_entry(path, rerooted, is_admin=True)
                scanned = found[(cid, target.hive, target.key, target.value)]
                snap = regsnap.snapshot(rerooted, scanned.reg)
                if regsnap.fingerprint(scanned.reg, snap) != scanned.reg.fingerprint:
                    hklm_fail.append(f"{target.key}: fingerprint differs")
            except Exception as exc:  # noqa: BLE001
                hklm_fail.append(f"{target.key}: {exc}")
        report.step("HKLM-logical entries restore with equal fingerprints", not hklm_fail,
                    "; ".join(hklm_fail))


# -- probes (real winreg only) -----------------------------------------------------------------
class _Nt:
    """The few ctypes calls for registry links. Windows only."""

    CREATE_LINK, OPEN_LINK, WOW64_64 = 0x2, 0x8, 0x100
    KEY_CREATE_LINK, KEY_SET_VALUE, KEY_QUERY_VALUE, DELETE = 0x20, 0x2, 0x1, 0x10000
    REG_LINK = 6

    def __init__(self) -> None:
        import ctypes
        import winreg
        from ctypes import wintypes as wt

        self.c, self.wt, self.winreg = ctypes, wt, winreg
        self.hkcu = ctypes.c_void_p(int(winreg.HKEY_CURRENT_USER))
        a = self.adv = ctypes.WinDLL("advapi32")
        self.nt = ctypes.WinDLL("ntdll")
        V = ctypes.c_void_p
        a.RegCreateKeyExW.argtypes = [V, wt.LPCWSTR, wt.DWORD, wt.LPCWSTR, wt.DWORD, wt.DWORD,
                                      V, ctypes.POINTER(V), V]
        a.RegCreateKeyExW.restype = wt.LONG
        a.RegOpenKeyExW.argtypes = [V, wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.POINTER(V)]
        a.RegOpenKeyExW.restype = wt.LONG
        a.RegSetValueExW.argtypes = [V, wt.LPCWSTR, wt.DWORD, wt.DWORD, V, wt.DWORD]
        a.RegSetValueExW.restype = wt.LONG
        a.RegQueryValueExW.argtypes = [V, wt.LPCWSTR, V, ctypes.POINTER(wt.DWORD), V,
                                       ctypes.POINTER(wt.DWORD)]
        a.RegQueryValueExW.restype = wt.LONG
        a.RegCloseKey.argtypes = [V]
        a.RegCloseKey.restype = wt.LONG
        self.nt.NtDeleteKey.argtypes = [V]
        self.nt.NtDeleteKey.restype = ctypes.c_long

    def _err(self, rc: int, what: str) -> None:
        if rc != 0:
            raise OSError(rc, f"{what} failed with error {rc}")

    def create_link(self, guard: Confined, key: str, target_native: str) -> None:
        guard.check(TEST_HIVE, key)
        c = self.c
        h = c.c_void_p()
        self._err(self.adv.RegCreateKeyExW(
            self.hkcu, key, 0, None, self.CREATE_LINK,
            self.KEY_CREATE_LINK | self.KEY_SET_VALUE | self.WOW64_64, None, c.byref(h), None),
            "RegCreateKeyEx(CREATE_LINK)")
        try:
            raw = target_native.encode("utf-16-le")
            buf = c.create_string_buffer(raw, len(raw))
            self._err(self.adv.RegSetValueExW(h, "SymbolicLinkValue", 0, self.REG_LINK,
                                              c.cast(buf, c.c_void_p), len(raw)),
                      "RegSetValueEx(SymbolicLinkValue)")
        finally:
            self.adv.RegCloseKey(h)

    def delete_link(self, guard: Confined, key: str) -> None:
        """Delete the link key ITSELF: open it with OPEN_LINK and NtDeleteKey."""
        guard.check(TEST_HIVE, key)
        c = self.c
        h = c.c_void_p()
        self._err(self.adv.RegOpenKeyExW(self.hkcu, key, self.OPEN_LINK,
                                         self.DELETE | self.WOW64_64, c.byref(h)),
                  "RegOpenKeyEx(OPEN_LINK, DELETE)")
        try:
            status = self.nt.NtDeleteKey(h)
        finally:
            self.adv.RegCloseKey(h)
        if status != 0:
            raise OSError(status, f"NtDeleteKey failed with status {status:#x}")

    def raw_value(self, key: str, name: str) -> Tuple[int, bytes]:
        """The value's type and exact bytes (no Python-side decoding)."""
        c = self.c
        h = c.c_void_p()
        self._err(self.adv.RegOpenKeyExW(self.hkcu, key, 0, self.KEY_QUERY_VALUE | self.WOW64_64,
                                         c.byref(h)), "RegOpenKeyEx")
        try:
            typ, size = self.wt.DWORD(), self.wt.DWORD()
            self._err(self.adv.RegQueryValueExW(h, name, None, c.byref(typ), None, c.byref(size)),
                      "RegQueryValueEx(size)")
            buf = c.create_string_buffer(size.value or 1)
            self._err(self.adv.RegQueryValueExW(h, name, None, c.byref(typ), c.cast(buf, c.c_void_p),
                                                c.byref(size)), "RegQueryValueEx")
            return typ.value, buf.raw[: size.value]
        finally:
            self.adv.RegCloseKey(h)


def parse_multi_sz(raw: bytes) -> Tuple[str, ...]:
    """The strings of a raw REG_MULTI_SZ value, keeping empty ones: each
    string is NUL-terminated and one extra NUL ends the list."""
    text = raw.decode("utf-16-le", "replace")
    if text.endswith("\x00"):
        text = text[:-1]
    if not text:
        return ()
    parts = text.split("\x00")
    if parts and parts[-1] == "":
        parts = parts[:-1]
    return tuple(parts)


def _reg_exe() -> str:
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "reg.exe")


def _run_reg(args: Sequence[str]) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run([_reg_exe(), *args], capture_output=True, timeout=60)


def run_probes(inner, report: Report, tmp: Path, links: List[str]) -> None:
    """Measure the Windows facts the unit tests only assume. Every write is
    under ``HKCU\\SOFTWARE\\CleanixTest\\_probe``. Link keys are appended to
    ``links`` so the cleanup can remove them first."""
    from cleanix.core import regbackup, regsnap
    from cleanix.core.models import RegTarget
    from cleanix.core.winregistry import RegValue

    guard = Confined(inner)
    H = TEST_HIVE
    bits = struct.calcsize("P") * 8
    report.info(f"python is {bits}-bit; every registry call uses KEY_WOW64_64KEY"
                + (" (32-bit process: the 64-bit view is requested explicitly)" if bits == 32 else ""))
    guard.create_key(H, PROBE_ROOT)

    # -- MULTI_SZ with empty strings ------------------------------------------------------
    try:
        key = PROBE_ROOT + r"\multisz"
        guard.create_key(H, key)
        want = ("a", "", "b", "")
        guard.set_value(H, key, RegValue("m", REG_MULTI_SZ, want))
        nt = _Nt()
        typ, raw = nt.raw_value(key, "m")
        raw_strings = parse_multi_sz(raw)
        got = [v for v in guard.values(H, key) if v.name == "m"][0].data
        report.step("probe: REG_MULTI_SZ with empty strings reads back exactly (not lossy)",
                    typ == REG_MULTI_SZ and tuple(got) == raw_strings == want,
                    f"raw bytes decode to {raw_strings!r}; backend read {tuple(got)!r}; wrote {want!r}")
    except Exception as exc:  # noqa: BLE001
        report.step("probe: REG_MULTI_SZ with empty strings reads back exactly (not lossy)", False,
                    f"{type(exc).__name__}: {exc}")

    # -- reg export vs to_reg_text, and a guarded reg import ----------------------------------
    try:
        key = PROBE_ROOT + r"\export"
        guard.create_key(H, key)
        sub = key + r"\child"
        guard.create_key(H, sub)
        samples = [
            RegValue("", REG_SZ, 'default "quoted" \\ back'),
            RegValue("sz", REG_SZ, "plain text"),
            RegValue("empty", REG_SZ, ""),
            RegValue("expand", REG_EXPAND_SZ, r"%SystemRoot%\x"),
            RegValue("dword", REG_DWORD, 0xDEADBEEF),
            RegValue("qword", REG_QWORD, 0x0123456789ABCDEF),
            RegValue("bin", REG_BINARY, bytes(range(1, 9))),
            RegValue("emptybin", REG_BINARY, b""),
            RegValue("multi", REG_MULTI_SZ, ("x", "y z")),
            RegValue("none", REG_NONE, b"ab"),
        ]
        for v in samples:
            guard.set_value(H, key, v)
        guard.set_value(H, sub, RegValue("child value", REG_SZ, "c"))
        target = RegTarget(H, key)
        snap = regsnap.snapshot(guard, target)
        ours = regbackup.to_reg_text(target, snap)
        exp = tmp / "export.reg"
        cp = _run_reg(["export", "HKCU\\" + key, str(exp), "/y", "/reg:64"])
        if cp.returncode != 0:
            raise RuntimeError(f"reg export failed: {cp.stderr[:200]!r}")
        theirs = exp.read_bytes().decode("utf-16")
        a, b = normalize_reg_text(ours), normalize_reg_text(theirs)
        diff = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
        report.step("probe: reg export and regbackup.to_reg_text agree (sections and value lines)",
                    not diff, "differs in: " + "; ".join(diff[:3]))

        # import: a .reg for the SAME snapshot at a different probe key
        imp_key = PROBE_ROOT + r"\import"
        text = regbackup.to_reg_text(RegTarget(H, imp_key), snap)
        if not reg_text_confined(text, "HKEY_CURRENT_USER\\" + PROBE_ROOT):
            raise RuntimeError("refusing reg import: the .reg is not confined to the probe key")
        imp = tmp / "import.reg"
        imp.write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))
        cp = _run_reg(["import", str(imp), "/reg:64"])
        if cp.returncode != 0:
            raise RuntimeError(f"reg import failed: {cp.stderr[:200]!r}")
        back = regsnap.snapshot(guard, RegTarget(H, imp_key))
        same = regsnap.fingerprint(RegTarget(H, imp_key), back) == regsnap.fingerprint(
            RegTarget(H, imp_key), snap)
        report.step("probe: reg import of a Cleanix-written .reg recreates the same values",
                    same)
    except Exception as exc:  # noqa: BLE001
        report.step("probe: reg export/import comparison", False, f"{type(exc).__name__}: {exc}")

    # -- registry links ---------------------------------------------------------------------------
    try:
        nt = _Nt()
        from cleanix.core.regbackup import _WinSecurity  # private helper: the user's SID text

        sid = _WinSecurity().user_sid()
        if not sid:
            raise RuntimeError("could not determine the current user's SID")
        tkey = PROBE_ROOT + r"\linktarget"
        lkey = PROBE_ROOT + r"\link"
        guard.create_key(H, tkey)
        guard.set_value(H, tkey, RegValue("marker", REG_SZ, "target-content"))
        native = "\\Registry\\User\\" + sid + "\\" + tkey
        links.append(lkey)  # registered BEFORE creation: the cleanup tolerates absence
        nt.create_link(guard, lkey, native)
        report.step("probe: a registry link key can be created under the test key", True)
        report.step("probe: is_link is True for the link and False for its target",
                    guard.is_link(H, lkey) and not guard.is_link(H, tkey))
        follows = [v.name for v in guard.values(H, lkey)]
        report.step("probe: a normal handle follows the link (reads the target's values)",
                    "marker" in follows, f"values seen through the link: {follows!r}")
        # what does DeleteKeyEx remove when the final component is a link?
        import winreg
        outcome = ""
        try:
            winreg.DeleteKeyEx(winreg.HKEY_CURRENT_USER, lkey, winreg.KEY_WOW64_64KEY, 0)
            outcome = "DeleteKeyEx returned success"
        except OSError as exc:
            outcome = f"DeleteKeyEx raised {exc!r}"
        link_left = guard.key_exists(H, lkey)   # OPEN_LINK handle: the link itself
        target_left = guard.key_exists(H, tkey)
        target_marker = target_left and _value_present(guard, H, tkey, "marker")
        report.info(f"R17 measurement: {outcome}; link itself still exists: {link_left}; "
                    f"link target still exists: {target_left} (marker value: {target_marker})")
        report.step("probe: DeleteKeyEx on a link did not escape the test key (measurement recorded)",
                    True, f"link removed: {not link_left}; target removed: {not target_left}")
        if link_left:
            nt.delete_link(guard, lkey)
            report.step("probe: a link key is deleted itself via OPEN_LINK + NtDeleteKey",
                        not guard.key_exists(H, lkey))
    except Exception as exc:  # noqa: BLE001
        report.step("probe: registry link behaviour", False, f"{type(exc).__name__}: {exc}")

    # -- the 64-bit view is what reg.exe /reg:64 sees ----------------------------------------------
    try:
        cp = _run_reg(["query", "HKCU\\" + TEST_ROOT, "/reg:64"])
        report.step("probe (informational, HKCU is not redirected): reg query /reg:64 sees the test key",
                    cp.returncode == 0)
    except Exception as exc:  # noqa: BLE001
        report.step("probe: reg query /reg:64", False, f"{type(exc).__name__}: {exc}")


# -- entry point ----------------------------------------------------------------------------------
def execute(inner, report: Report, *, system_drive: str, elevated: bool, with_probes: bool) -> int:
    """The guarded run. ``inner`` is the real WinRegBackend. Returns the exit code."""
    guard = Confined(inner)
    try:
        exists = guard.key_exists(TEST_HIVE, TEST_ROOT)
    except Exception as exc:  # noqa: BLE001
        print(f"abort: cannot tell whether HKCU\\{TEST_ROOT} exists ({exc}); nothing was written")
        return 2
    if exists:
        print(f"abort: HKCU\\{TEST_ROOT} already exists. Nothing was written. "
              "Inspect it, remove it yourself if it is a leftover of an earlier run, and run again.")
        return 2
    try:
        app_existed = inner.key_exists(TEST_HIVE, APP_KEY)  # read only
    except Exception:  # noqa: BLE001
        app_existed = None

    base = Path(system_drive + "\\") / f"CleanixVerify-{uuid.uuid4()}"
    tmp = Path(tempfile.mkdtemp(prefix="cleanix-verify-"))
    links: List[str] = []
    try:
        try:
            run_flow(inner, report, tmp, base, elevated=elevated)
            if with_probes:
                run_probes(inner, report, tmp, links)
        except Exception as exc:  # noqa: BLE001
            report.step("verification ran without an unexpected error", False,
                        f"{type(exc).__name__}: {exc}")
    finally:
        problems: List[str] = []
        nt = None
        if links:
            try:
                nt = _Nt()
            except Exception as exc:  # noqa: BLE001
                problems.append(f"links could not be removed: {exc}")
        for lkey in links:
            try:
                if guard.key_exists(TEST_HIVE, lkey):
                    nt.delete_link(guard, lkey)  # type: ignore[union-attr]
            except Exception as exc:  # noqa: BLE001
                problems.append(f"link {lkey}: {exc}")
        try:
            if guard.key_exists(TEST_HIVE, TEST_ROOT):
                def drop(h, k):
                    nt.delete_link(guard, k)  # type: ignore[union-attr]
                delete_tree(guard, TEST_HIVE, TEST_ROOT, on_link=drop if nt else None)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"tree: {exc}")
        shutil.rmtree(base, ignore_errors=True)
        shutil.rmtree(tmp, ignore_errors=True)
        report.step("cleanup removed the test key tree without errors", not problems, "; ".join(problems))
    try:
        gone = not guard.key_exists(TEST_HIVE, TEST_ROOT)
    except Exception:  # noqa: BLE001
        gone = False
    report.step(f"HKCU\\{TEST_ROOT} no longer exists", gone)
    try:
        now = inner.key_exists(TEST_HIVE, APP_KEY)
        report.step(f"HKCU\\{APP_KEY} (exact key) unchanged by this run", now == app_existed,
                    f"existed before: {app_existed}, now: {now}"
                    + ("" if not now else " (Cleanix settings exist from normal GUI use; never touched)"))
    except Exception as exc:  # noqa: BLE001
        report.step(f"HKCU\\{APP_KEY} unchanged", False, str(exc))
    report.step("base folder removed", not base.exists())
    return 0 if report.ok else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.dry_run:
        print("\n".join(plan_lines()))
        return 0
    why = refusal(args, sys.platform)
    if why:
        print(why)
        return 2
    from cleanix.core import winenv
    from cleanix.core.winregistry_win import WinRegBackend

    system_drive = os.environ.get("SystemDrive") or "C:"
    return execute(WinRegBackend(), Report(), system_drive=system_drive,
                   elevated=winenv.is_admin(), with_probes=True)


if __name__ == "__main__":
    sys.exit(main())
