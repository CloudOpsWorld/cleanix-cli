"""Shared foundation for the read-only orphan reports (Linux/macOS).

Everything here is report-only: nothing is ever deleted. The module provides

* an allowlisted, locale-pinned command runner (:func:`run`),
* a scan budget and a lstat-only, single-device size walker,
* package-ownership queries (dpkg/rpm/pacman) that only call a path unowned
  on *positive* evidence, and
* :class:`OrphanReporter`, which turns :class:`Finding` objects into
  report-only items.

Detector modules must call commands only as ``orphan_common.run(...)`` and
``orphan_common.tool(...)`` (module attribute access), so tests can patch them.
"""

from __future__ import annotations

import os
import re
import shlex
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

from cleanix.cleaners.base import Cleaner
from cleanix.core import platform as _platform
from cleanix.core.models import CleanableItem, ItemKind
from cleanix.core.utils import _allocated_bytes, run_command, which

READ_ONLY_COMMANDS: frozenset = frozenset(
    {
        ("dpkg-query", "-S"),
        ("dpkg-query", "-W"),
        ("rpm", "-qf"),
        ("rpm", "-qa"),
        ("pacman", "-Qo"),
        ("pacman", "-Qq"),
        ("mdfind", "kMDItemContentType == 'com.apple.application-bundle'"),
        ("pkgutil", "--pkgs"),
        ("pkgutil", "--pkg-info-plist"),
        ("pkgutil", "--only-files"),
    }
)


# Exact argument shapes. A path/id operand must not look like an option, so a
# smuggled ``--forget`` or ``-f`` after the fixed words is refused.
_FIXED_ARGV: frozenset = frozenset(
    {
        ("dpkg-query", "-W", "-f=${Package}\\n"),
        ("rpm", "-qa", "--qf", "%{NAME}\\n"),
        ("pacman", "-Qq"),
        ("mdfind", "kMDItemContentType == 'com.apple.application-bundle'"),
        ("pkgutil", "--pkgs"),
    }
)
# Prefixes followed by path operands / by exactly one id operand.
_PATH_ARGV = frozenset(
    {("dpkg-query", "-S"), ("rpm", "-qf"), ("pacman", "-Qo")}
)
_ID_ARGV = frozenset(
    {
        ("pkgutil", "--pkg-info-plist"),
        ("pkgutil", "--only-files", "--files"),
    }
)


def _argv_allowed(argv: Sequence[str]) -> bool:
    a = tuple(argv)
    if tuple(a[:2]) not in READ_ONLY_COMMANDS:
        return False
    if a in _FIXED_ARGV:
        return True
    if a[:2] in _PATH_ARGV:
        rest = a[2:]
        return bool(rest) and all(x.startswith("/") for x in rest)
    for prefix in _ID_ARGV:
        if a[: len(prefix)] == prefix:
            rest = a[len(prefix):]
            return len(rest) == 1 and bool(rest[0]) and not rest[0].startswith("-")
    return False


def run(argv: Sequence[str], timeout: int = 60) -> tuple[int, str, str]:
    """Run an allowlisted read-only command under the C locale."""
    if not _argv_allowed(argv):
        return 126, "", "refused"
    try:
        return run_command(["env", "LC_ALL=C", *argv], timeout)
    except Exception:  # noqa: BLE001 - e.g. UnicodeDecodeError on odd filenames
        return 125, "", ""  # unknown, never "unowned"


def tool(name: str) -> Optional[str]:
    """Path of an executable, or None. The single patch point for tests."""
    return which(name)


@dataclass(frozen=True)
class Finding:
    path: Path  # real on-disk path
    label: str
    hint: str
    requires_root: bool = True
    note: bool = False  # notes are never sized (size 0)


class ScanBudget:
    def __init__(
        self,
        max_items: int,
        max_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.max_items = max_items
        self.max_seconds = max_seconds
        self._clock = clock
        # The clock starts lazily (start()/first use) so a budget built in
        # __init__ is not already spent when a scan begins much later.
        self._start: Optional[float] = None
        self._taken = 0
        self.stop_reason: Optional[str] = None

    def start(self) -> None:
        self._start = self._clock()

    def expired(self) -> bool:
        if self._start is None:
            self.start()
        if self._clock() - self._start >= self.max_seconds:
            if self.stop_reason is None:
                self.stop_reason = "time limit"
            return True
        return False

    def remaining(self) -> float:
        """Seconds left before the time limit (0.0 once it is spent)."""
        if self._start is None:
            self.start()
        return max(0.0, self.max_seconds - (self._clock() - self._start))

    def take(self) -> bool:
        if self.expired():
            return False
        if self._taken >= self.max_items:
            if self.stop_reason is None:
                self.stop_reason = "item limit"
            return False
        self._taken += 1
        return True


# --------------------------------------------------------------- filesystem
def device_of(path: Path) -> Optional[int]:
    try:
        return Path(path).lstat().st_dev
    except OSError:
        return None


def list_dir(path: Path) -> Optional[list]:
    """Children of ``path``; ``[]`` if missing; ``None`` if unreadable."""
    try:
        with os.scandir(path) as it:
            return [Path(e.path) for e in it]
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError:
        return None


def bounded_size(path: Path, budget: ScanBudget) -> tuple[int, bool]:
    """Allocated bytes under ``path`` (lstat only) and whether it is complete.

    Never follows symlinks, never crosses to another device, stops as soon as
    the budget's time is up.
    """
    path = Path(path)
    try:
        st = path.lstat()
    except FileNotFoundError:
        return 0, True
    except OSError:
        return 0, False
    import stat as _stat

    if _stat.S_ISLNK(st.st_mode):
        return 0, True
    total = _allocated_bytes(st)
    if not _stat.S_ISDIR(st.st_mode):
        return total, True
    root_dev = device_of(path)
    if root_dev is None:
        return total, False
    complete = True
    stack = [path]
    while stack:
        if budget.expired():
            return total, False
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            complete = False
            continue
        with it:
            while True:
                if budget.expired():
                    return total, False
                try:
                    entry = next(it)
                except StopIteration:
                    break
                except OSError:
                    complete = False
                    break
                try:
                    est = entry.stat(follow_symlinks=False)
                except OSError:
                    complete = False
                    continue
                if _stat.S_ISLNK(est.st_mode):
                    continue
                if _stat.S_ISDIR(est.st_mode):
                    # device_of (path lstat), not entry.stat(): scandir stats
                    # carry no st_dev on Windows. Mount points are dirs.
                    child = Path(entry.path)
                    cdev = device_of(child)
                    if cdev is None:
                        complete = False
                        continue
                    if cdev != root_dev:
                        continue
                    total += _allocated_bytes(est)
                    stack.append(child)
                else:
                    total += _allocated_bytes(est)
    return total, complete


# ------------------------------------------------------------------- paths
def in_root(root: str | Path, logical: str) -> Path:
    if str(root) in ("/", ""):
        return Path(logical)
    return Path(root) / logical.lstrip("/")


def logical_path(root: str | Path, real: Path) -> str:
    if str(root) in ("/", ""):
        return Path(real).as_posix()
    try:
        rel = Path(real).relative_to(Path(root))
    except ValueError:
        return Path(real).as_posix()
    r = rel.as_posix()
    return "/" if r == "." else "/" + r


def link_target_exists(link: Path, root: str | Path) -> Optional[bool]:
    """Whether the symlink's target exists (one existence check, no walk)."""
    try:
        target = os.readlink(link)
    except OSError:
        return None
    if target == "/dev/null":
        return True
    if target.startswith("/"):
        dest = in_root(root, target)
    else:
        dest = Path(link).parent / target
    try:
        return os.path.exists(dest)
    except OSError:
        return None


# -------------------------------------------------------------------- text
_REMOVABLE = ("/mnt", "/media", "/run/media", "/Volumes", "/net", "/afs")


def is_removable_location(logical: str) -> bool:
    return any(logical == p or logical.startswith(p + "/") for p in _REMOVABLE)


def safe_label(text: str) -> str:
    out = "".join(
        "?" if (ord(c) < 32 or 127 <= ord(c) < 160) else c for c in text
    )
    return out[:200]


def bad_name(name: str) -> bool:
    """True for names with newline, CR or NUL. Detectors MUST skip such
    directory entries (they could forge output lines or break hints)."""
    return any(c in name for c in ("\n", "\r", "\0"))


# --------------------------------------------------------------- ownership
_BACKENDS = (
    ("dpkg", {"debian", "ubuntu"}, "dpkg-query"),
    (
        "rpm",
        {"fedora", "rhel", "centos", "suse", "opensuse", "sles", "mageia"},
        "rpm",
    ),
    ("pacman", {"arch", "manjaro"}, "pacman"),
)


def detect_pkg_backend(family: Optional[set] = None) -> Optional[str]:
    fam = {f.lower() for f in (family if family is not None else _platform.distro_family())}
    for name, families, exe in _BACKENDS:
        if fam & families and tool(exe):
            return name
    return None


_OWNER_CMDS = {
    "dpkg": "dpkg -S",
    "rpm": "rpm -qf",
    "pacman": "pacman -Qo",
    "pkgutil": "pkgutil --file-info",
}


def owner_check_command(backend: Optional[str], logical: str) -> Optional[str]:
    prefix = _OWNER_CMDS.get(backend or "")
    if prefix is None:
        return None
    return f"{prefix} {shlex.quote(logical)}"


def _parse(paths, rc, text, patterns, max_rc: int = 1) -> Optional[set]:
    # Only rc 0..max_rc is a real answer; 124 (timeout), 125/126/127 (unknown,
    # refused, missing) and anything larger mean "unknown", never "unowned".
    if not (0 <= rc <= max_rc):
        return None
    lines = {ln.strip() for ln in text.splitlines()}
    return {p for p in paths if any(pat.format(p=p) in lines for pat in patterns)}


def parse_dpkg(paths, rc, out, err) -> Optional[set]:
    return _parse(
        paths, rc, f"{out}\n{err}",
        ("dpkg-query: no path found matching pattern {p}",
         "no path found matching pattern {p}"),
    )


def parse_rpm(paths, rc, out, err) -> Optional[set]:
    return _parse(
        paths, rc, f"{out}\n{err}", ("file {p} is not owned by any package",),
        max_rc=len(paths),  # rpm -qf exits with the number of failed queries
    )


def parse_pacman(paths, rc, out, err) -> Optional[set]:
    return _parse(
        paths, rc, f"{out}\n{err}",
        ("error: No package owns {p}",),
    )


_PARSERS = {"dpkg": parse_dpkg, "rpm": parse_rpm, "pacman": parse_pacman}
_QUERY_ARGV = {
    "dpkg": ["dpkg-query", "-S"],
    "rpm": ["rpm", "-qf"],
    "pacman": ["pacman", "-Qo"],
}
_GLOB_CHARS = set("*?[]\\")
_MERGED = ("bin", "sbin", "lib", "lib32", "lib64", "libx32")


def _usr_alias(p: str) -> Optional[str]:
    """The usr-merge twin of ``p`` (/bin/x <-> /usr/bin/x), else None."""
    for d in _MERGED:
        if p == f"/{d}" or p.startswith(f"/{d}/"):
            return "/usr" + p
        if p == f"/usr/{d}" or p.startswith(f"/usr/{d}/"):
            return p[len("/usr"):]
    return None


def query_unowned(
    backend: str,
    logical_paths: Sequence[str],
    budget: ScanBudget,
    *,
    batch: int = 100,
    timeout: int = 60,
) -> set:
    """Subset of ``logical_paths`` that no package owns (positive evidence only).

    Skipped (counted as owned): paths with glob characters or with newline /
    CR / NUL (a crafted name could forge an "unowned" output line). A path in a
    usr-merge alias pair is unowned only if both forms are unowned.
    """
    if backend not in _PARSERS:
        return set()
    wanted = [
        p for p in logical_paths
        if not (_GLOB_CHARS & set(p)) and not bad_name(p)
    ]
    queryable = list(dict.fromkeys(
        q for p in wanted for q in (p, _usr_alias(p)) if q
    ))
    unowned: set = set()
    for i in range(0, len(queryable), batch):
        if budget.expired():
            break
        chunk = queryable[i : i + batch]
        rc, out, err = run([*_QUERY_ARGV[backend], *chunk], timeout)
        res = _PARSERS[backend](chunk, rc, out, err)
        if res:
            unowned |= res
    result = set()
    for p in wanted:
        alias = _usr_alias(p)
        if p in unowned and (alias is None or alias in unowned):
            result.add(p)
    return result


def installed_package_names(backend: str) -> Optional[set]:
    argv = {
        "dpkg": ["dpkg-query", "-W", "-f=${Package}\\n"],
        "rpm": ["rpm", "-qa", "--qf", "%{NAME}\\n"],
        "pacman": ["pacman", "-Qq"],
    }.get(backend)
    if argv is None:
        return None
    rc, out, _ = run(argv)
    if rc != 0:
        return None
    return {ln.strip() for ln in out.splitlines() if ln.strip()}


def system_account_names(root: str | Path) -> set:
    try:
        text = in_root(root, "/etc/passwd").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return set()
    return {ln.split(":", 1)[0] for ln in text.splitlines() if ln and ":" in ln}


def _norm(name: str) -> str:
    return re.sub(r"\d+$", "", re.sub(r"[^a-z0-9]", "", name.lower()))


# ---------------------------------------------------------------- reporter
MAX_NOTES = 25  # per scan; a detector yielding more gets one "suppressed" note


class OrphanReporter(Cleaner):
    """Base for report-only orphan detectors."""

    requires_root = False
    sysroot: str = "/"

    def __init__(self, config):
        super().__init__(config)
        self._reset()

    def _reset(self) -> None:
        self.budget = ScanBudget(
            self.config.orphan_max_items, self.config.orphan_max_seconds
        )
        self._system_done = False
        self._stop_noted = False
        self._notes = 0

    def scan(self):
        self._reset()
        self.budget.start()  # the clock runs from scan start, not construction
        return super().scan()

    def pkg_backend(self) -> Optional[str]:
        return detect_pkg_backend()

    def system_findings(self) -> Iterable[Finding]:
        return ()

    def user_findings(self) -> Iterable[Finding]:
        return ()

    def note(
        self, path: Path, label: str, hint: str, requires_root: bool = True
    ) -> Finding:
        return Finding(path, label, hint, requires_root, note=True)

    def find_items(self):
        if self.budget.stop_reason:
            # an earlier pass (e.g. another user) already ran out
            yield from self._stop_note()
            return
        if not self._system_done:
            self._system_done = True
            yield from self._emit(self.system_findings())
            yield from self._stop_note()
            if self.budget.stop_reason:
                return
        yield from self._emit(self.user_findings())
        yield from self._stop_note()

    def _stop_note(self):
        """The one "results are incomplete" note, once the budget has run out.

        Detectors that simply stop discovering when ``budget.expired()`` rely
        on this; it is emitted at most once per scan.
        """
        if self._stop_noted or not self.budget.stop_reason:
            return
        self._stop_noted = True
        yield self._item(
            Finding(
                Path(self.sysroot),
                f"Scan stopped early ({self.budget.stop_reason}); "
                "results are incomplete",
                "Raise orphan_max_items / orphan_max_seconds in the "
                "config to scan further.",
                requires_root=False,
                note=True,
            ),
            0,
            True,
        )

    def _emit(self, findings: Iterable[Finding]):
        for f in findings:
            if f.note:
                self._notes += 1
                if self._notes <= MAX_NOTES:
                    yield self._item(f, 0, True)
                elif self._notes == MAX_NOTES + 1:
                    yield self._item(
                        Finding(
                            f.path, "More notes suppressed",
                            "Further unreadable or skipped locations are not listed.",
                            requires_root=False, note=True,
                        ),
                        0, True,
                    )
                continue
            if not self.budget.take():
                yield from self._stop_note()
                return
            size, complete = bounded_size(f.path, self.budget)
            yield self._item(f, size, complete)

    def _item(self, f: Finding, size: int, complete: bool) -> CleanableItem:
        desc = safe_label(f.label)
        if not complete:
            desc += " (size is a lower bound)"
        return CleanableItem(
            cleaner_id=self.id,
            description=desc,
            size=size,
            kind=ItemKind.PATH,
            path=str(f.path),
            requires_root=f.requires_root,
            report_only=True,
            hint=f.hint,
        )
