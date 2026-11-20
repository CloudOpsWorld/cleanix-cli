"""Report-only detector for stale systemd units, drop-ins and enablement links.

Only administrator-owned directories are scanned (vendor directories are never
reported). Anything that cannot be judged with certainty is left alone:
unresolvable or templated ExecStart values, removable/network locations,
generator output, masked units, units whose drop-ins touch ExecStart or
Condition*/Assert*.

Known limitation: only the directories listed below are scanned. Unit
directories such as ``/etc/xdg/systemd/user`` are used for existence lookups
only, never reported.
"""

from __future__ import annotations

import os
import shlex
import stat
from pathlib import Path
from typing import Iterable, Iterator, Optional

from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners.base import SCOPE_USER
from cleanix.cleaners.orphan_common import Finding, OrphanReporter
from cleanix.core import utils
from cleanix.core.platform import LINUX
from cleanix.core.remedy import RemedyKind

_SYSTEM_SCAN = (
    "/etc/systemd/system",
    "/usr/local/lib/systemd/system",
    "/etc/systemd/user",
)
_SYSTEM_USER_DIR = "/etc/systemd/user"
# The system unit search path (systemd.unit(5)), plus Debian's /lib.
_SYSTEM_LOOKUP = (
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator.late",
)
_USER_LOOKUP_SYSTEM_PART = (
    "/etc/systemd/user",
    "/usr/local/lib/systemd/user",
    "/usr/lib/systemd/user",
    "/lib/systemd/user",
    "/etc/xdg/systemd/user",
    "/run/systemd/user",
    "/usr/share/systemd/user",
    "/var/lib/flatpak/exports/share/systemd/user",
)
_USER_LOOKUP_HOME = (
    ".config/systemd/user",
    ".local/share/systemd/user",
    ".local/share/flatpak/exports/share/systemd/user",
)
_BIN_DIRS = (
    "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
)
_LINK_SUBDIRS = (".wants", ".requires", ".upholds")
_DROPIN_SUFFIXES = (".service", ".socket", ".timer", ".path")
_MAX_UNIT_BYTES = 1024 * 1024
_STRIP = "@-:+!"


class StaleSystemdUnitReporter(OrphanReporter):
    id = "stale_services"
    name = "Services for removed programs"
    description = (
        "systemd units, drop-ins and enablement links whose program or unit "
        "is gone (report only)"
    )
    platforms = (LINUX,)
    scope = SCOPE_USER

    def available(self) -> Optional[str]:
        for d in ("/etc/systemd/system", "/usr/lib/systemd/system"):
            if os.path.isdir(oc.in_root(self.sysroot, d)):
                return None
        return "systemd unit directories not found"

    # -------------------------------------------------------------- entry
    def system_findings(self) -> Iterable[Finding]:
        for logical in _SYSTEM_SCAN:
            lookup = (
                _USER_LOOKUP_SYSTEM_PART
                if logical == "/etc/systemd/user"
                else _SYSTEM_LOOKUP
            )
            dirs = [oc.in_root(self.sysroot, d) for d in lookup]
            yield from self._scan_dir(
                oc.in_root(self.sysroot, logical), dirs, user=False
            )

    def user_findings(self) -> Iterable[Finding]:
        home = Path(utils.home())
        dirs = user_lookup_dirs(home, self.sysroot)
        yield from self._scan_dir(home / ".config/systemd/user", dirs, user=True)

    # --------------------------------------------------------------- scan
    def _scan_dir(self, root_dir: Path, lookup: list, user: bool) -> Iterator[Finding]:
        entries = oc.list_dir(root_dir)
        if entries is None:
            yield self._unreadable(root_dir, user)
            return
        for entry in sorted(entries):
            if self.budget.expired():
                return
            name = entry.name
            if oc.bad_name(name):
                continue
            mode = _lmode(entry)
            if mode is None:
                continue
            if stat.S_ISLNK(mode):
                yield from self._check_link(entry, user, lookup)
            elif stat.S_ISREG(mode) and name.endswith(".service"):
                yield from self._check_unit(entry, lookup, user)
            elif stat.S_ISDIR(mode):
                if name.endswith(_LINK_SUBDIRS):
                    yield from self._scan_links_dir(entry, user, lookup)
                elif name.endswith(".d"):
                    yield from self._check_dropin(entry, lookup, user)

    def _scan_links_dir(self, d: Path, user: bool, lookup: list) -> Iterator[Finding]:
        children = oc.list_dir(d)
        if children is None:
            yield self._unreadable(d, user)
            return
        for child in sorted(children):
            if self.budget.expired():
                return
            if oc.bad_name(child.name):
                continue
            mode = _lmode(child)
            if mode is not None and stat.S_ISLNK(mode):
                yield from self._check_link(child, user, lookup, in_link_dir=True)

    # ------------------------------------------------------ (b) broken link
    def _check_link(self, link: Path, user: bool, lookup: Optional[list] = None,
                    in_link_dir: bool = False) -> Iterator[Finding]:
        try:
            target = os.readlink(link)
        except OSError:
            return
        if oc.bad_name(target) or target == "/dev/null":
            return
        if oc.is_removable_location(target) or target.startswith("/run/"):
            return  # unknown, not stale
        if oc.link_target_exists(link, self.sysroot) is not False:
            return
        # Helper (root) scans: a missing target an ordinary user could have
        # removed (a folder on the way they can write, a link) is unknown.
        if oc.evidence_problem(oc.link_dest(link, self.sysroot)):
            return
        logical = oc.logical_path(self.sysroot, link)
        yield Finding(
            link,
            f"Broken unit link: {logical} -> {target}",
            self._hint(link.name, logical, user),
            requires_root=not user,
            **self._link_remedy(link, logical, user, lookup, in_link_dir),
        )

    def _link_remedy(self, link: Path, logical: str, user: bool,
                     lookup: Optional[list], in_link_dir: bool) -> dict:
        """Finding kwargs for the remedy of a broken unit link.

        User links: no remedy (report only) -- act never removes a link
        through a plain PATH remedy, and nothing would re-check that it is
        still broken, so nothing is offered. System-wide links: the
        LINK remedy (the link itself, elevated helper only) -- but none when
        it may still be live. systemd adds a ``*.wants``/``*.requires``/
        ``*.upholds`` dependency by the LINK's name, whatever its target, so
        such a link still enables its unit when a unit of that name (or its
        ``prefix@.type`` template) exists anywhere on the load path; links
        under /etc/systemd/user are resolved by each user's manager against
        units this scan cannot see (their homes). Unknown is "maybe live"."""
        if user:
            return {}
        if logical == _SYSTEM_USER_DIR or logical.startswith(_SYSTEM_USER_DIR + "/"):
            return {}
        if in_link_dir:
            if lookup is None:
                return {}
            name = link.name
            stem, dot, typ = name.rpartition(".")
            if not dot or _unit_known(name, lookup):
                return {}
            if "@" in stem and _unit_known(f"{stem.split('@', 1)[0]}@.{typ}", lookup):
                return {}
        return {"remedy_kind": RemedyKind.PATH, "remedy_extra": oc.LINK_REMEDY}

    # ------------------------------------------------------ (c) drop-in
    def _check_dropin(self, d: Path, lookup: list, user: bool) -> Iterator[Finding]:
        unit = d.name[:-2]
        if not unit.endswith(_DROPIN_SUFFIXES):
            return
        stem = unit.rsplit(".", 1)[0]
        if not stem or stem.endswith("-"):
            return
        if _unit_known(unit, lookup):
            return
        if "@" in stem:
            prefix = stem.split("@", 1)[0]
            if _unit_known(f"{prefix}@.{unit.rsplit('.', 1)[1]}", lookup):
                return
        logical = oc.logical_path(self.sysroot, d)
        # A system-wide drop-in for USER units (/etc/systemd/user) applies to
        # units that may exist only in some user's home, which this scan
        # cannot see: no remedy (report only), never removed by the helper.
        for_user_units = not user and logical.startswith(_SYSTEM_USER_DIR + "/")
        yield Finding(
            d,
            f"Settings for a removed service: {logical}",
            self._hint(unit, logical, user),
            requires_root=not user,
            remedy_kind=None if for_user_units else RemedyKind.PATH,
        )

    # ------------------------------------------------------ (a) unit file
    def _check_unit(self, path: Path, lookup: list, user: bool) -> Iterator[Finding]:
        try:
            with open(path, "rb") as fh:
                text = fh.read(_MAX_UNIT_BYTES).decode("utf-8", errors="replace")
        except OSError:
            return
        execs, conds = _parse_unit(text)
        if not execs:
            return
        if _dropins_override(path.name, lookup):
            return  # drop-ins may repoint ExecStart or add conditions
        binaries = []
        for value in execs:
            value = value.lstrip(_STRIP)
            try:
                tokens = shlex.split(value)
            except ValueError:
                return  # cannot parse: unknown
            if not tokens:
                return
            if any(("%" in t or "$" in t) for t in tokens):
                return
            binaries.append(tokens[0])
        for raw, binary in zip(execs, binaries):
            if oc.is_removable_location(binary):
                return
            found = self._binary_present(binary)
            if found is None or found:
                return
            if "-" in raw[: len(raw) - len(raw.lstrip(_STRIP))]:
                return  # missing binary is explicitly tolerated by the unit
            if any(binary in c for c in conds):
                return
        logical = oc.logical_path(self.sysroot, path)
        yield Finding(
            path,
            f"Service for a missing program: {path.name} (runs {binaries[0]})",
            self._hint(path.name, logical, user),
            requires_root=not user,
            **self._unit_remedy(path.name),
        )

    @staticmethod
    def _unit_remedy(unit: str) -> dict:
        """Finding kwargs for a SYSTEMD_UNIT remedy (only for a plain name)."""
        if not unit.endswith(".service") or not oc.valid_ident(unit):
            return {}
        return {
            "remedy_kind": RemedyKind.SYSTEMD_UNIT,
            "remedy_extra": (("unit", unit),),
        }

    def _binary_present(self, binary: str) -> Optional[bool]:
        """True/False, or None when it cannot be judged."""
        if binary.startswith("/"):
            candidates = [binary]
        elif "/" in binary:
            return None
        else:
            candidates = [f"{d}/{binary}" for d in _BIN_DIRS]
        try:
            if any(os.path.exists(oc.in_root(self.sysroot, c)) for c in candidates):
                return True
        except OSError:
            return None
        # Helper (root) scans: an absence an ordinary user could cause is unknown.
        if any(oc.evidence_problem(str(oc.in_root(self.sysroot, c))) for c in candidates):
            return None
        return False

    # ------------------------------------------------------------- misc
    def _reset(self) -> None:
        super()._reset()
        self._backend_known = False
        self._backend = None

    def _hint(self, unit: str, logical: str, user: bool) -> str:
        ctl = "systemctl --user" if user else "systemctl"
        sudo = "" if user else "sudo "
        check = f"{ctl} status {shlex.quote(unit)}"
        if not self._backend_known:
            self._backend_known = True
            self._backend = self.pkg_backend()  # once per scan, not per finding
        owner = oc.owner_check_command(self._backend, logical)
        if owner:
            check += f"; {owner}"
        return (
            f"Confirm it is unused: {check}. If so: {sudo}{ctl} disable "
            f"{shlex.quote(unit)}, remove {shlex.quote(logical)} by hand, "
            f"then {sudo}{ctl} daemon-reload."
        )

    def _unreadable(self, path: Path, user: bool) -> Finding:
        logical = oc.logical_path(self.sysroot, path)
        return self.note(
            path,
            f"Could not read {logical}; stale units there were not checked",
            f"Check the directory by hand: ls -l {shlex.quote(logical)}",
            requires_root=not user,
        )


def user_lookup_dirs(home: Path, sysroot: str) -> list:
    """Where a user unit (and its drop-ins) may live: ``home``'s own unit
    directories first, then the system-wide user-unit directories. Shared
    with the act-time re-check (:mod:`cleanix.core.remedy_exec`)."""
    dirs = [Path(home) / d for d in _USER_LOOKUP_HOME]
    dirs += [oc.in_root(sysroot, d) for d in _USER_LOOKUP_SYSTEM_PART]
    return dirs


def _lmode(p: Path) -> Optional[int]:
    try:
        return os.lstat(p).st_mode
    except OSError:
        return None


def _unit_known(unit: str, lookup: list) -> bool:
    for d in lookup:
        try:
            os.lstat(Path(d) / unit)
            return True
        except FileNotFoundError:
            continue
        except OSError:
            return True  # unreadable: unknown, so treat as present
    return False


def _dropin_dir_names(unit: str) -> list:
    stem, _, typ = unit.rpartition(".")
    names = [f"{unit}.d", f"{typ}.d"]
    parts = stem.split("-")
    for i in range(1, len(parts)):
        names.append("-".join(parts[:i]) + f"-.{typ}.d")
    if "@" in stem:
        names.append(f"{stem.split('@', 1)[0]}@.{typ}.d")
    return names


def _dropins_override(unit: str, lookup: list) -> bool:
    """True if any relevant drop-in mentions ExecStart/Condition/Assert, or
    cannot be read (unknown)."""
    for d in lookup:
        for name in _dropin_dir_names(unit):
            files = oc.list_dir(Path(d) / name)
            if files is None:
                return True
            for f in files:
                if not f.name.endswith(".conf"):
                    continue
                try:
                    with open(f, "rb") as fh:
                        text = fh.read(_MAX_UNIT_BYTES).decode("utf-8", "replace")
                except OSError:
                    return True
                if any(k in text for k in ("ExecStart", "Condition", "Assert")):
                    return True
    return False


def _parse_unit(text: str) -> tuple[list, list]:
    """(non-empty ExecStart values, Condition*/Assert* values)."""
    logical_lines: list = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not pending and (not line or line[0] in "#;"):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        logical_lines.append(pending + line)
        pending = ""
    if pending:
        logical_lines.append(pending)
    execs, conds = [], []
    for line in logical_lines:
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "ExecStart":
            if value:
                execs.append(value)
        elif key.startswith(("Condition", "Assert")):
            conds.append(value)
    return execs, conds


# ------------------------------------------------------- act-time re-check
_REVERIFY_SECONDS = 120.0


def _scan_root_of(logical: str) -> Optional[str]:
    """The scanned system folder ``logical`` lies in (directly, or in one of
    its ``*.wants``/``*.requires``/``*.upholds`` folders), else None."""
    parent = logical.rsplit("/", 1)[0]
    if parent in _SYSTEM_SCAN:
        return parent
    grand, _, sub = parent.rpartition("/")
    if grand in _SYSTEM_SCAN and sub.endswith(_LINK_SUBDIRS):
        return grand
    return None


def reverify_system_item(path: str, config) -> Optional[str]:
    """Act-time re-check of one system-wide finding (``reverify`` table):
    a broken unit link must still be a link whose target is positively
    missing (strict evidence); a drop-in folder (directly in a scanned
    folder, never ``/etc/systemd/user``) must still belong to no known
    unit. Unit files are not handled here (no PATH remedy). Anything
    unknown is a reason (fail closed)."""
    reporter = StaleSystemdUnitReporter(config)
    reporter.budget.start()
    real = Path(path)
    logical = oc.logical_path(reporter.sysroot, real)
    root = _scan_root_of(logical)
    if root is None:
        return "it is not in a folder this scenario checks"
    if oc.bad_name(real.name):
        return "its name cannot be checked"
    mode = _lmode(real)
    if mode is None:
        return "it cannot be inspected"
    if stat.S_ISLNK(mode):
        if root == _SYSTEM_USER_DIR:
            return "links for user units are never removed"
        dirs = [oc.in_root(reporter.sysroot, d) for d in _SYSTEM_LOOKUP]
        in_link_dir = logical.rsplit("/", 1)[0] != root
        found = list(reporter._check_link(real, False, dirs, in_link_dir))
        if not found:
            return "its target exists now, or cannot be confirmed missing"
        if found[0].remedy_kind is not RemedyKind.PATH:
            return "a unit of that name exists now (the link may still enable it)"
        return None
    directly_in_root = logical.rsplit("/", 1)[0] == root
    if stat.S_ISDIR(mode) and real.name.endswith(".d") and directly_in_root:
        if root == _SYSTEM_USER_DIR:
            return "drop-ins for user units are never removed"
        dirs = [oc.in_root(reporter.sysroot, d) for d in _SYSTEM_LOOKUP]
        if not list(reporter._check_dropin(real, dirs, user=False)):
            return "its service exists now, or cannot be confirmed missing"
        return None
    return "it is not a link or settings folder this scenario removes"
