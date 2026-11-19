"""Report-only: macOS launch jobs whose program no longer exists.

Scans ``~/Library/LaunchAgents`` (per user) and ``/Library/LaunchAgents`` plus
``/Library/LaunchDaemons`` (once per scan). ``/System/Library`` is never
looked at. Nothing is ever removed; each finding carries a hint naming the
one plist and how to confirm it before moving it to the Trash.

Unknown is not orphan: unparsable plists become notes, and programs that are
relative, templated, on removable/network volumes, in SIP-protected system
locations, inside an app bundle that still exists, or whose existence cannot
be determined are never reported.
"""

from __future__ import annotations

import os
import plistlib
import shlex
from pathlib import Path
from typing import Iterable, Optional

from cleanix.cleaners import orphan_common as oc
from cleanix.cleaners.base import SCOPE_USER
from cleanix.core.platform import MACOS
from cleanix.core.utils import current_uid, home

MAX_PLIST_BYTES = 1024 * 1024
_SIP_PREFIXES = ("/System", "/bin", "/sbin", "/usr")  # /usr/local is not SIP


def job_program(plist: dict) -> Optional[str]:
    """``Program``, else ``ProgramArguments[0]``; None for ``BundleProgram``."""
    if "BundleProgram" in plist:
        return None
    prog = plist.get("Program")
    if isinstance(prog, str) and prog:
        return prog
    args = plist.get("ProgramArguments")
    if isinstance(args, list) and args and isinstance(args[0], str) and args[0]:
        return args[0]
    return None


def _under(logical: str, prefix: str) -> bool:
    return logical == prefix or logical.startswith(prefix + "/")


def _is_sip(logical: str) -> bool:
    if _under(logical, "/usr/local"):
        return False
    return any(_under(logical, p) for p in _SIP_PREFIXES)


def _exists(path: Path) -> Optional[bool]:
    """True/False for a definite answer, None when it cannot be told."""
    try:
        os.stat(path)
        return True
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return None


class OrphanLaunchJobReporter(oc.OrphanReporter):
    id = "orphan_launch_jobs"
    name = "Background jobs of removed apps"
    description = "LaunchAgents and LaunchDaemons whose program is missing (report only)"
    platforms = (MACOS,)
    scope = SCOPE_USER

    # ------------------------------------------------------------ discovery
    def system_findings(self) -> Iterable[oc.Finding]:
        for sub in ("/Library/LaunchAgents", "/Library/LaunchDaemons"):
            yield from self._scan_dir(oc.in_root(self.sysroot, sub), system=True)

    def user_findings(self) -> Iterable[oc.Finding]:
        yield from self._scan_dir(home() / "Library" / "LaunchAgents", system=False)

    def _scan_dir(self, directory: Path, system: bool) -> Iterable[oc.Finding]:
        children = oc.list_dir(directory)
        if children is None:
            yield self.note(
                directory,
                f"Could not read {oc.logical_path(self.sysroot, directory)}",
                "Not checked. Grant Full Disk Access or run with admin rights to include it.",
                requires_root=system,
            )
            return
        for plist in sorted(children):
            if self.budget.expired():
                return
            if plist.suffix != ".plist" or oc.bad_name(plist.name):
                continue
            if plist.name.startswith("com.apple."):
                continue
            finding = self._check(plist, system)
            if finding is not None:
                yield finding

    # -------------------------------------------------------------- checking
    def _check(self, plist: Path, system: bool) -> Optional[oc.Finding]:
        logical = oc.logical_path(self.sysroot, plist)
        if os.path.islink(plist):
            if oc.link_target_exists(plist, self.sysroot) is False:
                return oc.Finding(
                    plist,
                    f"Broken job link: {logical}",
                    self._hint(logical, "", system),
                    requires_root=system,
                )
            try:
                if os.readlink(plist) == "/dev/null":
                    return None  # launchd's "disabled" idiom, not a job
            except OSError:
                return None
        data = self._load(plist)
        if isinstance(data, str):  # reason: unreadable
            return self.note(
                plist,
                f"Could not read launch job {logical}: {data}",
                f"Not checked. Inspect {shlex.quote(logical)} manually if you suspect it is stale.",
                requires_root=system,
            )
        if data is None:
            return None
        label = data.get("Label")
        label = label if isinstance(label, str) and label else plist.stem
        if label.startswith("com.apple."):
            return None
        program = job_program(data)
        if not program or not program.startswith("/"):
            return None
        if "~" in program or "$" in program or oc.bad_name(program):
            return None
        if oc.is_removable_location(program) or _is_sip(program):
            return None
        if self._exists_or_unknown(program):
            return None
        return oc.Finding(
            plist,
            f"Background job for a missing program: {label} (runs {program})",
            self._hint(logical, label, system),
            requires_root=system,
        )

    def _load(self, plist: Path):
        """dict on success, None to skip silently, str reason when unreadable."""
        try:
            if plist.stat().st_size > MAX_PLIST_BYTES:
                return "file is unusually large"
            with open(plist, "rb") as fh:
                data = plistlib.load(fh)
        except (plistlib.InvalidFileException, ValueError, EOFError, OverflowError):
            return "not a valid property list"
        except OSError:
            return "permission denied or unreadable"
        except Exception:  # noqa: BLE001 - expat and friends on hostile files
            return "not a valid property list"
        return data if isinstance(data, dict) else None

    def _exists_or_unknown(self, program: str) -> bool:
        """True when the program (or an enclosing app bundle) exists or when
        that cannot be determined."""
        found = _exists(oc.in_root(self.sysroot, program))
        if found is not False:
            return True
        parts = program.split("/")
        for i in range(2, len(parts)):
            if parts[i - 1].endswith(".app"):
                bundle = "/".join(parts[:i])
                if _exists(oc.in_root(self.sysroot, bundle)) is not False:
                    return True
        return False

    def _hint(self, logical: str, label: str, system: bool) -> str:
        q = shlex.quote(logical)
        if system:
            stop = f"sudo launchctl bootout system {q}"
        else:
            uid = current_uid()
            stop = f"launchctl bootout gui/{uid if uid is not None else '$(id -u)'} {q}"
        hint = (
            f"Confirm with: pkgutil --file-info {q}. "
            f"If unused: {stop}, then move {q} to the Trash."
        )
        if label.startswith("homebrew.mxcl."):
            hint += " For Homebrew services, check brew services list first."
        return hint
