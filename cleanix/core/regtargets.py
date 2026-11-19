"""Deciding whether a registry entry's target is provably missing.

Existence is tri-state. MISSING is reported only for a path on a mounted,
readable, fixed local drive whose ``lstat`` failed with "not found". Any
ambiguity (unexpandable variables, network or removable drives, quoting we
cannot parse, App Execution Aliases, System32 redirection, 8.3 names, access
errors) is UNKNOWN. Unknown is not dead. Every path operation uses ``ntpath``
so behaviour is identical on every OS.
"""

from __future__ import annotations

import ntpath
import os
import re
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Mapping, Optional, Protocol, Sequence, Tuple

from cleanix.core.winregistry import RegistryUnavailable


class Existence(Enum):
    PRESENT = "present"
    MISSING = "missing"
    UNKNOWN = "unknown"


class Prober(Protocol):
    def probe(self, path: str) -> Existence: ...


@dataclass(frozen=True)
class DetectorContext:
    env: Mapping[str, str]
    prober: Prober
    profiles_root: str
    system_root: str


DRIVE_FIXED = 3

HOST_EXES = frozenset(
    {
        "msiexec",
        "rundll32",
        "cmd",
        "powershell",
        "pwsh",
        "wscript",
        "cscript",
        "regsvr32",
        "mshta",
        "explorer",
        "conhost",
        "dllhost",
        "wsl",
    }
)

_ENV_RE = re.compile(r"%([^%\r\n]+)%")
_ICON_RE = re.compile(r",\s*-?\d+\s*$")
_DRIVE_ABS = re.compile(r"^[A-Za-z]:\\")
_BAD_CHARS = re.compile(r'[<>"|?*:\x00-\x1f]')
_SHORT_NAME = re.compile(r"~\d")
_DEVICE_NAMES = frozenset(
    {"con", "prn", "aux", "nul", "conin$", "conout$", "clock$"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)
_EXTENDED = "\\\\?\\"


def expand_env(text: str, env: Mapping[str, str]) -> Optional[str]:
    """Expand ``%NAME%`` (case-insensitive); None if any reference is unresolved."""
    folded = {str(k).casefold(): str(v) for k, v in env.items()}
    failed = False

    def sub(m: "re.Match[str]") -> str:
        nonlocal failed
        val = folded.get(m.group(1).casefold())
        if val is None:
            failed = True
            return m.group(0)
        return val

    out = _ENV_RE.sub(sub, text)
    return None if failed else out


def strip_icon_index(text: str) -> str:
    """Remove a trailing ``,<-?digits>`` icon index."""
    return _ICON_RE.sub("", text)


@dataclass(frozen=True)
class CommandParse:
    candidates: Tuple[str, ...]
    host: bool
    relative: bool


def _unwrap(path: str) -> str:
    """Slashes to backslashes and drop a ``\\\\?\\`` prefix (not ``\\\\?\\UNC``)."""
    p = path.replace("/", "\\")
    if p.startswith(_EXTENDED) and not p[4:].upper().startswith("UNC\\"):
        p = p[4:]
    return p


def _is_drive_abs(path: str) -> bool:
    return bool(_DRIVE_ABS.match(_unwrap(path)))


def _with_exe(path: str) -> Tuple[str, ...]:
    if ntpath.splitext(ntpath.basename(path))[1] == "":
        return (path, path + ".exe")
    return (path,)


def _stem(path: str) -> str:
    base = ntpath.basename(path.replace("/", "\\")).casefold()
    return base[:-4] if base.endswith(".exe") else base


_UNPARSEABLE = CommandParse((), False, True)


def parse_command(cmd: str) -> CommandParse:
    """Candidate executables of a command line, in CreateProcess order.

    Anything we cannot parse unambiguously yields no candidates and
    ``relative=True`` so the caller reports UNKNOWN.
    """
    text = cmd.strip()
    if not text:
        return _UNPARSEABLE
    cands: List[str] = []
    if text[0] == '"':
        end = text.find('"', 1)
        if end <= 1:
            return _UNPARSEABLE
        if len(text) > end + 1 and not text[end + 1].isspace():
            return _UNPARSEABLE
        token = text[1:end]
        if not token.strip():
            return _UNPARSEABLE
        cands.extend(_with_exe(token))
    else:
        prefixes = [text[:i].rstrip() for i, ch in enumerate(text) if ch == " "]
        prefixes.append(text)
        for pre in prefixes:
            if not pre:
                continue
            for c in _with_exe(pre):
                if c not in cands:
                    cands.append(c)
    host = any(_stem(c) in HOST_EXES for c in cands)
    relative = not any(_is_drive_abs(c) for c in cands)
    return CommandParse(tuple(cands), host, relative)


def _canon(path: str) -> str:
    return ntpath.normpath(_unwrap(path))


def _under(path: str, root: str) -> bool:
    p = path.casefold().rstrip("\\")
    r = root.casefold().rstrip("\\")
    return bool(r) and (p == r or p.startswith(r + "\\"))


def _first_component_after(path: str, root: str) -> str:
    rest = path[len(root.rstrip("\\")) :].lstrip("\\")
    return rest.split("\\", 1)[0].casefold()


def microsoft_roots(env: Mapping[str, str], system_drive: str) -> Tuple[str, ...]:
    """The ``<PF>`` set: every Program Files root we might see, deduplicated."""
    folded = {str(k).casefold(): str(v) for k, v in env.items()}
    roots: List[str] = []
    for name in ("programw6432", "programfiles", "programfiles(x86)"):
        v = folded.get(name)
        if v:
            roots.append(ntpath.normpath(v))
    sd = system_drive.rstrip("\\/")
    roots.append(sd + "\\Program Files")
    roots.append(sd + "\\Program Files (x86)")
    seen = set()
    out: List[str] = []
    for r in roots:
        k = r.casefold()
        if k not in seen:
            seen.add(k)
            out.append(r)
    return tuple(out)


class WinProber:
    """Tri-state existence of a Windows path (R11)."""

    def __init__(
        self,
        *,
        system_root: str,
        program_files: Sequence[str],
        program_data: str,
        local_appdata: str,
        drive_type: Callable[[str], int],
        lstat: Callable[[str], object] = os.lstat,
    ) -> None:
        self._system_root = system_root
        self._program_files = tuple(program_files)
        self._program_data = program_data
        self._local_appdata = local_appdata
        self._drive_type = drive_type
        self._lstat = lstat

    def _microsoft_owned(self, path: str) -> bool:
        if self._system_root and _under(path, self._system_root):
            return True
        for pf in self._program_files:
            if _under(path, pf):
                first = _first_component_after(path, pf)
                if first.startswith(("windows", "microsoft", "internet explorer")):
                    return True
        for base in (self._program_data, self._local_appdata):
            if base and _under(path, base):
                if _first_component_after(path, base).startswith("microsoft"):
                    return True
        return False

    def _exists(self, path: str) -> bool:
        try:
            self._lstat(path)
            return True
        except Exception:
            return False

    def probe(self, path: str) -> Existence:
        p = path.replace("/", "\\")
        if p.startswith("\\\\"):
            # UNC, device and \\?\UNC paths are never judged; \\?\X:\ is unwrapped.
            if not p.startswith(_EXTENDED):
                return Existence.UNKNOWN
            p = p[4:]
        if not _DRIVE_ABS.match(p):
            return Existence.UNKNOWN
        if _BAD_CHARS.search(p[2:]):  # wildcards, streams, control characters
            return Existence.UNKNOWN
        norm = ntpath.normpath(p)
        if not _DRIVE_ABS.match(norm):
            return Existence.UNKNOWN
        comps = [c for c in norm[3:].split("\\") if c]
        for i, comp in enumerate(comps):
            # Win32 trims trailing dots/spaces from the final name only.
            if i == len(comps) - 1 and comp != comp.rstrip(" ."):
                return Existence.UNKNOWN
            if comp.casefold().split(".", 1)[0] in _DEVICE_NAMES:
                return Existence.UNKNOWN
        root = norm[:3]
        try:
            if self._drive_type(root) != DRIVE_FIXED:
                return Existence.UNKNOWN
        except Exception:
            return Existence.UNKNOWN
        if self._microsoft_owned(norm):
            return Existence.PRESENT if self._exists(norm) else Existence.UNKNOWN
        if any(_SHORT_NAME.search(c) for c in norm.split("\\")):
            return Existence.PRESENT if self._exists(norm) else Existence.UNKNOWN
        try:
            self._lstat(norm)
            return Existence.PRESENT
        except OSError as exc:
            if getattr(exc, "winerror", None) not in (2, 3):
                return Existence.UNKNOWN
        except Exception:
            return Existence.UNKNOWN
        # Not found: only trust it when the drive root itself is readable.
        return Existence.MISSING if self._exists(root) else Existence.UNKNOWN


def target_state(
    raw: str, *, command: bool, ctx: DetectorContext, machine: bool
) -> Existence:
    """Existence of the file a registry value points at."""
    expanded = expand_env(raw, ctx.env)
    if expanded is None:
        return Existence.UNKNOWN
    if command:
        parsed = parse_command(expanded)
        if parsed.host or parsed.relative or not parsed.candidates:
            return Existence.UNKNOWN
        cands: Tuple[str, ...] = parsed.candidates
    else:
        s = expanded.strip()
        if len(s) >= 2 and s[0] == s[-1] == '"':
            s = s[1:-1].strip()
        if not s:
            return Existence.UNKNOWN
        cands = (s,)
    if machine:
        for c in cands:
            if _under(_canon(c), ctx.profiles_root):
                return Existence.UNKNOWN
    states = []
    for c in cands:
        try:
            states.append(ctx.prober.probe(c))
        except Exception:
            return Existence.UNKNOWN
    if Existence.PRESENT in states:
        return Existence.PRESENT
    if states and all(st is Existence.MISSING for st in states):
        return Existence.MISSING
    return Existence.UNKNOWN


def default_context() -> DetectorContext:
    if sys.platform != "win32":
        raise RegistryUnavailable("target evidence needs Windows")
    from cleanix.core import winenv

    env = dict(os.environ)
    sd = winenv.system_drive()

    def drive_type(root: str) -> int:
        import ctypes

        return int(ctypes.windll.kernel32.GetDriveTypeW(root))  # type: ignore[attr-defined]

    system_root = str(winenv.system_root())
    prober = WinProber(
        system_root=system_root,
        program_files=microsoft_roots(env, sd),
        program_data=str(winenv.programdata()),
        local_appdata=str(winenv.local_appdata()),
        drive_type=drive_type,
    )
    public = {k.casefold(): v for k, v in env.items()}.get("public")
    profiles = ntpath.dirname(ntpath.normpath(public)) if public else ""
    if not _DRIVE_ABS.match(profiles + "\\"):
        profiles = sd.rstrip("\\/") + "\\Users"
    return DetectorContext(
        env=env, prober=prober, profiles_root=profiles, system_root=system_root
    )
