"""Registry safety rules: what a detector may ever delete.

Pure policy (no registry access except the optional link check through a
backend). The file deletion guard in ``safety.py`` is unrelated and unchanged.
A deletable target is either an entry key exactly one level below a
key-level container, or a value directly inside a value-level container.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Tuple

from cleanix.core.models import RegTarget
from cleanix.core.winregistry import RegistryBackend, RegistryError


@dataclass(frozen=True)
class Container:
    hive: str
    key: str
    level: str  # "key" or "value"


_CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
_CVW = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion"
_CLASSES = r"SOFTWARE\Classes"


CONTAINERS: Mapping[str, Tuple[Container, ...]] = {
    "win_reg_uninstall": (
        Container("HKCU", _CV + r"\Uninstall", "key"),
        Container("HKLM", _CV + r"\Uninstall", "key"),
        Container("HKLM", _CVW + r"\Uninstall", "key"),
    ),
    "win_reg_app_paths": (
        Container("HKCU", _CV + r"\App Paths", "key"),
        Container("HKLM", _CV + r"\App Paths", "key"),
        Container("HKLM", _CVW + r"\App Paths", "key"),
    ),
    "win_reg_file_assoc": (
        Container("HKCU", _CLASSES, "key"),
        Container("HKLM", _CLASSES, "key"),
        Container("HKCU", _CLASSES + r"\Applications", "key"),
        Container("HKLM", _CLASSES + r"\Applications", "key"),
    ),
    "win_reg_startup": (
        Container("HKCU", _CV + r"\Run", "value"),
        Container("HKCU", _CV + r"\RunOnce", "value"),
        Container("HKLM", _CV + r"\Run", "value"),
        Container("HKLM", _CV + r"\RunOnce", "value"),
        Container("HKLM", _CVW + r"\Run", "value"),
        Container("HKLM", _CVW + r"\RunOnce", "value"),
    ),
    "win_reg_shared_dlls": (
        Container("HKLM", _CV + r"\SharedDLLs", "value"),
        Container("HKLM", _CVW + r"\SharedDLLs", "value"),
    ),
}

_HIVES = {
    "HKCU": "HKCU",
    "HKEY_CURRENT_USER": "HKCU",
    "HKLM": "HKLM",
    "HKEY_LOCAL_MACHINE": "HKLM",
}


def _p(path: str) -> Tuple[str, ...]:
    return tuple(path.casefold().split("\\"))


DENY_PREFIXES: Tuple[Tuple[str, ...], ...] = tuple(
    _p(p)
    for p in (
        r"software\microsoft\windows nt",
        r"software\microsoft\windows\currentversion\installer",
        r"software\microsoft\windows\currentversion\explorer",
        r"software\classes\installer",
        r"software\classes\clsid",
        r"software\classes\interface",
        r"software\classes\typelib",
        r"software\classes\appid",
        r"software\classes\local settings",
        r"software\classes\mime",
        r"software\classes\protocols",
    )
)
DENY_COMPONENTS = frozenset({"policies"})

_DENY_CLASS_EXACT = frozenset(
    {
        "*", "directory", "drive", "folder", "allfilesystemobjects",
        "systemfileassociations", "unknown", "exefile", "lnkfile", "batfile",
        "cmdfile", "comfile", "msi.package", "applications",
    }
)
_DENY_CLASS_PREFIXES = (
    "appx", "microsoft.", "windows.", "msedge", "ms-", "word.", "excel.",
    "powerpoint.", "outlook.", "access.", "onenote.", "visio.",
)


# Well-known Windows / browser / Office ProgIds (casefolded). Exact names and
# prefixes are merged once, at import time, into the deny tables below.
WINDOWS_PROGIDS = frozenset(
    {
        "txtfile", "txtfilelegacy", "paint.picture", "wordpad.document.1",
        "msinfo.document", "htafile", "msi.patch", "msi.package", "rtffile",
        "regfile", "inffile", "inifile", "cmdfile", "vbsfile", "vbefile",
        "jsfile", "jsefile", "wsffile", "wshfile", "chm.file", "cabfolder",
        "giffile", "jpegfile", "pngfile", "bmpfile", "icofile", "htmlfile",
        "mhtmlfile", "xmlfile", "msedgehtm", "chromehtml", "http", "https",
        "ftp", "file", "mailto", "component categories", "helpfile", "cabfile",
        "cdafile", "mscfile", "themefile", "curfile", "anifile", "dllfile",
        "sysfile", "cplfile", "scrfile", "ocxfile", "pffile", "fonfile",
        "ttffile", "otffile", "urlfile", "internetshortcut", "shortcut",
        "shell", "search", "search-ms", "telnet", "news", "nntp", "snews",
        "gopher", "tn3270", "sendto", "droptarget", "desktop", "network",
        "printers", "recyclebin",
    }
)
WINDOWS_PROGID_PREFIXES = ("firefoxhtml-", "ie.")
WINDOWS_APPLICATIONS = frozenset(
    f"{n}.exe"
    for n in (
        "explorer", "iexplore", "msedge", "notepad", "wordpad", "mspaint",
        "mmc", "cmd", "powershell", "wscript", "cscript", "regedit", "control",
        "calc", "write", "winword", "excel", "powerpnt", "outlook", "onenote",
    )
)
_DENY_CLASS_EXACT = _DENY_CLASS_EXACT | WINDOWS_PROGIDS
_DENY_CLASS_PREFIXES = _DENY_CLASS_PREFIXES + WINDOWS_PROGID_PREFIXES


def normalize(hive: str, key: str) -> Tuple[str, Tuple[str, ...]]:
    """Canonical ``(hive, casefolded components)``; raises ``ValueError`` for
    anything outside HKCU/HKLM ``SOFTWARE`` or any malformed path."""
    short = _HIVES.get(str(hive).upper())
    if short is None:
        raise ValueError(f"hive not allowed: {hive!r}")
    if not isinstance(key, str) or not key:
        raise ValueError("empty registry key")
    comps = []
    for comp in key.split("\\"):
        if comp in ("", ".", ".."):
            raise ValueError(f"bad registry key component: {comp!r}")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in comp):
            raise ValueError("control character in registry key")
        if comp != comp.strip():
            raise ValueError("whitespace around a registry key component")
        comps.append(comp.casefold())
    if comps[0] != "software":
        raise ValueError("registry key must be below SOFTWARE")
    return short, tuple(comps)


def _strip_wow(comps: Tuple[str, ...]) -> Tuple[str, ...]:
    if len(comps) > 1 and comps[1] == "wow6432node":
        return (comps[0],) + comps[2:]
    if len(comps) > 2 and comps[1] == "classes" and comps[2] == "wow6432node":
        return comps[:2] + comps[3:]
    return comps


def match_form(hive: str, key: str) -> Tuple[str, ...]:
    """Normalized components with the ``wow6432node`` alias removed when it
    directly follows ``software`` or ``software\\classes``."""
    _hive, comps = normalize(hive, key)
    return _strip_wow(comps)


def containers_for(cleaner_id: str) -> Tuple[Container, ...]:
    return CONTAINERS.get(cleaner_id, ())


def _folds(text: str) -> Tuple[str, str]:
    """Both comparison forms of a name. Windows compares by upper-casing,
    Python's casefold differs for a few characters (dotless i, long s), so a
    name is judged by both forms."""
    return text.casefold(), text.upper().casefold()


def _class_name_denied(name: str) -> bool:
    for n in _folds(name):
        if (
            n.startswith(".")
            or n in _DENY_CLASS_EXACT
            or n.startswith(_DENY_CLASS_PREFIXES)
        ):
            return True
    return False


def _bad_text(text: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)


def _all_container_matches() -> set:
    out = set()
    for conts in CONTAINERS.values():
        for c in conts:
            out.add(match_form(c.hive, c.key))
    return out


def _denied(comps: Tuple[str, ...]) -> bool:
    if DENY_COMPONENTS & set(comps):
        return True
    match = _strip_wow(comps)
    return any(match[: len(p)] == p for p in DENY_PREFIXES)


def check_target(
    cleaner_id: str,
    target: RegTarget,
    backend: Optional[RegistryBackend] = None,
) -> Optional[str]:
    """``None`` when ``target`` may be offered by ``cleaner_id``, else a short
    plain-language reason it may not."""
    containers = containers_for(cleaner_id)
    if not containers:
        return "unknown registry cleaner"
    if target.hive not in ("HKCU", "HKLM"):
        return "registry hive not allowed"
    hive = target.hive
    try:
        _h, comps = normalize(hive, target.key)
    except ValueError:
        return "not a valid registry location"
    parts = target.key.split("\\")

    if target.value is not None:
        if not isinstance(target.value, str) or not target.value:
            return "invalid value name"
        if _bad_text(target.value):
            return "invalid value name"

    # Everything above the entry name (the whole key for a value target)
    # must be plain ASCII: lookalike characters never reach a container.
    above = parts if target.value is not None else parts[:-1]
    if not all(p.isascii() for p in above):
        return "non-ASCII characters in the registry path"

    # The entry name is judged in both case-folding forms.
    last = () if target.value is not None else (parts[-1],)
    for form in range(2):
        variant = comps[: len(above)] + tuple(_folds(x)[form] for x in last)
        if _denied(variant):
            return "Windows-owned key"

    if target.value is None:
        if _strip_wow(comps) in _all_container_matches():
            return "a container key, not an entry"
        if "wow6432node" in _folds(parts[-1]):
            return "Windows redirection key"

    found = None
    for c in containers:
        chive, ccomps = normalize(c.hive, c.key)
        if chive != hive:
            continue
        if c.level == "key":
            if (
                target.value is None
                and len(comps) == len(ccomps) + 1
                and comps[: len(ccomps)] == ccomps
            ):
                found = c
                break
        elif target.value is not None and comps == ccomps:
            found = c
            break
    if found is None:
        return "not inside an allowed registry location"

    if cleaner_id == "win_reg_file_assoc":
        name = parts[-1]
        if not name.isascii() or _class_name_denied(name):
            return "Windows-owned file-type key"
        if comps[-2] == "applications" and any(
            f in WINDOWS_APPLICATIONS for f in _folds(name)
        ):
            return "Windows-owned file-type key"

    if backend is not None:
        for depth in range(2, len(parts) + 1):
            if hive == "HKCU" and depth == 2 and comps[1] == "classes":
                continue  # trusted anchor
            path = "\\".join(parts[:depth])
            try:
                if backend.is_link(hive, path):
                    return "registry link (symbolic link) in the path"
            except RegistryError:
                return "could not verify the key is not a link"
    return None
