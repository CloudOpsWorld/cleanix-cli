"""The elevated helper: ``python -m cleanix.elevated``.

Runs as root/Administrator (launched by ``cleanix.core.elevate_launch``) and
receives its instructions from a user-writable request file, so it trusts
nothing in it beyond *identifiers*:

1. The request must sit in a private directory owned by the requesting user
   (POSIX), and the result is written only into that same directory.
2. The requesting uid comes from ``--uid``, cross-checked against pkexec's
   ``PKEXEC_UID``; the user name is resolved from the uid, never just taken
   from the request.
3. Only that user's home is scanned (``context.configure(all_users=False)``).
4. A fresh scan is run; only items whose key was requested AND that are in the
   fresh scan AND require admin rights AND are not report-only are cleaned,
   through the normal engine (safety guard included).
5. The helper has its own deadline, below the launcher's timeout.

Exit codes (126/127 are never used: pkexec reserves them):
0 completed (details in the result file), 1 request unreadable/refused
(nothing deleted), 2 internal error, 3 deadline reached (partial result).
"""

from __future__ import annotations

import argparse
import math
import os
import sys
import time
from dataclasses import fields
from pathlib import Path
from typing import List, Optional, Sequence

from cleanix.core import context, elevate, service
from cleanix.core.models import item_key

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_INTERNAL = 2
EXIT_DEADLINE = 3
_ALLOWED_EXITS = {EXIT_OK, EXIT_REFUSED, EXIT_INTERNAL, EXIT_DEADLINE}

DEFAULT_DEADLINE = 3300.0  # seconds; the launcher gives up after 3600
MAX_CONFIG_BYTES = 1024 * 1024

# Config fields that name *where* to scan. The config is user-writable, so as
# admin these keep their built-in defaults: a user-chosen directory (possibly
# swapped for a link mid-clean) must never become a root deletion target.
# Items found there in the GUI's own scan come back as "unmatched".
_IGNORED_CONFIG_FIELDS = frozenset({"extra_cache_dirs", "symlink_scan_dirs",
                                    "project_scan_dirs"})

_monotonic = time.monotonic


class Refused(Exception):
    """The request (or its environment) is not acceptable; nothing deleted."""


def _is_posix() -> bool:
    return os.name != "nt"


def _user_for_uid(uid: int) -> Optional[str]:
    """Account name for ``uid`` from the system database (None if unknown)."""
    try:
        import pwd
    except ImportError:
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OverflowError, ValueError):
        return None


def _same_dir(a: Path, b: Path) -> bool:
    def norm(p: Path) -> str:
        return os.path.normcase(os.path.abspath(str(p)))

    return norm(a) == norm(b)


def _check_identity(requested: str, expected_uid: Optional[int]) -> str:
    """The invoking user's name, resolved from the uid where possible."""
    if expected_uid is None:
        if _is_posix():
            raise Refused("the requesting uid is unknown")
        return requested
    name = _user_for_uid(expected_uid)
    if name is None:
        if _is_posix():
            raise Refused("the requesting uid has no account")
        return requested
    if name != requested:
        raise Refused("the request names a different user than the one who launched it")
    return name


def _load_config(config_path: Optional[str], home: Path, expected_uid: Optional[int]):
    """The invoking user's config, read with the same checks as the request."""
    from cleanix.config import Config, _config_path

    if config_path:
        path = Path(config_path)
    elif _is_posix():
        path = home / ".config" / "cleanix" / "config.yaml"
    else:
        path = _config_path()
    cfg = Config()
    if not os.path.lexists(str(path)):
        return cfg
    try:
        data = elevate.read_secure(
            path, expected_uid=expected_uid if _is_posix() else None,
            max_bytes=MAX_CONFIG_BYTES, what="config", allow_root=True,
        )
    except ValueError as exc:
        raise Refused(str(exc)) from None
    try:
        import yaml
    except ImportError:
        return cfg
    try:
        obj = yaml.safe_load(data.decode("utf-8-sig")) or {}
    except Exception:  # noqa: BLE001 - never echo parser messages (file content)
        raise Refused("config is not valid YAML") from None
    if not isinstance(obj, dict):
        raise Refused("config is not a mapping")
    known = {f.name for f in fields(Config)} - _IGNORED_CONFIG_FIELDS
    for key, value in obj.items():
        if key in known and value is not None:
            setattr(cfg, key, value)
    if not isinstance(cfg.protected_globs, list):
        raise Refused("config protected_globs is not a list")
    cfg.protected_globs = [_user_glob(str(g), home) for g in cfg.protected_globs]
    return cfg


def _user_glob(glob: str, home: Path) -> str:
    """Expand ``~``/``$HOME`` against the invoking user's home, not the admin's."""
    for prefix in ("~", "$HOME", "${HOME}"):
        if glob == prefix:
            return str(home)
        if glob.startswith(prefix + "/") or glob.startswith(prefix + "\\"):
            return str(home) + glob[len(prefix):]
    return glob


def _bind_user(name: str) -> context.TargetUser:
    """Scope scanning to the invoking user's home only."""
    if _is_posix():
        os.environ["SUDO_USER"] = name
    clear = getattr(context.invoking_user, "cache_clear", None)
    if clear is not None:
        clear()
    context.configure(all_users=False)
    users = context.get_target_users()
    if len(users) != 1:
        raise Refused("could not restrict the scan to a single user")
    if _is_posix() and users[0].name != name:
        raise Refused("could not switch to the requesting user")
    return users[0]


def _safe_write(result_path: Path, result: elevate.HelperResult,
                expected_uid: Optional[int]) -> bool:
    try:
        elevate.write_result(result_path, result, dir_uid=expected_uid)
        return True
    except Exception:  # noqa: BLE001
        return False


def run(request_path: Path, result_path: Path, config_path: Optional[str] = None,
        *, expected_uid: Optional[int] = None,
        deadline: float = DEFAULT_DEADLINE) -> int:
    start = _monotonic()

    def cancel() -> bool:
        return _monotonic() - start >= deadline

    request_path = Path(request_path)
    result_path = Path(result_path)
    # Root only ever writes next to the request: never to a caller-chosen path.
    if (result_path.name != elevate.RESULT_NAME
            or not _same_dir(result_path.parent, request_path.parent)):
        return EXIT_REFUSED
    if _is_posix() and expected_uid is None:
        return EXIT_REFUSED

    nonce = ""
    try:
        try:
            selection = elevate.read_request(request_path, expected_uid=expected_uid)
        except ValueError as exc:
            raise Refused(str(exc)) from None
        nonce = selection.nonce
        name = _check_identity(selection.invoking_user, expected_uid)
        user = _bind_user(name)
        config = _load_config(config_path, Path(user.home), expected_uid)
    except Refused as exc:
        _safe_write(result_path, elevate.HelperResult(
            freed=0, removed=0, errors=[f"request refused: {exc}"], unmatched=0,
            nonce=nonce), expected_uid)
        return EXIT_REFUSED

    try:
        return _execute(selection, config, result_path, expected_uid, cancel)
    except Exception as exc:  # noqa: BLE001
        _safe_write(result_path, elevate.HelperResult(
            freed=0, removed=0,
            errors=[f"internal error in the elevated helper ({type(exc).__name__})"],
            unmatched=0, nonce=nonce), expected_uid)
        return EXIT_INTERNAL


def _execute(selection: elevate.Selection, config, result_path: Path,
             expected_uid: Optional[int], cancel) -> int:
    wanted = set(selection.keys)
    nonce = selection.nonce

    def finish(freed=0, removed=0, errors=(), unmatched=0, refused=0, hit=False) -> int:
        result = elevate.HelperResult(
            freed=freed, removed=removed, errors=list(errors), unmatched=unmatched,
            nonce=nonce, deadline_hit=hit, refused=refused)
        if not _safe_write(result_path, result, expected_uid):
            return EXIT_INTERNAL
        return EXIT_DEADLINE if hit else EXIT_OK

    if not selection.only or not wanted:
        # Fail closed: an empty cleaner list never means "every cleaner".
        return finish(unmatched=len(wanted))

    try:
        scan = service.scan(config, only=selection.only, cancel=cancel)
    except service.Cancelled:
        return finish(unmatched=0, hit=True,
                      errors=["deadline reached while scanning; nothing was cleaned"])

    matched_keys = set()
    eligible = []
    refused = 0
    for item in scan.all_items():
        key = item_key(item)
        if key not in wanted or key in matched_keys:
            continue
        matched_keys.add(key)
        if item.report_only or not item.requires_root:
            refused += 1
            continue
        eligible.append(item)
    unmatched = len(wanted - matched_keys)

    if cancel():
        return finish(unmatched=unmatched, refused=refused, hit=True,
                      errors=["deadline reached before cleaning; nothing was cleaned"])

    summary = service.clean(eligible, config, dry_run=False,
                            use_quarantine=selection.use_quarantine, cancel=cancel)
    outcomes = summary.result.outcomes
    hit = len(outcomes) < len(eligible)
    errors: List[str] = [f"{o.item.description}: {o.error}" for o in summary.errors]
    if hit:
        errors.append("deadline reached; the remaining items were not cleaned")
    return finish(freed=summary.freed, removed=summary.removed, errors=errors,
                  unmatched=unmatched, refused=refused, hit=hit)


def _resolve_uid(arg_uid: Optional[int], environ) -> Optional[int]:
    """Under pkexec the --uid must be the uid pkexec saw launch us."""
    pk = environ.get("PKEXEC_UID")
    if pk is not None:
        try:
            pk_uid = int(pk)
        except ValueError:
            raise Refused("PKEXEC_UID is not a number") from None
        if arg_uid is None or arg_uid != pk_uid:
            raise Refused("--uid does not match the user who requested elevation")
    return arg_uid


def _positive_deadline(text: str) -> float:
    value = float(text)
    if not math.isfinite(value) or value <= 0:
        raise ValueError("deadline must be positive")
    return value


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cleanix.elevated", add_help=True,
                                description="cleanix elevated helper (internal)")
    p.add_argument("--request", required=True)
    p.add_argument("--result", required=True)
    p.add_argument("--config", default=None)
    p.add_argument("--uid", type=int, default=None)
    p.add_argument("--deadline", type=_positive_deadline, default=DEFAULT_DEADLINE)
    return p


def _main(argv: Optional[Sequence[str]]) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return EXIT_OK if exc.code in (0, None) else EXIT_REFUSED
    try:
        uid = _resolve_uid(args.uid, os.environ)
    except Refused:
        return EXIT_REFUSED
    return run(Path(args.request), Path(args.result), args.config,
               expected_uid=uid, deadline=args.deadline)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        rc = _main(argv)
    except BaseException:  # noqa: BLE001 - incl. SystemExit/KeyboardInterrupt
        return EXIT_INTERNAL
    if not isinstance(rc, int) or isinstance(rc, bool) or rc not in _ALLOWED_EXITS:
        return EXIT_INTERNAL
    return rc


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
