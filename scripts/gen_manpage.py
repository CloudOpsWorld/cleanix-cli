#!/usr/bin/env python3
"""Generate ``cleanix.1`` (roff) from the argparse definition.

Keeping the man page generated from the same parser that drives the CLI means
the two never drift. Run from the repo root:

    python scripts/gen_manpage.py > cleanix.1
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cleanix import __version__  # noqa: E402
from cleanix.cli import build_parser  # noqa: E402


def _esc(text: str) -> str:
    return text.replace("\\", "\\\\").replace("-", "\\-")


def _options(parser: argparse.ArgumentParser) -> list:
    lines = []
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            continue
        if not action.option_strings and action.dest == "help":
            continue
        names = ", ".join(action.option_strings) or action.dest.upper()
        metavar = ""
        if action.option_strings and action.nargs != 0 and action.metavar:
            metavar = " " + action.metavar
        help_text = _esc(action.help or "")
        lines.append(f".TP\n.B {_esc(names)}{_esc(metavar)}\n{help_text}")
    return lines


def main() -> int:
    parser = build_parser()
    date = time.strftime("%Y-%m-%d", time.localtime())
    out = []
    out.append(
        f'.TH CLEANIX 1 "{date}" "cleanix {__version__}" "User Commands"'
    )
    out.append(".SH NAME")
    out.append("cleanix \\- safe, thorough cross-platform *nix system cleaner")
    out.append(".SH SYNOPSIS")
    out.append(".B cleanix")
    out.append("[\\fICOMMAND\\fR] [\\fIOPTIONS\\fR]")
    out.append(".SH DESCRIPTION")
    out.append(
        "cleanix analyzes and reclaims disk space across Linux, macOS and the "
        "BSDs. It scans read\\-only, previews every removal, funnels all "
        "deletions through a protected\\-path safety guard, and only deletes "
        "after confirmation. Report\\-only findings are surfaced but never "
        "auto\\-deleted."
    )
    out.append(".SH COMMANDS")

    subparsers_action = next(
        (a for a in parser._actions
         if isinstance(a, argparse._SubParsersAction)),
        None,
    )
    if subparsers_action:
        for name, sub in subparsers_action.choices.items():
            helptext = ""
            for choice_action in subparsers_action._choices_actions:
                if choice_action.dest == name:
                    helptext = choice_action.help or ""
            out.append(f".SS {_esc(name)}")
            if helptext:
                out.append(_esc(helptext))
            opts = _options(sub)
            if opts:
                out.extend(opts)

    out.append(".SH FILES")
    out.append(".TP")
    out.append(".I ~/.config/cleanix/config.yaml")
    out.append("User configuration (see \\fBcleanix config\\fR).")
    out.append(".TP")
    out.append(".I ~/.local/state/cleanix/")
    out.append("History, quarantine, scheduled\\-scan reports and audit logs.")
    out.append(".SH SAFETY")
    out.append(
        "cleanix never deletes protected system paths or a user's home, "
        "credential, or media directories, never follows a symlink to delete "
        "its target, and runs external commands without a shell. Use "
        "\\fB\\-\\-quarantine\\fR for reversible removal and \\fB\\-\\-simulate\\fR "
        "to preview the exact target list."
    )
    out.append(".SH SEE ALSO")
    out.append("Project home: https://github.com/CloudOpsWorld/cleanix\\-cli")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
