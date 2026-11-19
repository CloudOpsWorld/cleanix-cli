# Registry cleanup: what is still unverified on real Windows

Status: sub-project B (Windows registry cleanup) is implemented on
`feat/registry`. Every unit test runs against an in-memory registry. Nothing in
the test suite, and nothing written for this task, has run against a real
Windows registry. Until the checklist below passes, the **Undo promise for
registry entries stays off**: `UNDO_SHIPPED = False` in
`cleanix/core/regpromises.py`.

## What the user sees while the promise is off

- CLI (`cleanix clean --registry --execute`) and GUI (Power mode confirm dialog
  and result): "A backup of each removed registry entry is written to the
  quarantine folder, but restoring registry entries is not supported in this
  version yet; to restore one manually, inspect the .reg file and import it
  with reg import ... /reg:64."
- `quarantine.restore` (CLI `cleanix restore`, GUI Quarantine tab Restore and
  Simple-mode Undo) does **not** run the registry write path while the switch is
  off: registry entries are reported as "not restored: registry restore is not
  enabled in this version (backup files are in <dir>)", file entries restore as
  usual, and the run is kept. Error messages after a partial delete or a failed
  record save say where the backup files are, never how to restore.
- The backups are still written before every registry delete (a delete is
  refused without one) and kept in a quarantine run, so nothing is lost. The
  manual `reg import` route exists; the in-app restore is covered by unit tests
  only.
- The release is **not releasable** with registry cleaners enabled in a
  packaged build until the checklist has passed (plan, Risks:
  "Undocumented `winreg` behaviour").

## The verification script

`scripts/verify_registry_cleanup.py` is the only supported way to check the
facts. It writes **only** the disposable key `HKCU\SOFTWARE\CleanixTest`.

```text
python scripts/verify_registry_cleanup.py --dry-run          # prints the plan; no registry access
python scripts/verify_registry_cleanup.py --i-understand-this-writes-to-hkcu-software-cleanixtest
```

Safety properties (also unit-tested): refuses unless `sys.platform == "win32"`
and the long flag is present; aborts with exit 2 if `HKCU\SOFTWARE\CleanixTest`
already exists; every registry call goes through a guard that raises for any
key outside that key; never opens `HKLM`; never launches an elevation prompt;
never runs `reg import` on a backup Cleanix wrote (those name the logical keys,
which would be real ones); removes link keys first, then the tree, in a
`finally`; checks that `HKCU\SOFTWARE\Cleanix` (exact key) is unchanged. It
creates and removes `C:\CleanixVerify-<uuid>\`.

Run it first as a normal user, then once from an Administrator terminal (the
elevated run does not require `HKCU`-logical entries to be found, by design:
see ruling R15). Exit code 0 means every step printed `PASS`.

What it checks:

1. One dead and one live entry per detector (both hives where applicable, plus
   the 32-bit `WOW6432Node` Uninstall view) and controls (UNC path, undefined
   `%VAR%`, a target under the Windows directory) are created under the test
   key. The five detectors, run through a re-rooting backend, find **exactly**
   the dead ones.
2. A dry-run clean removes nothing. A real clean removes the dead entries and
   keeps every live entry and control.
3. Each removed entry has a `.reg` (UTF-16 with BOM and the Version 5.00
   header) and a `.json` backup.
4. `quarantine.restore`: `HKCU`-logical entries come back with equal
   fingerprints; `HKLM`-logical entries are refused with the Administrator
   terminal / `reg import` text (or the confirmation text when elevated), and
   are then restored with `regbackup.restore_entry(..., is_admin=True)`
   (safe: they are physically under `HKCU\...\CleanixTest`), fingerprints equal.
5. Probes (real `winreg` only, under `...\CleanixTest\_probe`):
   - `REG_MULTI_SZ` with empty strings: raw bytes (ctypes) versus the backend
     read. A mismatch means `winreg` reads it lossily and entries holding such
     values could be restored with data loss.
   - `reg export` of a key versus `regbackup.to_reg_text` (line by line, wrapped
     hex lines joined, value order ignored).
   - `reg import` of a Cleanix-written `.reg` into a probe key (the text is
     checked first: every `[section]` must lie inside the probe key), then the
     fingerprint of the result is compared.
   - A registry link key made with `REG_OPTION_CREATE_LINK` (ctypes):
     `is_link` true for the link and false for its target; a normal handle
     follows the link; what `DeleteKeyEx` removes when the final path component
     is a link is **measured and printed** (`R17 measurement:` line). The link
     is deleted itself with an `REG_OPTION_OPEN_LINK` handle and `NtDeleteKey`.
   - `reg query /reg:64` sees the test key, and the Python bitness is reported.
     This is informational only: `HKCU\Software` is not WOW64-redirected, so it
     does **not** prove that `KEY_WOW64_64KEY` is honoured. That flag's effect on
     `HKLM\SOFTWARE` (and `WOW6432Node`) cannot be tested inside
     `HKCU\Software\CleanixTest`; it is covered only by the fake-`winreg` unit
     tests that pin the flag. A 32-bit Python run is still useful for ctypes and
     handle-size issues (the link and `REG_MULTI_SZ` probes), not for view
     semantics.
6. Cleanup: link keys, then the test tree; the test key is gone;
   `HKCU\SOFTWARE\Cleanix` is unchanged (if the GUI has ever run, QSettings
   legitimately created it: the script never touches it).

The probes and the ctypes link code have **not been executed** by the author
(they need a real registry). Expect that a first real run may expose a bug in
the script itself rather than in the product; read any `FAIL` detail before
drawing a conclusion about Cleanix. The re-rooted main flow (steps 1 to 4) was
exercised on Windows against an in-memory registry only.

## Checklist (all boxes required before flipping the switch)

Use a normal (non-admin) account first, then an Administrator terminal.

- [ ] `python scripts/verify_registry_cleanup.py <flag>` prints only `PASS`
      lines, non-admin.
- [ ] The same from an Administrator terminal.
- [ ] `reg query HKCU\Software\CleanixTest` says the key cannot be found;
      `reg query HKCU\Software\Cleanix` is unchanged from before the run.
- [ ] Probe: `REG_MULTI_SZ` with empty strings is read back exactly. If it is
      lossy: make the backend or detectors refuse such values, add a test, and
      re-run before flipping.
- [ ] Probe: `reg export` and `to_reg_text` agree; `reg import` of the `.reg`
      recreates the same values (byte-wise comparison with `fc /b` of two
      `reg export` files of the original and the re-imported probe key is a
      useful extra check; wrapping of long hex lines is a known harmless
      difference).
- [ ] Probe: link behaviour recorded. `is_link` is correct; the `R17
      measurement:` line is copied into the ledger. If `DeleteKeyEx` follows a
      final-component link and deletes the target, the README text for R17
      already says so; nothing else changes. If it deletes the link only, the
      README wording can be softened. Either way, record the outcome here.
- [ ] 32-bit Python (if available): same script, all `PASS` (checks the ctypes
      and handle-size paths; it does not verify WOW64 view semantics, see
      above).
- [ ] `cleanix scan` lists no registry cleaners. `cleanix scan --registry` lists
      findings and writes nothing: `reg export` the five containers
      (`...\Uninstall`, `...\App Paths`, `HKCU\Software\Classes`,
      `...\Run`, `...\SharedDLLs`; both hives) before and after and compare
      with `fc /b`.
- [ ] `cleanix gui`, Power mode: tick a registry cleaner in "Choose what to
      scan" and scan. Groups show the Review badge, the Evidence text, no Open
      location, and the confirm wording. Simple mode shows "Registry leftovers
      are checked only in Power mode." Do **not** clean real entries.
- [ ] The `.reg` format is readable by Windows tools: the `reg export`
      comparison probe above covers it; the script itself checks the BOM and
      header of every backup. (The script deletes its temporary folder, so a
      manual look in Notepad is optional.)
- [ ] Elevated helper path: unit tests only. Do not clean real `HKLM` entries
      on the verification machine.

## Known issues that must be resolved before the flip (F1 to F5, I2, I3)

All of F1 to F5, and the review items I2 (restore hints follow the switch and
the hive) and I3 (restore gated on the switch), must be resolved and re-verified
before `UNDO_SHIPPED` is flipped. I2 and I3 are implemented (and unit-tested in
both switch states); F1 to F5 are open and are verification items, not code
done.

- **F1 Restore after an elevated clean is likely refused.** A backup file
  created by an elevated process is probably owned by `BUILTIN\Administrators`,
  and `restore_entry(require_owner=True)` then answers "the backup file is not
  owned by the current user" from a normal terminal or the GUI Quarantine tab.
  Check: an elevated clean followed by a normal-terminal restore, and an HKCU
  restore from the GUI tab. Fix ideas: accept the Administrators owner for HKCU
  entries, or tell the user to restore from an elevated terminal.
- **F2 GUI HKLM cleaning breaks silently if the quarantine folder was first
  created elevated.** The folder is then owned by Administrators and
  `_prepare_registry` refuses it (documented fail-closed). Check what the user
  sees and decide whether the message needs to be explicit.
- **F3 The GUI never shows `CleanSummary.undo_record_error` or `quarantine_run`
  after a Power clean.** Decide where the run id and a save error are shown.
- **F4 The owed real-Windows probes:** `REG_MULTI_SZ` lossy reads, the R17
  `DeleteKeyEx` measurement for a final-component link, `OPEN_LINK` handling
  (all in the script above).
- **F5 The Quarantine panel shows `count` instead of `removed_count`, and an
  elevated GUI's HKLM restore wording promises a confirmation the GUI does not
  have.** Fix both wordings, then re-check.

## The one-line flip

Only after every box above is ticked and any finding is fixed and re-verified:

```diff
--- a/cleanix/core/regpromises.py
+++ b/cleanix/core/regpromises.py
-UNDO_SHIPPED = False
+UNDO_SHIPPED = True
```

Then run the whole suite (the tests that pin both wordings monkeypatch the
switch, so both states stay covered), update the README "Undo status (gated)"
paragraph and "What Undo covers" to say the promise is on, and note the date
and the machine's Windows build in the ledger.

## Open questions (unchanged, for the user)

1. One-click Undo for machine-wide (`HKLM`) entries needs a new elevated
   "restore" helper action plus an administrator-only integrity record of each
   backup. Not built; `HKLM` restore stays an Administrator-terminal job.
2. Simple mode never scans the registry (ruling R13). The alternative is to add
   the detectors to Deep scan, read-only.
