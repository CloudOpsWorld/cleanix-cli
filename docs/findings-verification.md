# Acting on findings: what is still unverified on real systems

Status: the "actionable findings" feature set (`clean --act-on`, `review`, the
GUI Review and Registry tabs, and the system-wide actions of the administrator
helper) is implemented on `feat/actionable-findings` and ships as **BETA**
(version 1.5.0b1, a PyPI pre-release). Every test ran against fake data,
temporary folders, injected `lstat`/`os` seams and fake command runners. Nothing
described below has run as real root on a real Linux or macOS machine, and no
GUI flow has run on a real Linux or macOS desktop. **Do not ship a non-beta
release until every box below is ticked** (or the item is consciously removed
from the feature set); RELEASING.md says the same.

Beta means: the features are available, the README documents them as beta, and
pip needs `--pre`. It does not loosen any check. When in doubt every check
fails closed (an unknown answer means "skip").

**Beta gate.** Acting on system-wide findings is additionally switched off in
the client unless the environment variable `CLEANIX_BETA_SYSTEM_ACTIONS` is
exactly `1` (`system_findings.gate_problem`, applied in `system_findings.plan`,
which the CLI `--act-on`, `review` and the GUI Review tab all use). Without
it every system-wide item is "not offered" with the reason. Even with it, a
process running as root (euid 0) and the standalone (frozen PyInstaller)
binary are never offered system-wide items. The helper itself is not gated
(it sanitises its own environment). Set the variable only on the disposable
verification machines below; remove the gate only when this list is done.

## What the user sees today (compare observations against this)

- A scan never removes anything; acting is always an explicit, named action.
- User-space items: moved to the user quarantine (Undo), or deleted with
  `--permanent`. Launch jobs and systemd units are always permanent (a copy of
  the file is kept for manual recovery).
- System-wide items: only with `CLEANIX_BETA_SYSTEM_ACTIONS=1`, never from a
  root process or the standalone binary, only through the administrator
  helper, and always after the typed phrase `DELETE SYSTEM FILES`. By default moved
  into a root-only quarantine (`/var/lib/cleanix/quarantine`; macOS
  `/Library/Application Support/Cleanix/quarantine`) that has **no restore and
  no purge**, so no space is freed; or deleted with `--permanent`. No Undo is
  ever promised for them.

## Known residual risks (accepted for the beta)

- **Check-then-act windows.** Every item is re-verified right before its own
  move or delete, but a short window remains between the last `lstat` and the
  operation. The check is path-based, not descriptor-anchored. For user-space
  items, someone who can exploit it already runs as you; for system items only
  root, or an account that owns a trusted parent folder (which the parent-chain
  rule excludes), could use it.
- **ACLs and extended attributes.** Linux POSIX ACL xattrs
  (`system.posix_acl_*`, `system.nfs4_acl`, `system.richacl`) and macOS extended
  ACLs with write-like entries make the helper refuse a path or one of its
  parents. Other xattrs and SELinux/AppArmor/SIP policy are not evaluated.
- **Filesystems with `st_ino == 0` or unstable inode numbers.** The identity
  fingerprint (size, mtime, inode, device) then over-matches. That fails closed
  for the kept-copy and quarantine-alias checks, but a replaced file with a
  reused inode on such a filesystem would not be noticed as "a different file".
- **No restore or purge for the root quarantine.** Items the helper moved stay
  there until someone deletes them as root; the space is not freed. The copies
  kept for jobs, units and receipts are in the same place.
- **Items refused fail-closed.** Unknown ownership, unreadable folders, other
  filesystems, mount points, immutable files, OneDrive-style placeholders and
  reparse points (Windows), folders with more than 5 entries on Linux
  (`orphan_files`), apps Spotlight did not list: they are reported but not acted
  on. This is intended, but it can look like "Cleanix finds things it will not
  remove".
- **A deadline stop.** The helper has a time limit. A stop mid-batch leaves the
  later items untouched; units removed before the stop may need a manual
  `systemctl daemon-reload`.
- **Root and multi-user scope (fixed in the final review; keep checking).**
  Under `sudo`, `clean --act-on` and `review` used to scan every user's home
  and merge duplicate groups across accounts (one user's copies could be
  removed in favour of another user's copy). Now acting on findings always
  scans only the invoking user's home (SUDO_USER under sudo), `--all-users`,
  `--current-user` and `--min-uid` are refused with `--act-on`, a duplicate
  group whose copies have different owners (lstat uid) is skipped whole, and a
  root process is never offered system-wide items (so the old limitations
  "sudo still starts pkexec" and "under sudo the helper reads root's config"
  no longer apply to findings).
- **Standalone binary.** The PyInstaller binary cannot start the helper (it
  runs `sys.executable -I -m cleanix.elevated`, and the binary refuses `-I`),
  so system-wide items are never offered there and `run_findings_request`
  refuses before any prompt. Install with pip/pipx to act on them.
- **32-bit Linux.** The immutable/append-only check reads the inode flags with
  `FS_IOC_GETFLAGS`, whose ioctl number depends on `sizeof(long)` of the
  Python process (0x80086601 on 64-bit, 0x80046601 on 32-bit); Cleanix picks
  it with `struct.calcsize("l")`. It has never run on a real 32-bit system; a
  read that fails is treated as "no flags".

## How to use this checklist

Use a disposable machine or VM (snapshot first). Never run these steps on a
machine whose data matters. For each box: do the step, record the **exact
observation** (command output, text on screen), compare with the expectation,
and if it differs do what the "If it differs" line says before ticking the box.
Run the CLI as a normal user unless a step says root, with
`export CLEANIX_BETA_SYSTEM_ACTIONS=1` for every step that acts on
system-wide items (and for the GUI: start it from that shell).

## Linux (the helper runs as real root)

Setup: a Debian/Ubuntu VM and separately a Fedora or openSUSE VM and an Arch VM
(`pkexec` needs polkit, so use VMs, not bare containers, for the elevation
steps). Create test leftovers: a folder `/opt/cleanix-test/` with a few unowned
files, the same under `/usr/local` and `/var/lib/cleanix-test-data`, and a
`.service` file in `/etc/systemd/system` whose `ExecStart` binary does not exist.

- [ ] **dpkg real output.** `cleanix scan --only orphan_files` and
      `cleanix clean --act-on orphan_files` (preview) on Debian/Ubuntu. Record
      the output of `dpkg-query -S <path>` for owned and unowned paths and for
      many paths in one command. Expected: unowned test paths are reported with
      an action; owned ones never; the batched output is parsed the same as
      single queries. If it differs: fix the parser (`query_unowned` in
      `cleanix/cleaners/orphan_common.py`) and add the real output as a test.
- [ ] **rpm real output, including packages built with fpm.** On Fedora or
      openSUSE: `rpm -qf <path>` for an owned file, an unowned file, a folder
      (rpm usually owns files, not folders), a path under `/opt/vendor` of a
      package that installed only deeper files, and a package built with `fpm`
      (fpm RPMs often own odd paths and carry unusual metadata). Expected: a
      folder whose files an rpm owns gets **no** action; a completely unowned
      folder does; an fpm-owned folder is never offered because of one unowned
      file in it. If it differs: tighten `orphan_files._actionable` /
      `_descendants` and `still_unowned`, add a test.
- [ ] **pacman real output.** On Arch: `pacman -Qo <path>` for owned and
      unowned paths and for many paths in one command. Same expectation as dpkg.
- [ ] **usr-merged Debian/Ubuntu.** On a distribution where `/bin`, `/sbin` and
      `/lib` are links into `/usr`: unit enable links pointing to
      `/lib/systemd/system/...` and `.desktop` entries with `Exec=/bin/...` are
      judged by the helper. Expected: the narrow alias rule (a root-owned link
      whose target is exactly `usr/<alias>`) lets it see them; any other link
      is "unknown" and not offered. Record `ls -ld /bin /lib` and the findings.
      If it differs: adjust `elevated._evidence_problem`.
- [ ] **`/var/lib/cleanix/quarantine` permissions.** After one real
      `clean --act-on orphan_files --execute` of a test folder, record
      `stat -c '%U:%G %a %n' /var/lib/cleanix /var/lib/cleanix/quarantine
      /var/lib/cleanix/quarantine/*` and the manifest file. Expected: owned by
      root, the helper's folders and the run `0700`, the manifest not readable
      by others, nothing written under your home. If it differs: fix
      `elevated._prepare_root_quarantine`.
- [ ] **mountinfo and bind mounts.** Put a test folder on a bind mount
      (`mount --bind`) and another on a tmpfs inside `/opt`; test items that
      contain a mount point and items that are one. Record
      `/proc/self/mountinfo`. Expected: an item that is, or contains, a mount
      point is refused; an item on another filesystem than the quarantine
      reports "another filesystem" with the `--permanent` hint and nothing is
      copied across filesystems. If it differs: fix `root_delete.parse_mountinfo`
      (escaped spaces such as `\040`, a truncated table, the entry for `/`).
- [ ] **ACL xattrs.** `setfacl -m u:nobody:rwx` on a test folder and on its
      parent. Record `getfattr -m - -d` (shows `system.posix_acl_access`).
      Expected: the item, or any parent, is refused with an ACL reason. Also a
      folder on a filesystem without xattr support (a FAT/exFAT mount): expected
      not refused for ACL reasons. If it differs: adjust the ACL checks in
      `cleanix/elevated.py`.
- [ ] **Immutable flag.** `chattr +i` on a test unit file. Expected: refused;
      `lsattr` before and after shows it unchanged.
- [ ] **systemd: dangling alias shadowing a vendor unit.** Make a dangling
      `/etc/systemd/system/foo.service` link while a vendor `foo.service` exists
      under `/usr/lib/systemd/system`. Expected: no action offered. Record
      `systemctl cat foo` and `systemctl status foo`. If it differs: adjust the
      "name exists lower on the load path" rule in
      `cleanix/cleaners/stale_services.py`.
- [ ] **systemd: `disable --now` on a unit whose binary is missing.** Create a
      real unit with a missing `ExecStart`, enable it, run
      `clean --act-on stale_services --execute`. Record the exit code and output
      of `systemctl disable --now`, the copy in the root quarantine and that
      the file is gone. Expected: any warning appears in the item's note; the
      file is still copied, then removed. Then a template unit (`x@.service`):
      expected `disable` without `--now`. If it differs: fix the command shapes
      (`remedy_exec.MUTATING_COMMANDS` and the system set).
- [ ] **systemd: `daemon-reload` from the helper's sanitised environment.**
      Record whether `systemctl daemon-reload` succeeds when the helper runs
      under `pkexec` with its reduced environment (no D-Bus session variables).
      Expected: it works against the system manager without a session bus. If
      it fails: the note must tell the user to run it by hand; fix the
      environment the helper passes only if the system manager needs more.
- [ ] **Dangling wants link of an enabled unit whose name still resolves**
      gets no action; a dangling link to a unit that is really gone does.
- [ ] **End to end.** `cleanix clean --act-on orphan_files --execute` in a
      terminal on a desktop VM: the polkit prompt appears, the phrase
      `DELETE SYSTEM FILES` is required, the result lists each item. Record the
      prompt text and the printed per-item lines. Also
      `sudo cleanix clean --act-on orphan_files --execute --yes`: expected every
      system item "not offered: run cleanix as your normal user ...", nothing
      launched, and only the invoking user's home scanned. On a host without
      `pkexec` as a normal user: "not available; nothing was removed", exit 2.
- [ ] **Beta gate off.** The same command without
      `CLEANIX_BETA_SYSTEM_ACTIONS` (and with it set to `true` or `0`): every
      system item "not offered: system-wide actions are a beta feature ...",
      no prompt, nothing launched.
- [ ] **32-bit flags read.** On a 32-bit Linux (or a 32-bit Python on a 64-bit
      kernel), `chattr +i` a test unit file: expected refused as immutable.
      Record `python3 -c 'import struct; print(struct.calcsize("l"))'`.
- [ ] **Multi-user duplicates.** As root with two test accounts holding the
      same file twice each, `sudo cleanix clean --act-on duplicates --keep
      oldest`: expected only the invoking user's copies are listed; with
      `--all-users` the command is refused (exit 2).

## macOS (the helper runs as real root)

Setup: a macOS VM or spare Mac. Create test data: leftover folders with
reverse-DNS names in `/Library/Application Support`, a LaunchDaemons plist
whose program is missing, a LaunchAgents plist likewise, and a receipt for a
package whose installed files are gone.

- [ ] **launchctl exit codes (user scope).** `launchctl bootout
      gui/<uid>/<label>` for a loaded job, for a job that is not loaded and for
      a label that does not exist. Record the exit codes. Expected: the "not
      loaded" cases return 3 or 113 (shown as a soft "was not loaded"); anything
      else becomes a warning in the note and the file is still removed. If it
      differs: update the soft-code set and the argv form in `remedy_exec`.
- [ ] **A daemon plist removed while the job is loaded.** Load a test daemon
      whose program was deleted and run the action. Record
      `launchctl print system/<label>` before, right after the removal and
      after a restart. Expected: the helper runs **no** `launchctl` command for
      system jobs; the job may stay listed until the next restart but cannot
      run (its program is missing) and is gone after a restart. If it differs
      (launchd relaunches something, or the listing never clears): decide
      whether to bring a bootout back with a stricter label check, or to
      strengthen the note.
- [ ] **LaunchAgents in `/Library/LaunchAgents`.** A copy already running in a
      logged-in session keeps running until logout; the note says so. Record.
- [ ] **`pkgutil --forget` semantics.** For a receipt of a package whose files
      are gone, record the exit code and output; whether both
      `/private/var/db/receipts/<id>.plist` **and** `.bom` are gone afterwards;
      what happens for an id with no receipt; and whether SIP/TCC lets root
      write there from the helper (no Full Disk Access granted). Expected:
      `pkgutil` removes both files; otherwise the item reports "still there"
      and nothing else changes (Cleanix never unlinks receipt files itself). If
      `.bom` stays: every receipt item reports "still there", so fix or drop
      the receipt action. Also id matching: an id with unusual characters is
      refused, and `com.apple.*` in any letter case is never touched.
- [ ] **Spotlight in the helper's environment.** Under the helper's sanitised
      environment `mdfind` lists every app bundle in `/Applications`,
      `/System/Applications` (Safari and the other cryptex-delivered apps),
      each user's `~/Applications`, and Homebrew Caskroom apps. Record the counts
      against a `find` for `*.app`. Expected: the helper accepts Spotlight's
      answer only when it names every bundle its own walk found, so a mismatch
      makes every `orphan_app_data` item "unknown" (none offered). If Spotlight is
      off or the helper's environment hides it: document that `orphan_app_data`
      is unavailable there. If it differs in another way: fix the inventory in
      `cleanix/cleaners/orphan_app_data.py`.
- [ ] **Real `acl_to_text` output.** For `/`, `/Library`,
      `/Library/Application Support`, `/Library/LaunchDaemons`,
      `/private/var/db/receipts`, `/Users` and a user's home, record
      `ls -led <path>` and the text `acl_to_text` returns. Expected: stock ACLs
      are deny-only (for example `group:everyone deny delete`) and pass; any
      allow entry with a write-like right refuses. This exercises the ctypes
      calls (`acl_get_link_np`, `acl_get_entry`, `acl_to_text`) and the parser
      `elevated._macos_acl_entries_problem`, none of which has run on a Mac.
      If it differs: if stock paths are refused, every macOS item and the root
      quarantine are refused, so fix the parser (header, flag and permission
      names) and add the real text as a test.
- [ ] **Real ownership.** `/Library/Application Support` is expected `root:admin
      0755`; `/Library/LaunchDaemons` and `/private/var/db/receipts` `root:wheel
      0755`. Record `stat -f '%Su:%Sg %Lp %N'`. Expected: all accepted by the
      parent-chain rule (group id below 501). If it differs: fix
      `elevated._component_problem`.
- [ ] **Receipts that install into user-writable places** (`/Applications` is
      `root:admin 0775`; Intel Homebrew owns `/usr/local`): expected "unknown",
      not offered. Record how many real receipts on the machine are affected;
      if most third-party receipts are, decide whether that limitation is
      acceptable for a release.
- [ ] **Case-insensitive filesystem collision.** On a default case-insensitive
      APFS volume, check a path that differs only in case from the root
      quarantine (`/Library/Application Support/CLEANIX`). Expected: refused
      (device and inode comparison). If it differs: fix
      `elevated._quarantine_alias_problem`.
- [ ] **Home enumeration (uid below 501).** Record `dscl . list /Users UniqueID`
      and the ownership of `/Users` entries. Expected: only accounts with uid
      501 or higher and a home directly under `/Users` count as human users;
      anything unreadable or odd makes the app inventory "unknown". If it
      differs: fix `human_homes` in `cleanix/cleaners/orphan_app_data.py`.
- [ ] **SIP/TCC and `osascript`.** The password prompt text, the helper starting
      from `osascript ... with administrator privileges`, and moves into
      `/Library/Application Support/Cleanix/quarantine` succeeding.
- [ ] **End to end.** The same typed-phrase run as on Linux through
      `osascript`. Also `sudo cleanix clean --act-on ... --yes`: expected the
      system items "not offered" (root process), nothing launched.

## Windows

- [ ] **User-space findings only.** `cleanix scan`, and
      `clean --act-on big_files,downloads,duplicates --keep oldest` (preview,
      then `--execute` on test files) work; the system-wide scenarios are never
      offered and the GUI Review tab shows no system rows.
- [ ] **Junctions and OneDrive placeholders are skipped fail-closed.** A
      junction, a symlink and a OneDrive "files on demand" placeholder
      (reparse-point attribute `0x400`) named by a finding are skipped with
      "changed since scan (now a link or reparse point)" and left in place.
      Record the wording shown. If a placeholder should be allowed, the user
      text needs refining; do not loosen the check without a review.
- [ ] **Registry tab.** The tab lists the registry detectors, scans only on
      request, and HKLM entries go through UAC. It is the same code path as the
      old Scan-tab removal. The existing checklist
      [registry-cleanup-verification.md](registry-cleanup-verification.md)
      still gates the Undo promise for registry entries: run it as written.
      Do **not** clean real HKLM entries on the verification machine.

## Cross-cutting

- [ ] **`pkexec` / `osascript` elevation end to end** from the CLI and from the
      GUI Review tab, including the helper's real outcomes rendered in the
      results dialog, a declined prompt ("declined; nothing was removed"), no
      polkit agent ("not available") and a deadline hit.
- [ ] **GUI palettes on real desktops.** The Review and Registry tabs, the
      confirmation dialog and the badges in dark and light themes on GNOME, KDE
      and macOS (system palettes, not Fusion with hand-made test palettes).
      Check that disabled rows are greyed, badge text contrasts, the typed-phrase
      field and the disabled Act button are clear, and that nothing overrides
      the palette. Keyboard use: Space (not Enter) triggers Act; try a screen
      reader if one is available.
- [ ] **Python 3.8 on the whole suite.** The GUI suite needs PySide6, which does
      not support 3.8, so it cannot run there; run the non-GUI suite on 3.8 and
      the GUI suite on the oldest Python PySide6 supports. The non-GUI suite
      first ran on Python 3.8 (Windows) at release prep for 1.5.0b1 (2549
      passed, 147 skipped, no 3.8-only failures); repeat it on Linux and macOS
      and whenever the findings code changes.
- [ ] **Linux and macOS CI for the POSIX-only tests.** Confirm the GitHub CI
      matrix (Ubuntu and macOS, Python 3.8 to 3.13) is green. These tests are
      skipped on Windows: the symlink-swap tests, the ownership/uid tests, the
      helper's parent-chain and ACL tests and the POSIX-only helper fixtures.
- [ ] **Standalone binary.** Build the PyInstaller binary and run
      `CLEANIX_BETA_SYSTEM_ACTIONS=1 ./cleanix clean --act-on orphan_files`:
      expected every system item "not offered: the standalone binary cannot
      start the administrator helper ...", no prompt.
- [ ] **The beta text is accurate.** Re-read the README section "Findings and
      what you can do with them" against what you observed above and fix any
      sentence that no longer matches.

## When the list is done

Before a non-beta release: tick every box, record the date and the OS and
package-manager versions used, copy any new real output into unit tests, update
the README and the status at the top of this file, and change the version from
`1.5.0b1` to `1.5.0` in both `pyproject.toml` and `cleanix/__init__.py` (see
RELEASING.md).
