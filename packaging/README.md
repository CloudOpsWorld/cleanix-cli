# Packaging cleanix-cli

Distribution artifacts and how to publish them. PyPI + standalone binaries are
already automated in `.github/workflows/release.yml` (which also emits
`SHA256SUMS` and keyless **build-provenance attestations** — verify a download
with `gh attestation verify <file> --repo CloudOpsWorld/cleanix-cli`).

## Man page

`cleanix.1` is generated from the argparse definition so it never drifts:

```bash
python scripts/gen_manpage.py > cleanix.1
man -l cleanix.1        # preview
```

Regenerate and commit it whenever the CLI surface changes. All the packages
below install it to `.../man/man1/cleanix.1`.

## Homebrew (`homebrew/cleanix.rb`)

Copy into a tap repo as `Formula/cleanix.rb` (e.g.
`CloudOpsWorld/homebrew-tap`), then `brew install cloudopsworld/tap/cleanix`.

Per release: bump `url`/`sha256` to the new PyPI sdist and run
`brew update-python-resources Formula/cleanix.rb` to refresh the `resource`
checksums (the committed placeholders MUST be regenerated). Validate with
`brew audit --strict --new cleanix` and `brew test cleanix`.

## Arch (`aur/PKGBUILD`)

Publish to the AUR as `cleanix-cli`:

```bash
updpkgsums                                   # fill sha256sums from the sdist
makepkg --printsrcinfo > .SRCINFO
makepkg -si                                  # local test install
```

## Fedora/RHEL (`rpm/cleanix-cli.spec`)

```bash
rpmbuild -ba packaging/rpm/cleanix-cli.spec  # local build
```

For automated builds, submit the spec to [Fedora COPR]. Uses
`pyproject-rpm-macros`, so runtime deps come from the wheel metadata.

[Fedora COPR]: https://copr.fedorainfracloud.org/
