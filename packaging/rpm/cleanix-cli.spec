# RPM spec for cleanix-cli (Fedora/RHEL — build with pyproject macros).
# Build:  rpmbuild -ba packaging/rpm/cleanix-cli.spec
# Or submit to Fedora COPR for automated builds.
Name:           cleanix-cli
Version:        1.2.0
Release:        1%{?dist}
Summary:        Safe, thorough scheduled system cleaner for Linux, macOS and BSD

License:        MIT
URL:            https://github.com/CloudOpsWorld/cleanix-cli
Source0:        %{pypi_source cleanix_cli}

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros

%global _description %{expand:
cleanix analyzes and reclaims disk space across Linux, macOS and the BSDs. It
scans read-only, previews every removal, funnels all deletions through a
protected-path safety guard, and only deletes after confirmation.}

%description %_description

%prep
%autosetup -n cleanix_cli-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files cleanix

# Man page (generated from argparse; present in the sdist).
if [ -f cleanix.1 ]; then
  install -Dm644 cleanix.1 %{buildroot}%{_mandir}/man1/cleanix.1
fi

# Shell completions.
install -Dm644 /dev/stdin %{buildroot}%{bash_completions_dir}/cleanix <<< "$(%{buildroot}%{_bindir}/cleanix completion bash)" || true

%check
%pyproject_check_import

%files -f %{pyproject_files}
%doc README.md
%license LICENSE
%{_bindir}/cleanix
%{_mandir}/man1/cleanix.1*

%changelog
* Wed Jul 16 2026 CloudOpsWorld <dev@cloudopsworld.com> - 1.2.0-1
- Packaging for cleanix-cli 1.2.0
