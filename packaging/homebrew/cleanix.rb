# Homebrew formula for cleanix-cli.
#
# Publish by copying this file into a tap repo (e.g. CloudOpsWorld/homebrew-tap
# as Formula/cleanix.rb) so users can `brew install cloudopsworld/tap/cleanix`.
#
# Before publishing a new version:
#   1. Bump `url`/`sha256` to the new PyPI sdist (shasum -a 256 the tarball).
#   2. Run `brew update-python-resources Formula/cleanix.rb` to refresh the
#      `resource` blocks (rich, PyYAML and their transitive deps) — the
#      placeholders below MUST be regenerated; do not ship them as-is.
#   3. `brew audit --strict --new cleanix` and `brew test cleanix`.
class Cleanix < Formula
  include Language::Python::Virtualenv

  desc "Safe, thorough scheduled system cleaner for Linux, macOS and BSD"
  homepage "https://github.com/CloudOpsWorld/cleanix-cli"
  url "https://files.pythonhosted.org/packages/source/c/cleanix-cli/cleanix_cli-1.2.0.tar.gz"
  sha256 "REPLACE_WITH_SDIST_SHA256"
  license "MIT"

  depends_on "python@3.12"

  # `brew update-python-resources` regenerates these with correct checksums.
  resource "rich" do
    url "https://files.pythonhosted.org/packages/source/r/rich/rich-15.0.0.tar.gz"
    sha256 "REPLACE_WITH_RESOURCE_SHA256"
  end

  resource "PyYAML" do
    url "https://files.pythonhosted.org/packages/source/P/PyYAML/pyyaml-6.0.3.tar.gz"
    sha256 "REPLACE_WITH_RESOURCE_SHA256"
  end

  def install
    virtualenv_install_with_resources
    # Ship the generated man page and shell completions.
    man1.install "cleanix.1" if File.exist?("cleanix.1")
    generate_completions_from_executable(bin/"cleanix", "completion", shells: [:bash, :zsh, :fish], shell_parameter_format: :arg)
  end

  test do
    assert_match "cleanix #{version}", shell_output("#{bin}/cleanix --version")
    system bin/"cleanix", "list"
  end
end
