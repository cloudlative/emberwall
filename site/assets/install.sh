#!/bin/sh
# Emberwall installer: downloads the single-file binary for this machine from GitHub Releases,
# verifies it against the release's SHA256SUMS, and installs it as "emberwall".
#
#   curl -fsSL https://emberwall.cloudlative.com/install.sh | sh
#
# Options (environment variables):
#   EMBERWALL_VERSION      a release tag such as v1.0.0 (default: the latest release)
#   EMBERWALL_INSTALL_DIR  where to put the binary (default: /usr/local/bin if writable, else ~/.local/bin)
#   EMBERWALL_RELEASE_URL  base URL that holds the release files (for mirrors and testing)
#   EMBERWALL_NO_COMPLETIONS=1  do not install tab completion for bash and fish
set -eu

REPO="cloudlative/emberwall"

say() { printf '%s\n' "$*"; }
fail() { printf 'emberwall install: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) fail "unsupported system $(uname -s). On Windows, download emberwall-windows-x64.exe from https://github.com/$REPO/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "unsupported processor $(uname -m)" ;;
esac
asset="emberwall-$os-$arch"

if [ -n "${EMBERWALL_RELEASE_URL:-}" ]; then
  base="${EMBERWALL_RELEASE_URL%/}"
elif [ -n "${EMBERWALL_VERSION:-}" ]; then
  base="https://github.com/$REPO/releases/download/$EMBERWALL_VERSION"
else
  base="https://github.com/$REPO/releases/latest/download"
fi

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  fail "needs curl or wget"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  fail "needs sha256sum or shasum to verify the download"
fi

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t emberwall)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $asset ..."
fetch "$base/$asset" "$tmp/$asset" || fail "could not download $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download $base/SHA256SUMS"

expected="$(awk -v f="$asset" '{ n = $2; sub(/^\*/, "", n); if (n == f) print $1 }' "$tmp/SHA256SUMS")"
[ -n "$expected" ] || fail "SHA256SUMS has no entry for $asset"
actual="$(sha "$tmp/$asset")"
[ "$expected" = "$actual" ] || fail "checksum mismatch for $asset (expected $expected, got $actual)"
say "Checksum verified."

if [ -n "${EMBERWALL_INSTALL_DIR:-}" ]; then
  dir="$EMBERWALL_INSTALL_DIR"
elif [ -w /usr/local/bin ]; then
  dir=/usr/local/bin
else
  dir="$HOME/.local/bin"
fi
mkdir -p "$dir" || fail "cannot create $dir"
chmod +x "$tmp/$asset"
mv "$tmp/$asset" "$dir/emberwall" || fail "cannot write to $dir (set EMBERWALL_INSTALL_DIR, or run with sudo)"

say "Installed $("$dir/emberwall" --version 2>/dev/null || echo emberwall) to $dir/emberwall"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "Note: $dir is not on your PATH. Add it, for example: export PATH=\"$dir:\$PATH\"" ;;
esac

# Tab completion. bash (with bash-completion) and fish load these files on their own; zsh needs
# one line in ~/.zshrc. Skip with EMBERWALL_NO_COMPLETIONS=1.
if [ -z "${EMBERWALL_NO_COMPLETIONS:-}" ] && [ -n "${HOME:-}" ]; then
  done_for=""
  bash_dir="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions"
  if command -v bash >/dev/null 2>&1 && mkdir -p "$bash_dir" 2>/dev/null &&
    "$dir/emberwall" completion bash > "$bash_dir/emberwall" 2>/dev/null; then done_for="bash"; fi
  if command -v fish >/dev/null 2>&1 && mkdir -p "$HOME/.config/fish/completions" 2>/dev/null &&
    "$dir/emberwall" completion fish > "$HOME/.config/fish/completions/emberwall.fish" 2>/dev/null; then done_for="${done_for:+$done_for, }fish"; fi
  [ -n "$done_for" ] && say "Tab completion installed for $done_for (open a new shell)."
  command -v zsh >/dev/null 2>&1 && say "For zsh tab completion, add to ~/.zshrc after compinit:  source <(emberwall completion zsh)"
fi
say "Next: emberwall --help   ·   docs: https://emberwall.cloudlative.com/docs/"
