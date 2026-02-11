#!/usr/bin/env bash
# Sekura installer — https://sekura.ai
# Usage: curl -fsSL https://sekura.ai/install.sh | bash
set -euo pipefail

REPO="sekura-ai/sekura"

# ---------------------------------------------------------------------------
# Detect platform
# ---------------------------------------------------------------------------
detect_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux*)  os="unknown-linux-musl" ;;
    Darwin*) os="apple-darwin" ;;
    *)       echo "Error: unsupported OS: $os" >&2; exit 1 ;;
  esac

  case "$arch" in
    x86_64|amd64)  arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *)             echo "Error: unsupported architecture: $arch" >&2; exit 1 ;;
  esac

  echo "${arch}-${os}"
}

# ---------------------------------------------------------------------------
# Fetch latest version tag from GitHub Releases (no jq required)
# ---------------------------------------------------------------------------
latest_version() {
  local url="https://api.github.com/repos/${REPO}/releases/latest"
  # Grab the "tag_name" field with grep+sed — works on both GNU and BSD
  curl -fsSL "$url" | grep '"tag_name"' | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/'
}

# ---------------------------------------------------------------------------
# Verify SHA-256 checksum
# ---------------------------------------------------------------------------
verify_checksum() {
  local file="$1" expected="$2"
  local actual
  if command -v sha256sum &>/dev/null; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum &>/dev/null; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    echo "Warning: no sha256sum or shasum found — skipping checksum verification" >&2
    return 0
  fi
  if [ "$actual" != "$expected" ]; then
    echo "Error: checksum mismatch" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  local target version archive url checksum_url install_dir

  target="$(detect_platform)"
  echo "Detected platform: ${target}"

  echo "Fetching latest release..."
  version="$(latest_version)"
  if [ -z "$version" ]; then
    echo "Error: could not determine latest version" >&2
    exit 1
  fi
  echo "Latest version: ${version}"

  archive="sekura-${version}-${target}.tar.gz"
  url="https://github.com/${REPO}/releases/download/${version}/${archive}"
  checksum_url="${url}.sha256"

  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  echo "Downloading ${archive}..."
  curl -fsSL -o "${tmpdir}/${archive}" "$url"
  curl -fsSL -o "${tmpdir}/${archive}.sha256" "$checksum_url"

  echo "Verifying checksum..."
  local expected
  expected="$(awk '{print $1}' "${tmpdir}/${archive}.sha256")"
  verify_checksum "${tmpdir}/${archive}" "$expected"

  echo "Extracting..."
  tar -xzf "${tmpdir}/${archive}" -C "${tmpdir}"

  # Choose install directory
  install_dir="/usr/local/bin"
  if [ ! -w "$install_dir" ]; then
    install_dir="${HOME}/.local/bin"
    mkdir -p "$install_dir"
  fi

  cp "${tmpdir}/sekura" "${install_dir}/sekura"
  chmod +x "${install_dir}/sekura"
  echo "Installed sekura to ${install_dir}/sekura"

  # Warn if not in PATH
  case ":${PATH}:" in
    *":${install_dir}:"*) ;;
    *)
      echo ""
      echo "Warning: ${install_dir} is not in your PATH."
      echo "Add it with:  export PATH=\"${install_dir}:\$PATH\""
      ;;
  esac

  echo ""
  echo "Run 'sekura --help' to get started."
}

main "$@"
