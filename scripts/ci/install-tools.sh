#!/usr/bin/env bash
# Install pinned CLI tools for CI (Linux x86_64) into ~/.local/bin, verifying SHA-256 checksums.
set -euo pipefail

BIN="${HOME}/.local/bin"
mkdir -p "${BIN}"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

fetch() { # name version url sha256 member
  local name="$1" url="$3" sha="$4" member="$5"
  curl -fsSL --retry 3 -o "${TMP}/${name}.tar.gz" "${url}"
  echo "${sha}  ${TMP}/${name}.tar.gz" | sha256sum --check --strict -
  tar -xzf "${TMP}/${name}.tar.gz" -C "${TMP}" "${member}"
  install -m 0755 "${TMP}/${member}" "${BIN}/${name}"
  echo "installed ${name} $2"
}

fetch gitleaks 8.30.1 \
  "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz" \
  551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb gitleaks

fetch oasdiff 1.33.0 \
  "https://github.com/oasdiff/oasdiff/releases/download/v1.33.0/oasdiff_1.33.0_linux_amd64.tar.gz" \
  43a4e328e2d13ba1552d760aa68d2485c75c5621f309f6ff64ae895188345247 oasdiff

echo "${BIN}" >> "${GITHUB_PATH:-/dev/null}"
