#!/usr/bin/env bash
set -euo pipefail

OWNER="${OWNER:-nodyhody}"
REPO="${REPO:-vaulty}"
BIN_NAME="${BIN_NAME:-vaulty}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-latest}"

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "${os}" in
    Linux) os="unknown-linux-gnu" ;;
    Darwin) os="apple-darwin" ;;
    *)
      echo "Unsupported OS: ${os}" >&2
      exit 1
      ;;
  esac

  case "${arch}" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *)
      echo "Unsupported architecture: ${arch}" >&2
      exit 1
      ;;
  esac

  echo "${arch}-${os}"
}

resolve_version() {
  if [[ "${VERSION}" != "latest" ]]; then
    echo "${VERSION#v}"
    return
  fi

  local tag
  tag="$(curl -fsSL "https://api.github.com/repos/${OWNER}/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n1)"
  if [[ -z "${tag}" ]]; then
    echo "Could not resolve latest release tag for ${OWNER}/${REPO}" >&2
    exit 1
  fi
  echo "${tag#v}"
}

main() {
  local target version asset url tmpdir
  target="$(detect_target)"
  version="$(resolve_version)"
  asset="${BIN_NAME}-${version}-${target}.tar.gz"
  url="https://github.com/${OWNER}/${REPO}/releases/download/v${version}/${asset}"

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT

  echo "Downloading ${url}"
  curl -fsSL "${url}" -o "${tmpdir}/${asset}"
  tar -xzf "${tmpdir}/${asset}" -C "${tmpdir}"

  mkdir -p "${INSTALL_DIR}"
  install -m 0755 "${tmpdir}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"

  echo "Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
  echo "Ensure ${INSTALL_DIR} is in PATH."
}

main "$@"
