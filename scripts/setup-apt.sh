#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://nodyhody06.github.io/vaulty}"
KEY_URL="${KEY_URL:-${REPO_URL}/vaulty-archive-key.asc}"
KEYRING_PATH="${KEYRING_PATH:-/usr/share/keyrings/vaulty-archive-keyring.gpg}"
LIST_PATH="${LIST_PATH:-/etc/apt/sources.list.d/vaulty.list}"

if ! command -v apt >/dev/null 2>&1; then
  echo "apt is required. This script supports Debian/Ubuntu-style systems only." >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required but not installed." >&2
  exit 1
fi

if ! command -v gpg >/dev/null 2>&1; then
  echo "gpg is required but not installed." >&2
  exit 1
fi

if command -v dpkg >/dev/null 2>&1; then
  ARCH="${ARCH:-$(dpkg --print-architecture)}"
else
  ARCH="${ARCH:-amd64}"
fi

echo "Configuring Vaulty APT repository for architecture: ${ARCH}"
sudo mkdir -p "$(dirname "${KEYRING_PATH}")"
curl -fsSL "${KEY_URL}" | gpg --dearmor | sudo tee "${KEYRING_PATH}" >/dev/null

echo "deb [arch=${ARCH} signed-by=${KEYRING_PATH}] ${REPO_URL} stable main" \
  | sudo tee "${LIST_PATH}" >/dev/null

sudo apt update
echo "Vaulty repo configured. Install with: sudo apt install vaulty"
