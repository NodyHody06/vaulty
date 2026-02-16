#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

BIN_NAME="${BIN_NAME:-vaulty}"
TARGET="${TARGET:-$(rustc -vV | awk '/^host:/{print $2}')}"
VERSION="${VERSION:-$(awk -F '\"' '/^version = /{print $2; exit}' Cargo.toml)}"
DIST_DIR="${DIST_DIR:-dist}"

mkdir -p "${DIST_DIR}"
cargo build --release --locked --bin "${BIN_NAME}" --target "${TARGET}"

if [[ "${TARGET}" == *windows* ]]; then
  EXT=".exe"
  ARCHIVE_EXT="zip"
else
  EXT=""
  ARCHIVE_EXT="tar.gz"
fi

cp "target/${TARGET}/release/${BIN_NAME}${EXT}" "${DIST_DIR}/${BIN_NAME}${EXT}"
ASSET_NAME="${BIN_NAME}-${VERSION}-${TARGET}"

if [[ "${ARCHIVE_EXT}" == "zip" ]]; then
  (cd "${DIST_DIR}" && zip -q "${ASSET_NAME}.zip" "${BIN_NAME}${EXT}")
  ASSET_PATH="${DIST_DIR}/${ASSET_NAME}.zip"
else
  tar -czf "${DIST_DIR}/${ASSET_NAME}.tar.gz" -C "${DIST_DIR}" "${BIN_NAME}${EXT}"
  ASSET_PATH="${DIST_DIR}/${ASSET_NAME}.tar.gz"
fi

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "${ASSET_PATH}" > "${ASSET_PATH}.sha256"
elif command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${ASSET_PATH}" > "${ASSET_PATH}.sha256"
fi

echo "Built asset: ${ASSET_PATH}"
if [[ -f "${ASSET_PATH}.sha256" ]]; then
  echo "Checksum: ${ASSET_PATH}.sha256"
fi
