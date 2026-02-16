#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required but not found." >&2
  exit 1
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb is required but not found. Run this on Debian/Ubuntu (or install dpkg)." >&2
  exit 1
fi

PKG_NAME="${PKG_NAME:-vaulty}"
BIN_NAME="${BIN_NAME:-vaulty}"
VERSION="${VERSION:-$(awk -F '\"' '/^version = /{print $2; exit}' Cargo.toml)}"
MAINTAINER="${MAINTAINER:-Vaulty Maintainers <maintainers@example.com>}"
DESCRIPTION="${DESCRIPTION:-Local-first terminal vault for passwords and notes}"
SECTION="${SECTION:-utils}"
PRIORITY="${PRIORITY:-optional}"
DIST_DIR="${DIST_DIR:-dist}"

if command -v dpkg >/dev/null 2>&1; then
  ARCH="${ARCH:-$(dpkg --print-architecture)}"
else
  ARCH="${ARCH:-}"
fi

if [[ -z "${ARCH}" ]]; then
  case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
      echo "Could not determine Debian architecture. Set ARCH explicitly." >&2
      exit 1
      ;;
  esac
fi

WORK_DIR="$(mktemp -d)"
PKG_ROOT="${WORK_DIR}/${PKG_NAME}"
trap 'rm -rf "${WORK_DIR}"' EXIT

cargo build --release --locked --bin "${BIN_NAME}"

install -d "${PKG_ROOT}/DEBIAN"
install -d "${PKG_ROOT}/usr/bin"
install -d "${PKG_ROOT}/usr/share/doc/${PKG_NAME}"

install -m 0755 "target/release/${BIN_NAME}" "${PKG_ROOT}/usr/bin/${PKG_NAME}"
install -m 0644 "README.md" "${PKG_ROOT}/usr/share/doc/${PKG_NAME}/README.md"
install -m 0644 "CHANGELOG.md" "${PKG_ROOT}/usr/share/doc/${PKG_NAME}/CHANGELOG.md"

cat > "${PKG_ROOT}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: ${SECTION}
Priority: ${PRIORITY}
Architecture: ${ARCH}
Maintainer: ${MAINTAINER}
Description: ${DESCRIPTION}
EOF

mkdir -p "${DIST_DIR}"
OUT_DEB="${DIST_DIR}/${PKG_NAME}_${VERSION}_${ARCH}.deb"

if ! dpkg-deb --build --root-owner-group "${PKG_ROOT}" "${OUT_DEB}" 2>/dev/null; then
  dpkg-deb --build "${PKG_ROOT}" "${OUT_DEB}"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${OUT_DEB}" > "${OUT_DEB}.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "${OUT_DEB}" > "${OUT_DEB}.sha256"
fi

echo "Built package: ${OUT_DEB}"
if [[ -f "${OUT_DEB}.sha256" ]]; then
  echo "Checksum: ${OUT_DEB}.sha256"
fi
