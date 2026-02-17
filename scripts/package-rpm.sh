#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required but not found." >&2
  exit 1
fi

if ! command -v rpmbuild >/dev/null 2>&1; then
  echo "rpmbuild is required but not found. Install rpm/rpm-build first." >&2
  exit 1
fi

PKG_NAME="${PKG_NAME:-vaulty}"
BIN_NAME="${BIN_NAME:-vaulty}"
VERSION="${VERSION:-$(awk -F '\"' '/^version = /{print $2; exit}' Cargo.toml)}"
RELEASE="${RELEASE:-1}"
SUMMARY="${SUMMARY:-Local-first terminal vault for passwords and notes}"
LICENSE="${LICENSE:-Custom}"
URL="${URL:-https://github.com/Nodyhody06/vaulty}"
MAINTAINER="${MAINTAINER:-Vaulty Maintainers <maintainers@example.com>}"
DIST_DIR="${DIST_DIR:-dist}"

if command -v rpm >/dev/null 2>&1; then
  ARCH="${ARCH:-$(rpm --eval '%{_arch}')}"
else
  case "$(uname -m)" in
    x86_64|amd64) ARCH="${ARCH:-x86_64}" ;;
    aarch64|arm64) ARCH="${ARCH:-aarch64}" ;;
    *)
      echo "Could not determine RPM architecture. Set ARCH explicitly." >&2
      exit 1
      ;;
  esac
fi

cargo build --release --locked --bin "${BIN_NAME}"

WORK_DIR="$(mktemp -d)"
TOPDIR="${WORK_DIR}/rpmbuild"
SPECS_DIR="${TOPDIR}/SPECS"
SOURCES_DIR="${TOPDIR}/SOURCES"
trap 'rm -rf "${WORK_DIR}"' EXIT

mkdir -p "${SPECS_DIR}" "${SOURCES_DIR}" "${TOPDIR}/BUILD" "${TOPDIR}/BUILDROOT" "${TOPDIR}/RPMS" "${TOPDIR}/SRPMS"

cp "target/release/${BIN_NAME}" "${SOURCES_DIR}/${PKG_NAME}"
cp README.md "${SOURCES_DIR}/README.md"
cp CHANGELOG.md "${SOURCES_DIR}/CHANGELOG.md"

CHANGELOG_DATE="$(LC_ALL=C date +"%a %b %d %Y")"
cat > "${SPECS_DIR}/${PKG_NAME}.spec" <<EOF
Name:           ${PKG_NAME}
Version:        ${VERSION}
Release:        ${RELEASE}%{?dist}
Summary:        ${SUMMARY}
License:        ${LICENSE}
URL:            ${URL}
BuildArch:      ${ARCH}
Source0:        ${PKG_NAME}
Source1:        README.md
Source2:        CHANGELOG.md

%description
${SUMMARY}

%prep

%build

%install
rm -rf %{buildroot}
install -D -m 0755 %{SOURCE0} %{buildroot}/usr/bin/${PKG_NAME}
install -D -m 0644 %{SOURCE1} %{buildroot}/usr/share/doc/${PKG_NAME}/README.md
install -D -m 0644 %{SOURCE2} %{buildroot}/usr/share/doc/${PKG_NAME}/CHANGELOG.md

%files
/usr/bin/${PKG_NAME}
%doc /usr/share/doc/${PKG_NAME}/README.md
%doc /usr/share/doc/${PKG_NAME}/CHANGELOG.md

%changelog
* ${CHANGELOG_DATE} ${MAINTAINER} - ${VERSION}-${RELEASE}
- Package release.
EOF

rpmbuild -bb --define "_topdir ${TOPDIR}" "${SPECS_DIR}/${PKG_NAME}.spec"

mkdir -p "${DIST_DIR}"
RPM_PATH="$(find "${TOPDIR}/RPMS" -type f -name "${PKG_NAME}-*.rpm" | head -n1)"
if [[ -z "${RPM_PATH}" ]]; then
  echo "RPM build finished but no output package was found." >&2
  exit 1
fi

OUT_RPM="${DIST_DIR}/$(basename "${RPM_PATH}")"
cp "${RPM_PATH}" "${OUT_RPM}"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${OUT_RPM}" > "${OUT_RPM}.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "${OUT_RPM}" > "${OUT_RPM}.sha256"
fi

echo "Built package: ${OUT_RPM}"
if [[ -f "${OUT_RPM}.sha256" ]]; then
  echo "Checksum: ${OUT_RPM}.sha256"
fi
