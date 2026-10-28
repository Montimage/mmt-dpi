#!/usr/bin/env bash
#
# build-debian-package.sh — build, lint, install and exercise the Debian
# binary packages that debian/ produces (issue #475).
#
# This is the package a distribution would build itself: the FHS layout
# (`make -C sdk install-fhs`), versioned sonames, no /opt/mmt. It is NOT the
# upstream `make deb` package that build-package.sh ships to GitHub Releases.
#
# Runs as root inside a Debian/Ubuntu container with the checkout at $PWD
# (the release-packages.yml convention). The tree is copied to a scratch
# directory first so dpkg-buildpackage leaves nothing behind in the mount.
#
# Steps: build (-b) -> lintian (errors fail) -> install the .debs into the
# container -> debian/tests/installed-consumer, the autopkgtest payload.
# The .debs are collected into dist/debian-packages/.
#
# Exit: 0 = every step passed, non-zero = the first failing step.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
SRC="$PWD"
[ -f "${SRC}/debian/rules" ] || { echo "✗ run from the repository root (no debian/rules)" >&2; exit 2; }

apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    build-essential debhelper devscripts fakeroot lintian pkgconf git ca-certificates >/dev/null

git config --global --add safe.directory "${SRC}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${WORK}/src"
git -C "${SRC}" ls-files -co --exclude-standard -z \
    | tar -C "${SRC}" --null -T - -cf - | tar -C "${WORK}/src" -xf -

cd "${WORK}/src"
dpkg-buildpackage -b -us -uc

echo "--- lintian (errors fail the build, warnings are listed) ---"
lintian --fail-on error --tag-display-limit 0 "${WORK}"/*.changes

echo "--- install the packages into a clean system and run the consumer ---"
apt-get install -y -qq --no-install-recommends \
    "${WORK}"/libmmt-dpi1_*.deb "${WORK}"/libmmt-dpi-dev_*.deb gcc libc6-dev libpcap-dev >/dev/null
bash debian/tests/installed-consumer

mkdir -p "${SRC}/dist/debian-packages"
cp "${WORK}"/*.deb "${SRC}/dist/debian-packages/"
# The container runs as root: hand the output back to the checkout owner.
chown -R --reference="${SRC}" "${SRC}/dist/debian-packages"
ls -l "${SRC}/dist/debian-packages"
