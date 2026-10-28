#!/usr/bin/env bash
#
# build-source-tarball.sh — the reproducible upstream source tarball
# (issue #475): mmt-dpi-<VERSION>.tar.gz, the file a distribution packages.
#
# The archive is `git archive` of one commit (entry mtimes are the commit's
# own timestamp, owners are root) piped through `gzip -n` (no name, no
# timestamp), so the same commit always yields the same bytes and its sha256
# can be published, attested and re-derived by anyone with the repository.
# Only tracked files are archived — no build output, no untracked leftovers.
#
# Usage: build-source-tarball.sh [--out DIR] [--ref REF] [--verify]
#
#   --out DIR    directory for the tarball (default dist/source)
#   --ref REF    commit or tag to archive (default HEAD)
#   --verify     build a second copy and require it to be byte-identical
#
# Prints the path and sha256 of the tarball. Exit: 0 ok, 1 not reproducible,
# 2 usage/tool error.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${ROOT}/dist/source"
REF="HEAD"
VERIFY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --out)    OUT="${2:?--out needs a directory}"; shift 2 ;;
        --ref)    REF="${2:?--ref needs a commit or tag}"; shift 2 ;;
        --verify) VERIFY=1; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "✗ unknown argument: $1" >&2; exit 2 ;;
    esac
done

# The version comes from the archived commit, not from the working tree, so a
# tag build names the tarball after what it contains.
VERSION="$(git -C "${ROOT}" show "${REF}:rules/common.mk" \
    | sed -n 's/^VERSION[[:space:]]*:=[[:space:]]*//p' | head -n 1)"
[ -n "${VERSION}" ] || { echo "✗ cannot read VERSION from rules/common.mk at ${REF}" >&2; exit 2; }

NAME="mmt-dpi-${VERSION}"
mkdir -p "${OUT}"
TARBALL="${OUT}/${NAME}.tar.gz"

build() { git -C "${ROOT}" archive --format=tar --prefix="${NAME}/" "${REF}" | gzip -n -9 > "$1"; }

build "${TARBALL}"

if [ "${VERIFY}" -eq 1 ]; then
    again="$(mktemp)"
    trap 'rm -f "${again}"' EXIT
    build "${again}"
    if ! cmp -s "${TARBALL}" "${again}"; then
        echo "✗ ${NAME}.tar.gz is not reproducible: two builds of ${REF} differ" >&2
        exit 1
    fi
    echo "✓ two builds of ${REF} are byte-identical"
fi

echo "${TARBALL}"
sha256sum "${TARBALL}"
