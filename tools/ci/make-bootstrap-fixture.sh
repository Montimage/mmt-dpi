#!/usr/bin/env bash
#
# make-bootstrap-fixture.sh — release-shaped asset directories for the
# bootstrap installer smoke (issue #498), built from a PUBLISHED release.
#
# No release is cut to test the bootstrap: this script downloads the real
# packages of an existing release (default: the latest) for the given
# distributions on this host's architecture, and the release's real
# Sigstore provenance bundle from the public attestations API, then renders
# the bootstrap with tools/ci/make-release-bootstrap.sh exactly as the
# release job does. The attestation that is checked is the genuine one, so
# the full chain runs — only the download base differs
# (MMT_BOOTSTRAP_BASE_URL=file://<dir>).
#
# Four directories under <out-dir>:
#   good/                as the release job would publish it
#   reject-sha/          good/ with one byte appended to every alias package
#                        after rendering: the embedded sha256 no longer
#                        matches — the bootstrap must refuse
#   reject-attestation/  rendered from packages with one byte appended, so
#                        the embedded sha256 matches but no attestation
#                        names that digest — the bootstrap must refuse
#   reject-identity/     good/ with install.sh pinned to another published
#                        tag: digests match, but the attestation was issued
#                        to a different source ref — the bootstrap must refuse
#
# Usage: bash tools/ci/make-bootstrap-fixture.sh <out-dir> <distro>...
#   TAG=<vX.Y.Z>  release to use (default: the latest release)
#   ARCH=<x86_64|aarch64>  package architecture (default: uname -m)
#   GH_TOKEN      optional, raises the API rate limit
# Needs curl and jq. Exit: 0 = written, 1 = a download or check failed,
# 2 = usage error.

set -euo pipefail
shopt -s nullglob

REPO="montimage-projects/mmt-dpi"
API="https://api.github.com/repos/${REPO}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ $# -ge 2 ] || { echo "usage: $0 <out-dir> <distro>..." >&2; exit 2; }
OUT="$1"; shift
for tool in curl jq sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || { echo "✗ $tool is required" >&2; exit 2; }
done
ARCH="${ARCH:-$(uname -m)}"
case "$ARCH" in x86_64|aarch64) ;; *) echo "✗ ARCH must be x86_64 or aarch64" >&2; exit 2 ;; esac

api() {
    local auth=()
    [ -n "${GH_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${GH_TOKEN}")
    curl -fsSL --proto '=https' "${auth[@]}" -H "Accept: application/vnd.github+json" "$1"
}

if [ -n "${TAG:-}" ]; then
    release="$(api "${API}/releases/tags/${TAG}")"
else
    release="$(api "${API}/releases/latest")"
fi
TAG="$(jq -r .tag_name <<< "$release")"
# Another published tag, for the identity-mismatch directory.
OTHER_TAG="$(api "${API}/releases?per_page=10" | jq -r --arg t "$TAG" \
    '[.[] | select(.draft | not) | .tag_name | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$") and . != $t)][0] // empty')"
[ -n "$OTHER_TAG" ] || { echo "✗ no second release tag for reject-identity" >&2; exit 1; }
echo "==> fixture from ${REPO} ${TAG} (${ARCH}): $*"

rm -rf "$OUT"
mkdir -p "$OUT/download"
for distro in "$@"; do
    # The SDK package only: mmt-dpi-security exists from v1.9.2 (#497).
    mapfile -t assets < <(jq -r --arg d "$distro" --arg a "$ARCH" \
        '.assets[] | select(.name | test("^mmt-dpi_[^_]+_[^_]+_" + $d + "_" + $a + "\\.(deb|rpm)$")) | "\(.name) \(.browser_download_url) \(.digest // "")"' \
        <<< "$release")
    [ "${#assets[@]}" -eq 1 ] || { echo "✗ ${TAG} has ${#assets[@]} mmt-dpi package(s) for ${distro} ${ARCH}" >&2; exit 1; }
    read -r name url digest <<< "${assets[0]}"
    curl -fsSL --proto '=https' -o "$OUT/download/$name" "$url"
    sum="$(sha256sum "$OUT/download/$name" | cut -d' ' -f1)"
    if [ -n "$digest" ] && [ "$digest" != "sha256:${sum}" ]; then
        echo "✗ $name: downloaded sha256 ${sum} differs from the API's ${digest}" >&2; exit 1
    fi
    # Every bundle that names this digest; duplicates collapse below.
    api "${API}/attestations/sha256:${sum}" | jq -c '.attestations[].bundle' >> "$OUT/bundles"
    echo "  ✓ ${name}"
done
sort -u "$OUT/bundles" > "$OUT/download/mmt-dpi.intoto.jsonl"
[ -s "$OUT/download/mmt-dpi.intoto.jsonl" ] || { echo "✗ no attestation bundle for ${TAG}" >&2; exit 1; }

render() { # <dir> — the release job's step, on a copy of the downloads
    mkdir -p "$1"
    cp -p "$OUT"/download/*.deb "$OUT"/download/*.rpm "$1"/ 2>/dev/null || true
    [ -n "$(ls "$1")" ] || { echo "✗ nothing to render in $1" >&2; exit 1; }
    bash "${HERE}/make-release-bootstrap.sh" "$TAG" "$1" >/dev/null
    cp -p "$OUT/download/mmt-dpi.intoto.jsonl" "$1"/
}
tamper() { # <file>... — one appended byte changes the digest
    local f
    for f in "$@"; do printf 'x' >> "$f"; done
}

shopt -s nullglob
render "$OUT/good"
render "$OUT/reject-sha"
tamper "$OUT"/reject-sha/mmt-dpi_*_amd64.* "$OUT"/reject-sha/mmt-dpi_*_arm64.*
mkdir -p "$OUT/reject-attestation"
cp -p "$OUT"/download/*.deb "$OUT"/download/*.rpm "$OUT/reject-attestation"/
tamper "$OUT"/reject-attestation/*.deb "$OUT"/reject-attestation/*.rpm
bash "${HERE}/make-release-bootstrap.sh" "$TAG" "$OUT/reject-attestation" >/dev/null
cp -p "$OUT/download/mmt-dpi.intoto.jsonl" "$OUT/reject-attestation"/
# Same assets, but the bootstrap expects another tag's provenance: the
# sha256 rows match, the attestation's source ref does not.
cp -a "$OUT/good" "$OUT/reject-identity"
sed -i "s/^RELEASE_TAG=\"${TAG}\"$/RELEASE_TAG=\"${OTHER_TAG}\"/" "$OUT/reject-identity/install.sh"
grep -qx "RELEASE_TAG=\"${OTHER_TAG}\"" "$OUT/reject-identity/install.sh" \
    || { echo "✗ could not retarget reject-identity/install.sh" >&2; exit 1; }
rm -rf "$OUT/download" "$OUT/bundles"
echo "✓ fixture ${TAG}: $(cd "$OUT" && echo */)"
