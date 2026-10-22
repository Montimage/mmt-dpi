#!/usr/bin/env bash
#
# make-release-bootstrap.sh — the release-generated, verified bootstrap
# installer (issue #498, F-CI-112).
#
# The release job of .github/workflows/release-packages.yml runs this on the
# collected release/ directory BEFORE it writes SHA256SUMS and attests the
# asset set, so everything written here is covered by both. For every
# versioned package
#     <package>_<version>_<rev>_<distro>_<x86_64|aarch64>.<deb|rpm>
# (tools/ci/build-package.sh) it writes:
#   - a copy under the stable alias name <package>_<distro>_<amd64|arm64>.<ext>,
#     the same in every release, so releases/latest/download/<alias> resolves;
#   - manifest.json — tag, version and one entry per package: distro, arch,
#     package, format, file (the alias), source (the versioned name), sha256;
#   - install.sh — tools/ci/bootstrap-install.sh rendered for <tag>, with the
#     same rows embedded, so the bootstrap a user downloads checks each
#     package against the digest released next to it (and then its Sigstore
#     attestation, which the release job adds as mmt-dpi.intoto.jsonl).
#
# Fails closed: an unparseable package name, a version other than <tag>'s, a
# distribution the bootstrap does not map, a format that does not match the
# distribution, two packages for one alias, a security package without its
# mmt-dpi package, no mmt-dpi package at all, or pre-existing outputs.
#
# Usage: bash tools/ci/make-release-bootstrap.sh <tag> <release-dir>
#   BOOTSTRAP_TEMPLATE=<file>  template to render (default: the tracked one)
# Exit: 0 = written, 1 = refused (see message), 2 = usage error.

set -euo pipefail

# The distributions tools/ci/bootstrap-install.sh detect_distro maps, with
# the package format each one ships — keep the two in step.
declare -A FORMAT=(
    [ubuntu-22.04]=deb [ubuntu-24.04]=deb [debian-12]=deb
    [rocky-9]=rpm [centos-stream9]=rpm
)

[ $# -eq 2 ] || { echo "usage: $0 <tag> <release-dir>" >&2; exit 2; }
TAG="$1"; DIR="$2"
[[ "$TAG" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]] \
    || { echo "✗ '$TAG' is not a vX.Y.Z release tag" >&2; exit 2; }
VERSION="${BASH_REMATCH[1]}"
[ -d "$DIR" ] || { echo "✗ no directory $DIR" >&2; exit 2; }
TEMPLATE="${BOOTSTRAP_TEMPLATE:-$(cd "$(dirname "$0")" && pwd)/bootstrap-install.sh}"
[ -f "$TEMPLATE" ] || { echo "✗ no template $TEMPLATE" >&2; exit 2; }
[ "$(grep -cx '@MANIFEST_ROWS@' "$TEMPLATE")" -eq 1 ] \
    || { echo "✗ $TEMPLATE lacks exactly one @MANIFEST_ROWS@ line" >&2; exit 2; }

refuse() { echo "✗ $*" >&2; exit 1; }

for out in install.sh manifest.json; do
    [ ! -e "$DIR/$out" ] || refuse "$DIR/$out already exists — run on a fresh release directory"
done

name_re='^(mmt-dpi|mmt-dpi-security)_([^_]+)_([^_]+)_([^_]+)_(x86_64|aarch64)\.(deb|rpm)$'
declare -A ALIAS_OF=()
rows=()
shopt -s nullglob
for path in "$DIR"/*.deb "$DIR"/*.rpm; do
    name="${path##*/}"
    [[ "$name" =~ $name_re ]] || refuse "unrecognised package name: $name"
    pkg="${BASH_REMATCH[1]}"; ver="${BASH_REMATCH[2]}"; distro="${BASH_REMATCH[4]}"
    march="${BASH_REMATCH[5]}"; ext="${BASH_REMATCH[6]}"
    [ "$ver" = "$VERSION" ] || refuse "$name is version $ver, not $VERSION ($TAG)"
    [ -n "${FORMAT[$distro]:-}" ] \
        || refuse "$name: distribution '$distro' is not mapped by bootstrap-install.sh"
    [ "${FORMAT[$distro]}" = "$ext" ] || refuse "$name: $distro ships .${FORMAT[$distro]}, not .$ext"
    case "$march" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
    alias="${pkg}_${distro}_${arch}.${ext}"
    [ -z "${ALIAS_OF[$alias]:-}" ] || refuse "$name and ${ALIAS_OF[$alias]} both map to $alias"
    [ ! -e "$DIR/$alias" ] || refuse "$DIR/$alias already exists"
    ALIAS_OF[$alias]="$name"
    sum="$(sha256sum -- "$path" | cut -d' ' -f1)"
    rows+=("$distro $arch $pkg $alias $sum $ext $name")
done
[ "${#rows[@]}" -gt 0 ] || refuse "no .deb/.rpm package in $DIR"

mapfile -t rows < <(printf '%s\n' "${rows[@]}" | LC_ALL=C sort)
have_main=0
for row in "${rows[@]}"; do
    read -r distro arch pkg _ <<< "$row"
    if [ "$pkg" = mmt-dpi ]; then
        have_main=1
    else
        printf '%s\n' "${rows[@]}" | grep -q "^${distro} ${arch} mmt-dpi " \
            || refuse "mmt-dpi-security has no mmt-dpi package for $distro ($arch)"
    fi
done
[ "$have_main" -eq 1 ] || refuse "no mmt-dpi package in $DIR"

# Copies, then the digest of every alias is re-checked against its source.
for row in "${rows[@]}"; do
    read -r _ _ _ alias sum _ name <<< "$row"
    cp -p -- "$DIR/$name" "$DIR/$alias"
    [ "$(sha256sum -- "$DIR/$alias" | cut -d' ' -f1)" = "$sum" ] \
        || refuse "$alias does not match $name after the copy"
done

# manifest.json: every value matched a restricted pattern above (no quote,
# backslash or control character), so plain printf is valid JSON.
{
    printf '{\n  "tag": "%s",\n  "version": "%s",\n  "repository": "montimage-projects/mmt-dpi",\n' "$TAG" "$VERSION"
    printf '  "attestation_bundle": "mmt-dpi.intoto.jsonl",\n  "packages": [\n'
    n=0
    for row in "${rows[@]}"; do
        read -r distro arch pkg alias sum ext name <<< "$row"
        n=$((n + 1)); sep=","; [ "$n" -eq "${#rows[@]}" ] && sep=""
        printf '    {"distro": "%s", "arch": "%s", "package": "%s", "format": "%s", "file": "%s", "source": "%s", "sha256": "%s"}%s\n' \
            "$distro" "$arch" "$pkg" "$ext" "$alias" "$name" "$sum" "$sep"
    done
    printf '  ]\n}\n'
} > "$DIR/manifest.json"

# install.sh: the template with the tag and the rows filled in.
table="$(for row in "${rows[@]}"; do read -r d a p f s _ <<< "$row"; printf '%s %s %s %s %s\n' "$d" "$a" "$p" "$f" "$s"; done)"
awk -v tag="$TAG" -v table="$table" '
    $0 == "@MANIFEST_ROWS@" { print table; next }
    { gsub(/@RELEASE_TAG@/, tag); print }
' "$TEMPLATE" > "$DIR/install.sh"
chmod 0644 "$DIR/install.sh"
sh -n "$DIR/install.sh" || refuse "rendered install.sh is not valid sh"
! grep -q '@[A-Z_]*@' "$DIR/install.sh" || refuse "rendered install.sh still has a placeholder"

echo "✓ bootstrap for $TAG: install.sh, manifest.json and ${#rows[@]} alias package(s)"
printf '    %s\n' "${!ALIAS_OF[@]}" | LC_ALL=C sort
