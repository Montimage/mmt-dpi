#!/bin/sh
#
# install.sh — MMT-DPI verified package bootstrap (issue #498, F-CI-112).
#
#   curl -fsSL https://github.com/montimage-projects/mmt-dpi/releases/latest/download/install.sh | sh
#
# This file is the TEMPLATE. tools/ci/make-release-bootstrap.sh renders it in
# the release job of .github/workflows/release-packages.yml: it fills in the
# release tag and embeds one row per published package — distribution,
# architecture, package, alias asset name and sha256 — so the script a user
# downloads carries the digests of the very assets released next to it. The
# rendered install.sh is itself in SHA256SUMS and an attestation subject.
# Unrendered, it refuses to run.
#
# What it does, as root (or through sudo):
#   1. picks the package for this distribution and architecture from the
#      embedded table — Ubuntu 22.04/24.04 and Debian 12 (.deb), Rocky /
#      AlmaLinux / RHEL 9 and CentOS Stream 9 (.rpm), amd64 or arm64;
#      anything else is refused with a pointer to the source installer;
#   2. downloads it and the release's provenance bundle (mmt-dpi.intoto.jsonl)
#      and checks the package's sha256 against the embedded digest;
#   3. downloads the GitHub CLI release pinned below, checks its sha256, and
#      runs `gh attestation verify` offline against the bundle: the package
#      must be a subject of a Sigstore-signed provenance statement issued to
#      this repository's release workflow for this exact tag;
#   4. installs the package with apt-get or dnf, so its dependencies and the
#      loader registration (/etc/ld.so.conf.d/mmt-dpi.conf + ldconfig) come
#      from the package itself, then checks `ldconfig -p` lists libmmt_core.
# Any mismatch or failed check exits non-zero before anything is installed.
# There is no option to skip a check.
#
# Options (after `sh -s --`):
#   --with-security  also install mmt-dpi-security (libmmt_security,
#                    libmmt_fuzz — GPL-licensed engines, issue #497)
#   -h, --help       print this help
# Environment:
#   MMT_BOOTSTRAP_BASE_URL  download the release assets from this base URL
#                           instead of the GitHub release (a mirror or a
#                           local file:// copy). Safe to point anywhere: the
#                           digests are embedded and the provenance is
#                           verified against Sigstore, not the mirror.
#
# Exit: 0 = installed and verified, 1 = a check or the install failed,
#       2 = usage error or unsupported platform.

set -eu

REPO="montimage-projects/mmt-dpi"
RELEASE_TAG="@RELEASE_TAG@"
SIGNER_WORKFLOW="${REPO}/.github/workflows/release-packages.yml"
BUNDLE_ASSET="mmt-dpi.intoto.jsonl"
SOURCE_INSTALLER="https://raw.githubusercontent.com/${REPO}/main/install.sh"

# GitHub CLI used for the offline attestation check. Digests from the
# release's gh_<ver>_checksums.txt, equal to the GitHub API asset digests and
# verified with `gh attestation verify -R cli/cli` (docs/DECISIONS.md, #498).
GH_VERSION="2.101.0"
GH_SHA256_AMD64="9bca2d1c16825f109907a23307628a2f0698fbf99662b73a5cf0b020293072b8"
GH_SHA256_ARM64="b57e8063f18862647c9d22727c32e9da1b963f8bf9db648fe123a6975695640f"

OS_RELEASE="/etc/os-release"

# distro arch package file sha256 — one row per published package.
manifest_rows() {
    cat <<'MANIFEST'
@MANIFEST_ROWS@
MANIFEST
}

say() { printf '%s\n' "$*"; }
die() { code="$1"; shift; printf '✗ %s\n' "$*" >&2; exit "$code"; }

usage() {
    cat <<USAGE
MMT-DPI ${RELEASE_TAG} verified package bootstrap.
  curl -fsSL https://github.com/${REPO}/releases/latest/download/install.sh | sh
  ... | sh -s -- --with-security   also install mmt-dpi-security (GPL engines)
Checks every package's sha256 and Sigstore provenance, then installs it with
apt-get or dnf under /opt/mmt. To build from source (custom MMT_BASE,
--dry-run, --uninstall) use: curl -fsSL ${SOURCE_INSTALLER} | bash
USAGE
}

# Release tag the script was rendered for; refuse the raw template.
check_rendered() {
    case "$RELEASE_TAG" in
        v[0-9]*.[0-9]*.[0-9]*) ;;
        *) die 2 "this is the unrendered bootstrap template — download install.sh from a release" ;;
    esac
}

# Prints the package distribution token (as named in the release matrix).
detect_distro() {
    [ -r "$OS_RELEASE" ] || die 2 "cannot read ${OS_RELEASE} — unknown distribution"
    # shellcheck disable=SC1090  # runtime file
    ( . "$OS_RELEASE"
      id="${ID:-}"; ver="${VERSION_ID:-}"
      case "$id:$ver" in
          ubuntu:22.04|ubuntu:24.04) printf 'ubuntu-%s\n' "$ver" ;;
          debian:12)                 printf 'debian-12\n' ;;
          rocky:9|rocky:9.*|almalinux:9|almalinux:9.*|rhel:9|rhel:9.*)
                                     printf 'rocky-9\n' ;;
          centos:9)                  printf 'centos-stream9\n' ;;
          *) printf 'unsupported:%s\n' "${PRETTY_NAME:-$id $ver}" ;;
      esac )
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  printf 'amd64\n' ;;
        aarch64|arm64) printf 'arm64\n' ;;
        *) printf 'unsupported:%s\n' "$(uname -m)" ;;
    esac
}

# row_field <distro> <arch> <package> <column 4=file|5=sha256>
row_field() {
    manifest_rows | awk -v d="$1" -v a="$2" -v p="$3" -v c="$4" \
        '$1 == d && $2 == a && $3 == p { print $c; n++ } END { exit n == 1 ? 0 : 1 }'
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        die 1 "neither sha256sum nor shasum is available — cannot verify downloads"
    fi
}

# check_sha256 <file> <expected> <label>
check_sha256() {
    actual="$(sha256_of "$1")"
    [ "$actual" = "$2" ] \
        || die 1 "sha256 mismatch for $3: expected $2, got ${actual} — refusing to install"
    say "  ✓ sha256 $3"
}

# fetch <url> <dest> — https only (file:// for a local mirror), no redirect
# to plain http.
fetch() {
    curl -fsSL --proto '=https,file' --proto-redir '=https' -o "$2" "$1" \
        || die 1 "download failed: $1"
}

# Downloads the pinned GitHub CLI into $WORK and prints the gh path.
fetch_gh() {
    case "$1" in
        amd64) want="$GH_SHA256_AMD64" ;;
        arm64) want="$GH_SHA256_ARM64" ;;
    esac
    tarball="gh_${GH_VERSION}_linux_$1.tar.gz"
    fetch "https://github.com/cli/cli/releases/download/v${GH_VERSION}/${tarball}" \
        "${WORK}/${tarball}"
    check_sha256 "${WORK}/${tarball}" "$want" "${tarball}" >&2
    tar -xzf "${WORK}/${tarball}" -C "$WORK" \
        || die 1 "cannot extract ${tarball}"
    printf '%s\n' "${WORK}/gh_${GH_VERSION}_linux_$1/bin/gh"
}

# verify_attestation <gh> <package file> <label> — offline, no GitHub login:
# the bundle is checked against the Sigstore public-good trust root, and
# the signer must be this repository's release workflow at this tag.
verify_attestation() {
    mkdir -p "${WORK}/gh-home"
    env -u GH_TOKEN -u GITHUB_TOKEN -u GH_ENTERPRISE_TOKEN -u GH_HOST -u GH_REPO \
        HOME="${WORK}/gh-home" GH_CONFIG_DIR="${WORK}/gh-home" XDG_CACHE_HOME="${WORK}/gh-home" \
        XDG_STATE_HOME="${WORK}/gh-home" XDG_DATA_HOME="${WORK}/gh-home" \
        GH_NO_UPDATE_NOTIFIER=1 GH_PROMPT_DISABLED=1 \
        "$1" attestation verify "$2" --bundle "${WORK}/${BUNDLE_ASSET}" \
            --repo "$REPO" --signer-workflow "$SIGNER_WORKFLOW" \
            --source-ref "refs/tags/${RELEASE_TAG}" --deny-self-hosted-runners \
            >"${WORK}/attestation.log" 2>&1 \
        || { cat "${WORK}/attestation.log" >&2
             die 1 "provenance attestation does not match $3 — refusing to install"; }
    say "  ✓ attestation $3 (${SIGNER_WORKFLOW}@refs/tags/${RELEASE_TAG})"
}

install_packages() {
    if [ "$1" = deb ]; then
        command -v apt-get >/dev/null 2>&1 || die 1 "apt-get not found"
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -qq </dev/null
        # shellcheck disable=SC2086  # $PKG_PATHS is a list of absolute paths
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $PKG_PATHS </dev/null
    else
        pm=dnf; command -v dnf >/dev/null 2>&1 || pm=yum
        command -v "$pm" >/dev/null 2>&1 || die 1 "neither dnf nor yum found"
        # shellcheck disable=SC2086  # $PKG_PATHS is a list of absolute paths
        $SUDO "$pm" install -y -q $PKG_PATHS </dev/null
    fi
}

main() {
    with_security=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --with-security) with_security=1 ;;
            -h|--help) usage; exit 0 ;;
            *) die 2 "unknown option: $1 (see --help)" ;;
        esac
        shift
    done
    check_rendered
    case "${MMT_BASE:-/opt/mmt}" in
        /opt/mmt|/opt/mmt/) ;;
        *) die 2 "the packages install under /opt/mmt only (MMT_BASE=${MMT_BASE})." \
               "For another prefix build from source: curl -fsSL ${SOURCE_INSTALLER} | bash" ;;
    esac

    SUDO=""
    if [ "$(id -u)" -ne 0 ]; then
        command -v sudo >/dev/null 2>&1 || die 2 "run as root, or install sudo"
        SUDO="sudo"
    fi
    for tool in curl tar awk; do
        command -v "$tool" >/dev/null 2>&1 || die 2 "${tool} is required"
    done

    distro="$(detect_distro)"; arch="$(detect_arch)"
    case "$distro$arch" in
        *unsupported:*)
            die 2 "no ${RELEASE_TAG} package for ${distro#unsupported:} / ${arch#unsupported:}." \
                "Build from source instead: curl -fsSL ${SOURCE_INSTALLER} | bash" ;;
    esac
    packages="mmt-dpi"; [ "$with_security" -eq 1 ] && packages="mmt-dpi mmt-dpi-security"
    base="${MMT_BOOTSTRAP_BASE_URL:-https://github.com/${REPO}/releases/download/${RELEASE_TAG}}"
    base="${base%/}"
    say "==> MMT-DPI ${RELEASE_TAG}: ${packages} for ${distro} (${arch})"

    WORK="$(mktemp -d)"
    # Readable by the package manager's unprivileged download user (apt _apt).
    chmod 0755 "$WORK"
    trap 'rm -rf "$WORK"' EXIT
    trap 'exit 1' HUP INT TERM

    # 1-2. download, then check every digest before anything else runs.
    say "  [1/3] downloading and checking sha256"
    PKG_PATHS=""; format=""
    for p in $packages; do
        file="$(row_field "$distro" "$arch" "$p" 4)" \
            || die 2 "the ${RELEASE_TAG} release has no ${p} package for ${distro} (${arch})"
        sum="$(row_field "$distro" "$arch" "$p" 5)"
        fetch "${base}/${file}" "${WORK}/${file}"
        check_sha256 "${WORK}/${file}" "$sum" "$file"
        PKG_PATHS="${PKG_PATHS} ${WORK}/${file}"
        format="${file##*.}"
    done
    fetch "${base}/${BUNDLE_ASSET}" "${WORK}/${BUNDLE_ASSET}"

    # 3. provenance: Sigstore attestation of this repository's release workflow.
    say "  [2/3] verifying the build-provenance attestation"
    gh="$(fetch_gh "$arch")"
    for path in $PKG_PATHS; do
        verify_attestation "$gh" "$path" "${path##*/}"
    done

    # 4. install with the native package manager.
    say "  [3/3] installing with the native package manager"
    install_packages "$format"
    ldconfig_bin="$(command -v ldconfig || echo /sbin/ldconfig)"
    "$ldconfig_bin" -p | grep -q libmmt_core \
        || die 1 "installed, but libmmt_core is not in the loader cache (ldconfig -p)"

    say "✓ MMT-DPI ${RELEASE_TAG} installed under /opt/mmt — libmmt_core is registered with the loader."
    say "  The first run needs a C compiler and the libpcap headers:"
    if [ "$format" = deb ]; then
        say "    sudo apt-get install -y gcc libpcap-dev"
    else
        say "    sudo dnf --enablerepo=crb install -y gcc libpcap-devel   # EL9: libpcap-devel is in CRB"
        say "  (on RHEL 9 instead: sudo subscription-manager repos --enable codeready-builder-for-rhel-9-\$(arch)-rpms"
        say "   then sudo dnf install -y gcc libpcap-devel)"
    fi
    say "  then follow the first run on https://montimage-projects.github.io/mmt-dpi/"
}

# Sourcing with MMT_BOOTSTRAP_SOURCE_ONLY=1 defines the functions without
# running anything (tools/ci/tests/test-release-bootstrap.sh).
if [ "${MMT_BOOTSTRAP_SOURCE_ONLY:-0}" != 1 ]; then
    main "$@"
fi
