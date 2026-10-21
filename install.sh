#!/usr/bin/env bash
#
# MMT-DPI Installation Script
# https://github.com/montimage-projects/mmt-dpi
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
#   wget -qO- https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
#
# By default the installer clones the pinned release tag below and verifies it
# after checkout (commit pin, plus the tag signature when one is present) —
# never a moving branch. See docs/DECISIONS.md for the canonical-organisation
# and verification decisions (issue #197).
#
# Options:
#   --dry-run              - Print the install plan and exit without changes
#   --uninstall            - Remove an installed MMT-DPI (from --prefix/MMT_BASE)
#   --prefix <dir>         - Install to <dir> (same as MMT_BASE=<dir>)
#   --branch <ref>         - Build a specific branch instead of the release tag
#   --unverified-branch    - Required to permit a moving ref (no verification)
#   -h, --help             - Show usage
#
# Options (via environment variables):
#   MMT_BASE=/custom/path  - Install to a custom directory (default: /opt/mmt)
#   BRANCH=dev             - Same as --branch dev (requires --unverified-branch)
#   JOBS=4                 - Number of parallel build jobs (default: auto-detected)
#   SKIP_DEPS=1            - Skip dependency installation
#   LDCONF=0               - Do not register the libraries with the dynamic
#                            loader on a root install (default: auto)
#
# Examples:
#   curl -fsSL https://...install.sh | bash
#   curl -fsSL https://...install.sh | bash -s -- --dry-run
#   curl -fsSL https://...install.sh | MMT_BASE=/usr/local/mmt bash
#   curl -fsSL https://...install.sh | BRANCH=dev bash -s -- --unverified-branch
#   curl -fsSL https://...install.sh | bash -s -- --uninstall
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Canonical repository — the organisation is declared in docs/DECISIONS.md
# (issue #197). scripts/validate-install-origin.sh fails CI if this constant
# and the README clone URL ever diverge again.
REPO_URL="https://github.com/montimage-projects/mmt-dpi.git"
INSTALLER_URL="https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh"

# Default ref: the pinned release tag, never a moving branch (issue #197,
# F-SEC-006 / F-BUG-118). RELEASE_TAG_SHA pins the commit the tag must resolve
# to, so a moved or re-created tag fails verification right after cloning.
# It must be the PEELED commit (`git rev-parse "$RELEASE_TAG^{commit}"`), never
# the annotated tag object: write both lines with
# `bash tools/ci/check-release-tag.sh --write-pin vX.Y.Z`, and
# `bash tools/ci/check-release-tag.sh` fails CI when they disagree (issue #484).
RELEASE_TAG="v1.9.1"
RELEASE_TAG_SHA="1b4aad29aea50f24a25e2dbeee92c93b84146401"

BRANCH="${BRANCH:-}"           # opt-in moving ref (env BRANCH or --branch)
UNVERIFIED_BRANCH=0            # set by --unverified-branch
DRY_RUN=0                      # set by --dry-run
UNINSTALL=0                    # set by --uninstall
LDCONF="${LDCONF:-auto}"       # auto = register the loader on root installs
MMT_BASE="${MMT_BASE:-/opt/mmt}"
SKIP_DEPS="${SKIP_DEPS:-0}"
BUILD_DIR=""
REF=""                         # resolved by resolve_ref()
REF_KIND=""                    # "tag" (verified) or "branch" (unverified)

# ---------------------------------------------------------------------------
# Input validation (hardening: reject injection / path-traversal via env vars)
# ---------------------------------------------------------------------------
validate_branch() {
    local b="$1"
    if [ -z "$b" ] || [ ${#b} -gt 100 ]; then
        printf 'ERROR: BRANCH must be 1-100 characters\n' >&2; exit 1
    fi
    if [[ ! "$b" =~ ^[A-Za-z0-9._/-]+$ ]]; then
        printf 'ERROR: BRANCH contains invalid characters: %s\n' "$b" >&2; exit 1
    fi
    if [[ "$b" == *".."* ]] || [[ "$b" == "-"* ]] || [[ "$b" == *"--"* ]]; then
        printf 'ERROR: BRANCH contains forbidden sequence: %s\n' "$b" >&2; exit 1
    fi
}

validate_jobs() {
    local j="$1"
    if [[ ! "$j" =~ ^[0-9]+$ ]] || [ "$j" -lt 1 ] || [ "$j" -gt 256 ]; then
        printf 'ERROR: JOBS must be an integer 1-256: %s\n' "$j" >&2; exit 1
    fi
}

validate_skip_deps() {
    if [[ "$1" != "0" && "$1" != "1" ]]; then
        printf 'ERROR: SKIP_DEPS must be 0 or 1: %s\n' "$1" >&2; exit 1
    fi
}

validate_ldconf() {
    if [[ "$1" != "auto" && "$1" != "0" ]]; then
        printf 'ERROR: LDCONF must be auto or 0: %s\n' "$1" >&2; exit 1
    fi
}

usage() {
    cat <<'EOF'
MMT-DPI Installation Script — https://github.com/montimage-projects/mmt-dpi

Usage:
  bash install.sh [OPTIONS]

Options:
  --dry-run              Print the install plan and exit without changes.
  --uninstall            Remove MMT-DPI from the prefix (--prefix/MMT_BASE)
                         and its dynamic-loader registration.
  --prefix <dir>         Install to <dir> instead of /opt/mmt (same as
                         setting MMT_BASE=<dir> in the environment).
  --branch <ref>         Build a specific branch instead of the pinned
                         release tag. Moving refs carry no integrity
                         guarantee and require --unverified-branch.
  --unverified-branch    Permit building a moving ref (BRANCH env or
                         --branch) with no tag, signature or commit pin.
  -h, --help             Show this help.

Environment variables:
  MMT_BASE=/custom/path  Install to a custom directory (default: /opt/mmt)
  BRANCH=dev             Same as --branch dev (requires --unverified-branch)
  JOBS=4                 Number of parallel build jobs (default: auto)
  SKIP_DEPS=1            Skip dependency installation
  LDCONF=0               Do not register the libraries with the dynamic
                         loader on a root install (default: auto)
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)            DRY_RUN=1 ;;
            --uninstall)          UNINSTALL=1 ;;
            --unverified-branch)  UNVERIFIED_BRANCH=1 ;;
            --prefix)
                if [ $# -lt 2 ]; then
                    printf 'ERROR: --prefix requires a directory\n' >&2; exit 1
                fi
                MMT_BASE="$2"; shift ;;
            --prefix=*)           MMT_BASE="${1#*=}" ;;
            --branch)
                if [ $# -lt 2 ]; then
                    printf 'ERROR: --branch requires a value\n' >&2; exit 1
                fi
                BRANCH="$2"; shift ;;
            --branch=*)           BRANCH="${1#*=}" ;;
            -h|--help)            usage; exit 0 ;;
            *) printf 'ERROR: unknown option: %s (try --help)\n' "$1" >&2; exit 1 ;;
        esac
        shift
    done
}

# Resolve which ref to clone. The default is the pinned release tag; any other
# (moving) ref is refused unless --unverified-branch was given explicitly
# (issue #197, F-BUG-118 — the old validator admitted arbitrary refs).
resolve_ref() {
    if [ -n "$BRANCH" ] && [ "$BRANCH" != "$RELEASE_TAG" ]; then
        if [ "$UNVERIFIED_BRANCH" != "1" ]; then
            printf 'ERROR: refusing to build unverified moving ref: %s\n' "$BRANCH" >&2
            printf '       The default install pins release tag %s (verified after clone).\n' "$RELEASE_TAG" >&2
            printf '       Re-run with --unverified-branch to accept the risk.\n' >&2
            exit 1
        fi
        REF="$BRANCH"
        REF_KIND="branch"
    else
        REF="$RELEASE_TAG"
        REF_KIND="tag"
    fi
}

parse_args "$@"
resolve_ref
validate_branch "$REF"
validate_skip_deps "$SKIP_DEPS"
validate_ldconf "$LDCONF"

# ---------------------------------------------------------------------------
# Shared install definitions (single source of truth — issue #211, F-BUG-121)
# ---------------------------------------------------------------------------
# The prefix validator and the prefix-writability helper live in
# dist/ZIP/mmt-install-common.sh, shared with the offline ZIP installer. This
# script is designed for `curl | bash` where no repo file sits next to it, so:
#   * run from a checkout  -> source the file right away and validate MMT_BASE
#                             up front (fail fast, covers --dry-run too);
#   * curl|bash            -> source it from the verified clone after
#                             clone_repo(), before MMT_BASE is ever used.
COMMON_FILE=""   # path of the sourced mmt-install-common.sh, empty until then
ELEVATED=0       # set to 1 when the install step needed privilege escalation

# prefix_writable() and validate_mmt_base() below are local fallbacks: the
# canonical copies live in dist/ZIP/mmt-install-common.sh and overwrite these
# when sourced — tests/installer asserts the two stay byte-identical. Local
# copies are still needed because `curl | bash` has no repo file beside the
# script, --dry-run never reaches the clone, and a clone of the pinned release
# tag predates the common file entirely (v1.8.0 ships no
# dist/ZIP/mmt-install-common.sh — issue #211).
prefix_writable() {
    local p="$1"
    while [ ! -e "$p" ]; do
        p="$(dirname -- "$p")"
    done
    [ -w "$p" ]
}

# Fallback copy of dist/ZIP/mmt-install-common.sh's validator — keep identical
# (the installer suite diffs the two definitions).
validate_mmt_base() {
    local p="$1"
    if [ -z "$p" ] || [ ${#p} -gt 256 ]; then
        echo "ERROR: MMT_BASE must be 1-256 characters" >&2; return 1
    fi
    if [[ "$p" != /* ]]; then
        echo "ERROR: MMT_BASE must be an absolute path: $p" >&2; return 1
    fi
    if [ "$p" = "/" ]; then
        echo "ERROR: MMT_BASE must not be /" >&2; return 1
    fi
    if [[ "$p" == *".."* ]]; then
        echo "ERROR: MMT_BASE must not contain .. : $p" >&2; return 1
    fi
    # Allowlist: path components may only contain [A-Za-z0-9._-] — every
    # metacharacter, whitespace and control character is rejected by
    # construction rather than by an incomplete blacklist.
    if [[ ! "$p" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
        echo "ERROR: MMT_BASE contains characters outside [A-Za-z0-9._/-]: $p" >&2; return 1
    fi
    if [[ "$p" == */ ]]; then
        echo "ERROR: MMT_BASE must not have trailing slash: $p" >&2; return 1
    fi
    # An empty or '.' component would alias another directory (//, /.,
    # /opt/./mmt): uninstall removes paths under the prefix (issue #485).
    if [[ "$p/" == *//* || "$p/" == */./* ]]; then
        echo "ERROR: MMT_BASE must not contain empty or . components: $p" >&2; return 1
    fi
}

load_common_defs() {
    local f="$1"
    [ -f "$f" ] || return 1
    # shellcheck disable=SC1090  # runtime-resolved path, checked just above
    source "$f"
    COMMON_FILE="$f"
}

# Only a script read from a file has a directory. Under `curl | bash` the
# script comes from stdin: BASH_SOURCE[0] is empty and $0 is "bash", whose
# dirname is "." — the caller's working directory, which must never be
# trusted as the installer's checkout (issue #484, F-UX-003).
_INSTALLER_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    _INSTALLER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
fi
if [ -n "$_INSTALLER_DIR" ] && [ -f "$_INSTALLER_DIR/install.sh" ]; then
    load_common_defs "$_INSTALLER_DIR/dist/ZIP/mmt-install-common.sh" || true
fi
# Always validate the prefix up front — the local fallback exists even when no
# common file was sourced, so this also covers `curl | bash -s -- --dry-run`.
validate_mmt_base "$MMT_BASE" || exit 1

# Auto-detect parallelism
if [ -z "${JOBS:-}" ]; then
    if command -v nproc &>/dev/null; then
        JOBS=$(nproc)
    elif command -v sysctl &>/dev/null; then
        JOBS=$(sysctl -n hw.ncpu 2>/dev/null || echo 2)
    else
        JOBS=2
    fi
fi
validate_jobs "$JOBS"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()    { printf "${BLUE}[INFO]${NC}    %s\n" "$*"; }
success() { printf "${GREEN}[OK]${NC}      %s\n" "$*"; }
warn()    { printf "${YELLOW}[WARN]${NC}    %s\n" "$*"; }
error()   { printf "${RED}[ERROR]${NC}   %s\n" "$*" >&2; }
fatal()   { error "$@"; cleanup; exit 1; }
step()    { printf "\n${BOLD}==> %s${NC}\n" "$*"; }


cleanup() {
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
        case "$BUILD_DIR" in
            /tmp/*|/var/tmp/*)
                info "Cleaning up temporary build directory..."
                rm -rf "$BUILD_DIR"
                ;;
            *)
                warn "Skipping cleanup of unexpected BUILD_DIR: $BUILD_DIR"
                ;;
        esac
    fi
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# OS / Architecture Detection
# ---------------------------------------------------------------------------
detect_os() {
    local os
    os="$(uname -s)"
    case "$os" in
        Linux*)  echo "linux" ;;
        Darwin*) fatal "macOS is not currently supported. MMT-DPI only supports Linux." ;;
        CYGWIN*|MINGW*|MSYS*) fatal "Windows is not currently supported. MMT-DPI only supports Linux." ;;
        *)       fatal "Unsupported operating system: $os. MMT-DPI only supports Linux." ;;
    esac
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)  echo "x86_64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l)        echo "armv7" ;;
        *)             echo "$arch" ;;
    esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"

# ---------------------------------------------------------------------------
# Dependency Installation
# ---------------------------------------------------------------------------
check_command() {
    command -v "$1" &>/dev/null
}

# Use sudo only when not running as root
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if check_command sudo; then
        SUDO="sudo"
    else
        warn "Not running as root and sudo not found. Privilege escalation may fail."
    fi
fi

# EL8/EL9 ship libpcap-devel in a repository that is disabled by default —
# CRB (CodeReady Builder) on EL9, PowerTools on EL8 — so the dnf/yum install
# below fails with "No match for argument: libpcap-devel" unless it is enabled
# first. Same logic as tools/ci/install-build-deps.sh (issue #484, F-CI-106);
# Fedora carries the package in its main repository and is left untouched.
enable_el_builder_repo() {
    local pm="$1" ids=""
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091  # runtime file, sourced in a subshell
        ids="$(. /etc/os-release && printf ' %s %s ' "${ID:-}" "${ID_LIKE:-}")"
    fi
    case "$ids" in
        *" rhel "*|*" centos "*) ;;
        *) return 0 ;;
    esac
    info "Enabling the CRB / PowerTools repository (libpcap-devel lives there on EL8/EL9)"
    $SUDO "$pm" install -y dnf-plugins-core || true
    if $SUDO "$pm" config-manager --set-enabled crb 2>/dev/null \
        || $SUDO "$pm" config-manager --set-enabled powertools 2>/dev/null; then
        success "CRB / PowerTools repository enabled"
    else
        warn "Could not enable CRB / PowerTools — on RHEL run:"
        warn "  subscription-manager repos --enable codeready-builder-for-rhel-\$(rpm -E %rhel)-\$(uname -m)-rpms"
    fi
}

install_deps_linux() {
    step "Installing build dependencies (Linux)"

    if check_command apt-get; then
        info "Detected Debian/Ubuntu (apt)"
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq \
            build-essential \
            gcc \
            g++ \
            make \
            git \
            libxml2-dev \
            libpcap-dev \
            libnghttp2-dev
    elif check_command dnf; then
        info "Detected Fedora/RHEL (dnf)"
        enable_el_builder_repo dnf
        $SUDO dnf install -y \
            gcc \
            gcc-c++ \
            make \
            git \
            libxml2-devel \
            libpcap-devel \
            libnghttp2-devel
    elif check_command yum; then
        info "Detected CentOS/RHEL (yum)"
        enable_el_builder_repo yum
        $SUDO yum install -y \
            gcc \
            gcc-c++ \
            make \
            git \
            libxml2-devel \
            libpcap-devel \
            libnghttp2-devel
    elif check_command pacman; then
        info "Detected Arch Linux (pacman)"
        $SUDO pacman -Sy --noconfirm \
            base-devel \
            git \
            libxml2 \
            libpcap \
            nghttp2
    elif check_command apk; then
        info "Detected Alpine Linux (apk)"
        $SUDO apk add --no-cache \
            build-base \
            gcc \
            g++ \
            make \
            git \
            libxml2-dev \
            libpcap-dev \
            nghttp2-dev
    elif check_command zypper; then
        info "Detected openSUSE (zypper)"
        $SUDO zypper install -y \
            gcc \
            gcc-c++ \
            make \
            git \
            libxml2-devel \
            libpcap-devel \
            libnghttp2-devel
    else
        warn "Could not detect package manager. Please install manually:"
        warn "  gcc, g++, make, git, libxml2-dev, libpcap-dev, libnghttp2-dev"
        return 1
    fi

    success "Dependencies installed"
}

install_dependencies() {
    if [ "$SKIP_DEPS" = "1" ]; then
        warn "Skipping dependency installation (SKIP_DEPS=1)"
        return
    fi

    install_deps_linux
}

# ---------------------------------------------------------------------------
# Pre-flight Checks
# ---------------------------------------------------------------------------
preflight_checks() {
    step "Running pre-flight checks"

    local missing=()

    check_command gcc  || missing+=("gcc")
    check_command g++  || check_command c++ || missing+=("g++")
    check_command make || missing+=("make")
    check_command git  || missing+=("git")

    if [ ${#missing[@]} -gt 0 ]; then
        fatal "Missing required tools: ${missing[*]}. Run without SKIP_DEPS=1 or install them manually."
    fi

    success "All required tools found"
    info "OS: $OS | Arch: $ARCH | Jobs: $JOBS | Ref: $REF"
    info "Install prefix: $MMT_BASE"
}

# ---------------------------------------------------------------------------
# Dynamic-loader registration (issue #485, F-CI-104)
# ---------------------------------------------------------------------------
# A root install registers <prefix>/dpi/lib with the dynamic loader, whatever
# the prefix: the same rule as `make -C sdk install` (LDCONF=auto). The
# installer writes the drop-in itself too, because the pinned release tag's
# sdk/Makefile only registered the loader when MMT_BASE was unset — and this
# script always passes it. LDCONF=0 opts out.
LD_DROPIN="/etc/ld.so.conf.d/mmt-dpi.conf"
LD_DROPIN_LEGACY="/etc/ld.so.conf.d/mmt.conf"

# True when the install runs as root: directly, or through sudo because the
# prefix is not writable by this user.
installs_as_root() {
    [ "$(id -u)" -eq 0 ] || ! prefix_writable "$MMT_BASE"
}

will_register_loader() {
    [ "$LDCONF" != "0" ] && [ "$OS" = "linux" ] && installs_as_root
}

# ---------------------------------------------------------------------------
# Uninstall (issue #485, F-UX-007) — mirrors `make -C sdk uninstall`
# ---------------------------------------------------------------------------
# The build checkout is gone after an install, so the installer mirrors
# `make uninstall` itself: it removes exactly the entries listed in
# <prefix>/.mmt-dpi-manifest (written at install time) — never a whole
# directory tree, so another product's files under the prefix survive — then
# every SDK directory left empty (rmdir, deepest first), and the loader
# drop-in when it names this prefix. An install that predates the manifest
# loses only its libmmt_* libraries and plugins; its include and examples
# trees are kept with a warning, since nothing records which files are ours.
MANIFEST_NAME=".mmt-dpi-manifest"
MMT_PLUGIN_SET="libmmt_tcpip libmmt_tmobile libmmt_tdicom libmmt_business_app"

uninstall_mmt() {
    local lib="$MMT_BASE/dpi/lib" run="" f removed=0 rel p r entries rbase
    local manifest="$MMT_BASE/$MANIFEST_NAME"
    step "Uninstalling mmt-dpi from $MMT_BASE"

    # Privilege is needed for a root-owned prefix, or to drop a loader
    # registration that names this prefix from a directory we cannot write.
    if installs_as_root || { [ "$(cat "$LD_DROPIN" 2>/dev/null)" = "$lib" ] \
                             && [ ! -w "$(dirname "$LD_DROPIN")" ]; }; then
        run="$SUDO"
        if [ "$(id -u)" -ne 0 ] && [ -z "$run" ]; then
            fatal "Uninstalling $MMT_BASE needs root and sudo is unavailable — re-run as root"
        fi
    fi

    if [ ! -d "$MMT_BASE/dpi" ] && [ ! -d "$MMT_BASE/plugins" ] && [ ! -d "$MMT_BASE/examples" ]; then
        warn "No MMT-DPI install found under $MMT_BASE"
    fi
    if [ -L "$manifest" ]; then
        fatal "$manifest is a symlink — refusing to uninstall"
    fi
    # Entries are removed only when their directory resolves inside the real
    # prefix: a directory symlink planted under the prefix cannot redirect
    # the removal elsewhere.
    rbase="$(resolve_dir "$MMT_BASE")" || rbase="$MMT_BASE"
    if [ -f "$manifest" ]; then
        entries="$(grep -v '^#' "$manifest" || true)"
    else
        warn "No install manifest ($manifest): the install predates it — removing only the libmmt_* libraries and plugins"
        warn "Kept $MMT_BASE/dpi/include and $MMT_BASE/examples — remove them by hand"
        entries="$( (cd "$lib" 2>/dev/null && ls -d libmmt_*.so libmmt_*.so.* libmmt_*.a 2>/dev/null) | sed 's|^|dpi/lib/|'
                    for f in $MMT_PLUGIN_SET; do echo "plugins/$f.so"; done )"
    fi
    # Refuse the whole list before touching anything if one entry could
    # leave the prefix.
    while IFS= read -r rel; do
        case "$rel" in
            '') ;;
            /*|.|..|./*|../*|*/.|*/..|*/./*|*/../*|*//*|*[!A-Za-z0-9._/+-]*)
                fatal "Unsafe manifest entry '$rel' in $manifest — refusing to uninstall" ;;
        esac
    done <<< "$entries"
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        p="$MMT_BASE/$rel"
        if [ -L "$p" ] || { [ -e "$p" ] && [ ! -d "$p" ]; }; then
            r="$(resolve_dir "${p%/*}")" || r=""
            case "$r" in
                "$rbase"|"$rbase"/*) $run rm -f -- "$p" ;;
                *) warn "Skipped $p — its directory resolves outside $rbase" ;;
            esac
        fi
    done <<< "$entries"
    {
        while IFS= read -r rel; do
            [ -n "$rel" ] && [ -d "$MMT_BASE/$rel" ] && [ ! -L "$MMT_BASE/$rel" ] && echo "$rel"
        done <<< "$entries"
        printf '%s\n' dpi/include examples dpi/lib plugins dpi
    } | LC_ALL=C sort -r -u | while IFS= read -r rel; do
        p="$MMT_BASE/$rel"
        r="$(resolve_dir "$p")" || continue
        case "$r" in "$rbase"|"$rbase"/*) ;; *) continue ;; esac
        if [ ! -L "$p" ]; then
            $run rmdir -- "$p" 2>/dev/null || warn "Kept non-empty $p"
        fi
    done
    $run rm -f -- "$manifest"
    if [ -d "$MMT_BASE" ]; then
        $run rmdir -- "$MMT_BASE" 2>/dev/null || warn "Kept non-empty $MMT_BASE"
    fi

    for f in "$LD_DROPIN" "$LD_DROPIN_LEGACY"; do
        if [ -f "$f" ] && [ "$(cat "$f")" = "$lib" ]; then
            $run rm -f "$f"
            removed=1
            success "Removed loader registration $f"
        fi
    done
    if [ "$removed" = "1" ] && check_command ldconfig; then
        $run ldconfig
    fi

    success "MMT-DPI removed from $MMT_BASE"
}

# ---------------------------------------------------------------------------
# Dry-run plan
# ---------------------------------------------------------------------------
print_plan() {
    step "Install plan (dry run — no changes made)"
    printf "  Repository : %s\n" "$REPO_URL"
    if [ "$REF_KIND" = "tag" ]; then
        printf "  Ref        : %s (release tag)\n" "$REF"
        printf "  Verify     : pinned commit %s; tag signature checked when present\n" "$RELEASE_TAG_SHA"
    else
        printf "  Ref        : %s (moving branch — UNVERIFIED, --unverified-branch given)\n" "$REF"
    fi
    printf "  Prefix     : %s\n" "$MMT_BASE"
    if prefix_writable "$MMT_BASE"; then
        printf "  Elevation  : not needed (prefix writable by this user)\n"
    else
        printf "  Elevation  : sudo (prefix not writable by this user)\n"
    fi
    if will_register_loader; then
        printf "  Loader     : %s + ldconfig (root install)\n" "$LD_DROPIN"
    else
        printf "  Loader     : not registered — run programs with LD_LIBRARY_PATH=%s/dpi/lib\n" "$MMT_BASE"
    fi
    printf "  Jobs       : %s\n" "$JOBS"
    if [ "$SKIP_DEPS" = "1" ]; then
        printf "  Deps       : skipped (SKIP_DEPS=1)\n"
    else
        printf "  Deps       : auto-install via detected package manager\n"
    fi
    printf "  OS / Arch  : %s / %s\n" "$OS" "$ARCH"
    printf "\nRe-run without --dry-run to install.\n"
}

# ---------------------------------------------------------------------------
# Clone & Build
# ---------------------------------------------------------------------------

# Tag-path verification (issue #197, F-SEC-006). Two checks:
#  1. The tag must resolve to the pinned commit — a moved or re-created tag
#     fails here even though `git clone --branch` fetched it happily.
#  2. `git tag -v` verifies the tag signature. An invalid signature is fatal;
#     an unsigned tag warns — upstream release tags are currently unsigned
#     (docs/DECISIONS.md), so the commit pin above is the enforced check and
#     any future signed tag is verified automatically.
verify_release_tag() {
    local repo_dir="$1"
    local actual sig_out sig_rc

    actual="$(git -C "$repo_dir" rev-parse "${RELEASE_TAG}^{commit}" 2>/dev/null || true)"
    if [ "$actual" != "$RELEASE_TAG_SHA" ]; then
        fatal "Release tag $RELEASE_TAG resolved to '${actual:-unknown}', expected $RELEASE_TAG_SHA — the tag may have been moved; refusing to build"
    fi
    success "Release tag $RELEASE_TAG resolves to pinned commit"

    sig_rc=0
    sig_out="$(git -C "$repo_dir" tag -v "$RELEASE_TAG" 2>&1)" || sig_rc=$?
    case "$sig_out" in
        *"BAD signature"*|*"bad signature"*|*"not a valid signature"*)
            fatal "Tag $RELEASE_TAG carries an INVALID GPG signature — refusing to build" ;;
    esac
    if [ "$sig_rc" -eq 0 ]; then
        success "Tag $RELEASE_TAG signature verified"
    else
        warn "Tag $RELEASE_TAG carries no GPG signature — integrity asserted by the pinned commit"
    fi
}

clone_repo() {
    step "Cloning mmt-dpi ($REF)"

    BUILD_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'mmt-dpi')"
    info "Build directory: $BUILD_DIR"

    git clone --depth 1 --branch "$REF" -- "$REPO_URL" "$BUILD_DIR/mmt-dpi"
    success "Repository cloned"

    if [ "$REF_KIND" = "tag" ]; then
        verify_release_tag "$BUILD_DIR/mmt-dpi"
    fi
}

build() {
    step "Building mmt-dpi"

    cd "$BUILD_DIR/mmt-dpi/sdk"

    info "Running: make ARCH=linux MMT_BASE=$MMT_BASE -j$JOBS"
    make ARCH="linux" MMT_BASE="$MMT_BASE" -j"$JOBS"

    success "Build completed"
}

install_mmt() {
    step "Installing mmt-dpi to $MMT_BASE"

    cd "$BUILD_DIR/mmt-dpi/sdk"

    # Elevate by writability, not by a path literal (issue #211, F-BUG-116):
    # /usr/local/mmt needs sudo exactly like /opt/mmt did, while a prefix the
    # user can already write installs unprivileged — and must not trigger the
    # post-install ldconfig escalation.
    if prefix_writable "$MMT_BASE"; then
        info "Installing to user-writable prefix $MMT_BASE"
        make ARCH="linux" MMT_BASE="$MMT_BASE" LDCONF="$LDCONF" install
    else
        if [ -z "$SUDO" ]; then
            fatal "Prefix $MMT_BASE is not writable by this user and sudo is unavailable — set MMT_BASE to a user-writable directory or re-run as root"
        fi
        ELEVATED=1
        info "Prefix $MMT_BASE is not writable — installing via sudo"
        $SUDO make ARCH="linux" MMT_BASE="$MMT_BASE" LDCONF="$LDCONF" install
    fi

    # The pinned release tag's Makefile writes no install manifest: record
    # what it copied from this build so --uninstall can remove exactly that.
    if [ ! -f "$MMT_BASE/$MANIFEST_NAME" ]; then
        local priv=""
        [ "$ELEVATED" = "1" ] && priv="$SUDO"
        write_manifest "$BUILD_DIR/mmt-dpi/sdk" "$priv"
    fi

    success "Installation completed"
}

# write_manifest <sdk dir> [priv] — the same list `make install` records in
# <prefix>/.mmt-dpi-manifest (sdk/Makefile MMT_LIST_INSTALLED): every entry
# copied from <sdk dir>, relative to the prefix.
write_manifest() {
    local sdk="$1" priv="${2:-}" f
    local manifest="$MMT_BASE/$MANIFEST_NAME" tmp
    # Never write through a symlink planted at the manifest name: write a
    # fresh mktemp file and rename it into place.
    if [ -L "$manifest" ]; then
        fatal "$manifest is a symlink — refusing to write the install manifest"
    fi
    tmp="$($priv mktemp "$manifest.XXXXXX")" || fatal "Cannot create a temporary manifest under $MMT_BASE"
    {
        echo "# mmt-dpi install manifest: paths relative to $MMT_BASE, read by make uninstall"
        {
            (cd "$sdk/lib" && ls -d ./*.so.* ./*.a) | sed 's|^\./|dpi/lib/|'
            for f in libmmt_core libmmt_fuzz libmmt_security $MMT_PLUGIN_SET; do
                echo "dpi/lib/$f.so"
            done
            for f in $MMT_PLUGIN_SET; do echo "plugins/$f.so"; done
            (cd "$sdk/include" && find . -mindepth 1) | sed 's|^\./|dpi/include/|'
            (cd "$sdk/examples" && find . -mindepth 1) | sed 's|^\./|examples/|'
        } | LC_ALL=C sort -u
    } | $priv tee "$tmp" >/dev/null
    $priv chmod 0644 "$tmp"
    $priv mv -f -- "$tmp" "$manifest"
}

# resolve_dir <dir> — the physical path of an existing directory (cd -P), so
# symlinked components are resolved; fails when <dir> does not exist.
resolve_dir() {
    (cd -P -- "$1" 2>/dev/null && pwd -P)
}

# ---------------------------------------------------------------------------
# Post-install
# ---------------------------------------------------------------------------
post_install() {
    step "Post-installation setup"

    # Register the loader only when the install ran as root — elevated
    # (ELEVATED = 1) or invoked by root. A user-local prefix never writes to
    # system paths, so ldconfig would be a pointless privilege grab (issue
    # #211, F-BUG-116); a root install always registers (issue #485).
    local lib_dir="$MMT_BASE/dpi/lib"
    local registered=0
    if will_register_loader && check_command ldconfig; then
        local priv=""
        [ "$ELEVATED" = "1" ] && priv="$SUDO"
        if [ "$(cat "$LD_DROPIN" 2>/dev/null)" != "$lib_dir" ]; then
            printf '%s\n' "$lib_dir" | $priv tee "$LD_DROPIN" >/dev/null
            $priv chmod 0644 "$LD_DROPIN"
        fi
        $priv ldconfig
        registered=1
        success "Registered $lib_dir with the dynamic loader ($LD_DROPIN)"
    elif [ "$LDCONF" = "0" ]; then
        info "LDCONF=0: loader not registered — use LD_LIBRARY_PATH=$lib_dir"
    else
        info "User-local install: skipping ldconfig — use LD_LIBRARY_PATH=$lib_dir"
    fi

    # Verify installation
    if [ -f "$lib_dir/libmmt_core.so" ]; then
        success "Libraries found in $lib_dir"
    else
        # Check for versioned .so files
        if ls "$lib_dir"/libmmt_core.so.* &>/dev/null; then
            success "Libraries found in $lib_dir"
        else
            warn "Could not verify library installation in $lib_dir"
        fi
    fi

    # Print summary
    printf "\n"
    printf '%b\n' "${GREEN}${BOLD}============================================${NC}"
    printf '%b\n' "${GREEN}${BOLD}  MMT-DPI installed successfully!${NC}"
    printf '%b\n' "${GREEN}${BOLD}============================================${NC}"
    printf "\n"
    printf "  Libraries:  %s/dpi/lib/\n" "$MMT_BASE"
    printf "  Headers:    %s/dpi/include/\n" "$MMT_BASE"
    printf "  Plugins:    %s/plugins/\n" "$MMT_BASE"
    printf "  Examples:   %s/examples/\n" "$MMT_BASE"
    printf "\n"
    printf '%b\n' "${BOLD}Compile an example:${NC}"
    printf "  gcc -o extract_all %s/examples/extract_all.c \\\\\n" "$MMT_BASE"
    printf "      -I %s/dpi/include -L %s/dpi/lib -lmmt_core -ldl -lpcap\n" "$MMT_BASE" "$MMT_BASE"
    printf "\n"
    if [ "$registered" = "0" ]; then
        printf '%b\n' "${BOLD}Add to your linker path:${NC}"
        printf "  export LD_LIBRARY_PATH=%s/dpi/lib:\$LD_LIBRARY_PATH\n" "$MMT_BASE"
        printf "\n"
    fi
    if [ "$MMT_BASE" = "/opt/mmt" ]; then
        printf "To uninstall:  curl -fsSL %s | bash -s -- --uninstall\n" "$INSTALLER_URL"
    else
        printf "To uninstall:  curl -fsSL %s | bash -s -- --uninstall --prefix %s\n" "$INSTALLER_URL" "$MMT_BASE"
    fi
    printf "\n"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    printf "\n"
    printf '%b\n' "${BOLD}MMT-DPI Installer${NC}"
    printf "Deep Packet Inspection Library by Montimage\n"
    printf "https://github.com/montimage-projects/mmt-dpi\n"
    printf "\n"

    if [ "$UNINSTALL" = "1" ]; then
        if [ "$DRY_RUN" = "1" ]; then
            step "Uninstall plan (dry run — no changes made)"
            printf "  Prefix     : %s (SDK files, then empty directories)\n" "$MMT_BASE"
            printf "  Loader     : %s removed when it names %s/dpi/lib\n" "$LD_DROPIN" "$MMT_BASE"
            return 0
        fi
        uninstall_mmt
        return 0
    fi

    if [ "$DRY_RUN" = "1" ]; then
        print_plan
        return 0
    fi

    if [ "$REF_KIND" = "branch" ]; then
        warn "Building unverified moving ref '$REF' (--unverified-branch):"
        warn "no release tag, signature or commit-pin checks apply."
    fi

    install_dependencies
    preflight_checks
    clone_repo

    # curl|bash path: the shared definitions were not next to this script —
    # take them from the clone (commit-pinned and signature-checked when
    # REF_KIND=tag) when the file exists there. The pinned release tag
    # predates dist/ZIP/mmt-install-common.sh entirely, so a missing file is
    # not fatal — the identical local fallbacks defined above are used.
    if [ -z "$COMMON_FILE" ]; then
        load_common_defs "$BUILD_DIR/mmt-dpi/dist/ZIP/mmt-install-common.sh" || true
    fi
    validate_mmt_base "$MMT_BASE" || exit 1

    build
    install_mmt
    post_install
}

main
