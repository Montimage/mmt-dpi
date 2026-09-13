#!/usr/bin/env bash
#
# MMT-DPI Installation Script
# https://github.com/montimage-projects/mmt-dpi
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
#   wget -qO- https://raw.githubusercontent.com/montimage-projects/mmt-dpi/main/install.sh | bash
#
# By default the installer clones the pinned release tag below and verifies it
# after checkout (commit pin, plus the tag signature when one is present) —
# never a moving branch. See docs/DECISIONS.md for the canonical-organisation
# and verification decisions (issue #197).
#
# Options:
#   --dry-run              - Print the install plan and exit without changes
#   --branch <ref>         - Build a specific branch instead of the release tag
#   --unverified-branch    - Required to permit a moving ref (no verification)
#   -h, --help             - Show usage
#
# Options (via environment variables):
#   MMT_BASE=/custom/path  - Install to a custom directory (default: /opt/mmt)
#   BRANCH=dev             - Same as --branch dev (requires --unverified-branch)
#   JOBS=4                 - Number of parallel build jobs (default: auto-detected)
#   SKIP_DEPS=1            - Skip dependency installation
#
# Examples:
#   curl -sSL https://...install.sh | bash
#   curl -sSL https://...install.sh | bash -s -- --dry-run
#   curl -sSL https://...install.sh | MMT_BASE=/usr/local/mmt bash
#   curl -sSL https://...install.sh | BRANCH=dev bash -s -- --unverified-branch
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Canonical repository — the organisation is declared in docs/DECISIONS.md
# (issue #197). scripts/validate-install-origin.sh fails CI if this constant
# and the README clone URL ever diverge again.
REPO_URL="https://github.com/montimage-projects/mmt-dpi.git"

# Default ref: the pinned release tag, never a moving branch (issue #197,
# F-SEC-006 / F-BUG-118). RELEASE_TAG_SHA pins the commit the tag must resolve
# to, so a moved or re-created tag fails verification right after cloning.
RELEASE_TAG="v1.8.0"
RELEASE_TAG_SHA="af4c3cd7c4d04307411ef17bb16971a0df47f3d1"

BRANCH="${BRANCH:-}"           # opt-in moving ref (env BRANCH or --branch)
UNVERIFIED_BRANCH=0            # set by --unverified-branch
DRY_RUN=0                      # set by --dry-run
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

validate_mmt_base() {
    local p="$1"
    if [ -z "$p" ] || [ ${#p} -gt 256 ]; then
        printf 'ERROR: MMT_BASE must be 1-256 characters\n' >&2; exit 1
    fi
    if [[ "$p" != /* ]]; then
        printf 'ERROR: MMT_BASE must be an absolute path: %s\n' "$p" >&2; exit 1
    fi
    if [ "$p" = "/" ]; then
        printf 'ERROR: MMT_BASE must not be /\n' >&2; exit 1
    fi
    if [[ "$p" == *".."* ]]; then
        printf 'ERROR: MMT_BASE must not contain .. : %s\n' "$p" >&2; exit 1
    fi
    # shellcheck disable=SC1003  # single-quote pattern $'\'' is intentional
    if [[ "$p" == *';'* || "$p" == *'|'* || "$p" == *'&'* || "$p" == *'$'* || "$p" == *'`'* \
        || "$p" == *'!'* || "$p" == *'*'* || "$p" == *'?'* || "$p" == *'<'* || "$p" == *'>'* \
        || "$p" == *'"'* || "$p" == *$'\''* || "$p" == *'\\'* || "$p" == *$'\n'* ]]; then
        printf 'ERROR: MMT_BASE contains shell metacharacters: %s\n' "$p" >&2; exit 1
    fi
    if [[ "$p" == */ ]]; then
        printf 'ERROR: MMT_BASE must not have trailing slash: %s\n' "$p" >&2; exit 1
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

usage() {
    cat <<'EOF'
MMT-DPI Installation Script — https://github.com/montimage-projects/mmt-dpi

Usage:
  bash install.sh [OPTIONS]

Options:
  --dry-run              Print the install plan and exit without changes.
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
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)            DRY_RUN=1 ;;
            --unverified-branch)  UNVERIFIED_BRANCH=1 ;;
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
validate_mmt_base "$MMT_BASE"
validate_skip_deps "$SKIP_DEPS"

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

    if [ "$MMT_BASE" = "/opt/mmt" ] && [ -n "$SUDO" ]; then
        info "Installing to default path (requires sudo)..."
        $SUDO make ARCH="linux" MMT_BASE="$MMT_BASE" install
    else
        info "Installing to $MMT_BASE"
        make ARCH="linux" MMT_BASE="$MMT_BASE" install
    fi

    success "Installation completed"
}

# ---------------------------------------------------------------------------
# Post-install
# ---------------------------------------------------------------------------
post_install() {
    step "Post-installation setup"

    # Refresh shared library cache on Linux
    if [ "$OS" = "linux" ] && check_command ldconfig; then
        $SUDO ldconfig 2>/dev/null || true
    fi

    # Verify installation
    local lib_dir="$MMT_BASE/dpi/lib"
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
    printf '%b\n' "${BOLD}Add to your linker path:${NC}"
    printf "  export LD_LIBRARY_PATH=%s/dpi/lib:\$LD_LIBRARY_PATH\n" "$MMT_BASE"
    printf "\n"
    printf "To uninstall:  cd mmt-dpi/sdk && sudo make dist-clean\n"
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
    build
    install_mmt
    post_install
}

main
