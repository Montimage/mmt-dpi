#!/usr/bin/env bash
#
# MMT-DPI Installation Script
# https://github.com/Montimage/mmt-dpi
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/Montimage/mmt-dpi/main/install.sh | bash
#   wget -qO- https://raw.githubusercontent.com/Montimage/mmt-dpi/main/install.sh | bash
#
# Options (via environment variables):
#   MMT_BASE=/custom/path  - Install to a custom directory (default: /opt/mmt)
#   BRANCH=dev             - Use a specific git branch (default: main)
#   JOBS=4                 - Number of parallel build jobs (default: auto-detected)
#   SKIP_DEPS=1            - Skip dependency installation
#
# Examples:
#   curl -sSL https://...install.sh | bash
#   curl -sSL https://...install.sh | MMT_BASE=/usr/local/mmt bash
#   curl -sSL https://...install.sh | BRANCH=dev bash
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPO_URL="https://github.com/Montimage/mmt-dpi.git"
BRANCH="${BRANCH:-main}"
MMT_BASE="${MMT_BASE:-/opt/mmt}"
SKIP_DEPS="${SKIP_DEPS:-0}"
BUILD_DIR=""

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
        info "Cleaning up temporary build directory..."
        rm -rf "$BUILD_DIR"
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
        Darwin*) echo "macos" ;;
        *)       fatal "Unsupported operating system: $os" ;;
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

install_deps_macos() {
    step "Installing build dependencies (macOS)"

    if ! check_command brew; then
        info "Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi

    info "Installing packages via Homebrew..."
    brew install libxml2 libpcap nghttp2 gcc 2>/dev/null || true

    success "Dependencies installed"
}

install_dependencies() {
    if [ "$SKIP_DEPS" = "1" ]; then
        warn "Skipping dependency installation (SKIP_DEPS=1)"
        return
    fi

    case "$OS" in
        linux) install_deps_linux ;;
        macos) install_deps_macos ;;
    esac
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
    info "OS: $OS | Arch: $ARCH | Jobs: $JOBS | Branch: $BRANCH"
    info "Install prefix: $MMT_BASE"
}

# ---------------------------------------------------------------------------
# Clone & Build
# ---------------------------------------------------------------------------
clone_repo() {
    step "Cloning mmt-dpi ($BRANCH)"

    BUILD_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'mmt-dpi')"
    info "Build directory: $BUILD_DIR"

    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$BUILD_DIR/mmt-dpi"
    success "Repository cloned"
}

build() {
    step "Building mmt-dpi"

    local make_arch
    case "$OS" in
        linux) make_arch="linux" ;;
        macos) make_arch="osx" ;;
    esac

    cd "$BUILD_DIR/mmt-dpi/sdk"

    info "Running: make ARCH=$make_arch MMT_BASE=$MMT_BASE -j$JOBS"
    make ARCH="$make_arch" MMT_BASE="$MMT_BASE" -j"$JOBS"

    success "Build completed"
}

install_mmt() {
    step "Installing mmt-dpi to $MMT_BASE"

    local make_arch
    case "$OS" in
        linux) make_arch="linux" ;;
        macos) make_arch="osx" ;;
    esac

    cd "$BUILD_DIR/mmt-dpi/sdk"

    if [ "$MMT_BASE" = "/opt/mmt" ] && [ -n "$SUDO" ]; then
        info "Installing to default path (requires sudo)..."
        $SUDO make ARCH="$make_arch" MMT_BASE="$MMT_BASE" install
    else
        info "Installing to $MMT_BASE"
        make ARCH="$make_arch" MMT_BASE="$MMT_BASE" install
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
    if [ -f "$lib_dir/libmmt_core.so" ] || [ -f "$lib_dir/libmmt_core.dylib" ]; then
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
    printf "${GREEN}${BOLD}============================================${NC}\n"
    printf "${GREEN}${BOLD}  MMT-DPI installed successfully!${NC}\n"
    printf "${GREEN}${BOLD}============================================${NC}\n"
    printf "\n"
    printf "  Libraries:  %s/dpi/lib/\n" "$MMT_BASE"
    printf "  Headers:    %s/dpi/include/\n" "$MMT_BASE"
    printf "  Plugins:    %s/plugins/\n" "$MMT_BASE"
    printf "  Examples:   %s/examples/\n" "$MMT_BASE"
    printf "\n"
    printf "${BOLD}Compile an example:${NC}\n"
    printf "  gcc -o extract_all %s/examples/extract_all.c \\\\\n" "$MMT_BASE"
    printf "      -I %s/dpi/include -L %s/dpi/lib -lmmt_core -ldl -lpcap\n" "$MMT_BASE" "$MMT_BASE"
    printf "\n"
    printf "${BOLD}Add to your linker path:${NC}\n"
    if [ "$OS" = "linux" ]; then
        printf "  export LD_LIBRARY_PATH=%s/dpi/lib:\$LD_LIBRARY_PATH\n" "$MMT_BASE"
    else
        printf "  export DYLD_LIBRARY_PATH=%s/dpi/lib:\$DYLD_LIBRARY_PATH\n" "$MMT_BASE"
    fi
    printf "\n"
    printf "To uninstall:  cd mmt-dpi/sdk && sudo make dist-clean\n"
    printf "\n"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    printf "\n"
    printf "${BOLD}MMT-DPI Installer${NC}\n"
    printf "Deep Packet Inspection Library by Montimage\n"
    printf "https://github.com/Montimage/mmt-dpi\n"
    printf "\n"

    install_dependencies
    preflight_checks
    clone_repo
    build
    install_mmt
    post_install
}

main "$@"
