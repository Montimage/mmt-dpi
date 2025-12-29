# AI Agent Setup Instructions for MMT-DPI

## Overview

MMT-DPI (Montimage Deep Packet Inspection) is a high-performance C library for extracting data attributes from network packets. This document provides step-by-step instructions for an AI agent to perform a complete from-scratch installation and setup.

**Project Version:** 1.7.10
**Supported Platforms:** Linux (Ubuntu/Debian, RHEL/CentOS), macOS (Intel & Apple Silicon)
**Language:** C/C++
**Build System:** GNU Make

---

## Prerequisites

### Required Software

| Software | Linux | macOS | Purpose |
|----------|-------|-------|---------|
| GCC/Clang | gcc, g++ | clang (Xcode) | C/C++ compilation |
| GNU Make | make | make (Xcode) | Build system |
| libxml2 | libxml2-dev | brew install libxml2 | Configuration parsing |
| libpcap | libpcap-dev | brew install libpcap | Packet capture |
| Git | git | git | Version control |

### Optional Software

| Software | Purpose |
|----------|---------|
| cppcheck | Static code analysis |
| clang-format | Code formatting |
| valgrind | Memory profiling (Linux only) |
| pre-commit | Git hooks (pip install) |

---

## Setup Sequence

### 1. System Package Installation

#### Auto-Detection Commands

```bash
# Detect operating system
OS_TYPE=$(uname -s)
echo "Detected OS: $OS_TYPE"

# Detect architecture
ARCH_TYPE=$(uname -m)
echo "Detected Architecture: $ARCH_TYPE"

# Detect available CPU cores
if [ "$OS_TYPE" = "Darwin" ]; then
    CPU_CORES=$(sysctl -n hw.ncpu)
else
    CPU_CORES=$(nproc)
fi
echo "Available CPU cores: $CPU_CORES"
```

#### Linux Installation (Debian/Ubuntu)

```
PERMISSION REQUIRED: Install system packages
Command: sudo apt-get update && sudo apt-get install -y build-essential gcc g++ make git libxml2-dev libpcap-dev
Impact: Installs build tools and development libraries system-wide
Proceed? (yes/no)
```

```bash
# Execute after permission granted
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    gcc \
    g++ \
    make \
    git \
    libxml2-dev \
    libpcap-dev
```

#### Linux Installation (RHEL/CentOS/Fedora)

```
PERMISSION REQUIRED: Install system packages
Command: sudo dnf install -y gcc gcc-c++ make git libxml2-devel libpcap-devel
Impact: Installs build tools and development libraries system-wide
Proceed? (yes/no)
```

```bash
# Execute after permission granted
sudo dnf install -y \
    gcc \
    gcc-c++ \
    make \
    git \
    libxml2-devel \
    libpcap-devel
```

#### macOS Installation

```
PERMISSION REQUIRED: Install Xcode Command Line Tools
Command: xcode-select --install
Impact: Installs Apple's development tools (compiler, make, git)
Proceed? (yes/no)
```

```bash
# Check if Xcode CLT is installed
if ! xcode-select -p &>/dev/null; then
    xcode-select --install
    echo "Please complete the Xcode installation dialog, then re-run this setup"
    exit 1
fi
```

```
PERMISSION REQUIRED: Install Homebrew packages
Command: brew install libxml2 libpcap
Impact: Installs required libraries via Homebrew
Proceed? (yes/no)
```

```bash
# Check if Homebrew is installed
if ! command -v brew &>/dev/null; then
    echo "Homebrew not found. Install from https://brew.sh"
    exit 1
fi

# Install dependencies
brew install libxml2 libpcap
```

#### Verification

```bash
# Verify installations
echo "=== Verifying installations ==="

# Compiler
if command -v gcc &>/dev/null; then
    echo "✓ GCC: $(gcc --version | head -1)"
elif command -v clang &>/dev/null; then
    echo "✓ Clang: $(clang --version | head -1)"
else
    echo "✗ No C compiler found"
    exit 1
fi

# Make
if command -v make &>/dev/null; then
    echo "✓ Make: $(make --version | head -1)"
else
    echo "✗ Make not found"
    exit 1
fi

# libxml2
if [ -f /usr/include/libxml2/libxml/parser.h ] || \
   [ -f /opt/homebrew/opt/libxml2/include/libxml2/libxml/parser.h ] || \
   [ -f /usr/local/opt/libxml2/include/libxml2/libxml/parser.h ]; then
    echo "✓ libxml2 headers found"
else
    echo "✗ libxml2 headers not found"
    exit 1
fi

# libpcap
if [ -f /usr/include/pcap.h ] || \
   [ -f /opt/homebrew/opt/libpcap/include/pcap.h ] || \
   [ -f /usr/local/opt/libpcap/include/pcap.h ]; then
    echo "✓ libpcap headers found"
else
    echo "✗ libpcap headers not found"
    exit 1
fi

echo "=== All prerequisites verified ==="
```

---

### 2. Environment Configuration

#### Auto-Detected Values

```bash
# Project root (auto-detect from git or current directory)
if git rev-parse --show-toplevel &>/dev/null; then
    PROJECT_ROOT=$(git rev-parse --show-toplevel)
else
    PROJECT_ROOT=$(pwd)
fi
echo "Project root: $PROJECT_ROOT"

# OS-specific settings
OS_TYPE=$(uname -s)
if [ "$OS_TYPE" = "Darwin" ]; then
    # macOS
    if [ "$(uname -m)" = "arm64" ]; then
        # Apple Silicon
        HOMEBREW_PREFIX="/opt/homebrew"
    else
        # Intel Mac
        HOMEBREW_PREFIX="/usr/local"
    fi
    LIBXML2_DIR="${HOMEBREW_PREFIX}/opt/libxml2"
    LIBPCAP_DIR="${HOMEBREW_PREFIX}/opt/libpcap"
    LIB_PATH_VAR="DYLD_LIBRARY_PATH"
else
    # Linux
    LIBXML2_DIR="/usr"
    LIBPCAP_DIR="/usr"
    LIB_PATH_VAR="LD_LIBRARY_PATH"
fi
```

#### Environment Variables Setup

```bash
# Create environment setup script
cat > "${PROJECT_ROOT}/setup-env.sh" << 'ENVEOF'
#!/bin/bash
# MMT-DPI Environment Setup
# Source this file: source setup-env.sh

# Project paths
export MMT_PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export MMT_SDK_DIR="${MMT_PROJECT_ROOT}/sdk"
export MMT_LIB_DIR="${MMT_SDK_DIR}/lib"
export MMT_INC_DIR="${MMT_SDK_DIR}/include"

# Plugin path (CRITICAL for runtime)
export MMT_PLUGINS_PATH="${MMT_LIB_DIR}"

# OS-specific library path
OS_TYPE=$(uname -s)
if [ "$OS_TYPE" = "Darwin" ]; then
    export DYLD_LIBRARY_PATH="${MMT_LIB_DIR}:${DYLD_LIBRARY_PATH}"

    # Homebrew paths for macOS
    if [ "$(uname -m)" = "arm64" ]; then
        export LIBXML2_DIR="/opt/homebrew/opt/libxml2"
    else
        export LIBXML2_DIR="/usr/local/opt/libxml2"
    fi
    export CFLAGS="-I${LIBXML2_DIR}/include/libxml2 ${CFLAGS}"
    export LDFLAGS="-L${LIBXML2_DIR}/lib ${LDFLAGS}"
else
    export LD_LIBRARY_PATH="${MMT_LIB_DIR}:${LD_LIBRARY_PATH}"
fi

# Installation paths (for make install)
export MMT_BASE="${MMT_BASE:-/opt/mmt}"
export MMT_DPI="${MMT_BASE}/dpi"

echo "MMT-DPI environment configured:"
echo "  Project: ${MMT_PROJECT_ROOT}"
echo "  Libraries: ${MMT_LIB_DIR}"
echo "  Plugins: ${MMT_PLUGINS_PATH}"
ENVEOF

chmod +x "${PROJECT_ROOT}/setup-env.sh"
echo "Created: ${PROJECT_ROOT}/setup-env.sh"
```

---

### 3. Build Project

#### Clean Build

```bash
# Source environment
source "${PROJECT_ROOT}/setup-env.sh"

# Navigate to SDK directory
cd "${MMT_SDK_DIR}"

# Clean previous build artifacts
make clean 2>/dev/null || true
```

#### Build Libraries

```bash
# Detect CPU cores for parallel build
if [ "$(uname -s)" = "Darwin" ]; then
    JOBS=$(sysctl -n hw.ncpu)
else
    JOBS=$(nproc)
fi

# Build
echo "Building with ${JOBS} parallel jobs..."
make -j${JOBS}
```

#### Verification

```bash
# Verify build artifacts
echo "=== Verifying build ==="

if ls "${MMT_LIB_DIR}"/libmmt_core.so* 1>/dev/null 2>&1; then
    echo "✓ libmmt_core built: $(ls ${MMT_LIB_DIR}/libmmt_core.so* | head -1)"
else
    echo "✗ libmmt_core NOT found"
    exit 1
fi

if ls "${MMT_LIB_DIR}"/libmmt_tcpip.so* 1>/dev/null 2>&1; then
    echo "✓ libmmt_tcpip built: $(ls ${MMT_LIB_DIR}/libmmt_tcpip.so* | head -1)"
else
    echo "✗ libmmt_tcpip NOT found"
    exit 1
fi

# Check library dependencies
echo ""
echo "=== Library dependencies ==="
if [ "$(uname -s)" = "Darwin" ]; then
    otool -L "${MMT_LIB_DIR}"/libmmt_tcpip.so.* 2>/dev/null | head -5
else
    ldd "${MMT_LIB_DIR}"/libmmt_tcpip.so.* 2>/dev/null | head -5
fi

echo ""
echo "=== Build successful ==="
```

---

### 4. System Installation (Optional)

```
PERMISSION REQUIRED: Install libraries to system
Command: sudo make install
Impact: Copies libraries to /opt/mmt and configures system library path
Proceed? (yes/no)
```

```bash
# Only execute after permission granted
cd "${MMT_SDK_DIR}"
sudo make install

# On Linux, update library cache
if [ "$(uname -s)" = "Linux" ]; then
    sudo ldconfig
fi
```

---

### 5. Run Tests

```bash
# Source environment
source "${PROJECT_ROOT}/setup-env.sh"

# Run unit tests
echo "=== Running Unit Tests ==="
cd "${PROJECT_ROOT}/test/unit"

for test in test_*; do
    if [ -x "$test" ] && [ -f "$test" ]; then
        echo "Running $test..."
        ./"$test"
        if [ $? -eq 0 ]; then
            echo "✓ $test passed"
        else
            echo "✗ $test failed"
        fi
    fi
done

# Run example program
echo ""
echo "=== Running Example Program ==="
cd "${PROJECT_ROOT}"

if [ -x "${MMT_SDK_DIR}/examples/extract_all" ]; then
    "${MMT_SDK_DIR}/examples/extract_all" -t src/examples/google-fr.pcap
    echo "✓ Example program executed successfully"
else
    echo "⚠ Example program not found (build examples first)"
fi
```

---

### 6. Install Development Tools (Optional)

```
PERMISSION REQUIRED: Install code quality tools
Command: pip install pre-commit && pre-commit install
Impact: Installs pre-commit hooks for code quality checks
Proceed? (yes/no)
```

```bash
# Only execute after permission granted
cd "${PROJECT_ROOT}"

# Install pre-commit
pip install pre-commit

# Install hooks (may fail if core.hooksPath is set globally)
pre-commit install 2>/dev/null || echo "Note: pre-commit install skipped (custom hooks path)"

# Run all hooks
pre-commit run --all-files
```

---

### 7. Final Verification

```bash
#!/bin/bash
# Complete verification script

echo "=========================================="
echo "MMT-DPI Installation Verification"
echo "=========================================="

# Source environment
source "${PROJECT_ROOT}/setup-env.sh"

# Check 1: Libraries exist
echo ""
echo "[1/5] Checking libraries..."
LIBS_OK=true
for lib in libmmt_core libmmt_tcpip; do
    if ls "${MMT_LIB_DIR}"/${lib}.so* 1>/dev/null 2>&1; then
        echo "  ✓ ${lib} found"
    else
        echo "  ✗ ${lib} NOT found"
        LIBS_OK=false
    fi
done

# Check 2: Headers exist
echo ""
echo "[2/5] Checking headers..."
HEADERS_OK=true
for header in mmt_core.h; do
    if [ -f "${MMT_INC_DIR}/${header}" ]; then
        echo "  ✓ ${header} found"
    else
        echo "  ✗ ${header} NOT found"
        HEADERS_OK=false
    fi
done

# Check 3: Plugin path set
echo ""
echo "[3/5] Checking plugin path..."
if [ -n "${MMT_PLUGINS_PATH}" ] && [ -d "${MMT_PLUGINS_PATH}" ]; then
    echo "  ✓ MMT_PLUGINS_PATH=${MMT_PLUGINS_PATH}"
else
    echo "  ✗ MMT_PLUGINS_PATH not set or invalid"
fi

# Check 4: Library path set
echo ""
echo "[4/5] Checking library path..."
if [ "$(uname -s)" = "Darwin" ]; then
    if echo "${DYLD_LIBRARY_PATH}" | grep -q "${MMT_LIB_DIR}"; then
        echo "  ✓ DYLD_LIBRARY_PATH includes ${MMT_LIB_DIR}"
    else
        echo "  ⚠ DYLD_LIBRARY_PATH may not include library path"
    fi
else
    if echo "${LD_LIBRARY_PATH}" | grep -q "${MMT_LIB_DIR}"; then
        echo "  ✓ LD_LIBRARY_PATH includes ${MMT_LIB_DIR}"
    else
        echo "  ⚠ LD_LIBRARY_PATH may not include library path"
    fi
fi

# Check 5: Example can run
echo ""
echo "[5/5] Testing example program..."
if [ -x "${MMT_SDK_DIR}/examples/extract_all" ]; then
    if "${MMT_SDK_DIR}/examples/extract_all" -t "${PROJECT_ROOT}/src/examples/google-fr.pcap" >/dev/null 2>&1; then
        echo "  ✓ Example program runs successfully"
    else
        echo "  ⚠ Example program failed (check plugin path)"
    fi
else
    echo "  ⚠ Example program not built"
fi

echo ""
echo "=========================================="
if [ "${LIBS_OK}" = true ] && [ "${HEADERS_OK}" = true ]; then
    echo "✓ MMT-DPI installation verified successfully"
    echo "=========================================="
    exit 0
else
    echo "✗ Some components missing - check output above"
    echo "=========================================="
    exit 1
fi
```

---

## Manual Input Summary

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| MMT_BASE | Installation directory | No | /opt/mmt |
| ARCH | Build architecture | No | Auto-detected (linux/osx) |
| DEBUG | Enable debug symbols | No | 0 (disabled) |
| ENABLESEC | Enable security features | No | 0 (disabled) |

---

## Permission Gates

All permission-requiring operations in this document:

- [ ] Install system packages (apt-get/dnf/brew)
- [ ] Install Xcode Command Line Tools (macOS)
- [ ] System installation (`sudo make install`)
- [ ] Update library cache (`sudo ldconfig` on Linux)
- [ ] Install pre-commit hooks

---

## Troubleshooting

### Build Failures

**Problem:** `libxml2/parser.h: No such file or directory`
```bash
# Linux
sudo apt-get install libxml2-dev

# macOS - ensure Homebrew path is set
export CFLAGS="-I/opt/homebrew/opt/libxml2/include/libxml2"
```

**Problem:** `undefined reference to 'pcap_open_live'`
```bash
# Linux
sudo apt-get install libpcap-dev

# macOS
brew install libpcap
```

### Runtime Failures

**Problem:** `error while loading shared libraries: libmmt_core.so`
```bash
# Set library path
export LD_LIBRARY_PATH=/path/to/sdk/lib:$LD_LIBRARY_PATH  # Linux
export DYLD_LIBRARY_PATH=/path/to/sdk/lib:$DYLD_LIBRARY_PATH  # macOS
```

**Problem:** `Unsupported stack type` or protocol not detected
```bash
# Plugin not loading - set plugin path
export MMT_PLUGINS_PATH=/path/to/sdk/lib
```

**Problem:** `Permission denied` when capturing packets
```bash
# Run with sudo for live capture
sudo ./extract_all -i eth0

# Or set capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin=eip ./extract_all
```

---

## Next Steps

After successful setup:

1. **Explore Examples:** See `src/examples/` for usage patterns
2. **Read Documentation:** Check `docs/` and `new-docs/` for guides
3. **Run Benchmarks:** Execute `test/performance/` benchmarks
4. **Develop:** Use `make lint` and `make format` for code quality
5. **Contribute:** Follow pre-commit hooks for consistent code style

---

## Quick Reference Commands

```bash
# Source environment (run in each new terminal)
source setup-env.sh

# Build
cd sdk && make -j$(nproc)

# Clean build
cd sdk && make clean && make -j$(nproc)

# Debug build
cd sdk && make DEBUG=1 -j$(nproc)

# Run linting
make lint

# Format code
make format

# Run tests
make test-unit

# Run pre-commit checks
pre-commit run --all-files
```
