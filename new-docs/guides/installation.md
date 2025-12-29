# Installation Guide

Complete guide for building and installing MMT-DPI on all supported platforms.

## Prerequisites

### All Platforms

| Dependency | Purpose |
|------------|---------|
| GCC or Clang | C/C++ compiler |
| GNU Make | Build system |
| libpcap-dev | Packet capture |
| libxml2-dev | Configuration parsing |
| pthread | Threading support |

### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev libxml2-dev
```

### Linux (RHEL/CentOS/Fedora)

```bash
sudo dnf install gcc gcc-c++ make libpcap-devel libxml2-devel
```

### macOS

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install dependencies via Homebrew
brew install libpcap libxml2
```

**Important:** On macOS, you must use `ARCH=osx` when building (see [Platform-Specific Builds](#platform-specific-builds)).

### Windows (Cross-compilation)

Cross-compile from Linux using MinGW:
```bash
sudo apt-get install mingw-w64
```

## Building from Source

### Clone Repository

```bash
git clone https://github.com/Montimage/mmt-dpi.git
cd mmt-dpi
```

### Standard Build

```bash
cd sdk
make clean
make -j$(nproc)
```

### Verify Build

```bash
# Check libraries were created
ls -la lib/libmmt_core.so
ls -la lib/libmmt_tcpip.so

# Expected output:
# libmmt_core.so -> libmmt_core.so.1.7.10
# libmmt_tcpip.so -> libmmt_tcpip.so.1.7.10
```

## Platform-Specific Builds

### Linux

```bash
cd sdk
make ARCH=linux -j$(nproc)
```

### macOS

```bash
cd sdk
make ARCH=osx -j$(sysctl -n hw.ncpu)
```

**macOS Notes:**
- Uses Clang instead of GCC
- libxml2 path: `/opt/homebrew/opt/libxml2/include/libxml2/` (Apple Silicon)
- libxml2 path: `/usr/local/opt/libxml2/include/libxml2/` (Intel Mac)
- Uses `@rpath` for dynamic library loading
- **CRITICAL:** You must set both `MMT_PLUGINS_PATH` and `DYLD_LIBRARY_PATH` environment variables before running any MMT-DPI application (see [macOS Runtime Environment](#macos-runtime-environment))

### Windows (Cross-compile)

```bash
# 32-bit
make ARCH=win32 -j$(nproc)

# 64-bit
make ARCH=win64 -j$(nproc)
```

## Build Options

| Option | Description | Example |
|--------|-------------|---------|
| `DEBUG=1` | Enable debug symbols | `make DEBUG=1` |
| `VALGRIND=1` | Enable Valgrind support | `make VALGRIND=1` |
| `VERBOSE=1` | Show build commands | `make VERBOSE=1` |
| `NDEBUG=1` | Enable debug logging | `make NDEBUG=1` |

### Debug Build

```bash
make clean
make DEBUG=1 -j$(nproc)
```

### Optimized Build (Default)

```bash
make -j$(nproc)
# Uses -O3 optimization
```

## Installation

### System Installation

```bash
# Install to /opt/mmt (requires root)
cd sdk
sudo make install
```

### Custom Installation Path

```bash
# Install to custom directory
make install MMT_BASE=/path/to/install
```

### Installation Layout

```
/opt/mmt/                    # MMT_BASE
├── dpi/
│   ├── lib/                 # Libraries
│   │   ├── libmmt_core.so
│   │   ├── libmmt_tcpip.so
│   │   └── ...
│   └── include/             # Headers
│       ├── mmt_core.h
│       ├── tcpip/
│       └── ...
├── plugins/                 # Protocol plugins
│   └── libmmt_tcpip.so
└── examples/                # Example programs
```

### Library Path Configuration (Linux)

```bash
# Add to /etc/ld.so.conf.d/mmt-dpi.conf
echo "/opt/mmt/dpi/lib" | sudo tee /etc/ld.so.conf.d/mmt-dpi.conf
sudo ldconfig
```

### macOS Runtime Environment

On macOS, you **must** set both `DYLD_LIBRARY_PATH` and `MMT_PLUGINS_PATH` environment variables before running any MMT-DPI application. Failure to set these will result in a **segmentation fault** at runtime.

```bash
# REQUIRED: Set library path for dynamic linker
export DYLD_LIBRARY_PATH=/opt/mmt/dpi/lib:$DYLD_LIBRARY_PATH

# REQUIRED: Set plugin path for protocol handlers
export MMT_PLUGINS_PATH=/opt/mmt/dpi/lib
```

**For development (using SDK directory):**

```bash
# From project root directory
export DYLD_LIBRARY_PATH=$(pwd)/sdk/lib:$DYLD_LIBRARY_PATH
export MMT_PLUGINS_PATH=$(pwd)/sdk/lib
```

**Single-line execution (alternative):**

```bash
MMT_PLUGINS_PATH=sdk/lib DYLD_LIBRARY_PATH=sdk/lib ./sdk/examples/extract_all -t src/examples/google-fr.pcap
```

**Create a helper script (`setup-env.sh`):**

```bash
#!/bin/bash
# Source this file: source setup-env.sh
export MMT_PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export MMT_SDK_DIR="${MMT_PROJECT_ROOT}/sdk"
export MMT_LIB_DIR="${MMT_SDK_DIR}/lib"
export MMT_PLUGINS_PATH="${MMT_LIB_DIR}"
export DYLD_LIBRARY_PATH="${MMT_LIB_DIR}:${DYLD_LIBRARY_PATH}"
echo "MMT-DPI environment configured for macOS"
```

## Building Examples

```bash
cd src/examples
make
```

### Run Example

**Linux:**
```bash
# Set library path
export LD_LIBRARY_PATH=/path/to/sdk/lib:$LD_LIBRARY_PATH
export MMT_PLUGINS_PATH=/path/to/sdk/lib

# Run example
./sdk/examples/extract_all -t src/examples/google-fr.pcap
```

**macOS:**
```bash
# Set BOTH environment variables (REQUIRED to avoid segfault)
export DYLD_LIBRARY_PATH=/path/to/sdk/lib:$DYLD_LIBRARY_PATH
export MMT_PLUGINS_PATH=/path/to/sdk/lib

# Run example
./sdk/examples/extract_all -t src/examples/google-fr.pcap
```

**Or use single-line execution (macOS):**
```bash
MMT_PLUGINS_PATH=sdk/lib DYLD_LIBRARY_PATH=sdk/lib ./sdk/examples/extract_all -t src/examples/google-fr.pcap
```

## Package Building

### Debian Package

```bash
cd sdk
make deb
# Output: dist/mmt-dpi_*.deb
```

### RPM Package

```bash
cd sdk
make rpm
# Output: dist/mmt-dpi_*.rpm
```

### ZIP Archive

```bash
cd sdk
make zip
# Output: dist/mmt-dpi_*.zip
```

## Running Tests

### Unit Tests

**Linux:**
```bash
cd test/unit

# Build tests
make

# Set environment and run tests
export LD_LIBRARY_PATH=../../sdk/lib:$LD_LIBRARY_PATH
./test_error_handling      # 12 tests
./test_logging             # 14 tests
./test_recovery_debug      # 15 tests
```

**macOS:**
```bash
cd test/unit

# Build tests (compile with rpath)
clang -o test_error_handling test_error_handling.c \
    -I../../sdk/include -L../../sdk/lib -lmmt_core \
    -Wl,-rpath,@loader_path/../../sdk/lib

clang -o test_logging test_logging.c \
    -I../../sdk/include -L../../sdk/lib -lmmt_core \
    -Wl,-rpath,@loader_path/../../sdk/lib

clang -o test_recovery_debug test_recovery_debug.c \
    -I../../sdk/include -L../../sdk/lib -lmmt_core \
    -Wl,-rpath,@loader_path/../../sdk/lib

# Set environment and run tests
export DYLD_LIBRARY_PATH=../../sdk/lib:$DYLD_LIBRARY_PATH
./test_error_handling      # 12 tests
./test_logging             # 14 tests
./test_recovery_debug      # 15 tests
```

### Full Test Suite

```bash
cd test/scripts
./build_and_test.sh
```

## Troubleshooting

### Segmentation Fault on macOS

```
[1]    12345 segmentation fault  ./sdk/examples/extract_all -t file.pcap
```

This occurs when `DYLD_LIBRARY_PATH` or `MMT_PLUGINS_PATH` is not set correctly.

**Solution:**
```bash
# BOTH variables must be set
export DYLD_LIBRARY_PATH=/path/to/sdk/lib:$DYLD_LIBRARY_PATH
export MMT_PLUGINS_PATH=/path/to/sdk/lib

# Then run the application
./sdk/examples/extract_all -t src/examples/google-fr.pcap
```

**Alternative (single-line):**
```bash
MMT_PLUGINS_PATH=sdk/lib DYLD_LIBRARY_PATH=sdk/lib ./sdk/examples/extract_all -t src/examples/google-fr.pcap
```

### Library Not Found

```
error while loading shared libraries: libmmt_core.so: cannot open shared object file
```

**Solution:**
```bash
# Linux
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH
export MMT_PLUGINS_PATH=/opt/mmt/dpi/lib

# macOS
export DYLD_LIBRARY_PATH=/opt/mmt/dpi/lib:$DYLD_LIBRARY_PATH
export MMT_PLUGINS_PATH=/opt/mmt/dpi/lib
```

### libxml2 Not Found (macOS)

```
fatal error: 'libxml/parser.h' file not found
```

**Solution:**
```bash
brew install libxml2
# Ensure CFLAGS includes: -I/opt/homebrew/opt/libxml2/include/libxml2
```

### libpcap Not Found

```
fatal error: pcap.h: No such file or directory
```

**Solution:**
```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# RHEL/CentOS
sudo dnf install libpcap-devel

# macOS
brew install libpcap
```

### Permission Denied (Packet Capture)

```
pcap_open_live: You don't have permission to capture on that device
```

**Solution:**
```bash
# Run with sudo for live capture
sudo ./my_app

# Or set capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin=eip ./my_app
```

## Uninstallation

### Remove System Installation

```bash
cd sdk
sudo make dist-clean
```

### Manual Removal

```bash
sudo rm -rf /opt/mmt
sudo rm -f /etc/ld.so.conf.d/mmt-dpi.conf
sudo ldconfig
```

## Next Steps

- [Development Guide](development.md) - Set up development environment
- [API Reference](../api-reference/README.md) - Learn the API
- [Examples](../architecture/README.md) - See example code
