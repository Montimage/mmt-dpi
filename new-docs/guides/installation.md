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
make ARCH=osx -j$(nproc)
```

**macOS Notes:**
- Uses Clang instead of GCC
- libxml2 path: `/opt/homebrew/opt/libxml2/include/libxml2/` (Apple Silicon)
- Uses `@rpath` for dynamic library loading

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

### Library Path Configuration (macOS)

```bash
# Set DYLD_LIBRARY_PATH
export DYLD_LIBRARY_PATH=/opt/mmt/dpi/lib:$DYLD_LIBRARY_PATH
```

## Building Examples

```bash
cd src/examples
make
```

### Run Example

```bash
# Set library path
export LD_LIBRARY_PATH=/path/to/sdk/lib:$LD_LIBRARY_PATH

# Run example
./sdk/examples/extract_all -t test/pcap_samples/google-fr.pcap
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

```bash
cd test/unit

# Build tests
make

# Run tests
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

### Library Not Found

```
error while loading shared libraries: libmmt_core.so: cannot open shared object file
```

**Solution:**
```bash
# Linux
export LD_LIBRARY_PATH=/opt/mmt/dpi/lib:$LD_LIBRARY_PATH

# macOS
export DYLD_LIBRARY_PATH=/opt/mmt/dpi/lib:$DYLD_LIBRARY_PATH
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
