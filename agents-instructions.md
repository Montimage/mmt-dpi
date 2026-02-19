# AI Agent Setup Instructions for MMT-DPI

## Overview

**MMT-DPI** (Montimage Monitoring Toolbox - Deep Packet Inspection) is a high-performance C library for extracting data attributes from network packets, server logs, and structured events. This document provides step-by-step instructions for an AI agent to perform a complete from-scratch setup.

**Repository**: https://github.com/Montimage/mmt-dpi
**License**: Apache 2.0
**Current Version**: 1.7.10

---

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| GCC | 4.9 - 9.x | C/C++ compilation (GCC 10+ has known issues) |
| G++ | 4.9 - 9.x | C++ compilation (std=c++11) |
| GNU Make | 3.81+ | Build system |
| Git | Any recent | Source control |
| CMake | Any recent | Build support |
| libxml2-dev | Any | XML parsing (mandatory) |
| libpcap-dev | Any | Packet capture (for examples) |
| libnghttp2-dev | Any | HTTP/2 support (for mobile protocols) |

---

## Setup Sequence

### 1. System Package Installations

#### Auto-detect the platform first

```bash
OS_TYPE=$(uname -s)
ARCH=$(uname -m)
echo "OS: $OS_TYPE, Architecture: $ARCH"
```

#### Linux (Debian/Ubuntu)

```bash
sudo apt-get update -y
sudo apt-get install -y build-essential gcc g++ make git cmake
sudo apt-get install -y libxml2-dev libpcap-dev libnghttp2-dev
```

#### Linux (RHEL/CentOS/Fedora)

```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y git cmake
sudo dnf install -y libxml2-devel libpcap-devel libnghttp2-devel
```

> **Note:** Only Linux is currently supported. macOS and Windows are not supported.

#### Verification

```bash
gcc --version
g++ --version
make --version
pkg-config --modversion libxml-2.0
```

**Success**: All commands return version information without errors.

---

### 2. Environment Configuration

#### Auto-detectable values

| Value | Detection Command | Used For |
|-------|------------------|----------|
| OS type | `uname -s` | Selecting ARCH build flag |
| CPU count | `nproc` | Parallel compilation |
| Architecture | `uname -m` | Build configuration |
| GCC version | `gcc -dumpversion` | Compatibility check |

#### Build environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ARCH` | `linux` | Build target: `linux`, `linux-clang` |
| `MMT_BASE` | `/opt/mmt` | Installation base directory |
| `DEBUG` | `0` | Set to `1` for debug symbols |
| `ENABLESEC` | `0` | Set to `1` for security/fuzz modules |
| `SHOWLOG` | `0` | Set to `1` for verbose HTTP parser logging |
| `VALGRIND` | `0` | Set to `1` for Valgrind-compatible build |
| `TCP_SEGMENT` | `0` | Set to `1` for TCP reassembly support |
| `VERBOSE` | `0` | Set to `1` to show full compiler commands |

#### GCC version check (critical)

```bash
GCC_MAJOR=$(gcc -dumpversion | cut -d. -f1)
if [ "$GCC_MAJOR" -ge 10 ]; then
    echo "WARNING: GCC $GCC_MAJOR detected. MMT-DPI is tested with GCC 4.9-9.x."
    echo "You may need to add -fcommon to CFLAGS or use an older GCC version."
fi
```

---

### 3. Dependency Installation

Dependencies are system packages (handled in Step 1). No language-specific package manager is used.

#### Verify all dependencies are present

```bash
# Mandatory
ls /usr/include/libxml2/libxml/parser.h 2>/dev/null || echo "MISSING: libxml2-dev"

# For examples
ls /usr/include/pcap/pcap.h 2>/dev/null || echo "MISSING: libpcap-dev"

# For HTTP/2 / mobile protocols
ls /usr/include/nghttp2/nghttp2.h 2>/dev/null || echo "MISSING: libnghttp2-dev"
```

---

### 4. Build from Source

#### 4.1 Clone the repository (if not already present)

```bash
git clone https://github.com/Montimage/mmt-dpi.git
cd mmt-dpi
```

#### 4.2 Verify source integrity

```bash
ls sdk/Makefile && echo "OK: Build system found"
ls src/mmt_core/public_include/mmt_core.h && echo "OK: Core headers found"
```

#### 4.3 Build

**Linux (default GCC):**
```bash
cd sdk
make clean
make -j$(nproc)
```

**With optional security modules:**
```bash
make -j$(nproc) ENABLESEC=1
```

**With debug symbols:**
```bash
make -j$(nproc) DEBUG=1
```

#### 4.4 Verify build

```bash
# Check that libraries were compiled
ls -la src/mmt_core/src/libmmt_core.so* 2>/dev/null && echo "OK: Core library built"
ls -la src/mmt_tcpip/lib/libmmt_tcpip.so* 2>/dev/null && echo "OK: TCP/IP library built"
ls -la src/mmt_mobile/libmmt_tmobile.so* 2>/dev/null && echo "OK: Mobile library built"
```

**Success**: All library `.so` files exist.

---

### 5. Installation

> **PERMISSION REQUIRED**: This step writes to system directories.

#### 5.1 Install to default location (`/opt/mmt`)

```bash
cd sdk
sudo make install
```

#### 5.2 Install to custom location (no sudo needed)

```bash
cd sdk
make install MMT_BASE=$HOME/mmt
```

**Note**: If `MMT_BASE` differs from the value used during compilation, the build system will automatically recompile `plugins_engine.o` to embed the correct plugin path.

#### 5.3 Verify installation

```bash
ls /opt/mmt/dpi/lib/libmmt_core.so && echo "OK: Core library installed"
ls /opt/mmt/dpi/include/mmt_core.h && echo "OK: Headers installed"
ls /opt/mmt/plugins/libmmt_tcpip.so && echo "OK: Plugins installed"
```

#### Installed directory structure

```
/opt/mmt/
├── dpi/
│   ├── lib/           # libmmt_core.so, libmmt_tcpip.so, etc.
│   └── include/       # mmt_core.h, tcpip/, mobile/, business_app/
├── plugins/           # libmmt_tcpip.so, libmmt_tmobile.so, libmmt_business_app.so
└── examples/          # Example source files
```

---

### 6. Library Path Configuration

> **PERMISSION REQUIRED**: This step modifies system configuration.

#### Linux

```bash
# The install target should create this, but verify/create if missing
echo "/opt/mmt/dpi/lib" | sudo tee /etc/ld.so.conf.d/mmt-dpi.conf
sudo ldconfig
```

**Verification:**
```bash
ldconfig -p | grep libmmt
```

**Expected output**: List of `libmmt_*.so` libraries.

---

### 7. Verification Steps

#### 7.1 Run built-in test

```bash
cd sdk
make test
```

This compiles and runs `proto_attributes_iterator`, which lists all registered protocols and attributes.

#### 7.2 Compile and run an example manually

```bash
gcc -o /tmp/test_mmt_extract src/examples/extract_all.c \
    -I /opt/mmt/dpi/include \
    -L /opt/mmt/dpi/lib \
    -lmmt_core -ldl -lpcap

# Test with a pcap file (if available)
/tmp/test_mmt_extract -t path/to/capture.pcap
```

#### 7.3 Verify plugin loading

```bash
gcc -o /tmp/test_mmt_proto src/examples/proto_attributes_iterator.c \
    -I /opt/mmt/dpi/include \
    -L /opt/mmt/dpi/lib \
    -lmmt_core -ldl

/tmp/test_mmt_proto | head -20
```

**Success**: Outputs a list of protocols (e.g., `Protocol id 1 --- Name ETHERNET`).

---

## Configuration Files

### Build system files (reference only - no modifications needed)

| File | Purpose |
|------|---------|
| `sdk/Makefile` | Main build orchestration |
| `rules/common.mk` | Shared compiler flags, version (1.7.10) |
| `rules/common-linux.mk` | Linux-specific flags and library rules |
| `rules/arch-linux-gcc.mk` | GCC toolchain config |
| `rules/arch-linux-clang.mk` | Clang toolchain config |
| `rules/arch-osx.mk` | macOS toolchain config (unsupported) |
| `rules/arch-win32.mk` | Windows 32-bit cross-compilation (unsupported) |
| `rules/arch-win64.mk` | Windows 64-bit cross-compilation (unsupported) |

### Runtime configuration

| Item | Location | Description |
|------|----------|-------------|
| Library path | `/etc/ld.so.conf.d/mmt-dpi.conf` | Linux shared library path |
| Plugin directory | `/opt/mmt/plugins/` | Protocol plugin libraries |
| Fallback plugin dir | `./plugins/` (relative to binary) | Checked first before system path |

---

## Manual Input Summary

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| Installation path | Base directory for installed files | No | `/opt/mmt` |
| Architecture | Build target platform | No | `linux` |
| Security modules | Build fuzz/security libraries | No | Disabled |
| Debug mode | Include debug symbols | No | Disabled |

---

## Permission Gates

Document all steps requiring explicit user permission:

- [ ] **Install system packages** (Step 1) - Requires sudo for apt/dnf
- [ ] **Install libraries to /opt/mmt** (Step 5) - Writes to system directory
- [ ] **Configure /etc/ld.so.conf.d/** (Step 6) - Modifies system library config
- [ ] **Run ldconfig** (Step 6) - Updates system library cache

---

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| `cannot find -lmmt_core` | Library path not configured | Run `sudo ldconfig` or set `LD_LIBRARY_PATH=/opt/mmt/dpi/lib` |
| `libxml/parser.h: No such file` | libxml2-dev not installed | `sudo apt-get install libxml2-dev` |
| `multiple definition of` errors | GCC 10+ default behavior change | Use GCC 9 or compile with `CFLAGS=-fcommon make` |
| `error while loading shared libraries` | Plugin/library not found at runtime | Check `/etc/ld.so.conf.d/mmt-dpi.conf` and run `ldconfig` |
| Build fails on macOS | macOS is not supported | MMT-DPI only supports Linux |
| `undefined reference to nghttp2_*` | libnghttp2-dev missing | `sudo apt-get install libnghttp2-dev` |
| Permission denied during install | Not using sudo | Use `sudo make install` or set custom `MMT_BASE` |
| Test fails with segfault | Library version mismatch | Run `make clean && make` then reinstall |

---

## Next Steps

After successful setup:

1. **Explore examples**: Browse `src/examples/` for usage patterns
2. **Read the API docs**: See `docs/` for handler, session, protocol, and attribute documentation
3. **Add protocol support**: Follow `docs/Add-New-Protocol.md` to implement custom protocols
4. **Build packages**: Use `make deb` (Debian) or `make rpm` (RHEL) for distribution
5. **Run CI locally**: The GitHub Actions workflow in `.github/workflows/c-cpp.yml` shows the full build/test/package pipeline

### Quick reference for linking

```bash
# Minimal (core only)
gcc -o myapp myapp.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl

# With TCP/IP protocol attributes
gcc -o myapp myapp.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -lmmt_tcpip -ldl -lpcap

# With all protocol families
gcc -o myapp myapp.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib \
    -lmmt_core -lmmt_tcpip -ldl -lpcap
```

---

*Generated for AI agent automated setup. For human developers, see [README.md](README.md) and [docs/Compilation-and-Installation-Instructions.md](docs/Compilation-and-Installation-Instructions.md).*
