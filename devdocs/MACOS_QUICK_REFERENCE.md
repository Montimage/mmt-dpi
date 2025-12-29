# MMT-DPI macOS Quick Reference

## 🚀 Quick Start

### Prerequisites Installation

```bash
# Install Xcode tools
xcode-select --install

# Install dependencies via Homebrew
brew install libxml2 libpcap

# Set environment (Apple Silicon)
export CFLAGS="-I/opt/homebrew/opt/libxml2/include/libxml2 -I/opt/homebrew/opt/libpcap/include"
export LDFLAGS="-L/opt/homebrew/opt/libxml2/lib -L/opt/homebrew/opt/libpcap/lib"

# Set environment (Intel Mac)
export CFLAGS="-I/usr/local/opt/libxml2/include/libxml2 -I/usr/local/opt/libpcap/include"
export LDFLAGS="-L/usr/local/opt/libxml2/lib -L/usr/local/opt/libpcap/lib"
```

### Build Commands

```bash
# Quick build
make libraries

# Debug build
make DEBUG=1 libraries

# Clean and rebuild
rm -rf sdk/lib/*.so* sdk/lib/*.a && make libraries

# Build with security features
make ENABLESEC=1 libraries
```

### Run Example

```bash
# ALWAYS set plugin path first!
export MMT_PLUGINS_PATH=$(pwd)/sdk/lib

# Compile example
clang -o extract_all sdk/examples/extract_all.c \
    -I sdk/include -I sdk/include/tcpip \
    -L sdk/lib -lmmt_core -lpcap -ldl \
    -Wl,-rpath,sdk/lib

# Run example
./extract_all -t sample.pcap
```

## 📋 Linux → macOS Conversion Table

| Task | Linux | macOS |
|------|-------|-------|
| **Compiler** | `gcc` | `clang` |
| **C++ Compiler** | `g++` | `clang++` |
| **Library Extension** | `.so` | `.so` or `.dylib` |
| **Library Path Env** | `LD_LIBRARY_PATH` | `DYLD_LIBRARY_PATH` |
| **Force Load Symbols** | `-Wl,--whole-archive` | `-Wl,-force_load` |
| **No Whole Archive** | `-Wl,--no-whole-archive` | Not needed |
| **Export Dynamic** | `-Wl,--export-dynamic` | `-Wl,-export_dynamic` |
| **Runtime Path** | `-Wl,-rpath,/path` | `-Wl,-rpath,/path` |
| **Check Dependencies** | `ldd library.so` | `otool -L library.so` |
| **Symbol List** | `nm -D library.so` | `nm library.so` |
| **Debug** | `gdb` | `lldb` |

## 🔧 Essential Files to Modify

### 1. `rules/arch-osx.mk`

```makefile
# Key changes needed:
CXX := clang++
CC  := clang

# Force load for static archives
$(QUIET) $(CXX) -shared -o $@ -Wl,-force_load,$^ ...

# Link plugin to core
$(QUIET) $(CXX) -shared -o $@ -Wl,-force_load,$(SDKLIB)/$(LIBTCPIP).a \
    -L$(SDKLIB) -lmmt_core ...
```

### 2. Root `Makefile`

```makefile
ARCH     ?= osx  # Change from linux to osx
TOPDIR   ?= $(realpath $(CURDIR))  # Fix path
```

## 🐛 Troubleshooting Commands

### Check Library Linking

```bash
# Verify TCP/IP plugin links to core
otool -L sdk/lib/libmmt_tcpip.so* | grep libmmt_core

# Check all dependencies
otool -L sdk/lib/*.so*

# List exported symbols
nm -g sdk/lib/libmmt_core.so

# Check undefined symbols
nm -u sdk/lib/libmmt_tcpip.so
```

### Debug Runtime Issues

```bash
# Enable debug output
export MMT_DEBUG=1

# Check architecture
file sdk/lib/*.so*

# Use debugger
lldb ./your_program
(lldb) run
(lldb) bt  # backtrace on crash

# Check if plugin loads
export MMT_PLUGINS_PATH=$(pwd)/sdk/lib
ls -la $MMT_PLUGINS_PATH/libmmt_tcpip.so*
```

## ⚠️ Common Errors & Fixes

### Error: "Unsupported stack type 1"

```bash
# Fix: Set plugin path
export MMT_PLUGINS_PATH=/full/path/to/sdk/lib
```

### Error: Segmentation fault in plugin

```bash
# Fix: Rebuild with proper linking
# Check arch-osx.mk has:
-L$(SDKLIB) -lmmt_core
```

### Error: "Library not loaded"

```bash
# Fix: Use rpath when compiling
clang ... -Wl,-rpath,/path/to/sdk/lib

# Or set DYLD_LIBRARY_PATH
export DYLD_LIBRARY_PATH=/path/to/sdk/lib:$DYLD_LIBRARY_PATH
```

### Error: SIP blocks DYLD_LIBRARY_PATH

```bash
# Fix: Use rpath instead
clang ... -Wl,-rpath,@executable_path/../lib
# Or use absolute path
clang ... -Wl,-rpath,/absolute/path/to/lib
```

## 📦 Installation Paths

### Development (Recommended)

```bash
# Use from build directory
export MMT_PLUGINS_PATH=$(pwd)/sdk/lib
```

### System Installation

```bash
# Standard paths
/opt/mmt/dpi/lib/      # Libraries
/opt/mmt/dpi/include/  # Headers
/opt/mmt/plugins/      # Plugins

# Add to shell profile
echo 'export MMT_PLUGINS_PATH=/opt/mmt/dpi/lib' >> ~/.zshrc
```

## 💻 Sample Code Template

```c
#include <stdio.h>
#include <stdlib.h>
#include <mmt_core.h>
#include <pcap.h>

int main() {
    // CRITICAL: Set plugin path on macOS!
    setenv("MMT_PLUGINS_PATH", "/path/to/sdk/lib", 1);

    // Initialize
    if (!init_extraction()) {
        fprintf(stderr, "Init failed\n");
        return 1;
    }

    // Create handler
    mmt_handler_t *handler = mmt_init_handler(DLT_EN10MB, 0, 0);
    if (!handler) {
        fprintf(stderr, "Handler failed\n");
        close_extraction();
        return 1;
    }

    // Your code here...

    // Cleanup
    mmt_close_handler(handler);
    close_extraction();
    return 0;
}
```

### Compile Template

```bash
clang -o program program.c \
    -I /path/to/sdk/include \
    -L /path/to/sdk/lib \
    -lmmt_core -lpcap \
    -Wl,-rpath,/path/to/sdk/lib
```

## 🔍 Verification Checklist

- [ ] Homebrew dependencies installed (`libxml2`, `libpcap`)
- [ ] Environment variables set (`CFLAGS`, `LDFLAGS`)
- [ ] `arch-osx.mk` uses `clang`/`clang++`
- [ ] `arch-osx.mk` uses `-Wl,-force_load`
- [ ] TCP/IP plugin linked to core (`-lmmt_core`)
- [ ] Root Makefile has `ARCH=osx`
- [ ] `MMT_PLUGINS_PATH` exported before running
- [ ] Programs compiled with `-Wl,-rpath`

## 📚 Key Functions Reference

| Function | Purpose | Returns |
|----------|---------|---------|
| `init_extraction()` | Initialize MMT | 0 on failure |
| `mmt_init_handler(DLT_EN10MB, 0, 0)` | Create Ethernet handler | NULL on failure |
| `register_packet_handler()` | Register callback | - |
| `packet_process()` | Process single packet | 0 on failure |
| `mmt_close_handler()` | Clean up handler | - |
| `close_extraction()` | Clean up MMT | - |

## 🎯 Platform Detection

```c
#ifdef __APPLE__
    // macOS specific code
    setenv("MMT_PLUGINS_PATH", "/opt/mmt/dpi/lib", 1);
#else
    // Linux code
    setenv("MMT_PLUGINS_PATH", "/usr/lib/mmt/plugins", 1);
#endif
```

---
**Version**: 1.0 | **MMT-DPI**: 1.7.10 | **Updated**: September 2025
