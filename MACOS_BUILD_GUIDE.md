# MMT-DPI Build and Usage Guide for macOS

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Key Differences from Linux](#key-differences-from-linux)
4. [Build System Configuration](#build-system-configuration)
5. [Compilation](#compilation)
6. [Installation](#installation)
7. [Running Examples](#running-examples)
8. [Troubleshooting](#troubleshooting)
9. [API Usage](#api-usage)

## Overview

MMT-DPI (Montimage Monitoring Tool - Deep Packet Inspector) is a powerful network traffic analysis library. This guide provides complete instructions for building and using MMT-DPI on macOS, with special attention to platform-specific requirements and differences from Linux.

**Version**: 1.7.10  
**Tested on**: macOS with Apple Silicon (M1/M2) and Intel processors  
**Compiler**: Clang (Apple LLVM)

## Prerequisites

### Required Tools and Libraries

#### 1. Xcode Command Line Tools
```bash
xcode-select --install
```

#### 2. Homebrew Package Manager
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### 3. Required Dependencies
```bash
# Install required libraries
brew install libxml2
brew install libpcap
brew install pkg-config  # Optional, but helpful

# For Apple Silicon Macs, libraries are installed in /opt/homebrew
# For Intel Macs, libraries are installed in /usr/local
```

### Environment Setup

Set up environment variables for compilation:

```bash
# For Apple Silicon (M1/M2)
export LIBXML2_DIR=/opt/homebrew/opt/libxml2
export PCAP_DIR=/opt/homebrew/opt/libpcap

# For Intel Macs
export LIBXML2_DIR=/usr/local/opt/libxml2
export PCAP_DIR=/usr/local/opt/libpcap

# Common for both architectures
export CFLAGS="-I${LIBXML2_DIR}/include/libxml2 -I${PCAP_DIR}/include"
export LDFLAGS="-L${LIBXML2_DIR}/lib -L${PCAP_DIR}/lib"
```

## Key Differences from Linux

### 1. Compiler Differences

| Aspect | Linux | macOS |
|--------|-------|-------|
| Default Compiler | GCC | Clang |
| Compiler Command | `gcc` | `clang` |
| C++ Compiler | `g++` | `clang++` |
| Optimization Flags | Full GCC flags supported | Some GCC-specific flags not supported |

### 2. Dynamic Library Differences

| Aspect | Linux | macOS |
|--------|-------|-------|
| Shared Library Extension | `.so` | `.dylib` or `.so` |
| Library Loading | `LD_LIBRARY_PATH` | `DYLD_LIBRARY_PATH` |
| Linker Flag for All Symbols | `-Wl,--whole-archive` | `-Wl,-force_load` |
| Runtime Path | `RPATH` | `@rpath`, `@loader_path` |
| Symbol Export | `-Wl,--export-dynamic` | Automatic or `-Wl,-export_dynamic` |

### 3. Build System Modifications

The following files need macOS-specific modifications:

1. **`rules/arch-osx.mk`** - Main macOS build configuration
2. **`Makefile`** - Top-level makefile must set `ARCH=osx`

## Build System Configuration

### Step 1: Verify/Create arch-osx.mk

Ensure `rules/arch-osx.mk` contains:

```makefile
include $(RULESDIR)/common.mk

CFLAGS   += -D_OSX
CXXFLAGS += -D_OSX

LDFLAGS  += -L$(SDKLIB)

$(CORE_OBJECTS) $(TCPIP_OBJECTS): CFLAGS   += -fPIC
$(CORE_OBJECTS) $(TCPIP_OBJECTS): CXXFLAGS += -fPIC

# Include paths for Homebrew libraries (Apple Silicon)
$(SECURITY_OBJECTS): CFLAGS += -I/opt/homebrew/opt/libxml2/include/libxml2/
$(FUZZ_OBJECTS): CFLAGS += -I/opt/homebrew/opt/libxml2/include/libxml2/

# Libraries
libraries: \
 $(SDKLIB)/$(LIBCORE).so \
 $(SDKLIB)/$(LIBTCPIP).so

# CORE library
$(SDKLIB)/$(LIBCORE).so: $(SDKLIB)/$(LIBCORE).so.$(VERSION)
	@echo "[SYMLINK] $(notdir $@)"
	$(QUIET) ln -sf $(notdir $<) $@

$(SDKLIB)/$(LIBCORE).so.$(VERSION): $(SDKLIB)/$(LIBCORE).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) -shared -o $@ -Wl,-force_load,$^ -Wl,-install_name,@rpath/$(LIBCORE).so.$(VERSION) -Wl,-rpath,@loader_path

# TCP/IP plugin
$(SDKLIB)/$(LIBTCPIP).so: $(SDKLIB)/$(LIBTCPIP).so.$(VERSION)
	@echo "[SYMLINK] $(notdir $@)"
	$(QUIET) ln -sf $(notdir $<) $@

$(SDKLIB)/$(LIBTCPIP).so.$(VERSION): $(SDKLIB)/$(LIBTCPIP).a $(SDKLIB)/$(LIBCORE).so.$(VERSION)
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) -shared -o $@ -Wl,-force_load,$(SDKLIB)/$(LIBTCPIP).a -L$(SDKLIB) -lmmt_core -Wl,-install_name,@rpath/$(LIBTCPIP).so.$(VERSION) -Wl,-rpath,@loader_path

# Use Clang compilers
CXX := clang++
CC  := clang
AR  := ar rcs
```

### Step 2: Create/Update Main Makefile

Create a `Makefile` in the project root:

```makefile
ARCH     ?= osx
TOPDIR   ?= $(realpath $(CURDIR))
RULESDIR := $(TOPDIR)/rules

include $(RULESDIR)/arch-$(ARCH).mk

CFLAGS_osx      := -I$(SDKINC) -I$(SDKINC_TCPIP) -fPIC
CFLAGS += $(CFLAGS_$(ARCH))

LDFLAGS_osx     := -Wl,-export_dynamic
LDFLAGS += $(LDFLAGS_$(ARCH))
```

## Compilation

### Basic Build

```bash
# Navigate to the MMT-DPI directory
cd /path/to/mmt-dpi

# Set environment variables (adjust paths for your system)
export CFLAGS="-I/opt/homebrew/opt/libxml2/include/libxml2 -I/opt/homebrew/opt/libpcap/include"
export LDFLAGS="-L/opt/homebrew/opt/libxml2/lib -L/opt/homebrew/opt/libpcap/lib"

# Build libraries
make libraries

# Build examples (optional)
make examples

# Build tools (optional)
make tools
```

### Build Options

```bash
# Debug build
make DEBUG=1 libraries

# Release build with optimizations
make libraries

# Build with security features
make ENABLESEC=1 libraries

# Clean build
rm -rf sdk/lib/*.so* sdk/lib/*.a
make libraries
```

### Verify Build

After successful compilation, verify the libraries:

```bash
# Check library dependencies
otool -L sdk/lib/libmmt_core.so.1.7.10
otool -L sdk/lib/libmmt_tcpip.so.1.7.10

# Expected output for TCP/IP plugin should show dependency on core:
# @rpath/libmmt_tcpip.so.1.7.10
# @rpath/libmmt_core.so.1.7.10  <-- This is critical!
# /usr/lib/libc++.1.dylib
# /usr/lib/libSystem.B.dylib
```

## Installation

### Option 1: Local Installation (Recommended for Development)

```bash
# The libraries are already in sdk/lib/
# Just set the plugin path environment variable
export MMT_PLUGINS_PATH=/path/to/mmt-dpi/sdk/lib
```

### Option 2: System Installation

```bash
# Create installation directories
sudo mkdir -p /opt/mmt/dpi/lib
sudo mkdir -p /opt/mmt/dpi/include
sudo mkdir -p /opt/mmt/plugins

# Copy libraries
sudo cp -R sdk/lib/* /opt/mmt/dpi/lib/
sudo cp -R sdk/include/* /opt/mmt/dpi/include/

# Set up environment (add to ~/.zshrc or ~/.bash_profile)
echo 'export MMT_PLUGINS_PATH=/opt/mmt/dpi/lib' >> ~/.zshrc
echo 'export DYLD_LIBRARY_PATH=/opt/mmt/dpi/lib:$DYLD_LIBRARY_PATH' >> ~/.zshrc
```

## Running Examples

### Compiling Examples

```bash
# Compile extract_all example
clang -o extract_all sdk/examples/extract_all.c \
    -I sdk/include \
    -I sdk/include/tcpip \
    -I /opt/homebrew/opt/libpcap/include \
    -L sdk/lib \
    -L /opt/homebrew/opt/libpcap/lib \
    -lmmt_core -lpcap -ldl \
    -Wl,-rpath,sdk/lib

# Compile other examples
clang -o proto_attributes_iterator sdk/examples/proto_attributes_iterator.c \
    -I sdk/include \
    -L sdk/lib \
    -lmmt_core \
    -Wl,-rpath,sdk/lib
```

### Running Examples

```bash
# Set plugin path (REQUIRED!)
export MMT_PLUGINS_PATH=/path/to/mmt-dpi/sdk/lib

# Run extract_all with a pcap file
./extract_all -t sample.pcap

# Run on live interface (requires sudo)
sudo ./extract_all -i en0

# Run protocol iterator
./proto_attributes_iterator
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Segmentation Fault When Loading Plugins

**Problem**: Plugin crashes with segmentation fault during initialization.

**Solution**: Ensure the TCP/IP plugin is properly linked against the core library:
```bash
# Check if libmmt_tcpip.so is linked to libmmt_core
otool -L sdk/lib/libmmt_tcpip.so* | grep libmmt_core

# If missing, rebuild with corrected arch-osx.mk
```

#### 2. "Unsupported stack type" Error

**Problem**: Handler initialization fails with "Unsupported stack type 1".

**Solution**: The TCP/IP plugin isn't loading. Check:
- `MMT_PLUGINS_PATH` is set correctly
- Plugin file exists and is readable
- Plugin is properly linked (see issue #1)

#### 3. Library Not Found at Runtime

**Problem**: "Library not loaded" error when running programs.

**Solution**: 
```bash
# Option 1: Set runtime library path
export DYLD_LIBRARY_PATH=/path/to/mmt-dpi/sdk/lib:$DYLD_LIBRARY_PATH

# Option 2: Use install_name_tool to fix paths
install_name_tool -add_rpath /path/to/mmt-dpi/sdk/lib your_program

# Option 3: Link with -rpath during compilation
clang ... -Wl,-rpath,/path/to/mmt-dpi/sdk/lib
```

#### 4. Missing Symbols

**Problem**: "Undefined symbols" during linking.

**Solution**: Ensure you're linking all required libraries:
```bash
-lmmt_core  # Always required
-lpcap      # For pcap file/interface handling
-ldl        # For dynamic loading
-lxml2      # If using security features
```

#### 5. System Integrity Protection (SIP) Issues

**Problem**: DYLD_LIBRARY_PATH is ignored due to SIP.

**Solution**: 
- Use `-rpath` during compilation instead of relying on DYLD_LIBRARY_PATH
- Or disable SIP (not recommended for production)

### Debug Tips

1. **Enable Debug Output**:
```bash
# Compile with debug symbols
make DEBUG=1 libraries

# Run with debugger
lldb ./your_program
(lldb) run
```

2. **Check Plugin Loading**:
```bash
# Set environment variable to see plugin loading
export MMT_DEBUG=1
./your_program
```

3. **Verify Library Architecture**:
```bash
# Ensure libraries match your system architecture
file sdk/lib/*.so*
# Should show either "arm64" for Apple Silicon or "x86_64" for Intel
```

## API Usage

### Basic Example

```c
#include <stdio.h>
#include <stdlib.h>
#include <mmt_core.h>
#include <pcap.h>

int packet_handler(const struct ipacket_struct *ipacket, void *user_args) {
    printf("Packet processed\n");
    return 0;
}

int main() {
    // IMPORTANT: Set plugin path on macOS
    setenv("MMT_PLUGINS_PATH", "/path/to/mmt-dpi/sdk/lib", 1);
    
    // Initialize extraction
    if (init_extraction() == 0) {
        fprintf(stderr, "Failed to initialize\n");
        return 1;
    }
    
    // Create handler for Ethernet
    mmt_handler_t *handler = mmt_init_handler(DLT_EN10MB, 0, 0);
    if (!handler) {
        fprintf(stderr, "Failed to create handler\n");
        close_extraction();
        return 1;
    }
    
    // Register packet callback
    register_packet_handler(handler, 1, packet_handler, NULL);
    
    // Process packets (from pcap or live)
    // ... packet processing code ...
    
    // Cleanup
    mmt_close_handler(handler);
    close_extraction();
    
    return 0;
}
```

### Compilation Command

```bash
clang -o my_program my_program.c \
    -I /path/to/mmt-dpi/sdk/include \
    -L /path/to/mmt-dpi/sdk/lib \
    -lmmt_core -lpcap \
    -Wl,-rpath,/path/to/mmt-dpi/sdk/lib
```

## Platform-Specific Notes

### Apple Silicon (M1/M2) Considerations

1. **Library Paths**: Homebrew installs to `/opt/homebrew` instead of `/usr/local`
2. **Architecture**: Ensure all libraries are built for `arm64`
3. **Rosetta**: Avoid mixing x86_64 and arm64 binaries

### Security and Permissions

1. **Live Capture**: Requires `sudo` for network interface access
2. **Code Signing**: May be required for distribution
3. **Notarization**: Required for distributing outside App Store

### Performance Optimization

```bash
# Compile with optimizations
make CFLAGS="-O3 -march=native" libraries

# For Apple Silicon specific optimizations
make CFLAGS="-O3 -mcpu=apple-m1" libraries
```

## Conclusion

MMT-DPI can be successfully built and run on macOS with the proper configuration. The key differences from Linux are:

1. Use Clang instead of GCC
2. Use `-Wl,-force_load` instead of `-Wl,--whole-archive`
3. Set `MMT_PLUGINS_PATH` environment variable
4. Use `@rpath` and `@loader_path` for dynamic library paths
5. Link TCP/IP plugin explicitly against core library

For support or issues, refer to the troubleshooting section or contact Montimage support.

---
*Document Version: 1.0*  
*Last Updated: September 2025*  
*MMT-DPI Version: 1.7.10*
