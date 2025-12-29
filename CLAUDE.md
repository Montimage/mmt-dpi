# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MMT-DPI (Montimage Deep Packet Inspection) is a high-performance C library for real-time network traffic analysis. It extracts data attributes from network packets with support for 200+ protocols.

## Build Commands

```bash
# Build (from project root - auto-detects Linux/macOS)
cd sdk && make -j$(nproc)

# Build with specific architecture
cd sdk && make ARCH=osx     # macOS
cd sdk && make ARCH=linux   # Linux

# Build with debug symbols
cd sdk && make DEBUG=1

# Build with Valgrind support
cd sdk && make VALGRIND=1

# Show build commands (verbose)
cd sdk && make VERBOSE=1

# Clean build artifacts
cd sdk && make clean

# Install to system (default: /opt/mmt)
sudo make install

# Install to custom location
make install MMT_BASE=/path/to/install

# Build distribution packages
cd sdk && make deb   # Debian package
cd sdk && make rpm   # RPM package
cd sdk && make zip   # ZIP archive
```

## Testing

```bash
# Run unit tests (from test/unit directory)
cd test/unit
./test_error_handling      # Error framework tests (12 tests)
./test_logging             # Logging system tests (14 tests)
./test_recovery_debug      # Recovery & debug tests (15 tests)
./test_safe_headers        # Safe packet access tests

# Run validation tests
cd test/validation
./test_validation_framework

# Run performance benchmarks
cd test/performance
./bench_mempool            # Memory pool benchmarks
./bench_hash_table         # Hash table performance

# Full build and test script
cd test/scripts
./build_and_test.sh
```

## Architecture

### Library Structure
- **libmmt_core** - Core DPI engine (packet processing, sessions, memory pool)
- **libmmt_tcpip** - TCP/IP protocol handlers (50+ protocols: HTTP, DNS, TCP, UDP, etc.)
- **libmmt_mobile** - Mobile protocol handlers (GTP, S1AP, NGAP, NAS for LTE/5G)
- **libmmt_fuzz** - Fuzzing engine
- **libmmt_security** - Security features

### Source Layout
```
src/
├── mmt_core/
│   ├── public_include/    # Public API headers (mmt_core.h, mmt_errors.h, etc.)
│   ├── private_include/   # Internal headers
│   └── src/               # Core implementation
├── mmt_tcpip/
│   ├── include/           # Protocol headers
│   └── lib/protocols/     # Protocol implementations (50+ files)
├── mmt_mobile/            # Mobile protocols (S1AP, NGAP, NAS)
└── examples/              # Example programs
```

### Key Files
- `src/mmt_core/src/packet_processing.c` - Main packet processing engine
- `src/mmt_core/public_include/mmt_core.h` - Primary public API
- `src/mmt_core/public_include/mmt_errors.h` - Error handling framework (1000+ codes)
- `src/mmt_core/public_include/mmt_logging.h` - Logging system
- `src/mmt_tcpip/lib/protocols/` - All TCP/IP protocol handlers

### Build Output
```
sdk/
├── lib/                   # Compiled libraries (.so files)
├── include/               # Public headers (copied from source)
│   ├── tcpip/            # TCP/IP protocol headers
│   └── mobile/           # Mobile protocol headers
└── examples/             # Compiled example programs
```

## Development Patterns

### Adding Protocol Handlers
Protocol handlers are in `src/mmt_tcpip/lib/protocols/`. Each protocol typically has:
- Header file with attribute definitions
- Source file with parsing and extraction functions
- Registration in the protocol registry

### Thread Safety
- Protocol registry uses read-write locks
- Session maps use per-protocol locks
- Hot paths remain lock-free for performance

### Safe Coding Macros (required for protocol handlers)
```c
#include "mmt_protocol_validation.h"

// Validate minimum header size before accessing
MMT_VALIDATE_MIN_HEADER(ipacket, offset, header_type, proto_id);

// Safe header pointer extraction
MMT_GET_HEADER_PTR(ipacket, offset, header_type, ptr_var, proto_id);

// Bounds checking
MMT_VALIDATE_RANGE(value, min, max, "field_name", proto_id);
```

### Error Handling
```c
#include "mmt_errors.h"

MMT_CHECK_NOT_NULL(ptr, "description");
MMT_CHECK(condition, error_code, "message");
MMT_RETURN_ERROR(error_code, "message");
```

### Logging
```c
#include "mmt_logging.h"

MMT_LOG_ERROR("Error: %s", msg);
MMT_LOG_WARN("Warning: %d", val);
MMT_LOG_INFO("Info: %s", info);
MMT_LOG_DEBUG_CAT(MMT_LOG_CAT_PACKET, "Details: %s", details);
```

## Platform Notes

### macOS
- Uses Clang (not GCC)
- libxml2 path: `/opt/homebrew/opt/libxml2/include/libxml2/`
- Uses `@rpath` for shared library loading

### Linux
- Uses GCC by default
- Supports GCC, Clang, and ICC compilers
