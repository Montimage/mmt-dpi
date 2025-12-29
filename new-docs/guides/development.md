# Development Guide

Guide for developing and contributing to MMT-DPI.

## Development Environment Setup

### Required Tools

- GCC 7+ or Clang 10+
- GNU Make 4+
- Git
- libpcap-dev
- libxml2-dev
- Valgrind (for memory testing)
- GDB or LLDB (for debugging)

### Clone and Build

```bash
git clone https://github.com/Montimage/mmt-dpi.git
cd mmt-dpi
cd sdk
make DEBUG=1 -j$(nproc)
```

### Development Build

```bash
# Clean build with debug symbols
make clean
make DEBUG=1 -j$(nproc)
```

## Project Structure

```
mmt-dpi/
├── src/
│   ├── mmt_core/              # Core DPI engine
│   │   ├── public_include/    # Public API headers
│   │   ├── private_include/   # Internal headers
│   │   └── src/               # Implementation
│   ├── mmt_tcpip/             # TCP/IP protocols
│   │   ├── include/           # Protocol headers
│   │   └── lib/protocols/     # Protocol implementations
│   ├── mmt_mobile/            # Mobile protocols
│   └── examples/              # Example programs
├── sdk/                       # Build output
│   ├── lib/                   # Libraries
│   ├── include/               # Headers
│   └── examples/              # Example binaries
├── test/                      # Test suites
│   ├── unit/                  # Unit tests
│   ├── validation/            # Validation tests
│   └── performance/           # Benchmarks
├── rules/                     # Build configuration
│   ├── common.mk              # Shared settings
│   ├── arch-linux.mk          # Linux settings
│   └── arch-osx.mk            # macOS settings
└── docs/                      # Documentation
```

## Building and Testing

### Build Targets

```bash
# Full SDK build
cd sdk && make sdk

# Only libraries
cd sdk && make libraries

# Only examples
cd sdk && make examples

# Clean all
cd sdk && make clean
```

### Running Unit Tests

```bash
cd test/unit

# Build tests
make

# Run individual tests
./test_error_handling      # Error handling framework
./test_logging             # Logging system
./test_recovery_debug      # Recovery and debug tools
./test_safe_headers        # Safe packet access
```

### Running Validation Tests

```bash
cd test/validation
make
./test_validation_framework
```

### Running Performance Benchmarks

```bash
cd test/performance
make
./bench_mempool
./bench_hash_table
```

## Debugging

### GDB Debugging

```bash
# Build with debug symbols
make DEBUG=1

# Run with GDB
gdb ./sdk/examples/extract_all
(gdb) run -t test/pcap_samples/google-fr.pcap
```

### Valgrind Memory Check

```bash
# Build with Valgrind support
make VALGRIND=1

# Run Valgrind
valgrind --leak-check=full ./sdk/examples/extract_all \
    -t test/pcap_samples/google-fr.pcap
```

### Enable Debug Logging

```bash
# Build with debug logs
make SHOWLOG=1

# Or at runtime
export MMT_LOG_LEVEL=4  # DEBUG level
```

## Code Style

### Formatting Guidelines

- Indent: 4 spaces (no tabs)
- Line length: 100 characters max
- Braces: K&R style
- Naming: `snake_case` for functions and variables

### Example Style

```c
/**
 * Parse TCP header and extract attributes.
 *
 * @param packet The packet to parse
 * @param offset Offset to TCP header
 * @return MMT_ERROR_NONE on success, error code on failure
 */
static int parse_tcp_header(const ipacket_t *packet, size_t offset)
{
    // Validate inputs
    MMT_CHECK_NOT_NULL(packet, "packet");

    // Validate bounds
    MMT_VALIDATE_MIN_HEADER(packet, offset, tcp_header_t, PROTO_TCP);

    // Get header pointer safely
    const tcp_header_t *tcp;
    MMT_GET_HEADER_PTR(packet, offset, tcp_header_t, tcp, PROTO_TCP);

    // Extract fields
    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dst_port = ntohs(tcp->dst_port);

    return MMT_ERROR_NONE;
}
```

## Adding New Code

### Adding a Protocol Handler

See [Adding Protocols Guide](adding-protocols.md) for detailed instructions.

### Modifying Core Engine

1. Edit files in `src/mmt_core/`
2. Update public headers in `src/mmt_core/public_include/`
3. Add tests in `test/unit/`
4. Rebuild: `cd sdk && make -j$(nproc)`

### Adding Tests

```c
// test/unit/test_my_feature.c
#include <stdio.h>
#include <assert.h>
#include "mmt_core.h"

static int test_my_function(void) {
    // Arrange
    int input = 42;

    // Act
    int result = my_function(input);

    // Assert
    assert(result == expected_value);

    printf("test_my_function: PASSED\n");
    return 0;
}

int main(void) {
    int failed = 0;

    failed += test_my_function();
    // Add more tests...

    if (failed == 0) {
        printf("\nAll tests passed!\n");
    } else {
        printf("\n%d tests failed!\n", failed);
    }

    return failed;
}
```

## Common Development Tasks

### Rebuild After Changes

```bash
cd sdk
make -j$(nproc)
```

### Run Quick Smoke Test

```bash
./sdk/examples/extract_all -t test/pcap_samples/google-fr.pcap
```

### Check for Memory Leaks

```bash
valgrind --leak-check=full --show-leak-kinds=all \
    ./sdk/examples/extract_all -t test/pcap_samples/google-fr.pcap
```

### Profile Performance

```bash
# Build with profiling
make DEBUG=1

# Run with perf
perf record ./sdk/examples/extract_all_bench -t test/pcap_samples/google-fr.pcap
perf report
```

## Git Workflow

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `hotfix/description` - Urgent fixes

### Commit Messages

```
<type>: <short description>

<detailed description if needed>

Types: feat, fix, docs, refactor, test, perf
```

**Examples:**
```
feat: Add QUIC protocol handler
fix: Correct TCP checksum validation
perf: Optimize hash table lookup
```

## Troubleshooting Development Issues

### Undefined Symbol Errors

```
undefined reference to `mmt_function'
```

**Solution:** Check that the function is exported in the header and the library is linked.

### Segmentation Fault

1. Run with GDB to get backtrace:
   ```bash
   gdb ./my_program
   (gdb) run
   (gdb) bt
   ```

2. Check for:
   - Null pointer dereference
   - Buffer overflow
   - Use after free

### Build Warnings

Always compile with warnings enabled:
```bash
# Warnings are enabled by default (-Wall)
make -j$(nproc)
```

Fix all warnings before committing.

## Resources

- [Architecture Overview](../architecture/README.md)
- [API Reference](../api-reference/README.md)
- [Adding Protocols](adding-protocols.md)
- [Troubleshooting](../troubleshooting/README.md)
