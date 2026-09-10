# Development Guide

## Setting Up the Development Environment

### Prerequisites

The reference toolchain, the package list and the `apt-get` line are maintained
in one place:
[Agent Environment Notes §1 Toolchain Requirements](./AGENT_ENVIRONMENT.md#1-toolchain-requirements).
Development additionally uses Valgrind (optional, for memory-leak runs):

```bash
sudo apt-get install valgrind
```

> **Note:** Only Linux is currently supported. macOS and Windows are not supported.

## Building

### Standard Build

```bash
cd sdk
make -j$(nproc)
sudo make install
```

### Debug Build

```bash
cd sdk
make -j$(nproc) DEBUG=1
```

### Build with Logging

```bash
cd sdk
make -j$(nproc) SHOWLOG=1
```

### Build Options

| Option | Description | Source |
|--------|-------------|--------|
| `DEBUG=1` | `-g` instead of `-O3`; asserts/debug() stay active | `rules/common.mk:87-93` |
| `NDEBUG=1` | Suppress `-DNDEBUG` (keep debug/assert active; default build defines `-DNDEBUG`) | `rules/common.mk:38-43` |
| `SHOWLOG=1` | Show `MMT_LOG()` output (`-DDEBUG -DHTTP_PARSER_STRICT=1`) | `rules/common.mk:159-166` |
| `VALGRIND=1` | Valgrind-friendly instrumentation | `rules/common.mk:94-98` |
| `ENABLESEC=1` | Build `libmmt_security` + `libmmt_fuzz` (needs `libxml2-dev`) | `rules/common.mk:189-191` |
| `BUILD=asan` | AddressSanitizer + UBSan profile | `rules/common.mk:100-127` |
| `BUILD=tsan` | ThreadSanitizer profile | `rules/common.mk:129-157` |
| `VERBOSE=1` | Print full compile commands | `rules/common.mk:21-24` |

Before switching between `BUILD=` profiles, follow the clean rule in
[Agent Environment Notes §5 Sanitizer Build Profiles](./AGENT_ENVIRONMENT.md#5-sanitizer-build-profiles).

<!-- FLAG: unverified — TCP_SEGMENT=1 and STATIC_LINK=1 were previously documented
     but no Makefile rule or code reference was found. -->

## Testing

### Run the Test Suite

```bash
bash tests/run_all_tests.sh
# Subset:   bash tests/run_all_tests.sh hashmap memory
# Sanitizers: SANITIZE=asan bash tests/run_all_tests.sh
# Coverage: bash tests/run_all_tests.sh --coverage
```

> The expected result (suite count, runtime band, exit codes) and the
> `make -C sdk test` trap are stated once, in
> [Agent Environment Notes §3 Testing](./AGENT_ENVIRONMENT.md#3-testing) and
> [§4](./AGENT_ENVIRONMENT.md#4-mmt_base-install-prefix-behavior).

### Test with a Pcap File

```bash
cd src/examples
gcc -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
./extract_all -t /path/to/capture.pcap
```

### Memory Leak Detection

```bash
valgrind --leak-check=full --show-reachable=yes ./your_test_binary -t capture.pcap
```

## Debugging Tips

- Use `DEBUG=1` build flag for assertion checks and verbose output
- Use GDB with debug symbols: `gcc -g -o test test.c ...`
- Check protocol classification with `proto_attributes_iterator` example
- Use Wireshark to compare expected vs. actual protocol classification

## Code Organization

- Protocol implementations go in `src/mmt_tcpip/`, `src/mmt_mobile/`, etc.
- Each protocol has a `proto_<name>.c` file
- Public headers are in `src/mmt_core/public_include/`
- Build rules are in `rules/`

## Creating Packages

### Debian Package

```bash
cd sdk
make deb
```

(`sdk/Makefile:119`)


