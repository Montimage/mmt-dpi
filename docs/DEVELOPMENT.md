# Development Guide

## Setting Up the Development Environment

### Prerequisites

- GCC 4.9 to 9.x (recommended: GCC 9)
- GNU Make, CMake
- `libxml2-dev`
- `libpcap-dev` (for examples and testing)
- Valgrind (for memory leak detection)

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install build-essential gcc make cmake libxml2-dev libpcap-dev valgrind
```

### macOS

```bash
brew install gcc cmake libxml2 libpcap
```

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

| Option | Description |
|--------|-------------|
| `DEBUG=1` | Enable debug mode |
| `NDEBUG=1` | Show debug messages |
| `SHOWLOG=1` | Show MMT_LOG messages |
| `VALGRIND=1` | Enable Valgrind compatibility |
| `TCP_SEGMENT=1` | Enable TCP segment reassembly |
| `STATIC_LINK=1` | Build with static linking |

## Testing

### Run the Test Suite

```bash
cd sdk
make test
```

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

### ZIP Distribution

```bash
cd sdk
make zip
```
