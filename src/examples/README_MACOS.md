# MMT-DPI Examples - macOS Compilation Guide

## Overview
All example files in this directory have been updated with macOS-specific compilation and execution instructions. Each file now contains both Linux and macOS commands in its header comments.

## Files Updated
1. **extract_all.c** - Extract all protocol attributes from packets
2. **proto_attributes_iterator.c** - List available protocols and their attributes
3. **packet_handler.c** - Simple packet handler showing packet sizes
4. **MAC_extraction.c** - Extract MAC addresses from packets
5. **attribute_handler_session_counter.c** - Count network sessions
6. **simple_traffic_reporting.c** - Generate traffic reports from pcap files

## General Compilation Pattern

### From MMT-DPI Root Directory
```bash
clang -o <program_name> src/examples/<source_file>.c \
    -I sdk/include \
    -I sdk/include/tcpip \  # If TCP/IP headers needed
    -I /opt/homebrew/opt/libpcap/include \  # If pcap needed
    -L sdk/lib \
    -L /opt/homebrew/opt/libpcap/lib \  # If pcap needed
    -lmmt_core -lpcap -ldl \
    -Wl,-rpath,sdk/lib
```

### If MMT-DPI is Installed in /opt/mmt
```bash
clang -o <program_name> <source_file>.c \
    -I /opt/mmt/dpi/include \
    -I /opt/mmt/dpi/include/tcpip \  # If TCP/IP headers needed
    -L /opt/mmt/dpi/lib \
    -lmmt_core -lpcap -ldl \
    -Wl,-rpath,/opt/mmt/dpi/lib
```

## CRITICAL: Environment Setup Before Running

**Every example requires these environment variables on macOS (set these before running):**
```bash
export MMT_PLUGINS_PATH=/path/to/mmt-dpi/sdk/lib
export DYLD_LIBRARY_PATH=/path/to/mmt-dpi/sdk/lib:$DYLD_LIBRARY_PATH
```

**Why both variables are needed:**
- `MMT_PLUGINS_PATH`: Tells MMT where to find protocol plugins
- `DYLD_LIBRARY_PATH`: Tells macOS where to find dynamic libraries at runtime

Without `MMT_PLUGINS_PATH`, you'll get "Unsupported stack type" errors.  
Without `DYLD_LIBRARY_PATH`, you'll get "Library not loaded" errors.

## Example: Compile and Run extract_all

```bash
# From MMT-DPI root directory
cd /path/to/mmt-dpi

# Compile
clang -o extract_all src/examples/extract_all.c \
    -I sdk/include -I sdk/include/tcpip \
    -I /opt/homebrew/opt/libpcap/include \
    -L sdk/lib -L /opt/homebrew/opt/libpcap/lib \
    -lmmt_core -lpcap -ldl \
    -Wl,-rpath,sdk/lib

# Set environment variables (REQUIRED for macOS!)
export MMT_PLUGINS_PATH=$(pwd)/sdk/lib
export DYLD_LIBRARY_PATH=$(pwd)/sdk/lib:$DYLD_LIBRARY_PATH

# Run with pcap file
./extract_all -t sample.pcap > output.txt

# Run on live interface (requires sudo)
sudo env MMT_PLUGINS_PATH=$MMT_PLUGINS_PATH DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH ./extract_all -i en0
```

## Key Differences from Linux

1. **Compiler**: Use `clang` instead of `gcc`
2. **Library Paths**: 
   - Apple Silicon: Libraries in `/opt/homebrew/`
   - Intel Macs: Libraries in `/usr/local/`
3. **Network Interface**: Use `en0` instead of `eth0`
4. **Runtime Path**: Use `-Wl,-rpath,` to embed library paths
5. **Plugin Loading**: Must set `MMT_PLUGINS_PATH` environment variable

## Troubleshooting

### "Unsupported stack type 1" Error
```bash
# Solution: Set plugin path
export MMT_PLUGINS_PATH=/full/path/to/sdk/lib
```

### "Library not loaded" Error
```bash
# Solution 1: Add rpath when compiling
clang ... -Wl,-rpath,/path/to/sdk/lib

# Solution 2: Set DYLD_LIBRARY_PATH
export DYLD_LIBRARY_PATH=/path/to/sdk/lib:$DYLD_LIBRARY_PATH

# Solution 3: Use both for sudo commands
sudo env MMT_PLUGINS_PATH=/path DYLD_LIBRARY_PATH=/path ./program
```

### Permission Denied for Live Capture
```bash
# Solution: Use sudo
sudo ./your_program -i en0
```

## Quick Test Script

Create a test script `test_examples.sh`:
```bash
#!/bin/bash

# Set environment (REQUIRED for macOS)
export MMT_PLUGINS_PATH=$(pwd)/sdk/lib
export DYLD_LIBRARY_PATH=$(pwd)/sdk/lib:$DYLD_LIBRARY_PATH
export PCAP_FILE="sample.pcap"

# Compile all examples
for file in src/examples/*.c; do
    name=$(basename "$file" .c)
    echo "Compiling $name..."
    clang -o "$name" "$file" \
        -I sdk/include -I sdk/include/tcpip \
        -I /opt/homebrew/opt/libpcap/include \
        -L sdk/lib -L /opt/homebrew/opt/libpcap/lib \
        -lmmt_core -lpcap -ldl \
        -Wl,-rpath,sdk/lib
done

# Test proto_attributes_iterator (no pcap needed)
echo "Testing proto_attributes_iterator..."
./proto_attributes_iterator > proto_test.txt

# Test others with pcap
if [ -f "$PCAP_FILE" ]; then
    echo "Testing extract_all..."
    ./extract_all -t "$PCAP_FILE" | head -20
fi

echo "Done!"
```

## Recent Updates (September 2025)

**Enhanced macOS Support:**
- ✅ Updated `extract_all.c` with comprehensive macOS compilation instructions
- ✅ Fixed pcap timeout issues on macOS (now uses 1-second timeout)
- ✅ Added proper `DYLD_LIBRARY_PATH` setup instructions 
- ✅ Enhanced troubleshooting section with environment variable solutions
- ✅ Updated all example commands to use `env` with `sudo` for proper variable passing

## Notes
- All examples now work correctly on macOS with the fixed TCP/IP plugin
- The compilation commands are embedded in each source file's header
- **IMPORTANT**: Both `MMT_PLUGINS_PATH` and `DYLD_LIBRARY_PATH` must be set on macOS
- For Apple Silicon Macs, ensure all libraries are arm64 architecture
- Use `sudo env VAR1=value VAR2=value ./program` for live capture

---
*Last Updated: September 8, 2025*  
*MMT-DPI Version: 1.7.10*  
*macOS Support: Fully Tested and Working*
