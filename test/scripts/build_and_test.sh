#!/bin/bash
set -e

echo "=== Building MMT-DPI ==="
cd sdk
make clean
make -j$(nproc) 2>&1 | tee ../test/build.log

echo "=== Build successful ==="

# Check if libraries were created
if ls lib/libmmt_core.so* 1> /dev/null 2>&1; then
    echo "✓ libmmt_core library created: $(ls lib/libmmt_core.so*)"
else
    echo "✗ libmmt_core library MISSING"
    exit 1
fi

if ls lib/libmmt_tcpip.so* 1> /dev/null 2>&1; then
    echo "✓ libmmt_tcpip library created: $(ls lib/libmmt_tcpip.so*)"
else
    echo "✗ libmmt_tcpip library MISSING"
    exit 1
fi

echo "=== All libraries built successfully ==="
exit 0
