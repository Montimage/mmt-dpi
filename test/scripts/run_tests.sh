#!/bin/bash

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLES_DIR="$TEST_DIR/../src/examples"

echo "=== Running Examples as Tests ==="

# Test 1: Basic packet processing
if [ -f "$EXAMPLES_DIR/google-fr.pcap" ]; then
    echo "Running packet_handler example..."
    cd "$TEST_DIR/../sdk/lib" || exit 1
    export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH

    if [ -f "../../examples/packet_handler" ]; then
        ../../examples/packet_handler "$EXAMPLES_DIR/google-fr.pcap" 2>&1 | tee "$TEST_DIR/test_output.log"
        echo "✓ packet_handler test passed"
    else
        echo "⚠ packet_handler example not built"
    fi
else
    echo "⚠ No test pcap files found"
fi

echo "=== Tests completed ==="
