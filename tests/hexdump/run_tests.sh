#!/bin/bash
# Run hexdump tests
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source paths
CORE_SRC="$PROJECT_DIR/src/mmt_core/src"
CORE_PRIVATE_INC="$PROJECT_DIR/src/mmt_core/private_include"
CORE_PUBLIC_INC="$PROJECT_DIR/src/mmt_core/public_include"

# Compile test
echo "Compiling hexdump tests..."
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
${CC:-gcc} "${extra_cflags[@]}" -Wall -Wextra -std=c11 \
    -I"$CORE_PRIVATE_INC" \
    -I"$CORE_PUBLIC_INC" \
    -o "$SCRIPT_DIR/test_hexdump" \
    "$SCRIPT_DIR/test_hexdump.c" \
    "$CORE_SRC/hexdump.c"

# Run tests
echo "Running hexdump tests..."
if "$SCRIPT_DIR/test_hexdump"; then
    echo "Hexdump tests: PASSED"
else
    echo "Hexdump tests: FAILED"
    exit 1
fi
