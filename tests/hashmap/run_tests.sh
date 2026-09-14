#!/bin/bash
# Run hashmap tests
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source paths
CORE_SRC="$PROJECT_DIR/src/mmt_core/src"
CORE_PRIVATE_INC="$PROJECT_DIR/src/mmt_core/private_include"
CORE_PUBLIC_INC="$PROJECT_DIR/src/mmt_core/public_include"

# Compile test
echo "Compiling hashmap tests..."
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
${CC:-gcc} "${extra_cflags[@]}" -Wall -Wextra -std=c11 \
    -D'u_char=unsigned char' \
    -I"$CORE_PRIVATE_INC" \
    -I"$CORE_PUBLIC_INC" \
    -I"$PROJECT_DIR/src/mmt_tcpip/lib" \
    -o "$SCRIPT_DIR/test_hashmap" \
    "$SCRIPT_DIR/test_hashmap.c" \
    "$CORE_SRC/hashmap.c" \
    "$CORE_SRC/memory.c"

# Run tests
echo "Running hashmap tests..."
if "$SCRIPT_DIR/test_hashmap"; then
    echo "Hashmap tests: PASSED"
else
    echo "Hashmap tests: FAILED"
    exit 1
fi

# Session-table tests (hash_utils.cpp): C++ TU with calloc failure injection
# via --wrap so the F-BUG-001 resize path can be driven deterministically.
# No -D'u_char=...' here: g++ predefines _GNU_SOURCE so <sys/types.h> already
# provides u_char, and the macro would clash with the typedef.
echo "Compiling session-table tests..."
${CXX:-g++} "${extra_cflags[@]}" -Wall -Wextra -std=c++11 \
    -I"$CORE_PRIVATE_INC" \
    -I"$CORE_PUBLIC_INC" \
    -I"$PROJECT_DIR/src/mmt_tcpip/lib" \
    -Wl,--wrap=calloc \
    -o "$SCRIPT_DIR/test_session_table" \
    "$SCRIPT_DIR/test_session_table.cpp" \
    "$CORE_SRC/hash_utils.cpp"

echo "Running session-table tests..."
if "$SCRIPT_DIR/test_session_table"; then
    echo "Session-table tests: PASSED"
else
    echo "Session-table tests: FAILED"
    exit 1
fi
