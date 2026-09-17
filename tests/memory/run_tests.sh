#!/bin/bash
# Run memory allocator tests
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source paths
CORE_SRC="$PROJECT_DIR/src/mmt_core/src"
CORE_PRIVATE_INC="$PROJECT_DIR/src/mmt_core/private_include"
CORE_PUBLIC_INC="$PROJECT_DIR/src/mmt_core/public_include"

# Compile test
echo "Compiling memory tests..."
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
${CC:-gcc} "${extra_cflags[@]}" -Wall -Wextra -std=c11 \
    -D'u_char=unsigned char' \
    -I"$CORE_PUBLIC_INC" \
    -I"$CORE_PRIVATE_INC" \
    -o "$SCRIPT_DIR/test_memory" \
    "$SCRIPT_DIR/test_memory.c" \
    "$CORE_SRC/memory.c"

# Run tests
echo "Running memory tests..."
# Issue #255: with the size prefix gone, mmt_malloc(SIZE_MAX) reaches the real
# allocator. Under ASan/TSan that request is an allocation-size-too-big hard
# abort unless allocator_may_return_null=1 — set it (a shared sanitizer-common
# flag) so the oversized-request probes exercise the NULL-return contract they
# assert. No-ops for unsanitized runs.
if ASAN_OPTIONS="allocator_may_return_null=1${ASAN_OPTIONS:+:${ASAN_OPTIONS}}" \
    TSAN_OPTIONS="allocator_may_return_null=1${TSAN_OPTIONS:+:${TSAN_OPTIONS}}" \
    "$SCRIPT_DIR/test_memory"; then
    echo "Memory tests: PASSED"
else
    echo "Memory tests: FAILED"
    exit 1
fi
