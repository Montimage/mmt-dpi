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

# --- double init_extraction regression (issue #200, F-BUG-005) -------------
# A second init_extraction() in one process used to dereference the global
# protocol-stack map after close_extraction() deleted it without NULLing it.
# The test links the installed SDK (like tests/http_header_case) so it runs
# the real init_extraction()/plugin-registration path; under
# SANITIZE=asan|tsan the SDK is built with the matching profile via
# SDK_BUILD_PROFILE and the use-after-free is caught.
echo "Building SDK for double-init test..."
PREFIX="$(mktemp -d)"
WORK="$(mktemp -d)"
BUILD_LOG="$WORK/build.log"
trap 'rm -rf "$PREFIX" "$WORK"' EXIT

SDK_MAKE_ARGS=()
if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    SDK_MAKE_ARGS=("BUILD=${SDK_BUILD_PROFILE}")
fi

make -C "$PROJECT_DIR/sdk" clean >/dev/null 2>&1 || true
if ! make -C "$PROJECT_DIR/sdk" "${SDK_MAKE_ARGS[@]}" -j"$(nproc 2>/dev/null || echo 2)" \
        MMT_BASE="$PREFIX" >"$BUILD_LOG" 2>&1; then
    echo "✗ SDK build failed — last lines:" >&2; tail -20 "$BUILD_LOG" >&2; exit 1
fi
if ! make -C "$PROJECT_DIR/sdk" "${SDK_MAKE_ARGS[@]}" MMT_BASE="$PREFIX" install \
        >>"$BUILD_LOG" 2>&1; then
    echo "✗ SDK install failed — last lines:" >&2; tail -20 "$BUILD_LOG" >&2; exit 1
fi

INC="$PREFIX/dpi/include"
LIB="$PREFIX/dpi/lib"
PLUGINS="$PREFIX/plugins"
if [ ! -d "$PLUGINS" ]; then
    echo "✗ plugins dir not found after install: $PLUGINS" >&2; exit 1
fi

echo "Compiling double-init test..."
${CC:-gcc} "${extra_cflags[@]}" -O2 -Wall -o "$SCRIPT_DIR/test_double_init" \
    "$SCRIPT_DIR/test_double_init.c" -I "$INC" -L "$LIB" -lmmt_core -ldl

echo "Running double-init test..."
ln -sfn "$PLUGINS" "$WORK/plugins"
if ( cd "$WORK" && LD_LIBRARY_PATH="$LIB:${LD_LIBRARY_PATH:-}" \
        "$SCRIPT_DIR/test_double_init" ); then
    echo "Double-init test: PASSED"
else
    echo "Double-init test: FAILED"
    exit 1
fi
