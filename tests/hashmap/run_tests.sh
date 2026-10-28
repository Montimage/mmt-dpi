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

# Session-table tests (hash_utils.c) with calloc and malloc failure injection
# via --wrap so the F-BUG-001 resize path and the parked-index growth (issue
# #539) can be driven deterministically. No -D'u_char=...' here: gnu11 keeps
# _DEFAULT_SOURCE so <sys/types.h> already provides u_char, and the macro
# would clash with the typedef.
echo "Compiling session-table tests..."
${CC:-gcc} "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
    -I"$CORE_PRIVATE_INC" \
    -I"$CORE_PUBLIC_INC" \
    -I"$PROJECT_DIR/src/mmt_tcpip/lib" \
    -Wl,--wrap=calloc -Wl,--wrap=malloc \
    -o "$SCRIPT_DIR/test_session_table" \
    "$SCRIPT_DIR/test_session_table.c" \
    "$CORE_SRC/hash_utils.c"

echo "Running session-table tests..."
if "$SCRIPT_DIR/test_session_table"; then
    echo "Session-table tests: PASSED"
else
    echo "Session-table tests: FAILED"
    exit 1
fi

# Issue #551 (F-BUG-011): the table seeds are drawn per process, so two runs
# print different seeds; MMT_DETERMINISTIC_SEED=1 restores the fixed legacy
# sequence (asserted inside the binary), identical across runs.
echo "Checking table seeds across runs..."
seed_run() { # [VAR=value ...]: the seeds one `seed` run prints; fails with it
    local out
    if ! out="$(env -u MMT_DETERMINISTIC_SEED "$@" "$SCRIPT_DIR/test_session_table" seed)"; then
        echo "✗ test_session_table seed failed ($*)" >&2
        return 1
    fi
    printf '%s\n' "$out" | sed -n 's/^table seed: //p'
}
# A failing run (e.g. MMT_DETERMINISTIC_SEED=1 not giving the legacy seeds,
# asserted inside the binary) fails the assignment, so set -e stops here.
seed1="$(seed_run)"
seed2="$(seed_run)"
det1="$(seed_run MMT_DETERMINISTIC_SEED=1)"
det2="$(seed_run MMT_DETERMINISTIC_SEED=1)"
echo "  run 1: ${seed1:-?}"
echo "  run 2: ${seed2:-?}"
echo "  MMT_DETERMINISTIC_SEED=1: ${det1:-?} / ${det2:-?}"
if [ -z "$seed1" ] || [ -z "$seed2" ] || [ "$seed1" = "$seed2" ]; then
    echo "✗ two runs printed the same (or no) table seeds" >&2; exit 1
fi
if [ -z "$det1" ] || [ "$det1" != "$det2" ]; then
    echo "✗ MMT_DETERMINISTIC_SEED=1 runs printed different (or no) table seeds" >&2; exit 1
fi
echo "Table seeds: PASSED (random per run, fixed under MMT_DETERMINISTIC_SEED=1)"

# --- double init_extraction regression (issue #200, F-BUG-005) -------------
# A second init_extraction() in one process used to dereference the global
# protocol-stack map after close_extraction() deleted it without NULLing it.
# The test links the installed SDK (like tests/http_header_case) so it runs
# the real init_extraction()/plugin-registration path; under
# SANITIZE=asan|tsan the SDK is built with the matching profile via
# SDK_BUILD_PROFILE and the use-after-free is caught.
WORK="$(mktemp -d)"
BUILD_LOG="$WORK/build.log"
if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    # tests/run_all_tests.sh built and installed it once (issue #654).
    PREFIX="${MMT_PREFIX:-}"
    trap 'rm -rf "$WORK"' EXIT
    [ -e "$PREFIX/dpi/lib/libmmt_core.so" ] || { echo "✗ MMT_SDK_PREBUILT=1 but MMT_PREFIX='$PREFIX' holds no installed SDK" >&2; exit 1; }
    echo "Reusing the prebuilt SDK for double-init test (MMT_SDK_PREBUILT=1)..."
else
    echo "Building SDK for double-init test..."
    PREFIX="$(mktemp -d)"
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
