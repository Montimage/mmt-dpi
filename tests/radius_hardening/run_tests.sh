#!/usr/bin/env bash
# run_tests.sh — regression for issue #128: RADIUS parser hardening, run
# against the SHIPPED parser (issue #526, F-TEST-008).
#
# test_radius_hardening.c feeds crafted Ethernet/IPv4/UDP/RADIUS frames
# through the installed SDK (mmt_init_handler + packet_process) and asserts
# the attributes src/mmt_tcpip/lib/protocols/proto_radius.c reports:
#   - len<2 attributes end the TLV walk (F-BUG-102; len 0 used to hang it)
#   - over-long values clamped to the 64-byte attribute buffer
#   - 32-bit attributes shorter than 6 bytes rejected
#   - 3GPP vendor-specific attribute guards
#   - attributes running past the capture never stored
#
# The suite builds and installs the SDK into a throwaway prefix (the
# tests/parser_boundaries pattern), so it discards an existing sdk/ build.
# SDK_BUILD_PROFILE (set by run_all_tests.sh for SANITIZE=asan|tsan and
# --coverage) selects the SDK profile; EXTRA_CFLAGS instruments the test.
#
# Usage: tests/radius_hardening/run_tests.sh
#   MMT_PREFIX=<dir> — install into <dir> instead of a mktemp prefix
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_SRC="${SCRIPT_DIR}/test_radius_hardening.c"
TEST_BIN="${SCRIPT_DIR}/test_radius_hardening"

CC="${CC:-gcc}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"

if [ -z "${MMT_PREFIX:-}" ]; then
    PREFIX="$(mktemp -d)"
    PREFIX_CREATED=1
else
    PREFIX="${MMT_PREFIX}"
fi
WORK="$(mktemp -d)"
BUILD_LOG="${WORK}/build.log"
if [ -n "${PREFIX_CREATED:-}" ]; then
    trap 'rm -rf "${WORK}" "${PREFIX}"' EXIT
else
    trap 'rm -rf "${WORK}"' EXIT
fi

sdk_make_args=()
if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    sdk_make_args=("BUILD=${SDK_BUILD_PROFILE}")
fi

echo "  repo root      : ${REPO_ROOT}"
echo "  install prefix : ${PREFIX}"

# --- [1/3] SDK build+install ------------------------------------------------
if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    # tests/run_all_tests.sh built and installed it once (issue #654).
    [ -e "${PREFIX}/dpi/lib/libmmt_core.so" ] || { echo "✗ MMT_SDK_PREBUILT=1 but MMT_PREFIX='${MMT_PREFIX:-}' holds no installed SDK" >&2; exit 1; }
    echo "  [1/3] reusing the prebuilt SDK (MMT_SDK_PREBUILT=1) ..."
else
    echo "  [1/3] building + installing SDK ..."
    make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
    if ! make -C "${REPO_ROOT}/sdk" "${sdk_make_args[@]}" -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
        echo "✗ SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
    fi
    if ! make -C "${REPO_ROOT}/sdk" "${sdk_make_args[@]}" MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
        echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
    fi
fi
LIB="${PREFIX}/dpi/lib"

# --- [2/3] compile ----------------------------------------------------------
echo "  [2/3] compiling test_radius_hardening ..."
"${CC}" "${extra_cflags[@]}" -O1 -g -Wall -Wextra -std=gnu11 \
    -o "${TEST_BIN}" "${TEST_SRC}" \
    -I"${PREFIX}/dpi/include" \
    -L"${LIB}" -lmmt_tcpip -lmmt_core -ldl -lpcap -lpthread -lm

# --- [3/3] run --------------------------------------------------------------
# The protocol plugins are loaded via dlopen, so under a sanitizer profile
# the runtime must be preloaded (same contract as tests/parser_boundaries).
# `timeout` turns a walk that never terminates (a len-0 attribute accepted)
# into a failure instead of a hung suite.
echo "  [3/3] running test_radius_hardening ..."
env_prefix=()
case "${SDK_BUILD_PROFILE:-}" in
    asan) env_prefix=(LD_PRELOAD="$("${CC}" -print-file-name=libasan.so)") ;;
    tsan) env_prefix=(LD_PRELOAD="$("${CC}" -print-file-name=libtsan.so)") ;;
esac
rc=0
( cd "${PREFIX}" && \
    env "${env_prefix[@]}" \
        ASAN_OPTIONS="detect_leaks=0" \
        UBSAN_OPTIONS="print_stacktrace=1" \
        LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}" \
        timeout 60 "${TEST_BIN}" ) || rc=$?

if [ "${rc}" -eq 0 ]; then
    echo
    echo "✓ RADIUS hardening regression tests passed"
elif [ "${rc}" -eq 124 ]; then
    echo "✗ RADIUS hardening regression tests timed out (TLV walk did not terminate)" >&2
    exit 1
else
    echo "✗ RADIUS hardening regression tests failed (rc=${rc})" >&2
    exit 1
fi
