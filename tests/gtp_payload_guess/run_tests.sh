#!/usr/bin/env bash
#
# run_tests.sh — regression test for GTP-U inner payload-type guessing.
#
# A G-PDU (message type 0xFF) has no next-proto field, so the type of the
# tunneled payload must be inferred from the bytes after the GTP header. The
# test drives crafted Ethernet/IPv4/UDP/GTPv1-U frames through packet_process()
# and asserts which protocol the engine classifies the G-PDU payload as:
# IPv4 PDU -> IP, IPv6 PDU -> IPv6, Ethernet-framed non-IP PDU (TS 29.281)
# -> Ethernet. It pins the outcome, not the guessing mechanism, so a different
# or improved guess stays covered.
#
# Builds+installs the SDK to an isolated prefix, then compiles the test against
# the freshly built libraries.
#
# Usage: tests/gtp_payload_guess/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_SRC="${SCRIPT_DIR}/test_gtp_payload_guess.c"

PREFIX="${MMT_PREFIX:-$(mktemp -d)}"
WORK="$(mktemp -d)"
BUILD_LOG="${WORK}/build.log"
trap 'rm -rf "${WORK}"' EXIT

CC="${CC:-gcc}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

# Optional SDK build profile forwarded by tests/run_all_tests.sh when the
# suites run under SANITIZE=asan|tsan (mirrors BUILD= in rules/common.mk).
SDK_MAKE_ARGS=()
if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    SDK_MAKE_ARGS=("BUILD=${SDK_BUILD_PROFILE}")
fi

echo "  repo root      : ${REPO_ROOT}"
echo "  install prefix : ${PREFIX}"

# --- 1. build + install the SDK to the isolated prefix ---------------------
echo "  [1/3] building + installing SDK ..."
make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
if ! make -C "${REPO_ROOT}/sdk" "${SDK_MAKE_ARGS[@]}" -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
if ! make -C "${REPO_ROOT}/sdk" "${SDK_MAKE_ARGS[@]}" MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi

INC="${PREFIX}/dpi/include"
LIB="${PREFIX}/dpi/lib"
PLUGINS="${PREFIX}/plugins"
if [ ! -d "${PLUGINS}" ]; then
    echo "✗ plugins dir not found after install: ${PLUGINS}" >&2; exit 1
fi

# --- 2. compile the test ---------------------------------------------------
# EXTRA_CFLAGS carries sanitizer/coverage instrumentation requested by
# tests/run_all_tests.sh; the binary stays in the suite dir so gcov data
# (.gcno/.gcda) survives for the coverage report.
echo "  [2/3] compiling test ..."
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
${CC} "${extra_cflags[@]}" -O2 -Wall -o "${SCRIPT_DIR}/test_gtp_payload_guess" \
    "${TEST_SRC}" -I "${INC}" -L "${LIB}" -lmmt_core -ldl

# --- 3. run with CWD-relative plugins/ pointing at the built plugins -------
# GTP is dissected by libmmt_tcpip.so, which mmt_init_handler() only picks up
# once init_extraction() dlopen()s it out of ./plugins.
echo "  [3/3] running test ..."
ln -s "${PLUGINS}" "${WORK}/plugins"
( cd "${WORK}" && LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}" \
    "${SCRIPT_DIR}/test_gtp_payload_guess" )

echo
echo "✓ GTP-U inner payload-type guessing regression tests passed"