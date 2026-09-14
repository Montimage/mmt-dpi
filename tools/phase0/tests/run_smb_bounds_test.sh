#!/usr/bin/env bash
#
# run_smb_bounds_test.sh — build the issue #205 SMB regression test against an
# ASan/UBSan-instrumented build of the SDK and run it.
#
# Issue #205 (F-BUG-110, F-BUG-111, F-BUG-112): proto_smb.c trusted the 16-bit
# NT_CREATE filename length (65,535-byte walk with an off-by-one write into an
# unchecked allocation), and get_smb_payload() plus the padding/session
# analysis read up to +81 bytes past the protocol offset with no caplen check.
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/smb_bounds_test.c against it, itself
#      instrumented with -fsanitize=address,undefined, linking libmmt_tcpip
#      directly (the harness calls the protocol entry points in-process).
#   3. Run it. With -fno-sanitize-recover=all any out-of-bounds access aborts
#      with non-zero status; all assertions must also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_smb_bounds_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
WORK="$(mktemp -d)"
BIN="${WORK}/smb_bounds_test"
# The core dlopens protocol plugins from a relative "plugins/" dir first
# (PLUGINS_REPOSITORY) and the repo root has a dangling libmmt_tcpip.so
# symlink there — run from a scratch dir pointing at the ASan prefix.
ln -s "${PREFIX}/plugins" "${WORK}/plugins"
trap 'rm -rf "${WORK}"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling smb_bounds_test (ASan/UBSan)"
# The internal packet struct header is pulled from the source tree (it is not
# part of the installed public include set) — same pattern as
# run_dtls_classify_guard_test.sh.
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/smb_bounds_test.c" \
    -I"${PREFIX}/dpi/include" \
    -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -I"${REPO_ROOT}/src/mmt_core/public_include" \
    -I"${TEST_DIR}" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm

echo "[3/3] running smb_bounds_test under ASan/UBSan"
set +e
ASAN_OPTIONS="detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1" \
LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
    bash -c 'cd "$1" && shift && "$@"' _ "${WORK}" "${BIN}"
rc=$?
set -e

if [ "${rc}" -eq 0 ]; then
    echo "✓ smb bounds (issue #205) test: PASS"
else
    echo "✗ smb bounds (issue #205) test: FAIL (rc=${rc})"
fi
exit "${rc}"
