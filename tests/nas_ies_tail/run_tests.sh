#!/usr/bin/env bash
# run_tests.sh — regression for issue #133: NAS IE fixed-size decoders
# Crafted Attach-Accept/Request tail cases (ielen 0..10 at buffer end) must
# pass without ASan errors (F-BUG-202,203,204,205,206,214,215).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_SRC="${SCRIPT_DIR}/test_nas_ies_tail.c"

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

CC="${CC:-gcc}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    set -- "BUILD=${SDK_BUILD_PROFILE}"
else
    set --
fi

echo "  repo root      : ${REPO_ROOT}"
echo "  install prefix : ${PREFIX}"

echo "  [1/3] building + installing SDK ..."
make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
if ! make -C "${REPO_ROOT}/sdk" "$@" -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
if ! make -C "${REPO_ROOT}/sdk" "$@" MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi

INC="${PREFIX}/dpi/include"
LIB="${PREFIX}/dpi/lib"

SRC_INC=(
    -I "${REPO_ROOT}/src/mmt_mobile"
    -I "${REPO_ROOT}/src/mmt_mobile/nas"
    -I "${REPO_ROOT}/src/mmt_mobile/s1ap"
    -I "${REPO_ROOT}/src/mmt_mobile/asn1c/common"
    -I "${REPO_ROOT}/src/mmt_mobile/asn1c/s1ap"
    -I "${REPO_ROOT}/src/mmt_mobile/asn1c/ngap"
)

echo "  [2/3] compiling test ..."
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
${CC} "${extra_cflags[@]}" -O2 -Wall -o "${SCRIPT_DIR}/test_nas_ies_tail" \
    "${TEST_SRC}" "${SRC_INC[@]}" \
    -I "${INC}" -L "${LIB}" -lmmt_tmobile -lmmt_core

echo "  [3/3] running test ..."
LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}" \
    "${SCRIPT_DIR}/test_nas_ies_tail"

echo
echo "✓ NAS IE fixed-size decoder tail tests passed (issue #133)"
