#!/usr/bin/env bash
#
# run_ftp_data_session_uaf_test.sh — replay the FTP data-session
# use-after-free reproducer through phase0_classify under ASan/UBSan
# (issue #487, F-BUG-401).
#
# The input is the mutant weekly fuzz run 36412709200 found, committed by
# issue #486 to tools/ci/fuzz/regressions/. On a 226 reply the FTP dissector
# freed the control session's data session while the data flow's
# session_data[] still pointed at it; the flow's next packet read freed
# memory in ftp_session_data_analysis(). The fix resets the data session in
# place, and a flow of the finished transfer detaches itself.
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/phase0_classify.c against it with
#      -fsanitize=address,undefined -fno-sanitize-recover=all.
#   3. Check the reproducer's sha256, replay it, and require exit 0 with no
#      sanitizer report on stderr.
#
# Usage: tools/phase0/tests/run_ftp_data_session_uaf_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
REPRO="${REPO_ROOT}/tools/ci/fuzz/regressions/ftp_multiple_session-seed36412723701.pcap"
REPRO_SHA256="7b292b34abab71ddbfead47ccf47f8f018814d6505cc9eb6e7753e17ff7a4d6d"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

[ -f "${REPRO}" ] || { echo "✗ reproducer missing: ${REPRO}" >&2; exit 2; }
got="$(sha256sum "${REPRO}")"; got="${got%% *}"
[ "${got}" = "${REPRO_SHA256}" ] || { echo "✗ reproducer sha256 ${got} != ${REPRO_SHA256}" >&2; exit 2; }

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling phase0_classify (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${WORK}/phase0_classify" "${REPO_ROOT}/tools/phase0/phase0_classify.c" \
    -I"${PREFIX}/dpi/include" -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap

echo "[3/3] replaying the FTP data-session reproducer under ASan/UBSan"
# cwd = prefix: mmt_init_handler loads plugins/ relative to it.
set +e
( cd "${PREFIX}" && \
  ASAN_OPTIONS="abort_on_error=1:detect_leaks=0" \
  UBSAN_OPTIONS="print_stacktrace=1" \
  LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
  "${WORK}/phase0_classify" "${REPRO}" ) >"${WORK}/out.txt" 2>"${WORK}/err.txt"
rc=$?
set -e

if [ "${rc}" -eq 0 ] && ! grep -qE 'runtime error:|ERROR: [A-Za-z]+Sanitizer' "${WORK}/err.txt" \
        && grep -q '\.ftp$' "${WORK}/out.txt"; then
    echo "✓ FTP data-session use-after-free test: PASS"
    exit 0
fi
echo "✗ FTP data-session use-after-free test: FAIL (rc=${rc})"
sed 's/^/    | /' "${WORK}/err.txt" | head -40
exit 1
