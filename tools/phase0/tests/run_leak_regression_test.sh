#!/usr/bin/env bash
#
# run_leak_regression_test.sh — leak-regression gate over the golden pcaps
# (issue #216, F-TEST-008).
#
# Each of the four 1.8.0 leak fixes has a named case, plus a whole-corpus
# teardown case; every case is a separate process so a definite leak is
# attributed to exactly one fix:
#
#   reassembly_drop_skip      reassembly packets on analyzer DROP/SKIP paths
#   embedded_session_offsets  embedded-session proto_headers_offset
#   ftp_context_teardown      FTP protocol context teardown
#   session_evasion_ownership sessions/hashmap/evasion-handler ownership
#   golden_corpus_teardown    fresh handler per capture over the CI corpus
#
# Oracle selection (the gate fails on ANY definite leak):
#   - the aggregate runner (tools/phase0/run_all_harnesses.sh) groups this
#     harness by its BUILD=asan marker and hands it a shared ASan SDK build
#     (MMT_SDK_PREBUILT=1) -> leak check via ASan detect_leaks=1 (LSan).
#   - standalone with valgrind available -> default SDK build under
#     valgrind --errors-for-leak-kinds=definite --error-exitcode=42.
#   - standalone without valgrind (e.g. the CI harness-matrix job) ->
#     BUILD=asan SDK + ASAN_OPTIONS=detect_leaks=1.
#
# Usage: tools/phase0/tests/run_leak_regression_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE0_DIR="$(cd "${TEST_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PHASE0_DIR}/../.." && pwd)"
PCAP_DIR="${PHASE0_DIR}/ci/pcaps"
GOLDEN_LIST="${PHASE0_DIR}/ci/golden_pcaps.txt"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"; [ -n "${MMT_LEAK_PREFIX:-}" ] || rm -rf "${PREFIX:-}"' EXIT

JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

# --- oracle selection --------------------------------------------------------
MODE=""
if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    MODE="asan"   # the shared prebuilt prefix is an ASan build (see header)
elif command -v valgrind >/dev/null 2>&1; then
    MODE="valgrind"
else
    MODE="asan"
fi
echo "[0/3] leak oracle: ${MODE}"

# --- build -------------------------------------------------------------------
if [ "${MODE}" = "valgrind" ]; then
    PREFIX="${MMT_LEAK_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/leak.XXXXXX")}"
    echo "[1/3] building + installing SDK (default) -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" -j"${JOBS}" >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >/dev/null
    BIN="${WORK}/leak_regression_test"
    echo "[2/3] compiling leak_regression_test"
    gcc -g -O1 -std=gnu11 -o "${BIN}" "${TEST_DIR}/leak_regression_test.c" \
        -I"${PREFIX}/dpi/include" \
        -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap -lpthread -lm
else
    PREFIX="${MMT_LEAK_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/leak.XXXXXX")}"
    if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
        echo "[1/3] reusing prebuilt ASan SDK at ${PREFIX}"
    else
        echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
        make -C "${REPO_ROOT}/sdk" clean >/dev/null
        make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"${JOBS}" >/dev/null
        make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
    fi
    BIN="${WORK}/leak_regression_test"
    echo "[2/3] compiling leak_regression_test (ASan)"
    gcc -g -O1 -std=gnu11 -fsanitize=address -fno-sanitize-recover=all \
        -o "${BIN}" "${TEST_DIR}/leak_regression_test.c" \
        -I"${PREFIX}/dpi/include" \
        -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap -lpthread -lm
    # Force LSan on regardless of caller ASAN_OPTIONS (the suite runner and
    # project policy default to detect_leaks=0; this harness exists to leak).
    ASAN_BASE="$(printf '%s' "${ASAN_OPTIONS:-}" | tr ':' '\n' | grep -v '^detect_leaks=' | paste -sd: - || true)"
    export ASAN_OPTIONS="${ASAN_BASE}${ASAN_BASE:+:}detect_leaks=1"
fi

export LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}"

# --- case -> pcap sets ---------------------------------------------------------
pcap_list() { # shell glob -> absolute paths that exist
    local out="" f
    for f in "$@"; do
        [ -f "${PCAP_DIR}/${f}" ] && out="${out} ${PCAP_DIR}/${f}"
    done
    printf '%s' "${out# }"
}

ALL_PCAS="$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "${GOLDEN_LIST}" \
            | while read -r p; do echo "${PCAP_DIR}/${p}"; done | tr '\n' ' ')"
TCP_PCAS="$(pcap_list tcp_bbc-out-of-order.pcap tcp_ecn_sample.pcap tcp_tpncp_tcp.pcap ip_ping_local_ip_fragmentation.pcap ip_teardrop_overlaping_ip_fragments.pcap)"
FTP_PCAS="$(pcap_list ftp_txt.pcap ftp_login_fail.pcap ftp_multiple_session.pcap)"

echo "[3/3] running cases (${MODE})"
FAIL=0
run_case() {
    local name="$1"; shift
    local pcaps="$1"; shift
    if [ -z "${pcaps// /}" ]; then
        echo "  ✗ ${name}: no pcaps matched — corpus entry missing?" >&2
        FAIL=1
        return
    fi
    echo "  case ${name}"
    if [ "${MODE}" = "valgrind" ]; then
        # ${pcaps} is a space-separated list that must word-split into argv
        # shellcheck disable=SC2086
        if ! (cd "${WORK}" && valgrind -q --leak-check=full \
                --errors-for-leak-kinds=definite --error-exitcode=42 \
                "${BIN}" "${name}" ${pcaps} >"${WORK}/${name}.log" 2>&1); then
            echo "    ✗ definite leak or internal failure (see below)" >&2
            tail -20 "${WORK}/${name}.log" >&2
            FAIL=1
        fi
    else
        # same intentional list splitting
        # shellcheck disable=SC2086
        if ! (cd "${WORK}" && "${BIN}" "${name}" ${pcaps} >"${WORK}/${name}.log" 2>&1); then
            echo "    ✗ leak or internal failure (see below)" >&2
            tail -20 "${WORK}/${name}.log" >&2
            FAIL=1
        fi
    fi
}

run_case reassembly_drop_skip      "${TCP_PCAS}"
run_case embedded_session_offsets  "${TCP_PCAS} ${FTP_PCAS}"
run_case ftp_context_teardown      "${FTP_PCAS}"
run_case session_evasion_ownership "${TCP_PCAS} ${FTP_PCAS}"
run_case golden_corpus_teardown    "${ALL_PCAS}"

if [ "${FAIL}" -ne 0 ]; then
    echo "✗ leak regression: FAILED" >&2
    exit 1
fi
echo "✓ leak regression: PASSED (${MODE})"
