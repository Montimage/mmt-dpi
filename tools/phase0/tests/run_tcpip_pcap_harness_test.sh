#!/usr/bin/env bash
#
# run_tcpip_pcap_harness_test.sh — pcap-driven harness for TCP/IP-stack parsers
# (issue #143, 4.1).
#
# Drives the TCP/IP parsers (HTTP, FTP, DNS, TLS/SSL, TCP, IP, UDP, ICMP,
# HTTP/2, QUIC where present) with real pcap bytes through the public DPI API,
# capturing a deterministic classification fingerprint and checking it under
# AddressSanitizer + UBSan. This is the TCP/IP counterpart to the generic
# Phase 0 classification gate (tools/phase0/ci/check_classification.sh) and the
# mobile/security harness (issue #144).
#
# What it does:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/tcpip_pcap_harness.c with
#      -fsanitize=address,undefined -fno-sanitize-recover=all against that
#      library (so both the SDK and the harness are instrumented).
#   3. Generate synthetic TCP/IP pcaps (HTTP, DNS, TLS, FTP, ICMP) via
#      tools/phase0/gen_tcpip_pcap.py — pure stdlib, no scapy.
#   4. Replay every pcap (synthetic + the vendored CI subset under
#      tools/phase0/ci/pcaps/) through the harness TWICE and compare
#      fingerprints (stability check). With -fno-sanitize-recover=all any
#      OOB/UB inside the parsers aborts the process, so a clean exit plus
#      matching fingerprints is the pass condition.
#
# Usage: tools/phase0/tests/run_tcpip_pcap_harness_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE0_DIR="$(cd "${TEST_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PHASE0_DIR}/../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-/tmp/mmt-asan-tcpip-harness}"
WORK="$(mktemp -d)"
BIN="${WORK}/tcpip_pcap_harness"
SYNTH_DIR="${WORK}/synth"
PCAP_CI_DIR="${PHASE0_DIR}/ci/pcaps"

trap 'rm -rf "${WORK}" "${PREFIX}"' EXIT

echo "[1/4] building + installing SDK with BUILD=asan -> ${PREFIX}"
make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null

echo "[2/4] compiling tcpip_pcap_harness (ASan/UBSan)"
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/tcpip_pcap_harness.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap -lpthread -lm

echo "[3/4] generating synthetic TCP/IP pcaps"
mkdir -p "${SYNTH_DIR}"
python3 "${PHASE0_DIR}/gen_tcpip_pcap.py" --out-dir "${SYNTH_DIR}"

echo "[4/4] replaying pcaps under ASan/UBSan (stability = two fresh handlers)"
export LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}"
# Leak detection stays with Valgrind (see rules/common.mk BUILD=asan block).
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"

failures=0
checks=0

run_pcap() {
    local pcap="$1"
    local label="$2"
    checks=$((checks + 1))
    echo "  -> ${label}: ${pcap}"
    # Run from WORK so the SDK's CWD-relative plugins/ lookup misses and falls
    # back to ${PREFIX}/plugins (the repo root has a plugins/ dir pointing at
    # the default non-ASan build).
    if (cd "${WORK}" && "${BIN}" "${pcap}" --self-test >"${WORK}/out.txt" 2>"${WORK}/err.txt"); then
        echo "     PASS"
        # Show fingerprint for manual inspection on verbose runs.
        if [ "${VERBOSE:-0}" = "1" ]; then
            sed 's/^/       /' "${WORK}/out.txt"
        fi
    else
        rc=$?
        echo "     FAIL (rc=${rc})"
        echo "     --- stdout ---"; cat "${WORK}/out.txt" 2>/dev/null || true
        echo "     --- stderr ---"; cat "${WORK}/err.txt" 2>/dev/null || true
        failures=$((failures + 1))
    fi
}

# Synthetic pcaps (cover every TCP/IP parser the harness targets).
for p in "${SYNTH_DIR}"/*.pcap; do
    [ -f "$p" ] || continue
    run_pcap "$p" "synthetic $(basename "$p" .pcap)"
done

# Vendored CI pcaps (real captures: TCP out-of-order, FTP, IP fragmentation, ARP).
if [ -d "${PCAP_CI_DIR}" ]; then
    for p in "${PCAP_CI_DIR}"/*.pcap; do
        [ -f "$p" ] || continue
        run_pcap "$p" "CI $(basename "$p")"
    done
fi

echo ""
echo "TCP/IP pcap harness: ${checks} pcap(s), $((checks - failures)) passed, ${failures} failed"
if [ "${failures}" -ne 0 ]; then
    echo "✗ TCP/IP pcap harness: FAIL"
    exit 1
fi
echo "✓ TCP/IP pcap harness: PASS"
