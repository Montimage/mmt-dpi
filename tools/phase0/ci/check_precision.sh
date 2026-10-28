#!/usr/bin/env bash
#
# check_precision.sh — CI gate for the Phase 7 (M9, issue #74) precision/recall
# baseline.
#
# Runs the labelled-pcap precision/recall harness (tools/phase0/phase0_precision.c)
# over the labelled CI golden subset (tools/phase0/ci/labels.txt) against a
# freshly built+installed library, folds the retained predicted labels into an
# actual-by-predicted confusion matrix (render_precision.py — issue #373,
# F-TEST-002), and diffs the resulting metrics against the committed baseline
# (tools/phase0/ci/baseline/precision.txt). A non-empty diff means a change
# moved classification accuracy on the labelled set — the gate fails so the
# change is reviewed (acceptance criterion: precision/recall "improves or
# holds"). If the change is an intentional improvement, refresh the baseline
# in the same PR.
#
# It then runs the seeded random-payload abstention set (issue #527): captures
# regenerated at gate time by `gen_tcpip_pcap.py --abstention` from a fixed
# seed, carrying no application protocol, so the baseline records the share of
# packets the classifiers still label (the unknown rate) in its own section,
# after -- and separate from -- the labelled metrics.
#
# Fail-fast (F-TEST-002): a missing pcap, an empty harness run, or a malformed
# metric row FAILS the gate — silently dropping labelled examples would let
# accuracy regressions hide inside a smaller corpus.
#
# Used by .github/workflows/phase0-baseline.yml. Runnable locally too:
#   tools/phase0/ci/check_precision.sh
#
# On mismatch it writes the freshly captured metrics to
#   tools/phase0/ci/baseline/precision.actual.txt
# which CI uploads as an artifact, so refreshing the baseline is a copy away.
#
set -euo pipefail

# Pin the locale so awk's sprintf("%.4f", ...) always emits a '.' decimal
# separator. awk's %f honors LC_NUMERIC, so on a comma-decimal locale the
# metrics would render as "0,9717" and the diff against the committed baseline
# (which uses '.') would fail spuriously — the metric must be reproducible
# regardless of host locale.
export LC_ALL=C

CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE0_DIR="$(cd "${CI_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PHASE0_DIR}/../.." && pwd)"
LABELS="${CI_DIR}/labels.txt"
PCAPS_DIR="${CI_DIR}/pcaps"
EXPECTED="${CI_DIR}/baseline/precision.txt"
ACTUAL="${CI_DIR}/baseline/precision.actual.txt"
# Install prefix: MMT_PREFIX overrides (the precision-gate workflow job sets
# it to share the install with the accuracy oracle); by default a fresh,
# private mktemp directory removed on exit — never a fixed, predictable /tmp
# path another user could pre-create (issue #508).
BUILD_DIR="$(mktemp -d)"
if [ -n "${MMT_PREFIX:-}" ]; then
    PREFIX="${MMT_PREFIX}"
    trap 'rm -rf "${BUILD_DIR}"' EXIT
else
    PREFIX="$(mktemp -d /tmp/mmt-phase0.XXXXXX)"
    trap 'rm -rf "${BUILD_DIR}" "${PREFIX}"' EXIT
fi

if [ ! -f "${LABELS}" ]; then
    echo "✗ labelled-pcap manifest missing: ${LABELS}" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "✗ python3 required for render_precision.py" >&2
    exit 1
fi

# --- build + install the library -------------------------------------------
echo "[1/4] building + installing library -> ${PREFIX}"
make -C "${REPO_ROOT}/sdk" -j"$(nproc 2>/dev/null || echo 4)" MMT_BASE="${PREFIX}" \
    >"${BUILD_DIR}/build.log" 2>&1 || {
        echo "✗ library build failed — last lines:" >&2
        tail -20 "${BUILD_DIR}/build.log" >&2
        exit 1
    }
make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >>"${BUILD_DIR}/build.log" 2>&1

INC="${PREFIX}/dpi/include"
LIB="${PREFIX}/dpi/lib"
export LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}"

echo "[2/4] compiling phase0_precision"
gcc -O2 -Wall -o "${BUILD_DIR}/phase0_precision" \
    "${PHASE0_DIR}/phase0_precision.c" -I "${INC}" -L "${LIB}" -lmmt_core -ldl -lpcap

echo "[3/4] running the precision/recall harness over the labelled set"
RAW="${BUILD_DIR}/raw.tsv"
: > "${RAW}"
# Run the harness from a neutral dir so the SDK's CWD-relative "plugins/" lookup
# misses and falls back to ${PREFIX}/plugins (matches capture_baseline.sh).
while IFS= read -r line; do
    # strip comments / blanks
    line="${line%%#*}"
    rel="$(printf '%s' "${line}" | awk '{print $1}')"
    label="$(printf '%s' "${line}" | awk '{print $2}')"
    [ -z "${rel}" ] && continue
    pcap="${PCAPS_DIR}/${rel}"
    if [ ! -f "${pcap}" ]; then
        echo "✗ missing labelled pcap: ${rel} (a labelled example may never be" >&2
        echo "  dropped — restore the fixture or remove its labels.txt row)" >&2
        exit 1
    fi
    # output: <label> <total> <tp> <fp> <app_unknown> <predicted_csv>. A harness
    # non-zero exit or empty output fails the gate: a labelled example that
    # produces no metrics is a harness failure, not a skippable input.
    out="$(cd "${BUILD_DIR}" && "${BUILD_DIR}/phase0_precision" "${pcap}" "${label}" 2>/dev/null)" || out=""
    if [ -z "${out}" ]; then
        echo "✗ harness produced no output for: ${rel}" >&2
        exit 1
    fi
    printf '%s\t%s\n' "${rel}" "${out}" >> "${RAW}"
done < "${LABELS}"

echo "[4/4] running the harness over the seeded abstention set"
ABSTAIN_DIR="${BUILD_DIR}/abstention"
ABSTAIN_RAW="${BUILD_DIR}/abstention.tsv"
python3 "${PHASE0_DIR}/gen_tcpip_pcap.py" --out-dir "${ABSTAIN_DIR}" --abstention \
    >/dev/null
: > "${ABSTAIN_RAW}"
for pcap in "${ABSTAIN_DIR}"/abstain_*.pcap; do
    if [ ! -f "${pcap}" ]; then
        echo "✗ the abstention generator produced no capture" >&2
        exit 1
    fi
    # '<abstain>' is a label no protocol carries: every verdict is an accept.
    out="$(cd "${BUILD_DIR}" && "${BUILD_DIR}/phase0_precision" "${pcap}" "<abstain>" 2>/dev/null)" || out=""
    if [ -z "${out}" ]; then
        echo "✗ harness produced no output for: $(basename "${pcap}")" >&2
        exit 1
    fi
    printf '%s\t%s\n' "$(basename "${pcap}")" "${out}" >> "${ABSTAIN_RAW}"
done

# --- render the deterministic metrics file ---------------------------------
# Per-pcap rows + confusion matrix + per-class and overall micro-averages,
# then the abstention section (unknown rate of the seeded random payloads).
# render_precision.py validates every raw row and exits non-zero on malformed
# input, so a broken harness can never render a partial metric set.
python3 "${CI_DIR}/render_precision.py" "${RAW}" --abstention "${ABSTAIN_RAW}" \
    > "${BUILD_DIR}/precision.txt"

if [ ! -f "${EXPECTED}" ]; then
    cp "${BUILD_DIR}/precision.txt" "${EXPECTED}"
    echo
    echo "○ No committed precision baseline found — wrote one to:"
    echo "    ${EXPECTED#"${REPO_ROOT}/"}"
    echo "  Review it and commit it."
    cat "${EXPECTED}"
    exit 0
fi

if diff -u "${EXPECTED}" "${BUILD_DIR}/precision.txt"; then
    echo
    echo "✓ Phase 7 precision/recall gate: PASS (metrics match the baseline)"
    exit 0
else
    cp "${BUILD_DIR}/precision.txt" "${ACTUAL}"
    echo
    echo "✗ Phase 7 precision/recall gate: FAIL"
    echo "  Classification accuracy on the labelled set changed (diff above)."
    echo "  If this is an INTENTIONAL improvement, refresh the baseline:"
    echo "    cp ${ACTUAL#"${REPO_ROOT}/"} ${EXPECTED#"${REPO_ROOT}/"}"
    echo "  and commit it in the same PR, explaining the change."
    exit 1
fi
