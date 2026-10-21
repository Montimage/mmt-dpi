#!/usr/bin/env bash
#
# check_classification.sh — CI gate for the Phase 0 classification baseline.
#
# Captures the classification fingerprint of the vendored CI pcap subset against
# a freshly built+installed library and diffs it against the committed baseline
# (tools/phase0/ci/baseline/classification.txt). A non-empty diff means a phase
# changed the SDK's classification decisions — the gate fails so the change is
# reviewed (and, if intentional, the baseline updated in the same PR).
#
# Used by .github/workflows/phase0-baseline.yml. Runnable locally too:
#   tools/phase0/ci/check_classification.sh
#
# On mismatch it writes the freshly captured fingerprint to
#   tools/phase0/ci/baseline/classification.actual.txt
# which CI uploads as an artifact, so refreshing the baseline is a copy away.
#
set -euo pipefail

CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE0_DIR="$(cd "${CI_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PHASE0_DIR}/../.." && pwd)"
EXPECTED="${CI_DIR}/baseline/classification.txt"
ACTUAL="${CI_DIR}/baseline/classification.actual.txt"
# Install prefix: MMT_PREFIX overrides; by default a fresh, private mktemp
# directory removed on exit — never a fixed, predictable /tmp path another
# user could pre-create (issue #508).
OUT_DIR="$(mktemp -d)"
if [ -n "${MMT_PREFIX:-}" ]; then
    PREFIX="${MMT_PREFIX}"
    trap 'rm -rf "${OUT_DIR}"' EXIT
else
    PREFIX="$(mktemp -d /tmp/mmt-phase0.XXXXXX)"
    trap 'rm -rf "${OUT_DIR}" "${PREFIX}"' EXIT
fi

if [ ! -f "${EXPECTED}" ]; then
    echo "✗ committed CI baseline missing: ${EXPECTED}" >&2
    exit 1
fi

bash "${PHASE0_DIR}/capture_baseline.sh" \
    --golden   "${CI_DIR}/golden_pcaps.txt" \
    --datasets "${CI_DIR}/pcaps" \
    --out      "${OUT_DIR}" \
    --prefix   "${PREFIX}" \
    --iterations 30

if diff -u "${EXPECTED}" "${OUT_DIR}/classification.txt"; then
    echo
    echo "✓ Phase 0 classification gate: PASS (fingerprint matches the baseline)"
    exit 0
else
    cp "${OUT_DIR}/classification.txt" "${ACTUAL}"
    echo
    echo "✗ Phase 0 classification gate: FAIL"
    echo "  The SDK's classification of the golden pcaps changed (diff above)."
    echo "  If this is an INTENTIONAL classification change, refresh the baseline:"
    echo "    cp ${ACTUAL#"${REPO_ROOT}/"} ${EXPECTED#"${REPO_ROOT}/"}"
    echo "  and commit it in the same PR, explaining the change."
    exit 1
fi
