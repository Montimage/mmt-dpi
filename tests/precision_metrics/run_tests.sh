#!/bin/bash
# Delegate suite: the precision-metrics self-test lives beside the renderer it
# exercises — tools/phase0/ci/render_precision.py (issue #373, F-TEST-002) —
# and the accuracy-corpus oracle self-test beside its oracle,
# tools/ci/tests/check-accuracy-corpus.py (issues #389 and #390, F-TEST-003).
# Neither needs an SDK build: they feed synthetic raw TSV / canned
# fingerprints to the real scripts.
set -e
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../tools/ci/tests"
python3 "${TESTS_DIR}/test-precision-metrics.py" "$@"
python3 "${TESTS_DIR}/test-accuracy-corpus.py"
