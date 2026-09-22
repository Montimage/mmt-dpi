#!/bin/bash
# Delegate suite: the precision-metrics self-test lives beside the renderer it
# exercises — tools/phase0/ci/render_precision.py (issue #373, F-TEST-002).
# It needs no SDK build: the suite feeds synthetic raw TSV to the real script.
set -e
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../tools/ci/tests/test-precision-metrics.py" "$@"
