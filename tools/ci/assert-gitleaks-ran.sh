#!/usr/bin/env bash
#
# Assert that a secret scan actually executed (issue #191, F-SEC-001).
#
# The failure this exists to prevent is the silent one: the scanning step is
# skipped — a removed runtime, an unavailable action, a licence error swallowed
# by continue-on-error — and the job still reports green, so the repository
# looks scanned when nothing looked at it. A gate that cannot fail is not a
# gate, and its absence is invisible precisely when it matters.
#
# Usage: bash tools/ci/assert-gitleaks-ran.sh <action-outcome>
#   <action-outcome>  the gitleaks-action step's outcome: success | failure |
#                     skipped | cancelled

set -euo pipefail

ACTION_OUTCOME="${1:-unknown}"
MARKER="${GITLEAKS_MARKER:-.gitleaks-scan-ran}"

if [ "$ACTION_OUTCOME" = "success" ]; then
    echo "✓ secret scan ran via gitleaks-action"
    exit 0
fi

if [ -f "$MARKER" ]; then
    echo "✓ secret scan ran via the pinned gitleaks binary"
    echo "  gitleaks-action outcome was '${ACTION_OUTCOME}', so the fallback took over:"
    sed 's/^/    /' "$MARKER"
    exit 0
fi

echo "✗ no secret scan executed — the repository was not scanned" >&2
echo "    gitleaks-action outcome: ${ACTION_OUTCOME}" >&2
echo "    fallback marker:         ${MARKER} (absent)" >&2
echo "" >&2
echo "To fix:  check the two scan steps in the secret-scan job of" >&2
echo "         .github/workflows/c-cpp.yml — both failed to produce a scan." >&2
exit 1
