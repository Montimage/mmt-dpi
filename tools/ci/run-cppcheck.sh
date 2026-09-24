#!/usr/bin/env bash
#
# run-cppcheck.sh — cppcheck static-analysis gate for src/ (issue #189, F-CI-004).
#
# The lint job used to run cppcheck with its exit status discarded: findings
# were counted and uploaded, but nothing gated on them, so error-severity
# findings shipped green and the total had no ceiling. This script is the gate
# the report-only step used to lack; it applies two independent checks:
#
#   1. Ratchet — a full `--enable=warning` scan writes the XML report the job
#      uploads, and the total finding count must not exceed the committed
#      baseline in tools/ci/cppcheck-ratchet.txt. A rise fails the step; a drop
#      is reported so the baseline can be tightened in the same change.
#   2. Error gate — a second pass restricted to error severity (cppcheck's
#      default check scope — the checks that produce error-severity findings
#      are always enabled; --enable=warning adds the rest) with
#      --error-exitcode=1, so any error-severity finding fails the step.
#
# Writes the pass-1 findings to cppcheck-report.xml at the repo root (override
# with $CPPCHECK_REPORT) — the same artifact the lint job publishes.
#
# Pinned cppcheck version (issue #345): the ratchet baseline is only
# meaningful for the cppcheck release it was measured with — a different
# release adds or drops checks, so the total drifts on unchanged code (e.g.
# 2.21 reports 35 findings where the baseline of 24 was measured with 2.13).
# CPPCHECK_PINNED_VERSION below is the major.minor the lint job gets from the
# ubuntu-24.04 cppcheck package (.github/workflows/c-cpp.yml, `lint` job).
# The script compares `cppcheck --version` with it:
#   - match      -> both gates are enforced;
#   - mismatch in CI (CI=true) -> exit 2: the runner image changed; re-measure
#     tools/ci/cppcheck-ratchet.txt with the new release and bump the pin in
#     the same change;
#   - mismatch locally -> warning; the ratchet verdict is advisory only (the
#     count is not comparable) while the error-severity gate stays enforced
#     (another release may also add or drop error checks, so a local error
#     verdict may not reproduce in CI). Only CI=true (GitHub Actions) counts
#     as CI.
# For a verdict that matches CI, run cppcheck $CPPCHECK_PINNED_VERSION.x
# locally (e.g. in an ubuntu:24.04 container: apt-get install -y cppcheck).
# Never raise the baseline to absorb version drift.
#
# Exit codes: 0 = both gates pass, 1 = a gate tripped, 2 = the helper itself
# is broken (cppcheck missing or at an unexpected version in CI, unreadable
# baseline, unparseable report).
#
# Usage: bash tools/ci/run-cppcheck.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

REPORT="${CPPCHECK_REPORT:-cppcheck-report.xml}"
RATCHET="${CPPCHECK_RATCHET:-tools/ci/cppcheck-ratchet.txt}"
JOBS="${CPPCHECK_JOBS:-$(nproc 2>/dev/null || echo 2)}"
CPPCHECK_PINNED_VERSION="2.13"   # major.minor of ubuntu-24.04's cppcheck (CI)
SCAN_DIRS=(src)
EXCLUDE=(-i src/mmt_mobile/asn1c)   # generated ASN.1 tree — never scanned

# Vendored sources are excluded by configuration, not convention
# (issue #249, F-CLEAN-019): tools/ci/vendor-paths.txt lists them.
VENDOR_LIST="tools/ci/vendor-paths.txt"
[ -f "$VENDOR_LIST" ] || { echo "✗ vendored-source list not found: $VENDOR_LIST" >&2; exit 2; }
while IFS= read -r p; do
    case "$p" in ''|'#'*) continue ;; esac
    EXCLUDE+=(-i "$p")
done < "$VENDOR_LIST"

if ! command -v cppcheck >/dev/null 2>&1; then
    echo "✗ cppcheck is not installed" >&2
    echo "To fix:  apt-get install -y cppcheck" >&2
    exit 2
fi

# `cppcheck --version` prints e.g. "Cppcheck 2.13.0"; compare major.minor.
version_out="$(cppcheck --version 2>/dev/null || true)"
if ! [[ "$version_out" =~ ([0-9]+)\.([0-9]+) ]]; then
    echo "✗ cannot parse cppcheck version from: ${version_out:-<no output>}" >&2
    exit 2
fi
found_version="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
ratchet_enforced=1
if [ "$found_version" != "$CPPCHECK_PINNED_VERSION" ]; then
    if [ "${CI:-}" = "true" ]; then
        echo "✗ cppcheck $found_version found, the ratchet is pinned to $CPPCHECK_PINNED_VERSION" >&2
        echo "To fix:  re-measure $RATCHET with cppcheck $found_version and" >&2
        echo "         update CPPCHECK_PINNED_VERSION in $0 in the same change" >&2
        exit 2
    fi
    echo "⚠ cppcheck $found_version differs from the CI-pinned $CPPCHECK_PINNED_VERSION —"
    echo "  the finding count is not comparable with the baseline, so the"
    echo "  ratchet is advisory in this run (the error-severity gate still applies)."
    echo "  For a CI-equivalent verdict, run cppcheck $CPPCHECK_PINNED_VERSION.x."
    ratchet_enforced=0
fi

if [ ! -f "$RATCHET" ]; then
    echo "✗ ratchet baseline not found: $RATCHET" >&2
    exit 2
fi
# First non-comment line of the baseline file is the recorded count.
baseline="$(awk 'NF && $1 !~ /^#/ {print $1; exit}' "$RATCHET")"
if ! [[ "$baseline" =~ ^[0-9]+$ ]]; then
    echo "✗ ratchet baseline unreadable: $RATCHET" >&2
    echo "    expected a bare integer on the first non-comment line" >&2
    exit 2
fi

echo "── cppcheck pass 1/2: full scan (ratchet + report) ──"
# The exit status is deliberately discarded here: pass 1 is the reporting
# pass — the ratchet below decides, not cppcheck's own exit code.
cppcheck --enable=warning --inline-suppr -j"$JOBS" \
    "${EXCLUDE[@]}" \
    --xml --xml-version=2 \
    "${SCAN_DIRS[@]}" \
    2> "$REPORT" || true

# A crashed or missing cppcheck must not look like a clean scan: the
# <results> skeleton is written even at zero findings, never on abort.
if ! grep -q '<results' "$REPORT"; then
    echo "✗ cppcheck did not produce a parseable report ($REPORT)" >&2
    exit 2
fi

total="$(grep -c '<error ' "$REPORT" || true)"
errors="$(grep -c 'severity="error"' "$REPORT" || true)"
echo "    findings: $total total, $errors error-severity (ratchet baseline: $baseline)"

rc=0

if [ "$ratchet_enforced" -eq 0 ]; then
    echo "⚠ ratchet not enforced: $total findings under cppcheck $found_version are not"
    echo "  comparable with the $CPPCHECK_PINNED_VERSION baseline ($baseline) — do not re-baseline from this run"
elif [ "$total" -gt "$baseline" ]; then
    echo "✗ cppcheck findings rose above the ratchet: $total > $baseline" >&2
    echo "To fix:  resolve the new findings, or — only with a recorded" >&2
    echo "         justification — raise $RATCHET" >&2
    rc=1
elif [ "$total" -lt "$baseline" ]; then
    echo "  note: findings dropped below the baseline ($total < $baseline) —"
    echo "        tighten $RATCHET in this change to bank the progress"
else
    echo "✓ findings within the ratchet ($total ≤ $baseline)"
fi

echo "── cppcheck pass 2/2: error-severity gate ──"
# Default check scope (no --enable=...) runs only the checks whose findings
# are error-severity, so --error-exitcode=1 makes any such finding fail here.
# --inline-suppr is honoured in both passes so a justified inline suppression
# is counted consistently.
if cppcheck --inline-suppr --error-exitcode=1 -j"$JOBS" -q \
    "${EXCLUDE[@]}" "${SCAN_DIRS[@]}" 2>/dev/null; then
    echo "✓ no error-severity findings"
else
    echo "✗ error-severity findings present — see $REPORT" >&2
    echo "To fix:  fix the finding, or suppress it inline with a justification" >&2
    echo "         comment (// cppcheck-suppress <id> — reason)" >&2
    rc=1
fi

exit "$rc"
