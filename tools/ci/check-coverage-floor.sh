#!/usr/bin/env bash
#
# check-coverage-floor.sh — fail when the library-only coverage measured by
# `bash tests/run_all_tests.sh --coverage` drops below the committed floor
# (issue #185, F-CI-014).
#
# tests/run_all_tests.sh --coverage writes tests/coverage/summary.json with
# library_line_pct and instrumented_files (src/ sources only — test sources
# under tests/ are excluded so the number means the library). This helper
# compares both counters against the committed tests/coverage/floor.json and
# fails on a drop, so a suite losing instrumentation or coverage sinks the CI
# job instead of drifting unnoticed.
#
# Exit codes: 0 = at/above floor, 1 = below floor, 2 = helper broken
#             (missing or unparsable input).
#
# Usage: bash tools/ci/check-coverage-floor.sh [summary.json] [floor.json]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

SUMMARY="${1:-tests/coverage/summary.json}"
FLOOR="${2:-tests/coverage/floor.json}"

for f in "$SUMMARY" "$FLOOR"; do
    if [ ! -s "$f" ]; then
        echo "✗ $f is missing or empty — run tests/run_all_tests.sh --coverage" >&2
        exit 2
    fi
done
command -v jq >/dev/null 2>&1 || { echo "✗ jq is required" >&2; exit 2; }

pct=$(jq -r '.library_line_pct // empty' "$SUMMARY") || { echo "✗ could not parse $SUMMARY" >&2; exit 2; }
files=$(jq -r '.instrumented_files // empty' "$SUMMARY") || { echo "✗ could not parse $SUMMARY" >&2; exit 2; }
floor_pct=$(jq -r '.library_line_pct // empty' "$FLOOR") || { echo "✗ could not parse $FLOOR" >&2; exit 2; }
floor_files=$(jq -r '.instrumented_files // empty' "$FLOOR") || { echo "✗ could not parse $FLOOR" >&2; exit 2; }
for v in "$pct" "$files" "$floor_pct" "$floor_files"; do
    [ -n "$v" ] || { echo "✗ missing library_line_pct/instrumented_files key" >&2; exit 2; }
done

echo "coverage floor check: ${pct}% vs floor ${floor_pct}% ; ${files} files vs floor ${floor_files}"

rc=0
awk -v a="$pct" -v b="$floor_pct" 'BEGIN{exit !(a+0 < b+0)}' && {
    echo "✗ library line coverage ${pct}% is below the committed floor ${floor_pct}%" >&2
    rc=1
}
[ "$files" -lt "$floor_files" ] 2>/dev/null && {
    echo "✗ instrumented-file count ${files} is below the committed floor ${floor_files}" >&2
    rc=1
}
[ "$rc" -eq 0 ] && echo "✓ coverage floor holds"
exit "$rc"
