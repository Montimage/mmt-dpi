#!/usr/bin/env bash
#
# check-coverage-floor.sh — fail when the library-only coverage measured by
# `bash tests/run_all_tests.sh --coverage` drops below the committed floor
# (issue #185, F-CI-014).
#
# tests/run_all_tests.sh --coverage writes tests/coverage/summary.json with
# library_line_pct, instrumented_files and instrumented_sources (src/
# sources only — test sources under tests/ are excluded so the number means
# the library). This helper compares both counters against the committed
# tests/coverage/floor.json, verifies every source named in the floor's
# required_instrumented_files is still instrumented (issue #244), and fails
# on a drop, so a suite losing instrumentation or coverage sinks the CI job
# instead of drifting unnoticed.
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

# Named-file floor (issue #244): when floor.json pins required sources by
# repo-relative path, each one must appear in the summary's
# instrumented_sources — a suite silently dropping a required file fails even
# when the raw count still holds (another file could replace it).
jq -e '(.required_instrumented_files // []) | type == "array"' "$FLOOR" >/dev/null 2>&1 || {
    echo "✗ required_instrumented_files in $FLOOR is not an array" >&2
    exit 2
}
if [ "$(jq -r '.required_instrumented_files // [] | length' "$FLOOR")" -gt 0 ]; then
    jq -e '.instrumented_sources | type == "array"' "$SUMMARY" >/dev/null 2>&1 || {
        echo "✗ $SUMMARY has no instrumented_sources list — re-run tests/run_all_tests.sh --coverage" >&2
        exit 2
    }
    while IFS= read -r req; do
        [ -n "$req" ] || continue
        jq -e --arg req "$req" '.instrumented_sources | index($req) != null' \
            "$SUMMARY" >/dev/null || {
            echo "✗ required instrumented file $req is absent from the measured coverage" >&2
            rc=1
        }
    done < <(jq -r '.required_instrumented_files[]' "$FLOOR")
    [ "$rc" -eq 0 ] && echo "✓ all required instrumented files are present"
fi

[ "$rc" -eq 0 ] && echo "✓ coverage floor holds"
exit "$rc"
