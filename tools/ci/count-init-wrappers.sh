#!/usr/bin/env bash
#
# count-init-wrappers.sh — ratchet on the per-protocol init-wrapper count
# (issues #226/#227, F-DEAD-* family; helper committed under issue #190).
#
# Every protocol carries a `void mmt_init_classify_me_<proto>(void)` function
# whose whole job is filling three bitmask globals — an identical 4-line
# wrapper repeated once per protocol. Tasks 5.2/5.3 fold them into one generic
# function; this counter makes the shrinkage ratchetable instead of trusting
# the task to remember.
#
# What it counts: definitions of `mmt_init_classify_me_*` in tracked C sources
# under src/ — the wrapper population, identical or not.
#
#   default      exit 1 when the count rises above the committed baseline
#                (tools/ci/init-wrappers-baseline.txt); a drop is reported so
#                the baseline can be tightened in the same change.
#   --strict     exit 1 when the count is anything but 0 — the Task 5.3 gate.
#
# Exit codes: 0 = pass, 1 = condition violated, 2 = helper broken.
#
# Usage: bash tools/ci/count-init-wrappers.sh [--strict]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

BASELINE_FILE="tools/ci/init-wrappers-baseline.txt"
STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

count="$(git ls-files 'src/*.c' | xargs grep -hE '^[a-zA-Z_][a-zA-Z0-9_ \*]*\bmmt_init_classify_me_[A-Za-z0-9_]+[[:space:]]*\(' | wc -l)"
echo "    init-wrapper definitions: $count"

if [ "$STRICT" -eq 1 ]; then
    if [ "$count" -ne 0 ]; then
        echo "✗ $count init wrapper(s) remain — Task 5.3 requires 0" >&2
        exit 1
    fi
    echo "✓ no init wrappers remain"
    exit 0
fi

if [ ! -f "$BASELINE_FILE" ]; then
    echo "✗ baseline not found: $BASELINE_FILE" >&2
    exit 2
fi
baseline="$(awk 'NF && $1 !~ /^#/ {print $1; exit}' "$BASELINE_FILE")"
if ! [[ "$baseline" =~ ^[0-9]+$ ]]; then
    echo "✗ baseline unreadable: $BASELINE_FILE" >&2
    exit 2
fi

if [ "$count" -gt "$baseline" ]; then
    echo "✗ init-wrapper count rose above the baseline: $count > $baseline" >&2
    echo "To fix:  do not add per-protocol init wrappers — register through the" >&2
    echo "         shared mechanism, or update $BASELINE_FILE with justification" >&2
    exit 1
fi
if [ "$count" -lt "$baseline" ]; then
    echo "  note: count dropped below the baseline ($count < $baseline) —"
    echo "        tighten $BASELINE_FILE in this change"
fi
echo "✓ init-wrapper count within the baseline ($count ≤ $baseline)"
