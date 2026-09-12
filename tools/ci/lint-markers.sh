#!/usr/bin/env bash
#
# lint-markers.sh — ratchet on the TODO/FIXME/XXX/HACK backlog (issue #232,
# F-DEAD-008; helper committed under issue #190).
#
# 203 markers survive outside the generated tree and 176 of them are over a
# year old, so the recent ones are invisible in the noise. Two rules keep the
# backlog honest while Task 5.8 burns it down:
#
#   default      the marker count must not rise above the committed baseline
#                (tools/ci/marker-baseline.txt) — a ratchet, not a cleanup
#                gate, so it is green today.
#   --strict     additionally require every marker to carry an issue
#                reference (#N, GH-N or a github.com/.../issues/N link) — the
#                Task 5.8 gate, run once the backlog is triaged.
#
# Counted: lines matching TODO|FIXME|XXX|HACK in tracked C/C++ sources and
# headers, excluding the generated src/mmt_mobile/asn1c/ tree.
#
# Exit codes: 0 = pass, 1 = condition violated, 2 = helper broken.
#
# Usage: bash tools/ci/lint-markers.sh [--strict]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

BASELINE_FILE="tools/ci/marker-baseline.txt"
STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

marker_lines="$(git ls-files '*.[ch]' '*.cpp' '*.hpp' ':!:src/mmt_mobile/asn1c/*' \
    | xargs grep -nE 'TODO|FIXME|XXX|HACK' || true)"
count="$(printf '%s\n' "$marker_lines" | grep -c .)"

# A marker "carries an issue reference" when the same line names #N, GH-N or
# a full issues/ URL — everything else is a bare note nobody will find again.
unreferenced="$(printf '%s\n' "$marker_lines" \
    | grep -vE '(TODO|FIXME|XXX|HACK)[^\n]*(#\d+|GH-\d+|issues/\d+)' || true)"
unref_count="$(printf '%s\n' "$unreferenced" | grep -c .)"

echo "    markers: $count ($unref_count without an issue reference)"

if [ "$STRICT" -eq 1 ]; then
    if [ "$unref_count" -ne 0 ]; then
        echo "✗ $unref_count marker(s) carry no issue reference:" >&2
        printf '%s\n' "$unreferenced" | awk 'NR<=20 {print "      " $0}
                                            END {if (NR>20) printf "      … (%d more)\n", NR-20}' >&2
        echo "To fix:  file an issue and reference it (TODO(#N): …), or remove the marker" >&2
        exit 1
    fi
    echo "✓ every marker carries an issue reference"
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
    echo "✗ marker count rose above the baseline: $count > $baseline" >&2
    echo "To fix:  file an issue for the new marker and reference it, or" >&2
    echo "         remove the marker" >&2
    exit 1
fi
if [ "$count" -lt "$baseline" ]; then
    echo "  note: count dropped below the baseline ($count < $baseline) —"
    echo "        tighten $BASELINE_FILE in this change"
fi
echo "✓ marker count within the baseline ($count ≤ $baseline)"
