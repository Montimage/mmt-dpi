#!/usr/bin/env bash
#
# count-weak-types.sh — ratchet on raw-integer protocol-id parameters in the
# public headers (issues #230/#231, F-DEAD-010; helper committed under #190).
#
# src/mmt_core/public_include/ declares its API with bare `int`/`uint32_t`/
# `unsigned` protocol-id parameters even though a typedef exists — the type
# discipline is unenforceable while the weakly typed originals are the only
# ones in use. Tasks 5.6/5.7 migrate them; this counter makes the migration
# ratchetable.
#
# What it counts: parameter declarations in src/mmt_core/public_include/*.h
# whose name contains "proto" or "protocol" and whose type is a raw integer
# type (int/uintN_t/unsigned/short/long/char), excluding pointer parameters
# and `*_name` strings.
#
#   default      exit 1 when the count rises above the committed baseline
#                (tools/ci/weak-types-baseline.txt); a drop is reported so
#                the baseline can be tightened in the same change.
#   --strict     exit 1 when the count is anything but 0 — the Task 5.7 gate.
#
# Exit codes: 0 = pass, 1 = condition violated, 2 = helper broken.
#
# Usage: bash tools/ci/count-weak-types.sh [--strict]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

BASELINE_FILE="tools/ci/weak-types-baseline.txt"
STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

count="$(grep -hE '\b(int|uint32_t|uint16_t|uint8_t|unsigned|u_int32_t|short|long|char)[[:space:]]+[a-z_]*(proto|protocol)[a-z_]*[[:space:]]*[,)=]' \
    src/mmt_core/public_include/*.h \
    | grep -vcE '\*|_name[[:space:]]*[,)=]')"
echo "    raw-integer protocol-id parameters: $count"

if [ "$STRICT" -eq 1 ]; then
    if [ "$count" -ne 0 ]; then
        echo "✗ $count raw-integer protocol-id parameter(s) remain — Task 5.7 requires 0" >&2
        exit 1
    fi
    echo "✓ no raw-integer protocol-id parameters remain"
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
    echo "✗ weak-type count rose above the baseline: $count > $baseline" >&2
    echo "To fix:  use the protocol-id typedef for new parameters, or update" >&2
    echo "         $BASELINE_FILE with justification" >&2
    exit 1
fi
if [ "$count" -lt "$baseline" ]; then
    echo "  note: count dropped below the baseline ($count < $baseline) —"
    echo "        tighten $BASELINE_FILE in this change"
fi
echo "✓ weak-type count within the baseline ($count ≤ $baseline)"
