#!/usr/bin/env bash
# check-api-contracts.sh — every public MMTAPI function has a contract test
# (issue #525, F-TEST-011).
#
# The contract table in tests/core_engine/test_api_contracts.c holds one
# compiled entry per MMTAPI function: CONTRACT (a behaviour and an error-path
# assertion) or NO_ERROR_PATH (a behaviour assertion plus the reason the
# function has no error input). This helper compares that table with the
# declared set:
#
#   - every declared name has exactly one entry (none missing, none twice);
#   - every entry names a declared function (no stale entry);
#   - the NO_ERROR_PATH entries are exactly the names in the committed
#     waiver file — a new waiver has to be added there in review, and a
#     waiver that is no longer used has to be dropped, so the list only
#     ratchets down.
#
# Inputs (files, or process substitutions):
#   --decls FILE      one declared name per line
#                     (bash tools/ci/check-public-decls.sh --list)
#   --contracts FILE  "<CONTRACT|NO_ERROR_PATH> <name>" per line
#                     (tests/core_engine/test_api_contracts --list)
#   --waivers FILE    one waived name per line; blank lines and `#` comments
#                     ignored (tests/core_engine/api-contract-waivers.txt)
#
# Exit codes: 0 = every declared function tested, 1 = missing, stale,
#             duplicate or unratcheted entries, 2 = unreadable/empty/malformed
#             input or bad usage.
#
# Usage: bash tools/ci/check-api-contracts.sh --decls FILE --contracts FILE \
#            --waivers FILE

set -euo pipefail
export LC_ALL=C

DECLS="" CONTRACTS="" WAIVERS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --decls)     DECLS="${2:-}"; shift ;;
        --contracts) CONTRACTS="${2:-}"; shift ;;
        --waivers)   WAIVERS="${2:-}"; shift ;;
        *)           echo "✗ unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
for pair in "--decls:$DECLS" "--contracts:$CONTRACTS" "--waivers:$WAIVERS"; do
    if [ -z "${pair#*:}" ]; then
        echo "✗ ${pair%%:*} FILE is required" >&2
        exit 2
    fi
done

# Read each input once: process substitutions cannot be re-read.
decls_raw="$(cat -- "$DECLS")" || { echo "✗ cannot read $DECLS" >&2; exit 2; }
contracts_raw="$(cat -- "$CONTRACTS")" || { echo "✗ cannot read $CONTRACTS" >&2; exit 2; }
waivers_raw="$(cat -- "$WAIVERS")" || { echo "✗ cannot read $WAIVERS" >&2; exit 2; }

decls="$(printf '%s\n' "$decls_raw" | sed 's/[[:space:]]*$//' | grep -v '^$' | sort -u || true)"
if [ -z "$decls" ]; then
    echo "✗ no declared names in $DECLS — did check-public-decls.sh --list break?" >&2
    exit 2
fi
contracts="$(printf '%s\n' "$contracts_raw" | sed 's/[[:space:]]*$//' | grep -v '^$' || true)"
if [ -z "$contracts" ]; then
    echo "✗ no contract entries in $CONTRACTS — did test_api_contracts --list break?" >&2
    exit 2
fi
malformed="$(printf '%s\n' "$contracts" \
    | grep -Ev '^(CONTRACT|NO_ERROR_PATH) [A-Za-z_][A-Za-z0-9_]*$' || true)"
if [ -n "$malformed" ]; then
    echo "✗ malformed contract entries in $CONTRACTS:" >&2
    printf '      %s\n' "$malformed" >&2
    exit 2
fi
waivers="$(printf '%s\n' "$waivers_raw" | sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/^[[:space:]]*//' \
    | grep -v '^$' | sort -u || true)"

names="$(printf '%s\n' "$contracts" | awk '{print $2}' | sort)"
waived="$(printf '%s\n' "$contracts" | awk '$1 == "NO_ERROR_PATH" {print $2}' | sort -u)"

missing="$(comm -23 <(printf '%s\n' "$decls") <(printf '%s\n' "$names" | sort -u))"
stale="$(comm -13 <(printf '%s\n' "$decls") <(printf '%s\n' "$names" | sort -u))"
dupes="$(printf '%s\n' "$names" | uniq -d)"
unlisted="$(comm -23 <(printf '%s\n' "$waived" | grep -v '^$' || true) <(printf '%s\n' "$waivers" | grep -v '^$' || true))"
overlisted="$(comm -13 <(printf '%s\n' "$waived" | grep -v '^$' || true) <(printf '%s\n' "$waivers" | grep -v '^$' || true))"

report() { # report <label> <names> <fix>
    [ -n "$2" ] || return 0
    echo "✗ $(printf '%s\n' "$2" | wc -l | tr -d ' ') $1:" >&2
    printf '%s\n' "$2" | sed 's/^/      /' >&2
    echo "  To fix: $3" >&2
    status=1
}
status=0
report "MMTAPI function(s) without a contract entry" "$missing" \
    "add a CONTRACT (or a justified NO_ERROR_PATH) entry to tests/core_engine/test_api_contracts.c"
report "contract entr(y/ies) naming no MMTAPI function" "$stale" \
    "drop the entry, or restore the MMTAPI declaration"
report "function(s) with more than one contract entry" "$dupes" \
    "keep exactly one entry per function"
report "NO_ERROR_PATH waiver(s) not in $WAIVERS" "$unlisted" \
    "write an error-path assertion, or list the name in the waiver file (reviewed)"
report "waiver file name(s) with no NO_ERROR_PATH entry" "$overlisted" \
    "delete them from the waiver file — waivers only ratchet down"
[ "$status" -eq 0 ] || exit 1

n_decls="$(printf '%s\n' "$decls" | wc -l | tr -d ' ')"
n_waived="$(printf '%s\n' "$waived" | grep -c . || true)"
echo "✓ $n_decls MMTAPI functions, 0 untested, $n_waived error-path waivers"
