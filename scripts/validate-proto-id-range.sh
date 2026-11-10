#!/usr/bin/env bash
# validate-proto-id-range.sh — keep the third-party protocol id range free
# (issue #73; run by the doc-validators job from issue #187).
#
# docs/Add-New-Protocol.md reserves protocol ids 950–999 for plugins of your
# own (out-of-tree plugins): no built-in protocol is ever assigned there, so
# a plugin author can take an id from the range without colliding with the
# SDK. This guard holds the SDK to that promise. It fails when:
#
#   - a `#define PROTO_<NAME> <n>` anywhere under src/ gives a value in the
#     range — any spacing, spaces or tabs, around `#`, `define`, the name and
#     the value (src/mmt_tcpip/include/mmt_tcpip_protocols.h defines
#     PROTO_HTTP2 with tabs), decimal, hex or octal, with or without a U/L
#     suffix or parentheses. Every numeric PROTO_ define is checked, not only
#     protocol ids, so no other PROTO_ constant may take a value in the range
#     either (none does);
#   - `PROTO_MAX_IDENTIFIER` (src/mmt_core/public_include/mmt_core.h) is no
#     longer above the range's last id, so part of the range is unusable;
#   - the page no longer names the range the guard checks.
#
# The fixture self-test is tools/ci/tests/test-proto-id-range.sh.
#
# Environment (for the fixture self-test):
#   MMT_PROTO_ID_SRC     directory scanned for id defines (default src)
#   MMT_PROTO_ID_HEADER  header defining PROTO_MAX_IDENTIFIER
#                        (default src/mmt_core/public_include/mmt_core.h)
#   MMT_PROTO_ID_DOC     page that documents the range
#                        (default docs/Add-New-Protocol.md)
#
# Exit codes: 0 = range free, 1 = a built-in id in the range, the bound below
#             it, or the page not naming it, 2 = validator broken.
set -euo pipefail
export LC_ALL=C

RESERVED_FIRST=950
RESERVED_LAST=999

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${MMT_PROTO_ID_SRC:-${ROOT}/src}"
HEADER="${MMT_PROTO_ID_HEADER:-${ROOT}/src/mmt_core/public_include/mmt_core.h}"
DOC="${MMT_PROTO_ID_DOC:-${ROOT}/docs/Add-New-Protocol.md}"

[ -d "${SRC}" ] || { echo "✗ no source directory ${SRC}" >&2; exit 2; }
[ -f "${HEADER}" ] || { echo "✗ no header ${HEADER}" >&2; exit 2; }
[ -f "${DOC}" ] || { echo "✗ no page ${DOC}" >&2; exit 2; }

LIT='\(*[[:space:]]*(0[xX][0-9A-Fa-f]+|[0-9]+)[uUlL]*[[:space:]]*\)*'
DEFINE_RE="^[[:space:]]*#[[:space:]]*define[[:space:]]+PROTO_[A-Za-z0-9_]+[[:space:]]+${LIT}([[:space:]]|/[/*]|\$)"

# to_int <literal> — the integer value of a C integer literal: hex, octal
# (a leading zero, as in C) or decimal.
to_int() {
    case "$1" in
        0[xX]*) echo $(( $1 )) ;;
        0*)     echo $(( 8#$1 )) ;;
        *)      echo $(( 10#$1 )) ;;
    esac
}

failures=0
checked=0
HITS="$(mktemp)"
trap 'rm -f "${HITS}"' EXIT

# --- 1. no id define under src/ in the reserved range ------------------------
grep_exit=0
grep -rnIE -- "${DEFINE_RE}" "${SRC}" > "${HITS}" || grep_exit=$?
if [ "${grep_exit}" -gt 1 ]; then
    echo "✗ grep failed (exit ${grep_exit}) while scanning ${SRC}" >&2
    exit 2
fi
while IFS= read -r hit; do
    file="${hit%%:*}"; rest="${hit#*:}"
    line="${rest%%:*}"; text="${rest#*:}"
    name="$(sed -E 's/^[[:space:]]*#[[:space:]]*define[[:space:]]+(PROTO_[A-Za-z0-9_]+).*/\1/' <<<"${text}")"
    lit="$(sed -E 's/^[[:space:]]*#[[:space:]]*define[[:space:]]+PROTO_[A-Za-z0-9_]+[[:space:]]+\(*[[:space:]]*(0[xX][0-9A-Fa-f]+|[0-9]+).*/\1/' <<<"${text}")"
    val="$(to_int "${lit}")"
    checked=$((checked + 1))
    if [ "${val}" -ge "${RESERVED_FIRST}" ] && [ "${val}" -le "${RESERVED_LAST}" ]; then
        echo "✗ ${file#"${ROOT}/"}:${line}: ${name} = ${val} is in the third-party range ${RESERVED_FIRST}–${RESERVED_LAST} (docs/Add-New-Protocol.md); give the built-in protocol an id below ${RESERVED_FIRST}" >&2
        failures=$((failures + 1))
    fi
done < "${HITS}"

if [ "${checked}" -eq 0 ]; then
    echo "✗ no '#define PROTO_<NAME> <n>' found under ${SRC}: the scan is broken" >&2
    exit 2
fi

# --- 2. the range lies under PROTO_MAX_IDENTIFIER ----------------------------
max_lit="$(sed -nE 's/^[[:space:]]*#[[:space:]]*define[[:space:]]+PROTO_MAX_IDENTIFIER[[:space:]]+(0[xX][0-9A-Fa-f]+|[0-9]+).*/\1/p' "${HEADER}" | head -n 1)"
if [ -z "${max_lit}" ]; then
    echo "✗ no numeric PROTO_MAX_IDENTIFIER in ${HEADER}" >&2
    exit 2
fi
max="$(to_int "${max_lit}")"
if [ "${max}" -le "${RESERVED_LAST}" ]; then
    echo "✗ PROTO_MAX_IDENTIFIER is ${max}: ids must stay below it, so the range ${RESERVED_FIRST}–${RESERVED_LAST} no longer fits" >&2
    failures=$((failures + 1))
fi

# --- 3. the page names the range ---------------------------------------------
if ! grep -qF -- "${RESERVED_FIRST}–${RESERVED_LAST}" "${DOC}"; then
    echo "✗ ${DOC#"${ROOT}/"} does not name the reserved range ${RESERVED_FIRST}–${RESERVED_LAST}" >&2
    failures=$((failures + 1))
fi

if [ "${failures}" -gt 0 ]; then
    exit 1
fi
echo "✓ protocol id range ${RESERVED_FIRST}–${RESERVED_LAST} free: ${checked} numeric PROTO_ defines checked, PROTO_MAX_IDENTIFIER ${max}"
