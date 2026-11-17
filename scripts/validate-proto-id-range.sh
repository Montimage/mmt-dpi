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
#   - a `#define PROTO_<NAME> <value>` under src/ gives an expression —
#     arithmetic, a cast, another macro — instead of an integer literal: the
#     guard reads integer literals only (decimal, hex or octal, a U/L suffix,
#     parentheses, a trailing comment) and does not evaluate an expression,
#     so it reports one as a finding rather than pass it unchecked. String
#     values, comment-only values and a lone `\` continuation are not ids and
#     are skipped; an invalid literal such as 0960 (not valid C) exits 2;
#   - `PROTO_MAX_IDENTIFIER` (src/mmt_core/public_include/mmt_core.h) is no
#     longer above the range's last id, so part of the range is unusable;
#   - the page no longer names the range the guard checks (written with an
#     en dash, 950–999, or a hyphen, 950-999).
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
# Exit codes: 0 = range free, 1 = a built-in id in the range, an
#             expression-valued define, the bound below it, or the page not
#             naming it, 2 = validator broken or an invalid integer literal.
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

# Every object-like `#define PROTO_<NAME> <value>`: whitespace must follow the
# name, so function-like macros stay out. Each hit is classified below.
DEFINE_RE='^[[:space:]]*#[[:space:]]*define[[:space:]]+PROTO_[A-Za-z0-9_]+[[:space:]]+[^[:space:]]'
SPLIT_RE='^[[:space:]]*#[[:space:]]*define[[:space:]]+(PROTO_[A-Za-z0-9_]+)[[:space:]]+([^[:space:]].*)$'
LIT='\(*[[:space:]]*(0[xX][0-9A-Fa-f]+|[0-9]+)[uUlL]*[[:space:]]*\)*'
# One comment running to the end of the line: a `//` comment, a `/* */` block
# with nothing but whitespace after it, or a `/*` the next line closes (a
# multi-line doc comment; the guard reads one line, not the lines after it).
COMMENT='(//.*|/\*([^*]|\*+[^*/])*(\*+/[[:space:]]*|\**))'
COMMENT_RE="^${COMMENT}\$"
# The whole value is one literal, then at most that comment (CRLF passes: \r
# is [[:space:]]).
LITERAL_RE="^${LIT}[[:space:]]*${COMMENT}?\$"
CONTINUATION_RE='^\\[[:space:]]*$'

# to_int <literal> — the integer value of a C integer literal: hex, octal
# (a leading zero, as in C) or decimal. Returns 1 on an invalid literal.
to_int() {
    case "$1" in
        0[xX]*) [[ "$1" =~ ^0[xX][0-9A-Fa-f]+$ ]] || return 1; echo $(( $1 )) ;;
        0*)     [[ "$1" =~ ^0[0-7]*$ ]] || return 1; echo $(( 8#$1 )) ;;
        *)      [[ "$1" =~ ^[0-9]+$ ]] || return 1; echo $(( 10#$1 )) ;;
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
    if ! [[ "${text}" =~ ${SPLIT_RE} ]]; then
        echo "✗ ${file#"${ROOT}/"}:${line}: cannot split the define: the scan is broken" >&2
        exit 2
    fi
    name="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
    value="${value%"${value##*[![:space:]]}"}"
    case "${value}" in
        \"*) continue ;;   # a string: not an id
    esac
    [[ "${value}" =~ ${COMMENT_RE} ]] && continue
    [[ "${value}" =~ ${CONTINUATION_RE} ]] && continue
    if ! [[ "${value}" =~ ${LITERAL_RE} ]]; then
        echo "✗ ${file#"${ROOT}/"}:${line}: ${name} = ${value} is an expression the guard does not evaluate; write the id as an integer literal" >&2
        failures=$((failures + 1))
        continue
    fi
    lit="${BASH_REMATCH[1]}"
    if ! val="$(to_int "${lit}")"; then
        echo "✗ ${file#"${ROOT}/"}:${line}: ${name} has an invalid integer literal ${lit}" >&2
        exit 2
    fi
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
if ! max="$(to_int "${max_lit}")"; then
    echo "✗ ${HEADER#"${ROOT}/"}: PROTO_MAX_IDENTIFIER has an invalid integer literal ${max_lit}" >&2
    exit 2
fi
if [ "${max}" -le "${RESERVED_LAST}" ]; then
    echo "✗ PROTO_MAX_IDENTIFIER is ${max}: ids must stay below it, so the range ${RESERVED_FIRST}–${RESERVED_LAST} no longer fits" >&2
    failures=$((failures + 1))
fi

# --- 3. the page names the range ---------------------------------------------
if ! grep -qF -e "${RESERVED_FIRST}–${RESERVED_LAST}" -e "${RESERVED_FIRST}-${RESERVED_LAST}" -- "${DOC}"; then
    echo "✗ ${DOC#"${ROOT}/"} does not name the reserved range ${RESERVED_FIRST}–${RESERVED_LAST}" >&2
    failures=$((failures + 1))
fi

if [ "${failures}" -gt 0 ]; then
    exit 1
fi
echo "✓ protocol id range ${RESERVED_FIRST}–${RESERVED_LAST} free: ${checked} numeric PROTO_ defines checked, PROTO_MAX_IDENTIFIER ${max}"
