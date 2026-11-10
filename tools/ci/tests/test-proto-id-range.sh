#!/usr/bin/env bash
#
# test-proto-id-range.sh — self-test for scripts/validate-proto-id-range.sh,
# the guard that keeps protocol ids 950–999 free for third-party plugins
# (issue #73).
#
# The real tree passes by construction, so this self-test proves the guard
# can fail: it runs the REAL validator on a fixture tree — a source directory,
# a header defining PROTO_MAX_IDENTIFIER and a page naming the range — copied
# fresh per scenario.
#
# Scenario -> expected validator exit:
#   clean fixture (ids 1, 700, 904, 949 and 1000)                  -> 0
#   a space-separated id of 950                                    -> 1
#   a tab-separated id of 999                                      -> 1
#   `  #  define` with a hex id 0x3C0 (960)                        -> 1
#   an id of 980U with a trailing comment, in a .c file            -> 1
#   a parenthesised id (960)                                       -> 1
#   an octal id 01734 (988)                                        -> 1
#   an octal 0750 (488) and a 0 just below and above the range     -> 0
#   PROTO_MAX_IDENTIFIER 999                                       -> 1
#   a page that no longer names the range                          -> 1
#   no id define at all                                            -> 2
#   the real tree                                                  -> 0
#
# Usage: bash tools/ci/tests/test-proto-id-range.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
VALIDATOR="${REPO_ROOT}/scripts/validate-proto-id-range.sh"
[ -f "${VALIDATOR}" ] || { echo "✗ missing ${VALIDATOR}" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

checks=0
failures=0
pass() { checks=$((checks + 1)); echo "  ✓ $1"; }
fail() { checks=$((checks + 1)); failures=$((failures + 1)); echo "  ✗ $1" >&2; }

# fixture <name> — a fresh clean fixture tree under WORK; prints its path.
fixture() {
    local d="${WORK}/$1"
    mkdir -p "${d}/src/core" "${d}/src/tcpip/lib" "${d}/docs"
    printf '#define PROTO_MAX_IDENTIFIER    1000    /**< Maximum */\n' > "${d}/src/core/core.h"
    # shellcheck disable=SC1003  # the last define continues on the next line
    printf '%s\n' \
        '#define PROTO_UNKNOWN 0' \
        '#define PROTO_ETHERNET 1' \
        '#define PROTO_HTTP2		700' \
        '#define PROTO_NAS5G 904' \
        '#define PROTO_LAST_FREE 949 // just below the range' \
        '#define PROTO_ALIAS "alias"' \
        '#define PROTO_CLASS_LABELS \' > "${d}/src/tcpip/protocols.h"
    printf 'Ids **950–999** are reserved for third-party plugins.\n' > "${d}/docs/page.md"
    echo "${d}"
}

# expect DESC WANT DIR [NEEDLE] — runs the real validator on fixture DIR;
# NEEDLE, when given, must appear in its output (the finding planted).
expect() {
    local desc="$1" want="$2" dir="$3" needle="${4:-}"
    local got=0 out
    out="$(MMT_PROTO_ID_SRC="${dir}/src" \
           MMT_PROTO_ID_HEADER="${dir}/src/core/core.h" \
           MMT_PROTO_ID_DOC="${dir}/docs/page.md" \
           bash "${VALIDATOR}" 2>&1)" || got=$?
    if [ "${got}" -ne "${want}" ]; then
        fail "${desc} (exit ${got}, want ${want})"
        printf '%s\n' "${out}" | sed 's/^/      /' >&2
    elif [ -n "${needle}" ] && ! grep -qF -- "${needle}" <<<"${out}"; then
        fail "${desc} (no '${needle}' in the output)"
        printf '%s\n' "${out}" | sed 's/^/      /' >&2
    else
        pass "${desc}"
    fi
}

echo "validate-proto-id-range.sh self-test"

d="$(fixture clean)"
expect "clean fixture" 0 "${d}" "range 950–999 free"

d="$(fixture space950)"
printf '#define PROTO_FIRST_RESERVED 950\n' >> "${d}/src/tcpip/protocols.h"
expect "a space-separated id of 950" 1 "${d}" "PROTO_FIRST_RESERVED = 950"

d="$(fixture tab999)"
printf '#define\tPROTO_LAST_RESERVED\t\t999\n' >> "${d}/src/tcpip/protocols.h"
expect "a tab-separated id of 999" 1 "${d}" "PROTO_LAST_RESERVED = 999"

d="$(fixture hex)"
printf '  #  define   PROTO_HEXED   0x3C0\n' >> "${d}/src/tcpip/protocols.h"
expect "an indented '#  define' with a hex id 0x3C0" 1 "${d}" "PROTO_HEXED = 960"

d="$(fixture suffix)"
printf '/* a source file */\n#define PROTO_IN_C 980U // taken\n' > "${d}/src/tcpip/lib/proto_in_c.c"
expect "an id of 980U in a .c file" 1 "${d}" "src/tcpip/lib/proto_in_c.c:2: PROTO_IN_C = 980"

d="$(fixture parens)"
printf '#define PROTO_PARENS ( 960 )\n' >> "${d}/src/tcpip/protocols.h"
expect "a parenthesised id (960)" 1 "${d}" "PROTO_PARENS = 960"

d="$(fixture octal)"
printf '#define PROTO_OCTAL 01734\n' >> "${d}/src/tcpip/protocols.h"
expect "an octal id 01734 (988)" 1 "${d}" "PROTO_OCTAL = 988"

d="$(fixture octal_free)"
printf '#define PROTO_OCT_A 0750\n#define PROTO_ZERO 0\n#define PROTO_ABOVE (1000)\n' >> "${d}/src/tcpip/protocols.h"
expect "an octal 0750 (488), a 0 and (1000)" 0 "${d}" "range 950–999 free"

d="$(fixture bound)"
printf '#define PROTO_MAX_IDENTIFIER 999\n' > "${d}/src/core/core.h"
expect "PROTO_MAX_IDENTIFIER 999" 1 "${d}" "PROTO_MAX_IDENTIFIER is 999"

d="$(fixture doc)"
printf 'Pick any free id.\n' > "${d}/docs/page.md"
expect "a page that no longer names the range" 1 "${d}" "does not name the reserved range"

d="$(fixture empty)"
printf '#define PROTO_ALIAS "alias"\n' > "${d}/src/tcpip/protocols.h"
printf '#define PROTO_MAX_IDENTIFIER_UNSET\n' > "${d}/src/core/core.h"
expect "no id define at all" 2 "${d}" "the scan is broken"

got=0
out="$(bash "${VALIDATOR}" 2>&1)" || got=$?
if [ "${got}" -eq 0 ]; then
    pass "the real tree"
else
    fail "the real tree (exit ${got}, want 0)"
    printf '%s\n' "${out}" | sed 's/^/      /' >&2
fi

echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
