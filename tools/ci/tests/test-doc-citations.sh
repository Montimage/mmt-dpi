#!/usr/bin/env bash
#
# test-doc-citations.sh — self-test for tools/ci/check-doc-citations.py, the
# `path:line` citation guard of every docs/*.md page (issue #582, F-DOCS-009).
#
# The real docs tree passes by construction, so this self-test proves the
# guard can fail: it runs the REAL checker (--root, --registry) on a fixture
# repository — a source file, a page citing it, an append-only log and a
# delegated page — copied fresh per scenario.
#
# Scenario -> expected checker exit:
#   clean fixture                                                  -> 0
#   the cited code slides down one line                            -> 1
#   a range's last line no longer holds the tail needle            -> 1
#   a citation past the end of the file                            -> 1
#   a citation no registry row anchors                             -> 1
#   a registry row the page no longer cites                        -> 1
#   a bare basename instead of the repository path                 -> 1
#   the generated sdk/include/ copy instead of the source header   -> 1
#   a citation of a file that does not exist                       -> 1
#   an exempt page that does not declare itself append-only        -> 1
#   a delegated page whose script does not exist                   -> 1
#   a delegated page citing past the end of a file                 -> 1
#   a bare file:N in a fenced code block, and `ubuntu:24.04`       -> 0
#   an unregistered repository path:N in a fenced code block       -> 1
#   a basename linked to github.com blob/<ref>/<path>#L            -> 0
#   a malformed registry row                                       -> 2
#   the real docs tree and tools/ci/doc-citations.txt              -> 0
#
# Usage: bash tools/ci/tests/test-doc-citations.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

# shellcheck disable=SC2016  # backticks in the fixture text are Markdown
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
CHECKER="${REPO_ROOT}/tools/ci/check-doc-citations.py"
[ -f "${CHECKER}" ] || { echo "✗ missing ${CHECKER}" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

checks=0
failures=0
pass() { checks=$((checks + 1)); echo "  ✓ $1"; }
fail() { checks=$((checks + 1)); failures=$((failures + 1)); echo "  ✗ $1" >&2; }

# expect DESC WANT DIR [NEEDLE] — runs the real checker on fixture DIR;
# NEEDLE, when given, must appear in its output (the finding planted).
expect() {
    local desc="$1" want="$2" dir="$3" needle="${4:-}"
    local got=0 out
    out="$(python3 "${CHECKER}" --root "${dir}" --registry reg.txt 2>&1)" || got=$?
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

# --- fixture repository -----------------------------------------------------
ORIG="${WORK}/orig"
mkdir -p "${ORIG}/docs" "${ORIG}/src/lib" "${ORIG}/scripts"
cat >"${ORIG}/src/lib/engine.c" <<'EOF'
#include <stdio.h>

int engine_start(void)
{
    return 0;
}
EOF
cat >"${ORIG}/docs/Guide.md" <<'EOF'
# Guide

`engine_start()` is defined at `src/lib/engine.c:3` and spans
`src/lib/engine.c:3-6`.
EOF
cat >"${ORIG}/docs/LOG.md" <<'EOF'
# Log

Append-only log of fixes; entries cite the tree on their date
(`src/lib/engine.c:99`).
EOF
cat >"${ORIG}/docs/Delegated.md" <<'EOF'
# Delegated

See `src/lib/engine.c:1`.
EOF
printf '# names docs/Delegated.md\n' >"${ORIG}/scripts/validate-delegated.sh"
printf '%s\n' \
    '# fixture registry' \
    "$(printf 'cite\tdocs/Guide.md\tsrc/lib/engine.c:3\tint engine_start(void)')" \
    "$(printf 'cite\tdocs/Guide.md\tsrc/lib/engine.c:3-6\tint engine_start(\t}')" \
    "$(printf 'exempt\tdocs/LOG.md\tappend-only fixture log')" \
    "$(printf 'delegate\tdocs/Delegated.md\tscripts/validate-delegated.sh')" \
    >"${ORIG}/reg.txt"

n=0
fresh() { n=$((n + 1)); rm -rf "${WORK}/t${n}"; cp -R "${ORIG}" "${WORK}/t${n}"; T="${WORK}/t${n}"; }

echo "=== test-doc-citations.sh (issue #582) ==="

fresh
expect "clean fixture" 0 "${T}"

fresh
sed -i '1i /* moved */' "${T}/src/lib/engine.c"
expect "the cited code slides down one line" 1 "${T}" "no longer holds 'int engine_start(void)'"

fresh
sed -i '6s/}/\/\/ end/' "${T}/src/lib/engine.c"
expect "a range's last line loses its tail needle" 1 "${T}" "line 6 no longer holds '}'"

fresh
sed -i 's/engine.c:3-6/engine.c:3-60/' "${T}/docs/Guide.md"
expect "a citation past the end of the file" 1 "${T}" "range outside the file (6 lines)"

fresh
printf '\nAlso `src/lib/engine.c:5`.\n' >>"${T}/docs/Guide.md"
expect "a citation no registry row anchors" 1 "${T}" "not registered in reg.txt"

fresh
printf 'cite\tdocs/Guide.md\tsrc/lib/engine.c:1\t#include\n' >>"${T}/reg.txt"
expect "a registry row the page no longer cites" 1 "${T}" "no longer cites src/lib/engine.c:1"

fresh
printf '\nShort form `engine.c:3`.\n' >>"${T}/docs/Guide.md"
expect "a bare basename instead of the repository path" 1 "${T}" "cite the full repository path"

fresh
printf '\nInstalled copy `sdk/include/engine.h:3`.\n' >>"${T}/docs/Guide.md"
expect "the generated sdk/include/ copy" 1 "${T}" "sdk/include/ is the generated copy"

fresh
printf '\nGone `src/lib/removed.c:3`.\n' >>"${T}/docs/Guide.md"
expect "a citation of a file that does not exist" 1 "${T}" "no such file from the repository root"

fresh
sed -i 's/Append-only log/Running log/' "${T}/docs/LOG.md"
expect "an exempt page that does not declare itself append-only" 1 "${T}" "do not declare it append-only"

fresh
rm "${T}/scripts/validate-delegated.sh"
expect "a delegated page whose script does not exist" 1 "${T}" "which does not exist"

fresh
sed -i 's/engine.c:1`/engine.c:70`/' "${T}/docs/Delegated.md"
expect "a delegated page citing past the end of a file" 1 "${T}" "range outside the file"

fresh
printf '\n```\nengine.c:42: warning: example output\n```\n\nImage `ubuntu:24.04`.\n' >>"${T}/docs/Guide.md"
expect "fenced compiler output and version strings are not citations" 0 "${T}"

fresh
printf '\n```c\nengine_start();  // src/lib/engine.c:5\n```\n' >>"${T}/docs/Guide.md"
expect "a repository path:N in fenced code is a citation" 1 "${T}" "not registered in reg.txt"

fresh
printf '\n[`engine.c:3`](https://github.com/o/r/blob/main/src/lib/engine.c#L3)\n' >>"${T}/docs/Guide.md"
expect "a basename linked to its blob path resolves" 0 "${T}"

fresh
printf 'cite\tdocs/Guide.md\n' >>"${T}/reg.txt"
expect "a malformed registry row" 2 "${T}" "malformed"

got=0
out="$(python3 "${CHECKER}" 2>&1)" || got=$?
if [ "${got}" -eq 0 ]; then
    pass "the real docs tree and tools/ci/doc-citations.txt"
else
    fail "the real docs tree and tools/ci/doc-citations.txt (exit ${got})"
    printf '%s\n' "${out}" | sed 's/^/      /' >&2
fi

echo ""
if [ "${failures}" -ne 0 ]; then
    echo "✗ ${failures} of ${checks} check(s) failed" >&2
    exit 1
fi
echo "✓ all ${checks} checks passed"
