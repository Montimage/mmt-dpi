#!/usr/bin/env bash
#
# test-sdk-coverage.sh — self-test for the SDK integration coverage path of
# `bash tests/run_all_tests.sh --coverage` (issue #387, F-TEST-004).
#
# It drives the REAL pieces the runner uses:
#
#   - the BUILD=coverage SDK profile (rules/common.mk), built and installed
#     into a throwaway prefix, exactly as an SDK-building suite does;
#   - a tiny consumer (NOT instrumented itself) compiled against the
#     installed public headers, which calls mmt_version() (libmmt_core) and
#     s1ap_entities_count() (libmmt_tmobile) only when argv[1] is `call`;
#   - tools/ci/sdk-coverage.sh `harvest` and `report`.
#
# Each consumer run writes its counters under GCOV_PREFIX=$WORK/gcda-<run>
# (GCOV_PREFIX_STRIP drops the physical repo root), so the controlled hits
# never land in src/ where the runner's own harvest would pick them up. The
# install prefix is deleted BEFORE harvesting: the counters must survive it.
#
# Scenario -> expected result:
#   consumer run `call`                   -> both functions hit >= 1
#   consumer run `nocall` (call removed)  -> both functions hit == 0
#   prefix deleted before the harvest     -> counters still harvested
#   harvest --consume                     -> harvested .gcda removed
#   real harvest through `report`         -> asn1c rows only in generated_asn1c
#   synthetic logical/physical/relative   -> each source counted once in
#     spellings of one path                  combined, counts summed
#   every cohort                          -> non-empty denominator
#   report on an existing summary.json    -> top-level keys unchanged; the
#                                            floor gate still reads them
#
# SDK_BUILD_PROFILE / EXTRA_CFLAGS from the runner (SANITIZE=asan|tsan,
# --coverage) are ignored: the self-test always builds its own coverage
# profile, and it leaves a clean sdk/ tree (make clean) behind.
#
# Usage: bash tools/ci/tests/test-sdk-coverage.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
REPO_PHYS="$(cd "${REPO_ROOT}" && pwd -P)"
HELPER="${REPO_ROOT}/tools/ci/sdk-coverage.sh"
FLOOR_GATE="${REPO_ROOT}/tools/ci/check-coverage-floor.sh"
[ -f "${HELPER}" ] || { echo "✗ missing ${HELPER}" >&2; exit 2; }
[ -f "${FLOOR_GATE}" ] || { echo "✗ missing ${FLOOR_GATE}" >&2; exit 2; }

for tool in gcc gcov make jq; do
    command -v "${tool}" >/dev/null 2>&1 \
        || { echo "✗ test-sdk-coverage.sh requires '${tool}'" >&2; exit 2; }
done
gcov --help 2>/dev/null | grep -q -- '--json-format' \
    || { echo "✗ gcov has no --json-format (needs GCC >= 9)" >&2; exit 2; }

unset SDK_BUILD_PROFILE EXTRA_CFLAGS
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
WORK="$(mktemp -d)"
PREFIX="$(mktemp -d)"
cleanup() {
    rm -rf "${WORK}" "${PREFIX}"
    # Never leave a coverage-profile tree behind: a later plain `make -C sdk`
    # would relink these objects (rules/common.mk:467-469).
    make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
    find "${REPO_PHYS}/src" \( -name '*.gcda' -o -name '*.gcno' \) -delete 2>/dev/null || true
}
trap cleanup EXIT

# --- harness -----------------------------------------------------------------
PASS=0
FAIL=0
TESTED=0

check() {
    # $1 = check name, $2 = detail on success, remaining = command to test.
    local name="$1" detail="$2"
    shift 2
    TESTED=$((TESTED + 1))
    if "$@" >"${WORK}/check.log" 2>&1; then
        PASS=$((PASS + 1)); printf '  ✓ %-56s %s\n' "${name}" "${detail}"
    else
        FAIL=$((FAIL + 1)); printf '  ✗ %-56s\n' "${name}"
        sed 's/^/      | /' "${WORK}/check.log" | tail -15
    fi
}

hits() {
    # $1 = harvest dir, $2 = repo-relative source, $3 = function; prints the
    # summed execution count, or "missing" when no record names it.
    awk -F'\t' -v f="$2" -v fn="$3" '
        $1 == f && $2 == fn { n += $3; seen = 1 }
        END { if (seen) print n + 0; else print "missing" }' "$1/functions.tsv"
}

expect_hits() {
    # $1 = harvest dir, $2 = source, $3 = function, $4 = ge1|zero.
    local got
    got="$(hits "$1" "$2" "$3")"
    echo "$3 in $2: ${got}"
    [ "${got}" != "missing" ] || return 1
    case "$4" in
        ge1)  [ "${got}" -ge 1 ] ;;
        zero) [ "${got}" -eq 0 ] ;;
    esac
}

jq_true() {
    # $1 = JSON file, $2 = jq expression that must evaluate to true.
    jq -e "$2" "$1"
}

echo "SDK integration coverage self-test (issue #387, F-TEST-004)"
echo ""

# --- instrumented SDK in a throwaway prefix ----------------------------------
echo "  building the SDK with BUILD=coverage into a throwaway prefix ..."
if ! { make -C "${REPO_ROOT}/sdk" clean \
        && make -C "${REPO_ROOT}/sdk" BUILD=coverage MMT_BASE="${PREFIX}" -j"${JOBS}" \
        && make -C "${REPO_ROOT}/sdk" BUILD=coverage MMT_BASE="${PREFIX}" install; } \
        >"${WORK}/build.log" 2>&1; then
    echo "✗ BUILD=coverage SDK build/install failed" >&2
    tail -30 "${WORK}/build.log" >&2
    exit 2
fi

cat >"${WORK}/consumer.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include "mmt_core.h"
#include "mobile/proto_s1ap.h"

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "call") == 0) {
        printf("mmt_version=%s s1ap_entities=%u\n",
               mmt_version(), (unsigned) s1ap_entities_count());
    } else {
        puts("no SDK call");
    }
    return 0;
}
EOF
if ! gcc -Wall -Wextra -O0 -I"${PREFIX}/dpi/include" -o "${WORK}/consumer" \
        "${WORK}/consumer.c" -L"${PREFIX}/dpi/lib" -lmmt_tmobile -lmmt_core \
        >"${WORK}/cc.log" 2>&1; then
    echo "✗ consumer compile failed" >&2
    cat "${WORK}/cc.log" >&2
    exit 2
fi

strip_n="$(printf '%s' "${REPO_PHYS}" | tr -cd '/' | wc -c)"
for run in call nocall; do
    if ! (cd "${WORK}" && GCOV_PREFIX="${WORK}/gcda-${run}" GCOV_PREFIX_STRIP="${strip_n}" \
            LD_LIBRARY_PATH="${PREFIX}/dpi/lib" ./consumer "${run}" >"${WORK}/run-${run}.log" 2>&1); then
        echo "✗ consumer run '${run}' failed" >&2
        cat "${WORK}/run-${run}.log" >&2
        exit 2
    fi
done

# The prefix goes away before anything is harvested, as in every SDK suite.
rm -rf "${PREFIX}"
check "install prefix deleted before the harvest" "gone" test ! -e "${PREFIX}"
check "controlled hits kept out of src/ (GCOV_PREFIX)" "0 .gcda under src/" \
    bash -c "[ -z \"\$(find '${REPO_PHYS}/src' -name '*.gcda' -print -quit)\" ]"

for run in call nocall; do
    consume=()
    [ "${run}" = nocall ] && consume=(--consume)
    if ! bash "${HELPER}" harvest --gcda-root "${WORK}/gcda-${run}" \
            --gcno-root "${REPO_PHYS}" --repo-root "${REPO_ROOT}" \
            --out "${WORK}/harvest/${run}" "${consume[@]}" >"${WORK}/harvest-${run}.log" 2>&1; then
        echo "✗ harvest of run '${run}' failed" >&2
        cat "${WORK}/harvest-${run}.log" >&2
        exit 2
    fi
done

H_CALL="${WORK}/harvest/call"
H_NOCALL="${WORK}/harvest/nocall"
check "counters survived prefix cleanup" "$(wc -l <"${H_CALL}/lines.tsv") line rows" \
    test -s "${H_CALL}/lines.tsv"
check "call: mmt_version() hit (libmmt_core)" ">= 1" \
    expect_hits "${H_CALL}" src/mmt_core/src/packet_processing.c mmt_version ge1
check "call: s1ap_entities_count() hit (libmmt_tmobile)" ">= 1" \
    expect_hits "${H_CALL}" src/mmt_mobile/proto_s1ap.c s1ap_entities_count ge1
check "call removed: mmt_version() back to zero" "== 0" \
    expect_hits "${H_NOCALL}" src/mmt_core/src/packet_processing.c mmt_version zero
check "call removed: s1ap_entities_count() back to zero" "== 0" \
    expect_hits "${H_NOCALL}" src/mmt_mobile/proto_s1ap.c s1ap_entities_count zero
check "harvest --consume removes the harvested .gcda" "0 left" \
    bash -c "[ -z \"\$(find '${WORK}/gcda-nocall' -name '*.gcda' -print -quit)\" ]"
check "harvest rows are repo-relative src/ paths" "src/..." \
    bash -c "! cut -f1 '${H_CALL}/lines.tsv' | grep -qv '^src/'"

# --- report over the real harvest ---------------------------------------------
: >"${WORK}/unit-empty.tsv"
echo '{"library_line_pct": 0, "instrumented_files": 0}' >"${WORK}/real-summary.json"
mkdir -p "${WORK}/real-harvest"
cp -r "${H_CALL}" "${WORK}/real-harvest/consumer"
check "report over the real harvest" "exit 0" \
    bash "${HELPER}" report --unit-tsv "${WORK}/unit-empty.tsv" \
        --harvest-dir "${WORK}/real-harvest" --repo-root "${REPO_ROOT}" \
        --summary "${WORK}/real-summary.json"
# shellcheck disable=SC2016  # $c is a jq variable, not a shell expansion
check "generated ASN.1 reached, counted only in generated_asn1c" "prefix src/mmt_mobile/asn1c/" \
    jq_true "${WORK}/real-summary.json" '
        .cohorts as $c
        | ($c.generated_asn1c.files > 0)
          and ($c.generated_asn1c.sources | all(startswith("src/mmt_mobile/asn1c/")))
          and ([$c.unit, $c.sdk_integration, $c.combined][]
               | .sources | all(startswith("src/mmt_mobile/asn1c/") | not))'
check "mobile handwritten source in sdk_integration" "proto_s1ap.c" \
    jq_true "${WORK}/real-summary.json" \
        '.cohorts.sdk_integration.sources | index("src/mmt_mobile/proto_s1ap.c") != null'

# --- report over synthetic rows: dedup, denominators, top-level keys ----------
FAKE="${WORK}/fake"
mkdir -p "${FAKE}/real/src" "${WORK}/syn-harvest/suite_a" "${WORK}/syn-harvest/suite_b"
ln -s "${FAKE}/real" "${FAKE}/link"
{
    printf '%s\t1\t1\n' "${FAKE}/link/src/a.c"
    printf '%s\t1\t2\n' "${FAKE}/real/src/a.c"
    printf '%s\t2\t0\n' "${FAKE}/real/src/a.c"
    printf '%s\t5\t1\n' "${FAKE}/link/src/mmt_mobile/asn1c/common/x.c"
    printf '%s\t9\t1\n' "${FAKE}/link/tests/t.c"
} >"${WORK}/syn-unit.tsv"
printf 'src/a.c\t2\t3\nsrc/b.c\t1\t0\nsrc/mmt_mobile/asn1c/ngap/y.c\t7\t0\n' \
    >"${WORK}/syn-harvest/suite_a/lines.tsv"
printf 'src/a.c\t1\t1\n' >"${WORK}/syn-harvest/suite_b/lines.tsv"
jq -n '{library_line_pct: 50.0, instrumented_files: 1,
        instrumented_sources: ["src/a.c"],
        library_lines_hit: 1, library_lines_total: 2, scope: "src/"}' \
    >"${WORK}/syn-summary.json"
cp "${WORK}/syn-summary.json" "${WORK}/syn-before.json"
check "report over synthetic rows" "exit 0" \
    bash "${HELPER}" report --unit-tsv "${WORK}/syn-unit.tsv" \
        --harvest-dir "${WORK}/syn-harvest" --repo-root "${FAKE}/link" \
        --summary "${WORK}/syn-summary.json" --combined-info "${WORK}/combined.info"
S="${WORK}/syn-summary.json"
check "top-level unit keys unchanged by the cohorts" "identical" \
    bash -c "jq -S 'del(.cohorts)' '${S}' | diff - <(jq -S . '${WORK}/syn-before.json')"
check "floor gate still reads the top-level keys" "check-coverage-floor.sh exit 0" \
    bash -c "echo '{\"library_line_pct\": 50.0, \"instrumented_files\": 1,
                    \"required_instrumented_files\": [\"src/a.c\"]}' >'${WORK}/floor.json' \
             && bash '${FLOOR_GATE}' '${S}' '${WORK}/floor.json'"
check "every cohort states a denominator" "4 cohorts" \
    jq_true "${S}" '.cohorts | (keys == ["combined", "generated_asn1c", "sdk_integration", "unit"])
        and all(.[]; (.denominator | type == "string" and length > 0))'
check "unit: logical+physical spellings deduplicated" "src/a.c once, 1/2 lines" \
    jq_true "${S}" '.cohorts.unit | .sources == ["src/a.c"] and .lines_total == 2 and .lines_hit == 1'
check "sdk_integration: union of suites + per-suite rows" "2 suites, 2/3 lines" \
    jq_true "${S}" '.cohorts.sdk_integration
        | .sources == ["src/a.c", "src/b.c"] and .lines_total == 3 and .lines_hit == 2
          and ([.suites[].suite] == ["suite_a", "suite_b"])'
check "combined: one record per path+line, counts summed" "2 files, 2/3 lines" \
    jq_true "${S}" '.cohorts.combined
        | .sources == ["src/a.c", "src/b.c"] and .lines_total == 3 and .lines_hit == 2
          and (.dedup | length > 0)'
check "generated_asn1c: separate and excluded elsewhere" "2 files, 1/2 lines" \
    jq_true "${S}" '.cohorts.generated_asn1c
        | .prefix == "src/mmt_mobile/asn1c/" and .lines_total == 2 and .lines_hit == 1
          and .excluded_from == ["unit", "sdk_integration", "combined"]'
check "non-src/ rows ignored" "tests/t.c dropped" \
    jq_true "${S}" '[.cohorts[].sources[]] | all(startswith("src/"))'
check "combined tracefile has one SF per source" "2 SF records" \
    bash -c "[ \"\$(grep -c '^SF:' '${WORK}/combined.info')\" -eq 2 ] \
             && grep -qx 'SF:${FAKE}/link/src/a.c' '${WORK}/combined.info' \
             && grep -qx 'DA:1,4' '${WORK}/combined.info'"

echo ""
echo "SDK coverage self-test: ${PASS} passed, ${FAIL} failed (${TESTED} checks)"
[ "${FAIL}" -eq 0 ]
