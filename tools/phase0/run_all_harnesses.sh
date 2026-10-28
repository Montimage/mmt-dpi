#!/usr/bin/env bash
#
# run_all_harnesses.sh — one aggregate pass over every phase0 harness
# (issue #183, F-TEST-016). The phase0-baseline.yml `harness` legs run it
# with --group/--shard (issue #655), so it is the one enumeration of
# tools/phase0/tests/run_*.sh that CI and local runs share.
#
# Every harness script normally builds + installs the SDK itself into its own
# MMT_*_PREFIX — 24 harnesses, 24 builds. Under this runner each profile group
# is built ONCE into a shared mktemp prefix instead:
#
#   1. Enumerate tools/phase0/tests/run_*.sh (sorted).
#   2. Group them by the SDK profile their own build step would use, read
#      from each script's non-comment BUILD= line: "asan", "tsan", "default" (a make with
#      no BUILD= flag) or "none" (no SDK build at all — run_bitmask_oob_test
#      compiles header-only against the source tree).
#   3. Per non-"none" group: `make -C sdk clean` (the profile-switch clean
#      rule, docs/AGENT_ENVIRONMENT.md §5), then one
#      `make -C sdk [BUILD=<profile>] MMT_BASE=<prefix>` + `install`.
#   4. Run every harness with MMT_SDK_PREBUILT=1 (skips its build+install
#      block) and its MMT_*_PREFIX variable pointing at the group prefix.
#
# The build count is asserted in this log: every build emits a
# "sdk_build <n>: profile=<p>" line and the summary prints "sdk_builds=<n>"
# (one per profile group — 3 at time of writing: asan x42, tsan x1,
# default x6; the "none" group builds nothing). mt_tsan cannot share the asan
# prefix — its whole point is detecting races inside the SDK, which requires
# BUILD=tsan instrumentation — and run_oom_no_abort_test must run against a
# non-sanitized allocator, so "default" is its own group.
#
# --profile coverage (issue #524, F-TEST-006): the harness arm of
# `tests/run_all_tests.sh --coverage`. Instead of one build per profile
# group, ONE `make -C sdk clean` + `make -C sdk BUILD=coverage` + install
# into a shared prefix, and every harness — whatever its own profile — runs
# against it, except the COVERAGE_SKIP list below (each with its reason).
# The skipped count is printed; every other harness failure is fatal. The
# counters stay next to the in-tree objects under src/ (the EXIT trap's
# `make -C sdk clean` does not delete .gcda/.gcno), so the caller harvests
# them afterwards. The option is explicit, never read from
# SDK_BUILD_PROFILE: the --with-harnesses arm must keep its own profiles.
#
# Selecting and sharding (issue #655): the phase0-baseline.yml `harness`
# jobs each run one slice of the enumeration, so a CI run builds one SDK per
# slice instead of one per harness. The selection is applied to the sorted
# enumeration before grouping, in this order:
#   --group G[,G...]  keep the harnesses whose profile group (none, default,
#                     asan, tsan — the profile_of classification below) is
#                     listed; repeatable.
#   --shard K/N       of what is left, keep every N-th harness starting at
#                     the K-th (1 <= K <= N): the N shards of one selection
#                     are disjoint and together cover it, whatever is added.
# --list prints the harnesses the selection would run, one "<group> <harness>"
# line each (group "coverage" under --profile coverage, COVERAGE_SKIP
# applied), and exits without building. An empty selection runs nothing and
# exits 0. --log-dir DIR keeps each harness's output in DIR/<harness>.log,
# each SDK build's output in DIR/sdk-build-<profile>.log and the verdict
# table in DIR/verdicts.tsv; without it they go to a temporary directory
# removed on exit. Under GitHub Actions each harness's output is a collapsed
# log group, a failure is an ::error annotation naming the harness, and the
# verdict table is appended to $GITHUB_STEP_SUMMARY.
#
# Usage: tools/phase0/run_all_harnesses.sh [--profile coverage]
#            [--group G[,G...]]... [--shard K/N] [--list] [--log-dir DIR]
# Exit: 0 when every (non-skipped) selected harness passes; 1 on any harness
#       failure; 2 on setup failure (bad argument, no harnesses found, a
#       COVERAGE_SKIP entry naming no harness, SDK build failed).
set -euo pipefail

USAGE="usage: run_all_harnesses.sh [--profile coverage] [--group G[,G...]] [--shard K/N] [--list] [--log-dir DIR]"
MODE=default
GROUPS_SEL=()
SHARD_K=1
SHARD_N=1
LIST_ONLY=0
LOG_DIR=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --profile)
            [ "${2:-}" = coverage ] || { echo "✗ --profile takes 'coverage' (got '${2:-}')" >&2; exit 2; }
            MODE=coverage
            shift 2 ;;
        --group)
            [ -n "${2:-}" ] || { echo "✗ --group takes a group list (${USAGE})" >&2; exit 2; }
            IFS=, read -r -a _groups <<< "$2"
            for g in "${_groups[@]}"; do
                case "${g}" in
                    none|default|asan|tsan) GROUPS_SEL+=("${g}") ;;
                    *) echo "✗ --group: unknown group '${g}' (none, default, asan, tsan)" >&2; exit 2 ;;
                esac
            done
            shift 2 ;;
        --shard)
            if [[ ! "${2:-}" =~ ^([1-9][0-9]*)/([1-9][0-9]*)$ ]] \
               || [ "${BASH_REMATCH[1]}" -gt "${BASH_REMATCH[2]}" ]; then
                echo "✗ --shard takes K/N with 1 <= K <= N (got '${2:-}')" >&2
                exit 2
            fi
            SHARD_K="${BASH_REMATCH[1]}"
            SHARD_N="${BASH_REMATCH[2]}"
            shift 2 ;;
        --list)
            LIST_ONLY=1
            shift ;;
        --log-dir)
            case "${2:-}" in
                ''|-*) echo "✗ --log-dir takes a directory (${USAGE})" >&2; exit 2 ;;
            esac
            LOG_DIR="$2"
            shift 2 ;;
        *) echo "✗ unknown argument: $1 (${USAGE})" >&2
           exit 2 ;;
    esac
done

# Harnesses --profile coverage does not run, with the reason. The first three
# assert debug counters that only assert-enabled or sanitizer builds arm
# (`#if !defined(NDEBUG) || defined(MMT_BUILD_ASAN)`, e.g.
# src/mmt_core/src/packet_pipeline.c); BUILD=coverage keeps the release
# -DNDEBUG (rules/common.mk), so they are compiled out. mt_tsan refuses an
# SDK that is not BUILD=tsan.
COVERAGE_SKIP=(
    "run_classified_flow_fastpath_test.sh|asserts fast-path debug counters, compiled out of BUILD=coverage (-DNDEBUG)"
    "run_position_unknown_guard_test.sh|asserts guard debug counters, compiled out of BUILD=coverage (-DNDEBUG)"
    "run_session_lookup_perf_test.sh|asserts lookup debug counters, compiled out of BUILD=coverage (-DNDEBUG)"
    "run_mt_tsan_test.sh|refuses an SDK that is not BUILD=tsan (race detection needs TSan instrumentation)"
)

PHASE0_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="${PHASE0_DIR}/tests"
REPO_ROOT="$(cd "${PHASE0_DIR}/../.." && pwd)"

# --- enumeration --------------------------------------------------------------
mapfile -t HARNESSES < <(find "${TEST_DIR}" -maxdepth 1 -name 'run_*.sh' -printf '%f\n' | sort)
if [ "${#HARNESSES[@]}" -eq 0 ]; then
    echo "✗ no run_*.sh harnesses found under ${TEST_DIR}" >&2
    exit 2
fi

# profile_of <script> — the SDK build profile the harness's own build step
# would use, or "none" when it never builds the SDK. Comment lines are not
# read: run_tcp_reassembly_perf_test.sh mentions BUILD=asan only in its
# header, and builds (so groups) default (issue #655).
profile_of() {
    local code
    code="$(grep -v '^[[:space:]]*#' "$1" || true)"
    if grep -q 'BUILD=tsan' <<< "${code}"; then
        echo tsan
    elif grep -q 'BUILD=asan' <<< "${code}"; then
        echo asan
    elif grep -q 'make -C .*sdk' <<< "${code}"; then
        echo default
    else
        echo none
    fi
}

# prefix_var_of <script> — the MMT_*_PREFIX override variable the harness
# reads (empty when it has none).
prefix_var_of() {
    grep -o 'MMT_[A-Z_]*_PREFIX' "$1" | head -n 1 || true
}

# --- selection (--group, then --shard) -----------------------------------------
declare -A PROFILE=()
SELECTED=()
for h in "${HARNESSES[@]}"; do
    PROFILE["${h}"]="$(profile_of "${TEST_DIR}/${h}")"
    if [ "${#GROUPS_SEL[@]}" -gt 0 ]; then
        keep=0
        for g in "${GROUPS_SEL[@]}"; do [ "${PROFILE[${h}]}" = "${g}" ] && keep=1; done
        [ "${keep}" -eq 1 ] || continue
    fi
    SELECTED+=("${h}")
done
if [ "${SHARD_N}" -gt 1 ]; then
    sharded=()
    for i in "${!SELECTED[@]}"; do
        [ $((i % SHARD_N + 1)) -eq "${SHARD_K}" ] && sharded+=("${SELECTED[${i}]}")
    done
    SELECTED=("${sharded[@]}")
fi

# --- run plan: (group, harness) pairs in run order ------------------------------
PLAN_GROUPS=()
PLAN_HARNESSES=()
SKIPPED=0
SKIP_LINES=()
if [ "${MODE}" = coverage ]; then
    # Every skip entry must name an enumerated harness: a renamed one would
    # otherwise silently start running (or a typo silently skip nothing).
    declare -A skip_reason=()
    for entry in "${COVERAGE_SKIP[@]}"; do
        name="${entry%%|*}"
        if [ -z "${PROFILE[${name}]:-}" ]; then
            echo "✗ COVERAGE_SKIP names ${name}, which is not under ${TEST_DIR}" >&2
            exit 2
        fi
        skip_reason["${name}"]="${entry#*|}"
    done
    for h in "${SELECTED[@]}"; do
        if [ -n "${skip_reason[${h}]:-}" ]; then
            SKIP_LINES+=("  skip ${h}: ${skip_reason[${h}]}")
            SKIPPED=$((SKIPPED + 1))
        else
            PLAN_GROUPS+=(coverage)
            PLAN_HARNESSES+=("${h}")
        fi
    done
else
    # Fixed group order keeps the log deterministic. "none" first: it needs
    # no build, so it runs even when the tree starts dirty.
    for profile in none default asan tsan; do
        for h in "${SELECTED[@]}"; do
            if [ "${PROFILE[${h}]}" = "${profile}" ]; then
                PLAN_GROUPS+=("${profile}")
                PLAN_HARNESSES+=("${h}")
            fi
        done
    done
fi

if [ "${LIST_ONLY}" -eq 1 ]; then
    for i in "${!PLAN_HARNESSES[@]}"; do
        echo "${PLAN_GROUPS[${i}]} ${PLAN_HARNESSES[${i}]}"
    done
    exit 0
fi

WORK_ROOT="$(mktemp -d /tmp/mmt-harness-run.XXXXXX)"
cleanup() {
    rm -rf "${WORK_ROOT}"
    # Leave the sdk tree neutral for whatever runs next (the same profile-
    # switch clean rule the group builds apply between profiles).
    make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
}
trap cleanup EXIT

[ -n "${LOG_DIR}" ] || LOG_DIR="${WORK_ROOT}/logs"
mkdir -p -- "${LOG_DIR}"
LOG_DIR="$(cd -- "${LOG_DIR}" && pwd)"
GHA=0
[ "${GITHUB_ACTIONS:-}" = true ] && GHA=1

selection="all"
[ "${#GROUPS_SEL[@]}" -gt 0 ] && selection="group $(IFS=,; echo "${GROUPS_SEL[*]}")"
[ "${SHARD_N}" -gt 1 ] && selection="${selection}, shard ${SHARD_K}/${SHARD_N}"

echo "============================================"
echo "  Phase0 harness runner (aggregate)"
echo "============================================"
echo "  harnesses enumerated: ${#HARNESSES[@]} (tools/phase0/tests/run_*.sh)"
echo "  selected:             ${#SELECTED[@]} (${selection})"
echo "  logs:                 ${LOG_DIR}"
echo ""
if [ "${#SKIP_LINES[@]}" -gt 0 ]; then
    printf '%s\n' "${SKIP_LINES[@]}"
    echo ""
fi

PASS=0
FAIL=0
BUILDS=0
FAILED=()
VERDICTS=()   # "verdict<TAB>seconds<TAB>group<TAB>harness"

# build_sdk <profile> <count> — one clean build + install of the profile into
# its shared prefix; its output goes to the log directory, and its tail is
# printed when it fails (exit 2).
build_sdk() {
    local profile="$1" count="$2"
    local prefix="${WORK_ROOT}/${profile}"
    local build_flag=()
    local log="${LOG_DIR}/sdk-build-${profile}.log"
    [ "${profile}" != "default" ] && build_flag=("BUILD=${profile}")
    echo "== SDK build ${profile}: make -C sdk ${build_flag[*]:-} MMT_BASE=${prefix} (shared by ${count} harness(es))"
    if ! { make -C "${REPO_ROOT}/sdk" clean \
           && make -C "${REPO_ROOT}/sdk" "${build_flag[@]}" MMT_BASE="${prefix}" -j"$(nproc)" \
           && make -C "${REPO_ROOT}/sdk" "${build_flag[@]}" MMT_BASE="${prefix}" install; } \
           >"${log}" 2>&1; then
        echo "✗ SDK build ${profile} failed — last lines of ${log}:" >&2
        tail -n 40 "${log}" >&2
        [ "${GHA}" -eq 1 ] && echo "::error title=phase0 SDK build failed::profile ${profile}; see sdk-build-${profile}.log"
        exit 2
    fi
    BUILDS=$((BUILDS + 1))
    echo "   sdk_build ${BUILDS}: profile=${profile} prefix=${prefix}"
    echo ""
}

# run_harness <group> <harness> — replay one harness against its group's
# prefix with MMT_SDK_PREBUILT=1, tee'ing its output to its own log.
run_harness() {
    local group="$1" h="$2"
    local prefix="" var rc start secs verdict
    [ "${group}" != "none" ] && prefix="${WORK_ROOT}/${group}"
    var="$(prefix_var_of "${TEST_DIR}/${h}")"
    if [ -n "${var}" ] && [ -n "${prefix}" ]; then
        export "${var}=${prefix}"
    fi
    [ "${GHA}" -eq 1 ] && echo "::group::${h} (profile: ${group})"
    echo "--- Running: ${h} (profile: ${group}) ---"
    start=${SECONDS}
    set +e
    MMT_SDK_PREBUILT=1 bash "${TEST_DIR}/${h}" 2>&1 | tee "${LOG_DIR}/${h}.log"
    rc=${PIPESTATUS[0]}
    set -e
    secs=$((SECONDS - start))
    [ "${GHA}" -eq 1 ] && echo "::endgroup::"
    if [ "${rc}" -eq 0 ]; then
        echo "  ✓ ${h}: PASSED (${secs}s)"
        PASS=$((PASS + 1))
        verdict=PASS
    else
        echo "  ✗ ${h}: FAILED (rc=${rc}, ${secs}s)"
        [ "${GHA}" -eq 1 ] && echo "::error title=phase0 harness failed::${h} failed (rc=${rc}); log: ${h}.log"
        FAIL=$((FAIL + 1))
        FAILED+=("${h}")
        verdict=FAIL
    fi
    VERDICTS+=("${verdict}"$'\t'"${secs}"$'\t'"${group}"$'\t'"${h}")
    [ -n "${var}" ] && unset "${var}"
    echo ""
}

current=""
for i in "${!PLAN_HARNESSES[@]}"; do
    group="${PLAN_GROUPS[${i}]}"
    if [ "${group}" != "${current}" ]; then
        current="${group}"
        if [ "${group}" != "none" ]; then
            count=0
            for g in "${PLAN_GROUPS[@]}"; do [ "${g}" = "${group}" ] && count=$((count + 1)); done
            build_sdk "${group}" "${count}"
        fi
    fi
    run_harness "${group}" "${PLAN_HARNESSES[${i}]}"
done

{
    printf 'verdict\tseconds\tprofile\tharness\n'
    [ "${#VERDICTS[@]}" -gt 0 ] && printf '%s\n' "${VERDICTS[@]}"
} > "${LOG_DIR}/verdicts.tsv"

echo "============================================"
echo "  Phase0 harness results"
echo "============================================"
[ "${#SELECTED[@]}" -eq 0 ] && echo "  (no harness selected: ${selection})"
if [ "${#VERDICTS[@]}" -gt 0 ]; then
    awk -F'\t' '{ printf "  %-8s %7s  %-8s %s\n", $1, $2, $3, $4 }' "${LOG_DIR}/verdicts.tsv"
fi
echo "  harnesses:  ${#HARNESSES[@]}"
echo "  selected:   ${#SELECTED[@]}"
echo "  passed:     ${PASS}"
echo "  failed:     ${FAIL}"
echo "  sdk_builds: ${BUILDS}"
[ "${MODE}" = coverage ] && echo "  skipped:    ${SKIPPED} (COVERAGE_SKIP, profile coverage)"
if [ "${#FAILED[@]}" -gt 0 ]; then
    for h in "${FAILED[@]}"; do
        echo "    ✗ ${h}"
    done
fi
echo "============================================"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### Phase0 harnesses (${selection}): ${PASS} passed, ${FAIL} failed"
        echo ""
        echo "| Verdict | Seconds | Profile | Harness |"
        echo "|---------|--------:|---------|---------|"
        for v in "${VERDICTS[@]}"; do
            IFS=$'\t' read -r verdict secs group h <<< "${v}"
            echo "| ${verdict} | ${secs} | ${group} | \`${h}\` |"
        done
    } >> "${GITHUB_STEP_SUMMARY}"
fi

[ "${FAIL}" -eq 0 ]
