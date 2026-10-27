#!/usr/bin/env bash
#
# run_all_harnesses.sh — one aggregate pass over every phase0 harness
# (issue #183, F-TEST-016; shares the tools/phase0/tests/run_*.sh enumeration
# with the phase0-baseline workflow matrix from issue #182).
#
# Every harness script normally builds + installs the SDK itself into its own
# MMT_*_PREFIX — 24 harnesses, 24 builds. Under this runner each profile group
# is built ONCE into a shared mktemp prefix instead:
#
#   1. Enumerate tools/phase0/tests/run_*.sh (sorted — the same glob the
#      phase0-baseline.yml `list-harnesses` job expands).
#   2. Group them by the SDK profile their own build step would use, read
#      from each script's BUILD= line: "asan", "tsan", "default" (a make with
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
# (one per profile group — 3 at time of writing: asan x23, tsan x1,
# default x2; the "none" group builds nothing). mt_tsan cannot share the asan
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
# Usage: tools/phase0/run_all_harnesses.sh [--profile coverage]
# Exit: 0 when every (non-skipped) harness passes; 1 on any harness failure;
#       2 on setup failure (bad argument, no harnesses found, a
#       COVERAGE_SKIP entry naming no harness, SDK build failed).
set -euo pipefail

MODE=default
while [ "$#" -gt 0 ]; do
    case "$1" in
        --profile)
            [ "${2:-}" = coverage ] || { echo "✗ --profile takes 'coverage' (got '${2:-}')" >&2; exit 2; }
            MODE=coverage
            shift 2 ;;
        *) echo "✗ unknown argument: $1 (usage: run_all_harnesses.sh [--profile coverage])" >&2
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

WORK_ROOT="$(mktemp -d /tmp/mmt-harness-run.XXXXXX)"
cleanup() {
    rm -rf "${WORK_ROOT}"
    # Leave the sdk tree neutral for whatever runs next (the same profile-
    # switch clean rule the group builds apply between profiles).
    make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- enumeration --------------------------------------------------------------
mapfile -t HARNESSES < <(find "${TEST_DIR}" -maxdepth 1 -name 'run_*.sh' -printf '%f\n' | sort)
if [ "${#HARNESSES[@]}" -eq 0 ]; then
    echo "✗ no run_*.sh harnesses found under ${TEST_DIR}" >&2
    exit 2
fi

# profile_of <script> — the SDK build profile the harness's own build step
# would use, or "none" when it never builds the SDK.
profile_of() {
    local script="$1"
    if grep -q 'BUILD=tsan' "${script}"; then
        echo tsan
    elif grep -q 'BUILD=asan' "${script}"; then
        echo asan
    elif grep -q 'make -C .*sdk' "${script}"; then
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

echo "============================================"
echo "  Phase0 harness runner (aggregate)"
echo "============================================"
echo "  harnesses enumerated: ${#HARNESSES[@]} (tools/phase0/tests/run_*.sh)"
echo ""

PASS=0
FAIL=0
BUILDS=0
FAILED=()

# run_group <profile> <harness...> — build the profile once into a shared
# prefix (unless profile "none"), then replay every member against it.
run_group() {
    local profile="$1"
    shift
    [ "$#" -eq 0 ] && return 0

    local prefix=""
    if [ "${profile}" != "none" ]; then
        prefix="${WORK_ROOT}/${profile}"
        local build_flag=()
        [ "${profile}" != "default" ] && build_flag=("BUILD=${profile}")
        echo "== SDK build ${profile}: make -C sdk ${build_flag[*]:-} MMT_BASE=${prefix} (shared by $# harness(es))"
        make -C "${REPO_ROOT}/sdk" clean >/dev/null
        make -C "${REPO_ROOT}/sdk" "${build_flag[@]}" MMT_BASE="${prefix}" -j"$(nproc)" >/dev/null
        make -C "${REPO_ROOT}/sdk" "${build_flag[@]}" MMT_BASE="${prefix}" install >/dev/null
        BUILDS=$((BUILDS + 1))
        echo "   sdk_build ${BUILDS}: profile=${profile} prefix=${prefix}"
        echo ""
    fi

    local h var rc
    for h in "$@"; do
        echo "--- Running: ${h} (profile: ${profile}) ---"
        var="$(prefix_var_of "${TEST_DIR}/${h}")"
        if [ -n "${var}" ] && [ -n "${prefix}" ]; then
            export "${var}=${prefix}"
        fi
        rc=0
        MMT_SDK_PREBUILT=1 bash "${TEST_DIR}/${h}" || rc=$?
        if [ "${rc}" -eq 0 ]; then
            echo "  ✓ ${h}: PASSED"
            PASS=$((PASS + 1))
        else
            echo "  ✗ ${h}: FAILED (rc=${rc})"
            FAIL=$((FAIL + 1))
            FAILED+=("${h}")
        fi
        [ -n "${var}" ] && unset "${var}"
        echo ""
    done
}

SKIPPED=0
if [ "${MODE}" = coverage ]; then
    # Every skip entry must name an enumerated harness: a renamed one would
    # otherwise silently start running (or a typo silently skip nothing).
    declare -A skip_reason=()
    for entry in "${COVERAGE_SKIP[@]}"; do
        name="${entry%%|*}"
        found=0
        for h in "${HARNESSES[@]}"; do [ "${h}" = "${name}" ] && found=1; done
        if [ "${found}" -eq 0 ]; then
            echo "✗ COVERAGE_SKIP names ${name}, which is not under ${TEST_DIR}" >&2
            exit 2
        fi
        skip_reason["${name}"]="${entry#*|}"
    done
    members=()
    for h in "${HARNESSES[@]}"; do
        if [ -n "${skip_reason[${h}]:-}" ]; then
            echo "  skip ${h}: ${skip_reason[${h}]}"
            SKIPPED=$((SKIPPED + 1))
        else
            members+=("${h}")
        fi
    done
    echo ""
    run_group coverage "${members[@]}"
else
    # Fixed group order keeps the log deterministic. "none" first: it needs
    # no build, so it runs even when the tree starts dirty.
    for profile in none default asan tsan; do
        members=()
        for h in "${HARNESSES[@]}"; do
            [ "$(profile_of "${TEST_DIR}/${h}")" = "${profile}" ] && members+=("${h}")
        done
        run_group "${profile}" "${members[@]}"
    done
fi

echo "============================================"
echo "  Phase0 harness results"
echo "============================================"
echo "  harnesses:  ${#HARNESSES[@]}"
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

[ "${FAIL}" -eq 0 ]
