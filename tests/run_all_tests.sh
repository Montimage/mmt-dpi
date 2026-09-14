#!/bin/bash
# Master test runner for all test suites
# Usage: ./run_all_tests.sh [--coverage] [--with-harnesses] [suite ...]
#   With no arguments, runs every suite below. Pass one or more suite names
#   (directory names under tests/) to run only those — e.g. CI runs just the
#   core suites under EXTRA_CFLAGS=-fsigned-char.
#
# Modes:
#   --coverage      Compile the suites with gcov instrumentation, then emit a
#                   machine-readable lcov-format tracefile at
#                   tests/coverage/coverage.info restricted to library sources
#                   (src/ — test files under tests/ are excluded so the number
#                   means the library, issue #185), print the library-only
#                   line-coverage percentage and instrumented-file count, and
#                   write both to tests/coverage/summary.json. Needs gcov
#                   (shipped with gcc) and jq.
#   SANITIZE=asan   Compile the suites with AddressSanitizer + UBSan, mirroring
#                   the SDK's BUILD=asan profile (rules/common.mk). Suites that
#                   build the SDK internally (citrix_ica_detection,
#                   http_header_case) inherit BUILD=asan via SDK_BUILD_PROFILE.
#   SANITIZE=tsan   Same for the SDK's BUILD=tsan profile (ThreadSanitizer).
#   --with-harnesses  After the suites, run every phase0 harness
#                   (tools/phase0/tests/run_*.sh) via the aggregate runner
#                   tools/phase0/run_all_harnesses.sh — one shared SDK build
#                   per sanitizer profile, not one per harness (issue #183).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COVERAGE_DIR="$SCRIPT_DIR/coverage"
PASS=0
FAIL=0
TOTAL=0

echo "============================================"
echo "  MMT-DPI Test Suite Runner"
echo "============================================"
echo ""

# --- argument parsing --------------------------------------------------------
COVERAGE=0
WITH_HARNESSES=0
SUITES=()
for arg in "$@"; do
    case "$arg" in
        --coverage)
            COVERAGE=1
            ;;
        --with-harnesses)
            WITH_HARNESSES=1
            ;;
        -*)
            echo "Unknown option: $arg" >&2
            echo "Usage: $0 [--coverage] [--with-harnesses] [suite ...]" >&2
            exit 2
            ;;
        *)
            SUITES+=("$arg")
            ;;
    esac
done

# --- compile-flag composition -------------------------------------------------
# The sanitizer flag sets mirror the SDK profiles in rules/common.mk so the
# standalone suites exercise the same instrumentation as BUILD=asan/BUILD=tsan
# library builds. EXTRA_CFLAGS lands on every suite compile+link line.
extra_flags=""
case "${SANITIZE:-}" in
    asan)
        extra_flags="-g -O1 -fno-omit-frame-pointer -fno-common \
-fsanitize=address,undefined -fno-sanitize-recover=all"
        export SDK_BUILD_PROFILE=asan
        # Project policy: leak detection stays with Valgrind; ASan targets
        # memory safety and UB (see rules/common.mk BUILD=asan block).
        export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
        echo "Mode: suites under AddressSanitizer + UBSan (SDK BUILD=asan)"
        ;;
    tsan)
        extra_flags="-g -O1 -fno-omit-frame-pointer -fno-common \
-fsanitize=thread -fno-sanitize-recover=all"
        export SDK_BUILD_PROFILE=tsan
        # TSan's shadow-memory layout is incompatible with high-entropy ASLR
        # (kernel default vm.mmap_rnd_bits=32): it aborts at startup with
        # "unexpected memory mapping". Re-exec once with ASLR disabled.
        if [ "${MMT_TSAN_REEXEC:-0}" != "1" ] && command -v setarch >/dev/null 2>&1; then
            export MMT_TSAN_REEXEC=1
            exec setarch "$(uname -m)" -R bash "$0" "$@"
        fi
        echo "Mode: suites under ThreadSanitizer (SDK BUILD=tsan)"
        ;;
    "")
        ;;
    *)
        echo "Invalid SANITIZE value '${SANITIZE}' (expected: asan|tsan)" >&2
        exit 2
        ;;
esac

if [ "$COVERAGE" -eq 1 ]; then
    extra_flags="${extra_flags:+${extra_flags} }--coverage"
fi

if [ -n "$extra_flags" ] || [ -n "${EXTRA_CFLAGS:-}" ]; then
    EXTRA_CFLAGS="${EXTRA_CFLAGS:-}${extra_flags:+ ${extra_flags}}"
    export EXTRA_CFLAGS
    if [ "$COVERAGE" -eq 1 ] && [ "${VERBOSE_COVERAGE:-0}" = "1" ]; then
        echo "EXTRA_CFLAGS=${EXTRA_CFLAGS}"
    fi
fi

if [ "$COVERAGE" -eq 1 ]; then
    for tool in gcov jq; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "✗ --coverage requires '$tool' (gcov ships with gcc; jq: apt-get install jq)" >&2
            exit 2
        fi
    done
    # Keep the committed floor (issue #185): wipe reports, not the baseline.
    mkdir -p "$COVERAGE_DIR" && find "$COVERAGE_DIR" -mindepth 1 ! -name floor.json -delete
    # Drop stale gcov data from previous runs/profiles so the report only
    # reflects this invocation's binaries.
    find "$SCRIPT_DIR" \( -name '*.gcda' -o -name '*.gcno' \) -delete
    echo "Mode: coverage report -> ${COVERAGE_DIR#"$REPO_ROOT"/}/coverage.info"
fi
echo ""

run_test_suite() {
    local suite_name=$1
    local test_dir="$SCRIPT_DIR/$suite_name"
    local test_script="$test_dir/run_tests.sh"

    TOTAL=$((TOTAL + 1))

    # A listed suite whose script is absent is a failure, not a skip (issue
    # #186, F-TEST-019): silently passing hides a renamed/deleted suite.
    if [ ! -f "$test_script" ]; then
        echo "  ✗ $suite_name: FAILED (run_tests.sh not found)"
        FAIL=$((FAIL + 1))
        return
    fi

    echo "--- Running: $suite_name ---"
    if bash "$test_script" 2>&1; then
        echo "  ✓ $suite_name: PASSED"
        PASS=$((PASS + 1))
    else
        echo "  ✗ $suite_name: FAILED"
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

# Default suite list (run in this order when no arguments are given).
DEFAULT_SUITES=(
    hashmap
    memory
    hexdump
    mmt_utils
    mmt_inet_ntop
    avltree
    citrix_ica_detection
    http_header_case
    s1ap_ngap_decode
    rule_engine
    radius_hardening
    nas_ies_tail
    installer
    dicom_dissector
    ndn_dissector
)

# Run the requested suites, or all of them if none were named on the CLI.
if [ "${#SUITES[@]}" -gt 0 ]; then
    SUITES_LIST=("${SUITES[@]}")
else
    SUITES_LIST=("${DEFAULT_SUITES[@]}")
fi

for suite in "${SUITES_LIST[@]}"; do
    run_test_suite "$suite"
done

# --- coverage report ----------------------------------------------------------
# Aggregates every .gcda produced by this run into an lcov-format tracefile:
# per-source DA records plus LF/LH totals, then prints the overall line rate.
write_coverage_report() {
    local tmp trace tsv totals lines_total lines_hit pct
    tmp="$(mktemp -d)"
    tsv="$tmp/lines.tsv"
    totals="$tmp/totals.txt"
    trace="$COVERAGE_DIR/coverage.info"

    : > "$tsv"
    local found=0 gcda
    while IFS= read -r -d '' gcda; do
        found=1
        # gcov --json-format writes <gcda-basename>.gcov.json.gz into the
        # current working directory (basename without the .gcda suffix).
        local json_base json_file
        json_base="$(basename "$gcda" .gcda)"
        if ! (cd "$tmp" && gcov -j "$gcda" >"$tmp/gcov.err" 2>&1); then
            echo "✗ coverage extraction failed for $gcda" >&2
            cat "$tmp/gcov.err" >&2
            rm -rf "$tmp"
            return 1
        fi
        json_file="$tmp/${json_base}.gcov.json.gz"
        zcat "$json_file" \
            | jq -r --arg repo "$REPO_ROOT" '.files[]
            | .file as $f
            | select($f | startswith($repo + "/src/"))
            | .lines[]
            | select(.line_number > 0)
            | [$f, (.line_number | tostring), (.count | tostring)]
            | @tsv' >> "$tsv" || {
            echo "✗ coverage JSON parsing failed: $json_file" >&2
            rm -rf "$tmp"
            return 1
        }
    done < <(find "$SCRIPT_DIR" -name '*.gcda' -print0)

    if [ "$found" -eq 0 ]; then
        echo "✗ no .gcda files found — suites were not compiled with --coverage" >&2
        rm -rf "$tmp"
        return 1
    fi

    sort -t "$(printf '\t')" -k 1,1 -k 2,2n "$tsv" | awk -F'\t' -v totals="$totals" '
        function flush_line() {
            if (cl != "") {
                printf "DA:%s,%d\n", cl, cc
                if (cc > 0) lh++
                lf++
            }
        }
        function flush_file() {
            flush_line()
            if (cf != "") {
                printf "LF:%d\nLH:%d\nend_of_record\n", lf, lh
                gt += lf
                gh += lh
            }
        }
        $1 != cf {
            flush_file()
            cf = $1
            printf "TN:suite\nSF:%s\n", cf
            cl = ""; cc = 0; lf = 0; lh = 0
        }
        {
            if ($2 == cl) { cc += $3 } else { flush_line(); cl = $2; cc = $3 }
        }
        END {
            flush_file()
            printf "%d %d\n", gt, gh > totals
        }
    ' > "$trace"

    read -r lines_total lines_hit < "$totals"
    rm -rf "$tmp"

    if [ "${lines_total:-0}" -eq 0 ]; then
        echo "✗ coverage report is empty — no instrumented sources recorded" >&2
        return 1
    fi
    pct="$(awk -v h="$lines_hit" -v t="$lines_total" 'BEGIN { printf "%.1f", 100 * h / t }')"
    # Instrumented files == SF: records in the tracefile (all under src/).
    local instrumented
    instrumented="$(grep -c '^SF:' "$trace")"
    jq -n --argjson pct "$pct" --argjson files "$instrumented" \
        --argjson hit "$lines_hit" --argjson total "$lines_total" \
        '{library_line_pct: $pct, instrumented_files: $files,
          library_lines_hit: $hit, library_lines_total: $total,
          scope: "src/"}' > "$COVERAGE_DIR/summary.json"
    echo "Library line coverage: ${pct}% (${lines_hit}/${lines_total} executable lines, ${instrumented} instrumented files under src/)"
    echo "Coverage report: ${trace#"$REPO_ROOT"/} (lcov tracefile format)"
    echo "Coverage summary: ${COVERAGE_DIR#"$REPO_ROOT"/}/summary.json"
}

if [ "$COVERAGE" -eq 1 ]; then
    if ! write_coverage_report; then
        exit 1
    fi
    echo ""
fi

# --- phase0 harnesses ---------------------------------------------------------
# --with-harnesses: one aggregate pass over tools/phase0/tests/run_*.sh sharing
# a single SDK build per required profile (issue #183, F-TEST-016). The
# aggregate prints the per-harness detail; it counts here as one arm so a
# harness failure still fails the whole invocation.
if [ "$WITH_HARNESSES" -eq 1 ]; then
    echo "--- Running: phase0 harnesses (tools/phase0/run_all_harnesses.sh) ---"
    TOTAL=$((TOTAL + 1))
    if bash "${REPO_ROOT}/tools/phase0/run_all_harnesses.sh"; then
        echo "  ✓ phase0-harnesses: PASSED"
        PASS=$((PASS + 1))
    else
        echo "  ✗ phase0-harnesses: FAILED"
        FAIL=$((FAIL + 1))
    fi
    echo ""
fi

echo "============================================"
echo "  Test Results"
echo "============================================"
echo "  Total:  $TOTAL"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
if [ "$COVERAGE" -eq 1 ]; then
    echo "  Coverage report: ${COVERAGE_DIR#"$REPO_ROOT"/}/coverage.info"
fi
echo "============================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
