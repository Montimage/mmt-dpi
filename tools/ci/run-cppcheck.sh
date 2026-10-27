#!/usr/bin/env bash
#
# run-cppcheck.sh — cppcheck static-analysis gate for src/ (issue #189, F-CI-004).
#
# The lint job used to run cppcheck with its exit status discarded: findings
# were counted and uploaded, but nothing gated on them, so error-severity
# findings shipped green and the total had no ceiling. This script is the gate
# the report-only step used to lack. One `--enable=warning` scan writes the
# XML report the job uploads, and two independent checks read it:
#
#   1. Ratchet — the total finding count must not exceed the committed
#      baseline for the scan mode in tools/ci/cppcheck-ratchet.txt. A rise
#      fails the step; a drop is reported so the baseline can be tightened
#      in the same change.
#   2. Error gate — any error-severity finding in the report fails the step.
#      The checks that produce error-severity findings are always enabled
#      (--enable=warning only adds the rest), so the report already holds
#      every finding a separate error-only pass would print. That second pass
#      used to rescan the whole tree and doubled the lint job (issue #552,
#      F-CI-007).
#
# Writes the findings to cppcheck-report.xml at the repo root (override
# with $CPPCHECK_REPORT) — the same artifact the lint job publishes.
#
# Incremental analysis (issue #552): with $CPPCHECK_BUILD_DIR set, cppcheck
# keeps its per-file results there (--cppcheck-build-dir) and reanalyses only
# a file whose preprocessed code or options changed; unchanged files replay
# their stored findings into the report, so the totals do not depend on the
# cache. The lint job restores that directory with actions/cache, keyed on
# the pinned release.
#
# Scan modes (issue #653): $CPPCHECK_MODE picks how many preprocessor
# configurations each file is checked in, and each mode has its own line in
# the ratchet baseline:
#   full (default) — every #ifdef configuration cppcheck finds, up to its
#                    default of 12 per file: the `#ifdef` branches the build
#                    never compiles stay covered. The lint job runs it on
#                    pushes, tags, the merge queue and the weekly schedule.
#   pr             — the one configuration the default SDK build compiles:
#                    --max-configs=1 with the build's own defines, -DNDEBUG
#                    (rules/common.mk:41) and -D_MMT_BUILD_SDK
#                    (rules/common.mk:276). About 10x faster cold; the lint job
#                    runs it on pull requests (docs/ci-audit-2026-10.md §4).
# Macros a scanned header defines still apply in both modes.
#
# Pinned cppcheck version (issue #345): the ratchet baseline is only
# meaningful for the cppcheck release it was measured with — a different
# release adds or drops checks, so the total drifts on unchanged code (e.g.
# 2.21 reports 35 findings where the baseline of 24 was measured with 2.13).
# CPPCHECK_PINNED_VERSION below is the major.minor the lint job builds from
# source with tools/ci/install-cppcheck.sh (issue #518) inside its
# digest-pinned ubuntu:24.04 container (.github/workflows/c-cpp.yml, `lint`
# job); tools/ci/tests/test-cppcheck-version.sh fails when the installer's
# release and this pin disagree. The script compares `cppcheck --version`
# with it:
#   - match      -> both checks are enforced;
#   - mismatch in CI (CI=true) -> exit 2: the installed release changed;
#     re-measure tools/ci/cppcheck-ratchet.txt with the new release and bump
#     the pin and the installer in the same change;
#   - mismatch locally -> warning; the ratchet verdict is advisory only (the
#     count is not comparable) while the error-severity gate stays enforced
#     (another release may also add or drop error checks, so a local error
#     verdict may not reproduce in CI). Only CI=true (GitHub Actions) counts
#     as CI.
# For a verdict that matches CI, run cppcheck $CPPCHECK_PINNED_VERSION.x
# locally (e.g. built by tools/ci/install-cppcheck.sh in an ubuntu:24.04
# container, as the lint job does).
# Never raise the baseline to absorb version drift.
#
# Exit codes: 0 = both checks pass, 1 = a check tripped, 2 = the helper itself
# is broken (cppcheck missing or at an unexpected version in CI, unreadable
# baseline, unparseable report).
#
# Usage: bash tools/ci/run-cppcheck.sh                 (full scan)
#        CPPCHECK_MODE=pr bash tools/ci/run-cppcheck.sh   (pull-request scan)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

REPORT="${CPPCHECK_REPORT:-cppcheck-report.xml}"
RATCHET="${CPPCHECK_RATCHET:-tools/ci/cppcheck-ratchet.txt}"
JOBS="${CPPCHECK_JOBS:-$(nproc 2>/dev/null || echo 2)}"
CPPCHECK_PINNED_VERSION="2.22"   # major.minor tools/ci/install-cppcheck.sh builds (CI)
MODE="${CPPCHECK_MODE:-full}"
SCAN_DIRS=(src)
# The SDK is GNU C built by GCC only (rules/arch-linux.mk): gnu.cfg teaches
# cppcheck __builtin_expect and the kernel-style likely()/unlikely() macros,
# whose project definitions it cannot see (no -I is passed). Without it every
# `if (unlikely(p == NULL)) return` guard is opaque and cppcheck 2.22 reports
# the dereference behind it (issue #518).
LIBRARIES=(--library=gnu)
EXCLUDE=(-i src/mmt_mobile/asn1c)   # generated ASN.1 tree — never scanned
case "$MODE" in
    full) CONFIG_ARGS=() ;;
    pr)   CONFIG_ARGS=(--max-configs=1 -DNDEBUG -D_MMT_BUILD_SDK) ;;
    *)
        echo "✗ unknown CPPCHECK_MODE '$MODE' — expected pr or full" >&2
        exit 2
        ;;
esac

# Vendored sources (tools/ci/vendor-paths.txt) are excluded by configuration.
# shellcheck source=tools/ci/vendor-paths-lib.sh
. "$ROOT/tools/ci/vendor-paths-lib.sh"
vendor_paths_load "$VENDOR_LIST" || exit 2
for p in "${VENDOR_PATHS[@]}"; do
    EXCLUDE+=(-i "$p")
done

if ! command -v cppcheck >/dev/null 2>&1; then
    echo "✗ cppcheck is not installed" >&2
    echo "To fix:  bash tools/ci/install-cppcheck.sh   (the pinned release)" >&2
    exit 2
fi

# `cppcheck --version` prints e.g. "Cppcheck 2.13.0"; compare major.minor.
version_out="$(cppcheck --version 2>/dev/null || true)"
if ! [[ "$version_out" =~ ([0-9]+)\.([0-9]+) ]]; then
    echo "✗ cannot parse cppcheck version from: ${version_out:-<no output>}" >&2
    exit 2
fi
found_version="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
ratchet_enforced=1
if [ "$found_version" != "$CPPCHECK_PINNED_VERSION" ]; then
    if [ "${CI:-}" = "true" ]; then
        echo "✗ cppcheck $found_version found, the ratchet is pinned to $CPPCHECK_PINNED_VERSION" >&2
        echo "To fix:  re-measure $RATCHET with cppcheck $found_version and" >&2
        echo "         update CPPCHECK_PINNED_VERSION in $0 in the same change" >&2
        exit 2
    fi
    echo "⚠ cppcheck $found_version differs from the CI-pinned $CPPCHECK_PINNED_VERSION —"
    echo "  the finding count is not comparable with the baseline, so the"
    echo "  ratchet is advisory in this run (the error-severity gate still applies)."
    echo "  For a CI-equivalent verdict, run cppcheck $CPPCHECK_PINNED_VERSION.x."
    ratchet_enforced=0
fi

if [ ! -f "$RATCHET" ]; then
    echo "✗ ratchet baseline not found: $RATCHET" >&2
    exit 2
fi
# The baseline file holds one `<mode> <count>` line per scan mode.
baseline="$(awk -v m="$MODE" 'NF && $1 !~ /^#/ && $1 == m {print $2; exit}' "$RATCHET")"
if ! [[ "$baseline" =~ ^[0-9]+$ ]]; then
    echo "✗ ratchet baseline unreadable: $RATCHET" >&2
    echo "    expected a '$MODE <count>' line" >&2
    exit 2
fi

BUILD_DIR_ARGS=()
if [ -n "${CPPCHECK_BUILD_DIR:-}" ]; then
    mkdir -p "$CPPCHECK_BUILD_DIR"
    BUILD_DIR_ARGS=(--cppcheck-build-dir="$CPPCHECK_BUILD_DIR")
fi

echo "── cppcheck: $MODE scan (ratchet + error gate + report) ──"
# The exit status is deliberately discarded here: the ratchet and the error
# gate below decide from the report, not cppcheck's own exit code.
cppcheck --enable=warning --inline-suppr -j"$JOBS" \
    "${LIBRARIES[@]}" "${EXCLUDE[@]}" "${CONFIG_ARGS[@]}" "${BUILD_DIR_ARGS[@]}" \
    --xml --xml-version=2 \
    "${SCAN_DIRS[@]}" \
    2> "$REPORT" || true

# A crashed or missing cppcheck must not look like a clean scan: the
# <results> skeleton is written even at zero findings, never on abort.
if ! grep -q '<results' "$REPORT"; then
    echo "✗ cppcheck did not produce a parseable report ($REPORT)" >&2
    exit 2
fi

total="$(grep -c '<error ' "$REPORT" || true)"
errors="$(grep -c 'severity="error"' "$REPORT" || true)"
echo "    findings: $total total, $errors error-severity ($MODE ratchet baseline: $baseline)"

rc=0

if [ "$ratchet_enforced" -eq 0 ]; then
    echo "⚠ ratchet not enforced: $total findings under cppcheck $found_version are not"
    echo "  comparable with the $CPPCHECK_PINNED_VERSION baseline ($baseline) — do not re-baseline from this run"
elif [ "$total" -gt "$baseline" ]; then
    echo "✗ cppcheck findings rose above the ratchet: $total > $baseline" >&2
    echo "To fix:  resolve the new findings, or — only with a recorded" >&2
    echo "         justification — raise the $MODE line of $RATCHET" >&2
    rc=1
elif [ "$total" -lt "$baseline" ]; then
    echo "  note: findings dropped below the baseline ($total < $baseline) —"
    echo "        tighten the $MODE line of $RATCHET in this change to bank the progress"
else
    echo "✓ findings within the ratchet ($total ≤ $baseline)"
fi

# Error gate: read from the same report, enforced whatever the version check
# decided about the ratchet. --inline-suppr applies to the scan above, so a
# justified inline suppression is honoured here too.
if [ "$errors" -eq 0 ]; then
    echo "✓ no error-severity findings"
else
    echo "✗ $errors error-severity finding(s) — see $REPORT" >&2
    echo "To fix:  fix the finding, or suppress it inline with a justification" >&2
    echo "         comment (// cppcheck-suppress <id> — reason)" >&2
    rc=1
fi

exit "$rc"
