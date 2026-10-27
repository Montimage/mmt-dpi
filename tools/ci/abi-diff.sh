#!/usr/bin/env bash
#
# abi-diff.sh — report-only ABI comparison of the five SDK libraries against
# the last release (issue #525; issue #536 turns the verdict into a gate).
#
# Libraries compared: libmmt_core, libmmt_tcpip, libmmt_tmobile,
# libmmt_business_app, libmmt_tdicom (the regular libmmt_<name>.so.* file of
# each; the unversioned symlinks are skipped).
#
# Modes:
#   build (default)  `git worktree add --detach` the baseline ref (v1.9.1)
#                    and the head ref (HEAD) into a scratch directory and
#                    build them one after the other in the RELEASE profile
#                    plus DWARF: CC/CXX are overridden on the make command
#                    line with the compilers both refs set in
#                    rules/arch-linux-gcc.mk plus -g, so LTO, -O3 and the
#                    hardening block stay on. DEBUG=1 is not used — it clears
#                    MMT_RELEASE_BUILD and builds -O0, a different binary.
#                    abidiff then compares types as well as symbols
#                    (--fail-no-debug-info: a build that lost its DWARF is a
#                    tool error, not a silent symbol-only pass), filtered to
#                    the public headers (sdk/include of each side). The
#                    worktrees it created are removed on exit; the caller's
#                    checkout and its sdk/ are never touched. The head ref is
#                    a commit: uncommitted changes are not part of it.
#   prebuilt         --baseline-dir DIR --head-dir DIR: compare libraries
#                    already built (optional --headers-dir1/--headers-dir2).
#   release          --release-deb FILE: the shipped .deb of the baseline
#                    release, extracted with dpkg-deb -x, against the head
#                    libraries (--head-dir DIR, else the head ref is built as
#                    above). The release packages carry no DWARF, so both
#                    sides are `objcopy --strip-debug` copies: an ELF-symbol
#                    comparison, like for like.
#
# Verdict per library, from the abidiff exit bitmask: bit 1 or 2 (error,
# usage) = tool error; bit 8 = INCOMPATIBLE; bit 4 = CHANGED; 0 = NO CHANGE.
# A library present on one side only is INCOMPATIBLE.
#
# Options:
#   --baseline-ref REF   build mode baseline (default v1.9.1)
#   --head-ref REF       build mode head (default HEAD)
#   --keep-libs DIR      build mode: copy each side's libraries and headers
#                        to DIR/{baseline,head}/{lib,include} before cleanup
#   --fail-on WHAT       none (default) | incompatible | change
#   --report FILE        full abidiff output (default: printed to stdout)
#   --summary FILE       short Markdown summary: a verdict per library and an
#                        excerpt of the report cut at ABI_SUMMARY_MAX_BYTES
#                        (default 61440) bytes
#
# Environment: ABIDIFF (default abidiff), OBJCOPY (objcopy), DPKG_DEB
# (dpkg-deb), MAKE (make), ABI_CC (gcc -g), ABI_CXX (g++ -std=c++11 -g),
# ROOT_DIR (the repository the refs are read from; default this checkout),
# TMPDIR (scratch location).
#
# Exit codes: 0 = no finding the --fail-on level counts (always 0 under the
# default `none` unless the tool broke), 1 = a counted ABI finding,
# 2 = tool or usage error (abidiff missing or failing, unknown ref, failed
# build, unreadable input).
#
# Usage:
#   bash tools/ci/abi-diff.sh [--baseline-ref REF] [--head-ref REF] [--keep-libs DIR]
#   bash tools/ci/abi-diff.sh --baseline-dir DIR --head-dir DIR
#   bash tools/ci/abi-diff.sh --release-deb FILE [--head-dir DIR | --head-ref REF]
#   (each with [--fail-on none|incompatible|change] [--report FILE] [--summary FILE])

set -euo pipefail

ROOT="${ROOT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
LIBS=(core tcpip tmobile business_app tdicom)
ABIDIFF="${ABIDIFF:-abidiff}"
OBJCOPY="${OBJCOPY:-objcopy}"
DPKG_DEB="${DPKG_DEB:-dpkg-deb}"
MAKE="${MAKE:-make}"
ABI_CC="${ABI_CC:-gcc -g}"
ABI_CXX="${ABI_CXX:-g++ -std=c++11 -g}"
SUMMARY_MAX="${ABI_SUMMARY_MAX_BYTES:-61440}"

usage() { sed -n '/^# Usage:/,/^$/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2; exit 2; }
die() { echo "✗ abi-diff: $*" >&2; exit 2; }

baseline_ref=v1.9.1
head_ref=HEAD
baseline_dir=""
head_dir=""
headers1=""
headers2=""
release_deb=""
keep_libs=""
fail_on=none
report_out=""
summary_out=""

while [ $# -gt 0 ]; do
    case "$1" in
        --baseline-ref|--head-ref|--baseline-dir|--head-dir|--headers-dir1|\
        --headers-dir2|--release-deb|--keep-libs|--fail-on|--report|--summary)
            if [ $# -lt 2 ] || [ -z "$2" ]; then die "$1 needs a value"; fi
            case "$1" in
                --baseline-ref) baseline_ref="$2" ;;
                --head-ref)     head_ref="$2" ;;
                --baseline-dir) baseline_dir="$2" ;;
                --head-dir)     head_dir="$2" ;;
                --headers-dir1) headers1="$2" ;;
                --headers-dir2) headers2="$2" ;;
                --release-deb)  release_deb="$2" ;;
                --keep-libs)    keep_libs="$2" ;;
                --fail-on)      fail_on="$2" ;;
                --report)       report_out="$2" ;;
                --summary)      summary_out="$2" ;;
            esac
            shift 2 ;;
        -h|--help) usage ;;
        *) echo "✗ abi-diff: unknown argument: $1" >&2; usage ;;
    esac
done

case "$fail_on" in none|incompatible|change) ;; *) die "--fail-on must be none, incompatible or change" ;; esac
[[ "$SUMMARY_MAX" =~ ^[0-9]+$ ]] || die "ABI_SUMMARY_MAX_BYTES must be a byte count"
if [ -n "$release_deb" ]; then
    mode=release
    [ -z "$baseline_dir" ] || die "--release-deb and --baseline-dir are exclusive"
    [ -f "$release_deb" ] || die "release package not found: $release_deb"
elif [ -n "$baseline_dir" ] || [ -n "$head_dir" ]; then
    mode=prebuilt
    if [ -z "$baseline_dir" ] || [ -z "$head_dir" ]; then
        die "prebuilt mode needs both --baseline-dir and --head-dir"
    fi
else
    mode=build
fi
[ -z "$keep_libs" ] || [ "$mode" = build ] || die "--keep-libs applies to build mode only"
for d in "$baseline_dir" "$head_dir" "$headers1" "$headers2"; do
    [ -z "$d" ] || [ -d "$d" ] || die "not a directory: $d"
done
command -v "$ABIDIFF" >/dev/null 2>&1 || die "abidiff not found ('$ABIDIFF'; install abigail-tools or set ABIDIFF)"
if [ "$mode" = release ]; then
    command -v "$DPKG_DEB" >/dev/null 2>&1 || die "dpkg-deb not found ('$DPKG_DEB')"
    command -v "$OBJCOPY" >/dev/null 2>&1 || die "objcopy not found ('$OBJCOPY')"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mmt-abi.XXXXXX")"
CREATED_WT=()
cleanup() {
    local wt
    for wt in ${CREATED_WT[@]+"${CREATED_WT[@]}"}; do
        # A failed remove (a half-created worktree) falls back to deleting
        # the directory; the prune then drops its stale administrative entry.
        git -C "$ROOT" worktree remove --force "$wt" >/dev/null 2>&1 || {
            rm -rf -- "$wt"
            git -C "$ROOT" worktree prune >/dev/null 2>&1 || true
        }
    done
    rm -rf -- "$WORK"
}
trap cleanup EXIT

# build_ref <ref> <side>: build <ref> in its own worktree, $WORK/<side>.
# Called in the main shell (never in $(...)) so CREATED_WT reaches cleanup.
build_ref() {
    local ref="$1" side="$2" wt log
    git -C "$ROOT" rev-parse --verify --quiet "${ref}^{commit}" >/dev/null \
        || die "unknown ref '$ref' in $ROOT (a release tag needs fetch-depth: 0 or git fetch --tags)"
    wt="$WORK/$side"
    log="$WORK/build-$side.log"
    CREATED_WT+=("$wt")
    git -C "$ROOT" worktree add --detach --quiet "$wt" "$ref" >&2 || die "git worktree add failed for '$ref'"
    echo "  building $side ($ref = $(git -C "$wt" rev-parse --short HEAD)) ..." >&2
    if ! "$MAKE" -C "$wt/sdk" -j"$(nproc)" CC="$ABI_CC" CXX="$ABI_CXX" >"$log" 2>&1; then
        tail -n 40 "$log" >&2
        die "build of '$ref' failed (log above)"
    fi
}

# find_lib <dir> <name>: the regular libmmt_<name>.so.* file in <dir>, or "".
find_lib() {
    local f found=""
    for f in "$1"/libmmt_"$2".so.*; do
        if [ ! -f "$f" ] || [ -L "$f" ]; then continue; fi
        [ -z "$found" ] || die "more than one libmmt_$2.so.* in $1"
        found="$f"
    done
    printf '%s\n' "$found"
}

title=""
diff_opts=()
strip=0
case "$mode" in
    build)
        build_ref "$baseline_ref" baseline
        build_ref "$head_ref" head
        wt_old="$WORK/baseline"
        wt_new="$WORK/head"
        baseline_dir="$wt_old/sdk/lib"
        head_dir="$wt_new/sdk/lib"
        headers1="$wt_old/sdk/include"
        headers2="$wt_new/sdk/include"
        diff_opts+=(--fail-no-debug-info)
        title="$baseline_ref → $head_ref ($(git -C "$wt_new" rev-parse --short HEAD)): types and symbols, release profile + -g"
        if [ -n "$keep_libs" ]; then
            for side in baseline head; do
                src="$WORK/$side/sdk"
                mkdir -p "$keep_libs/$side/lib"
                for name in "${LIBS[@]}"; do
                    lib="$(find_lib "$src/lib" "$name")"
                    [ -z "$lib" ] || cp -p -- "$lib" "$keep_libs/$side/lib/"
                done
                rm -rf -- "$keep_libs/$side/include"
                cp -pR -- "$src/include" "$keep_libs/$side/include"
            done
        fi
        ;;
    release)
        mkdir -p "$WORK/deb"
        "$DPKG_DEB" -x "$release_deb" "$WORK/deb" || die "cannot extract $release_deb"
        core="$(find "$WORK/deb" -path '*/dpi/lib/*' -name 'libmmt_core.so.*' -type f | head -n 1)"
        [ -n "$core" ] || die "no dpi/lib/libmmt_core.so.* in $release_deb"
        baseline_dir="$(dirname "$core")"
        if [ -z "$head_dir" ]; then
            build_ref "$head_ref" head
            head_dir="$WORK/head/sdk/lib"
        fi
        headers1=""
        headers2=""
        strip=1
        title="shipped $(basename "$release_deb") → head: ELF symbols only (both sides --strip-debug)"
        ;;
    prebuilt)
        title="$baseline_dir → $head_dir"
        ;;
esac
[ -z "$headers1" ] || diff_opts+=(--headers-dir1 "$headers1")
[ -z "$headers2" ] || diff_opts+=(--headers-dir2 "$headers2")

REPORT="$WORK/report.txt"
: > "$REPORT"
rows=()
n_error=0
n_incompat=0
n_changed=0
for name in "${LIBS[@]}"; do
    lib="libmmt_$name"
    old="$(find_lib "$baseline_dir" "$name")"
    new="$(find_lib "$head_dir" "$name")"
    if [ -z "$old" ] && [ -z "$new" ]; then
        verdict="ERROR"; rc="-"; body="$lib.so.* is missing on both sides"
    elif [ -z "$old" ] || [ -z "$new" ]; then
        verdict="INCOMPATIBLE"; rc="-"
        body="$lib.so.* is missing on the $([ -z "$old" ] && echo baseline || echo head) side"
    else
        if [ "$strip" = 1 ]; then
            mkdir -p "$WORK/strip/old" "$WORK/strip/new"
            if ! "$OBJCOPY" --strip-debug "$old" "$WORK/strip/old/$(basename "$old")" \
                || ! "$OBJCOPY" --strip-debug "$new" "$WORK/strip/new/$(basename "$new")"; then
                die "objcopy --strip-debug failed for $lib"
            fi
            old="$WORK/strip/old/$(basename "$old")"
            new="$WORK/strip/new/$(basename "$new")"
        fi
        set +e
        body="$("$ABIDIFF" ${diff_opts[@]+"${diff_opts[@]}"} "$old" "$new" 2>&1)"
        rc=$?
        set -e
        if (( rc & 3 )); then verdict="ERROR"
        elif (( rc & 8 )); then verdict="INCOMPATIBLE"
        elif (( rc & 4 )); then verdict="CHANGED"
        elif (( rc == 0 )); then verdict="NO CHANGE"
        else verdict="ERROR"
        fi
    fi
    case "$verdict" in
        ERROR) n_error=$((n_error + 1)) ;;
        INCOMPATIBLE) n_incompat=$((n_incompat + 1)) ;;
        CHANGED) n_changed=$((n_changed + 1)) ;;
    esac
    rows+=("$lib|$verdict|$rc")
    {
        echo "=== $lib: $verdict (abidiff exit $rc) ==="
        [ -z "$body" ] || printf '%s\n' "$body"
        echo
    } >> "$REPORT"
done

echo "ABI diff: $title"
for row in "${rows[@]}"; do
    IFS='|' read -r lib verdict rc <<< "$row"
    echo "  $lib: $verdict (abidiff exit $rc)"
done

if [ -n "$report_out" ]; then
    cp -- "$REPORT" "$report_out"
    echo "Full report: $report_out"
else
    echo
    cat "$REPORT"
fi

if [ -n "$summary_out" ]; then
    size="$(wc -c < "$REPORT")"
    {
        echo "### ABI diff: $title"
        echo
        echo "Report-only (issue #525) — --fail-on $fail_on."
        echo
        echo "| Library | Verdict | abidiff exit |"
        echo "|---------|---------|--------------|"
        for row in "${rows[@]}"; do
            IFS='|' read -r lib verdict rc <<< "$row"
            echo "| \`$lib\` | $verdict | $rc |"
        done
        echo
        echo "<details><summary>abidiff report ($size bytes)</summary>"
        echo
        echo '```text'
        head -c "$SUMMARY_MAX" "$REPORT"
        if [ "$size" -gt "$SUMMARY_MAX" ]; then
            echo
            echo "... truncated at $SUMMARY_MAX of $size bytes — the full report is in the artifact"
        fi
        echo '```'
        echo
        echo "</details>"
    } > "$summary_out"
fi

if [ "$n_error" -gt 0 ]; then
    echo "Result: ERROR ($n_error librar$([ "$n_error" = 1 ] && echo y || echo ies) could not be compared)" >&2
    exit 2
fi
counted=0
case "$fail_on" in
    incompatible) counted=$n_incompat ;;
    change) counted=$((n_incompat + n_changed)) ;;
esac
echo "Result: $n_incompat incompatible, $n_changed changed (--fail-on $fail_on)"
# The last command's status is the script's: no trailing `exit 0`
# (shellcheck 0.11 then misreads the EXIT trap's function as unused).
[ "$counted" -eq 0 ] || exit 1
