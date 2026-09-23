#!/usr/bin/env bash
#
# check-sdk-coverage.sh — whole-SDK coverage accounting and gate (issue #388,
# plan task 4.2, F-TEST-004).
#
# `bash tests/run_all_tests.sh --coverage` writes tests/coverage/
# coverage-combined.info: the unit-suite records plus every BUILD=coverage
# SDK build the SDK-building suites made, including the zero-hit objects no
# consumer loaded (read from their .gcno at count 0 by `sdk-coverage.sh
# harvest --unexecuted`). This helper reconciles that tracefile with the
# handwritten build sources and reports, from one run:
#
#   families        numeric line coverage per SDK family — core, tcpip,
#                   mobile (handwritten), business_app, dicom and the optional
#                   ENABLESEC=1 cohort security_fuzz — by path prefix, headers
#                   included (their inline code is executable)
#   whole_sdk       the non-optional families together: its own denominator,
#                   gated by the floor's whole_sdk_line_pct
#   original_cohort the fixed 30 sources of the 82.9% audit measurement
#                   (floor.json sdk.original_cohort), gated by its line_pct
#   excluded        generated ASN.1 (src/mmt_mobile/asn1c/) and vendored
#                   (tools/ci/vendor-paths.txt) sources, measured but kept out
#                   of every family, plus the handwritten sources the floor
#                   justifies as not measured (sdk.excluded_sources)
#   branch_coverage "Not Assessed" — only line coverage is measured
#
# It fails (exit 1) when a handwritten build source is missing from the
# measured records (a zero-hit source disappearing from the denominator), a
# tracked handwritten source is neither built nor justified, a justification
# is stale, a family measures nothing, a record falls outside every family,
# an original-cohort source is missing or the cohort drops below its floor,
# or the whole-SDK line rate drops below its floor. The report is written to
# tests/coverage/sdk-coverage.json (uploaded with the coverage artifact).
#
# Usage: bash tools/ci/check-sdk-coverage.sh [options]
#   --combined-info FILE   default tests/coverage/coverage-combined.info
#   --unit-info FILE       default tests/coverage/coverage.info (informational
#                          unit-only rate of the original cohort)
#   --summary FILE         default tests/coverage/summary.json (its
#                          cohorts.generated_asn1c totals: coverage-combined.info
#                          already leaves the generated sources out)
#   --floor FILE           default tests/coverage/floor.json (key "sdk")
#   --out FILE             default tests/coverage/sdk-coverage.json
#   --repo-root DIR        root stripped from tracefile paths (default: repo)
#   --build-sources FILE   repo-relative build sources, one per line (default:
#                          the SDK object lists, from make ENABLESEC=1)
#   --tracked-sources FILE repo-relative tracked sources (default: git ls-files)
#   --vendor-paths FILE    default tools/ci/vendor-paths.txt
#
# Exit codes: 0 = accounting complete and floors hold, 1 = gate failure,
#             2 = helper broken (missing tool, input or floor key).

set -euo pipefail
export LC_ALL=C  # comm and sort must agree on one collation

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

GENERATED_PREFIX="src/mmt_mobile/asn1c/"
# family <TAB> optional <TAB> space-separated path prefixes
FAMILIES="core	0	src/mmt_core/
tcpip	0	src/mmt_tcpip/
mobile	0	src/mmt_mobile/
business_app	0	src/mmt_business_app/
dicom	0	src/mmt_dicom/
security_fuzz	1	src/mmt_security/ src/mmt_fuzz_engine/"
# The make variables holding every SDK library's object list (rules/common.mk).
OBJECT_VARS="CORE_OBJECTS TCPIP_OBJECTS LIBMOBILE_OBJECTS LIBBAPP_OBJECTS LIBDICOM_OBJECTS SECURITY_OBJECTS FUZZ_OBJECTS"

combined="tests/coverage/coverage-combined.info"
unit="tests/coverage/coverage.info"
summary="tests/coverage/summary.json"
floor="tests/coverage/floor.json"
out="tests/coverage/sdk-coverage.json"
repo_root="$ROOT"
build_sources=""
tracked_sources=""
vendor_paths="tools/ci/vendor-paths.txt"

die() { echo "✗ check-sdk-coverage.sh: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --combined-info)   combined="${2:-}"; shift 2 ;;
        --unit-info)       unit="${2:-}"; shift 2 ;;
        --summary)         summary="${2:-}"; shift 2 ;;
        --floor)           floor="${2:-}"; shift 2 ;;
        --out)             out="${2:-}"; shift 2 ;;
        --repo-root)       repo_root="${2:-}"; shift 2 ;;
        --build-sources)   build_sources="${2:-}"; shift 2 ;;
        --tracked-sources) tracked_sources="${2:-}"; shift 2 ;;
        --vendor-paths)    vendor_paths="${2:-}"; shift 2 ;;
        *) sed -n '/^# Usage:/,/^#   --vendor-paths/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
    esac
done

command -v jq >/dev/null 2>&1 || die "jq is required"
[ -s "$combined" ] || die "$combined is missing or empty — run tests/run_all_tests.sh --coverage"
[ -s "$floor" ] || die "$floor is missing or empty"
[ -f "$vendor_paths" ] || die "missing $vendor_paths"
jq -e '.sdk | (.whole_sdk_line_pct | type == "number")
        and (.original_cohort.line_pct | type == "number")
        and (.original_cohort.sources | type == "array" and length > 0)
        and (.excluded_sources | type == "object")' "$floor" >/dev/null 2>&1 \
    || die "$floor has no valid \"sdk\" object (whole_sdk_line_pct, original_cohort{line_pct,sources}, excluded_sources)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log_root="${repo_root%/}"
phys_root="$(cd "$repo_root" && pwd -P)"

# per_file <tracefile> — repo-relative src/ path <TAB> LF <TAB> LH.
per_file() {
    awk -v OFS='\t' -v log_root="$log_root/" -v phys_root="$phys_root/" '
        /^SF:/ {
            f = substr($0, 4)
            if (index(f, phys_root) == 1) f = substr(f, length(phys_root) + 1)
            else if (index(f, log_root) == 1) f = substr(f, length(log_root) + 1)
            lf = 0; lh = 0
        }
        /^LF:/ { lf = substr($0, 4) + 0 }
        /^LH:/ { lh = substr($0, 4) + 0 }
        /^end_of_record/ { if (f ~ /^src\//) print f, lf, lh; f = "" }
    ' "$1" | sort -t "$(printf '\t')" -k 1,1
}

per_file "$combined" >"$WORK/records.tsv"
[ -s "$WORK/records.tsv" ] || die "$combined holds no src/ records"
: >"$WORK/unit.tsv"
[ -s "$unit" ] && per_file "$unit" >"$WORK/unit.tsv"

if [ -n "$build_sources" ]; then
    [ -f "$build_sources" ] || die "missing $build_sources"
    grep -v '^[[:space:]]*$' "$build_sources" | sort -u >"$WORK/build.txt"
else
    # Object -> source, from the same object lists the libraries link.
    # ENABLESEC=1 so the optional engines' objects are listed too.
    : >"$WORK/objects.txt"
    for var in $OBJECT_VARS; do
        # shellcheck disable=SC2016  # $($*) is make syntax, not a shell expansion
        make -s --no-print-directory -C sdk ENABLESEC=1 \
            --eval 'print-%: ; @echo $($*)' "print-$var" >>"$WORK/objects.txt" \
            || die "could not list $var from sdk/Makefile"
    done
    tr ' ' '\n' <"$WORK/objects.txt" | grep . | while IFS= read -r obj; do
        base="${obj%.o}"
        for ext in c cpp cc; do
            if [ -f "$base.$ext" ]; then
                src="$base.$ext"
                src="${src#"$phys_root"/}"
                src="${src#"$log_root"/}"
                echo "$src"
                break
            fi
        done
    done | sort -u >"$WORK/build.txt"
fi
[ -s "$WORK/build.txt" ] || die "empty build source list"

if [ -n "$tracked_sources" ]; then
    [ -f "$tracked_sources" ] || die "missing $tracked_sources"
    grep -v '^[[:space:]]*$' "$tracked_sources" | sort -u >"$WORK/tracked.txt"
else
    git ls-files 'src/*.c' 'src/*.cpp' 'src/*.cc' | sort -u >"$WORK/tracked.txt"
fi

sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$vendor_paths" | grep . | sort -u >"$WORK/vendored.txt" || true
jq -r '.sdk.excluded_sources | to_entries[] | "\(.key)\t\(.value)"' "$floor" \
    | sort -t "$(printf '\t')" -k 1,1 >"$WORK/excluded.tsv"
cut -f1 "$WORK/excluded.tsv" >"$WORK/excluded.txt"
jq -r '.sdk.original_cohort.sources[]' "$floor" | sort -u >"$WORK/original.txt"
cut -f1 "$WORK/records.tsv" >"$WORK/measured.txt"

# Handwritten = not generated, not vendored.
handwritten() {
    grep -v "^${GENERATED_PREFIX}" "$1" | { grep -vxF -f "$WORK/vendored.txt" || true; }
}

rc=0
fail() { echo "✗ $*" >&2; rc=1; }

# --- reconciliation -----------------------------------------------------------
handwritten "$WORK/build.txt" >"$WORK/build.hw"
handwritten "$WORK/tracked.txt" >"$WORK/tracked.hw"
while IFS= read -r src; do
    fail "zero-hit source disappeared: $src is built but absent from the measured records (justify it in sdk.excluded_sources if it has no executable lines)"
done < <(comm -23 "$WORK/build.hw" "$WORK/measured.txt" | comm -23 - "$WORK/excluded.txt")
while IFS= read -r src; do
    fail "handwritten source $src is neither built into an SDK library nor justified in sdk.excluded_sources"
done < <(comm -23 "$WORK/tracked.hw" "$WORK/build.hw" | comm -23 - "$WORK/excluded.txt")
while IFS= read -r src; do
    fail "stale justification: $src is in sdk.excluded_sources but is not a tracked source"
done < <(comm -23 "$WORK/excluded.txt" "$WORK/tracked.txt")
while IFS= read -r src; do
    fail "stale justification: $src is in sdk.excluded_sources but is measured now — drop the entry"
done < <(comm -12 "$WORK/excluded.txt" "$WORK/measured.txt")

# --- classification -----------------------------------------------------------
# Every record gets exactly one bucket: generated, vendored, a family, or
# unclassified (a gate failure).
printf '%s\n' "$FAMILIES" >"$WORK/families.tsv"
awk -F'\t' -v OFS='\t' -v gen="$GENERATED_PREFIX" \
    -v vend="$WORK/vendored.txt" -v fams="$WORK/families.tsv" '
    BEGIN {
        while ((getline l < vend) > 0) v[l] = 1
        n = 0
        while ((getline l < fams) > 0) {
            split(l, p, "\t"); k = split(p[3], pre, " ")
            for (i = 1; i <= k; i++) { n++; fam[n] = p[1]; pfx[n] = pre[i] }
        }
    }
    {
        b = "unclassified"
        if (index($1, gen) == 1) b = "generated"
        else if ($1 in v) b = "vendored"
        else for (i = 1; i <= n; i++) if (index($1, pfx[i]) == 1) { b = fam[i]; break }
        print b, $1, $2, $3
    }' "$WORK/records.tsv" >"$WORK/classified.tsv"

while IFS=$'\t' read -r _ src _ _; do
    fail "record $src belongs to no SDK family"
done < <(awk -F'\t' '$1 == "unclassified"' "$WORK/classified.tsv")

# stats_json <rows: path<TAB>LF<TAB>LH> — totals as JSON.
stats_json() {
    awk -F'\t' '{ n++; t += $2; h += $3; if ($2 > 0 && $3 == 0) z++ }
        END { printf "%d\t%d\t%d\t%d\n", n, t, h, z }' "$1" \
        | jq -R 'split("\t") | map(tonumber)
            | {files: .[0], lines_total: .[1], lines_hit: .[2],
               line_pct: (if .[1] > 0 then ((10000 * .[2] / .[1]) | floor) / 100 else null end),
               zero_hit_files: .[3]}'
}

fam_json="{}"
: >"$WORK/whole.tsv"
while IFS=$'\t' read -r name optional prefixes; do
    awk -F'\t' -v OFS='\t' -v f="$name" '$1 == f { print $2, $3, $4 }' \
        "$WORK/classified.tsv" >"$WORK/fam.tsv"
    s="$(stats_json "$WORK/fam.tsv")"
    if [ "$(jq -r '.lines_total' <<<"$s")" -eq 0 ]; then
        fail "family $name measured nothing (no records under ${prefixes}) — a family went missing"
    fi
    [ "$optional" -eq 1 ] || cat "$WORK/fam.tsv" >>"$WORK/whole.tsv"
    fam_json="$(jq --arg n "$name" --argjson s "$s" --arg p "$prefixes" \
        --argjson opt "$optional" '. + {($n): ($s + {
            prefixes: ($p | split(" ")),
            optional: ($opt == 1),
            cohort: (if $opt == 1 then "optional ENABLESEC=1 engines (libmmt_security, libmmt_fuzz), excluded from whole_sdk" else "default SDK build" end)})}' \
        <<<"$fam_json")"
done <"$WORK/families.tsv"

whole="$(stats_json "$WORK/whole.tsv")"
whole_floor="$(jq -r '.sdk.whole_sdk_line_pct' "$floor")"

# --- original 30-file cohort -----------------------------------------------------
while IFS= read -r src; do
    fail "original-cohort source $src is absent from the measured records (cohort identity lost)"
done < <(comm -23 "$WORK/original.txt" "$WORK/measured.txt")
awk -F'\t' -v OFS='\t' 'NR == FNR { w[$1] = 1; next } ($1 in w)' \
    "$WORK/original.txt" "$WORK/records.tsv" >"$WORK/orig.tsv"
awk -F'\t' -v OFS='\t' 'NR == FNR { w[$1] = 1; next } ($1 in w)' \
    "$WORK/original.txt" "$WORK/unit.tsv" >"$WORK/orig-unit.tsv"
orig="$(stats_json "$WORK/orig.tsv")"
orig_unit="$(stats_json "$WORK/orig-unit.tsv")"
orig_floor="$(jq -r '.sdk.original_cohort.line_pct' "$floor")"

below() {  # below <hit> <total> <floor_pct>: true when 100*hit/total < floor
    awk -v h="$1" -v t="$2" -v f="$3" 'BEGIN { exit !(t == 0 || 100 * h < f * t) }'
}
if below "$(jq -r .lines_hit <<<"$whole")" "$(jq -r .lines_total <<<"$whole")" "$whole_floor"; then
    fail "whole-SDK line coverage $(jq -r .line_pct <<<"$whole")% is below its floor ${whole_floor}%"
fi
if below "$(jq -r .lines_hit <<<"$orig")" "$(jq -r .lines_total <<<"$orig")" "$orig_floor"; then
    fail "original 30-file cohort $(jq -r .line_pct <<<"$orig")% is below its floor ${orig_floor}%"
fi

# --- report ----------------------------------------------------------------------
awk -F'\t' -v OFS='\t' '$1 == "generated" { print $2, $3, $4 }' "$WORK/classified.tsv" >"$WORK/gen.tsv"
awk -F'\t' -v OFS='\t' '$1 == "vendored" { print $2, $3, $4 }' "$WORK/classified.tsv" >"$WORK/vend.tsv"
awk -F'\t' '$1 != "generated" && $1 != "vendored" && $3 > 0 && $4 == 0 { print $2 }' \
    "$WORK/classified.tsv" >"$WORK/zero.txt"
gen_build="$(grep -c "^${GENERATED_PREFIX}" "$WORK/build.txt" || true)"
# The combined tracefile carries generated records only if a caller put them
# there; the runner's own totals for them live in summary.json.
gen="$(stats_json "$WORK/gen.tsv")"
if [ "$(jq -r .files <<<"$gen")" -eq 0 ] && [ -s "$summary" ] \
        && jq -e '.cohorts.generated_asn1c.files | type == "number"' "$summary" >/dev/null 2>&1; then
    gen="$(jq '.cohorts.generated_asn1c | {files, lines_total, lines_hit, line_pct}' "$summary")"
fi

jq -n \
    --argjson families "$fam_json" \
    --argjson whole "$whole" --argjson whole_floor "$whole_floor" \
    --argjson orig "$orig" --argjson orig_unit "$orig_unit" --argjson orig_floor "$orig_floor" \
    --slurpfile fl "$floor" \
    --argjson gen "$gen" --argjson gen_build "$gen_build" \
    --argjson vend "$(stats_json "$WORK/vend.tsv")" \
    --arg gen_prefix "$GENERATED_PREFIX" \
    --arg combined "$combined" \
    --rawfile vend_list "$WORK/vendored.txt" \
    --rawfile zero "$WORK/zero.txt" \
    --argjson rc "$rc" '
    ($vend_list | split("\n") | map(select(length > 0))) as $vl
    | {
        tracefile: $combined,
        metric: "executable src/ lines (gcov), unit-suite and BUILD=coverage SDK records combined; each source counted once",
        branch_coverage: "Not Assessed",
        families: $families,
        whole_sdk: ($whole + {
            families: [$families | to_entries[] | select(.value.optional | not) | .key],
            denominator: "every executable line of the handwritten sources the default SDK build compiles (zero-hit sources included from their .gcno), headers included; generated ASN.1, vendored sources and the optional ENABLESEC=1 engines excluded",
            floor: $whole_floor}),
        original_cohort: ($orig + {
            commit: $fl[0].sdk.original_cohort.commit,
            audit: $fl[0].sdk.original_cohort.audit,
            floor: $orig_floor,
            unit_only: $orig_unit}),
        excluded: {
            generated: ($gen + {prefix: $gen_prefix, build_sources: $gen_build,
                reason: "asn1c output regenerated from the ASN.1 specs (never hand-edited)"}),
            vendored: ($vend + {sources: $vl,
                reason: "verbatim upstream copies pinned in tools/ci/vendor-paths.txt"}),
            justified: ($fl[0].sdk.excluded_sources | to_entries | map({source: .key, reason: .value}))
        },
        zero_hit_sources: ($zero | split("\n") | map(select(length > 0))),
        passed: ($rc == 0)
    }' >"$out"

jq -r '
    def pct: if . == null then "n/a" else "\(.)%" end;
    (.families | to_entries[]
        | "  \(.key)\(if .value.optional then " (optional, ENABLESEC=1)" else "" end): \(.value.line_pct | pct) (\(.value.lines_hit)/\(.value.lines_total) lines, \(.value.files) files, \(.value.zero_hit_files) zero-hit)"),
    "  whole SDK: \(.whole_sdk.line_pct | pct) (\(.whole_sdk.lines_hit)/\(.whole_sdk.lines_total) lines, \(.whole_sdk.files) files) vs floor \(.whole_sdk.floor)%",
    "  original 30-file cohort: \(.original_cohort.line_pct | pct) (\(.original_cohort.lines_hit)/\(.original_cohort.lines_total) lines, \(.original_cohort.files) files; unit-only \(.original_cohort.unit_only.line_pct | pct)) vs floor \(.original_cohort.floor)%",
    "  excluded: generated \(.excluded.generated.files) files (\(.excluded.generated.line_pct | pct)), vendored \(.excluded.vendored.files) files (\(.excluded.vendored.line_pct | pct)), justified \(.excluded.justified | length) sources",
    "  branch coverage: \(.branch_coverage)"' "$out"
echo "SDK coverage report: $out"

[ "$rc" -eq 0 ] && echo "✓ SDK coverage accounting complete and floors hold"
exit "$rc"
