#!/usr/bin/env bash
#
# sdk-coverage.sh — harvest and report the gcov counters of an instrumented
# SDK build (BUILD=coverage) reached by integration consumers (issue #387).
#
# The SDK compiles its objects in-tree, so a consumer run against a throwaway
# install prefix writes its .gcda next to the objects under src/, never into
# the prefix. Those counters survive the prefix cleanup but not the next SDK
# build: every recompile (-frandom-seed, rules/common.mk) deletes the object's
# .gcda and rewrites its .gcno. `harvest` therefore runs after each suite, turns
# the .gcda/.gcno pairs of that one build into plain TSV rows, and (--consume)
# deletes the harvested .gcda so a later suite cannot count them again.
#
#   harvest --gcda-root DIR --gcno-root DIR --repo-root DIR --out DIR [--consume]
#           [--unexecuted]
#       Pairs every DIR(gcda-root)/src/**/*.gcda with the .gcno at the same
#       relative path under --gcno-root (the two differ when a consumer ran
#       with GCOV_PREFIX), runs `gcov -j` per source directory (asn1c reuses
#       basenames across directories) and writes, with repo-relative src/
#       paths (logical and physical --repo-root both stripped):
#         OUT/lines.tsv      file <TAB> line <TAB> count
#         OUT/functions.tsv  file <TAB> function <TAB> execution_count
#       --unexecuted (issue #388) also reads every --gcno-root/src/**/*.gcno
#       that has no .gcda: an object the build compiled but no consumer ever
#       loaded. gcov reports its executable lines at count 0, so zero-hit
#       sources enter the denominator instead of being absent; with --consume
#       those .gcno are deleted too (the next SDK build rewrites them), so a
#       later suite does not read the same build again. This relies on every
#       SDK build running `make -C sdk clean` first (all SDK-building suites
#       do): an incremental coverage build would keep objects whose notes are
#       gone, and their next .gcda would fail the pairing above.
#       Nothing to harvest = exit 0 and OUT is not created.
#
#   report --unit-tsv FILE --harvest-dir DIR --repo-root DIR --summary FILE
#          [--combined-info FILE]
#       Adds a `cohorts` object to an existing summary.json, leaving its
#       top-level (unit-only, floor-checked) keys untouched:
#         unit             — the unit-suite rows (FILE: path <TAB> line <TAB> count)
#         sdk_integration  — every DIR/<suite>/lines.tsv, with a per-suite list
#         combined         — unit + sdk_integration, one record per
#                            repo-relative path and line
#         generated_asn1c  — rows under src/mmt_mobile/asn1c/ from any cohort,
#                            excluded from the three cohorts above
#       Each cohort states its denominator. --combined-info also writes the
#       combined cohort as an lcov tracefile.
#
# Exit codes: 0 = done, 1 = gcov/jq failed on the data, 2 = usage error or
#             missing tool.

set -euo pipefail

GENERATED_PREFIX="src/mmt_mobile/asn1c/"

usage() {
    sed -n '/^#   harvest/,/^#       combined cohort/p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

need() {
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 \
            || { echo "✗ sdk-coverage.sh: '$tool' is required" >&2; exit 2; }
    done
}

# Physical form of a directory (symlinks resolved), so paths gcov recorded
# through TOPDIR := $(realpath ...) (sdk/Makefile) and paths given through a
# symlinked checkout normalize to the same repo-relative name.
physical() {
    (cd "$1" && pwd -P)
}

# --- harvest -------------------------------------------------------------------
harvest() {
    local gcda_root="" gcno_root="" repo_root="" out="" consume=0 unexecuted=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --gcda-root)  gcda_root="${2:-}"; shift 2 ;;
            --gcno-root)  gcno_root="${2:-}"; shift 2 ;;
            --repo-root)  repo_root="${2:-}"; shift 2 ;;
            --out)        out="${2:-}"; shift 2 ;;
            --consume)    consume=1; shift ;;
            --unexecuted) unexecuted=1; shift ;;
            *) usage ;;
        esac
    done
    if [ -z "$gcda_root" ] || [ -z "$gcno_root" ] || [ -z "$repo_root" ] || [ -z "$out" ]; then usage; fi
    need gcov jq
    local d
    for d in "$gcda_root" "$gcno_root" "$repo_root"; do
        [ -d "$d" ] || { echo "✗ sdk-coverage.sh: no such directory: $d" >&2; exit 2; }
    done

    local gcda_list=()
    if [ -d "$gcda_root/src" ]; then
        mapfile -d '' gcda_list < <(find "$gcda_root/src" -name '*.gcda' -print0 | sort -z)
    fi

    # Stage each .gcda beside the .gcno of the same build, keeping the
    # src-relative tree so identical basenames in different directories stay
    # apart.
    local gcda gcno rel rels=() dirs=() zero_rels=() zero_list=()
    declare -A paired=()
    for gcda in "${gcda_list[@]}"; do
        rel="${gcda#"$gcda_root"/}"
        rel="${rel%.gcda}"
        if [ ! -f "$gcno_root/$rel.gcno" ]; then
            echo "✗ sdk-coverage.sh: no .gcno for $gcda (expected $gcno_root/$rel.gcno)" >&2
            return 1
        fi
        rels+=("$rel")
        paired["$rel"]=1
    done
    if [ "$unexecuted" -eq 1 ] && [ -d "$gcno_root/src" ]; then
        while IFS= read -r -d '' gcno; do
            rel="${gcno#"$gcno_root"/}"
            rel="${rel%.gcno}"
            [ -n "${paired[$rel]:-}" ] && continue
            zero_rels+=("$rel")
            zero_list+=("$gcno")
        done < <(find "$gcno_root/src" -name '*.gcno' -print0 | sort -z)
    fi
    [ "$((${#rels[@]} + ${#zero_rels[@]}))" -gt 0 ] || return 0

    local tmp="$WORK/harvest"
    mkdir -p "$tmp/stage"
    if [ "${#rels[@]}" -gt 0 ]; then
        printf '%s.gcda\0' "${rels[@]}" | (cd "$gcda_root" && xargs -0 cp --parents -t "$tmp/stage")
    fi
    printf '%s.gcno\0' "${rels[@]}" "${zero_rels[@]}" \
        | (cd "$gcno_root" && xargs -0 cp --parents -t "$tmp/stage")
    mapfile -t dirs < <(cd "$tmp/stage" && find . -name '*.gcno' -printf '%h\n' | sort -u)

    # gcov is named by .gcno: a note file with no .gcda beside it is reported
    # as not executed (every line count 0), which is what --unexecuted wants.
    local i=0 dir files=()
    for dir in "${dirs[@]}"; do
        i=$((i + 1))
        mkdir -p "$tmp/json/$i"
        mapfile -t files < <(find "$tmp/stage/$dir" -maxdepth 1 -name '*.gcno' | sort)
        if ! (cd "$tmp/json/$i" && gcov -j "${files[@]}" >"$tmp/gcov.err" 2>&1); then
            echo "✗ sdk-coverage.sh: gcov failed in $dir" >&2
            cat "$tmp/gcov.err" >&2
            return 1
        fi
    done

    local phys
    phys="$(physical "$repo_root")"
    mkdir -p "$out"
    # One jq pass over every JSON document: L rows (lines) and F rows
    # (functions), each keyed by the repo-relative source path, src/ only.
    if ! find "$tmp/json" -name '*.gcov.json.gz' -print0 \
            | xargs -0 zcat \
            | jq -r --arg log "${repo_root%/}" --arg phys "$phys" '
                .files[]
                | .file as $f
                | (if ($f | startswith($phys + "/")) then ($f | ltrimstr($phys + "/"))
                   elif ($f | startswith($log + "/")) then ($f | ltrimstr($log + "/"))
                   else null end) as $rel
                | select($rel != null and ($rel | startswith("src/")))
                | ((.lines[] | select(.line_number > 0)
                    | ["L", $rel, (.line_number | tostring), (.count | tostring)]),
                   (.functions[]
                    | ["F", $rel, (.demangled_name // .name), (.execution_count | tostring)]))
                | @tsv' >"$tmp/rows.tsv"; then
        echo "✗ sdk-coverage.sh: gcov JSON parsing failed" >&2
        return 1
    fi
    awk -F'\t' -v OFS='\t' -v lines="$out/lines.tsv" -v funcs="$out/functions.tsv" '
        BEGIN { printf "" > lines; printf "" > funcs }
        $1 == "L" { print $2, $3, $4 > lines }
        $1 == "F" { print $2, $3, $4 > funcs }
    ' "$tmp/rows.tsv"

    if [ "$consume" -eq 1 ]; then
        [ "${#gcda_list[@]}" -eq 0 ] || rm -f -- "${gcda_list[@]}"
        if [ "$unexecuted" -eq 1 ]; then
            # The paired notes go too: once their .gcda is consumed, a later
            # --unexecuted harvest would read them again as zero-hit objects.
            [ "${#zero_list[@]}" -eq 0 ] || rm -f -- "${zero_list[@]}"
            for rel in "${rels[@]}"; do rm -f -- "$gcno_root/$rel.gcno"; done
        fi
    fi
    echo "SDK coverage harvested: ${#gcda_list[@]} .gcda + ${#zero_rels[@]} unexecuted .gcno -> ${out}"
}

# --- report --------------------------------------------------------------------

# stats <rows.tsv> <denominator> — aggregates path<TAB>line<TAB>count rows
# (summing duplicate (path,line) records) into a cohort JSON object.
stats() {
    local rows="$1" denominator="$2" agg
    agg="$(sort -t "$(printf '\t')" -k 1,1 -k 2,2n "$rows" | awk -F'\t' '
        function flush_line() { if (cl != "") { lf++; if (cc > 0) lh++ } }
        $1 != cf {
            flush_line()
            if (cf != "") print "S\t" cf
            cf = $1; cl = ""; cc = 0
        }
        { if ($2 == cl) { cc += $3 } else { flush_line(); cl = $2; cc = $3 } }
        END {
            flush_line()
            if (cf != "") print "S\t" cf
            printf "T\t%d\t%d\n", lf, lh
        }')"
    printf '%s\n' "$agg" | jq -Rn --arg denominator "$denominator" '
        [inputs | split("\t")] as $rows
        | ($rows | map(select(.[0] == "T")) | .[0]) as $t
        | ($t[1] | tonumber) as $total | ($t[2] | tonumber) as $hit
        | [$rows[] | select(.[0] == "S") | .[1]] as $sources
        | {denominator: $denominator,
           lines_total: $total, lines_hit: $hit,
           line_pct: (if $total > 0 then ((1000 * $hit / $total) | round) / 10 else null end),
           files: ($sources | length), sources: $sources}'
}

# lcov <rows.tsv> <repo-root> — the rows as an lcov tracefile (the same record
# layout tests/run_all_tests.sh writes to coverage.info).
lcov() {
    sort -t "$(printf '\t')" -k 1,1 -k 2,2n "$1" | awk -F'\t' -v root="${2%/}" '
        function flush_line() {
            if (cl != "") { printf "DA:%s,%d\n", cl, cc; lf++; if (cc > 0) lh++ }
        }
        function flush_file() {
            flush_line()
            if (cf != "") printf "LF:%d\nLH:%d\nend_of_record\n", lf, lh
        }
        $1 != cf {
            flush_file()
            cf = $1
            printf "TN:combined\nSF:%s/%s\n", root, cf
            cl = ""; cc = 0; lf = 0; lh = 0
        }
        { if ($2 == cl) { cc += $3 } else { flush_line(); cl = $2; cc = $3 } }
        END { flush_file() }'
}

report() {
    local unit_tsv="" harvest_dir="" repo_root="" summary="" combined_info=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --unit-tsv)      unit_tsv="${2:-}"; shift 2 ;;
            --harvest-dir)   harvest_dir="${2:-}"; shift 2 ;;
            --repo-root)     repo_root="${2:-}"; shift 2 ;;
            --summary)       summary="${2:-}"; shift 2 ;;
            --combined-info) combined_info="${2:-}"; shift 2 ;;
            *) usage ;;
        esac
    done
    if [ -z "$unit_tsv" ] || [ -z "$harvest_dir" ] || [ -z "$repo_root" ] || [ -z "$summary" ]; then usage; fi
    need jq
    [ -f "$unit_tsv" ] || { echo "✗ sdk-coverage.sh: missing unit TSV $unit_tsv" >&2; exit 2; }
    [ -d "$harvest_dir" ] || { echo "✗ sdk-coverage.sh: missing harvest dir $harvest_dir" >&2; exit 2; }
    [ -s "$summary" ] || { echo "✗ sdk-coverage.sh: missing summary $summary" >&2; exit 2; }
    jq -e 'type == "object"' "$summary" >/dev/null 2>&1 \
        || { echo "✗ sdk-coverage.sh: $summary is not a JSON object" >&2; exit 2; }

    local tmp="$WORK/report" log phys
    mkdir -p "$tmp"
    log="${repo_root%/}"
    phys="$(physical "$repo_root")"

    # Normalize unit rows (absolute paths, logical or physical root) to
    # repo-relative src/ paths, then split handwritten from generated.
    awk -F'\t' -v OFS='\t' -v log_root="$log/" -v phys_root="$phys/" '
        {
            f = $1
            if (index(f, phys_root) == 1) f = substr(f, length(phys_root) + 1)
            else if (index(f, log_root) == 1) f = substr(f, length(log_root) + 1)
            if (f ~ /^src\//) print f, $2, $3
        }' "$unit_tsv" >"$tmp/unit.all"

    : >"$tmp/sdk.all"
    local suites=() suite
    mapfile -t suites < <(find "$harvest_dir" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
    for suite in "${suites[@]}"; do
        [ -f "$harvest_dir/$suite/lines.tsv" ] || continue
        cat "$harvest_dir/$suite/lines.tsv" >>"$tmp/sdk.all"
    done

    local gen="$GENERATED_PREFIX"
    awk -F'\t' -v g="$gen" 'index($1, g) != 1' "$tmp/unit.all" >"$tmp/unit.tsv"
    awk -F'\t' -v g="$gen" 'index($1, g) != 1' "$tmp/sdk.all" >"$tmp/sdk.tsv"
    cat "$tmp/unit.tsv" "$tmp/sdk.tsv" >"$tmp/combined.tsv"
    cat "$tmp/unit.all" "$tmp/sdk.all" | awk -F'\t' -v g="$gen" 'index($1, g) == 1' >"$tmp/generated.tsv"

    stats "$tmp/unit.tsv" \
        "executable src/ lines recorded by the unit-suite binaries (tests/**/*.gcda), ${GENERATED_PREFIX} excluded; the top-level library_* keys and floor.json measure these same unit records" \
        >"$tmp/unit.json"
    stats "$tmp/sdk.tsv" \
        "executable src/ lines of the BUILD=coverage SDK builds made by the SDK-building suites (harvested after each suite): lines their integration consumers ran (src/**/*.gcda) plus, from the .gcno of objects that wrote no .gcda, the zero-hit sources at count 0 (issue #388); ${GENERATED_PREFIX} excluded" \
        >"$tmp/sdk.json"
    stats "$tmp/combined.tsv" \
        "union of the unit and sdk_integration records, ${GENERATED_PREFIX} excluded" \
        >"$tmp/combined.json"
    stats "$tmp/generated.tsv" \
        "executable lines of the generated ASN.1 sources under ${GENERATED_PREFIX}, from any cohort" \
        >"$tmp/generated.json"

    local per_suite="[]" s_json
    for suite in "${suites[@]}"; do
        [ -f "$harvest_dir/$suite/lines.tsv" ] || continue
        awk -F'\t' -v g="$gen" 'index($1, g) != 1' "$harvest_dir/$suite/lines.tsv" >"$tmp/suite.tsv"
        s_json="$(stats "$tmp/suite.tsv" "-" | jq --arg s "$suite" \
            '{suite: $s, lines_total, lines_hit, line_pct, files}')"
        per_suite="$(jq --argjson row "$s_json" '. + [$row]' <<<"$per_suite")"
    done

    local combined_rel=""
    if [ -n "$combined_info" ]; then
        lcov "$tmp/combined.tsv" "$log" >"$combined_info"
        combined_rel="${combined_info#"$log"/}"
    fi

    jq --slurpfile unit "$tmp/unit.json" \
       --slurpfile sdk "$tmp/sdk.json" \
       --slurpfile combined "$tmp/combined.json" \
       --slurpfile generated "$tmp/generated.json" \
       --argjson suites "$per_suite" \
       --arg gen "$GENERATED_PREFIX" \
       --arg info "$combined_rel" '
        . + {cohorts: {
            unit: $unit[0],
            sdk_integration: ($sdk[0] + {suites: $suites}),
            combined: ($combined[0] + {
                dedup: "source paths normalized to repo-relative form (logical and physical repo roots both stripped); records with the same (path, line) are summed across cohorts, so each source and line is counted once",
                tracefile: (if $info == "" then null else $info end)}),
            generated_asn1c: ($generated[0] + {
                prefix: $gen,
                excluded_from: ["unit", "sdk_integration", "combined"]})
        }}' "$summary" >"$tmp/summary.json"
    mv "$tmp/summary.json" "$summary"

    jq -r '.cohorts | to_entries[]
        | "Coverage cohort \(.key): \(if .value.line_pct == null then "n/a" else "\(.value.line_pct)%" end) (\(.value.lines_hit)/\(.value.lines_total) lines, \(.value.files) files)"' \
        "$summary"
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

case "${1:-}" in
    harvest) shift; harvest "$@" ;;
    report)  shift; report "$@" ;;
    *) usage ;;
esac
