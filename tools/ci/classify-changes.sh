#!/usr/bin/env bash
#
# classify-changes.sh — which tests does a pull request need? (issue #656,
# extending the docs-only filter of issue #552, F-CI-009)
#
# The `changes` job of .github/workflows/c-cpp.yml and phase0-baseline.yml
# feeds it the pull request's changed paths (`git diff --name-only` of the
# merge commit against the base tip) and writes its answer to
# $GITHUB_OUTPUT. Every other run (push, tag, schedule, merge queue) feeds it
# an empty list, which is `full`.
#
# Five tiers, the highest any changed path reaches wins:
#   docs     docs/ and root-level Markdown only — the C jobs skip (#552)
#   tooling  CI and helper tooling (tools/ci, scripts, .github non-workflow
#            files, root dotfiles) that nothing outside tools/ci, scripts and
#            the unit suites references — the tooling self-test suites and
#            the suites that reference the file; no sanitizer, phase0 or
#            toolchain leg
#   tests    files of one unit suite or phase0 harness — those, the smoke
#            set and the golden/precision gates
#   family   one family's own sources (tcpip dissectors, mobile, dicom,
#            business_app) — that family's suites and harnesses, those that
#            name the file or reach it through a tools/ci delegate, the smoke
#            set, the gates, CodeQL and fuzzing
#   full     everything else — the whole suite and harness set, coverage,
#            root-install, abi-diff
# Pull requests never run the queue-only legs (unit-tests-unsigned-char and
# the -fsigned-char unit-tests leg, issue #658) whatever the tier; the merge
# queue, fed no path, runs them.
# The path-to-tier rules, the suite and harness tags and the smoke set live
# in tools/ci/test-map.txt (checked by tools/ci/check-test-map.sh).
#
# Fail-closed, every doubt is `full`:
#   - an empty list, an unreadable or malformed map, a suite of
#     tests/run_all_tests.sh DEFAULT_SUITES or a tools/phase0/tests/run_*.sh
#     the map does not name;
#   - a path git quoted (it starts with `"`: git's default core.quotePath
#     C-quotes non-ASCII and control bytes), or one with a backslash, a byte
#     outside printable ASCII, or a `.`/`..`/empty component;
#   - a path no map glob matches;
#   - a test or tooling file that something outside its own suite, harness
#     set or tooling directory references (by basename; a basename two
#     tracked files share is looked up with its parent directory);
#   - a list the tiers below `full` would leave without a suite or harness.
# Markdown, docs/, src/, the map, this script's self-test, the shape
# ratchets and the unreachable-section allowlist (which name paths as data)
# are never read as references; a reference in any other
# tracked file counts, comments included (over-selection is safe), except
# that a C file uses another C source or header only through an #include.
#
# Usage:   git diff --no-renames --name-only BASE HEAD \
#              | bash tools/ci/classify-changes.sh >> "$GITHUB_OUTPUT"
#          CLASSIFY_TEST_MAP (default tools/ci/test-map.txt) and
#          CLASSIFY_REPO_ROOT (default this script's repository) override
#          the inputs, for the self-test.
# Output:  six lines on stdout, in this order and only once the whole list
#          is classified:
#            code=true|false        false only on the docs tier (#552)
#            tier=docs|tooling|tests|family|full
#            full=true|false
#            gates=true|false       true on tests, family and full
#            suites=<a b ...>       sorted; empty = every suite (full) or
#                                   none (docs)
#            harnesses=<a,b,...>    run_<stem>.sh stems, sorted; empty = every
#                                   harness (full) or none (docs, tooling)
#          The reason and the counts go to stderr.
# Exit:    0 = classified; 2 = bad usage.

set -euo pipefail
export LC_ALL=C

if [ $# -ne 0 ]; then
    echo "usage: <changed paths, one per line> | bash $0" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${CLASSIFY_REPO_ROOT:-${SCRIPT_DIR}/../..}"
REPO="$(cd "${REPO}" && pwd)"
MAP="${CLASSIFY_TEST_MAP:-${REPO}/tools/ci/test-map.txt}"
case "${MAP}" in /*) ;; *) MAP="${PWD}/${MAP}" ;; esac

PATHS=()
while IFS= read -r path || [ -n "${path}" ]; do
    [ -n "${path}" ] && PATHS+=("${path}")
done

cd "${REPO}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

TIER_NAMES=(none docs tooling tests family full)
TIER=0
REASON=""
declare -A SEL_S=() SEL_H=() FAMS=()
HAS_DOCS=0
HAS_TOOLING=0

go_full() {
    if [ "${TIER}" -lt 5 ]; then
        TIER=5
        REASON="$1"
    fi
}
raise() { [ "$1" -le "${TIER}" ] || TIER="$1"; }

# --- the map -------------------------------------------------------------------
GLOBS=()
TOKENS=()
declare -A SUITE_TAGS=() HARN_TAGS=()
NAME_RE='^[a-z0-9_]+$'
map_error=""
load_map() {
    local line kind a b extra lineno=0 t tags
    if [ ! -r "${MAP}" ]; then
        map_error="cannot read ${MAP}"
        return
    fi
    while IFS= read -r line || [ -n "${line}" ]; do
        lineno=$((lineno + 1))
        kind="" a="" b="" extra=""
        read -r kind a b extra <<< "${line}" || true
        case "${kind}" in ''|'#'*) continue ;; esac
        if [ -z "${b}" ] || [ -n "${extra}" ]; then
            map_error="line ${lineno}: want three fields"
            return
        fi
        case "${kind}" in
            path)
                case "${b}" in
                    docs|tooling|suite|harness|tcpip|mobile|dicom|business_app|full) ;;
                    *) map_error="line ${lineno}: unknown token '${b}'"; return ;;
                esac
                GLOBS+=("${a}")
                TOKENS+=("${b}") ;;
            suite|harness)
                if [[ ! ${a} =~ ${NAME_RE} ]]; then
                    map_error="line ${lineno}: bad name '${a}'"
                    return
                fi
                IFS=, read -r -a tags <<< "${b}"
                for t in "${tags[@]}"; do
                    case "${t}" in
                        smoke|core|tcpip|mobile|dicom|business_app|security|tooling|docs|build|site) ;;
                        *) map_error="line ${lineno}: unknown tag '${t}'"; return ;;
                    esac
                done
                if [ "${kind}" = suite ]; then
                    [ -z "${SUITE_TAGS[${a}]+x}" ] || { map_error="line ${lineno}: duplicate suite ${a}"; return; }
                    SUITE_TAGS["${a}"]=",${b},"
                else
                    [ -z "${HARN_TAGS[${a}]+x}" ] || { map_error="line ${lineno}: duplicate harness ${a}"; return; }
                    HARN_TAGS["${a}"]=",${b},"
                fi ;;
            *) map_error="line ${lineno}: unknown record '${kind}'"; return ;;
        esac
    done < "${MAP}"
    if [ "${#GLOBS[@]}" -eq 0 ] || [ "${#SUITE_TAGS[@]}" -eq 0 ] \
       || [ "${#HARN_TAGS[@]}" -eq 0 ]; then
        map_error="no path, suite or harness record"
    fi
}

# Every suite and harness that exists must be mapped, or a change would
# silently leave it out.
check_coverage() {
    local s h n=0
    while IFS= read -r s; do
        n=$((n + 1))
        [ -n "${SUITE_TAGS[${s}]+x}" ] || { go_full "suite ${s} is not in the map"; return; }
    done < <(awk '
        !inside && /^[[:space:]]*DEFAULT_SUITES=\(/ { inside = 1; sub(/^[^(]*\(/, "") }
        inside {
            line = $0; sub(/#.*/, "", line)
            done = index(line, ")")
            if (done) line = substr(line, 1, done - 1)
            n = split(line, w, /[[:space:]]+/)
            for (i = 1; i <= n; i++) if (w[i] != "") print w[i]
            if (done) exit
        }' tests/run_all_tests.sh 2>/dev/null)
    [ "${n}" -gt 0 ] || { go_full "no DEFAULT_SUITES in tests/run_all_tests.sh"; return; }
    n=0
    while IFS= read -r h; do
        n=$((n + 1))
        h="${h#run_}"
        h="${h%.sh}"
        [ -n "${HARN_TAGS[${h}]+x}" ] || { go_full "harness ${h} is not in the map"; return; }
    done < <(find tools/phase0/tests -maxdepth 1 -name 'run_*.sh' -printf '%f\n' 2>/dev/null)
    [ "${n}" -gt 0 ] || go_full "no tools/phase0/tests/run_*.sh"
}

# --- references ------------------------------------------------------------------
# The tracked files a reference can come from: not docs/, src/ or Markdown,
# and not the two files that only describe the selection — the map and this
# script's self-test name paths as data, they do not run them. The shape
# ratchets (issue #547) and the unreachable-section allowlist (issue #541)
# name src/ functions as data too, and the gates that read them run in
# verify-helpers on every tier.
FILES="${WORK}/files"
list_files() {
    if [ -e .git ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git ls-files -z --cached --others --exclude-standard
    else
        find . -path ./.git -prune -o -type f -print0 | sed -z 's|^\./||'
    fi | { grep -zvE '^(docs|src)/|\.md$|^tools/ci/test-map\.txt$|^tools/ci/tests/test-classify-changes\.sh$|^tools/ci/(function-shape|param-count)-ratchet\.txt$|^tools/ci/unreachable-sections-allowlist\.txt$' || true; } > "${FILES}"
}
declare -A BASE_COUNT=()
count_basenames() {
    local f
    while IFS= read -r -d '' f; do
        f="${f##*/}"
        BASE_COUNT["${f}"]=$(( ${BASE_COUNT[${f}]:-0} + 1 ))
    done < "${FILES}"
}

# ref_key <path> — the string a reference to <path> contains: its basename,
# or <parent>/<basename> when two tracked files share the basename.
ref_key() {
    local base="${1##*/}" parent
    KEY="${base}"
    if [ "${BASE_COUNT[${base}]:-0}" -gt 1 ] && [[ $1 == */* ]]; then
        parent="${1%/*}"
        KEY="${parent##*/}/${base}"
    fi
}

is_source() {
    case "$1" in *.c|*.h|*.cc|*.cpp|*.hh|*.hpp|*.inc|*.def) return 0 ;; esac
    return 1
}

# lookup <string> — CONS: the files mentioning <string>, one per line
# (cached). C code depends on another C source or header only by including
# it, so when <string> names one, a C file counts only through an #include
# line, not a comment.
declare -A CONS_CACHE=()
lookup() {
    local raw c out=""
    if [ -z "${CONS_CACHE[$1]+x}" ]; then
        raw="$(xargs -0 -r grep -lsIF -e "$1" -- < "${FILES}" || true)"
        while IFS= read -r c; do
            [ -n "${c}" ] || continue
            if is_source "$1" && is_source "${c}" \
               && ! grep -sE '^[[:space:]]*#[[:space:]]*include' -- "${c}" | grep -qF -e "$1"; then
                continue
            fi
            out+="${c}"$'\n'
        done <<< "${raw}"
        CONS_CACHE["$1"]="${out}"
    fi
    CONS="${CONS_CACHE[$1]}"
}

suite_of() {   # suite_of <tests/<name>/...> — SUITE or empty
    local rest="${1#tests/}"
    SUITE=""
    case "${rest}" in */*) SUITE="${rest%%/*}" ;; esac
    [ -n "${SUITE}" ] && [ -n "${SUITE_TAGS[${SUITE}]+x}" ] || SUITE=""
}

# resolve <tools/phase0/tests/file> <mode> — select every harness and suite
# that runs the file, directly or through other files of tools/phase0/tests.
# A run_<stem>.sh selects <stem>. A consumer in a mapped suite selects the
# suite; one elsewhere makes the change full in mode `tests` and is ignored
# in mode `family` (the family tier runs every gate). A file that reaches no
# harness at all is full. RESOLVED=1 when a harness or suite was selected.
declare -A VISITED=()
RESOLVED=0
resolve() {
    local file="$1" mode="$2" base found=0 c stem
    base="${file##*/}"
    RESOLVED=0
    if [ -n "${VISITED[${file}]+x}" ]; then
        RESOLVED="${VISITED[${file}]}"
        return
    fi
    VISITED["${file}"]=1
    case "${base}" in
        run_*.sh)
            stem="${base#run_}"
            stem="${stem%.sh}"
            if [ -z "${HARN_TAGS[${stem}]+x}" ]; then
                go_full "${file} is not in the map"
                return
            fi
            SEL_H["${stem}"]=1
            found=1 ;;
    esac
    ref_key "${file}"
    lookup "${KEY}"
    while IFS= read -r c; do
        if [ -z "${c}" ] || [ "${c}" = "${file}" ]; then continue; fi
        case "${c}" in
            tools/phase0/tests/*/*)
                go_full "${c} references ${file}" ;;
            tools/phase0/tests/*)
                resolve "${c}" "${mode}"
                [ "${RESOLVED}" -eq 0 ] || found=1 ;;
            tests/*/*)
                suite_of "${c}"
                if [ -n "${SUITE}" ]; then
                    SEL_S["${SUITE}"]=1
                    found=1
                elif [ "${mode}" = tests ]; then
                    go_full "${c} references ${file}"
                fi ;;
            *)
                [ "${mode}" = family ] || go_full "${c} references ${file}" ;;
        esac
        [ "${TIER}" -lt 5 ] || return 0
    done <<< "${CONS}"
    [ "${found}" -eq 1 ] || go_full "${file} reaches no harness"
    VISITED["${file}"]="${found}"
    RESOLVED="${found}"
}

# --- one path --------------------------------------------------------------------
UNSAFE_RE='[^ -~]'
classify() {
    local p="$1" i g token=""
    case "${p}" in
        '"'*|*\\*|/*|./*|../*|*/./*|*/../*|*/.|*/..|*//*|*/)
            go_full "unsafe path ${p}"; return ;;
    esac
    if [[ ${p} =~ ${UNSAFE_RE} ]]; then
        go_full "unsafe path ${p}"
        return
    fi
    for i in "${!GLOBS[@]}"; do
        g="${GLOBS[${i}]}"
        [[ ${g} == */* || ${p} != */* ]] || continue
        # shellcheck disable=SC2053  # the map entry is a glob on purpose
        if [[ ${p} == ${g} ]]; then
            token="${TOKENS[${i}]}"
            break
        fi
    done
    case "${token}" in
        '') go_full "no map entry for ${p}" ;;
        full) go_full "${p} is mapped full" ;;
        docs) HAS_DOCS=1; raise 1 ;;
        tooling) HAS_TOOLING=1; raise 2; tooling "${p}" ;;
        suite) raise 3; test_file "${p}" ;;
        harness) raise 3; harness_file "${p}" ;;
        *) raise 4; FAMS["${token}"]=1; family_file "${p}" ;;
    esac
}

# A family source also selects every suite and harness that names it, and
# every suite that a tools/ci or scripts file naming it reaches (the
# self-test a suite delegates to), followed as a tooling change is: a
# consumer outside tools/ci, scripts and the suites makes it full.
family_file() {
    local c
    lookup "${1##*/}"
    while IFS= read -r c; do
        case "${c}" in
            tests/*/*)
                suite_of "${c}"
                [ -z "${SUITE}" ] || SEL_S["${SUITE}"]=1 ;;
            tools/phase0/tests/*)
                resolve "${c}" family ;;
            tools/ci/*|scripts/*)
                tooling "${c}" ;;
        esac
        [ "${TIER}" -lt 5 ] || return 0
    done <<< "${CONS}"
}

# tests/<suite>/<file>: that suite, unless something outside the suite
# references the file or the suite directory.
test_file() {
    local p="$1" c key
    suite_of "${p}"
    if [ -z "${SUITE}" ]; then
        go_full "${p} is not in a mapped suite"
        return
    fi
    ref_key "${p}"
    for key in "${KEY}" "tests/${SUITE}/"; do
        lookup "${key}"
        while IFS= read -r c; do
            case "${c}" in
                ''|"tests/${SUITE}/"*) ;;
                *) go_full "${c} references ${p}"; return ;;
            esac
        done <<< "${CONS}"
    done
    SEL_S["${SUITE}"]=1
}

# tools/phase0/tests/<file>: a run_<stem>.sh, or a source a run_*.sh names,
# selects the harnesses that run it; any other file there is shared (a
# header, a link helper, a suppression list) and full.
harness_file() {
    local p="$1" base="${1##*/}" c named=0
    case "${p#tools/phase0/tests/}" in */*) go_full "${p} is below tools/phase0/tests"; return ;; esac
    case "${base}" in
        run_*.sh) named=1 ;;
        *.c)
            lookup "${base}"
            while IFS= read -r c; do
                case "${c}" in tools/phase0/tests/run_*.sh) named=1 ;; esac
            done <<< "${CONS}" ;;
    esac
    if [ "${named}" -eq 0 ]; then
        go_full "${p} is shared by the harnesses"
        return
    fi
    resolve "${p}" tests
}

# Tooling: follow the references through tools/ci and scripts; a consumer
# anywhere but there, a mapped suite or a root dotfile makes it full. Each
# start file is followed once (family_file reaches the same delegate from
# many sources).
declare -A TOOLING_DONE=()
tooling() {
    local queue=("$1") q c n=0
    [ -z "${TOOLING_DONE[$1]+x}" ] || return 0
    TOOLING_DONE["$1"]=1
    declare -A seen=(["$1"]=1)
    while [ "${#queue[@]}" -gt 0 ]; do
        q="${queue[0]}"
        queue=("${queue[@]:1}")
        n=$((n + 1))
        [ "${n}" -le 200 ] || { go_full "tooling references of $1 do not settle"; return; }
        ref_key "${q}"
        lookup "${KEY}"
        while IFS= read -r c; do
            if [ -z "${c}" ] || [ "${c}" = "${q}" ]; then continue; fi
            case "${c}" in
                tools/ci/*|scripts/*)
                    if [ -z "${seen[${c}]+x}" ]; then
                        seen["${c}"]=1
                        queue+=("${c}")
                    fi ;;
                tests/run_all_tests.sh)
                    go_full "${c} references ${q}"; return ;;
                tests/*/*)
                    suite_of "${c}"
                    if [ -z "${SUITE}" ]; then
                        go_full "${c} references ${q}"
                        return
                    fi
                    SEL_S["${SUITE}"]=1 ;;
                .gitignore|.gitleaks.toml|.gitleaksignore|.pre-commit-config.yaml|.shellcheckrc) ;;
                *) go_full "${c} references ${q}"; return ;;
            esac
        done <<< "${CONS}"
    done
}

# --- classify --------------------------------------------------------------------
load_map
if [ -n "${map_error}" ]; then
    go_full "test map: ${map_error}"
else
    check_coverage
fi
if [ "${TIER}" -lt 5 ] && [ "${#PATHS[@]}" -eq 0 ]; then
    go_full "no changed path to classify"
fi
if [ "${TIER}" -lt 5 ]; then
    list_files
    count_basenames
    for p in "${PATHS[@]}"; do
        classify "${p}"
        [ "${TIER}" -lt 5 ] || break
    done
fi

# has_tag <tags> <tag...> — the ",a,b," tag list carries one of the tags.
has_tag() {
    local list="$1" t
    shift
    for t in "$@"; do
        case "${list}" in *",${t},"*) return 0 ;; esac
    done
    return 1
}

suites=""
harnesses=""
if [ "${TIER}" -ge 2 ] && [ "${TIER}" -le 4 ]; then
    want=()
    [ "${TIER}" -lt 3 ] || want+=(smoke)
    [ "${TIER}" -lt 4 ] || want+=("${!FAMS[@]}")
    s_want=("${want[@]}")
    [ "${HAS_TOOLING}" -eq 0 ] || s_want+=(tooling)
    [ "${HAS_DOCS}" -eq 0 ] || s_want+=(docs)
    for s in "${!SUITE_TAGS[@]}"; do
        if [ "${#s_want[@]}" -gt 0 ] && has_tag "${SUITE_TAGS[${s}]}" "${s_want[@]}"; then
            SEL_S["${s}"]=1
        fi
    done
    for h in "${!HARN_TAGS[@]}"; do
        if [ "${#want[@]}" -gt 0 ] && has_tag "${HARN_TAGS[${h}]}" "${want[@]}"; then
            SEL_H["${h}"]=1
        fi
    done
    [ "${TIER}" -ge 3 ] || SEL_H=()
    for n in "${!SEL_S[@]}" "${!SEL_H[@]}"; do
        [[ ${n} =~ ${NAME_RE} ]] || go_full "bad selected name '${n}'"
    done
    if [ "${TIER}" -lt 5 ]; then
        suites="$(printf '%s\n' "${!SEL_S[@]}" | sort -u | paste -sd' ' -)"
        harnesses="$(printf '%s\n' "${!SEL_H[@]}" | sort -u | paste -sd, -)"
        if [ -z "${suites}" ] || { [ "${TIER}" -ge 3 ] && [ -z "${harnesses}" ]; }; then
            go_full "the ${TIER_NAMES[${TIER}]} tier selected no suite or harness"
            suites=""
            harnesses=""
        fi
    fi
fi

tier="${TIER_NAMES[${TIER}]}"
code=true
[ "${TIER}" -ne 1 ] || code=false
full=false
[ "${TIER}" -ne 5 ] || full=true
gates=false
[ "${TIER}" -lt 3 ] || gates=true

case "${tier}" in
    full) echo "full: ${REASON} — every job runs everything (fail-closed)" >&2 ;;
    docs) echo "docs-only change (${#PATHS[@]} path(s)) — the C jobs skip" >&2 ;;
    *) echo "${tier} change (${#PATHS[@]} path(s)): suites=[${suites}] harnesses=[${harnesses}]" >&2 ;;
esac
printf 'code=%s\ntier=%s\nfull=%s\ngates=%s\nsuites=%s\nharnesses=%s\n' \
    "${code}" "${tier}" "${full}" "${gates}" "${suites}" "${harnesses}"
