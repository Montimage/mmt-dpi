#!/usr/bin/env bash
#
# check-test-map.sh — tools/ci/test-map.txt against the suites and harnesses
# that exist (issue #656).
#
# tools/ci/classify-changes.sh selects a pull request's suites and harnesses
# from the map, so an entry that is missing or under-tagged would silently
# leave a test out of the pull requests that need it. This check fails when:
#   - a line is malformed: not three fields, an unknown record, path token or
#     tag, a bad name, a duplicate suite or harness;
#   - a suite of DEFAULT_SUITES (tests/run_all_tests.sh, read, not run) or a
#     tools/phase0/tests/run_<stem>.sh has no entry, or an entry names one
#     that does not exist (stale);
#   - an entry's files — every file of tests/<suite>/, or run_<stem>.sh
#     plus the tools/phase0/tests files it names; then the tools/ci and
#     tools/phase0 files the suite's files or the run_<stem>.sh name, and
#     the ones each such tools/ci file names, transitively (a suite that
#     delegates to tools/ci/tests carries what the delegate loads) — load a
#     family's library or sources (the patterns in FAMILY_RE below) and the
#     entry carries neither that family's tag nor `smoke`;
#   - an entry tagged only with families (no smoke, tooling, docs, build or
#     site tag) names no source file of one of them — each tagged family
#     but core and security (whose sources are `full`) needs one: an entry
#     is family-selective only when it targets each of its families'
#     sources by name; anything else exercising the SDK (a whole-SDK test
#     tagged tcpip only through its runtime dependency) must be `smoke`;
#   - no suite or no harness is tagged `smoke`.
#
# Usage: bash tools/ci/check-test-map.sh [MAP [RUNNER [HARNESS_DIR]]]
#        (defaults: tools/ci/test-map.txt, tests/run_all_tests.sh,
#        tools/phase0/tests; the suites live next to RUNNER)
# Exit:  0 = consistent; 1 = a problem, each named on stderr; 2 = bad usage
#        or a missing input.
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ $# -gt 3 ]; then
    echo "usage: bash $0 [MAP [RUNNER [HARNESS_DIR]]]" >&2
    exit 2
fi
MAP="${1:-${ROOT}/tools/ci/test-map.txt}"
RUNNER="${2:-${ROOT}/tests/run_all_tests.sh}"
HDIR="${3:-${ROOT}/tools/phase0/tests}"
for f in "${MAP}" "${RUNNER}"; do
    [ -f "${f}" ] || { echo "check-test-map: no such file: ${f}" >&2; exit 2; }
done
[ -d "${HDIR}" ] || { echo "check-test-map: no such directory: ${HDIR}" >&2; exit 2; }
SUITE_DIR="$(cd "$(dirname "${RUNNER}")" && pwd)"

problems=0
problem() { echo "check-test-map: $*" >&2; problems=$((problems + 1)); }

# --- parse the map ---------------------------------------------------------------
declare -A SUITE_TAGS=() HARN_TAGS=()
rules=0
lineno=0
while IFS= read -r line || [ -n "${line}" ]; do
    lineno=$((lineno + 1))
    kind="" a="" b="" extra=""
    read -r kind a b extra <<< "${line}" || true
    case "${kind}" in ''|'#'*) continue ;; esac
    if [ -z "${b}" ] || [ -n "${extra}" ]; then
        problem "line ${lineno}: want three fields: ${line}"
        continue
    fi
    case "${kind}" in
        path)
            case "${b}" in
                docs|tooling|suite|harness|tcpip|mobile|dicom|business_app|full) rules=$((rules + 1)) ;;
                *) problem "line ${lineno}: unknown path token '${b}'" ;;
            esac ;;
        suite|harness)
            if [[ ! ${a} =~ ^[a-z0-9_]+$ ]]; then
                problem "line ${lineno}: bad ${kind} name '${a}'"
                continue
            fi
            IFS=, read -r -a tags <<< "${b}"
            for t in "${tags[@]}"; do
                case "${t}" in
                    smoke|core|tcpip|mobile|dicom|business_app|security|tooling|docs|build|site) ;;
                    *) problem "line ${lineno}: ${kind} ${a}: unknown tag '${t}'" ;;
                esac
            done
            if [ "${kind}" = suite ]; then
                [ -z "${SUITE_TAGS[${a}]+x}" ] || problem "line ${lineno}: duplicate suite ${a}"
                SUITE_TAGS["${a}"]=",${b},"
            else
                [ -z "${HARN_TAGS[${a}]+x}" ] || problem "line ${lineno}: duplicate harness ${a}"
                HARN_TAGS["${a}"]=",${b},"
            fi ;;
        *) problem "line ${lineno}: unknown record '${kind}'" ;;
    esac
done < "${MAP}"
[ "${rules}" -gt 0 ] || problem "no path record"

# --- what exists -------------------------------------------------------------------
mapfile -t SUITES < <(awk '
    !inside && /^[[:space:]]*DEFAULT_SUITES=\(/ { inside = 1; sub(/^[^(]*\(/, "") }
    inside {
        line = $0; sub(/#.*/, "", line)
        done = index(line, ")")
        if (done) line = substr(line, 1, done - 1)
        n = split(line, w, /[[:space:]]+/)
        for (i = 1; i <= n; i++) if (w[i] != "") print w[i]
        if (done) exit
    }' "${RUNNER}")
mapfile -t HARNESSES < <(find "${HDIR}" -maxdepth 1 -name 'run_*.sh' -printf '%f\n' \
                         | sed 's/^run_//; s/\.sh$//' | sort)
[ "${#SUITES[@]}" -gt 0 ] || problem "no DEFAULT_SUITES in ${RUNNER}"
[ "${#HARNESSES[@]}" -gt 0 ] || problem "no run_*.sh under ${HDIR}"

declare -A IS_SUITE=() IS_HARN=()
for s in "${SUITES[@]}"; do
    IS_SUITE["${s}"]=1
    [ -n "${SUITE_TAGS[${s}]+x}" ] || problem "suite ${s} (DEFAULT_SUITES) has no map entry"
done
for h in "${HARNESSES[@]}"; do
    IS_HARN["${h}"]=1
    [ -n "${HARN_TAGS[${h}]+x}" ] || problem "harness ${h} (run_${h}.sh) has no map entry"
done
for s in "${!SUITE_TAGS[@]}"; do
    [ -n "${IS_SUITE[${s}]+x}" ] || problem "suite ${s} is mapped but not in DEFAULT_SUITES (stale entry)"
done
for h in "${!HARN_TAGS[@]}"; do
    [ -n "${IS_HARN[${h}]+x}" ] || problem "harness ${h} is mapped but run_${h}.sh does not exist (stale entry)"
done

smoke_s=0
smoke_h=0
for s in "${!SUITE_TAGS[@]}"; do case "${SUITE_TAGS[${s}]}" in *,smoke,*) smoke_s=1 ;; esac; done
for h in "${!HARN_TAGS[@]}"; do case "${HARN_TAGS[${h}]}" in *,smoke,*) smoke_h=1 ;; esac; done
[ "${smoke_s}" -eq 1 ] || problem "no suite is tagged smoke"
[ "${smoke_h}" -eq 1 ] || problem "no harness is tagged smoke"

# --- tags against the entries' own files ---------------------------------------------
# A family's runtime dependency, as an entry's files show it.
declare -A FAMILY_RE=(
    [tcpip]='lmmt_tcpip|libmmt_tcpip|mmt_static_plugin_link|src/mmt_tcpip|packet_process|mmt_init_handler|make -C [^ ]*sdk'
    [mobile]='src/mmt_mobile|lmmt_tmobile|libmmt_tmobile'
    [dicom]='src/mmt_dicom|lmmt_tdicom|libmmt_tdicom'
    [business_app]='src/mmt_business_app|lmmt_business_app|libmmt_business_app'
)
# A family's source files, by basename (what an entry that targets them names).
declare -A FAMILY_SRC=(
    [core]=src/mmt_core [tcpip]=src/mmt_tcpip [mobile]=src/mmt_mobile
    [dicom]=src/mmt_dicom [business_app]=src/mmt_business_app [security]=src/mmt_security
)
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
for fam in "${!FAMILY_SRC[@]}"; do
    if git -C "${ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git -C "${ROOT}" ls-files -- "${FAMILY_SRC[${fam}]}"
    else
        (cd "${ROOT}" && find "${FAMILY_SRC[${fam}]}" -type f 2>/dev/null)
    fi | sed -n 's|.*/\([^/]*\.c\)$|\1|p' | sort -u > "${WORK}/${fam}.src"
done

# check_entry <kind> <name> <tags> <file>... — the two tag rules above.
check_entry() {
    local kind="$1" name="$2" taglist="$3" fam shown
    shift 3
    [ "$#" -gt 0 ] || { problem "${kind} ${name}: no file to read"; return; }
    for fam in "${!FAMILY_RE[@]}"; do
        if grep -sqIE -e "${FAMILY_RE[${fam}]}" -- "$@"; then
            case "${taglist}" in
                *",${fam},"*|*,smoke,*) ;;
                *) problem "${kind} ${name}: its files load ${fam} (${FAMILY_RE[${fam}]}) but it is tagged neither ${fam} nor smoke" ;;
            esac
        fi
    done
    case "${taglist}" in *,smoke,*|*,tooling,*|*,docs,*|*,build,*|*,site,*) return ;; esac
    shown="${taglist#,}"
    shown="${shown%,}"
    # core and security sources are `full`, so those two tags never select.
    for fam in tcpip mobile dicom business_app; do
        case "${taglist}" in *",${fam},"*) ;; *) continue ;; esac
        if [ ! -s "${WORK}/${fam}.src" ] || ! grep -sqIF -f "${WORK}/${fam}.src" -- "$@"; then
            problem "${kind} ${name}: tagged ${shown} without smoke but names no ${fam} source file — tag it smoke"
        fi
    done
}

# dir_files <dir> — its files: tracked and new ones in a checkout (no build
# output), every file elsewhere.
dir_files() {
    if git -C "$1" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git -C "$1" ls-files --cached --others --exclude-standard -- . \
            | sed "s|^|$1/|" | while IFS= read -r f; do [ ! -f "${f}" ] || echo "${f}"; done
    else
        find "$1" -type f
    fi | sort
}

# --- delegates: the tools/ci and tools/phase0 files an entry's files name ------
# Named by basename (what a reference contains). Markdown and the files that
# only describe the selection — the map, this checker, the classifier's
# self-test — name paths as data and are never followed (as in
# classify-changes.sh).
DELEG_LIST="${WORK}/delegates"
if git -C "${ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "${ROOT}" ls-files --cached --others --exclude-standard -- tools/ci tools/phase0
else
    (cd "${ROOT}" && find tools/ci tools/phase0 -type f 2>/dev/null)
fi | grep -vE '\.md$|^tools/ci/test-map\.txt$|^tools/ci/check-test-map\.sh$|^tools/ci/tests/test-classify-changes\.sh$' \
   | while IFS= read -r f; do [ ! -f "${ROOT}/${f}" ] || echo "${f}"; done | sort > "${DELEG_LIST}"
declare -A DELEG_BY_BASE=()
while IFS= read -r f; do
    DELEG_BY_BASE["${f##*/}"]+="${ROOT}/${f}"$'\n'
done < "${DELEG_LIST}"
sed 's|.*/||' "${DELEG_LIST}" | sort -u > "${WORK}/delegate-names"

# named_by <file> — NAMED: the delegate files <file> names (cached).
declare -A NAMED_CACHE=()
named_by() {
    local b out=""
    if [ -z "${NAMED_CACHE[$1]+x}" ]; then
        while IFS= read -r b; do
            if [ -z "${b}" ] || [ -z "${DELEG_BY_BASE[${b}]+x}" ]; then continue; fi
            out+="${DELEG_BY_BASE[${b}]}"
        done < <(grep -ohsIF -f "${WORK}/delegate-names" -- "$1" | sort -u)
        NAMED_CACHE["$1"]="${out}"
    fi
    NAMED="${NAMED_CACHE[$1]}"
}

# add_delegates <seed>... — append to `files` the delegate files the seeds
# name — the entry's own files: a suite's, a harness's run_<stem>.sh (its
# test sources' shared headers are not followed) — and, in turn, the ones
# each tools/ci delegate names (bounded by the visited set).
add_delegates() {
    local -A seen=()
    local queue=("$@") f c
    for f in "${files[@]}"; do seen["${f}"]=1; done
    while [ "${#queue[@]}" -gt 0 ]; do
        f="${queue[0]}"
        queue=("${queue[@]:1}")
        named_by "${f}"
        while IFS= read -r c; do
            if [ -z "${c}" ] || [ -n "${seen[${c}]+x}" ]; then continue; fi
            seen["${c}"]=1
            files+=("${c}")
            case "${c}" in "${ROOT}/tools/ci/"*) queue+=("${c}") ;; esac
        done <<< "${NAMED}"
    done
}

for s in "${!SUITE_TAGS[@]}"; do
    [ -d "${SUITE_DIR}/${s}" ] || continue
    mapfile -t files < <(dir_files "${SUITE_DIR}/${s}")
    add_delegates "${files[@]}"
    check_entry suite "${s}" "${SUITE_TAGS[${s}]}" "${files[@]}"
done
mapfile -t HFILES < <(dir_files "${HDIR}" | sed -n 's|.*/||; /^run_.*\.sh$/!p')
for h in "${!HARN_TAGS[@]}"; do
    run="${HDIR}/run_${h}.sh"
    [ -f "${run}" ] || continue
    files=("${run}")
    text="$(< "${run}")"
    for g in "${HFILES[@]}"; do
        [[ ${text} != *"${g}"* ]] || files+=("${HDIR}/${g}")
    done
    add_delegates "${run}"
    check_entry harness "${h}" "${HARN_TAGS[${h}]}" "${files[@]}"
done

if [ "${problems}" -gt 0 ]; then
    echo "check-test-map: ${problems} problem(s) in ${MAP}" >&2
    exit 1
fi
echo "check-test-map: OK — ${#SUITES[@]} suites, ${#HARNESSES[@]} harnesses, ${rules} path rules"
