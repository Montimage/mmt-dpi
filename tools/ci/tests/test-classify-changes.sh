#!/usr/bin/env bash
# test-classify-changes.sh — self-test for the path-to-test selection
# (tools/ci/classify-changes.sh with tools/ci/test-map.txt, issues #552,
# #656) and for the CI job set it feeds (issues #528, #552, #656).
#
# (1) Drives the real classifier on path lists and checks its six output
#     lines (code, tier, full, gates, suites, harnesses) and their invariants
#     after every fixture:
#       - docs/ and root-level Markdown are docs (code=false);
#       - one tcpip dissector is the family tier: the tcpip suites and
#         harnesses, the smoke set (which holds the whole-SDK dicom_test,
#         s1ap_ngap_decode, nas_ies_tail and rule_engine), nothing of
#         another family's own tests;
#       - the core, any header, a transport dissector, rules/, sdk/, a
#         workflow or action, the runners, the map, an unmapped path and an
#         empty list are full with empty lists;
#       - a quoted, non-ASCII, backslash, tab or `..` path is full;
#       - suite, harness and tooling files select what runs them, and are
#         full when something outside references them.
#     Then tools/ci/check-test-map.sh passes on the tree and fails on map
#     copies missing a suite or a harness, with a stale entry, an unknown
#     tag, a missing family tag, a mis-tagged dissector harness or an
#     entry naming a source of only some of its families without smoke.
# (2) Reads .github/workflows/c-cpp.yml and phase0-baseline.yml and pins the
#     wiring that keeps every required context reporting on every tier:
#       - each workflow has a `changes` job with the same classify step and
#         the six outputs; a non-pull-request run feeds it /dev/null (full);
#       - every job that needs `changes` and has a job-level `if:` keeps
#         !cancelled() or always() in it, so a failed `changes` runs the job
#         instead of skipping it (a skipped job reports success: fail-open);
#       - every condition on the outputs is fail-closed (`!= 'false'`, no
#         `== 'true'`), and jobs read only the six outputs;
#       - single-context C jobs skip at job level on code=false, the
#         full-only, gates and family-only sets carry their conditions;
#       - matrix C jobs never skip at job level (a skipped matrix reports only
#         its bare name) and skip every step instead;
#       - the suite legs run the tier's suite list;
#       - the docs jobs never skip, and doc-validators runs docs_lifecycle on
#         a docs-only change;
#       - every c-cpp.yml job is in exactly one of those sets, so a new job
#         has to be classified;
#     plus the issue #528 jobs (native ARM and x86 -funsigned-char suite
#     legs, both required); the issue #659 folds (enablesec and the phase0
#     asan-build are `if: false` stubs of retired contexts, the BUILD=asan
#     check is a sanitizer asan-leg step, site-onboarding is verify-helpers'
#     last step, resource-budgets is arm64 only); and the issue #658
#     queue-only legs (unit-tests-unsigned-char, the -fsigned-char leg,
#     coverage, toolchain-floor and assertions-live skip on pull requests;
#     `build` needs the last two under !cancelled(), and its gate step, run
#     over every event and result, fails unless each succeeded;
#     unit-tests-arm, toolchain-ceiling, the default unit-tests leg and the
#     sanitizer legs stay on pull requests).
#
# Part (2) needs python3 with PyYAML: without it, it reports SKIP, unless
# REQUIRE_PYYAML=1 (the verify-helpers job), under which that fails.
#
# Usage: bash tools/ci/tests/test-classify-changes.sh
# Exit: 0 = all checks passed, 1 = at least one failed.
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CLASSIFIER="${REPO_ROOT}/tools/ci/classify-changes.sh"

pass=0
fail=0
ok()  { echo "  PASS $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }

CHECKER="${REPO_ROOT}/tools/ci/check-test-map.sh"
MAP="${REPO_ROOT}/tools/ci/test-map.txt"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "=== classify-changes self-test ==="

# expect_class <want: true|false> <label> <path>... — the first output line.
expect_class() {
    local want="$1" label="$2" out rc
    shift 2
    out="$(printf '%s\n' "$@" | bash "$CLASSIFIER" 2>/dev/null)"
    rc=$?
    if [ "$rc" -eq 0 ] && [ "$(head -n 1 <<< "$out")" = "code=${want}" ]; then
        ok "$label -> code=${want}"
    else
        bad "$label: got '$(head -n 1 <<< "$out")' (exit ${rc}), want code=${want}"
    fi
}

expect_class false "docs/ tree only" docs/USER_GUIDE.md docs/index.html \
    docs/first-run/hello_packet.c docs/_config.yml
expect_class false "root-level Markdown only" README.md CHANGELOG.md AGENTS.md
expect_class false "docs/ plus root Markdown" docs/DECISIONS.md CONTRIBUTING.md
expect_class true  "a source file among docs" docs/USER_GUIDE.md src/mmt_core/src/packet_processing.c
expect_class true  "Markdown under src/ is code" src/mmt_mobile/asn1c/support/DELTA-r16.1.0.md
expect_class true  "Markdown under tests/ is code" tests/docs_onboarding/README.md
expect_class true  "a workflow change is code" .github/workflows/c-cpp.yml
expect_class true  "a root file that is not Markdown is code" LICENSE
expect_class true  "a tool script is code" tools/ci/classify-changes.sh
expect_class true  "an empty list is code (fail-closed)" ""
out="$(printf 'README.md' | bash "$CLASSIFIER" 2>/dev/null)"
if [ "$(head -n 1 <<< "$out")" = "code=false" ]; then ok "a last line without a newline is read"
else bad "a last line without a newline: got '${out}'"; fi
if bash "$CLASSIFIER" unexpected-arg </dev/null >/dev/null 2>&1; then
    bad "an argument is bad usage (exit 2)"
else
    rc=$?
    if [ "$rc" -eq 2 ]; then ok "an argument is bad usage (exit 2)"
    else bad "an argument: exit ${rc}, want 2"; fi
fi

echo "=== tiers and selections (issue #656) ==="
mapfile -t ALL_SUITES < <(awk '/^DEFAULT_SUITES=\(/ {f = 1; next} f && /^\)/ {exit} f {print $1}' \
                              "${REPO_ROOT}/tests/run_all_tests.sh")
SMOKE_SUITES="hashmap memory core_engine mmt_utils proto_classifiers parser_boundaries"
SMOKE_HARNESSES="tcpip_pcap_harness_test mobile_pcap_harness_test mt_tsan_test"

# run_case <path>... — OUT (stdout), RC, and K[key] for each output line,
# with every invariant of the output contract checked.
declare -A K=()
run_case() {
    local label="$1" line keys="" n
    shift
    OUT="$(printf '%s\n' "$@" | bash "$CLASSIFIER" 2>/dev/null)"
    RC=$?
    K=()
    while IFS= read -r line; do
        [ -n "${line}" ] || continue
        keys="${keys}${line%%=*} "
        K["${line%%=*}"]="${line#*=}"
    done <<< "${OUT}"
    local errs=()
    [ "${RC}" -eq 0 ] || errs+=("exit ${RC}")
    [ "${keys}" = "code tier full gates suites harnesses " ] || errs+=("keys '${keys}'")
    case "${K[tier]:-}" in
        docs|tooling|tests|family|full) ;;
        *) errs+=("tier '${K[tier]:-}'") ;;
    esac
    { [ "${K[code]:-}" = false ] && [ "${K[tier]:-}" = docs ]; } \
        || { [ "${K[code]:-}" = true ] && [ "${K[tier]:-}" != docs ]; } || errs+=("code/tier")
    { [ "${K[full]:-}" = true ] && [ "${K[tier]:-}" = full ]; } \
        || { [ "${K[full]:-}" = false ] && [ "${K[tier]:-}" != full ]; } || errs+=("full/tier")
    case "${K[tier]:-}" in
        tests|family|full) [ "${K[gates]:-}" = true ] || errs+=("gates") ;;
        *) [ "${K[gates]:-}" = false ] || errs+=("gates") ;;
    esac
    case "${K[tier]:-}" in
        full|docs) [ -z "${K[suites]:-}" ] && [ -z "${K[harnesses]:-}" ] || errs+=("lists not empty") ;;
        tooling) [ -n "${K[suites]:-}" ] && [ -z "${K[harnesses]:-}" ] || errs+=("tooling lists") ;;
        tests|family) [ -n "${K[suites]:-}" ] && [ -n "${K[harnesses]:-}" ] || errs+=("empty list") ;;
    esac
    [ "${K[suites]:-}" = "$(tr ' ' '\n' <<< "${K[suites]:-}" | sed '/^$/d' | LC_ALL=C sort -u | paste -sd' ' -)" ] \
        || errs+=("suites not sorted/unique")
    [ "${K[harnesses]:-}" = "$(tr ',' '\n' <<< "${K[harnesses]:-}" | sed '/^$/d' | LC_ALL=C sort -u | paste -sd, -)" ] \
        || errs+=("harnesses not sorted/unique")
    for n in ${K[suites]:-}; do
        printf '%s\n' "${ALL_SUITES[@]}" | grep -qx -- "${n}" || errs+=("unknown suite ${n}")
    done
    for n in ${K[harnesses]//,/ }; do
        [ -f "${REPO_ROOT}/tools/phase0/tests/run_${n}.sh" ] || errs+=("unknown harness ${n}")
    done
    if [ "${#errs[@]}" -eq 0 ]; then ok "${label}: output contract holds"
    else bad "${label}: output contract: ${errs[*]} — ${OUT//$'\n'/ }"; fi
}
want_tier() {
    if [ "${K[tier]:-}" = "$2" ]; then ok "$1 -> tier=$2"
    else bad "$1: tier=${K[tier]:-} (want $2)"; fi
}
has()     { [[ " $2 " == *" $3 "* ]]; }
suite_in()  { if has "$1" "${K[suites]:-}" "$2"; then ok "$1 selects suite $2"; else bad "$1 does not select suite $2"; fi; }
suite_out() { if has "$1" "${K[suites]:-}" "$2"; then bad "$1 selects suite $2"; else ok "$1 leaves out suite $2"; fi; }
harn_in()   { if has "$1" "${K[harnesses]//,/ }" "$2"; then ok "$1 selects harness $2"; else bad "$1 does not select harness $2"; fi; }
harn_out()  { if has "$1" "${K[harnesses]//,/ }" "$2"; then bad "$1 selects harness $2"; else ok "$1 leaves out harness $2"; fi; }
expect_tier() {   # expect_tier <tier> <label> <path>...
    local tier="$1" label="$2"
    shift 2
    run_case "${label}" "$@"
    want_tier "${label}" "${tier}"
}

# AC1: one dissector of the tcpip family.
L="proto_dns.c (tcpip family)"
expect_tier family "$L" src/mmt_tcpip/lib/protocols/proto_dns.c
for s in ${SMOKE_SUITES} citrix_ica_detection radius_hardening s1ap_ngap_decode; do suite_in "$L" "$s"; done
for s in dicom_dissector hexdump mmt_inet_ntop; do suite_out "$L" "$s"; done
for h in ${SMOKE_HARNESSES} dns_parser_test ssl_record_test dicom_test; do harn_in "$L" "$h"; done
L="dicom.c (dicom family)"
expect_tier family "$L" src/mmt_dicom/dicom.c
for s in ${SMOKE_SUITES} dicom_dissector; do suite_in "$L" "$s"; done
for s in s1ap_ngap_decode nas_ies_tail rule_engine; do suite_in "$L" "$s"; done
suite_out "$L" citrix_ica_detection
for h in ${SMOKE_HARNESSES} dicom_test; do harn_in "$L" "$h"; done
for h in ssl_record_test http2_parser_test; do harn_out "$L" "$h"; done
L="proto_s1ap.c (mobile family)"
expect_tier family "$L" src/mmt_mobile/proto_s1ap.c
for s in s1ap_ngap_decode nas_ies_tail sdk_coverage installed_consumer; do suite_in "$L" "$s"; done
for s in dicom_dissector citrix_ica_detection; do suite_out "$L" "$s"; done
for h in mobile_pcap_harness_test dicom_test; do harn_in "$L" "$h"; done
harn_out "$L" ssl_record_test
L="proto_ips_data.c (business_app family)"
expect_tier family "$L" src/mmt_business_app/proto_ips_data.c
for s in business_app s1ap_ngap_decode nas_ies_tail rule_engine installed_consumer; do suite_in "$L" "$s"; done
suite_out "$L" dicom_dissector
harn_in "$L" dicom_test
# A suite that delegates to tools/ci is selected through the delegate, not
# only through its tags: with mobile stripped from sdk_coverage, the mobile
# source its delegate (tools/ci/tests) asserts on still selects it.
sed '/^suite sdk_coverage /s/.*/suite sdk_coverage build,tcpip/' "${MAP}" > "${TMP}/sdkcov-no-mobile.txt"
L="proto_s1ap.c through the sdk_coverage delegate"
CLASSIFY_TEST_MAP="${TMP}/sdkcov-no-mobile.txt" run_case "$L" src/mmt_mobile/proto_s1ap.c
want_tier "$L" family
suite_in "$L" sdk_coverage
expect_tier family "two tcpip dissectors" src/mmt_tcpip/lib/protocols/proto_dns.c \
    src/mmt_tcpip/lib/protocols/proto_ssl.c

# AC2: shared code, build, workflows, runners, the selection, unmapped.
for p in src/mmt_core/src/packet_processing.c src/mmt_core/public_include/mmt_core.h \
         src/mmt_tcpip/include/mmt_tcpip.h src/mmt_tcpip/lib/protocols/dns.h \
         src/mmt_tcpip/lib/protocols/ip_l4_proto_table.inc src/mmt_tcpip/lib/proto_init_list.def \
         src/mmt_business_app/mmt_business_app_internal.h src/mmt_mobile/include/proto_s1ap.h \
         src/mmt_tcpip/lib/mmt_tcpip_utils.c src/mmt_tcpip/lib/protocols/proto_sctp.c \
         src/mmt_tcpip/lib/protocols/proto_tcp.c src/mmt_tcpip/lib/protocols/proto_ip.c \
         src/mmt_tcpip/lib/protocols/tcp_segment.c src/mmt_tcpip/lib/protocols/http.c \
         src/mmt_security/src/new_file.c src/examples/extract_all.c \
         rules/common.mk sdk/Makefile .github/workflows/c-cpp.yml \
         .github/actions/bootstrap-deps/action.yml tests/run_all_tests.sh \
         tools/phase0/run_all_harnesses.sh tools/phase0/ci/check_classification.sh \
         tools/phase0/phase0_classify.c tools/ci/classify-changes.sh tools/ci/test-map.txt \
         tools/ci/check-test-map.sh tools/ci/fuzz/regressions/new-crash.pcap \
         install.sh LICENSE Makefile data/port_map.example.txt dist/ZIP/install.sh; do
    expect_tier full "${p}" "${p}"
done
expect_tier full "an empty list" ""
expect_tier full "a dissector plus rules/" src/mmt_tcpip/lib/protocols/proto_dns.c rules/common.mk

# AC5: paths that are not plain printable ASCII, or not normalised.
expect_tier full "a git-quoted path" '"docs/caf\303\251.md"'
expect_tier full "a raw UTF-8 path" "docs/caf$(printf '\303\251').md"
expect_tier full "a path with a backslash" 'docs/a\b.md'
expect_tier full "a path with a tab" "docs/a$(printf '\t')b.md"
expect_tier full "a path with a carriage return" "README.md$(printf '\r')"
expect_tier full "a path with a .. component" docs/../src/mmt_core/src/packet_processing.c
expect_tier full "a quoted path among docs" docs/USER_GUIDE.md '"docs/caf\303\251.md"'

# Tests tier.
L="tests/hashmap/test_hashmap.c"
expect_tier tests "$L" "$L"
for s in ${SMOKE_SUITES} hashmap; do suite_in "$L" "$s"; done
suite_out "$L" citrix_ica_detection
for h in ${SMOKE_HARNESSES}; do harn_in "$L" "$h"; done
harn_out "$L" ssl_record_test
expect_tier tests "tests/citrix_ica_detection/test_citrix_ica.c" tests/citrix_ica_detection/test_citrix_ica.c
suite_in "a citrix suite file" citrix_ica_detection
for p in tests/resource_bounds/tcp_alloc_count.c tests/fault_injection/fi_alloc.c \
         tests/core_engine/api_contract.h tests/coverage/floor.json tests/test_common.h \
         tests/no_such_suite/test.c; do
    expect_tier full "${p} (shared or unmapped)" "${p}"
done
L="tools/phase0/tests/dns_parser_test.c"
expect_tier tests "$L" "$L"
harn_in "$L" dns_parser_test
for h in ${SMOKE_HARNESSES}; do harn_in "$L" "$h"; done
harn_out "$L" ssl_record_test
suite_out "$L" citrix_ica_detection
expect_tier tests "tools/phase0/tests/run_ssl_record_test.sh" tools/phase0/tests/run_ssl_record_test.sh
harn_in "run_ssl_record_test.sh" ssl_record_test
for p in tools/phase0/tests/internal_decls.h tools/phase0/tests/static_core_link.sh \
         tools/phase0/tests/mt_tsan_suppressions.txt tools/phase0/tests/run_no_such_test.sh \
         tools/phase0/tests/sub/x_test.c tools/phase0/tests/unnamed_by_any_run.c; do
    expect_tier full "${p} (shared or unmapped)" "${p}"
done

# Tooling tier.
L="an unreferenced tools/ci script"
expect_tier tooling "$L" tools/ci/zz-unreferenced-656.sh
if [ "${K[suites]:-}" = "fuzz_verdicts precision_metrics release_gates" ]; then
    ok "$L runs the three tooling delegate suites"
else bad "$L: suites='${K[suites]:-}'"; fi
expect_tier tooling ".github/CODEOWNERS" .github/CODEOWNERS
expect_tier tooling "a suite-referenced tools/ci test" tools/ci/tests/test-sdk-coverage.sh
suite_in "test-sdk-coverage.sh" sdk_coverage
run_case "tools/ci/tests/fixtures.txt" tools/ci/tests/fixtures.txt
if [ "${K[tier]:-}" = full ] || has x "${K[suites]:-}" installed_consumer; then
    ok "tools/ci/tests/fixtures.txt selects installed_consumer or is full (workflow-reachable)"
else bad "tools/ci/tests/fixtures.txt: tier=${K[tier]:-} suites='${K[suites]:-}'"; fi
expect_tier full "a workflow-referenced tools/ci script" tools/ci/check-hardening-flags.sh
expect_tier full "a tools/ci file a workflow reaches through another" tools/ci/marker-baseline.txt

# Mixed lists: the highest tier wins, the selections add up (A8: docs_lifecycle).
L="docs plus a tooling script"
expect_tier tooling "$L" docs/USER_GUIDE.md tools/ci/zz-unreferenced-656.sh
suite_in "$L" docs_lifecycle
L="docs plus a suite file"
expect_tier tests "$L" docs/USER_GUIDE.md tests/hashmap/test_hashmap.c
suite_in "$L" docs_lifecycle
L="docs plus a dissector"
expect_tier family "$L" README.md src/mmt_tcpip/lib/protocols/proto_dns.c
suite_in "$L" docs_lifecycle
L="a suite file plus a tooling script"
expect_tier tests "$L" tests/hashmap/test_hashmap.c tools/ci/zz-unreferenced-656.sh
for s in hashmap fuzz_verdicts release_gates; do suite_in "$L" "$s"; done
expect_tier docs "docs alone" docs/USER_GUIDE.md
suite_out "docs alone" docs_lifecycle

# The map itself: unreadable, malformed or incomplete is full.
CLASSIFY_TEST_MAP="${TMP}/no-such-map" run_case "a missing map" src/mmt_dicom/dicom.c
want_tier "a missing map" full
sed 's/^path docs\/\* docs$/path docs\/* sometimes/' "${MAP}" > "${TMP}/bad-token.txt"
CLASSIFY_TEST_MAP="${TMP}/bad-token.txt" run_case "a map with an unknown token" docs/USER_GUIDE.md
want_tier "a map with an unknown token" full
sed '/^suite hexdump /d' "${MAP}" > "${TMP}/no-hexdump.txt"
CLASSIFY_TEST_MAP="${TMP}/no-hexdump.txt" run_case "a map missing a suite" docs/USER_GUIDE.md
want_tier "a map missing a suite" full
sed '/^harness ndn_test /d' "${MAP}" > "${TMP}/no-ndn.txt"
CLASSIFY_TEST_MAP="${TMP}/no-ndn.txt" run_case "a map missing a harness" tests/hashmap/test_hashmap.c
want_tier "a map missing a harness" full

# A large family pull request classifies (cached reference lookups).
git -C "${REPO_ROOT}" ls-files 'src/mmt_tcpip/lib/protocols/proto_[a-f]*.c' \
    | grep -vE '/proto_(8021ad|8021q|arp|batman|etherip|ethernet)\.c$' > "${TMP}/many.txt"
mapfile -t many < "${TMP}/many.txt"
expect_tier family "${#many[@]} tcpip dissectors at once" "${many[@]}"

echo "=== test map (tools/ci/check-test-map.sh) ==="
if out="$(bash "${CHECKER}" 2>&1)"; then ok "the committed map passes: ${out}"
else bad "the committed map fails: ${out}"; fi
# expect_map_fail <label> <sed script> — a map copy the checker must reject.
expect_map_fail() {
    sed "$2" "${MAP}" > "${TMP}/map.txt"
    if bash "${CHECKER}" "${TMP}/map.txt" >/dev/null 2>&1; then
        bad "check-test-map accepts a map ${1}"
    else
        rc=$?
        if [ "${rc}" -eq 1 ]; then ok "check-test-map rejects a map ${1}"
        else bad "check-test-map: a map ${1}: exit ${rc}, want 1"; fi
    fi
}
expect_map_fail "missing a suite" '/^suite hexdump /d'
expect_map_fail "missing a harness" '/^harness ndn_test /d'
expect_map_fail "with a stale suite" "\$a suite gone_suite core"
expect_map_fail "with a stale harness" "\$a harness gone_test smoke"
expect_map_fail "with an unknown family tag" '/^suite hexdump /s/core/kernel/'
expect_map_fail "with an unknown path token" '/^path docs\/\* docs$/s/docs$/sometimes/'
expect_map_fail "with a malformed line" "\$a suite"
expect_map_fail "with a duplicate entry" "\$a suite hexdump core"
expect_map_fail "without tcpip on dicom_test (two-way tag)" '/^harness dicom_test /s/.*/harness dicom_test dicom/'
expect_map_fail "without tcpip on s1ap_ngap_decode (two-way tag)" '/^suite s1ap_ngap_decode /s/.*/suite s1ap_ngap_decode mobile/'
expect_map_fail "with s1ap_ngap_decode (mobile,tcpip) naming only a mobile source" '/^suite s1ap_ngap_decode /s/,smoke$//'
expect_map_fail "with dicom_test (dicom,tcpip) naming only a dicom source" '/^harness dicom_test /s/,smoke$//'
expect_map_fail "without business_app on installed_consumer (its delegate loads it)" '/^suite installed_consumer /s/,business_app//'
expect_map_fail "without mobile on sdk_coverage (its delegate loads it)" '/^suite sdk_coverage /s/,mobile//'
expect_map_fail "with a family-selective harness naming no source" '/^harness dns_parser_test /s/smoke/tcpip/'
expect_map_fail "with no smoke harness" '/^harness /s/smoke/tcpip/; /^harness /s/,smoke//; /^harness /s/tcpip,tcpip/tcpip/'
bash "${CHECKER}" a b c d >/dev/null 2>&1
if [ "$?" -eq 2 ]; then ok "check-test-map: too many arguments is exit 2"
else bad "check-test-map: too many arguments is not exit 2"; fi
bash "${CHECKER}" "${TMP}/no-such-map" >/dev/null 2>&1
if [ "$?" -eq 2 ]; then ok "check-test-map: a missing map is exit 2"
else bad "check-test-map: a missing map is not exit 2"; fi

echo "=== CI job wiring (c-cpp.yml, phase0-baseline.yml) ==="
if ! python3 -c 'import yaml' 2>/dev/null; then
    if [ "${REQUIRE_PYYAML:-0}" = "1" ]; then
        bad "PyYAML (python3-yaml) is missing and REQUIRE_PYYAML=1"
    else
        echo "  SKIP PyYAML (python3-yaml) not installed — install it to run the wiring checks"
    fi
else
    wiring="$(python3 - "$REPO_ROOT" <<'PY'
import os
import re
import subprocess
import sys

import yaml

root = sys.argv[1]
GATE = "needs.changes.outputs.code != 'false'"
GATES = "needs.changes.outputs.gates != 'false'"
FULL = "needs.changes.outputs.full != 'false'"
NOT_TESTS = "needs.changes.outputs.tier != 'tests'"
OUTPUTS = ["code", "tier", "full", "gates", "suites", "harnesses"]
SUITES_ENV = "${{ needs.changes.outputs.suites }}"
results = []


def check(label, cond):
    results.append(("PASS" if cond else "FAIL", label))


def load(name):
    with open(os.path.join(root, ".github", "workflows", name),
              encoding="utf-8") as fh:
        return yaml.safe_load(fh)["jobs"]


def needs(job):
    n = job.get("needs") or []
    return [n] if isinstance(n, str) else list(n)


def is_matrix(job):
    return (job.get("strategy") or {}).get("matrix") is not None


def cond(job):
    return str(job.get("if", ""))


def skips_at_job_level(job):
    return GATE in cond(job)


def steps_all_gated(job):
    steps = job.get("steps") or []
    return bool(steps) and all(GATE in str(s.get("if", "")) for s in steps)


WORKFLOWS = {
    "c-cpp.yml": {
        "single": ["unit-tests-arm", "unit-tests-unsigned-char",
                   "toolchain-floor", "toolchain-ceiling", "coverage", "lint",
                   "codeql", "root-install", "assertions-live",
                   "fuzz", "abi-diff"],
        "matrix": ["unit-tests", "sanitizer-tests", "resource-budgets"],
        "docs": ["build", "verify-helpers", "pre-commit", "doc-validators",
                 "version-agreement", "secret-scan"],
        "retired": ["enablesec", "asan-build"],
        "other": ["changes", "fuzz-alert"],
    },
    "phase0-baseline.yml": {
        "single": ["classification-gate", "leak-gate", "precision-gate",
                   "instruction-gate"],
        "matrix": [],
        "docs": [],
        "retired": [],
        "other": ["changes", "harness", "harness-gate"],
    },
}

# Issue #656: tier conditions, on top of the docs-only GATE.
TIER_SETS = {
    "c-cpp.yml": {
        "gates": ["unit-tests-arm", "unit-tests-unsigned-char",
                  "toolchain-floor", "toolchain-ceiling", "assertions-live",
                  "codeql", "fuzz"],
        "full": ["coverage", "root-install", "abi-diff"],
        "not_tests": ["codeql", "fuzz"],
        "suite_legs": ["unit-tests-arm", "unit-tests-unsigned-char",
                       "toolchain-floor", "toolchain-ceiling",
                       "assertions-live", "sanitizer-tests"],
    },
    "phase0-baseline.yml": {
        "gates": ["classification-gate", "leak-gate", "precision-gate",
                  "instruction-gate", "harness"],
        "full": [],
        "not_tests": [],
        "suite_legs": [],
    },
}

classify_steps = {}
for wf, sets in WORKFLOWS.items():
    jobs = load(wf)
    ch = jobs.get("changes") or {}
    run = " ".join(str(s.get("run", "")) for s in ch.get("steps") or [])
    check(f"{wf}: a `changes` job runs tools/ci/classify-changes.sh",
          "tools/ci/classify-changes.sh" in run
          and "code" in (ch.get("outputs") or {}))
    outs = ch.get("outputs") or {}
    check(f"{wf}: `changes` exports the six outputs of the classify step",
          sorted(outs) == sorted(OUTPUTS)
          and all(str(outs[k]).replace(" ", "")
                  == "${{steps.filter.outputs." + k + "}}" for k in OUTPUTS))
    fstep = [s for s in ch.get("steps") or [] if s.get("id") == "filter"]
    classify_steps[wf] = fstep[0] if fstep else {}
    frun = str(classify_steps[wf].get("run", ""))
    check(f"{wf}: a run that is not a pull request classifies /dev/null "
          "(full), the classifier's answer is written only when complete",
          "changed=/dev/null" in frun
          and '"$EVENT" = pull_request' in frun
          and 'classify-changes.sh < "$changed" > "$RUNNER_TEMP/classified.txt"' in frun
          and 'tee -a "$GITHUB_OUTPUT" < "$RUNNER_TEMP/classified.txt"' in frun
          and "| tee" not in frun)
    text = open(os.path.join(root, ".github", "workflows", wf),
                encoding="utf-8").read()
    read = set(re.findall(r"needs\.changes\.outputs\.(\w+)", text))
    check(f"{wf}: jobs read only the six `changes` outputs"
          + (f" (also: {', '.join(sorted(read - set(OUTPUTS)))})"
             if read - set(OUTPUTS) else ""), read <= set(OUTPUTS))
    eqs = re.findall(r"needs\.changes\.outputs\.(\w+)\s*==\s*'([^']*)'", text)
    check(f"{wf}: every `== ` test of an output is the docs-only "
          f"code == 'false' (fail-closed: no == 'true'; got {eqs})",
          all(e == ("code", "false") for e in eqs))
    ts = TIER_SETS[wf]
    for name in ts["gates"]:
        check(f"{wf}: {name} skips on the docs and tooling tiers (gates)",
              GATES in cond(jobs.get(name) or {}))
    for name in ts["full"]:
        check(f"{wf}: {name} runs on the full tier only",
              FULL in cond(jobs.get(name) or {}))
    for name in ts["not_tests"]:
        check(f"{wf}: {name} skips on the tests tier",
              NOT_TESTS in cond(jobs.get(name) or {}))
    for name in ts["suite_legs"]:
        steps = (jobs.get(name) or {}).get("steps") or []
        legs = [st for st in steps
                if "tests/run_all_tests.sh" in str(st.get("run", ""))]
        check(f"{wf}: {name} runs the tier's suite list",
              len(legs) == 1
              and str(legs[0]["run"]).strip().endswith(
                  "bash tests/run_all_tests.sh $SUITES")
              and (legs[0].get("env") or {}).get("SUITES") == SUITES_ENV)
    listed = [j for k in ("single", "matrix", "docs", "retired", "other")
              for j in sets[k]]
    if wf == "c-cpp.yml":
        unclassified = sorted(set(jobs) - set(listed))
        check(f"{wf}: every job is classified as a C or a docs job"
              + (f" (unclassified: {', '.join(unclassified)})"
                 if unclassified else ""), not unclassified)
    for name in listed:
        check(f"{wf}: job {name} exists", name in jobs)
    for name, job in jobs.items():
        if "changes" in needs(job) and job.get("if") is not None:
            c = cond(job)
            check(f"{wf}: {name} keeps !cancelled()/always() in its if: "
                  f"(fail-closed when `changes` fails)",
                  "!cancelled()" in c or "always()" in c)
    for name in sets["single"]:
        job = jobs.get(name) or {}
        check(f"{wf}: {name} needs changes and skips at job level on "
              f"code=false", "changes" in needs(job) and not is_matrix(job)
              and skips_at_job_level(job))
    for name in sets["matrix"]:
        job = jobs.get(name) or {}
        check(f"{wf}: matrix job {name} never skips at job level and skips "
              f"every step on code=false",
              "changes" in needs(job) and is_matrix(job)
              and not skips_at_job_level(job) and steps_all_gated(job))
        check(f"{wf}: matrix job {name} keeps exactly `${{{{ !cancelled() }}}}`",
              cond(job).strip() == "${{ !cancelled() }}")
    for name in sets["docs"]:
        job = jobs.get(name) or {}
        check(f"{wf}: docs job {name} never skips on code=false",
              not skips_at_job_level(job))
    # Issue #659: a retired context's job is a stub that skips on every
    # event (a skipped job reports success), so it never runs and never
    # waits on `changes`.
    for name in sets["retired"]:
        job = jobs.get(name) or {}
        check(f"{wf}: retired job {name} is an `if: false` stub with no needs",
              job.get("if") is False and not needs(job)
              and all("run_all_tests" not in str(st.get("run", ""))
                      and "make" not in str(st.get("run", ""))
                      for st in job.get("steps") or []))

check("the c-cpp.yml and phase0-baseline.yml classify steps are identical",
      bool(classify_steps.get("c-cpp.yml"))
      and classify_steps.get("c-cpp.yml") == classify_steps.get("phase0-baseline.yml"))

cc = load("c-cpp.yml")
ut = cc.get("unit-tests") or {}
ut_run = [st for st in ut.get("steps") or []
          if "tests/run_all_tests.sh" in str(st.get("run", ""))]
check("c-cpp.yml: unit-tests runs a leg's fixed list, else the tier's",
      len(ut_run) == 1
      and str(ut_run[0]["run"]).strip() == "bash tests/run_all_tests.sh $SUITES"
      and (ut_run[0].get("env") or {}).get("SUITES")
      == "${{ matrix.suites || needs.changes.outputs.suites }}")
san = cc.get("sanitizer-tests") or {}
check("c-cpp.yml: sanitizer-tests skips every step on the tooling tier",
      all(GATES in str(st.get("if", "")) for st in san.get("steps") or []))
RB = ("contains(format(' {0} ', needs.changes.outputs.suites), "
      "' resource_bounds ')")
rbj = cc.get("resource-budgets") or {}
check("c-cpp.yml: resource-budgets runs its steps on full or when "
      "resource_bounds is selected",
      all(FULL in str(st.get("if", "")) and RB in str(st.get("if", ""))
          for st in rbj.get("steps") or []))
with open(os.path.join(root, ".github", "required-checks.txt"),
          encoding="utf-8") as fh:
    required_ctx = {ln.strip() for ln in fh
                    if ln.strip() and not ln.lstrip().startswith("#")}
for wf in WORKFLOWS:
    for name, job in load(wf).items():
        label = str(job.get("name") or name)
        is_req = any(c == name or c.startswith(name + " (")
                     or label.startswith(c) for c in required_ctx)
        if is_req and "changes" in needs(job):
            check(f"{wf}: required job {name} still reports on every tier "
                  "(!cancelled()/always() in its if:)",
                  "!cancelled()" in cond(job) or "always()" in cond(job))
gate_run = " ".join(str(st.get("run", "")) for st in
                    (load("phase0-baseline.yml").get("harness-gate") or {})
                    .get("steps") or [])
check("phase0-baseline.yml: harness-gate accepts skipped legs on a docs or "
      "tooling change only", 'GATES' in gate_run
      and '[ "${GATES}" = "false" ]' in gate_run
      and '[ "${CHANGES}" = "success" ]' in gate_run)
hj = load("phase0-baseline.yml").get("harness") or {}
hrun = [st for st in hj.get("steps") or []
        if "run_all_harnesses.sh" in str(st.get("run", ""))]
check("phase0-baseline.yml: the harness legs pass --only the named "
      "harnesses when full=false, and every harness otherwise",
      len(hrun) == 1
      and (hrun[0].get("env") or {}).get("FULL") == "${{ needs.changes.outputs.full }}"
      and (hrun[0].get("env") or {}).get("HARNESSES")
      == "${{ needs.changes.outputs.harnesses }}"
      and 'if [ "$FULL" = false ]; then only=(--only "$HARNESSES"); fi'
      in str(hrun[0]["run"])
      and '"${only[@]}"' in str(hrun[0]["run"]))

dv = cc.get("doc-validators") or {}
check("c-cpp.yml: doc-validators runs docs_lifecycle on a docs-only change",
      any("docs_lifecycle" in str(s.get("run", ""))
          and "needs.changes.outputs.code == 'false'" in str(s.get("if", ""))
          for s in dv.get("steps") or []))

# Issue #528: unsigned plain char on native ARM, mirrored on x86.
arm = cc.get("unit-tests-arm") or {}
arm_runs = [str(s.get("run", "")).strip() for s in arm.get("steps") or []]
check("c-cpp.yml: unit-tests-arm runs the tier's suite set on ubuntu-24.04-arm",
      arm.get("runs-on") == "ubuntu-24.04-arm"
      and "bash tests/run_all_tests.sh $SUITES" in arm_runs)
uc = cc.get("unit-tests-unsigned-char") or {}
env = uc.get("env") or {}
uc_runs = [str(s.get("run", "")).strip() for s in uc.get("steps") or []]
check("c-cpp.yml: unit-tests-unsigned-char runs the tier's suite set with "
      "-funsigned-char on the suites and the SDK",
      "-funsigned-char" in str(env.get("EXTRA_CFLAGS", ""))
      and "-funsigned-char" in str(env.get("MMT_EXTRA_CFLAGS", ""))
      and "bash tests/run_all_tests.sh $SUITES" in uc_runs)
with open(os.path.join(root, ".github", "required-checks.txt"),
          encoding="utf-8") as fh:
    required = {ln.strip() for ln in fh
                if ln.strip() and not ln.lstrip().startswith("#")}
for ctx in ("unit-tests-arm", "unit-tests-unsigned-char"):
    check(f"required-checks.txt requires {ctx}", ctx in required)

# Issue #659: enablesec is retired. The ENABLESEC=1 compile is the shared
# enablesec SDK build tests/run_all_tests.sh makes for rule_engine and
# installed_consumer, and codeql traces an ENABLESEC=1 build.
with open(os.path.join(root, "tests", "run_all_tests.sh"),
          encoding="utf-8") as fh:
    runner = fh.read()
check("tests/run_all_tests.sh builds the ENABLESEC=1 group for rule_engine",
      "rule_engine|installed_consumer)" in runner
      and "make_args+=(ENABLESEC=1)" in runner)
cq = " ".join(str(st.get("run", ""))
              for st in (cc.get("codeql") or {}).get("steps") or [])
check("c-cpp.yml: codeql builds the SDK with ENABLESEC=1",
      "ENABLESEC=1" in cq)
check("phase0-baseline.yml: the retired asan-build job is gone",
      "asan-build" not in load("phase0-baseline.yml"))
with open(os.path.join(root, ".github", "retired-checks.txt"),
          encoding="utf-8") as fh:
    retired_ctx = {ln.strip() for ln in fh
                   if ln.strip() and not ln.lstrip().startswith("#")}
check("retired-checks.txt lists exactly the two stubs' contexts",
      retired_ctx == {"enablesec", "ASan/UBSan profile compiles"}
      and (cc.get("asan-build") or {}).get("name")
      == "ASan/UBSan profile compiles")

# Issue #659: the BUILD=asan profile check runs in the sanitizer asan leg.
asan_steps = [st for st in san.get("steps") or []
              if "__asan_init" in str(st.get("run", ""))]
check("c-cpp.yml: the sanitizer asan leg builds BUILD=asan and checks "
      "__asan_init before the suites",
      len(asan_steps) == 1
      and "matrix.sanitize == 'asan'" in str(asan_steps[0].get("if", ""))
      and GATES in str(asan_steps[0].get("if", ""))
      and "BUILD=asan" in str(asan_steps[0]["run"])
      and "make -C sdk clean" in str(asan_steps[0]["run"])
      and (san.get("steps") or []).index(asan_steps[0])
      < max(i for i, st in enumerate(san.get("steps") or [])
            if "run_all_tests.sh" in str(st.get("run", ""))))

# Issue #659: site-onboarding folded into verify-helpers, after the site build.
vh = [str(st.get("run", "")) for st in (cc.get("verify-helpers") or {}).get("steps") or []]
vh_env = [(st.get("env") or {}) for st in (cc.get("verify-helpers") or {}).get("steps") or []]
site = [i for i, r in enumerate(vh) if "build-docs-site.sh" in r]
onb = [i for i, r in enumerate(vh) if "tests/docs_onboarding/run_tests.sh" in r]
check("c-cpp.yml: verify-helpers runs docs_onboarding against the site it "
      "built (DOCS_SITE_DIR=docs/_site), as its last step",
      len(site) == 1 and len(onb) == 1 and site[0] < onb[0]
      and onb[0] == len(vh) - 1
      and vh_env[onb[0]].get("DOCS_SITE_DIR") == "docs/_site")

# Issue #659: resource-budgets keeps only the arm64 leg; resource_bounds
# (DEFAULT_SUITES) runs the fixtures and the checker on x86 in unit-tests.
check("c-cpp.yml: resource-budgets runs on ubuntu-24.04-arm only",
      ((rbj.get("strategy") or {}).get("matrix") or {}).get("runner")
      == ["ubuntu-24.04-arm"])
check("tests/run_all_tests.sh lists resource_bounds in DEFAULT_SUITES",
      re.search(r"DEFAULT_SUITES=\([^)]*\bresource_bounds\b", runner, re.S)
      is not None)

# Issue #658: the unsigned-char mirror and the -fsigned-char leg skip on
# pull requests (merge queue, push and schedule only); unit-tests-arm and
# the default unit-tests leg stay on every pull request.
OFF_PR = "github.event_name != 'pull_request'"
check("c-cpp.yml: unit-tests-unsigned-char skips on pull requests only",
      OFF_PR in cond(uc) and GATES in cond(uc) and "!cancelled()" in cond(uc))
check("c-cpp.yml: unit-tests-arm still runs on pull requests",
      "event_name" not in cond(arm))
LEG = "(matrix.extra_cflags == '' || " + OFF_PR + ")"
check("c-cpp.yml: every unit-tests step skips the -fsigned-char leg on "
      "pull requests, and only it",
      all(LEG in str(st.get("if", "")) for st in ut.get("steps") or [])
      and cond(ut).strip() == "${{ !cancelled() }}"
      and [leg.get("extra_cflags") for leg in
           ((ut.get("strategy") or {}).get("matrix") or {}).get("include") or []]
      == ["", "-fsigned-char"])
for name in ("sanitizer-tests", "unit-tests-arm", "toolchain-ceiling"):
    j = cc.get(name) or {}
    check(f"c-cpp.yml: {name} still runs on pull requests",
          OFF_PR not in cond(j)
          and all(OFF_PR not in str(st.get("if", ""))
                  for st in j.get("steps") or []))
# coverage gates itself: its context is required. The variant-build legs
# gate through `build`, a required context that needs them.
VARIANT_BUILDS = ["toolchain-floor", "assertions-live"]
for name in VARIANT_BUILDS + ["coverage"]:
    j = cc.get(name) or {}
    check(f"c-cpp.yml: {name} skips on pull requests only (merge queue, "
          f"push, schedule)",
          OFF_PR in cond(j) and "!cancelled()" in cond(j) and GATE in cond(j))
bj = cc.get("build") or {}
bsteps = bj.get("steps") or []
bgate = bsteps[0] if bsteps else {}
bgate_text = str(bgate.get("env", "")) + str(bgate.get("run", ""))
check("c-cpp.yml: build needs the variant-build legs and still runs when "
      "one fails (!cancelled(), never a tier condition)",
      sorted(needs(bj)) == sorted(VARIANT_BUILDS)
      and cond(bj).strip() == "${{ !cancelled() }}")
benv = bgate.get("env") or {}
check("c-cpp.yml: build's first step reads each variant-build leg's result",
      "uses" not in bgate and benv.get("EVENT") == "${{ github.event_name }}"
      and all(f"${{{{ needs.{n}.result }}}}" in benv.values()
              for n in VARIANT_BUILDS))
# Run the step itself, as the runner does (bash -e), over events and results:
# it passes only when every leg succeeded, or skipped on a pull request.
leg_vars = [k for k, v in benv.items()
            if any(f"needs.{n}.result" in str(v) for n in VARIANT_BUILDS)]
verdicts = []
for event in ("pull_request", "merge_group", "push", "schedule"):
    for bad_leg in [None] + leg_vars:
        for res in ("success", "skipped", "failure", "cancelled", ""):
            env = dict(os.environ, EVENT=event)
            for k in leg_vars:
                env[k] = res if (bad_leg is None or k == bad_leg) else "success"
            got = subprocess.run(
                ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c",
                 str(bgate.get("run", "exit 9"))], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
            want = 0 if res == "success" or (
                res == "skipped" and event == "pull_request") else 1
            verdicts.append((event, bad_leg, res, got, want))
wrong = [v for v in verdicts if v[3] != v[4]]
check(f"c-cpp.yml: build's gate step passes only on success, or a skip on "
      f"a pull request ({len(verdicts)} cases"
      + (f"; wrong: {wrong[:3]}" if wrong else "") + ")",
      len(leg_vars) == len(VARIANT_BUILDS) and not wrong)

for status, label in results:
    print(f"  {status} {label}")
PY
)"
    rc=$?
    printf '%s\n' "$wiring"
    if [ "$rc" -ne 0 ]; then
        bad "wiring check crashed (exit ${rc})"
    fi
    n_pass=$(printf '%s\n' "$wiring" | grep -c '^  PASS ' || true)
    n_fail=$(printf '%s\n' "$wiring" | grep -c '^  FAIL ' || true)
    pass=$((pass + n_pass))
    fail=$((fail + n_fail))
fi

echo
echo "classify-changes self-test: ${pass} passed, ${fail} failed"
if [ "$fail" -eq 0 ]; then
    echo "Result: PASS (classify-changes self-test)"
    exit 0
fi
echo "Result: FAIL (classify-changes self-test)"
exit 1
