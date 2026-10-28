#!/usr/bin/env bash
#
# run_tests.sh — rule-engine tests for issue #126 / F-TEST-003.
#
# The security-rule engine (src/mmt_security/tips*.c — split in #235) and
# the fuzz engine
# are only compiled when the SDK is built with ENABLESEC=1. This suite
# builds the SDK with ENABLESEC=1 into an isolated prefix, then loads a
# hand-crafted rule-set XML through the library's public entry point
# init_sec_lib() (tips.c) -> read_rules() -> processNode() (tips_xml.c)
# and asserts parse/construction outcomes:
#   1. a valid ruleset parses end-to-end and every attribute referenced by
#      its boolean_expression attributes gets registered for extraction;
#   2. a missing rule file and malformed XML hit the documented error paths
#      (Error 13/14 in read_rules);
#   3. the tips_extract.c overflow family (#137) stays fixed: a packet-forced divisor
#      of 0 on the u16/u32/u64 COMPUTE paths returns NULL instead of SIGFPE
#      (F-BUG-212) and a >99-byte header line is clamped inside
#      get_my_data()'s 100-byte buffer (F-BUG-208) — test_overflow_family.c,
#      which under SANITIZE=asan also fences the copy;
#   4. the tips_extract.c/tips_report.c rule-engine overflow family (#209)
#      stays fixed:
#      MMT_STRING_LONG_DATA/MMT_DATA_PATH clamping (F-BUG-091/093),
#      size*6+1 JSON escaping (F-BUG-092), header-line length ordering
#      (F-BUG-095), the single-cleanup-exit allocation failure in
#      store_history (F-BUG-096, via an interposed failing xmalloc),
#      growable command substitution without leaks (F-BUG-102) and the
#      bounded tokenize/xml_summary buffers (F-BUG-103);
#   5. the #326 fill-in/prune branches behave as documented: IPv6/float/
#      timeval/string-pointer/generic-header-line formatting, string-pointer
#      content comparison, fixed-width XIN membership for IP/MAC/timeval,
#      float COMPUTE incl. the zero-divisor guard, get_xdata() constants for
#      IPv4/IPv6/float/string-pointer, and the counter_min/max count window;
#   6. the fuzz engine's quality-estimation fixes (#210) hold: the grade
#      membership-function parameters live inside the allocation
#      (F-BUG-094), the XML parser refuses missing app_id / empty
#      documents instead of dereferencing NULL (F-BUG-100), and the
#      parameter array is bounded + initialised with every
#      children->content access NULL-checked (F-BUG-101) —
#      test_fuzz_engine.c;
#   7. the rule evaluator (tips_eval.c) is characterised (#509): synthetic
#      UDP frames are fed through packet_process() against the rule XMLs in
#      eval/ — THEN on the same packet, AFTER and BEFORE, delay and counter
#      windows, AND, OR, NOT, REPEAT, nested THEN, event references,
#      ||/arithmetic expressions — and the reported verdicts are pinned to
#      the current behaviour — test_rule_eval.c; since #510 also keep_state
#      and the verdict JSON, which jq must parse (step 8);
#   8. #511/#512: a malformed rule file (malformed/*.xml) or a missing or
#      over-long embedded-function call makes init_sec_lib() return an error
#      and free what it built (LSan), a second init_sec_lib() on one handler
#      is refused (one engine per handler, also under a two-thread race;
#      #551: two handlers run two engines independently), embedded
#      functions resolve at load from a test libembedded_functions.so, a
#      NOT_VALID instance no longer loops forever, and a reaction runs from
#      MMT_SEC_REACTION_DIR, printing U32/IP attributes from 4 bytes and
#      claiming detection_<n>.data with O_CREAT|O_EXCL|O_NOFOLLOW (step 8).
#
# Usage: tests/rule_engine/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_SRC="${SCRIPT_DIR}/test_rule_engine.c"
RULES_XML="${SCRIPT_DIR}/rules_minimal.xml"

if [ -z "${MMT_PREFIX:-}" ]; then
    PREFIX="$(mktemp -d)"
    PREFIX_CREATED=1
else
    PREFIX="${MMT_PREFIX}"
fi
WORK="$(mktemp -d)"
BUILD_LOG="${WORK}/build.log"
if [ -n "${PREFIX_CREATED:-}" ]; then
    trap 'rm -rf "${WORK}" "${PREFIX}"' EXIT
else
    trap 'rm -rf "${WORK}"' EXIT
fi

CC="${CC:-gcc}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

# Optional SDK build profile forwarded by tests/run_all_tests.sh when the
# suites run under SANITIZE=asan|tsan (mirrors BUILD= in rules/common.mk).
# Positional params are unused when the suite is invoked by run_all_tests.sh,
# so they carry the optional BUILD= argument for the two make calls below.
if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    set -- "BUILD=${SDK_BUILD_PROFILE}"
    # Under AddressSanitizer, mmt_init_handler() loads libmmt_tmobile.so as a
    # plugin while the test binary also links it statically, so the generated
    # asn1c globals (e.g. asn_DEF_ANY) are legitimately defined twice — the
    # same benign duplicate the mmt-probe application itself has. The SDK's
    # ASan build already runs with detect_leaks=0 (run_all_tests.sh); fold in
    # detect_odr_violation=0 for this suite rather than treating that shared
    # symbol as a bug introduced here.
    if [[ "${SDK_BUILD_PROFILE}" == *asan* ]]; then
        export ASAN_OPTIONS="${ASAN_OPTIONS:+${ASAN_OPTIONS}:}detect_odr_violation=0"
        # test_overflow_family is built uninstrumented on purpose: its
        # malloc/free/fopen shims forward through dlsym(RTLD_NEXT) into
        # libasan's allocator. With an uninstrumented exe libasan must be
        # preloaded so the runtime is first in the library list.
        SAN_RT="$(${CC} -print-file-name=libasan.so)"
    elif [[ "${SDK_BUILD_PROFILE}" == *tsan* ]]; then
        # Same for ThreadSanitizer (#412): without the preload libtsan only
        # arrives transitively (via libmmt_security/libmmt_core), after libc
        # and ld.so in the link map. The runtime then initialises from the
        # first instrumented .so constructor and InitTlsSize() calls
        # dlsym(RTLD_NEXT, "_dl_get_tls_static_info"), which returns NULL
        # because ld.so precedes libtsan — a jump to address 0 (SIGSEGV)
        # before main(). Observed on aarch64; preloading puts the runtime
        # first, as the instrumented test binaries already do.
        SAN_RT="$(${CC} -print-file-name=libtsan.so)"
    fi
else
    set --
fi

echo "  repo root      : ${REPO_ROOT}"
echo "  install prefix : ${PREFIX}"

# --- 1. build + install the SDK with the security engine --------------------
if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    # tests/run_all_tests.sh built and installed it once (issue #654).
    [ -e "${PREFIX}/dpi/lib/libmmt_security.so" ] || { echo "✗ MMT_SDK_PREBUILT=1 but MMT_PREFIX='${MMT_PREFIX:-}' holds no installed ENABLESEC=1 SDK" >&2; exit 1; }
    echo "  [1/8] reusing the prebuilt SDK (ENABLESEC=1, MMT_SDK_PREBUILT=1) ..."
else
    echo "  [1/8] building + installing SDK (ENABLESEC=1) ..."
    make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
    if ! make -C "${REPO_ROOT}/sdk" "$@" ENABLESEC=1 -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
        echo "✗ ENABLESEC SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
    fi
    if ! make -C "${REPO_ROOT}/sdk" "$@" ENABLESEC=1 MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
        echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
    fi
fi

INC="${PREFIX}/dpi/include"
LIB="${PREFIX}/dpi/lib"

# The plugin engine (packet_processing.c -> plugins_engine.c) dlopens
# libmmt_tcpip.so. Its search path is compile-time, not runtime-env:
# mmt_init_handler falls back from PLUGINS_REPOSITORY_OPT (baked in via
# -DPLUGINS_REPOSITORY_OPT="$(MMT_PLUGINS)") to the relative "plugins"
# (plugins_engine.h:21) and then "/opt/mmt/plugins". The build above already
# installed libmmt_tcpip.so into ${PREFIX}/plugins (sdk/Makefile install), so
# the test binary is run with CWD=${PREFIX} to satisfy the relative "plugins"
# fallback, on top of LD_LIBRARY_PATH for the shared libraries.

# Both optional engines must exist once ENABLESEC=1 is set: libmmt_security
# hosts the rule engine under test, libmmt_fuzz the fuzz engine (#126).
for libname in libmmt_security libmmt_fuzz; do
    if ! ls "${LIB}/${libname}".so* >/dev/null 2>&1; then
        echo "✗ ${libname} not produced by the ENABLESEC build (${LIB})" >&2
        exit 1
    fi
done

# --- 2. compile the test ----------------------------------------------------
echo "  [2/8] compiling test ..."
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
${CC} "${extra_cflags[@]}" -O2 -Wall -pthread \
    -I "${INC}" -I "${REPO_ROOT}/src/mmt_security" -o "${SCRIPT_DIR}/test_rule_engine" \
    "${TEST_SRC}" -L "${LIB}" \
    -lmmt_security -lmmt_core -lmmt_tcpip -lmmt_tmobile -lxml2 -lm

# The libembedded_functions.so the engine dlopens for #function(...) calls
# (#511): built uninstrumented — it only computes on the values it is
# handed — and found through LD_LIBRARY_PATH.
EMBEDDED_DIR="${WORK}/embedded"
mkdir -p "${EMBEDDED_DIR}"
${CC} -O2 -Wall -shared -fPIC -I "${INC}" -o "${EMBEDDED_DIR}/libembedded_functions.so" \
    "${SCRIPT_DIR}/embedded_functions.c"

# Fixtures exercising the parser error paths (schema derived from
# read_rules / create_boolean_expression in src/mmt_security/tips_xml.c).
MALFORMED_XML="${WORK}/rule_malformed.xml"
printf '<?xml version="1.0"?>\n<beginning>\n  <property property_id="1"\n' > "${MALFORMED_XML}"

# Run from ${PREFIX} so the plugin engine's relative "plugins" fallback
# (plugins_engine.h:21) resolves to ${PREFIX}/plugins where the SDK install
# dropped libmmt_tcpip.so. RUN_DIR is defined before the helpers.
RUN_DIR="${PREFIX}"

run_expect_ok() { # <label> <logfile> <cmd...>
    local label="$1" log="$2"; shift 2
    if ( cd "${RUN_DIR}" && "$@" ) >"${log}" 2>&1; then
        return 0
    fi
    echo "✗ ${label} failed — output:" >&2; tail -30 "${log}" >&2
    return 1
}

run_expect_fail() { # <label> <expected-error-substring> <logfile> <cmd...>
    local label="$1" err="$2" log="$3"; shift 3
    if ( cd "${RUN_DIR}" && "$@" ) >>"${log}" 2>&1; then
        echo "✗ ${label}: expected failure, but command succeeded" >&2
        cat "${log}" >&2
        return 1
    fi
    if grep -q "${err}" "${log}"; then
        return 0
    fi
    echo "✗ ${label}: failed as expected, but error '${err}' not reported — output:" >&2
    tail -30 "${log}" >&2
    return 1
}

LD_ENV=(env "LD_LIBRARY_PATH=${LIB}:${EMBEDDED_DIR}:${LD_LIBRARY_PATH:-}")
if [ -n "${SAN_RT:-}" ]; then
    LD_ENV+=("LD_PRELOAD=${SAN_RT}")
fi
BIN="${SCRIPT_DIR}/test_rule_engine"

# --- 2b. compile metacharacter injection test (F-BUG-207 / #136) --------------
echo "  [2b/8] compiling injection test ..."
INJECTION_SRC="${SCRIPT_DIR}/test_injection.c"
INJECTION_BIN="${SCRIPT_DIR}/test_injection"
${CC} "${extra_cflags[@]}" -O2 -Wall -o "${INJECTION_BIN}" "${INJECTION_SRC}"

# --- 2c. compile the overflow-family regression test (F-BUG-208/212, #137;
#         F-BUG-091/092/093/095/096/102/103, #209) -------------------------
# Drives compute()/get_my_data()/get_value()/store_history()/generate_command()
# from libmmt_security directly. The #209 checks interpose the C-allocation
# family (malloc/calloc/realloc/free/fopen) and get_attribute_extracted_data —
# those stay PLT-preemptible even though the shared build uses -flto — for
# fault injection and live-allocation tracking. The test is deliberately NOT
# compiled with ${extra_cflags}: under SANITIZE=asan the .so stays ASan-
# instrumented (overflows in library code are still caught) while the test's
# own shims keep forwarding through dlsym(RTLD_NEXT), which resolves to
# the preloaded sanitizer runtime's allocator (libasan/libtsan) — so the fault-injection checks work in every profile.
echo "  [2c/8] compiling overflow-family test ..."
OVERFLOW_SRC="${SCRIPT_DIR}/test_overflow_family.c"
OVERFLOW_BIN="${SCRIPT_DIR}/test_overflow_family"
${CC} -O2 -Wall \
    -I "${INC}" -I "${REPO_ROOT}/src/mmt_security" -o "${OVERFLOW_BIN}" \
    "${OVERFLOW_SRC}" -L "${LIB}" \
    -lmmt_security -lmmt_core -lmmt_tcpip -lmmt_tmobile -lxml2 -lm -ldl

# --- 3. run ------------------------------------------------------------------
echo "  [3/8] loading valid rule set through init_sec_lib() ..."
POSITIVE_LOG="${WORK}/positive.log"
run_expect_ok "valid ruleset load+assertions" "${POSITIVE_LOG}" \
    "${LD_ENV[@]}" "${BIN}" parse "${RULES_XML}"
grep '^ok - ' "${POSITIVE_LOG}" | sed 's/^/  /'
echo "  $(grep -c '^ok - ' "${POSITIVE_LOG}") assertions passed (valid ruleset)"

echo "  [4/8] parser error paths ..."
NEGATIVE_LOG="${WORK}/negative.log"
: > "${NEGATIVE_LOG}"
# Missing file -> init_sec_lib() fails to open it and raises Error 100
# (tips.c open_file), aborting before read_rules() is reached.
run_expect_fail "missing rule file" "Error 100" "${NEGATIVE_LOG}" \
    "${LD_ENV[@]}" "${BIN}" parse "${WORK}/does_not_exist.xml"
# Malformed XML -> libxml2 parse failure -> "Error 13 ... Parsing failed".
run_expect_fail "malformed rule XML" "Error 13" "${NEGATIVE_LOG}" \
    "${LD_ENV[@]}" "${BIN}" parse "${MALFORMED_XML}"
echo "  2 error paths verified"

# #511/#512: well-formed XML the engine cannot run is rejected by an error
# return — the loader used to exit() or dereference NULL — and the failed
# load frees what it built. LSan is the leak oracle (detect_leaks=1 is
# appended last, as for the fuzz engine in step 7; ignored outside ASan).
# Each fixture names the reason the engine reports.
# The suppression is the libmmt_tcpip constructor's protocol trees
# (_init_proto_avltrees): the test links libmmt_tcpip and the handler loads
# it again as a plugin, and nothing frees the trees the first copy built —
# unrelated to the rule engine.
LSAN_SUPP="${WORK}/lsan.supp"
printf 'leak:_init_proto_avltrees\n' > "${LSAN_SUPP}"
LSAN_ENV=("ASAN_OPTIONS=${ASAN_OPTIONS:+${ASAN_OPTIONS}:}detect_leaks=1" "LSAN_OPTIONS=suppressions=${LSAN_SUPP}")
declare -A LOAD_ERRORS=(
    [empty_delay_max]="Error 12b: Empty delay_max"
    [unknown_element]="Error 12a: Unknown element <rule>"
    [unbalanced_then]="Error 12d: THEN node with 1 branch"
    [outside_property]="Error 12c"
    [leading_operator]="Error 37b: Unbalanced boolean expression"
    [extra_paren]="Error 37b: Unbalanced boolean expression"
    [illegal_char]="Error 37: Illegal character"
    [unknown_attribute]="Error 9a: Unknown attribute NOPROTO.nofield"
    [funct_five_params]="Error 3e: Embedded function echo_port takes 5 parameters"
    [funct_missing]="Error 3h: Embedded function no_such_function not found"
    [funct_trailing_comma]="Error 3f: Empty parameter"
)
for fixture in "${SCRIPT_DIR}"/malformed/*.xml; do
    name="$(basename "${fixture}" .xml)"
    expected="${LOAD_ERRORS[${name}]:-}"
    if [ -z "${expected}" ]; then
        echo "✗ malformed/${name}.xml has no expected error in run_tests.sh" >&2; exit 1
    fi
    LOAD_LOG="${WORK}/load-${name}.log"
    run_expect_ok "load error: ${name}" "${LOAD_LOG}" \
        "${LD_ENV[@]}" "${LSAN_ENV[@]}" "${BIN}" load-error "${fixture}"
    if ! grep -qF "${expected}" "${LOAD_LOG}"; then
        echo "✗ load error: ${name}: '${expected}' not reported — output:" >&2
        cat "${LOAD_LOG}" >&2; exit 1
    fi
    echo "  ok - malformed/${name}.xml rejected: ${expected}"
done
echo "  ${#LOAD_ERRORS[@]} invalid rule files return a load error"

# One engine per process: a second init_sec_lib() is refused without a leak
# (LSan) and two racing threads get exactly one engine (TSan under
# SANITIZE=tsan).
REINIT_LOG="${WORK}/reinit.log"
run_expect_ok "second init_sec_lib()" "${REINIT_LOG}" \
    "${LD_ENV[@]}" "${LSAN_ENV[@]}" "${BIN}" reinit "${RULES_XML}"
grep -q "Error 105" "${REINIT_LOG}" || { echo "✗ reinit: Error 105 not reported" >&2; cat "${REINIT_LOG}" >&2; exit 1; }
grep '^ok - ' "${REINIT_LOG}" | sed 's/^/  /'
RACE_LOG="${WORK}/race.log"
run_expect_ok "concurrent init_sec_lib()" "${RACE_LOG}" \
    "${LD_ENV[@]}" "${BIN}" race "${RULES_XML}"
grep '^ok - ' "${RACE_LOG}" | tail -1 | sed 's/^/  /'

echo "  [5/8] metacharacter injection test (F-BUG-207 / #136) ..."
INJECTION_LOG="${WORK}/injection.log"
run_expect_ok "metacharacter injection (no shell interpretation)" "${INJECTION_LOG}" "${INJECTION_BIN}"
grep '^ok - ' "${INJECTION_LOG}" | sed 's/^/  /'
echo "  injection test passed (packet-derived metachars treated literally)"

echo "  [6/8] tips_extract.c overflow family (F-BUG-208 / F-BUG-212, #137; #326 fill-in branches) ..."
OVERFLOW_LOG="${WORK}/overflow.log"
OVERFLOW_JSON="${WORK}/packet_strings.json"
run_expect_ok "overflow-family + #326 regression" "${OVERFLOW_LOG}" \
    "${LD_ENV[@]}" "OVERFLOW_JSON_OUT=${OVERFLOW_JSON}" "${OVERFLOW_BIN}"
grep '^ok - ' "${OVERFLOW_LOG}" | sed 's/^/  /'
# #510 (F-BUG-209): the verdict document built from packet strings holding
# quotes and control bytes parses with jq and gives the bytes back.
if ! command -v jq >/dev/null 2>&1; then
    echo "✗ jq is required to validate the verdict JSON (apt-get install jq)" >&2; exit 1
fi
if ! jq -e --arg hl "$(printf 'Host: "evil"\\\n\001\t')" \
        '.event_4.attributes | map(to_entries[0].value) | index($hl) != null' \
        "${OVERFLOW_JSON}" >/dev/null; then
    echo "✗ packet-string verdict JSON is invalid or lost the header line — document:" >&2
    cat "${OVERFLOW_JSON}" >&2 2>/dev/null; exit 1
fi
echo "  ok - packet-string verdict JSON parses with jq and round-trips the header line"
echo "  $(grep -c '^ok - ' "${OVERFLOW_LOG}") assertions passed (overflow family + #326)"

# --- 7. fuzz-engine parser + parameter storage (F-BUG-094/100/101, #210)
# Drives application_quality_estimation_xml_parser() and the init_trapez_*
# entry points exported by libmmt_fuzz. Under SANITIZE=asan the binary and
# the library are both instrumented, so the pre-fix past-the-allocation
# writes and NULL children dereferences abort; unsanitised, the NULL-deref
# cases still crash.
echo "  [7/8] fuzz-engine quality-estimation fixes (F-BUG-094/100/101, #210) ..."
FUZZ_SRC="${SCRIPT_DIR}/test_fuzz_engine.c"
FUZZ_BIN="${SCRIPT_DIR}/test_fuzz_engine"
${CC} "${extra_cflags[@]}" -O2 -Wall \
    -I "${INC}" -o "${FUZZ_BIN}" \
    "${FUZZ_SRC}" -L "${LIB}" \
    -lmmt_fuzz -lmmt_security -lmmt_core -lmmt_tcpip -lmmt_tmobile -lxml2 -lm

# #466: LSan is the oracle for the parser's rules-set ownership.
# run_all_tests.sh exports ASAN_OPTIONS=detect_leaks=0 for SANITIZE=asan
# (project policy: leak detection via Valgrind) -- this binary opts back
# in, as tests/s1ap_ngap_decode does. Appended last so it wins over any
# earlier detect_leaks= setting; ignored outside ASan.
FUZZ_LOG="${WORK}/fuzz.log"
run_expect_ok "fuzz-engine regression (trailing-storage params, XML NULL guards)" "${FUZZ_LOG}" \
    "${LD_ENV[@]}" "ASAN_OPTIONS=${ASAN_OPTIONS:+${ASAN_OPTIONS}:}detect_leaks=1" "${FUZZ_BIN}"
grep '^ok - ' "${FUZZ_LOG}" | sed 's/^/  /'
# #466/#468: the parser reports the rules sets and quality metrics it drops
# instead of leaking them.
for msg in "Several <rules> nodes" "<rules> without a quality metric" \
        "Cannot register the <indexs> quality metric"; do
    if ! grep -qF "${msg}" "${FUZZ_LOG}"; then
        echo "✗ fuzz-engine: parser did not report '${msg}'" >&2; exit 1
    fi
done
echo "  $(grep -c '^ok - ' "${FUZZ_LOG}") assertions passed (fuzz engine)"

# --- 8. rule evaluator characterisation (tips_eval.c, F-TEST-004, #509)
# Each scenario loads one eval/*.xml rule in a forked child (the engine
# keeps its rule list in process globals) and replays a scripted packet
# sequence; the expectations pin the CURRENT verdicts, quirks included.
echo "  [8/8] rule evaluator characterisation (F-TEST-004, #509) ..."
EVAL_SRC="${SCRIPT_DIR}/test_rule_eval.c"
EVAL_BIN="${SCRIPT_DIR}/test_rule_eval"
${CC} "${extra_cflags[@]}" -O2 -Wall -pthread \
    -I "${INC}" -I "${REPO_ROOT}/src/mmt_security" -o "${EVAL_BIN}" \
    "${EVAL_SRC}" -L "${LIB}" \
    -lmmt_security -lmmt_core -lmmt_tcpip -lmmt_tmobile -lxml2 -lm
EVAL_LOG="${WORK}/eval.log"
HIST_LOG="${WORK}/histories.jsonl"
: > "${HIST_LOG}"
# reaction.xml's record(...) script runs from this folder (#512). A planted
# detection_1.data symlink must be neither followed nor truncated: the
# engine skips to detection_2.data.
REACTION_DIR="${WORK}/reactions"
mkdir -p "${REACTION_DIR}"
# shellcheck disable=SC2016 # the script's own "$@"/$0, expanded when it runs
printf '#!/bin/sh\nprintf "%%s\\n" "$@" > "$(dirname "$0")/record.out"\n' > "${REACTION_DIR}/record"
chmod +x "${REACTION_DIR}/record"
: > "${WORK}/victim"
ln -s "${WORK}/victim" "${REACTION_DIR}/detection_1.data"
# The evaluator is instrumented like the SDK, so it needs no sanitizer
# preload — and the reaction's /bin/sh must not inherit it: a shell with
# libtsan preloaded dies with SIGSEGV before running the script (aarch64).
EVAL_ENV=("${LD_ENV[@]}")
if [ -n "${SAN_RT:-}" ]; then
    EVAL_ENV+=("LD_PRELOAD=")
fi
run_expect_ok "rule evaluator characterisation" "${EVAL_LOG}" \
    "${EVAL_ENV[@]}" "RULE_EVAL_HISTORY_LOG=${HIST_LOG}" "MMT_SEC_REACTION_DIR=${REACTION_DIR}" \
    "${EVAL_BIN}" "${SCRIPT_DIR}/eval"
grep '^ok - ' "${EVAL_LOG}" | sed 's/^/  /'
echo "  $(grep -c '^ok - ' "${EVAL_LOG}") scenarios passed (rule evaluator)"

# #551 (F-BUG-215): two handlers of one process run two engines with
# different rule files — fed in turn from one thread, then concurrently from
# two (the TSan run covers the per-handler state) — and each reports only
# its own rule's verdicts.
TWO_LOG="${WORK}/two_engines.log"
run_expect_ok "two engines in one process" "${TWO_LOG}" \
    "${EVAL_ENV[@]}" "${EVAL_BIN}" two-engines "${SCRIPT_DIR}/eval"
grep '^ok - ' "${TWO_LOG}" | sed 's/^/  /'
# #551: close_sec_lib() frees an engine with live instances (LSan) and the
# handler reloads; a handler closed without it never blocks a later one; an
# application's own packet handler 1 is refused and left registered.
LIFE_LOG="${WORK}/engine_lifecycle.log"
run_expect_ok "engine lifecycle" "${LIFE_LOG}" \
    "${EVAL_ENV[@]}" "${LSAN_ENV[@]}" "${EVAL_BIN}" engine-lifecycle "${SCRIPT_DIR}/eval"
grep '^ok - ' "${LIFE_LOG}" | sed 's/^/  /'

# #510 (F-BUG-209): every history the callback reported is a JSON document
# jq parses, and json_escape.xml's quote/backslash/control-character
# descriptions come back unchanged.
if ! command -v jq >/dev/null 2>&1; then
    echo "✗ jq is required to validate the verdict JSON (apt-get install jq)" >&2; exit 1
fi
if ! jq -e -s 'length > 0' "${HIST_LOG}" >/dev/null; then
    echo "✗ verdict histories are not valid JSON — log:" >&2; cat "${HIST_LOG}" >&2; exit 1
fi
DESC1="$(printf 'A "quoted"\ttab\\back')"
DESC2="$(printf 'line\nbreak\rctl')"
if ! jq -e -s --arg d1 "${DESC1}" --arg d2 "${DESC2}" \
        'map(select(.event_1.description == $d1 and .event_2.description == $d2)) | length == 1' \
        "${HIST_LOG}" >/dev/null; then
    echo "✗ json_escape.xml descriptions did not round-trip through the verdict JSON" >&2
    cat "${HIST_LOG}" >&2; exit 1
fi
# keep_state.xml's second verdict (B at +1.7 s): copy_instance() kept A's
# event_1 member and the new B added event_2 — each exactly once.
KEPT_LINE="$(grep -F '"timestamp":1700000001.700000' "${HIST_LOG}" || true)"
if [ "$(printf '%s\n' "${KEPT_LINE}" | grep -c .)" -ne 1 ] ||
   [ "$(printf '%s' "${KEPT_LINE}" | grep -o '"event_1"' | wc -l)" -ne 1 ] ||
   [ "$(printf '%s' "${KEPT_LINE}" | grep -o '"event_2"' | wc -l)" -ne 1 ] ||
   ! printf '%s' "${KEPT_LINE}" | jq -e '(keys == ["event_1", "event_2"]) and
        .event_1.description == "A" and .event_1.timestamp == 1700000000 and
        .event_2.description == "B"' >/dev/null; then
    echo "✗ keep_state: the kept history is not A's event_1 plus the new event_2 — got:" >&2
    printf '%s\n' "${KEPT_LINE}" >&2; exit 1
fi
echo "  $(jq -s length "${HIST_LOG}") verdict histories parsed by jq (escaped descriptions round-trip, keep_state history kept)"

# #511/#512: the reaction ran from MMT_SEC_REACTION_DIR with its detection
# number, the 4-byte META.packet_len and both IP addresses printed right.
if [ "$(cat "${REACTION_DIR}/record.out" 2>/dev/null)" != "$(printf '2\n120\n10.0.0.1\n10.0.0.2')" ]; then
    echo "✗ reaction: record(...) arguments are not '2 120 10.0.0.1 10.0.0.2' — got:" >&2
    cat "${REACTION_DIR}/record.out" >&2 2>/dev/null; exit 1
fi
DATA_FILE="${REACTION_DIR}/detection_2.data"
if [ -L "${DATA_FILE}" ] || [ "$(stat -c %a "${DATA_FILE}" 2>/dev/null)" != "600" ] ||
   [ "$(sed -n 2p "${DATA_FILE}")" != "reaction" ] || [ "$(tail -1 "${DATA_FILE}")" != "detected" ]; then
    echo "✗ reaction: ${DATA_FILE} is not a 0600 detection file" >&2
    ls -l "${REACTION_DIR}" >&2; exit 1
fi
if [ -s "${WORK}/victim" ] || [ ! -L "${REACTION_DIR}/detection_1.data" ]; then
    echo "✗ reaction: the planted detection_1.data symlink was followed or replaced" >&2; exit 1
fi
echo "  ok - reaction ran from MMT_SEC_REACTION_DIR: U32/IP arguments printed right, detection_2.data created 0600, planted symlink skipped"

echo
echo "✓ Rule-engine tests passed"

