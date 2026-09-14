#!/usr/bin/env bash
#
# run_tests.sh — rule-engine tests for issue #126 / F-TEST-003.
#
# The security-rule engine (src/mmt_security/tips.c) and the fuzz engine
# are only compiled when the SDK is built with ENABLESEC=1. This suite
# builds the SDK with ENABLESEC=1 into an isolated prefix, then loads a
# hand-crafted rule-set XML through the library's public entry point
# init_sec_lib() -> read_rules() -> processNode() (src/mmt_security/tips.c)
# and asserts parse/construction outcomes:
#   1. a valid ruleset parses end-to-end and every attribute referenced by
#      its boolean_expression attributes gets registered for extraction;
#   2. a missing rule file and malformed XML hit the documented error paths
#      (Error 13/14 in read_rules);
#   3. the tips.c overflow family (#137) stays fixed: a packet-forced divisor
#      of 0 on the u16/u32/u64 COMPUTE paths returns NULL instead of SIGFPE
#      (F-BUG-212) and a >99-byte header line is clamped inside
#      get_my_data()'s 100-byte buffer (F-BUG-208) — test_overflow_family.c,
#      which under SANITIZE=asan also fences the copy;
#   4. the fuzz engine's quality-estimation fixes (#210) hold: the grade
#      membership-function parameters live inside the allocation
#      (F-BUG-094), the XML parser refuses missing app_id / empty
#      documents instead of dereferencing NULL (F-BUG-100), and the
#      parameter array is bounded + initialised with every
#      children->content access NULL-checked (F-BUG-101) —
#      test_fuzz_engine.c.
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
    fi
else
    set --
fi

echo "  repo root      : ${REPO_ROOT}"
echo "  install prefix : ${PREFIX}"

# --- 1. build + install the SDK with the security engine --------------------
echo "  [1/7] building + installing SDK (ENABLESEC=1) ..."
make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
if ! make -C "${REPO_ROOT}/sdk" "$@" ENABLESEC=1 -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
    echo "✗ ENABLESEC SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
if ! make -C "${REPO_ROOT}/sdk" "$@" ENABLESEC=1 MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
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
echo "  [2/7] compiling test ..."
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
${CC} "${extra_cflags[@]}" -O2 -Wall \
    -I "${INC}" -o "${SCRIPT_DIR}/test_rule_engine" \
    "${TEST_SRC}" -L "${LIB}" \
    -lmmt_security -lmmt_core -lmmt_tcpip -lmmt_tmobile -lxml2 -lm

# Fixtures exercising the parser error paths (schema derived from
# read_rules / create_boolean_expression in src/mmt_security/tips.c).
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

LD_ENV=(env "LD_LIBRARY_PATH=${LIB}:${LD_LIBRARY_PATH:-}")
BIN="${SCRIPT_DIR}/test_rule_engine"

# --- 2b. compile metacharacter injection test (F-BUG-207 / #136) --------------
echo "  [2b/7] compiling injection test ..."
INJECTION_SRC="${SCRIPT_DIR}/test_injection.c"
INJECTION_BIN="${SCRIPT_DIR}/test_injection"
${CC} "${extra_cflags[@]}" -O2 -Wall -o "${INJECTION_BIN}" "${INJECTION_SRC}"

# --- 2c. compile the overflow-family regression test (F-BUG-208/212, #137) --
# Drives compute() and get_my_data() (exported by libmmt_security) directly.
echo "  [2c/7] compiling overflow-family test ..."
OVERFLOW_SRC="${SCRIPT_DIR}/test_overflow_family.c"
OVERFLOW_BIN="${SCRIPT_DIR}/test_overflow_family"
${CC} "${extra_cflags[@]}" -O2 -Wall \
    -I "${INC}" -o "${OVERFLOW_BIN}" \
    "${OVERFLOW_SRC}" -L "${LIB}" \
    -lmmt_security -lmmt_core -lmmt_tcpip -lmmt_tmobile -lxml2 -lm

# --- 3. run ------------------------------------------------------------------
echo "  [3/7] loading valid rule set through init_sec_lib() ..."
POSITIVE_LOG="${WORK}/positive.log"
run_expect_ok "valid ruleset load+assertions" "${POSITIVE_LOG}" \
    "${LD_ENV[@]}" "${BIN}" parse "${RULES_XML}"
grep '^ok - ' "${POSITIVE_LOG}" | sed 's/^/  /'
echo "  $(grep -c '^ok - ' "${POSITIVE_LOG}") assertions passed (valid ruleset)"

echo "  [4/7] parser error paths ..."
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

echo "  [5/7] metacharacter injection test (F-BUG-207 / #136) ..."
INJECTION_LOG="${WORK}/injection.log"
run_expect_ok "metacharacter injection (no shell interpretation)" "${INJECTION_LOG}" "${INJECTION_BIN}"
grep '^ok - ' "${INJECTION_LOG}" | sed 's/^/  /'
echo "  injection test passed (packet-derived metachars treated literally)"

echo "  [6/7] tips.c overflow family (F-BUG-208 / F-BUG-212, #137) ..."
OVERFLOW_LOG="${WORK}/overflow.log"
run_expect_ok "overflow-family regression (zero divisor, >99-byte header line)" "${OVERFLOW_LOG}" \
    "${LD_ENV[@]}" "${OVERFLOW_BIN}"
grep '^ok - ' "${OVERFLOW_LOG}" | sed 's/^/  /'
echo "  $(grep -c '^ok - ' "${OVERFLOW_LOG}") assertions passed (overflow family)"

# --- 7. fuzz-engine parser + parameter storage (F-BUG-094/100/101, #210)
# Drives application_quality_estimation_xml_parser() and the init_trapez_*
# entry points exported by libmmt_fuzz. Under SANITIZE=asan the binary and
# the library are both instrumented, so the pre-fix past-the-allocation
# writes and NULL children dereferences abort; unsanitised, the NULL-deref
# cases still crash.
echo "  [7/7] fuzz-engine quality-estimation fixes (F-BUG-094/100/101, #210) ..."
FUZZ_SRC="${SCRIPT_DIR}/test_fuzz_engine.c"
FUZZ_BIN="${SCRIPT_DIR}/test_fuzz_engine"
${CC} "${extra_cflags[@]}" -O2 -Wall \
    -I "${INC}" -o "${FUZZ_BIN}" \
    "${FUZZ_SRC}" -L "${LIB}" \
    -lmmt_fuzz -lmmt_security -lmmt_core -lmmt_tcpip -lmmt_tmobile -lxml2 -lm

FUZZ_LOG="${WORK}/fuzz.log"
run_expect_ok "fuzz-engine regression (trailing-storage params, XML NULL guards)" "${FUZZ_LOG}" \
    "${LD_ENV[@]}" "${FUZZ_BIN}"
grep '^ok - ' "${FUZZ_LOG}" | sed 's/^/  /'
echo "  $(grep -c '^ok - ' "${FUZZ_LOG}") assertions passed (fuzz engine)"

echo
echo "✓ Rule-engine tests passed"

