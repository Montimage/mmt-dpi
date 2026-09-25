#!/usr/bin/env bash
#
# run_tests.sh — regression tests for issue #132: S1AP/NGAP decode-result
# checking (F-BUG-201/210/213/218/219/220/221).
#
# Builds+installs the SDK to an isolated prefix, then compiles the test
# directly against the repo-tree headers of s1ap_common.h / ngap.h and links
# it with libmmt_tmobile so the ASN.1 decoders under test are exercised in
# their shipped configuration.
#
# Usage: tests/s1ap_ngap_decode/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_SRC="${SCRIPT_DIR}/test_s1ap_ngap_decode.c"

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
else
    set --
fi

echo "  repo root      : ${REPO_ROOT}"
echo "  install prefix : ${PREFIX}"

# --- 1. build + install the SDK to the isolated prefix ---------------------
echo "  [1/3] building + installing SDK ..."
make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
if ! make -C "${REPO_ROOT}/sdk" "$@" -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
if ! make -C "${REPO_ROOT}/sdk" "$@" MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi

INC="${PREFIX}/dpi/include"
LIB="${PREFIX}/dpi/lib"

# s1ap_common.h / ngap.h are internal headers (not installed), so the test
# compiles against the repo tree; the generated asn1c trees are never edited.
SRC_INC=(
    -I "${REPO_ROOT}/src/mmt_mobile/s1ap"
    -I "${REPO_ROOT}/src/mmt_mobile/ngap"
    -I "${REPO_ROOT}/src/mmt_mobile/asn1c/common"
    -I "${REPO_ROOT}/src/mmt_mobile/asn1c/s1ap"
    -I "${REPO_ROOT}/src/mmt_mobile/asn1c/ngap"
)

# --- 2. compile the tests ---------------------------------------------------
# EXTRA_CFLAGS carries sanitizer/coverage instrumentation requested by
# tests/run_all_tests.sh; the binaries stay in the suite dir so gcov data
# (.gcno/.gcda) survives for the coverage report.
echo "  [2/3] compiling tests ..."
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
# The decode test calls the asn1c runtime (aper_decode, asn_DEF_*) directly.
# Issue #443 keeps those symbols out of libmmt_tmobile.so's dynamic symbol
# table, so the test links the installed static archive, where the hidden
# asn1c objects stay linkable. --whole-archive, as for the .so itself: the
# release archive holds slim LTO objects that plain `ar` indexes no symbol of.
${CC} "${extra_cflags[@]}" -O2 -Wall -o "${SCRIPT_DIR}/test_s1ap_ngap_decode" \
    "${TEST_SRC}" "${SRC_INC[@]}" -I "${INC}" \
    -Wl,--whole-archive "${LIB}/libmmt_tmobile.a" -Wl,--no-whole-archive \
    -L "${LIB}" -lmmt_core -lm

# The packet-level test drives packet_process() with the real plugins, so it
# links libmmt_core only — the mobile plugin is loaded via dlopen from the
# installed prefix. Linking libmmt_tmobile here too would duplicate its
# globals (once direct, once via dlopen).
${CC} "${extra_cflags[@]}" -O2 -Wall -o "${SCRIPT_DIR}/test_s1ap_ngap_packets" \
    "${SCRIPT_DIR}/test_s1ap_ngap_packets.c" \
    -I "${INC}" -L "${LIB}" -lmmt_core -ldl -lpthread -lm

# --- 3. run -----------------------------------------------------------------
echo "  [3/3] running tests ..."

# Issue #443: no asn1c runtime symbol is exported from the shipped mobile
# library (a host linking its own asn1c runtime must not interpose them, nor
# see the load-time asn_OP_ANY patch), while the plugin entry points and the
# handwritten decoders still are. The asn1c symbol set is read from the
# in-tree objects the build just produced.
MOBILE_SO="${LIB}/libmmt_tmobile.so"
ASN1C_SYMS="${WORK}/asn1c.syms"
EXPORTED_SYMS="${WORK}/exported.syms"
# gcc-nm reads the slim LTO objects of the release profile (plain nm cannot).
NM_OBJ="$(command -v gcc-nm || command -v nm)"
find "${REPO_ROOT}/src/mmt_mobile/asn1c" -name '*.o' -exec "${NM_OBJ}" -g --defined-only {} + 2>/dev/null \
    | awk 'NF == 3 { print $3 }' | sort -u > "${ASN1C_SYMS}"
nm -D --defined-only "${MOBILE_SO}" | awk 'NF == 3 { print $3 }' | sort -u > "${EXPORTED_SYMS}"
if ! grep -qx 'asn_OP_ANY' "${ASN1C_SYMS}"; then
    echo "✗ asn1c symbol list looks wrong (no asn_OP_ANY in the asn1c objects)" >&2; exit 1
fi
leaked="$(comm -12 "${ASN1C_SYMS}" "${EXPORTED_SYMS}")"
if [ -n "${leaked}" ]; then
    echo "✗ libmmt_tmobile.so exports $(wc -l <<<"${leaked}") asn1c symbol(s), e.g.:" >&2
    head -5 <<<"${leaked}" >&2
    exit 1
fi
for sym in init_proto cleanup_proto s1ap_decode; do
    if ! grep -qx "${sym}" "${EXPORTED_SYMS}"; then
        echo "✗ libmmt_tmobile.so no longer exports ${sym}" >&2; exit 1
    fi
done
echo "  ok   no asn1c runtime symbol exported from libmmt_tmobile.so ($(wc -l < "${ASN1C_SYMS}") hidden)"
# The malformed-S1AP loop is the F-BUG-078 regression; LSAN is its oracle.
# run_all_tests.sh exports ASAN_OPTIONS=detect_leaks=0 for SANITIZE=asan
# (project policy: leak detection via Valgrind) — this suite deliberately
# opts back in: issue #207's acceptance criterion is a zero-leak report.
# Appended last so it wins over any earlier detect_leaks= setting.
ASAN_OPTIONS="${ASAN_OPTIONS:+${ASAN_OPTIONS}:}detect_leaks=1" \
LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}" \
    "${SCRIPT_DIR}/test_s1ap_ngap_decode"

# Run the packet-level test from WORK: it has no plugins/ directory, so
# load_plugins() falls back to PLUGINS_REPOSITORY_OPT = ${PREFIX}/plugins —
# the just-installed, profile-matched plugins. A CWD-visible plugins/ (e.g.
# the repo-root symlink to sdk/lib) would shadow them with the wrong build.
(cd "${WORK}" && \
LD_LIBRARY_PATH="${LIB}:${LD_LIBRARY_PATH:-}" \
    "${SCRIPT_DIR}/test_s1ap_ngap_packets")

echo
echo "✓ S1AP/NGAP decode regression tests passed"
