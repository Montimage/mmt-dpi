#!/usr/bin/env bash
#
# run_tests.sh — installed-consumer regression suite (issue #374, F-CI-002).
#
# Exercises tools/ci/tests/run-installed-consumer.sh + installed_consumer.c
# the same way release-packages.yml does inside each package test container,
# but against a throwaway install prefix instead of a real .deb/.rpm:
#
#   1. build + install the SDK with ENABLESEC=1 (the package configuration)
#      into a private MMT_BASE prefix;
#   2. the script compiles the consumer against only the installed
#      headers/libraries, then every vendored fixture must classify to its
#      known label through the installed plugins;
#      the installed headers leave ntohl/ntohs to <arpa/inet.h> and a
#      consumer gets single-evaluation, host-correct byte order (#504);
#   3. failure legs: a missing required plugin, an absent ENABLESEC engine,
#      a wrong expected label and an unregistered required protocol must all
#      make the script fail (acceptance criterion 2);
#   4. the provenance line records the package filename, SHA-256, distro and
#      architecture it was given.
#
# Usage: tests/installed_consumer/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DRIVER="${REPO_ROOT}/tools/ci/tests/run-installed-consumer.sh"

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

JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

PASS=0
FAIL=0
ok()   { echo "  ✓ $1"; PASS=$((PASS + 1)); }
bad()  { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }

check() {
    local desc="$1"; shift
    if "$@" >"${WORK}/out.log" 2>&1; then ok "$desc"; else bad "$desc"; head -10 "${WORK}/out.log" | sed 's/^/      /'; fi
}

check_fail() {
    local desc="$1"; shift
    if "$@" >"${WORK}/out.log" 2>&1; then bad "$desc (unexpected success)"; head -10 "${WORK}/out.log" | sed 's/^/      /'; else ok "$desc"; fi
}

# Optional SDK build profile forwarded by tests/run_all_tests.sh under
# SANITIZE=asan|tsan (mirrors BUILD= in rules/common.mk).
SDK_MAKE_ARGS=()
if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    SDK_MAKE_ARGS=("BUILD=${SDK_BUILD_PROFILE}")
fi

echo "=== installed-consumer suite (issue #374) ==="
echo "  install prefix : ${PREFIX}"

# --- 1. build + install the packaged configuration ----------------------------
echo "  [1/4] building + installing SDK (ENABLESEC=1) ..."
make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
if ! make -C "${REPO_ROOT}/sdk" "${SDK_MAKE_ARGS[@]}" ENABLESEC=1 -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
    echo "✗ ENABLESEC SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
if ! make -C "${REPO_ROOT}/sdk" "${SDK_MAKE_ARGS[@]}" ENABLESEC=1 MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi

# --- 2. happy path --------------------------------------------------------------
echo "  [2/4] installed consumer over the installed prefix"
check "installed consumer passes on the installed prefix" \
    bash "${DRIVER}" --prefix "${PREFIX}" --distro suite-local

# Byte order (issue #504, F-BUG-009): the installed public headers must not
# override ntohl/ntohs, and a consumer including mmt_core.h then
# <arpa/inet.h> must get single-evaluation, host-correct byte-order macros —
# at -O0 (glibc's out-of-line ntohl) and -O2 (its inline bswap).
check_fail "installed headers carry no ntohl/ntohs override" \
    grep -rn 'undef ntoh' "${PREFIX}/dpi/include"
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
byte_order_consumer() {
    local opt="$1" bin="${WORK}/byte_order$1"
    "${CC:-gcc}" "${extra_cflags[@]}" "${opt}" -Wall -Wextra -o "${bin}" \
        "${SCRIPT_DIR}/test_byte_order.c" \
        -I "${PREFIX}/dpi/include" -L "${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap \
        && LD_LIBRARY_PATH="${PREFIX}/dpi/lib" "${bin}"
}
for opt in -O0 -O2; do
    check "byte-order consumer compiles and passes (${opt})" byte_order_consumer "${opt}"
done

# Provenance: a real file is hashed and every log line is tagged.
: > "${WORK}/mmt-dpi_test.deb"
WANT_SHA="$(sha256sum "${WORK}/mmt-dpi_test.deb" | awk '{print substr($1,1,12)}')"
check "package filename/SHA/distro/arch recorded in the log" \
    bash -c "bash '${DRIVER}' --prefix '${PREFIX}' --package '${WORK}/mmt-dpi_test.deb' --distro ubuntu-24.04 --arch amd64 \
             | grep -F 'mmt-dpi_test.deb|${WANT_SHA}|ubuntu-24.04|amd64'"

# --- 3. failure legs ----------------------------------------------------------
echo "  [3/4] failure legs"

# A missing required plugin must fail (and naming the plugin in the log).
mv "${PREFIX}/plugins/libmmt_tdicom.so" "${PREFIX}/plugins/libmmt_tdicom.so.bak"
check_fail "missing libmmt_tdicom.so plugin fails" \
    bash "${DRIVER}" --prefix "${PREFIX}" --distro suite-local
mv "${PREFIX}/plugins/libmmt_tdicom.so.bak" "${PREFIX}/plugins/libmmt_tdicom.so"

# An ENABLESEC engine missing from the payload must fail under the default
# --expect-engines. The file leaves the lib dir entirely — a *.bak rename
# would still match the driver's .so.* glob.
for f in "${PREFIX}/dpi/lib/"libmmt_security.so.*; do mv "$f" "${WORK}/"; done
check_fail "missing libmmt_security engine fails" \
    bash "${DRIVER}" --prefix "${PREFIX}" --distro suite-local
for f in "${WORK}/"libmmt_security.so.*; do mv "$f" "${PREFIX}/dpi/lib/"; done

# A wrong expected label must fail the classification verdict.
printf 'ftp_txt.pcap    http\n' > "${WORK}/fixtures-wrong-label.txt"
check_fail "wrong expected label fails" \
    env FIXTURES="${WORK}/fixtures-wrong-label.txt" \
        bash "${DRIVER}" --prefix "${PREFIX}" --distro suite-local

# A required protocol no plugin registers must fail the enumeration leg.
check_fail "unregistered required protocol fails" \
    env REQUIRED_PROTOS="tcp,not_a_real_proto" \
        bash "${DRIVER}" --prefix "${PREFIX}" --distro suite-local

# A missing fixture pcap must fail before any consumer run.
printf 'no_such_capture.pcap    ftp\n' > "${WORK}/fixtures-missing.txt"
check_fail "missing fixture pcap fails" \
    env FIXTURES="${WORK}/fixtures-missing.txt" \
        bash "${DRIVER}" --prefix "${PREFIX}" --distro suite-local

# The root-install leg (issue #485) must refuse a prefix the loader does not
# know: this throwaway prefix was installed unprivileged, so no drop-in names
# it and the consumer cannot rely on LD_LIBRARY_PATH.
check_fail "--root-install fails on a prefix not registered with the loader" \
    env LDCONF_FILE="${WORK}/no-such-dropin.conf" \
        bash "${DRIVER}" --prefix "${PREFIX}" --distro suite-local --root-install
printf '%s\n' "${PREFIX}/dpi/lib" > "${WORK}/dropin.conf"
check_fail "--root-install fails when ldconfig cannot resolve libmmt_core" \
    env LDCONF_FILE="${WORK}/dropin.conf" \
        bash "${DRIVER}" --prefix "${PREFIX}" --distro suite-local --root-install

# --- 4. wiring ------------------------------------------------------------------
echo "  [4/4] packaging wiring"
check "build-package.sh invokes the installed consumer" \
    grep -q 'run-installed-consumer.sh' "${REPO_ROOT}/tools/ci/build-package.sh"
check "build-package.sh --dry-run documents the consumer step" \
    bash -c "bash '${REPO_ROOT}/tools/ci/build-package.sh' --dry-run | grep -q 'installed consumer'"
check "driver is executable-compatible via bash" \
    bash -n "${DRIVER}"
check "driver replays with LD_LIBRARY_PATH unset under --root-install" \
    grep -q 'env -u LD_LIBRARY_PATH' "${DRIVER}"
check "CI runs the root-install leg in a container" \
    grep -q 'tools/ci/tests/run-root-install.sh' "${REPO_ROOT}/.github/workflows/c-cpp.yml"
check "root-install leg invokes the driver with --root-install" \
    grep -q -- '--root-install' "${REPO_ROOT}/tools/ci/tests/run-root-install.sh"
if [ "$(id -u)" -ne 0 ]; then
    check_fail "root-install leg refuses to run unprivileged" \
        bash "${REPO_ROOT}/tools/ci/tests/run-root-install.sh"
fi
check "driver compiles the consumer source" \
    bash -c "grep -q 'installed_consumer.c' '${DRIVER}'"

echo
if [ "${FAIL}" -gt 0 ]; then
    echo "✗ installed_consumer suite: ${FAIL} check(s) failed (${PASS} passed)" >&2
    exit 1
fi
echo "✓ installed_consumer suite: all ${PASS} checks passed"
