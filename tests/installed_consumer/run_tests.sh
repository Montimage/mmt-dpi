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

# --- 4. wiring ------------------------------------------------------------------
echo "  [4/4] packaging wiring"
check "build-package.sh invokes the installed consumer" \
    grep -q 'run-installed-consumer.sh' "${REPO_ROOT}/tools/ci/build-package.sh"
check "build-package.sh --dry-run documents the consumer step" \
    bash -c "bash '${REPO_ROOT}/tools/ci/build-package.sh' --dry-run | grep -q 'installed consumer'"
check "driver is executable-compatible via bash" \
    bash -n "${DRIVER}"
check "driver compiles the consumer source" \
    bash -c "grep -q 'installed_consumer.c' '${DRIVER}'"

echo
if [ "${FAIL}" -gt 0 ]; then
    echo "✗ installed_consumer suite: ${FAIL} check(s) failed (${PASS} passed)" >&2
    exit 1
fi
echo "✓ installed_consumer suite: all ${PASS} checks passed"
