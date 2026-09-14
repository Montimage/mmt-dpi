#!/usr/bin/env bash
#
# run_tests.sh — regression suite for issue #211
# (F-BUG-104, F-BUG-105, F-BUG-116, F-BUG-117, F-BUG-121):
#
#   * the install prefix validator is an allowlist defined canonically in
#     dist/ZIP/mmt-install-common.sh; the root install.sh carries a
#     byte-identical fallback for `curl | bash` runs whose pinned clone
#     predates the common file (v1.8.0 ships none);
#   * install.sh elevates by prefix writability (not the /opt/mmt literal)
#     and only runs ldconfig when it installed with elevation;
#   * tools/ci/build-package.sh supports --dry-run, clears dist/packages/
#     before collecting and smoke-tests the tracked artifact path;
#   * the offline ZIP install/uninstall round trip leaves no residue under a
#     temporary prefix (runnable unprivileged);
#   * the patched examples initialise their argument storage, reject an unset
#     mode, and use a flag + pcap_breakloop in the signal handler.
#
# Usage: tests/installer/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

CC="${CC:-gcc}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

PASS=0
FAIL=0

ok()   { echo "  ✓ $1"; PASS=$((PASS + 1)); }
bad()  { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }

# check <desc> <cmd...> — pass when the command exits 0.
check() {
    local desc="$1"; shift
    if "$@" >"${WORK}/out.log" 2>&1; then ok "$desc"; else bad "$desc"; sed 's/^/      /' "${WORK}/out.log" | head -10; fi
}

# check_fail <desc> <cmd...> — pass when the command exits non-zero.
check_fail() {
    local desc="$1"; shift
    if "$@" >"${WORK}/out.log" 2>&1; then bad "$desc (unexpected success)"; else ok "$desc"; fi
}

# vbase <prefix> — run the shared validator inside a subshell.
vbase() {
    ( # shellcheck disable=SC1091  # path anchored at the repo root
      source "${REPO_ROOT}/dist/ZIP/mmt-install-common.sh"
      validate_mmt_base "$1" )
}

echo "=== installer / examples regression (issue #211) ==="

# --- 1. Shared validator is an allowlist -----------------------------------
echo "--- shared prefix validator (allowlist) ---"
for p in /opt/mmt /usr/local/mmt /tmp/mmt-v1.8_test.x /a; do
    check "validator accepts $p" vbase "$p"
done
# shellcheck disable=SC2016  # single quotes are intentional: literal metachars
for p in "rel/path" "/" "/tmp/../etc" "/tmp/x;id" '/tmp/$(id)' '/tmp/x`id`' \
         "/tmp/has space" "/tmp/x'y" '/tmp/x"y' "/tmp/x|y" "/tmp/x&y" \
         "/tmp/x(y)" "/tmp/x=y" "/tmp/x:y" "/tmp/x!y" "/tmp/trail/" \
         "/tmp/x<y" "/tmp/x>y" "/tmp/x,y"; do
    check_fail "validator rejects ${p@Q}" vbase "$p"
done
check "validator is an allowlist (no blacklist glob left)" \
    bash -c "grep -q 'A-Za-z0-9._/-' '${REPO_ROOT}/dist/ZIP/mmt-install-common.sh'"

# --- 2. Canonical definition in the shared file; install.sh carries an ------
#      identical local fallback (sourced copy wins when present). The fallback
#      exists because `curl | bash` clones the pinned v1.8.0 tag, which ships
#      no dist/ZIP/mmt-install-common.sh at all — the diff check is what keeps
#      the two copies from drifting (issue #211, F-BUG-121).
echo "--- shared validator + install.sh fallback (dedupe) ---"
check "shared file defines the canonical validator" \
    bash -c "grep -q '^validate_mmt_base()' '${REPO_ROOT}/dist/ZIP/mmt-install-common.sh'"
check "install.sh fallback is identical to the shared definition" \
    bash -c "diff -q <(sed -n '/^validate_mmt_base()/,/^}/p' '${REPO_ROOT}/install.sh') <(sed -n '/^validate_mmt_base()/,/^}/p' '${REPO_ROOT}/dist/ZIP/mmt-install-common.sh') >/dev/null"
check "install.sh sources mmt-install-common.sh when present" \
    grep -q 'mmt-install-common\.sh' "${REPO_ROOT}/install.sh"
check "clone lacking the common file is not fatal (local fallback)" \
    bash -c "grep -qF 'load_common_defs \"\$BUILD_DIR/mmt-dpi/dist/ZIP/mmt-install-common.sh\" || true' '${REPO_ROOT}/install.sh'"

# --- 3. Root installer: --prefix, writability-based elevation --------------
echo "--- install.sh CLI and elevation ---"
check "install.sh --dry-run" \
    bash "${REPO_ROOT}/install.sh" --dry-run
check "install.sh --prefix <tmp> --dry-run" \
    bash "${REPO_ROOT}/install.sh" --prefix "${WORK}/p1" --dry-run
check "--prefix value lands in the plan" \
    bash -c "bash '${REPO_ROOT}/install.sh' --prefix '${WORK}/p1' --dry-run | grep -qF '${WORK}/p1'"
check "MMT_BASE=/usr/local/mmt dry run succeeds" \
    bash -c "MMT_BASE=/usr/local/mmt bash '${REPO_ROOT}/install.sh' --dry-run"
check "/usr/local/mmt needs elevation (not a path literal)" \
    bash -c "MMT_BASE=/usr/local/mmt bash '${REPO_ROOT}/install.sh' --dry-run | grep -q 'Elevation.*sudo'"
check "user-local prefix needs no elevation" \
    bash -c "MMT_BASE='${WORK}/ulocal' bash '${REPO_ROOT}/install.sh' --dry-run | grep -q 'Elevation.*not needed'"
check_fail "install.sh rejects metachar prefix" \
    bash "${REPO_ROOT}/install.sh" --prefix '/tmp/x;id' --dry-run
check "ldconfig gated on elevation" \
    bash -c "awk '/^post_install/,/^}/' '${REPO_ROOT}/install.sh' | grep -q 'ELEVATED.*=.*1'"
# Standalone copy (no sibling repo files): exercises the `curl | bash` shape —
# the local fallback validator must run even with no common file beside the
# script, and a bad prefix must still be refused before any clone.
SA="${WORK}/standalone"; mkdir -p "$SA"; cp "${REPO_ROOT}/install.sh" "$SA/"
check "install.sh runs standalone (no sibling repo files)" \
    bash -c "cd '${SA}' && bash install.sh --prefix '${WORK}/sa-prefix' --dry-run"
check_fail "standalone run still rejects a metachar prefix" \
    bash -c "cd '${SA}' && bash install.sh --prefix '/tmp/x;id' --dry-run"

# --- 4. build-package.sh: --dry-run + tracked artifact ---------------------
echo "--- build-package.sh ---"
check "build-package.sh --dry-run" \
    bash "${REPO_ROOT}/tools/ci/build-package.sh" --dry-run
check "no dist/packages/* glob remains" \
    bash -c "[ \"\$(grep -c 'dist/packages/\*' '${REPO_ROOT}/tools/ci/build-package.sh')\" = '0' ]"
check "dist/packages cleared before collecting" \
    bash -c "grep -q 'rm -rf dist/packages' '${REPO_ROOT}/tools/ci/build-package.sh'"
check "smoke test installs tracked artifacts" \
    bash -c "grep -q 'apt-get install -y \"\${artifacts' '${REPO_ROOT}/tools/ci/build-package.sh'"

# --- 5. ZIP install/uninstall round trip — no residue ----------------------
echo "--- ZIP install/uninstall round trip ---"
Z="${WORK}/zip"
mkdir -p "${Z}/lib" "${Z}/include" "${Z}/examples"
cp "${REPO_ROOT}"/dist/ZIP/install.sh "${REPO_ROOT}"/dist/ZIP/uninstall.sh \
   "${REPO_ROOT}"/dist/ZIP/mmt-install-common.sh "${Z}/"
for l in libmmt_core libmmt_tcpip libmmt_tmobile libmmt_tdicom \
         libmmt_business_app libmmt_security libmmt_fuzz; do
    : > "${Z}/lib/${l}.so.1.8.0"
done
echo '/* stub header */'  > "${Z}/include/mmt_core.h"
echo '/* stub example */' > "${Z}/examples/stub.c"

ZPREFIX="${WORK}/prefix"
check "ZIP install into temp prefix (unprivileged)" \
    bash -c "cd '${Z}' && MMT_BASE='${ZPREFIX}' bash install.sh"
check "installed lib present"  test -f "${ZPREFIX}/dpi/lib/libmmt_core.so.1.8.0"
check "installed .so link"     test -e "${ZPREFIX}/dpi/lib/libmmt_core.so"
check "installed plugin"       test -f "${ZPREFIX}/plugins/libmmt_tcpip.so"
check "installed examples dir" test -f "${ZPREFIX}/examples/stub.c"
check "uninstaller removes examples dir (was created by installer)" \
    bash -c "cd '${Z}' && MMT_BASE='${ZPREFIX}' bash uninstall.sh >/dev/null 2>&1 && [ ! -e '${ZPREFIX}/examples' ]"
check "no residue under prefix after round trip" \
    bash -c "! [ -e '${ZPREFIX}' ] || [ -z \"\$(find '${ZPREFIX}' -mindepth 1 -print -quit)\" ]"
check_fail "unwritable prefix still refused for non-root" \
    bash -c "cd '${Z}' && MMT_BASE=/sys/mmt-nope bash install.sh"

# --- 6. Examples: compile + behaviour ---------------------------------------
echo "--- example programs (build SDK to throwaway prefix) ---"
PREFIX2="${WORK}/sdk-prefix"
BUILD_LOG="${WORK}/sdk-build.log"
SDK_MAKE_ARGS=()
if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    SDK_MAKE_ARGS=("BUILD=${SDK_BUILD_PROFILE}")
fi
make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
if ! make -C "${REPO_ROOT}/sdk" "${SDK_MAKE_ARGS[@]}" -j"${JOBS}" MMT_BASE="${PREFIX2}" >"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
if ! make -C "${REPO_ROOT}/sdk" "${SDK_MAKE_ARGS[@]}" MMT_BASE="${PREFIX2}" install >>"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi

INC="${PREFIX2}/dpi/include"
LIB="${PREFIX2}/dpi/lib"
PLUGINS="${PREFIX2}/plugins"
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
ln -s "${PLUGINS}" "${WORK}/plugins"

for ex in extract_all MAC_extraction simple_traffic_reporting; do
    check "compile ${ex} against installed SDK" \
        "${CC}" "${extra_cflags[@]}" -O1 -Wall -o "${WORK}/${ex}" \
            "${PREFIX2}/examples/${ex}.c" -I "${INC}" -L "${LIB}" -lmmt_core -ldl -lpcap
done

# Unset mode must be rejected (was: uninitialised `type` branched randomly).
check_fail "extract_all with no args is rejected" \
    bash -c "cd '${WORK}' && LD_LIBRARY_PATH='${LIB}' '${WORK}/extract_all'"
check_fail "MAC_extraction with no args is rejected" \
    bash -c "cd '${WORK}' && LD_LIBRARY_PATH='${LIB}' '${WORK}/MAC_extraction'"
check_fail "extract_all -t missing file fails cleanly" \
    bash -c "cd '${WORK}' && LD_LIBRARY_PATH='${LIB}' '${WORK}/extract_all' -t '${WORK}/missing.pcap'"

# Real capture runs end-to-end and exits cleanly (single clean() pass).
check "extract_all processes google-fr.pcap" \
    bash -c "cd '${WORK}' && LD_LIBRARY_PATH='${LIB}' '${WORK}/extract_all' -t '${REPO_ROOT}/src/examples/google-fr.pcap' >'${WORK}/exta.txt' 2>/dev/null"
check "MAC_extraction processes google-fr.pcap" \
    bash -c "cd '${WORK}' && LD_LIBRARY_PATH='${LIB}' '${WORK}/MAC_extraction' -t '${REPO_ROOT}/src/examples/google-fr.pcap' >/dev/null 2>&1"
check "simple_traffic_reporting processes google-fr.pcap" \
    bash -c "cd '${WORK}' && LD_LIBRARY_PATH='${LIB}' '${WORK}/simple_traffic_reporting' '${REPO_ROOT}/src/examples/google-fr.pcap' >'${WORK}/str.txt' 2>/dev/null"

# Signal handling: handler must only flag + breakloop (no printf/clean inside).
check "extract_all handler uses pcap_breakloop" \
    grep -q 'pcap_breakloop' "${REPO_ROOT}/src/examples/extract_all.c"
check "extract_all handler never calls clean()/printf" \
    bash -c "! sed -n '/^void signal_handler/,/^}/p' '${REPO_ROOT}/src/examples/extract_all.c' | grep -qE 'clean|printf|fflush'"
check "extract_all loop observes the stop flag" \
    grep -q 'stop_flag' "${REPO_ROOT}/src/examples/extract_all.c"
check "simple_traffic_reporting uses bounded hierarchy API" \
    grep -q 'proto_hierarchy_to_str_with_size' "${REPO_ROOT}/src/examples/simple_traffic_reporting.c"

echo
if [ "${FAIL}" -gt 0 ]; then
    echo "✗ installer suite: ${FAIL} check(s) failed (${PASS} passed)" >&2
    exit 1
fi
echo "✓ installer suite: all ${PASS} checks passed"
