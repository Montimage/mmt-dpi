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
#     mode, and use a flag + pcap_breakloop in the signal handler;
#   * issue #485 (F-CI-104, F-UX-007, F-SEC-005, F-CI-116): `make install`
#     consumes built artifacts only, registers the loader by privilege
#     (LDCONF=auto|0|1), `make uninstall` / `install.sh --uninstall` leave no
#     residue, and the installer drops its LD_LIBRARY_PATH advice once the
#     loader is registered. Loader legs use a staged LDCONF_DIR and a fake
#     ldconfig — the suite never writes /etc (the real root leg is
#     tools/ci/tests/run-root-install.sh, run in a container by CI).
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
# Real `curl | bash` (script on stdin) from a directory that looks like a
# checkout: BASH_SOURCE[0] is empty there, and the installer must not resolve
# its own directory to the caller's cwd and source a foreign common file
# (issue #484, F-UX-003). The decoy would announce itself and disable the
# prefix validator.
DECOY="${WORK}/decoy"; mkdir -p "$DECOY/dist/ZIP"; touch "$DECOY/install.sh"
printf 'echo DECOY-SOURCED\nvalidate_mmt_base() { return 0; }\n' \
    > "$DECOY/dist/ZIP/mmt-install-common.sh"
check "piped install.sh ignores a checkout-shaped cwd" \
    bash -c "cd '${DECOY}' && bash -s -- --dry-run < '${REPO_ROOT}/install.sh' > out.txt 2>&1 && ! grep -q DECOY-SOURCED out.txt"
check_fail "piped install.sh still rejects a metachar prefix" \
    bash -c "cd '${DECOY}' && bash -s -- --prefix '/tmp/x;id' --dry-run < '${REPO_ROOT}/install.sh'"
# EL8/EL9 keep libpcap-devel in a disabled repo: both RHEL-family branches
# must enable CRB / PowerTools before installing (issue #484, F-CI-106).
# Loader registration + uninstall (issue #485).
check "--uninstall --dry-run prints the uninstall plan" \
    bash -c "bash '${REPO_ROOT}/install.sh' --uninstall --prefix '${WORK}/un' --dry-run | grep -q 'Uninstall plan'"
check "user-local prefix plan does not register the loader" \
    bash -c "MMT_BASE='${WORK}/ulocal' bash '${REPO_ROOT}/install.sh' --dry-run | grep -q 'Loader.*not registered'"
if [ "$(id -u)" -ne 0 ]; then
    check "root-owned prefix plan registers the loader" \
        bash -c "MMT_BASE=/usr/local/mmt bash '${REPO_ROOT}/install.sh' --dry-run | grep -q 'Loader.*mmt-dpi.conf + ldconfig'"
fi
check "LDCONF=0 plan does not register the loader" \
    bash -c "MMT_BASE=/usr/local/mmt LDCONF=0 bash '${REPO_ROOT}/install.sh' --dry-run | grep -q 'Loader.*not registered'"
check_fail "install.sh rejects LDCONF=bogus" \
    env LDCONF=bogus bash "${REPO_ROOT}/install.sh" --dry-run
check "LD_LIBRARY_PATH advice only when the loader is not registered" \
    bash -c "awk '/^post_install/,/^}/' '${REPO_ROOT}/install.sh' | grep -B2 'export LD_LIBRARY_PATH' | grep -q 'registered\" = \"0'"
check "installer no longer prints the dist-clean uninstall" \
    bash -c "! grep -q 'make dist-clean' '${REPO_ROOT}/install.sh'"
check "install.sh passes LDCONF to make install" \
    bash -c "[ \"\$(grep -c 'MMT_BASE=\"\$MMT_BASE\" LDCONF=\"\$LDCONF\" install' '${REPO_ROOT}/install.sh')\" -eq 2 ]"
# A real --uninstall over a user-writable fake install: the entries its
# manifest lists and the directories they leave empty go; foreign files under
# the prefix — even inside examples/ and dpi/include/ — stay.
UI="${WORK}/ui-prefix"
mkdir -p "${UI}/dpi/lib" "${UI}/dpi/include/sub" "${UI}/plugins" "${UI}/examples" "${UI}/probe"
: > "${UI}/dpi/lib/libmmt_core.so.1.9.1"; ln -s libmmt_core.so.1.9.1 "${UI}/dpi/lib/libmmt_core.so"
: > "${UI}/dpi/lib/libmmt_core.a"; : > "${UI}/dpi/include/sub/mmt_core.h"
: > "${UI}/plugins/libmmt_tcpip.so"; : > "${UI}/examples/extract_all.c"; : > "${UI}/probe/keep.conf"
printf '%s\n' '# manifest' dpi/include/sub dpi/include/sub/mmt_core.h dpi/lib/libmmt_core.a \
    dpi/lib/libmmt_core.so dpi/lib/libmmt_core.so.1.9.1 examples/extract_all.c \
    plugins/libmmt_tcpip.so > "${UI}/.mmt-dpi-manifest"
check "install.sh --uninstall removes a user-local install" \
    bash -c "bash '${REPO_ROOT}/install.sh' --uninstall --prefix '${UI}' && [ ! -e '${UI}/dpi' ] && [ ! -e '${UI}/plugins' ] && [ ! -e '${UI}/examples' ] && [ ! -e '${UI}/.mmt-dpi-manifest' ]"
check "install.sh --uninstall keeps foreign files under the prefix" \
    test -f "${UI}/probe/keep.conf"
mkdir -p "${UI}/dpi/include" "${UI}/examples"
: > "${UI}/dpi/include/mmt_core.h"; : > "${UI}/examples/extract_all.c"
: > "${UI}/dpi/include/foreign.h"; : > "${UI}/examples/foreign.c"
printf '%s\n' dpi/include/mmt_core.h examples/extract_all.c > "${UI}/.mmt-dpi-manifest"
check "install.sh --uninstall keeps foreign files in examples/ and dpi/include/" \
    bash -c "bash '${REPO_ROOT}/install.sh' --uninstall --prefix '${UI}' && [ -f '${UI}/dpi/include/foreign.h' ] && [ -f '${UI}/examples/foreign.c' ] && [ ! -e '${UI}/dpi/include/mmt_core.h' ] && [ ! -e '${UI}/examples/extract_all.c' ]"
rm -rf "${UI}"; mkdir -p "${UI}/dpi/lib" "${UI}/dpi/include" "${UI}/examples"
: > "${UI}/dpi/lib/libmmt_core.so.1.9.1"; : > "${UI}/dpi/include/mmt_core.h"; : > "${UI}/examples/extract_all.c"
check "install.sh --uninstall without a manifest removes libraries, keeps include/examples" \
    bash -c "bash '${REPO_ROOT}/install.sh' --uninstall --prefix '${UI}' && [ ! -e '${UI}/dpi/lib' ] && [ -f '${UI}/dpi/include/mmt_core.h' ] && [ -f '${UI}/examples/extract_all.c' ]"
rm -rf "${UI}"; mkdir -p "${UI}/examples" "${WORK}/outside"; : > "${WORK}/outside/keep"
printf '%s\n' examples/../../outside/keep > "${UI}/.mmt-dpi-manifest"
check_fail "install.sh --uninstall refuses a manifest entry leaving the prefix" \
    bash "${REPO_ROOT}/install.sh" --uninstall --prefix "${UI}"
check "refused manifest uninstall deleted nothing" \
    bash -c "[ -f '${WORK}/outside/keep' ] && [ -f '${UI}/.mmt-dpi-manifest' ]"
# A directory symlink planted under the prefix must not redirect removal
# outside it, and a symlinked manifest is refused.
rm -rf "${UI}"; mkdir -p "${UI}/dpi" "${WORK}/outside-ui"; : > "${WORK}/outside-ui/victim.h"
ln -s "${WORK}/outside-ui" "${UI}/dpi/include"
printf '%s\n' dpi/include/victim.h > "${UI}/.mmt-dpi-manifest"
check "install.sh --uninstall skips an entry behind a symlinked parent" \
    bash -c "bash '${REPO_ROOT}/install.sh' --uninstall --prefix '${UI}' && [ -f '${WORK}/outside-ui/victim.h' ]"
rm -rf "${UI}"; mkdir -p "${UI}"; printf 'examples/x.c\n' > "${WORK}/outside-ui/manifest"
ln -s "${WORK}/outside-ui/manifest" "${UI}/.mmt-dpi-manifest"
check_fail "install.sh --uninstall refuses a symlinked manifest" \
    bash "${REPO_ROOT}/install.sh" --uninstall --prefix "${UI}"
rm -rf "${UI}"
for bad in '//' '/.' '/opt/./mmt' '/opt/*'; do
    check_fail "install.sh --uninstall refuses MMT_BASE='${bad}'" \
        bash "${REPO_ROOT}/install.sh" --uninstall --prefix "${bad}" --dry-run
done
check "install.sh writes a manifest when the pinned Makefile did not" \
    bash -c "awk '/^install_mmt/,/^}/' '${REPO_ROOT}/install.sh' | grep -q 'write_manifest'"
check "dnf and yum branches enable CRB first" \
    bash -c "[ \"\$(awk '/^install_deps_linux/,/^}/' '${REPO_ROOT}/install.sh' | grep -c 'enable_el_builder_repo \(dnf\|yum\)')\" -eq 2 ]"

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

# --- 7. make install / uninstall contract (issue #485) ----------------------
echo "--- make install consumes artifacts; loader by privilege; uninstall ---"
SDKM=(make -C "${REPO_ROOT}/sdk" "${SDK_MAKE_ARGS[@]}")
FAKE_LDCONFIG="${WORK}/bin/ldconfig"
mkdir -p "${WORK}/bin"
printf '#!/bin/sh\necho ran >> "%s"\n' "${WORK}/ldconfig.calls" > "${FAKE_LDCONFIG}"
chmod +x "${FAKE_LDCONFIG}"
STAGE=(LDCONF_DIR="${WORK}/etc" LDCONFIG="${FAKE_LDCONFIG}")
DROPIN="${WORK}/etc/mmt-dpi.conf"
COMPILER_RE='\[COMPILE\]|(^|[[:space:]/])(gcc|g\+\+|cc|c\+\+|clang)[[:space:]]'

check "make -n install after a build prints no compiler invocation" \
    bash -c "! \"\$@\" -n MMT_BASE='${PREFIX2}' install 2>&1 | grep -Eq '${COMPILER_RE}'" _ "${SDKM[@]}"
check "rebuild with the same prefix compiles nothing" \
    bash -c "! \"\$@\" -j'${JOBS}' MMT_BASE='${PREFIX2}' 2>&1 | grep -q '\[COMPILE\]'" _ "${SDKM[@]}"
check_fail "install to a prefix the build was not made for is refused" \
    "${SDKM[@]}" MMT_BASE="${WORK}/other-prefix" "${STAGE[@]}" install
check "refused install created nothing" test ! -e "${WORK}/other-prefix"
check_fail "LDCONF=bogus is refused" \
    "${SDKM[@]}" MMT_BASE="${PREFIX2}" "${STAGE[@]}" LDCONF=bogus install
if [ "$(id -u)" -ne 0 ]; then
    check "non-root install (LDCONF=auto) writes no loader drop-in" \
        bash -c "\"\$@\" MMT_BASE='${PREFIX2}' install && [ ! -e '${DROPIN}' ] && [ ! -e '${WORK}/ldconfig.calls' ]" _ "${SDKM[@]}" "${STAGE[@]}"
fi
# `make -n` cannot see the old defect (it deleted plugins_engine.o in a
# recipe, which -n skips), so a real install must compile nothing either.
check "make install (real run) compiles nothing" \
    bash -c "! \"\$@\" MMT_BASE='${PREFIX2}' LDCONF=0 install 2>&1 | grep -q '\[COMPILE\]'" _ "${SDKM[@]}" "${STAGE[@]}"
check "LDCONF=0 writes no loader drop-in" \
    bash -c "\"\$@\" MMT_BASE='${PREFIX2}' LDCONF=0 install && [ ! -e '${DROPIN}' ]" _ "${SDKM[@]}" "${STAGE[@]}"
check "LDCONF=1 writes the drop-in naming the library dir" \
    bash -c "\"\$@\" MMT_BASE='${PREFIX2}' LDCONF=1 install && [ \"\$(cat '${DROPIN}')\" = '${PREFIX2}/dpi/lib' ]" _ "${SDKM[@]}" "${STAGE[@]}"
check "loader drop-in is mode 0644" \
    bash -c "[ \"\$(stat -c %a '${DROPIN}')\" = 644 ]"
check "registration runs ldconfig" test -s "${WORK}/ldconfig.calls"
check "make install writes the install manifest" \
    bash -c "grep -qx 'dpi/lib/libmmt_core.so' '${PREFIX2}/.mmt-dpi-manifest' && grep -qx 'examples/extract_all.c' '${PREFIX2}/.mmt-dpi-manifest'"
mkdir -p "${PREFIX2}/probe"; : > "${PREFIX2}/probe/keep.conf"
: > "${PREFIX2}/examples/foreign.c"; : > "${PREFIX2}/dpi/include/foreign.h"
check "make uninstall succeeds" \
    "${SDKM[@]}" MMT_BASE="${PREFIX2}" "${STAGE[@]}" uninstall
check "uninstall removes the SDK files" \
    bash -c "[ ! -e '${PREFIX2}/dpi/lib' ] && [ ! -e '${PREFIX2}/plugins' ] && [ ! -e '${PREFIX2}/.mmt-dpi-manifest' ] && [ \"\$(find '${PREFIX2}/examples' '${PREFIX2}/dpi' -type f | wc -l)\" -eq 2 ]"
check "uninstall keeps foreign files under the prefix" test -f "${PREFIX2}/probe/keep.conf"
check "uninstall keeps foreign files in examples/ and dpi/include/" \
    bash -c "[ -f '${PREFIX2}/examples/foreign.c' ] && [ -f '${PREFIX2}/dpi/include/foreign.h' ]"
rm -rf "${PREFIX2}/examples" "${PREFIX2}/dpi"
check "uninstall removes the drop-in and reruns ldconfig" \
    bash -c "[ ! -e '${DROPIN}' ] && [ \"\$(wc -l < '${WORK}/ldconfig.calls')\" -eq 2 ]"
rm -rf "${PREFIX2}/probe"
# A full round trip leaves no prefix; a drop-in registering another prefix
# survives.
mkdir -p "${WORK}/etc"; echo /some/other/lib > "${DROPIN}"
check "round trip leaves neither the prefix nor its drop-in" \
    bash -c "\"\$@\" MMT_BASE='${PREFIX2}' LDCONF=0 install && \"\$@\" MMT_BASE='${PREFIX2}' uninstall && [ ! -e '${PREFIX2}' ]" _ "${SDKM[@]}" "${STAGE[@]}"
check "uninstall keeps a drop-in naming another prefix" \
    bash -c "[ \"\$(cat '${DROPIN}')\" = /some/other/lib ]"
check_fail "uninstall refuses MMT_BASE=/" \
    "${SDKM[@]}" MMT_BASE=/ "${STAGE[@]}" uninstall
# Prefix guard: every refusal happens before anything is removed. A canary
# directory the bad paths point at must survive each attempt.
CANARY="${WORK}/canary"; mkdir -p "${CANARY}"; : > "${CANARY}/keep"
mkdir -p "${PREFIX2}"
for bad in "MMT_BASE=//" "MMT_BASE=/." "MMT_BASE=${WORK}/c*" "MMT_BASE=${PREFIX2}/" \
           "MMT_INC=${PREFIX2}/../canary" "MMT_EXAMS=${CANARY}" "MMT_EXAMS=${PREFIX2}" \
           "MMT_INC=${PREFIX2}/./dpi/include"; do
    case "${bad}" in MMT_BASE=*) args=("${bad}") ;; *) args=(MMT_BASE="${PREFIX2}" "${bad}") ;; esac
    check_fail "uninstall refuses ${bad#"${WORK}"/}" \
        "${SDKM[@]}" "${args[@]}" "${STAGE[@]}" uninstall
done
check "refused uninstalls deleted nothing" test -f "${CANARY}/keep"
rmdir "${PREFIX2}"
# Symlinked parent inside the prefix pointing outside it: the canary named in
# the manifest survives; a symlinked manifest is refused.
SYMP="${WORK}/sym-prefix"; mkdir -p "${SYMP}/dpi"; : > "${CANARY}/victim.h"
ln -s "${CANARY}" "${SYMP}/dpi/include"
printf '%s\n' dpi/include/victim.h > "${SYMP}/.mmt-dpi-manifest"
check "uninstall skips an entry behind a symlinked parent" \
    bash -c "\"\$@\" MMT_BASE='${SYMP}' uninstall && [ -f '${CANARY}/victim.h' ]" _ "${SDKM[@]}" "${STAGE[@]}"
rm -rf "${SYMP}"; mkdir -p "${SYMP}"; printf 'examples/x.c\n' > "${CANARY}/manifest"
ln -s "${CANARY}/manifest" "${SYMP}/.mmt-dpi-manifest"
check_fail "uninstall refuses a symlinked manifest" \
    "${SDKM[@]}" MMT_BASE="${SYMP}" "${STAGE[@]}" uninstall
mkdir -p "${PREFIX2}"; ln -s "${CANARY}/manifest" "${PREFIX2}/.mmt-dpi-manifest"
check_fail "install refuses to write through a symlinked manifest" \
    "${SDKM[@]}" MMT_BASE="${PREFIX2}" "${STAGE[@]}" LDCONF=0 install
rm -rf "${PREFIX2}"
check "symlinked manifest target untouched" \
    bash -c "[ \"\$(cat '${CANARY}/manifest')\" = examples/x.c ]"
rm -rf "${SYMP}"
check "dist-clean is an alias for uninstall" \
    grep -q '^dist-clean: uninstall$' "${REPO_ROOT}/sdk/Makefile"

echo
if [ "${FAIL}" -gt 0 ]; then
    echo "✗ installer suite: ${FAIL} check(s) failed (${PASS} passed)" >&2
    exit 1
fi
echo "✓ installer suite: all ${PASS} checks passed"
