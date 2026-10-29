#!/usr/bin/env bash
#
# run_tests.sh — regression suite for issue #211
# (F-BUG-104, F-BUG-105, F-BUG-116, F-BUG-117, F-BUG-121):
#
#   * the install prefix validator is an allowlist, defined once in the root
#     install.sh, which sources no file from a checkout or a clone (the
#     offline ZIP that shared it is retired, issue #550);
#   * install.sh elevates by prefix writability (not the /opt/mmt literal)
#     and only runs ldconfig when it installed with elevation;
#   * tools/ci/build-package.sh supports --dry-run, clears dist/packages/
#     before collecting and smoke-tests the tracked artifact path;
#   * issue #550: every install route writes mmt-dpi.pc — `make install`
#     (recorded in the manifest, with the rpath an /opt prefix needs),
#     install-fhs and the make deb/rpm staging; mmt-dpi.spec is the
#     distribution recipe; dist/ZIP is retired; MMT_EXAMPLES_SRC names only
#     the programs in src/examples;
#   * the patched examples initialise their argument storage, reject an unset
#     mode, and use a flag + pcap_breakloop in the signal handler;
#   * issue #485 (F-CI-104, F-UX-007, F-SEC-005, F-CI-116): `make install`
#     consumes built artifacts only, registers the loader by privilege
#     (LDCONF=auto|0|1), `make uninstall` / `install.sh --uninstall` leave no
#     residue, and the installer drops its LD_LIBRARY_PATH advice once the
#     loader is registered. Loader legs use a staged LDCONF_DIR and a fake
#     ldconfig — the suite never writes /etc (the real root leg is
#     tools/ci/tests/run-root-install.sh, run in a container by CI).
#   * issue #497 (F-CI-109): every install route ships LICENSE and a
#     THIRD-PARTY-NOTICES generated from tools/ci/vendored-components.json;
#     the rpm spec's License: fields are the SPDX expressions the notices
#     check derives; the ENABLESEC engines (libmmt_security, libmmt_fuzz)
#     build into their own package, mmt-dpi-security, with the GPL text.
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

# vbase <prefix> — run install.sh's validator inside a subshell.
vbase() {
    ( eval "$(sed -n '/^validate_mmt_base()/,/^}/p' "${REPO_ROOT}/install.sh")"
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
    bash -c "sed -n '/^validate_mmt_base()/,/^}/p' '${REPO_ROOT}/install.sh' | grep -q 'A-Za-z0-9._/-'"

# --- 2. One definition, nothing sourced (issue #550) ------------------------
#      install.sh used to source dist/ZIP/mmt-install-common.sh from its
#      checkout or its clone and keep a byte-identical fallback; with the ZIP
#      retired its own definitions are the only ones.
echo "--- install.sh: one validator, nothing sourced ---"
check "install.sh defines validate_mmt_base and prefix_writable once" \
    bash -c "[ \"\$(grep -c '^validate_mmt_base()' '${REPO_ROOT}/install.sh')\" -eq 1 ] && [ \"\$(grep -c '^prefix_writable()' '${REPO_ROOT}/install.sh')\" -eq 1 ]"
check "install.sh sources no file" \
    bash -c "! grep -nE '^[[:space:]]*(source|\.)[[:space:]]' '${REPO_ROOT}/install.sh'"
check "dist/ZIP is retired: no tracked file, no zip target" \
    bash -c "[ -z \"\$(git -C '${REPO_ROOT}' ls-files dist/ZIP)\" ] && ! grep -q '^zip:' '${REPO_ROOT}/sdk/Makefile'"

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
check "install.sh lays down the licence files when the pinned Makefile did not" \
    bash -c "awk '/^install_mmt/,/^}/' '${REPO_ROOT}/install.sh' | grep -q 'install_licence_files'"
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
check "build-package.sh requires both mmt-dpi and mmt-dpi-security" \
    grep -q 'for name in mmt-dpi mmt-dpi-security; do' "${REPO_ROOT}/tools/ci/build-package.sh"

# --- 4b. Licence fields (issue #497) -----------------------------------------
# The spec used to say `License: proprietary`; each package now carries the
# SPDX expression `vendored-components.py notices --check` derives from the
# repository LICENSE, the vendored-component manifest and the engine sources.
echo "--- package licence fields ---"
MK="${REPO_ROOT}/sdk/Makefile"
check "PKG_LICENSE is the mmt-dpi SPDX expression" \
    grep -qx 'PKG_LICENSE := Apache-2.0 AND BSD-2-Clause AND MIT' "${MK}"
check "SEC_PKG_LICENSE is the mmt-dpi-security SPDX expression" \
    grep -qx 'SEC_PKG_LICENSE := GPL-3.0-or-later AND Apache-2.0' "${MK}"
check "rpm spec: mmt-dpi License: is PKG_LICENSE" \
    bash -c "sed -n '/^rpm:/,/^clean:/p' '${MK}' | grep -qF '\\nLicense: \$(PKG_LICENSE)'"
check "rpm spec: the security subpackage License: is SEC_PKG_LICENSE" \
    bash -c "sed -n '/^rpm:/,/^clean:/p' '${MK}' | grep -qF '\\nLicense: \$(SEC_PKG_LICENSE)'"
check "rpm spec: libmmt_security/libmmt_fuzz belong to the security subpackage" \
    bash -c "sed -n '/^rpm:/,/^clean:/p' '${MK}' | grep -q '%package security' && grep -qx 'MMT_PKG_LIBS  = \$(MMT_LAYOUT_LIBS)' '${MK}' && ! grep '^MMT_LAYOUT_LIBS' '${MK}' | grep -Eq 'SECURITY|FUZZ|security|fuzz'"
check "no hard-coded licence literal is left in the spec" \
    bash -c "! sed -n '/^rpm:/,/^clean:/p' '${MK}' | grep -Eq 'License: *(proprietary|Apache-2.0)'"
check "THIRD-PARTY-NOTICES and the licence expressions are current" \
    python3 "${REPO_ROOT}/tools/ci/vendored-components.py" notices --check
# mmt-dpi.spec (issue #550): the distribution recipe builds the mmt-dpi
# package's libraries, so it carries the same expression; it builds from the
# release source tarball through install-fhs, one variable set for both.
SPEC="${REPO_ROOT}/mmt-dpi.spec"
check "mmt-dpi.spec License: is PKG_LICENSE" \
    bash -c "[ \"\$(sed -n 's/^License:[[:space:]]*//p' '${SPEC}')\" = \"\$(sed -n 's/^PKG_LICENSE := //p' '${MK}')\" ]"
check "mmt-dpi.spec builds from the release source tarball" \
    grep -qE '^Source0:.*/%\{name\}-%\{version\}\.tar\.gz$' "${SPEC}"
check "mmt-dpi.spec passes one variable set to the build and to install-fhs" \
    bash -c "grep -qE '^LDFLAGS=\"%\\{build_ldflags\\}\" %make_build -C sdk %\\{mmt_vars\\} MMT_EXTRA_CFLAGS' '${SPEC}' && grep -qE '^%make_build -C sdk %\\{mmt_vars\\} DESTDIR=%\\{buildroot\\} install-fhs$' '${SPEC}'"

# --- 4c. One install layout (issue #538, F-DEAD-011) -------------------------
# install, its manifest and uninstall, the deb/rpm staging and install-fhs all
# iterate the MMT_LAYOUT_* lists: no other line of sdk/Makefile may name a
# plugin or engine library as a list or recipe token. Description text
# ("the libmmt_security rule engine") and the *_OBJECTS variables do not
# count; a hard-coded recipe line must.
echo "--- one install layout list (issue #538) ---"
# second_layout_list <makefile> — prints each non-comment line outside the
# MMT_LAYOUT_ definitions that names a plugin/engine library; fails if any.
second_layout_list() {
    ! grep -nE '\$\(LIB(TCPIP|MOBILE|DICOM|BAPP|SECURITY|FUZZ)\)|libmmt_(tcpip|tmobile|tdicom|business_app|security|fuzz)(\.so|\.\*|\*|\.a)' "$1" \
        | grep -vE '^[0-9]+:[[:space:]]*#' | grep -vE '^[0-9]+:MMT_LAYOUT_'
}
check "sdk/Makefile names the plugin and engine libraries only in MMT_LAYOUT_*" \
    second_layout_list "${MK}"
cp "${MK}" "${WORK}/Makefile.second-list"
# shellcheck disable=SC2016  # a literal make recipe line
printf '\t@ install -m 0755 $(SDKLIB)/libmmt_tcpip.so.$(VERSION) $(MMT_PLUGINS)/libmmt_tcpip.so\n' >> "${WORK}/Makefile.second-list"
check_fail "a hard-coded plugin recipe line is caught" \
    second_layout_list "${WORK}/Makefile.second-list"
# Evaluated without ENABLESEC: rules/common.mk defines LIBSECURITY/LIBFUZZ
# only with it, but a build made with ENABLESEC=1 is installed and packaged
# by a plain `make install`/`make deb`, which must still lay out the engines.
# print_var <var> [make args...] — the value of one sdk/Makefile variable.
print_var() {
    local v="$1"; shift
    # shellcheck disable=SC2016  # $($*) is make syntax, not shell
    make -s -C "${REPO_ROOT}/sdk" "$@" --eval 'print-%: ; @echo $($*)' "print-${v}"
}
# engines_listed — both engines in the SONAME and dev-link lists, no ENABLESEC.
engines_listed() {
    local o
    o="$(print_var MMT_SONAME_LIBS)" && grep -qw libmmt_security <<< "${o}" && grep -qw libmmt_fuzz <<< "${o}" \
        && o="$(print_var MMT_LIB_LINKS)" && grep -qw 'libmmt_security\.so' <<< "${o}" && grep -qw 'libmmt_fuzz\.so' <<< "${o}"
}
# plugins_shared — install-fhs and the install manifest use the layout's plugins.
plugins_shared() {
    local p
    # shellcheck disable=SC2086  # one word per plugin
    p="$(print_var MMT_LAYOUT_PLUGINS)" && [ -n "${p}" ] \
        && [ "$(print_var FHS_PLUGINS)" = "${p}" ] \
        && [ "$(print_var MMT_PLUGIN_FILES)" = "$(printf '%s.so\n' ${p} | paste -sd' ')" ]
}
# fhs_engines_opt_in — install-fhs ships the engines only with ENABLESEC=1.
fhs_engines_opt_in() {
    ! print_var FHS_LIBS | grep -q libmmt_security && print_var FHS_LIBS ENABLESEC=1 | grep -qw libmmt_security
}
check "without ENABLESEC the SONAME/dev-link lists still name both engines" engines_listed
check "install, install-fhs and the packages share the plugin list" plugins_shared
check "install-fhs adds the engines only with ENABLESEC=1" fhs_engines_opt_in
# no_engine_in_main — evaluated, with and without ENABLESEC=1: the mmt-dpi
# package's libraries and the plugin list never hold an engine.
no_engine_in_main() {
    local v
    for v in MMT_PKG_LIBS MMT_LAYOUT_LIBS MMT_LAYOUT_PLUGINS; do
        print_var "${v}" | grep -Eq 'libmmt_(core|tcpip)' || [ "${v}" = MMT_LAYOUT_PLUGINS ] || return 1
        ! print_var "${v}" | grep -Eq 'libmmt_(security|fuzz)' || return 1
        ! print_var "${v}" ENABLESEC=1 | grep -Eq 'libmmt_(security|fuzz)' || return 1
    done
}
check "the mmt-dpi package and the plugin list hold no engine (with or without ENABLESEC)" no_engine_in_main

# --- 5. Versions and the installed examples ----------------------------------
SOV="$(sed -n 's/^SOVERSION[[:space:]]*:=[[:space:]]*//p' "${REPO_ROOT}/rules/common.mk")"
VER="$(sed -n 's/^VERSION[[:space:]]*:=[[:space:]]*//p' "${REPO_ROOT}/rules/common.mk")"
check "rules/common.mk defines SOVERSION" test -n "${SOV}"
# Issue #550: MMT_EXAMPLES_SRC listed three files that do not exist and a
# capture no rule copies. It must name exactly the programs in src/examples.
examples_listed() {
    local listed have
    listed="$(print_var MMT_EXAMPLES_SRC | tr ' ' '\n' | sed '/^$/d' | LC_ALL=C sort)"
    have="$(find "${REPO_ROOT}/src/examples" -maxdepth 1 -name '*.c' | sed 's|.*/||' | LC_ALL=C sort)"
    [ -n "${listed}" ] && [ "${listed}" = "${have}" ]
}
check "MMT_EXAMPLES_SRC names exactly the src/examples/*.c programs" examples_listed

# --- 5b. Distribution packaging (issue #475) -------------------------------
# The debian/changelog version is checked by scripts/validate-release-prep.sh
# (the version-agreement job and verify-tag), not here.
echo "--- distribution packaging: FHS install guards, debian/, source tarball ---"
check_fail "install-fhs refuses the /opt/mmt default directories" \
    make -C "${REPO_ROOT}/sdk" install-fhs
check_fail "install-fhs needs the plugin directory named too" \
    make -C "${REPO_ROOT}/sdk" MMT_LIB=/x/lib MMT_INC=/x/inc MMT_EXAMS=/x/ex install-fhs
check "debian/ is a 3.0 (quilt) source with an executable rules file" \
    bash -c "grep -qx '3.0 (quilt)' '${REPO_ROOT}/debian/source/format' && [ -x '${REPO_ROOT}/debian/rules' ]"
check "debian/copyright is machine-readable (DEP-5)" \
    bash -c "head -1 '${REPO_ROOT}/debian/copyright' | grep -q 'copyright-format/1.0'"
check "debian/control names the Montimage maintainer" \
    bash -c "grep -q '^Maintainer: .*<developer@montimage.eu>' '${REPO_ROOT}/debian/control'"
check "source tarball is reproducible and holds only tracked files" \
    bash -c "bash '${REPO_ROOT}/tools/ci/build-source-tarball.sh' --verify --out '${WORK}/tarball' >'${WORK}/tb.log' 2>&1 \
        && tar -tzf '${WORK}'/tarball/mmt-dpi-*.tar.gz | grep -q '/rules/common.mk\$' \
        && ! tar -tzf '${WORK}'/tarball/mmt-dpi-*.tar.gz | grep -qE '\.(o|so|a)\$'"

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

# Issue #536: every installed library carries the versioned SONAME, make
# install lays down its runtime link, and a consumer records that SONAME.
# dynamic_entries <TAG> <file> — the values of one dynamic tag, objdump -p.
dynamic_entries() { objdump -p "$2" 2>/dev/null | awk -v t="$1" '$1 == t { print $2 }'; }
for l in libmmt_core libmmt_tcpip libmmt_tmobile libmmt_business_app libmmt_tdicom; do
    check "${l}: SONAME is ${l}.so.${SOV}" \
        test "$(dynamic_entries SONAME "${LIB}/${l}.so.${VER}")" = "${l}.so.${SOV}"
    check "${l}: make install links ${l}.so.${SOV} -> ${l}.so.${VER}" \
        test "$(readlink "${LIB}/${l}.so.${SOV}")" = "${l}.so.${VER}"
done
check "a consumer's NEEDED entry names libmmt_core.so.${SOV}" \
    grep -qx "libmmt_core.so.${SOV}" <(dynamic_entries NEEDED "${WORK}/extract_all")

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

# Signal handling: the handler only flags the stop + breaks the pcap loop,
# and clean() runs once, from main. The live-capture path (pcap_loop) needs
# capture privileges, so its pcap_breakloop stays pinned by source text.
check "extract_all handler uses pcap_breakloop" \
    grep -q 'pcap_breakloop' "${REPO_ROOT}/src/examples/extract_all.c"

# Issue #526 (F-TEST-016): the offline path is exercised for real. extract_all
# reads a FIFO that this shell keeps open for writing (no EOF), so its
# capture loop only ends if the signal handler stops it. Sequence: wait
# until extract_all has opened the FIFO (pcap_open_offline runs after the
# handlers are installed), write the pcap header + one record, deliver the
# signal, write one more record (wakes the read that SA_RESTART resumed),
# then require exit status 0 within 10 s and exactly one clean() pass.
printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' \
    > "${WORK}/sig.hdr"
printf '\x01\x00\x00\x00\x00\x00\x00\x00\x3c\x00\x00\x00\x3c\x00\x00\x00' > "${WORK}/sig.rec"
head -c 60 /dev/zero >> "${WORK}/sig.rec"

# signal_stops_extract_all <SIGNAL> — the stop sequence above; prints the
# outcome and returns 0 only for status 0 + one "[info] Cleaning" line.
signal_stops_extract_all() {
    local sig="$1"
    local fifo="${WORK}/sig-${sig}.fifo" out="${WORK}/sig-${sig}.out"
    local wfd pid opened=0 status=0 cleans
    rm -f "${fifo}"
    mkfifo "${fifo}"
    exec {wfd}<>"${fifo}"   # read-write: opening never blocks; holds the writer side
    ( exec {wfd}>&-; cd "${WORK}" && LD_LIBRARY_PATH="${LIB}" exec "${WORK}/extract_all" -t "${fifo}" ) \
        >"${out}" 2>&1 &
    pid=$!
    for _ in $(seq 1 300); do
        if find "/proc/${pid}/fd" -lname "${fifo}" 2>/dev/null | grep -q .; then opened=1; break; fi
        kill -0 "${pid}" 2>/dev/null || break
        sleep 0.1
    done
    if [ "${opened}" -ne 1 ]; then
        echo "extract_all never opened ${fifo}"
        kill -KILL "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
        exec {wfd}>&-
        return 1
    fi
    cat "${WORK}/sig.hdr" "${WORK}/sig.rec" >&"${wfd}"
    sleep 1                      # record 1 processed; blocked reading record 2
    kill -s "${sig}" "${pid}"
    sleep 0.2
    cat "${WORK}/sig.rec" >&"${wfd}"
    for _ in $(seq 1 100); do
        kill -0 "${pid}" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "${pid}" 2>/dev/null; then
        kill -KILL "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
        exec {wfd}>&-
        echo "extract_all still running 10 s after ${sig}: the handler did not stop the capture loop"
        return 1
    fi
    wait "${pid}" || status=$?
    exec {wfd}>&-
    cleans="$(grep -c '^\[info\] Cleaning' "${out}" || true)"
    echo "extract_all after ${sig}: exit status ${status}, clean() passes ${cleans}"
    tail -5 "${out}"
    [ "${status}" -eq 0 ] && [ "${cleans}" -eq 1 ]
}
for sig in INT TERM; do
    check "extract_all stops its capture loop on SIG${sig}, exits 0, cleans once" \
        signal_stops_extract_all "${sig}"
done
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
# Issue #550: make install writes mmt-dpi.pc, records it, and its rpath lets
# a consumer built through pkg-config run with LD_LIBRARY_PATH unset.
PC2="${PREFIX2}/dpi/lib/pkgconfig/mmt-dpi.pc"
check "make install writes dpi/lib/pkgconfig/mmt-dpi.pc (0644) and records it" \
    bash -c "[ \"\$(stat -c %a '${PC2}')\" = 644 ] && grep -qx 'dpi/lib/pkgconfig' '${PREFIX2}/.mmt-dpi-manifest' && grep -qx 'dpi/lib/pkgconfig/mmt-dpi.pc' '${PREFIX2}/.mmt-dpi-manifest'"
if command -v pkg-config >/dev/null 2>&1; then
    pc2() { PKG_CONFIG_PATH="${PREFIX2}/dpi/lib/pkgconfig" pkg-config "$@" mmt-dpi; }
    check "pkg-config --cflags --libs mmt-dpi names the prefix, with its rpath" \
        bash -c "[ \"\$(PKG_CONFIG_PATH='${PREFIX2}/dpi/lib/pkgconfig' pkg-config --cflags --libs mmt-dpi | xargs)\" = '-I${INC} -L${LIB} -Wl,-rpath,${LIB} -lmmt_core' ]"
    check "pkg-config --modversion mmt-dpi is VERSION" test "$(pc2 --modversion)" = "${VER}"
    read -r -a PC_FLAGS <<< "$(pc2 --cflags --libs)"
    check "extract_all built through pkg-config runs with LD_LIBRARY_PATH unset" \
        bash -c "'${CC}' -O1 -o '${WORK}/extract_all_pc' '${PREFIX2}/examples/extract_all.c' \"\$@\" -lpcap \
            && cd '${WORK}' && env -u LD_LIBRARY_PATH '${WORK}/extract_all_pc' -t '${REPO_ROOT}/src/examples/google-fr.pcap' >/dev/null 2>&1" _ "${extra_cflags[@]}" "${PC_FLAGS[@]}"
else
    echo "  ○ pkg-config unavailable — mmt-dpi.pc contents not exercised"
fi
check "the manifest records the SONAME links (issue #536)" \
    bash -c "grep -qx 'dpi/lib/libmmt_core.so.${SOV}' '${PREFIX2}/.mmt-dpi-manifest' && grep -qx 'dpi/lib/libmmt_tcpip.so.${SOV}' '${PREFIX2}/.mmt-dpi-manifest'"
# Issue #536: upgrading in place over v1.9.1 or before. The stale library has
# SONAME libmmt_core.so, so if it survived, ldconfig would repoint the
# development link libmmt_core.so at it; install removes it first.
printf 'int mmt_stale_core;\n' > "${WORK}/stale.c"
"${CC}" -shared -fPIC -Wl,--soname=libmmt_core.so -o "${LIB}/libmmt_core.so.1.8.0" "${WORK}/stale.c"
check "make install over a stale earlier library succeeds" \
    "${SDKM[@]}" MMT_BASE="${PREFIX2}" "${STAGE[@]}" LDCONF=0 install
check "make install removes the stale earlier library" test ! -e "${LIB}/libmmt_core.so.1.8.0"
REAL_LDCONFIG="$(PATH="${PATH}:/sbin:/usr/sbin" command -v ldconfig || true)"
if [ -n "${REAL_LDCONFIG}" ]; then
    check "after ldconfig, libmmt_core.so still resolves to libmmt_core.so.${VER}" \
        bash -c "'${REAL_LDCONFIG}' -n '${LIB}' && [ \"\$(basename \"\$(readlink -f '${LIB}/libmmt_core.so')\")\" = libmmt_core.so.${VER} ]"
else
    echo "  - ldconfig not found: skipped the development-link check"
fi
DOC2="${PREFIX2}/dpi/share/doc/mmt-dpi"
check "make install lays down LICENSE and THIRD-PARTY-NOTICES (0644)" \
    bash -c "cmp -s '${REPO_ROOT}/LICENSE' '${DOC2}/LICENSE' && cmp -s '${REPO_ROOT}/THIRD-PARTY-NOTICES' '${DOC2}/THIRD-PARTY-NOTICES' && [ \"\$(stat -c %a '${DOC2}/LICENSE' '${DOC2}/THIRD-PARTY-NOTICES' | sort -u)\" = 644 ]"
check "the manifest records the licence files and their directories" \
    bash -c "for e in dpi/share dpi/share/doc dpi/share/doc/mmt-dpi dpi/share/doc/mmt-dpi/LICENSE dpi/share/doc/mmt-dpi/THIRD-PARTY-NOTICES; do grep -qx \"\$e\" '${PREFIX2}/.mmt-dpi-manifest' || exit 1; done"
mkdir -p "${PREFIX2}/probe"; : > "${PREFIX2}/probe/keep.conf"
: > "${PREFIX2}/examples/foreign.c"; : > "${PREFIX2}/dpi/include/foreign.h"
check "make uninstall succeeds" \
    "${SDKM[@]}" MMT_BASE="${PREFIX2}" "${STAGE[@]}" uninstall
check "uninstall removes the SDK files" \
    bash -c "[ ! -e '${PREFIX2}/dpi/lib' ] && [ ! -e '${PREFIX2}/plugins' ] && [ ! -e '${PREFIX2}/.mmt-dpi-manifest' ] && [ ! -e '${PREFIX2}/dpi/share' ] && [ \"\$(find '${PREFIX2}/examples' '${PREFIX2}/dpi' -type f | wc -l)\" -eq 2 ]"
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

# --- 7b. FHS install for distribution packages (issue #475) -----------------
# The build above baked ${PREFIX2}/plugins into plugins_engine.o, so that is
# the plugin directory install-fhs must be given; the other three are FHS-like
# paths staged under DESTDIR.
echo "--- make install-fhs: staged FHS layout ---"
FHS="${WORK}/fhs"
FHS_LIB=/usr/lib/mmt-test-triplet
FHS_VARS=(MMT_LIB="${FHS_LIB}" MMT_INC=/usr/include/mmt-dpi
          MMT_PLUGINS="${PREFIX2}/plugins" MMT_EXAMS=/usr/share/doc/libmmt-dpi-dev/examples)
check_fail "install-fhs refuses a plugin directory the build was not made for" \
    "${SDKM[@]}" MMT_LIB=/l MMT_INC=/i MMT_PLUGINS=/p MMT_EXAMS=/e DESTDIR="${WORK}/fhs-refused" install-fhs
check "refused install-fhs created nothing" test ! -e "${WORK}/fhs-refused"
check "install-fhs (real run) compiles nothing" \
    bash -c "! \"\$@\" DESTDIR='${FHS}' install-fhs 2>&1 | grep -q '\[COMPILE\]'" _ "${SDKM[@]}" "${FHS_VARS[@]}"
for l in libmmt_core libmmt_tcpip libmmt_tmobile libmmt_business_app libmmt_tdicom; do
    check "install-fhs: ${l}.so.${SOV} -> ${l}.so.${VER}, ${l}.so -> ${l}.so.${SOV}" \
        bash -c "[ -f '${FHS}${FHS_LIB}/${l}.so.${VER}' ] \
            && [ \"\$(readlink '${FHS}${FHS_LIB}/${l}.so.${SOV}')\" = '${l}.so.${VER}' ] \
            && [ \"\$(readlink '${FHS}${FHS_LIB}/${l}.so')\" = '${l}.so.${SOV}' ]"
done
for l in libmmt_tcpip libmmt_tmobile libmmt_business_app libmmt_tdicom; do
    check "install-fhs: plugin ${l}.so is a relative link to the installed library" \
        bash -c "t=\"\$(readlink '${FHS}${PREFIX2}/plugins/${l}.so')\" && [ \"\${t#/}\" = \"\$t\" ] \
            && [ \"\$(readlink -f '${FHS}${PREFIX2}/plugins/${l}.so')\" = \"\$(readlink -f '${FHS}${FHS_LIB}/${l}.so.${VER}')\" ]"
done
check "install-fhs: no static archive, no loader drop-in, no manifest" \
    bash -c "! ls '${FHS}${FHS_LIB}'/*.a >/dev/null 2>&1 && [ -z \"\$(find '${FHS}' -name 'mmt-dpi.conf' -o -name '.mmt-dpi-manifest')\" ]"
check "install-fhs: headers, examples and the pkg-config file" \
    bash -c "[ -f '${FHS}/usr/include/mmt-dpi/mmt_core.h' ] \
        && [ -f '${FHS}/usr/share/doc/libmmt-dpi-dev/examples/extract_all.c' ] \
        && grep -qx 'libdir=${FHS_LIB}' '${FHS}${FHS_LIB}/pkgconfig/mmt-dpi.pc' \
        && grep -qx 'Version: ${VER}' '${FHS}${FHS_LIB}/pkgconfig/mmt-dpi.pc'"
check "install-fhs: mmt-dpi.pc carries no rpath (the FHS libdir is on the loader path)" \
    grep -qx 'rpath=' "${FHS}${FHS_LIB}/pkgconfig/mmt-dpi.pc"
check "install-fhs: no group/world-writable file" \
    bash -c "[ -z \"\$(find '${FHS}' -type f -perm /022)\" ]"

# --- 8. Package split and licence files in the built .deb (issue #497) ------
# An ENABLESEC=1 `make deb` yields mmt-dpi and mmt-dpi-security; both list
# LICENSE and THIRD-PARTY-NOTICES, only the latter holds the engines and the
# GPL text. The .rpm counterpart is built by the release containers
# (tools/ci/build-package.sh); its spec fields are asserted in section 4b.
echo "--- package split (make deb, ENABLESEC=1) ---"
# The sanitizer/coverage profiles are skipped: their libraries NEED runtime
# sonames no package maps, and no profile switch happens without a clean.
if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    echo "  ○ SDK_BUILD_PROFILE=${SDK_BUILD_PROFILE} — package split checked in the default profile only"
elif ! command -v dpkg-deb >/dev/null 2>&1 || ! command -v objdump >/dev/null 2>&1; then
    echo "  ○ dpkg-deb/objdump unavailable — package split not built here"
elif ! pkg-config --exists libxml-2.0 2>/dev/null && [ ! -f /usr/include/libxml2/libxml/parser.h ]; then
    echo "  ○ libxml2 headers unavailable — the ENABLESEC=1 engines cannot build here"
else
    DEBLOG="${WORK}/deb.log"
    rm -f "${REPO_ROOT}"/sdk/mmt-dpi_*.deb "${REPO_ROOT}"/sdk/mmt-dpi-security_*.deb
    if "${SDKM[@]}" ENABLESEC=1 -j"${JOBS}" >"${DEBLOG}" 2>&1 \
        && "${SDKM[@]}" ENABLESEC=1 deb >>"${DEBLOG}" 2>&1; then
        ok "make deb (ENABLESEC=1) builds"
    else
        bad "make deb (ENABLESEC=1) builds"; tail -20 "${DEBLOG}" | sed 's/^/      /'
    fi
    shopt -s nullglob
    MAIN_DEB=("${REPO_ROOT}"/sdk/mmt-dpi_*.deb)
    SEC_DEB=("${REPO_ROOT}"/sdk/mmt-dpi-security_*.deb)
    shopt -u nullglob
    check "exactly one mmt-dpi and one mmt-dpi-security .deb" \
        test "${#MAIN_DEB[@]}" -eq 1 -a "${#SEC_DEB[@]}" -eq 1
    if [ "${#MAIN_DEB[@]}" -eq 1 ] && [ "${#SEC_DEB[@]}" -eq 1 ]; then
        check "check-package-split.sh: licence files listed, engines only in mmt-dpi-security" \
            bash "${REPO_ROOT}/tools/ci/check-package-split.sh" "${MAIN_DEB[0]}" "${SEC_DEB[0]}"
        dpkg-deb -c "${MAIN_DEB[0]}" > "${WORK}/main.list"
        dpkg-deb -c "${SEC_DEB[0]}" > "${WORK}/sec.list"
        for f in LICENSE THIRD-PARTY-NOTICES; do
            check "dpkg-deb -c mmt-dpi lists ${f}" \
                grep -q "/dpi/share/doc/mmt-dpi/${f}\$" "${WORK}/main.list"
            check "dpkg-deb -c mmt-dpi-security lists ${f}" \
                grep -q "/dpi/share/doc/mmt-dpi-security/${f}\$" "${WORK}/sec.list"
        done
        # Issue #536: each package carries its libraries' SONAME links.
        for l in libmmt_core libmmt_tcpip libmmt_tmobile libmmt_business_app libmmt_tdicom; do
            check "dpkg-deb -c mmt-dpi lists ${l}.so.${SOV} -> ${l}.so.${VER}" \
                grep -qF "/dpi/lib/${l}.so.${SOV} -> ${l}.so.${VER}" "${WORK}/main.list"
        done
        for l in libmmt_security libmmt_fuzz; do
            check "dpkg-deb -c mmt-dpi-security lists ${l}.so.${SOV} -> ${l}.so.${VER}" \
                grep -qF "/dpi/lib/${l}.so.${SOV} -> ${l}.so.${VER}" "${WORK}/sec.list"
        done
        # Issue #550: the package ships the `install` .pc and a link that puts
        # it on pkg-config's default search path.
        check "dpkg-deb -c mmt-dpi lists dpi/lib/pkgconfig/mmt-dpi.pc and the /usr/share/pkgconfig link" \
            bash -c "grep -q '/opt/mmt/dpi/lib/pkgconfig/mmt-dpi.pc\$' '${WORK}/main.list' && grep -qF './usr/share/pkgconfig/mmt-dpi.pc -> /opt/mmt/dpi/lib/pkgconfig/mmt-dpi.pc' '${WORK}/main.list'"
        check "mmt-dpi holds neither engine nor the fuzz headers" \
            bash -c "! grep -Eq 'libmmt_(security|fuzz)|/include/fuzz/' '${WORK}/main.list'"
        check "mmt-dpi-security depends on exactly its own mmt-dpi version" \
            bash -c "dpkg-deb -f '${SEC_DEB[0]}' Depends | tr ',' '\\n' | grep -qx \" *mmt-dpi (= \$(dpkg-deb -f '${SEC_DEB[0]}' Version))\""
        check "mmt-dpi-security replaces the files a pre-split mmt-dpi owned" \
            bash -c "[ \"\$(dpkg-deb -f '${SEC_DEB[0]}' Replaces)\" = mmt-dpi ]"
        check "mmt-dpi does not depend on mmt-dpi-security" \
            bash -c "! dpkg-deb -f '${MAIN_DEB[0]}' Depends | grep -q mmt-dpi"
        for d in "${MAIN_DEB[0]}" "${SEC_DEB[0]}"; do
            check "check-package-deps.sh --verify-package $(basename "${d}")" \
                bash "${REPO_ROOT}/tools/ci/check-package-deps.sh" --verify-package "${d}"
        done
    fi
    rm -f "${REPO_ROOT}"/sdk/mmt-dpi_*.deb "${REPO_ROOT}"/sdk/mmt-dpi-security_*.deb
fi

echo
if [ "${FAIL}" -gt 0 ]; then
    echo "✗ installer suite: ${FAIL} check(s) failed (${PASS} passed)" >&2
    exit 1
fi
echo "✓ installer suite: all ${PASS} checks passed"
