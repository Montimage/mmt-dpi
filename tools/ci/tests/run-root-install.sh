#!/usr/bin/env bash
#
# run-root-install.sh — the source root-install round trip (issue #485,
# F-CI-104 / F-UX-007 / F-SEC-005 / F-CI-116).
#
# Runs as root inside a DISPOSABLE container (the `root-install` job in
# .github/workflows/c-cpp.yml runs it in the pinned ubuntu:24.04 image). It
# writes /etc/ld.so.conf.d and runs ldconfig, so it refuses to run anywhere
# else — never on a developer host.
#
# Asserts, in order:
#   1. after a build, `make -n install` prints no compiler invocation, and the
#      real root install compiles nothing either (install
#      consumes the built artifacts; root never compiles);
#   2. `make -C sdk MMT_BASE=<prefix> install` as root writes the loader
#      drop-in naming <prefix>/dpi/lib and `ldconfig -p` lists libmmt_core;
#   3. the installed consumer passes with LD_LIBRARY_PATH unset
#      (run-installed-consumer.sh --root-install);
#   4. `make -C sdk MMT_BASE=<prefix> uninstall` leaves neither <prefix> nor
#      the drop-in, and ldconfig forgets libmmt_core;
#   5. LDCONF=0 opts a root install out of loader registration.
#
# Usage: run-root-install.sh [--install-deps] [--prefix DIR]
#   --install-deps   install the build dependencies first
#                    (tools/ci/install-build-deps.sh ubuntu-24.04 deb)
#   --prefix DIR     install prefix (default /opt/mmt)
#
# Exit: 0 = every check passed; 1 = a check failed; 2 = refused / usage.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
PREFIX="/opt/mmt"
INSTALL_DEPS=0
DROPIN="/etc/ld.so.conf.d/mmt-dpi.conf"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

while [ $# -gt 0 ]; do
    case "$1" in
        --install-deps) INSTALL_DEPS=1; shift ;;
        --prefix)       PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        -h|--help)      sed -n '2,28p' "$0"; exit 0 ;;
        *) echo "✗ unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "✗ run-root-install.sh must run as root (inside a disposable container)" >&2
    exit 2
fi
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then
    echo "✗ refusing to write /etc/ld.so.conf.d outside a container" >&2
    exit 2
fi

PASS=0
FAIL=0
ok()  { echo "  ✓ $1"; PASS=$((PASS + 1)); }
bad() { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }
loader_lists_core() { ldconfig -p | grep -c libmmt_core || true; }

if [ "${INSTALL_DEPS}" -eq 1 ]; then
    bash "${REPO_ROOT}/tools/ci/install-build-deps.sh" ubuntu-24.04 deb >/dev/null
fi
# The checkout is bind-mounted and owned by another uid: let git read it so
# rules/common.mk can stamp GIT_VERSION.
git config --global --add safe.directory "${REPO_ROOT}" 2>/dev/null || true

SDK="${REPO_ROOT}/sdk"
LOG="$(mktemp)"
trap 'rm -f "${LOG}"' EXIT

echo "=== root-install round trip (issue #485) — prefix ${PREFIX} ==="
make -C "${SDK}" clean >/dev/null 2>&1 || true
if ! make -C "${SDK}" MMT_BASE="${PREFIX}" -j"${JOBS}" >"${LOG}" 2>&1; then
    echo "✗ SDK build failed — last lines:" >&2; tail -20 "${LOG}" >&2; exit 1
fi

# 1. install never compiles.
if make -n -C "${SDK}" MMT_BASE="${PREFIX}" install 2>&1 \
        | grep -E '\[COMPILE\]|(^|[[:space:]/])(gcc|g\+\+|cc|c\+\+|clang)[[:space:]]' >"${LOG}"; then
    bad "make -n install prints no compiler invocation"; sed 's/^/      /' "${LOG}" | head -5
else
    ok "make -n install prints no compiler invocation"
fi

# 2. root install registers the loader.
if make -C "${SDK}" MMT_BASE="${PREFIX}" install >"${LOG}" 2>&1; then
    ok "make install as root succeeds"
else
    bad "make install as root succeeds"; tail -10 "${LOG}" | sed 's/^/      /'
fi
if grep -q '\[COMPILE\]' "${LOG}"; then
    bad "root make install compiled nothing"
else
    ok "root make install compiled nothing"
fi
if [ -f "${DROPIN}" ] && [ "$(cat "${DROPIN}")" = "${PREFIX}/dpi/lib" ]; then
    ok "${DROPIN} names ${PREFIX}/dpi/lib"
else
    bad "${DROPIN} names ${PREFIX}/dpi/lib"
fi
if [ "$(loader_lists_core)" -ge 1 ]; then
    ok "ldconfig -p lists libmmt_core"
else
    bad "ldconfig -p lists libmmt_core"
fi

# 3. consumer resolves the SDK through the loader alone.
if env -u LD_LIBRARY_PATH bash "${SCRIPT_DIR}/run-installed-consumer.sh" \
        --prefix "${PREFIX}" --no-engines --root-install --distro root-install \
        >"${LOG}" 2>&1; then
    ok "installed consumer passes with LD_LIBRARY_PATH unset"
else
    bad "installed consumer passes with LD_LIBRARY_PATH unset"; tail -10 "${LOG}" | sed 's/^/      /'
fi

# 4. uninstall leaves nothing behind.
if make -C "${SDK}" MMT_BASE="${PREFIX}" uninstall >"${LOG}" 2>&1; then
    ok "make uninstall succeeds"
else
    bad "make uninstall succeeds"; tail -10 "${LOG}" | sed 's/^/      /'
fi
# shellcheck disable=SC2012  # the AC's own probe, verbatim
left="$(ls "${PREFIX}" "${DROPIN}" 2>/dev/null || true)"
if [ -z "${left}" ]; then
    ok "uninstall leaves neither ${PREFIX} nor ${DROPIN}"
else
    bad "uninstall leaves neither ${PREFIX} nor ${DROPIN}"; echo "      ${left}"
fi
if [ "$(loader_lists_core)" -eq 0 ]; then
    ok "ldconfig no longer lists libmmt_core"
else
    bad "ldconfig no longer lists libmmt_core"
fi

# 5. LDCONF=0 opt-out.
make -C "${SDK}" MMT_BASE="${PREFIX}" LDCONF=0 install >"${LOG}" 2>&1 || true
if [ -d "${PREFIX}/dpi/lib" ] && [ ! -e "${DROPIN}" ]; then
    ok "LDCONF=0 installs without writing ${DROPIN}"
else
    bad "LDCONF=0 installs without writing ${DROPIN}"
fi
make -C "${SDK}" MMT_BASE="${PREFIX}" uninstall >/dev/null 2>&1 || true
make -C "${SDK}" clean >/dev/null 2>&1 || true

echo
if [ "${FAIL}" -gt 0 ]; then
    echo "✗ root-install round trip: ${FAIL} check(s) failed (${PASS} passed)" >&2
    exit 1
fi
echo "✓ root-install round trip: all ${PASS} checks passed"
