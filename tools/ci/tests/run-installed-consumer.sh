#!/usr/bin/env bash
#
# run-installed-consumer.sh — execute a packaged-SDK consumer end to end
# (issue #374, F-CI-002).
#
# Compiles tools/ci/tests/installed_consumer.c against ONLY the installed
# package payload (<prefix>/dpi/include + <prefix>/dpi/lib) and replays every
# vendored fixture listed in tools/ci/tests/fixtures.txt (captures vendored
# under tools/phase0/ci/pcaps/) through the plugins installed under
# <prefix>/plugins. One leg of every release distro/architecture matrix row —
# build-package.sh invokes it right after the package install smoke-test.
#
# Asserts, in order:
#   1. installed layout — core lib, headers, the four protocol plugins and
#      (with --expect-engines) the ENABLESEC=1 engines all exist;
#   2. consumer builds against the packaged headers/libraries alone, with
#      the flags `pkg-config --cflags --libs mmt-dpi` prints (issue #550):
#      the install's own mmt-dpi.pc (<libdir>/pkgconfig first on
#      PKG_CONFIG_PATH) must be found and must name the directories under test;
#   3. per fixture: registry initializes before the handler, every required
#      protocol resolves (one name per plugin — a plugin that failed to
#      dlopen cannot hide), the capture classifies to its known label, and
#      the SDK shuts down cleanly;
#   4. run from a directory holding plugins/evil.so (hostile_plugin.c), the
#      consumer still passes and evil.so is never loaded (issue #503);
#   5. every log line carries the package filename, SHA-256, distro and
#      architecture so a failure is attributable to one matrix row.
#
# With --root-install (issue #485, F-CI-104) the run is the root-install leg:
# the prefix must be registered with the dynamic loader — the drop-in names
# <prefix>/dpi/lib and `ldconfig -p` resolves libmmt_core.so there — and every
# fixture replays with LD_LIBRARY_PATH unset, so the consumer can only find
# the SDK through the loader cache a root `make install` wrote.
#
# Usage:
#   run-installed-consumer.sh [--prefix DIR] [--package FILE] \
#       [--distro ID] [--arch ARCH] [--expect-engines|--no-engines]
#
#   --prefix DIR       install root to test (default /opt/mmt — the package's
#                      own layout; the unit suite passes a throwaway prefix)
#   --libdir DIR       library directory   (default <prefix>/dpi/lib)
#   --includedir DIR   header directory    (default <prefix>/dpi/include)
#   --plugindir DIR    plugin directory    (default <prefix>/plugins)
#                      The three overrides describe an FHS install (issue #475,
#                      `make install-fhs`, e.g. the Debian package) whose
#                      layout is not rooted under one prefix.
#   --package FILE     package file for logging; '-' or omitted = none
#   --distro ID        distro tag recorded in the logs (default unknown)
#   --arch ARCH        architecture tag (default: uname -m)
#   --expect-engines   require libmmt_fuzz/libmmt_security (default: on —
#                      release packages are always built ENABLESEC=1)
#   --no-engines       skip the engine check (non-ENABLESEC installs)
#   --root-install     require loader registration; replay with
#                      LD_LIBRARY_PATH unset (root-install leg)
#
# Env:
#   CC                 compiler (default gcc)
#   PKG_CONFIG         pkg-config binary (default pkg-config)
#   EXTRA_CFLAGS       extra flags for the consumer compile (sanitizer runs)
#   REQUIRED_PROTOS    override the required-protocol CSV
#   FIXTURES           override the fixture list (tests, exotic layouts)
#   PCAP_DIR           override the vendored-pcap directory
#   LDCONF_FILE        loader drop-in --root-install checks
#                      (default /etc/ld.so.conf.d/mmt-dpi.conf)
#
# Exit: 0 = every check passed; 1 = a check failed; 2 = usage error.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CONSUMER_SRC="${SCRIPT_DIR}/installed_consumer.c"
HOSTILE_SRC="${SCRIPT_DIR}/hostile_plugin.c"
# Overridable for tests and exotic layouts; production runs use the vendored
# defaults beside this script.
FIXTURES="${FIXTURES:-${SCRIPT_DIR}/fixtures.txt}"
PCAP_DIR="${PCAP_DIR:-${REPO_ROOT}/tools/phase0/ci/pcaps}"

PREFIX="/opt/mmt"
LIB_OVERRIDE=""
INC_OVERRIDE=""
PLUGINS_OVERRIDE=""
PACKAGE="-"
DISTRO="unknown"
ARCH="$(uname -m)"
EXPECT_ENGINES=1
ROOT_INSTALL=0
LDCONF_FILE="${LDCONF_FILE:-/etc/ld.so.conf.d/mmt-dpi.conf}"

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)         PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --libdir)         LIB_OVERRIDE="${2:?--libdir needs a directory}"; shift 2 ;;
        --includedir)     INC_OVERRIDE="${2:?--includedir needs a directory}"; shift 2 ;;
        --plugindir)      PLUGINS_OVERRIDE="${2:?--plugindir needs a directory}"; shift 2 ;;
        --package)        PACKAGE="${2:?--package needs a file or -}"; shift 2 ;;
        --distro)         DISTRO="${2:?--distro needs an id}"; shift 2 ;;
        --arch)           ARCH="${2:?--arch needs a value}"; shift 2 ;;
        --expect-engines) EXPECT_ENGINES=1; shift ;;
        --no-engines)     EXPECT_ENGINES=0; shift ;;
        --root-install)   ROOT_INSTALL=1; shift ;;
        -h|--help)
            sed -n '2,66p' "$0"; exit 0 ;;
        *) echo "✗ unknown argument: $1" >&2; exit 2 ;;
    esac
done

CC="${CC:-gcc}"

# One protocol name per shipped plugin: a plugin that failed to dlopen (bad
# soname, missing dir entry) leaves its protocols unregistered, so this list
# is the functional check behind "required plugins present".
#   tcp/udp/ip/http/ftp/dns            -> libmmt_tcpip
#   s1ap/ngap/gtpv2/diameter/nas_5g    -> libmmt_tmobile
#   dicom                              -> libmmt_tdicom
#   lps_data                           -> libmmt_business_app
REQUIRED_PROTOS="${REQUIRED_PROTOS:-tcp,udp,ip,http,ftp,dns,s1ap,ngap,gtpv2,diameter,nas_5g,dicom,lps_data}"

# --- provenance log line -----------------------------------------------------
PKG_NAME="-"
PKG_SHA="-"
if [ "${PACKAGE}" != "-" ]; then
    if [ ! -f "${PACKAGE}" ]; then
        echo "✗ package file not found: ${PACKAGE}" >&2
        exit 1
    fi
    PKG_NAME="$(basename "${PACKAGE}")"
    PKG_SHA="$(sha256sum "${PACKAGE}" | awk '{print $1}')"
fi

say()  { printf 'installed-consumer[%s|%s|%s|%s] %s\n' \
            "${PKG_NAME}" "${PKG_SHA:0:12}" "${DISTRO}" "${ARCH}" "$*"; }
fail() { say "✗ $*"; exit 1; }

say "prefix=${PREFIX} engines_expected=${EXPECT_ENGINES} root_install=${ROOT_INSTALL}"

LIB="${LIB_OVERRIDE:-${PREFIX}/dpi/lib}"
INC="${INC_OVERRIDE:-${PREFIX}/dpi/include}"
PLUGINS="${PLUGINS_OVERRIDE:-${PREFIX}/plugins}"

# --- 1. installed layout ------------------------------------------------------
[ -d "${INC}" ] || fail "packaged headers missing: ${INC}"
[ -f "${INC}/mmt_core.h" ] || fail "mmt_core.h missing under ${INC}"
[ -e "${LIB}/libmmt_core.so" ] || fail "libmmt_core.so missing under ${LIB}"
for so in libmmt_tcpip libmmt_tmobile libmmt_tdicom libmmt_business_app; do
    ls "${LIB}/${so}".so.* >/dev/null 2>&1 \
        || fail "installed library missing: ${LIB}/${so}.so.*"
done
for plugin in libmmt_tcpip libmmt_tmobile libmmt_tdicom libmmt_business_app; do
    [ -e "${PLUGINS}/${plugin}.so" ] \
        || fail "required plugin missing: ${PLUGINS}/${plugin}.so"
done
if [ "${EXPECT_ENGINES}" -eq 1 ]; then
    for engine in libmmt_fuzz libmmt_security; do
        ls "${LIB}/${engine}".so.* >/dev/null 2>&1 \
            || fail "ENABLESEC engine missing from package: ${LIB}/${engine}.so.*"
    done
fi
[ -f "${FIXTURES}" ] || fail "fixture list missing: ${FIXTURES}"
while read -r rel expected _rest; do
    case "${rel}" in ''|'#'*) continue ;; esac
    [ -f "${PCAP_DIR}/${rel}" ] || fail "fixture pcap missing: ${PCAP_DIR}/${rel}"
done < "${FIXTURES}"
say "layout OK — libs, plugins, headers and fixtures present"

# --- 1b. root-install leg: the loader must already know the prefix -----------
if [ "${ROOT_INSTALL}" -eq 1 ]; then
    [ -f "${LDCONF_FILE}" ] \
        || fail "loader drop-in missing: ${LDCONF_FILE} (root install did not register ${LIB})"
    grep -qxF "${LIB}" "${LDCONF_FILE}" \
        || fail "loader drop-in ${LDCONF_FILE} does not name ${LIB}"
    LDCONFIG_BIN="$(command -v ldconfig 2>/dev/null || echo /sbin/ldconfig)"
    "${LDCONFIG_BIN}" -p 2>/dev/null | grep -F 'libmmt_core.so' | grep -qF "=> ${LIB}/" \
        || fail "ldconfig -p does not resolve libmmt_core.so under ${LIB}"
    say "loader OK — ${LDCONF_FILE} registers ${LIB}; ldconfig -p resolves libmmt_core.so"
fi

# --- 2. compile the consumer against the packaged SDK -------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${WORK}/run"   # neutral CWD: './plugins' must not shadow <prefix>/plugins
BIN="${WORK}/installed_consumer"

# Through pkg-config (issue #550): every install route ships mmt-dpi.pc, and
# it must describe this install, not another one on the default search path.
PKG_CONFIG="${PKG_CONFIG:-pkg-config}"
command -v "${PKG_CONFIG}" >/dev/null 2>&1 \
    || fail "${PKG_CONFIG} not found — the consumer is built through mmt-dpi.pc"
export PKG_CONFIG_PATH="${LIB}/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
"${PKG_CONFIG}" --exists mmt-dpi \
    || fail "mmt-dpi.pc not found (${LIB}/pkgconfig, then the default search path)"
for var in libdir:"${LIB}" includedir:"${INC}" plugindir:"${PLUGINS}"; do
    got="$("${PKG_CONFIG}" --variable="${var%%:*}" mmt-dpi)"
    [ "${got}" = "${var#*:}" ] \
        || fail "mmt-dpi.pc ${var%%:*}=${got}, not the install under test ${var#*:}"
done
read -r -a pc_flags <<< "$("${PKG_CONFIG}" --cflags --libs mmt-dpi)"
# The root-install leg proves the loader cache: drop the rpath an /opt
# prefix's .pc carries, or the consumer would find the SDK through it.
if [ "${ROOT_INSTALL}" -eq 1 ]; then
    kept=()
    for f in "${pc_flags[@]}"; do
        case "${f}" in -Wl,-rpath,*) ;; *) kept+=("${f}") ;; esac
    done
    pc_flags=("${kept[@]}")
fi
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
if ! "${CC}" "${extra_cflags[@]}" -O2 -Wall -o "${BIN}" "${CONSUMER_SRC}" \
        "${pc_flags[@]}" -lpcap; then
    fail "consumer does not compile with the flags of mmt-dpi.pc: ${pc_flags[*]}"
fi
say "consumer compiled through pkg-config: ${pc_flags[*]}"

# --- 3. replay each fixture ----------------------------------------------------
failures=0
while read -r rel expected _rest; do
    case "${rel}" in ''|'#'*) continue ;; esac
    # The root-install leg must resolve the SDK through the loader cache alone.
    if [ "${ROOT_INSTALL}" -eq 1 ]; then
        run_env=(env -u LD_LIBRARY_PATH)
    else
        run_env=(env LD_LIBRARY_PATH="${LIB}")
    fi
    if (cd "${WORK}/run" && "${run_env[@]}" "${BIN}" \
            "${PCAP_DIR}/${rel}" "${expected}" "${REQUIRED_PROTOS}") \
            >"${WORK}/out.log" 2>"${WORK}/err.log"; then
        say "✓ ${rel} -> ${expected} :: $(tail -1 "${WORK}/out.log")"
    else
        rc=$?
        say "✗ ${rel} (expected ${expected}) failed rc=${rc}"
        cat "${WORK}/out.log" "${WORK}/err.log" > "${WORK}/fail.log" 2>/dev/null || true
        head -12 "${WORK}/fail.log" | while IFS= read -r line; do say "  ${line}"; done
        failures=$((failures + 1))
    fi
done < "${FIXTURES}"

if [ "${failures}" -gt 0 ]; then
    fail "${failures} fixture(s) failed"
fi

# --- 4. a hostile working directory cannot inject a plugin (issue #503) -------
# plugins/evil.so in the consumer's CWD creates SENTINEL from its constructor
# the moment anything dlopen()s it; the SDK loads only <prefix>/plugins.
HOSTILE="${WORK}/hostile"
SENTINEL="${WORK}/hostile-plugin-loaded"
mkdir -p "${HOSTILE}/plugins"
if ! "${CC}" -O2 -Wall -fPIC -shared -DHOSTILE_SENTINEL="\"${SENTINEL}\"" \
        -o "${HOSTILE}/plugins/evil.so" "${HOSTILE_SRC}"; then
    fail "hostile plugin does not compile"
fi
read -r rel expected _rest < <(grep -Ev '^[[:space:]]*(#|$)' "${FIXTURES}")
if [ "${ROOT_INSTALL}" -eq 1 ]; then
    run_env=(env -u LD_LIBRARY_PATH -u MMT_DPI_PLUGINS_DIR)
else
    run_env=(env -u MMT_DPI_PLUGINS_DIR LD_LIBRARY_PATH="${LIB}")
fi
if ! (cd "${HOSTILE}" && "${run_env[@]}" "${BIN}" \
        "${PCAP_DIR}/${rel}" "${expected}" "${REQUIRED_PROTOS}") \
        >"${WORK}/out.log" 2>"${WORK}/err.log"; then
    head -12 "${WORK}/err.log" | while IFS= read -r line; do say "  ${line}"; done
    fail "consumer run from a directory holding plugins/evil.so failed"
fi
[ ! -e "${SENTINEL}" ] \
    || fail "plugins/evil.so in the working directory was loaded (sentinel created)"
say "✓ ./plugins/evil.so in the working directory was not loaded"
say "OK — installed SDK consumer passed on every fixture"
