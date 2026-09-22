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
#   2. consumer builds against the packaged headers/libraries alone;
#   3. per fixture: registry initializes before the handler, every required
#      protocol resolves (one name per plugin — a plugin that failed to
#      dlopen cannot hide), the capture classifies to its known label, and
#      the SDK shuts down cleanly;
#   4. every log line carries the package filename, SHA-256, distro and
#      architecture so a failure is attributable to one matrix row.
#
# Usage:
#   run-installed-consumer.sh [--prefix DIR] [--package FILE] \
#       [--distro ID] [--arch ARCH] [--expect-engines|--no-engines]
#
#   --prefix DIR       install root to test (default /opt/mmt — the package's
#                      own layout; the unit suite passes a throwaway prefix)
#   --package FILE     package file for logging; '-' or omitted = none
#   --distro ID        distro tag recorded in the logs (default unknown)
#   --arch ARCH        architecture tag (default: uname -m)
#   --expect-engines   require libmmt_fuzz/libmmt_security (default: on —
#                      release packages are always built ENABLESEC=1)
#   --no-engines       skip the engine check (non-ENABLESEC installs)
#
# Env:
#   CC                 compiler (default gcc)
#   EXTRA_CFLAGS       extra flags for the consumer compile (sanitizer runs)
#   REQUIRED_PROTOS    override the required-protocol CSV
#   FIXTURES           override the fixture list (tests, exotic layouts)
#   PCAP_DIR           override the vendored-pcap directory
#
# Exit: 0 = every check passed; 1 = a check failed; 2 = usage error.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CONSUMER_SRC="${SCRIPT_DIR}/installed_consumer.c"
# Overridable for tests and exotic layouts; production runs use the vendored
# defaults beside this script.
FIXTURES="${FIXTURES:-${SCRIPT_DIR}/fixtures.txt}"
PCAP_DIR="${PCAP_DIR:-${REPO_ROOT}/tools/phase0/ci/pcaps}"

PREFIX="/opt/mmt"
PACKAGE="-"
DISTRO="unknown"
ARCH="$(uname -m)"
EXPECT_ENGINES=1

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)         PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --package)        PACKAGE="${2:?--package needs a file or -}"; shift 2 ;;
        --distro)         DISTRO="${2:?--distro needs an id}"; shift 2 ;;
        --arch)           ARCH="${2:?--arch needs a value}"; shift 2 ;;
        --expect-engines) EXPECT_ENGINES=1; shift ;;
        --no-engines)     EXPECT_ENGINES=0; shift ;;
        -h|--help)
            sed -n '2,40p' "$0"; exit 0 ;;
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

say "prefix=${PREFIX} engines_expected=${EXPECT_ENGINES}"

LIB="${PREFIX}/dpi/lib"
INC="${PREFIX}/dpi/include"
PLUGINS="${PREFIX}/plugins"

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

# --- 2. compile the consumer against the packaged SDK -------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${WORK}/run"   # neutral CWD: './plugins' must not shadow <prefix>/plugins
BIN="${WORK}/installed_consumer"

read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
if ! "${CC}" "${extra_cflags[@]}" -O2 -Wall -o "${BIN}" "${CONSUMER_SRC}" \
        -I "${INC}" -L "${LIB}" -lmmt_core -ldl -lpcap; then
    fail "consumer does not compile against packaged headers/libraries"
fi
say "consumer compiled against ${INC} + ${LIB}"

# --- 3. replay each fixture ----------------------------------------------------
failures=0
while read -r rel expected _rest; do
    case "${rel}" in ''|'#'*) continue ;; esac
    if (cd "${WORK}/run" && LD_LIBRARY_PATH="${LIB}" "${BIN}" \
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
say "OK — installed SDK consumer passed on every fixture"
