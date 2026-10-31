#!/usr/bin/env bash
#
# check-static-link.sh — an installed SDK supports the downstream STATIC_LINK
# mode (issue #675).
#
# 5Greplay and NetworkFuzzer have an optional `make STATIC_LINK=1` that links
# the core archive into their executable (their Makefile:37-43):
#
#   -Wl,--export-dynamic ... -l:libmmt_core.a -l:libmmt_tcpip.so \
#       -l:libmmt_tmobile.a ... -l:libmmt_tcpip.a
#
# A static consumer holds only the libmmt_core.a members its own references
# pull, and --export-dynamic makes their default-visibility (MMTAPI) symbols
# the core that libmmt_tcpip.so and every plugin dlopen()ed from the plugin
# directory bind to. A plugin that imports a core function no pulled member
# defines breaks that mode: the link fails on libmmt_tcpip.so's unresolved
# references, or the plugin fails to load at run time with "undefined
# symbol". After #533 that was libmmt_tcpip's mmt_utils.h helpers (hex2int,
# str_get_indexes_n, ...) and libmmt_tmobile's logger entry points; the core
# now anchors them (src/mmt_core/src/mmt_init.c).
#
# The check builds a minimal consumer that calls only the engine lifecycle
# (init_extraction, mmt_init_handler, mmt_close_handler, close_extraction)
# and, against PREFIX's installed SDK:
#   1. links it with the downstream library order, --no-as-needed so the
#      linker checks libmmt_tcpip.so's undefined references (a toolchain
#      without the Ubuntu --as-needed default, or a consumer calling an
#      exported tcpip function, does the same);
#   2. requires every core symbol a plugin under PREFIX/plugins imports to be
#      defined in the executable's dynamic symbol table;
#   3. runs it: every plugin must load (no "undefined symbol" on stderr) and
#      the lifecycle must succeed.
# Profile flags (asan, ubsan, tsan, coverage) are read from the archive, as
# tools/phase0/tests/static_core_link.sh does for the harnesses.
#
# Usage: tools/ci/check-static-link.sh PREFIX
#   PREFIX is an MMT_BASE an SDK was installed into (make -C sdk install).
# Environment: CC (default gcc).
# Exit codes: 0 = static link works, 1 = it does not, 2 = helper broken
#             (bad argument, missing archive or tool).
set -uo pipefail

PREFIX="${1:-}"
if [ -z "${PREFIX}" ] || [ "$#" -ne 1 ]; then
    echo "usage: check-static-link.sh PREFIX" >&2
    exit 2
fi
LIB="${PREFIX}/dpi/lib"
INC="${PREFIX}/dpi/include"
PLUGINS="${PREFIX}/plugins"
CC="${CC:-gcc}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

for f in "${LIB}/libmmt_core.a" "${LIB}/libmmt_core.so" "${LIB}/libmmt_tcpip.so" \
         "${LIB}/libmmt_tcpip.a" "${LIB}/libmmt_tmobile.a" "${INC}/mmt_core.h"; do
    if [ ! -e "${f}" ]; then
        echo "✗ check-static-link: ${f} not found — install an SDK into ${PREFIX} first" >&2
        exit 2
    fi
done
for t in "${CC}" nm; do
    if ! command -v "${t}" >/dev/null 2>&1; then
        echo "✗ check-static-link: ${t} not found" >&2
        exit 2
    fi
done

# shellcheck source=tools/phase0/tests/static_core_link.sh
. "${REPO_ROOT}/tools/phase0/tests/static_core_link.sh"
_mmt_static_profile_flags "${LIB}/libmmt_core.a"
PROFILE_FLAGS=(${_MMT_STATIC_PROFILE_FLAGS[@]+"${_MMT_STATIC_PROFILE_FLAGS[@]}"})

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mmt-static-link.XXXXXX")"
trap 'rm -rf -- "${WORK}"' EXIT

cat > "${WORK}/consumer.c" <<'EOF'
#include <stdio.h>
#include "mmt_core.h"

int main(void)
{
    if (!init_extraction())
        return 1;
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, NULL);
    if (h == NULL)
        return 1;
    mmt_close_handler(h);
    close_extraction();
    puts("static-link consumer: ok");
    return 0;
}
EOF

FAIL=0
echo "=== static link (issue #675): ${LIB} ==="

if ! "${CC}" -c -I"${INC}" ${PROFILE_FLAGS[@]+"${PROFILE_FLAGS[@]}"} \
        -o "${WORK}/consumer.o" "${WORK}/consumer.c" 2>"${WORK}/cc.log"; then
    sed 's/^/    /' "${WORK}/cc.log" >&2
    echo "✗ check-static-link: the consumer does not compile" >&2
    exit 2
fi

# 1. Link in the downstream order.
if "${CC}" -Wl,--no-as-needed -Wl,--export-dynamic -o "${WORK}/consumer" \
        "${WORK}/consumer.o" -L"${LIB}" \
        -l:libmmt_core.a -l:libmmt_tcpip.so -l:libmmt_tmobile.a -l:libmmt_tcpip.a \
        -ldl -lpthread -lm ${PROFILE_FLAGS[@]+"${PROFILE_FLAGS[@]}"} \
        >"${WORK}/ld.log" 2>&1; then
    echo "  ✓ links with libmmt_core.a before libmmt_tcpip.so (--export-dynamic)"
else
    sed 's/^/    /' "${WORK}/ld.log"
    echo "  ✗ the STATIC_LINK order does not link"
    exit 1
fi

# 2. Every core symbol a plugin imports is in the executable.
nm -D --defined-only "${LIB}/libmmt_core.so" | awk '{print $3}' | sort -u > "${WORK}/core.txt"
nm -D --defined-only "${WORK}/consumer" | awk '{print $3}' | sort -u > "${WORK}/exe.txt"
nplugins=0
for so in "${PLUGINS}"/*.so; do
    [ -e "${so}" ] || continue
    nplugins=$((nplugins + 1))
    missing="$(nm -D --undefined-only "${so}" | awk '{print $2}' | sed 's/@.*//' | sort -u \
               | comm -12 - "${WORK}/core.txt" | comm -23 - "${WORK}/exe.txt" | tr '\n' ' ')"
    if [ -n "${missing}" ]; then
        echo "  ✗ $(basename "${so}") imports core symbols the static executable lacks: ${missing}"
        FAIL=1
    else
        echo "  ✓ $(basename "${so}"): every imported core symbol is in the executable"
    fi
done
if [ "${nplugins}" -eq 0 ]; then
    echo "✗ check-static-link: no plugin found under ${PLUGINS}" >&2
    exit 2
fi

# 3. Run it: the plugins load and the lifecycle succeeds. It runs from WORK
# because the engine scans ./plugins before the installed plugin directory.
if (cd "${WORK}" && LD_LIBRARY_PATH="${LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" ./consumer) \
        >"${WORK}/run.out" 2>"${WORK}/run.err" \
        && grep -q 'static-link consumer: ok' "${WORK}/run.out" \
        && ! grep -q 'undefined symbol' "${WORK}/run.err"; then
    echo "  ✓ runs: every plugin loads, init_extraction() and the handler succeed"
else
    sed 's/^/    /' "${WORK}/run.out" "${WORK}/run.err"
    echo "  ✗ the static consumer fails at run time"
    FAIL=1
fi

exit "${FAIL}"
