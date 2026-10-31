#!/usr/bin/env bash
#
# run_tests.sh — fault-injection suite (issue #216, F-TEST-007).
#
# Two layers:
#
#   1. fi-core (always, every profile): memory.c is compiled with
#      -Dmalloc=fiu_malloc -Drealloc=fiu_realloc -Dfree=fiu_free so every
#      allocation behind mmt_malloc/mmt_realloc/mmt_free/mmt_arena is routed
#      through the counting front-end in fi_alloc.c, then a sweep forces the
#      Nth allocation to fail and asserts NULL propagation, no double free
#      and zero net leaked blocks. hashmap.c joins through mmt_malloc.
#
#   2. fi-engine (default or coverage profile): libfi_alloc.so is LD_PRELOADed so
#      the installed SDK's allocations — including C++ new — are counted;
#      the sweep covers the hardened mmt_init_handler() allocation sites
#      (the second-allocation-failure ip_streams branch fixed by task 2.1)
#      and the session/int map-space lifecycle. Under SANITIZE=asan|tsan
#      the sanitizer runtime owns malloc and the interposer would be inert,
#      so the engine layer is skipped (the unit layer still runs and keeps
#      memory.c/hashmap.c under the sanitizer).
#
# Usage: tests/fault_injection/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CORE_SRC="${REPO_ROOT}/src/mmt_core/src"
CORE_PRIV="${REPO_ROOT}/src/mmt_core/private_include"
CORE_PUB="${REPO_ROOT}/src/mmt_core/public_include"

CC="${CC:-gcc}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"

BIN_CORE="${SCRIPT_DIR}/test_fi_core"
BIN_ENGINE="${SCRIPT_DIR}/test_fi_engine"
BIN_HTTP="${SCRIPT_DIR}/test_fi_http"
INTERPOSER="${SCRIPT_DIR}/libfi_alloc.so"

echo "  repo root : ${REPO_ROOT}"

# --- 1. unit-level sweep (source-compiled, every profile) -------------------
echo "  [1/3] building + running fi-core (allocator/hashmap/HTTP-parser sweeps)"
# memory.c is the only translation unit whose libc allocation calls are
# remapped to the counting front-end; mmt_malloc/mmt_free inside it keep
# their public names so hashmap.c exercises them unchanged.
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=c11 -g \
    -D'u_char=unsigned char' \
    -Dmalloc=fiu_malloc -Dcalloc=fiu_calloc -Drealloc=fiu_realloc -Dfree=fiu_free \
    -I"${CORE_PRIV}" -I"${CORE_PUB}" \
    -c "${CORE_SRC}/memory.c" -o "${SCRIPT_DIR}/test_fi_memory.o"
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=c11 -g \
    -D'u_char=unsigned char' \
    -I"${CORE_PRIV}" -I"${CORE_PUB}" -I"${REPO_ROOT}/src/mmt_tcpip/lib" \
    -c "${CORE_SRC}/hashmap.c" -o "${SCRIPT_DIR}/test_fi_hashmap.o"
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=c11 -g \
    -I"${SCRIPT_DIR}" \
    -c "${SCRIPT_DIR}/fi_alloc.c" -o "${SCRIPT_DIR}/test_fi_alloc.o"
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=c11 -g \
    -D'u_char=unsigned char' \
    -I"${CORE_PRIV}" -I"${CORE_PUB}" -I"${SCRIPT_DIR}" \
    -c "${SCRIPT_DIR}/test_fi_core.c" -o "${SCRIPT_DIR}/test_fi_core.o"
"${CC}" "${extra_cflags[@]}" -o "${BIN_CORE}" \
    "${SCRIPT_DIR}/test_fi_core.o" "${SCRIPT_DIR}/test_fi_alloc.o" \
    "${SCRIPT_DIR}/test_fi_memory.o" "${SCRIPT_DIR}/test_fi_hashmap.o"

# The contract test issues a ~2^63-byte mmt_malloc that must return NULL;
# the ASan/TSan runtimes abort on such requests unless told NULL is an
# acceptable answer (each reads its own *_OPTIONS variable). Harmless when
# no sanitizer runtime is present.
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}:allocator_may_return_null=1"
export TSAN_OPTIONS="${TSAN_OPTIONS:+${TSAN_OPTIONS}:}allocator_may_return_null=1"
"${BIN_CORE}"

# Issue #505: the HTTP stream-parser constructor (a static inline in
# http_parser_integration.h) against the same fiu-remapped memory.c, linked
# with the vendored llhttp it initialises -- built without gcov flags so it stays out of the unit coverage cohort.
TCPIP_LIB="${REPO_ROOT}/src/mmt_tcpip/lib"
fi_http_objs=(); vendor_cflags=()
for f in "${extra_cflags[@]}"; do [[ "${f}" =~ ^(--coverage|-fprofile-arcs|-ftest-coverage)$ ]] || vendor_cflags+=("${f}"); done
for src in llhttp.c llhttp_api.c llhttp_http.c; do
    obj="${SCRIPT_DIR}/test_fi_$(basename "${src}" .c).o"
    "${CC}" "${vendor_cflags[@]}" -std=gnu11 -g -I"${TCPIP_LIB}" \
        -c "${TCPIP_LIB}/${src}" -o "${obj}"
    fi_http_objs+=("${obj}"); done
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 -g \
    -I"${CORE_PRIV}" -I"${CORE_PUB}" -I"${TCPIP_LIB}" -I"${SCRIPT_DIR}" \
    -c "${SCRIPT_DIR}/test_fi_http.c" -o "${SCRIPT_DIR}/test_fi_http.o"
"${CC}" "${extra_cflags[@]}" -o "${BIN_HTTP}" \
    "${SCRIPT_DIR}/test_fi_http.o" "${SCRIPT_DIR}/test_fi_alloc.o" \
    "${SCRIPT_DIR}/test_fi_memory.o" "${fi_http_objs[@]}"
"${BIN_HTTP}"

# Issues #503/#674: the real mobile and business-app init_proto() against stub
# protocol initializers, each made to fail in turn -- each must return 0 and
# log the protocol, never exit(). Both define init_proto/cleanup_proto, so
# each is renamed to share one binary.
BIN_PLUGIN_EXIT="${SCRIPT_DIR}/test_fi_plugin_exit"
plugin_incs=(-I"${CORE_PUB}" -I"${CORE_PRIV}" -I"${REPO_ROOT}/src/mmt_tcpip/include"
    -I"${TCPIP_LIB}" -I"${REPO_ROOT}/src/mmt_mobile/include" -I"${REPO_ROOT}/src/mmt_fuzz_engine")
"${CC}" "${extra_cflags[@]}" -std=gnu11 -g "${plugin_incs[@]}" \
    -Dinit_proto=mobile_init_proto -Dcleanup_proto=mobile_cleanup_proto \
    -c "${REPO_ROOT}/src/mmt_mobile/mmt_mobile_plugin.c" -o "${SCRIPT_DIR}/test_fi_plugin_exit_mobile.o"
"${CC}" "${extra_cflags[@]}" -std=gnu11 -g "${plugin_incs[@]}" \
    -Dinit_proto=ba_init_proto -Dcleanup_proto=ba_cleanup_proto \
    -c "${REPO_ROOT}/src/mmt_business_app/mmt_business_app.c" -o "${SCRIPT_DIR}/test_fi_plugin_exit_ba.o"
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 -g \
    -c "${SCRIPT_DIR}/test_fi_plugin_exit.c" -o "${SCRIPT_DIR}/test_fi_plugin_exit.o"
"${CC}" "${extra_cflags[@]}" -o "${BIN_PLUGIN_EXIT}" "${SCRIPT_DIR}/test_fi_plugin_exit.o" \
    "${SCRIPT_DIR}/test_fi_plugin_exit_mobile.o" "${SCRIPT_DIR}/test_fi_plugin_exit_ba.o"
"${BIN_PLUGIN_EXIT}"

# --- 2. engine-level sweep (LD_PRELOAD, not under sanitizer profiles) -------
if [[ "${SDK_BUILD_PROFILE:-}" =~ ^(asan|tsan)$ ]]; then
    echo "  [2/3] fi-engine and plugin-init cases skipped: SDK_BUILD_PROFILE=${SDK_BUILD_PROFILE}" \
         "(sanitizer runtimes own malloc; the unit layer above still ran)"
    echo "Fault-injection tests: PASSED"
    exit 0
fi

echo "  [2/3] building SDK + running fi-engine (LD_PRELOAD sweeps)"
PREFIX="${MMT_FI_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/fi.XXXXXX")}"
if [ -z "${MMT_FI_PREFIX:-}" ]; then
    trap 'rm -rf "${PREFIX}"' EXIT
fi

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    # tests/run_all_tests.sh built and installed it once (issue #654).
    [ -e "${PREFIX}/dpi/lib/libmmt_core.so" ] || { echo "✗ MMT_SDK_PREBUILT=1 but MMT_FI_PREFIX='${MMT_FI_PREFIX:-}' holds no installed SDK" >&2; exit 1; }
    echo "  reusing the prebuilt SDK in ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    make -C "${REPO_ROOT}/sdk" ${SDK_BUILD_PROFILE:+"BUILD=${SDK_BUILD_PROFILE}"} clean >/dev/null
    make -C "${REPO_ROOT}/sdk" ${SDK_BUILD_PROFILE:+"BUILD=${SDK_BUILD_PROFILE}"} MMT_BASE="${PREFIX}" -j"${JOBS}" >/dev/null
    make -C "${REPO_ROOT}/sdk" ${SDK_BUILD_PROFILE:+"BUILD=${SDK_BUILD_PROFILE}"} MMT_BASE="${PREFIX}" install >/dev/null
fi

"${CC}" -Wall -Wextra -std=c11 -g -O1 -fPIC -shared \
    -DFI_INTERPOSE -I"${SCRIPT_DIR}" \
    -o "${INTERPOSER}" "${SCRIPT_DIR}/fi_alloc.c" -ldl

# u_char comes from sys/types.h via pcap.h — the -D'u_char=...' shim the
# source-compiled suites need would collide with that typedef.
# Issue #533: test_fi_engine calls hash_utils map-space internals that
# libmmt_core.so hides, so it links the static archive (never -lmmt_core as
# well). malloc stays a dynamic libc call, so LD_PRELOAD still interposes it.
# shellcheck source=tools/phase0/tests/static_core_link.sh
. "${REPO_ROOT}/tools/phase0/tests/static_core_link.sh"
mmt_static_core_link "${PREFIX}/dpi/lib" || exit 2
"${CC}" -Wall -Wextra -std=gnu11 -g -O1 \
    -I"${SCRIPT_DIR}" -I"${CORE_PRIV}" -I"${CORE_PUB}" \
    -I"${PREFIX}/dpi/include" \
    -o "${BIN_ENGINE}" "${SCRIPT_DIR}/test_fi_engine.c" \
    -L"${PREFIX}/dpi/lib" -L"${SCRIPT_DIR}" \
    "${MMT_STATIC_CORE_LDFLAGS[@]}" -lfi_alloc -ldl -lpcap

# The engine binary exercises libmmt_tcpip plugin loading; init_extraction()
# resolves plugins relative to the install prefix, so run from a neutral
# directory with the prefix on the loader path.
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"; [ -z "${MMT_FI_PREFIX:-}" ] && rm -rf "${PREFIX}" || true' EXIT
(cd "${WORK}" && \
    LD_PRELOAD="${INTERPOSER}" \
    LD_LIBRARY_PATH="${SCRIPT_DIR}:${PREFIX}/dpi/lib" \
    "${BIN_ENGINE}")

# --- 3. plugin load/init failures reach init_extraction() (issue #503) ------
# Same profiles as layer 2. A stub plugin whose init_proto() fails, or that
# exports none, must make init_extraction() return failure; a relative or
# missing MMT_DPI_PLUGINS_DIR is refused; a ./plugins in the working
# directory is never loaded. Each case is one process: the protocol registry
# is process-global.
echo "  [3/3] plugin load/init failure propagation"
BIN_PLUGIN="${SCRIPT_DIR}/test_fi_plugin_init"
"${CC}" -Wall -Wextra -std=gnu11 -g -O1 \
    -I"${PREFIX}/dpi/include" \
    -o "${BIN_PLUGIN}" "${SCRIPT_DIR}/test_fi_plugin_init.c" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl

# The installed plugins plus one stub sorted after them (fi_plugin.c): its
# init_proto() fails in FAIL_DIR, it exports none in NOSYM_DIR.
FAIL_DIR="${WORK}/plugins-init-fails"
NOSYM_DIR="${WORK}/plugins-no-init"
mkdir -p "${FAIL_DIR}" "${NOSYM_DIR}" "${WORK}/plugins"
for so in "${PREFIX}"/plugins/*.so; do
    ln -s "${so}" "${FAIL_DIR}/"
    ln -s "${so}" "${NOSYM_DIR}/"
done
"${CC}" -Wall -Wextra -std=c11 -fPIC -shared \
    -o "${FAIL_DIR}/libzz_fi_plugin.so" "${SCRIPT_DIR}/fi_plugin.c"
"${CC}" -Wall -Wextra -std=c11 -fPIC -shared -DFI_NO_INIT_PROTO \
    -o "${NOSYM_DIR}/libzz_fi_plugin.so" "${SCRIPT_DIR}/fi_plugin.c"
# A failing plugin in the working directory must be ignored: only the
# compiled-in directory or MMT_DPI_PLUGINS_DIR is ever scanned.
cp "${FAIL_DIR}/libzz_fi_plugin.so" "${WORK}/plugins/"

plugin_case() {
    local desc="$1" want="$2"; shift 2
    if (cd "${WORK}" && env -u MMT_DPI_PLUGINS_DIR "$@" \
            LD_LIBRARY_PATH="${PREFIX}/dpi/lib" "${BIN_PLUGIN}" "${want}"); then
        echo "    ✓ ${desc}"
    else
        echo "    ✗ ${desc}"
        plugin_failures=$((plugin_failures + 1))
    fi
}
plugin_failures=0
plugin_case "compiled-in plugin directory loads; ./plugins is ignored" ok
plugin_case "MMT_DPI_PLUGINS_DIR selects the plugin directory" ok \
    MMT_DPI_PLUGINS_DIR="${PREFIX}/plugins"
plugin_case "a plugin whose init_proto() fails fails init_extraction()" fail \
    MMT_DPI_PLUGINS_DIR="${FAIL_DIR}"
plugin_case "a plugin without init_proto() fails init_extraction()" fail \
    MMT_DPI_PLUGINS_DIR="${NOSYM_DIR}"
plugin_case "a relative MMT_DPI_PLUGINS_DIR is refused" fail \
    MMT_DPI_PLUGINS_DIR=plugins
plugin_case "a missing MMT_DPI_PLUGINS_DIR is refused" fail \
    MMT_DPI_PLUGINS_DIR="${WORK}/no-such-dir"
if [ "${plugin_failures}" -gt 0 ]; then
    echo "Fault-injection tests: FAILED (${plugin_failures} plugin case(s))"
    exit 1
fi

echo "Fault-injection tests: PASSED"
