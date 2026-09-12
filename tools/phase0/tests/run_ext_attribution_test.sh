#!/usr/bin/env bash
#
# run_ext_attribution_test.sh — build the externally-updatable IP-range / port
# attribution loader unit test against an ASan/UBSan-instrumented build of the
# SDK and run it (issue #26, M9).
#
# Steps:
#   1. Build + install the SDK with BUILD=asan into an isolated prefix.
#   2. Compile tools/phase0/tests/ext_attribution_test.c against that library,
#      itself instrumented with -fsanitize=address,undefined. The loaders under
#      test (mmt_tcpip_load_ip_ranges_file / mmt_tcpip_load_port_map_file) and
#      the AVL lookup (_find_proto_id_by_address) are exported from libmmt_tcpip
#      but not part of any installed public header, so the test re-declares them
#      and links libmmt_tcpip directly.
#   3. Run it. With -fno-sanitize-recover=all any sanitizer hit aborts; all
#      assertions must also pass. Exit 0 == clean.
#
# Usage: tools/phase0/tests/run_ext_attribution_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_ASAN_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/asan.XXXXXX")}"
BIN="$(mktemp -d)/ext_attribution_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_ASAN_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/3] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/3] building + installing SDK with BUILD=asan -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" BUILD=asan MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/3] compiling ext_attribution_test (ASan/UBSan)"
# Link libmmt_tcpip directly to reach its exported loaders / AVL lookup. The
# protocol registry is populated at run time by init_extraction(), which loads
# the same plugin set from $PREFIX/plugins (libpcap is pulled in for DLT_EN10MB).
gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -o "${BIN}" "${TEST_DIR}/ext_attribution_test.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_tcpip -lmmt_core -ldl -lpthread -lm -lpcap

echo "[3/3] running ext_attribution_test under ASan/UBSan"
# Preload the ASan runtime (the SDK is also pulled in via dlopen) and run from
# the install prefix so the SDK's CWD-relative "plugins/" lookup resolves.
set +e
( cd "${PREFIX}" && \
  LD_PRELOAD="$(gcc -print-file-name=libasan.so)" \
  ASAN_OPTIONS="detect_leaks=0" \
  UBSAN_OPTIONS="print_stacktrace=1" \
  LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
      "${BIN}" )
rc=$?
set -e

if [ "${rc}" -eq 0 ]; then
    echo "✓ external attribution loader test: PASS"
else
    echo "✗ external attribution loader test: FAIL (rc=${rc})"
fi
exit "${rc}"
