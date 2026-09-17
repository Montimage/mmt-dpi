#!/usr/bin/env bash
#
# run_oom_no_abort_test.sh — build + run the B5 OOM hardening regression test
# (issue #16). Verifies that mmt_malloc()/mmt_realloc() return NULL on
# allocation failure instead of abort()ing the host process, and that no exit()
# remains on the shared-library protocol-init path.
#
# Steps:
#   1. Build + install the SDK into an isolated prefix.
#   2. Compile tools/phase0/tests/oom_no_abort_test.c against that library.
#   3. Run it. The allocator must return NULL (not SIGABRT) on a huge request;
#      a process killed by abort() would exit with a signal, failing the gate.
#   4. Static guard: assert no live exit() remains on the protocol-init path.
#
# Usage: tools/phase0/tests/run_oom_no_abort_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_OOM_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/oom.XXXXXX")}"
BIN="$(mktemp -d)/oom_no_abort_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_OOM_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/4] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/4] building + installing SDK -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/4] compiling oom_no_abort_test"
gcc -g -O1 -o "${BIN}" "${TEST_DIR}/oom_no_abort_test.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpthread -lm

echo "[3/4] running oom_no_abort_test"
set +e
LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" "${BIN}"
rc=$?
set -e
if [ "${rc}" -ne 0 ]; then
    echo "✗ OOM hardening test: FAIL (rc=${rc} — allocator aborted or assertion failed)"
    exit "${rc}"
fi

echo "[4/4] static guard: no live exit() on the protocol-init path"
# Strip C/C++ comments, then look for a bare exit( call. A match means an
# init/registration path can still kill the host process.
strip_and_grep() {
    # shellcheck disable=SC2002
    cat "$1" | sed -E 's://.*$::' | grep -nE '\bexit[[:space:]]*\(' || true
}
hits=""
hits+="$(strip_and_grep "${REPO_ROOT}/src/mmt_tcpip/lib/configured_protocols.c")"
# init_extraction() lives in packet_registry.c; only flag exit() inside it.
pp_init="$(awk '/^bool init_extraction\(/{f=1} f; /^}/{if(f)exit}' \
            "${REPO_ROOT}/src/mmt_core/src/packet_registry.c" \
            | sed -E 's://.*$::' | grep -nE '\bexit[[:space:]]*\(' || true)"
hits+="${pp_init}"
if [ -n "${hits//[[:space:]]/}" ]; then
    echo "✗ OOM hardening test: FAIL (live exit() remains on init path):"
    echo "${hits}"
    exit 1
fi

echo "✓ OOM hardening test: PASS (allocator returns NULL; no exit() on init path)"
exit 0
