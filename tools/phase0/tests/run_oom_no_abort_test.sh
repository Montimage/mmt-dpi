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
#   4. Executed guard (issue #526, F-TEST-016): oom_init_exit_sweep fails the
#      first allocation of every distinct call site of init_extraction() —
#      one forked child each, under LD_PRELOAD of the fault-injection
#      interposer (tests/fault_injection/fi_alloc.c) — and traps exit(),
#      _exit() and _Exit(). An exit reached from libmmt_core or libmmt_tcpip
#      fails the gate; plugin exits (libmmt_tmobile, libmmt_business_app
#      init_proto exit(0)) are reported, out of scope (docs/DECISIONS.md).
#   5. Static guard, kept as a second layer and fail-closed: no live exit()
#      in configured_protocols.c or the init_extraction() body, whose anchor
#      must match exactly once.
#
# Usage: tools/phase0/tests/run_oom_no_abort_test.sh
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
PREFIX="${MMT_OOM_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/oom.XXXXXX")}"
BIN="$(mktemp -d)/oom_no_abort_test"
trap 'rm -rf "$(dirname "${BIN}")"; [ -n "${MMT_OOM_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/5] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
else
    echo "[1/5] building + installing SDK -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/5] compiling oom_no_abort_test"
gcc -g -O1 -o "${BIN}" "${TEST_DIR}/oom_no_abort_test.c" \
    -I"${PREFIX}/dpi/include" \
    -L"${PREFIX}/dpi/lib" -lmmt_core -ldl -lpthread -lm

echo "[3/5] running oom_no_abort_test"
set +e
LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" "${BIN}"
rc=$?
set -e
if [ "${rc}" -ne 0 ]; then
    echo "✗ OOM hardening test: FAIL (rc=${rc} — allocator aborted or assertion failed)"
    exit "${rc}"
fi

echo "[4/5] executed guard: fail each init_extraction() allocation call site, trap exit()"
FI_SRC="${REPO_ROOT}/tests/fault_injection"
BIN_DIR="$(dirname "${BIN}")"
gcc -Wall -Wextra -std=c11 -g -O1 -fPIC -shared -DFI_INTERPOSE -I"${FI_SRC}" \
    -o "${BIN_DIR}/libfi_alloc.so" "${FI_SRC}/fi_alloc.c" -ldl
# -rdynamic exports the sweep's exit()/_exit()/_Exit(), so the SDK and the
# plugins it dlopens resolve them to the trap instead of libc.
gcc -Wall -Wextra -std=gnu11 -g -O1 -rdynamic -I"${FI_SRC}" -I"${PREFIX}/dpi/include" \
    -o "${BIN_DIR}/oom_init_exit_sweep" "${TEST_DIR}/oom_init_exit_sweep.c" \
    -L"${BIN_DIR}" -L"${PREFIX}/dpi/lib" -lmmt_core -lfi_alloc -ldl
mkdir -p "${BIN_DIR}/run"
set +e
( cd "${BIN_DIR}/run" && \
  LD_PRELOAD="${BIN_DIR}/libfi_alloc.so" \
  LD_LIBRARY_PATH="${BIN_DIR}:${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" \
      "${BIN_DIR}/oom_init_exit_sweep" )
rc=$?
set -e
if [ "${rc}" -ne 0 ]; then
    echo "✗ OOM hardening test: FAIL (rc=${rc} — exit() reached on the init path, or the sweep could not run)"
    exit 1
fi

echo "[5/5] static guard: no live exit() on the protocol-init path"
# Strip C/C++ comments, then look for a bare exit( call. A match means an
# init/registration path can still kill the host process.
strip_and_grep() {
    # shellcheck disable=SC2002
    cat "$1" | sed -E 's://.*$::' | grep -nE '\bexit[[:space:]]*\(' || true
}
hits=""
hits+="$(strip_and_grep "${REPO_ROOT}/src/mmt_tcpip/lib/configured_protocols.c")"
# init_extraction() lives in packet_registry.c; only flag exit() inside it.
# Fail closed: a renamed or reformatted definition must not scan nothing.
REGISTRY="${REPO_ROOT}/src/mmt_core/src/packet_registry.c"
anchors="$(grep -c '^bool init_extraction(' "${REGISTRY}" || true)"
if [ "${anchors}" != "1" ]; then
    echo "✗ OOM hardening test: FAIL (static guard anchor '^bool init_extraction(' matched ${anchors} times in packet_registry.c, expected 1)"
    exit 1
fi
pp_init="$(awk '/^bool init_extraction\(/{f=1} f; /^}/{if(f)exit}' "${REGISTRY}" \
            | sed -E 's://.*$::' | grep -nE '\bexit[[:space:]]*\(' || true)"
hits+="${pp_init}"
if [ -n "${hits//[[:space:]]/}" ]; then
    echo "✗ OOM hardening test: FAIL (live exit() remains on init path):"
    echo "${hits}"
    exit 1
fi

echo "✓ OOM hardening test: PASS (allocator returns NULL; no exit() on init path, executed and static)"
exit 0
