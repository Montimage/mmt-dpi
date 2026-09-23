#!/usr/bin/env bash
# run_tests.sh — issue #381 (F-PERF-003, first part): characterize the TCP
# pending-segment store's ordering, duplicate, overlap, 32-bit wrap, partial
# consumption and teardown behavior with explicit byte-output assertions
# BEFORE its insertion structure changes.
#
#   test_tcp_pending_order.c — includes proto_tcp.c and tcp_segment.c
#                              directly so the static reassembly helpers run
#                              unmodified; it and memory.c are compiled with
#                              -Dmalloc=tcm_malloc (etc.) so teardown can
#                              prove every allocation is returned.
#
# Reused from tests/resource_bounds (issue #380 tcp-memory fixture): the
# counting allocator (tcp_alloc_count.c/.h) and the mmt_core link stubs and
# reassembly gauges (tcp_reasm_stubs.h).
#
# No SDK build is needed: every TU compiles straight from src/ (issue #367
# standalone contract). Objects stay in a throwaway work dir.
#
# Usage: tests/tcp_pending_order/run_tests.sh
#   SANITIZE=asan|tsan is honored for direct invocations.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SHARED="${REPO_ROOT}/tests/resource_bounds"

CC="${CC:-gcc}"

# Same flag derivation as tests/resource_bounds/run_tests.sh: under the
# master runner EXTRA_CFLAGS is already set and wins.
if [ -z "${EXTRA_CFLAGS:-}" ]; then
    case "${SANITIZE:-}" in
        asan) EXTRA_CFLAGS="-g -O1 -fno-omit-frame-pointer -fno-common -fsanitize=address,undefined -fno-sanitize-recover=all"
              export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}" ;;
        tsan) EXTRA_CFLAGS="-g -O1 -fno-omit-frame-pointer -fno-common -fsanitize=thread -fno-sanitize-recover=all" ;;
        "") ;;
        *) echo "✗ invalid SANITIZE value '${SANITIZE}' (expected: asan|tsan)" >&2
           exit 2 ;;
    esac
fi
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"

INCS=(
    -I"${SHARED}"
    -I"${REPO_ROOT}/src/mmt_core/public_include"
    -I"${REPO_ROOT}/src/mmt_core/private_include"
    -I"${REPO_ROOT}/src/mmt_tcpip/lib"
    -I"${REPO_ROOT}/src/mmt_tcpip/include"
    -I"${REPO_ROOT}/src/mmt_fuzz_engine"
)

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

count=(-Dmalloc=tcm_malloc -Dcalloc=tcm_calloc -Drealloc=tcm_realloc -Dfree=tcm_free)

echo "  [1/2] compiling ..."
# proto_tcp.c's attribute extractors ignore their proto_index argument.
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -Wno-unused-parameter -std=gnu11 \
    "${count[@]}" "${INCS[@]}" \
    -c "${SCRIPT_DIR}/test_tcp_pending_order.c" -o "${WORK}/test_tcp_pending_order.o"
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
    "${count[@]}" "${INCS[@]}" \
    -c "${REPO_ROOT}/src/mmt_core/src/memory.c" -o "${WORK}/memory_counted.o"
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
    -c "${SHARED}/tcp_alloc_count.c" -o "${WORK}/tcp_alloc_count.o"
"${CC}" "${extra_cflags[@]}" -o "${SCRIPT_DIR}/test_tcp_pending_order" \
    "${WORK}/test_tcp_pending_order.o" "${WORK}/memory_counted.o" "${WORK}/tcp_alloc_count.o"

echo "  [2/2] running ..."
if "${SCRIPT_DIR}/test_tcp_pending_order"; then
    echo "  ✓ test_tcp_pending_order: PASSED"
else
    echo "  ✗ test_tcp_pending_order: FAILED" >&2
    exit 1
fi
echo "✓ tcp pending-order characterization passed (issue #381)"
