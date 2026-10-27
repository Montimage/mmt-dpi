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
#   test_tcp_classify_giveup.c — issue #526 (F-TEST-009): the same include
#                              pattern, calling the shipped
#                              tcp_pre_classification_function() and its
#                              reassembling twin to pin the issue #99
#                              unknown-flow give-up (CONTINUE through packet
#                              40, SKIP on packet 41).
#
# Reused from tests/resource_bounds (issue #380 tcp-memory fixture): the
# counting allocator (tcp_alloc_count.c/.h) and the mmt_core link stubs and
# reassembly gauges (tcp_reasm_stubs.h).
#
# No SDK build is needed: every TU compiles straight from src/ (issue #367
# standalone contract). Objects go to the suite directory (as in
# tests/core_engine): under `tests/run_all_tests.sh --coverage` each
# object's .gcda is written beside it and must outlive this script for the
# runner to aggregate it (issue #524).
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

count=(-Dmalloc=tcm_malloc -Dcalloc=tcm_calloc -Drealloc=tcm_realloc -Dfree=tcm_free)

echo "  [1/2] compiling ..."
# proto_tcp.c's attribute extractors ignore their proto_index argument.
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -Wno-unused-parameter -std=gnu11 \
    "${count[@]}" "${INCS[@]}" \
    -c "${SCRIPT_DIR}/test_tcp_pending_order.c" -o "${SCRIPT_DIR}/test_tcp_pending_order.o"
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
    "${count[@]}" "${INCS[@]}" \
    -c "${REPO_ROOT}/src/mmt_core/src/memory.c" -o "${SCRIPT_DIR}/memory_counted.o"
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
    -c "${SHARED}/tcp_alloc_count.c" -o "${SCRIPT_DIR}/tcp_alloc_count.o"
"${CC}" "${extra_cflags[@]}" -o "${SCRIPT_DIR}/test_tcp_pending_order" \
    "${SCRIPT_DIR}/test_tcp_pending_order.o" "${SCRIPT_DIR}/memory_counted.o" "${SCRIPT_DIR}/tcp_alloc_count.o"
# -DNDEBUG as in the default SDK build: proto_tcp.c's per-packet debug()
# lines would otherwise print 160 times (the test asserts with CHECK).
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -Wno-unused-parameter -std=gnu11 \
    -DNDEBUG "${count[@]}" "${INCS[@]}" \
    -c "${SCRIPT_DIR}/test_tcp_classify_giveup.c" -o "${SCRIPT_DIR}/test_tcp_classify_giveup.o"
"${CC}" "${extra_cflags[@]}" -o "${SCRIPT_DIR}/test_tcp_classify_giveup" \
    "${SCRIPT_DIR}/test_tcp_classify_giveup.o" "${SCRIPT_DIR}/memory_counted.o" "${SCRIPT_DIR}/tcp_alloc_count.o"

echo "  [2/2] running ..."
rc=0
for t in test_tcp_pending_order test_tcp_classify_giveup; do
    if "${SCRIPT_DIR}/${t}"; then
        echo "  ✓ ${t}: PASSED"
    else
        echo "  ✗ ${t}: FAILED" >&2
        rc=1
    fi
done
[ "${rc}" -eq 0 ] || exit 1
echo "✓ tcp pending-order characterization (issue #381) and unknown-flow give-up (issue #526) passed"
