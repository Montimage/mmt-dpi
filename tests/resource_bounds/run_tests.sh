#!/usr/bin/env bash
# run_tests.sh — resource-bound tests: per-operation work must stay under a
# stated ceiling even on adversarial inputs.
#
# Issue #379 (F-PERF-001) adds the "ipv6-hash" fixture: the interned-IPv6
# address store must hash all 16 address bytes through a per-handler keyed
# hash and bound collision work — comparator calls stay under the issue's
# budgets at 1,024/16,384 inputs, and forced collisions are capped by a
# finite per-operation probe bound.
#
#   ipv6_addr_fns.c          — includes ip_session_id_management.c directly
#                              so the REAL static ipv6_addr_hash and the
#                              registered comparator run unmodified (the
#                              test_udp_bounds_unit.c convention), plus thin
#                              wrappers over setup_ipv6_internal_context /
#                              get_ip6_id / findID6.
#   test_ipv6_hash_bounds.cpp — includes hash_utils.cpp so the harness reads
#                              table internals (seed, cap) and the armed
#                              comparator counters without new exports.
#
# No SDK build is needed: both TUs compile straight from src/ — the same
# standalone property the other unit suites keep (issue #367 contract).
#
# Usage: tests/resource_bounds/run_tests.sh [fixture ...]
#   no arguments runs every fixture; "ipv6-hash" selects it explicitly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

FIXTURES=( "$@" )
[ "${#FIXTURES[@]}" -eq 0 ] && FIXTURES=(ipv6-hash)

TESTS=()
for f in "${FIXTURES[@]}"; do
    case "$f" in
        ipv6-hash) TESTS+=(ipv6_hash_bounds) ;;
        *) echo "✗ unknown resource_bounds fixture '$f' (known: ipv6-hash)" >&2
           exit 2 ;;
    esac
done

CC="${CC:-gcc}"
CXX="${CXX:-g++}"

# Honor a direct SANITIZE=asan|tsan invocation (the issue's verify command)
# by composing the same flag set tests/run_all_tests.sh derives; when the
# suite runs under the master runner, EXTRA_CFLAGS is already set and wins.
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
    -I"${REPO_ROOT}/src/mmt_core/public_include"
    -I"${REPO_ROOT}/src/mmt_core/private_include"
    -I"${REPO_ROOT}/src/mmt_tcpip/lib"
    -I"${REPO_ROOT}/src/mmt_tcpip/include"
    # mmt_common_internal_include.h pulls protocols/rtp.h, which needs the
    # fuzz-engine include dir (same as tests/parser_boundaries).
    -I"${REPO_ROOT}/src/mmt_fuzz_engine"
)

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "  [1/2] compiling ..."
# The C TU wraps the real ipv6 address functions. No -D'u_char=...' here —
# unlike the hashmap suite's -std=c11, gnu11/gnu++11 keep _DEFAULT_SOURCE /
# _GNU_SOURCE so <sys/types.h> already provides the type.
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
    "${INCS[@]}" -c "${SCRIPT_DIR}/ipv6_addr_fns.c" -o "${WORK}/ipv6_addr_fns.o"

# The C++ harness includes hash_utils.cpp (stats counters armed: no NDEBUG).
"${CXX}" "${extra_cflags[@]}" -Wall -Wextra -std=c++11 \
    "${INCS[@]}" -c "${SCRIPT_DIR}/test_ipv6_hash_bounds.cpp" -o "${WORK}/test_ipv6_hash_bounds.o"

# mmt_malloc/mmt_free come from the real allocator.
"${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
    "${INCS[@]}" -c "${REPO_ROOT}/src/mmt_core/src/memory.c" -o "${WORK}/memory.o"

"${CXX}" "${extra_cflags[@]}" -o "${SCRIPT_DIR}/test_ipv6_hash_bounds" \
    "${WORK}/test_ipv6_hash_bounds.o" "${WORK}/ipv6_addr_fns.o" "${WORK}/memory.o"

echo "  [2/2] running ..."
rc=0
for name in "${TESTS[@]}"; do
    if "${SCRIPT_DIR}/test_${name}"; then
        echo "  ✓ test_${name}: PASSED"
    else
        echo "  ✗ test_${name}: FAILED" >&2
        rc=1
    fi
    echo
done

[ "${rc}" -eq 0 ] || { echo "✗ resource bounds tests failed" >&2; exit 1; }
echo "✓ resource bounds tests passed (issue #379)"
