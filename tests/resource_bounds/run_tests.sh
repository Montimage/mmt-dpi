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
# Issue #380 (F-PERF-002) adds the "tcp-memory" fixture: TCP reassembly
# must reject duplicate segments before allocating and keep RESERVED
# storage (segment blocks incl. headers + image capacities) within the
# per-flow tcp_reassembly_limit, with bounded exhaustion and full teardown.
#
#   test_tcp_memory.c — includes proto_tcp.c and tcp_segment.c directly so
#                       the static reassembly helpers run unmodified; it and
#                       memory.c are compiled with -Dmalloc=tcm_malloc (etc.)
#                       so every allocation is counted.
#   tcp_alloc_count.c — the counting allocator front-end (own TU: glibc's
#                       leaf attributes could fold caller-TU counters).
#
# Issue #382 (F-PERF-003) adds the "tcp-order" fixture: out-of-order TCP
# inserts are located through an AVL index over the pending list, so
# interleaved, tail-anchored and shuffled arrivals stay below the issue
# #381 list-walk evidence with at most 24-fold growth from 1,024 to 16,384
# segments, with byte-exact output, index-shape and OOM-reset checks.
#
#   test_tcp_order.c — same direct-include + counted-allocator build as
#                      test_tcp_memory.c.
#
# Issue #383 (F-PERF-004) adds the "fragment-eviction" fixture: the IPv4/IPv6
# fragment maps pick their ceiling-eviction victim from an intrusive recency
# list, so 10,000 replacement arrivals at the 1,024-datagram ceiling examine
# at most 10,000 victims (not 10,240,000 walker callbacks) with no map walk
# on the arrival path; list order is checked against a reference model for
# increasing, equal and backward timestamps, through sweep and teardown.
#
#   test_frag_eviction.c — includes proto_ip_dgram.c, proto_ipv6_dgram.c,
#                          proto_ip_frag.c and hashmap.c directly, with the
#                          index counters armed (-DMMT_IP_FRAG_INDEX_STATS)
#                          and the counted allocator of tcp-memory.
#
# Issue #394 (F-PERF-001..004) consolidates the four fixtures into
# reproducible adversarial resource budgets: every fixture reports its
# workload scales, fixed seeds, accepted/refused work and counters as
# "@rb" lines (rb_result.h); this runner collects them into a
# machine-readable results.json (schema: results.schema.json) and evaluates
# the budgets committed in budgets.json against them. Budgets are
# deterministic counts and bytes — no pps or timing guarantee is asserted.
# A missing or duplicated metric, a failed budget or a failed fixture fails
# the run. RESOURCE_BOUNDS_RESULTS=<path> redirects the results file
# (default: tests/resource_bounds/results.json, git-ignored). Requires jq.
#
# Issue #395 (M4) makes the budgets a CI gate: tools/ci/check-resource-budgets.py
# validates results.json against results.schema.json and re-evaluates every
# budget independently of the jq evaluation below (a missing dimension,
# workload record or metric, or any breach, fails), and its --self-test
# proves each failure mode is detected. Both run at the end of this script;
# a subset run is checked with --partial. results.json also carries labelled
# "observations" (uname -m, per-fixture wall-clock) that no budget reads.
# Requires python3.
#
# No SDK build is needed: every TU compiles straight from src/ — the same
# standalone property the other unit suites keep (issue #367 contract).
# Objects stay in a throwaway work dir; only the selected fixtures build.
#
# Usage: tests/resource_bounds/run_tests.sh [all | fixture ...]
#   no arguments (or "all") runs every fixture; "ipv6-hash" / "tcp-memory" /
#   "tcp-order" / "fragment-eviction" select one.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

ALL_FIXTURES=(ipv6-hash tcp-memory tcp-order fragment-eviction)
FIXTURES=()
for f in "$@"; do
    if [ "$f" = "all" ]; then FIXTURES+=("${ALL_FIXTURES[@]}"); else FIXTURES+=("$f"); fi
done
[ "${#FIXTURES[@]}" -eq 0 ] && FIXTURES=("${ALL_FIXTURES[@]}")

TESTS=()
FIXTURE_IDS=()
for f in "${FIXTURES[@]}"; do
    case " ${FIXTURE_IDS[*]} " in *" $f "*) continue ;; esac
    case "$f" in
        ipv6-hash) TESTS+=(ipv6_hash_bounds) ;;
        tcp-memory) TESTS+=(tcp_memory) ;;
        tcp-order) TESTS+=(tcp_order) ;;
        fragment-eviction) TESTS+=(frag_eviction) ;;
        *) echo "✗ unknown resource_bounds fixture '$f' (known: all, ipv6-hash, tcp-memory, tcp-order, fragment-eviction)" >&2
           exit 2 ;;
    esac
    FIXTURE_IDS+=("$f")
done

BUDGETS="${SCRIPT_DIR}/budgets.json"
RESULTS="${RESOURCE_BOUNDS_RESULTS:-${SCRIPT_DIR}/results.json}"
if ! command -v jq >/dev/null 2>&1; then
    echo "✗ jq is required to evaluate the resource budgets (apt-get install jq)" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "✗ python3 is required to check the resource budgets (apt-get install python3)" >&2
    exit 2
fi
CHECKER="${REPO_ROOT}/tools/ci/check-resource-budgets.py"

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

build_ipv6_hash_bounds() {
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
}

build_tcp_memory() {
    # Route every libc allocation of the code under test (proto_tcp.c,
    # tcp_segment.c and mmt_malloc in memory.c) through the counter.
    local count=(-Dmalloc=tcm_malloc -Dcalloc=tcm_calloc
                 -Drealloc=tcm_realloc -Dfree=tcm_free)
    # proto_tcp.c's attribute extractors ignore their proto_index argument.
    "${CC}" "${extra_cflags[@]}" -Wall -Wextra -Wno-unused-parameter -std=gnu11 \
        "${count[@]}" "${INCS[@]}" \
        -c "${SCRIPT_DIR}/test_tcp_memory.c" -o "${WORK}/test_tcp_memory.o"
    "${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
        "${count[@]}" "${INCS[@]}" \
        -c "${REPO_ROOT}/src/mmt_core/src/memory.c" -o "${WORK}/memory_counted.o"
    "${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
        -c "${SCRIPT_DIR}/tcp_alloc_count.c" -o "${WORK}/tcp_alloc_count.o"
    "${CC}" "${extra_cflags[@]}" -o "${SCRIPT_DIR}/test_tcp_memory" \
        "${WORK}/test_tcp_memory.o" "${WORK}/memory_counted.o" "${WORK}/tcp_alloc_count.o"
}

build_tcp_order() {
    # Same counted-allocator build as tcp-memory (the OOM case injects an
    # image allocation failure through tcm_fail_at).
    local count=(-Dmalloc=tcm_malloc -Dcalloc=tcm_calloc
                 -Drealloc=tcm_realloc -Dfree=tcm_free)
    "${CC}" "${extra_cflags[@]}" -Wall -Wextra -Wno-unused-parameter -std=gnu11 \
        "${count[@]}" "${INCS[@]}" \
        -c "${SCRIPT_DIR}/test_tcp_order.c" -o "${WORK}/test_tcp_order.o"
    "${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
        "${count[@]}" "${INCS[@]}" \
        -c "${REPO_ROOT}/src/mmt_core/src/memory.c" -o "${WORK}/memory_counted_order.o"
    "${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
        -c "${SCRIPT_DIR}/tcp_alloc_count.c" -o "${WORK}/tcp_alloc_count_order.o"
    "${CC}" "${extra_cflags[@]}" -o "${SCRIPT_DIR}/test_tcp_order" \
        "${WORK}/test_tcp_order.o" "${WORK}/memory_counted_order.o" \
        "${WORK}/tcp_alloc_count_order.o" -lm
}

build_frag_eviction() {
    # Same counted-allocator build as tcp-memory; the fragment-map sources
    # are included by the test TU with the index counters armed.
    local count=(-Dmalloc=tcm_malloc -Dcalloc=tcm_calloc
                 -Drealloc=tcm_realloc -Dfree=tcm_free)
    "${CC}" "${extra_cflags[@]}" -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -std=gnu11 \
        -DMMT_IP_FRAG_INDEX_STATS "${count[@]}" "${INCS[@]}" \
        -I"${REPO_ROOT}/src/mmt_tcpip/lib/protocols" \
        -c "${SCRIPT_DIR}/test_frag_eviction.c" -o "${WORK}/test_frag_eviction.o"
    "${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
        "${count[@]}" "${INCS[@]}" \
        -c "${REPO_ROOT}/src/mmt_core/src/memory.c" -o "${WORK}/memory_counted_frag.o"
    "${CC}" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
        -c "${SCRIPT_DIR}/tcp_alloc_count.c" -o "${WORK}/tcp_alloc_count_frag.o"
    "${CC}" "${extra_cflags[@]}" -o "${SCRIPT_DIR}/test_frag_eviction" \
        "${WORK}/test_frag_eviction.o" "${WORK}/memory_counted_frag.o" \
        "${WORK}/tcp_alloc_count_frag.o"
}

echo "  [1/3] compiling ..."
for name in "${TESTS[@]}"; do
    "build_${name}"
done

echo "  [2/3] running ..."
rc=0
: > "${WORK}/rb.lines"
: > "${WORK}/status"
: > "${WORK}/wall"
for i in "${!TESTS[@]}"; do
    name="${TESTS[$i]}"
    status=0
    t0="$(date +%s%N)"
    "${SCRIPT_DIR}/test_${name}" > "${WORK}/${name}.log" 2>&1 || status=$?
    # Observation only (issue #395): recorded, never budgeted.
    printf '%s %s\n' "${FIXTURE_IDS[$i]}" "$(( ($(date +%s%N) - t0) / 1000000 ))" >> "${WORK}/wall"
    # Human log without the machine-readable lines, which go to results.json.
    grep -v '^@rb ' "${WORK}/${name}.log" || true
    grep '^@rb ' "${WORK}/${name}.log" >> "${WORK}/rb.lines" || true
    printf '%s %s\n' "${FIXTURE_IDS[$i]}" "${status}" >> "${WORK}/status"
    if [ "${status}" -eq 0 ]; then
        echo "  ✓ test_${name}: PASSED"
    else
        echo "  ✗ test_${name}: FAILED (exit ${status})" >&2
        rc=1
    fi
    echo
done

# ---- [3/3] results.json + budget evaluation (issue #394) --------------------
echo "  [3/3] evaluating budgets (${BUDGETS#"${REPO_ROOT}/"}) ..."
mkdir -p "$(dirname "${RESULTS}")"
jq -n -R --slurpfile budgets "${BUDGETS}" --rawfile status "${WORK}/status" \
      --rawfile wall "${WORK}/wall" --arg platform "$(uname -m)" \
      --arg budgets_path "${BUDGETS#"${REPO_ROOT}/"}" '
  $budgets[0] as $B
  | [inputs | split(" ") | select(.[0] == "@rb")] as $raw
  | def wellformed: length == 5 and (.[3] | test("^[a-z0-9_.-]+$"))
        and ((.[2] == "metric" and (.[4] | test("^[0-9]+$")))
             or (.[2] == "seed" and (.[4] | test("^0x[0-9a-f]{16}$"))));
    [$raw[] | select(wellformed | not) | join(" ")] as $malformed
  | [$raw[] | select(wellformed)] as $L
  | [$L | group_by(.[1:4])[] | select(length > 1) | .[0][1:4] | join(" ")] as $dups
  | [$status | split("\n")[] | select(length > 0) | split(" ")
     | {key: .[0], value: (.[1] | tonumber)}] as $S
  | (reduce $L[] as $l ({};
        if $l[2] == "metric" then .[$l[1]].metrics[$l[3]] = ($l[4] | tonumber)
        else .[$l[1]].seeds[$l[3]] = $l[4] end)) as $M
  | def mval($f; $k): $M[$f].metrics[$k];
    [ $S[].key as $f | ($B.fixtures[$f].checks // [])[] | . as $c
      | mval($f; $c.metric) as $v
      # A malformed budget (no/non-integer limit, no parts) is reported as
      # "invalid budget", not as a missing metric (issue #395).
      | (if ($c.op | IN("eq", "le", "lt", "sum") | not) then false
         elif $c.op == "sum" then (($c.parts | type) == "array" and ($c.parts | length) > 0)
         elif ($c | has("limit_metric")) then (($c.limit_metric | type) == "string"
              and (($c.factor // 1) | type == "number" and . == floor and . > 0))
         else ($c.limit | type == "number" and . == floor) end) as $valid
      | (if ($valid | not) then null
         elif $c.op == "sum" then
           [$c.parts[] | mval($f; .)] as $p
           | (if ($p | any(. == null)) then null else ($p | add) end)
         elif ($c | has("limit_metric")) then
           mval($f; $c.limit_metric) as $lm
           | (if $lm == null then null else $lm * ($c.factor // 1) end)
         else $c.limit end) as $lim
      | {fixture: $f, id: $c.id, metric: $c.metric, op: $c.op, value: $v,
         limit: $lim, baseline: ($c.baseline // null),
         pass: (if ($valid | not) or $v == null or $lim == null then false
                elif $c.op == "eq" or $c.op == "sum" then $v == $lim
                elif $c.op == "le" then $v <= $lim
                elif $c.op == "lt" then $v < $lim
                else false end)}
      + (if ($c.op | IN("eq", "sum", "le", "lt") | not) then {error: "unknown op"}
         elif ($valid | not) then {error: "invalid budget"}
         elif $v == null or $lim == null then {error: "missing metric"}
         else {} end) ] as $C
  | [$S[] | select(($B.fixtures[.key].checks // []) | length == 0) | .key] as $unbudgeted
  | ([$S[].key]) as $ran
  | [$L[] | .[1] | select(. as $f | $ran | index($f) | not)] | unique as $stray
  | {
      schema: "mmt-dpi/resource-bounds-result/v1",
      budgets: $budgets_path,
      timing_asserted: false,
      fixtures: ([$S[] | .key as $f | {key: $f, value: {
          issue: $B.fixtures[$f].issue, finding: $B.fixtures[$f].finding,
          workload: $B.fixtures[$f].workload, exit_status: .value,
          seeds: ($M[$f].seeds // {}), metrics: ($M[$f].metrics // {})}}]
        | from_entries),
      checks: $C,
      errors: ([$malformed[] | "malformed line: \(.)"]
               + [$dups[] | "duplicate key: \(.)"]
               + [$unbudgeted[] | "fixture without budgets: \(.)"]
               + [$stray[] | "results for a fixture that did not run: \(.)"]),
      observations: {
        platform: $platform,
        wall_ms: ([$wall | split("\n")[] | select(length > 0) | split(" ")
                   | {key: .[0], value: (.[1] | tonumber)}] | from_entries)
      },
      summary: {
        fixtures: ($S | length),
        failed_fixtures: ([$S[] | select(.value != 0)] | length),
        checks: ($C | length),
        failed_checks: ([$C[] | select(.pass | not)] | length)
      }
    }
  | .summary.pass = (.summary.failed_fixtures == 0 and .summary.failed_checks == 0
                     and (.errors | length) == 0)
' < "${WORK}/rb.lines" > "${WORK}/results.json"
mv "${WORK}/results.json" "${RESULTS}"

jq -r '.fixtures | to_entries[] | .key as $f
       | "    \($f): \(.value.metrics | length) counters, \(.value.seeds | length) seed(s)"' "${RESULTS}"
jq -r '.checks[] | select(.pass | not)
       | "  ✗ budget \(.fixture)/\(.id): \(.metric) = \(.value) \(.op) \(.limit)\(if .error then " (" + .error + ")" else "" end)"' \
    "${RESULTS}" >&2
jq -r '.errors[] | "  ✗ \(.)"' "${RESULTS}" >&2
jq -r '.summary | "  budgets: \(.checks - .failed_checks)/\(.checks) within limits"' "${RESULTS}"
echo "  results: ${RESULTS}"
jq -e '.summary.pass' "${RESULTS}" >/dev/null || rc=1

# ---- CI gate (issue #395): independent re-evaluation + detector self-test ---
echo "  checking budgets independently (${CHECKER#"${REPO_ROOT}/"}) ..."
partial=()
[ "${#FIXTURE_IDS[@]}" -eq "${#ALL_FIXTURES[@]}" ] || partial=(--partial)
python3 "${CHECKER}" "${partial[@]}" "${RESULTS}" || rc=1
python3 "${CHECKER}" --self-test > "${WORK}/selftest.log" 2>&1 || { cat "${WORK}/selftest.log"; rc=1; }
tail -n 1 "${WORK}/selftest.log"

[ "${rc}" -eq 0 ] || { echo "✗ resource bounds tests failed" >&2; exit 1; }
echo "✓ resource bounds tests passed (issues #379, #380, #382, #383; budgets #394, gate #395)"
