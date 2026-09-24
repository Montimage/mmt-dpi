#!/usr/bin/env bash
# run_tests.sh — documented embedding lifecycle (issue #392, F-DOCS-001).
#
# docs/USER_GUIDE.md §3 documents the init/handler/process/teardown order and
# the worker-ownership rule with path:line citations, and names
# src/examples/packet_handler.c as the runnable reference. This suite keeps the
# three in agreement:
#   [1/4] every path:line citation in the lifecycle docs lands on the line it
#         is cited for (an unregistered citation fails, so none can drift);
#   [2/4] the example calls init_extraction() before mmt_init_handler(),
#         checks both, and closes the handler before close_extraction();
#   [3/4] the SDK builds and installs into a throwaway MMT_BASE prefix;
#   [4/4] the *installed* example compiles against that prefix and runs: a
#         pcap is processed, and bad input exits 1 through the cleanup paths
#         instead of crashing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
EXAMPLE_REL="src/examples/packet_handler.c"
PCAP="${REPO_ROOT}/src/examples/google-fr.pcap"

ERRORS=0
ok()   { echo "    ✓ $1"; }
fail() { echo "    ✗ $1"; ERRORS=$((ERRORS + 1)); }

# ---------------------------------------------------------------------------
# [1/4] Citations
# ---------------------------------------------------------------------------
echo "  [1/4] checking lifecycle doc citations ..."

# Docs whose path:line citations this suite owns.
# docs/MMT-Handler.md: handler teardown, session count and the fragment
# resource limits (issue #396).
CITING_DOCS=(docs/USER_GUIDE.md docs/THREADING.md docs/Global-Handler.md docs/MMT-Handler.md)

# <path>:<start>[-<end>] <TAB> <regex the start line must match>
#   [<TAB> <regex the end line must match>]
CITATIONS="$(cat <<'TABLE'
src/mmt_core/src/packet_registry.c:1255	^bool init_extraction\(\)
src/mmt_core/src/packet_registry.c:1303-1304	^ *init_plugins\(\);	mmt_configured_handlers_map = init_map_space
src/mmt_core/src/packet_registry.c:950	^mmt_handler_t \*mmt_init_handler\(
src/mmt_core/src/packet_registry.c:1097	insert_key_value\(mmt_configured_handlers_map
src/mmt_core/src/packet_pipeline.c:1389	^bool packet_process\(
src/mmt_core/src/packet_registry.c:1130	^void mmt_close_handler\(mmt_handler_t
src/mmt_core/src/packet_registry.c:1180	delete_key_value\(mmt_configured_handlers_map
src/mmt_core/src/packet_registry.c:1333	^void close_extraction\(\)
src/mmt_core/src/packet_registry.c:1333-1351	^void close_extraction\(\)	^\}$
src/mmt_core/src/packet_registry.c:1336	iterate_through_mmt_handlers\(mmt_close_handler_internal
src/mmt_core/src/packet_registry.c:1350	^ *close_plugins\(\);
src/examples/packet_handler.c:63	if *\(!init_extraction\(\)\)
src/examples/packet_handler.c:69	mmt_handler = mmt_init_handler\(
src/examples/packet_handler.c:100	if *\(!packet_process\(mmt_handler
src/examples/packet_handler.c:108	^	mmt_close_handler\(mmt_handler\);
src/examples/packet_handler.c:111	^	close_extraction\(\);
src/mmt_core/public_include/mmt_core.h:185	MMTAPI bool MMTCALL init_extraction\(\);
src/mmt_core/public_include/mmt_core.h:198	MMTAPI void MMTCALL close_extraction\(\);
src/mmt_core/public_include/mmt_core.h:1228	MMTAPI char\* MMTCALL mmt_version\(\);
src/mmt_core/public_include/mmt_core.h:106-110	^#define EVA_IP_FRAGMENT_PACKET 1	^#define EVA_IP_FRAGMENT_DUPLICATED 5
src/mmt_core/public_include/mmt_core.h:125	^typedef void \(\*generic_evasion_handler_callback\)
src/mmt_core/public_include/mmt_core.h:218	^MMTAPI void MMTCALL mmt_close_handler\(
src/mmt_core/public_include/mmt_core.h:229	^MMTAPI uint64_t MMTCALL get_active_session_count\(
src/mmt_core/public_include/mmt_core.h:331	^MMTAPI bool MMTCALL register_evasion_handler\(
src/mmt_core/public_include/mmt_core.h:580	^MMTAPI bool MMTCALL set_fragment_in_packet\(
src/mmt_core/public_include/mmt_core.h:592	^MMTAPI bool MMTCALL set_fragmented_packet_in_session\(
src/mmt_core/public_include/mmt_core.h:604	^MMTAPI bool MMTCALL set_fragment_in_session\(
src/mmt_core/src/plugins_engine.c:43-50	scandir\( PLUGINS_REPOSITORY,	scandir\( PLUGINS_REPOSITORY_OPT,
TABLE
)"

registered=""
while IFS=$'\t' read -r cite head tail; do
    [ -n "$cite" ] || continue
    registered="${registered}${cite}"$'\n'
    file="${cite%%:*}"
    spec="${cite##*:}"
    start="${spec%%-*}"
    end="${spec##*-}"
    if [ ! -f "${REPO_ROOT}/${file}" ]; then
        fail "${cite} — cited file does not exist"
        continue
    fi
    if ! sed -n "${start}p" "${REPO_ROOT}/${file}" | grep -Eq -- "${head}"; then
        fail "${cite} — stale: line ${start} does not match /${head}/"
        continue
    fi
    if [ -n "${tail:-}" ] && ! sed -n "${end}p" "${REPO_ROOT}/${file}" | grep -Eq -- "${tail}"; then
        fail "${cite} — stale: line ${end} does not match /${tail}/"
        continue
    fi
    ok "${cite}"
done <<< "${CITATIONS}"

# Every source citation the docs make must be registered above. A backticked
# citation may list several comma-separated lines (`file.h:185,198`).
# shellcheck disable=SC2016  # backticks are Markdown syntax, not a subshell
doc_cites="$(
    for doc in "${CITING_DOCS[@]}"; do
        grep -o '`src/[^`]*`' "${REPO_ROOT}/${doc}" || true
    done | tr -d '`' \
         | grep -E '^[A-Za-z0-9_./-]+:[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$' \
         | awk -F: '{ n = split($2, r, ","); for (i = 1; i <= n; i++) print $1 ":" r[i] }' \
         | sort -u
)"
while IFS= read -r cite; do
    [ -n "$cite" ] || continue
    printf '%s' "$registered" | grep -qxF -- "$cite" \
        || fail "${cite} — cited in the lifecycle docs but not registered in this suite"
done <<< "${doc_cites}"

# The docs must still state the ordering and ownership rules this suite pins.
# shellcheck disable=SC2016  # backticks are Markdown syntax, not a subshell
if grep -qF 'once with `init_extraction()`, **before any' "${REPO_ROOT}/docs/USER_GUIDE.md" \
   && grep -qF '**Worker ownership.**' "${REPO_ROOT}/docs/USER_GUIDE.md" \
   && grep -qF "${EXAMPLE_REL}" "${REPO_ROOT}/docs/USER_GUIDE.md"; then
    ok "USER_GUIDE.md states init order, worker ownership and names ${EXAMPLE_REL}"
else
    fail "USER_GUIDE.md lost the lifecycle order, worker ownership or example reference"
fi

# ---------------------------------------------------------------------------
# [2/4] Example call order (source-level)
# ---------------------------------------------------------------------------
echo "  [2/4] checking the example's lifecycle order ..."
EX="${REPO_ROOT}/${EXAMPLE_REL}"
# A missing call yields an empty value (reported below), not a set -e abort.
code_lines() { grep -nE -- "$1" "$EX" | grep -vE '^[0-9]+:[[:space:]]*(\*|//)' | cut -d: -f1 || true; }
first_line() { code_lines "$1" | sed -n '1p'; }
last_line()  { code_lines "$1" | sed -n '$p'; }
l_init="$(first_line 'init_extraction\(\)')"
l_handler="$(first_line 'mmt_init_handler\(')"
l_process="$(first_line 'packet_process\(')"
l_close_h="$(last_line 'mmt_close_handler\(')"
l_close_x="$(last_line 'close_extraction\(\)')"
if [ -n "$l_init" ] && [ -n "$l_handler" ] && [ -n "$l_process" ] \
   && [ -n "$l_close_h" ] && [ -n "$l_close_x" ] \
   && [ "$l_init" -lt "$l_handler" ] && [ "$l_handler" -lt "$l_process" ] \
   && [ "$l_process" -lt "$l_close_h" ] && [ "$l_close_h" -lt "$l_close_x" ]; then
    ok "init_extraction(${l_init}) < mmt_init_handler(${l_handler}) < packet_process(${l_process}) < mmt_close_handler(${l_close_h}) < close_extraction(${l_close_x})"
else
    fail "example lifecycle order is wrong or incomplete (lines: ${l_init:-?} ${l_handler:-?} ${l_process:-?} ${l_close_h:-?} ${l_close_x:-?})"
fi
if grep -qE 'if *\(!init_extraction\(\)\)' "$EX"; then
    ok "example checks the init_extraction() result"
else
    fail "example ignores the init_extraction() result"
fi
if grep -qE 'if *\(!mmt_handler\)' "$EX"; then
    ok "example checks the mmt_init_handler() result"
else
    fail "example ignores the mmt_init_handler() result"
fi

if [ "$ERRORS" -ne 0 ]; then
    echo "✗ docs_lifecycle: ${ERRORS} static check(s) failed" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# [3/4] Build + install into a throwaway prefix
# ---------------------------------------------------------------------------
PREFIX="$(mktemp -d)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}" "${PREFIX}"' EXIT
BUILD_LOG="${WORK}/build.log"
CC="${CC:-gcc}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
if [ -n "${SDK_BUILD_PROFILE:-}" ]; then
    set -- "BUILD=${SDK_BUILD_PROFILE}"
else
    set --
fi

echo "  [3/4] building + installing SDK into ${PREFIX} ..."
make -C "${REPO_ROOT}/sdk" clean >/dev/null 2>&1 || true
if ! make -C "${REPO_ROOT}/sdk" "$@" -j"${JOBS}" MMT_BASE="${PREFIX}" >"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK build failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi
if ! make -C "${REPO_ROOT}/sdk" "$@" MMT_BASE="${PREFIX}" install >>"${BUILD_LOG}" 2>&1; then
    echo "✗ SDK install failed — last lines:" >&2; tail -20 "${BUILD_LOG}" >&2; exit 1
fi

# ---------------------------------------------------------------------------
# [4/4] Compile and run the installed example
# ---------------------------------------------------------------------------
echo "  [4/4] compiling + running the installed example ..."
INSTALLED_EX="${PREFIX}/examples/packet_handler.c"
if ! cmp -s "${INSTALLED_EX}" "${EX}"; then
    echo "✗ installed ${INSTALLED_EX} differs from ${EXAMPLE_REL}" >&2; exit 1
fi
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
"${CC}" "${extra_cflags[@]}" -O2 -Wall -o "${WORK}/packet_handler" "${INSTALLED_EX}" \
    -I "${PREFIX}/dpi/include" -L "${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap
# init_extraction() scans ./plugins before <prefix>/plugins
# (src/mmt_core/src/plugins_engine.c:43-50): run from a neutral CWD so a
# checkout-local ./plugins can never shadow the installed plugins.
mkdir -p "${WORK}/run"
run() { (cd "${WORK}/run" && LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}" "${WORK}/packet_handler" "$@"); }

rc=0
run "${PCAP}" >"${WORK}/out.txt" 2>"${WORK}/err.txt" || rc=$?
packets="$(grep -c '^Received packet of size ' "${WORK}/out.txt" || true)"
if [ "$rc" -eq 0 ] && [ "$packets" -gt 0 ]; then
    ok "processed google-fr.pcap: exit 0, ${packets} packet callback(s)"
else
    fail "google-fr.pcap run: exit ${rc}, ${packets} packet callback(s)"
    tail -5 "${WORK}/err.txt" >&2 || true
fi

rc=0
run "${WORK}/does-not-exist.pcap" >/dev/null 2>"${WORK}/err.txt" || rc=$?
if [ "$rc" -eq 1 ] && grep -q 'pcap_open failed' "${WORK}/err.txt"; then
    ok "unreadable pcap exits 1 after releasing handler and global state"
else
    fail "unreadable pcap: expected exit 1 with 'pcap_open failed', got exit ${rc}"
fi

rc=0
run >/dev/null 2>"${WORK}/err.txt" || rc=$?
if [ "$rc" -eq 1 ] && grep -q '^Usage:' "${WORK}/err.txt"; then
    ok "missing argument exits 1 with usage"
else
    fail "missing argument: expected exit 1 with usage, got exit ${rc}"
fi

if [ "$ERRORS" -ne 0 ]; then
    echo "✗ docs_lifecycle: ${ERRORS} check(s) failed" >&2
    exit 1
fi
echo
echo "✓ documented embedding lifecycle verified against an installed SDK (issue #392)"
