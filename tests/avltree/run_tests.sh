#!/usr/bin/env bash
#
# run_tests.sh — run the AVL correctness suite against the working-tree
# avltree.c (issue #21 height-cache change, now merged).
#
# This suite used to also diff the tree shape and build time against a pre-fix
# avltree.c pulled from a git ref. Once the fix merged, no ref carries a
# *distinct* pre-fix source (and a shallow CI checkout fetches none at all), so
# that arm exited 0 having asserted nothing — a false pass (issue #186,
# F-TEST-010). It is deleted: the script now cannot exit 0 without the
# correctness assertions in test_avltree.c actually running.
#
# Usage: tests/avltree/run_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LIB_DIR="${REPO_ROOT}/src/mmt_tcpip/lib"
CORE_PUBLIC_INC="${REPO_ROOT}/src/mmt_core/public_include"
TEST_SRC="${SCRIPT_DIR}/test_avltree.c"

CC="${CC:-gcc}"
# EXTRA_CFLAGS carries sanitizer/coverage instrumentation requested by
# tests/run_all_tests.sh (appended last so its -O level wins over -O2).
CFLAGS="-O2 -Wall -g ${EXTRA_CFLAGS:-}"
read -r -a cflags <<< "${CFLAGS}"

echo "  building correctness binary ..."
${CC} "${cflags[@]}" -I "${LIB_DIR}" -I "${CORE_PUBLIC_INC}" -o "${SCRIPT_DIR}/test_avltree" \
    "${TEST_SRC}" "${LIB_DIR}/avltree.c"

echo
echo "== correctness suite =="
"${SCRIPT_DIR}/test_avltree"

echo
echo "✓ avltree correctness suite passed"
