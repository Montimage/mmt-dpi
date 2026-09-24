#!/bin/bash
# Delegate suite: the exact-release-SHA gate self-test lives beside the script
# it exercises — tools/ci/check-release-gates.sh (issue #371, F-CI-001). It
# needs no SDK build: the gate runs in --check-runs mode on synthetic
# check-run payloads, so the suite exercises the real verdict logic.
# It also runs the cppcheck lint gate's version-pin self-test beside
# tools/ci/run-cppcheck.sh (issue #345), which drives the real gate with a
# stub cppcheck on PATH.
set -e
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../tools/ci/tests"
python3 "${TESTS_DIR}/test-release-gates.py" "$@"
bash "${TESTS_DIR}/test-cppcheck-version.sh"
