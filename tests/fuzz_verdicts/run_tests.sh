#!/bin/bash
# Delegate suite: the fuzz-gate verdict self-test lives beside the script it
# exercises — tools/ci/run-fuzz.sh (issue #370, F-TEST-001). It needs no SDK
# build: the suite stubs gcc/python3 and runs the real wrapper end-to-end.
# It also covers the scheduled-failure alert, tools/ci/fuzz-alert.sh (issue
# #486), with a stubbed gh.
set -e
CI_TESTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../tools/ci/tests"
bash "${CI_TESTS}/test-fuzz-verdicts.sh" "$@"
exec bash "${CI_TESTS}/test-fuzz-alert.sh"
