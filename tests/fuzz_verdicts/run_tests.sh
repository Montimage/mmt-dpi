#!/bin/bash
# Delegate suite: the fuzz-gate verdict self-test lives beside the script it
# exercises — tools/ci/run-fuzz.sh (issue #370, F-TEST-001). It needs no SDK
# build: the suite stubs gcc/python3 and runs the real wrapper end-to-end.
set -e
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../tools/ci/tests/test-fuzz-verdicts.sh" "$@"
