#!/bin/bash
# Delegate suite: the exact-release-SHA gate self-test lives beside the script
# it exercises — tools/ci/check-release-gates.sh (issue #371, F-CI-001). It
# needs no SDK build: the gate runs in --check-runs mode on synthetic
# check-run payloads, so the suite exercises the real verdict logic.
set -e
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../tools/ci/tests/test-release-gates.py" "$@"
