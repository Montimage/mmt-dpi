#!/bin/bash
# Delegate suite: the SDK integration coverage self-test lives beside the
# helper it exercises — tools/ci/sdk-coverage.sh (issue #387, F-TEST-004). It
# builds the SDK itself with BUILD=coverage into a throwaway prefix (ignoring
# SANITIZE/--coverage) and runs `make -C sdk clean` when it finishes.
set -e
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../tools/ci/tests/test-sdk-coverage.sh" "$@"
