#!/bin/bash
# Delegate suite: the exact-release-SHA gate self-test lives beside the script
# it exercises — tools/ci/check-release-gates.sh (issue #371, F-CI-001). It
# needs no SDK build: the gate runs in --check-runs mode on synthetic
# check-run payloads, so the suite exercises the real verdict logic.
# It also runs the cppcheck lint gate's version-pin self-test beside
# tools/ci/run-cppcheck.sh (issue #345), which drives the real gate with a
# stub cppcheck on PATH, and the version-agreement self-test beside
# scripts/validate-release-prep.sh (issue #483), which runs the real validator
# on fixtures where one version site disagrees with rules/common.mk, and the
# release-tag gate self-test beside tools/ci/check-release-tag.sh (issue
# #484), which asserts install.sh's RELEASE_TAG_SHA is the peeled tag commit
# on a fixture repository with an annotated tag, and the single-publisher
# self-test beside tools/ci/publish-release.sh and tools/ci/release-alert.sh
# (issue #489), which drives both against a stub gh. The ancestry gate of
# check-release-tag.sh (issue #489) is covered in test-release-gates.py.
# It also runs the image-pin self-test beside tools/ci/check-image-digests.sh
# and tools/ci/refresh-base-images.sh (issue #491), which drives both against
# a fixture repository and a stub registry inspector (no docker, no network).
set -e
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../tools/ci/tests"
python3 "${TESTS_DIR}/test-release-gates.py" "$@"
bash "${TESTS_DIR}/test-cppcheck-version.sh"
bash "${TESTS_DIR}/test-version-agreement.sh"
bash "${TESTS_DIR}/test-release-tag-pin.sh"
bash "${TESTS_DIR}/test-release-publish.sh"
bash "${TESTS_DIR}/test-image-pins.sh"
