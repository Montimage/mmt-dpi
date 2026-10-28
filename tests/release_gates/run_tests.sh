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
# It also runs the dependency-advisory self-test beside
# tools/ci/check-dependency-advisories.sh (issue #492), which drives the real
# script on fixture trees against a local stub of the advisory feeds
# (tools/ci/tests/dependency-advisories-feeds.json; no docker, no network).
# It also runs the required-checks self-test beside
# tools/ci/check-required-checks.sh (issue #490), which drives the real
# checker on the committed .github/required-checks.txt and on fixture
# workflows (no network: --live runs against a stub gh). It skips without
# PyYAML; the verify-helpers job runs it with PyYAML required.
# It also runs the vendored-inventory self-test beside
# tools/ci/vendored-components.py (issue #496), which checks the committed
# manifest, fixture manifests that must fail, and the SBOM injection on a
# fixture SPDX document.
# It also runs the release-hardening self-test beside
# tools/ci/check-hardening-flags.sh (issue #508), which evaluates the real
# makefiles with a print goal (no SDK compile) to pin that hardening is keyed
# on compiler identity, and drives --built DIR on fixture shared objects.
# It also runs the dependency-list self-test beside
# tools/ci/check-dependency-lists.sh (issue #495), which runs the real lint
# on fixture trees where one list or tools/ci/build-deps.txt row diverges.
# It also runs the release-bootstrap self-test beside
# tools/ci/make-release-bootstrap.sh and tools/ci/bootstrap-install.sh
# (issue #498), which renders fixture release directories and drives the
# rendered bootstrap's detection, lookup and digest check (no network).
# It also runs the shlib-deps self-test beside tools/ci/shlib-deps.sh
# (issue #515), which maps each libxml2 soname to its runtime package on
# fixture payloads (libxml2.so.16 -> libxml2-16 on Ubuntu 26.04).
# It also runs the path-to-test selection self-test beside
# tools/ci/classify-changes.sh (issues #528, #552, #656), which classifies
# fixture path lists, runs tools/ci/check-test-map.sh on the map and on
# broken copies of it, and pins the c-cpp.yml / phase0-baseline.yml job
# wiring that keeps every required context reporting on every tier. Its
# wiring half skips without PyYAML; verify-helpers runs it with PyYAML
# required.
# It also runs the commented-out code ratchet self-test beside
# tools/ci/lint-commented-code.sh (issue #529), which drives the real lint on
# a fixture git repository with fixture baselines and vendored-source lists.
# It also runs the public-API contract checker self-test beside
# tools/ci/check-api-contracts.sh (issue #525), which drives the real checker
# on fixture name lists (missing, stale, duplicate and waiver-ratchet cases)
# and proves CONTRACT() rejects an undeclared name at compile time, and the
# ABI-diff self-test beside tools/ci/abi-diff.sh (issue #525), which maps stub
# abidiff exit codes to verdicts on dummy libraries (no SDK build, no
# network).
# It also runs the plugin export-gate self-test beside
# scripts/validate-exported-symbols.sh (issue #534), which drives the real
# validator on a fixture shared object and fixture documents (an unrecorded
# export, a removed one, a missing section, --write; no SDK build).
# It also runs the phase0 harness-shard self-test beside
# tools/phase0/run_all_harnesses.sh (issue #655), which drives the runner's
# --group/--shard/--list selectors and a fixture run that builds no SDK, and
# pins that the phase0-baseline.yml harness legs cover every harness once.
# Its wiring half skips without PyYAML; verify-helpers runs it with PyYAML
# required.
# It also runs the shared-build self-test beside tests/run_all_tests.sh
# (issue #654), which drives a copy of the real runner over fake suites with
# a stub make on PATH (one build per group, the incremental ENABLESEC=1
# build, the prefixes handed to consumers, a failed build; no SDK build).
set -e
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../tools/ci/tests"
python3 "${TESTS_DIR}/test-release-gates.py" "$@"
bash "${TESTS_DIR}/test-cppcheck-version.sh"
bash "${TESTS_DIR}/test-version-agreement.sh"
bash "${TESTS_DIR}/test-release-tag-pin.sh"
bash "${TESTS_DIR}/test-release-publish.sh"
bash "${TESTS_DIR}/test-image-pins.sh"
python3 "${TESTS_DIR}/test-dependency-advisories.py"
bash "${TESTS_DIR}/test-required-checks.sh"
python3 "${TESTS_DIR}/test-vendored-components.py"
bash "${TESTS_DIR}/test-hardening-identity.sh"
bash "${TESTS_DIR}/test-dependency-lists.sh"
bash "${TESTS_DIR}/test-release-bootstrap.sh"
bash "${TESTS_DIR}/test-shlib-deps.sh"
bash "${TESTS_DIR}/test-classify-changes.sh"
bash "${TESTS_DIR}/test-commented-code-ratchet.sh"
bash "${TESTS_DIR}/test-api-contracts.sh"
bash "${TESTS_DIR}/test-abi-diff.sh"
bash "${TESTS_DIR}/test-exported-symbols.sh"
bash "${TESTS_DIR}/test-harness-shards.sh"
bash "${TESTS_DIR}/test-shared-sdk-build.sh"
