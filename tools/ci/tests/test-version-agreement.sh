#!/usr/bin/env bash
#
# test-version-agreement.sh — self-test for the version-agreement check in
# scripts/validate-release-prep.sh (issue #483).
#
# It copies every file the validator reads into a scratch fixture, runs the
# REAL validator on it with --root, then breaks one version site at a time
# and asserts the validator fails. Needs no SDK build; runs in well under a
# second.
#
# Scenario -> expected validator exit:
#   pristine copy of this checkout                     -> 0
#   mmt_core.h VERSION differs from rules/common.mk    -> non-zero
#   ZIP mmt-install-common.sh fallback differs         -> non-zero
#   CHANGELOG topmost Version heading differs          -> non-zero
#   rules/common.mk has no VERSION line                -> non-zero
#   debian/changelog present and matching (epoch/rev)  -> 0
#   debian/changelog present and differing             -> non-zero
#   install.sh RELEASE_TAG newer than VERSION          -> non-zero
#   install.sh RELEASE_TAG names an unreleased entry   -> non-zero
#   README 'Current release' differs from RELEASE_TAG  -> non-zero
#   site hero version differs from RELEASE_TAG         -> non-zero
#   abi-diff ABI_BASELINE differs from RELEASE_TAG     -> non-zero (#536)
#   abi-diff.sh baseline_ref differs from RELEASE_TAG  -> non-zero (#536)
#
# Usage: bash tools/ci/tests/test-version-agreement.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
VALIDATOR="${REPO_ROOT}/scripts/validate-release-prep.sh"
[ -f "${VALIDATOR}" ] || { echo "✗ missing ${VALIDATOR}" >&2; exit 2; }

VERSION="$(sed -n 's/^VERSION[[:space:]]*:=[[:space:]]*//p' "${REPO_ROOT}/rules/common.mk" | head -n 1)"
[ -n "${VERSION}" ] || { echo "✗ VERSION not found in rules/common.mk" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# Every file validate-release-prep.sh reads or tests for existence.
FILES="rules/common.mk src/mmt_core/public_include/mmt_core.h
dist/ZIP/install.sh dist/ZIP/uninstall.sh dist/ZIP/mmt-install-common.sh
install.sh README.md CHANGELOG.md docs/_includes/quick-start.md docs/index.html
src/examples/google-fr.pcap .github/workflows/c-cpp.yml
.github/workflows/release-packages.yml tools/ci/abi-diff.sh"

fresh() {
    rm -rf "${WORK}/tree"
    local f
    for f in ${FILES}; do
        mkdir -p "${WORK}/tree/$(dirname "${f}")"
        cp "${REPO_ROOT}/${f}" "${WORK}/tree/${f}"
    done
}

FAILED=0
expect() {
    # expect pass|fail DESC [SITE] — a failure must name SITE on a ✗ line.
    local want="$1" desc="$2" site="${3:-}" rc=0
    bash "${VALIDATOR}" --root "${WORK}/tree" >"${WORK}/out" 2>&1 || rc=$?
    if { [ "${want}" = pass ] && [ "${rc}" -eq 0 ]; } ||
       { [ "${want}" = fail ] && [ "${rc}" -ne 0 ] &&
         grep "✗" "${WORK}/out" | grep -qF -- "${site}"; }; then
        echo "  ✓ ${desc} (exit ${rc})"
    else
        echo "  ✗ ${desc}: expected ${want}, got exit ${rc}"
        sed 's/^/      /' "${WORK}/out"
        FAILED=1
    fi
}

edit() { sed -i "$2" "${WORK}/tree/$1"; }

echo "=== version-agreement self-test (VERSION ${VERSION}) ==="

fresh
expect pass "pristine checkout copy"

fresh; edit src/mmt_core/public_include/mmt_core.h 's/^#define VERSION ".*"/#define VERSION "0.0.1"/'
expect fail "mmt_core.h disagrees with rules/common.mk" "mmt_core.h"

fresh
# shellcheck disable=SC2016  # literal ${VERSION:-...} written into the fixture
edit dist/ZIP/mmt-install-common.sh 's/^VERSION=.*/VERSION="${VERSION:-0.0.1}"/'
expect fail "ZIP fallback disagrees" "mmt-install-common.sh"

fresh; edit CHANGELOG.md '0,/^Version [0-9]/s/^Version [0-9][^ ]*/Version 0.0.1/'
expect fail "CHANGELOG topmost Version heading disagrees" "topmost"

fresh; edit rules/common.mk 's/^VERSION[[:space:]]*:=.*/# VERSION removed/'
expect fail "rules/common.mk lacks VERSION" "rules/common.mk"

fresh; mkdir -p "${WORK}/tree/debian"
printf 'mmt-dpi (1:%s-1) unstable; urgency=medium\n' "${VERSION}" > "${WORK}/tree/debian/changelog"
expect pass "debian/changelog present and matching"
printf 'mmt-dpi (0.0.1-1) unstable; urgency=medium\n' > "${WORK}/tree/debian/changelog"
expect fail "debian/changelog present and differing" "debian/changelog"

fresh; edit install.sh 's/^RELEASE_TAG=".*"/RELEASE_TAG="v999.0.0"/'
expect fail "install.sh RELEASE_TAG newer than VERSION" "install.sh RELEASE_TAG"

fresh
tag="$(sed -n 's/^RELEASE_TAG="\(.*\)"/\1/p' "${WORK}/tree/install.sh")"
for f in install.sh README.md docs/_includes/quick-start.md docs/index.html; do
    edit "${f}" "s/${tag//./\\.}/v${VERSION}/g"
done
if grep -qi "^Version ${VERSION//./\\.} (unreleased" "${WORK}/tree/CHANGELOG.md"; then
    expect fail "install.sh RELEASE_TAG names an unreleased CHANGELOG entry" "dated entry"
else
    echo "  ○ VERSION ${VERSION} is dated in CHANGELOG — unreleased-pin scenario skipped"
fi

fresh; edit README.md 's/Current release: \[v[^]]*\]/Current release: [v0.0.1]/'
expect fail "README 'Current release' disagrees with RELEASE_TAG" "Current release"

fresh; edit docs/index.html 's/<\/span>v[0-9][^ ]* ·/<\/span>v0.0.1 ·/'
expect fail "site hero version disagrees with RELEASE_TAG" "hero"

fresh; edit .github/workflows/c-cpp.yml 's/^\([[:space:]]*ABI_BASELINE:\).*/\1 v0.0.1/'
expect fail "abi-diff ABI_BASELINE disagrees with RELEASE_TAG" "ABI_BASELINE"

fresh; edit tools/ci/abi-diff.sh 's/^baseline_ref=.*/baseline_ref=v0.0.1/'
expect fail "abi-diff.sh baseline_ref disagrees with RELEASE_TAG" "baseline_ref"

echo ""
if [ "${FAILED}" -eq 0 ]; then
    echo "Result: PASS (version-agreement self-test)"
else
    echo "Result: FAIL (version-agreement self-test)"
fi
exit "${FAILED}"
