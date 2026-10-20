#!/usr/bin/env bash
#
# test-release-tag-pin.sh — self-test for tools/ci/check-release-tag.sh
# (issues #220 and #484; the ancestry gate of issue #489 has its own cases in
# test-release-gates.py).
#
# It builds a throwaway git repository with an annotated release tag, points
# the REAL gate at it with ROOT_DIR, and asserts each verdict. Needs no SDK
# build and no network; runs in well under a second.
#
# Scenario -> expected gate exit:
#   pin = peeled commit of RELEASE_TAG                     -> 0
#   pin = another commit (the v1.9.0 -> v1.8.0 bug)        -> 1
#   pin = the annotated tag OBJECT, not its commit         -> 1
#   RELEASE_TAG absent locally                             -> 0 (skipped)
#   RELEASE_TAG absent locally, REQUIRE_RELEASE_TAG=1      -> 2
#   --write-pin repairs a stale pin                        -> 0, then gate 0
#   --write-pin with an unknown or malformed tag           -> 2
#   version gate: tag == v$VERSION / != / empty argument   -> 0 / 1 / 2
#   this checkout (when its RELEASE_TAG is fetched)        -> 0
#
# Usage: bash tools/ci/tests/test-release-tag-pin.sh
# Exit: 0 = all checks passed, 1 = at least one failed, 2 = self-test broke.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SELF_DIR}/../../.." && pwd)"
GATE="${REPO_ROOT}/tools/ci/check-release-tag.sh"
[ -f "${GATE}" ] || { echo "✗ missing ${GATE}" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
FX="${WORK}/repo"

g() { git -C "${FX}" -c user.name=fixture -c user.email=fixture@example.invalid \
        -c commit.gpgsign=false -c tag.gpgsign=false "$@"; }

mkdir -p "${FX}/rules"
git init -q "${FX}" || exit 2
printf 'VERSION := 1.2.3\n' > "${FX}/rules/common.mk"
printf '#!/usr/bin/env bash\nRELEASE_TAG="v1.2.2"\nRELEASE_TAG_SHA="0000000000000000000000000000000000000000"\n' \
    > "${FX}/install.sh"
g add -A && g commit -q -m released || exit 2
g tag -a v1.2.2 -m "release v1.2.2" || exit 2
TAGGED="$(g rev-parse 'v1.2.2^{commit}')"
TAG_OBJECT="$(g rev-parse v1.2.2)"
printf '\n' >> "${FX}/rules/common.mk"
g commit -q -am later || exit 2
LATER="$(g rev-parse HEAD)"
# The version-gate cases name v1.2.3: the ancestry gate (issue #489) needs it
# tagged locally and on the release base, origin/main.
g tag -a v1.2.3 -m "release v1.2.3" || exit 2
g update-ref refs/remotes/origin/main "${LATER}" || exit 2
[ "${TAG_OBJECT}" != "${TAGGED}" ] || { echo "✗ fixture tag is not annotated" >&2; exit 2; }

pin() { # pin <tag> <sha>
    sed -i -e "s/^RELEASE_TAG=.*/RELEASE_TAG=\"$1\"/" \
           -e "s/^RELEASE_TAG_SHA=.*/RELEASE_TAG_SHA=\"$2\"/" "${FX}/install.sh"
}

FAILED=0
expect() {
    # expect <exit> <desc> <gate args...> — runs the gate on the fixture.
    local want="$1" desc="$2" rc=0
    shift 2
    env -u GITHUB_REF_TYPE -u GITHUB_REF_NAME ROOT_DIR="${FX}" \
        bash "${GATE}" "$@" >"${WORK}/out" 2>&1 || rc=$?
    if [ "${rc}" -eq "${want}" ]; then
        echo "  ✓ ${desc} (exit ${rc})"
    else
        echo "  ✗ ${desc}: expected exit ${want}, got ${rc}"
        sed 's/^/      /' "${WORK}/out"
        FAILED=1
    fi
}

echo "=== release-tag pin self-test ==="

pin v1.2.2 "${TAGGED}"
expect 0 "pin is the peeled commit of RELEASE_TAG"

pin v1.2.2 "${LATER}"
expect 1 "pin names another commit"

pin v1.2.2 "${TAG_OBJECT}"
expect 1 "pin names the annotated tag object, not its commit"

pin v9.9.9 "${TAGGED}"
expect 0 "RELEASE_TAG not available locally is skipped"
REQUIRE_RELEASE_TAG=1 expect 2 "RELEASE_TAG not available, REQUIRE_RELEASE_TAG=1"

pin v1.2.2 "${LATER}"
expect 0 "--write-pin rewrites the stale pin" --write-pin v1.2.2
expect 0 "gate passes after --write-pin"
if grep -qx "RELEASE_TAG_SHA=\"${TAGGED}\"" "${FX}/install.sh"; then
    echo "  ✓ --write-pin wrote the peeled commit"
else
    echo "  ✗ --write-pin did not write ${TAGGED}"; FAILED=1
fi
expect 2 "--write-pin refuses an unknown tag" --write-pin v9.9.9
expect 2 "--write-pin refuses a non-vX.Y.Z tag" --write-pin 'v1/2&3'

expect 0 "version gate: tag equals v\$VERSION" v1.2.3
expect 1 "version gate: tag differs from v\$VERSION" v1.2.4
expect 2 "version gate: explicitly empty tag argument" ""

# This checkout: the real install.sh pin must resolve whenever the tag exists.
rc=0
env -u GITHUB_REF_TYPE -u GITHUB_REF_NAME bash "${GATE}" >"${WORK}/out" 2>&1 || rc=$?
if [ "${rc}" -eq 0 ]; then
    echo "  ✓ this checkout: $(head -n 1 "${WORK}/out")"
else
    echo "  ✗ this checkout's install.sh pin is wrong (exit ${rc})"
    sed 's/^/      /' "${WORK}/out"
    FAILED=1
fi

if [ "${FAILED}" -ne 0 ]; then
    echo "✗ release-tag pin self-test FAILED"
    exit 1
fi
echo "✓ release-tag pin self-test passed"
